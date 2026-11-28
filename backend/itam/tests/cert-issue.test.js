// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Certificate issuance (engine/cert-issue.js + csr.js + acme.js + adcs.js; the decisions in Python - pyengine/cert_rules.py,
// run for real). A fake ACME CA over HTTPS checks every JWS (ES256 signature, single-use nonce, url, account kid, EAB HMAC),
// verifies the CSR signature and names, demands the http-01 file / the dns-01 TXT record and issues real certificates; a fake
// AD CS certsrv checks Basic authentication and the template and can hold a request for a CA manager. Verifies: issuers are
// admin-only with secrets sealed and never returned; ACME http-01 end to end (renewal moved to issued); a name the endpoint
// does not present, or a wildcard, waits for a DIFFERENT person; dns-01 waits for the TXT record; IP names refused for ACME;
// AD CS immediate, held then released by the tick, wrong template → failed; manual: CSR out, a certificate for another key
// refused, the right one accepted; export is admin-only with a reason, the key matches and never appears in the view, list
// or audit; auto-renewal of a flagged endpoint; a failed request is a finding. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createSealer } = require('../engine/discovery/vault');
const { makeCA, makeServerCert, build } = require('./helpers/x509');

const PY = process.env.PYTHON || 'python3';
const DAY = 86400000;
const OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'khalid.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ub64u = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// ---- a little DER reader: enough to take a CSR apart --------------------------------------------------------------------
function tlv(buf, off) { const tag = buf[off]; let len = buf[off + 1], hdr = 2; if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i]; hdr = 2 + n; } return { tag, start: off + hdr, end: off + hdr + len, off }; }
function kids(buf, t) { const out = []; let o = t.start; while (o < t.end) { const c = tlv(buf, o); out.push(c); o = c.end; } return out; }
function parseCsr(pem) {
  const d = Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64'), top = tlv(d, 0), [cri, alg, sig] = kids(d, top), [, , spki] = kids(d, cri);
  const pub = crypto.createPublicKey({ key: d.slice(spki.off, spki.end), format: 'der', type: 'spki' });
  const hash = d.slice(alg.off, alg.end).includes(Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03])) ? 'sha384' : 'sha256';
  const ok = crypto.verify(hash, d.slice(cri.off, cri.end), pub, d.slice(sig.start + 1, sig.end));
  const names = [], i = d.indexOf(Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x11]));
  if (i > 0) { const oct = tlv(d, i + 5), gn = tlv(d, oct.start); for (const n of kids(d, gn)) { if (n.tag === 0x82) names.push(d.slice(n.start, n.end).toString('ascii')); if (n.tag === 0x87) names.push([...d.slice(n.start, n.end)].join('.')); } }
  return { pub, ok, names };
}

// ---- the fake CAs ------------------------------------------------------------------------------------------------------
const CA = makeCA('Synthetic Issuing CA'), TLSC = makeServerCert(CA, { cn: 'localhost', dns: ['localhost'], ip: ['127.0.0.1'], days: 30 });
const ACME = { nonces: new Set(), accounts: {}, orders: {}, authz: {}, chals: {}, eab: null, dns: {}, jwsChecked: 0, n: 0 };
let acmeBase = '', webroot = '';
function issueFor(pub, names, days) { return build({ subject: names[0], issuer: CA.cn, pub, signKey: CA.key, isCA: false, dns: names.filter((n) => !/^\d/.test(n)), ip: names.filter((n) => /^\d/.test(n)), days: days || 90, aki: CA.ski }); }
function acmeHandler(req, res) {
  const nonce = () => { const n = crypto.randomBytes(12).toString('hex'); ACME.nonces.add(n); return n; };
  const send = (code, obj, h) => { res.writeHead(code, Object.assign({ 'Content-Type': 'application/json', 'Replay-Nonce': nonce() }, h || {})); res.end(typeof obj === 'string' ? obj : JSON.stringify(obj)); };
  const url = acmeBase + req.url;
  if (req.url === '/dir') return send(200, { newNonce: acmeBase + '/nonce', newAccount: acmeBase + '/acct', newOrder: acmeBase + '/order' });
  if (req.url === '/nonce') { res.writeHead(200, { 'Replay-Nonce': nonce() }); return res.end(); }
  let b = ''; req.on('data', (c) => { b += c; });
  req.on('end', () => {
    let j, prot, payload, key;
    try { j = JSON.parse(b); prot = JSON.parse(ub64u(j.protected)); payload = j.payload === '' ? '' : JSON.parse(ub64u(j.payload)); } catch (e) { return send(400, { type: 'urn:ietf:params:acme:error:malformed' }); }
    if (!ACME.nonces.delete(prot.nonce)) return send(400, { type: 'urn:ietf:params:acme:error:badNonce' });
    if (prot.url !== url) return send(400, { type: 'urn:ietf:params:acme:error:unauthorized', detail: 'url mismatch' });
    if (prot.jwk) key = prot.jwk; else if (ACME.accounts[prot.kid]) key = ACME.accounts[prot.kid].jwk; else return send(400, { type: 'urn:ietf:params:acme:error:accountDoesNotExist' });
    if (!crypto.verify('sha256', Buffer.from(j.protected + '.' + j.payload), { key: crypto.createPublicKey({ key, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, ub64u(j.signature))) return send(400, { type: 'urn:ietf:params:acme:error:unauthorized', detail: 'bad signature' });
    ACME.jwsChecked++;
    const thumb = b64u(crypto.createHash('sha256').update(JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y })).digest());
    if (req.url === '/acct') {
      if (ACME.eab) {
        const e = payload.externalAccountBinding; if (!e) return send(400, { type: 'urn:ietf:params:acme:error:externalAccountRequired' });
        const ep = JSON.parse(ub64u(e.protected)); if (ep.kid !== ACME.eab.kid || crypto.createHmac('sha256', ub64u(ACME.eab.hmac)).update(e.protected + '.' + e.payload).digest().compare(ub64u(e.signature)) !== 0) return send(400, { type: 'urn:ietf:params:acme:error:unauthorized', detail: 'bad EAB' });
      }
      const kid = acmeBase + '/acct/' + (++ACME.n); ACME.accounts[kid] = { jwk: key }; return send(201, { status: 'valid' }, { Location: kid });
    }
    if (req.url === '/order') {
      const id = 'o' + (++ACME.n), az = payload.identifiers.map((x, i) => { const aid = id + 'a' + i, w = x.value.startsWith('*.'), v = x.value.replace(/^\*\./, '');
        const ch = [{ type: 'dns-01', url: acmeBase + '/chal/' + aid + 'd', token: crypto.randomBytes(18).toString('base64url'), status: 'pending' }];
        if (!w) ch.unshift({ type: 'http-01', url: acmeBase + '/chal/' + aid + 'h', token: crypto.randomBytes(18).toString('base64url'), status: 'pending' });
        ACME.authz[aid] = { identifier: { type: 'dns', value: v }, status: 'pending', wildcard: w, challenges: ch, thumb };
        for (const c of ch) ACME.chals[c.url] = { aid, c };
        return acmeBase + '/authz/' + aid; });
      ACME.orders[id] = { status: 'pending', identifiers: payload.identifiers, authorizations: az, finalize: acmeBase + '/finalize/' + id };
      return send(201, ACME.orders[id], { Location: acmeBase + '/order/' + id });
    }
    let m;
    if ((m = /^\/authz\/(\w+)$/.exec(req.url))) return send(200, ACME.authz[m[1]]);
    if ((m = /^\/order\/(\w+)$/.exec(req.url))) { const o = ACME.orders[m[1]]; if (o.status === 'pending' && o.authorizations.every((u) => ACME.authz[u.split('/').pop()].status === 'valid')) o.status = 'ready'; return send(200, o); }
    if (ACME.chals[url]) {
      const { aid, c } = ACME.chals[url], a = ACME.authz[aid], ka = c.token + '.' + a.thumb;
      let good = false;
      if (c.type === 'http-01') { try { good = fs.readFileSync(path.join(webroot, '.well-known', 'acme-challenge', c.token), 'utf8') === ka; } catch (e) { good = false; } }
      else good = ACME.dns['_acme-challenge.' + a.identifier.value] === b64u(crypto.createHash('sha256').update(ka).digest());
      c.status = a.status = good ? 'valid' : 'invalid'; return send(200, c);
    }
    if ((m = /^\/finalize\/(\w+)$/.exec(req.url))) {
      const o = ACME.orders[m[1]]; if (o.status !== 'ready') return send(403, { type: 'urn:ietf:params:acme:error:orderNotReady' });
      const csr = parseCsr('-----BEGIN CERTIFICATE REQUEST-----\n' + ub64u(payload.csr).toString('base64') + '\n-----END CERTIFICATE REQUEST-----');
      const want = o.identifiers.map((x) => x.value).sort().join(), got = csr.names.slice().sort().join();
      if (!csr.ok || want !== got) return send(400, { type: 'urn:ietf:params:acme:error:badCSR', detail: 'signature ' + csr.ok + ' names ' + got });
      o.cert = issueFor(csr.pub, csr.names) + CA.cert; o.status = 'valid'; o.certificate = acmeBase + '/cert/' + m[1]; return send(200, o);
    }
    if ((m = /^\/cert\/(\w+)$/.exec(req.url))) { res.writeHead(200, { 'Content-Type': 'application/pem-certificate-chain', 'Replay-Nonce': nonce() }); return res.end(ACME.orders[m[1]].cert); }
    send(404, { type: 'notFound' });
  });
}
const ADCS = { hold: false, reqs: {}, n: 6, user: 'svc-pki', pass: 'Synthetic-Pass-1' };
function adcsHandler(req, res) {
  const html = (code, s) => { res.writeHead(code, { 'Content-Type': 'text/html' }); res.end('<html><body>' + s + '</body></html>'); };
  if (req.headers.authorization !== 'Basic ' + Buffer.from(ADCS.user + ':' + ADCS.pass).toString('base64')) return html(401, 'Unauthorized');
  if (req.method === 'POST' && req.url === '/certsrv/certfnsh.asp') {
    let b = ''; req.on('data', (c) => { b += c; });
    req.on('end', () => {
      const p = new URLSearchParams(b);
      if (p.get('CertAttrib') !== 'CertificateTemplate:WebServerSyn') return html(200, 'Your certificate request was denied. Denied by Policy Module 0x80094800 template not allowed');
      const csr = parseCsr(p.get('CertRequest')), id = String(++ADCS.n);
      ADCS.reqs[id] = { csr, pem: ADCS.hold ? null : issueFor(csr.pub, csr.names, 365) };
      if (ADCS.hold) return html(200, 'Certificate Pending. Your certificate request has been received. However, you must wait for an administrator to issue the certificate. Your Request Id is ' + id + '. taken under submission');
      return html(200, 'Certificate Issued <a href="certnew.cer?ReqID=' + id + '&amp;Enc=b64">Download</a>');
    });
    return;
  }
  const m = /^\/certsrv\/certnew\.cer\?ReqID=(\d+)&Enc=b64$/.exec(req.url);
  if (m && ADCS.reqs[m[1]]) { const r = ADCS.reqs[m[1]]; if (!r.pem) return html(200, 'Your certificate request is still pending'); res.writeHead(200, { 'Content-Type': 'application/pkix-cert' }); return res.end(r.pem); }
  html(404, 'not found');
}

// ---- the platform -------------------------------------------------------------------------------------------------------
const PRESENT = {};
const stubRead = async (host, port) => { const p = PRESENT[host + ':' + port]; if (!p) return { ok: false, error: 'ECONNREFUSED' }; return Object.assign({ not_after_iso: new Date(p.not_after).toISOString().slice(0, 10) }, p); };
const present = (o) => Object.assign({ ok: true, subject: 'x', issuer: "R3 · Let's Encrypt", names: [], name_ok: true, trusted: true, self_signed: false, not_after: Date.now() + 200 * DAY, key_type: 'rsa', key_bits: 2048, serial: 'OLD', fingerprint256: 'FP:OLD', chain: [] }, o);
let acmeSrv, adcsSrv, adcsPort, tmp;
test.before(async () => {
  https.globalAgent.options.ca = CA.cert;     // the gateway's ACME client trusts the synthetic CA like a public one
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-issue-')); webroot = path.join(tmp, 'webroot');
  acmeSrv = https.createServer({ key: TLSC.key, cert: TLSC.cert }, acmeHandler); await new Promise((r) => acmeSrv.listen(0, '127.0.0.1', r)); acmeBase = 'https://localhost:' + acmeSrv.address().port;
  adcsSrv = https.createServer({ key: TLSC.key, cert: TLSC.cert }, adcsHandler); await new Promise((r) => adcsSrv.listen(0, '127.0.0.1', r)); adcsPort = adcsSrv.address().port;
});
test.after(() => { acmeSrv.close(); adcsSrv.close(); });
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const sealer = createSealer({ keyFile: path.join(fs.mkdtempSync(path.join(tmp, 'k')), 'vault.key'), createKey: true, purpose: 'sentra-itam-pki' });
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, python: PY, readCert: stubRead, certSealer: sealer, adcsCa: CA.cert });
  return { e, D, C: e.app.addons.certs };
}
const post = (e, p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
async function endpoint(e, host, names, extra) {
  PRESENT[host + ':443'] = present(Object.assign({ names }, extra || {}));
  const ep = (await post(e, '/certs/endpoints', Object.assign({ host, port: 443 }, (extra && extra.ep) || {}))).json; await post(e, '/certs/scan', { id: ep.id }); return ep;
}
const acmeSetup = (e, extra) => post(e, '/certs/issuers/acme', Object.assign({ directory_url: acmeBase + '/dir', contact: 'pki@synthetic.test', http01_webroot: webroot, tos_agreed: true }, extra || {}), ADM);

test('issuers: admin only, validated, secrets sealed and never returned, audited', async (t) => {
  const { e } = await setup(t);
  assert.equal((await post(e, '/certs/issuers/acme', { directory_url: acmeBase + '/dir', tos_agreed: true })).status, 403, 'operator refused');
  assert.match((await post(e, '/certs/issuers/acme', { directory_url: 'http://ca.synthetic.test/dir', tos_agreed: true }, ADM)).json.error, /directory_url/);
  assert.match((await post(e, '/certs/issuers/acme', { directory_url: acmeBase + '/dir', tos_agreed: false }, ADM)).json.error, /tos_agreed/);
  assert.match((await post(e, '/certs/issuers/acme', { directory_url: acmeBase + '/dir', tos_agreed: true, eab_kid: 'k1' }, ADM)).json.error, /eab/);
  const ok = await acmeSetup(e, { eab_kid: 'kid-synthetic', eab_hmac: b64u(crypto.randomBytes(32)) });
  assert.equal(ok.status, 200); assert.equal(ok.json.acme.eab, true);
  assert.match((await post(e, '/certs/issuers/adcs', { url: 'https://ca.synthetic.test/other', template: 'WebServerSyn', username: 'svc-pki', password: 'x' }, ADM)).json.error, /certsrv/);
  assert.match((await post(e, '/certs/issuers/adcs', { url: 'https://localhost:' + adcsPort + '/certsrv', template: 'WebServerSyn', username: 'svc-pki' }, ADM)).json.error, /password/);
  await post(e, '/certs/issuers/adcs', { url: 'https://localhost:' + adcsPort + '/certsrv', template: 'WebServerSyn', username: 'svc-pki', password: ADCS.pass }, ADM);
  const v = await e.req('GET', '/certs/issuers', OP);
  assert.equal(v.status, 200); assert.equal(v.json.adcs.password_set, true);
  const all = JSON.stringify(v.json) + JSON.stringify((await e.req('GET', '/certs', { role: 'viewer' })).json) + JSON.stringify(e.app.store.collection('cert_issuers').all()) + JSON.stringify(e.app.store.auditTail(30));
  assert.ok(!all.includes(ADCS.pass) && !/BEGIN (EC )?PRIVATE KEY/.test(all), 'no password or key anywhere it can be read');
  assert.ok(e.app.store.auditTail(10).some((x) => x.action === 'certs.issuer.acme' && x.by === 'syed' && x.detail.eab === true));
});

test('ACME http-01 end to end: key + CSR, every JWS checked, the certificate checked, the renewal moved to issued', async (t) => {
  const { e } = await setup(t); await acmeSetup(e);
  const ep = await endpoint(e, 'portal.synthetic.test', ['portal.synthetic.test', 'www.portal.synthetic.test']);
  const rn = (await post(e, '/certs/renewals', { endpoint_id: ep.id })).json;
  const before = ACME.jwsChecked;
  const r = await post(e, '/certs/requests', { endpoint_id: ep.id, renewal_id: rn.id });
  assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.status, 'issued', JSON.stringify(r.json.history));
  assert.equal(r.json.method, 'acme', 'from the issuer'); assert.deepEqual(r.json.names, ['portal.synthetic.test', 'www.portal.synthetic.test'], 'the names the endpoint presents');
  assert.ok(ACME.jwsChecked - before >= 6, 'account, order, authz, challenges, finalize, download - all signed');
  assert.match(r.json.cert_pem, /BEGIN CERTIFICATE/); assert.equal(r.json.key_pem, undefined);
  assert.ok(fs.readdirSync(path.join(webroot, '.well-known', 'acme-challenge')).length >= 2, 'http-01 files written to the web root');
  const v = (await e.req('GET', '/certs', { role: 'viewer' })).json;
  assert.equal(v.renewals.find((x) => x.id === rn.id).status, 'issued');
  assert.ok(!JSON.stringify(v).includes('PRIVATE KEY'));
  const au = e.app.store.auditTail(30).map((x) => x.action);
  assert.ok(au.includes('certs.request.create') && au.includes('certs.request.issued') && au.includes('certs.renewal.issued'));
  assert.equal((await post(e, '/certs/requests', { endpoint_id: ep.id, method: 'acme', names: ['10.1.2.3'] })).status, 400, 'IP names refused for ACME');
});

test('a new name or a wildcard waits for a different person; dns-01 waits for the TXT record', async (t) => {
  const { e } = await setup(t); await acmeSetup(e);
  const ep = await endpoint(e, 'shop.synthetic.test', ['shop.synthetic.test']);
  const r = await post(e, '/certs/requests', { endpoint_id: ep.id, names: ['shop.synthetic.test', '*.shop.synthetic.test'] });
  assert.equal(r.json.status, 'awaiting-approval'); assert.match(r.json.approval.why.join(), /wildcard/);
  assert.equal((await post(e, '/certs/requests/' + r.json.id + '/approve', {})).status, 403, 'the requester cannot approve');
  const r2 = await post(e, '/certs/requests/' + r.json.id + '/approve', {}, { user: ' Nora.Syn ', role: 'operator' }); assert.equal(r2.status, 403, 'the requester cannot approve under another spelling of their name'); assert.match(r2.json.error, /different person/);
  assert.equal((await post(e, '/certs/requests/' + r.json.id + '/approve', {}, { user: 'svc:auto', role: 'operator' })).status, 403, 'no service identity');
  assert.equal((await post(e, '/certs/requests/' + r.json.id + '/approve', {}, { user: 'v', role: 'viewer' })).status, 403);
  const a = await post(e, '/certs/requests/' + r.json.id + '/approve', {}, OP2);
  assert.equal(a.status, 200); assert.equal(a.json.status, 'awaiting-dns', 'the wildcard can only be validated by DNS');
  const rec = a.json.acme.dns.find((x) => x.name === '*.shop.synthetic.test');
  assert.equal(rec.record, '_acme-challenge.shop.synthetic.test'); assert.ok(rec.txt.length > 20);
  ACME.dns[rec.record] = rec.txt;
  const done = await post(e, '/certs/requests/' + r.json.id + '/advance', { dns_published: true });
  assert.equal(done.json.status, 'issued', JSON.stringify(done.json.history.slice(-2)));
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'certs.request.approve' && x.by === 'khalid.syn' && x.detail.requested_by === 'nora.syn'));
});

test('AD CS: issued at once; held by the CA manager then released by the tick; a template the CA refuses fails', async (t) => {
  const { e, C } = await setup(t);
  await post(e, '/certs/issuers/adcs', { url: 'https://localhost:' + adcsPort + '/certsrv', template: 'WebServerSyn', username: 'svc-pki', password: ADCS.pass }, ADM);
  const ep = await endpoint(e, 'erp.synthetic.local', ['erp.synthetic.local'], { trusted: false, issuer: 'Synthetic Issuing CA' });
  const r = await post(e, '/certs/requests', { endpoint_id: ep.id, key_type: 'ec', key_bits: 256 });
  assert.equal(r.json.method, 'adcs', 'guessed: a private CA'); assert.equal(r.json.status, 'issued', JSON.stringify(r.json.history)); assert.equal(r.json.key_type, 'ec');
  ADCS.hold = true;
  const ep2 = await endpoint(e, 'hr.synthetic.local', ['hr.synthetic.local'], { trusted: false, issuer: 'Synthetic Issuing CA' });
  const h = await post(e, '/certs/requests', { endpoint_id: ep2.id });
  assert.equal(h.json.status, 'adcs-pending'); assert.ok(h.json.adcs.req_id);
  ADCS.reqs[h.json.adcs.req_id].pem = issueFor(ADCS.reqs[h.json.adcs.req_id].csr.pub, ADCS.reqs[h.json.adcs.req_id].csr.names, 365); ADCS.hold = false;
  await C.issue.tick();
  assert.equal(C.issue.get(h.json.id).status, 'issued');
  await post(e, '/certs/issuers/adcs', { url: 'https://localhost:' + adcsPort + '/certsrv', template: 'NotAllowed', username: 'svc-pki' }, ADM);
  const ep3 = await endpoint(e, 'crm.synthetic.local', ['crm.synthetic.local'], { trusted: false, issuer: 'Synthetic Issuing CA' });
  const f = await post(e, '/certs/requests', { endpoint_id: ep3.id });
  assert.equal(f.json.status, 'failed'); assert.match(f.json.error, /Denied by Policy Module/);
  const v = (await e.req('GET', '/certs', { role: 'viewer' })).json;
  assert.ok(v.findings.some((x) => x.key === ep3.id + ':issue-failed:' + f.json.id), 'a failed request is a finding');
});

test('manual order: CSR out, a certificate for another key refused, the right one accepted; export rules', async (t) => {
  const { e } = await setup(t);
  const ep = await endpoint(e, 'bank.synthetic.test', ['bank.synthetic.test'], { issuer: 'Synthetic Commercial CA', ep: { issuer_kind: 'manual' } });
  const r = await post(e, '/certs/requests', { endpoint_id: ep.id });
  assert.equal(r.json.status, 'awaiting-certificate'); assert.match(r.json.csr_pem, /BEGIN CERTIFICATE REQUEST/);
  const csr = parseCsr(r.json.csr_pem); assert.equal(csr.ok, true); assert.deepEqual(csr.names, ['bank.synthetic.test']);
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
  const wrong = await post(e, '/certs/requests/' + r.json.id + '/upload', { pem: issueFor(other, ['bank.synthetic.test']) });
  assert.equal(wrong.status, 422); assert.match(wrong.json.error, /private key/);
  const short = await post(e, '/certs/requests/' + r.json.id + '/upload', { pem: issueFor(csr.pub, ['other.synthetic.test']) });
  assert.equal(short.status, 422); assert.match(short.json.error, /not covered: bank\.synthetic\.test/);
  assert.match((await post(e, '/certs/requests/' + r.json.id + '/upload', { pem: 'hello' })).json.error, /pem/);
  const good = await post(e, '/certs/requests/' + r.json.id + '/upload', { pem: issueFor(csr.pub, ['bank.synthetic.test']) + CA.cert });
  assert.equal(good.status, 200); assert.equal(good.json.status, 'issued'); assert.match(good.json.chain_pem, /BEGIN CERTIFICATE/);
  // export: administrators only, with a reason; the key matches the certificate; never in the view or the audit
  assert.equal((await post(e, '/certs/requests/' + r.json.id + '/export', { include_key: true, reason: 'install on IIS' })).status, 403);
  assert.match((await post(e, '/certs/requests/' + r.json.id + '/export', { include_key: true }, ADM)).json.error, /reason/);
  const x = await post(e, '/certs/requests/' + r.json.id + '/export', { include_key: true, reason: 'install on IIS by hand (synthetic)' }, ADM);
  assert.equal(x.status, 200); assert.ok(new crypto.X509Certificate(x.json.cert_pem).checkPrivateKey(crypto.createPrivateKey(x.json.key_pem)), 'the exported key belongs to the certificate');
  const a = e.app.store.auditTail(10).find((y) => y.action === 'certs.request.export');
  assert.ok(a && a.by === 'syed' && a.detail.include_key === true); assert.ok(!JSON.stringify(e.app.store.auditTail(40)).includes('PRIVATE KEY'));
  assert.ok(!JSON.stringify((await e.req('GET', '/certs', { role: 'viewer' })).json).includes('PRIVATE KEY'));
  assert.ok(!JSON.stringify(e.app.store.collection('cert_keys').all()).includes('PRIVATE KEY'), 'stored sealed');
  // cancel needs a reason
  const ep2 = await endpoint(e, 'b2.synthetic.test', ['b2.synthetic.test'], { ep: { issuer_kind: 'manual' } });
  const r2 = await post(e, '/certs/requests', { endpoint_id: ep2.id });
  assert.match((await post(e, '/certs/requests/' + r2.json.id + '/cancel', {})).json.error, /reason/);
  assert.equal((await post(e, '/certs/requests/' + r2.json.id + '/cancel', { reason: 'ordered elsewhere (synthetic)' })).json.status, 'cancelled');
});

test('auto-renewal: a flagged endpoint inside its lead time gets a request (same names) and the certificate, by system:pki', async (t) => {
  const { e, C } = await setup(t); await acmeSetup(e);
  const ep = await endpoint(e, 'auto.synthetic.test', ['auto.synthetic.test'], { not_after: Date.now() + 10 * DAY, ep: { auto_renew: true } });
  const quiet = await endpoint(e, 'manualonly.synthetic.test', ['manualonly.synthetic.test'], { not_after: Date.now() + 10 * DAY });
  await C.issue.tick();
  const q = C.issue.list().find((x) => x.endpoint_id === ep.id);
  assert.ok(q, 'request created'); assert.equal(q.requested_by, 'system:pki'); assert.equal(q.status, 'issued'); assert.deepEqual(q.names, ['auto.synthetic.test']);
  assert.ok(!C.issue.list().some((x) => x.endpoint_id === quiet.id), 'not flagged: nothing automatic');
  const v = (await e.req('GET', '/certs', { role: 'viewer' })).json;
  assert.equal(v.renewals.find((x) => x.endpoint_id === ep.id).status, 'issued');
  await C.issue.tick(); assert.equal(C.issue.list().filter((x) => x.endpoint_id === ep.id).length, 1, 'no second request');
});
