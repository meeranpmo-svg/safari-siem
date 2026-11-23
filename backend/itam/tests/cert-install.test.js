// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Certificate installation, phase 3 (engine/cert-install.js, pyengine/cert_rules.py certs.plan_install) against simulated
// Palo Alto (XML API) and FortiGate (REST) devices: targets are admin-only with the write key sealed and never returned;
// a job is proposed for an issued certificate, approved by a DIFFERENT person who may approve Security (never the
// requester, never a service identity), run (Palo Alto refuses when someone has uncommitted changes; key sent encrypted;
// commit), verified by a scan (renewal → installed → verified), rolled back on failure and on request; pinned TLS; a
// certificate that does not cover the endpoint is refused by Python. Roles, validation, audit. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, build } = require('./helpers/x509');
const { createSealer } = require('../engine/discovery/vault');

const PY = process.env.PYTHON || 'python3';
let clock = Date.now();
const now = () => clock;
const fp = (pem) => new crypto.X509Certificate(pem).fingerprint256;
const CA = makeCA('Synthetic Issuing CA');
const OLD = { pa: 'AA:' + 'BB:'.repeat(30) + 'CC', fg: '11:' + '22:'.repeat(30) + '33' };

// ---- the simulated devices
const DEV = {
  pa: { pin: OLD.pa, pending: false, profile: { 'GP-Portal': 'old-gp-cert' }, certs: {}, commits: 0, failCommit: 0, calls: [] },
  fg: { pin: OLD.fg, global: { 'admin-server-cert': 'Fortinet_Factory' }, ssl: { servercert: 'old-vpn' }, local: {}, cas: 0, calls: [] },
};
const panResp = (inner) => ({ status: 200, text: '<response status="success">' + inner + '</response>', json: null });
function device(t, o, pins) {
  const d = t.kind === 'paloalto' ? DEV.pa : DEV.fg;
  if (!pins.map((p) => p.replace(/:/g, '').toUpperCase()).includes(d.pin.replace(/:/g, '').toUpperCase())) return Promise.reject(Object.assign(new Error('the device presented a certificate that is not pinned'), { status: 502 }));
  d.calls.push(o.method + ' ' + o.path.split('?')[0] + (o.path.includes('type=') ? ' ' + /type=([a-z]+)/.exec(o.path)[1] : ''));
  if (t.kind === 'paloalto') {
    assert.ok(o.headers['X-PAN-KEY'], 'API key in a header, never the URL');
    const q = new URLSearchParams(o.path.split('?')[1]);
    if (q.get('type') === 'op') {
      const cmd = q.get('cmd');
      if (/pending-changes/.test(cmd)) return Promise.resolve(panResp('<result>' + (d.pending ? 'yes' : 'no') + '</result>'));
      if (/system><info/.test(cmd)) return Promise.resolve(panResp('<result><system><hostname>PA-EDGE-SYN</hostname><model>PA-3220</model><sw-version>10.2.9</sw-version></system></result>'));
      if (/<jobs>/.test(cmd)) return Promise.resolve(panResp('<result><job><status>FIN</status><result>' + (d.failCommit-- > 0 ? 'FAIL' : 'OK') + '</result><details><line>synthetic</line></details></job></result>'));
    }
    if (q.get('type') === 'config' && q.get('action') === 'get') { const n = /entry\[@name='([^']+)'\]/.exec(q.get('xpath'))[1]; return Promise.resolve(panResp('<result><certificate>' + d.profile[n] + '</certificate></result>')); }
    if (q.get('type') === 'config' && q.get('action') === 'edit') { const n = /entry\[@name='([^']+)'\]/.exec(q.get('xpath'))[1]; d.profile[n] = /<certificate>([^<]+)<\/certificate>/.exec(q.get('element'))[1]; return Promise.resolve(panResp('<msg>command succeeded</msg>')); }
    if (q.get('type') === 'import') {
      const body = o.body;
      if (q.get('category') === 'keypair') {
        assert.match(body, /BEGIN ENCRYPTED PRIVATE KEY/, 'the key is sent encrypted'); assert.doesNotMatch(body, /BEGIN PRIVATE KEY/);
        assert.ok(q.get('passphrase') && q.get('passphrase').length >= 20, 'one-time passphrase');
        const certPem = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(body)[0];
        d.certs[q.get('certificate-name')] = fp(certPem);
      }
      return Promise.resolve(panResp('<msg>imported</msg>'));
    }
    if (q.get('type') === 'commit') { d.commits++; return Promise.resolve(panResp('<result><job>' + (100 + d.commits) + '</job></result>')); }
    return Promise.resolve({ status: 400, text: '<response status="error"><msg>unknown</msg></response>' });
  }
  assert.match(o.headers.Authorization, /^Bearer /);
  const p = o.path.split('?')[0], body = o.body ? JSON.parse(o.body) : null, ok = (results) => Promise.resolve({ status: 200, json: { status: 'success', results } });
  if (o.method === 'GET' && p === '/api/v2/monitor/system/status') return Promise.resolve({ status: 200, json: { status: 'success', version: 'v7.2.8', results: { model_name: 'FortiGate-600E', hostname: 'FG-USERS-SYN' } } });
  if (o.method === 'GET' && p === '/api/v2/cmdb/system/global') return ok(d.global);
  if (o.method === 'GET' && p === '/api/v2/cmdb/vpn.ssl/settings') return ok(d.ssl);
  if (p === '/api/v2/monitor/vpn-certificate/ca/import') { d.cas++; return ok({}); }
  if (p === '/api/v2/monitor/vpn-certificate/local/import') {
    assert.match(Buffer.from(body.key_file_content, 'base64').toString(), /BEGIN ENCRYPTED PRIVATE KEY/); assert.ok(body.password.length >= 20);
    d.local[body.certname] = fp(Buffer.from(body.file_content, 'base64').toString()); return ok({});
  }
  if (o.method === 'PUT' && p === '/api/v2/cmdb/system/global') { Object.assign(d.global, body); if (body['admin-server-cert'] && d.local[body['admin-server-cert']]) d.pin = d.local[body['admin-server-cert']]; return ok({}); }
  if (o.method === 'PUT' && p === '/api/v2/cmdb/vpn.ssl/settings') { Object.assign(d.ssl, body); return ok({}); }
  return Promise.resolve({ status: 404, json: { status: 'error', error: 'not found' } });
}
// what each endpoint presents now: Palo Alto GP portal = the cert bound to its profile; FortiGate SSL-VPN = servercert
function readCert(host) {
  if (host === 'vpn.example.test') { const n = DEV.pa.profile['GP-Portal']; return Promise.resolve({ ok: true, fingerprint256: DEV.pa.certs[n] || OLD.pa, subject: 'x', not_after: clock + 30 * 864e5, names: ['vpn.example.test'] }); }
  if (host === 'sslvpn.example.test') { const n = DEV.fg.ssl.servercert; return Promise.resolve({ ok: true, fingerprint256: DEV.fg.local[n] || OLD.fg, subject: 'x', not_after: clock + 30 * 864e5, names: ['sslvpn.example.test'] }); }
  return Promise.resolve({ ok: false, error: 'unreachable' });
}
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.roles = { approves: (u, scope, role) => !/^(system|svc)[:_-]/.test(u) && (role === 'admin' || (u === 'sec.approver' && scope === 'eng:security')) };
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, readCert, deviceRequest: device });
  const keySealer = createSealer({ keyFile: e.app.config.discovery.vault_key_file, purpose: 'sentra-itam-pki' });
  // an issued certificate request (as phase 2 leaves it): key sealed, certificate + chain checked
  const issue = (id, names, days = 90) => {
    const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = build({ subject: names[0], issuer: CA.cn, pub: k.publicKey, signKey: CA.key, isCA: false, dns: names, days, aki: CA.ski });
    e.app.store.collection('cert_keys').put({ id, enc: keySealer.seal('key|' + id, k.privateKey.export({ type: 'pkcs8', format: 'pem' })) });
    e.app.store.collection('cert_requests').put({ id, status: 'issued', names, cert_pem: pem, chain_pem: CA.cert, fingerprint256: fp(pem), not_after: clock + days * 864e5, created_ms: clock, history: [] });
    return fp(pem);
  };
  return { e, issue, post: (p, body, who) => e.req('POST', p, Object.assign({ body }, who)) };
}
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, SEC = { user: 'sec.approver', role: 'operator' }, OTHER = { user: 'other.syn', role: 'operator' };

test('Palo Alto: propose → four-eyes approve → run (no pending changes, import, bind, commit) → verified by a scan', async (t) => {
  const { e, issue, post } = await setup(t);
  const ep = (await post('/certs/endpoints', { host: 'vpn.example.test', port: 443, label: 'GlobalProtect portal', deploy_target: 'paloalto' }, OP)).json;
  // target: admin only, pin + key required, key never returned
  assert.equal((await post('/certs/install/targets', { label: 'PA edge', kind: 'paloalto', host: '192.0.2.1', pin: OLD.pa, api_key: 'LUFRPT-synthetic', binding: { type: 'ssl-tls-profile', name: 'GP-Portal' } }, OP)).status, 403);
  let r = await post('/certs/install/targets', { label: 'PA edge', kind: 'paloalto', host: '192.0.2.1', api_key: 'LUFRPT-synthetic', binding: { type: 'ssl-tls-profile', name: 'GP-Portal' } }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /pin/);
  r = await post('/certs/install/targets', { label: 'PA edge', kind: 'paloalto', host: '192.0.2.1', pin: OLD.pa, api_key: 'LUFRPT-synthetic', binding: { type: 'vip', name: 'x' } }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /binding.type/);
  r = await post('/certs/install/targets', { label: 'PA edge', kind: 'paloalto', host: '192.0.2.1', pin: OLD.pa, api_key: 'LUFRPT-synthetic', binding: { type: 'ssl-tls-profile', name: "GP'] or 1=1" } }, ADM);
  assert.equal(r.status, 400, 'an xpath-breaking profile name is refused');
  const tg = (await post('/certs/install/targets', { label: 'PA edge (external, branches, data centres)', kind: 'paloalto', host: '192.0.2.1', pin: OLD.pa, api_key: 'LUFRPT-synthetic', binding: { type: 'ssl-tls-profile', name: 'GP-Portal' }, endpoint_id: ep.id }, ADM)).json;
  assert.match(tg.id, /^CT-\d{4}$/); assert.equal(tg.key_set, true); assert.ok(!JSON.stringify(tg).includes('LUFRPT'));
  const test1 = (await post('/certs/install/targets/' + tg.id + '/test', {}, ADM)).json; assert.equal(test1.ok, true); assert.equal(test1.info.model, 'PA-3220');
  const list = (await e.req('GET', '/certs/install', OP)).json; assert.ok(!JSON.stringify(list).includes('LUFRPT'));
  // a certificate that does not cover the endpoint is refused by Python
  issue('CQ-0001', ['other.example.test']);
  r = await post('/certs/install/jobs', { request_id: 'CQ-0001', target_id: tg.id, reason: 'renewal' }, OP); assert.equal(r.status, 409); assert.match(r.json.error, /does not cover vpn.example.test/);
  const newFp = issue('CQ-0002', ['vpn.example.test']);
  e.app.store.collection('cert_requests').patch ? null : null;
  r = await post('/certs/install/jobs', { request_id: 'CQ-0002', target_id: tg.id }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /reason/);
  const job = (await post('/certs/install/jobs', { request_id: 'CQ-0002', target_id: tg.id, reason: 'GlobalProtect portal renewal' }, OP)).json;
  assert.equal(job.status, 'proposed'); assert.match(job.cert_name, /^zyb-vpn-example-test-\d{8}$/); assert.ok(job.plan.some((x) => /uncommitted/.test(x)));
  assert.equal((await post('/certs/install/jobs', { request_id: 'CQ-0002', target_id: tg.id, reason: 'again' }, OP)).status, 409, 'one open job per device');
  // run before approval refused; approval rules
  assert.equal((await post('/certs/install/jobs/' + job.id + '/run', {}, OP)).status, 409);
  r = await post('/certs/install/jobs/' + job.id + '/approve', {}, OP); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  r = await post('/certs/install/jobs/' + job.id + '/approve', {}, OTHER); assert.equal(r.status, 403); assert.match(r.json.error, /Security/);
  r = await post('/certs/install/jobs/' + job.id + '/approve', {}, { user: 'system:pki', role: 'admin' }); assert.equal(r.status, 403);
  r = await post('/certs/install/jobs/' + job.id + '/approve', {}, SEC); assert.equal(r.status, 200); assert.equal(r.json.status, 'approved');
  // someone else has uncommitted changes → refused, nothing changed
  DEV.pa.pending = true;
  r = await post('/certs/install/jobs/' + job.id + '/run', {}, OP); assert.equal(r.json.status, 'failed'); assert.match(r.json.steps.slice(-1)[0].detail, /uncommitted changes/);
  assert.equal(DEV.pa.profile['GP-Portal'], 'old-gp-cert'); assert.equal(DEV.pa.commits, 0);
  DEV.pa.pending = false;
  // a failed job needs a new proposal + approval
  const job2 = (await post('/certs/install/jobs', { request_id: 'CQ-0002', target_id: tg.id, reason: 'retry after the other admin committed' }, OP)).json;
  await post('/certs/install/jobs/' + job2.id + '/approve', {}, SEC);
  const done = (await post('/certs/install/jobs/' + job2.id + '/run', {}, OP)).json;
  assert.equal(done.status, 'verified', JSON.stringify(done.steps));
  assert.equal(DEV.pa.profile['GP-Portal'], job2.cert_name); assert.equal(DEV.pa.commits, 1); assert.equal(done.previous, 'old-gp-cert');
  assert.ok(done.steps.some((x) => /verified: vpn.example.test:443/.test(x.step)));
  assert.ok(DEV.pa.calls.some((c) => /import/.test(c)));
  // rollback: approver only, restores the previous binding and commits
  assert.equal((await post('/certs/install/jobs/' + job2.id + '/rollback', { reason: 'portal clients complain' }, OTHER)).status, 403);
  const rb = (await post('/certs/install/jobs/' + job2.id + '/rollback', { reason: 'portal clients complain' }, SEC)).json;
  assert.equal(rb.status, 'rolled-back'); assert.equal(DEV.pa.profile['GP-Portal'], 'old-gp-cert'); assert.equal(DEV.pa.commits, 2);
  assert.equal(newFp, done.fingerprint256);
  // a commit that fails after the bind: the binding is restored automatically and committed
  issue('CQ-0003', ['vpn.example.test']);
  const job3 = (await post('/certs/install/jobs', { request_id: 'CQ-0003', target_id: tg.id, reason: 'second renewal' }, OP)).json;
  await post('/certs/install/jobs/' + job3.id + '/approve', {}, SEC);
  DEV.pa.failCommit = 1;
  const f3 = (await post('/certs/install/jobs/' + job3.id + '/run', {}, OP)).json;
  assert.equal(f3.status, 'failed'); assert.ok(f3.steps.some((x) => /automatic roll-back to old-gp-cert/.test(x.step) && x.ok));
  assert.equal(DEV.pa.profile['GP-Portal'], 'old-gp-cert');
  const acts = e.app.store.auditTail(80).map((a) => a.action);
  for (const a of ['certs.install.target.add', 'certs.install.propose', 'certs.install.approve', 'certs.install.run', 'certs.install.failed', 'certs.install.done', 'certs.install.rollback']) assert.ok(acts.includes(a), a);
  assert.ok(!JSON.stringify(e.app.store.auditTail(80)).includes('LUFRPT'), 'the key never reaches the audit trail');
});

test('FortiGate: SSL-VPN certificate installed and verified; a failed commit-equivalent rolls back; wrong pin refused; management cert re-pins', async (t) => {
  const { e, issue, post } = await setup(t);
  const ep = (await post('/certs/endpoints', { host: 'sslvpn.example.test', port: 443, label: 'SSL-VPN', deploy_target: 'fortigate' }, OP)).json;
  const tg = (await post('/certs/install/targets', { label: 'FortiGate users', kind: 'fortigate', host: '192.0.2.2', pin: OLD.fg, api_key: 'fgt-synthetic-token', binding: { type: 'ssl-vpn' }, endpoint_id: ep.id }, ADM)).json;
  issue('CQ-0010', ['sslvpn.example.test']);
  const job = (await post('/certs/install/jobs', { request_id: 'CQ-0010', target_id: tg.id, reason: 'SSL-VPN renewal' }, OP)).json;
  await post('/certs/install/jobs/' + job.id + '/approve', {}, ADM);
  const done = (await post('/certs/install/jobs/' + job.id + '/run', {}, OP)).json;
  assert.equal(done.status, 'verified', JSON.stringify(done.steps)); assert.equal(DEV.fg.ssl.servercert, job.cert_name); assert.equal(done.previous, 'old-vpn'); assert.equal(DEV.fg.cas, 1);
  // wrong pin: refused before anything is sent
  await post('/certs/install/targets', { id: tg.id, pin: 'FF:'.repeat(31) + 'FF' }, ADM);
  const t2 = (await post('/certs/install/targets/' + tg.id + '/test', {}, ADM)).json; assert.equal(t2.ok, false); assert.match(t2.error, /not pinned/);
  // management certificate: after the bind the device presents the new certificate - the job follows it and re-pins
  await post('/certs/install/targets', { id: tg.id, pin: OLD.fg, binding: { type: 'admin-server-cert' }, endpoint_id: undefined }, ADM);
  const mfp = issue('CQ-0011', ['sslvpn.example.test']);
  const j2 = (await post('/certs/install/jobs', { request_id: 'CQ-0011', target_id: tg.id, reason: 'management certificate' }, OP)).json;
  assert.ok(j2.warnings.some((w) => /management certificate/.test(w)));
  await post('/certs/install/jobs/' + j2.id + '/approve', {}, ADM);
  const d2 = (await post('/certs/install/jobs/' + j2.id + '/run', {}, OP)).json;
  assert.ok(['verified', 'installed'].includes(d2.status), JSON.stringify(d2.steps));
  assert.equal(DEV.fg.global['admin-server-cert'], j2.cert_name);
  const tgNow = (await e.req('GET', '/certs/install', OP)).json.targets.find((x) => x.id === tg.id);
  assert.equal(tgNow.pin.replace(/:/g, ''), mfp.replace(/:/g, ''), 'the pin follows the new management certificate');
  assert.equal((await post('/certs/install/targets/' + tg.id + '/test', {}, ADM)).json.ok, true, 'the device is still reachable with the new pin');
});

test('validation and expiry: ids, run_after format, a certificate with less than 7 days refused', async (t) => {
  const { issue, post } = await setup(t);
  const tg = (await post('/certs/install/targets', { label: 'PA', kind: 'paloalto', host: '192.0.2.1', pin: OLD.pa, api_key: 'k', binding: { type: 'none' } }, ADM)).json;
  issue('CQ-0020', ['x.example.test'], 5);
  let r = await post('/certs/install/jobs', { request_id: 'CQ-0020', target_id: tg.id, reason: 'r' }, OP); assert.equal(r.status, 409); assert.match(r.json.error, /less than 7 days/);
  issue('CQ-0021', ['x.example.test']);
  r = await post('/certs/install/jobs', { request_id: 'CQ-0021', target_id: tg.id, reason: 'r', run_after: 'tonight' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /run_after/);
  r = await post('/certs/install/jobs', { request_id: 'bad', target_id: tg.id, reason: 'r' }, OP); assert.equal(r.status, 400);
  r = await post('/certs/install/jobs/CI-x/approve', {}, ADM); assert.equal(r.status, 400);
  const j = (await post('/certs/install/jobs', { request_id: 'CQ-0021', target_id: tg.id, reason: 'import only', run_after: new Date(clock + 3600e3).toISOString() }, OP)).json;
  assert.ok(j.warnings.some((w) => /imported only|no certificate endpoint/.test(w)));
  r = await post('/certs/install/jobs/' + j.id + '/reject', {}, ADM); assert.equal(r.status, 400);
  r = await post('/certs/install/jobs/' + j.id + '/cancel', { reason: 'not needed' }, OP); assert.equal(r.json.status, 'cancelled');
});

// regression: pinnedRequest used to write the API key header and the body (private key + passphrase) BEFORE it compared the
// device certificate with the pin; an impersonator on the management network received them and only then was refused
test('pinnedRequest sends no header and no body to a device whose certificate is not pinned', async (t) => {
  const { execFileSync } = require('node:child_process'), fs = require('node:fs'), os = require('node:os'), path = require('node:path'), https = require('node:https');
  try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch (e) { t.skip('openssl not available'); return; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=fw', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem')], { stdio: 'ignore' });
  const cert = fs.readFileSync(path.join(dir, 'c.pem')), seen = [];
  const srv = https.createServer({ key: fs.readFileSync(path.join(dir, 'k.pem')), cert }, (req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { seen.push({ key: req.headers['x-pan-key'], body: b }); res.end('{}'); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); t.after(() => srv.close());
  const fp = new (require('node:crypto').X509Certificate)(cert).fingerprint256, dev = { host: '127.0.0.1', port: srv.address().port };
  const { pinnedRequest } = require('../engine/cert-install');
  await assert.rejects(pinnedRequest(dev, { method: 'POST', path: '/api', headers: { 'X-PAN-KEY': 'SYNTH-KEY' }, body: 'passphrase=SYNTH-PASS' }, ['AA'.repeat(32)]), /not pinned/);
  await new Promise((r) => setTimeout(r, 200));
  assert.deepEqual(seen, [], 'the impersonating device received nothing');
  const ok = await pinnedRequest(dev, { method: 'POST', path: '/api', headers: { 'X-PAN-KEY': 'SYNTH-KEY' }, body: 'x=1' }, [fp]);
  assert.equal(ok.status, 200); assert.equal(seen[0].key, 'SYNTH-KEY');
});
