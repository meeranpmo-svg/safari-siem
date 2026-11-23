// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Certificate issuance (phase 2 of the certificate lifecycle). Python decides (pyengine/cert_rules.py: which names need a
 * second person, key policy, method, and whether an issued certificate is accepted); this file generates the key and the
 * CSR (engine/csr.js), talks to the CA (engine/acme.js, engine/adcs.js), seals every secret and commits.
 *
 *   Request: CQ-nnnn {endpoint_id, renewal_id?, method acme|adcs|manual, names[], key_type, key_bits, status, history}
 *     draft → awaiting-approval (names outside what the endpoint presents, or a wildcard: a DIFFERENT person approves)
 *           → acme: acme-validating → (awaiting-dns when only dns-01 is possible: a person publishes the TXT record)
 *           → adcs: adcs-pending while a CA manager holds it
 *           → manual: awaiting-certificate (the CSR is downloaded, the CA's certificate pasted back)
 *           → issued (checked: our key, every name, valid) | failed | cancelled
 *   The private key is generated here and SEALED at once (vault key, purpose sentra-itam-pki); the ACME account key, the EAB
 *   HMAC key and the AD CS password likewise. None of them is ever returned, logged or audited - except a private key an
 *   administrator EXPORTS with a reason (audited). Installation is phase 3: nothing here touches a server.
 *   Auto-renewal: an endpoint flagged auto_renew whose certificate is renew-due gets a request by system:pki with the SAME
 *   names (no approval needed), advanced automatically (ACME http-01, AD CS); dns-01 and manual still need a person.
 */
const fs = require('node:fs');
const path = require('node:path');
const { newKey, buildCsr, inspectCert } = require('./csr');
const { createAcme, newAccountKey } = require('./acme');
const { createAdcs } = require('./adcs');
const { createSealer } = require('./discovery/vault');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const OPEN = ['draft', 'awaiting-approval', 'acme-validating', 'awaiting-dns', 'adcs-pending', 'awaiting-certificate'];

function createIssuer(app, C, opts = {}) {
  const now = opts.now || Date.now, store = app.store, py = C.py;
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-pki' });
  const Q = () => store.collection('cert_requests'), IS = () => store.collection('cert_issuers'), K = () => store.collection('cert_keys');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const SYS = { user: 'system:pki', role: '' };
  const ask = async (op, body) => { const r = await py.call(op, body); if (r && r.ok === false) throw httpErr(409, 'The certificate rules run in Python and Python did not answer (' + (r.error_class || 'error') + ') - run the update'); return r; };
  const hist = (q, by, to, note) => { q.history = (q.history || []).concat([{ at: new Date(now()).toISOString(), by, from: q.status || null, to, note: String(note || '').slice(0, 400) }]); q.status = to; q.updated_ms = now(); };
  const pub = (q) => { const o = Object.assign({}, q); delete o.acme_secret; return o; };

  // ---------------------------------------------------------------- issuers (admin): secrets sealed, never returned
  function issuers() {
    const a = IS().get('acme'), d = IS().get('adcs');
    return { acme: a ? { directory_url: a.directory_url, contact: a.contact, eab: !!a.eab, http01_webroot: a.http01_webroot || '', account: a.kid ? 'registered' : 'not registered yet', updated_by: a.updated_by, updated_at: a.updated_at } : null,
      adcs: d ? { url: d.url, template: d.template, username: d.username, password_set: !!d.enc, updated_by: d.updated_by, updated_at: d.updated_at } : null, vault: sealer.available() ? 'available' : 'unavailable: ' + sealer.unavailableReason() };
  }
  function setAcme(b, who) {
    const cur = IS().get('acme') || { id: 'acme' };
    if (cur.directory_url && cur.directory_url !== b.directory_url) { delete cur.kid; delete cur.key; }   // another CA: another account
    const rec = Object.assign(cur, { directory_url: b.directory_url, contact: b.contact || '', http01_webroot: b.http01_webroot || '', updated_by: who.user, updated_at: new Date(now()).toISOString() });
    if (!rec.key) rec.key = sealer.seal('acme-account', newAccountKey());
    if (b.eab_kid && b.eab_hmac) { rec.eab = sealer.seal('acme-eab', JSON.stringify({ kid: b.eab_kid, hmac: b.eab_hmac })); delete rec.kid; }
    IS().put(rec); audit(who, 'certs.issuer.acme', 'acme', { directory_url: rec.directory_url, eab: !!rec.eab, http01_webroot: !!rec.http01_webroot });
    return issuers();
  }
  function setAdcs(b, who) {
    createAdcs({ url: b.url, template: b.template, username: 'x', password: 'x' });   // validates url + template
    const cur = IS().get('adcs') || { id: 'adcs' };
    const rec = Object.assign(cur, { url: b.url, template: b.template, username: b.username, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    if (b.password) rec.enc = sealer.seal('adcs-password', b.password);
    if (!rec.enc) throw httpErr(400, 'password is required the first time');
    IS().put(rec); audit(who, 'certs.issuer.adcs', 'adcs', { url: rec.url, template: rec.template, username: rec.username, password_changed: !!b.password });
    return issuers();
  }
  function acmeClient() {
    const a = IS().get('acme'); if (!a || !a.key) throw httpErr(409, 'ACME is not configured (Certificates → Issuers, admin)');
    return { rec: a, client: createAcme(a.directory_url, { accountKeyPem: sealer.unseal('acme-account', a.key), kid: a.kid, request: opts.acmeRequest }) };
  }
  function adcsClient() {
    const d = IS().get('adcs'); if (!d || !d.enc) throw httpErr(409, 'AD CS is not configured (Certificates → Issuers, admin)');
    return createAdcs({ url: d.url, template: d.template, username: d.username, password: sealer.unseal('adcs-password', d.enc), caPem: opts.adcsCa, request: opts.adcsRequest });
  }

  // ---------------------------------------------------------------- requests
  async function create(b, who) {
    const ep = store.collection('cert_endpoints').get(b.endpoint_id); if (!ep || ep.retired) throw httpErr(404, 'no certificate endpoint ' + b.endpoint_id);
    if (Q().all((q) => q.endpoint_id === ep.id && OPEN.includes(q.status)).length) throw httpErr(409, 'a request is already in progress for ' + ep.id);
    if (!sealer.available()) throw httpErr(409, 'the key vault is unavailable (' + sealer.unavailableReason() + '): private keys cannot be stored');
    const sc = (store.collection('cert_scans').get(ep.id) || {}).scan || {};
    const plan = await ask('certs.plan_request', { endpoint: ep, scan: sc, policy: (store.collection('cert_policy').get('policy') || {}), names: b.names, method: b.method, key_type: b.key_type, key_bits: b.key_bits });
    if (plan.refuse) throw httpErr(plan.refuse.status, plan.refuse.error);
    let n = Q().all().length + 1, id; do { id = 'CQ-' + String(n++).padStart(4, '0'); } while (Q().get(id));
    const k = newKey({ type: plan.key_type, bits: plan.key_bits });
    K().put({ id, enc: sealer.seal('key|' + id, k.keyPem) });
    const csr = buildCsr(k.privateKey, plan.names, { o: (app.config && app.config.org_name) || undefined });
    const q = { id, endpoint_id: ep.id, renewal_id: b.renewal_id || null, method: plan.method, names: plan.names, key_type: plan.key_type, key_bits: plan.key_bits, csr_pem: csr.pem,
      requested_by: who.user, created_ms: now(), created_at: new Date(now()).toISOString(), approval: plan.needs_approval ? { needed: true, why: plan.why } : null, history: [] };
    hist(q, who.user, 'draft', 'requested ' + plan.method + ' for ' + plan.names.join(', '));
    if (plan.needs_approval) hist(q, who.user, 'awaiting-approval', plan.why.join('; '));
    Q().put(q); audit(who, 'certs.request.create', id, { endpoint: ep.id, method: plan.method, names: plan.names, key: plan.key_type + plan.key_bits, needs_approval: plan.needs_approval });
    if (!plan.needs_approval) await advance(id, who);
    return pub(Q().get(id));
  }
  async function approve(id, who) {
    const q = Q().get(id); if (!q) throw httpErr(404, 'no request ' + id);
    if (q.status !== 'awaiting-approval') throw httpErr(409, 'request ' + id + ' is ' + q.status + ', not waiting for approval');
    if (q.requested_by === who.user) throw httpErr(403, 'a different person must approve the names - you requested them');
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot approve');
    q.approval = Object.assign({}, q.approval, { by: who.user, at: new Date(now()).toISOString() });
    hist(q, who.user, 'draft', 'names approved by ' + who.user); Q().put(q);
    audit(who, 'certs.request.approve', id, { names: q.names, requested_by: q.requested_by });
    await advance(id, who);
    return pub(Q().get(id));
  }
  function fail(q, by, e) { q.error = String((e && e.message) || e).slice(0, 400); hist(q, by.user, 'failed', q.error); Q().put(q); audit(by, 'certs.request.failed', q.id, { error: q.error }); }
  async function issued(q, by, pem) {
    const keyPem = sealer.unseal('key|' + q.id, K().get(q.id).enc);
    const f = inspectCert(pem, require('node:crypto').createPrivateKey(keyPem));
    const verdict = await ask('certs.accept_issued', { request: q, facts: Object.assign({}, f, { leaf_pem: undefined, chain_pem: undefined }), now: now(), policy: store.collection('cert_policy').get('policy') || {} });
    if (!verdict.accept) throw httpErr(422, 'certificate not accepted: ' + verdict.problems.join('; '));
    Object.assign(q, { cert_pem: f.leaf_pem, chain_pem: f.chain_pem, fingerprint256: f.fingerprint256, serial: f.serial, not_after: f.not_after, issuer: f.issuer });
    hist(q, by.user, 'issued', 'serial ' + f.serial + ', expires ' + new Date(f.not_after).toISOString().slice(0, 10) + ' - checked: our key, every name');
    Q().put(q); audit(by, 'certs.request.issued', q.id, { serial: f.serial, fingerprint256: f.fingerprint256, not_after: f.not_after });
    if (q.renewal_id && C.moveRenewalTo) C.moveRenewalTo(q.renewal_id, 'issued', by, 'certificate ' + q.id + ' issued (serial ' + f.serial + ')');
  }
  // one step forward; safe to call again (from a person, after a DNS record is published, or the minute tick)
  async function advance(id, who) {
    const q = Q().get(id); if (!q) throw httpErr(404, 'no request ' + id);
    if (!['draft', 'acme-validating', 'awaiting-dns', 'adcs-pending'].includes(q.status)) return pub(q);
    try {
      if (q.method === 'manual') { hist(q, who.user, 'awaiting-certificate', 'download the CSR, order the certificate, paste it back'); Q().put(q); return pub(q); }
      if (q.method === 'adcs') {
        const ca = adcsClient();
        const r = q.adcs && q.adcs.req_id ? await ca.fetch(q.adcs.req_id) : await ca.submit(q.csr_pem);
        q.adcs = { req_id: r.reqId };
        if (r.status === 'pending') { if (q.status !== 'adcs-pending') hist(q, who.user, 'adcs-pending', 'held by the AD CS manager (request ' + r.reqId + ')'); Q().put(q); return pub(q); }
        await issued(q, who, r.pem); return pub(Q().get(id));
      }
      // ACME
      const { rec, client } = acmeClient();
      if (!rec.kid) { const eab = rec.eab ? JSON.parse(sealer.unseal('acme-eab', rec.eab)) : null; const acc = await client.account({ contact: rec.contact, eab }); rec.kid = acc.kid; IS().put(rec); }
      if (!q.acme || !q.acme.order) { const o = await client.newOrder(q.names); q.acme = { order: o.url, finalize: o.finalize, authz: [] }; hist(q, who.user, 'acme-validating', 'order placed'); Q().put(q); }
      let order = await client.poll(q.acme.order);
      if (order.status === 'pending') {
        const az = await client.authorizations(Object.assign({ url: q.acme.order }, order)), pendingDns = [];
        for (const a of az) {
          if (a.status === 'valid') continue;
          if (a.status === 'invalid') throw new Error('validation failed for ' + a.name);
          const h = a.challenges.http01, d = a.challenges.dns01;
          if (h && rec.http01_webroot && !a.wildcard) {
            const dir = path.join(rec.http01_webroot, '.well-known', 'acme-challenge'); fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
            fs.writeFileSync(path.join(dir, h.token), h.keyAuthorization, { mode: 0o644 });
            if (h.status === 'pending') await client.respond(h.url);
          } else if (d) {
            pendingDns.push({ name: a.name, record: '_acme-challenge.' + a.name.replace(/^\*\./, ''), txt: d.txt, url: d.url, status: d.status });
          } else throw new Error('no usable challenge for ' + a.name + (h ? ' (set the http-01 web root in Issuers)' : ''));
        }
        q.acme.dns = pendingDns;
        if (pendingDns.length && !who.dnsPublished) {
          if (q.status !== 'awaiting-dns') hist(q, who.user, 'awaiting-dns', 'publish ' + pendingDns.length + ' TXT record(s), then press "DNS published"');
          Q().put(q); return pub(q);
        }
        if (pendingDns.length) { for (const p of pendingDns) if (p.status === 'pending') await client.respond(p.url); hist(q, who.user, 'acme-validating', 'DNS records published - validation asked'); }
        Q().put(q); order = await client.poll(q.acme.order);
      }
      if (order.status === 'invalid') throw new Error('the ACME order is invalid (a validation failed)');
      if (order.status === 'ready') { order = await client.finalize(Object.assign({ url: q.acme.order }, order), Buffer.from(q.csr_pem.replace(/-----[^-]+-----|\s/g, ''), 'base64')); }
      if (order.status === 'processing') order = await client.poll(q.acme.order);
      if (order.status === 'valid' && order.certificate) { await issued(q, who, await client.download(order.certificate)); return pub(Q().get(id)); }
      Q().put(q); return pub(q);
    } catch (e) {
      if (e.status === 409 && /not configured|Python/.test(e.message)) throw e;   /* a setup problem: say so, keep the request */
      fail(Q().get(id) || q, who, e); return pub(Q().get(id));
    }
  }
  async function upload(id, pem, who) {
    const q = Q().get(id); if (!q) throw httpErr(404, 'no request ' + id);
    if (!['awaiting-certificate', 'adcs-pending'].includes(q.status)) throw httpErr(409, 'request ' + id + ' is ' + q.status + ' - a certificate is pasted only for a manual order or a held AD CS request');
    await issued(q, who, pem); return pub(Q().get(id));
  }
  function cancel(id, reason, who) {
    const q = Q().get(id); if (!q) throw httpErr(404, 'no request ' + id);
    if (!OPEN.includes(q.status)) throw httpErr(409, 'request ' + id + ' is ' + q.status);
    hist(q, who.user, 'cancelled', reason); Q().put(q); audit(who, 'certs.request.cancel', id, { reason }); return pub(q);
  }
  // administrator export for installation by hand (until phase 3): the certificate, the chain and - with a reason - the key
  function exportBundle(id, b, who) {
    const q = Q().get(id); if (!q || q.status !== 'issued') throw httpErr(409, 'only an issued certificate can be exported');
    const out = { id, cert_pem: q.cert_pem, chain_pem: q.chain_pem || '' };
    if (b.include_key) { out.key_pem = sealer.unseal('key|' + id, K().get(id).enc); q.key_exported = (q.key_exported || []).concat([{ by: who.user, at: new Date(now()).toISOString(), reason: b.reason }]); Q().put(q); }
    audit(who, 'certs.request.export', id, { include_key: !!b.include_key, reason: b.reason });
    return out;
  }
  // auto-renewal + the minute tick: renew-due endpoints flagged auto_renew get a request (same names); open ones move on
  async function tick() {
    const a = await C.assess();
    for (const e of a.endpoints) {
      const ep = store.collection('cert_endpoints').get(e.id);
      if (!ep || !ep.auto_renew || !['renew-due', 'expiring', 'expired'].includes(e.state)) continue;
      if (Q().all((q) => q.endpoint_id === e.id && (OPEN.includes(q.status) || (q.status === 'issued' && now() - q.updated_ms < 14 * 86400000))).length) continue;
      let rn = null; try { rn = C.openRenewal({ endpoint_id: e.id, note: 'automatic renewal (' + e.state + ')' }, SYS); } catch (x) { rn = null; }
      try { await create({ endpoint_id: e.id, renewal_id: rn && rn.id }, SYS); } catch (x) { if (app.log && app.log.every) app.log.every('certs:auto:' + e.id, 3600000, 'warn', 'automatic certificate renewal could not start', { endpoint: e.id, err: String(x.message).slice(0, 200) }); }
    }
    for (const q of Q().all((x) => ['acme-validating', 'adcs-pending'].includes(x.status))) await advance(q.id, SYS);
  }
  return { issuers, setAcme, setAdcs, create, approve, advance, upload, cancel, exportBundle, tick,
    list: () => Q().all().sort((x, y) => y.created_ms - x.created_ms).slice(0, 300).map(pub), get: (id) => { const q = Q().get(id); return q ? pub(q) : null; } };
}

module.exports = { createIssuer, OPEN };
