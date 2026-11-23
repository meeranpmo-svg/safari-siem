// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Certificate installation - phase 3 of the certificate lifecycle: Palo Alto (PAN-OS XML API) and FortiGate (FortiOS REST).
 * Python decides whether an installation may go ahead (pyengine/cert_rules.py certs.plan_install: the certificate was
 * issued and checked here, has 7+ days left, covers the name the endpoint is reached by, the binding exists); this file
 * talks to the device and commits.
 *
 * Install targets CT-nnnn (administrator): device kind, host, port, the device's TLS certificate fingerprint (PINNED - a
 * device presenting another certificate is refused), a WRITE API key (sealed at once in the vault, purpose
 * sentra-itam-pki-install, never returned or logged; give it the narrowest admin role that can import certificates and edit
 * the one binding), what the certificate is bound to (Palo Alto: an SSL/TLS service profile; FortiGate: the admin GUI
 * certificate, SSL-VPN, or a virtual server) and the certificate endpoint used to verify.
 *
 * Install jobs CI-nnnn: proposed (an operator, for an issued request) → approved (a DIFFERENT person: an administrator or a
 * human approver for Security - never the requester, never a service / AI identity) → running → verified (a scan of the
 * endpoint shows the new fingerprint; the renewal moves to installed and the scan confirms it) | installed (no endpoint to
 * scan: the device accepted it) | failed (with automatic roll-back of the binding when the failure came after it) →
 * rolled-back (an approver restores the previous binding). rejected / cancelled close a job before it runs.
 * Steps on Palo Alto: refuse if anyone has uncommitted changes (a commit would push them too) · read the binding in use ·
 * import the CA chain and the key pair (PEM, the key encrypted with a one-time passphrase) · edit the profile's certificate
 * · commit and wait for the job. On FortiGate: read the binding · import the CA chain and the local certificate · set the
 * binding (applied at once). Every step is logged on the job and the whole job is audited.
 */
const https = require('node:https');
const crypto = require('node:crypto');
const { createSealer } = require('./discovery/vault');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n = 300) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').slice(0, n);
const normFp = (v) => String(v || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
const NAME_RE = /^[A-Za-z0-9 ._-]{1,63}$/;
const SCOPE = 'eng:security';

// one HTTPS request to a device whose certificate fingerprint must be one of `pins`
function pinnedRequest(t, o, pins) {
  return new Promise((resolve, reject) => {
    const r = https.request({ host: t.host, port: t.port || 443, method: o.method || 'GET', path: o.path, headers: o.headers || {}, rejectUnauthorized: false, agent: false, timeout: 30000, servername: /^[\d.]+$/.test(t.host) ? undefined : t.host }, (res) => {
      const fp = normFp(res.socket.getPeerCertificate && res.socket.getPeerCertificate().fingerprint256);
      if (!pins.map(normFp).includes(fp)) { res.destroy(); return reject(httpErr(502, 'the device presented a certificate that is not pinned (' + fp.slice(0, 16) + '…) - check it is the right device, then update the pin')); }
      let d = ''; res.setEncoding('utf8'); res.on('data', (c) => { d += c; if (d.length > 4e6) r.destroy(new Error('answer too large')); });
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch (e) { /* XML or empty */ } resolve({ status: res.statusCode, text: d, json: j }); });
    });
    r.on('timeout', () => r.destroy(new Error('device timeout'))); r.on('error', reject);
    // nothing - no API key header, no private key in the body - is written until the certificate matches a pin
    r.on('socket', (sock) => sock.once('secureConnect', () => {
      const fp = normFp(sock.getPeerCertificate && sock.getPeerCertificate().fingerprint256);
      if (!pins.map(normFp).includes(fp)) { r.destroy(httpErr(502, 'the device presented a certificate that is not pinned (' + fp.slice(0, 16) + '…) - check it is the right device, then update the pin')); return; }
      if (o.body) r.write(o.body); r.end();
    }));
  });
}

const xmlTag = (x, tag) => { const m = new RegExp('<' + tag + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + tag + '>').exec(x || ''); return m ? m[1].trim() : null; };
const xmlOk = (x) => /<response[^>]*status=["']success["']/.test(x || '');
const xmlMsg = (x) => s((xmlTag(x, 'msg') || xmlTag(x, 'line') || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() || 'no message', 200);
const xesc = (v) => String(v).replace(/[<>&'"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[c]));

function panos(req, t, key, pins) {
  const H = { 'X-PAN-KEY': key };
  const call = async (qs, extra) => {
    const r = await req(t, Object.assign({ method: 'GET', path: '/api/?' + qs, headers: H }, extra || {}), pins);
    if (r.status === 401 || r.status === 403) throw httpErr(502, 'Palo Alto refused the API key (' + r.status + ')');
    if (r.status !== 200 || !xmlOk(r.text)) throw httpErr(502, 'Palo Alto: ' + xmlMsg(r.text));
    return r.text;
  };
  const op = (cmd) => call('type=op&cmd=' + encodeURIComponent(cmd));
  const xp = (name) => "/config/shared/ssl-tls-service-profile/entry[@name='" + name + "']/certificate";
  return {
    info: async () => { const x = await op('<show><system><info></info></system></show>'); return { model: xmlTag(x, 'model'), version: xmlTag(x, 'sw-version'), hostname: xmlTag(x, 'hostname') }; },
    pending: async () => /^yes$/i.test(xmlTag(await op('<check><pending-changes></pending-changes></check>'), 'result') || ''),
    readBinding: async (b) => (b.type === 'ssl-tls-profile' ? xmlTag(await call('type=config&action=get&xpath=' + encodeURIComponent(xp(b.name))), 'certificate') : null),
    importFile: async (category, name, pem, passphrase) => {
      const boundary = '----zyb' + crypto.randomBytes(8).toString('hex');
      const body = '--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="' + name + '.pem"\r\nContent-Type: application/octet-stream\r\n\r\n' + pem + '\r\n--' + boundary + '--\r\n';
      const qs = 'type=import&category=' + category + '&certificate-name=' + encodeURIComponent(name) + '&format=pem' + (passphrase ? '&passphrase=' + encodeURIComponent(passphrase) : '');
      return call(qs, { method: 'POST', headers: Object.assign({}, H, { 'Content-Type': 'multipart/form-data; boundary=' + boundary, 'Content-Length': Buffer.byteLength(body) }), body });
    },
    bind: (b, name) => call('type=config&action=edit&xpath=' + encodeURIComponent(xp(b.name)) + '&element=' + encodeURIComponent('<certificate>' + xesc(name) + '</certificate>')),
    commit: async (desc) => {
      const x = await call('type=commit&cmd=' + encodeURIComponent('<commit><description>' + xesc(desc) + '</description></commit>'));
      const job = xmlTag(x, 'job'); if (!job) return { result: 'OK', note: xmlMsg(x) };   // "no changes to commit"
      for (let i = 0; i < 120; i++) {
        const j = xmlTag(await op('<show><jobs><id>' + xesc(job) + '</id></jobs></show>'), 'job') || '';   // the job element: <result> outside it is the API wrapper
        if (/^FIN$/i.test(xmlTag(j, 'status') || '')) { const res = xmlTag(j, 'result'); if (res !== 'OK') throw httpErr(502, 'Palo Alto commit job ' + job + ' ended ' + res + ': ' + xmlMsg(j)); return { result: 'OK', job }; }
        await new Promise((ok) => setTimeout(ok, t.poll_ms || 5000));
      }
      throw httpErr(504, 'Palo Alto commit job ' + job + ' did not finish in 10 minutes - check it on the firewall');
    },
  };
}

function fortios(req, t, token, pins) {
  const vd = '?vdom=' + encodeURIComponent(t.vdom || 'root');
  const call = async (method, path, body) => {
    const data = body ? JSON.stringify(body) : null;
    const r = await req(t, { method, path: path + vd, headers: Object.assign({ Authorization: 'Bearer ' + token, Accept: 'application/json' }, data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}), body: data }, pins);
    if (r.status === 401 || r.status === 403) throw httpErr(502, 'FortiGate refused the API token (' + r.status + ')');
    if (r.status !== 200 || !r.json || (r.json.status && r.json.status !== 'success')) throw httpErr(502, 'FortiGate ' + method + ' ' + path.split('?')[0] + ': ' + s((r.json && (r.json.error || r.json.cli_error || r.json.status)) || ('HTTP ' + r.status), 200));
    return r.json;
  };
  const one = (j) => (Array.isArray(j.results) ? j.results[0] : j.results) || {};
  const vipName = (b) => encodeURIComponent(b.name);
  return {
    info: async () => { const j = await call('GET', '/api/v2/monitor/system/status'); return { model: (j.results && j.results.model_name) || j.serial || '', version: j.version || '', hostname: (j.results && j.results.hostname) || '' }; },
    readBinding: async (b) => {
      if (b.type === 'admin-server-cert') return one(await call('GET', '/api/v2/cmdb/system/global'))['admin-server-cert'] || null;
      if (b.type === 'ssl-vpn') return one(await call('GET', '/api/v2/cmdb/vpn.ssl/settings')).servercert || null;
      if (b.type === 'vip') { const v = one(await call('GET', '/api/v2/cmdb/firewall/vip/' + vipName(b)))['ssl-certificate']; return Array.isArray(v) ? (v[0] && (v[0].name || v[0]['q_origin_key'])) || null : v || null; }
      return null;
    },
    importCa: (pem) => call('POST', '/api/v2/monitor/vpn-certificate/ca/import', { import_method: 'file', scope: 'global', file_content: Buffer.from(pem).toString('base64') }),
    importLocal: (name, certPem, keyPem, passphrase) => call('POST', '/api/v2/monitor/vpn-certificate/local/import', { type: 'regular', scope: 'global', certname: name, password: passphrase,
      file_content: Buffer.from(certPem).toString('base64'), key_file_content: Buffer.from(keyPem).toString('base64') }),
    bind: (b, name) => {
      if (b.type === 'admin-server-cert') return call('PUT', '/api/v2/cmdb/system/global', { 'admin-server-cert': name });
      if (b.type === 'ssl-vpn') return call('PUT', '/api/v2/cmdb/vpn.ssl/settings', { servercert: name });
      if (b.type === 'vip') return call('PUT', '/api/v2/cmdb/firewall/vip/' + vipName(b), { 'ssl-certificate': [{ name }] });
      return null;
    },
  };
}

const pemBlocks = (pem) => String(pem || '').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];

function createInstaller(app, C, opts = {}) {
  const now = opts.now || Date.now, store = app.store, req = opts.request || pinnedRequest;
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-pki-install' });
  const keySealer = opts.keySealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-pki' });
  const T = () => store.collection('cert_install_targets'), J = () => store.collection('cert_install_jobs');
  const Q = () => store.collection('cert_requests'), K = () => store.collection('cert_keys'), E = () => store.collection('cert_endpoints');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const isHuman = require('./approve-scopes').isHuman;
  const pubT = (t) => ({ id: t.id, label: t.label, kind: t.kind, host: t.host, port: t.port, pin: t.pin, vsys: t.vsys, vdom: t.vdom, binding: t.binding, endpoint_id: t.endpoint_id || null,
    key_set: !!t.enc, updated_by: t.updated_by, updated_at: t.updated_at, last_test: t.last_test || null });
  const nextId = (col, pre) => { const n = col().size() + 1; let id = pre + String(n).padStart(4, '0'), k = n; while (col().get(id)) id = pre + String(++k).padStart(4, '0'); return id; };
  const step = (j, name, ok, detail) => { j.steps = (j.steps || []).concat([{ at: new Date(now()).toISOString(), step: name, ok, detail: s(detail, 400) }]); };
  const hist = (j, by, to, note) => { j.history = (j.history || []).concat([{ at: new Date(now()).toISOString(), by, from: j.status || null, to, note: s(note, 300) }]); j.status = to; };
  function mayApprove(who) {
    if (!isHuman(who.user)) return false;
    if (app.roles && typeof app.roles.approves === 'function') return app.roles.approves(who.user, SCOPE, who.role);
    return who.role === 'admin';
  }

  // ---- targets (administrator): the write key is sealed and never returned
  function putTarget(b, who) {
    let rec;
    if (b.id) { const cur = T().get(b.id); if (!cur) throw httpErr(404, 'no install target ' + b.id); rec = Object.assign({}, cur); }
    else { if (!b.api_key) throw httpErr(400, 'api_key is required for a new install target'); rec = { id: nextId(T, 'CT-'), created_by: who.user, created_at: new Date(now()).toISOString() }; }
    for (const k of ['label', 'kind', 'host', 'port', 'vsys', 'vdom', 'binding', 'endpoint_id']) if (b[k] !== undefined) rec[k] = b[k];
    if (b.pin) rec.pin = normFp(b.pin).match(/.{2}/g).join(':');
    if (!rec.pin) throw httpErr(400, 'pin is required: the SHA-256 fingerprint of the certificate the device presents (the platform refuses any other)');
    if (rec.binding && ['ssl-tls-profile', 'vip'].includes(rec.binding.type) && !NAME_RE.test(String(rec.binding.name || ''))) throw httpErr(400, 'binding.name must be the profile / virtual server name (letters, digits, space . _ -)');
    if (rec.endpoint_id && !E().get(rec.endpoint_id)) throw httpErr(404, 'no certificate endpoint ' + rec.endpoint_id);
    if (b.api_key) rec.enc = sealer.seal('target|' + rec.id, b.api_key);
    rec.updated_by = who.user; rec.updated_at = new Date(now()).toISOString();
    T().put(rec);
    audit(who, b.id ? 'certs.install.target.update' : 'certs.install.target.add', rec.id, { kind: rec.kind, host: rec.host, binding: rec.binding, key_changed: !!b.api_key });
    return pubT(rec);
  }
  function client(t, extraPins) {
    const key = sealer.unseal('target|' + t.id, t.enc), pins = [t.pin].concat(extraPins || []);
    return t.kind === 'paloalto' ? panos(req, t, key, pins) : fortios(req, t, key, pins);
  }
  async function testTarget(id, who) {
    const t = T().get(id); if (!t) throw httpErr(404, 'no install target ' + id);
    let r;
    try { const info = await client(t).info(); r = { ok: true, at: new Date(now()).toISOString(), info }; }
    catch (e) { r = { ok: false, at: new Date(now()).toISOString(), error: s(e.message, 200) }; }
    T().put(Object.assign({}, t, { last_test: r }));
    audit(who, 'certs.install.target.test', id, { ok: r.ok, error: r.error });
    return r;
  }

  // ---- jobs
  async function plan(q, t) {
    const ep = t.endpoint_id ? E().get(t.endpoint_id) : null;
    const r = await C.py.call('certs.plan_install', { request: { id: q.id, status: q.status, names: q.names, fingerprint256: q.fingerprint256, not_after: q.not_after }, target: { kind: t.kind, binding: t.binding }, endpoint: ep ? { host: ep.host, sni: ep.sni } : null, now: now() });
    if (r && r.ok === false) throw httpErr(409, 'The certificate rules run in Python and Python did not answer (' + (r.error_class || 'error') + ') - run the update so pyengine is installed');
    if (r.refuse) throw httpErr(r.refuse.status, r.refuse.error);
    return r;
  }
  async function propose(b, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person proposes an installation');
    const q = Q().get(b.request_id); if (!q) throw httpErr(404, 'no certificate request ' + b.request_id);
    const t = T().get(b.target_id); if (!t) throw httpErr(404, 'no install target ' + b.target_id);
    if (J().all((j) => j.target_id === t.id && ['proposed', 'approved', 'running'].includes(j.status)).length) throw httpErr(409, 'an installation on ' + t.id + ' is already open');
    const p = await plan(q, t);
    const j = { id: nextId(J, 'CI-'), request_id: q.id, target_id: t.id, endpoint_id: t.endpoint_id || null, cert_name: p.cert_name, binding: t.binding || { type: 'none' }, plan: p.steps, warnings: p.warnings,
      fingerprint256: q.fingerprint256, names: q.names, renewal_id: q.renewal_id || null, run_after: b.run_after || null, reason: b.reason, requested_by: who.user, created_at: new Date(now()).toISOString(), steps: [], history: [] };
    hist(j, who.user, 'proposed', b.reason); J().put(j);
    audit(who, 'certs.install.propose', j.id, { request: q.id, target: t.id, binding: j.binding, run_after: j.run_after });
    return j;
  }
  function decide(id, b, who) {
    const j = J().get(id); if (!j) throw httpErr(404, 'no install job ' + id);
    if (j.status !== 'proposed') throw httpErr(409, id + ' is ' + j.status + ' - only a proposed installation is approved or rejected');
    if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot approve');
    if (String(j.requested_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: a different person approves - you proposed this installation');
    if (!mayApprove(who)) throw httpErr(403, 'approving a firewall change needs an administrator or a human approver for Security (Roles & Functions)');
    if (b.decision === 'reject' && !b.note) throw httpErr(400, 'note is required: say why the installation is rejected');
    j.approval = { decision: b.decision, by: who.user, at: new Date(now()).toISOString(), note: b.note || '' };
    hist(j, who.user, b.decision === 'approve' ? 'approved' : 'rejected', b.note); J().put(j);
    audit(who, 'certs.install.' + b.decision, id, { request: j.request_id, target: j.target_id, requested_by: j.requested_by });
    return j;
  }
  function cancel(id, reason, who) {
    const j = J().get(id); if (!j) throw httpErr(404, 'no install job ' + id);
    if (!['proposed', 'approved'].includes(j.status)) throw httpErr(409, id + ' is ' + j.status + ' - it can no longer be cancelled');
    hist(j, who.user, 'cancelled', reason); J().put(j); audit(who, 'certs.install.cancel', id, { reason });
    return j;
  }
  let running = null;
  async function run(id, who) {
    if (running) throw httpErr(409, 'another installation is running - try again in a moment');
    const j0 = J().get(id); if (!j0) throw httpErr(404, 'no install job ' + id);
    if (j0.status !== 'approved') throw httpErr(409, id + ' is ' + j0.status + ' - an installation runs only after approval');
    if (!isHuman(who.user) && who.user !== 'system:pki') throw httpErr(403, 'a person (or the scheduled window) runs an installation');
    running = id;
    try { return await execute(j0, who); } finally { running = null; }
  }
  async function execute(j, who) {
    const t = T().get(j.target_id), q = Q().get(j.request_id);
    hist(j, who.user, 'running', 'started by ' + who.user); J().put(j);
    audit(who, 'certs.install.run', j.id, { target: j.target_id, cert_name: j.cert_name });
    let bound = false;
    const pins = j.binding.type === 'admin-server-cert' ? [j.fingerprint256] : [];
    const dev = client(t, pins);
    try {
      await plan(q, t);   // re-checked at run time: still issued, still valid, still covers the endpoint
      if (t.kind === 'paloalto') {
        if (await dev.pending()) throw httpErr(409, 'the firewall has uncommitted changes by someone else - a commit would push them too; ask them to commit or revert, then run again');
        step(j, 'no uncommitted changes on the firewall', true, '');
      }
      j.previous = j.binding.type === 'none' ? null : await dev.readBinding(j.binding);
      step(j, 'read the binding in use', true, j.binding.type === 'none' ? 'import only' : (j.previous || 'nothing bound') + ' (kept for roll-back)');
      const keyPem = keySealer.unseal('key|' + q.id, K().get(q.id).enc), pass = crypto.randomBytes(18).toString('base64url');
      const encKey = crypto.createPrivateKey(keyPem).export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: pass });
      const chain = pemBlocks(q.chain_pem);
      for (let i = 0; i < chain.length; i++) {
        try { if (t.kind === 'paloalto') await dev.importFile('certificate', (j.cert_name + '-ca' + (i + 1)).slice(0, 63), chain[i]); else await dev.importCa(chain[i]); step(j, 'import CA certificate ' + (i + 1), true, ''); }
        catch (e) { step(j, 'import CA certificate ' + (i + 1), false, e.message + ' (often: already on the device - continuing)'); }
      }
      if (t.kind === 'paloalto') await dev.importFile('keypair', j.cert_name, q.cert_pem + '\n' + encKey, pass);
      else await dev.importLocal(j.cert_name, q.cert_pem, encKey, pass);
      step(j, 'import key pair ' + j.cert_name, true, 'key sent encrypted with a one-time passphrase');
      if (j.binding.type !== 'none') {
        bound = true;
        await dev.bind(j.binding, j.cert_name); step(j, 'bind ' + j.binding.type + (j.binding.name ? ' ' + j.binding.name : ''), true, j.cert_name);
        if (t.kind === 'paloalto') { const c = await dev.commit('Certificate ' + j.cert_name + ' (' + j.id + ', approved by ' + (j.approval && j.approval.by) + ')'); step(j, 'commit', true, c.job ? 'job ' + c.job + ' OK' : c.note); }
      }
      await verify(j, t, who);
    } catch (e) {
      step(j, 'failed', false, e.message);
      if (bound && j.previous) {
        try { await dev.bind(j.binding, j.previous); if (t.kind === 'paloalto') await dev.commit('Roll-back ' + j.id); step(j, 'automatic roll-back to ' + j.previous, true, ''); }
        catch (e2) { step(j, 'automatic roll-back to ' + j.previous, false, e2.message + ' - restore the binding by hand'); }
      }
      hist(j, who.user, 'failed', e.message); J().put(j);
      audit(who, 'certs.install.failed', j.id, { error: s(e.message, 200), rolled_back: bound && !!j.previous });
      if (app.log && app.log.warn) app.log.warn('certificate installation failed', { job: j.id, target: j.target_id, err: s(e.message, 200) });
      return j;
    }
    return J().get(j.id);
  }
  async function verify(j, t, who) {
    if (j.binding.type === 'admin-server-cert') { T().put(Object.assign({}, T().get(t.id), { pin: j.fingerprint256 })); step(j, 'management certificate changed: the device pin now follows it', true, ''); }
    const ep = j.endpoint_id ? E().get(j.endpoint_id) : null;
    if (ep && j.binding.type !== 'none') {
      let seen = null;
      for (let i = 0; i < 3 && normFp(seen) !== normFp(j.fingerprint256); i++) {
        if (i) await new Promise((ok) => setTimeout(ok, t.verify_wait_ms || 10000));
        const sc = await C.readCert(ep.host, ep.port, ep.sni || '', 8000); seen = sc && sc.ok ? sc.fingerprint256 : null;
      }
      if (normFp(seen) !== normFp(j.fingerprint256)) throw httpErr(502, ep.host + ':' + ep.port + ' still presents ' + (seen ? String(seen).slice(0, 23) + '…' : 'nothing readable') + ' after the installation');
      step(j, 'verified: ' + ep.host + ':' + ep.port + ' presents the new certificate', true, String(seen).slice(0, 47));
      hist(j, who.user, 'verified', 'scan shows the new fingerprint'); J().put(j);
      if (j.renewal_id && C.moveRenewalTo) C.moveRenewalTo(j.renewal_id, 'installed', who, 'installed by ' + j.id + ' on ' + t.label);
      try { await C.scan(ep.id, who); } catch (e) { step(j, 'endpoint re-scan', false, e.message); J().put(j); }
    } else {
      hist(j, who.user, 'installed', j.binding.type === 'none' ? 'imported only (nothing bound)' : 'the device accepted it (no endpoint linked to verify)'); J().put(j);
      if (j.renewal_id && C.moveRenewalTo && j.binding.type !== 'none') C.moveRenewalTo(j.renewal_id, 'installed', who, 'installed by ' + j.id + ' on ' + t.label);
    }
    audit(who, 'certs.install.done', j.id, { status: J().get(j.id).status, target: t.id, fingerprint256: j.fingerprint256 });
  }
  async function rollback(id, b, who) {
    const j = J().get(id); if (!j) throw httpErr(404, 'no install job ' + id);
    if (!['verified', 'installed', 'failed'].includes(j.status)) throw httpErr(409, id + ' is ' + j.status + ' - nothing to roll back');
    if (!j.previous) throw httpErr(409, 'there was no certificate bound before ' + id + ' - nothing to restore');
    if (!mayApprove(who)) throw httpErr(403, 'rolling back a firewall change needs an administrator or a human approver for Security');
    const t = T().get(j.target_id), dev = client(t, [j.fingerprint256]);
    await dev.bind(j.binding, j.previous); if (t.kind === 'paloalto') await dev.commit('Roll-back ' + j.id + ' by ' + who.user);
    step(j, 'roll-back to ' + j.previous, true, b.reason); hist(j, who.user, 'rolled-back', b.reason); J().put(j);
    audit(who, 'certs.install.rollback', id, { restored: j.previous, reason: b.reason });
    return j;
  }
  // a scheduled window: approved jobs with run_after in the past run on the minute tick, as system:pki
  async function tick() {
    for (const j of J().all((x) => x.status === 'approved' && x.run_after && Date.parse(x.run_after) <= now())) {
      try { await run(j.id, { user: 'system:pki', role: '' }); } catch (e) { if (app.log && app.log.every) app.log.every('certs:install:' + j.id, 600000, 'warn', 'scheduled installation not started', { job: j.id, err: s(e.message, 200) }); }
    }
  }
  return { putTarget, testTarget, targets: () => T().all().map(pubT), propose, decide, cancel, run, rollback, tick,
    jobs: () => J().all().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, 200), job: (id) => J().get(id) || null };
}

module.exports = { createInstaller, pinnedRequest, panos, fortios, normFp };
