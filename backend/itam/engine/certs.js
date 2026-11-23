// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SSL / TLS certificate lifecycle (phase 1) and the AI PKI Engineer. The RULES are in Python (pyengine/cert_rules.py):
 * lifecycle state, renew-by date per issuer, weak keys, name / chain problems, findings, and when a scan confirms a renewal.
 * This file reads certificates (TLS handshake only - nothing is sent to the service), validates, checks roles, commits what
 * Python decided and writes the audit record.
 *
 *  - Endpoints: host:port (+ SNI name) with owner, criticality, issuer kind (acme | adcs | manual | self; guessed from the
 *    certificate when not set) and where it is installed (nginx, Apache, IIS, Exchange, F5, FortiGate, Palo Alto).
 *  - Discovery: the TLS ports of the asset register's networked assets and the Domains & Hosting sites are probed; what
 *    answers is PROPOSED - a person adds it.
 *  - Scans every 6 h and on demand. A renewal is opened by a person and moved through requested → issued → installed;
 *    VERIFIED is set only by a scan that sees the new certificate (different fingerprint, later expiry).
 *  - Phase 2 (ACME / AD CS / CSR issuance) and phase 3 (installation, as change plans a second person approves) are not
 *    built: this module changes nothing on any server.
 *
 *   GET  /certs                          viewer    inventory with lifecycle state, renewals, counts
 *   POST /certs/endpoints                operator  {host, port, sni?, label?, owner?, critical?, issuer_kind?, deploy_target?, id?}
 *   POST /certs/endpoints/:id/retire     operator  {reason}
 *   POST /certs/scan                     operator  {id?}   read now
 *   POST /certs/discover                 operator  probe the register's assets → proposals (answers within 20 s: the result,
 *                                                  or {status:'running', probed, total} - the probe carries on in the background)
 *   GET  /certs/discover                 operator  the running or last probe: progress, then the proposals
 *   POST /certs/renewals                 operator  {endpoint_id, note?, ticket?}
 *   POST /certs/renewals/:id             operator  {status: requested|issued|installed|cancelled, note?, ticket?}
 *   POST /certs/policy                   admin     {lead_days?: {acme, adcs, manual, self, unknown}, min_rsa?}
 */
const tls = require('node:tls');
const fs = require('node:fs');
const { guardOf } = require('./errors');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const KINDS = ['acme', 'adcs', 'manual', 'self', 'unknown'];
const TARGETS = ['linux-nginx', 'linux-apache', 'iis', 'exchange', 'f5', 'fortigate', 'paloalto', 'other', 'none'];
const FLOW = { open: ['requested', 'cancelled'], requested: ['issued', 'cancelled'], issued: ['installed', 'cancelled'], installed: ['cancelled'] };
const DISCOVER_PORTS = [443, 8443, 636, 5986];
const HOST_RE = /^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$/;
const IP_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

// TLS handshake only: the certificate the service presents (with its chain), whether the chain is trusted and the name covered
function readCert(host, port, sni, timeoutMs) {
  return new Promise((resolve) => {
    const name = sni || (IP_RE.test(host) ? undefined : host);
    let done = false; const fin = (v) => { if (!done) { done = true; resolve(v); } };
    const sock = tls.connect({ host, port, servername: name, rejectUnauthorized: false, timeout: timeoutMs || 8000 }, () => {
      try {
        const c = sock.getPeerCertificate(true) || {};
        if (!c.raw) { sock.end(); return fin({ ok: false, error: 'no certificate presented' }); }
        const names = String(c.subjectaltname || '').split(/,\s*/).filter((x) => /^(DNS|IP Address):/.test(x)).map((x) => x.replace(/^(DNS|IP Address):/, '').toLowerCase());
        const idErr = name ? tls.checkServerIdentity(name, c) : null;
        const selfSigned = !!(c.issuerCertificate && c.issuerCertificate.fingerprint256 === c.fingerprint256);
        const na = Date.parse(c.valid_to);
        fin({ ok: true, at: Date.now(), sni: name || '', subject: (c.subject && c.subject.CN) || '', issuer: [c.issuer && c.issuer.CN, c.issuer && c.issuer.O].filter(Boolean).join(' · '),
          names, name_ok: name ? !idErr : null, trusted: sock.authorized, trust_error: sock.authorized ? '' : String(sock.authorizationError || ''), self_signed: selfSigned,
          not_before: Date.parse(c.valid_from), not_after: na, not_after_iso: isFinite(na) ? new Date(na).toISOString().slice(0, 10) : '', serial: String(c.serialNumber || '').slice(0, 80),
          key_type: c.asn1Curve || c.nistCurve ? 'ec' : c.modulus ? 'rsa' : '', key_bits: Number(c.bits) || 0, fingerprint256: c.fingerprint256 || '',
          chain: (function () { const out = []; let x = c.issuerCertificate, n = 0; while (x && x !== c && n < 5 && x.fingerprint256 !== (out[out.length - 1] || {}).fp) { out.push({ cn: (x.subject && x.subject.CN) || '', fp: x.fingerprint256 }); if (x.issuerCertificate === x) break; x = x.issuerCertificate; n++; } return out.map((y) => y.cn); })() });
      } catch (e) { fin({ ok: false, error: 'could not read the certificate: ' + String(e.message).slice(0, 160) }); }
      sock.end();
    });
    sock.on('timeout', () => { sock.destroy(); fin({ ok: false, error: 'timeout' }); });
    sock.on('error', (e) => fin({ ok: false, error: String(e.code || e.message).slice(0, 160) }));
  });
}

function createCerts(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, read = opts.readCert || readCert;
  const py = opts.py || require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 30000, resident: false });
  const E = () => store.collection('cert_endpoints'), SC = () => store.collection('cert_scans'), RN = () => store.collection('cert_renewals'), CF = () => store.collection('cert_policy');
  const policy = () => (CF().get('policy') || { id: 'policy' });
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const SYS = { user: 'system:pki', role: '' };
  async function assess() {
    const scans = {}; for (const s of SC().all()) scans[s.id] = s.scan;
    const r = await py.call('certs.assess', { endpoints: E().all(), scans, renewals: RN().all(), requests: store.collection('cert_requests').all().map((q) => ({ id: q.id, endpoint_id: q.endpoint_id, status: q.status, error: q.error, created_ms: q.created_ms, updated_ms: q.updated_ms, fingerprint256: q.fingerprint256 })), policy: policy(), now: now() });
    if (r && r.ok === false) {
      if (app.log && app.log.every) app.log.every('certs:py', 300000, 'error', 'certificate rules (Python) did not answer', { cls: r.error_class, err: String(r.error || '').slice(0, 200) });
      throw httpErr(409, 'The certificate rules run in Python and Python did not answer (' + (r.error_class || 'error') + ') - run the update so pyengine is installed');
    }
    return r;
  }
  // a scan that shows the new certificate confirms the renewal (Python decides which)
  async function confirmFromScans() {
    const a = await assess();
    for (const c of a.confirm || []) {
      const rn = RN().get(c.renewal_id); if (!rn || rn.status === 'verified' || rn.status === 'cancelled') continue;
      rn.history = (rn.history || []).concat([{ at: new Date(now()).toISOString(), by: SYS.user, from: rn.status, to: 'verified', note: c.note }]);
      rn.status = 'verified'; rn.verified_at = new Date(now()).toISOString(); rn.new_fingerprint = c.fingerprint256; RN().put(rn);
      audit(SYS, 'certs.renewal.verified', rn.id, { endpoint: c.endpoint_id, note: c.note });
    }
    return a;
  }
  async function scanOne(ep) {
    const s = await read(ep.host, ep.port, ep.sni || '', 8000);
    const prev = SC().get(ep.id);
    SC().put({ id: ep.id, scan: s, prev_fingerprint: prev && prev.scan && prev.scan.ok ? prev.scan.fingerprint256 : '' });
    return s;
  }
  async function scan(id, who) {
    const list = id ? [E().get(id)].filter((x) => x && !x.retired) : E().all((x) => !x.retired);
    if (id && !list.length) throw httpErr(404, 'no certificate endpoint ' + id);
    let ok = 0, bad = 0;
    for (let i = 0; i < list.length; i += 8) {
      const r = await Promise.all(list.slice(i, i + 8).map((ep) => scanOne(ep)));
      for (const s of r) { if (s.ok) ok++; else bad++; }
    }
    if (who) audit(who, 'certs.scan', id || 'all', { endpoints: list.length, read: ok, failed: bad });
    await confirmFromScans();
    return { scanned: list.length, read: ok, failed: bad };
  }
  function putEndpoint(b, who) {
    const key = (h, p) => String(h).toLowerCase() + ':' + p;
    const dup = E().all((x) => !x.retired && x.id !== b.id && key(x.host, x.port) === key(b.host, b.port) && (x.sni || '') === (b.sni || ''))[0];
    if (dup) throw httpErr(409, b.host + ':' + b.port + ' is already registered as ' + dup.id);
    let rec;
    if (b.id) { const cur = E().get(b.id); if (!cur || cur.retired) throw httpErr(404, 'no certificate endpoint ' + b.id); rec = Object.assign({}, cur, b); }
    else { let n = E().all().length + 1, id; do { id = 'CE-' + String(n++).padStart(4, '0'); } while (E().get(id)); rec = Object.assign({ created_by: who.user, created_at: new Date(now()).toISOString() }, b, { id }); }
    rec.host = String(rec.host).toLowerCase(); rec.updated_by = who.user; rec.updated_at = new Date(now()).toISOString();
    E().put(rec);
    audit(who, b.id ? 'certs.endpoint.update' : 'certs.endpoint.add', rec.id, { host: rec.host, port: rec.port, fields: Object.keys(b).filter((k) => k !== 'id').sort() });
    return rec;
  }
  function retire(id, reason, who) {
    const cur = E().get(id); if (!cur || cur.retired) throw httpErr(404, 'no certificate endpoint ' + id);
    cur.retired = { at: new Date(now()).toISOString(), by: who.user, reason }; E().put(cur);
    audit(who, 'certs.endpoint.retire', id, { reason });
    return cur;
  }
  // probe the TLS ports of the register's networked assets and the Domains & Hosting sites; propose what answers
  // one probe at a time; progress kept so a large register (minutes of probing) never holds a request open past the gateway
  let job = null;
  const jobView = () => job || store.collection('cert_discover_job').get('last') || { status: 'idle' };
  function discoverStart(who) {
    if (job && job.status === 'running') return { job: jobView(), promise: job.promise };
    job = { id: 'last', status: 'running', started_at: new Date(now()).toISOString(), by: who.user, total: 0, probed: 0 };
    const pr = discover(who).then((r) => { Object.assign(job, r, { status: 'done', finished_at: new Date(now()).toISOString() }); store.collection('cert_discover_job').put(Object.assign({}, job, { promise: undefined })); return job; },
      (e) => { Object.assign(job, { status: 'failed', error: String(e.message).slice(0, 200), finished_at: new Date(now()).toISOString() }); if (app.log && app.log.every) app.log.every('certs:discover', 600000, 'warn', 'certificate discovery failed', { err: job.error }); return job; });
    Object.defineProperty(job, 'promise', { value: pr, enumerable: false, writable: true });
    return { job: jobView(), promise: pr };
  }
  async function discover(who) {
    const known = new Set(E().all((x) => !x.retired).map((x) => x.host + ':' + x.port));
    const cand = new Map();
    for (const a of store.collection('assets').all((x) => x.mgmt_ip && !['disposed', 'retired', 'lost', 'stolen'].includes(x.status))) for (const p of DISCOVER_PORTS) cand.set(a.mgmt_ip + ':' + p, { host: a.mgmt_ip, port: p, asset_id: a.id, label: a.name || a.mgmt_ip });
    try { const Dm = app.addons && app.addons.domains; if (Dm) for (const h of (Dm.view('admin').hosts || [])) if (h.fqdn) cand.set(String(h.fqdn).toLowerCase() + ':' + (h.port || 443), { host: String(h.fqdn).toLowerCase(), port: h.port || 443, label: h.fqdn, source: 'domains' }); }
    catch (e) { if (app.log && app.log.every) app.log.every('certs:domains', 600000, 'warn', 'certificate discovery could not read Domains & Hosting', { err: String(e.message).slice(0, 160) }); }
    const todo = [...cand.values()].filter((c) => !known.has(c.host + ':' + c.port)).slice(0, 2000), found = [];
    if (job) job.total = todo.length;
    for (let i = 0; i < todo.length; i += 48) {
      const r = await Promise.all(todo.slice(i, i + 48).map((c) => read(c.host, c.port, '', 3000).then((s) => ({ c, s }))));
      if (job) { job.probed = Math.min(todo.length, i + 48); job.found_so_far = found.length; }
      for (const { c, s } of r) if (s.ok) found.push(Object.assign({}, c, { subject: s.subject, issuer: s.issuer, not_after_iso: s.not_after_iso, self_signed: s.self_signed, names: (s.names || []).slice(0, 6) }));
    }
    audit(who, 'certs.discover', 'assets', { probed: todo.length, found: found.length });
    return { probed: todo.length, found, ports: DISCOVER_PORTS, note: 'Proposals only: add the ones that matter (an endpoint is scanned every 6 h once added).' };
  }
  function openRenewal(b, who) {
    const ep = E().get(b.endpoint_id); if (!ep || ep.retired) throw httpErr(404, 'no certificate endpoint ' + b.endpoint_id);
    if (RN().all((r) => r.endpoint_id === ep.id && !['verified', 'cancelled'].includes(r.status)).length) throw httpErr(409, 'a renewal is already open for ' + ep.id);
    const sc = (SC().get(ep.id) || {}).scan;
    if (!sc || !sc.ok) throw httpErr(409, 'scan the endpoint first: the renewal is confirmed against the certificate it presents now');
    let n = RN().all().length + 1, id; do { id = 'CR-' + String(n++).padStart(4, '0'); } while (RN().get(id));
    const rec = { id, endpoint_id: ep.id, status: 'open', opened_by: who.user, opened_at: new Date(now()).toISOString(), old_fingerprint: sc.fingerprint256, old_not_after: sc.not_after, old_serial: sc.serial,
      ticket: b.ticket || '', history: [{ at: new Date(now()).toISOString(), by: who.user, from: null, to: 'open', note: b.note || '' }] };
    RN().put(rec); audit(who, 'certs.renewal.open', id, { endpoint: ep.id, ticket: rec.ticket });
    return rec;
  }
  function moveRenewal(id, b, who) {
    const rn = RN().get(id); if (!rn) throw httpErr(404, 'no renewal ' + id);
    const allowed = FLOW[rn.status] || [];
    if (!allowed.includes(b.status)) throw httpErr(409, 'a renewal that is ' + rn.status + ' can move to: ' + (allowed.join(', ') || 'nothing (closed)') + ' - verified is set only by a scan that sees the new certificate');
    rn.history = (rn.history || []).concat([{ at: new Date(now()).toISOString(), by: who.user, from: rn.status, to: b.status, note: b.note || '' }]);
    rn.status = b.status; if (b.ticket) rn.ticket = b.ticket; RN().put(rn);
    audit(who, 'certs.renewal.' + b.status, id, { endpoint: rn.endpoint_id, note: String(b.note || '').slice(0, 200) });
    return rn;
  }
  // issuance moves its renewal forward (open / requested → issued) and says so in the renewal's history
  function moveRenewalTo(id, to, who, note) {
    const rn = RN().get(id); if (!rn || ['verified', 'cancelled', 'installed', to].includes(rn.status)) return null;
    rn.history = (rn.history || []).concat([{ at: new Date(now()).toISOString(), by: who.user, from: rn.status, to, note }]); rn.status = to; RN().put(rn);
    audit(who, 'certs.renewal.' + to, id, { endpoint: rn.endpoint_id, note }); return rn;
  }
  function setPolicy(b, who) {
    const p = Object.assign({}, policy(), { id: 'policy' });
    if (b.lead_days) p.lead_days = Object.assign({}, p.lead_days || {}, b.lead_days);
    if (b.min_rsa) p.min_rsa = b.min_rsa;
    if (b.allowed_names) p.allowed_names = b.allowed_names;
    if (b.key_type) p.key_type = b.key_type;
    p.updated_by = who.user; p.updated_at = new Date(now()).toISOString(); CF().put(p);
    audit(who, 'certs.policy', 'policy', { lead_days: p.lead_days, min_rsa: p.min_rsa, allowed_names: p.allowed_names, key_type: p.key_type });
    return p;
  }
  async function view() {
    const a = await assess();
    return Object.assign(a, { requests: C2.issue ? C2.issue.list() : [], issuers: C2.issue ? C2.issue.issuers() : null, renewals: RN().all().sort((x, y) => (x.opened_at < y.opened_at ? 1 : -1)).slice(0, 300), policy: policy(), kinds: KINDS, targets: TARGETS, engine: 'python',
      automation: { issuance: C2.issue ? 'ACME, AD CS and ordered certificates (key + CSR on the platform, sealed)' : 'not installed', installation: C2.install ? 'Palo Alto and FortiGate (a second person approves; verified by a scan)' : 'not installed' } });
  }
  // the AI PKI Engineer on the duty desk: every lifecycle finding is a work item; verify = read the endpoint again
  const adapter = {
    id: 'pki', name: 'AI PKI Engineer',
    async findings() { const a = await assess(); return a.connected ? a.findings : null; },
    investigate(it) {
      const ep = E().get(String(it.key).split(':')[0]), sc = ep && (SC().get(ep.id) || {}).scan;
      if (!ep) return { summary: 'The endpoint is no longer registered.', checks: [], causes: [] };
      return { summary: ep.host + ':' + ep.port + (ep.owner ? ' - owner ' + ep.owner : '') + (ep.critical ? ' (critical)' : ''),
        checks: [{ name: 'Certificate', status: sc && sc.ok ? 'ok' : 'fail', detail: sc && sc.ok ? sc.subject + ' · ' + sc.issuer + ' · expires ' + sc.not_after_iso + ' · ' + String(sc.key_type).toUpperCase() + ' ' + sc.key_bits : (sc ? sc.error : 'not scanned') },
          { name: 'Chain', status: sc && sc.trusted ? 'ok' : 'warn', detail: sc ? (sc.trusted ? 'trusted' : 'not trusted: ' + sc.trust_error) + (sc.chain && sc.chain.length ? ' · ' + sc.chain.join(' ← ') : '') : '' }],
        causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
    },
    async verify(it) {
      const ep = E().get(String(it.key).split(':')[0]); if (!ep || ep.retired) return { present: false, note: 'endpoint retired' };
      await scanOne(ep); const a = await confirmFromScans();
      const present = a.findings.some((f) => f.key === it.key);
      return { present, note: present ? 'the new scan still shows it' : 'the new scan no longer shows it' };
    },
  };
  const C2 = { view, scan, scanOne, putEndpoint, retire, discover, discoverStart, discoverJob: jobView, openRenewal, moveRenewal, moveRenewalTo, setPolicy, assess, adapter, readCert: read, py };
  return C2;
}

// how long a request waits for a probe before answering "running" (well under the 60 s gateway timeout)
const opts20 = () => Number(process.env.SENTRA_CERT_WAIT_MS) || 20000;
function registerCertRoutes(srv, app, C) {
  const { body } = require('./check');
  srv.route('GET', '/certs', (ctx) => { ctx.need('viewer'); return C.view(); });
  srv.route('POST', '/certs/endpoints', (ctx) => {
    ctx.need('operator');
    const upd = !!(ctx.body && ctx.body.id), need = upd ? {} : { required: true };
    const b = body(ctx.body).str('id', { max: 12, re: /^CE-\d{4,}$/, msg: 'id must be a certificate endpoint id (CE-nnnn)' })
      .str('host', Object.assign({ max: 253, re: new RegExp(HOST_RE.source + '|' + IP_RE.source), msg: 'host must be a host name or IPv4 address' }, need))
      .int('port', Object.assign({ min: 1, max: 65535 }, need)).str('sni', { max: 253, re: HOST_RE, msg: 'sni must be a host name' })
      .str('label', { max: 120 }).str('owner', { max: 120 }).bool('critical').oneOf('issuer_kind', KINDS).oneOf('deploy_target', TARGETS).bool('auto_renew').str('asset_id', { max: 64, id: true }).done();
    return C.putEndpoint(b, ctx.who);
  });
  srv.route('POST', '/certs/endpoints/:id/retire', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('reason', { required: true, max: 300 }).done();
    const id = String(ctx.params.id || ''); if (!/^CE-\d{4,}$/.test(id)) throw Object.assign(new Error('id must be a certificate endpoint id (CE-nnnn)'), { status: 400 });
    return C.retire(id, b.reason, ctx.who);
  });
  srv.route('POST', '/certs/scan', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('id', { max: 12, re: /^CE-\d{4,}$/, msg: 'id must be a certificate endpoint id (CE-nnnn)' }).done();
    return C.scan(b.id || '', ctx.who);
  });
  srv.route('POST', '/certs/discover', async (ctx) => {
    ctx.need('operator'); body(ctx.body).done();
    const s = C.discoverStart(ctx.who);
    const r = await Promise.race([s.promise, new Promise((ok) => { const t = setTimeout(() => ok(null), opts20(ctx)); if (t.unref) t.unref(); })]);
    return r ? Object.assign({}, r) : Object.assign({}, C.discoverJob(), { note: 'Still probing - the result appears here when it finishes.' });
  });
  srv.route('GET', '/certs/discover', (ctx) => { ctx.need('operator'); return Object.assign({}, C.discoverJob()); });
  srv.route('POST', '/certs/renewals', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('endpoint_id', { required: true, re: /^CE-\d{4,}$/, msg: 'endpoint_id must be a certificate endpoint id (CE-nnnn)' }).str('note', { max: 500 }).str('ticket', { max: 60 }).done();
    return C.openRenewal(b, ctx.who);
  });
  srv.route('POST', '/certs/renewals/:id', (ctx) => {
    ctx.need('operator');
    const id = String(ctx.params.id || ''); if (!/^CR-\d{4,}$/.test(id)) throw Object.assign(new Error('id must be a renewal id (CR-nnnn)'), { status: 400 });
    const b = body(ctx.body).oneOf('status', ['requested', 'issued', 'installed', 'cancelled'], { required: true }).str('note', { max: 500 }).str('ticket', { max: 60 })
      .rule((o) => (o.status === 'cancelled' && !o.note ? 'note is required to cancel a renewal' : null)).done();
    return C.moveRenewal(id, b, ctx.who);
  });
  srv.route('POST', '/certs/policy', (ctx) => {
    ctx.need('admin');
    const b = body(ctx.body).int('min_rsa', { min: 2048, max: 8192 }).oneOf('key_type', ['rsa', 'ec'])
      .list('allowed_names', { item: 'str', itemMax: 120, max: 50, unique: true }).rule((o) => ((o.allowed_names || []).some((n) => !/^(\*\.)?[a-z0-9.-]{1,120}$/i.test(n)) ? 'allowed_names: each entry is a name or *.domain pattern' : null)).done();
    const ld = ctx.body && ctx.body.lead_days;
    if (ld !== undefined) {
      if (!ld || typeof ld !== 'object' || Array.isArray(ld)) throw Object.assign(new Error('lead_days must be an object'), { status: 400 });
      b.lead_days = {};
      for (const k of Object.keys(ld)) { if (!KINDS.includes(k)) throw Object.assign(new Error('lead_days.' + String(k).slice(0, 30) + ' is not an issuer kind (' + KINDS.join(', ') + ')'), { status: 400 });
        const n = Number(ld[k]); if (!Number.isInteger(n) || n < 7 || n > 180) throw Object.assign(new Error('lead_days.' + k + ' must be a whole number of days between 7 and 180'), { status: 400 }); b.lead_days[k] = n; }
    }
    return C.setPolicy(b, ctx.who);
  });
  if (C.issue) registerIssueRoutes(srv, app, C.issue, body);
  if (C.install) registerInstallRoutes(srv, app, C.install, body);
  if (!app.noTimers) {
    if (C.issue) { const t3 = setInterval(guardOf(app, 'certs.issue', () => C.issue.tick()), 60000); if (t3.unref) t3.unref(); }
    if (C.install) { const t4 = setInterval(guardOf(app, 'certs.install', () => C.install.tick()), 60000); if (t4.unref) t4.unref(); }
    const run = guardOf(app, 'certs.scan', () => C.scan('', null));
    const t1 = setTimeout(run, 120000), t2 = setInterval(run, 6 * 3600000); if (t1.unref) { t1.unref(); t2.unref(); }
  }
}

// ---- phase 3: installation on Palo Alto / FortiGate (engine/cert-install.js)
function registerInstallRoutes(srv, app, I, body) {
  const ID = (re, what) => (ctx) => { const id = String(ctx.params.id || ''); if (!re.test(id)) throw Object.assign(new Error('id must be ' + what), { status: 400 }); return id; };
  const ct = ID(/^CT-\d{4,}$/, 'an install target id (CT-nnnn)'), ci = ID(/^CI-\d{4,}$/, 'an install job id (CI-nnnn)');
  srv.route('GET', '/certs/install', (ctx) => { ctx.need('operator'); return { targets: I.targets(), jobs: I.jobs() }; });
  srv.route('POST', '/certs/install/targets', (ctx) => {
    ctx.need('admin');   // a write credential for a firewall: a security-integration setting
    const upd = !!(ctx.body && ctx.body.id), need = upd ? {} : { required: true };
    const b = body(ctx.body).str('id', { max: 12, re: /^CT-\d{4,}$/, msg: 'id must be an install target id (CT-nnnn)' }).str('label', Object.assign({ max: 120 }, need)).oneOf('kind', ['paloalto', 'fortigate'], need)
      .str('host', Object.assign({ max: 253, re: new RegExp(HOST_RE.source + '|' + IP_RE.source), msg: 'host must be a host name or IPv4 address' }, need)).int('port', { min: 1, max: 65535, def: upd ? undefined : 443 })
      .str('pin', { max: 110, re: /^([0-9A-Fa-f]{2}:?){32}$/, msg: 'pin must be the SHA-256 fingerprint of the device certificate (64 hex digits, colons optional)' })
      .str('api_key', { max: 600, re: /^[\x21-\x7e]+$/, msg: 'api_key must be the API key / token (printable characters, no spaces)' })
      .str('vsys', { max: 20, re: /^vsys\d{1,3}$/, msg: 'vsys must look like vsys1' }).str('vdom', { max: 31, re: /^[A-Za-z0-9_-]+$/, msg: 'vdom has an invalid format' })
      .str('endpoint_id', { max: 12, re: /^CE-\d{4,}$/, msg: 'endpoint_id must be a certificate endpoint id (CE-nnnn)' }).done();
    const bd = ctx.body && ctx.body.binding;
    if (bd !== undefined) {
      if (!bd || typeof bd !== 'object' || Array.isArray(bd)) throw Object.assign(new Error('binding must be {type, name?}'), { status: 400 });
      const types = { paloalto: ['ssl-tls-profile', 'none'], fortigate: ['admin-server-cert', 'ssl-vpn', 'vip', 'none'] };
      const kind = b.kind || (upd && I.targets().find((x) => x.id === b.id) || {}).kind;
      if (!types[kind] || !types[kind].includes(bd.type)) throw Object.assign(new Error('binding.type for ' + (kind || '?') + ' must be one of ' + ((types[kind] || []).join(', ') || 'paloalto / fortigate types')), { status: 400 });
      b.binding = { type: bd.type }; if (bd.name !== undefined) b.binding.name = String(bd.name).slice(0, 63);
    }
    return I.putTarget(b, ctx.who);
  });
  srv.route('POST', '/certs/install/targets/:id/test', async (ctx) => { ctx.need('admin'); body(ctx.body).done(); return I.testTarget(ct(ctx), ctx.who); });
  srv.route('POST', '/certs/install/jobs', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('request_id', { required: true, re: /^CQ-\d{4,}$/, msg: 'request_id must be a certificate request id (CQ-nnnn)' }).str('target_id', { required: true, re: /^CT-\d{4,}$/, msg: 'target_id must be an install target id (CT-nnnn)' })
      .str('reason', { required: true, max: 300 }).str('run_after', { max: 30, re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/, msg: 'run_after must be an ISO date-time with a zone (the maintenance window)' }).done();
    return I.propose(b, ctx.who);
  });
  srv.route('POST', '/certs/install/jobs/:id/approve', (ctx) => { ctx.need('operator'); body(ctx.body).done(); return I.decide(ci(ctx), { decision: 'approve' }, ctx.who); });
  srv.route('POST', '/certs/install/jobs/:id/reject', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('note', { required: true, max: 300 }).done(); return I.decide(ci(ctx), { decision: 'reject', note: b.note }, ctx.who); });
  srv.route('POST', '/certs/install/jobs/:id/cancel', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('reason', { required: true, max: 300 }).done(); return I.cancel(ci(ctx), b.reason, ctx.who); });
  srv.route('POST', '/certs/install/jobs/:id/run', async (ctx) => { ctx.need('operator'); body(ctx.body).done(); return I.run(ci(ctx), ctx.who); });
  srv.route('POST', '/certs/install/jobs/:id/rollback', async (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('reason', { required: true, max: 300 }).done(); return I.rollback(ci(ctx), b, ctx.who); });
}

const CQ = /^CQ-\d{4,}$/;
function cqId(ctx) { const id = String(ctx.params.id || ''); if (!CQ.test(id)) throw Object.assign(new Error('id must be a certificate request id (CQ-nnnn)'), { status: 400 }); return id; }
function registerIssueRoutes(srv, app, I, body) {
  srv.route('GET', '/certs/issuers', (ctx) => { ctx.need('operator'); return I.issuers(); });
  srv.route('POST', '/certs/issuers/acme', (ctx) => {
    ctx.need('admin');   // a security-integration setting
    const b = body(ctx.body).str('directory_url', { required: true, max: 300, re: /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/\S*$/, msg: 'directory_url must be the https URL of the ACME directory' })
      .str('contact', { max: 120, email: true }).str('eab_kid', { max: 200, re: /^[A-Za-z0-9_.:-]+$/, msg: 'eab_kid has an invalid format' }).str('eab_hmac', { max: 200, re: /^[A-Za-z0-9_-]+$/, msg: 'eab_hmac must be the base64url HMAC key from the CA' })
      .str('http01_webroot', { max: 200, re: /^\/[A-Za-z0-9._/-]+$/, msg: 'http01_webroot must be an absolute path' }).bool('tos_agreed', { required: true })
      .rule((o) => (o.tos_agreed !== true ? 'tos_agreed: the CA\'s terms of service must be accepted' : null)).rule((o) => (!!o.eab_kid !== !!o.eab_hmac ? 'eab_kid and eab_hmac go together' : null)).done();
    return I.setAcme(b, ctx.who);
  });
  srv.route('POST', '/certs/issuers/adcs', (ctx) => {
    ctx.need('admin');
    const b = body(ctx.body).str('url', { required: true, max: 200 }).str('template', { required: true, max: 64 }).str('username', { required: true, max: 120, re: /^[A-Za-z0-9._@\\-]+$/, msg: 'username has an invalid format' }).str('password', { max: 256 }).done();
    return I.setAdcs(b, ctx.who);
  });
  srv.route('POST', '/certs/requests', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('endpoint_id', { required: true, re: /^CE-\d{4,}$/, msg: 'endpoint_id must be a certificate endpoint id (CE-nnnn)' }).oneOf('method', ['acme', 'adcs', 'manual'])
      .list('names', { item: 'str', itemMax: 253, max: 50, unique: true }).oneOf('key_type', ['rsa', 'ec']).int('key_bits', { min: 256, max: 4096 }).str('renewal_id', { max: 12, re: /^CR-\d{4,}$/, msg: 'renewal_id must be a renewal id (CR-nnnn)' })
      .rule((o) => ((o.names || []).some((n) => !(require('./csr').NAME_RE.test(n) || require('./csr').IP_RE.test(n))) ? 'names: each must be a host name, *.domain or IPv4 address' : null)).done();
    return I.create(b, ctx.who);
  });
  srv.route('POST', '/certs/requests/:id/approve', async (ctx) => { ctx.need('operator'); body(ctx.body).done(); return I.approve(cqId(ctx), ctx.who); });
  srv.route('POST', '/certs/requests/:id/advance', async (ctx) => {
    ctx.need('operator'); const b = body(ctx.body).bool('dns_published').done();
    return I.advance(cqId(ctx), Object.assign({}, ctx.who, { dnsPublished: b.dns_published === true }));
  });
  srv.route('POST', '/certs/requests/:id/upload', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('pem', { required: true, max: 60000, re: /-----BEGIN CERTIFICATE-----/, msg: 'pem must be the certificate in PEM form (with its chain if you have it)' }).done();
    return I.upload(cqId(ctx), b.pem, ctx.who);
  });
  srv.route('POST', '/certs/requests/:id/cancel', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('reason', { required: true, max: 300 }).done(); return I.cancel(cqId(ctx), b.reason, ctx.who); });
  srv.route('POST', '/certs/requests/:id/export', (ctx) => {
    ctx.need('admin');   // the private key leaves the vault: administrators, with a reason, audited
    const b = body(ctx.body).bool('include_key').str('reason', { required: true, min: 5, max: 300 }).done();
    return I.exportBundle(cqId(ctx), b, ctx.who);
  });
}

module.exports = { createCerts, registerCertRoutes, readCert, KINDS, TARGETS };
