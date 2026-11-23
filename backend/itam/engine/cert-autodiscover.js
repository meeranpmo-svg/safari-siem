// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { guardOf } = require('./errors');
/*
 * Automatic certificate discovery from Asset Discovery (Certificates -> Discovery & Inventory -> Automatic): the servers the
 * discovery scopes already swept tell us which TLS ports are open (disc_devices.open_ports, plus the asset register's
 * management addresses). Every open TLS-capable port is read with a TLS handshake only (nothing is sent to the service) and,
 * when it presents a certificate, it is ADDED to the certificate inventory as source "discovery" - with the device's name as
 * SNI, the asset's owner and criticality - so the 6-hourly scans, expiry alerts, risks and the report cover it with no typing.
 * A port that answered without TLS is not probed again for 7 days. Nothing here changes a server.
 * Off until an administrator switches it on; "propose" mode lists what it found instead of adding it.
 *   GET  /certs/autodiscovery         operator  settings, last run, coverage (devices with TLS ports, registered, not TLS)
 *   POST /certs/autodiscovery         admin     {enabled, mode: add|propose, ports[], include_unapproved, every_hours}   audited
 *   POST /certs/autodiscovery/run     operator  run now; answers within 20 s with the result or {status:'running'}      audited
 */
const DEFAULT_PORTS = [443, 444, 465, 636, 993, 995, 3269, 4443, 5061, 5986, 8443, 9443, 10443];
const NOT_TLS_AGAIN_MS = 7 * 86400000;
const IP_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

function createCertAutodiscover(app, C, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const cfgC = () => store.collection('cert_autodisc'), seenC = () => store.collection('cert_autodisc_seen');
  const SYSTEM = { user: 'system:pki-discovery', role: 'system', ip: '' };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('cert-autodisc:' + key, 3600000, 'warn', msg, detail); };
  const cfg = () => Object.assign({ enabled: false, mode: 'add', ports: DEFAULT_PORTS, include_unapproved: true, every_hours: 6, last_run: null }, cfgC().get('cfg') || {});
  let running = false, current = null, progress = null;

  // what discovery saw: device / asset -> its address, name and the TLS ports open on it
  function candidates() {
    const c = cfg(), ports = new Set(c.ports), out = new Map(), assets = new Map();
    for (const a of store.collection('assets').all((x) => !['disposed', 'retired', 'lost', 'stolen'].includes(x.status))) assets.set(a.id, a);
    for (const d of store.collection('disc_devices').all((x) => x.status !== 'ignored' && (x.open_ports || []).length)) {
      if (!c.include_unapproved && !d.asset_id) continue;
      const ip = d.ip || (d.ips || [])[0]; if (!ip || !IP_RE.test(ip)) continue;
      const a = d.asset_id ? assets.get(d.asset_id) : null;
      const sni = d.fqdn || (a && a.fqdn) || '';
      for (const p of d.open_ports) if (ports.has(p)) out.set(ip + ':' + p, { host: ip, port: p, sni, label: d.hostname || (a && a.name) || ip, device_id: d.id, asset_id: d.asset_id || null, asset: a });
    }
    return [...out.values()];
  }
  const known = () => {
    const s = new Set();
    for (const e of store.collection('cert_endpoints').all((x) => !x.retired)) { s.add(String(e.host).toLowerCase() + ':' + e.port); if (e.sni) s.add(String(e.sni).toLowerCase() + ':' + e.port); }
    return s;
  };

  async function run(who) {
    const c = cfg();
    if (running) throw httpErr(409, 'a discovery run is already in progress');
    running = true; progress = { status: 'running', started: iso(), by: who.user, probed: 0, total: 0 };
    const started = iso(); let probed = 0, added = 0, notTls = 0, skipped = 0, failed = 0; const proposals = [];
    try {
      const k = known(), cand = candidates().filter((x) => !(k.has(x.host + ':' + x.port) || (x.sni && k.has(x.sni.toLowerCase() + ':' + x.port))));
      const todo0 = cand.filter((x) => { const s = seenC().get(x.host + ':' + x.port); if (s && !s.tls && now() - Date.parse(s.at) < NOT_TLS_AGAIN_MS) { skipped++; return false; } return true; }).slice(0, 3000), todo = todo0;
      progress.total = todo.length;
      for (let i = 0; i < todo.length; i += 48) {
        progress.probed = i;
        const res = await Promise.all(todo.slice(i, i + 48).map((x) => C.readCert(x.host, x.port, x.sni, 4000).then((s) => ({ x, s }), (e) => ({ x, s: { ok: false, error: String(e.message) } }))));
        for (const { x, s } of res) {
          probed++;
          seenC().put({ id: x.host + ':' + x.port, at: iso(), tls: !!s.ok, error: s.ok ? '' : String(s.error || '').slice(0, 120), device_id: x.device_id });
          if (!s.ok) { notTls++; continue; }
          const row = { host: x.host, port: x.port, sni: x.sni || '', label: x.label, subject: s.subject, issuer: s.issuer, not_after_iso: s.not_after_iso, self_signed: s.self_signed, device_id: x.device_id, asset_id: x.asset_id };
          if (c.mode !== 'add') { proposals.push(row); continue; }
          try {
            const a = x.asset || {};
            const ep = C.putEndpoint({ host: x.host, port: x.port, sni: x.sni || '', label: String(x.label).slice(0, 120), owner: a.owner || a.custodian || '', critical: /^(critical|high)$/i.test(a.criticality || ''),
              source: 'discovery', device_id: x.device_id, asset_id: x.asset_id }, SYSTEM);
            await C.scanOne(ep);
            added++;
          } catch (e) { failed++; warn('add', 'certificate discovery: an endpoint could not be added', { host: x.host, port: x.port, err: String(e.message).slice(0, 160) }); }
        }
      }
      const last = { started, finished: iso(), by: who.user, candidates: cand.length, probed, added, not_tls: notTls, skipped_recent_not_tls: skipped, failed, proposals: proposals.slice(0, 500) };
      cfgC().put(Object.assign({}, cfg(), { id: 'cfg', last_run: last }));
      audit(who, 'certs.autodiscovery.run', 'discovery', { candidates: cand.length, probed, added, not_tls: notTls, proposed: proposals.length, failed });
      return last;
    } finally { running = false; progress = null; }
  }
  // start a run (or join the one going) and wait at most waitMs; the run carries on after the request has answered
  async function runFor(who, waitMs) {
    if (!running) current = run(who).catch((e) => { warn('run', 'certificate discovery run failed', { err: String(e.message).slice(0, 160) }); throw e; });
    const r = await Promise.race([current, new Promise((ok) => { const t = setTimeout(() => ok(null), waitMs); if (t.unref) t.unref(); })]);
    return r || Object.assign({ note: 'Still probing - the result appears under "Last run" when it finishes.' }, progress || { status: 'running' });
  }

  function view() {
    const c = cfg(), cand = candidates(), k = known();
    const reg = store.collection('cert_endpoints').all((x) => !x.retired);
    const seen = seenC().all(() => true);
    const devicesWithTls = new Set(cand.map((x) => x.device_id)).size;
    const byPort = {}; for (const x of cand) byPort[x.port] = (byPort[x.port] || 0) + 1;
    return { running: progress, settings: { enabled: c.enabled, mode: c.mode, ports: c.ports, include_unapproved: c.include_unapproved, every_hours: c.every_hours, updated_by: c.updated_by || null, updated_at: c.updated_at || null },
      last_run: c.last_run, default_ports: DEFAULT_PORTS,
      coverage: { devices_with_tls_ports: devicesWithTls, open_tls_ports: cand.length, registered: cand.filter((x) => k.has(x.host + ':' + x.port) || (x.sni && k.has(x.sni.toLowerCase() + ':' + x.port))).length,
        not_tls: seen.filter((s) => !s.tls).length, from_discovery: reg.filter((e) => e.source === 'discovery').length, by_port: byPort,
        sweep_hint: 'Asset Discovery sweeps ports 443 and 444 by default. Add 636, 8443, 9443, 5986 (and any other TLS port you use) to the scopes\' TCP sweep ports so their certificates are found too.' } };
  }

  function configure(input, who) {
    if (/^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(who.user || ''))) throw httpErr(403, 'a service or AI identity cannot change these settings');
    const b = body(input || {}).bool('enabled').oneOf('mode', ['add', 'propose']).list('ports', { max: 32, unique: true }).bool('include_unapproved').num('every_hours', { min: 1, max: 168 }).done();
    if (b.ports && b.ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) throw httpErr(400, 'ports: each must be a TCP port number (1-65535)');
    if (b.ports && !b.ports.length) throw httpErr(400, 'ports needs at least one port');
    if (b.every_hours !== undefined && !Number.isInteger(b.every_hours)) throw httpErr(400, 'every_hours must be a whole number of hours (1-168)');
    const c = Object.assign(cfg(), b, { id: 'cfg', updated_by: who.user, updated_at: iso() });
    cfgC().put(c);
    audit(who, 'certs.autodiscovery.settings', 'discovery', { enabled: c.enabled, mode: c.mode, ports: c.ports, include_unapproved: c.include_unapproved, every_hours: c.every_hours });
    return view();
  }

  async function tick() {
    const c = cfg();
    if (!c.enabled) return null;
    if (c.last_run && now() - Date.parse(c.last_run.finished) < c.every_hours * 3600000) return null;
    return run(SYSTEM);
  }
  if (!(app.noTimers || opts.noTimer)) { const t = setInterval(guardOf(app, 'certs.autodiscovery', tick), 15 * 60000); if (t.unref) t.unref(); }
  return { view, configure, run, runFor, tick, candidates };
}

function registerCertAutodiscoverRoutes(srv, app, A) {
  srv.route('GET', '/certs/autodiscovery', (ctx) => { ctx.need('operator'); return A.view(); });
  srv.route('POST', '/certs/autodiscovery', (ctx) => { ctx.need('admin'); return A.configure(ctx.body, ctx.who); });
  srv.route('POST', '/certs/autodiscovery/run', async (ctx) => { ctx.need('operator'); body(ctx.body).done(); return A.runFor(ctx.who, Number(process.env.SENTRA_CERT_WAIT_MS) || 20000); });
}

module.exports = { createCertAutodiscover, registerCertAutodiscoverRoutes, DEFAULT_PORTS };
