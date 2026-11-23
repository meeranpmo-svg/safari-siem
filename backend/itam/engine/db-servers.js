// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
/*
 * Database servers (Databases -> Database Servers, {P} = /api/itam): the hosts the monitored Oracle databases run on, which
 * the DBA looks after - each aligned with its IT asset record, and its operating system read over SSH.
 *
 * Servers = every host of a database Database health reads (Asset Discovery proven logins + registered databases), one row
 * per host. The asset each one is, in this order (never by name similarity alone):
 *   1. a link an administrator set here (POST /db-servers/link) - stored, audited
 *   2. the Asset Discovery device for that IP, when it is linked to an asset
 *   3. an asset whose management IP is that IP
 *   A host-name match is only a SUGGESTION shown to the administrator; a server with no asset is a finding ("not in the
 *   asset register"), so ownership, warranty and end of life are tracked for every database server.
 *
 * Operating system health: inv-helper.py op "ssh_health" - fixed read-only commands (file systems, inodes, memory / swap,
 * load, Oracle processes vs oratab, listeners, NTP, HugePages / THP, uptime, last patch). Same trust rule as Asset
 * Discovery: the SSH host key must be one an administrator trusted (disc_trust), checked BEFORE the password is sent; the
 * login is the SSH credential Asset Discovery proved on that host, or one an administrator chose here. A server that cannot
 * be read says why - it is never shown as healthy. Every config.db_servers.interval_min (default 15).
 * Readings also go to the SIEM (kinds db_server / db_server_fs, keyed by the database instance on that host) so the AI
 * Oracle DBA and the detections see them.
 *
 * Routes: GET /db-servers (operator) · POST /db-servers/run (operator) · POST /db-servers/link {ip, asset_id|null} (admin)
 *         POST /db-servers/ssh {ip, cred_id|null} (admin)
 */
const SEV = { critical: 4, high: 3, medium: 2, low: 1 };
const CLOSED = { disposed: 1, retired: 1 };
const ORA_MOUNT = /^\/(u0\d|u\d\d|oracle|ora\w*|app|arch\w*|fra|redo\w*|data\w*|backup\w*|orabackup\w*)(\/|$)/i;

function createDbServers(app, opts = {}) {
  const store = app.store, devs = store.collection('disc_devices'), assets = store.collection('assets'), trustCol = store.collection('disc_trust');
  const links = store.collection('db_server_links'), snaps = store.collection('db_server_health');
  const dc = (app.config && app.config.discovery) || {};
  const cfg = () => Object.assign({ enabled: true, interval_min: 15, fs_warn: 85, fs_high: 90, fs_crit: 95 }, (app.config && app.config.db_servers) || {});
  const D = () => opts.discovery || app.discovery || null;
  const H = () => opts.dbHealth || (app.addons && app.addons.dbHealth) || null;
  const runHelper = opts.invRun || require('./discovery/methods/login').realRunner(dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3');
  const now = opts.now || Date.now;
  const lg = app.log || { info() {}, warn() {} };
  const bad = (m, status = 400) => Object.assign(new Error(m), { status });
  const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
  const short = (v) => low(v).split('.')[0];
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || 'system:itam-db-servers', role: (who && who.role) || 'system', ip: (who && who.ip) || '', action, target, detail }); };
  let timer = null, running = null;

  function vaultSsh() { try { const V = D() && D().vault; return V ? (V.list() || []).filter((c) => c.kind === 'ssh') : []; } catch (e) { return []; } }
  // hosts of the monitored databases, one per IP, with the databases on each
  function hosts() {
    const T = (H() && H().targets && H().targets().list) || [], by = new Map();
    for (const t of T) {
      const ip = String(t.ip || '').trim(); if (!ip) continue;
      const h = by.get(ip) || { ip, host: t.host || ip, device_id: t.device_id || null, asset_id: t.asset_id || null, databases: [] };
      h.databases.push({ instance: t.instance || '', service: t.service || '', credential: t.cred_label || '', registered: !!t.reg_id, asset_id: t.asset_id || null });
      if (!h.device_id && t.device_id) h.device_id = t.device_id;
      if (!h.asset_id && t.asset_id) h.asset_id = t.asset_id;
      by.set(ip, h);
    }
    return [...by.values()];
  }
  function assetView(a, how) { return a ? { id: a.id, name: a.name || null, asset_tag: a.asset_tag || null, type: a.type || null, status: a.status || null, owner: a.owner || a.assigned_to || null, department: a.department || null,
    vendor: a.vendor || null, model: a.model || null, serial: a.serial || null, warranty_end: (a.warranty && a.warranty.end) || null, location: a.location || null, how } : null; }
  // the asset this server is (see the header for the order); a host-name match is a suggestion only
  function resolveAsset(h) {
    const L = links.get(h.ip);
    if (L && L.asset_id) { const a = assets.get(L.asset_id); if (a) return { asset: assetView(a, 'linked by ' + (L.by || 'an administrator')), suggestion: null }; }
    const dev = (h.device_id && devs.get(h.device_id)) || devs.all((d) => d.ip === h.ip)[0] || null;
    if (dev && dev.asset_id) { const a = assets.get(dev.asset_id); if (a && !CLOSED[a.status]) return { asset: assetView(a, 'Asset Discovery device'), suggestion: null, device: dev }; }
    if (h.asset_id) { const a = assets.get(h.asset_id); if (a && !CLOSED[a.status]) return { asset: assetView(a, 'database registration'), suggestion: null, device: dev }; }
    const byIp = assets.all((a) => !CLOSED[a.status] && a.mgmt_ip && low(a.mgmt_ip) === low(h.ip))[0];
    if (byIp) return { asset: assetView(byIp, 'management IP'), suggestion: null, device: dev };
    const names = [short(h.host), short(dev && dev.hostname)].filter((x) => x && x.length >= 3);
    const sug = names.length ? assets.all((a) => !CLOSED[a.status] && a.name && names.includes(short(a.name)))[0] : null;
    return { asset: null, suggestion: sug ? assetView(sug, 'same host name - confirm to link') : null, device: dev };
  }
  // which SSH login and trusted host key to use for a server
  function sshFor(h, dev) {
    const L = links.get(h.ip) || {}, creds = vaultSsh();
    let cred = L.ssh_cred_id ? creds.find((c) => c.id === L.ssh_cred_id) : null, via = cred ? 'chosen here' : '';
    const proven = dev && dev.extra && dev.extra.unix_login && dev.extra.unix_login.credential;
    if (!cred && proven) { cred = creds.find((c) => c.label === proven) || null; via = cred ? 'proven by Asset Discovery' : ''; }
    const port = (cred && cred.target && cred.target.port) || 22;
    const tr = trustCol.get(`ssh:${h.ip}:${port}`);
    return { cred, via, port, trust: tr || null };
  }

  function findings(h, s, A, S) {
    const C = cfg(), out = [], add = (severity, kind, title, rec, evidence) => out.push({ ip: h.ip, host: h.host, severity, kind, title, recommendation: rec, evidence: (evidence || []).filter(Boolean) });
    if (!A.asset) add('low', 'asset', `${h.host}: not in the IT asset register`, A.suggestion ? `Asset "${A.suggestion.name}" has the same host name - confirm the link here.` : 'Approve it from Asset Discovery or add it as a server asset, then link it here, so owner, warranty and end of life are tracked.');
    else if (A.asset.warranty_end && Date.parse(A.asset.warranty_end) < now()) add('low', 'warranty', `${h.host}: hardware warranty ended ${A.asset.warranty_end}`, 'Renew support or plan the replacement (End of Life & Isolation).');
    if (!s || !s.server) {
      const why = !S.cred ? 'no SSH login: Asset Discovery has not proven one on this host - choose one here (read-only account)' : !S.trust ? 'the SSH host key has not been seen yet - run Asset Discovery (unix method) on this host' : S.trust.state !== 'trusted' ? `the SSH host key is ${S.trust.state} - an administrator must trust it in Asset Discovery → Trust` : (s && s.error) || 'not read yet';
      add(s && s.error ? 'medium' : 'low', 'not-read', `${h.host}: operating system not read`, why, s && s.error_class ? ['error: ' + s.error_class] : []);
      return out;
    }
    const v = s.server;
    for (const f of v.filesystems || []) {
      if (f.used_pct == null) continue;
      const ora = ORA_MOUNT.test(f.mount), sev = f.used_pct >= C.fs_crit ? 'critical' : f.used_pct >= C.fs_high ? 'high' : f.used_pct >= C.fs_warn ? 'medium' : null;
      if (sev) add(sev, 'filesystem', `${h.host} ${f.mount} ${f.used_pct}% full${ora ? ' (Oracle file system)' : ''}`, ora ? 'Archive logs, trace / audit files or datafile growth: free space (RMAN delete obsolete / archivelog backed up, adrci purge) or extend the volume before the database stops.' : 'Free space or extend the volume.', [`${Math.round(f.avail_kb / 1048576 * 10) / 10} GB free of ${Math.round(f.size_kb / 1048576 * 10) / 10} GB`, f.fs]);
    }
    for (const i of v.inodes || []) if (i.used_pct >= 90) add('high', 'inodes', `${h.host} ${i.mount}: ${i.used_pct}% of inodes used`, 'Usually millions of small trace / audit (.aud) files: purge them (adrci purge, audit trail cleanup).');
    if (v.mem_total_mb && v.mem_avail_mb != null) { const p = Math.round(v.mem_avail_mb / v.mem_total_mb * 100); if (p < 10) add(p < 5 ? 'high' : 'medium', 'memory', `${h.host}: only ${p}% memory available`, 'Check SGA + PGA against host memory and other processes (top).', [`${v.mem_avail_mb} MB of ${v.mem_total_mb} MB`]); }
    if (v.swap_total_mb && v.swap_used_mb != null && v.swap_used_mb / v.swap_total_mb > 0.5) add('medium', 'swap', `${h.host}: ${Math.round(v.swap_used_mb / v.swap_total_mb * 100)}% of swap in use`, 'An Oracle host swapping is slow everywhere: reduce memory targets or add memory; HugePages keep the SGA out of swap.');
    if (v.ncpu && v.load5 != null) { const r = v.load5 / v.ncpu; if (r > 1.5) add(r > 2 ? 'high' : 'medium', 'load', `${h.host}: load ${v.load5} on ${v.ncpu} CPUs (5 min)`, 'CPU is saturated: see Top SQL on Database Performance and the top processes.', (v.top || []).slice(0, 3).map((x) => `${x.command} ${x.cpu_pct}% CPU`)); }
    const running = new Set((v.oracle && v.oracle.pmon || []).map((x) => x.toUpperCase()));
    for (const o of v.oratab || []) if (o.autostart && !running.has(String(o.sid).toUpperCase()) && !/^\+ASM/i.test(o.sid)) add('critical', 'instance-down', `${h.host}: instance ${o.sid} is in oratab (start = Y) but not running`, 'The database (or this instance of it) is down on this server: check the alert log and start it - or set N in /etc/oratab if it moved.', ['no ora_pmon_' + o.sid + ' process']);
    if (running.size && v.oracle && !v.oracle.listeners.length) add('high', 'listener', `${h.host}: no listener (tnslsnr) running`, 'Applications cannot connect: lsnrctl start (or srvctl start listener under Grid Infrastructure).');
    if (v.ntp_synced === false) add('medium', 'ntp', `${h.host}: clock not synchronised (NTP)`, 'Data Guard, RAC and audit timelines need synchronised clocks: fix chrony / ntpd.');
    if (v.thp && v.thp !== 'never') add('low', 'thp', `${h.host}: Transparent HugePages is "${v.thp}"`, 'Oracle recommends disabling THP on database servers (transparent_hugepage=never) - change at the next reboot window.');
    if (v.mem_total_mb >= 32768 && v.hugepages_total === 0 && running.size) add('low', 'hugepages', `${h.host}: HugePages not configured (${Math.round(v.mem_total_mb / 1024)} GB host)`, 'Configure HugePages for the SGA (use_large_pages=ONLY): less memory overhead, no SGA swapping.');
    if (v.last_patch && now() - Date.parse(v.last_patch) > 180 * 86400000) add('medium', 'patch', `${h.host}: last OS package installed ${v.last_patch}`, 'Patch the operating system in the next maintenance window (coordinate with the database / Data Guard switchover).');
    if (v.uptime_s != null && v.uptime_s > 365 * 86400) add('low', 'uptime', `${h.host}: up ${Math.round(v.uptime_s / 86400)} days`, 'A year without a restart usually means kernel patches are not applied.');
    return out;
  }

  function view() {
    const H0 = hosts(), rows = [], all = [];
    for (const h of H0) {
      const A = resolveAsset(h), S = sshFor(h, A.device), s = snaps.get(h.ip) || null, F = findings(h, s, A, S);
      all.push(...F);
      const v = s && s.server, fsMax = v ? (v.filesystems || []).filter((f) => f.used_pct != null).sort((a, b) => b.used_pct - a.used_pct)[0] || null : null;
      rows.push({ ip: h.ip, host: h.host, databases: h.databases, asset: A.asset, asset_suggestion: A.suggestion,
        os: (v && v.os) || (A.device && A.device.os) || null, read_at: s ? s.at : null, read_error: s && s.error ? s.error : null,
        ssh: { credential: S.cred ? S.cred.label : null, via: S.via || null, port: S.port, host_key: S.trust ? S.trust.state : 'not seen' },
        server: v || null, fs_fullest: fsMax, findings: F.length, worst: F.reduce((m, f) => (SEV[f.severity] > SEV[m] ? f.severity : m), F.length ? 'low' : null) });
    }
    all.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
    return { generated_at: new Date(now()).toISOString(), settings: cfg(), servers: rows, findings: all, ssh_logins: vaultSsh().map((c) => ({ id: c.id, label: c.label })),
      summary: { servers: rows.length, read: rows.filter((r) => r.server).length, in_asset_register: rows.filter((r) => r.asset).length, critical: all.filter((f) => f.severity === 'critical').length, high: all.filter((f) => f.severity === 'high').length } };
  }

  async function readOne(h) {
    const A = resolveAsset(h), S = sshFor(h, A.device), at = new Date(now()).toISOString();
    if (!S.cred || !S.trust || S.trust.state !== 'trusted') { snaps.put({ id: h.ip, at, error: null, server: (snaps.get(h.ip) || {}).server || null, skipped: !S.cred ? 'no-login' : 'host-key' }); return null; }
    const V = D().vault, c = V.open(S.cred.id);
    let r;
    try { r = await runHelper({ op: 'ssh_health', host: h.ip, port: S.port, username: c.secret.username, password: c.secret.password, private_key: c.secret.private_key, fp: S.trust.fp }); }
    finally { c.release(); }
    if (!r || !r.ok) {
      if (r && r.error_class === 'hostkey_changed' && D().trust) D().trust.see('ssh', h.ip, S.port, r.fp, {});   // shows up for an administrator to decide; never auto-accepted
      snaps.put({ id: h.ip, at, error: (r && r.error) || 'no answer', error_class: (r && r.error_class) || 'error', server: null });
      return null;
    }
    snaps.put({ id: h.ip, at, server: r.server, error: null });
    return r.server;
  }
  // the server readings for the SIEM, on the database instance(s) of that host
  function records(h, v) {
    const insts = [...new Set(h.databases.map((d) => String(d.instance || d.service || '').toUpperCase()).filter(Boolean))]; if (!insts.length) return [];
    const t = new Date(now()).toISOString(), out = [];
    for (const inst of insts) {
      const common = { collector: 'sentra-oracle-itam', t, host: h.host, instance: inst, db_name: inst };
      out.push(Object.assign({ kind: 'db_server', ip: h.ip, os: v.os, uptime_s: v.uptime_s, load5: v.load5, ncpu: v.ncpu, mem_total_mb: v.mem_total_mb, mem_avail_mb: v.mem_avail_mb,
        swap_total_mb: v.swap_total_mb, swap_used_mb: v.swap_used_mb, ntp_synced: v.ntp_synced, thp: v.thp, pmon: (v.oracle.pmon || []).join(','), listeners: (v.oracle.listeners || []).join(','),
        oratab_down: (v.oratab || []).filter((o) => o.autostart && !(v.oracle.pmon || []).map((x) => x.toUpperCase()).includes(o.sid.toUpperCase()) && !/^\+ASM/i.test(o.sid)).map((o) => o.sid).join(','), last_patch: v.last_patch }, common));
      for (const f of (v.filesystems || []).filter((x) => x.used_pct != null).slice(0, 40)) out.push(Object.assign({ kind: 'db_server_fs', mount: f.mount, used_pct: f.used_pct, size_mb: Math.round(f.size_kb / 1024), avail_mb: Math.round(f.avail_kb / 1024), oracle_fs: ORA_MOUNT.test(f.mount) }, common));
    }
    return out;
  }
  async function pass() {
    if (running) return running;
    running = (async () => {
      const res = { at: new Date(now()).toISOString(), servers: 0, read: 0, skipped: 0, failed: 0, sent: 0 };
      if (!cfg().enabled) return Object.assign(res, { note: 'switched off (config db_servers.enabled)' });
      const batch = [];
      for (const h of hosts()) {
        res.servers++;
        try { const v = await readOne(h); if (v) { res.read++; batch.push(...records(h, v)); } else if ((snaps.get(h.ip) || {}).skipped) res.skipped++; else res.failed++; }
        catch (e) { res.failed++; snaps.put({ id: h.ip, at: res.at, error: String(e.message || e).slice(0, 200), error_class: 'error', server: null }); }
      }
      if (batch.length && H() && typeof H().push === 'function') { try { res.sent = await H().push(batch); } catch (e) { res.push_error = String(e.message || e).slice(0, 200); } }
      if (res.failed || res.push_error) lg.warn('db-servers pass', res);
      return res;
    })().finally(() => { running = null; });
    return running;
  }
  function link(b, who) {
    const ip = String((b && b.ip) || '').trim(); if (!hosts().some((h) => h.ip === ip)) throw bad('not a monitored database server', 404);
    const id = b.asset_id == null || b.asset_id === '' ? null : String(b.asset_id);
    if (id) { const a = assets.get(id); if (!a || CLOSED[a.status]) throw bad('asset not found (or disposed)', 404); }
    const cur = links.get(ip) || { id: ip };
    links.put(Object.assign(cur, { asset_id: id, by: (who && who.user) || '', at: new Date(now()).toISOString() }));
    audit(who, 'db.servers.link', ip, { asset_id: id });
    return view().servers.find((x) => x.ip === ip);
  }
  function setSsh(b, who) {
    const ip = String((b && b.ip) || '').trim(); if (!hosts().some((h) => h.ip === ip)) throw bad('not a monitored database server', 404);
    const id = b.cred_id == null || b.cred_id === '' ? null : String(b.cred_id);
    if (id && !vaultSsh().some((c) => c.id === id)) throw bad('choose a saved SSH login (Asset Discovery → Credentials, kind ssh)');
    const cur = links.get(ip) || { id: ip };
    links.put(Object.assign(cur, { ssh_cred_id: id, ssh_by: (who && who.user) || '', ssh_at: new Date(now()).toISOString() }));
    audit(who, 'db.servers.ssh', ip, { cred_id: id });
    return view().servers.find((x) => x.ip === ip);
  }
  function start() { if (timer) return; timer = setInterval(guardOf(app, 'db-servers.pass', () => pass()), Math.max(5, Number(cfg().interval_min) || 15) * 60000); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  return { hosts, view, pass, link, setSsh, start, stop, resolveAsset, findings };
}

function registerDbServers(srv, app, opts = {}) {
  const S = createDbServers(app, opts);
  (app.addons = app.addons || {}).dbServers = S;
  srv.route('GET', '/db-servers', (ctx) => { ctx.need('operator'); return S.view(); });
  srv.route('POST', '/db-servers/run', async (ctx) => { ctx.need('operator'); return S.pass(); });
  srv.route('POST', '/db-servers/link', (ctx) => { ctx.need('admin'); return S.link(ctx.body || {}, ctx.who); });
  srv.route('POST', '/db-servers/ssh', (ctx) => { ctx.need('admin'); return S.setSsh(ctx.body || {}, ctx.who); });
  if (!opts.noTimer) { S.start(); const t = setTimeout(guardOf(app, 'db-servers.pass', () => S.pass()), 180000); if (t.unref) t.unref(); }
  return S;
}

module.exports = { createDbServers, registerDbServers, ORA_MOUNT };
