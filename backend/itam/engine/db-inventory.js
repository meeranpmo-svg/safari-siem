// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { guardOf } = require('./errors');
/*
 * Oracle, SQL Server, PostgreSQL and MySQL details, pulled automatically from the servers already in the platform ({P} = /api/itam).
 * Nothing is typed in by hand:
 *   - which servers run a database comes from what the platform already knows: Asset Discovery's proven read-only login on
 *     the host (disc_devices extra.db_login.<engine>) and the Business Services map (a SQL Server / PostgreSQL / MySQL service
 *     confirmed on a server, engine/service-map.js) - and, for Oracle, the databases registered on the Databases page
 *   - every server with a proven login is READ every pass (config.db_inventory.interval_h, default 6) through
 *     inv-helper.py op db_details: server version, edition, start time, sessions, every database with its state, size,
 *     recovery model and last backup (SQL Server), and the replication role - fixed SELECTs, a read-only session where the
 *     engine supports it; a query the login may not run is listed as "missing privilege", never guessed
 *   - a server where a database service is confirmed but no login is proven is listed as FOUND with the exact statements a
 *     DBA runs to create a read-only login; the login is then added in Asset Discovery (the vault seals it) and the next
 *     scan proves it - a password is never tried against a server it was not proven on, so no account can be locked out
 * Results are linked to the asset (asset_id) and kept in db_inventory. Oracle health, tablespaces and performance stay on
 * Database Health (every 4 min); this is the inventory view, with the same rule: an Oracle account holding more than
 * read-only monitoring rights is refused before any query runs.
 * No lockout: after a refused login (or an unsafe account) the timer stops reading that server - only a person retries it
 * (Read now), after fixing the login.
 *
 *   GET  /db-inventory          operator   servers read, servers found without a login, totals, the read-only login scripts
 *   POST /db-inventory/run      operator   read every server now                                                  audited
 *   POST /db-inventory/settings admin      {interval_h}                                                           audited
 */
const ENGINES = ['oracle', 'mssql', 'postgres', 'mysql'];
const LABEL = { oracle: 'Oracle', mssql: 'SQL Server', postgres: 'PostgreSQL', mysql: 'MySQL / MariaDB' };
const HOLD = new Set(['auth', 'unsafe']);   // a refused login / an unsafe account: not retried by the timer
const DAY = 86400000;
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const num = (v) => (v == null || v === '' || Number.isNaN(Number(v)) ? null : Number(v));
// the read-only login a DBA creates once per server (shown on the page; the platform never runs these)
const GRANTS = {
  oracle: ['-- the Oracle monitoring account (＋ Add database, install/oracle-monitor-account.sql): CREATE SESSION and SELECT ANY DICTIONARY only', 'CREATE USER zyb_monitor IDENTIFIED BY "<strong password>";', 'GRANT CREATE SESSION, SELECT ANY DICTIONARY TO zyb_monitor;'],
  mssql: ['CREATE LOGIN zyb_monitor WITH PASSWORD = \'<strong password>\', CHECK_POLICY = ON;', 'GRANT VIEW SERVER STATE TO zyb_monitor;', 'GRANT VIEW ANY DEFINITION TO zyb_monitor;',
    'USE msdb; CREATE USER zyb_monitor FOR LOGIN zyb_monitor; GRANT SELECT ON dbo.backupset TO zyb_monitor;'],
  postgres: ['CREATE ROLE zyb_monitor LOGIN PASSWORD \'<strong password>\';', 'GRANT pg_monitor TO zyb_monitor;   -- read-only statistics, no table data'],
  mysql: ['CREATE USER \'zyb_monitor\'@\'<platform server IP>\' IDENTIFIED BY \'<strong password>\';', 'GRANT PROCESS, SHOW DATABASES ON *.* TO \'zyb_monitor\'@\'<platform server IP>\';',
    'GRANT SELECT ON performance_schema.* TO \'zyb_monitor\'@\'<platform server IP>\';'],
};

function createDbInventory(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const col = () => store.collection('db_inventory'), cfgCol = () => store.collection('db_inventory_cfg');
  const L = app.log || { every() {} };
  const every = (key, msg, ctx) => { if (L.every) L.every('dbinv:' + key, 3600000, 'warn', msg, ctx); };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'db_inventory.' + action, target, detail }); };
  let runHelper = null;
  const helper = () => opts.invRun || runHelper || (runHelper = require('./discovery/methods/login').realRunner(((app.config && app.config.discovery) || {}).python_bin || '/opt/sentra-siem/pyenv/bin/python3'));
  const settings = () => Object.assign({ interval_h: 6 }, ((app.config && app.config.db_inventory) || {}), cfgCol().get('cfg') || {});
  const targets = () => require('./db-targets').dbTargets(app, { engines: ENGINES });
  let running = null, timer = null;

  // servers where a database service is confirmed (Business Services) - the ones without a proven login are "found"
  function detected() {
    const S = app.addons && app.addons.serviceMap; if (!S) return [];
    let rows = []; try { rows = S.view('operator').servers || []; } catch (e) { every('svc', 'database inventory: the Business Services map was not read', { err: s(e.message, 200) }); return []; }
    const out = [];
    for (const r of rows) for (const x of r.services || []) {
      if (!ENGINES.includes(x.id) || x.confidence !== 'confirmed') continue;
      out.push({ engine: x.id, ip: r.ip, host: r.host || r.ip, asset_id: r.asset ? r.asset.id : null, asset_name: r.asset ? r.asset.name : null, evidence: s((x.evidence || []).map((e) => e.detail || e).join('; '), 300) });
    }
    return out;
  }
  function assetName(id) { if (!id) return null; try { const a = store.collection('assets').get(id); return a ? s(a.name || a.asset_tag || id, 120) : null; } catch (e) { return null; } }

  // one engine's rows → one shape: {name, state, size_mb, recovery, last_full, last_log, read_only, encoding, sessions}
  function shape(eng, r) {
    const one = (k) => (Array.isArray(r[k]) && r[k][0]) || null, sv = one('server') || [], st = one('started') || [];
    const sys = new Set(r.system || []);
    const dbRows = eng === 'oracle' && !(r.databases || []).length ? (r.database_noncdb || []) : (r.databases || []);
    const bk = eng === 'oracle' ? ((r.backup || [])[0] || []) : [];
    const dbs = dbRows.map((d) => {
      if (eng === 'oracle') return { name: s(d[0], 128), state: s(d[1], 30), size_mb: num(d[2]), restricted: d[3] === 'YES', last_full: bk[0] ? s(bk[0], 19) + 'Z' : null, last_log: bk[1] ? s(bk[1], 19) + 'Z' : null };
      if (eng === 'mssql') return { name: s(d[0], 128), state: s(d[1], 30), recovery: s(d[2], 20), compat: num(d[3]), size_mb: num(d[4]), last_full: d[5] ? s(d[5], 19) + 'Z' : null, last_log: d[6] ? s(d[6], 19) + 'Z' : null, read_only: !!d[7], access: s(d[8], 20) };
      if (eng === 'postgres') return { name: s(d[0], 128), state: s(d[1], 30), encoding: s(d[2], 30), size_mb: num(d[3]), sessions: num(d[4]), deadlocks: num(d[5]), transactions: num(d[6]) };
      return { name: s(d[0], 128), state: s(d[1], 30), encoding: s(d[2], 30), size_mb: num(d[3]), tables: num(d[4]) };
    }).map((d) => Object.assign(d, { system: sys.has(d.name) }));
    let server;
    const ses = one('sessions') || [];
    if (eng === 'oracle') server = { instance: s(sv[0], 80), host_name: s(sv[1], 120), version: s(sv[2], 40), edition: s((/(Enterprise|Standard|Express|Personal|Free)\s+Edition[^,]*/i.exec(s(sv[3], 200)) || [s(sv[3], 120)])[0], 120), status: s(sv[4], 20),
      role: s(sv[5], 30), open_mode: s(sv[6], 30), log_mode: s(sv[7], 20), db_name: s(sv[8], 60), unique_name: s(sv[9], 60), started: st[0] ? s(st[0], 19) + 'Z' : null, cpus: num(st[1]), sga_mb: num(st[2]), max_connections: num(ses[1]),
      multitenant: (r.databases || []).length > 0, last_full: bk[0] ? s(bk[0], 19) + 'Z' : null, last_arch: bk[1] ? s(bk[1], 19) + 'Z' : null };
    else if (eng === 'mssql') server = { host_name: s(sv[0], 120), instance: s(sv[1], 120), version: s(sv[2], 50), level: s(sv[3], 30), edition: s(sv[4], 120), clustered: sv[5] === 1, always_on: sv[6] === 1, collation: s(sv[7], 80), started: st[0] ? s(st[0], 19) + 'Z' : null, cpus: num(st[1]), memory_mb: num(st[2]) };
    else if (eng === 'postgres') server = { banner: s(sv[0], 200), version: s(sv[1], 40), port: num(sv[2]), max_connections: num(sv[3]), standby: sv[4] === true || sv[4] === 'true' || sv[4] === 1, started: st[0] ? s(st[0], 19) + 'Z' : null };
    else server = { version: s(sv[0], 60), edition: s(sv[1], 120), host_name: s(sv[2], 120), port: num(sv[3]), max_connections: num(sv[4]), read_only: sv[5] === 1 || sv[5] === '1', started: num(st[0]) != null ? new Date(now() - num(st[0]) * 1000).toISOString().slice(0, 19) + 'Z' : null };
    server.sessions = num((one('sessions') || [])[0]);
    const lag = (v) => { const m = /^\+?(\d+)\s+(\d+):(\d+):(\d+)/.exec(s(v, 40)); return m ? ((+m[1] * 24 + +m[2]) * 60 + +m[3]) * 60 + +m[4] : num(v); };   // Oracle '+00 00:00:05'
    const repl = (r.replication || []).map((x) => ({ name: s(x[0], 120), role: s(x[1], 40), state: s(x[2], 40), lag_s: lag(x[3]) }));
    return { server, databases: dbs, replication: repl };
  }
  // what a DBA should look at, from the facts only
  function notes(eng, rec) {
    const out = [], user = rec.databases.filter((d) => !d.system);
    if (eng === 'mssql') {
      for (const d of user) {
        if (d.state && d.state !== 'ONLINE') out.push({ severity: 'high', kind: 'db-state', subject: d.name, text: `${d.name} is ${d.state}` });
        if (d.state === 'ONLINE' && !d.last_full) out.push({ severity: 'high', kind: 'no-backup', subject: d.name, text: `${d.name}: no full backup recorded in msdb` });
        else if (d.last_full && now() - Date.parse(d.last_full) > 7 * DAY) out.push({ severity: 'medium', kind: 'old-backup', subject: d.name, text: `${d.name}: last full backup ${d.last_full.slice(0, 10)} (older than 7 days)` });
        if (d.recovery === 'FULL' && d.last_full && !d.last_log) out.push({ severity: 'medium', kind: 'no-log-backup', subject: d.name, text: `${d.name}: FULL recovery but no log backup - the log grows until one runs` });
      }
    }
    if (eng === 'oracle') {
      const sv = rec.server;
      for (const d of user) if (d.state && !/^READ WRITE$/.test(d.state) && !(sv.role && sv.role !== 'PRIMARY')) out.push({ severity: 'high', kind: 'db-state', subject: d.name, text: `${d.name} is ${d.state}${d.restricted ? ' (restricted)' : ''}` });
      if (sv.role === 'PRIMARY' || !sv.role) {
        if (!sv.last_full) out.push({ severity: 'high', kind: 'no-backup', subject: '', text: 'no completed RMAN full / incremental backup in the control file' });
        else if (now() - Date.parse(sv.last_full) > 7 * DAY) out.push({ severity: 'medium', kind: 'old-backup', subject: '', text: `last RMAN backup ${sv.last_full.slice(0, 10)} (older than 7 days)` });
        if (sv.log_mode === 'NOARCHIVELOG') out.push({ severity: 'medium', kind: 'noarchivelog', subject: '', text: 'NOARCHIVELOG: no point-in-time recovery, only the last full backup' });
        else if (sv.last_full && !sv.last_arch) out.push({ severity: 'medium', kind: 'no-log-backup', subject: '', text: 'ARCHIVELOG but no archive-log backup recorded' });
      }
      for (const x of rec.replication || []) if (x.lag_s != null && x.lag_s > 900) out.push({ severity: 'high', kind: 'repl-lag', subject: x.name, text: `Data Guard apply lag ${Math.round(x.lag_s / 60)} min on ${x.name}` });
    }
    if (rec.server.max_connections && rec.server.sessions != null && rec.server.sessions / rec.server.max_connections > 0.8) out.push({ severity: 'medium', kind: 'sessions', subject: '', text: `sessions at ${Math.round(100 * rec.server.sessions / rec.server.max_connections)}% of max_connections` });
    for (const d of user) if (d.deadlocks) out.push({ severity: 'low', kind: 'deadlocks', subject: d.name, text: `${d.name}: ${d.deadlocks} deadlock(s) since statistics reset` });
    return out.slice(0, 50);
  }

  async function pass(who, only) {
    if (running && !only) return running;
    if (running) await running.catch(() => null);   // a single re-read waits for the full pass: never two reads of one server at once (the result is in the store)
    running = (async () => {
      const V = app.discovery && app.discovery.vault, res = { at: new Date(now()).toISOString(), targets: 0, read: 0, failed: 0 };
      if (!V) return Object.assign(res, { note: 'Asset Discovery credential vault not available' });
      for (const t of targets()) {
        if (only && t.key !== only) continue;
        res.targets++;
        const last = col().get(t.key);
        if (!who && last && last.error && HOLD.has(last.error_class)) { res.held = (res.held || 0) + 1; continue; }   // no lockout: a person retries it
        let c = null, r = null, user = null;
        try {
          c = V.open(t.cred_id); const tg = c.target || {}; user = s(c.secret.username, 64);
          r = await helper()({ op: 'db_details', engine: t.engine, host: t.ip, port: t.port, username: c.secret.username, password: c.secret.password, service: t.service || tg.service, database: tg.database, tls: tg.tls || 'off', ca_file: tg.ca_file });
        } catch (e) { r = { ok: false, error: e.message, error_class: 'error' }; }
        finally { if (c) try { c.release(); } catch (e) { /* the vault entry is released on its own at the end of the read */ } }
        const base = { id: t.key, engine: t.engine, ip: t.ip, port: t.port, host: t.host, asset_id: t.asset_id || null, asset_name: assetName(t.asset_id), login: user };
        if (r && r.ok) {
          const rec = Object.assign(base, shape(t.engine, r), { at: res.at, error: null, error_class: null, missing: Object.entries(r.errors || {}).map(([k, v]) => ({ query: k, reason: s(v, 160) })) });
          rec.notes = notes(t.engine, rec);
          col().put(rec); res.read++;
        } else {
          res.failed++;
          const prev = col().get(t.key) || {};
          col().put(Object.assign({}, prev, base, { error: s((r && r.error) || 'no answer', 200), error_class: (r && r.error_class) || 'error', error_at: res.at }));
          every('read:' + t.key, 'database inventory: read failed', { engine: t.engine, ip: t.ip, cls: r && r.error_class });
        }
      }
      if (who && !only) audit(who, 'run', 'all', res);
      return res;
    })();
    const mine = running;
    try { return await mine; } finally { if (running === mine) running = null; }
  }

  function view() {
    const readKeys = new Set(), servers = [];
    const tk = new Set(targets().map((t) => t.key));
    for (const r of col().all(() => true)) {
      const stale = !tk.has(r.id);   // the login is no longer proven on that host (removed in Asset Discovery)
      readKeys.add(r.engine + '|' + r.ip);
      const user = (r.databases || []).filter((d) => !d.system);
      servers.push(Object.assign({}, r, { label: LABEL[r.engine], asset_name: r.asset_name || assetName(r.asset_id), stale,
        totals: { databases: user.length, size_mb: user.reduce((t, d) => t + (d.size_mb || 0), 0) } }));
    }
    const found = detected().filter((d) => !readKeys.has(d.engine + '|' + d.ip) && !targets().some((t) => t.engine === d.engine && t.ip === d.ip))
      .map((d) => Object.assign(d, { label: LABEL[d.engine], asset_name: d.asset_name || assetName(d.asset_id), next: 'Create the read-only login below on this server, add it in Asset Discovery → Credentials (kind database login, engine ' + d.engine + '), then run the scope: the next pass reads it.' }));
    const by = {}; for (const e of ENGINES) by[e] = { read: 0, found: 0, databases: 0, size_mb: 0 };
    for (const x of servers) if (!x.error && by[x.engine]) { by[x.engine].read++; by[x.engine].databases += x.totals.databases; by[x.engine].size_mb += x.totals.size_mb; }
    for (const x of found) by[x.engine].found++;
    servers.sort((a, b) => (a.engine + a.host).localeCompare(b.engine + b.host));
    return { generated_at: new Date(now()).toISOString(), settings: settings(), engines: ENGINES.map((e) => Object.assign({ engine: e, label: LABEL[e] }, by[e])),
      servers, found, grants: GRANTS,
      note: 'Pulled from the servers already in the platform: a database login Asset Discovery proved on the host (and, for Oracle, a database registered on this page) is read every ' + settings().interval_h + ' h with fixed read-only queries. A refused login is not retried until a person presses Read now. Oracle health and performance: Database Health, every 4 min.' };
  }
  function setSettings(input, who) {
    const b = body(input).int('interval_h', { required: true, min: 1, max: 168 }).done();
    const prev = settings().interval_h;
    cfgCol().put(Object.assign({ id: 'cfg' }, b));
    audit(who, 'settings', 'cfg', { interval_h: [prev, b.interval_h] });
    restart();
    return view();
  }
  const job = guardOf(app, 'db_inventory.pass', () => pass(null));
  function restart() { if (timer) clearInterval(timer); timer = null; start(); }
  function start() {
    if (opts.noTimer || app.noTimers || timer) return;
    timer = setInterval(job, settings().interval_h * 3600000); if (timer.unref) timer.unref();
    const first = setTimeout(job, 180000); if (first.unref) first.unref();
  }
  // one server re-read now (the AI DBA's verify after a fix); null when the server is no longer a target
  async function readOne(key) { if (!targets().some((t) => t.key === key)) return null; await pass(null, key); return col().get(key) || null; }
  const record = (key) => col().get(key) || null;
  return { pass, view, setSettings, start, shape, notes, detected, readOne, record, targets, LABEL };
}

function registerDbInventory(srv, app, D) {
  const I = D && D.view ? D : createDbInventory(app, D || {});
  (app.addons = app.addons || {}).dbInventory = I;
  srv.route('GET', '/db-inventory', (ctx) => { ctx.need('operator'); return I.view(); });
  srv.route('POST', '/db-inventory/run', async (ctx) => { ctx.need('operator'); const r = await I.pass(ctx.who); return Object.assign(I.view(), { run: r }); });
  srv.route('POST', '/db-inventory/settings', (ctx) => { ctx.need('admin'); return I.setSettings(ctx.body, ctx.who); });
  return I;
}

module.exports = { createDbInventory, registerDbInventory, ENGINES, GRANTS };
