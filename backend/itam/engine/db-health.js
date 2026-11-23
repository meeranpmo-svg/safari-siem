// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
/*
 * Oracle health from the asset inventory, for the AI Oracle DBA ({P} = /api/itam). No agent on the database hosts: the
 * read-only Oracle login an administrator already saved in Asset Discovery (credential kind db_login, engine oracle) is
 * used on every host where Asset Discovery found that login working (disc_devices extra.db_login.oracle, matched by the
 * credential's label - a login is never tried against a host it was not proven on, so no account can be locked out).
 *
 * Every pass (config.db_health.interval_min, default 4 — the SIEM marks an instance stale after 5 min without a sample):
 *   inv-helper.py op "oracle_health" → fixed read-only SELECTs (instance, tablespaces, sessions, blocked sessions, redo,
 *   last RMAN job, Data Guard lag, invalid objects, recovery area) → the SAME record kinds the Oracle collector agent sends
 *   → POSTed as NDJSON to the SIEM ingest (/ingest/<src>, X-Sentra-Token) of ONE "oracle-health" source this add-on registers
 *   once (POST /api/soc/onboard/sources over the existing loopback link, as system:itam-db-health, audited). The token is
 *   sealed in the vault (purpose sentra-itam-db-health), never logged or returned.
 * The SIEM then parses them exactly like agent samples: the AI Oracle DBA, Database Performance and detections all see them.
 * A query the account may not run is skipped and listed per host ("missing privilege"), never guessed.
 * Databases can also be REGISTERED directly (Connections & Setup → Oracle databases): host, port, service name and a
 * read-only login (sealed in the same vault as a db_login credential). One test login runs when it is added; from then on it
 * is read every pass (the dictionary scans - backup history, invalid objects - once an hour). The account is checked first:
 * one holding more than read-only monitoring privileges is refused before any query runs and the database is PAUSED (cls
 * 'unsafe'). A refused login (ORA-01017 / ORA-28000 locked / ORA-28001 expired) PAUSES that database - it is never retried on its own, so a wrong or
 * expired password cannot lock the account out - until an administrator tests it again.
 * Inventory: POST /db-health/inventory/remove {device_id, reason} · /restore {device_id} (admin) - a found database nobody wants
 *          is left out of the inventory and never read (the server stays in Asset Discovery).
 * Routes:  GET /db-health (viewer) - hosts, last read, missing privileges     POST /db-health/run (admin) - run a pass now
 *          GET /db-health/databases (operator) · POST /db-health/databases {label, host, port?, service, cred_id | username +
 *          password} (admin) · POST /db-health/databases/:id/test (admin) · POST /db-health/databases/:id/delete (admin)
 */
const loginM = require('./discovery/methods/login');
const { createSealer } = require('./discovery/vault');

const SRC_ID = 'ora-itam-assets';
const SYS = { user: 'system:itam-db-health', role: 'admin', ip: '' };

// the Oracle views each health reading needs: a reading the account may not run names the exact grants to add
const NEEDS = { instance: ['V_$INSTANCE', 'V_$DATABASE'], tablespace: ['DBA_TABLESPACE_USAGE_METRICS', 'DBA_TABLESPACES'], sessions: ['V_$SESSION', 'V_$PARAMETER'],
  blocked: ['V_$SESSION'], redo: ['V_$LOG', 'V_$LOG_HISTORY', 'V_$ARCHIVE_DEST', 'V_$ARCHIVED_LOG', 'V_$DATABASE'], backup: ['V_$RMAN_BACKUP_JOB_DETAILS'],
  dataguard: ['V_$DATAGUARD_STATS'], invalid_objects: ['DBA_OBJECTS'], fra: ['V_$RECOVERY_FILE_DEST'],
  asm: ['V_$ASM_DISKGROUP_STAT'], archive_gen: ['V_$ARCHIVED_LOG'], archive_dest: ['V_$ARCHIVE_DEST'], archive_gap: ['V_$ARCHIVE_GAP'], mrp: ['V_$MANAGED_STANDBY'], alert_errors_24h: ['V_$DIAG_ALERT_EXT'] };
// the tuning / Data Guard / connections readings (discovery/oracle-tuning.sql): the views each block reads, taken from its own
// SQL so the fix can never drift from what the platform runs. v$x -> sys.v_$x, gv$x -> sys.gv_$x, dba_x -> sys.dba_x.
let TUNING_VIEWS = null;
function tuningViews() {
  if (TUNING_VIEWS) return TUNING_VIEWS;
  TUNING_VIEWS = {};
  try {
    const text = require('node:fs').readFileSync(require('node:path').join(__dirname, 'discovery', 'oracle-tuning.sql'), 'utf8');
    for (const blk of ('\n' + text).split(/\n(?=-- @(?:kit|own|pack|fallback) )/)) {
      const m = /^\s*-- @(kit|own|pack|fallback) (\w+)/.exec(blk); if (!m || m[1] === 'fallback') continue;
      const sql = blk.split('\n').filter((l) => !/^\s*--/.test(l)).join(' ');
      const v = new Set(); let x; const re = /\b(g?v\$[a-z_]+|dba_[a-z_]+)\b/gi;
      while ((x = re.exec(sql))) v.add(x[1].toUpperCase().replace('$', '_$'));
      TUNING_VIEWS[m[2]] = [...v];
    }
  } catch (e) { TUNING_VIEWS = {}; /* the SQL file is missing: the fix falls back to the account script */ }
  return TUNING_VIEWS;
}
// what each reading feeds, in words a DBA recognises
const QLAB = { instance: 'instance status', tablespace: 'tablespaces', sessions: 'sessions', blocked: 'blocked sessions', redo: 'redo / archive', backup: 'RMAN backups',
  dataguard: 'Data Guard lag', invalid_objects: 'invalid objects', fra: 'recovery area', asm: 'ASM disk groups', archive_gen: 'archive generation', archive_dest: 'archive destinations',
  archive_gap: 'archive gaps (standby)', mrp: 'managed recovery (standby)', alert_errors_24h: 'alert log errors', audit_trail: 'Database Audit (unified audit trail)',
  wait_events: 'wait events (Oracle Tuning)', ash_sql: 'top SQL', long_query: 'long-running queries', plan_change: 'plan changes', temp_undo: 'TEMP / UNDO use', memory: 'memory (SGA / PGA)',
  limits: 'resource limits', redo_rate: 'redo rate', sqlstats: 'SQL statistics', stats_stale: 'stale statistics', gg_capture: 'GoldenGate Extract', gg_apply: 'GoldenGate Replicat',
  sched_jobs: 'long scheduler jobs (DBA alerts)', delstats: 'bulk deletes (DBA alerts)', code_change: 'code changes', code_change_by: 'who changed code', app_sessions: 'Application Connections',
  lsnr_conns: 'listener connections', db_links: 'database links', user_write: 'what application users can change', rac_nodes: 'RAC nodes', dg_config: 'Data Guard configuration',
  dg_dest: 'Data Guard transport', dg_applied: 'Data Guard apply', dg_stats: 'Data Guard lag', dg_process: 'Data Guard processes', dg_gap: 'Data Guard gaps', dg_event: 'Data Guard errors',
  dg_broker: 'Data Guard broker', dg_srl: 'standby redo logs', dg_nologging: 'NOLOGGING changes', audit_config: 'audit configuration' };
// ORA codes that mean the account may not read the object (a grant fixes it) vs a query the platform sent that Oracle refused
const GRANT_ORA = new Set(['ORA-00942', 'ORA-01031', 'ORA-04043', 'ORA-01039']);
const QUERY_ORA = /^ORA-(009(0[4-9]|1[78]|2[013]|3[2-7]|79)|01722|01790|0655[0-3]|4\d{4})$/;
function missingDetail(errors, account) {
  const who = /^[A-Za-z0-9_$#]{1,128}$/.test(String(account || '')) ? String(account).toLowerCase() : '<monitoring user>';
  return (errors || []).map((e) => {
    const ora = e.ora || ((/ORA-\d{5}/.exec(e.error || '') || [])[0] || ''), txt = String(e.error || '');
    const views = e.query === 'audit_trail' ? [] : (NEEDS[e.query] || tuningViews()[e.query] || []);
    let kind = 'other', fix;
    if (GRANT_ORA.has(ora) || (!ora && /privilege|insufficient|does not exist|not authori[sz]ed/i.test(txt))) kind = 'grant';
    else if (QUERY_ORA.test(ora)) kind = 'platform';
    else if (/time ?out|timed out|DPY-4024|call timeout|took longer/i.test(txt)) kind = 'timeout';
    const grants = kind !== 'grant' ? [] : e.query === 'audit_trail' ? ['GRANT AUDIT_VIEWER TO ' + who + ';'] : views.map((v) => 'GRANT SELECT ON sys.' + v.toLowerCase() + ' TO ' + who + ';');
    if (kind === 'grant') fix = grants.length ? 'Your DBA grants read access (script below), then the next read picks it up by itself.' : 'Re-run the account script from Add database for this account.';
    else if (kind === 'platform') fix = 'A query the platform sends was refused by this Oracle release (' + ora + ') - not a grant. It is fixed in the platform; install the update. Nothing for the DBA to do.';
    else if (kind === 'timeout') fix = 'The reading took longer than its 10-second limit (busy database or a large view). It is retried at every read; if it keeps happening, tell the platform team.';
    else fix = (ora ? ora + ': ' : '') + 'look up the error in the database alert log; it is retried at every read.';
    return { query: e.query, label: QLAB[e.query] || e.query, error: txt.slice(0, 300), ora, kind, grants, fix };
  });
}
// one script for the DBA: every grant this database still needs, once each, naming the real account
function fixScript(detail) { return [...new Set((detail || []).flatMap((d) => d.grants || []))]; }
function createDbHealth(app, opts = {}) {
  const store = app.store, devs = store.collection('disc_devices'), meta = store.collection('db_health_meta'), regs = store.collection('db_health_targets');
  const dc = (app.config && app.config.discovery) || {};
  const sc = dc.siem || {};
  const cfg = () => Object.assign({ enabled: true, interval_min: 4, max_hosts: 100 }, (app.config && app.config.db_health) || {});
  const D = () => opts.discovery || app.discovery || null;
  const runHelper = opts.invRun || loginM.realRunner(dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3');
  const request = opts.request || require('./discovery/httpc').request;
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-db-health' });
  const base = String(sc.base_url || 'http://127.0.0.1:9120').replace(/\/+$/, '');
  const now = opts.now || Date.now;
  const lg = app.log || { info() {}, warn() {} };
  const audit = (action, target, detail) => { if (app.audit) app.audit({ by: SYS.user, role: 'system', ip: '', action, target, detail }); };
  let running = null, timer = null;
  // admin switches kept in the store (they override config): diagnostics_pack = the Oracle Diagnostics Pack licence is
  // confirmed, so V$ACTIVE_SESSION_HISTORY may be read (audited, with who confirmed it and why)
  const settings = () => Object.assign({ diagnostics_pack: !!cfg().diagnostics_pack, tuning: cfg().tuning !== false, audit: cfg().audit !== false }, ((meta.get('settings') || {}).value) || {});
  // Top SQL: the previous V$SQLSTATS snapshot per database; deltas between two passes become sql_delta records
  const snaps = new Map();
  // bulk deletes: rows deleted per DELETE statement since the previous pass. A statement not in the previous snapshot (new in
  // the shared pool, or reloaded - its counters restart at 0) counts in full; the first pass after a restart is only a baseline.
  const delSnaps = new Map();
  function deleteDeltas(key, rows, at) {
    const prev = delSnaps.get(key), cur = new Map();
    for (const x of rows || []) cur.set(x.sql_id + ':' + x.plan_hash, x);
    delSnaps.set(key, { at, m: cur });
    if (!prev || at <= prev.at) return [];
    const out = [];
    for (const [k, x] of cur) {
      const p = prev.m.get(k), rws = Math.max(0, (Number(x.rows_processed) || 0) - (p ? Number(p.rows_processed) || 0 : 0));
      if (!rws) continue;
      const m = /^\s*delete\s+(?:\/\*.*?\*\/\s*)?(?:from\s+)?("?[\w$#]+"?(?:\."?[\w$#]+"?)?)/i.exec(String(x.sql_text || ''));
      out.push({ kind: 'bulk_delete', sql_id: x.sql_id, rows_deleted: rws, executions: Math.max(0, (Number(x.executions) || 0) - (p ? Number(p.executions) || 0 : 0)), user: x.user || '', module: x.module || '',
        table: m ? m[1].replace(/"/g, '').toUpperCase() : '', sql_text: x.sql_text || '', period_s: Math.round((at - prev.at) / 1000), new_cursor: !p });
    }
    return out.sort((a, b) => b.rows_deleted - a.rows_deleted).slice(0, 25);
  }
  function sqlDeltas(key, rows, at) {
    const prev = snaps.get(key), cur = new Map();
    for (const x of rows || []) cur.set(x.sql_id + ':' + x.plan_hash, x);
    snaps.set(key, { at, m: cur });
    if (!prev || at <= prev.at) return [];
    const period = Math.round((at - prev.at) / 1000), out = [];
    for (const [k, x] of cur) {
      const p = prev.m.get(k); if (!p) continue;
      const d = (f) => Math.max(0, (Number(x[f]) || 0) - (Number(p[f]) || 0));
      const ex = d('executions'), ela = d('elapsed_us'); if (!ex && !ela) continue;
      const per = (v) => (ex ? Math.round(v / ex * 1000) / 1000 : null);
      out.push({ kind: 'sql_delta', sql_id: x.sql_id, plan_hash: x.plan_hash, module: x.module || '', user: x.user || '', sql_text: x.sql_text || '', executions: ex,
        elapsed_s: Math.round(ela / 1e3) / 1e3, cpu_s: Math.round(d('cpu_us') / 1e3) / 1e3, buffer_gets: d('buffer_gets'), disk_reads: d('disk_reads'), rows_processed: d('rows_processed'),
        ela_ms_exec: per(ela / 1000), cpu_ms_exec: per(d('cpu_us') / 1000), gets_exec: per(d('buffer_gets')), reads_exec: per(d('disk_reads')), rows_exec: per(d('rows_processed')),
        execs_s: period ? Math.round(ex / period * 1000) / 1000 : null, period_s: period, top_by: 'elapsed' });
    }
    out.sort((a, b) => b.elapsed_s - a.elapsed_s);
    return out.slice(0, 25).map((x, i) => Object.assign(x, { rank: i + 1 }));
  }

  // hosts × the Oracle login proven on each (label match only)
  function targets() {
    const d = D(), V = d && d.vault; if (!V) return { list: [], creds: 0 };
    let creds = []; try { creds = (V.list() || []).filter((c) => c.kind === 'db_login' && c.target && c.target.engine === 'oracle'); } catch (e) { creds = []; }
    const out = [], seen = new Set();
    const gone = dismissedIds();
    for (const x of devs.all((v) => v.ip && v.status !== 'ignored' && !gone.has(v.id) && v.extra && v.extra.db_login && v.extra.db_login.oracle)) {
      const o = x.extra.db_login.oracle;
      for (const c of creds.filter((k) => k.label === o.credential)) {
        const key = x.ip + '|' + c.id; if (seen.has(key)) continue; seen.add(key);
        out.push({ key, ip: x.ip, device_id: x.id, asset_id: x.asset_id || null, host: o.host_name || x.hostname || x.ip, instance: o.instance || '', cred_id: c.id, cred_label: c.label,
          port: (c.target && c.target.port) || 1521, service: (c.target && c.target.service) || undefined, tls: (c.target && c.target.tls) || 'off', ca_file: (c.target && c.target.ca_file) || undefined });
      }
    }
    // databases an administrator registered directly (paused ones are skipped until tested again)
    for (const r of regs.all((x) => !x.paused)) {
      const key = 'reg:' + r.id; if (seen.has(key)) continue; seen.add(key);
      out.push({ key, reg_id: r.id, ip: r.host, device_id: null, asset_id: r.asset_id || null, host: r.label || r.host, instance: '', cred_id: r.cred_id, cred_label: r.cred_label, port: r.port || 1521, service: r.service || undefined });
    }
    return { list: out.slice(0, cfg().max_hosts), creds: creds.length, registered: regs.size() };
  }

  /* ---- registered databases ---- */
  const bad = (m, status = 400) => Object.assign(new Error(m), { status });
  const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
  const regView = (r) => ({ id: r.id, label: r.label, host: r.host, port: r.port, service: r.service, asset_id: r.asset_id || null, credential: r.cred_label, cred_id: r.cred_id, login_shared_with: regs.all((x) => x.cred_id === r.cred_id && x.id !== r.id).map((x) => x.label), added_by: r.added_by, added_at: r.added_at, last_test: r.last_test || null, paused: r.paused || null });
  // stop using a database until an administrator tests it again: a refused login (no account lockout) or an account with
  // more than read-only rights (the platform will not use it)
  function pauseFor(cls, at, during) {
    if (cls === 'auth') return { at, reason: 'login refused' + (during ? ' during a read' : '') + ' - tested again only by an administrator (no account lockout)' };
    if (cls === 'unsafe') return { at, reason: 'the account has more than read-only monitoring privileges - not used; give it read-only rights or use a dedicated monitoring user, then test again' };
    return null;
  }
  function databases() {
    let creds = []; try { creds = (D() && D().vault ? D().vault.list() : []).filter((c) => c.kind === 'db_login' && c.target && c.target.engine === 'oracle').map((c) => ({ id: c.id, label: c.label })); } catch (e) { creds = []; }
    return { databases: regs.all().map(regView).sort((a, b) => (a.label < b.label ? -1 : 1)), credentials: creds, last: (meta.get('last') || {}).value || null, dismissed: dism.all().sort((a, b) => (a.at < b.at ? 1 : -1)) };
  }
  /* A database Asset Discovery found that nobody wants in the inventory (unknown, unused, a test copy): removed from the
     inventory and never read, with who and why. The server itself stays in Asset Discovery; Restore brings the database back. */
  const dism = store.collection('db_health_dismissed');
  function dismissedIds() { return new Set(dism.all().map((x) => x.id)); }
  function dismiss(b, who) {
    const id = String((b && b.device_id) || ''), why = clip(b && b.reason, 300);
    const d = devs.get(id); if (!d) throw bad('database not found in Asset Discovery', 404);
    if (!why) throw bad('say why it is removed (unknown, not used, test copy …) - it is recorded');
    const dl = (d.extra && d.extra.db_login) || {};
    const rec = { id, ip: d.ip || '', host: d.hostname || '', engines: Object.keys(dl), reason: why, by: (who && who.user) || '', at: new Date(now()).toISOString() };
    dism.put(rec);
    if (app.audit) app.audit({ by: rec.by, role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'db.health.inventory.remove', target: id, detail: { ip: rec.ip, host: rec.host, engines: rec.engines, reason: why } });
    return rec;
  }
  function undismiss(b, who) {
    const id = String((b && b.device_id) || ''), r = dism.get(id); if (!r) throw bad('not in the removed list', 404);
    dism.remove(id);
    if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'db.health.inventory.restore', target: id, detail: { ip: r.ip, host: r.host } });
    return { restored: id };
  }
  async function testDb(id, who) {
    const r = regs.get(String(id || '')); if (!r) throw bad('database not found', 404);
    const t = { ip: r.host, host: r.label || r.host, instance: '', cred_id: r.cred_id, port: r.port || 1521, service: r.service };
    let res;
    try { const g = await readOne(t, { heavy: true }); const md = missingDetail(g.errors, g.account); res = { at: new Date(now()).toISOString(), ok: true, instance: g.instance, records: g.recs.length, account: g.account || null, missing: g.errors.map((e) => e.query), missing_detail: md, fix_script: fixScript(md) }; }
    catch (e) { res = { at: new Date(now()).toISOString(), ok: false, error: String(e.message || e).slice(0, 600), cls: e.cls || 'error' }; }
    regs.patch(r.id, (x) => { x.last_test = res; x.paused = res.ok ? null : pauseFor(res.cls, res.at) || x.paused || null; return x; });
    if (app.audit) app.audit({ by: (who && who.user) || SYS.user, role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'db.health.database.test', target: r.id, detail: { host: r.host, ok: res.ok, cls: res.cls || null } });
    if (res.ok) guardOf(app, 'db-health.pass', pass)();   // its first sample reaches the AI Oracle DBA now, not in 4 minutes
    return regView(regs.get(r.id));
  }
  async function addDb(b, who) {
    b = b || {};
    const V = D() && D().vault; if (!V || (V.available && !V.available())) throw bad('the credential vault is not available (Asset Discovery)', 503);
    const host = clip(b.host, 253), label = clip(b.label, 80) || host, service = clip(b.service, 128);
    if (!/^[A-Za-z0-9.-]{1,253}$/.test(host)) throw bad('host must be an IP address or a host name');
    const port = b.port == null || b.port === '' ? 1521 : Number(b.port);
    if (!(Number.isInteger(port) && port >= 1 && port <= 65535)) throw bad('port must be 1-65535');
    if (!/^[A-Za-z0-9_.$#-]{1,128}$/.test(service)) throw bad('service name is required (the Oracle service, e.g. ORCLPDB1)');
    if (regs.all((x) => x.host.toLowerCase() === host.toLowerCase() && x.port === port && String(x.service).toLowerCase() === service.toLowerCase()).length) throw bad('this database is already registered', 409);
    // aligned with the asset register: the server asset this database runs on (optional here; Database Servers flags a server with none)
    let assetId = b.asset_id ? String(b.asset_id) : null;
    if (assetId) { const a = store.collection('assets').get(assetId); if (!a || a.status === 'disposed') throw bad('asset not found', 404); }
    let cred;
    if (b.cred_id) { cred = V.get(String(b.cred_id)); if (!cred || cred.kind !== 'db_login' || !cred.target || cred.target.engine !== 'oracle') throw bad('choose a saved Oracle login (Asset Discovery credential, kind db_login, engine oracle)'); }
    else {
      if (!clip(b.username, 128) || !String(b.password || '')) throw bad('enter the read-only Oracle user and password, or choose a saved login');
      // encryption in transit (TCPS): off | require | verify (+ ca_file) - validated by the vault (engine/discovery/vault.js)
      const target = { engine: 'oracle', port, service }; if (b.tls) target.tls = String(b.tls); if (b.ca_file) target.ca_file = String(b.ca_file);
      const body = { kind: 'db_login', label: 'oracle-' + label.replace(/[^A-Za-z0-9_.-]+/g, '-').slice(0, 60), target, secret: { username: String(b.username), password: String(b.password) } };
      cred = D().createCredential ? D().createCredential(body, who) : V.create(body, who);   // sealed; audited by Asset Discovery
    }
    const id = 'odb_' + require('node:crypto').randomBytes(4).toString('hex');
    regs.put({ id, label, host, port, service, asset_id: assetId, cred_id: cred.id, cred_label: cred.label, added_by: (who && who.user) || '', added_at: new Date(now()).toISOString() });
    if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'db.health.database.add', target: id, detail: { host, port, service, credential: cred.label, asset_id: assetId } });
    return testDb(id, who);
  }
  // edit a registered database: its name / address / service / server asset, and its login - a new password for the same
  // saved login (versioned in the vault, audited by Asset Discovery; every database using that login gets it), or another
  // saved login. Then it is tested once, which lifts a pause when the login now works.
  async function editDb(id, b, who) {
    b = b || {};
    const r = regs.get(String(id || '')); if (!r) throw bad('database not found', 404);
    const V = D() && D().vault; if (!V || (V.available && !V.available())) throw bad('the credential vault is not available (Asset Discovery)', 503);
    const host = b.host !== undefined ? clip(b.host, 253) : r.host, label = b.label !== undefined ? (clip(b.label, 80) || host) : r.label, service = b.service !== undefined ? clip(b.service, 128) : r.service;
    if (!/^[A-Za-z0-9.-]{1,253}$/.test(host)) throw bad('host must be an IP address or a host name');
    const port = b.port === undefined || b.port === '' ? r.port : Number(b.port);
    if (!(Number.isInteger(port) && port >= 1 && port <= 65535)) throw bad('port must be 1-65535');
    if (!/^[A-Za-z0-9_.$#-]{1,128}$/.test(service)) throw bad('service name is required (the Oracle service, e.g. ORCLPDB1)');
    if (regs.all((x) => x.id !== r.id && x.host.toLowerCase() === host.toLowerCase() && x.port === port && String(x.service).toLowerCase() === service.toLowerCase()).length) throw bad('another registered database already has this host, port and service', 409);
    let assetId = b.asset_id !== undefined ? (b.asset_id ? String(b.asset_id) : null) : (r.asset_id || null);
    if (assetId && b.asset_id !== undefined) { const a = store.collection('assets').get(assetId); if (!a || a.status === 'disposed') throw bad('asset not found', 404); }
    let credId = r.cred_id, credLabel = r.cred_label, how = [];
    if (b.cred_id && String(b.cred_id) !== r.cred_id) {
      const c = V.get(String(b.cred_id)); if (!c || c.kind !== 'db_login' || !c.target || c.target.engine !== 'oracle') throw bad('choose a saved Oracle login (Asset Discovery credential, kind db_login, engine oracle)');
      credId = c.id; credLabel = c.label; how.push('login switched to ' + c.label);
    } else if (String(b.password || '')) {
      const secret = { password: String(b.password) }; if (clip(b.username, 128)) secret.username = String(b.username).trim();
      if (!D().updateCredential) throw bad('this Asset Discovery cannot update a saved login - run the server update', 501);
      const u = D().updateCredential(r.cred_id, { secret }, who);   // versioned + audited (discovery.credential.update)
      credLabel = (u && (u.credential || u).label) || credLabel; how.push(secret.username ? 'user and password changed' : 'password changed');
    } else if (clip(b.username, 128)) throw bad('enter the password together with the user name (the password is never shown, so it cannot be kept by itself)');
    const changed = ['label', 'host', 'port', 'service'].filter((k) => ({ label, host, port, service })[k] !== r[k]);
    if ((assetId || null) !== (r.asset_id || null)) changed.push('asset');
    regs.patch(r.id, (x) => Object.assign(x, { label, host, port, service, asset_id: assetId, cred_id: credId, cred_label: credLabel, edited_by: (who && who.user) || '', edited_at: new Date(now()).toISOString() }));
    if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'db.health.database.edit', target: r.id, detail: { changed, login: how.join('; ') || 'unchanged', host, port, service } });
    return testDb(r.id, who);
  }
  function removeDb(id, who) {
    const r = regs.get(String(id || '')); if (!r) throw bad('database not found', 404);
    regs.remove(r.id);
    if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'db.health.database.remove', target: r.id, detail: { host: r.host, service: r.service, note: 'the saved login stays in Asset Discovery → Credentials' } });
    return { removed: r.id };
  }

  // the SIEM source + its token (sealed); re-created / rotated when the SIEM no longer accepts it
  async function source(force) {
    const cur = meta.get('source');
    if (cur && cur.enc && !force) { try { return { id: cur.src_id, token: sealer.unseal('source', cur.enc) }; } catch (e) { /* key changed: mint again */ } }
    const S = D() && D().siem; if (!S || typeof S.call !== 'function') throw Object.assign(new Error('the SIEM link is not configured (discovery.siem)'), { status: 503 });
    const rotate = (id) => S.call('POST', '/onboard/sources/' + encodeURIComponent(id) + '/rotate-token', SYS);
    let r;
    if (force && cur && cur.src_id) r = await rotate(cur.src_id);   // the source exists, its token was refused: new token only
    else {
      // the SIEM requires a site on every new source: config db_health.site, else the SIEM's main site (else its first)
      let site = String(cfg().site || '').trim().toLowerCase();
      if (!site) { try { const sr = await S.call('GET', '/onboard/sites', SYS); const L = (sr.json && sr.json.sites) || []; const m = L.find((x) => x.kind === 'main') || L[0]; site = m ? String(m.id) : ''; } catch (e) { site = ''; } }
      r = await S.call('POST', '/onboard/sources', SYS, { id: SRC_ID, kind: 'oracle-health', site: site || undefined, label: 'Oracle health from IT Asset Management (Asset Discovery database logins)' });
      if (r.status === 409 || (r.status >= 400 && /exist/i.test(JSON.stringify(r.json || {})))) r = await rotate(SRC_ID);   // registered before (e.g. state lost)
    }
    const token = r.json && r.json.token;
    if (r.status >= 300 || !token) throw Object.assign(new Error('the SIEM did not register the oracle-health source (HTTP ' + r.status + (r.json && r.json.error ? ': ' + String(r.json.error).slice(0, 160) : '') + ')'), { status: 502 });
    meta.put({ id: 'source', src_id: (r.json.source && r.json.source.id) || SRC_ID, enc: sealer.seal('source', String(token)), at: new Date(now()).toISOString() });
    audit(force ? 'db-health.source.rotate' : 'db-health.source.create', SRC_ID, { kind: 'oracle-health' });
    return { id: (r.json.source && r.json.source.id) || SRC_ID, token: String(token) };
  }
  async function push(records) {
    let src = await source(false);
    const body = records.map((x) => JSON.stringify(x)).join('\n') + '\n';
    const send = (s) => request(base + '/ingest/' + encodeURIComponent(s.id), { method: 'POST', headers: { 'X-Sentra-Token': s.token, 'Content-Type': 'application/x-ndjson' }, body, timeoutMs: 20000 });
    let r = await send(src);
    if (r.status === 401 || r.status === 403) { src = await source(true); r = await send(src); }   // the SIEM's tokens were reset
    if (r.status >= 300) throw new Error('SIEM ingest HTTP ' + r.status);
    return records.length;
  }

  // what to do about a failed connection, in words a DBA can act on (the driver's own text is kept before it)
  const CONNECT_HINT = {
    dns: 'the platform server cannot resolve "{host}" in DNS: register the name in DNS (or the server\'s hosts file), or enter the database server\'s IP address instead',
    service: 'the listener on {host}:{port} answered but does not know the service "{service}": run lsnrctl status on the database server and use a service name it lists (a PDB service, not the SID)',
    busy: 'the listener knows the service but refused a session for now (instance starting, restricted mode, or PROCESSES / SESSIONS reached) - it is tried again on the next pass; check the alert log if it persists',
    refused: 'nothing accepted the connection on {host}:{port}: check the listener is running and the port (1521 by default)',
    timeout: 'no answer from {host}:{port}: a firewall between the platform server and the database is probably dropping the connection - open {port}/tcp from the platform server',
    unreachable: 'no network route to {host}: check the address and routing from the platform server',
  };
  const HEAVY_MS = 60 * 60000, lastHeavy = new Map();   // per database: the dictionary scans run at most once an hour
  async function readOne(t, o) {
    const V = D().vault, c = V.open(t.cred_id), key = t.ip + ':' + t.port + '/' + (t.service || '');
    const heavy = !!(o && o.heavy) || !(now() - (lastHeavy.get(key) || 0) < HEAVY_MS);
    let r;
    try { r = await runHelper({ op: 'oracle_health', host: t.ip, port: t.port, username: c.secret.username, password: c.secret.password, service: t.service, tls: (c.target && c.target.tls) || t.tls || 'off', ca_file: (c.target && c.target.ca_file) || t.ca_file, heavy, morning: !!(o && o.morning), tuning: settings().tuning, pack: settings().diagnostics_pack === true }); }
    finally { c.release(); }
    // keep the driver's own message (ORA-01017 / ORA-28000 / ORA-28001 / ORA-01045 …): it says WHICH login problem it is,
    // and Oracle never puts the password in it
    if (!r || !r.ok) {
      const msg = (r && (r.error_class === 'unsafe' ? r.error : r.error && r.error_class ? r.error_class + ': ' + String(r.error).replace(/\s+/g, ' ').slice(0, 220) : (r.error_class || r.error))) || 'no answer';
      const hint = r && CONNECT_HINT[r.error_class] ? ' - ' + CONNECT_HINT[r.error_class].replace('{host}', t.ip).replace('{port}', t.port).replace('{service}', t.service || '') : '';
      throw Object.assign(new Error(msg + hint), { cls: r && r.error_class, hint: hint.slice(3) || null });
    }
    if (heavy) lastHeavy.set(key, now());
    const inst = (r.records || []).find((x) => x.kind === 'instance') || {};
    const at = new Date(now()).toISOString(), common = { collector: 'sentra-oracle-itam', t: at, host: inst.host || t.host, instance: inst.instance || t.instance, db_name: inst.db_name || inst.instance || t.instance };
    // a Data Guard standby usually has the SAME instance name as its primary: key it by its DB_UNIQUE_NAME (which Data Guard
    // requires to differ), or the two databases' readings would merge into one in the SIEM
    if (/STANDBY/i.test(inst.role || '') && inst.db_unique_name && String(inst.db_unique_name).toUpperCase() !== String(inst.instance || '').toUpperCase()) common.instance = String(inst.db_unique_name).toUpperCase().slice(0, 64);
    // no instance reading (e.g. a missing grant): keep every record on ONE instance key - the service name - not an empty one
    if (!common.instance) common.instance = common.db_name = String(t.service || t.host || '').toUpperCase().slice(0, 64);
    const recs = (r.records || []).map((x) => Object.assign({}, x, common, { host: common.host, instance: common.instance, db_name: common.db_name }));
    const snapRows = r.sqlstats || [];
    for (const x of sqlDeltas(key, snapRows.filter((y) => y.kind !== 'delstats'), now())) recs.push(Object.assign(x, common));
    for (const x of deleteDeltas(key, snapRows.filter((y) => y.kind === 'delstats'), now())) recs.push(Object.assign(x, common));
    recs.push(Object.assign({ kind: 'heartbeat' }, common));
    const errors = r.errors || [];
    if (settings().audit !== false) { const a = await readAudit(t, key, common); recs.push(...a.recs); if (a.error) errors.push({ query: 'audit_trail', error: a.error }); }
    return { recs, errors, instance: common.instance, tuning: r.tuning, version: r.version || inst.version || null, account: r.account || '' };
  }

  // Database Audit: new UNIFIED_AUDIT_TRAIL rows since this database's cursor (first pass: the last 24 h), as kind
  // unified_audit - the SIEM's Oracle audit parser classifies them. Rows on the cursor's own timestamp are remembered so a
  // row is never sent twice; a capped read (2000 rows) carries on from where it stopped on the next pass.
  async function readAudit(t, key, common) {
    const cur = (meta.get('audit:' + key) || {}).value || null;
    const since = cur && cur.since ? cur.since : new Date(now() - 24 * 3600000).toISOString().slice(0, 19);
    const V = D().vault, c = V.open(t.cred_id);
    let r;
    try { r = await runHelper({ op: 'oracle_audit', since, host: t.ip, port: t.port, username: c.secret.username, password: c.secret.password, service: t.service, tls: (c.target && c.target.tls) || t.tls || 'off', ca_file: (c.target && c.target.ca_file) || t.ca_file }); }
    finally { c.release(); }
    if (!r || !r.ok) return { recs: [], error: (r && r.error_class) || 'error' };
    const seen = new Set((cur && cur.seen) || []), id = (x) => [x.SESSIONID, x.ENTRY_ID, x.STATEMENT_ID, x.EVENT_TIMESTAMP_UTC].join('|');
    const rows = (r.rows || []).filter((x) => !seen.has(id(x)));
    const last = (r.rows || []).length ? String(r.rows[r.rows.length - 1].EVENT_TIMESTAMP_UTC || '').replace(/Z$/, '') : '';
    if (last) meta.put({ id: 'audit:' + key, value: { since: last, seen: (r.rows || []).filter((x) => String(x.EVENT_TIMESTAMP_UTC).replace(/Z$/, '') === last).map(id).slice(0, 5000), at: new Date(now()).toISOString(), capped: !!r.capped } });
    else if (!cur) meta.put({ id: 'audit:' + key, value: { since, seen: [], at: new Date(now()).toISOString() } });
    return { recs: rows.map((x) => Object.assign({}, x, common)), capped: !!r.capped };
  }

  async function pass() {
    if (running) return running;
    running = (async () => {
      const t0 = now(), C = cfg(), T = targets(), res = { at: new Date(t0).toISOString(), enabled: C.enabled, logins: T.creds, hosts: T.list.length, read: 0, sent: 0, failed: 0, results: [] };
      if (!C.enabled) { res.note = 'switched off (config db_health.enabled)'; }
      else if (!T.list.length) { res.note = T.registered ? 'every registered database is paused (login refused or not a read-only account) - test it again in Connections & Setup → Oracle databases' : T.creds ? 'an Oracle login is saved but Asset Discovery has not yet proven it on any host — run the scope with the db method, or register the database in Connections & Setup → Oracle databases' : 'no Oracle database connected - add one in Connections & Setup → Oracle databases'; }
      else {
        const batch = [];
        for (const t of T.list) {
          const row = { host: t.host, ip: t.ip, credential: t.cred_label, ok: false };
          try { const g = await readOne(t); batch.push(...g.recs); row.ok = true; row.instance = g.instance; row.records = g.recs.length; row.missing = g.errors.map((e) => e.query); row.missing_detail = missingDetail(g.errors, g.account); row.fix_script = fixScript(row.missing_detail); row.account = g.account || null; row.at = new Date(now()).toISOString(); row.tuning = g.tuning; row.version = g.version; const ir = g.recs.find((x) => x.kind === 'instance'); if (ir) { row.edition = ir.edition || ''; row.banner = ir.banner || ''; row.role = ir.role || ''; } res.read++; }
          catch (e) {
            row.error = String(e.message || e).slice(0, 600); res.failed++;
            // a refused login or an over-privileged account on a registered database: stop until an administrator tests it again
            const pz = t.reg_id && pauseFor(e.cls, new Date(now()).toISOString(), true);
            if (pz) regs.patch(t.reg_id, (x) => { x.paused = pz; x.last_test = { at: pz.at, ok: false, error: row.error, cls: e.cls }; return x; });
          }
          res.results.push(row);
        }
        if (batch.length) { try { res.sent = await push(batch); } catch (e) { res.push_error = String(e.message || e).slice(0, 200); } }
      }
      meta.put({ id: 'last', value: res });
      if (res.failed || res.push_error) lg.warn('db-health pass', { read: res.read, failed: res.failed, push_error: res.push_error || null });
      return res;
    })().finally(() => { running = null; });
    return running;
  }

  function status() {
    const C = cfg(), T = targets(), last = (meta.get('last') || {}).value || null, src = meta.get('source');
    return { enabled: C.enabled, interval_min: C.interval_min, source_id: src ? src.src_id : null, source_registered: !!(src && src.enc),
      oracle_logins: T.creds, registered: T.registered, hosts: T.list.map((t) => ({ host: t.host, ip: t.ip, instance: t.instance, credential: t.cred_label })), last,
      settings: settings() };
  }
  // the licence switch: only an administrator who is a person, with a reason (who confirmed the licence) - audited
  function setSettings(b, who) {
    b = b || {}; const cur = settings(), next = Object.assign({}, cur);
    if (b.diagnostics_pack !== undefined) {
      const on = b.diagnostics_pack === true;
      if (on && !clip(b.note, 300)) throw bad('say who confirmed the Oracle Diagnostics Pack licence (e.g. the licence reference) - it is recorded');
      next.diagnostics_pack = on;
    }
    if (b.tuning !== undefined) next.tuning = b.tuning !== false;
    if (b.audit !== undefined) next.audit = b.audit !== false;
    next.by = (who && who.user) || ''; next.at = new Date(now()).toISOString(); if (b.note) next.note = clip(b.note, 300);
    meta.put({ id: 'settings', value: next });
    if (app.audit) app.audit({ by: next.by, role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'db.health.settings', target: 'db-health', detail: { diagnostics_pack: next.diagnostics_pack, tuning: next.tuning, audit: next.audit, note: next.note || '' } });
    return next;
  }
  // one cursor's execution plan, live from the database (DBMS_XPLAN.DISPLAY_CURSOR - licence-free), literals masked
  async function plan(q, who) {
    const sqlId = String((q && q.sql_id) || ''), host = String((q && q.host) || '').toLowerCase(), inst = String((q && q.instance) || '').toUpperCase();
    if (!/^[0-9a-z]{13}$/.test(sqlId)) throw bad('sql_id must be the 13-character Oracle SQL_ID');
    const T = targets().list, t = T.find((x) => (host && (String(x.ip).toLowerCase() === host || String(x.host).toLowerCase() === host)) || (inst && (String(x.instance).toUpperCase() === inst || String(x.service || '').toUpperCase() === inst))) || (T.length === 1 ? T[0] : null);
    if (!t) throw bad('no monitored Oracle database matches - choose the database', 404);
    const V = D().vault, c = V.open(t.cred_id);
    let r;
    try { r = await runHelper({ op: 'oracle_plan', sql_id: sqlId, host: t.ip, port: t.port, username: c.secret.username, password: c.secret.password, service: t.service, tls: (c.target && c.target.tls) || 'off', ca_file: c.target && c.target.ca_file }); }
    finally { c.release(); }
    if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'db.health.plan', target: t.host || t.ip, detail: { sql_id: sqlId } });
    if (!r || !r.ok) throw bad((r && (r.error || r.error_class)) || 'no answer from the database', 502);
    return { database: t.host || t.ip, sql_id: sqlId, found: !!r.found, lines: r.lines || [] };
  }
  // personal-data discovery for the AI PDPL Consultant (inv-helper op oracle_pii_scan): column names, comments and row
  // estimates from the dictionary; values are tested inside the helper and only match COUNTS come back
  async function piiScan(t) {
    const V = D() && D().vault; if (!V) throw bad('Asset Discovery vault not available', 503);
    const c = V.open(t.cred_id);
    let r;
    try { r = await runHelper({ op: 'oracle_pii_scan', host: t.ip, port: t.port, username: c.secret.username, password: c.secret.password, service: t.service, tls: (c.target && c.target.tls) || t.tls || 'off', ca_file: (c.target && c.target.ca_file) || t.ca_file }); }
    finally { c.release(); }
    return r || { ok: false, error_class: 'error', error: 'no answer from the helper' };
  }
  function start() { if (timer) return; const ms = Math.max(2, Number(cfg().interval_min) || 4) * 60000; timer = setInterval(guardOf(app, 'db-health.pass', () => pass()), ms); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  return { targets, readOne, pass, status, start, stop, piiScan, source, push, databases, addDb, editDb, testDb, removeDb, plan, setSettings, settings, sqlDeltas, dismiss, undismiss };
}

function registerDbHealth(srv, app, opts = {}) {
  const H = createDbHealth(app, opts);
  (app.addons = app.addons || {}).dbHealth = H;
  srv.route('GET', '/db-health', (ctx) => void ctx.need('viewer') || H.status());
  srv.route('POST', '/db-health/run', async (ctx) => { ctx.need('admin'); return H.pass(); });
  srv.route('GET', '/db-health/databases', (ctx) => { ctx.need('operator'); return H.databases(); });
  srv.route('GET', '/db-health/plan', async (ctx) => { ctx.need('operator'); return H.plan(ctx.query || {}, ctx.who); });
  srv.route('POST', '/db-health/settings', (ctx) => { ctx.need('admin'); if (!require('./approve-scopes').isHuman(ctx.who && ctx.who.user)) throw Object.assign(new Error('only a person changes this'), { status: 403 }); return H.setSettings(ctx.body || {}, ctx.who); });
  srv.route('POST', '/db-health/databases', async (ctx) => { ctx.need('admin'); return { database: await H.addDb(ctx.body || {}, ctx.who) }; });
  srv.route('POST', '/db-health/databases/:id/test', async (ctx) => { ctx.need('admin'); return { database: await H.testDb(ctx.params.id, ctx.who) }; });
  srv.route('POST', '/db-health/databases/:id', async (ctx) => { ctx.need('admin'); return { database: await H.editDb(ctx.params.id, ctx.body || {}, ctx.who) }; });
  srv.route('POST', '/db-health/databases/:id/delete', (ctx) => { ctx.need('admin'); return H.removeDb(ctx.params.id, ctx.who); });
  srv.route('POST', '/db-health/inventory/remove', (ctx) => { ctx.need('admin'); return H.dismiss(ctx.body || {}, ctx.who); });
  srv.route('POST', '/db-health/inventory/restore', (ctx) => { ctx.need('admin'); return H.undismiss(ctx.body || {}, ctx.who); });
  if (!opts.noTimer && H.status().enabled) { H.start(); const t = setTimeout(guardOf(app, 'db-health.pass', () => H.pass()), 120000); if (t.unref) t.unref(); }
  // the servers these databases run on (Databases -> Database Servers): same install unit, no extra main.js line
  try { require('./db-servers').registerDbServers(srv, app, { invRun: opts.invRun, dbHealth: H, noTimer: opts.noTimer }); }
  catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; (app.log || { warn() {} }).warn('db-health: db-servers.js not installed - Database Servers unavailable'); }
  // Morning Health Check: the DBA's daily round (every database + its server), as one checklist, mailed and signed off
  try { require('./db-morning').registerDbMorning(srv, app, { dbHealth: H, discovery: opts.discovery, noTimer: opts.noTimer }); }
  catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; (app.log || { warn() {} }).warn('db-health: db-morning.js not installed - Morning Health Check unavailable'); }
  // Long-Running Queries: find the sessions hurting a database; cancel / kill only after a DBA approver says yes
  try { require('./db-sessions').registerDbSessions(srv, app, { invRun: opts.invRun, dbHealth: H, discovery: opts.discovery }); }
  catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; (app.log || { warn() {} }).warn('db-health: db-sessions.js not installed - Long-Running Queries unavailable'); }
  // our own engines next to GoldenGate: Data Verify, Change Stream, Replication (Databases -> Replication & Data Guard)
  try { require('./db-replicate').registerReplicate(srv, app, { dbHealth: H, noTimer: opts.noTimer }); }
  catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; (app.log || { warn() {} }).warn('db-health: db-replicate.js not installed - replication engines unavailable'); }
  return H;
}

module.exports = { createDbHealth, registerDbHealth, SRC_ID, missingDetail, fixScript };
