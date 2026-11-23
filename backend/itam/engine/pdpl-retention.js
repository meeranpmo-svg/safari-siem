// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * PDPL retention enforcement (Law Art. 18, Implementing Regulation Art. 19: personal data is kept no longer than needed).
 * The retention schedule (records of kind retention, and the retention_months of each processing activity) says HOW LONG;
 * this module tracks WHETHER it is kept to, table by table:
 *
 *   Map       a person (the DPO or a data steward, operator) maps a rule to a table of the Data Catalog and the table's date
 *             column (e.g. claims.closed_date + 120 months). The table must be in the catalog (the read-only discovery scan);
 *             the catalog's date columns are offered as suggestions; the scan confirms the column in the database's own
 *             dictionary (it exists and is a date) before anything is counted.
 *   Scan      monthly by default, and Scan now: per mapped table ONE fixed query, built from validated identifiers with the
 *             cut-off date as a bound parameter -  select count(*), min(<date column>) from <schema>.<table> where <date column> < ?
 *             - through the catalog's own read-only path (inv-helper.py _pii_open: a login that can write, own or administer
 *             is refused before anything is read; read-only transaction; the vault login, on stdin only). Only the number
 *             of rows and the oldest date come back. A failure says why (no login, no grant, no such column) - never a number.
 *   Task      a table with rows past retention is a disposal task for the system's data owner (the owner named in the mapping,
 *             else the Privacy Office's data owner of the system). The owner records what they did in the system - deletion,
 *             anonymisation, or archive under legal hold, with the date, a reference and a note (a deletion ATTESTATION);
 *             the DPO (or an administrator) who is not the attester accepts or returns it; the next scan verifies the count
 *             fell (verified / not verified). The platform itself never deletes or changes data.
 *   Hold      a rule can be suspended for one table (a claim, a case, an inquiry) with a reason and an end date: requested
 *             by one person, approved by the DPO (or an administrator) who did not request it. An active PDPL legal hold
 *             (pdpl.js) that covers the system suspends the table's task too.
 *   Signals   for Notification & Escalation (source "pdpl"): rows past retention with no attestation after N days; an
 *             accepted attestation the next scan did not verify.
 *
 *   GET  /pdpl/retention/enforcement             operator  rules, catalog tables, mappings, last results, tasks, holds, settings
 *   GET  /pdpl/retention/enforcement/mine        viewer    my disposal tasks (a data owner may hold the viewer role)
 *   POST /pdpl/retention/maps                    operator  {rule_id, db, schema, table, date_column, system?, owner?, note?}  audited
 *   POST /pdpl/retention/maps/:id/retire         operator  {reason}                                                        audited
 *   POST /pdpl/retention/scan                    operator  scan now (also monthly on its own)                              audited
 *   POST /pdpl/retention/settings                admin or the DPO  {enabled, every_days, attest_days}                     audited
 *   POST /pdpl/retention/tasks/:id/attest        the data owner (any role) or an operator  {method, date, reference, note} audited
 *   POST /pdpl/retention/tasks/:id/accept        the DPO or an administrator, not the attester  {note?}                    audited
 *   POST /pdpl/retention/tasks/:id/return        the DPO or an administrator, not the attester  {note}                     audited
 *   POST /pdpl/retention/holds                   operator  {map_id, reason, until}                                         audited
 *   POST /pdpl/retention/holds/:id/approve       the DPO or an administrator, not the requester                            audited
 *   POST /pdpl/retention/holds/:id/reject        the DPO or an administrator, not the requester  {note}                    audited
 *   POST /pdpl/retention/holds/:id/end           the DPO or an administrator  {note}                                       audited
 *
 * Counts only: no row, no value and no personal data is read, stored, logged or shown. Service and AI identities never
 * attest, accept or approve (approve-scopes.js isHuman).
 */
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (v) => String(v || '').trim().toLowerCase();
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const DAY = 86400000, HOUR = 3600000, RIYADH = 3 * HOUR;
const SYS = { user: 'system:pdpl-retention', role: 'system', ip: '' };
// a database identifier that may be put into the fixed query: the same rule the helper applies (no quote, no bracket, no space)
const NAME = /^[A-Za-z0-9_$#]{1,128}$/;
const USER = /^[A-Za-z0-9._@-]{1,80}$/;
const ENGINES = ['oracle', 'postgres', 'mssql'];
const METHODS = ['deletion', 'anonymisation', 'archive_legal_hold'];
const METHOD_LABEL = { deletion: 'deletion', anonymisation: 'anonymisation', archive_legal_hold: 'archive under legal hold' };
const DATE_TYPE = /date|time/i;
const HELPER = path.join(__dirname, 'discovery', 'inv-helper.py');

/* The count, in Python, through the inventory helper's own read-only path (engine/discovery/inv-helper.py is loaded as a
   module: _pii_open checks the login is read-only and opens a read-only transaction, _q quotes a validated identifier).
   Nothing here takes SQL from the caller: the dictionary lookup and the count are constants; the identifiers are checked
   twice (NAME here, PII_IDENT in _q) and the cut-off date is a bound parameter. Only the count and the oldest date leave. */
const COUNT_PY_LIB = String.raw`
import re as _rre, datetime as _rdt
_R_NAME = _rre.compile(r"^[A-Za-z0-9_$#]{1,128}$")
_R_DATES = {"postgres": ("date", "timestamp without time zone", "timestamp with time zone"),
            "mssql": ("date", "datetime", "datetime2", "smalldatetime", "datetimeoffset"), "oracle": ("DATE",)}
_R_DICT = {"postgres": "select data_type from information_schema.columns where table_schema = %s and table_name = %s and column_name = %s",
           "mssql": "select data_type from information_schema.columns where table_schema = %s and table_name = %s and column_name = %s",
           "oracle": "select data_type from all_tab_columns where owner = :1 and table_name = :2 and column_name = :3"}
def _r_short(e):
    m = _rre.search(r"(ORA-\d{5}|permission denied|SELECT permission was denied|insufficient privileges|does not exist|Invalid object name|timeout|canceling statement)", str(e), _rre.I)
    return (m.group(1) if m else type(e).__name__)[:80]
def _r_fail(cls, msg):
    return {"ok": False, "error_class": cls, "error": str(msg)[:200]}
def retention_count(m, r):
    eng = r.get("engine")
    if eng not in _R_DICT:
        return _r_fail("config", "no retention count for this engine")
    names = [r.get("schema"), r.get("table"), r.get("column")]
    if not all(isinstance(n, str) and _R_NAME.match(n) for n in names):
        return _r_fail("name", "identifier not allowed")
    try:
        cut = _rdt.date.fromisoformat(str(r.get("cutoff")))
    except Exception:
        return _r_fail("config", "cutoff must be a date")
    param = _rdt.datetime(cut.year, cut.month, cut.day) if eng == "oracle" else cut
    try:
        conn, cur, refused = m._pii_open(r)
    except Exception as e:
        return _r_fail(m.classify(e), _r_short(e))
    r["password"] = None
    if refused:
        return _r_fail(refused.get("error_class") or "unsafe", refused.get("error") or "login refused")
    try:
        try:
            cur.execute(_R_DICT[eng], names)
            row = cur.fetchone()
        except Exception as e:
            return _r_fail(m.classify(e), _r_short(e))
        if not row:
            return _r_fail("no_column", "the column was not found, or the login cannot see the table")
        dtype = str(row[0])
        if not (dtype in _R_DATES[eng] or (eng == "oracle" and dtype.upper().startswith("TIMESTAMP"))):
            return _r_fail("not_date", "the column is " + dtype[:40] + ", not a date")
        tbl, col = m._q(eng, names[0], names[1]), m._q(eng, names[2])
        ph = ":1" if eng == "oracle" else "%s"
        try:
            cur.execute("select count(*), min(%s) from %s where %s < %s" % (col, tbl, col, ph), [param])
            n, oldest = cur.fetchone()
        except Exception as e:
            return _r_fail(m.classify(e), _r_short(e))
        return {"ok": True, "engine": eng, "count": int(n), "oldest": oldest.isoformat()[:10] if hasattr(oldest, "isoformat") else None, "data_type": dtype[:40]}
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
`;
const COUNT_PY = COUNT_PY_LIB + String.raw`
import json as _rjson, sys as _rsys, importlib.machinery as _rim, importlib.util as _riu
def _r_main():
    try:
        req = _rjson.loads(_rsys.stdin.read() or "{}")
    except Exception:
        return _r_fail("config", "bad request")
    spec = _riu.spec_from_loader("invh", _rim.SourceFileLoader("invh", _rsys.argv[1]))
    m = _riu.module_from_spec(spec)
    spec.loader.exec_module(m)
    try:
        return retention_count(m, req)
    except ImportError as e:
        return _r_fail("missing_module", str(e)[:120])
    except Exception as e:
        return _r_fail("error", type(e).__name__)
_rsys.stdout.write(_rjson.dumps(_r_main()))
`;

// what a failed count means, in words a person can act on
const WHY = {
  no_login: 'no read-only login is recorded for this source - run discovery on the Data Catalog page again',
  no_vault: 'the Asset Discovery credential vault is not available on this server',
  auth: 'the database refused the read-only login (wrong password, locked or expired account)',
  unsafe: 'the login can write, own or administer this database - it is not used (a read-only login is required)',
  denied: 'the read-only login may not read this table (no SELECT grant) - ask the DBA for a read-only SELECT grant on it',
  no_column: 'the date column was not found in the table, or the login cannot see the table',
  not_date: 'the column is not a date - map the column that holds the date retention starts from',
  name: 'the table or column name cannot be queried safely',
  missing_module: 'the database driver is not installed on the platform server (run the update)',
  timeout: 'the database did not answer in time',
  dns: 'the database host name does not resolve on the platform server',
  refused: 'the database refused the connection (listener down or port closed)',
  unreachable: 'the database is not reachable from the platform server',
  tls: 'the encrypted connection to the database failed (certificate or TLS setting)',
  service: 'the database service name is not known to the listener',
  busy: 'the database did not hand out a session (busy or restricted)',
  config: 'the request to the helper was not valid',
  not_in_catalog: 'the table is no longer in the Data Catalog - run discovery again, or retire this mapping',
  engine: 'retention counts run on Oracle, SQL Server and PostgreSQL only',
  bad_answer: 'the helper did not return a count',
};

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}
// the Python process: the request (with the vault login) goes on stdin only - never argv or the environment
function pyCounter(python, timeoutMs = 120000) {
  return (req) => new Promise((resolve) => {
    let p;
    try { p = spawn(python, ['-I', '-c', COUNT_PY, HELPER], { stdio: ['pipe', 'pipe', 'ignore'], env: { PATH: process.env.PATH || '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1', LANG: 'C.UTF-8' } }); }
    catch (e) { resolve({ ok: false, error_class: 'missing_module', error: 'Python not found (' + python + ')' }); return; }
    let out = '';
    const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch (e) { /* the process has already ended */ } }, timeoutMs);
    p.stdout.on('data', (d) => { if (out.length < 20000) out += d; });
    p.on('error', () => { clearTimeout(t); resolve({ ok: false, error_class: 'missing_module', error: 'Python not found (' + python + ')' }); });
    p.on('close', () => { clearTimeout(t); try { resolve(JSON.parse(out)); } catch (e) { resolve({ ok: false, error_class: 'timeout', error: 'the helper did not answer' }); } });
    p.stdin.end(JSON.stringify(req));
  });
}

// calendar months back from a Riyadh day (YYYY-MM-DD), the day clamped to the end of a shorter month
function monthsBack(day, months) {
  const [y, m, d] = day.split('-').map(Number);
  const t = y * 12 + (m - 1) - months, Y = Math.floor(t / 12), M = t - Y * 12;
  const last = new Date(Date.UTC(Y, M + 1, 0)).getUTCDate();
  return new Date(Date.UTC(Y, M, Math.min(d, last))).toISOString().slice(0, 10);
}

function createPdplRetention(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || {};
  const mapsC = () => store.collection('pdpl_retention_maps'), tasksC = () => store.collection('pdpl_retention_tasks');
  const holdsC = () => store.collection('pdpl_retention_holds'), runsC = () => store.collection('pdpl_retention_runs'), cfgC = () => store.collection('pdpl_retention_cfg');
  const recs = (kind) => store.collection('pdpl_records').all((r) => r.kind === kind && r.status !== 'archived');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'pdpl.retention.' + action, target, detail }); };
  const iso = () => new Date(now()).toISOString();
  const today = () => new Date(now() + RIYADH).toISOString().slice(0, 10);
  const warn = (key, msg, f) => { if (L.every) L.every('pdpl-retention:' + key, 3600000, 'warn', msg, f); };
  const settings = () => Object.assign({ enabled: true, every_days: 30, attest_days: 30 }, cfgC().get('cfg') || {});
  const dpo = () => ((store.collection('pdpl_records').get('profile') || {}).dpo_user) || null;
  const isDpo = (who) => !!dpo() && low(dpo()) === low(who.user);
  const mayApprove = (who) => isHuman(who.user) && (who.role === 'admin' || isDpo(who));
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const nextId = (col, prefix) => { let n = col().size() + 1, id; do { id = prefix + String(n++).padStart(5, '0'); } while (col().get(id)); return id; };
  const hist = (x, who, what) => (x.history || []).concat([{ at: iso(), by: who.user, what }]).slice(-50);

  // ---- the query runner: opts.runQuery(spec) replaces it whole (tests); opts.runHelper(req with login) replaces only Python
  let counter = null;
  async function vaulted(q) {
    const V = app.discovery && app.discovery.vault;
    if (!V || typeof V.open !== 'function') return { ok: false, error_class: 'no_vault', error: '' };
    let c = null;
    try {
      try { c = V.open(q.cred_id); } catch (e) { return { ok: false, error_class: 'no_login', error: s(e.message, 120) }; }
      if (!c || !c.secret) return { ok: false, error_class: 'no_login', error: '' };
      const tg = c.target || {};
      const run = opts.runHelper || counter || (counter = pyCounter(pythonBin(app, opts)));
      return await run({ op: 'retention_count', engine: q.engine, host: q.host, port: q.port, username: c.secret.username, password: c.secret.password, service: q.service || tg.service, database: tg.database, tls: tg.tls || 'off', ca_file: tg.ca_file,
        schema: q.schema, table: q.table, column: q.column, cutoff: q.cutoff });
    } finally { if (c && typeof c.release === 'function') try { c.release(); } catch (e) { /* the vault entry is released on its own at the end of the read */ } }
  }
  const runQuery = opts.runQuery || vaulted;

  // ---- what the person maps from: the retention schedule, the processing activities, the Data Catalog
  function rules() {
    const out = [];
    for (const r of recs('retention')) out.push({ id: r.id, source: 'retention', name: r.name || r.id, period_months: Number(r.period_months) || null, trigger: r.trigger || null, action: r.action || null, legal_ref: r.legal_ref || '', systems: r.systems || [], owner: r.owner || '' });
    for (const r of recs('ropa')) if (Number(r.retention_months) > 0) out.push({ id: r.id, source: 'ropa', name: r.name || r.id, period_months: Number(r.retention_months), trigger: null, action: null, legal_ref: r.retention_basis || '', systems: r.systems || [], owner: r.owner || '' });
    return out;
  }
  const scans = () => store.collection('pdpl_discovery').all((x) => x.id !== '_last');
  function catalog() {
    const out = new Map();
    for (const sc of scans()) {
      for (const c of sc.columns || []) {
        const k = sc.id + '|' + c.owner + '|' + c.table;
        let t = out.get(k);
        if (!t) { t = { db: sc.id, label: sc.label || sc.host || sc.id, engine: sc.engine || 'oracle', schema: String(c.owner), table: String(c.table), rows: c.rows == null ? null : Number(c.rows), personal: [], date_columns: [], safe: NAME.test(String(c.owner)) && NAME.test(String(c.table)), login: !!sc.cred_id }; out.set(k, t); }
        if (c.confirmed !== false) t.personal.push({ column: String(c.column), category: c.category || null });
        if (DATE_TYPE.test(String(c.type || ''))) t.date_columns.push({ column: String(c.column), type: String(c.type), kind: c.kind || null, safe: NAME.test(String(c.column)), note: c.kind === 'birth_date' ? 'a birth date - retention rarely starts from it' : '' });
        if (c.rows != null && (t.rows == null || Number(c.rows) > t.rows)) t.rows = Number(c.rows);
      }
    }
    return [...out.values()];
  }
  const catalogTable = (db, schema, table) => catalog().find((t) => t.db === db && t.schema === schema && t.table === table) || null;

  // ---- holds: this module's per-table suspensions, and the PDPL legal holds that cover the system
  function holdState(h) { return h.status === 'active' && h.until < today() ? 'expired' : h.status; }
  const activeHold = (mapId) => holdsC().all((h) => h.map_id === mapId && holdState(h) === 'active')[0] || null;
  function legalHold(m) {
    return recs('legal_hold').filter((h) => h.status === 'active' && (h.all_systems || (h.systems || []).some((x) => low(x) === low(m.system))))
      .map((h) => ({ id: h.id, ref: h.ref, reason: h.reason }))[0] || null;
  }
  const suspended = (m) => !!(activeHold(m.id) || legalHold(m));

  // ---- the data owner: named in the mapping, else the Privacy Office's owner of the system
  function ownerOf(m) {
    if (m.owner_user) return m.owner_user;
    const o = ((store.collection('pdpl_office_cfg').get('cfg') || {}).owners || []).find((x) => low(x.system) === low(m.system));
    return o && isHuman(o.user) ? o.user : null;
  }

  // ---- map a rule to a table
  function addMap(b, who) {
    person(who, 'maps a retention rule to a table');
    const rule = rules().find((r) => r.id === b.rule_id);
    if (!rule) throw httpErr(404, 'no retention rule or processing activity ' + b.rule_id + ' (an archived rule cannot be mapped)');
    if (!rule.period_months) throw httpErr(409, b.rule_id + ' has no retention period - set period_months (or retention_months) on the rule first');
    const sc = store.collection('pdpl_discovery').get(b.db);
    if (!sc || b.db === '_last') throw httpErr(404, 'no Data Catalog source ' + b.db + ' - run discovery on the Data Catalog page first');
    if (!ENGINES.includes(sc.engine || 'oracle')) throw httpErr(409, WHY.engine);
    const t = catalogTable(b.db, b.schema, b.table);
    if (!t) throw httpErr(404, 'table ' + b.schema + '.' + b.table + ' is not in the Data Catalog for ' + (sc.label || b.db) + ' - only a table the read-only discovery found can be mapped');
    const dc = t.date_columns.find((c) => c.column === b.date_column);
    const known = (sc.columns || []).find((c) => c.owner === b.schema && c.table === b.table && c.column === b.date_column);
    if (known && !DATE_TYPE.test(String(known.type || ''))) throw httpErr(409, 'date_column ' + b.date_column + ' is ' + known.type + ' in the catalog, not a date');
    if (mapsC().all((m) => m.status === 'active' && m.db === b.db && m.schema === b.schema && m.table === b.table && m.rule_id === b.rule_id).length) throw httpErr(409, b.schema + '.' + b.table + ' is already mapped to ' + b.rule_id + ' - retire that mapping first');
    if (b.owner && !isHuman(b.owner)) throw httpErr(400, 'owner: a data owner is a person, not a service or AI identity');
    const at = iso();
    const m = { id: nextId(mapsC, 'RM-'), rule_id: rule.id, rule_source: rule.source, db: b.db, db_label: sc.label || sc.host || b.db, engine: sc.engine || 'oracle', schema: b.schema, table: b.table, date_column: b.date_column,
      column_from: dc ? 'catalog' : 'typed', system: b.system || sc.label || sc.host || b.db, owner_user: b.owner || null, note: b.note || '', status: 'active', by: who.user, at, last: null, history: [{ at, by: who.user, what: 'mapped to ' + rule.id }] };
    mapsC().put(m);
    audit(who, 'map.add', m.id, { rule_id: m.rule_id, db: m.db, table: m.schema + '.' + m.table, date_column: m.date_column, column_from: m.column_from, system: m.system, owner: m.owner_user });
    return m;
  }
  function retireMap(id, b, who) {
    person(who, 'retires a retention mapping');
    const m = mapsC().get(id); if (!m) throw httpErr(404, 'no retention mapping ' + id);
    if (m.status !== 'active') throw httpErr(409, id + ' is already retired');
    const rec = Object.assign({}, m, { status: 'retired', retired_by: who.user, retired_at: iso(), retire_reason: b.reason, history: hist(m, who, 'retired: ' + b.reason) });
    mapsC().put(rec);
    const closed = [];
    for (const t of tasksC().all((x) => x.map_id === id && !['verified', 'cleared', 'retired'].includes(x.status))) { tasksC().put(Object.assign({}, t, { status: 'retired', closed_at: iso(), history: hist(t, who, 'mapping retired') })); closed.push(t.id); }
    audit(who, 'map.retire', id, { reason: s(b.reason, 200), tasks_closed: closed });
    return rec;
  }

  // ---- the scan
  let scanning = null;
  function rule(m) { return rules().find((r) => r.id === m.rule_id) || null; }
  async function countOne(m) {
    const r = rule(m), at = iso();
    const fail = (cls, extra) => ({ at, ok: false, error_class: cls, error: WHY[cls] || 'the count failed', detail: s(extra, 120), cutoff: null, count: null, oldest: null });
    if (!r || !r.period_months) return fail('config', 'the rule ' + m.rule_id + ' is archived or has no retention period');
    const cutoff = monthsBack(today(), r.period_months);
    const sc = store.collection('pdpl_discovery').get(m.db);
    if (!sc || !catalogTable(m.db, m.schema, m.table)) return Object.assign(fail('not_in_catalog'), { cutoff });
    if (!ENGINES.includes(sc.engine || 'oracle')) return Object.assign(fail('engine'), { cutoff });
    if (![m.schema, m.table, m.date_column].every((x) => NAME.test(String(x)))) return Object.assign(fail('name'), { cutoff });   // validated at mapping; checked again before every run
    if (!sc.cred_id) return Object.assign(fail('no_login'), { cutoff });
    let x;
    try { x = await runQuery({ op: 'retention_count', key: m.db, engine: sc.engine || 'oracle', host: sc.host, port: sc.port || (sc.engine === 'mssql' ? 1433 : sc.engine === 'postgres' ? 5432 : 1521), service: sc.service || '', cred_id: sc.cred_id, schema: m.schema, table: m.table, column: m.date_column, cutoff }); }
    catch (e) { x = { ok: false, error_class: 'error', error: s(e.message, 120) }; }
    if (!x || x.ok !== true) { const cls = (x && WHY[x.error_class]) ? x.error_class : 'error'; return Object.assign(fail(cls, x && x.error), { cutoff, error: WHY[cls] || ('the count failed (' + s(x && x.error_class, 40) + ')') }); }
    if (!Number.isInteger(x.count) || x.count < 0) return Object.assign(fail('bad_answer'), { cutoff });
    return { at, ok: true, count: x.count, oldest: /^\d{4}-\d{2}-\d{2}$/.test(String(x.oldest || '')) ? x.oldest : null, cutoff, period_months: r.period_months, error_class: null, error: '' };
  }
  function openTask(m, res, who, note) {
    const t = { id: nextId(tasksC, 'RT-'), map_id: m.id, rule_id: m.rule_id, system: m.system, table: m.schema + '.' + m.table, owner: ownerOf(m), status: 'open', opened_at: res.at, count_at_open: res.count, count: res.count, oldest: res.oldest, cutoff: res.cutoff, last_scan: res.at,
      note: note || '', history: [{ at: res.at, by: who.user, what: res.count + ' row(s) past retention' + (note ? ' - ' + note : '') }] };
    tasksC().put(t);
    audit(who, 'task.open', t.id, { map_id: m.id, table: t.table, count: res.count, owner: t.owner });
    return t;
  }
  // what a successful count means for the table's task
  function onResult(m, res, who) {
    const live = tasksC().all((t) => t.map_id === m.id && ['open', 'attested', 'accepted', 'not_verified'].includes(t.status))[0];
    const held = suspended(m);
    if (!live) { if (res.count > 0 && !held) return { opened: openTask(m, res, who).id }; return {}; }
    const t = Object.assign({}, live);
    if (t.status === 'accepted' && Date.parse(res.at) > Date.parse(t.accepted_at)) {
      const before = t.baseline, verified = res.count < before;
      Object.assign(t, { status: verified ? 'verified' : 'not_verified', verification: { at: res.at, before, after: res.count, verified }, count: res.count, oldest: res.oldest, last_scan: res.at, closed_at: verified ? res.at : undefined,
        history: hist(t, who, verified ? 'verified: rows past retention fell from ' + before + ' to ' + res.count : 'NOT verified: ' + res.count + ' row(s) past retention, ' + before + ' when the attestation was accepted') });
      tasksC().put(t);
      audit(who, verified ? 'task.verified' : 'task.not_verified', t.id, { map_id: m.id, before, after: res.count });
      const out = { [verified ? 'verified' : 'not_verified']: t.id };
      if (verified && res.count > 0 && !held) out.opened = openTask(m, res, who, 'rows still past retention after ' + t.id).id;   // newly aged rows, or what the disposal did not reach
      return out;
    }
    if ((t.status === 'open' || t.status === 'not_verified') && res.count === 0) {
      Object.assign(t, { status: 'cleared', count: 0, last_scan: res.at, closed_at: res.at, history: hist(t, who, 'the scan found no row past retention' + (t.attestation ? '' : ' - no attestation was recorded')) });
      tasksC().put(t); audit(who, 'task.cleared', t.id, { map_id: m.id, attested: !!t.attestation });
      return { cleared: t.id };
    }
    Object.assign(t, { count: res.count, oldest: res.oldest, cutoff: res.cutoff, last_scan: res.at, owner: t.owner || ownerOf(m) });
    tasksC().put(t);
    return {};
  }
  async function scan(who, why) {
    if (scanning) return scanning;
    scanning = (async () => {
      const list = mapsC().all((m) => m.status === 'active');
      if (!list.length) throw httpErr(409, 'no table is mapped to a retention rule yet - map one first (rule -> table -> date column)');
      const at = iso(), results = [], events = { opened: [], verified: [], not_verified: [], cleared: [] };
      for (const m of list) {
        const res = await countOne(m);
        const cur = mapsC().get(m.id);
        mapsC().put(Object.assign({}, cur, { last: res }));
        results.push({ map_id: m.id, table: m.schema + '.' + m.table, system: m.system, ok: res.ok, count: res.count, cutoff: res.cutoff, error_class: res.error_class });
        if (!res.ok) { warn('count:' + m.id, 'retention count could not read a table', { map: m.id, engine: m.engine, cls: res.error_class }); continue; }
        const ev = onResult(Object.assign({}, cur, { last: res }), res, who);
        for (const k of Object.keys(ev)) events[k].push(ev[k]);
      }
      const run = { id: nextId(runsC, 'RR-'), at, by: who.user, why: why || 'manual', mapped: list.length, ok: results.filter((x) => x.ok).length, failed: results.filter((x) => !x.ok).length,
        past: results.filter((x) => x.ok && x.count > 0).length, rows: results.reduce((a, x) => a + (x.ok ? x.count : 0), 0), results, events };
      runsC().put(run);
      for (const old of runsC().all().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(36)) runsC().remove(old.id);
      audit(who, 'scan', run.id, { why: run.why, mapped: run.mapped, ok: run.ok, failed: run.failed, tables_past: run.past, rows_past: run.rows, events });
      return run;
    })();
    try { return await scanning; } finally { scanning = null; }
  }

  // ---- attestation, acceptance, return
  function task(id) { const t = tasksC().get(id); if (!t) throw httpErr(404, 'no retention task ' + id); return t; }
  function attest(id, b, who) {
    person(who, 'records a disposal');
    const t = task(id);
    if (!['open', 'not_verified'].includes(t.status)) throw httpErr(409, id + ' is ' + t.status.replace('_', ' ') + ' - a disposal is recorded on an open task');
    const isOwner = t.owner && low(t.owner) === low(who.user);
    if (!isOwner && who.role !== 'operator' && who.role !== 'admin') throw httpErr(403, 'only the data owner (' + (t.owner || 'not named') + ') or an operator records the disposal for ' + id);
    if (b.date > today()) throw httpErr(400, 'date cannot be in the future');
    const floor = new Date(Date.parse(String(t.opened_at).slice(0, 10)) - 366 * DAY).toISOString().slice(0, 10);
    if (b.date < floor) throw httpErr(400, 'date is more than a year before the task was opened (' + String(t.opened_at).slice(0, 10) + ')');
    const m = mapsC().get(t.map_id);
    if (activeHold(t.map_id) && b.method !== 'archive_legal_hold') throw httpErr(409, 'the rule is suspended for ' + t.table + ' (hold ' + activeHold(t.map_id).id + ') - only an archive under legal hold is recorded while it lasts');
    const att = { method: b.method, date: b.date, reference: b.reference, note: b.note, by: who.user, role: who.role, at: iso(), count_when_recorded: t.count };
    const rec = Object.assign({}, t, { status: 'attested', attestation: att, attestations: (t.attestations || []).concat([att]).slice(-10), history: hist(t, who, 'disposal recorded: ' + METHOD_LABEL[b.method] + ' on ' + b.date + ' (' + b.reference + ')') });
    tasksC().put(rec);
    audit(who, 'task.attest', id, { map_id: t.map_id, table: t.table, system: m ? m.system : t.system, method: b.method, date: b.date, reference: s(b.reference, 120), count: t.count });
    return rec;
  }
  function decide(id, b, who, accept) {
    person(who, accept ? 'accepts a disposal attestation' : 'returns a disposal attestation');
    if (!mayApprove(who)) throw httpErr(403, 'the DPO (' + (dpo() || 'not named in the PDPL profile') + ') or an administrator ' + (accept ? 'accepts' : 'returns') + ' a disposal attestation');
    const t = task(id);
    if (t.status !== 'attested') throw httpErr(409, id + ' is ' + t.status.replace('_', ' ') + ' - only a recorded disposal is accepted or returned');
    if (low(t.attestation.by) === low(who.user)) throw httpErr(403, 'four-eyes: ' + who.user + ' recorded this disposal and cannot ' + (accept ? 'accept' : 'return') + ' it - another person (the DPO or an administrator) decides');
    const rec = accept
      ? Object.assign({}, t, { status: 'accepted', accepted_by: who.user, accepted_at: iso(), accept_note: b.note || '', baseline: t.count, history: hist(t, who, 'accepted' + (b.note ? ': ' + b.note : '') + ' - the next scan verifies the count fell') })
      : Object.assign({}, t, { status: 'open', returned_by: who.user, returned_at: iso(), return_note: b.note, attestation: null, history: hist(t, who, 'returned: ' + b.note) });
    tasksC().put(rec);
    audit(who, accept ? 'task.accept' : 'task.return', id, { map_id: t.map_id, attested_by: t.attestation.by, method: t.attestation.method, baseline: accept ? t.count : undefined, note: s(b.note, 200) });
    return rec;
  }

  // ---- holds (four-eyes)
  function hold(id) { const h = holdsC().get(id); if (!h) throw httpErr(404, 'no retention hold ' + id); return Object.assign({}, h, { status: holdState(h) }); }
  function requestHold(b, who) {
    person(who, 'requests a retention hold');
    const m = mapsC().get(b.map_id); if (!m || m.status !== 'active') throw httpErr(404, 'no active retention mapping ' + b.map_id);
    if (b.until <= today()) throw httpErr(400, 'until must be a date after today');
    if (Date.parse(b.until) - Date.parse(today()) > 3 * 366 * DAY) throw httpErr(400, 'until must be within 3 years - review and renew a longer hold');
    if (holdsC().all((h) => h.map_id === b.map_id && ['requested', 'active'].includes(holdState(h))).length) throw httpErr(409, m.schema + '.' + m.table + ' already has a requested or active hold');
    const h = { id: nextId(holdsC, 'RH-'), map_id: m.id, table: m.schema + '.' + m.table, system: m.system, reason: b.reason, until: b.until, status: 'requested', requested_by: who.user, requested_at: iso(), history: [{ at: iso(), by: who.user, what: 'requested until ' + b.until }] };
    holdsC().put(h);
    audit(who, 'hold.request', h.id, { map_id: m.id, table: h.table, until: b.until, reason: s(b.reason, 200) });
    return h;
  }
  function decideHold(id, b, who, action) {
    person(who, 'decides a retention hold');
    if (!mayApprove(who)) throw httpErr(403, 'the DPO (' + (dpo() || 'not named in the PDPL profile') + ') or an administrator ' + (action === 'end' ? 'ends' : action === 'approve' ? 'approves' : 'rejects') + ' a retention hold');
    const h = hold(id);
    if (action === 'end') { if (h.status !== 'active') throw httpErr(409, id + ' is ' + h.status + ' - only an active hold is ended'); }
    else {
      if (h.status !== 'requested') throw httpErr(409, id + ' is ' + h.status + ' - only a requested hold is approved or rejected');
      if (low(h.requested_by) === low(who.user)) throw httpErr(403, 'four-eyes: ' + who.user + ' requested this hold and cannot ' + action + ' it - another person (the DPO or an administrator) decides');
      if (action === 'approve' && h.until <= today()) throw httpErr(409, id + ' ends on ' + h.until + ' - request it again with a later end date');
    }
    const st = { approve: 'active', reject: 'rejected', end: 'ended' }[action];
    const past = { approve: 'approved', reject: 'rejected', end: 'ended' }[action];
    const rec = Object.assign({}, holdsC().get(id), { status: st, [past + '_by']: who.user, [past + '_at']: iso(), [action + '_note']: b.note || '', history: hist(h, who, past + (b.note ? ': ' + b.note : '')) });
    holdsC().put(rec);
    audit(who, 'hold.' + action, id, { map_id: h.map_id, table: h.table, until: h.until, requested_by: h.requested_by, note: s(b.note, 200) });
    return rec;
  }

  function saveSettings(b, who) {
    person(who, 'sets the retention scan');
    if (!mayApprove(who)) throw httpErr(403, 'an administrator or the DPO (' + (dpo() || 'not named') + ') sets the retention scan');
    const cur = settings(), rec = Object.assign({ id: 'cfg' }, cur);
    for (const k of ['enabled', 'every_days', 'attest_days']) if (b[k] !== undefined) rec[k] = b[k];
    rec.by = who.user; rec.at = iso();
    cfgC().put(rec);
    audit(who, 'settings', 'cfg', { enabled: rec.enabled, every_days: rec.every_days, attest_days: rec.attest_days, previous: { enabled: cur.enabled, every_days: cur.every_days, attest_days: cur.attest_days } });
    return settings();
  }

  // ---- views
  const lastRun = () => runsC().all().sort((a, b) => String(b.at).localeCompare(String(a.at)))[0] || null;
  function nextScan() { const st = settings(), l = lastRun(); return st.enabled && l ? new Date(Date.parse(l.at) + st.every_days * DAY).toISOString() : null; }
  function decorate(t) {
    const m = mapsC().get(t.map_id) || {}, h = activeHold(t.map_id), lh = m.id ? legalHold(m) : null;
    const overdue = t.status === 'open' && !h && !lh && now() - Date.parse(t.opened_at) > settings().attest_days * DAY;
    return Object.assign({}, t, { rule_id: m.rule_id || t.rule_id, date_column: m.date_column, db_label: m.db_label, hold: h ? { id: h.id, until: h.until } : null, legal_hold: lh, overdue });
  }
  function view(who) {
    const R = rules(), maps = mapsC().all().sort((a, b) => (a.status !== 'active') - (b.status !== 'active') || String(a.id).localeCompare(String(b.id)));
    const tasks = tasksC().all().map(decorate).sort((a, b) => (['verified', 'cleared', 'retired'].includes(a.status)) - (['verified', 'cleared', 'retired'].includes(b.status)) || String(b.opened_at).localeCompare(String(a.opened_at)));
    const holds = holdsC().all().map((h) => Object.assign({}, h, { status: holdState(h) })).sort((a, b) => String(b.requested_at).localeCompare(String(a.requested_at)));
    const M = maps.map((m) => { const r = R.find((x) => x.id === m.rule_id); const t = tasks.find((x) => x.map_id === m.id && ['open', 'attested', 'accepted', 'not_verified'].includes(x.status));
      return Object.assign({}, m, { rule: r ? { name: r.name, period_months: r.period_months, trigger: r.trigger, action: r.action, source: r.source } : null, owner: ownerOf(m), hold: activeHold(m.id), legal_hold: legalHold(m), task: t ? { id: t.id, status: t.status } : null }); });
    const active = M.filter((m) => m.status === 'active'), live = tasks.filter((t) => ['open', 'attested', 'accepted', 'not_verified'].includes(t.status));
    const C = catalog().map((t) => Object.assign(t, { rules: R.filter((r) => (r.systems || []).some((x) => low(x) === low(t.label))).map((r) => r.id), mapped: active.filter((m) => m.db === t.db && m.schema === t.schema && m.table === t.table).map((m) => m.id) }));
    return { me: who.user, role: who.role, dpo: dpo(), is_dpo: isDpo(who), can_approve: mayApprove(who), settings: settings(), last_run: lastRun(), next_scan: nextScan(), methods: METHODS.map((k) => [k, METHOD_LABEL[k]]),
      rules: R, catalog: C, maps: M, tasks, holds,
      totals: { mapped: active.length, scanned_ok: active.filter((m) => m.last && m.last.ok).length, failed: active.filter((m) => m.last && !m.last.ok).length, never: active.filter((m) => !m.last).length,
        tables_past: active.filter((m) => m.last && m.last.ok && m.last.count > 0).length, rows_past: active.reduce((a, m) => a + (m.last && m.last.ok ? m.last.count : 0), 0),
        open: live.filter((t) => t.status === 'open').length, overdue: live.filter((t) => t.overdue).length, awaiting: live.filter((t) => t.status === 'attested').length, accepted: live.filter((t) => t.status === 'accepted').length,
        not_verified: live.filter((t) => t.status === 'not_verified').length, verified: tasks.filter((t) => t.status === 'verified').length, holds_requested: holds.filter((h) => h.status === 'requested').length, holds_active: holds.filter((h) => h.status === 'active').length },
      note: 'Counts only: one fixed, read-only COUNT per mapped table through the Data Catalog\'s read-only login. No row and no personal data value is read, stored or shown. The platform never deletes or changes data: the data owner disposes of the rows in the system and records it here; the DPO accepts; the next scan verifies the count fell.' };
  }
  function mine(who) {
    const t = tasksC().all((x) => x.owner && low(x.owner) === low(who.user) && ['open', 'attested', 'accepted', 'not_verified'].includes(x.status)).map(decorate);
    return { me: who.user, tasks: t.sort((a, b) => String(a.opened_at).localeCompare(String(b.opened_at))), methods: METHODS.map((k) => [k, METHOD_LABEL[k]]), attest_days: settings().attest_days };
  }

  // ---- Notification & Escalation
  function signals() {
    const out = [], st = settings();
    for (const t0 of tasksC().all((x) => ['open', 'not_verified'].includes(x.status))) {
      const t = decorate(t0); if (t.hold || t.legal_hold) continue;
      if (t.status === 'open' && t.overdue) {
        const days = Math.floor((now() - Date.parse(t.opened_at)) / DAY);
        out.push({ fp: 'pdpl:retention:overdue:' + t.id, source: 'pdpl', ref: t.id, title: 'Rows past retention in ' + s(t.system, 80) + ' ' + s(t.table, 120) + ' with no disposal recorded after ' + days + ' days',
          text: t.count + ' row(s) past ' + t.rule_id + ' (older than ' + t.cutoff + (t.oldest ? ', oldest ' + t.oldest : '') + '); data owner ' + (t.owner || 'not named') + '. Record the disposal on PDPL -> Retention Enforcement (limit ' + st.attest_days + ' days).', severity: 2, condition: true });
      }
      if (t.status === 'not_verified') {
        const v = t.verification || {};
        out.push({ fp: 'pdpl:retention:unverified:' + t.id, source: 'pdpl', ref: t.id, title: 'Disposal for ' + s(t.system, 80) + ' ' + s(t.table, 120) + ' was not verified by the scan',
          text: 'accepted by ' + (t.accepted_by || '?') + ', but rows past retention went from ' + v.before + ' to ' + v.after + '. The data owner (' + (t.owner || 'not named') + ') checks the disposal and records it again.', severity: 3, condition: true });
      }
    }
    return out;
  }

  // ---- the monthly scan
  function due() { const st = settings(); if (!st.enabled || !mapsC().all((m) => m.status === 'active').length) return false; const l = lastRun(); return !l || now() - Date.parse(l.at) >= st.every_days * DAY; }
  async function tick() { if (due()) await scan(SYS, 'schedule'); }
  function start() {
    if (opts.noTimer || app.noTimers) return () => { /* timers are off (tests): tick() is driven by hand */ };
    const job = guardOf(app, 'pdpl.retention.scan', tick);
    const t1 = setTimeout(job, 5 * 60000), t2 = setInterval(job, HOUR);
    if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
    return () => { clearTimeout(t1); clearInterval(t2); };
  }

  return { view, mine, rules, catalog, addMap, retireMap, scan, tick, attest, accept: (id, b, who) => decide(id, b, who, true), giveBack: (id, b, who) => decide(id, b, who, false),
    requestHold, decideHold, saveSettings, signals, start, isDpo, METHODS };
}

function registerPdplRetention(srv, app, X0) {
  const X = X0 && typeof X0.view === 'function' ? X0 : createPdplRetention(app, X0 || {});
  app.addons = app.addons || {}; app.addons.pdplRetention = X;
  const { body, param } = require('./check');
  const id = (ctx, re, what) => { const v = param(ctx.params.id, 'id'); if (!re.test(v)) throw httpErr(400, 'id must be ' + what); return v; };
  const MID = (ctx) => id(ctx, /^RM-\d{5,}$/, 'a retention mapping id (RM-nnnnn)'), TID = (ctx) => id(ctx, /^RT-\d{5,}$/, 'a retention task id (RT-nnnnn)'), HID = (ctx) => id(ctx, /^RH-\d{5,}$/, 'a retention hold id (RH-nnnnn)');
  const DBNAME = (f) => ({ required: true, max: 128, re: NAME, msg: f + ' must be a database name of letters, digits, _ $ # only (anything else cannot be queried safely)' });
  srv.route('GET', '/pdpl/retention/enforcement', (ctx) => { ctx.need('operator'); return X.view(ctx.who); });
  srv.route('GET', '/pdpl/retention/enforcement/mine', (ctx) => { ctx.need('viewer'); return X.mine(ctx.who); });
  srv.route('POST', '/pdpl/retention/maps', (ctx) => {
    ctx.need('operator');   // the DPO or a data steward
    const b = body(ctx.body).str('rule_id', { required: true, max: 40, re: /^PD-(RETENTION|ROPA)-\d{3,}$/, msg: 'rule_id must be a retention rule (PD-RETENTION-nnn) or a processing activity (PD-ROPA-nnn)' })
      .str('db', { required: true, max: 200, re: /^[A-Za-z0-9_.:|-]+$/, msg: 'db must be a Data Catalog source key' }).str('schema', DBNAME('schema')).str('table', DBNAME('table')).str('date_column', DBNAME('date_column'))
      .str('system', { max: 120 }).str('owner', { max: 80, re: USER, msg: 'owner must be a platform user name' }).str('note', { max: 500 }).done();
    return X.addMap(b, ctx.who);
  });
  srv.route('POST', '/pdpl/retention/maps/:id/retire', (ctx) => { ctx.need('operator'); return X.retireMap(MID(ctx), body(ctx.body).str('reason', { required: true, min: 5, max: 300 }).done(), ctx.who); });
  srv.route('POST', '/pdpl/retention/scan', (ctx) => { ctx.need('operator'); return X.scan(ctx.who, 'manual'); });
  srv.route('POST', '/pdpl/retention/settings', (ctx) => {
    ctx.need('operator');   // an administrator or the DPO - checked in saveSettings
    return X.saveSettings(body(ctx.body).bool('enabled').int('every_days', { min: 7, max: 92 }).int('attest_days', { min: 1, max: 180 }).done(), ctx.who);
  });
  srv.route('POST', '/pdpl/retention/tasks/:id/attest', (ctx) => {
    ctx.need('viewer');
    const b = body(ctx.body).oneOf('method', METHODS, { required: true }).date('date', { required: true }).str('reference', { required: true, min: 3, max: 120 }).str('note', { required: true, min: 10, max: 1000 }).done();
    return X.attest(TID(ctx), b, ctx.who);
  }, { anyRole: 'the data owner may hold the viewer role - attest checks the owner, or an operator' });
  srv.route('POST', '/pdpl/retention/tasks/:id/accept', (ctx) => { ctx.need('operator'); return X.accept(TID(ctx), body(ctx.body).str('note', { max: 500 }).done(), ctx.who); });
  srv.route('POST', '/pdpl/retention/tasks/:id/return', (ctx) => { ctx.need('operator'); return X.giveBack(TID(ctx), body(ctx.body).str('note', { required: true, min: 5, max: 500 }).done(), ctx.who); });
  srv.route('POST', '/pdpl/retention/holds', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('map_id', { required: true, max: 20, re: /^RM-\d{5,}$/, msg: 'map_id must be a retention mapping id (RM-nnnnn)' }).str('reason', { required: true, min: 10, max: 500 }).date('until', { required: true }).done();
    return X.requestHold(b, ctx.who);
  });
  srv.route('POST', '/pdpl/retention/holds/:id/approve', (ctx) => { ctx.need('operator'); return X.decideHold(HID(ctx), body(ctx.body).str('note', { max: 500 }).done(), ctx.who, 'approve'); });
  srv.route('POST', '/pdpl/retention/holds/:id/reject', (ctx) => { ctx.need('operator'); return X.decideHold(HID(ctx), body(ctx.body).str('note', { required: true, min: 5, max: 500 }).done(), ctx.who, 'reject'); });
  srv.route('POST', '/pdpl/retention/holds/:id/end', (ctx) => { ctx.need('operator'); return X.decideHold(HID(ctx), body(ctx.body).str('note', { required: true, min: 5, max: 500 }).done(), ctx.who, 'end'); });
  return X;
}

module.exports = { createPdplRetention, registerPdplRetention, COUNT_PY, COUNT_PY_LIB, monthsBack, METHODS };
