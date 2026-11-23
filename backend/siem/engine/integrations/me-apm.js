// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * ManageEngine Applications Manager (APM) integration - read its monitors and alarms beside the SIEM's own database
 * monitoring, and control the few things APM's REST API documents, under four-eyes approval.
 *
 * APM REST contract used (documented API names; "VERIFY" the JSON shape on the customer's build - docs/MANAGEENGINE.md):
 *   key       ?apikey=<the user's REST API key>   (APM → Settings → REST API; a key sees only that user's monitors)
 *   read      GET {base}/AppManager/json/ListMonitor?type=all        monitors with health / availability
 *             GET {base}/AppManager/json/ListAlarms?type=all         alarms (critical / warning / clear)
 *             GET {base}/AppManager/json/GetMonitorData?resourceid=  one monitor's attributes (drill-down)
 *   control   GET {base}/AppManager/json/PollNow?resourceid=         poll one monitor now (no configuration change)
 *             GET {base}/AppManager/json/UnmanageMonitor?resourceid=&time=<until, ms>&suppresstype=<alerts|monitoring>
 *             GET {base}/AppManager/json/ManageMonitor?resourceid=   back under management
 *   replies   {"response-code":"4000", "response":{...}} = success; any other code is a failure with its message.
 * Only these six paths can ever be called (ALLOWED). Thresholds, actions and monitor definitions are NOT changed from
 * here: APM documents no API for them that this module relies on.
 *
 * Control: Poll now = operator, at once (audited). Unmanage / Manage = a request by an operator, decided by a DIFFERENT
 * person - an administrator, or the human approver for the monitor's area (database monitors: eng:dba; others: infra) -
 * then executed by the engine with the stored key. A service / AI identity never decides.
 * The key lives only in secrets.json (sealed) integrations.me_apm.api_key; it is never returned, logged or stored in state,
 * and it is scrubbed from every error text (it travels in the query string, so URLs are never logged).
 *
 *   createMeApm({ state, config, log, now, transport, dbInstances() })
 *     → { settings(), setSettings(p, by), setKey(k, by), clearKey(by), keyState(), test(), sync(), status(), monitors(f), alarms(f),
 *         monitorData(id), coverage(), request(b, by), decide(id, decision, by, comment), actions(f), start(), stop(), isDb(m) }
 */
const SF = require('../secretfile');
const crypto = require('node:crypto');
const { request: httpsRequest } = require('../secops/https');

const ALLOWED = new Set(['ListMonitor', 'ListAlarms', 'GetMonitorData', 'PollNow', 'UnmanageMonitor', 'ManageMonitor']);
const DEFAULTS = { enabled: false, base_url: '', verify_tls: true, ca_file: '', fingerprint256: '', timeout_ms: 20000, poll_min: 5 };
const DB_RE = /oracle|mssql|sql ?server|mysql|maria|postgre|db2|sybase|mongo|redis|hana|cassandra|informix|database|\bdb\b/i;
const ID_RE = /^[0-9]{1,15}$/;

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const bad = (msg, code = 400) => Object.assign(new Error(msg), { code });
const pick = (o, ...k) => { for (const x of k) { const v = o[x] !== undefined ? o[x] : o[x.toLowerCase()] !== undefined ? o[x.toLowerCase()] : o[x.toUpperCase()]; if (v !== undefined && v !== null && v !== '') return String(v); } return ''; };
const fp = (k) => crypto.createHash('sha256').update(String(k)).digest('hex').slice(0, 8);

/** every object in the reply that names a resource (APM nests results differently per build and per API) */
function records(j, keyRe = /^resourceid$/i) {
  const out = []; const seen = new Set();
  (function walk(v, d) {
    if (d > 8 || v === null || typeof v !== 'object') return;
    if (Array.isArray(v)) { v.forEach((x) => walk(x, d + 1)); return; }
    if (Object.keys(v).some((k) => keyRe.test(k)) && !seen.has(v)) { seen.add(v); out.push(v); }
    Object.values(v).forEach((x) => walk(x, d + 1));
  })(j, 0);
  return out;
}
function normHealth(v) { const s = String(v || '').toLowerCase(); return /crit|^1$|down/.test(s) ? 'critical' : /warn|^4$/.test(s) ? 'warning' : /clear|ok|up|^5$/.test(s) ? 'clear' : s || 'unknown'; }
function normMonitor(r) {
  const avail = pick(r, 'AVAILABILITYSTATUS', 'Availability', 'AVAILABILITYSEVERITY');
  return { id: pick(r, 'RESOURCEID', 'resourceid'), name: pick(r, 'DISPLAYNAME', 'RESOURCENAME', 'NAME'), type: pick(r, 'TYPE', 'TYPEDISPLAYNAME', 'MONITORTYPE'),
    host: pick(r, 'HOSTNAME', 'HOSTIP', 'HOST'), health: normHealth(pick(r, 'HEALTHSTATUS', 'HEALTHSEVERITY', 'Health')), availability: /down|^1$|crit/i.test(avail) ? 'down' : /up|^5$|clear/i.test(avail) ? 'up' : (avail || 'unknown').toLowerCase(),
    managed: !/unmanaged|^false$/i.test(pick(r, 'MANAGED', 'MONITORSTATUS', 'STATUS')), last_polled: pick(r, 'LASTPOLLEDTIME', 'LASTPOLLED'), message: pick(r, 'HEALTHMESSAGE', 'MESSAGE').slice(0, 300) };
}
function normAlarm(r) {
  return { resource_id: pick(r, 'RESOURCEID', 'resourceid'), name: pick(r, 'DISPLAYNAME', 'RESOURCENAME', 'NAME'), type: pick(r, 'TYPE', 'TYPEDISPLAYNAME'),
    severity: normHealth(pick(r, 'SEVERITY', 'STATUS', 'HEALTHSTATUS')), attribute: pick(r, 'ATTRIBUTE', 'ATTRIBUTENAME'), message: pick(r, 'MESSAGE', 'HEALTHMESSAGE').slice(0, 500),
    time: pick(r, 'MODTIME', 'TIME', 'DATETIME', 'LASTMODIFIED'), technician: pick(r, 'TECHNICIAN', 'OWNER') };
}

function createMeApm(o = {}) {
  const { state } = o;
  if (!state) throw new Error('createMeApm needs state');
  const cfg = o.config || {};
  const log = o.log || { info() {}, warn() {}, error() {} };
  const now = o.now || Date.now;
  const transport = o.transport || httpsRequest;
  const col = state.collection('integrations');
  const acts = state.collection('apm_actions');
  const counters = state.collection('counters');
  const auditFn = (e) => { try { if (typeof state.audit === 'function') state.audit(e); } catch (x) { /* audit must not break the integration */ } };
  let timer = null; let snap = { at: 0, monitors: [], alarms: [], error: '', ok: null }; let syncing = null;

  function doc() { return col.get('me_apm') || { id: 'me_apm', settings: {}, cred: {} }; }
  function settings() { return Object.assign({}, DEFAULTS, doc().settings || {}); }
  function setSettings(p, by) {
    if (!isObj(p)) throw bad('settings must be an object');
    const s = settings(); const errs = [];
    for (const k of Object.keys(p)) if (!(k in DEFAULTS)) errs.push(`unknown setting ${String(k).slice(0, 30)}`);
    if (p.base_url !== undefined) { let u = null; try { u = new URL(String(p.base_url)); } catch (e) { /* below */ } if (!u || u.protocol !== 'https:' || u.search || u.username) errs.push('base_url must be https://host:port of Applications Manager (no path parameters, no user in the URL)'); else s.base_url = `${u.protocol}//${u.host}`; }
    for (const k of ['enabled', 'verify_tls']) if (p[k] !== undefined) { if (typeof p[k] !== 'boolean') errs.push(`${k} must be true or false`); else s[k] = p[k]; }
    if (p.poll_min !== undefined) { const v = Number(p.poll_min); if (!Number.isInteger(v) || v < 1 || v > 60) errs.push('poll_min must be 1-60'); else s.poll_min = v; }
    if (p.timeout_ms !== undefined) { const v = Number(p.timeout_ms); if (!Number.isInteger(v) || v < 2000 || v > 120000) errs.push('timeout_ms must be 2000-120000'); else s.timeout_ms = v; }
    if (p.ca_file !== undefined) s.ca_file = String(p.ca_file).slice(0, 300);
    if (p.fingerprint256 !== undefined) { const f = String(p.fingerprint256).replace(/[^0-9a-f]/gi, ''); if (f && f.length !== 64) errs.push('fingerprint256 must be the SHA-256 of the certificate (64 hex characters)'); else s.fingerprint256 = f; }
    if (s.enabled && !s.base_url) errs.push('set base_url before switching on');
    if (errs.length) throw Object.assign(bad(errs[0]), { errors: errs });
    col.put(Object.assign({}, doc(), { settings: s, updated: now(), updated_by: by || '' }));
    restart();
    return settings();
  }
  function key() { const s = cfg.secrets && cfg.secrets.integrations && cfg.secrets.integrations.me_apm; return s && typeof s.api_key === 'string' ? s.api_key : ''; }
  function keyState() { const k = key(); const c = doc().cred || {}; return { api_key_set: !!k, key_fingerprint: k ? fp(k) : '', set_at: c.set_at || 0, set_by: c.set_by || '' }; }
  function writeKey(k) {
    const file = cfg._paths && cfg._paths.secrets;
    if (file) { let sec = {}; try { sec = SF.read(file) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; } sec.integrations = Object.assign({}, sec.integrations || {}); sec.integrations.me_apm = Object.assign({}, sec.integrations.me_apm || {}); if (k) sec.integrations.me_apm.api_key = k; else delete sec.integrations.me_apm.api_key; SF.write(file, sec); }
    if (!cfg.secrets) Object.defineProperty(cfg, 'secrets', { value: {}, enumerable: false, writable: true });
    cfg.secrets.integrations = Object.assign({}, cfg.secrets.integrations || {}); cfg.secrets.integrations.me_apm = Object.assign({}, cfg.secrets.integrations.me_apm || {});
    if (k) cfg.secrets.integrations.me_apm.api_key = k; else delete cfg.secrets.integrations.me_apm.api_key;
  }
  function setKey(k, by) {
    if (typeof k !== 'string' || !/^[A-Za-z0-9._-]{8,200}$/.test(k.trim())) throw bad('api_key: the REST API key from Applications Manager → Settings → REST API');
    writeKey(k.trim()); col.put(Object.assign({}, doc(), { cred: { set_at: now(), set_by: by || '' } }));
    log.info('me-apm: API key stored (write-only)', { by: by || '' }); return keyState();
  }
  function clearKey(by) { writeKey(''); col.put(Object.assign({}, doc(), { cred: {} })); log.info('me-apm: API key removed', { by: by || '' }); return keyState(); }
  const scrub = (t) => { const k = key(); let s = String(t || ''); if (k) s = s.split(k).join('[key]'); return s.replace(/apikey=[^&\s]+/gi, 'apikey=[key]').slice(0, 300); };

  async function call(api, params = {}) {
    if (!ALLOWED.has(api)) throw bad(`${api} is not an allowed Applications Manager call`, 500);
    const s = settings(); const k = key();
    if (!s.base_url) throw bad('Applications Manager is not configured (base_url)', 503);
    if (!k) throw bad('no Applications Manager API key stored', 503);
    const q = new URLSearchParams(Object.assign({ apikey: k }, params));
    let r;
    try { r = await transport({ url: `${s.base_url}/AppManager/json/${api}?${q}`, method: 'GET', timeoutMs: s.timeout_ms, tls: { ca: s.ca_file ? safeRead(s.ca_file) : undefined, fingerprint256: s.fingerprint256 || undefined, insecure: s.verify_tls === false } }); }
    catch (e) { throw bad(`Applications Manager unreachable: ${scrub(e.message)}`, 502); }
    let j = r.json; if (j === undefined || j === null) { try { j = JSON.parse(r.text); } catch (e) { j = null; } }
    if (r.status === 401 || r.status === 403) throw bad(`Applications Manager refused the key (HTTP ${r.status})`, 502);
    if (!j) throw bad(`Applications Manager did not answer JSON (HTTP ${r.status}) - check the URL is the APM web console and that this build serves /AppManager/json`, 502);
    const code = pick(j, 'response-code', 'responsecode');
    if (code && code !== '4000') { const m = (records(j, /^message$/i)[0] || {}).message || (j.response && (j.response.message || j.response.error)) || ''; throw bad(`Applications Manager answered ${code}${m ? `: ${scrub(typeof m === 'string' ? m : JSON.stringify(m))}` : ''}`, 502); }
    return j;
  }
  function safeRead(f) { try { return require('node:fs').readFileSync(f, 'utf8'); } catch (e) { return undefined; } }

  async function test() { const j = await call('ListMonitor', { type: 'all' }); return { ok: true, monitors: records(j).length }; }
  async function sync() {
    if (syncing) return syncing;
    syncing = (async () => {
      try {
        const [m, a] = await Promise.all([call('ListMonitor', { type: 'all' }), call('ListAlarms', { type: 'all' })]);
        const mons = records(m).map(normMonitor).filter((x) => ID_RE.test(x.id));
        const byId = new Map(mons.map((x) => [x.id, x]));
        const alarms = records(a).map(normAlarm).filter((x) => ID_RE.test(x.resource_id)).map((x) => Object.assign(x, { db: isDb(byId.get(x.resource_id) || x) }));
        snap = { at: now(), ok: true, error: '', monitors: mons.map((x) => Object.assign(x, { db: isDb(x) })), alarms };
      } catch (e) { snap = Object.assign({}, snap, { ok: false, error: e.message, error_at: now() }); log.warn('me-apm sync failed', { err: e.message }); }
      return status();
    })().finally(() => { syncing = null; });
    return syncing;
  }
  function isDb(m) { return DB_RE.test(`${m.type || ''} ${m.name || ''}`); }
  function status() {
    const s = settings(); const M = snap.monitors; const A = snap.alarms.filter((x) => x.severity !== 'clear');
    return { configured: !!(s.base_url && key()), enabled: s.enabled, base_url: s.base_url, last_sync: snap.at, ok: snap.ok, error: snap.error,
      monitors: M.length, db_monitors: M.filter((x) => x.db).length, down: M.filter((x) => x.availability === 'down').length, unmanaged: M.filter((x) => !x.managed).length,
      alarms: { critical: A.filter((x) => x.severity === 'critical').length, warning: A.filter((x) => x.severity === 'warning').length, db: A.filter((x) => x.db).length },
      pending_actions: acts.all((x) => x.status === 'pending').length, key: keyState() };
  }
  function monitors(f = {}) { return snap.monitors.filter((x) => (!(f.db === '1' || f.db === true) || x.db) && (!f.q || `${x.name} ${x.type} ${x.host}`.toLowerCase().includes(String(f.q).toLowerCase()))); }
  function alarms(f = {}) { return snap.alarms.filter((x) => (f.all === '1' || x.severity !== 'clear') && (!(f.db === '1' || f.db === true) || x.db)); }
  async function monitorData(id) {
    if (!ID_RE.test(String(id))) throw bad('resourceid must be a number');
    const j = await call('GetMonitorData', { resourceid: String(id) });
    const attrs = []; (function walk(v, d) { if (d > 8 || !v || typeof v !== 'object') return; if (Array.isArray(v)) return v.forEach((x) => walk(x, d + 1));
      const n = pick(v, 'DISPLAYNAME', 'ATTRIBUTENAME', 'NAME'), val = pick(v, 'VALUE', 'CURRENTVALUE'); if (n && val && attrs.length < 400) attrs.push({ name: n.slice(0, 120), value: val.slice(0, 200), unit: pick(v, 'UNITS', 'UNIT'), status: normHealth(pick(v, 'STATUS', 'HEALTHSTATUS', 'SEVERITY')) });
      Object.values(v).forEach((x) => walk(x, d + 1)); })(j, 0);
    return { resource_id: String(id), monitor: snap.monitors.find((x) => x.id === String(id)) || null, attributes: attrs };
  }
  // which databases APM watches that the SIEM dashboard does not, and the other way round (matched by NAME - a lead to verify)
  function coverage() {
    const inst = typeof o.dbInstances === 'function' ? (o.dbInstances() || []) : [];
    const dbm = snap.monitors.filter((x) => x.db);
    const hit = (m, i) => { const n = `${m.name} ${m.host}`.toUpperCase(); return n.includes(String(i.instance || '').toUpperCase()) || (i.host && n.includes(String(i.host).toUpperCase())); };
    return { matched_by: 'name / host text - verify', apm_only: dbm.filter((m) => !inst.some((i) => hit(m, i))).map((m) => ({ id: m.id, name: m.name, type: m.type, host: m.host })),
      siem_only: inst.filter((i) => !dbm.some((m) => hit(m, i))).map((i) => ({ instance: i.instance, host: i.host })),
      both: dbm.filter((m) => inst.some((i) => hit(m, i))).map((m) => ({ id: m.id, name: m.name, instance: (inst.find((i) => hit(m, i)) || {}).instance })) };
  }

  // ---------------------------------------------------------------- control
  function nextId() { const c = counters.get('apm_actions') || { id: 'apm_actions', n: 0 }; c.n++; counters.put(c); return `APMA-${String(c.n).padStart(5, '0')}`; }
  async function exec(a) {
    const p = { resourceid: a.resource_id };
    if (a.action === 'unmanage') { p.time = String(now() + a.hours * 3600000); p.suppresstype = a.suppress; }
    const api = a.action === 'poll' ? 'PollNow' : a.action === 'unmanage' ? 'UnmanageMonitor' : 'ManageMonitor';
    try { await call(api, p); a.status = 'executed'; a.executed_at = now(); a.result = `${api} accepted by Applications Manager`; }
    catch (e) { a.status = 'failed'; a.executed_at = now(); a.result = scrub(e.message); }
    return a;
  }
  async function request(b, by) {
    if (!isObj(b)) throw bad('request must be an object');
    const action = String(b.action || ''); const rid = String(b.resource_id || '');
    if (!['poll', 'unmanage', 'manage'].includes(action)) throw bad('action must be poll, unmanage or manage');
    if (!ID_RE.test(rid)) throw bad('resource_id must be the monitor\'s numeric RESOURCEID');
    const m = snap.monitors.find((x) => x.id === rid);
    if (!m) throw bad('that monitor is not in the last Applications Manager read - sync first', 404);
    const a = { id: nextId(), action, resource_id: rid, monitor: m.name, type: m.type, db: !!m.db, requested_by: by || '', requested_at: now(), reason: String(b.reason || '').trim().slice(0, 300), status: 'pending' };
    if (action === 'unmanage') {
      a.hours = Number(b.hours); a.suppress = b.suppress === 'monitoring' ? 'monitoring' : 'alerts';
      if (!(a.hours > 0 && a.hours <= 72)) throw bad('hours must be 1-72');
    }
    if (action !== 'poll' && a.reason.length < 3) throw bad('say why (reason) - it goes to the approver and the audit log');
    if (action === 'poll') { await exec(a); acts.put(a); auditFn({ at: now(), user: by, action: 'apm.poll', target: rid, detail: { monitor: m.name, status: a.status } }); return a; }
    acts.put(a); auditFn({ at: now(), user: by, action: 'apm.action.request', target: rid, detail: { id: a.id, action, hours: a.hours, suppress: a.suppress } });
    return a;
  }
  function scopeFor(id) { const a = acts.get(id); return a && a.db ? 'eng:dba' : 'infra'; }
  async function decide(id, decision, by, comment) {
    const a = acts.get(String(id)); if (!a) throw bad('no such request', 404);
    if (a.status !== 'pending') throw bad(`already ${a.status}`, 409);
    if (!['approve', 'reject'].includes(decision)) throw bad('decision must be approve or reject');
    if (String(by || '').toLowerCase() === String(a.requested_by || '').toLowerCase()) throw bad('four-eyes: the person who asked cannot decide', 403);
    if (decision === 'reject' && String(comment || '').trim().length < 3) throw bad('say why it is rejected');
    a.decided_by = by; a.decided_at = now(); a.comment = String(comment || '').slice(0, 300);
    if (decision === 'reject') a.status = 'rejected'; else await exec(a);
    acts.put(a); auditFn({ at: now(), user: by, action: `apm.action.${decision}`, target: a.resource_id, detail: { id: a.id, action: a.action, status: a.status, result: a.result || '' } });
    if (a.status === 'executed') guardJob('integrations.me-apm.sync', () => sync())();
    return a;
  }
  function actions(f = {}) { return acts.all((x) => !f.status || x.status === f.status).sort((x, y) => y.requested_at - x.requested_at).slice(0, 300); }

  function restart() { stop(); start(); }
  function start() { const s = settings(); if (!s.enabled || cfg.me_apm_scheduler === false) return; guardJob('integrations.me-apm.sync', () => sync())(); timer = setInterval(guardJob('integrations.me-apm.sync', () => sync()), s.poll_min * 60000); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  return { settings, setSettings, setKey, clearKey, keyState, test, sync, status, monitors, alarms, monitorData, coverage, request, decide, scopeFor, actions, start, stop, isDb, _call: call };
}

module.exports = { createMeApm, records, normMonitor, normAlarm, ALLOWED };
