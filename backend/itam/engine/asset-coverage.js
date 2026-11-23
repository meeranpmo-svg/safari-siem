// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const fs = require('node:fs');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * Asset Coverage & Query ({P} = /api/itam, IT Assets -> Coverage & Query). Every asset the register holds, joined with what the
 * security tools this platform already reads say about it - one record per asset, each fact with the source that reported it:
 *   edr        an endpoint protection product in the asset's installed software (word-bounded vendor list below). WEAK when its
 *              version is older than the newest version of the same product seen on this estate, or the software report is older
 *              than stale_days. No software inventory for the asset = NOT CHECKED (never "missing": nothing was read).
 *   patch      the Endpoint Central agent (ManageEngine sync, me_ec_computers). WEAK: agent gone from Endpoint Central, last contact
 *              older than stale_days, or critical patches missing. Endpoint Central not connected = NOT CHECKED.
 *   backup     the Backup Coverage verdict (engine/backup.js view): protected = present, stale / failed = weak, none = missing,
 *              exempt there = exempt. No backup platform configured = NOT CHECKED. Servers and VMs only.
 *   vuln_scan  the newest scan of one of the asset's addresses or names by any scanner: Greenbone (vulnscan_results), Tenable /
 *              Nessus (vapt_scanned: every host a pull examined, also clean ones; and its findings), FireCompass (its findings).
 *              Older than scan_days (90) = weak, never scanned = missing, no scanner read yet = NOT CHECKED. The tool is named.
 *   siem_logs  the inventory's SIEM log coverage (discovery logCoverage): covered / silent = weak / absent = missing; SIEM not
 *              reachable = NOT CHECKED. Servers, VMs, network and storage.
 *   monitoring the SIEM's Server Availability map (GET /netops/avail/map, by IP): online = present, offline = weak (monitored, but
 *              not answering since <time> - down, or its checks are blocked), not in the map = missing; SIEM not reachable = NOT
 *              CHECKED. An asset without an IP cannot be monitored and says so. Servers, VMs, network and storage.
 * Each control applies to the asset types listed in CONTROLS; elsewhere it is "n/a". A gap = weak or missing. PRIORITY ranks the
 * gaps by business criticality (criticality, else CIA availability; unrated counts as medium and says so):
 *   priority = weight(criticality) x (2 x missing + weak)      weight: critical 4, high 3, medium / unrated 2, low 1
 * QUERY LANGUAGE (GET /asset-coverage/query?q=): terms joined by AND, at most 20, at most 500 characters:
 *   field:value      equals (case-insensitive, * wildcard, comma = any of: type:server,vm)
 *   field~text       contains                       -field:value  /  field!:value   not
 *   field>n field<n  numbers (gaps, priority, seen_days)          a bare word  matches name, hostname or an address
 *   control fields edr / patch / backup / vuln_scan / siem_logs take present | weak | missing | gap | not_checked | exempt | na
 * An unknown field or a malformed term is a 400 that names it. Saved queries (operator) are shared with every team; an admin can
 * SCHEDULE one (daily / weekly at HH:MM Riyadh) to mail its result as CSV through the SIEM's Reports relay - "always", or only
 * "on change" (assets that entered or left the result since the last run). Every run is recorded.
 * ACTION CENTER: an operator requests an action on a query result or a list of assets (at most 200) - enrol into SIEM log
 * collection, set the owner / department, add a tag - with a reason. A DIFFERENT named person approves it (app.approveGate,
 * scope infra; never the requester, never a service / AI identity), and only then it runs, asset by asset, each result recorded.
 * A request not decided in 7 days expires. Exemptions (admin, with a reason and an end date at most a year away) take a control
 * out of the gaps for one asset; they are listed on the page and expire on their own.
 *   GET  /asset-coverage                          viewer    controls, summary per control / site / type, assets by priority
 *   GET  /asset-coverage/asset/:id                viewer    one asset, every control with its source and reason
 *   GET  /asset-coverage/query?q=&limit=          viewer    run a query (limit 1..2000, default 500)
 *   GET  /asset-coverage/fields                   viewer    the query fields and their values
 *   POST /asset-coverage/exempt                   admin     {asset_id, control, reason, until} | {asset_id, control, remove:true}
 *   GET  /asset-coverage/queries                  viewer    saved queries (schedule recipients: admin only), recent runs
 *   POST /asset-coverage/queries                  operator  {id?, name, q, team?}                       audited
 *   POST /asset-coverage/queries/:id/delete       operator  the creator, or an admin                    audited
 *   POST /asset-coverage/queries/:id/schedule     admin     {enabled, period, at, weekday?, recipients[], mode}   audited
 *   POST /asset-coverage/queries/:id/run-now      admin                                                 audited
 *   GET  /asset-coverage/actions                  viewer    requests with their per-asset results
 *   POST /asset-coverage/actions                  operator  {kind, q? | asset_ids?, owner?, department?, tag?, reason}   audited
 *   POST /asset-coverage/actions/:id/approve      approver (four-eyes)                                  audited
 *   POST /asset-coverage/actions/:id/reject       approver  {reason}                                    audited
 *   POST /asset-coverage/actions/:id/cancel       the requester, or an admin                            audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DAY = 86400000, RIYADH = 3 * 3600000;
const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const ENDPOINT = ['server', 'vm', 'workstation', 'laptop'];
const CONTROLS = {
  edr: { label: 'Endpoint protection (EDR / antivirus)', types: ENDPOINT, source: 'installed software (agent / import)' },
  patch: { label: 'Patch agent (Endpoint Central)', types: ENDPOINT, source: 'ManageEngine Endpoint Central' },
  backup: { label: 'Backup', types: ['server', 'vm'], source: 'Backup Coverage (NetBackup / Veeam / Cohesity)' },
  vuln_scan: { label: 'Vulnerability scan', types: ['server', 'vm', 'network', 'storage'], source: 'Greenbone, Tenable / Nessus and FireCompass (VAPT Studio)' },
  siem_logs: { label: 'SIEM log collection', types: ['server', 'vm', 'network', 'storage'], source: 'SIEM log coverage' },
  monitoring: { label: 'Availability monitoring', types: ['server', 'vm', 'network', 'storage'], source: 'Server Availability (SIEM)' },
};
const CK = Object.keys(CONTROLS);
const STATES = ['present', 'weak', 'missing', 'not_checked', 'exempt', 'na'];
// endpoint protection products, word-bounded (a bare "sense" or "traps" would match unrelated software)
const EDR = [
  ['Kaspersky', /\bkaspersky\b.*\b(endpoint|security|anti-?virus|edr)\b/i], ['Microsoft Defender', /\b(microsoft|windows) defender\b|\bdefender for (endpoint|servers)\b/i],
  ['CrowdStrike', /\bcrowdstrike\b|\bfalcon sensor\b/i], ['SentinelOne', /\bsentinel ?one\b|\bsentinel agent\b/i],
  ['Trend Micro', /\btrend micro\b|\bapex one\b|\bdeep security agent\b/i], ['Sophos', /\bsophos\b.*\b(endpoint|intercept|anti-?virus)\b/i],
  ['Symantec', /\bsymantec endpoint\b/i], ['Trellix / McAfee', /\b(trellix|mcafee)\b.*\b(endpoint|agent|ens)\b/i],
  ['ESET', /\beset\b.*\b(endpoint|security|anti-?virus)\b/i], ['Bitdefender', /\bbitdefender\b/i], ['Carbon Black', /\bcarbon ?black\b/i],
  ['FortiClient / FortiEDR', /\bforti(client|edr)\b/i], ['Cortex XDR', /\bcortex xdr\b/i],
];
const CRIT_W = { critical: 4, high: 3, medium: 2, low: 1 };
const KINDS = { siem_enrol: 'Enrol into SIEM log collection', set_owner: 'Set owner / department', add_tag: 'Add a tag' };
const EMAIL = /^[^\s@<>"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/;
const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const low = (v) => String(v == null ? '' : v).toLowerCase().trim();
const short = (v) => low(v).split('.')[0];
const s = (v, n) => String(v == null ? '' : v).slice(0, n);
const ipsOf = (a) => [...new Set([a.mgmt_ip, a.ip].concat(a.ips || []).filter((x) => IP_RE.test(String(x || ''))))];
const critOf = (a) => { const c = low(a.criticality || (a.cia && a.cia.a)); return CRIT_W[c] ? c : null; };
function vcmp(x, y) {   // dotted version compare: 1.10 > 1.9; non-numeric parts compare as text
  const A = String(x || '').split(/[^0-9A-Za-z]+/).filter(Boolean), B = String(y || '').split(/[^0-9A-Za-z]+/).filter(Boolean);
  for (let i = 0; i < Math.max(A.length, B.length); i++) {
    const p = A[i] || '0', q = B[i] || '0', np = /^\d+$/.test(p), nq = /^\d+$/.test(q);
    const c = np && nq ? Number(p) - Number(q) : p.localeCompare(q);
    if (c) return c < 0 ? -1 : 1;
  }
  return 0;
}
const csvCell = (v) => { let t = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return /[",\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };

// ---------- the query language (pure; exported for the tests) ----------
const TEXT_FIELDS = { name: 1, hostname: 1, type: 1, site: 1, status: 1, os: 1, owner: 1, department: 1, criticality: 1, vendor: 1, model: 1, serial: 1, ip: 1, tag: 1, source: 1, edr_product: 1 };
const NUM_FIELDS = { gaps: 1, priority: 1, seen_days: 1 };
function tokenize(q) {
  const out = []; const re = /\s*(-?[A-Za-z_]+(?:!:|:|~|>=|<=|>|<)(?:"[^"]*"|\S+)|"[^"]*"|\S+)/g; let m;
  while ((m = re.exec(q))) out.push(m[1]);
  return out;
}
function parseQuery(q0) {
  const q = String(q0 == null ? '' : q0).trim();
  if (q.length > 500) throw httpErr(400, 'q is longer than 500 characters');
  if (/[\u0000-\u001f\u007f]/.test(q)) throw httpErr(400, 'q contains control characters');
  const terms = [];
  for (const t of tokenize(q)) {
    const m = /^(-?)([A-Za-z_]+)(!:|:|~|>=|<=|>|<)(.*)$/.exec(t);
    if (!m) { const w = t.replace(/^"|"$/g, ''); if (w) terms.push({ field: '*', op: '~', values: [low(w)], neg: false }); continue; }
    const field = low(m[2]), op = m[3], raw = m[4].replace(/^"|"$/g, ''), neg = m[1] === '-' || op === '!:';
    const isCtl = CK.includes(field);
    if (!TEXT_FIELDS[field] && !NUM_FIELDS[field] && !isCtl) throw httpErr(400, 'q: unknown field "' + s(field, 30) + '" - fields: ' + Object.keys(TEXT_FIELDS).concat(Object.keys(NUM_FIELDS), CK).join(', '));
    if (!raw) throw httpErr(400, 'q: "' + s(t, 40) + '" has no value');
    if (/[<>]/.test(op)) {
      if (!NUM_FIELDS[field]) throw httpErr(400, 'q: ' + field + ' is not a number field - use ' + field + ':value');
      if (!/^\d+(\.\d+)?$/.test(raw)) throw httpErr(400, 'q: ' + field + op + ' needs a number');
      terms.push({ field, op, values: [Number(raw)], neg: m[1] === '-' }); continue;
    }
    if (isCtl) {
      const vals = raw.split(',').map(low).filter(Boolean);
      const badV = vals.find((v) => !STATES.includes(v) && v !== 'gap' && v !== 'n/a'); if (badV) throw httpErr(400, 'q: ' + field + ' takes present, weak, missing, gap, not_checked, exempt or na - not "' + s(badV, 30) + '"');
      terms.push({ field, op: ':', values: vals.map((v) => (v === 'n/a' ? 'na' : v)), neg }); continue;
    }
    if (NUM_FIELDS[field] && op === ':') { if (!/^\d+(\.\d+)?$/.test(raw)) throw httpErr(400, 'q: ' + field + ' needs a number'); terms.push({ field, op: '=', values: [Number(raw)], neg }); continue; }
    terms.push({ field, op: op === '~' ? '~' : ':', values: raw.split(',').map(low).filter(Boolean), neg });
  }
  if (terms.length > 20) throw httpErr(400, 'q has more than 20 terms');
  return terms;
}
const wild = (pat, v) => (pat.includes('*') ? new RegExp('^' + pat.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$').test(v) : pat === v);
function fieldValues(r, f) {
  if (f === 'tag') return (r.tags || []).map(low);
  if (f === 'source') return (r.sources || []).map(low);
  if (f === 'ip') return (r.ips || []).map(low);
  return [low(r[f])];
}
function matches(r, terms) {
  for (const t of terms) {
    let hit;
    if (t.field === '*') hit = [r.name, r.hostname].concat(r.ips || []).some((x) => low(x).includes(t.values[0]));
    else if (CK.includes(t.field)) { const st = r.controls[t.field].state; hit = t.values.some((v) => (v === 'gap' ? st === 'weak' || st === 'missing' : v === st)); }
    else if (NUM_FIELDS[t.field]) {
      const v = r[t.field], n = t.values[0]; if (v == null) { hit = false; }
      else hit = t.op === '>' ? v > n : t.op === '<' ? v < n : t.op === '>=' ? v >= n : t.op === '<=' ? v <= n : v === n;
    } else {
      const vs = fieldValues(r, t.field);
      hit = t.op === '~' ? t.values.some((p) => vs.some((v) => v.includes(p))) : t.values.some((p) => vs.some((v) => wild(p, v)));
    }
    if (t.neg ? hit : !hit) return false;
  }
  return true;
}

function createAssetCoverage(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { every() {}, warn() {} };
  const cfg = () => Object.assign({ stale_days: 7, scan_days: 90 }, (app.config && app.config.asset_coverage) || {});
  const iso = (t) => new Date(t == null ? now() : t).toISOString();
  const exC = () => store.collection('acov_exempt'), qC = () => store.collection('acov_queries'), runC = () => store.collection('acov_runs'), actC = () => store.collection('acov_actions');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'asset.coverage.' + action, target, detail }); };
  const seq = () => now().toString(36) + Math.random().toString(36).slice(2, 6);

  // ---- sources ----
  let logCache = { at: 0, v: null };
  async function logCov() {
    if (logCache.v && now() - logCache.at < 300000) return logCache.v;
    const fn = opts.logCoverage || (app.discovery && typeof app.discovery.logCoverage === 'function' ? () => app.discovery.logCoverage() : null);
    let v;
    if (!fn) v = { ok: false, error: 'SIEM log coverage is not available (discovery not loaded)' };
    else { try { const r = await fn(); v = r && r.ok ? { ok: true, by: new Map((r.assets || []).map((x) => [x.asset_id, x])) } : { ok: false, error: (r && r.error) || 'SIEM not reachable' }; } catch (e) { v = { ok: false, error: s(e.message, 200) }; L.every('acov.logcov', 3600000, 'warn', 'asset coverage: SIEM log coverage could not be read', { err: s(e.message, 200) }); } }
    logCache = { at: now(), v }; return v;
  }
  let availCache = { at: 0, v: null };
  async function availMap() {
    if (availCache.v && now() - availCache.at < 300000) return availCache.v;
    let v;
    try {
      let r;
      if (opts.availMap) r = await opts.availMap();
      else {
        const siem = app.discovery && app.discovery.siem;
        if (!siem || typeof siem.call !== 'function' || (typeof siem.configured === 'function' && !siem.configured())) r = { ok: false, error: 'SIEM link not configured - Server Availability runs in the SIEM' };
        else { const x = await siem.call('GET', '/netops/avail/map', { user: 'system:itam-asset-coverage', role: 'viewer' });
          r = x && x.status === 200 && x.json ? { ok: true, hosts: x.json.hosts || {} } : { ok: false, error: x && x.status === 404 ? 'Server Availability is not installed in the SIEM (404)' : 'SIEM answered HTTP ' + (x && x.status) }; }
      }
      v = r && r.ok ? { ok: true, hosts: r.hosts || {} } : { ok: false, error: (r && r.error) || 'Server Availability not reachable' };
    } catch (e) { v = { ok: false, error: 'SIEM not reachable (' + s(e.code || e.message, 120) + ')' }; L.every('acov.avail', 3600000, 'warn', 'asset coverage: Server Availability could not be read', { err: s(e.message, 200) }); }
    availCache = { at: now(), v }; return v;
  }
  function backupView() {
    try {
      if (!store.collection('backup_platforms').all().length) return { ok: false, error: 'no backup platform connected (Backup Coverage)' };
      const B = opts.backup || require('./backup').createBackup(app); const v = B.view();
      return { ok: true, by: new Map((v.assets || []).map((x) => [x.asset_id, x])) };
    } catch (e) { L.every('acov.backup', 3600000, 'warn', 'asset coverage: backup coverage could not be read', { err: s(e.message, 200) }); return { ok: false, error: s(e.message, 200) }; }
  }
  function ecIndex() {
    const rows = store.collection('me_ec_computers').all();
    if (!rows.length) return { ok: false, error: 'Endpoint Central not connected (ManageEngine sync has no computers)' };
    const byAsset = new Map(), byName = new Map();
    for (const r of rows) { if (r.asset_id) byAsset.set(r.asset_id, r); for (const k of [low(r.name), short(r.name), short(r.fqdn)]) if (k && !byName.has(k)) byName.set(k, r); }
    return { ok: true, byAsset, byName };
  }
  // the newest scan of each address / host name, across every scanner the platform reads: Greenbone (vulnscan_results: hosts
  // covered by each scan), Tenable (vapt_scanned: every host a pull examined, clean ones too; and its findings), FireCompass
  // (findings - an import lists only what it found, so a host FireCompass found nothing on cannot be told apart from one it never saw)
  function scanIndex() {
    const last = new Map(), tools = new Set();
    const add = (k0, at, tool) => { const k = low(k0); if (!k || !at || !Number.isFinite(Date.parse(at))) return; const cur = last.get(k); if (!cur || String(at) > cur.at) last.set(k, { at: new Date(Date.parse(at)).toISOString(), tool }); };
    const addName = (n, at, tool) => { add(n, at, tool); if (!IP_RE.test(low(n)) && low(n).indexOf('.') > 0) add(short(n), at, tool); };
    for (const r of store.collection('vulnscan_results').all()) { tools.add('Greenbone'); for (const h of r.hosts || []) addName(h, r.at, 'Greenbone'); }
    for (const r of store.collection('vapt_scanned').all()) { tools.add('Tenable'); for (const ip of r.ips || []) add(ip, r.at, r.tool || 'Tenable'); for (const n of r.names || []) addName(n, r.at, r.tool || 'Tenable'); }
    for (const f of store.collection('fc_findings').all()) {
      const tool = (f.vendor || 'firecompass') === 'tenable' ? 'Tenable' : 'FireCompass'; tools.add(tool);
      const at = f.last_seen && /^\d{4}-\d{2}-\d{2}/.test(f.last_seen) ? f.last_seen : f.last_imported;
      for (const n of [f.host, f.asset]) if (n) addName(n, at, tool);
    }
    if (!tools.size) return { ok: false, error: 'no vulnerability scan has been read yet (Greenbone, Tenable or FireCompass in VAPT Studio)' };
    return { ok: true, last, tools: [...tools].sort() };
  }

  async function build() {
    const c = cfg(), t = now(), staleMs = c.stale_days * DAY;
    const assets = store.collection('assets').all((a) => !CLOSED[a.status]).slice(0, 50000);
    const [lc, av] = await Promise.all([logCov(), availMap()]);
    const bk = backupView(), ec = ecIndex(), sc = scanIndex();
    const ex = new Map(); for (const e of exC().all()) { if (Date.parse(e.until + 'T23:59:59Z') >= t) ex.set(e.asset_id + '|' + e.control, e); }
    // the newest version of each endpoint protection product seen on the estate
    const newest = new Map();
    const edrOf = (a) => { for (const sw of a.software || []) { const n = String((sw && (sw.name || sw)) || '') + ' ' + String((sw && sw.publisher) || ''); const hit = EDR.find((p) => p[1].test(n)); if (hit) return { product: hit[0], version: (sw && sw.version) || null, name: s(sw.name || sw, 120) }; } return null; };
    for (const a of assets) { const e = edrOf(a); if (e && e.version && (!newest.has(e.product) || vcmp(e.version, newest.get(e.product)) > 0)) newest.set(e.product, e.version); }
    const rows = assets.map((a) => {
      const ctl = {}, ips = ipsOf(a);
      const set = (k, state, why, extra) => { ctl[k] = Object.assign({ state, why, source: CONTROLS[k].source }, extra || {}); };
      for (const k of CK) {
        if (!CONTROLS[k].types.includes(a.type)) { set(k, 'na', 'does not apply to a ' + (a.type || 'asset')); continue; }
        const e = ex.get(a.id + '|' + k); if (e) { set(k, 'exempt', 'exempt until ' + e.until + ': ' + e.reason + ' (' + e.by + ')'); continue; }
        if (k === 'edr') {
          if (!(a.software || []).length) { set(k, 'not_checked', 'no installed-software inventory for this asset - install the agent or import its software'); continue; }
          const e2 = edrOf(a), agentSeen = (a.sources || []).filter((x) => x.source === 'agent').map((x) => x.last_seen).sort().pop() || a.last_seen || null;
          if (!e2) { set(k, 'missing', 'no endpoint protection product in its ' + a.software.length + ' installed programs'); continue; }
          const nv = newest.get(e2.product);
          if (e2.version && nv && vcmp(e2.version, nv) < 0) set(k, 'weak', e2.product + ' ' + e2.version + ' is older than ' + nv + ', the newest on this estate', { product: e2.product, version: e2.version });
          else if (agentSeen && t - Date.parse(agentSeen) > staleMs) set(k, 'weak', e2.product + ' installed, but the software report is ' + Math.floor((t - Date.parse(agentSeen)) / DAY) + ' days old', { product: e2.product, version: e2.version });
          else set(k, 'present', e2.product + (e2.version ? ' ' + e2.version : ''), { product: e2.product, version: e2.version });
        } else if (k === 'patch') {
          if (!ec.ok) { set(k, 'not_checked', ec.error); continue; }
          const r = ec.byAsset.get(a.id) || [a.name, a.hostname].map((x) => ec.byName.get(low(x)) || ec.byName.get(short(x))).find(Boolean);
          if (!r) { set(k, 'missing', 'not in Endpoint Central'); continue; }
          const lcT = r.last_contact ? Number(r.last_contact) : null;
          if (r.gone_since) set(k, 'weak', 'gone from Endpoint Central since ' + String(r.gone_since).slice(0, 10));
          else if (lcT && t - lcT > staleMs) set(k, 'weak', 'agent last contact ' + Math.floor((t - lcT) / DAY) + ' days ago');
          else if (r.critical > 0) set(k, 'weak', r.critical + ' critical patch(es) missing');
          else set(k, 'present', 'agent ' + (r.agent_version || '') + (r.missing != null ? ' · ' + r.missing + ' patch(es) missing' : ''));
        } else if (k === 'backup') {
          if (!bk.ok) { set(k, 'not_checked', bk.error); continue; }
          const r = bk.by.get(a.id);
          if (!r || r.status === 'none') set(k, 'missing', 'no backup found on any connected platform');
          else if (r.status === 'protected') set(k, 'present', 'last good backup ' + r.age_hours + ' h ago (' + (r.platforms || []).join(', ') + ')');
          else if (r.status === 'exempt') set(k, 'exempt', 'exempt in Backup Coverage: ' + ((r.exempt && r.exempt.reason) || ''));
          else set(k, 'weak', r.status === 'failed' ? 'last backup attempt failed' : 'last good backup ' + (r.age_hours == null ? 'never' : r.age_hours + ' h ago') + ' - older than the target');
        } else if (k === 'vuln_scan') {
          if (!sc.ok) { set(k, 'not_checked', sc.error); continue; }
          const keys = ips.concat([a.name, a.hostname, a.fqdn].filter(Boolean).reduce((o, n) => o.concat([low(n), short(n)]), []));
          if (!keys.length) { set(k, 'not_checked', 'no IP address or name on the asset - a scan cannot be matched to it'); continue; }
          const hit = keys.map((x) => sc.last.get(low(x))).filter(Boolean).sort((p, q) => q.at.localeCompare(p.at))[0];
          if (!hit) set(k, 'missing', 'no scan by ' + sc.tools.join(' / ') + ' has covered ' + (ips.join(', ') || a.name));
          else { const d = Math.floor((t - Date.parse(hit.at)) / DAY); if (d > c.scan_days) set(k, 'weak', 'last scanned ' + d + ' days ago by ' + hit.tool + ' (target ' + c.scan_days + ')', { tool: hit.tool }); else set(k, 'present', 'scanned ' + hit.at.slice(0, 10) + ' by ' + hit.tool, { tool: hit.tool }); }
        } else if (k === 'siem_logs') {
          if (!lc.ok) { set(k, 'not_checked', lc.error); continue; }
          const r = lc.by.get(a.id);
          if (!r || r.status === 'unknown') set(k, 'not_checked', 'the SIEM did not report on this asset');
          else if (r.status === 'covered') set(k, 'present', 'logs arriving' + (r.last_seen ? ', last ' + String(r.last_seen).slice(0, 16).replace('T', ' ') : ''));
          else if (r.status === 'silent') set(k, 'weak', 'a SIEM source exists but has gone silent' + (r.last_seen ? ' since ' + String(r.last_seen).slice(0, 10) : ''));
          else set(k, 'missing', 'no SIEM log source');
        } else if (k === 'monitoring') {
          if (!av.ok) { set(k, 'not_checked', av.error); continue; }
          if (!ips.length) { set(k, 'missing', 'no IP address on the asset - Server Availability monitors by IP; add the management IP'); continue; }
          const ip = ips.find((x) => av.hosts[x]), h = ip ? av.hosts[ip] : null, since = h && h.since ? ' since ' + new Date(typeof h.since === 'number' ? h.since : Date.parse(h.since)).toISOString().slice(0, 16).replace('T', ' ') : '';
          if (!h) set(k, 'missing', 'not monitored by Server Availability (' + ips.join(', ') + ')');
          else if (h.s === 'online') set(k, 'present', 'monitored at ' + ip + ', online' + since);
          else if (h.s === 'offline') set(k, 'weak', 'monitored at ' + ip + ', but not answering' + since + ' - the host is down or its checks are blocked');
          else set(k, 'weak', 'monitored at ' + ip + ', state ' + s(h.s, 30) + since);
        }
      }
      const missing = CK.filter((k) => ctl[k].state === 'missing').length, weak = CK.filter((k) => ctl[k].state === 'weak').length;
      const crit = critOf(a), w = CRIT_W[crit || 'medium'];
      const seen = [a.last_seen].concat((a.sources || []).map((x) => x.last_seen)).filter(Boolean).sort().pop();
      return { id: a.id, name: a.name || a.id, hostname: a.hostname || '', type: a.type || 'other', site: a.site || '', status: a.status || '', os: a.os || '', owner: a.owner || '', department: a.department || '',
        criticality: crit || 'unrated', vendor: a.vendor || '', model: a.model || '', serial: a.serial || '', ips, tags: a.tags || [], sources: [...new Set((a.sources || []).map((x) => x.source).filter(Boolean))],
        edr_product: (ctl.edr && ctl.edr.product) || '', seen_days: seen ? Math.floor((t - Date.parse(seen)) / DAY) : null,
        controls: ctl, gaps: missing + weak, priority: w * (2 * missing + weak) };
    });
    rows.sort((x, y) => y.priority - x.priority || y.gaps - x.gaps || String(x.name).localeCompare(String(y.name)));
    return { rows, sources: { edr: { ok: true }, patch: ec.ok ? { ok: true } : { ok: false, error: ec.error }, backup: bk.ok ? { ok: true } : { ok: false, error: bk.error }, vuln_scan: sc.ok ? { ok: true } : { ok: false, error: sc.error }, siem_logs: lc.ok ? { ok: true } : { ok: false, error: lc.error }, monitoring: av.ok ? { ok: true } : { ok: false, error: av.error } } };
  }
  function summarise(rows) {
    const per = {};
    for (const k of CK) {
      const n = (st) => rows.filter((r) => r.controls[k].state === st).length;
      const o = { present: n('present'), weak: n('weak'), missing: n('missing'), not_checked: n('not_checked'), exempt: n('exempt') };
      const measured = o.present + o.weak + o.missing;
      per[k] = Object.assign({ label: CONTROLS[k].label, applies_to: CONTROLS[k].types, source: CONTROLS[k].source, applicable: measured + o.not_checked + o.exempt, coverage_pct: measured ? Math.round(100 * o.present / measured) : null }, o);
    }
    const by = (f) => { const m = new Map(); for (const r of rows) { const key = r[f] || 'Unassigned'; if (!m.has(key)) m.set(key, []); m.get(key).push(r); }
      return [...m.entries()].map(([key, rs]) => { const o = { key, assets: rs.length, gaps: rs.reduce((x, r) => x + r.gaps, 0) };
        for (const k of CK) { const ms = rs.filter((r) => ['present', 'weak', 'missing'].includes(r.controls[k].state)); o[k] = ms.length ? Math.round(100 * ms.filter((r) => r.controls[k].state === 'present').length / ms.length) : null; }
        return o; }).sort((x, y) => y.assets - x.assets).slice(0, 60); };
    return { per_control: per, by_site: by('site'), by_type: by('type'), assets: rows.length, with_gaps: rows.filter((r) => r.gaps > 0).length, unrated_with_gaps: rows.filter((r) => r.gaps > 0 && r.criticality === 'unrated').length };
  }
  async function view() {
    const B = await build();
    return { generated_at: iso(), controls: CONTROLS, states: STATES, sources: B.sources, summary: summarise(B.rows), assets: B.rows.slice(0, 2000), truncated: B.rows.length > 2000,
      exemptions: exC().all().map((e) => Object.assign({}, e, { active: Date.parse(e.until + 'T23:59:59Z') >= now() })).sort((x, y) => String(x.until).localeCompare(String(y.until))),
      priority_rule: 'priority = weight(criticality) x (2 x missing + weak); weight critical 4, high 3, medium / unrated 2, low 1', edr_products: EDR.map((p) => p[0]) };
  }
  async function asset(id) {
    param(id, 'id'); const B = await build(); const r = B.rows.find((x) => x.id === id);
    if (!r) throw httpErr(404, 'asset not found (or retired / disposed)'); return { asset: r, sources: B.sources };
  }
  async function query(q, limit0) {
    const terms = parseQuery(q);
    const limit = limit0 == null || limit0 === '' ? 500 : Number(limit0);
    if (!Number.isInteger(limit) || limit < 1 || limit > 2000) throw httpErr(400, 'limit must be a whole number from 1 to 2000');
    const B = await build(); const hit = B.rows.filter((r) => matches(r, terms));
    return { q: String(q || ''), terms: terms.length, total: hit.length, rows: hit.slice(0, limit), truncated: hit.length > limit, sources: B.sources };
  }
  function fields() {
    return { text: Object.keys(TEXT_FIELDS), numbers: Object.keys(NUM_FIELDS), controls: CK, control_values: ['present', 'weak', 'missing', 'gap', 'not_checked', 'exempt', 'na'],
      examples: ['type:server,vm edr:missing', 'criticality:critical,high gaps>0', 'site:HQ backup:gap', 'siem_logs:missing -status:in_stock', 'os~2012 patch:weak', 'source:vcenter -source:agent', 'type:server,vm monitoring:missing'] };
  }
  function exempt(input, who) {
    const b = body(input).str('asset_id', { required: true, id: true }).oneOf('control', CK, { required: true }).bool('remove', { def: false }).str('reason', { max: 300 }).date('until', {}).done();
    const id = b.asset_id + '|' + b.control;
    if (b.remove) { if (!exC().get(id)) throw httpErr(404, 'no exemption for ' + b.control + ' on that asset'); exC().remove(id); audit(who, 'exempt.remove', b.asset_id, { control: b.control }); return { removed: true }; }
    if (!store.collection('assets').get(b.asset_id)) throw httpErr(404, 'asset not found');
    if (!b.reason || b.reason.length < 5) throw httpErr(400, 'reason is required (at least 5 characters): why this control does not apply');
    if (!b.until) throw httpErr(400, 'until is required (YYYY-MM-DD): an exemption ends');
    const u = Date.parse(b.until + 'T00:00:00Z'); if (u < now() - DAY) throw httpErr(400, 'until is in the past'); if (u > now() + 366 * DAY) throw httpErr(400, 'until must be within a year');
    const rec = { id, asset_id: b.asset_id, control: b.control, reason: b.reason, until: b.until, by: who.user, at: iso() };
    exC().put(rec); audit(who, 'exempt', b.asset_id, { control: b.control, until: b.until, reason: b.reason }); return { exemption: rec };
  }

  // ---- saved queries + schedules ----
  const pubQ = (x, role) => { const o = Object.assign({}, x); if (o.schedule && role !== 'admin') o.schedule = Object.assign({}, o.schedule, { recipients: undefined, recipient_count: (o.schedule.recipients || []).length }); delete o.last_ids; return o; };
  function queries(role) {
    return { queries: qC().all().sort((x, y) => String(x.name).localeCompare(String(y.name))).map((x) => pubQ(x, role)),
      runs: runC().all().sort((x, y) => y.at - x.at).slice(0, 50) };
  }
  function saveQuery(input, who) {
    const b = body(input).str('id', { max: 40, re: /^q-[a-z0-9]{1,30}$/, msg: 'id has an invalid format' }).str('name', { required: true, max: 120 }).str('q', { required: true, max: 500 }).str('team', { max: 80 }).done();
    parseQuery(b.q);   // a saved query must run
    const prev = b.id ? qC().get(b.id) : null;
    if (b.id && !prev) throw httpErr(404, 'no saved query "' + b.id + '"');
    if (prev && prev.created_by !== who.user && who.role !== 'admin') throw httpErr(403, 'only ' + prev.created_by + ' or an administrator can change this saved query');
    if (!prev && qC().all().length >= 100) throw httpErr(409, 'at most 100 saved queries - delete one first');
    const rec = Object.assign({}, prev || { id: 'q-' + seq(), created_by: who.user, created_at: iso() }, { name: b.name, q: b.q, team: b.team || '', updated_by: who.user, updated_at: iso() });
    if (prev && prev.q !== b.q) delete rec.last_ids;   // a different question: "on change" starts again
    qC().put(rec); audit(who, prev ? 'query.update' : 'query.save', rec.id, { name: b.name, q: b.q }); return { query: pubQ(rec, who.role) };
  }
  function deleteQuery(id, who) {
    param(id, 'id'); const x = qC().get(id); if (!x) throw httpErr(404, 'no saved query "' + s(id, 40) + '"');
    if (x.created_by !== who.user && who.role !== 'admin') throw httpErr(403, 'only ' + x.created_by + ' or an administrator can delete this saved query');
    qC().remove(id); audit(who, 'query.delete', id, { name: x.name }); return { deleted: id };
  }
  const riyadhDay = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
  function nextRun(sc, after) {
    const [hh, mm] = sc.at.split(':').map(Number);
    for (let i = 0; i < 9; i++) {
      const t = Date.parse(riyadhDay(after + i * DAY) + 'T00:00:00Z') - RIYADH + (hh * 60 + mm) * 60000;
      if (t <= after) continue;
      if (sc.period === 'weekly' && new Date(t + RIYADH).getUTCDay() !== sc.weekday) continue;
      return t;
    }
    return null;
  }
  function schedule(id, input, who) {
    param(id, 'id'); const x = qC().get(id); if (!x) throw httpErr(404, 'no saved query "' + s(id, 40) + '"');
    const b = body(input).bool('enabled', { required: true }).oneOf('period', ['daily', 'weekly'], { def: 'daily' }).str('at', { def: '07:30', re: HHMM, msg: 'at must be HH:MM (Riyadh time)' })
      .int('weekday', { min: 0, max: 6, def: 0 }).list('recipients', { max: 20, item: 'str', itemMax: 254, unique: true, def: [] }).oneOf('mode', ['always', 'on_change'], { def: 'on_change' }).done();
    b.recipients = [...new Set(b.recipients.map((r) => r.toLowerCase()))];
    const badR = b.recipients.find((r) => !EMAIL.test(r)); if (badR) throw httpErr(400, 'recipients: "' + s(badR, 60) + '" is not an e-mail address');
    if (b.enabled && !b.recipients.length) throw httpErr(400, 'recipients: at least one e-mail address to send the result to');
    const sc = Object.assign({}, b, { next_at: b.enabled ? nextRun(b, now()) : null, by: who.user, at_set: iso() });
    qC().put(Object.assign({}, x, { schedule: Object.assign({}, x.schedule || {}, sc) }));
    audit(who, 'query.schedule', id, { enabled: b.enabled, period: b.period, at: b.at, mode: b.mode, recipients: b.recipients.length }); return { query: pubQ(qC().get(id), 'admin') };
  }
  const sc0 = ((app.config && app.config.discovery) || {}).siem || {};
  // The SIEM relay (engine/reports/routes.js RELAY_CALLERS) accepts only system:itam-report-center and system:itam-notify;
  // scheduled query e-mail is a notification, so it sends as system:itam-notify (the run itself is audited here as query.*).
  const RELAY_AS = 'system:itam-notify';
  async function relay(payload) {
    if (opts.siem) return opts.siem('POST', '/reports/deliver', payload, RELAY_AS);
    if (!sc0.secret_file) return { ok: false, error: 'SIEM link not configured (discovery.siem.secret_file) - mail goes through the SIEM Reports relay' };
    let sec; try { sec = String(fs.readFileSync(sc0.secret_file, 'utf8')).trim(); if (sec.startsWith('{')) sec = String(JSON.parse(sec).proxy_secret || ''); } catch (e) { return { ok: false, error: 'SIEM secret not readable (' + (e.code || 'error') + ')' }; }
    try {
      const base = String(sc0.base_url || 'http://127.0.0.1:9120').replace(/\/+$/, ''), prefix = sc0.prefix || '/api/soc';
      const r = await require('./discovery/httpc').request(base + prefix + '/reports/deliver', { method: 'POST', headers: { 'X-Sentra-Proxy-Secret': sec, 'X-Auth-User': RELAY_AS, 'X-Auth-Role': 'admin', 'Content-Type': 'application/json' }, body: JSON.stringify(payload), timeoutMs: 45000 });
      return r.status === 200 ? { ok: true } : { ok: false, error: (r.json && r.json.error) || 'SIEM answered HTTP ' + r.status };
    } catch (e) { return { ok: false, error: 'SIEM not reachable (' + (e.code || e.message || 'error') + ')' }; }
  }
  function csvOf(rows) {
    const head = ['name', 'type', 'site', 'criticality', 'owner', 'ip'].concat(CK, ['gaps', 'priority']);
    return [head.join(',')].concat(rows.map((r) => [r.name, r.type, r.site, r.criticality, r.owner, (r.ips || []).join(' ')].concat(CK.map((k) => r.controls[k].state), [r.gaps, r.priority]).map(csvCell).join(','))).join('\n');
  }
  async function runQuery(id, reason, who) {
    const x = qC().get(id); if (!x) throw httpErr(404, 'no saved query "' + s(id, 40) + '"');
    const sc = x.schedule || {}; if (!(sc.recipients || []).length) throw httpErr(409, 'this saved query has no recipients - set its schedule first');
    const run = { id: 'run-' + seq(), query_id: id, name: x.name, reason, at: now(), status: 'running' };
    try {
      const r = await query(x.q, 2000), ids = r.rows.map((y) => y.id), prev = new Set(x.last_ids || []), cur = new Set(ids);
      const added = ids.filter((i) => !prev.has(i)), removed = [...prev].filter((i) => !cur.has(i));
      Object.assign(run, { total: r.total, added: added.length, removed: removed.length });
      if (sc.mode === 'on_change' && x.last_ids && !added.length && !removed.length && reason !== 'run-now') run.status = 'unchanged';
      else {
        const names = (list) => list.slice(0, 30).map((i) => (r.rows.find((y) => y.id === i) || { name: i }).name).join(', ');
        const text = x.name + '\nQuery: ' + x.q + '\n\n' + r.total + ' asset(s) match' + (r.truncated ? ' (first 2000 attached)' : '') + '.\n' +
          (x.last_ids ? 'New since the last run: ' + added.length + (added.length ? ' - ' + names(added) : '') + '\nNo longer matching: ' + removed.length + '\n' : '') +
          ('\nThe list is attached as CSV. Generated by ' + ZYB_ORG.short + ' IT Asset Management - Coverage & Query.\n');
        const d = await relay({ id: run.id, subject: ('[' + ZYB_ORG.short + '] ') + x.name + ' - ' + r.total + ' asset(s)' + (x.last_ids ? ', ' + added.length + ' new' : ''), text, recipients: sc.recipients,
          attachments: [{ filename: 'asset-query-' + id + '-' + riyadhDay(now()) + '.csv', content: csvOf(r.rows), contentType: 'text/csv' }] });
        if (!d.ok) throw httpErr(502, d.error);
        run.status = 'sent';
      }
      qC().put(Object.assign({}, qC().get(id), { last_ids: ids, last_run: { at: run.at, status: run.status, total: r.total } }));
    } catch (e) {
      Object.assign(run, { status: 'failed', error: s(e.message, 300) });
      L.every('acov.run.' + id, 3600000, 'warn', 'asset coverage: scheduled query not delivered', { query: id, err: s(e.message, 200) });
      qC().put(Object.assign({}, qC().get(id), { last_run: { at: run.at, status: 'failed', error: run.error } }));
    }
    run.done_at = now(); runC().put(run);
    for (const old of runC().all().sort((a, b) => b.at - a.at).slice(300)) runC().remove(old.id);
    if (who) audit(who, 'query.run-now', id, { status: run.status, total: run.total });
    return run;
  }
  async function tick() {
    for (const x of qC().all((y) => y.schedule && y.schedule.enabled && y.schedule.next_at && y.schedule.next_at <= now())) {
      try { await runQuery(x.id, 'schedule', null); }
      finally { const cur = qC().get(x.id); if (cur) qC().put(Object.assign({}, cur, { schedule: Object.assign({}, cur.schedule, { next_at: nextRun(cur.schedule, now()) }) })); }
    }
  }

  // ---- Action Center (four-eyes) ----
  const EXPIRE = 7 * DAY;
  function actions() {
    for (const a of actC().all((x) => x.status === 'pending' && now() - Date.parse(x.requested_at) > EXPIRE)) actC().put(Object.assign({}, a, { status: 'expired', decided_at: iso() }));
    return { kinds: KINDS, actions: actC().all().sort((x, y) => String(y.requested_at).localeCompare(String(x.requested_at))).slice(0, 200) };
  }
  async function request(input, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person requests an action, not a service or AI identity');
    const b = body(input).oneOf('kind', Object.keys(KINDS), { required: true }).str('q', { max: 500 }).list('asset_ids', { max: 200, item: 'id', unique: true })
      .str('owner', { max: 120 }).str('department', { max: 120 }).str('tag', { max: 40, re: /^[A-Za-z0-9 _.:-]{1,40}$/, msg: 'tag may hold letters, digits, space and _ . : - only' })
      .str('reason', { required: true, min: 10, max: 500 }).done();
    if (!b.q && !(b.asset_ids || []).length) throw httpErr(400, 'q or asset_ids is required: which assets the action is for');
    if (b.kind === 'set_owner' && !b.owner && !b.department) throw httpErr(400, 'owner or department is required for set_owner');
    if (b.kind === 'add_tag' && !b.tag) throw httpErr(400, 'tag is required for add_tag');
    let ids = b.asset_ids || [];
    if (b.q) { const r = await query(b.q, 2000); if (r.total > 200) throw httpErr(400, 'q matches ' + r.total + ' assets - an action covers at most 200; narrow the query'); ids = r.rows.map((x) => x.id); }
    const col = store.collection('assets'), missing = ids.filter((i) => !col.get(i)); if (missing.length) throw httpErr(400, 'asset_ids: ' + missing.slice(0, 5).join(', ') + ' not found');
    if (!ids.length) throw httpErr(400, 'no asset matches - nothing to act on');
    const rec = { id: 'act-' + seq(), kind: b.kind, label: KINDS[b.kind], q: b.q || null, asset_ids: ids, assets: ids.map((i) => ({ id: i, name: (col.get(i) || {}).name || i })),
      params: { owner: b.owner || null, department: b.department || null, tag: b.tag || null }, reason: b.reason, status: 'pending', requested_by: who.user, requested_role: who.role, requested_at: iso() };
    actC().put(rec); audit(who, 'action.request', rec.id, { kind: b.kind, assets: ids.length, q: b.q || null, reason: b.reason }); return { action: rec };
  }
  const pending = (id) => { param(id, 'id'); const a = actC().get(id); if (!a) throw httpErr(404, 'no action "' + s(id, 40) + '"');
    if (a.status === 'pending' && now() - Date.parse(a.requested_at) > EXPIRE) { actC().put(Object.assign({}, a, { status: 'expired', decided_at: iso() })); throw httpErr(409, 'this request expired (not decided in 7 days) - request it again'); }
    if (a.status !== 'pending') throw httpErr(409, 'this request is ' + a.status); return a; };
  async function approve(id, who) {
    const a = pending(id);
    if (!isHuman(who.user)) throw httpErr(403, 'only a person approves: ' + who.user + ' is a service / AI identity');
    if (low(a.requested_by) === low(who.user)) throw httpErr(403, 'four-eyes: ' + who.user + ' requested this - a different person approves it');
    actC().put(Object.assign({}, a, { status: 'running', approved_by: who.user, approved_role: who.role, approved_at: iso() }));
    // runs as the approver, with the administrator role for this one approved request (the asset and SIEM paths need it)
    const actor = { user: who.user, role: 'admin', ip: who.ip || '' }, results = [];
    for (const aid of a.asset_ids) {
      try {
        if (a.kind === 'siem_enrol') {
          if (!app.membership || typeof app.membership.enable !== 'function') throw httpErr(424, 'SIEM log collection is not available');
          const r = await app.membership.enable(aid, actor); results.push({ id: aid, ok: true, detail: r.already ? 'already enrolled' : 'SIEM source ' + (r.source_id || 'created') });
        } else if (a.kind === 'set_owner') {
          const p = {}; if (a.params.owner) p.owner = a.params.owner; if (a.params.department) p.department = a.params.department;
          app.assets.assign(aid, p, actor); results.push({ id: aid, ok: true, detail: Object.entries(p).map(([k, v]) => k + ' = ' + v).join(', ') });
        } else if (a.kind === 'add_tag') {
          const cur = store.collection('assets').get(aid); const tags = [...new Set((cur.tags || []).concat([a.params.tag]))];
          app.assets.edit(aid, { tags }, actor); results.push({ id: aid, ok: true, detail: 'tag ' + a.params.tag });
        }
      } catch (e) { results.push({ id: aid, ok: false, detail: s(e.message, 200) }); if (!e.status) L.every('acov.action.' + a.kind, 600000, 'warn', 'asset coverage: action step failed', { action: a.id, asset: aid, err: s(e.message, 200) }); }
    }
    const ok = results.filter((r) => r.ok).length;
    const done = Object.assign({}, actC().get(id), { status: ok === results.length ? 'done' : ok ? 'partial' : 'failed', results, done_at: iso() });
    actC().put(done); logCache = { at: 0, v: null }; availCache = { at: 0, v: null };
    audit(who, 'action.approve', id, { kind: a.kind, requested_by: a.requested_by, assets: results.length, ok, failed: results.length - ok });
    return { action: done };
  }
  function reject(id, input, who) {
    const a = pending(id); const b = body(input).str('reason', { required: true, min: 5, max: 300 }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'only a person decides: ' + who.user + ' is a service / AI identity');
    const r = Object.assign({}, a, { status: 'rejected', decided_by: who.user, decided_at: iso(), decision_reason: b.reason }); actC().put(r);
    audit(who, 'action.reject', id, { kind: a.kind, requested_by: a.requested_by, reason: b.reason }); return { action: r };
  }
  function cancel(id, who) {
    const a = pending(id);
    if (low(a.requested_by) !== low(who.user) && who.role !== 'admin') throw httpErr(403, 'only ' + a.requested_by + ' or an administrator can cancel this request');
    const r = Object.assign({}, a, { status: 'cancelled', decided_by: who.user, decided_at: iso() }); actC().put(r); audit(who, 'action.cancel', id, { kind: a.kind }); return { action: r };
  }

  let timer = null;
  function start() {
    if (app.noTimers || opts.noTimer || timer) return;
    const job = guardOf(app, 'asset-coverage.schedules', tick);
    timer = setInterval(job, 5 * 60000); if (timer.unref) timer.unref();
  }
  return { view, asset, query, fields, exempt, queries, saveQuery, deleteQuery, schedule, runQuery, tick, actions, request, approve, reject, cancel, start, _build: build };
}

function registerAssetCoverage(srv, app, C0, o = {}) {
  const C = C0 && C0.view ? C0 : createAssetCoverage(app, Object.assign({}, o, C0 && !C0.view ? C0 : {}));
  app.addons = app.addons || {}; app.addons.assetCoverage = C;
  const gate = (ctx) => { if (typeof app.approveGate === 'function') return app.approveGate(ctx, 'infra'); if (!isHuman(ctx.who && ctx.who.user)) throw httpErr(403, 'only a person approves'); ctx.need('admin'); return true; };
  srv.route('GET', '/asset-coverage', (ctx) => { ctx.need('viewer'); return C.view(); });
  srv.route('GET', '/asset-coverage/asset/:id', (ctx) => { ctx.need('viewer'); return C.asset(ctx.params.id); });
  srv.route('GET', '/asset-coverage/query', (ctx) => { ctx.need('viewer'); return C.query((ctx.query || {}).q, (ctx.query || {}).limit); });
  srv.route('GET', '/asset-coverage/fields', (ctx) => { ctx.need('viewer'); return C.fields(); });
  srv.route('POST', '/asset-coverage/exempt', (ctx) => { ctx.need('admin'); return C.exempt(ctx.body, ctx.who); });
  srv.route('GET', '/asset-coverage/queries', (ctx) => { ctx.need('viewer'); return C.queries(ctx.who.role); });
  srv.route('POST', '/asset-coverage/queries', (ctx) => { ctx.need('operator'); return C.saveQuery(ctx.body, ctx.who); });
  srv.route('POST', '/asset-coverage/queries/:id/delete', (ctx) => { ctx.need('operator'); return C.deleteQuery(ctx.params.id, ctx.who); });
  srv.route('POST', '/asset-coverage/queries/:id/schedule', (ctx) => { ctx.need('admin'); return C.schedule(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/asset-coverage/queries/:id/run-now', (ctx) => { ctx.need('admin'); param(ctx.params.id, 'id'); return C.runQuery(ctx.params.id, 'run-now', ctx.who); });
  srv.route('GET', '/asset-coverage/actions', (ctx) => { ctx.need('viewer'); return C.actions(); });
  srv.route('POST', '/asset-coverage/actions', (ctx) => { ctx.need('operator'); return C.request(ctx.body, ctx.who); }, { maxBody: 32768 });
  srv.route('POST', '/asset-coverage/actions/:id/approve', (ctx) => { ctx.need('operator'); gate(ctx); return C.approve(ctx.params.id, ctx.who); });
  srv.route('POST', '/asset-coverage/actions/:id/reject', (ctx) => { ctx.need('operator'); gate(ctx); return C.reject(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/asset-coverage/actions/:id/cancel', (ctx) => { ctx.need('operator'); return C.cancel(ctx.params.id, ctx.who); });
  C.start();
  return C;
}
module.exports = { createAssetCoverage, registerAssetCoverage, parseQuery, matches, vcmp, CONTROLS, EDR };
