// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * Audit Analytics ({P} = /api/itam, Audit -> Audit Analytics): the data-analytics workbench of the audit teams - the class of work an
 * ACL / Galvanize analytics licence is bought for, built into the platform and joined to its audit engagements:
 *   datasets   the platform's own records (assets, licences, support contracts, GRC risks / actions / exceptions, joiners, leavers,
 *              privileged access, the audit trail - read-only, secret-shaped fields never read) or a CSV the auditor imports (payments,
 *              claims, vendor master, HR list ...). An import is hashed (SHA-256) and never edited: evidence. Archived, never deleted.
 *   profile    field statistics per column (type, blanks, distinct, min / max / sum / mean / median / stdev, top values) and
 *              suggested tests from the columns (an amount -> Benford, outliers, strata; a sequence number -> gaps; a name -> fuzzy ...)
 *   tests      duplicates, fuzzy duplicates, gaps, Benford's law, stratify, ageing, summarize, outliers (robust z, overall or by peer
 *              group), join / unmatched against a second dataset, period to period (this month's payroll against last month's: new,
 *              gone, changed, by how much - a changed bank account first), filter (structured conditions - never an expression evaluated)
 *   series     imports of the same extract over time (Payroll 2026-09, 2026-10 ...); a script reads latest:<series> / previous:<series>
 *   excel      a workbook (.xlsx, first sheet) imports like a CSV; the exception list exports to Excel and comes back with the
 *              auditee's decision + note per exception (checked against the run, exception and row it was exported with)
 *   sampling   attribute sample size (binomial), seeded random record sample, monetary-unit sample - re-performable from the seed
 *   log        every run is a command in the log: who, when, the dataset and its hash, the parameters, the result and its hash - so
 *              any result can be re-performed and shown unchanged
 *   review     a run is reviewed by a different person (four-eyes on the workpaper); each exception is dispositioned (explained /
 *              false positive / finding) with a note; a run becomes a draft audit finding in the IT / Cyber / Internal Audit Team only
 *              when an auditor on that engagement raises it there (engine/audit-engage.js addFinding, with its own checks)
 *   scripts    a saved sequence of tests on a dataset (the analytic library). A scheduled script runs daily, weekly (Sunday),
 *              monthly (the 1st, Riyadh) or on import (a new period in its series) only after a different person approved it; any
 *              edit withdraws the approval
 *   advisor    the read-only AI audit analytics advisor (intel kit: ai-guard budget, redactSecrets, untrusted tool output). It sees
 *              dataset names, columns, counts and run summaries - never row values - and proposes tests; people run and conclude.
 * Results are indicators for an auditor to follow up, not proof of wrongdoing. Datasets can hold personal data (PDPL): operators and
 * administrators only, every view, export and import audited.
 *   GET  /audit-analytics                              overview: sources, datasets, runs, scripts, open exceptions, test catalogue
 *   GET  /audit-analytics/datasets/:id                 profile, suggestions, 25-row preview (audited)
 *   POST /audit-analytics/datasets                     {name, purpose, csv | xlsx_b64 + filename, series?, period?}  audited
 *   POST /audit-analytics/datasets/:id/archive         admin  {note}                                                audited
 *   POST /audit-analytics/run                          {dataset, test, params, other?}                              audited
 *   POST /audit-analytics/sample                       {dataset, method, size?, confidence?, tolerable?, expected?, amount?, seed?} audited
 *   GET  /audit-analytics/runs/:id · /runs/:id/export  the result · its exceptions as CSV and as an Excel sheet (audited)
 *   POST /audit-analytics/runs/:id/dispositions        {csv | xlsx_b64, filename}  the exception file back with decision + note  audited
 *   POST /audit-analytics/runs/:id/review              {note}  not the person who ran it                             audited
 *   POST /audit-analytics/runs/:id/exceptions/:n       {decision: explained|false_positive|finding, note}            audited
 *   POST /audit-analytics/runs/:id/to-finding          {team, engagement, owner, title, condition, criteria, cause, effect, recommendation, rating}
 *   POST /audit-analytics/scripts                      {id?, name, dataset, steps[{test, params, other?}], schedule}   audited
 *   POST /audit-analytics/scripts/:id/approve          not the author, a person                                     audited
 *   POST /audit-analytics/scripts/:id/run                                                                          audited
 *   POST /audit-analytics/ask                          {question}  the AI advisor (kit)
 */
const crypto = require('node:crypto');
const { body, param, fileCheck } = require('./check');
const { readXlsx } = require('./xlsx-read');
const { guardOf } = require('./errors');
const L = require('./audit-analytics-lib');
const { createIntelKit } = require('./intel-kit');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const same = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
const sha = (x) => 'sha256:' + crypto.createHash('sha256').update(typeof x === 'string' ? x : JSON.stringify(x)).digest('hex');
const SECRET = /pass(word)?|secret|token|api_?key|private|cred|seal|hash|otp|pin\b|cookie/i;
const TEAMS = { it: 'auditEngage', cyber: 'cyberAuditEngage', internal: 'internalAuditEngage' };
const MAX_ROWS = 50000;
// the platform's own records an auditor may analyse - read-only, scalar fields only, secret-shaped fields never read
const SOURCES = {
  'src:assets': { name: 'Asset register', col: 'assets', why: 'every asset with owner, department, vendor, cost and dates' },
  'src:licences': { name: 'Software licences', col: 'licences', why: 'licence counts, costs and renewals' },
  'src:contracts': { name: 'Support contracts', col: 'support_contracts', why: 'vendors, contract values and end dates' },
  'src:risks': { name: 'GRC risks', col: 'grc_risks', why: 'the risk register' },
  'src:actions': { name: 'GRC remediation actions', col: 'grc_actions', why: 'owners, due dates, states' },
  'src:exceptions': { name: 'GRC policy exceptions', col: 'grc_exceptions', why: 'exceptions with expiry' },
  'src:joiners': { name: 'Joiners (HR onboarding)', col: 'onboarding', why: 'requests, approvals and start dates' },
  'src:leavers': { name: 'Leavers (HR offboarding)', col: 'offboarding', why: 'last days and when accounts were disabled' },
  'src:pam': { name: 'Privileged access requests', col: 'pam_requests', why: 'who asked, who approved, for how long' },
  'src:trail': { name: 'Platform audit trail (last 50,000 entries)', trail: true, why: 'who did what, when, from where' },
};
const TESTS = {
  duplicates: { name: 'Duplicates', why: 'records with the same key fields (double payments, duplicate vendors)', params: (b) => b.list('keys', { required: true, item: 'str', itemMax: 60, max: 6, unique: true }) },
  fuzzy: { name: 'Fuzzy duplicates', why: 'near-identical names after normalising (ghost vendors, the same claimant twice)', params: (b) => b.str('field', { required: true, max: 60 }).num('threshold', { min: 0.6, max: 0.99, def: 0.85 }) },
  gaps: { name: 'Gaps in a sequence', why: 'missing and repeated numbers (unrecorded or destroyed documents)', params: (b) => b.str('field', { required: true, max: 60 }) },
  benford: { name: 'Benford\'s law', why: 'first-digit frequencies against Benford - invented or manipulated figures', params: (b) => b.str('field', { required: true, max: 60 }) },
  stratify: { name: 'Stratify', why: 'how the value is spread over bands', params: (b) => b.str('field', { required: true, max: 60 }).int('count', { min: 2, max: 20, def: 5 }).list('bands', { max: 19, def: [] }) },
  age: { name: 'Ageing', why: 'how old the records are, with the value in each bucket', params: (b) => b.str('field', { required: true, max: 60 }).str('amount', { max: 60 }).date('as_of').list('buckets', { max: 8, def: [] }) },
  summarize: { name: 'Summarize', why: 'count and total by a field', params: (b) => b.str('by', { required: true, max: 60 }).str('amount', { max: 60 }) },
  outliers: { name: 'Outliers', why: 'values far from the median (robust z), overall or within a peer group', params: (b) => b.str('field', { required: true, max: 60 }).str('by', { max: 60 }).num('z', { min: 2, max: 10, def: 3.5 }) },
  compare: { name: 'Period to period', why: 'this period against the previous one on a key (payroll, vendor master, claims list): who is new, who has gone, what changed and by how much - a changed bank account comes first', needsOther: true,
    params: (b) => b.str('key', { required: true, max: 60 }).str('other_key', { max: 60 }).list('watch', { max: 30, item: 'str', itemMax: 60, unique: true, def: [] }).str('amount', { max: 60 }).num('pct', { min: 0, max: 1000, def: 10 }) },
  join: { name: 'Join / unmatched', why: 'records in one dataset without a match in another (leavers still active, vendors not in the master)', needsOther: true, params: (b) => b.str('key', { required: true, max: 60 }).str('other_key', { required: true, max: 60 }).oneOf('mode', ['both', 'unmatched_this', 'unmatched_other'], { def: 'both' }) },
  filter: { name: 'Filter', why: 'records that meet structured conditions', params: (b) => b.oneOf('match', ['all', 'any'], { def: 'all' }).list('conditions', { required: true, max: 8 }) },
};
const DECISIONS = ['explained', 'false_positive', 'finding'];
const DECISION_WORDS = { explained: 'explained', 'false positive': 'false_positive', false_positive: 'false_positive', fp: 'false_positive', finding: 'finding' };
const SCHEDULES = ['none', 'daily', 'weekly', 'monthly', 'on_import'];
// a series groups the imports of the same extract over time (Payroll 2026-09, Payroll 2026-10 ...): a script names latest:<series> and
// previous:<series> and so keeps working month after month without being edited (or re-approved)
const SERIES = /^[a-z0-9][a-z0-9 _-]{0,39}$/i, SERIES_REF = /^(latest|previous):([a-z0-9][a-z0-9 _-]{0,39})$/i;
const seriesKey = (v) => String(v || '').trim().toLowerCase().replace(/\s+/g, ' ');

function createAuditAnalytics(app, opts = {}) {
  const now = opts.now || Date.now, st = app.store, iso = () => new Date(now()).toISOString();
  const ds = () => st.collection('aa_datasets'), dsRows = () => st.collection('aa_rows'), runs = () => st.collection('aa_runs'), scripts = () => st.collection('aa_scripts');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'audit-analytics.' + action, target, detail }); };
  const person = (who) => { if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot do this - a named person does'); };
  const nextId = (pre, col) => { const n = col().all(() => true).length + 1; let id = pre + String(n).padStart(4, '0'), k = n; while (col().get(id)) id = pre + String(++k).padStart(4, '0'); return id; };
  const scalar = (r) => { const o = {}; for (const [k, v] of Object.entries(r || {})) { if (SECRET.test(k)) continue; if (v === null || ['string', 'number', 'boolean'].includes(typeof v)) o[k] = typeof v === 'string' ? v.slice(0, 2000) : v; } return o; };

  function sourceRows(id) {
    const S = SOURCES[id];
    if (S.trail) return st.auditTail(MAX_ROWS).map((a) => scalar({ at: a.at, by: a.by, role: a.role, ip: a.ip, action: a.action, target: a.target }));
    let all = []; try { all = st.collection(S.col).all(() => true); } catch (e) { all = []; if (app.log && app.log.every) app.log.every('aa:src:' + id, 600000, 'warn', 'audit analytics: a source could not be read', { source: id, err: String(e.message).slice(0, 160) }); }
    return all.slice(0, MAX_ROWS).map(scalar);
  }
  const fieldsOf = (rows) => { const s = new Set(); for (const r of rows.slice(0, 2000)) for (const k of Object.keys(r)) { s.add(k); if (s.size >= 60) break; } return [...s]; };
  function load(id0) {
    const id = String(id0 || '');
    const sr = SERIES_REF.exec(id);
    if (sr) {
      const list = ds().all((m) => !m.archived && m.series && m.series === seriesKey(sr[2])).sort((a, b) => String(b.period || '').localeCompare(String(a.period || '')) || String(b.at).localeCompare(String(a.at)));
      const m = list[sr[1].toLowerCase() === 'latest' ? 0 : 1];
      if (!m) throw httpErr(409, 'series ' + sr[2] + ': no ' + (sr[1].toLowerCase() === 'latest' ? 'import yet' : 'previous period imported yet') + ' - import the next period into the series');
      return Object.assign(load(m.id), { ref: id });
    }
    if (SOURCES[id]) { const rows = sourceRows(id), fields = fieldsOf(rows); for (const r of rows) for (const f of fields) if (!(f in r)) r[f] = ''; return { id, name: SOURCES[id].name, kind: 'platform', rows, fields, hash: sha(rows) }; }
    const m = ds().get(param(id, 'dataset')); if (!m) throw httpErr(404, 'no dataset ' + id.slice(0, 40));
    if (m.archived) throw httpErr(409, 'dataset ' + m.id + ' is archived');
    const r = dsRows().get(m.id); return { id: m.id, name: m.name, kind: 'import', rows: (r && r.rows) || [], fields: m.fields, hash: m.hash };
  }
  function overview() {
    const R = runs().all(() => true).sort((a, b) => String(b.at).localeCompare(String(a.at)));
    const open = R.reduce((t, r) => t + Math.max(0, (r.result.exceptions_total || 0) - Object.keys(r.dispositions || {}).length), 0);
    return { generated_at: iso(), tests: Object.entries(TESTS).map(([k, t]) => ({ id: k, name: t.name, why: t.why, needs_other: !!t.needsOther })), decisions: DECISIONS, teams: Object.keys(TEAMS).filter((k) => app.addons && app.addons[TEAMS[k]]),
      sources: Object.entries(SOURCES).map(([id, s]) => { let n = 0; try { n = s.trail ? null : st.collection(s.col).all(() => true).length; } catch (e) { n = 0; /* a source not installed reads as empty, said by its count */ } return { id, name: s.name, why: s.why, rows: n }; }),
      datasets: ds().all(() => true).map((m) => ({ id: m.id, name: m.name, purpose: m.purpose, rows: m.rows, fields: m.fields.length, hash: m.hash, imported_by: m.imported_by, at: m.at, archived: !!m.archived, series: m.series || null, period: m.period || null, format: m.format || 'csv', file: m.file || null })),
      series: seriesList(), schedules: SCHEDULES,
      runs: R.slice(0, 200).map(rview), scripts: scripts().all(() => true).map(sview),
      kpis: { runs: R.length, exceptions_open: open, reviewed: R.filter((r) => r.review).length, awaiting_review: R.filter((r) => !r.review && r.result.exceptions_total).length, scripts_scheduled: scripts().all((s) => s.schedule !== 'none' && s.approved_by).length },
      note: 'Results are indicators for an auditor to follow up, not proof of wrongdoing. Datasets may hold personal data (PDPL): every view, import and export is recorded.' };
  }
  function seriesList() {
    const G = {}; for (const m of ds().all((x) => x.series && !x.archived)) (G[m.series] = G[m.series] || []).push({ id: m.id, period: m.period || null, rows: m.rows, at: m.at });
    return Object.entries(G).map(([k, L2]) => { L2.sort((a, b) => String(b.period || '').localeCompare(String(a.period || '')) || String(b.at).localeCompare(String(a.at))); return { series: k, periods: L2.length, latest: L2[0], previous: L2[1] || null, refs: ['latest:' + k, 'previous:' + k] }; });
  }
  const rview = (r) => ({ id: r.id, test: r.test, test_name: (TESTS[r.test] || { name: r.test === 'sample' ? 'Sample' : r.test }).name, dataset: r.dataset, dataset_name: r.dataset_name, other: r.other || null, params: r.params, by: r.by, at: r.at, script: r.script || null,
    summary: r.result.summary, exceptions_total: r.result.exceptions_total || 0, dispositioned: Object.keys(r.dispositions || {}).length, review: r.review || null, finding: r.finding || null, input_hash: r.input_hash, result_hash: r.result_hash });
  const sview = (s) => ({ id: s.id, name: s.name, dataset: s.dataset, steps: s.steps, schedule: s.schedule, author: s.author, version: s.version, approved_by: s.approved_by || null, approved_at: s.approved_at || null, last_run: s.last_run || null, last_runs: s.last_runs || [] });

  function datasetView(id0, who) {
    const d = load(id0), ty = L.types(d.rows, d.fields), prof = L.profile(d.rows, d.fields, ty);
    audit(who, 'dataset.view', d.id, { rows: d.rows.length });
    return { id: d.id, name: d.name, kind: d.kind, rows: d.rows.length, fields: d.fields, types: ty, hash: d.hash, profile: prof, suggestions: L.suggest(d.fields, ty, prof), preview: d.rows.slice(0, 25) };
  }
  function importCsv(b0, who) {
    person(who);
    const b = body(b0).str('name', { required: true, max: 120 }).str('purpose', { required: true, max: 500 }).str('csv', { max: 8000000 }).str('xlsx_b64', { max: 11500000 }).str('filename', { max: 200 })
      .str('series', { max: 40 }).str('period', { max: 7 }).rule((x) => (!x.csv && !x.xlsx_b64 ? 'csv or xlsx_b64: the file to import is required' : x.csv && x.xlsx_b64 ? 'send csv or xlsx_b64, not both' : null))
      .rule((x) => (x.series && !SERIES.test(x.series) ? 'series: letters, digits, space, - and _ only (up to 40)' : x.period && !/^\d{4}-(0[1-9]|1[0-2])$/.test(x.period) ? 'period must be YYYY-MM' : x.series && !x.period ? 'period (YYYY-MM) is required for an import into a series' : null)).done();
    const P = b.csv ? parseFile('csv', b.csv) : parseFile('xlsx', b.xlsx_b64, b.filename), id = nextId('AAD-', ds), hash = P.hash;
    if (ds().all((m) => m.hash === hash && !m.archived).length) throw httpErr(409, (b.csv ? 'csv' : 'xlsx_b64') + ': this exact file is already imported (' + ds().all((m) => m.hash === hash)[0].id + ')');
    const series = b.series ? seriesKey(b.series) : null;
    if (series && ds().all((m) => !m.archived && m.series === series && m.period === b.period).length) throw httpErr(409, 'period: ' + b.period + ' is already imported into series ' + series + ' - archive that import first if it was wrong');
    const m = { id, name: b.name, purpose: b.purpose, rows: P.rows.length, fields: P.fields, delimiter: P.delimiter || null, format: P.format, file: P.file || null, hash, bytes: P.bytes, imported_by: who.user, at: iso(), series, period: series ? b.period : null };
    dsRows().put({ id, rows: P.rows }); ds().put(m);
    audit(who, 'dataset.import', id, { name: b.name, rows: m.rows, fields: m.fields.length, hash, format: m.format, series, period: m.period });
    if (series) m.triggered = onImport(series);
    return m;
  }
  // a CSV or a workbook (first sheet) into rows; the hash is of the bytes as uploaded, so the evidence is the file the auditee sent
  function parseFile(kind, data, filename) {
    if (kind === 'csv') { const P = L.parseCsv(data, { maxRows: MAX_ROWS, maxCols: 60 }); return Object.assign(P, { format: 'csv', hash: sha(data), bytes: Buffer.byteLength(data) }); }
    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(data)) throw httpErr(400, 'xlsx_b64: the file content is not base64');
    const buf = Buffer.from(data, 'base64'), fc = fileCheck(filename || 'upload.xlsx', buf, { allow: ['xlsx'], max: 8 * 1024 * 1024 });
    const X = readXlsx(buf, { maxRows: MAX_ROWS, maxCols: 60 });
    return { fields: X.fields, rows: X.rows, format: 'xlsx', file: fc.name, hash: 'sha256:' + crypto.createHash('sha256').update(buf).digest('hex'), bytes: buf.length };
  }
  // approved on-import scripts that read this series run as soon as a new period arrives - the monthly payroll comparison, unattended
  function onImport(series) {
    const hit = scripts().all((sc) => sc.approved_by && sc.schedule === 'on_import' && [sc.dataset].concat(sc.steps.map((x) => x.other || '')).some((ref) => { const m = SERIES_REF.exec(ref); return m && seriesKey(m[2]) === series; }));
    return hit.map((sc) => { try { const o = runScript(sc.id, SCHED); return { script: sc.id, runs: o.script.last_run.runs, errors: o.script.last_run.errors }; } catch (e) { if (app.log && app.log.every) app.log.every('aa:onimport:' + sc.id, 600000, 'warn', 'audit analytics: an on-import script failed', { script: sc.id, err: String(e.message).slice(0, 200) }); return { script: sc.id, error: String(e.message).slice(0, 200) }; } });
  }
  function archive(id0, b0, who) {
    person(who); const b = body(b0).str('note', { required: true, max: 500 }).done();
    const m = ds().get(param(id0, 'id')); if (!m) throw httpErr(404, 'no dataset ' + String(id0).slice(0, 40)); if (m.archived) throw httpErr(409, 'already archived');
    m.archived = { by: who.user, at: iso(), note: b.note }; ds().put(m); audit(who, 'dataset.archive', m.id, { note: b.note.slice(0, 200) }); return m;
  }

  function execute(dsId, test, p0, other, who, script) {
    const T = TESTS[test]; if (!T) throw httpErr(400, 'test must be one of: ' + Object.keys(TESTS).join(', '));
    const p = T.params(body(p0 || {})).done();
    if (test === 'filter') p.conditions = p.conditions.map((c, i) => { const x = body(c && typeof c === 'object' ? c : {}).str('field', { required: true, max: 60 }).oneOf('op', L.OPS, { required: true }).str('value', { max: 200 }).done(); if (!['blank', 'not_blank'].includes(x.op) && (x.value === undefined || x.value === '')) throw httpErr(400, 'conditions[' + i + '].value is required for ' + x.op); return x; });
    if (test === 'stratify') p.bands = p.bands.map((v, i) => { if (typeof v !== 'number' || !Number.isFinite(v)) throw httpErr(400, 'bands[' + i + '] must be a number'); return v; });
    if (test === 'age') p.buckets = p.buckets.map((v, i) => { if (!Number.isInteger(v) || v < 1 || v > 3650) throw httpErr(400, 'buckets[' + i + '] must be days (1-3650)'); return v; });
    const d = load(dsId); let o = null;
    if (T.needsOther) { if (!other) throw httpErr(400, 'other: the second dataset is required' + (test === 'compare' ? ' (the previous period)' : ' (to join with)')); o = load(other); }
    if (o && o.id === d.id) throw httpErr(400, 'other: compare with a different dataset - both sides are ' + d.id);
    const res = test === 'join' ? L.join(d.rows, p, o.rows) : test === 'compare' ? L.compare(d.rows, p, o.rows) : test === 'age' ? L.age(d.rows, p, now()) : L[test](d.rows, p);
    return record({ test, dataset: d, other: o, params: p, result: res, who, script });
  }
  function record({ test, dataset: d, other: o, params, result, who, script, seed }) {
    const id = nextId('AAR-', runs), r = { id, test, dataset: d.id, dataset_name: d.name, other: o ? o.id : null, refs: d.ref || (o && o.ref) ? { dataset: d.ref || null, other: (o && o.ref) || null } : undefined, params, seed: seed || null, by: who.user, role: who.role || '', at: iso(), script: script || null, rows: d.rows.length,
      input_hash: o ? sha(d.hash + '|' + o.hash) : d.hash, result, dispositions: {} };
    r.result_hash = sha(result); runs().put(r);
    audit(who, 'run', id, { test, dataset: d.id, other: r.other, exceptions: result.exceptions_total || 0, script: script || null, input_hash: r.input_hash, result_hash: r.result_hash });
    return Object.assign(rview(r), { result });
  }
  function run(b0, who) {
    person(who);
    const b = body(b0).str('dataset', { required: true, max: 60 }).oneOf('test', Object.keys(TESTS), { required: true }).str('other', { max: 60 }).done();
    return execute(b.dataset, b.test, b0 && b0.params, b.other, who, null);
  }
  function sample(b0, who) {
    person(who);
    const b = body(b0).str('dataset', { required: true, max: 40 }).oneOf('method', ['attribute', 'random', 'mus'], { required: true }).int('size', { min: 1, max: 2000 })
      .int('confidence', { min: 80, max: 99, def: 95 }).num('tolerable', { min: 1, max: 20, def: 5 }).num('expected', { min: 0, max: 19, def: 0 }).str('amount', { max: 60 }).int('seed', { min: 1, max: 2147483647 })
      .rule((x) => (x.method === 'mus' && !x.amount ? 'amount: the monetary field is required for monetary-unit sampling' : x.method !== 'attribute' && x.method !== 'mus' && !x.size ? null : null)).done();
    const d = load(b.dataset), seed = b.seed || crypto.randomInt(1, 2147483647);
    let size = b.size, calc = null;
    if (b.method === 'attribute' || !size) { calc = L.sampleSize({ confidence: b.confidence, tolerable: b.tolerable, expected: b.expected, population: d.rows.length }); size = b.size || calc.size; }
    let picked, summary, extra = {};
    if (b.method === 'mus') { const m = L.mus(d.rows, { amount: b.amount, size }, seed); picked = m.picked.map((q) => q.i); summary = m.summary; extra = { interval: m.interval, start: m.start, total: m.total }; }
    else { picked = L.draw(d.rows.length, size, seed); summary = picked.length + ' of ' + d.rows.length + ' record(s) drawn at random (seed ' + seed + ')'; }
    const ex = picked.map((i) => ({ '#': i + 1, values: d.rows[i], why: 'selected for testing' }));
    const result = Object.assign({ summary: (calc ? calc.why + '. ' : '') + summary, method: b.method, size: picked.length, seed, calc }, extra, { exceptions: ex.slice(0, 2000), exceptions_total: ex.length, kind: 'sample' });
    return record({ test: 'sample', dataset: d, params: { method: b.method, size, confidence: b.confidence, tolerable: b.tolerable, expected: b.expected, amount: b.amount || null }, result, who, seed });
  }
  const mustRun = (id0) => { const r = runs().get(param(id0, 'id')); if (!r) throw httpErr(404, 'no run ' + String(id0).slice(0, 40)); return r; };
  const getRun = (id0) => { const r = mustRun(id0); return Object.assign(rview(r), { result: r.result, dispositions: r.dispositions || {} }); };
  function review(id0, b0, who) {
    person(who); const b = body(b0).str('note', { required: true, max: 1000 }).done(), r = mustRun(id0);
    if (same(r.by, who.user)) throw httpErr(403, 'a run is reviewed by a different person from the one who ran it (four-eyes)');
    if (r.review) throw httpErr(409, 'already reviewed by ' + r.review.by);
    if (sha(r.result) !== r.result_hash) throw httpErr(409, 'the result no longer matches its recorded hash - it cannot be reviewed');
    r.review = { by: who.user, at: iso(), note: b.note }; runs().put(r); audit(who, 'review', r.id, { note: b.note.slice(0, 200) }); return getRun(r.id);
  }
  function dispose(id0, n0, b0, who) {
    person(who); const r = mustRun(id0), b = body(b0).oneOf('decision', DECISIONS, { required: true }).str('note', { required: true, max: 1000 }).done();
    const n = Number(n0); if (!Number.isInteger(n) || n < 0 || n >= (r.result.exceptions || []).length) throw httpErr(400, 'n: no exception ' + String(n0).slice(0, 10) + ' in run ' + r.id);
    const prev = (r.dispositions || {})[n]; r.dispositions = r.dispositions || {}; r.dispositions[n] = { decision: b.decision, note: b.note, by: who.user, at: iso() }; runs().put(r);
    audit(who, 'exception.disposition', r.id + '/' + n, { decision: b.decision, previous: prev ? prev.decision : null }); return r.dispositions[n];
  }
  function toFinding(id0, b0, who) {
    person(who); const r = mustRun(id0);
    const b = body(b0).oneOf('team', Object.keys(TEAMS), { required: true }).str('engagement', { required: true, id: true }).str('owner', { required: true, max: 80 }).str('title', { required: true, max: 200 })
      .str('condition', { max: 4000 }).str('criteria', { required: true, max: 2000 }).str('cause', { required: true, max: 2000 }).str('effect', { required: true, max: 2000 }).str('recommendation', { required: true, max: 2000 }).oneOf('rating', ['high', 'medium', 'low'], { required: true }).done();
    if (r.finding) throw httpErr(409, 'run ' + r.id + ' is already finding ' + r.finding.id);
    const team = app.addons && app.addons[TEAMS[b.team]]; if (!team) throw httpErr(409, 'the ' + b.team + ' audit team is not installed');
    const fl = Object.entries(r.dispositions || {}).filter(([, d]) => d.decision === 'finding').length;
    const condition = b.condition || ((TESTS[r.test] || { name: 'Sample' }).name + ' on ' + r.dataset_name + ' (' + r.rows + ' records, ' + r.input_hash.slice(0, 19) + '...): ' + r.result.summary + '. ' + (r.result.exceptions_total || 0) + ' exception(s), ' + fl + ' confirmed as finding by the auditor. Run ' + r.id + ', re-performable from the analytics log.');
    const f = team.addFinding(b.engagement, { title: b.title, condition, criteria: b.criteria, cause: b.cause, effect: b.effect, recommendation: b.recommendation, rating: b.rating, owner: b.owner }, who);
    r.finding = { id: f.id, team: b.team, engagement: b.engagement, by: who.user, at: iso() }; runs().put(r);
    audit(who, 'finding', r.id, { finding: f.id, team: b.team, engagement: b.engagement, rating: b.rating }); return { run: rview(r), finding: f };
  }
  function exportCsv(id0, who) {
    const r = mustRun(id0), ex = r.result.exceptions || [], keys = [...new Set(ex.flatMap((e) => Object.keys(e.values || {})))].slice(0, 40);
    const q = (v) => { let s = String(v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
    const head = ['run', 'exception', 'row', 'why'].concat(keys, ['decision', 'note', 'by']);
    const data = ex.map((e, n) => { const d = (r.dispositions || {})[n] || {}; return [r.id, n + 1, e['#'], e.why].concat(keys.map((k) => { const v = (e.values || {})[k]; return v != null && typeof v === 'object' ? JSON.stringify(v) : v; }), [d.decision || '', d.note || '', d.by || '']); });
    const lines = [head.map(q).join(',')].concat(data.map((row) => row.map(q).join(',')));
    audit(who, 'export', r.id, { rows: ex.length });
    const title = r.id + ' ' + r.test + ' on ' + r.dataset_name + ' by ' + r.by + ' at ' + r.at + '; input ' + r.input_hash + '; result ' + r.result_hash + '. Indicators for follow-up, not proof of wrongdoing.';
    return { filename: 'audit-analytics-' + r.id + '.csv', csv: '# ' + title + '\n' + lines.join('\n') + '\n',
      // the same rows for Excel (zyb-xlsx.js): the auditee fills decision + note and the file comes back through /dispositions
      xlsx: { filename: 'audit-analytics-' + r.id + '.xlsx', title, columns: head.map((h) => ({ h, t: h === 'exception' || h === 'row' ? 'n' : 's', w: h === 'why' ? 60 : h === 'note' ? 50 : 18 })), rows: data,
        how: 'Fill "decision" (explained / false positive / finding) and "note" for each exception, keep the run and exception columns, and import the file back on the run.' } };
  }
  // the Excel round trip: the exception list comes back with decision + note filled in. Every row is checked against this run (run id,
  // exception number, and the row number it was exported with), so a file for another run - or one whose rows were re-sorted into the
  // wrong exceptions - cannot disposition anything. Each change is recorded like a click on the page.
  function importDispositions(id0, b0, who) {
    person(who); const r = mustRun(id0);
    const b = body(b0).str('csv', { max: 4000000 }).str('xlsx_b64', { max: 11500000 }).str('filename', { max: 200 }).rule((x) => (!x.csv && !x.xlsx_b64 ? 'csv or xlsx_b64: the returned exception file is required' : null)).done();
    const P = b.csv ? parseFile('csv', String(b.csv).replace(/^\uFEFF?#[^\n]*\n/, '')) : parseFile('xlsx', b.xlsx_b64, b.filename);
    const col = (name) => P.fields.find((f) => f.trim().toLowerCase() === name);
    const C = { run: col('run'), ex: col('exception'), row: col('row'), dec: col('decision'), note: col('note') };
    for (const [k, v] of Object.entries(C)) if (!v) throw httpErr(400, 'the file has no "' + ({ run: 'run', ex: 'exception', row: 'row', dec: 'decision', note: 'note' })[k] + '" column - use the file exported from this run');
    const ex = r.result.exceptions || [], out = { applied: 0, unchanged: 0, blank: 0, errors: [] };
    P.rows.forEach((row, i) => {
      const line = i + 2, dec0 = String(row[C.dec] || '').trim().toLowerCase(), note = String(row[C.note] || '').trim();
      if (!dec0 && !note) { out.blank++; return; }
      if (String(row[C.run] || '').trim() !== r.id) { out.errors.push({ line, error: 'run is ' + String(row[C.run] || '(blank)').slice(0, 20) + ', not ' + r.id }); return; }
      const n = Number(row[C.ex]) - 1; if (!Number.isInteger(n) || n < 0 || n >= ex.length) { out.errors.push({ line, error: 'exception ' + String(row[C.ex]).slice(0, 10) + ' is not in this run' }); return; }
      if (String(ex[n]['#']) !== String(row[C.row]).trim()) { out.errors.push({ line, error: 'exception ' + (n + 1) + ' was row ' + ex[n]['#'] + ', the file says ' + String(row[C.row]).slice(0, 10) + ' - the rows were changed' }); return; }
      const decision = DECISION_WORDS[dec0]; if (!decision) { out.errors.push({ line, error: 'decision "' + dec0.slice(0, 30) + '" must be explained, false positive or finding' }); return; }
      if (!note) { out.errors.push({ line, error: 'a note is required with the decision' }); return; }
      const cur = (r.dispositions || {})[n]; if (cur && cur.decision === decision && cur.note === note.slice(0, 1000)) { out.unchanged++; return; }
      r.dispositions = r.dispositions || {}; r.dispositions[n] = { decision, note: note.slice(0, 1000), by: who.user, at: iso(), via: 'file ' + P.format + ' ' + P.hash.slice(0, 19) };
      out.applied++;
      audit(who, 'exception.disposition', r.id + '/' + n, { decision, previous: cur ? cur.decision : null, via: P.format, file_hash: P.hash });
    });
    if (out.applied) runs().put(r);
    audit(who, 'dispositions.import', r.id, { format: P.format, file_hash: P.hash, applied: out.applied, unchanged: out.unchanged, errors: out.errors.length });
    return Object.assign(out, { errors: out.errors.slice(0, 200), run: rview(r) });
  }

  function putScript(b0, who) {
    person(who);
    const b = body(b0).str('id', { id: true }).str('name', { required: true, max: 120 }).str('dataset', { required: true, max: 60 }).list('steps', { required: true, max: 12 }).oneOf('schedule', SCHEDULES, { def: 'none' }).done();
    const steps = b.steps.map((s0, i) => { const s = body(s0 && typeof s0 === 'object' ? s0 : {}).oneOf('test', Object.keys(TESTS), { required: true }).str('other', { max: 60 }).done(); const T = TESTS[s.test];
      let p; try { p = T.params(body(s0.params || {})).done(); } catch (e) { throw httpErr(400, 'steps[' + i + '].' + e.message); } if (T.needsOther && !s.other) throw httpErr(400, 'steps[' + i + '].other is required for ' + s.test);
      return Object.assign({ test: s.test, params: s0.params || {} }, s.other ? { other: s.other } : {}); });
    if (b.schedule === 'on_import' && ![b.dataset].concat(steps.map((x) => x.other || '')).some((ref) => SERIES_REF.test(ref))) throw httpErr(400, 'schedule: on_import needs the script to read a series (latest:<series> / previous:<series>)');
    try { load(b.dataset); } catch (e) { if (!(SERIES_REF.test(b.dataset) && e.status === 409)) throw e; /* a series with no import yet: the script waits for its first period */ }
    const cur = b.id ? scripts().get(b.id) : null; if (b.id && !cur) throw httpErr(404, 'no script ' + b.id);
    const sc = Object.assign({}, cur || { id: nextId('AAS-', scripts), author: who.user, created_at: iso(), version: 0 }, { name: b.name, dataset: b.dataset, steps, schedule: b.schedule, version: ((cur && cur.version) || 0) + 1, edited_by: who.user, edited_at: iso(), approved_by: null, approved_at: null });
    scripts().put(sc); audit(who, cur ? 'script.edit' : 'script.create', sc.id, { name: sc.name, steps: steps.map((s) => s.test), schedule: sc.schedule, version: sc.version, approval_withdrawn: !!(cur && cur.approved_by) });
    return sview(sc);
  }
  function approveScript(id0, who) {
    person(who); const sc = scripts().get(param(id0, 'id')); if (!sc) throw httpErr(404, 'no script ' + String(id0).slice(0, 40));
    if (same(sc.author, who.user) || same(sc.edited_by, who.user)) throw httpErr(403, 'a script is approved by a different person from the one who wrote or last edited it (four-eyes)');
    if (sc.approved_by) throw httpErr(409, 'version ' + sc.version + ' is already approved by ' + sc.approved_by);
    sc.approved_by = who.user; sc.approved_at = iso(); scripts().put(sc); audit(who, 'script.approve', sc.id, { version: sc.version }); return sview(sc);
  }
  function runScript(id0, who) {
    const sc = scripts().get(param(id0, 'id')); if (!sc) throw httpErr(404, 'no script ' + String(id0).slice(0, 40));
    const out = [];
    for (const s of sc.steps) { try { out.push(execute(sc.dataset, s.test, s.params, s.other, who, sc.id + ' v' + sc.version)); } catch (e) { out.push({ test: s.test, error: String(e.message).slice(0, 300) }); } }
    sc.last_run = { at: iso(), by: who.user, runs: out.filter((x) => x.id).map((x) => x.id), errors: out.filter((x) => x.error).length }; sc.last_runs = [sc.last_run].concat(sc.last_runs || []).slice(0, 10); scripts().put(sc);
    audit(who, 'script.run', sc.id, { version: sc.version, runs: sc.last_run.runs.length, errors: sc.last_run.errors });
    return { script: sview(sc), results: out.map((x) => (x.id ? { id: x.id, test: x.test, summary: x.summary, exceptions_total: x.exceptions_total } : x)) };
  }
  const SCHED = { user: 'system:audit-analytics', role: 'operator', ip: '' };
  const daily = guardOf(app, 'audit-analytics.scheduled', () => {
    const t = new Date(now() + 3 * 3600000), day = t.toISOString().slice(0, 10), sunday = t.getUTCDay() === 0, first = t.getUTCDate() === 1;   // Riyadh calendar
    for (const sc of scripts().all((s) => s.approved_by && ['daily', 'weekly', 'monthly'].includes(s.schedule))) {
      if (sc.last_run && String(sc.last_run.at).slice(0, 10) === day && sc.last_run.by === SCHED.user) continue;
      if (sc.schedule === 'weekly' && !sunday) continue;
      if (sc.schedule === 'monthly' && !first) continue;
      try { runScript(sc.id, SCHED); } catch (e) { if (app.log && app.log.every) app.log.every('aa:script:' + sc.id, 3600000, 'warn', 'audit analytics: a scheduled script failed', { script: sc.id, err: String(e.message).slice(0, 200) }); }
    }
  });
  let timer = null;
  function start() { if (timer || app.noTimers || opts.noTimer) return; setTimeout(daily, 90000).unref(); timer = setInterval(daily, 3600000); if (timer.unref) timer.unref(); }

  const K = createIntelKit(app, { key: 'audit-analytics', feature: 'itam.audit-analytics-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: true,
    system: ('You are the audit data analytics advisor to the internal audit, IT audit and cyber security audit teams of ' + ZYB_ORG.name + '. You see the datasets (names, columns, types, row counts), the tests available, and the summaries of runs already made - never the records themselves. Propose which tests to run on which columns and why (duplicates, fuzzy duplicates, gaps, Benford, stratify, ageing, summarize, outliers, join, filter, sampling), explain results in plain language and what an auditor should follow up. Results are indicators, not proof of wrongdoing. You never run a test, conclude an exception or raise a finding: a person does.'),
    tools: [{ name: 'analytics', description: 'Datasets (names, columns, types, rows), the test catalogue, and recent run summaries.', run: async () => { const o = overview();
      return { tests: o.tests.map((t) => t.id + ': ' + t.why), sources: o.sources.map((s) => s.id + ' ' + s.name + ' (' + (s.rows == null ? 'audit trail' : s.rows + ' rows') + ')'), datasets: o.datasets.filter((d) => !d.archived).map((d) => d.id + ' ' + d.name + ' (' + d.rows + ' rows, ' + d.fields + ' columns)'), runs: o.runs.slice(0, 30).map((r) => r.id + ' ' + r.test + ' on ' + r.dataset_name + ': ' + r.summary) }; } },
    { name: 'columns', description: 'The columns of one dataset with their type and field statistics (no record values beyond the five most common per column).', input_schema: { type: 'object', properties: { dataset: { type: 'string', maxLength: 40 } }, required: ['dataset'], additionalProperties: false },
      run: async (inp) => { const d = load(inp.dataset), ty = L.types(d.rows, d.fields), pr = L.profile(d.rows, d.fields, ty); return { dataset: d.name, rows: d.rows.length, columns: pr.map((p) => ({ field: p.field, type: p.type, blanks: p.blanks, distinct: p.distinct, min: p.min, max: p.max })), suggestions: L.suggest(d.fields, ty, pr) }; } }] });

  return { SOURCES, TESTS, overview, datasetView, importCsv, archive, run, sample, getRun, review, dispose, importDispositions, toFinding, exportCsv, putScript, approveScript, runScript: (id, who) => { person(who); return runScript(id, who); }, daily, start, ask: K.ask, aiStatus: K.aiStatus, TOOLS: K.TOOLS };
}

function registerAuditAnalytics(srv, app, X) {
  const op = (fn) => (ctx) => { ctx.need('operator'); return fn(ctx); };   // datasets can hold personal data (PDPL): no viewers
  srv.route('GET', '/audit-analytics', op(() => X.overview()));
  srv.route('GET', '/audit-analytics/datasets/:id', op((ctx) => X.datasetView(ctx.params.id, ctx.who)));
  srv.route('POST', '/audit-analytics/datasets', op((ctx) => X.importCsv(ctx.body, ctx.who)), { maxBody: 12000000 });
  srv.route('POST', '/audit-analytics/datasets/:id/archive', (ctx) => { ctx.need('admin'); return X.archive(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/audit-analytics/run', op((ctx) => X.run(ctx.body, ctx.who)), { maxBody: 16384 });
  srv.route('POST', '/audit-analytics/sample', op((ctx) => X.sample(ctx.body, ctx.who)), { maxBody: 4096 });
  srv.route('GET', '/audit-analytics/runs/:id', op((ctx) => X.getRun(ctx.params.id)));
  srv.route('GET', '/audit-analytics/runs/:id/export', op((ctx) => X.exportCsv(ctx.params.id, ctx.who)));
  srv.route('POST', '/audit-analytics/runs/:id/review', op((ctx) => X.review(ctx.params.id, ctx.body, ctx.who)), { maxBody: 4096 });
  srv.route('POST', '/audit-analytics/runs/:id/exceptions/:n', op((ctx) => X.dispose(ctx.params.id, ctx.params.n, ctx.body, ctx.who)), { maxBody: 4096 });
  srv.route('POST', '/audit-analytics/runs/:id/dispositions', op((ctx) => X.importDispositions(ctx.params.id, ctx.body, ctx.who)), { maxBody: 12000000 });
  srv.route('POST', '/audit-analytics/runs/:id/to-finding', op((ctx) => X.toFinding(ctx.params.id, ctx.body, ctx.who)), { maxBody: 16384 });
  srv.route('POST', '/audit-analytics/scripts', op((ctx) => X.putScript(ctx.body, ctx.who)), { maxBody: 32768 });
  srv.route('POST', '/audit-analytics/scripts/:id/approve', op((ctx) => X.approveScript(ctx.params.id, ctx.who)));
  srv.route('POST', '/audit-analytics/scripts/:id/run', op((ctx) => X.runScript(ctx.params.id, ctx.who)));
  srv.route('GET', '/audit-analytics/ai/status', op(() => X.aiStatus()));
  srv.route('POST', '/audit-analytics/ask', op((ctx) => X.ask(ctx.body, ctx.who)), { maxBody: 8192 });
}

module.exports = { createAuditAnalytics, registerAuditAnalytics, SOURCES, TESTS };
