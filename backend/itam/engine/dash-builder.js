// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const fs = require('node:fs');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * Custom Dashboards ({P} = /api/itam, Home -> Custom Dashboards): people build their own dashboards from widgets over a FIXED
 * catalog of datasets the platform already holds - there is no free query language into the stores, only the catalog below:
 *   assets    every active asset with its coverage controls (Coverage & Query): type, site, criticality, os, owner, sources, EDR,
 *             edr / patch / backup / vuln_scan / siem_logs / monitoring states, gaps, priority. Filter = the Coverage & Query language.
 *   vulns     open vulnerability findings (Greenbone, Tenable, FireCompass): severity, tool, host, title, cve, cvss
 *   software  installed software rolled up: product, publisher, version, installs
 *   sources   the platform's sources and their state (Platform Map)
 * A widget = {title, dataset, q, viz, group_by?, good_q?, target?, limit, size}. viz:
 *   kpi        rows matching q (and, with good_q, the share that also match good_q, against target) - Result / Trend / Target / Current
 *   gauge      0-100 score = share of q rows that match good_q, coloured against target
 *   bar|table|donut   the q rows grouped by group_by, top limit
 *   list       the first limit rows (a table of records)
 *   split      the q rows grouped by group_by, shown as a strip of counts under a big total
 * Query builder: GET /dash/values gives the fields and their real values for a dataset, so the page builds q from picks.
 * MACHINE LEARNING (no AI model): each widget's headline value is recorded once a day; trend = least-squares slope per week over
 * the history (withheld below 3 days), 30-day forecast, "unusual today" when today's value is 3+ standard deviations from its own
 * history (withheld below 7 days). Every result says how many days it rests on.
 * AI (engine/ai-backend.js - the local model or Claude, per AI Engine): describe a widget in words and the model PROPOSES one
 * through a single tool whose input is validated against the catalog; the proposal is returned for a person to add. The model never
 * saves a widget, sees no records (only the catalog of datasets and fields), and its text is untrusted. ai-guard budget, redaction.
 *   GET  /dash/catalog                 viewer    datasets, fields, visualisations, starter template
 *   GET  /dash/boards                  viewer    dashboards: shared ones and your own
 *   GET  /dash/boards/:id              viewer    the dashboard with each widget computed + its ML
 *   POST /dash/boards                  operator  {name, starter?}                                  audited
 *   PUT  /dash/boards/:id              operator  {name?, shared?, widgets[]}  owner or admin       audited
 *   POST /dash/boards/:id/delete       operator  owner or admin                                     audited
 *   POST /dash/preview                 viewer    {widget}  compute one widget (query builder preview)
 *   GET  /dash/values?dataset=&field=  viewer    fields of a dataset, top values of one field
 *   POST /dash/ai/propose              operator  {request}  the AI proposes a widget for you to add   audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DAY = 86400000;
const VIZ = ['kpi', 'gauge', 'bar', 'table', 'donut', 'list', 'split'];
const GROUPED = { bar: 1, table: 1, donut: 1, split: 1 };
const low = (v) => String(v == null ? '' : v).toLowerCase().trim();
const s = (v, n) => String(v == null ? '' : v).slice(0, n);
const SEV = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

// fields per dataset: get(row) -> value (string | number | array of strings); num = numeric comparisons allowed
const CONTROLS = ['edr', 'patch', 'backup', 'vuln_scan', 'siem_logs', 'monitoring'];
const F = {
  assets: Object.assign({
    type: { get: (r) => r.type }, site: { get: (r) => r.site || 'Unassigned' }, criticality: { get: (r) => r.criticality }, os: { get: (r) => r.os || 'unknown' },
    os_family: { get: (r) => { const o = low(r.os); return /windows/.test(o) ? 'Windows' : /linux|red ?hat|ubuntu|centos|oracle linux|suse|debian/.test(o) ? 'Linux' : /mac ?os|darwin/.test(o) ? 'macOS' : /solaris|aix|hp-ux/.test(o) ? 'Unix' : o ? 'Other' : 'unknown'; } },
    owner: { get: (r) => r.owner || '(none)' }, department: { get: (r) => r.department || '(none)' }, status: { get: (r) => r.status }, vendor: { get: (r) => r.vendor || 'unknown' },
    edr_product: { get: (r) => r.edr_product || '(none)' }, source: { get: (r) => r.sources || [] }, gaps: { get: (r) => r.gaps, num: true }, priority: { get: (r) => r.priority, num: true },
  }, Object.fromEntries(CONTROLS.map((k) => [k, { get: (r) => (r.controls && r.controls[k] ? r.controls[k].state : 'na') }]))),
  vulns: { severity: { get: (r) => r.severity }, tool: { get: (r) => r.tool }, host: { get: (r) => r.host || 'unknown' }, title: { get: (r) => r.title }, cve: { get: (r) => r.cves }, cvss: { get: (r) => r.cvss, num: true } },
  software: { product: { get: (r) => r.product }, publisher: { get: (r) => r.publisher || 'unknown' }, version: { get: (r) => r.version || 'unknown' }, installs: { get: (r) => r.installs, num: true } },
  sources: { label: { get: (r) => r.label }, state: { get: (r) => r.state } },
};
const DATASETS = { assets: 'Assets (with security coverage)', vulns: 'Vulnerability findings (open)', software: 'Installed software', sources: 'Platform sources' };
const LABEL_FIELD = { assets: 'name', vulns: 'title', software: 'product', sources: 'label' };

// the query language of the non-asset datasets (assets use Coverage & Query's, so the two pages agree): field:a,b  field~text
// -field:x  field>n  a bare word searches the record's name / title
function parseQ(q0, dataset) {
  const q = String(q0 == null ? '' : q0).trim(); if (q.length > 500) throw httpErr(400, 'q is longer than 500 characters');
  if (/[\u0000-\u001f\u007f]/.test(q)) throw httpErr(400, 'q contains control characters');
  if (dataset === 'assets') { const AC = require('./asset-coverage'); return { assets: AC.parseQuery(q) }; }
  const terms = [], fields = F[dataset];
  for (const t of q.match(/-?[A-Za-z_]+(?:!:|:|~|>=|<=|>|<)(?:"[^"]*"|\S+)|"[^"]*"|\S+/g) || []) {
    const m = /^(-?)([A-Za-z_]+)(!:|:|~|>=|<=|>|<)(.*)$/.exec(t);
    if (!m) { terms.push({ word: low(t.replace(/^"|"$/g, '')) }); continue; }
    const f = low(m[2]), op = m[3], raw = m[4].replace(/^"|"$/g, '');
    if (!fields[f]) throw httpErr(400, 'q: unknown field "' + s(f, 30) + '" for ' + dataset + ' - fields: ' + Object.keys(fields).join(', '));
    if (/[<>]/.test(op) && (!fields[f].num || !/^\d+(\.\d+)?$/.test(raw))) throw httpErr(400, 'q: ' + f + op + ' needs a number field and a number');
    terms.push({ f, op, neg: m[1] === '-' || op === '!:', vals: /[<>]/.test(op) ? [Number(raw)] : raw.split(',').map(low).filter(Boolean) });
  }
  if (terms.length > 20) throw httpErr(400, 'q has more than 20 terms');
  return { terms };
}
function match(r, P, dataset) {
  if (P.assets) return require('./asset-coverage').matches(r, P.assets);
  for (const t of P.terms) {
    let hit;
    if (t.word != null) hit = low(r[LABEL_FIELD[dataset]]).includes(t.word) || low(r.host).includes(t.word);
    else {
      const v = F[dataset][t.f].get(r), vs = (Array.isArray(v) ? v : [v]).map(low);
      if (/[<>]/.test(t.op)) { const n = Number(v); hit = Number.isFinite(n) && (t.op === '>' ? n > t.vals[0] : t.op === '<' ? n < t.vals[0] : t.op === '>=' ? n >= t.vals[0] : n <= t.vals[0]); }
      else if (t.op === '~') hit = t.vals.some((p) => vs.some((x) => x.includes(p)));
      else hit = t.vals.some((p) => vs.includes(p));
    }
    if (t.neg ? hit : !hit) return false;
  }
  return true;
}

function validateWidget(w0, i) {
  const at = i == null ? 'widget' : 'widgets[' + i + ']';
  if (!w0 || typeof w0 !== 'object' || Array.isArray(w0)) throw httpErr(400, at + ' must be an object');
  let w; try {
    w = body(w0).str('id', { max: 40, re: /^w-[a-z0-9]{1,30}$/, msg: at + '.id has an invalid format' }).str('title', { required: true, max: 80 }).oneOf('dataset', Object.keys(DATASETS), { required: true })
      .str('q', { max: 500, def: '' }).oneOf('viz', VIZ, { required: true }).str('group_by', { max: 40 }).str('good_q', { max: 500 }).int('target', { min: 0, max: 100 })
      .int('limit', { min: 1, max: 20, def: 5 }).int('size', { min: 1, max: 3, def: 1 }).done();
  } catch (e) { throw httpErr(400, at + ': ' + e.message); }
  if (GROUPED[w.viz] && (!w.group_by || !F[w.dataset][w.group_by])) throw httpErr(400, at + '.group_by is required for ' + w.viz + ' - one of: ' + Object.keys(F[w.dataset]).join(', '));
  if (w.group_by && !F[w.dataset][w.group_by]) throw httpErr(400, at + '.group_by: unknown field "' + s(w.group_by, 30) + '" for ' + w.dataset);
  if (w.viz === 'gauge' && !w.good_q) throw httpErr(400, at + '.good_q is required for a gauge: which of the rows count as good');
  parseQ(w.q, w.dataset); if (w.good_q) parseQ(w.good_q, w.dataset);
  if (!w.id) w.id = 'w-' + Math.random().toString(36).slice(2, 10);
  return w;
}

// the screenshot's layout, on this platform's own data
const STARTER = [
  { title: 'Endpoint protection installed', dataset: 'assets', q: 'edr:present,weak,missing', viz: 'kpi', good_q: 'edr:present', target: 98, size: 1 },
  { title: 'Overall security coverage score', dataset: 'assets', q: 'gaps>=0 -type:printer,phone,ups', viz: 'gauge', good_q: 'gaps<1', target: 90, size: 1 },
  { title: 'Device discovery by source', dataset: 'assets', q: '', viz: 'table', group_by: 'source', limit: 8, size: 1 },
  { title: 'Total unique devices', dataset: 'assets', q: '', viz: 'split', group_by: 'os_family', limit: 5, size: 1 },
  { title: 'SIEM log sources sending', dataset: 'assets', q: 'siem_logs:present,weak,missing', viz: 'kpi', good_q: 'siem_logs:present', target: 90, size: 1 },
  { title: 'Top vulnerabilities by devices', dataset: 'vulns', q: '', viz: 'table', group_by: 'cve', limit: 6, size: 1 },
  { title: 'Vulnerable software (top 5)', dataset: 'vulns', q: '', viz: 'bar', group_by: 'title', limit: 5, size: 1 },
  { title: 'Vulnerability status', dataset: 'vulns', q: '', viz: 'split', group_by: 'severity', limit: 5, size: 1 },
  { title: 'Backup protection', dataset: 'assets', q: 'backup:present,weak,missing', viz: 'kpi', good_q: 'backup:present', target: 100, size: 1 },
];

function createDashBuilder(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { every() {}, warn() {} };
  const boards = () => store.collection('dash_boards'), hist = () => store.collection('dash_hist');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'dash.' + action, target, detail }); };
  const isAdmin = (who) => low(who.role) === 'admin';
  const canSee = (b, who) => b.shared || low(b.owner) === low(who.user) || isAdmin(who);
  const canEdit = (b, who) => low(b.owner) === low(who.user) || isAdmin(who);

  // ---- datasets ----
  async function rowsOf(dataset) {
    if (dataset === 'assets') {
      const AC = app.addons && app.addons.assetCoverage;
      if (AC && AC._build) return (await AC._build()).rows;
      return store.collection('assets').all((a) => !['retired', 'disposed'].includes(a.status)).map((a) => ({ id: a.id, name: a.name || a.id, type: a.type, site: a.site, os: a.os, owner: a.owner, criticality: a.criticality || 'unrated', sources: (a.sources || []).map((x) => x.source), controls: {}, gaps: 0, priority: 0 }));
    }
    if (dataset === 'vulns') {
      const out = [];
      for (const f of store.collection('vulnscan_findings').all((x) => x.status !== 'fixed')) out.push({ title: s(f.name || f.title || f.nvt || 'finding', 160), severity: low(f.severity) || 'unknown', tool: 'Greenbone', host: f.host || '', cves: f.cves || (f.cve ? [f.cve] : []), cvss: f.score != null ? f.score : f.cvss });
      for (const f of store.collection('fc_findings').all((x) => x.seen_in_latest !== false && !(x.decision && x.decision.state === 'approved'))) out.push({ title: s(f.title, 160), severity: low(f.severity) || 'unknown', tool: f.vendor === 'tenable' ? 'Tenable' : 'FireCompass', host: f.host || f.asset || '', cves: f.cves || [], cvss: f.cvss });
      return out.map((r) => Object.assign(r, { severity: SEV.includes(r.severity) ? r.severity : 'unknown', cves: (r.cves || []).length ? r.cves : ['(no CVE)'] }));
    }
    if (dataset === 'software') {
      const m = new Map();
      for (const a of store.collection('assets').all((x) => !['retired', 'disposed'].includes(x.status))) for (const sw of a.software || []) {
        const name = s(sw && (sw.name || sw), 160); if (!name) continue; const k = low(name) + '|' + low(sw.version);
        const e = m.get(k) || { product: name, publisher: s(sw.publisher, 120), version: s(sw.version, 60), installs: 0 }; e.installs++; m.set(k, e);
      }
      return [...m.values()];
    }
    const PM = app.addons && app.addons.platformMap; return PM ? PM.view().sources : [];
  }
  function groupCount(rows, dataset, field, limit) {
    const g = F[dataset][field], m = new Map();
    for (const r of rows) { const v = g.get(r); for (const x of (Array.isArray(v) ? v : [v])) { const k = x == null || x === '' ? '(none)' : String(x); m.set(k, (m.get(k) || 0) + 1); } }
    const all = [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    return { groups: all.slice(0, limit).map(([key, count]) => ({ key, count })), distinct: all.length };
  }
  async function compute(w, cache) {
    const rows = cache[w.dataset] || (cache[w.dataset] = await rowsOf(w.dataset));
    const P = parseQ(w.q, w.dataset), base = rows.filter((r) => match(r, P, w.dataset)), out = { total: base.length };
    if (w.good_q) { const G = parseQ(w.good_q, w.dataset), good = base.filter((r) => match(r, G, w.dataset)).length; out.good = good; out.pct = base.length ? Math.round(1000 * good / base.length) / 10 : null; }
    if (w.target != null && out.pct != null) out.on_target = out.pct >= w.target;
    if (GROUPED[w.viz]) Object.assign(out, groupCount(base, w.dataset, w.group_by, w.limit));
    if (w.viz === 'list') out.rows = base.slice(0, w.limit).map((r) => Object.fromEntries([[LABEL_FIELD[w.dataset], r[LABEL_FIELD[w.dataset]]]].concat(Object.keys(F[w.dataset]).slice(0, 4).map((f) => { const v = F[w.dataset][f].get(r); return [f, Array.isArray(v) ? v.slice(0, 3).join(', ') : v]; }))));
    out.headline = w.viz === 'gauge' || (w.viz === 'kpi' && out.pct != null) ? out.pct : out.total;
    return out;
  }
  // ---- machine learning on each widget's own daily history ----
  function ml(boardId, w, value) {
    const day = new Date(now()).toISOString().slice(0, 10), id = boardId + '|' + w.id + '|' + day;
    if (value != null && !hist().get(id)) hist().put({ id, board: boardId, widget: w.id, day, value });
    const pts = hist().all((h) => h.board === boardId && h.widget === w.id).sort((a, b) => a.day.localeCompare(b.day)).slice(-120);
    const n = pts.length, res = { days: n };
    if (n >= 2) { const prev = pts[n - 2].value; res.change = value != null && prev != null ? Math.round((value - prev) * 10) / 10 : null; res.direction = res.change > 0 ? 'up' : res.change < 0 ? 'down' : 'flat'; }
    if (n < 3) { res.note = 'trend withheld - ' + n + ' day(s) recorded, 3 needed'; return res; }
    const xs = pts.map((p) => (Date.parse(p.day) - Date.parse(pts[0].day)) / DAY), ys = pts.map((p) => Number(p.value) || 0), mx = xs.reduce((a, b) => a + b, 0) / n, my = ys.reduce((a, b) => a + b, 0) / n;
    const sxx = xs.reduce((a, x) => a + (x - mx) * (x - mx), 0), slope = sxx ? xs.reduce((a, x, i) => a + (x - mx) * (ys[i] - my), 0) / sxx : 0;
    res.per_week = Math.round(slope * 7 * 10) / 10; res.forecast_30d = Math.round((my + slope * (xs[n - 1] + 30 - mx)) * 10) / 10;
    if (n >= 7) { const hy = ys.slice(0, -1), hm = hy.reduce((a, b) => a + b, 0) / hy.length, sd = Math.sqrt(hy.reduce((a, b) => a + (b - hm) * (b - hm), 0) / hy.length);
      res.z = sd ? Math.round(((ys[n - 1] - hm) / sd) * 10) / 10 : 0; res.unusual = Math.abs(res.z) >= 3; } else res.note = 'unusual-day check withheld - ' + n + ' days recorded, 7 needed';
    return res;
  }

  // ---- routes' logic ----
  function catalog() {
    return { datasets: Object.entries(DATASETS).map(([id, label]) => ({ id, label, fields: Object.entries(F[id]).map(([f, d]) => ({ id: f, numeric: !!d.num })) })), viz: VIZ, starter: STARTER,
      grammar: 'field:a,b (any of) · field~text (contains) · -field:x (not) · field>n · a bare word searches the name' };
  }
  function list(who) { return { boards: boards().all((b) => canSee(b, who)).sort((a, b) => String(a.name).localeCompare(String(b.name))).map((b) => ({ id: b.id, name: b.name, owner: b.owner, shared: b.shared, widgets: (b.widgets || []).length, can_edit: canEdit(b, who) })) }; }
  async function board(id, who) {
    param(id, 'id'); const b = boards().get(id); if (!b || !canSee(b, who)) throw httpErr(404, 'no dashboard "' + s(id, 40) + '"');
    const cache = {}, widgets = [];
    for (const w of b.widgets || []) { let data; try { data = await compute(w, cache); } catch (e) { data = { error: s(e.message, 200) }; if (!e.status) L.every('dash.compute', 600000, 'warn', 'dashboard: a widget could not be computed', { board: id, err: s(e.message, 200) }); }
      widgets.push(Object.assign({}, w, { data, ml: data.error ? null : ml(id, w, data.headline) })); }
    return { id: b.id, name: b.name, owner: b.owner, shared: b.shared, can_edit: canEdit(b, who), updated_at: b.updated_at, widgets, generated_at: new Date(now()).toISOString() };
  }
  function create(input, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person creates a dashboard');
    const b = body(input).str('name', { required: true, max: 60 }).bool('starter', { def: false }).bool('shared', { def: true }).done();
    if (boards().all().length >= 50) throw httpErr(409, 'at most 50 dashboards - delete one first');
    const rec = { id: 'db-' + now().toString(36) + Math.random().toString(36).slice(2, 5), name: b.name, owner: who.user, shared: b.shared, widgets: b.starter ? STARTER.map((w, i) => validateWidget(Object.assign({}, w), i)) : [], created_at: new Date(now()).toISOString(), updated_at: new Date(now()).toISOString() };
    boards().put(rec); audit(who, 'create', rec.id, { name: rec.name, starter: b.starter, widgets: rec.widgets.length }); return { board: { id: rec.id, name: rec.name } };
  }
  function update(id, input, who) {
    param(id, 'id'); const cur = boards().get(id); if (!cur || !canSee(cur, who)) throw httpErr(404, 'no dashboard "' + s(id, 40) + '"');
    if (!canEdit(cur, who)) throw httpErr(403, 'only ' + cur.owner + ' or an administrator can change this dashboard');
    const b = body(input).str('name', { max: 60 }).bool('shared').list('widgets', { max: 24 }).done();
    const widgets = b.widgets ? b.widgets.map((w, i) => validateWidget(w, i)) : cur.widgets;
    const rec = Object.assign({}, cur, { name: b.name || cur.name, shared: b.shared == null ? cur.shared : b.shared, widgets, updated_at: new Date(now()).toISOString(), updated_by: who.user });
    boards().put(rec); audit(who, 'update', id, { name: rec.name, shared: rec.shared, widgets: widgets.map((w) => ({ title: w.title, dataset: w.dataset, viz: w.viz })) }); return { board: { id, name: rec.name } };
  }
  function remove(id, who) {
    param(id, 'id'); const cur = boards().get(id); if (!cur || !canSee(cur, who)) throw httpErr(404, 'no dashboard "' + s(id, 40) + '"');
    if (!canEdit(cur, who)) throw httpErr(403, 'only ' + cur.owner + ' or an administrator can delete this dashboard');
    boards().remove(id); for (const h of hist().all((x) => x.board === id)) hist().remove(h.id); audit(who, 'delete', id, { name: cur.name }); return { deleted: id };
  }
  async function preview(input) { const w = validateWidget((input || {}).widget); return { widget: w, data: await compute(w, {}) }; }
  async function values(dataset, field) {
    if (!DATASETS[dataset]) throw httpErr(400, 'dataset must be one of: ' + Object.keys(DATASETS).join(', '));
    const out = { dataset, fields: Object.entries(F[dataset]).map(([f, d]) => ({ id: f, numeric: !!d.num })) };
    if (field) { if (!F[dataset][field]) throw httpErr(400, 'field: unknown field "' + s(field, 30) + '" for ' + dataset); if (!F[dataset][field].num) out.values = groupCount(await rowsOf(dataset), dataset, field, 30).groups; }
    return out;
  }

  // ---- AI: propose a widget, a person adds it ----
  const cfgA = (app.config && app.config.ai) || {}, dc = (app.config && app.config.discovery) || {};
  const getKey = opts.getKey || (() => { try { return require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'anthropic_api_key', dc.vault_key_file)() || process.env.ANTHROPIC_API_KEY || ''; } catch (e) { return process.env.ANTHROPIC_API_KEY || ''; } });
  let Ctor = null;
  function loadSdk() { if (opts.sdk) return opts.sdk; if (Ctor) return Ctor; for (const p of [cfgA.sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', require('path').join(__dirname, 'ai-sdk-shim.js')].filter(Boolean)) { try { if (p.startsWith('/') && !fs.existsSync(p)) continue; const m = require(p); Ctor = require('./ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { Ctor = null; /* next location */ } } return null; }
  function aiStatus() {
    let ok = false; try { ok = !!(app.settings && require('./ai-backend').allowed(app.settings.get())); } catch (e) { ok = false; /* settings unreadable = not allowed */ }
    if (!ok) return { enabled: false, reason: 'AI is not available: external AI is not allowed in Settings, or the AI engine is switched off (Platform Administration -> AI Engine)' };
    if (!getKey()) return { enabled: false, reason: 'no AI key and no local model set (Platform Administration -> AI Engine)' };
    if (!loadSdk()) return { enabled: false, reason: 'the AI client is not installed' };
    return { enabled: true, model: cfgA.model || 'claude-opus-5-5' };
  }
  const TOOL = { name: 'propose_widget', description: 'Propose ONE dashboard widget over the catalog. Only the datasets and fields listed in the system prompt exist.',
    input_schema: { type: 'object', additionalProperties: false, required: ['title', 'dataset', 'viz'], properties: {
      title: { type: 'string' }, dataset: { type: 'string', enum: Object.keys(DATASETS) }, q: { type: 'string' }, viz: { type: 'string', enum: VIZ }, group_by: { type: 'string' },
      good_q: { type: 'string' }, target: { type: 'integer' }, limit: { type: 'integer' }, why: { type: 'string' } } } };
  async function propose(input, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person asks for a widget');
    const b = body(input).str('request', { required: true, min: 5, max: 600 }).done();
    const st = aiStatus(); if (!st.enabled) throw httpErr(424, st.reason);
    const G = require('./ai-guard'), bud = G.sharedBudget({ log: L, limits: () => ((app.config && app.config.ai) || {}).limits || {} });
    const flags = G.injectionSignals(b.request), req = G.redactSecrets(b.request);
    const sys = ('You design one dashboard widget for ' + ZYB_ORG.short + '\'s IT and security platform. Datasets and their fields (nothing else exists):\n') +
      Object.entries(F).map(([d, f]) => '- ' + d + ' (' + DATASETS[d] + '): ' + Object.keys(f).join(', ')).join('\n') +
      '\nVisualisations: ' + VIZ.join(', ') + ' (bar, table, donut and split need group_by; gauge needs good_q). Filters use: ' + catalog().grammar +
      '. Asset control fields take present, weak, missing, gap, not_checked, exempt, na. Call propose_widget exactly once; explain in "why" in one sentence. You cannot save anything: a person decides.\n\n' + G.UNTRUSTED_RULE;
    bud.admit(who.user, 'dash.propose', req.length + sys.length);
    const C = loadSdk(), client = new C({ apiKey: getKey(), timeout: (cfgA.timeout_s || 120) * 1000, maxRetries: 1 });
    let resp, usage = {};
    try { resp = await client.messages.create({ model: st.model, max_tokens: 1200, system: sys, tools: [TOOL], tool_choice: { type: 'tool', name: 'propose_widget' }, messages: [{ role: 'user', content: G.untrusted('request', req) }] }); usage = resp.usage || {}; }
    finally { bud.record(who.user, 'dash.propose', usage, flags); }
    const u = (resp.content || []).find((x) => x.type === 'tool_use' && x.name === 'propose_widget');
    if (!u) throw httpErr(422, 'the AI did not propose a widget - describe it again, more concretely');
    const why = s(u.input && u.input.why, 300); const w0 = Object.assign({}, u.input); delete w0.why;
    let w; try { w = validateWidget(w0); } catch (e) { throw httpErr(422, 'the AI proposed a widget that does not fit the catalog (' + e.message + ') - rephrase, or build it in the query builder'); }
    audit(who, 'ai.propose', w.title, { dataset: w.dataset, viz: w.viz, flagged: flags.length > 0 });
    return { proposal: w, why, model: resp.model || st.model, injection_signals: flags, note: 'a proposal: nothing is saved until you add it' };
  }

  if (!(app.noTimers || opts.noTimer)) {
    // one snapshot per widget per day even when nobody opens the dashboard, so the trend has its history
    const tick = guardOf(app, 'dash.snapshot', async () => { for (const b of boards().all()) { await board(b.id, { user: 'system:dash-snapshot', role: 'admin' }); } });
    const t = setInterval(tick, 6 * 3600000); if (t.unref) t.unref();
  }
  return { catalog, list, board, create, update, remove, preview, values, propose, aiStatus, _compute: compute };
}

function registerDashBuilder(srv, app, D0) {
  const D = D0 && D0.catalog ? D0 : createDashBuilder(app, D0 && !D0.catalog ? D0 : {});
  app.addons = app.addons || {}; app.addons.dashBuilder = D;
  srv.route('GET', '/dash/catalog', (ctx) => { ctx.need('viewer'); return Object.assign(D.catalog(), { ai: D.aiStatus() }); });
  srv.route('GET', '/dash/boards', (ctx) => { ctx.need('viewer'); return D.list(ctx.who); });
  srv.route('GET', '/dash/boards/:id', (ctx) => { ctx.need('viewer'); return D.board(ctx.params.id, ctx.who); });
  srv.route('POST', '/dash/boards', (ctx) => { ctx.need('operator'); return D.create(ctx.body, ctx.who); });
  srv.route('PUT', '/dash/boards/:id', (ctx) => { ctx.need('operator'); return D.update(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 65536 });
  srv.route('POST', '/dash/boards/:id/delete', (ctx) => { ctx.need('operator'); return D.remove(ctx.params.id, ctx.who); });
  srv.route('POST', '/dash/preview', (ctx) => { ctx.need('viewer'); return D.preview(ctx.body); }, { anyRole: 'a preview computes a widget over data the viewer may read; nothing is stored' });
  srv.route('GET', '/dash/values', (ctx) => { ctx.need('viewer'); const q = ctx.query || {}; return D.values(q.dataset, q.field); });
  srv.route('POST', '/dash/ai/propose', (ctx) => { ctx.need('operator'); return D.propose(ctx.body, ctx.who); });
  return D;
}
module.exports = { createDashBuilder, registerDashBuilder, validateWidget, parseQ, STARTER, DATASETS };
