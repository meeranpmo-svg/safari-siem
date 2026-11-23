// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Detection API routes — register(api, deps) with deps = { ch, state, detector, alerts, cases, config, log, search,
 *                                                         intel?, scheduled? }
 *
 *   GET  {P}/rules                    list effective rules ?type=&enabled=true|false&q=&origin=  → {total, items[]}; each item =
 *                                     rule + origin (builtin|custom|sigma) + alerts_24h + noisy (alerts_24h ≥ config.noisy_alerts_per_day,
 *                                     default 20) + stats (live detector / scheduler counters)
 *   GET  {P}/rules/intel              viewer   Alarm Rules Studio (rule-intel.js): per-rule noise, false-positive rate (withheld
 *                                     below 3 closures), bursts, proposed exclusions, overlaps, ATT&CK tactic coverage, next steps
 *   GET  {P}/rules/intel/:id          viewer   one rule's analysis + its recent alerts
 *   POST {P}/rules/assist             operator a person: AI rule assistant {mode: draft|tune, text?, rule_id?} → a DISABLED draft
 *                                     checked by the engine's compiler; never stored (saving is POST /rules, admin)   audited
 *   GET  {P}/rules/:id                one rule (same decoration) + prefilter_query
 *   POST {P}/rules                    admin   {rule} (or the rule itself) — create / update by id (validated by compiling it)
 *   POST {P}/rules/:id/enable         admin   {enabled: true|false} (default true)
 *   POST {P}/rules/:id/disable        admin
 *   POST {P}/rules/:id/delete         admin   custom rule → deleted; built-in → override removed (reset to shipped)
 *   DELETE {P}/rules/:id              admin   same as above
 *   POST {P}/rules/sigma              {yaml, dry_run} → {rule, warnings[], stored}; dry_run: operator, save: admin
 *   POST {P}/rules/import-sigma       admin   multi-document {yaml, enabled? (default false), dry_run?} → {results[], stored[]}
 *   POST {P}/rules/test               operator {rule | rule_id | sigma, from, to, q?, max_events?}
 *                                     → {alerts[], events_scanned, took_ms, truncated, total_alerts, query, stats}
 *                                     (replays the time range through a fresh detector; events fetched with deps.search
 *                                     in pages of 1000, ordered by time)
 *   GET  {P}/detector/stats           detector + scheduled stats
 *   GET  {P}/intel                    IOC list stats            POST {P}/intel/reload   admin
 * {P} = config.api_prefix || '/api/soc'.
 * deps.search(q, fromMs, toMs, {limit, offset, order:'asc'}) → Promise<{rows[], total_estimate?} | rows[]>.
 */
const { createDetector, compileRule, indexKeyOf } = require('./engine');
const { convertSigmaAll } = require('./sigma');
const { loadBuiltinRules, effectiveRules } = require('./ruleset');
const { createScheduled, normScheduledRule } = require('./scheduled');
const { HttpError, wrap, audit, body, timeParam, prefixOf } = require('../soc/routeutil');
const path = require('node:path');
const { createIntelFeeds } = require('./intel-feeds');
const { createRuleIntel } = require('./rule-intel');
const { body: checkBody } = require('../util/check');
const samaCatalogue = require('../compliance/sama-catalogue');

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$/;
const MAX_TEST_EVENTS = 1000000;

function chTimeToMs(v) {
  if (typeof v === 'number') return v;
  if (v === undefined || v === null || v === '') return 0;
  const s = String(v);
  if (/^\d+(\.\d+)?$/.test(s)) return Number(s) < 1e11 ? Math.round(Number(s) * 1000) : Number(s);
  const iso = s.replace(' ', 'T');
  return Date.parse(/[zZ]$|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z');
}

function rowToEvent(r) {
  const ev = Object.assign({}, r);
  ev.ts = chTimeToMs(r.ts);
  ev.rts = chTimeToMs(r.rts);
  if (typeof ev.fields === 'string') { try { ev.fields = JSON.parse(ev.fields); } catch { ev.fields = {}; } }
  if (!ev.fields || typeof ev.fields !== 'object') ev.fields = {};
  return ev;
}

/** Narrowest query we can derive from the rule's mandatory index condition (else '' = everything in range). */
function prefilterQuery(def) {
  let key = null;
  if (def.type === 'sequence' && Array.isArray(def.steps)) {
    const keys = def.steps.map((s) => indexKeyOf(s.match));
    if (keys.every((k) => k && k.field === keys[0].field)) key = { field: keys[0].field, values: [...new Set(keys.flatMap((k) => k.values))] };
  } else key = indexKeyOf(def.match);
  if (!key || !key.values.length) return '';
  const esc = (v) => `"${String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  const parts = key.values.map((v) => `${key.field}:${esc(v)}`);
  return parts.length === 1 ? parts[0] : `(${parts.join(' OR ')})`;
}

function validateRule(def) {
  if (!def || typeof def !== 'object' || Array.isArray(def)) throw new HttpError(400, 'rule object required');
  if (!ID_RE.test(String(def.id || ''))) throw new HttpError(400, 'rule.id must be 2-64 chars [A-Za-z0-9_.:-]');
  try {
    if (def.type === 'scheduled') normScheduledRule(def);
    else compileRule(def);
  } catch (e) { throw new HttpError(400, e.message); }
  const sev = Number(def.severity === undefined ? 2 : def.severity);
  if (!(sev >= 0 && sev <= 4)) throw new HttpError(400, 'severity must be 0-4');
  // optional SAMA CSF control tags (engine/compliance): array of catalogue ids, e.g. ["3.3.5", "3.3.14"]
  if (def.sama !== undefined) {
    if (!Array.isArray(def.sama) || def.sama.length > 32) throw new HttpError(400, 'sama must be an array of SAMA CSF control ids');
    const bad = def.sama.filter((id) => !samaCatalogue.has(id));
    if (bad.length) throw new HttpError(400, `unknown SAMA CSF control id(s): ${bad.map(String).join(', ').slice(0, 200)}`);
  }
}

function register(api, deps) {
  const P = prefixOf(deps);
  const log = deps.log || { info() {}, warn() {}, error() {} };
  const state = deps.state;
  const rulesCol = state.collection('rules');
  const rulesDir = deps.config && deps.config.detect && deps.config.detect.rules_dir;
  const builtins = loadBuiltinRules(rulesDir || undefined);
  const builtinIds = new Set(builtins.map((r) => r.id));

  const current = () => effectiveRules(state, builtins);
  function apply() {
    const all = current();
    let res = null;
    if (deps.detector) res = deps.detector.load(all);
    if (deps.scheduled) deps.scheduled.load(all);
    return res;
  }
  apply();

  function statsById() {
    const m = new Map();
    if (deps.detector) for (const s of deps.detector.stats().rules) m.set(s.id, s);
    if (deps.scheduled) for (const s of deps.scheduled.stats()) m.set(s.id, s);
    return m;
  }
  function findRule(id) {
    const r = current().find((x) => x.id === id);
    if (!r) throw new HttpError(404, `rule ${id} not found`);
    return r;
  }
  function store(def, by, origin) {
    const prev = current().find((x) => x.id === def.id);
    const doc = Object.assign({}, def, {
      version: prev ? (Number(prev.version) || 1) + 1 : Number(def.version) || 1,
      origin: builtinIds.has(def.id) ? 'builtin' : (origin || (prev && prev.origin) || 'custom'),
      updated: Date.now(), updated_by: by || '',
    });
    delete doc.builtin; delete doc.overridden; delete doc.pack_file;
    rulesCol.put(doc);
    const res = apply();
    const err = res && res.errors.find((e) => e.id === def.id);
    const saved = current().find((x) => x.id === def.id);
    return { rule: saved ? Object.assign({}, saved, { origin: saved.builtin ? 'builtin' : saved.origin || 'custom' }) : null, load_error: err ? err.error : null };
  }

  // shared with other route modules (engine/reports/routes.js after-hours alerting toggles): the SAME store/apply path
  // as POST /rules/:id/enable, so a toggle there is an ordinary rule override (visible and resettable in the rule editor).
  deps.ruleAdmin = {
    list: current,
    setEnabled(id, enabled, by) { const r = findRule(id); return store(Object.assign({}, r, { enabled: !!enabled }), by); },
  };

  // ---- list / get
  const originOf = (r) => (r.builtin ? 'builtin' : r.origin || 'custom');
  const noisyPerDay = () => (deps.config && deps.config.noisy_alerts_per_day) || 20;
  function alerts24h() {
    const m = new Map();
    if (!deps.alerts || typeof deps.alerts.all !== 'function') return m;
    const since = Date.now() - 86400000;
    for (const a of deps.alerts.all((x) => x.created >= since && x.source !== 'logrhythm')) m.set(a.rule_id, (m.get(a.rule_id) || 0) + 1);
    return m;
  }
  function decorate(r, st, a24) {
    const n = a24.get(r.id) || 0;
    return Object.assign({}, r, { origin: originOf(r), alerts_24h: n, noisy: n >= noisyPerDay(), stats: st.get(r.id) || null });
  }

  api.route('GET', `${P}/rules`, wrap(deps, null, (ctx) => {
    const q = ctx.query || {};
    const st = statsById();
    const a24 = alerts24h();
    let items = current();
    if (q.type) items = items.filter((r) => (r.type || 'single') === q.type);
    if (q.enabled === 'true') items = items.filter((r) => r.enabled !== false);
    if (q.enabled === 'false') items = items.filter((r) => r.enabled === false);
    if (q.origin) items = items.filter((r) => originOf(r) === q.origin);
    if (q.q) { const s = String(q.q).toLowerCase(); items = items.filter((r) => `${r.id} ${r.name} ${r.description || ''} ${(r.mitre || []).join(' ')}`.toLowerCase().includes(s)); }
    const loadErrors = deps.detector ? deps.detector.stats().load_errors : [];
    return ctx.ok({ total: items.length, items: items.map((r) => decorate(r, st, a24)), load_errors: loadErrors });
  }));

  // ---- Alarm Rules Studio (rule-intel.js): noise, false-positive rate, bursts, proposed exclusions, overlaps, ATT&CK gaps,
  //      AI rule assistant. Registered before /rules/:id so 'intel' / 'assist' are not read as rule ids.
  const RI = createRuleIntel({ rules: current, alerts: deps.alerts, detector: deps.detector, config: deps.config, log, now: deps.now, sdk: deps.sdk });
  api.route('GET', `${P}/rules/intel`, wrap(deps, null, (ctx) => ctx.ok(Object.assign(RI.view(), { ai: RI.aiStatus() }))));
  api.route('GET', `${P}/rules/intel/:id`, wrap(deps, null, (ctx) => {
    const p = checkBody(ctx.params || {}).str('id', { required: true, max: 64, re: ID_RE, msg: 'id must be a rule id' }).done();
    try { return ctx.ok(RI.ruleView(p.id)); } catch (e) { if (e.status) throw new HttpError(e.status, e.message); throw e; }
  }));
  api.route('POST', `${P}/rules/assist`, wrap(deps, 'operator', async (ctx) => {
    const b = checkBody(body(ctx)).oneOf('mode', ['draft', 'tune'], { required: true }).str('text', { max: 2000 }).str('rule_id', { max: 64, re: ID_RE, msg: 'rule_id must be a rule id' }).done();
    if (b.mode === 'draft' && !b.text) throw new HttpError(400, 'text: describe what the rule should detect');
    if (b.mode === 'tune' && !b.rule_id) throw new HttpError(400, 'rule_id: which rule to tune');
    let r;
    try { r = await RI.assist({ user: ctx.user, role: ctx.role }, b); } catch (e) { if (e.status) throw new HttpError(e.status, e.message); throw e; }
    audit(ctx, 'rule.assist', b.rule_id || (r.rule && r.rule.id) || '-', { mode: b.mode, ok: r.ok, compile_error: r.compile_error || null, tokens: r.usage ? (r.usage.input_tokens || 0) + (r.usage.output_tokens || 0) : 0 });
    return ctx.ok(r);
  }));

  api.route('GET', `${P}/rules/:id`, wrap(deps, null, (ctx) => {
    const r = findRule(ctx.params.id);
    return ctx.ok(Object.assign(decorate(r, statsById(), alerts24h()), { prefilter_query: r.type === 'scheduled' ? r.query : prefilterQuery(r) }));
  }));

  // ---- create / update
  api.route('POST', `${P}/rules`, wrap(deps, 'admin', (ctx) => {
    const def = body(ctx).rule || body(ctx);
    validateRule(def);
    const res = store(def, ctx.user);
    audit(ctx, 'rule.upsert', def.id, { version: res.rule && res.rule.version, enabled: def.enabled !== false });
    return ctx.ok(res);
  }));

  // POST /rules/:id/enable {enabled: true|false} (default true);  /disable = {enabled:false}
  const toggle = (fixed) => wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const enabled = fixed !== undefined ? fixed : !(b.enabled === false || b.enabled === 'false');
    const r = findRule(ctx.params.id);
    const def = Object.assign({}, r, { enabled });
    const res = store(def, ctx.user);
    audit(ctx, enabled ? 'rule.enable' : 'rule.disable', r.id, { enabled });
    return ctx.ok(res);
  });
  api.route('POST', `${P}/rules/:id/enable`, toggle(undefined));
  api.route('POST', `${P}/rules/:id/disable`, toggle(false));

  const del = wrap(deps, 'admin', (ctx) => {
    const id = ctx.params.id;
    const stored = rulesCol.get(id);
    if (!stored && builtinIds.has(id)) throw new HttpError(409, `${id} is a built-in rule without changes — disable it instead`);
    if (!stored) throw new HttpError(404, `rule ${id} not found`);
    rulesCol.remove(id);
    apply();
    const reset = builtinIds.has(id);
    audit(ctx, reset ? 'rule.reset' : 'rule.delete', id, {});
    return ctx.ok({ id, deleted: !reset, reset_to_builtin: reset });
  });
  api.route('POST', `${P}/rules/:id/delete`, del);
  api.route('DELETE', `${P}/rules/:id`, del);

  // ---- Sigma (portal): POST /rules/sigma {yaml, dry_run, enabled?, id?} → {rule, warnings[], stored}
  //      one Sigma document; dry_run (operator) converts without saving, saving needs admin.
  //      Conversion problems → 400 {error, errors:[…]} (unsupported constructs are named explicitly).
  api.route('POST', `${P}/rules/sigma`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx);
    const dry = b.dry_run === true || b.dry_run === 'true';
    if (!dry && typeof ctx.need === 'function' && ctx.need('admin') === false) return undefined;
    if (typeof b.yaml !== 'string' || !b.yaml.trim()) throw new HttpError(400, 'yaml (string) required');
    if (b.yaml.length > 1_000_000) throw new HttpError(413, 'yaml too large');
    const results = convertSigmaAll(b.yaml, { enabled: b.enabled !== undefined ? !!b.enabled : true, id: b.id });
    if (results.length !== 1) throw new HttpError(400, `expected exactly one Sigma document, got ${results.length}`, [`expected exactly one Sigma document, got ${results.length}`]);
    const r = results[0];
    if (!r.ok) throw new HttpError(400, 'Sigma rule cannot be converted', r.errors.concat((r.warnings || []).map((w) => `warning: ${w}`)));
    try { compileRule(r.rule); } catch (e) { throw new HttpError(400, 'converted rule does not compile', [e.message]); }
    if (dry) return ctx.ok({ rule: r.rule, warnings: r.warnings, stored: false });
    const res = store(r.rule, ctx.user, 'sigma');
    audit(ctx, 'rule.import-sigma', r.rule.id, { warnings: r.warnings.length, enabled: r.rule.enabled });
    return ctx.ok({ rule: res.rule, warnings: r.warnings, stored: true, load_error: res.load_error });
  }));

  // ---- Sigma bulk import (multi-document YAML): POST /rules/import-sigma {yaml, enabled?, dry_run?} (admin)
  api.route('POST', `${P}/rules/import-sigma`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    if (typeof b.yaml !== 'string' || !b.yaml.trim()) throw new HttpError(400, 'yaml (string) required');
    if (b.yaml.length > 2_000_000) throw new HttpError(413, 'yaml too large');
    const results = convertSigmaAll(b.yaml, { enabled: b.enabled !== undefined ? !!b.enabled : false, id: b.id });
    const out = [];
    for (const r of results) {
      if (!r.ok) { out.push(r); continue; }
      try { compileRule(r.rule); } catch (e) { out.push({ ok: false, errors: [`converted rule does not compile: ${e.message}`], warnings: r.warnings }); continue; }
      if (b.dry_run) { out.push(Object.assign({ stored: false }, r)); continue; }
      const res = store(r.rule, ctx.user, 'sigma');
      out.push(Object.assign({ stored: true, load_error: res.load_error }, r, { rule: res.rule }));
    }
    const stored = out.filter((x) => x.stored).map((x) => x.rule.id);
    audit(ctx, 'rule.import-sigma', stored.join(',') || '-', { documents: results.length, stored: stored.length, dry_run: !!b.dry_run });
    return ctx.ok({ results: out, stored });
  }));

  // ---- test (replay)
  api.route('POST', `${P}/rules/test`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx);
    let def;
    if (b.rule) def = b.rule;
    else if (b.rule_id) def = findRule(String(b.rule_id));
    else if (typeof b.sigma === 'string') {
      const r = convertSigmaAll(b.sigma)[0];
      if (!r || !r.ok) throw new HttpError(400, `sigma: ${(r && r.errors.join('; ')) || 'no document'}`);
      def = r.rule;
    } else throw new HttpError(400, 'rule, rule_id or sigma required');
    def = Object.assign({}, def, { enabled: true, id: def.id || 'TEST' });
    if (!def.name) def.name = def.id;
    validateRule(def);
    if (typeof deps.search !== 'function') throw new HttpError(503, 'search backend not available');
    const to = timeParam(b.to, Date.now());
    const from = timeParam(b.from, to - 3600000);
    if (!(from < to)) throw new HttpError(400, 'from must be before to');
    if (to - from > 31 * 86400000) throw new HttpError(400, 'time range too large (max 31 days)');
    const maxEvents = Math.min(MAX_TEST_EVENTS, Math.max(1, Number(b.max_events) || 200000));
    const t0 = Date.now();
    audit(ctx, 'rule.test', def.id, { from, to });

    if (def.type === 'scheduled') {
      const found = [];
      const sch = createScheduled({ rules: [def], search: deps.search, onAlert: (p) => found.push(p), log });
      const r = await sch.runRule(def.id, to);
      return ctx.ok({ rule_id: def.id, alerts: found, total_alerts: found.length, result: r, took_ms: Date.now() - t0 });
    }

    const found = [];
    const det = createDetector({ rules: [def], onAlert: (p) => found.push(p), log, intel: deps.intel || null, now: () => to });
    const q = typeof b.q === 'string' ? b.q : prefilterQuery(def);
    const page = 1000;
    let offset = 0; let scanned = 0; let truncated = false; let timedOut = false;
    const deadline = t0 + Math.min(120000, Number(b.timeout_ms) || 60000);
    for (;;) {
      const res = await deps.search(q, from, to, { limit: page, offset, order: 'asc' });
      const rows = Array.isArray(res) ? res : (res && res.rows) || [];
      for (const r of rows) { det.onEvent(rowToEvent(r)); scanned++; }
      offset += rows.length;
      if (rows.length < page) break;
      if (scanned >= maxEvents) { truncated = true; break; }
      if (Date.now() > deadline) { timedOut = true; break; }
    }
    det.flush();
    const merged = found.filter((p) => !p.update);
    return ctx.ok({
      rule_id: def.id, query: q, from, to, events_scanned: scanned, truncated, timed_out: timedOut,
      total_alerts: merged.length, updates: found.length - merged.length, alerts: found.slice(0, 500),
      stats: det.stats().rules[0] || null, took_ms: Date.now() - t0,
    });
  }));

  // ---- stats / intel
  api.route('GET', `${P}/detector/stats`, wrap(deps, null, (ctx) => ctx.ok({
    detector: deps.detector ? deps.detector.stats() : null,
    scheduled: deps.scheduled ? deps.scheduled.stats() : [],
  })));
  api.route('GET', `${P}/intel`, wrap(deps, null, (ctx) => {
    if (!deps.intel) return ctx.ok({ enabled: false });
    return ctx.ok({ enabled: true, stats: deps.intel.stats(), lists: deps.intel.lists() });
  }));
  // Email / Phishing Analysis asks which indicator lists hold a message's sender domains, link hosts and origin IP. Only
  // the indicators come here, never the message (it is parsed in the browser). lookup() does not count as a hit.
  // Reference lists (allow-*, internal-*) are returned apart: being on them is not a threat.
  api.route('POST', `${P}/intel/check`, wrap(deps, null, (ctx) => {
    if (!deps.intel) return ctx.ok({ enabled: false, results: {} });
    const v = body(ctx).values;
    if (!Array.isArray(v) || v.length > 200) throw new HttpError(400, 'values: a list of up to 200 indicators');
    const results = {}, reference = {};
    for (const x of v) {
      const s = String(x || '').trim().toLowerCase();
      if (!s || s.length > 300 || results[s] || reference[s]) continue;
      const lists = deps.intel.lookup(s) || [];
      const threat = lists.filter((n) => !/^(allow|internal)-/.test(n)), ref = lists.filter((n) => /^(allow|internal)-/.test(n));
      if (threat.length) results[s] = threat;
      if (ref.length) reference[s] = ref;
    }
    audit(ctx, 'intel.check', 'email-analysis', { values: v.length, matches: Object.keys(results).length });
    return ctx.ok({ enabled: true, checked: v.length, results, reference, loaded_at: (deps.intel.stats() || {}).loaded_at || null });
  }), { anyRole: 'a lookup of indicators against the threat feeds - reads only' });
  // ---- threat-intel feeds (detect/intel-feeds.js): download on a schedule into the intel folder, or upload a list
  const intelDir = (deps.config && deps.config.detect && deps.config.detect.intel_dir) || path.join((deps.config && deps.config.data_dir) || '/var/lib/sentra-siem', 'intel');
  const feeds = deps.intelFeeds || createIntelFeeds({ dir: intelDir, state: deps.state, config: deps.config, log: deps.log, audit: (e) => deps.state && deps.state.audit && deps.state.audit(e),
    secretsPath: deps.config && deps.config._paths && deps.config._paths.secrets });
  if (!deps.intelFeeds) feeds.start();
  const fe = (fn) => async (ctx) => { try { return ctx.ok(await fn(ctx, body(ctx) || {})); } catch (e) { throw new HttpError(Number.isInteger(e.code) ? e.code : 500, e.message); } };
  api.route('GET', `${P}/intel/feeds`, wrap(deps, null, fe(() => ({ items: feeds.list() }))));
  api.route('POST', `${P}/intel/feeds`, wrap(deps, 'admin', fe((ctx, b) => feeds.put(b, ctx.user))));
  api.route('POST', `${P}/intel/feeds/:id/run`, wrap(deps, 'admin', fe(async (ctx) => { const r = await feeds.run(ctx.params.id, ctx.user); if (deps.intel) deps.intel.reload(); return { results: r }; })));
  api.route('DELETE', `${P}/intel/feeds/:id`, wrap(deps, 'admin', fe((ctx) => feeds.remove(ctx.params.id, ctx.user))));
  api.route('POST', `${P}/intel/upload`, wrap(deps, 'admin', fe((ctx, b) => { const r = feeds.upload(b.name, b.text, ctx.user); if (deps.intel) deps.intel.reload(); return r; })), { maxBody: 32 * 1024 * 1024 });
  api.route('POST', `${P}/intel/reload`, wrap(deps, 'admin', (ctx) => {
    if (!deps.intel) throw new HttpError(503, 'intel not configured');
    deps.intel.reload();
    audit(ctx, 'intel.reload', '-', deps.intel.stats());
    return ctx.ok(deps.intel.stats());
  }));

  return { apply, current };
}

module.exports = { register, prefilterQuery, rowToEvent, validateRule };
