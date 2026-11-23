// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SAMA Cyber Security Framework coverage — what the SIEM can evidence, per control, from live data.
 *
 *   loadMap(file?) → map (sama-map.json, validated against sama-catalogue.js; throws listing every problem)
 *   validateMap(map) → errors[]
 *   createSettings({ state, config, map }) → { get(), set(patch, by) }   (state collection "compliance_settings", id "sama")
 *   evaluate(map, evidence, settings) → { summary, controls[] }          (pure)
 *   createSamaCompliance(deps) → { map, settings, evidence({days, force}), summary(q), control(id, q), report(q) }
 *
 * Status per control: n/a (not SIEM-evidenced, owned by GRC) | covered | partial | gap — see sama-map.json "_about".
 * Coverage % = (covered + 0.5 × partial) / SIEM-evidenced controls × 100 (weights: map.scoring).
 * The mapping is a draft to be verified by the the organisation compliance team; reports say so.
 */
const fs = require('node:fs');
const path = require('node:path');
const cat = require('./sama-catalogue');
const { KINDS } = require('./checks');
const { collectEvidence } = require('./evidence');

const MAP_FILE = path.join(__dirname, 'sama-map.json');
const STATUS_RANK = { covered: 0, partial: 1, gap: 2 };
const D = 86400000;
const bad = (msg, errors) => Object.assign(new Error(msg), { code: 400, errors: errors || [msg] });

function validateMap(map) {
  const errs = [];
  if (!map || typeof map !== 'object' || !map.controls) return ['map.controls missing'];
  const classes = map.source_classes || {};
  for (const c of cat.CONTROLS) if (!map.controls[c.ref]) errs.push(`control ${c.ref} (${c.title}) missing from the map`);
  for (const [id, m] of Object.entries(map.controls)) {
    const c = cat.control(id);
    if (!c) { errs.push(`${id}: not a SAMA CSF control id in the catalogue`); continue; }
    if (m.title !== c.title) errs.push(`${id}: title "${m.title}" differs from the catalogue "${c.title}"`);
    if (typeof m.siem_evidenced !== 'boolean') errs.push(`${id}: siem_evidenced must be true or false`);
    if (!m.siem_evidenced) { if (!m.reason) errs.push(`${id}: a not SIEM-evidenced control needs a reason`); continue; }
    if (m.max_status && !(m.max_status in STATUS_RANK)) errs.push(`${id}: invalid max_status ${m.max_status}`);
    if (!Array.isArray(m.checks) || !m.checks.length) { errs.push(`${id}: SIEM-evidenced control needs checks[]`); continue; }
    const ids = new Set();
    for (const k of m.checks) {
      if (!k.id || ids.has(k.id)) errs.push(`${id}: check id missing or duplicate (${k.id})`);
      ids.add(k.id);
      if (!KINDS[k.kind]) errs.push(`${id}/${k.id}: unknown kind "${k.kind}"`);
      if (k.on_fail !== 'gap' && k.on_fail !== 'partial') errs.push(`${id}/${k.id}: on_fail must be gap or partial`);
      if (!k.action) errs.push(`${id}/${k.id}: action (how to close the gap) required`);
      if (k.kind === 'source_class' && !classes[(k.params || {}).class]) errs.push(`${id}/${k.id}: unknown source class "${(k.params || {}).class}"`);
    }
  }
  return errs;
}

function loadMap(file = MAP_FILE) {
  const map = JSON.parse(fs.readFileSync(file, 'utf8'));
  const errs = validateMap(map);
  if (errs.length) throw new Error(`SAMA map invalid (${file}): ${errs.join('; ')}`);
  return map;
}

// ------------------------------------------------------------------ settings
const DEFAULT_CLASSES = ['domain_controllers', 'windows_servers', 'firewall_network', 'microsoft_365'];
const LIST_RE = /^[A-Za-z0-9_.*?\\@$ -]{1,128}$/;
function createSettings({ state, config = {}, map } = {}) {
  const col = state ? state.collection('compliance_settings') : null;
  const base = Object.assign({ required_retention_days: 365, required_source_classes: DEFAULT_CLASSES.slice(), period_days: 30, active_window_h: 24, cache_s: 60,
    dc_hosts: [], known_assets: [], expected_asset_count: 0, vendor_account_patterns: [] }, ((config.compliance || {}).sama) || {});
  delete base.grc_push;
  const classes = Object.keys((map && map.source_classes) || {});
  function get() { const s = col ? col.get('sama') : null; const { id, updated, updated_by, ...rest } = s || {}; return Object.assign({}, base, rest); }
  const intIn = (k, v, lo, hi) => { const n = Number(v); if (!Number.isInteger(n) || n < lo || n > hi) throw bad(`${k} must be an integer ${lo}-${hi}`); return n; };
  const strList = (k, v, max) => {
    if (!Array.isArray(v) || v.length > max) throw bad(`${k} must be an array (max ${max} entries)`);
    const out = v.map((x) => String(x).trim()).filter(Boolean);
    const wrong = out.filter((x) => !LIST_RE.test(x));
    if (wrong.length) throw bad(`${k}: invalid entr${wrong.length > 1 ? 'ies' : 'y'} ${wrong.slice(0, 5).join(', ')}`);
    return [...new Set(out)];
  };
  function set(patch, by) {
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) throw bad('settings object required');
    const next = get(); const errors = [];
    for (const [k, v] of Object.entries(patch)) {
      try {
        if (k === 'required_retention_days') next[k] = intIn(k, v, 1, 36500);
        else if (k === 'period_days') next[k] = intIn(k, v, 1, 400);
        else if (k === 'active_window_h') next[k] = intIn(k, v, 1, 720);
        else if (k === 'expected_asset_count') next[k] = intIn(k, v, 0, 1000000);
        else if (k === 'required_source_classes') {
          const l = strList(k, v, 50); const unknown = l.filter((x) => !classes.includes(x));
          if (unknown.length) throw bad(`required_source_classes: unknown class ${unknown.join(', ')} (known: ${classes.join(', ')})`);
          next[k] = l;
        } else if (k === 'dc_hosts' || k === 'vendor_account_patterns') next[k] = strList(k, v, 200);
        else if (k === 'known_assets') next[k] = strList(k, v, 20000);
        else throw bad(`unknown setting "${k}"`);
      } catch (e) { errors.push(e.message); }
    }
    if (errors.length) throw bad('invalid settings', errors);
    if (col) col.put(Object.assign({ id: 'sama' }, next, { updated: Date.now(), updated_by: by || '' }));
    return get();
  }
  return { get, set, defaults: () => Object.assign({}, base) };
}

// ------------------------------------------------------------------ evaluation (pure)
function evaluate(map, ev, settings) {
  const w = Object.assign({ covered: 1, partial: 0.5, gap: 0 }, map.scoring || {});
  const controls = cat.CONTROLS.map((c) => {
    const m = map.controls[c.ref] || { siem_evidenced: false, reason: 'not in the map' };
    const base = { id: c.ref, title: c.title, domain: c.domain, domain_title: cat.DOMAINS[c.domain], owner: c.owner, siem_evidenced: !!m.siem_evidenced };
    if (!m.siem_evidenced) return Object.assign(base, { status: 'n/a', reasons: [m.reason || 'not SIEM-evidenced — owned by GRC'], checks: [], actions: [] });
    let status = 'covered'; const reasons = []; const actions = [];
    const checks = m.checks.map((k) => {
      let res;
      try { res = KINDS[k.kind](k, { ctrl: c.ref, ev, settings, map }); } catch (e) { res = { pass: null, value: null, reason: `evaluation error: ${e.message}` }; }
      const result = res.pass === true ? 'pass' : res.pass === false ? 'fail' : 'unknown';
      if (result !== 'pass') {
        const st = result === 'unknown' ? 'partial' : k.on_fail;
        if (STATUS_RANK[st] > STATUS_RANK[status]) status = st;
        reasons.push(`${k.title}: ${res.reason}`);
        actions.push({ check: k.id, action: k.action });
        const miss = res.details && Array.isArray(res.details.missing) ? res.details.missing : [];
        for (const t of miss) if (t.action) actions.push({ check: k.id, topic: t.topic, action: t.action });
      }
      return { id: k.id, title: k.title, kind: k.kind, on_fail: k.on_fail, result, value: res.value === undefined ? null : res.value, reason: res.reason, details: res.details || null, action: k.action };
    });
    let capped = false;
    if (m.max_status && STATUS_RANK[status] < STATUS_RANK[m.max_status]) { status = m.max_status; capped = true; reasons.push(`SIEM evidence alone cannot cover this control: ${m.scope || 'the rest is GRC evidence'}`); }
    const tagged = ev.rules.filter((x) => x.sama.includes(c.ref));
    return Object.assign(base, { status, capped, scope: m.scope || '', reasons, checks, actions,
      rules: { tagged: tagged.length, enabled: tagged.filter((x) => x.enabled).length } });
  });
  const counts = { covered: 0, partial: 0, gap: 0, 'n/a': 0 };
  const byDomain = {};
  for (const c of controls) {
    counts[c.status]++;
    const d = byDomain[c.domain] = byDomain[c.domain] || { title: cat.DOMAINS[c.domain], covered: 0, partial: 0, gap: 0, 'n/a': 0 };
    d[c.status]++;
  }
  const evidenced = controls.filter((c) => c.siem_evidenced).length;
  const score = evidenced ? ((counts.covered * w.covered + counts.partial * w.partial + counts.gap * w.gap) / evidenced) * 100 : 0;
  return { summary: { coverage_pct: Math.round(score * 10) / 10, evidenced, total: controls.length, counts, by_domain: byDomain, scoring: w }, controls };
}

// ------------------------------------------------------------------ service
function createSamaCompliance(deps = {}) {
  const map = deps.map || loadMap(deps.mapFile);
  const settings = deps.settings || createSettings({ state: deps.state, config: deps.config || {}, map });
  const now = deps.now || Date.now;
  const cache = new Map();

  async function evidence({ days, force } = {}) {
    const s = settings.get();
    if (days !== undefined && days !== null && days !== '') { const n = Number(days); if (!Number.isInteger(n) || n < 1 || n > 400) throw bad('days must be an integer 1-400'); s.period_days = n; }
    const key = JSON.stringify(s);
    const hit = cache.get(key);
    if (!force && hit && now() - hit.at < (Number(s.cache_s) || 60) * 1000) return { ev: hit.ev, settings: s };
    const ev = await collectEvidence(deps, { map, settings: s, now: now() });
    cache.clear(); cache.set(key, { at: now(), ev });
    return { ev, settings: s };
  }

  const meta = (ev, s) => ({ framework: 'SAMA Cyber Security Framework', catalogue: cat.SOURCE, map_version: map.version, verify_with_compliance_team: true,
    generated_at: new Date(ev.generated_at).toISOString(), period: { from: new Date(ev.period.from).toISOString(), to: new Date(ev.period.to).toISOString(), days: ev.period.days },
    clickhouse: ev.clickhouse, settings: s });

  async function summary(q = {}) {
    const { ev, settings: s } = await evidence({ days: q.days, force: q.refresh === '1' || q.refresh === true });
    const res = evaluate(map, ev, s);
    return Object.assign(meta(ev, s), { summary: res.summary,
      controls: res.controls.map((c) => ({ id: c.id, title: c.title, domain: c.domain, owner: c.owner, siem_evidenced: c.siem_evidenced, status: c.status, capped: !!c.capped,
        reasons: c.reasons, actions: c.actions, rules: c.rules, checks: c.checks.map((k) => ({ id: k.id, title: k.title, result: k.result, value: k.value, reason: k.reason })) })) });
  }

  function detailOf(c, ev) {
    const m = map.controls[c.id] || {};
    const rules = ev.rules.filter((r) => r.sama.includes(c.id));
    const ids = new Set(rules.map((r) => r.id));
    const alerts = (ev._alerts || []).filter((a) => ids.has(a.rule_id));
    const perRule = {}; for (const a of alerts) perRule[a.rule_id] = (perRule[a.rule_id] || 0) + 1;
    const cls = new Set();
    for (const k of m.checks || []) { if (k.kind === 'source_class') cls.add(k.params.class); if (k.kind === 'required_source_classes') for (const n of ev.__required || []) cls.add(n); }
    return {
      contributing_rules: rules.map((r) => ({ id: r.id, name: r.name, enabled: r.enabled, severity: r.severity, mitre: r.mitre, type: r.type, origin: r.origin, alerts_in_period: perRule[r.id] || 0 }))
        .sort((a, b) => b.alerts_in_period - a.alerts_in_period || (a.id < b.id ? -1 : 1)),
      source_classes: [...cls].map((n) => Object.assign({ class: n }, ev.classes[n] || { title: n, present: false })),
      sources: c.id === '3.3.14' ? ev.sources.list : undefined,
      recent_alerts: alerts.slice().sort((a, b) => (b.ts_last || 0) - (a.ts_last || 0)).slice(0, 10)
        .map((a) => ({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, status: a.status, ts_last: a.ts_last, summary: String(a.summary || '').slice(0, 300), case_id: a.case_id || null })),
      alerts_in_period: alerts.length,
    };
  }

  async function control(id, q = {}) {
    if (!cat.has(id)) throw Object.assign(new Error(`unknown SAMA CSF control ${String(id).slice(0, 20)}`), { code: 404 });
    const { ev, settings: s } = await evidence({ days: q.days, force: q.refresh === '1' });
    Object.defineProperty(ev, '__required', { value: s.required_source_classes || [], configurable: true, enumerable: false });
    const c = evaluate(map, ev, s).controls.find((x) => x.id === id);
    return Object.assign(meta(ev, s), { control: Object.assign({}, c, detailOf(c, ev)) });
  }

  async function report(q = {}) {
    const { ev, settings: s } = await evidence({ days: q.days, force: q.refresh === '1' });
    Object.defineProperty(ev, '__required', { value: s.required_source_classes || [], configurable: true, enumerable: false });
    const res = evaluate(map, ev, s);
    return Object.assign(meta(ev, s), { summary: res.summary, controls: res.controls.map((c) => Object.assign({}, c, c.siem_evidenced ? detailOf(c, ev) : {})),
      evidence_overview: { sources: { configured: ev.sources.configured, active: ev.sources.active, silent: ev.sources.silent.length }, hosts_reporting: ev.hosts.count,
        retention: ev.retention, detector: ev.detector, alerts: Object.assign({}, ev.alerts, { escalation: undefined }), cases: ev.cases, intel: ev.intel, identity: ev.identity, ueba: ev.ueba, assets: ev.assets } });
  }

  return { map, settings, evidence, summary, control, report, evaluate: (ev, s) => evaluate(map, ev, s || settings.get()) };
}

module.exports = { loadMap, validateMap, createSettings, evaluate, createSamaCompliance, MAP_FILE, D };
