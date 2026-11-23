// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * PDPL Intelligence ({P} = /api/itam, PDPL -> PDPL Intelligence): three things a privacy analyst does by hand, done on the
 * registers the PDPL pages already keep - people still decide.
 *
 * 1. Column review that learns. The discovery scans (engine/pdpl.js, pdpl_discovery) flag columns that look like personal
 *    data. Each flagged column gets a probability that it really holds personal data: a naive Bayes model (Laplace-smoothed)
 *    over the column's name tokens, the attribute the scan matched, how it matched (name / sampled values / both), the
 *    sampled match rate and the data type - trained on the columns people have already reviewed here. With fewer than 10
 *    reviews the scan's own evidence sets the probability and the page says the model is not trained yet. Columns are
 *    offered for review most-uncertain first (active learning), so each review teaches the model the most. A review is a
 *    person's decision (confirm / reject, with a note) and survives the next scan; the model never confirms anything.
 * 2. Deadline risk. Every open data subject request against its 30-day answer (60 with a notified extension; Art. 4, IR
 *    Art. 5) and every breach against SDAIA's 72 hours (IR Art. 24). For a request the chance of answering in time comes
 *    from this organisation's own answered requests of the same type that were still open at the same age (empirical,
 *    conditional on the age reached); with fewer than 5 such requests the rules decide (stage, identity check, days left)
 *    and the page says which. A breach is graded by hours left and playbook steps still open.
 * 3. DPIA drafts. For a processing activity that needs an impact assessment (sensitive data, automated decisions,
 *    profiling, monitoring, several sources - IR Art. 25) and has none completed, the necessity, risks and measures are
 *    drafted from the activity's own record (rules, or worded by the AI when an administrator allows external AI; one call
 *    through ai-guard). The DPO named in the PDPL profile - never the person who asked for the draft - approves or returns it;
 *    the assessment itself is still recorded on the DPIA page.
 *
 *   GET  /pdpl/intel                          operator  model, review queue, deadline risk, DPIA candidates, drafts (PDPL records: no viewers)
 *   POST /pdpl/intel/columns/review           operator  {key, decision: personal|not_personal, note}               audited
 *   POST /pdpl/intel/dpia/:ropa/draft         operator  {use_ai?}                                                   audited
 *   POST /pdpl/intel/drafts/:id/decide        operator  {decision: approve|return, note}  the DPO / an admin, not the requester   audited
 *   GET  /pdpl/intel/ai/status                operator
 */
const fs = require('node:fs');
const { body, param } = require('./check');
const G = require('./ai-guard');

const DAY = 86400000, MODEL = 'claude-opus-5-5';
const SENSITIVE = ['health', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const s = (v, n = 200) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, n);
const isService = (u) => !norm(u) || /^(duty|system|core|ai|svc|service|agent|bot)([:._-]|$)/i.test(String(u).trim());
const ms = (v) => { if (!v) return null; const t = Date.parse(/T/.test(v) ? (/Z$|[+-]\d\d:?\d\d$/.test(v) ? v : v + 'Z') : v + 'T00:00:00Z'); return Number.isFinite(t) ? t : null; };
const OPEN_DSR = (r) => !['responded', 'refused', 'withdrawn'].includes(r.stage) && r.status !== 'archived';

/* ---- the column model */
function tokens(name) { return String(name || '').replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 2 && t.length <= 24).slice(0, 8); }
function features(c) {
  const f = tokens(c.column).map((t) => 'tok:' + t);
  f.push('kind:' + (c.kind || 'none'), 'by:' + (c.by || 'unknown'), 'type:' + String(c.type || '').toLowerCase().replace(/[^a-z]/g, '').slice(0, 12));
  if (c.sampled) { const r = (c.matched || 0) / c.sampled; f.push('rate:' + (r >= 0.8 ? 'high' : r >= 0.3 ? 'mid' : 'low')); } else f.push('rate:none');
  return f;
}
// the scan's own evidence, before anyone has reviewed enough columns: matched on sampled values beats matched on the name only
function prior(c) {
  const r = c.sampled ? (c.matched || 0) / c.sampled : null;
  let p = c.by === 'both' ? 0.9 : c.by === 'sample' || c.by === 'value' ? 0.8 : 0.6;
  if (r !== null) p = Math.max(0.05, Math.min(0.97, 0.5 * p + 0.5 * (0.15 + 0.8 * r)));
  return p;
}
function train(rows) {   // rows: [{features, y}] -> model
  const m = { n: [0, 0], f: [new Map(), new Map()], vocab: new Set() };
  for (const r of rows) { const y = r.y ? 1 : 0; m.n[y]++; for (const x of new Set(r.features)) { m.f[y].set(x, (m.f[y].get(x) || 0) + 1); m.vocab.add(x); } }
  return m;
}
function predict(m, feats) {   // log-odds with Laplace smoothing; returns p and the features that moved it most
  const N = m.n[0] + m.n[1], lp = [Math.log((m.n[0] + 1) / (N + 2)), Math.log((m.n[1] + 1) / (N + 2))], why = [];
  for (const x of new Set(feats)) {
    if (!m.vocab.has(x)) continue;
    const l1 = Math.log(((m.f[1].get(x) || 0) + 1) / (m.n[1] + 2)), l0 = Math.log(((m.f[0].get(x) || 0) + 1) / (m.n[0] + 2));
    lp[1] += l1; lp[0] += l0; why.push({ feature: x, weight: Math.round((l1 - l0) * 100) / 100 });
  }
  const p = 1 / (1 + Math.exp(lp[0] - lp[1]));
  return { p, why: why.sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight)).slice(0, 4) };
}

function createPdplIntel(app, PD, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, warn() {}, error() {} };
  const iso = () => new Date(now()).toISOString();
  const reviews = () => store.collection('pdpl_column_review'), drafts = () => store.collection('pdpl_dpia_drafts');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'pdpl.intel.' + action, target, detail }); };
  const person = (who) => { if (!who || isService(who.user)) throw httpErr(403, 'a named person makes this decision - not a service or AI identity'); };
  const profile = () => PD.records('profile')[0] || {};
  const keyOf = (scan, c) => [scan.db, c.owner || '', c.table || '', c.column || ''].join('|').slice(0, 300);
  const rid = (k) => 'COL-' + G.sha256(k).slice(0, 16);   // a route-safe id for a column key

  function columns() {
    const out = [];
    let scans = []; try { scans = store.collection('pdpl_discovery').all((x) => x.id !== '_last'); } catch (e) { scans = []; /* discovery not installed: no columns */ }
    for (const sc of scans) for (const c of sc.columns || []) { const k = keyOf(sc, c); out.push(Object.assign({ key: k, id: rid(k), db: sc.db, label: sc.label || sc.db, engine: sc.engine }, c)); }
    return out;
  }
  function model() {
    const cols = columns(), R = reviews(), byId = new Map(cols.map((c) => [c.id, c]));
    const labelled = R.all(() => true).map((r) => ({ r, c: byId.get(r.id) || r.snapshot })).filter((x) => x.c);
    const m = train(labelled.map((x) => ({ features: features(x.c), y: x.r.decision === 'personal' })));
    const trained = labelled.length >= 10 && m.n[0] >= 2 && m.n[1] >= 2;
    // leave-one-out accuracy on the reviews, so the page can say how good the model is - never a claimed figure
    let correct = 0;
    if (trained) for (const x of labelled) { const rest = train(labelled.filter((y) => y !== x).map((y) => ({ features: features(y.c), y: y.r.decision === 'personal' }))); if ((predict(rest, features(x.c)).p >= 0.5) === (x.r.decision === 'personal')) correct++; }
    const scored = cols.map((c) => {
      const rv = R.get(c.id), pr = prior(c);
      let p = pr, why = [{ feature: 'scan evidence (' + (c.by || 'unknown') + (c.sampled ? ', ' + (c.matched || 0) + '/' + c.sampled + ' sampled values matched' : '') + ')', weight: null }];
      if (trained) { const q = predict(m, features(c)); p = 0.8 * q.p + 0.2 * pr; why = q.why; }
      return { id: c.id, db: c.db, label: c.label, owner: c.owner || '', table: c.table || '', column: c.column || '', type: c.type || '', kind: c.kind || '', category: c.category || '', sensitive: SENSITIVE.includes(c.category),
        rows: c.rows == null ? null : c.rows, by: c.by || '', p: Math.round(p * 1000) / 1000, uncertainty: Math.round((1 - Math.abs(2 * p - 1)) * 1000) / 1000, why, review: rv ? { decision: rv.decision, by: rv.by, at: rv.at, note: rv.note } : null };
    });
    const queue = scored.filter((c) => !c.review).sort((a, b) => (b.uncertainty - a.uncertainty) || (b.sensitive - a.sensitive) || ((b.rows || 0) - (a.rows || 0)));
    return { trained, reviews: labelled.length, personal: m.n[1], not_personal: m.n[0], loo_accuracy: trained ? Math.round(correct / labelled.length * 1000) / 10 : null,
      note: trained ? 'Trained on ' + labelled.length + ' reviews; leave-one-out accuracy ' + Math.round(correct / labelled.length * 1000) / 10 + ' %. The model ranks and suggests; a person decides.' : 'Not trained yet: ' + labelled.length + ' review(s), it needs 10 with at least 2 of each answer. Until then the scan\'s own evidence sets the probability.',
      columns: scored.length, queue: queue.slice(0, 200), reviewed: scored.filter((c) => c.review).slice(0, 200), likely_not_personal: queue.filter((c) => trained && c.p < 0.2).length };
  }
  function review(b0, who) {
    person(who);
    const b = body(b0).str('key', { required: true, max: 40, re: /^COL-[0-9a-f]{16}$/, msg: 'key must be a column id (COL-…)' }).oneOf('decision', ['personal', 'not_personal'], { required: true }).str('note', { required: true, min: 5, max: 1000 }).done();
    const c = columns().find((x) => x.id === b.key); if (!c) throw httpErr(404, 'no scanned column ' + b.key + ' - run the discovery scan first');
    const prev = reviews().get(b.key);
    const rec = { id: b.key, decision: b.decision, note: b.note, by: who.user, at: iso(), snapshot: { column: c.column, owner: c.owner, table: c.table, type: c.type, kind: c.kind, by: c.by, sampled: c.sampled, matched: c.matched, category: c.category, db: c.db } };
    reviews().put(rec);
    audit(who, 'column.review', b.key, { db: c.db, table: c.table, column: c.column, decision: b.decision, previous: prev ? prev.decision : null });   // the column name, never a value
    return rec;
  }

  /* ---- deadline risk */
  function dsarRisk() {
    const all = PD.records('dsr').filter((r) => r.status !== 'archived'), t = now();
    const done = all.filter((r) => r.stage === 'responded' && ms(r.received) && ms(r.responded)).map((r) => ({ type: r.type, d: (ms(r.responded) - ms(r.received)) / DAY }));
    return all.filter(OPEN_DSR).map((r) => {
      const rec = ms(r.received); if (!rec) return null;
      const limit = r.extended ? 60 : 30, age = (t - rec) / DAY, left = limit - age;
      const hist = done.filter((h) => h.type === r.type && h.d >= age);   // answered requests still open at this age
      let p = null, method, why = [];
      if (hist.length >= 5) { p = hist.filter((h) => h.d <= limit).length / hist.length; method = 'history'; why.push(hist.filter((h) => h.d <= limit).length + ' of ' + hist.length + ' earlier ' + r.type + ' requests still open at day ' + Math.floor(age) + ' were answered within ' + limit + ' days'); }
      else {
        method = 'rules'; p = left <= 0 ? 0 : 0.9;
        if (!r.identity_verified && age > 7) { p -= 0.35; why.push('identity still not verified after ' + Math.floor(age) + ' days'); }
        const tasks = r.tasks || [], openT = tasks.filter((x) => x.status === 'open').length;
        if (openT) { p -= Math.min(0.4, 0.08 * openT); why.push(openT + ' system task(s) still open'); }
        if (left < 7 && left > 0) { p -= 0.25; why.push(Math.ceil(left) + ' day(s) left'); }
        p = Math.max(0, Math.min(1, p)); why.unshift('only ' + hist.length + ' comparable answered request(s) - the rules decide');
      }
      const risk = left <= 0 ? 'breached' : p < 0.5 ? 'high' : p < 0.8 ? 'medium' : 'low';
      return { id: r.id, ref: r.ref, type: r.type, stage: r.stage, received: r.received, due: new Date(rec + limit * DAY).toISOString().slice(0, 10), extended: !!r.extended, days_left: Math.round(left * 10) / 10,
        p_on_time: Math.round(p * 100) / 100, risk, method, why, assigned_to: r.assigned_to || null, can_extend: !r.extended && left > 0 };
    }).filter(Boolean).sort((a, b) => ({ breached: 0, high: 1, medium: 2, low: 3 }[a.risk] - { breached: 0, high: 1, medium: 2, low: 3 }[b.risk]) || a.days_left - b.days_left);
  }
  function breachRisk() {
    const t = now();
    return PD.records('breach').filter((b) => b.status !== 'archived' && !b.sdaia_notified_at && ms(b.aware_at)).map((b) => {
      const left = (ms(b.aware_at) + 72 * 3600000 - t) / 3600000, done = Object.keys(b.playbook || {}).length;
      const risk = left <= 0 ? 'breached' : left < 12 || (left < 36 && !done) ? 'high' : left < 48 ? 'medium' : 'low';
      return { id: b.id, ref: b.ref, aware_at: b.aware_at, deadline: new Date(ms(b.aware_at) + 72 * 3600000).toISOString(), hours_left: Math.round(left * 10) / 10, steps_done: done, harm_likely: b.harm_likely === true ? true : b.harm_likely === false ? false : null, risk,
        why: [left <= 0 ? 'the 72 hours have passed without an SDAIA notification - notify now with what is known and record why it was late' : Math.floor(left) + ' hour(s) left to notify SDAIA'].concat(done ? [done + ' playbook step(s) recorded'] : ['no playbook step recorded yet']) };
    }).sort((a, b) => a.hours_left - b.hours_left);
  }

  /* ---- DPIA candidates and drafts */
  function triggers(r) {
    const t = [], sens = (r.data_categories || []).filter((c) => SENSITIVE.includes(c));
    if (sens.length) t.push('sensitive data: ' + sens.join(', '));
    if ((r.data_categories || []).includes('credit')) t.push('credit data');
    for (const [k, l] of [['automated_decision', 'solely automated decisions'], ['automated_underwriting', 'automated underwriting'], ['profiling', 'profiling'], ['fraud_scoring', 'fraud scoring'], ['large_scale_monitoring', 'continuous large-scale monitoring'], ['telematics', 'telematics (location over time)']]) if (r[k] === true) t.push(l);
    if ((r.sources || 0) >= 2) t.push('data linked from ' + r.sources + ' sources');
    return t;
  }
  function candidates() {
    const dpias = PD.records('dpia').filter((d) => d.status !== 'archived');
    return PD.records('ropa').filter((r) => r.status !== 'archived').map((r) => ({ r, t: triggers(r) })).filter((x) => x.t.length).map(({ r, t }) => {
      const done = dpias.find((d) => d.ropa_id === r.id && d.completed);
      return { ropa_id: r.id, name: r.name, purpose: r.purpose || '', legal_basis: r.legal_basis || '', triggers: t, dpia: done ? { id: done.id, completed: done.completed, outcome: done.outcome || null } : null,
        draft: drafts().all((d) => d.ropa_id === r.id && d.state !== 'returned').sort((a, b) => String(b.at).localeCompare(String(a.at)))[0] || null };
    }).sort((a, b) => (!!a.dpia - !!b.dpia) || b.triggers.length - a.triggers.length);
  }
  function ruleDraft(r, t) {
    const cats = (r.data_categories || []).join(', ') || 'not recorded';
    return {
      necessity: 'Purpose recorded: ' + (r.purpose || 'NOT RECORDED - complete the processing record first') + '. Legal basis: ' + (r.legal_basis || 'NOT RECORDED') + '. Data categories: ' + cats + '. To confirm with the process owner: that each category is needed for this purpose and that less data, or pseudonymised data, would not do (IR Art. 25: necessity and proportionality).',
      risks: t.map((x) => '- ' + x + ': ' + ({ 'sensitive data': 'disclosure or misuse causes serious harm to the person (material and moral)', 'credit data': 'wrong or disclosed credit data affects financing decisions', 'solely automated decisions': 'a person is affected by a decision nobody reviewed', 'automated underwriting': 'cover or price decided without human review', profiling: 'inferences the person does not expect', 'fraud scoring': 'a wrong score treats a customer as a suspect', 'continuous large-scale monitoring': 'people watched beyond what they expect', 'telematics (location over time)': 'movement patterns reveal habits and places' }[x.replace(/:.*$/, '')] || (/sources/.test(x) ? 'linking sources builds a fuller profile than any one system holds' : 'to assess'))).join('\n'),
      measures: '- Access limited to the roles that need it, reviewed quarterly (Sensitive Data Controls page)\n- Retention per the schedule; destruction recorded\n' + (t.some((x) => /automated|scoring|underwriting|profiling/.test(x)) ? '- A person reviews adverse automated decisions on request; the logic is explained to the person\n' : '') + (t.some((x) => /sensitive|credit/.test(x)) ? '- Explicit consent or another basis that allows this category, recorded per person\n' : '') + '- Security measures recorded on the processing record: ' + (r.security_measures || 'NOT RECORDED'),
      residual: 'To be decided by the DPO after the measures are confirmed.' };
  }
  const cfg = () => (app.config && app.config.pdpl_ai) || (app.config && app.config.ia_ai) || {};
  const getKey = opts.getKey || (() => { const get = require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'anthropic_api_key', app.config && app.config.discovery && app.config.discovery.vault_key_file); return () => get() || process.env.ANTHROPIC_API_KEY || ''; })();
  let Ctor = null, loadError = '';
  function loadSdk() {
    if (opts.sdk) return opts.sdk; if (Ctor) return Ctor;
    for (const p of [cfg().sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', require('path').join(__dirname, 'ai-sdk-shim.js')].filter(Boolean)) {
      try { if (p.startsWith('/') && !fs.existsSync(p)) continue; const m = require(p); Ctor = require('./ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (the update installs it)' : s(e.message, 200); }
    }
    return null;
  }
  function aiStatus() {
    const model = cfg().model || MODEL;
    let allowed = false; try { allowed = !!(app.settings && require('./ai-backend').allowed(app.settings.get())); } catch (e) { allowed = false; /* settings unreadable = not allowed */ }
    if (!allowed) return { enabled: false, reason: 'external AI is not allowed in IT Asset Management settings (external_ai_allowed), or the AI engine is switched off (Platform Administration -> AI Engine) - drafts come from the rules only', model };
    if (!getKey()) return { enabled: false, reason: 'no Anthropic API key (sudo zyb-virt-ai --set-key) - drafts come from the rules only', model };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed', model };
    return { enabled: true, model };
  }
  const FIELDS = ['necessity', 'risks', 'measures', 'residual'];
  async function aiWord(r, t, base, who) {
    const st = aiStatus(); if (!st.enabled) throw httpErr(503, st.reason);
    // only the processing record's own description - never a person's data (the catalogue gives column names and counts, not values)
    const facts = JSON.stringify({ activity: { id: r.id, name: r.name, purpose: r.purpose, legal_basis: r.legal_basis, data_categories: r.data_categories, subjects: r.subjects, sources: r.sources, security_measures: r.security_measures, retention_basis: r.retention_basis }, triggers: t, rule_draft: base });
    const q = G.redactSecrets('Improve the wording of this PDPL data protection impact assessment draft (Implementing Regulation Art. 25) for the DPO, using ONLY the facts below. Do not invent facts, systems, numbers or measures that are not in the facts; where something is not recorded, say it must be confirmed. Answer with one JSON object with exactly the keys necessity, risks, measures, residual.\n\n' + G.untrusted('ropa:' + r.id, facts));
    const budget = G.sharedBudget({ log: L, limits: () => ((app.config && app.config.ai) || {}).limits || {} });
    budget.admit(who.user, 'itam.pdpl-dpia-draft', q.length);
    const flags = G.injectionSignals(facts), usage = { input_tokens: 0, output_tokens: 0 };
    let text = '';
    try {
      const Anthropic = loadSdk(), client = new Anthropic({ apiKey: getKey(), timeout: (cfg().timeout_s || 180) * 1000, maxRetries: 2 });
      const resp = await client.messages.create({ model: st.model, max_tokens: 4000, system: 'You are a privacy analyst at a Saudi insurer drafting a PDPL impact assessment for the DPO. You draft; the DPO decides.\n\n' + G.UNTRUSTED_RULE, messages: [{ role: 'user', content: q }] });
      for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0;
      text = (resp.content || []).filter((x) => x.type === 'text').map((x) => x.text).join('\n');
    } finally { budget.record(who.user, 'itam.pdpl-dpia-draft', usage, flags); }
    const mm = text.match(/\{[\s\S]*\}/); let o = null; try { o = mm ? JSON.parse(mm[0]) : null; } catch (e) { o = null; /* not JSON: refused below, the rule draft is still offered */ }
    if (!o || typeof o !== 'object') throw httpErr(502, 'the AI did not return a usable draft - draft from the rules instead');
    const out = {}; for (const k of FIELDS) out[k] = typeof o[k] === 'string' && o[k].trim() ? s(o[k].replace(/\r/g, ''), 3000) : base[k];   // schema-checked: anything else keeps the rule text
    return { out, flags };
  }
  async function draft(ropa0, b0, who) {
    person(who);
    const id = param(ropa0, 'ropa'), b = body(b0).bool('use_ai', { def: false }).done();
    const r = PD.records('ropa').find((x) => x.id === id && x.status !== 'archived'); if (!r) throw httpErr(404, 'no processing activity ' + id);
    const t = triggers(r); if (!t.length) throw httpErr(409, r.name + ' has no DPIA trigger on its record - an impact assessment is not required by these rules');
    if (drafts().all((d) => d.ropa_id === id && d.state === 'draft').length) throw httpErr(409, 'a draft for ' + id + ' is waiting for the DPO');
    let content = ruleDraft(r, t), source = 'rules', flags = [];
    if (b.use_ai) { const a = await aiWord(r, t, content, who); content = a.out; source = 'ai'; flags = a.flags; }
    const d = Object.assign({ id: 'DPIAD-' + String(drafts().all(() => true).length + 1).padStart(4, '0'), ropa_id: id, name: r.name, triggers: t, source, flags, state: 'draft', requested_by: who.user, at: iso() }, content);
    drafts().put(d); audit(who, 'dpia.draft', d.id, { ropa: id, source, triggers: t.length, flags: flags.length });
    return d;
  }
  function decide(id0, b0, who) {
    person(who);
    const d = drafts().get(param(id0, 'id')); if (!d) throw httpErr(404, 'no draft ' + s(id0, 30));
    if (d.state !== 'draft') throw httpErr(409, 'the draft is ' + d.state);
    const dpo = profile().dpo_user;
    if (!(dpo && same(dpo, who.user)) && who.role !== 'admin') throw httpErr(403, 'the DPO (' + (dpo || 'not named in the PDPL profile') + ') or an administrator decides a DPIA draft');
    if (same(d.requested_by, who.user)) throw httpErr(403, 'you asked for this draft - another person (the DPO) decides it');
    const b = body(b0).oneOf('decision', ['approve', 'return'], { required: true }).str('note', { required: true, min: 5, max: 1000 }).done();
    d.state = b.decision === 'approve' ? 'approved' : 'returned'; d.decided_by = who.user; d.decided_at = iso(); d.decision_note = b.note;
    drafts().put(d); audit(who, 'dpia.decide', d.id, { ropa: d.ropa_id, decision: b.decision, source: d.source, requested_by: d.requested_by });
    return d;
  }
  function view() {
    const m = model(), ds = dsarRisk(), br = breachRisk(), cand = candidates();
    return { at: iso(), model: m, dsar: ds, breaches: br, dpia: cand, drafts: drafts().all(() => true).sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 50), ai: aiStatus(), dpo: profile().dpo_user || null,
      summary: { review_queue: m.queue.length, sensitive_unreviewed: m.queue.filter((c) => c.sensitive).length, dsar_at_risk: ds.filter((x) => x.risk === 'high' || x.risk === 'breached').length, dsar_open: ds.length,
        breach_at_risk: br.filter((x) => x.risk === 'high' || x.risk === 'breached').length, dpia_missing: cand.filter((c) => !c.dpia).length },
      note: 'Probabilities and forecasts are computed from this organisation\'s own records and say how they were made. They rank the work; they do not decide it.' };
  }
  return { view, model, review, dsarRisk, breachRisk, candidates, draft, decide, aiStatus };
}

function registerPdplIntel(srv, app, I) {
  const op = (fn) => (ctx) => { ctx.need('operator'); return fn(ctx); };   // PDPL records name people and systems: no viewers
  srv.route('GET', '/pdpl/intel', op(() => I.view()));
  srv.route('GET', '/pdpl/intel/ai/status', op(() => I.aiStatus()));
  srv.route('POST', '/pdpl/intel/columns/review', op((ctx) => I.review(ctx.body, ctx.who)));
  srv.route('POST', '/pdpl/intel/dpia/:ropa/draft', op((ctx) => I.draft(ctx.params.ropa, ctx.body, ctx.who)));
  srv.route('POST', '/pdpl/intel/drafts/:id/decide', op((ctx) => I.decide(ctx.params.id, ctx.body, ctx.who)));
}

module.exports = { createPdplIntel, registerPdplIntel, features, prior, train, predict, tokens };
