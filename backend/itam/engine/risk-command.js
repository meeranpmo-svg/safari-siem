// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { createIntelKit, registerIntel, trend } = require('./intel-kit');
/*
 * Risk Command Center ({P} = /api/itam; Risk management -> Overview). The front door of the risk area: one view over the risk
 * register (engine/grc-registers.js through Risk Studio, engine/risk-studio.js) and the ten insurer risk scenarios (engine/
 * risk-assess.js). It writes nothing: risks are created, rated, treated and accepted on their own pages, by people.
 *   posture       100 less itemised points: open risks rated high, risks above the appetite, the scenario exposure, risks without an
 *                 owner / review / action (hygiene), under-rated risks (the evidence suggests a higher rating), deteriorating risks;
 *                 withheld while the register is empty and no scenario is assessed (an empty register must not read as safe)
 *   simulation    a seeded Monte Carlo over the open risks: the owner's residual likelihood (1-5) read as an annual probability
 *                 (5 / 15 / 35 / 60 / 85 %), 5,000 years simulated - how many risks, and how many high-impact ones (impact 4-5),
 *                 are expected to occur in a year (P50 / P90). The mapping is stated on the page: a model, not a forecast.
 *   treatment     inherent -> residual reduction per category and per treatment; "mitigate" risks with no reduction recorded
 *   concentration residual score summed per category (against the appetite) and per owner (the share the top owners carry)
 *   movers        the risks whose score moved most in 30 days (Risk Studio's daily samples)
 *   history       one snapshot a day: posture and total residual - movement and a projection to the target (intel kit)
 *   my brief      for the person signed in (the Head of Risk & Compliance's workspace): the risks and GRC actions they own, reviews due,
 *                 the team's overdue actions, the compliance position (Audit Dashboard), and one ranked list of priorities - each with
 *                 its points and reasons (severity, days overdue, a regulatory clock, above appetite) - plus a plain-language brief
 *                 and Workflow Automation (requests the risk function raised that are late with the IT teams, results to accept,
 *                 approvals waiting - engine/workflow-auto.js attention)
 *   GET  /risk-command          viewer      (the register is already readable by every role on Risk Studio)
 *   GET  /risk-command/my       operator    the personal brief (names owners and their work: no viewers)
 *   POST /risk-command/ask      operator    the read-only AI risk advisor (kit)
 */
const PROB = { 1: 0.05, 2: 0.15, 3: 0.35, 4: 0.6, 5: 0.85 };
const TARGET = 80, YEARS = 5000;
const catOf = (r) => r.category || (r.category_suggested && (r.category_suggested.category || r.category_suggested)) || 'Uncategorised';
const band = (x) => (x == null ? null : x >= 15 ? 'high' : x >= 8 ? 'medium' : 'low');
function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const pct = (arr, p) => { if (!arr.length) return null; const s = arr.slice().sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };

function simulate(risks, years = YEARS, seed = 20261104) {
  const R = risks.map((r) => ({ p: PROB[r.l] || 0, hi: r.i >= 4 })), r0 = rng(seed), all = [], hi = [], hist = {};
  if (!R.length) return null;
  for (let y = 0; y < years; y++) { let n = 0, h = 0; for (const x of R) if (r0() < x.p) { n++; if (x.hi) h++; } all.push(n); hi.push(h); hist[n] = (hist[n] || 0) + 1; }
  const mean = (a) => Math.round(a.reduce((t, v) => t + v, 0) / a.length * 10) / 10;
  return { years, seed, expected: mean(all), p50: pct(all, 0.5), p90: pct(all, 0.9), high_expected: mean(hi), high_p90: pct(hi, 0.9), p_any_high: Math.round(hi.filter((v) => v > 0).length / years * 100),
    histogram: Object.keys(hist).map(Number).sort((a, b) => a - b).map((k) => ({ n: k, share: Math.round(hist[k] / years * 1000) / 10 })),
    why: 'likelihood 1-5 read as an annual probability of ' + Object.values(PROB).map((p) => Math.round(p * 100) + '%').join(' / ') + '; ' + years.toLocaleString('en') + ' simulated years, seed ' + seed + ' (re-performable) - a model of the owners\' ratings, not a forecast' };
}

function createRiskCommand(app, opts = {}) {
  let K;
  async function collect() {
    const notes = [], A = K.A();
    const studio = A.riskStudio ? await K.read('Risk Studio', () => A.riskStudio.view({ user: 'risk-command', role: 'viewer' }), notes) : (notes.push('Risk Studio is not installed'), null);
    const assess = A.riskAssess ? await K.read('Automated Risk Assessment', () => A.riskAssess.view({ user: 'risk-command', role: 'viewer' }), notes) : (notes.push('Automated Risk Assessment is not installed'), null);
    return { studio, assess, notes };
  }
  function analyse(C) {
    const S = C.studio, Aa = C.assess, risks = S ? S.risks : [], scen = Aa ? Aa.scenarios.filter((x) => x.assessed) : [];
    const rated = (r) => (r.residual != null ? r.residual : r.inherent), ap = S ? S.appetite : { default: 12, categories: {} };
    // posture: 100 less itemised points
    let posture = null; const items = [];
    if (risks.length || scen.length) {
      const pen = (label, n, each, max, why) => { if (n > 0) items.push({ label: label + ' (' + n + ' x ' + each + ', at most ' + max + ')', points: -Math.min(max, n * each), why }); };
      pen('open risks rated high', risks.filter((r) => band(rated(r)) === 'high').length, 6, 30, 'residual (or inherent) score 15 or more');
      pen('risks above the appetite', risks.filter((r) => r.over_appetite).length, 5, 25, 'above the most the category accepts (Risk Studio appetite)');
      if (Aa && Aa.exposure != null) items.push({ label: 'scenario exposure ' + Aa.exposure + ' / 100 (x 0.2)', points: -Math.round(Aa.exposure * 0.2), why: Aa.exposure_why });
      pen('under-rated against the evidence', risks.filter((r) => r.calibration && /under-rated/.test(r.calibration)).length, 3, 12, 'the linked signals suggest a higher rating');
      pen('hygiene issues', risks.filter((r) => (r.hygiene || []).length).length, 1, 10, 'no owner, review overdue, mitigate without an action, old acceptance');
      pen('deteriorating risks', risks.filter((r) => r.trend && r.trend.change > 0).length, 2, 10, 'score up against 30 days ago');
      posture = Math.max(0, Math.min(100, 100 + items.reduce((t, x) => t + x.points, 0)));
    }
    // treatment effectiveness
    const cats = {}, treat = {};
    for (const r of risks) {
      const c = catOf(r), red = r.residual != null && r.inherent != null ? r.inherent - r.residual : null;
      const x = cats[c] = cats[c] || { category: c, risks: 0, residual: 0, inherent: 0, high: 0, over: 0, appetite: (ap.categories || {})[c] || ap.default };
      x.risks++; x.residual += rated(r) || 0; x.inherent += r.inherent || 0; if (band(rated(r)) === 'high') x.high++; if (r.over_appetite) x.over++;
      const t = treat[r.treatment || 'none'] = treat[r.treatment || 'none'] || { treatment: r.treatment || 'none', risks: 0, reduced: 0, reduction: 0 };
      t.risks++; if (red != null) { t.reduction += red; if (red > 0) t.reduced++; }
    }
    const byCat = Object.values(cats).map((x) => Object.assign(x, { reduction_pct: x.inherent ? Math.round((1 - x.residual / x.inherent) * 100) : 0 })).sort((a, b) => b.residual - a.residual);
    const noReduction = risks.filter((r) => r.treatment === 'mitigate' && (r.residual == null || r.residual >= r.inherent)).map((r) => ({ id: r.id, title: r.title, owner: r.owner, inherent: r.inherent, residual: r.residual, open_actions: r.open_actions }));
    const owners = {}; for (const r of risks) { const o = r.owner || '(no owner)', x = owners[o] = owners[o] || { owner: o, risks: 0, residual: 0, high: 0 }; x.risks++; x.residual += rated(r) || 0; if (band(rated(r)) === 'high') x.high++; }
    const ownerList = Object.values(owners).sort((a, b) => b.residual - a.residual), totRes = ownerList.reduce((t, o) => t + o.residual, 0), topN = Math.max(1, Math.ceil(ownerList.length * 0.2));
    const movers = risks.filter((r) => r.trend && r.trend.change).sort((a, b) => Math.abs(b.trend.change) - Math.abs(a.trend.change)).slice(0, 10).map((r) => ({ id: r.id, title: r.title, owner: r.owner, from: r.trend.from, to: r.trend.to, change: r.trend.change, since: r.trend.since }));
    const sim = simulate(risks.map((r) => ({ l: r.residual_likelihood || r.likelihood, i: r.residual_impact || r.impact })));
    const heat = S ? S.heat : { inherent: {}, residual: {} };
    return { posture, items, risks, scen, byCat, treat: Object.values(treat), noReduction, ownerList, ownerShare: totRes ? Math.round(ownerList.slice(0, topN).reduce((t, o) => t + o.residual, 0) / totRes * 100) : null, topN, movers, sim, heat, total_residual: risks.reduce((t, r) => t + (rated(r) || 0), 0) };
  }
  async function view() {
    const C = await collect(), X = analyse(C), S = C.studio, Aa = C.assess, ref = K.ago(30);
    const tr = X.posture == null ? { why: 'withheld' } : trend(K.pts('posture'), { target: TARGET, current: X.posture, now: K.now() });
    const urgent = X.risks.filter((r) => r.over_appetite || band(r.residual != null ? r.residual : r.inherent) === 'high').sort((a, b) => (b.residual ?? b.inherent) - (a.residual ?? a.inherent)).slice(0, 12)
      .map((r) => ({ id: r.id, title: r.title, owner: r.owner, category: catOf(r), score: r.residual ?? r.inherent, band: band(r.residual ?? r.inherent), over_appetite: r.over_appetite, appetite: r.appetite, calibration: r.calibration, hygiene: r.hygiene || [], open_actions: r.open_actions, treatment: r.treatment }));
    return { generated_at: K.iso(), notes: C.notes, ai: K.aiStatus(), target: TARGET,
      posture: { value: X.posture, items: X.items, why: X.posture == null ? 'withheld until the register holds a risk or a scenario is assessed - an empty register must not read as safe' : '100 less the points itemised below - indicative, for the risk committee, not a rating', move_30d: X.posture != null && ref && ref.posture != null ? X.posture - ref.posture : null, projection: tr,
        history: K.history(90).map((h) => ({ date: h.id, posture: h.posture, residual: h.residual })) },
      kpis: { open: X.risks.length, high: X.risks.filter((r) => band(r.residual ?? r.inherent) === 'high').length, over_appetite: X.risks.filter((r) => r.over_appetite).length,
        under_rated: X.risks.filter((r) => r.calibration && /under-rated/.test(r.calibration)).length, hygiene: X.risks.filter((r) => (r.hygiene || []).length).length, candidates: S ? S.candidates.length : 0,
        scenarios_assessed: X.scen.length, scenario_exposure: Aa ? Aa.exposure : null, deteriorating: X.risks.filter((r) => r.trend && r.trend.change > 0).length },
      heat: X.heat, urgent, simulation: X.sim, categories: X.byCat, treatments: X.treat, no_reduction: X.noReduction.slice(0, 12), owners: X.ownerList.slice(0, 12),
      owner_concentration: X.ownerShare == null ? { why: 'no open risk' } : { share: X.ownerShare, top: X.topN, why: 'the top ' + X.topN + ' owner(s) (20 %) carry ' + X.ownerShare + ' % of the residual score' },
      movers: X.movers, candidates: S ? S.candidates.slice(0, 8).map((c) => ({ id: c.id, title: c.title, signals: (c.signals || []).length, score: c.score, band: c.band, category: c.category && c.category.category ? c.category.category : c.category || null })) : [],
      scenarios: Aa ? Aa.scenarios.map((x) => ({ id: x.id, name: x.name, category: x.category, assessed: x.assessed, likelihood: x.likelihood, impact: x.impact, inherent: x.inherent, residual: x.residual, band: x.band })) : [],
      appetite: S ? S.appetite : null,
      note: 'Read from the risk register and the scenario assessment - indicators for the risk owners and the risk committee. Risks are created, rated, treated and accepted on their own pages, by people.' };
  }
  const GR = () => (K.A().grcRegisters) || null;
  async function my(who) {
    const u = String(who.user || '').toLowerCase(), mine = (o) => String(o || '').toLowerCase() === u, t0 = K.now(), today = new Date(t0 + 3 * 3600000).toISOString().slice(0, 10);
    const days = (d) => Math.max(0, Math.round((Date.parse(today + 'T00:00:00Z') - Date.parse(String(d).slice(0, 10) + 'T00:00:00Z')) / 86400000));
    const v = await view(), R = GR(), notes = [];
    const studio = new Map((K.A().riskStudio ? (await K.read('Risk Studio', () => K.A().riskStudio.view({ user: 'risk-command', role: 'viewer' }), notes)) || { risks: [] } : { risks: [] }).risks.map((r) => [r.id, r]));
    const risks = R ? R.riskList().items.filter((r) => r.status === 'open') : [], acts = R ? R.actionList({ status: 'open' }).items : [];
    if (!R) notes.push('the GRC register is not installed');
    const myRisks = risks.filter((r) => mine(r.owner)).map((r) => { const x = studio.get(r.id) || {}; const sc = r.residual != null ? r.residual : r.inherent;
      return { id: r.id, title: r.title, score: sc, band: band(sc), review_due: r.review_due, review_overdue: !!r.review_overdue, over_appetite: !!x.over_appetite, calibration: x.calibration || null, open_actions: r.open_actions, treatment: r.treatment }; });
    const myActs = acts.filter((a) => mine(a.owner)).map((a) => ({ id: a.id, title: a.title, due: a.due, overdue: a.overdue, due_soon: a.due_soon, priority: a.priority || null, framework: a.framework || null, source: a.source }));
    const teamOverdue = acts.filter((a) => a.overdue && !mine(a.owner)).map((a) => ({ id: a.id, title: a.title, owner: a.owner, due: a.due, days: days(a.due) })).sort((a, b) => b.days - a.days);
    let comp = null; const AD = K.A().auditDashboard;
    if (AD) { const d = await K.read('Audit Dashboard', () => AD.view(), notes); if (d) comp = { index: d.insight ? d.insight.index.value : null, summary: d.summary, frameworks: d.frameworks.map((f) => ({ id: f.id, name: f.name, score: f.score, status: f.status, page: f.page })), attention: d.attention.slice(0, 10) }; }
    else notes.push('the Audit Dashboard is not installed');
    const P = [], add = (kind, ref, text, why, page) => P.push({ kind, ref, text, page, score: Math.min(100, why.reduce((t, w) => t + w[1], 0)), why: why.map((w) => w[0] + ' +' + w[1]) });
    for (const a of myActs) if (a.overdue) add('my action', a.id, a.title + ' - due ' + a.due, [['your action, overdue', 60], [days(a.due) + ' day(s) late', Math.min(25, Math.round(6 * Math.log(1 + days(a.due))))]], 'grc-workspace.html');
      else if (a.due_soon) add('my action', a.id, a.title + ' - due ' + a.due, [['your action, due within 14 days', 40]], 'grc-workspace.html');
    for (const r of myRisks) { const w = []; if (r.over_appetite) w.push(['above the appetite', 35]); if (r.band === 'high') w.push(['rated high (' + r.score + ')', 25]); if (r.review_overdue) w.push(['review overdue since ' + r.review_due, 20]); if (r.calibration) w.push(['the evidence suggests a higher rating', 10]);
      if (w.length) add('my risk', r.id, r.title, w, 'risk-studio.html'); }
    for (const a of teamOverdue.slice(0, 8)) add('team action', a.id, a.title + ' - ' + (a.owner || 'no owner') + ', ' + a.days + ' day(s) late', [['an overdue action in your area', 30], [a.days + ' day(s) late', Math.min(20, Math.round(5 * Math.log(1 + a.days)))]], 'grc-workspace.html');
    if (comp) for (const a of comp.attention.slice(0, 8)) add('compliance', a.ref, a.text + ' (' + a.source + ')', [['compliance: ' + a.severity, a.severity === 'high' ? 35 : 20]].concat(a.kind === 'clock' ? [['a legal clock is running (PDPL)', 25]] : []), a.page);
    // Workflow Automation (engine/workflow-auto.js attention): what the risk function asked the IT teams for that is late, results
    // waiting for acceptance, requests waiting for this person's approval - the same reading as the CISO's and the IT Manager's briefs
    const WF = K.A().workflow, at = WF ? await K.read('Workflow Automation', () => WF.attention({ user: who.user, role: who.role }), notes) : null;
    if (!WF) notes.push('Workflow Automation is not installed');
    if (at) for (const p of at.priorities) add(p.kind, p.ref, p.text, p.why, p.page);
    const wf = at ? at.summary : null;
    P.sort((a, b) => b.score - a.score);
    const lines = [];
    const od = myActs.filter((a) => a.overdue).length, ds = myActs.filter((a) => a.due_soon).length, ap = myRisks.filter((r) => r.over_appetite).length, rv = myRisks.filter((r) => r.review_overdue).length;
    lines.push(myRisks.length ? 'You own ' + myRisks.length + ' open risk(s)' + (ap ? ', ' + ap + ' above the appetite' : '') + (rv ? ', ' + rv + ' with a review overdue' : '') + '.' : 'You own no open risk in the register.');
    lines.push(myActs.length ? 'You have ' + myActs.length + ' open action(s)' + (od ? ', ' + od + ' overdue' : '') + (ds ? ', ' + ds + ' due within 14 days' : '') + '.' : 'You have no open GRC action.');
    if (teamOverdue.length) lines.push(teamOverdue.length + ' action(s) owned by others are overdue - the oldest ' + teamOverdue[0].days + ' day(s) (' + teamOverdue[0].id + ').');
    if (v.posture.value != null) lines.push('Risk posture ' + v.posture.value + ' / 100' + (v.posture.move_30d != null ? ' (' + (v.posture.move_30d >= 0 ? '+' : '') + v.posture.move_30d + ' in 30 days)' : '') + '; ' + v.kpis.over_appetite + ' risk(s) above appetite across the register.');
    if (comp && comp.index != null) lines.push('Assurance index ' + comp.index + ' / 100; ' + (comp.summary.overdue_findings || 0) + ' overdue audit finding(s), ' + (comp.summary.pdpl_deadlines_at_risk || 0) + ' PDPL deadline(s) at risk.');
    if (wf) lines.push('Workflow Automation: ' + wf.raised_open + ' request(s) from you' + (wf.functions.includes('risk') ? ' and the risk function' : '') + ' open with the IT teams' + (wf.raised_late ? ', ' + wf.raised_late + ' late' : '')
      + (wf.to_accept ? ', ' + wf.to_accept + ' result(s) waiting for your acceptance' : '') + (wf.approvals ? ', ' + wf.approvals + ' request(s) waiting for your approval' : '') + '; ' + wf.all_overdue + ' overdue across the IT teams.');
    if (P[0]) lines.push('First: ' + P[0].ref + ' - ' + P[0].text + '.');
    return { generated_at: K.iso(), user: who.user, brief: lines, wf, priorities: P.slice(0, 15), my_risks: myRisks, my_actions: myActs, team_overdue: teamOverdue.slice(0, 10), team_overdue_total: teamOverdue.length,
      posture: { value: v.posture.value, move_30d: v.posture.move_30d }, kpis: v.kpis, compliance: comp, notes,
      note: 'Ranked from the registers - each priority shows its points. The brief is written by rules from the records, not by an AI; ask the advisor for a discussion.' };
  }
  async function snapshot() { return K.snapshot(async () => { const C = await collect(), X = analyse(C); if (X.posture == null) return null; return { posture: X.posture, residual: X.total_residual, open: X.risks.length }; }); }
  K = createIntelKit(app, { key: 'risk-command', feature: 'itam.risk-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: opts.noTimer,
    system: ('You are the risk advisor to the Chief Risk Officer and the risk committee of ' + ZYB_ORG.name + '. You read the risk register (inherent and residual ratings, owners, treatments, appetite, evidence-based calibration, hygiene, movement), the ten insurer risk scenarios and a Monte Carlo of how many risks may occur in a year from the owners\' own ratings. Base every statement on the tool results and name the risk ids. You propose priorities and treatments; risk owners and the committee decide. The simulation is a model of the ratings, not a forecast.'),
    tools: [{ name: 'risk_overview', description: 'Posture with its breakdown, KPIs, the urgent risks, categories against appetite, treatment effectiveness, owners, movers, the simulation.', run: async () => { const v = await view();
      return { posture: v.posture, kpis: v.kpis, urgent: v.urgent, categories: v.categories, treatments: v.treatments, no_reduction: v.no_reduction, owners: v.owners, movers: v.movers, simulation: v.simulation ? { expected: v.simulation.expected, p90: v.simulation.p90, high_expected: v.simulation.high_expected, p_any_high: v.simulation.p_any_high, why: v.simulation.why } : null }; } },
    { name: 'scenarios', description: 'The ten insurer risk scenarios with likelihood, impact, inherent and residual scores.', run: async () => (await view()).scenarios }] });
  return { view, my, snapshot, ask: K.ask, start: () => K.start(snapshot), stop: K.stop, TOOLS: K.TOOLS, simulate };
}
function registerRiskCommand(srv, app, X) {
  registerIntel(srv, X, '/risk-command');
  srv.route('GET', '/risk-command/my', (ctx) => { ctx.need('operator'); return X.my(ctx.who); });   // names owners and their work: no viewers
}
module.exports = { createRiskCommand, registerRiskCommand, simulate, PROB };
