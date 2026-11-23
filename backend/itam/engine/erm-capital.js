// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Capital, ORSA & Stress Testing - the capital side of the enterprise risk management of an insurer (KPMG ERM framework: 2 risk
 * oversight - ORSA, capital and reserve adequacy; 5 risk / reward trade-offs; 6 business resilience - stress scenarios, sensitivity,
 * contingency plans). NOTHING HERE IS ESTIMATED: every figure is entered by a person (finance / actuarial) and confirmed by a second
 * person; the platform calculates the ratios, judges them against the Board-approved Risk Appetite Statement (Business Risk metrics -
 * an administrator links which RAS metric is the solvency ratio and which the liquidity ratio; without a link nothing is judged and
 * the page says so), applies stress shocks, freezes the ORSA and keeps every decision in the audit log.
 *
 *   POSITION     per period (2026-Q3, 2026-H1, 2026-FY): available capital, required capital (minimum solvency margin), liquid assets,
 *                expected outflows of the next three months, and per line of business GWP, NEP, net claims, expenses, net profit and
 *                the capital allocated to it. A position is confirmed by an administrator who did not enter it; entering it again
 *                keeps the earlier figures in its history and needs a new confirmation.
 *   STRESS       scenarios (a shock in % to available capital, required capital, liquid assets and outflows) with contingency
 *                actions (amounts a management action adds to capital / liquidity or takes off the requirement, and its trigger).
 *                A scenario is proposed by one person and approved by a different administrator; a changed scenario is proposed
 *                again. Results on the latest confirmed position: solvency and liquidity before / after the shock / after the
 *                actions, each judged against the RAS; the reverse stress (the capital fall that brings solvency to 100 % and to
 *                the RAS capacity floor); a sensitivity table.
 *   ORSA         the yearly Own Risk and Solvency Assessment: opened for a year and a confirmed position; business plan, capital
 *                projection, conclusions and management actions written by people; submitting freezes it (position, ratios,
 *                every approved scenario's results, the register's risk profile, the projection) with a SHA-256 fingerprint; the
 *                Board approval is recorded by an administrator who did not submit it, with the Board reference - or returned.
 *   PERFORMANCE  per line of business: return on risk capital (net profit / allocated capital), loss and combined ratios, share of
 *                capital, against the hurdle rate an administrator sets (no hurdle - not judged).
 *   INITIATIVES  M&A, transformation, new products, major IT: the capital effect entered, a pro-forma solvency on the latest
 *                confirmed position, a risk review by the risk function (not the sponsor, not the person who raised it): within /
 *                conditional / outside appetite, then a decision by an administrator who neither raised nor reviewed it.
 *
 * Routes ({P} = /api/itam) - reads viewer; writes a person (never a service or AI identity), each audited 'erm-capital.*'
 *   GET  /erm-cap                               viewer   everything the page shows
 *   PUT  /erm-cap/settings                      admin    {solvency_metric?, liquidity_metric?, hurdle_pct?, currency?, orsa_due?}
 *   POST /erm-cap/positions                     operator {period, available_capital, required_capital, liquid_assets?, outflows_3m?, lines[], source}
 *   POST /erm-cap/positions/:id/confirm         admin    {note?}                   not the person who entered it
 *   POST /erm-cap/scenarios                     operator {id?, name, category, description, shocks{}, actions[]}   proposed
 *   POST /erm-cap/scenarios/:id/decision        admin    {decision: approve | reject, note}   not the proposer
 *   POST /erm-cap/orsa                          admin    {year, position, due}
 *   POST /erm-cap/orsa/:id                      operator {business_plan?, risk_profile_note?, projection?, conclusions?, management_actions?}
 *   POST /erm-cap/orsa/:id/submit               operator {note?}                  freezes it
 *   POST /erm-cap/orsa/:id/decision             admin    {decision: approve | return, board_ref?, note}   not the submitter
 *   GET  /erm-cap/orsa/:id/report               operator the frozen ORSA as a report (audited: it exports the position)
 *   POST /erm-cap/initiatives                   operator {title, kind, description, sponsor, expected_benefit?, capital_impact?, required_impact?, decision_due}
 *   POST /erm-cap/initiatives/:id/review        operator {appetite, risks, conditions?, linked_risks?}   not the raiser, not the sponsor
 *   POST /erm-cap/initiatives/:id/decision      admin    {decision: approve | reject | defer, note}   neither the raiser nor the reviewer
 */
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const ML = require('./brisk-ml');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const PERIOD = /^\d{4}-(Q[1-4]|H[12]|FY)$/;
const CATS = ['insurance', 'catastrophe', 'market', 'credit', 'liquidity', 'operational', 'cyber', 'reputational', 'combined'];
const KINDS = ['m_and_a', 'transformation', 'new_product', 'major_it', 'partnership', 'other'];
const r4 = (x) => (x == null || !Number.isFinite(x) ? null : Math.round(x * 10000) / 10000);
const r2 = (x) => (x == null || !Number.isFinite(x) ? null : Math.round(x * 100) / 100);
const div = (a, b) => (a == null || b == null || !b ? null : a / b);
const pOrder = (p) => { const m = /^(\d{4})-(Q([1-4])|H([12])|FY)$/.exec(p) || []; return Number(m[1] || 0) * 10 + (m[3] ? Number(m[3]) * 2 : m[4] ? Number(m[4]) * 4 : 9); };

function createErmCapital(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString(), C = (n) => app.store.collection(n);
  const SET = () => C('ec_settings'), POS = () => C('ec_positions'), SCN = () => C('ec_scenarios'), ORSA = () => C('ec_orsa'), INI = () => C('ec_initiatives');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'erm-capital.' + action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const same = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
  const seq = (col, prefix) => { let n = 0; for (const x of col.all()) { const m = new RegExp('^' + prefix + '-(\\d+)$').exec(x.id); if (m) n = Math.max(n, Number(m[1])); } return prefix + '-' + String(n + 1).padStart(4, '0'); };
  const settings = () => Object.assign({ solvency_metric: null, liquidity_metric: null, hurdle_pct: null, currency: 'SAR', orsa_due: null }, (SET().get('settings') || {}).values || {});
  const metric = (id) => { if (!id) return null; const m = C('br_metrics').get(id); return m && !m.retired ? m : null; };
  // a ratio judged against a RAS metric's limits - or not judged, and why
  function judge(id, v) {
    if (v == null) return { zone: null, why: 'not calculable - a figure is missing' };
    const m = metric(id); if (!m) return { zone: null, why: 'not judged - link the RAS metric in Settings' };
    if (!m.limits || m.kind === 'boolean') return { zone: null, why: 'not judged - the RAS metric ' + (m.component || m.id) + ' has no limits' };
    const z = ML.zoneOf(m, v); return { zone: z.zone, level: z.level, metric: m.id, component: m.component || m.id };
  }

  // ---------- positions
  const ratios = (p) => {
    const sol = div(p.available_capital, p.required_capital), liq = div(p.liquid_assets, p.outflows_3m), st = settings();
    const L = p.lines || [], T = (k) => (L.length ? L.reduce((n, l) => n + (l[k] || 0), 0) : null);
    return { solvency: r4(sol), liquidity: r4(liq), solvency_judged: judge(st.solvency_metric, sol), liquidity_judged: judge(st.liquidity_metric, liq),
      loss_ratio: r4(div(T('net_claims'), T('nep'))), combined_ratio: r4(div(T('net_claims') == null ? null : T('net_claims') + (T('expenses') || 0), T('nep'))), net_profit: T('net_profit'), gwp: T('gwp') };
  };
  const posView = (p) => Object.assign({}, p, { ratios: ratios(p), is_confirmed: !!(p.confirmed && p.confirmed.by) });
  const latest = () => POS().all((p) => p.confirmed && p.confirmed.by).sort((a, b) => pOrder(b.period) - pOrder(a.period))[0] || null;
  function positionSave(input, who) {
    person(who, 'enter the capital position');
    const b = body(input).str('period', { required: true, re: PERIOD, msg: 'period must be like 2026-Q3, 2026-H1 or 2026-FY' })
      .num('available_capital', { required: true, min: 0 }).num('required_capital', { required: true, min: 0.01 }).num('liquid_assets', { min: 0 }).num('outflows_3m', { min: 0 })
      .list('lines', { max: 30, def: [] }).str('source', { required: true, min: 5, max: 300 }).done();
    const lines = b.lines.map((l, i) => {
      const x = body(l).str('name', { required: true, max: 80 }).num('gwp', { min: 0 }).num('nep', { min: 0 }).num('net_claims', { min: 0 }).num('expenses', { min: 0 }).num('net_profit').num('allocated_capital', { min: 0 }).done();
      if (!x.name) throw httpErr(400, `lines[${i}].name is required`); return x;
    });
    if (new Set(lines.map((l) => l.name.toLowerCase())).size !== lines.length) throw httpErr(400, 'lines: a line of business appears twice');
    const id = 'pos-' + b.period, cur = POS().get(id), at = iso();
    const rec = { id, period: b.period, available_capital: b.available_capital, required_capital: b.required_capital, liquid_assets: b.liquid_assets == null ? null : b.liquid_assets, outflows_3m: b.outflows_3m == null ? null : b.outflows_3m,
      lines, source: b.source, entered_by: who.user, entered_at: at, confirmed: null,
      history: cur ? (cur.history || []).concat({ at: cur.entered_at, by: cur.entered_by, available_capital: cur.available_capital, required_capital: cur.required_capital, confirmed_by: cur.confirmed ? cur.confirmed.by : null }).slice(-20) : [] };
    POS().put(rec);
    audit(who, cur ? 'position.update' : 'position.enter', id, { period: b.period, available_capital: b.available_capital, required_capital: b.required_capital, lines: lines.length, source: b.source });
    return posView(rec);
  }
  function positionConfirm(id, input, who) {
    person(who, 'confirm the capital position');
    const b = body(input || {}).str('note', { max: 500 }).done(), p = POS().get(id); if (!p) throw httpErr(404, 'no position ' + id);
    if (p.confirmed && p.confirmed.by) throw httpErr(409, p.period + ' is already confirmed by ' + p.confirmed.by);
    if (same(p.entered_by, who.user)) throw httpErr(403, 'the person who entered the figures cannot confirm them - a second person checks them');
    p.confirmed = { by: who.user, at: iso(), note: b.note || null }; POS().put(p);
    audit(who, 'position.confirm', id, { period: p.period, entered_by: p.entered_by, solvency: ratios(p).solvency });
    return posView(p);
  }

  // ---------- stress scenarios
  const SHOCKS = ['capital_pct', 'required_pct', 'liquid_pct', 'outflow_pct'];
  function stress(p, s) {
    const st = settings(), k = s.shocks || {}, f = (v, pct) => (v == null ? null : v * (1 + (pct || 0) / 100));
    const A1 = f(p.available_capital, k.capital_pct), R1 = f(p.required_capital, k.required_pct), L1 = f(p.liquid_assets, k.liquid_pct), O1 = f(p.outflows_3m, k.outflow_pct);
    const sum = (key) => (s.actions || []).reduce((n, a) => n + (a[key] || 0), 0);
    const A2 = A1 + sum('capital_amount'), R2 = R1 + sum('required_amount'), L2 = L1 == null ? null : L1 + sum('liquid_amount');
    const sol = [div(p.available_capital, p.required_capital), div(A1, R1), div(A2, R2)], liq = [div(p.liquid_assets, p.outflows_3m), div(L1, O1), div(L2, O1)];
    const m = metric(st.solvency_metric), capFloor = m && m.limits ? m.limits.cap_floor : null;
    // reverse stress: the fall in available capital (with this scenario's change to the requirement) that brings solvency to 100 % / to the capacity floor
    const reverse = { to_100: r2((R1 / p.available_capital - 1) * 100), to_capacity_floor: capFloor != null ? r2((capFloor * R1 / p.available_capital - 1) * 100) : null };
    return { scenario: s.id, name: s.name, solvency: sol.map(r4), liquidity: liq.map(r4), judged: { after_shock: judge(st.solvency_metric, sol[1]), after_actions: judge(st.solvency_metric, sol[2]), liquidity_after_shock: judge(st.liquidity_metric, liq[1]) },
      below_100_after_actions: sol[2] != null && sol[2] < 1, reverse, actions: (s.actions || []).length };
  }
  const sensitivity = (p) => [-10, -20, -30, -40, -50].map((x) => ({ capital_pct: x, solvency: r4(div(p.available_capital * (1 + x / 100), p.required_capital)) }));
  function scenarioSave(input, who) {
    person(who, 'propose a stress scenario');
    const b = body(input).str('id', { max: 20, id: true }).str('name', { required: true, min: 3, max: 120 }).oneOf('category', CATS, { required: true }).str('description', { required: true, min: 10, max: 1000 })
      .list('actions', { max: 10, def: [] }).done();
    const sh = body((input && input.shocks) || {}); SHOCKS.forEach((k) => sh.num(k, { min: -100, max: 500, def: 0 })); const shocks = sh.done();
    if (!SHOCKS.some((k) => shocks[k])) throw httpErr(400, 'shocks: at least one shock (capital_pct, required_pct, liquid_pct, outflow_pct) other than 0');
    const actions = b.actions.map((a, i) => { const x = body(a).str('action', { required: true, min: 3, max: 200 }).str('trigger', { required: true, min: 3, max: 200 }).str('owner', { required: true, max: 80 })
      .num('capital_amount', { def: 0 }).num('required_amount', { def: 0 }).num('liquid_amount', { def: 0 }).done(); if (!x.action) throw httpErr(400, `actions[${i}].action is required`); return x; });
    const cur = b.id ? SCN().get(b.id) : null; if (b.id && !cur) throw httpErr(404, 'no scenario ' + b.id);
    const id = cur ? cur.id : seq(SCN(), 'SC'), at = iso();
    const rec = Object.assign({}, cur || {}, { id, name: b.name, category: b.category, description: b.description, shocks, actions, status: 'proposed', proposed_by: who.user, proposed_at: at, decided_by: null, decided_at: null, note: null,
      history: cur ? (cur.history || []).concat({ at: cur.proposed_at, by: cur.proposed_by, status: cur.status, shocks: cur.shocks }).slice(-20) : [] });
    SCN().put(rec); audit(who, cur ? 'scenario.change' : 'scenario.propose', id, { name: b.name, category: b.category, shocks, actions: actions.length });
    return rec;
  }
  function scenarioDecision(id, input, who) {
    person(who, 'approve a stress scenario');
    const b = body(input).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { required: true, min: 3, max: 500 }).done();
    const s = SCN().get(id); if (!s) throw httpErr(404, 'no scenario ' + id);
    if (s.status !== 'proposed') throw httpErr(409, id + ' is ' + s.status + ', not waiting for a decision');
    if (same(s.proposed_by, who.user)) throw httpErr(403, 'the person who proposed the scenario cannot approve it');
    Object.assign(s, { status: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), note: b.note }); SCN().put(s);
    audit(who, 'scenario.' + b.decision, id, { name: s.name, proposed_by: s.proposed_by, note: b.note });
    return s;
  }

  // ---------- ORSA
  function riskProfile() {
    const R = C('br_risks').all((r) => r.status !== 'solved'), byClass = {}, byCat = {};
    let rate = null; try { rate = require('./business-risk').rate; } catch (e) { rate = null; /* Business Risk not installed: counts by category only */ }
    for (const r of R) { const k = rate ? rate(r.likelihood, r.impact, r.exposure).class || 'unrated' : 'unrated'; byClass[k] = (byClass[k] || 0) + 1; const c = r.ins_cat || 'uncategorised'; byCat[c] = (byCat[c] || 0) + 1; }
    return { open: R.length, by_class: byClass, by_category: byCat };
  }
  function orsaOpen(input, who) {
    person(who, 'open an ORSA');
    const b = body(input).int('year', { required: true, min: 2000, max: 2100 }).str('position', { required: true, max: 20, id: true }).date('due', { required: true }).done();
    const id = 'ORSA-' + b.year; if (ORSA().get(id)) throw httpErr(409, 'the ORSA for ' + b.year + ' is already open');
    if (!POS().get(b.position)) throw httpErr(400, 'position: no capital position ' + b.position + ' - enter it first');
    const o = { id, year: b.year, position: b.position, due: b.due, state: 'draft', opened_by: who.user, opened_at: iso(), business_plan: '', risk_profile_note: '', projection: [], conclusions: '', management_actions: '', frozen: null, decisions: [] };
    ORSA().put(o); audit(who, 'orsa.open', id, { year: b.year, position: b.position, due: b.due }); return o;
  }
  function orsaEdit(id, input, who) {
    person(who, 'write the ORSA');
    const o = ORSA().get(id); if (!o) throw httpErr(404, 'no ORSA ' + id);
    if (o.state === 'submitted' || o.state === 'approved') throw httpErr(409, 'the ORSA is ' + o.state + ' - it is frozen');
    const b = body(input).str('business_plan', { max: 8000 }).str('risk_profile_note', { max: 4000 }).str('conclusions', { max: 8000 }).str('management_actions', { max: 4000 }).str('position', { max: 20, id: true }).list('projection', { max: 5 }).done();
    if (b.position) { if (!POS().get(b.position)) throw httpErr(400, 'position: no capital position ' + b.position); o.position = b.position; }
    if (b.projection) o.projection = b.projection.map((x, i) => { const y = body(x).int('year', { required: true, min: 2000, max: 2100 }).num('available_capital', { required: true, min: 0 }).num('required_capital', { required: true, min: 0.01 }).done(); if (!y.year) throw httpErr(400, `projection[${i}].year is required`); return y; });
    const changed = ['business_plan', 'risk_profile_note', 'conclusions', 'management_actions'].filter((k) => b[k] !== undefined && b[k] !== o[k]);
    changed.forEach((k) => { o[k] = b[k]; });
    o.edited_by = who.user; o.edited_at = iso(); ORSA().put(o);
    audit(who, 'orsa.edit', id, { fields: changed.concat(b.projection ? ['projection'] : [], b.position ? ['position'] : []) });
    return orsaView(o);
  }
  function snapshot(o) {
    const p = POS().get(o.position), scn = SCN().all((s) => s.status === 'approved').sort((a, b) => a.id.localeCompare(b.id));
    return { at: iso(), position: p, ratios: ratios(p), stress: scn.map((s) => Object.assign(stress(p, s), { shocks: s.shocks, actions_list: s.actions, category: s.category, approved_by: s.decided_by })), sensitivity: sensitivity(p),
      risk_profile: riskProfile(), projection: o.projection.map((x) => Object.assign({}, x, { solvency: r4(div(x.available_capital, x.required_capital)), judged: judge(settings().solvency_metric, div(x.available_capital, x.required_capital)) })),
      business_plan: o.business_plan, risk_profile_note: o.risk_profile_note, conclusions: o.conclusions, management_actions: o.management_actions, settings: settings() };
  }
  function orsaSubmit(id, input, who) {
    person(who, 'submit the ORSA');
    const b = body(input || {}).str('note', { max: 500 }).done(), o = ORSA().get(id); if (!o) throw httpErr(404, 'no ORSA ' + id);
    if (o.state === 'submitted' || o.state === 'approved') throw httpErr(409, 'the ORSA is already ' + o.state);
    const p = POS().get(o.position), miss = [];
    if (!p) miss.push('the capital position ' + o.position); else if (!(p.confirmed && p.confirmed.by)) miss.push('a second person to confirm the position ' + p.period);
    if (!SCN().all((s) => s.status === 'approved').length) miss.push('at least one approved stress scenario');
    if (!o.projection.length) miss.push('a capital projection for at least one future year');
    if (String(o.conclusions || '').trim().length < 20) miss.push('the conclusions (20 characters or more)');
    if (String(o.business_plan || '').trim().length < 20) miss.push('the business plan summary (20 characters or more)');
    if (miss.length) throw httpErr(400, 'the ORSA cannot be submitted yet - it needs ' + miss.join('; '));
    const snap = snapshot(o), fp = 'sha256:' + crypto.createHash('sha256').update(JSON.stringify(snap)).digest('hex');
    Object.assign(o, { state: 'submitted', frozen: { snapshot: snap, fingerprint: fp, by: who.user, at: snap.at, note: b.note || null } }); ORSA().put(o);
    audit(who, 'orsa.submit', id, { fingerprint: fp, position: o.position, scenarios: snap.stress.length });
    return orsaView(o);
  }
  function orsaDecision(id, input, who) {
    person(who, 'record the Board decision on the ORSA');
    const b = body(input).oneOf('decision', ['approve', 'return'], { required: true }).str('board_ref', { max: 120 }).str('note', { required: true, min: 3, max: 1000 })
      .rule((x) => (x.decision === 'approve' && !x.board_ref ? 'board_ref is required to record the Board approval (the resolution or minutes reference)' : null)).done();
    const o = ORSA().get(id); if (!o) throw httpErr(404, 'no ORSA ' + id);
    if (o.state !== 'submitted') throw httpErr(409, 'the ORSA is ' + o.state + ' - only a submitted ORSA is decided');
    if (same(o.frozen.by, who.user)) throw httpErr(403, 'the person who submitted the ORSA cannot record its approval');
    const d = { decision: b.decision, board_ref: b.board_ref || null, note: b.note, by: who.user, at: iso(), fingerprint: o.frozen.fingerprint };
    o.decisions = (o.decisions || []).concat(d);
    if (b.decision === 'approve') o.state = 'approved'; else { o.state = 'returned'; o.frozen = null; }
    ORSA().put(o); audit(who, 'orsa.' + b.decision, id, { board_ref: d.board_ref, note: b.note, fingerprint: d.fingerprint });
    return orsaView(o);
  }
  function orsaView(o) {
    const p = POS().get(o.position);
    return Object.assign({}, o, { position_view: p ? posView(p) : null, overdue: o.state !== 'approved' && o.due < iso().slice(0, 10) });
  }
  function orsaReport(id, who) {
    const o = ORSA().get(id); if (!o) throw httpErr(404, 'no ORSA ' + id);
    if (!o.frozen) throw httpErr(409, 'the ORSA ' + id + ' is ' + o.state + ' - the report is made from a submitted or approved ORSA');
    audit(who, 'orsa.report', id, { state: o.state, fingerprint: o.frozen.fingerprint });
    return { id, year: o.year, state: o.state, fingerprint: o.frozen.fingerprint, submitted_by: o.frozen.by, submitted_at: o.frozen.at, decisions: o.decisions || [], content: o.frozen.snapshot,
      note: 'The ORSA as submitted, frozen with its fingerprint. Figures are those entered and confirmed by the company; the structure is a working layout, to be checked against the Insurance Authority\'s current ORSA requirements.' };
  }

  // ---------- performance per line of business
  function performance(p) {
    if (!p) return { lines: [], why: 'no confirmed capital position yet' };
    const st = settings(), L = p.lines || [], cap = L.reduce((n, l) => n + (l.allocated_capital || 0), 0);
    const rows = L.map((l) => { const rorc = div(l.net_profit, l.allocated_capital), comb = l.net_claims == null || !l.nep ? null : (l.net_claims + (l.expenses || 0)) / l.nep;
      const flags = []; if (st.hurdle_pct != null && rorc != null && rorc * 100 < st.hurdle_pct) flags.push('return on risk capital below the hurdle of ' + st.hurdle_pct + '%'); if (comb != null && comb > 1) flags.push('combined ratio above 100%');
      return { name: l.name, gwp: l.gwp == null ? null : l.gwp, net_profit: l.net_profit == null ? null : l.net_profit, allocated_capital: l.allocated_capital == null ? null : l.allocated_capital, capital_share: r4(div(l.allocated_capital, cap)), rorc: r4(rorc), loss_ratio: r4(div(l.net_claims, l.nep)), combined_ratio: r4(comb), flags }; })
      .sort((a, b) => (b.rorc == null ? -1e9 : b.rorc) - (a.rorc == null ? -1e9 : a.rorc));
    return { period: p.period, hurdle_pct: st.hurdle_pct, lines: rows, why: !L.length ? 'the position ' + p.period + ' has no lines of business' : st.hurdle_pct == null ? 'no hurdle rate set - returns are shown, not judged' : null };
  }

  // ---------- initiatives (M&A, transformation, new products, major IT)
  function proForma(i, p) { if (!p) return null; const A = p.available_capital + (i.capital_impact || 0), R = p.required_capital + (i.required_impact || 0), s = div(A, R); return { period: p.period, solvency_before: r4(div(p.available_capital, p.required_capital)), solvency_after: r4(s), judged: judge(settings().solvency_metric, s) }; }
  function initiativeSave(input, who) {
    person(who, 'raise an initiative');
    const b = body(input).str('title', { required: true, min: 3, max: 160 }).oneOf('kind', KINDS, { required: true }).str('description', { required: true, min: 10, max: 2000 }).str('sponsor', { required: true, max: 80 })
      .str('expected_benefit', { max: 500 }).num('capital_impact', { def: 0 }).num('required_impact', { def: 0 }).date('decision_due', { required: true }).done();
    const id = seq(INI(), 'IN'), rec = Object.assign({ id }, b, { state: 'awaiting_review', raised_by: who.user, raised_at: iso(), review: null, decision: null });
    INI().put(rec); audit(who, 'initiative.raise', id, { title: b.title, kind: b.kind, capital_impact: b.capital_impact, required_impact: b.required_impact });
    return Object.assign({}, rec, { pro_forma: proForma(rec, latest()) });
  }
  function initiativeReview(id, input, who) {
    person(who, 'review an initiative');
    const b = body(input).oneOf('appetite', ['within', 'conditional', 'outside'], { required: true }).str('risks', { required: true, min: 10, max: 2000 }).str('conditions', { max: 1000 }).list('linked_risks', { max: 20, item: 'id', def: [] })
      .rule((x) => (x.appetite === 'conditional' && !x.conditions ? 'conditions are required when the initiative is within appetite only on conditions' : null)).done();
    const i = INI().get(id); if (!i) throw httpErr(404, 'no initiative ' + id);
    if (i.state !== 'awaiting_review') throw httpErr(409, id + ' is ' + i.state.replace(/_/g, ' '));
    if (same(i.raised_by, who.user) || same(i.sponsor, who.user)) throw httpErr(403, 'the risk review is done by the risk function - not by the person who raised or sponsors the initiative');
    const bad = b.linked_risks.filter((r) => !C('br_risks').get(r)); if (bad.length) throw httpErr(400, 'linked_risks: not in the register: ' + bad.join(', '));
    i.review = Object.assign({}, b, { by: who.user, at: iso(), pro_forma: proForma(i, latest()) }); i.state = 'awaiting_decision'; INI().put(i);
    audit(who, 'initiative.review', id, { appetite: b.appetite, linked_risks: b.linked_risks.length });
    return Object.assign({}, i, { pro_forma: proForma(i, latest()) });
  }
  function initiativeDecision(id, input, who) {
    person(who, 'decide on an initiative');
    const b = body(input).oneOf('decision', ['approve', 'reject', 'defer'], { required: true }).str('note', { required: true, min: 3, max: 1000 }).done();
    const i = INI().get(id); if (!i) throw httpErr(404, 'no initiative ' + id);
    if (i.state !== 'awaiting_decision') throw httpErr(409, id + (i.state === 'awaiting_review' ? ' needs the risk review first' : ' is already decided'));
    if (same(i.raised_by, who.user) || same(i.review.by, who.user)) throw httpErr(403, 'the decision is taken by an administrator who neither raised nor reviewed the initiative');
    if (b.decision === 'approve' && i.review.appetite === 'outside' && b.note.length < 20) throw httpErr(400, 'note: approving an initiative the risk review found outside appetite needs the reason (20 characters or more)');
    i.decision = { decision: b.decision, note: b.note, by: who.user, at: iso(), outside_appetite: i.review.appetite === 'outside' }; i.state = b.decision === 'approve' ? 'approved' : b.decision === 'reject' ? 'rejected' : 'deferred'; INI().put(i);
    audit(who, 'initiative.' + b.decision, id, { appetite: i.review.appetite, outside_appetite: i.decision.outside_appetite, note: b.note });
    return Object.assign({}, i, { pro_forma: proForma(i, latest()) });
  }

  // ---------- settings, the view, signals
  function settingsSave(input, who) {
    person(who, 'change the capital settings');
    const b = body(input).str('solvency_metric', { max: 20, id: true }).str('liquidity_metric', { max: 20, id: true }).num('hurdle_pct', { min: -50, max: 100 }).str('currency', { max: 3, re: /^[A-Z]{3}$/, msg: 'currency must be a 3-letter code' }).date('orsa_due').done();
    for (const k of ['solvency_metric', 'liquidity_metric']) if (b[k] && !metric(b[k])) throw httpErr(400, k + ': no RAS metric ' + b[k]);
    const v = Object.assign(settings(), b); SET().put({ id: 'settings', values: v, by: who.user, at: iso() });
    audit(who, 'settings', 'settings', b); return v;
  }
  function view() {
    const st = settings(), P = POS().all().sort((a, b) => pOrder(b.period) - pOrder(a.period)).map(posView), lp = latest();
    const S = SCN().all().sort((a, b) => a.id.localeCompare(b.id)).map((s) => Object.assign({}, s, { result: lp ? stress(lp, s) : null }));
    const flags = [];
    if (!st.solvency_metric) flags.push({ area: 'settings', text: 'No RAS metric is linked as the solvency ratio - ratios are shown but not judged against appetite' });
    if (!lp) flags.push({ area: 'positions', text: P.length ? 'No capital position is confirmed yet - a second person confirms the figures' : 'No capital position entered yet - finance enters the available and required capital for a period' });
    if (lp && ratios(lp).solvency_judged.level >= 1) flags.push({ area: 'positions', text: 'Solvency ' + Math.round(ratios(lp).solvency * 100) + '% in ' + lp.period + ' is ' + ratios(lp).solvency_judged.zone.replace(/_/g, ' ') });
    S.filter((s) => s.status === 'approved' && s.result && s.result.below_100_after_actions).forEach((s) => flags.push({ area: 'stress', text: s.name + ': solvency stays below 100% even after the contingency actions' }));
    S.filter((s) => s.status === 'proposed').forEach((s) => flags.push({ area: 'stress', text: s.name + ' waits for approval (proposed by ' + s.proposed_by + ')' }));
    const O = ORSA().all().sort((a, b) => b.year - a.year).map(orsaView); O.filter((o) => o.overdue).forEach((o) => flags.push({ area: 'orsa', text: o.id + ' is past its due date ' + o.due + ' and not approved' }));
    const I = INI().all().sort((a, b) => b.id.localeCompare(a.id)).map((i) => Object.assign({}, i, { pro_forma: proForma(i, lp), overdue: !i.decision && i.decision_due < iso().slice(0, 10) }));
    I.filter((i) => i.overdue).forEach((i) => flags.push({ area: 'initiatives', text: i.title + ' passed its decision date ' + i.decision_due + ' (' + i.state.replace(/_/g, ' ') + ')' }));
    const metrics = C('br_metrics').all((m) => !m.retired).map((m) => ({ id: m.id, component: m.component, kind: m.kind, unit: m.unit, has_limits: !!m.limits })).sort((a, b) => String(a.component).localeCompare(String(b.component)));
    return { settings: st, positions: P, latest: lp ? posView(lp) : null, sensitivity: lp ? sensitivity(lp) : [], scenarios: S, orsa: O, performance: performance(lp), initiatives: I, metrics, flags, categories: CATS, kinds: KINDS,
      note: 'Every figure is entered by the company and confirmed by a second person - nothing is estimated. Ratios are judged against the Risk Appetite Statement only through the metrics linked in Settings.' };
  }
  function signals() {
    const out = [], lp = latest();
    if (lp) { const R = ratios(lp); if (R.solvency_judged.level >= 1) out.push({ fp: 'erm-capital:solvency:' + lp.period, source: 'platform', ref: lp.id, title: 'Solvency ' + Math.round(R.solvency * 100) + '% (' + lp.period + ') is ' + R.solvency_judged.zone.replace(/_/g, ' '), text: 'Capital, ORSA & Stress Testing: judged against the RAS metric ' + R.solvency_judged.component, severity: R.solvency_judged.level >= 2 ? 3 : 2, condition: true }); }
    if (lp) for (const s of SCN().all((x) => x.status === 'approved')) { const r = stress(lp, s); if (r.below_100_after_actions) out.push({ fp: 'erm-capital:stress:' + s.id, source: 'platform', ref: s.id, title: 'Stress scenario ' + s.name + ': solvency below 100% after the contingency actions', text: 'on the ' + lp.period + ' position', severity: 3, condition: true }); }
    for (const o of ORSA().all()) if (o.state !== 'approved' && o.due < iso().slice(0, 10)) out.push({ fp: 'erm-capital:orsa:' + o.id, source: 'platform', ref: o.id, title: o.id + ' is past its due date ' + o.due + ' and not approved by the Board', text: 'state: ' + o.state, severity: 2, condition: true });
    return out;
  }
  return { view, settingsSave, positionSave, positionConfirm, scenarioSave, scenarioDecision, orsaOpen, orsaEdit, orsaSubmit, orsaDecision, orsaReport, initiativeSave, initiativeReview, initiativeDecision, signals, stress, sensitivity };
}

function registerErmCapital(srv, app, X) {
  const W = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip });
  const ID = (ctx) => param(ctx.params.id, 'id');
  srv.route('GET', '/erm-cap', (ctx) => { ctx.need('viewer'); return X.view(); });
  srv.route('PUT', '/erm-cap/settings', (ctx) => { ctx.need('admin'); return X.settingsSave(ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-cap/positions', (ctx) => { ctx.need('operator'); return X.positionSave(ctx.body, W(ctx)); }, { maxBody: 64 * 1024 });
  srv.route('POST', '/erm-cap/positions/:id/confirm', (ctx) => { ctx.need('admin'); return X.positionConfirm(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-cap/scenarios', (ctx) => { ctx.need('operator'); return X.scenarioSave(ctx.body, W(ctx)); }, { maxBody: 32 * 1024 });
  srv.route('POST', '/erm-cap/scenarios/:id/decision', (ctx) => { ctx.need('admin'); return X.scenarioDecision(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-cap/orsa', (ctx) => { ctx.need('admin'); return X.orsaOpen(ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-cap/orsa/:id', (ctx) => { ctx.need('operator'); return X.orsaEdit(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 64 * 1024 });
  srv.route('POST', '/erm-cap/orsa/:id/submit', (ctx) => { ctx.need('operator'); return X.orsaSubmit(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-cap/orsa/:id/decision', (ctx) => { ctx.need('admin'); return X.orsaDecision(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('GET', '/erm-cap/orsa/:id/report', (ctx) => { ctx.need('operator'); return X.orsaReport(ID(ctx), W(ctx)); });
  srv.route('POST', '/erm-cap/initiatives', (ctx) => { ctx.need('operator'); return X.initiativeSave(ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/erm-cap/initiatives/:id/review', (ctx) => { ctx.need('operator'); return X.initiativeReview(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/erm-cap/initiatives/:id/decision', (ctx) => { ctx.need('admin'); return X.initiativeDecision(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
}

module.exports = { createErmCapital, registerErmCapital, CATS, KINDS };
