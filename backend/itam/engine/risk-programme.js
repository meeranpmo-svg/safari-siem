// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Enterprise Risk Programme - the parts of the enterprise risk management of an insurer that lived in Excel, run in the system on
 * top of Business Risk (engine/business-risk.js: the register, the methodology, the RAS metrics and their values).
 *
 * 1 REGISTER: Close a risk with a reason (treated / no longer applicable / merged into another). A Class III / IV risk, and every
 *   merge, is four-eyes: requested by one person, approved by a different administrator. A merge moves the appetite-metric links
 *   to the surviving risk. Every edit, assessment, category and close is in the risk's change log (business-risk.js logChange).
 * 2 ASSESSMENT CYCLE (RCSA): risk management opens a cycle for a period (e.g. 2026-Q4) over every open risk (or chosen
 *   departments); each risk is re-assessed (or confirmed unchanged, with a note) through Business Risk's assess, so the register
 *   and its history are the record; a department is signed off by a person who did not assess any of its risks; the risk
 *   committee approves (an administrator who did not open the cycle and signed no department off) or returns it with a reason.
 *   Approval freezes the cycle: the ratings, the class counts and every movement, compared with the previous approved cycle.
 * 3 RAS IN THE SYSTEM: a new metric, a change to a metric's definition, or retiring one is a PROPOSAL a different administrator
 *   approves (limits of an existing metric keep Business Risk's own limit-change approval). The year's RAS is approved by the
 *   Board as a frozen version (every metric and its limits, with a fingerprint): requested by one person, recorded by another;
 *   what changed since the approved version is shown.
 * 4 INSURANCE: the risk categories of an insurer (underwriting, reserving, reinsurance and counterparty, catastrophe and
 *   concentration, capital and solvency, market, credit, liquidity, operational, IT and cyber, conduct, regulatory, strategic) with
 *   a category suggested for each register risk from its words (a person confirms); metric TEMPLATES (definition, formula, kind,
 *   frequency - never a limit: limits come from the Board-approved RAS); an emerging-risks list, promoted to the register by a person.
 * 5 REPORTS: the Risk Committee pack, the Board report and the regulator (Insurance Authority) pack, built from the records above
 *   at the moment they are asked for. Their structure is a working layout, to be checked against the Authority's current template.
 *
 * Routes ({P} = /api/itam) - reads: viewer; writes: a person (never a service or AI identity), every one audited
 *   POST /brisk/risks/:id/close               operator {reason, into?, note}       Class III / IV and merges wait for a 2nd person
 *   POST /brisk/risks/:id/close/decision      admin    {decision, note}             not the requester
 *   GET  /brisk/risks/:id/changes             viewer   the change log
 *   GET  /brisk/cycles  | /brisk/cycles/:id   viewer   cycles; one cycle with its items, progress and comparison
 *   POST /brisk/cycles                        admin    {period, name?, due, departments?}
 *   POST /brisk/cycles/:id/submit             operator {risk, unchanged?, likelihood, impact, exposure, control_rating?, treatment_status?, note}
 *   POST /brisk/cycles/:id/signoff            operator {department, note?}         not an assessor of that department
 *   POST /brisk/cycles/:id/decision           admin    {decision: approve | return, note}   not the opener, not a signer
 *   POST /brisk/cycles/:id/cancel             admin    {note}
 *   GET  /brisk/ras/proposals                 viewer
 *   POST /brisk/ras/proposals                 operator {kind: new | edit | retire, metric?, fields{}, raw{}, template?, note}
 *   POST /brisk/ras/proposals/:id/decision    admin    {decision, note}             not the proposer
 *   GET  /brisk/ras/approvals                 viewer   the Board approvals and what changed since
 *   POST /brisk/ras/approvals                 operator {year, note}                freezes the current RAS for approval
 *   POST /brisk/ras/approvals/:id/decision    admin    {decision, board_ref, note}  not the requester
 *   GET  /brisk/catalogue                     viewer   categories, templates, a category per risk (recorded or suggested)
 *   POST /brisk/catalogue/assign              operator {pairs: [{risk, category}]}
 *   GET  /brisk/emerging                      viewer
 *   POST /brisk/emerging                      operator {title, description?, category, horizon, trend, impact, owner, signals?}
 *   POST /brisk/emerging/:id                  operator {..., state?: watching | dismissed, note}
 *   POST /brisk/emerging/:id/promote          operator {department, likelihood, impact, exposure?, owner, note}
 *   GET  /brisk/reports/:kind                 operator committee | board | regulator  (audited: it exports the register)
 */
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const ML = require('./brisk-ml');
const RAS = require('./brisk-ras');
const { rate, logChange } = require('./business-risk');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const CATEGORIES = [
  { id: 'underwriting', name: 'Underwriting risk', desc: 'Pricing, risk selection, product design and policy terms produce losses above what was priced.', words: ['underwrit', 'pricing', 'premium', 'tariff', 'product', 'policy', 'policies', 'acceptance', 'rating', 'actuarial', 'lapse', 'medical', 'motor', 'portfolio'] },
  { id: 'reserving', name: 'Reserving risk', desc: 'Technical reserves (outstanding claims, IBNR, premium deficiency) prove insufficient for the claims that arise.', words: ['reserve', 'reserving', 'ibnr', 'outstanding', 'claim', 'claims', 'settlement', 'run-off', 'actuary', 'ifrs'] },
  { id: 'reinsurance', name: 'Reinsurance and counterparty risk', desc: 'Reinsurance cover fails, is inadequate, or a reinsurer or other counterparty does not pay.', words: ['reinsur', 'treaty', 'retrocession', 'facultative', 'cession', 'counterparty', 'recoverable', 'reinsurer'] },
  { id: 'catastrophe', name: 'Catastrophe and concentration risk', desc: 'One event, area, line or customer group produces losses beyond the capacity of the portfolio.', words: ['catastroph', 'flood', 'earthquake', 'accumulation', 'concentration', 'pandemic', 'event', 'aggregate', 'exposure'] },
  { id: 'capital', name: 'Capital and solvency risk', desc: 'Available capital falls toward or below the regulatory solvency margin.', words: ['solvency', 'capital', 'margin', 'equity', 'dividend', 'own funds', 'regulatory capital'] },
  { id: 'market', name: 'Market and investment risk', desc: 'Changes in interest rates, equity prices, sukuk spreads or currency reduce the value of investments.', words: ['market', 'investment', 'equity', 'sukuk', 'interest', 'currency', 'return', 'benchmark', 'portfolio', 'asset'] },
  { id: 'credit', name: 'Credit and receivables risk', desc: 'Policyholders, brokers, agents or issuers do not pay what they owe.', words: ['credit', 'receivable', 'collection', 'debt', 'broker', 'agent', 'default', 'overdue', 'provision'] },
  { id: 'liquidity', name: 'Liquidity risk', desc: 'Cash is not available to pay claims and obligations when due without loss.', words: ['liquidity', 'cash', 'outflow', 'funding', 'treasury', 'deposit', 'forecast'] },
  { id: 'operational', name: 'Operational risk', desc: 'Failed processes, people, fraud, outsourcing or external events cause loss.', words: ['process', 'operation', 'fraud', 'staff', 'people', 'outsourc', 'vendor', 'supplier', 'document', 'manual', 'error', 'reconcil', 'continuity', 'branch'] },
  { id: 'technology', name: 'IT and cyber risk', desc: 'Systems are unavailable, compromised or changed without control; data is lost or exposed.', words: ['system', 'server', 'network', 'cyber', 'security', 'backup', 'patch', 'access', 'application', 'outage', 'data', 'technology', 'disaster', 'recovery'] },
  { id: 'conduct', name: 'Conduct and customer risk', desc: 'Customers are treated unfairly: mis-selling, claim handling, complaints, disclosure.', words: ['customer', 'complaint', 'conduct', 'mis-sell', 'disclosure', 'fair', 'service', 'policyholder', 'satisfaction'] },
  { id: 'regulatory', name: 'Regulatory and compliance risk', desc: 'Breach of Insurance Authority rules, AML / CTF, PDPL, Zakat and tax, or other law; findings not closed.', words: ['regulat', 'compliance', 'authority', 'sama', 'circular', 'aml', 'pdpl', 'zakat', 'tax', 'law', 'legal', 'penalty', 'audit', 'finding', 'licence'] },
  { id: 'strategic', name: 'Strategic and reputational risk', desc: 'Strategy, growth, competition, governance or reputation leave the company short of its plan.', words: ['strateg', 'growth', 'competition', 'market share', 'plan', 'governance', 'board', 'reputation', 'brand', 'merger', 'budget'] },
];
const CAT_IDS = CATEGORIES.map((c) => c.id);
// metric TEMPLATES: definitions an insurer commonly monitors - never a limit; the limits are the Board-approved RAS's
const TEMPLATES = [
  ['T-CAP-01', 'capital', 'Solvency coverage ratio', 'Available solvency capital over the required solvency margin', 'available capital / required solvency margin', 'floor', '%', 'quarterly'],
  ['T-CAP-02', 'capital', 'Return on equity', 'Net profit over average shareholders\' equity', 'net profit / average equity', 'floor', '%', 'quarterly'],
  ['T-UW-01', 'underwriting', 'Loss ratio (by line of business)', 'Incurred claims over net earned premium', 'net incurred claims / net earned premium', 'ceiling', '%', 'monthly'],
  ['T-UW-02', 'underwriting', 'Combined ratio', 'Claims plus expenses over net earned premium', '(net incurred claims + expenses) / net earned premium', 'ceiling', '%', 'quarterly'],
  ['T-UW-03', 'underwriting', 'Expense ratio', 'Operating and acquisition expenses over net earned premium', 'expenses / net earned premium', 'ceiling', '%', 'quarterly'],
  ['T-UW-04', 'underwriting', 'Premium growth against plan', 'Gross written premium against the business plan', 'GWP actual / GWP plan', 'band', '%', 'monthly'],
  ['T-RES-01', 'reserving', 'Reserve run-off deviation', 'Prior-year reserves against the claims later paid and re-reserved', '(prior reserve - paid - re-reserved) / prior reserve', 'band', '%', 'quarterly'],
  ['T-RES-02', 'reserving', 'Claims settled within the service standard', 'Claims settled within the target number of days', 'claims settled in time / claims settled', 'floor', '%', 'monthly'],
  ['T-RI-01', 'reinsurance', 'Largest reinsurer share of recoverables', 'Reinsurance recoverables due from the largest reinsurer', 'largest reinsurer recoverables / total recoverables', 'ceiling', '%', 'quarterly'],
  ['T-RI-02', 'reinsurance', 'Recoverables from reinsurers below the minimum rating', 'Recoverables from reinsurers rated below the policy minimum', 'recoverables below minimum rating / total recoverables', 'ceiling', '%', 'quarterly'],
  ['T-CAT-01', 'catastrophe', 'Net probable maximum loss against capital', 'Net PML of the worst modelled event over available capital', 'net PML / available capital', 'ceiling', '%', 'quarterly'],
  ['T-CAT-02', 'catastrophe', 'Largest single risk retention', 'Net retention on the largest single risk', 'largest net retention / available capital', 'ceiling', '%', 'quarterly'],
  ['T-MKT-01', 'market', 'Single issuer investment concentration', 'Investments in the largest single issuer', 'largest issuer / total investments', 'ceiling', '%', 'monthly'],
  ['T-MKT-02', 'market', 'Investment return against benchmark', 'Portfolio return over its benchmark', 'portfolio return - benchmark return', 'floor', '%', 'quarterly'],
  ['T-CR-01', 'credit', 'Premium receivables over 180 days', 'Receivables outstanding more than 180 days', 'receivables > 180 days / total receivables', 'ceiling', '%', 'monthly'],
  ['T-LIQ-01', 'liquidity', 'Liquid assets against expected outflows', 'Liquid assets over the expected claims and expense outflows of the next three months', 'liquid assets / 3-month expected outflows', 'floor', 'x', 'monthly'],
  ['T-OPS-01', 'operational', 'Operational loss events', 'Operational loss events above the reporting threshold', 'count of loss events', 'ceiling', 'count', 'monthly'],
  ['T-OPS-02', 'operational', 'Overdue internal audit actions', 'Audit actions past their due date', 'count of overdue actions', 'ceiling', 'count', 'monthly'],
  ['T-IT-01', 'technology', 'Core system availability', 'Availability of the core insurance system in business hours', 'uptime / scheduled time', 'floor', '%', 'monthly'],
  ['T-IT-02', 'technology', 'Critical vulnerabilities past their fix date', 'Critical vulnerabilities open beyond the patch policy', 'count', 'ceiling', 'count', 'monthly'],
  ['T-CON-01', 'conduct', 'Complaints per 1,000 policies', 'Customer complaints received per 1,000 policies in force', 'complaints / policies in force x 1000', 'ceiling', 'count', 'monthly'],
  ['T-REG-01', 'regulatory', 'Regulatory findings past their due date', 'Insurance Authority and other regulatory findings not closed by their due date', 'count', 'ceiling', 'count', 'monthly'],
  ['T-REG-02', 'regulatory', 'Regulatory reporting submitted on time', 'Returns submitted to the regulator by their deadline', 'on-time returns / returns due', 'floor', '%', 'quarterly'],
].map(([id, category, component, description, formula, kind, unit, frequency]) => ({ id, category, component, description, formula, kind, unit, frequency }));
const HORIZON = ['0-1y', '1-3y', '3-5y', '5y+'], TREND = ['rising', 'stable', 'falling'];
const CLOSE_REASONS = ['treated', 'no_longer_applicable', 'merged'];
const PERIOD = /^\d{4}-(Q[1-4]|H[12]|FY)$/;
const FIELDS = ['section_title', 'component', 'description', 'formula', 'source', 'responsibility', 'rbs', 'frequency'];
const crypto = require('crypto');

function createRiskProgramme(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString(), C = (n) => app.store.collection(n);
  const RISK = () => C('br_risks'), MET = () => C('br_metrics'), CYC = () => C('rp_cycles'), PROP = () => C('rp_metric_props'), YEAR = () => C('rp_ras_years'), EMG = () => C('rp_emerging');
  const BR = () => { const b = app.addons && app.addons.businessRisk; if (!b) throw httpErr(424, 'Business Risk is not installed'); return b; };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'risk-programme.' + action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const same = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
  const seq = (col, prefix) => { let n = 0; for (const x of col.all()) { const m = new RegExp('^' + prefix + '-(\\d+)$').exec(x.id); if (m) n = Math.max(n, Number(m[1])); } return prefix + '-' + String(n + 1).padStart(4, '0'); };
  const ratingOf = (r) => { const R = rate(r.likelihood, r.impact, r.exposure); return { likelihood: r.likelihood, impact: r.impact, exposure: r.exposure, inherent: R.inherent, label: R.label, residual: R.residual, class: R.class }; };

  // ---------- 1 register: close (four-eyes for Class III / IV and merges), the change log
  function closeApply(r, req, approver) {
    const at = iso(), from = r.status;
    r.status = 'solved'; r.closed = { reason: req.reason, into: req.into || null, note: req.note, by: req.by, approved_by: approver || null, at };
    if (req.reason === 'merged') {
      r.merged_into = req.into; const into = RISK().get(req.into);
      for (const m of MET().all((x) => (x.links || []).includes(r.id))) { m.links = [...new Set(m.links.filter((l) => l !== r.id).concat([req.into]))].sort(); MET().put(m); }
      logChange(into, { user: req.by }, 'merged in', [{ field: 'merged', from: null, to: r.id + ' ' + r.title }], req.note, at); RISK().put(into);
    }
    logChange(r, { user: approver || req.by }, 'closed', [{ field: 'status', from, to: 'solved' }, { field: 'close_reason', from: null, to: req.reason + (req.into ? ' into ' + req.into : '') }], req.note, at);
    r.close_request = null; RISK().put(r);
  }
  function closeRequest(id, input, who) {
    person(who, 'close a risk');
    const b = body(input || {}).oneOf('reason', CLOSE_REASONS, { required: true }).str('into', { max: 20, id: true }).str('note', { required: true, min: 5, max: 1000 })
      .rule((o) => (o.reason === 'merged' && !o.into ? 'into is required to merge: the risk that stays' : null)).done();
    const r = RISK().get(id); if (!r) throw httpErr(404, 'no risk ' + id);
    if (r.status === 'solved') throw httpErr(409, id + ' is already closed');
    if (r.close_request && r.close_request.status === 'pending') throw httpErr(409, id + ' already has a close waiting for approval (requested by ' + r.close_request.by + ')');
    if (b.reason === 'merged') { const t = RISK().get(b.into); if (!t) throw httpErr(400, 'into: no risk ' + b.into); if (b.into === id) throw httpErr(400, 'into: a risk cannot be merged into itself'); if (t.status === 'solved') throw httpErr(400, 'into: ' + b.into + ' is closed - merge into an open risk'); }
    const R = rate(r.likelihood, r.impact, r.exposure), req = { status: 'pending', reason: b.reason, into: b.into || null, note: b.note, by: who.user, at: iso(), class: R.class };
    if ((R.residual || 0) >= 3 || b.reason === 'merged') { r.close_request = req; RISK().put(r); audit(who, 'risk.close.request', id, { reason: b.reason, into: b.into, class: R.class }); return { pending: true, risk: BR().riskGet(id) }; }
    closeApply(r, req, null); audit(who, 'risk.close', id, { reason: b.reason, class: R.class }); return { pending: false, risk: BR().riskGet(id) };
  }
  function closeDecision(id, input, who) {
    person(who, 'approve closing a risk');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 }).rule((o) => (o.decision === 'reject' && !o.note ? 'note is required to reject: say why' : null)).done();
    const r = RISK().get(id); if (!r) throw httpErr(404, 'no risk ' + id);
    const q = r.close_request; if (!q || q.status !== 'pending') throw httpErr(409, 'no close is waiting for ' + id);
    if (same(q.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked to close ' + id + ' and cannot also approve it');
    if (b.decision === 'reject') { r.close_request = Object.assign(q, { status: 'rejected', decided_by: who.user, decided_at: iso(), decision_note: b.note }); logChange(r, who, 'close refused', [{ field: 'close_request', from: q.reason, to: 'rejected' }], b.note, iso()); RISK().put(r); }
    else { if (q.reason === 'merged') { const t = RISK().get(q.into); if (!t || t.status === 'solved') throw httpErr(409, 'the risk to merge into (' + q.into + ') is no longer open - reject this and ask again'); } closeApply(r, q, who.user); }
    audit(who, 'risk.close.' + b.decision, id, { requested_by: q.by, reason: q.reason, into: q.into });
    return BR().riskGet(id);
  }
  function changes(id) { const r = RISK().get(id); if (!r) throw httpErr(404, 'no risk ' + id); return { id, code: r.code, title: r.title, changes: (r.changelog || []).slice().reverse(), ratings: (r.history || []).slice().reverse(), close_request: r.close_request || null, closed: r.closed || null }; }

  // ---------- 2 the assessment cycle (RCSA)
  function cycleView(c, full) {
    const items = c.items, depts = [...new Set(items.map((i) => i.department))].sort();
    const by = depts.map((d) => { const I = items.filter((i) => i.department === d), s = c.signoffs.find((x) => x.department === d); return { department: d, risks: I.length, submitted: I.filter((i) => i.state === 'submitted').length, signed: s || null }; });
    const done = items.filter((i) => i.state === 'submitted').length, moved = (i) => (i.after && i.before.residual != null && i.after.residual != null ? Math.sign(i.after.residual - i.before.residual) || Math.sign((i.after.inherent || 0) - (i.before.inherent || 0)) : 0);
    const out = { id: c.id, name: c.name, period: c.period, due: c.due, state: c.state, opened_by: c.opened_by, opened_at: c.opened_at, departments_scope: c.departments, decision: c.decision || null, returns: c.returns || [],
      progress: { risks: items.length, submitted: done, pct: items.length ? Math.round(done / items.length * 100) : 0, unchanged: items.filter((i) => i.unchanged).length, up: items.filter((i) => moved(i) > 0).length, down: items.filter((i) => moved(i) < 0).length,
        departments: by.length, signed: by.filter((x) => x.signed).length, overdue: c.state === 'open' && c.due < iso().slice(0, 10) ? items.length - done : 0 }, by_department: by };
    if (full) { out.items = items.map((i) => Object.assign({}, i, { movement: moved(i) > 0 ? 'up' : moved(i) < 0 ? 'down' : i.after ? 'same' : null })); out.snapshot = c.snapshot || null; out.compare = compare(c); }
    return out;
  }
  function compare(c) {
    const prev = CYC().all((x) => x.state === 'approved' && x.id !== c.id && (x.decision.at < (c.decision ? c.decision.at : '9999'))).sort((a, b) => b.decision.at.localeCompare(a.decision.at))[0];
    if (!prev) return { previous: null, note: 'the first approved cycle - movements are against the ratings at the start of this cycle' };
    const P = new Map(prev.items.map((i) => [i.risk, i.after || i.before])), rows = [];
    for (const i of c.items) { const p = P.get(i.risk), a = i.after || i.before; rows.push({ risk: i.risk, code: i.code, title: i.title, department: i.department, previous: p ? p.class : null, now: a.class, change: !p ? 'new' : (a.residual || 0) > (p.residual || 0) ? 'up' : (a.residual || 0) < (p.residual || 0) ? 'down' : 'same' }); }
    const cur = new Set(c.items.map((i) => i.risk)), left = prev.items.filter((i) => !cur.has(i.risk)).map((i) => ({ risk: i.risk, code: i.code, title: i.title, department: i.department, previous: (i.after || i.before).class, now: null, change: 'left' }));
    const all = rows.concat(left), n = (k) => all.filter((x) => x.change === k).length;
    return { previous: { id: prev.id, period: prev.period, approved_at: prev.decision.at }, summary: { up: n('up'), down: n('down'), same: n('same'), new: n('new'), left: n('left') }, rows: all.filter((x) => x.change !== 'same').slice(0, 300) };
  }
  function cycleGet(id) { const c = CYC().get(id); if (!c) throw httpErr(404, 'no cycle ' + id); return cycleView(c, true); }
  function cycles() { return { cycles: CYC().all().sort((a, b) => b.opened_at.localeCompare(a.opened_at)).map((c) => cycleView(c, false)), departments: [...new Set(RISK().all((r) => r.status !== 'solved').map((r) => r.department).filter(Boolean))].sort() }; }
  function cycleOpen(input, who) {
    person(who, 'open an assessment cycle');
    const b = body(input || {}).str('period', { required: true, max: 7, re: PERIOD, msg: 'period must be YYYY-Qn, YYYY-H1 / H2 or YYYY-FY' }).str('name', { max: 120 }).date('due', { required: true }).list('departments', { item: 'str', itemMax: 80, max: 100, unique: true }).done();
    if (b.due < iso().slice(0, 10)) throw httpErr(400, 'due cannot be in the past');
    if (CYC().all((c) => c.state === 'open' || c.state === 'review').length) throw httpErr(409, 'an assessment cycle is already running - approve, return or cancel it first');
    const id = 'RC-' + b.period; if (CYC().get(id) && CYC().get(id).state !== 'cancelled') throw httpErr(409, 'period: a cycle for ' + b.period + ' already exists');
    const scope = b.departments || [], R = RISK().all((r) => r.status !== 'solved' && (!scope.length || scope.includes(r.department)));
    if (!R.length) throw httpErr(409, scope.length ? 'departments: no open risk in ' + scope.join(', ') : 'the register has no open risk to assess - import or add risks first');
    const c = { id, period: b.period, name: b.name || 'Risk and control self-assessment ' + b.period, due: b.due, departments: scope, state: 'open', opened_by: who.user, opened_at: iso(), signoffs: [], returns: [],
      items: R.sort((a, c2) => a.id.localeCompare(c2.id)).map((r) => ({ risk: r.id, code: r.code, title: r.title, department: r.department || '(none)', owner: r.owner || '', before: ratingOf(r), state: 'pending' })) };
    CYC().put(c); audit(who, 'cycle.open', id, { period: b.period, risks: c.items.length, departments: scope.length ? scope : 'all', due: b.due });
    return cycleView(c, true);
  }
  function running(id) { const c = CYC().get(id); if (!c) throw httpErr(404, 'no cycle ' + id); return c; }
  function cycleSubmit(id, input, who) {
    person(who, 'assess a risk');
    const c = running(id); if (c.state !== 'open') throw httpErr(409, id + ' is ' + c.state + ' - assessments are closed');
    const b = body(input || {}).str('risk', { required: true, max: 20, id: true }).bool('unchanged', { def: false }).int('likelihood', { min: 1, max: 5 }).int('impact', { min: 1, max: 5 }).int('exposure', { min: 1, max: 5 })
      .str('control_rating', { max: 40 }).str('treatment_status', { max: 40 }).str('note', { required: true, min: 3, max: 1000 })
      .rule((o) => (!o.unchanged && (o.likelihood == null || o.impact == null || o.exposure == null) ? 'likelihood, impact and exposure are required (or unchanged: true)' : null)).done();
    const it = c.items.find((i) => i.risk === b.risk); if (!it) throw httpErr(400, 'risk: ' + b.risk + ' is not in this cycle');
    if (c.signoffs.some((s) => s.department === it.department)) throw httpErr(409, it.department + ' is already signed off - ask the committee to return the cycle to change it');
    const r = RISK().get(b.risk); if (!r) throw httpErr(409, b.risk + ' is no longer in the register');
    const L = b.unchanged ? r.likelihood : b.likelihood, I = b.unchanged ? r.impact : b.impact, X = b.unchanged ? r.exposure : b.exposure;
    if (L == null || I == null || X == null) throw httpErr(400, 'unchanged: ' + b.risk + ' is not fully rated - give likelihood, impact and exposure');
    BR().assess(b.risk, { likelihood: L, impact: I, exposure: X, control_rating: b.control_rating, treatment_status: b.treatment_status, note: c.period + ' self-assessment' + (b.unchanged ? ' (unchanged)' : '') + ': ' + b.note }, who);
    Object.assign(it, { state: 'submitted', unchanged: b.unchanged, after: ratingOf(RISK().get(b.risk)), note: b.note, by: who.user, at: iso() });
    CYC().put(c); audit(who, 'cycle.submit', id, { risk: b.risk, unchanged: b.unchanged, from: it.before.class, to: it.after.class });
    return cycleView(c, true);
  }
  function cycleSignoff(id, input, who) {
    person(who, 'sign off a department');
    const c = running(id); if (c.state !== 'open') throw httpErr(409, id + ' is ' + c.state);
    const b = body(input || {}).str('department', { required: true, max: 80 }).str('note', { max: 1000 }).done();
    const I = c.items.filter((i) => i.department === b.department); if (!I.length) throw httpErr(400, 'department: ' + b.department + ' has no risk in this cycle');
    if (c.signoffs.some((s) => s.department === b.department)) throw httpErr(409, b.department + ' is already signed off');
    const left = I.filter((i) => i.state !== 'submitted'); if (left.length) throw httpErr(409, b.department + ': ' + left.length + ' risk(s) not assessed yet (' + left.slice(0, 5).map((i) => i.code).join(', ') + ')');
    if (I.some((i) => same(i.by, who.user))) throw httpErr(403, 'four eyes: ' + who.user + ' assessed risks of ' + b.department + ' and cannot also sign it off');
    c.signoffs.push({ department: b.department, by: who.user, at: iso(), note: b.note || '' });
    const all = [...new Set(c.items.map((i) => i.department))].every((d) => c.signoffs.some((s) => s.department === d)); if (all) c.state = 'review';
    CYC().put(c); audit(who, 'cycle.signoff', id, { department: b.department, risks: I.length, ready_for_committee: all });
    return cycleView(c, true);
  }
  function cycleDecision(id, input, who) {
    person(who, 'approve an assessment cycle');
    const c = running(id); if (c.state !== 'review') throw httpErr(409, id + ' is ' + c.state + (c.state === 'open' ? ' - every department must be signed off first' : ''));
    const b = body(input || {}).oneOf('decision', ['approve', 'return'], { required: true }).str('note', { max: 1000 }).rule((o) => (o.decision === 'return' && !o.note ? 'note is required to return: say what to correct' : null)).done();
    if (same(c.opened_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' opened this cycle and cannot also approve it');
    if (c.signoffs.some((s) => same(s.by, who.user))) throw httpErr(403, 'four eyes: ' + who.user + ' signed off a department of this cycle and cannot also approve it');
    if (b.decision === 'return') { c.returns.push({ by: who.user, at: iso(), note: b.note, signoffs: c.signoffs }); c.signoffs = []; c.state = 'open'; }
    else {
      const cls = [1, 2, 3, 4].map((k) => c.items.filter((i) => (i.after || i.before).residual === k).length);
      c.decision = { by: who.user, at: iso(), note: b.note || '' }; c.state = 'approved';
      c.snapshot = { at: iso(), risks: c.items.length, classes: cls, unchanged: c.items.filter((i) => i.unchanged).length, fingerprint: crypto.createHash('sha256').update(JSON.stringify(c.items.map((i) => [i.risk, i.after]))).digest('hex').slice(0, 16) };
    }
    CYC().put(c); audit(who, 'cycle.' + b.decision, id, { period: c.period, risks: c.items.length, opened_by: c.opened_by });
    return cycleView(c, true);
  }
  function cycleCancel(id, input, who) {
    person(who, 'cancel an assessment cycle');
    const b = body(input || {}).str('note', { required: true, min: 5, max: 1000 }).done();
    const c = running(id); if (c.state === 'approved' || c.state === 'cancelled') throw httpErr(409, id + ' is ' + c.state);
    c.state = 'cancelled'; c.cancelled = { by: who.user, at: iso(), note: b.note }; CYC().put(c); audit(who, 'cycle.cancel', id, { submitted: c.items.filter((i) => i.state === 'submitted').length });
    return cycleView(c, false);
  }

  // ---------- 3 the RAS in the system: proposals (four-eyes) and the Board approval of the year's RAS
  function limitsOf(R0) {
    if (R0 === undefined || R0 === null) return null;
    if (typeof R0 !== 'object' || Array.isArray(R0)) throw httpErr(400, 'raw must be {' + RAS.KEYS.join(', ') + '}');
    let v = body(R0); for (const k of RAS.KEYS) v = v.str(k, { max: 80 }); const o = v.done(); return Object.fromEntries(RAS.KEYS.map((k) => [k, o[k] || '']));
  }
  function proposals() { return { proposals: PROP().all().sort((a, b) => b.at.localeCompare(a.at)).slice(0, 300), templates: TEMPLATES, sections: [...new Map(MET().all((m) => !m.retired).map((m) => [m.section, { section: m.section, title: m.section_title }])).values()].sort((a, b) => a.section - b.section) }; }
  function propose(input, who) {
    person(who, 'propose a metric change');
    const src = input || {}, b = body(src).oneOf('kind', ['new', 'edit', 'retire'], { required: true }).str('metric', { max: 20, id: true }).str('template', { max: 20, id: true }).str('note', { required: true, min: 5, max: 1000 }).done();
    if (src.fields !== undefined && (typeof src.fields !== 'object' || Array.isArray(src.fields) || src.fields === null)) throw httpErr(400, 'fields must be an object');
    const f = body(src.fields || {}).str('section_title', { max: 80 }).str('component', { max: 120 }).str('description', { max: 2000 }).str('formula', { max: 500 }).str('source', { max: 200 }).str('responsibility', { max: 80 }).str('rbs', { max: 80 }).oneOf('frequency', ['monthly', 'quarterly']).done();
    const raw = limitsOf(src.raw);
    if (b.template && !TEMPLATES.some((x) => x.id === b.template)) throw httpErr(400, 'template: no template ' + b.template);
    let cur = null;
    if (b.kind !== 'new') { if (!b.metric) throw httpErr(400, 'metric is required to ' + b.kind); cur = MET().get(b.metric); if (!cur) throw httpErr(400, 'metric: no metric ' + b.metric); if (cur.retired) throw httpErr(409, b.metric + ' is retired'); }
    if (b.kind === 'new') { for (const k of ['section_title', 'component', 'description', 'responsibility']) if (!f[k]) throw httpErr(400, 'fields.' + k + ' is required for a new metric'); }
    if (b.kind === 'edit') { if (raw) throw httpErr(400, 'raw: the limits of an existing metric change through its limit change (Risk appetite -> Limits), approved by a second administrator'); if (!Object.keys(f).length) throw httpErr(400, 'fields: say what changes'); }
    if (b.kind !== 'new' && PROP().all((p) => p.state === 'pending' && p.metric === b.metric).length) throw httpErr(409, b.metric + ' already has a proposal waiting');
    let P = null; if (raw) { P = ML.parseLimits(raw); if (P.issues.length && P.kind !== 'manual') throw httpErr(400, 'raw: ' + P.issues.join('; ')); }
    if (b.kind === 'new' && MET().all((m) => !m.retired && same(m.component, f.component) && same(m.section_title, f.section_title)).length) throw httpErr(409, 'fields.component: "' + f.component + '" already exists in ' + f.section_title);
    const p = { id: seq(PROP(), 'MP'), kind: b.kind, metric: b.metric || null, template: b.template || null, fields: f, raw, limits_kind: P ? P.kind : null, note: b.note, state: 'pending', by: who.user, at: iso(),
      before: cur ? Object.fromEntries(FIELDS.map((k) => [k, cur[k] == null ? null : cur[k]])) : null };
    PROP().put(p); audit(who, 'ras.propose.' + b.kind, p.id, { metric: p.metric, component: f.component || (cur && cur.component), template: p.template, fields: Object.keys(f) });
    return p;
  }
  function proposalDecision(id, input, who) {
    person(who, 'approve a metric change');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 }).rule((o) => (o.decision === 'reject' && !o.note ? 'note is required to reject: say why' : null)).done();
    const p = PROP().get(id); if (!p) throw httpErr(404, 'no proposal ' + id); if (p.state !== 'pending') throw httpErr(409, id + ' is already ' + p.state);
    if (same(p.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' proposed ' + id + ' and cannot also approve it');
    Object.assign(p, { state: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), decision_note: b.note || '' });
    if (b.decision === 'approve') {
      if (p.kind === 'new') {
        const act = MET().all((m) => !m.retired), sec = act.find((m) => same(m.section_title, p.fields.section_title)), all = MET().all();
        const section = sec ? sec.section : Math.max(0, ...all.map((m) => m.section || 0)) + 1, n = Math.max(0, ...all.filter((m) => m.section === section).map((m) => Number((/\.(\d+)/.exec(m.id) || [0, 0])[1]))) + 1;
        const mid = 'RAS-' + String(section).padStart(2, '0') + '.' + String(n).padStart(2, '0'), raw = p.raw || Object.fromEntries(RAS.KEYS.map((k) => [k, ''])), P = ML.parseLimits(raw);
        MET().put({ id: mid, section, section_title: sec ? sec.section_title : p.fields.section_title, component: p.fields.component, description: p.fields.description, formula: p.fields.formula || '', source: p.fields.source || '', responsibility: p.fields.responsibility, rbs: p.fields.rbs || '',
          raw, kind: P.kind, unit: P.unit, limits: P.limits, issues: P.issues, question: P.question || null, frequency: p.fields.frequency || 'monthly', links: [], origin: 'system', template: p.template, proposed_by: p.by, approved_by: who.user, created_at: iso() });
        p.metric = mid;
      } else {
        const m = MET().get(p.metric); if (!m || m.retired) throw httpErr(409, p.metric + ' is no longer active - reject this proposal');
        if (p.kind === 'edit') { for (const [k, v] of Object.entries(p.fields)) m[k] = v; m.edited = { by: p.by, approved_by: who.user, at: iso() }; }
        else m.retired = { by: p.by, approved_by: who.user, at: iso(), note: p.note };
        MET().put(m);
      }
    }
    PROP().put(p); audit(who, 'ras.proposal.' + b.decision, id, { kind: p.kind, metric: p.metric, proposed_by: p.by });
    return p;
  }
  const rasFrozen = () => MET().all((m) => !m.retired).sort((a, b) => a.id.localeCompare(b.id)).map((m) => ({ id: m.id, section_title: m.section_title, component: m.component, responsibility: m.responsibility, frequency: m.frequency || 'monthly', raw: m.raw, kind: m.kind }));
  const fpOf = (ms) => crypto.createHash('sha256').update(JSON.stringify(ms)).digest('hex').slice(0, 16);
  function drift(a) {
    const cur = rasFrozen(), A = new Map(a.metrics.map((m) => [m.id, m])), N = new Map(cur.map((m) => [m.id, m]));
    return { added: cur.filter((m) => !A.has(m.id)).map((m) => ({ id: m.id, component: m.component })), removed: a.metrics.filter((m) => !N.has(m.id)).map((m) => ({ id: m.id, component: m.component })),
      limits_changed: cur.filter((m) => A.has(m.id) && JSON.stringify(A.get(m.id).raw) !== JSON.stringify(m.raw)).map((m) => ({ id: m.id, component: m.component, approved: A.get(m.id).raw, now: m.raw })), unchanged: fpOf(cur) === a.fingerprint };
  }
  function approvals() {
    const L = YEAR().all().sort((a, b) => b.at.localeCompare(a.at)), year = new Date(now()).getUTCFullYear(), cur = L.find((a) => a.state === 'approved' && a.year === year) || L.find((a) => a.state === 'approved') || null;
    return { approvals: L.map((a) => Object.assign({}, a, { metrics: undefined, count: a.metrics.length })), current: cur ? Object.assign({ id: cur.id, year: cur.year, decided_by: cur.decided_by, decided_at: cur.decided_at, board_ref: cur.board_ref, fingerprint: cur.fingerprint, count: cur.metrics.length }, { drift: drift(cur) }) : null, metrics_now: rasFrozen().length };
  }
  function approvalRequest(input, who) {
    person(who, 'ask for the RAS approval');
    const b = body(input || {}).int('year', { required: true, min: 2020, max: 2100 }).str('note', { required: true, min: 5, max: 1000 }).done();
    if (YEAR().all((a) => a.state === 'pending').length) throw httpErr(409, 'a RAS approval is already waiting');
    const ms = rasFrozen(); if (!ms.length) throw httpErr(409, 'the RAS has no metric - import it or add metrics first');
    const v = YEAR().all((a) => a.year === b.year).length + 1;
    const a = { id: 'RY-' + b.year + '-v' + v, year: b.year, version: v, state: 'pending', requested_by: who.user, at: iso(), note: b.note, metrics: ms, fingerprint: fpOf(ms) };
    YEAR().put(a); audit(who, 'ras.approval.request', a.id, { metrics: ms.length, fingerprint: a.fingerprint }); return Object.assign({}, a, { count: ms.length });
  }
  function approvalDecision(id, input, who) {
    person(who, 'record the Board approval of the RAS');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('board_ref', { max: 120 }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'approve' && !o.board_ref ? 'board_ref is required: the Board resolution or meeting the RAS was approved in' : o.decision === 'reject' && !o.note ? 'note is required to reject: say why' : null)).done();
    const a = YEAR().get(id); if (!a) throw httpErr(404, 'no approval ' + id); if (a.state !== 'pending') throw httpErr(409, id + ' is already ' + a.state);
    if (same(a.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked for this approval and cannot also record it');
    if (b.decision === 'approve' && fpOf(rasFrozen()) !== a.fingerprint) throw httpErr(409, 'the RAS changed after this approval was asked for - reject it and ask again, so the Board approves what is in the system');
    Object.assign(a, { state: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), board_ref: b.board_ref || '', decision_note: b.note || '' });
    if (b.decision === 'approve') for (const o of YEAR().all((x) => x.state === 'approved' && x.year === a.year && x.id !== a.id)) { o.state = 'superseded'; o.superseded_by = a.id; YEAR().put(o); }
    YEAR().put(a); audit(who, 'ras.approval.' + b.decision, id, { year: a.year, board_ref: b.board_ref, requested_by: a.requested_by, metrics: a.metrics.length });
    return Object.assign({}, a, { metrics: undefined, count: a.metrics.length });
  }

  // ---------- 4 insurance: categories, templates, a category per risk, emerging risks
  function suggestCat(r) {
    const text = (s) => String(s || '').toLowerCase(), parts = [[text(r.area).replace(/_/g, ' '), 3], [text(r.primary_cat), 2], [text(r.secondary_cat), 1], [text(r.title), 2], [text(r.description), 1]];
    let best = null;
    for (const c of CATEGORIES) { let s = 0; const hit = []; for (const w of c.words) for (const [p, wt] of parts) if (p.includes(w)) { s += wt; if (!hit.includes(w)) hit.push(w); } if (s && (!best || s > best.score)) best = { id: c.id, score: s, words: hit.slice(0, 5) }; }
    return best;
  }
  function catalogue() {
    const R = RISK().all((r) => r.status !== 'solved'), rows = R.sort((a, b) => a.id.localeCompare(b.id)).map((r) => { const s = r.ins_cat ? null : suggestCat(r); return { id: r.id, code: r.code, title: r.title, department: r.department, area: r.area, category: r.ins_cat || null, suggested: s, class: rate(r.likelihood, r.impact, r.exposure).class }; });
    const M = MET().all((m) => !m.retired);
    const cats = CATEGORIES.map((c) => ({ id: c.id, name: c.name, desc: c.desc, risks: rows.filter((x) => x.category === c.id).length, suggested: rows.filter((x) => !x.category && x.suggested && x.suggested.id === c.id).length,
      templates: TEMPLATES.filter((t) => t.category === c.id).map((t) => Object.assign({}, t, { in_ras: M.some((m) => same(m.component, t.component) || m.template === t.id) })) }));
    return { categories: cats, risks: rows, summary: { open: rows.length, categorised: rows.filter((x) => x.category).length, suggested: rows.filter((x) => !x.category && x.suggested).length, none: rows.filter((x) => !x.category && !x.suggested).length },
      note: 'Categories and metric templates are a starting point for an insurer - edit them to your own risk taxonomy. A template has no limit: limits come from the Board-approved RAS. A suggested category is read from the risk\'s words; a person confirms it.' };
  }
  function assign(input, who) {
    person(who, 'set risk categories');
    const b = body(input || {}).list('pairs', { required: true, max: 500 }).done();
    const pairs = b.pairs.map((p, i) => { if (!p || typeof p !== 'object' || Array.isArray(p)) throw httpErr(400, 'pairs[' + i + '] must be {risk, category}'); try { return body(p).str('risk', { required: true, max: 20, id: true }).oneOf('category', CAT_IDS, { required: true }).done(); } catch (e) { throw httpErr(400, 'pairs[' + i + ']: ' + e.message); } });
    for (const [i, p] of pairs.entries()) if (!RISK().get(p.risk)) throw httpErr(400, 'pairs[' + i + ']: no risk ' + p.risk);
    let n = 0; for (const p of pairs) { const r = RISK().get(p.risk); if (r.ins_cat === p.category) continue; logChange(r, who, 'categorised', [{ field: 'ins_cat', from: r.ins_cat || null, to: p.category }], '', iso()); r.ins_cat = p.category; RISK().put(r); n++; }
    audit(who, 'catalogue.assign', String(n), { changed: n, pairs: pairs.slice(0, 50).map((p) => p.risk + '>' + p.category) });
    return { ok: true, changed: n, unchanged: pairs.length - n };
  }
  const emFields = (b) => b.str('title', { max: 300 }).str('description', { max: 4000 }).oneOf('category', CAT_IDS).oneOf('horizon', HORIZON).oneOf('trend', TREND).int('impact', { min: 1, max: 5 }).str('owner', { max: 80 }).str('signals', { max: 2000 });
  function emerging() { const L = EMG().all().sort((a, b) => (a.state === 'watching' ? 0 : 1) - (b.state === 'watching' ? 0 : 1) || (b.impact || 0) - (a.impact || 0) || a.id.localeCompare(b.id)); return { emerging: L, horizons: HORIZON, trends: TREND, categories: CATEGORIES.map((c) => ({ id: c.id, name: c.name })) }; }
  function emergingSave(id, input, who) {
    person(who, 'record an emerging risk');
    const b = emFields(body(input || {}).oneOf('state', ['watching', 'dismissed']).str('note', { max: 1000 })).done();
    const cur = id ? EMG().get(id) : null; if (id && !cur) throw httpErr(404, 'no emerging risk ' + id);
    if (cur && cur.state === 'promoted') throw httpErr(409, id + ' was promoted to the register as ' + cur.promoted_to + ' - change it there');
    if (!cur) for (const k of ['title', 'category', 'horizon', 'trend', 'impact', 'owner']) if (b[k] == null) throw httpErr(400, k + ' is required');
    if (b.state === 'dismissed' && !b.note) throw httpErr(400, 'note is required to dismiss: say why');
    const rec = Object.assign({ id: seq(EMG(), 'ER'), state: 'watching', created_by: who.user, created_at: iso(), log: [] }, cur || {});
    const ch = Object.keys(b).filter((k) => k !== 'note' && b[k] !== undefined && rec[k] !== b[k]);
    for (const k of ch) rec[k] = b[k];
    rec.reviewed_by = who.user; rec.reviewed_at = iso(); rec.log = (rec.log || []).concat([{ at: iso(), by: who.user, what: cur ? 'reviewed' : 'recorded', fields: ch, note: b.note || '' }]).slice(-50);
    EMG().put(rec); audit(who, cur ? 'emerging.update' : 'emerging.create', rec.id, { fields: ch, state: rec.state });
    return rec;
  }
  function promote(id, input, who) {
    person(who, 'promote an emerging risk');
    const e = EMG().get(id); if (!e) throw httpErr(404, 'no emerging risk ' + id); if (e.state !== 'watching') throw httpErr(409, id + ' is ' + e.state);
    const b = body(input || {}).str('department', { required: true, max: 80 }).int('likelihood', { required: true, min: 1, max: 5 }).int('impact', { required: true, min: 1, max: 5 }).int('exposure', { min: 1, max: 5 }).str('owner', { required: true, max: 80 }).str('note', { required: true, min: 5, max: 1000 }).done();
    const r = BR().riskSave({ department: b.department, title: e.title, description: (e.description || '') + (e.signals ? '\nSignals: ' + e.signals : ''), likelihood: b.likelihood, impact: b.impact, exposure: b.exposure, owner: b.owner, change_note: 'promoted from emerging risk ' + id + ': ' + b.note }, who);
    const rec = RISK().get(r.id); rec.ins_cat = e.category; rec.from_emerging = id; RISK().put(rec);
    Object.assign(e, { state: 'promoted', promoted_to: r.id, promoted_by: who.user, promoted_at: iso() }); e.log = (e.log || []).concat([{ at: iso(), by: who.user, what: 'promoted', note: b.note }]).slice(-50); EMG().put(e);
    audit(who, 'emerging.promote', id, { risk: r.id, department: b.department });
    return { emerging: e, risk: BR().riskGet(r.id) };
  }

  // ---------- 5 reports: committee, board, regulator - built from the records at the moment they are asked for
  async function report(kind, who) {
    if (!['committee', 'board', 'regulator'].includes(kind)) throw httpErr(404, 'report: committee, board or regulator');
    const v = await BR().view(), R = BR().riskList().risks, open = R.filter((r) => r.status !== 'solved'), cat = catalogue(), ap = approvals(), cy = cycles().cycles;
    const last = cy.find((c) => c.state === 'approved') || null, live = cy.find((c) => c.state === 'open' || c.state === 'review') || null, lastFull = last ? cycleGet(last.id) : null;
    const catName = Object.fromEntries(CATEGORIES.map((c) => [c.id, c.name])), catOf = (r) => { if (r.ins_cat) return r.ins_cat; const x = cat.risks.find((y) => y.id === r.id); return x ? (x.category || (x.suggested ? x.suggested.id : null)) : null; };
    const top = open.filter((r) => r.residual >= 3).sort((a, b) => (b.residual - a.residual) || ((b.inherent || 0) - (a.inherent || 0))).map((r) => ({ id: r.id, code: r.code, title: r.title, department: r.department, owner: r.owner, category: catName[catOf(r)] || '', inherent: r.label, class: r.class, treatment: r.treatment_status, target: r.target || '', response: r.response }));
    const byCat = CATEGORIES.map((c) => { const I = open.filter((r) => catOf(r) === c.id); return { category: c.name, risks: I.length, class3_plus: I.filter((r) => r.residual >= 3).length }; }).filter((x) => x.risks);
    const out = { kind, title: { committee: 'Risk Committee pack', board: 'Board risk report', regulator: 'Insurance Authority risk pack' }[kind], generated_at: iso(), generated_by: who.user,
      profile: { kpis: v.kpis, classes: v.kpis.class, open_classes: [1, 2, 3, 4].map((c) => open.filter((r) => r.residual === c).length), by_category: byCat, uncategorised: open.filter((r) => !catOf(r)).length, heat: v.heat },
      top_risks: kind === 'board' ? top.slice(0, 10) : top,
      appetite: { zones: v.zones, breaches: v.breaches, warnings: v.warnings, due: v.due, approval: ap.current ? { id: ap.current.id, year: ap.current.year, board_ref: ap.current.board_ref, decided_at: ap.current.decided_at, changed_since: ap.current.drift.unchanged ? null : { added: ap.current.drift.added.length, removed: ap.current.drift.removed.length, limits_changed: ap.current.drift.limits_changed.length } } : null },
      assessment: { last: last ? { id: last.id, period: last.period, approved_at: last.decision.at, approved_by: last.decision.by, risks: last.progress.risks, up: last.progress.up, down: last.progress.down, compare: lastFull.compare.summary || null } : null, running: live ? { id: live.id, period: live.period, state: live.state, due: live.due, pct: live.progress.pct, signed: live.progress.signed, departments: live.progress.departments, overdue: live.progress.overdue } : null },
      emerging: EMG().all((e) => e.state === 'watching').sort((a, b) => (b.impact || 0) - (a.impact || 0)).map((e) => ({ id: e.id, title: e.title, category: catName[e.category] || e.category, horizon: e.horizon, trend: e.trend, impact: e.impact, owner: e.owner })),
      quality: { flagged: v.kpis.flagged, stale: v.kpis.stale, not_rated: v.kpis.not_rated, acceptance_pending: v.kpis.acceptance_pending, limit_issues: v.kpis.limit_issues },
      method: v.method };
    if (kind === 'board') { out.appetite.breaches = out.appetite.breaches.slice(0, 10); out.emerging = out.emerging.slice(0, 5); delete out.profile.heat; }
    if (kind === 'regulator') {
      out.register = R.map((r) => ({ id: r.id, code: r.code, department: r.department, title: r.title, category: catName[catOf(r)] || '', owner: r.owner, likelihood: r.likelihood, impact: r.impact, inherent: r.label, exposure: r.exposure, class: r.class, response: r.response, treatment: r.treatment_status, status: r.status, assessed_at: r.assessed_at || r.identified || '' }));
      out.ras = BR().rasAll().metrics.map((m) => ({ id: m.id, section: m.section_title, component: m.component, responsibility: m.responsibility, frequency: m.frequency, limits: m.raw, latest: m.latest ? { period: m.latest.period, value: m.latest.text || m.latest.value, zone: m.latest.zone } : null }));
      out.note = 'Built from the records in the system. The layout is a working structure: check it against the Insurance Authority\'s current reporting template before submitting.';
    }
    audit(who, 'report.' + kind, kind, { risks: R.length, top: out.top_risks.length });
    return out;
  }

  return { closeRequest, closeDecision, changes, cycles, cycleGet, cycleOpen, cycleSubmit, cycleSignoff, cycleDecision, cycleCancel, proposals, propose, proposalDecision, approvals, approvalRequest, approvalDecision, catalogue, assign, emerging, emergingSave, promote, report, CATEGORIES, TEMPLATES };
}

function registerRiskProgramme(srv, app, X) {
  const W = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip });
  const ID = (ctx) => param(ctx.params.id, 'id');
  srv.route('POST', '/brisk/risks/:id/close', (ctx) => { ctx.need('operator'); return X.closeRequest(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/risks/:id/close/decision', (ctx) => { ctx.need('admin'); return X.closeDecision(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('GET', '/brisk/risks/:id/changes', (ctx) => { ctx.need('viewer'); return X.changes(ID(ctx)); });
  srv.route('GET', '/brisk/cycles', (ctx) => { ctx.need('viewer'); return X.cycles(); });
  srv.route('GET', '/brisk/cycles/:id', (ctx) => { ctx.need('viewer'); return X.cycleGet(ID(ctx)); });
  srv.route('POST', '/brisk/cycles', (ctx) => { ctx.need('admin'); return X.cycleOpen(ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/brisk/cycles/:id/submit', (ctx) => { ctx.need('operator'); return X.cycleSubmit(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/cycles/:id/signoff', (ctx) => { ctx.need('operator'); return X.cycleSignoff(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/cycles/:id/decision', (ctx) => { ctx.need('admin'); return X.cycleDecision(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/cycles/:id/cancel', (ctx) => { ctx.need('admin'); return X.cycleCancel(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('GET', '/brisk/ras/proposals', (ctx) => { ctx.need('viewer'); return X.proposals(); });
  srv.route('POST', '/brisk/ras/proposals', (ctx) => { ctx.need('operator'); return X.propose(ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/brisk/ras/proposals/:id/decision', (ctx) => { ctx.need('admin'); return X.proposalDecision(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('GET', '/brisk/ras/approvals', (ctx) => { ctx.need('viewer'); return X.approvals(); });
  srv.route('POST', '/brisk/ras/approvals', (ctx) => { ctx.need('operator'); return X.approvalRequest(ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/ras/approvals/:id/decision', (ctx) => { ctx.need('admin'); return X.approvalDecision(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('GET', '/brisk/catalogue', (ctx) => { ctx.need('viewer'); return X.catalogue(); });
  srv.route('POST', '/brisk/catalogue/assign', (ctx) => { ctx.need('operator'); return X.assign(ctx.body, W(ctx)); }, { maxBody: 64 * 1024 });
  srv.route('GET', '/brisk/emerging', (ctx) => { ctx.need('viewer'); return X.emerging(); });
  srv.route('POST', '/brisk/emerging', (ctx) => { ctx.need('operator'); return X.emergingSave(null, ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/brisk/emerging/:id', (ctx) => { ctx.need('operator'); return X.emergingSave(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/brisk/emerging/:id/promote', (ctx) => { ctx.need('operator'); return X.promote(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('GET', '/brisk/reports/:kind', (ctx) => { ctx.need('operator'); return X.report(param(ctx.params.kind, 'kind'), W(ctx)); });
}

module.exports = { createRiskProgramme, registerRiskProgramme, CATEGORIES, TEMPLATES };
