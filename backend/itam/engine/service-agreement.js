// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const crypto = require('node:crypto');
const { body } = require('./check');
/*
 * Service Agreement - the SLA and the NDA between the organisation (Customer) and Citynet Work (Provider),
 * delivered through Zyberon Information Technology, Saudi Arabia (the Provider's technology and delivery partner), kept and
 * measured inside the platform.
 *   terms        customisable by an administrator (every change audited, versioned, baseVersion against races): parties, the
 *                people of each side, support hours (Riyadh, Sun-Thu), priorities P1-P4 with response / resolution targets and
 *                24x7 or business-hours cover, internal audit remediation targets per rating (IT, Cyber Security and Internal
 *                Audit teams' findings), platform availability, monthly report, and the service credit (deduction) for each
 *                missed target as a % of the monthly fee, capped per month. The defaults are a starting point the parties change.
 *   support      cases between the two parties: the Customer opens (priority, category), the Provider responds and resolves,
 *                the Customer confirms closure. Times are measured in the cover hours of the priority. An exclusion (customer-
 *                caused, agreed maintenance, force majeure) is asked by one side and decided by the other - never by itself.
 *   audit fixes  every issued finding of the audit teams in scope must be implemented within its rating's target from the day
 *                it was issued; a finding still open after the target is a miss in the month the target fell.
 *   statement    each month: every target with measured / met / missed, the deductions, the cap, the amount when the monthly fee
 *                is entered (never invented). The Provider issues it (frozen), the Customer accepts or disputes it with a reason.
 *   documents    SLA and NDA generated from the terms (sections an administrator may edit), each version approved by the named
 *                signatory of BOTH parties (two different people), then published read-only to every signed-in user. Drafts for
 *                legal review: the platform records approval, it is not a qualified electronic signature.
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (s) => String(s == null ? '' : s).trim().toLowerCase();
const SERVICE = /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i;
const RIYADH = 3 * 3600000, MIN = 60000, DAY = 86400000;
const PRI = ['P1', 'P2', 'P3', 'P4'];
const RATINGS = ['high', 'medium', 'low'];
const TEAMS = { ia: 'IT Audit', csa: 'Cyber Security Audit', iad: 'Internal Audit' };
const USER = /^[A-Za-z0-9._@\\-]{1,120}$/;
const HM = /^([01]\d|2[0-3]):[0-5]\d$/;
const DEFAULTS = {
  parties: {
    customer: { legal_name: ZYB_ORG.name, short: ZYB_ORG.short, cr: '', address: 'Riyadh, Kingdom of Saudi Arabia', signatory: { name: '', title: '', user: '' } },
    provider: { legal_name: 'Citynet Work', short: 'Citynet Work', cr: '', address: 'Kingdom of Saudi Arabia', signatory: { name: '', title: '', user: '' } },
    partner: { legal_name: 'Zyberon Information Technology, Saudi Arabia', short: 'Zyberon', address: '1A Al Dahna Center, Al Ehsa Street, Zahra District, Riyadh 12815, Kingdom of Saudi Arabia', role: 'technology and delivery partner of the Provider' },
  },
  members: { customer: [], provider: [] },
  commercial: { monthly_fee_sar: null, cap_pct: 10, term_months: 12, start: '' },
  hours: { days: [0, 1, 2, 3, 4], start: '08:00', end: '17:00' },
  priorities: {
    P1: { name: 'Critical', description: 'A security incident or the platform down for everyone', cover: '24x7', response_min: 30, resolve_h: 4, credit_pct: 2 },
    P2: { name: 'High', description: 'A main function unavailable, or degraded for many users', cover: '24x7', response_min: 60, resolve_h: 8, credit_pct: 1 },
    P3: { name: 'Medium', description: 'A function degraded with a workaround', cover: 'business', response_min: 240, resolve_h: 27, credit_pct: 0.5 },
    P4: { name: 'Low', description: 'A question, a small change or a cosmetic issue', cover: 'business', response_min: 540, resolve_h: 45, credit_pct: 0.25 },
  },
  audit: { teams: ['ia', 'csa', 'iad'], days: { high: 30, medium: 60, low: 90 }, credit_pct: { high: 1, medium: 0.5, low: 0.25 } },
  availability: { target_pct: 99.5, credit_pct: 5 },
  report: { due_day: 5, credit_pct: 0.5 },
};

// minutes between two instants inside the cover: 24x7, or the business days / hours in Riyadh time
function coverMinutes(from, to, cover, hours) {
  if (!(to > from)) return 0;
  if (cover === '24x7') return Math.round((to - from) / MIN);
  const [sh, sm] = hours.start.split(':').map(Number), [eh, em] = hours.end.split(':').map(Number);
  let total = 0, d = Math.floor((from + RIYADH) / DAY) * DAY - RIYADH;
  for (let i = 0; d < to && i < 800; i++, d += DAY) {
    const wd = new Date(d + RIYADH).getUTCDay(); if (!hours.days.includes(wd)) continue;
    const a = Math.max(from, d + (sh * 60 + sm) * MIN), b = Math.min(to, d + (eh * 60 + em) * MIN);
    if (b > a) total += (b - a) / MIN;
  }
  return Math.round(total);
}
// the instant at which `minutes` of cover have passed since `from`
function coverDeadline(from, minutes, cover, hours) {
  if (cover === '24x7') return from + minutes * MIN;
  const [sh, sm] = hours.start.split(':').map(Number), [eh, em] = hours.end.split(':').map(Number);
  let left = minutes, d = Math.floor((from + RIYADH) / DAY) * DAY - RIYADH;
  for (let i = 0; i < 800; i++, d += DAY) {
    const wd = new Date(d + RIYADH).getUTCDay(); if (!hours.days.includes(wd)) continue;
    const a = Math.max(from, d + (sh * 60 + sm) * MIN), b = d + (eh * 60 + em) * MIN;
    if (b <= a) continue;
    const avail = (b - a) / MIN; if (avail >= left) return a + left * MIN; left -= avail;
  }
  return null;
}
const monthOf = (t) => new Date(t + RIYADH).toISOString().slice(0, 7);
const monthBounds = (m) => { const s = Date.parse(m + '-01T00:00:00Z') - RIYADH; const d = new Date(s + RIYADH); d.setUTCMonth(d.getUTCMonth() + 1); return [s, d.getTime() - RIYADH]; };

function createServiceAgreement(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, iso = () => new Date(now()).toISOString();
  const C = { cfg: () => store.collection('sa_cfg'), cases: () => store.collection('sa_cases'), st: () => store.collection('sa_statements'), docs: () => store.collection('sa_documents'), meas: () => store.collection('sa_measures') };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const cfg = () => { const c = C.cfg().get('cfg') || {}; const m = JSON.parse(JSON.stringify(DEFAULTS)); for (const k of Object.keys(c)) if (k in m && c[k] && typeof c[k] === 'object' && !Array.isArray(c[k])) m[k] = Object.assign(m[k], c[k]); else if (k in m) m[k] = c[k]; m.version = c.version || 0; m.updated_by = c.updated_by || null; m.updated_at = c.updated_at || null; return m; };
  const partyOf = (who, c) => { const u = low(who.user); c = c || cfg(); return c.members.customer.map(low).includes(u) ? 'customer' : c.members.provider.map(low).includes(u) ? 'provider' : null; };
  const needParty = (who, p, what) => { if (SERVICE.test(String(who.user || ''))) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); const mine = partyOf(who); if (mine !== p) throw httpErr(403, 'only the ' + (p === 'customer' ? ('Customer (' + ZYB_ORG.short + ')') : 'Provider (Citynet Work / Zyberon)') + ' team ' + what + ' - an administrator adds you to a party under Terms'); return mine; };

  // ---------- terms (administrators)
  // a nested field's error names its full path (priorities.P1.resolve_h, not resolve_h)
  const at = (prefix, fn) => { try { return fn(); } catch (e) { if (e.status === 400 && !String(e.message).startsWith(prefix)) e.message = prefix + '.' + e.message; throw e; } };
  function saveTerms(input, who, baseVersion) {
    if (SERVICE.test(String(who.user || ''))) throw httpErr(403, 'a service or AI identity cannot change the agreement terms');
    const cur = cfg();
    if (baseVersion != null && Number(baseVersion) !== cur.version) throw httpErr(409, 'the terms were changed by ' + (cur.updated_by || 'someone') + ' since you opened them - reload and apply your change again');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw httpErr(400, 'terms must be an object');
    const out = JSON.parse(JSON.stringify(cur)); delete out.version; delete out.updated_by; delete out.updated_at;
    const obj = (x, k) => { if (x[k] === undefined) return null; if (!x[k] || typeof x[k] !== 'object' || Array.isArray(x[k])) throw httpErr(400, k + ' must be an object'); return x[k]; };
    const parties = obj(input, 'parties');
    if (parties) for (const p of ['customer', 'provider', 'partner']) {
      const x = parties[p]; if (x === undefined) continue; if (!x || typeof x !== 'object') throw httpErr(400, 'parties.' + p + ' must be an object');
      const e = at('parties.' + p, () => body(x).str('legal_name', { max: 160 }).str('short', { max: 60 }).str('cr', { max: 20, re: /^[0-9A-Za-z-]{0,20}$/, msg: 'parties.' + p + '.cr must be the commercial registration number' }).str('address', { max: 300 }).str('role', { max: 200 }).done());
      if (e.legal_name === '') throw httpErr(400, 'parties.' + p + '.legal_name is required');
      Object.assign(out.parties[p], e);
      if (p !== 'partner' && x.signatory !== undefined) { const s = at('parties.' + p + '.signatory', () => body(x.signatory || {}).str('name', { max: 100 }).str('title', { max: 100 }).str('user', { max: 120, re: USER, msg: 'parties.' + p + '.signatory.user must be a sign-in name' }).done()); Object.assign(out.parties[p].signatory, s); }
    }
    const members = obj(input, 'members');
    if (members) for (const p of ['customer', 'provider']) if (members[p] !== undefined) {
      const L = body({ v: members[p] }).list('v', { max: 200, item: 'str', itemMax: 120, unique: true }).done().v;
      for (const u of L) if (!USER.test(u)) throw httpErr(400, 'members.' + p + ': "' + u + '" is not a sign-in name');
      out.members[p] = L;
    }
    if (out.members.customer.some((u) => out.members.provider.map(low).includes(low(u)))) throw httpErr(400, 'members: a person cannot be on both sides');
    for (const p of ['customer', 'provider']) { const s = out.parties[p].signatory.user; if (s && !out.members[p].map(low).includes(low(s))) throw httpErr(400, 'parties.' + p + '.signatory.user must be one of the ' + p + ' members'); }
    if (out.parties.customer.signatory.user && low(out.parties.customer.signatory.user) === low(out.parties.provider.signatory.user)) throw httpErr(400, 'the two signatories must be different people');
    const com = obj(input, 'commercial');
    if (com) { const e = at('commercial', () => body(com).num('monthly_fee_sar', { min: 0, max: 100000000 }).num('cap_pct', { min: 0, max: 100 }).int('term_months', { min: 1, max: 120 }).date('start').done()); if (com.monthly_fee_sar === null) e.monthly_fee_sar = null; Object.assign(out.commercial, e); }
    const hours = obj(input, 'hours');
    if (hours) { const e = at('hours', () => body(hours).list('days', { max: 7, item: [0, 1, 2, 3, 4, 5, 6], unique: true }).str('start', { max: 5, re: HM, msg: 'hours.start must be HH:MM' }).str('end', { max: 5, re: HM, msg: 'hours.end must be HH:MM' }).done()); Object.assign(out.hours, e); if (out.hours.end <= out.hours.start) throw httpErr(400, 'hours.end must be after hours.start'); if (!out.hours.days.length) throw httpErr(400, 'hours.days needs at least one working day'); }
    const pr = obj(input, 'priorities');
    if (pr) for (const p of PRI) if (pr[p] !== undefined) {
      const e = at('priorities.' + p, () => body(pr[p] || {}).str('name', { max: 40 }).str('description', { max: 300 }).oneOf('cover', ['24x7', 'business']).int('response_min', { min: 5, max: 10080 }).num('resolve_h', { min: 0.5, max: 2000 }).num('credit_pct', { min: 0, max: 100 }).done());
      Object.assign(out.priorities[p], e);
      if (out.priorities[p].resolve_h * 60 < out.priorities[p].response_min) throw httpErr(400, 'priorities.' + p + ': resolution must not be shorter than the response time');
    }
    const au = obj(input, 'audit');
    if (au) {
      const e = body(au).list('teams', { max: 3, item: Object.keys(TEAMS), unique: true }).done(); if (e.teams) out.audit.teams = e.teams;
      for (const k of ['days', 'credit_pct']) if (au[k] !== undefined) { if (!au[k] || typeof au[k] !== 'object') throw httpErr(400, 'audit.' + k + ' must be an object'); const x = at('audit.' + k, () => body(au[k]).num('high', { min: 0, max: k === 'days' ? 730 : 100 }).num('medium', { min: 0, max: k === 'days' ? 730 : 100 }).num('low', { min: 0, max: k === 'days' ? 730 : 100 }).done()); Object.assign(out.audit[k], x); }
      if (!(out.audit.days.high <= out.audit.days.medium && out.audit.days.medium <= out.audit.days.low)) throw httpErr(400, 'audit.days: a high finding must be due no later than a medium one, and a medium no later than a low one');
    }
    const av = obj(input, 'availability'); if (av) Object.assign(out.availability, at('availability', () => body(av).num('target_pct', { min: 90, max: 100 }).num('credit_pct', { min: 0, max: 100 }).done()));
    const rp = obj(input, 'report'); if (rp) Object.assign(out.report, at('report', () => body(rp).int('due_day', { min: 1, max: 28 }).num('credit_pct', { min: 0, max: 100 }).done()));
    const rec = Object.assign({ id: 'cfg' }, out, { version: cur.version + 1, updated_by: who.user, updated_at: iso() });
    C.cfg().put(rec);
    audit(who, 'sla.terms.save', 'agreement', { version: rec.version, fee_set: rec.commercial.monthly_fee_sar != null, cap_pct: rec.commercial.cap_pct, members: { customer: rec.members.customer.length, provider: rec.members.provider.length } });
    return cfg();
  }

  // ---------- support cases
  const hist = (x, who, action, note) => { x.history = (x.history || []).concat([{ at: iso(), by: who.user, action, note: note || null }]).slice(-200); };
  function caseView(x, c, t) {
    const p = c.priorities[x.priority], open = Date.parse(x.opened_at), cov = p.cover;
    const respDue = coverDeadline(open, p.response_min, cov, c.hours), resDue = coverDeadline(open, p.resolve_h * 60, cov, c.hours);
    const respAt = x.responded_at ? Date.parse(x.responded_at) : null, resAt = x.resolved_at ? Date.parse(x.resolved_at) : null;
    const used = (end, mins) => Math.round(coverMinutes(open, end, cov, c.hours) / mins * 100);
    return Object.assign({}, x, { priority_name: p.name, cover: cov, response_due: respDue ? new Date(respDue).toISOString() : null, resolve_due: resDue ? new Date(resDue).toISOString() : null,
      response_met: respAt ? respAt <= respDue : t > respDue ? false : null, resolve_met: resAt ? resAt <= resDue : t > resDue ? false : null,
      response_used_pct: used(respAt || t, p.response_min), resolve_used_pct: used(resAt || t, p.resolve_h * 60), excluded: !!(x.exclusion && x.exclusion.decision === 'accepted') });
  }
  function listCases(q, who) {
    const c = cfg(), t = now(), L = C.cases().all().map((x) => caseView(x, c, t)).sort((a, b) => String(b.opened_at).localeCompare(String(a.opened_at)));
    const st = q && q.status; return { cases: (st ? L.filter((x) => x.status === st) : L).slice(0, 500), party: partyOf(who, c), at_risk: L.filter((x) => !['resolved', 'closed'].includes(x.status) && (x.resolve_used_pct >= 75 || x.response_used_pct >= 75)).length };
  }
  function openCase(input, who) {
    needParty(who, 'customer', 'opens a support case');
    const b = body(input).str('title', { required: true, max: 160 }).str('description', { required: true, max: 4000 }).oneOf('priority', PRI, { required: true }).oneOf('category', ['incident', 'request', 'audit-fix', 'change', 'question'], { def: 'incident' }).str('finding', { max: 60, re: /^[A-Za-z0-9_.:-]{1,60}$/, msg: 'finding must be a finding id' }).done();
    const id = 'SLA-' + new Date(now() + RIYADH).toISOString().slice(0, 10).replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const x = Object.assign({ id }, b, { status: 'open', opened_by: who.user, opened_at: iso(), history: [] }); hist(x, who, 'opened', b.priority);
    C.cases().put(x); audit(who, 'sla.case.open', id, { priority: b.priority, category: b.category });
    return caseView(x, cfg(), now());
  }
  function caseAct(id, action, input, who) {
    const x0 = C.cases().get(id); if (!x0) throw httpErr(404, 'there is no case "' + id + '"');
    const x = JSON.parse(JSON.stringify(x0)), b = body(input || {}).str('note', { max: 2000 }).oneOf('decision', ['accepted', 'rejected']).oneOf('reason', ['customer-caused', 'agreed-maintenance', 'force-majeure', 'third-party', 'other']).done();
    const st = (...s) => { if (!s.includes(x.status)) throw httpErr(409, 'the case is ' + x.status); };
    if (action === 'respond') { needParty(who, 'provider', 'responds to a case'); st('open'); x.status = 'responded'; x.responded_at = iso(); x.responded_by = who.user; hist(x, who, 'responded', b.note); }
    else if (action === 'resolve') { needParty(who, 'provider', 'resolves a case'); st('open', 'responded'); if (!b.note) throw httpErr(400, 'note: say what was done'); if (!x.responded_at) { x.responded_at = iso(); x.responded_by = who.user; } x.status = 'resolved'; x.resolved_at = iso(); x.resolved_by = who.user; hist(x, who, 'resolved', b.note); }
    else if (action === 'close') { needParty(who, 'customer', 'confirms a case is fixed'); st('resolved'); x.status = 'closed'; x.closed_at = iso(); x.closed_by = who.user; hist(x, who, 'closed', b.note); }
    else if (action === 'reopen') { needParty(who, 'customer', 'reopens a case'); st('resolved'); if (!b.note) throw httpErr(400, 'note: say what is still wrong'); x.status = 'responded'; x.resolved_at = null; x.resolved_by = null; hist(x, who, 'reopened', b.note); }
    else if (action === 'exclude') {
      const p = partyOf(who); if (!p || SERVICE.test(String(who.user || ''))) throw httpErr(403, 'only a person of either party asks for an exclusion');
      if (x.exclusion && !x.exclusion.decision) throw httpErr(409, 'an exclusion is already waiting for a decision');
      if (!b.reason || !b.note) throw httpErr(400, 'reason and note are required for an exclusion');
      x.exclusion = { requested_by: who.user, party: p, reason: b.reason, note: b.note, at: iso() }; hist(x, who, 'exclusion requested', b.reason);
    } else if (action === 'decide-exclusion') {
      if (!x.exclusion || x.exclusion.decision) throw httpErr(409, 'no exclusion is waiting');
      const p = partyOf(who); if (!p || p === x.exclusion.party || SERVICE.test(String(who.user || ''))) throw httpErr(403, 'the other party decides an exclusion (four eyes)');
      if (!b.decision) throw httpErr(400, 'decision must be accepted or rejected');
      Object.assign(x.exclusion, { decision: b.decision, decided_by: who.user, decided_at: iso(), decision_note: b.note || null }); hist(x, who, 'exclusion ' + b.decision, b.note);
    } else if (action === 'comment') { if (!partyOf(who)) throw httpErr(403, 'only the two parties comment on a case'); if (!b.note) throw httpErr(400, 'note is required'); hist(x, who, 'comment', b.note); }
    else throw httpErr(404, 'unknown action');
    C.cases().put(x); audit(who, 'sla.case.' + action, id, { status: x.status, decision: b.decision || undefined });
    return caseView(x, cfg(), now());
  }

  // ---------- monthly measures entered by one side and confirmed by the other (availability, report delivery)
  function saveMeasure(month, input, who) {
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) throw httpErr(400, 'month must be YYYY-MM');
    const p = partyOf(who); if (!p || SERVICE.test(String(who.user || ''))) throw httpErr(403, 'only a person of either party records a monthly measure');
    const b = body(input).num('availability_pct', { min: 0, max: 100 }).date('report_delivered').bool('confirm').done();
    const cur = C.meas().get(month) || { id: month };
    if (b.confirm) {
      if (!cur.entered_by) throw httpErr(409, 'nothing to confirm yet');
      if (cur.party === p) throw httpErr(403, 'the other party confirms the figures (four eyes)');
      Object.assign(cur, { confirmed_by: who.user, confirmed_at: iso() });
    } else {
      if (b.availability_pct === undefined && b.report_delivered === undefined) throw httpErr(400, 'availability_pct or report_delivered is required');
      Object.assign(cur, b.availability_pct !== undefined ? { availability_pct: b.availability_pct } : {}, b.report_delivered !== undefined ? { report_delivered: b.report_delivered } : {}, { entered_by: who.user, party: p, entered_at: iso(), confirmed_by: null, confirmed_at: null });
      delete cur.confirm;
    }
    C.meas().put(cur); audit(who, 'sla.measure.' + (b.confirm ? 'confirm' : 'enter'), month, { availability_pct: cur.availability_pct, report_delivered: cur.report_delivered || null });
    return cur;
  }

  // ---------- the monthly statement
  function findings() { const c = cfg(), out = []; for (const k of c.audit.teams) for (const f of store.collection(k + '_findings').all()) if (f.issued_at && RATINGS.includes(f.rating)) out.push(Object.assign({ team: k, team_name: TEAMS[k] }, f)); return out; }
  function compute(month) {
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) throw httpErr(400, 'month must be YYYY-MM');
    const c = cfg(), t = now(), [ms, me] = monthBounds(month), end = Math.min(me, t), lines = [];
    const credit = (kind, ref, title, met, pct, why) => lines.push({ kind, ref, title, met, deduction_pct: met === false ? pct : 0, why });
    for (const x0 of C.cases().all()) {
      const x = caseView(x0, c, end), o = Date.parse(x.opened_at); if (o < ms || o >= me) continue;
      const p = c.priorities[x.priority];
      if (x.excluded) { lines.push({ kind: 'case', ref: x.id, title: x.priority + ' ' + x.title, met: null, deduction_pct: 0, why: 'excluded: ' + x.exclusion.reason + ' (agreed by ' + x.exclusion.decided_by + ')' }); continue; }
      const respAt = x.responded_at ? Date.parse(x.responded_at) : null, resAt = x.resolved_at ? Date.parse(x.resolved_at) : null;
      const rMet = respAt && respAt <= end ? respAt <= Date.parse(x.response_due) : end > Date.parse(x.response_due) ? false : null;
      const zMet = resAt && resAt <= end ? resAt <= Date.parse(x.resolve_due) : end > Date.parse(x.resolve_due) ? false : null;
      credit('response', x.id, x.priority + ' response: ' + x.title, rMet, p.credit_pct, 'target ' + p.response_min + ' min (' + p.cover + ')');
      credit('resolution', x.id, x.priority + ' resolution: ' + x.title, zMet, p.credit_pct, 'target ' + p.resolve_h + ' h (' + p.cover + ')');
    }
    for (const f of findings()) {
      const due = Date.parse(f.issued_at) + c.audit.days[f.rating] * DAY; if (due < ms || due >= me) continue;
      const doneAt = f.implemented_at ? Date.parse(f.implemented_at) : ['closed', 'withdrawn', 'risk_accepted'].includes(f.state) ? Date.parse(f.retested_at || f.accepted_at || f.withdrawn_at || f.issued_at) : null;
      if (f.state === 'withdrawn' || f.state === 'risk_accepted') { lines.push({ kind: 'audit', ref: f.id, title: f.team_name + ' (' + f.rating + '): ' + f.title, met: null, deduction_pct: 0, why: f.state === 'withdrawn' ? 'withdrawn by the auditor' : 'risk accepted by the Head of Audit' }); continue; }
      const met = doneAt ? doneAt <= due : end > due ? false : null;
      credit('audit', f.id, f.team_name + ' (' + f.rating + '): ' + f.title, met, c.audit.credit_pct[f.rating], 'fix within ' + c.audit.days[f.rating] + ' days of ' + String(f.issued_at).slice(0, 10) + ' (due ' + new Date(due).toISOString().slice(0, 10) + ')');
    }
    const m = C.meas().get(month) || {};
    if (m.availability_pct != null) credit('availability', month, 'Platform availability ' + m.availability_pct + '% (target ' + c.availability.target_pct + '%)', m.availability_pct >= c.availability.target_pct, c.availability.credit_pct, m.confirmed_by ? 'confirmed by ' + m.confirmed_by : 'NOT CONFIRMED by the other party yet');
    else lines.push({ kind: 'availability', ref: month, title: 'Platform availability', met: null, deduction_pct: 0, why: 'not recorded for this month' });
    const repDue = new Date(me + RIYADH); repDue.setUTCDate(c.report.due_day); const repDueS = repDue.toISOString().slice(0, 10);
    if (m.report_delivered) credit('report', month, 'Monthly service report delivered ' + m.report_delivered + ' (due ' + repDueS + ')', m.report_delivered <= repDueS, c.report.credit_pct, m.confirmed_by ? 'confirmed by ' + m.confirmed_by : 'NOT CONFIRMED by the other party yet');
    else lines.push({ kind: 'report', ref: month, title: 'Monthly service report (due ' + repDueS + ')', met: t > Date.parse(repDueS + 'T23:59:59Z') - RIYADH ? false : null, deduction_pct: t > Date.parse(repDueS + 'T23:59:59Z') - RIYADH ? c.report.credit_pct : 0, why: 'no delivery recorded' });
    const raw = Math.round(lines.reduce((a, l) => a + l.deduction_pct, 0) * 100) / 100, total = Math.min(raw, c.commercial.cap_pct);
    const fee = c.commercial.monthly_fee_sar;
    return { month, period: { from: new Date(ms).toISOString(), to: new Date(me).toISOString() }, final: t >= me, lines, summary: { targets: lines.filter((l) => l.met !== null).length, met: lines.filter((l) => l.met === true).length, missed: lines.filter((l) => l.met === false).length, pending: lines.filter((l) => l.met === null).length,
      deduction_raw_pct: raw, cap_pct: c.commercial.cap_pct, deduction_pct: total, capped: raw > total, monthly_fee_sar: fee, deduction_sar: fee == null ? null : Math.round(fee * total) / 100 }, terms_version: c.version };
  }
  function statement(month) { const s = C.st().get(month); return s ? Object.assign({}, s.snapshot, { state: s.state, issued_by: s.issued_by, issued_at: s.issued_at, decided_by: s.decided_by || null, decided_at: s.decided_at || null, dispute: s.dispute || null, frozen: true }) : Object.assign(compute(month), { state: 'draft', frozen: false }); }
  function issue(month, who) {
    needParty(who, 'provider', 'issues the monthly statement');
    const cur = C.st().get(month); if (cur && cur.state !== 'disputed') throw httpErr(409, 'the statement for ' + month + ' is already ' + cur.state);
    const snap = compute(month); if (!snap.final) throw httpErr(409, month + ' has not ended yet - the statement is issued after the month');
    C.st().put({ id: month, snapshot: snap, state: 'issued', issued_by: who.user, issued_at: iso(), history: ((cur && cur.history) || []).concat([{ at: iso(), by: who.user, action: 'issued' }]) });
    audit(who, 'sla.statement.issue', month, { deduction_pct: snap.summary.deduction_pct, missed: snap.summary.missed });
    return statement(month);
  }
  function decideStatement(month, input, who) {
    needParty(who, 'customer', 'accepts or disputes the statement');
    const s = C.st().get(month); if (!s || s.state !== 'issued') throw httpErr(409, 'there is no issued statement for ' + month + ' to decide');
    const b = body(input).oneOf('decision', ['accepted', 'disputed'], { required: true }).str('note', { max: 2000 }).done();
    if (b.decision === 'disputed' && !b.note) throw httpErr(400, 'note: say what is disputed');
    Object.assign(s, { state: b.decision, decided_by: who.user, decided_at: iso(), dispute: b.decision === 'disputed' ? b.note : null, history: s.history.concat([{ at: iso(), by: who.user, action: b.decision, note: b.note || null }]) });
    C.st().put(s); audit(who, 'sla.statement.' + b.decision, month, { deduction_pct: s.snapshot.summary.deduction_pct });
    return statement(month);
  }

  // ---------- documents (SLA, NDA): generated from the terms, approved by both signatories, published
  const or = (v, ph) => (v && String(v).trim() ? String(v).trim() : '[' + ph + ']');
  function partiesText(c) {
    const P = c.parties;
    return [P.customer.legal_name + ', commercial registration ' + or(P.customer.cr, 'CR number') + ', ' + or(P.customer.address, 'address') + ' (the "Customer");',
      P.provider.legal_name + ', commercial registration ' + or(P.provider.cr, 'CR number') + ', ' + or(P.provider.address, 'address') + ' (the "Provider"), acting together with ' + P.partner.legal_name + ', ' + P.partner.address + ', its ' + P.partner.role + ' (the "Delivery Partner").'];
  }
  function slaSections(c) {
    const P = c.parties, pr = PRI.map((k) => k + ' ' + c.priorities[k].name + ' - ' + c.priorities[k].description + ': response ' + c.priorities[k].response_min + ' minutes, resolution ' + c.priorities[k].resolve_h + ' hours, ' + (c.priorities[k].cover === '24x7' ? '24 hours a day, 7 days a week' : 'business hours') + '; service credit ' + c.priorities[k].credit_pct + '% of the monthly fee per missed target.');
    const DN = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return [
      { h: '1. Parties', t: partiesText(c).join('\n') },
      { h: '2. Purpose and scope', t: 'The Provider, through the Delivery Partner, operates and supports the Zyberon unified IT and cyber security platform for the Customer and remediates the findings of the Customer\'s internal audits of information technology and cyber security (' + c.audit.teams.map((k) => TEAMS[k]).join(', ') + '). This Agreement sets the service levels, how they are measured in the platform, and the service credits for missed levels.' },
      { h: '3. Term', t: 'This Agreement starts on ' + or(c.commercial.start, 'start date') + ' and runs for ' + c.commercial.term_months + ' months, renewing on written agreement of both parties.' },
      { h: '4. Support hours', t: 'Business hours are ' + c.hours.days.map((d) => DN[d]).join(', ') + ', ' + c.hours.start + '-' + c.hours.end + ' Riyadh time, excluding official public holidays of the Kingdom of Saudi Arabia. Priorities with 24x7 cover are measured around the clock.' },
      { h: '5. Priorities and targets', t: pr.join('\n') + '\nThe Customer sets the priority when opening a case; the parties may agree to change it, recorded on the case. Response means a named Provider engineer has acknowledged the case and started work; resolution means service is restored or the request fulfilled, confirmed by the Customer.' },
      { h: '6. Internal audit remediation', t: 'Every finding issued by the Customer\'s audit teams in scope is implemented within ' + c.audit.days.high + ' days (high), ' + c.audit.days.medium + ' days (medium) and ' + c.audit.days.low + ' days (low) of the date it is issued. A finding still open after its target is a missed target in the month the target falls, with a service credit of ' + c.audit.credit_pct.high + '% (high), ' + c.audit.credit_pct.medium + '% (medium) and ' + c.audit.credit_pct.low + '% (low) of the monthly fee. A finding withdrawn by the auditor or whose risk is accepted by the Head of Audit carries no credit. Closure follows the auditor\'s re-test.' },
      { h: '7. Availability and reporting', t: 'Monthly platform availability is at least ' + c.availability.target_pct + '% outside agreed maintenance windows; below it the service credit is ' + c.availability.credit_pct + '%. The Provider delivers the monthly service report by day ' + c.report.due_day + ' of the following month; late delivery carries ' + c.report.credit_pct + '%. Figures are recorded by one party and confirmed by the other in the platform.' },
      { h: '8. Service credits (deductions)', t: 'Service credits are a percentage of the monthly fee' + (c.commercial.monthly_fee_sar != null ? ' (SAR ' + c.commercial.monthly_fee_sar.toLocaleString('en-US') + ')' : ' [monthly fee]') + ', added up for the month and capped at ' + c.commercial.cap_pct + '% of that month\'s fee. They are deducted from the invoice of the following month. The Provider issues the monthly statement from the platform; the Customer accepts it or disputes it in writing within 10 working days. Service credits are the Customer\'s sole financial remedy for missed service levels, without prejudice to termination rights for repeated material failure.' },
      { h: '9. Exclusions', t: 'No credit applies where a miss is caused by the Customer, its other suppliers or systems outside the Provider\'s control, during maintenance agreed in advance, or by force majeure. An exclusion is requested by one party and accepted or rejected by the other in the platform, with its reason.' },
      { h: '10. Governance and escalation', t: 'The parties meet monthly to review the statement, open cases, audit remediation and risks. Escalation: the case\'s engineer, then the Provider\'s service manager, then the signatories of this Agreement.' },
      { h: '11. Customer responsibilities', t: 'The Customer provides timely access, named contacts, information needed to diagnose a case, and approves changes in its change process. Access to the Customer\'s systems is read-only unless a change is approved by a named Customer person.' },
      { h: '12. Delivery Partner', t: 'The Provider may deliver the services through the Delivery Partner. The Provider remains fully responsible to the Customer for the Delivery Partner\'s performance, confidentiality and compliance, and ensures the Delivery Partner is bound by obligations at least as strict as this Agreement and the Non-Disclosure Agreement.' },
      { h: '13. Security, regulation and personal data', t: 'The services comply with the NCA Essential Cybersecurity Controls, the SAMA Cyber Security Framework and the Personal Data Protection Law. Customer data and evidence stay in the Kingdom of Saudi Arabia and are not transferred abroad without the Customer\'s written approval. Personnel with access are vetted, named and subject to the Non-Disclosure Agreement.' },
      { h: '14. Changes to this Agreement', t: 'Changes are agreed in writing; in the platform each new version is approved by the signatories of both parties before it is published.' },
      { h: '15. Governing law', t: 'This Agreement is governed by the laws of the Kingdom of Saudi Arabia. Disputes the parties cannot settle within 30 days go to the competent courts of Riyadh.' },
      { h: 'Signatures', t: 'For the Customer: ' + or(P.customer.signatory.name, 'name') + ', ' + or(P.customer.signatory.title, 'title') + '\nFor the Provider: ' + or(P.provider.signatory.name, 'name') + ', ' + or(P.provider.signatory.title, 'title') },
    ];
  }
  function ndaSections(c) {
    const P = c.parties;
    return [
      { h: '1. Parties', t: partiesText(c).join('\n') + '\nEach party may disclose and receive Confidential Information (mutual agreement).' },
      { h: '2. Purpose', t: 'Evaluating, delivering and receiving the IT operations, cyber security, governance, risk and compliance and internal audit remediation services between the parties (the "Purpose").' },
      { h: '3. Confidential Information', t: 'All information disclosed in any form in connection with the Purpose, including system configurations, network diagrams, credentials, vulnerability and audit findings, security incidents, logs, personal data, policies, commercial terms, and the source code, documentation and know-how of the platform.' },
      { h: '4. Obligations', t: 'The receiving party uses Confidential Information only for the Purpose; discloses it only to its personnel and the Delivery Partner who need it and are bound in writing by obligations at least as strict; protects it at least as carefully as its own and never with less than reasonable care; does not copy, reverse engineer or remove it from the agreed environments; and reports any unauthorised disclosure within 24 hours.' },
      { h: '5. Exceptions', t: 'Obligations do not apply to information that is or becomes public through no fault of the receiving party, was lawfully known to it before disclosure, is independently developed without use of it, or is lawfully received from a third party without restriction. Disclosure required by law, a court or a regulator (including SAMA, NCA, SDAIA) is permitted after prompt notice to the disclosing party where lawful.' },
      { h: '6. Personal data', t: 'Personal data is processed only on the Customer\'s instructions and in line with the Personal Data Protection Law and its Implementing Regulations; it stays in the Kingdom of Saudi Arabia unless the Customer approves a transfer in writing; personal data breaches are notified to the Customer without delay and in any case within 24 hours of awareness so the Customer can meet its 72-hour obligation.' },
      { h: '7. Security', t: 'Access to the Customer\'s systems is by named accounts with multi-factor authentication, least privilege and logging, consistent with the NCA Essential Cybersecurity Controls (third-party cybersecurity) and the SAMA Cyber Security Framework.' },
      { h: '8. Return and destruction', t: 'On request or at the end of the Purpose, the receiving party returns or securely destroys Confidential Information and confirms it in writing, except copies law requires it to keep, which stay protected under this Agreement.' },
      { h: '9. Intellectual property', t: 'No licence or right is granted by disclosure. The platform remains the property of Citynet Work and Zyberon Information Technology, Saudi Arabia; the Customer\'s data and documents remain the Customer\'s.' },
      { h: '10. Term', t: 'This Agreement takes effect on signature and its obligations last for the duration of the relationship and 5 years after it ends; for credentials, personal data and security findings they continue for as long as the information remains confidential.' },
      { h: '11. Remedies', t: 'Unauthorised disclosure may cause irreparable harm; the disclosing party may seek injunctive relief in addition to any other remedy.' },
      { h: '12. Governing law', t: 'This Agreement is governed by the laws of the Kingdom of Saudi Arabia; the competent courts of Riyadh have jurisdiction.' },
      { h: 'Signatures', t: 'For the Customer: ' + or(P.customer.signatory.name, 'name') + ', ' + or(P.customer.signatory.title, 'title') + '\nFor the Provider: ' + or(P.provider.signatory.name, 'name') + ', ' + or(P.provider.signatory.title, 'title') },
    ];
  }
  const docView = (d) => Object.assign({}, d, { placeholders: (JSON.stringify(d.sections).match(/\[(CR number|address|name|title|start date|monthly fee)\]/g) || []).length });
  function documents(who) {
    const all = C.docs().all().sort((a, b) => a.kind.localeCompare(b.kind) || b.version - a.version), admin = who.role === 'admin', mine = partyOf(who);
    const published = ['sla', 'nda'].map((k) => all.find((d) => d.kind === k && d.state === 'published') || null).filter(Boolean).map(docView);
    return { published, versions: (admin || mine) ? all.map(docView) : [], can_edit: admin, party: mine };
  }
  function generate(input, who) {
    if (SERVICE.test(String(who.user || ''))) throw httpErr(403, 'a person drafts the agreement');
    const b = body(input).oneOf('kind', ['sla', 'nda'], { required: true }).done(), c = cfg();
    if (C.docs().all().some((d) => d.kind === b.kind && ['draft', 'review'].includes(d.state))) throw httpErr(409, 'a ' + b.kind.toUpperCase() + ' draft is already open - finish or discard it first');
    const ver = Math.max(0, ...C.docs().all().filter((d) => d.kind === b.kind).map((d) => d.version)) + 1;
    const d = { id: b.kind + '-v' + ver, kind: b.kind, version: ver, title: b.kind === 'sla' ? 'Service Level Agreement' : 'Mutual Non-Disclosure Agreement', terms_version: c.version, sections: b.kind === 'sla' ? slaSections(c) : ndaSections(c), state: 'draft', approvals: [], created_by: who.user, created_at: iso(), history: [] };
    hist(d, who, 'drafted from terms v' + c.version); C.docs().put(d); audit(who, 'sla.document.draft', d.id, { kind: d.kind, version: ver });
    return docView(d);
  }
  function docAct(id, action, input, who) {
    const d = C.docs().get(id); if (!d) throw httpErr(404, 'there is no document "' + id + '"');
    const x = JSON.parse(JSON.stringify(d)), c = cfg();
    if (action === 'edit') {
      if (who.role !== 'admin') throw httpErr(403, 'an administrator edits a draft'); if (x.state !== 'draft') throw httpErr(409, 'only a draft is edited - it is ' + x.state);
      const b = body(input).list('sections', { required: true, max: 40 }).done();
      x.sections = b.sections.map((s, i) => { if (!s || typeof s !== 'object') throw httpErr(400, 'sections[' + i + '] must be {h, t}'); return body(s).str('h', { required: true, max: 160 }).str('t', { required: true, max: 8000 }).done(); });
      hist(x, who, 'edited');
    } else if (action === 'submit') {
      if (who.role !== 'admin') throw httpErr(403, 'an administrator sends a draft for approval'); if (x.state !== 'draft') throw httpErr(409, 'the document is ' + x.state);
      if (!c.parties.customer.signatory.user || !c.parties.provider.signatory.user) throw httpErr(424, 'name the signatory (sign-in) of both parties under Terms first');
      x.state = 'review'; hist(x, who, 'sent for approval');
    } else if (action === 'approve') {
      if (x.state !== 'review') throw httpErr(409, 'the document is ' + x.state);
      if (SERVICE.test(String(who.user || ''))) throw httpErr(403, 'a person approves an agreement');
      const p = ['customer', 'provider'].find((k) => low(c.parties[k].signatory.user) === low(who.user)); if (!p) throw httpErr(403, 'only the named signatory of a party approves the agreement');
      if (x.approvals.some((a) => a.party === p)) throw httpErr(409, 'the ' + p + ' has already approved this version');
      x.approvals.push({ party: p, user: who.user, name: c.parties[p].signatory.name || who.user, at: iso() }); hist(x, who, 'approved for the ' + p);
      if (x.approvals.length === 2) {
        for (const o of C.docs().all()) if (o.kind === x.kind && o.state === 'published') C.docs().put(Object.assign({}, o, { state: 'superseded', superseded_at: iso() }));
        x.state = 'published'; x.published_at = iso(); hist(x, who, 'published');
      }
    } else if (action === 'discard') {
      if (who.role !== 'admin') throw httpErr(403, 'an administrator discards a draft'); if (!['draft', 'review'].includes(x.state)) throw httpErr(409, 'a ' + x.state + ' document is kept');
      x.state = 'discarded'; hist(x, who, 'discarded');
    } else throw httpErr(404, 'unknown action');
    C.docs().put(x); audit(who, 'sla.document.' + action, id, { state: x.state, approvals: x.approvals.map((a) => a.party) });
    return docView(x);
  }

  function view(who) {
    const c = cfg(), t = now(), mine = partyOf(who, c), m = monthOf(t), prev = monthOf(Date.parse(m + '-01T00:00:00Z') - RIYADH - DAY);
    const cases = C.cases().all().map((x) => caseView(x, c, t)), open = cases.filter((x) => !['resolved', 'closed'].includes(x.status));
    const cur = compute(m), terms = Object.assign({}, c);
    if (!(who.role === 'admin' || mine)) terms.members = { customer: c.members.customer.length, provider: c.members.provider.length };
    return { terms, party: mine, can_edit: who.role === 'admin', documents: documents(who), month: m, previous: prev, current: cur.summary, previous_state: (C.st().get(prev) || {}).state || 'not issued',
      cases: { open: open.length, at_risk: open.filter((x) => x.resolve_used_pct >= 75 || x.response_used_pct >= 75).length, breached: open.filter((x) => x.resolve_met === false || x.response_met === false).length },
      audit_due: findings().filter((f) => !['implemented', 'closed', 'withdrawn', 'risk_accepted', 'draft'].includes(f.state)).map((f) => ({ id: f.id, team: f.team_name, rating: f.rating, title: f.title, due: new Date(Date.parse(f.issued_at) + c.audit.days[f.rating] * DAY).toISOString().slice(0, 10) })).sort((a, b) => a.due.localeCompare(b.due)).slice(0, 50) };
  }
  return { view, saveTerms, listCases, openCase, caseAct, saveMeasure, compute, statement, issue, decideStatement, documents, generate, docAct, cfg, coverMinutes, coverDeadline };
}

function registerServiceAgreement(srv, app, S0) {
  const S = S0 || createServiceAgreement(app);
  app.addons = app.addons || {}; app.addons.serviceAgreement = S;
  const party = { anyRole: 'the two parties\' people act whatever their access level - membership is checked in the handler' };
  const M = (ctx) => String(ctx.params.month || '');
  srv.route('GET', '/sla', (ctx) => { ctx.need('viewer'); return S.view(ctx.who); });
  srv.route('POST', '/sla/terms', (ctx) => { ctx.need('admin'); const b = ctx.body || {}; return S.saveTerms(b.terms || {}, ctx.who, b.baseVersion); }, { maxBody: 65536 });
  srv.route('GET', '/sla/cases', (ctx) => { ctx.need('viewer'); return S.listCases(ctx.query || {}, ctx.who); });
  srv.route('POST', '/sla/cases', (ctx) => { ctx.need('viewer'); return S.openCase(ctx.body, ctx.who); }, Object.assign({ maxBody: 16384 }, party));
  srv.route('POST', '/sla/cases/:id/:action', (ctx) => { ctx.need('viewer'); return S.caseAct(ctx.params.id, ctx.params.action, ctx.body, ctx.who); }, Object.assign({ maxBody: 8192 }, party));
  srv.route('POST', '/sla/measures/:month', (ctx) => { ctx.need('viewer'); return S.saveMeasure(M(ctx), ctx.body, ctx.who); }, party);
  srv.route('GET', '/sla/statements/:month', (ctx) => { ctx.need('viewer'); return S.statement(M(ctx)); });
  srv.route('POST', '/sla/statements/:month/issue', (ctx) => { ctx.need('viewer'); return S.issue(M(ctx), ctx.who); }, party);
  srv.route('POST', '/sla/statements/:month/decide', (ctx) => { ctx.need('viewer'); return S.decideStatement(M(ctx), ctx.body, ctx.who); }, party);
  srv.route('GET', '/sla/documents', (ctx) => { ctx.need('viewer'); return S.documents(ctx.who); });
  srv.route('POST', '/sla/documents', (ctx) => { ctx.need('admin'); return S.generate(ctx.body, ctx.who); });
  srv.route('POST', '/sla/documents/:id/:action', (ctx) => { ctx.need('viewer'); return S.docAct(ctx.params.id, ctx.params.action, ctx.body, ctx.who); }, Object.assign({ maxBody: 131072 }, { anyRole: 'a signatory of either party approves whatever their access level - edit, submit and discard are admin-only in the handler' }));
  return S;
}

module.exports = { createServiceAgreement, registerServiceAgreement, coverMinutes, coverDeadline, DEFAULTS };
