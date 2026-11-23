// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const crypto = require('node:crypto');
const G = require('../util/ai-guard');
const SC = require('../approvers/scopes');
const { createModel, runLoop } = require('./ai-loop');
/*
 * Insider Risk (the portal's "Insider Risk", which showed illustrative people). Live, from what the SIEM already learns - nothing is
 * assessed twice and nothing is invented:
 *   UEBA        each user's behaviour risk against their own history and their peers (engine/ueba)
 *   DLP         each person's DLP risk: data that left, sensitive classes, channels, after hours, agent tamper (reports/dlp.js)
 *   watchlist   context a person adds for a limited time - departing (with the last working day), privileged role, role change - with
 *               a reason, approved by a different person (an administrator, never the requester, never a service / AI identity),
 *               at most 90 days; an expired entry stops counting by itself
 * Behaviour is an INDICATOR, never proof of wrongdoing (PDPL). People are PSEUDONYMISED: everyone who may open the page sees
 * "P-xxxxxxxx" and the department. A name is shown only inside an authorised case, to the person who asked for it or the person who
 * authorised it, and every look is audited. Viewers and analysts cannot open the programme at all.
 *
 * Score 0-100 per person, every point itemised: UEBA risk x 0.4 (max 40) + DLP risk x 0.4 (max 40) + context (departing with any
 * other signal +15, privileged +5) + patterns (data left while departing +10, DLP agent disabled +10).
 * Learning (explainable): within a department of 5+ people with a score, a robust z (median / MAD) above 3 marks a person as unusual
 * for their peers; the two-signal pattern (behaviour AND data) separates a real lead from one noisy detector.
 * Cases: requested with a basis and a reason (operator) → authorised / rejected by a different administrator → investigating →
 * closed with an outcome (no concern, policy reminder, HR referral, security incident) and a note. Every step audited by the routes.
 * AI insider-risk analyst: sees only pseudonyms and indicators, writes neutral questions and benign explanations to rule out; it
 * never names, accuses or decides, and changes nothing.
 *
 *   createInsider({ state, ueba?, dlp?, config, log, sdk?, now? }) → { view(), person(p), watchAdd, watchDecide, caseOpen, caseDecide,
 *     caseNote, caseClose, caseSubject, cases(), ask(p, question, who) }
 */
const DAY = 86400000;
const BASES = ['indicators', 'hr_referral', 'legal_request', 'incident'];
const OUTCOMES = ['no_concern', 'policy_reminder', 'hr_referral', 'security_incident'];
const CONTEXTS = ['departing', 'privileged', 'role_change'];
const httpErr = (code, msg) => Object.assign(new Error(msg), { code, status: code });
const S = (o) => Object.assign({ type: 'object', additionalProperties: false }, o);
const STR = (max) => ({ type: 'string', maxLength: max || 2000 });
const median = (a) => { const t = [...a].sort((x, y) => x - y), m = t.length >> 1; return t.length % 2 ? t[m] : (t[m - 1] + t[m]) / 2; };

const SYSTEM = `You support ${ZYB_ORG.short}'s insider-risk team. You see ONE pseudonymised person's indicators: behaviour (UEBA), DLP and the context a manager recorded.
Indicators are reasons to look, never proof of wrongdoing (Saudi PDPL). Never guess or ask who the person is, never judge intent, character or private life, and never recommend action against the person.
Read the indicators (person_indicators) and the peer comparison (peer_group), then call submit_note once:
- summary: what stands out, in two or three neutral sentences;
- benign_explanations: ordinary reasons to rule out first (a new role, a project hand-over, a migration, approved travel);
- questions: neutral questions for the line manager or data owner;
- recommendation: no_action, keep_watching, or open_case (a person decides);
- refs: the indicator ids you relied on.`;

function createInsider(deps = {}) {
  const state = deps.state; if (!state) throw new Error('createInsider needs deps.state');
  const now = deps.now || Date.now, L = deps.log || { info() {}, warn() {}, error() {} };
  const watch = state.collection('insider_watch'), casesC = state.collection('insider_cases'), meta = state.collection('insider_meta');
  const AI = createModel({ config: deps.config || {}, deps, log: L });
  const key = () => { let k = meta.get('pseudonym_key'); if (!k) { k = { id: 'pseudonym_key', v: crypto.randomBytes(32).toString('hex'), at: now() }; meta.put(k); } return k.v; };
  const pseud = (user) => 'P-' + crypto.createHmac('sha256', key()).update(String(user || '').toLowerCase()).digest('hex').slice(0, 8);
  const today = () => new Date(now()).toISOString().slice(0, 10);
  const person0 = (who, what) => { if (!SC.isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const nextId = () => { const n = ((meta.get('case_seq') || {}).n || 0) + 1; meta.put({ id: 'case_seq', n }); return 'IRC-' + String(n).padStart(4, '0'); };

  // ---- signals
  async function signals() {
    const notes = [], P = new Map();
    const get = (u) => { const k = String(u || '').toLowerCase(); if (!k) return null; if (!P.has(k)) P.set(k, { user: k, dept: '', ueba: null, dlp: null, watch: [] }); return P.get(k); };
    if (deps.ueba) {
      try { for (const e of deps.ueba.entities({ type: 'user', limit: 500 }).items || []) { const p = get(e.name || e.id); if (!p) continue; p.dept = e.peer_group || p.dept; p.ueba = { score: Math.round((e.risk && e.risk.score) || 0), tier: (e.risk && e.risk.tier) || 'low', id: e.id, factors: ((e.risk && e.risk.contributions) || (e.risk && e.risk.factors) || []).slice(0, 5).map((f) => (typeof f === 'string' ? f : f.detector || f.name || f.why || JSON.stringify(f)).slice(0, 160)) }; } }
      catch (x) { notes.push('UEBA could not be read'); L.warn('insider: UEBA not read', { err: String(x.message).slice(0, 160) }); }
    } else notes.push('UEBA is not running');
    if (deps.dlp) {
      try { const d = await (deps.dlp.api || deps.dlp).summary({ period: '30d' }, { names: true }); if (!d.available) notes.push('no DLP incident in 30 days (or DLP not connected)'); for (const u of d.users || []) { const p = get(u.user); if (p) p.dlp = { risk: u.risk, why: u.why || [], left: u.left, incidents: u.incidents, tamper: u.tamper || 0, sensitive: u.sensitive || [] }; } }
      catch (x) { notes.push('DLP could not be read'); L.warn('insider: DLP not read', { err: String(x.message).slice(0, 160) }); }
    } else notes.push('DLP analysis is not running');
    const t = today();
    for (const w of watch.all()) if (w.status === 'active' && w.until >= t) { const p = get(w.user); if (p) p.watch.push({ context: w.context, last_day: w.last_day || null, until: w.until }); }
    return { people: [...P.values()], notes };
  }
  function score(p) {
    const why = []; let s = 0;
    const add = (pts, txt, id) => { if (pts > 0) { s += pts; why.push({ id, points: pts, why: txt }); } };
    if (p.ueba && p.ueba.score) add(Math.min(40, Math.round(p.ueba.score * 0.4)), 'behaviour risk ' + p.ueba.score + ' / 100 (' + p.ueba.tier + ')' + (p.ueba.factors.length ? ': ' + p.ueba.factors.join('; ') : ''), 'ueba');
    if (p.dlp && p.dlp.risk) add(Math.min(40, Math.round(p.dlp.risk * 0.4)), 'DLP risk ' + p.dlp.risk + ' / 100: ' + (p.dlp.why || []).slice(0, 4).map((w) => (typeof w === 'string' ? w : w.why || w.what || '')).join('; '), 'dlp');
    const dep = p.watch.find((w) => w.context === 'departing'), other = (p.ueba && p.ueba.score >= 20) || (p.dlp && p.dlp.incidents);
    if (dep && other) add(15, 'departing' + (dep.last_day ? ' (last day ' + dep.last_day + ')' : '') + ' with other indicators', 'ctx-departing');
    if (p.watch.some((w) => w.context === 'privileged')) add(5, 'holds a privileged role', 'ctx-privileged');
    if (dep && p.dlp && p.dlp.left) add(10, 'pattern: ' + p.dlp.left + ' DLP incident(s) where data left while departing', 'pattern-exfil');
    if (p.dlp && p.dlp.tamper) add(10, 'pattern: the DLP agent was disabled on their account', 'pattern-tamper');
    s = Math.min(100, s);
    return { score: s, tier: s >= 70 ? 'high' : s >= 40 ? 'elevated' : 'low', why, two_signals: !!(p.ueba && p.ueba.score >= 20 && p.dlp && p.dlp.risk >= 20) };
  }
  async function model() {
    const sg = await signals(), rows = sg.people.map((p) => Object.assign({ pseudonym: pseud(p.user), dept: p.dept || 'unknown', sources: { ueba: !!p.ueba, dlp: !!p.dlp, watch: p.watch.length > 0 } }, score(p), { _user: p.user, _p: p })).filter((r) => r.score > 0);
    const byDept = {}; for (const r of rows) (byDept[r.dept] = byDept[r.dept] || []).push(r);
    for (const [d, L0] of Object.entries(byDept)) {
      if (L0.length < 5) { for (const r of L0) r.peer = { why: 'department too small to compare (' + L0.length + ' with a score; 5 needed)' }; continue; }
      const m = median(L0.map((r) => r.score)), mad = median(L0.map((r) => Math.abs(r.score - m))) || 1;
      for (const r of L0) { const z = Math.round(((r.score - m) / (1.4826 * mad)) * 10) / 10; r.peer = { z, median: m, unusual: z > 3, why: z > 3 ? 'unusual for ' + d + ': score ' + r.score + ' against a peer median of ' + m : 'within the usual range of ' + d }; }
    }
    rows.sort((a, b) => b.score - a.score);
    return { rows, notes: sg.notes };
  }
  const pub = (r) => ({ pseudonym: r.pseudonym, dept: r.dept, score: r.score, tier: r.tier, why: r.why, two_signals: r.two_signals, peer: r.peer, sources: r.sources, open_case: !!casesC.all().find((c) => c.pseudonym === r.pseudonym && !['closed', 'rejected'].includes(c.status)) });
  async function view() {
    const M = await model(), C = casesC.all(), t = today();
    const W = watch.all().map((w) => ({ id: w.id, pseudonym: pseud(w.user), context: w.context, until: w.until, last_day: w.last_day || null, status: w.status === 'active' && w.until < t ? 'expired' : w.status, requested_by: w.requested_by, decided_by: w.decided_by || null, reason: w.reason }));
    const depts = {}; for (const r of M.rows) { const d = depts[r.dept] || (depts[r.dept] = { dept: r.dept, people: 0, high: 0, elevated: 0, sum: 0 }); d.people++; d.sum += r.score; if (r.tier === 'high') d.high++; if (r.tier === 'elevated') d.elevated++; }
    return { generated_at: now(), notes: M.notes, people: M.rows.slice(0, 300).map(pub),
      kpis: { people: M.rows.length, high: M.rows.filter((r) => r.tier === 'high').length, elevated: M.rows.filter((r) => r.tier === 'elevated').length, two_signals: M.rows.filter((r) => r.two_signals).length, unusual: M.rows.filter((r) => r.peer && r.peer.unusual).length,
        cases_open: C.filter((c) => ['requested', 'authorised', 'investigating'].includes(c.status)).length, awaiting: C.filter((c) => c.status === 'requested').length + W.filter((w) => w.status === 'requested').length, watch_active: W.filter((w) => w.status === 'active').length },
      departments: Object.values(depts).map((d) => ({ dept: d.dept, people: d.people, high: d.high, elevated: d.elevated, avg: Math.round(d.sum / d.people) })).sort((a, b) => b.avg - a.avg),
      watchlist: W, cases: C.map(caseView).sort((a, b) => b.opened_at - a.opened_at), ai: AI.status(),
      framing: 'Behavioural indicators, not proof of wrongdoing (PDPL). People are pseudonymised; a name is shown only inside an authorised case.' };
  }
  async function person(p) {
    if (!/^P-[0-9a-f]{8}$/.test(String(p))) throw httpErr(400, 'pseudonym must look like P-1a2b3c4d');
    const M = await model(), r = M.rows.find((x) => x.pseudonym === p); if (!r) throw httpErr(404, 'no indicators for ' + p);
    return Object.assign(pub(r), { ueba: r._p.ueba ? { score: r._p.ueba.score, tier: r._p.ueba.tier, factors: r._p.ueba.factors } : null, dlp: r._p.dlp ? { risk: r._p.dlp.risk, incidents: r._p.dlp.incidents, left: r._p.dlp.left, sensitive: r._p.dlp.sensitive, tamper: r._p.dlp.tamper } : null, context: r._p.watch, cases: casesC.all().filter((c) => c.pseudonym === p).map(caseView) });
  }
  // ---- watchlist
  function watchAdd(b, who) {
    person0(who, 'add watchlist context');
    const until = b.until, max = new Date(now() + 90 * DAY).toISOString().slice(0, 10);
    if (until <= today()) throw httpErr(400, 'until must be in the future'); if (until > max) throw httpErr(400, 'until can be at most 90 days ahead (' + max + ')');
    if (b.context === 'departing' && !b.last_day) throw httpErr(400, 'last_day is required for a departing person');
    const id = 'IRW-' + crypto.randomBytes(4).toString('hex');
    const rec = { id, user: String(b.user).toLowerCase(), context: b.context, until, last_day: b.last_day || null, reason: b.reason, status: 'requested', requested_by: who.user, requested_at: now() };
    watch.put(rec); return { id, pseudonym: pseud(rec.user), status: rec.status };
  }
  function watchDecide(id, b, who) {
    person0(who, 'approve watchlist context');
    const w = watch.get(id); if (!w) throw httpErr(404, 'no watchlist entry ' + id);
    if (w.status !== 'requested') throw httpErr(409, id + ' is ' + w.status);
    if (String(w.requested_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four eyes: ' + who.user + ' asked for this entry and cannot also approve it');
    watch.put(Object.assign({}, w, { status: b.decision === 'approve' ? 'active' : 'rejected', decided_by: who.user, decided_at: now(), note: b.note || '' }));
    return { id, status: watch.get(id).status, pseudonym: pseud(w.user) };
  }
  // ---- cases
  function caseView(c) { return { id: c.id, pseudonym: c.pseudonym, basis: c.basis, reason: c.reason, status: c.status, requested_by: c.requested_by, authorised_by: c.authorised_by || null, opened_at: c.opened_at, outcome: c.outcome || null, notes: (c.notes || []).length, history: c.history || [] }; }
  const hist = (c, by, what) => { c.history = (c.history || []).concat([{ at: now(), by, what }]).slice(-50); };
  async function caseOpen(b, who) {
    person0(who, 'open an insider-risk case');
    const M = await model(), r = M.rows.find((x) => x.pseudonym === b.pseudonym); if (!r) throw httpErr(404, 'no indicators for ' + b.pseudonym + ' - a case starts from indicators the platform holds');
    if (casesC.all().some((c) => c.pseudonym === b.pseudonym && !['closed', 'rejected'].includes(c.status))) throw httpErr(409, b.pseudonym + ' already has an open case');
    const c = { id: nextId(), pseudonym: b.pseudonym, _user: r._user, basis: b.basis, reason: b.reason, status: 'requested', requested_by: who.user, opened_at: now(), score_at_open: r.score, notes: [] };
    hist(c, who.user, 'requested (' + b.basis + ')'); casesC.put(c); return caseView(c);
  }
  function mustCase(id) { const c = casesC.get(id); if (!c) throw httpErr(404, 'no case ' + id); return c; }
  function caseDecide(id, b, who) {
    person0(who, 'authorise an insider-risk case'); const c = mustCase(id);
    if (c.status !== 'requested') throw httpErr(409, id + ' is ' + c.status);
    if (String(c.requested_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four eyes: ' + who.user + ' requested this case and cannot also authorise it');
    c.status = b.decision === 'authorise' ? 'authorised' : 'rejected'; if (c.status === 'authorised') c.authorised_by = who.user; else c.rejected_by = who.user;
    hist(c, who.user, c.status + (b.note ? ': ' + b.note : '')); casesC.put(c); return caseView(c);
  }
  const team = (c, who) => [c.requested_by, c.authorised_by].map((x) => String(x || '').toLowerCase()).includes(String(who.user).toLowerCase());
  function caseSubject(id, who) {
    const c = mustCase(id);
    if (!['authorised', 'investigating'].includes(c.status)) throw httpErr(409, 'the name is shown only for an authorised case (' + id + ' is ' + c.status + ')');
    if (!team(c, who)) throw httpErr(403, 'only the person who requested or authorised ' + id + ' sees the name');
    if (c.status === 'authorised') { c.status = 'investigating'; hist(c, who.user, 'investigation started (name viewed)'); casesC.put(c); }
    return { id, pseudonym: c.pseudonym, user: c._user, note: 'Shown to you for this case only; this view is recorded.' };
  }
  function caseNote(id, b, who) {
    person0(who, 'add a case note'); const c = mustCase(id);
    if (!['authorised', 'investigating'].includes(c.status)) throw httpErr(409, id + ' is ' + c.status);
    if (!team(c, who)) throw httpErr(403, 'only the case team adds notes to ' + id);
    c.notes = (c.notes || []).concat([{ at: now(), by: who.user, text: G.redactSecrets(b.text) }]); casesC.put(c); return caseView(c);
  }
  function caseClose(id, b, who) {
    person0(who, 'close an insider-risk case'); const c = mustCase(id);
    if (!['authorised', 'investigating'].includes(c.status)) throw httpErr(409, id + ' is ' + c.status);
    if (!team(c, who)) throw httpErr(403, 'only the case team closes ' + id);
    c.status = 'closed'; c.outcome = b.outcome; c.closed_at = now(); hist(c, who.user, 'closed: ' + b.outcome + ' - ' + b.note); casesC.put(c); return caseView(c);
  }
  // ---- AI insider-risk analyst (pseudonyms only)
  const TOOLS = [
    { name: 'person_indicators', description: 'The pseudonymised person: score, itemised indicators (UEBA, DLP, context), sources, peer comparison.', input_schema: S({ properties: { pseudonym: STR(12) }, required: ['pseudonym'] }) },
    { name: 'peer_group', description: 'Their department: people with a score, average, high / elevated counts.', input_schema: S({ properties: { dept: STR(120) }, required: ['dept'] }) },
    { name: 'submit_note', description: 'Submit the note. Call once, last.', input_schema: S({ properties: { summary: STR(2000), benign_explanations: { type: 'array', maxItems: 8, items: STR(400) }, questions: { type: 'array', maxItems: 8, items: STR(400) },
      recommendation: { type: 'string', enum: ['no_action', 'keep_watching', 'open_case'] }, refs: { type: 'array', maxItems: 12, items: STR(40) } }, required: ['summary', 'recommendation'] }) }];
  async function ask(p, question, who) {
    const st = AI.status(); if (!st.enabled) throw httpErr(503, st.reason);
    const pr = await person(p);
    const run = async (name, inp, seen) => {
      if (name === 'person_indicators') { if (inp.pseudonym !== p) return { error: 'only ' + p + ' is in scope' }; for (const w of pr.why) seen.add(w.id); return { pseudonym: pr.pseudonym, dept: pr.dept, score: pr.score, tier: pr.tier, indicators: pr.why, two_signals: pr.two_signals, peer: pr.peer, context: pr.context.map((c) => ({ context: c.context, last_day: c.last_day })) }; }
      if (name === 'peer_group') { const v = await view(); return v.departments.find((d) => d.dept === inp.dept) || { error: 'no department ' + String(inp.dept).slice(0, 60) }; }
      throw new Error('unknown tool ' + name);
    };
    const q = G.redactSecrets(String(question || '')).slice(0, 1500);
    const r = await runLoop({ client: AI.client(), model: AI.model(), effort: AI.effort(), system: SYSTEM, tools: TOOLS, role: who.role || 'operator', user: who.user || 'unknown', feature: 'soc.insider-analyst', config: deps.config, log: L,
      prompt: 'Person ' + p + '.' + (q ? '\nThe analyst asks:\n' + G.untrusted('analyst-question', q) : '') + '\nUse the tools, then call submit_note.', run, final: 'submit_note', maxSteps: 6 });
    if (!r.result) throw httpErr(502, 'the AI did not return a note (' + r.note + ') - try again');
    const d = r.result, refs = (d.refs || []).map((x) => ({ ref: x, verified: r.seen.has(String(x)) }));
    return { pseudonym: p, summary: d.summary, benign_explanations: d.benign_explanations || [], questions: d.questions || [], recommendation: d.recommendation, refs, unverified: refs.filter((x) => !x.verified).length, steps: r.steps, usage: r.usage, injection_signals: r.flags,
      framing: 'An indicator summary for a person to review - not a finding about anyone.' };
  }
  return { view, person, watchAdd, watchDecide, caseOpen, caseDecide, caseSubject, caseNote, caseClose, ask, pseud, TOOLS, BASES, OUTCOMES, CONTEXTS };
}

module.exports = { createInsider, BASES, OUTCOMES, CONTEXTS };
