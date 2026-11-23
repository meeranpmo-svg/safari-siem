// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * RoPA by department (PDPL Implementing Regulation Art. 33): the campaign a consultant runs to build the register,
 * automated. The rules are Python (pyengine/pdpl_ropa.py): templates per insurer department, the checks on every draft,
 * suggestions from the Data Catalog and the asset register, progress and duty findings, the approval plan, the export.
 *
 *   The DPO opens a campaign {name, due, departments[]}; each department's data steward (Programme page) describes its
 *   activities - starting from a template, from a system the Data Catalog found holding personal data in the department,
 *   or from an activity already in the register - then submits. The DPO, or an administrator, who did not submit it
 *   approves (the drafts become register records: created or updated, versioned, with who approved) or returns it with a
 *   comment. Stewards edit only their own department; an operator may edit any. Every write is audited.
 *
 *   GET  /pdpl/ropa/templates                         viewer    departments and template activities
 *   GET  /pdpl/ropa/campaigns                         viewer    campaigns; a steward sees the departments they steward,
 *                                                               an operator all
 *   GET  /pdpl/ropa/campaigns/:id                     viewer    the campaign view (same scoping)
 *   POST /pdpl/ropa/campaigns                         operator  {name, due, departments[]}                   audited
 *   POST /pdpl/ropa/campaigns/:id/close               operator                                               audited
 *   POST /pdpl/ropa/drafts                            viewer + steward of the department (or operator)  {campaign, department, id?, ...}  audited
 *   POST /pdpl/ropa/drafts/:id/remove                 viewer + steward (or operator)                         audited
 *   POST /pdpl/ropa/campaigns/:id/submit              viewer + steward (or operator)  {department}           audited
 *   POST /pdpl/ropa/campaigns/:id/review              operator: the DPO / an administrator, not the submitter  {department, decision, comment}  audited
 *   GET  /pdpl/ropa/register?department=              operator  the Art. 33 register (rows), audited
 *   POST /pdpl/ropa/assist                            viewer + steward (or operator)  {campaign, department, ...draft fields, question?}
 *                                                               AI help for one activity: suggestions per field + questions,
 *                                                               checked in code; it never saves a draft (the steward applies
 *                                                               and saves), never submits, never approves. Audited.
 *
 *   The assistant (docs/AI-SECURITY.md): the model sees the steward's own fields, the checks, the department's template
 *   activities and the systems the Data Catalog found in that department - nothing from other departments. Everything the
 *   steward typed and every system name is framed as untrusted data. The answer is schema-checked here: only known fields,
 *   legal_basis / categories from the fixed lists, a system only if the department holds it, a basis the law refuses for
 *   the data (legitimate interest or plain consent on sensitive data) dropped, lia_done never suggested (a person attests a
 *   balancing test), lengths capped. A suggestion is a proposal: the page fills the form only when the steward clicks, and
 *   the department still goes through submit and the DPO's four-eyes review. Injection is mitigated, not solved.
 */
const G = require('./ai-guard');
const { extractJson } = require('./ai/validate');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const low = (v) => String(v || '').trim().toLowerCase();
const CATS = ['identity', 'contact', 'financial', 'health', 'credit', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage', 'location', 'employment', 'other'];
const BASES = ['consent', 'explicit_consent', 'contract', 'legal_obligation', 'vital_interest', 'public_interest', 'legitimate_interest'];
const FLAGS = ['automated_decision', 'large_scale_monitoring', 'fraud_scoring', 'profiling', 'automated_underwriting', 'telematics', 'transfer_outside', 'reinsurance_outside', 'lia_done'];
const SENSITIVE = ['health', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage'];   // PDPL Art. 1; credit is its own class (explicit consent)
const AI_FLAGS = FLAGS.filter((f) => f !== 'lia_done');   // a balancing test is attested by a person, never proposed by the AI
const AI_SYSTEM = [
  'TASK: You help the data steward of one department of a Saudi insurance company describe ONE processing activity for the Records of',
  'Processing Activities (PDPL Implementing Regulation Art. 33). You propose values for the questionnaire; the steward checks them, saves',
  'them and submits; the DPO reviews. You never save, submit or approve anything and you never claim that you did.',
  'Use only what you are given: the steward\'s current fields, the checks that failed, the department\'s template activities and the',
  'systems the Data Catalog found in the department. Do not invent systems, recipients, volumes or retention periods - when a fact only',
  'the department knows is missing, ask the steward a question instead. PDPL rules: sensitive data (health, biometric, genetic, criminal or',
  'security records, religious, intellectual or political beliefs, racial or ethnic origin, unknown parentage) and credit data cannot rest on legitimate interest or plain consent; explicit consent, contract, legal obligation',
  'or vital interest may apply. Prefer the shortest correct wording.',
  'ANSWER: one JSON object and nothing else: {"summary": "<= 2 sentences", "suggestions": [{"field": "<field>", "value": <value>, "why": "<= 1 sentence"}],',
  '"questions": ["<question for the steward>"]}. Fields: name, purpose, legal_basis (' + BASES.join('|') + '), data_categories (list of ' + CATS.join('|') + '),',
  'subjects, systems (list, only systems you were given), retention_months (integer), retention_basis, recipients (list), security_measures,',
  'and the yes/no flags ' + AI_FLAGS.join(', ') + '. At most 10 suggestions and 5 questions.',
].join('\n');
const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, n);

// the model's answer -> what the page may show: unknown fields, values outside the fixed lists, systems the department does
// not hold and bases the law refuses for the data are dropped and counted; nothing here writes anything
function checkSuggestions(j, draft, known) {
  const out = { summary: clip(j && j.summary, 600), suggestions: [], questions: [], dropped: [] };
  if (!j || typeof j !== 'object') return out;
  const knownSys = new Map((known || []).map((s) => [low(s), s]));
  const drop = (field, why) => out.dropped.push({ field: clip(field, 40) || '?', why });
  const strF = { name: 160, purpose: 500, subjects: 300, retention_basis: 300, security_measures: 1000 };
  const seen = new Set();
  for (const x of [].concat(j.suggestions || []).slice(0, 20)) {
    if (!x || typeof x !== 'object') { drop('?', 'not a suggestion'); continue; }
    const f = String(x.field || ''), why = clip(x.why, 300); let v = x.value;
    if (seen.has(f)) { drop(f, 'repeated'); continue; }
    if (strF[f]) { v = clip(v, strF[f]); if (!v) { drop(f, 'empty'); continue; } }
    else if (f === 'legal_basis') { if (!BASES.includes(v)) { drop(f, 'not a legal basis'); continue; } }
    else if (f === 'data_categories') {
      if (!Array.isArray(v)) { drop(f, 'not a list'); continue; }
      const bad = v.filter((c) => !CATS.includes(c)); v = [...new Set(v.filter((c) => CATS.includes(c)))];
      if (bad.length) drop(f, bad.length + ' unknown categor' + (bad.length > 1 ? 'ies' : 'y') + ' removed');
      if (!v.length) continue;
    } else if (f === 'systems') {
      if (!Array.isArray(v)) { drop(f, 'not a list'); continue; }
      const bad = v.filter((s) => !knownSys.has(low(s))); v = [...new Set(v.filter((s) => knownSys.has(low(s))).map((s) => knownSys.get(low(s))))];
      if (bad.length) drop(f, bad.length + ' system(s) the department does not hold removed');
      if (!v.length) continue;
    } else if (f === 'recipients') {
      if (!Array.isArray(v)) { drop(f, 'not a list'); continue; }
      v = [...new Set(v.map((r) => clip(r, 160)).filter(Boolean))].slice(0, 50); if (!v.length) continue;
    } else if (f === 'retention_months') { v = Number(v); if (!Number.isInteger(v) || v < 1 || v > 1200) { drop(f, 'not 1-1200 months'); continue; } }
    else if (AI_FLAGS.includes(f)) { if (typeof v !== 'boolean') { drop(f, 'not yes/no'); continue; } }
    else { drop(f, f === 'lia_done' ? 'a person attests the balancing test' : 'not a questionnaire field'); continue; }
    seen.add(f);
    const cur = draft[f];
    if (JSON.stringify(cur) === JSON.stringify(v) || (cur == null && v === false)) continue;   // nothing to change
    out.suggestions.push({ field: f, value: v, why });
  }
  // the law, in code: a basis that cannot cover the data the activity would hold is not offered
  const cats = (out.suggestions.find((s) => s.field === 'data_categories') || {}).value || draft.data_categories || [];
  const sens = cats.filter((c) => SENSITIVE.includes(c) || c === 'credit');   // both need explicit consent (or another basis the law gives)
  out.suggestions = out.suggestions.filter((s) => {
    if (s.field !== 'legal_basis' || !sens.length || !['legitimate_interest', 'consent'].includes(s.value)) return true;
    drop('legal_basis', s.value + ' cannot cover ' + sens.join(', ') + ' data'); return false;
  }).slice(0, 10);
  out.questions = [].concat(j.questions || []).map((q) => clip(q, 300)).filter(Boolean).slice(0, 5);
  return out;
}

function createRopa(app, PD, opts) {
  const now = opts.now, store = app.store, py = opts.py;
  const camps = () => store.collection('pdpl_ropa_campaigns'), drafts = () => store.collection('pdpl_ropa_drafts');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const iso = () => new Date(now()).toISOString();
  async function rules(op, body) {
    const r = await py.call(op, body);
    if (!r || r.ok === false) throw httpErr(409, 'The RoPA rules run in Python and Python did not answer (' + ((r && r.error_class) || 'no answer') + ') - run the update so pyengine is installed');
    return r;
  }
  const isOp = (who) => who.role === 'operator' || who.role === 'admin';
  const stewardsOf = (dept) => PD.records('steward').filter((s) => s.status !== 'archived' && low(s.department) === low(dept));
  const stewardsMine = (who) => PD.records('steward').filter((s) => s.status !== 'archived' && low(s.user) === low(who.user)).map((s) => low(s.department));
  function mayEdit(who, dept) {
    if (isService(who.user)) throw httpErr(403, 'a person describes the processing, not a service or AI identity');
    if (isOp(who)) return true;
    if (stewardsOf(dept).some((s) => low(s.user) === low(who.user))) return true;
    throw httpErr(403, 'only the data steward of ' + dept + ' (Programme page) or an operator edits its RoPA');
  }
  function camp(id) { const c = camps().get(id); if (!c) throw httpErr(404, 'no RoPA campaign ' + id); return c; }
  function deptOf(c, name) { const k = Object.keys(c.departments || {}).find((d) => low(d) === low(name)); if (!k) throw httpErr(404, name + ' is not in campaign ' + c.id); return k; }
  const openCamp = (c) => { if (c.status !== 'open') throw httpErr(409, c.id + ' is closed'); };

  const templates = () => rules('pdpl.ropa_templates', {});
  function list(who) {
    const mine = isOp(who) ? null : stewardsMine(who);
    return { campaigns: camps().all().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).map((c) => ({ id: c.id, name: c.name, due: c.due, status: c.status, created_at: c.created_at,
      departments: Object.entries(c.departments || {}).filter(([d]) => !mine || mine.includes(low(d))).map(([d, s]) => ({ department: d, status: s.status || 'not_started', steward: s.steward || null })) })),
    can_manage: isOp(who), stewards_of: mine };
  }
  async function view(id, who) {
    const c = camp(id), mine = isOp(who) ? null : stewardsMine(who);
    let assets = []; try { assets = store.collection('assets').all((a) => a.status !== 'disposed').map((a) => ({ name: a.name, hostname: a.hostname, mgmt_ip: a.mgmt_ip, department: a.department })); } catch (e) { assets = []; }
    const scans = store.collection('pdpl_discovery').all((x) => x.id !== '_last');
    const r = await rules('pdpl.ropa_campaign_view', { campaign: c, drafts: drafts().all((d) => d.campaign === id), records: PD.records(), scans, assets, now: now() });
    if (mine) r.departments = r.departments.filter((d) => mine.includes(low(d.department)));
    r.can_manage = isOp(who); r.me = who.user;
    return r;
  }
  function createCampaign(b, who) {
    if (isService(who.user)) throw httpErr(403, 'a person opens a RoPA campaign');
    const deps = {}; for (const d of b.departments) { const st = stewardsOf(d); const pick = st.find((s) => s.role === 'data_steward') || st[0]; deps[d] = { status: 'not_started', steward: pick ? pick.user : null, comments: [] }; }
    let n = camps().size() + 1, id = 'RC-' + String(n).padStart(3, '0'); while (camps().get(id)) id = 'RC-' + String(++n).padStart(3, '0');
    const c = { id, name: b.name, due: b.due, status: 'open', departments: deps, created_by: who.user, created_at: iso() };
    camps().put(c);
    audit(who, 'pdpl.ropa.campaign.open', id, { name: b.name, due: b.due, departments: b.departments.length, without_steward: Object.values(deps).filter((x) => !x.steward).length });
    return c;
  }
  function closeCampaign(id, who) {
    const c = camp(id); openCamp(c);
    if (isService(who.user)) throw httpErr(403, 'a person closes a RoPA campaign');
    const rec = Object.assign({}, c, { status: 'closed', closed_at: iso(), closed_by: who.user }); camps().put(rec);
    audit(who, 'pdpl.ropa.campaign.close', id, { approved: Object.values(c.departments).filter((d) => d.status === 'approved').length, departments: Object.keys(c.departments).length });
    return rec;
  }
  function putDraft(b, who) {
    const c = camp(b.campaign); openCamp(c);
    const dept = deptOf(c, b.department); mayEdit(who, dept);
    const st = c.departments[dept];
    if (st.status === 'submitted') throw httpErr(409, dept + ' is submitted and waiting for review - the DPO returns it to change it');
    if (st.status === 'approved') throw httpErr(409, dept + ' is approved - open a new campaign for changes');
    if (b.ropa_id) { const r = PD.records('ropa').find((x) => x.id === b.ropa_id); if (!r) throw httpErr(404, 'no processing activity ' + b.ropa_id); }
    const fields = Object.assign({}, b); delete fields.campaign; delete fields.department; delete fields.id;
    let rec;
    if (b.id) {
      const cur = drafts().get(b.id); if (!cur || cur.campaign !== c.id || low(cur.department) !== low(dept)) throw httpErr(404, 'no draft ' + b.id + ' in ' + dept);
      if (cur.status === 'removed') throw httpErr(409, b.id + ' was removed');
      rec = Object.assign({}, cur, fields, { updated_by: who.user, updated_at: iso() });
    } else {
      if (!b.name) throw httpErr(400, 'name is required');
      if (drafts().all((d) => d.campaign === c.id && d.status !== 'removed').length >= 500) throw httpErr(409, 'a campaign holds at most 500 activities');
      let n = drafts().size() + 1, id = 'RD-' + String(n).padStart(4, '0'); while (drafts().get(id)) id = 'RD-' + String(++n).padStart(4, '0');
      rec = Object.assign({ id, campaign: c.id, department: dept, owner: dept, status: 'draft', created_by: who.user, created_at: iso() }, fields, { updated_by: who.user, updated_at: iso() });
    }
    drafts().put(rec);
    if (st.status === 'not_started' || st.status === 'returned') camps().put(Object.assign({}, c, { departments: Object.assign({}, c.departments, { [dept]: Object.assign({}, st, { status: 'in_progress' }) }) }));
    audit(who, 'pdpl.ropa.draft.put', rec.id, { campaign: c.id, department: dept, template: rec.template || null, fields: Object.keys(fields).sort() });
    return rec;
  }
  function removeDraft(id, who) {
    const d = drafts().get(id); if (!d) throw httpErr(404, 'no draft ' + id);
    const c = camp(d.campaign); openCamp(c); mayEdit(who, d.department);
    const st = c.departments[d.department]; if (st.status === 'submitted' || st.status === 'approved') throw httpErr(409, d.department + ' is ' + st.status);
    drafts().put(Object.assign({}, d, { status: 'removed', removed_by: who.user, removed_at: iso() }));
    audit(who, 'pdpl.ropa.draft.remove', id, { campaign: c.id, department: d.department });
    return { id, removed: true };
  }
  async function submit(id, b, who) {
    const c = camp(id); openCamp(c);
    const dept = deptOf(c, b.department); mayEdit(who, dept);
    const st = c.departments[dept];
    if (st.status === 'submitted' || st.status === 'approved') throw httpErr(409, dept + ' is already ' + st.status);
    const v = await view(id, { user: who.user, role: 'admin' }), d = v.departments.find((x) => x.department === dept);
    if (!d || !d.drafts.length) throw httpErr(409, 'describe at least one processing activity before submitting');
    const gaps = d.drafts.filter((x) => x.gaps); if (gaps.length) throw httpErr(409, 'complete the missing fields first: ' + gaps.map((x) => x.name + ' (' + x.gaps + ')').join(', '));
    camps().put(Object.assign({}, c, { departments: Object.assign({}, c.departments, { [dept]: Object.assign({}, st, { status: 'submitted', submitted_by: who.user, submitted_at: iso() }) }) }));
    audit(who, 'pdpl.ropa.submit', id, { department: dept, activities: d.drafts.length });
    return { campaign: id, department: dept, status: 'submitted' };
  }
  async function review(id, b, who) {
    const c = camp(id); openCamp(c);
    if (isService(who.user)) throw httpErr(403, 'a person approves the RoPA, not a service or AI identity');
    const dept = deptOf(c, b.department), st = c.departments[dept];
    if (st.status !== 'submitted') throw httpErr(409, dept + ' is ' + (st.status || 'not started') + ' - only a submitted department is reviewed');
    const P = PD.records('profile')[0] || {};
    const isDpo = P.dpo_user && low(P.dpo_user) === low(who.user);
    if (!isDpo && who.role !== 'admin') throw httpErr(403, 'the DPO (' + (P.dpo_user || 'not named') + ') or an administrator approves the RoPA');
    if (low(st.submitted_by) === low(who.user)) throw httpErr(403, 'four-eyes: the person who submitted ' + dept + ' cannot review it');
    const comment = { at: iso(), by: who.user, decision: b.decision, text: b.comment || '' };
    if (b.decision === 'return') {
      camps().put(Object.assign({}, c, { departments: Object.assign({}, c.departments, { [dept]: Object.assign({}, st, { status: 'returned', comments: (st.comments || []).concat([comment]) }) }) }));
      audit(who, 'pdpl.ropa.return', id, { department: dept, comment: String(b.comment).slice(0, 200) });
      return { campaign: id, department: dept, status: 'returned' };
    }
    const mine = drafts().all((d) => d.campaign === id && low(d.department) === low(dept) && d.status !== 'removed');
    const plan = (await rules('pdpl.ropa_approve_plan', { drafts: mine, records: PD.records() })).writes;
    const t = iso(), out = [];
    for (const w of plan) {
      const rec = PD.putRecord(Object.assign({ kind: 'ropa' }, w.ropa_id ? { id: w.ropa_id } : {}, w.fields, { owner: dept, version: w.version, approved_by: who.user, approved_at: t, reviewed: t.slice(0, 10), from_campaign: id }), who);
      drafts().put(Object.assign({}, drafts().get(w.draft), { status: 'approved', ropa_id: rec.id, approved_at: t }));
      out.push({ draft: w.draft, ropa_id: rec.id, op: w.op, changed: w.changed });
    }
    camps().put(Object.assign({}, c, { departments: Object.assign({}, c.departments, { [dept]: Object.assign({}, st, { status: 'approved', reviewed_by: who.user, reviewed_at: t, comments: (st.comments || []).concat([comment]) }) }) }));
    audit(who, 'pdpl.ropa.approve', id, { department: dept, created: out.filter((x) => x.op === 'create').length, updated: out.filter((x) => x.op === 'update').length, records: out.map((x) => x.ropa_id) });
    return { campaign: id, department: dept, status: 'approved', register: out };
  }
  async function exportRegister(q, who) {
    const r = await rules('pdpl.ropa_export', { records: PD.records(), department: q.department || '' });
    audit(who, 'pdpl.ropa.export', q.department || 'all', { rows: r.rows.length });
    return r;
  }
  async function findings() {
    const out = [];
    for (const c of camps().all((x) => x.status === 'open')) { try { out.push(...(await view(c.id, { user: 'system:pdpl', role: 'admin' })).findings); } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:ropa-findings', 3600000, 'warn', 'RoPA campaign findings not computed', { err: String(e.message).slice(0, 200) }); } }
    return out;
  }
  async function assist(b, who) {
    const c = camp(b.campaign); openCamp(c);
    const dept = deptOf(c, b.department); mayEdit(who, dept);
    const st = c.departments[dept];
    if (st.status === 'submitted' || st.status === 'approved') throw httpErr(409, dept + ' is ' + st.status + ' - nothing to fill in');
    const question = b.question || ''; const draft = Object.assign({}, b); for (const k of ['campaign', 'department', 'question', 'id']) delete draft[k];
    const NOTE = 'AI suggestion - verify every value. Nothing is saved until you save the questionnaire, and the DPO still reviews the department.';
    if (!app.provider) return { available: false, message: 'There is no AI provider on this server.', note: NOTE };
    let ps; try { ps = await app.provider.status(); } catch (e) { ps = { state: 'error', message: 'the AI provider did not answer (' + clip(e.message, 120) + ')' }; }
    if (ps.state !== 'ready') return { available: false, message: ps.message || ps.state, note: NOTE };
    let scans = [], assets = [];
    try { assets = store.collection('assets').all((a) => a.status !== 'disposed').map((a) => ({ name: a.name, hostname: a.hostname, mgmt_ip: a.mgmt_ip, department: a.department })); } catch (e) { assets = []; /* no asset register yet: the assistant works without department systems */ }
    scans = store.collection('pdpl_discovery').all((x) => x.id !== '_last');
    const ctxR = await rules('pdpl.ropa_assist_context', { draft, department: dept, records: PD.records('ropa'), scans, assets });
    const known = ctxR.known_systems || [];
    const prompt = [
      'DEPARTMENT: ' + dept,
      'FIELDS (key: label): ' + (ctxR.fields || []).map((f) => f[0] + ': ' + f[1]).join('; '),
      'CHECKS THAT FAILED (from the platform rules): ' + JSON.stringify((ctxR.issues || []).map((i) => ({ level: i.level, field: i.field, text: i.text }))),
      'TEMPLATE THE STEWARD STARTED FROM: ' + JSON.stringify(ctxR.template || null),
      'OTHER TEMPLATE ACTIVITIES OF THE DEPARTMENT: ' + JSON.stringify(ctxR.department_templates || []),
      G.untrusted('ropa.draft', JSON.stringify(draft)),
      G.untrusted('pdpl.data_catalog', JSON.stringify({ department_systems: ctxR.department_systems || [], activity_systems: ctxR.draft_systems || [] })),
      question ? G.untrusted('steward.question', question) : 'STEWARD QUESTION: none - review the activity and fill what you can.',
    ].join('\n\n');
    let res; try { res = await app.provider.call({ system: AI_SYSTEM, prompt, who: { user: who.user }, feature: 'itam.ropa_assist' }); } catch (e) { res = { ok: false, code: 'error', message: clip(e.message, 200) }; }
    const j = res && res.ok ? extractJson(res.text || '').obj : null;
    const out = res && res.ok ? checkSuggestions(j, draft, known) : null;
    audit(who, 'ai.call', c.id, { feature: 'ropa_assist', department: dept, status: res && res.ok ? (j ? 'ok' : 'unreadable') : 'error', code: res && !res.ok ? res.code || null : null, model: (res && res.model) || null,
      suggested: out ? out.suggestions.map((x) => x.field) : [], dropped: out ? out.dropped.length : 0, question: !!question, injection_signals: G.injectionSignals(prompt).length,
      prompt_sha256: (res && res.sent_prompt_sha256) || null });
    if (!res || !res.ok) return { available: true, ok: false, message: 'The AI could not answer: ' + clip((res && res.message) || 'no answer', 200), note: NOTE };
    if (!j) return { available: true, ok: false, message: 'The AI answer was not in the expected form - try again or fill the questionnaire yourself.', note: NOTE };
    return Object.assign({ available: true, ok: true, model: res.model || null, note: NOTE, issues: ctxR.issues || [] }, out);
  }
  return { templates, list, view, createCampaign, closeCampaign, putDraft, removeDraft, submit, review, exportRegister, findings, assist };
}

function registerRopaRoutes(srv, app, R) {
  const { body, param } = require('./check');
  const CID = (ctx) => { const id = param(ctx.params.id, 'id'); if (!/^RC-\d{3,}$/.test(id)) throw httpErr(400, 'id must be a RoPA campaign id (RC-nnn)'); return id; };
  const DEPT = { required: true, max: 120, re: /^[A-Za-z0-9؀-ۿ &/().,'-]+$/, msg: 'department must be a department name' };
  function draftBody(raw) {
    const v = body(raw).str('campaign', { required: true, re: /^RC-\d{3,}$/, msg: 'campaign must be a campaign id (RC-nnn)' }).str('department', DEPT).str('id', { re: /^RD-\d{4,}$/, msg: 'id must be a draft id (RD-nnnn)' })
      .str('template', { max: 40, re: /^[a-z_]+$/, msg: 'template must be a template key' }).str('ropa_id', { re: /^PD-ROPA-\d{3,}$/, msg: 'ropa_id must be a processing activity id (PD-ROPA-nnn)' })
      .str('name', { max: 160 }).str('purpose', { max: 500 }).oneOf('legal_basis', BASES).list('data_categories', { item: CATS, unique: true, max: 15 }).str('subjects', { max: 300 })
      .list('systems', { item: 'str', itemMax: 120, max: 50, unique: true }).int('retention_months', { min: 1, max: 1200 }).str('retention_basis', { max: 300 })
      .list('recipients', { item: 'str', itemMax: 160, max: 50, unique: true }).str('security_measures', { max: 1000 }).int('sources', { min: 1, max: 50 }).int('volume', { min: 0, max: 100000000 }).str('controller_notes', { max: 1000 });
    for (const f of FLAGS) v.bool(f);
    return v;
  }
  srv.route('GET', '/pdpl/ropa/templates', (ctx) => { ctx.need('viewer'); return R.templates(); });
  srv.route('GET', '/pdpl/ropa/campaigns', (ctx) => { ctx.need('viewer'); return R.list(ctx.who); });
  srv.route('GET', '/pdpl/ropa/campaigns/:id', (ctx) => { ctx.need('viewer'); return R.view(CID(ctx), ctx.who); });
  srv.route('POST', '/pdpl/ropa/campaigns', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('name', { required: true, min: 3, max: 120 }).str('due', { required: true, re: /^\d{4}-\d{2}-\d{2}$/, msg: 'due must be a date (YYYY-MM-DD)' })
      .list('departments', { item: 'str', itemMax: 120, max: 40, unique: true, required: true })
      .rule((o) => (!(o.departments || []).length ? 'departments: name at least one department' : (o.departments || []).some((d) => !DEPT.re.test(d)) ? 'departments must be department names' : null)).done();
    return R.createCampaign(b, ctx.who);
  });
  srv.route('POST', '/pdpl/ropa/campaigns/:id/close', (ctx) => { ctx.need('operator'); return R.closeCampaign(CID(ctx), ctx.who); });
  srv.route('POST', '/pdpl/ropa/drafts', (ctx) => {
    ctx.need('viewer');   // a data steward may hold the viewer role: the department check is in R.putDraft
    return R.putDraft(draftBody(ctx.body).done(), ctx.who);
  }, { anyRole: 'a data steward with any role edits only their own department - checked in putDraft' });
  srv.route('POST', '/pdpl/ropa/drafts/:id/remove', (ctx) => {
    ctx.need('viewer');
    const id = param(ctx.params.id, 'id'); if (!/^RD-\d{4,}$/.test(id)) throw httpErr(400, 'id must be a draft id (RD-nnnn)');
    return R.removeDraft(id, ctx.who);
  }, { anyRole: 'a data steward with any role edits only their own department - checked in removeDraft' });
  srv.route('POST', '/pdpl/ropa/campaigns/:id/submit', (ctx) => { ctx.need('viewer'); return R.submit(CID(ctx), body(ctx.body).str('department', DEPT).done(), ctx.who); },
    { anyRole: 'the department\'s data steward submits whatever their role - checked in submit' });
  srv.route('POST', '/pdpl/ropa/campaigns/:id/review', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('department', DEPT).oneOf('decision', ['approve', 'return'], { required: true }).str('comment', { max: 1000 })
      .rule((o) => (o.decision === 'return' && String(o.comment || '').trim().length < 10 ? 'comment is required when returning: say what to change (at least 10 characters)' : null)).done();
    return R.review(CID(ctx), b, ctx.who);
  });
  srv.route('POST', '/pdpl/ropa/assist', (ctx) => {
    ctx.need('viewer');   // a data steward may hold the viewer role: the department check is in R.assist
    return R.assist(draftBody(ctx.body).str('question', { max: 500 }).done(), ctx.who);
  }, { anyRole: 'a data steward with any role asks for help on their own department - checked in assist; it writes no draft' });
  srv.route('GET', '/pdpl/ropa/register', (ctx) => { ctx.need('operator'); return R.exportRegister(body(ctx.query || {}).str('department', { max: 120 }).done(), ctx.who); });
}

module.exports = { createRopa, registerRopaRoutes, checkSuggestions };
