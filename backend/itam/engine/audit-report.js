// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * Audit Reports ({P} = /api/itam, Audit -> Audit Reports): an engagement's report drafted from its OWN records, for the IT Audit,
 * Cyber Security Audit and Internal Audit teams (engine/audit-engage.js, read through app.addons.auditEngage / cyberAuditEngage /
 * internalAuditEngage - this module never writes their records).
 *
 *   skeleton   built by the platform, deterministic: scope, period, objectives, criteria, the procedures performed (workpapers with
 *              their conclusion and reviewer), the samples (population, method, seed, size and the auditor's results), each finding
 *              with condition / criteria / cause / effect / recommendation / management response / action plan / owner / due /
 *              rating, and the OVERALL RATING computed by the stated rule (RATING_RULE) from the findings' ratings. A SHA-256 of the
 *              source facts is kept: when the records change, the draft is "stale" and must be refreshed before it is signed.
 *   AI         optional: an executive summary, a conclusion and a polished narrative per finding, through app.provider (engine/ai/
 *              provider.js -> ai-guard: budget.admit before / budget.record after, redactSecrets, UNTRUSTED_RULE). The records go to
 *              the model framed untrusted(), people's names removed (PDPL) and personal identifiers sanitised. The answer is schema-
 *              checked (declared fields only, unknown finding ids dropped and listed) and kept as a PROPOSAL: it is not in the report
 *              until a person saves it as their own edit. The model cannot set the rating, sign, approve or issue. Without AI the
 *              skeleton works and the page says the summary is not drafted.
 *   edit       the auditors (engagement team, Head of Audit or an administrator - a person) edit title, executive summary,
 *              background, conclusion and a note per finding; every save is a new version (all kept), optimistic concurrency.
 *   sign       the engagement lead signs as author (a person; executive summary written; no draft findings; records not changed).
 *   approve    an ADMINISTRATOR who is not the signer and not on the audit team (a person, never a service / AI identity)
 *              approves it for issue - it is then frozen with a SHA-256 fingerprint (canonical JSON). Print / Excel on the page.
 *   return     an administrator returns a signed report to draft with a reason.
 * Reports name people and weaknesses: operators and administrators only (PDPL). Every draft, edit, AI call (without its content),
 * sign, return and issue is audited.
 *
 *   GET  /audit-reports                     operator  teams, engagements that can be reported, reports, AI status, the rating rule
 *   POST /audit-reports                     operator  {team: it|cyber|internal, engagement}                 draft (skeleton)  audited
 *   GET  /audit-reports/:id                 operator  the report: skeleton, current text, versions, AI proposal, stale, can
 *   POST /audit-reports/:id/edit            operator  {version, title?, executive_summary?, background?, conclusion?,
 *                                                      finding_notes?[{id, text}], note?}                    new version       audited
 *   POST /audit-reports/:id/refresh         operator  {version}  rebuild the skeleton from the records (clears a signature) audited
 *   POST /audit-reports/:id/ai-draft        operator  AI proposal of summary / conclusion / narratives        audited (no content)
 *   POST /audit-reports/:id/sign            operator  {version}  the engagement lead                                       audited
 *   POST /audit-reports/:id/return          admin     {version, note}                                                      audited
 *   POST /audit-reports/:id/approve         admin     {version, note?}  four eyes; frozen + fingerprint                    audited
 *   GET  /audit-reports/:id/verify          operator  recompute the fingerprint of an issued report
 */
const { body, param } = require('./check');
const G = require('./ai-guard');
const { sanitise } = require('./ai/sanitise');
const { isHuman } = require('./approve-scopes');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const clean = (x, n) => String(x == null ? '' : x).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').trim().slice(0, n);
const TEAMS = {
  it: { addon: 'auditEngage', name: 'IT Audit Team', page: 'audit-team.html' },
  cyber: { addon: 'cyberAuditEngage', name: 'Cyber Security Audit Team', page: 'cyber-audit-team.html' },
  internal: { addon: 'internalAuditEngage', name: 'Internal Audit Team', page: 'internal-audit-team.html' },
};
const REPORTABLE = ['fieldwork', 'draft_report', 'final'];
const SIGNABLE = ['draft_report', 'final'];
const RATINGS = ['high', 'medium', 'low'];
const LABELS = ['Satisfactory', 'Needs improvement', 'Unsatisfactory'];
const RATING_RULE = 'Overall rating from the findings\' ratings (withdrawn findings are not counted): Unsatisfactory - at least one high-rated finding, or three or more medium-rated findings; Needs improvement - at least one medium-rated finding, or three or more low-rated findings; Satisfactory - otherwise (at most two low-rated findings, or none).';
const TEXT_FIELDS = { title: 200, executive_summary: 8000, background: 6000, conclusion: 6000 };
const MAX_VERSIONS = 100;
const AI_ID = 'ai:audit-report';
const FEATURE = 'itam.audit_report';

function overall(findings) {
  const n = { high: 0, medium: 0, low: 0 };
  for (const f of findings) if (n[f.rating] !== undefined) n[f.rating]++;
  const value = n.high >= 1 || n.medium >= 3 ? 'Unsatisfactory' : n.medium >= 1 || n.low >= 3 ? 'Needs improvement' : 'Satisfactory';
  const why = n.high >= 1 ? n.high + ' high-rated finding(s)' : n.medium >= 3 ? n.medium + ' medium-rated findings (three or more)' : n.medium >= 1 ? n.medium + ' medium-rated finding(s)'
    : n.low >= 3 ? n.low + ' low-rated findings (three or more)' : n.low ? n.low + ' low-rated finding(s) only' : 'no findings';
  return { value, why, counts: n, rule: RATING_RULE };
}
// canonical JSON: keys sorted at every level, so the fingerprint does not depend on property order
// the fingerprint of the source facts; the engagement's own state is left out (it moves on to final without changing the facts)
const hashOf = (sk) => G.sha256(canon(Object.assign({}, sk, { engagement: Object.assign({}, sk.engagement, { state: undefined }), built_at: undefined, records_hash: undefined })));
function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return JSON.stringify(v === undefined ? null : v);
}

const SYSTEM = `You write the narrative of an internal audit report for ${ZYB_ORG.name} (IIA Global Internal Audit Standards). The platform has already assembled the facts of the report - scope, period, objectives, procedures, samples, findings and the overall rating - from the audit records, and the auditors will edit and sign what you propose.

How you work:
- Use only the facts in the report data you are given. Never invent findings, figures, dates, people, records or management commitments; if something is missing, say it is not recorded.
- The overall rating is fixed by the platform's rule. Repeat it exactly; never propose a different rating.
- People's names have been removed: refer to roles (the lead auditor, the finding owner, management).
- You cannot sign, approve, issue or change any record. Your text is a proposal for the auditor.
- Plain text only: no Markdown links, no URLs, no HTML.
Answer with ONE JSON object and nothing else:
{"executive_summary": "at most 250 words for the Board Audit Committee: the overall rating and why, the most important findings by rating, management's commitments",
 "conclusion": "at most 120 words",
 "finding_narratives": [{"id": "<finding id from the data>", "text": "the finding restated clearly in at most 120 words, same facts"}]}`;

function createAuditReport(app, opts = {}) {
  const now = opts.now || Date.now, L = app.log || { info() {}, warn() {}, every() {} };
  const R = () => app.store.collection('audit_reports');
  const iso = () => new Date(now()).toISOString();
  const provider = () => opts.provider || app.provider || null;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'audit-report.' + action, target, detail }); };
  const warn = (key, msg, err) => { if (L.every) L.every('audit-report:' + key, 3600000, 'warn', msg, { err: clean((err && err.message) || err, 200) }); };
  const team = (k) => { const t = TEAMS[k]; const T = t && app.addons && app.addons[t.addon]; return T ? Object.assign({ key: k, T }, t) : null; };
  const person = (who, what) => { if (!who || !isHuman(who.user)) throw httpErr(403, 'a named person ' + what + ' - service and AI identities cannot'); };
  const must = (id) => { const r = R().get(param(id)); if (!r) throw httpErr(404, 'report not found'); return r; };
  const teamOf = (r) => { const t = team(r.team); if (!t) throw httpErr(409, 'the ' + TEAMS[r.team].name + ' engine is not installed - run the update'); return t; };
  const headOf = (t) => { try { return (t.T.profile() || {}).head_of_audit || ''; } catch (e) { warn('profile', 'audit reports: a team profile could not be read', e); return ''; } };
  const onTeam = (eng, who) => same(eng.lead, who.user) || (eng.team || []).some((x) => same(x, who.user));
  const author = (t, eng, who) => onTeam(eng, who) || same(headOf(t), who.user) || who.role === 'admin';

  /* ---- the deterministic skeleton, from the team's own records */
  function build(t, engId) {
    const e = t.T.view(engId);
    const findings = (e.findings || []).filter((f) => f.state !== 'withdrawn')
      .sort((a, b) => RATINGS.indexOf(a.rating) - RATINGS.indexOf(b.rating) || String(a.id).localeCompare(String(b.id)))
      .map((f) => ({ id: f.id, title: f.title, rating: f.rating, state: f.state, condition: f.condition, criteria: f.criteria, cause: f.cause, effect: f.effect, recommendation: f.recommendation,
        management_response: f.response || '', action_plan: f.action_plan || '', owner: f.owner, due: f.due || null, samples: f.samples || [] }));
    const procedures = (e.workpapers || []).slice().sort((a, b) => String(a.id).localeCompare(String(b.id))).map((w) => ({ id: w.id, title: w.title, objective: w.objective, procedure: w.procedure,
      sample: w.sample || null, conclusion: w.conclusion || null, summary: w.summary || '', state: w.state, prepared_by: w.prepared_by || null, reviewed_by: w.reviewed_by || null }));
    const samples = (e.samples || []).slice().sort((a, b) => String(a.id).localeCompare(String(b.id))).map((s) => {
      const res = { pass: 0, exception: 0, na: 0, open: 0 }; for (const i of s.items || []) res[i.result || 'open'] = (res[i.result || 'open'] || 0) + 1;
      return { id: s.id, population: s.population_name, method: s.method, seed: s.seed, from: s.from, to: s.to, population_size: s.population_size, size: s.size, results: res,
        exceptions: (s.items || []).filter((i) => i.result === 'exception').slice(0, 30).map((i) => ({ ref: i.ref, label: i.label, note: i.note || '' })) };
    });
    const rating = overall(findings), warnings = [];
    for (const f of findings) if (f.state === 'draft') warnings.push(f.id + ' is still a draft finding - issue or withdraw it before the report is signed');
    for (const w of procedures) if (w.state !== 'reviewed') warnings.push(w.id + ' (' + w.title + ') is not reviewed yet');
    for (const s of samples) if (s.results.open) warnings.push(s.id + ': ' + s.results.open + ' sample item(s) not concluded');
    const ineff = procedures.filter((w) => w.conclusion === 'ineffective');
    if (ineff.length && rating.value !== 'Unsatisfactory') warnings.push('workpaper(s) ' + ineff.map((w) => w.id).join(', ') + ' concluded "ineffective" but the findings give "' + rating.value + '" - check that every weakness is raised as a finding');
    if (!findings.length && !procedures.length) warnings.push('no workpaper and no finding is recorded yet - the report has nothing to say');
    const sk = { team: t.key, team_name: t.name,
      engagement: { id: e.id, title: e.title, area: e.area, area_name: e.area_name || e.area, auditee_dept: e.auditee_dept, auditee_owner: e.auditee_owner, lead: e.lead, team: e.team || [], state: e.state },
      period: { start: e.start, fieldwork_end: e.fieldwork_end, report_due: e.report_due }, scope: e.scope || '', objectives: e.objectives || [], criteria: e.criteria || '',
      procedures, samples, findings, rating, warnings,
      totals: { procedures: procedures.length, samples: samples.length, items_tested: samples.reduce((n, s) => n + s.size, 0), exceptions: samples.reduce((n, s) => n + s.results.exception, 0), findings: findings.length } };
    sk.records_hash = hashOf(sk);
    return Object.assign(sk, { built_at: iso() });
  }
  const findingIds = (r) => new Set(r.skeleton.findings.map((f) => f.id));
  function freshHash(r) { const t = teamOf(r); return build(t, r.engagement).records_hash; }

  /* ---- the view */
  function can(r, who) {
    const t = team(r.team), eng = r.skeleton.engagement, human = isHuman(who && who.user), live = r.state !== 'issued';
    return { edit: !!(t && human && live && author(t, eng, who)), sign: !!(human && r.state === 'draft' && same(eng.lead, who.user)),
      approve: !!(human && r.state === 'signed' && who.role === 'admin' && !same(r.signed_by, who.user) && !onTeam(eng, who)) };
  }
  function view(r, who) {
    let stale = null;
    if (r.state !== 'issued') { try { stale = freshHash(r) !== r.skeleton.records_hash; } catch (e) { stale = null; warn('stale', 'audit reports: the records of an engagement could not be read', e); } }
    const cur = r.versions[r.versions.length - 1];
    return { id: r.id, team: r.team, team_name: (TEAMS[r.team] || {}).name, team_page: (TEAMS[r.team] || {}).page, engagement: r.engagement, state: r.state, version: r.version,
      content: cur.content, adopted_ai: cur.adopted_ai || [], skeleton: r.skeleton, ai: r.ai || null, ai_note: r.ai ? 'AI draft - a proposal: it is in the report only when a person saves it as their edit' : 'The executive summary is not drafted by the AI - write it yourself, or ask the AI for a draft when AI is configured.',
      versions: r.versions.map((v) => ({ v: v.v, at: v.at, by: v.by, note: v.note || '', changed: v.changed || [], adopted_ai: v.adopted_ai || [], content: v.content })),
      created_by: r.created_by, created_at: r.created_at, signed_by: r.signed_by || null, signed_at: r.signed_at || null, returned: r.returned || null,
      approved_by: r.approved_by || null, approved_at: r.approved_at || null, approval_note: r.approval_note || '', fingerprint: r.fingerprint || null, issued_at: r.issued_at || null,
      stale, can: can(r, who), rule: RATING_RULE };
  }
  function list(who) {
    const teams = Object.keys(TEAMS).map((k) => ({ key: k, name: TEAMS[k].name, page: TEAMS[k].page, installed: !!team(k) })), engagements = [];
    const byEng = new Map(R().all(() => true).map((r) => [r.engagement, r.id]));
    for (const k of Object.keys(TEAMS)) { const t = team(k); if (!t) continue;
      let es = []; try { es = t.T.listEngagements(); } catch (e) { warn('list:' + k, 'audit reports: engagements could not be read', e); }
      for (const e of es) if (REPORTABLE.includes(e.state)) engagements.push({ team: k, team_name: t.name, id: e.id, title: e.title, state: e.state, lead: e.lead, start: e.start, report: byEng.get(e.id) || null }); }
    const reports = R().all(() => true).sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at))).map((r) => ({ id: r.id, team: r.team, team_name: (TEAMS[r.team] || {}).name,
      engagement: r.engagement, title: r.versions[r.versions.length - 1].content.title, state: r.state, version: r.version, rating: r.skeleton.rating.value,
      findings: r.skeleton.findings.length, signed_by: r.signed_by || null, approved_by: r.approved_by || null, fingerprint: r.fingerprint || null, updated_at: r.updated_at }));
    return aiStatus().then((ai) => ({ teams, engagements, reports, ai, rule: RATING_RULE, me: who.user,
      note: 'The report is assembled from the engagement\'s own records; the AI can only propose text. The lead signs, an administrator who is not on the audit team approves it for issue, and the issued report is frozen with its SHA-256 fingerprint.' }));
  }
  async function aiStatus() {
    const P = provider(); if (!P) return { ready: false, message: 'There is no AI provider on this server - the report works without it; write the executive summary yourself.' };
    try { const s = await P.status(); return s.state === 'ready' ? { ready: true, model: s.model || null } : { ready: false, message: (s.message || s.state) + ' - the report works without it; write the executive summary yourself.' }; }
    catch (e) { warn('ai-status', 'audit reports: the AI provider status could not be read', e); return { ready: false, message: 'the AI provider did not answer - the report works without it.' }; }
  }

  /* ---- draft, edit, refresh */
  function create(b0, who) {
    person(who, 'drafts a report');
    const b = body(b0).oneOf('team', Object.keys(TEAMS), { required: true }).str('engagement', { required: true, max: 40, id: true }).done();
    const t = team(b.team); if (!t) throw httpErr(409, 'the ' + TEAMS[b.team].name + ' engine is not installed - run the update');
    const sk = build(t, b.engagement);
    if (!REPORTABLE.includes(sk.engagement.state)) throw httpErr(409, 'the engagement is ' + sk.engagement.state + ' - a report is drafted from fieldwork on');
    if (!author(t, sk.engagement, who)) throw httpErr(403, 'only the engagement\'s audit team (' + [sk.engagement.lead].concat(sk.engagement.team).join(', ') + '), the Head of Audit or an administrator drafts its report');
    const id = 'AR-' + sk.engagement.id; if (R().get(id)) throw httpErr(409, 'a report for ' + sk.engagement.id + ' already exists (' + id + ')');
    const content = { title: clean('Audit report: ' + sk.engagement.title, 200), executive_summary: '', background: '', conclusion: '', finding_notes: {} };
    const r = { id, team: b.team, engagement: sk.engagement.id, state: 'draft', version: 1, skeleton: sk, versions: [{ v: 1, at: iso(), by: who.user, note: 'drafted from the records', changed: [], content }],
      ai: null, created_by: who.user, created_at: iso(), updated_at: iso() };
    R().put(r);
    audit(who, 'draft', id, { team: b.team, engagement: sk.engagement.id, rating: sk.rating.value, findings: sk.findings.length, records_hash: sk.records_hash });
    return view(r, who);
  }
  const live = (r) => { if (r.state === 'issued') throw httpErr(409, 'the report was issued on ' + String(r.issued_at).slice(0, 10) + ' and is frozen (fingerprint ' + String(r.fingerprint).slice(0, 16) + ')'); };
  const vcheck = (r, v) => { if (v !== r.version) throw httpErr(409, 'the report changed since you opened it (version ' + r.version + ', yours ' + v + ') - reload and try again'); };
  function unsign(r, who, why) { if (r.state === 'signed') { r.state = 'draft'; r.unsigned = { at: iso(), by: who.user, why, was: r.signed_by }; r.signed_by = null; r.signed_at = null; return true; } return false; }
  function edit(id, b0, who) {
    person(who, 'edits a report');
    const r = must(id); live(r); const t = teamOf(r);
    if (!author(t, r.skeleton.engagement, who)) throw httpErr(403, 'only the engagement\'s audit team, the Head of Audit or an administrator edits its report');
    let v = body(b0).int('version', { required: true, min: 1 }).str('note', { max: 500 }).list('finding_notes', { max: 200 });
    for (const [k, max] of Object.entries(TEXT_FIELDS)) v = v.str(k, { max });
    const b = v.done();
    if (b.title !== undefined && !b.title) throw httpErr(400, 'title is required');
    vcheck(r, b.version);
    const ids = findingIds(r), prev = r.versions[r.versions.length - 1].content, next = JSON.parse(JSON.stringify(prev)), changed = [];
    // an explicitly empty text clears that section (check.js treats '' as absent; the title can never be cleared)
    for (const k of Object.keys(TEXT_FIELDS)) if (k !== 'title' && b0 && b0[k] === '' && prev[k]) b[k] = '';
    for (const k of Object.keys(TEXT_FIELDS)) if (b[k] !== undefined && b[k] !== prev[k]) { next[k] = b[k]; changed.push(k); }
    (b.finding_notes || []).forEach((x0, i) => {
      if (!x0 || typeof x0 !== 'object' || Array.isArray(x0)) throw httpErr(400, 'finding_notes[' + i + '] must be an object {id, text}');
      const x = body(x0).str('id', { required: true, max: 40, id: true }).str('text', { max: 3000, def: '' }).done();
      if (!ids.has(x.id)) throw httpErr(400, 'finding_notes[' + i + '].id: ' + x.id + ' is not a finding of this report');
      if ((prev.finding_notes[x.id] || '') !== x.text) { if (x.text) next.finding_notes[x.id] = x.text; else delete next.finding_notes[x.id]; changed.push('finding_notes.' + x.id); }
    });
    if (!changed.length) return Object.assign(view(r, who), { unchanged: true });
    // which parts are the AI's words, adopted unchanged by this person (shown on the report and in the audit trail)
    const ai = r.ai || {}, adopted = [];
    if (ai.executive_summary && next.executive_summary === ai.executive_summary) adopted.push('executive_summary');
    if (ai.conclusion && next.conclusion === ai.conclusion) adopted.push('conclusion');
    for (const [fid, txt] of Object.entries(next.finding_notes)) if (ai.finding_narratives && ai.finding_narratives[fid] === txt) adopted.push('finding_notes.' + fid);
    const wasSigned = unsign(r, who, 'edited after signing');
    r.version++; r.versions.push({ v: r.version, at: iso(), by: who.user, note: b.note || '', changed, adopted_ai: adopted, content: next });
    if (r.versions.length > MAX_VERSIONS) r.versions.splice(1, r.versions.length - MAX_VERSIONS);   // the first draft is always kept
    r.updated_at = iso(); R().put(r);
    audit(who, 'edit', r.id, { version: r.version, changed, adopted_ai: adopted, signature_cleared: wasSigned, chars: changed.filter((k) => TEXT_FIELDS[k]).reduce((n, k) => n + String(next[k]).length, 0) });
    return view(r, who);
  }
  function refresh(id, b0, who) {
    person(who, 'refreshes a report');
    const r = must(id); live(r); const t = teamOf(r);
    if (!author(t, r.skeleton.engagement, who)) throw httpErr(403, 'only the engagement\'s audit team, the Head of Audit or an administrator refreshes its report');
    const b = body(b0).int('version', { required: true, min: 1 }).done(); vcheck(r, b.version);
    const was = r.skeleton, sk = build(t, r.engagement);
    const gone = was.findings.map((f) => f.id).filter((x) => !sk.findings.some((f) => f.id === x)), cur = r.versions[r.versions.length - 1].content;
    const wasSigned = unsign(r, who, 'refreshed from the records');
    r.skeleton = sk; r.version++;
    const content = JSON.parse(JSON.stringify(cur)); for (const g of gone) delete content.finding_notes[g];
    r.versions.push({ v: r.version, at: iso(), by: who.user, note: 'refreshed from the records', changed: ['skeleton'], content });
    if (r.versions.length > MAX_VERSIONS) r.versions.splice(1, r.versions.length - MAX_VERSIONS);
    r.updated_at = iso(); R().put(r);
    audit(who, 'refresh', r.id, { version: r.version, records_hash: sk.records_hash, was_hash: was.records_hash, rating: sk.rating.value, was_rating: was.rating.value, findings_removed: gone, signature_cleared: wasSigned });
    return view(r, who);
  }

  /* ---- the AI proposal (optional) */
  function aiPayload(r) {
    const s = r.skeleton;
    // no people's names: roles are enough for the narrative (PDPL); sample item labels name people, so only the counts go
    return { report: r.id, team: s.team_name, engagement: { id: s.engagement.id, title: s.engagement.title, area: s.engagement.area_name, auditee_department: s.engagement.auditee_dept },
      period: s.period, scope: s.scope, objectives: s.objectives, criteria: s.criteria, overall_rating: s.rating.value, rating_basis: s.rating.why,
      procedures: s.procedures.map((w) => ({ id: w.id, title: w.title, objective: w.objective, procedure: w.procedure, conclusion: w.conclusion, summary: w.summary })),
      samples: s.samples.map((x) => ({ id: x.id, population: x.population, method: x.method, population_size: x.population_size, size: x.size, results: x.results })),
      findings: s.findings.map((f) => ({ id: f.id, title: f.title, rating: f.rating, condition: f.condition, criteria: f.criteria, cause: f.cause, effect: f.effect, recommendation: f.recommendation,
        management_response: f.management_response, action_plan: f.action_plan, due: f.due })) };
  }
  function names(r, t) {
    const s = r.skeleton, out = new Set([s.engagement.lead, s.engagement.auditee_owner, headOf(t)].concat(s.engagement.team));
    for (const f of s.findings) out.add(f.owner); for (const w of s.procedures) { out.add(w.prepared_by); out.add(w.reviewed_by); }
    return [...out].filter((x) => x && String(x).length >= 2);
  }
  function parseAi(text, ids, rating) {
    const raw = String(text || ''), dropped = [], fence = /```(?:json)?\s*([\s\S]*?)```/i.exec(raw);
    const cand = fence ? fence[1] : raw.indexOf('{') >= 0 ? raw.slice(raw.indexOf('{'), raw.lastIndexOf('}') + 1) : '';
    let j = null; try { j = cand ? JSON.parse(cand) : null; } catch (e) { j = null; /* not JSON: kept below as plain text, flagged */ }
    const out = { executive_summary: '', conclusion: '', finding_narratives: {}, format: 'json', dropped };
    if (!j || typeof j !== 'object' || Array.isArray(j)) { out.format = 'text'; out.executive_summary = clean(raw, 4000); dropped.push('the answer was not the requested JSON object - kept as plain text for the auditor to check'); }
    else {
      for (const k of Object.keys(j)) if (!['executive_summary', 'conclusion', 'finding_narratives'].includes(k)) dropped.push('"' + clean(k, 40) + '" is not a field the AI may write - ignored');
      if (typeof j.executive_summary === 'string') out.executive_summary = clean(j.executive_summary, 4000); else if (j.executive_summary !== undefined) dropped.push('executive_summary was not text - ignored');
      if (typeof j.conclusion === 'string') out.conclusion = clean(j.conclusion, 3000); else if (j.conclusion !== undefined) dropped.push('conclusion was not text - ignored');
      if (Array.isArray(j.finding_narratives)) for (const x of j.finding_narratives.slice(0, 200)) {
        const fid = x && typeof x.id === 'string' ? x.id : '';
        if (!ids.has(fid)) { dropped.push('a narrative for "' + clean(fid || '?', 40) + '", which is not a finding of this report - dropped'); continue; }
        if (typeof x.text !== 'string' || !x.text.trim()) { dropped.push('the narrative for ' + fid + ' was empty - dropped'); continue; }
        out.finding_narratives[fid] = clean(x.text, 3000);
      } else if (j.finding_narratives !== undefined) dropped.push('finding_narratives was not a list - ignored');
    }
    // the rating is the platform's: a different one named in the AI text is pointed out, never applied
    const others = LABELS.filter((l) => l !== rating && new RegExp('\\b' + l + '\\b', 'i').test(out.executive_summary + ' ' + out.conclusion));
    const notes = others.length ? ['the AI text names the rating "' + others.join('", "') + '" but the platform\'s rating is "' + rating + '" - correct it before saving'] : [];
    if (/https?:\/\/|www\.|<\s*[a-z]/i.test(JSON.stringify(out))) notes.push('the AI text contains a link or markup - it is shown as plain text and never as a link');
    return Object.assign(out, { notes });
  }
  async function aiDraft(id, who) {
    person(who, 'asks the AI for a draft');
    const r = must(id); live(r); const t = teamOf(r);
    if (!author(t, r.skeleton.engagement, who)) throw httpErr(403, 'only the engagement\'s audit team, the Head of Audit or an administrator asks for a draft of its report');
    const P = provider(); if (!P) throw httpErr(409, 'there is no AI provider on this server - write the executive summary yourself');
    const st = await P.status(); if (st.state !== 'ready') throw httpErr(409, 'the AI is not ready: ' + (st.message || st.state) + ' - the report works without it; write the executive summary yourself');
    let terms = names(r, t); try { terms = terms.concat((app.settings && app.settings.get().redact_terms) || []); } catch (e) { warn('terms', 'audit reports: the redaction terms could not be read', e); }
    const data = sanitise(JSON.stringify(aiPayload(r)), { redact_terms: terms });
    const flags = G.injectionSignals(data);
    const prompt = 'The overall rating is fixed by the platform: "' + r.skeleton.rating.value + '" (' + r.skeleton.rating.why + '). Write the narrative for this report from the data below only.\n\n'
      + G.untrusted('audit-report:' + r.id, data);
    const out = await P.call({ system: SYSTEM + '\n\n' + G.UNTRUSTED_RULE, prompt, who: { user: who.user, role: who.role }, feature: FEATURE });
    if (!out || out.ok === false) {
      audit(who, 'ai.failed', r.id, { code: (out && out.code) || 'error', model: (out && out.model) || null });
      const code = out && out.code, status = code === 'budget' ? 429 : code === 'too_large' ? 413 : 409;
      throw httpErr(status, 'the AI did not draft the report: ' + clean((out && out.message) || 'no answer', 300) + ' - the report works without it');
    }
    const p = parseAi(out.text, findingIds(r), r.skeleton.rating.value);
    r.ai = { at: iso(), by: AI_ID, requested_by: who.user, model: clean(out.model, 80) || null, executive_summary: p.executive_summary, conclusion: p.conclusion, finding_narratives: p.finding_narratives,
      format: p.format, dropped: p.dropped.slice(0, 50), notes: p.notes, injection_signals: flags, for_version: r.version, records_hash: r.skeleton.records_hash, label: 'AI draft - check every statement against the records before you adopt it' };
    r.updated_at = iso(); R().put(r);
    // the AI call is audited WITHOUT its content: sizes, the model, what was dropped, the fingerprint of what was sent
    audit(who, 'ai.draft', r.id, { model: r.ai.model, format: p.format, chars: p.executive_summary.length + p.conclusion.length + Object.values(p.finding_narratives).reduce((n, x) => n + x.length, 0),
      narratives: Object.keys(p.finding_narratives).length, dropped: p.dropped.length, injection_signals: flags.length, sent_prompt_sha256: out.sent_prompt_sha256 || null });
    return view(r, who);
  }

  /* ---- sign, return, approve for issue */
  function sign(id, b0, who) {
    person(who, 'signs a report');
    const r = must(id); live(r); const t = teamOf(r);
    const b = body(b0).int('version', { required: true, min: 1 }).done();
    const eng = t.T.view(r.engagement);
    if (!same(eng.lead, who.user)) throw httpErr(403, 'the engagement lead (' + eng.lead + ') signs the report as its author');
    if (r.state !== 'draft') throw httpErr(409, 'the report is ' + r.state + ' - only a draft is signed');
    vcheck(r, b.version);
    if (!SIGNABLE.includes(eng.state)) throw httpErr(409, 'the engagement is ' + eng.state + ' - the report is signed once the engagement reaches draft report');
    if (freshHash(r) !== r.skeleton.records_hash) throw httpErr(409, 'the engagement\'s records changed since the skeleton was built - refresh the report and check it before signing');
    const drafts = r.skeleton.findings.filter((f) => f.state === 'draft'); if (drafts.length) throw httpErr(409, 'issue or withdraw every draft finding first: ' + drafts.map((f) => f.id).join(', '));
    const c = r.versions[r.versions.length - 1].content;
    if (String(c.executive_summary || '').trim().length < 20) throw httpErr(409, 'executive_summary: a person writes (or adopts) the executive summary before signing (at least 20 characters)');
    Object.assign(r, { state: 'signed', signed_by: who.user, signed_at: iso(), signed_version: r.version, returned: null, updated_at: iso() }); R().put(r);
    audit(who, 'sign', r.id, { version: r.version, rating: r.skeleton.rating.value, records_hash: r.skeleton.records_hash, adopted_ai: r.versions[r.versions.length - 1].adopted_ai || [] });
    return view(r, who);
  }
  function giveBack(id, b0, who) {
    person(who, 'returns a report');
    if (who.role !== 'admin') throw httpErr(403, 'an administrator returns a signed report');
    const r = must(id); live(r);
    const b = body(b0).int('version', { required: true, min: 1 }).str('note', { required: true, min: 5, max: 1000 }).done();
    if (r.state !== 'signed') throw httpErr(409, 'the report is ' + r.state + ' - only a signed report is returned'); vcheck(r, b.version);
    const was = r.signed_by; unsign(r, who, 'returned: ' + b.note); r.returned = { by: who.user, at: iso(), note: b.note }; r.updated_at = iso(); R().put(r);
    audit(who, 'return', r.id, { version: r.version, signed_by: was, note: b.note.slice(0, 200) });
    return view(r, who);
  }
  function approve(id, b0, who) {
    person(who, 'approves a report for issue');
    if (who.role !== 'admin') throw httpErr(403, 'an administrator approves a report for issue');
    const r = must(id); live(r); const t = teamOf(r);
    const b = body(b0).int('version', { required: true, min: 1 }).str('note', { max: 1000 }).done();
    if (r.state !== 'signed') throw httpErr(409, 'the engagement lead signs the report first (it is ' + r.state + ')');
    vcheck(r, b.version);
    const eng = t.T.view(r.engagement);
    if (same(r.signed_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' signed this report and cannot also approve it');
    if (onTeam(eng, who)) throw httpErr(403, 'four eyes: ' + who.user + ' is on the audit team of ' + eng.id + ' - an administrator outside the team approves');
    if (freshHash(r) !== r.skeleton.records_hash) throw httpErr(409, 'the engagement\'s records changed after the report was signed - return it so the lead refreshes and signs again');
    const at = iso(), content = r.versions[r.versions.length - 1].content;
    const frozen = { id: r.id, team: r.team, engagement: r.engagement, version: r.version, skeleton: r.skeleton, content, adopted_ai: r.versions[r.versions.length - 1].adopted_ai || [],
      signed_by: r.signed_by, signed_at: r.signed_at, approved_by: who.user, approved_at: at, approval_note: b.note || '' };
    Object.assign(r, { state: 'issued', approved_by: who.user, approved_at: at, approval_note: b.note || '', issued_at: at, frozen, fingerprint: G.sha256(canon(frozen)), updated_at: at });
    R().put(r);
    audit(who, 'issue', r.id, { version: r.version, fingerprint: r.fingerprint, signed_by: r.signed_by, rating: r.skeleton.rating.value, findings: r.skeleton.findings.length });
    return view(r, who);
  }
  function verify(id) {
    const r = must(id); if (r.state !== 'issued') throw httpErr(409, 'the report is ' + r.state + ' - only an issued report has a fingerprint');
    const computed = G.sha256(canon(r.frozen));
    return { id: r.id, fingerprint: r.fingerprint, computed, ok: computed === r.fingerprint, algorithm: 'SHA-256 over the canonical JSON (keys sorted) of the issued report' };
  }

  return { list, get: (id, who) => view(must(id), who), create, edit, refresh, aiDraft, sign, giveBack, approve, verify, aiStatus, build: (k, id) => { const t = team(k); if (!t) throw httpErr(409, 'team not installed'); return build(t, id); },
    RATING_RULE, overall, TEAMS };
}

function registerAuditReport(srv, app, X) {
  // reports name people and weaknesses (PDPL): operators and administrators only, viewers are refused
  const op = (fn) => (ctx) => { ctx.need('operator'); return fn(ctx); };
  const ad = (fn) => (ctx) => { ctx.need('admin'); return fn(ctx); };
  srv.route('GET', '/audit-reports', op((ctx) => X.list(ctx.who)));
  srv.route('POST', '/audit-reports', op((ctx) => X.create(ctx.body, ctx.who)), { maxBody: 4096 });
  srv.route('GET', '/audit-reports/:id', op((ctx) => X.get(ctx.params.id, ctx.who)));
  srv.route('POST', '/audit-reports/:id/edit', op((ctx) => X.edit(ctx.params.id, ctx.body, ctx.who)), { maxBody: 512 * 1024 });
  srv.route('POST', '/audit-reports/:id/refresh', op((ctx) => X.refresh(ctx.params.id, ctx.body, ctx.who)), { maxBody: 4096 });
  srv.route('POST', '/audit-reports/:id/ai-draft', op((ctx) => X.aiDraft(ctx.params.id, ctx.who)), { maxBody: 4096 });
  srv.route('POST', '/audit-reports/:id/sign', op((ctx) => X.sign(ctx.params.id, ctx.body, ctx.who)), { maxBody: 4096 });
  srv.route('POST', '/audit-reports/:id/return', ad((ctx) => X.giveBack(ctx.params.id, ctx.body, ctx.who)), { maxBody: 8192 });
  srv.route('POST', '/audit-reports/:id/approve', ad((ctx) => X.approve(ctx.params.id, ctx.body, ctx.who)), { maxBody: 8192 });
  srv.route('GET', '/audit-reports/:id/verify', op((ctx) => X.verify(ctx.params.id)));
}

module.exports = { createAuditReport, registerAuditReport, RATING_RULE, overall, canon, SYSTEM };
