// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The PDPL operating pages: Records of Processing, Sensitive Data Controls, Data Subject Requests, DPIA, Cross-Border
 * Transfers, Breach Response, Processor Management and the PDPL Programme. Python decides (pyengine/pdpl_workflows.py:
 * clocks, completeness, scores, letters, what blocks an answer); this file validates, checks the role, commits through the
 * PDPL registers (engine/pdpl.js putRecord - records are evidence, archived never deleted) and writes the audit record.
 * Everything is operator-only: these registers are PDPL records themselves. Writes are made by a person, never a service.
 *
 *   GET  /pdpl/ropa                               register with completeness and links     ·  GET /pdpl/ropa/export (audited)
 *   GET  /pdpl/sensitive                          sensitive activities and their controls
 *   POST /pdpl/sensitive/:ropa                    {controls…, access_tiers[], access_review, evidence}       audited
 *   GET  /pdpl/dsar                               requests, due dates, blockers
 *   POST /pdpl/dsar                               {ref, type, channel, received, systems[]}  staff record it  audited
 *   POST /pdpl/dsar/:id/verify|task|extend|respond|refuse|withdraw                            audited
 *   GET  /pdpl/dsar/:id/letter                    response draft (Arabic / English)                          audited
 *   GET  /pdpl/dpia/view                          which activities need an assessment (wizard: engine/pdpl.js)
 *   GET  /pdpl/transfers                          transfers and their assessments
 *   POST /pdpl/transfers/:id/tia                  {answers}  transfer impact assessment                       audited
 *   POST /pdpl/transfers/:id/tia/sign             the DPO, not the preparer                                   audited
 *   GET  /pdpl/breaches                           the 72-hour clock and the playbook
 *   POST /pdpl/breach/:id/step                    {step, note, at?}                                            audited
 *   POST /pdpl/breach/:id/regulator               {regulator, required, reason?, notified_at?, ref?, name?, hours?}  audited
 *        the other regulators (Insurance Authority, SAMA, NCA, CHI, other): a decision per regulator, the notification
 *        time and reference once sent (then fixed - it is evidence); deadlines are hours an admin sets in the profile
 *   GET  /pdpl/processors                         agreement, due diligence, review, sub-processors
 *   POST /pdpl/processors/:id/assessment          {checks}                                                    audited
 *   POST /pdpl/processors/:id/subprocessor        {name, service, country}  proposed                          audited
 *   POST /pdpl/processors/:id/subprocessor/:n     {decision, note}  the DPO / an administrator, not the proposer audited
 *   GET  /pdpl/programme                          departments, stewards, playbooks, maturity, obligations, penalties
 *   POST /pdpl/stewards | /pdpl/playbooks | /pdpl/training                                     audited
 *   POST /pdpl/maturity                           {answers}  scored in Python                                 audited
 *   GET  /pdpl/governance               operator  DPO line, named owner per function, committee, privacy-by-design reviews, programme reviews
 *   POST /pdpl/accountability           admin     {function, user, deputy?}  a named person per PDPL function       audited
 *   POST /pdpl/committee                operator  {date, departments[], attendees[], decisions, actions[]}         audited
 *   POST /pdpl/pbd                      operator  {name, type, go_live, ropa_id?, answers}  privacy by design       audited
 *   POST /pdpl/pbd/:id/decide           operator  the DPO / an administrator, not the requester; DPIA first if required  audited
 *   POST /pdpl/reviews                  operator  {date, checks{}, summary, actions[]}  yearly programme review    audited
 *   POST /pdpl/reviews/:id/action/:n    operator  {status, note}  remediation action closed / reopened          audited
 *   GET  /pdpl/policies                 viewer    the PDPL policy set against the GRC policy register and drafts
 *   POST /pdpl/policies/:id/draft       operator  starts a GRC draft from the outline (approved on GRC Policies)   audited
 *   POST /pdpl/policies/:id/upload      operator  the owner's own policy (PDF / Word, content-checked, 6 MB) onto its draft;
 *                                                 submit=true sends it for approval at once                          audited
 *   POST /pdpl/policies/:id/submit      operator  a draft with a document (or text) goes to review                    audited
 *   POST /pdpl/policies/:id/decide      admin     approve | reject (reason required); never the person who wrote or uploaded it
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const same = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
const WF_KINDS = ['sensitive_control', 'steward', 'playbook', 'training', 'maturity'];
const DSR_TYPES = ['access', 'copy', 'correction', 'destruction', 'withdraw_consent', 'objection', 'other'];
const CHANNELS = ['branch', 'call_centre', 'email', 'web', 'letter', 'app', 'other'];
const ID_METHODS = ['nafath', 'national_id_in_branch', 'absher_otp', 'policy_number_and_otp', 'registered_email', 'guardian_documents', 'other'];
const GROUNDS = ['repetitive', 'unfounded', 'disproportionate', 'legal', 'identity', 'third_party'];
const STEPS = ['contain', 'assess', 'notify_sdaia', 'notify_subjects', 'remediate', 'lessons'];
const REGS = ['ia', 'sama', 'nca', 'chi', 'other'];
const CONTROLS = ['lawful_basis', 'encryption_at_rest', 'masking_nonprod', 'access_logged', 'health_chi', 'credit_notice', 'biometric_purpose'];
const DD = ['iso27001', 'pdpl_terms', 'breach_24h', 'data_in_ksa', 'deletion_at_end', 'audit_right', 'staff_confidentiality'];
const DT = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})?)?$/;

function createWorkflows(app, PD, opts = {}) {
  const now = opts.now || Date.now;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const human = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const get = (id, kind, label) => { const r = PD.records(kind).find((x) => x.id === id); if (!r) throw httpErr(404, 'no ' + label + ' ' + id); return r; };
  const profile = () => PD.records('profile')[0] || {};
  const isDpo = (who) => profile().dpo_user && same(profile().dpo_user, who.user);
  const iso = () => new Date(now()).toISOString();
  async function rules(op, extra) { const r = await PD.rules(op, extra); if (r && r.refuse) throw httpErr(r.refuse.status, r.refuse.error); return r; }

  // ---- RoPA
  const ropa = () => rules('pdpl.ropa_view');
  async function ropaExport(who) { const r = await ropa(); audit(who, 'pdpl.ropa.export', 'ropa', { rows: r.export_rows.length }); return { columns: r.export_columns, rows: r.export_rows, generated_at: iso(), note: r.note }; }

  // ---- Sensitive controls: one record per activity, updated in place
  async function putSensitive(ropaId, b, who) {
    human(who, 'records sensitive data controls');
    const a = get(ropaId, 'ropa', 'processing activity');
    const cur = PD.records('sensitive_control').find((c) => c.ropa_id === ropaId && c.status !== 'archived');
    const rec = PD.putRecord(Object.assign({ kind: 'sensitive_control', ropa_id: ropaId }, cur ? { id: cur.id } : {}, b), who);
    audit(who, 'pdpl.sensitive.controls', rec.id, { ropa_id: ropaId, activity: a.name, set: Object.keys(b).sort() });
    return (await rules('pdpl.sensitive_view')).activities.find((x) => x.id === ropaId) || null;
  }

  // ---- Data subject requests (staff record them; only a reference is kept)
  const dsrOne = async (id) => (await rules('pdpl.dsar_view')).requests.find((x) => x.id === id);
  async function dsarNew(b, who) {
    human(who, 'records a data subject request');
    if (Date.parse(b.received) > now() + 300000) throw httpErr(400, 'received cannot be in the future');
    if (PD.records('dsr').some((r) => same(r.ref, b.ref))) throw httpErr(409, 'a request with reference ' + b.ref + ' is already recorded');
    const rec = PD.putRecord({ kind: 'dsr', ref: b.ref, type: b.type, channel: b.channel, received: b.received, stage: 'received', assigned_to: b.assigned_to || who.user,
      tasks: (b.systems || []).map((s) => ({ system: s, status: 'open', note: '' })) }, who);
    audit(who, 'pdpl.dsar.new', rec.id, { type: b.type, channel: b.channel, systems: (b.systems || []).length });
    return dsrOne(rec.id);
  }
  function dsrOpen(id) {
    const r = get(id, 'dsr', 'data subject request');
    if (['responded', 'refused', 'withdrawn'].includes(r.stage) || (r.responded && !r.stage)) throw httpErr(409, id + ' is closed (' + (r.stage || 'responded') + ')');
    return r;
  }
  async function dsarVerify(id, b, who) {
    human(who, 'verifies a requester\'s identity'); const r = dsrOpen(id);
    PD.putRecord({ kind: 'dsr', id, identity_verified: true, identity_method: b.method, identity_note: b.note || '', identity_by: who.user, identity_at: iso(), stage: r.stage === 'received' || r.stage === 'verifying' || !r.stage ? 'in_progress' : r.stage }, who);
    audit(who, 'pdpl.dsar.verify', id, { method: b.method });
    return dsrOne(id);
  }
  async function dsarTask(id, b, who) {
    human(who, 'works a data subject request'); const r = dsrOpen(id);
    const tasks = (r.tasks || []).filter((t) => !same(t.system, b.system));
    tasks.push({ system: b.system, status: b.status, note: b.note || '', by: who.user, at: iso() });
    if (tasks.length > 50) throw httpErr(400, 'a request lists at most 50 systems');
    PD.putRecord({ kind: 'dsr', id, tasks }, who);
    audit(who, 'pdpl.dsar.task', id, { system: b.system, status: b.status });
    return dsrOne(id);
  }
  async function dsarExtend(id, b, who) {
    human(who, 'extends a data subject request'); const r = dsrOpen(id);
    if (r.extended) throw httpErr(409, id + ' was already extended - the period may be extended once');
    const due = Date.parse(String(r.received).length === 10 ? r.received + 'T00:00:00Z' : r.received) + 30 * 86400000;
    if (now() > due) throw httpErr(409, 'the 30 days ended on ' + new Date(due).toISOString().slice(0, 10) + ' - an extension must be notified before the deadline');
    PD.putRecord({ kind: 'dsr', id, extended: true, extension_notified: iso().slice(0, 16) + 'Z', extension_reason: b.reason, extension_by: who.user }, who);
    audit(who, 'pdpl.dsar.extend', id, { reason: b.reason.slice(0, 200) });
    return dsrOne(id);
  }
  async function dsarRespond(id, b, who) {
    human(who, 'answers a data subject request'); dsrOpen(id);
    const v = await dsrOne(id);
    if (!v.can_respond) throw httpErr(409, 'not ready to answer: ' + v.blockers.join('; '));
    if (b.outcome === 'partially' && !b.note) throw httpErr(400, 'note is required: say which part could not be met and why');
    PD.putRecord({ kind: 'dsr', id, stage: 'responded', outcome: b.outcome, responded: iso().slice(0, 10), response_note: b.note || '', responded_by: who.user }, who);
    audit(who, 'pdpl.dsar.respond', id, { outcome: b.outcome });
    return dsrOne(id);
  }
  async function dsarRefuse(id, b, who) {
    human(who, 'refuses a data subject request'); dsrOpen(id);
    if (!isDpo(who) && who.role !== 'admin') throw httpErr(403, 'refusing a request is a decision for the DPO (' + (profile().dpo_user || 'not named') + ') or an administrator');
    PD.putRecord({ kind: 'dsr', id, stage: 'refused', outcome: 'refused', refusal_ground: b.ground, refusal_reason: b.note, responded: iso().slice(0, 10), responded_by: who.user }, who);
    audit(who, 'pdpl.dsar.refuse', id, { ground: b.ground });
    return dsrOne(id);
  }
  async function dsarWithdraw(id, b, who) {
    human(who, 'closes a withdrawn request'); dsrOpen(id);
    PD.putRecord({ kind: 'dsr', id, stage: 'withdrawn', withdrawn_note: b.note, withdrawn_at: iso(), withdrawn_by: who.user }, who);
    audit(who, 'pdpl.dsar.withdraw', id, {});
    return dsrOne(id);
  }
  async function dsarLetter(id, who) {
    const r = get(id, 'dsr', 'data subject request');
    const out = await rules('pdpl.dsar_letter', { request: r, profile: profile() });
    audit(who, 'pdpl.dsar.letter', id, { stage: r.stage || null });
    return out;
  }

  // ---- Transfers: impact assessment, signed by the DPO who did not prepare it
  async function transferTia(id, b, who) {
    human(who, 'prepares a transfer impact assessment');
    const t = get(id, 'transfer', 'transfer');
    const sc = await rules('pdpl.transfer_tia', { answers: b.answers, transfer: { basis: t.basis } });
    PD.putRecord({ kind: 'transfer', id, tia: { answers: b.answers, score: sc, prepared_by: who.user, prepared_at: iso(), notes: b.notes || '' } }, who);
    audit(who, 'pdpl.transfer.tia', id, { country: t.country, level: sc.level, outcome: sc.outcome });
    return Object.assign({ id }, sc);
  }
  function transferSign(id, who) {
    human(who, 'signs a transfer impact assessment');
    const t = get(id, 'transfer', 'transfer'), tia = t.tia;
    if (!tia || !tia.score) throw httpErr(409, 'no impact assessment prepared for ' + id);
    if (tia.signed_by) throw httpErr(409, id + ': the assessment is already signed - prepare a new one for a change');
    if (!profile().dpo_user) throw httpErr(409, 'no DPO is named in the PDPL profile');
    if (!isDpo(who)) throw httpErr(403, 'only the DPO named in the profile (' + profile().dpo_user + ') signs a transfer impact assessment');
    if (same(tia.prepared_by, who.user)) throw httpErr(403, 'four-eyes: the DPO cannot sign an assessment they prepared');
    if (tia.score.outcome === 'not_permitted') throw httpErr(409, 'the transfer does not meet PDPL Art. 29 (' + ((tia.score.conditions || []).filter((c) => c.state === 'not_met').map((c) => c.label).join('; ') || 'no permitted purpose') + ') - it cannot be signed off');
    const rec = PD.putRecord({ kind: 'transfer', id, risk_assessed: iso().slice(0, 10), tia: Object.assign({}, tia, { signed_by: who.user, signed_at: iso() }) }, who);
    audit(who, 'pdpl.transfer.tia.sign', id, { level: tia.score.level, outcome: tia.score.outcome });
    return rec;
  }

  // ---- Breach playbook
  async function breachStep(id, b, who) {
    human(who, 'records a breach response step');
    const x = get(id, 'breach', 'breach record'), pb = Object.assign({}, x.playbook || {});
    if (pb[b.step]) throw httpErr(409, 'step ' + b.step + ' is already recorded (' + pb[b.step].at + ' by ' + pb[b.step].by + ')');
    if (b.step === 'lessons' && !pb.remediate) throw httpErr(409, 'record remediation before lessons learned');
    if (b.step === 'notify_sdaia' && !pb.assess) throw httpErr(409, 'record the assessment first: the notification states what data and how many people');
    const at = b.at || iso().slice(0, 16) + 'Z';
    if (Date.parse(at) > now() + 300000) throw httpErr(400, 'at cannot be in the future');
    pb[b.step] = { at, by: who.user, note: b.note || '' };
    const upd = { kind: 'breach', id, playbook: pb };
    if (b.step === 'notify_sdaia') upd.sdaia_notified_at = at;
    if (b.step === 'notify_subjects') upd.subjects_notified_at = at;
    PD.putRecord(upd, who);
    audit(who, 'pdpl.breach.step', id, { step: b.step, at });
    return (await rules('pdpl.breach_view')).breaches.find((r) => r.id === id);
  }

  async function breachRegulator(id, b, who) {
    human(who, 'records a regulator notification decision');
    const x = get(id, 'breach', 'breach record'), regs = Object.assign({}, x.regulators || {}), cur = regs[b.regulator];
    if (cur && cur.notified_at) throw httpErr(409, b.regulator + ' was recorded as notified on ' + cur.notified_at + ' by ' + cur.by + ' - that record is evidence and is not changed');
    if (b.required === false && b.notified_at) throw httpErr(400, 'notified_at: a regulator recorded as not required cannot have a notification time');
    if (b.required === false && !b.reason) throw httpErr(400, 'reason is required: say why this regulator\'s instructions do not require notification');
    if (b.regulator === 'other' && !b.name && !(cur && cur.name)) throw httpErr(400, 'name is required for another authority');
    if (b.notified_at) {
      if (Date.parse(b.notified_at) > now() + 300000) throw httpErr(400, 'notified_at cannot be in the future');
      if (x.aware_at && Date.parse(b.notified_at) < Date.parse(x.aware_at) - 60000) throw httpErr(400, 'notified_at is before awareness (' + x.aware_at + ')');
      if (!(x.playbook || {}).assess) throw httpErr(409, 'record the assessment first: the notification states what data and how many people');
      if (!b.ref) throw httpErr(400, 'ref is required with notified_at: the regulator\'s reference or the letter / e-mail reference');
    }
    const at = iso();
    const hist = ((cur && cur.history) || []).concat([{ at, by: who.user, required: b.required, notified_at: b.notified_at || null }]);
    regs[b.regulator] = Object.assign({}, cur || {}, { required: b.required, reason: b.required ? '' : b.reason, notified_at: b.notified_at || null, ref: b.ref || '', by: who.user, at, history: hist },
      b.regulator === 'other' ? { name: b.name || cur.name, hours: b.hours || (cur && cur.hours) || null } : {});
    PD.putRecord({ kind: 'breach', id, regulators: regs }, who);
    audit(who, 'pdpl.breach.regulator', id, { regulator: b.regulator, required: b.required, notified: !!b.notified_at, ref: b.ref || '' });
    return (await rules('pdpl.breach_view')).breaches.find((r) => r.id === id);
  }

  // ---- Processors
  async function processorAssess(id, b, who) {
    human(who, 'records processor due diligence');
    get(id, 'processor', 'processor');
    const a = {}; for (const k of DD) a[k] = !!b[k];
    PD.putRecord({ kind: 'processor', id, assessment: a, assessed: iso().slice(0, 10), assessment_evidence: b.evidence || '', assessed_by: who.user }, who);
    audit(who, 'pdpl.processor.assess', id, { met: DD.filter((k) => a[k]).length, of: DD.length });
    return (await rules('pdpl.processor_view')).processors.find((p) => p.id === id);
  }
  async function subNew(id, b, who) {
    human(who, 'proposes a sub-processor');
    const p = get(id, 'processor', 'processor'), subs = (p.subprocessors || []).slice();
    if (subs.length >= 30) throw httpErr(400, 'a processor lists at most 30 sub-processors');
    if (subs.some((s) => same(s.name, b.name) && s.status !== 'rejected')) throw httpErr(409, b.name + ' is already listed for ' + p.name);
    subs.push({ n: subs.length + 1, name: b.name, service: b.service || '', country: b.country, status: 'pending', proposed_by: who.user, proposed_at: iso() });
    PD.putRecord({ kind: 'processor', id, subprocessors: subs }, who);
    audit(who, 'pdpl.processor.sub.propose', id, { name: b.name, country: b.country });
    return (await rules('pdpl.processor_view')).processors.find((x) => x.id === id);
  }
  async function subDecide(id, n, b, who) {
    human(who, 'approves a sub-processor');
    const p = get(id, 'processor', 'processor'), subs = (p.subprocessors || []).map((s) => Object.assign({}, s));
    const s = subs.find((x) => x.n === n); if (!s) throw httpErr(404, 'no sub-processor ' + n + ' for ' + id);
    if (s.status !== 'pending') throw httpErr(409, 'sub-processor ' + s.name + ' is already ' + s.status);
    if (!isDpo(who) && who.role !== 'admin') throw httpErr(403, 'the DPO (' + (profile().dpo_user || 'not named') + ') or an administrator approves a sub-processor');
    if (same(s.proposed_by, who.user)) throw httpErr(403, 'four-eyes: the person who proposed the sub-processor cannot approve it');
    if (b.decision === 'reject' && !b.note) throw httpErr(400, 'note is required: say why the sub-processor is rejected');
    Object.assign(s, { status: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), note: b.note || '' });
    PD.putRecord({ kind: 'processor', id, subprocessors: subs }, who);
    audit(who, 'pdpl.processor.sub.' + b.decision, id, { name: s.name });
    return (await rules('pdpl.processor_view')).processors.find((x) => x.id === id);
  }

  // ---- Programme: stewards, playbooks, training, maturity
  function putSimple(kind, b, who, action) {
    human(who, 'records the PDPL programme');
    if (b.id) get(b.id, kind, kind);
    const rec = PD.putRecord(Object.assign({ kind }, b), who);
    audit(who, action, rec.id, { fields: Object.keys(b).filter((k) => k !== 'id').sort() });
    return rec;
  }
  async function maturity(b, who) {
    human(who, 'records a maturity assessment');
    const sc = await rules('pdpl.maturity_score', { answers: b.answers });
    const rec = PD.putRecord({ kind: 'maturity', answers: b.answers, score: sc, assessed_by: who.user }, who);
    audit(who, 'pdpl.maturity', rec.id, { overall: sc.overall, level: sc.level });
    return rec;
  }

  // ---- PDPL policy set: read against the GRC register and drafts; a missing one starts a GRC draft (four-eyes there)
  let G0 = null;
  const grc = () => G0 || (G0 = opts.grc || (app.addons && app.addons.grc) || require('./grc').createGrc(app));
  const policyInput = () => ({ policies: grc().register().items.map((p) => ({ doc_id: p.doc_id, title: p.title, version: p.version, owner: p.owner, approver: p.approver, next_review: p.next_review, review: p.review })),
    drafts: grc().draftList().items.map((d) => ({ id: d.id, title: d.title, status: d.status, version: d.version, owner: d.owner, approved_by: d.approved_by, updated: d.updated })) });
  const policies = () => rules('pdpl.policy_view', policyInput());
  async function policyDraft(id, who) {
    human(who, 'starts a policy draft');
    const r = await rules('pdpl.policy_draft', Object.assign({ id }, policyInput()));
    const d = grc().draftPut(r.draft, who);
    audit(who, 'pdpl.policy.draft', d.id, { policy: id, title: d.title });
    return (await policies()).policies.find((x) => x.id === id);
  }

  // ---- an existing policy uploaded by its owner: checked by its content, attached to this policy's GRC draft (created when the
  // policy is missing, a revision draft when it is approved), optionally submitted for approval at once. Approval stays four-eyes
  // in the GRC draft rules: whoever created, changed or uploaded the draft does not approve it.
  const MAX_POLICY = 6 * 1024 * 1024;
  async function policyRow(id) { const p = (await policies()).policies.find((x) => x.id === id); if (!p) throw httpErr(404, 'no PDPL policy ' + id); return p; }
  async function policyUpload(id, b, who) {
    human(who, 'uploads a policy');
    const buf = Buffer.from(String(b.content_b64 || ''), 'base64');
    const fc = require('./check').fileCheck(b.filename, buf, { allow: ['pdf', 'docx', 'doc'], max: MAX_POLICY });
    const sha = require('node:crypto').createHash('sha256').update(buf).digest('hex');   // computed here, never taken from the page
    const p = await policyRow(id);
    let draftId = p.doc, created = false;
    if (p.state === 'missing') {
      const r = await rules('pdpl.policy_draft', Object.assign({ id }, policyInput()));
      draftId = grc().draftPut(Object.assign({}, r.draft, b.owner ? { owner: b.owner } : {}), who).id; created = true;
    } else if (p.state === 'approved' && p.revision) {
      draftId = p.revision.doc;   // the revision already open for this approved policy
      if (b.owner) grc().draftPut({ id: draftId, owner: b.owner }, who);
    } else if (p.state === 'approved') {
      draftId = grc().draftPut({ title: p.title, domain: 'Data Protection', frameworks: 'PDPL (' + p.ref + ')', supersedes: p.doc || '', owner: b.owner || p.owner || '',
        purpose: 'Revision of ' + (p.doc || p.title) + ' (uploaded by its owner)' }, who).id; created = true;
    } else if (b.owner) grc().draftPut({ id: draftId, owner: b.owner }, who);
    grc().draftUpload(draftId, { filename: fc.name, content_b64: buf.toString('base64'), size: fc.size, sha256: sha }, who, { maxInlineB64: Math.ceil(MAX_POLICY / 3) * 4 + 4 });
    if (b.submit) grc().draftStatus(draftId, 'in-review', who);
    audit(who, 'pdpl.policy.upload', draftId, { policy: id, title: p.title, filename: fc.name, size: fc.size, sha256: sha, new_draft: created, revision_of: p.state === 'approved' ? p.doc || null : null, submitted: !!b.submit });
    return policyRow(id);
  }
  async function policySubmit(id, who) {
    human(who, 'submits a policy for approval');
    const p0 = await policyRow(id), p = p0.revision ? Object.assign({}, p0, p0.revision) : p0;   // a revision of an approved policy is what moves
    if (p.state !== 'draft') throw httpErr(409, p.title + ' is ' + p.state.replace('_', ' ') + ' - only a draft is submitted for approval');
    const d = grc().draftGet(p.doc);
    if (!d || (!d.document && !String(d.body || '').trim())) throw httpErr(409, 'upload the policy document (or write its text on GRC Policies) before submitting it');
    grc().draftStatus(p.doc, 'in-review', who);
    audit(who, 'pdpl.policy.submit', p.doc, { policy: id, title: p.title, document: d.document ? d.document.filename : null, sha256: d.document ? d.document.sha256 : null });
    return policyRow(id);
  }
  async function policyDecide(id, b, who) {
    human(who, 'decides on a policy');
    const p0 = await policyRow(id), p = p0.revision ? Object.assign({}, p0, p0.revision) : p0;
    if (p.state !== 'in_review') throw httpErr(409, p.title + ' is not waiting for approval (it is ' + p.state.replace('_', ' ') + ')');
    if (b.decision === 'reject' && String(b.note || '').trim().length < 5) throw httpErr(400, 'note: say why it is rejected (at least 5 characters) - the owner needs it to fix the policy');
    const d = grc().draftStatus(p.doc, b.decision === 'approve' ? 'approved' : 'rejected', who);   // four-eyes enforced here (403 for the author)
    audit(who, 'pdpl.policy.' + (b.decision === 'approve' ? 'approve' : 'reject'), p.doc, { policy: id, title: p.title, version: d.version, note: b.note ? String(b.note).slice(0, 500) : null });
    return policyRow(id);
  }

  // ---- Governance: named owners, committee, privacy by design before go-live, yearly programme review with actions
  const governance = () => rules('pdpl.governance_view');
  async function putAccountability(b, who) {
    human(who, 'names who is accountable');
    const cur = PD.records('accountability').find((x) => x.function === b.function && x.status !== 'archived');
    const rec = PD.putRecord(Object.assign({ kind: 'accountability' }, cur ? { id: cur.id } : {}, b), who);
    audit(who, 'pdpl.accountability', rec.id, { function: b.function, user: b.user, deputy: b.deputy || null, previous: cur ? cur.user : null });
    return (await governance()).functions.find((f) => f.function === b.function);
  }
  function committee(b, who) {
    human(who, 'records a committee meeting');
    if (Date.parse(b.date + 'T00:00:00Z') > now()) throw httpErr(400, 'date cannot be in the future');
    const rec = PD.putRecord(Object.assign({ kind: 'committee_meeting' }, b), who);
    audit(who, 'pdpl.committee.meeting', rec.id, { date: b.date, departments: b.departments, actions: (b.actions || []).length });
    return rec;
  }
  async function pbdNew(b, who) {
    human(who, 'requests a privacy review');
    if (b.ropa_id) get(b.ropa_id, 'ropa', 'processing activity');
    const sc = await rules('pdpl.pbd_assess', { answers: b.answers });
    const rec = PD.putRecord({ kind: 'pbd_review', name: b.name, type: b.type, go_live: b.go_live, ropa_id: b.ropa_id, answers: b.answers, score: sc, state: 'submitted' }, who);
    audit(who, 'pdpl.pbd.submit', rec.id, { name: b.name, dpia_required: sc.dpia_required, required: sc.required.length });
    return rec;
  }
  function pbdDecide(id, b, who) {
    human(who, 'decides a privacy review');
    const r = get(id, 'pbd_review', 'privacy review');
    if (r.state && r.state !== 'submitted') throw httpErr(409, id + ' is already ' + r.state);
    if (!isDpo(who) && who.role !== 'admin') throw httpErr(403, 'the DPO (' + (profile().dpo_user || 'not named') + ') or an administrator decides a privacy review');
    if (same(r.created_by, who.user)) throw httpErr(403, 'four-eyes: the person who requested the review cannot decide it');
    if (b.decision === 'reject' && !b.note) throw httpErr(400, 'note is required: say what must change before go-live');
    if (b.decision === 'approve' && r.score && r.score.dpia_required) {
      const ok = r.ropa_id && PD.records('dpia').some((d) => d.ropa_id === r.ropa_id && d.completed);
      if (!ok) throw httpErr(409, 'an impact assessment is required: link the processing activity and have its DPIA signed first');
    }
    const rec = PD.putRecord({ kind: 'pbd_review', id, state: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: new Date(now()).toISOString(), decision_note: b.note || '' }, who);
    audit(who, 'pdpl.pbd.' + b.decision, id, { name: r.name });
    return rec;
  }
  function review(b, who) {
    human(who, 'records a programme review');
    if (Date.parse(b.date + 'T00:00:00Z') > now()) throw httpErr(400, 'date cannot be in the future');
    const issues = Object.keys(b.checks).filter((k) => b.checks[k].result === 'issues');
    if (issues.length && !(b.actions || []).length) throw httpErr(400, 'actions are required: ' + issues.join(', ') + ' found issues - record what will be done, by whom and when');
    const rec = PD.putRecord({ kind: 'programme_review', date: b.date, checks: b.checks, summary: b.summary || '', actions: (b.actions || []).map((x) => Object.assign({ status: 'open' }, x)) }, who);
    audit(who, 'pdpl.review', rec.id, { date: b.date, issues, actions: (b.actions || []).length });
    return rec;
  }
  function reviewAction(id, n, b, who) {
    human(who, 'updates a review action');
    const r = get(id, 'programme_review', 'programme review'), acts = (r.actions || []).map((x) => Object.assign({}, x));
    const x = acts[n - 1]; if (!x) throw httpErr(404, 'no action ' + n + ' in ' + id);
    if (b.status === 'done' && !b.note) throw httpErr(400, 'note is required: say what was done (evidence)');
    Object.assign(x, { status: b.status, note: b.note || x.note || '', by: who.user, at: new Date(now()).toISOString() });
    PD.putRecord({ kind: 'programme_review', id, actions: acts }, who);
    audit(who, 'pdpl.review.action', id, { n, status: b.status });
    return x;
  }

  // the consultant's patrol: sensitive-control and processor gaps become work items too
  async function findings() {
    const s = await rules('pdpl.sensitive_view'), p = await rules('pdpl.processor_view'), br = await rules('pdpl.breach_view');
    return s.findings.concat(p.findings, br.findings || []);
  }

  return { ropa, ropaExport, putSensitive, sensitive: () => rules('pdpl.sensitive_view'), dsar: () => rules('pdpl.dsar_view'), dsarNew, dsarVerify, dsarTask, dsarExtend, dsarRespond, dsarRefuse, dsarWithdraw, dsarLetter,
    dpia: () => rules('pdpl.dpia_view'), transfers: () => rules('pdpl.transfer_view'), transferTia, transferSign, breaches: () => rules('pdpl.breach_view'), breachStep, breachRegulator,
    processors: () => rules('pdpl.processor_view'), processorAssess, subNew, subDecide, programme: () => rules('pdpl.programme_view'), putSimple, maturity, policies, policyDraft, policyUpload, policySubmit, policyDecide, governance, putAccountability, committee, pbdNew, pbdDecide, review, reviewAction, findings };
}

function registerWorkflowRoutes(srv, app, WF) {
  const { body, param } = require('./check');
  const pid = (ctx, re, label, name = 'id') => { const v = param(ctx.params[name], name); if (!re.test(v)) throw httpErr(400, name + ' must be ' + label); return v; };
  const DSR = (ctx) => pid(ctx, /^PD-DSR-\d{3,}$/, 'a data subject request id (PD-DSR-nnn)');
  const op = (fn) => async (ctx) => { ctx.need('operator'); return fn(ctx); };
  const answers = (ctx, max) => {
    const a = ctx.body && ctx.body.answers;
    if (!a || typeof a !== 'object' || Array.isArray(a)) throw httpErr(400, 'answers must be an object {question: option}');
    const out = {}; for (const [k, v] of Object.entries(a).slice(0, max)) { if (!/^[a-z_.]{1,40}$/.test(k) || typeof v !== 'string' || v.length > 60) throw httpErr(400, 'answers: ' + k.slice(0, 40) + ' is not a valid answer'); out[k] = v; }
    return out;
  };
  const dt = (v, f, o) => v.str(f, Object.assign({ max: 30, re: DT, msg: f + ' must be a date or date-time (YYYY-MM-DD[THH:MM])' }, o || {}));

  srv.route('GET', '/pdpl/ropa', op(() => WF.ropa()));
  srv.route('GET', '/pdpl/ropa/export', op((ctx) => WF.ropaExport(ctx.who)));
  srv.route('GET', '/pdpl/sensitive', op(() => WF.sensitive()));
  srv.route('POST', '/pdpl/sensitive/:id', op((ctx) => {
    const id = pid(ctx, /^PD-ROPA-\d{3,}$/, 'a processing activity id (PD-ROPA-nnn)');
    const v = body(ctx.body); for (const c of CONTROLS) v.bool(c);
    v.list('access_tiers', { item: 'str', itemMax: 80, max: 20, unique: true }).date('access_review', { notFuture: true }).str('evidence', { max: 500 });
    return WF.putSensitive(id, v.done(), ctx.who);
  }));

  srv.route('GET', '/pdpl/dsar', op(() => WF.dsar()));
  srv.route('POST', '/pdpl/dsar', op((ctx) => {
    const v = body(ctx.body).str('ref', { required: true, max: 60, re: /^[A-Za-z0-9_./-]+$/, msg: 'ref must be the request reference from the customer system (letters, digits, - _ . /)' })
      .oneOf('type', DSR_TYPES, { required: true }).oneOf('channel', CHANNELS, { required: true }).list('systems', { item: 'str', itemMax: 120, max: 50, unique: true }).str('assigned_to', { max: 80, re: /^[A-Za-z0-9._@-]+$/, msg: 'assigned_to must be a platform user name' });
    dt(v, 'received', { required: true });
    return WF.dsarNew(v.done(), ctx.who);
  }));
  srv.route('POST', '/pdpl/dsar/:id/verify', op((ctx) => WF.dsarVerify(DSR(ctx), body(ctx.body).oneOf('method', ID_METHODS, { required: true }).str('note', { max: 300 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/dsar/:id/task', op((ctx) => WF.dsarTask(DSR(ctx), body(ctx.body).str('system', { required: true, max: 120 }).oneOf('status', ['open', 'done', 'not_found', 'retained_by_law'], { required: true }).str('note', { max: 300 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/dsar/:id/extend', op((ctx) => WF.dsarExtend(DSR(ctx), body(ctx.body).str('reason', { required: true, min: 10, max: 500 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/dsar/:id/respond', op((ctx) => WF.dsarRespond(DSR(ctx), body(ctx.body).oneOf('outcome', ['fulfilled', 'partially'], { required: true }).str('note', { max: 500 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/dsar/:id/refuse', op((ctx) => WF.dsarRefuse(DSR(ctx), body(ctx.body).oneOf('ground', GROUNDS, { required: true }).str('note', { required: true, max: 500 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/dsar/:id/withdraw', op((ctx) => WF.dsarWithdraw(DSR(ctx), body(ctx.body).str('note', { required: true, max: 300 }).done(), ctx.who)));
  srv.route('GET', '/pdpl/dsar/:id/letter', op((ctx) => WF.dsarLetter(DSR(ctx), ctx.who)));

  srv.route('GET', '/pdpl/dpia/view', op(() => WF.dpia()));

  const TR = (ctx) => pid(ctx, /^PD-TRANSFER-\d{3,}$/, 'a transfer id (PD-TRANSFER-nnn)');
  srv.route('GET', '/pdpl/transfers', op(() => WF.transfers()));
  srv.route('POST', '/pdpl/transfers/:id/tia', op((ctx) => { const id = TR(ctx); const b = body(ctx.body).str('notes', { max: 1000 }).done(); b.answers = answers(ctx, 20); return WF.transferTia(id, b, ctx.who); }));
  srv.route('POST', '/pdpl/transfers/:id/tia/sign', op((ctx) => WF.transferSign(TR(ctx), ctx.who)));

  srv.route('GET', '/pdpl/breaches', op(() => WF.breaches()));
  srv.route('POST', '/pdpl/breach/:id/step', op((ctx) => {
    const id = pid(ctx, /^PD-BREACH-\d{3,}$/, 'a breach id (PD-BREACH-nnn)');
    const v = body(ctx.body).oneOf('step', STEPS, { required: true }).str('note', { max: 500 }); dt(v, 'at');
    return WF.breachStep(id, v.done(), ctx.who);
  }));
  srv.route('POST', '/pdpl/breach/:id/regulator', op((ctx) => {
    const id = pid(ctx, /^PD-BREACH-\d{3,}$/, 'a breach id (PD-BREACH-nnn)');
    const v = body(ctx.body).oneOf('regulator', REGS, { required: true }).bool('required', { required: true }).str('reason', { max: 500 }).str('ref', { max: 80 }).str('name', { max: 120 }).int('hours', { min: 1, max: 720 }); dt(v, 'notified_at');
    return WF.breachRegulator(id, v.done(), ctx.who);
  }));

  const PR = (ctx) => pid(ctx, /^PD-PROCESSOR-\d{3,}$/, 'a processor id (PD-PROCESSOR-nnn)');
  srv.route('GET', '/pdpl/processors', op(() => WF.processors()));
  srv.route('POST', '/pdpl/processors/:id/assessment', op((ctx) => { const v = body(ctx.body); for (const k of DD) v.bool(k); return WF.processorAssess(PR(ctx), v.str('evidence', { max: 500 }).done(), ctx.who); }));
  srv.route('POST', '/pdpl/processors/:id/subprocessor', op((ctx) => WF.subNew(PR(ctx), body(ctx.body).str('name', { required: true, max: 160 }).str('service', { max: 300 }).str('country', { required: true, max: 80 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/processors/:id/subprocessor/:n', op((ctx) => {
    const n = Number(param(ctx.params.n, 'n')); if (!Number.isInteger(n) || n < 1 || n > 30) throw httpErr(400, 'n must be a sub-processor number (1-30)');
    return WF.subDecide(PR(ctx), n, body(ctx.body).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 500 }).done(), ctx.who);
  }));

  srv.route('GET', '/pdpl/programme', op(() => WF.programme()));
  const user = { max: 80, re: /^[A-Za-z0-9._@-]+$/, msg: 'user must be a platform user name' };
  srv.route('POST', '/pdpl/stewards', op((ctx) => {
    const v = body(ctx.body).str('id', { re: /^PD-STEWARD-\d{3,}$/, msg: 'id must be a steward id (PD-STEWARD-nnn)' }).oneOf('status', ['active', 'archived']);
    const need = ctx.body && ctx.body.id ? {} : { required: true };
    return WF.putSimple('steward', v.str('department', Object.assign({ max: 120 }, need)).str('user', Object.assign({}, user, need)).oneOf('role', ['data_steward', 'deputy', 'champion'], need).str('email', { max: 254, email: true }).done(), ctx.who, 'pdpl.steward.put');   // email: RoPA reminders (engine/pdpl-ropa-flow.js)
  }));
  srv.route('POST', '/pdpl/playbooks', op((ctx) => {
    const need = ctx.body && ctx.body.id ? {} : { required: true };
    const v = body(ctx.body).str('id', { re: /^PD-PLAYBOOK-\d{3,}$/, msg: 'id must be a playbook id (PD-PLAYBOOK-nnn)' }).oneOf('status', ['active', 'archived'])
      .str('team', Object.assign({ max: 120 }, need)).str('title', Object.assign({ max: 160 }, need)).oneOf('topic', ['consent', 'classification', 'sharing', 'deletion', 'requests', 'breach', 'marketing', 'other'], need)
      .str('tool', { max: 160 }).list('steps', { item: 'str', itemMax: 300, max: 30 }).date('reviewed', { notFuture: true });
    return WF.putSimple('playbook', v.done(), ctx.who, 'pdpl.playbook.put');
  }));
  srv.route('POST', '/pdpl/training', op((ctx) => {
    const v = body(ctx.body).str('team', { required: true, max: 120 }).str('topic', { required: true, max: 200 }).date('date', { required: true, notFuture: true }).int('attendees', { required: true, min: 1, max: 100000 }).str('evidence', { max: 300 })
      .oneOf('audience', ['all_staff', 'finance', 'customer_facing', 'it_security', 'hr', 'marketing', 'management']).bool('onboarding');
    return WF.putSimple('training', v.done(), ctx.who, 'pdpl.training.put');
  }));
  srv.route('GET', '/pdpl/governance', op(() => WF.governance()));
  srv.route('POST', '/pdpl/accountability', async (ctx) => {
    ctx.need('admin');   // who is accountable for a PDPL function is a management decision
    return WF.putAccountability(body(ctx.body).oneOf('function', ['inventory', 'approval', 'requests', 'incidents', 'training', 'sdaia'], { required: true }).str('user', Object.assign({ required: true }, user)).str('deputy', user).done(), ctx.who);
  });
  const ACT = (v) => v.list('actions', { max: 30 }).rule((o) => ((o.actions || []).some((a) => !a || typeof a !== 'object' || typeof a.action !== 'string' || !a.action.trim() || a.action.length > 300 || !/^[A-Za-z0-9._@-]{1,80}$/.test(String(a.owner || '')) || !/^\d{4}-\d{2}-\d{2}$/.test(String(a.due || '')))
    ? 'each action needs {action, owner (user name), due (YYYY-MM-DD)}' : null));
  const cleanActs = (o) => { if (o.actions) o.actions = o.actions.map((a) => ({ action: a.action.trim(), owner: a.owner, due: a.due })); return o; };
  srv.route('POST', '/pdpl/committee', op((ctx) => {
    const v = body(ctx.body).date('date', { required: true }).list('departments', { required: true, item: ['legal', 'it', 'hr', 'operations', 'compliance', 'risk', 'finance', 'marketing', 'customer_service', 'claims', 'underwriting', 'management'], unique: true, max: 12 })
      .list('attendees', { item: 'str', itemMax: 80, max: 30, unique: true }).str('decisions', { max: 2000 });
    return WF.committee(cleanActs(ACT(v).done()), ctx.who);
  }));
  srv.route('POST', '/pdpl/pbd', op((ctx) => {
    const v = body(ctx.body).str('name', { required: true, max: 160 }).oneOf('type', ['new_system', 'new_product', 'change', 'vendor', 'other'], { required: true }).date('go_live')
      .str('ropa_id', { max: 40, re: /^PD-ROPA-\d{3,}$/, msg: 'ropa_id must be a processing activity id (PD-ROPA-nnn)' }).done();
    v.answers = answers(ctx, 20); return WF.pbdNew(v, ctx.who);
  }));
  srv.route('POST', '/pdpl/pbd/:id/decide', op((ctx) => WF.pbdDecide(pid(ctx, /^PD-PBD_REVIEW-\d{3,}$/, 'a privacy review id (PD-PBD_REVIEW-nnn)'), body(ctx.body).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 500 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/reviews', op((ctx) => {
    const v = body(ctx.body).date('date', { required: true }).str('summary', { max: 2000 });
    const c = ctx.body && ctx.body.checks, checks = {};
    if (!c || typeof c !== 'object' || Array.isArray(c)) throw httpErr(400, 'checks must be an object {check: {result, note}}');
    for (const k of ['followed', 'changes', 'guidance', 'processors', 'incidents']) {
      const x = c[k]; if (!x || !['ok', 'issues'].includes(x.result)) throw httpErr(400, 'checks.' + k + '.result must be ok or issues');
      if (x.note !== undefined && (typeof x.note !== 'string' || x.note.length > 1000)) throw httpErr(400, 'checks.' + k + '.note must be text up to 1000 characters');
      checks[k] = { result: x.result, note: x.note || '' };
    }
    const o = cleanActs(ACT(v).done()); o.checks = checks; return WF.review(o, ctx.who);
  }));
  srv.route('POST', '/pdpl/reviews/:id/action/:n', op((ctx) => {
    const n = Number(param(ctx.params.n, 'n')); if (!Number.isInteger(n) || n < 1 || n > 30) throw httpErr(400, 'n must be an action number (1-30)');
    return WF.reviewAction(pid(ctx, /^PD-PROGRAMME_REVIEW-\d{3,}$/, 'a programme review id (PD-PROGRAMME_REVIEW-nnn)'), n, body(ctx.body).oneOf('status', ['open', 'done'], { required: true }).str('note', { max: 500 }).done(), ctx.who);
  }));
  srv.route('GET', '/pdpl/policies', async (ctx) => { ctx.need('viewer'); return WF.policies(); });   // policy titles and states, no personal data
  srv.route('POST', '/pdpl/policies/:id/draft', op((ctx) => WF.policyDraft(pid(ctx, /^PP-\d{2}$/, 'a PDPL policy id (PP-nn)'), ctx.who)));
  const PPID = (ctx) => pid(ctx, /^PP-\d{2}$/, 'a PDPL policy id (PP-nn)');
  srv.route('POST', '/pdpl/policies/:id/upload', op((ctx) => WF.policyUpload(PPID(ctx), body(ctx.body || {}).str('filename', { required: true, max: 200 })
    .str('content_b64', { required: true, max: 8400000, re: /^[A-Za-z0-9+/=\s]+$/, msg: 'content_b64 must be the file in base64' }).str('owner', { max: 120 }).bool('submit').done(), ctx.who)), { maxBody: 9 * 1024 * 1024 });
  srv.route('POST', '/pdpl/policies/:id/submit', op((ctx) => WF.policySubmit(PPID(ctx), ctx.who)));
  srv.route('POST', '/pdpl/policies/:id/decide', async (ctx) => { ctx.need('admin');
    return WF.policyDecide(PPID(ctx), body(ctx.body || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 500 }).done(), ctx.who); });
  srv.route('POST', '/pdpl/maturity', op((ctx) => WF.maturity({ answers: answers(ctx, 40) }, ctx.who)));
}

module.exports = { createWorkflows, registerWorkflowRoutes, WF_KINDS };
