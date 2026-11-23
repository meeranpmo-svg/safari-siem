// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * IT Audit Inspections ({P} = /api/itam, Audit -> IT Audit Inspections) - the on-site side of the IT audit: a scored checklist
 * walked at a site (data centre, server room, branch, network closet, a desk), with photo evidence, signatures, corrective
 * actions that keep the inspection open until a second person verifies them, a branded report, schedules and cross-site analytics.
 *   templates   sections of items; an item is yes/no, a 1-5 rating, a number with a range, or text; weight 1-5; CRITICAL items
 *               fail the whole inspection; evidence none / optional / required / required when the item fails; a framework
 *               reference (NCA ECC sub-domain). Five starter templates ship (content, not data); edits make a new version and an
 *               inspection keeps the version it was started on.
 *   inspection  in_progress -> submitted (no failed items) | actions_open -> closed. Score = weighted share of applicable items
 *               that pass (rating: (r-1)/4; n/a excluded); pass when >= the template's pass mark AND no critical item failed.
 *               Submitting needs every applicable item answered, the evidence each item requires, the inspector's signature and
 *               the site representative's name and signature. A DIFFERENT person reviews it (approve, or return with a reason).
 *               It closes when it is approved and every corrective action is verified; the report is then frozen and hashed.
 *   evidence    photos (PNG / JPEG / WEBP, checked by their bytes, <= 3 MB) stored on the server by SHA-256 with when they were
 *               taken and, if the browser allowed it, where; never in the repository (PDPL: do not photograph people's screens or
 *               documents with personal data). Signatures are PNG, stored the same way.
 *   actions     one per failed item: critical 7 days, otherwise 30 (editable); the assignee records the fix, a DIFFERENT person
 *               verifies it or reopens it with a reason. Overdue actions are listed for the duty desk.
 *   schedules   template x site every N days (7-365); the next due date moves when a scheduled inspection is submitted.
 *   analytics   per site: last / average score, a least-squares trend per inspection (3+ needed) and its forecast; items that
 *               fail most often; REPEAT failures (the same item failed at the same site in its last two inspections).
 * Names, photos and sites' weaknesses are internal: viewers see counts and scores per site only; operators work; admins archive.
 *   GET  /inspect                                 viewer    kpis, sites, analytics (+ inspections, actions, due: operator)
 *   GET  /inspect/templates · /inspect/templates/:id          operator
 *   POST /inspect/templates                       operator  {name, category?, pass_mark?, sections[]}               audited
 *   PUT  /inspect/templates/:id                   operator  a new version                                            audited
 *   POST /inspect/templates/:id/archive           admin                                                              audited
 *   POST /inspect/schedules                       operator  {template_id, site, every_days, next_due?}             audited
 *   POST /inspect/schedules/:id/delete            operator                                                           audited
 *   POST /inspect/inspections                     operator  {template_id, site, schedule_id?}                      audited
 *   GET  /inspect/inspections/:id                 operator
 *   POST /inspect/inspections/:id/answers         operator  the inspector: {answers[{item, value?, na?, note?}], location?}
 *   POST /inspect/inspections/:id/evidence        operator  the inspector: {item, image, taken_at?, lat?, lon?}   audited
 *   GET  /inspect/evidence/:sha                   operator  the image (attachment-safe headers)
 *   POST /inspect/inspections/:id/submit          operator  the inspector: {inspector_signature, auditee_name, auditee_role?, auditee_signature}  audited
 *   POST /inspect/inspections/:id/review          operator  not the inspector: {decision: approve|return, note?}  audited
 *   POST /inspect/actions/:id                     operator  {assignee?, due?, text?}                                audited
 *   POST /inspect/actions/:id/fix                 operator  {note, evidence?}                                        audited
 *   POST /inspect/actions/:id/verify              operator  not the fixer: {decision: verify|reopen, note?}        audited
 *   GET  /inspect/inspections/:id/report          operator  {filename, html, hash?}                                   audited
 *   POST /inspect/actions/:id/exception           operator  {reason, until, compensating?}  ask to accept the risk         audited
 *   POST /inspect/actions/:id/exception/decide    admin     not the requester: {decision: approve|reject, note?}           audited
 *   POST /inspect/templates/ai-draft              operator  {request, arabic?}  the AI DRAFTS a checklist; nothing saved   audited
 * Risk on each action = likelihood x impact (1-25; critical items start at 4x5, others 3x3). A risk acceptance (exception) counts
 * as resolved until its date, then the action is open again. Templates carry Arabic beside English (title_ar, text_ar).
 * Insurer templates ship too: claims & policy system access, third-party connectivity (TPA / brokers / reinsurers), customer data
 * at branches and the call centre (SAMA CSF / IA / PDPL references).
 */
const DAY = 86400000, RIYADH = 3 * 3600000;
const TYPES = ['yesno', 'rating', 'number', 'text'], EVID = ['none', 'optional', 'required', 'on_fail'];
const MAX_IMG = 3 * 1024 * 1024, MAX_SIG = 300 * 1024;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const escH = (x) => String(x == null ? '' : x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rid = (p) => p + '-' + crypto.randomBytes(5).toString('hex');
function lsq(pts) { const n = pts.length; if (n < 3) return null; const mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n, sxx = pts.reduce((a, p) => a + (p[0] - mx) ** 2, 0); return sxx ? { slope: pts.reduce((a, p) => a + (p[0] - mx) * (p[1] - my), 0) / sxx, mx, my } : { slope: 0, mx, my }; }

// starter templates - methodology content an auditor edits, never data about a site
const Y = (id, text, o) => Object.assign({ id, text, type: 'yesno', weight: 2, critical: false, evidence: 'on_fail', guidance: '', ref: '' }, o || {});
const STARTER = [
  { key: 'dc', name: 'Data centre / server room inspection', category: 'Physical & environmental', pass_mark: 85, sections: [
    { id: 's1', title: 'Physical access', items: [Y('a1', 'Entry is controlled by badge / biometric and the reader works', { critical: true, ref: 'NCA ECC 2-14', weight: 3 }), Y('a2', 'The visitor log is kept and complete for the last 30 days', { ref: 'NCA ECC 2-14' }), Y('a3', 'CCTV covers the entrance and the rack rows and is recording', { critical: true, ref: 'NCA ECC 2-14', weight: 3, evidence: 'required' }), Y('a4', 'Racks and cabinets are locked', { ref: 'NCA ECC 2-14' })] },
    { id: 's2', title: 'Environment', items: [Y('e1', 'Room temperature (deg C)', { type: 'number', min: 18, max: 27, ref: 'NCA ECC 2-3', evidence: 'required' }), Y('e2', 'Relative humidity (%)', { type: 'number', min: 40, max: 60, ref: 'NCA ECC 2-3' }), Y('e3', 'Fire suppression serviced within its interval (label checked)', { critical: true, ref: 'NCA ECC 2-14', weight: 3, evidence: 'required' }), Y('e4', 'Water / leak detection present and alarming to the NOC', { ref: 'NCA ECC 2-3' }), Y('e5', 'Housekeeping: no boxes, combustibles or food in the room', { type: 'rating', weight: 1 })] },
    { id: 's3', title: 'Power & cabling', items: [Y('p1', 'UPS on line, no alarms, battery test within 12 months', { ref: 'NCA ECC 2-3', weight: 3 }), Y('p2', 'Generator run-tested in the last 30 days (log checked)', { ref: 'NCA ECC 2-3' }), Y('p3', 'Cabling labelled at both ends; no trailing or loose cables', { type: 'rating' }), Y('p4', 'No unidentified device in the racks (each has an asset tag)', { ref: 'NCA ECC 2-1' })] }] },
  { key: 'branch', name: 'Branch IT inspection', category: 'Branch', pass_mark: 80, sections: [
    { id: 's1', title: 'Network cabinet', items: [Y('n1', 'Network cabinet locked and its key controlled', { ref: 'NCA ECC 2-14', weight: 3 }), Y('n2', 'Switch / firewall / router labelled and tagged', { ref: 'NCA ECC 2-1' }), Y('n3', 'UPS present and on line for the network equipment', { ref: 'NCA ECC 2-3' }), Y('n4', 'No unmanaged switch or personal Wi-Fi access point found', { critical: true, ref: 'NCA ECC 2-5', weight: 3 })] },
    { id: 's2', title: 'Workplace', items: [Y('w1', 'Unattended workstations are locked (spot check of 5)', { ref: 'NCA ECC 2-6', weight: 3 }), Y('w2', 'No passwords written on desks or monitors', { critical: true, ref: 'NCA ECC 2-2' }), Y('w3', 'Guest Wi-Fi is separate from the corporate network', { ref: 'NCA ECC 2-5' }), Y('w4', 'Printers use secure release; no documents left in trays', { ref: 'NCA ECC 2-7' }), Y('w5', 'Clean desk observed', { type: 'rating', weight: 1, evidence: 'none' })] }] },
  { key: 'backup', name: 'Backup & restore verification', category: 'Resilience', pass_mark: 90, sections: [
    { id: 's1', title: 'Backups', items: [Y('b1', 'Last scheduled backup job of each critical system succeeded', { critical: true, ref: 'NCA ECC 2-9', weight: 3, evidence: 'required' }), Y('b2', 'An offline / immutable or off-site copy exists for critical systems', { critical: true, ref: 'NCA ECC 2-9', weight: 3 }), Y('b3', 'Retention matches the backup policy', { ref: 'NCA ECC 2-9' }), Y('b4', 'Backup data is encrypted at rest', { ref: 'NCA ECC 2-8' })] },
    { id: 's2', title: 'Restore', items: [Y('r1', 'A restore test was performed this quarter and documented', { critical: true, ref: 'NCA ECC 2-9', weight: 3, evidence: 'required' }), Y('r2', 'Restore time achieved (hours) for the tested system', { type: 'number', min: 0, max: 24, ref: 'NCA ECC 2-9' }), Y('r3', 'Access to the backup console requires MFA', { ref: 'NCA ECC 2-2', weight: 3 })] }] },
  { key: 'endpoint', name: 'End-user workstation spot check', category: 'Endpoints', pass_mark: 80, sections: [
    { id: 's1', title: 'Device', items: [Y('d1', 'Endpoint protection (EDR / antivirus) running and up to date', { critical: true, ref: 'NCA ECC 2-3', weight: 3 }), Y('d2', 'Operating system patched within 30 days', { ref: 'NCA ECC 2-3', weight: 3 }), Y('d3', 'Disk encryption enabled', { ref: 'NCA ECC 2-8' }), Y('d4', 'User is not a local administrator', { ref: 'NCA ECC 2-2' }), Y('d5', 'Screen lock at 15 minutes or less', { ref: 'NCA ECC 2-6' }), Y('d6', 'No unauthorised software installed', { ref: 'NCA ECC 2-1', evidence: 'optional' })] }] },
  { key: 'claims', name: 'Claims & policy system access review (insurer)', category: 'Insurance operations', pass_mark: 90, sections: [
    { id: 's1', title: 'Access to the core insurance systems', items: [Y('c1', 'Every user of the claims system has an approved access request on file (sample of 10)', { critical: true, ref: 'SAMA CSF 3.3.5', weight: 3, evidence: 'required' }), Y('c2', 'Leavers removed from the policy administration system within 1 working day', { critical: true, ref: 'SAMA CSF 3.3.5', weight: 3 }), Y('c3', 'Segregation of duties: no user can both register and approve a claim payment', { critical: true, ref: 'SAMA CSF 3.3.5', weight: 3, evidence: 'required' }), Y('c4', 'Privileged / DBA access to the claims database is named, logged and reviewed monthly', { ref: 'SAMA CSF 3.3.5', weight: 3 }), Y('c5', 'Quarterly user access review signed by the business owner', { ref: 'SAMA CSF 3.3.5' })] },
    { id: 's2', title: 'Change and data', items: [Y('d1', 'Changes to premium / reserve calculation rules went through change approval', { critical: true, ref: 'SAMA CSF 3.3.7', weight: 3 }), Y('d2', 'Production claims data is not used in test without masking', { ref: 'PDPL Art. 19', weight: 3 }), Y('d3', 'Bulk exports of policyholder data are logged and approved', { ref: 'PDPL Art. 19' })] }] },
  { key: 'tpa', name: 'Third-party connectivity: TPA, brokers, reinsurers (insurer)', category: 'Third party', pass_mark: 85, sections: [
    { id: 's1', title: 'Contract & assurance', items: [Y('t1', 'A signed contract with security and data-protection clauses exists for the third party', { critical: true, ref: 'SAMA CSF 3.4.1', weight: 3, evidence: 'required' }), Y('t2', 'Latest assurance (ISO 27001 certificate / SOC 2 / questionnaire) is less than 12 months old', { ref: 'SAMA CSF 3.4.1' }), Y('t3', 'Cross-border transfer of policyholder data has a PDPL basis and safeguards', { critical: true, ref: 'PDPL Art. 29', weight: 3 })] },
    { id: 's2', title: 'Technical connection', items: [Y('n1', 'Connection limited to named systems and ports (firewall rule reviewed)', { ref: 'SAMA CSF 3.3.8', weight: 3 }), Y('n2', 'Third-party accounts are individual, MFA-protected and expire', { critical: true, ref: 'SAMA CSF 3.3.5', weight: 3 }), Y('n3', 'Data exchanged over encrypted channels only (SFTP / TLS 1.2+)', { ref: 'SAMA CSF 3.3.9' }), Y('n4', 'Third-party access is logged to the SIEM', { ref: 'SAMA CSF 3.3.14' })] }] },
  { key: 'pdpl-branch', name: 'Customer data handling: branch & call centre (insurer, PDPL)', category: 'Data protection', pass_mark: 85, sections: [
    { id: 's1', title: 'Front office', items: [Y('p1', 'Customer ID copies and medical documents are locked away, not left on desks', { critical: true, ref: 'PDPL Art. 19', weight: 3, evidence: 'on_fail' }), Y('p2', 'Screens facing customers do not show other customers\' data', { ref: 'PDPL Art. 19' }), Y('p3', 'Privacy notice displayed / given at the point of collection', { ref: 'PDPL Art. 12' }), Y('p4', 'Shredder or secure disposal bin in use', { ref: 'PDPL Art. 18' })] },
    { id: 's2', title: 'Call centre', items: [Y('k1', 'Callers are verified before policy or claim details are disclosed', { critical: true, ref: 'PDPL Art. 4', weight: 3 }), Y('k2', 'Call recordings have a retention period and restricted access', { ref: 'PDPL Art. 18' }), Y('k3', 'No personal mobile phones at agent desks', { ref: 'SAMA CSF 3.3.10' })] }] },
  { key: 'closet', name: 'Network closet / IDF inspection', category: 'Physical & environmental', pass_mark: 80, sections: [
    { id: 's1', title: 'Closet', items: [Y('c1', 'Door locked; access limited to IT', { critical: true, ref: 'NCA ECC 2-14', weight: 3 }), Y('c2', 'Temperature acceptable (deg C)', { type: 'number', min: 15, max: 30, ref: 'NCA ECC 2-3' }), Y('c3', 'Patch panels labelled', { type: 'rating', ref: 'NCA ECC 2-5' }), Y('c4', 'Console ports secured / not left connected', { ref: 'NCA ECC 2-5' }), Y('c5', 'No storage of unrelated items', { weight: 1, evidence: 'none' })] }] }
];

function createAuditInspect(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, every() {} };
  const T = () => store.collection('insp_templates'), SC = () => store.collection('insp_schedules'), IN = () => store.collection('insp_inspections'), AC = () => store.collection('insp_actions'), EV = () => store.collection('insp_evidence');
  const iso = () => new Date(now()).toISOString(), day = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
  const dir = opts.evidenceDir || path.join((app.config && app.config.data_dir) || os.tmpdir(), 'inspection-evidence');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'inspect.' + action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };

  /* ---- templates */
  function seed() { if (T().all().length) return; for (const t of STARTER) { const id = 'tpl-' + t.key; T().put({ id, name: t.name, category: t.category, pass_mark: t.pass_mark, sections: t.sections, version: 1, status: 'active', builtin: true, by: 'built-in', at: null }); } }
  function checkSections(secs) {
    if (!Array.isArray(secs) || !secs.length) throw httpErr(400, 'sections: at least one section is required');
    if (secs.length > 20) throw httpErr(400, 'sections: at most 20');
    let n = 0; const ids = new Set();
    return secs.map((sec, i) => {
      const sb = body(sec).str('id', { max: 20, re: /^[a-z0-9_-]{1,20}$/, msg: 'sections[' + i + '].id must be short letters / digits' }).str('title', { required: true, max: 120 }).str('title_ar', { max: 120 }).done();
      if (!Array.isArray(sec.items) || !sec.items.length) throw httpErr(400, 'sections[' + i + '].items: at least one item is required');
      if (sec.items.length > 60) throw httpErr(400, 'sections[' + i + '].items: at most 60');
      return { id: sb.id || 's' + (i + 1), title: sb.title, title_ar: sb.title_ar || '', items: sec.items.map((it, j) => {
        const f = 'sections[' + i + '].items[' + j + ']';
        const b = body(it).str('id', { max: 20, re: /^[a-z0-9_-]{1,20}$/, msg: f + '.id must be short letters / digits' }).str('text', { required: true, max: 300 }).str('text_ar', { max: 300 }).oneOf('type', TYPES, { def: 'yesno' })
          .int('weight', { min: 1, max: 5, def: 2 }).bool('critical', { def: false }).oneOf('evidence', EVID, { def: 'on_fail' }).str('guidance', { max: 400 }).str('ref', { max: 60 })
          .num('min', {}).num('max', {}).done();
        const id = b.id || 'i' + (i + 1) + '_' + (j + 1); if (ids.has(id)) throw httpErr(400, f + '.id: "' + id + '" is used twice'); ids.add(id);
        if (b.type === 'number' && b.min != null && b.max != null && b.min > b.max) throw httpErr(400, f + '.min: must not exceed max');
        if (++n > 300) throw httpErr(400, 'sections: at most 300 items in a template');
        return Object.assign({}, b, { id });
      }) };
    });
  }
  function templates() { seed(); return T().all().sort((a, b) => (a.status === 'archived') - (b.status === 'archived') || String(a.name).localeCompare(String(b.name))); }
  function template(id) { seed(); const t = T().get(id); if (!t) throw httpErr(404, 'no template ' + id); return t; }
  function createTemplate(input, who) {
    const b = body(input).str('name', { required: true, max: 120 }).str('category', { max: 60 }).int('pass_mark', { min: 50, max: 100, def: 80 }).done();
    person(who, 'write an audit template');
    if (templates().length >= 100) throw httpErr(409, 'at most 100 templates');
    const t = { id: rid('tpl'), name: b.name, category: b.category || 'General', pass_mark: b.pass_mark, sections: checkSections(input && input.sections), version: 1, status: 'active', by: who.user, at: iso() };
    T().put(t); audit(who, 'template.create', t.id, { name: t.name, items: t.sections.reduce((a, x) => a + x.items.length, 0) });
    return { template: t };
  }
  function updateTemplate(id, input, who) {
    const t0 = template(id); if (t0.status === 'archived') throw httpErr(409, 'this template is archived');
    const b = body(input).str('name', { max: 120 }).str('category', { max: 60 }).int('pass_mark', { min: 50, max: 100 }).done();
    person(who, 'change an audit template');
    const t = Object.assign({}, t0, { name: b.name || t0.name, category: b.category || t0.category, pass_mark: b.pass_mark || t0.pass_mark, sections: input && input.sections ? checkSections(input.sections) : t0.sections, version: (t0.version || 1) + 1, by: who.user, at: iso() });
    T().put(t); audit(who, 'template.update', id, { version: t.version });
    return { template: t };
  }
  function archiveTemplate(id, who) { const t = template(id); person(who, 'archive an audit template'); T().put(Object.assign({}, t, { status: 'archived', by: who.user, at: iso() })); audit(who, 'template.archive', id, { name: t.name }); return { ok: true }; }

  /* ---- sites and schedules */
  function sites() { const set = new Set(); for (const a of store.collection('assets').all((x) => x.status !== 'disposed')) if (a.site) set.add(s(a.site, 80)); for (const x of SC().all()) set.add(x.site); for (const x of IN().all()) set.add(x.site); return [...set].filter(Boolean).sort(); }
  const siteOk = (v) => { const x = s(v, 80); if (!x) throw httpErr(400, 'site is required'); return x; };
  function createSchedule(input, who) {
    const b = body(input).str('template_id', { required: true, max: 40 }).str('site', { required: true, max: 80 }).int('every_days', { required: true, min: 7, max: 365 }).date('next_due', {}).done();
    person(who, 'schedule inspections'); const t = template(b.template_id); if (t.status !== 'active') throw httpErr(409, 'template_id: the template is archived');
    if (SC().all().length >= 500) throw httpErr(409, 'at most 500 schedules');
    const x = { id: rid('sch'), template_id: t.id, template: t.name, site: siteOk(b.site), every_days: b.every_days, next_due: b.next_due || day(now()), by: who.user, at: iso() };
    SC().put(x); audit(who, 'schedule.create', x.id, { template: t.name, site: x.site, every_days: x.every_days });
    return { schedule: x };
  }
  function deleteSchedule(id, who) { const x = SC().get(id); if (!x) throw httpErr(404, 'no schedule ' + id); person(who, 'remove a schedule'); SC().remove(id); audit(who, 'schedule.delete', id, { site: x.site, template: x.template }); return { ok: true }; }

  /* ---- inspections */
  function getIns(id) { const x = IN().get(id); if (!x) throw httpErr(404, 'no inspection ' + id); return x; }
  const items = (ins) => [].concat(...ins.snapshot.map((sec) => sec.items.map((it) => Object.assign({ section: sec.id }, it))));
  function itemResult(it, a) {
    if (!a || a.na) return a && a.na ? { applicable: false } : { applicable: true, answered: false };
    const v = a.value;
    if (it.type === 'text') return { applicable: true, answered: v != null && String(v).trim() !== '', score: null };
    if (it.type === 'yesno') return { applicable: true, answered: v === 'yes' || v === 'no', score: v === 'yes' ? 1 : 0, failed: v === 'no' };
    if (it.type === 'rating') { const r = Number(v); const okv = Number.isInteger(r) && r >= 1 && r <= 5; return { applicable: true, answered: okv, score: okv ? (r - 1) / 4 : 0, failed: okv && r <= 2 }; }
    const n = Number(v); const okv = v !== '' && v != null && isFinite(n); const inRange = okv && (it.min == null || n >= it.min) && (it.max == null || n <= it.max);
    return { applicable: true, answered: okv, score: inRange ? 1 : 0, failed: okv && !inRange };
  }
  function scoreOf(ins) {
    const t = { w: 0, got: 0 }, secs = {}, failed = [], unanswered = [], missingEvidence = [];
    let critical = false;
    for (const it of items(ins)) {
      const a = (ins.answers || {})[it.id], r = itemResult(it, a);
      if (!r.applicable) continue;
      if (!r.answered) { unanswered.push(it.id); continue; }
      const ev = (a && a.evidence) || [];
      if ((it.evidence === 'required' || (it.evidence === 'on_fail' && r.failed)) && !ev.length) missingEvidence.push(it.id);
      if (r.score == null) continue;
      const S = secs[it.section] || (secs[it.section] = { w: 0, got: 0 });
      S.w += it.weight; S.got += it.weight * r.score; t.w += it.weight; t.got += it.weight * r.score;
      if (r.failed) { failed.push(it.id); if (it.critical) critical = true; }
    }
    const pct = t.w ? Math.round(1000 * t.got / t.w) / 10 : null;
    return { score: pct, sections: ins.snapshot.map((sec) => ({ id: sec.id, title: sec.title, score: secs[sec.id] && secs[sec.id].w ? Math.round(1000 * secs[sec.id].got / secs[sec.id].w) / 10 : null })),
      failed, critical_failed: critical, unanswered, missing_evidence: missingEvidence, result: pct == null ? null : (critical || pct < ins.pass_mark ? 'fail' : 'pass') };
  }
  function startInspection(input, who) {
    const b = body(input).str('template_id', { required: true, max: 40 }).str('site', { required: true, max: 80 }).str('schedule_id', { max: 40 }).done();
    person(who, 'run an inspection');
    const t = template(b.template_id); if (t.status !== 'active') throw httpErr(409, 'template_id: the template is archived');
    if (b.schedule_id && !SC().get(b.schedule_id)) throw httpErr(400, 'schedule_id: no such schedule');
    const x = { id: rid('ins'), template_id: t.id, template: t.name, template_version: t.version, category: t.category, pass_mark: t.pass_mark, snapshot: t.sections, site: siteOk(b.site), schedule_id: b.schedule_id || null,
      inspector: who.user, started_at: iso(), state: 'in_progress', answers: {}, location: null, history: [{ at: iso(), by: who.user, what: 'started' }] };
    IN().put(x); audit(who, 'start', x.id, { template: t.name, version: t.version, site: x.site });
    return { inspection: view1(x) };
  }
  function mine(ins, who, what) { if (ins.inspector !== who.user) throw httpErr(403, 'only the inspector (' + ins.inspector + ') can ' + what); if (ins.state !== 'in_progress') throw httpErr(409, 'the inspection is ' + ins.state + ' - it can no longer be changed'); }
  function answers(id, input, who) {
    const ins = getIns(id); person(who, 'answer an inspection'); mine(ins, who, 'answer it');
    if (!input || !Array.isArray(input.answers)) throw httpErr(400, 'answers must be a list');
    if (input.answers.length > 300) throw httpErr(400, 'answers: at most 300');
    const byId = new Map(items(ins).map((it) => [it.id, it])), A = Object.assign({}, ins.answers);
    input.answers.forEach((a0, i) => {
      const b = body(a0).str('item', { required: true, max: 20 }).bool('na').str('note', { max: 1000 }).done();
      const it = byId.get(b.item); if (!it) throw httpErr(400, 'answers[' + i + '].item: not an item of this checklist');
      // only what the request carries changes: a note on its own must not wipe the answer (and the reverse)
      const hasV = !!a0 && Object.prototype.hasOwnProperty.call(a0, 'value'), hasNa = !!a0 && Object.prototype.hasOwnProperty.call(a0, 'na');
      let value = a0 && a0.value;
      if (value != null && value !== '') {
        if (it.type === 'yesno' && value !== 'yes' && value !== 'no') throw httpErr(400, 'answers[' + i + '].value: yes or no');
        if (it.type === 'rating' && !(Number.isInteger(Number(value)) && value >= 1 && value <= 5)) throw httpErr(400, 'answers[' + i + '].value: a rating from 1 to 5');
        if (it.type === 'number' && !isFinite(Number(value))) throw httpErr(400, 'answers[' + i + '].value: a number');
        if (it.type === 'text') value = s(value, 1000);
        if (it.type === 'number' || it.type === 'rating') value = Number(value);
      } else value = null;
      const prev = A[b.item] || {};
      A[b.item] = Object.assign({}, prev, { value: hasV ? value : prev.value == null ? null : prev.value, na: hasNa ? !!b.na : !!prev.na, note: b.note != null ? b.note : prev.note || '', at: iso() });
    });
    let loc = ins.location;
    if (input.location) { const l = body(input.location).num('lat', { min: -90, max: 90, required: true }).num('lon', { min: -180, max: 180, required: true }).num('accuracy', { min: 0, max: 100000 }).done(); loc = Object.assign(l, { at: iso() }); }
    IN().put(Object.assign({}, ins, { answers: A, location: loc }));
    return { inspection: view1(IN().get(id)) };
  }
  // an image is accepted by its bytes, not by its name
  function decodeImage(v, field, max, pngOnly) {
    const m = /^data:image\/(png|jpe?g|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(v || ''));
    if (!m) throw httpErr(400, field + ': must be a PNG' + (pngOnly ? '' : ', JPEG or WEBP') + ' image');
    const buf = Buffer.from(m[2], 'base64'); if (!buf.length) throw httpErr(400, field + ': empty image');
    if (buf.length > max) throw httpErr(400, field + ': image is too large (max ' + Math.round(max / 1024) + ' KB)');
    const kind = buf[0] === 0x89 && buf.slice(1, 4).toString() === 'PNG' ? 'png' : buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff ? 'jpeg' : buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP' ? 'webp' : null;
    if (!kind || (pngOnly && kind !== 'png')) throw httpErr(400, field + ': the file is not a ' + (pngOnly ? 'PNG' : 'PNG, JPEG or WEBP') + ' image');
    return { buf, kind };
  }
  function putBlob(img, meta) {
    const sha = crypto.createHash('sha256').update(img.buf).digest('hex');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const f = path.join(dir, sha + '.' + img.kind); if (!fs.existsSync(f)) fs.writeFileSync(f, img.buf, { mode: 0o600 });
    if (!EV().get(sha)) EV().put(Object.assign({ id: sha, kind: img.kind, bytes: img.buf.length, stored_at: iso() }, meta));
    return sha;
  }
  function evidence(id, input, who) {
    const ins = getIns(id); person(who, 'add evidence'); mine(ins, who, 'add evidence');
    const b = body(input).str('item', { required: true, max: 20 }).str('taken_at', { max: 40 }).num('lat', { min: -90, max: 90 }).num('lon', { min: -180, max: 180 }).done();
    const it = items(ins).find((x) => x.id === b.item); if (!it) throw httpErr(400, 'item: not an item of this checklist');
    const a = (ins.answers || {})[b.item] || {}; if ((a.evidence || []).length >= 10) throw httpErr(409, 'item: at most 10 photos per item');
    const img = decodeImage(input && input.image, 'image', MAX_IMG, false);
    const taken = b.taken_at && !isNaN(Date.parse(b.taken_at)) ? new Date(b.taken_at).toISOString() : null;
    const sha = putBlob(img, { inspection: id, item: b.item, by: who.user, taken_at: taken, lat: b.lat == null ? null : b.lat, lon: b.lon == null ? null : b.lon });
    const A = Object.assign({}, ins.answers); A[b.item] = Object.assign({}, a, { evidence: [...new Set((a.evidence || []).concat(sha))] });
    IN().put(Object.assign({}, ins, { answers: A }));
    audit(who, 'evidence', id, { item: b.item, sha256: sha, bytes: img.buf.length, located: b.lat != null });
    return { sha256: sha, inspection: view1(IN().get(id)) };
  }
  function evidenceFile(sha) {
    if (!/^[0-9a-f]{64}$/.test(sha)) throw httpErr(400, 'not an evidence id');
    const m = EV().get(sha); if (!m) throw httpErr(404, 'no evidence ' + sha);
    const f = path.join(dir, sha + '.' + m.kind); if (!fs.existsSync(f)) throw httpErr(410, 'the evidence file is missing on the server');
    return { kind: m.kind, buf: fs.readFileSync(f) };
  }
  function submit(id, input, who) {
    const ins = getIns(id); person(who, 'submit an inspection'); mine(ins, who, 'submit it');
    const b = body(input).str('auditee_name', { required: true, max: 120 }).str('auditee_role', { max: 120 }).done();
    const sc = scoreOf(ins);
    if (sc.unanswered.length) throw httpErr(400, 'answers: ' + sc.unanswered.length + ' item(s) not answered (' + sc.unanswered.slice(0, 5).join(', ') + ') - answer them or mark n/a');
    if (sc.missing_evidence.length) throw httpErr(400, 'evidence: photo evidence is required for ' + sc.missing_evidence.join(', '));
    if (sc.score == null) throw httpErr(400, 'answers: nothing scoreable was answered');
    const isig = putBlob(decodeImage(input && input.inspector_signature, 'inspector_signature', MAX_SIG, true), { inspection: id, kind_of: 'signature', by: who.user });
    const asig = putBlob(decodeImage(input && input.auditee_signature, 'auditee_signature', MAX_SIG, true), { inspection: id, kind_of: 'signature', by: b.auditee_name });
    const byId = new Map(items(ins).map((it) => [it.id, it])), due = (crit) => day(now() + (crit ? 7 : 30) * DAY);
    for (const iid of sc.failed) { const it = byId.get(iid); AC().put({ id: rid('act'), inspection: id, site: ins.site, item: iid, item_text: it.text, severity: it.critical ? 'critical' : 'major', likelihood: it.critical ? 4 : 3, impact: it.critical ? 5 : 3, text: 'Correct: ' + it.text, note: ((ins.answers[iid] || {}).note) || '', assignee: null, due: due(it.critical), state: 'open', created_at: iso(), history: [{ at: iso(), by: who.user, what: 'opened from the failed item' }] }); }
    const next = Object.assign({}, ins, { state: sc.failed.length ? 'actions_open' : 'submitted', submitted_at: iso(), score: sc.score, result: sc.result, critical_failed: sc.critical_failed, section_scores: sc.sections, failed: sc.failed,
      signatures: { inspector: { name: who.user, sha256: isig, at: iso() }, auditee: { name: b.auditee_name, role: b.auditee_role || '', sha256: asig, at: iso() } }, history: ins.history.concat([{ at: iso(), by: who.user, what: 'submitted: ' + sc.score + '% ' + sc.result + (sc.failed.length ? ', ' + sc.failed.length + ' corrective action(s)' : '') }]) });
    IN().put(next);
    if (ins.schedule_id) { const x = SC().get(ins.schedule_id); if (x) SC().put(Object.assign({}, x, { next_due: day(now() + x.every_days * DAY), last_done: day(now()) })); }
    audit(who, 'submit', id, { site: ins.site, score: sc.score, result: sc.result, failed: sc.failed.length, critical: sc.critical_failed });
    return { inspection: view1(next) };
  }
  function maybeClose(id) {
    const ins = getIns(id); if (!ins.review || ins.review.decision !== 'approve' || ins.state === 'closed') return;
    const t = day(now()); if (AC().all((a) => a.inspection === id && !resolved(a, t)).length) return;
    const html = reportHtml(ins, true), hash = crypto.createHash('sha256').update(html).digest('hex');
    IN().put(Object.assign({}, ins, { state: 'closed', closed_at: iso(), report_hash: hash, history: ins.history.concat([{ at: iso(), by: 'system', what: 'closed: approved and every action verified; report frozen ' + hash.slice(0, 12) }]) }));
  }
  function review(id, input, who) {
    const ins = getIns(id); person(who, 'review an inspection');
    const b = body(input).oneOf('decision', ['approve', 'return'], { required: true }).str('note', { max: 600 }).done();
    if (ins.inspector === who.user) throw httpErr(403, 'the inspector cannot review their own inspection (four eyes)');
    if (!['submitted', 'actions_open'].includes(ins.state) || (ins.review && ins.review.decision === 'approve')) throw httpErr(409, 'the inspection is ' + ins.state + (ins.review ? ' and already reviewed' : '') + ' - nothing to review');
    if (b.decision === 'return') {
      if (!b.note) throw httpErr(400, 'note is required to return an inspection');
      if (AC().all((a) => a.inspection === id && a.state !== 'open').length) throw httpErr(409, 'corrective actions are already being worked - it cannot be returned');
      for (const a of AC().all((x) => x.inspection === id)) AC().remove(a.id);
      IN().put(Object.assign({}, ins, { state: 'in_progress', signatures: null, review: null, history: ins.history.concat([{ at: iso(), by: who.user, what: 'returned: ' + b.note }]) }));
    } else IN().put(Object.assign({}, ins, { review: { decision: 'approve', by: who.user, at: iso(), note: b.note || '' }, history: ins.history.concat([{ at: iso(), by: who.user, what: 'approved' + (b.note ? ': ' + b.note : '') }]) }));
    audit(who, 'review', id, { decision: b.decision, note: b.note || '' });
    maybeClose(id);
    return { inspection: view1(getIns(id)) };
  }

  /* ---- corrective actions */
  function getAct(id) { const a = AC().get(id); if (!a) throw httpErr(404, 'no corrective action ' + id); return a; }
  function editAction(id, input, who) {
    const a = getAct(id); person(who, 'assign a corrective action'); if (a.state === 'verified') throw httpErr(409, 'the action is verified');
    const b = body(input).str('assignee', { max: 120 }).date('due', {}).str('text', { max: 400 }).int('likelihood', { min: 1, max: 5 }).int('impact', { min: 1, max: 5 }).done();
    const next = Object.assign({}, a, { assignee: b.assignee != null ? b.assignee : a.assignee, due: b.due || a.due, text: b.text || a.text, likelihood: b.likelihood || a.likelihood, impact: b.impact || a.impact,
      history: a.history.concat([{ at: iso(), by: who.user, what: 'updated' + (b.assignee ? ', assignee ' + b.assignee : '') + (b.due ? ', due ' + b.due : '') + (b.likelihood || b.impact ? ', risk ' + (b.likelihood || a.likelihood) + 'x' + (b.impact || a.impact) : '') }]) });
    AC().put(next); audit(who, 'action.update', id, { assignee: next.assignee, due: next.due, likelihood: next.likelihood, impact: next.impact }); return { action: riskOf(next) };
  }
  function fixAction(id, input, who) {
    const a = getAct(id); person(who, 'record a fix'); if (!['open', 'reopened'].includes(a.state)) throw httpErr(409, 'the action is ' + a.state);
    if (a.assignee && a.assignee !== who.user && who.role !== 'admin') throw httpErr(403, 'the action is assigned to ' + a.assignee);
    const b = body(input).str('note', { required: true, max: 1000 }).done();
    let sha = null; if (input && input.evidence) sha = putBlob(decodeImage(input.evidence, 'evidence', MAX_IMG, false), { action: id, by: who.user, taken_at: null });
    const next = Object.assign({}, a, { state: 'fixed', fix: { by: who.user, at: iso(), note: b.note, evidence: sha }, history: a.history.concat([{ at: iso(), by: who.user, what: 'fixed: ' + b.note }]) });
    AC().put(next); audit(who, 'action.fix', id, { inspection: a.inspection, evidence: !!sha }); return { action: next };
  }
  function verifyAction(id, input, who) {
    const a = getAct(id); person(who, 'verify a fix'); if (a.state !== 'fixed') throw httpErr(409, 'only a fixed action can be verified');
    if (a.fix && a.fix.by === who.user) throw httpErr(403, 'the person who fixed it cannot verify it (four eyes)');
    const b = body(input).oneOf('decision', ['verify', 'reopen'], { required: true }).str('note', { max: 600 }).done();
    if (b.decision === 'reopen' && !b.note) throw httpErr(400, 'note is required to reopen an action');
    const next = Object.assign({}, a, { state: b.decision === 'verify' ? 'verified' : 'reopened', verify: { by: who.user, at: iso(), decision: b.decision, note: b.note || '' }, history: a.history.concat([{ at: iso(), by: who.user, what: b.decision + (b.note ? ': ' + b.note : '') }]) });
    AC().put(next); audit(who, 'action.' + b.decision, id, { inspection: a.inspection, note: b.note || '' });
    maybeClose(a.inspection);
    return { action: next };
  }

  // risk = likelihood x impact (1-25): high >= 15, medium >= 8, else low
  function riskOf(a) { const r = (a.likelihood || 3) * (a.impact || 3); return Object.assign({}, a, { risk: r, risk_band: r >= 15 ? 'high' : r >= 8 ? 'medium' : 'low' }); }
  const resolved = (a, t) => a.state === 'verified' || (a.state === 'accepted' && a.exception && a.exception.until >= t);
  // exceptions: the owner asks to accept the risk for a time, with a reason; a DIFFERENT administrator decides; it lapses on its date
  function requestException(id, input, who) {
    const a = getAct(id); person(who, 'request a risk acceptance'); if (!['open', 'reopened', 'fixed'].includes(a.state)) throw httpErr(409, 'the action is ' + a.state);
    const b = body(input).str('reason', { required: true, max: 1000 }).date('until', { required: true }).str('compensating', { max: 600 }).done();
    const t = day(now()); if (b.until <= t || b.until > day(now() + 365 * DAY)) throw httpErr(400, 'until: a date after today and within 12 months');
    const next = Object.assign({}, a, { state: 'exception_requested', prev_state: a.state, exception: { reason: b.reason, compensating: b.compensating || '', until: b.until, by: who.user, at: iso() }, history: a.history.concat([{ at: iso(), by: who.user, what: 'risk acceptance requested until ' + b.until + ': ' + b.reason }]) });
    AC().put(next); audit(who, 'action.exception.request', id, { until: b.until, risk: riskOf(next).risk }); return { action: riskOf(next) };
  }
  function decideException(id, input, who) {
    const a = getAct(id); person(who, 'decide a risk acceptance'); if (a.state !== 'exception_requested') throw httpErr(409, 'no risk acceptance is waiting');
    if (a.exception.by === who.user) throw httpErr(403, 'the person who asked cannot accept their own risk (four eyes)');
    const b = body(input).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 600 }).done();
    if (b.decision === 'reject' && !b.note) throw httpErr(400, 'note is required to reject');
    const next = Object.assign({}, a, { state: b.decision === 'approve' ? 'accepted' : a.prev_state || 'open', exception: Object.assign({}, a.exception, { decision: b.decision, decided_by: who.user, decided_at: iso(), note: b.note || '' }), history: a.history.concat([{ at: iso(), by: who.user, what: 'risk acceptance ' + b.decision + 'd' + (b.note ? ': ' + b.note : '') }]) });
    AC().put(next); audit(who, 'action.exception.' + b.decision, id, { until: a.exception.until, note: b.note || '' });
    maybeClose(a.inspection);
    return { action: riskOf(next) };
  }

  /* ---- AI: draft a checklist from a described scope; a person reviews and saves it */
  const cfgA = (app.config && app.config.ai) || {}, dcf = (app.config && app.config.discovery) || {};
  const getKey = opts.getKey || (() => { try { return require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'anthropic_api_key', dcf.vault_key_file)() || process.env.ANTHROPIC_API_KEY || ''; } catch (e) { return process.env.ANTHROPIC_API_KEY || ''; } });
  let Ctor = null;
  function loadSdk() { if (opts.sdk) return opts.sdk; if (Ctor) return Ctor; for (const p of [cfgA.sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', path.join(__dirname, 'ai-sdk-shim.js')].filter(Boolean)) { try { if (p.startsWith('/') && !fs.existsSync(p)) continue; const m = require(p); Ctor = require('./ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { Ctor = null; /* next location */ } } return null; }
  function aiStatus() {
    let ok = false; try { ok = !!(app.settings && require('./ai-backend').allowed(app.settings.get())); } catch (e) { ok = false; /* settings unreadable = not allowed */ }
    if (!ok) return { enabled: false, reason: 'AI is not available: external AI is not allowed in Settings, or the AI engine is switched off (Platform Administration -> AI Engine)' };
    if (!getKey()) return { enabled: false, reason: 'no AI key and no local model set (Platform Administration -> AI Engine)' };
    if (!loadSdk()) return { enabled: false, reason: 'the AI client is not installed' };
    return { enabled: true, model: cfgA.model || 'claude-opus-5-5' };
  }
  const ITEM_SCHEMA = { type: 'object', additionalProperties: false, required: ['text', 'type'], properties: { text: { type: 'string' }, text_ar: { type: 'string' }, type: { type: 'string', enum: TYPES }, weight: { type: 'integer' }, critical: { type: 'boolean' }, evidence: { type: 'string', enum: EVID }, ref: { type: 'string' }, guidance: { type: 'string' }, min: { type: 'number' }, max: { type: 'number' } } };
  const TOOL = { name: 'draft_template', description: 'Draft ONE on-site IT audit checklist. It is a draft a person reviews, edits and saves; you save nothing.',
    input_schema: { type: 'object', additionalProperties: false, required: ['name', 'sections'], properties: { name: { type: 'string' }, category: { type: 'string' }, pass_mark: { type: 'integer' },
      sections: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['title', 'items'], properties: { title: { type: 'string' }, title_ar: { type: 'string' }, items: { type: 'array', items: ITEM_SCHEMA } } } } } } };
  async function aiDraft(input, who) {
    person(who, 'ask the AI for a checklist');
    const b = body(input).str('request', { required: true, max: 800 }).bool('arabic', { def: false }).done();
    if (b.request.length < 10) throw httpErr(400, 'request: describe the scope in at least 10 characters');
    const st = aiStatus(); if (!st.enabled) throw httpErr(424, st.reason);
    const G = require('./ai-guard'), bud = G.sharedBudget({ log: L, limits: () => ((app.config && app.config.ai) || {}).limits || {} });
    const flags = G.injectionSignals(b.request), req = G.redactSecrets(b.request);
    const sys = ('You draft on-site IT audit checklists for ' + ZYB_ORG.short + ', a Saudi cooperative insurance company regulated by SAMA (Cyber Security Framework), the Insurance Authority, the NCA (ECC) and SDAIA (PDPL). ') +
      'Each item is one observable check a person can verify at the site, phrased so "yes" / a high rating / an in-range number means the control works. Use type yesno, rating (1-5), number (with min and max) or text. Mark critical only what alone should fail the inspection. ' +
      'evidence: required when a photo or document must prove it, on_fail when a failure must be photographed. ref: a framework reference you are confident of (e.g. "SAMA CSF 3.3.5", "NCA ECC 2-14", "PDPL Art. 19") or leave it empty - never invent one. ' +
      (b.arabic ? 'Give every section title and item text in Arabic too (title_ar, text_ar). ' : '') + 'At most 8 sections and 60 items. Call draft_template exactly once. You save nothing: a person reviews and saves it.\n\n' + G.UNTRUSTED_RULE;
    bud.admit(who.user, 'inspect.ai.draft', req.length + sys.length);
    const C = loadSdk(), client = new C({ apiKey: getKey(), timeout: (cfgA.timeout_s || 120) * 1000, maxRetries: 1 });
    let resp, usage = {};
    try { resp = await client.messages.create({ model: st.model, max_tokens: 6000, system: sys, tools: [TOOL], tool_choice: { type: 'tool', name: 'draft_template' }, messages: [{ role: 'user', content: G.untrusted('scope', req) }] }); usage = resp.usage || {}; }
    finally { bud.record(who.user, 'inspect.ai.draft', usage, flags); }
    const u = (resp.content || []).find((x) => x.type === 'tool_use' && x.name === 'draft_template'), i = (u && u.input) || {};
    if (!u) throw httpErr(422, 'the AI did not draft a checklist - describe the scope again');
    let sections; try { sections = checkSections(i.sections); } catch (e) { throw httpErr(422, 'the AI draft does not fit a checklist (' + e.message + ') - ask again or build it by hand'); }
    const draft = { name: s(i.name, 120) || 'AI draft', category: s(i.category, 60) || 'General', pass_mark: Number.isInteger(i.pass_mark) && i.pass_mark >= 50 && i.pass_mark <= 100 ? i.pass_mark : 80, sections };
    audit(who, 'ai.draft', draft.name, { sections: sections.length, items: sections.reduce((a, x) => a + x.items.length, 0), flagged: flags.length > 0 });
    return { draft, model: resp.model || st.model, injection_signals: flags, note: 'a draft: nothing is saved until a person reviews it and saves it as a template' };
  }

  /* ---- report */
  function brand() { try { const P = (app.addons || {}).pentest; return P && P.reportBrand ? P.reportBrand() : {}; } catch (e) { return {}; /* brand optional: a plain header */ } }
  function imgTag(sha, w) { try { const f = evidenceFile(sha); return '<img src="data:image/' + f.kind + ';base64,' + f.buf.toString('base64') + '" style="max-width:' + w + 'px;max-height:' + w + 'px;border:1px solid #ccd;border-radius:4px;margin:2px" alt="evidence ' + sha.slice(0, 8) + '">'; } catch (e) { return '<span>[evidence ' + escH(sha.slice(0, 12)) + ' unavailable]</span>'; } }
  function reportHtml(ins, frozen) {
    const B = brand(), A = AC().all((a) => a.inspection === ins.id), byId = new Map(items(ins).map((it) => [it.id, it]));
    const row = (it) => { const a = (ins.answers || {})[it.id] || {}, r = itemResult(it, a); const v = a.na ? 'n/a' : it.type === 'yesno' ? (a.value || '') : a.value == null ? '' : String(a.value);
      return '<tr' + (r.failed ? ' style="background:#fdecee"' : '') + '><td>' + escH(it.text) + (it.text_ar ? '<br><span dir="rtl" lang="ar">' + escH(it.text_ar) + '</span>' : '') + (it.critical ? ' <b style="color:#b00020">[critical]</b>' : '') + (it.ref ? '<br><small>' + escH(it.ref) + '</small>' : '') + '</td><td>' + escH(v) + '</td><td>' + (r.failed ? '<b style="color:#b00020">FAIL</b>' : a.na ? '-' : 'ok') + '</td><td>' + escH(a.note || '') + ((a.evidence || []).length ? '<br>' + a.evidence.map((x) => imgTag(x, 140)).join('') : '') + '</td></tr>'; };
    const sig = (x, label) => x ? '<div style="display:inline-block;margin-right:40px"><div>' + imgTag(x.sha256, 220) + '</div><div><b>' + escH(x.name) + '</b>' + (x.role ? ', ' + escH(x.role) : '') + '<br><small>' + escH(label + ' · ' + String(x.at).slice(0, 16).replace('T', ' ')) + '</small></div></div>' : '';
    return '<!doctype html><html><head><meta charset="utf-8"><title>' + escH(ins.template + ' - ' + ins.site) + '</title><style>@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}body{font:13px Arial,sans-serif;color:#111;background:#fff;margin:28px}h1{font-size:20px;margin:0}table{border-collapse:collapse;width:100%;margin:8px 0 16px}td,th{border:1px solid #ccd;padding:5px 7px;vertical-align:top;text-align:left}th{background:#eef1f7}.big{font-size:32px;font-weight:700}</style></head><body>'
      + (B.letterhead ? '<img src="' + escH(B.letterhead) + '" style="max-height:70px" alt="letterhead"><br>' : '') + '<div style="display:flex;justify-content:space-between;align-items:flex-end"><div><small>' + escH(B.org_name || '') + ' · IT Audit Inspection report</small><h1>' + escH(ins.template) + '</h1><div>Site: <b>' + escH(ins.site) + '</b> · template v' + escH(ins.template_version) + ' · inspector ' + escH(ins.inspector) + ' · ' + escH(String(ins.submitted_at || ins.started_at).slice(0, 16).replace('T', ' ')) + (ins.location ? ' · location ' + ins.location.lat.toFixed(5) + ', ' + ins.location.lon.toFixed(5) : '') + '</div></div>'
      + '<div style="text-align:right"><div class="big" style="color:' + (ins.result === 'pass' ? '#0a7d3c' : '#b00020') + '">' + escH(ins.score == null ? '-' : ins.score + '%') + '</div><div>' + escH((ins.result || 'not submitted').toUpperCase()) + ' · pass mark ' + ins.pass_mark + '%' + (ins.critical_failed ? ' · critical item failed' : '') + '</div></div></div>'
      + '<h3>Sections</h3><table><tr><th>Section</th><th>Score</th></tr>' + (ins.section_scores || []).map((x) => '<tr><td>' + escH(x.title) + '</td><td>' + (x.score == null ? '-' : x.score + '%') + '</td></tr>').join('') + '</table>'
      + ins.snapshot.map((sec) => '<h3>' + escH(sec.title) + '</h3><table><tr><th style="width:42%">Item</th><th>Answer</th><th>Result</th><th>Note / evidence</th></tr>' + sec.items.map(row).join('') + '</table>').join('')
      + '<h3>Corrective actions (' + A.length + ')</h3>' + (A.length ? '<table><tr><th>Item</th><th>Action</th><th>Severity</th><th>Assignee</th><th>Due</th><th>State</th></tr>' + A.map((a) => '<tr><td>' + escH((byId.get(a.item) || {}).text || a.item) + '</td><td>' + escH(a.text) + (a.fix ? '<br><small>fix: ' + escH(a.fix.note) + ' (' + escH(a.fix.by) + ')</small>' : '') + '</td><td>' + escH(a.severity) + ' / ' + riskOf(a).risk + ' (' + riskOf(a).risk_band + ')</td><td>' + escH(a.assignee || 'unassigned') + '</td><td>' + escH(a.due) + '</td><td>' + escH(a.state) + (a.verify ? ' by ' + escH(a.verify.by) : '') + (a.exception && a.exception.decision === 'approve' ? '<br><small>risk accepted until ' + escH(a.exception.until) + ' by ' + escH(a.exception.decided_by) + ': ' + escH(a.exception.reason) + '</small>' : '') + '</td></tr>').join('') + '</table>' : '<p>None - every item passed.</p>')
      + '<h3>Sign-off</h3>' + (ins.signatures ? sig(ins.signatures.inspector, 'inspector') + sig(ins.signatures.auditee, 'site representative') : '<p>Not signed.</p>') + (ins.review ? '<p>Reviewed and approved by <b>' + escH(ins.review.by) + '</b> on ' + escH(String(ins.review.at).slice(0, 16).replace('T', ' ')) + (ins.review.note ? ': ' + escH(ins.review.note) : '') + '</p>' : '<p>Not yet reviewed.</p>')
      + (frozen ? '' : (ins.report_hash ? '<p><small>Final report SHA-256 ' + escH(ins.report_hash) + '</small></p>' : '<p><small>Working copy - the report is frozen and hashed when the inspection closes.</small></p>')) + '</body></html>';
  }
  function report(id, who) {
    const ins = getIns(id); const html = reportHtml(ins, false);
    audit(who, 'report', id, { state: ins.state, hash: ins.report_hash || null });
    return { filename: 'inspection-' + ins.site.replace(/[^A-Za-z0-9]+/g, '-').slice(0, 40) + '-' + String(ins.submitted_at || ins.started_at).slice(0, 10) + '.html', html, hash: ins.report_hash || null };
  }

  /* ---- views */
  function view1(x) { const sc = scoreOf(x); return Object.assign({}, x, { live: sc, actions: AC().all((a) => a.inspection === x.id).map(riskOf) }); }
  function inspection(id) { return view1(getIns(id)); }
  function view(who) {
    seed();
    const t = day(now()), done = IN().all((x) => x.state !== 'in_progress' && x.score != null).sort((a, b) => String(a.submitted_at).localeCompare(String(b.submitted_at)));
    const since90 = done.filter((x) => Date.parse(x.submitted_at) >= now() - 90 * DAY), acts = AC().all(), open = acts.filter((a) => !resolved(a, t)), overdue = open.filter((a) => a.due < t && a.state !== 'exception_requested'), accepted = acts.filter((a) => a.state === 'accepted');
    const bySite = new Map(); for (const x of done) { if (!bySite.has(x.site)) bySite.set(x.site, []); bySite.get(x.site).push(x); }
    const siteRows = [...bySite.entries()].map(([site, L]) => {
      const pts = L.map((x, i) => [i, x.score]), f = lsq(pts), last = L[L.length - 1];
      const forecast = f ? Math.max(0, Math.min(100, Math.round((f.my + f.slope * (L.length - f.mx)) * 10) / 10)) : null;
      return { site, inspections: L.length, last_score: last.score, last_result: last.result, last_at: last.submitted_at, average: Math.round(10 * L.reduce((a, x) => a + x.score, 0) / L.length) / 10,
        trend_per_inspection: f ? Math.round(f.slope * 10) / 10 : null, forecast_next: forecast, at_risk: forecast != null && forecast < last.pass_mark, open_actions: open.filter((a) => a.site === site).length, note: f ? null : 'trend withheld - ' + L.length + ' inspection(s), 3 needed' };
    }).sort((a, b) => a.last_score - b.last_score);
    // items that fail most often, and repeats: failed at the same site in its last two inspections
    const fails = new Map(); for (const x of done) for (const iid of x.failed || []) { const it = (x.snapshot ? items(x) : []).find((y) => y.id === iid); const k = x.template_id + '|' + iid; const e = fails.get(k) || { template: x.template, item: iid, text: it ? it.text : iid, count: 0, sites: new Set() }; e.count++; e.sites.add(x.site); fails.set(k, e); }
    const repeats = []; for (const [site, L] of bySite) { const byT = new Map(); for (const x of L) { if (!byT.has(x.template_id)) byT.set(x.template_id, []); byT.get(x.template_id).push(x); } for (const LL of byT.values()) if (LL.length >= 2) { const a = LL[LL.length - 2], b = LL[LL.length - 1]; for (const iid of b.failed || []) if ((a.failed || []).includes(iid)) { const it = items(b).find((y) => y.id === iid); repeats.push({ site, template: b.template, item: iid, text: it ? it.text : iid, last: b.submitted_at }); } } }
    const due = SC().all().map((x) => Object.assign({}, x, { status: x.next_due < t ? 'overdue' : x.next_due <= day(now() + 7 * DAY) ? 'due_soon' : 'scheduled' })).sort((a, b) => a.next_due.localeCompare(b.next_due));
    const months = new Map(); for (const x of done) { const m = String(x.submitted_at).slice(0, 7); const e = months.get(m) || { month: m, n: 0, sum: 0 }; e.n++; e.sum += x.score; months.set(m, e); }
    const res = { generated_at: iso(),
      kpis: { inspections_90d: since90.length, average_90d: since90.length ? Math.round(10 * since90.reduce((a, x) => a + x.score, 0) / since90.length) / 10 : null, pass_rate_90d: since90.length ? Math.round(1000 * since90.filter((x) => x.result === 'pass').length / since90.length) / 10 : null,
        open_actions: open.length, overdue_actions: overdue.length, overdue_schedules: due.filter((x) => x.status === 'overdue').length, in_progress: IN().all((x) => x.state === 'in_progress').length, repeat_failures: repeats.length, high_risk_actions: open.filter((a) => riskOf(a).risk_band === 'high').length,
        exceptions_active: accepted.filter((a) => a.exception.until >= t).length, exceptions_expired: accepted.filter((a) => a.exception.until < t).length, exceptions_waiting: acts.filter((a) => a.state === 'exception_requested').length },
      sites: siteRows, by_month: [...months.values()].sort((a, b) => a.month.localeCompare(b.month)).map((e) => ({ month: e.month, inspections: e.n, average: Math.round(10 * e.sum / e.n) / 10 })),
      top_failures: [...fails.values()].sort((a, b) => b.count - a.count).slice(0, 10).map((e) => ({ template: e.template, item: e.item, text: e.text, count: e.count, sites: e.sites.size })), repeats: repeats.slice(0, 50),
      can_work: ['operator', 'admin'].includes(who.role), can_archive: who.role === 'admin', ai: aiStatus(), site_options: sites(), types: TYPES, evidence_rules: EVID };
    if (res.can_work) {
      res.inspections = IN().all().sort((a, b) => String(b.submitted_at || b.started_at).localeCompare(String(a.submitted_at || a.started_at))).slice(0, 200).map((x) => ({ id: x.id, template: x.template, site: x.site, inspector: x.inspector, state: x.state, score: x.score == null ? null : x.score, result: x.result || null, started_at: x.started_at, submitted_at: x.submitted_at || null, critical_failed: !!x.critical_failed, reviewed_by: x.review ? x.review.by : null, open_actions: open.filter((a) => a.inspection === x.id).length }));
      res.actions = open.map(riskOf).sort((a, b) => b.risk - a.risk || a.due.localeCompare(b.due)).slice(0, 200).map((a) => Object.assign({}, a, { overdue: a.due < t && a.state !== 'exception_requested', exception_expired: a.state === 'accepted' && a.exception.until < t }));
      res.schedules = due;
      res.templates = templates().map((x) => ({ id: x.id, name: x.name, category: x.category, version: x.version, status: x.status, pass_mark: x.pass_mark, items: x.sections.reduce((a, y) => a + y.items.length, 0), builtin: !!x.builtin }));
    }
    return res;
  }
  if (!(app.noTimers || opts.noTimer)) { const tm = setInterval(guardOf(app, 'inspect.overdue', () => { const t = day(now()), n = AC().all((a) => a.state !== 'verified' && a.due < t).length; if (n) L.every('inspect:overdue', 6 * 3600000, 'info', 'IT Audit Inspections: corrective actions past their due date', { overdue: n }); }), 3600000); if (tm.unref) tm.unref(); }
  return { view, templates, template, createTemplate, updateTemplate, archiveTemplate, createSchedule, deleteSchedule, startInspection, inspection, answers, evidence, evidenceFile, submit, review, editAction, fixAction, verifyAction, requestException, decideException, aiDraft, aiStatus, report, scoreOf };
}

function registerAuditInspect(srv, app, X0) {
  const X = X0 && X0.view ? X0 : createAuditInspect(app, X0 || {});
  app.addons = app.addons || {}; app.addons.auditInspect = X;
  const ID = (re, what) => (ctx) => { const v = param(ctx.params.id, 'id'); if (!re.test(v)) throw httpErr(400, 'id is not ' + what); return v; };
  const TID = ID(/^tpl-[a-z0-9]{2,20}$/, 'a template id'), IID = ID(/^ins-[0-9a-f]{10}$/, 'an inspection id'), AID = ID(/^act-[0-9a-f]{10}$/, 'an action id'), SID = ID(/^sch-[0-9a-f]{10}$/, 'a schedule id');
  const big = { maxBody: 5 * 1024 * 1024 }, sig = { maxBody: 1024 * 1024 };
  srv.route('GET', '/inspect', (ctx) => { ctx.need('viewer'); return X.view(ctx.who); });
  srv.route('GET', '/inspect/templates', (ctx) => { ctx.need('operator'); return { templates: X.templates() }; });
  srv.route('GET', '/inspect/templates/:id', (ctx) => { ctx.need('operator'); return X.template(TID(ctx)); });
  srv.route('POST', '/inspect/templates', (ctx) => { ctx.need('operator'); return X.createTemplate(ctx.body, ctx.who); }, { maxBody: 262144 });
  srv.route('PUT', '/inspect/templates/:id', (ctx) => { ctx.need('operator'); return X.updateTemplate(TID(ctx), ctx.body, ctx.who); }, { maxBody: 262144 });
  srv.route('POST', '/inspect/templates/:id/archive', (ctx) => { ctx.need('admin'); return X.archiveTemplate(TID(ctx), ctx.who); });
  srv.route('POST', '/inspect/schedules', (ctx) => { ctx.need('operator'); return X.createSchedule(ctx.body, ctx.who); });
  srv.route('POST', '/inspect/schedules/:id/delete', (ctx) => { ctx.need('operator'); return X.deleteSchedule(SID(ctx), ctx.who); });
  srv.route('POST', '/inspect/inspections', (ctx) => { ctx.need('operator'); return X.startInspection(ctx.body, ctx.who); });
  srv.route('GET', '/inspect/inspections/:id', (ctx) => { ctx.need('operator'); return X.inspection(IID(ctx)); });
  srv.route('POST', '/inspect/inspections/:id/answers', (ctx) => { ctx.need('operator'); return X.answers(IID(ctx), ctx.body, ctx.who); }, { maxBody: 262144 });
  srv.route('POST', '/inspect/inspections/:id/evidence', (ctx) => { ctx.need('operator'); return X.evidence(IID(ctx), ctx.body, ctx.who); }, big);
  srv.route('GET', '/inspect/evidence/:id', (ctx) => { ctx.need('operator'); const v = param(ctx.params.id, 'id'); const f = X.evidenceFile(v);
    ctx.raw(200, { 'Content-Type': 'image/' + f.kind, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox", 'Cache-Control': 'private, max-age=3600' }, f.buf); });
  srv.route('POST', '/inspect/inspections/:id/submit', (ctx) => { ctx.need('operator'); return X.submit(IID(ctx), ctx.body, ctx.who); }, sig);
  srv.route('POST', '/inspect/inspections/:id/review', (ctx) => { ctx.need('operator'); return X.review(IID(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/inspect/actions/:id', (ctx) => { ctx.need('operator'); return X.editAction(AID(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/inspect/actions/:id/fix', (ctx) => { ctx.need('operator'); return X.fixAction(AID(ctx), ctx.body, ctx.who); }, big);
  srv.route('POST', '/inspect/actions/:id/verify', (ctx) => { ctx.need('operator'); return X.verifyAction(AID(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/inspect/actions/:id/exception', (ctx) => { ctx.need('operator'); return X.requestException(AID(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/inspect/actions/:id/exception/decide', (ctx) => { ctx.need('admin'); return X.decideException(AID(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/inspect/templates/ai-draft', (ctx) => { ctx.need('operator'); return X.aiDraft(ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('GET', '/inspect/inspections/:id/report', (ctx) => { ctx.need('operator'); return X.report(IID(ctx), ctx.who); });
  return X;
}

module.exports = { createAuditInspect, registerAuditInspect, STARTER };
