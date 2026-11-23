// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * Implementation Roadmap ({P} = /api/itam; Data Privacy -> PDPL Implementation Roadmap, NDMO Implementation Roadmap): how the
 * organisation implements PDPL and the NDMO standards from the first day to "compliant and kept compliant", in order, over the modules
 * the platform already has. Each framework is a list of phases and tasks; each task names the article / domain it serves, the
 * page that does the work, the tasks it waits for, and - where the platform holds the records - a measured status read from those
 * records (the DPO profile, records of processing, impact assessments, processors, transfers, retention, training, the signed
 * statement, the NDMO profile, the official control list and its mapping, the confirmations and their approvals).
 *   measured   the module's own records decide done / in progress / not started; a person cannot overrule them - a task a person
 *              marks done while the records show nothing reads "claimed - the records do not show it yet"
 *   manual     a task the platform cannot measure (a decision, a meeting, an annual review) is set by a person with evidence
 *   plan       owner, due date and evidence per task (operator, audited); target date (admin, audited)
 *   ML         progress; a daily snapshot (impl_roadmap_hist, 'impl.snapshot' job) gives the completion velocity over the last 4 weeks
 *              and the forecast finish date against the target - withheld below 2 weeks of snapshots or with no task finished;
 *              blocked tasks (waiting for others), next best actions (unblocked; overdue first, then the earliest phase, then the most tasks waiting on them), the
 *              critical path (the longest chain still open) and overdue tasks
 *   GET  /impl/:fw                       viewer    phases, tasks with status and evidence, plan, forecast, next actions
 *   POST /impl/:fw/task/:id              operator  {status?, owner?, due?, evidence?, note?}  a person, audited
 *   POST /impl/:fw/target                admin     {target, start?}                            audited
 * Nothing here changes a register: the work is done on the module's own page; this tracks and measures it.
 */
const DAY = 86400000, FW = ['pdpl', 'ndmo', 'iso', 'nca', 'sama'], MANUAL = ['done', 'in_progress', 'not_started', 'not_applicable'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

function createImplRoadmap(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const col = (n) => { try { return store.collection(n); } catch (e) { return null; /* a module that is not installed has no collection */ } };
  const all = (n, f) => { const c = col(n); return c ? c.all(f || (() => true)) : []; };
  const get = (n, id) => { const c = col(n); return c ? c.get(id) : null; };
  const rec = (kind) => all('pdpl_records', (r) => r.kind === kind && !r.archived);
  const plan = () => store.collection('impl_roadmap'), hist = () => store.collection('impl_roadmap_hist');
  const iso = (t) => new Date(t == null ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'impl.' + action, target, detail }); };
  const n = (L) => L.length, has = (v) => v !== undefined && v !== null && v !== '' && v !== false;
  const done = (ok, ev) => ({ v: ok ? 1 : 0, ev });
  const part = (k, of, ev) => ({ v: of ? Math.min(1, k / of) : 0, ev });

  // ---- the tasks: [id, phase, title, ref, page, deps, measure() -> {v 0..1, ev} | null (a person decides)]
  const P = () => get('pdpl_records', 'profile') || {};
  const PDPL = [
    ['p-dpo', 'Mobilise', 'Appoint the Data Protection Officer', 'Implementing Regulation Art. 32', 'pdpl-governance.html', [], () => done(has(P().dpo_user) || has(P().dpo_appointed), has(P().dpo_user) ? 'DPO named: ' + P().dpo_user : 'no DPO named in the PDPL profile')],
    ['p-sdaia', 'Mobilise', 'Register with SDAIA (national register of controllers)', 'PDPL Art. 33 · SDAIA register', 'pdpl-governance.html', ['p-dpo'], () => done(has(P().sdaia_registered) || has(P().sdaia_ref), has(P().sdaia_ref) ? 'SDAIA reference ' + P().sdaia_ref : 'no SDAIA registration recorded')],
    ['p-gov', 'Mobilise', 'Privacy committee and data stewards in place', 'PDPL Art. 30 (accountability)', 'pdpl-programme.html', ['p-dpo'], () => { const c = n(rec('committee_meeting')), s = n(rec('steward')); return { v: (c ? 0.5 : 0) + (s ? 0.5 : 0), ev: c + ' committee meeting(s), ' + s + ' steward(s) recorded' }; }],
    ['p-policy', 'Mobilise', 'Approve the privacy policy and publish the privacy notice', 'PDPL Art. 12-13 · IR Art. 4', 'pdpl-policies.html', ['p-dpo'], () => done(has(P().privacy_policy_published), has(P().privacy_policy_url) ? 'published at ' + P().privacy_policy_url : 'privacy policy not recorded as published')],
    ['p-disc', 'Discover', 'Discover personal data in the systems', 'PDPL Art. 11 (minimum data)', 'pdpl-intel.html', [], () => { const d = n(all('pdpl_discovery')); return done(d > 0, d + ' database scan(s) recorded'); }],
    ['p-cat', 'Discover', 'Catalogue personal-data identifiers', 'PDPL Art. 11 · NDMO Data Catalog', 'pdpl-catalog.html', ['p-disc'], () => { const d = n(all('pdpl_identifiers')); return done(d > 0, d + ' identifier(s) catalogued'); }],
    ['p-ropa', 'Discover', 'Record every processing activity (RoPA)', 'Implementing Regulation Art. 33', 'pdpl-ropa.html', ['p-disc'], () => { const r = n(rec('ropa')), d = n(all('pdpl_discovery')); return part(r, Math.max(1, Math.min(d || 1, 5)), r + ' processing activit' + (r === 1 ? 'y' : 'ies') + ' recorded' + (d ? ' for ' + d + ' scanned system(s)' : '')); }],
    ['p-sens', 'Discover', 'Identify sensitive data and its controls', 'PDPL Art. 1, 23-24 · IR Art. 26-27', 'pdpl-sensitive.html', ['p-ropa'], () => { const s = n(rec('sensitive_control')); return done(s > 0, s + ' sensitive-data control(s) recorded'); }],
    ['p-proc', 'Discover', 'List processors and their contracts', 'PDPL Art. 8 · IR Art. 17', 'pdpl-processors.html', ['p-ropa'], () => { const p = n(rec('processor')); return done(p > 0, p + ' processor(s) recorded'); }],
    ['p-xfer', 'Discover', 'Map personal data sent outside the Kingdom', 'PDPL Art. 29 · Transfer Regulation', 'pdpl-transfers.html', ['p-ropa'], () => { const t = n(rec('transfer')); return t ? done(true, t + ' transfer(s) recorded') : null; }],
    ['p-gap', 'Assess', 'Run the PDPL self-assessment', 'PDPL Art. 19-22', 'pdpl-assessment.html', ['p-ropa'], () => { const a = n(all('pdpl_assessments')); return done(a > 0, a + ' self-assessment(s)'); }],
    ['p-dpia', 'Assess', 'Impact assessments for high-risk processing, signed by the DPO', 'PDPL Art. 22 · IR Art. 25', 'pdpl-dpia.html', ['p-sens'], () => { const L = rec('dpia'), c = L.filter((d) => d.completed).length; return L.length ? part(c, L.length, c + ' of ' + L.length + ' impact assessment(s) signed') : done(false, 'no impact assessment started'); }],
    ['p-vendor', 'Assess', 'Assess each processor', 'Implementing Regulation Art. 17', 'pdpl-processors.html', ['p-proc'], () => { const v = n(all('pdpl_vendor_assessments')), p = n(rec('processor')); return p ? part(v, p, v + ' of ' + p + ' processor(s) assessed') : done(false, 'no processor recorded yet'); }],
    ['p-xra', 'Assess', 'Transfer risk assessment for each transfer', 'Transfer Regulation Art. 8', 'pdpl-transfers.html', ['p-xfer'], () => { const L = rec('transfer'); if (!L.length) return null; const k = L.filter((t) => has(t.risk_assessment) || has(t.safeguard) || has(t.basis)).length; return part(k, L.length, k + ' of ' + L.length + ' transfer(s) with a basis / safeguard recorded'); }],
    ['p-consent', 'Implement', 'Consent purposes, records and withdrawal', 'PDPL Art. 5-6 · IR Art. 11-12', 'pdpl-studio.html', ['p-ropa'], () => { const c = n(rec('consent_purpose')) + n(all('pdpl_consent_meta')); return done(c > 0, c + ' consent purpose / record source(s)'); }],
    ['p-dsr', 'Implement', 'Data subject requests answered within 30 days', 'PDPL Art. 4 · IR Art. 3-10', 'pdpl-dsar.html', ['p-dpo'], () => { const L = rec('dsr'), intake = n(all('pdpl_intake_meta')); if (!L.length && !intake) return done(false, 'no request channel or request recorded'); const late = L.filter((d) => !d.closed && d.received && now() - Date.parse(d.received) > 30 * DAY).length; return { v: late ? 0.5 : 1, ev: L.length + ' request(s) recorded' + (late ? ', ' + late + ' open past 30 days' : '') + (intake ? ' · intake channel connected' : '') }; }],
    ['p-ret', 'Implement', 'Retention schedule and secure destruction', 'PDPL Art. 18 · IR Art. 19', 'pdpl-retention.html', ['p-ropa'], () => { const r = n(rec('retention')), d = rec('destruction').filter((x) => x.status === 'executed').length; return { v: (r ? 0.6 : 0) + (d ? 0.4 : 0), ev: r + ' retention rule(s), ' + d + ' destruction(s) executed' }; }],
    ['p-breach', 'Implement', 'Breach procedure: SDAIA within 72 hours', 'PDPL Art. 20 · IR Art. 24', 'pdpl-breach.html', ['p-dpo'], () => { const pb = n(rec('playbook')), b = rec('breach'); return pb ? done(true, pb + ' playbook(s)' + (b.length ? ', ' + b.length + ' breach record(s)' : '')) : done(false, 'no breach playbook recorded'); }],
    ['p-access', 'Implement', 'Access to personal data reviewed', 'PDPL Art. 19 · IR Art. 23', 'pdpl-access.html', ['p-ropa'], () => { const r = n(all('pdpl_access_rev')); return done(r > 0, r + ' access review(s)'); }],
    ['p-train', 'Train', 'Train staff and the data stewards', 'PDPL Art. 30', 'pdpl-programme.html', ['p-gov'], () => { const t = n(rec('training')); return done(t > 0, t + ' training record(s)'); }],
    ['p-monitor', 'Operate', 'Continuous control monitoring and Privacy Office tasks', 'PDPL Art. 19', 'pdpl-monitor.html', ['p-gap'], () => { const t = n(all('pdpl_office_tasks')); return done(t > 0, t + ' Privacy Office task(s) raised by monitoring'); }],
    ['p-pbd', 'Operate', 'Privacy by design reviews for new systems', 'PDPL Art. 19 · IR Art. 25', 'pdpl-programme.html', ['p-dpia'], () => { const r = n(rec('pbd_review')); return done(r > 0, r + ' privacy-by-design review(s)'); }],
    ['p-acc', 'Operate', 'Accountability evidence kept up to date', 'PDPL Art. 30', 'pdpl-programme.html', ['p-gov'], () => { const r = n(rec('accountability')); return done(r > 0, r + ' accountability record(s)'); }],
    ['p-review', 'Assure', 'Management reviews the programme', 'PDPL Art. 30', 'pdpl-programme.html', ['p-train'], () => { const r = n(rec('programme_review')); return done(r > 0, r + ' programme review(s)'); }],
    ['p-stmt', 'Assure', 'DPO signs the compliance statement, management countersigns', 'Self-assessment (not an SDAIA certificate)', 'pdpl-dashboard.html', ['p-review', 'p-monitor'], () => { const s = get('pdpl_statement', 'statement'); return !s ? done(false, 'not signed') : s.status === 'attested' ? done(true, 'attested' + (s.valid_until ? ' until ' + String(s.valid_until).slice(0, 10) : '')) : { v: 0.5, ev: 'signed by the DPO, waiting for the management countersignature' }; }],
  ];
  const NP = () => get('ndmo_profile', 'profile') || {};
  const NDMO = [
    ['n-cdo', 'Mobilise', 'Appoint the Chief Data Officer', 'NDMO Data Governance', 'ndmo.html', [], () => done(has(NP().cdo_user), has(NP().cdo_user) ? 'CDO: ' + NP().cdo_user : 'no Chief Data Officer in the NDMO profile')],
    ['n-dmo', 'Mobilise', 'Establish the Data Management Office', 'NDMO Data Governance', 'ndmo.html', ['n-cdo'], () => done(has(NP().dmo_established), has(NP().dmo_established) ? 'established ' + NP().dmo_established : 'not recorded')],
    ['n-strat', 'Mobilise', 'Approve the data management strategy', 'NDMO Data Governance', 'ndmo.html', ['n-dmo'], () => done(has(NP().strategy_approved), has(NP().strategy_approved) ? 'approved ' + NP().strategy_approved : 'not recorded')],
    ['n-comm', 'Mobilise', 'Data governance committee meets', 'NDMO Data Governance', 'ndmo.html', ['n-cdo'], () => { const t = Date.parse(NP().committee_last_met || ''); return !isFinite(t) ? done(false, 'no meeting recorded') : now() - t <= 120 * DAY ? done(true, 'last met ' + NP().committee_last_met) : { v: 0.5, ev: 'last met ' + NP().committee_last_met + ' - more than 120 days ago' }; }],
    ['n-appl', 'Mobilise', 'Decide which domains apply (Open Data, Freedom of Information)', 'NDMO applicability', 'ndmo.html', ['n-cdo'], () => { const a = NP().applicability || {}; const k = Object.keys(a).length; return done(k > 0, k ? Object.keys(a).map((x) => x + ': ' + a[x]).join(', ') : 'applicability not decided'); }],
    ['n-off', 'Discover', 'Import the official NDMO control list', 'NDMO standards', 'ndmo.html', ['n-cdo'], () => { const o = n(all('ndmo_official')); return done(o > 0, o + ' official control(s) imported'); }],
    ['n-map', 'Discover', 'Map each official control to a register control', 'NDMO standards', 'ndmo.html', ['n-off'], () => { const o = n(all('ndmo_official')), m = n(all('ndmo_mapping')); return o ? part(m, o, m + ' of ' + o + ' official control(s) mapped') : done(false, 'import the official list first'); }],
    ['n-cat', 'Discover', 'Data catalogue of systems and personal data', 'NDMO Data Catalog & Metadata', 'pdpl-catalog.html', [], () => { const i = n(all('pdpl_identifiers')), d = n(all('pdpl_discovery')); return { v: (d ? 0.5 : 0) + (i ? 0.5 : 0), ev: d + ' system scan(s), ' + i + ' identifier(s) catalogued' }; }],
    ['n-class', 'Discover', 'Classify data (top secret / secret / restricted / public)', 'NDMO Data Classification', 'inventory.html', ['n-cat'], () => { const A = all('assets', (a) => !['retired', 'disposed'].includes(a.status) && ['server', 'vm', 'database', 'storage'].includes(a.type)); if (!A.length) return null; const k = A.filter((a) => has(a.classification)).length; return part(k, A.length, k + ' of ' + A.length + ' servers / databases classified in the asset register'); }],
    ['n-record', 'Assess', 'Record every control with its evidence', 'NDMO standards', 'ndmo.html', ['n-map'], () => { const c = n(all('ndmo_confirm')), m = n(all('ndmo_mapping')) || n(all('ndmo_official')); return m ? part(c, m, c + ' control(s) recorded of ' + m) : (c ? done(true, c + ' control(s) recorded') : done(false, 'no control recorded')); }],
    ['n-approve', 'Assess', 'A second person approves each recorded control', 'NDMO standards (four eyes)', 'ndmo.html', ['n-record'], () => { const L = all('ndmo_confirm'), a = L.filter((c) => c.decision === 'approve' || c.approved_by || c.state === 'approved').length; return L.length ? part(a, L.length, a + ' of ' + L.length + ' recorded control(s) approved') : done(false, 'nothing recorded yet'); }],
    ['n-pdpl', 'Implement', 'Personal Data Protection domain - the PDPL programme', 'NDMO PDP domain = PDPL', 'pdpl-roadmap.html', ['n-cat'], () => { const r = n(rec('ropa')), s = get('pdpl_statement', 'statement'); return s && s.status === 'attested' ? done(true, 'PDPL statement attested') : { v: r ? 0.5 : 0, ev: r ? r + ' processing activities; the PDPL statement is not attested yet' : 'no processing activity recorded' }; }],
    ['n-life', 'Implement', 'Data lifecycle: retention and destruction', 'NDMO Data Lifecycle', 'pdpl-retention.html', ['n-cat'], () => { const r = n(rec('retention')); return done(r > 0, r + ' retention rule(s)'); }],
    ['n-quality', 'Implement', 'Data quality rules and checks', 'NDMO Data Quality', 'ndmo.html', ['n-cat'], () => null],
    ['n-gaps', 'Operate', 'Every gap becomes a tracked GRC action', 'NDMO standards', 'ndmo.html', ['n-approve'], () => { const g = all('grc_drafts', (d) => /ndmo/i.test(String(d.source || d.origin || d.id || ''))).length; return done(g > 0, g + ' GRC action(s) raised from NDMO gaps'); }],
    ['n-review', 'Assure', 'Annual NDMO compliance review with the CDO', 'NDMO standards', 'ndmo.html', ['n-gaps'], () => null],
  ];
  // ---- shared measures for the three security frameworks: a register entry counts in full only once a second person approved it
  const dateOk = (v, maxDays) => { const t = Date.parse(v || ''); return isFinite(t) && (!maxDays || now() - t <= maxDays * DAY); };
  const approvedOf = (L) => L.filter((c) => c.approved_by).length;
  const confScore = (c) => !c ? 0 : (c.status === 'compliant' || c.status === 'not_applicable') ? (c.approved_by ? 1 : 0.7) : c.status === 'partial' ? 0.5 : 0.2;
  const clauses = (ids) => { const L = ids.map((i) => get('iso_confirm', i)); const k = L.filter(Boolean).length; return { v: L.reduce((a, c) => a + confScore(c), 0) / ids.length, ev: k ? ids.map((i, j) => i + ': ' + (L[j] ? L[j].status + (L[j].approved_by ? ' (approved)' : ' (awaiting a second person)') : 'not recorded')).join(', ') : 'clause ' + ids.join(', ') + ' not recorded in the ISO register' }; };
  const risks = () => all('grc_risks', (r) => r.status !== 'closed' && r.status !== 'retired');
  const actionsFor = (fw) => all('grc_actions', (a) => a.framework === fw);
  const actMeasure = (fw) => { const L = actionsFor(fw), c = L.filter((a) => a.status === 'closed' || a.status === 'done').length; return L.length ? part(c, L.length, c + ' of ' + L.length + ' ' + fw + ' GRC action(s) closed') : null; };
  const drill = () => { const L = all('grc_drills', (d) => d.status === 'completed'); const last = L.map((d) => d.executed).filter((d) => isFinite(Date.parse(d || ''))).sort().pop(); return last ? (dateOk(last, 366) ? done(true, 'last drill completed ' + last) : { v: 0.5, ev: 'last drill ' + last + ' - more than a year ago' }) : done(false, 'no completed DR / BCM drill recorded'); };
  const assetsOwned = () => { const A = all('assets', (a) => !['retired', 'disposed'].includes(a.status)); if (!A.length) return done(false, 'the asset register is empty'); const k = A.filter((a) => has(a.owner) || has(a.assigned_to)).length; return part(k, A.length, k + ' of ' + A.length + ' asset(s) with an owner'); };
  const committee = (v) => !dateOk(v) ? done(false, 'no meeting recorded') : dateOk(v, 120) ? done(true, 'last met ' + v) : { v: 0.5, ev: 'last met ' + v + ' - more than 120 days ago' };
  const fields = (o, ks, label) => { const k = ks.filter((x) => has(o[x])).length; return part(k, ks.length, k === ks.length ? ks.map((x) => label[x] + ' ' + o[x]).join(' · ') : 'missing: ' + ks.filter((x) => !has(o[x])).map((x) => label[x]).join(', ')); };

  const IP = () => get('iso_profile', 'profile') || {};
  const EP = () => get('ecc_profile', 'profile') || {};
  const SP = () => get('sama_profile', 'profile') || {};
  const ISO = [
    ['i-lead', 'Mobilise', 'Top management commits and names the ISMS manager', 'ISO 27001 cl. 5.1, 5.3', 'iso27001.html', [], () => fields(IP(), ['top_management', 'isms_manager'], { top_management: 'top management:', isms_manager: 'ISMS manager:' })],
    ['i-ctx', 'Mobilise', 'Context and interested parties reviewed', 'cl. 4.1, 4.2', 'iso27001.html', ['i-lead'], () => fields(IP(), ['context_reviewed', 'parties_reviewed'], { context_reviewed: 'context reviewed', parties_reviewed: 'parties reviewed' })],
    ['i-scope', 'Mobilise', 'ISMS scope written and approved', 'cl. 4.3', 'iso27001.html', ['i-ctx'], () => { const p = IP(); return has(p.scope_approved) ? done(true, 'scope approved ' + p.scope_approved) : { v: has(p.scope) ? 0.5 : 0, ev: has(p.scope) ? 'scope written, not approved' : 'no scope statement' }; }],
    ['i-pol', 'Mobilise', 'Information security policy approved', 'cl. 5.2 · A.5.1', 'iso27001.html', ['i-lead'], () => clauses(['5.2', 'A.5.1'])],
    ['i-method', 'Discover', 'Risk assessment method approved', 'cl. 6.1.2', 'iso27001.html', ['i-scope'], () => done(has(IP().risk_method_approved), has(IP().risk_method_approved) ? 'approved ' + IP().risk_method_approved : 'not recorded')],
    ['i-assets', 'Discover', 'Information assets have owners', 'A.5.9', 'inventory.html', ['i-scope'], assetsOwned],
    ['i-risk', 'Assess', 'Risks assessed, each with an owner', 'cl. 6.1.2, 8.2', 'grc-register.html', ['i-method'], () => { const L = risks(); if (!L.length) return done(false, 'no risk in the register'); const k = L.filter((r) => has(r.owner)).length; return part(k, L.length, k + ' of ' + L.length + ' open risk(s) with an owner'); }],
    ['i-treat', 'Assess', 'Risk treatment plan', 'cl. 6.1.3, 8.3', 'grc-register.html', ['i-risk'], () => { const L = risks(); if (!L.length) return done(false, 'no risk to treat yet'); const k = L.filter((r) => has(r.treatment)).length; return part(k, L.length, k + ' of ' + L.length + ' risk(s) with a treatment decision'); }],
    ['i-soa', 'Assess', 'Statement of Applicability approved', 'cl. 6.1.3 d', 'iso27001.html', ['i-treat'], () => { const s = get('iso_soa', 'current'); return !s ? done(false, 'no SoA proposed') : s.approved_by ? done(true, 'version ' + s.version + ' approved by ' + s.approved_by) : { v: 0.5, ev: 'version ' + s.version + ' proposed, awaiting approval' }; }],
    ['i-obj', 'Implement', 'Security objectives with a measure and a target', 'cl. 6.2', 'iso27001.html', ['i-pol'], () => { const L = IP().objectives || []; if (!L.length) return done(false, 'no objective recorded'); const k = L.filter((o) => has(o.measure) && has(o.target)).length; return part(k, L.length, k + ' of ' + L.length + ' objective(s) with measure and target'); }],
    ['i-annex', 'Implement', 'Record the 93 Annex A controls with evidence', 'Annex A (A.5-A.8)', 'iso27001.html', ['i-soa'], () => { const L = all('iso_confirm', (c) => /^A\./.test(c.id)); return part(L.length, 93, L.length + ' of 93 Annex A control(s) recorded'); }],
    ['i-appr', 'Implement', 'A second person approves each recorded control', 'four eyes', 'iso27001.html', ['i-annex'], () => { const L = all('iso_confirm'); return L.length ? part(approvedOf(L), L.length, approvedOf(L) + ' of ' + L.length + ' recorded entr(ies) approved') : done(false, 'nothing recorded yet'); }],
    ['i-aware', 'Train', 'Competence and awareness', 'cl. 7.2, 7.3 · A.6.3', 'iso27001.html', ['i-pol'], () => clauses(['7.2', '7.3', 'A.6.3'])],
    ['i-ops', 'Operate', 'Operate the controls and the treatment plan', 'cl. 8.1', 'iso27001.html', ['i-appr'], () => clauses(['8.1'])],
    ['i-mon', 'Operate', 'Measure the objectives', 'cl. 9.1', 'iso27001.html', ['i-obj'], () => { const L = IP().objectives || []; if (!L.length) return done(false, 'no objective to measure'); const k = L.filter((o) => has(o.current) && dateOk(o.measured_on, 100)).length; return part(k, L.length, k + ' of ' + L.length + ' objective(s) measured in the last 100 days'); }],
    ['i-audit', 'Assure', 'Internal audit programme carried out', 'cl. 9.2', 'iso27001.html', ['i-ops'], () => { const L = all('iso_audits'); if (!L.length) return done(false, 'no audit programme planned'); const k = L.filter((a) => a.status === 'accepted').length; return part(k, L.length, k + ' of ' + L.length + ' planned audit(s) accepted'); }],
    ['i-nc', 'Assure', 'Nonconformities corrected and verified', 'cl. 10.2', 'iso27001.html', ['i-audit'], () => { const L = all('iso_ncs'); if (!L.length) return all('iso_audits', (a) => a.status === 'accepted').length ? done(true, 'no nonconformity raised by accepted audits') : null; const k = L.filter((x) => x.status === 'closed').length; return part(k, L.length, k + ' of ' + L.length + ' nonconformit(ies) closed as effective'); }],
    ['i-mr', 'Assure', 'Management review held', 'cl. 9.3', 'iso27001.html', ['i-audit'], () => { const L = all('iso_reviews', (r) => r.status === 'held').map((r) => r.held_on).filter(Boolean).sort(); const last = L.pop(); return !last ? done(false, 'no management review recorded') : dateOk(last, 366) ? done(true, 'last held ' + last) : { v: 0.5, ev: 'last held ' + last + ' - more than a year ago' }; }],
    ['i-cert', 'Assure', 'Certification audit: Stage 1 then Stage 2', 'ISO/IEC 17021 certification', 'iso-lifecycle.html', ['i-mr', 'i-nc'], () => { const L = all('iso_lc_cert'); const s2 = L.find((e) => ['stage2', 'recertification'].includes(e.event) && ['recommended', 'minor'].includes(e.result)); return s2 ? done(true, s2.event + ' ' + s2.result + ' (' + s2.date + ', ' + s2.body + ')') : L.some((e) => e.event === 'stage1') ? { v: 0.5, ev: 'Stage 1 recorded; no recommended Stage 2 yet' } : done(false, 'no certification audit recorded'); }],
  ];

  const eccConf = () => all('ecc_confirm');
  const NCA = [
    ['e-head', 'Mobilise', 'Appoint the head of cybersecurity (Saudi, full time)', 'ECC 1-2-1', 'nca-ecc.html', [], () => done(has(EP().ciso_user), has(EP().ciso_user) ? 'head of cybersecurity: ' + EP().ciso_user : 'no head of cybersecurity in the ECC profile')],
    ['e-func', 'Mobilise', 'Cybersecurity function independent of IT', 'ECC 1-2-1, 1-2-2', 'nca-ecc.html', ['e-head'], () => fields(EP(), ['function_established', 'reports_to'], { function_established: 'established', reports_to: 'reports to' })],
    ['e-strat', 'Mobilise', 'Cybersecurity strategy approved', 'ECC 1-1', 'nca-ecc.html', ['e-func'], () => done(has(EP().strategy_approved), has(EP().strategy_approved) ? 'approved ' + EP().strategy_approved : 'not recorded')],
    ['e-comm', 'Mobilise', 'Cybersecurity steering committee meets', 'ECC 1-2-3', 'nca-ecc.html', ['e-head'], () => committee(EP().committee_last_met)],
    ['e-appl', 'Mobilise', 'Decide whether Third-Party/Cloud (4-2) and ICS (5-1) apply', 'ECC 4-2, 5-1', 'nca-ecc.html', ['e-head'], () => { const a = EP().applicability || {}; const k = ['4-2', '5-1'].filter((x) => has(a[x])).length; return part(k, 2, k ? Object.keys(a).map((x) => x + ': ' + a[x]).join(', ') : 'applicability not decided'); }],
    ['e-off', 'Discover', 'Import the official ECC-2:2024 control list', 'ECC-2:2024', 'nca-ecc.html', ['e-head'], () => { const o = n(all('ecc_official')); return done(o > 0, o + ' official control(s) imported'); }],
    ['e-map', 'Discover', 'Map each official control to a register control', 'ECC-2:2024', 'nca-ecc.html', ['e-off'], () => { const o = n(all('ecc_official')), m = n(all('ecc_mapping')); return o ? part(m, o, m + ' of ' + o + ' official control(s) mapped') : done(false, 'import the official list first'); }],
    ['e-assets', 'Discover', 'Asset inventory with owners', 'ECC 2-1', 'inventory.html', [], assetsOwned],
    ['e-risk', 'Assess', 'Cybersecurity risks assessed', 'ECC 1-5', 'grc-register.html', ['e-strat'], () => { const L = risks(); return done(L.length > 0, L.length + ' open risk(s) in the register'); }],
    ['e-record', 'Assess', 'Record every control with its evidence', 'ECC-2:2024', 'nca-ecc.html', ['e-map'], () => { const c = n(eccConf()), m = n(all('ecc_mapping')); return m ? part(c, m, c + ' control(s) recorded of ' + m + ' mapped') : done(c > 0, c + ' control(s) recorded'); }],
    ['e-approve', 'Assess', 'The head of cybersecurity approves each recorded control', 'four eyes', 'nca-ecc.html', ['e-record'], () => { const L = eccConf(); return L.length ? part(approvedOf(L), L.length, approvedOf(L) + ' of ' + L.length + ' recorded control(s) approved') : done(false, 'nothing recorded yet'); }],
    ['e-gaps', 'Implement', 'Every verified gap becomes a GRC action', 'ECC 1-3', 'nca-ecc.html', ['e-approve'], () => { const k = n(actionsFor('NCA ECC')); return done(k > 0, k + ' NCA ECC GRC action(s)'); }],
    ['e-close', 'Implement', 'Close the remediation actions', 'ECC 1-3', 'grc-register.html', ['e-gaps'], () => actMeasure('NCA ECC')],
    ['e-aware', 'Train', 'Cybersecurity awareness programme', 'ECC 1-10', 'nca-ecc.html', ['e-strat'], () => null],
    ['e-bcm', 'Operate', 'Business continuity drill', 'ECC 3-1', 'dr-drills.html', ['e-risk'], drill],
    ['e-review', 'Assure', 'Periodic cybersecurity review and audit', 'ECC 1-8', 'nca-it-audit.html', ['e-close'], () => null],
  ];

  const SAMA = [
    ['s-ciso', 'Mobilise', 'Appoint the CISO', 'SAMA CSF 3.1.2', 'sama-ia.html', [], () => done(has(EP().ciso_user), has(EP().ciso_user) ? 'CISO: ' + EP().ciso_user : 'no CISO in the profile')],
    ['s-comm', 'Mobilise', 'Cyber security committee meets', 'SAMA CSF 3.1.2', 'sama-ia.html', ['s-ciso'], () => committee(EP().committee_last_met)],
    ['s-strat', 'Mobilise', 'Cyber security strategy approved', 'SAMA CSF 3.1.3', 'sama-ia.html', ['s-ciso'], () => done(has(EP().strategy_approved), has(EP().strategy_approved) ? 'approved ' + EP().strategy_approved : 'not recorded')],
    ['s-appl', 'Mobilise', 'Decide whether 3.3.12 and 3.3.13 apply', 'SAMA CSF 3.3.12, 3.3.13', 'sama-ia.html', ['s-ciso'], () => { const a = SP().applicability || {}; const k = ['3.3.12', '3.3.13'].filter((x) => has(a[x])).length; return part(k, 2, k ? Object.keys(a).map((x) => x + ': ' + a[x]).join(', ') : 'applicability not decided'); }],
    ['s-assets', 'Discover', 'Asset management with owners', 'SAMA CSF 3.3.3', 'inventory.html', [], assetsOwned],
    ['s-risk', 'Discover', 'Cyber security risk assessment', 'SAMA CSF 3.2', 'grc-register.html', ['s-strat'], () => { const L = risks(); return done(L.length > 0, L.length + ' open risk(s) in the register'); }],
    ['s-record', 'Assess', 'Record each requirement with its evidence', 'SAMA CSF 3.1-3.4', 'sama-ia.html', ['s-appl'], () => { const c = n(all('sama_confirm')); return done(c > 0, c + ' requirement(s) recorded'); }],
    ['s-approve', 'Assess', 'The CISO approves each recorded requirement', 'four eyes', 'sama-ia.html', ['s-record'], () => { const L = all('sama_confirm'); return L.length ? part(approvedOf(L), L.length, approvedOf(L) + ' of ' + L.length + ' recorded requirement(s) approved') : done(false, 'nothing recorded yet'); }],
    ['s-run', 'Assess', 'Run the maturity self-assessment', 'SAMA CSF maturity model', 'sama-ia.html', ['s-record'], () => { const L = all('sama_runs').sort((a, b) => String(a.id).localeCompare(String(b.id))); const r = L[L.length - 1]; return r ? done(true, 'last run ' + r.id + ' - score ' + r.score) : done(false, 'no assessment run'); }],
    ['s-level3', 'Implement', 'Reach maturity level 3 in every subdomain', 'SAMA CSF target level 3', 'sama-ia.html', ['s-run'], () => { const L = all('sama_runs').sort((a, b) => String(a.id).localeCompare(String(b.id))); const r = L[L.length - 1]; if (!r || typeof r.score !== 'number') return done(false, 'no assessment run'); return { v: Math.max(0, Math.min(1, r.score / 100)), ev: 'score ' + r.score + (r.at_target != null ? ', ' + r.at_target + ' subdomain(s) at level 3' : '') }; }],
    ['s-gaps', 'Implement', 'Every gap becomes a GRC action', 'SAMA CSF', 'sama-ia.html', ['s-run'], () => { const k = n(actionsFor('SAMA CSF')); return done(k > 0, k + ' SAMA CSF GRC action(s)'); }],
    ['s-close', 'Implement', 'Close the remediation actions', 'SAMA CSF', 'grc-register.html', ['s-gaps'], () => actMeasure('SAMA CSF')],
    ['s-aware', 'Train', 'Cyber security awareness programme', 'SAMA CSF 3.1.6', 'sama-ia.html', ['s-strat'], () => null],
    ['s-bcm', 'Operate', 'Business continuity drill', 'SAMA BCM framework', 'dr-drills.html', ['s-risk'], drill],
    ['s-monthly', 'Operate', 'Re-assess at least monthly', 'SAMA CSF 3.1.8', 'sama-ia.html', ['s-run'], () => { const L = all('sama_runs').map((r) => r.id).sort(); const last = L.pop(); return !last ? done(false, 'no assessment run') : dateOk(last, 31) ? done(true, 'last run ' + last) : { v: 0.5, ev: 'last run ' + last + ' - more than a month ago' }; }],
    ['s-audit', 'Assure', 'Independent cyber security audit', 'SAMA CSF 3.1.8', 'sama-it-audit.html', ['s-close'], () => null],
  ];

  const DEF = { pdpl: { name: 'PDPL', owner: 'Data Protection Officer', tasks: PDPL }, ndmo: { name: 'NDMO', owner: 'Chief Data Officer', tasks: NDMO },
    iso: { name: 'ISO/IEC 27001:2022', owner: 'ISMS manager', tasks: ISO }, nca: { name: 'NCA ECC-2:2024', owner: 'Head of cybersecurity', tasks: NCA },
    sama: { name: 'SAMA Cyber Security Framework', owner: 'CISO', tasks: SAMA } };
  const PHASES = ['Mobilise', 'Discover', 'Assess', 'Implement', 'Train', 'Operate', 'Assure'];

  function fwOf(fw0) { const fw = param(fw0, 'fw'); if (!DEF[fw]) throw httpErr(404, 'roadmap ' + fw + ' not found - one of ' + FW.join(', ')); return fw; }
  function state(fw) {
    const D = DEF[fw], pl = plan().get(fw) || { id: fw, tasks: {}, target: null, start: null };
    const tasks = D.tasks.map(([id, phase, title, ref, page, deps, measure]) => {
      let m = null; try { m = measure(); } catch (e) { m = null; /* a module that is not installed: the task is set by a person */ }
      const p = (pl.tasks || {})[id] || {};
      let status, progress, source;
      if (m) { progress = Math.round(m.v * 100); status = m.v >= 1 ? 'done' : m.v > 0 ? 'in_progress' : 'not_started'; source = 'measured'; }
      else { status = p.status || 'not_started'; progress = status === 'done' || status === 'not_applicable' ? 100 : status === 'in_progress' ? 50 : 0; source = 'manual'; }
      const claimed = source === 'measured' && p.status === 'done' && status !== 'done';
      return { id, phase, title, ref, page, deps, status, progress, source, evidence: m ? m.ev : (p.evidence || ''), claimed, owner: p.owner || null, due: p.due || null, note: p.note || '', manual_evidence: p.evidence || '', updated_by: p.by || null, updated_at: p.at || null };
    });
    return { D, pl, tasks };
  }
  // the daily snapshot that the forecast learns from
  function snapshot() {
    const day = iso().slice(0, 10), out = [];
    for (const fw of FW) { const s = state(fw); const rec0 = { id: fw + ':' + day, fw, day, done: s.tasks.filter((t) => t.status === 'done' || t.status === 'not_applicable').map((t) => t.id), progress: Math.round(s.tasks.reduce((a, t) => a + t.progress, 0) / s.tasks.length) }; hist().put(rec0); out.push(rec0); }
    const cut = iso(now() - 400 * DAY).slice(0, 10); for (const r of hist().all()) if (r.day < cut) hist().remove(r.id);
    return out;
  }
  function view(fw0) {
    const fw = fwOf(fw0), s = state(fw), T = s.tasks, byId = {}, t0 = now();
    T.forEach((t) => { byId[t.id] = t; });
    const isDone = (t) => t.status === 'done' || t.status === 'not_applicable';
    T.forEach((t) => { t.blocked_by = t.deps.filter((d) => byId[d] && !isDone(byId[d])); t.overdue = !isDone(t) && t.due && Date.parse(t.due) < t0; });
    // dependants (transitive) - how much work waits on a task
    const kids = {}; T.forEach((t) => t.deps.forEach((d) => { (kids[d] = kids[d] || []).push(t.id); }));
    const reach = (id, seen) => { (kids[id] || []).forEach((k) => { if (!seen[k]) { seen[k] = 1; reach(k, seen); } }); return seen; };
    T.forEach((t) => { t.unlocks = Object.keys(reach(t.id, {})).filter((k) => !isDone(byId[k])).length; });
    // critical path: the longest chain of open tasks
    const memo = {}; const depth = (id) => { if (memo[id] != null) return memo[id]; const t = byId[id]; if (!t || isDone(t)) return (memo[id] = 0); memo[id] = 1 + Math.max(0, ...(kids[id] || []).map(depth)); return memo[id]; };
    let start = null; T.filter((t) => !isDone(t) && !t.blocked_by.length).forEach((t) => { if (!start || depth(t.id) > depth(start.id)) start = t; });
    const path = []; let cur = start; while (cur) { path.push(cur.id); const nx = (kids[cur.id] || []).map((k) => byId[k]).filter((k) => k && !isDone(k)).sort((a, b) => depth(b.id) - depth(a.id))[0]; cur = nx || null; }
    const next = T.filter((t) => !isDone(t) && !t.blocked_by.length).sort((a, b) => (b.overdue - a.overdue) || PHASES.indexOf(a.phase) - PHASES.indexOf(b.phase) || (b.unlocks - a.unlocks)).slice(0, 6).map((t) => ({ id: t.id, title: t.title, page: t.page, unlocks: t.unlocks, overdue: t.overdue, owner: t.owner, why: t.overdue ? 'overdue since ' + t.due : t.unlocks ? t.unlocks + ' task(s) wait for it' : 'nothing waits for it, but it is open' }));
    const progress = Math.round(T.reduce((a, t) => a + t.progress, 0) / T.length), doneN = T.filter(isDone).length;
    // forecast from the snapshots: tasks finished per week over the last 4 weeks
    const H = hist().all((r) => r.fw === fw).sort((a, b) => a.day.localeCompare(b.day)), span = H.length ? (Date.parse(H[H.length - 1].day) - Date.parse(H[0].day)) / DAY : 0;
    let forecast = { finish: null, per_week: null, why: '' };
    if (H.length < 2 || span < 14) forecast.why = 'needs 2 weeks of daily snapshots (' + Math.round(span) + ' day(s) so far)';
    else { const from = H.filter((r) => Date.parse(r.day) >= t0 - 28 * DAY)[0] || H[0], last = H[H.length - 1], weeks = Math.max(1, (Date.parse(last.day) - Date.parse(from.day)) / (7 * DAY)), gained = last.done.length - from.done.length, pw = Math.round(gained / weeks * 10) / 10, left = T.length - doneN;
      forecast = pw > 0 ? { finish: iso(t0 + Math.ceil(left / pw) * 7 * DAY).slice(0, 10), per_week: pw, why: pw + ' task(s) a week over the last ' + Math.round(weeks) + ' week(s); ' + left + ' left' } : { finish: null, per_week: 0, why: 'no task finished in the last 4 weeks - at this pace it never finishes' }; }
    const target = s.pl.target || null, late = target && forecast.finish ? Math.round((Date.parse(forecast.finish) - Date.parse(target)) / DAY) : null;
    const phases = PHASES.filter((ph) => T.some((t) => t.phase === ph)).map((ph) => { const L = T.filter((t) => t.phase === ph); return { phase: ph, tasks: L.length, done: L.filter(isDone).length, progress: Math.round(L.reduce((a, t) => a + t.progress, 0) / L.length) }; });
    return { fw, name: s.D.name, owner_role: s.D.owner, at: iso(t0), progress, done: doneN, total: T.length, measured: T.filter((t) => t.source === 'measured').length, phases, tasks: T,
      next, critical_path: path, overdue: T.filter((t) => t.overdue).map((t) => t.id), blocked: T.filter((t) => !isDone(t) && t.blocked_by.length).length, claimed: T.filter((t) => t.claimed).map((t) => t.id),
      target, start: s.pl.start || null, forecast, late_days: late, history: H.slice(-90).map((r) => ({ day: r.day, progress: r.progress, done: r.done.length })),
      note: 'Measured tasks read the modules\' own records - a person cannot mark them done; the rest is set by a person with evidence. This is an implementation tracker, not a certificate.' };
  }
  function setTask(fw0, id0, input, who) {
    const fw = fwOf(fw0), id = param(id0, 'id');
    if (!DEF[fw].tasks.some((t) => t[0] === id)) throw httpErr(404, 'task ' + id + ' is not on the ' + DEF[fw].name + ' roadmap');
    const b = body(input).oneOf('status', MANUAL).str('owner', { max: 120 }).str('due', { re: /^\d{4}-\d{2}-\d{2}$/, msg: 'due must be a date (YYYY-MM-DD)' }).str('evidence', { max: 1000 }).str('note', { max: 500 })
      .rule((o) => (o.status === 'not_applicable' && !o.note ? 'note is required: say why the task does not apply' : null)).rule((o) => (o.status === 'done' && !o.evidence ? 'evidence is required to mark a task done: where it can be seen' : null)).done();
    if (!Object.keys(b).length) throw httpErr(400, 'nothing to change: status, owner, due, evidence or note');
    if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity does not update the roadmap: a person does');
    const cur = plan().get(fw) || { id: fw, tasks: {}, target: null, start: null }, prev = (cur.tasks || {})[id] || {};
    const next = Object.assign({}, prev, b, { by: who.user, at: iso() });
    cur.tasks = Object.assign({}, cur.tasks, { [id]: next }); if (!cur.start) cur.start = iso().slice(0, 10); plan().put(cur);
    audit(who, 'task', fw + ':' + id, { changed: Object.keys(b), status: b.status || prev.status || null, owner: next.owner || null, due: next.due || null });
    return view(fw);
  }
  function setTarget(fw0, input, who) {
    const fw = fwOf(fw0), b = body(input).str('target', { required: true, re: /^\d{4}-\d{2}-\d{2}$/, msg: 'target must be a date (YYYY-MM-DD)' }).str('start', { re: /^\d{4}-\d{2}-\d{2}$/, msg: 'start must be a date (YYYY-MM-DD)' }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity does not set the target: a person does');
    if (b.start && b.start > b.target) throw httpErr(400, 'start must be before target');
    const cur = plan().get(fw) || { id: fw, tasks: {} }; cur.target = b.target; if (b.start) cur.start = b.start; else if (!cur.start) cur.start = iso().slice(0, 10); plan().put(cur);
    audit(who, 'target', fw, { target: b.target, start: cur.start });
    return view(fw);
  }
  const runSnap = guardOf(app, 'impl.snapshot', () => snapshot());
  if (!(app.noTimers || opts.noTimer)) { let timer = null; const loop = async () => { try { await runSnap(); } finally { timer = setTimeout(loop, 6 * 3600000); if (timer.unref) timer.unref(); } }; timer = setTimeout(loop, 45000); if (timer.unref) timer.unref(); }
  return { view, setTask, setTarget, snapshot };
}

function registerImplRoadmap(srv, app, R0) {
  const R = R0 && R0.view ? R0 : createImplRoadmap(app, R0 || {});
  app.addons = app.addons || {}; app.addons.implRoadmap = R;
  srv.route('GET', '/impl/:fw', (ctx) => { ctx.need('viewer'); return R.view(ctx.params.fw); });
  srv.route('POST', '/impl/:fw/task/:id', (ctx) => { ctx.need('operator'); return R.setTask(ctx.params.fw, ctx.params.id, ctx.body, Object.assign({ ip: ctx.ip }, ctx.who)); }, { maxBody: 8192 });
  srv.route('POST', '/impl/:fw/target', (ctx) => { ctx.need('admin'); return R.setTarget(ctx.params.fw, ctx.body, Object.assign({ ip: ctx.ip }, ctx.who)); }, { maxBody: 2048 });
  return R;
}
module.exports = { createImplRoadmap, registerImplRoadmap };
