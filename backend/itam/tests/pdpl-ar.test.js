// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Arabic for PDPL findings (pyengine/pdpl_ar.py): a synthetic register raises a wide spread of real findings through the real
// routes; every Privacy Office task must come back with an Arabic title and recommendation (a new finding type without Arabic
// fails here). A sample of every finding type's English title checks the catalogue's patterns. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };

test('every task raised from a wide synthetic register has Arabic', async (t) => {
  const clock = Date.parse('2026-10-20T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY });
  const post = async (p, body, who = ADM) => { const r = await e.req('POST', p, Object.assign({ body }, who)); assert.equal(r.status, 200, p + ' ' + r.raw); return r.json; };
  await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', notify_hours_ia: 24 });
  const a = await post('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', owner: 'Claims', legal_basis: 'legitimate_interest', data_categories: ['identity', 'health'], systems: ['CLAIMS-SQL'] });
  const b = await post('/pdpl/records', { kind: 'ropa', name: 'Premium finance (synthetic)', owner: 'Finance', purpose: 'Instalments', legal_basis: 'consent', data_categories: ['identity', 'credit'], subjects: 'Customers', systems: ['FIN'], retention_months: 60, recipients: ['Bank'], security_measures: 'Access control', reinsurance_outside: true, reviewed: '2024-01-01' });
  await post('/pdpl/records', { kind: 'ropa', name: 'Credit scoring (synthetic)', owner: 'Finance', legal_basis: 'legitimate_interest', data_categories: ['credit'] });
  await post('/pdpl/records', { kind: 'dsr', ref: 'DSR-SYN-1', type: 'access', received: '2026-08-01', extended: true });
  await post('/pdpl/records', { kind: 'breach', ref: 'BR-SYN-1', aware_at: '2026-10-10T08:00', harm_likely: true, subjects_count: 40 });
  await post('/pdpl/records', { kind: 'processor', name: 'Overseas TPA (synthetic)', outside_ksa: true });
  await post('/pdpl/records', { kind: 'processor', name: 'Print house (synthetic)', agreement: '2024-01-01', clauses: ['purpose'], assessed: '2024-01-01' });
  await post('/pdpl/records', { kind: 'transfer', name: 'Cloud backup (synthetic)', country: 'Ireland', ropa_id: a.id });
  await post('/pdpl/records', { kind: 'transfer', name: 'Treaty bordereaux (synthetic)', country: 'Switzerland', basis: 'scc', sensitive: true, large_scale: true, flow_type: 'reinsurance', data_form: 'identified', ropa_id: b.id });
  await post('/pdpl/records', { kind: 'consent_purpose', title: 'Marketing (synthetic)' });
  await post('/pdpl/stewards', { department: 'Claims', user: 'faisal.syn', role: 'data_steward' }, OP);
  await post('/pdpl/ropa/campaigns', { name: 'RoPA 2026 (synthetic)', due: '2026-10-01', departments: ['Claims', 'Legal'] }, OP);
  await post('/pdpl/office/run', {}, OP);
  const tasks = (await e.req('GET', '/pdpl/office', OP)).json.tasks;
  const missing = tasks.filter((x) => !x.title_ar || !x.recommendation_ar).map((x) => x.key + ' | ' + x.title);
  assert.deepEqual(missing, [], 'tasks without Arabic');
  const fam = new Set(tasks.map((x) => x.key.replace(/^f:/, '').replace(/PD-[A-Z_]+-\d+|RC-\d+|DSR-SYN-1|BR-SYN-1/g, '#').split(':').slice(0, 3).join(':')));
  assert.ok(fam.size >= 20, 'a wide spread of finding types was exercised (' + fam.size + ')');
  assert.ok(tasks.some((x) => /^النشاط «Medical claims \(synthetic\)» يستند إلى المصلحة المشروعة لمعالجة بيانات حساسة \(البيانات الصحية\)$/.test(x.title_ar)));
  assert.ok(tasks.some((x) => /^حادثة التسرّب BR-SYN-1: لم تُبلَّغ سدايا/.test(x.title_ar)));
  assert.ok(tasks.some((x) => /^حادثة التسرّب BR-SYN-1: لم يُسجَّل قرار بشأن إبلاغ .*هيئة التأمين/.test(x.title_ar)), 'regulator names translated: ' + tasks.filter((x) => /BR-SYN/.test(x.title)).map((x) => x.title_ar).join(' | '));
  // the consultant's findings, the statement's open items and the duty desk's work items carry the Arabic as well
  const pv = (await e.req('GET', '/pdpl', OP)).json;
  assert.ok(pv.findings.length >= 10, pv.findings.length + ' findings');
  assert.deepEqual(pv.findings.filter((f) => !f.title_ar || !f.recommendation_ar).map((f) => f.key), [], 'consultant findings without Arabic');
  const stv = (await e.req('GET', '/pdpl/statement', OP)).json;
  assert.equal(stv.blockers_ar.length, stv.blockers.length);
  assert.ok(stv.blockers_ar.some((b) => /^ملاحظة (حرجة|عالية|متوسطة|منخفضة) مفتوحة: [\u0600-\u06ff«]/.test(b)), 'open findings named in Arabic: ' + stv.blockers_ar.slice(-3).join(' | '));
  await D.patrol('pdpl');
  const items = D.list({ engineer: 'pdpl', status: 'open', limit: 200 }).items;
  assert.ok(items.length >= 10);
  assert.deepEqual(items.filter((x) => !x.title_ar || !x.recommendation_ar).map((x) => x.key), [], 'duty desk work items without Arabic');
  assert.equal(items.find((x) => x.title_ar).title, pv.findings.find((f) => f.key === items.find((x) => x.title_ar).key).title, 'the English stays as recorded');
  const cal = (await e.req('GET', '/pdpl/office', OP)).json.calendar;
  assert.ok(cal.length && cal.every((x) => x.title_ar), 'recurring duties have Arabic');
  // the page: route map, organisation, routing reasons
  const v = (await e.req('GET', '/pdpl/office', OP)).json, rm = v.roadmap;
  assert.ok(rm.phases.every((p) => p.name_ar && p.goal_ar && p.when_ar && p.resources_ar.length), 'every phase in Arabic');
  assert.ok(rm.steps.every((x) => x.label_ar && x.evidence_ar && x.evidence_ar !== x.evidence), 'every step and its evidence in Arabic: ' + rm.steps.filter((x) => x.evidence_ar === x.evidence).map((x) => x.evidence).join(' | '));
  assert.ok(rm.maintain.every((m) => m.cadence_ar && m.what_ar && m.who_ar) && rm.note_ar);
  assert.equal(v.gaps_ar.length, v.gaps.length); assert.ok(v.gaps_ar.every((g, i) => g !== v.gaps[i]), 'every gap in Arabic');
  assert.ok(v.org.functions.every((f) => f.label_ar));
  assert.ok(v.tasks.every((x) => x.why_ar && (x.why_ar !== x.why || !/[A-Za-z]{5,} of /.test(x.why))), 'routing reasons in Arabic: ' + v.tasks.filter((x) => x.why_ar === x.why).map((x) => x.why).join(' | '));
});

test('the catalogue reads every finding type\'s English title', () => {
  const S = [
    ['P-01:dpo', 'No Data Protection Officer recorded'], ['P-02:register', "Registration on SDAIA's National Data Governance Platform not recorded"], ['P-03:policy', 'Privacy policy not published'],
    ['P-04:ropa:PD-ROPA-001:incomplete', 'Processing activity "A" is incomplete'], ['P-04:ropa:PD-ROPA-001:review', 'Processing activity "A" not reviewed in the last 12 months'],
    ['P-05:basis:PD-ROPA-001:records', '"A" relies on consent with no consent records'], ['P-05:basis:PD-ROPA-001:explicit', '"A" needs explicit consent (health, credit)'],
    ['P-05:basis:PD-ROPA-002:explicit', '"A" needs explicit consent (solely automated decision)'], ['P-06:lia:PD-ROPA-001:sensitive', '"A" uses legitimate interest for sensitive data (health)'],
    ['P-15:lia:PD-ROPA-001:credit', '"A" uses legitimate interest for credit data'], ['P-06:lia:PD-ROPA-001:assessment', '"A" on legitimate interest without a written assessment'],
    ['P-07:dpia:PD-ROPA-001', 'No impact assessment for "A"'], ['P-08:dsr:PD-DSR-001:extension', 'Request R1 extended without notice to the data subject'],
    ['P-08:dsr:PD-DSR-001:late', 'Request R1 (access) open after 45 days'], ['P-09:breach:PD-BREACH-001:sdaia', 'Breach B1: SDAIA not notified (120 h since awareness)'],
    ['P-09:breach:PD-BREACH-002:sdaia', 'Breach B1: SDAIA notified after 80 h'], ['P-09:breach:PD-BREACH-001:subjects', 'Breach B1: data subjects not notified'],
    ['breach:PD-BREACH-001:reg:ia', 'Breach B1: Insurance Authority not notified - its 24-hour deadline has passed'],
    ['breach:PD-BREACH-001:reg:undecided', 'Breach B1: no decision recorded on notifying Saudi Central Bank (SAMA), Council of Health Insurance (CHI)'],
    ['P-10:proc:PD-PROCESSOR-001:agreement', 'Processor P has no written agreement'], ['P-10:proc:PD-PROCESSOR-001:clauses', 'Processor P: agreement lacks duration, audit_right'],
    ['P-10:proc:PD-PROCESSOR-001:assessed', 'Processor P not assessed in the last 12 months'], ['proc:PD-PROCESSOR-001:dd', 'Processor P: due diligence 40%'],
    ['P-11:transfer:unrecorded', 'Data leaves the Kingdom but no transfer is recorded'], ['P-11:transfer:PD-ROPA-001:reinsurance', '"A" is reinsured outside the Kingdom but no reinsurance transfer is recorded for it'],
    ['P-11:transfer:PD-TRANSFER-001:minimise', 'Transfer T sends identified sensitive data to a reinsurer'], ['P-11:transfer:PD-TRANSFER-001:basis', 'Transfer T to Ireland has no basis'],
    ['P-11:transfer:PD-TRANSFER-001:risk', 'Transfer T needs a risk assessment'], ['P-20:withdrawal:PD-ROPA-001', '"A" relies on consent but its withdrawals are not tracked in the consent ledger'],
    ['P-12:retention:hold:PD-LEGAL_HOLD-001:review', 'Legal hold H1 has not been reviewed since 2026-01-01'], ['P-12:retention:PD-ROPA-001:schedule', '"A" has a retention period but no retention rule in the schedule'],
    ['P-12:retention:PD-RETENTION-001:overdue', 'Retention rule "R": no destruction evidenced since 2025-01-01'], ['P-12:retention:PD-DESTRUCTION-001:unapproved', 'Destruction PD-DESTRUCTION-001 executed without an approval'],
    ['P-12:retention:PD-DESTRUCTION-001:stalled', 'Destruction PD-DESTRUCTION-001 approved more than 30 days ago and not recorded as done'], ['P-12:retention:PD-ROPA-001', '"A" has no retention period'],
    ['P-13:security:db-encryption', 'Security measure failing: Database encryption at rest'], ['P-04:disc:mssql|h|1433:unmapped', 'CLAIMS-SQL holds personal data (health, identity) but no processing activity names it'],
    ['P-16:disc:mssql|h|1433:undeclared', 'CLAIMS-SQL: identity data found that its processing activities do not declare'], ['P-07:disc:mssql|h|1433:dpia', 'CLAIMS-SQL: sensitive data (health) with no completed impact assessment'],
    ['P-05:consent:chain', 'The consent ledger fails its integrity check at entry 12'], ['P-05:consent:PD-CONSENT_PURPOSE-001:ropa', 'Consent purpose "M" is not linked to a processing activity'],
    ['P-05:consent:PD-CONSENT_PURPOSE-001:silent', 'No consent has been recorded for "M" - the collecting system is not sending to the ledger yet'],
    ['P-05:consent:PD-CONSENT_PURPOSE-001:stale', '3 consent(s) for "M" were given under an older notice than version 2'], ['P-05:consent:nokey', 'No active consent key: no system can send consents to the ledger'],
    ['sens:PD-ROPA-001', '"A" (health, credit): 3 control(s) missing'], ['ropa:RC-001:claims:late', 'RoPA campaign "C": Claims not approved by 2026-10-01'],
    ['ropa:RC-001:claims:review', 'Claims submitted its RoPA over 7 days ago - waiting for review'], ['ropa:RC-001:legal:steward', 'Legal has no data steward to complete its RoPA'],
    ['files:F1:exposed', 'claims.xlsx (SharePoint) holds National ID, IBAN and is shared by an anonymous link (anyone with the link)'], ['files:exposed:more', '12 more exposed files with personal data'],
    ['access:exc:no_purpose', '2 access exception(s) not reviewed for over 7 days: sensitive record opened with no purpose'], ['access:ind:ali.syn', 'Access pattern to review for ali.syn (2 indicator(s))'],
    ['access:silent:AK-1', 'System "MEDICAL" has sent no access events for over 7 days'], ['access:chain', 'The sensitive-access journal fails its integrity check at entry 7'],
    ['duty:ropa-review:PD-ROPA-001', 'Annual review of "A" (PD-ROPA-001)'], ['duty:access-review:PD-ROPA-001', 'Access review of sensitive data in "A"'], ['duty:committee', 'Privacy committee meeting (quarterly)'],
    ['duty:programme-review', 'Yearly PDPL programme review'], ['duty:training:claims', 'PDPL training for Claims'], ['duty:processor-review:PD-PROCESSOR-001', 'Yearly review of processor "P"'],
  ];
  const code = 'import json,sys\nsys.path.insert(0, sys.argv[1])\nimport pdpl_ar\nprint(json.dumps([pdpl_ar.translate({"key": k, "title": t}) for k, t in json.loads(sys.stdin.read())]))';
  const out = JSON.parse(execFileSync(PY, ['-c', code, path.join(__dirname, '../pyengine')], { input: JSON.stringify(S) }).toString());
  const bad = S.filter((s, i) => !out[i].title_ar || !out[i].recommendation_ar || /[A-Za-z]{4,} (?:has|is|not|was)\b/.test(out[i].title_ar)).map((s) => s[0]);
  assert.deepEqual(bad, [], 'no Arabic (or English sentence left) for');
  const by = Object.fromEntries(S.map((s, i) => [s[0], out[i].title_ar]));
  assert.equal(by['P-08:dsr:PD-DSR-001:late'], 'الطلب R1 (وصول) ما زال مفتوحاً بعد 45 يوماً');
  assert.equal(by['breach:PD-BREACH-001:reg:undecided'], 'حادثة التسرّب B1: لم يُسجَّل قرار بشأن إبلاغ البنك المركزي السعودي (ساما)، مجلس الضمان الصحي');
  assert.equal(by['P-05:basis:PD-ROPA-002:explicit'], 'النشاط «A» يحتاج إلى موافقة صريحة (قرار آلي بالكامل)');
  assert.equal(by['files:F1:exposed'], 'الملف claims.xlsx (SharePoint) يحتوي National ID, IBAN وهو مشارَك برابط مفتوح لأي شخص');
  // an unknown finding is left in English, never guessed
  assert.deepEqual(JSON.parse(execFileSync(PY, ['-c', code, path.join(__dirname, '../pyengine')], { input: JSON.stringify([['P-99:new', 'Something new']]) }).toString()), [{}]);
});

test('findings built in Node.js get their Arabic through pdpl.translate; other engineers\' work items are unchanged', () => {
  const run = (req) => JSON.parse(execFileSync(PY, [path.join(__dirname, '..', 'pyengine', 'run.py')], { input: JSON.stringify(req) }).toString());
  const r = run({ op: 'pdpl.translate', findings: [{ key: 'access:chain', severity: 'critical', title: 'The sensitive-access journal fails its integrity check at entry 7' }, { key: 'x:unknown', severity: 'low', title: 'Something new' }, 'not a finding'] });
  assert.equal(r.findings.length, 2, 'only objects come back');
  assert.match(r.findings[0].title_ar, /^سجل الوصول الحساس لا يجتاز فحص السلامة عند القيد 7$/);
  assert.equal(r.findings[1].title_ar, undefined, 'an unknown finding keeps its English only');
  const { planPatrol } = require('../engine/duty-core');
  const base = { engineer: 'network', engineer_name: 'AI Network Engineer', now: 1, counter: 0, items: [], policy: { reopen_window_days: 7 } };
  const plain = planPatrol(Object.assign({}, base, { findings: [{ key: 'k1', severity: 'high', title: 'Link down' }] }));
  const it = plain.puts[0];
  assert.ok(!('title_ar' in it), 'no Arabic field added where the rules write none');
  const ar = planPatrol(Object.assign({}, base, { findings: [{ key: 'k1', severity: 'high', title: 'Link down', title_ar: 'الرابط متوقف', recommendation_ar: 'افحص الرابط' }] }));
  const it2 = ar.puts[0];
  assert.equal(it2.title_ar, 'الرابط متوقف'); assert.equal(it2.recommendation_ar, 'افحص الرابط');
  // the Python twin (engine/duty_rules.py) answers the same
  for (const inp of [Object.assign({}, base, { findings: [{ key: 'k1', severity: 'high', title: 'Link down' }] }), Object.assign({}, base, { findings: [{ key: 'k1', severity: 'high', title: 'Link down', title_ar: 'الرابط متوقف', recommendation_ar: 'افحص الرابط' }] })]) {
    const py = JSON.parse(execFileSync(PY, ['-I', path.join(__dirname, '..', 'engine', 'duty_rules.py')], { input: JSON.stringify(Object.assign({ op: 'duty.plan' }, inp)) }).toString());
    assert.deepEqual(py, JSON.parse(JSON.stringify(planPatrol(inp))));
  }
});
