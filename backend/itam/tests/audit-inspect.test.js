// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IT Audit Inspections (engine/audit-inspect.js) through the real routes on SYNTHETIC records: starter templates, a custom template
// validated field by field, running an inspection (answers per type, n/a, location), photo evidence checked by its bytes, submit
// rules (unanswered, required evidence, signatures), weighted scoring with a critical failure, corrective actions per failed item,
// four-eyes review and verification, closure with a frozen hashed report, schedules moving their due date, analytics (site trend,
// repeat failures), roles (viewer counts only, operator works, admin archives) and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, INS = { user: 'nora.syn', role: 'operator' }, REV = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const T0 = Date.parse('2026-11-08T08:00:00Z'), DAY = 86400000;
// a real 1x1 PNG and a real tiny JPEG header (synthetic)
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const JPG = 'data:image/jpeg;base64,' + Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 16, 0x4a, 0x46, 0x49, 0x46, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0xff, 0xd9]).toString('base64');

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let now = T0; const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'insp-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => now, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }), inspectDir: dir, inspSdk: o.sdk, inspKey: () => (o.sdk ? 'sk-ant-synthetic' : '') });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call, dir, setNow: (x) => { now = x; } };
}
// a small custom template: one critical yes/no, one rating, one number with a range, one text
const TPL = { name: 'Server room quick check (synthetic)', category: 'Physical', pass_mark: 80, sections: [
  { id: 's1', title: 'Access', items: [{ id: 'door', text: 'Door locked', type: 'yesno', weight: 3, critical: true, evidence: 'on_fail' }, { id: 'clean', text: 'Housekeeping', type: 'rating', weight: 1, evidence: 'none' }] },
  { id: 's2', title: 'Environment', items: [{ id: 'temp', text: 'Temperature', type: 'number', min: 18, max: 27, weight: 2, evidence: 'required' }, { id: 'obs', text: 'Observations', type: 'text', evidence: 'none' }] }] };

async function runOne(call, tplId, site, ans, opts = {}) {
  const ins = (await call('POST', '/inspect/inspections', { template_id: tplId, site }, INS)).json.inspection;
  assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/answers', { answers: ans, location: { lat: 24.7136, lon: 46.6753, accuracy: 12 } }, INS)).status, 200);
  for (const it of opts.photos || []) assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/evidence', { item: it, image: JPG, taken_at: '2026-11-08T07:55:00Z', lat: 24.71, lon: 46.67 }, INS)).status, 200);
  const r = await call('POST', '/inspect/inspections/' + ins.id + '/submit', { inspector_signature: PNG, auditee_name: 'Site Manager (synthetic)', auditee_role: 'IT supervisor', auditee_signature: PNG }, INS);
  assert.equal(r.status, 200, r.text); return r.json.inspection;
}

test('templates: five starters, a custom one validated field by field, versions, archive admin-only', async (t) => {
  const { call } = await setup(t);
  const L = (await call('GET', '/inspect/templates', undefined, INS)).json.templates; assert.equal(L.length, 8); assert.ok(L.some((x) => x.id === 'tpl-dc'));
  for (const k of ['tpl-claims', 'tpl-tpa', 'tpl-pdpl-branch']) assert.ok(L.some((x) => x.id === k), 'insurer template ' + k);
  assert.equal((await call('GET', '/inspect/templates', undefined, VIEW)).status, 403);
  let r = await call('POST', '/inspect/templates', { name: 'x', sections: [] }, INS); assert.equal(r.status, 400); assert.match(r.text, /sections/);
  r = await call('POST', '/inspect/templates', { name: 'x', sections: [{ title: 'a', items: [{ text: 'b', type: 'colour' }] }] }, INS); assert.equal(r.status, 400); assert.match(r.text, /type/);
  r = await call('POST', '/inspect/templates', { name: 'x', sections: [{ title: 'a', items: [{ id: 'k', text: 'b' }, { id: 'k', text: 'c' }] }] }, INS); assert.equal(r.status, 400); assert.match(r.text, /used twice/);
  r = await call('POST', '/inspect/templates', { name: 'x', sections: [{ title: 'a', items: [{ text: 'b', type: 'number', min: 9, max: 3 }] }] }, INS); assert.equal(r.status, 400); assert.match(r.text, /min/);
  r = await call('POST', '/inspect/templates', TPL, INS); assert.equal(r.status, 200, r.text); const id = r.json.template.id;
  r = await call('PUT', '/inspect/templates/' + id, { pass_mark: 85 }, INS); assert.equal(r.json.template.version, 2);
  assert.equal((await call('POST', '/inspect/templates/' + id + '/archive', undefined, INS)).status, 403);
  assert.equal((await call('POST', '/inspect/templates/' + id + '/archive', undefined, ADM)).status, 200);
  assert.equal((await call('POST', '/inspect/inspections', { template_id: id, site: 'HQ' }, INS)).status, 409, 'an archived template cannot be used');
});

test('inspection: answers per type, evidence by bytes, submit rules, weighted score, critical failure, actions', async (t) => {
  const { call, e } = await setup(t);
  const tpl = (await call('POST', '/inspect/templates', TPL, INS)).json.template.id;
  const ins = (await call('POST', '/inspect/inspections', { template_id: tpl, site: 'HQ-SYN' }, INS)).json.inspection;
  assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/answers', { answers: [{ item: 'door', value: 'maybe' }] }, INS)).status, 400);
  assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/answers', { answers: [{ item: 'clean', value: 7 }] }, INS)).status, 400);
  assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/answers', { answers: [{ item: 'nope', value: 'yes' }] }, INS)).status, 400);
  assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/answers', { answers: [{ item: 'door', value: 'yes' }] }, REV)).status, 403, 'only the inspector answers');
  assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/answers', { answers: [{ item: 'door', value: 'no', note: 'propped open (synthetic)' }, { item: 'clean', value: 4 }, { item: 'temp', value: 31 }, { item: 'obs', value: 'cables tidy' }] }, INS)).status, 200);
  // a note saved on its own keeps the answer (regression: a note-only save used to wipe it)
  await call('POST', '/inspect/inspections/' + ins.id + '/answers', { answers: [{ item: 'door', note: 'still propped open (synthetic)' }] }, INS);
  const kept = (await call('GET', '/inspect/inspections/' + ins.id, undefined, INS)).json.answers.door; assert.equal(kept.value, 'no'); assert.equal(kept.note, 'still propped open (synthetic)');
  let r = await call('POST', '/inspect/inspections/' + ins.id + '/submit', { inspector_signature: PNG, auditee_name: 'X', auditee_signature: PNG }, INS);
  assert.equal(r.status, 400); assert.match(r.text, /evidence/, 'the failed door and the temperature need photos');
  assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/evidence', { item: 'door', image: 'data:image/png;base64,' + Buffer.from('<svg onload=alert(1)>').toString('base64') }, INS)).status, 400, 'a file that is not an image is refused by its bytes');
  for (const it of ['door', 'temp']) assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/evidence', { item: it, image: JPG, taken_at: '2026-11-08T07:55:00Z', lat: 24.7, lon: 46.6 }, INS)).status, 200);
  r = await call('POST', '/inspect/inspections/' + ins.id + '/submit', { inspector_signature: JPG, auditee_name: 'X', auditee_signature: PNG }, INS); assert.equal(r.status, 400); assert.match(r.text, /inspector_signature/);
  r = await call('POST', '/inspect/inspections/' + ins.id + '/submit', { inspector_signature: PNG, auditee_name: 'Site Manager (synthetic)', auditee_signature: PNG }, INS); assert.equal(r.status, 200, r.text);
  const s = r.json.inspection;
  // weights: door 3 (0), clean 1 ((4-1)/4 = .75), temp 2 (0, out of range); text not scored -> 0.75 / 6 = 12.5 %
  assert.equal(s.score, 12.5); assert.equal(s.result, 'fail'); assert.equal(s.critical_failed, true); assert.equal(s.state, 'actions_open');
  assert.deepEqual(s.actions.map((a) => [a.item, a.severity]).sort(), [['door', 'critical'], ['temp', 'major']]);
  assert.equal(s.actions.find((a) => a.item === 'door').due, '2026-11-15', 'critical: 7 days');
  const sha = s.answers.door.evidence[0]; const img = await call('GET', '/inspect/evidence/' + sha, undefined, INS); assert.equal(img.status, 200);
  assert.equal((await call('GET', '/inspect/evidence/' + sha, undefined, VIEW)).status, 403, 'a viewer never sees photos');
  assert.ok(e.app.store.auditTail(30).some((x) => x.action === 'inspect.submit' && x.by === 'nora.syn'));
});

test('four eyes: a different person reviews and verifies; the inspection closes with a frozen, hashed report', async (t) => {
  const { call, e } = await setup(t);
  const tpl = (await call('POST', '/inspect/templates', TPL, INS)).json.template.id;
  const s = await runOne(call, tpl, 'HQ-SYN', [{ item: 'door', value: 'yes' }, { item: 'clean', value: 5 }, { item: 'temp', value: 30 }, { item: 'obs', na: true }], { photos: ['temp'] });
  assert.equal(s.result, 'fail', '4/6 = 66.7 % under the 80 % pass mark'); assert.equal(s.score, 66.7);
  assert.equal((await call('POST', '/inspect/inspections/' + s.id + '/review', { decision: 'approve' }, INS)).status, 403, 'the inspector does not review');
  assert.equal((await call('POST', '/inspect/inspections/' + s.id + '/review', { decision: 'return' }, REV)).status, 400, 'return needs a note');
  assert.equal((await call('POST', '/inspect/inspections/' + s.id + '/review', { decision: 'approve' }, REV)).status, 200);
  const act = s.actions[0];
  assert.equal((await call('POST', '/inspect/actions/' + act.id, { assignee: 'facilities.syn', due: '2026-11-20' }, INS)).status, 200);
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/fix', { note: 'x' }, REV)).status, 403, 'assigned to someone else');
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/fix', {}, ADM)).status, 400, 'a fix needs a note');
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/fix', { note: 'CRAC unit serviced (synthetic)', evidence: JPG }, ADM)).status, 200);
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/verify', { decision: 'verify' }, ADM)).status, 403, 'the fixer does not verify');
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/verify', { decision: 'reopen' }, REV)).status, 400, 'reopen needs a note');
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/verify', { decision: 'verify', note: 'checked on site' }, REV)).status, 200);
  const done = (await call('GET', '/inspect/inspections/' + s.id, undefined, INS)).json;
  assert.equal(done.state, 'closed'); assert.match(done.report_hash, /^[0-9a-f]{64}$/);
  const rep = (await call('GET', '/inspect/inspections/' + s.id + '/report', undefined, INS)).json;
  assert.match(rep.html, /Site Manager \(synthetic\)/); assert.match(rep.html, /66\.7%/); assert.equal(rep.hash, done.report_hash);
  const a = e.app.store.auditTail(60).map((x) => x.action); for (const k of ['inspect.review', 'inspect.action.fix', 'inspect.action.verify', 'inspect.report']) assert.ok(a.includes(k), k);
});

test('schedules move their due date; analytics: site trend, repeat failures; viewer counts only', async (t) => {
  const { call, setNow } = await setup(t);
  const tpl = (await call('POST', '/inspect/templates', TPL, INS)).json.template.id;
  assert.equal((await call('POST', '/inspect/schedules', { template_id: tpl, site: 'BR-SYN', every_days: 3 }, INS)).status, 400, 'every_days at least 7');
  const sch = (await call('POST', '/inspect/schedules', { template_id: tpl, site: 'BR-SYN', every_days: 30, next_due: '2026-11-01' }, INS)).json.schedule;
  let v = (await call('GET', '/inspect', undefined, INS)).json; assert.equal(v.schedules[0].status, 'overdue'); assert.equal(v.kpis.overdue_schedules, 1);
  const good = [{ item: 'door', value: 'yes' }, { item: 'clean', value: 5 }, { item: 'temp', value: 22 }, { item: 'obs', na: true }];
  const bad = [{ item: 'door', value: 'yes' }, { item: 'clean', value: 1 }, { item: 'temp', value: 22 }, { item: 'obs', na: true }];
  const ins = (await call('POST', '/inspect/inspections', { template_id: tpl, site: 'BR-SYN', schedule_id: sch.id }, INS)).json.inspection;
  await call('POST', '/inspect/inspections/' + ins.id + '/answers', { answers: bad }, INS);
  await call('POST', '/inspect/inspections/' + ins.id + '/evidence', { item: 'temp', image: JPG }, INS);
  await call('POST', '/inspect/inspections/' + ins.id + '/evidence', { item: 'clean', image: JPG }, INS);
  assert.equal((await call('POST', '/inspect/inspections/' + ins.id + '/submit', { inspector_signature: PNG, auditee_name: 'A', auditee_signature: PNG }, INS)).status, 200);
  v = (await call('GET', '/inspect', undefined, INS)).json; assert.equal(v.schedules[0].next_due, '2026-12-08', 'the schedule moved 30 days on');
  setNow(T0 + DAY); await runOne(call, tpl, 'BR-SYN', bad, { photos: ['temp'] });
  v = (await call('GET', '/inspect', undefined, INS)).json;
  assert.ok(v.repeats.some((x) => x.item === 'clean'), 'housekeeping failed in two consecutive inspections at the same site');
  setNow(T0 + 2 * DAY); await runOne(call, tpl, 'BR-SYN', good, { photos: ['temp'] });
  v = (await call('GET', '/inspect', undefined, INS)).json;
  assert.ok(!v.repeats.some((x) => x.item === 'clean'), 'the repeat clears once the item passes');
  const site = v.sites.find((x) => x.site === 'BR-SYN'); assert.equal(site.inspections, 3); assert.ok(site.trend_per_inspection > 0, 'improving'); assert.ok(site.forecast_next != null);
  assert.ok(v.top_failures.some((x) => x.item === 'clean' && x.count === 2));
  const vv = (await call('GET', '/inspect', undefined, VIEW)).json; assert.equal(vv.inspections, undefined); assert.equal(vv.actions, undefined); assert.ok(vv.sites.length);
});

test('risk on actions; exceptions: a reason and an expiry, a DIFFERENT admin decides, lapses on its date; Arabic text in the report', async (t) => {
  const { call, e, setNow } = await setup(t);
  const tpl = (await call('POST', '/inspect/templates', Object.assign({}, TPL, { sections: [{ id: 's1', title: 'Access', title_ar: 'الوصول', items: [{ id: 'door', text: 'Door locked', text_ar: 'الباب مقفل', type: 'yesno', critical: true, evidence: 'none' }] }] }), INS)).json.template.id;
  const s = await runOne(call, tpl, 'HQ-SYN', [{ item: 'door', value: 'no' }]);
  const act = s.actions[0]; assert.equal(act.risk, 20); assert.equal(act.risk_band, 'high', 'critical starts at 4 x 5');
  let r = await call('POST', '/inspect/actions/' + act.id, { likelihood: 2, impact: 3 }, INS); assert.equal(r.json.action.risk, 6); assert.equal(r.json.action.risk_band, 'low');
  assert.equal((await call('POST', '/inspect/actions/' + act.id, { likelihood: 9 }, INS)).status, 400);
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/exception', { reason: 'door replacement ordered (synthetic)', until: '2028-01-01' }, INS)).status, 400, 'at most 12 months');
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/exception', { until: '2026-12-31' }, INS)).status, 400, 'a reason is required');
  r = await call('POST', '/inspect/actions/' + act.id + '/exception', { reason: 'door replacement ordered (synthetic)', until: '2026-12-31', compensating: 'guard posted' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.action.state, 'exception_requested');
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/exception/decide', { decision: 'approve' }, INS)).status, 403, 'an operator does not accept risk');
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/exception/decide', { decision: 'approve' }, ADM)).status, 403, 'the requester does not accept their own risk');
  assert.equal((await call('POST', '/inspect/actions/' + act.id + '/exception/decide', { decision: 'approve' }, { user: 'head.audit.syn', role: 'admin' })).status, 200);
  await call('POST', '/inspect/inspections/' + s.id + '/review', { decision: 'approve' }, REV);
  assert.equal((await call('GET', '/inspect/inspections/' + s.id, undefined, INS)).json.state, 'closed', 'an accepted risk resolves the action until its date');
  let v = (await call('GET', '/inspect', undefined, INS)).json; assert.equal(v.kpis.exceptions_active, 1);
  setNow(Date.parse('2027-01-02T08:00:00Z')); v = (await call('GET', '/inspect', undefined, INS)).json; assert.equal(v.kpis.exceptions_expired, 1); assert.ok(v.actions.some((a) => a.id === act.id && a.exception_expired), 'lapsed: open again');
  const rep = (await call('GET', '/inspect/inspections/' + s.id + '/report', undefined, INS)).json; assert.match(rep.html, /الباب مقفل/); assert.match(rep.html, /risk accepted until 2026-12-31/);
  const a = e.app.store.auditTail(40).map((x) => x.action); for (const k of ['inspect.action.exception.request', 'inspect.action.exception.approve']) assert.ok(a.includes(k), k);
});

test('AI drafts a checklist a person saves; validated; nothing saved; refused when AI is off and for a viewer', async (t) => {
  let script; const seen = [];
  class Fake { constructor() { this.messages = { create: async (req) => { seen.push(JSON.parse(JSON.stringify(req))); return script(); } }; } }
  const { call, e } = await setup(t, { sdk: Fake });
  assert.equal((await call('POST', '/inspect/templates/ai-draft', { request: 'claims system access review at the Jeddah branch' }, INS)).status, 424, 'AI off until allowed');
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  script = () => ({ model: 'claude-opus-5-5', stop_reason: 'tool_use', usage: {}, content: [{ type: 'tool_use', id: 'a', name: 'draft_template', input: { name: 'Claims access - Jeddah (synthetic)', category: 'Insurance operations', pass_mark: 90, sections: [{ title: 'Access', title_ar: 'الوصول', items: [{ text: 'Every claims user has an approved request', text_ar: 'لكل مستخدم طلب معتمد', type: 'yesno', critical: true, evidence: 'required', ref: 'SAMA CSF 3.3.5' }] }] } }] });
  assert.equal((await call('POST', '/inspect/templates/ai-draft', { request: 'claims access' }, VIEW)).status, 403);
  assert.equal((await call('POST', '/inspect/templates/ai-draft', { request: 'short' }, INS)).status, 400);
  const before = e.app.store.collection('insp_templates').all().length;
  let r = await call('POST', '/inspect/templates/ai-draft', { request: 'claims system access review at the Jeddah branch', arabic: true }, INS); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.draft.sections[0].items[0].text_ar, 'لكل مستخدم طلب معتمد'); assert.equal(e.app.store.collection('insp_templates').all().length, before, 'nothing saved');
  assert.deepEqual(seen[0].tools.map((x) => x.name), ['draft_template']); assert.match(seen[0].system, /insurance/i);
  r = await call('POST', '/inspect/templates', r.json.draft, INS); assert.equal(r.status, 200, 'a person saves the draft as a template');
  script = () => ({ stop_reason: 'tool_use', usage: {}, content: [{ type: 'tool_use', id: 'b', name: 'draft_template', input: { name: 'x', sections: [{ title: 'a', items: [{ text: 'b', type: 'shell_command' }] }] } }] });
  assert.equal((await call('POST', '/inspect/templates/ai-draft', { request: 'claims system access review at the Jeddah branch' }, INS)).status, 422, 'a draft that does not fit a checklist is refused');
});
