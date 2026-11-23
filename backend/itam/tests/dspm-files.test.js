// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// DSPM sensitive files, label policies and breach analysis (engine/dspm-files.js) over a SYNTHETIC Data Security Posture context:
// file items with format / system / elements / owner; the risk itemised with the toxic combination; violations and clusters; the built-in
// label policies (lowest priority wins, conflicts named, Copilot exclusion); policies written by an admin person with a reason, versioned,
// validated, audited; label logs on change; stats and learned suggestions; breach radius with obligations, tier and the DPO's cost basis;
// what-if ranking; roles (viewer refused, operator reads, admin writes, service identity refused).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const DF = require('../engine/dspm-files');

const NOW = Date.parse('2026-11-19T08:00:00Z');
const KIND_LABEL = { national_id: 'National ID', iban: 'IBAN / bank account', email: 'E-mail address', health: 'Health / diagnosis', password: 'Password in text', name: 'Person name' };
function ctx() {
  const hr = { id: 'm365:hr', type: 'sharepoint', label: 'HR Site', files_seen: 4000 }, fin = { id: 'm365:fin', type: 'sharepoint', label: 'Finance', files_seen: 6000 }, od = { id: 'm365:od1', type: 'onedrive', label: 'Nora Syn', files_seen: 500 }, fs = { id: 'fs:srv1:d', type: 'fileshare', label: '\\\\srv1\\data', files_seen: 1500 };
  const rows = [
    { store: hr, name: 'employees-iqama.xlsx', path: '/HR', kinds: ['national_id', 'email'], shared: 'anonymous', modified: '2026-10-01' },
    { store: hr, name: 'Board minutes 2026.docx', path: '/HR', kinds: ['name'], shared: 'none', modified: '2026-10-01' },
    { store: fin, name: 'vendors.csv', path: '/Fin', kinds: ['iban'], shared: 'external', modified: '2020-01-01' },
    { store: od, name: 'my-passwords.txt', path: '/', kinds: ['password'], shared: 'organization', modified: '2026-11-01' },
    { store: fs, name: 'medical.pdf', path: 'd\\x', kinds: ['health', 'national_id'], shared: 'everyone', modified: '2026-09-01' }];
  for (let i = 0; i < 6; i++) rows.push({ store: fs, name: 'contacts' + i + '.csv', path: 'd\\c', kinds: ['email'], shared: 'none', modified: '2026-09-01' });
  return { src: { m365_files: { measured: true } }, rows, stores: [hr, fin, od, fs], cloudStores: [{ id: 'cloud:aws:b1', raw_id: 'b1', type: 'cloud:aws', label: 'exports-bucket', public: true, in_kingdom: false, objects_scanned: 300 }],
    cloudObjects: [{ store_id: 'b1', key: 'dump/customers.sql', kinds: ['national_id', 'iban'], modified: '2026-08-01' }] };
}
const P = { KIND_LABEL, build: async () => ({ C: ctx() }) };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };

test('files: format, system, owner, risk itemised, toxic combinations, violations, clusters, KPIs', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const X = DF.registerDspmFiles(e.app.srv, e.app, P, { now: () => NOW });
  const v = await X.filesView({}, OP), by = (n) => v.files.find((f) => f.name === n);
  assert.equal(v.kpis.files, 4000 + 6000 + 500 + 1500 + 300); assert.equal(v.kpis.sensitive, 12);
  const iq = by('employees-iqama.xlsx'); assert.equal(iq.format, 'Excel'); assert.equal(iq.system, 'SharePoint'); assert.deepEqual(iq.elements, ['National ID', 'E-mail address']);
  assert.equal(iq.label, 'Restricted'); assert.equal(iq.toxic, true); assert.match(iq.violation, /Restricted data reachable by anyone with the link/); assert.ok(iq.risk_items.some((i) => /TOXIC/.test(i.label)));
  assert.equal(v.files[0].name, 'customers.sql', 'public bucket abroad with ID and IBAN is the riskiest'); assert.equal(v.files[0].system, 'AWS S3');
  assert.equal(by('my-passwords.txt').owner, 'Nora Syn'); assert.match(by('my-passwords.txt').violation, /a secret shared with the whole organisation/);
  assert.equal(by('Board minutes 2026.docx').label, 'Highly Confidential', 'the name policy');
  assert.ok(v.clusters.length >= 3 && v.clusters.every((c) => /one fix/.test(c.why)));
  assert.ok(v.kpis.violations >= 4); assert.equal(v.kpis.unlabelled, 0);
  const vio = await X.filesView({ filter: 'violations' }, OP); assert.ok(vio.files.every((f) => f.violation));
  assert.ok(e.app.store.auditTail(20).some((a) => a.action === 'dspm.files.read' && a.by === 'nora.syn'));
  let r = await e.req('GET', '/data-posture/files', VW); assert.equal(r.status, 403);
  r = await e.req('GET', '/data-posture/files?filter=bogus', OP); assert.equal(r.status, 400); assert.match(r.json.error, /filter/);
});

test('label policies: priority, conflicts, Copilot exclusion, writes by an admin person, logs, stats and learned suggestions', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const X = DF.registerDspmFiles(e.app.srv, e.app, P, { now: () => NOW });
  let L = await X.labelsView(OP);
  assert.equal(L.policies.length, 4); assert.ok(L.stats.find((s) => s.id === 'lp-restricted').files >= 3); assert.ok(L.stats.find((s) => s.id === 'lp-restricted').copilot_excluded >= 3);
  assert.ok(L.suggestions.length === 0, 'contacts are labelled Internal by the built-in policy');
  const log1 = X.labelLog({}); assert.ok(log1.total >= 12, 'first evaluation logs every label'); assert.ok(log1.items.some((x) => x.to === 'Restricted' && x.policy));
  let r = await e.req('POST', '/data-posture/label-policies', Object.assign({ body: { name: 'HR is Highly Confidential', label: 'Highly Confidential', location_contains: 'HR', exclude_copilot: true, priority: 5, reason: 'DPO decision' } }, OP)); assert.equal(r.status, 403, 'an operator does not write policies');
  r = await e.req('POST', '/data-posture/label-policies', Object.assign({ body: { name: 'nothing', label: 'Internal', reason: 'x test' } }, ADM)); assert.equal(r.status, 400); assert.match(r.json.error, /at least one condition/);
  r = await e.req('POST', '/data-posture/label-policies', Object.assign({ body: { name: 'HR is Highly Confidential', label: 'Top Secret', location_contains: 'HR', reason: 'DPO decision' } }, ADM)); assert.equal(r.status, 400); assert.match(r.json.error, /label/);
  await assert.rejects(Promise.resolve().then(() => X.savePolicy({ name: 'x policy', label: 'Internal', location_contains: 'HR', reason: 'by a bot' }, { user: 'svc:bot', role: 'admin' })), /a person/);
  r = await e.req('POST', '/data-posture/label-policies', Object.assign({ body: { name: 'HR is Highly Confidential', label: 'Highly Confidential', location_contains: 'HR', exclude_copilot: true, priority: 5, reason: 'DPO decision' } }, ADM)); assert.equal(r.status, 200, r.text);
  const id = r.json.id;
  const v = await X.filesView({}, OP), iq = v.files.find((f) => f.name === 'employees-iqama.xlsx');
  assert.equal(iq.label, 'Highly Confidential', 'priority 5 wins over the built-in Restricted (10)'); assert.equal(iq.conflict, true);
  const log2 = X.labelLog({}); assert.ok(log2.items.some((x) => x.file === 'employees-iqama.xlsx' && x.from === 'Restricted' && x.to === 'Highly Confidential' && x.policy === 'HR is Highly Confidential'));
  r = await e.req('POST', '/data-posture/label-policies', Object.assign({ body: { id, base_version: 9, name: 'HR is Highly Confidential', label: 'Restricted', location_contains: 'HR', reason: 'change' } }, ADM)); assert.equal(r.status, 409);
  r = await e.req('POST', '/data-posture/label-policies/' + id + '/delete', Object.assign({ body: { reason: 'superseded' } }, ADM)); assert.equal(r.status, 200);
  assert.ok(['dspm.label.policy.create', 'dspm.label.policy.delete'].every((a) => e.app.store.auditTail(50).some((x) => x.action === a && x.by === 'syed')));
  // a cluster no policy labels becomes a suggestion
  r = await e.req('POST', '/data-posture/label-policies/lp-internal/delete', Object.assign({ body: { reason: 'test the learning' } }, ADM)); assert.equal(r.status, 200);
  L = await X.labelsView(OP); const sg = L.suggestions.find((s) => /E-mail address in \\\\srv1\\data/.test(s.name)); assert.ok(sg, JSON.stringify(L.suggestions)); assert.equal(sg.files, 6); assert.equal(sg.label, 'Internal');
});

test('breach analysis: radius, who could reach it, obligations with deadlines, tier, the DPO cost basis, what-if; roles', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const X = DF.registerDspmFiles(e.app.srv, e.app, P, { now: () => NOW });
  let r = await e.req('POST', '/data-posture/breach', Object.assign({ body: { scope_type: 'store', scope: 'm365:hr' } }, OP)); assert.equal(r.status, 200, r.text);
  const b = r.json; assert.equal(b.files, 2); assert.equal(b.tier, 'High'); assert.ok(b.reasons.some((x) => /identity, financial or health/.test(x)));
  assert.ok(b.regulations.includes('PDPL')); assert.ok(b.obligations.some((o) => /SDAIA/.test(o.who) && /72 hours/.test(o.when))); assert.equal(b.estimate.sar, null); assert.match(b.estimate.basis, /set a cost per affected file/);
  assert.equal(b.reachable_by['anyone with the link'], 1);
  r = await e.req('POST', '/data-posture/breach', Object.assign({ body: { scope_type: 'element', scope: 'iban' } }, OP)); assert.ok(r.json.obligations.some((o) => /SAMA/.test(o.who))); assert.equal(r.json.abroad, 1);
  r = await e.req('POST', '/data-posture/breach/settings', Object.assign({ body: { cost_per_file_sar: 500, reason: 'board-approved planning figure' } }, OP)); assert.equal(r.status, 403);
  r = await e.req('POST', '/data-posture/breach/settings', Object.assign({ body: { cost_per_file_sar: 500, reason: 'board-approved planning figure' } }, ADM)); assert.equal(r.status, 200);
  r = await e.req('POST', '/data-posture/breach', Object.assign({ body: { scope_type: 'store', scope: 'm365:hr' } }, OP)); assert.equal(r.json.estimate.sar, 1000); assert.match(r.json.estimate.basis, /an indication, not a valuation/);
  r = await e.req('POST', '/data-posture/breach', Object.assign({ body: { scope_type: 'store', scope: 'nowhere' } }, OP)); assert.equal(r.status, 404);
  r = await e.req('POST', '/data-posture/breach', Object.assign({ body: { scope_type: 'planet', scope: 'x' } }, OP)); assert.equal(r.status, 400);
  r = await e.req('POST', '/data-posture/breach', Object.assign({ body: { scope_type: 'store', scope: 'm365:hr' } }, VW)); assert.equal(r.status, 403);
  const w = await X.whatIf(OP); assert.equal(w.stores[0].tier, 'High'); assert.ok(w.stores.length >= 4);
  assert.ok(e.app.store.auditTail(30).some((a) => a.action === 'dspm.breach.analyse' && a.by === 'nora.syn'));
});
