// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL Control Monitor (engine/pdpl-monitor.js) through the real routes on SYNTHETIC records: systems from RoPA and discovery,
// exact asset matching (and an ambiguous one), each test with evidence, not measured never counted as a pass, drift between runs,
// a failing test sent to GRC (only failing, never twice), the evidence pack hashed and audited, acknowledgement campaigns (admin /
// DPO only, a person acknowledges for themselves, wrong version, not on the campaign, an AI identity refused), roles throughout.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' };
let T = Date.parse('2026-11-08T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  const C = (n) => e.app.store.collection(n);
  C('assets').put({ id: 'AST-1', name: 'claims-db', hostname: 'claims-db.syn.local', ip: '10.9.0.11', classification: 'restricted', cia: { c: 'high', i: 'high', a: 'high' }, owner: 'dba.syn', eol: '2030-01-01', type: 'server', status: 'active' });
  C('assets').put({ id: 'AST-2', name: 'hr-app', ip: '10.9.0.12', classification: 'internal', cia: { c: 'medium' }, owner: '', eol: '2025-01-01', type: 'server', status: 'active' });
  C('assets').put({ id: 'AST-3', name: 'portal', ip: '10.9.0.13', type: 'server', status: 'active' });
  C('assets').put({ id: 'AST-4', name: 'portal', ip: '10.9.0.14', type: 'server', status: 'active' });
  C('pdpl_records').put({ id: 'profile', kind: 'profile', dpo_user: 'dina.syn' });
  C('pdpl_records').put({ id: 'PD-ROPA-001', kind: 'ropa', name: 'Medical claims (synthetic)', systems: ['claims-db'], data_categories: ['identity', 'health'] });
  C('pdpl_records').put({ id: 'PD-ROPA-002', kind: 'ropa', name: 'HR (synthetic)', systems: ['HR-APP', 'portal'], data_categories: ['identity', 'employment'] });
  C('pdpl_records').put({ id: 'PD-RET-001', kind: 'retention', name: 'Claims 10 years (synthetic)', systems: ['claims-db'] });
  C('pdpl_discovery').put({ id: 'db1', db: 'db1', ok: true, label: '10.9.0.99', host: '10.9.0.99', columns: [{ table: 'T', column: 'NID', category: 'identity', confirmed: true }] });
  const rows = { 'AST-1': { id: 'AST-1', type: 'server', controls: { edr: { state: 'present', why: 'synthetic EDR' }, patch: { state: 'present' }, backup: { state: 'present' }, vuln_scan: { state: 'present' }, siem_logs: { state: 'present' } } },
    'AST-2': { id: 'AST-2', type: 'server', controls: { edr: { state: 'missing', why: 'no EDR in software' }, patch: { state: 'not_checked', why: 'Endpoint Central not connected' }, backup: { state: 'exempt' }, vuln_scan: { state: 'weak', why: 'scan 120 days old' }, siem_logs: { state: 'na' } } } };
  e.app.addons.assetCoverage = { view: async () => ({ rows: Object.values(rows) }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call, C, rows };
}

test('systems, exact matching, tests with evidence, not measured, drift, roles', async (t) => {
  const { call, C, rows, e } = await setup(t);
  assert.equal((await call('POST', '/pdpl/monitor/run', {}, VIEW)).status, 403);
  let r = await call('POST', '/pdpl/monitor/run', {}, OP); assert.equal(r.status, 200, r.text);
  const v = (await call('GET', '/pdpl/monitor', undefined, OP)).json, S = Object.fromEntries(v.systems.map((s) => [s.name, s]));
  assert.deepEqual(Object.keys(S).sort(), ['10.9.0.99', 'HR-APP', 'claims-db', 'portal'], 'RoPA systems + a discovered database, case-insensitive merge');
  const c = S['claims-db'];
  assert.equal(c.sensitive, true); assert.equal(c.asset.id, 'AST-1');
  for (const k of ['M01', 'M02', 'M03', 'M04', 'M05', 'M06', 'M07', 'M08', 'M09', 'M10', 'M11']) assert.equal(c.tests[k].state, 'pass', k + ' ' + c.tests[k].evidence);
  const h = S['HR-APP'];
  assert.equal(h.asset.id, 'AST-2', 'matched by name, case-insensitive');
  assert.equal(h.tests.M02.state, 'fail'); assert.match(h.tests.M02.evidence, /internal/);
  assert.equal(h.tests.M03.state, 'pass', 'medium is enough without sensitive data');
  assert.equal(h.tests.M04.state, 'fail'); assert.equal(h.tests.M05.state, 'fail');
  assert.equal(h.tests.M06.state, 'fail'); assert.equal(h.tests.M07.state, 'not_measured', 'a tool not connected is never a pass');
  assert.equal(h.tests.M08.state, 'pass', 'an exemption recorded in Asset Coverage'); assert.equal(h.tests.M09.state, 'fail'); assert.equal(h.tests.M10.state, 'na');
  assert.equal(h.tests.M11.state, 'fail');
  assert.equal(S.portal.tests.M01.state, 'fail'); assert.match(S.portal.tests.M01.evidence, /matches 2 assets/, 'never guesses between two assets');
  assert.equal(S['10.9.0.99'].tests.M01.state, 'fail');
  assert.equal(v.programme.P01.state, 'fail', 'no acknowledgement campaign yet');
  assert.ok(v.now.not_measured > 0 && v.now.score < 100);
  // viewer: summary only
  const vv = (await call('GET', '/pdpl/monitor', undefined, VIEW)).json; assert.equal(vv.systems, undefined); assert.ok(vv.last_run);
  // link the ambiguous system by hand: validated, audited
  assert.equal((await call('POST', '/pdpl/monitor/map', { system: S.portal.id, asset_id: 'AST-3' }, VIEW)).status, 403);
  assert.equal((await call('POST', '/pdpl/monitor/map', { system: 'bad id', asset_id: 'AST-3' }, OP)).status, 400);
  r = await call('POST', '/pdpl/monitor/map', { system: S.portal.id, asset_id: 'AST-404' }, OP); assert.equal(r.status, 400); assert.match(r.text, /asset_id/);
  assert.equal((await call('POST', '/pdpl/monitor/map', { system: S.portal.id, asset_id: 'AST-3' }, OP)).status, 200);
  // drift: claims-db loses its backup
  rows['AST-1'].controls.backup = { state: 'missing', why: 'no backup job' };
  T += 3600000; r = await call('POST', '/pdpl/monitor/run', {}, OP); assert.equal(r.status, 200);
  assert.ok(r.json.run.drift.includes(c.id + ':M08'), 'passed last run, fails now');
  const w = (await call('GET', '/pdpl/monitor', undefined, OP)).json;
  assert.equal(w.systems.find((s) => s.name === 'portal').tests.M01.state, 'pass', 'the hand link is used');
  const a = e.app.store.auditTail(40).map((x) => x.action); for (const n of ['pdpl.monitor.run', 'pdpl.monitor.drift', 'pdpl.monitor.link']) assert.ok(a.includes(n), n);
});

test('GRC actions, evidence pack, acknowledgement campaigns', async (t) => {
  const { call, e } = await setup(t);
  await call('POST', '/pdpl/monitor/run', {}, OP);
  const v = (await call('GET', '/pdpl/monitor', undefined, OP)).json, h = v.systems.find((s) => s.name === 'HR-APP'), c = v.systems.find((s) => s.name === 'claims-db');
  assert.equal((await call('POST', '/pdpl/monitor/grc', { key: 'nonsense' }, OP)).status, 400);
  let r = await call('POST', '/pdpl/monitor/grc', { key: c.id + ':M02' }, OP); assert.equal(r.status, 409, 'a passing test is not an action');
  r = await call('POST', '/pdpl/monitor/grc', { key: h.id + ':M02' }, OP); assert.equal(r.status, 200, r.text); assert.match(r.json.action, /^ACT-/);
  assert.equal((await call('POST', '/pdpl/monitor/grc', { key: h.id + ':M02' }, OP)).status, 409, 'never twice while open');
  assert.ok((await call('GET', '/pdpl/monitor', undefined, OP)).json.in_grc.includes(h.id + ':M02'));
  // pack
  assert.equal((await call('GET', '/pdpl/monitor/pack', undefined, VIEW)).status, 403);
  const p = (await call('GET', '/pdpl/monitor/pack', undefined, OP)).json; assert.match(p.pack_sha256, /^[0-9a-f]{64}$/); assert.ok(p.sections.systems.length === 4);
  // campaigns
  const camp = { policy: 'IT-GOV-001', audience: ['vera.syn', 'nora.syn'], due: '2026-11-30' };
  assert.equal((await call('POST', '/pdpl/monitor/campaigns', camp, OP)).status, 403, 'an operator who is not the DPO cannot start one');
  assert.equal((await call('POST', '/pdpl/monitor/campaigns', camp, { user: 'ai:pdpl', role: 'admin' })).status, 403, 'not an AI identity');
  r = await call('POST', '/pdpl/monitor/campaigns', Object.assign({}, camp, { policy: 'NOPE-1' }), ADM); assert.equal(r.status, 400); assert.match(r.text, /policy/);
  r = await call('POST', '/pdpl/monitor/campaigns', Object.assign({}, camp, { audience: ['svc:x'] }), ADM); assert.equal(r.status, 400);
  r = await call('POST', '/pdpl/monitor/campaigns', Object.assign({}, camp, { due: '2027-12-31' }), ADM); assert.equal(r.status, 400);
  r = await call('POST', '/pdpl/monitor/campaigns', camp, { user: 'dina.syn', role: 'operator' }); assert.equal(r.status, 200, 'the DPO may start one: ' + r.text);
  const id = r.json.id, ver = r.json.version;
  assert.equal((await call('POST', '/pdpl/monitor/campaigns', camp, ADM)).status, 409, 'one open campaign per policy version');
  const mine = (await call('GET', '/pdpl/monitor/my', undefined, VIEW)).json; assert.equal(mine.items.length, 1); assert.equal(mine.items[0].acknowledged_at, null);
  assert.equal((await call('POST', '/pdpl/monitor/campaigns/' + id + '/ack', { version: ver }, { user: 'other.syn', role: 'viewer' })).status, 403, 'not on the campaign');
  assert.equal((await call('POST', '/pdpl/monitor/campaigns/' + id + '/ack', { version: '9.9' }, VIEW)).status, 409, 'wrong version');
  assert.equal((await call('POST', '/pdpl/monitor/campaigns/' + id + '/ack', {}, VIEW)).status, 400);
  assert.equal((await call('POST', '/pdpl/monitor/campaigns/' + id + '/ack', { version: ver }, VIEW)).status, 200);
  assert.equal((await call('POST', '/pdpl/monitor/campaigns/' + id + '/ack', { version: ver }, VIEW)).status, 409, 'once');
  let cs = (await call('GET', '/pdpl/monitor/campaigns', undefined, OP)).json.items[0]; assert.equal(cs.pct, 50); assert.deepEqual(cs.pending, ['nora.syn']);
  assert.equal((await call('GET', '/pdpl/monitor', undefined, OP)).json.programme.P01.state, 'not_measured', 'in progress before the due date');
  T = Date.parse('2026-12-02T08:00:00Z');
  assert.equal((await call('GET', '/pdpl/monitor', undefined, OP)).json.programme.P01.state, 'fail', 'past due below 95%');
  assert.equal((await call('POST', '/pdpl/monitor/campaigns/' + id + '/ack', { version: ver }, OP)).status, 200);
  assert.equal((await call('GET', '/pdpl/monitor', undefined, OP)).json.programme.P01.state, 'pass');
  assert.equal((await call('POST', '/pdpl/monitor/campaigns/' + id + '/close', {}, OP)).status, 403);
  assert.equal((await call('POST', '/pdpl/monitor/campaigns/' + id + '/close', {}, ADM)).status, 200);
  T = Date.parse('2026-11-08T08:00:00Z');
  const a = e.app.store.auditTail(60).map((x) => x.action); for (const n of ['pdpl.monitor.grc', 'pdpl.monitor.pack', 'pdpl.monitor.campaign.start', 'pdpl.monitor.ack', 'pdpl.monitor.campaign.close']) assert.ok(a.includes(n), n);
});

test('a new PDPL policy reaches staff only after four-eyes approval as a GRC draft', async (t) => {
  const { call, e } = await setup(t);
  let r = await call('GET', '/pdpl/monitor/policies', undefined, OP); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.has_pdpl_policy, false); assert.match(r.json.note, /PP-01/);
  assert.equal((await call('GET', '/pdpl/monitor/policies', undefined, VIEW)).status, 403);
  r = await call('POST', '/grc/drafts', { title: 'Personal Data Protection Policy', frameworks: 'PDPL (Arts. 5, 10-19; IR Arts. 11-23)', purpose: 'How the company meets the PDPL (synthetic)' }, OP);
  assert.equal(r.status, 200, r.text); const did = r.json.id;
  const camp = { policy: did, audience: ['vera.syn'], due: '2026-11-30' };
  r = await call('POST', '/pdpl/monitor/campaigns', camp, ADM); assert.equal(r.status, 409, 'an unapproved draft is not sent to staff'); assert.match(r.text, /four-eyes/);
  assert.equal((await call('POST', '/grc/drafts/' + did + '/status', { status: 'approved' }, { user: 'nora.syn', role: 'admin' })).status, 403, 'the author does not approve');
  assert.equal((await call('POST', '/grc/drafts/' + did + '/status', { status: 'approved' }, ADM)).status, 200);
  r = await call('GET', '/pdpl/monitor/policies', undefined, OP); assert.equal(r.json.has_pdpl_policy, true); assert.equal(r.json.items[0].id, did, 'the PDPL policy is offered first');
  r = await call('POST', '/pdpl/monitor/campaigns', camp, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.version, '1.0');
  const mine = (await call('GET', '/pdpl/monitor/my', undefined, VIEW)).json.items[0];
  assert.equal(mine.title, 'Personal Data Protection Policy'); assert.match(mine.purpose, /PDPL/);
  assert.equal((await call('POST', '/pdpl/monitor/campaigns/' + r.json.id + '/ack', { version: '1.0' }, VIEW)).status, 200);
  assert.ok(e.app.store.auditTail(30).some((x) => x.action === 'pdpl.monitor.campaign.start' && x.target === r.json.id));
});
