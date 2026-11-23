// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Data map (engine/data-map.js) over SYNTHETIC PDPL records and discovered systems: activities linked to systems by name; UNMAPPED systems
// with a drafted activity (no purpose or legal basis invented); UNDER-DECLARED and NOT FOUND categories; UNKNOWN SYSTEMS; TRANSFER gaps
// (cloud abroad, processor outside KSA, missing risk assessment); DPIA triggers; EXPOSED systems; STALE reviews; risk itemised; coverage;
// the route: operator reads (audited), viewer refused; discovery missing is said.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const DM = require('../engine/data-map');

const NOW = Date.parse('2026-11-19T08:00:00Z');
function C() {
  const claims = { id: 'm365:claims', type: 'sharepoint', label: 'Claims Site', personal: 40, kinds: { national_id: 30, health: 12, email: 40 }, last_scan: '2026-11-18' };
  const hr = { id: 'fs:srv1:hr', type: 'fileshare', label: '\\\\srv1\\HR', host: 'srv1', personal: 9, kinds: { salary: 9 }, last_scan: '2026-11-18' };
  return { src: { m365_files: { measured: true } }, stores: [claims, hr],
    cloudStores: [{ id: 'cloud:aws:exp', raw_id: 'exp', type: 'cloud:aws', label: 'claims-exports', personal: true, with_findings: 5, kinds: { iban: 5 }, in_kingdom: false, public: true, last_scan: '2026-11-18' }],
    dbs: [{ id: 'db:ora1', key: 'ora1', label: 'CORE-DB', host: 'ora1', service: 'CORE', ok: true, personal: true, cats: ['identity', 'financial'], kinds: {}, columns: 14 }],
    rows: [{ store: claims, personal: true, shared: 'external' }] };
}
const recs = () => [
  { id: 'PD-ROPA-001', kind: 'ropa', name: 'Claims handling', systems: ['Claims Site', 'claims-exports', 'LEGACY-CLAIMS'], data_categories: ['identity', 'contact', 'religious'], legal_basis: 'contract', processor_ids: ['PD-PROCESSOR-001'], reviewed: '2026-06-01', volume: 50000 },
  { id: 'PD-ROPA-002', kind: 'ropa', name: 'Policy administration', systems: ['CORE'], data_categories: ['identity', 'financial'], legal_basis: 'contract', reviewed: '2024-01-01' },
  { id: 'PD-PROCESSOR-001', kind: 'processor', name: 'Offshore TPA', outside_ksa: true },
  { id: 'PD-TRF-001', kind: 'transfer', name: 'Policy data to reinsurer', country: 'Germany', ropa_id: 'PD-ROPA-002' }];

test('the register against discovery: links, gaps with evidence and fix, drafts, risk and coverage', () => {
  const v = DM.analyse({ C: C(), records: recs(), now: NOW }), a1 = v.activities.find((a) => a.id === 'PD-ROPA-001'), a2 = v.activities.find((a) => a.id === 'PD-ROPA-002');
  assert.deepEqual(a1.systems.map((s) => s.label).sort(), ['Claims Site', 'claims-exports']); assert.deepEqual(a1.unknown_systems, ['LEGACY-CLAIMS']);
  assert.deepEqual(a2.systems.map((s) => s.label), ['CORE-DB'], 'matched by service name');
  const f = (type, id) => v.findings.filter((x) => x.type === type && (!id || (x.activity && x.activity.id === id)));
  assert.match(f('under-declared', 'PD-ROPA-001')[0].why, /health, financial/);
  assert.match(f('not-found', 'PD-ROPA-001')[0].why, /declares religious/);
  assert.equal(f('unknown-systems', 'PD-ROPA-001').length, 1);
  assert.match(f('transfer', 'PD-ROPA-001')[0].why, /1 system\(s\) abroad, 1 processor\(s\) outside KSA/);
  assert.match(f('transfer', 'PD-ROPA-002')[0].why, /Germany has no risk assessment/);
  assert.match(f('dpia', 'PD-ROPA-001')[0].why, /sensitive data \(religious, health\)|sensitive data \(health, religious\)/); assert.match(f('dpia', 'PD-ROPA-001')[0].why, /50,000 people/);
  assert.match(f('exposed', 'PD-ROPA-001')[0].why, /claims-exports is public/); assert.match(f('exposed', 'PD-ROPA-001')[0].why, /Claims Site has 1 file\(s\) shared outside/);
  assert.equal(f('stale', 'PD-ROPA-002').length, 1); assert.equal(f('stale', 'PD-ROPA-001').length, 0);
  const un = f('unmapped'); assert.equal(un.length, 1); assert.equal(un[0].system, '\\\\srv1\\HR');
  const sg = v.suggestions[0]; assert.equal(sg.draft.name, 'Processing in \\\\srv1\\HR'); assert.deepEqual(sg.draft.data_categories, ['financial']); assert.equal(sg.draft.legal_basis, undefined, 'never invents a legal basis'); assert.match(sg.why, /discovery cannot know/);
  assert.deepEqual(v.coverage, { systems_with_personal_data: 4, mapped: 3, pct: 75 });
  assert.ok(a1.risk > a2.risk && a1.risk_items.some((i) => /transfer record/.test(i.label)));
  assert.equal(v.activities[0].id, 'PD-ROPA-001', 'riskiest first'); assert.ok(v.countries.includes('Germany'));
});

test('route: operator reads (audited), viewer refused; without discovery the register alone is checked and it says so', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  for (const r of recs()) e.app.store.collection('pdpl_records').put(r);
  DM.registerDataMap(e.app.srv, e.app, { now: () => NOW });
  let r = await e.req('GET', '/pdpl/data-map', { user: 'vera.syn', role: 'viewer' }); assert.equal(r.status, 403);
  r = await e.req('GET', '/pdpl/data-map', { user: 'nora.syn', role: 'operator' }); assert.equal(r.status, 200, r.text);
  assert.match(r.json.discovery.why, /not installed/); assert.equal(r.json.activities.length, 2); assert.ok(r.json.findings.some((x) => x.type === 'unknown-systems'));
  assert.ok(e.app.store.auditTail(20).some((a) => a.action === 'pdpl.datamap.read' && a.by === 'nora.syn'));
  e.app.addons = Object.assign(e.app.addons || {}, { dataPosture: { build: async () => ({ C: C() }) } });
  r = await e.req('GET', '/pdpl/data-map', { user: 'nora.syn', role: 'operator' }); assert.equal(r.json.coverage.pct, 75);
});
