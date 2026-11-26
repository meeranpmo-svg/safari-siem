// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI GRC Consultant (engine/grc-consultant.js, on the duty desk via engine/duty.js): compliance gaps from the platform's
// own GRC records become work items with the recommendation and framework clauses; a fixed gap resolves on the next
// patrol; "ask the consultant" answers from the records only (invented refs are stripped; no AI = labelled rule-based
// answer); the roadmap groups gaps by horizon; viewers read, operators ask; it never approves anything.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { registerOwnership } = require('../engine/ownership');
const { orgFrameworks, fwLabel } = require('../engine/grc-consultant');
const BRAND = require('../engine/brand'), F = orgFrameworks(BRAND);   // the installed organisation's frameworks

const ADM = { user: 'syed', role: 'admin', ip: '' };
let clock = Date.parse('2026-10-15T08:00:00Z');
const now = () => clock;

test('grc consultant: gaps become work items with advice and frameworks; fixing a gap resolves it', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const O = registerOwnership(e.app.srv, e.app);
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now });
  assert.ok(D.engineers().some((x) => x.id === 'grc'), 'the consultant is on the duty desk');
  const G = e.app.addons.grc;
  G.drillPut({ title: 'Core insurance DR', system: 'Core Insurance', type: 'failover', scheduled: '2025-01-10', frequency_months: 12 }, ADM);
  const a1 = e.app.assets.create({ name: 'CLAIMS01', type: 'server', status: 'in_use' }, ADM).asset.id;
  await D.patrol('grc');
  const items = D.list({ engineer: 'grc' }).items, kind = (k) => items.filter((x) => x.kind === k);
  assert.equal(kind('drill-overdue').length, 1, 'never-tested system is overdue');
  assert.match(kind('drill-overdue')[0].recommendation, /RTO \/ RPO/);
  assert.ok(kind('drill-overdue')[0].evidence.some((x) => x === 'framework: ' + fwLabel('drill-overdue', F)), 'the clauses of this organisation\'s frameworks');
  if (!F.ia) assert.equal(kind('ia-gap').length + kind('ia-partial').length, 0, 'no Insurance Authority gaps where it does not apply');
  const own = kind('owner-business')[0];
  assert.ok(own, 'asset without a business owner'); assert.equal(own.severity, 'high', 'under 50% named');
  assert.ok(items.every((x) => x.recommendation && !/approved|signed off by the consultant/i.test(x.title)));
  // the owners are named: the ownership gap clears on the next patrol
  O.assign({ ids: [a1], it_owner: 'Infra team', business_owner: 'Head of Claims', reason: 'test' }, ADM);
  clock += 600000; await D.patrol('grc');
  assert.equal(D.get(own.id).status, 'resolved'); assert.equal(D.get(own.id).resolution, 'cleared');
  // roadmap: now / next / later with frameworks
  const r = await e.req('GET', '/grc/roadmap', { role: 'viewer' });
  assert.equal(r.status, 200);
  assert.ok(r.json.horizons.now.some((x) => x.kind === 'drill-overdue' && x.framework === fwLabel('drill-overdue', F)));
  assert.deepEqual(r.json.frameworks, F.names);
  if (!F.sama) assert.ok(!JSON.stringify(r.json.horizons).includes('SAMA'), 'no SAMA clause where SAMA does not apply');
  assert.ok(!r.json.horizons.now.concat(r.json.horizons.next, r.json.horizons.later).some((x) => /^owner-/.test(x.kind)));
});

test('grc consultant: ask - answers from the records, invented refs stripped; no AI = labelled rule-based answer; roles', async (t) => {
  const e = await startApp({}); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now });
  e.app.addons.grc.drillPut({ title: 'ERP DR', system: 'ERP', type: 'restore', scheduled: '2025-02-01', frequency_months: 6 }, ADM);
  assert.equal((await e.req('POST', '/grc/consult', { role: 'viewer', body: { question: 'x' } })).status, 403, 'viewers read, operators ask');
  assert.equal((await e.req('POST', '/grc/consult', { role: 'operator', body: {} })).status, 400);
  e.fake.override = () => ({ ok: true, model: 'synthetic-model-1', text: JSON.stringify({ answer: 'Test the ERP recovery first.',
    actions: [{ action: 'Run the ERP restore test', owner_role: 'IT Ops', refs: ['gap:drill-overdue:ERP', 'policy:INVENTED-999'] }], refs: ['gap:drill-overdue:ERP', 'control:made-up'] }) });
  const r = await e.req('POST', '/grc/consult', { role: 'operator', body: { question: 'What should we fix first for SAMA BCM?' } });
  assert.equal(r.status, 200); assert.equal(r.json.kind, 'ai');
  assert.deepEqual(r.json.refs, ['gap:drill-overdue:ERP'], 'only refs that exist in the context');
  assert.deepEqual(r.json.actions[0].refs, ['gap:drill-overdue:ERP']);
  assert.equal(r.json.refs_dropped, 2);
  const sent = e.fake.requests.at(-1).body;
  assert.match(JSON.stringify(sent), /never state that anything was approved/i);
  // AI answer not valid → rule-based, labelled
  e.fake.override = () => ({ ok: true, model: 'm', text: 'not json at all' });
  const r2 = await e.req('POST', '/grc/consult', { role: 'operator', body: { question: 'and now?' } });
  assert.equal(r2.json.kind, 'rules'); assert.match(r2.json.why_rules, /not valid/);
  assert.ok(r2.json.actions.some((a) => /ERP/.test(a.action)));
  const l = await e.req('GET', '/grc/consults', { role: 'viewer' });
  assert.equal(l.status, 200); assert.equal(l.json.consults.length, 2);
});

test('grc consultant: readiness names what is missing', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now });
  const r = await e.req('GET', '/duty/readiness', { role: 'viewer' });
  const g = r.json.engineers.find((x) => x.id === 'grc');
  assert.ok(g, 'grc in readiness');
  assert.ok(g.checks.find((c) => c.name === 'GRC records readable').ok);
  assert.ok(g.to_fix.some((f) => /add-ownership/.test(f.fix)), 'ownership module missing is named');
  assert.equal(g.status, 'partial');
});

test('grc consultant: serious penetration-testing findings become one compliance gap per asset, with the owners', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const O = registerOwnership(e.app.srv, e.app);
  const a1 = e.app.assets.create({ name: 'WEB-DMZ-01', type: 'server', status: 'in_use' }, ADM).asset.id;
  O.assign({ ids: [a1], it_owner: 'Infra team', business_owner: 'Head of Digital', reason: 'test' }, ADM);
  let findings = [
    { id: 'f1', asset_id: a1, asset: 'WEB-DMZ-01', title: 'Telnet open', severity: 'critical', internet: true },
    { id: 'f2', asset_id: a1, asset: 'WEB-DMZ-01', title: 'FTP open', severity: 'high', internet: true },
    { id: 'f3', asset_id: a1, asset: 'WEB-DMZ-01', title: 'SNMP v2c', severity: 'medium', internet: false },
  ];
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now, pentest: { assessment: () => ({ summary: { assets: 1 }, findings }) } });
  e.app.addons.pentest = { assessment: () => ({ summary: { assets: 1 }, findings }) };
  await D.patrol('grc');
  const g = D.list({ engineer: 'grc' }).items.filter((x) => x.kind === 'pentest-exposure');
  assert.equal(g.length, 1, 'one gap for the asset, not one per finding');
  assert.equal(g[0].severity, 'critical', 'critical and internet-facing');
  assert.match(g[0].title, /WEB-DMZ-01: 2 serious exposures/);
  assert.ok(g[0].evidence.some((x) => /IT owner: Infra team · business owner: Head of Digital/.test(x)));
  assert.ok(g[0].evidence.some((x) => /NCA ECC 2-10/.test(x)));
  // the exposures are closed: the next patrol resolves the gap
  findings = [findings[2]];
  clock += 600000; await D.patrol('grc');
  assert.equal(D.get(g[0].id).status, 'resolved');
});

// frameworks per organisation: a SAMA-regulated insurer keeps SAMA / IA clauses and gaps; an organisation without them (Safari:
// NCA ECC, ISO 27001, PDPL, NDMO) gets the NCA ECC equivalents and no SAMA / IA anywhere
test('grc consultant: clause labels and frameworks follow the organisation', () => {
  const insurer = orgFrameworks({ frameworks: ['nca', 'iso27001', 'pdpl'], modules_off: [] });
  assert.ok(insurer.sama && insurer.ia); assert.deepEqual(insurer.names, ['SAMA CSF', 'NCA ECC', 'ISO 27001', 'PDPL', 'Insurance Authority']);
  assert.match(fwLabel('drill-overdue', insurer), /SAMA BCM/);
  const safari = orgFrameworks({ frameworks: ['nca', 'iso27001', 'pdpl', 'ndmo'], modules_off: ['fw-sama', 'fw-ia'] });
  assert.ok(!safari.sama && !safari.ia); assert.deepEqual(safari.names, ['NCA ECC', 'ISO 27001', 'PDPL', 'NDMO']);
  for (const k of ['control-fail', 'control-partial', 'policy-review', 'drill-overdue', 'drill-failed', 'drill-signoff', 'owner-business', 'owner-it', 'pentest-exposure']) {
    const l = fwLabel(k, safari); assert.ok(l && !/SAMA/.test(l), k + ': ' + l);
  }
  assert.equal(fwLabel('policy-review', safari), 'NCA ECC 1-3 (policies and procedures) · ISO 27001 5.2 / A.5.1');
  assert.equal(fwLabel('control-fail', safari), 'NCA ECC 2 · ISO 27001 Annex A');
  assert.equal(fwLabel('pentest-exposure', safari), 'NCA ECC 2-10 (vulnerability management) · ISO 27001 A.8.8 (technical vulnerabilities)');
});
