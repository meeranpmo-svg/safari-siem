// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Oracle Licence Inventory (engine/oracle-licences.js): the Oracle Processor Core Factor Table matched against each server's
// CPU text (most specific row first, single-core = 1.0, nothing matched = default ASSUMED, never "matched"), a person's factor
// with a reason wins and is never replaced, the admin's own rows (validated), the edition a monitored database reported
// counted as a deployment, processor licences per database on every host of its VMware cluster, and unplaced databases named.
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createCoreLicensing } = require('../engine/core-licensing');
const { createOracleLicences } = require('../engine/oracle-licences');

const ADM = { user: 'syed', role: 'admin', ip: '' };
test('core factor table: matching', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const O = createOracleLicences(e.app, { coreLicensing: createCoreLicensing(e.app), noTimer: true });
  const f = (cpu, cps) => (O.match(cpu, cps) || {}).factor || null;
  assert.equal(f('2 x Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz'), 0.5);
  assert.equal(f('AMD EPYC 7543 32-Core'), 0.5);
  assert.equal(f('IBM POWER9 2x12 cores'), 1); assert.equal(f('POWER10'), 1);
  assert.equal(f('SPARC M7 32 cores'), 0.5); assert.equal(f('SPARC T5'), 0.5); assert.equal(f('SPARC64 X+'), 0.5);
  assert.equal(f('UltraSPARC IV+'), 0.75); assert.equal(f('UltraSPARC T1 1.2 GHz'), 0.25); assert.equal(f('UltraSPARC T1 1.4 GHz'), 0.5);
  assert.equal(f('Intel Itanium 9560'), 0.5); assert.equal(f('Intel Itanium 2 9050'), 1, 'pre-9300 Itanium');
  assert.equal(f('Ampere Altra Q80-30'), 0.25);
  assert.equal(f('Intel Xeon 5160', 1), 1, 'a single-core chip is 1.0');
  assert.equal(f('Hygon C86 7285'), null, 'nothing matched: no factor invented'); assert.equal(f(''), null);
  // admin rows: validated, first
  assert.throws(() => O.setTable({ rows: [{ label: 'x', pattern: '(', factor: 0.5 }] }, ADM), /not a valid regular expression/);
  assert.throws(() => O.setTable({ rows: [{ label: 'x', pattern: 'hygon', factor: 0.6 }] }, ADM), /factor must be one of/);
  assert.throws(() => O.setTable({ rows: [{ label: 'Hygon', pattern: 'hygon', factor: 0.5 }] }, { user: 'svc:x', role: 'admin' }), /only a person/);
  O.setTable({ rows: [{ id: 'hygon', label: 'Hygon Dhyana (x86-64, per contract clause 4.2)', pattern: '\\bhygon\\b', factor: 0.5 }] }, ADM);
  assert.equal(f('Hygon C86 7285'), 0.5);
});

test('inventory: matched factors in the licence rules, a person\'s factor wins, monitored database editions counted', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const mk = (o) => e.app.assets.create(Object.assign({ status: 'in_use' }, o), ADM).asset.id;
  const ids = {
    esx1: mk({ name: 'esx01', type: 'server', os: 'VMware ESXi 8.0', cpu: '2 x Intel Xeon Gold 6338 32-Core', tags: ['esxi-host'] }),
    esx2: mk({ name: 'esx02', type: 'server', os: 'VMware ESXi 8.0', cpu: '2 x Intel Xeon Gold 6338 32-Core', tags: ['esxi-host'] }),
    vm: mk({ name: 'oravm01', type: 'vm', os: 'Oracle Linux 8', software: [{ name: 'Oracle Database 19c Enterprise Edition', publisher: 'Oracle' }] }),
    sparc: mk({ name: 'sun-t5', type: 'server', os: 'Solaris 11', cpu: 'SPARC T5 2 sockets, 16 cores each' }),
    power: mk({ name: 'aix01', type: 'server', os: 'AIX 7.2', cpu: 'IBM POWER9 2 x 12 cores', software: [{ name: 'Oracle Database 12c Standard Edition 2', publisher: 'Oracle' }] }),
    odd: mk({ name: 'odd01', type: 'server', os: 'Linux', cpu: 'Hygon C86 7285 2 x 32 cores', software: [{ name: 'Oracle Database 19c', publisher: 'Oracle' }] }),
  };
  e.app.store.collection('relationships').put({ id: 'r1', type: 'runs_on', from: ids.vm, to: ids.esx1 });
  const F = e.app.store.collection('core_lic_facts');
  F.put({ id: ids.esx1, cluster: 'PROD' }); F.put({ id: ids.esx2, cluster: 'PROD' });
  const C = createCoreLicensing(e.app);
  // a monitored database on the SPARC server, its edition read from the database (no software inventory there)
  const dbHealth = { targets: () => ({ list: [{ key: 'reg:1', ip: '10.0.0.9', host: 'sun-t5', service: 'ERP', asset_id: ids.sparc }, { key: 'reg:2', ip: '10.0.0.10', host: 'nowhere', service: 'X' }] }),
    status: () => ({ last: { at: new Date().toISOString(), results: [{ ip: '10.0.0.9', ok: true, instance: 'ERP', version: '19.0.0.0.0', edition: 'EE', banner: 'Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production' }, { ip: '10.0.0.10', ok: true, instance: 'X', edition: 'EE' }] } }) };
  const O = createOracleLicences(e.app, { coreLicensing: C, dbHealth, noTimer: true });
  const inv = O.inventory();
  const dep = (n) => inv.deployments.find((d) => d.name === n);
  // VM on ESXi: licensed on every host of the PROD cluster, Intel 0.5 from the table
  const v = dep('oravm01');
  assert.deepEqual(v.scope.map((x) => [x.host, x.cores, x.factor, x.factor_source, x.licences]).sort(), [['esx01', 64, 0.5, 'table', 32], ['esx02', 64, 0.5, 'table', 32]]);
  assert.equal(v.licences, 64); assert.match(v.scope[0].factor_row, /Intel Xeon/);
  // SPARC: deployment comes from the database itself
  const s = dep('sun-t5'); assert.equal(s.edition, 'ee'); assert.match(s.how, /read from the database \(ERP\)/); assert.equal(s.databases[0].instance, 'ERP');
  assert.deepEqual([s.scope[0].cores, s.scope[0].factor, s.scope[0].licences], [32, 0.5, 16]);
  // SE2 on POWER: sockets
  assert.deepEqual([dep('aix01').edition, dep('aix01').scope[0].licences], ['se2', 2]);
  // nothing matched: default ASSUMED
  const o = dep('odd01').scope[0]; assert.deepEqual([o.factor, o.factor_assumed, o.factor_source], [0.5, true, 'default'], 'the default factor, shown as assumed');
  assert.equal(inv.hosts.find((h) => h.host === 'odd01').matched, null);
  assert.equal(inv.unplaced.length, 1); assert.match(inv.unplaced[0].why, /not in the asset register/);
  // a person's factor wins (with a reason) and survives the next match
  assert.throws(() => O.setFactor({ asset_id: ids.odd, factor: 0.5 }, ADM), /say why/);
  assert.throws(() => O.setFactor({ asset_id: ids.odd, factor: 0.3, reason: 'x' }, ADM), /factor must be one of/);
  O.setFactor({ asset_id: ids.odd, factor: 1, reason: 'Hygon not in the Oracle table - Oracle LMS confirmed 1.0 (ticket 4711)' }, ADM);
  const o2 = O.inventory().deployments.find((d) => d.name === 'odd01').scope[0];
  assert.deepEqual([o2.factor, o2.factor_source, o2.licences], [1, 'entered', 64]); assert.match(o2.factor_row, /LMS confirmed/);
  O.setTable({ rows: [{ id: 'hygon', label: 'Hygon', pattern: 'hygon', factor: 0.5 }] }, ADM);
  assert.equal(O.inventory().deployments.find((d) => d.name === 'odd01').scope[0].factor, 1, 'the table never replaces a person\'s factor');
  // the same numbers in Licence audit -> Core-based licences
  const ee = C.view().products.oracle_ee; assert.equal(ee.hosts.find((h) => h.host === 'sun-t5').licences, 16);
  O.setFactor({ asset_id: ids.odd, factor: null }, ADM);
  assert.equal(O.inventory().deployments.find((d) => d.name === 'odd01').scope[0].factor_source, 'table', 'cleared: the admin row matches now');
});

test('compliance: matrix, over-utilisation / at-risk / expiry / incomplete alerts, the one-page report, mailed once to DBA + managers', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const mk = (o) => e.app.assets.create(Object.assign({ status: 'in_use' }, o), ADM).asset.id;
  const ids = {
    esx1: mk({ name: 'esx01', type: 'server', os: 'VMware ESXi 8.0', cpu: '2 x Intel Xeon Gold 6338 32-Core', tags: ['esxi-host'] }),
    vm: mk({ name: 'oravm01', type: 'vm', os: 'Oracle Linux 8', software: [{ name: 'Oracle Database 19c Enterprise Edition', publisher: 'Oracle' }] }),
    power: mk({ name: 'aix01', type: 'server', os: 'AIX 7.2', cpu: 'IBM POWER9 2 x 12 cores', software: [{ name: 'Oracle Database 12c Standard Edition 2', publisher: 'Oracle' }] }),
    odd: mk({ name: 'odd01', type: 'server', os: 'Linux', cpu: 'Hygon C86 7285 2 x 32 cores', software: [{ name: 'Oracle Database 19c', publisher: 'Oracle' }] }),
  };
  e.app.store.collection('relationships').put({ id: 'r1', type: 'runs_on', from: ids.vm, to: ids.esx1 });
  // one clock for both engines: core licensing decides which entitlements are expired (and counted as owned)
  let T = Date.UTC(2026, 9, 22, 6, 0);   // 09:00 Riyadh, the 22nd
  const C = createCoreLicensing(e.app, { now: () => T });
  const mails = [], siem = { call: async (m, p, who, body) => { mails.push({ p, who, body }); return { status: 200, json: { ok: true, recipients: 3, managers: 1 } }; } };
  const O = createOracleLicences(e.app, { coreLicensing: C, discovery: { siem }, noTimer: true, now: () => T });
  // nothing owned yet: every licence needed is over-use
  let c = O.compliance();
  const ee = () => c.matrix.find((m) => m.product === 'oracle_ee'), se = () => c.matrix.find((m) => m.product === 'oracle_se2');
  assert.equal(ee().required, 64); assert.equal(ee().owned, 0); assert.equal(ee().level, 'over'); assert.equal(c.verdict, 'over');
  // EE: esx01 32 (0.5 x 64) + odd01 32 (assumed 0.5 x 64); own 60 -> over by 4; SE2 aix01 2 sockets, own 2 -> 100 % at risk
  C.putEnt({ product: 'oracle_ee', quantity: 60, contract: 'CSI-1001', expiry: '2026-11-10' }, ADM);
  C.putEnt({ product: 'oracle_se2', quantity: 2, contract: 'CSI-2002' }, ADM);
  c = O.compliance();
  assert.deepEqual([ee().owned, ee().required, ee().delta, ee().level, ee().utilisation_pct], [60, 64, -4, 'over', 107]);
  assert.deepEqual([se().owned, se().required, se().level, se().utilisation_pct], [2, 2, 'near', 100]);
  assert.equal(ee().factor_assumed, 1, 'the Hygon server has an assumed factor');
  assert.equal(ee().nup_minimum, 1600);
  const keys = c.alerts.map((a) => a.key);
  assert.ok(keys.includes('over:oracle_ee') && keys.includes('near:oracle_se2') && keys.includes('inc:oracle_ee') && keys.some((k) => k.startsWith('exp:')), JSON.stringify(keys));
  const over = c.alerts.find((a) => a.key === 'over:oracle_ee');
  assert.equal(over.severity, 'critical'); assert.match(over.title, /64 licences needed, 60 owned - over-utilised by 4/); assert.match(over.action, /Buy 4 more/); assert.equal(over.owner, 'Infrastructure manager');
  assert.equal(c.alerts.find((a) => a.key.startsWith('exp:')).severity, 'critical', '19 days left');
  // the one page
  const r = O.reportOf();
  assert.match(r.subject, /Oracle licence compliance 2026-10-22: OVER-UTILISED - \d+ critical/);
  assert.match(r.html, /Compliance matrix/); assert.match(r.html, /OVER-UTILISED/); assert.match(r.html, /CSI-1001/); assert.match(r.html, /Infrastructure Manager and the DBA team/);
  assert.match(r.html, /odd01/); assert.match(r.html, /\(assumed\)/);
  assert.ok(!/<script/i.test(r.html));
  // hourly check: a new critical alert mails the report once, to DBA + managers, as the service identity
  let k = await O.check();
  assert.equal(mails.length, 1); assert.equal(mails[0].p, '/db/dba/morning-report'); assert.equal(mails[0].who.user, 'system:itam-oracle-licences'); assert.equal(mails[0].body.audience, 'dba+managers');
  assert.equal(k.sent.ok, true);
  T += 3600000; k = await O.check(); assert.equal(mails.length, 1, 'not again an hour later');
  T += 7 * 86400000; k = await O.check(); assert.equal(mails.length, 2, 'reminded after 7 days while still open');
  // fixed: buy licences -> the over alert clears, no new mail for it
  C.putEnt({ product: 'oracle_ee', quantity: 20, contract: 'CSI-1003' }, ADM);
  T += 3600000; k = await O.check();
  assert.ok(e.app.store.collection('ora_lic_alerts').get('over:oracle_ee').cleared_at, 'cleared');
  const v = O.complianceView(); assert.ok(v.reports.length >= 2 && v.reports[0].mail.ok);
  // manual send (a person) is audited
  await O.sendReport('manual', ADM);
  assert.ok(e.app.store.auditTail(50, (x) => x.action === 'oracle.licence.report.send' && x.by === 'syed').length === 1);
});
