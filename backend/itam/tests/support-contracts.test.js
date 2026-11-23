// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Support contracts register: families recognised from asset facts (Windows / Exchange / ESXi / Nutanix / Oracle / Cisco /
// vendor hardware), dates, coverage gaps, quantity against the inventory and the core-licensing audit, listed / retired /
// unknown serials, vendor verification per term (a renewal resets it), Cisco validation through cisco-support, import,
// coverage lookup with the case portal, cost hidden from viewers, roles and audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createSupportContracts, registerSupportContracts } = require('../engine/support-contracts');
const { createCiscoSupport } = require('../engine/cisco-support');

const ADM = { user: 'syed', role: 'admin', ip: '' }, OP = { user: 'eng1', role: 'operator', ip: '' };
const NOW = Date.parse('2026-10-14T08:00:00Z');

test('support contracts: families, gaps, quantities, verification, Cisco check, import, coverage, roles', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const A = e.app.assets;
  const dc01 = A.create({ name: 'DC01', type: 'server', status: 'in_use', os: 'Windows Server 2022 Datacenter', mgmt_ip: '10.1.0.10' }, ADM).asset.id;
  const ex01 = A.create({ name: 'EXCH01', type: 'vm', status: 'in_use', os: 'Windows Server 2019 Standard', tags: ['exchange'] }, ADM).asset.id;
  A.create({ name: 'APP02', type: 'vm', status: 'in_use', os: 'Windows Server 2019 Standard' }, ADM);
  const esx1 = A.create({ name: 'esx01', type: 'server', status: 'in_use', os: 'VMware ESXi 8.0.2', cpu: '2 x 16 cores' }, ADM).asset.id;
  A.create({ name: 'esx02', type: 'server', status: 'in_use', os: 'VMware ESXi 8.0.2', cpu: '2 x 16 cores' }, ADM);
  const ntx = A.create({ name: 'NTX-A', type: 'server', status: 'in_use', vendor: 'Nutanix', model: 'NX-3170-G8', serial: 'NXS1' }, ADM).asset.id;
  A.create({ name: 'ORA1', type: 'server', status: 'in_use', os: 'Oracle Linux 8', tags: ['oracle'] }, ADM);
  const sw = A.create({ name: 'CORE-SW1', type: 'network', status: 'in_use', vendor: 'Cisco', model: 'C9500-24Y4C', serial: 'FDO1111AAAA', mgmt_ip: '10.0.0.2' }, ADM).asset.id;
  const dell = A.create({ name: 'R750-1', type: 'server', status: 'in_use', vendor: 'Dell Inc.', model: 'PowerEdge R750', serial: 'DL1' }, ADM).asset.id;
  const old = A.create({ name: 'R640-old', type: 'server', status: 'in_use', vendor: 'Dell Inc.', serial: 'DL0' }, ADM).asset.id;
  A.transition(old, 'retire', ADM, 'replaced');

  const cisco = createCiscoSupport(e.app, { now: () => NOW, noTimer: true, request: async (url) => (url.includes('/token') ? { status: 200, json: { access_token: 't' } } : { status: 200, json: { serial_numbers: [{ sr_no: 'FDO1111AAAA', is_covered: 'NO' }] } }) });
  const C = createSupportContracts(e.app, { now: () => NOW, ciscoSupport: cisco });

  // nothing recorded: every family with assets shows its gap
  let v = C.view('operator');
  assert.deepEqual(Object.fromEntries(Object.entries(v.gaps).map(([k, g]) => [k, [g.in_scope, g.uncovered]])),
    { windows_server: [3, 3], exchange: [1, 1], vmware: [2, 2], nutanix: [1, 1], oracle_db: [1, 1], cisco: [1, 1] });
  assert.match(v.gaps.exchange.items[0].why, /tag: exchange/);

  // contracts
  assert.throws(() => C.put({ family: 'windows_server' }, OP), /end date required/);
  assert.throws(() => C.put({ family: 'nope', end: '2027-01-01' }, OP), /family must be/);
  assert.throws(() => C.put({ family: 'other', vendor: 'X', end: '2027-01-01', portal: 'http://x' }, OP), /https/);
  const ms = C.put({ family: 'windows_server', contract_number: 'MS-UNIFIED-1', level: 'Unified Enterprise', end: '2026-11-30', quantity: 2, unit: 'servers', cost: 250000 }, OP);
  const exc = C.put({ family: 'exchange', contract_number: 'MS-SA-2', end: '2027-06-30', asset_ids: [ex01] }, OP);
  const vmw = C.put({ family: 'vmware', contract_number: 'BRCM-77', end: '2027-03-01', quantity: 32, unit: 'cores' }, OP);
  const nut = C.put({ family: 'nutanix', contract_number: 'NTX-9', end: '2026-09-30', serials: ['nxs1', 'NXS-GONE'] }, OP);
  C.put({ family: 'cisco', contract_number: '8000', end: '2027-12-31', serials: ['FDO1111AAAA'] }, OP);
  const hw = C.put({ family: 'hardware', vendor: 'Dell', contract_number: 'PS-1', end: '2028-01-01', asset_ids: [dell, old], quantity: 10, unit: 'devices' }, OP);

  v = C.view('operator');
  const by = (id) => v.contracts.find((c) => c.id === id);
  assert.equal(by(ms.id).state, 'expiring'); assert.ok(by(ms.id).issues.some((i) => /covers 2 servers, the estate has 3/.test(i.text)));
  assert.equal(by(nut.id).state, 'expired'); assert.ok(by(nut.id).issues.some((i) => /NXSGONE/.test(i.text)), 'unknown serial listed');
  assert.ok(by(hw.id).issues.some((i) => /R640-old is retired: drop it at renewal/.test(i.text)));
  assert.ok(by(hw.id).issues.some((i) => /possible saving/.test(i.text)));
  // VMware cores: 2 hosts x 2 sockets x 16 = 64, raised to the 72-core minimum order by the core-licensing audit; 32 owned
  assert.ok(by(vmw.id).issues.some((i) => /covers 32 cores, the estate has 72 \(core-licensing audit\)/.test(i.text)), JSON.stringify(by(vmw.id).issues));
  assert.equal(by(exc.id).covered_count, 1); assert.equal(by(exc.id).portal, 'https://serviceshub.microsoft.com');
  assert.equal(v.gaps.windows_server.uncovered, 0); assert.equal(v.gaps.nutanix.uncovered, 1, 'expired contract does not cover');
  assert.equal(v.gaps.oracle_db.uncovered, 1);

  // verification for the term, reset by a renewal
  assert.ok(by(exc.id).issues.some((i) => /not verified/.test(i.text)));
  assert.throws(() => C.verify(exc.id, {}, OP), /reference is required/);
  C.verify(exc.id, { reference: 'Services Hub agreement page, 14 Oct' }, OP);
  assert.ok(!C.view('operator').contracts.find((c) => c.id === exc.id).issues.some((i) => /not verified/.test(i.text)));
  C.put({ id: exc.id, end: '2028-06-30' }, OP);
  const ren = C.view('operator').contracts.find((c) => c.id === exc.id);
  assert.ok(ren.issues.some((i) => /not verified/.test(i.text)), 'a new term needs verifying again'); assert.match(ren.history.map((h) => h.what).join('|'), /end date 2027-06-30 → 2028-06-30/);

  // Cisco family: checked with Cisco itself
  cisco.saveConfig({ api: { enabled: true, client_id: 'c', client_secret: 's' } }, ADM); await cisco.check(OP);
  const cc = C.view('operator').contracts.find((c) => c.family === 'cisco');
  assert.equal(cc.vendor_check.by, 'Cisco Support API'); assert.ok(cc.issues.some((i) => /NOT covered by Cisco/.test(i.text)));

  // coverage lookup (ticket desks): contracts, portal, Cisco row
  const cv = C.coverage({ ip: '10.1.0.10' }); assert.equal(cv.found, true); assert.deepEqual(cv.families, ['Windows Server']); assert.equal(cv.contracts[0].contract_number, 'MS-UNIFIED-1'); assert.equal(cv.covered, true);
  assert.equal(C.coverage({ asset_id: sw }).cisco.device.status, 'not-covered');
  assert.equal(C.coverage({ asset_id: ntx }).covered, false, 'only an expired contract');

  // import
  const imp = C.importText({ text: 'vendor,family,product,contract,end,quantity,unit,assets\nOracle,oracle_db,Oracle Database EE,CSI 1234567,2027-05-31,4,processors,ORA1\nRed Hat,rhel,RHEL,RH-1,31/12/2027,,servers,\nOracle,oracle_db,x,CSI 2,2027-05-31,,,NOPE\n' }, OP);
  assert.equal(imp.created, 1); assert.equal(imp.errors_total, 2); assert.match(imp.errors.map((x) => x.error).join(' '), /YYYY-MM-DD/); assert.match(imp.errors.map((x) => x.error).join(' '), /not in the inventory: NOPE/);
  assert.equal(C.view('operator').gaps.oracle_db.uncovered, 0);

  // roles, cost hidden from viewers, audit
  registerSupportContracts(e.app.srv, e.app);
  const vv = await e.req('GET', '/support-contracts', { role: 'viewer' });
  assert.equal(vv.status, 200); assert.ok(vv.json.contracts.every((c) => c.cost === undefined)); assert.equal(vv.json.summary.renewal_cost_90d, undefined);
  assert.equal((await e.req('GET', '/support-contracts', { role: 'operator' })).json.summary.renewal_cost_90d, 250000);
  assert.equal((await e.req('POST', '/support-contracts', { role: 'viewer', body: { family: 'other', vendor: 'X', end: '2027-01-01' } })).status, 403);
  assert.equal((await e.req('PUT', '/support-contracts/settings', { role: 'operator', body: { expiring_days: 30 } })).status, 403);
  assert.equal((await e.req('POST', `/support-contracts/${nut.id}/retire`, { role: 'operator', body: { reason: 'nodes replaced' } })).status, 200);
  const aud = e.app.store.auditTail(200, (x) => /^support\./.test(x.action || '')).map((x) => x.action);
  for (const a of ['support.create', 'support.update', 'support.verify', 'support.import', 'support.retire']) assert.ok(aud.includes(a), a);
  void dc01; void esx1;
});

test('support contracts: Fortinet and Palo Alto devices are recognised and covered by serial', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const A = e.app.assets;
  A.create({ name: 'FGT-HQ', type: 'network', status: 'in_use', vendor: 'Fortinet', model: 'FortiGate 100F', serial: 'FG100FTK1' }, ADM);
  A.create({ name: 'FS-ACC1', type: 'network', status: 'in_use', model: 'FS-148F', serial: 'S148F1' }, ADM);
  A.create({ name: 'PA-DC', type: 'network', status: 'in_use', vendor: 'Palo Alto Networks', model: 'PA-3220', serial: '0123' }, ADM);
  const C = createSupportContracts(e.app, { now: () => NOW });
  let g = C.view('operator').gaps;
  assert.deepEqual([g.fortinet.in_scope, g.fortinet.uncovered, g.paloalto.in_scope], [2, 2, 1]);
  C.put({ family: 'fortinet', contract_number: 'FC-2026', level: 'FortiCare 24x7 + UTP', end: '2027-04-30', serials: ['FG100FTK1'] }, OP);
  C.put({ family: 'paloalto', contract_number: 'PAN-77', level: 'Premium support + Threat Prevention', end: '2027-01-31' }, OP);
  g = C.view('operator').gaps;
  assert.equal(g.fortinet.uncovered, 1); assert.equal(g.fortinet.items[0].name, 'FS-ACC1'); assert.equal(g.paloalto.uncovered, 0);
  assert.equal(C.coverage({ name: 'pa-dc' }).contracts[0].portal, 'https://support.paloaltonetworks.com');
  assert.equal(C.coverage({ name: 'fgt-hq' }).contracts[0].portal, 'https://support.fortinet.com');
});
