// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Next-year IT budget: generated lines (carry-over, licence renewals, support, end of life, storage), the Cyber
// Security / IT Operations split, CAPEX / OPEX, no invented prices, fit against the envelopes, decisions and audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { isSecurity } = require('../engine/budget');

const ADM = { user: 'cio', role: 'admin' };

test('security classification is word-bounded', () => {
  assert.equal(isSecurity('Kaspersky Endpoint Security for Business'), true);
  assert.equal(isSecurity('FortiGate 200F UTP bundle'), true);
  assert.equal(isSecurity('Palo Alto PA-3410 threat prevention'), true);
  assert.equal(isSecurity('Microsoft 365 E3'), false);
  assert.equal(isSecurity('Oracle Database Enterprise'), false);
  assert.equal(isSecurity('Associates programme'), false, '"soc" inside a word is not security');
  assert.equal(isSecurity('Veeam Backup & Replication'), false);
});

test('budget: lines from every source, envelopes 66M / 30M, CAPEX / OPEX, unpriced never guessed, fit and decisions', async () => {
  const t = await startApp({ noAi: true });
  try {
    const { app } = t;
    require('../engine/budget').registerBudget(app.srv, app);
    const adm = t.as('cio', 'admin');
    const now = new Date(), fy = now.getUTCFullYear() + 1;
    // inventory: an EOL server with a purchase cost, an EOL VM, a firewall whose warranty ends, a server without cost
    const mk = (b) => app.assets.create(Object.assign({ status: 'in_use' }, b), ADM).asset.id;
    const eolSrv = mk({ name: 'FS01', type: 'server', os: 'Windows Server 2012 R2 Standard', purchase: { date: '2016-03-01', cost: 85000 }, warranty: { end: `${fy}-05-01` } });
    mk({ name: 'APP-VM', type: 'vm', os: 'Windows Server 2012 R2 Standard' });
    mk({ name: 'FW-HQ', type: 'network', vendor: 'Fortinet', model: 'FortiGate 600E', os: 'FortiOS 7.4', purchase: { cost: 300000 }, warranty: { end: `${fy}-03-31`, provider: 'Fortinet FortiCare' } });
    mk({ name: 'DB02', type: 'server', os: 'Red Hat Enterprise Linux 9', warranty: { end: `${fy}-08-31` } });
    // licences: security and non-security, one expiring after the year, one without a cost
    app.licences.upsert({ id: 'lic_kav', product: 'Kaspersky Endpoint Security for Business', seats: 900, expiry: `${fy}-02-28`, cost: 420000 }, ADM);
    app.licences.upsert({ id: 'lic_m365', product: 'Microsoft 365 E3', seats: 850, expiry: `${fy}-06-30`, cost: 2400000 }, ADM);
    app.licences.upsert({ id: 'lic_far', product: 'Oracle Database Enterprise', expiry: `${fy + 2}-01-01`, cost: 900000 }, ADM);
    app.licences.upsert({ id: 'lic_nocost', product: 'Veeam Backup & Replication', expiry: `${fy}-09-30` }, ADM);
    // storage array at 90 %
    app.store.collection('storage_platforms').put({ id: 'st1', label: 'NetApp HQ', kind: 'ontap' });
    app.store.collection('storage_snapshots').put({ id: 'st1', at: now.toISOString(), pools: [{ name: 'aggr1', size_bytes: 100e12, used_bytes: 90e12 }] });

    let r = await adm('GET', '/budget');
    assert.equal(r.status, 200, r.text);
    let B = r.json;
    assert.equal(B.fy, fy); assert.equal(B.currency, 'SAR');
    assert.deepEqual(B.envelopes.map((e) => [e.id, e.envelope]), [['it_ops', 66000000], ['cyber', 30000000]]);
    const by = (id) => B.lines.find((l) => l.id === id);
    assert.deepEqual([by(`lic:lic_kav:${fy}`).envelope, by(`lic:lic_kav:${fy}`).kind, by(`lic:lic_kav:${fy}`).amount], ['cyber', 'opex', 420000]);
    assert.deepEqual([by(`lic:lic_m365:${fy}`).envelope, by(`lic:lic_m365:${fy}`).area, by(`lic:lic_m365:${fy}`).amount], ['it_ops', 'applications', 2400000]);
    assert.ok(!by(`lic:lic_far:${fy}`), 'a licence expiring after the year is not in it');
    const nc = by(`lic:lic_nocost:${fy}`);
    assert.deepEqual([nc.priced, nc.amount, nc.fit], [false, null, 'unpriced'], 'no cost recorded → price needed, never 0');
    const rep = by(`eol:${eolSrv}:${fy}`);
    assert.deepEqual([rep.kind, rep.amount, rep.envelope, rep.area], ['capex', 85000, 'it_ops', 'infrastructure']);
    assert.match(rep.basis, /original purchase cost 85,000/);
    assert.ok(!by(`sup:${eolSrv}:${fy}`), 'an asset being replaced gets no support renewal');
    const vm = B.lines.find((l) => l.source === 'eol' && /APP-VM/.test(l.title));
    assert.deepEqual([vm.title.startsWith('OS upgrade'), vm.priced], [true, false], 'VM: OS upgrade, standard cost not set yet');
    const fw = B.lines.find((l) => l.source === 'support' && /FW-HQ/.test(l.title));
    assert.deepEqual([fw.envelope, fw.kind, fw.priced], ['cyber', 'opex', false], 'firewall support → Cyber Security; no support % set → unpriced');
    const st = B.lines.find((l) => l.source === 'storage');
    assert.match(st.title, /\+29 TB/); assert.equal(st.priced, false);
    assert.equal(B.summary.unpriced, 5);
    // standard costs fill the unpriced lines; support % uses the purchase cost
    r = await adm('PUT', '/budget/settings', { body: { unit_costs: { os_upgrade: 4000, storage_tb: 15000, support_server: 12000 }, support_pct: 10, inflation_pct: 0 } });
    assert.equal(r.status, 200, r.text); B = r.json;
    assert.equal(B.lines.find((l) => l.source === 'storage').amount, 435000);
    assert.equal(B.lines.find((l) => l.source === 'support' && /FW-HQ/.test(l.title)).amount, 30000, '10% of 300,000');
    assert.equal(B.lines.find((l) => l.source === 'support' && /DB02/.test(l.title)).amount, 12000, 'no purchase cost → standard support cost');
    assert.equal(B.summary.unpriced, 1, 'only the licence with no cost is left');
    assert.equal((await adm('PUT', '/budget/settings', { body: { envelopes: { cyber: 'thirty' } } })).status, 400);
    // last year's budget: pending / in-progress carried over (approved - spent), completed and cancelled dropped
    const imp = await adm('POST', '/budget/previous', { body: { fy: fy - 1, rows: [
      { item: 'Data centre UPS replacement', budget: 'IT Operations', category: 'Infrastructure', type: 'CAPEX', approved: '1,200,000', spent: '200,000', status: 'In progress' },
      { item: 'SIEM expansion', budget: 'Cyber Security', type: 'CAPEX', approved: 2000000, spent: 0, status: 'Pending' },
      { item: 'Laptops refresh', budget: 'IT Operations', type: 'CAPEX', approved: 3000000, spent: 3000000, status: 'Completed' },
      { item: 'Old project', budget: 'IT Operations', type: 'OPEX', approved: 100000, status: 'Cancelled' },
      { description: '' },
    ] } });
    assert.equal(imp.status, 200, imp.text); assert.equal(imp.json.imported, 4); assert.equal(imp.json.skipped, 1);
    B = imp.json.budget;
    const ups = B.lines.find((l) => /UPS/.test(l.title)), siem = B.lines.find((l) => /SIEM/.test(l.title));
    assert.deepEqual([ups.source, ups.amount, ups.kind, ups.envelope, ups.area, ups.priority], ['carryover', 1000000, 'capex', 'it_ops', 'infrastructure', 'must']);
    assert.deepEqual([siem.envelope, siem.amount], ['cyber', 2000000]);
    assert.ok(!B.lines.some((l) => /Laptops|Old project/.test(l.title)));
    // a new requirement; does not fit: a 40M cyber project over the 30M envelope
    r = await adm('POST', '/budget/lines', { body: { title: 'SOC 24x7 managed service', envelope: 'cyber', kind: 'opex', amount: 40000000, priority: 'could', justification: 'NCA ECC 2-13' } });
    B = r.json;
    const soc = B.lines.find((l) => /SOC 24x7/.test(l.title));
    assert.equal(soc.fit, 'over');
    const cy = B.envelopes.find((e) => e.id === 'cyber');
    assert.equal(cy.over, 1); assert.ok(cy.headroom < 0);
    assert.equal(cy.proposed, cy.capex + cy.opex);
    // decisions: defer needs a reason; approving an unpriced line needs an amount; overrides are kept and shown
    assert.equal((await adm('POST', `/budget/lines/${encodeURIComponent(soc.id)}/decide`, { body: { status: 'deferred' } })).status, 400);
    r = await adm('POST', `/budget/lines/${encodeURIComponent(soc.id)}/decide`, { body: { status: 'deferred', note: 'phase 2 in FY' + (fy + 1) } });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.envelopes.find((e) => e.id === 'cyber').over, 0, 'a deferred line leaves the envelope');
    assert.equal((await adm('POST', `/budget/lines/${encodeURIComponent(nc.id)}/decide`, { body: { status: 'approved' } })).status, 400);
    r = await adm('POST', `/budget/lines/${encodeURIComponent(nc.id)}/decide`, { body: { status: 'approved', amount: '150000' } });
    const ncd = r.json.lines.find((l) => l.id === nc.id);
    assert.deepEqual([ncd.status, ncd.amount, ncd.priced, ncd.decided_by], ['approved', 150000, true, 'cio']);
    assert.equal((await adm('POST', `/budget/lines/${encodeURIComponent(nc.id)}/delete`, {})).status, 400, 'generated lines are rejected, not deleted');
    // roles + audit
    assert.equal((await t.as('v', 'viewer')('GET', '/budget')).status, 200);   // read-only for every role (decided Oct 2026); changes still need operator
    assert.equal((await t.req('POST', '/budget/lines', { body: { title: 'x' } })).status, 403);
    const acts = app.store.auditTail(200).map((e) => e.action);
    for (const a of ['budget.settings', 'budget.import_previous', 'budget.line_add', 'budget.decide']) assert.ok(acts.includes(a), a);
  } finally { await t.close(); }
});
