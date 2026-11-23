// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Printers: Printer-MIB parsing (status, error bits, supplies, trays, alerts, page counter), issues, inventory sync,
// SAFEQ 6 usage CSV import, settings (write-only SNMP secret), routes and roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const { createPrinters, errBits } = require('../engine/printers/printers');
const { writeJsonAtomic } = require('../engine/onboard/store');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'prn-'));

// a synthetic Xerox VersaLink answering the standard Printer-MIB
function fakeXerox(o = {}) {
  const B = (s) => Buffer.from(s);
  const walks = {
    '1.3.6.1.2.1.25.3.2.1.5': [['1.3.6.1.2.1.25.3.2.1.5.1', o.devStatus || 3]],
    '1.3.6.1.2.1.25.3.5.1.1': [['1.3.6.1.2.1.25.3.5.1.1.1', 3]],
    '1.3.6.1.2.1.25.3.5.1.2': [['1.3.6.1.2.1.25.3.5.1.2.1', Buffer.from(o.err || [0x24, 0x00])]],   // bits 2 (low toner) and 5 (paper jam)
    '1.3.6.1.2.1.43.5.1.1.17': [['1.3.6.1.2.1.43.5.1.1.17.1', B('XRX-SN-0001')]],
    '1.3.6.1.2.1.43.10.2.1.4': [['1.3.6.1.2.1.43.10.2.1.4.1.1', o.pages || 123456]],
    '1.3.6.1.2.1.43.11.1.1.5': [['1.3.6.1.2.1.43.11.1.1.5.1.1', 3], ['1.3.6.1.2.1.43.11.1.1.5.1.2', 9], ['1.3.6.1.2.1.43.11.1.1.5.1.3', 4]],
    '1.3.6.1.2.1.43.11.1.1.6': [['1.3.6.1.2.1.43.11.1.1.6.1.1', B('Black Toner Cartridge')], ['1.3.6.1.2.1.43.11.1.1.6.1.2', B('Drum Cartridge')], ['1.3.6.1.2.1.43.11.1.1.6.1.3', B('Waste Cartridge')]],
    '1.3.6.1.2.1.43.11.1.1.8': [['1.3.6.1.2.1.43.11.1.1.8.1.1', 100], ['1.3.6.1.2.1.43.11.1.1.8.1.2', 100], ['1.3.6.1.2.1.43.11.1.1.8.1.3', 100]],
    '1.3.6.1.2.1.43.11.1.1.9': [['1.3.6.1.2.1.43.11.1.1.9.1.1', o.toner == null ? 4 : o.toner], ['1.3.6.1.2.1.43.11.1.1.9.1.2', 62], ['1.3.6.1.2.1.43.11.1.1.9.1.3', -3]],
    '1.3.6.1.2.1.43.8.2.1.13': [['1.3.6.1.2.1.43.8.2.1.13.1.1', B('Tray 1')], ['1.3.6.1.2.1.43.8.2.1.13.1.2', B('Bypass')]],
    '1.3.6.1.2.1.43.8.2.1.9': [['1.3.6.1.2.1.43.8.2.1.9.1.1', 520], ['1.3.6.1.2.1.43.8.2.1.9.1.2', 100]],
    '1.3.6.1.2.1.43.8.2.1.10': [['1.3.6.1.2.1.43.8.2.1.10.1.1', 260], ['1.3.6.1.2.1.43.8.2.1.10.1.2', -2]],
    '1.3.6.1.2.1.43.18.1.1.2': [['1.3.6.1.2.1.43.18.1.1.2.1.7', 3]],
    '1.3.6.1.2.1.43.18.1.1.8': [['1.3.6.1.2.1.43.18.1.1.8.1.7', B('Paper jam in tray 1')]],
    '1.3.6.1.2.1.25.3.2.1.3': [['1.3.6.1.2.1.25.3.2.1.3.1', B('Xerox VersaLink B405')]],
  };
  return (opts) => {
    if (o.down || (o.only && opts.host !== o.only)) return { get: async () => { throw new Error('request timeout'); }, walk: async () => { throw new Error('request timeout'); }, close() {} };
    if (opts.community !== 'prn-ro') return { get: async () => { throw new Error('request timeout'); }, walk: async () => [], close() {} };
    return {
      get: async () => ({ '1.3.6.1.2.1.1.1.0': B('Xerox VersaLink B405 MFP; SS 1.2'), '1.3.6.1.2.1.1.5.0': B('XRX-HQ-2F'), '1.3.6.1.2.1.1.6.0': B('HQ 2nd floor'), '1.3.6.1.2.1.1.3.0': 360000 }),
      walk: async (root) => walks[root] || [], close() {},
    };
  };
}

async function setup(o = {}) {
  const dir = tmp(), secFile = path.join(dir, 'secrets.json'); fs.writeFileSync(secFile, '{}');
  const state = await createState({ dir });
  const config = { clickhouse: { database: 'siem' } };
  Object.defineProperty(config, '_paths', { value: { config: path.join(dir, 'config.json'), secrets: secFile } });
  Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  const rows = [];
  const ch = { insertRows: async (t, r) => { rows.push(...r); }, query: async () => [{ device: 'x', d: new Date().toISOString().slice(0, 10), n: 40 }] };
  const P = createPrinters(Object.assign({ state, config, ch, snmp: fakeXerox(o.xerox), writeJson: writeJsonAtomic }, o.extra || {}));
  return { P, state, config, rows, secFile };
}

test('error bits follow RFC 2790 bit order', () => {
  assert.deepEqual(errBits(Buffer.from([0x24, 0x00])), ['low toner', 'paper jam']);
  assert.deepEqual(errBits(Buffer.from([0x00, 0x80])), ['input tray missing']);
  assert.deepEqual(errBits(Buffer.from([0x40])), ['no paper']);
});

test('poll: status, errors, toner / drum / waste, trays, alerts, pages; issues and summary; no credentials = clear error', async () => {
  const { P, rows, secFile, config } = await setup();
  const p = P.put({ ip: '192.168.20.31', name: 'XRX-HQ-2F', site: 'Riyadh HQ' }, 'adm');
  let s = await P.pollNow(p.id); assert.equal(s.ok, false); assert.match(s.error, /no SNMP credentials/);
  assert.throws(() => P.setSettings({ snmp: { version: '2c', community: '' } }, 'adm'), /community required/);
  const st = P.setSettings({ snmp: { version: '2c', community: 'prn-ro' }, toner_warn_pct: 20 }, 'adm');
  assert.equal(st.snmp.set, true); assert.ok(!JSON.stringify(st).includes('prn-ro'));
  assert.equal(JSON.parse(fs.readFileSync(secFile, 'utf8')).printers.snmp.community, 'prn-ro'); assert.equal(config.secrets.printers.snmp.community, 'prn-ro');
  s = await P.pollNow(p.id);
  assert.equal(s.ok, true); assert.equal(s.model, 'Xerox VersaLink B405'); assert.equal(s.serial, 'XRX-SN-0001'); assert.equal(s.pages_total, 123456);
  assert.deepEqual(s.errors, ['low toner', 'paper jam']); assert.equal(s.device_status, 'warning');
  assert.deepEqual(s.supplies.map((x) => [x.name, x.type, x.pct, x.state]), [['Black Toner Cartridge', 'toner', 4, 'measured'], ['Drum Cartridge', 'drum', 62, 'measured'], ['Waste Cartridge', 'waste toner', null, 'ok']]);
  assert.deepEqual(s.trays.map((x) => [x.name, x.pct]), [['Tray 1', 50], ['Bypass', null]]);
  assert.deepEqual(s.alerts, [{ text: 'Paper jam in tray 1', severity: 'critical' }]);
  const v = await P.view(); const it = v.items[0];
  assert.equal(it.status, 'error'); assert.ok(it.issues.some((x) => x.text === 'paper jam' && x.level === 'bad')); assert.ok(it.issues.some((x) => x.text === 'Black Toner Cartridge: 4% left' && x.level === 'bad'));
  assert.equal(v.summary.toner_low, 1); assert.equal(v.summary.error, 1);
  assert.ok(rows.some((r) => r.metric === 'pages_total' && r.value === 123456) && rows.some((r) => r.metric === 'toner_min_pct' && r.value === 4) && rows.some((r) => r.metric === 'printer_up' && r.value === 1));
  assert.equal(P.get(p.id).model, 'Xerox VersaLink B405', 'model / serial filled in from SNMP');
});

test('offline printer keeps its last known supplies and says why', async () => {
  const { P } = await setup({ xerox: { only: '192.168.20.31' } });
  P.setSettings({ snmp: { version: '2c', community: 'prn-ro' } }, 'adm');
  const p = P.put({ ip: '192.168.20.31' }, 'adm'); await P.pollNow(p.id);
  P.put({ id: p.id, ip: '192.168.20.99' }, 'adm');
  const s = await P.pollNow(p.id); assert.equal(s.ok, false); assert.match(s.error, /no SNMP answer/); assert.equal(s.supplies.length, 3); assert.equal(s.pages_total, 123456);
  assert.equal((await P.view()).items[0].status, 'offline');
});

test('inventory sync: printers with an IP from IT Asset Management, retired ones removed, manual kept', async () => {
  let inv = [{ id: 'as_1', name: 'XRX-HQ-1F', type: 'printer', status: 'in_use', mgmt_ip: '192.168.20.30', vendor: 'Xerox', model: 'AltaLink C8130', site: 'Riyadh HQ' },
    { id: 'as_2', name: 'XRX-JED', type: 'printer', status: 'in_use', mgmt_ip: '' }, { id: 'as_3', name: 'XRX-OLD', type: 'printer', status: 'retired', mgmt_ip: '192.168.20.40' }];
  const calls = [];
  const { P } = await setup({ extra: { discovery: { assets: async (q, who) => { calls.push([q, who.role]); return { assets: inv }; } } } });
  P.put({ ip: '192.168.21.5', name: 'manual' }, 'adm');
  const r = await P.syncFromInventory();
  assert.deepEqual(calls[0], [{ type: 'printer', limit: 5000 }, 'viewer']);
  assert.deepEqual([r.added, r.updated, r.removed, r.skipped_no_ip], [1, 0, 0, ['XRX-JED']]);
  assert.equal(P.list().find((x) => x.ip === '192.168.20.30').model, 'Xerox AltaLink C8130');
  inv = inv.map((a) => (a.id === 'as_1' ? Object.assign({}, a, { status: 'disposed' }) : a));
  assert.equal((await P.syncFromInventory()).removed, 1); assert.deepEqual(P.list().map((x) => x.name), ['manual']);
});

test('SAFEQ 6 usage CSV: column detection (; or ,), per user / department / printer, re-import replaces the period', async () => {
  const { P } = await setup();
  assert.throws(() => P.importUsage('User;Something\nali;x\n', {}, 'adm'), /no page column/);
  const csv = '﻿User name;Department;Device name;Total pages;Colour;B&W;Cost\n"ali.k";Finance;XRX-HQ-2F;120;20;100;"14,50"\nsara.m;Claims;XRX-HQ-2F;80;0;80;8\nali.k;Finance;XRX-HQ-1F;30;30;0;9\n';
  const r = P.importUsage(csv, { period: '2026-09' }, 'adm');
  assert.deepEqual([r.rows, r.pages, r.period], [3, 230, '2026-09']); assert.ok(r.columns.includes('cost') && r.columns.includes('color'));
  let u = P.usage().periods[0];
  assert.deepEqual(u.totals, { pages: 230, color: 50, mono: 180, cost: 31.5 });
  assert.deepEqual(u.by_user.map((x) => [x.name, x.pages]), [['ali.k', 150], ['sara.m', 80]]);
  assert.deepEqual(u.by_department[0], { name: 'Finance', pages: 150, color: 50, mono: 100, cost: 23.5, jobs: 0 });
  assert.equal(u.by_printer[0].name, 'XRX-HQ-2F');
  P.importUsage('Login,Pages\nbob,5\n', { period: '2026-09' }, 'adm');
  u = P.usage(); assert.equal(u.periods.length, 1); assert.equal(u.periods[0].totals.pages, 5);
});

test('routes: viewer reads, operator polls, admin changes; secrets never returned', async () => {
  const { P, state, config } = await setup();
  const routes = require('../engine/printers/routes');
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {}, warn() {} }, printers: P });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (m, p, role, b, params = {}) => { const o = {}; const ctx = { role, user: 'u', body: b, params, query: {}, need(r) { if (RANK[role] < RANK[r]) { o.s = 403; return false; } return true; }, audit() {}, ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }; const rv = await R[m + ' /api/soc/printers' + p](ctx); if (rv !== undefined && !o.s) { o.s = 200; o.b = rv; } return o; };
  assert.equal((await call('POST', '', 'operator', { ip: '10.0.0.5' })).s, 403);
  const add = await call('POST', '', 'admin', { ip: '10.0.0.5', name: 'XRX-T' }); assert.equal(add.s, 200);
  assert.equal((await call('POST', '', 'admin', { ip: 'nope' })).s, 400);
  assert.equal((await call('PUT', '/settings', 'operator', { snmp: { community: 'x' } })).s, 403);
  assert.equal((await call('PUT', '/settings', 'admin', { snmp: { version: '2c', community: 'prn-ro' } })).s, 200);
  const v = await call('GET', '', 'viewer'); assert.equal(v.b.summary.total, 1); assert.ok(!JSON.stringify(v.b).includes('prn-ro'));
  assert.equal((await call('POST', '/:id/poll', 'operator', null, { id: add.b.id })).b.ok, true);
  assert.equal((await call('POST', '/usage/import', 'admin', { csv: 'User,Pages\na,1\n', period: '2026-10' })).b.rows, 1);
  assert.equal((await call('POST', '/sync', 'admin', {})).s, 503, 'no ITAM link in this test');
  assert.equal((await call('DELETE', '/:id', 'admin', null, { id: add.b.id })).s, 200);
});
