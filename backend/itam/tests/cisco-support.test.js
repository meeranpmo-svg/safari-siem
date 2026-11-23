// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cisco support coverage: contract export import (title lines before the header, CCW dates), manual assignment by serial,
// validation with the Cisco Support API (serials only, token + coverage-summary calls only), statuses covered / expiring /
// expired / not-covered / not-assigned / no-serial, mismatch between import and Cisco, sealed client secret, roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerCiscoSupport, createCiscoSupport, dateOf, normSerial, parseExport } = require('../engine/cisco-support');

const ADM = { user: 'syed', role: 'admin' };
const DAY = 86400000;
const day = (n) => new Date(Date.parse('2026-10-14T00:00:00Z') + n * DAY).toISOString().slice(0, 10);

test('dates and serials as the exports write them', () => {
  assert.equal(dateOf('15-Mar-2027'), '2027-03-15'); assert.equal(dateOf('2027-03-15T00:00:00Z'), '2027-03-15');
  assert.equal(dateOf('25/12/2026'), '2026-12-25'); assert.equal(dateOf('not a date'), null);
  assert.equal(normSerial(' fdo2231x0ab '), 'FDO2231X0AB');
  const p = parseExport('Cisco Commerce Workspace export\nGenerated 2026-10-01\n\nSerial Number,Contract Number,Service Level Description,Coverage End Date,Product ID\nFDO1,9001,SNT 8X5XNBD,15-Mar-2027,C9300-48P\n');
  assert.equal(p.header_line, 4); assert.equal(p.columns.serial, 'Serial Number'); assert.equal(p.rows[0]['Contract Number'], '9001');
});

test('coverage: import, assign, Cisco validation, statuses, mismatch, secret handling, roles', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const A = e.app.assets;
  const core = A.create({ name: 'CORE-SW1', type: 'network', status: 'in_use', vendor: 'Cisco', model: 'C9500-24Y4C', serial: 'FDO1111AAAA', mgmt_ip: '10.0.0.2' }, ADM).asset.id;
  const acc = A.create({ name: 'ACC-SW7', type: 'network', status: 'in_use', vendor: 'Cisco Systems', model: 'C9200L-48P', serial: 'JAE2222BBBB' }, ADM).asset.id;
  const rtr = A.create({ name: 'JED-RTR', type: 'network', status: 'in_use', model: 'ISR4331/K9', serial: 'FDO3333CCCC' }, ADM).asset.id;
  const ucs = A.create({ name: 'esx-ucs-01', type: 'server', status: 'in_use', vendor: 'Cisco Systems Inc', model: 'UCSC-C240-M5SX', serial: 'WZP4444DDDD' }, ADM).asset.id;
  A.create({ name: 'NOSERIAL-SW', type: 'network', status: 'in_use', vendor: 'Cisco', model: 'C9300-24T' }, ADM);
  A.create({ name: 'dell-r750', type: 'server', status: 'in_use', vendor: 'Dell Inc.', model: 'PowerEdge R750', serial: 'DELL1' }, ADM);
  A.create({ name: 'IP phone', type: 'phone', status: 'in_use', vendor: 'Cisco', model: 'CP-8845', serial: 'FCH5555' }, ADM);

  const calls = [];
  const request = async (url, o) => {
    calls.push({ url, method: o.method, body: o.body || '', auth: (o.headers || {}).Authorization || '' });
    if (url.endsWith('/oauth2/default/v1/token')) return /client_secret=right-secret/.test(o.body) ? { status: 200, json: { access_token: 'tok-1', expires_in: 3600 } } : { status: 401, json: {} };
    const sns = url.split('/').pop().split(',');
    return { status: 200, json: { serial_numbers: sns.map((sn) => sn === 'FDO1111AAAA' ? { sr_no: sn, is_covered: 'YES', service_contract_number: '9001', service_line_descr: 'SNT 24X7X4', coverage_end_date: day(400), orderable_pid_list: [{ orderable_pid: 'C9500-24Y4C' }] }
      : sn === 'FDO3333CCCC' ? { sr_no: sn, is_covered: 'NO', warranty_end_date: day(20), warranty_type: 'WARR-1YR-LTD-HW' }
      : sn === 'JAE2222BBBB' ? { sr_no: sn, is_covered: 'YES', service_contract_number: '9002', service_line_descr: 'SNT 8X5XNBD', coverage_end_date: day(30) }
      : { sr_no: sn, is_covered: 'YES', service_contract_number: '9100', coverage_end_date: day(-5) }) } };
  };
  const C = createCiscoSupport(e.app, { request, now: () => Date.parse('2026-10-14T08:00:00Z'), noTimer: true });
  const OP = { user: 'eng1', role: 'operator', ip: '' };

  // nothing known yet
  let rep = C.report();
  assert.equal(rep.total, 5, 'Cisco switches, router and UCS; Dell and the phone left out');
  assert.equal(rep.counts['not-assigned'], 4); assert.equal(rep.counts['no-serial'], 1);

  // import: covers CORE (expiring by import: 60 days), ACC, plus a serial we do not have
  const csv = 'Smart Net Total Care - Contract coverage\n\nSerial Number,Contract Number,Service Level,Coverage Start Date,Coverage End Date,Product ID,Install Site Name\n'
    + `fdo1111aaaa,8000,SNT 8X5XNBD,01-Jan-2026,${day(60)},C9500-24Y4C,Riyadh HQ\nJAE2222BBBB,9002,SNT 8X5XNBD,,${day(30)},C9200L-48P,Jeddah\nFOC9999ZZZZ,9002,SNT,,${day(100)},C9300,Dammam\n,,,,,,\nWZP4444DDDD,9100,SNT,,someday,UCSC,Riyadh\n`;
  const imp = C.importText({ text: csv, filename: 'sntc.csv' }, OP);
  assert.equal(imp.imported, 3); assert.equal(imp.skipped_total, 1); assert.match(imp.skipped[0].reason, /end date not understood/); assert.equal(imp.unmatched_serials, 1);
  assert.throws(() => C.importText({ text: 'Name,Value\nx,1\n' }, OP), /no serial-number column/);

  // manual assignment for the UCS server
  assert.throws(() => C.assign({ asset_id: ucs, contract: '9100' }, OP), /end date required/);
  C.assign({ asset_id: ucs, contract: '9100', service_level: 'SNT 24X7X4', end: day(200) }, OP);
  rep = C.report();
  const by = (id) => rep.rows.find((r) => r.asset_id === id);
  assert.equal(by(core).status, 'expiring'); assert.equal(by(core).days_left, 60); assert.equal(by(core).validated, false); assert.match(by(core).notes.join(' '), /Not validated with Cisco/);
  assert.equal(by(acc).status, 'expiring'); assert.equal(by(ucs).status, 'covered'); assert.equal(by(rtr).status, 'not-assigned');
  assert.equal(rep.unmatched_contracts[0].serial, 'FOC9999ZZZZ');

  // the Cisco API: client secret sealed, wrong secret refused, then validation
  assert.throws(() => C.saveConfig({ api: { enabled: true, client_id: 'cid' } }, ADM), /client id and a client secret/);
  assert.throws(() => C.saveConfig({ api: { token_url: 'http://id.cisco.com/token' } }, ADM), /https/);
  C.saveConfig({ api: { enabled: true, client_id: 'cid', client_secret: 'wrong' } }, ADM);
  let r = await C.check(OP); assert.equal(r.ok, false); assert.equal(r.error_class, 'auth');
  assert.throws(() => C.saveConfig({ api: { base_url: 'https://evil.example' } }, ADM), /enter the client secret again/, 'a saved secret never goes to a new address');
  C.saveConfig({ api: { client_secret: 'right-secret' } }, ADM);
  assert.ok(!JSON.stringify(C.config()).includes('right-secret') && !JSON.stringify(e.app.store.collection('cisco_support').all()).includes('right-secret'));
  r = await C.check(OP);
  assert.equal(r.ok, true); assert.equal(r.serials, 4); assert.equal(r.covered, 3); assert.equal(r.not_covered, 1);
  const cov = calls.filter((c) => c.method === 'GET');
  assert.equal(cov.length, 1); assert.match(cov[0].url, /^https:\/\/apix\.cisco\.com\/sn2info\/v2\/coverage\/summary\/serial_numbers\/[A-Z0-9,]+$/); assert.equal(cov[0].auth, 'Bearer tok-1');
  assert.ok(!cov[0].url.includes('CORE-SW1') && !cov[0].url.includes('10.0.0.2'), 'only serial numbers go to Cisco');

  rep = C.report();
  assert.equal(by(core).status, 'covered', 'Cisco says 400 days'); assert.equal(by(core).validated, true); assert.match(by(core).notes.join(' '), /Cisco reports contract 9001; the import record says 8000/);
  assert.equal(by(rtr).status, 'not-covered'); assert.match(by(rtr).notes.join(' '), /warranty .*until/i);
  assert.equal(by(ucs).status, 'expired', 'Cisco end date wins over the hand-entered one');
  assert.equal(rep.validated, 4);

  // SIEM ticket desk lookup: by IP, with a TAC case summary only when covered
  const cv = C.coverage({ ip: '10.0.0.2' }); assert.equal(cv.found, true); assert.equal(cv.tac.contract, '9001'); assert.equal(cv.tac.serial, 'FDO1111AAAA');
  assert.equal(C.coverage({ name: 'jed-rtr' }).tac, null); assert.equal(C.coverage({ serial: 'NOPE' }).found, false);

  // routes and roles
  registerCiscoSupport(e.app.srv, e.app);
  assert.equal((await e.req('GET', '/cisco-support/report', { role: 'viewer' })).status, 200);
  assert.equal((await e.req('POST', '/cisco-support/assign', { role: 'viewer', body: { asset_id: rtr } })).status, 403);
  assert.equal((await e.req('POST', '/cisco-support/config', { role: 'operator', body: { expiring_days: 30 } })).status, 403);
  assert.equal((await e.req('POST', '/cisco-support/unassign', { role: 'operator', body: { serial: 'WZP4444DDDD' } })).status, 200);
  const aud = e.app.store.auditTail(100, (x) => /^cisco\./.test(x.action || ''));
  assert.ok(['cisco.import', 'cisco.assign', 'cisco.config', 'cisco.check', 'cisco.unassign'].every((a) => aud.some((x) => x.action === a)));
  assert.ok(!JSON.stringify(aud).includes('right-secret'));
});

test('Cisco devices recorded with other vendor / OS wording are listed; the rest are explained, never silently missing', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const A = e.app.assets, S = e.app.store;
  const id = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset.id;
  const a1 = id({ name: 'SW-SYN-1', type: 'network', vendor: 'CiscoSystems', serial: 'SYN0001' });            // no word boundary
  const a2 = id({ name: 'SW-SYN-2', type: 'network', os: 'Cisco IOS Software, C2960X', serial: 'SYN0002' });   // vendor blank, OS says Cisco
  const a3 = id({ name: 'SW-SYN-3', type: 'network', model: 'Catalyst 9300', serial: 'SYN0003' });            // model name, no PID
  const a4 = id({ name: 'SW-SYN-4', type: 'network', serial: 'SYN0004' });
  S.collection('assets').patch(a4, (x) => { x.discovery = { vendor: 'cisco-ios', class: 'switch' }; return x; });   // vendor only in the discovery link
  const wk = id({ name: 'SW-SYN-5', type: 'workstation', vendor: 'Cisco', model: 'C9200L-24P', serial: 'SYN0005' });   // wrong type
  id({ name: 'FG-SYN', type: 'network', vendor: 'Fortinet', model: 'FG-100F', serial: 'FGT1' });
  S.collection('disc_devices').put({ id: 'dd_syn1', status: 'new', type: 'switch', hostname: 'acc-sw-syn-9', ip: '10.9.9.9', vendor: 'cisco-ios', model: 'C9200L-48P', serial: 'syn0099', methods: { netops: {} } });
  S.collection('disc_devices').put({ id: 'dd_syn2', status: 'ignored', type: 'switch', hostname: 'old', vendor: 'Cisco' });
  S.collection('disc_devices').put({ id: 'dd_syn3', status: 'new', type: 'printer', hostname: 'prn', vendor: 'HP' });
  const C = createCiscoSupport(e.app, { noTimer: true });
  const r = C.report(), ids = r.rows.map((x) => x.asset_id);
  for (const a of [a1, a2, a3, a4]) assert.ok(ids.includes(a), 'listed: ' + a);
  assert.equal(r.rows.length, 4, 'the FortiGate is not Cisco');
  assert.deepEqual(r.excluded.map((x) => [x.asset_id, /set the type to Network/.test(x.why)]), [[wk, true]]);
  assert.deepEqual(r.waiting.map((x) => [x.device_id, x.serial, x.seen_by.join()]), [['dd_syn1', 'SYN0099', 'netops']], 'a switch from the AI Network Engineer waiting for approval in Asset Discovery');
});
