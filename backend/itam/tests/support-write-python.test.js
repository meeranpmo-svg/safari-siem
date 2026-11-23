// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 9g (docs/PYTHON-MIGRATION.md): the Support Contracts writes decided by pyengine/support_write.py and
// committed by engine/py-writer.js must do exactly what engine/support-contracts.js does, over HTTP: new contracts with
// odd values (quantity '12' / -1 / 'x', cost '', serials to normalise, unknown family / unit / kind, a bad date, portal
// addresses - plain, upper-case host, :443, a login, http), an edit, a renewal that resets the vendor verification,
// verify / retire with and without a reference, the expiring window, and a CSV import (assets by name, a row with an
// unknown asset). Same answers, records and audit entries; Python decides every write except the portal addresses only
// the WHATWG URL parser reads.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { registerSupportContracts } = require('../engine/support-contracts');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z');

test('Python-decided Support Contracts writes do exactly what Node.js does', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const RealDate = Date, realRB = crypto.randomBytes;
  global.Date = class extends RealDate { constructor(...a) { if (a.length) super(...a); else super(NOW); } static now() { return NOW; } };
  let seq = 0;
  crypto.randomBytes = function (n, cb) { if ((n !== 5 && n !== 6) || cb) return realRB.apply(this, arguments); seq++; return Buffer.from(String(seq).padStart(2 * n, '0'), 'hex'); };   // distinct within a request too (the import makes one per row)
  t.after(() => { global.Date = RealDate; crypto.randomBytes = realRB; });
  const N = await startApp({ noAi: true, config: { supportContracts: { engine: 'node' }, assets: { engine: 'node' } } }), P = await startApp({ noAi: true, config: { discovery: { python_bin: PY } } });
  t.after(async () => { await N.close(); await P.close(); });
  for (const e of [N, P]) registerSupportContracts(e.app.srv, e.app);
  const strip = (j) => JSON.parse(JSON.stringify(j));
  let i = 0;
  const call = async (method, path, body, role = 'operator') => {
    i++;
    seq = i * 100; const a = await N.req(method, path, { body, user: 'eng1', role });
    seq = i * 100; const b = await P.req(method, path, { body, user: 'eng1', role });
    assert.equal(b.status, a.status, path + ' status ' + a.text);
    return [a, b];
  };
  const both = async (path, body, role, method = 'POST') => { const [a, b] = await call(method, path, body, role); assert.deepEqual(strip(b.json), strip(a.json), path + ' ' + JSON.stringify(body)); return a.json; };
  const A = {};
  for (const [k, body] of [['dc', { name: 'DC01', type: 'server', os: 'Windows Server 2022', serial: 'dl-1' }], ['ex', { name: 'EXCH01', type: 'vm', os: 'Windows Server 2019' }], ['old', { name: 'OLD', type: 'server' }]]) A[k] = (await both('/assets', body, 'operator')).asset.id;
  await both('/assets/' + A.old + '/retire', { reason: 'gone' });
  const w0 = i;
  const steps = [
    ['/support-contracts', { family: 'windows_server', contract_number: ' EA-1 ', end: '2027-06-30', start: '2024-07-01', quantity: '12', unit: 'cores', asset_ids: [() => A.dc, () => A.dc, ''], serials: [' dl-1 ', 'ab:cd', ''], cost: '45000.5', currency: 'usd ', portal: 'https://ServicesHub.Microsoft.com:443/support?x=1#top', notes: 'line1\nline2' }],
    ['/support-contracts', { family: 'vmware', end: '2026-12-01', quantity: -1 }],
    ['/support-contracts', { family: 'vmware', end: '2026-12-01', quantity: 'x' }],
    ['/support-contracts', { family: 'nutanix', end: '2026/12/01' }],
    ['/support-contracts', { family: 'toString', end: '2026-12-01' }],             // FAMILIES['toString'] in JS: Node.js decides
    ['/support-contracts', { family: 'spaceship', end: '2026-12-01' }],
    ['/support-contracts', { family: 'hardware', end: '2026-12-01' }],
    ['/support-contracts', { family: 'hardware', vendor: 'Dell', end: '2026-12-01', unit: 'litres' }],
    ['/support-contracts', { family: 'other', vendor: 'Acme', end: '2026-12-01', kind: 'magic' }],
    ['/support-contracts', { family: 'other', vendor: 'Acme', end: '2026-12-01', asset_ids: ['as_nope'] }],
    ['/support-contracts', { family: 'other', vendor: 'Acme', end: '2026-12-01', cost: '' , quantity: null, portal: 'www.acme.com' }],
    ['/support-contracts', { family: 'cisco', end: '2027-01-31', portal: 'https://user:pw@mycase.cisco.com/' }],   // a login: Node.js decides
    ['/support-contracts', { family: 'cisco', end: '2027-01-31', portal: 'http://mycase.cisco.com/' }],            // another scheme: Node.js decides
    ['/support-contracts', { family: 'rhel', end: '2026-11-30', start: '', cost: -5 }],
    ['/support-contracts', { id: 'sc_nope', family: 'rhel', end: '2026-11-30' }],
  ];
  const val = (v) => (typeof v === 'function' ? v() : Array.isArray(v) ? v.map(val) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, val(x)])) : v);
  let win = null;
  for (const [p, body] of steps) { const r = await both(p, val(body)); if (!win && r && r.family === 'windows_server') win = r.id; }
  assert.ok(win);
  await both('/support-contracts/' + win + '/verify', { reference: ' partner e-mail 14 Oct ' });
  await both('/support-contracts/' + win + '/verify', { reference: '  ' });
  await both('/support-contracts', { id: win, level: 'Unified Enterprise', owner: 'Infra' });            // edit: verification kept
  await both('/support-contracts', { id: win, end: '2028-06-30', quantity: '' });                       // renewal: verification reset
  await both('/support-contracts/' + win + '/retire', {});
  await both('/support-contracts/' + win + '/retire', { reason: 'moved to CSP' });
  await both('/support-contracts/nope/verify', { reference: 'x' });
  await both('/support-contracts/settings', { expiring_days: '60' }, 'admin', 'PUT');
  await both('/support-contracts/settings', { expiring_days: 3 }, 'admin', 'PUT');
  await both('/support-contracts/settings', { expiring_days: 30.5 }, 'admin', 'PUT');
  // the import makes one id per created row (random in both engines): compared without the ids
  const csv = 'Vendor,Family,Product,Contract Number,End Date,Qty,Unit,Serial numbers,Assets,Cost\n' +
    'Microsoft,Windows Server,,EA-2,2027-01-31,2,servers,"S1; s2|S1",DC01;exch01,100\n' +
    'Dell,hardware,ProSupport,D-9,2026-12-31,,,,NOPE,\n' +
    ',exchange,,EX-3,2027/01/01,,,,,\n' +
    'Red Hat,rhel,,RH-4,2027-03-31,1,,,,""\n';
  const [ia, ib] = await call('POST', '/support-contracts/import', { text: csv });
  assert.deepEqual(strip(ib.json), strip(ia.json), 'import answer');
  const writes = i - w0;
  const noId = (e) => strip(e.app.store.collection('support_contracts').all()).map(({ id, ...r }) => r).sort((x, y) => (x.contract_number + x.family).localeCompare(y.contract_number + y.family));
  assert.deepEqual(noId(P), noId(N), 'the same contracts');
  assert.deepEqual(P.app.store.collection('support_contracts_cfg').all(), N.app.store.collection('support_contracts_cfg').all());
  const audits = (e) => strip(e.app.store.auditTail(2000, (x) => /^support\./.test(x.action)).map(({ at, prev, hash, seq: _s, target, ...rest }) => rest));
  assert.deepEqual(audits(P), audits(N), 'the same audit entries');
  const st = P.app.supportWriteStats();
  assert.deepEqual({ python: st.python, node: st.node, changed: st.changed_meanwhile }, { python: writes - 3, node: 3, changed: 0 }, 'Python decided all but the 3 handed back: ' + JSON.stringify(st));
  assert.deepEqual(st.node_by_op, { 'support.put': 3 });
  const rec = P.app.store.collection('support_contracts').get(win);
  assert.equal(rec.portal, 'https://serviceshub.microsoft.com/support?x=1#top', 'the portal normalised as the URL parser does');
  assert.equal(rec.verified, null, 'the renewal reset the verification'); assert.equal(rec.status, 'retired');
  assert.deepEqual(rec.serials, ['DL1', 'ABCD']);
});
