// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// An asset added or changed reaches every related list straight away (engine/asset-propagate.js): one run of the related
// syncs shortly after the last change (debounced), the syncs' own write-backs during the run do not start another, a failed
// sync is reported and audited, operator reads the status. Exchange evidence (engine/exchange-evidence.js): Active
// Directory's Exchange server objects, the Exchange cmdlet log hosts and Exchange ports seen by Asset Discovery mark the
// asset, with the reason. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createAssetPropagate } = require('../engine/asset-propagate');
const { exchangeHints } = require('../engine/exchange-evidence');
const ADM = { user: 'syed', role: 'admin' };
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('propagation: changes are batched into one run of the related syncs; write-backs during the run are ignored; failures audited', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const audits = []; const orig = e.app.audit; e.app.audit = (r) => { audits.push(r); if (orig) orig.call(e.app, r); };
  const calls = [];
  e.app.addons = Object.assign(e.app.addons || {}, {
    sysadminSync: { run: async (who) => { calls.push(['sysadmin', who.user]); e.app.assets.create({ name: 'WRITEBACK-SYN', type: 'server', status: 'in_use' }, ADM); return { ok: true }; } },
    netopsSync: { run: async () => { calls.push(['netops']); return { ok: false, error: 'SIEM not reachable' }; } },
    hardening: { refresh: () => { calls.push(['hardening']); return { ok: true }; } },
  });
  const P = createAssetPropagate(e.app, { debounceMs: 60, maxWaitMs: 300 });
  e.app.store.onChange('assets', () => P.changedNow());
  for (let i = 0; i < 3; i++) e.app.assets.create({ name: 'EXCH-SYN-0' + i, type: 'server', os: 'Windows Server 2019', mgmt_ip: '10.8.0.6' + i, status: 'in_use' }, ADM);
  assert.equal(P.view().scheduled, true);
  await wait(250);
  assert.deepEqual(calls.map((c) => c[0]), ['sysadmin', 'netops', 'hardening'], 'one run for three changes, every related sync');
  assert.equal(calls[0][1], 'system:asset-propagate');
  await wait(200);
  assert.equal(calls.length, 3, 'the write-back made by a sync during the run did not start another run');
  assert.equal(P.view().last.changes, 3);
  assert.deepEqual(P.view().last.steps.map((s) => [s.name, s.ok]), [['AI Windows / Exchange Server Administrators', true], ['AI Network Engineer', false], ['Baseline Hardening', true]]);
  assert.ok(audits.some((a) => a.action === 'assets.propagate' && a.detail.steps.includes('AI Network Engineer (failed)')));
  e.app.assets.create({ name: 'NEW-SYN', type: 'server', status: 'in_use' }, ADM); await wait(250);
  assert.equal(calls.length, 6, 'a later change runs again');
  P.stop();
  assert.equal((await e.req('GET', '/asset-propagate', { user: 'v', role: 'viewer' })).status, 403);
  assert.equal((await e.req('GET', '/asset-propagate', { user: 'o', role: 'operator' })).status, 200);
});

test('Exchange evidence: AD server objects, cmdlet log hosts and Exchange ports mark the asset, with the reason', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const S = e.app.store, seen = S.collection('exchange_seen');
  seen.put({ id: 'ad', servers: [{ name: 'SYNMSG01', fqdn: 'synmsg01.corp-hq.test', version: 'Version 15.2 (Build 1544.4)', roles: ['mailbox'] }], names: ['SYNMSG01'] });
  seen.put({ id: 'siem-cmdlets', names: ['synmsg02.corp-hq.test'], ips: ['10.8.0.72'] });
  S.collection('disc_devices').put({ id: 'dd1', ip: '10.8.0.73', ips: ['10.8.0.73'], asset_id: 'a-ports', open_ports: [25, 443, 444, 3389] });
  S.collection('disc_devices').put({ id: 'dd2', ip: '10.8.0.74', ips: ['10.8.0.74'], open_ports: [443, 3389] });
  const H = exchangeHints(e.app);
  assert.match(H.forAsset({ id: 'x1', name: 'SYNMSG01' }), /Active Directory: Exchange server object \(Version 15\.2 \(Build 1544\.4\)\), mailbox/);
  assert.match(H.forAsset({ id: 'x2', name: 'synmsg01.corp-hq.test' }), /Active Directory/, 'FQDN matches the short name');
  assert.match(H.forAsset({ id: 'x3', name: 'OTHER', mgmt_ip: '10.8.0.72' }), /cmdlet log/);
  assert.match(H.forAsset({ id: 'x4', name: 'synmsg02' }), /cmdlet log/);
  assert.match(H.forAsset({ id: 'a-ports', name: 'SRV9' }), /Exchange ports open \(25, 443, 444\)/);
  assert.equal(H.forAsset({ id: 'x5', name: 'WEB01', mgmt_ip: '10.8.0.74' }), '', '443 alone is not Exchange');
});
