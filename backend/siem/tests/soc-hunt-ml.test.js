// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/util/brand');
// Threat Hunting machine-learning hunts (engine/soc/hunt-ml.js, POST {P}/soc/hunt/ml): DGA-like domains scored on entropy, length,
// digits, consonant runs and rarity (CDN / vendor names skipped, a normal domain not flagged), rare and Office-to-shell process
// lineage against 7 days, logon fan-out against the account's own week, the route's role (viewer refused), validation naming the
// field and the audit record. SYNTHETIC events only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const HML = require('../engine/soc/hunt-ml');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const routes = require('../engine/soc/investigate-routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600e3, DAY = 24 * H, NOW = Date.parse('2026-11-18T09:00:00Z');

test('dga: random-looking, long, digit-mixed, rare names are leads; normal and CDN names are not', () => {
  const r = HML.dga([{ domain: 'xk7q9zt2vbn4mwp8.com', n: 3, hosts: 1 }, { domain: ZYB_ORG.domain, n: 900, hosts: 300 }, { domain: 'e1234.dscb.akamaiedge.net', n: 4, hosts: 1 }, { domain: 'portal.example.invalid', n: 2, hosts: 1 }]);
  assert.deepEqual(r.map((x) => x.domain), ['xk7q9zt2vbn4mwp8.com']);
  assert.ok(r[0].score >= 80, JSON.stringify(r[0].why)); for (const f of ['entropy', 'length', 'digits', 'rare']) assert.ok(r[0].why.some((w) => w.factor === f), 'feature named: ' + f);
  assert.equal(HML.label(('mail.' + ZYB_ORG.domain)), ZYB_ORG.domain.split('.')[0], 'the label before a two-part suffix');
  assert.match(r[0].q, /^dns_query:"xk7q9zt2vbn4mwp8\.com"$/);
});

test('lineage: Word starting PowerShell on one host is a lead; a common pair is not', () => {
  const week = []; for (let i = 0; i < 30; i++) week.push({ host: 'pc-' + i, parent_process: 'C:\\Windows\\explorer.exe', process: 'C:\\Windows\\System32\\cmd.exe' });
  const recent = [{ host: 'pc-syn-7', user: 'syn.lina', parent_process: 'C:\\Program Files\\Microsoft Office\\WINWORD.EXE', process: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
    { host: 'pc-3', parent_process: 'C:\\Windows\\explorer.exe', process: 'C:\\Windows\\System32\\cmd.exe' },
    { host: 'srv-syn-2', parent_process: 'C:\\Windows\\System32\\cmd.exe', process: 'C:\\Windows\\System32\\certutil.exe' }];
  const r = HML.lineage(recent, week);
  assert.equal(r[0].parent, 'winword.exe'); assert.equal(r[0].child, 'powershell.exe'); assert.equal(r[0].score, 70);
  assert.ok(r[0].why.some((w) => /macro and document exploits/.test(w.reason)));
  assert.ok(r.some((x) => x.child === 'certutil.exe' && x.score === 50), 'a rare living-off-the-land child');
  assert.ok(!r.some((x) => x.parent === 'explorer.exe'), 'explorer starting cmd on 30 hosts is normal');
});

test('fanout: an account reaching many hosts in an hour against its own week', () => {
  const ev = [];
  for (let d = 2; d <= 7; d++) for (let h = 0; h < 2; h++) ev.push({ ts: NOW - d * DAY - h * H, user: 'syn.admin', host: 'srv-' + h });
  for (let i = 0; i < 9; i++) ev.push({ ts: NOW - 3 * H + i * 60000, user: 'syn.admin', host: 'pc-syn-' + i });
  for (let i = 0; i < 9; i++) ev.push({ ts: NOW - 3 * H + i * 60000, user: 'SRV-01$', host: 'pc-syn-' + i });
  for (let d = 1; d <= 7; d++) for (let i = 0; i < 8; i++) ev.push({ ts: NOW - d * DAY + i * 60000, user: 'syn.backup', host: 'srv-b' + i });
  for (let i = 0; i < 8; i++) ev.push({ ts: NOW - 2 * H + i * 60000, user: 'syn.backup', host: 'srv-b' + i });
  const r = HML.fanout(ev, NOW);
  assert.deepEqual(r.map((x) => x.user), ['syn.admin']); assert.equal(r[0].hosts, 9); assert.equal(r[0].usual_max, 1);
  assert.match(r[0].why, /9 hosts within one hour; at most 1 in any hour of the 7 days before/);
});

test('route: POST /soc/hunt/ml is analyst and above, validated and audited', async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  const search = { rare: async () => ({ values: [{ v: 'qz8x7k2v9bnm4wtp.net', n: 2, hosts: 1 }] }), fetchEvents: async () => [], parse: () => ({}) };
  const api = fakeApi({ realRanks: true }); routes.register(api, { state, alerts, cases, search, config: {}, log: quietLog, now: () => NOW });
  try {
    let r = await api.call('POST', '/api/soc/soc/hunt/ml', { role: 'viewer', body: {} }); assert.equal(r.status, 403);
    r = await api.call('POST', '/api/soc/soc/hunt/ml', { role: 'analyst', body: { kinds: ['nope'] } }); assert.equal(r.status, 400); assert.match(r.body.error, /kinds must be among/);
    r = await api.call('POST', '/api/soc/soc/hunt/ml', { role: 'analyst', user: 'syn.hunter', body: {} }); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.dga.items[0].domain, 'qz8x7k2v9bnm4wtp.net'); assert.deepEqual(r.body.lineage.items, []); assert.deepEqual(r.body.fanout.items, []);
    assert.ok(api.audits.some((a) => a.action === 'soc.hunt.ml' && a.user === 'syn.hunter'));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
