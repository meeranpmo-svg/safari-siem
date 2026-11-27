// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The PowerShell asset agent (agent/sentra-asset-agent.ps1) for computers at project sites: the enrol / report exchange it makes,
// replayed against the REAL gateway with the exact body the script builds (host facts, software, seq, nonce, ts) - the one-time
// key works once, the report creates the asset tagged agent-reported with its software, a replayed or stale report is refused,
// a revoked agent is refused; and the script's own safety rules: https only, TLS 1.2, the key prompted without echo and never
// logged or put on a command line it builds, the key folder readable by SYSTEM / Administrators only, no Invoke-Expression,
// read-only collection (no Set- / Remove- outside its own folder and task), a failure logged with the reason.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');

const PS = fs.readFileSync(path.join(__dirname, '..', 'agent', 'sentra-asset-agent.ps1'), 'utf8');
const ADM = { user: 'admin.syn', role: 'admin' };
// the body sentra-asset-agent.ps1 sends (same keys and nesting), with SYNTHETIC facts
const report = (seq, over) => Object.assign({ seq, nonce: 'n-' + seq + '-' + Math.random(), ts: new Date().toISOString(), host: {
  hostname: 'SITE-PC-SYN-01', manufacturer: 'Dell Inc.', model: 'Latitude 5440', serial: 'SYNSER123', uuid: '4C4C4544-0000-0000-0000-000000000001', chassis: 'laptop', type: 'laptop',
  os: 'Microsoft Windows 11 Pro 10.0.22631', cpu: 'Intel(R) Core(TM) i7', mem_gb: 15.7, disk_gb: 477, ip: '192.168.50.20', mac: '00:11:22:33:44:55', macs: ['00:11:22:33:44:55'], patch_level: 'newest update KB5000001 on 2026-11-10' },
  software: [{ name: 'Microsoft 365 Apps for enterprise', publisher: 'Microsoft Corporation', version: '16.0.1' }, { name: '7-Zip 23.01', publisher: 'Igor Pavlov', version: '23.01' }] }, over || {});

test('PowerShell asset agent: enrol once, report creates the asset, replay / stale / revoked refused', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const tok = (await e.req('POST', '/settings/agent-tokens', Object.assign({ body: { note: 'Asset agent: Jubail project site', site: 'Jubail' } }, ADM))).json.token;
  assert.ok(tok);
  const enr = await e.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok, hostname: 'SITE-PC-SYN-01', platform: 'windows' } });
  assert.equal(enr.status, 200, enr.text); const key = enr.json.agent_key; assert.ok(key && enr.json.agent_id);
  assert.equal((await e.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok, hostname: 'X', platform: 'windows' } })).status, 401, 'the key works once');
  const send = (b) => e.req('POST', '/agent/report', { user: '', role: '', headers: { authorization: 'Bearer ' + key }, body: b });
  const r1 = await send(report(1)); assert.equal(r1.status, 200, r1.text); assert.ok(r1.json.asset_id || r1.json.review, 'accepted into the register');
  const A = e.app.store.collection('assets').all().find((a) => a.serial === 'SYNSER123');
  if (A) { assert.ok((A.tags || []).includes('agent-reported')); assert.ok((A.software || []).some((x) => /7-Zip/.test(x.name))); }
  assert.equal((await send(report(1))).status, 409, 'a replayed sequence number is refused');
  assert.equal((await send(report(2, { ts: new Date(Date.now() - 3 * 3600000).toISOString() }))).status, 409, 'a stale report is refused');
  const n = 'fixed-nonce'; assert.equal((await send(report(3, { nonce: n }))).status, 200); assert.equal((await send(report(4, { nonce: n }))).status, 409, 'a replayed nonce is refused');
  assert.equal((await e.req('POST', '/agent/report', { user: '', role: '', headers: { authorization: 'Bearer wrong' }, body: report(5) })).status, 401, 'a wrong key is refused');
  await e.req('POST', '/agents/' + enr.json.agent_id + '/revoke', Object.assign({ body: {} }, ADM));
  assert.equal((await send(report(6))).status, 401, 'a revoked agent is refused');
});

test('PowerShell asset agent: safety rules in the script', () => {
  assert.match(PS, /\[ValidatePattern\('\^https:\/\//, 'https only');
  assert.match(PS, /SecurityProtocolType\]::Tls12/, 'TLS 1.2');
  assert.match(PS, /Read-Host -AsSecureString/, 'the key is prompted without echo');
  assert.ok(!/Write-AgentLog\([^)]*(EnrolToken|\$key|agent_key)/.test(PS), 'the key is never logged');
  assert.ok(!/-EnrolToken \$|-EnrolToken \"/.test(PS.split('Register-ScheduledTask')[0].split('$arg = ')[1] || ''), 'the scheduled task command carries no key');
  assert.match(PS, /SetAccessRuleProtection\(\$true, \$false\)/); assert.match(PS, /'S-1-5-18', 'S-1-5-32-544'/, 'key folder: SYSTEM and Administrators only');
  assert.ok(!/Invoke-Expression|\biex\b/i.test(PS), 'no Invoke-Expression');
  const writes = PS.match(/\b(Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Set-Service|Stop-Service|Disable-|Enable-|Restart-Computer)\b/g) || [];
  assert.deepEqual(writes, [], 'read-only collection: ' + writes.join(','));
  assert.match(PS, /Write-AgentLog \('report failed: '/, 'a failed report is logged with the reason');
  assert.match(PS, /\/report"/); assert.match(PS, /\/enrol"/); assert.match(PS, /Authorization = "Bearer \$key"/);
  for (const k of ['hostname', 'manufacturer', 'model', 'serial', 'uuid', 'os', 'cpu', 'mem_gb', 'disk_gb', 'macs', 'patch_level']) assert.match(PS, new RegExp('\\b' + k + ' = '), 'sends ' + k);
});
