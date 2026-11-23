// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Exchange hybrid parsers: on-prem admin audit (MSExchange Management), Exchange Online (Management Activity API),
// message tracking logs, IIS W3C logs of the Exchange web front end. ALL DATA IS SYNTHETIC (test.local / test-ex*,
// documentation IP ranges, made-up message ids).
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createParser } = require('../engine/parse');
const exchange = require('../engine/parse/exchange');
const { CATEGORIES, OUTCOMES, FIELD_NAMES } = require('../engine/schema');

const parser = createParser({ config: {} });
const RTS = Date.UTC(2024, 4, 1, 12, 0, 0);
const p = (line, meta = {}) => parser.parse(line, { collector: 'syslog-tcp', src_id: 'test-exch', peer_ip: '10.20.0.5', rts: RTS, tz_offset_min: 0, ...meta });
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
function valid(ev) {
  for (const f of FIELD_NAMES) assert.ok(f in ev, 'missing ' + f);
  assert.ok(CATEGORIES.includes(ev.category), ev.category);
  assert.ok(OUTCOMES.includes(ev.outcome));
  assert.equal(ev.raw_body, undefined);
  return ev;
}

test('cmdlet parameter strings: quoted values, switches, colon syntax, Exchange 2010 braces', () => {
  assert.deepEqual(exchange.parseCmdletParams('-Identity "Alice Smith" -ForwardTo "x@test.invalid","y@test.invalid" -StopProcessingRules $true -Enabled -Priority:1'),
    { Identity: 'Alice Smith', ForwardTo: '"x@test.invalid","y@test.invalid"', StopProcessingRules: '$true', Enabled: 'True', Priority: '1' });
  assert.deepEqual(exchange.parseCmdletParams("-Identity 'bob-test' -Name 'It''s -synthetic'"), { Identity: 'bob-test', Name: "It's -synthetic" });
  assert.deepEqual(exchange.parseCmdletParams('{Identity=test.local/Users/Carol, ForwardingSmtpAddress=smtp:z@test.invalid}'), { Identity: 'test.local/Users/Carol', ForwardingSmtpAddress: 'smtp:z@test.invalid' });
  assert.deepEqual(exchange.parseCmdletParams(''), {});
});

test('cmdlet classification', () => {
  const c = (n, prm) => exchange.classifyCmdlet(n, prm);
  assert.equal(c('Set-Mailbox', { Identity: 'bob', ForwardingSmtpAddress: 'smtp:x@test.invalid' }).action, 'mail-forwarding-set');
  assert.equal(c('Set-Mailbox', { Identity: 'bob', DeliverToMailboxAndForward: '$true' }).action, 'mail-forwarding-set');
  assert.equal(c('Set-Mailbox', { Identity: 'bob', ForwardingSmtpAddress: '$null' }).action, 'mail-forwarding-removed');
  assert.equal(c('Set-Mailbox', { Identity: 'bob', AuditEnabled: '$false' }).action, 'audit-disabled');
  assert.equal(c('Set-Mailbox', { Identity: 'bob', Office: 'x' }).action, 'mailbox-modified');
  let r = c('New-InboxRule', { Mailbox: 'Bob', ForwardTo: 'x@test.invalid' });
  assert.deepEqual([r.action, r.severity, r.target], ['inbox-rule-created', 3, 'bob']);
  assert.ok(r.tags.includes('T1114.003'));
  assert.ok(c('Set-InboxRule', { Identity: 'r', DeleteMessage: 'True' }).tags.includes('T1564.008'));
  assert.equal(c('Add-MailboxPermission', { Identity: 'ceo', User: 'x', AccessRights: 'FullAccess' }).severity, 3);
  assert.equal(c('Add-RecipientPermission', { Identity: 'ceo', Trustee: 'x', AccessRights: 'SendAs' }).action, 'sendas-permission-added');
  assert.equal(c('Add-ADPermission', { Identity: 'ceo', User: 'x', ExtendedRights: 'Send-As' }).action, 'sendas-permission-added');
  r = c('New-TransportRule', { Name: 'r1', BlindCopyTo: 'x@test.invalid' });
  assert.deepEqual([r.category, r.action, r.severity], ['policy', 'transport-rule-created', 3]);
  assert.equal(c('Set-TransportRule', { Identity: 'r1', Comments: 'x' }).severity, 2);
  r = c('New-ManagementRoleAssignment', { Role: 'ApplicationImpersonation', User: 'svc' });
  assert.deepEqual([r.category, r.action, r.severity], ['iam', 'role-assigned', 4]);
  for (const n of ['Set-InboundConnector', 'New-OutboundConnector', 'Remove-SendConnector', 'Set-ReceiveConnector']) assert.equal(c(n, {}).action, 'mail-connector-changed', n);
  assert.equal(c('Set-OrganizationRelationship', { Identity: 'O365' }).action, 'org-relationship-changed');
  assert.equal(c('Set-HybridConfiguration', {}).action, 'hybrid-config-changed');
  assert.equal(c('Set-RemoteDomain', { Identity: 'Default', AutoForwardEnabled: '$true' }).action, 'mail-forwarding-set');
  assert.equal(c('New-MailboxExportRequest', { Mailbox: 'ceo', FilePath: '\\\\test-fs\\x.pst' }).severity, 4);
  assert.equal(c('Set-AdminAuditLogConfig', { AdminAuditLogEnabled: '$false' }).action, 'audit-disabled');
  assert.equal(c('Get-Mailbox', { Identity: 'x' }).action, 'config-read');
  assert.equal(c('Set-OwaVirtualDirectory', {}).action, 'config-change');
});

const MGMT = (eid, data, message) => JSON.stringify({ Channel: 'MSExchange Management', EventID: eid, TimeCreated: '2024-05-01T10:00:00.000Z', Computer: 'TEST-EX01.test.local', RecordId: 77, Level: eid === 6 ? 2 : 4, ProviderName: 'MSExchange CmdletLogs', EventData: data, Message: message });

test('on-prem MSExchange Management: EventID 1 / 6 → exchange-cmdlet', () => {
  let ev = valid(p(MGMT(1, { Data0: 'Set-Mailbox', Data1: '-Identity "test.local/Users/Bob" -ForwardingSmtpAddress "smtp:exfil@test.invalid" -DeliverToMailboxAndForward $true', Data2: 'test.local/Users/Admin1', Data3: 'S-1-5-21-0-0-0-500' }), { src_type: 'windows', collector: 'agent' }));
  assert.equal(ev.src_type, 'windows');
  assert.equal(ev.action, 'exchange-cmdlet');
  assert.equal(ev.category, 'email');
  assert.equal(ev.outcome, 'success');
  assert.equal(ev.severity, 3);
  assert.equal(ev.user, 'admin1');
  assert.equal(ev.target_user, 'test.local/users/bob');
  assert.equal(ev.fields.cmdlet, 'Set-Mailbox');
  assert.equal(ev.fields.exchange_action, 'mail-forwarding-set');
  assert.equal(ev.fields['params.ForwardingSmtpAddress'], 'smtp:exfil@test.invalid');
  assert.equal(ev.fields.Operation, 'Set-Mailbox');
  assert.match(ev.fields.Parameters, /ForwardingSmtpAddress/);
  assert.ok(ev.tags.includes('T1114.003') && ev.tags.includes('exchange-onprem'));
  assert.equal(ev.event_code, '1');
  // failure event, parsed from the rendered message only
  ev = valid(p(MGMT(6, {}, 'Cmdlet failed. Cmdlet New-InboxRule, parameters -Mailbox "carol" -Name "sync" -RedirectTo "x@test.invalid".')));
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.fields.cmdlet, 'New-InboxRule');
  assert.equal(ev.fields['params.RedirectTo'], 'x@test.invalid');
  assert.equal(ev.fields.exchange_action, 'inbox-rule-created');
  // other event ids of the channel stay generic
  ev = valid(p(MGMT(2, { Data0: 'x' })));
  assert.equal(ev.action, 'event');
});

const UAL = (o) => JSON.stringify({ CreationTime: '2024-05-01T10:00:00', Id: crypto.randomUUID(), OrganizationId: '00000000-0000-0000-0000-000000000000', UserType: 2, UserKey: 'x', ResultStatus: 'True', ...o });

test('Exchange Online admin cmdlets (RecordType 1) incl. hybrid connectors', () => {
  const cases = [
    ['Set-Mailbox', [{ Name: 'Identity', Value: 'bob@test.local' }, { Name: 'ForwardingSmtpAddress', Value: 'smtp:x@test.invalid' }], 'mail-forwarding-set', 'email'],
    ['New-InboxRule', [{ Name: 'Mailbox', Value: 'bob@test.local' }, { Name: 'ForwardAsAttachmentTo', Value: 'x@test.invalid' }], 'inbox-rule-created', 'email'],
    ['Add-MailboxPermission', [{ Name: 'Identity', Value: 'ceo@test.local' }, { Name: 'AccessRights', Value: 'FullAccess' }], 'mailbox-permission-added', 'iam'],
    ['Add-RecipientPermission', [{ Name: 'Identity', Value: 'ceo@test.local' }, { Name: 'AccessRights', Value: 'SendAs' }], 'sendas-permission-added', 'iam'],
    ['New-TransportRule', [{ Name: 'Name', Value: 'r' }, { Name: 'BlindCopyTo', Value: 'x@test.invalid' }], 'transport-rule-created', 'policy'],
    ['New-ManagementRoleAssignment', [{ Name: 'Role', Value: 'ApplicationImpersonation' }], 'role-assigned', 'iam'],
    ['Set-InboundConnector', [{ Name: 'Identity', Value: 'Inbound from test-ex01' }, { Name: 'TlsSenderCertificateName', Value: 'test.local' }], 'mail-connector-changed', 'policy'],
    ['New-OutboundConnector', [{ Name: 'Name', Value: 'Outbound to test-ex01' }, { Name: 'SmartHosts', Value: 'test-ex01.test.local' }], 'mail-connector-changed', 'policy'],
    ['Set-OrganizationRelationship', [{ Name: 'Identity', Value: 'O365 to On-premises' }], 'org-relationship-changed', 'policy'],
  ];
  for (const [op, params, action, category] of cases) {
    const ev = valid(p(UAL({ Operation: op, RecordType: 1, Workload: 'Exchange', UserId: 'Admin@test.local', ClientIP: '[2001:db8::5]:52000', ObjectId: 'obj', Parameters: params, ExternalAccess: false }), { src_type: 'm365', collector: 'm365' }));
    assert.equal(ev.src_type, 'm365', op);
    assert.equal(ev.action, action, op);
    assert.equal(ev.category, category, op);
    assert.equal(ev.event_code, op);
    assert.equal(ev.user, 'admin@test.local');
    assert.equal(ev.src_ip, '2001:db8::5');
    assert.equal(ev.fields.Operation, op);
    assert.ok(ev.fields.Parameters.includes(params[0].Name), 'raw Parameters kept');
    assert.equal(ev.fields['params.' + params[0].Name], params[0].Value);
    assert.ok(ev.tags.includes('exchange-online'));
  }
});

test('Exchange Online mailbox audit: MailItemsAccessed, Send (subject hashed, raw redacted), SendAs', () => {
  let ev = valid(p(UAL({ Operation: 'MailItemsAccessed', RecordType: 50, Workload: 'Exchange', UserId: 'svc-sync@test.local', MailboxOwnerUPN: 'CEO@test.local', ClientIPAddress: '203.0.113.20', ClientInfoString: 'Client=REST;Client=RESTSystem;', OperationProperties: [{ Name: 'MailAccessType', Value: 'Sync' }, { Name: 'IsThrottled', Value: 'False' }], OperationCount: 1 })));
  assert.equal(ev.category, 'email');
  assert.equal(ev.action, 'mail-items-accessed');
  assert.equal(ev.target_user, 'ceo@test.local');
  assert.equal(ev.fields.mail_access_type, 'Sync');
  assert.ok(ev.tags.includes('mail-sync') && ev.tags.includes('delegate-access'));
  const subject = 'Synthetic board minutes, do not share';
  const line = UAL({ Operation: 'Send', RecordType: 2, Workload: 'Exchange', UserId: 'alice@test.local', MailboxOwnerUPN: 'alice@test.local', ClientIPAddress: '198.51.100.9', Item: { Id: 'x', Subject: subject, InternetMessageId: '<synthetic-1@test.local>', SizeInBytes: 2048 } });
  ev = valid(p(line));
  assert.equal(ev.action, 'send');
  assert.equal(ev.fields.subject_sha256, sha(subject));
  assert.equal(ev.fields.internet_message_id, '<synthetic-1@test.local>');
  assert.ok(!ev.raw.includes('board minutes'), 'subject must not be stored in raw');
  assert.ok(!JSON.stringify(ev.fields).includes('board minutes'), 'subject must not be stored in fields');
  assert.ok(ev.raw.includes('sha256:' + sha(subject)));
  ev = valid(p(UAL({ Operation: 'SendAs', RecordType: 2, Workload: 'Exchange', UserId: 'mallory@test.local', SendAsUserSmtp: 'CFO@test.local', Item: { Subject: 'x' } })));
  assert.equal(ev.action, 'send-as');
  assert.equal(ev.target_user, 'cfo@test.local');
  assert.ok(ev.tags.includes('impersonation'));
  // existing Entra records unaffected
  ev = valid(p(UAL({ Operation: 'UserLoginFailed', RecordType: 15, Workload: 'AzureActiveDirectory', UserId: 'bob@test.local', ClientIP: '203.0.113.5' })));
  assert.equal(ev.action, 'logon-failed');
});

const csv = (vals) => vals.map((v) => (/[",]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v)).join(',');
const TRK = (over = {}) => {
  const m = Object.fromEntries(exchange.MSGTRK_FIELDS.map((f) => [f, '']));
  Object.assign(m, {
    'date-time': '2024-05-01T10:00:00.123Z', 'client-ip': '10.20.0.15', 'client-hostname': 'TEST-EX01', 'server-ip': '10.20.0.16', 'server-hostname': 'TEST-EX02',
    'source-context': '08D00000SYNTHETIC;250 2.0.0 OK', 'connector-id': 'TEST-EX01\\Default TEST-EX01', source: 'STOREDRIVER', 'event-id': 'DELIVER',
    'internal-message-id': '12345678', 'message-id': '<synthetic-0001@test-ex01.test.local>', 'network-message-id': 'aaaabbbb-0000-1111-2222-333344445555',
    'recipient-address': 'Bob@test.local;carol@test.local', 'recipient-status': '250 2.1.5 Recipient OK;250 2.1.5 Recipient OK', 'total-bytes': '5120',
    'recipient-count': '2', 'message-subject': 'Quarterly results, "confidential"', 'sender-address': 'Alice@test.local', 'return-path': 'alice@test.local',
    'message-info': '2024-05-01T09:59:59.000Z;SRV=TEST-EX01', directionality: 'Originating', 'original-client-ip': '10.20.0.99', 'transport-traffic-type': 'Email',
    'log-id': 'log-0001', 'schema-version': '15.02.1544.004',
  }, over);
  return csv(exchange.MSGTRK_FIELDS.map((f) => m[f]));
};

test('message tracking CSV: default field order, subject hashed + redacted in raw, actions, tag-derived host', () => {
  const line = TRK();
  let ev = valid(p(line, { src_type: 'exchange' }));
  assert.equal(ev.src_type, 'exchange');
  assert.equal(ev.category, 'email');
  assert.equal(ev.action, 'deliver');
  assert.equal(ev.outcome, 'success');
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 10, 0, 0, 123));
  assert.equal(ev.user, 'alice@test.local');
  assert.equal(ev.target_user, 'bob@test.local');
  assert.equal(ev.fields.recipients, 'bob@test.local;carol@test.local');
  assert.equal(ev.src_ip, '10.20.0.15');
  assert.equal(ev.fields.message_id, '<synthetic-0001@test-ex01.test.local>');
  assert.equal(ev.fields.subject_sha256, sha('Quarterly results, "confidential"'));
  assert.equal(ev.fields.subject, undefined);
  assert.ok(!ev.raw.includes('Quarterly'), 'subject redacted from raw');
  assert.ok(ev.raw.includes('sha256:' + sha('Quarterly results, "confidential"')));
  assert.equal(ev.raw.split(',').length, line.split(',').length - 1, 'other columns kept (the quoted subject had one comma)');
  for (const [id, action, outcome] of [['RECEIVE', 'receive', 'success'], ['SEND', 'send', 'success'], ['FAIL', 'fail', 'failure'], ['DSN', 'dsn', 'unknown'], ['AGENTINFO', 'transport', 'unknown']]) {
    ev = valid(p(TRK({ 'event-id': id })));
    assert.equal(ev.src_type, 'exchange', id);
    assert.equal(ev.action, action, id);
    assert.equal(ev.outcome, outcome, id);
  }
  ev = valid(p('<134>May  1 10:00:00 test-collector-01 exmsgtrk-TEST-EX01: ' + TRK({ 'event-id': 'SEND' })));
  assert.equal(ev.host, 'test-ex01');
  assert.ok(ev.raw.startsWith('<134>May  1 10:00:00 test-collector-01 exmsgtrk-TEST-EX01: 2024-05-01T10:00:00.123Z'));
  assert.ok(!ev.raw.includes('Quarterly'));
});

test('message tracking: #Fields header defines the column order for that stream', () => {
  const meta = { src_id: 'test-exch-hdr', src_type: 'exchange' };
  const hdr = valid(p('#Fields: event-id,date-time,sender-address,recipient-address,message-subject,client-ip', meta));
  assert.equal(hdr.fields.log_header, '1');
  const ev = valid(p('SEND,2024-05-01T11:00:00.000Z,dave@test.local,erin@test.local,Synthetic hello,10.20.0.30', meta));
  assert.equal(ev.action, 'send');
  assert.equal(ev.user, 'dave@test.local');
  assert.equal(ev.src_ip, '10.20.0.30');
  assert.equal(ev.fields.subject_sha256, sha('Synthetic hello'));
  assert.ok(!ev.raw.includes('Synthetic hello'));
});

test('message tracking JSON shapes: #Fields-keyed and Get-MessageTrackingLog objects', () => {
  let ev = valid(p(JSON.stringify({ server: 'TEST-EX02', 'date-time': '2024-05-01T10:00:00.000Z', 'event-id': 'RECEIVE', 'sender-address': 'x@test.invalid', 'recipient-address': 'bob@test.local', 'message-subject': 'Synthetic invoice', 'client-ip': '203.0.113.7', source: 'SMTP' }), { collector: 'agent', src_type: 'exchange' }));
  assert.equal(ev.action, 'receive');
  assert.equal(ev.host, 'test-ex02');
  assert.equal(ev.src_ip, '203.0.113.7');
  assert.ok(!ev.raw.includes('Synthetic invoice'));
  const obj = { Timestamp: '/Date(1714557600000)/', EventId: 'SEND', Source: 'SMTP', Sender: 'alice@test.local', Recipients: ['x@test.invalid', 'y@test.invalid'], MessageSubject: 'Synthetic export', MessageId: '<synthetic-2@test.local>', ClientIp: '10.20.0.15', ServerHostname: 'relay.test.invalid', TotalBytes: 999 };
  ev = valid(parser.parse(JSON.stringify(obj), { collector: 'http', src_id: 'test-json', src_type: 'syslog', peer_ip: '10.20.0.5', rts: RTS, obj }));
  assert.equal(ev.src_type, 'exchange');
  assert.equal(ev.action, 'send');
  assert.equal(ev.ts, 1714557600000);
  assert.equal(ev.fields.recipients, 'x@test.invalid;y@test.invalid');
  assert.equal(ev.fields.subject_sha256, sha('Synthetic export'));
  assert.ok(!ev.raw.includes('Synthetic export'));
});

test('config exchange.store_subjects = true keeps subjects in clear', () => {
  const clear = createParser({ config: { exchange: { store_subjects: true } } });
  try {
    const ev = clear.parse(TRK(), { src_id: 'x', rts: RTS });
    assert.equal(ev.fields.subject, 'Quarterly results, "confidential"');
    assert.ok(ev.raw.includes('Quarterly'));
  } finally { createParser({ config: {} }); }
  assert.ok(!p(TRK()).raw.includes('Quarterly'));
});

const IIS = '2024-05-01 10:00:00 10.20.0.15 POST /owa/auth.owa &ClientId=SYNTHETIC&CorrelationID=<empty>; 443 TEST\\Alice 203.0.113.44 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+SyntheticTest https://test-mail.test.local/owa/ 302 0 0 15';

test('IIS W3C (Exchange front end): default fields, Exchange vdir tags, user/domain, ProxyShell pattern', () => {
  let ev = valid(p(IIS, { src_type: 'iis' }));
  assert.equal(ev.src_type, 'iis');
  assert.equal(ev.category, 'web');
  assert.equal(ev.action, 'http-request');
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 10, 0, 0));
  assert.equal(ev.src_ip, '203.0.113.44');
  assert.equal(ev.dst_ip, '10.20.0.15');
  assert.equal(ev.dst_port, 443);
  assert.equal(ev.user, 'alice');
  assert.equal(ev.domain, 'test');
  assert.equal(ev.http_method, 'POST');
  assert.equal(ev.url, '/owa/auth.owa?&ClientId=SYNTHETIC&CorrelationID=<empty>;');
  assert.equal(ev.http_status, 302);
  assert.equal(ev.outcome, 'success');
  assert.equal(ev.user_agent, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SyntheticTest');
  assert.ok(ev.tags.includes('exchange') && ev.tags.includes('exchange-owa'));
  // sniffed without a configured type, and on an "exchange" source that mixes msgtrk + IIS
  assert.equal(valid(p(IIS)).src_type, 'iis');
  assert.equal(valid(p(IIS, { src_type: 'exchange' })).src_type, 'iis');
  ev = valid(p('2024-05-01 10:00:01 10.20.0.15 GET /autodiscover/autodiscover.json @test.invalid/powershell/?X-Rps-CAT=SYNTHETIC&Email=autodiscover/autodiscover.json%3F@test.invalid 443 - 203.0.113.66 python-requests/2.31.0 - 200 0 0 50'));
  assert.ok(ev.tags.includes('T1190'));
  assert.equal(ev.severity, 3);
  ev = valid(p('2024-05-01 10:00:02 10.20.0.15 POST /ecp/DDI/DDIService.svc/GetList - 443 TEST\\bob 198.51.100.4 SyntheticAgent - 500 0 0 900'));
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.severity, 1);
  assert.ok(ev.tags.includes('exchange-ecp'));
});

test('IIS: #Fields header with a custom field set; JSON shape; syslog-wrapped with exiis-<server> tag', () => {
  const meta = { src_id: 'test-iis-hdr', src_type: 'iis' };
  valid(p('#Software: Microsoft Internet Information Services 10.0', meta));
  valid(p('#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken X-Forwarded-For', meta));
  let ev = valid(p('2024-05-01 10:00:03 W3SVC1 TEST-EX01 10.20.0.15 GET /mapi/emsmdb/ mailboxId=synthetic 443 TEST\\carol 10.20.0.2 Microsoft+Office/16.0 200 0 0 31 198.51.100.77', meta));
  assert.equal(ev.src_ip, '198.51.100.77', 'X-Forwarded-For preferred when present');
  assert.equal(ev.fields.c_ip, '10.20.0.2');
  assert.equal(ev.host, 'test-ex01');
  assert.ok(ev.tags.includes('exchange-mapi'));
  ev = valid(p(JSON.stringify({ server: 'TEST-EX01', date: '2024-05-01', time: '10:00:04', 'cs-method': 'GET', 'cs-uri-stem': '/EWS/Exchange.asmx', 'cs-uri-query': '-', 'c-ip': '203.0.113.9', 'cs-username': 'dave@test.local', 'sc-status': '401', 'cs(User-Agent)': 'SyntheticEWS' }), { collector: 'agent', src_type: 'iis' }));
  assert.equal(ev.url, '/EWS/Exchange.asmx');
  assert.equal(ev.user, 'dave@test.local');
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.host, 'test-ex01');
  assert.ok(ev.tags.includes('exchange-ews'));
  ev = valid(p('<134>May  1 10:00:05 test-collector-01 exiis-TEST-EX02: ' + IIS));
  assert.equal(ev.src_type, 'iis');
  assert.equal(ev.host, 'test-ex02');
});
