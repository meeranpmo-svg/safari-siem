// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Microsoft 365 / Entra ID records:
//  - Graph signIns          {id, createdDateTime, userPrincipalName, ipAddress, appDisplayName, status:{errorCode, failureReason}, …}
//  - Graph directoryAudits  {id, activityDateTime, activityDisplayName, category, result, initiatedBy:{user|app}, targetResources:[…]}
//  - Management Activity API (unified audit log) {CreationTime, Operation, Workload, UserId, ClientIP, ResultStatus, …}
const { parseTime, ipOrEmpty, safeJson, clean, flatten } = require('./util');
const exchange = require('./exchange');

const AUDIT_ACTIONS = [
  [/^add user$/i, 'user-created', 2, ['T1136.003']],
  [/^delete user$/i, 'user-deleted', 2, []],
  [/^(disable account|update user.*accountenabled.*false)/i, 'user-disabled', 1, []],
  [/^enable account/i, 'user-enabled', 1, []],
  [/^reset (user )?password|^reset password/i, 'password-reset', 1, ['T1098']],
  [/^change (user )?password/i, 'password-change', 0, []],
  [/^add member to group$/i, 'group-member-added', 1, ['T1098']],
  [/^remove member from group$/i, 'group-member-removed', 1, []],
  [/^add member to role|^add eligible member to role|^add (app )?role assignment/i, 'role-assigned', 3, ['T1098.003', 'admin']],
  [/^update user$/i, 'user-modified', 0, []],
  [/^(add|update|delete) (service principal|application|policy|conditional access policy|named location)/i, 'config-change', 2, []],
  [/^consent to application/i, 'config-change', 2, ['T1528']],
];

function signIn(o) {
  const err = Number(o.status && o.status.errorCode) || 0;
  const ok = err === 0;
  const upn = clean(o.userPrincipalName).toLowerCase();
  const ev = {
    src_type: 'm365', ts: parseTime(o.createdDateTime), category: 'authentication', action: ok ? 'logon' : 'logon-failed',
    outcome: ok ? 'success' : 'failure', user: upn, domain: upn.includes('@') ? upn.split('@').pop() : '',
    src_ip: ipOrEmpty(o.ipAddress), user_agent: clean(o.userAgent), event_code: String(err),
    severity: ok ? 0 : 1, host: 'entra-id', tags: ok ? [] : ['T1110'],
    message: `Sign-in ${ok ? 'succeeded' : 'failed'} for ${upn} to ${o.appDisplayName || '?'}${ok ? '' : ': ' + ((o.status && o.status.failureReason) || err)}`.slice(0, 300),
    fields: {
      ...flatten(o),
      m365_type: 'signin', record_id: o.id, app: o.appDisplayName, client_app: o.clientAppUsed, resource: o.resourceDisplayName,
      failure_reason: o.status && o.status.failureReason, ca_status: o.conditionalAccessStatus,
      risk_level: o.riskLevelDuringSignIn, risk_state: o.riskState, interactive: o.isInteractive === undefined ? undefined : String(o.isInteractive),
      city: o.location && o.location.city, country: o.location && o.location.countryOrRegion,
      os: o.deviceDetail && o.deviceDetail.operatingSystem, browser: o.deviceDetail && o.deviceDetail.browser,
      mfa: o.mfaDetail && o.mfaDetail.authMethod, correlation_id: o.correlationId,
    },
  };
  if (['high', 'medium'].includes(String(o.riskLevelDuringSignIn).toLowerCase())) { ev.severity = Math.max(ev.severity, o.riskLevelDuringSignIn.toLowerCase() === 'high' ? 3 : 2); ev.tags.push('risky-signin'); }
  return ev;
}

function directoryAudit(o) {
  const name = String(o.activityDisplayName || '');
  let action = 'config-change';
  let sev = 0;
  let tags = [];
  for (const [re, a, s, t] of AUDIT_ACTIONS) if (re.test(name)) { action = a; sev = s; tags = t; break; }
  const by = (o.initiatedBy && (o.initiatedBy.user || o.initiatedBy.app)) || {};
  const targets = Array.isArray(o.targetResources) ? o.targetResources : [];
  const tUser = targets.find((t) => String(t.type).toLowerCase() === 'user') || targets[0] || {};
  const ok = String(o.result || '').toLowerCase() !== 'failure';
  const groupT = targets.find((t) => String(t.type).toLowerCase() === 'group');
  return {
    src_type: 'm365', ts: parseTime(o.activityDateTime), category: o.category === 'UserManagement' || o.category === 'GroupManagement' || o.category === 'RoleManagement' ? 'iam' : 'cloud',
    action, outcome: ok ? 'success' : 'failure', severity: sev, tags: [...tags], host: 'entra-id',
    user: clean(by.userPrincipalName || by.displayName).toLowerCase(), src_ip: ipOrEmpty(by.ipAddress),
    target_user: clean(tUser.userPrincipalName || tUser.displayName).toLowerCase(), event_code: name,
    message: `${name}${tUser.userPrincipalName || tUser.displayName ? ': ' + (tUser.userPrincipalName || tUser.displayName) : ''}`.slice(0, 300),
    fields: {
      ...flatten(o),
      m365_type: 'directory_audit', record_id: o.id, audit_category: o.category, service: o.loggedByService, operation_type: o.operationType,
      result_reason: o.resultReason, correlation_id: o.correlationId, group: groupT && groupT.displayName,
      modified: targets.length ? JSON.stringify(targets.map((t) => ({ type: t.type, name: t.displayName || t.userPrincipalName, props: (t.modifiedProperties || []).map((p) => p.displayName) }))).slice(0, 4000) : undefined,
    },
  };
}

// Exchange Online mailbox-audit operations (RecordType 2 ExchangeItem / 3 ExchangeItemGroup) → action
const MAILBOX_OPS = {
  mailitemsaccessed: 'mail-items-accessed', send: 'send', sendas: 'send-as', sendonbehalf: 'send-on-behalf',
  harddelete: 'mail-deleted', softdelete: 'mail-deleted', movetodeleteditems: 'mail-deleted', move: 'mail-moved',
  create: 'mail-item-created', update: 'mail-item-updated', folderbind: 'mail-folder-accessed', mailboxlogin: 'logon',
};
const cip = (v) => ipOrEmpty(String(v || '').replace(/^\[?([^\]]+?)\]?(:\d+)?$/, '$1'));
const nv = (arr) => { const m = {}; for (const x of Array.isArray(arr) ? arr : []) if (x && x.Name !== undefined) m[x.Name] = x.Value; return m; };

// Management Activity API (unified audit log) record. Subjects are hashed (see parse/exchange.js) before anything is
// copied into fields/raw. Exchange admin cmdlets (RecordType 1) are classified with exchange.classifyCmdlet().
function unified(o) {
  const op = String(o.Operation || '');
  const opl = op.toLowerCase();
  const status = String(o.ResultStatus || '').toLowerCase();
  const fail = /fail/.test(status);
  const { obj: so, hashes } = exchange.scrubSubjects(o);
  const f = flatten(so);
  delete f.CreationTime;
  const ev = {
    src_type: 'm365', ts: parseTime(o.CreationTime, 0), category: 'cloud', action: 'event',
    outcome: fail || /failed/i.test(op) ? 'failure' : (status ? 'success' : 'unknown'),
    user: clean(o.UserId).toLowerCase(), src_ip: cip(o.ClientIP), event_code: op, host: String(o.Workload || 'm365').toLowerCase(),
    message: `${o.Workload || 'M365'} ${op}`.trim(), tags: [], fields: { m365_type: 'unified_audit', ...f },
  };
  const workload = String(o.Workload || '').toLowerCase();
  const rt = Number(o.RecordType);
  if (/^userlogin(failed)?$/i.test(op)) { ev.category = 'authentication'; ev.action = /failed/i.test(op) ? 'logon-failed' : 'logon'; }
  else if (rt === 1 || (workload === 'exchange' && Array.isArray(o.Parameters) && /^[a-z]+-[a-z]/i.test(op))) {
    // Exchange admin audit: cmdlet + parameters
    const params = nv(o.Parameters);
    const c = exchange.classifyCmdlet(op, params);
    Object.assign(ev, { category: c.category, action: c.action, severity: c.severity });
    ev.tags.push(...c.tags, 'exchange', 'exchange-online');
    ev.target_user = c.target || clean(o.ObjectId || o.ModifiedObjectResolvedName).toLowerCase();
    ev.fields.cmdlet = op;
    ev.fields.exchange_action = c.action;
    for (const [k, v] of Object.entries(params)) ev.fields['params.' + k] = String(v === null || v === undefined ? '' : v).slice(0, 2000);
    if (o.ExternalAccess === true) ev.tags.push('external-admin');
    ev.message = `Exchange Online ${op}${ev.target_user ? ' on ' + ev.target_user : ''} by ${ev.user || '?'}`.slice(0, 300);
  } else if (workload === 'exchange' && (MAILBOX_OPS[opl] || rt === 2 || rt === 3 || opl === 'updateinboxrules')) {
    ev.tags.push('exchange', 'exchange-online');
    ev.src_ip = cip(o.ClientIPAddress) || cip(o.ClientIP);
    ev.target_user = clean(o.MailboxOwnerUPN).toLowerCase();
    Object.assign(ev.fields, { client_info: o.ClientInfoString, logon_type: o.LogonType === undefined ? undefined : String(o.LogonType), mailbox_guid: o.MailboxGuid });
    if (opl === 'updateinboxrules') {
      const c = exchange.classifyCmdlet(op, nv(o.OperationProperties));
      Object.assign(ev, { category: c.category, action: c.action, severity: c.severity });
      ev.tags.push(...c.tags);
    } else {
      ev.action = MAILBOX_OPS[opl] || 'mailbox-activity';
      ev.category = ev.action === 'logon' ? 'authentication' : 'email';
    }
    if (opl === 'mailitemsaccessed') {
      const props = nv(o.OperationProperties);
      Object.assign(ev.fields, { mail_access_type: props.MailAccessType, is_throttled: props.IsThrottled, operation_count: o.OperationCount === undefined ? undefined : String(o.OperationCount) });
      if (/sync/i.test(props.MailAccessType || '')) ev.tags.push('mail-sync');
    }
    const item = o.Item || {};
    if (item.InternetMessageId) ev.fields.internet_message_id = item.InternetMessageId;
    if (item.SizeInBytes !== undefined) ev.fields.size_bytes = String(item.SizeInBytes);
    if (item.Subject) { if (exchange.subjectsInClear()) ev.fields.subject = item.Subject; else ev.fields.subject_sha256 = exchange.sha256(item.Subject); }
    if (opl === 'sendas') { ev.target_user = clean(o.SendAsUserSmtp).toLowerCase(); ev.tags.push('impersonation'); ev.severity = 1; }
    if (opl === 'sendonbehalf') { ev.target_user = clean(o.SendOnBehalfOfUserSmtp).toLowerCase(); ev.tags.push('impersonation'); ev.severity = 1; }
    if (ev.target_user && ev.user && ev.target_user !== ev.user && opl !== 'sendas' && opl !== 'sendonbehalf') ev.tags.push('delegate-access');
    ev.message = `Exchange Online ${op} by ${ev.user || '?'}${ev.target_user && ev.target_user !== ev.user ? ' on ' + ev.target_user : ''}`.slice(0, 300);
  } else if (/^(filedownloaded|fileaccessed|fileuploaded|filedeleted)$/i.test(op)) { ev.category = 'file'; }
  if (!ev.tags.length) delete ev.tags;
  if (hashes.length) ev.raw_body = JSON.stringify(so); // raw without subjects in clear
  return ev;
}

function parse(line, meta = {}) {
  const o = meta.obj || safeJson(line);
  if (!o || Array.isArray(o)) return null;
  if (o.userPrincipalName !== undefined && o.createdDateTime !== undefined && (o.status !== undefined || o.appDisplayName !== undefined)) return signIn(o);
  if (o.activityDisplayName !== undefined && o.activityDateTime !== undefined) return directoryAudit(o);
  if (o.Operation !== undefined && o.CreationTime !== undefined && (o.Workload !== undefined || o.RecordType !== undefined)) return unified(o);
  return null;
}

module.exports = {
  name: 'm365',
  sniff(line, meta = {}) {
    const o = meta.obj || safeJson(line);
    return !!o && ((o.userPrincipalName !== undefined && o.createdDateTime !== undefined) || (o.activityDisplayName !== undefined && o.activityDateTime !== undefined) || (o.Operation !== undefined && o.CreationTime !== undefined && (o.Workload !== undefined || o.RecordType !== undefined)));
  },
  parse,
};
