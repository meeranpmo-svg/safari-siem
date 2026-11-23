// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Microsoft Exchange (on-premises, hybrid) helpers + the message tracking log parser.
//
// 1) Cmdlet classification shared by
//    - Exchange Online admin audit records (Management Activity API, RecordType 1 "ExchangeAdmin", parse/m365.js) and
//    - on-prem admin audit events from the Windows channel "MSExchange Management" (EventID 1 = cmdlet succeeded,
//      6 = cmdlet failed; EventData Data0 = cmdlet, Data1 = parameters, Data2 = caller — the layout also used by
//      Microsoft Sentinel's ExchangeAdminAuditLogs parser), see parse/windows.js.
//    classifyCmdlet(name, params) → {category, action, severity, tags, target}. Action names (Exchange-specific):
//      inbox-rule-created, inbox-rule-modified, inbox-rule-removed, mail-forwarding-set, mail-forwarding-removed,
//      mailbox-modified, mailbox-permission-added, mailbox-permission-removed, mailbox-folder-permission-added,
//      sendas-permission-added, sendas-permission-removed, transport-rule-created, transport-rule-modified,
//      transport-rule-removed, role-assigned, group-member-added, mailbox-export, mailbox-search,
//      mail-connector-changed, org-relationship-changed, hybrid-config-changed, mail-domain-changed,
//      journal-rule-changed, audit-disabled, user-created, user-deleted, config-change, config-read
//
// 2) Message tracking log (Exchange 2016/2019/SE, %ExchangeInstallPath%TransportRoles\Logs\MessageTracking\MSGTRK*.log):
//    CSV with '#Software/#Version/#Log-Type/#Date/#Fields' header lines. Field list and event types verified against
//    https://learn.microsoft.com/en-us/exchange/mail-flow/transport-logs/message-tracking
//    Accepted shapes: raw CSV lines (e.g. rsyslog imfile), JSON objects keyed by the #Fields names
//    ({"date-time": …, "event-id": …}), and Get-MessageTrackingLog objects ({Timestamp, EventId, Sender, Recipients[] …}).
//    Actions: receive, send, deliver, fail (the four main ones) + submit, defer, dsn, drop, expand, redirect, resolve,
//    transfer, transport (everything else). Category email.
//    SUBJECTS ARE NOT STORED IN CLEAR: fields.subject_sha256 = SHA-256 hex of the subject, and the subject inside `raw`
//    is replaced by "sha256:<hex>" — unless config.exchange.store_subjects = true.
const crypto = require('node:crypto');
const { split, parseTime, ipOrEmpty, clean, safeJson } = require('./util');

let storeSubjects = false;
function configure(cfg = {}) { storeSubjects = !!(cfg && cfg.store_subjects); }
const subjectsInClear = () => storeSubjects;

const sha256 = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
const subjectToken = (s) => 'sha256:' + sha256(s);

// Deep copy with every "Subject"-like key replaced by its hash (unless subjects may be stored). Returns {obj, hashes[]}.
const SUBJECT_KEY = /^(subject|messagesubject|message-subject|message_subject)$/i;
function scrubSubjects(o) {
  const hashes = [];
  if (storeSubjects) return { obj: o, hashes };
  const walk = (v, depth) => {
    if (depth > 8 || v === null || typeof v !== 'object') return v;
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      if (SUBJECT_KEY.test(k) && typeof x === 'string' && x !== '') { const h = sha256(x); hashes.push(h); out[k] = 'sha256:' + h; }
      else out[k] = walk(x, depth + 1);
    }
    return out;
  };
  return { obj: walk(o, 0), hashes };
}

// ------------------------------------------------------------------ cmdlet parameters
// On-prem parameter strings: `-Identity "a b" -ForwardTo "x@y" -StopProcessingRules $true -Enabled`
// (Exchange 2010 style `{Identity=a, ForwardTo=x}` too). Returns {name: value} with original names.
function parseCmdletParams(str) {
  const out = {};
  const s = String(str || '').trim();
  if (!s) return out;
  if (s[0] === '{' && s.endsWith('}')) {
    for (const part of s.slice(1, -1).split(/,\s*(?=[A-Za-z][\w-]*=)/)) {
      const eq = part.indexOf('=');
      if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
    }
    return out;
  }
  let i = 0;
  const n = s.length;
  while (i < n) {
    while (i < n && /\s/.test(s[i])) i++;
    if (s[i] !== '-' || !/[A-Za-z]/.test(s[i + 1] || '')) { // stray token: skip to next whitespace
      while (i < n && !/\s/.test(s[i])) i++;
      continue;
    }
    i++;
    let name = '';
    while (i < n && /[\w]/.test(s[i])) name += s[i++];
    let colon = false;
    if (s[i] === ':') { colon = true; i++; }
    if (!colon) while (i < n && /\s/.test(s[i])) i++;
    // value runs until the next top-level " -Name" (quotes respected)
    let val = '';
    let q = null;
    while (i < n) {
      const c = s[i];
      if (q) { if (c === q) { if (s[i + 1] === q) { val += c + c; i += 2; continue; } q = null; } val += c; i++; continue; }
      if (c === '"' || c === "'") { q = c; val += c; i++; continue; }
      if (/\s/.test(c) && s[i + 1] === '-' && /[A-Za-z]/.test(s[i + 2] || '')) break;
      if (!val && c === '-' && /[A-Za-z]/.test(s[i + 1] || '')) break; // switch parameter without value
      val += c;
      i++;
    }
    val = val.trim();
    if (/^"(?:[^"]|"")*"$/.test(val)) val = val.slice(1, -1).replace(/""/g, '"');
    else if (/^'(?:[^']|'')*'$/.test(val)) val = val.slice(1, -1).replace(/''/g, "'");
    if (name) out[name] = val === '' ? 'True' : val;
  }
  return out;
}

function lowerKeys(p) { const o = {}; for (const [k, v] of Object.entries(p || {})) o[k.toLowerCase()] = v === undefined || v === null ? '' : String(v); return o; }
const isSet = (v) => v !== undefined && v !== '' && !/^\$?(null|false|\$null|none)$/i.test(String(v).trim());
const isTrue = (v) => /^\$?true$/i.test(String(v || '').trim());

// ------------------------------------------------------------------ cmdlet classification
function classifyCmdlet(name, params) {
  const n = String(name || '').trim().toLowerCase();
  const p = lowerKeys(params);
  const target = clean(p.identity || p.mailbox || p.user || p.name || '').toLowerCase();
  const r = (category, action, severity, tags = []) => ({ category, action, severity, tags, target });
  const any = (...ks) => ks.some((k) => isSet(p[k]));
  const blob = JSON.stringify(p).toLowerCase();

  if (n === 'new-inboxrule' || n === 'set-inboxrule' || n === 'updateinboxrules' || n === 'remove-inboxrule' || n === 'disable-inboxrule') {
    if (n === 'remove-inboxrule' || n === 'disable-inboxrule') return r('email', 'inbox-rule-removed', 1);
    const fwd = any('forwardto', 'forwardasattachmentto', 'redirectto') || (n === 'updateinboxrules' && /forward|redirect/.test(blob));
    const hide = any('deletemessage', 'movetofolder', 'markasread', 'softdeletemessage') || (n === 'updateinboxrules' && /delete|movetofolder|markasread/.test(blob));
    const tags = [];
    if (fwd) tags.push('T1114.003', 'mail-forwarding');
    if (hide) tags.push('T1564.008');
    return r('email', n === 'new-inboxrule' ? 'inbox-rule-created' : 'inbox-rule-modified', fwd ? 3 : hide ? 2 : 1, tags);
  }
  if (n === 'set-mailbox') {
    if (p.auditenabled !== undefined && !isTrue(p.auditenabled)) return r('system', 'audit-disabled', 4, ['T1685.002']);
    const fwdKeys = ['forwardingsmtpaddress', 'forwardingaddress'];
    if (fwdKeys.some((k) => isSet(p[k])) || isTrue(p.delivertomailboxandforward)) return r('email', 'mail-forwarding-set', 3, ['T1114.003', 'mail-forwarding']);
    if (fwdKeys.some((k) => k in p)) return r('email', 'mail-forwarding-removed', 1);
    if (isSet(p.grantsendonbehalfto)) return r('iam', 'mailbox-permission-added', 2, ['T1098.002']);
    return r('email', 'mailbox-modified', 1);
  }
  if (n === 'add-mailboxpermission') return r('iam', 'mailbox-permission-added', /fullaccess/i.test(p.accessrights || '') ? 3 : 2, ['T1098.002']);
  if (n === 'remove-mailboxpermission') return r('iam', 'mailbox-permission-removed', 1);
  if (n === 'add-recipientpermission') return r('iam', 'sendas-permission-added', 3, ['T1098.002']);
  if (n === 'remove-recipientpermission') return r('iam', 'sendas-permission-removed', 1);
  if (n === 'add-adpermission') return /send-?as|receive-?as/i.test(p.extendedrights || '') ? r('iam', 'sendas-permission-added', 3, ['T1098.002']) : r('iam', 'mailbox-permission-added', 2, ['T1098.002']);
  if (n === 'add-mailboxfolderpermission' || n === 'set-mailboxfolderpermission') return r('iam', 'mailbox-folder-permission-added', 2, ['T1098.002']);
  if (n === 'new-transportrule' || n === 'set-transportrule' || n === 'enable-transportrule') {
    const fwd = any('blindcopyto', 'redirectmessageto', 'copyto', 'addtorecipients', 'addmanagerasrecipienttype');
    return r('policy', n === 'new-transportrule' ? 'transport-rule-created' : 'transport-rule-modified', fwd ? 3 : 2, fwd ? ['T1114.003', 'mail-forwarding'] : []);
  }
  if (n === 'remove-transportrule' || n === 'disable-transportrule') return r('policy', 'transport-rule-removed', 2);
  if (n === 'new-managementroleassignment') {
    const role = String(p.role || '').toLowerCase();
    return r('iam', 'role-assigned', /applicationimpersonation|mailbox import export|mailbox search|role management/.test(role) ? 4 : 3, ['T1098', 'admin']);
  }
  if (n === 'add-rolegroupmember' || n === 'update-rolegroupmember') return r('iam', 'group-member-added', 3, ['T1098', 'admin']);
  if (n === 'new-mailboxexportrequest') return r('email', 'mailbox-export', 4, ['T1114.002']);
  if (n === 'new-compliancesearchaction') return r('email', 'mailbox-export', /export/i.test(blob) ? 3 : 2, ['T1114.002']);
  if (n === 'search-mailbox' || n === 'new-compliancesearch' || n === 'start-compliancesearch') return r('email', 'mailbox-search', 2, ['T1114.002']);
  if (/^(new|set|remove|enable|disable)-(inbound|outbound|send|receive)connector$/.test(n)) return r('policy', 'mail-connector-changed', 3, ['hybrid', 'mail-flow']);
  if (/^(new|set|remove)-(organizationrelationship|intraorganizationconnector|federationtrust)$/.test(n)) return r('policy', 'org-relationship-changed', 3, ['hybrid']);
  if (/^(new|set|update)-hybridconfiguration$/.test(n)) return r('policy', 'hybrid-config-changed', 3, ['hybrid']);
  if (n === 'set-remotedomain' && isTrue(p.autoforwardenabled)) return r('email', 'mail-forwarding-set', 3, ['T1114.003', 'mail-forwarding']);
  if (/^(new|set|remove)-(remotedomain|accepteddomain)$/.test(n)) return r('policy', 'mail-domain-changed', 2, ['mail-flow']);
  if (/^(new|set|remove|enable|disable)-journalrule$/.test(n) || (n === 'set-transportconfig' && isSet(p.journalingreportndrto))) return r('policy', 'journal-rule-changed', 3, ['T1114']);
  if (n === 'set-adminauditlogconfig' && p.adminauditlogenabled !== undefined && !isTrue(p.adminauditlogenabled)) return r('system', 'audit-disabled', 4, ['T1685.002']);
  if (n === 'set-organizationconfig' && p.auditdisabled !== undefined && isTrue(p.auditdisabled)) return r('system', 'audit-disabled', 4, ['T1685.002']);
  if (n === 'set-mailboxauditbypassassociation' && isTrue(p.auditbypassenabled)) return r('system', 'audit-disabled', 4, ['T1685.002']);
  if (/^(new|enable)-(remote)?mailbox$/.test(n)) return r('iam', 'user-created', 1);
  if (/^(remove|disable)-(remote)?mailbox$/.test(n)) return r('iam', 'user-deleted', 1);
  if (/^(get|test|search|export-?get)-/.test(n)) return r('system', 'config-read', 0);
  return r('system', 'config-change', 1);
}

// ------------------------------------------------------------------ CSV
// RFC 4180-ish split that also returns each cell's [start, end) offsets in the line (for redaction).
function splitCsv(line) {
  const cells = [];
  let i = 0;
  const n = line.length;
  while (i <= n) {
    const start = i;
    let val = '';
    if (line[i] === '"') {
      i++;
      while (i < n) {
        if (line[i] === '"') { if (line[i + 1] === '"') { val += '"'; i += 2; continue; } i++; break; }
        val += line[i++];
      }
      while (i < n && line[i] !== ',') i++;
    } else {
      while (i < n && line[i] !== ',') val += line[i++];
    }
    cells.push({ v: val, start, end: i });
    i++;
    if (i > n) break;
  }
  return cells;
}
const csvCell = (s) => (/[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s);

// ------------------------------------------------------------------ message tracking
const MSGTRK_FIELDS = ['date-time', 'client-ip', 'client-hostname', 'server-ip', 'server-hostname', 'source-context', 'connector-id',
  'source', 'event-id', 'internal-message-id', 'message-id', 'network-message-id', 'recipient-address', 'recipient-status',
  'total-bytes', 'recipient-count', 'related-recipient-address', 'reference', 'message-subject', 'sender-address', 'return-path',
  'message-info', 'directionality', 'tenant-id', 'original-client-ip', 'original-server-ip', 'custom-data', 'transport-traffic-type',
  'log-id', 'schema-version'];
// Get-MessageTrackingLog property names → #Fields names
const PS_NAMES = {
  timestamp: 'date-time', clientip: 'client-ip', clienthostname: 'client-hostname', serverip: 'server-ip', serverhostname: 'server-hostname',
  sourcecontext: 'source-context', connectorid: 'connector-id', source: 'source', eventid: 'event-id', internalmessageid: 'internal-message-id',
  messageid: 'message-id', networkmessageid: 'network-message-id', recipients: 'recipient-address', recipientstatus: 'recipient-status',
  totalbytes: 'total-bytes', recipientcount: 'recipient-count', relatedrecipientaddress: 'related-recipient-address', reference: 'reference',
  messagesubject: 'message-subject', sender: 'sender-address', returnpath: 'return-path', messageinfo: 'message-info', directionality: 'directionality',
  tenantid: 'tenant-id', originalclientip: 'original-client-ip', originalserverip: 'original-server-ip', customdata: 'custom-data',
  transporttraffictype: 'transport-traffic-type', logid: 'log-id', schemaversion: 'schema-version',
};
const EVENT_ACTION = {
  RECEIVE: 'receive', HARECEIVE: 'receive', SEND: 'send', DELIVER: 'deliver', DUPLICATEDELIVER: 'deliver', FAIL: 'fail', DELIVERFAIL: 'fail',
  SUBMITFAIL: 'fail', RESUBMITFAIL: 'fail', HAREDIRECTFAIL: 'fail', BADMAIL: 'fail', POISONMESSAGE: 'fail', SUBMIT: 'submit',
  CLIENTSUBMISSION: 'submit', DEFER: 'defer', SUBMITDEFER: 'defer', RESUBMITDEFER: 'defer', DSN: 'dsn', DROP: 'drop', EXPAND: 'expand',
  DUPLICATEEXPAND: 'expand', REDIRECT: 'redirect', DUPLICATEREDIRECT: 'redirect', RESOLVE: 'resolve', TRANSFER: 'transfer',
};

const headerCache = new Map(); // "<src_id>|<host>|<app>|<kind>" → field list (learned from #Fields lines)
// meta.stream (relay file sources: "<host>|<path>") identifies one tailed file, so every file keeps its own #Fields list
function cacheKey(meta, hdr, kind) { return `${meta.src_id || ''}|${meta.stream || (hdr && hdr.host) || meta.peer_ip || ''}|${(hdr && hdr.app) || ''}|${kind}`; }
function rememberFields(key, list) { if (headerCache.size > 2000) headerCache.clear(); headerCache.set(key, list); }

const DT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z,/;
// '#Fields:' with a comma-separated list = message tracking (IIS W3C uses spaces)
const isMsgTrkHeader = (s) => /^#(Software: Microsoft Exchange|Log-type: Message Tracking|Fields:\s*[\w-]+(,[\w-]+){3,}\s*$)/i.test(s);

function hostFromTag(hdr) {
  // imfile tags like "exmsgtrk-EX01:" / "exiis-EX01:" carry the Exchange server name (see agents/exchange/README.md)
  const m = hdr && hdr.app ? /^ex(?:msgtrk|iis)[-_](.+)$/i.exec(hdr.app) : null;
  return m ? m[1].toLowerCase() : '';
}

function headerEvent(src_type, body, host) {
  return { src_type, category: 'system', action: 'event', outcome: 'unknown', severity: 0, host, message: body.slice(0, 300), fields: { log_header: '1' } };
}

function msgtrkFromMap(m, host) {
  const ev = String(m['event-id'] || '').toUpperCase();
  const action = EVENT_ACTION[ev] || 'transport';
  const rcpts = String(m['recipient-address'] || '').split(';').map((x) => x.trim().toLowerCase()).filter(Boolean);
  const sender = clean(m['sender-address']).toLowerCase();
  const subject = m['message-subject'] || '';
  const fields = {
    msgtrk_source: m.source, source_context: String(m['source-context'] || '').slice(0, 2000), connector_id: m['connector-id'],
    client_hostname: m['client-hostname'], server_hostname: m['server-hostname'], internal_message_id: m['internal-message-id'],
    message_id: m['message-id'], network_message_id: m['network-message-id'], recipients: rcpts.join(';').slice(0, 4000),
    recipient_status: String(m['recipient-status'] || '').slice(0, 2000), recipient_count: m['recipient-count'], total_bytes: m['total-bytes'],
    related_recipient_address: m['related-recipient-address'], reference: m.reference, return_path: m['return-path'],
    message_info: m['message-info'], directionality: m.directionality, original_client_ip: m['original-client-ip'],
    original_server_ip: m['original-server-ip'], custom_data: String(m['custom-data'] || '').slice(0, 2000), schema_version: m['schema-version'],
  };
  if (subject) { if (storeSubjects) fields.subject = subject; else fields.subject_sha256 = sha256(subject); }
  const failed = action === 'fail' || action === 'drop';
  return {
    src_type: 'exchange', ts: parseTime(m['date-time'], 0), host, category: 'email', action,
    outcome: failed ? 'failure' : ['send', 'deliver', 'receive', 'submit'].includes(action) ? 'success' : 'unknown',
    severity: failed ? 1 : 0, user: sender, target_user: rcpts[0] || '',
    src_ip: ipOrEmpty(m['client-ip']) || ipOrEmpty(m['original-client-ip']), dst_ip: ipOrEmpty(m['server-ip']),
    event_code: ev, tags: ['exchange'],
    message: `${ev} ${sender || '<>'} → ${rcpts.slice(0, 3).join(', ')}${rcpts.length > 3 ? ` (+${rcpts.length - 3})` : ''} [${m.source || ''}]`.slice(0, 300),
    fields,
  };
}

function parseMsgTrk(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const host = hostFromTag(hdr) || (hdr && hdr.host) || '';
  const obj = meta.obj || (body.charCodeAt(0) === 123 ? safeJson(body) : null);
  if (obj && !Array.isArray(obj)) {
    let m = null;
    if (obj['event-id'] !== undefined) m = obj;
    else if (obj.EventId !== undefined && (obj.MessageId !== undefined || obj.Timestamp !== undefined)) {
      m = {};
      for (const [k, v] of Object.entries(obj)) {
        const f = PS_NAMES[k.toLowerCase()];
        if (f) m[f] = Array.isArray(v) ? v.join(';') : v;
      }
    }
    if (!m) return null;
    const jhost = clean(obj.server || obj.Server || obj.host || obj.Host || '').toLowerCase(); // reporting Exchange server
    const ev = msgtrkFromMap(m, jhost || host);
    const { obj: scrubbed } = scrubSubjects(obj);
    if (!storeSubjects) ev.raw_body = JSON.stringify(scrubbed);
    return ev;
  }
  if (body[0] === '#') {
    if (!isMsgTrkHeader(body) && !/^#(Version|Date):/i.test(body)) return null;
    const fm = /^#Fields:\s*(.+)$/i.exec(body);
    if (fm) rememberFields(cacheKey(meta, hdr, 'msgtrk'), fm[1].split(',').map((x) => x.trim().toLowerCase()));
    return headerEvent(meta.src_type && meta.src_type !== 'syslog' ? meta.src_type : 'exchange', body, host);
  }
  const cached = headerCache.get(cacheKey(meta, hdr, 'msgtrk'));
  // data line: starts with the ISO date-time (default layout), or a #Fields header was seen for this stream
  if (!DT_RE.test(body) && !(cached && body.split(',').length >= Math.min(cached.length, 4))) return null;
  const names = cached || MSGTRK_FIELDS;
  const cells = splitCsv(body);
  if (cells.length < Math.min(names.length, 9)) return null;
  const m = {};
  names.forEach((nm, i) => { if (cells[i]) m[nm] = cells[i].v; });
  const ev = msgtrkFromMap(m, host);
  const si = names.indexOf('message-subject');
  if (!storeSubjects && si >= 0 && cells[si] && cells[si].v) {
    const c = cells[si];
    ev.raw_body = body.slice(0, c.start) + csvCell(subjectToken(c.v)) + body.slice(c.end);
  }
  return ev;
}

module.exports = {
  name: 'exchange',
  sniff(line, meta = {}) {
    const { body } = split(line, meta);
    if (meta.obj) return meta.obj['event-id'] !== undefined || (meta.obj.EventId !== undefined && meta.obj.MessageId !== undefined && meta.obj.Channel === undefined);
    return DT_RE.test(body) || isMsgTrkHeader(body);
  },
  parse: parseMsgTrk,
  configure, subjectsInClear, scrubSubjects, sha256, classifyCmdlet, parseCmdletParams, splitCsv, MSGTRK_FIELDS, headerCache,
  hostFromTag, cacheKey, rememberFields, headerEvent,
};
