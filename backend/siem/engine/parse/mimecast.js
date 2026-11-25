// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Mimecast email security events pulled by collect/mimecast.js from the API 2.0 SIEM batch endpoint (objects tagged _mc
// with the log type: receipt, process, delivery, av, spam, impersonation protect, url protect, attachment protect, ...).
// Every record lands on the common email schema through mailnorm.normalizeMail (category email; action delivered |
// rejected | blocked | quarantined; verdict malware | phishing | spam), so the email pages and rules read Mimecast like any
// other gateway. Field names are read defensively (several spellings): Mimecast's exact keys vary by log type and are to be
// confirmed on the first real records - an unrecognised record is still kept as an email event, never dropped.
const { parseTime, ipOrEmpty, safeJson, clean } = require('./util');
const { normalizeMail } = require('./mailnorm');

const pick = (o, ...keys) => { for (const k of keys) { const v = o[k]; if (v !== undefined && v !== null && v !== '') return v; } return undefined; };
const list = (v) => (Array.isArray(v) ? v.map((x) => (x && typeof x === 'object' ? x.emailAddress || x.address || x.email || '' : x)).filter(Boolean).join(', ') : v);
const VERDICT_BY_TYPE = { av: 'malware', 'attachment protect': 'malware', 'impersonation protect': 'phishing', 'url protect': 'url', spam: 'spam', 'internal email protect': 'malware' };

function ts(v) {
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v === 'number' || /^\d{10,13}$/.test(String(v))) { const n = Number(v); return n < 1e11 ? n * 1000 : n; }
  return parseTime(String(v));
}

function parse(line, meta = {}) {
  const o = meta.obj || safeJson(line);
  if (!o || Array.isArray(o) || typeof o !== 'object') return null;
  if (o._mc === undefined && meta.src_type !== 'mimecast') return null;
  const type = String(o._mc || pick(o, 'type', 'logType') || '').toLowerCase();
  const sub = clean(pick(o, 'subtype', 'subType', 'eventType') || '');
  const action = pick(o, 'action', 'actionTriggered', 'act', 'delivered', 'rejectionType', 'result');
  const ev = {
    src_type: 'mimecast', ts: ts(pick(o, 'timestamp', 'eventTime', 'datetime', 'dateTime', 'date')), host: 'mimecast', severity: 0, tags: ['mimecast'],
    fields: { mimecast_type: type || undefined, mimecast_subtype: sub || undefined, aggregate_id: clean(pick(o, 'aggregateId', 'aggregateID') || '') || undefined,
      processing_id: clean(pick(o, 'processingId', 'processingID') || '') || undefined, account_id: clean(pick(o, 'accountId', 'account') || '') || undefined,
      rejection: clean(pick(o, 'rejectionType', 'rejectionInfo', 'rejectReason') || '') || undefined, policy: clean(pick(o, 'policy', 'policyDefinition', 'definition') || '') || undefined,
      route: clean(pick(o, 'route', 'direction') || '') || undefined },
  };
  if (type === 'delivery' && action === undefined && o.delivered !== undefined) o.action = o.delivered === true || o.delivered === 'true' ? 'delivered' : 'rejected';
  normalizeMail(ev, {
    vendor: 'Mimecast',
    from: pick(o, 'senderEnvelope', 'senderHeader', 'sender', 'fromHeader', 'fromEnvelope', 'from'),
    to: list(pick(o, 'recipients', 'recipient', 'rcpt', 'to', 'toHeader')),
    subject: pick(o, 'subject', 'Subject'),
    action: pick(o, 'action', 'actionTriggered', 'act', 'rejectionType', 'result') || (type === 'receipt' || type === 'delivery' ? 'delivered' : ''),
    verdict: [VERDICT_BY_TYPE[type], pick(o, 'threatType', 'scanResults', 'spamVerdict', 'subtype')].filter(Boolean).join(' '),
    threat: pick(o, 'virusFound', 'threatName', 'fileName', 'url'), url: type === 'url protect' ? pick(o, 'url', 'urlCategory') : undefined,
    attachment: type === 'attachment protect' || type === 'av' ? pick(o, 'fileName', 'sha256', 'md5') : undefined,
    spam: pick(o, 'spamScore', 'spamProcessingDetail'), direction: pick(o, 'direction', 'route'), msgid: pick(o, 'messageId', 'messageID', 'msgId'),
    src: ipOrEmpty(pick(o, 'senderIp', 'senderIP', 'sourceIp', 'remoteIp', 'ip')),
  });
  ev.tags.push('mimecast');
  ev.tags = [...new Set(ev.tags)];
  return ev;
}

module.exports = {
  name: 'mimecast',
  sniff(line, meta = {}) { const o = meta.obj || safeJson(line); return !!o && typeof o === 'object' && o._mc !== undefined; },
  parse,
};
