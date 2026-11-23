// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Shared Secure Email Gateway normaliser. Lands a mail-security event on the common schema under category 'email'.
 * Used by the dedicated Libraesva ESG parser (engine/parse/libraesva.js) AND by the CEF email-gateway hook in
 * cef-vendors.js (Proofpoint, Mimecast, Cisco ESA / IronPort, Forcepoint Email Security, Trend Micro / Symantec
 * Messaging Gateway). Microsoft Defender for Office 365 does NOT ride here — it rides the existing M365 connector.
 *
 * d = { vendor, from, to, subject, action, verdict, spam, direction, threat, attachment, url, msgid, src, severity }
 *   - subject is PDPL-hashed with the SAME convention as Exchange / message tracking (engine/parse/exchange.js):
 *     stored only as "sha256:<hex>" unless config.exchange.store_subjects = true (exchange.subjectsInClear()).
 * Normalised: category 'email'; action delivered | quarantined | blocked | rejected (outcome success only when delivered,
 * i.e. the gateway let it through — failure = the gateway stopped it); fields.email_from / email_to / email_subject /
 * email_action(+_raw) / email_verdict (malware|phishing|spam|auth-failure|dlp) / email_direction (inbound|outbound) /
 * spam_score / threat_name / attachment_verdict / url_verdict / message_id; tags email (+ the verdict, + T1566 on phish).
 */
const { clean, splitUser, sevFromName } = require('./util');
const exchange = require('./exchange'); // sha256 + subjectsInClear (no cycle: exchange does not require this module)

const lc = (v) => String(v === undefined || v === null ? '' : v).toLowerCase();

function hashSubject(s) {
  s = clean(s);
  if (!s) return undefined;
  return exchange.subjectsInClear() ? s.slice(0, 998) : 'sha256:' + exchange.sha256(s);
}

// Disposition vocabulary. Order matters (quarantine/reject are more specific than block/deliver).
const ACT = [
  [/quarant|\bhold\b|sandbox.?hold|spam ?box|pending|deferred quarantine/, 'quarantined'],
  [/reject|bounce|refuse|denied|55\d|rejected/, 'rejected'],
  [/block|discard|drop|delet|strip|blackhol|dispose|silently/, 'blocked'],
  [/deliver|allow|accept|\bpass\b|clean|forward|\bsent\b|release|relay|\bok\b|passed/, 'delivered'],
];
function mailAction(v) { const s = lc(v); if (!s) return ''; for (const [re, a] of ACT) if (re.test(s)) return a; return s.replace(/\s+/g, '-'); }

const VERDICT = [
  [/phish|impersonat|spoof|\bbec\b|business email compromise|fraud|\bceo\b|display name/, 'phishing'],
  [/malware|virus|trojan|ransom|\bworm\b|exploit|malicious|infected|sandbox|banned|dangerous/, 'malware'],
  [/\bspam\b|bulk|graymail|gray mail|marketing|newsletter|\badult\b|unsolicited/, 'spam'],
  [/dmarc|dkim|\bspf\b|auth(?:entication)? fail/, 'auth-failure'],
  [/\bdlp\b|data loss|data leak/, 'dlp'],
];
function mailVerdict(...vals) { const s = vals.map(lc).filter(Boolean).join(' '); if (!s) return ''; for (const [re, v] of VERDICT) if (re.test(s)) return v; return ''; }

function normalizeMail(ev, d) {
  const action = mailAction(d.action);
  const verdict = mailVerdict(d.verdict, d.threat, d.attachment, d.url, d.action);
  Object.assign(ev, {
    category: 'email', action: action || 'email-event',
    outcome: action === 'delivered' ? 'success' : action ? 'failure' : 'unknown',
  });
  const dir = /out/.test(lc(d.direction)) ? 'outbound' : /in/.test(lc(d.direction)) ? 'inbound' : '';
  if (!ev.fields) ev.fields = {};
  Object.assign(ev.fields, {
    vendor_class: 'email_gateway', email_vendor: clean(d.vendor) || undefined,
    email_action: action || undefined, email_action_raw: clean(d.action) || undefined,
    email_from: clean(d.from) ? clean(d.from).toLowerCase().slice(0, 320) : undefined,
    email_to: clean(d.to) ? clean(d.to).toLowerCase().slice(0, 500) : undefined,
    email_subject: hashSubject(d.subject), email_verdict: verdict || undefined, email_direction: dir || undefined,
    spam_score: clean(d.spam) || undefined, threat_name: clean(d.threat) || undefined,
    attachment_verdict: clean(d.attachment) || undefined, url_verdict: clean(d.url) || undefined,
    message_id: clean(d.msgid) ? clean(d.msgid).slice(0, 200) : undefined,
  });
  if (clean(d.src) && !ev.src_ip) ev.src_ip = clean(d.src);
  if (d.severity) ev.severity = Math.max(ev.severity || 0, sevFromName(d.severity, 0));
  if (verdict === 'malware') ev.severity = Math.max(ev.severity || 0, action && action !== 'delivered' ? 2 : 3);
  else if (verdict === 'phishing') ev.severity = Math.max(ev.severity || 0, 2);
  if (!ev.tags) ev.tags = [];
  ev.tags.push('email');
  if (verdict) ev.tags.push(verdict === 'auth-failure' ? 'mail-auth' : verdict);
  if (verdict === 'phishing') ev.tags.push('T1566');
  if (!ev.message || ev.message === '') ev.message = `email ${action || 'event'}${verdict ? ' (' + verdict + ')' : ''}${clean(d.from) ? ' from ' + clean(d.from) : ''}`.slice(0, 1000);
  return ev;
}

module.exports = { normalizeMail, mailAction, mailVerdict, hashSubject };
