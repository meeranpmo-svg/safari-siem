// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Libraesva Email Security Gateway (ESG) — the customer's secure email gateway (type `libraesva`). Libraesva ESG is a
 * Postfix + Amavis(New) based appliance that forwards its mail logs by remote syslog (Admin → System → Log settings /
 * remote syslog). The exact line format depends on the release and the admin's forwarding configuration —
 * // VERIFY in customer environment. This parser handles, most-specific first:
 *   1) a Libraesva structured key=value mail line (the documented default we onboard with), e.g.
 *      libraesva-esg: action=Quarantined direction=Inbound from=<a@ext> to=<b@corp> subject="Invoice" score=9.9
 *        verdict=Spam msgid=<...> clientip=203.0.113.9 attachment=clean urlsand=clean
 *   2) Amavis(New) verdict lines (the scanning engine under ESG):
 *      amavis[1234]: (02918-16) Blocked SPAM {DiscardedInbound}, [203.0.113.9]:1234 <a@ext> -> <b@corp>,
 *        Message-ID: <...>, Hits: 12.3, ...  (QuickSand = attachment sandbox, URLSand = URL sandbox)
 *   3) Postfix smtpd reject / milter-reject lines -> rejected.
 * Everything else from a libraesva source becomes a generic email event (never dropped, never thrown). All mapping is
 * done by engine/parse/mailnorm.js so the fields match the CEF email-gateway hook exactly (category email, email_from /
 * email_to / email_subject (PDPL-hashed) / email_action / email_verdict / email_direction / spam_score / threat_name /
 * attachment_verdict / url_verdict / message_id). Microsoft Defender for Office 365 rides the M365 connector, not here.
 */
const { split, clean, ipOrEmpty, parseKV, sevFromSyslog } = require('./util');
const { normalizeMail } = require('./mailnorm');

const APP_MARK = /^(?:amavis|amavisd|libraesva|esg)/i;
const MARK = /\b(?:libraesva|amavisd?|quicksand|urlsand)\b/i;
const unangle = (s) => clean(s).replace(/^<+|>+$/g, '');

function fromAmavis(text) {
  // (id) <Verb> <CATEGORY> {PolicyBank}, [ip]:port <from> -> <to>, ... Message-ID: <...>, Hits: N
  const vm = /\b(Passed|Blocked|Not-Delivered|Temporarily-Blocked|TempFailed)\b\s+([A-Za-z-]+)?\s*(?:\{([^}]*)\})?/i.exec(text);
  if (!vm) return null;
  const verb = vm[1], cat = vm[2] || '', bank = vm[3] || '';
  const addr = /<([^>]*)>\s*->\s*<([^>]*)>/.exec(text) || /\bfrom\s+<([^>]*)>.*?\bto\s+<([^>]*)>/i.exec(text);
  const ipm = /\[(\d{1,3}(?:\.\d{1,3}){3})\](?::\d+)?/.exec(text);
  const mid = /Message-ID:\s*<?([^>,\s]+)>?/i.exec(text);
  const hits = /Hits:\s*(-?\d+(?:\.\d+)?)/i.exec(text);
  return {
    vendor: 'Libraesva',
    action: `${verb} ${bank}`.trim(),
    verdict: `${cat} ${bank}`.trim(),
    from: addr ? unangle(addr[1]) : '',
    to: addr ? unangle(addr[2]) : '',
    subject: '', // Amavis does not emit the subject in clear on the verdict line
    spam: hits ? hits[1] : '',
    direction: /inbound/i.test(bank) ? 'Inbound' : /outbound/i.test(bank) ? 'Outbound' : '',
    threat: /INFECTED|BANNED|MALWARE|VIRUS/i.test(cat) ? cat : '',
    msgid: mid ? mid[1] : '',
    src: ipm ? ipOrEmpty(ipm[1]) : '',
  };
}

function fromPostfixReject(text) {
  const ipm = /\bfrom\s+\S+\[(\d{1,3}(?:\.\d{1,3}){3})\]/i.exec(text);
  const rcpt = /\bto=<([^>]*)>/i.exec(text) || /RCPT from[^:]*:\s*\S+\s+\S+\s+<([^>]*)>/i.exec(text);
  const from = /\bfrom=<([^>]*)>/i.exec(text);
  const reason = /:\s*(5\d\d\s[^;]+)/.exec(text);
  return {
    vendor: 'Libraesva', action: 'reject', verdict: /spam/i.test(text) ? 'spam' : /virus|malware/i.test(text) ? 'malware' : reason ? reason[1] : 'reject',
    from: from ? unangle(from[1]) : '', to: rcpt ? unangle(rcpt[1]) : '', direction: 'Inbound',
    src: ipm ? ipOrEmpty(ipm[1]) : '', subject: '',
  };
}

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const text = String(body || '').trim();
  if (!text) return null;
  const app = (hdr && hdr.app ? hdr.app : '').replace(/[/[].*$/, '').toLowerCase();
  const ev = {
    src_type: 'libraesva', category: 'email', action: 'email-event', outcome: 'unknown',
    severity: hdr && hdr.sev >= 0 ? sevFromSyslog(hdr.sev) : 0, process: app || 'libraesva',
    message: text.slice(0, 1000), tags: [], fields: {},
  };
  let d = null;
  if (/\b(?:action|verdict|direction|msgid|clientip|score)=/i.test(text)) {
    const kv = parseKV(text, { lowerKeys: true });
    d = {
      vendor: 'Libraesva',
      action: kv.action || kv.disposition || kv.status,
      verdict: kv.verdict || kv.threat || kv.spamclass || kv.classification,
      direction: kv.direction,
      from: unangle(kv.from || kv.sender || kv.mailfrom || kv.envfrom),
      to: unangle(kv.to || kv.rcpt || kv.recipient || kv.envto),
      subject: kv.subject,
      spam: kv.score || kv.spamscore || kv.hits,
      threat: kv.virus || kv.malware || kv.threatname || kv.signature,
      attachment: kv.attachment || kv.quicksand || kv.attachmentverdict,
      url: kv.urlsand || kv.urlverdict || kv.url,
      msgid: unangle(kv.msgid || kv.messageid),
      src: ipOrEmpty(kv.clientip || kv.ip || kv.senderip || kv.src),
    };
  } else if (/\bamavis/i.test(app) || /\(\d+-\d+\)/.test(text)) {
    d = fromAmavis(text);
  } else if (/\breject\b|milter-reject|blocked using/i.test(text) && /postfix|smtpd|cleanup/.test(app + ' ' + text)) {
    d = fromPostfixReject(text);
  }
  if (!d) { ev.tags.push('email'); return ev; }
  if (d.src) ev.src_ip = d.src;
  normalizeMail(ev, d);
  return ev;
}

module.exports = {
  name: 'libraesva',
  sniff(line, meta = {}) {
    const { hdr, body } = split(line, meta);
    if (hdr && APP_MARK.test(hdr.app || '')) return true;
    const b = String(body || '');
    if (MARK.test(b)) return true;
    // Amavis verdict line without a vendor word: "(id) Passed|Blocked CATEGORY {Bank}, [ip] <a> -> <b>"
    return /\(\d+-\d+\)\s+(?:Passed|Blocked|Not-Delivered|TempFailed)\b/.test(b) && /<[^>]*>\s*->\s*<[^>]*>/.test(b);
  },
  parse,
  fromAmavis,
};
