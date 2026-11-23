// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cisco UCS Manager syslog (faults, events, audit). NX-OS style transport header, then the UCSM tag:
//   <187>: 2024 May  1 10:00:00 UTC: %UCSM-3-LINK_DOWN: [F0727][major][link-down][sys/switch-A/slot-1/switch-ether/port-1] ether port 1/1 on fabric interconnect A oper state: link-down, reason: Link failure
//   <190>: 2024 May  1 10:00:01 UTC: %UCSM-6-AUDIT: [creation][admin][internal][sys/user-ext/user-ops][id:12345] User ops created
// Fault lines: [<fault code F####>][<severity>][<cause>][<affected DN>] <description>  (UCS Manager Faults Reference / System
// Monitoring Guide "Syslog"). Event/audit lines carry a variable set of bracket tokens — they are classified by token shape
// (F#### = fault code, E#### = event id, severity word, creation|modification|deletion = audit indication, 'sys/…' = DN,
// 'key:value' = named attribute). ["verify": audit token order against the customer's UCSM release.]
const { split, parseTime, sevFromSyslog, clean, splitUser, ipOrEmpty } = require('./util');

const TAG_RE = /%UCSM-([0-7])-([A-Z0-9_]+):\s*/;
const PREFIX_TS = /(\d{4})\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:\s+([A-Z]{2,5}|[+-]\d{2}:?\d{2}))?/;
const FAULT_SEV = { critical: 4, major: 3, minor: 2, warning: 1, info: 0, cleared: 0, condition: 0, soaking: 1, 'soaking-clearing': 0 };
const INDICATION = new Set(['creation', 'modification', 'deletion']);

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const m = TAG_RE.exec(body);
  if (!m) return null;
  const [tag, sevS, mn] = m;
  let rest = body.slice(m.index + tag.length);
  const prefix = body.slice(0, m.index);
  const ev = {
    src_type: 'cisco-ucs', severity: sevFromSyslog(Number(sevS)), category: 'system', action: 'event', outcome: 'unknown',
    event_code: mn, message: '', tags: [], fields: { ucs_mnemonic: mn, ucs_syslog_severity: sevS },
  };
  const tm = PREFIX_TS.exec(prefix);
  if (tm) ev.ts = parseTime(`${tm[2]} ${tm[3]} ${tm[1]} ${tm[4]}${tm[5] ? ' ' + tm[5] : ''}`, meta.tz_offset_min || 0);
  if (!hdr || !hdr.host) { const hm = /^\s*([A-Za-z][\w.-]*)\s*:?\s+(?:\d{4}\s|%)/.exec(prefix); if (hm) ev.host = hm[1]; }

  // leading bracket tokens
  const tokens = [];
  let bm;
  while ((bm = /^\s*\[([^\]]*)\]/.exec(rest))) { tokens.push(bm[1]); rest = rest.slice(bm[0].length); }
  const desc = rest.trim();
  ev.message = desc || mn;
  const unnamed = [];
  for (const t of tokens) {
    const kv = /^([A-Za-z_]+):(.*)$/.exec(t);
    if (/^F\d{3,5}$/.test(t)) ev.fields.fault_code = t;
    else if (/^E\d{3,6}$/.test(t)) ev.fields.event_id = t;
    else if (FAULT_SEV[t.toLowerCase()] !== undefined && ev.fields.fault_severity === undefined) ev.fields.fault_severity = t.toLowerCase();
    else if (INDICATION.has(t.toLowerCase())) ev.fields.indication = t.toLowerCase();
    else if (/^(?:sys|org|fabric|capabilities|domain)\//.test(t) || /^[a-z-]+\/[a-z-]+/i.test(t) && t.includes('/')) ev.fields.affected_dn = t;
    else if (kv) ev.fields['ucs_' + kv[1].toLowerCase()] = kv[2].trim();
    else unnamed.push(t);
  }
  if (ev.fields.fault_code) { if (unnamed.length) ev.fields.cause = unnamed.shift(); } else if (mn === 'AUDIT' && unnamed.length) {
    // audit: first unnamed token after the indication is the user, the next the trigger (admin/internal)  — verify
    if (!ev.fields.ucs_user) ev.fields.ucs_user = unnamed.shift();
    if (unnamed.length) ev.fields.trigger = unnamed.shift();
  }
  if (unnamed.length) ev.fields.ucs_tokens = unnamed.join('|');

  const dn = ev.fields.affected_dn || '';
  if (ev.fields.fault_code) {
    ev.tags.push('fault');
    const fs = ev.fields.fault_severity || '';
    ev.severity = Math.max(ev.severity, FAULT_SEV[fs] || 0);
    if (fs === 'cleared') { ev.outcome = 'success'; ev.fields.fault_state = 'cleared'; ev.severity = 0; } else ev.outcome = 'failure';
    ev.action = 'event';
    if (/link-down|port-failed|equipment-(?:inoperable|degraded|removed|missing|disabled|unacknowledged)|thermal|voltage|power-problem|psu|fan|memory-degraded|disk|storage/i.test((ev.fields.cause || '') + ' ' + mn)) ev.tags.push('hardware');
  } else if (mn === 'AUDIT' || ev.fields.indication) {
    ev.tags.push('audit', 'admin');
    const who = splitUser(ev.fields.ucs_user || '');
    ev.user = who.user; ev.domain = who.domain;
    const ind = ev.fields.indication || '';
    if (/sys\/user-ext\/sh-login|sys\/user-ext\/web-login|login/i.test(dn + ' ' + desc)) {
      Object.assign(ev, { category: 'authentication', action: ind === 'deletion' ? 'logoff' : 'logon', outcome: 'success' });
      const ipm = /(?:from|host)\s+(\d{1,3}(?:\.\d{1,3}){3})/i.exec(desc); if (ipm) ev.src_ip = ipOrEmpty(ipm[1]);
    } else if (/^sys\/user-ext\/user-/.test(dn) || /\buser\b.*\b(created|deleted|modified)/i.test(desc)) {
      Object.assign(ev, { category: 'iam', action: ind === 'creation' ? 'user-created' : ind === 'deletion' ? 'user-deleted' : 'user-modified', outcome: 'success', severity: Math.max(ev.severity, 2) });
      const um = /sys\/user-ext\/user-([^/\]\s]+)/.exec(dn); if (um) ev.target_user = um[1].toLowerCase();
    } else {
      Object.assign(ev, { action: 'config-change', outcome: 'success', severity: Math.max(ev.severity, 1) });
    }
  } else if (/LOGIN|AUTH/i.test(mn)) {
    const failed = /fail|denied|invalid|rejected/i.test(mn + ' ' + desc);
    Object.assign(ev, { category: 'authentication', action: failed ? 'logon-failed' : 'logon', outcome: failed ? 'failure' : 'success' });
    const um = /[Uu]ser\s+'?([^'\s]+)'?/.exec(desc); if (um) ev.user = clean(um[1]).toLowerCase();
    const ipm = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(desc); if (ipm) ev.src_ip = ipOrEmpty(ipm[1]);
    if (failed) ev.tags.push('T1110');
  } else {
    ev.tags.push('event');
    if (/UP$|_UP_|CLEAR/.test(mn)) ev.outcome = 'success';
  }
  return ev;
}

module.exports = {
  name: 'cisco-ucs',
  sniff(line, meta = {}) { const { body } = split(line, meta); return TAG_RE.test(body); },
  parse,
};
