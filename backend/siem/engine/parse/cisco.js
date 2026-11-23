// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cisco ASA / FTD (%ASA-6-302013: …) and IOS / IOS-XE (%SEC_LOGIN-4-LOGIN_FAILED: …) basics.
const { split, parseTime, toInt, ipOrEmpty, protoName, sevFromSyslog, clean } = require('./util');

const TAG_RE = /%([A-Z][A-Z0-9_]*)-([0-7])-([A-Z0-9_]+):?\s*/;
const ASA = new Set(['ASA', 'FTD', 'PIX', 'FWSM']);
const u = (s) => clean(s).replace(/^["']|["']$/g, '').toLowerCase();

function net(ev, action, src, sport, dst, dport, proto) {
  return Object.assign(ev, {
    category: 'network', action, outcome: action === 'blocked' ? 'failure' : 'success',
    src_ip: ipOrEmpty(src), src_port: toInt(sport), dst_ip: ipOrEmpty(dst), dst_port: toInt(dport), proto: protoName(proto),
  });
}

function asa(ev, id, msg) {
  let m;
  switch (id) {
    case '106023':
      if ((m = /^Deny (\S+) src (\S+?):([^/\s]+)(?:\/(\d+))? dst (\S+?):([^/\s]+)(?:\/(\d+))?(?: .*?by access-group "([^"]+)")?/.exec(msg))) {
        net(ev, 'blocked', m[3], m[4], m[6], m[7], m[1]);
        Object.assign(ev.fields, { src_if: m[2], dst_if: m[5], acl: m[8] });
      }
      return;
    case '106001':
      if ((m = /^Inbound (\S+) connection denied from ([^/\s]+)\/(\d+) to ([^/\s]+)\/(\d+)/.exec(msg))) net(ev, 'blocked', m[2], m[3], m[4], m[5], m[1]);
      return;
    case '106006': case '106007': case '106015':
      if ((m = /^Deny (?:inbound )?(\S+) (?:\(No connection\) )?from ([^/\s]+)\/(\d+) to ([^/\s]+)\/(\d+)/.exec(msg))) net(ev, 'blocked', m[2], m[3], m[4], m[5], m[1]);
      return;
    case '106014':
      if ((m = /^Deny (?:inbound|outbound) icmp src (\S+?):(\S+) dst (\S+?):(\S+)/.exec(msg))) net(ev, 'blocked', m[2], 0, m[4], 0, 'icmp');
      return;
    case '106100':
      if ((m = /^access-list (\S+) (permitted|denied|est-allowed) (\S+) (\S+?)\/([^(]+)\((\d+)\)[^-]*-> (\S+?)\/([^(]+)\((\d+)\)/.exec(msg))) {
        net(ev, m[2] === 'denied' ? 'blocked' : 'allowed', m[5], m[6], m[8], m[9], m[3]);
        Object.assign(ev.fields, { acl: m[1], src_if: m[4], dst_if: m[7] });
      }
      return;
    case '302013': case '302015':
      if ((m = /^Built (inbound|outbound) (\S+) connection (\d+) for (\S+?):([^/\s]+)\/(\d+) .*?to (\S+?):([^/\s]+)\/(\d+)/.exec(msg))) {
        if (m[1] === 'outbound') net(ev, 'connection', m[8], m[9], m[5], m[6], m[2]);
        else net(ev, 'connection', m[5], m[6], m[8], m[9], m[2]);
        Object.assign(ev.fields, { direction: m[1], conn_id: m[3] });
      }
      return;
    case '302014': case '302016':
      if ((m = /^Teardown (\S+) connection (\d+) for (\S+?):([^/\s]+)\/(\d+) to (\S+?):([^/\s]+)\/(\d+)(?: duration (\S+) bytes (\d+))?/.exec(msg))) {
        net(ev, 'connection', m[4], m[5], m[7], m[8], m[1]);
        Object.assign(ev.fields, { conn_id: m[2], teardown: 'true', duration: m[9], bytes: m[10] });
      }
      return;
    case '113004': case '113005': case '113015': {
      const ok = /Successful/i.test(msg);
      Object.assign(ev, { category: 'authentication', action: ok ? 'logon' : 'logon-failed', outcome: ok ? 'success' : 'failure', severity: ok ? ev.severity : Math.max(ev.severity, 1) });
      if ((m = /user = ([^:]+?)(?: :|$)/.exec(msg))) ev.user = u(m[1]);
      if ((m = /user IP = (\S+)/.exec(msg))) ev.src_ip = ipOrEmpty(m[1]);
      if ((m = /server = (\S+)/.exec(msg))) ev.fields.aaa_server = m[1];
      if ((m = /reason = ([^:]+?) :/.exec(msg))) ev.fields.reason = m[1];
      if (!ok) ev.tags.push('T1110');
      return;
    }
    case '605004': case '605005': {
      const ok = id === '605005';
      if ((m = /from ([^/\s]+)\/(\d+) to (\S+?):([^/\s]+)\/(\S+) for user "([^"]*)"/.exec(msg))) {
        Object.assign(ev, { src_ip: ipOrEmpty(m[1]), src_port: toInt(m[2]), dst_ip: ipOrEmpty(m[4]), user: u(m[6]) });
        ev.fields.service = m[5];
      }
      Object.assign(ev, { category: 'authentication', action: ok ? 'logon' : 'logon-failed', outcome: ok ? 'success' : 'failure', severity: ok ? ev.severity : Math.max(ev.severity, 2) });
      ev.tags.push('admin');
      if (!ok) ev.tags.push('T1110');
      return;
    }
    case '111008': case '111010':
      if ((m = /^User '([^']+)'(?:, running '([^']*)' from IP (\S+),)? executed (?:the )?'([^']+)'/.exec(msg))) {
        Object.assign(ev, { user: u(m[1]), src_ip: ipOrEmpty(m[3]), cmdline: m[4] });
      }
      Object.assign(ev, { category: 'system', action: 'config-change', outcome: 'success' });
      ev.tags.push('admin');
      return;
    case '113039': case '722051': case '716001':
      if ((m = /Group <([^>]*)> User <([^>]*)> IP <([^>]*)>/.exec(msg))) {
        Object.assign(ev, { user: u(m[2]), src_ip: ipOrEmpty(m[3]) });
        ev.fields.vpn_group = m[1];
      }
      Object.assign(ev, { category: 'authentication', action: id === '722051' ? 'vpn-event' : 'logon', outcome: 'success' });
      ev.tags.push('vpn');
      return;
    case '733100':
      Object.assign(ev, { category: 'network', action: 'ips-detection', severity: Math.max(ev.severity, 2) });
      return;
    default:
      if (/^4000\d\d$/.test(id) && (m = /^IPS:(\d+) (.*?) from (\S+) to (\S+) on interface (\S+)/.exec(msg))) {
        Object.assign(ev, { category: 'network', action: 'ips-detection', src_ip: ipOrEmpty(m[3]), dst_ip: ipOrEmpty(m[4]), severity: Math.max(ev.severity, 2) });
        ev.fields.signature = m[1];
      }
  }
}

function ios(ev, fac, mn, msg) {
  let m;
  const key = fac + '-' + mn;
  if (key === 'SEC_LOGIN-LOGIN_FAILED' || key === 'SEC_LOGIN-LOGIN_SUCCESS') {
    const ok = mn === 'LOGIN_SUCCESS';
    if ((m = /\[user: ([^\]]*)\]/.exec(msg))) ev.user = u(m[1]);
    if ((m = /\[Source: ([^\]]*)\]/.exec(msg))) ev.src_ip = ipOrEmpty(m[1]);
    if ((m = /\[localport: (\d+)\]/.exec(msg))) ev.dst_port = toInt(m[1]);
    if ((m = /\[Reason: ([^\]]*)\]/.exec(msg))) ev.fields.reason = m[1];
    Object.assign(ev, { category: 'authentication', action: ok ? 'logon' : 'logon-failed', outcome: ok ? 'success' : 'failure' });
    if (!ok) { ev.tags.push('T1110'); ev.severity = Math.max(ev.severity, 1); }
    ev.tags.push('admin');
  } else if (key === 'SYS-CONFIG_I') {
    if ((m = /Configured from (\S+) by (\S+)(?: on (\S+))?(?: \(([^)]+)\))?/.exec(msg))) {
      Object.assign(ev, { user: u(m[2]), src_ip: ipOrEmpty(m[4]) });
      ev.fields.config_source = m[1];
      if (m[3]) ev.fields.line = m[3];
    }
    Object.assign(ev, { category: 'system', action: 'config-change', outcome: 'success' });
    ev.tags.push('admin');
  } else if (key === 'PARSER-CFGLOG_LOGGEDCMD') {
    if ((m = /User:(\S+)\s+logged command:(.*)$/.exec(msg))) Object.assign(ev, { user: u(m[1]), cmdline: m[2].trim() });
    Object.assign(ev, { category: 'system', action: 'config-change', outcome: 'success' });
  } else if (fac === 'SEC' && /^IPACCESSLOG/.test(mn)) {
    if ((m = /list (\S+) (permitted|denied) (\S+) ([0-9a-fA-F.:]+)(?:\((\d+)\))? -> ([0-9a-fA-F.:]+)(?:\((\d+)\))?/.exec(msg))) {
      net(ev, m[2] === 'denied' ? 'blocked' : 'allowed', m[4], m[5], m[6], m[7], m[3]);
      ev.fields.acl = m[1];
    }
  } else if (fac === 'SSH' && /USERAUTH/.test(mn)) {
    if ((m = /User '([^']+)' authentication for SSH2? Session from (\S+).*?(Succeeded|Failed)/i.exec(msg))) {
      const ok = /succeeded/i.test(m[3]);
      Object.assign(ev, { category: 'authentication', action: ok ? 'logon' : 'logon-failed', outcome: ok ? 'success' : 'failure', user: u(m[1]), src_ip: ipOrEmpty(m[2]) });
      if (!ok) ev.tags.push('T1110');
    }
  } else if (/UPDOWN|CHANGED/.test(mn)) {
    ev.category = 'system';
    ev.action = 'event';
  }
}

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const m = TAG_RE.exec(body);
  if (!m) return null;
  const [tag, fac, sevS, mn] = m;
  const msg = body.slice(m.index + tag.length).trim();
  const prefix = body.slice(0, m.index);
  const ev = {
    src_type: 'cisco', severity: sevFromSyslog(Number(sevS)), category: 'network', action: 'event', outcome: 'unknown',
    event_code: ASA.has(fac) ? mn : `${fac}-${sevS}-${mn}`, message: msg.slice(0, 1000), tags: [],
    fields: { cisco_facility: fac, cisco_mnemonic: mn, cisco_severity: sevS },
  };
  // IOS prefix: "52: test-rtr-01: *May  1 10:00:00.123 UTC: " or ASA "May 01 2024 10:00:00 asa-01 : "
  if (prefix.trim()) {
    const tm = /\*?\.?([A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+(?:UTC|GMT|Z))?)/.exec(prefix);
    if (tm) ev.ts = parseTime(tm[1], meta.tz_offset_min || 0);
    if (!hdr || !hdr.host) {
      const hm = /(?:^|\s)([A-Za-z][A-Za-z0-9_.-]*):\s/.exec(prefix.replace(/\*?[A-Z][a-z]{2}\s+\d.*$/, ''));
      if (hm) ev.host = hm[1];
    }
  }
  if (ASA.has(fac)) asa(ev, mn, msg);
  else ios(ev, fac, mn, msg);
  return ev;
}

module.exports = {
  name: 'cisco',
  sniff(line, meta = {}) { const { body } = split(line, meta); return TAG_RE.test(body); },
  parse,
};
