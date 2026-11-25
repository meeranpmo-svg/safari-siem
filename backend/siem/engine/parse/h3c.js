// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// H3C (and HPE Comware) switches and routers: the Comware information-center format.
//   Comware 7:  "%%10SHELL/5/SHELL_LOGIN: admin logged in from 10.1.1.1."      (%%<version><MODULE>/<level>/<MNEMONIC>(l|s|t)?:)
//   Comware 5:  "SHELL/5/SHELL_LOGIN(l): admin logged in from 10.1.1.1."       (only for a source registered as h3c: too generic to sniff)
// Logins, failed logins, commands typed, configuration saves / changes and interface events are normalised to the same
// actions the Cisco parser uses, so the device rules (failed admin logins, changes outside the window) apply to H3C too.
// Written from the documented format and synthetic lines; real device output may differ by release - unknown messages
// are kept as plain events, never dropped.
const { split, parseTime, ipOrEmpty, sevFromSyslog, clean, wallToMs, MONTHS } = require('./util');
const CW_TS = /\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?::(\d{3}))?\s+(\d{4})\b/;   // Comware: time, then year

const TAG7 = /%%\d{2}([A-Z][A-Z0-9_]*)\/([0-7])\/([A-Z0-9_]+)(?:\([lst]\))?:\s*/;
const TAG5 = /(?:^|\s)%?([A-Z][A-Z0-9_]*)\/([0-7])\/([A-Z0-9_]+)(?:\([lst]\))?:\s*/;
const u = (s) => clean(s).replace(/^["']|["']$/g, '').toLowerCase();
const ip = (s) => ipOrEmpty(String(s || '').replace(/\.$/, ''));

function auth(ev, ok) {
  Object.assign(ev, { category: 'authentication', action: ok ? 'logon' : 'logon-failed', outcome: ok ? 'success' : 'failure' });
  ev.tags.push('admin');
  if (!ok) { ev.tags.push('T1110'); ev.severity = Math.max(ev.severity, 1); }
}

function comware(ev, mod, mn, msg) {
  let m;
  if (mod === 'SHELL' && mn === 'SHELL_LOGIN') {
    if ((m = /^(\S+) logged in from (\S+?)\.?$/.exec(msg))) { ev.user = u(m[1]); ev.src_ip = ip(m[2]); ev.fields.line = ev.src_ip ? '' : m[2]; }
    auth(ev, true);
  } else if (mod === 'SHELL' && mn === 'SHELL_LOGOUT') {
    if ((m = /^(\S+) logged out from (\S+?)\.?$/.exec(msg))) { ev.user = u(m[1]); ev.src_ip = ip(m[2]); }
    Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' });
  } else if ((mod === 'LOGIN' && /LOGIN_FAIL/.test(mn)) || (mod === 'SHELL' && /LOGINFAIL|LOGIN_FAIL/.test(mn)) || (mod === 'SSHS' && /AUTH_FAIL/.test(mn))) {
    if ((m = /^(\S+) failed to log in from (\S+?)\.?$/.exec(msg)) || (m = /user (\S+) \(IP: ([^)]+)\)/i.exec(msg))) { ev.user = u(m[1]); ev.src_ip = ip(m[2]); }
    if (mod === 'SSHS') ev.fields.service = 'ssh';
    auth(ev, false);
  } else if (mod === 'SSHS' && /AUTH_SUCCESS|CONNECT/.test(mn) && /pass(?:ed)?|success/i.test(msg)) {
    if ((m = /user (\S+) \(IP: ([^)]+)\)/i.exec(msg))) { ev.user = u(m[1]); ev.src_ip = ip(m[2]); }
    ev.fields.service = 'ssh'; auth(ev, true);
  } else if (mod === 'SHELL' && mn === 'SHELL_CMD') {
    // -Line=vty0-IPAddr=10.1.1.1-User=admin; Command is undo shutdown
    if ((m = /IPAddr=([^-;\s]+)/.exec(msg))) ev.src_ip = ip(m[1]);
    if ((m = /User=([^-;\s]+)/.exec(msg))) ev.user = u(m[1]);
    if ((m = /Line=([^-;\s]+)/.exec(msg))) ev.fields.line = m[1];
    if ((m = /Command is (.*)$/.exec(msg))) ev.cmdline = m[1].trim().slice(0, 500);
    Object.assign(ev, { category: 'system', action: /^(?:display|dis\b|ping|tracert|quit|return)/i.test(ev.cmdline || '') ? 'command' : 'config-change', outcome: 'success' });
    ev.tags.push('admin');
  } else if (mod === 'CFGMAN' || /CFGCHANGED|CFG_CHANGE|SAVE/.test(mn)) {
    Object.assign(ev, { category: 'system', action: 'config-change', outcome: 'success' });
    if ((m = /User=([^-;\s]+)/.exec(msg))) ev.user = u(m[1]);
    ev.tags.push('admin');
  } else if (mod === 'IFNET' || /UPDOWN|LINK_|PHY_/.test(mn)) {
    Object.assign(ev, { category: 'system', action: 'event' });
    if ((m = /interface (\S+?) changed to (up|down)/i.exec(msg))) { ev.fields.interface = m[1]; ev.fields.state = m[2].toLowerCase(); }
  }
}

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const forced = meta.src_type === 'h3c' || meta.src_type === 'comware' || meta.src_type === 'h3c-comware';
  let m = TAG7.exec(body), v = 7;
  if (!m && forced) { m = TAG5.exec(body); v = 5; }
  if (!m) return null;
  const [tag, mod, sevS, mn] = m;
  const msg = body.slice(m.index + tag.length).trim();
  const prefix = body.slice(0, m.index);
  const ev = {
    src_type: 'h3c', severity: sevFromSyslog(Number(sevS)), category: 'network', action: 'event', outcome: 'unknown',
    event_code: `${mod}-${sevS}-${mn}`, message: msg.slice(0, 1000), tags: [],
    fields: { comware_module: mod, comware_mnemonic: mn, comware_level: sevS, comware_version: String(v) },
  };
  // the device's own header before the tag: "Nov 25 10:00:00 2026 SW-CORE " (Comware puts the year after the time)
  if (prefix.trim()) {
    const tm = /([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?::\d{3})?\s+\d{4})/.exec(prefix);
    if (tm) { const t = tm[1].replace(/(\d{2}:\d{2}:\d{2}):\d{3}/, '$1').replace(/^([A-Z][a-z]{2}\s+\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})$/, '$1 $3 $2'); ev.ts = parseTime(t, meta.tz_offset_min || 0); }
    if (!hdr || !hdr.host) { const hm = /(?:\d{4}|\d{2}:\d{2}:\d{2})\s+([A-Za-z][A-Za-z0-9_.-]*)\s*$/.exec(prefix.trim()); if (hm) ev.host = hm[1]; }
  }
  // a plain syslog header reads Comware's year as the host ("Nov 25 10:00:00 2026 SW-CORE ..."): the real host follows it
  if (hdr && /^\d{4}$/.test(String(hdr.host || ''))) {
    const hm = /^([A-Za-z][A-Za-z0-9_.-]*)\s/.exec(prefix.trim() + ' '); if (hm) ev.host = hm[1];
    if (hdr.ts) { const d = new Date(hdr.ts); d.setUTCFullYear(Number(hdr.host)); ev.ts = d.getTime(); }   // and that "host" is the year
  }
  // Comware's own time stamp "Nov 25 10:00:00 2026" (year after the time, which a plain syslog header cannot read)
  const tw = CW_TS.exec(line);
  if (tw && MONTHS[tw[1].toLowerCase()] !== undefined) ev.ts = wallToMs(+tw[7], MONTHS[tw[1].toLowerCase()], +tw[2], +tw[3], +tw[4], +tw[5], tw[6] ? +tw[6] : 0, meta.tz_offset_min || 0);
  comware(ev, mod, mn, msg);
  return ev;
}

module.exports = {
  name: 'h3c',
  sniff(line, meta = {}) { const { body } = split(line, meta); return TAG7.test(body); },
  parse,
};
