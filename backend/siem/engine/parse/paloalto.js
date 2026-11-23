// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Palo Alto Networks PAN-OS syslog (CSV "default" format, not CEF — CEF-formatted PAN logs are handled by cef.js).
//   <14>May  1 10:00:00 pa-fw-01 1,2024/05/01 10:00:00,0123456789,TRAFFIC,end,2561,2024/05/01 10:00:00,10.0.1.5,…
// Field positions follow the PAN-OS "Syslog Field Descriptions" documentation (Traffic / Threat / System / Config /
// User-ID / GlobalProtect). Positions 0-52 of TRAFFIC, 0-59 of THREAT, 0-22 of SYSTEM, 0-23 of CONFIG and 0-25 of
// USERID have been stable since PAN-OS 8.x; the tail (device-ID / SD-WAN / high-res timestamp) grows with each release
// and is only mapped where unambiguous. ["verify" marks = check against the PAN-OS version the customer runs.]
// Fields the firewall leaves empty are omitted; nothing is invented.
const { split, parseTime, sevFromName, toInt, ipOrEmpty, protoName, splitUser, clean } = require('./util');

// CSV with "quoted" fields (PAN quotes a field that contains a comma or a quote; "" = escaped quote).
function csv(s) {
  const out = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === '"') { if (s[i + 1] === '"') { cur += '"'; i++; } else q = false; }
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

const TYPES = new Set(['TRAFFIC', 'THREAT', 'SYSTEM', 'CONFIG', 'USERID', 'GLOBALPROTECT', 'HIPMATCH', 'CORRELATION', 'DECRYPTION', 'AUTH', 'AUTHENTICATION', 'TUNNEL', 'SCTP', 'IPTAG', 'GTP', 'USERID']);
const START_RE = /(?:^|\s)\d*,\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2},[^,]*,(?:TRAFFIC|THREAT|SYSTEM|CONFIG|USERID|GLOBALPROTECT|HIPMATCH|CORRELATION|DECRYPTION|AUTH|AUTHENTICATION|TUNNEL|SCTP|IPTAG|GTP)(?:,|$)/;
// PAN writes "YYYY/MM/DD HH:MM:SS" in the firewall's local time (no zone) → ISO so parseTime applies the source offset
const panTime = (s, off) => parseTime(String(s || '').replace(/^(\d{4})\/(\d{2})\/(\d{2}) /, '$1-$2-$3T'), off);

// position tables (0-based). Names are the documented field names in snake_case.
const COMMON = { 1: 'receive_time', 2: 'serial', 3: 'pan_type', 4: 'subtype', 6: 'generated_time' };
const TRAFFIC = { 7: 'src', 8: 'dst', 9: 'natsrc', 10: 'natdst', 11: 'rule', 12: 'srcuser', 13: 'dstuser', 14: 'app', 15: 'vsys', 16: 'from_zone', 17: 'to_zone',
  18: 'inbound_if', 19: 'outbound_if', 20: 'logset', 22: 'sessionid', 23: 'repeatcnt', 24: 'sport', 25: 'dport', 26: 'natsport', 27: 'natdport', 28: 'flags',
  29: 'proto', 30: 'pan_action', 31: 'bytes', 32: 'bytes_sent', 33: 'bytes_received', 34: 'packets', 35: 'start', 36: 'elapsed', 37: 'category', 39: 'seqno',
  40: 'actionflags', 41: 'src_country', 42: 'dst_country', 44: 'pkts_sent', 45: 'pkts_received', 46: 'session_end_reason', 47: 'dg_hier_level_1', 48: 'dg_hier_level_2',
  49: 'dg_hier_level_3', 50: 'dg_hier_level_4', 51: 'vsys_name', 52: 'device_name', 53: 'action_source',
  // PAN-OS 9.0+ tail — verify positions per release
  65: 'rule_uuid', 68: 'policy_id', 75: 'xff_ip', 82: 'src_hostname', 91: 'dst_hostname' };
const THREAT = { 7: 'src', 8: 'dst', 9: 'natsrc', 10: 'natdst', 11: 'rule', 12: 'srcuser', 13: 'dstuser', 14: 'app', 15: 'vsys', 16: 'from_zone', 17: 'to_zone',
  18: 'inbound_if', 19: 'outbound_if', 20: 'logset', 22: 'sessionid', 23: 'repeatcnt', 24: 'sport', 25: 'dport', 26: 'natsport', 27: 'natdport', 28: 'flags',
  29: 'proto', 30: 'pan_action', 31: 'misc', 32: 'threat_name', 33: 'category', 34: 'pan_severity', 35: 'direction', 36: 'seqno', 37: 'actionflags',
  38: 'src_country', 39: 'dst_country', 41: 'contenttype', 42: 'pcap_id', 43: 'filedigest', 44: 'cloud', 45: 'url_idx', 46: 'user_agent', 47: 'filetype',
  48: 'xff', 49: 'referer', 50: 'sender', 51: 'subject', 52: 'recipient', 53: 'reportid', 54: 'dg_hier_level_1', 55: 'dg_hier_level_2', 56: 'dg_hier_level_3',
  57: 'dg_hier_level_4', 58: 'vsys_name', 59: 'device_name',
  // PAN-OS 8.1+/9.0+ tail — verify positions per release
  63: 'http_method', 69: 'thr_category', 70: 'contentver', 76: 'rule_uuid' };
const SYSTEM = { 7: 'vsys', 8: 'eventid', 9: 'object', 12: 'module', 13: 'pan_severity', 14: 'description', 15: 'seqno', 16: 'actionflags',
  17: 'dg_hier_level_1', 18: 'dg_hier_level_2', 19: 'dg_hier_level_3', 20: 'dg_hier_level_4', 21: 'vsys_name', 22: 'device_name' };
const CONFIG = { 7: 'client_host', 8: 'vsys', 9: 'command', 10: 'admin', 11: 'client', 12: 'result', 13: 'path', 14: 'before_change', 15: 'after_change',
  16: 'seqno', 17: 'actionflags', 18: 'dg_hier_level_1', 19: 'dg_hier_level_2', 20: 'dg_hier_level_3', 21: 'dg_hier_level_4', 22: 'vsys_name', 23: 'device_name',
  24: 'device_group', 25: 'audit_comment' /* verify: 10.0+ */ };
const USERID = { 7: 'vsys', 8: 'ip', 9: 'user', 10: 'datasourcename', 11: 'eventid', 12: 'repeatcnt', 13: 'timeout', 14: 'beginport', 15: 'endport',
  16: 'datasource', 17: 'datasourcetype', 18: 'seqno', 19: 'actionflags', 20: 'dg_hier_level_1', 21: 'dg_hier_level_2', 22: 'dg_hier_level_3', 23: 'dg_hier_level_4',
  24: 'vsys_name', 25: 'device_name', 27: 'factortype' /* verify: 8.0+ */ };
// GlobalProtect log (own log type since PAN-OS 9.1) — verify positions per release
const GLOBALPROTECT = { 7: 'vsys', 8: 'eventid', 9: 'stage', 10: 'auth_method', 11: 'tunnel_type', 12: 'srcuser', 13: 'src_region', 14: 'machinename',
  15: 'public_ip', 16: 'public_ipv6', 17: 'private_ip', 18: 'private_ipv6', 19: 'hostid', 20: 'serialnumber', 21: 'client_ver', 22: 'client_os', 23: 'client_os_ver',
  24: 'repeatcnt', 25: 'reason', 26: 'error', 27: 'opaque', 28: 'status', 29: 'location', 30: 'login_duration', 31: 'connect_method', 32: 'error_code', 33: 'portal',
  34: 'seqno', 35: 'actionflags' };
const TABLES = { TRAFFIC, THREAT, SYSTEM, CONFIG, USERID, GLOBALPROTECT, DECRYPTION: TRAFFIC };

const BLOCK = new Set(['deny', 'drop', 'reset-client', 'reset-server', 'reset-both', 'block-url', 'block-ip', 'random-drop', 'sinkhole', 'block-continue', 'block-override', 'drop-all-packets']);
const ALLOW = new Set(['allow', 'alert', 'continue', 'override', 'syncookie-sent', 'allow-all']);
const verdict = (a) => (BLOCK.has(a) ? 'blocked' : ALLOW.has(a) ? 'allowed' : '');

// after-change detail of a security rule: source any + destination any + action allow (XML or set-cli form)
function anyAnyAllow(path, after) {
  if (!/rulebase\/security|security\s+rules|rulebase security/i.test(path || '') || !after) return false;
  const t = after.toLowerCase();
  const anyIn = (tag) => new RegExp(`<${tag}>\\s*<member>any</member>\\s*</${tag}>|\\b${tag}\\s+any\\b|"${tag}"\\s*:\\s*\\[?\\s*"any"`).test(t);
  return anyIn('source') && anyIn('destination') && /<action>allow<\/action>|\baction\s+allow\b|"action"\s*:\s*"allow"/.test(t);
}

function parse(line, meta = {}) {
  const { body } = split(line, meta);
  const at = body.search(START_RE);
  if (at < 0) return null;
  const cols = csv(body.slice(at).replace(/^\s+/, ''));
  const type = (cols[3] || '').toUpperCase();
  if (!TYPES.has(type)) return null;
  const table = TABLES[type] || {};
  const f = {};
  for (const [i, name] of Object.entries(COMMON)) if (cols[i] !== undefined && cols[i] !== '') f[name] = cols[i];
  for (const [i, name] of Object.entries(table)) if (cols[i] !== undefined && cols[i] !== '') f[name] = cols[i];
  f.pan_type = type;
  const sub = String(f.subtype || '').toLowerCase();
  const act = String(f.pan_action || '').toLowerCase();
  const off = meta.tz_offset_min || 0;
  const ev = {
    src_type: 'paloalto', ts: panTime(f.generated_time || f.receive_time || '', off), host: clean(f.device_name),
    src_ip: ipOrEmpty(f.src), dst_ip: ipOrEmpty(f.dst), src_port: toInt(f.sport), dst_port: toInt(f.dport), proto: protoName(f.proto),
    user: '', domain: '', event_code: `${type}${sub ? ':' + sub : ''}`, severity: 0, category: 'network', action: 'event', outcome: 'unknown',
    message: '', tags: [], fields: f,
  };
  if (f.srcuser) { const w = splitUser(f.srcuser); ev.user = w.user; ev.domain = w.domain; }
  if (f.dstuser) ev.target_user = splitUser(f.dstuser).user;
  if (!ev.host && meta.syslog && meta.syslog.host) ev.host = meta.syslog.host;

  if (type === 'TRAFFIC' || type === 'DECRYPTION') {
    const vd = verdict(act) || 'allowed';
    ev.action = vd;
    ev.outcome = vd === 'blocked' ? 'failure' : 'success';
    ev.message = `${sub} ${act || vd} ${f.src || ''}:${f.sport || ''} → ${f.dst || ''}:${f.dport || ''} ${f.app || ''} rule=${f.rule || ''}`.trim();
  } else if (type === 'THREAT') {
    const vd = verdict(act);
    ev.severity = sevFromName(f.pan_severity, 0);
    ev.outcome = vd === 'blocked' ? 'failure' : vd === 'allowed' ? 'success' : 'unknown';
    if (f.user_agent) ev.user_agent = f.user_agent;
    if (f.http_method) ev.http_method = f.http_method.toUpperCase();
    if (f.filedigest) ev.hash = clean(f.filedigest).toLowerCase();
    if (sub === 'url') {
      ev.category = 'web'; ev.action = vd || 'allowed'; ev.url = f.misc || '';
      ev.message = `URL ${act}: ${f.misc || ''} (${f.category || ''})`;
    } else if (sub === 'virus' || sub === 'wildfire-virus') {
      ev.category = 'malware'; ev.action = 'av-detection'; ev.severity = Math.max(ev.severity, 3); ev.url = f.misc || '';
      ev.message = `AV: ${f.threat_name || ''} in ${f.misc || ''}`.trim();
    } else if (sub === 'vulnerability' || sub === 'spyware' || sub === 'scan' || sub === 'flood' || sub === 'packet') {
      ev.action = 'ips-detection'; ev.severity = Math.max(ev.severity, sub === 'scan' || sub === 'flood' ? 1 : 2);
      ev.message = `IPS: ${f.threat_name || sub} ${act}`.trim();
    } else if (sub === 'file' || sub === 'data' || sub === 'wildfire') {
      ev.category = 'file'; ev.action = vd || 'allowed'; ev.url = f.misc || '';
      ev.message = `${sub} ${act}: ${f.misc || f.threat_name || ''}`.trim();
    } else {
      ev.action = vd || 'event';
      ev.message = `${sub} ${act} ${f.threat_name || ''}`.trim();
    }
    if (f.threat_name) { const m = /\((\d+)\)\s*$/.exec(f.threat_name); if (m) f.threat_id = m[1]; }
  } else if (type === 'SYSTEM') {
    ev.category = 'system';
    ev.severity = sevFromName(f.pan_severity, 0);
    const eid = String(f.eventid || '').toLowerCase();
    const desc = f.description || '';
    ev.message = desc || eid;
    ev.event_code = `SYSTEM:${eid || sub}`;
    let m;
    if (eid === 'auth-fail' || /authentication failed|failed authentication/i.test(desc)) {
      Object.assign(ev, { category: 'authentication', action: 'logon-failed', outcome: 'failure', severity: Math.max(ev.severity, 2) });
      ev.tags.push('admin', 'T1110');
    } else if (eid === 'auth-success' || /logged in via/i.test(desc)) {
      Object.assign(ev, { category: 'authentication', action: 'logon', outcome: 'success' });
      ev.tags.push('admin');
    } else if (/logged out/i.test(desc)) {
      Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' });
      ev.tags.push('admin');
    } else if (sub === 'globalprotect' || /^globalprotect/.test(eid) || /gateway-auth|portal-auth/.test(eid)) {
      const failed = /fail|denied|invalid/i.test(eid + ' ' + desc);
      Object.assign(ev, { category: 'authentication', action: failed ? 'logon-failed' : /logout|disconnect/i.test(eid + ' ' + desc) ? 'logoff' : 'logon', outcome: failed ? 'failure' : 'success' });
      ev.tags.push('vpn');
      if (failed) ev.tags.push('T1110');
    } else if (eid === 'commit' || eid === 'commit-all' || /^config/.test(sub)) {
      Object.assign(ev, { action: 'config-change', outcome: /fail/i.test(desc) ? 'failure' : 'success' });
      ev.tags.push('admin');
    } else {
      ev.action = 'event';
    }
    if ((m = /user '?([^' ]+)'?/i.exec(desc)) && !ev.user) { const w = splitUser(m[1]); ev.user = w.user; ev.domain = w.domain; }
    if ((m = /(?:from|From):?\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]+)/.exec(desc)) && !ev.src_ip) ev.src_ip = ipOrEmpty(m[1]);
    if ((m = /Reason:\s*([^.]+)/.exec(desc))) f.reason = m[1].trim();
  } else if (type === 'CONFIG') {
    ev.category = /rulebase|security|nat|policy/i.test(f.path || '') ? 'policy' : 'system';
    ev.action = 'config-change';
    ev.outcome = /^succ/i.test(f.result || '') ? 'success' : /fail/i.test(f.result || '') ? 'failure' : 'unknown';
    ev.severity = 1;
    ev.tags.push('admin');
    if (f.admin) { const w = splitUser(f.admin); ev.user = w.user; ev.domain = w.domain; }
    ev.src_ip = ipOrEmpty(f.client_host);
    ev.cmdline = [f.command, f.path].filter(Boolean).join(' ').slice(0, 2000);
    ev.event_code = `CONFIG:${String(f.command || '').toLowerCase()}`;
    ev.message = `${f.admin || '?'} ${f.command || ''} ${f.path || ''} via ${f.client || ''} (${f.result || ''})`.trim();
    if (anyAnyAllow(f.path, f.after_change)) { f.rule_any_any = 'true'; ev.severity = 3; ev.tags.push('any-any-rule'); }
  } else if (type === 'USERID') {
    ev.category = 'authentication';
    ev.src_ip = ipOrEmpty(f.ip);
    if (f.user) { const w = splitUser(f.user); ev.user = w.user; ev.domain = w.domain; }
    const eid = String(f.eventid || '').toLowerCase();
    ev.event_code = `USERID:${eid || sub}`;
    ev.action = /logout|timeout|delete/.test(eid) ? 'logoff' : /login|logon|add/.test(eid) ? 'logon' : 'event';
    ev.outcome = ev.action === 'event' ? 'unknown' : 'success';
    ev.message = `User-ID ${eid || sub}: ${f.user || ''} ${f.ip || ''} (${f.datasourcename || f.datasource || ''})`.trim();
  } else if (type === 'GLOBALPROTECT') {
    ev.category = 'authentication';
    ev.tags.push('vpn');
    ev.src_ip = ipOrEmpty(f.public_ip) || ipOrEmpty(f.public_ipv6);
    if (f.srcuser) { const w = splitUser(f.srcuser); ev.user = w.user; ev.domain = w.domain; }
    if (f.src_region) f.src_country = f.src_region;
    const eid = String(f.eventid || '').toLowerCase();
    const status = String(f.status || '').toLowerCase();
    ev.event_code = `GLOBALPROTECT:${eid}`;
    const failed = status === 'failure' || /fail|denied/.test(eid);
    if (/auth|login|connected|gateway-.*connect|portal-.*|tunnel/.test(eid) && failed) { Object.assign(ev, { action: 'logon-failed', outcome: 'failure', severity: 1 }); ev.tags.push('T1110'); }
    else if (/logout|disconnect/.test(eid)) Object.assign(ev, { action: 'logoff', outcome: 'success' });
    else if (/auth|login|connected|connect/.test(eid)) Object.assign(ev, { action: 'logon', outcome: 'success' });
    else { ev.action = 'vpn-event'; ev.category = 'network'; ev.outcome = failed ? 'failure' : status === 'success' ? 'success' : 'unknown'; }
    ev.message = `GlobalProtect ${eid} ${f.stage || ''} ${f.srcuser || ''} ${f.public_ip || ''} ${status}${f.reason ? ' reason=' + f.reason : ''}`.replace(/\s+/g, ' ').trim();
  } else {
    ev.category = 'system';
    ev.action = verdict(act) || 'event';
    ev.message = `${type} ${sub} ${act}`.trim();
  }
  return ev;
}

module.exports = {
  name: 'paloalto',
  sniff(line, meta = {}) { const { body } = split(line, meta); return START_RE.test(body); },
  parse,
  csv,
  anyAnyAllow,
  verdict,
};
