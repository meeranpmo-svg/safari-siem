// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// F5 BIG-IP syslog: LTM/mcpd/tmsh (message-id lines "01070638:5: …"), ASM request log (default remote-logging
// template, key="value" pairs), AFM network events ("key"="value" pairs). ASM/AFM CEF templates go to cef.js.
//   <133>May  1 10:00:00 bigip-01 notice mcpd[5693]: 01070638:5: Pool /Common/web_pool member /Common/10.0.5.10:80 monitor status down. [ /Common/http: down; last error: /Common/http: Unable to connect ] [ was up for 0hr:1min:40sec ]
//   <134>May  1 10:00:01 bigip-01 notice tmsh[12345]: 01420002:5: AUDIT - pid=12345 user=admin folder=/Common module=(tmos)# status=[Command OK] cmd_data=modify ltm pool web_pool members add { 10.0.5.11:80 }
//   <86>May  1 10:00:02 bigip-01 info httpd[1234]: 01070417:5: AUDIT - user admin - RAW: httpd(mod_auth_pam): user=admin(admin) partition=[All] level=Administrator tty=/usr/bin/tmsh host=10.0.0.5 attempts=1 start="Wed May  1 10:00:02 2024".
//   <134>May  1 10:00:03 bigip-01 ASM:unit_hostname="bigip-01",management_ip_address="10.0.0.10",policy_name="/Common/app",violations="Attack signature detected",support_id="123",request_status="blocked",response_code="0",ip_client="203.0.113.5",method="GET",protocol="HTTPS",severity="Critical",attack_type="SQL-Injection",uri="/login.php",dest_ip="10.0.5.20",dest_port="443",…
//   <134>May  1 10:00:04 bigip-01 info tmm[1234]: "acl_policy_name"="/Common/pol","acl_rule_name"="deny_all","action"="Drop","device_vendor"="F5","device_product"="Advanced Firewall Module","source_ip"="203.0.113.5",…
// References: K16932 (pool member status messages), K13080 (audit logging), ASM "Logging Profiles → Remote Storage" default
// template (11.x–17.x), AFM "Network Firewall Logging" default template. ["verify": template fields are customer-editable.]
const { split, sevFromName, sevFromSyslog, toInt, ipOrEmpty, protoName, splitUser, clean } = require('./util');
const cef = require('./cef');

const MSG_RE = /(?:^|\s)(0[0-9A-Fa-f]{7}):(\d):\s*(.*)$/s;
// "ASM:" may already have been taken as the syslog tag (hdr.app === 'ASM'); then the body starts with the first pair.
const ASM_RE = /(?:^|\s)ASM:\s*(?:CEF:|[A-Za-z_]+=")|^(?:unit_hostname|management_ip_address|policy_name|web_application_name|http_class_name)="/;
// BIG-IP writes "<host> <level> <daemon>[pid]: <msg>" — the level word sits where RFC 3164 expects the tag, so the
// generic header parser leaves app empty and the body starts with "info httpd[1234]: …"; peel that off here.
const LEVEL_RE = /^(emerg|alert|crit|err|error|warning|warn|notice|info|debug)\s+([A-Za-z0-9_.-]+)(?:\[(\d+)\])?:\s*/;
const LEVEL_SEV = { emerg: 4, alert: 4, crit: 4, err: 3, error: 3, warning: 2, warn: 2, notice: 1, info: 0, debug: 0 };
function peel(hdr, body) {
  const m = LEVEL_RE.exec(body);
  if (m) return { app: m[2].toLowerCase(), pid: m[3] || '', level: m[1], body: body.slice(m[0].length) };
  return { app: (hdr && hdr.app ? hdr.app : '').toLowerCase(), pid: hdr && hdr.pid ? hdr.pid : '', level: '', body };
}
const AFM_RE = /"(?:acl_policy_name|errdefs_msgno|device_vendor|bigip_mgmt_ip)"="/;
const PAM_RE = /(?:pam_audit|mod_auth_pam)[^:]*:\s*user=/;
const CHANGE_VERBS = /^(?:create|modify|delete|save|load|install|run|reset-stats|reboot|restart|start|stop|publish|edit|mv|cp|merge|import|revert|edit|tmsh)\b/i;

// key="value" (quotes escaped as \") or "key"="value"
function kvq(s) {
  const out = {};
  const re = /"?([A-Za-z_][A-Za-z0-9_]*)"?="((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(s))) out[m[1]] = m[2].replace(/\\(["\\])/g, '$1');
  return out;
}

function asm(ev, body) {
  const at = body.indexOf('ASM:');
  const kv = kvq(at >= 0 ? body.slice(at + 4) : body);
  if (!Object.keys(kv).length) return null;
  const status = String(kv.request_status || '').toLowerCase();
  const blocked = status === 'blocked';
  const who = splitUser(kv.username && kv.username !== 'N/A' ? kv.username : '');
  Object.assign(ev, {
    category: 'web', action: 'waf-detection', outcome: blocked ? 'failure' : status === 'passed' || status === 'alerted' ? 'success' : 'unknown',
    host: clean(kv.unit_hostname) || ev.host, src_ip: ipOrEmpty(kv.ip_client), dst_ip: ipOrEmpty(kv.dest_ip), src_port: toInt(kv.src_port), dst_port: toInt(kv.dest_port),
    http_method: (kv.method || '').toUpperCase(), http_status: toInt(kv.response_code), url: (kv.uri || '') + (kv.query_string && kv.query_string !== 'N/A' ? '?' + kv.query_string : ''),
    user: who.user, domain: who.domain, event_code: 'ASM:' + (kv.attack_type || kv.violations || 'request'),
    severity: Math.max(ev.severity || 0, sevFromName(kv.severity, 0), blocked ? 2 : 1),
  });
  ev.tags.push('waf', 'asm');
  ev.message = `ASM ${status || 'request'}: ${kv.attack_type || ''} ${kv.violations || ''} ${kv.ip_client || ''} → ${kv.uri || ''}`.replace(/\s+/g, ' ').trim();
  for (const [k, v] of Object.entries(kv)) {
    if (v === '' || v === 'N/A' || ['unit_hostname', 'ip_client', 'dest_ip', 'dest_port', 'src_port', 'method', 'response_code', 'uri', 'username'].includes(k)) continue;
    ev.fields[k] = (k === 'request' || k === 'header') ? v.slice(0, 2000) : v;
  }
  if (kv.x_forwarded_for_header_value && kv.x_forwarded_for_header_value !== 'N/A') ev.fields.xff = kv.x_forwarded_for_header_value;
  if (kv.geo_location && kv.geo_location !== 'N/A') ev.fields.src_country = kv.geo_location;
  return ev;
}

function afm(ev, body) {
  const kv = kvq(body);
  const act = String(kv.action || '').toLowerCase();
  const blocked = /drop|reject|deny|block/.test(act);
  Object.assign(ev, {
    category: 'network', action: blocked ? 'blocked' : /accept|allow|permit/.test(act) ? 'allowed' : 'event', outcome: blocked ? 'failure' : act ? 'success' : 'unknown',
    src_ip: ipOrEmpty(kv.source_ip), dst_ip: ipOrEmpty(kv.dest_ip), src_port: toInt(kv.source_port), dst_port: toInt(kv.dest_port), proto: protoName(kv.ip_protocol),
    event_code: 'AFM:' + (kv.errdefs_msgno || kv.errdefs_msg_name || 'network'),
  });
  if (kv.source_user && kv.source_user !== 'unknown') { const w = splitUser(kv.source_user); ev.user = w.user; ev.domain = w.domain; }
  ev.tags.push('afm');
  ev.message = `AFM ${kv.action || ''} ${kv.source_ip || ''}:${kv.source_port || ''} → ${kv.dest_ip || ''}:${kv.dest_port || ''} ${kv.ip_protocol || ''} rule=${kv.acl_rule_name || ''}`.replace(/\s+/g, ' ').trim();
  for (const [k, v] of Object.entries(kv)) if (v !== '' && v !== 'unknown' && !['source_ip', 'dest_ip', 'source_port', 'dest_port', 'ip_protocol', 'source_user'].includes(k)) ev.fields[k] = v;
  return ev;
}

function pamAudit(ev, text) {
  const m = /user=([^\s(]+)(?:\(([^)]*)\))?\s+partition=\[([^\]]*)\]\s+level=(\S+)\s+tty=(\S+)\s+host=(\S+)(?:\s+(?:attempts|failed to login after)\s*=?\s*(\d+))?/.exec(text);
  if (!m) return false;
  const failed = /failed to login/.test(text);
  const logout = /\send="/.test(text) && !failed;
  const who = splitUser(m[1]);
  Object.assign(ev, {
    category: 'authentication', action: failed ? 'logon-failed' : logout ? 'logoff' : 'logon', outcome: failed ? 'failure' : 'success',
    user: who.user, domain: who.domain, src_ip: ipOrEmpty(m[6]), severity: Math.max(ev.severity || 0, failed ? 2 : 0),
  });
  Object.assign(ev.fields, { partition: m[3], role: m[4], tty: m[5], attempts: m[7] });
  ev.tags.push('admin');
  if (failed) ev.tags.push('T1110');
  ev.message = `BIG-IP ${failed ? 'login failed' : logout ? 'logout' : 'login'} ${who.user} (${m[4]}) from ${m[6]}`;
  return true;
}

function msgLine(ev, id, level, text) {
  ev.fields.f5_msg_id = id;
  ev.fields.f5_level = level;
  ev.event_code = id;
  ev.message = text.slice(0, 1000);
  let m;
  if ((m = /^(Pool|Node) (\S+)(?: member (\S+))? monitor status (up|down|forced down|checking|unchecked|node down|disabled|forced disabled)\.?(?:\s*\[\s*(.*?)\s*\])?(?:\s*\[\s*was (\w+) for ([^\]]*)\])?/.exec(text))) {
    const st = m[4].toLowerCase();
    const down = /down|disabled/.test(st);
    Object.assign(ev, { category: 'system', action: down ? 'service-failed' : st === 'up' ? 'service-started' : 'event', outcome: down ? 'failure' : st === 'up' ? 'success' : 'unknown' });
    Object.assign(ev.fields, { pool: m[1] === 'Pool' ? m[2] : undefined, node: m[1] === 'Node' ? m[2] : undefined, member: m[3], member_status: st, monitor_detail: m[5], previous_state: m[6], previous_duration: m[7] && m[7].trim() });
    if (m[5]) { const le = /last error:\s*(.*)$/.exec(m[5]); if (le) ev.fields.reason = le[1].trim(); }
    if (m[3]) { const mp = /^(?:\/[^/]+\/)?(.+):(\d+)$/.exec(m[3]); if (mp) { ev.dst_ip = ipOrEmpty(mp[1]); ev.dst_port = toInt(mp[2]); } }
    ev.tags.push('ltm', down ? 'pool-member-down' : 'pool-member-up');
    ev.severity = Math.max(ev.severity || 0, down ? 2 : 0);
  } else if ((m = /^Pool (\S+) member (\S+) session status (.*?)\.?$/.exec(text))) {
    Object.assign(ev, { category: 'system', action: 'config-change', outcome: 'success' });
    Object.assign(ev.fields, { pool: m[1], member: m[2], session_status: m[3] });
    ev.tags.push('ltm');
  } else if ((m = /^AUDIT - pid=(\d+) user=(\S+) folder=(\S+) module=\(([^)]*)\)#? status=\[([^\]]*)\] cmd_data=(.*)$/s.exec(text))) {
    const who = splitUser(m[2]);
    const change = CHANGE_VERBS.test(m[6]);
    Object.assign(ev, { category: change ? 'system' : 'system', action: change ? 'config-change' : 'event', outcome: /Command OK/i.test(m[5]) ? 'success' : 'failure', user: who.user, domain: who.domain, cmdline: m[6].trim().slice(0, 4000) });
    Object.assign(ev.fields, { pid: m[1], folder: m[3], module: m[4], status: m[5] });
    ev.tags.push('audit', 'admin', 'tmsh');
    if (change) ev.severity = Math.max(ev.severity || 0, 1);
  } else if ((m = /^AUDIT - client (\S+?),(?: tmsh-pid-(\d+),)? user (\S+) - transaction #(\S+) - object (\d+) - (\w+)\s*\{?(.*?)\}?\s*\[Status=([^\]]*)\]/s.exec(text))) {
    const who = splitUser(m[3]);
    Object.assign(ev, { category: 'system', action: 'config-change', outcome: /Command OK/i.test(m[8]) ? 'success' : 'failure', user: who.user, domain: who.domain, cmdline: `${m[6]} ${m[7].trim()}`.slice(0, 4000) });
    Object.assign(ev.fields, { client: m[1], pid: m[2], transaction: m[4], object_id: m[5], operation: m[6], status: m[8] });
    ev.tags.push('audit', 'admin', 'mcpd');
    ev.severity = Math.max(ev.severity || 0, 1);
  } else if ((m = /^AUDIT - user (\S+) - RAW:\s*(.*)$/s.exec(text))) {
    if (!pamAudit(ev, m[2])) { const who = splitUser(m[1]); Object.assign(ev, { category: 'system', action: 'event', user: who.user, domain: who.domain }); ev.tags.push('audit'); }
  } else if ((m = /^(?:Virtual (?:Server|Address)|SNAT|iRule) (\S+) .*?(?:status|state) (up|down|unknown|unavailable|offline|available)/i.exec(text))) {
    const down = /down|unavailable|offline/i.test(m[2]);
    Object.assign(ev, { category: 'system', action: down ? 'service-failed' : 'service-started', outcome: down ? 'failure' : 'success' });
    ev.fields.object = m[1]; ev.fields.state = m[2].toLowerCase();
  } else if (/Configuration (?:load|save)|config(?:uration)? (?:loaded|saved)|Loading configuration/i.test(text)) {
    Object.assign(ev, { category: 'system', action: 'config-change', outcome: 'success' });
  } else if (/fail(?:ed|over)|standby|active|high availability|HA /i.test(text) && /^(?:Failover|Standby|Active|Sod|HA)/i.test(text)) {
    Object.assign(ev, { category: 'system', action: 'event' }); ev.tags.push('ha');
  } else {
    Object.assign(ev, { category: 'system', action: 'event' });
  }
}

function parse(line, meta = {}) {
  const { hdr, body: body0 } = split(line, meta);
  const isAsm = ASM_RE.test(body0) || (hdr && /^asm$/i.test(hdr.app || '') && /^[A-Za-z_]+="/.test(body0));
  if (/(?:^|ASM:\s*)CEF:\d\|/.test(body0)) { const ev = cef.parse(body0.slice(body0.indexOf('CEF:')), { ...meta, syslog: null }); if (ev) { ev.src_type = 'f5'; (ev.tags = ev.tags || []).push('waf', 'asm'); } return ev; }
  const { app, pid, level, body } = peel(hdr, body0);
  const ev = {
    src_type: 'f5', severity: Math.max(hdr && hdr.sev >= 0 ? sevFromSyslog(hdr.sev) : 0, LEVEL_SEV[level] || 0), category: 'system', action: 'event', outcome: 'unknown',
    event_code: '', message: '', tags: [], fields: { app: app || undefined, pid: pid || undefined, f5_log_level: level || undefined },
  };
  let m;
  if (isAsm) return asm(ev, body0);
  if (AFM_RE.test(body)) return afm(ev, body);
  if ((m = MSG_RE.exec(body))) { msgLine(ev, m[1].toUpperCase(), m[2], m[3].trim()); return ev; }
  if (PAM_RE.test(body) && pamAudit(ev, body)) return ev;
  return null;
}

module.exports = {
  name: 'f5',
  sniff(line, meta = {}) {
    const { hdr, body: body0 } = split(line, meta);
    if (MSG_RE.test(body0) || ASM_RE.test(body0) || AFM_RE.test(body0)) return true;
    if (hdr && /^asm$/i.test(hdr.app || '') && /^[A-Za-z_]+="/.test(body0)) return true;
    const { app, body } = peel(hdr, body0);
    return PAM_RE.test(body) && /^(?:httpd|sshd|tmsh|mcpd)$/.test(app);
  },
  parse,
  kvq,
};
