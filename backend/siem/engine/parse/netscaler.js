// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Citrix NetScaler / ADC / Gateway audit syslog (ns.log "default" format, Citrix ADC Audit Logging documentation):
//   <134> 05/01/2024:10:00:00 GMT ns-01 0-PPE-0 : default AAA LOGIN_FAILED 12345 0 :  User admin - Client_ip 10.0.0.5 - Failure_reason "External authentication server denied access" - Browser Mozilla/5.0
//   <134> 05/01/2024:10:00:01 GMT ns-01 0-PPE-0 : default GUI CMD_EXECUTED 12346 0 :  User nsroot - Remote_ip 10.0.0.5 - Command "add lb vserver v1 HTTP 10.0.5.1 80" - Status "Success"
//   <134> 05/01/2024:10:00:02 GMT ns-01 0-PPE-0 : default SSLVPN LOGIN 12347 0 : Context user1@203.0.113.5 - SessionId: 5- User user1 - Client_ip 203.0.113.5 - Nat_ip "Mapped Ip" - Vserver 10.0.5.100:443 - Browser_type "Mozilla/5.0" - SSLVPN_client_type ICA - Group(s) "N/A"
//   <134> 05/01/2024:10:00:03 GMT ns-01 0-PPE-0 : default APPFW APPFW_SQL 12348 0 :  203.0.113.5 12345-PPE0 abcd1234 app_profile http://10.0.5.20/login.php SQL Injection check failed for field id="1' or '1'='1" <blocked>
//   <134> 05/01/2024:10:00:04 GMT ns-01 0-PPE-0 : default EVENT DEVICEDOWN 12349 0 :  Device "server_svc_1(10.0.5.10:80)" - State DOWN
// Header: <PRI> MM/DD/YYYY:HH:MM:SS TZ <hostname> <coreid>-PPE-<n> : <partition> <module> <event> <msgid> <flags> : <body>.
// Body = " - "-separated "Key value" / Key "quoted value" items (AAA, SSLVPN, CMD_EXECUTED, EVENT) or positional text (APPFW_*).
// ["verify": with "dateFormat"/"logFacility" changed in the audit nslog action, or in NetScaler 14.x "ns.log" Hostname-first
// ordering, the header differs — the regex tolerates an optional leading hostname.]
const { split, parseTime, sevFromSyslog, toInt, ipOrEmpty, splitUser, clean } = require('./util');

const HDR_RE = /(?:^|\s)(?:([\w.-]+)\s+)?(\d{2})\/(\d{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+(\w+)\s+([\w.-]+)\s+(\d+-PPE-\d+)\s*:\s*(\S+)\s+([A-Z0-9_]+)\s+([A-Z0-9_]+)\s+(\d+)\s+(\d+)\s*:\s*(.*)$/s;
const CHANGE_VERBS = /^(?:add|set|rm|unset|bind|unbind|save|enable|disable|install|clear|create|rename|update|import|link|unlink|sync|force|shell|start|stop|reboot|shutdown|apply|kill|restore|convert|init|flush|expire|delete|reset|unload|load|batch|configure)\b/i;
const TZ = { GMT: 0, UTC: 0 };

function items(body) {
  const out = {};
  const parts = body.split(/\s+-\s+/);
  for (const p of parts) {
    const s = p.trim();
    if (!s) continue;
    const m = /^([A-Za-z_()]+):?\s*(?:"((?:[^"\\]|\\.)*)"|(.*))$/s.exec(s);
    if (!m) continue;
    const key = m[1].replace(/\(s\)$/, 's').toLowerCase();
    const val = (m[2] !== undefined ? m[2] : m[3] || '').trim();
    if (key) out[key] = val;
  }
  return out;
}

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const m = HDR_RE.exec(body);
  if (!m) return null;
  const [, host0, MM, DD, YYYY, hh, mm, ss, tz, host, ppe, partition, module, event, msgid, flags, rest] = m;
  const off = TZ[tz.toUpperCase()] !== undefined ? TZ[tz.toUpperCase()] : (meta.tz_offset_min || 0);
  const ev = {
    src_type: 'netscaler', ts: parseTime(`${YYYY}-${MM}-${DD}T${hh}:${mm}:${ss}${off === 0 ? 'Z' : ''}`, off), host: clean(host) || clean(host0),
    severity: hdr && hdr.sev >= 0 ? sevFromSyslog(hdr.sev) : 0, category: 'system', action: 'event', outcome: 'unknown',
    event_code: `${module}:${event}`, message: rest.slice(0, 1000).trim(), tags: [],
    fields: { ns_partition: partition, ns_module: module, ns_event: event, ns_msgid: msgid, ns_ppe: ppe, ns_tz: tz },
  };
  const mod = module.toUpperCase();
  const evn = event.toUpperCase();
  if (evn.startsWith('APPFW_') || mod === 'APPFW') {
    // "<client ip> <session> <transaction> <profile> <url> <message> <blocked|not blocked|transformed>"
    const am = /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*?)\s*<(blocked|not blocked|transformed|allowed)>\s*$/s.exec(rest.trim()) || /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/s.exec(rest.trim());
    const verdict = am && am[7] ? am[7].toLowerCase() : '';
    Object.assign(ev, { category: 'web', action: 'waf-detection', outcome: verdict === 'blocked' ? 'failure' : verdict ? 'success' : 'unknown', severity: Math.max(ev.severity, verdict === 'blocked' ? 2 : 1) });
    ev.tags.push('waf', 'appfw');
    ev.fields.appfw_check = evn.replace(/^APPFW_/, '').toLowerCase();
    if (am) {
      ev.src_ip = ipOrEmpty(am[1]);
      Object.assign(ev.fields, { appfw_session: am[2], appfw_transaction: am[3], appfw_profile: am[4], appfw_verdict: verdict || undefined });
      ev.url = am[5];
      ev.message = `APPFW ${ev.fields.appfw_check} ${verdict || ''}: ${am[6].trim()}`.slice(0, 1000);
      if (/^(sql|xss|fieldformat|fieldconsistency|cmd|jsonsql|jsonxss|xmlsql|xmlxss)/.test(ev.fields.appfw_check) && verdict !== 'blocked') ev.severity = Math.max(ev.severity, 3);
    }
    return ev;
  }
  const it = items(rest);
  for (const [k, v] of Object.entries(it)) if (v !== '' && v !== 'N/A' && k !== 'context') ev.fields[k] = v;
  if (it.user) { const w = splitUser(it.user); ev.user = w.user; ev.domain = w.domain; }
  else if (it.context) { const cm = /^([^@\s]+)@/.exec(it.context); if (cm) { const w = splitUser(cm[1]); ev.user = w.user; ev.domain = w.domain; } }
  ev.src_ip = ipOrEmpty(it.client_ip) || ipOrEmpty(it.remote_ip) || ipOrEmpty((it.context || '').split('@')[1]) || '';
  if (it.vserver) { const vm = /^([0-9a-fA-F.:]+):(\d+)$/.exec(it.vserver); if (vm) { ev.dst_ip = ipOrEmpty(vm[1]); ev.dst_port = toInt(vm[2]); } }
  if (it.source) { const sm = /^([0-9a-fA-F.:]+):(\d+)$/.exec(it.source); if (sm) { ev.src_ip = ipOrEmpty(sm[1]); ev.src_port = toInt(sm[2]); } }
  if (it.destination) { const dm = /^([0-9a-fA-F.:]+):(\d+)$/.exec(it.destination); if (dm) { ev.dst_ip = ipOrEmpty(dm[1]); ev.dst_port = toInt(dm[2]); } }
  if (it.browser || it.browser_type) ev.user_agent = it.browser || it.browser_type;
  const adminModule = /^(UI|CLI|GUI|API|NSSSH|SSH|NITRO)$/.test(mod);
  const vpnModule = mod === 'SSLVPN' || mod === 'AAATM' || it.sslvpn_client_type !== undefined || it.vserver !== undefined;
  if (evn === 'CMD_EXECUTED') {
    const cmd = it.command || '';
    const change = CHANGE_VERBS.test(cmd);
    const ok = /^success/i.test(it.status || '');
    Object.assign(ev, { category: 'system', action: change ? 'config-change' : 'event', outcome: it.status ? (ok ? 'success' : 'failure') : 'unknown', cmdline: cmd.slice(0, 4000) });
    ev.tags.push('admin', 'audit');
    if (change) ev.severity = Math.max(ev.severity, 1);
    ev.message = `${it.user || '?'} executed: ${cmd}`.slice(0, 1000);
  } else if (evn === 'LOGIN' || evn === 'LOGIN_FAILED' || evn === 'LOGOUT' || evn === 'LOGIN_SUCCESS') {
    const failed = evn === 'LOGIN_FAILED';
    Object.assign(ev, { category: 'authentication', action: failed ? 'logon-failed' : evn === 'LOGOUT' ? 'logoff' : 'logon', outcome: failed ? 'failure' : 'success' });
    if (adminModule) ev.tags.push('admin');
    if (vpnModule) ev.tags.push('vpn');
    if (mod === 'AAA' && !vpnModule && !adminModule) ev.tags.push('aaa');
    if (failed) { ev.tags.push('T1110'); ev.severity = Math.max(ev.severity, adminModule ? 2 : 1); if (it.failure_reason) ev.fields.reason = it.failure_reason; }
    ev.message = `${mod} ${evn} ${it.user || ''}${ev.src_ip ? ' from ' + ev.src_ip : ''}${it.failure_reason ? ': ' + it.failure_reason : ''}`.trim();
  } else if (mod === 'EVENT') {
    const state = String(it.state || '').toUpperCase();
    const down = /DOWN|OUT OF SERVICE|FAIL/.test(state) || /DOWN$/.test(evn);
    const up = /UP|IN SERVICE/.test(state) || /UP$/.test(evn);
    Object.assign(ev, { category: 'system', action: down ? 'service-failed' : up ? 'service-started' : /^CONFIG/.test(evn) ? 'config-change' : 'event', outcome: down ? 'failure' : up ? 'success' : 'unknown' });
    if (it.device) { const dm = /^([^(]+)\(([0-9a-fA-F.:]+):(\d+)\)$/.exec(it.device); if (dm) { ev.fields.device_name = dm[1]; ev.dst_ip = ipOrEmpty(dm[2]); ev.dst_port = toInt(dm[3]); } }
    if (down) ev.severity = Math.max(ev.severity, 2);
    ev.message = `${evn} ${it.device || ''} ${state}`.trim();
  } else if (mod === 'SSLVPN' || mod === 'AAATM') {
    ev.tags.push('vpn');
    if (/^(TCPCONNSTAT|UDPFLOWSTAT|ICASTART|ICAEND|HTTPREQUEST|NONHTTP_RESOURCEACCESS_DENIED|CLISEC_EXP|CLISEC_CHECK)$/.test(evn)) {
      Object.assign(ev, { category: evn === 'HTTPREQUEST' ? 'web' : 'network', action: evn === 'HTTPREQUEST' ? 'http-request' : evn === 'NONHTTP_RESOURCEACCESS_DENIED' ? 'blocked' : 'connection', outcome: evn === 'NONHTTP_RESOURCEACCESS_DENIED' ? 'failure' : 'success' });
      if (it.url) ev.url = it.url;
    } else { ev.category = 'network'; ev.action = 'vpn-event'; }
  } else if (mod === 'AAA' && /^(EXTRACTED_GROUPS|LOGOUT_SESSION|SESSION_EXPIRED)$/.test(evn)) {
    Object.assign(ev, { category: 'authentication', action: evn === 'EXTRACTED_GROUPS' ? 'event' : 'logoff', outcome: 'success' });
  } else if (/^(CONFIG|SAVECONFIG|CONFIGSAVE)/.test(evn) || /^SAVE/.test(evn)) {
    Object.assign(ev, { category: 'system', action: 'config-change', outcome: 'success' });
    ev.tags.push('admin');
  }
  if (flags !== '0') ev.fields.ns_flags = flags;
  return ev;
}

module.exports = {
  name: 'netscaler',
  sniff(line, meta = {}) { const { body } = split(line, meta); return /\d{2}\/\d{2}\/\d{4}:\d{2}:\d{2}:\d{2}\s+\w+\s+[\w.-]+\s+\d+-PPE-\d+\s*:/.test(body); },
  parse,
  items,
};
