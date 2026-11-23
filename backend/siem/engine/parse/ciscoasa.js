// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cisco ASA / FTD (Firepower Threat Defense, "ASA syslog" format) — %ASA-<sev>-<6-digit id>: <message>.
// Layered on cisco.js: cisco.js keeps the connection/ACL basics (106023, 106100, 302013-16, 113004/5/15, 605004/5,
// 111008/111010, 733100…); this module adds the management-access, AAA, local-user, VPN (713xxx IPsec/IKE, 716xxx
// WebVPN, 722xxx AnyConnect), botnet-filter and FTD 430001-430005 messages. Message texts follow the "Cisco Secure
// Firewall ASA Series Syslog Messages" guide (9.x) and the FTD "Syslog Messages" guide (7.x). ["verify" = wording
// may differ slightly between releases; the regexes are tolerant.]
// Event src_type stays 'cisco' when the line was sniffed (compatibility with existing rules/tests) and becomes
// 'cisco-asa' when the source is configured with that type.
const { split, toInt, ipOrEmpty, protoName, clean, parseTime, splitUser } = require('./util');
const cisco = require('./cisco');

const ASA_RE = /%(ASA|FTD|PIX|FWSM)-(?:\w+-)?([0-7])-(\d{6}):?\s*/;
const u = (s) => clean(s).replace(/^["'<]|["'>]$/g, '').toLowerCase();

function auth(ev, ok, sevFail = 1) {
  Object.assign(ev, { category: 'authentication', action: ok ? 'logon' : 'logon-failed', outcome: ok ? 'success' : 'failure' });
  if (!ok) { ev.severity = Math.max(ev.severity, sevFail); ev.tags.push('T1110'); }
}
function net(ev, action, src, sport, dst, dport, proto) {
  Object.assign(ev, { category: 'network', action, outcome: action === 'blocked' ? 'failure' : 'success' });
  if (src !== undefined) { ev.src_ip = ipOrEmpty(src); ev.src_port = toInt(sport); }
  if (dst !== undefined) { ev.dst_ip = ipOrEmpty(dst); ev.dst_port = toInt(dport); }
  if (proto) ev.proto = protoName(proto);
}
// "Group = g, Username = u, IP = ip" / "Group <g> User <u> IP <ip>" / "Group = g, IP = ip" / "peer 1.2.3.4"
function vpnTriplet(ev, msg) {
  let m;
  if ((m = /Group\s*[=<]\s*([^,>]*?)[,>]?\s*(?:Username|User)\s*[=<]\s*([^,>]*?)[,>]?\s*IP\s*[=<]\s*([^,>\s]+)/.exec(msg))) {
    ev.fields.vpn_group = m[1].trim(); ev.user = u(m[2]); ev.src_ip = ipOrEmpty(m[3]);
  } else if ((m = /Group\s*=\s*([^,]*?),\s*IP\s*=\s*(\S+?),?\s/.exec(msg))) {
    ev.fields.vpn_group = m[1].trim(); ev.src_ip = ipOrEmpty(m[2]);
  } else if ((m = /(?:peer|IP = |Remote address )\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]+)/i.exec(msg))) ev.src_ip = ipOrEmpty(m[1]);
  if ((m = /Reason:\s*([^.]+)/.exec(msg))) ev.fields.reason = m[1].trim();
  if ((m = /Session Type:\s*([^,]+)/.exec(msg))) ev.fields.session_type = m[1].trim();
  if ((m = /Duration:\s*(\S+)/.exec(msg))) ev.fields.duration = m[1];
  ev.tags.push('vpn');
}

// FTD 430001-430005: "Key: value, Key: value, …"
function ftdKV(msg) {
  const out = {};
  const re = /([A-Za-z][A-Za-z0-9_]*): ([^,]*?)(?=, [A-Za-z][A-Za-z0-9_]*: |$)/g;
  let m;
  while ((m = re.exec(msg))) out[m[1]] = m[2].trim();
  return out;
}
const FTD_PRIO = { 1: 3, 2: 2, 3: 1, high: 3, medium: 2, low: 1 };
function ftd(ev, msg, id) {
  const kv = ftdKV(msg);
  for (const [k, v] of Object.entries(kv)) if (v !== '' && v !== 'N/A') ev.fields[k] = v;
  ev.src_ip = ipOrEmpty(kv.SrcIP || kv.InitiatorIP || kv.src_ip); ev.dst_ip = ipOrEmpty(kv.DstIP || kv.ResponderIP || kv.dst_ip);
  ev.src_port = toInt(kv.SrcPort || kv.InitiatorPort); ev.dst_port = toInt(kv.DstPort || kv.ResponderPort); ev.proto = protoName(kv.Protocol);
  if (kv.User && kv.User !== 'No Authentication Required') { const w = splitUser(kv.User); ev.user = w.user; if (w.domain) ev.domain = w.domain; }
  if (kv.URL) ev.url = kv.URL;
  if (kv.UserAgent) ev.user_agent = kv.UserAgent;
  ev.tags.push('ftd');
  const act = String(kv.AccessControlRuleAction || kv.ACRuleAction || '').toLowerCase();
  const blocked = /block|deny|drop|reset/.test(act);
  switch (id) {
    case '430001':
      Object.assign(ev, { category: 'network', action: 'ips-detection', outcome: blocked || /block|drop|reset/i.test(kv.InlineResult || '') ? 'failure' : 'success' });
      ev.severity = Math.max(ev.severity, FTD_PRIO[String(kv.Priority || '').toLowerCase()] || 2, kv.ImpactFlag ? 0 : 0);
      if (kv.SID) ev.fields.signature = `${kv.GID || 1}:${kv.SID}`;
      ev.message = `IPS: ${kv.Message || kv.Classification || 'intrusion event'}`.slice(0, 1000);
      break;
    case '430002': case '430003':
      Object.assign(ev, { category: 'network', action: blocked ? 'blocked' : 'connection', outcome: blocked ? 'failure' : 'success' });
      ev.fields.direction = id === '430002' ? 'begin' : 'end';
      break;
    case '430004':
      Object.assign(ev, { category: 'file', action: /block/i.test(kv.FileAction || '') ? 'blocked' : 'allowed', outcome: /block/i.test(kv.FileAction || '') ? 'failure' : 'success' });
      if (kv.SHA_Disposition && /malware/i.test(kv.SHA_Disposition)) { ev.category = 'malware'; ev.action = 'av-detection'; ev.severity = Math.max(ev.severity, 3); }
      ev.hash = clean(kv.FileSHA256 || kv.SHA256).toLowerCase();
      break;
    case '430005':
      Object.assign(ev, { category: 'malware', action: 'av-detection', outcome: /block|quarant/i.test(kv.FileAction || kv.Action || '') ? 'failure' : 'success', severity: Math.max(ev.severity, 3) });
      ev.hash = clean(kv.FileSHA256 || kv.SHA256).toLowerCase();
      ev.message = `Malware: ${kv.ThreatName || kv.FileName || kv.SHA_Disposition || ''}`.trim();
      break;
    default:
  }
}

const EXTRA = {
  // ---- management access (to-the-box)
  710002(ev, msg) { const m = /^(\S+) access permitted from ([^/\s]+)\/(\d+) to (\S+?):([^/\s]+)\/(\d+)/.exec(msg); if (m) { net(ev, 'allowed', m[2], m[3], m[5], m[6], m[1]); ev.fields.dst_if = m[4]; } ev.tags.push('mgmt-access'); },
  710003(ev, msg) { const m = /^(\S+) access denied by ACL from ([^/\s]+)\/(\d+) to (\S+?):([^/\s]+)\/(\d+)/.exec(msg); if (m) { net(ev, 'blocked', m[2], m[3], m[5], m[6], m[1]); ev.fields.dst_if = m[4]; } ev.tags.push('mgmt-access'); ev.severity = Math.max(ev.severity, 1); },
  710005(ev, msg) { const m = /^(\S+) request discarded from ([^/\s]+)\/(\d+) to (\S+?):([^/\s]+)\/(\d+)/.exec(msg); if (m) { net(ev, 'blocked', m[2], m[3], m[5], m[6], m[1]); ev.fields.dst_if = m[4]; } ev.tags.push('mgmt-access'); },
  // ---- AAA
  113008(ev, msg) { const m = /user = (\S+)/.exec(msg); if (m) ev.user = u(m[1]); auth(ev, /ACCEPT/.test(msg)); },
  113012(ev, msg) { const m = /user = (\S+)/.exec(msg); if (m) ev.user = u(m[1]); auth(ev, /Successful/i.test(msg)); ev.fields.aaa_server = 'local'; },
  113019(ev, msg) { vpnTriplet(ev, msg); Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' }); const m = /Bytes xmt: (\d+), Bytes rcv: (\d+)/.exec(msg); if (m) { ev.fields.bytes_sent = m[1]; ev.fields.bytes_received = m[2]; } },
  109005(ev, msg) { const m = /for user '([^']*)' from ([^/\s]+)\/\d+ to ([^/\s]+)\/\d+ on interface (\S+)/.exec(msg); if (m) { ev.user = u(m[1]); ev.src_ip = ipOrEmpty(m[2]); ev.dst_ip = ipOrEmpty(m[3]); ev.fields.src_if = m[4]; } auth(ev, true); },
  109006(ev, msg) { EXTRA[109005](ev, msg); auth(ev, false); },
  109024(ev, msg) { const m = /from ([^/\s]+)\/\d+ to ([^/\s]+)\/\d+/.exec(msg); if (m) { ev.src_ip = ipOrEmpty(m[1]); ev.dst_ip = ipOrEmpty(m[2]); } Object.assign(ev, { category: 'authentication', action: 'logon-failed', outcome: 'failure' }); ev.fields.reason = 'authorization denied'; },
  611101(ev, msg) { const m = /Uname: (\S+)/.exec(msg); if (m) ev.user = u(m[1]); auth(ev, true); ev.tags.push('admin'); },
  611102(ev, msg) { const m = /Uname: (\S+)/.exec(msg); if (m) ev.user = u(m[1]); auth(ev, false, 2); ev.tags.push('admin'); },
  611103(ev, msg) { const m = /Uname: (\S+)/.exec(msg); if (m) ev.user = u(m[1]); Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' }); ev.tags.push('admin'); },
  315011(ev, msg) { const m = /SSH session from (\S+) on interface (\S+) for user "([^"]*)" disconnected by SSH server, reason: "?([^"]*)"?/.exec(msg); if (m) { ev.src_ip = ipOrEmpty(m[1]); ev.fields.src_if = m[2]; ev.user = u(m[3]); ev.fields.reason = m[4]; } Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' }); ev.tags.push('admin'); },
  // ---- local user database
  502101(ev, msg) { const m = /Uname: (\S+)(?: Priv: (\d+))?/.exec(msg); if (m) { ev.target_user = u(m[1]); if (m[2]) ev.fields.priv_level = m[2]; } Object.assign(ev, { category: 'iam', action: 'user-created', outcome: 'success', severity: Math.max(ev.severity, 2) }); ev.tags.push('admin', 'T1136'); },
  502102(ev, msg) { const m = /Uname: (\S+)/.exec(msg); if (m) ev.target_user = u(m[1]); Object.assign(ev, { category: 'iam', action: 'user-deleted', outcome: 'success', severity: Math.max(ev.severity, 2) }); ev.tags.push('admin'); },
  502103(ev, msg) { const m = /Uname: (\S+) From: (\d+) To: (\d+)/.exec(msg); if (m) { ev.target_user = u(m[1]); ev.fields.priv_from = m[2]; ev.fields.priv_to = m[3]; } Object.assign(ev, { category: 'iam', action: 'user-modified', outcome: 'success', severity: Math.max(ev.severity, Number(m && m[3]) >= 15 ? 3 : 2) }); ev.tags.push('admin', 'T1098'); },
  // ---- configuration
  111001(ev, msg) { const m = /^Begin configuration: (\S+) (.*)$/.exec(msg); if (m) { ev.src_ip = ipOrEmpty(m[1]); ev.fields.config_op = m[2]; } Object.assign(ev, { category: 'system', action: 'config-change', outcome: 'success' }); ev.tags.push('admin'); },
  111004(ev, msg) { const m = /^(\S+) end configuration: (\S+)/.exec(msg); if (m) { ev.src_ip = ipOrEmpty(m[1]); ev.fields.result = m[2]; } Object.assign(ev, { category: 'system', action: 'config-change', outcome: /ok/i.test(m ? m[2] : '') ? 'success' : 'failure' }); ev.tags.push('admin'); },
  111005(ev, msg) { EXTRA[111004](ev, msg); },
  111007(ev, msg) { EXTRA[111001](ev, msg); },
  111009(ev, msg) { const m = /^User '([^']+)' executed cmd: ?(.*)$/.exec(msg); if (m) { ev.user = u(m[1]); ev.cmdline = m[2].trim(); } Object.assign(ev, { category: 'system', action: 'event', outcome: 'success' }); ev.tags.push('admin', 'show-cmd'); },
  // ---- anti-spoof / reverse path
  106016(ev, msg) { const m = /^Deny IP spoof from \((\S+)\) to (\S+) on interface (\S+)/.exec(msg); if (m) { net(ev, 'blocked', m[1], 0, m[2], 0, 'ip'); ev.fields.src_if = m[3]; } ev.tags.push('spoof'); },
  106021(ev, msg) { const m = /^Deny (\S+) reverse path check from (\S+) to (\S+) on interface (\S+)/.exec(msg); if (m) { net(ev, 'blocked', m[2], 0, m[3], 0, m[1]); ev.fields.src_if = m[4]; } ev.tags.push('spoof'); },
  // ---- threat detection
  733101(ev, msg) { Object.assign(ev, { category: 'network', action: 'ips-detection', severity: Math.max(ev.severity, 2) }); const m = /Object (\S+)/.exec(msg); if (m) ev.src_ip = ipOrEmpty(m[1].replace(/^\(|\)$/g, '')); ev.tags.push('threat-detection'); },
  733102(ev, msg) { EXTRA[733101](ev, msg); },
  // ---- WebVPN / AnyConnect
  716002(ev, msg) { vpnTriplet(ev, msg); Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' }); },
  716038(ev, msg) { vpnTriplet(ev, msg); auth(ev, true); },
  716039(ev, msg) { vpnTriplet(ev, msg); auth(ev, false, 1); },
  716058(ev, msg) { vpnTriplet(ev, msg); Object.assign(ev, { category: 'network', action: 'vpn-event', outcome: 'unknown' }); },
  722022(ev, msg) { vpnTriplet(ev, msg); Object.assign(ev, { category: 'network', action: 'vpn-event', outcome: 'success' }); ev.fields.vpn_state = 'established'; },
  722023(ev, msg) { vpnTriplet(ev, msg); Object.assign(ev, { category: 'network', action: 'vpn-event', outcome: 'success' }); ev.fields.vpn_state = 'terminated'; },
  722033(ev, msg) { vpnTriplet(ev, msg); Object.assign(ev, { category: 'authentication', action: 'logon', outcome: 'success' }); },
  722037(ev, msg) { vpnTriplet(ev, msg); Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' }); },
  722028(ev, msg) { vpnTriplet(ev, msg); Object.assign(ev, { category: 'network', action: 'vpn-event', outcome: 'unknown' }); },
  // ---- botnet traffic filter
  338001(ev, msg) { botnet(ev, msg); }, 338002(ev, msg) { botnet(ev, msg); }, 338003(ev, msg) { botnet(ev, msg); }, 338004(ev, msg) { botnet(ev, msg); },
  338005(ev, msg) { botnet(ev, msg); }, 338006(ev, msg) { botnet(ev, msg); }, 338007(ev, msg) { botnet(ev, msg); }, 338008(ev, msg) { botnet(ev, msg); },
  // ---- FTD
  430001: ftd, 430002: ftd, 430003: ftd, 430004: ftd, 430005: ftd,
};

function botnet(ev, msg) {
  const m = /Dynamic [Ff]ilter (monitored|dropped) (\S+) (\S+) traffic from (\S+?):([^/\s]+)\/(\d+) \(([^)]*)\) to (\S+?):([^/\s]+)\/(\d+) \(([^)]*)\)/.exec(msg);
  if (m) {
    net(ev, m[1] === 'dropped' ? 'blocked' : 'allowed', m[5], m[6], m[9], m[10], m[3]);
    Object.assign(ev.fields, { src_if: m[4], dst_if: m[8], list: m[2], src_nat: m[7], dst_nat: m[11] });
  }
  ev.category = 'malware';
  ev.severity = Math.max(ev.severity, 3);
  ev.tags.push('botnet', 'T1071');
  const d = /(?:destination|source) malicious address resolved from (?:dynamic|local) list: ([^,]+)(?:, threat-level: (\S+)(?:, category: (.*))?)?/.exec(msg);
  if (d) { ev.dns_query = d[1].trim().toLowerCase(); if (d[2]) ev.fields.threat_level = d[2]; if (d[3]) ev.fields.threat_category = d[3].trim(); }
}

// 713xxx IKE/IPsec: classify by wording
function ipsec(ev, msg, id) {
  vpnTriplet(ev, msg);
  ev.tags.push('ipsec');
  ev.category = 'network';
  ev.action = 'vpn-event';
  ev.outcome = 'unknown';
  if (/PHASE 1 COMPLETED|PHASE 2 COMPLETED|Security negotiation complete|Assigned private IP|Automatic NAT Detection Status/i.test(msg)) {
    ev.outcome = 'success';
    if (id === '713120' || id === '713049' || id === '713228') { ev.category = 'authentication'; ev.action = 'logon'; }
    const p = /PHASE (\d) COMPLETED/i.exec(msg); if (p) ev.fields.ike_phase = p[1];
  } else if (/authentication attempt|failed user authentication|Authorization failed|rejected|Peer authentication failed|No matching tunnel group|login failure/i.test(msg)) {
    auth(ev, false, 1);
  } else if (/Connection terminated|Session is being torn down|Deleting (?:static|dynamic)|Removing peer|Duplicate Phase 1 packet/i.test(msg)) {
    ev.outcome = 'success';
    if (id === '713050' || id === '713259') { ev.category = 'authentication'; ev.action = 'logoff'; }
  }
}

function parse(line, meta = {}) {
  const { body } = split(line, meta);
  const m = ASA_RE.exec(body);
  if (!m) return null;
  const ev = cisco.parse(line, meta);
  if (!ev) return null;
  if (!ev.tags) ev.tags = [];
  const id = m[3];
  const msg = body.slice(m.index + m[0].length).trim();
  ev.fields.cisco_platform = m[1].toLowerCase();
  if (meta.src_type === 'cisco-asa') ev.src_type = 'cisco-asa';
  if (!ev.ts && meta.syslog && meta.syslog.ts) ev.ts = meta.syslog.ts;
  const h = EXTRA[id];
  if (h) h(ev, msg, id);
  else if (/^713\d{3}$/.test(id)) ipsec(ev, msg, id);
  else if (/^(?:716|722|725|734|737|751)\d{3}$/.test(id) && /Group\s*[=<]|User\s*[=<]|IP\s*[=<]/.test(msg)) { vpnTriplet(ev, msg); if (ev.action === 'event') { ev.category = 'network'; ev.action = 'vpn-event'; } }
  // ASA lines without a syslog header but with the ASA "Mon DD YYYY HH:MM:SS" prefix are handled by cisco.js
  if (ev.ts === undefined || ev.ts === 0) { const t = /^([A-Z][a-z]{2} \d{2} \d{4} \d{2}:\d{2}:\d{2})/.exec(body); if (t) ev.ts = parseTime(t[1], meta.tz_offset_min || 0); }
  return ev;
}

module.exports = {
  name: 'cisco-asa',
  sniff(line, meta = {}) { const { body } = split(line, meta); return ASA_RE.test(body); },
  parse,
  ftdKV,
};
