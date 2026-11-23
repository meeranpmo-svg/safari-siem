// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Silver Peak / HPE Aruba EdgeConnect (ECOS) and NX / VX WAN optimisation appliances - syslog (type `silverpeak`).
// Transport: standard RFC 3164 / RFC 5424 headers from the appliance (remote log receiver configured per appliance or
// pushed by an Orchestrator template). Message bodies handled (docs/PARSERS.md "Silver Peak"):
//   OpenSSH on the appliance (documented OpenSSH texts):
//     sshd[812]: Accepted password for admin from 10.20.1.5 port 51234 ssh2         -> logon (tags admin, ui ssh)
//     sshd[812]: Failed password for admin from 10.20.1.5 port 51234 ssh2           -> logon-failed
//   management / audit daemon - "[<proc>.<LEVEL>]: AUDIT: ..." layout of the ECOS management framework (verify the
//   exact wording on the customer's release; the patterns below key on the stable words only):
//     [mgmtd.NOTICE]: AUDIT: User login: username: admin, remote address: 10.20.1.5, auth method: local, via: Web UI
//     [mgmtd.NOTICE]: AUDIT: User login failure: username: admin, remote address: 10.20.1.5, via: Web UI
//     [mgmtd.NOTICE]: AUDIT: User logout: username: admin, remote address: 10.20.1.5
//     [mgmtd.NOTICE]: AUDIT: Config change ID 77: requested by: user admin via Web UI, remote address: 10.20.1.5:
//                     Configuration changes: Item 1: /interfaces/wan1/shaper/max_bw changed from 50000 to 100000
//   alarms (raised / cleared / acknowledged; severity CRITICAL|MAJOR|MINOR|WARNING; verify wording):
//     alarmd[901]: Alarm raised: severity=CRITICAL type=TUNNEL_DOWN source=to_wan-jeddah-sp_MPLS-MPLS text="Tunnel is down"
//     alarmd[901]: ALARM CLEARED [MAJOR] Interface wan1 link is up
//   tunnel state changes (verify): "Tunnel to_wan-jeddah-sp_MPLS-MPLS state changed from Up - Active to Down"
//   reboot / upgrade (verify): "System reboot requested by user admin", "Software upgrade to 9.3.2.0 completed"
// Normalised to: category authentication | network | system (the schema has no "config" category - configuration
// changes are category system, action config-change, tag config), action logon | logon-failed | logoff |
// config-change | alarm | tunnel-down | tunnel-up | reboot | upgrade | log, outcome, severity 0-4, user, src_ip, host,
// fields.ui / reason / alarm_type / alarm_severity / alarm_state / tunnel / peer / change / version / sp_process.
// fields.site is stamped by the router from the source registry (meta.site). Unrecognised lines from a silverpeak
// source become a generic system/log event (never dropped, never thrown).
const { split, sevFromSyslog, ipOrEmpty, splitUser } = require('./util');

const LEVEL_RE = /^\[([A-Za-z0-9_-]+)\.(EMERG|ALERT|CRIT|ERR|ERROR|WARNING|WARN|NOTICE|INFO|DEBUG)\]:\s*/i;
const LEVEL_SEV = { EMERG: 4, ALERT: 4, CRIT: 4, ERR: 3, ERROR: 3, WARNING: 2, WARN: 2, NOTICE: 1, INFO: 0, DEBUG: 0 };
const MARK = /\b(?:silver\s?peak|edge\s?connect|ECOS|VXOA)\b/i;   // vendor words only ("Orchestrator" alone is too generic)
const APP_MARK = /^(?:silverpeak|silver-peak|edgeconnect|ecos|vxoa)/i;
const ALARM_SEV = { critical: 4, major: 3, minor: 2, warning: 1, warn: 1, info: 0, informational: 0 };

function setUser(ev, u) { if (!u) return; const w = splitUser(String(u).replace(/^["']|["',;:]$/g, '')); if (w.user) { ev.user = w.user; if (w.domain && !ev.domain) ev.domain = w.domain; } }
const USER_PATS = [
  /\busername\s*[:=]\s*["']?([^\s,;"'()]+)/i,
  /\brequested\s+by\s*:?\s*(?:user\s+)?["']?([^\s,;"'()]+)/i,
  /\b(?:by|for)\s+user\s+["']?([^\s,;"'()]+)/i,
  /\buser\s*[:=]\s*["']?([^\s,;"'()]+)/i,
  /\buser\s+["']?([A-Za-z0-9][A-Za-z0-9._@\\-]{0,63})["']?\s+(?:logged|log\s?in|log\s?out|from|via|has)\b/i,
];
const USER_STOP = /^(login|logout|logged|failure|failed|name|is|was|from|via|session|user|unknown|-)$/i;
function userOf(t) { for (const re of USER_PATS) { const m = re.exec(t); if (m && !USER_STOP.test(m[1])) return m[1].replace(/[:.]$/, ''); } return ''; }
function ipOf(t) {
  const m = /\b(?:remote\s+(?:address|addr|host|ip)|from|client(?:\s+ip)?|src(?:_ip)?|source\s+ip|rhost)\s*[:=]?\s*\[?([0-9a-fA-F][0-9a-fA-F.:]{5,})\]?/i.exec(t);
  if (!m) return '';
  let ip = m[1].replace(/[:.]$/, '');
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(ip)) ip = ip.replace(/:\d+$/, '');   // a.b.c.d:port
  return ipOrEmpty(ip);
}
function uiOf(t, dflt) {
  const m = /\bvia\s*:?\s*(web\s*ui|webui|https?|gui|cli|ssh|console|telnet|rest(?:\s*api)?|api|orchestrator|gms|xml-?rpc)\b/i.exec(t);
  const v = (m ? m[1] : dflt || '').toLowerCase().replace(/\s+/g, '');
  if (!v) return '';
  if (/^(webui|https?|gui)$/.test(v)) return 'web';
  if (/^(rest|restapi|api|xml-?rpc)$/.test(v)) return 'api';
  if (v === 'gms') return 'orchestrator';
  return v;
}

const ALARM_TYPES = [
  [/tunnel/i, 'tunnel_down'],
  [/interface|link|\bport\b|\bwan\d|\blan\d|ethernet/i, 'interface_down'],
  [/\bdisk|storage|raid|ssd|filesystem/i, 'disk'],
  [/\bha\b|high.availability|vrrp|redundan|peer appliance/i, 'ha'],
  [/power|psu|\bfan\b|temperat|thermal|hardware/i, 'hardware'],
  [/licen[cs]e/i, 'license'],
  [/memory|\bcpu\b|resource|utili[sz]ation/i, 'resource'],
  [/reboot|restart|unexpected shutdown|crash/i, 'reboot'],
  [/config|software version|upgrade/i, 'config'],
];
function alarmType(t) { for (const [re, k] of ALARM_TYPES) if (re.test(t)) return k; return 'other'; }

// "to_wan-jeddah-sp_MPLS-MPLS" - Orchestrator's default tunnel alias "to_<peer host>_<local label>-<remote label>" (verify)
function peerOfTunnel(name) { const m = /^to_(.+)_[A-Za-z0-9]+-[A-Za-z0-9]+$/.exec(String(name || '')); return m ? m[1] : ''; }

function alarm(ev, text) {
  const kv = {};
  text.replace(/\b([A-Za-z_]+)=("([^"]*)"|'([^']*)'|(\S+))/g, (all, k, v, q1, q2, bare) => { kv[k.toLowerCase()] = q1 !== undefined ? q1 : q2 !== undefined ? q2 : bare; return all; });
  const state = /\bclear(?:ed)?\b/i.test(text) ? 'cleared' : /\backnowledg/i.test(text) ? 'acknowledged' : 'raised';
  const sm = /\b(critical|major|minor|warning|info)\b/i.exec(kv.severity || kv.sev || text);
  const sev = sm ? sm[1].toLowerCase() : '';
  const desc = kv.text || kv.desc || kv.description || text.replace(/^.*?\balarm\b\s*(?:raised|cleared|acknowledged)?\s*:?\s*(?:\[[A-Za-z]+\])?\s*/i, '');
  const typeText = `${kv.type || ''} ${kv.name || ''} ${desc}`;
  Object.assign(ev, { category: /tunnel|interface|link/i.test(typeText) ? 'network' : 'system', action: 'alarm', outcome: state === 'raised' ? 'failure' : 'success' });
  ev.severity = state === 'raised' ? (sev ? ALARM_SEV[sev] : Math.max(ev.severity, 2)) : 0;
  Object.assign(ev.fields, { alarm_state: state, alarm_severity: sev || undefined, alarm_type: alarmType(typeText), alarm_raw_type: kv.type || undefined, alarm_id: kv.id || kv.typeid || undefined, alarm_source: kv.source || undefined });
  const tm = /\b(to_[A-Za-z0-9._-]+_[A-Za-z0-9]+-[A-Za-z0-9]+)\b/.exec(`${kv.source || ''} ${desc}`) || /\btunnel\s+["']?([A-Za-z0-9._:-]{3,})["']?/i.exec(desc);
  if (tm && !/^(is|was|state|down|up)$/i.test(tm[1])) { ev.fields.tunnel = tm[1]; const p = peerOfTunnel(tm[1]); if (p) ev.fields.peer = p; }
  ev.tags.push('alarm');
  ev.message = desc.slice(0, 1000) || text.slice(0, 1000);
}

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  let text = String(body || '').trim();
  if (!text) return null;
  const app = (hdr && hdr.app ? hdr.app : '').replace(/\[\d+\]$/, '').toLowerCase();
  const ev = {
    src_type: 'silverpeak', category: 'system', action: 'log', outcome: 'unknown', severity: hdr && hdr.sev >= 0 ? sevFromSyslog(hdr.sev) : 0,
    process: app, message: text.slice(0, 1000), tags: ['silverpeak'], fields: { sp_process: app || undefined },
  };
  let m;
  if ((m = LEVEL_RE.exec(text))) { ev.process = ev.process || m[1].toLowerCase(); ev.fields.sp_process = ev.fields.sp_process || m[1].toLowerCase(); ev.fields.sp_level = m[2].toUpperCase(); ev.severity = Math.max(ev.severity, LEVEL_SEV[m[2].toUpperCase()] || 0); text = text.slice(m[0].length); }
  if (/^AUDIT:\s*/i.test(text)) { ev.tags.push('audit'); text = text.replace(/^AUDIT:\s*/i, ''); }
  ev.message = text.slice(0, 1000);

  // ---- OpenSSH (documented texts) ----
  if ((m = /^Accepted (\S+) for (\S+) from (\S+) port (\d+)/.exec(text))) {
    setUser(ev, m[2]); ev.src_ip = ipOrEmpty(m[3]); ev.src_port = Number(m[4]);
    Object.assign(ev, { category: 'authentication', action: 'logon', outcome: 'success' });
    Object.assign(ev.fields, { ui: 'ssh', auth_method: m[1] }); ev.tags.push('admin'); return ev;
  }
  if ((m = /^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)/.exec(text)) || (m = /^Invalid user (\S*) from (\S+)(?: port (\d+))?/.exec(text))) {
    const inv = /^Invalid user/.test(text) || /for invalid user/.test(text);
    if (/^Invalid user/.test(text)) { setUser(ev, m[1]); ev.src_ip = ipOrEmpty(m[2]); if (m[3]) ev.src_port = Number(m[3]); } else { setUser(ev, m[2]); ev.src_ip = ipOrEmpty(m[3]); ev.src_port = Number(m[4]); ev.fields.auth_method = m[1]; }
    Object.assign(ev, { category: 'authentication', action: 'logon-failed', outcome: 'failure', severity: Math.max(ev.severity, 2) });
    Object.assign(ev.fields, { ui: 'ssh', reason: inv ? 'invalid user' : 'bad credentials' }); ev.tags.push('admin', 'T1110'); return ev;
  }
  if ((m = /session closed for user (\S+)/.exec(text)) && /sshd/.test(`${app} ${text}`)) {
    setUser(ev, m[1]); Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' }); ev.fields.ui = 'ssh'; ev.tags.push('admin'); return ev;
  }

  // ---- alarms (raised / cleared / acknowledged) ----
  if (/\balarm\b/i.test(text) && /\b(raised|cleared|clear|acknowledged|severity\s*=|\[(?:critical|major|minor|warning)\])/i.test(text)) { alarm(ev, text); return ev; }

  // ---- management logins / logouts (web UI, CLI / SSH, REST API, Orchestrator) ----
  const isLoginFail = /\b(?:user\s+)?log\s?in\s+(?:failure|failed)\b|\bfailed\s+(?:to\s+)?log\s?in\b|\bauthentication\s+(?:failure|failed)\b|\blogin\s+refused\b|\binvalid\s+(?:password|credentials)\b/i.test(text);
  const isLogin = !isLoginFail && /\buser\s+(?:login|logged\s+in)\b|\blogged\s+in\b|\blogin\s+(?:succeeded|successful|success)\b|\bsession\s+(?:opened|started)\s+for\s+user\b/i.test(text);
  const isLogout = /\buser\s+(?:logout|logged\s+out)\b|\blogged\s+out\b|\bsession\s+(?:closed|ended|expired)\s+for\s+user\b/i.test(text);
  if (isLoginFail || isLogin || isLogout) {
    setUser(ev, userOf(text)); ev.src_ip = ipOf(text);
    const ui = uiOf(text, app === 'sshd' ? 'ssh' : /web|http/.test(app) ? 'web' : /rest|api/.test(app) ? 'api' : '');
    if (ui) ev.fields.ui = ui;
    const am = /\bauth(?:entication)?\s+method\s*:?\s*([A-Za-z0-9_-]+)/i.exec(text); if (am) ev.fields.auth_method = am[1].toLowerCase();
    ev.category = 'authentication'; ev.tags.push('admin');
    if (isLoginFail) {
      Object.assign(ev, { action: 'logon-failed', outcome: 'failure', severity: Math.max(ev.severity, 2) }); ev.tags.push('T1110');
      const rm = /\breason\s*[:=]\s*([^,;]+)/i.exec(text); if (rm) ev.fields.reason = rm[1].trim().slice(0, 200);
    } else if (isLogout) Object.assign(ev, { action: 'logoff', outcome: 'success' });
    else Object.assign(ev, { action: 'logon', outcome: 'success' });
    return ev;
  }

  // ---- reboot / software upgrade ----
  const isUpgrade = /\b(?:software|image|firmware|ecos|vxoa)\s+(?:upgrade|update|install(?:ation)?)\b|\bupgrad(?:e|ed|ing)\s+(?:to|from|software|the appliance|appliance)\b/i.test(text);
  const isReboot = !isUpgrade && /\breboot(?:ing|ed)?\b|\brestart(?:ing|ed)?\s+(?:the\s+)?(?:system|appliance)\b|\bsystem\s+(?:is\s+)?(?:going\s+down|shutting\s+down|halt(?:ed|ing)?)\b|\b(?:system|appliance)\s+(?:boot(?:ed)?|start(?:ed)?\s+up)\b/i.test(text);
  if (isReboot || isUpgrade) {
    Object.assign(ev, { category: 'system', action: isUpgrade ? 'upgrade' : 'reboot', outcome: /\bfail(?:ed|ure)?\b|\berror\b/i.test(text) ? 'failure' : 'success', severity: Math.max(ev.severity, 2) });
    setUser(ev, userOf(text)); ev.src_ip = ipOf(text);
    const ui = uiOf(text); if (ui) ev.fields.ui = ui;
    ev.fields.phase = /\b(?:request(?:ed)?|initiat(?:ed|ing)|schedul(?:ed|ing)|going down|shutting down|rebooting|start(?:ed|ing)?\s+(?:the\s+)?upgrade)\b/i.test(text) ? 'requested' : /\bboot(?:ed)?|start(?:ed)?\s+up|complet(?:ed|e)\b|finish(?:ed)?\b/i.test(text) ? 'completed' : undefined;
    const vm = /\b(?:to|version|release|image)\s+v?(\d+(?:\.\d+){2,}[\w.-]*)/i.exec(text); if (vm) ev.fields.version = vm[1];
    ev.tags.push(isUpgrade ? 'upgrade' : 'reboot'); return ev;
  }

  // ---- tunnel state changes ----
  if ((m = /\btunnel\s+["']?([A-Za-z0-9._:-]{2,})["']?\b.*?\bto\s+(up|down)\b/i.exec(text)) || (m = /\btunnel\s+["']?([A-Za-z0-9._:-]{2,})["']?\s+(?:is|went|has\s+gone|transitioned|changed)\s+(?:to\s+)?(up|down)\b/i.exec(text)) || (m = /\btunnel\s+(up|down)\s*[:\-]\s*["']?([A-Za-z0-9._:-]{2,})/i.exec(text))) {
    const name = /^(up|down)$/i.test(m[1]) ? m[2] : m[1];
    const st = (/^(up|down)$/i.test(m[1]) ? m[1] : m[2]).toLowerCase();
    Object.assign(ev, { category: 'network', action: st === 'down' ? 'tunnel-down' : 'tunnel-up', outcome: st === 'down' ? 'failure' : 'success', severity: st === 'down' ? Math.max(ev.severity, 2) : Math.min(ev.severity, 1) });
    ev.fields.tunnel = name;
    const pm = /\b(?:peer|remote(?:\s+appliance)?|destination)\s*[:=]?\s*["']?([A-Za-z0-9._:-]{2,})/i.exec(text);
    const peer = peerOfTunnel(name) || (pm ? pm[1] : '');
    if (peer) { ev.fields.peer = peer; if (ipOrEmpty(peer)) ev.dst_ip = peer; }
    const rm = /\b(?:reason|cause)\s*[:=]\s*([^,;]+)/i.exec(text); if (rm) ev.fields.reason = rm[1].trim().slice(0, 200);
    ev.tags.push('tunnel'); return ev;
  }

  // ---- configuration changes (audit) ----
  if (/\bconfig(?:uration)?\s+change\b|\bconfiguration\s+(?:changed|modified|updated|saved|committed)\b|\bconfiguration\s+changes\s*:|\bconfig(?:uration)?\s+(?:write|save|commit)\b|\bchanged\s+(?:the\s+)?(?:configuration|setting)\b/i.test(text)) {
    Object.assign(ev, { category: 'system', action: 'config-change', outcome: /\bfail(?:ed|ure)?\b/i.test(text) ? 'failure' : 'success', severity: Math.max(ev.severity, 1) });
    setUser(ev, userOf(text)); ev.src_ip = ipOf(text);
    const ui = uiOf(text); if (ui) ev.fields.ui = ui;
    const cm = /\bconfiguration\s+changes\s*:\s*(.*)$/is.exec(text) || /\bconfig(?:uration)?\s+change(?:\s+ID\s+\d+)?\s*:\s*(.*)$/is.exec(text);
    if (cm) ev.fields.change = cm[1].trim().slice(0, 2000);
    const im = /\bchange\s+ID\s+(\d+)/i.exec(text); if (im) ev.fields.change_id = im[1];
    ev.tags.push('admin', 'config'); return ev;
  }

  // ---- anything else: generic syslog event of the silverpeak source ----
  return ev;
}

module.exports = {
  name: 'silverpeak',
  // sniffed only on unmistakable vendor markers (a plain sshd / Linux line keeps going to linux.js)
  sniff(line, meta = {}) {
    const { hdr, body } = split(line, meta);
    if (hdr && APP_MARK.test(hdr.app || '')) return true;
    return MARK.test(String(body || '')) && /\b(?:tunnel|alarm|appliance|AUDIT|login|config(?:uration)?|reboot|upgrade)\b/i.test(String(body || ''));
  },
  parse,
  peerOfTunnel, alarmType,
};
