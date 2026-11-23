// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// VMware ESXi 6.7/7.x/8.x host syslog (hostd / vpxa / vobd / fdm). Transport is RFC 3164 with an ISO timestamp:
//   <166>2024-05-01T10:00:00.123Z esxi-01.corp.local Hostd: info hostd[2099456] [Originator@6876 sub=Vimsvc.ha-eventmgr opID=abc] Event 123 : User root@10.0.0.5 logged in as VMware-client/8.0.0
//   <166>2024-05-01T10:00:01Z esxi-01 Hostd: info hostd[2099456] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 124 : vm01 on esxi-01 in ha-datacenter is powered on
//   <166>2024-05-01T10:00:02Z esxi-01 vobd:  [GenericCorrelator] 123456us: [esx.audit.ssh.enabled] SSH access has been enabled.
//   <166>2024-05-01T10:00:03Z esxi-01 Vpxa: verbose vpxa[2099600] [Originator@6876 sub=vpxLro opID=xyz] [VpxLRO] -- BEGIN task-123 -- vm-45 -- vim.VirtualMachine.powerOff -- 52d8…
// ESXi 8 writes "Hostd[2099456]:" as the tag; both forms are accepted. Event texts are the vim.event.* descriptions
// (VMware vSphere API reference, "Event" data objects); vobd ids are the esx.audit.* / esx.problem.* / vob.* VOB identifiers.
// sshd on ESXi logs the standard OpenSSH texts and is parsed by linux.js when the source type is 'syslog'/'esxi' falls back.
const { split, sevFromSyslog, sevFromName, ipOrEmpty, splitUser, clean, toInt } = require('./util');

const BODY_RE = /^(?:(info|warning|error|verbose|debug|trivia)\s+)?(hostd|vpxa|vobd|fdm|rhttpproxy|hostd-probe|vmkernel|vmkwarning|crond|dcui|vmsyslogd|likewise|lsassd|vpxd)?(?:\[(\d+)\])?\s*(?:\[Originator@6876([^\]]*)\]\s*)?(.*)$/s;
const VOB_RE = /\[((?:esx|vob|com)\.[a-z0-9.]+)\]\s*(.*)$/s;
const APPS = /^(hostd|vpxa|vobd|fdm|rhttpproxy|hostd-probe|vmkernel|vmkwarning|dcui|vpxd)$/i;
const LEVEL_SEV = { error: 3, warning: 2, info: 0, verbose: 0, debug: 0, trivia: 0 };

function who(ev, u) { const w = splitUser(u); ev.user = w.user; if (w.domain) ev.domain = w.domain; }

function vob(ev, id, text) {
  ev.fields.vob_id = id;
  ev.event_code = id;
  ev.message = text.slice(0, 1000) || id;
  let m;
  if (/^esx\.problem\./.test(id)) { ev.severity = Math.max(ev.severity, 2); ev.outcome = 'failure'; ev.tags.push('problem'); }
  if (/^esx\.clear\./.test(id)) { ev.outcome = 'success'; ev.tags.push('cleared'); }
  if ((m = /^esx\.audit\.(ssh|shell|dcui|lockdownmode|net\.firewall|esxcli\.host\.restart|host\.stop|host\.boot|account|usb|vmfs|maintenancemode|net\.firewall\.config|uw\.secpolicy)\.?(\w*)/.exec(id))) {
    const what = m[1], how = m[2] || '';
    ev.tags.push('audit');
    if (what === 'account') {
      if (/loginfailures|locked/.test(id)) { Object.assign(ev, { category: 'iam', action: 'account-locked', outcome: 'failure', severity: Math.max(ev.severity, 2) }); ev.tags.push('T1110'); }
      else if (/user\.(add|create)/.test(id)) Object.assign(ev, { category: 'iam', action: 'user-created', outcome: 'success', severity: Math.max(ev.severity, 2) });
      else if (/user\.(remove|delete)/.test(id)) Object.assign(ev, { category: 'iam', action: 'user-deleted', outcome: 'success', severity: Math.max(ev.severity, 2) });
      else if (/password/.test(id)) Object.assign(ev, { category: 'iam', action: 'password-change', outcome: 'success', severity: Math.max(ev.severity, 1) });
      else Object.assign(ev, { category: 'iam', action: 'user-modified', outcome: 'success' });
      const um = /(?:user )?account '([^']+)'|user '([^']+)'|user (\S+)/i.exec(text); if (um) ev.target_user = (um[1] || um[2] || um[3]).toLowerCase();
    } else if (what === 'maintenancemode') {
      Object.assign(ev, { category: 'system', action: 'maintenance-mode', outcome: 'success' });
      ev.fields.maintenance = /enter|entered/.test(how) ? 'enter' : /exit|exited/.test(how) ? 'exit' : how;
      ev.severity = Math.max(ev.severity, 1);
    } else if (what === 'host.boot' || what === 'host.stop' || what === 'esxcli.host.restart') {
      Object.assign(ev, { category: 'system', action: what === 'host.boot' ? 'service-started' : 'service-stopped', outcome: 'success', severity: Math.max(ev.severity, 1) });
    } else if (what === 'dcui' && /login/.test(id)) {
      const failed = /fail/.test(id);
      Object.assign(ev, { category: 'authentication', action: failed ? 'logon-failed' : 'logon', outcome: failed ? 'failure' : 'success' });
      ev.tags.push('admin');
    } else {
      // ssh / shell / lockdownmode / net.firewall / usb / vmfs / secpolicy: configuration audit
      const risky = /(?:ssh|shell)\.enabled|lockdownmode\.disabled|net\.firewall\.disabled|secpolicy/.test(id);
      Object.assign(ev, { category: /firewall|lockdown|secpolicy/.test(id) ? 'policy' : 'system', action: 'config-change', outcome: 'success', severity: Math.max(ev.severity, risky ? 3 : 1) });
      ev.tags.push('admin');
      if (risky) ev.tags.push('T1685');
      if ((m = /Operation '([^']+)' for rule set (\S+) (succeeded|failed)/.exec(text))) { ev.fields.firewall_op = m[1]; ev.fields.ruleset = m[2]; ev.outcome = m[3] === 'succeeded' ? 'success' : 'failure'; }
    }
  } else if (/^vob\.|^esx\.problem\./.test(id)) {
    Object.assign(ev, { category: 'system', action: 'event' });
    if (/linkstate\.down|psu|fan|temperature|thermal|degraded|lost|apd|pdl|offline|redundancy|heartbeat/.test(id)) ev.tags.push('hardware');
    if (/vmnic|net/.test(id)) { const nm = /(vmnic\d+)/.exec(text); if (nm) ev.fields.nic = nm[1]; }
  } else {
    Object.assign(ev, { category: 'system', action: 'event' });
  }
}

function hostdEvent(ev, text) {
  let m;
  if ((m = /^User ([^\s@]+)(?:@(\S+))? logged in as (.*)$/.exec(text))) {
    who(ev, m[1]); ev.src_ip = ipOrEmpty(m[2]); ev.user_agent = m[3].trim();
    Object.assign(ev, { category: 'authentication', action: 'logon', outcome: 'success' });
    ev.fields.esx_event = 'user.login';
    ev.tags.push('admin');
  } else if ((m = /^User ([^\s@]+)(?:@(\S+))? logged out(?: \(login time: ([^,]*), number of API invocations: (\d+), user agent: ([^)]*)\))?/.exec(text))) {
    who(ev, m[1]); ev.src_ip = ipOrEmpty(m[2]);
    Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' });
    if (m[3]) ev.fields.login_time = m[3];
    if (m[4]) ev.fields.api_invocations = m[4];
    if (m[5]) ev.user_agent = m[5];
    ev.fields.esx_event = 'user.logout';
    ev.tags.push('admin');
  } else if ((m = /^Cannot login ([^\s@]+)(?:@(\S+))?/.exec(text)) || (m = /^User ([^\s@]+)(?:@(\S+))? (?:failed to log in|login failed)/.exec(text))) {
    who(ev, m[1]); ev.src_ip = ipOrEmpty(m[2]);
    Object.assign(ev, { category: 'authentication', action: 'logon-failed', outcome: 'failure', severity: Math.max(ev.severity, 2) });
    ev.fields.esx_event = 'user.loginfailed';
    ev.tags.push('admin', 'T1110');
  } else if ((m = /^(\S+) on (\S+) in (\S+) is powered (on|off)\b/.exec(text)) || (m = /^(\S+) on host (\S+) in (\S+) is (?:powered|being) (on|off|suspended|reset)/.exec(text))) {
    Object.assign(ev, { category: 'system', action: m[4] === 'on' ? 'vm-power-on' : m[4] === 'off' ? 'vm-power-off' : 'event', outcome: 'success' });
    Object.assign(ev.fields, { vm: m[1], esx_host: m[2], datacenter: m[3], esx_event: `vm.powered${m[4]}` });
  } else if ((m = /^(?:Removed|Deleted) (\S+) (?:on (\S+) )?from (\S+)/.exec(text))) {
    Object.assign(ev, { category: 'system', action: 'vm-deleted', outcome: 'success', severity: Math.max(ev.severity, 2) });
    Object.assign(ev.fields, { vm: m[1], esx_host: m[2], datacenter: m[3], esx_event: 'vm.removed' });
    ev.tags.push('T1485');
  } else if ((m = /^Created virtual machine (\S+) on (\S+) in (\S+)/.exec(text)) || (m = /^(?:Registered|Deploying|Cloning) (\S+) on (\S+) in (\S+)/.exec(text))) {
    Object.assign(ev, { category: 'system', action: 'vm-created', outcome: 'success', severity: Math.max(ev.severity, 1) });
    Object.assign(ev.fields, { vm: m[1], esx_host: m[2], datacenter: m[3], esx_event: 'vm.created' });
  } else if ((m = /^Reconfigured (\S+) on (\S+) in (\S+)/.exec(text))) {
    Object.assign(ev, { category: 'system', action: 'vm-reconfigured', outcome: 'success' });
    Object.assign(ev.fields, { vm: m[1], esx_host: m[2], datacenter: m[3], esx_event: 'vm.reconfigured' });
  } else if ((m = /^Host (\S+) in (\S+) has (entered|exited) maintenance mode/.exec(text))) {
    Object.assign(ev, { category: 'system', action: 'maintenance-mode', outcome: 'success', severity: Math.max(ev.severity, 1) });
    Object.assign(ev.fields, { esx_host: m[1], datacenter: m[2], maintenance: m[3] === 'entered' ? 'enter' : 'exit', esx_event: `host.maintenance.${m[3] === 'entered' ? 'enter' : 'exit'}` });
  } else if ((m = /^(\S+) on (\S+) in (\S+) is (?:migrating|being migrated|migrated)/.exec(text))) {
    Object.assign(ev, { category: 'system', action: 'event', outcome: 'success' });
    Object.assign(ev.fields, { vm: m[1], esx_host: m[2], datacenter: m[3], esx_event: 'vm.migrated' });
  } else if ((m = /^(?:Firewall configuration has changed|Enabled|Disabled) (.*)$/i.exec(text)) || /SSH (?:access|for the host) has been (?:enabled|disabled)/i.test(text) || /lockdown mode/i.test(text)) {
    Object.assign(ev, { category: 'policy', action: 'config-change', outcome: 'success', severity: Math.max(ev.severity, 2) });
    ev.tags.push('admin');
    ev.fields.esx_event = 'host.config';
  } else if ((m = /^(?:Snapshot|Removed snapshot|Created snapshot|Reverted) .*?(?:of|for|on) (\S+)/i.exec(text))) {
    Object.assign(ev, { category: 'system', action: 'event', outcome: 'success' });
    Object.assign(ev.fields, { vm: m[1], esx_event: 'vm.snapshot' });
  } else {
    Object.assign(ev, { category: 'system', action: 'event' });
  }
}

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const app = (hdr && hdr.app ? hdr.app : '').replace(/\[\d+\]$/, '').toLowerCase();
  const bm = BODY_RE.exec(body.trim());
  if (!bm) return null;
  const [, level, proc0, pid, orig, text0] = bm;
  const proc = proc0 || (APPS.test(app) ? app : '');
  const hasVob = VOB_RE.exec(text0);
  if (!proc && !orig && !hasVob && !/^(?:\[\w+Correlator\]|Event \d+ :)/.test(text0)) return null;
  const ev = {
    src_type: 'esxi', severity: Math.max(hdr && hdr.sev >= 0 ? sevFromSyslog(hdr.sev) : 0, LEVEL_SEV[level] || 0),
    category: 'system', action: 'event', outcome: 'unknown', process: proc, event_code: '', message: '', tags: [],
    fields: { esx_process: proc || undefined, pid: pid || undefined, log_level: level || undefined },
  };
  if (orig) {
    const sm = /sub=(\S+)/.exec(orig); if (sm) ev.fields.sub = sm[1];
    const om = /opID=(\S+)/.exec(orig); if (om) ev.fields.op_id = om[1];
    const um = /user=(\S+)/.exec(orig); if (um) who(ev, um[1]);
  }
  let text = text0.trim();
  let m;
  if ((m = /^(?:\[\w+Correlator\]\s*)?(\d+)us:\s*/.exec(text))) { ev.fields.vob_uptime_us = m[1]; text = text.slice(m[0].length); }
  if ((m = VOB_RE.exec(text))) { vob(ev, m[1], m[2].trim()); return ev; }
  if ((m = /^Event (\d+) :\s*(.*)$/s.exec(text))) { ev.fields.esx_event_id = m[1]; text = m[2].trim(); ev.event_code = 'event:' + m[1]; }
  if ((m = /^\[VpxLRO\] -- (BEGIN|FINISH) (\S+)(?: -- (\S*) -- (\S+))?/.exec(text))) {
    Object.assign(ev.fields, { vpx_task: m[2], vpx_phase: m[1].toLowerCase(), vpx_entity: m[3] || undefined, vpx_method: m[4] || undefined });
    ev.event_code = m[4] || 'vpxlro';
    ev.message = text.slice(0, 1000);
    if (m[4] && /\.(?:powerOff|powerOn|destroy|unregister|reconfigure|createSnapshot|removeSnapshot|enterMaintenanceMode|exitMaintenanceMode)/i.test(m[4]) && m[1] === 'BEGIN') {
      const meth = m[4].split('.').pop().toLowerCase();
      ev.action = meth === 'poweroff' ? 'vm-power-off' : meth === 'poweron' ? 'vm-power-on' : meth === 'destroy' ? 'vm-deleted' : meth === 'reconfigure' ? 'vm-reconfigured' : meth === 'entermaintenancemode' ? 'maintenance-mode' : 'event';
      if (meth === 'entermaintenancemode') ev.fields.maintenance = 'enter';
      if (meth === 'destroy') ev.severity = Math.max(ev.severity, 2);
      ev.fields.esx_event = 'task.' + meth;
    }
    return ev;
  }
  ev.message = text.slice(0, 1000) || body.slice(0, 1000);
  hostdEvent(ev, text);
  if (!ev.event_code) ev.event_code = ev.fields.esx_event || (proc ? proc + ':' + (level || 'log') : 'esxi');
  if (!ev.user && (m = /\b(?:user|User)[:= ]+'?([A-Za-z0-9_.\\@-]+)'?/.exec(text)) && !/^(agent|invocations)$/i.test(m[1])) who(ev, m[1]);
  return ev;
}

module.exports = {
  name: 'esxi',
  sniff(line, meta = {}) {
    const { hdr, body } = split(line, meta);
    if (/\[Originator@6876[\s\]]/.test(body) || VOB_RE.test(body) || /\[VpxLRO\]/.test(body)) return true;
    const app = (hdr && hdr.app ? hdr.app : '').replace(/\[\d+\]$/, '').toLowerCase();
    return APPS.test(app) && /^(?:info|warning|error|verbose|debug)\s+\w+(?:\[\d+\])?\s/.test(body.trim()) || /^\s*(?:info|warning|error|verbose)\s+(?:hostd|vpxa|vobd|fdm|rhttpproxy)\[\d+\]/.test(body);
  },
  parse,
};
