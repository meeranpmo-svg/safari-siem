// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Linux syslog programs: sshd, sudo, su, useradd/userdel/usermod/groupadd/gpasswd/passwd, systemd(-logind), kernel
// (iptables/UFW, OOM), cron, and pam_unix lines from any program.
const { split, clean, protoName, toInt, ipOrEmpty, parseKV } = require('./util');

const KNOWN = new Set(['sshd', 'sudo', 'su', 'useradd', 'adduser', 'userdel', 'deluser', 'usermod', 'groupadd', 'groupdel',
  'gpasswd', 'passwd', 'chpasswd', 'chage', 'kernel', 'systemd', 'systemd-logind', 'cron', 'crond', 'login', 'sshd-session']);

const ADMIN_GROUPS = /^(sudo|wheel|admin|root|adm|docker|lxd)$/i;
const u = (s) => clean(s).toLowerCase();

function auth(action, outcome, extra) { return { category: 'authentication', action, outcome, ...extra }; }

function sshd(msg) {
  let m;
  if ((m = /^Accepted (\S+) for (\S+) from (\S+) port (\d+)/.exec(msg))) {
    return auth('logon', 'success', { user: u(m[2]), src_ip: ipOrEmpty(m[3]), src_port: toInt(m[4]), dst_port: 0, proto: 'tcp', fields: { auth_method: m[1], service: 'ssh' }, message: `SSH logon ${m[2]} from ${m[3]} (${m[1]})` });
  }
  if ((m = /^Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)/.exec(msg))) {
    return auth('logon-failed', 'failure', { user: u(m[3]), src_ip: ipOrEmpty(m[4]), src_port: toInt(m[5]), proto: 'tcp', severity: 1, tags: ['T1110'], fields: { auth_method: m[1], service: 'ssh', invalid_user: m[2] ? 'true' : undefined }, message: `SSH logon failed for ${m[2] ? 'invalid user ' : ''}${m[3]} from ${m[4]}` });
  }
  if ((m = /^Invalid user (\S*) from (\S+)(?: port (\d+))?/.exec(msg))) {
    return auth('logon-failed', 'failure', { user: u(m[1]), src_ip: ipOrEmpty(m[2]), src_port: toInt(m[3]), proto: 'tcp', severity: 1, tags: ['T1110'], fields: { service: 'ssh', invalid_user: 'true', stage: 'preauth' }, message: `SSH invalid user ${m[1]} from ${m[2]}` });
  }
  if ((m = /^error: maximum authentication attempts exceeded for (invalid user )?(\S+) from (\S+) port (\d+)/.exec(msg))) {
    return auth('logon-failed', 'failure', { user: u(m[2]), src_ip: ipOrEmpty(m[3]), src_port: toInt(m[4]), severity: 2, tags: ['T1110'], fields: { service: 'ssh', max_attempts: 'true' }, message: msg });
  }
  if ((m = /^Disconnected from user (\S+) (\S+) port (\d+)/.exec(msg))) {
    return auth('logoff', 'success', { user: u(m[1]), src_ip: ipOrEmpty(m[2]), src_port: toInt(m[3]), fields: { service: 'ssh' }, message: msg });
  }
  if ((m = /^(?:Connection closed|Disconnected) by (?:(?:authenticating|invalid) user (\S+) )?(\S+) port (\d+)/.exec(msg))) {
    return { category: 'network', action: 'connection', outcome: m[1] ? 'failure' : 'unknown', user: u(m[1]), src_ip: ipOrEmpty(m[2]), src_port: toInt(m[3]), fields: { service: 'ssh' }, message: msg };
  }
  if ((m = /^Received disconnect from (\S+) port (\d+)/.exec(msg))) {
    return { category: 'network', action: 'connection', outcome: 'unknown', src_ip: ipOrEmpty(m[1]), src_port: toInt(m[2]), fields: { service: 'ssh' }, message: msg };
  }
  return null;
}

function sudo(msg) {
  const m = /^\s*(\S+) : (?:(.*?) ; )?TTY=(\S+) ; PWD=(.*?) ; USER=(\S+) ; (?:.*?; )?COMMAND=(.*)$/.exec(msg);
  if (m) {
    const failed = !!m[2];
    const target = u(m[5]);
    return {
      category: 'process', action: 'sudo', outcome: failed ? 'failure' : 'success', user: u(m[1]), target_user: target,
      cmdline: m[6], process: m[6].split(/\s+/)[0], severity: failed ? 2 : 0,
      tags: failed ? ['T1548.003'] : (target === 'root' ? ['admin'] : []),
      fields: { tty: m[3], pwd: m[4], reason: m[2] || undefined }, message: failed ? `sudo failed for ${m[1]}: ${m[2]}` : `sudo ${m[1]} → ${m[5]}: ${m[6]}`.slice(0, 300),
    };
  }
  return null;
}

function su(msg) {
  let m;
  if ((m = /^(FAILED SU )?\(to (\S+)\) (\S+) on (\S+)/.exec(msg))) {
    const failed = !!m[1];
    return auth('su', failed ? 'failure' : 'success', { user: u(m[3]), target_user: u(m[2]), severity: failed ? 1 : 0, tags: m[2] === 'root' ? ['admin'] : [], fields: { tty: m[4] }, message: msg });
  }
  return null;
}

function pam(msg, app) {
  let m;
  if ((m = /pam_unix\(([^:)]+):(\w+)\): authentication failure;(.*)$/.exec(msg))) {
    const kv = parseKV(m[3]);
    const svc = m[1];
    const failAction = svc === 'su' ? 'su' : (svc === 'sshd' ? 'event' : 'logon-failed');
    return auth(failAction, 'failure', { user: u(kv.user || kv.ruser || kv.logname), src_ip: ipOrEmpty(kv.rhost), severity: 1, fields: { service: svc, pam: 'auth', ruser: kv.ruser, tty: kv.tty }, message: msg.slice(0, 300) });
  }
  if ((m = /pam_unix\(([^:)]+):session\): session (opened|closed) for user ([^\s(]+)(?:\(uid=\d+\))?(?: by ([^\s(]*))?/.exec(msg))) {
    return auth(m[2] === 'opened' ? 'session-opened' : 'session-closed', 'success', { user: u(m[4] || m[3]), target_user: m[4] ? u(m[3]) : '', fields: { service: m[1] }, message: msg.slice(0, 300) });
  }
  if ((m = /pam_unix\((passwd|chpasswd):chauthtok\): password changed for (\S+)/.exec(msg))) {
    return { category: 'iam', action: 'password-change', outcome: 'success', target_user: u(m[2]), fields: { service: m[1] }, message: msg };
  }
  if (app === 'passwd' && (m = /password (?:for '?(\S+?)'? )?changed(?: by '?(\S+?)'?)?$/.exec(msg))) {
    return { category: 'iam', action: 'password-change', outcome: 'success', target_user: u(m[1]), user: u(m[2]), message: msg };
  }
  return null;
}

function accounts(msg) {
  let m;
  if ((m = /^new user: name=([^,]+),\s*UID=(\d+)/.exec(msg))) {
    return { category: 'iam', action: 'user-created', outcome: 'success', target_user: u(m[1]), severity: 2, tags: ['T1136.001'], fields: { uid: m[2] }, message: `local user created: ${m[1]}` };
  }
  if ((m = /^delete user '([^']+)'/.exec(msg))) {
    return { category: 'iam', action: 'user-deleted', outcome: 'success', target_user: u(m[1]), severity: 1, message: msg };
  }
  if ((m = /^add '([^']+)' to (?:shadow )?group '([^']+)'/.exec(msg)) || (m = /^user (\S+) added by \S+ to group (\S+)/.exec(msg))) {
    const admin = ADMIN_GROUPS.test(m[2]);
    return { category: 'iam', action: 'group-member-added', outcome: 'success', target_user: u(m[1]), severity: admin ? 3 : 1, tags: admin ? ['T1098', 'admin'] : ['T1098'], fields: { group: m[2] }, message: `${m[1]} added to group ${m[2]}` };
  }
  if ((m = /^new group: name=([^,]+)/.exec(msg))) {
    return { category: 'iam', action: 'config-change', outcome: 'success', fields: { group: m[1], change: 'group-created' }, message: msg };
  }
  return null;
}

function kernel(msg) {
  msg = msg.replace(/^\[\s*\d+\.\d+\]\s*/, '');
  if (/\bSRC=\S+ DST=\S+/.test(msg)) {
    const kv = parseKV(msg);
    const pm = /^\[?([^\]=]*?)\]?\s*IN=/.exec(msg);
    const prefix = pm ? pm[1].trim() : '';
    const blocked = /block|drop|deny|reject/i.test(prefix);
    const allowed = /allow|accept|audit/i.test(prefix);
    return {
      category: 'network', action: blocked ? 'blocked' : (allowed ? 'allowed' : 'connection'), outcome: blocked ? 'failure' : 'success',
      src_ip: ipOrEmpty(kv.SRC), dst_ip: ipOrEmpty(kv.DST), src_port: toInt(kv.SPT), dst_port: toInt(kv.DPT), proto: protoName(kv.PROTO),
      fields: { fw_prefix: prefix, in_if: kv.IN, out_if: kv.OUT, len: kv.LEN, ttl: kv.TTL }, message: `${prefix || 'netfilter'} ${kv.PROTO || ''} ${kv.SRC}:${kv.SPT || ''} → ${kv.DST}:${kv.DPT || ''}`,
    };
  }
  let m;
  if ((m = /Out of memory: Killed process (\d+) \(([^)]+)\)/.exec(msg))) {
    return { category: 'system', action: 'event', outcome: 'unknown', severity: 2, process: m[2], fields: { pid_killed: m[1], oom: 'true' }, message: msg.slice(0, 300) };
  }
  if (/segfault at/.test(msg)) return { category: 'system', action: 'event', severity: 1, message: msg.slice(0, 300), fields: { segfault: 'true' } };
  return null;
}

function systemd(msg) {
  let m;
  if ((m = /^New session (\S+) of user (\S+?)\.?$/.exec(msg))) return auth('session-opened', 'success', { user: u(m[2]), fields: { session: m[1], service: 'logind' }, message: msg });
  if ((m = /^Removed session (\S+?)\.?$/.exec(msg))) return auth('session-closed', 'success', { fields: { session: m[1], service: 'logind' }, message: msg });
  if ((m = /^Failed to start (.+?)\.?$/.exec(msg)) || (m = /^(\S+): Failed with result '([^']+)'/.exec(msg))) {
    return { category: 'system', action: 'service-failed', outcome: 'failure', severity: 2, fields: { unit: m[1], result: m[2] }, message: msg };
  }
  if ((m = /^Started (.+?)\.?$/.exec(msg))) return { category: 'system', action: 'service-started', outcome: 'success', fields: { unit: m[1] }, message: msg };
  if ((m = /^Stopped (.+?)\.?$/.exec(msg))) return { category: 'system', action: 'service-stopped', outcome: 'success', fields: { unit: m[1] }, message: msg };
  return null;
}

function cron(msg) {
  const m = /^\((\S+)\) CMD \((.*)\)\s*$/.exec(msg);
  if (m) return { category: 'process', action: 'cron', outcome: 'success', user: u(m[1]), cmdline: m[2], process: m[2].split(/\s+/)[0], message: `cron (${m[1]}): ${m[2]}`.slice(0, 300) };
  return null;
}

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  if (!hdr || !hdr.app) return null;
  const app = hdr.app.toLowerCase();
  let ev = null;
  if (app === 'sshd' || app === 'sshd-session') ev = sshd(body);
  else if (app === 'sudo') ev = sudo(body);
  else if (app === 'su') ev = su(body);
  else if (app === 'kernel') ev = kernel(body);
  else if (app === 'systemd' || app === 'systemd-logind') ev = systemd(body);
  else if (app === 'cron' || app === 'crond') ev = cron(body);
  else if (/^(useradd|adduser|userdel|deluser|usermod|groupadd|groupdel|gpasswd)$/.test(app)) ev = accounts(body);
  if (!ev && body.includes('pam_unix(')) ev = pam(body, app);
  if (!ev && (app === 'passwd' || app === 'chpasswd')) ev = pam(body, app);
  if (!ev) {
    if (!KNOWN.has(app) && meta.src_type !== 'linux') return null;
    ev = { category: 'system', action: 'log', outcome: 'unknown', message: body.slice(0, 1000) };
  }
  ev.src_type = 'linux';
  if (!ev.process) ev.process = hdr.app;
  return ev;
}

module.exports = {
  name: 'linux',
  sniff(line, meta = {}) {
    const { hdr, body } = split(line, meta);
    if (!hdr || !hdr.app) return false;
    return KNOWN.has(hdr.app.toLowerCase()) || body.includes('pam_unix(');
  },
  parse,
};
