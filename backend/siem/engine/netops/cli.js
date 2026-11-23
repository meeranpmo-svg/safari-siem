// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Read-only device CLI for the AI Network Engineer: SSH to a Cisco switch / router / ASA (Netmiko, through
 * cli-helper.py) and run show commands from a fixed allowlist. Nothing here can enter configuration mode, reload, copy,
 * write or clear: a command is accepted only when it matches one of the read-only templates below, and the helper
 * checks again that every command starts with "show".
 *   createCli({ inventory, state, config, log, runner? })
 *     .status()                      → {available, reason, netmiko, python}           (helper probed, cached 5 min)
 *     .catalogue(vendor?)            → the allowed commands per vendor
 *     .check(vendor, cmd)            → normalised command or throws (400) with the reason
 *     .fetchHostKey(id)              → {type, fingerprint, pinned, matches}  (no login, nothing sent but the SSH hello)
 *     .trustHostKey(id, fingerprint, by)  pins the key fetched in the last 10 min if the fingerprint is the one shown
 *     .forgetHostKey(id, by)
 *     .hostKey(id)                   → {type, fingerprint, by, at} | null
 *     .run(id, commands[], {by, via, textfsm})  → {device, prompt, results:[{command, output, parsed?, error?}], ms}
 *     .facts(id, by)                 → reads show version + show inventory, stores model / serial / IOS on the device
 *     .log(limit)                    → who ran what, newest first (every run, from the portal or the AI)
 * Login: secrets.json "netops.devices.<id>.ssh" {username, password, secret?, port?} (write-only, like SNMP / API).
 * The SSH host key must be trusted by an administrator before the first login (no trust-on-first-use): a password is
 * never sent to a device that has not proved it is the one that was trusted.
 * Output passes through redact(): passwords, secrets, keys and SNMP communities in running-config are removed before
 * the text reaches the portal, the AI or a log.
 */
const path = require('node:path');
const fs = require('node:fs');
const { spawn } = require('node:child_process');

const IF = '(?:[a-z][a-z-]{1,24}\\s?\\d{1,3}(?:/\\d{1,3}){0,3}(?:\\.\\d{1,5})?|vlan\\s?\\d{1,4}|po\\d{1,3})';
const ARG = { if: IF, mac: '[0-9a-f]{4}\\.[0-9a-f]{4}\\.[0-9a-f]{4}', ip: '\\d{1,3}(?:\\.\\d{1,3}){3}', vlan: '\\d{1,4}', n: '\\d{1,4}' };
// "| include text" style output filters are allowed after any command (text: letters, digits, space . / : _ -)
const FILTER = '(?:\\s*\\|\\s*(?:include|exclude|begin|section|count)\\s+[a-z0-9 ./:_-]{1,60})?';

const CATALOGUE = {
  'cisco-ios': [
    ['show version', 'IOS version, model, serial, uptime, last reload reason'],
    ['show inventory', 'chassis, modules, power supplies and SFPs with serial numbers'],
    ['show switch', 'stack members, roles and state'],
    ['show running-config', 'current configuration (passwords, keys and communities removed)'],
    ['show running-config interface {if}', 'configuration of one interface'],
    ['show interfaces status', 'every port: connected / notconnect / err-disabled, VLAN, speed, duplex'],
    ['show interfaces', 'all interface counters'],
    ['show interfaces {if}', 'one interface: errors, drops, load, duplex'],
    ['show interfaces counters errors', 'CRC, input / output errors per port'],
    ['show interfaces trunk', 'trunk ports and allowed VLANs'],
    ['show interfaces description', 'port descriptions and status'],
    ['show interfaces {if} transceiver', 'optical levels of one SFP'],
    ['show ip interface brief', 'interfaces with IP and up / down'],
    ['show vlan brief', 'VLANs and their access ports'],
    ['show cdp neighbors', 'connected Cisco devices per port'],
    ['show cdp neighbors detail', 'neighbours with IP, model and software'],
    ['show lldp neighbors', 'connected LLDP devices per port'],
    ['show lldp neighbors detail', 'LLDP neighbours with management address'],
    ['show mac address-table', 'learned MAC addresses'],
    ['show mac address-table interface {if}', 'MACs learned on one port'],
    ['show mac address-table address {mac}', 'which port a MAC is on (aaaa.bbbb.cccc)'],
    ['show mac address-table vlan {vlan}', 'MACs in one VLAN'],
    ['show ip arp', 'ARP table'],
    ['show ip arp {ip}', 'ARP entry for one IP'],
    ['show spanning-tree summary', 'STP mode and port states'],
    ['show spanning-tree', 'STP per VLAN'],
    ['show spanning-tree vlan {vlan}', 'STP for one VLAN'],
    ['show spanning-tree blockedports', 'ports blocked by STP'],
    ['show etherchannel summary', 'port-channels and members'],
    ['show errdisable recovery', 'err-disable causes and recovery timers'],
    ['show port-security', 'port-security per port'],
    ['show authentication sessions', '802.1X / MAB sessions'],
    ['show ip dhcp snooping binding', 'DHCP snooping bindings'],
    ['show power inline', 'PoE budget and per-port power'],
    ['show environment all', 'fans, temperature, power supplies'],
    ['show processes cpu sorted', 'CPU per process'],
    ['show processes memory sorted', 'memory per process'],
    ['show logging', 'the switch\'s local log buffer'],
    ['show clock', 'device time'],
    ['show ntp status', 'NTP synchronisation'],
    ['show ip route', 'routing table'],
    ['show ip route {ip}', 'route to one address'],
    ['show ip ospf neighbor', 'OSPF neighbours'],
    ['show ip bgp summary', 'BGP peers'],
    ['show standby brief', 'HSRP groups'],
    ['show vrrp brief', 'VRRP groups'],
    ['show access-lists', 'ACLs with hit counters'],
    ['show users', 'who is logged in'],
    ['show privilege', 'the privilege level of this login (onboarding checks it is not 15)'],
    ['show license summary', 'licence state'],
    ['show boot', 'boot image settings'],
  ],
  'cisco-asa': [
    ['show version', 'ASA version, model, serial, uptime'],
    ['show inventory', 'chassis and modules with serial numbers'],
    ['show interface ip brief', 'interfaces with IP and status'],
    ['show interface {if}', 'one interface: errors, drops'],
    ['show nameif', 'interface names and security levels'],
    ['show route', 'routing table'],
    ['show failover', 'failover state'],
    ['show vpn-sessiondb summary', 'VPN sessions'],
    ['show crypto ipsec sa', 'IPsec security associations'],
    ['show conn count', 'connection count'],
    ['show cpu usage', 'CPU'],
    ['show memory', 'memory'],
    ['show logging', 'local log buffer'],
    ['show clock', 'device time'],
    ['show access-list', 'ACLs with hit counters'],
    ['show running-config', 'current configuration (passwords, keys and communities removed)'],
  ],
};
const DEVICE_TYPE = { 'cisco-ios': 'cisco_ios', 'cisco-asa': 'cisco_asa' };
const MAX_CMDS = 8, HOSTKEY_TTL = 10 * 60 * 1000;

class CliError extends Error { constructor(code, msg, kind) { super(msg); this.code = code; this.kind = kind || ''; } }

const compiled = {};
function patterns(vendor) {
  if (!compiled[vendor]) compiled[vendor] = (CATALOGUE[vendor] || []).map(([t]) => new RegExp('^' + t.replace(/ /g, '\\s+').replace(/\{(\w+)\}/g, (m, k) => '(?:' + ARG[k] + ')') + FILTER + '$', 'i'));
  return compiled[vendor];
}
function check(vendor, cmd) {
  if (!CATALOGUE[vendor]) throw new CliError(400, `CLI access is available for Cisco IOS switches / routers and Cisco ASA (this device is ${vendor || 'unknown'})`);
  const c = String(cmd == null ? '' : cmd).replace(/\s+/g, ' ').trim();
  if (!c || c.length > 160 || /[\r\n;`$\\]/.test(c)) throw new CliError(400, 'invalid command');
  if (!patterns(vendor).some((re) => re.test(c))) throw new CliError(400, `"${c.slice(0, 80)}" is not on the read-only list for ${vendor}. Allowed: ${CATALOGUE[vendor].map((x) => x[0]).join(', ')}`);
  return c;
}

// passwords / secrets / keys / communities out of any output (running-config, show tech excerpts, logs)
function redact(text) {
  return String(text == null ? '' : text).split('\n').map((l) => {
    let x = l.replace(/\b(community)\s+(?:\d\s+)?\S+/gi, '$1 <removed>');
    x = x.replace(/\b(snmp-server user\s+\S+\s+\S+\s+v3).*$/i, '$1 <auth / priv keys removed>');
    // "(?![-\w])": "service password-encryption" / "password encryption aes" are settings, not secrets, and the auditor reads them
    const m = /\b(secret|password|passwd|key-string|authentication-key|message-digest-key|pre-shared-key|ikev[12] (?:local|remote)-authentication pre-shared-key|key)\b(?![-\w])(?! encryption\b)/i.exec(x);
    if (m && !/^\s*(?:crypto key generate|key chain|key config-key|no )/i.test(x) && !/^\s*!/.test(x)) {
      // the hash type digit (0 clear, 5 MD5, 7 reversible, 8 PBKDF2, 9 scrypt) is kept: it is the audit fact, not the secret
      const ty = /^\s+(\d)\s+\S/.exec(x.slice(m.index + m[0].length));
      x = x.slice(0, m.index + m[0].length) + (ty ? ' ' + ty[1] : '') + ' <removed>';
    }
    return x;
  }).join('\n');
}

function realRunner(config) {
  const c = (config && config.netops && config.netops.cli) || {};
  const helper = c.helper || path.join(__dirname, 'cli-helper.py');
  const candidates = [c.python, '/opt/sentra-siem/pyenv/bin/python3', 'python3'].filter(Boolean);
  const py = candidates.find((p) => p === 'python3' || fs.existsSync(p));
  return (req, timeoutMs) => new Promise((resolve) => {
    let child; try { child = spawn(py, [helper], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH || '/usr/bin:/bin', LANG: 'C.UTF-8', HOME: process.env.HOME || '/tmp', PYTHONDONTWRITEBYTECODE: '1' } }); }
    catch (e) { return resolve({ ok: false, kind: 'missing', error: 'cannot start Python: ' + e.message }); }
    let out = '', err = '', done = false;
    const fin = (r) => { if (!done) { done = true; clearTimeout(t); resolve(r); } };
    const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) { /* gone */ } fin({ ok: false, kind: 'timeout', error: `the SSH session took longer than ${Math.round(timeoutMs / 1000)} s` }); }, timeoutMs);
    child.stdout.on('data', (d) => { if (out.length < 8e6) out += d; });
    child.stderr.on('data', (d) => { if (err.length < 4000) err += d; });
    child.on('error', (e) => fin({ ok: false, kind: 'missing', error: e.code === 'ENOENT' ? 'Python 3 is not installed on the SIEM server' : e.message }));
    child.on('close', () => { try { fin(JSON.parse(out)); } catch (e) { fin({ ok: false, kind: 'error', error: 'helper failed: ' + (err.trim().split('\n').pop() || 'no answer').slice(0, 300) }); } });
    child.stdin.end(JSON.stringify(req));
  });
}

function createCli({ inventory, state, config, log, runner } = {}) {
  if (!inventory || !state) throw new Error('cli needs inventory and state');
  const L = log || { info() {}, warn() {} };
  const keys = state.collection('netops_ssh_hostkeys'), runs = state.collection('netops_cli_log');
  const exec = runner || realRunner(config);
  const pending = new Map(), busy = new Set();
  let probe = null, probeAt = 0, active = 0;
  const cfg = () => (config && config.netops && config.netops.cli) || {};

  async function status() {
    if (cfg().enabled === false) return { available: false, reason: 'device CLI access is switched off (config netops.cli.enabled)' };
    if (!probe || Date.now() - probeAt > 5 * 60 * 1000) {
      const r = await exec({ op: 'version' }, 20000);
      probe = r.ok ? { available: true, netmiko: r.netmiko, paramiko: r.paramiko, python: r.python } : { available: false, reason: r.error || 'helper not available' };
      // the installer's own result says WHY (no suitable Python, no venv module, wheels that do not fit …)
      if (!r.ok) { try { const st = JSON.parse(fs.readFileSync(cfg().status_file || '/opt/sentra-siem/pyenv-status.json', 'utf8')); if (st && st.ok === false && st.reason) probe.reason = 'setup failed on ' + String(st.at || '').slice(0, 16).replace('T', ' ') + ': ' + String(st.reason).slice(0, 400); } catch (e) { if (!fs.existsSync('/opt/sentra-siem/pyenv')) probe.reason += ' - the setup has not run on this server yet (it runs with the update, step 2)'; } }
      // a failed probe is retried after 1 minute, so a fresh install shows up quickly
      probeAt = r.ok ? Date.now() : Date.now() - 4 * 60 * 1000;
    }
    return probe;
  }
  function device(id) { const d = inventory.get(id); if (!d) throw new CliError(404, 'device not found'); return d; }
  function login(d) { const s = (inventory.credentials(d.id) || {}).ssh; if (!s || !s.username || !s.password) throw new CliError(409, `no SSH login stored for ${d.name} - an administrator adds it under Credentials (use a read-only / privilege-1 account)`, 'no-login'); return s; }
  const hostKey = (id) => { const k = keys.get(id); return k ? { type: k.type, fingerprint: k.fingerprint, by: k.by, at: k.at } : null; };

  async function fetchHostKey(id) {
    const d = device(id), port = ((inventory.credentials(d.id) || {}).ssh || {}).port || 22;
    const r = await exec({ op: 'hostkey', host: d.ip, port, timeout: 15 }, 30000);
    if (!r.ok) throw new CliError(r.kind === 'missing' ? 503 : 502, r.error, r.kind);
    pending.set(d.id, { type: r.type, key: r.key, fingerprint: r.fingerprint, at: Date.now() });
    const k = keys.get(d.id);
    return { device: d.id, type: r.type, fingerprint: r.fingerprint, pinned: k ? k.fingerprint : null, matches: k ? k.key === r.key && k.type === r.type : null };
  }
  function trustHostKey(id, fingerprint, by) {
    const d = device(id), p = pending.get(d.id);
    if (!p || Date.now() - p.at > HOSTKEY_TTL) throw new CliError(409, 'read the host key first (it is shown for 10 minutes), compare it with the device, then trust it');
    if (String(fingerprint || '') !== p.fingerprint) throw new CliError(409, 'the fingerprint does not match the key that was read - read it again');
    keys.put({ id: d.id, type: p.type, key: p.key, fingerprint: p.fingerprint, by: by || '', at: Date.now() });
    pending.delete(d.id); L.info('netops ssh host key trusted', { id: d.id, by, fingerprint: p.fingerprint });
    return hostKey(d.id);
  }
  function forgetHostKey(id, by) { if (!keys.get(id)) device(id); keys.remove(id); L.info('netops ssh host key removed', { id, by }); return { removed: id }; }

  function record(entry) {
    runs.put(entry);
    const all = runs.all(); if (all.length > 600) all.sort((a, b) => a.at - b.at).slice(0, all.length - 500).forEach((x) => runs.remove(x.id));
  }
  async function run(id, commands, { by, via, textfsm } = {}) {
    const d = device(id);
    const list = (Array.isArray(commands) ? commands : [commands]).filter((c) => String(c || '').trim());
    if (!list.length) throw new CliError(400, 'no command');
    if (list.length > MAX_CMDS) throw new CliError(400, `at most ${MAX_CMDS} commands per session`);
    const cmds = list.map((c) => check(d.vendor, c));
    const st = await status(); if (!st.available) throw new CliError(503, st.reason, 'missing');
    const s = login(d), k = keys.get(d.id);
    if (!k) throw new CliError(409, `the SSH host key of ${d.name} is not trusted yet - an administrator reads and trusts it under SSH host key`, 'hostkey-unknown');
    if (busy.has(d.id)) throw new CliError(429, `another SSH session to ${d.name} is running - try again in a moment`);
    if (active >= (cfg().max_sessions || 3)) throw new CliError(429, 'too many SSH sessions running - try again in a moment');
    busy.add(d.id); active++;
    const t0 = Date.now();
    let r;
    try {
      r = await exec({ op: 'run', host: d.ip, port: s.port || 22, device_type: DEVICE_TYPE[d.vendor], username: s.username, password: s.password, secret: s.secret || '',
        known_host: { type: k.type, key: k.key }, commands: cmds, textfsm: !!textfsm, timeout: 20, read_timeout: cfg().read_timeout_s || 60 }, (cfg().session_timeout_s || 150) * 1000);
    } finally { busy.delete(d.id); active--; }
    const ms = Date.now() - t0;
    const entry = { id: 'cl-' + t0.toString(36) + Math.random().toString(36).slice(2, 6), at: t0, device: d.id, name: d.name, by: by || '', via: via || 'portal', commands: cmds, ok: !!r.ok, ms, error: r.ok ? '' : String(r.error || '').slice(0, 300) };
    record(entry);
    L.info('netops cli', { device: d.id, by, via: entry.via, commands: cmds.length, ok: entry.ok, ms });
    if (!r.ok) throw new CliError(r.kind === 'auth' || /^hostkey/.test(r.kind || '') ? 409 : r.kind === 'missing' ? 503 : 502, r.error || 'SSH session failed', r.kind);
    const results = (r.results || []).map((x) => Object.assign({ command: x.command }, x.error ? { error: x.error } : { output: redact(String(x.output || '').slice(0, 200000)) }, x.parsed ? { parsed: JSON.parse(redact(JSON.stringify(x.parsed))) } : {}));
    return { device: d.id, name: d.name, prompt: r.prompt || '', results, ms };
  }

  // model / serial / IOS from show version + show inventory (TextFSM), stored on the device record
  async function facts(id, by) {
    const d = device(id);
    const r = await run(id, ['show version', 'show inventory'], { by, via: 'facts', textfsm: true });
    const v = ((r.results[0] || {}).parsed || [])[0] || {}, inv = (r.results[1] || {}).parsed || [];
    const raw = (r.results[0] || {}).output || '';
    const arr = (x) => (Array.isArray(x) ? x : x ? [x] : []).filter(Boolean);
    const chassis = inv.filter((i) => /chassis|stack|switch \d|^\d$/i.test(String(i.name || i.descr || '')));
    const f = {
      hostname: v.hostname || '', version: v.version || (/Version ([^\s,]+)/.exec(raw) || [])[1] || '',
      model: arr(v.hardware)[0] || (chassis[0] && chassis[0].pid) || (/^[Mm]odel [Nn]umber\s*:\s*(\S+)/m.exec(raw) || /^cisco (\S+) .*processor/m.exec(raw) || [])[1] || '',
      serials: arr(v.serial).length ? arr(v.serial) : chassis.map((c) => c.sn).filter(Boolean),
      uptime: v.uptime || '', reload_reason: v.reload_reason || '', image: v.running_image || '',
      stack: chassis.length > 1 ? chassis.map((c) => ({ name: c.name, pid: c.pid, sn: c.sn })) : undefined,
      modules: inv.length, at: Date.now(), by: by || '',
    };
    inventory.setFacts(d.id, f);
    return f;
  }

  return { hostKeyFull: (id) => { const k = keys.get(id); return k ? { type: k.type, key: k.key } : null; }, status, catalogue: (v) => (v ? { [v]: CATALOGUE[v] || [] } : CATALOGUE), check, fetchHostKey, trustHostKey, forgetHostKey, hostKey, run, facts,
    log: (limit) => runs.all().sort((a, b) => b.at - a.at).slice(0, Math.min(200, limit || 50)), supported: (vendor) => !!CATALOGUE[vendor] };
}

module.exports = { createCli, check, redact, CATALOGUE, CliError, DEVICE_TYPE, realRunner };
