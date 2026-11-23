// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network sweep + ARP table (Node stdlib only).
//   ICMP   — the system `fping` (batch) or `ping` (per host) binary via child_process.execFile with a STRICT argument
//            array: no shell, every address re-serialised from its parsed uint32 so only digits and dots reach argv.
//   TCP    — connect probes (open / refused both prove the host is up; timeout / unreachable do not).
//   ARP    — /proc/net/arp of THIS server (passive: on-link subnets only; complete entries, flag 0x2).
// Everything that touches the OS is injectable: opts.exec(bin, args, {timeout}) → {code, stdout}; opts.connect(ip,
// port, ms) → 'open'|'closed'|'timeout'|'unreachable'; opts.readFile(path) → text. Tests never touch the network.
const { execFile } = require('node:child_process');
const net = require('node:net');
const fs = require('node:fs');
const ip4 = require('../ipv4');

const BIN_RE = /^\/[A-Za-z0-9._/-]{1,200}$/;

function realExec(bin, args, { timeout = 10000 } = {}) {
  return new Promise((resolve) => {
    execFile(bin, args, { shell: false, timeout, windowsHide: true, maxBuffer: 1024 * 1024, env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' } }, (err, stdout) => {
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, stdout: String(stdout || ''), error: err && typeof err.code !== 'number' ? String(err.code || 'error') : null });
    });
  });
}

// normalise + validate addresses for argv: parsed and re-serialised, never passed through as given
function cleanIps(ips) {
  const out = [];
  for (const x of ips) { const n = typeof x === 'number' ? x : ip4.parseIp(x); if (n === null) throw new Error(`refusing to pass a non-IPv4 argument to ping: ${String(x).slice(0, 40)}`); out.push(ip4.ipStr(n)); }
  return out;
}

function fpingArgs(ips, timeoutMs) { return ['-a', '-q', '-r', '1', '-t', String(Math.max(50, Math.min(5000, timeoutMs | 0))), ...cleanIps(ips)]; }
function pingArgs(ip, timeoutMs) { return ['-n', '-q', '-c', '1', '-W', String(Math.max(1, Math.min(5, Math.ceil(timeoutMs / 1000)))), cleanIps([ip])[0]]; }

// icmp(ips, {mode:'fping'|'ping', fping_bin, ping_bin, timeout_ms, exec}) → Set of alive addresses
async function icmp(ips, o = {}) {
  const exec = o.exec || realExec;
  const timeout = o.timeout_ms || 800;
  const alive = new Set();
  if (!ips.length) return alive;
  const mode = o.mode === 'ping' ? 'ping' : 'fping';
  const bin = mode === 'fping' ? (o.fping_bin || '/usr/bin/fping') : (o.ping_bin || '/usr/bin/ping');
  if (!BIN_RE.test(bin)) throw new Error('ping binary path must be absolute');
  if (mode === 'fping') {
    for (let i = 0; i < ips.length; i += 64) {
      const batch = ips.slice(i, i + 64);
      const r = await exec(bin, fpingArgs(batch, timeout), { timeout: timeout * 3 + 5000 });
      // fping exits 0 (all alive) or 1 (some unreachable); 2+ = error (e.g. no permission for ICMP)
      if (r.code > 1 || r.error) throw Object.assign(new Error(`fping failed (exit ${r.code}${r.error ? ', ' + r.error : ''})`), { code: 'icmp_unavailable' });
      for (const line of r.stdout.split('\n')) { const n = ip4.parseIp(line.trim()); if (n !== null) alive.add(ip4.ipStr(n)); }
    }
    return alive;
  }
  for (const ip of ips) {
    const r = await exec(bin, pingArgs(ip, timeout), { timeout: timeout + 3000 });
    if (r.error) throw Object.assign(new Error(`ping failed (${r.error})`), { code: 'icmp_unavailable' });
    if (r.code === 0) alive.add(cleanIps([ip])[0]);
  }
  return alive;
}

function realConnect(ip, port, ms) {
  return new Promise((resolve) => {
    const s = net.connect({ host: ip, port });
    let done = false;
    const fin = (v) => { if (done) return; done = true; s.destroy(); resolve(v); };
    s.setTimeout(ms, () => fin('timeout'));
    s.once('connect', () => fin('open'));
    s.once('error', (e) => fin(e.code === 'ECONNREFUSED' ? 'closed' : e.code === 'ETIMEDOUT' ? 'timeout' : 'unreachable'));
  });
}

// tcp(ip, ports, {connect, timeout_ms}) → {alive, open[]}
async function tcp(ip, ports, o = {}) {
  const connect = o.connect || realConnect;
  const host = cleanIps([ip])[0];
  const open = []; let alive = false;
  for (const p of ports) {
    const r = await connect(host, p, o.timeout_ms || 800);
    if (r === 'open') { open.push(p); alive = true; } else if (r === 'closed') alive = true;
  }
  return { alive, open };
}

// parse /proc/net/arp → [{ip, mac, device}] (complete entries only)
function parseArp(text) {
  const out = [];
  for (const line of String(text || '').split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6) continue;
    const n = ip4.parseIp(f[0]);
    const flags = parseInt(f[2], 16);
    const mac = f[3].toLowerCase();
    if (n === null || !(flags & 0x2) || !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac) || mac === '00:00:00:00:00:00') continue;
    out.push({ ip: ip4.ipStr(n), mac, device: f[5] });
  }
  return out;
}
function arp(o = {}) {
  const read = o.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  let text = '';
  try { text = read(o.arp_path || '/proc/net/arp'); } catch (e) { throw Object.assign(new Error(`ARP table not readable (${e.code || 'error'})`), { code: 'arp_unavailable' }); }
  return parseArp(text);
}

module.exports = { icmp, tcp, arp, parseArp, fpingArgs, pingArgs, cleanIps, realExec, realConnect };
