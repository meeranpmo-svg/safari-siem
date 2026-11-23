#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Speed of the Go test slice against the Node.js engine on the same SYNTHETIC FortiGate lines (go/, docs/GO-SLICE.md).
//   node tools/go-slice-bench.js [--lines 300000]
// 1. parse + serialise only (the CPU work per line): Node.js on one thread, Go on one core and on every core.
// 2. end to end over TCP: the same lines sent to each collector (Node.js createSyslog, Go sentra-ingest listen) on
//    localhost; time until the last event is parsed, and the resident memory of each process.
// Nothing is written anywhere but a temporary folder.
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { spawnSync, spawn } = require('child_process');

const N = Number((process.argv.find((a, i) => process.argv[i - 1] === '--lines')) || 300000);
const ROOT = path.join(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-go-bench-'));
const BIN = path.join(TMP, 'sentra-ingest');
const GO = ['/usr/local/go/bin/go', 'go'].find((g) => spawnSync(g, ['version']).status === 0);
if (!GO) { console.error('Go is not installed'); process.exit(1); }

// realistic FortiOS 7 lines (synthetic): traffic most, then utm and event, as on a perimeter firewall
let seed = 7;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x80000000; };
const pick = (a) => a[Math.floor(rnd() * a.length)];
const ip = () => `10.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}.${1 + Math.floor(rnd() * 250)}`;
function line(i) {
  const t = `date=2026-10-21 time=10:${String(i % 60).padStart(2, '0')}:${String((i * 7) % 60).padStart(2, '0')} devname="FG-SYNTH-01" devid="FGT00SYNTHETIC00" eventtime=${1792578930000000000 + i * 1000} tz="+0300"`;
  const r = rnd();
  if (r < 0.75) return `<189>${t} logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=${ip()} srcport=${1024 + Math.floor(rnd() * 60000)} srcintf="port1" srcintfrole="lan" dstip=${ip()} dstport=${pick([443, 53, 80, 3389, 445])} dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Saudi Arabia" sessionid=${100000 + i} proto=6 action="${pick(['accept', 'close', 'deny', 'timeout'])}" policyid=${pick([0, 5, 12])} policytype="policy" service="${pick(['HTTPS', 'DNS', 'RDP', 'SMB'])}" trandisp="snat" duration=${Math.floor(rnd() * 300)} sentbyte=${Math.floor(rnd() * 1e6)} rcvdbyte=${Math.floor(rnd() * 1e6)} sentpkt=12 rcvdpkt=10 appcat="unscanned"`;
  if (r < 0.85) return `<185>${t} logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" severity="${pick(['high', 'critical', 'medium'])}" srcip=${ip()} dstip=${ip()} srcport=51000 dstport=445 proto=6 action="dropped" attack="MS.SMB.Server.SYNTHETIC" attackid=12345 crlevel="high" msg="synthetic test signature"`;
  if (r < 0.93) return `<189>${t} logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root" policyid=7 srcip=${ip()} srcport=52000 dstip=${ip()} dstport=443 proto=6 action="blocked" hostname="blocked.example.test" url="/path?q=1" method="get" cat=26 catdesc="Malicious Websites" user="synthetic.user"`;
  return `<189>${t} logid="0101039424" type="event" subtype="vpn" level="${pick(['information', 'alert'])}" vd="root" logdesc="SSL VPN tunnel ${pick(['up', 'login fail'])}" action="${pick(['tunnel-up', 'ssl-login-fail', 'tunnel-down'])}" tunneltype="ssl-web" remip=${ip()} user="synthetic.user" group="vpn-users" reason="${pick(['login successfully', 'sslvpn_login_permission_denied'])}" msg="SSL VPN event"`;
}
const lines = Array.from({ length: 5000 }, (_, i) => line(i));
fs.writeFileSync(path.join(TMP, 'lines.txt'), lines.join('\n') + '\n');

const out = { cpu: os.cpus()[0].model, cores: os.cpus().length, lines: N };
let r = spawnSync(GO, ['build', '-trimpath', '-o', BIN, './cmd/sentra-ingest'], { cwd: path.join(ROOT, 'go'), encoding: 'utf8', env: { ...process.env, CGO_ENABLED: '0' } });
if (r.status !== 0) { console.error(r.stderr); process.exit(1); }
out.go_binary_mb = Math.round(fs.statSync(BIN).size / 1e5) / 10;

// 1. parse + serialise
{
  const { createParser } = require('../engine/parse');
  const P = createParser({});
  for (let i = 0; i < 20000; i++) JSON.stringify(P.parse(lines[i % lines.length], { collector: 'syslog-udp', src_id: 'fw1', src_type: 'fortigate', peer_ip: '10.0.0.1', rts: 1792605600000 })); // warm-up
  const t0 = process.hrtime.bigint();
  let bytes = 0;
  for (let i = 0; i < N; i++) bytes += JSON.stringify(P.parse(lines[i % lines.length], { collector: 'syslog-udp', src_id: 'fw1', src_type: 'fortigate', peer_ip: '10.0.0.1', rts: 1792605600000 })).length;
  const s = Number(process.hrtime.bigint() - t0) / 1e9;
  out.parse_node_1_thread = Math.round(N / s);
  const goRun = (w) => JSON.parse(spawnSync(BIN, ['bench', '-f', path.join(TMP, 'lines.txt'), '-n', String(N), '-workers', String(w)], { encoding: 'utf8' }).stdout);
  out.parse_go_1_core = Math.round(goRun(1).lines_per_sec);
  out.parse_go_all_cores = Math.round(goRun(0).lines_per_sec);
}

// 2. end to end over TCP
function sendAll(port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () => {
      let i = 0;
      const pump = () => { while (i < N) { const ok = s.write(lines[i % lines.length] + '\n'); i++; if (!ok) return s.once('drain', pump); } s.end(); resolve(); };
      pump();
    });
    s.on('error', reject);
  });
}
function rssOf(pid) { try { return Math.round(Number(/VmHWM:\s+(\d+)/.exec(fs.readFileSync(`/proc/${pid}/status`, 'utf8'))[1]) / 1024); } catch { return null; } }

async function e2eNode() {
  const script = `
    const { createSyslog } = require(${JSON.stringify(path.join(ROOT, 'engine/collect/syslog'))});
    const { createParser } = require(${JSON.stringify(path.join(ROOT, 'engine/parse'))});
    let n = 0, t0 = 0; const N = ${N};
    const cfg = { syslog: { host: '127.0.0.1', udp: { enabled: false }, tcp: { port: 0 }, unknown_sources: 'accept', default_sources: { 'syslog-tcp': { id: 'fw1', type: 'fortigate' } } }, sources: [] };
    const sl = createSyslog({ config: cfg, parser: createParser({}), pipeline: { emit(ev) { JSON.stringify(ev); if (!t0) t0 = Date.now(); if (++n === N) { process.stdout.write(JSON.stringify({ ms: Date.now() - t0 }) + '\\n'); process.exit(0); } } } });
    sl.start().then(() => process.stdout.write('PORT ' + sl.stats().listeners.tcp.port + '\\n'));`;
  return runE2E(spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'inherit'] }), 'stdout');
}
async function e2eGo() {
  const cfg = path.join(TMP, 'syslog.json');
  fs.writeFileSync(cfg, JSON.stringify({ syslog: { host: '127.0.0.1', udp: { enabled: false }, tcp: { port: 0 }, unknown_sources: 'accept', default_sources: { 'syslog-tcp': { id: 'fw1', type: 'fortigate' } } }, sources: [] }));
  const p = spawn(BIN, ['listen', '-config', cfg, '-out', '', '-stats-every', '100ms'], { stdio: ['ignore', 'ignore', 'pipe'] });
  return runE2E(p, 'stderr');
}
function runE2E(p, stream) {
  return new Promise((resolve, reject) => {
    let buf = '', t0 = 0, peak = 0, sent = false;
    const iv = setInterval(() => { const m = rssOf(p.pid); if (m) peak = Math.max(peak, m); }, 50);
    p[stream].on('data', async (d) => {
      buf += d.toString();
      let m;
      if (!sent && ((m = /PORT (\d+)/.exec(buf)) || (m = /LISTENING .*"tcp":"127\.0\.0\.1:(\d+)"/.exec(buf)))) { sent = true; t0 = Date.now(); sendAll(Number(m[1])).catch(reject); }
      if (/"ms":/.test(buf)) { clearInterval(iv); resolve({ seconds: (Date.now() - t0) / 1000, peak_mb: peak }); p.kill(); }
      const st = buf.match(/STATS (\{.*\})/g);
      if (st) { const last = JSON.parse(st[st.length - 1].slice(6)); if (last.parser.events + last.parser.handbacks >= N) { clearInterval(iv); resolve({ seconds: (Date.now() - t0) / 1000, peak_mb: Math.max(peak, rssOf(p.pid) || 0) }); p.kill(); } buf = buf.slice(buf.lastIndexOf('STATS')); }
    });
    p.on('error', reject);
  });
}

(async () => {
  const node = await e2eNode();
  const go = await e2eGo();
  out.tcp_node = { lines_per_sec: Math.round(N / node.seconds), peak_memory_mb: node.peak_mb };
  out.tcp_go = { lines_per_sec: Math.round(N / go.seconds), peak_memory_mb: go.peak_mb };
  out.speedup = { parse_1_core: +(out.parse_go_1_core / out.parse_node_1_thread).toFixed(1), parse_all_cores: +(out.parse_go_all_cores / out.parse_node_1_thread).toFixed(1),
    tcp_end_to_end: +(out.tcp_go.lines_per_sec / out.tcp_node.lines_per_sec).toFixed(1) };
  console.log(JSON.stringify(out, null, 2));
  fs.rmSync(TMP, { recursive: true, force: true });
})().catch((e) => { console.error(e); process.exit(1); });
