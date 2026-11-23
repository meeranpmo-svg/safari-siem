// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Go test slice (go/, docs/GO-SLICE.md): the Go syslog collector + FortiGate parser must give the SAME event as the
// Node.js engine for every line, field for field (only the random event id differs), and hand a line back to Node.js
// - never guess - whenever the JavaScript router would have used something this slice has not ported.
// All log lines here are SYNTHETIC test data built by the generator below; no real device, address or person.
// Skipped when Go is not installed.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawnSync } = require('child_process');
const { createParser } = require('../engine/parse');
const { createFramer } = require('../engine/collect/syslog');

const GO_DIR = path.join(__dirname, '..', 'go');
const GO = fs.existsSync(path.join(GO_DIR, 'go.mod')) && ['/usr/local/go/bin/go', 'go'].find((g) => spawnSync(g, ['version']).status === 0);
const RTS = Date.UTC(2026, 9, 21, 9, 0, 0);
const BIN = path.join(os.tmpdir(), 'sentra-ingest-parity-' + process.pid);

function build() {
  const r = spawnSync(GO, ['build', '-o', BIN, './cmd/sentra-ingest'], { cwd: GO_DIR, encoding: 'utf8', env: { ...process.env, CGO_ENABLED: '0' } });
  assert.equal(r.status, 0, 'go build: ' + r.stderr);
}
function runGo(mode, reqs) {
  const r = spawnSync(BIN, [mode], { input: reqs.map((x) => JSON.stringify(x)).join('\n') + '\n', encoding: 'utf8', maxBuffer: 1 << 30 });
  assert.equal(r.status, 0, 'sentra-ingest ' + mode + ': ' + r.stderr);
  return r.stdout.trim().split('\n').map((l) => JSON.parse(l));
}

// deterministic generator
let seed = 20261021;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x80000000; };
const pick = (a) => a[Math.floor(rnd() * a.length)];

const TYPES = {
  traffic: [['forward', ['accept', 'deny', 'close', 'timeout', 'server-rst', 'client-rst', '', 'ip-conn', 'drop']], ['local', ['deny', 'accept']], ['sniffer', ['accept']]],
  utm: [['ips', ['dropped', 'detected', 'reset', 'pass']], ['anomaly', ['clear_session', 'detected']], ['virus', ['blocked', 'passthrough', 'monitored']],
    ['av', ['blocked']], ['webfilter', ['blocked', 'passthrough', 'allowed', '']], ['dns', ['block', 'pass', '']], ['app-ctrl', ['pass', 'block', '']],
    ['application', ['block']], ['dlp', ['block', 'log-only']], ['ssl', ['']]],
  event: [['vpn', ['tunnel-up', 'tunnel-down', 'ssl-login', 'ssl-login-fail', 'login', 'logout', 'negotiate', 'auth-fail', 'ssl-alert']],
    ['system', ['login', 'logout', 'edit', 'add', 'delete', 'set', 'config', 'update', '', 'move']], ['user', ['authentication', 'auth-logon', '']],
    ['ha', ['']], ['endpoint', ['']], ['wireless', ['']], ['router', ['']], ['sdwan', ['']]],
  anomaly: [['anomaly', ['detected']]], dns: [['dns-query', ['pass']]],
};
const LEVELS = ['notice', 'information', 'warning', 'alert', 'critical', 'error', 'emergency', 'debug', '', 'WARNING', ' notice ', 'constructor', 'toString'];
const IPS = ['10.1.2.3', '192.168.10.25', '172.16.0.9', '8.8.8.8', '2001:db8::1', '::ffff:10.0.0.7', '[2001:db8::2]', '01.2.3.4', '999.1.1.1', 'N/A', '', '-', 'fe80::1%port1', 'FE80::ABCD', '0.0.0.0'];
const USERS = ['', 'jdoe', 'CORP\\Jdoe', 'a.user@example.local', 'N/A', 'İlker', 'ΟΔΥΣΣΕΑΣ', 'admin', 'ahmad.alharbi', 'محمد'];
const MSGS = ['', 'Admin login successful', 'Administrator admin login failed from https(10.9.9.9)', 'Attribute configured', 'SSL VPN login fail',
  'Edit firewall.policy 7', 'tunnel statistics', 'Admin logout successful', 'User authentication failed', 'Login failed', 'shell "quoted" \\ text', 'رسالة'];
const URLS = ['/index.html', '/a?b=c&d=<e>', '', '/très/long/' + 'x'.repeat(40)];
const DATES = [['2026-10-21', '10:15:30'], ['2026-10-21', '10:15'], ['2026/10/21', '10:15:30'], ['2026-02-30', '25:61:61'], ['0099-01-01', '00:00:00'], ['2026-10-21', ''], ['', '10:00:00']];
const TZS = ['', '+0300', '+03:00', '-0500', 'Z', 'UTC', '+3'];
const ETIMES = ['', '1792578930123456789', '1792578930', '1792578930123', '1792578930123456', '12', 'abc', '9999999999999999999999999'];

function q(v) { return rnd() < 0.5 ? '"' + String(v).replace(/(["\\])/g, '\\$1') + '"' : (/[\s"']/.test(v) || v === '' ? '"' + String(v).replace(/(["\\])/g, '\\$1') + '"' : v); }
function fgBody() {
  const type = pick(Object.keys(TYPES));
  const [sub, acts] = pick(TYPES[type]);
  const act = pick(acts);
  const kv = [];
  const add = (k, v) => kv.push(k + '=' + q(v));
  const [d, t] = pick(DATES);
  if (rnd() < 0.9 && d) add('date', d);
  if (rnd() < 0.9 && t) add('time', t);
  if (rnd() < 0.5) add('devname', pick(['FG-HQ-01', 'FG-BR-02', 'N/A', 'fw edge']));
  if (rnd() < 0.8) add('devid', pick(['FG100FTK00000001', 'FGVM02TM00000002']));
  if (rnd() < 0.5) { const e = pick(ETIMES); if (e) add('eventtime', e); }
  if (rnd() < 0.4) { const z = pick(TZS); if (z) add('tz', z); }
  if (rnd() < 0.95) add('logid', pick(['0000000013', '0101039424', '0100032001', '1059028704', '0419016384', '0211008192']));
  if (rnd() < 0.95) add('type', type);
  if (rnd() < 0.9) add('subtype', sub);
  if (rnd() < 0.8) add('level', pick(LEVELS));
  if (rnd() < 0.5) add('vd', 'root');
  if (rnd() < 0.8) add('srcip', pick(IPS));
  if (rnd() < 0.6) add('srcport', pick(['51000', '0', '-1', '70000', '443abc', ' 80', '']));
  if (rnd() < 0.8) add('dstip', pick(IPS));
  if (rnd() < 0.6) add('dstport', pick(['53', '443', '3389', '99999999999999999999']));
  if (rnd() < 0.6) add('proto', pick(['6', '17', '1', '47', '255', 'TCP', ' 58 ']));
  if (act || rnd() < 0.2) add('action', act);
  if (rnd() < 0.5) add('policyid', pick(['0', '1', '15']));
  if (rnd() < 0.4) add('service', pick(['HTTPS', 'DNS', 'RDP', 'tcp/8443']));
  if (rnd() < 0.5) add(pick(['user', 'srcuser', 'unauthuser']), pick(USERS));
  if (rnd() < 0.5) add('msg', pick(MSGS));
  if (rnd() < 0.4) add('logdesc', pick(MSGS));
  if (rnd() < 0.3) add('status', pick(['success', 'failed', 'FAILURE', 'negotiate_error']));
  if (rnd() < 0.3) add('crlevel', pick(['high', 'critical', 'medium', 'low']));
  if (rnd() < 0.3) add('severity', pick(['high', 'critical', 'info', '']));
  if (rnd() < 0.3) add('attack', pick(['MS.SMB.Server.Trans.Peeking', 'Log4j2.Remote.Code.Execution']));
  if (rnd() < 0.3) add('virus', pick(['EICAR_TEST_FILE', 'W32/Agent.ABC!tr']));
  if (rnd() < 0.3) add('filename', pick(['eicar.com', 'invoice.pdf.exe']));
  if (rnd() < 0.3) add('filehash', pick(['ABCDEF0123', 'n/a']));
  if (rnd() < 0.2) add('analyticscksum', 'ffee00');
  if (rnd() < 0.4) add('hostname', pick(['www.example.test', 'Example.TEST', '']));
  if (rnd() < 0.4) add('url', pick(URLS));
  if (rnd() < 0.3) add('method', pick(['get', 'POST', 'straße']));
  if (rnd() < 0.3) add('qname', pick(['WWW.Example.Test', 'none', 'evil.example.']));
  if (rnd() < 0.3) add('remip', pick(IPS));
  if (rnd() < 0.2) add('tunnelip', '10.212.134.200');
  if (rnd() < 0.3) add('ui', pick(['https(10.9.9.9)', 'ssh(2001:db8::5)', 'GUI(bad)', 'console']));
  if (rnd() < 0.3) add('cfgpath', pick(['firewall.policy', 'system.admin', 'user.local']));
  if (rnd() < 0.2) add('app', pick(['HTTPS.BROWSER', 'Microsoft.Teams']));
  if (rnd() < 0.15) add('constructor', 'x');
  if (rnd() < 0.1) add('__proto__', 'y');
  if (rnd() < 0.15) { add('2', 'two'); add('10', 'ten'); add('01', 'zero-one'); }
  for (let i = kv.length - 1; i > 0; i--) { if (rnd() < 0.15) { const j = Math.floor(rnd() * (i + 1)); [kv[i], kv[j]] = [kv[j], kv[i]]; } }
  return kv.join(pick([' ', ' ', '  ', '\t']));
}
const HOSTS = ['FG-HQ-01', 'fw-branch', '10.0.0.1', ''];
function withHeader(body) {
  const pri = pick(['<189>', '<190>', '<13>', '<191>', '<192>', '']);
  switch (Math.floor(rnd() * 7)) {
    case 0: return pri + body;                                                     // FortiGate default: PRI only
    case 1: return pri + 'Oct 21 10:15:30 ' + pick(HOSTS) + ' ' + body;               // BSD
    case 2: return pri + 'Oct  2 2026 10:15:30.123 ' + pick(HOSTS) + ' ' + body;      // BSD with year
    case 3: return pri + '2026-10-21T10:15:30.5+03:00 ' + pick(HOSTS) + ' ' + body;   // ISO
    case 4: return '<189>1 2026-10-21T07:15:30.000Z ' + (pick(HOSTS) || '-') + ' - - - - ' + body; // RFC 5424
    case 5: return '<189>1 ' + pick(['2026-10-21T07:15:30Z', 'Oct-21', '-']) + ' fw app 123 ID47 [ex@32473 a="1" b="x\\"y"] ' + body;
    default: return body;
  }
}
function corpus(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    let l = withHeader(fgBody());
    const r = rnd();
    if (r < 0.03) l = l.replace(/msg="[^"]*"/, 'msg="' + 'm'.repeat(4100) + '😀' + '"');
    else if (r < 0.05) l += Array.from({ length: 230 }, (_, k) => ` k${k}=v${k}`).join('') + ' 7=seven 3=three';
    else if (r < 0.06) l += ' ' + 'x'.repeat(130) + '=long-key';
    else if (r < 0.08) l = l.replace(/ /, '\u00a0');
    else if (r < 0.10) l = 'not a fortigate line at all ' + l.slice(0, 20);
    else if (r < 0.11) l = 'CEF:0|Fortinet|FortiGate|7.2|13|traffic|5|src=10.0.0.1';
    else if (r < 0.12) l = '{"logid":"1","type":"traffic"}';
    out.push(l);
  }
  return out;
}

function metaFor(i) {
  return { collector: pick(['syslog-udp', 'syslog-tcp', 'syslog-tls']), src_id: 'fw-' + (i % 3), src_type: 'fortigate',
    peer_ip: pick(['10.0.0.1', '::ffff:10.0.0.2', '2001:DB8::9', 'not-an-ip']), rts: RTS + i, tz_offset_min: pick([0, 180, -300]), site: pick(['', 'HQ', 'Riyadh-DC']) };
}

test('Go FortiGate parser = Node.js parser, field for field, on 6,000 synthetic lines', { skip: !GO && 'Go or the go/ folder not present' }, () => {
  build();
  try {
    const lines = corpus(6000);
    const metas = lines.map((_, i) => metaFor(i));
    const goOut = runGo('parse', lines.map((line, i) => ({ line, meta: metas[i] })));
    assert.equal(goOut.length, lines.length);
    const P = createParser({});
    let same = 0, handed = 0;
    const reasons = {};
    for (let i = 0; i < lines.length; i++) {
      const before = P.stats().by_parser.fortigate || 0;
      const js = JSON.parse(JSON.stringify(P.parse(lines[i], metas[i])));
      const usedFG = (P.stats().by_parser.fortigate || 0) > before;
      const g = goOut[i];
      if (g.handback) {
        handed++;
        reasons[g.handback] = (reasons[g.handback] || 0) + 1;
        // a hand-back is right only when JavaScript did NOT end on the FortiGate parser (or needed Date.parse)
        if (/Date\.parse/.test(g.handback)) continue;
        assert.ok(!usedFG, `line ${i}: Go handed back (${g.handback}) but Node.js parsed it as FortiGate:\n${lines[i]}`);
        continue;
      }
      assert.ok(usedFG, `line ${i}: Go parsed it but Node.js did not use the FortiGate parser:\n${lines[i]}`);
      delete js.id; delete g.event.id;
      assert.deepEqual(g.event, js, `line ${i}:\n${lines[i]}`);
      same++;
    }
    console.log(`  identical: ${same}, handed back to Node.js: ${handed}`, reasons);
    assert.ok(same > 4500, 'most lines are decided in Go: ' + same);
  } finally { fs.rmSync(BIN, { force: true }); }
});

test('Go framer + UTF-8 decoder = createFramer + Buffer.toString (LF, octet counting, oversized, split chunks, bad bytes)', { skip: !GO && 'Go or the go/ folder not present' }, () => {
  build();
  try {
    const cases = [];
    const pieces = ['<189>date=2026-10-21 logid=1 type=traffic\n', '57 <189>1 2026-10-21T07:15:30Z h a p m - message here x\n', 'abc\r\n', '\n\n',
      Buffer.from([0x3c, 0x31, 0x3e, 0xe2, 0x82, 0x20, 0xff, 0xf0, 0x9f, 0x98, 0x80, 0xed, 0xa0, 0x80, 0x0a]).toString('latin1'),
      'x'.repeat(300) + '\n', '12 <13>short', '999999 <1>huge', '5 <1>ab', 'no newline at end'];
    for (let c = 0; c < 400; c++) {
      let s = '';
      const k = 1 + Math.floor(rnd() * 8);
      for (let j = 0; j < k; j++) s += pick(pieces);
      const buf = Buffer.from(s, 'latin1');
      const chunks = [];
      for (let o = 0; o < buf.length;) { const n = 1 + Math.floor(rnd() * 40); chunks.push(buf.subarray(o, o + n)); o += n; }
      cases.push({ max_line: pick([64, 128, 256, 65536]), chunks });
    }
    const goOut = runGo('frames', cases.map((c) => ({ max_line: c.max_line, chunks: c.chunks.map((b) => b.toString('base64')) })));
    cases.forEach((c, i) => {
      const frames = [];
      const f = createFramer(c.max_line, (b, t) => frames.push({ text: b.toString('utf8'), truncated: t }));
      for (const ch of c.chunks) f.push(ch);
      f.end();
      assert.deepEqual(goOut[i].frames, frames, 'case ' + i);
      assert.equal(goOut[i].mode, f.mode() || '', 'mode, case ' + i);
    });
  } finally { fs.rmSync(BIN, { force: true }); }
});
