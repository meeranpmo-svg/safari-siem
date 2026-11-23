// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Syslog framing (LF + RFC 6587 octet counting), live UDP/TCP listeners, source mapping, pipeline, config.
// All lines are synthetic test data.
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const dgram = require('node:dgram');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createFramer, createSyslog } = require('../engine/collect/syslog');
const { createSourceMap } = require('../engine/collect/sources');
const { createParser } = require('../engine/parse');
const { createPipeline } = require('../engine/pipeline');
const { loadConfig, DEFAULTS } = require('../engine/config');

const waitFor = async (fn, ms = 3000) => { const t = Date.now(); while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 10)); } };

function frames(chunks, max = 100) {
  const out = [];
  const f = createFramer(max, (b, t) => out.push([b.toString(), t]));
  for (const c of chunks) f.push(Buffer.from(c));
  f.end();
  return out;
}

test('framer: LF framing across chunk boundaries, CRLF, blank lines', () => {
  assert.deepEqual(frames(['<13>a\n<13>b', 'c\r\n\n<13>d\n']), [['<13>a', false], ['<13>bc', false], ['<13>d', false]]);
  assert.deepEqual(frames(['no newline at end']), [['no newline at end', false]]);
});

test('framer: RFC 6587 octet counting incl. split length prefix and embedded newlines', () => {
  const m1 = '<13>1 - h a - - - x\ny';
  const m2 = '<14>hello';
  const s = `${Buffer.byteLength(m1)} ${m1}${Buffer.byteLength(m2)} ${m2}`;
  assert.deepEqual(frames([s]), [[m1, false], [m2, false]]);
  // split at every position
  for (let i = 1; i < s.length; i++) assert.deepEqual(frames([s.slice(0, i), s.slice(i)]), [[m1, false], [m2, false]], 'split at ' + i);
});

test('framer: LF lines starting with digits are not mistaken for octet counts', () => {
  assert.deepEqual(frames(['2024-05-01 test line\n12 apples\n']), [['2024-05-01 test line', false], ['12 apples', false]]);
});

test('framer: oversized frames are truncated to max_line, stream stays in sync', () => {
  const long = 'A'.repeat(250);
  let out = frames([`<13>${long}\n<13>next\n`], 100);
  assert.equal(out.length, 2);
  assert.equal(out[0][0].length, 100);
  assert.equal(out[0][1], true);
  assert.deepEqual(out[1], ['<13>next', false]);
  const big = '<13>' + 'B'.repeat(300);
  out = frames([`${big.length} ${big}9 <13>small`], 100);
  assert.equal(out[0][0].length, 100);
  assert.equal(out[0][1], true);
  assert.deepEqual(out[1], ['<13>small', false]);
  // oversized LF line delivered in many small chunks
  const chunks = [];
  for (let i = 0; i < 50; i++) chunks.push('C'.repeat(10));
  chunks.push('\n<13>after\n');
  out = frames(chunks, 100);
  assert.equal(out[0][1], true);
  assert.deepEqual(out.at(-1), ['<13>after', false]);
});

test('source map: exact IP beats CIDR, CIDR order, IPv4-mapped peers, defaults per collector', () => {
  const m = createSourceMap([
    { id: 'net-a', type: 'fortigate', match: { cidr: '10.0.0.0/8' } },
    { id: 'host-b', type: 'linux', match: { ip: ['10.1.1.1', '10.1.1.2'] } },
    { id: 'v6', type: 'cisco', match: { cidr: '2001:db8::/32' } },
  ], { 'syslog-udp': { id: 'udp-default', type: 'syslog' } });
  assert.equal(m.lookup('10.1.1.1', 'syslog-udp').id, 'host-b');
  assert.equal(m.lookup('::ffff:10.1.1.2', 'syslog-udp').id, 'host-b');
  assert.equal(m.lookup('10.9.9.9', 'syslog-tcp').id, 'net-a');
  assert.equal(m.lookup('2001:db8::5', 'syslog-tcp').id, 'v6');
  assert.equal(m.lookup('192.0.2.1', 'syslog-udp').id, 'udp-default');
  assert.equal(m.lookup('192.0.2.1', 'syslog-tcp').id, 'syslog-tcp');
});

test('pipeline: stages in order, throwing / rejecting stage never drops the event, timing stats', async () => {
  const errs = [];
  const log = { every: (k, ms, lvl, msg, f) => errs.push(f), error() {} };
  const p = createPipeline({ log });
  const seen = [];
  p.use((ev) => { ev.a = 1; seen.push('a'); }, 'first');
  p.use(() => { throw new Error('boom'); }, 'bad');
  p.use(async () => { throw new Error('async boom'); }, 'bad-async');
  p.use((ev) => { seen.push('c:' + ev.a); }, 'last');
  for (let i = 0; i < 3; i++) p.emit({});
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(seen, ['a', 'c:1', 'a', 'c:1', 'a', 'c:1']);
  const st = p.stats();
  assert.equal(st.events, 3);
  assert.deepEqual(st.stages.map((s) => [s.name, s.calls, s.errors]), [['first', 3, 0], ['bad', 3, 3], ['bad-async', 3, 3], ['last', 3, 0]]);
  assert.equal(st.stages[1].last_error, 'boom');
  assert.ok(errs.length >= 2);
  assert.ok(st.eps_10s >= 0);
});

test('syslog listeners: UDP + TCP (LF and octet-counted) → parser → pipeline, per-peer stats, source mapping', async () => {
  const cfg = { syslog: { ...DEFAULTS.syslog, host: '127.0.0.1', udp: { enabled: true, port: 0 }, tcp: { enabled: true, port: 0 }, tls: { enabled: false }, tz_offset_min: 0 },
    sources: [{ id: 'test-lo', type: 'linux', match: { ip: '127.0.0.1' } }] };
  const events = [];
  const pipeline = createPipeline();
  pipeline.use((ev) => events.push(ev));
  const sys = createSyslog({ config: cfg, parser: createParser(), pipeline });
  await sys.start();
  try {
    const { udp, tcp } = sys.stats().listeners;
    const u = dgram.createSocket('udp4');
    await new Promise((r) => u.send('<38>May  1 10:00:00 test-host-01 sshd[1]: Accepted password for alice from 192.0.2.1 port 1 ssh2\n', udp.port, '127.0.0.1', r));
    u.close();
    const sock = net.connect(tcp.port, '127.0.0.1');
    await new Promise((r) => sock.on('connect', r));
    const m = '<38>May  1 10:00:01 test-host-01 sshd[1]: Failed password for bob from 192.0.2.2 port 2 ssh2';
    sock.write(`${m.length} ${m}`);
    sock.write(`${m.length} ${m}`);
    const sock2 = net.connect(tcp.port, '127.0.0.1');
    sock2.write('<38>May  1 10:00:02 test-host-01 sudo:    carol : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n');
    await waitFor(() => events.length === 4);
    sock.end(); sock2.end();
    const byCollector = events.reduce((a, e) => ((a[e.collector] = (a[e.collector] || 0) + 1), a), {});
    assert.deepEqual(byCollector, { 'syslog-udp': 1, 'syslog-tcp': 3 });
    assert.ok(events.every((e) => e.src_id === 'test-lo' && e.src_type === 'linux' && e.host_ip === '127.0.0.1'));
    assert.deepEqual(events.map((e) => e.action).sort(), ['logon', 'logon-failed', 'logon-failed', 'sudo']);
    const st = sys.stats();
    assert.equal(st.messages, 4);
    assert.ok(st.peers.some((p) => p.collector === 'syslog-tcp' && p.messages === 3));
  } finally { await sys.stop(); }
});

test('config: defaults, file merge, secrets non-enumerable, validation, env override', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-siem-cfg-'));
  const cfgPath = path.join(dir, 'config.json');
  fs.writeFileSync(cfgPath, JSON.stringify({ retention_days: 90, syslog: { udp: { port: 1514 } }, sources: [{ id: 'fw-test-01', type: 'fortigate', match: { cidr: '10.0.0.0/8' } }] }));
  fs.writeFileSync(path.join(dir, 'secrets.json'), JSON.stringify({ clickhouse: { user: 'sentra_siem', password: 'synthetic-secret' }, ingest_tokens: { a: 'b' } }));
  const cfg = loadConfig({ configPath: cfgPath });
  assert.equal(cfg.retention_days, 90);
  assert.equal(cfg.syslog.udp.port, 1514);
  assert.equal(cfg.syslog.tcp.port, 5514);
  assert.equal(cfg.api.port, 9120);
  assert.equal(cfg.clickhouse.password, 'synthetic-secret');
  assert.equal(cfg.secrets.ingest_tokens.a, 'b');
  assert.doesNotMatch(JSON.stringify(cfg), /synthetic-secret|ingest_tokens/);
  const prev = process.env.SENTRA_SIEM_CONFIG;
  process.env.SENTRA_SIEM_CONFIG = cfgPath;
  try { assert.equal(loadConfig().retention_days, 90); } finally { if (prev === undefined) delete process.env.SENTRA_SIEM_CONFIG; else process.env.SENTRA_SIEM_CONFIG = prev; }
  const missing = loadConfig({ configPath: path.join(dir, 'nope.json') });
  assert.equal(missing.data_dir, '/var/lib/sentra-siem');
  fs.writeFileSync(cfgPath, JSON.stringify({ sources: [{ id: 'bad id!', type: 'x', match: { cidr: '10.0.0.0/40' } }] }));
  assert.throws(() => loadConfig({ configPath: cfgPath }), /sources\[0\]\.id invalid.*cidr invalid/);
  fs.writeFileSync(cfgPath, '{ not json');
  assert.throws(() => loadConfig({ configPath: cfgPath }), /invalid JSON/);
});

test('syslog TCP: per-peer connection cap and idle timeout free the slots', async () => {
  const cfg = { syslog: { ...DEFAULTS.syslog, host: '127.0.0.1', udp: { enabled: false }, tcp: { enabled: true, port: 0, max_connections: 100, max_connections_per_peer: 3, idle_timeout_s: 0.3 }, tls: { enabled: false }, tz_offset_min: 0 }, sources: [] };
  const sys = createSyslog({ config: cfg, parser: createParser(), pipeline: createPipeline() });
  await sys.start();
  const socks = [];
  try {
    const { tcp } = sys.stats().listeners;
    const open = () => new Promise((resolve) => {
      const s = net.connect(tcp.port, '127.0.0.1');
      socks.push(s);
      s.on('error', () => {});
      s.on('connect', () => resolve(s));
    });
    const closed = (s) => new Promise((resolve) => (s.destroyed ? resolve() : s.on('close', resolve)));
    for (let i = 0; i < 3; i++) await open();
    const fourth = await open();
    await closed(fourth); // over the per-peer cap: the server closes it straight away
    assert.ok(socks.slice(0, 3).every((s) => !s.destroyed));
    await Promise.all(socks.slice(0, 3).map(closed)); // silent sockets are closed by the idle timeout
    const again = await open(); // and the peer can connect again
    assert.equal(again.destroyed, false);
  } finally {
    for (const s of socks) s.destroy();
    await sys.stop();
  }
});

test('syslog: unregistered senders are tagged by default and can be dropped', async () => {
  const line = '<38>May  1 10:00:00 test-host-01 sshd[1]: Accepted password for alice from 192.0.2.1 port 1 ssh2\n';
  async function run(mode, sources) {
    const cfg = { syslog: { ...DEFAULTS.syslog, host: '127.0.0.1', udp: { enabled: false }, tcp: { enabled: true, port: 0 }, tls: { enabled: false }, tz_offset_min: 0, unknown_sources: mode }, sources };
    const events = [];
    const pipeline = createPipeline();
    pipeline.use((ev) => events.push(ev));
    const sys = createSyslog({ config: cfg, parser: createParser(), pipeline });
    await sys.start();
    try {
      const s = net.connect(sys.stats().listeners.tcp.port, '127.0.0.1');
      await new Promise((r) => s.on('connect', r));
      s.end(line);
      await new Promise((r) => s.on('close', r));
      await new Promise((r) => setTimeout(r, 100));
      return { events, stats: sys.stats() };
    } finally { await sys.stop(); }
  }
  let r = await run('tag', []);
  assert.equal(r.events.length, 1);
  assert.ok(r.events[0].tags.includes('unregistered-source'));
  r = await run('drop', []);
  assert.equal(r.events.length, 0);
  assert.equal(r.stats.dropped_unregistered, 1);
  r = await run('drop', [{ id: 'test-lo', type: 'linux', match: { ip: '127.0.0.1' } }]); // registered: kept, not tagged
  assert.equal(r.events.length, 1);
  assert.ok(!r.events[0].tags.includes('unregistered-source'));
});
