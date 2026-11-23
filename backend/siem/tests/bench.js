#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Throughput benchmark: parse + pipeline on the synthetic fixture mix, no ClickHouse (writer stubbed).
//   node tests/bench.js [--events 200000]
// Stages measured: parse only; parse + enrich + source stats + tail; + real writer (row serialisation, sha256 chain)
// against a stub ClickHouse client; + the detection engine with the built-in rule pack (when engine/detect exists).
const fs = require('node:fs');
const path = require('node:path');
const { createParser } = require('../engine/parse');
const { createPipeline } = require('../engine/pipeline');
const { createEnricher } = require('../engine/enrich');
const { createSourceTracker } = require('../engine/collect/tracker');
const { createTail } = require('../engine/api/tail');
const { createWriter } = require('../engine/store/writer');

const argv = process.argv.slice(2);
const N = Number(argv[argv.indexOf('--events') + 1]) || 200000;
const lines = fs.readFileSync(path.join(__dirname, 'fixtures', 'synthetic-mixed.log'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
const metas = [{ collector: 'syslog-tcp', src_id: 'bench', src_type: 'syslog', peer_ip: '10.0.0.1', tz_offset_min: 180 }];

function run(label, fn) {
  global.gc && global.gc();
  const t0 = process.hrtime.bigint();
  fn();
  const s = Number(process.hrtime.bigint() - t0) / 1e9;
  const eps = Math.round(N / s);
  console.log(`${label.padEnd(58)} ${String(eps).padStart(8)} events/s  (${N} events, ${s.toFixed(2)} s)`);
  return eps;
}

async function main() {
  const parser = createParser();
  // warm-up
  for (let i = 0; i < 20000; i++) parser.parse(lines[i % lines.length], { ...metas[0], rts: Date.now() });
  const results = {};
  results.parse = run('parse only (router + format parsers + normalise)', () => {
    for (let i = 0; i < N; i++) parser.parse(lines[i % lines.length], { ...metas[0], rts: Date.now() });
  });

  const cfg = { enrich: { assets: [], admin_users: [] } };
  const p1 = createPipeline();
  p1.use(createEnricher({ config: cfg }), 'enrich');
  p1.use(createSourceTracker().stage, 'sources');
  p1.use(createTail({}).stage, 'tail');
  results.pipeline = run('parse + pipeline (enrich, source stats, tail)', () => {
    for (let i = 0; i < N; i++) p1.emit(parser.parse(lines[i % lines.length], { ...metas[0], rts: Date.now() }));
  });

  // stub ClickHouse: accepts everything instantly (measures serialisation + hashing, not the network)
  const stubCH = { insertNDJSON: async () => {}, insertRows: async () => {}, query: async () => [] };
  const writer = createWriter({ ch: stubCH, node: 'bench', batchSize: 5000, flushMs: 1000, statsFlushMs: 600000 });
  const p2 = createPipeline();
  p2.use(createEnricher({ config: cfg }), 'enrich');
  p2.use(createSourceTracker().stage, 'sources');
  p2.use((ev) => writer.push(ev), 'store');
  p2.use(createTail({}).stage, 'tail');
  results.writer = run('parse + pipeline + writer (JSONEachRow rows, sha256 chain)', () => {
    for (let i = 0; i < N; i++) p2.emit(parser.parse(lines[i % lines.length], { ...metas[0], rts: Date.now() }));
  });
  await writer.close();

  const detPath = path.join(__dirname, '..', 'engine', 'detect', 'engine.js');
  if (fs.existsSync(detPath)) {
    const { createDetector } = require(detPath);
    const { loadBuiltinRules } = require(path.join(__dirname, '..', 'engine', 'detect', 'ruleset.js'));
    let alerts = 0;
    const rules = loadBuiltinRules();
    const det = createDetector({ rules, onAlert: () => { alerts++; }, now: Date.now, log: { info() {}, warn() {}, error() {}, debug() {} } });
    const writer2 = createWriter({ ch: stubCH, node: 'bench', batchSize: 5000, flushMs: 1000, statsFlushMs: 600000 });
    const p3 = createPipeline();
    p3.use(createEnricher({ config: cfg }), 'enrich');
    p3.use(createSourceTracker().stage, 'sources');
    p3.use((ev) => { if (ev.action !== 'agent-heartbeat') det.onEvent(ev); }, 'detect');
    p3.use((ev) => writer2.push(ev), 'store');
    p3.use(createTail({}).stage, 'tail');
    results.full = run(`full: + detection (${det.stats().rules_loaded} built-in rules)`, () => {
      for (let i = 0; i < N; i++) p3.emit(parser.parse(lines[i % lines.length], { ...metas[0], rts: Date.now() }));
    });
    await writer2.close();
    const st = p3.stats().stages.map((s) => `${s.name} ${s.avg_us} µs`).join(', ');
    console.log(`stage averages: ${st}; alerts raised: ${alerts}`);
  }
  console.log(`node ${process.version}, ${require('node:os').cpus().length} CPUs (${require('node:os').cpus()[0].model.trim()}), single thread, load avg ${require('node:os').loadavg().map((x) => x.toFixed(1)).join('/')}`);
  // calibration: how busy/slow is this machine right now? (≈0.8–1.5 µs per round-trip on an idle modern x86 core)
  const o = { a: 1, b: 'hello world', c: [1, 2, 3], d: { e: 'x' } };
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < 200000; i++) JSON.parse(JSON.stringify(o));
  console.log(`calibration: JSON round-trip ${(Number(process.hrtime.bigint() - t0) / 1e3 / 200000).toFixed(2)} µs`);
  return results;
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { main };
