// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Private AI Server (engine/private-ai.js): the Prometheus reader (node_exporter, NVIDIA DCGM, vLLM), the forecast and the
// Wilson interval on their own; then the routes against a SYNTHETIC gateway (OpenAI-compatible + Ollama /api/ps) and two
// synthetic exporters: nothing measured before the AI Engine is set, the poll, the AI calls through the switch (answered and
// failed) with latency and failure rate, a hot GPU and a down gateway as named deductions with their action, the outage, the
// four-eyes model change (only a model the gateway serves; the proposer cannot decide; a reject needs a note; approve applies it
// through the AI Engine), validation errors naming the field, the roles (viewer refused, operator reads, admin changes, an AI
// identity refused) and the audit records. Synthetic data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const B = require('../engine/ai-backend');
const { parseProm, readMetrics, forecast, wilson } = require('../engine/private-ai');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'amal.syn', role: 'admin' }, BOT = { user: 'ai:engine-bot', role: 'admin' };
const NODE = (idle, total) => [
  '# HELP node_cpu_seconds_total synthetic', 'node_cpu_seconds_total{cpu="0",mode="idle"} ' + idle, 'node_cpu_seconds_total{cpu="0",mode="user"} ' + (total - idle),
  'node_memory_MemTotal_bytes 64000000000', 'node_memory_MemAvailable_bytes 16000000000',
  'node_filesystem_size_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 1000000000000', 'node_filesystem_avail_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 300000000000',
  'node_filesystem_size_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 9000000000000', 'node_load1 2.5', 'node_boot_time_seconds 1000', 'node_time_seconds 361000'].join('\n');
const DCGM = (temp) => ['DCGM_FI_DEV_GPU_UTIL{gpu="0",modelName="Synthetic GPU 48GB"} 71', 'DCGM_FI_DEV_GPU_TEMP{gpu="0"} ' + temp, 'DCGM_FI_DEV_POWER_USAGE{gpu="0"} 250.5',
  'DCGM_FI_DEV_FB_USED{gpu="0",modelName="Synthetic GPU 48GB"} 30720', 'DCGM_FI_DEV_FB_FREE{gpu="0"} 18432'].join('\n');

test('the readers: Prometheus text, CPU from two reads, GPU, vLLM; the forecast; the Wilson interval', () => {
  const a = readMetrics(parseProm(NODE(100, 200)), null); assert.equal(a.host.cpu_pct, undefined, 'one read of a counter is not a CPU figure');
  const b = readMetrics(parseProm(NODE(150, 400) + '\n' + DCGM(66)), Object.assign({ at: 1 }, a.counters));
  assert.equal(b.host.cpu_pct, 75, '50 idle of 200 seconds'); assert.equal(b.host.mem_pct, 75); assert.equal(b.host.disk_pct, 70, 'the root file system, not the tmpfs'); assert.equal(b.host.uptime_h, 100);
  assert.deepEqual([b.gpus[0].util, b.gpus[0].temp, b.gpus[0].mem_total_gb, b.gpus[0].mem_pct, b.gpus[0].name], [71, 66, 48, 62.5, 'Synthetic GPU 48GB']);
  const v = readMetrics(parseProm('vllm:num_requests_running{model_name="m"} 3\nvllm:num_requests_waiting{model_name="m"} 2\nvllm:gpu_cache_usage_perc{model_name="m"} 0.97\n# a comment\ngarbage line'), null);
  assert.deepEqual(v.llm, { server: 'vLLM', running: 3, waiting: 2, kv_pct: 97 });
  const pts = Array.from({ length: 30 }, (_, i) => ({ t: i, y: 60 + i * 0.5 }));   // +0.5 a point an hour
  const f = forecast(pts, 90); assert.equal(f.per_day, 12); assert.equal(f.hours_to, 31, '74.5 now, 15.5 points to go at 0.5 an hour');
  assert.match(forecast(pts.slice(0, 5), 90).note, /needs 24 hours/);
  const w = wilson(1, 10); assert.equal(w.pct, 10); assert.ok(w.low < 10 && w.high > 30, 'one failure in ten is not a precise 10 %'); assert.equal(wilson(0, 0), null);
});

test('routes: nothing measured until set, the poll, AI calls, deductions with actions, outage, four-eyes model change, roles, audit', async (t) => {
  let T = Date.parse('2026-11-17T08:00:00Z'), gwUp = true, temp = 90, cpu = [100, 200];
  const fetch = async (url, init) => {
    const u = new URL(url), r = (status, b) => ({ status, text: async () => (typeof b === 'string' ? b : JSON.stringify(b)) });
    if (u.port === '9100') return r(200, NODE(cpu[0], cpu[1]));
    if (u.port === '9400') return r(200, DCGM(temp));
    if (!gwUp) throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    if (u.pathname === '/v1/models') return r(200, { data: [{ id: 'synthetic-local-7b' }, { id: 'synthetic-local-14b' }] });
    if (u.pathname === '/api/ps') return r(200, { models: [{ name: 'synthetic-local-7b', size: 5e9, size_vram: 4.8e9, expires_at: '2026-11-17T09:00:00Z' }] });
    if (u.pathname === '/v1/chat/completions') { const q = JSON.parse(init.body); if (/FAIL/.test(JSON.stringify(q.messages))) return r(500, { error: 'synthetic overload' });
      return r(200, { id: 'c', model: q.model, choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'OK' } }], usage: { prompt_tokens: 10, completion_tokens: 40 } }); }
    return r(404, 'not found');
  };
  const e = await startApp({ noAi: true }); t.after(() => { if (e.app.addons.privateAi) e.app.addons.privateAi.stop(); return e.close(); });
  e.app.settings.update({ external_ai_allowed: false }, ADM);
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3', aiFetch: fetch, aiLocalKey: () => '' });
  const c = (m, p, b, w) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, w || ADM));
  assert.equal((await c('GET', '/private-ai', undefined, VIEW)).status, 403, 'a viewer is refused');
  let v = (await c('GET', '/private-ai', undefined, OP)).json;
  assert.equal(v.configured, false); assert.equal(v.health.score, null); assert.ok(v.health.not_measured.some((x) => /no local model address/.test(x)), 'says what to connect');
  // point the AI Engine at the synthetic AI server
  assert.equal((await c('PUT', '/ai-engine', { mode: 'local', local: { api: 'openai', base_url: 'http://10.20.0.40:11434/v1', model: 'synthetic-local-7b' } })).status, 200);
  // monitoring settings: validation names the field, version, roles
  let r = await c('PUT', '/private-ai/config', { metrics_urls: ['http://8.8.8.8:9100/metrics'], version: 0 }); assert.equal(r.status, 400); assert.match(r.json.error, /metrics_urls\[0\] is a public address/);
  r = await c('PUT', '/private-ai/config', { metrics_urls: ['http://10.20.0.40:9100/metrics'], thresholds: { gpu_temp_c: 200 }, version: 0 }); assert.equal(r.status, 400); assert.match(r.json.error, /gpu_temp_c must be at most 105/);
  assert.equal((await c('PUT', '/private-ai/config', { metrics_urls: [], version: 0 }, OP)).status, 403, 'an operator cannot change it');
  assert.equal((await c('PUT', '/private-ai/config', { metrics_urls: [], version: 0 }, BOT)).status, 403, 'an AI identity cannot change it');
  r = await c('PUT', '/private-ai/config', { metrics_urls: ['http://10.20.0.40:9100/metrics', 'http://10.20.0.40:9400/metrics'], version: 0 }); assert.equal(r.status, 200, r.text); assert.equal(r.json.version, 1);
  assert.equal((await c('PUT', '/private-ai/config', { metrics_urls: [], version: 0 })).status, 409, 'a stale version is refused');
  assert.equal((await c('POST', '/private-ai/poll', {}, OP)).status, 403, 'an operator cannot poll on demand');
  // two polls a minute apart (CPU is a counter), then AI calls through the switch: three answered, one failed
  assert.equal((await c('POST', '/private-ai/poll', {})).status, 200); T += 60000; cpu = [150, 400]; await c('POST', '/private-ai/poll', {});
  const C = B.wrap(null), client = new C({ apiKey: 'x' });
  await (async () => { B.setFeature('itam.synthetic-feature');
    for (let i = 0; i < 3; i++) await client.messages.create({ model: 'any', max_tokens: 50, messages: [{ role: 'user', content: 'synthetic question ' + i }] });
    await assert.rejects(client.messages.create({ model: 'any', max_tokens: 50, messages: [{ role: 'user', content: 'please FAIL' }] })); })();
  v = (await c('GET', '/private-ai', undefined, OP)).json;
  assert.equal(v.configured, true); assert.equal(v.gateway.ok, true); assert.deepEqual(v.gateway.models, ['synthetic-local-7b', 'synthetic-local-14b']);
  assert.equal(v.gateway.server, 'Ollama'); assert.equal(v.gateway.loaded[0].vram_gb, 4.8);
  assert.equal(v.server.host.cpu_pct, 75); assert.equal(v.server.host.disk_pct, 70); assert.equal(v.server.gpus[0].temp, 90);
  assert.equal(v.calls.last_hour, 4); assert.equal(v.calls.error_1h.pct, 25); assert.ok(v.calls.tokens_per_s > 0); assert.equal(v.calls.kept_in_network_pct, 100);
  assert.equal(v.calls.recent_failures[0].feature, 'itam.synthetic-feature'); assert.equal(v.calls.recent_failures[0].status, 424);
  assert.match(v.calls.latency_note, /needs 7\+ earlier hours/, 'no usual yet: said, not invented');
  const hot = v.health.deductions.find((d) => /GPU is at 90/.test(d.why)); assert.ok(hot && hot.points === 15 && /cooling/.test(hot.action), JSON.stringify(v.health));
  assert.equal(v.health.score, 85); assert.equal(v.health.band, 'healthy'); assert.equal(v.availability.pct, 100);
  assert.ok(v.charts.length >= 1 && v.charts.some((x) => x.gpu_temp === 90));
  assert.ok(!JSON.stringify(v).includes('synthetic question'), 'no prompt is kept');
  // the gateway goes down: 50 points, an open outage
  gwUp = false; T += 60000; await c('POST', '/private-ai/poll', {});
  v = (await c('GET', '/private-ai', undefined, OP)).json;
  const down = v.health.deductions.find((d) => d.points === 50); assert.ok(down && /not answering \(not reachable \(ECONNREFUSED\)\)/.test(down.why) && /systemctl/.test(down.action));
  assert.ok(v.availability.outages[0].open); assert.ok(v.availability.pct < 100); assert.equal(v.health.band, 'critical');
  // four-eyes model change
  gwUp = true; temp = 60; T += 60000; await c('POST', '/private-ai/poll', {});
  r = await c('POST', '/private-ai/model-change', { model: 'not-served-model', reason: 'synthetic test' }); assert.equal(r.status, 422); assert.match(r.json.error, /does not serve not-served-model/);
  r = await c('POST', '/private-ai/model-change', { model: 'synthetic-local-7b', reason: 'synthetic test' }); assert.equal(r.status, 409, 'already in use');
  r = await c('POST', '/private-ai/model-change', { model: 'synthetic-local-14b' }); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  assert.equal((await c('POST', '/private-ai/model-change', { model: 'synthetic-local-14b', reason: 'better answers' }, OP)).status, 403, 'an operator cannot propose');
  r = await c('POST', '/private-ai/model-change', { model: 'synthetic-local-14b', reason: 'better answers (synthetic)' }); assert.equal(r.status, 200); const id = r.json.id;
  assert.equal((await c('POST', '/private-ai/model-change', { model: 'synthetic-local-14b', reason: 'again please' })).status, 409, 'one pending change at a time');
  r = await c('POST', '/private-ai/model-change/' + id + '/decide', { decision: 'approve' }); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  assert.equal((await c('POST', '/private-ai/model-change/' + id + '/decide', { decision: 'approve' }, BOT)).status, 403, 'an AI identity never approves');
  r = await c('POST', '/private-ai/model-change/' + id + '/decide', { decision: 'reject' }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await c('POST', '/private-ai/model-change/' + id + '/decide', { decision: 'maybe' }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /decision must be one of/);
  r = await c('POST', '/private-ai/model-change/' + id + '/decide', { decision: 'approve', note: 'checked on the test bench' }, ADM2); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'applied');
  assert.equal(B.status().local.model, 'synthetic-local-14b', 'applied through the AI Engine');
  assert.equal((await c('POST', '/private-ai/model-change/' + id + '/decide', { decision: 'approve' }, ADM2)).status, 409, 'decided once');
  const A = e.app.store.auditTail(300), has = (a, by) => A.some((x) => x.action === a && x.by === by);
  assert.ok(has('private-ai.config', 'syed') && has('private-ai.poll', 'syed') && has('private-ai.model-change.propose', 'syed') && has('private-ai.model-change.approve', 'amal.syn') && has('ai.engine.save', 'amal.syn'), 'every change audited');
  v = (await c('GET', '/private-ai', undefined, OP)).json; assert.equal(v.changes.recent[0].status, 'applied'); assert.equal(v.engine.model, 'synthetic-local-14b');
  // back to Claude for the next test files (the switch is process-wide)
  await c('PUT', '/ai-engine', { mode: 'anthropic' });
});
