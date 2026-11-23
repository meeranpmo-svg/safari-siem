// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
const { createIntelKit, robustZ, median } = require('./intel-kit');
const B = require('./ai-backend');
/*
 * Private AI Server ({P} = /api/itam; Platform Administration -> Private AI Server). The health and management view of the
 * organisation's own AI server (AI-01): the model gateway the AI Engine points at (engine/ai-backend.js, "local"), the server's
 * exporters, and every AI call the platform made through the switch. Read-only towards the server: it only GETs.
 *   poll         every poll_s (60 s): the gateway's model list (GET <base>/v1/models) and its answer time; Ollama's loaded models
 *                and VRAM (/api/ps) and vLLM's own metrics (/metrics) when the gateway is one of those; and up to 4 Prometheus
 *                exporters an administrator lists (node_exporter: CPU, memory, disk, load; NVIDIA DCGM or nvidia_gpu_exporter:
 *                GPU use, memory, temperature, power). An exporter that does not answer is said, never shown as 0.
 *   calls        every model call through the AI switch (ai-backend listen()): engine, feature, ms, tokens, answered or failed -
 *                never the prompt or the answer.
 *   models (ML)  availability and outages; latency p50 / p95 per hour against the server's own usual (median / MAD robust z over
 *                7+ hours - an hour unlike the others is flagged, not a fixed limit); failure rate with a Wilson 95 % interval;
 *                generation speed (tokens / s); queueing (vLLM waiting requests); GPU temperature against its own usual;
 *                disk and GPU memory forecast (least squares over the hourly means, 24+ hours) to the threshold; a health score
 *                that subtracts named points, and the action that removes each. With nothing monitored a point is not measured,
 *                never assumed fine.
 *   GET  /private-ai                     operator  the dashboard
 *   PUT  /private-ai/config              admin     {metrics_urls[], poll_s, thresholds{}, version} - a person, versioned, audited
 *   POST /private-ai/poll                admin     poll now (audited)
 *   POST /private-ai/model-change        admin     {model, reason} propose switching the platform to another model the gateway
 *                                                  serves (four eyes: a different administrator decides) - audited
 *   POST /private-ai/model-change/:id/decide admin {decision: approve|reject, note} - not the proposer, a person; approve applies it
 *                                                  through the AI Engine's own audited save
 *   POST /private-ai/ask                 operator  the read-only AI advisor (intel kit): a briefing on the server's health
 *   (vLLM reserves GPU memory up front, so there high GPU memory is normal and the KV cache is the measure)
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const PRIVATE = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^127\./, /^169\.254\./];
const DEF = { metrics_urls: [], poll_s: 60, thresholds: { gpu_temp_c: 85, gpu_mem_pct: 95, disk_pct: 90, mem_pct: 95, p95_s: 60, error_pct: 10 } };
const KEEP_MIN = 1440, KEEP_HOURS = 720, KEEP_CALLS = 5000, HOUR = 3600000, DAY = 86400000;
const r1 = (x) => (x == null || !Number.isFinite(x) ? null : Math.round(x * 10) / 10);
const pct = (a, b) => (b > 0 ? r1((a / b) * 100) : null);
const quant = (a, q) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y); return b[Math.min(b.length - 1, Math.floor(q * b.length))]; };
const clip = (x, n = 200) => String(x == null ? '' : x).replace(/[\u0000-\u001f]/g, ' ').slice(0, n);

// ---- Prometheus text format: [{name, labels, value}] (comments and malformed lines skipped)
function parseProm(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    if (!line || line[0] === '#') continue;
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+(\S+)/.exec(line); if (!m) continue;
    const v = Number(m[4]); if (!Number.isFinite(v)) continue;
    const labels = {}; if (m[3]) for (const p of m[3].matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g)) labels[p[1]] = p[2];
    out.push({ name: m[1], labels, value: v });
  }
  return out;
}
// what the exporters say, in one shape; cpu needs two polls (counters)
function readMetrics(rows, prev) {
  const by = (n) => rows.filter((r) => r.name === n), one = (n, f) => { const x = by(n).filter(f || (() => true)); return x.length ? x.reduce((a, r) => a + r.value, 0) : null; };
  const host = {}, gpus = {}, llm = {}, counters = {};
  // node_exporter
  const cpu = by('node_cpu_seconds_total');
  if (cpu.length) { counters.cpu_total = cpu.reduce((a, r) => a + r.value, 0); counters.cpu_idle = cpu.filter((r) => r.labels.mode === 'idle' || r.labels.mode === 'iowait').reduce((a, r) => a + r.value, 0);
    if (prev && prev.cpu_total != null && counters.cpu_total > prev.cpu_total) host.cpu_pct = r1(100 * (1 - (counters.cpu_idle - prev.cpu_idle) / (counters.cpu_total - prev.cpu_total))); }
  const mt = one('node_memory_MemTotal_bytes'), ma = one('node_memory_MemAvailable_bytes'); if (mt) host.mem_pct = pct(mt - (ma || 0), mt), host.mem_total_gb = r1(mt / 1e9);
  const fs = by('node_filesystem_size_bytes').filter((r) => !/tmpfs|overlay|squashfs/.test(r.labels.fstype || ''));
  const root = fs.find((r) => r.labels.mountpoint === '/') || fs.sort((a, b) => b.value - a.value)[0];
  if (root) { const av = by('node_filesystem_avail_bytes').find((r) => r.labels.mountpoint === root.labels.mountpoint && r.labels.device === root.labels.device);
    if (av) { host.disk_pct = pct(root.value - av.value, root.value); host.disk_free_gb = r1(av.value / 1e9); host.disk_mount = clip(root.labels.mountpoint, 60); } }
  const l1 = one('node_load1'); if (l1 != null) host.load1 = r1(l1);
  const cores = new Set(cpu.map((r) => r.labels.cpu)).size; if (cores) host.cores = cores;
  const boot = one('node_boot_time_seconds'), tnow = one('node_time_seconds'); if (boot && tnow) host.uptime_h = r1((tnow - boot) / 3600);
  // NVIDIA DCGM exporter (MiB) and nvidia_gpu_exporter (bytes / ratio)
  const g = (id) => (gpus[id] = gpus[id] || { id });
  for (const r of by('DCGM_FI_DEV_GPU_UTIL')) g(r.labels.gpu || '0').util = r1(r.value);
  for (const r of by('DCGM_FI_DEV_GPU_TEMP')) g(r.labels.gpu || '0').temp = r1(r.value);
  for (const r of by('DCGM_FI_DEV_POWER_USAGE')) g(r.labels.gpu || '0').power_w = r1(r.value);
  for (const r of by('DCGM_FI_DEV_FB_USED')) g(r.labels.gpu || '0').mem_used_gb = r1(r.value / 1024);
  for (const r of by('DCGM_FI_DEV_FB_FREE')) { const x = g(r.labels.gpu || '0'); x.mem_free_gb = r1(r.value / 1024); }
  for (const r of rows) if (/^DCGM_FI_/.test(r.name) && r.labels.modelName) g(r.labels.gpu || '0').name = clip(r.labels.modelName, 60);
  for (const r of by('nvidia_smi_utilization_gpu_ratio')) g(r.labels.uuid || r.labels.gpu || '0').util = r1(r.value * 100);
  for (const r of by('nvidia_smi_temperature_gpu')) g(r.labels.uuid || r.labels.gpu || '0').temp = r1(r.value);
  for (const r of by('nvidia_smi_power_draw_watts')) g(r.labels.uuid || r.labels.gpu || '0').power_w = r1(r.value);
  for (const r of by('nvidia_smi_memory_used_bytes')) g(r.labels.uuid || r.labels.gpu || '0').mem_used_gb = r1(r.value / 1e9);
  for (const r of by('nvidia_smi_memory_total_bytes')) { const x = g(r.labels.uuid || r.labels.gpu || '0'); x.mem_total_gb = r1(r.value / 1e9); }
  for (const r of by('nvidia_smi_gpu_info')) { const x = gpus[r.labels.uuid]; if (x && r.labels.name) x.name = clip(r.labels.name, 60); }
  const G = Object.values(gpus).map((x) => { if (x.mem_total_gb == null && x.mem_free_gb != null && x.mem_used_gb != null) x.mem_total_gb = r1(x.mem_used_gb + x.mem_free_gb); delete x.mem_free_gb;
    if (x.mem_total_gb) x.mem_pct = pct(x.mem_used_gb, x.mem_total_gb); x.id = clip(x.id, 60); return x; });
  // vLLM (names with ':' since 0.4; kv cache name changed in 0.8)
  const vr = one('vllm:num_requests_running'), vw = one('vllm:num_requests_waiting'), kv = one('vllm:gpu_cache_usage_perc') != null ? one('vllm:gpu_cache_usage_perc') : one('vllm:kv_cache_usage_perc');
  if (vr != null || vw != null) { llm.server = 'vLLM'; llm.running = vr; llm.waiting = vw; if (kv != null) llm.kv_pct = r1(kv * 100); }
  const gen = one('vllm:generation_tokens_total'), ts = one('vllm:time_to_first_token_seconds_sum'), tc = one('vllm:time_to_first_token_seconds_count');
  if (gen != null) counters.gen = gen; if (ts != null) { counters.ttft_s = ts; counters.ttft_n = tc; }
  return { host, gpus: G, llm, counters };
}
const wilson = (k, n) => { if (!n) return null; const z = 1.96, p = k / n, d = 1 + z * z / n, c = p + z * z / (2 * n), m = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n));
  return { pct: r1(100 * p), low: r1(100 * Math.max(0, (c - m) / d)), high: r1(100 * Math.min(1, (c + m) / d)) }; };
// least squares to a threshold over hourly means: {per_day, hours_to, low/high band} - 24 points before saying anything
function forecast(pts, limit) {
  const P = pts.filter((p) => p.y != null && Number.isFinite(p.y));
  if (P.length < 24) return { note: 'needs 24 hours of samples (' + P.length + ' so far)' };
  const n = P.length, mx = P.reduce((a, p) => a + p.t, 0) / n, my = P.reduce((a, p) => a + p.y, 0) / n, sxx = P.reduce((a, p) => a + (p.t - mx) ** 2, 0);
  const b = sxx ? P.reduce((a, p) => a + (p.t - mx) * (p.y - my), 0) / sxx : 0, a = my - b * mx, last = P[n - 1];
  const se = Math.sqrt(P.reduce((s, p) => s + (p.y - (a + b * p.t)) ** 2, 0) / Math.max(1, n - 2));
  const out = { per_day: r1(b * 24), now: r1(last.y), band: r1(1.28 * se) };
  if (b > 1e-6 && last.y < limit) { const h = (limit - (a + b * last.t)) / b; out.hours_to = Math.max(0, Math.round(h)); }
  return out;
}

function createPrivateAi(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString(), L = app.log || { info() {}, warn() {}, every() {} };
  const col = () => app.store.collection('private_ai'), chg = () => app.store.collection('private_ai_changes');
  const fetchFn = opts.fetch || ((...a) => globalThis.fetch(...a));
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'private-ai.' + action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const keyFn = () => { try { const E = (app.addons || {}).aiEngine; return (opts.gatewayKey ? opts.gatewayKey() : E && E.gatewayKey ? E.gatewayKey() : '') || ''; } catch (e) { return ''; /* no key source: the gateway is asked without one */ } };
  // state: minute samples (24 h), hourly means (30 days), calls (5000), last counters - persisted every 10 polls
  const saved = col().get('state') || {};
  const S = { min: saved.min || [], hours: saved.hours || [], calls: saved.calls || [], counters: saved.counters || null, polls: 0, last: saved.last || null };
  const persist = () => { try { col().put({ id: 'state', min: S.min, hours: S.hours, calls: S.calls, counters: S.counters, last: S.last }); } catch (e) { L.every('private-ai:persist', 600000, 'warn', 'private-ai: state could not be saved', { err: clip(e.message, 160) }); } };
  const unlisten = B.listen((c) => { S.calls.push([now(), c.ok ? 1 : 0, Math.round(c.ms || 0), c.output_tokens || 0, c.mode, clip(c.feature, 80), c.ok ? 0 : (c.status || 500)]); if (S.calls.length > KEEP_CALLS) S.calls.splice(0, S.calls.length - KEEP_CALLS); });
  function cfg() { const c = col().get('cfg') || {}; const v = c.v || {}; return { metrics_urls: v.metrics_urls || DEF.metrics_urls, poll_s: v.poll_s || DEF.poll_s, thresholds: Object.assign({}, DEF.thresholds, v.thresholds || {}), version: c.version || 0, by: c.by || null, at: c.at || null }; }
  function checkUrl(u0, name) {
    let u; try { u = new URL(u0); } catch (e) { throw httpErr(400, name + ' is not a URL (for example http://10.20.0.40:9100/metrics)'); }
    if (!/^https?:$/.test(u.protocol)) throw httpErr(400, name + ' must start with http:// or https://');
    if (u.username || u.password) throw httpErr(400, name + ' must not carry a user or password');
    if (u.search || u.hash) throw httpErr(400, name + ' must not carry a query or fragment');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) && !PRIVATE.some((r) => r.test(u.hostname))) throw httpErr(400, name + (' is a public address - the AI server is inside ' + ZYB_ORG.short + '\'s network'));
    return u.toString();
  }
  async function get(url, ms, json, withKey) {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), ms || 8000), t0 = Date.now(), headers = { Accept: json ? 'application/json' : 'text/plain' };
    if (withKey) { const k = keyFn(); if (k) headers.Authorization = 'Bearer ' + k; }
    try {
      const r = await fetchFn(url, { method: 'GET', headers, signal: ctl.signal }); const txt = await r.text(), ms2 = Date.now() - t0;
      if (r.status < 200 || r.status >= 300) return { ok: false, status: r.status, ms: ms2, error: 'HTTP ' + r.status };
      if (!json) return { ok: true, ms: ms2, text: txt };
      try { return { ok: true, ms: ms2, json: JSON.parse(txt) }; } catch (e) { return { ok: false, status: r.status, ms: ms2, error: 'not JSON' }; }
    } catch (e) { return { ok: false, ms: Date.now() - t0, error: e.name === 'AbortError' ? 'no answer within ' + Math.round((ms || 8000) / 1000) + ' s' : 'not reachable (' + clip(e.cause && e.cause.code || e.code || e.message, 60) + ')' }; }
    finally { clearTimeout(t); }
  }
  const endpoint = (base, path) => { const b = String(base).replace(/\/+$/, ''); return /\/v1$/.test(b) ? b + path : b + '/v1' + path; };
  async function poll() {
    const st = B.status(), c = cfg(), smp = { at: now(), gw: null, models: [], loaded: [], host: {}, gpus: [], llm: {}, exporters: [] };
    let counters = {};
    if (st.local.base_url) {
      const base = st.local.base_url, root = String(base).replace(/\/+$/, '').replace(/\/v1$/, '');
      const m = await get(endpoint(base, '/models'), 8000, true, true);
      smp.gw = { ok: m.ok, ms: m.ms, error: m.ok ? null : m.error };
      if (m.ok) smp.models = ((m.json && m.json.data) || []).map((x) => clip(x && x.id, 120)).filter(Boolean).slice(0, 50);
      const ps = await get(root + '/api/ps', 5000, true, true);   // Ollama: loaded models and VRAM; anything else: 404, said as not reported
      if (ps.ok && ps.json && Array.isArray(ps.json.models)) { smp.llm.server = 'Ollama'; smp.loaded = ps.json.models.slice(0, 20).map((x) => ({ name: clip(x.name || x.model, 120), vram_gb: r1((Number(x.size_vram) || 0) / 1e9), size_gb: r1((Number(x.size) || 0) / 1e9), until: clip(x.expires_at, 40) })); }
      if (m.ok && !smp.llm.server) { const vm = await get(root + '/metrics', 5000, false, true);
        if (vm.ok && /vllm:/.test(vm.text)) { const R = readMetrics(parseProm(vm.text), S.counters); Object.assign(smp.llm, R.llm); Object.assign(counters, R.counters); } }
    }
    for (const [i, u] of c.metrics_urls.entries()) {
      const x = await get(u, 8000, false, false), host = (() => { try { return new URL(u).host; } catch (e) { return u; } })();
      smp.exporters.push({ url: u, host, ok: x.ok, ms: x.ms, error: x.ok ? null : x.error, index: i });
      if (!x.ok) { L.every('private-ai:exp:' + host, 600000, 'warn', 'private-ai: an exporter did not answer', { host, err: x.error }); continue; }
      const R = readMetrics(parseProm(x.text), S.counters);
      Object.assign(smp.host, R.host); smp.gpus = smp.gpus.concat(R.gpus); Object.keys(R.llm).forEach((k) => { if (smp.llm[k] == null) smp.llm[k] = R.llm[k]; }); Object.assign(counters, R.counters);
    }
    // counters -> rates against the previous poll
    const P = S.counters, dt = P && P.at ? (smp.at - P.at) / 1000 : 0;
    if (P && dt > 0) { if (counters.gen != null && P.gen != null && counters.gen >= P.gen) smp.llm.gen_tps = r1((counters.gen - P.gen) / dt);
      if (counters.ttft_n != null && P.ttft_n != null && counters.ttft_n > P.ttft_n) smp.llm.ttft_ms = Math.round(1000 * (counters.ttft_s - P.ttft_s) / (counters.ttft_n - P.ttft_n)); }
    S.counters = Object.assign({ at: smp.at }, counters);
    if (smp.gw && !smp.gw.ok) L.every('private-ai:gw', 300000, 'warn', 'private-ai: the model gateway did not answer', { host: st.local.host, err: smp.gw.error });
    if (S.last && S.last.gw && smp.gw && S.last.gw.ok !== smp.gw.ok) L.info('private-ai: the model gateway is ' + (smp.gw.ok ? 'answering again' : 'not answering'), { host: st.local.host });
    S.last = smp; S.min.push(smp); if (S.min.length > KEEP_MIN) S.min.splice(0, S.min.length - KEEP_MIN);
    rollHour(smp);
    if (++S.polls % 10 === 1) persist();
    return smp;
  }
  // hourly means for the forecasts and the "usual" of each measure
  function rollHour(smp) {
    const h = Math.floor(smp.at / HOUR) * HOUR; let H = S.hours[S.hours.length - 1];
    if (!H || H.h !== h) { H = { h, n: 0, up: 0, sum: {}, cnt: {} }; S.hours.push(H); if (S.hours.length > KEEP_HOURS) S.hours.splice(0, S.hours.length - KEEP_HOURS); }
    H.n++; if (smp.gw && smp.gw.ok) H.up++;
    const add = (k, v) => { if (v == null || !Number.isFinite(v)) return; H.sum[k] = (H.sum[k] || 0) + v; H.cnt[k] = (H.cnt[k] || 0) + 1; };
    add('disk', smp.host.disk_pct); add('mem', smp.host.mem_pct); add('cpu', smp.host.cpu_pct);
    const temps = smp.gpus.map((g) => g.temp).filter((x) => x != null), mems = smp.gpus.map((g) => g.mem_pct).filter((x) => x != null), utils = smp.gpus.map((g) => g.util).filter((x) => x != null);
    if (temps.length) add('gtemp', Math.max(...temps)); if (mems.length) add('gmem', Math.max(...mems)); if (utils.length) add('gutil', utils.reduce((a, b) => a + b, 0) / utils.length);
    add('gwms', smp.gw && smp.gw.ok ? smp.gw.ms : null); add('kv', smp.llm.kv_pct);
  }
  const hm = (k) => S.hours.map((H) => ({ t: H.h / HOUR, y: H.cnt[k] ? H.sum[k] / H.cnt[k] : null, h: H.h }));

  function model() {
    const st = B.status(), c = cfg(), T = c.thresholds, t = now(), cur = S.last;
    const configured = !!(st.local.base_url && st.local.model), usesLocal = st.mode === 'local' || st.routes.some((r) => r.engine === 'local');
    // availability (24 h of polls) and outages (runs of polls without an answer)
    const day = S.min.filter((m) => m.gw && m.at >= t - DAY), up = day.filter((m) => m.gw.ok).length;
    const outages = []; let o = null;
    for (const m of day) { if (!m.gw.ok) { if (!o) o = { from: m.at, to: m.at, reason: m.gw.error }; else o.to = m.at; } else if (o) { outages.push(o); o = null; } }
    if (o) { o.open = true; outages.push(o); }
    const availability = day.length ? r1(100 * up / day.length) : null;
    // calls through the switch to the local engine
    const lc = S.calls.filter((x) => x[4] === 'local'), h1 = lc.filter((x) => x[0] >= t - HOUR), d1 = lc.filter((x) => x[0] >= t - DAY);
    const okMs = (a) => a.filter((x) => x[1]).map((x) => x[2]);
    const p50 = quant(okMs(h1), 0.5), p95 = quant(okMs(h1), 0.95);
    // the usual: median latency of each earlier hour with 3+ calls (7+ hours before a judgement)
    const byHour = new Map(); for (const x of lc) { if (!x[1] || x[0] >= t - HOUR) continue; const k = Math.floor(x[0] / HOUR); (byHour.get(k) || byHour.set(k, []).get(k)).push(x[2]); }
    const hourMed = [...byHour.values()].filter((a) => a.length >= 3).map((a) => median(a));
    const lz = p50 != null && okMs(h1).length >= 3 ? robustZ(hourMed, p50) : null;
    const err1 = wilson(h1.filter((x) => !x[1]).length, h1.length), err24 = wilson(d1.filter((x) => !x[1]).length, d1.length);
    const speed = (() => { const v = d1.filter((x) => x[1] && x[3] > 0 && x[2] > 0).map((x) => x[3] / (x[2] / 1000)); return v.length ? r1(median(v)) : null; })();
    const allDay = S.calls.filter((x) => x[0] >= t - DAY), keptIn = allDay.length ? r1(100 * allDay.filter((x) => x[4] === 'local').length / allDay.length) : null;
    const feats = {}; for (const x of d1) { const f = feats[x[5] || '(no feature name)'] = feats[x[5] || '(no feature name)'] || { feature: x[5] || '(no feature name)', calls: 0, failed: 0, ms: [] }; f.calls++; if (!x[1]) f.failed++; else f.ms.push(x[2]); }
    const features = Object.values(feats).map((f) => ({ feature: f.feature, calls: f.calls, failed: f.failed, p50_ms: quant(f.ms, 0.5) })).sort((a, b) => b.calls - a.calls).slice(0, 30);
    const recentErr = lc.filter((x) => !x[1]).slice(-8).reverse().map((x) => ({ at: new Date(x[0]).toISOString(), feature: x[5], status: x[6], ms: x[2] }));
    // the server: newest sample, the GPU temperature against its usual, the forecasts
    const H = cur ? cur.host : {}, Gs = cur ? cur.gpus : [], LL = cur ? cur.llm : {};
    const gTempNow = Gs.some((g) => g.temp != null) ? Math.max(...Gs.filter((g) => g.temp != null).map((g) => g.temp)) : null, gtHist = hm('gtemp').slice(0, -1).map((p) => p.y).filter((y) => y != null);
    const gtz = gTempNow ? robustZ(gtHist, gTempNow) : null;
    const fDisk = H.disk_pct != null ? forecast(hm('disk'), T.disk_pct) : null;
    const fGmem = Gs.length && !LL.kv_pct && LL.server !== 'vLLM' ? forecast(hm('gmem'), T.gpu_mem_pct) : null;
    const waitAvg = (() => { const w = S.min.slice(-5).map((m) => m.llm && m.llm.waiting).filter((x) => x != null); return w.length ? r1(w.reduce((a, b) => a + b, 0) / w.length) : null; })();
    // the health score: 100 minus named points, each with the action that removes it
    const ded = [], not = [];
    const D = (pts, why, act, sev) => ded.push({ points: pts, why, action: act, sev: sev || (pts >= 25 ? 'bad' : 'warn') });
    if (!configured) not.push('the AI Engine has no local model address and model (Platform Administration -> AI Engine)');
    else {
      if (cur && cur.gw && !cur.gw.ok) D(50, 'the model gateway at ' + st.local.host + ' is not answering (' + cur.gw.error + ')', 'Check the AI server is on and its model service runs (systemctl status ollama / vllm); until then every AI feature routed to it gives the rule-based answer', 'bad');
      else if (cur && cur.gw && cur.gw.ok && cur.models.length && !cur.models.includes(st.local.model)) D(25, 'the AI Engine uses ' + st.local.model + ' but the gateway serves only ' + cur.models.slice(0, 5).join(', '), 'Pull or load ' + st.local.model + ' on the server, or propose switching to a model it serves (below)', 'bad');
      if (availability != null && availability < 99) D(Math.min(20, Math.ceil((99 - availability) * 4)), 'answered ' + availability + ' % of health checks in 24 h (' + outages.length + ' outage(s))', 'Read the outages below; a service that restarts on its own often runs out of GPU memory');
      if (err1 && err1.low > T.error_pct) D(15, err1.pct + ' % of AI calls failed in the last hour (95 % interval ' + err1.low + '-' + err1.high + ' %)', 'Open the failed calls below: a timeout means the model is too slow for the timeout set in the AI Engine, a 4xx means a request the model refused');
      if (p95 != null && p95 > T.p95_s * 1000) D(10, 'the slowest 5 % of answers took over ' + Math.round(p95 / 1000) + ' s in the last hour (limit ' + T.p95_s + ' s)', 'Lower max tokens in the AI Engine, use a smaller or quantised model, or add GPU capacity');
      if (lz && lz.z >= 3.5) D(10, 'answers are slower than usual: ' + Math.round(p50 / 1000 * 10) / 10 + ' s median against ' + Math.round(lz.usual / 1000 * 10) / 10 + ' s (robust z ' + (lz.z === Infinity ? 'n/a' : lz.z) + ')', 'Something changed on the server: another workload on the GPU, a model swapped to CPU, thermal throttling - check the GPU charts');
      if (waitAvg != null && waitAvg >= 1) D(10, 'requests are queuing: ' + waitAvg + ' waiting on average over the last 5 checks', 'Too many AI features at once for one GPU: route the less urgent features to another engine or lower max tokens');
      if (LL.kv_pct != null && LL.kv_pct >= 95) D(10, 'the KV cache is ' + LL.kv_pct + ' % full', 'Long prompts and answers fill the cache: lower max tokens or raise --gpu-memory-utilization on vLLM');
    }
    if (!c.metrics_urls.length) not.push('the server itself (CPU, memory, disk, GPU): no exporter listed - add node_exporter (:9100) and the NVIDIA DCGM exporter (:9400) below');
    else {
      const down = cur ? cur.exporters.filter((e) => !e.ok) : []; if (down.length) D(5, down.length + ' exporter(s) did not answer: ' + down.map((e) => e.host + ' (' + e.error + ')').join(', '), 'Check the exporter service on the server; until then those measures are not measured');
      if (gTempNow && gTempNow >= T.gpu_temp_c) D(15, 'a GPU is at ' + gTempNow + ' °C (limit ' + T.gpu_temp_c + ' °C)', 'Check the server room cooling and the GPU fans; a hot GPU slows itself down (throttling)', 'bad');
      else if (gtz && gtz.z >= 3.5) D(5, 'a GPU runs hotter than usual: ' + gTempNow + ' °C against ' + r1(gtz.usual) + ' °C', 'Look at the cooling before it reaches the limit');
      Gs.forEach((g) => { if (g.mem_pct != null && g.mem_pct >= T.gpu_mem_pct && LL.server !== 'vLLM') D(5, 'GPU ' + g.id + ' memory is ' + g.mem_pct + ' % used', 'A second model loaded beside the first: unload the one nobody uses'); });
      if (H.disk_pct != null && H.disk_pct >= T.disk_pct) D(15, 'the disk (' + (H.disk_mount || '/') + ') is ' + H.disk_pct + ' % full', 'Remove old model files (ollama rm / the Hugging Face cache) or extend the disk', 'bad');
      else if (fDisk && fDisk.hours_to != null && fDisk.hours_to < 24 * 7) D(10, 'the disk reaches ' + T.disk_pct + ' % in about ' + Math.max(1, Math.round(fDisk.hours_to / 24)) + ' day(s) at the current rate (' + fDisk.per_day + ' points a day)', 'Find what writes to the disk (logs, downloaded models) before it fills');
      if (H.mem_pct != null && H.mem_pct >= T.mem_pct) D(5, 'memory is ' + H.mem_pct + ' % used', 'A model may be running on the CPU instead of the GPU, or the server needs more memory');
      if (!Gs.length && cur && cur.exporters.some((e) => e.ok)) not.push('no GPU exporter answered: GPU use, memory and temperature are not measured');
    }
    const score = configured ? Math.max(0, 100 - ded.reduce((a, d) => a + d.points, 0)) : null;
    const band = score == null ? 'not measured' : score >= 80 ? 'healthy' : score >= 50 ? 'degraded' : 'critical';
    // charts: 5-minute buckets of the last 24 h
    const bucket = 300000, series = {};
    for (const m of S.min.filter((m) => m.at >= t - DAY)) { const k = Math.floor(m.at / bucket) * bucket, b = series[k] = series[k] || { at: k, gw: [], up: 0, n: 0, gutil: [], gtemp: [], cpu: [], mem: [], kv: [], wait: [] };
      b.n++; if (m.gw) { if (m.gw.ok) { b.up++; b.gw.push(m.gw.ms); } }
      m.gpus.forEach((g) => { if (g.util != null) b.gutil.push(g.util); if (g.temp != null) b.gtemp.push(g.temp); }); if (m.host.cpu_pct != null) b.cpu.push(m.host.cpu_pct); if (m.host.mem_pct != null) b.mem.push(m.host.mem_pct);
      if (m.llm.kv_pct != null) b.kv.push(m.llm.kv_pct); if (m.llm.waiting != null) b.wait.push(m.llm.waiting); }
    const avg = (a) => (a.length ? r1(a.reduce((x, y) => x + y, 0) / a.length) : null);
    const calls5 = {}; for (const x of lc.filter((x) => x[0] >= t - DAY)) { const k = Math.floor(x[0] / bucket) * bucket, b = calls5[k] = calls5[k] || { ms: [], fail: 0, n: 0 }; b.n++; if (x[1]) b.ms.push(x[2]); else b.fail++; }
    const keys = [...new Set(Object.keys(series).concat(Object.keys(calls5)))].map(Number).sort((a, b) => a - b);
    const charts = keys.map((k) => { const s = series[k] || { gw: [], gutil: [], gtemp: [], cpu: [], mem: [], kv: [], wait: [], n: 0, up: 0 }, c5 = calls5[k] || { ms: [], fail: 0, n: 0 };
      return { at: new Date(k).toISOString(), up: s.n ? (s.up === s.n ? 1 : s.up ? 0.5 : 0) : null, gw_ms: avg(s.gw), gpu_util: avg(s.gutil), gpu_temp: avg(s.gtemp), cpu: avg(s.cpu), mem: avg(s.mem), kv: avg(s.kv), waiting: avg(s.wait),
        calls: c5.n, failed: c5.fail, p95_ms: quant(c5.ms, 0.95) }; });
    const pend = chg().all((x) => x.status === 'pending').sort((a, b) => b.at.localeCompare(a.at)), hist = chg().all((x) => x.status !== 'pending').sort((a, b) => b.at.localeCompare(a.at)).slice(0, 10);
    return {
      at: iso(), configured, uses_local: usesLocal, mode: st.mode, engine: { host: st.local.host || null, model: st.local.model || null, api: st.local.api, max_tokens: st.local.max_tokens, timeout_s: st.local.timeout_s, routes: st.routes.filter((r) => r.engine === 'local').map((r) => r.match) },
      last_poll: cur ? new Date(cur.at).toISOString() : null, polls_24h: day.length, health: { score, band, deductions: ded.sort((a, b) => b.points - a.points), not_measured: not },
      gateway: cur && cur.gw ? { ok: cur.gw.ok, ms: cur.gw.ms, error: cur.gw.error, server: LL.server || null, models: cur.models, loaded: cur.loaded } : null,
      availability: { pct: availability, outages: outages.slice(-10).reverse().map((x) => ({ from: new Date(x.from).toISOString(), to: new Date(x.to).toISOString(), minutes: Math.max(1, Math.round((x.to - x.from) / 60000) + 1), open: !!x.open, reason: clip(x.reason, 120) })) },
      calls: { last_hour: h1.length, day: d1.length, p50_ms: p50, p95_ms: p95, usual_p50_ms: lz ? Math.round(lz.usual) : null, latency_z: lz ? (lz.z === Infinity ? null : lz.z) : null, latency_note: lz ? null : 'the usual needs 7+ earlier hours with 3+ answers (' + hourMed.length + ' so far)',
        error_1h: err1, error_24h: err24, tokens_per_s: speed, kept_in_network_pct: keptIn, by_engine_24h: allDay.reduce((a, x) => { a[x[4]] = (a[x[4]] || 0) + 1; return a; }, {}), features, recent_failures: recentErr },
      server: { host: H, gpus: Gs, llm: LL, gpu_temp_z: gtz && gtz.z !== Infinity ? gtz.z : null, forecast: { disk: fDisk, gpu_mem: fGmem }, exporters: cur ? cur.exporters.map((e) => ({ host: e.host, ok: e.ok, ms: e.ms, error: e.error })) : [] },
      charts, config: c, changes: { pending: pend, recent: hist },
    };
  }
  function view(who) { return model(); }
  function saveConfig(input, who) {
    person(who, 'change the AI server monitoring');
    const b = body(input).list('metrics_urls', { item: 'str', itemMax: 300, max: 4, def: [] }).int('poll_s', { min: 30, max: 900, def: DEF.poll_s }).int('version', { required: true, min: 0 }).done();
    const t0 = input.thresholds && typeof input.thresholds === 'object' && !Array.isArray(input.thresholds) ? input.thresholds : {};
    const th = body(t0).int('gpu_temp_c', { min: 50, max: 105, def: DEF.thresholds.gpu_temp_c }).int('gpu_mem_pct', { min: 50, max: 100, def: DEF.thresholds.gpu_mem_pct }).int('disk_pct', { min: 50, max: 99, def: DEF.thresholds.disk_pct })
      .int('mem_pct', { min: 50, max: 100, def: DEF.thresholds.mem_pct }).int('p95_s', { min: 1, max: 600, def: DEF.thresholds.p95_s }).int('error_pct', { min: 1, max: 100, def: DEF.thresholds.error_pct }).done();
    const urls = [...new Set(b.metrics_urls.filter(Boolean).map((u, i) => checkUrl(u, 'metrics_urls[' + i + ']')))];
    const cur = cfg(); if (b.version !== cur.version) throw httpErr(409, 'the settings were changed meanwhile (version ' + cur.version + ') - reload and try again');
    col().put({ id: 'cfg', v: { metrics_urls: urls, poll_s: b.poll_s, thresholds: th }, version: cur.version + 1, by: who.user, at: iso() });
    audit(who, 'config', 'private-ai', { version: cur.version + 1, from: { metrics_urls: cur.metrics_urls.map((u) => new URL(u).host), poll_s: cur.poll_s, thresholds: cur.thresholds }, to: { metrics_urls: urls.map((u) => new URL(u).host), poll_s: b.poll_s, thresholds: th } });
    restart(); return cfg();
  }
  async function pollNow(who) { person(who, 'poll the AI server'); const s = await poll(); persist(); audit(who, 'poll', 'private-ai', { gateway_ok: s.gw ? s.gw.ok : null, exporters: s.exporters.map((e) => ({ host: e.host, ok: e.ok })) }); return model(); }
  function propose(input, who) {
    person(who, 'propose a model change');
    const b = body(input).str('model', { required: true, max: 120, re: /^[A-Za-z0-9._:/@+-]{1,120}$/, msg: 'model may hold letters, digits and . _ : / @ + - only' }).str('reason', { required: true, min: 5, max: 500 }).done();
    const st = B.status(); if (!st.local.base_url) throw httpErr(409, 'the AI Engine has no local model address yet - set it on the AI Engine page');
    const served = (S.last && S.last.models) || []; if (!served.includes(b.model)) throw httpErr(422, 'the gateway does not serve ' + b.model + ' - it serves: ' + (served.join(', ') || 'nothing yet (poll first)'));
    if (b.model === st.local.model) throw httpErr(409, b.model + ' is already the model in use');
    if (chg().all((x) => x.status === 'pending').length) throw httpErr(409, 'a model change is already waiting for a decision');
    const rec = { id: 'mc_' + now().toString(36) + Math.random().toString(36).slice(2, 6), at: iso(), by: who.user, from: st.local.model, to: b.model, reason: b.reason, status: 'pending' };
    chg().put(rec); audit(who, 'model-change.propose', rec.id, { from: rec.from, to: rec.to, reason: rec.reason }); return rec;
  }
  async function decide(id, input, who) {
    param(id, 'id'); person(who, 'decide a model change');
    const b = body(input).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 500 }).done();
    const rec = chg().get(id); if (!rec) throw httpErr(404, 'no such model change');
    if (rec.status !== 'pending') throw httpErr(409, 'this change was already ' + rec.status);
    if (rec.by === who.user) throw httpErr(403, 'four eyes: the person who proposed the change cannot decide it - another administrator does');
    if (b.decision === 'reject') { if (!b.note) throw httpErr(400, 'note is required to reject (say why)'); Object.assign(rec, { status: 'rejected', decided_by: who.user, decided_at: iso(), note: b.note }); chg().put(rec); audit(who, 'model-change.reject', id, { to: rec.to, note: b.note }); return rec; }
    const E = (app.addons || {}).aiEngine; if (!E) throw httpErr(424, 'the AI Engine is not installed');
    const st = B.status(); if (st.local.model !== rec.from) throw httpErr(409, 'the model was changed meanwhile (now ' + st.local.model + ') - reject this one and propose again');
    E.save({ mode: st.mode, local: { api: st.local.api, base_url: st.local.base_url, model: rec.to, timeout_s: st.local.timeout_s, max_tokens: st.local.max_tokens, tools: st.local.tools }, routes: st.routes }, who);
    Object.assign(rec, { status: 'applied', decided_by: who.user, decided_at: iso(), note: b.note || '' }); chg().put(rec);
    audit(who, 'model-change.approve', id, { from: rec.from, to: rec.to, proposed_by: rec.by });
    return rec;
  }
  // the advisor's view: numbers and named reasons only, no URL, no key
  function aiSummary() {
    const v = model();
    return { health: v.health, mode: v.mode, model: v.engine.model, host: v.engine.host, gateway: v.gateway && { ok: v.gateway.ok, ms: v.gateway.ms, error: v.gateway.error, server: v.gateway.server, models: v.gateway.models, loaded: v.gateway.loaded },
      availability: v.availability, calls: Object.assign({}, v.calls, { features: v.calls.features.slice(0, 10) }), server: v.server, pending_model_change: v.changes.pending[0] ? { to: v.changes.pending[0].to, by: v.changes.pending[0].by } : null };
  }
  const K = createIntelKit(app, { key: 'private-ai', feature: 'itam.private-ai-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: true,
    system: ('You are the AI infrastructure engineer for ' + ZYB_ORG.name + '. You read the health of the company\'s own AI server (its model gateway, GPUs, disk, memory, the latency and failures of the AI calls the platform made) through the ai_server_health tool and write a short briefing for the platform administrators: what is wrong now and its likely cause, what is trending towards a limit and when, and the one action for each. Use only what the tool returns; say plainly what is not measured. You cannot change anything: a model change is proposed on the page and approved by a second administrator.'),
    tools: [{ name: 'ai_server_health', description: 'Health of the private AI server: score with named deductions and not-measured items, gateway, models served and loaded, availability and outages, AI call latency / failures / speed against the usual, GPU / CPU / memory / disk, forecasts, pending model change.', run: async () => aiSummary() }] });
  // the poll loop: guarded, rescheduled in finally
  const RUN = { timer: null, stopped: false };
  const g = guardOf(app, 'private-ai.poll', poll);
  function loop() { RUN.timer = setTimeout(async () => { try { await g(); } finally { if (!RUN.stopped) loop(); } }, cfg().poll_s * 1000); if (RUN.timer.unref) RUN.timer.unref(); }
  function start() { if (opts.noTimer || app.noTimers || RUN.timer) return; RUN.stopped = false; loop(); }
  function restart() { if (!RUN.timer) return; clearTimeout(RUN.timer); RUN.timer = null; start(); }
  function stop() { RUN.stopped = true; if (RUN.timer) clearTimeout(RUN.timer); RUN.timer = null; persist(); unlisten(); }
  return { view, model, poll, pollNow, saveConfig, propose, decide, aiSummary, ask: K.ask, TOOLS: K.TOOLS, start, stop, _state: S };
}

function registerPrivateAi(srv, app, X0) {
  const X = X0 && X0.view ? X0 : createPrivateAi(app, X0 || {});
  (app.addons = app.addons || {}).privateAi = X;
  srv.route('GET', '/private-ai', (ctx) => { ctx.need('operator'); return X.view(ctx.who); });
  srv.route('PUT', '/private-ai/config', (ctx) => { ctx.need('admin'); return X.saveConfig(ctx.body, ctx.who); });
  srv.route('POST', '/private-ai/poll', async (ctx) => { ctx.need('admin'); return X.pollNow(ctx.who); });
  srv.route('POST', '/private-ai/model-change', (ctx) => { ctx.need('admin'); return X.propose(ctx.body, ctx.who); });
  srv.route('POST', '/private-ai/model-change/:id/decide', async (ctx) => { ctx.need('admin'); return X.decide(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/private-ai/ask', (ctx) => { ctx.need('operator'); return X.ask(ctx.body, ctx.who); }, { maxBody: 8192 });
  X.start();
  return X;
}
module.exports = { createPrivateAi, registerPrivateAi, parseProm, readMetrics, forecast, wilson };
