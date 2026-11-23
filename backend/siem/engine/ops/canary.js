// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * SIEM pipeline canary and Pipeline Health. Proves, continuously, that what reaches the SIEM is read, analysed and alerted on - not
 * only that the dashboards are quiet.
 *
 * Every `every_min` minutes (default 15) one harmless, clearly labelled test line - an RFC 5424 syslog line from host
 * "siem-canary", event code ZYB-CANARY, with a run id - goes through the REAL path:
 *   parse    the engine's own parser (engine/parse) turns it into an event
 *   pipeline the live pipeline (enrich -> sources -> detect -> store -> tail), the same emit() every collector uses
 *   alert    the built-in rule SENTRA-OPS-900 (detect/rules/platform-health.json) must raise an alert for that run id
 *   store    the event must be searchable in the event store (ClickHouse) by its run id
 * within `alert_within_s` (default 300 s). Each stage's time is recorded. The canary alert is closed at once as benign by
 * system:canary, and the analyst views (Alert Queue, Overview) leave rule SENTRA-OPS-900 out, so it never reaches an analyst.
 * A run that misses a stage is FAILED and names the stage; the last runs say whether the pipeline is healthy, degraded (some runs
 * failed in 24 h) or failing (the latest run failed or no run for 3 intervals - the canary itself stopped).
 * What it does NOT prove: that each collector and network path is up (the Log Sources page and the "log source went silent" rule
 * cover each source) - the canary enters at the parser, after the network listener.
 * Telling people when it fails does not depend on the SIEM: IT Asset Management (engine/pipeline-health.js there) reads
 * GET /ops/pipeline every 5 minutes and raises a platform incident in Notification & Escalation - also when the SIEM does not answer.
 *   GET  {P}/ops/pipeline           any signed-in user   status, last run with its stages, 24 h runs, latency, intake, stage errors
 *   POST {P}/ops/pipeline/run       operator             run the canary now (waits for the result, at most alert_within_s)  audited
 *   PUT  {P}/ops/pipeline/settings  admin                {enabled, every_min 5-60, alert_within_s 60-900}                 audited
 */
const crypto = require('node:crypto');
const { guard } = require('../util/errors');
const { body } = require('../util/check');
const { wrap, audit, prefixOf, HttpError } = require('../soc/routeutil');

const RULE = 'SENTRA-OPS-900', HOST = 'siem-canary', CODE = 'ZYB-CANARY', MIN = 60000, KEEP = 1000;
const isClosed = (s) => typeof s === 'string' && s.startsWith('closed-');
const q = (a, p) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y); return b[Math.min(b.length - 1, Math.floor(p * (b.length - 1) + 0.5))]; };

function createCanary(deps = {}) {
  const { state, parser, pipeline, alerts, search } = deps;
  const L = deps.log || { info() {}, warn() {}, error() {}, every() {} };
  const now = deps.now || Date.now, sleep = deps.sleep || ((ms) => new Promise((r) => { const t = setTimeout(r, ms); if (t.unref) t.unref(); }));
  const runs = state.collection('siem_canary_runs'), cfgC = state.collection('siem_canary_cfg');
  const settings = () => Object.assign({ enabled: true, every_min: 15, alert_within_s: 300 }, ((deps.config || {}).canary) || {}, (cfgC.get('cfg') || {}).v || {});
  let running = null;

  function findAlert(id) {
    const L0 = typeof alerts.all === 'function' ? alerts.all((a) => a.rule_id === RULE) : [];
    return L0.find((a) => (a.group && a.group['fields.canary_run'] === id) || (a.fields && a.fields.canary_run === id) || String(a.group_key || '').includes(id) || String(a.summary || '').includes(id)) || null;
  }
  async function stored(id, t0) {
    if (!search || typeof search.search !== 'function') return null;
    const r = await search.search({ q: 'host:' + HOST + ' AND event_code:' + CODE + ' AND "' + id + '"', from: t0 - MIN, to: now() + MIN, limit: 1, fields: ['ts'] });
    return r && r.rows && r.rows.length ? true : false;
  }

  async function run(by) {
    if (running) return running;
    running = (async () => {
      // the run id carries a random part: two runs in the same millisecond must never find each other's alert
      const s = settings(), t0 = now(), id = 'CNY-' + t0.toString(36).toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase(), stages = [];
      const stage = (name, ok, ms, detail) => stages.push({ stage: name, ok, ms: ms == null ? null : Math.round(ms), detail: detail || null });
      const before = pipeline && typeof pipeline.stats === 'function' ? pipeline.stats() : null;
      let ev = null;
      try {
        const line = '<14>1 ' + new Date(t0).toISOString() + ' ' + HOST + ' zyb-canary - - - ' + JSON.stringify({ event_code: CODE, message: (ZYB_ORG.short + ' SIEM pipeline canary ') + id + ' - a test, not an attack', canary_run: id, category: 'other', severity: 0 });
        ev = parser.parse(line, { src_type: 'json', src_id: HOST, collector: 'canary', rts: t0 });
        const okParse = ev && ev.event_code === CODE && ev.fields && ev.fields.canary_run === id;
        stage('parse', !!okParse, now() - t0, okParse ? null : 'the parser did not produce the canary event (event_code / run id missing)');
      } catch (e) { stage('parse', false, null, 'the parser failed: ' + String(e.message).slice(0, 200)); }
      if (stages[0].ok) {
        try { pipeline.emit(ev); const after = pipeline.stats ? pipeline.stats() : null;
          const errs = before && after ? (after.stages || []).filter((x, i) => before.stages && before.stages[i] && x.errors > before.stages[i].errors).map((x) => x.name + ': ' + x.last_error) : [];
          stage('pipeline', !errs.length, now() - t0, errs.length ? 'stage error(s): ' + errs.join('; ').slice(0, 300) : null);
        } catch (e) { stage('pipeline', false, null, 'the pipeline refused the event: ' + String(e.message).slice(0, 200)); }
      }
      if (stages.length === 2 && stages[1].ok) {
        const limit = t0 + s.alert_within_s * 1000; let alertAt = null, storeAt = null, a = null, lastErr = null;
        while (now() <= limit && (alertAt == null || storeAt == null)) {
          if (alertAt == null) { a = findAlert(id); if (a) alertAt = now(); }
          if (storeAt == null) { try { if (await stored(id, t0)) storeAt = now(); } catch (e) { lastErr = String(e.message).slice(0, 200); } }
          if (alertAt != null && storeAt != null) break;
          await sleep(deps.pollMs || 5000);
        }
        stage('alert', alertAt != null, alertAt == null ? null : alertAt - t0, alertAt == null ? 'rule ' + RULE + ' raised no alert within ' + s.alert_within_s + ' s - the detector or the alert store is not working' : null);
        stage('store', storeAt != null, storeAt == null ? null : storeAt - t0, storeAt == null ? (search ? 'the event was not searchable within ' + s.alert_within_s + ' s - the writer or the event store is not working' + (lastErr ? ' (' + lastErr + ')' : '') : 'the event store is not configured') : null);
        if (a && !isClosed(a.status)) { try { alerts.close(a.id, 'benign', 'system:canary', 'pipeline canary ' + id + ' verified - a test, not an attack'); } catch (e) { L.warn('canary: could not close its alert', { err: e.message }); } }
      }
      const ok = stages.length === 4 && stages.every((x) => x.ok), failed = stages.find((x) => !x.ok);
      const rec = { id, at: t0, done: now(), ok, by: by || 'system:canary', stages, total_ms: now() - t0, failed_stage: failed ? failed.stage : null, why: failed ? failed.detail : null };
      runs.put(rec);
      const all = runs.all().sort((x, y) => x.at - y.at); for (const x of all.slice(0, Math.max(0, all.length - KEEP))) runs.remove(x.id);
      if (!ok) L.every('canary-failed', 600000, 'error', 'SIEM pipeline canary FAILED', { run: id, stage: rec.failed_stage, why: rec.why });
      return rec;
    })();
    try { return await running; } finally { running = null; }
  }

  function view() {
    const s = settings(), t = now(), all = runs.all().sort((a, b) => b.at - a.at || (b.done || 0) - (a.done || 0)), last = all[0] || null, day = all.filter((r) => r.at >= t - 24 * 3600000);
    const stale = s.enabled && (!last || t - last.at > 3 * s.every_min * MIN + s.alert_within_s * 1000);
    const status = !s.enabled ? 'off' : !last ? 'waiting' : stale ? 'stale' : !last.ok ? 'failing' : day.some((r) => !r.ok) ? 'degraded' : 'healthy';
    const lat = (k) => day.map((r) => (r.stages.find((x) => x.stage === k) || {}).ms).filter((x) => x != null);
    const ps = pipeline && typeof pipeline.stats === 'function' ? pipeline.stats() : null;
    return { status, settings: s, last, history: all.slice(0, 96).map((r) => ({ id: r.id, at: r.at, ok: r.ok, failed_stage: r.failed_stage, total_ms: r.total_ms })),
      day: { runs: day.length, ok: day.filter((r) => r.ok).length, failed: day.filter((r) => !r.ok).length, success_pct: day.length ? Math.round(100 * day.filter((r) => r.ok).length / day.length) : null },
      latency: { alert_p50_ms: q(lat('alert'), 0.5), alert_p95_ms: q(lat('alert'), 0.95), store_p50_ms: q(lat('store'), 0.5), store_p95_ms: q(lat('store'), 0.95) },
      intake: ps ? { events_total: ps.events, eps_1m: ps.eps_1m != null ? ps.eps_1m : null, stages: (ps.stages || []).map((x) => ({ name: x.name, calls: x.calls, errors: x.errors, last_error: x.errors ? x.last_error || null : null, avg_us: x.avg_us != null ? x.avg_us : null })) } : null,
      why: status === 'stale' ? 'no canary run for ' + Math.round((t - (last ? last.at : t)) / MIN) + ' min - the canary itself is not running (engine restarting or stalled)' : status === 'failing' ? 'the latest run failed at "' + last.failed_stage + '": ' + last.why : status === 'degraded' ? day.filter((r) => !r.ok).length + ' of ' + day.length + ' runs in 24 h failed - the latest one passed' : status === 'healthy' ? 'every run in 24 h passed: parse, pipeline, alert and store' : status === 'off' ? 'the canary is switched off' : 'the first run has not finished yet',
      covers: 'parser -> pipeline (enrich, sources, detect, store, tail) -> detection rule -> alert store, and the event store search. Each collector and network path is covered by Log Sources and the "log source went silent" rule.' };
  }
  function saveSettings(b0, who) {
    const b = body(b0 || {}).bool('enabled').int('every_min', { min: 5, max: 60 }).int('alert_within_s', { min: 60, max: 900 }).done();
    const v = Object.assign({}, (cfgC.get('cfg') || {}).v || {}, b); cfgC.put({ id: 'cfg', v, by: who, at: now() });
    return settings();
  }
  // the self-rescheduling loop: guarded, rescheduled in finally
  let timer = null, stopped = false;
  const job = guard('ops.canary', async () => { if (settings().enabled) await run('system:canary'); });
  function schedule(ms) { if (stopped) return; timer = setTimeout(async () => { try { await job(); } finally { schedule(settings().every_min * MIN); } }, ms); if (timer.unref) timer.unref(); }
  function start() { if (deps.noTimers || timer) return; schedule(2 * MIN); }
  function stop() { stopped = true; if (timer) clearTimeout(timer); }
  return { run, view, saveSettings, start, stop, RULE };
}

function register(api, deps) {
  if (!deps.state || !deps.parser || !deps.pipeline || !deps.alerts) return;
  const P = prefixOf(deps), K = createCanary(deps);
  deps.canary = K;
  api.route('GET', `${P}/ops/pipeline`, wrap(deps, null, (ctx) => ctx.ok(K.view())));
  api.route('POST', `${P}/ops/pipeline/run`, wrap(deps, 'operator', async (ctx) => {
    body(ctx.body || {}).done();
    const r = await K.run(ctx.user);
    audit(ctx, 'ops.canary.run', r.id, { ok: r.ok, failed_stage: r.failed_stage });
    return ctx.ok(r);
  }));
  api.route('PUT', `${P}/ops/pipeline/settings`, wrap(deps, 'admin', (ctx) => {
    const r = K.saveSettings(ctx.body, ctx.user);
    audit(ctx, 'ops.canary.settings', 'canary', r);
    return ctx.ok({ settings: r });
  }));
  K.start();
}

module.exports = { register, createCanary, RULE };
