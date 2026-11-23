// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI job queue (same shape as sentra-grcai): one job at a time, FIFO, at most config.ai.max_queue waiting. Caps checked
// at start: settings-less daily_cap (config.ai.daily_cap, Asia/Riyadh day) and per-user hourly cap. Every call is
// logged (collection `aicalls` + hash-chained audit, with the sanitised system+prompt). Prompts live in memory only;
// a restart fails queued jobs with code "interrupted".
const crypto = require('node:crypto');
const { sanitisePair } = require('./sanitise');

const DAY_OFFSET_MS = 3 * 3600 * 1000; // Asia/Riyadh, UTC+3
const dayKey = (ms) => new Date(ms + DAY_OFFSET_MS).toISOString().slice(0, 10);
const newId = (p) => `${p}_${crypto.randomBytes(6).toString('hex')}`;
const NOT_SENT = new Set(['cap', 'not_configured', 'external_not_allowed', 'disabled', 'ai_service_down', 'bad_url']);

function createJobs({ store, provider, getSettings, config, log, audit, onResult }) {
  const jobs = store.collection('jobs');
  const calls = store.collection('aicalls');
  const maxQueue = (config.ai && config.ai.max_queue) || 20;
  const perUser = (config.ai && config.ai.per_user_hourly_cap) || 20;
  const dailyCap = (config.ai && config.ai.daily_cap) || 60;
  const queue = []; let running = null; let stopped = false;
  const idleWaiters = [];

  for (const j of jobs.all((x) => x.status === 'queued' || x.status === 'running')) {
    jobs.patch(j.id, (o) => { o.status = 'failed'; o.error = { code: 'interrupted', message: 'The service restarted before this job finished — run it again.' }; o.finished_at = new Date().toISOString(); });
  }

  function callsToday(now = Date.now()) { const d = dayKey(now); return calls.all((c) => c.sent && dayKey(Date.parse(c.at)) === d).length; }
  function userCallsLastHour(user, now = Date.now()) { return calls.all((c) => c.sent && c.user === user && now - Date.parse(c.at) < 3600000).length; }

  function enqueue({ feature, user, role, prepared }) {
    if (queue.length >= maxQueue) { const e = new Error(`The AI queue is full (${maxQueue} jobs waiting) — try again later.`); e.status = 429; e.code2 = 'queue_full'; throw e; }
    const job = { id: newId('job'), feature, status: 'queued', user, role, title: prepared.meta && prepared.meta.title, created_at: new Date().toISOString(), started_at: null, finished_at: null, result_ref: null, error: null };
    jobs.put(job);
    queue.push({ id: job.id, prepared });
    setImmediate(pump);
    return job;
  }
  function finish(id, patch) { return jobs.patch(id, (o) => Object.assign(o, patch, { finished_at: new Date().toISOString() })); }

  function logCall(job, entry, pair) {
    const rec = Object.assign({ id: newId('call'), at: new Date().toISOString(), feature: job.feature, user: job.user, job_id: job.id, prompt_sha256: pair ? pair.prompt_sha256 : null, system_sha256: pair ? pair.system_sha256 : null, in_chars: pair ? pair.system.length + pair.prompt.length : 0, prompt_head: pair ? pair.prompt.slice(0, 2048) : '' }, entry);
    rec.sent = !NOT_SENT.has(rec.status) && !NOT_SENT.has(rec.code);
    calls.put(rec);
    audit({ by: job.user, role: job.role, action: 'ai.call', target: job.id, detail: { call_id: rec.id, feature: job.feature, status: rec.status, code: rec.code || null, model: rec.model || null, tokens_in: rec.tokens_in || 0, tokens_out: rec.tokens_out || 0, system_sha256: rec.system_sha256, prompt_sha256: rec.prompt_sha256, in_chars: rec.in_chars } });   // hashes, never the prompt text: the audit trail is kept for years and the prompt names people (PDPL)
    return rec;
  }

  async function runOne(entry) {
    const { id, prepared } = entry;
    const job = jobs.patch(id, (o) => { o.status = 'running'; o.started_at = new Date().toISOString(); });
    if (callsToday() >= dailyCap) { logCall(job, { status: 'cap', code: 'cap', model: null }, null); return finish(id, { status: 'failed', error: { code: 'cap', message: `Daily cap of ${dailyCap} AI calls reached — resets at midnight (Riyadh).` } }); }
    if (userCallsLastHour(job.user) >= perUser) { logCall(job, { status: 'cap', code: 'cap', model: null }, null); return finish(id, { status: 'failed', error: { code: 'cap', message: `Per-user cap of ${perUser} AI calls per hour reached — try again later.` } }); }
    const settings = getSettings();
    // masked by Python too when it answers identically (engine/ai/guard-py.js, step 9j-a); otherwise sanitise.js, as before
    let pair; try { pair = await require('./guard-py').guardFor(config).sanitisePair(prepared.system, prepared.prompt, settings.redact_terms); } catch (e) { pair = sanitisePair(prepared.system, prepared.prompt, settings.redact_terms); }
    const t0 = Date.now(); let res;
    try { res = await provider.call({ system: pair.system, prompt: pair.prompt, who: { user: job.user }, feature: 'itam.' + job.feature }); } catch (e) { res = { ok: false, code: 'internal', message: 'The AI call failed unexpectedly.' }; log.error('jobs: provider threw', { err: e.message }); }
    if (res && res.sent_prompt_sha256) pair = Object.assign({}, pair, { prompt_sha256: res.sent_prompt_sha256, system_sha256: res.sent_system_sha256 });   // log what was sent
    const call = logCall(job, { status: res.ok ? 'ok' : res.code === 'refusal' ? 'refusal' : 'error', code: res.ok ? null : res.code, model: res.model || null, ms: Date.now() - t0, out_chars: res.text ? res.text.length : 0, tokens_in: res.usage ? res.usage.input : 0, tokens_out: res.usage ? res.usage.output : 0, truncated: !!res.truncated }, pair);
    if (!res.ok) return finish(id, { status: 'failed', error: { code: res.code, message: res.message } });
    try {
      const ref = await onResult(jobs.get(id), prepared, res, { call_id: call.id });
      calls.patch(call.id, (o) => { o.result_ref = ref; });
      return finish(id, { status: 'done', result_ref: ref });
    } catch (e) { log.error('jobs: storing the AI result failed', { job: id, err: e.message }); return finish(id, { status: 'failed', error: { code: 'internal', message: 'The AI answer could not be stored.' } }); }
  }

  async function pump() {
    if (running || stopped) return;
    const next = queue.shift();
    if (!next) { while (idleWaiters.length) idleWaiters.shift()(); return; }
    running = next.id;
    try { await runOne(next); } catch (e) { log.error('jobs: job crashed', { job: next.id, err: e.message }); try { finish(next.id, { status: 'failed', error: { code: 'internal', message: 'internal error' } }); } catch { /* ignore */ } }
    running = null; setImmediate(pump);
  }

  function view(j, includeUser) {
    if (!j) return null;
    const pos = queue.findIndex((q) => q.id === j.id);
    const v = { id: j.id, feature: j.feature, status: j.status, title: j.title || null, created_at: j.created_at, started_at: j.started_at, finished_at: j.finished_at, result_ref: j.result_ref || null, error: j.error ? j.error.message : null, code: j.error ? j.error.code : null, position: pos >= 0 ? pos + 1 : null };
    if (includeUser) v.user = j.user;
    return v;
  }

  return {
    enqueue, view, get: (id) => jobs.get(id), list: (filter) => jobs.all(filter),
    queueInfo: () => ({ queued: queue.length, running: running ? 1 : 0, max: maxQueue }),
    callsToday, userCallsLastHour, dailyCap, perUser,
    idle: () => new Promise((r) => { if (!running && !queue.length) r(); else idleWaiters.push(r); }),
    stop() { stopped = true; },
  };
}

module.exports = { createJobs, dayKey };
