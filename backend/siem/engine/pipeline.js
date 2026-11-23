// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Event pipeline: createPipeline({log}) → { use(stageFn, name?), emit(event), stats() }.
// Stages run synchronously in registration order and may mutate the event. A stage that throws (or returns a
// rejected promise) is counted and logged (throttled) — the event still continues to the next stage; it is never dropped.
const { performance } = require('node:perf_hooks');

function createPipeline({ log } = {}) {
  const stages = [];
  let events = 0;
  const secs = new Array(60).fill(0);
  const secKeys = new Array(60).fill(0);

  function stageError(s, err, isAsync) {
    s.errors++;
    s.last_error = String((err && err.message) || err).slice(0, 300);
    if (log) log.every('pipeline-stage-' + s.name, 10000, 'error', 'pipeline stage failed', { stage: s.name, async: !!isAsync, err });
  }

  function use(fn, name) {
    if (typeof fn !== 'function') throw new TypeError('pipeline stage must be a function');
    stages.push({ fn, name: name || fn.name || 'stage' + stages.length, calls: 0, errors: 0, total_ms: 0, max_ms: 0, last_error: '' });
    return api;
  }

  function emit(ev) {
    events++;
    const sec = Math.floor(Date.now() / 1000);
    const slot = sec % 60;
    if (secKeys[slot] !== sec) { secKeys[slot] = sec; secs[slot] = 0; }
    secs[slot]++;
    for (let i = 0; i < stages.length; i++) {
      const s = stages[i];
      const t0 = performance.now();
      try {
        const r = s.fn(ev);
        if (r && typeof r.then === 'function') r.then(null, (e) => stageError(s, e, true));
      } catch (e) {
        stageError(s, e, false);
      }
      const dt = performance.now() - t0;
      s.calls++;
      s.total_ms += dt;
      if (dt > s.max_ms) s.max_ms = dt;
    }
    return ev;
  }

  function eps(windowS) {
    const now = Math.floor(Date.now() / 1000);
    let n = 0;
    for (let i = 1; i <= windowS; i++) { const k = now - i; const slot = k % 60; if (secKeys[slot] === k) n += secs[slot]; }
    return n / windowS;
  }

  function stats() {
    return {
      events,
      eps_10s: Math.round(eps(10) * 10) / 10,
      eps_1m: Math.round(eps(59) * 10) / 10,
      stages: stages.map((s) => ({
        name: s.name, calls: s.calls, errors: s.errors,
        avg_us: s.calls ? Math.round((s.total_ms / s.calls) * 1000 * 10) / 10 : 0,
        max_us: Math.round(s.max_ms * 1000),
        total_ms: Math.round(s.total_ms),
        last_error: s.last_error || undefined,
      })),
    };
  }

  const api = { use, emit, stats, eps };
  return api;
}

module.exports = { createPipeline };
