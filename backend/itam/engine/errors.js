// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/* errors.js - one place where every failure of the platform is caught, counted and shown (the same file in sentra-itam
 * engine/errors.js and sentra-siem engine/util/errors.js).
 *
 *   guard(name, fn)     wraps a background job (a setInterval / setTimeout callback, a scheduler tick): a throw or a rejected
 *                       promise is logged (once a minute per job, so a broken job cannot flood the log), counted and kept as
 *                       the job's last error. It never reaches the process, so one broken job cannot stop the engine or the
 *                       other jobs. A job that swallowed its own errors before now returns them, so they are seen here.
 *   recordServer(..)    an HTTP handler that failed with a 5xx (the caller got "internal error"; the detail is kept here)
 *   recordClient(..)    an error a dashboard page reported (uncaught error, unhandled promise, failed request)
 *   process(proc, ..)   unhandledRejection is logged and kept; uncaughtException is logged, kept, the state is flushed and
 *                       the process exits 1 so systemd starts a clean one (a process after an uncaught exception is in an
 *                       unknown state - carrying on would be worse than a restart of a few seconds)
 *   view()              what Platform Health shows an administrator: every job with runs / failures / last error, the
 *                       latest server and page errors. Messages are cut to 300 characters; no request body, no stack to the
 *                       browser (stacks stay in the log), no query string (it can carry names / search terms - PDPL).
 */
const MAX = 200;

// error text is shown to administrators on Platform Health: a credential inside a message (a URL with user:password, a
// token in an exception) is masked first (ai-guard.js redactSecrets)
function msgOf(e) {
  const red = (t) => { try { return require('./ai-guard').redactSecrets(t); } catch (x) { return t; } };
  if (e === undefined || e === null) return 'unknown error';
  if (typeof e === 'string') return red(e).slice(0, 300);
  return red(String((e && (e.message || e.code)) || e)).slice(0, 300);
}
function stackOf(e) { return e && e.stack ? String(e.stack).split('\n').slice(0, 6).join('\n') : undefined; }
const clip = (s, n) => String(s === undefined || s === null ? '' : s).replace(/[\u0000-\u001f\u007f]+/g, ' ').slice(0, n);

function createErrors(opts = {}) {
  let log = opts.log || { error() {}, warn() {}, every() {} };
  const now = opts.now || Date.now;
  const iso = () => new Date(now()).toISOString();
  const jobs = new Map(), server = [], client = [], proc = { unhandled: 0, uncaught: 0, last: null };
  const push = (arr, x) => { arr.unshift(x); if (arr.length > MAX) arr.length = MAX; };
  const every = (key, lvl, msg, fields) => { if (typeof log.every === 'function') log.every(key, 60000, lvl, msg, fields); else if (log[lvl]) log[lvl](msg, fields); };

  function job(name) {
    let j = jobs.get(name);
    if (!j) { j = { name, runs: 0, failures: 0, consecutive: 0, running: 0, last_run: null, last_ok: null, last_error: null, last_error_at: null }; jobs.set(name, j); }
    return j;
  }
  function fail(j, e) {
    j.failures++; j.consecutive++; j.last_error = msgOf(e); j.last_error_at = iso();
    every('job:' + j.name, 'error', 'background job failed - it keeps running on its schedule', { job: j.name, failures: j.failures, consecutive: j.consecutive, err: j.last_error, stack: stackOf(e) });
  }
  function ok(j) { j.consecutive = 0; j.last_ok = iso(); }

  /* the wrapper keeps the job's return value, so callers that await it still can; a failure resolves to undefined */
  function guard(name, fn) {
    if (typeof fn !== 'function') throw new TypeError('guard(' + name + '): not a function');
    const j = job(String(name));
    const wrapped = function () {
      j.runs++; j.last_run = iso(); j.running++;
      let r;
      try { r = fn.apply(this, arguments); } catch (e) { j.running--; fail(j, e); return undefined; }
      if (r && typeof r.then === 'function') return r.then((v) => { j.running--; ok(j); return v; }, (e) => { j.running--; fail(j, e); return undefined; });
      j.running--; ok(j); return r;
    };
    wrapped.job = j.name;
    return wrapped;
  }
  /* a job that runs on its own (not through guard) reports a failure / success here */
  function report(name, e) { const j = job(String(name)); j.runs++; j.last_run = iso(); if (e) fail(j, e); else ok(j); }

  function recordServer(x) {
    push(server, { at: iso(), method: clip(x.method, 10), path: clip(String(x.path || '').split('?')[0], 200), status: Number(x.status) || 500, error: msgOf(x.err) });
  }
  /* page errors: one user may report at most 30 a minute (a page in a loop must not fill the list) */
  const rate = new Map();
  function recordClient(b, who) {
    b = b && typeof b === 'object' ? b : {};
    const user = clip(who && who.user, 120) || '-', t = now();
    const r = rate.get(user) || { at: t, n: 0 }; if (t - r.at > 60000) { r.at = t; r.n = 0; }
    r.n++; rate.set(user, r); if (rate.size > 2000) rate.clear();
    if (r.n > 30) return { ok: false, limited: true };
    const kind = /^(error|rejection|http|network|timeout|session)$/.test(String(b.kind)) ? String(b.kind) : 'error';
    const rec = { at: iso(), user, role: clip(who && who.role, 20), kind, page: clip(String(b.page || '').split(/[?#]/)[0], 160),
      message: msgOf(clip(b.message, 300)), status: Number.isInteger(b.status) ? b.status : null, url: clip(String(b.url || '').split('?')[0], 200), ref: clip(b.ref, 24),
      source: clip(String(b.source || '').split('?')[0], 160), line: Number.isInteger(b.line) ? b.line : null };
    push(client, rec);
    every('client:' + rec.page + ':' + kind, 'warn', 'page error reported by a browser', { page: rec.page, kind, user, message: rec.message, status: rec.status, url: rec.url, ref: rec.ref });
    return { ok: true, ref: rec.ref };
  }

  // graceMs: how long the fatal path may take to save state before the forced exit - at least as long as the engine's own
  // shutdown (the SIEM flushes the writer, the detector state and the snapshot within 25 s)
  function processHandlers(p, onFatal, popts = {}) {
    const graceMs = Number(popts.graceMs) > 0 ? Number(popts.graceMs) : 10000;
    p.on('unhandledRejection', (e) => {
      proc.unhandled++; proc.last = { at: iso(), kind: 'unhandledRejection', error: msgOf(e) };
      every('unhandledRejection', 'error', 'unhandled promise rejection (caught by the safety net, the engine keeps running)', { err: msgOf(e), stack: stackOf(e) });
    });
    p.on('uncaughtException', (e) => {
      proc.uncaught++; proc.last = { at: iso(), kind: 'uncaughtException', error: msgOf(e) };
      try { (log.fatal || log.error).call(log, 'uncaught exception - saving state and restarting', { err: msgOf(e), stack: stackOf(e) }); } catch { /* the exit below still happens */ }
      let done = false; const exit = () => { if (!done) { done = true; p.exit(1); } };
      setTimeout(exit, graceMs).unref();
      try { Promise.resolve(onFatal && onFatal(e)).then(exit, exit); } catch { exit(); }
    });
  }

  function view() {
    const list = [...jobs.values()].map((j) => Object.assign({}, j, { state: j.consecutive >= 3 ? 'failing' : j.consecutive ? 'last run failed' : j.last_ok ? 'ok' : j.runs ? 'running' : 'not run yet' }))
      .sort((a, b) => b.consecutive - a.consecutive || b.failures - a.failures || a.name.localeCompare(b.name));
    return { at: iso(), jobs: list, failing: list.filter((j) => j.consecutive).length, server: server.slice(0, 100), client: client.slice(0, 100), process: Object.assign({}, proc) };
  }
  return { guard, report, recordServer, recordClient, processHandlers, view, setLog: (l) => { if (l) log = l; }, _jobs: jobs };
}

/* one register for the whole process, for modules that are not handed the app (the SIEM collectors and pollers): main.js
   gives it the logger at start; a module may guard its jobs before that, its failures are kept all the same */
let SHARED = null;
function shared() { if (!SHARED) SHARED = createErrors(); return SHARED; }

/* guard a job when the app has the error register; unchanged otherwise (an old main.js, a test without it) */
/* an engine whose main.js predates this file (main.js is patched on the server by the add-on installers) gets its register
   and the Platform Health route from the first add-on that guards a job */
function guardOf(app, name, fn) {
  if (!app || typeof fn !== 'function') return fn;
  if (!app.errors && app.srv && typeof app.srv.route === 'function') {
    try { app.errors = createErrors({ log: app.log }); registerErrorRoutes(app.srv, app); } catch (e) { return fn; }
  }
  if (app.errors && typeof app.errors.guard === 'function') return app.errors.guard(name, fn);
  // no register at all (a bare test app, an engine without routes): still never let the job reject unhandled
  const lg = app.log || { error() {} };
  return function () { try { const r = fn.apply(this, arguments); return r && typeof r.then === 'function' ? r.catch((e) => { lg.error('background job failed', { job: name, err: msgOf(e) }); }) : r; } catch (e) { lg.error('background job failed', { job: name, err: msgOf(e) }); return undefined; } };
}
const guard = (name, fn) => shared().guard(name, fn);

/* GET  /platform/errors          admin: jobs, latest server and page errors, process safety-net counts
   POST /platform/client-errors   any signed-in role: a page reports an error it caught (zyb-errors.js) */
function registerErrorRoutes(srv, app) {
  srv.route('GET', '/platform/errors', (ctx) => { ctx.need('admin'); return app.errors.view(); });
  // AI use today: calls, tokens, refusals and prompt-injection flags per person (engine/ai-guard.js)
  srv.route('GET', '/platform/ai-usage', (ctx) => { ctx.need('admin'); return require('./ai-guard').sharedBudget({ log: app.log, limits: () => ((app.config && app.config.ai) || {}).limits || {} }).view(); });
  srv.route('POST', '/platform/client-errors', (ctx) => app.errors.recordClient(ctx.body, ctx.who), { maxBody: 8192, anyRole: 'every signed-in page reports its own errors; rate-limited per user' });
}

module.exports = { createErrors, shared, guard, guardOf, registerErrorRoutes, msgOf };
