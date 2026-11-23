// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// HTTP API server (127.0.0.1 only; nginx in front does the portal session check and sets X-Auth-User / X-Auth-Role).
//   createApi({port, host, log, audit?, dataDir?, maxBody?}) → { route(method, pattern, handler, opts?), start(), stop(), setAudit(fn), address() }
//   pattern: '/api/soc/alerts/:id' (":name" = one path segment, trailing "*" = rest of path → params['*'])
//   handler(ctx) with ctx = { method, path, params, query, body, rawBody, headers, user, role, ip,
//                             ok(obj), fail(code, message, errors?), need(role), audit(action, target, detail), sse(), req, res }
//   - a handler may also just `return obj` (→ ok(obj)); throwing an error with .status → fail(status, message)
//   - ctx.need('operator'|'admin') throws 403 unless the caller's role is sufficient (viewer < analyst < operator < admin)
//   - ctx.audit(...) appends {at, by, role, ip, action, target, detail} via the injectable audit function
//     (default: JSON line appended to <dataDir>/state/audit.jsonl)
//   - opts.raw: skip JSON parsing (ctx.body = null, use ctx.rawBody); opts.maxBody: per-route body limit (bytes)
//   - opts.preAuth(ctx): checked from the headers before the body is read; must return true (or reply and return false)
// Proxy secret: every request below `protectPrefix` (/api/soc) must carry X-Sentra-Proxy-Secret equal to `proxySecret`
// (secrets.json proxy_secret; nginx adds the header). Otherwise X-Auth-User / X-Auth-Role are ignored and the request is
// refused with 401 — except {protectPrefix}/health, which stays readable (without identity) for local diagnostics.
// When no proxy secret is configured at all, every protected request except /health is refused.
// Paths outside the prefix (e.g. /ingest/<src_id>, which has its own per-source token) are not affected.
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROLE_RANK = Object.freeze(Object.assign(Object.create(null), { viewer: 1, readonly: 1, analyst: 2, operator: 3, admin: 4 }));   // no prototype: "constructor" / "__proto__" are not roles

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; this.name = 'HttpError'; }
}

function compilePattern(pattern) {
  const parts = pattern.replace(/\/+$/, '').split('/').filter((p, i) => i === 0 || p !== '');
  const keys = [];
  let re = '^';
  for (let i = 1; i < parts.length; i++) {
    const p = parts[i];
    if (p === '*' && i === parts.length - 1) { re += '(?:/(.*))?'; keys.push('*'); continue; }
    if (p.startsWith(':')) { re += '/([^/]+)'; keys.push(p.slice(1)); continue; }
    re += '/' + p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return { re: new RegExp(re + '/?$'), keys };
}

const digest = (s) => crypto.createHash('sha256').update(String(s)).digest();

// Audit entries stay bounded: a request body echoed into `detail` could otherwise be megabytes per line.
const MAX_DETAIL = 4096;
function boundDetail(detail) {
  if (detail === undefined) return null;
  let s;
  try { s = JSON.stringify(detail); } catch { return { unserialisable: true }; }
  if (s === undefined || s.length <= MAX_DETAIL) return detail;
  return { truncated: true, bytes: s.length, preview: s.slice(0, MAX_DETAIL) };
}
// What a data read asked for (query, time range, field), never the results.
function readDetail(src) {
  const o = src && typeof src === 'object' ? src : {};
  const pick = (v) => (v === undefined || v === null ? undefined : String(v).slice(0, 500));
  return { q: pick(o.q), from: pick(o.from), to: pick(o.to), field: pick(o.field), limit: pick(o.limit) };
}

// a JSON key that could reach Object.prototype through a later Object.assign / spread is refused outright (400)
// the reviver runs only when the raw text contains such a key (a reviver makes a large body ~5x slower to parse)
const PROTO_KEY = /"(__proto__|constructor|prototype)"\s*:|\\u/;   // \\u: an escaped key ("\\u005f_proto__") parses to the same key
function noProtoKeys(k, v) { if (k === '__proto__' || k === 'constructor' || k === 'prototype') throw Object.assign(new Error('proto key'), { protoKey: k }); return v; }

function createApi({ port = 9120, host = '127.0.0.1', log, audit, dataDir = '/var/lib/sentra-siem', maxBody = 5 * 1024 * 1024, trustProxy = true, proxySecret = null, protectPrefix = '/api/soc', onError = null } = {}) {
  const secretDigest = typeof proxySecret === 'string' && proxySecret.length >= 16 ? digest(proxySecret) : null;
  if (proxySecret && !secretDigest && log) log.error('api: proxy_secret is shorter than 16 characters — treated as not configured');
  if (!secretDigest && log) log.error('api: no proxy_secret configured in secrets.json — all /api/soc requests except /api/soc/health will be refused');
  function proxyOk(v) {
    if (!secretDigest) return false;
    return crypto.timingSafeEqual(digest(v === undefined ? '' : Array.isArray(v) ? v[0] : v), secretDigest);
  }
  const routes = [];
  const inflight = new Map();   // duplicate-submission guard (see handle)
  const sseClients = new Set();
  let server = null;
  let auditFn = audit || defaultAudit;
  let auditReady = false;
  const st = { requests: 0, errors_5xx: 0, errors_4xx: 0, sse_open: 0 };

  function defaultAudit(entry) {
    const file = path.join(dataDir, 'state', 'audit.jsonl');
    if (!auditReady) { fs.mkdirSync(path.dirname(file), { recursive: true }); auditReady = true; }
    fs.appendFileSync(file, JSON.stringify(entry) + '\n');
  }

  // access gates (approvers/routes.js: an engineer job role may call only its own routes): gate(ctx) answers null to let the
  // request through, or a reason to refuse it with 403; they run on every identified request below the protected prefix
  const gates = [];
  function route(method, pattern, handler, opts = {}) {
    if (typeof handler !== 'function') throw new TypeError('route handler must be a function');
    const { re, keys } = compilePattern(pattern);
    routes.push({ method: String(method).toUpperCase(), pattern, re, keys, handler, opts });
  }

  function match(method, p) {
    let pathMatched = false;
    for (const r of routes) {
      const m = r.re.exec(p);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== method && !(method === 'HEAD' && r.method === 'GET')) continue;
      const params = {};
      r.keys.forEach((k, i) => { let v = m[i + 1]; if (v !== undefined) { try { v = decodeURIComponent(v); } catch { /* keep raw */ } } params[k] = v; });
      return { r, params };
    }
    return pathMatched ? { methodMismatch: true } : null;
  }

  function readBody(req, limit) {
    return new Promise((resolve, reject) => {
      const len = Number(req.headers['content-length'] || 0);
      if (len > limit) { reject(new HttpError(413, `body too large (max ${limit} bytes)`)); req.resume(); return; }
      const chunks = [];
      let size = 0;
      let failed = false;
      req.on('data', (c) => {
        if (failed) return;
        size += c.length;
        if (size > limit) { failed = true; reject(new HttpError(413, `body too large (max ${limit} bytes)`)); req.resume(); return; }
        chunks.push(c);
      });
      req.on('end', () => { if (!failed) resolve(Buffer.concat(chunks)); });
      req.on('error', (e) => { if (!failed) reject(e); });
    });
  }

  function clientIp(req) {
    const peer = String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
    if (trustProxy && (peer === '127.0.0.1' || peer === '::1')) {
      const xr = req.headers['x-real-ip'];

      if (xr) return String(xr).trim();
      const xff = req.headers['x-forwarded-for'];
      if (xff) return String(xff).split(',')[0].trim();
    }
    return peer;
  }

  function send(res, code, obj) {
    if (res.headersSent || res.writableEnded) return;
    const body = JSON.stringify(obj === undefined ? {} : obj);
    res.writeHead(code, {
      'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body),
      'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    });
    res.end(body);
  }

  async function handle(req, res) {
    st.requests++;
    const t0 = Date.now();
    let url;
    try { url = new URL(req.url, 'http://localhost'); } catch { st.errors_4xx++; return send(res, 400, { error: 'bad url' }); }
    const p = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, '') : url.pathname;
    const method = req.method.toUpperCase();
    let trusted = false; // identity headers are never trusted outside the protected prefix
    if (protectPrefix && (p === protectPrefix || p.startsWith(protectPrefix + '/'))) {
      trusted = proxyOk(req.headers['x-sentra-proxy-secret']);
      if (!trusted && p !== protectPrefix + '/health') {
        st.errors_4xx++;
        st.proxy_rejected = (st.proxy_rejected || 0) + 1;
        if (log) log.every('api-proxy-secret', 60000, secretDigest ? 'warn' : 'error', secretDigest ? 'api: request without a valid X-Sentra-Proxy-Secret refused' : 'api: request refused — no proxy_secret configured', { ip: String(req.socket.remoteAddress || ''), path: p });
        req.resume();
        return send(res, 401, { error: 'missing or invalid proxy credentials', errors: ['missing or invalid proxy credentials'] });
      }
    }
    const hit = match(method, p);
    if (!hit) { st.errors_4xx++; req.resume(); return send(res, 404, { error: 'not found' }); }
    if (hit.methodMismatch) { st.errors_4xx++; req.resume(); return send(res, 405, { error: 'method not allowed' }); }
    const { r, params } = hit;
    // identity headers are only honoured when the request came through the proxy (valid secret)
    const user = trusted ? String(req.headers['x-auth-user'] || '').slice(0, 200) : '';
    const role = trusted ? String(req.headers['x-auth-role'] || '').toLowerCase().slice(0, 50) : '';
    const ip = clientIp(req);
    const ctx = {
      method, path: p, params, query: Object.fromEntries(url.searchParams), headers: req.headers, user, role, ip,
      body: null, rawBody: null, req, res, sent: false, streaming: false,
      ok(obj) { ctx.sent = true; ctx._okBody = obj; send(res, 200, obj); },
      // 4xx replies carry {error, errors:[…]} (the portal lists `errors`); pass an array to report several problems
      fail(code, message, errors) {
        ctx.sent = true;
        if (code >= 500) st.errors_5xx++; else st.errors_4xx++;
        const msg = message || http.STATUS_CODES[code] || 'error';
        ctx._fail = [code, msg, errors];   // a waiting duplicate gets the same answer (see handle)
        // every 5xx reaches the error register, whether a route's wrap() answered it or the server did (ctx._err = the cause)
        if (code >= 500 && onError) { try { onError({ method, path: p, status: code, err: ctx._err || new Error(msg) }); } catch { /* the answer still goes out */ } }
        send(res, code, code < 500 ? { error: msg, errors: Array.isArray(errors) && errors.length ? errors.map(String) : [msg] } : { error: msg });
      },
      need(min) {
        const want = ROLE_RANK[min] || ROLE_RANK.admin;
        if ((ROLE_RANK[role] || 0) < want) throw new HttpError(403, `requires role ${min}`);
        return true;
      },
      audit(action, target, detail) {
        const entry = { at: new Date().toISOString(), by: user || 'unknown', role, ip, action: String(action), target: target === undefined ? '' : target, detail: boundDetail(detail) };
        try {
          const rv = auditFn(entry);
          if (rv && typeof rv.then === 'function') rv.then(null, (e) => log && log.error('audit write failed', { err: e.message, action }));
        } catch (e) { if (log) log.error('audit write failed', { err: e.message, action }); }
        return entry;
      },
      sse() {
        ctx.sent = true;
        ctx.streaming = true;
        res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
        res.write(': connected\n\n');
        const closers = [];
        let closed = false;
        st.sse_open++;
        const client = {
          dropped: 0,
          get closed() { return closed; },
          send(event, data, id) {
            if (closed) return false;
            if (res.writableLength > 1024 * 1024) { client.dropped++; return false; }
            let s = '';
            if (id !== undefined) s += `id: ${id}\n`;
            if (event) s += `event: ${event}\n`;
            s += `data: ${JSON.stringify(data)}\n\n`;
            res.write(s);
            return true;
          },
          comment(text) { if (!closed) res.write(`: ${String(text).replace(/\n/g, ' ')}\n\n`); },
          onClose(fn) { closers.push(fn); },
          close() { if (!closed) res.end(); cleanup(); },
        };
        const ka = setInterval(() => { try { client.comment('ka'); } catch (e) { cleanup(); } }, 15000);   // a closed client must not throw out of the timer
        ka.unref();
        function cleanup() {
          if (closed) return;
          closed = true;
          st.sse_open--;
          clearInterval(ka);
          sseClients.delete(client);
          for (const fn of closers) { try { fn(); } catch { /* ignore */ } }
        }
        req.on('close', cleanup);
        res.on('error', cleanup);
        sseClients.add(client);
        return client;
      },
    };
    // Below the protected prefix every route needs a known role and a user (fail closed: nginx sets both from the
    // portal session; a request that carries neither must not read SIEM data). /health stays open for diagnostics.
    if (trusted && p !== protectPrefix + '/health') {
      if (!user || !ROLE_RANK[role]) {
        ctx.audit('access.denied', p, { method, status: 401, reason: !user ? 'no user' : 'unknown role' });
        req.resume();
        return ctx.fail(401, 'no portal identity on this request');
      }
      // CSRF: a state-changing request must come from the portal page itself (browsers send Sec-Fetch-Site) and,
      // when it carries a JSON body, say so — an HTML form cannot send application/json without CORS preflight.
      if (method !== 'GET' && method !== 'HEAD') {
        const site = String(req.headers['sec-fetch-site'] || '').toLowerCase();
        const hasBody = Number(req.headers['content-length'] || 0) > 0 || !!req.headers['transfer-encoding'];
        const ct = String(req.headers['content-type'] || '').toLowerCase();
        let why = '';
        if (site === 'cross-site' || site === 'same-site') why = 'cross-site request refused';
        else if (hasBody && !r.opts.raw && !/^application\/json(\s*;|$)/.test(ct)) why = 'Content-Type must be application/json';
        // an HTML form always declares a form type, even with no fields - refuse it on a body-less request too
        else if (!hasBody && !r.opts.raw && /^(application\/x-www-form-urlencoded|multipart\/form-data|text\/plain)\b/.test(ct)) why = 'Content-Type must be application/json';
        if (why) {
          ctx.audit('access.denied', p, { method, status: 403, reason: why });
          req.resume();
          return ctx.fail(403, why);
        }
      }
      for (const g of gates) {
        let why = null;
        try { why = g(ctx); } catch (e) { why = 'access check unavailable'; if (log) log.every('api-gate-error', 60000, 'error', 'api: access gate failed - refusing (fail closed)', { path: p, err: e.message }); }
        if (why) { req.resume(); return ctx.fail(403, String(why)); }
      }
      if (r.opts.auditRead) ctx.audit('data.read', p, readDetail(method === 'GET' ? ctx.query : null));
    }
    if (typeof r.opts.preAuth === 'function') {
      let pass = false;
      try { pass = r.opts.preAuth(ctx) === true; } catch (e) { if (log) log.error('api preAuth error', { path: p, err: e.message }); }
      if (!pass) {
        if (!ctx.sent) ctx.fail(401, 'unauthorised');
        req.resume();
        return;
      }
    }
    try {
      if (method !== 'GET' && method !== 'HEAD' && method !== 'DELETE' || Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding']) {
        ctx.rawBody = await readBody(req, r.opts.maxBody || maxBody);
        if (!r.opts.raw) {
          const s = ctx.rawBody.toString('utf8').trim();
          if (s) { try { ctx.body = JSON.parse(s, PROTO_KEY.test(s) ? noProtoKeys : undefined); } catch (e) { throw new HttpError(400, e && e.protoKey ? 'the body may not contain the key "' + e.protoKey + '"' : 'invalid JSON body'); } }
        }
      }
      if (!r.opts.raw && (ctx.body === null || typeof ctx.body !== 'object')) ctx.body = ctx.body === null ? {} : ctx.body;
      if (r.opts.auditRead && method !== 'GET' && trusted) ctx.audit('data.read', p, readDetail(ctx.body));
      // duplicate submissions: an identical request (same person, route, body) arriving while the first still runs waits for
      // it and gets the same answer (a double click runs once); sequential repeats still meet the business rules
      let dk = null, entry = null;
      if (method !== 'GET' && !r.opts.raw && !r.opts.noDedup && ctx.user) {
        // the query string is part of the request (POST …/poll?security=1): two different ones never merge
        const qs = [...url.searchParams.entries()].sort((x, y) => (x[0] + '=' + x[1]).localeCompare(y[0] + '=' + y[1])).map((kv) => kv.join('=')).join('&');
        dk = crypto.createHash('sha256').update(String(ctx.user) + '\n' + method + '\n' + p + '?' + qs + '\n' + JSON.stringify(ctx.body)).digest('hex');
        const prev = inflight.get(dk);
        if (prev) {
          // a waiting duplicate gets exactly the first request's outcome - its success, or its 4xx / 5xx - and never runs
          // the handler itself; it never registers or removes an entry (the first request owns it)
          const out = await prev;
          if (out && out.ok) { if (!ctx.sent) { res.setHeader('Idempotent-Replay', 'true'); ctx.ok(out.value); } return; }
          if (out && out.fail) { if (!ctx.sent) { res.setHeader('Idempotent-Replay', 'true'); ctx.fail(out.fail[0], out.fail[1], out.fail[2]); } return; }
          if (out && out.err) throw out.err;
          dk = null;   // the first answered with a stream / raw body: this one runs on its own, unregistered
        } else { let done; entry = new Promise((resolve) => { done = resolve; }); entry.done = done; inflight.set(dk, entry); }
      }
      let rv;
      try { rv = await r.handler(ctx); } catch (e) { if (entry) { entry.done({ err: e }); inflight.delete(dk); } throw e; }
      if (entry) {
        entry.done(ctx._fail ? { fail: ctx._fail } : ctx.sent ? (ctx._okBody !== undefined ? { ok: true, value: ctx._okBody } : null) : rv !== undefined ? { ok: true, value: rv } : null);
        inflight.delete(dk);
      }
      if (!ctx.sent) {
        if (rv !== undefined) ctx.ok(rv);
        else { ctx.sent = true; res.writeHead(204); res.end(); }
      }
    } catch (e) {
      const status = e && Number.isInteger(e.status) && e.status >= 400 && e.status < 600 ? e.status : 500;
      if (status === 401 || status === 403) ctx.audit('access.denied', p, { method, status, reason: String(e.message || '').slice(0, 200) });
      if (status >= 500 && log) log.error('api handler error', { method, path: p, err: e });
      ctx._err = e;   // ctx.fail reports the 5xx to the error register with this cause
      if (status >= 500 && ctx.sent && onError) { try { onError({ method, path: p, status, err: e }); } catch { /* a stream already answered */ } }
      if (!ctx.sent) ctx.fail(status, status >= 500 && !(e instanceof HttpError) && !e.expose ? 'internal error' : e.message, Array.isArray(e.errors) ? e.errors : undefined);
      else if (ctx.streaming) { try { res.end(); } catch { /* ignore */ } }
    } finally {
      if (log && log.isDebug()) log.debug('api request', { method, path: p, ms: Date.now() - t0, user });
    }
  }

  function start() {
    return new Promise((resolve, reject) => {
      server = http.createServer((req, res) => { handle(req, res).catch((e) => { if (log) log.error('api fatal', { err: e }); if (onError) { try { onError({ method: req.method, path: String(req.url || '').split('?')[0], status: 500, err: e }); } catch { /* still answer */ } } try { send(res, 500, { error: 'internal error' }); } catch { /* ignore */ } }); });
      server.keepAliveTimeout = 65000;
      server.headersTimeout = 66000;
      server.requestTimeout = 120000;
      server.once('error', reject);
      server.listen({ port, host }, () => {
        server.removeListener('error', reject);
        server.on('error', (e) => log && log.error('api server error', { err: e.message }));
        if (log) log.info('api: listening', { host, port: server.address().port });
        resolve(server.address());
      });
    });
  }

  function stop() {
    return new Promise((resolve) => {
      for (const c of sseClients) c.close();
      if (!server) return resolve();
      server.close(() => resolve());
      if (server.closeIdleConnections) server.closeIdleConnections();
      setTimeout(() => { if (server.closeAllConnections) server.closeAllConnections(); }, 3000).unref();
    });
  }

  return {
    route, start, stop,
    gate(fn) { if (typeof fn !== 'function') throw new TypeError('gate must be a function'); gates.push(fn); },
    setAudit(fn) { auditFn = fn || defaultAudit; },
    address: () => (server ? server.address() : null),
    stats: () => ({ ...st, routes: routes.length }),
    routes: () => routes.map((r) => `${r.method} ${r.pattern}`),
  };
}

module.exports = { createApi, HttpError, ROLE_RANK };
