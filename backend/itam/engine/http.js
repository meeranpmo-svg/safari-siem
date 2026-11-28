// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// HTTP server (127.0.0.1 only; nginx in front). Pattern of sentra-grcai/engine/http.js, extended with an agent gateway.
// Two families of routes, both requiring X-Sentra-Proxy-Secret (timing-safe) added by nginx:
//   - portal routes under `prefix` (/api/itam): identity from X-Auth-User (non-empty) + X-Auth-Role ∈
//     admin|operator|viewer, honoured only with a valid secret. {prefix}/health needs the secret but no identity.
//   - agent routes under `agentPrefix` (/agent): NO portal identity (agents are outbound-only with a per-agent
//     bearer token that the handler itself verifies). nginx does not run auth_request on this location.
// Body limit 1 MB default, per-route override (agent report 8 MB). Errors are JSON {error}; no stack traces to clients.
// CSRF hardening: a browser request marked Sec-Fetch-Site: cross-site|same-site is refused (403), and every non-GET/HEAD
// request must declare Content-Type: application/json (415 otherwise) — HTML forms cannot send that type cross-origin
// without a CORS preflight, which this server never grants. The agent always sends application/json.
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');

const ROLE_RANK = Object.freeze(Object.assign(Object.create(null), { viewer: 1, operator: 2, admin: 3 }));   // no prototype: a role header "constructor" / "__proto__" is not a role
const rankOf = (r) => (Object.prototype.hasOwnProperty.call(ROLE_RANK, r) ? ROLE_RANK[r] : 0);

function compile(pattern) {
  const keys = [];
  const re = pattern.replace(/\/+$/, '').split('/').map((p) => {
    if (p.startsWith(':')) { keys.push(p.slice(1)); return '([^/]+)'; }
    return p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }).join('/');
  return { re: new RegExp(`^${re}/?$`), keys };
}
const digest = (s) => crypto.createHash('sha256').update(String(s)).digest();
const mediaType = (v) => String(v == null ? '' : v).split(';')[0].trim().toLowerCase();

// a JSON key that could reach Object.prototype through a later Object.assign / spread is refused outright (400)
// the reviver runs only when the raw text contains such a key (a reviver makes a large body ~5x slower to parse)
const PROTO_KEY = /"(__proto__|constructor|prototype)"\s*:|\\u/;   // \\u: an escaped key ("\\u005f_proto__") parses to the same key
function noProtoKeys(k, v) { if (k === '__proto__' || k === 'constructor' || k === 'prototype') throw Object.assign(new Error('proto key'), { protoKey: k }); return v; }

function createServer({ host = '127.0.0.1', port = 9150, prefix = '/api/itam', agentPrefix = '/agent', proxySecret, log, maxBody = 1024 * 1024, onError }) {
  const secretDigest = typeof proxySecret === 'string' && proxySecret.length >= 16 ? digest(proxySecret) : null;
  if (!secretDigest && log) log.error('http: no usable proxy_secret (>= 16 chars) in secrets.json — every request will be refused');
  const routes = [], upgrades = [];
  // access gates (roles.js: engineer job roles may call only their own routes) - each gate(ctx) throws {status} to refuse;
  // they run on every portal route and WebSocket after the identity is known and before any body is read
  const gates = [];
  const runGates = (ctx) => { for (const g of gates) g(ctx); };
  const inflight = new Map();   // duplicate-submission guard (see the handler)
  const IDEM_TTL_MS = 600000, IDEM_MAX_BYTES = 256 * 1024, INFLIGHT_MAX = 5000;
  // expired keyed answers go by age; over the cap the oldest FINISHED entries go - a running request is never evicted
  // (evicting it would let its duplicate run a second time)
  function sweepInflight(now) {
    for (const [k, v] of inflight) if (!v.pending && now - v.at >= IDEM_TTL_MS) inflight.delete(k);
    if (inflight.size <= INFLIGHT_MAX) return;
    for (const [k, v] of inflight) { if (inflight.size <= INFLIGHT_MAX) break; if (!v.pending) inflight.delete(k); }
  }
  let server = null;

  function secretOk(v) {
    if (!secretDigest) return false;
    return crypto.timingSafeEqual(digest(v === undefined ? '' : Array.isArray(v) ? v[0] : v), secretDigest);
  }
  // opts.agent=true → route lives under agentPrefix and skips portal identity
  // opts.navigable=true (agent GET routes only, exact path, no parameters) → a top-level browser NAVIGATION from another site
  // is allowed to open it (a risk owner clicking a link in Outlook Web). Only GET + Sec-Fetch-Mode: navigate; every fetch, form
  // POST and non-navigable path from another site is still refused below. Used for the public RCSA form page, which holds no
  // secret and changes nothing (its API calls are same-origin).
  const navigable = new Set();
  function route(method, pattern, handler, opts = {}) {
    const base = opts.agent ? agentPrefix : prefix;
    const { re, keys } = compile(base + pattern);
    if (opts.navigable) {
      if (!opts.agent || method !== 'GET' || keys.length) throw new Error('navigable routes must be agent GET routes with an exact path: ' + base + pattern);
      navigable.add(base + pattern);
    }
    routes.push({ method, path: base + pattern, re, keys, handler, opts });
  }
  // a WebSocket endpoint (GET + Upgrade): the same proxy secret, identity and cross-site checks as every other route, then
  // handler(ctx, req, socket, head) owns the socket. ctx.need() refuses with an HTTP status before anything is upgraded.
  function upgrade(pattern, handler, opts = {}) {
    const { re, keys } = compile(prefix + pattern);
    upgrades.push({ method: 'GET', path: prefix + pattern, re, keys, handler, opts: Object.assign({ upgrade: true }, opts) });
  }
  function refuseUpgrade(socket, code, msg) {
    try { socket.end('HTTP/1.1 ' + code + ' ' + (msg || 'Refused').replace(/[^\x20-\x7e]/g, '') + '\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); } catch { /* the client already went away */ }
    socket.destroy();
  }
  async function onUpgrade(req, socket, head) {
    let url;
    try { url = new URL(req.url, 'http://localhost'); } catch { return refuseUpgrade(socket, 400, 'Bad URL'); }
    const p = url.pathname.replace(/\/+$/, '');
    const hit = upgrades.map((r) => ({ r, m: r.re.exec(p) })).find((x) => x.m);
    if (!hit) return refuseUpgrade(socket, 404, 'Not Found');
    if (!secretOk(req.headers['x-sentra-proxy-secret'])) { if (log) log.every('proxy-secret-ws', 60000, 'warn', 'http: WebSocket without a valid proxy secret refused', { path: p }); return refuseUpgrade(socket, 401, 'Unauthorized'); }
    const user = String(req.headers['x-auth-user'] || '').trim().slice(0, 200), role = String(req.headers['x-auth-role'] || '').trim().toLowerCase();
    if (!user || !rankOf(role)) return refuseUpgrade(socket, 401, 'Unauthorized');
    const fetchSite = String(req.headers['sec-fetch-site'] || '').trim().toLowerCase();
    if (fetchSite === 'cross-site' || fetchSite === 'same-site') { if (log) log.every('csrf-ws', 60000, 'warn', 'http: cross-site WebSocket refused', { path: p, site: fetchSite }); return refuseUpgrade(socket, 403, 'Forbidden'); }
    // cross-site WebSocket hijacking: a browser always sends Origin on a WebSocket; it must be this site
    const origin = req.headers.origin;
    if (origin !== undefined) { let oh = ''; try { oh = new URL(String(origin)).host; } catch { oh = ''; } if (!oh || oh !== String(req.headers.host || '')) { if (log) log.every('ws-origin', 60000, 'warn', 'http: WebSocket from another origin refused', { path: p }); return refuseUpgrade(socket, 403, 'Forbidden'); } }
    const xr = req.headers['x-real-ip'], params = {};
    hit.r.keys.forEach((k, i) => { try { params[k] = decodeURIComponent(hit.m[i + 1]); } catch { params[k] = hit.m[i + 1]; } });
    const ctx = { method: 'GET', path: p, params, query: Object.fromEntries(url.searchParams), user, role, ip: xr ? String(xr).slice(0, 64) : String(socket.remoteAddress || ''),
      who: { user, role, ip: xr ? String(xr).slice(0, 64) : '' }, headers: req.headers,
      need(min) { if (rankOf(role) < (rankOf(min) || 99)) throw Object.assign(new Error(`requires role ${min}`), { status: 403 }); } };
    try { runGates(ctx); await hit.r.handler(ctx, req, socket, head); } catch (e) {
      const status = e && Number.isInteger(e.status) && e.status >= 400 && e.status < 600 ? e.status : 500;
      if (status >= 500 && log) log.error('http: WebSocket handler error', { path: p, err: e && e.message });
      if (!socket.destroyed) refuseUpgrade(socket, status, status >= 500 ? 'Internal Error' : 'Refused');
    }
  }
  function send(res, code, obj, extra) {
    if (res.headersSent || res.writableEnded) return;
    const body = JSON.stringify(obj === undefined ? {} : obj);
    res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }, extra || {}));
    res.end(body);
  }
  function readBody(req, limit) {
    return new Promise((resolve, reject) => {
      if (Number(req.headers['content-length'] || 0) > limit) { req.resume(); return reject(Object.assign(new Error(`body too large (max ${limit} bytes)`), { status: 413 })); }
      const chunks = []; let size = 0; let failed = false;
      req.on('data', (c) => { if (failed) return; size += c.length; if (size > limit) { failed = true; req.resume(); reject(Object.assign(new Error(`body too large (max ${limit} bytes)`), { status: 413 })); return; } chunks.push(c); });
      req.on('end', () => { if (!failed) resolve(Buffer.concat(chunks)); });
      req.on('error', (e) => { if (!failed) reject(e); });
    });
  }

  async function handle(req, res) {
    let url;
    try { url = new URL(req.url, 'http://localhost'); } catch { return send(res, 400, { error: 'bad url' }); }
    const p = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, '') : url.pathname;
    const inPortal = p === prefix || p.startsWith(prefix + '/');
    const inAgent = p === agentPrefix || p.startsWith(agentPrefix + '/');
    if (!inPortal && !inAgent) { req.resume(); return send(res, 404, { error: 'not found' }); }
    if (!secretOk(req.headers['x-sentra-proxy-secret'])) {
      req.resume();
      if (log) log.every('proxy-secret', 60000, 'warn', 'http: request without a valid proxy secret refused', { path: p });
      return send(res, 401, { error: 'missing or invalid proxy credentials' });
    }
    const user = String(req.headers['x-auth-user'] || '').trim().slice(0, 200);
    const role = String(req.headers['x-auth-role'] || '').trim().toLowerCase();
    const isHealth = p === `${prefix}/health`;
    if (inPortal && !isHealth && (!user || !rankOf(role))) { req.resume(); return send(res, 401, { error: 'missing or invalid identity' }); }
    const fetchSite = String(req.headers['sec-fetch-site'] || '').trim().toLowerCase();
    if (fetchSite === 'cross-site' || fetchSite === 'same-site') {
      req.resume();
      // the one exception: a top-level navigation (GET / HEAD, Sec-Fetch-Mode: navigate) to a route declared navigable - a link
      // clicked in another site's page. It reads no body (resume above is harmless for GET) and the page changes nothing.
      const topNav = (req.method === 'GET' || req.method === 'HEAD') && String(req.headers['sec-fetch-mode'] || '').trim().toLowerCase() === 'navigate' && navigable.has(p);
      if (!topNav) {
        if (log) log.every('csrf-fetch-site', 60000, 'warn', 'http: cross-site browser request refused', { path: p, site: fetchSite });
        return send(res, 403, { error: 'cross-site request refused' });
      }
    }
    const method = req.method === 'HEAD' ? 'GET' : req.method;
    let hit = null; let pathMatched = false;
    for (const r of routes) {
      const m = r.re.exec(p);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== method) continue;
      const params = {};
      r.keys.forEach((k, i) => { try { params[k] = decodeURIComponent(m[i + 1]); } catch { params[k] = m[i + 1]; } });
      hit = { r, params }; break;
    }
    if (!hit) { req.resume(); return send(res, pathMatched ? 405 : 404, { error: pathMatched ? 'method not allowed' : 'not found' }); }
    const xr = req.headers['x-real-ip'];
    const ip = xr ? String(xr).slice(0, 64) : String(req.socket.remoteAddress || '');
    const ctx = {
      method, path: p, params: hit.params, query: Object.fromEntries(url.searchParams), user, role,
      ip, body: {}, req, res, sent: false, headers: req.headers,
      agent: !!hit.r.opts.agent,
      who: { user, role, ip: xr ? String(xr).slice(0, 64) : '' },
      bearer() { const h = String(req.headers['authorization'] || ''); const m = /^Bearer\s+(.+)$/i.exec(h); return m ? m[1].trim() : ''; },
      need(min) { if (rankOf(role) < (rankOf(min) || 99)) throw Object.assign(new Error(`requires role ${min}`), { status: 403 }); },
      raw(code, headers, body) { ctx.sent = true; res.writeHead(code, Object.assign({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }, headers)); res.end(body); },
      file(filePath, headers) {
        ctx.sent = true;
        const st = fs.statSync(filePath);
        res.writeHead(200, Object.assign({ 'Content-Length': st.size, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }, headers));
        fs.createReadStream(filePath).pipe(res);
      },
    };
    try {
      if (!hit.r.opts.agent && !isHealth) runGates(ctx);
      const ctype = req.headers['content-type'];
      // any declared body type other than JSON is refused (also for an empty form POST); see the CSRF note at the top
      if (method !== 'GET' && ctype !== undefined && mediaType(ctype) !== 'application/json') { req.resume(); throw Object.assign(new Error('Content-Type must be application/json'), { status: 415 }); }
      if (method !== 'GET' && method !== 'DELETE') {
        const buf = await readBody(req, hit.r.opts.maxBody || maxBody);
        const s = buf.toString('utf8').trim();
        if (s && mediaType(ctype) !== 'application/json') throw Object.assign(new Error('Content-Type must be application/json'), { status: 415 });
        if (s) {
          try { ctx.body = JSON.parse(s, PROTO_KEY.test(s) ? noProtoKeys : undefined); } catch (e) { throw Object.assign(new Error(e && e.protoKey ? 'the body may not contain the key "' + e.protoKey + '"' : 'invalid JSON body'), { status: 400 }); }
          if (!ctx.body || typeof ctx.body !== 'object' || Array.isArray(ctx.body)) throw Object.assign(new Error('JSON body must be an object'), { status: 400 });
        }
      } else req.resume();
      // duplicate submissions: an identical request (same person, route and body) that arrives while the first is still
      // running gets the first one's answer instead of running twice (a double click); with an Idempotency-Key header a
      // retry within 10 minutes gets the first answer again. A failed request is never replayed. A repeat AFTER the first
      // finished is a new request on purpose: re-running an import must report "updated", a second delete must say 404.
      let dk = null, entry = null, ik = '';
      if (method !== 'GET' && !hit.r.opts.agent && !hit.r.opts.noDedup) {
        ik = String(req.headers['idempotency-key'] || '').trim();
        if (ik && !/^[A-Za-z0-9_.:-]{8,100}$/.test(ik)) throw Object.assign(new Error('Idempotency-Key: 8-100 letters, digits, _ . : -'), { status: 400 });
        // the query string is part of the request (POST /discovery/run?source=… reads it): two different ones never merge
        const qs = [...url.searchParams.entries()].sort((x, y) => (x[0] + '=' + x[1]).localeCompare(y[0] + '=' + y[1])).map((kv) => kv.join('=')).join('&');
        const bodyHash = crypto.createHash('sha256').update(user + '\n' + method + '\n' + p + '?' + qs + '\n' + JSON.stringify(ctx.body)).digest('hex');
        dk = ik ? 'k|' + user + '|' + method + '|' + p + '|' + ik : 'b|' + bodyHash;
        const now0 = Date.now(), prev = inflight.get(dk);
        if (prev && (prev.pending || (ik && now0 - prev.at < IDEM_TTL_MS))) {
          // one key = one request: the same key with a different body is the client's mistake, never a silent replay
          if (ik && prev.bodyHash !== bodyHash) throw Object.assign(new Error('this Idempotency-Key was already used for a different request'), { status: 422 });
          const r = prev.pending ? await prev.pending : prev.result;
          if (r && r.ok) { send(res, 200, r.value, { 'Idempotent-Replay': 'true' }); return; }
          if (r && r.err) throw r.err;
        }
        let done; entry = { at: now0, bodyHash, pending: new Promise((resolve) => { done = resolve; }) }; entry.done = done;
        inflight.set(dk, entry); sweepInflight(now0);
      }
      let rv;
      try { rv = await hit.r.handler(ctx); } catch (e) { if (entry) { entry.done({ err: e }); entry.pending = null; inflight.delete(dk); } throw e; }
      if (entry) {
        const v = rv === undefined ? { ok: true } : rv; entry.result = ctx.sent ? null : { ok: true, value: v }; entry.done(entry.result); entry.pending = null;
        // only an Idempotency-Key answer is kept (10 minutes), and only if it is small: a big one is answered again by running
        if (!ik || ctx.sent || JSON.stringify(v).length > IDEM_MAX_BYTES) inflight.delete(dk); else entry.at = Date.now();
      }
      if (!ctx.sent) send(res, 200, rv === undefined ? { ok: true } : rv);
    } catch (e) {
      const status = e && Number.isInteger(e.status) && e.status >= 400 && e.status < 600 ? e.status : 500;
      if (status >= 500 && log) log.error('http: handler error', { method, path: p, err: e && e.message, stack: e && e.stack ? String(e.stack).split('\n').slice(0, 6).join('\n') : undefined });
      if (status >= 500 && onError) { try { onError({ method, path: p, status, err: e }); } catch { /* the answer below still goes out */ } }
      if (!ctx.sent) send(res, status, Object.assign({ error: status >= 500 ? 'internal error' : e.message }, e.code2 ? { code: e.code2 } : {}));
    }
  }

  return {
    route, upgrade,
    gate(fn) { if (typeof fn !== 'function') throw new TypeError('gate must be a function'); gates.push(fn); },
    // every registered route, read-only (the contract test checks that each one declares who may call it)
    list: () => routes.concat(upgrades).map((r) => ({ method: r.method, path: r.path, handler: r.handler, opts: r.opts })),
    start() {
      return new Promise((resolve, reject) => {
        server = http.createServer((req, res) => { handle(req, res).catch((e) => { if (log) log.error('http: request failed outside a handler', { path: String(req.url || '').split('?')[0], err: e && e.message }); if (onError) { try { onError({ method: req.method, path: req.url, status: 500, err: e }); } catch { /* still answer */ } } try { if (!res.headersSent) send(res, 500, { error: 'internal error' }); else res.end(); } catch { /* connection already gone */ } }); });
        server.requestTimeout = 120000;
        server.on('upgrade', (req, socket, head) => { onUpgrade(req, socket, head).catch((e) => { if (log) log.error('http: WebSocket upgrade failed', { err: e && e.message }); socket.destroy(); }); });
        server.once('error', reject);
        // after a successful listen the start-up handler is gone; a later server error is logged here instead of crashing the process
        server.on('error', (e) => { if (log) log.error('itam http server error', { err: e && e.message }); });
        server.listen({ host, port }, () => { server.removeListener('error', reject); resolve(server.address()); });
      });
    },
    stop() {
      return new Promise((resolve) => {
        if (!server) return resolve();
        server.close(() => resolve());
        if (server.closeAllConnections) server.closeAllConnections();
      });
    },
    address: () => (server ? server.address() : null),
    prefix,
  };
}

module.exports = { createServer, ROLE_RANK };
