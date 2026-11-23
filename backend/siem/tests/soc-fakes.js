// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Small local fakes of the core interfaces (ARCH "Internal interfaces") used by detect*/soc* tests.
const fs = require('fs');
const os = require('os');
const path = require('path');

const RANK = { viewer: 0, analyst: 0, operator: 1, admin: 2 };

/** createApi() stand-in: route(method, pattern, handler) + call() to invoke a handler with a fake ctx. */
function fakeApi(o = {}) {
  // o.realRanks: the core server's order (viewer < analyst < operator < admin, engine/api/server.js ROLE_RANK) for tests
  // that must show a viewer refused by an analyst route; the default keeps the older tests' ranks
  const ranks = o.realRanks ? { viewer: 0, analyst: 1, operator: 2, admin: 3 } : RANK;
  const routes = [];
  const audits = [];
  function compile(pattern) {
    const keys = [];
    const re = new RegExp('^' + pattern.replace(/\/:([A-Za-z_]+)/g, (_, k) => { keys.push(k); return '/([^/]+)'; }) + '$');
    return { re, keys };
  }
  return {
    routes, audits,
    route(method, pattern, handler) { routes.push(Object.assign({ method, pattern, handler }, compile(pattern))); },
    has(method, pattern) { return routes.some((r) => r.method === method && r.pattern === pattern); },
    async call(method, url, opts = {}) {
      const [p, qs] = url.split('?');
      const query = Object.assign(Object.fromEntries(new URLSearchParams(qs || '')), opts.query || {});
      const r = routes.find((x) => x.method === method && x.re.test(p));
      if (!r) return { status: 404, body: { error: 'no route' } };
      const m = r.re.exec(p);
      const params = {};
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
      let res = null;
      const role = opts.role || 'admin';
      const user = opts.user || 'tester';
      const ctx = {
        method, path: p, params, query, body: opts.body, user, role, ip: '127.0.0.1',
        ok(obj) { res = { status: 200, body: obj }; return res; },
        // mirrors engine/api/server.js: fail(code, message, errors?) → 4xx body {error, errors:[…]}
        fail(code, message, errors) { res = { status: code, body: code < 500 ? { error: message, errors: Array.isArray(errors) && errors.length ? errors : [message] } : { error: message } }; return res; },
        // like the core server: throws an error with .status 403 when the role is insufficient
        need(want) { if ((ranks[role] || 0) < ranks[want]) throw Object.assign(new Error('requires role ' + want), { status: 403 }); return true; },
        audit(action, target, detail) { audits.push({ action, target, detail, user }); },
        sse() { throw new Error('not supported in tests'); },
      };
      try { const out = await r.handler(ctx); if (!res && out !== undefined) res = { status: 200, body: out }; } catch (e) {
        const code = e.status || 500;
        res = { status: code, body: { error: e.message, errors: Array.isArray(e.errors) ? e.errors : [e.message] } };
      }
      return res || { status: 500, body: { error: 'handler returned nothing' } };
    },
  };
}

/** createCH() stand-in: records insertRows calls; can be told to fail. */
function fakeCH() {
  const inserts = [];
  let failing = false;
  return {
    inserts,
    setFailing(v) { failing = v; },
    async insertRows(table, rows) { if (failing) throw new Error('ClickHouse unavailable'); inserts.push({ table, rows: JSON.parse(JSON.stringify(rows)) }); },
    async query() { return []; },
    async exec() { return ''; },
    async ping() { return !failing; },
  };
}

/** deps.search stand-in over an in-memory event array: search(q, from, to, {limit, offset}) → {rows, total_estimate}. */
function fakeSearch(events, opts = {}) {
  const calls = [];
  const fn = async (q, from, to, o = {}) => {
    calls.push({ q, from, to, o });
    let rows = events.filter((e) => e.ts >= from && e.ts <= to).sort((a, b) => a.ts - b.ts);
    if (opts.filter) rows = rows.filter((e) => opts.filter(q, e));
    const total = rows.length;
    const off = o.offset || 0;
    const lim = o.limit || 100;
    const page = rows.slice(off, off + lim).map((e) => (opts.asCH ? Object.assign({}, e, { ts: new Date(e.ts).toISOString().replace('T', ' ').replace('Z', '') }) : e));
    return opts.arrayOnly ? page : { rows: page, total_estimate: total };
  };
  fn.calls = calls;
  return fn;
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix || 'sentra-siem-test-'));
}

const quietLog = { info() {}, warn() {}, error() {}, debug() {}, every() {} };

module.exports = { fakeApi, fakeCH, fakeSearch, tmpDir, quietLog };
