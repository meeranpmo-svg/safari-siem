// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/* The engineering contract (CLAUDE.md "Definition of done"), checked on every test run so it is met WITH the business logic,
 * not added later:
 *   1. every route that changes something checks the caller's role (ctx.need / admin(ctx)) or says why every role may call it
 *      (opts.anyRole: '<reason>')
 *   2. every read route declares its role the same way - the routes written before this rule are listed in
 *      tests/contract-baseline.json; a NEW route is not, so it must declare. The list can only shrink: a listed route that now
 *      declares its role fails the test until it is taken off the list.
 *   3. every engine module that registers routes has a test that loads it
 *   4. no error is swallowed silently: an empty catch / .catch(() => {}) must say why in a comment
 *   5. no password / secret / token is passed to a log call
 * Run with UPDATE_CONTRACT_BASELINE=1 only to REMOVE entries (it never adds one).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');

const ENGINE = path.join(__dirname, '..', 'engine'), BASE_FILE = path.join(__dirname, 'contract-baseline.json');
const baseline = JSON.parse(fs.readFileSync(BASE_FILE, 'utf8'));
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((x) => x.isDirectory() ? (x.name === 'node_modules' || x.name === '__pycache__' ? [] : walk(path.join(d, x.name))) : x.name.endsWith('.js') ? [path.join(d, x.name)] : []);
const declares = (r) => /\.need\(|\badmin\(ctx\)/.test(r.handler.toString()) || (typeof r.opts.anyRole === 'string' && r.opts.anyRole.length >= 10);

async function allRoutes() {
  const e = await startApp({ noAi: true }); e.app.noTimers = true;
  for (const f of fs.readdirSync(ENGINE).filter((x) => x.endsWith('.js') && x !== 'main.js')) {
    let m; try { m = require(path.join(ENGINE, f)); } catch (x) { continue; }
    for (const k of Object.keys(m)) {
      if (!/^register[A-Z]/.test(k) || typeof m[k] !== 'function' || k === 'registerRoutes' || k === 'registerErrorRoutes') continue;
      try { m[k](e.app.srv, e.app, { noTimer: true, noTimers: true, noPush: true }); } catch (x) { /* a module that needs a live dependency to register is covered by its own test */ }
    }
  }
  const seen = new Set(), list = e.app.srv.list().filter((r) => !r.opts.agent && r.path !== '/api/itam/health').filter((r) => { const k = r.method + ' ' + r.path; if (seen.has(k)) return false; seen.add(k); return true; });
  await e.close();
  return list;
}


// a timer callback that is neither guarded nor catches: a throw there reaches the process (CLAUDE.md, error handling)
function bareIntervals(src) {
  const out = [];
  for (const m of src.matchAll(/\bsetInterval\(/g)) {
    let depth = 0, k = m.index + 'setInterval'.length;
    for (; k < src.length; k++) { const c = src[k]; if (c === '(') depth++; else if (c === ')') { depth--; if (!depth) break; } }
    const call = src.slice(m.index, k + 1);
    const id = /^setInterval\(\s*([A-Za-z_$][\w$]*)\s*[,)]/.exec(call);   // setInterval(job, …): look at how job was made
    const viaId = id && new RegExp('(?:const|let|var)\\s+' + id[1] + '\\s*=\\s*[^;\\n]*(guard|guardJob|guardOf|\\.catch\\()').test(src);
    if (!viaId && !/guard|guardJob|guardOf|\.catch\(|try\s*\{/.test(call)) out.push(src.slice(0, m.index).split('\n').length);
  }
  return out;
}
const SILENT = [/\.catch\(\(\w*\)\s*=>\s*\{\s*\}\)/g, /catch\s*(\(\w*\))?\s*\{\s*\}/g];   // whole file: an empty block over several lines too
function silentCatches(src) { const out = []; for (const re of SILENT) for (const m of src.matchAll(re)) out.push(src.slice(0, m.index).split('\n').length); return out; }

test('1-2. every route declares who may call it', async () => {
  const routes = await allRoutes();
  assert.ok(routes.length > 300, 'all modules registered (' + routes.length + ' routes)');
  const writes = routes.filter((r) => r.method !== 'GET' && !declares(r)).map((r) => r.method + ' ' + r.path);
  const reads = routes.filter((r) => r.method === 'GET' && !declares(r)).map((r) => r.method + ' ' + r.path);
  const allowed = new Set(baseline.read_routes_without_role);
  const fresh = reads.filter((k) => !allowed.has(k));
  assert.deepEqual({ writes, fresh }, { writes: [], fresh: [] }, 'writes = routes that change something without a role check; fresh = new read routes that do not declare their role (ctx.need(\'viewer\' | \'operator\' | \'admin\'))');
  const fixed = baseline.read_routes_without_role.filter((k) => !reads.includes(k));
  if (fixed.length && process.env.UPDATE_CONTRACT_BASELINE) { baseline.read_routes_without_role = baseline.read_routes_without_role.filter((k) => reads.includes(k)); fs.writeFileSync(BASE_FILE, JSON.stringify(baseline, null, 1) + '\n'); }
  else assert.deepEqual(fixed, [], 'these routes now declare their role - remove them from tests/contract-baseline.json (UPDATE_CONTRACT_BASELINE=1):\n  ' + fixed.join('\n  '));
});

test('3. every module with routes has a test', () => {
  const names = new Set(fs.readdirSync(__dirname).filter((f) => f.endsWith('.test.js')).map((f) => f.slice(0, -8)));
  const tests = fs.readdirSync(__dirname).filter((f) => f.endsWith('.test.js')).map((f) => fs.readFileSync(path.join(__dirname, f), 'utf8')).join('\n');
  const missing = fs.readdirSync(ENGINE).filter((f) => f.endsWith('.js') && f !== 'main.js').filter((f) => /\bsrv\.route\(/.test(fs.readFileSync(path.join(ENGINE, f), 'utf8')))
    .map((f) => f.slice(0, -3))
    // tested = a test file named after it, or a test that loads it; routes.js is the core every startApp() test drives
    .filter((m) => m !== 'routes' && !names.has(m) && !tests.includes('engine/' + m + "'") && !tests.includes('engine/' + m + '"') && !tests.includes('engine/' + m + '.js'))
    .filter((m) => !(baseline.modules_without_test || []).includes(m));
  assert.deepEqual(missing, [], 'modules with routes and no test:\n  ' + missing.join('\n  '));
});

test('4-5. no silent catch, no secret in a log call', () => {
  const silent = [], leaks = [], bare = {};
  for (const f of walk(ENGINE)) {
    const rel = path.relative(ENGINE, f), src = fs.readFileSync(f, 'utf8'), lines = src.split('\n');
    for (const n of silentCatches(src)) silent.push(rel + ':' + n);
    const bi = bareIntervals(src).length; if (bi) bare[rel] = bi;
    lines.forEach((l, i) => {
      if (/\blog\w*\.(info|warn|error|debug|fatal|every)\([^;]*\b(password|passwd|secret|token|api_?key|private_?key)\s*:/i.test(l) && !/_present|has_|:\s*!!|redact|mask/i.test(l)) leaks.push(rel + ':' + (i + 1));
    });
  }
  const allowed = baseline.bare_intervals || {}, grown = Object.keys(bare).filter((k) => bare[k] > (allowed[k] || 0)).map((k) => k + ' (' + bare[k] + ')');
  const shrunk = Object.keys(allowed).filter((k) => (bare[k] || 0) < allowed[k]).map((k) => k + ' (' + (bare[k] || 0) + ', baseline ' + allowed[k] + ')');
  assert.deepEqual({ grown, shrunk }, { grown: [], shrunk: [] }, 'grown = a new setInterval that is neither guarded nor catches; shrunk = fewer than the baseline - lower tests/contract-baseline.json bare_intervals');
  assert.deepEqual({ silent, leaks }, { silent: [], leaks: [] }, 'silent = errors swallowed without a reason (add /* why */ inside the catch); leaks = a secret-looking field passed to a log call');
});
