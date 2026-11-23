// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/* The engineering contract (CLAUDE.md "Definition of done"), checked on every test run so it is met WITH the business logic,
 * not added later. Read from the source (the route modules need a live log store to register):
 *   1. every route declares who may call it: wrap(deps, '<role>' | 'approve:<scope>' | <role function>, …), ctx.need(…) or
 *      atLeast(ctx, …). wrap(deps, null, …) - any signed-in user - is allowed for reads; a route that CHANGES something with
 *      null must say why in its options ({ anyRole: '<reason>' }).
 *   2. routes written before this rule that the reader cannot resolve are listed in tests/contract-baseline.json; the list
 *      can only shrink.
 *   3. every engine module that registers routes has a test that loads it
 *   4. no error is swallowed silently: an empty catch / .catch(() => {}) must say why in a comment
 *   5. no password / secret / token is passed to a log call
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ENGINE = path.join(__dirname, '..', 'engine'), BASE_FILE = path.join(__dirname, 'contract-baseline.json');
const baseline = fs.existsSync(BASE_FILE) ? JSON.parse(fs.readFileSync(BASE_FILE, 'utf8')) : { undeclared_routes: [] };
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((x) => x.isDirectory() ? (x.name === 'node_modules' ? [] : walk(path.join(d, x.name))) : x.name.endsWith('.js') ? [path.join(d, x.name)] : []);
const ROUTE = /\b\w+\.route\(\s*'(GET|POST|PUT|DELETE|PATCH)'\s*,\s*(['`])((?:(?!\2).)+)\2\s*,\s*/g;

// the end of the api.route( call that starts at `from` (balanced brackets, strings skipped)
function callEnd(s, from) {
  let depth = 0;
  for (let k = s.indexOf('(', from); k < s.length; k++) {
    const c = s[k];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { depth--; if (!depth) return k; }
    else if (c === '\'' || c === '"' || c === '`') { const q = c; k++; while (k < s.length && s[k] !== q) { if (s[k] === '\\') k++; k++; } }
  }
  return s.length;
}
// the role a handler declares: directly, or through a helper defined in the same file (const x = wrap(deps, R, …) or a factory)
function roleOf(h, src, depth = 0) {
  const direct = /^wrap\(\s*deps\s*,\s*([^,]+),/.exec(h);
  if (direct) return direct[1].trim();
  if (/^[^]{0,400}?(\.need\(|\batLeast\(ctx)/.test(h)) return 'checked';
  const id = /^(\w+)\s*[()]/.exec(h);
  if (id) {
    const def = new RegExp(`(?:const|let|var)\\s+${id[1]}\\s*=|function\\s+${id[1]}\\s*\\(`).exec(src);
    if (def) {
      const body = src.slice(def.index, def.index + 600), w = /wrap\(\s*deps\s*,\s*([^,]+),/.exec(body);
      if (w) return w[1].trim();
      const via = /=\s*(\w+)\(/.exec(body.slice(0, 120));   // const setOwner = caseOp(...): follow caseOp
      if (via && via[1] !== id[1] && depth < 2) return roleOf(via[1] + '(', src, depth + 1);
    }
  }
  return null;
}
function routes() {
  const out = [];
  for (const f of walk(ENGINE)) {
    const src = fs.readFileSync(f, 'utf8'), rel = path.relative(ENGINE, f);
    if (rel === 'util/errors.js') continue;   // its route is the ITAM engine's (the file is shared)
    for (const m of src.matchAll(ROUTE)) {
      const end = callEnd(src, m.index), call = src.slice(m.index, end + 1), h = src.slice(m.index + m[0].length, m.index + m[0].length + 600);
      out.push({ file: rel, method: m[1], path: m[3], role: roleOf(h, src), anyRole: /anyRole:\s*'[^']{10,}'/.test(call.slice(-400)), preAuth: /\bpreAuth\b/.test(call.slice(-300)) });
    }
  }
  return out;
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

test('1-2. every route declares who may call it', () => {
  const list = routes();
  assert.ok(list.length > 350, 'routes found (' + list.length + ')');
  const key = (r) => r.file + ' ' + r.method + ' ' + r.path;
  const undeclared = list.filter((r) => !r.role && !r.preAuth && r.path !== '/api/soc/health').map(key);
  const writesAnyRole = list.filter((r) => r.role === 'null' && r.method !== 'GET' && !r.anyRole).map(key);
  const allowed = new Set(baseline.undeclared_routes);
  const fresh = undeclared.filter((k) => !allowed.has(k));
  assert.deepEqual({ fresh, writesAnyRole }, { fresh: [], writesAnyRole: [] }, 'fresh = routes that do not declare a role; writesAnyRole = routes that change something for any role without { anyRole: <reason> }');
  const fixed = baseline.undeclared_routes.filter((k) => !undeclared.includes(k));
  assert.deepEqual(fixed, [], 'these routes now declare their role - remove them from tests/contract-baseline.json');
});

test('3. every module with routes has a test', () => {
  const dir = __dirname, names = new Set(fs.readdirSync(dir).filter((f) => f.endsWith('.test.js')).map((f) => f.slice(0, -8)));
  const tests = fs.readdirSync(dir).filter((f) => f.endsWith('.test.js')).map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('\n');
  const mods = [...new Set(routes().map((r) => r.file))];
  const missing = mods.filter((m) => { const base = m.replace(/\.js$/, ''), leaf = path.basename(base), parent = base.split('/')[0];
    return !names.has(leaf) && !names.has(parent) && ![...names].some((n) => n.startsWith(parent + '-')) && !names.has(base.replace(/\//g, '-')) && !tests.includes('engine/' + base + "'") && !tests.includes('engine/' + base + '.js') && !tests.includes('engine/' + base + '"'); })
    .filter((m) => !(baseline.modules_without_test || []).includes(m));
  assert.deepEqual(missing, [], 'modules with routes and no test:\n  ' + missing.join('\n  '));
  const done = (baseline.modules_without_test || []).filter((m) => tests.includes('engine/' + m.replace(/\.js$/, '')));
  assert.deepEqual(done, [], 'these modules have a test now - remove them from tests/contract-baseline.json');
});

test('4-5. no silent catch, no secret in a log call', () => {
  const silent = [], leaks = [], bare = {};
  for (const f of walk(ENGINE)) {
    const rel = path.relative(ENGINE, f), src = fs.readFileSync(f, 'utf8');
    for (const n of silentCatches(src)) silent.push(rel + ':' + n);
    const bi = bareIntervals(src).length; if (bi) bare[rel] = bi;
    src.split('\n').forEach((l, i) => {
      if (/\b(log|lg|L)\w*\.(info|warn|error|debug|fatal|every)\([^;]*\b(password|passwd|secret|token|api_?key|private_?key)\s*:/i.test(l) && !/_present|has_|:\s*!!|redact|mask/i.test(l)) leaks.push(rel + ':' + (i + 1));
    });
  }
  const known = new Set(baseline.silent_catch || []);
  const allowed = baseline.bare_intervals || {}, grown = Object.keys(bare).filter((k) => bare[k] > (allowed[k] || 0)).map((k) => k + ' (' + bare[k] + ')');
  const shrunk = Object.keys(allowed).filter((k) => (bare[k] || 0) < allowed[k]).map((k) => k + ' (' + (bare[k] || 0) + ', baseline ' + allowed[k] + ')');
  assert.deepEqual({ grown, shrunk }, { grown: [], shrunk: [] }, 'grown = a new setInterval that is neither guarded nor catches; shrunk = fewer than the baseline - lower tests/contract-baseline.json bare_intervals');
  assert.deepEqual({ silent: silent.filter((x) => !known.has(x.replace(/:\d+$/, ''))), leaks }, { silent: [], leaks: [] }, 'silent = errors swallowed without a reason (add /* why */ inside the catch); leaks = a secret-looking field passed to a log call');
});
