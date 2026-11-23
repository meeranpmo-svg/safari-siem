// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Safari / iPhone / iPad compatibility of every page and vendor script. There is no WebKit browser in the test machines, so this
// checks the source for what older Safari cannot run, and runs the tile matcher (zyb-tiles.js) without a lookbehind:
//  - regex lookbehind ((?<= / (?<!) is a SyntaxError on Safari before 16.4: the script stops, the page breaks (zyb-tiles.js had one);
//  - backdrop-filter needs -webkit-backdrop-filter beside it on Safari before 18, or the blur is lost;
//  - JavaScript newer than the Safari our people use (Object.groupBy, Promise.withResolvers, toSorted ...).
// Run: node safari-compat.test.js
const fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const files = fs.readdirSync(DASH).filter((f) => f.endsWith('.html')).concat(fs.readdirSync(path.join(DASH, 'vendor')).filter((f) => f.endsWith('.js')).map((f) => 'vendor/' + f));
const src = (f) => fs.readFileSync(path.join(DASH, f), 'utf8');
const NEW_JS = [/\bObject\.groupBy\s*\(/, /\bMap\.groupBy\s*\(/, /\bPromise\.withResolvers\s*\(/, /\.toSorted\s*\(/, /\.toReversed\s*\(/, /\.toSpliced\s*\(/, /\.(union|intersection|symmetricDifference|isSubsetOf)\s*\(\s*new Set/];
const look = [], blur = [], js = [];
for (const f of files) {
  const s = src(f);
  if (/\(\?<[=!]/.test(s)) look.push(f);
  const plain = (s.match(/(^|[^-])backdrop-filter\s*:/g) || []).length, pre = (s.match(/-webkit-backdrop-filter\s*:/g) || []).length;
  if (pre < plain) blur.push(f + ' (' + plain + ' blur, ' + pre + ' with -webkit-)');
  NEW_JS.forEach((r) => { if (r.test(s)) js.push(f + ' ' + r.source); });
}
ok(files.length > 50, 'the pages and vendor scripts are found: ' + files.length);
ok(!look.length, 'no regex lookbehind (Safari before 16.4 stops the script): ' + look.join(', '));
ok(!blur.length, 'every backdrop-filter has -webkit-backdrop-filter beside it: ' + blur.join(', '));
ok(!js.length, 'no JavaScript newer than Safari 16: ' + js.join(', '));

// the tile matcher still tells "Compliant" from "Non-compliant" without a lookbehind
const T = src('vendor/zyb-tiles.js'), i = T.indexOf('function rx(p)'), j = T.indexOf('\n  var AUTOKEY', i);
ok(i > 0 && j > i, 'zyb-tiles.js has its matcher');
const rx = new Function(T.slice(i, j) + '\nreturn rx;')();
const t = (p, s) => rx(p).test(s);
ok(t('compliant', 'Server A Compliant') && !t('compliant', 'Server A Non-compliant') && !t('compliant', 'not compliant') && !t('compliant', 'NON_COMPLIANT'), 'Compliant matches, Non-compliant / not compliant do not');
ok(t('compliant', 'Non-compliant here, Compliant there'), 'a later plain match still counts after a negated one');
ok(t('open ticket', 'three open_tickets') && t('patch', 'patches (Patch)') && !t('patch', 'dispatcher') && !t('risk', 'brisk'), 'whole words, plurals, separators');
ok(t('c++', 'uses C++ daily') && !t('a.b', 'axb'), 'special characters are literal');
const r = rx('high'); ok(r.test('High') && r.test('very high') && r.test('High'), 'the same matcher can be used again and again');
ok(!t('x', null) && !t('x', undefined), 'empty text matches nothing');
console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
