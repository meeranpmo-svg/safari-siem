// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The POC Office Connectivity Map (ui/network-geomap-poc.html, built by tools/build-poc-geomap.js): up to date with the live page,
// marked POC everywhere, every office named "(POC)", answers itself (no server call, nothing changed), in the menu and installer.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '..'), P = require(path.join(ROOT, 'tools/build-poc-geomap.js'));
test('POC map: up to date, marked, illustrative only', () => {
  const h = fs.readFileSync(path.join(ROOT, 'ui/network-geomap-poc.html'), 'utf8');
  assert.equal(h, P.build(), 'run node tools/build-poc-geomap.js');
  assert.equal((h.match(/class="poc-r (tl|tr|bl|br)"/g) || []).length, 4, 'a ribbon on every corner');
  assert.match(h, /<title>Office Connectivity Map \(POC\)<\/title>/); assert.match(h, /not live data/);
  assert.ok(P.data().sites.every((s) => / \(POC\)$/.test(s.name)), 'every office says POC');
  assert.match(h, /nothing is changed from here/); assert.match(h, /S\.can = function \(\) \{ return false; \}/);
  const nav = fs.readFileSync(path.join(ROOT, 'ui/vendor/zyb-nav.js'), 'utf8'); assert.ok(nav.includes('"h": "network-geomap-poc.html"'));
  assert.match(fs.readFileSync(path.join(ROOT, 'ui/install-dashboards.sh'), 'utf8'), / network-geomap-poc\.html /);
});
