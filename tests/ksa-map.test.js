// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The Saudi map shared by the pages (ui/vendor/zyb-ksa-map.js, built by tools/build-ksa-map.js from the SIEM office map): up to
// date with its source, and a site is placed by the Saudi city in its name.
const test = require('node:test'), assert = require('node:assert/strict'), path = require('path'), { execFileSync } = require('child_process');
const ROOT = path.resolve(__dirname, '..');
test('KSA map: generated from the office map, places sites by city', () => {
  execFileSync(process.execPath, [path.join(ROOT, 'tools/build-ksa-map.js'), '--check'], { stdio: 'pipe' });
  global.window = {}; require(path.join(ROOT, 'ui/vendor/zyb-ksa-map.js'));
  const M = global.window.zybKsaMap;
  assert.equal(M.place('Jubail Project Site').city, 'Jubail'); assert.equal(M.place('Riyadh Head Office').city, 'Riyadh'); assert.equal(M.place('Somewhere else'), null);
});
