// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Route status file (engine/util/route-status.js): every route module's outcome at start - registered, not present, failed to
// load / register with the first line of the error - written atomically for the updater's summary; a write failure never throws.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createRouteStatus } = require('../engine/util/route-status');

test('route status: outcomes recorded with the reason, written atomically, never fatal', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rs-')), file = path.join(dir, 'state', 'routes-status.json');
  const S = createRouteStatus({ file, now: () => Date.parse('2026-10-26T15:00:00Z') });
  S.registered('netops/routes.js'); S.absent('dfir/routes.js');
  S.loadFailed('ksc/routes.js', new Error("Cannot find module './ksc-client'\nRequire stack:\n- /opt/x")); S.registerFailed('zscaler/routes.js', 'boom');
  assert.equal(S.write(), true);
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(j.at, '2026-10-26T15:00:00.000Z');
  assert.deepEqual(j.modules.map((m) => m.module + ':' + m.state), ['netops/routes.js:registered', 'dfir/routes.js:not_present', 'ksc/routes.js:load_failed', 'zscaler/routes.js:register_failed']);
  assert.equal(j.modules[2].error, "Cannot find module './ksc-client'", 'first line of the error only');
  assert.ok(!fs.existsSync(file + '.tmp'), 'no temporary file left');
  const plain = path.join(dir, 'plain'); fs.writeFileSync(plain, 'x');
  assert.equal(createRouteStatus({ file: path.join(plain, 'x.json') }).write(), false, 'an unwritable place returns false, never throws');
  assert.equal(createRouteStatus({}).write(), false);
});
