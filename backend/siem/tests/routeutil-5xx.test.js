// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SIEM route wrapper (engine/soc/routeutil.js wrap / safe5xx): a deliberate 5xx keeps its plain message ("Exchange Online did not
// answer"); a server file path or a stack line in a 5xx never reaches the browser - it is removed and the full error is kept for the
// error register; a 4xx is passed as written. SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { wrap, safe5xx } = require('../engine/soc/routeutil');

function ctx() { const c = { path: '/x', role: 'admin', user: 'syed.syn', need: () => true, res: null }; c.fail = (code, msg) => { c.res = { code, msg }; return c.res; }; return c; }
const logged = []; const deps = { log: { error: (m, f) => logged.push(f) } };

test('5xx: paths and stack lines removed, plain messages kept; 4xx unchanged', async () => {
  let c = ctx(); await wrap(deps, null, () => { throw Object.assign(new Error('cannot read /etc/sentra-siem/identity.json: Unexpected token } in JSON'), { status: 500 }); })(c);
  assert.equal(c.res.code, 500); assert.ok(!/\/etc\/sentra-siem/.test(c.res.msg), c.res.msg); assert.match(c.res.msg, /<path>/); assert.ok(c._err, 'the full error kept for the register'); assert.equal(logged.length, 1);
  c = ctx(); await wrap(deps, null, () => { throw Object.assign(new Error('Exchange Online did not answer within 3 minutes'), { status: 502 }); })(c);
  assert.deepEqual(c.res, { code: 502, msg: 'Exchange Online did not answer within 3 minutes' });
  c = ctx(); await wrap(deps, null, () => { throw Object.assign(new Error('name: must be at least 3 characters'), { status: 400 }); })(c);
  assert.deepEqual(c.res, { code: 400, msg: 'name: must be at least 3 characters' });
  assert.equal(safe5xx('boom\n    at fn (/opt/sentra-siem/engine/x.js:10:5)'), 'boom');
  assert.equal(safe5xx('C:\\ProgramData\\Sentra\\a.json is locked'), '<path> is locked');
});
