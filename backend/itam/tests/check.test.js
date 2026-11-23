// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// engine/check.js: boundary validation - every rule throws a 400 naming the field; undeclared fields never reach the logic.
const test = require('node:test');
const assert = require('node:assert/strict');
const { body, param } = require('../engine/check');

const err = (fn, re) => { try { fn(); } catch (e) { assert.equal(e.status, 400); assert.match(e.message, re); return; } assert.fail('expected a 400 matching ' + re); };

test('valid input: typed, trimmed, defaults, only declared fields', () => {
  const b = body({ label: '  ESX DR ', host: 'db01.corp.local', port: '1521', kind: 'oracle', due: '2026-12-31', ids: ['a1', 'a1', 'b2'], on: true, role: 'admin', __proto__x: 1 })
    .str('label', { required: true, max: 40 }).str('host', { host: true }).int('port', { min: 1, max: 65535 }).oneOf('kind', ['oracle', 'mssql'])
    .date('due').list('ids', { item: 'id', unique: true }).bool('on').int('retries', { def: 3 }).done();
  assert.deepEqual(b, { label: 'ESX DR', host: 'db01.corp.local', port: 1521, kind: 'oracle', due: '2026-12-31', ids: ['a1', 'b2'], on: true, retries: 3 });
  assert.equal(b.role, undefined, 'a field that was not declared is dropped (no mass assignment)');
});

test('every rule refuses with the field name', () => {
  err(() => body([]), /JSON object/);
  err(() => body({}).str('label', { required: true }), /label is required/);
  err(() => body({ label: 'x'.repeat(201) }).str('label', { max: 200 }), /longer than 200/);
  err(() => body({ label: 'a\u0000b' }).str('label'), /control characters/);
  err(() => body({ host: 'bad host!' }).str('host', { host: true }), /host name or IP/);
  err(() => body({ ip: '10.0.0.300' }).str('ip', { ip: true }), /IP address/);
  err(() => body({ to: 'not-mail' }).str('to', { email: true }), /e-mail/);
  err(() => body({ port: '15.5' }).int('port'), /whole number/);
  err(() => body({ port: 70000 }).int('port', { max: 65535 }), /at most 65535/);
  err(() => body({ on: 'yes' }).bool('on'), /true or false/);
  err(() => body({ kind: 'db2' }).oneOf('kind', ['oracle', 'mssql']), /one of: oracle, mssql/);
  err(() => body({ due: '2026-02-30' }).date('due'), /YYYY-MM-DD/);
  err(() => body({ due: '2030-01-01' }).date('due', { notFuture: true, now: Date.parse('2026-10-22') }), /future/);
  err(() => body({ ids: 'a1' }).list('ids'), /must be a list/);
  err(() => body({ ids: ['ok', '../etc'] }).list('ids', { item: 'id' }), /ids\[1\]/);
  err(() => body({ ids: new Array(11).fill('a') }).list('ids', { max: 10 }), /more than 10/);
  err(() => body({ from: '2026-10-10', to: '2026-10-01' }).date('from').date('to').rule((o) => o.to < o.from && 'to must be after from'), /after from/);
  err(() => param('a/b'), /id is not a valid id/);
  assert.equal(param('ast_12'), 'ast_12');
});
