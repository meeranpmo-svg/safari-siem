// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// engine/discovery/httpc.js servername: an appliance reached by IP but configured for a host name gets that name as the TLS
// server name; a value that is not a host name is refused before anything is sent.
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const { request } = require('../engine/discovery/httpc');

test('servername: refused when not a host name; passed to TLS when it is', async () => {
  await assert.rejects(request('https://10.10.10.63/x', { servername: 'bad name!' }), /invalid servername/);
  const orig = https.request; let seen = null;
  https.request = (opts) => { seen = opts; const fake = new (require('node:events'))(); fake.setTimeout = () => {}; fake.end = () => fake.emit('error', Object.assign(new Error('stop'), { code: 'ESTOP' })); fake.write = () => {}; fake.destroy = () => {}; fake.on = fake.on.bind(fake); return fake; };
  try { await request('https://10.10.10.63/x', { servername: 'esg.corpgroup.test', headers: { Host: 'esg.corpgroup.test' }, timeoutMs: 1000 }).catch(() => null); }
  finally { https.request = orig; }
  assert.ok(seen, 'a request was built'); assert.equal(seen.servername, 'esg.corpgroup.test'); assert.equal(seen.hostname, '10.10.10.63'); assert.equal(seen.headers.Host, 'esg.corpgroup.test');
});

test('a connection with no HTTP answer keeps the OS code in sys, so the caller can say what to fix', async () => {
  const net = require('node:net'), srv = net.createServer(); await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port; await new Promise((r) => srv.close(r));   // a port nothing listens on
  const e = await request('https://127.0.0.1:' + port + '/x', { timeoutMs: 3000 }).then(() => null, (x) => x);
  assert.ok(e); assert.equal(e.code, 'unreachable'); assert.equal(e.sys, 'ECONNREFUSED');
});
