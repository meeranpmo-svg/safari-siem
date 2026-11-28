'use strict';
// engine/http.js: a server error after start-up is logged, never an uncaught exception.
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeHttp = require('node:http');
const { createServer } = require('../engine/http');

test('a server error after listen is logged instead of crashing', async () => {
  const real = nodeHttp.createServer; let captured = null;
  nodeHttp.createServer = function (...a) { captured = real.apply(this, a); return captured; };
  const logged = [];
  const srv = createServer({ host: '127.0.0.1', port: 0, proxySecret: 'synthetic-secret-0123456789', log: { error: (m, d) => logged.push([m, d]), warn() {}, every() {} } });
  try {
    await srv.start();
    assert.ok(captured, 'the http server was created');
    assert.doesNotThrow(() => captured.emit('error', new Error('synthetic late failure')));
    assert.equal(logged.length, 1); assert.match(logged[0][0], /itam http server error/); assert.equal(logged[0][1].err, 'synthetic late failure');
  } finally { nodeHttp.createServer = real; await srv.stop(); }
});
