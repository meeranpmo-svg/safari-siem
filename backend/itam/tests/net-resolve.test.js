// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The name behind an IP (engine/net-resolve.js) with a SYNTHETIC DNS: a PTR confirmed by the forward lookup gives the short name in
// capitals and the FQDN; a PTR that does not point back is said as stale; no PTR and DNS not answering say what to do; validation names
// the field; the route is operator-only (viewer refused) through the real app.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createResolve } = require('../engine/net-resolve');

const err = (code) => Object.assign(new Error(code), { code });
const fakeDns = {
  reverse: async (ip) => { if (ip === '10.0.1.12') return ['hqdc01.safari-syn.example']; if (ip === '10.0.1.40') return ['old-host.safari-syn.example.']; if (ip === '10.0.1.99') throw err('ENOTFOUND'); throw err('ETIMEOUT'); },
  resolve4: async (n) => { if (n === 'hqdc01.safari-syn.example') return ['10.0.1.12']; if (n === 'old-host.safari-syn.example') return ['10.0.1.77']; throw err('ENOTFOUND'); },
  resolve6: async () => { throw err('ENODATA'); },
};

test('lookup: confirmed, stale, none, DNS down, validation', async () => {
  const R = createResolve({ resolver: fakeDns });
  let r = await R.lookup('10.0.1.12'); assert.deepEqual([r.found, r.name, r.fqdn, r.confirmed], [true, 'HQDC01', 'hqdc01.safari-syn.example', true]);
  r = await R.lookup('10.0.1.40'); assert.equal(r.found, true); assert.equal(r.confirmed, false); assert.match(r.why, /may be stale/); assert.equal(r.fqdn, 'old-host.safari-syn.example', 'trailing dot removed');
  r = await R.lookup('10.0.1.99'); assert.equal(r.found, false); assert.match(r.why, /no name \(PTR record\)/);
  r = await R.lookup('10.0.1.50'); assert.equal(r.found, false); assert.match(r.why, /did not answer \(ETIMEOUT\)/);
  await assert.rejects(R.lookup(''), /ip is required/); await assert.rejects(R.lookup('hqdc01; rm'), /not an IP address/);
});

test('route: operator, viewer refused', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, dnsResolver: fakeDns, python: process.env.PYTHON || 'python3' });
  let r = await e.req('GET', '/discovery/resolve?ip=10.0.1.12', { user: 'vera.syn', role: 'viewer' }); assert.equal(r.status, 403);
  r = await e.req('GET', '/discovery/resolve?ip=10.0.1.12', { user: 'nora.syn', role: 'operator' }); assert.equal(r.status, 200, r.text); assert.equal(r.json.name, 'HQDC01');
  r = await e.req('GET', '/discovery/resolve?ip=nope', { user: 'nora.syn', role: 'operator' }); assert.equal(r.status, 400); assert.match(r.json.error, /ip:/);
});
