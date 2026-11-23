// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Software & Licences Studio (engine/software-studio.js) over SYNTHETIC assets and licences: seats vs installs, waste and true-up
// from the licence's own cost (costs hidden from viewers); reclaim from in-stock / not-seen assets; commercial software with no
// licence; remote-access tools; a product rare for its asset type (ML); version sprawl; the policy - a person, a reason, audited,
// approve silences risky, block raises a finding.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'sam.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const A = e.app.store.collection('assets'), old = new Date(Date.now() - 90 * 86400000).toISOString(), now = new Date().toISOString();
  const sw = (i) => [{ name: 'Microsoft Visio Professional', publisher: 'Microsoft', version: i < 3 ? '16.0.1' : '16.0.2' }, { name: 'Google Chrome', publisher: 'Google', version: String(100 + (i % 5)) }]
    .concat(i === 0 ? [{ name: 'AnyDesk', publisher: 'AnyDesk Software' }, { name: 'Autodesk AutoCAD 2024', publisher: 'Autodesk' }, { name: 'SynOddTool', publisher: 'SynSoft' }] : []);
  for (let i = 0; i < 22; i++) A.put({ id: 'ws' + i, name: 'WS-' + i, type: 'workstation', status: i === 1 ? 'in_stock' : 'in_use', last_seen: i === 2 ? old : now, software: i < 5 ? sw(i) : [{ name: 'Google Chrome', publisher: 'Google', version: '120' }] });
  e.app.store.collection('licences').put({ id: 'lic_visio', product: 'Visio', product_key_match: 'visio', seats: 10, cost: 10000, expiry: new Date(Date.now() + 30 * 86400000).toISOString(), status: 'active' });
  e.app.store.collection('licences').put({ id: 'lic_tiny', product: 'Google Chrome Enterprise', product_key_match: 'chrome', seats: 5, cost: 500, status: 'active' });
  return { e, call };
}

test('licences, reclaim, unlicensed, risky, rare, sprawl; costs only for operators', async (t) => {
  const { call } = await setup(t);
  const v = (await call('GET', '/software-studio', undefined, OP)).json;
  const visio = v.licences.find((l) => l.id === 'lic_visio');
  assert.equal(visio.used, 5); assert.equal(visio.compliance, 'under'); assert.equal(visio.utilisation_pct, 50); assert.equal(visio.waste, 5000, '5 unused seats x 1000');
  assert.equal(visio.reclaim_count, 2, 'one in stock + one not seen for 90 days'); assert.ok(visio.days_left <= 30);
  const ch = v.licences.find((l) => l.id === 'lic_tiny'); assert.equal(ch.compliance, 'over'); assert.equal(ch.true_up, 1700, '17 installs over x 100');
  const K = (k) => v.findings.filter((f) => f.kind === k);
  assert.ok(K('unlicensed').some((f) => /AutoCAD/.test(f.product)), 'commercial software with no licence');
  assert.ok(!K('unlicensed').some((f) => /Chrome/.test(f.product)), 'free software is not "unlicensed"');
  assert.ok(K('risky').some((f) => /AnyDesk/.test(f.product)));
  assert.ok(K('rare').some((f) => /SynOddTool/.test(f.product) && /on 1 of 22 workstation/.test(f.why)), 'rare for its type: ' + JSON.stringify(K('rare')));
  assert.ok(K('sprawl').some((f) => /Chrome/.test(f.product)), 'version sprawl');
  assert.equal(v.findings[0].severity, 'high');
  const vw = (await call('GET', '/software-studio', undefined, VW)).json;
  assert.equal(vw.costs_visible, false); assert.equal(vw.licences.find((l) => l.id === 'lic_visio').waste, undefined, 'viewers see no money'); assert.equal(vw.kpis.waste, undefined);
});

test('policy: a person, a reason, audited; approve silences risky, block raises a finding', async (t) => {
  const { e, call } = await setup(t);
  const key = (await call('GET', '/software-studio', undefined, OP)).json.products.find((p) => /anydesk/i.test(p.name)).key;
  assert.equal((await call('POST', '/software-studio/policy', { key, status: 'approved', reason: 'IT support tool' }, VW)).status, 403);
  assert.equal((await call('POST', '/software-studio/policy', { key, status: 'approved', reason: 'x' }, { user: 'system:bot', role: 'admin' })).status, 403, 'a service identity does not set policy');
  assert.equal((await call('POST', '/software-studio/policy', { key, status: 'approved' }, OP)).status, 400, 'a reason is required');
  assert.equal((await call('POST', '/software-studio/policy', { key, status: 'maybe', reason: 'x' }, OP)).status, 400);
  assert.equal((await call('POST', '/software-studio/policy', { key, status: 'approved', reason: 'sanctioned IT support tool' }, OP)).status, 200);
  let v = (await call('GET', '/software-studio', undefined, OP)).json;
  assert.ok(!v.findings.some((f) => f.kind === 'risky' && f.key === key), 'approved: no longer a finding');
  const odd = v.products.find((p) => p.name === 'SynOddTool').key;
  await call('POST', '/software-studio/policy', { key: odd, status: 'blocked', reason: 'not approved software' }, OP);
  v = (await call('GET', '/software-studio', undefined, OP)).json;
  assert.ok(v.findings.some((f) => f.kind === 'blocked' && f.key === odd && f.severity === 'high'));
  assert.ok(e.app.store.auditTail(30).some((a) => a.action === 'software.policy' && a.by === 'sam.syn' && a.detail.to === 'blocked'));
  await call('POST', '/software-studio/policy', { key: odd, status: 'none' }, OP);
  assert.equal((await call('GET', '/software-studio', undefined, OP)).json.policy.filter((p) => p.id === odd).length, 0, 'cleared');
});
