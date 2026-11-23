// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ITAM Overview (engine/itam-overview.js) over SYNTHETIC data: the health score is withheld below 3 measured parts and never counts
// an unmeasured part as good; with data it is the weighted mean of the measured parts, itemised; actions come from the modules
// (findings, renewals, duplicates, ghosts) ranked with the page that fixes them; a module that throws is named in errors; viewers do
// not get purchasing (operator route) and see it as "operators"; the daily snapshot feeds the trend; viewers read; unauthenticated refused.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, VW = { user: 'vera.syn', role: 'viewer' };
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString();
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}

test('empty register: score withheld, nothing counted as good, honest modules', async (t) => {
  const { call } = await setup(t);
  const v = (await call('GET', '/itam/overview', undefined, VW)).json;
  assert.equal(v.health.score, null); assert.match(v.health.why, /withheld/);
  assert.ok(v.health.components.every((c) => c.measured === false && c.points === 0), 'no part counted without data');
  assert.equal(v.tiles.assets, 0);
  assert.equal(v.modules.find((m) => m.key === 'purchasing').state, 'operators', 'viewer: purchasing is for operators');
  assert.equal(v.budget, null);
});

test('with data: weighted score, itemised, actions ranked with links, errors named, trend', async (t) => {
  const { e, call } = await setup(t);
  const A = e.app.store.collection('assets'), now = new Date().toISOString();
  for (let i = 0; i < 4; i++) A.put({ id: 'w' + i, name: 'WS-SYN-' + i, type: 'workstation', status: 'in_use', networked: true, site: 'Riyadh', serial: 'SERSYN' + i, owner: 'o' + i, department: 'IT', vendor: 'SynV', model: 'M1', last_seen: ago(1), updated_at: now });
  A.put({ id: 'dup', name: 'WS-SYN-0b', type: 'workstation', status: 'in_use', serial: 'SERSYN0', last_seen: ago(1), updated_at: now });
  A.put({ id: 'ghost', name: 'SRV-SYN-OLD', type: 'server', status: 'retired', networked: true, last_seen: ago(1), updated_at: now });
  e.app.store.collection('findings').put({ id: 'f1', key: 'k1', kind: 'warranty_expired', severity: 'high', asset_id: 'w1', title: 'Warranty expired on WS-SYN-1', status: 'open', created_at: ago(40), evidence: {} });
  // a closed stocktake gives the accuracy part
  e.app.store.collection('stocktakes').put({ id: 'stk_syn', name: 'SYN', site: 'Riyadh', status: 'closed', opened_at: ago(10), closed_at: ago(9), expected: ['w0', 'w1', 'w2', 'w3'], scanned: [{ asset_id: 'w0' }, { asset_id: 'w1' }, { asset_id: 'w2' }], unexpected: [], missing: ['w3'] });
  const v = (await call('GET', '/itam/overview', undefined, ADM)).json;
  const C = Object.fromEntries(v.health.components.map((c) => [c.key, c]));
  assert.ok(C.quality.measured && C.stocktake.measured && C.findings.measured, 'three parts measured');
  assert.equal(C.stocktake.value, 75); assert.equal(C.licences.measured, false); assert.equal(C.licences.points, 0);
  const m = v.health.components.filter((c) => c.measured), w = m.reduce((n, c) => n + c.weight, 0);
  assert.equal(v.health.score, Math.round(m.reduce((n, c) => n + c.weight * c.value, 0) / w), 'weighted mean of the measured parts');
  assert.ok(Math.abs(m.reduce((n, c) => n + c.points, 0) - v.health.score) <= 1, 'points add up to the score');
  const titles = v.actions.map((a) => a.title).join(' | ');
  assert.match(titles, /Warranty expired on WS-SYN-1/); assert.match(titles, /duplicate/); assert.match(titles, /retired asset\(s\) still seen/);
  assert.ok(v.actions.every((a) => /\.html$/.test(a.href)), 'every action links to the page that fixes it');
  for (let i = 1; i < v.actions.length; i++) assert.ok(v.actions[i - 1].priority >= v.actions[i].priority, 'ranked');
  assert.equal(v.tiles.assets, 5); assert.equal(v.modules.find((x) => x.key === 'purchasing').state, 'ok', 'admin gets purchasing');
  // a module that throws is named, the rest still answer
  const orig = e.app.addons.softwareStudio.analyse; e.app.addons.softwareStudio.analyse = () => { throw new Error('synthetic failure'); };
  const v2 = (await call('GET', '/itam/overview', undefined, ADM)).json; e.app.addons.softwareStudio.analyse = orig;
  assert.deepEqual(v2.errors, [{ module: 'software', error: 'synthetic failure' }]); assert.equal(v2.modules.find((x) => x.key === 'software').state, 'error'); assert.equal(v2.tiles.assets, 5);
  // trend
  const s = await e.app.addons.itamOverview.snapshot(); assert.equal(s.score, v.health.score);
  const v3 = (await call('GET', '/itam/overview', undefined, VW)).json; assert.equal(v3.trend.length, 1); assert.equal(v3.trend[0].score, v.health.score);
  assert.equal((await e.req('GET', '/itam/overview', { user: '', role: '' })).status >= 400, true, 'needs a signed-in role');
});
