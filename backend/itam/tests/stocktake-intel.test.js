// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ITAM Stocktake intelligence (engine/stocktake-intel.js) over SYNTHETIC assets and real stocktake routes: progress by type /
// department, missing ranked by likelihood with reasons (seen on the network recently, portable, missed before, not seen 90+ days),
// unexpected codes matched to the closest tag / serial (O/0 folding, edit distance), misplaced assets found at another site's count,
// the next site to count; resolve by a person (service identity refused), validation 400, a scanned asset 409, unknown 404, viewer
// refused, audited; viewers read.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { fold, lev } = require('../engine/stocktake-intel');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'asset.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString();
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const A = e.app.store.collection('assets'), now = new Date().toISOString();
  const put = (o) => A.put(Object.assign({ status: 'in_use', updated_at: now, created_at: now }, o));
  put({ id: 'a1', name: 'WS-SYN-1', type: 'workstation', site: 'Riyadh', department: 'Finance', asset_tag: 'ZS-0001', serial: 'SNSYN1', last_seen: ago(1) });
  put({ id: 'a2', name: 'WS-SYN-2', type: 'workstation', site: 'Riyadh', department: 'Finance', asset_tag: 'ZS-0002', serial: 'SNSYN2', last_seen: ago(2) });
  put({ id: 'a3', name: 'LT-SYN-3', type: 'laptop', site: 'Riyadh', department: 'Sales', asset_tag: 'ZS-0003', owner: 'owner.syn', last_seen: ago(200) });
  put({ id: 'a4', name: 'SRV-SYN-4', type: 'server', site: 'Riyadh', department: 'IT', asset_tag: 'ZS-0004', classification: 'secret', last_seen: ago(150) });
  put({ id: 'j1', name: 'WS-SYN-J1', type: 'workstation', site: 'Jeddah', asset_tag: 'ZS-0101' });
  return { e, call };
}

test('fold and edit distance', () => {
  assert.equal(fold('ZS-0O1'), fold('zs001')); assert.equal(lev('as0001', 'as0010', 2), 2); assert.ok(lev('abcdef', 'zzzzzz', 2) > 2);
});

test('progress, missing with likelihood, unexpected matched, misplaced, plan', async (t) => {
  const { call } = await setup(t);
  let r = await call('POST', '/stocktake', { site: 'Riyadh', name: 'SYN Q4 Riyadh' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json)); const id = r.json.id;
  assert.equal((await call('POST', '/stocktake/' + id + '/scan', { code: 'ZS-0001' }, OP)).status, 200);
  assert.equal((await call('POST', '/stocktake/' + id + '/scan', { code: 'ZS-OOO2X' }, OP)).json.result, 'unexpected');
  assert.equal((await call('POST', '/stocktake/' + id + '/scan', { code: 'ZS-0101' }, OP)).json.result, 'found_out_of_scope');
  assert.equal((await call('POST', '/stocktake/' + id + '/scan', { code: 'ZZZ-NOPE-999' }, OP)).json.result, 'unexpected');
  const v = (await call('GET', '/stocktake-intel', undefined, VW)).json, c = v.current;
  assert.equal(c.id, id); assert.equal(c.expected, 4); assert.equal(c.found, 1); assert.equal(c.pct, 25);
  const fin = c.by_department.find((d) => d.value === 'Finance'); assert.deepEqual([fin.expected, fin.found], [2, 1]);
  const m = Object.fromEntries(c.missing.map((x) => [x.asset_id, x]));
  assert.ok(m.a2.likely_gone < 30 && /probably present/.test(m.a2.why.join(' ')), 'seen yesterday: probably present');
  assert.ok(m.a3.why.some((w) => /portable - may be with owner.syn/.test(w)), 'portable');
  assert.ok(m.a4.likely_gone >= 70 && m.a4.critical, 'not seen 150 days, critical');
  assert.equal(c.missing[0].asset_id, 'a4', 'most likely gone first');
  const u = c.unexpected.find((x) => x.code === 'ZS-OOO2X'); assert.equal(u.suggestion.asset_id, 'a2'); assert.match(u.suggestion.why, /character|same code/);
  assert.equal(c.unexpected.find((x) => x.code === 'ZZZ-NOPE-999').suggestion, null);
  assert.equal(c.misplaced.length, 1); assert.equal(c.misplaced[0].recorded_site, 'Jeddah');
  assert.ok(v.plan.find((p) => p.site === 'Jeddah').why.includes('never counted'));
  // close: missing in a second count raises the likelihood
  assert.equal((await call('POST', '/stocktake/' + id + '/close', {}, ADM)).status, 200);
  const id2 = (await call('POST', '/stocktake', { site: 'Riyadh' }, ADM)).json.id;
  const v2 = (await call('GET', '/stocktake-intel?id=' + id2, undefined, VW)).json;
  assert.ok(v2.current.missing.find((x) => x.asset_id === 'a2').why.some((w) => /also missing in 1 earlier/.test(w)));
  assert.equal(v2.kpis.last_accuracy, 25); assert.equal(v2.kpis.closed, 1);
  assert.equal((await call('GET', '/stocktake-intel?id=stk_nope', undefined, VW)).status, 404);
});

test('resolve: a person, validation, roles, audit', async (t) => {
  const { e, call } = await setup(t);
  const id = (await call('POST', '/stocktake', { site: 'Riyadh' }, ADM)).json.id;
  await call('POST', '/stocktake/' + id + '/scan', { code: 'ZS-0001' }, OP);
  assert.equal((await call('POST', '/stocktake/' + id + '/resolve', { asset_id: 'a3', outcome: 'found' }, VW)).status, 403);
  assert.equal((await call('POST', '/stocktake/' + id + '/resolve', { asset_id: 'a3', outcome: 'found' }, { user: 'system:bot', role: 'admin' })).status, 403);
  let r = await call('POST', '/stocktake/' + id + '/resolve', { asset_id: 'a3', outcome: 'gone' }, OP); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /outcome/);
  r = await call('POST', '/stocktake/' + id + '/resolve', { asset_id: 'a3', outcome: 'lost' }, OP); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /note/);
  assert.equal((await call('POST', '/stocktake/' + id + '/resolve', { asset_id: 'j1', outcome: 'found' }, OP)).status, 400, 'not expected here');
  assert.equal((await call('POST', '/stocktake/' + id + '/resolve', { asset_id: 'a1', outcome: 'found' }, OP)).status, 409, 'already scanned');
  assert.equal((await call('POST', '/stocktake/stk_nope/resolve', { asset_id: 'a3', outcome: 'found' }, OP)).status, 404);
  r = await call('POST', '/stocktake/' + id + '/resolve', { asset_id: 'a3', outcome: 'explained', note: 'with the user on leave (synthetic)', extra: 'x' }, OP);
  assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.resolution.by, OP.user); assert.equal(r.json.resolution.extra, undefined);
  const v = (await call('GET', '/stocktake-intel', undefined, VW)).json;
  const m = v.current.missing.find((x) => x.asset_id === 'a3'); assert.equal(m.resolution.outcome, 'explained'); assert.equal(v.current.resolved, 1);
  assert.equal(v.current.missing[v.current.missing.length - 1].asset_id, 'a3', 'resolved items sort last');
  assert.ok(e.app.store.auditTail(50).some((a) => a.action === 'stocktake.resolve' && a.by === OP.user && a.detail.outcome === 'explained'));
});

test('an empty register gives an honest empty view', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true });
  const v = (await e.req('GET', '/stocktake-intel', VW)).json;
  assert.equal(v.current, null); assert.deepEqual(v.stocktakes, []); assert.deepEqual(v.plan, []); assert.equal(v.kpis.last_accuracy, null);
});
