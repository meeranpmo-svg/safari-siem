// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ITAM AI Findings intelligence (engine/findings-intel.js) over SYNTHETIC findings: priority itemised (severity, asset classification /
// CIA / type, age, recurrence, what people did with the kind before); per-kind learning (dismissal rate, reasons, tuning suggestion
// over >= 5 decisions); hotspots and 12-week trend; bulk accept / dismiss / reopen by a person (service identity refused), dismissal
// needs a reason, unknown ids 404, validation 400, viewer refused, audited per finding and in bulk; viewers read.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'asset.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString();
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const col = e.app.store.collection('findings');
  let n = 0;
  const put = (o) => { const id = 'fnd-syn-' + (++n); col.put(Object.assign({ id, key: 'k' + n, kind: 'missing_owner', severity: 'low', asset_id: null, licence_id: null, title: 'SYN finding ' + n, detail: '', evidence: {}, status: 'open', ai_label: 'AI — verify', created_at: ago(1) }, o, { id })); return id; };
  const mk = async (o) => { const r = await call('POST', '/assets', o, ADM); assert.equal(r.status, 200, JSON.stringify(r.json)); return (r.json.asset || r.json).id; };
  return { e, call, put, mk, col };
}

test('priority is itemised: severity, a critical asset, age, recurrence; learning lowers a kind people dismiss', async (t) => {
  const { call, put, mk } = await setup(t);
  const crit = await mk({ name: 'SRV-SYN-CORE', type: 'server', classification: 'secret', cia: { c: 'high', i: 'high', a: 'high' }, site: 'HQ-SYN', owner: 'owner.syn' });
  const lap = await mk({ name: 'LT-SYN-1', type: 'laptop', site: 'BR-SYN' });
  const hi = put({ kind: 'warranty_expired', severity: 'high', asset_id: crit, created_at: ago(40), reopened_at: ago(2) });
  const lo = put({ kind: 'missing_location', severity: 'low', asset_id: lap });
  // people dismissed 'missing_location' 6 of 7 times, mostly "remote worker"
  for (let i = 0; i < 6; i++) put({ kind: 'missing_location', status: 'dismissed', reason: i < 4 ? 'Remote worker' : 'n/a', created_at: ago(20), dismissed_at: ago(18) });
  put({ kind: 'missing_location', status: 'accepted', created_at: ago(20), accepted_at: ago(19) });
  const v = (await call('GET', '/ai/findings/intel', undefined, VW)).json;
  const H = v.open.find((f) => f.id === hi), L = v.open.find((f) => f.id === lo);
  assert.equal(v.open[0].id, hi, 'the critical, old, recurring finding comes first');
  for (const w of [/high severity/, /classified secret/, /high CIA/, /server/, /open 40 days/, /came back/]) assert.ok(H.why.some((x) => w.test(x.why)), 'reason ' + w);
  assert.equal(H.priority, Math.min(100, H.why.reduce((s, x) => s + x.points, 0)), 'the score is the sum of its reasons');
  assert.ok(L.why.some((x) => x.points < 0 && /dismiss 86 %/.test(x.why)), 'a mostly-dismissed kind is lowered, with the count');
  const k = v.kinds.find((x) => x.kind === 'missing_location');
  assert.equal(k.dismissal_rate, 86); assert.equal(k.decided, 7); assert.equal(k.top_reasons[0].reason, 'remote worker'); assert.equal(k.top_reasons[0].n, 4);
  assert.match(k.tuning, /dismissed 6 of 7/); assert.equal(k.median_days_to_decide, 2);
  assert.equal(k.fix.href, 'inventory.html');
  assert.equal(v.kpis.open, 2); assert.equal(v.kpis.high, 1); assert.equal(v.kpis.aged, 1); assert.equal(v.kpis.recurring, 1); assert.equal(v.kpis.noisy_kinds, 1);
  assert.equal(v.hotspots.assets[0].asset_id, crit); assert.ok(v.hotspots.sites.some((s) => s.value === 'HQ-SYN'));
  assert.equal(v.trend.length, 12); assert.equal(v.trend.reduce((s, w) => s + w.closed, 0), 7);
});

test('an empty register returns an honest empty view', async (t) => {
  const { call } = await setup(t);
  const v = (await call('GET', '/ai/findings/intel', undefined, VW)).json;
  assert.equal(v.kpis.open, 0); assert.deepEqual(v.open, []); assert.deepEqual(v.kinds, []); assert.equal(v.trend.length, 12);
});

test('bulk decisions: a person, a reason to dismiss, roles, validation, audit', async (t) => {
  const { e, call, put, col } = await setup(t);
  const a = put({}), b = put({}), c = put({});
  assert.equal((await call('POST', '/ai/findings/bulk', { ids: [a], status: 'accepted' }, VW)).status, 403, 'viewers do not decide');
  assert.equal((await call('POST', '/ai/findings/bulk', { ids: [a], status: 'accepted' }, { user: 'system:bot', role: 'admin' })).status, 403, 'a service identity does not decide');
  let r = await call('POST', '/ai/findings/bulk', { ids: [a], status: 'closed' }, OP); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /status/);
  r = await call('POST', '/ai/findings/bulk', { status: 'accepted' }, OP); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /ids/);
  r = await call('POST', '/ai/findings/bulk', { ids: [a, b], status: 'dismissed' }, OP); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /reason/);
  r = await call('POST', '/ai/findings/bulk', { ids: [a, 'fnd-nope'], status: 'accepted' }, OP); assert.equal(r.status, 404);
  assert.equal(col.get(a).status, 'open', 'nothing changes when one id is unknown');
  r = await call('POST', '/ai/findings/bulk', { ids: [a, b], status: 'dismissed', reason: 'Spare stock, synthetic', extra: 1 }, OP);
  assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.updated, 2);
  assert.equal(col.get(a).status, 'dismissed'); assert.equal(col.get(a).dismissed_by, OP.user); assert.equal(col.get(a).reason, 'Spare stock, synthetic');
  r = await call('POST', '/ai/findings/bulk', { ids: [a], status: 'open' }, OP); assert.equal(r.status, 200); assert.equal(col.get(a).status, 'open', 'reopened');
  r = await call('POST', '/ai/findings/bulk', { ids: [c], status: 'accepted' }, OP); assert.equal(r.status, 200); assert.equal(col.get(c).status, 'accepted');
  const au = e.app.store.auditTail(200);
  const bulk = au.filter((x) => x.action === 'ai.findings.bulk');
  assert.equal(bulk.length, 3); assert.equal(bulk[0].by, OP.user); assert.ok(bulk.some((x) => x.detail.count === 2 && x.detail.status === 'dismissed' && x.detail.reason === 'Spare stock, synthetic'));
  assert.equal(au.filter((x) => x.action === 'ai.findings.dismissed').length, 2, 'each finding is also audited');
});
