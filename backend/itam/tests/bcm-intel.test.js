// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Business Continuity & DR Matrix (engine/bcm-intel.js) over the REAL DR & BCM drill register with SYNTHETIC drills and a SYNTHETIC
// DR Studio: a tested, passing, signed-off system within its RPO is ready; a system never tested is UNTESTED whatever its replication
// says; overdue and failed are said; readiness itemised over what is measured only; the next-test pass chance (Beta(1,1)); RTO worsening
// across three tests; a GRC test action raised by a person (untested / overdue / failed only, once, audited); roles; advisor off.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const D = e.app.store.collection('grc_drills'), put = (id, o) => D.put(Object.assign({ id, status: 'completed', type: 'failover', frequency_months: 12, result: 'pass', history: [], signoff: { by: 'syed', at: Date.now() } }, o));
  put('DR-0001', { system: 'Core insurance (synthetic)', executed: ago(400), rto_target_min: 240, rto_actual_min: 120, rpo_target_min: 60, rpo_actual_min: 20 });
  put('DR-0002', { system: 'Core insurance (synthetic)', executed: ago(250), rto_target_min: 240, rto_actual_min: 180, rpo_target_min: 60, rpo_actual_min: 30 });
  put('DR-0003', { system: 'Core insurance (synthetic)', executed: ago(60), rto_target_min: 240, rto_actual_min: 230, rpo_target_min: 60, rpo_actual_min: 30 });
  put('DR-0004', { system: 'Claims portal (synthetic)', executed: ago(500), result: 'pass', rto_target_min: 120, rto_actual_min: 60 });   // overdue
  put('DR-0005', { system: 'Email (synthetic)', executed: ago(30), result: 'fail', rto_target_min: 60, rto_actual_min: 200 });
  e.app.addons.drStudio = { view: async () => ({ streams: [{ key: 'ntx:1:core', system: 'Core insurance (synthetic)', tech: 'Nutanix protection domain', lag_s: 600, rpo_s: 3600 }, { key: 'dg:hr', system: 'HR database (synthetic)', tech: 'Data Guard standby', lag_s: 120, rpo_s: 900 }] }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}
const row = (v, id) => v.sections[0].items.find((i) => i.id === id);

test('the matrix: ready, untested whatever its replication, overdue, failed; readiness itemised; learning', async (t) => {
  const s = await setup(t);
  const r = await s.get('/bcm-intel', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  const core = row(v, 'Core insurance (synthetic)'); assert.ok(core.tags.includes('ready')); assert.equal(core.metrics[0].value, '100%');
  assert.match(core.detail.rows.find((x) => x[0] === 'Chance the next test passes')[1], /80 % \(Beta\(1,1\) over 3/);
  assert.match(core.detail.rows.find((x) => x[0] === 'RTO across tests')[1], /a week over 3|over 3 snapshots/); assert.ok(core.badges.some((b) => /RTO worsening/.test(b.text)));
  const hr = row(v, 'HR database (synthetic)'); assert.ok(hr.tags.includes('untested'), 'replication alone is not readiness'); assert.ok(hr.detail.lists[0].items.some((i) => /within its RPO/.test(i)));
  assert.ok(row(v, 'Claims portal (synthetic)').tags.includes('overdue')); assert.ok(row(v, 'Email (synthetic)').tags.includes('failed'));
  assert.ok(row(v, 'Email (synthetic)').detail.lists[0].items.some((i) => /✗ RTO missed/.test(i)));
  assert.equal(v.kpis.find((k) => k.label === 'Untested').value, 1); assert.match(v.note, /never been tested is untested/);
});

test('a GRC test action by a person, once; roles', async (t) => {
  const s = await setup(t), P = (n) => '/bcm-intel/' + encodeURIComponent(n) + '/drill';
  assert.equal((await s.post(P('Email (synthetic)'), {}, VIEW)).status, 403);
  assert.equal((await s.post(P('Email (synthetic)'), {}, BOT)).status, 403);
  let r = await s.post(P('Email (synthetic)'), { due: '2020-01-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /due/);
  assert.equal((await s.post(P('Core insurance (synthetic)'), {})).status, 409, 'a ready system needs no test action');
  assert.equal((await s.post(P('Nope'), {})).status, 404);
  r = await s.post(P('Email (synthetic)'), { owner: 'nora.syn' }); assert.equal(r.status, 200, r.raw);
  assert.equal((await s.post(P('Email (synthetic)'), {})).status, 409, 'once');
  assert.equal(s.audit('bcm-intel.drill').length, 1);
  assert.equal((await s.post('/bcm-intel/ask', { question: 'where would recovery fail?' })).status, 424);
});
