// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 9h (docs/PYTHON-MIGRATION.md): the Desk Support and Budget store writes decided by
// pyengine/desk_budget_write.py and committed by engine/py-writer.js must do exactly what Node.js does, over HTTP:
// desk settings (modes, technicians, rules, the patch window, arming auto-approval and keeping who armed it), a patch
// request found by resource id, taking over a request the AI engineer raised (and refusing a person's); last year's
// budget import (envelope / area / kind read from free text, amounts with "SAR" and commas), requirements added / edited
// by hand, deleting one, budget settings. Same answers (pages built by Node.js after the write), records and audit
// entries; Python decides every write. Ticket triage, patch approval and budget decisions stay in Node.js.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z');

test('Python-decided Desk Support and Budget writes do exactly what Node.js does', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const RealDate = Date, realRB = crypto.randomBytes;
  global.Date = class extends RealDate { constructor(...a) { if (a.length) super(...a); else super(NOW); } static now() { return NOW; } };
  let seq = 0;
  crypto.randomBytes = function (n, cb) { if ((n < 4 || n > 6) || cb) return realRB.apply(this, arguments); seq++; return Buffer.from(String(seq).padStart(2 * n, '0'), 'hex'); };
  t.after(() => { global.Date = RealDate; crypto.randomBytes = realRB; });
  const N = await startApp({ noAi: true, config: { deskSupport: { engine: 'node' }, budget: { engine: 'node' } } }), P = await startApp({ noAi: true, config: { discovery: { python_bin: PY } } });
  t.after(async () => { await N.close(); await P.close(); });
  for (const e of [N, P]) {
    require('../engine/desksupport').registerDeskSupport(e.app.srv, e.app);
    require('../engine/budget').registerBudget(e.app.srv, e.app);
    const c = e.app.store.collection('me_ec_computers');
    c.put({ id: 'r9', resource_id: 'r9', name: 'PC-9', critical: 3, missing: 5 });
    c.put({ id: 'ec-77', resource_id: 'R77', name: 'PC-77', critical: 1, missing: 1 });
    e.app.store.collection('desk_patch').put({ id: 'dp_ai000001', resource_id: 'r9', name: 'PC-9', critical: 3, missing: 5, state: 'requested', requested_by: 'duty:desktop', requested_at: '2026-10-18T22:00:00.000Z', history: [{ at: '2026-10-18T22:00:00.000Z', by: 'duty:desktop', what: 'raised' }] });
  }
  const strip = (j) => JSON.parse(JSON.stringify(j));
  let i = 0;
  const both = async (method, path, body, user = 'syed', role = 'admin') => {
    i++;
    seq = i * 100; const a = await N.req(method, path, { body, user, role });
    seq = i * 100; const b = await P.req(method, path, { body, user, role });
    assert.equal(b.status, a.status, path + ' status ' + a.text);
    assert.deepEqual(strip(b.json), strip(a.json), method + ' ' + path + ' ' + JSON.stringify(body));
    return a.json;
  };
  // ---- Desk Support
  await both('POST', '/me/desk/config', { mode: ' SUGGEST ', technicians: [{ name: ' Ali ', email: 'ali@x', skills: 'network, vpn ,' }, { skills: ['x'] }, 'bob'], priority_rules: [['Urgent', 'down'], ['Critical', 'x'], 'no', ['Low']], groups: [['Net', 'wifi'], []], max_per_run: '30', patch: { mode: 'Auto', min_critical: '2', window_start: '21:30', auto_approve: true } });
  await both('POST', '/me/desk/config', { patch: { auto_approve: true, window_end: '05:00' } });            // still armed: who armed it is kept
  await both('POST', '/me/desk/config', { patch: { window_start: '25:00' } });
  await both('POST', '/me/desk/config', { max_per_run: 0 });
  await both('POST', '/me/desk/config', { patch: [], ack_status: '  ', first_response: 'Hello' });
  await both('POST', '/me/desk/patch/r9/request', {}, 'eng1', 'operator');
  await both('POST', '/me/desk/patch/R77/request', {}, 'eng1', 'operator');                                 // found by resource id
  await both('POST', '/me/desk/patch/none/request', {}, 'eng1', 'operator');
  await both('POST', '/me/desk/patch/dp_ai000001/endorse', {}, 'eng1', 'operator');
  await both('POST', '/me/desk/patch/dp_ai000001/endorse', {}, 'eng2', 'operator');                         // no longer the AI's
  const mine = P.app.store.collection('desk_patch').all().find((x) => x.requested_by === 'eng1' && x.resource_id === 'R77');
  await both('POST', '/me/desk/patch/' + mine.id + '/endorse', {}, 'eng2', 'operator');
  await both('POST', '/me/desk/patch/nope/endorse', {}, 'eng2', 'operator');
  // ---- Budget
  await both('POST', '/budget/previous', { fy: '2026', rows: [{ item: 'Core switch refresh', envelope: 'IT Operations', category: 'Network', capex_opex: 'CAPEX', approved: 'SAR 1,250,000.555', spent: '400000' }, { title: 'SOC subscription', department: 'Cyber Security', type: 'Opex', budget_amount: 90000, actual: null }, { description: 'Printers', amount: 'abc' }, { notes: 'no title' }, 'junk'] });
  await both('POST', '/budget/previous', { fy: 1999, rows: [{ title: 'x' }] });
  await both('POST', '/budget/previous', { fy: 2026, rows: [] });
  await both('POST', '/budget/lines', { envelope: 'cyber', area: 'applications', kind: 'opex', title: 'EDR renewal', amount: '120,000', priority: 'must', due: '2027-03-01', justification: ' contract ends ' });
  await both('POST', '/budget/lines', { envelope: 'it_ops', kind: 'capex', title: 'New SAN', amount: '' });
  await both('POST', '/budget/lines', { envelope: 'toString', kind: 'capex', title: 'x y z' });              // AREAS['toString'] in JS: Node.js decides
  await both('POST', '/budget/lines', { envelope: 'it_ops', kind: 'other', title: 'abc' });
  await both('POST', '/budget/lines', { envelope: 'it_ops', kind: 'opex', title: 'ab' });
  await both('POST', '/budget/lines', { envelope: 'it_ops', kind: 'opex', title: 'Bad amount', amount: 'lots' });
  const san = P.app.store.collection('budget_lines').all().find((x) => x.title === 'New SAN');
  await both('POST', '/budget/lines', { id: san.id, envelope: 'it_ops', kind: 'capex', title: 'New SAN (60 TB)', amount: 'sr 800000', due: 'soon' });
  await both('PUT', '/budget/settings', { fy: 2027, currency: 'usd', envelopes: { it_ops: '70,000,000', cyber: 'x' } });
  await both('PUT', '/budget/settings', { currency: 'us dollars' });
  await both('PUT', '/budget/settings', { envelopes: { cyber: '35000000' }, unit_costs: { server: '45000', firewall: '', laptop: 5 }, support_pct: '', inflation_pct: '3.5', storage_warn_pct: 101 });
  await both('PUT', '/budget/settings', { unit_costs: { server: '45000', storage_tb: null }, inflation_pct: '3.5' });
  await both('POST', '/budget/lines/' + encodeURIComponent(san.id) + '/delete', {});
  await both('POST', '/budget/lines/' + encodeURIComponent(san.id) + '/delete', {});
  for (const c of ['desk_config', 'desk_patch', 'budget_settings', 'budget_previous', 'budget_lines']) assert.deepEqual(P.app.store.collection(c).all(), N.app.store.collection(c).all(), c + ': the same records');
  const audits = (e) => strip(e.app.store.auditTail(2000, (x) => /^(desk|budget)\./.test(x.action)).map(({ at, prev, hash, seq: _s, ...rest }) => rest));
  assert.deepEqual(audits(P), audits(N), 'the same audit entries');
  const d = P.app.deskWriteStats(), bs = P.app.budgetWriteStats();
  assert.deepEqual({ py: d.python + bs.python, node: d.node + bs.node, changed: d.changed_meanwhile + bs.changed_meanwhile }, { py: i - 1, node: 1, changed: 0 }, 'Python decided all but the one handed back: ' + JSON.stringify({ d, bs }));
  assert.deepEqual(bs.node_by_op, { 'budget.line': 1 });
  const cfg = P.app.store.collection('desk_config').get('cfg').values;
  assert.equal(cfg.patch.auto_approve, false, 'a later save without auto_approve disarms it'); assert.equal(cfg.patch.armed_by, undefined); assert.equal(cfg.mode, 'suggest'); assert.equal(cfg.technicians.length, 1, 'entries with neither a name nor an e-mail are dropped');
  const prev = P.app.store.collection('budget_previous').get('current');
  assert.equal(prev.rows[0].approved, 1250000.56); assert.equal(prev.rows[0].envelope, 'it_ops'); assert.equal(prev.rows[1].envelope, 'cyber');
});
