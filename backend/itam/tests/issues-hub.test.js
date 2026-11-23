// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Issues Management (engine/issues-hub.js) through the real routes on SYNTHETIC records in each source: audit team findings (a
// draft is not an issue), inspection actions, GRC actions, regulator findings in the Audit Repository; significance mapping,
// overdue, repeats, possible duplicates across sources, the escalation list, MTTR, links to a GRC risk / a duplicate (validated,
// reversible, audited), the export (audited), roles (viewer counts only, operator works, an AI identity refused).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };
const T0 = Date.parse('2026-11-08T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  const C = (n) => e.app.store.collection(n);
  C('ia_findings').put({ id: 'ITA-001', engagement: 'ENG-001', area: 'access', title: 'Privileged access review not performed quarterly', rating: 'high', state: 'open', owner: 'it.manager.syn', due: '2026-09-01', raised_at: '2026-08-01T08:00:00Z', history: [] });
  C('ia_findings').put({ id: 'ITA-002', title: 'Draft only (synthetic)', rating: 'high', state: 'draft', owner: 'x', raised_at: '2026-10-01T08:00:00Z' });
  C('csa_findings').put({ id: 'CSA-001', title: 'Firewall rules not reviewed (synthetic)', rating: 'medium', state: 'closed', owner: 'net.syn', raised_at: '2026-09-01T08:00:00Z', history: [{ at: '2026-09-11T08:00:00Z', what: 'closed after retest' }] });
  C('grc_actions').put({ id: 'ACT-0001', title: 'Quarterly privileged access review not performed', source: 'nca_ecc', ref: '2-2', priority: 'high', status: 'open', owner: 'it.manager.syn', due: '2026-12-31', created_at: '2026-10-01T08:00:00Z' });
  C('insp_actions').put({ id: 'act-0123456789', inspection: 'ins-0123456789', site: 'JED-SYN', item: 'n1', item_text: 'Network cabinet locked', severity: 'critical', likelihood: 4, impact: 5, state: 'open', due: '2026-11-01', created_at: '2026-10-25T08:00:00Z', history: [] });
  C('ar_findings').put({ id: 'ARF-00001', year: 2025, body: 'SAMA', title: 'Backup restore not tested (synthetic)', status: 'open', owner: 'infra.syn', due: '2026-06-30', created_at: '2026-01-15T08:00:00Z', repeat: [{ of: 'ARF-00000' }] });
  C('grc_risks').put({ id: 'RSK-001', title: 'Unauthorised privileged access (synthetic)', status: 'open' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}

test('one register across sources: mapping, overdue, repeats, regulator, possible duplicates, escalation, MTTR', async (t) => {
  const { call } = await setup(t);
  const r = await call('GET', '/issues', undefined, OP); assert.equal(r.status, 200, r.text);
  const v = r.json, I = Object.fromEntries(v.issues.map((i) => [i.key, i]));
  assert.ok(!I['ia:ITA-002'], 'a draft finding is not an issue yet');
  assert.equal(I['ia:ITA-001'].significance, 'high'); assert.equal(I['ia:ITA-001'].overdue_days, 68);
  assert.equal(I['inspect:act-0123456789'].significance, 'critical');
  assert.equal(I['repo:ARF-00001'].regulator, true); assert.equal(I['repo:ARF-00001'].repeat, true); assert.equal(I['repo:ARF-00001'].significance, 'high', 'a regulator finding without a rating counts as high');
  assert.equal(I['csa:CSA-001'].status, 'resolved'); assert.equal(v.learning.mttr_days.csa.days, 10);
  assert.equal(v.kpis.open, 4); assert.equal(v.kpis.regulator_open, 1); assert.equal(v.kpis.repeats_open, 1);
  assert.ok(v.duplicates.some((d) => [d.a, d.b].sort().join() === ['grc:ACT-0001', 'ia:ITA-001'].sort().join()), 'the same weakness raised by the IT audit and as a GRC action');
  const esc = v.escalate.map((x) => x.key); assert.ok(esc.includes('ia:ITA-001'), 'high and 68 days overdue'); assert.ok(esc.includes('repo:ARF-00001'), 'regulator, repeat, overdue');
  assert.ok(!esc.includes('grc:ACT-0001'), 'not overdue');
  assert.match(v.learning.note, /withheld/);
  assert.ok(Object.values(v.sources).every((x) => x.ok), 'every source read');
});

test('links: to a GRC risk or as a duplicate - validated, reversible, audited; roles; export audited', async (t) => {
  const { call, e } = await setup(t);
  const v = (await call('GET', '/issues', undefined, VIEW)).json; assert.equal(v.issues, undefined, 'a viewer sees counts only'); assert.equal(v.kpis.open, 4);
  const k = encodeURIComponent('ia:ITA-001');
  assert.equal((await call('POST', '/issues/' + k + '/link', { risk: 'RSK-001' }, VIEW)).status, 403);
  assert.equal((await call('POST', '/issues/' + k + '/link', { risk: 'RSK-001' }, { user: 'ai:grc', role: 'operator' })).status, 403, 'an AI identity cannot link');
  let r = await call('POST', '/issues/' + k + '/link', { risk: 'risk one' }, OP); assert.equal(r.status, 400); assert.match(r.text, /risk/);
  r = await call('POST', '/issues/' + k + '/link', { risk: 'RSK-999' }, OP); assert.equal(r.status, 400); assert.match(r.text, /no GRC risk/);
  r = await call('POST', '/issues/' + k + '/link', { duplicate_of: 'ia:ITA-001' }, OP); assert.equal(r.status, 400);
  assert.equal((await call('POST', '/issues/bad%20key/link', { risk: 'RSK-001' }, OP)).status, 400);
  r = await call('POST', '/issues/' + encodeURIComponent('grc:ACT-0001') + '/link', { duplicate_of: 'ia:ITA-001', note: 'same weakness (synthetic)' }, OP); assert.equal(r.status, 200, r.text);
  r = await call('POST', '/issues/' + k + '/link', { risk: 'RSK-001' }, OP); assert.equal(r.status, 200);
  let w = (await call('GET', '/issues', undefined, OP)).json;
  assert.equal(w.issues.find((i) => i.key === 'ia:ITA-001').link.risk, 'RSK-001');
  assert.equal(w.kpis.possible_duplicates, 0, 'a confirmed duplicate leaves the possible-duplicates list'); assert.equal(w.kpis.open, 3, 'and is not counted twice');
  r = await call('POST', '/issues/' + encodeURIComponent('grc:ACT-0001') + '/link', {}, OP); assert.equal(r.status, 200); assert.equal(r.json.link, null);
  w = (await call('GET', '/issues', undefined, OP)).json; assert.equal(w.kpis.open, 4, 'reversible');
  assert.equal((await call('GET', '/issues/export', undefined, VIEW)).status, 403);
  const x = await call('GET', '/issues/export', undefined, OP); assert.equal(x.status, 200); assert.match(x.json.csv, /ARF-00001/);
  const a = e.app.store.auditTail(30).map((y) => y.action); for (const n of ['issues.link', 'issues.link.remove', 'issues.export']) assert.ok(a.includes(n), n);
});
