// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Framework Crosswalk + Gap Analysis (engine/crosswalk.js). Unit part with SYNTHETIC framework engines: one level for every result
// vocabulary (unknown = not assessed, never compliant); NCA ECC as the hub with SAMA / ISO items on it; a disagreement (met in one,
// gap in another); de-duplicated work items with itemised priority (leverage across frameworks, the SAMA engine's p_gap); not
// assessed listed apart; a framework that fails to answer shown as such; mapping suggestions (similarity) and an administrator's
// mapping (validation, audit, removal); planning a work item (roles, past date refused, audit); gaps-to-GRC through every engine;
// daily snapshots and the forecast (needs 3); export. Route part through the real ITAM with the real ECC / SAMA / ISO / NDMO engines.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createCrosswalk, levelOf } = require('../engine/crosswalk');

const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:grc', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const DAY = 86400000;
function fake(o = {}) {
  const cols = {}, col = (n) => cols[n] || (cols[n] = (() => { const m = new Map(); return { get: (k) => m.get(k), put: (x) => m.set(x.id, x), all: (f) => [...m.values()].filter(f || (() => true)), remove: (k) => m.delete(k) }; })());
  const audits = [], grc = [];
  const addons = {
    ncaEcc: { view: async () => ({ controls: [
      { id: 'ZS-1-1-01', subdomain: '1-1', subdomain_name: 'Cybersecurity Strategy', title: 'A cybersecurity strategy and roadmap are approved', severity: 'high', result: 'gap', why: 'no strategy (synthetic)' },
      { id: 'ZS-2-3-01', subdomain: '2-3', subdomain_name: 'Information System Protection', title: 'Malware protection on every endpoint', severity: 'high', result: 'verified', why: 'EDR on 98 % (synthetic)' },
      { id: 'ZS-2-12-01', subdomain: '2-12', subdomain_name: 'Event Logs and Monitoring', title: 'Security event logs are collected and monitored', severity: 'medium', result: 'no_evidence' }] }), gapsToGrc: async () => { grc.push('ecc'); return { created: 1 }; } },
    samaIa: { view: async () => ({ requirements: [
      { id: 'SA-3.1.2-01', subdomain: '3.1.2', subdomain_name: 'Cyber Security Strategy', title: 'Strategy approved by the board', severity: 'high', result: 'gap', ecc: 'ZS-1-1-01', history: { runs: 4, p_gap: 0.75 } },
      { id: 'SA-3.3.6-01', subdomain: '3.3.6', subdomain_name: 'Malware', title: 'Anti-malware deployed', severity: 'high', result: 'gap', ecc: 'ZS-2-3-01' },
      { id: 'SA-3.4.1-01', subdomain: '3.4.1', subdomain_name: 'Third party', title: 'Third party cyber security requirements in contracts', severity: 'medium', result: 'mystery-state' }] }) },
    iso27001: o.isoFails ? { view: async () => { throw new Error('rules engine timed out (synthetic)'); } } : { view: async () => ({ clauses: [], annex: [
      { id: 'A.5.1', group: '5', group_name: 'Organizational', title: 'Information security policies and strategy', severity: 'high', level: 'not', ecc: ['ZS-1-1-01'] },
      { id: 'A.8.7', group: '8', group_name: 'Technological', title: 'Protection against malware', severity: 'high', level: 'fully', ecc: ['ZS-2-3-01'] }] }), gapsToGrc: async () => { grc.push('iso'); return { created: 2 }; } },
    ndmo: { view: async () => ({ controls: [{ id: 'ZS-DG-01', domain: 'DG', domain_name: 'Data Governance', title: 'Security event logs monitoring for data platforms', severity: 'medium', result: 'gap' }] }), gapsToGrc: async () => { throw new Error('GRC is busy (synthetic)'); } },
    pdplAssessment: { summary: async () => ({ approved: null, note: 'No approved PDPL self-assessment yet.' }) },
  };
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const app = { store: { collection: col }, addons, settings: { get: () => ({}) }, audit: (a) => audits.push(a), log: { every() {}, warn() {}, info() {} } };
  const X = createCrosswalk(app, { now: () => clock, noTimer: true });
  return { X, audits, grc, tick: (ms) => { clock += ms; }, addons };
}

test('levels: every engine vocabulary maps to one level; anything unknown is not assessed, never compliant', () => {
  assert.equal(levelOf({ result: 'verified' }), 'fully'); assert.equal(levelOf({ result: 'confirmed' }), 'fully'); assert.equal(levelOf({ result: 'gap' }), 'not');
  assert.equal(levelOf({ level: 'partially' }), 'partially'); assert.equal(levelOf({ nca_level: 'not' }), 'not'); assert.equal(levelOf({ result: 'na' }), 'na');
  assert.equal(levelOf({ result: 'no_evidence' }), 'not_assessed'); assert.equal(levelOf({ result: 'something-new' }), 'not_assessed'); assert.equal(levelOf({}), 'not_assessed');
});

test('crosswalk: ECC hub lines, disagreement named, unmapped listed, a framework that fails is shown as not available', async () => {
  const { X } = fake({ isoFails: true });
  let c = await X.crosswalk(OP);
  assert.equal(c.frameworks.iso.available, false); assert.match(c.frameworks.iso.reason, /could not be read/); assert.equal(c.frameworks.iso.pct_fully, null, 'not available is never a percentage');
  const f = fake(); c = await f.X.crosswalk(OP);
  const strat = c.lines.find((l) => l.ecc_id === 'ZS-1-1-01'), mal = c.lines.find((l) => l.ecc_id === 'ZS-2-3-01');
  assert.deepEqual(strat.frameworks.sort(), ['ecc', 'iso', 'sama']); assert.equal(strat.state, 'gap');
  assert.equal(mal.state, 'disagree'); assert.ok(mal.disagree.met.some((x) => /ZS-2-3-01/.test(x)) && mal.disagree.gap.some((x) => /SA-3.3.6-01/.test(x)), 'which items disagree');
  assert.equal(c.stats.disagree, 1);
  assert.ok(c.unmapped.some((u) => u.id === 'ZS-DG-01') && c.unmapped.some((u) => u.id === 'SA-3.4.1-01'));
  assert.equal(c.frameworks.pdpl.assessed, false, 'PDPL without an approved self-assessment says so');
});

test('gap analysis: one work item for one piece of work across frameworks, priority itemised, not assessed apart, plan, GRC, export', async () => {
  const f = fake(), g = await f.X.gaps(OP);
  const w = g.items.find((i) => i.key === 'ECC:ZS-1-1-01');
  assert.deepEqual(w.refs.map((r) => r.fw).sort(), ['ecc', 'iso', 'sama'], 'ECC + SAMA + ISO gaps are one work item');
  assert.ok(w.why.some((p) => /closes the gap in 3 frameworks/.test(p.what)) && w.why.some((p) => /75 % chance/.test(p.what)), 'leverage and the SAMA engine\'s chance itemised');
  assert.equal(g.items[0].key, 'ECC:ZS-1-1-01', 'the cross-framework item ranks first');
  assert.ok(g.not_assessed.some((n) => n.id === 'ZS-2-12-01') && g.not_assessed.some((n) => n.id === 'SA-3.4.1-01'), 'not assessed is listed apart');
  assert.ok(!g.items.some((i) => i.refs.some((r) => r.id === 'ZS-2-12-01')), 'not assessed is not a gap');
  await assert.rejects(f.X.planItem('ECC:ZS-1-1-01', { owner: 'nora.syn' }, BOT), /service or AI identity/);
  await assert.rejects(f.X.planItem('ECC:ZS-1-1-01', { due: '2026-10-01' }, OP), /past/);
  await assert.rejects(f.X.planItem('ECC:ZS-9-9-99', { owner: 'x' }, OP), /not an open gap/);
  await assert.rejects(f.X.planItem('ECC:ZS-1-1-01', {}, OP), /owner, due or note/);
  await f.X.planItem('ECC:ZS-1-1-01', { owner: 'khalid.syn', due: '2026-12-15', note: 'board paper in December' }, OP);
  const g2 = await f.X.gaps(OP), w2 = g2.items.find((i) => i.key === 'ECC:ZS-1-1-01'); assert.equal(w2.owner, 'khalid.syn'); assert.equal(g2.kpis.unowned, g.kpis.unowned - 1);
  assert.ok(f.audits.some((a) => a.action === 'crosswalk.gap.plan' && a.by === 'nora.syn'));
  const r = await f.X.toGrc(OP); assert.deepEqual(f.grc.sort(), ['ecc', 'iso']); assert.match(r.ndmo.error, /busy/); assert.ok(r.pdpl === undefined);
  assert.ok(f.audits.some((a) => a.action === 'crosswalk.gaps_to_grc' && a.detail.ndmo === 'error'));
  const x = await f.X.exportRows(OP); assert.ok(x.rows.some((rw) => rw[4] === 'SA-3.1.2-01') && x.rows.some((rw) => rw[6] === 'not assessed'));
});

test('learning: mapping suggestions are proposals; an administrator maps (validated, audited, removable); forecast needs 3 snapshots', async () => {
  const f = fake();
  const sg = await f.X.suggest(); const nd = sg.items.find((x) => x.item_id === 'ZS-DG-01');
  assert.ok(nd && nd.ecc_id === 'ZS-2-12-01' && nd.similarity >= 0.25, 'NDMO log monitoring suggested onto ECC event logs');
  await assert.rejects(f.X.setMapping({ fw: 'ndmo', item_id: 'ZS-DG-01', ecc_id: 'ZS-9-9-99' }, ADM), /not an NCA ECC control/);
  await assert.rejects(f.X.setMapping({ fw: 'ecc', item_id: 'ZS-1-1-01', ecc_id: 'ZS-1-1-01' }, ADM), /fw must be one of/);
  await assert.rejects(f.X.setMapping({ fw: 'ndmo', item_id: 'ZS-DG-01', ecc_id: 'ZS-2-12-01' }, BOT), /service or AI identity/);
  await f.X.setMapping({ fw: 'ndmo', item_id: 'ZS-DG-01', ecc_id: 'ZS-2-12-01' }, ADM);
  let c = await f.X.crosswalk(ADM); assert.ok(c.lines.find((l) => l.ecc_id === 'ZS-2-12-01').items.some((i) => i.id === 'ZS-DG-01' && i.mapped_by === 'syed'));
  assert.ok(!c.unmapped.some((u) => u.id === 'ZS-DG-01'));
  await f.X.setMapping({ fw: 'ndmo', item_id: 'ZS-DG-01', remove: true }, ADM); c = await f.X.crosswalk(ADM); assert.ok(c.unmapped.some((u) => u.id === 'ZS-DG-01'));
  assert.ok(f.audits.some((a) => a.action === 'crosswalk.mapping.set') && f.audits.some((a) => a.action === 'crosswalk.mapping.remove'));
  // forecast: ECC improves 10 points a day over three snapshots
  let g = await f.X.gaps(OP); assert.match(g.forecast.ecc.why, /needs 3 daily snapshots/);
  const snap = f.X.collect;   // the snapshots read the same engines; move the ECC result between days
  let pct = [0, 33, 67]; for (let d = 0; d < 3; d++) { const p = pct[d]; f.addons.ncaEcc.view = async () => ({ controls: [{ id: 'ZS-1-1-01', title: 't', severity: 'high', result: p >= 33 ? 'verified' : 'gap' }, { id: 'ZS-2-3-01', title: 't', severity: 'high', result: p >= 67 ? 'verified' : 'gap' }, { id: 'ZS-2-12-01', title: 't', severity: 'medium', result: 'gap' }] }); await f.X.snapshot(); f.tick(DAY); }
  assert.equal(typeof snap, 'function');
  g = await f.X.gaps(OP); assert.ok(g.forecast.ecc.date && /points a week over 3 snapshots/.test(g.forecast.ecc.why), 'a date at the current pace: ' + JSON.stringify(g.forecast.ecc));
  assert.equal(g.trend.length, 3);
});

test('routes: real ECC / SAMA / ISO / NDMO engines, roles, validation, audit', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  const c = (await call('GET', '/crosswalk', undefined, VIEW)).json;
  for (const k of ['ecc', 'sama', 'iso', 'ndmo']) assert.equal(c.frameworks[k].available, true, k + ' available');
  assert.ok(c.lines.length >= 40 && c.stats.sama_on_ecc > 0 && c.stats.iso_on_ecc > 0, 'SAMA and ISO items sit on ECC controls');
  const g = (await call('GET', '/gap-analysis', undefined, VIEW)).json; assert.ok(g.items.length > 0 && g.items.some((i) => i.frameworks.length > 1), 'cross-framework work items');
  assert.equal((await call('GET', '/crosswalk/suggest', undefined, VIEW)).status, 403);
  assert.equal((await call('POST', '/crosswalk/mappings', { fw: 'ndmo', item_id: 'ZS-DG-01', ecc_id: 'ZS-1-1-01' }, OP)).status, 403);
  let r = await call('POST', '/crosswalk/mappings', { fw: 'nist', item_id: 'x', ecc_id: 'ZS-1-1-01' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /fw must be one of/);
  assert.equal((await call('POST', '/gap-analysis/items/' + encodeURIComponent(g.items[0].key), { owner: 'x' }, VIEW)).status, 403);
  assert.equal((await call('POST', '/gap-analysis/items/' + encodeURIComponent(g.items[0].key), { owner: 'khalid.syn' }, OP)).status, 200);
  assert.equal((await call('POST', '/gap-analysis/settings', { target_pct: 5 }, ADM)).status, 400);
  assert.equal((await call('POST', '/gap-analysis/settings', { target_pct: 85 }, OP)).status, 403);
  assert.equal((await call('GET', '/gap-analysis/export', undefined, VIEW)).status, 403);
  assert.ok((await call('GET', '/gap-analysis/export', undefined, OP)).json.rows.length > 0);
  assert.equal((await call('POST', '/crosswalk/ask', { question: 'what first?' }, OP)).status, 424, 'AI off until allowed');
  const au = e.app.store.auditTail(500).map((x) => x.action); assert.ok(au.includes('crosswalk.gap.plan') && au.includes('crosswalk.export'));
});
