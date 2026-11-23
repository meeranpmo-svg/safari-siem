// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// UEBA (engine/ueba): baselines from history, detectors on a new window, risk scoring, analyst review (benign tunes the
// entity + detector, confirm raises the weight), and the API routes (engine/ueba/api.js) with their roles and audit records.
// Before this file UEBA was only touched by sql-alias.test.js. SYNTHETIC events only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createUeba } = require('../engine/ueba/index');
const uebaRoutes = require('../engine/ueba/api');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const DAY = 864e5, H = 36e5;
function world() {
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const ueba = createUeba({ state, ch: null, alerts: null, config: {}, settings: {}, log: quietLog });
  const t = Date.now(), hist = [];
  // 20 days of ordinary working-hours logons by alice on her own PC
  for (let d = 20; d >= 1; d--) for (let i = 0; i < 20; i++) hist.push({ ts: t - d * DAY + (10 + (i % 6)) * H, user: 'alice', host: 'pc-1', src_ip: '10.0.0.5', category: 'authentication', action: 'logon', outcome: 'success', src_type: 'windows', fields: { logon_type: '2' } });
  ueba.rebuildFromEvents(hist, t - H);
  // the new window: a burst of failures across many servers from another subnet, then a success, then a group change
  const win = [];
  for (let i = 0; i < 30; i++) win.push({ ts: t - 600e3 + i * 1000, user: 'alice', host: 'srv-' + i, src_ip: '10.9.9.9', category: 'authentication', action: 'logon', outcome: i < 25 ? 'failure' : 'success', src_type: 'windows', fields: { logon_type: '3' } });
  win.push({ ts: t - 300e3, user: 'alice', host: 'dc-1', src_ip: '10.9.9.9', category: 'iam', action: 'group-member-added', outcome: 'success', src_type: 'windows', fields: {} });
  ueba.detectFromEvents(win, t);
  const api = fakeApi({ realRanks: true }); uebaRoutes.register(api, { ueba, state, log: quietLog });
  return { ueba, api, cleanup: () => { try { ueba.stop(); } catch (e) { /* timers may not exist without ClickHouse */ } fs.rmSync(dir, { recursive: true, force: true }); } };
}

test('detectors raise explained findings against the learned baseline, and the entity is scored with its contributions', () => {
  const w = world(); try {
    const F = w.ueba.findings({ entity_id: 'user:alice', limit: 100 }).items, det = new Set(F.map((f) => f.detector));
    for (const d of ['brute_force_then_success', 'lateral_movement', 'privilege_escalation', 'first_seen_subnet']) assert.ok(det.has(d), d + ' raised');
    assert.ok(F.every((f) => f.explanation && f.status === 'open'), 'every finding is explained');
    const e = w.ueba.entity('user:alice');
    assert.equal(e.entity.state, 'established', '20 days of history = established baseline');
    assert.equal(e.risk.tier, 'critical'); assert.ok(e.risk.contributions.length > 0, 'the score is itemised');
    assert.ok(e.features.some((x) => x.feature === 'hosts' && x.observed.new.length > 0), 'new hosts compared with the baseline');
  } finally { w.cleanup(); }
});

test('review: benign tunes that entity + detector and lowers the score; confirm keeps it; roles and audit', async () => {
  const w = world(); try {
    const before = w.ueba.entity('user:alice').risk.score;
    const priv = w.ueba.findings({ entity_id: 'user:alice', detector: 'privilege_escalation' }).items[0];
    let r = await w.api.call('POST', '/api/soc/ueba/findings/' + priv.id + '/benign', { role: 'viewer', body: {} }); assert.equal(r.status, 403, 'a viewer cannot review');
    r = await w.api.call('POST', '/api/soc/ueba/findings/' + priv.id + '/benign', { role: 'operator', user: 'nora.syn', body: { note: 'planned change CHG-1 (synthetic)' } }); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.finding.status, 'benign'); assert.equal(r.body.tuning.detector, 'privilege_escalation');
    assert.ok(w.ueba.entity('user:alice').risk.score <= before, 'benign does not raise the score');
    const bf = w.ueba.findings({ entity_id: 'user:alice', detector: 'brute_force_then_success' }).items[0];
    r = await w.api.call('POST', '/api/soc/ueba/findings/' + bf.id + '/confirm', { role: 'operator', user: 'nora.syn', body: {} }); assert.equal(r.body.finding.status, 'confirmed');
    assert.equal((await w.api.call('POST', '/api/soc/ueba/findings/nope/confirm', { role: 'operator', body: {} })).status, 404);
    assert.ok(w.api.audits.some((a) => a.action === 'ueba.finding.benign' && a.user === 'nora.syn') && w.api.audits.some((a) => a.action === 'ueba.finding.confirm'));
    assert.equal((await w.api.call('GET', '/api/soc/ueba/settings', { role: 'operator' })).status, 403, 'settings are admin-only');
    assert.equal((await w.api.call('GET', '/api/soc/ueba/summary', { role: 'viewer' })).status, 200);
  } finally { w.cleanup(); }
});

