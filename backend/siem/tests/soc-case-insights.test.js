// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Investigations & Cases insights (engine/soc/case-insights.js via investigate.js, GET {P}/soc/cases/insights and the workspace's
// ml part): time-to-close forecast and SLA breach risk from 5+ comparable closed cases (withheld below), a stalled case against the
// usual gap between timeline entries, the stage bottleneck from status changes, similar past cases with their resolution and note,
// duplicate candidates among open cases, a suggested owner (never a service identity), the analyst role (viewer refused).
// SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const routes = require('../engine/soc/investigate-routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600e3, DAY = 24 * H;
function world() {
  let T = Date.parse('2026-11-18T09:00:00Z');
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), now = () => T;
  const alerts = createAlerts({ state, log: quietLog, now }), cases = createCases({ state, alerts, log: quietLog, now });
  const api = fakeApi({ realRanks: true }); routes.register(api, { state, alerts, cases, config: {}, log: quietLog, now, noTimers: true });
  let k = 0;
  const alert = (o) => alerts.raise(Object.assign({ rule_id: 'R-PHISH', rule_name: 'Synthetic phishing', severity: 3, group: {}, fields: {}, summary: 'synthetic', ts_first: T - H, ts_last: T - H, source: 'engine', count: 1, group_key: 'g' + (++k) }, o)).alert;
  // a past case, created "ago" hours before now and closed after "took" hours, with timeline entries every "gap" hours
  const past = (o, ago, took, gap, owner, resolution, note) => {
    const save = T; T = save - ago * H; const a = alert(o); const c = cases.create({ title: 'Past ' + (o.title || 'case'), alert_ids: [a.id], auto_playbook: false, owner }, owner || 'syn.lead');
    for (let h = gap; h < took; h += gap) { T = save - ago * H + h * H; cases.note(c.id, 'progress', owner || 'syn.lead'); }
    T = save - ago * H + took * H; cases.setStatus(c.id, 'investigating', owner || 'syn.lead'); cases.setStatus(c.id, 'closed', owner || 'syn.lead', { resolution: resolution || 'true-positive', note: note || 'mailbox rule removed' }); T = save; return c;
  };
  return { api, alerts, cases, alert, past, at: (x) => { T = x; }, now, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('case insights: forecast and breach risk, stalled, stage bottleneck, similar, duplicates, suggested owner; viewer refused', async () => {
  const w = world(); try {
    let r = await w.api.call('GET', '/api/soc/soc/cases/insights', { role: 'analyst' });
    assert.equal(r.status, 200); assert.equal(r.body.open, 0);
    // six closed high cases about phishing on user syn.lina, 10-60 h to close, touched every 4 h, mostly by syn.huda
    for (let i = 0; i < 6; i++) w.past({ group: { user: 'syn.lina' }, mitre: ['T1566'] }, 200 + i * 24, 10 + i * 10, 4, i < 4 ? 'syn.huda' : 'ai:soc-analyst', 'true-positive', 'removed the forwarding rule ' + i);
    // an open case on the same user, 50 h old, nothing since it was opened
    const a1 = w.alert({ group: { user: 'syn.lina' }, mitre: ['T1566'] }), a2 = w.alert({ rule_id: 'R-FWD', rule_name: 'Synthetic forwarding rule', group: { user: 'syn.lina', host: 'pc-syn-3' } });
    w.at(w.now() - 50 * H); const c1 = w.cases.create({ title: 'Phishing on syn.lina', alert_ids: [a1.id], auto_playbook: false }, 'syn.lead'); w.at(w.now() + 50 * H);
    const c2 = w.cases.create({ title: 'Forwarding rule on syn.lina', alert_ids: [a2.id, w.alert({ group: { user: 'syn.lina', host: 'pc-syn-3' } }).id], auto_playbook: false }, 'syn.lead');
    w.cases.addAlerts(c1.id, [w.alert({ group: { host: 'pc-syn-3', user: 'syn.lina' } }).id], 'syn.lead');
    w.at(w.now() + 30 * H);
    r = await w.api.call('GET', '/api/soc/soc/cases/insights', { role: 'viewer' }); assert.equal(r.status, 403);
    r = await w.api.call('GET', '/api/soc/soc/cases/insights', { role: 'analyst' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    const f = r.body.forecasts[c1.id];
    assert.equal(f.judged, true); assert.equal(f.comparables, 6); assert.equal(f.median_h, 40); assert.match(f.why, /6 closed high cases took a median 40 h/);
    assert.equal(f.breach_risk, 100, 'resolve SLA (72 h for high) already passed at 80 h');
    assert.ok(r.body.at_risk.some((x) => x.id === c1.id));
    assert.ok(r.body.stalled.some((x) => x.id === c1.id && /no activity for 30 h; comparable cases are touched every 4 h/.test(x.stalled.why)), JSON.stringify(r.body.stalled));
    const d = r.body.duplicates[0]; assert.ok(d && [d.a, d.b].sort().join() === [c1.id, c2.id].sort().join() && d.shared.includes('user:syn.lina') && d.shared.includes('host:pc-syn-3'), 'duplicate candidates: ' + JSON.stringify(r.body.duplicates));
    const sg = r.body.suggestions.find((x) => x.id === c1.id); assert.equal(sg.owner.user, 'syn.huda'); assert.ok(!JSON.stringify(r.body.suggestions).includes('ai:soc-analyst'), 'an AI identity is never suggested');
    assert.ok(r.body.stages.rows.some((x) => x.status === 'open') && r.body.stages.bottleneck, 'stage durations from status changes');
    // workspace: similar past cases with how they were closed
    r = await w.api.call('GET', '/api/soc/soc/cases/' + c1.id + '/workspace', { role: 'viewer' });
    const sim = r.body.ml.similar; assert.ok(sim.length >= 1 && sim[0].resolution === 'true-positive' && /removed the forwarding rule/.test(sim[0].note) && sim[0].shared.includes('user:syn.lina'));
    assert.equal(r.body.ml.forecast.judged, true); assert.equal(r.body.ml.suggested_owner.user, 'syn.huda');
    // fewer than 5 comparables: withheld
    const lowCase = w.cases.create({ title: 'Low', alert_ids: [w.alert({ severity: 1 }).id], auto_playbook: false }, 'syn.lead');
    r = await w.api.call('GET', '/api/soc/soc/cases/insights', { role: 'analyst' });
    assert.match(r.body.forecasts[lowCase.id].why, /needs 5 closed low cases/);
  } finally { w.cleanup(); }
});
