// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// XDR machine learning (engine/xdr/xdr-ml.js, xdr.js intel(), GET {P}/xdr/intel): the tactic chain learned from past incidents in
// firing order and the next tactic for an open incident (with the observed transitions), the kill-chain prior with too little
// history (said as a prior), similar closed incidents with how their alerts were closed, the daily trend withheld below 14 days,
// entities on the incident timeline for the attack graph, the analyst role (viewer refused). SYNTHETIC alerts only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const XML = require('../engine/xdr/xdr-ml');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const xdrRoutes = require('../engine/xdr/routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600e3, DAY = 24 * H, NOW = Date.now();
const name = (k) => k;

test('chain: next tactic learned from 3+ transitions, a kill-chain prior otherwise', () => {
  const c = XML.learnChain([['initial-access', 'execution', 'credential-access'], ['initial-access', 'execution', 'credential-access'], ['initial-access', 'execution', 'credential-access'], ['initial-access', 'execution', 'discovery']]);
  assert.equal(c.total, 8);
  const p = XML.predictNext(c, 'execution', name);
  assert.equal(p.learned, true); assert.equal(p.transitions, 4); assert.equal(p.next[0].tactic, 'credential-access'); assert.equal(p.next[0].observed, 3);
  assert.ok(p.next[0].p > p.next[1].p); assert.match(p.why, /credential-access \(3\), discovery \(1\) - 4 observed transition/);
  assert.deepEqual(p.next.map((x) => x.tactic), ['credential-access', 'discovery'], 'only observed next tactics');
  assert.deepEqual(XML.predictNext(c, 'execution', name, ['initial-access', 'execution', 'discovery']).next.map((x) => x.tactic), ['credential-access'], 'not one already on the path');
  const q = XML.predictNext(c, 'persistence', name);
  assert.equal(q.learned, false); assert.deepEqual(q.next.map((x) => x.tactic), ['privilege-escalation', 'defense-evasion']); assert.match(q.why, /a prior, not learned here/);
});

test('similar past incidents and the trend', () => {
  const past = [{ id: 'P1', title: 'p1', rules: ['R1', 'R2'], domains: { identity: 1, email: 1 }, tactics: ['initial-access'], first: NOW - 9 * DAY }, { id: 'P2', title: 'p2', rules: ['R9'], domains: { network: 1 }, tactics: ['impact'] }];
  const s = XML.similarPast({ id: 'O', rules: ['R1', 'R2'], domains: { identity: 1, email: 1 }, tactics: ['initial-access', 'execution'] }, past, () => ({ verdict: 'false-positive' }));
  assert.deepEqual(s.map((x) => x.id), ['P1']); assert.equal(s[0].verdict, 'false-positive'); assert.equal(s[0].similarity, 83);
  assert.match(XML.trend([{ first: NOW, domain_count: 2 }], NOW).why, /from 14 days/);
  const many = []; for (let d = 1; d <= 20; d++) many.push({ first: NOW - d * DAY, domain_count: 1 }); for (let i = 0; i < 6; i++) many.push({ first: NOW - 60000, domain_count: 2 });
  const t = XML.trend(many, NOW); assert.equal(t.judged, true); assert.equal(t.unusual, true); assert.equal(t.series.at(-1).cross_domain, 6);
});

test('route: GET /xdr/intel learns from the alerts, predicts the open incident\'s next tactic, finds a similar closed one; viewer refused', async () => {
  const dir = tmpDir('sentra-xdrml-'), state = createState({ dir, log: quietLog }), alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  const api = fakeApi({ realRanks: true }); xdrRoutes.register(api, { state, alerts, cases, config: {}, log: quietLog });
  let k = 0;
  const raise = (o) => alerts.raise(Object.assign({ severity: 3, group: {}, fields: {}, group_key: 'g' + (++k), count: 1, sample_event_ids: [], summary: 'synthetic' }, o)).alert;
  try {
    // four past incidents, each a different user: phishing -> encoded PowerShell -> credential dumping, closed
    for (let i = 0; i < 4; i++) {
      const t = NOW - (10 + i * 5) * DAY, u = { user: 'syn.u' + i };
      const a = [raise({ rule_id: 'SENTRA-MAIL-001', rule_name: 'Phishing link clicked', mitre: ['T1566'], group: u, ts_first: t, ts_last: t }),
        raise({ rule_id: 'SENTRA-EXEC-002', rule_name: 'Encoded PowerShell', mitre: ['T1059'], group: u, ts_first: t + H, ts_last: t + H }),
        raise({ rule_id: 'SENTRA-CRED-001', rule_name: 'LSASS access', mitre: ['T1003'], group: u, ts_first: t + 2 * H, ts_last: t + 2 * H })];
      for (const x of a) alerts.setStatus(x.id, i < 3 ? 'closed-true-positive' : 'closed-false-positive', 'syn.ana', 'synthetic');
    }
    // open now: phishing then PowerShell for syn.lina
    raise({ rule_id: 'SENTRA-MAIL-001', rule_name: 'Phishing link clicked', mitre: ['T1566'], group: { user: 'syn.lina' }, host: 'pc-syn-7', ts_first: NOW - 3 * H, ts_last: NOW - 3 * H });
    raise({ rule_id: 'SENTRA-EXEC-002', rule_name: 'Encoded PowerShell', mitre: ['T1059'], group: { user: 'syn.lina' }, host: 'pc-syn-7', ts_first: NOW - 2 * H, ts_last: NOW - 2 * H });
    let r = await api.call('GET', '/api/soc/xdr/intel', { role: 'viewer' }); assert.equal(r.status, 403);
    r = await api.call('GET', '/api/soc/xdr/intel', { role: 'analyst' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.history.closed, 4); assert.ok(r.body.history.transitions >= 8);
    const ids = Object.keys(r.body.incidents); assert.equal(ids.length, 1);
    const x = r.body.incidents[ids[0]];
    assert.equal(x.next.learned, true); assert.match(x.next.next[0].name, /Credential Access/i, JSON.stringify(x.next));
    assert.equal(x.similar[0].verdict, 'true-positive'); assert.ok(x.similar[0].similarity >= 35);
    assert.ok(r.body.transitions.length >= 2);
    // the incident's timeline carries the entities for the attack graph
    r = await api.call('GET', '/api/soc/xdr/incidents/' + ids[0], { role: 'viewer' });
    assert.ok(r.body.timeline.every((a) => Array.isArray(a.entities)) && r.body.timeline[0].entities.includes('user:syn.lina'));
  } finally { alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
