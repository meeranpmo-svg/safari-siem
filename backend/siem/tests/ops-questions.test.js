// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Questions to the teams (engine/ops/questions.js, questions-routes.js) over SYNTHETIC problems from fake DBA / server / Exchange /
// network sources: flagged by team (critical + high), one source failing does not hide the others; the infrastructure manager asks
// from a problem (the team must match, one open question per problem, a cleared problem is refused); the team is mailed; only the
// team answers (admin or its approver scope), never the asker or a service identity; follow-up re-opens, close by the asker; SLA due
// time and overdue; answer time learned per team and breach risk from 5 answers; "asked before" finds the earlier answer on the same
// asset; config admin-only with mail validation; validation errors name the field; every write audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/ops/questions-routes');
const { jaccard, words } = require('../engine/ops/questions');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600e3, T0 = Date.parse('2026-11-05T08:00:00Z');
function world() {
  let clock = T0; const dir = tmpDir(), state = createState({ dir, log: quietLog }), mails = [];
  let dbaOpen = [{ id: 'tbs|USERS@ODS', instance: 'ODS', level: 'critical', label: 'Tablespace USERS 96 %', metric: 'tbs', value: 96, unit: '%', threshold: 87, since: T0 - H }, { id: 'arch@ESS', instance: 'ESS', level: 'warning', label: 'Archive lag', metric: 'arch_lag', value: 4.7, unit: ' h', since: T0 - 4 * H }, { id: 'x@LOW', instance: 'LOW', level: 'info', label: 'minor' }];
  const deps = { state, log: quietLog, now: () => clock, config: {},
    dbaAlerts: { conditions: () => dbaOpen, notifySettings: () => ({ recipients: ['dba.syn@example.test'] }) },
    sysadminFindings: (role) => role === 'exchange' ? [{ server: 'EXCH01', server_name: 'EXCH01', scope: 'exchange', severity: 'critical', kind: 'queue', title: 'Mail queue 4,200 (synthetic)', evidence: ['queue 4200'] }] : [{ server: 'APP01', server_name: 'APP01', scope: 'windows', severity: 'high', kind: 'disk', title: 'C: 97 % full (synthetic)', evidence: ['C: 97 %'] }],
    netopsFindings: () => { throw new Error('poller offline (synthetic)'); },
    reports: { schedules: { mail: async (m) => { mails.push(m); } } } };
  const api = fakeApi({ realRanks: true }); routes.register(api, deps);
  return { api, deps, mails, state, clear: (id) => { dbaOpen = dbaOpen.filter((c) => c.id !== id); }, tick: (ms) => { clock += ms; }, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
const M = { role: 'operator', user: 'infra.mgr' }, DBA = { role: 'operator', user: 'dba.one' }, ADM = { role: 'admin', user: 'sec.admin' }, VW = { role: 'viewer', user: 'vera.syn' };
const setApprover = (w, user, scope) => w.state.collection('approvers').put({ id: 'map', scopes: { [scope]: [user] } });

test('flagged problems by team; asking from a problem; mail; team answers; follow-up; close; audit', async () => {
  const w = world(); try {
    let r = await w.api.call('GET', '/api/soc/ops/issues', VW); assert.equal(r.status, 200);
    const I = r.body; assert.equal(I.items.length, 4, 'critical + high from DBA, server, Exchange (info dropped)');
    assert.ok(I.missing.some((m) => m.team === 'network' && /poller offline/.test(m.why)), 'a failing source is named, the others still show');
    assert.equal(I.by_team.find((t) => t.team === 'dba').critical, 1);
    const tbs = I.items.find((x) => x.asset === 'ODS');
    // validation + roles
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'dba', question: 'Why is USERS at 96 % on ODS?', ref: tbs.ref } }, VW))).status, 403);
    r = await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'storage', question: 'Why is USERS at 96 %?' } }, M)); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /team/);
    r = await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'dba', question: 'short' } }, M)); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /question/);
    r = await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'network', question: 'Why is USERS at 96 % on ODS?', ref: tbs.ref } }, M)); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /belongs to Database/);
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'dba', question: 'Why is USERS at 96 % on ODS?', ref: tbs.ref } }, { role: 'operator', user: 'system:bot' }))).status, 403);
    r = await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'dba', question: 'Why is USERS at 96 % on ODS, and when will it be extended?', ref: tbs.ref, reply_to: 'infra.mgr@example.test', extra: 'x' } }, M));
    assert.equal(r.status, 200, JSON.stringify(r.body)); const q = r.body; assert.equal(q.issue.asset, 'ODS'); assert.equal(q.severity, 'critical'); assert.equal(q.due_at - q.asked_at, 4 * H); assert.equal(q.extra, undefined);
    await new Promise((res) => setImmediate(res)); assert.deepEqual(w.mails[0].to, ['dba.syn@example.test'], 'DBA mailed (DBA alert recipients when no team list)'); assert.match(w.mails[0].subject, /Q-/);
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'dba', question: 'Second question on the same problem?', ref: tbs.ref } }, M))).status, 409, 'one open question per problem');
    I.items = (await w.api.call('GET', '/api/soc/ops/issues', VW)).body.items; assert.equal(I.items.find((x) => x.ref === tbs.ref).question.id, q.id, 'the problem shows its question');
    // who answers
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/answer', Object.assign({ body: { text: 'we are on it' } }, DBA))).status, 403, 'not an approver for eng:dba');
    setApprover(w, 'dba.one', 'eng:dba');
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/answer', Object.assign({ body: { text: 'x' } }, DBA))).status, 400, 'text too short');
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/answer', Object.assign({ body: { text: 'I answer myself' } }, { role: 'admin', user: 'infra.mgr' }))).status, 403, 'the asker never answers');
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/ack', DBA)).status, 200);
    w.tick(2 * H);
    r = await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/answer', Object.assign({ body: { text: 'Batch load grew USERS; datafile added (+20 GB), now 71 % (synthetic).' } }, DBA)); assert.equal(r.status, 200); assert.equal(r.body.status, 'answered');
    await new Promise((res) => setImmediate(res)); assert.deepEqual(w.mails[1].to, ['infra.mgr@example.test'], 'the asker is told');
    // follow-up, close
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/follow-up', Object.assign({ body: { text: 'Will it happen again?' } }, DBA))).status, 403, 'only the asker follows up');
    r = await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/follow-up', Object.assign({ body: { text: 'Will it happen again next month?' } }, M)); assert.equal(r.body.status, 'reopened');
    await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/answer', Object.assign({ body: { text: 'Autoextend on, alert at 87 % (synthetic).' } }, DBA));
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/close', DBA)).status, 403);
    r = await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/close', Object.assign({ body: { note: 'thanks' } }, M)); assert.equal(r.body.status, 'closed'); assert.equal(r.body.thread.length, 6);
    const acts = w.api.audits.map((a) => a.action); for (const a of ['ops.question.ask', 'ops.question.ack', 'ops.question.answer', 'ops.question.follow_up', 'ops.question.close']) assert.ok(acts.includes(a), 'audited ' + a);
    // a cleared problem cannot be asked about
    w.clear('arch@ESS'); const arch = I.items.find((x) => x.asset === 'ESS');
    assert.equal((await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'dba', question: 'Why is archive lag so high?', ref: arch.ref } }, M))).status, 409);
  } finally { w.cleanup(); }
});

test('SLA overdue, learned answer time and breach risk, asked before; config admin-only', async () => {
  const w = world(); try {
    setApprover(w, 'dba.one', 'eng:dba');
    for (let i = 0; i < 6; i++) { const q = (await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'dba', question: 'ODS tablespace USERS full again #' + i + '?', severity: 'high' } }, M))).body;
      w.tick((2 + i * 3) * H); await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/answer', Object.assign({ body: { text: 'Added a datafile #' + i } }, DBA)); await w.api.call('POST', '/api/soc/ops/questions/' + q.id + '/close', M); }
    const tbs = (await w.api.call('GET', '/api/soc/ops/issues', VW)).body.items.find((x) => x.asset === 'ODS');
    const q = (await w.api.call('POST', '/api/soc/ops/questions', Object.assign({ body: { team: 'dba', question: 'ODS tablespace USERS full again - why?', ref: tbs.ref } }, M))).body;
    w.tick(5 * H);
    const v = (await w.api.call('GET', '/api/soc/ops/questions?team=dba', VW)).body, it = v.items.find((x) => x.id === q.id);
    assert.equal(it.overdue, true, 'critical: 4 h due'); assert.equal(v.kpis.overdue, 1);
    assert.equal(v.teams.find((t) => t.id === 'dba').answered, 6); assert.ok(v.teams.find((t) => t.id === 'dba').median_h > 0);
    assert.ok(it.risk.p != null && /past Database \(DBA\) answers/.test(it.risk.why), JSON.stringify(it.risk));
    assert.ok(it.asked_before && /Added a datafile/.test(it.asked_before.answer), 'asked before: the earlier answer');
    assert.ok(jaccard(words('tablespace USERS full'), words('USERS tablespace full again')) > 0.5);
    assert.equal((await w.api.call('GET', '/api/soc/ops/questions?team=storage', VW)).status, 400);
    // config
    assert.equal((await w.api.call('PUT', '/api/soc/ops/questions/config', Object.assign({ body: { teams: { dba: { emails: ['a@b.test'] } } } }, M))).status, 403);
    let r = await w.api.call('PUT', '/api/soc/ops/questions/config', Object.assign({ body: { teams: { dba: { emails: ['not-a-mail'] } } } }, ADM)); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /teams\.dba\.emails/);
    r = await w.api.call('PUT', '/api/soc/ops/questions/config', Object.assign({ body: { baseVersion: 0, sla_h: { critical: 2 }, teams: { network: { emails: ['NOC.syn@example.test'] } } } }, ADM)); assert.equal(r.status, 200);
    assert.equal((await w.api.call('PUT', '/api/soc/ops/questions/config', Object.assign({ body: { baseVersion: 0 } }, ADM))).status, 409);
    const c = (await w.api.call('GET', '/api/soc/ops/questions', VW)).body.config; assert.equal(c.sla_h.critical, 2); assert.deepEqual(c.teams.network.emails, ['noc.syn@example.test']);
    assert.ok(w.api.audits.some((a) => a.action === 'ops.question.config'));
  } finally { w.cleanup(); }
});
