// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Workflow Automation (engine/workflow-auto.js) with SYNTHETIC people and records: an auditor's evidence request to the DBA team is
// worked, the evidence pack is collected from the platform's own records (allow-listed fields only - never a password), fulfilled and
// accepted by the requesting side; HR's leaver request needs a lead's approval (never the requester's, never an AI identity); roles
// (viewer / operator outside the team / admin), membership, validation (undeclared fields dropped), the ML (turnaround, breach risk,
// route suggestion, duplicates, recurring demand -> schedule, assignment), schedules raised by the background job with their
// evidence, escalation of overdue requests into Notification & Escalation's signals, settings (admin, version), the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'admin2.syn', role: 'admin' }, AUD = { user: 'aud.syn', role: 'viewer' }, HR = { user: 'hr.syn', role: 'viewer' };
const DBA = { user: 'dba.syn', role: 'operator' }, DBA2 = { user: 'dba2.syn', role: 'operator' }, IDL = { user: 'idlead.syn', role: 'operator' }, OUT = { user: 'net.syn', role: 'operator' }, BOT = { user: 'ai:desk', role: 'admin' };
const H = 3600000;

async function setup(t) {
  let T = Date.parse('2026-11-13T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  const st = await call('POST', '/workflow/settings', { version: 0, functions: { audit: ['aud.syn'], hr: ['hr.syn'] }, teams: { dba: ['dba.syn', 'dba2.syn'], identity: ['idm.syn'], network: ['net.syn'] }, leads: { identity: ['idlead.syn'], dba: ['dba.syn'] } });
  assert.equal(st.status, 200, st.text);
  e.app.store.collection('db_inventory').put({ id: 'db1', name: 'CLAIMS-SYN', host: 'dbsrv01.synthetic.test', version: '19c', password: 'Synthetic-DB-Secret-1', status: 'up', updated_at: '2026-11-12T10:00:00Z' });
  e.app.store.collection('db_inventory').put({ id: 'db2', name: 'POLICY-SYN', host: 'dbsrv02.synthetic.test', connection_string: 'user/pass@x', status: 'up' });
  return { e, call, clock: (ms) => { T += ms; }, now: () => T, audits: (a) => e.app.store.auditTail(500).filter((x) => x.action === 'workflow.' + a) };
}
const REQ = { type: 'db-user-review', from: 'audit', title: 'Q4 database accounts review', details: 'All accounts with DBA or SYSDBA on the claims and policy databases.' };

test('evidence request: auditor -> DBA team, evidence from the platform (no secrets), fulfilled, accepted by the requester; audited', async (t) => {
  const s = await setup(t);
  const c = await s.call('POST', '/workflow/requests', Object.assign({ status: 'closed', requester: 'someone' }, REQ), AUD);
  assert.equal(c.status, 200, c.text); const r = c.json;
  assert.match(r.id, /^REQ-2026-\d{4}$/); assert.equal(r.status, 'open', 'undeclared status dropped'); assert.equal(r.requester, 'aud.syn'); assert.equal(r.team, 'dba'); assert.equal(r.from_verified, true);
  assert.equal(r.due, '2026-11-16T08:00:00.000Z', 'SLA 72 h at normal priority');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/start', {}, AUD)).status, 403, 'a viewer does not work requests');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/start', {}, OUT)).status, 403, 'an operator outside the team does not either');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/start', {}, DBA)).json.status, 'in_progress');
  const f0 = await s.call('POST', '/workflow/requests/' + r.id + '/fulfil', { response: 'done' }, DBA); assert.equal(f0.status, 409); assert.match(f0.json.error, /evidence/);
  const ev = await s.call('POST', '/workflow/requests/' + r.id + '/evidence', { kind: 'auto' }, DBA); assert.equal(ev.status, 200, ev.text);
  const pack = ev.json.evidence[0].pack, part = pack.parts.find((p) => p.collection === 'db_inventory');
  assert.equal(part.records, 2); assert.equal(part.latest, '2026-11-12T10:00:00.000Z'); assert.match(pack.sha256, /^[0-9a-f]{64}$/);
  assert.equal(part.sample[0].name, 'CLAIMS-SYN');
  assert.ok(!JSON.stringify(pack).includes('Synthetic-DB-Secret-1') && !JSON.stringify(pack).includes('user/pass@x'), 'only allow-listed fields leave the collection');
  const empty = pack.parts.find((p) => p.collection === 'db_health_targets'); assert.equal(empty.records, 0); assert.match(empty.note, /not evidence of compliance/);
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/evidence', { kind: 'reference' }, DBA)).status, 400, 'a reference needs its text');
  await s.call('POST', '/workflow/requests/' + r.id + '/evidence', { kind: 'reference', text: 'Export from OEM, file DBA-Q4-SYN.xlsx' }, DBA);
  const f = await s.call('POST', '/workflow/requests/' + r.id + '/fulfil', { response: 'Accounts listed in the pack and the OEM export.' }, DBA);
  assert.equal(f.json.status, 'fulfilled'); assert.equal(f.json.fulfilled_by, 'dba.syn');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/accept', {}, DBA)).status, 403, 'the person who fulfilled it cannot accept it');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/return', {}, AUD)).status, 400, 'a return needs a reason');
  const ret = await s.call('POST', '/workflow/requests/' + r.id + '/return', { reason: 'The SYSDBA list for POLICY-SYN is missing' }, AUD); assert.equal(ret.json.status, 'returned');
  await s.call('POST', '/workflow/requests/' + r.id + '/fulfil', { response: 'Added POLICY-SYN.' }, DBA2);
  const acc = await s.call('POST', '/workflow/requests/' + r.id + '/accept', { note: 'ok' }, AUD); assert.equal(acc.json.status, 'closed'); assert.equal(acc.json.accepted_by, 'aud.syn');
  for (const a of ['create', 'start', 'evidence', 'fulfil', 'return', 'accept']) assert.ok(s.audits(a).length >= 1, 'audited: ' + a);
  assert.equal(s.audits('create')[0].by, 'aud.syn');
  const v = await s.call('GET', '/workflow', undefined, AUD); assert.equal(v.json.mine.length, 1); assert.deepEqual(v.json.all, [], 'only admins see everyone\'s requests');
  assert.equal((await s.call('GET', '/workflow/requests/' + r.id, undefined, { user: 'other.syn', role: 'viewer' })).status, 403, 'not a participant');
});

test('approval: HR leaver request waits for a lead who is not the requester; never an AI identity; rejection needs a reason', async (t) => {
  const s = await setup(t);
  const r = (await s.call('POST', '/workflow/requests', { type: 'leaver-disable', from: 'hr', title: 'Leaver: badr.syn', details: 'Last day today', priority: 'urgent' }, HR)).json;
  assert.equal(r.status, 'awaiting_approval'); assert.equal(r.sla_h, 1, 'urgent = a quarter of the 4 h SLA');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/start', {}, IDL)).status, 409, 'not before approval');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/approve', {}, DBA)).status, 403, 'a lead of another team cannot approve');
  const ai = await s.call('POST', '/workflow/requests/' + r.id + '/approve', {}, BOT); assert.equal(ai.status, 403); assert.match(ai.json.error, /person/);
  const ok = await s.call('POST', '/workflow/requests/' + r.id + '/approve', { note: 'confirmed with HR' }, IDL); assert.equal(ok.json.status, 'open'); assert.equal(ok.json.approval.by, 'idlead.syn');
  const own = (await s.call('POST', '/workflow/requests', { type: 'net-change', from: 'admin', title: 'Open 443 to the claims portal', details: 'new portal' }, ADM)).json;
  const self = await s.call('POST', '/workflow/requests/' + own.id + '/approve', {}, ADM); assert.equal(self.status, 403); assert.match(self.json.error, /four-eyes/);
  assert.equal((await s.call('POST', '/workflow/requests/' + own.id + '/reject', {}, ADM2)).status, 400);
  const rej = await s.call('POST', '/workflow/requests/' + own.id + '/reject', { reason: 'no change ticket' }, ADM2); assert.equal(rej.json.status, 'rejected');
  assert.equal(s.audits('approve').length, 1); assert.equal(s.audits('reject').length, 1);
});

test('membership and validation: a configured function refuses outsiders; an open function is declared, not verified; fields named', async (t) => {
  const s = await setup(t);
  const no = await s.call('POST', '/workflow/requests', REQ, { user: 'stranger.syn', role: 'viewer' }); assert.equal(no.status, 403); assert.match(no.json.error, /not a member/);
  const decl = await s.call('POST', '/workflow/requests', { type: 'vuln-remediation', from: 'ciso', title: 'Top criticals', details: 'status of criticals' }, { user: 'ciso.syn', role: 'viewer' });
  assert.equal(decl.status, 200); assert.equal(decl.json.from_verified, false);
  const bad = async (b, re) => { const x = await s.call('POST', '/workflow/requests', b, AUD); assert.equal(x.status, 400, JSON.stringify(b)); assert.match(x.json.error, re); };
  await bad(Object.assign({}, REQ, { type: 'nope' }), /type/);
  await bad(Object.assign({}, REQ, { from: 'hr' }), /from/);
  await bad({ type: 'other', from: 'audit', title: 'x', details: 'y' }, /team/);
  await bad(Object.assign({}, REQ, { title: '' }), /title/);
  await bad(Object.assign({}, REQ, { priority: 'asap' }), /priority/);
  await bad(Object.assign({}, REQ, { due: 'yesterday' }), /due/);
  const r = (await s.call('POST', '/workflow/requests', REQ, AUD)).json;
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/assign', { assignee: 'aud.syn' }, DBA)).status, 403, 'not a team member');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/assign', { assignee: 'dba2.syn' }, DBA)).json.assignee, 'dba2.syn');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/cancel', { reason: 'x' }, DBA)).status, 403, 'only the requester cancels');
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/comment', { text: 'Which databases?' }, DBA)).json.comments.length, 1);
  assert.equal((await s.call('POST', '/workflow/requests/' + r.id + '/cancel', { reason: 'raised twice' }, AUD)).json.status, 'cancelled');
});

test('ML: turnaround, breach risk, route suggestion, duplicates, recurring demand, assignment - from this platform\'s own history', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('POST', '/workflow/classify', { text: 'list of database accounts and their privileges' }, AUD)).json.type, 'db-user-review');
  assert.equal((await s.call('POST', '/workflow/classify', { text: '' }, AUD)).status, 400);
  for (let i = 0; i < 6; i++) {
    const r = (await s.call('POST', '/workflow/requests', Object.assign({}, REQ, { title: 'Review ' + i }), AUD)).json;
    await s.call('POST', '/workflow/requests/' + r.id + '/evidence', { kind: 'note', text: 'listed' }, DBA);
    s.clock((i < 1 ? 24 : 96) * H);
    await s.call('POST', '/workflow/requests/' + r.id + '/fulfil', { response: 'ok' }, DBA);
    await s.call('POST', '/workflow/requests/' + r.id + '/accept', {}, AUD);
    s.clock(5 * 24 * H);
  }
  const a = (await s.call('POST', '/workflow/requests', Object.assign({}, REQ, { title: 'claims database privileged accounts review', details: 'privileged accounts on claims database' }), AUD)).json;
  await s.call('POST', '/workflow/requests', Object.assign({}, REQ, { title: 'claims database privileged accounts review again', details: 'privileged accounts on claims database' }), AUD);
  s.clock(50 * H);
  const v = (await s.call('GET', '/workflow', undefined, ADM)).json;
  const ta = v.catalogue.find((c) => c.id === 'db-user-review').turnaround; assert.equal(ta.n, 6); assert.equal(ta.median_h, 96);
  const open = v.all.find((r) => r.id === a.id); assert.equal(open.breach_risk.p, 1, 'of the 5 still open at 50 h, all missed 72 h'); assert.match(open.breach_risk.why, /5 of 5/);
  assert.ok(v.ml.duplicates.some((d) => [d.a, d.b].includes(a.id)), 'the two near-identical open requests are flagged');
  const rec = v.ml.recurring.find((x) => x.type === 'db-user-review' && x.from === 'audit'); assert.ok(rec && rec.count >= 3, 'recurring demand proposes a schedule');
  const team = v.ml.teams.find((x) => x.team === 'dba'); assert.equal(team.n, 6); assert.equal(team.on_time, 1); assert.equal(team.rate, 0.25);
  assert.equal(v.ml.assign.dba.user, 'dba2.syn', 'the less loaded member is suggested');
  assert.equal((await s.call('POST', '/workflow/requests/' + a.id + '/ai-draft', {}, DBA)).status, 409, 'no AI on this server: said so');
});

test('schedules: raised by the background job with the evidence pack, next date advanced; overdue requests escalated into the signals', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('POST', '/workflow/schedules', { type: 'leaver-disable', from: 'hr', title: 'x', details: 'y', every: 'monthly', next: '2026-11-13T08:00:00Z' }, ADM)).status, 400, 'access requests are not scheduled');
  assert.equal((await s.call('POST', '/workflow/schedules', { type: 'db-user-review', from: 'audit', title: 'x', details: 'y', every: 'monthly', next: '2026-11-13' }, AUD)).status, 403, 'viewer');
  const sc = await s.call('POST', '/workflow/schedules', { type: 'db-user-review', from: 'audit', title: 'Monthly DB accounts', details: 'every month', every: 'monthly', next: '2026-11-13T07:00:00Z' }, { user: 'aud.syn', role: 'operator' });
  assert.equal(sc.status, 200, sc.text);
  const did = s.e.app.addons.workflow.tick(); assert.equal(did.raised, 1);
  const raised = s.e.app.store.collection('wf_requests').all().find((r) => r.schedule === sc.json.id);
  assert.equal(raised.requester, 'aud.syn'); assert.equal(raised.evidence[0].kind, 'auto'); assert.equal(raised.evidence[0].pack.parts[0].records, 2);
  assert.equal(s.e.app.store.collection('wf_schedules').get(sc.json.id).next, '2026-12-13T07:00:00.000Z');
  assert.equal(s.e.app.addons.workflow.tick().raised, 0, 'not twice');
  s.clock(80 * H); assert.equal(s.e.app.addons.workflow.tick().escalated, 1);
  const sig = s.e.app.addons.workflow.signals(); assert.equal(sig.length, 1); assert.equal(sig[0].source, 'requests'); assert.match(sig[0].title, /overdue/);
  assert.equal(s.audits('escalate').length, 1);
  assert.equal((await s.call('POST', '/workflow/schedules/' + sc.json.id + '/delete', {}, DBA)).status, 403);
  assert.equal((await s.call('POST', '/workflow/schedules/' + sc.json.id + '/delete', {}, ADM)).status, 200);
});

test('settings: admin only, a person, version-checked, user names validated, audited', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('POST', '/workflow/settings', { version: 1 }, DBA)).status, 403);
  assert.equal((await s.call('GET', '/workflow/settings', undefined, DBA)).status, 403);
  assert.equal((await s.call('POST', '/workflow/settings', { version: 0 })).status, 409, 'stale version');
  assert.equal((await s.call('POST', '/workflow/settings', { version: 1, teams: { dba: ['bad name!'] } })).status, 400);
  assert.equal((await s.call('POST', '/workflow/settings', { version: 1, teams: { mainframe: ['x.syn'] } })).status, 400);
  assert.equal((await s.call('POST', '/workflow/settings', { version: 1, functions: ['x'] })).status, 400);
  assert.equal((await s.call('POST', '/workflow/settings', { version: 1, escalate: false }, BOT)).status, 403);
  const ok = await s.call('POST', '/workflow/settings', { version: 1, escalate: false }); assert.equal(ok.status, 200); assert.equal(ok.json.escalate, false); assert.deepEqual(ok.json.teams.dba, ['dba.syn', 'dba2.syn'], 'unchanged maps kept');
  assert.equal(s.audits('settings').length, 2);
});

test('GET /workflow/attention: what needs this person, any signed-in role, read only', async (t) => {
  const s = await setup(t);
  const r = (await s.call('POST', '/workflow/requests', REQ, AUD)).json;
  const a = await s.call('GET', '/workflow/attention', undefined, AUD); assert.equal(a.status, 200);
  assert.equal(a.json.summary.raised_open, 1); assert.deepEqual(a.json.summary.functions, ['audit']);
  const q = (await s.call('GET', '/workflow/attention', undefined, DBA)).json; assert.equal(q.summary.queue_open, 1);
  assert.equal(s.e.app.store.collection('wf_requests').get(r.id).status, 'open', 'reading changes nothing');
});

test('flow (rev 2): stage medians and the bottleneck, rework, demand forecast against throughput, expected wait, automation candidates', async (t) => {
  const { e, call, now } = await setup(t);
  const R = e.app.store.collection('wf_requests'), T0 = now(), iso = (ms) => new Date(ms).toISOString();
  // 12 weeks of database-account reviews to the DBA team: approval in 2 h, started 30 h later (the bottleneck), worked in 4 h,
  // accepted in 1 h; demand rises; 2 were returned once
  let n = 0;
  for (let w = 11; w >= 0; w--) for (let k = 0; k < 2 + Math.floor((11 - w) / 3); k++) {
    const c = T0 - w * 7 * 24 * H - (k + 1) * 6 * H, ap = c + 2 * H, st = ap + 30 * H, fu = st + 4 * H, ac = fu + 1 * H, done = w >= 1;
    const hist = [{ at: iso(c), by: 'aud.syn', action: 'created' }, { at: iso(ap), by: 'idlead.syn', action: 'approved' }, { at: iso(st), by: 'dba.syn', action: 'started' }];
    if (done) hist.push({ at: iso(fu), by: 'dba.syn', action: 'fulfilled' }); if (done && n < 2) hist.push({ at: iso(fu + H / 2), by: 'aud.syn', action: 'returned' });
    if (done) hist.push({ at: iso(ac), by: 'aud.syn', action: 'accepted' });
    R.put({ id: 'WF-SYN-' + (++n), type: 'db-user-review', team: 'dba', from: 'audit', title: 'Synthetic review ' + n, details: 'synthetic', requester: 'aud.syn', priority: 'normal', status: done ? 'closed' : 'in_progress',
      created_at: iso(c), updated_at: iso(c), due: iso(c + 72 * H), fulfilled_at: done ? iso(fu) : null, fulfilled_by: done ? 'dba.syn' : null, closed_at: done ? iso(ac) : null, assignee: 'dba.syn', evidence: [], comments: [], history: hist });
  }
  const v = (await call('GET', '/workflow', undefined, AUD)).json, F = v.ml.flow;
  const dba = F.teams.find((x) => x.team === 'dba');
  assert.ok(dba, 'the DBA team has a flow');
  assert.equal(dba.stages.approval, 2); assert.equal(dba.stages.start, 30); assert.equal(dba.stages.work, 4); assert.equal(dba.stages.accept, 1);
  assert.equal(dba.bottleneck.stage, 'start', 'waiting to be started is where the time goes'); assert.match(dba.bottleneck.label, /waiting to be started/);
  assert.equal(dba.rework.returned, 2); assert.ok(dba.rework.rate > 0);
  assert.equal(dba.weekly.length, 12); assert.ok(dba.next_week > dba.weekly[0], 'rising demand forecast above the first week'); assert.ok(dba.throughput > 0);
  assert.ok(dba.open >= 2 && dba.wait_weeks > 0, 'expected wait from Little\'s law');
  assert.match(dba.why, /Holt/);
  const c = F.candidates.find((x) => x.type === 'db-user-review'); assert.ok(c, 'a steady, frequent type is an automation candidate'); assert.ok(c.steady >= 80); assert.ok(c.n90 > 10);
  assert.ok(!JSON.stringify(F).includes('aud.syn') && !JSON.stringify(F).includes('dba.syn'), 'the flow carries counts, not names');
  // a team with too little history says why
  R.put({ id: 'WF-SYN-NET', type: 'other', team: 'network', from: 'audit', title: 'x', details: 'x', requester: 'aud.syn', status: 'open', created_at: iso(T0 - H), due: iso(T0 + H), history: [] });
  const v2 = (await call('GET', '/workflow', undefined, AUD)).json, net = v2.ml.flow.teams.find((x) => x.team === 'network');
  assert.equal(net.next_week, null); assert.match(net.why, /needs 4 weeks/); assert.equal(net.bottleneck, null); assert.equal(net.rework, null);
});
