// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Notification & Escalation (engine/notify-center.js, pyengine/notify_rules.py): configuration validated and admin-only (addresses
// hidden from non-admins), routing by policy to the on-call person, the ladder escalates when nobody acknowledges, acknowledgement by a
// person stops it (never a service identity), SOC status kept in step, maintenance windows and after-hours hold stop paging only,
// platform conditions resolve themselves, delivery through the SIEM relay as system:itam-notify, ML noise -> proposal, four-eyes.
// The SIEM is stubbed; data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const MIN = 60000;
// Tuesday 2026-10-27 10:00 Riyadh (working hours)
const T0 = Date.parse('2026-10-27T07:00:00Z');
const TEAMS = { teams: [{ id: 'net', name: 'Network team', rota_start: '2026-10-25', rota_days: 7, members: [{ name: 'Ali Syn', email: 'ali.syn@corpgroup.test' }, { name: 'Omar Syn', email: 'omar.syn@corpgroup.test' }] },
  { id: 'mgr', name: 'IT managers', members: [{ name: 'Head Syn', email: 'head.syn@corpgroup.test' }] }] };
const POL = { id: 'soc-high', name: 'SOC high and critical', sources: ['soc'], min_severity: 3, team: 'net', steps: [{ after_min: 0, to: 'oncall' }, { after_min: 15, to: 'team' }, { after_min: 30, to: 'team:mgr' }] };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = T0; const alerts = [], sent = [];
  const siem = async (m, p, b, user) => {
    if (p.startsWith('/alerts')) return { ok: true, status: 200, data: { total: alerts.length, items: alerts.slice() } };
    if (p === '/reports/deliver') { sent.push({ b, user }); return { ok: true, status: 200, data: { ok: true } }; }
    return { ok: false, status: 0, error: 'no' };
  };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, ncSiem: siem });
  const N = e.app.addons.notifyCenter;
  return { e, N, alerts, sent, at: (t2) => { clock = t2; }, now: () => clock };
}
const post = (e, p, body, who = ADM) => e.req('POST', p, Object.assign({ body }, who));

test('configuration: admin only, every field validated, addresses hidden from non-admins, audited', async (t) => {
  const { e } = await setup(t);
  assert.equal((await post(e, '/notify/teams', TEAMS, OP)).status, 403);
  let r = await post(e, '/notify/teams', { teams: [{ id: 'net', name: 'N', members: [{ name: 'A', email: 'not-mail' }] }] });
  assert.equal(r.status, 400); assert.match(r.json.error, /teams\[0\]\.members\[0\]\.email/);
  r = await post(e, '/notify/teams', { teams: [{ id: 'Net X', name: 'N', members: [] }] }); assert.equal(r.status, 400); assert.match(r.json.error, /teams\[0\]\.id/);
  assert.equal((await post(e, '/notify/teams', TEAMS)).status, 200);
  r = await post(e, '/notify/policies', { policies: [Object.assign({}, POL, { steps: [{ after_min: 5, to: 'oncall' }] })] }); assert.equal(r.status, 400); assert.match(r.json.error, /steps\[0\]\.after_min must be 0/);
  r = await post(e, '/notify/policies', { policies: [Object.assign({}, POL, { team: 'ghost' })] }); assert.equal(r.status, 400); assert.match(r.json.error, /no team "ghost"/);
  r = await post(e, '/notify/policies', { policies: [Object.assign({}, POL, { steps: [{ after_min: 0, to: 'everyone' }] })] }); assert.equal(r.status, 400); assert.match(r.json.error, /must be oncall, team or team:<id>/);
  r = await post(e, '/notify/policies', { policies: [Object.assign({ evil: 1 }, POL)] }); assert.equal(r.status, 200); assert.equal(r.json.policies[0].evil, undefined);
  r = await post(e, '/notify/teams', { teams: [TEAMS.teams[1]] }); assert.equal(r.status, 400); assert.match(r.json.error, /routes to the team "net"/);
  const v = (await e.req('GET', '/notify', VW)).json;
  assert.equal(v.teams[0].members[0].email, undefined); assert.equal(v.teams[0].members[0].has_email, true);
  assert.equal(v.oncall.find((o) => o.team === 'net').now.name, 'Ali Syn', 'rota: first turn');
  assert.ok((await e.req('GET', '/notify', ADM)).json.teams[0].members[0].email);
  const au = e.app.store.auditTail(20).find((x) => x.action === 'notify.teams.save'); assert.deepEqual(au.detail, { teams: 2, members: 3 });
  assert.ok(!JSON.stringify(e.app.store.auditTail(20)).includes('ali.syn@'), 'addresses never in the audit');
});

test('escalation: on-call first, the team after 15 min, managers after 30; a person acknowledges and it stops', async (t) => {
  const { e, N, alerts, sent, at } = await setup(t);
  await post(e, '/notify/teams', TEAMS); await post(e, '/notify/policies', { policies: [POL] });
  alerts.push({ id: 'ALR-0000101', rule_id: 'r1', rule_name: 'Brute force against the VPN (synthetic)', severity: 3, status: 'new', summary: 'synthetic' });
  alerts.push({ id: 'ALR-0000102', rule_id: 'r2', rule_name: 'Low noise (synthetic)', severity: 2, status: 'new', summary: '' });
  await N.tick(null);
  let v = (await e.req('GET', '/notify', OP)).json, inc = v.incidents.find((i) => i.ref === 'ALR-0000101');
  assert.equal(inc.status, 'open'); assert.equal(inc.policy, 'soc-high');
  assert.equal(sent.length, 1); assert.equal(sent[0].user, 'system:itam-notify'); assert.deepEqual(sent[0].b.recipients, ['ali.syn@corpgroup.test']);
  assert.match(sent[0].b.subject, /^\[ALERT\]\[HIGH\] Brute force/);
  const un = v.incidents.find((i) => i.ref === 'ALR-0000102'); assert.equal(un.policy, null); assert.match(un.history[0].what, /no policy matches/);
  at(T0 + 10 * MIN); await N.tick(null); assert.equal(sent.length, 1, 'not yet');
  at(T0 + 16 * MIN); await N.tick(null); assert.equal(sent.length, 2); assert.deepEqual(sent[1].b.recipients.sort(), ['ali.syn@corpgroup.test', 'omar.syn@corpgroup.test'], 'step 2: the whole team');
  // a service identity cannot acknowledge; a person can, and the ladder stops
  let r = await post(e, '/notify/incidents/' + inc.id + '/ack', {}, { user: 'svc:bot', role: 'operator' }); assert.equal(r.status, 403);
  assert.equal((await post(e, '/notify/incidents/' + inc.id + '/ack', {}, VW)).status, 403);
  r = await post(e, '/notify/incidents/' + inc.id + '/ack', { note: 'on it' }, OP); assert.equal(r.status, 200); assert.equal(r.json.acked_by, 'nora.syn');
  at(T0 + 40 * MIN); await N.tick(null); assert.equal(sent.length, 2, 'no manager page after the acknowledgement');
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'notify.ack' && x.by === 'nora.syn' && x.detail.minutes === 16));
  r = await post(e, '/notify/incidents/' + inc.id + '/resolve', { resolution: 'guessed' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /resolution must be one of/);
  r = await post(e, '/notify/incidents/' + inc.id + '/resolve', { resolution: 'fixed' }, OP); assert.equal(r.status, 200); assert.equal(r.json.status, 'resolved');
  assert.equal((await post(e, '/notify/incidents/NC-NOPE-1/ack', {}, OP)).status, 404);
});

test('SOC in step, maintenance windows and after-hours hold stop paging only, platform conditions resolve themselves', async (t) => {
  const { e, N, alerts, sent, at } = await setup(t);
  await post(e, '/notify/teams', TEAMS);
  await post(e, '/notify/policies', { policies: [POL, { id: 'platform', name: 'Platform', sources: ['platform', 'dr', 'certs', 'reports'], min_severity: 2, team: 'net', after_hours: 'hold', steps: [{ after_min: 0, to: 'oncall' }] }] });
  const uh = e.app.addons.updateHealth, healthy = () => ({ pages: [{ name: 'Email Route Map', ok: true }] });
  uh.view = healthy;   // a healthy platform to start (in this test engine the AI CISO routes main.js adds on a server are missing)
  // SOC: acknowledged there = acknowledged here; closed there = resolved here
  alerts.push({ id: 'ALR-1', rule_name: 'Malware on a server (synthetic)', severity: 4, status: 'new' });
  await N.tick(null); assert.equal(sent.length, 1);
  alerts[0].status = 'acknowledged'; alerts[0].assignee = 'soc.analyst.syn';
  at(T0 + 20 * MIN); await N.tick(null);
  let inc = (await e.req('GET', '/notify', OP)).json.incidents.find((i) => i.ref === 'ALR-1');
  assert.equal(inc.status, 'acked'); assert.equal(inc.acked_by, 'SOC: soc.analyst.syn'); assert.equal(sent.length, 1, 'no escalation once the SOC has it');
  alerts[0].status = 'closed-true-positive'; await N.tick(null);
  inc = (await e.req('GET', '/notify', OP)).json.incidents.find((i) => i.ref === 'ALR-1'); assert.equal(inc.status, 'resolved'); assert.equal(inc.resolution, 'closed-in-soc');
  // maintenance: recorded, not paged; paging resumes after the window
  assert.equal((await post(e, '/notify/maintenance', { windows: [{ id: 'fw-upgrade', name: 'Firewall upgrade', from: new Date(T0).toISOString(), to: new Date(T0 + 60 * MIN).toISOString(), sources: ['soc'] }] })).status, 200);
  alerts.push({ id: 'ALR-2', rule_name: 'Firewall unreachable (synthetic)', severity: 3, status: 'new' });
  await N.tick(null);
  inc = (await e.req('GET', '/notify', OP)).json.incidents.find((i) => i.ref === 'ALR-2'); assert.match(inc.suppressed, /maintenance window "Firewall upgrade"/); assert.equal(sent.length, 1, 'held during maintenance');
  at(T0 + 61 * MIN); await N.tick(null); assert.equal(sent.length, 2, 'paged when the window ends');
  inc = (await e.req('GET', '/notify', OP)).json.incidents.find((i) => i.ref === 'ALR-2');
  assert.equal((await post(e, '/notify/incidents/' + inc.id + '/resolve', { resolution: 'fixed' }, OP)).status, 200);
  await N.tick(null); assert.equal((await e.req('GET', '/notify', OP)).json.incidents.filter((i) => i.ref === 'ALR-2').length, 1, 'resolved here, still new in the SOC: not opened again');
  alerts[1].ts_last = T0 + 62 * MIN; at(T0 + 63 * MIN); await N.tick(null);
  const again = (await e.req('GET', '/notify', OP)).json.incidents.filter((i) => i.ref === 'ALR-2'); assert.equal(again.length, 2, 'new activity after the resolution opens it again');
  assert.equal(sent.length, 3, 'and pages'); sent.pop();
  assert.equal((await post(e, '/notify/incidents/' + again.find((i) => i.status === 'open').id + '/resolve', { resolution: 'duplicate' }, OP)).status, 200);
  // a platform condition: a page not working; medium + after hours is held to the morning; cleared = resolved
  uh.view = () => ({ pages: [{ name: 'Email Route Map', ok: false, why: 'module missing (synthetic)' }] });
  const late = Date.parse('2026-10-27T17:30:00Z');   // 20:30 Riyadh
  at(late); await N.tick(null);
  inc = (await e.req('GET', '/notify', OP)).json.incidents.find((i) => i.source === 'platform');
  assert.equal(inc.title, 'Email Route Map is not working'); assert.equal(inc.status, 'open');
  assert.equal(sent.length, 3, 'severity 3 platform -> paged at once; the hold is for medium and low only: ' + sent.map((x) => x.b.subject).join(' / '));
  uh.view = healthy; await N.tick(null);
  inc = (await e.req('GET', '/notify', OP)).json.incidents.find((i) => i.source === 'platform'); assert.equal(inc.status, 'resolved'); assert.equal(inc.resolution, 'auto');
  // report delivery failed (medium) after hours -> held until 07:00 Riyadh
  e.app.addons.reportCenter.home = async () => ({ schedules: [{ id: 'rs-1', name: 'Weekly (synthetic)', enabled: true, last: { status: 'failed', error: 'relay down' } }] });
  await N.tick(null);
  inc = (await e.req('GET', '/notify', OP)).json.incidents.find((i) => i.source === 'reports');
  assert.ok(inc.held_until > late); assert.equal(new Date(inc.held_until + 3 * 3600000).getUTCHours(), 7); assert.equal(sent.length, 3, 'held');
  at(inc.held_until + MIN); await N.tick(null); assert.equal(sent.length, 4, 'sent in the morning');
});

test('ML: a noisy policy becomes a proposal; four-eyes - the proposer never approves, reject needs a reason, approve applies it', async (t) => {
  const { e, N, at } = await setup(t);
  await post(e, '/notify/teams', TEAMS); await post(e, '/notify/policies', { policies: [Object.assign({}, POL, { min_severity: 2 })] });
  const C = e.app.store.collection('nc_incidents');
  for (let i = 0; i < 25; i++) C.put({ id: 'NC-SYN-' + i, fp: 'soc:x' + i, source: 'soc', title: 'Port scan from 198.51.100.' + i, severity: 2, policy: 'soc-high', team: 'net', first: T0 - (i + 1) * 3600000, acked_at: T0 - (i + 1) * 3600000 + (5 + i) * MIN, resolved_at: T0 - (i + 1) * 3600000 + 9 * MIN, status: 'resolved', resolution: i < 20 ? 'false-positive' : 'fixed', notified: [{ at: T0 - (i + 1) * 3600000, to: ['Ali Syn'], after_hours: false }] });
  assert.equal((await e.req('GET', '/notify/insights', VW)).status, 403);
  const ins = (await e.req('GET', '/notify/insights', OP)).json;
  assert.ok(ins.ok, JSON.stringify(ins).slice(0, 200)); assert.equal(ins.teams.net.acked, 25); assert.ok(ins.teams.net.median_min > 0);
  assert.equal(ins.noise[0].noisy, true); assert.equal(ins.fatigue[0].person, 'Ali Syn');
  const pr = (await e.req('GET', '/notify', OP)).json.proposals[0];
  assert.equal(pr.by, 'ml:notify-noise'); assert.deepEqual(pr.change, { min_severity: 3 }); assert.equal(pr.status, 'pending');
  assert.equal((await post(e, '/notify/proposals/' + pr.id + '/decide', { decision: 'approve' }, OP)).status, 403);
  let r = await post(e, '/notify/proposals/' + pr.id + '/decide', { decision: 'reject' }); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await post(e, '/notify/proposals/' + pr.id + '/decide', { decision: 'approve' }, { user: 'ai:helper', role: 'admin' }); assert.equal(r.status, 403, 'an AI identity never decides');
  r = await post(e, '/notify/proposals/' + pr.id + '/decide', { decision: 'approve' }); assert.equal(r.status, 200); assert.equal(r.json.status, 'approved');
  assert.equal((await e.req('GET', '/notify', OP)).json.policies[0].min_severity, 3, 'applied');
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'notify.proposal.approved' && x.by === 'syed'));
  assert.equal((await post(e, '/notify/proposals/' + pr.id + '/decide', { decision: 'approve' })).status, 409);
  // test e-mail and the AI switched off say why
  r = await post(e, '/notify/test', { team: 'mgr' }); assert.equal(r.status, 200); assert.equal(r.json.status, 'sent');
  r = await post(e, '/notify/ai/ask', { question: 'What is happening?' }, OP); assert.equal(r.status, 424); assert.match(r.json.error, /external AI is not allowed/);
  assert.equal((await post(e, '/notify/ai/ask', { question: 'What is happening?' }, VW)).status, 403);
  void at;
});
