// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Team Workspace (engine/team-workspace.js): organisation admin-only and validated (loops refused, undeclared fields dropped),
// reporting authority from the person / role / department head, tasks assigned only down the reporting line and reviewed by the
// step's person (never the assignee, never a service identity), returns need a reason, audit on every change; Microsoft 365 is
// per person and delegated - the account must be the profile e-mail, state bound to the user, the token sealed, mail content
// never in the audit, a person can never reach another person's mailbox. Microsoft is stubbed; data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { toText, teamsJoin } = require('../engine/team-workspace');

const ADM = { user: 'admin.syn', role: 'admin' };
const MGR = { user: 'mgr.syn', role: 'operator' }, ASSOC = { user: 'assoc.syn', role: 'operator' }, ENG = { user: 'eng.syn', role: 'viewer' }, DSK = { user: 'desk.syn', role: 'viewer' };
const SVC = { user: 'svc:robot', role: 'admin' };
const T0 = Date.parse('2026-10-27T07:00:00Z');
const sealer = { available: () => true, unavailableReason: () => null, seal: (id, v) => ({ id, ct: Buffer.from(String(v)).toString('base64') }), unseal: (id, e) => { assert.equal(e.id, id, 'sealed value bound to its id'); return Buffer.from(e.ct, 'base64').toString(); } };

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const calls = []; let me = { userPrincipalName: 'eng.syn@corpgroup.test', mail: 'eng.syn@corpgroup.test' };
  const request = async (url, o) => {
    calls.push({ url, o });
    if (url.endsWith('/oauth2/v2.0/token')) {
      const f = new URLSearchParams(o.body);
      if (f.get('grant_type') === 'refresh_token' && f.get('refresh_token') === 'RT-revoked') return { status: 400, json: { error: 'invalid_grant' } };
      return { status: 200, json: { access_token: 'AT-' + (f.get('code') || f.get('refresh_token')), refresh_token: 'RT-' + Math.random().toString(36).slice(2), expires_in: 3600, scope: 'Mail.Read' } };
    }
    if (url.includes('/me?$select')) return { status: 200, json: me };
    if (url.includes('/me/mailFolders/inbox/messages')) return { status: 200, json: { value: [
      { id: 'AAMkMSG0000000001', subject: 'Firewall change (synthetic)', from: { emailAddress: { name: 'Mgr Syn', address: 'MGR.SYN@corpgroup.test' } }, receivedDateTime: '2026-10-27T06:00:00Z', isRead: false, importance: 'normal', bodyPreview: 'please check' },
      { id: 'AAMkMSG0000000002', subject: 'Newsletter (synthetic)', from: { emailAddress: { name: 'News', address: 'news@vendor.test' } }, receivedDateTime: '2026-10-27T05:00:00Z', isRead: true, importance: 'normal', bodyPreview: '' }] } };
    if (url.includes('/me/messages/AAMkMSG0000000001/reply')) return { status: 202, json: null };
    if (url.includes('/me/messages/AAMkMSG0000000001')) return { status: 200, json: { id: 'AAMkMSG0000000001', subject: 'Firewall change (synthetic)', from: { emailAddress: { name: 'Mgr Syn', address: 'mgr.syn@corpgroup.test' } }, body: { contentType: 'text', content: 'Body text <script>x</script>' } } };
    if (url.includes('/me/calendarView')) return { status: 200, json: { value: [
      { id: 'EV1', subject: 'CAB (synthetic)', start: { dateTime: '2026-10-27T08:00:00.0000000' }, end: { dateTime: '2026-10-27T09:00:00.0000000' }, isOnlineMeeting: true, onlineMeeting: { joinUrl: 'https://teams.microsoft.com/l/meetup-join/19%3asyn' } },
      { id: 'EV2', subject: 'Phish (synthetic)', start: { dateTime: '2026-10-27T10:00:00.0000000' }, end: { dateTime: '2026-10-27T11:00:00.0000000' }, isOnlineMeeting: true, onlineMeeting: { joinUrl: 'https://evil.test/teams.microsoft.com' } }] } };
    if (url.includes('/me/chats?')) return { status: 200, json: { value: [{ id: '19:abcdef0123@thread.v2', chatType: 'group', topic: 'Infra (synthetic)', lastMessagePreview: { createdDateTime: '2026-10-27T06:30:00Z', from: { user: { displayName: 'Mgr Syn' } }, body: { content: '<p>hello <b>team</b></p>' } } }] } };
    if (url.includes('/chats/19%3Aabcdef0123%40thread.v2/messages') && o.method === 'POST') return { status: 201, json: {} };
    return { status: 404, json: null };
  };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, wsRequest: request, wsSealer: sealer });
  return { e, calls, setMe: (x) => { me = x; } };
}
const post = (e, p, body, who = ADM) => e.req('POST', p, Object.assign({ body }, who));
async function org(e) {
  assert.equal((await post(e, '/workspace/template', { template: 'standard-it' })).status, 200);
  const P = [['mgr', 'Mgr Syn', 'mgr.syn', 'infra-manager'], ['assoc', 'Assoc Syn', 'assoc.syn', 'infra-assoc-manager'], ['eng', 'Eng Syn', 'eng.syn', 'senior-net-sec-engineer'], ['desk', 'Desk Syn', 'desk.syn', 'desktop-support-engineer']];
  for (const [id, name, user, role] of P) { const r = await post(e, '/workspace/people', { id, name, user, email: user + '@corpgroup.test', department: 'infrastructure', role }); assert.equal(r.status, 200, r.text); }
}

test('organisation: admin only, validated, loops refused, reporting authority from role / person / department head, audited', async (t) => {
  const { e } = await setup(t);
  assert.equal((await post(e, '/workspace/template', { template: 'standard-it' }, MGR)).status, 403);
  assert.equal((await post(e, '/workspace/departments', { name: 'X' }, SVC)).status, 403, 'service identity refused');
  await org(e);
  let r = await post(e, '/workspace/people', { name: 'Bad', department: 'nowhere' }); assert.equal(r.status, 400); assert.match(r.json.error, /department: there is no department/);
  r = await post(e, '/workspace/people', { name: 'Bad', department: 'infrastructure', email: 'nope' }); assert.equal(r.status, 400); assert.match(r.json.error, /email/);
  r = await post(e, '/workspace/people', { name: 'Dup', department: 'infrastructure', user: 'ENG.SYN' }); assert.equal(r.status, 400); assert.match(r.json.error, /already on another profile/);
  r = await post(e, '/workspace/people', { id: 'mgr', name: 'Mgr Syn', user: 'mgr.syn', email: 'mgr.syn@corpgroup.test', department: 'infrastructure', role: 'infra-manager', reports_to: 'eng' }); assert.equal(r.status, 400); assert.match(r.json.error, /loop/);
  r = await post(e, '/workspace/roles', { id: 'infra-manager', name: 'Infrastructure Manager', department: 'infrastructure', reports_to_role: 'desktop-support-engineer' }); assert.equal(r.status, 400); assert.match(r.json.error, /loop/);
  r = await post(e, '/workspace/workflows', { name: 'Bad', steps: [{ name: 'x', to: 'everyone' }] }); assert.equal(r.status, 400); assert.match(r.json.error, /steps\[0\]\.to/);
  r = await post(e, '/workspace/departments', { name: 'Applications', evil: 1 }); assert.equal(r.status, 200); assert.equal(r.json.evil, undefined);
  assert.equal((await post(e, '/workspace/roles/infra-manager/delete', {})).status, 409, 'role in use cannot be deleted');
  const me = (await e.req('GET', '/workspace/me', ENG)).json;
  assert.equal(me.profile.name, 'Eng Syn'); assert.deepEqual(me.managers.map((m) => m.id), ['assoc', 'mgr'], 'role line: engineer -> associate manager -> manager');
  assert.equal(me.head.id, 'mgr', 'department head from head_role');
  assert.deepEqual((await e.req('GET', '/workspace/me', ASSOC)).json.reports.map((x) => x.id).sort(), ['desk', 'eng']);
  const ov = (await e.req('GET', '/workspace/org', ENG)).json;
  assert.equal(ov.people[0].email, undefined, 'e-mail and sign-in names hidden from non-admins'); assert.equal(ov.can_edit, false);
  assert.ok((await e.req('GET', '/workspace/org', ADM)).json.people.find((p) => p.id === 'eng').email);
  assert.equal((await e.req('GET', '/workspace/me', { user: 'stranger', role: 'viewer' })).json.profile, null);
  const au = e.app.store.auditTail(50).find((x) => x.action === 'workspace.person.create'); assert.equal(au.by, 'admin.syn'); assert.equal(au.detail.email, 'set');
  assert.ok(!JSON.stringify(e.app.store.auditTail(50)).includes('@corpgroup.test'), 'addresses never in the audit');
});

test('tasks: assigned down the reporting line only, reviewed by the step person (never the assignee), returns need a reason', async (t) => {
  const { e } = await setup(t);
  await org(e);
  let r = await post(e, '/workspace/tasks', { title: 'Patch the core switch (synthetic)', assignee: 'mgr' }, ENG); assert.equal(r.status, 403, 'cannot assign upward'); assert.match(r.json.error, /does not report to you/);
  r = await post(e, '/workspace/tasks', { title: 'x', assignee: 'eng' }, { user: 'stranger', role: 'admin' }); assert.equal(r.status, 200, 'admin assigns to anyone');
  r = await post(e, '/workspace/tasks', { title: 'Bad', assignee: 'eng', priority: 'yesterday' }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /priority/);
  await post(e, '/workspace/workflows', { id: 'two-step', name: 'Associate then head', steps: [{ name: 'Associate manager', to: 'manager' }, { name: 'Department head', to: 'dept_head' }] });
  r = await post(e, '/workspace/tasks', { title: 'Review VPN rules (synthetic)', assignee: 'eng', priority: 'high', due: '2026-10-26', workflow: 'two-step' }, MGR); assert.equal(r.status, 200, r.text);
  const id = r.json.id; assert.equal(r.json.overdue, true);
  assert.equal((await post(e, '/workspace/tasks/' + id + '/start', {}, DSK)).status, 404, 'not visible to a peer');
  assert.equal((await post(e, '/workspace/tasks/' + id + '/start', {}, MGR)).status, 403, 'only the assignee starts');
  assert.equal((await post(e, '/workspace/tasks/' + id + '/submit', { note: 'done' }, ENG)).status, 200);
  assert.equal((await post(e, '/workspace/tasks/' + id + '/approve', {}, ENG)).status, 403, 'assignee never approves');
  assert.equal((await post(e, '/workspace/tasks/' + id + '/approve', {}, MGR)).status, 403, 'step 1 is for the associate manager');
  assert.equal((await e.req('GET', '/workspace/tasks?scope=review', ASSOC)).json.tasks.length, 1);
  r = await post(e, '/workspace/tasks/' + id + '/return', {}, ASSOC); assert.equal(r.status, 400); assert.match(r.json.error, /note/);
  r = await post(e, '/workspace/tasks/' + id + '/return', { note: 'add the rollback' }, ASSOC); assert.equal(r.json.status, 'returned');
  await post(e, '/workspace/tasks/' + id + '/submit', {}, ENG);
  r = await post(e, '/workspace/tasks/' + id + '/approve', {}, ASSOC); assert.equal(r.json.status, 'in_review'); assert.equal(r.json.reviewer.name, 'Mgr Syn');
  r = await post(e, '/workspace/tasks/' + id + '/approve', {}, MGR); assert.equal(r.json.status, 'done');
  assert.equal((await post(e, '/workspace/tasks/' + id + '/frobnicate', {}, MGR)).status, 404);
  assert.equal((await e.req('GET', '/workspace/tasks?scope=all', MGR)).status, 403);
  assert.equal((await e.req('GET', '/workspace/me', MGR)).json.tasks.team.open, 1, 'the admin-assigned one is still open');
  const acts = e.app.store.auditTail(80).filter((x) => x.target === id).map((x) => x.action).reverse();
  assert.deepEqual(acts, ['workspace.task.create', 'workspace.task.submit', 'workspace.task.return', 'workspace.task.submit', 'workspace.task.approve', 'workspace.task.approve']);
});

test('Microsoft 365: admin settings, own account only, profile e-mail enforced, sealed token, mail content never audited', async (t) => {
  const { e, calls, setMe } = await setup(t);
  await org(e);
  assert.equal((await post(e, '/workspace/m365/connect', {}, ENG)).status, 424, 'not configured');
  assert.equal((await post(e, '/workspace/m365/settings', { enabled: true }, MGR)).status, 403);
  let r = await post(e, '/workspace/m365/settings', { enabled: true, tenant_id: 'nope' }); assert.equal(r.status, 400); assert.match(r.json.error, /tenant_id/);
  r = await post(e, '/workspace/m365/settings', { enabled: true, tenant_id: '11111111-1111-1111-1111-111111111111', client_id: '22222222-2222-2222-2222-222222222222', client_secret: 'SECRET-syn', redirect_uri: 'http://portal.test/dashboards/my-workspace.html' }); assert.equal(r.status, 400, 'https only');
  r = await post(e, '/workspace/m365/settings', { enabled: true, tenant_id: '11111111-1111-1111-1111-111111111111', client_id: '22222222-2222-2222-2222-222222222222', client_secret: 'SECRET-syn', redirect_uri: 'https://portal.test/dashboards/my-workspace.html' }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.client_secret_set, true); assert.ok(!JSON.stringify(r.json).includes('SECRET-syn'));
  assert.equal((await post(e, '/workspace/m365/connect', {}, { user: 'stranger', role: 'viewer' })).status, 424, 'no profile, no connection');
  const c = (await post(e, '/workspace/m365/connect', {}, ENG)).json; const u = new URL(c.url);
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256'); assert.match(u.searchParams.get('scope'), /Mail\.Send/); assert.doesNotMatch(u.searchParams.get('scope'), /\.All/, 'delegated, never tenant-wide');
  const state = u.searchParams.get('state');
  assert.equal((await post(e, '/workspace/m365/callback', { code: 'C1', state }, DSK)).status, 403, 'state bound to the user who started it');
  assert.equal((await post(e, '/workspace/m365/callback', { code: 'C1', state }, ENG)).status, 400, 'a state is single use');
  const s2 = new URL((await post(e, '/workspace/m365/connect', {}, ENG)).json.url).searchParams.get('state');
  setMe({ userPrincipalName: 'mgr.syn@corpgroup.test', mail: 'mgr.syn@corpgroup.test' });
  r = await post(e, '/workspace/m365/callback', { code: 'C2', state: s2 }, ENG); assert.equal(r.status, 403, 'another account refused'); assert.match(r.json.error, /your own work account/);
  setMe({ userPrincipalName: 'eng.syn@corpgroup.test', mail: 'eng.syn@corpgroup.test' });
  const s3 = new URL((await post(e, '/workspace/m365/connect', {}, ENG)).json.url).searchParams.get('state');
  r = await post(e, '/workspace/m365/callback', { code: 'C3', state: s3 }, ENG); assert.equal(r.status, 200, r.text);
  const tok = e.app.store.collection('ws_m365_tokens').get('eng.syn'); assert.ok(tok.enc && !JSON.stringify(tok).includes('RT-') , 'refresh token stored sealed only');
  assert.equal((await e.req('GET', '/workspace/me', ENG)).json.m365.connected, true);
  const m = (await e.req('GET', '/workspace/mail', ENG)).json;
  assert.equal(m.messages[0].tag, 'from your reporting line', 'mail from the department head is flagged'); assert.equal(m.unread, 1);
  assert.equal((await e.req('GET', '/workspace/mail', DSK)).status, 424, 'another person has no access to this mailbox');
  assert.equal((await e.req('GET', '/workspace/mail', ADM)).status, 424, 'an administrator cannot read it either');
  assert.equal((await e.req('GET', '/workspace/mail/..%2Fusers', ENG)).status, 400);
  const one = (await e.req('GET', '/workspace/mail/AAMkMSG0000000001', ENG)).json; assert.match(one.text, /Body text/);
  r = await post(e, '/workspace/mail/AAMkMSG0000000001/reply', {}, ENG); assert.equal(r.status, 400); assert.match(r.json.error, /comment/);
  r = await post(e, '/workspace/mail/AAMkMSG0000000001/reply', { comment: 'Confidential reply text (synthetic)' }, ENG); assert.equal(r.status, 200);
  assert.ok(calls.some((x) => x.url.endsWith('/me/messages/AAMkMSG0000000001/reply') && x.o.headers.Authorization === 'Bearer AT-C3'), 'sent with the person\'s own token');
  const au = e.app.store.auditTail(50); assert.ok(au.find((x) => x.action === 'workspace.mail.reply' && x.by === 'eng.syn'));
  assert.ok(!JSON.stringify(au).includes('Confidential reply') && !JSON.stringify(au).includes('Firewall change'), 'no mail content in the audit');
  const cal = (await e.req('GET', '/workspace/calendar?days=1', ENG)).json;
  assert.equal(cal.events[0].join, 'https://teams.microsoft.com/l/meetup-join/19%3asyn'); assert.equal(cal.events[1].join, null, 'only Teams addresses become join links');
  const ch = (await e.req('GET', '/workspace/chats', ENG)).json; assert.equal(ch.chats[0].last.text, 'hello team');
  r = await post(e, '/workspace/chats/19:abcdef0123@thread.v2/send', { text: 'on it' }, ENG); assert.equal(r.status, 200, r.text);
  assert.equal((await post(e, '/workspace/mail/AAMkMSG0000000001/reply', { comment: 'x' }, { user: 'svc:robot', role: 'viewer' })).status, 403, 'service identity cannot send');
  // a revoked sign-in drops the connection
  e.app.store.collection('ws_m365_tokens').put(Object.assign({}, tok, { id: 'desk.syn', enc: sealer.seal('rt:desk.syn', 'RT-revoked'), upn: 'desk.syn@corpgroup.test' }));
  r = await e.req('GET', '/workspace/mail', DSK); assert.equal(r.status, 424); assert.match(r.json.error, /connect again/);
  assert.equal(e.app.store.collection('ws_m365_tokens').get('desk.syn'), null);
  assert.equal((await post(e, '/workspace/m365/revoke', { user: 'eng.syn' }, MGR)).status, 403);
  assert.equal((await post(e, '/workspace/m365/revoke', { user: 'eng.syn' })).json.had, true);
  assert.equal((await e.req('GET', '/workspace/mail', ENG)).status, 424);
});

test('text helpers: Teams HTML to text, join links only for Teams', () => {
  assert.equal(toText('<p>a<br>b</p><script>alert(1)</script>&amp;'), 'a\nb\n&');
  assert.equal(teamsJoin('javascript:alert(1)'), null); assert.equal(teamsJoin('https://teams.microsoft.com.evil.test/x'), null);
});

test('template: the Desktop Support Engineer (reports to the Infrastructure Associate Manager) and GRC Analyst (reports to the CISO) job titles carry their access role', async (t) => {
  const { e } = await setup(t);
  await org(e);
  assert.equal((await post(e, '/workspace/people', { id: 'noor', name: 'Noor Syn', user: 'noor.syn', email: 'noor.syn@corpgroup.test', department: 'cyber-security', role: 'grc-analyst' })).status, 200);
  const o = (await e.req('GET', '/workspace/org', ADM)).json, R = Object.fromEntries(o.roles.map((r) => [r.id, r]));
  assert.equal(R['desktop-support-engineer'].access_role, 'desktop-engineer');
  assert.equal(R['grc-analyst'].access_role, 'grc-analyst'); assert.equal(R['grc-analyst'].reports_to_role, 'ciso'); assert.equal(R['grc-analyst'].department, 'cyber-security');
  assert.ok(e.app.store.auditTail(200).some((a) => a.action === 'workspace.person.save' || /workspace\.person/.test(a.action)), 'the profile change is audited');
});

test('reporting lines: a Desktop Support Engineer reports to the Infrastructure Associate Manager, a GRC Analyst to the CISO', async (t) => {
  const { e } = await setup(t);
  await org(e);
  for (const [id, name, user, dept, role] of [['ciso', 'Ciso Syn', 'ciso.syn', 'cyber-security', 'ciso'], ['noor', 'Noor Syn', 'noor.syn', 'cyber-security', 'grc-analyst']])
    assert.equal((await post(e, '/workspace/people', { id, name, user, email: user + '@corpgroup.test', department: dept, role })).status, 200);
  const mgr = async (user) => { const m = (await e.req('GET', '/workspace/me', { user, role: 'operator' })).json; return ((m.managers || [])[0] || {}).name; };
  assert.match(String(await mgr('desk.syn')), /assoc/i, 'Desktop Support Engineer -> Infrastructure Associate Manager');
  assert.match(String(await mgr('noor.syn')), /ciso/i, 'GRC Analyst -> CISO');
});

test('template: the Head of Risk & Compliance leads the Risk & Compliance Department and carries the risk-head access role', async (t) => {
  const { e } = await setup(t);
  await org(e);
  const o = (await e.req('GET', '/workspace/org', ADM)).json, R = Object.fromEntries(o.roles.map((r) => [r.id, r])), D = Object.fromEntries(o.departments.map((d) => [d.id, d]));
  assert.equal(R['head-risk-compliance'].access_role, 'risk-head'); assert.equal(R['head-risk-compliance'].department, 'risk-compliance'); assert.equal(R['head-risk-compliance'].reports_to_role, null);
  assert.equal(D['risk-compliance'].head_role, 'head-risk-compliance');
  assert.equal((await post(e, '/workspace/people', { id: 'risk', name: 'Risk Head Syn', user: 'risk', email: 'risk.syn@corpgroup.test', department: 'risk-compliance', role: 'head-risk-compliance' })).status, 200);
  const me = (await e.req('GET', '/workspace/me', { user: 'risk', role: 'operator' })).json;
  assert.equal(me.profile.role, 'head-risk-compliance'); assert.match(me.profile.role_name, /Head of Risk & Compliance/);
});

test('template: SOC, Applications, Audit and Network & Security departments with their heads, reporting lines and access roles; re-applying adds only what is missing; all editable', async (t) => {
  const { e } = await setup(t);
  await org(e);
  let o = (await e.req('GET', '/workspace/org', ADM)).json;
  const D = Object.fromEntries(o.departments.map((d) => [d.id, d])), R = Object.fromEntries(o.roles.map((r) => [r.id, r]));
  for (const [dep, head] of [['soc', 'soc-manager'], ['application', 'application-manager'], ['audit', 'audit-head'], ['network-security', 'network-security-lead']]) assert.equal((D[dep] || {}).head_role, head, dep);
  assert.equal(R['soc-analyst'].access_role, 'soc-analyst'); assert.equal(R['soc-analyst'].reports_to_role, 'soc-manager'); assert.equal(R['soc-manager'].reports_to_role, 'ciso');
  assert.equal(R['application-engineer'].access_role, 'application-admin'); assert.equal(R['it-auditor'].access_role, 'auditor'); assert.equal(R['network-security-engineer'].access_role, 'network-admin');
  // every access role the template names is a real job role
  const { BUILTIN } = require('../engine/roles'), ids = new Set(BUILTIN.map((b) => b.id));
  for (const r of o.template.roles) if (r.access_role) assert.ok(ids.has(r.access_role), r.id + ' -> ' + r.access_role);
  // a SOC analyst reports to the SOC manager
  for (const [id, name, user, role] of [['socm', 'Socm Syn', 'socm.syn', 'soc-manager'], ['soca', 'Soca Syn', 'soca.syn', 'soc-analyst']])
    assert.equal((await post(e, '/workspace/people', { id, name, user, email: user + '@corpgroup.test', department: 'soc', role })).status, 200);
  const me = (await e.req('GET', '/workspace/me', { user: 'soca.syn', role: 'operator' })).json;
  assert.match(String(((me.managers || [])[0] || {}).name), /Socm/);
  // customised: rename the department, then re-apply the template - the change is kept and nothing is duplicated
  assert.equal((await post(e, '/workspace/departments', Object.assign({}, D.audit, { name: 'Internal Audit (customised)' }))).status, 200);
  const again = (await post(e, '/workspace/template', { template: 'standard-it' })).json;
  assert.deepEqual(again.departments, []); assert.deepEqual(again.roles, []);
  o = (await e.req('GET', '/workspace/org', ADM)).json;
  assert.equal(o.departments.find((d) => d.id === 'audit').name, 'Internal Audit (customised)');
  assert.equal(o.departments.filter((d) => d.id === 'audit').length, 1);
});
