// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// What a human IT auditor asks next, in the AI auditors (engine/auditors.js; rules pyengine/infra_audit_rules.py):
// leavers' AD accounts (CY-21), shared / generic / built-in accounts (CY-22), unauthorised configuration changes (CY-23),
// Microsoft 365 MFA + Conditional Access (CY-24), guest / unused cloud accounts (CY-25), Intune compliance (CY-26), log
// retention (IT-17), DR replication (IT-18), evidence requests answered on time (IT-19) - and the PBC list itself
// (engine/audit-checklist.js): issue, respond, four-eyes decide, roles, validation, audit. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createAuditors } = require('../engine/auditors');
const { createChecklist } = require('../engine/audit-checklist');

const DAY = 86400000;
let T = Date.parse('2026-10-20T08:00:00Z');
const iso = (d) => new Date(T - d * DAY).toISOString();
const testOf = (r, id) => r.tests.find((x) => x.id === id);
const keys = (t) => t.findings.map((f) => f.key.split(':').slice(1).join(':')).sort();
const U = (sam, o = {}) => Object.assign({ sam, name: 'Synthetic ' + sam, disabled: false, privileged: false, privileged_groups: [], service_account: false, dormant: false, rid: '', has_mail: false,
  last_logon: iso(1), pwd_last_set: iso(30), created: iso(400) }, o);

function evidence(bad) {
  const ad = { available: true, synced: iso(0), domain: 'example.test', users: bad ? [
    U('leaver-a', { last_logon: iso(2) }),                       // left 10 days ago, signed in 2 days ago
    U('leaver-b', { last_logon: iso(12) }),                      // left 10 days ago, still enabled
    U('Administrator', { rid: '500', last_logon: iso(3) }), U('Guest', { rid: '501' }), U('test01'), U('scanner'),
    U('adm-mail', { privileged: true, privileged_groups: ['Domain Admins'], has_mail: true }), U('svc-backup', { service_account: true }),
  ] : [U('leaver-a', { disabled: true, last_logon: iso(12) }), U('it-admin', { rid: '500', last_logon: iso(200) }), U('Guest', { rid: '501', disabled: true }), U('adm-sep', { privileged: true })] };
  const dev = { id: 'sw-syn-1', name: 'SW-SYN-1', vendor: 'cisco-ios', site: 'HQ', config: { sha256: 'b'.repeat(64), history: [
    { sha256: 'a'.repeat(64), first_seen: iso(60), previous_read: null },
    { sha256: 'c'.repeat(64), first_seen: iso(20), previous_read: iso(21) },     // matched by NCH-1
    { sha256: 'b'.repeat(64), first_seen: iso(5), previous_read: iso(6) } ] },   // bad: nothing applied in that window
  changes: [{ id: 'NCH-1', status: 'validated', title: 'add VLAN 30', decided_by: 'net.lead', applied_at: new Date(T - 20.5 * DAY).toISOString(), proposed_at: iso(22) }].concat(bad ? [] : [{ id: 'NCH-2', status: 'applied', title: 'trunk', decided_by: 'net.lead', applied_at: new Date(T - 5.5 * DAY).toISOString(), proposed_at: iso(7) }]) };
  const m365 = { available: true, updated: iso(0),
    mfa: { users: 50, registered: bad ? 44 : 50, notRegistered: bad ? [{ name: 'Admin Syn', upn: 'admin.syn@example.test', admin: true }].concat([1, 2, 3, 4, 5].map((i) => ({ name: 'User ' + i, upn: 'u' + i + '@example.test', admin: false }))) : [] },
    conditional_access: bad ? [{ name: 'Require MFA', state: 'enabledForReportingButNotEnforced', modified: iso(9) }] : [{ name: 'Require MFA', state: 'enabled', modified: iso(9) }],
    risky_users: bad ? [{ name: 'R', upn: 'r@example.test', level: 'high', state: 'atRisk', updated: iso(1) }] : [],
    users: [{ name: 'Guest Syn', upn: 'g_ext@example.test', enabled: true, guest: true, licensed: false, created: iso(300), last: bad ? iso(200) : iso(10) },
      { name: 'Member Syn', upn: 'm@example.test', enabled: true, guest: false, licensed: true, created: iso(500), last: bad ? null : iso(1) }],
    intune: [{ name: 'LT-SYN-1', upn: 'a@example.test', os: 'Windows 11', compliance: bad ? 'noncompliant' : 'compliant', last_sync: iso(1) }, { name: 'LT-SYN-2', upn: 'b@example.test', os: 'Windows 11', compliance: 'compliant', last_sync: bad ? iso(45) : iso(2) }] };
  const platform = { available: true, retention_days: bad ? 180 : 400, archive_retention_days: 730, required_retention_days: 365, oldest_event: iso(150) };
  return (p) => (p === '/audit/evidence/ad' ? ad : p === '/audit/evidence/network' ? { available: true, devices: [dev] } : p === '/audit/evidence/m365' ? m365 : p === '/audit/evidence/platform' ? platform : null);
}
async function setup(t, bad) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.addons = e.app.addons || {};
  e.app.addons.handover = { list: () => [{ id: 'HO-1', leaver: 'leaver-a', leaver_name: 'Leaver A (synthetic)', team: 'it', last_day: iso(10).slice(0, 10), state: 'signed-off' },
    { id: 'HO-2', leaver: 'leaver-b', leaver_name: 'Leaver B (synthetic)', team: 'cyber', last_day: iso(10).slice(0, 10), state: 'access' }, { id: 'HO-3', leaver: 'gone-c', leaver_name: 'Gone C', team: 'it', last_day: iso(40).slice(0, 10), state: 'signed-off' }] };
  e.app.duty = { engineers: () => [{ id: 'virt', last_patrol: T - 600000, not_connected: false }],
    list: () => ({ items: bad ? [{ id: 'W-1', kind: 'dr-rpo', severity: 'critical', title: 'PD-CORE: DR copy 300 min old - RPO 60 min missed', status: 'new', first_seen: T - DAY }, { id: 'W-2', kind: 'dr-unprotected', severity: 'medium', title: '4 VMs not protected', status: 'new', first_seen: T - DAY }, { id: 'W-3', kind: 'snapshot-old', severity: 'medium', title: 'x' }] : [] }) };
  return { e, AU: createAuditors(e.app, { now: () => T, siemEvidence: async (p) => evidence(bad)(p) }) };
}

test('the human auditor\'s questions fail on evidence and name the rows', async (t) => {
  const { AU } = await setup(t, true);
  const c = await AU.run('cyberaudit'), i = await AU.run('itaudit');
  const lv = testOf(c, 'CY-21');
  assert.deepEqual(keys(lv), ['signed-in-after', 'still-enabled']);
  assert.equal(lv.findings.find((f) => /signed-in-after/.test(f.key)).severity, 'critical');
  assert.deepEqual(lv.findings.find((f) => /still-enabled/.test(f.key)).items.map((r) => r[3]), ['leaver-b']);
  assert.ok(lv.findings[0].basis.some((b) => /Not checked: 1 leaver\(s\) not found in AD/.test(b)), 'a leaver not in AD is stated, not passed silently');
  assert.deepEqual(keys(testOf(c, 'CY-22')), ['admin-mailbox', 'builtin-admin-name', 'builtin-admin-used', 'generic', 'guest']);
  assert.deepEqual(testOf(c, 'CY-22').findings.find((f) => /generic/.test(f.key)).items.map((r) => r[0]).sort(), ['scanner', 'test01'], 'service accounts are not generic');
  const ch = testOf(c, 'CY-23'); assert.deepEqual(keys(ch), ['unauthorised']); assert.equal(ch.findings[0].items.length, 1, 'the change matched by NCH-1 is authorised');
  assert.deepEqual(keys(testOf(c, 'CY-24')), ['admin-no-mfa', 'no-ca', 'risky', 'users-no-mfa']);
  assert.equal(testOf(c, 'CY-24').findings.find((f) => /admin-no-mfa/.test(f.key)).severity, 'critical');
  assert.deepEqual(keys(testOf(c, 'CY-25')), ['stale-guests', 'stale-users']);
  assert.deepEqual(keys(testOf(c, 'CY-26')), ['noncompliant', 'not-checking-in']);
  assert.deepEqual(keys(testOf(i, 'IT-17')), ['short']); assert.equal(testOf(i, 'IT-17').findings[0].severity, 'high');
  assert.deepEqual(keys(testOf(i, 'IT-18')), ['dr-copy', 'dr-rpo']); assert.equal(testOf(i, 'IT-18').findings.find((f) => /dr-rpo/.test(f.key)).severity, 'critical');
  for (const f of testOf(c, 'CY-24').findings) assert.match(f.evidence_digest, /^sha256:/);
});

test('a clean estate passes; missing sources are not tested', async (t) => {
  const { AU } = await setup(t, false);
  const c = await AU.run('cyberaudit'), i = await AU.run('itaudit');
  for (const id of ['CY-21', 'CY-22', 'CY-23', 'CY-24', 'CY-25', 'CY-26']) assert.equal(testOf(c, id).state, 'pass', id + ' ' + testOf(c, id).detail + ' ' + JSON.stringify(keys(testOf(c, id))));
  for (const id of ['IT-17', 'IT-18']) assert.equal(testOf(i, id).state, 'pass', id + ' ' + testOf(i, id).detail);
  assert.equal(testOf(i, 'IT-19').state, 'not_tested', 'no checklist / no request issued');

  const e2 = await startApp({ noAi: true }); t.after(() => e2.close());
  const AU2 = createAuditors(e2.app, { now: () => T, siemEvidence: async (p) => (p === '/audit/evidence/m365' ? { available: true, updated: iso(0), mfa: null, conditional_access: null, risky_users: null, users: null, intune: null } : p === '/audit/evidence/platform' ? { available: true, retention_days: null } : null) });
  const c2 = await AU2.run('cyberaudit'), i2 = await AU2.run('itaudit');
  assert.equal(testOf(c2, 'CY-24').state, 'not_tested'); assert.match(testOf(c2, 'CY-24').detail, /UserAuthenticationMethod/);
  assert.equal(testOf(c2, 'CY-26').state, 'not_tested'); assert.match(testOf(c2, 'CY-26').detail, /DeviceManagementManagedDevices/);
  assert.equal(testOf(c2, 'CY-21').state, 'not_tested'); assert.equal(testOf(c2, 'CY-23').state, 'not_tested');
  assert.equal(testOf(i2, 'IT-17').state, 'not_tested'); assert.equal(testOf(i2, 'IT-18').state, 'not_tested');
});

test('PBC list: issue, respond, four-eyes decide, overdue raises IT-19; roles, validation and audit', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T });
  let r = await e.req('GET', '/audit-checklist/requests?fw=sama', { role: 'viewer' }); assert.equal(r.status, 403, 'a viewer may not read the request list');
  r = await e.req('GET', '/audit-checklist/requests?fw=sama', { role: 'operator' });
  assert.equal(r.status, 200); assert.ok(r.json.items.length > 50, 'fresh: every check is an open request'); assert.equal(r.json.by_state.not_issued, r.json.items.length);
  const ac24 = r.json.items.find((x) => x.id === 'AC-24'); assert.equal(ac24.ref, 'PBC-AC-24'); assert.match(ac24.evidence_expected, /Privileged account list/);
  // validation
  let b = await e.req('POST', '/audit-checklist/requests/issue', { user: 'aud.syn', role: 'operator', body: { fw: 'sama', due: '2020-01-01' } }); assert.equal(b.status, 400); assert.match(b.json.error, /due must be between/);
  b = await e.req('POST', '/audit-checklist/requests/issue', { user: 'aud.syn', role: 'operator', body: { fw: 'sama' } }); assert.equal(b.status, 400); assert.match(b.json.error, /due/);
  b = await e.req('POST', '/audit-checklist/requests/issue', { user: 'aud.syn', role: 'operator', body: { fw: 'sama', due: '2026-11-03', ids: ['XX-1'] } }); assert.equal(b.status, 400);
  b = await e.req('POST', '/audit-checklist/requests/issue', { user: 'system:bot', role: 'operator', body: { fw: 'sama', due: '2026-11-03' } }); assert.equal(b.status, 403);
  b = await e.req('POST', '/audit-checklist/requests/issue', { user: 'aud.syn', role: 'viewer', body: { fw: 'sama', due: '2026-11-03' } }); assert.equal(b.status, 403);
  // issue two requests
  b = await e.req('POST', '/audit-checklist/requests/issue', { user: 'aud.syn', role: 'operator', body: { fw: 'sama', due: '2026-11-03', ids: ['AC-24', 'AC-29'] } });
  assert.equal(b.status, 200); assert.equal(b.json.issued, 2);
  // respond, then four-eyes
  b = await e.req('POST', '/audit-checklist/requests/respond', { user: 'infra.syn', role: 'operator', body: { id: 'AC-24' } }); assert.equal(b.status, 400); assert.match(b.json.error, /reference/);
  b = await e.req('POST', '/audit-checklist/requests/respond', { user: 'infra.syn', role: 'operator', body: { id: 'AC-24', reference: 'DMS/IT/2026/PRIV-LIST-Q3.pdf' } }); assert.equal(b.status, 200); assert.equal(b.json.state, 'provided');
  b = await e.req('POST', '/audit-checklist/requests/respond', { user: 'infra.syn', role: 'operator', body: { id: 'AC-24', reference: 'again' } }); assert.equal(b.status, 409);
  b = await e.req('POST', '/audit-checklist/requests/decide', { user: 'infra.syn', role: 'operator', body: { id: 'AC-24', decision: 'accept' } }); assert.equal(b.status, 403); assert.match(b.json.error, /four-eyes/);
  b = await e.req('POST', '/audit-checklist/requests/decide', { user: 'aud.syn', role: 'operator', body: { id: 'AC-24', decision: 'reject' } }); assert.equal(b.status, 400); assert.match(b.json.error, /note/);
  b = await e.req('POST', '/audit-checklist/requests/decide', { user: 'aud.syn', role: 'operator', body: { id: 'AC-24', decision: 'reject', note: 'list is not signed by the CISO' } }); assert.equal(b.json.state, 'issued');
  b = await e.req('POST', '/audit-checklist/requests/respond', { user: 'infra.syn', role: 'operator', body: { id: 'AC-24', reference: 'DMS/IT/2026/PRIV-LIST-Q3-signed.pdf' } });
  b = await e.req('POST', '/audit-checklist/requests/decide', { user: 'aud.syn', role: 'operator', body: { id: 'AC-24', decision: 'accept' } }); assert.equal(b.json.state, 'accepted');
  const acts = e.app.store.auditTail(50).map((a) => a.action);
  for (const a of ['audit.pbc.issue', 'audit.pbc.respond', 'audit.pbc.reject', 'audit.pbc.accept']) assert.ok(acts.includes(a), a + ' audited');
  // AC-29 not answered: overdue after the due date → IT-19 raises it to IT Infrastructure
  T = Date.parse('2026-11-20T08:00:00Z');
  r = (await e.req('GET', '/audit-checklist/requests?fw=sama', { role: 'operator' })).json;
  const ac29 = r.items.find((x) => x.id === 'AC-29'); assert.equal(ac29.overdue, true); assert.equal(ac29.days_overdue, 16); assert.equal(r.by_state.overdue, 1);
  assert.equal(r.items.find((x) => x.id === 'AC-24').state, 'accepted');
  const it = testOf(await e.app.addons.auditors.run('itaudit'), 'IT-19');
  assert.equal(it.state, 'fail'); assert.equal(it.findings[0].key, 'IT-19:overdue:infra'); assert.equal(it.findings[0].severity, 'high'); assert.equal(it.findings[0].items[0][0], 'PBC-AC-29');
  T = Date.parse('2026-10-20T08:00:00Z');
});
