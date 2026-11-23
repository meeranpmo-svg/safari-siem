// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Password & MFA Posture (engine/identity-posture.js), report only, SYNTHETIC people and a stubbed SIEM link: the domain
// policy scored against the baseline; accounts with a never-expiring / not-required / old password (enabled only); MFA from
// the SIEM's Graph sync (administrators without MFA first, Conditional Access by name); lockouts from 4740; the ranked
// remediation list; fine-grained policies read over the directory connection (fake AD over LDAPS); nothing connected = the
// reason and what to connect, never a zero; roles (viewer refused, operator reads, admin changes the baseline, AI identity
// refused); validation errors naming the field; the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startApp } = require('./helpers');
const { createIdentityPosture, registerIdentityPosture } = require('../engine/identity-posture');

const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };
const T = Date.parse('2026-11-12T08:00:00Z'), DAY = 86400000, ago = (d) => new Date(T - d * DAY).toISOString();
const U = (sam, o) => Object.assign({ sam, name: sam.replace('.syn', ' Synthetic'), disabled: false, privileged: false, service_account: false, pwd_never_expires: false, pwd_not_required: false, pwd_last_set: ago(30) }, o);
const AD = { available: true, synced: ago(0.1), domain: 'corp-hq.example', policy: { min_length: 8, history: 24, max_age_days: 0, min_age_days: 1, complexity: true, reversible: false, lockout_threshold: 0, lockout_minutes: 30, lockout_window_minutes: 30 },
  users: [U('alia.syn'), U('badr.syn', { privileged: true, pwd_never_expires: true }), U('carl.syn', { pwd_not_required: true }), U('dina.syn', { pwd_last_set: ago(400) }), U('eve.syn', { disabled: true, pwd_never_expires: true }),
    U('svc-backup-syn', { service_account: true, pwd_never_expires: true }), U('fadi.syn', { privileged: true, pwd_last_set: ago(500) })] };
const M365 = { available: true, updated: ago(0.05), blocks: { mfa: { ok: true }, conditionalAccess: { ok: true } },
  mfa: { users: 10, registered: 7, notRegistered: [{ name: 'Badr Synthetic', upn: 'badr.syn@corp-hq.example', admin: true }, { name: '<img src=x>Hala Synthetic', upn: 'hala.syn@corp-hq.example', admin: false }, { name: 'Imad Synthetic', upn: 'imad.syn@corp-hq.example', admin: false }] },
  conditional_access: [{ name: 'Require MFA for admins', state: 'enabledForReportingButNotEnforced', modified: ago(40) }, { name: 'Block legacy authentication', state: 'enabled', modified: ago(10) }] };
function fakeSiem(o = {}) {
  const calls = [];
  const fn = async (m, p, b) => {
    calls.push({ m, p, b });
    if (o.fail) throw o.fail;
    if (p === '/audit/evidence/ad') return o.ad || AD;
    if (p === '/audit/evidence/m365') return o.m365 || M365;
    if (p === '/histogram') return { buckets: Array.from({ length: 30 }, (_, i) => ({ t: T - (29 - i) * DAY, n: i === 29 ? 12 : i % 7 === 0 ? 1 : 0 })) };
    if (p === '/top' && b.field === 'target_user') return { values: [{ v: 'gina.syn', n: 12 }, { v: 'alia.syn', n: 3 }] };
    if (p === '/top') return { values: [{ v: 'WS-SYN-07', n: 12 }, { v: '', n: 1 }] };
    throw new Error('unexpected ' + p);
  };
  fn.calls = calls; return fn;
}
const FG = { readable: true, items: [{ name: 'PSO-Admins-Syn', precedence: 10, applies_to: 1, min_length: 16, history: 24, max_age_days: 90, min_age_days: 1, complexity: true, reversible: false, lockout_threshold: 5, lockout_minutes: 30, lockout_window_minutes: 30 },
  { name: 'PSO-Legacy-Syn', precedence: 20, applies_to: 2, min_length: 6, history: 0, max_age_days: 0, min_age_days: 0, complexity: false, reversible: true, lockout_threshold: 0, lockout_minutes: 0, lockout_window_minutes: 0 }] };

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const siem = o.siem === null ? undefined : (o.siem || fakeSiem());
  const X = createIdentityPosture(e.app, { now: () => T, siem, fgpp: o.fgpp === null ? undefined : (o.fgpp || (async () => FG)) });
  registerIdentityPosture(e.app.srv, e.app, X);
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const audits = (a) => e.app.store.auditTail(300).filter((x) => x.action === a);
  return { e, X, siem, call, audits };
}

test('roles: viewers refused (it names people), operators read, only a person with the admin role changes the baseline', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('GET', '/identity-posture', undefined, VIEW)).status, 403);
  assert.equal((await s.call('GET', '/identity-posture', undefined, OP)).status, 200);
  assert.equal((await s.call('POST', '/identity-posture/baseline', { reason: 'synthetic test', values: { min_length: 12 } }, OP)).status, 403, 'operators do not change the baseline');
  const r = await s.call('POST', '/identity-posture/baseline', { reason: 'synthetic test', values: { min_length: 12 } }, BOT);
  assert.equal(r.status, 403); assert.match(r.json.error, /a person changes the identity baseline/);
  assert.equal(s.audits('identity_posture.baseline').length, 0, 'nothing changed, nothing recorded');
  const rd = s.audits('identity_posture.read').pop(); assert.equal(rd.by, OP.user); assert.equal(rd.role, 'operator');
});

test('the report: policy against the baseline, accounts, MFA, Conditional Access, lockouts, a ranked remediation list', async (t) => {
  const s = await setup(t);
  const r = await s.call('GET', '/identity-posture', undefined, OP); assert.equal(r.status, 200, r.raw);
  const v = r.json, chk = (id) => v.policy.checks.find((c) => c.id === 'domain:' + id);
  // every SIEM read through the analyst role's evidence routes, never collected again
  assert.deepEqual([...new Set(s.siem.calls.map((c) => c.p))].sort(), ['/audit/evidence/ad', '/audit/evidence/m365', '/histogram', '/top']);
  assert.deepEqual(s.siem.calls.filter((c) => c.p === '/top').map((c) => c.b.q), ['action:account-locked', 'action:account-locked']);
  // policy
  assert.equal(chk('min_length').ok, false); assert.equal(chk('min_length').expected, '≥ 14');
  assert.equal(chk('max_age').value, 'never'); assert.equal(chk('max_age').ok, false);
  assert.equal(chk('lockout_threshold').value, '0 (never locks)'); assert.equal(chk('lockout_threshold').ok, false);
  assert.equal(chk('complexity').ok, true); assert.equal(chk('reversible').ok, true); assert.equal(chk('history').ok, true);
  assert.ok(chk('min_length').refs.includes('NCA ECC 2-2-3') && chk('min_length').refs.includes('SAMA CSF 3.3.5'));
  assert.equal(v.policy.score, 50);
  // accounts: enabled only; privileged first
  assert.deepEqual(v.accounts.never_expires.items.map((u) => u.sam), ['badr.syn', 'svc-backup-syn'], 'the disabled eve.syn is left out');
  assert.equal(v.accounts.never_expires.items[1].service, true);
  assert.deepEqual(v.accounts.not_required.items.map((u) => u.sam), ['carl.syn']);
  assert.deepEqual(v.accounts.old.items.map((u) => [u.sam, u.pwd_age_days]), [['fadi.syn', 500], ['dina.syn', 400]]);
  // MFA + CA
  assert.equal(v.mfa.pct, 70); assert.deepEqual(v.mfa.admins_without.map((u) => u.upn), ['badr.syn@corp-hq.example']); assert.equal(v.mfa.not_registered.count, 3);
  assert.equal(v.mfa.methods.available, false); assert.match(v.mfa.methods.reason, /not which methods/);
  assert.deepEqual(v.conditional_access.mfa_enforced, []); assert.deepEqual(v.conditional_access.mfa_report_only, ['Require MFA for admins']); assert.match(v.conditional_access.note, /by name only/);
  // lockouts
  assert.equal(v.lockouts.total, 12 + 5); assert.equal(v.lockouts.per_day.length, 30); assert.deepEqual(v.lockouts.top_accounts[0], { sam: 'gina.syn', n: 12 });
  assert.deepEqual(v.lockouts.top_computers, [{ computer: 'WS-SYN-07', n: 12 }]);
  // fine-grained
  assert.deepEqual(v.fine_grained.items.map((p) => p.name), ['PSO-Admins-Syn', 'PSO-Legacy-Syn']); assert.equal(v.fine_grained.items[0].score, 100);
  // remediation, ranked
  const titles = v.remediation.map((x) => x.title);
  assert.match(titles[0], /^Administrator\(s\) without MFA registered$/); assert.equal(v.remediation[0].severity, 'critical'); assert.equal(v.remediation[0].count, 1); assert.equal(v.remediation[0].page, 'm365-security.html');
  assert.match(titles[1], /PASSWD_NOTREQD/); assert.match(titles[2], /No enabled Conditional Access policy enforcing MFA/); assert.match(v.remediation[2].detail, /report-only mode: Require MFA for admins/);
  assert.ok(v.remediation.some((x) => /Fine-grained policy PSO-Legacy-Syn: reversible encryption is on/.test(x.title) && x.severity === 'high'));
  assert.ok(v.remediation.some((x) => /locked out 10 or more times/.test(x.title) && /gina\.syn \(12\)/.test(x.detail)));
  assert.ok(!v.remediation.some((x) => /lockout duration/.test(x.title)), 'the duration is not a second finding when the domain never locks');
  assert.deepEqual(v.remediation.map((x) => x.rank), v.remediation.map((_, i) => i + 1));
  for (let i = 1; i < v.remediation.length; i++) assert.ok(v.remediation[i - 1].score >= v.remediation[i].score, 'ranked by score');
  assert.equal(v.summary.admins_without_mfa, 1); assert.equal(v.summary.mfa_pct, 70); assert.equal(v.summary.not_required, 1);
  assert.ok(!/password"\s*:/i.test(r.raw), 'no password field anywhere');
});

test('nothing connected: each part says what to connect - no zero, no sample, no finding', async (t) => {
  const s = await setup(t, { siem: null, fgpp: null });
  const v = (await s.call('GET', '/identity-posture', undefined, OP)).json;
  for (const k of ['ad', 'm365', 'lockouts', 'fgpp']) assert.equal(v.sources[k].state, 'not_connected', k);
  assert.match(v.policy.reason, /not linked.*connect Active Directory to the SIEM/);
  assert.match(v.mfa.reason, /connect Microsoft 365 to the SIEM/); assert.match(v.lockouts.reason, /event 4740/); assert.match(v.fine_grained.reason, /directory connection is not set/);
  assert.deepEqual(v.remediation, []);
  for (const k of ['policy_score', 'mfa_pct', 'admins_without_mfa', 'never_expires', 'not_required', 'lockouts', 'overall']) assert.equal(v.summary[k], null, k);
  // an older SIEM / a block Graph did not give
  const s2 = await setup(t, { siem: fakeSiem({ ad: { available: false, reason: 'the AD identity sync has not completed yet' }, m365: Object.assign({}, M365, { mfa: null, conditional_access: null, blocks: { mfa: { ok: false, perm: 'UserAuthenticationMethod.Read.All', error: 'permission not granted' } } }) }) });
  const w = (await s2.call('GET', '/identity-posture', undefined, OP)).json;
  assert.match(w.policy.reason, /has not completed yet/); assert.match(w.mfa.reason, /grant UserAuthenticationMethod\.Read\.All/); assert.match(w.conditional_access.reason, /not read yet/);
  // a SIEM that errors: stated, logged once with context, the rest of the page still works
  const s3 = await setup(t, { siem: fakeSiem({ fail: new Error('SIEM answered HTTP 502') }) });
  const x = (await s3.call('GET', '/identity-posture', undefined, OP)).json;
  assert.equal(x.sources.ad.state, 'error'); assert.match(x.sources.ad.reason, /HTTP 502/); assert.equal(x.fine_grained.items.length, 2);
  assert.ok(s3.e.logs.some((l) => l[0] === 'warn' && /identity posture: the ad source could not be read/.test(l[1])));
});

test('baseline: an administrator adjusts it within fixed bounds, with a reason; audited with what changed and whether weaker', async (t) => {
  const s = await setup(t);
  const post = (b, who) => s.call('POST', '/identity-posture/baseline', b, who || ADM);
  let r = await post({ values: { min_length: 12 } }); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await post({ reason: 'synthetic test', values: { min_length: 4 } }); assert.equal(r.status, 400); assert.match(r.json.error, /min_length must be at least 8/);
  r = await post({ reason: 'synthetic test', values: { lockout_threshold: 50 } }); assert.equal(r.status, 400); assert.match(r.json.error, /lockout_threshold must be at most 10/);
  r = await post({ reason: 'synthetic test', values: { min_length: 'long' } }); assert.equal(r.status, 400); assert.match(r.json.error, /min_length must be a whole number/);
  r = await post({ reason: 'synthetic test', values: {} }); assert.equal(r.status, 400); assert.match(r.json.error, /values: nothing to change/);
  r = await post({ reason: 'synthetic test', values: [] }); assert.equal(r.status, 400); assert.match(r.json.error, /values must be an object/);
  r = await post({ reason: 'synthetic test', values: { reversible: true, min_length: 12 } }); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.values.min_length, 12); assert.equal(r.json.values.reversible, undefined, 'fixed rules are not adjustable'); assert.equal(r.json.changed_by, ADM.user);
  const a = s.audits('identity_posture.baseline').pop();
  assert.equal(a.by, ADM.user); assert.equal(a.role, 'admin'); assert.equal(a.detail.reason, 'synthetic test'); assert.deepEqual(a.detail.changed, [{ key: 'min_length', from: 14, to: 12, weaker: true }]);
  r = await post({ reason: 'match the legacy domain (synthetic)', values: { min_length: 8 } }); assert.equal(r.status, 200, r.raw);
  const v = (await s.call('GET', '/identity-posture', undefined, OP)).json;
  assert.equal(v.policy.checks.find((c) => c.id === 'domain:min_length').ok, true, 'the report follows the new baseline at once'); assert.equal(v.baseline.values.min_length, 8);
  r = await post({ reason: 'back to the platform default (synthetic)', reset: true }); assert.equal(r.json.values.min_length, 14);
  const bl = s.audits('identity_posture.baseline'); assert.equal(bl.length, 3); assert.ok(bl.some((x) => x.detail.reset === true && x.detail.reason === 'back to the platform default (synthetic)' && x.detail.changed[0].to === 14 && x.detail.changed[0].weaker === false));
});

test('fine-grained policies over the directory connection (fake AD over LDAPS, read only)', async (t) => {
  const { makeCA, makeServerCert } = require('./helpers/x509');
  const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');
  const { createAdWriter } = require('../engine/ad-writer');
  const BASE = 'DC=corp-hq,DC=com', SVC = 'CN=svc-dir-syn,' + BASE, PW = 'Synthetic-Bind-Pass-7';
  const ca = makeCA('Synthetic AD CA posture'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const dir = makeDirectory();
  dir.add(BASE, { objectClass: ['domain'] }); dir.add('CN=System,' + BASE, { objectClass: ['container'] }); dir.add(SVC, { objectClass: ['user'], sAMAccountName: 'svc-dir-syn' });
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: PW } }); t.after(() => ldap.close());
  const w = createAdWriter({ servers: ['ldaps://127.0.0.1:' + ldap.port], ca: ca.cert, bindDN: SVC, password: PW, baseDN: BASE });
  let r = await w.passwordSettings(); assert.equal(r.readable, false, 'no container visible: said, not an empty list passed off as none'); assert.deepEqual(r.items, []);
  dir.add('CN=Password Settings Container,CN=System,' + BASE, { objectClass: ['msDS-PasswordSettingsContainer'] });
  dir.add('CN=PSO-Syn,CN=Password Settings Container,CN=System,' + BASE, { objectClass: ['msDS-PasswordSettings'], cn: 'PSO-Syn', 'msDS-PasswordSettingsPrecedence': '10',
    'msDS-PSOAppliesTo': ['CN=Claims-Team,' + BASE, 'CN=VPN-Users,' + BASE], 'msDS-MinimumPasswordLength': '15', 'msDS-PasswordHistoryLength': '24', 'msDS-MaximumPasswordAge': '-77760000000000',
    'msDS-MinimumPasswordAge': '-864000000000', 'msDS-PasswordComplexityEnabled': 'TRUE', 'msDS-PasswordReversibleEncryptionEnabled': 'FALSE', 'msDS-LockoutThreshold': '5',
    'msDS-LockoutDuration': '-18000000000', 'msDS-LockoutObservationWindow': '-18000000000' });
  r = await w.passwordSettings();
  assert.equal(r.readable, true);
  assert.deepEqual(r.items, [{ name: 'PSO-Syn', precedence: 10, applies_to: 2, min_length: 15, history: 24, max_age_days: 90, min_age_days: 1, complexity: true, reversible: false, lockout_threshold: 5, lockout_minutes: 30, lockout_window_minutes: 30 }]);
  assert.deepEqual([...new Set(ldap.requests.map((q) => q.op))].filter((o) => !['bind', 'search', 'unbind'].includes(o)), [], 'read only: no add, modify, delete or move');
  // and through the report: the onboarding directory connection's writer is used when no stub is given
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.addons = e.app.addons || {}; e.app.addons.onboarding = { ad: { cfg: () => ({ bind_enc: { sealed: true }, servers: ['ldaps://127.0.0.1:' + ldap.port], base_dn: BASE }), writer: () => w } };
  const v = await createIdentityPosture(e.app, { now: () => T, siem: fakeSiem() }).build();
  assert.equal(v.sources.fgpp.state, 'live'); assert.equal(v.fine_grained.items[0].name, 'PSO-Syn'); assert.equal(v.fine_grained.items[0].score, 100);
});
