// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit evidence for the AI auditors (engine/itaudit/routes.js), the Cisco running-config capture (netops/config-audit.js),
// the AD domain password policy read (ad/sync.js policyOf) and redact() keeping audit facts while removing secrets.
// Synthetic data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createState } = require('../engine/soc/state');
const { createIdentity } = require('../engine/ad/identity');
const { policyOf } = require('../engine/ad/sync');
const { redact } = require('../engine/netops/cli');
const { createConfigAudit } = require('../engine/netops/config-audit');
const ita = require('../engine/itaudit/routes');

const DAY = 86400000, T = Date.parse('2026-10-20T08:00:00Z');
function ctxOf(user, role, query, params) {
  const out = { status: 200, body: null }, audits = [];
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  return { user, role, query: query || {}, params: params || {}, out, audits,
    need: (r) => { if ((RANK[role] || 0) < RANK[r]) { out.status = 403; return false; } return true; },
    ok: (j) => { out.body = j; return j; }, fail: (code, msg) => { out.status = code; out.body = { error: msg }; return out.body; },
    audit: (action, target, detail) => audits.push({ action, target, detail }) };
}
async function call(h, ctx) { const r = await h(ctx); if (ctx.out.body === null && r !== undefined) ctx.out.body = r; return ctx; }

test('redact: secrets removed, the hash type and password-encryption kept (they are the audit facts)', () => {
  const r = redact('service password-encryption\nenable secret 9 $9$synthetic\nenable password 7 0822455D0A16\nusername test-admin privilege 15 secret 5 $1$synthetic\nusername test-op password plain\nsnmp-server community synthetic RO 10\npassword encryption aes');
  assert.match(r, /^service password-encryption$/m);
  assert.match(r, /^enable secret 9 <removed>$/m);
  assert.match(r, /^enable password 7 <removed>$/m);
  assert.match(r, /secret 5 <removed>$/m);
  assert.match(r, /^username test-op password <removed>$/m);
  assert.match(r, /^snmp-server community <removed> RO 10$/m);
  assert.match(r, /^password encryption aes$/m);
  assert.doesNotMatch(r, /synthetic|0822455D|plain/);
});

test('AD domain policy: 100-ns intervals → days / minutes, complexity bit, never = 0', () => {
  const v = { minPwdLength: '7', pwdHistoryLength: '24', maxPwdAge: '-36288000000000', minPwdAge: '-864000000000', pwdProperties: '1', lockoutThreshold: '0', lockoutDuration: '-18000000000', lockOutObservationWindow: '-18000000000', 'msDS-Behavior-Version': '7' };
  const p = policyOf((n) => v[n]);
  assert.deepEqual(p, { min_length: 7, history: 24, max_age_days: 42, min_age_days: 1, complexity: true, reversible: false, lockout_threshold: 0, lockout_minutes: 30, lockout_window_minutes: 30, functional_level: 7 });
  assert.equal(policyOf((n) => (n === 'maxPwdAge' ? '-9223372036854775808' : undefined)).max_age_days, 0, 'never expires');
  assert.equal(policyOf(() => undefined).min_length, null, 'not readable stays null, never a default');
});

test('config capture: Cisco only, needs SSH + trusted host key, keeps the previous copy on failure', async () => {
  const state = createState({ dir: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-ita-')), 'state') });
  const devs = [{ id: 'sw1', name: 'SW-TEST-1', vendor: 'cisco-ios' }, { id: 'sw2', name: 'SW-TEST-2', vendor: 'cisco-ios' }, { id: 'fw1', name: 'FW-TEST', vendor: 'fortigate' }];
  let fail = false; const ran = [];
  const cli = { supported: (v) => v === 'cisco-ios', hostKey: (id) => (id === 'sw1' ? { fingerprint: 'x' } : null),
    run: async (id, cmds, o) => { ran.push([id, cmds, o.by]); if (fail) throw new Error('SSH session failed'); return { results: [{ command: cmds[0], output: 'hostname SW-TEST-1\nservice password-encryption\n' }] }; } };
  const inventory = { list: () => devs, credentialSummary: (id) => ({ ssh: id === 'sw1' || id === 'sw2' ? 'user x' : null }) };
  let t = T; const ca = createConfigAudit({ inventory, cli, state, now: () => t });
  assert.deepEqual(await ca.run(), { read: 1, failed: 0, skipped: 1 });
  assert.deepEqual(ran, [['sw1', ['show running-config'], 'system:it-auditor']]);
  const c = ca.get('sw1'); assert.match(c.text, /password-encryption/); assert.equal(c.sha256.length, 64); assert.equal(c.at, T);
  assert.match(ca.get('sw2').error, /no SSH login or trusted host key/);
  assert.equal(ca.get('fw1'), null, 'not a Cisco device');
  assert.deepEqual(await ca.run(), { read: 0, failed: 0, skipped: 2 }, 'read once a day');
  t = T + 2 * DAY; fail = true;
  assert.deepEqual(await ca.run(), { read: 0, failed: 1, skipped: 1 });
  const c2 = ca.get('sw1'); assert.equal(c2.at, T, 'previous capture kept'); assert.match(c2.error, /SSH session failed/); assert.equal(c2.text, c.text);
});

test('evidence routes: analyst and above, validated, audited; not configured says so', async () => {
  const id = createIdentity({ now: () => T });
  id.replace({ synced: T, server: 'ldaps://dc.test', dnsDomain: 'example.test', policy: { min_length: 8 },
    users: [{ sam: 'test-admin', name: 'Test Admin', uac: 0x200 | 0x10000, privileged: true, priv_groups: ['Domain Admins'], last_logon: T - DAY, pwd_last_set: T - 400 * DAY },
      { sam: 'test-user', name: 'Test User', uac: 0x200 | 0x400000, last_logon: T - 200 * DAY, pwd_last_set: T - 10 * DAY, mail: 'x@example.test' }],
    groups: [{ sam: 'Domain Admins', privileged: true, members: [{ sam: 'test-admin' }] }] });
  const caps = new Map([['sw1', { id: 'sw1', name: 'SW-TEST-1', vendor: 'cisco-ios', at: T, checked: T, sha256: 'a'.repeat(64), text: 'hostname SW-TEST-1' }]]);
  const N = { inventory: { list: () => [{ id: 'sw1', name: 'SW-TEST-1', vendor: 'cisco-ios', ip: '192.0.2.10', cli_facts: { version: '15.2(7)E' } }], credentialSummary: () => ({ snmp: 'v2c', api: null, ssh: 'user audit-ro' }) },
    poller: { snapshot: () => ({ at: T, errors: [], security: { at: T, items: [{ kind: 'snmp-v2c', severity: 'medium', key: 'snmp', title: 'SNMP v2c', evidence: [], rec: 'v3' }], errors: [] } }) },
    configAudit: { list: () => [...caps.values()], get: (k) => caps.get(k) || null } };
  let reported = 0;
  const deps = { identity: id, netopsInstance: N, config: {}, log: { error() {} },
    oracle_audit_report: { report: async (q) => { reported = q.hours; return { available: true, total: 3, findings: [] }; } },
    appAuditInstance: { list: async () => ({ applications: [{ key: 'b', name: 'B app', critical: false }, { key: 'a', name: 'A app', critical: true }] }), report: async (q) => { if (q.app === 'b') throw new Error('synthetic failure'); return { application: { key: q.app, name: 'A app', critical: true }, findings: [] }; } } };
  const routes = {}; ita.register({ route: (m, p, h) => { routes[m + ' ' + p] = h; } }, deps);
  const P = '/api/soc/audit/evidence';
  let c = await call(routes['GET ' + P + '/ad'], ctxOf('viewer1', 'viewer')); assert.equal(c.out.status, 403, 'a viewer may not read named accounts');
  c = await call(routes['GET ' + P + '/ad'], ctxOf('system:itam-auditor', 'analyst'));
  assert.equal(c.out.status, 200); const ad = c.out.body;
  assert.equal(ad.available, true); assert.equal(ad.users.length, 2); assert.deepEqual(ad.policy, { min_length: 8 });
  const u = ad.users.find((x) => x.sam === 'test-user'); assert.equal(u.no_preauth, true); assert.equal(u.dormant, true); assert.equal(u.mail, undefined, 'only audit fields leave the SIEM');
  assert.deepEqual(ad.groups, [{ name: 'Domain Admins', members: [{ sam: 'test-admin', nested: false }] }]);
  assert.deepEqual(c.audits, [{ action: 'audit.evidence.read', target: 'ad', detail: { users: 2 } }]);

  c = await call(routes['GET ' + P + '/network'], ctxOf('system:itam-auditor', 'analyst'));
  const d = c.out.body.devices[0]; assert.equal(d.os_version, '15.2(7)E'); assert.equal(d.monitoring.ssh, 'set'); assert.equal(d.security[0].kind, 'snmp-v2c'); assert.equal(d.config.sha256.length, 64); assert.equal(d.config.text, undefined);
  c = await call(routes['GET ' + P + '/network/config/:id'], ctxOf('system:itam-auditor', 'analyst', {}, { id: 'sw1' })); assert.equal(c.out.body.text, 'hostname SW-TEST-1'); assert.equal(c.audits[0].target, 'config:sw1');
  c = await call(routes['GET ' + P + '/network/config/:id'], ctxOf('system:itam-auditor', 'analyst', {}, { id: '../x' })); assert.equal(c.out.status, 400); assert.match(c.out.body.error, /device is not a valid id/);

  c = await call(routes['GET ' + P + '/database'], ctxOf('system:itam-auditor', 'analyst', { hours: '720' })); assert.equal(reported, 720); assert.equal(c.audits[0].detail.events, 3);
  c = await call(routes['GET ' + P + '/database'], ctxOf('system:itam-auditor', 'analyst', { hours: '9999' })); assert.equal(c.out.status, 400); assert.match(c.out.body.error, /hours/);
  c = await call(routes['GET ' + P + '/applications'], ctxOf('system:itam-auditor', 'analyst'));
  assert.deepEqual(c.out.body.applications.map((a) => a.application.key), ['a', 'b'], 'critical applications first');
  assert.match(c.out.body.applications[1].error, /synthetic failure/);

  const r0 = {}; ita.register({ route: (m, p, h) => { r0[m + ' ' + p] = h; } }, { config: {}, log: { error() {} } });
  c = await call(r0['GET ' + P + '/ad'], ctxOf('a', 'analyst')); assert.equal(c.out.body.available, false); assert.match(c.out.body.reason, /not configured/);
  c = await call(r0['GET ' + P + '/network'], ctxOf('a', 'analyst')); assert.equal(c.out.body.available, false);
});

test('config capture: volatile lines do not count as a change; a real change is kept in the history', async () => {
  const { normalise } = require('../engine/netops/config-audit');
  assert.equal(normalise('Building configuration...\nCurrent configuration : 1234 bytes\n! Last configuration change at 10:00\nntp clock-period 36028\nhostname X\n'), 'hostname X');
  const state = createState({ dir: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-ita2-')), 'state') });
  let out = '! Last configuration change at 10:00\nhostname SW-TEST-1\nntp clock-period 1\n';
  const cli = { supported: () => true, hostKey: () => ({ fingerprint: 'x' }), run: async () => ({ results: [{ output: out }] }) };
  const inventory = { list: () => [{ id: 'sw1', name: 'SW-TEST-1', vendor: 'cisco-ios' }], credentialSummary: () => ({ ssh: 'user x' }) };
  let t = T; const ca = createConfigAudit({ inventory, cli, state, now: () => t });
  await ca.run(); t += 2 * DAY; out = '! Last configuration change at 11:00\nhostname SW-TEST-1\nntp clock-period 2\n'; await ca.run();
  assert.equal(ca.get('sw1').history.length, 1, 'only volatile lines moved: no change');
  t += 2 * DAY; out = 'hostname SW-TEST-1\nip http server\n'; await ca.run();
  const h = ca.get('sw1').history; assert.equal(h.length, 2); assert.equal(h[1].first_seen, t); assert.equal(h[1].previous_read, T + 2 * DAY);
});

test('platform and Microsoft 365 evidence: retention, oldest event, MFA / guests / Intune as synced; viewer refused', async () => {
  const ch = { query: async (sql) => { assert.match(sql, /system\.parts/); return [{ table: 'events', oldest: Date.parse('2025-11-02T00:00:00Z') / 1000 }]; } };
  const G = { data: () => ({ updated: '2026-10-20T07:00:00Z', blocks: { mfa: { ok: true } }, users: { list: [{ name: 'Guest Synthetic', upn: 'g#EXT#@example.test', enabled: true, guest: true, lic: 0, created: '2025-01-01T00:00:00Z', last: null }] },
    intuneOk: true, intune: [{ name: 'LT-SYN-1', upn: 'a@example.test', os: 'Windows 11', compliance: 'noncompliant', lastSync: '2026-10-19T00:00:00Z' }],
    security: { mfa: { ok: true, data: { users: 10, registered: 9, notRegistered: [{ name: 'A', upn: 'a@example.test', admin: true }] } }, conditionalAccess: { ok: false, perm: 'Policy.Read.All' }, riskyUsers: { ok: true, data: [] } } }) };
  const deps = { ch, m365Graph: G, config: { retention_days: 365, compliance: { sama: { required_retention_days: 365 } } }, log: { error() {} } };
  const routes = {}; ita.register({ route: (m, p, h) => { routes[m + ' ' + p] = h; } }, deps);
  let c = await call(routes['GET /api/soc/audit/evidence/platform'], ctxOf('system:itam-auditor', 'analyst'));
  assert.deepEqual([c.out.body.retention_days, c.out.body.required_retention_days, c.out.body.oldest_event], [365, 365, '2025-11-02T00:00:00.000Z']);
  c = await call(routes['GET /api/soc/audit/evidence/m365'], ctxOf('viewer', 'viewer')); assert.equal(c.out.status, 403);
  c = await call(routes['GET /api/soc/audit/evidence/m365'], ctxOf('system:itam-auditor', 'analyst'));
  const m = c.out.body; assert.equal(m.mfa.notRegistered[0].admin, true); assert.equal(m.conditional_access, null, 'a block not granted is null, never empty');
  assert.equal(m.users[0].guest, true); assert.equal(m.intune[0].compliance, 'noncompliant'); assert.deepEqual(c.audits[0], { action: 'audit.evidence.read', target: 'm365', detail: { users: 1 } });
  const r0 = {}; ita.register({ route: (mm, p, h) => { r0[mm + ' ' + p] = h; } }, { config: {}, log: { error() {} } });
  c = await call(r0['GET /api/soc/audit/evidence/m365'], ctxOf('a', 'analyst')); assert.equal(c.out.body.available, false);
  c = await call(r0['GET /api/soc/audit/evidence/platform'], ctxOf('a', 'analyst')); assert.match(c.out.body.oldest_error, /not available/);
});
