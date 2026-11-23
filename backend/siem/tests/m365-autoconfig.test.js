// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Microsoft Security - Auto-Configuration (engine/collect/m365-autoconfig.js; the token roles read in m365-graph.js): which Graph
// application permissions are granted - exactly from the token's roles claim, else from each dataset's answer (403 = not granted,
// unknown stays unknown); the steps; the admin-consent link from validated IDs only; a grant script for ONLY the missing
// permissions; the hardening checks from the Microsoft 365 Security analysis; Conditional Access templates refused until a
// break-glass account is recorded, then always report-only and excluding it; the AI plan (operator, steps verified against what the
// tools returned); roles incl. the refused cases, validation errors naming the field, and the audit records. SYNTHETIC tenant only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createState } = require('../engine/soc/state');
const AC = require('../engine/collect/m365-autoconfig');
const { createGraph, PERMS } = require('../engine/collect/m365-graph');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const TEN = '11111111-2222-3333-4444-555555555555', CID = '66666666-7777-8888-9999-000000000000', BG = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const T = Date.parse('2026-11-14T08:00:00Z'), D = 86400000, iso = (ms) => new Date(T - ms).toISOString();
function cfg(sec, extra) { const c = Object.assign({ m365: {}, soc_analyst: {}, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } }, extra || {}); Object.defineProperty(c, 'secrets', { value: { m365: sec, netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, writable: true }); return c; }
const ok = (data) => ({ ok: true, data });
function snap(caName) {
  return { configured: true, updated: iso(0), blocks: { secureScore: { ok: true }, mfa: { ok: true }, riskyUsers: { ok: false, perm: 'IdentityRiskyUser.Read.All', error: 'permission not granted' }, conditionalAccess: { ok: true }, defenderAlerts: { ok: true }, signins: { ok: true }, users: { ok: true } },
    signins: [], security: {
      secureScore: ok({ current: 41.5, max: 100, lowest: [{ name: 'BlockLegacyAuthentication', cat: 'Identity', score: 0 }] }),
      mfa: ok({ users: 50, registered: 45, notRegistered: [{ name: 'Admin Syn', upn: 'admin.syn@as.test', admin: true }, { name: 'X', upn: 'x.syn@as.test' }] }),
      riskyUsers: { ok: false }, riskDetections: { ok: false },
      conditionalAccess: ok([{ name: caName || 'Require MFA for administrators', state: 'enabledForReportingButNotEnforced', modified: iso(60 * D) }, { name: 'Block legacy authentication', state: 'disabled', modified: iso(2 * D) }]),
      defenderAlerts: ok([]) } };
}
function world(o = {}) {
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), script = [];
  const status = { enabled: true, ready: true, missing: [], blocks: snap().blocks, last_error: '', granted: o.granted === undefined ? { roles: Object.values(PERMS).join(' + ').split(' + ').filter((p) => p !== 'Policy.Read.All' && p !== 'IdentityRiskEvent.Read.All'), at: T } : o.granted };
  const graph = { status: () => status, data: () => snap(o.caName), PERMS };
  class FakeAnthropic { constructor() { this.messages = { create: async () => { const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const deps = { state, m365Graph: graph, config: cfg({ tenant: TEN, client_id: CID, client_secret: 'very-secret-synthetic' }), log: quietLog, now: () => T, sdk: FakeAnthropic };
  const api = fakeApi({ realRanks: true }); AC.register(api, deps);
  return { api, state, status, script, call: (m, p, x) => api.call(m, '/api/soc' + p, x), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('readiness: permissions from the token roles (exact), the consent link, a script for only what is missing', async () => {
  const w = world(); try {
    const r = (await w.call('GET', '/m365/autoconfig', { role: 'analyst' })).body.readiness;
    assert.equal(r.granted_source, 'token');
    assert.deepEqual(r.missing.sort(), ['IdentityRiskEvent.Read.All', 'Policy.Read.All']);
    assert.equal(r.permissions.find((p) => p.permission === 'User.Read.All').granted, true);
    assert.ok(r.permissions.find((p) => p.permission === 'Policy.Read.All').enables.includes('Conditional Access policies'));
    assert.equal(r.consent_url, 'https://login.microsoftonline.com/' + TEN + '/adminconsent?client_id=' + CID);
    assert.deepEqual(r.steps.map((s) => [s.id, s.state]), [['app', 'done'], ['signin', 'done'], ['consent', 'partial'], ['data', 'partial']]);
    assert.ok(!JSON.stringify(r).includes('very-secret'), 'the secret never leaves');
    assert.equal((await w.call('GET', '/m365/autoconfig/script', { role: 'operator' })).status, 403);
    const s = await w.call('GET', '/m365/autoconfig/script', { role: 'admin', user: 'syed' }); assert.equal(s.status, 200);
    assert.match(s.body.script, /\$want = @\('IdentityRiskEvent\.Read\.All', 'Policy\.Read\.All'\)|\$want = @\('Policy\.Read\.All', 'IdentityRiskEvent\.Read\.All'\)/);
    assert.ok(s.body.script.includes("appId eq '" + CID + "'") && !/User\.Read\.All/.test(s.body.script), 'only the missing permissions, looked up by name');
    assert.ok(w.api.audits.some((a) => a.action === 'm365.autoconfig.script' && a.detail.missing.length === 2));
    // datasets fallback when the token carries no roles; an unread dataset stays unknown
    w.status.granted = { roles: null, at: T };
    const r2 = (await w.call('GET', '/m365/autoconfig', { role: 'analyst' })).body.readiness;
    assert.equal(r2.granted_source, 'datasets'); assert.equal(r2.permissions.find((p) => p.permission === 'IdentityRiskyUser.Read.All').granted, false);
    assert.equal(r2.permissions.find((p) => p.permission === 'SecurityEvents.Read.All').granted, true); assert.equal(r2.permissions.find((p) => p.permission === 'Application.Read.All').granted, null);
    assert.equal((await w.call('GET', '/m365/autoconfig', { role: 'viewer' })).status, 403);
  } finally { w.cleanup(); }
});

test('the consent link is built only from valid IDs; an unset app says what to enter', () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  try {
    const graph = { status: () => ({ blocks: {} }), data: () => ({ configured: false }), PERMS };
    const A = AC.createAutoConfig({ state, m365Graph: graph, config: cfg({ tenant: 'evil"/><script>', client_id: 'x' }), log: quietLog, now: () => T });
    const r = A.readiness(); assert.equal(r.consent_url, null); assert.equal(r.steps[0].state, 'todo'); assert.match(r.steps[0].detail, /tenant ID missing/);
    assert.equal(AC.grantScript('not-a-guid', ['Policy.Read.All']), null);
    assert.equal(A.hardening().configured, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('hardening checks, break-glass first, then report-only templates that exclude it; validated and audited', async () => {
  const w = world(); try {
    const h = (await w.call('GET', '/m365/autoconfig', { role: 'analyst' })).body.hardening;
    const c = (id) => h.checks.find((x) => x.id === id);
    assert.equal(c('ca-admins-mfa').state, 'warn'); assert.match(c('ca-admins-mfa').detail, /report-only/);
    assert.equal(c('ca-legacy').state, 'fail'); assert.deepEqual(c('ca-legacy').fix.templates, ['legacy']);
    assert.deepEqual(c('ca-risk').fix.templates, ['signin-risk', 'user-risk']); assert.match(c('ca-location').fix.note, /named location/);
    assert.equal(c('mfa-admins').state, 'fail'); assert.equal(c('mfa-all').state, 'warn'); assert.equal(c('score').state, 'warn'); assert.equal(c('ca-stale').state, 'warn');
    // templates refused until a break-glass account is recorded
    let r = await w.call('GET', '/m365/autoconfig/template/legacy', { role: 'admin' }); assert.equal(r.status, 409); assert.match(r.body.error, /break-glass/);
    assert.equal((await w.call('POST', '/m365/autoconfig/breakglass', { role: 'operator', body: { accounts: [{ id: BG, label: 'BG1' }] } })).status, 403, 'security-integration settings are admin-only');
    r = await w.call('POST', '/m365/autoconfig/breakglass', { role: 'admin', body: { accounts: [{ id: 'breakglass@as.test', label: 'BG1' }] } }); assert.equal(r.status, 400); assert.match(r.body.error, /accounts\[0\]\.id must be the account's object ID/);
    r = await w.call('POST', '/m365/autoconfig/breakglass', { role: 'admin', body: { accounts: [{ id: BG, label: 'BG1' }, { id: BG.toUpperCase(), label: 'BG2' }] } }); assert.equal(r.status, 400); assert.match(r.body.error, /listed twice/);
    r = await w.call('POST', '/m365/autoconfig/breakglass', { role: 'admin', body: { accounts: [] } }); assert.equal(r.status, 400);
    r = await w.call('POST', '/m365/autoconfig/breakglass', { role: 'admin', user: 'syed', body: { accounts: [{ id: BG, label: 'Emergency access 1 (synthetic)', role: 'admin' }] } }); assert.equal(r.status, 200);
    assert.deepEqual(Object.keys(r.body.accounts[0]).sort(), ['id', 'label'], 'undeclared fields are dropped');
    assert.ok(w.api.audits.some((a) => a.action === 'm365.autoconfig.breakglass' && a.user === 'syed'));
    assert.equal((await w.call('GET', '/m365/autoconfig/template/legacy', { role: 'operator' })).status, 403);
    for (const id of Object.keys(AC.TEMPLATES)) {
      const t = (await w.call('GET', '/m365/autoconfig/template/' + id, { role: 'admin', user: 'syed' })).body;
      assert.equal(t.policy.state, 'enabledForReportingButNotEnforced', id + ' is report-only'); assert.deepEqual(t.policy.conditions.users.excludeUsers, [BG], id + ' excludes the break-glass account');
      assert.match(t.import, /New-MgIdentityConditionalAccessPolicy/);
    }
    const adm = (await w.call('GET', '/m365/autoconfig/template/admins-mfa', { role: 'admin' })).body; assert.ok(adm.roles.some((x) => x.name === 'Global Administrator' && x.id === '62e90394-69f5-4237-9190-012177145e10'));
    assert.equal((await w.call('GET', '/m365/autoconfig/template/nope', { role: 'admin' })).status, 404);
    assert.equal((await w.call('GET', '/m365/autoconfig/template/' + encodeURIComponent('a b'), { role: 'admin' })).status, 400);
    assert.ok(w.api.audits.some((a) => a.action === 'm365.autoconfig.template' && a.target === 'legacy'));
  } finally { w.cleanup(); }
});

test('AI plan: operator only, read-only tools, steps verified against what the tools returned, audited', async () => {
  const w = world(); try {
    assert.equal((await w.call('POST', '/m365/autoconfig/plan', { role: 'analyst', body: {} })).status, 403);
    const use = (id, name, input) => ({ type: 'tool_use', id, name, input }), turn = (content) => ({ content, stop_reason: 'tool_use', usage: { input_tokens: 40, output_tokens: 10 } });
    w.script.push(turn([use('a', 'readiness', {}), use('b', 'hardening', {}), use('c', 'templates', {})]),
      turn([use('d', 'submit_plan', { summary: 'Finish consent, then close the legacy authentication gap.', steps: [
        { title: 'Grant Policy.Read.All', why: 'Conditional Access cannot be read otherwise', how: 'Run the generated script', ref: 'Policy.Read.All' },
        { title: 'Record break-glass accounts', why: 'before any policy', how: 'Auto-Configuration -> Break-glass', ref: 'legacy' },
        { title: 'Delete all users', why: 'invented', how: 'n/a', ref: 'ca-delete-everything' }] })]));
    let r = await w.call('POST', '/m365/autoconfig/plan', { role: 'operator', user: 'nora.syn', body: { focus: 'legacy authentication', extra: 1 } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.steps.map((s) => s.verified), [true, true, false], 'a step citing something no tool returned is unverified');
    assert.equal(r.body.unverified, 1);
    assert.ok(w.api.audits.some((a) => a.action === 'm365.autoconfig.plan' && a.detail.unverified === 1));
    const v = (await w.call('GET', '/m365/autoconfig', { role: 'analyst' })).body; assert.equal(v.plan.asked_by, 'nora.syn');
    r = await w.call('POST', '/m365/autoconfig/plan', { role: 'operator', body: { focus: 'x'.repeat(1001) } }); assert.equal(r.status, 400); assert.match(r.body.error, /focus/);
  } finally { w.cleanup(); }
});

test('the Graph collector reads the granted permissions from the token roles and never keeps the token', async () => {
  const jwt = (p) => 'h.' + Buffer.from(JSON.stringify(p)).toString('base64url') + '.s';
  const c = { m365: {} }; Object.defineProperty(c, 'secrets', { value: { m365: { tenant: TEN, client_id: CID, client_secret: 'very-secret-synthetic' } } });
  const R = (status, j) => ({ status, ok: status < 300, json: async () => j, headers: { get: () => null }, arrayBuffer: async () => Buffer.from(JSON.stringify(j)) });
  const f = async (url) => (url.includes('/oauth2/v2.0/token') ? R(200, { access_token: jwt({ roles: ['User.Read.All', 'Policy.Read.All'] }), expires_in: 3600 }) : R(403, { error: { code: 'Forbidden' } }));
  const g = createGraph({ config: c, fetchImpl: f, now: () => T });
  await g.syncNow().catch(() => null /* every dataset refused - only the sign-in matters here */);
  const st = g.status(); assert.deepEqual(st.granted.roles, ['Policy.Read.All', 'User.Read.All']);
  assert.ok(!JSON.stringify(st).includes(jwt({ roles: ['User.Read.All', 'Policy.Read.All'] })) && !JSON.stringify(st).includes('very-secret'), 'neither the token nor the secret is in the status');
});
