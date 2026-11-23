// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/util/brand');
// Cloudflare: parser (audit + security events), pull collector (cursor, pagination, GraphQL per zone, errors), settings routes.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const P = require('../engine/parse');
const cf = require('../engine/collect/cloudflare');

const ACCT = 'a'.repeat(32), ZONE = 'b'.repeat(32);

test('parser: audit log and WAF / security events', () => {
  const a = P.parse('', { src_type: 'cloudflare', obj: { _cf: 'audit', id: '1', when: '2026-10-11T09:00:00Z', action: { type: 'token_create', result: true }, actor: { email: 'Admin@Example.com', ip: '198.51.100.4', type: 'user' }, resource: { type: 'api_token', id: 't1' } } });
  assert.equal(a.src_type, 'cloudflare'); assert.equal(a.user, 'admin@example.com'); assert.equal(a.src_ip, '198.51.100.4'); assert.equal(a.category, 'cloud'); assert.ok(a.tags.includes('config-change'));
  const s = P.parse('', { src_type: 'cloudflare', obj: { _cf: 'security', datetime: '2026-10-11T10:00:00Z', action: 'block', clientIP: '203.0.113.9', clientCountryName: 'XX', clientRequestHTTPHost: 'claims.example.com', clientRequestPath: '/login', clientRequestHTTPMethodName: 'post', source: 'waf', ruleId: 'r1', rayName: '8d1' } });
  assert.deepEqual([s.category, s.action, s.outcome, s.src_ip, s.url, s.http_method, s.severity], ['web', 'block', 'failure', '203.0.113.9', 'https://claims.example.com/login', 'POST', 2]);
  assert.equal(s.fields.rule_id, 'r1'); assert.equal(s.fields.country, 'XX');
});

test('collector: audit pagination + cursor, security events per zone, token never logged, errors reported', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-')), events = [], calls = [];
  const audit = Array.from({ length: 1000 }, (_, i) => ({ id: 'a' + i, when: `2026-10-11T08:${String(Math.floor(i / 60)).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}Z`, action: { type: 'dns_record_update', result: true }, actor: { email: 'x@y.z', type: 'user' }, resource: { type: 'dns_record', id: 'r' } }));
  const fetchImpl = async (url, o) => {
    calls.push([url, o && o.method, o && o.headers.Authorization]);
    if (url.includes('/audit_logs')) { const page = Number(new URL(url).searchParams.get('page')); return { status: 200, ok: true, json: async () => ({ success: true, result: page === 1 ? audit : [{ id: 'last', when: '2026-10-11T09:30:00Z', action: { type: 'login', result: false }, actor: { email: 'x@y.z' }, resource: { type: 'account' } }] }) }; }
    if (url.endsWith('/graphql')) { const b = JSON.parse(o.body); assert.equal(b.variables.zone, ZONE); return { status: 200, ok: true, json: async () => ({ data: { viewer: { zones: [{ firewallEventsAdaptive: [{ datetime: '2026-10-11T09:40:00Z', action: 'managed_challenge', clientIP: '203.0.113.7', rayName: 'r', clientRequestHTTPHost: 'h.example.com', clientRequestPath: '/' }] }] } } }) }; }
    return { status: 404, ok: false, json: async () => ({}) };
  };
  const config = { cloudflare: { enabled: true, account_id: ACCT, zones: [ZONE] } }; Object.defineProperty(config, 'secrets', { value: { cloudflare: { api_token: 'cf-secret-token' } } });
  const logs = []; const log = { info: (m, f) => logs.push([m, f]), warn: (m, f) => logs.push([m, f]), error: (m, f) => logs.push([m, f]) };
  const c = cf.start({ config, parser: P, pipeline: { emit: (e) => events.push(e) }, log, stateDir: dir, fetchImpl, autoStart: false, now: () => Date.parse('2026-10-11T10:00:00Z') });
  await c.pollNow();
  const st = c.stats(); assert.equal(st.audit, 1001); assert.equal(st.security, 1); assert.equal(st.last_error, '');
  assert.ok(calls.every((x) => x[2] === 'Bearer cf-secret-token')); assert.ok(!JSON.stringify(logs).includes('cf-secret-token'));
  assert.ok(events.some((e) => e.action === 'login' && e.outcome === 'failure'));
  const cur = JSON.parse(fs.readFileSync(path.join(dir, 'cloudflare-cursor.json'), 'utf8')); assert.equal(cur.audit, '2026-10-11T09:30:00Z'); assert.equal(cur['sec:' + ZONE], '2026-10-11T09:40:00Z');
  // second poll starts from the cursor: nothing re-emitted
  calls.length = 0; await c.pollNow(); assert.ok(calls[0][0].includes('since=2026-10-11T09%3A30%3A00Z')); assert.equal(c.stats().audit, 1001);
  // token without permission
  const c2 = cf.start({ config, parser: P, pipeline: { emit() {} }, log, stateDir: '', autoStart: false, fetchImpl: async () => ({ status: 403, ok: false, json: async () => ({ success: false, errors: [{ code: 10000, message: 'Authentication error' }] }) }) });
  await c2.pollNow(); assert.match(c2.stats().last_error, /permission missing/);
  // misconfigured: not started, says why
  assert.match(cf.start({ config: { cloudflare: { enabled: true } }, parser: P, pipeline: {} }).stats().error, /api_token missing/);
});

test('settings routes: validation, write-only token, files written, collector reloaded, token test', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cfr-')), cfgFile = path.join(dir, 'config.json'), secFile = path.join(dir, 'secrets.json');
  fs.writeFileSync(cfgFile, '{"api":{"port":9120}}'); fs.writeFileSync(secFile, '{}');
  const config = {}; Object.defineProperty(config, '_paths', { value: { config: cfgFile, secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  let reloads = 0;
  const cloudFetch = async (u, o) => { const t = o.headers.Authorization; if (u.endsWith('/user/tokens/verify')) return { status: t === 'Bearer good' ? 200 : 401, json: async () => (t === 'Bearer good' ? { result: { status: 'active' } } : { errors: [{ message: 'Invalid API Token' }] }) }; if (u.includes('/zones')) return { status: 200, json: async () => ({ result: [{ id: ZONE, name: ZYB_ORG.domain }] }) }; return { status: 200, json: async () => ({ result: [] }) }; };
  const R = {}; require('../engine/collect/cloud-routes').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config, log: { error() {} }, cloudFetch, reloadCloudflare: async () => { reloads++; }, cloudflareStats: () => ({ polls: 0 }) });
  const call = async (m, p, b) => { const o = {}; const ctx = { role: 'admin', user: 'adm', body: b, params: {}, need: () => true, audit() {}, ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }; const rv = await R[m + ' /api/soc' + p](ctx); if (rv !== undefined && !o.s) { o.s = 200; o.b = rv; } return o; };
  assert.equal((await call('PUT', '/cloud/cloudflare', { enabled: true, account_id: ACCT })).s, 400, 'token required to enable');
  assert.equal((await call('PUT', '/cloud/cloudflare', { account_id: 'nope' })).s, 400);
  assert.equal((await call('PUT', '/cloud/cloudflare', { zones: ZYB_ORG.domain })).s, 400, 'a domain name needs the token to be looked up');
  assert.equal((await call('PUT', '/cloud/cloudflare', { zones: 'not a zone!' })).s, 400, 'neither a domain nor an ID');
  const r = await call('PUT', '/cloud/cloudflare', { enabled: true, account_id: ACCT, zones: ZONE, api_token: 'good' });
  assert.equal(r.s, 200, r.e); assert.equal(r.b.token_set, true); assert.equal(r.b.applied, true); assert.equal(reloads, 1); assert.ok(!JSON.stringify(r.b).includes('good'));
  assert.equal(JSON.parse(fs.readFileSync(secFile, 'utf8')).cloudflare.api_token, 'good'); assert.equal(JSON.parse(fs.readFileSync(cfgFile, 'utf8')).cloudflare.zones[0], ZONE); assert.ok(!fs.readFileSync(cfgFile, 'utf8').includes('good'));
  const t1 = await call('POST', '/cloud/cloudflare/test', {}); assert.equal(t1.b.ok, true); assert.match(t1.b.steps[1].text, new RegExp(ZYB_ORG.domain_re));
  // engineers know the domain, not the zone ID: a name is looked up with the token; an unknown one is refused, named
  const byName = await call('PUT', '/cloud/cloudflare', { zones: 'https://' + ZYB_ORG.domain.toUpperCase() + '/' }); assert.equal(byName.s, 200, byName.e); assert.deepEqual(byName.b.zones, [ZONE]);
  const unknown = await call('PUT', '/cloud/cloudflare', { zones: 'other.example' }); assert.equal(unknown.s, 400); assert.match(unknown.e, /other\.example is not a zone this token can read/);
  const t2 = await call('POST', '/cloud/cloudflare/test', { api_token: 'bad' }); assert.equal(t2.b.ok, false); assert.match(t2.b.steps[0].text, /Invalid API Token/);
});

test('diagnose: each step with its fix - Global API Key, egress, token, zones, security events, audit log, collector', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cfd-')), cfgFile = path.join(dir, 'config.json'), secFile = path.join(dir, 'secrets.json');
  fs.writeFileSync(cfgFile, '{}'); fs.writeFileSync(secFile, '{}');
  const mk = (cloudflare, token, cloudFetch, stats) => {
    const config = { cloudflare }; Object.defineProperty(config, '_paths', { value: { config: cfgFile, secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: { cloudflare: { api_token: token } }, writable: true });
    const R = {}, audits = []; require('../engine/collect/cloud-routes').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config, log: { error() {} }, cloudFetch, cloudflareStats: () => stats || { enabled: true, polls: 3, records: 12, last_poll_at: '2026-10-29T08:00:00Z' }, audit: (x) => audits.push(x) });
    return async (role = 'admin') => { const o = {}; const ctx = { role, user: 'adm', body: {}, params: {}, need: () => true, audit() {}, ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }; const rv = await R['POST /api/soc/cloud/cloudflare/diagnose'](ctx); if (rv !== undefined && !o.s) { o.s = 200; o.b = rv; } return o; };
  };
  const good = async (u, o) => {
    if (u.endsWith('/user/tokens/verify')) return { status: 200, json: async () => ({ result: { status: 'active' } }) };
    if (u.includes('/zones')) return { status: 200, json: async () => ({ result: [{ id: ZONE, name: ZYB_ORG.domain }] }) };
    if (u.endsWith('/graphql')) { assert.equal(o.method, 'POST'); assert.match(o.body, /firewallEventsAdaptive/); assert.doesNotMatch(o.body, /mutation/); return { status: 200, json: async () => ({ data: { viewer: { zones: [{ firewallEventsAdaptive: [{ datetime: 'x' }] }] } } }) }; }
    if (u.includes('/audit_logs')) return { status: 200, json: async () => ({ result: [] }) };
    return { status: 404, json: async () => ({}) };
  };
  const step = (r, n) => r.b.steps.find((x) => x.step === n || x.step.startsWith(n));
  let r = await mk({ enabled: true, account_id: ACCT, zones: [ZONE] }, 'tok-good', good)();
  assert.equal(r.b.ok, true, JSON.stringify(r.b.steps)); assert.deepEqual(r.b.steps.map((x) => x.status), ['ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok']);
  assert.match(step(r, 'Security events').detail, /events in the last hour/); assert.ok(!JSON.stringify(r.b).includes('tok-good'), 'the token is never returned');
  r = await mk({ enabled: true, zones: [ZONE] }, 'a'.repeat(37), good)(); assert.equal(step(r, 'Token type').status, 'fail'); assert.match(step(r, 'Token type').fix, /Global API Key/);
  r = await mk({ enabled: true, zones: [ZONE] }, 'tok-good', async () => { throw Object.assign(new Error('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); })();
  assert.equal(step(r, 'Outbound HTTPS').status, 'fail'); assert.match(step(r, 'Outbound HTTPS').fix, /api\.cloudflare\.com:443/);
  r = await mk({ enabled: true, zones: [ZONE] }, 'tok-good', async (u) => (u.endsWith('/verify') ? { status: 401, json: async () => ({ errors: [{ code: 9109, message: 'Cannot use the access token from location: 1.2.3.4' }] }) } : good(u)))();
  assert.equal(step(r, 'API token').status, 'fail'); assert.match(step(r, 'API token').fix, /IP/);
  const OTHER = 'c'.repeat(32);
  r = await mk({ enabled: true, zones: [OTHER] }, 'tok-good', good)(); assert.equal(step(r, 'Zones').status, 'fail'); assert.match(step(r, 'Zones').detail, new RegExp(OTHER));
  r = await mk({ enabled: true, zones: [ZONE] }, 'tok-good', async (u, o) => (u.endsWith('/graphql') ? { status: 200, json: async () => ({ errors: [{ message: 'not authorized for that zone' }] }) } : good(u, o)))();
  assert.equal(step(r, 'Security events').status, 'fail'); assert.match(step(r, 'Security events').fix, /Analytics: Read/);
  r = await mk({ enabled: true, account_id: ACCT, zones: [ZONE] }, 'tok-good', async (u, o) => (u.includes('/audit_logs') ? { status: 403, json: async () => ({ errors: [{ code: 10000, message: 'Authentication error' }] }) } : good(u, o)))();
  assert.equal(step(r, 'Account audit log').status, 'fail'); assert.match(step(r, 'Account audit log').fix, /Account Settings: Read/);
  r = await mk({ enabled: false, zones: [ZONE] }, 'tok-good', good, { enabled: false })(); assert.equal(step(r, 'Settings').status, 'warn'); assert.equal(step(r, 'Collector').status, 'warn');
  r = await mk({ enabled: true, zones: [ZONE] }, '', good)(); assert.equal(r.b.steps[0].status, 'fail'); assert.match(r.b.steps[0].fix, /API Tokens/);
});
