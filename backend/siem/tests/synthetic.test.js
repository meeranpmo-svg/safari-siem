// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Synthetic monitoring + Apdex (engine/netops/synthetic.js, engine/netops/synthetic-routes.js) against LOCAL synthetic web servers:
// the SSRF allow-list (loopback / link-local never, private only when allowed AND listed, every resolved address, redirects
// re-checked), GET / HEAD only (no body, steps only follow links), expected status / text, timings, TLS certificate validity and
// expiry (self-signed test certificate), Apdex classification and the hourly aggregate (uptime, Apdex, p50 / p95), portal Apdex
// from (fake) access-log rows, health by device type, and the routes: roles (viewer / operator / admin, refused), validation
// errors naming the field, the audit record. No real host is contacted.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const cp = require('node:child_process');
const { createState } = require('../engine/soc/state');
const S = require('../engine/netops/synthetic');
const R = require('../engine/netops/synthetic-routes');

const quiet = { info() {}, warn() {}, error() {}, every() {} };
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
const blocked = (msg) => Object.assign(new Error(msg), { status: 403 });

test('allow-list: loopback / link-local never, private only when allowed and listed, public by name or network', () => {
  const st = { allow: ['portal.example.com', '*.corp.example', '10.20.0.0/16', '203.0.113.7'], allow_private: true };
  assert.equal(S.decide('portal.example.com', ['198.51.100.5'], st), '198.51.100.5');
  assert.equal(S.decide('a.corp.example', ['198.51.100.6'], st), '198.51.100.6');
  assert.equal(S.decide('anything.test', ['203.0.113.7'], st), '203.0.113.7', 'a listed IP');
  assert.equal(S.decide('app', ['10.20.3.4'], st), '10.20.3.4', 'private inside a listed network');
  assert.throws(() => S.decide('corp.example', ['198.51.100.6'], st), /not on the allow-list/, '*.corp.example does not cover corp.example itself');
  assert.throws(() => S.decide('evil.test', ['198.51.100.9'], st), (e) => e.status === 403 && /not on the allow-list/.test(e.message));
  for (const a of ['127.0.0.1', '169.254.169.254', '0.0.0.0', '::1', 'fe80::1', '::ffff:127.0.0.1', '224.0.0.1']) assert.throws(() => S.decide('portal.example.com', [a], st), /never allowed/, a);
  assert.throws(() => S.decide('portal.example.com', ['198.51.100.5', '10.99.0.1'], st), /not inside a network/, 'EVERY resolved address must pass');
  assert.throws(() => S.decide('app', ['10.20.3.4'], Object.assign({}, st, { allow_private: false })), /private networks are not allowed/);
  assert.throws(() => S.decide('portal.example.com', ['198.51.100.5'], { allow: [] }), /no allowed hosts/);
  assert.throws(() => S.parseAllow(['http://x/']), /allow\[0\]/); assert.throws(() => S.parseAllow(['10.0.0.0/4']), /allow\[0\]/);
  assert.ok(S.never('169.254.1.1') && S.isPrivate('172.20.1.1') && !S.isPrivate('172.32.0.1') && S.isPrivate('fd00::1'));
});

test('Apdex: satisfied / tolerating / frustrated, score, rating, percentile from the histogram', () => {
  assert.equal(S.classify(true, 400, 500), 's'); assert.equal(S.classify(true, 1900, 500), 't'); assert.equal(S.classify(true, 2100, 500), 'f'); assert.equal(S.classify(false, 10, 500), 'f', 'a failed run is frustrated');
  assert.equal(S.apdex({ n: 100, s: 60, t: 30 }), 0.75); assert.equal(S.apdex({ n: 0 }), null, 'no runs: no score, never 0');
  assert.equal(S.rating(0.95), 'excellent'); assert.equal(S.rating(0.6), 'poor'); assert.equal(S.rating(null), null);
  const h = new Array(S.HIST.length + 1).fill(0); h[S.bucketOf(80)] = 50; h[S.bucketOf(900)] = 45; h[S.bucketOf(4000)] = 5;
  assert.equal(S.pctl(h, 0.5), 100); assert.equal(S.pctl(h, 0.95), 1000); assert.equal(S.pctl([], 0.5), null);
  const st = S.stats({ n: 4, s: 2, t: 1, f: 1, err: 1, ms: 300, ok_n: 3, hist: h });
  assert.equal(st.uptime_pct, 75); assert.equal(st.error_rate_pct, 25); assert.equal(st.avg_ms, 100); assert.equal(st.apdex, 0.63);
});

test('transaction steps: GET only, unknown step fields refused, links found by their text', () => {
  assert.throws(() => S.normSteps([{ url: 'https://a.test/', method: 'POST' }]), /steps\[0\]\.method is not a step field.*GET requests only/);
  assert.throws(() => S.normSteps([{ url: 'https://a.test/', body: 'x=1' }]), /steps\[0\]\.body/);
  assert.throws(() => S.normSteps([{ link_text: 'Login' }]), /steps\[0\] needs a url/);
  assert.throws(() => S.normSteps([{ url: 'ftp://a.test/' }]), /http:\/\/ or https:\/\//);
  assert.throws(() => S.validUrl('https://user:pw@a.test/', 'url'), /user name or password/);
  const html = '<a href="javascript:x()">Claims</a> <a class="n" href=\'/claims?x=1&amp;y=2\'><b>Motor Claims</b></a> <a href="mailto:a@b">Claims</a>';
  assert.equal(S.findLink(html, 'motor claims', 'https://portal.test/home').toString(), 'https://portal.test/claims?x=1&y=2');
  assert.equal(S.findLink(html, 'Policies', 'https://portal.test/'), null);
});

/* a local web server standing in for the monitored applications */
function site() {
  return http.createServer((q, r) => {
    const u = q.url;
    if (q.method !== 'GET' && q.method !== 'HEAD') { r.writeHead(405); return r.end(); }
    if (u === '/ok') { r.writeHead(200, { 'Content-Type': 'text/html' }); return r.end('<html>Welcome to the SYNTHETIC portal <a href="/claims">Claims</a></html>'); }
    if (u === '/claims') { r.writeHead(200); return r.end('Claims list (synthetic)'); }
    if (u === '/slow') return setTimeout(() => { r.writeHead(200); r.end('slow ok'); }, 130);
    if (u === '/hang') return undefined;
    if (u === '/err') { r.writeHead(503); return r.end('down'); }
    if (u === '/redir-ok') { r.writeHead(302, { Location: '/ok' }); return r.end(); }
    if (u === '/redir-out') { r.writeHead(302, { Location: 'http://blocked.test/x' }); return r.end(); }
    if (u === '/loop') { r.writeHead(302, { Location: '/loop' }); return r.end(); }
    r.writeHead(404); r.end();
  });
}
async function listen(srv) { await new Promise((ok) => srv.listen(0, '127.0.0.1', ok)); return srv.address().port; }

test('checks against a local server: status, text, timings, redirects re-checked, transaction, timeout, Apdex and aggregates', async (t) => {
  const srv = site(), port = await listen(srv); t.after(() => srv.close());
  const state = await createState({ dir: tmp('sentra-syn-') });
  const seen = [];
  const resolve = async (u) => { seen.push(u.hostname); if (u.hostname === 'blocked.test') throw blocked('blocked.test is not on the allow-list'); return '127.0.0.1'; };
  const syn = S.createSynthetic({ state, log: quiet, resolve });
  assert.throws(() => syn.put({ name: 'x', url: `http://app.test:${port}/ok` }, 'syn.admin'), /allowed hosts \/ networks first/);
  syn.setSettings({ allow: ['app.test'] }, 'syn.admin');
  const mk = (o) => syn.put(Object.assign({ name: 'c', url: `http://app.test:${port}/ok`, apdex_t_ms: 500, timeout_ms: 2000 }, o), 'syn.admin').check;
  assert.throws(() => mk({ method: 'POST' }), /GET or HEAD/); assert.throws(() => mk({ method: 'HEAD', expect_text: 'x' }), /needs method GET/);

  const ok = await syn.runNow(mk({ id: 'portal-ok', expect_text: 'SYNTHETIC portal', app: 'Customer portal' }).id);
  assert.equal(ok.ok, true); assert.equal(ok.status, 200); assert.equal(ok.apdex, 's');
  for (const k of ['dns', 'connect', 'ttfb', 'total']) assert.equal(typeof ok.ms[k], 'number', 'timing ' + k);
  assert.ok(ok.ms.total >= ok.ms.ttfb);
  const head = await syn.runNow(mk({ id: 'portal-head', method: 'HEAD' }).id); assert.equal(head.ok, true);
  const txt = await syn.runNow(mk({ id: 'portal-text', expect_text: 'not on the page', app: 'Customer portal' }).id);
  assert.equal(txt.ok, false); assert.match(txt.error, /expected text not found/); assert.equal(txt.apdex, 'f');
  const st = await syn.runNow(mk({ id: 'portal-503', url: `http://app.test:${port}/err` }).id); assert.match(st.error, /HTTP 503/);
  const want = await syn.runNow(mk({ id: 'portal-want', url: `http://app.test:${port}/err`, expect_status: [503] }).id); assert.equal(want.ok, true, 'an expected 503 passes');
  const rd = await syn.runNow(mk({ id: 'redir-ok', url: `http://app.test:${port}/redir-ok` }).id); assert.equal(rd.ok, true); assert.equal(rd.redirects, 1); assert.match(rd.final_url, /\/ok$/);
  seen.length = 0;
  const out = await syn.runNow(mk({ id: 'redir-out', url: `http://app.test:${port}/redir-out` }).id);
  assert.equal(out.ok, false); assert.equal(out.blocked, true); assert.match(out.error, /blocked\.test is not on the allow-list/); assert.deepEqual(seen, ['app.test', 'blocked.test'], 'the redirect target is checked again');
  const lp = await syn.runNow(mk({ id: 'redir-loop', url: `http://app.test:${port}/loop`, max_redirects: 3 }).id); assert.match(lp.error, /more than 3 redirects/);
  const tx = await syn.runNow(mk({ id: 'claims-tx', steps: [{ url: `http://app.test:${port}/ok`, expect_text: 'Welcome' }, { link_text: 'claims', expect_text: 'Claims list' }] }).id);
  assert.equal(tx.ok, true, JSON.stringify(tx.steps)); assert.equal(tx.steps.length, 2); assert.match(tx.steps[1].url, /\/claims$/);
  const tx2 = await syn.runNow(mk({ id: 'claims-tx2', steps: [{ url: `http://app.test:${port}/ok` }, { link_text: 'Policies' }] }).id);
  assert.match(tx2.error, /step 2: no link with the text "Policies"/);
  const slow = await syn.runNow(mk({ id: 'slow', url: `http://app.test:${port}/slow`, apdex_t_ms: 100 }).id); assert.equal(slow.apdex, 't', 'between T and 4T: ' + slow.ms.total);
  const hang = await syn.runNow(mk({ id: 'hang', url: `http://app.test:${port}/hang`, timeout_ms: 300 }).id); assert.match(hang.error, /timed out after 300 ms/);

  await syn.runNow('portal-ok');
  const v = syn.view(), row = v.checks.find((c) => c.id === 'portal-ok');
  assert.equal(row.d1.runs, 2); assert.equal(row.d1.apdex, 1); assert.equal(row.d1.uptime_pct, 100); assert.equal(row.status, 'up');
  assert.equal(v.checks.find((c) => c.id === 'portal-text').status, 'down'); assert.equal(v.checks[0].status, 'down', 'down first');
  const app = v.apps.find((a) => a.app === 'Customer portal'); assert.equal(app.checks, 2); assert.equal(app.runs, 3); assert.equal(app.down, 1); assert.equal(app.apdex, 0.67);
  assert.equal(v.summary.checks, 12);
  const d = syn.detail('portal-ok'); assert.ok(d.hours.length >= 48); assert.equal(d.hours[d.hours.length - 1].runs, 2); assert.equal(d.days.length, 1); assert.equal(d.recent.length, 2);
  syn.remove('portal-ok'); assert.equal(state.collection('syn_hourly').all((h) => h.check === 'portal-ok').length, 0, 'history removed with the check');
  assert.throws(() => syn.detail('portal-ok'), (e) => e.status === 404);
});

test('the real resolver never reaches loopback, even when the address itself is on the allow-list', async (t) => {
  const srv = site(), port = await listen(srv); t.after(() => srv.close());
  const syn = S.createSynthetic({ state: await createState({ dir: tmp('sentra-syn-') }), log: quiet });
  syn.setSettings({ allow: ['127.0.0.1', 'localhost'], allow_private: true }, 'syn.admin');
  const a = await syn.runNow(syn.put({ name: 'lo', url: `http://127.0.0.1:${port}/ok` }, 'syn.admin').check.id);
  assert.equal(a.ok, false); assert.equal(a.blocked, true); assert.match(a.error, /never allowed/);
  const b = await syn.runNow(syn.put({ name: 'lo2', url: `http://localhost:${port}/ok` }, 'syn.admin').check.id);
  assert.match(b.error, /never allowed/);
});

test('TLS: certificate validity and days to expiry; an untrusted certificate fails unless verification is off', { skip: !fs.existsSync('/usr/bin/openssl') && 'openssl not available' }, async (t) => {
  const d = tmp('sentra-syn-tls-');
  cp.execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '20', '-subj', '/CN=app.test/O=Synthetic Test CA', '-keyout', path.join(d, 'k.pem'), '-out', path.join(d, 'c.pem')], { stdio: 'ignore' });
  const srv = https.createServer({ key: fs.readFileSync(path.join(d, 'k.pem')), cert: fs.readFileSync(path.join(d, 'c.pem')) }, (q, r) => { r.writeHead(200); r.end('tls ok'); });
  const port = await listen(srv); t.after(() => srv.close());
  const syn = S.createSynthetic({ state: await createState({ dir: tmp('sentra-syn-') }), log: quiet, resolve: async () => '127.0.0.1' });
  syn.setSettings({ allow: ['app.test'] }, 'syn.admin');
  const strict = await syn.runNow(syn.put({ id: 'tls-strict', name: 'TLS strict', url: `https://app.test:${port}/` }, 'syn.admin').check.id);
  assert.equal(strict.ok, false); assert.match(strict.error, /TLS certificate not trusted/);
  assert.equal(strict.cert.authorized, false); assert.ok(strict.cert.days_left >= 18 && strict.cert.days_left <= 20, 'days left ' + strict.cert.days_left); assert.equal(strict.cert.subject, 'app.test');
  const lax = await syn.runNow(syn.put({ id: 'tls-lax', name: 'TLS lax', url: `https://app.test:${port}/`, tls_verify: false, cert_warn_days: 30 }, 'syn.admin').check.id);
  assert.equal(lax.ok, true); assert.equal(typeof lax.ms.tls, 'number');
  const v = syn.view(); const c = v.certs.find((x) => x.id === 'tls-lax');
  assert.equal(c.state, 'untrusted'); assert.equal(v.checks.find((x) => x.id === 'tls-lax').status, 'degraded'); assert.ok(v.summary.certs_bad >= 1);
});

test('portal Apdex from the access-log rows (request time; 5xx frustrated); no request time = no Apdex', async () => {
  const calls = [];
  const ch = { query: async (sql, p) => { calls.push({ sql, p }); if (/syn_portal_sites/.test(sql)) return [{ site: 'portal.syn', n: 1000, timed: 900, s: 700, t: 120, e5: 30, p50: 0.21, p95: 1.8 }];
    return [{ h: '2026-11-13 08:00:00', n: 500, timed: 450, s: 350, t: 60, e5: 10, p50: 0.2, p95: 1.7 }]; }, insertRows: async () => {} };
  const syn = S.createSynthetic({ state: await createState({ dir: tmp('sentra-syn-') }), log: quiet, ch });
  const r = await syn.portalApdex({ hours: 24, t_ms: 500, site: 'portal.syn' });
  assert.equal(r.sites[0].apdex, 0.84); assert.equal(r.sites[0].frustrated, 80); assert.equal(r.sites[0].p95_ms, 1800); assert.equal(r.sites[0].error_rate_pct, 3); assert.equal(r.measured, true);
  assert.equal(r.series[0].hour, Date.parse('2026-11-13T08:00:00Z'));
  assert.equal(calls[0].p.T.value, 0.5); assert.equal(calls[0].p.s.value, 'portal.syn'); assert.ok(!/portal\.syn/.test(calls[0].sql), 'the site is a parameter, never in the SQL');
  const none = S.createSynthetic({ state: await createState({ dir: tmp('sentra-syn-') }), log: quiet, ch: { query: async () => [{ site: 'x', n: 10, timed: 0, s: 0, t: 0, e5: 0 }] } });
  const n = await none.portalApdex({ hours: 24, t_ms: 500 }); assert.equal(n.sites[0].apdex, null); assert.equal(n.measured, false); assert.match(n.note, /\$request_time/);
  await assert.rejects(S.createSynthetic({ state: await createState({ dir: tmp('sentra-syn-') }) }).portalApdex({ hours: 24, t_ms: 500 }), (e) => e.status === 503);
});

test('health by device type: servers, domain controllers, WLCs, FC switches up / down', () => {
  const v = R.healthByType({
    hosts: [{ name: 'app01', ip: '10.0.0.1', kind: 'server' }, { name: 'asdc01', ip: '10.0.0.2', kind: 'server' }, { name: 'hq-adc2', ip: '10.0.0.3' }, { name: 'nas1', ip: '10.0.0.4', kind: 'storage' }, { name: 'old', ip: '10.0.0.5', monitor: false }],
    hostStatus: { '10.0.0.1': { s: 'online' }, '10.0.0.2': { s: 'offline', since: 5 }, '10.0.0.3': { s: 'online' }, '10.0.0.4': { s: 'online' } },
    devices: [{ id: 'wlc1', name: 'WLC-1', role: 'wlc', poll: { snmp: true } }, { id: 'fc1', name: 'FC-A', role: 'fc_switch', poll: { snmp: true } }, { id: 'fc2', name: 'FC-B', role: 'fc_switch', poll: { snmp: true } }, { id: 'fw', name: 'FW', role: 'firewall', poll: { ping: false } }],
    snapshot: (id) => ({ wlc1: { at: 1, ok: true }, fc1: { at: 1, ok: false, errors: ['snmp: timeout'] } })[id] || null });
  const by = Object.fromEntries(v.types.map((x) => [x.type, x]));
  assert.deepEqual([by.servers.total, by.servers.up, by.servers.unmonitored], [2, 1, 1]);
  assert.deepEqual([by.domain_controllers.total, by.domain_controllers.up, by.domain_controllers.down], [2, 1, 1]); assert.equal(by.domain_controllers.down_items[0].name, 'asdc01');
  assert.equal(by.storage.up, 1); assert.equal(by.wlcs.up, 1);
  assert.deepEqual([by.fc_switches.down, by.fc_switches.unknown], [1, 1]); assert.match(by.fc_switches.down_items[0].why, /timeout/);
  assert.equal(by.firewalls.unmonitored, 1);
  const empty = R.healthByType({}); assert.deepEqual(empty.types.map((x) => x.type), ['servers', 'domain_controllers', 'wlcs', 'fc_switches'], 'the four asked-for types always shown, with 0 - not invented');
});

/* ---------------- routes */
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
function ctxFor(role, o = {}) {
  const out = { s: 200, audits: [] };
  return { out, ctx: { role, user: 'syn.' + role, ip: '10.0.0.9', body: o.body || {}, params: o.params || {}, query: o.query || {},
    need(r) { if ((RANK[role] || 0) < RANK[r]) { out.s = 403; return false; } return true; },
    ok(b) { out.b = b; return b; }, fail(c, msg) { out.s = c; out.b = { error: msg }; return out.b; }, audit(a, t, d) { out.audits.push({ a, t, d }); } } };
}
test('routes: roles (refused below admin / operator), validation errors name the field, every change audited', async (t) => {
  const srv = site(), port = await listen(srv); t.after(() => srv.close());
  const state = await createState({ dir: tmp('sentra-syn-r-') });
  const syn = S.createSynthetic({ state, log: quiet, resolve: async () => '127.0.0.1' });
  const inv = { list: () => [{ id: 'wlc1', name: 'WLC-1', role: 'wlc', ip: '10.0.5.1', site: 'Riyadh', poll: { snmp: true } }], credentialSummary: () => ({ snmp: 'v3 authPriv' }) };
  const N = { inventory: inv, poller: { snapshot: () => null }, availability: { list: () => [{ name: 'app01', ip: '10.0.0.1', kind: 'server' }], ipMap: () => ({ '10.0.0.1': { s: 'online' } }) } };
  const H = {}; R.register({ route: (m, p, h) => { H[m + ' ' + p] = h; } }, { state, config: { netops: { enabled: false } }, log: quiet, synthetic: syn, netopsInstance: N });
  const call = async (key, role, o) => { const { out, ctx } = ctxFor(role, o); const r = await H[key](ctx); if (out.s === 200) out.b = r; return out; };
  const P = '/api/soc/netops/synthetic';

  for (const role of ['viewer', 'operator']) {
    assert.equal((await call(`PUT ${P}/settings`, role, { body: { allow: ['app.test'] } })).s, 403, role + ' cannot change the allow-list');
    assert.equal((await call(`POST ${P}/checks`, role, { body: { name: 'x', url: 'http://app.test/' } })).s, 403, role + ' cannot add a check');
  }
  let r = await call(`PUT ${P}/settings`, 'admin', { body: { allow: ['app.test', '10.20.0.0/16'], allow_private: true, extra: 'dropped' } });
  assert.equal(r.s, 200); assert.deepEqual(r.b.allow, ['app.test', '10.20.0.0/16']);
  assert.deepEqual(r.audits[0], { a: 'netops.synthetic.settings', t: 'allow-list', d: { from: { allow: [], allow_private: false, default_t_ms: 500 }, to: { allow: ['app.test', '10.20.0.0/16'], allow_private: true, default_t_ms: 500 } } });
  assert.match((await call(`PUT ${P}/settings`, 'admin', { body: { allow: ['ftp://x'] } })).b.error, /allow\[0\]/);
  assert.match((await call(`PUT ${P}/settings`, 'admin', { body: { allow_private: 'yes' } })).b.error, /allow_private must be true or false/);

  for (const [b, re] of [[{ name: 'x', url: 'http://app.test/', interval_s: 5 }, /interval_s must be at least 30/], [{ name: 'x', url: 'http://app.test/', method: 'POST' }, /method must be one of: GET, HEAD/],
    [{ name: 'x' }, /name and url are required/], [{ name: 'x', url: 'file:///etc/passwd' }, /url must start with http/], [{ name: 'x', url: 'http://app.test/', timeout_ms: 999999 }, /timeout_ms must be at most 60000/],
    [{ name: 'x', url: 'http://app.test/', steps: [{ url: 'http://app.test/', method: 'POST' }] }, /steps\[0\]\.method/]]) {
    const x = await call(`POST ${P}/checks`, 'admin', { body: b }); assert.equal(x.s, 400, JSON.stringify(b)); assert.match(x.b.error, re);
  }
  r = await call(`POST ${P}/checks`, 'admin', { body: { id: 'portal', name: 'Portal', url: `http://app.test:${port}/ok`, apdex_t_ms: 400, created_by: 'mallory' } });
  assert.equal(r.s, 200); assert.equal(r.b.created_by, 'syn.admin', 'undeclared fields never reach the logic');
  assert.equal(r.audits[0].a, 'netops.synthetic.check.create'); assert.equal(r.audits[0].t, 'portal'); assert.equal(r.audits[0].d.apdex_t_ms, 400);
  r = await call(`POST ${P}/checks`, 'admin', { body: { id: 'portal', interval_s: 60 } });
  assert.equal(r.audits[0].a, 'netops.synthetic.check.update'); assert.deepEqual(r.audits[0].d.changed, ['interval_s']);

  assert.equal((await call(`POST ${P}/checks/:id/run`, 'viewer', { params: { id: 'portal' } })).s, 403, 'a viewer cannot run a check');
  r = await call(`POST ${P}/checks/:id/run`, 'operator', { params: { id: 'portal' } }); assert.equal(r.b.ok, true); assert.deepEqual(r.audits[0], { a: 'netops.synthetic.run', t: 'portal', d: {} });
  assert.equal((await call(`POST ${P}/checks/:id/run`, 'operator', { params: { id: 'nope' } })).s, 404);
  r = await call(`GET ${P}`, 'viewer'); assert.equal(r.b.checks.length, 1); assert.equal(r.b.settings, undefined, 'the allow-list is shown to administrators only');
  assert.ok((await call(`GET ${P}`, 'admin')).b.settings.allow.length);
  r = await call(`GET ${P}/checks/:id`, 'viewer', { params: { id: 'portal' } }); assert.equal(r.b.check.d1.runs, 1);
  assert.equal((await call(`GET ${P}/checks/:id`, 'viewer', { params: { id: '../x' } })).s, 400);
  assert.equal((await call(`DELETE ${P}/checks/:id`, 'operator', { params: { id: 'portal' } })).s, 403);
  r = await call(`DELETE ${P}/checks/:id`, 'admin', { params: { id: 'portal' } }); assert.equal(r.audits[0].a, 'netops.synthetic.check.delete'); assert.match(r.audits[0].d.url, /\/ok$/);

  assert.equal((await call('GET /api/soc/netops/apdex/portal', 'viewer', { query: { hours: '24' } })).s, 503, 'no event store: says so');
  assert.match((await call('GET /api/soc/netops/apdex/portal', 'viewer', { query: { hours: '5' } })).b.error, /hours must be one of/);
  assert.match((await call('GET /api/soc/netops/apdex/portal', 'viewer', { query: { site: "x' OR 1=1" } })).b.error, /site must be a host name/);
  r = await call('GET /api/soc/netops/health/types', 'viewer'); assert.equal(r.b.types.find((x) => x.type === 'servers').up, 1); assert.equal(r.b.types.find((x) => x.type === 'wlcs').unknown, 1);
  r = await call('GET /api/soc/netops/wlc', 'viewer'); assert.equal(r.b.configured, true); assert.equal(r.b.controllers[0].state, 'waiting');
});
