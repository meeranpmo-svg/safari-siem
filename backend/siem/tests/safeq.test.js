// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// YSoft SAFEQ 6: console link + scheduled read-only pulls (usage report, printer list) over the real HTTP client against
// a local fake SAFEQ: CSV and nested JSON, authentication header, {from}/{to}/{period}, login-page / redirect detection,
// URLs with credentials refused, secret write-only, printers matched by IP, per-user usage only for operators / admins.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createState } = require('../engine/soc/state');
const { createPrinters } = require('../engine/printers/printers');
const { createSafeq, recordsOf } = require('../engine/printers/safeq');
const { writeJsonAtomic } = require('../engine/onboard/store');

const KEY = 'sq-api-key-7f3a9c';

async function fakeSafeq(seen) {
  const srv = http.createServer((req, res) => {
    seen.push({ url: req.url, key: req.headers['x-api-key'] || null, auth: req.headers.authorization || null });
    if (req.headers['x-api-key'] !== KEY) { res.writeHead(302, { Location: '/login' }); return res.end(); }
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/api/v1/reports/usage') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ meta: { from: u.searchParams.get('from'), to: u.searchParams.get('to') }, data: { content: [
        { userName: 'ali.hassan', costCenter: 'Finance', deviceName: 'XRX-HQ-2F', colorPages: 120, bwPages: 380, totalPages: 500, cost: 61.5 },
        { userName: 'sara.k', costCenter: 'HR', deviceName: 'XRX-HQ-3F', colorPages: 0, bwPages: 75, totalPages: 75, cost: 3.75 }] } }));
    }
    if (u.pathname === '/export/devices.csv') { res.writeHead(200, { 'Content-Type': 'text/csv' }); return res.end('Device name;IP address;Model;Serial number;Location\nXRX-HQ-2F;192.168.20.31;Xerox AltaLink C8130;XRX-001;HQ 2nd floor\nXRX-HQ-3F;192.168.20.32;Xerox VersaLink B405;XRX-002;HQ 3rd floor\nVirtual queue;;;;\n'); }
    if (u.pathname === '/login-page') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<!doctype html><html><body>SAFEQ login</body></html>'); }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, base: `http://127.0.0.1:${srv.address().port}` };
}
async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sq-')), secFile = path.join(dir, 'secrets.json'); fs.writeFileSync(secFile, '{}');
  const state = await createState({ dir });
  const config = { clickhouse: { database: 'siem' }, printers: { safeq_allow_http: true } };
  Object.defineProperty(config, '_paths', { value: { config: path.join(dir, 'config.json'), secrets: secFile } });
  Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  const P = createPrinters({ state, config, writeJson: writeJsonAtomic, now: () => Date.parse('2026-10-14T09:00:00Z') });
  const S = createSafeq({ state, config, printers: P, writeJson: writeJsonAtomic, now: () => Date.parse('2026-10-14T09:00:00Z') });
  return { P, S, state, config, secFile };
}

test('recordsOf finds the first list of records and flattens nested keys', () => {
  const t = recordsOf({ a: 1, page: { items: [{ user: { name: 'x' }, pages: 2 }, { user: { name: 'y' }, pages: 3, extra: 'z' }] } });
  assert.deepEqual(t[0], ['user name', 'pages', 'extra']); assert.deepEqual(t[1], [['x', '2', ''], ['y', '3', 'z']]);
  assert.equal(recordsOf({ ok: true }), null);
});

test('SAFEQ settings: https only, no logins in URLs, secret write-only, auth needs its secret', async () => {
  const { S, config, secFile } = await setup();
  config.printers.safeq_allow_http = false;
  assert.throws(() => S.setSettings({ usage_url: 'http://safeq.corp.local/api' }, 'syed'), /https/);
  assert.throws(() => S.setSettings({ usage_url: 'https://admin:pw@safeq.corp.local/api' }, 'syed'), /user name \/ password/);
  assert.throws(() => S.setSettings({ auth: 'header', header_name: 'X-Api-Key' }, 'syed'), /token \/ API key/);
  assert.throws(() => S.setSettings({ auth: 'header' }, 'syed'), /header name/);
  const r = S.setSettings({ console_url: 'https://safeq.corp.local:9443/', usage_url: 'https://safeq.corp.local:9443/api/v1/reports/usage?from={from}&to={to}', auth: 'header', header_name: 'X-Api-Key', secret: KEY }, 'syed');
  assert.equal(r.secret_set, true); assert.ok(!JSON.stringify(r).includes(KEY), 'secret never returned');
  assert.equal(JSON.parse(fs.readFileSync(secFile, 'utf8')).printers.safeq.value, KEY);
  assert.throws(() => S.setSettings({ fingerprint256: 'AB:CD' }, 'syed'), /64 hex/);
});

test('SAFEQ pulls: JSON usage with dates, CSV printer list matched by IP, errors explained', async (t) => {
  const seen = [], f = await fakeSafeq(seen); t.after(() => f.srv.close());
  const { P, S } = await setup();
  P.put({ ip: '192.168.20.31', name: 'XRX-HQ-2F (SNMP)' }, 'adm');
  S.setSettings({ console_url: f.base + '/', usage_url: f.base + '/api/v1/reports/usage?from={from}&to={to}', devices_url: f.base + '/export/devices.csv', auth: 'header', header_name: 'X-Api-Key', secret: KEY }, 'syed');

  const tt = await S.test('usage');
  assert.equal(tt.format, 'json'); assert.equal(tt.rows, 2); assert.ok(tt.columns.includes('user Name'));
  assert.equal(seen[0].url, '/api/v1/reports/usage?from=2026-10-01&to=2026-10-14'); assert.equal(seen[0].key, KEY);

  const u = await S.pullUsage('syed');
  assert.equal(u.ok, true, u.error); assert.deepEqual(u.periods.map((x) => [x.period, x.rows, x.pages]), [['2026-10', 2, 575]]);
  const per = P.usage().periods[0];
  assert.equal(per.source, 'safeq'); assert.deepEqual([per.totals.color, per.totals.mono, per.totals.cost], [120, 455, 65.25]);
  assert.deepEqual(per.by_department.map((x) => x.name), ['Finance', 'HR']); assert.equal(per.by_user[0].name, 'ali.hassan');
  assert.deepEqual(P.usage({ users: false }).periods[0].by_user, [], 'viewers do not get per-user rows');

  const d = await S.pullDevices('syed');
  assert.deepEqual([d.ok, d.rows, d.added, d.updated, d.skipped], [true, 3, 1, 1, 1], JSON.stringify(d));
  const list = P.list().sort((a, b) => (a.ip < b.ip ? -1 : 1));
  assert.deepEqual(list.map((p) => [p.ip, p.name, p.safeq_name, p.model, p.serial, p.source || 'manual']), [
    ['192.168.20.31', 'XRX-HQ-2F (SNMP)', 'XRX-HQ-2F', 'Xerox AltaLink C8130', 'XRX-001', 'manual'],
    ['192.168.20.32', 'XRX-HQ-3F', 'XRX-HQ-3F', 'Xerox VersaLink B405', 'XRX-002', 'safeq']]);
  assert.equal((await S.pullDevices('syed')).updated, 0, 'nothing changes on a second pull');

  // a wrong key lands on the login redirect; a login page is recognised
  S.setSettings({ secret: 'wrong-key-123' }, 'syed');
  const bad = await S.pullUsage('syed'); assert.equal(bad.ok, false); assert.match(bad.error, /redirect/);
  S.setSettings({ secret: KEY, usage_url: f.base + '/login-page' }, 'syed');
  await assert.rejects(S.test('usage'), /web page, not data/);
  assert.equal(S.settings().last_usage.ok, false);
});

test('SAFEQ routes: console link for everyone, settings operator+, changes admin', async () => {
  const { P, S, state, config } = await setup();
  const routes = require('../engine/printers/routes');
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {}, warn() {} }, printers: P, safeq: S });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (m, p, role, b) => { const o = {}; const ctx = { role, user: 'u', body: b, params: {}, query: {}, need(r) { if (RANK[role] < RANK[r]) { o.s = 403; return false; } return true; }, audit() {}, fail(c, msg) { o.s = c; o.e = msg; } }; const rv = await R[m + ' /api/soc/printers' + p](ctx); if (rv !== undefined && !o.s) { o.s = 200; o.b = rv; } return o; };
  assert.equal((await call('PUT', '/safeq', 'operator', { console_url: 'http://x' })).s, 403);
  assert.equal((await call('PUT', '/safeq', 'admin', { console_url: 'http://127.0.0.1:9/safeq' })).s, 200);
  assert.equal((await call('GET', '', 'viewer')).b.safeq_console, 'http://127.0.0.1:9/safeq');
  assert.equal((await call('GET', '/safeq', 'viewer')).s, 403);
  assert.equal((await call('GET', '/safeq', 'operator')).s, 200);
  P.importUsage('User,Department,Pages\nali,Finance,4\n', { period: '2026-10' }, 'adm');
  assert.deepEqual((await call('GET', '/usage', 'viewer')).b.periods[0].by_user, []);
  assert.equal((await call('GET', '/usage', 'operator')).b.periods[0].by_user[0].name, 'ali');
  assert.equal((await call('POST', '/safeq/pull', 'admin', { which: 'usage' })).s, 409, 'no usage address yet');
});
