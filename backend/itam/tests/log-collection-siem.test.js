// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Contract test: IT Asset Management's inventory "Log collection" (monitoring-membership.js) and the automatic enrolment
// (log-enrol.js) against the REAL SIEM routes (sentra-siem engine/onboard/routes.js + collection.js) served over HTTP - the
// link that used to answer 404 because the SIEM side did not exist. Skipped when the sentra-siem checkout is not next to
// shield. Synthetic assets, RFC 1918 addresses.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startApp } = require('./helpers');
const { startHttpFake } = require('./helpers/discovery-fakes');

const SIEM = path.join(__dirname, '..', '..', 'siem', 'engine');
const SECRET = 'synthetic-siem-proxy-secret-0123456789';
const ADM = { user: 'adm.sara', role: 'admin' };

async function realSiem(tmp) {
  const paths = { config: path.join(tmp, 'siem-config.json'), secrets: path.join(tmp, 'siem-secrets.json') };
  const sites = [{ id: 'riyadh-hq', name: 'Riyadh HQ', kind: 'main' }];
  fs.writeFileSync(paths.config, JSON.stringify({ sources: [], onboard: { sites } })); fs.writeFileSync(paths.secrets, JSON.stringify({ ingest_tokens: {} }));
  const live = new Map();
  const deps = { config: { sources: [], onboard: { sites, siem_ip: ZYB_ORG.platform_addr }, syslog: { tcp: { port: 5514 } } }, onboardPaths: paths, log: { info() {}, warn() {}, error() {} },
    tracker: { summary: () => [...live.values()] }, ch: { query: async () => [] } };
  const routes = [];
  const api = { route: (method, p, h) => { const keys = []; const re = new RegExp('^' + p.replace(/:([a-z]+)/g, (m, k) => { keys.push(k); return '([^/]+)'; }) + '$'); routes.push({ method, re, keys, h }); } };
  require(path.join(SIEM, 'onboard', 'routes')).register(api, deps);
  require(path.join(SIEM, 'onboard', 'collection')).register(api, deps);
  const rank = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const fake = await startHttpFake(async (r) => {
    if (r.headers['x-sentra-proxy-secret'] !== SECRET) return { status: 401, body: { error: 'bad secret' } };
    const u = new URL(r.url, 'http://x'), role = r.headers['x-auth-role'] || 'viewer';
    for (const rt of routes) {
      const m = rt.method === r.method && rt.re.exec(u.pathname); if (!m) continue;
      const params = {}; rt.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
      const out = {};
      await rt.h({ body: r.body ? JSON.parse(r.body) : {}, params, query: Object.fromEntries(u.searchParams), user: r.headers['x-auth-user'], role, path: u.pathname,
        need: (want) => { if (rank[role] < rank[want]) { out.status = 403; out.body = { error: 'requires role ' + want }; return false; } return true; }, audit() {},
        ok: (b) => { out.status = 200; out.body = b; }, fail: (c, msg) => { out.status = c; out.body = { error: msg }; } });
      return out;
    }
    if (u.pathname === '/api/soc/reporting-hosts') return { status: 200, body: { hours: 168, hosts: [] } };
    return null;
  });
  return { fake, deps, live };
}

test('inventory log collection ↔ real SIEM collection routes: enable, status, setup, auto-enrol, pause, stop', async (t) => {
  if (!fs.existsSync(path.join(SIEM, 'onboard', 'collection.js'))) { t.skip('sentra-siem checkout (with onboard/collection.js) not next to shield'); return; }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-lc-siem-'));
  const S = await realSiem(tmp);
  fs.writeFileSync(path.join(tmp, 'secret'), JSON.stringify({ proxy_secret: SECRET }));
  const h = await startApp({ noAi: true, config: { discovery: { siem: { base_url: S.fake.url, secret_file: path.join(tmp, 'secret') } } } });
  t.after(async () => { await h.close(); await S.fake.close(); fs.rmSync(tmp, { recursive: true, force: true }); });
  const adm = (m, p, body) => h.req(m, p, Object.assign({}, ADM, body === undefined ? {} : { body }));
  const mk = async (name, ip, extra) => (await adm('POST', '/assets', Object.assign({ name, type: 'network', vendor: 'Fortinet', mgmt_ip: ip, site: 'Riyadh HQ' }, extra || {}))).json.asset;
  const fw = await mk('TEST-FW-1', '10.70.0.1', { os: 'FortiOS 7.4' });
  const en = await adm('POST', `/assets/${fw.id}/log-collection`, { action: 'enable' });
  assert.equal(en.status, 200, en.text);
  assert.equal(en.json.created, true); assert.ok(en.json.source_id);
  assert.match(en.json.setup.syslog_target, new RegExp('^' + ZYB_ORG.platform_addr_re + ':5514\\/'), 'the SIEM tells the device where to send');
  const src = S.deps.config.sources.find((s) => s.id === en.json.source_id);
  assert.equal(src.asset_id, fw.id); assert.equal(src.match.ip, '10.70.0.1'); assert.equal(src.site, 'riyadh-hq');
  h.app.membership.invalidate();
  let d = (await h.req('GET', `/assets/${fw.id}/log-collection`, { role: 'viewer' })).json;
  assert.equal(d.status, 'never-seen', 'registered, nothing received yet');
  // logs arrive
  S.live.set(src.id, { src_id: src.id, last_seen: Date.now() - 60000, events_since_start: 50, eps_1m: 2, eps_1h: 2, parse_error_rate_1h: 0, hosts: [] });
  h.app.membership.invalidate();
  d = (await h.req('GET', `/assets/${fw.id}/log-collection`, { role: 'viewer' })).json;
  assert.equal(d.status, 'covered'); assert.equal(d.sla_class, 'firewall'); assert.equal(d.sla_min, 15);
  assert.match((await h.req('GET', `/assets/${fw.id}/log-collection/setup`, { role: 'viewer' })).json.setup.snippet, new RegExp(ZYB_ORG.platform_addr_re));
  // auto-enrolment through the real SIEM: a new Linux server gets its source without a click
  const E = require('../engine/log-enrol').registerLogEnrol(h.app.srv, h.app, { noTimer: true });
  const lx = await mk('TEST-LX-1', '10.70.0.20', { type: 'server', vendor: 'Dell', os: 'Red Hat Enterprise Linux 9' });
  h.app.membership.invalidate();
  const pass = await E.pass();
  assert.deepEqual(pass.enrolled.map((x) => x.asset_id), [lx.id], JSON.stringify(pass));
  const lsrc = S.deps.config.sources.find((s) => s.asset_id === lx.id);
  assert.equal(lsrc.kind, 'linux'); assert.equal(lsrc.auto_onboarded, true, 'marked as enrolled automatically');
  // pause / stop
  assert.equal((await adm('POST', `/assets/${fw.id}/log-collection`, { action: 'pause', reason: 'synthetic maintenance' })).status, 200);
  assert.equal(S.deps.config.sources.find((s) => s.id === src.id).paused, true);
  const st = await adm('POST', `/assets/${fw.id}/log-collection`, { action: 'stop', confirm: true });
  assert.equal(st.status, 200); assert.equal(st.json.removed, false, 'still sending in the last 24 h: paused, not removed'); assert.equal(st.json.paused, true);
});
