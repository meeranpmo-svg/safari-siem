// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/util/brand');
// Inventory log collection + log-flow assurance (engine/onboard/collection.js, assurance.js): the /collection/* contract
// IT Asset Management's per-asset "Log collection" calls (ensure is idempotent per asset / IP, setup, pause / resume, stop
// pauses while still sending), per-class silence (a firewall quiet 20 min is silent, a switch is not), lag from rts - ts,
// and the AI SIEM Engineer's work items: silent asset, registered-but-never-received, not onboarded, unknown sender,
// parse errors, collectors quiet; nothing connected = not connected, never "healthy".
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const { createDuty } = require('../engine/duty/duty-core');

const T0 = Date.UTC(2026, 9, 17, 8);

async function setup(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-coll-'));
  const paths = { config: path.join(dir, 'config.json'), secrets: path.join(dir, 'secrets.json') };
  const sites = [{ id: 'riyadh-hq', name: 'Riyadh HQ', kind: 'main' }, { id: 'jeddah', name: 'Jeddah', kind: 'branch' }];
  fs.writeFileSync(paths.config, JSON.stringify({ sources: [], onboard: { sites } })); fs.writeFileSync(paths.secrets, JSON.stringify({ ingest_tokens: {} }));
  const env = { now: T0, live: new Map(), lag: [], hosts: [], inv: opts.inv === undefined ? [] : opts.inv, audit: [] };
  const config = { sources: [], onboard: { sites, siem_ip: ZYB_ORG.platform_addr }, syslog: { tcp: { port: 5514 } }, clickhouse: { database: 'siem' } };
  const ch = { query: async (sql) => {
    if (/quantile/.test(sql)) return env.lag;
    if (/GROUP BY host/.test(sql)) return env.hosts;
    return [];
  } };
  const tracker = { summary: () => [...env.live.values()] };
  const state = await createState({ dir: path.join(dir, 'state') });
  const deps = { config, ch, tracker, state, now: () => env.now, log: { info() {}, warn() {}, error() {} }, onboardPaths: paths,
    discoveryClient: opts.inv === null ? undefined : { logCoverage: async () => ({ assets: env.inv }) } };
  const R = {};
  const api = { route: (m, p, h) => { R[m + ' ' + p] = h; } };
  require('../engine/onboard/routes').register(api, deps);
  require('../engine/onboard/collection').register(api, deps);
  env.call = async (key, { body, params, query, role = 'admin', user = 'syed' } = {}) => {
    const o = {}; const rank = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
    await R[key]({ body, params: params || {}, query: query || {}, user, role,
      need: (r) => { if (rank[role] < rank[r]) { o.s = 403; return false; } return true; }, audit: (a, t, d) => env.audit.push([a, t, d]),
      ok(x) { o.s = 200; o.b = x; }, fail(c, m) { o.s = c; o.e = m; } });
    return o;
  };
  env.deps = deps; env.config = config; env.state = state;
  env.recv = (id, minsAgo, extra) => env.live.set(id, Object.assign({ src_id: id, last_seen: env.now - minsAgo * 60000, events_since_start: 100, eps_1m: 1, eps_1h: 1.5, parse_error_rate_1h: 0, hosts: [] }, extra || {}));
  return env;
}

test('collection API: ensure creates once per asset / IP, setup, per-class silence, lag, pause / resume, stop', async () => {
  const e = await setup();
  const fw = { asset_id: 'A-FW1', name: 'FW-HQ-01', mgmt_ip: '10.1.0.1', type: 'network', class: 'firewall', vendor: 'Fortinet', os: 'FortiOS 7.4', site: 'Riyadh HQ' };
  assert.equal((await e.call('POST /api/soc/collection/sources/ensure', { body: { asset: fw }, role: 'operator' })).s, 403, 'creating a source needs admin');
  const r = await e.call('POST /api/soc/collection/sources/ensure', { body: { asset: fw } });
  assert.equal(r.s, 200, r.e); assert.equal(r.b.created, true); assert.equal(r.b.kind, 'fortigate'); assert.equal(r.b.site, 'riyadh-hq', 'site matched by name');
  assert.equal(r.b.source_id, 'fw-fw-hq-01'); assert.equal(r.b.setup.syslog_target, (ZYB_ORG.platform_addr + ':5514/tcp')); assert.match(r.b.setup.snippet, new RegExp('set server "' + ZYB_ORG.platform_addr_re + '"'));
  const again = await e.call('POST /api/soc/collection/sources/ensure', { body: { asset: Object.assign({}, fw, { asset_id: 'A-OTHER' }) } });
  assert.equal(again.b.created, false, 'same IP: the existing source is reused'); assert.equal(e.config.sources.length, 1);
  const src = e.config.sources[0];
  assert.equal(src.asset_id, 'A-FW1'); assert.equal(src.origin, 'inventory'); assert.equal(src.auto_onboarded, false); assert.equal(src.sla_class, 'firewall');
  // a Windows server: token connector, token returned once
  const win = await e.call('POST /api/soc/collection/sources/ensure', { body: { asset: { asset_id: 'A-DC1', name: 'DC01', mgmt_ip: '10.1.0.10', type: 'server', os: 'Windows Server 2022', is_dc: true, site: 'jeddah' } }, user: 'system:itam-auto-enrol' });
  assert.equal(win.b.kind, 'dc'); assert.ok(win.b.token && win.b.token_shown_once); assert.equal(e.config.sources[1].auto_onboarded, true, 'system enrolment is marked automatic');
  // unknown kind / public IP refused with the reason
  assert.match((await e.call('POST /api/soc/collection/sources/ensure', { body: { asset: { asset_id: 'P1', name: 'printer', type: 'printer', mgmt_ip: '10.1.0.50' } } })).e, /print module/);
  assert.match((await e.call('POST /api/soc/collection/sources/ensure', { body: { asset: { asset_id: 'L1', name: 'web', os: 'Ubuntu', type: 'server', mgmt_ip: '8.8.8.8' } } })).e, /not a private address/);
  // health: a firewall 20 min quiet is silent (threshold 15), a DC never seen is never-seen
  e.recv('fw-fw-hq-01', 20);
  e.lag = [{ src_id: 'fw-fw-hq-01', p50: 2, p95: 9 }];
  let h = (await e.call('GET /api/soc/collection/health', { role: 'viewer' })).b;
  const row = (id) => h.sources.find((x) => x.src_id === id);
  assert.equal(row('fw-fw-hq-01').state, 'silent'); assert.equal(row('fw-fw-hq-01').sla_min, 15); assert.equal(row('fw-fw-hq-01').lag_p95_s, 9);
  assert.equal(row('dc-dc01') ? row('dc-dc01').state : h.sources[1].state, 'never-seen');
  e.recv('fw-fw-hq-01', 2); h = (await e.call('GET /api/soc/collection/health', { role: 'viewer' })).b;
  assert.equal(row('fw-fw-hq-01').state, 'receiving');
  // setup, pause / resume
  assert.match((await e.call('GET /api/soc/collection/sources/:id/setup', { params: { id: 'fw-fw-hq-01' }, role: 'viewer' })).b.setup.summary.en, new RegExp(ZYB_ORG.platform_addr_re + ':5514'));
  assert.equal((await e.call('POST /api/soc/collection/sources/:id/pause', { params: { id: 'fw-fw-hq-01' }, body: { reason: 'maintenance' } })).b.paused, true);
  h = (await e.call('GET /api/soc/collection/health', { role: 'viewer' })).b; assert.equal(row('fw-fw-hq-01').state, 'paused');
  await e.call('POST /api/soc/collection/sources/:id/resume', { params: { id: 'fw-fw-hq-01' } });
  assert.equal(e.config.sources[0].paused, undefined);
  // stop: still sending → paused, not removed; a silent-for-a-day source is removed
  const st = await e.call('POST /api/soc/collection/sources/:id/stop', { params: { id: 'fw-fw-hq-01' } });
  assert.equal(st.b.removed, false); assert.equal(st.b.paused, true); assert.match(st.b.reason, /stop the sender/);
  const dcId = e.config.sources[1].id;
  const st2 = await e.call('POST /api/soc/collection/sources/:id/stop', { params: { id: dcId } });
  assert.equal(st2.b.removed, true); assert.equal(e.config.sources.length, 1);
  assert.ok(e.audit.some((a) => a[0] === 'collection.source.create'));
});

test('assurance + AI SIEM Engineer: silent / never received / not onboarded / unknown sender / parse errors / collectors quiet', async () => {
  const e = await setup();
  await e.call('POST /api/soc/collection/sources/ensure', { body: { asset: { asset_id: 'A-FW1', name: 'FW-HQ-01', mgmt_ip: '10.1.0.1', type: 'network', class: 'firewall', vendor: 'Fortinet', site: 'riyadh-hq' } } });
  await e.call('POST /api/soc/collection/sources/ensure', { body: { asset: { asset_id: 'A-SW1', name: 'SW-CORE', mgmt_ip: '10.1.0.2', type: 'network', class: 'switch', vendor: 'Cisco', site: 'riyadh-hq' } } });
  e.config.sources[1].created_at = new Date(T0 - 3 * 86400000).toISOString();
  e.inv = [
    { asset_id: 'A-FW1', name: 'FW-HQ-01', mgmt_ip: '10.1.0.1', type: 'network', class: 'firewall', asset_status: 'in_use', status: 'silent', source_id: 'fw-fw-hq-01', last_seen: new Date(T0 - 40 * 60000).toISOString(), matched_by: 'source', site: 'Riyadh HQ' },
    { asset_id: 'A-SW1', name: 'SW-CORE', mgmt_ip: '10.1.0.2', type: 'network', class: 'switch', asset_status: 'in_use', status: 'silent', source_id: e.config.sources[1].id, last_seen: null, matched_by: 'source' },
    { asset_id: 'A-SRV1', name: 'APP01', mgmt_ip: '10.1.0.20', type: 'server', asset_status: 'in_use', status: 'absent', source_id: null, suggested_kind: 'windows' },
    { asset_id: 'A-SRV2', name: 'APP02', mgmt_ip: '10.1.0.21', type: 'server', asset_status: 'in_use', status: 'covered', source_id: 'win-shared', last_seen: new Date(T0 - 5 * 60000).toISOString(), matched_by: 'host-logs' },
    { asset_id: 'A-PC1', name: 'PC-001', mgmt_ip: '10.2.0.5', type: 'workstation', asset_status: 'in_use', status: 'absent', suggested_kind: 'windows' },
    { asset_id: 'A-OLD', name: 'OLD01', type: 'server', asset_status: 'in_stock', status: 'absent', suggested_kind: 'windows' },
  ];
  e.recv('fw-fw-hq-01', 40);
  e.recv('syslog-udp', 1, { parse_error_rate_1h: 0.5, eps_1h: 3, hosts: ['rogue-box'] });
  e.hosts = [{ host: 'rogue-box', ip: '10.9.9.9', src_id: 'syslog-udp', last_seen: '2026-10-17 07:59:00', events: 500 }, { host: 'app02', ip: '10.1.0.21', src_id: 'win-shared', events: 900 }];
  const m = (await e.call('GET /api/soc/collection/assurance', { role: 'viewer', query: { fresh: '1' } })).b;
  assert.equal(m.summary.required, 4, 'workstations (policy) and in-stock assets are not required');
  assert.equal(m.summary.covered, 1); assert.equal(m.summary.silent, 1); assert.equal(m.summary.waiting, 1); assert.equal(m.summary['not-onboarded'], 1);
  assert.equal(m.summary.coverage_pct, 25);
  assert.deepEqual(m.unknown_senders.map((x) => x.host), ['rogue-box'], 'APP02 is known by name; rogue-box is not');
  assert.ok(m.unconfigured.some((u) => u.src_id === 'syslog-udp'), 'catch-all traffic shown');
  // the engineer on the duty desk
  const D = createDuty({ store: e.state, engineers: [e.deps.collectionAssurance.adapter], now: () => e.now });
  await D.patrol('siem');
  const items = D.list({ engineer: 'siem' }).items, by = (k) => items.filter((x) => x.kind === k);
  assert.equal(by('asset-silent')[0].severity, 'critical', 'a silent firewall is critical');
  assert.match(by('asset-silent')[0].title, /FW-HQ-01: stopped sending logs/);
  assert.match(by('never-received')[0].recommendation, new RegExp(ZYB_ORG.platform_addr_re + ':5514'), 'tells exactly what to configure');
  assert.equal(by('not-onboarded')[0].severity, 'high'); assert.equal(by('not-onboarded')[0].target.name, 'APP01');
  assert.equal(by('unknown-sender')[0].severity, 'low');
  assert.ok(by('parse-errors').length === 0, 'catch-all is not a configured source; quality only for configured sources');
  // the firewall comes back: its item clears
  e.inv[0].last_seen = new Date(T0 - 60000).toISOString(); e.now += 600000; await D.patrol('siem');
  assert.equal(D.get(by('asset-silent')[0].id).resolution, 'cleared');
  // everything goes quiet: one critical "collectors quiet" item, the per-asset ones are downgraded
  e.now += 3 * 3600000; for (const a of e.inv) if (a.last_seen) a.last_seen = new Date(T0).toISOString();
  e.live.clear(); e.recv('fw-fw-hq-01', 200);
  await D.patrol('siem');
  const q = D.list({ engineer: 'siem', status: 'open' }).items.find((x) => x.kind === 'collector-quiet');
  assert.ok(q); assert.equal(q.severity, 'critical');
});

test('assurance: nothing connected = not connected; no inventory link = sources only, said so; readiness', async () => {
  const e = await setup({ inv: null });
  const D = createDuty({ store: e.state, engineers: [e.deps.collectionAssurance.adapter], now: () => e.now });
  assert.equal((await D.patrol('siem')).not_connected, true);
  const m = (await e.call('GET /api/soc/collection/assurance', { role: 'viewer', query: { fresh: '1' } })).b;
  assert.equal(m.inventory.connected, false); assert.match(m.inventory.error, /not configured/); assert.equal(m.summary.coverage_pct, null, 'no coverage % without the inventory');
  const { readiness } = require('../engine/duty/readiness');
  const r = await readiness(e.deps, D);
  const s = r.engineers.find((x) => x.id === 'siem');
  assert.equal(s.status, 'blocked'); assert.ok(s.to_fix.some((f) => /onboard\.discovery/.test(f.fix)));
  // policy: admin only, validated
  assert.equal((await e.call('PUT /api/soc/collection/policy', { role: 'operator', body: {} })).s, 403);
  assert.equal((await e.call('PUT /api/soc/collection/policy', { body: { sla_min: { firewall: 1 } } })).s, 400);
  const p = await e.call('PUT /api/soc/collection/policy', { body: { sla_min: { firewall: 30 }, require_workstations: true } });
  assert.equal(p.b.sla_min.firewall, 30); assert.equal(p.b.require_workstations, true); assert.equal(p.b.sla_min.dc, 15);
});
