// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NetFlow Analytics (engine/soc/flow-analytics.js through engine/soc/flow-analytics-routes.js) and the NetFlow source of the
// Network Flows views (engine/soc/flows.js), on a stub ClickHouse that answers by query tag and SYNTHETIC data:
//   roles: viewer / analyst / operator / admin and every refused case; validation 400s that name the field; an audit record
//   for every change and for the views that name addresses; groups + billing from the administrator's rate only; utilisation
//   only with a known speed; forecast with the minimum-history rule; hour-of-week patterns; alarms with for_min, clear,
//   alert pipeline and the e-mail template (placeholders escaped, no header injection); security detections (port scan, host
//   sweep, unusual outbound volume, threat-intel address) raised through alerts.raise; values passed as parameters only.
const test = require('node:test');
const assert = require('node:assert/strict');
const routes = require('../engine/soc/flow-analytics-routes');
const FA = require('../engine/soc/flow-analytics');
const flows = require('../engine/soc/flows');

const NOW = Date.UTC(2026, 10, 13, 9, 0);
function memState() {
  const cols = {};
  return { collection(n) { const m = cols[n] || (cols[n] = new Map()); return { get: (id) => m.get(id), put: (d) => m.set(d.id, JSON.parse(JSON.stringify(d))), remove: (id) => m.delete(id),
    patch: (id, fn) => { const x = JSON.parse(JSON.stringify(m.get(id))); fn(x); m.set(id, x); return x; }, all: (f) => [...m.values()].filter(f || (() => true)) }; } };
}
function fakeCh(answers) {
  const calls = [];
  return { calls, query: async (sql, params) => { const tag = /^\/\*q:([a-z_0-9]+)\*\//.exec(sql)[1]; calls.push({ tag, sql, params }); const a = answers[tag]; return typeof a === 'function' ? a(params) : (a || []).map((r) => Object.assign({}, r)); } };
}
const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
function harness(answers = {}, extra = {}) {
  const R = {}, audits = [], raised = [], mails = [], reloads = [];
  const ch = fakeCh(answers);
  const netops = { inventory: { list: () => [{ id: 'd1', name: 'RTR-HQ', ip: '192.0.2.1' }] }, poller: { snapshot: (id) => (id === 'd1' ? { interfaces: [{ index: 3, name: 'Gi0/3', speed_mbps: 100 }] } : null) } };
  const deps = Object.assign({ state: memState(), ch, config: { clickhouse: { database: 'siem' } }, now: () => NOW, noTimers: true, netopsInstance: netops,
    alerts: { raise: (a) => { raised.push(a); return { created: true }; } }, intel: { match: (l, ip) => ip === '203.0.113.66', lookup: () => ['bad-ips'] },
    reports: { schedules: { mail: async (m) => { mails.push(m); if (extra.mailFails) throw new Error('SMTP 550'); } } } }, extra.deps || {});
  const N = routes.register({ route: (m, p, fn) => { R[m + ' ' + p] = fn; } }, deps);
  N.collector.reload = () => reloads.push(1);
  const call = async (m, p, opt = {}) => {
    let out = null;
    const role = opt.role || 'admin';
    const ctx = { body: opt.body, query: opt.query || {}, params: opt.params || {}, role, user: opt.user || 'syed', ip: '10.0.0.5', path: p,
      ok: (x) => { out = { status: 200, body: x }; return out; }, fail: (s, msg) => { out = { status: s, error: msg }; return out; },
      need: (r) => { if ((RANK[role] || 0) < RANK[r]) { out = { status: 403, error: 'requires ' + r }; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d }) };
    const fn = R[m + ' /api/soc' + (opt.params && opt.params.id !== undefined ? p.replace(/\/[^/]+$/, '/:id') : p)];
    assert.ok(fn, 'route ' + m + ' ' + p);
    await fn(ctx); return out;
  };
  return { call, audits, raised, mails, ch, N, reloads, deps };
}

test('roles: every route declares who may call it; refused cases', async () => {
  const h = harness();
  for (const [m, p, role] of [['GET', '/netflow/talkers', 'viewer'], ['GET', '/netflow/security', 'viewer'], ['GET', '/netflow/billing', 'analyst'],
    ['POST', '/netflow/groups', 'operator'], ['POST', '/netflow/apps', 'operator'], ['POST', '/netflow/settings', 'operator'], ['POST', '/netflow/exporters', 'operator'],
    ['POST', '/netflow/detection', 'operator'], ['POST', '/netflow/alarms', 'analyst'], ['POST', '/netflow/templates', 'viewer'], ['POST', '/netflow/templates/preview', 'viewer'],
    ['DELETE', '/netflow/groups/g-1', 'operator'], ['DELETE', '/netflow/exporters/x-1', 'operator'], ['DELETE', '/netflow/alarms/al-1', 'analyst']]) {
    const r = await h.call(m, p, { role, body: {}, params: m === 'DELETE' ? { id: 'x-1' } : undefined });
    assert.equal(r.status, 403, `${m} ${p} refused for ${role}`);
  }
  assert.equal(h.audits.length, 0, 'a refused call changes and audits nothing');
  const st = await h.call('GET', '/netflow/status', { role: 'viewer' });
  assert.equal(st.status, 200); assert.equal(st.body.configured, false);
  assert.match(st.body.todo.join(' '), /allow-list/); assert.match(st.body.todo.join(' '), /Enable the flow listeners \(UDP 2055, 4739, 6343\)/);
});

test('exporters (the allow-list) and listener settings: admin, validated, audited, the collector reloads', async () => {
  const h = harness();
  for (const [b, msg] of [[{}, /ip is required/], [{ ip: '999.1.1.1' }, /ip must be an IP address/], [{ ip: '192.0.2.1', sampling: 0 }, /sampling must be at least 1/],
    [{ ip: '192.0.2.1', if_speeds: [{ if_index: 0, mbps: 10 }] }, /if_speeds\[0\]\.if_index must be at least 1/], [{ ip: '192.0.2.1', if_speeds: 'x' }, /if_speeds must be a list/]]) {
    const r = await h.call('POST', '/netflow/exporters', { body: b }); assert.equal(r.status, 400, JSON.stringify(b)); assert.match(r.error, msg);
  }
  const r = await h.call('POST', '/netflow/exporters', { body: { ip: '192.0.2.9', name: 'FW-DR', sampling: 1000, if_speeds: [{ if_index: 2, mbps: 1000, name: 'wan1' }], is_admin: true } });
  assert.equal(r.status, 200); assert.equal(r.body.exporter.is_admin, undefined, 'undeclared field dropped');
  assert.deepEqual(h.audits.at(-1), { a: 'netflow.exporter.add', t: '192.0.2.9', d: { name: 'FW-DR', sampling: 1000, if_speeds: 1 } });
  assert.equal(h.reloads.length, 1, 'the collector picked up the new allow-list');
  assert.equal(h.N.analytics.collectorSettings().exporters[0].ip, '192.0.2.9');
  assert.equal((await h.call('DELETE', '/netflow/exporters/x-192-0-2-9', { params: { id: 'x-192-0-2-9' } })).status, 200);
  assert.equal(h.audits.at(-1).a, 'netflow.exporter.remove');
  assert.equal((await h.call('DELETE', '/netflow/exporters/x-nope', { params: { id: 'x-nope' } })).status, 404);
  assert.equal((await h.call('DELETE', '/netflow/exporters/x', { params: { id: '../etc' } })).status, 400, 'path parameter validated');
  for (const [b, msg] of [[{ ports: { netflow: 514 } }, /ports\.netflow must be 0 \(off\) or 1024-65535/], [{ ports: 'x' }, /ports must be an object/], [{ enabled: 'yes' }, /enabled must be true or false/], [{ raw_per_minute: 99999 }, /raw_per_minute must be at most 5000/]]) {
    const x = await h.call('POST', '/netflow/settings', { body: b }); assert.equal(x.status, 400); assert.match(x.error, msg);
  }
  const s = await h.call('POST', '/netflow/settings', { body: { enabled: true, ports: { netflow: 9995 } } });
  assert.equal(s.status, 200); assert.equal(s.body.settings.enabled, true); assert.deepEqual(s.body.settings.ports, { netflow: 9995, ipfix: 4739, sflow: 6343 });
  assert.equal(h.audits.at(-1).a, 'netflow.settings.save'); assert.deepEqual(h.audits.at(-1).d.changed.sort(), ['enabled', 'ports']);
});

test('groups + billing: admin defines CIDR groups and rates; a bill only from a rate that was set; operator reads, audited', async () => {
  const h = harness({ grp_bytes: [{ ip: '10.10.1.5', dir: 'dst', b: 3e9 }, { ip: '10.10.1.5', dir: 'src', b: 1e9 }, { ip: '10.20.0.7', dir: 'dst', b: 5e8 }, { ip: '10.99.0.1', dir: 'dst', b: 7e8 }] });
  for (const [b, msg] of [[{ name: 'Finance' }, /cidrs is required/], [{ name: 'Finance', cidrs: ['10.10.0.0/33'] }, /cidrs\[0\] "10.10.0.0\/33" is not an IP address or CIDR range/],
    [{ name: 'Finance', cidrs: ['10.10.0.0/16'], rate_per_gb: -1 }, /rate_per_gb must be at least 0/], [{ name: 'Finance', cidrs: ['10.10.0.0/16'], currency: 'riyal' }, /currency must be a 3-letter code/],
    [{ cidrs: ['10.10.0.0/16'] }, /name is required/], [{ name: 'X', cidrs: ['10.0.0.0/8'], kind: 'team' }, /kind must be one of/]]) {
    const r = await h.call('POST', '/netflow/groups', { body: b }); assert.equal(r.status, 400, JSON.stringify(b)); assert.match(r.error, msg);
  }
  const fin = (await h.call('POST', '/netflow/groups', { body: { name: 'Finance', kind: 'department', cidrs: ['10.10.0.0/16'], rate_per_gb: 0.5 } })).body.group;
  await h.call('POST', '/netflow/groups', { body: { name: 'Jeddah branch', kind: 'site', cidrs: ['10.20.0.0/16'] } });
  assert.equal(h.audits.at(-1).a, 'netflow.group.create');
  assert.equal((await h.call('POST', '/netflow/groups', { body: { name: 'finance', cidrs: ['10.30.0.0/16'] } })).status, 400, 'duplicate name');
  const up = await h.call('POST', '/netflow/groups', { body: { id: fin.id, name: 'Finance', cidrs: ['10.10.0.0/16'], rate_per_gb: 0.75 } });
  assert.deepEqual(h.audits.at(-1), { a: 'netflow.group.update', t: fin.id, d: { name: 'Finance', cidrs: 1, rate_per_gb: 0.75, rate_from: 0.5 } }, 'the rate change is in the audit');
  assert.equal(up.status, 200);
  const bill = await h.call('GET', '/netflow/billing', { role: 'operator', query: { month: '2026-11' } });
  assert.equal(bill.status, 200); assert.equal(bill.body.partial, true);
  const f = bill.body.lines.find((l) => l.name === 'Finance'), j = bill.body.lines.find((l) => l.name === 'Jeddah branch');
  assert.deepEqual([f.gb, f.amount, f.currency], [4, 3, 'SAR']); assert.equal(j.amount, null, 'no rate: not billed, never an invented rate'); assert.match(j.note, /no rate per GB/);
  assert.equal(bill.body.total, 3); assert.equal(bill.body.unassigned_private_bytes, 7e8);
  assert.deepEqual(h.audits.at(-1), { a: 'netflow.billing.view', t: '2026-11', d: { exporter: 'all', groups: 2 } });
  assert.equal((await h.call('GET', '/netflow/billing', { role: 'operator', query: { month: '2026-13' } })).status, 400);
  assert.equal((await h.call('GET', '/netflow/billing', { role: 'operator', query: { month: '2027-01' } })).status, 400, 'a month that has not started');
  const use = await h.call('GET', '/netflow/groups', { role: 'viewer', query: { range: '1440' } });
  assert.equal(use.body.groups.find((g) => g.name === 'Finance').in_bytes, 3e9);
  assert.equal((await h.call('GET', '/netflow/groups', { role: 'viewer', query: { range: '15' } })).status, 400, 'range validated');
  // a group an alarm watches cannot be deleted
  await h.call('POST', '/netflow/alarms', { role: 'operator', body: { name: 'Finance heavy', scope: 'group', target: fin.id, metric: 'mbps', threshold: 50 } });
  assert.equal((await h.call('DELETE', '/netflow/groups/' + fin.id, { params: { id: fin.id } })).status, 409);
});

test('custom applications: admin edits the table, validated, audited, used by the classifier first', async () => {
  const h = harness();
  for (const [b, msg] of [[{ name: 'Core' }, /ports or cidrs/], [{ name: 'Core', ports: ['70000'] }, /ports\[0\] "70000" must be a port/], [{ name: 'Core', ports: ['90-80'] }, /ports\[0\]/],
    [{ name: '(overflow)', ports: ['80'] }, /name: may not start/], [{ name: 'Core', proto: 'icmp', ports: ['80'] }, /proto must be one of/]]) {
    const r = await h.call('POST', '/netflow/apps', { body: b }); assert.equal(r.status, 400, JSON.stringify(b)); assert.match(r.error, msg);
  }
  const r = await h.call('POST', '/netflow/apps', { body: { name: 'Core insurance', proto: 'tcp', ports: ['8443', '9000-9010'], cidrs: ['10.50.0.0/24'] } });
  assert.equal(r.status, 200); assert.deepEqual(r.body.app.ports, [[8443, 8443], [9000, 9010]]);
  assert.deepEqual(h.audits.at(-1), { a: 'netflow.app.create', t: r.body.app.id, d: { name: 'Core insurance', proto: 'tcp', ports: 2, cidrs: 1 } });
  const m = h.N.analytics.mapper();
  assert.equal(m.classify({ proto: 6, sport: 50000, dport: 8443, src: '10.1.1.1', dst: '10.50.0.9' }), 'Core insurance');
  assert.equal(m.classify({ proto: 6, sport: 50000, dport: 8443, src: '10.1.1.1', dst: '10.60.0.9' }), 'HTTPS alt', 'outside the range: the well-known name');
  assert.equal(m.classify({ proto: 6, sport: 50000, dport: 9999, app_name: 'ms-teams', src: '10.1.1.1', dst: '10.60.0.9' }), 'ms-teams', 'the exporter\'s NBAR name');
  assert.equal(m.classify({ proto: 6, sport: 50000, dport: 9999, src: '10.1.1.1', dst: '10.60.0.9' }), '', 'unknown stays unclassified - never a guess');
  assert.equal((await h.call('DELETE', '/netflow/apps/' + r.body.app.id, { params: { id: r.body.app.id } })).status, 200);
  assert.equal(h.audits.at(-1).a, 'netflow.app.delete');
});

test('interfaces, top, talkers: utilisation only with a speed; values are parameters; addresses analyst+ and audited', async () => {
  const h = harness({ if_list: [{ exporter: '192.0.2.1', if_index: 3, dir: 'in', bytes: 3.6e9, packets: 1, peak: 6e8 }, { exporter: '192.0.2.1', if_index: 7, dir: 'out', bytes: 1e6, packets: 1, peak: 1e5 }],
    if_total: [{ k: 0, b: 6e8, n: 10 }], top_app: [{ k: 'HTTPS', b: 900, p: 9, n: 3 }, { k: 'DNS', b: 100, p: 1, n: 1 }], top_series: [{ t: 1, k: 'HTTPS', b: 6e5 }],
    talk_src: [{ a: '10.10.1.5', b: 50, p: 1, n: 1, peers: 2, apps: ['HTTPS'] }] });
  const r = await h.call('GET', '/netflow/interfaces', { role: 'viewer', query: { range: '60', exporter: '192.0.2.1' } });
  assert.equal(r.status, 200);
  const i3 = r.body.interfaces.find((x) => x.if_index === 3), i7 = r.body.interfaces.find((x) => x.if_index === 7);
  assert.deepEqual([i3.speed_mbps, i3.if_name, i3.in_peak_mbps, i3.util_in_peak, i3.in_avg_mbps], [100, 'Gi0/3', 80, 80, 8], 'speed from the SNMP poller: 6e8 bytes in a minute = 80 Mbps = 80 %');
  assert.equal(i7.util_out_peak, null, 'no speed: no utilisation, never a guess');
  assert.equal(r.body.total_mbps.length, 60); assert.equal(r.body.total_mbps[0], 80);
  for (const c of h.ch.calls) assert.ok(!c.sql.includes('192.0.2.1'), c.tag + ': the exporter is a parameter');
  assert.equal((await h.call('GET', '/netflow/interfaces', { role: 'viewer', query: { range: '7' } })).status, 400);
  assert.equal((await h.call('GET', '/netflow/interfaces', { role: 'viewer', query: { exporter: "1' OR 1=1" } })).status, 400);
  const t = await h.call('GET', '/netflow/top', { role: 'viewer', query: { by: 'app', range: '60' } });
  assert.deepEqual(t.body.rows.map((x) => [x.label, x.share]), [['HTTPS', 90], ['DNS', 10]]); assert.equal(t.body.series[0].mbps[1], 0.08);
  assert.deepEqual(h.ch.calls.find((c) => c.tag === 'top_series').params.keys.value, ['HTTPS', 'DNS']);
  assert.equal((await h.call('GET', '/netflow/top', { role: 'viewer', query: { by: 'user' } })).status, 400);
  const tk = await h.call('GET', '/netflow/talkers', { role: 'analyst', query: { by: 'src', range: '60' } });
  assert.equal(tk.body.rows[0].group, 'internal'); assert.deepEqual(h.audits.at(-1), { a: 'netflow.talkers.view', t: 'src', d: { range: 60, group: null } });
  assert.equal((await h.call('GET', '/netflow/talkers', { role: 'analyst', query: { group: 'g-none' } })).status, 404);
  const live = await h.call('GET', '/netflow/live', { role: 'viewer' });
  assert.equal(live.body.talkers, null, 'viewer: no addresses in the live view'); assert.deepEqual(live.body.minutes, []);
});

test('forecast: least squares + Holt on daily peaks to 80 / 100 %; minimum-history rule; speed from the exporter setting', async () => {
  const day = 86400000, d0 = Math.floor(NOW / day) * day - 30 * day;
  const peaks = [];
  for (let i = 0; i < 30; i++) peaks.push({ exporter: '192.0.2.1', if_index: 3, dir: 'in', d: (d0 + i * day) / 1000, peak: (30 + i) * 1e6 * 60 / 8 });   // 30 → 59 Mbps on a 100 Mbps link
  for (let i = 0; i < 5; i++) peaks.push({ exporter: '192.0.2.5', if_index: 1, dir: 'out', d: (d0 + i * day) / 1000, peak: 1e6 });
  const h = harness({ fc_peaks: peaks });
  const r = await h.call('GET', '/netflow/forecast', { role: 'viewer' });
  assert.equal(r.status, 200);
  const a = r.body.items.find((x) => x.exporter === '192.0.2.1'), b = r.body.items.find((x) => x.exporter === '192.0.2.5');
  assert.equal(a.unit, '%'); assert.equal(a.forecast.enough, true); assert.equal(a.forecast.slope_per_day, 1);
  assert.equal(a.forecast.to80.linear, 21, '59 % growing 1 %/day reaches 80 % in 21 days'); assert.equal(a.forecast.to100.linear, 41); assert.ok(a.forecast.to80.holt > 0);
  assert.equal(b.forecast.enough, false); assert.match(b.forecast.note, /needs 14 days of daily peaks - 5 so far/); assert.equal(b.unit, 'Mbps'); assert.match(b.speed_note, /needs the interface speed/);
  assert.equal(r.body.items[0].exporter, '192.0.2.1', 'soonest to 80 % first');
  const f = FA.forecastSeries(Array.from({ length: 20 }, (_, i) => ({ day: i * day, v: 50 - i * 0.5 })), { util: true });
  assert.equal(f.to80.linear, null, 'shrinking traffic never reaches 80 %'); assert.equal(f.growing, false);
  assert.equal((await h.call('GET', '/netflow/forecast', { query: { days: '3' } })).status, 400);
});

test('patterns: hour-of-week baseline, deviations, too little history said', async () => {
  const hour = 3600000, start = Math.floor(NOW / hour) * hour - 5 * 7 * 24 * hour, rows = [];
  for (let t = start; t < NOW; t += hour) rows.push({ h: t / 1000, b: 1000 + (new Date(t).getUTCHours() === 10 ? 500 : 0) });
  rows[rows.length - 3].b = 50000;   // a spike in the last week
  const h = harness({ pat_total: rows });
  const r = await h.call('GET', '/netflow/patterns', { role: 'viewer', query: { weeks: '4' } });
  assert.equal(r.body.enough, true); assert.equal(r.body.baseline.length, 168);
  assert.equal(r.body.deviations[0].bytes, 50000); assert.ok(r.body.deviations[0].z >= 3);
  const short = harness({ pat_total: rows.slice(-200) });
  const s = await short.call('GET', '/netflow/patterns', { role: 'viewer' });
  assert.equal(s.body.enough, false); assert.match(s.body.note, /needs two weeks/); assert.deepEqual(s.body.deviations, []);
});

test('alarms + templates: for_min, raised once, cleared, alert pipeline, e-mail rendered with escaped values', async () => {
  const h = harness();
  for (const [b, msg] of [[{ name: 'x', scope: 'interface', metric: 'util_pct', threshold: 80 }, /target is required/], [{ name: 'x', scope: 'interface', target: 'rtr', metric: 'util_pct', threshold: 80 }, /<exporter IP>#<ifIndex>/],
    [{ name: 'x', scope: 'total', metric: 'util_pct', threshold: 80 }, /utilisation % is for interfaces/], [{ name: 'x', scope: 'total', metric: 'mbps', threshold: 'a lot' }, /threshold must be a number/],
    [{ name: 'x', scope: 'total', metric: 'mbps', threshold: 5, recipients: ['noc@corpgroup.test', 'bad address'] }, /recipients: "bad address"/], [{ name: 'x', scope: 'total', metric: 'new_top_talker', threshold: 50 }, /top N \(1-20\)/],
    [{ name: 'x', scope: 'total', metric: 'mbps', threshold: 5, template_id: 'missing' }, /template_id: no such template/]]) {
    const r = await h.call('POST', '/netflow/alarms', { role: 'operator', body: b }); assert.equal(r.status, 400, JSON.stringify(b)); assert.match(r.error, msg);
  }
  for (const [b, msg] of [[{ name: 't', subject: 'a\nBcc: x', body: 'b' }, /subject must be one line/], [{ name: 't', subject: 's', body: '{{password}}' }, /unknown placeholder \{\{password\}\}/], [{ id: 'default', name: 't', subject: 's', body: 'b' }, /default template cannot be changed/]]) {
    const r = await h.call('POST', '/netflow/templates', { role: 'operator', body: b }); assert.equal(r.status, 400); assert.match(r.error, msg);
  }
  const tpl = (await h.call('POST', '/netflow/templates', { role: 'operator', body: { name: 'NOC', subject: 'NOC: {{alarm}} on {{target}}', body: '<b>{{alarm}}</b> {{value}}{{unit}} >= {{threshold}}' } })).body.template;
  assert.equal(h.audits.at(-1).a, 'netflow.template.create');
  const pv = await h.call('POST', '/netflow/templates/preview', { role: 'operator', body: { subject: 'x {{alarm}}', body: '<script>{{alarm}}</script>' } });
  assert.equal(pv.body.html, '&lt;script&gt;Example alarm&lt;/script&gt;', 'template text and values escaped in HTML');
  const al = (await h.call('POST', '/netflow/alarms', { role: 'operator', body: { name: 'WAN <hot>', scope: 'interface', target: '192.0.2.1#3', metric: 'util_pct', dir: 'in', threshold: 80, for_min: 2, severity: 'high', template_id: tpl.id, recipients: ['NOC@corpgroup.test'] } })).body.alarm;
  assert.deepEqual(h.audits.at(-1).d, { name: 'WAN <hot>', scope: 'interface', target: '192.0.2.1#3', metric: 'util_pct', threshold: 80, for_min: 2, enabled: true, recipients: 1 });
  const A = h.N.analytics, min = (k, bytes) => ({ minute: NOW + k * 60000, bytes, packets: 1, flows: 1, exporters: {}, interfaces: [{ exporter: '192.0.2.1', if_index: 3, dir: 'in', bytes }], apps: [], talkers: [], ips: [], app_totals: {}, all_talkers: [] });
  A.onMinute(min(0, 6.75e8)); assert.equal(h.raised.length, 0, 'one minute over: not yet (for_min 2)');
  A.onMinute(min(1, 6.75e8));
  assert.equal(h.raised.length, 1); assert.equal(h.raised[0].rule_id, 'netflow-alarm'); assert.equal(h.raised[0].severity, 3); assert.match(h.raised[0].summary, /util_pct 90 % >= 80 %/);
  A.onMinute(min(2, 7e8)); assert.equal(h.raised.length, 1, 'still over: raised once');
  await new Promise((r) => setImmediate(r));
  assert.equal(h.mails.length, 1); assert.deepEqual(h.mails[0].to, ['noc@corpgroup.test']);
  assert.equal(h.mails[0].subject, 'NOC: WAN <hot> on 192.0.2.1#3'); assert.match(h.mails[0].html, /&lt;b&gt;WAN &lt;hot&gt;&lt;\/b&gt; 90% &gt;= 80/);
  A.onMinute(min(3, 1e7));
  const v = (await h.call('GET', '/netflow/alarms', { role: 'viewer' })).body;
  assert.deepEqual(v.events.map((e) => e.state).sort(), ['cleared', 'raised']); assert.equal(v.events.find((e) => e.state === 'raised').notified, 'sent');
  assert.equal(v.alarms[0].active, false);
  // an alarm on an interface without a known speed says why instead of guessing
  await h.call('POST', '/netflow/alarms', { role: 'operator', body: { name: 'No speed', scope: 'interface', target: '192.0.2.77#1', metric: 'util_pct', threshold: 50 } });
  A.onMinute(min(4, 1e9));
  assert.match((await h.call('GET', '/netflow/alarms', { role: 'viewer' })).body.alarms.find((a) => a.name === 'No speed').why, /no interface speed/);
  assert.equal((await h.call('DELETE', '/netflow/templates/' + tpl.id, { role: 'operator', params: { id: tpl.id } })).status, 409, 'a template in use is kept');
  assert.equal((await h.call('DELETE', '/netflow/alarms/' + al.id, { role: 'operator', params: { id: al.id } })).status, 200);
  assert.equal(h.audits.at(-1).a, 'netflow.alarm.delete');
});

test('security analytics on flows: scan, sweep, outbound volume, threat-intel address raised through the alert pipeline; excluded scanner ignored', async () => {
  const h = harness();
  const A = h.N.analytics, f = (o) => Object.assign({ exporter: '192.0.2.1', proto: 6, tcp_flags: 0x02, sport: 40000, bytes: 60, packets: 1 }, o);
  for (let p = 1; p <= 120; p++) A.observe(f({ src: '10.1.1.66', dst: '10.1.1.10', dport: p }));                 // port scan
  for (let i = 1; i <= 60; i++) A.observe(f({ src: '10.1.1.77', dst: '10.1.2.' + i, dport: 445 }));             // host sweep
  for (let p = 1; p <= 120; p++) A.observe(f({ src: '10.1.1.10', dst: '10.1.1.66', sport: p, dport: 40000 + p, tcp_flags: 0x12 }));   // SYN-ACK replies: not a scan
  A.observe(f({ src: '10.1.1.80', dst: '203.0.113.66', dport: 443, tcp_flags: 0x18, bytes: 5000 }));          // known-bad
  let r = A.onMinute({ minute: NOW, bytes: 0, interfaces: [], ips: [], all_talkers: [] });
  assert.equal(r.detections, 3);
  const ids = h.raised.map((a) => a.rule_id).sort();
  assert.deepEqual(ids, ['netflow-host-sweep', 'netflow-intel-ip', 'netflow-port-scan']);
  const scan = h.raised.find((a) => a.rule_id === 'netflow-port-scan');
  assert.deepEqual([scan.mitre, scan.group.src_ip, scan.source, scan.severity], [['T1046'], '10.1.1.66', 'netflow', 3]); assert.match(scan.summary, /probed 120 ports on 10.1.1.10/);
  assert.equal(h.raised.find((a) => a.rule_id === 'netflow-intel-ip').severity, 4);
  // outbound volume: learns first, then a burst far above the host's own usual minute
  for (let k = 1; k <= 12; k++) { A.observe(f({ src: '10.1.1.90', dst: '198.51.100.9', tcp_flags: 0x18, dport: 443, bytes: 1e6 })); A.onMinute({ minute: NOW + k * 60000, interfaces: [], ips: [], all_talkers: [] }); }
  assert.equal(h.raised.filter((a) => a.rule_id === 'netflow-outbound-volume').length, 0, 'still learning (learn_minutes)');
  assert.equal((await h.call('POST', '/netflow/detection', { body: { learn_minutes: 5 } })).status, 400, 'learn_minutes at least 10');
  const d = await h.call('POST', '/netflow/detection', { body: { learn_minutes: 10, outbound_mb: 100, exclude: ['10.1.1.66/32'] } });
  assert.equal(d.status, 200); assert.equal(h.audits.at(-1).a, 'netflow.detection.save'); assert.deepEqual(h.audits.at(-1).d.changed.sort(), ['exclude', 'learn_minutes', 'outbound_mb']);
  A.observe(f({ src: '10.1.1.90', dst: '198.51.100.9', tcp_flags: 0x18, dport: 443, bytes: 900e6 }));
  for (let p = 1; p <= 120; p++) A.observe(f({ src: '10.1.1.66', dst: '10.1.1.10', dport: p }));   // the excluded scanner
  r = A.onMinute({ minute: NOW + 13 * 60000, interfaces: [], ips: [], all_talkers: [] });
  const ob = h.raised.filter((a) => a.rule_id === 'netflow-outbound-volume');
  assert.equal(ob.length, 1); assert.match(ob[0].summary, /10\.1\.1\.90 sent 900 MB/); assert.deepEqual(ob[0].mitre, ['T1048']);
  assert.equal(h.raised.filter((a) => a.rule_id === 'netflow-port-scan').length, 1, 'the excluded scanner raises nothing');
  assert.equal((await h.call('GET', '/netflow/security', { role: 'viewer' })).status, 403);
  const s = await h.call('GET', '/netflow/security', { role: 'analyst' });
  assert.equal(s.body.items.length, 4); assert.equal(s.body.counts['port-scan'], 1); assert.match(s.body.note, /not proof/);
  assert.deepEqual(h.audits.at(-1), { a: 'netflow.security.view', t: 'detections', d: { items: 4 } });
});

test('Network Flows views: NetFlow as another source, firewall view unchanged, parameters only', async () => {
  const ch = fakeCh({ nf_hist: [{ b: 2, a: 7, by: 7000 }], nf_ports: [{ p: 'tcp', port: 443, n: 7 }], nf_apps: [{ app: 'HTTPS', n: 7 }], nf_exporters: [{ host: '192.0.2.1', n: 7, last: NOW }],
    nf_talkers: [{ src_ip: '10.0.0.5', dst_ip: '198.51.100.1', p: 'tcp', port: 443, app: 'HTTPS', flows: 7, by: 7000 }], nf_conv: [], nf_dev_port: [], nf_dev_app: [], nf_avail: [{ n: 3 }],
    nfd_total: [{ a: 7, by: 7000, first: NOW - 1000, last: NOW }], nfd_src: [{ v: '10.0.0.5', n: 7 }], nfd_dst: [], nfd_svc: [] });
  const R = {}, audits = [];
  flows.register({ route: (m, p, fn) => { R[m + ' ' + p] = fn; } }, { ch, now: () => NOW, config: {} });
  const call = async (p, query, role = 'analyst') => { let out; await R['GET /api/soc' + p]({ query, role, ok: (b) => { out = { status: 200, body: b }; }, fail: (s, m) => { out = { status: s, error: m }; }, audit: (a, t, d) => audits.push({ a, t, d }) }); return out; };
  const s = (await call('/flows/summary', { source: 'netflow', fw: '192.0.2.1', range: '60' })).body;
  assert.equal(s.source, 'netflow'); assert.equal(s.connected, true); assert.equal(s.total, 7); assert.equal(s.hist[2].bytes, 7000); assert.deepEqual(s.countries, []); assert.match(s.note, /no country/);
  assert.equal(s.talkers[0].svc, 'tcp/443 HTTPS'); assert.equal(s.firewalls[0].src_type, 'netflow');
  for (const c of ch.calls) { assert.match(c.sql, /siem\.flow_minute/); assert.ok(!c.sql.includes('192.0.2.1'), c.tag); }
  assert.equal(audits.at(-1).d.source, 'netflow');
  const fw = (await call('/flows/summary', { range: '60' })).body;
  assert.equal(fw.source, 'fw'); assert.equal(fw.netflow_available, true, 'the firewall view says NetFlow data exists');
  assert.deepEqual(audits.at(-1).d, { range: 60, dir: 'in', addresses: true }, 'firewall view audit unchanged');
  assert.equal((await call('/flows/summary', { source: 'pcap' })).status, 400);
  assert.equal((await call('/flows/drill', { source: 'netflow', country: 'RU' })).status, 400);
  const d = (await call('/flows/drill', { source: 'netflow', src: '10.0.0.5', range: '60' })).body;
  assert.equal(d.allow, 7); assert.equal(ch.calls.find((c) => c.tag === 'nfd_total').params.v_src.value, '10.0.0.5');
  const broken = { query: async (sql) => { if (/nf_avail/.test(sql)) throw new Error('Code: 60. Table siem.flow_minute does not exist'); return []; } };
  const R2 = {}; flows.register({ route: (m, p, fn) => { R2[m + ' ' + p] = fn; } }, { ch: broken, now: () => NOW, config: {} });
  let out; await R2['GET /api/soc/flows/summary']({ query: {}, role: 'viewer', ok: (b) => { out = b; }, fail: (st, m) => { out = { st, m }; }, audit() {} });
  assert.equal(out.netflow_available, false, 'before the schema update the firewall view still answers');
});

test('maths: linear regression and Holt', () => {
  const lr = FA.linreg([0, 1, 2, 3], [1, 3, 5, 7]); assert.deepEqual([lr.slope, lr.intercept, lr.r2], [2, 1, 1]);
  const h = FA.holt([10, 12, 14, 16, 18]); assert.ok(h.trend > 1.5 && h.level > 17);
  const t = FA.render({ subject: 'a {{alarm}}\r\nBcc: x', body: '{{value}} {{nope}}' }, { alarm: 'A', value: '<1>' });
  assert.equal(t.subject, 'a A Bcc: x'); assert.equal(t.text, '<1> '); assert.equal(t.html, '&lt;1&gt; ');
});
