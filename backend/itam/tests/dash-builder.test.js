// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Custom Dashboards (engine/dash-builder.js) through the real routes on SYNTHETIC records: the starter dashboard computed from the
// platform's data (KPI share against target, gauge, grouped tables, split), the query builder (values, preview, errors naming the
// field), roles (viewer reads, operator builds, another operator cannot change, admin can, a private board is hidden), the daily
// ML (trend withheld below 3 days, then slope + forecast, unusual day after 7), and the AI proposing a widget a person adds.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const T0 = Date.parse('2026-11-08T08:00:00Z'), DAY = 86400000;

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let now = T0;
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => now, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }), dashSdk: o.sdk, dashKey: () => (o.sdk ? 'sk-ant-synthetic' : '') });
  const col = e.app.store.collection('assets');
  const mk = (x, sw) => { const id = e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id; col.put(Object.assign({}, col.get(id), { software: sw, sources: [{ source: 'agent', last_seen: new Date(T0).toISOString() }] })); return id; };
  mk({ name: 'SRV-SYN-1', os: 'Windows Server 2019', mgmt_ip: '10.1.0.1' }, [{ name: 'Kaspersky Endpoint Security for Windows', version: '12' }]);
  mk({ name: 'SRV-SYN-2', os: 'Red Hat Enterprise Linux 9', mgmt_ip: '10.1.0.2' }, [{ name: 'Notepad++' }]);
  mk({ name: 'SRV-SYN-3', os: 'Windows Server 2022', mgmt_ip: '10.1.0.3' }, [{ name: 'Kaspersky Endpoint Security for Windows', version: '12' }]);
  e.app.store.collection('vulnscan_findings').put({ id: 'v1', status: 'open', name: 'OpenSSH < 9.6 (synthetic)', severity: 'high', host: '10.1.0.2', cves: ['CVE-2024-6387'], score: 8.1 });
  e.app.store.collection('vulnscan_findings').put({ id: 'v2', status: 'open', name: 'OpenSSH < 9.6 (synthetic)', severity: 'high', host: '10.1.0.1', cves: ['CVE-2024-6387'], score: 8.1 });
  e.app.store.collection('vulnscan_findings').put({ id: 'v3', status: 'open', name: 'TLS 1.0 enabled (synthetic)', severity: 'medium', host: '10.1.0.3', cves: [] });
  e.app.store.collection('vulnscan_findings').put({ id: 'v4', status: 'fixed', name: 'old', severity: 'critical', host: '10.1.0.3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call, setNow: (x) => { now = x; } };
}

test('starter dashboard computed from the platform\'s own data', async (t) => {
  const { call } = await setup(t);
  assert.equal((await call('POST', '/dash/boards', { name: 'Security overview', starter: true }, VIEW)).status, 403, 'a viewer does not build');
  const r = await call('POST', '/dash/boards', { name: 'Security overview', starter: true }, OP); assert.equal(r.status, 200, r.text);
  const b = (await call('GET', '/dash/boards/' + r.json.board.id, undefined, VIEW)).json, W = (title) => b.widgets.find((w) => w.title === title);
  const edr = W('Endpoint protection installed').data; assert.equal(edr.total, 3); assert.equal(edr.good, 2); assert.equal(edr.pct, 66.7); assert.equal(edr.on_target, false, 'below the 98 % target');
  assert.deepEqual(W('Total unique devices').data.groups.map((g) => [g.key, g.count]), [['Windows', 2], ['Linux', 1]]);
  const top = W('Top vulnerabilities by devices').data.groups; assert.equal(top[0].key, 'CVE-2024-6387'); assert.equal(top[0].count, 2, 'a fixed finding is not counted');
  assert.deepEqual(W('Vulnerability status').data.groups.map((g) => g.key), ['high', 'medium']);
  assert.ok(W('Overall security coverage score').data.pct != null);
});

test('query builder: values, preview, errors naming the field', async (t) => {
  const { call } = await setup(t);
  let r = await call('GET', '/dash/values?dataset=assets&field=os_family', undefined, VIEW); assert.equal(r.status, 200); assert.ok(r.json.values.some((v) => v.key === 'Windows' && v.count === 2));
  assert.equal((await call('GET', '/dash/values?dataset=secrets', undefined, VIEW)).status, 400);
  r = await call('POST', '/dash/preview', { widget: { title: 'Linux without EDR', dataset: 'assets', q: 'os~linux edr:missing', viz: 'kpi' } }, VIEW); assert.equal(r.status, 200, r.text); assert.equal(r.json.data.total, 1);
  r = await call('POST', '/dash/preview', { widget: { title: 'x', dataset: 'vulns', q: 'colour:red', viz: 'kpi' } }, VIEW); assert.equal(r.status, 400); assert.match(r.text, /colour/);
  r = await call('POST', '/dash/preview', { widget: { title: 'x', dataset: 'vulns', viz: 'bar' } }, VIEW); assert.equal(r.status, 400); assert.match(r.text, /group_by/);
  r = await call('POST', '/dash/preview', { widget: { title: 'x', dataset: 'assets', viz: 'gauge' } }, VIEW); assert.equal(r.status, 400); assert.match(r.text, /good_q/);
  r = await call('POST', '/dash/preview', { widget: { title: 'x', dataset: 'vulns', q: 'severity:high', viz: 'list', limit: 50 } }, VIEW); assert.equal(r.status, 400); assert.match(r.text, /limit/);
});

test('roles: owner and admin edit, another operator cannot, a private board is hidden; audited', async (t) => {
  const { call, e } = await setup(t);
  const id = (await call('POST', '/dash/boards', { name: 'Nora private', shared: false }, OP)).json.board.id;
  assert.equal((await call('GET', '/dash/boards/' + id, undefined, OP2)).status, 404, 'a private board is not visible to others');
  assert.ok(!(await call('GET', '/dash/boards', undefined, OP2)).json.boards.some((b) => b.id === id));
  const w = { title: 'Open high findings', dataset: 'vulns', q: 'severity:high', viz: 'kpi' };
  assert.equal((await call('PUT', '/dash/boards/' + id, { widgets: [w], shared: true }, OP)).status, 200);
  assert.equal((await call('PUT', '/dash/boards/' + id, { widgets: [] }, OP2)).status, 403, 'another operator cannot change it');
  assert.equal((await call('PUT', '/dash/boards/' + id, { name: 'Renamed by admin' }, ADM)).status, 200);
  assert.equal((await call('PUT', '/dash/boards/' + id, { widgets: [{ title: 'bad', dataset: 'x', viz: 'kpi' }] }, OP)).status, 400);
  assert.equal((await call('GET', '/dash/boards/' + id, undefined, VIEW)).json.widgets[0].data.total, 2);
  assert.equal((await call('POST', '/dash/boards/' + id + '/delete', undefined, OP2)).status, 403);
  assert.equal((await call('POST', '/dash/boards/' + id + '/delete', undefined, OP)).status, 200);
  const a = e.app.store.auditTail(40).map((x) => x.action); for (const k of ['dash.create', 'dash.update', 'dash.delete']) assert.ok(a.includes(k), k);
});

test('ML per widget: trend withheld below 3 days, then slope and forecast; unusual day after 7', async (t) => {
  const { call, e, setNow } = await setup(t);
  const id = (await call('POST', '/dash/boards', { name: 'Trend' }, OP)).json.board.id;
  await call('PUT', '/dash/boards/' + id, { widgets: [{ id: 'w-open', title: 'Open findings', dataset: 'vulns', q: '', viz: 'kpi' }] }, OP);
  let w = (await call('GET', '/dash/boards/' + id, undefined, VIEW)).json.widgets[0]; assert.equal(w.ml.days, 1); assert.match(w.ml.note, /withheld/);
  // seed six earlier synthetic days of history, then a sudden jump today
  const H = e.app.store.collection('dash_hist'); e.app.store.collection('dash_hist').remove(id + '|w-open|' + new Date(T0).toISOString().slice(0, 10));
  for (let i = 7; i >= 1; i--) { const d = new Date(T0 - i * DAY).toISOString().slice(0, 10); H.put({ id: id + '|w-open|' + d, board: id, widget: 'w-open', day: d, value: 3 + (i % 2) * 0.2 }); }
  for (let i = 0; i < 20; i++) e.app.store.collection('vulnscan_findings').put({ id: 'n' + i, status: 'open', name: 'new (synthetic)', severity: 'low', host: '10.9.9.' + i });
  setNow(T0); w = (await call('GET', '/dash/boards/' + id, undefined, VIEW)).json.widgets[0];
  assert.equal(w.ml.days, 8); assert.ok(w.ml.per_week > 0); assert.ok(w.ml.forecast_30d > 23); assert.equal(w.ml.unusual, true, '23 open findings against a steady ~3 is unusual'); assert.equal(w.ml.direction, 'up');
});

test('AI proposes a widget, validated against the catalog; nothing saved; a bad proposal refused; viewers never reach it', async (t) => {
  let script; const seen = [];
  class Fake { constructor() { this.messages = { create: async (req) => { seen.push(JSON.parse(JSON.stringify(req))); return script(); } }; } }
  const { call, e } = await setup(t, { sdk: Fake });
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  script = () => ({ model: 'claude-opus-5-5', stop_reason: 'tool_use', usage: { input_tokens: 10, output_tokens: 5 }, content: [{ type: 'tool_use', id: 'p1', name: 'propose_widget', input: { title: 'Servers without EDR', dataset: 'assets', q: 'type:server edr:missing', viz: 'kpi', why: 'counts unprotected servers' } }] });
  assert.equal((await call('POST', '/dash/ai/propose', { request: 'servers without endpoint protection' }, VIEW)).status, 403);
  assert.equal(seen.length, 0);
  let r = await call('POST', '/dash/ai/propose', { request: 'servers without endpoint protection' }, OP); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.proposal.dataset, 'assets'); assert.match(r.json.why, /unprotected/); assert.equal(e.app.store.collection('dash_boards').all().length, 0, 'nothing is saved');
  assert.ok(seen[0].tools.length === 1 && seen[0].tools[0].name === 'propose_widget', 'one tool, propose only'); assert.ok(!/SRV-SYN/.test(JSON.stringify(seen[0])), 'the model sees the catalog, never records');
  script = () => ({ stop_reason: 'tool_use', usage: {}, content: [{ type: 'tool_use', id: 'p2', name: 'propose_widget', input: { title: 'x', dataset: 'credentials', viz: 'list' } }] });
  r = await call('POST', '/dash/ai/propose', { request: 'list every stored password' }, OP); assert.equal(r.status, 422); assert.match(r.text, /does not fit the catalog/);
  assert.ok(e.app.store.auditTail(30).some((x) => x.action === 'dash.ai.propose' && x.by === 'nora.syn'));
});
