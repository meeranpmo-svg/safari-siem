// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Discovery Studio (engine/discovery-studio.js, pyengine/discovery_studio_rules.py) through the real routes and the REAL discovery
// engine's devices / bulk / merge on SYNTHETIC devices (runs, scopes and credential metadata supplied as synthetic records): a
// recommendation per new device with its reasons (merge on a strong duplicate, approve with an identity, review when seen once with
// none, ignore only when past decisions point there - naive Bayes), bulk groups, a run drop against its own median, failed methods,
// credential health with every point named (and hidden from operators), coverage gaps; applying a group goes through the discovery
// bulk (admin, a person, validated, audited), merge; roles; the AI analyst refused for a viewer.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:disc', role: 'admin' };
const NOW = Date.parse('2026-10-31T09:00:00Z'), DAY = 86400000;
const iso = (t) => new Date(t).toISOString();

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const real = e.app.discovery;
  const obs = (o, ctx) => real.devices.observe(o, Object.assign({ scope_id: 'sc_hq', site: 'Riyadh HQ' }, ctx || {}));
  // past decisions: 12 printers from the guest range ignored, 8 servers approved
  for (let i = 0; i < 12; i++) { const d = obs({ method: 'arp', ip: '10.99.0.' + (10 + i), mac: '02:99:00:00:00:' + String(10 + i).padStart(2, '0'), vendor: 'GuestPrint', type: 'printer' }, { site: 'Guest' }); real.devices.ignore(d.id || real.devices.list((x) => x.ip === '10.99.0.' + (10 + i))[0].id, 'guest printers are not ours (synthetic)', ADM); }
  for (let i = 0; i < 8; i++) { const ip = '10.10.0.' + (10 + i); obs({ method: 'arp', ip, mac: '02:10:00:00:00:' + String(10 + i).padStart(2, '0'), hostname: 'SRV-SYN-' + i, vendor: 'Dell', type: 'server' }); real.devices.approve(real.devices.list((x) => x.ip === ip)[0].id, ADM); }
  // new: 3 servers (identity, seen twice), 1 guest printer, 1 bare IP seen once, 1 with the MAC of an existing asset
  for (let i = 0; i < 3; i++) for (let k = 0; k < 2; k++) obs({ method: 'arp', ip: '10.10.1.' + (10 + i), mac: '02:11:00:00:00:' + String(10 + i).padStart(2, '0'), hostname: 'APP-SYN-' + i, vendor: 'Dell', type: 'server' });
  obs({ method: 'arp', ip: '10.99.0.50', mac: '02:99:00:00:00:50', vendor: 'GuestPrint', type: 'printer' }, { site: 'Guest' });
  obs({ method: 'sweep', ip: '10.10.9.9' });
  e.app.assets.create({ name: 'EXIST-SYN', type: 'server', status: 'in_use', mac: '02:aa:bb:cc:dd:ee' }, ADM);
  obs({ method: 'arp', ip: '10.10.2.2', mac: '02:aa:bb:cc:dd:ee', hostname: 'EXIST-SYN-NIC2', type: 'server' });
  obs({ method: 'unix', ip: '10.10.3.3', mac: '02:33:00:00:00:01', hostname: 'NIX-SYN', type: 'server', extra: { unix: { ssh_banner: 'SSH-2.0-OpenSSH_9.0' } } });
  const runs = [], scopes = [{ id: 'sc_hq', name: 'HQ (synthetic)', status: 'active', site: 'Riyadh HQ', targets: ['10.10.0.0/16'], methods: { sweep: { enabled: true }, snmp: { credential_ids: ['cr_snmp'] }, unix: { enabled: true } }, checklist: {} }];
  for (let i = 0; i < 6; i++) runs.push({ id: 'run' + i, scope_id: 'sc_hq', status: 'done', started_at: iso(NOW - (6 - i) * DAY), devices_seen: i < 5 ? 100 + i : 30, devices_new: i < 5 ? 1 : 0, stats: { sweep: { ok: true }, snmp: i < 5 ? { ok: true } : { ok: false, error_class: 'auth' } } });
  const creds = [{ id: 'cr_snmp', kind: 'snmp_v3', label: 'SNMP HQ (synthetic)', last_tested: { at: iso(NOW - 2 * DAY), ok: false, error_class: 'auth' }, updated_at: iso(NOW - 400 * DAY), created_at: iso(NOW - 400 * DAY) },
    { id: 'cr_old', kind: 'ssh', label: 'Unused SSH (synthetic)', last_tested: null, updated_at: iso(NOW - 10 * DAY) }];
  e.app.discovery = Object.assign({}, real, { listRuns: () => runs.slice().reverse(), listScopes: () => scopes, credentials: () => creds });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call, real };
}
const auditOf = (e, a) => e.app.store.auditTail(500).filter((x) => x.action === a);

test('recommendations with reasons, learnt ignore, groups, run anomaly, method failures, credential health, coverage', async (t) => {
  const { call } = await setup(t);
  let r = await call('GET', '/discovery-studio', undefined, VIEW); assert.equal(r.status, 403);
  r = await call('GET', '/discovery-studio', undefined, ADM); assert.equal(r.status, 200, r.raw);
  const v = r.json, rec = (ip) => v.recommendations.find((x) => x.ip === ip);
  assert.equal(v.learnt.decisions, 20);
  assert.equal(rec('10.10.1.10').recommend, 'approve'); assert.ok(rec('10.10.1.10').why.some((w) => /seen 2 times/.test(w)) && rec('10.10.1.10').why.some((w) => /approved before/.test(w)));
  assert.equal(rec('10.99.0.50').recommend, 'ignore'); assert.match(rec('10.99.0.50').why[0], /people ignored devices like this before/);
  assert.equal(rec('10.10.9.9').recommend, 'review'); assert.match(rec('10.10.9.9').why[0], /seen once/);
  assert.equal(rec('10.10.2.2').recommend, 'merge'); assert.ok(rec('10.10.2.2').merge_into); assert.match(rec('10.10.2.2').why[0], /mac/);
  const g = v.groups.find((x) => x.recommend === 'approve' && x.vendor === 'Dell'); assert.ok(g && g.count >= 3, 'one bulk group for the Dell servers');
  const tr = v.trends.find((x) => x.scope_id === 'sc_hq'); assert.match(tr.flag, /fell from about 10\d to 30/); assert.deepEqual(tr.failed_methods, ['snmp']);
  const sn = v.methods.find((x) => x.method === 'snmp'); assert.equal(sn.failed, 1); assert.equal(sn.errors.auth, 1);
  const c1 = v.credentials.find((x) => x.id === 'cr_snmp');
  assert.ok(c1.why.some((w) => /last test failed/.test(w.text)) && c1.why.some((w) => /rotate it/.test(w.text)) && c1.why.some((w) => /failed in the last run/.test(w.text)));
  assert.equal(c1.score, 100 - c1.why.reduce((a, w) => a + w.points, 0));
  const c2 = v.credentials.find((x) => x.id === 'cr_old'); assert.ok(c2.why.some((w) => /never tested/.test(w.text)) && c2.why.some((w) => /not used by any scope/.test(w.text)));
  assert.ok(v.coverage.some((x) => x.method === 'unix' && x.scope_id === 'sc_hq'), 'SSH found but the scope has no SSH credential');
  assert.equal(v.can_apply, true);
  const o = (await call('GET', '/discovery-studio', undefined, OP)).json;
  assert.equal(o.credentials, undefined, 'credential health is for administrators'); assert.equal(o.can_apply, false);
});

test('apply a group through the discovery bulk (admin, person, validated, audited), merge, AI refused', async (t) => {
  const { e, call, real } = await setup(t);
  const v = (await call('GET', '/discovery-studio', undefined, ADM)).json;
  const ids = v.groups.find((x) => x.recommend === 'approve' && x.vendor === 'Dell').ids;
  let r = await call('POST', '/discovery-studio/apply', { action: 'approve', ids }, OP); assert.equal(r.status, 403);
  r = await call('POST', '/discovery-studio/apply', { action: 'approve', ids }, BOT); assert.equal(r.status, 403, 'an AI identity cannot add assets');
  r = await call('POST', '/discovery-studio/apply', { action: 'delete', ids }, ADM); assert.equal(r.status, 400);
  r = await call('POST', '/discovery-studio/apply', { action: 'approve', ids: ['<bad>'] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /not a device id/);
  r = await call('POST', '/discovery-studio/apply', { action: 'ignore', ids }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await call('POST', '/discovery-studio/apply', { action: 'approve', ids }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.approved, ids.length);
  assert.ok(ids.every((id) => real.devices.get(id).status === 'approved'));
  assert.equal(auditOf(e, 'discovery.studio.apply')[0].detail.approved, ids.length); assert.ok(auditOf(e, 'discovery.bulk.approve').length >= 1, 'the discovery engine wrote its own summary');
  const m = v.recommendations.find((x) => x.recommend === 'merge');
  r = await call('POST', '/discovery-studio/merge', { id: m.id, asset_id: m.merge_into }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(auditOf(e, 'discovery.studio.merge').length, 1);
  r = await call('POST', '/discovery-studio/merge', { id: m.id }, ADM); assert.equal(r.status, 400);
  const after = (await call('GET', '/discovery-studio', undefined, ADM)).json;
  assert.ok(!after.recommendations.some((x) => ids.includes(x.id)), 'applied devices are no longer new');
  r = await call('POST', '/discovery-studio/ai/ask', { question: 'what first?' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/discovery-studio/ai/ask', { question: 'what first?' }, OP); assert.equal(r.status, 503);
});
