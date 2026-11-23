// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// DR Studio (engine/dr-studio.js, pyengine/dr_studio_rules.py) through the real routes on SYNTHETIC replication data: Nutanix
// protection domains from the Virtualization DR view and Oracle Data Guard standbys from the SIEM's Oracle summary (both
// stubbed), the 15-minute samples, a rising lag forecast to breach, an unusual lag, flapping, 7-day compliance, readiness with
// every point named (including the DR test), the overall state, nothing invented when no source is connected; recording a DR
// test from DR & BCM Drills, the RPO and drill link (admin, a person), roles, validation and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:dr', role: 'admin' };
const NOW = Date.parse('2026-10-31T09:00:00Z');

function setup(t, { siem = true, ntx = true } = {}) {
  return (async () => {
    const e = await startApp({ noAi: true }); t.after(() => e.close());
    let t0 = NOW;
    const pd = (name, age, rpo, status, why) => ({ name, rpo_min: rpo, age_min: age, status, why, remote_sites: ['DR-SYN'], vms: [1, 2] });
    e.app.addons = e.app.addons || {};
    if (ntx) e.app.addons.virtCapacity = { report: () => ({ dr: { sites: [{ platform_id: 'ntx1', platform: 'Prism HQ (synthetic)', site: 'Riyadh', at: new Date(t0).toISOString(),
      protection_domains: [pd('PD-CLAIMS', 20, 60, 'ok', 'last replicated copy 20 min ago, within RPO 60 min'), pd('PD-ERP', 150, 60, 'late', 'last replicated copy 150 min ago, RPO 60 min (more than 2x)'), Object.assign(pd('PD-LAB', null, 60, 'no-remote', 'snapshots stay on this cluster only - no remote site, so there is no DR copy'), { remote_sites: [] })] }],
      cross: [{ name: 'PD-HR', status: 'both-active', why: 'active on both sites (split brain)' }] } }) };
    let dgLag = 120;
    const siemOracle = async () => (siem ? { ok: true, data: { instances: [{ key: 'drdb|ORCLSB', host: 'drdb', instance: 'ORCLSB', db_name: 'SYNCLM', role: 'PHYSICAL STANDBY', stale: false, dataguard: { role: 'PHYSICAL STANDBY', apply_lag_s: dgLag, transport_lag_s: 30, protection_mode: 'MAXIMUM PERFORMANCE' } }, { key: 'prod|ORCL', host: 'prod', instance: 'ORCL', role: 'PRIMARY', dataguard: { role: 'PRIMARY' } }] } } : { ok: false, error: 'SIEM link not configured' });
    registerDuty(e.app.srv, e.app, { noTimer: true, now: () => t0, python: process.env.PYTHON || 'python3', drSiem: siemOracle });
    const S = e.app.addons.drStudio;
    const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
    return { e, S, call, setT: (x) => { t0 = x; }, setLag: (x) => { dgLag = x; } };
  })();
}
const auditOf = (e, action) => e.app.store.auditTail(300).filter((x) => x.action === action);

test('streams from Nutanix and Data Guard, samples, forecast, anomaly, compliance, readiness, overall state', async (t) => {
  const { e, S, call, setT, setLag } = await setup(t);
  // a week of quiet samples, then the Data Guard lag rises over the last 6 hours
  for (let i = 7 * 96; i > 24; i--) { setT(NOW - i * 900000); setLag(100 + (i % 3) * 10); await S.sample(null); }
  for (let i = 24; i >= 0; i--) { setT(NOW - i * 900000); setLag(200 + (24 - i) * 25); await S.sample(null); }
  setT(NOW);
  const r = await call('GET', '/dr-studio', undefined, VIEW); assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.equal(v.streams.length, 4, '3 protection domains + 1 standby (the primary is not a stream)');
  const dg = v.streams.find((x) => x.tech === 'Oracle Data Guard');
  assert.equal(dg.rpo_s, 900); assert.match(dg.why, /RPO default 15 min/);
  assert.ok(dg.forecast.breach_h > 0 && /passes the RPO in about/.test(dg.forecast.text), 'rising lag forecast: ' + dg.forecast.text);
  assert.ok(dg.anomaly && dg.anomaly.z >= 3, 'unusual for this stream');
  assert.ok(dg.why_score.some((w) => /never DR-tested/.test(w.text)) && dg.why_score.some((w) => /passes the RPO/.test(w.text)));
  assert.equal(dg.readiness, 100 + dg.why_score.reduce((n, w) => n + w.points, 0), 'readiness is 100 minus the named points');
  const lab = v.streams.find((x) => x.system === 'PD-LAB'); assert.ok(lab.why_score.some((w) => /no remote site/.test(w.text)));
  assert.equal(v.overall.state, 'AT RISK', 'a cross-site conflict puts DR at risk'); assert.equal(v.conflicts[0].status, 'both-active');
  assert.ok(v.summary.compliance_7d > 50 && v.summary.samples_7d > 1000);
  assert.equal(v.heat.length, 4); assert.equal(v.heat[0].cells.length, 24);
  assert.equal(v.sources.dataguard.standbys, 1); assert.equal(v.sources.nutanix.sites, 1);
  assert.equal(v.ai.enabled, false);
});

test('nothing connected: NOT MEASURED and the reasons, never a sample stream', async (t) => {
  const { call } = await setup(t, { siem: false, ntx: false });
  const v = (await call('GET', '/dr-studio', undefined, VIEW)).json;
  assert.equal(v.streams.length, 0); assert.equal(v.overall.state, 'NOT MEASURED');
  assert.match(v.sources.nutanix.error, /no Nutanix cluster connected/); assert.match(v.sources.dataguard.error, /SIEM link not configured/);
});

test('DR tests come from DR & BCM Drills; RPO and drill link are admin settings: a person, validation, audit', async (t) => {
  const { e, call } = await setup(t);
  const key = 'dg:drdb|ORCLSB', G = require('../engine/grc').createGrc(e.app);
  let dg = (await call('GET', '/dr-studio', undefined, OP)).json.streams.find((x) => x.key === key);
  assert.equal(dg.last_test, null); assert.ok(dg.why_score.some((w) => /never DR-tested/.test(w.text)));
  // a drill on the database name matches the standby; one on PD-ERP matches the protection domain
  const d1 = G.drillPut({ title: 'Switchover (synthetic)', system: 'SYNCLM', type: 'failover' }, OP); G.drillResult(d1.id, { result: 'pass', executed: '2026-10-20' }, OP);
  const d2 = G.drillPut({ title: 'PD failover (synthetic)', system: 'pd-erp', type: 'failover' }, OP); G.drillResult(d2.id, { result: 'fail', executed: '2026-10-01' }, OP);
  let v = (await call('GET', '/dr-studio', undefined, OP)).json;
  dg = v.streams.find((x) => x.key === key);
  assert.equal(dg.last_test.result, 'pass'); assert.equal(dg.drill_system, 'SYNCLM'); assert.match(dg.last_test.by, /DR & BCM Drills/);
  assert.ok(!dg.why_score.some((w) => /DR-tested|DR test/.test(w.text)), 'a recent passed drill costs nothing');
  assert.ok(v.streams.find((x) => x.system === 'PD-ERP').why_score.some((w) => /last DR test failed/.test(w.text)));
  assert.equal(v.sources.drills.ok, true); assert.equal(v.sources.drills.linked, 2);
  // settings: admin only, a person, validated, audited
  let r = await call('POST', '/dr-studio/settings', { key, rpo_min: 5 }, OP); assert.equal(r.status, 403, 'the RPO is an admin decision');
  r = await call('POST', '/dr-studio/settings', { key, rpo_min: 5 }, BOT); assert.equal(r.status, 403);
  r = await call('POST', '/dr-studio/settings', { key: 'bogus', rpo_min: 5 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /key is not a stream key/);
  r = await call('POST', '/dr-studio/settings', { key, rpo_min: -1 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /rpo_min/);
  r = await call('POST', '/dr-studio/settings', { key }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /required/);
  r = await call('POST', '/dr-studio/settings', { key, rpo_min: 1 }, ADM); assert.equal(r.status, 200);
  dg = (await call('GET', '/dr-studio', undefined, OP)).json.streams.find((x) => x.key === key);
  assert.equal(dg.rpo_s, 60); assert.equal(dg.status, 'breached', '120 s lag against a 1-minute RPO'); assert.doesNotMatch(dg.why, /RPO default/);
  // link the standby to another drill system (the failed one), then unlink
  r = await call('POST', '/dr-studio/settings', { key, drill_system: 'PD-ERP' }, ADM); assert.equal(r.status, 200);
  dg = (await call('GET', '/dr-studio', undefined, OP)).json.streams.find((x) => x.key === key);
  assert.equal(dg.last_test.result, 'fail'); assert.equal(dg.rpo_s, 60, 'the link keeps the RPO');
  r = await call('POST', '/dr-studio/settings', { key, unlink_drill: true }, ADM); assert.equal(r.status, 200);
  dg = (await call('GET', '/dr-studio', undefined, OP)).json.streams.find((x) => x.key === key); assert.equal(dg.last_test.result, 'pass');
  const au = auditOf(e, 'dr.studio.settings');
  assert.equal(au.length, 3); assert.ok(au.some((x) => x.detail.rpo_min.to === 1 && x.by === 'syed' && x.role === 'admin'));
  assert.ok(au.some((x) => x.detail.drill_system.to === 'PD-ERP'));
  r = await call('POST', '/dr-studio/sample', undefined, OP); assert.equal(r.status, 403);
  r = await call('POST', '/dr-studio/sample', undefined, ADM); assert.equal(r.status, 200); assert.equal(r.json.sampled, 4);
  assert.equal(auditOf(e, 'dr.studio.sample').length, 1);
  r = await call('POST', '/dr-studio/ai/ask', { question: 'can we fail over?' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/dr-studio/ai/ask', { question: 'x' }, OP); assert.equal(r.status, 400);
  r = await call('POST', '/dr-studio/ai/ask', { question: 'can we fail over?' }, OP); assert.equal(r.status, 503);
});
