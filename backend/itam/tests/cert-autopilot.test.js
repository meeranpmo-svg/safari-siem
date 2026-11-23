// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Certificate Renewal Autopilot (engine/cert-autopilot.js) over the REAL lifecycle (certs.js + Python rules, cert-issue.js,
// cert-install.js) with SYNTHETIC endpoints: readiness levels and blockers with fixes, the lead-time model learned from history
// (shrunk toward defaults), risk itemised, bottlenecks ranked, bulk enable (blocked refused), a person starts renewals (a manual
// order goes to awaiting-certificate), issued certificates proposed for install (a different person approves), roles, validation
// and the audit record.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createSealer } = require('../engine/discovery/vault');
const { learn } = require('../engine/cert-autopilot');

const PY = process.env.PYTHON || 'python3', DAY = 86400000;
let clock = Date.parse('2026-11-04T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const PRESENT = {};
const cert = (host, days, o) => Object.assign({ ok: true, subject: host, issuer: 'Synthetic Issuing CA', names: [host], name_ok: true, trusted: true, self_signed: false, not_after: clock + days * DAY, key_type: 'rsa', key_bits: 2048, serial: 'S-' + host, fingerprint256: 'FP:' + host, chain: ['Synthetic Issuing CA'] }, o);
const stubRead = async (host, port) => { const p = PRESENT[host + ':' + port]; if (!p) return { ok: false, error: 'ECONNREFUSED' }; return Object.assign({ not_after_iso: new Date(p.not_after).toISOString().slice(0, 10) }, p); };

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const sealer = createSealer({ keyFile: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cap')), 'vault.key'), createKey: true, purpose: 'sentra-itam-pki' });
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, readCert: stubRead, certSealer: sealer });
  return e;
}
const post = (e, p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
async function seed(e) {
  PRESENT['portal.synthetic.test:443'] = cert('portal.synthetic.test', 20);         // manual order, 20 days left, critical
  PRESENT['vpn.synthetic.test:443'] = cert('vpn.synthetic.test', 120);              // AD CS not configured -> blocked
  PRESENT['intranet.synthetic.test:443'] = cert('intranet.synthetic.test', 200);    // self-signed -> blocked
  const ids = {};
  for (const [k, host, kind, dt, crit] of [['portal', 'portal.synthetic.test', 'manual', 'linux-nginx', true], ['vpn', 'vpn.synthetic.test', 'adcs', 'paloalto', false], ['intra', 'intranet.synthetic.test', 'self', 'iis', false]]) {
    const r = await post(e, '/certs/endpoints', { host, port: 443, issuer_kind: kind, deploy_target: dt, critical: crit, owner: 'ali.syn' }); assert.equal(r.status, 200, r.raw); ids[k] = r.json.id;
  }
  assert.equal((await post(e, '/certs/scan', {})).status, 200);
  return ids;
}

test('lead model: defaults with no history, shrunk toward them with a little, learned with enough', () => {
  assert.equal(learn([], 2).median, 2); assert.match(learn([], 2).source, /default/);
  const one = learn([10], 2); assert.ok(one.median > 2 && one.median < 10, 'one run moves it, does not replace it: ' + one.median);
  const many = learn([5, 5, 5, 5, 5, 5, 5, 5, 5], 2); assert.ok(Math.abs(many.median - 5) < 1.2); assert.match(many.source, /learned from 9/);
});

test('readiness, blockers with fixes, risk itemised, bottlenecks, calendar; roles', async (t) => {
  const e = await setup(t); const ids = await seed(e);
  const v = (await e.req('GET', '/certs/autopilot', VIEW)).json;
  assert.equal(v.installed, true); assert.equal(v.kpis.endpoints, 3);
  const row = (id) => v.queue.find((r) => r.id === id);
  assert.equal(row(ids.portal).level, 'assisted', 'a manual order needs a person');
  assert.equal(row(ids.vpn).level, 'blocked');
  assert.ok(row(ids.vpn).steps.some((s) => s.step === 'issued' && s.mode === 'blocked' && /Issuers -> AD CS/.test(s.fix)));
  assert.ok(row(ids.vpn).steps.some((s) => s.step === 'installed' && s.mode === 'blocked' && /Add a device/.test(s.fix)), 'a Palo Alto endpoint with no device set up');
  assert.equal(row(ids.intra).level, 'blocked');
  assert.equal(v.queue[0].id, ids.portal, 'the critical one with 20 days left ranks first');
  const p = row(ids.portal); assert.equal(p.risk, p.risk_why.reduce((s, x) => s + x.points, 0)); assert.ok(p.risk_why.some((x) => /critical/.test(x.label)));
  assert.ok(p.lead_days >= 7 * 2, 'manual default P90 is used: ' + p.lead_days); assert.equal(p.start_now, true, 'lead + margin has run out');
  assert.ok(v.bottlenecks.length >= 2 && v.bottlenecks[0].mode === 'blocked'); assert.equal(v.calendar.length, 13);
  assert.ok(v.brief.some((l) => /should be started now/.test(l)), v.brief.join(' | '));
  assert.equal(v.kpis.coverage, 0);
  assert.equal((await post(e, '/certs/autopilot/enable', { ids: [ids.portal] }, VIEW)).status, 403, 'a viewer cannot switch on automation');
  assert.equal((await post(e, '/certs/autopilot/start', { ids: [ids.portal] }, VIEW)).status, 403);
  assert.equal((await post(e, '/certs/autopilot/settings', { margin_days: 10, version: 0 }, OP)).status, 403, 'settings are admin');
  assert.equal((await post(e, '/certs/autopilot/ask', { question: 'what first?' }, VIEW)).status, 403);
});

test('validation names the field', async (t) => {
  const e = await setup(t); await seed(e);
  let r = await post(e, '/certs/autopilot/enable', {}); assert.equal(r.status, 400); assert.match(r.json.error, /ids/);
  r = await post(e, '/certs/autopilot/enable', { ids: ['bad id!'] }); assert.equal(r.status, 400); assert.match(r.json.error, /ids\[0\]/);
  r = await post(e, '/certs/autopilot/settings', { margin_days: 99, version: 0 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /margin_days/);
});

test('enable: blocked refused with the reason; start: a person starts the renewal; audited', async (t) => {
  const e = await setup(t); const ids = await seed(e);
  const en = (await post(e, '/certs/autopilot/enable', { ids: [ids.portal, ids.vpn] })).json.results;
  assert.equal(en.find((x) => x.id === ids.portal).ok, true); const b = en.find((x) => x.id === ids.vpn); assert.equal(b.ok, false); assert.match(b.error, /blocked: AD CS is not configured/);
  assert.equal(e.app.store.collection('cert_endpoints').get(ids.portal).auto_renew, true);
  const st = (await post(e, '/certs/autopilot/start', { ids: [ids.portal, ids.intra] })).json.results;
  const s1 = st.find((x) => x.id === ids.portal); assert.equal(s1.ok, true, JSON.stringify(st)); assert.equal(s1.status, 'awaiting-certificate', 'a manual order waits for the CA certificate');
  assert.equal(st.find((x) => x.id === ids.intra).ok, false);
  const v = (await e.req('GET', '/certs/autopilot', OP)).json; assert.ok(v.queue.find((r) => r.id === ids.portal).in_flight, 'shown in flight'); assert.equal(v.queue.find((r) => r.id === ids.portal).start_now, false);
  const again = (await post(e, '/certs/autopilot/start', { ids: [ids.portal] })).json.results[0]; assert.equal(again.ok, false); assert.match(again.error, /already in progress/);
  const A = e.app.store.auditTail(300).map((x) => x.action);
  assert.ok(A.includes('certs.autopilot.enable') && A.includes('certs.autopilot.start') && A.includes('certs.endpoint.update') && A.includes('certs.request.create'), A.join(','));
});

test('history teaches the lead model; issued certificates proposed for install, a different person approves', async (t) => {
  const e = await setup(t); const ids = await seed(e);
  const Q = e.app.store.collection('cert_requests');
  for (let i = 0; i < 4; i++) { const t0 = clock - (60 + i) * DAY; Q.put({ id: 'CQ-09' + i + '0', endpoint_id: ids.intra, method: 'manual', status: 'issued', created_ms: t0, names: ['x'], history: [{ at: new Date(t0).toISOString(), to: 'draft' }, { at: new Date(t0 + 2 * DAY).toISOString(), to: 'issued' }] }); }
  Q.put({ id: 'CQ-0990', endpoint_id: ids.intra, method: 'manual', status: 'failed', created_ms: clock - 70 * DAY, names: ['x'], history: [] });
  let v = (await e.req('GET', '/certs/autopilot', OP)).json;
  assert.equal(v.model.issue.manual.n, 4); assert.ok(v.model.issue.manual.median < 7, 'learned: faster than the 7-day default'); assert.equal(v.model.issue.manual.failure_rate, Math.round(2 / 7 * 100));
  // a bound Palo Alto device and an issued certificate for the vpn endpoint
  e.app.store.collection('cert_install_targets').put({ id: 'CT-0001', label: 'PA-EDGE-SYN', kind: 'paloalto', host: '192.0.2.10', port: 443, pin: 'AA', binding: { type: 'ssl-tls-profile', name: 'GP-Portal' }, endpoint_id: ids.vpn, enc: 'sealed-synthetic' });
  Q.put({ id: 'CQ-0500', endpoint_id: ids.vpn, method: 'adcs', status: 'issued', names: ['vpn.synthetic.test'], fingerprint256: 'FP:NEW', not_after: clock + 365 * DAY, created_ms: clock - DAY, history: [] });
  v = (await e.req('GET', '/certs/autopilot', OP)).json;
  const vpn = v.queue.find((r) => r.id === ids.vpn); assert.equal(vpn.install_ready, 'CQ-0500'); assert.ok(vpn.steps.some((s) => s.step === 'installed' && s.mode === 'approval'));
  assert.equal(v.kpis.install_ready, 1);
  const pr = (await post(e, '/certs/autopilot/propose-installs', {})).json; assert.equal(pr.results.length, 1); assert.equal(pr.results[0].ok, true, JSON.stringify(pr));
  const j = e.app.store.collection('cert_install_jobs').get(pr.results[0].job); assert.equal(j.status, 'proposed'); assert.equal(j.requested_by, OP.user);
  assert.equal((await post(e, '/certs/install/jobs/' + j.id + '/approve', {}, OP)).status, 403, 'the proposer cannot approve');
  assert.equal((await e.req('GET', '/certs/autopilot', OP)).json.kpis.install_ready, 0, 'no second proposal');
  assert.ok(e.app.store.auditTail(300).some((x) => x.action === 'certs.autopilot.propose-installs'));
  // settings: admin, versioned
  const s = await post(e, '/certs/autopilot/settings', { margin_days: 14, version: 0 }, ADM); assert.equal(s.status, 200, s.raw); assert.equal(s.json.margin_days, 14);
  assert.equal((await post(e, '/certs/autopilot/settings', { margin_days: 10, version: 0 }, ADM)).status, 409, 'stale version');
});
