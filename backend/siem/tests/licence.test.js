// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Platform licence on the SIEM (engine/licence/routes.js) with a THROWAWAY Ed25519 key made in the test: not enforced without a
// built-in key; with one: a licence signed by the issuer installs (admin or the ITAM service identity, audited) and must list this
// server when it has `servers`; an edited / unsigned / expired / other-server licence is refused naming the reason; no licence ->
// grace (administrators warned) -> locked after 90 days: people refused except the licence routes, service identities pass;
// a clock moved back is a problem; roles. SYNTHETIC names only.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { createState } = require('../engine/soc/state');
const lic = require('../engine/licence/routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const DAY = 86400000, T0 = Date.UTC(2026, 10, 6, 9, 0, 0);
const KP = crypto.generateKeyPairSync('ed25519'), PUB = KP.publicKey.export({ type: 'spki', format: 'pem' });
const sign = (o, k = KP.privateKey) => Object.assign({}, o, { signature: crypto.sign(null, Buffer.from(lic.payloadOf(o)), k).toString('base64') });
const FP = lic.fingerprintOf('siem-syn', 'mid-syn');
const LIC = { licence_id: 'CN-SYN-9', customer: 'Synthetic Customer', issued: '2026-11-01', expires: '2027-11-01', servers: [FP, 'AAAA-BBBB-CCCC-DDDD'] };

function setup(t, key = PUB) {
  const dir = tmpDir('sentra-lic-'); const state = createState({ dir, log: quietLog }); let now = T0;
  t.after(() => { state.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const api = fakeApi(), deps = { state, log: quietLog, config: {}, now: () => now, licenceOpts: { publicKey: key, hostname: 'siem-syn', machineId: 'mid-syn', now: () => now } };
  const L = lic.register(api, deps);
  return { api, L, deps, set: (ms) => { now = ms; deps.siemLicence.status && (deps.siemLicence._c = null); } };
}

test('without a built-in key licensing is not enforced and nothing is ever locked', (t) => {
  const s = setup(t, '');
  assert.equal(s.L.status().enforced, false); assert.equal(s.L.allowed({ user: 'omar.syn', path: '/api/soc/alerts' }), null);
});

test('no licence: grace for 90 days, then people are locked out; licence routes and service identities still pass', async (t) => {
  const s = setup(t);
  let st = s.L.status(); assert.equal(st.gate, 'grace'); assert.equal(st.grace_days_left, 90); assert.match(st.reason, /no licence/);
  assert.equal(s.L.allowed({ user: 'omar.syn', path: '/api/soc/alerts' }), null, 'grace: still works');
  s.set(T0 + 91 * DAY); await new Promise((r) => setTimeout(r, 5));
  const L2 = lic.createSiemLicence(s.deps, Object.assign({}, s.deps.licenceOpts, { now: () => T0 + 91 * DAY }));
  st = L2.status(); assert.equal(st.gate, 'locked', 'the first problem time is kept: ' + JSON.stringify(st));
  assert.match(L2.allowed({ user: 'omar.syn', path: '/api/soc/alerts' }), /licence is not valid/);
  assert.equal(L2.allowed({ user: 'omar.syn', path: '/api/soc/licence' }), null, 'the licence route stays open');
  assert.equal(L2.allowed({ user: 'system:itam-roles', path: '/api/soc/approvers' }), null, 'engine-to-engine service identities keep working');
  assert.equal(L2.allowed({ user: '', path: '/api/soc/alerts' }), null, 'unidentified requests (ingest has its own token) are not this gate\'s');
});

test('install: the signed licence for this server unlocks; edited, other-server, expired and unsigned are refused; roles; audit', async (t) => {
  const s = setup(t);
  const call = (b, role, user) => s.api.call('POST', '/api/soc/licence', { role, user, body: b });
  assert.equal((await call({ licence: sign(LIC) }, 'operator', 'nora.syn')).status, 403, 'operators cannot install');
  let r = await call({ licence: Object.assign(sign(LIC), { customer: 'Edited' }) }, 'admin', 'syed.syn'); assert.equal(r.status, 400); assert.match(r.body.error, /signature does not match/);
  r = await call({ licence: sign(Object.assign({}, LIC, { servers: ['AAAA-BBBB-CCCC-DDDD'] })) }, 'admin', 'syed.syn'); assert.equal(r.status, 400); assert.match(r.body.error, /other servers/);
  r = await call({ licence: sign(Object.assign({}, LIC, { expires: '2026-10-01' })) }, 'admin', 'syed.syn'); assert.equal(r.status, 400); assert.match(r.body.error, /expired/);
  r = await call({ licence: sign(LIC, crypto.generateKeyPairSync('ed25519').privateKey) }, 'admin', 'syed.syn'); assert.equal(r.status, 400, 'signed with another key');
  r = await call({}, 'admin', 'syed.syn'); assert.equal(r.status, 400); assert.match(r.body.error, /^licence/);
  r = await call({ licence: sign(LIC) }, 'admin', 'system:itam-licence'); assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.gate, 'ok');
  assert.ok(s.api.audits.some((a) => a.action === 'licence.install' && a.user === 'system:itam-licence'));
  const g = await s.api.call('GET', '/api/soc/licence', { role: 'viewer', user: 'vera.syn' }); assert.equal(g.status, 200); assert.equal(g.body.fingerprint, FP); assert.equal(g.body.licence.customer, 'Synthetic Customer');
});

test('a licence that later expires, or a clock moved back, starts the grace period', (t) => {
  const s = setup(t);
  s.L.install(sign(LIC), 'syed.syn');
  let L2 = lic.createSiemLicence(s.deps, Object.assign({}, s.deps.licenceOpts, { now: () => Date.UTC(2027, 10, 5) }));
  let st = L2.status(); assert.equal(st.gate, 'grace'); assert.match(st.reason, /expired on 2027-11-01/);
  const L3 = lic.createSiemLicence(s.deps, Object.assign({}, s.deps.licenceOpts, { now: () => T0 - 10 * DAY }));
  st = L3.status(); assert.match(st.reason || '', /clock moved back/);
});
