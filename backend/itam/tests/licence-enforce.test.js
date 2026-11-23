// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Licence ENFORCEMENT (engine/licence.js once an issuer key is built in) with a THROWAWAY Ed25519 key and SYNTHETIC names: no
// licence -> grace (admins warned, everything works) -> locked after the grace period: people are refused 403 on every route
// except /licence, service identities still pass; a licence for this server's fingerprint unlocks; one for other servers, an
// expired one or a moved-back clock is a problem; installing is admin-only and audited; the licence tool prints a fingerprint
// and refuses to build in a PRIVATE key.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { payloadOf, fingerprintOf } = require('../engine/licence');

const T0 = Date.parse('2026-11-06T08:00:00Z'), DAY = 86400000;
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed.syn', role: 'admin' };
const KP = crypto.generateKeyPairSync('ed25519'), PUB = KP.publicKey.export({ type: 'spki', format: 'pem' });
const sign = (o) => Object.assign({}, o, { signature: crypto.sign(null, Buffer.from(payloadOf(o)), KP.privateKey).toString('base64') });
const FP = fingerprintOf('itam-syn', 'mid-itam-syn');
const LIC = { licence_id: 'CN-SYN-ENF', customer: 'Synthetic Customer', issued: '2026-11-06', expires: '2029-11-06', servers: [FP] };

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'licenf-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const clock = { t: T0 };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', licenceFile: path.join(dir, 'licence.json'),
    licenceKey: PUB, licenceEnforce: true, licenceHost: 'itam-syn', licenceMachineId: 'mid-itam-syn' });
  const L = e.app.addons.licence;
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, L, clock, call, later: (days) => { clock.t = T0 + days * DAY; } };
}

test('no licence: grace with a warning, then locked for people; /licence and service identities still pass', async (t) => {
  const s = await setup(t);
  let r = await s.call('GET', '/licence', undefined, VIEW); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.state, 'unlicensed'); assert.equal(r.json.enforcement.gate, 'grace'); assert.equal(r.json.enforcement.grace_days_left, 90); assert.equal(r.json.fingerprint, FP);
  assert.match(r.json.warnings[0], /Licence problem: no licence is installed/);
  assert.ok(s.e.app.store.auditTail(50).some((a) => a.action === 'licence.problem'), 'the first problem is audited');
  assert.equal((await s.call('GET', '/assets', undefined, VIEW)).status, 200, 'grace: everything works');
  s.later(89); assert.equal((await s.call('GET', '/assets', undefined, VIEW)).status, 200, 'day 89 of the 90-day grace: still works');
  s.later(91);
  r = await s.call('GET', '/assets', undefined, OP); assert.equal(r.status, 403); assert.match(r.text, /licence is not valid/);
  r = await s.call('GET', '/licence', undefined, VIEW); assert.equal(r.status, 200); assert.equal(r.json.enforcement.gate, 'locked');
  assert.equal(s.L.allowed({ who: { user: 'system:itam-roles' }, path: '/assets' }), null, 'service identities keep running');
  r = await s.call('POST', '/licence', { licence: sign(LIC) }, OP); assert.equal(r.status, 403, 'operators cannot install');
  r = await s.call('POST', '/licence', { licence: sign(LIC) }, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.enforcement.gate, 'ok'); assert.equal(r.json.state, 'valid');
  assert.ok(s.e.app.store.auditTail(50).some((a) => a.action === 'licence.install' && a.by === 'syed.syn'));
  assert.equal((await s.call('GET', '/assets', undefined, OP)).status, 200, 'unlocked');
});

test('refused: a licence for other servers, an expired one, an edited one', async (t) => {
  const s = await setup(t);
  let r = await s.call('POST', '/licence', { licence: sign(Object.assign({}, LIC, { servers: ['AAAA-BBBB-CCCC-DDDD'] })) }, ADM); assert.equal(r.status, 400); assert.match(r.text, /licence\.servers.*other servers/);
  r = await s.call('POST', '/licence', { licence: sign(Object.assign({}, LIC, { expires: '2026-10-01' })) }, ADM); assert.equal(r.status, 400); assert.match(r.text, /licence\.expires/);
  r = await s.call('POST', '/licence', { licence: Object.assign(sign(LIC), { expires: '2099-01-01' }) }, ADM); assert.equal(r.status, 400); assert.match(r.text, /licence\.signature/);
  r = await s.call('POST', '/licence', { licence: sign(Object.assign({}, LIC, { servers: ['not a fp!'] })) }, ADM); assert.equal(r.status, 400); assert.match(r.text, /licence\.servers must be/);
});

test('a licence that expires later, or a clock moved back, starts the grace period', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('POST', '/licence', { licence: sign(LIC) }, ADM)).status, 200);
  s.later(3 * 365 + 5); let st = s.L.status(); assert.equal(st.enforcement.gate, 'grace'); assert.match(st.enforcement.reason, /expired on 2029-11-06/);
  s.later(-10); st = (s.e.app.addons.licence.status(), s.L.status());
  assert.match(st.enforcement.reason || '', /clock moved back|expired/);
});

test('licence tool: fingerprint prints a grouped fingerprint; set-public-key refuses a private key', () => {
  const tool = path.join(__dirname, '..', '..', '..', 'tools', 'licence', 'licence-tool.js');
  assert.match(execFileSync(process.execPath, [tool, 'fingerprint'], { encoding: 'utf8' }), /[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lictool-')); const priv = path.join(dir, 'p.pem');
  fs.writeFileSync(priv, KP.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  let err = ''; try { execFileSync(process.execPath, [tool, 'set-public-key', priv], { encoding: 'utf8', stdio: 'pipe' }); } catch (e) { err = String(e.stderr); }
  assert.match(err, /private/i); fs.rmSync(dir, { recursive: true, force: true });
});
