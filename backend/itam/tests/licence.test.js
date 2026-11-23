// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// The platform licence (engine/licence.js) with a THROWAWAY Ed25519 key made in the test and SYNTHETIC assets: no licence = unlimited
// (the organisation); a licence signed by the issuer installs (administrator, a person, audited) and its limits are measured against
// usage; a changed limit, an unknown key or a bad field is refused naming the field; expired / over a limit is warned, never locked;
// a viewer reads the status, an operator cannot install; the offline licence tool signs what the server verifies.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { payloadOf } = require('../engine/licence');

const T = Date.parse('2026-11-03T08:00:00Z'), DAY = 86400000;
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed.syn', role: 'admin' }, BOT = { user: 'ai:grc', role: 'admin' };
const KP = crypto.generateKeyPairSync('ed25519'), PUB = KP.publicKey.export({ type: 'spki', format: 'pem' });
const sign = (lic, key = KP.privateKey) => Object.assign({}, lic, { signature: crypto.sign(null, Buffer.from(payloadOf(lic)), key).toString('base64') });
const LIC = { licence_id: 'CN-SYN-001', customer: 'Synthetic Customer', edition: 'Cyber Security', modules: ['siem-core', 'incidents'], limits: { users: 2, ips: 3, servers: 'unlimited', network_devices: 10, databases: null }, issued: '2026-11-01', expires: '2027-11-01' };

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lic-')), file = path.join(dir, 'licence.json'); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (let i = 0; i < 5; i++) e.app.store.collection('assets').put({ id: 'A' + i, name: 'SYN-' + i, type: i < 2 ? 'server' : 'switch', status: 'active', mgmt_ip: '192.0.2.' + (10 + i) });
  e.app.store.collection('assets').put({ id: 'R1', name: 'SYN-OLD', type: 'server', status: 'retired', mgmt_ip: '192.0.2.99' });
  for (const u of ['amal.syn', 'bader.syn', 'caro.syn']) e.app.store.audit({ by: u, role: 'operator', ip: '', action: 'asset.edit', target: 'A1', at: new Date(T - DAY).toISOString() });
  e.app.store.audit({ by: 'ai:netops', role: 'operator', ip: '', action: 'asset.edit', target: 'A1', at: new Date(T - DAY).toISOString() });
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3', licenceFile: file, licenceKey: PUB, licenceEnforce: false });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, file, get: (who = VIEW) => call('GET', '/licence', undefined, who), post: (b, who = ADM) => call('POST', '/licence', b, who), audit: (a) => e.app.store.auditTail(200).filter((x) => x.action === a) };
}

test(('no licence installed: unlimited, every module (' + ZYB_ORG.short + ')'), async (t) => {
  const s = await setup(t); const r = await s.get(); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.state, 'unlimited'); assert.equal(r.json.modules, null); assert.ok(Object.values(r.json.limits).every((v) => v === null));
  assert.deepEqual([r.json.usage.ips, r.json.usage.servers, r.json.usage.network_devices, r.json.usage.users], [5, 2, 3, 3], 'retired assets and AI identities are not counted');
  assert.deepEqual(r.json.warnings, []);
});

test('install a signed licence: limits measured, over-limit warned, never locked; audited', async (t) => {
  const s = await setup(t);
  const r = await s.post({ licence: sign(LIC) }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.state, 'valid'); assert.deepEqual(r.json.modules, ['siem-core', 'incidents']); assert.equal(r.json.limits.servers, null, '"unlimited" = no limit'); assert.equal(r.json.limits.ips, 3);
  assert.ok(r.json.warnings.some((w) => /Monitored IP addresses: 5 in use, the licence allows 3\. Nothing is switched off/.test(w)));
  assert.ok(r.json.warnings.some((w) => /Named users: 4 in use, the licence allows 2/.test(w)), 'the three synthetic users plus the administrator who installed it');
  const a = s.audit('licence.install'); assert.equal(a.length, 1); assert.equal(a[0].by, ADM.user); assert.equal(a[0].detail.customer, 'Synthetic Customer');
  assert.equal((await s.get(VIEW)).json.state, 'valid', 'a viewer reads the status');
});

test('refused: a changed limit, another issuer, bad fields, wrong roles', async (t) => {
  const s = await setup(t);
  const forged = Object.assign({}, sign(LIC), { limits: Object.assign({}, LIC.limits, { ips: 100000 }) });
  let r = await s.post({ licence: forged }); assert.equal(r.status, 400); assert.match(r.text, /licence\.signature: the signature does not match/);
  r = await s.post({ licence: sign(LIC, crypto.generateKeyPairSync('ed25519').privateKey) }); assert.equal(r.status, 400); assert.match(r.text, /licence\.signature/);
  r = await s.post({ licence: sign(Object.assign({}, LIC, { limits: { cpus: 4 } })) }); assert.equal(r.status, 400); assert.match(r.text, /licence\.limits\.cpus is not a known limit/);
  r = await s.post({ licence: sign(Object.assign({}, LIC, { limits: { ips: -1 } })) }); assert.equal(r.status, 400); assert.match(r.text, /licence\.limits\.ips must be a whole number/);
  r = await s.post({}); assert.equal(r.status, 400); assert.match(r.text, /licence: the licence document/);
  assert.equal((await s.post({ licence: sign(LIC) }, OP)).status, 403, 'administrators install a licence');
  assert.equal((await s.post({ licence: sign(LIC) }, BOT)).status, 403, 'a service or AI identity cannot');
  assert.equal(s.audit('licence.install').length, 0); assert.ok(!fs.existsSync(s.file), 'nothing refused is kept');
});

test('expired, or a file that no longer verifies: said, not trusted, nothing switched off', async (t) => {
  const s = await setup(t);
  fs.writeFileSync(s.file, JSON.stringify(sign(Object.assign({}, LIC, { expires: '2026-10-01' }))));
  let v = (await s.get()).json; assert.equal(v.state, 'expired'); assert.ok(v.warnings.some((w) => /expired on 2026-10-01\. Nothing is switched off/.test(w)));
  fs.writeFileSync(s.file, JSON.stringify(Object.assign(sign(LIC), { customer: 'Edited Customer' })));
  v = (await s.get()).json; assert.equal(v.state, 'invalid'); assert.ok(v.warnings.some((w) => /does not verify/.test(w)));
});

test('the offline licence tool signs what the server verifies', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lictool-')), tool = path.join(__dirname, '..', '..', '..', 'tools', 'licence', 'licence-tool.js');
  try {
    execFileSync('node', [tool, 'keygen', dir]);
    assert.equal((fs.statSync(path.join(dir, 'licence-private.pem')).mode & 0o777).toString(8), '600', 'the private key is readable by its owner only');
    fs.writeFileSync(path.join(dir, 'req.json'), JSON.stringify(LIC));
    const signed = execFileSync('node', [tool, 'sign', path.join(dir, 'licence-private.pem'), path.join(dir, 'req.json')]).toString();
    fs.writeFileSync(path.join(dir, 'lic.json'), signed);
    assert.match(execFileSync('node', [tool, 'verify', path.join(dir, 'licence-pub.pem'), path.join(dir, 'lic.json')]).toString(), /^valid/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
