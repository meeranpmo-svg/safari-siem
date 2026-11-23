// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Credential security evidence (engine/soc/credposture.js): from a real sealed secrets.json and key on disk - sealed vs
// clear, key custody (256-bit, mode, key id never the key), the AES-256-GCM self-test, per-device SNMP / API / SSH
// protection, weakening switches found with their path, the disk scan (clean, then a planted copy found by area), the
// operator / admin gates, and no secret value in any answer or audit entry.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'siem-credpost-'));
const keyDir = path.join(dir, 'keys'); fs.mkdirSync(keyDir, { mode: 0o750 });
const keyFile = path.join(keyDir, 'secrets.key');
process.env.SENTRA_SIEM_SECRETS_KEY = keyFile;
const SF = require('../engine/secretfile');
const CP = require('../engine/soc/credposture');

const COMM = 'Synthetic-Community-4410', TOKEN = 'synthetic-fortigate-token-7788', CHPASS = 'Synthetic-ClickHouse-9921';
function harness(cfg) {
  const routes = {}, audits = [];
  CP.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { config: cfg, now: () => Date.UTC(2026, 9, 20, 9), log: { error() {} } });
  const call = async (m, p, role = 'operator') => {
    let out = null;
    const ctx = { method: m, path: p, query: {}, role, user: 'syed', need: (r) => { const R = { viewer: 0, analyst: 1, operator: 2, admin: 3 }; if ((R[role] || 0) < R[r]) { out = { status: 403 }; return false; } return true; },
      ok: (b) => { out = { status: 200, body: b }; return out; }, fail: (s, msg) => { out = { status: s, error: msg }; return out; }, audit: (a, t, d) => audits.push({ a, t, d }) };
    await routes[m + ' /api/soc' + p](ctx); return out;
  };
  return { call, audits };
}

test('SIEM credential evidence: sealed file, key custody, self-test, devices, weak switches, scan, roles', async () => {
  const secPath = path.join(dir, 'secrets.json'), state = path.join(dir, 'state'); fs.mkdirSync(state);
  const sec = { clickhouse: { user: 'sentra_siem', password: CHPASS }, netops: { devices: {
    'fw-hq': { api: { token: TOKEN, tls: { fingerprint256: 'AB'.repeat(32) } }, snmp: { version: '3', authKey: 'Synthetic-Auth-1111', privKey: 'Synthetic-Priv-2222' }, ssh: { username: 'ro', password: 'Synthetic-Ssh-3333' } },
    'sw-branch': { snmp: { version: '2c', community: COMM } },
    'pa-dc': { api: { token: 'synthetic-pa-token-5566', tls: { insecure: true } } } } } };
  // no key yet: stored in clear → critical
  SF._reset(); SF.write(secPath, sec);
  const cfg = { _paths: { secrets: secPath }, state_dir: state, data_dir: dir, syslog: { tls: { enabled: false } }, clickhouse: { url: 'http://127.0.0.1:8123' } };
  let h = harness(cfg), r = (await h.call('GET', '/security/credentials')).body;
  assert.ok(r.findings.some((f) => f.sev === 'critical' && /NOT sealed/.test(f.text)));
  // key + seal
  fs.writeFileSync(keyFile, crypto.randomBytes(32).toString('hex') + '\n', { mode: 0o440 }); SF._reset();
  SF.write(secPath, sec);
  assert.ok(!fs.readFileSync(secPath, 'utf8').includes(COMM));
  h = harness(cfg); r = (await h.call('GET', '/security/credentials')).body;
  assert.equal(r.summary.plaintext, 0); assert.equal(r.summary.sealed, r.summary.stored); assert.ok(r.summary.stored >= 10);
  assert.equal(r.key.bits, 256); assert.equal(r.key.restricted, true); assert.match(r.key.key_id, /^[0-9a-f]{16}$/);
  assert.ok(!JSON.stringify(r).includes(fs.readFileSync(keyFile, 'utf8').trim()));
  assert.equal(r.self_test.ok, true); assert.equal(r.self_test.tamper_refused, true); assert.equal(r.self_test.move_refused, true);
  const lv = Object.fromEntries(r.transport.devices.map((d) => [d.id, d.level]));
  assert.deepEqual(lv, { 'fw-hq': 'ok', 'sw-branch': 'bad', 'pa-dc': 'bad' });
  assert.ok(r.findings.some((f) => /secrets\.netops\.devices\.pa-dc\.api\.tls\.insecure/.test(f.text)), 'the switch is named by its path');
  assert.ok(r.findings.some((f) => /SNMPv1\/v2c: sw-branch/.test(f.text) && f.controls.includes('SAMA CSF 3.3.9')));
  assert.ok(r.findings.some((f) => /Syslog is received over UDP\/TCP without TLS/.test(f.text)));
  for (const s of [COMM, TOKEN, CHPASS, 'Synthetic-Ssh-3333']) assert.ok(!JSON.stringify(r).includes(s));
  // roles
  assert.equal((await h.call('GET', '/security/credentials', 'analyst')).status, 403);
  assert.equal((await h.call('POST', '/security/credentials/scan', 'operator')).status, 403);
  // scan: clean, then a planted copy
  let sc = (await h.call('POST', '/security/credentials/scan', 'admin')).body;
  assert.equal(sc.ok, true, JSON.stringify(sc.hits)); assert.ok(sc.secrets_checked >= 8);
  fs.writeFileSync(path.join(state, 'debug-dump.json'), JSON.stringify({ token: TOKEN }));
  sc = (await h.call('POST', '/security/credentials/scan', 'admin')).body;
  assert.equal(sc.ok, false); assert.deepEqual(sc.hits.map((x) => [path.basename(x.file), x.secret]), [['debug-dump.json', 'netops.devices.fw-hq · token']]);
  assert.equal((await h.call('GET', '/security/credentials')).body.last_scan.hits.length, 1);
  assert.ok(!JSON.stringify(h.audits).includes(TOKEN) && JSON.stringify(h.audits).includes('debug-dump.json'));
});
