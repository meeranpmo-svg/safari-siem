// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Credential security evidence (engine/cred-posture.js + engine/secret-values.js), over HTTP on the real engine:
// stores counted sealed vs clear from the records themselves, secrets.json values sealed in place (proxy_secret readable
// by design and said so), the engine still reads a sealed value, key custody (mode, 256-bit, key id - never the key), the
// encryption self-test (round trip, fresh IV, tamper and move refused), each login's protection in transit (SNMPv2c and a
// database without TLS are findings with their SAMA control), the disk scan finding no secret in clear and then finding
// one that was planted, operator / admin gates, and no secret value anywhere in an answer or the audit trail.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');
const SV = require('../engine/secret-values');
const { registerCredPosture } = require('../engine/cred-posture');

const COMMUNITY = 'Synthetic-Community-7311', DBPASS = 'Synthetic-DbPass-5521', CLAUDE = 'sk-ant-synthetic-test-0000000000';

test('credential evidence: sealed stores, secrets.json, key custody, self-test, transport, disk scan, roles', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const secFile = path.join(e.dir, 'secrets.json');
  fs.writeFileSync(secFile, JSON.stringify({ proxy_secret: 'synthetic-proxy-secret-0123456789', anthropic_api_key: CLAUDE, private_token: 'synthetic-private-token-1' }), { mode: 0o640 });
  process.env.SENTRA_ITAM_SECRETS = secFile; t.after(() => { delete process.env.SENTRA_ITAM_SECRETS; });
  const keyFile = e.app.config.discovery.vault_key_file;
  registerCredPosture(e.app.srv, e.app);
  const adm = (m, p, b) => e.req(m, p, { body: b, user: 'syed', role: 'admin' });
  const op = (m, p, b) => e.req(m, p, { body: b, user: 'siva', role: 'operator' });
  const ok = (r) => { assert.ok(r.status >= 200 && r.status < 300, r.status + ' ' + r.text); return r.json; };

  ok(await adm('POST', '/discovery/credentials', { kind: 'snmp_v2c', label: 'Branch switches v2c', secret: { community: COMMUNITY } }));
  ok(await adm('POST', '/discovery/credentials', { kind: 'snmp_v3', label: 'Core v3', target: { auth_protocol: 'sha256', priv_protocol: 'aes' }, secret: { user: 'itam-disc', auth_password: 'Synthetic-Auth-9999', priv_password: 'Synthetic-Priv-9999' } }));
  ok(await adm('POST', '/discovery/credentials', { kind: 'db_login', label: 'Oracle ERP', target: { engine: 'oracle', service: 'ERP' }, secret: { username: 'zyb_mon', password: DBPASS } }));
  ok(await adm('POST', '/discovery/credentials', { kind: 'db_login', label: 'Postgres BI', target: { engine: 'postgres', tls: 'verify', ca_file: '/etc/ssl/bi-ca.pem' }, secret: { username: 'zyb_mon', password: 'Synthetic-Pg-8812' } }));
  assert.equal((await adm('POST', '/discovery/credentials', { kind: 'db_login', label: 'x', target: { engine: 'mysql', tls: 'maybe' }, secret: { username: 'u', password: 'p' } })).status, 400, 'tls is one of off / require / verify');

  // before sealing: secrets.json values in clear are a finding
  assert.equal((await op('GET', '/security/credentials')).status, 200);
  assert.equal((await e.req('GET', '/security/credentials', { user: 'guest', role: 'viewer' })).status, 403, 'it names systems and weaknesses');
  let r = ok(await op('GET', '/security/credentials'));
  const sf = r.stores.find((s) => s.store === 'secrets.json');
  assert.deepEqual(sf.plaintext_ids.sort(), ['anthropic_api_key', 'private_token']);
  assert.deepEqual(sf.by_design.map((x) => x.name), ['proxy_secret']);
  assert.ok(r.findings.some((f) => f.area === 'Encryption at rest' && /secrets\.json/.test(f.text)));

  // seal in place; the engine reader still gets the value; the file holds no value in clear
  assert.deepEqual(SV.sealFile(secFile, keyFile).sort(), ['anthropic_api_key', 'private_token']);
  const raw = fs.readFileSync(secFile, 'utf8');
  assert.ok(!raw.includes(CLAUDE) && raw.includes('synthetic-proxy-secret-0123456789') && raw.includes('aes-256-gcm/v1'));
  assert.equal(SV.fileValue(secFile, 'anthropic_api_key', keyFile)(), CLAUDE, 'the AI provider still reads its key');
  const { loadConfig } = require('../engine/config');
  const cfgFile = path.join(e.dir, 'config.json'); fs.writeFileSync(cfgFile, JSON.stringify({ discovery: { vault_key_file: keyFile } }));
  assert.equal(loadConfig({ SENTRA_ITAM_CONFIG: cfgFile, SENTRA_ITAM_SECRETS: secFile }).secrets.private_token, 'synthetic-private-token-1');
  assert.throws(() => SV.setValue(secFile, path.join(e.dir, 'no-such.key'), 'netops_token', 'x-synthetic-1'), /refusing to store the value in clear/);
  SV.setValue(secFile, keyFile, 'netops_token', 'synthetic-netops-token-2');
  assert.ok(!fs.readFileSync(secFile, 'utf8').includes('synthetic-netops-token-2'));

  r = ok(await op('GET', '/security/credentials'));
  assert.equal(r.stores.find((s) => s.store === 'secrets.json').plaintext, 0);
  const dcs = r.stores.find((s) => s.store === 'disc_credentials');
  assert.equal(dcs.records, 4); assert.equal(dcs.sealed, 4); assert.equal(dcs.plaintext, 0);
  // key custody: never the key
  assert.equal(r.key.bits, 256); assert.equal(r.key.restricted, true); assert.match(r.key.key_id, /^[0-9a-f]{16}$/);
  assert.ok(!JSON.stringify(r).includes(fs.readFileSync(keyFile, 'utf8').trim()), 'the key is never in the report');
  // self-test
  assert.deepEqual([r.self_test.ok, r.self_test.round_trip, r.self_test.fresh_iv, r.self_test.tamper_refused, r.self_test.move_refused], [true, true, true, true, true]);
  // transport
  const lv = Object.fromEntries(r.transport.credentials.map((c) => [c.label, c.level]));
  assert.deepEqual(lv, { 'Branch switches v2c': 'bad', 'Core v3': 'ok', 'Oracle ERP': 'bad', 'Postgres BI': 'ok' });
  const fdb = r.findings.find((f) => /database login\(s\) without TLS/.test(f.text));
  assert.ok(fdb && fdb.controls.includes('SAMA CSF 3.3.9') && /Oracle ERP/.test(fdb.text));
  assert.ok(r.findings.some((f) => /SNMPv2c/.test(f.text)));
  assert.match(r.integrity, /^[0-9a-f]{64}$/);
  for (const s of [COMMUNITY, DBPASS, CLAUDE, 'Synthetic-Auth-9999']) assert.ok(!JSON.stringify(r).includes(s), 'no secret in the report');

  // disk scan: admin only; nothing in clear; then a planted copy is found by label
  assert.equal((await op('POST', '/security/credentials/scan', {})).status, 403);
  let sc = ok(await adm('POST', '/security/credentials/scan', {}));
  assert.equal(sc.ok, true, JSON.stringify(sc.hits)); assert.ok(sc.secrets_checked >= 9, String(sc.secrets_checked)); assert.ok(sc.files > 0);
  fs.writeFileSync(path.join(e.app.store.dir, 'stray-export.txt'), 'exported: ' + DBPASS + '\n');
  sc = ok(await adm('POST', '/security/credentials/scan', {}));
  assert.equal(sc.ok, false); assert.deepEqual(sc.hits.map((h) => [path.basename(h.file), h.secret]), [['stray-export.txt', 'Oracle ERP · password']]);
  assert.ok(!JSON.stringify(sc).includes(DBPASS));
  assert.equal(ok(await op('GET', '/security/credentials')).last_scan.hits.length, 1, 'the last scan rides the report');
  const aud = JSON.stringify(e.app.store.auditTail(200, (x) => x.action === 'security.credentials.scan'));
  assert.ok(aud.includes('stray-export.txt') && !aud.includes(DBPASS), 'audited by file and label, never the value');
});
