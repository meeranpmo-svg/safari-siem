// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// secrets.json sealed at rest: round trip, legacy plaintext read, the engine's writers keep every other secret, no
// plaintext copy left behind, a wrong / world-readable key refused, loadConfig reads a sealed file.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');

function setup() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-sec-')), key = path.join(d, 'secrets.key'), sec = path.join(d, 'secrets.json');
  fs.writeFileSync(key, crypto.randomBytes(32).toString('hex') + '\n', { mode: 0o440 });
  process.env.SENTRA_SIEM_SECRETS_KEY = key;
  const SF = require('../engine/secretfile'); SF._reset();
  return { d, key, sec, SF };
}

test('secretfile: sealed on disk, read back, legacy plaintext upgraded on the next write, no plaintext copy', () => {
  const { d, sec, SF } = setup();
  fs.writeFileSync(sec, JSON.stringify({ clickhouse: { user: 'u', password: 'Ch-Pass-1' }, ingest_tokens: { a: 'tok-123456' } }), { mode: 0o600 });
  assert.equal(SF.read(sec).clickhouse.password, 'Ch-Pass-1', 'a plaintext file is still read (migration)');
  SF.write(sec, Object.assign(SF.read(sec), { m365: { client_secret: 'M365-Secret-9' } }));
  const disk = fs.readFileSync(sec, 'utf8');
  assert.ok(!/Ch-Pass-1|tok-123456|M365-Secret-9/.test(disk), 'nothing readable on disk'); assert.match(disk, /"_sealed":"aes-256-gcm\/v1"/);
  assert.equal((fs.statSync(sec).mode & 0o777).toString(8), '600');
  assert.deepEqual(SF.read(sec).m365, { client_secret: 'M365-Secret-9' });
  assert.deepEqual(fs.readdirSync(d).sort(), ['secrets.json', 'secrets.key'], 'no .bak / temp file left');
  // the generic writer used by onboarding / devices / KSC / Zscaler seals it too and keeps no plaintext .bak
  const { writeJsonAtomic } = require('../engine/onboard/store');
  const o = SF.read(sec); o.ksc = { servers: { k1: { password: 'Ksc-Pw-7' } } }; writeJsonAtomic(sec, o);
  assert.ok(!/Ksc-Pw-7/.test(fs.readFileSync(sec, 'utf8'))); assert.equal(SF.read(sec).clickhouse.password, 'Ch-Pass-1', 'other secrets kept');
  assert.ok(!fs.existsSync(sec + '.bak'), 'no plaintext .bak');
  // loadConfig reads the sealed file
  const cfgPath = path.join(d, 'config.json'); fs.writeFileSync(cfgPath, '{}');
  const cfg = require('../engine/config').loadConfig({ configPath: cfgPath, secretsPath: sec });
  assert.equal(cfg.clickhouse.password, 'Ch-Pass-1'); assert.equal(cfg.secrets.ksc.servers.k1.password, 'Ksc-Pw-7');
  assert.ok(!JSON.stringify(cfg).includes('Ch-Pass-1'));
});

test('secretfile: wrong key, changed file and a world-readable key are refused; a link is never written through', () => {
  const { d, key, sec, SF } = setup();
  SF.write(sec, { proxy_secret: 'P'.repeat(32) });
  fs.writeFileSync(key, crypto.randomBytes(32).toString('hex') + '\n'); fs.chmodSync(key, 0o440); SF._reset();
  assert.throws(() => SF.read(sec), /cannot be opened/);
  fs.chmodSync(key, 0o444); SF._reset(); assert.throws(() => SF.read(sec), /readable by other users/);
  fs.chmodSync(key, 0o440); SF._reset();
  const link = path.join(d, 'secrets-link.json'); fs.symlinkSync(path.join(d, 'elsewhere.json'), link);
  assert.throws(() => SF.write(link, {}), /symbolic link/);
  assert.equal(SF.isSecretsPath('/etc/sentra-siem/secrets.json'), true); assert.equal(SF.isSecretsPath('/etc/sentra-siem/config.json'), false);
});

test('secretfile: no key yet (before the update) keeps working in plaintext', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-sec-')); process.env.SENTRA_SIEM_SECRETS_KEY = path.join(d, 'none.key');
  const SF = require('../engine/secretfile'); SF._reset();
  const f = path.join(d, 'secrets.json'); assert.equal(SF.write(f, { a: 1 }).sealed, false); assert.deepEqual(SF.read(f), { a: 1 });
  delete process.env.SENTRA_SIEM_SECRETS_KEY; SF._reset();
});

test('secretfile: writing without a key still works but is warned about (never the content)', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-sec-')), sec = path.join(d, 'secrets.json');
  process.env.SENTRA_SIEM_SECRETS_KEY = path.join(d, 'absent.key');
  const SF = require('../engine/secretfile'); SF._reset();
  const seen = [];
  const r = SF.write(sec, { m365: { client_secret: 'Synthetic-Secret-1' } }, { log: { every: (k, ms, lvl, msg, det) => seen.push({ lvl, msg, det }) } });
  assert.equal(r.sealed, false, 'behaviour kept: stored plaintext');
  assert.equal(seen.length, 1); assert.equal(seen[0].lvl, 'warn'); assert.match(seen[0].msg, /WITHOUT encryption/);
  assert.ok(!JSON.stringify(seen).includes('Synthetic-Secret-1'));
  SF.write(sec, { a: 1 }, { plain: true }); assert.equal(seen.length, 1, 'an explicit plain write is not warned about');
});
