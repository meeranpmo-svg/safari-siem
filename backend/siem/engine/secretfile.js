// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * secrets.json sealed at rest. Every password, API key and token the SIEM keeps (ClickHouse, Microsoft 365, AD bind,
 * SMTP, network-device / server logins, Kaspersky, Zscaler, Cloudflare, ManageEngine, intel feeds, the Anthropic key,
 * ingest tokens) is in secrets.json. On disk the file is one AES-256-GCM envelope:
 *     {"_sealed":"aes-256-gcm/v1","iv":"<hex>","tag":"<hex>","data":"<base64>"}
 * The key is /etc/sentra-siem-keys/secrets.key (64 hex characters): owned by root, group sentra-siem, mode 0440, in a folder the
 * service cannot write (sentra-siem.service: ReadWritePaths covers /etc/sentra-siem, not /etc/sentra-siem-keys) - so the engine can
 * read its secrets but cannot replace the key, and the key is kept OUT of the nightly backup archive (zyb-backup keys
 * archive, local only). A copied secrets.json, a backup on the share or a stolen disk image without the key shows nothing.
 *   read(file)          → object (sealed or a legacy plaintext file; ENOENT → null)
 *   write(file, obj)    atomic (temp + rename, 0600), sealed when the key is there; never leaves a plaintext copy
 *   isSecretsPath(file) the writers that handle config.json AND secrets.json use it to pick write()
 * CLI (installed as /usr/local/sbin/sentra-siem-secrets, root):
 *   sentra-siem-secrets status | seal | unseal | get <dotted.key> | set <dotted.key>  (value on stdin, never on the command line)
 *   sentra-siem-secrets merge  (JSON object on stdin, deep-merged)  | keygen (creates the key once)
 * SENTRA_SIEM_SECRETS_KEY=<path> overrides the key path (tests).
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ALG = 'aes-256-gcm/v1', AAD = Buffer.from('sentra-siem-secrets|v1');
const keyPath = () => process.env.SENTRA_SIEM_SECRETS_KEY || '/etc/sentra-siem-keys/secrets.key';
let cache = null;

function loadKey() {
  const p = keyPath();
  if (cache && cache.p === p) return cache.k;
  let st; try { st = fs.statSync(p); } catch (e) { if (e.code === 'ENOENT') return null; throw new Error(`cannot read the secrets key ${p}: ${e.code || e.message}`); }
  if (st.mode & 0o007) throw new Error(`the secrets key ${p} is readable by other users (mode ${(st.mode & 0o777).toString(8)}) - chmod 440 it`);
  const hex = fs.readFileSync(p, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error(`the secrets key ${p} is not 64 hex characters`);
  cache = { p, k: Buffer.from(hex, 'hex') };
  return cache.k;
}
function isSealed(o) { return !!o && typeof o === 'object' && o._sealed === ALG; }
function seal(obj, key) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv); c.setAAD(AAD);
  const data = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj), 'utf8')), c.final()]);
  return { _sealed: ALG, iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), data: data.toString('base64') };
}
function unseal(env, file) {
  const key = loadKey(); if (!key) throw new Error(`${file} is sealed but the key ${keyPath()} is missing - restore it (zyb-restore keys <file>)`);
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(env.iv, 'hex'), { authTagLength: 16 }); d.setAAD(AAD); d.setAuthTag(Buffer.from(env.tag, 'hex'));
    return JSON.parse(Buffer.concat([d.update(Buffer.from(env.data, 'base64')), d.final()]).toString('utf8'));
  } catch (e) { throw new Error(`${file} cannot be opened with ${keyPath()} (wrong key or the file was changed)`); }
}
function read(file) {
  let text; try { text = fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  const o = JSON.parse(text);
  return isSealed(o) ? unseal(o, file) : o;
}
function write(file, obj, opts) {
  let st = null; try { st = fs.lstatSync(file); } catch (e) { /* new file */ }
  if (st && st.isSymbolicLink()) throw new Error(`${file} is a symbolic link - refusing to write secrets through it`);
  const key = opts && opts.plain ? null : loadKey(), body = JSON.stringify(key ? seal(obj, key) : obj, null, key ? 0 : 2) + '\n';
  const t = path.join(path.dirname(file), '.' + path.basename(file) + '.tmp-' + crypto.randomBytes(4).toString('hex'));
  const fd = fs.openSync(t, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try { fs.writeSync(fd, body); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  if (st) { try { fs.chownSync(t, st.uid, st.gid); } catch (e) { /* not root: same owner anyway */ } }
  fs.renameSync(t, file);
  return { sealed: !!key };
}
const isSecretsPath = (file) => /(^|[\\/])secrets[^\\/]*\.json$/i.test(String(file || ''));
function status(file) {
  let o = null, sealed = false, err = ''; try { const t = fs.readFileSync(file, 'utf8'); o = JSON.parse(t); sealed = isSealed(o); } catch (e) { err = e.code || e.message; }
  let key = false, kerr = ''; try { key = !!loadKey(); } catch (e) { kerr = e.message; }
  return { file, exists: !!o || err !== 'ENOENT', sealed, key_path: keyPath(), key_present: key, key_error: kerr || undefined, error: err && err !== 'ENOENT' ? err : undefined };
}

module.exports = { read, write, isSealed, isSecretsPath, status, loadKey, keyPath, _reset: () => { cache = null; } };

// ---- CLI
if (require.main === module) {
  const [cmd, arg] = process.argv.slice(2), file = process.env.SENTRA_SIEM_SECRETS || '/etc/sentra-siem/secrets.json';
  const stdin = () => { try { return fs.readFileSync(0, 'utf8'); } catch (e) { return ''; } };
  const at = (o, k) => k.split('.').reduce((a, x) => (a && typeof a === 'object' ? a[x] : undefined), o);
  const merge = (a, b) => { for (const [k, v] of Object.entries(b || {})) a[k] = v && typeof v === 'object' && !Array.isArray(v) && a[k] && typeof a[k] === 'object' ? merge(a[k], v) : v; return a; };
  try {
    if (cmd === 'status') { console.log(JSON.stringify(status(file))); }
    else if (cmd === 'keygen') {
      const p = keyPath(); if (fs.existsSync(p)) { console.log('key already there: ' + p); process.exit(0); }
      fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o750 });
      fs.writeFileSync(p, crypto.randomBytes(32).toString('hex') + '\n', { mode: 0o440, flag: 'wx' }); console.log('key created: ' + p);
    } else if (cmd === 'unseal') { const o = read(file); if (!o) throw new Error(file + ' not found'); write(file, o, { plain: true }); console.error('UNSEALED (plaintext) - only for a rollback to an older engine; run "sentra-siem-secrets seal" again after'); }
    else if (cmd === 'seal') { const o = read(file); if (!o) throw new Error(file + ' not found'); const r = write(file, o); console.log(r.sealed ? 'sealed: ' + file : 'NOT sealed - no key at ' + keyPath()); }
    else if (cmd === 'get') { const v = at(read(file) || {}, String(arg || '')); if (v === undefined) process.exit(3); process.stdout.write(typeof v === 'string' ? v : JSON.stringify(v)); }
    else if (cmd === 'set') { if (!arg) throw new Error('set <dotted.key> (value on stdin)'); const o = read(file) || {}; const ks = arg.split('.'); let c = o; for (const k of ks.slice(0, -1)) c = c[k] = c[k] && typeof c[k] === 'object' ? c[k] : {}; c[ks[ks.length - 1]] = stdin().replace(/\r?\n$/, ''); write(file, o); console.log('stored ' + arg); }
    else if (cmd === 'merge') { const o = read(file) || {}; write(file, merge(o, JSON.parse(stdin() || '{}'))); console.log('merged into ' + file); }
    else { console.error('usage: sentra-siem-secrets status | keygen | seal | unseal | get <dotted.key> | set <dotted.key> | merge'); process.exit(2); }
  } catch (e) { console.error('sentra-siem-secrets: ' + e.message); process.exit(1); }
}
