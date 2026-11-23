// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Values in /etc/sentra-itam/secrets.json sealed one by one, at rest:
//   {"anthropic_api_key": {"$sealed": "aes-256-gcm/v1", "iv": "…", "tag": "…", "ct": "…"}, "proxy_secret": "…"}
// AES-256-GCM under a purpose subkey of the discovery vault master key (engine/discovery/vault.js createSealer, purpose
// "sentra-itam-secrets-file", AAD "<purpose>|<name>"), so a value cannot be moved to another name and a changed byte fails.
// proxy_secret stays readable ON PURPOSE: nginx holds the same value in clear (/etc/nginx/sentra-itam-proxy-secret.conf, 600)
// to add the header, and the install scripts read it for their smoke checks - sealing it here would protect nothing.
// Readers never fail the engine: a sealed value that cannot be opened (no key, wrong key) reads as '' and the credential
// evidence report (engine/cred-posture.js) says why.
const fs = require('node:fs');
const crypto = require('node:crypto');
const { createSealer } = require('./discovery/vault');

const MARK = 'aes-256-gcm/v1';
const PURPOSE = 'sentra-itam-secrets-file';
const PLAIN_BY_DESIGN = { proxy_secret: 'nginx needs the same value in clear to add the X-Sentra-Proxy-Secret header' };
const DEFAULT_KEY = '/etc/sentra-itam/discovery-vault.key';

const isSealed = (v) => !!(v && typeof v === 'object' && v.$sealed === MARK && v.iv && v.tag && v.ct);
const sealerFor = (keyFile) => createSealer({ keyFile: keyFile || DEFAULT_KEY, createKey: false, purpose: PURPOSE });

function openValue(name, v, sealer) {
  if (isSealed(v)) {
    if (!sealer || !sealer.available()) return '';
    try { return sealer.unseal(name, v); } catch { return ''; }
  }
  return v == null || typeof v === 'object' ? '' : String(v);
}

// every non-empty string value except the plain-by-design ones
function sealObject(obj, sealer) {
  const out = {}, sealed = [];
  for (const [k, v] of Object.entries(obj || {})) {
    if (typeof v === 'string' && v && !PLAIN_BY_DESIGN[k]) { const e = sealer.seal(k, v); out[k] = { $sealed: MARK, iv: e.iv, tag: e.tag, ct: e.ct }; sealed.push(k); } else out[k] = v;
  }
  return { obj: out, sealed };
}

function readRaw(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }

// refuse a symlink; temp file O_EXCL|O_NOFOLLOW with the same owner and mode (never wider than 640); fsync; rename.
// No plaintext backup copy is left behind.
function writeAtomic(file, obj) {
  const K = fs.constants, st = fs.lstatSync(file);
  if (!st.isFile()) throw new Error(file + ' is not a regular file (symlink?) - refusing');
  const tmp = file + '.tmp-' + crypto.randomBytes(6).toString('hex');
  const fd = fs.openSync(tmp, K.O_WRONLY | K.O_CREAT | K.O_EXCL | (K.O_NOFOLLOW || 0), 0o600);
  try {
    try { fs.fchownSync(fd, st.uid, st.gid); } catch { /* not root: keep ours */ }
    fs.fchmodSync(fd, st.mode & 0o640);
    fs.writeSync(fd, JSON.stringify(obj, null, 2) + '\n'); fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, file);
}

function sealFile(file, keyFile) {
  const sealer = sealerFor(keyFile);
  if (!sealer.available()) throw new Error('vault key not usable: ' + sealer.unavailableReason());
  const r = sealObject(readRaw(file), sealer);
  if (r.sealed.length) writeAtomic(file, r.obj);
  return r.sealed;
}

function setValue(file, keyFile, name, value) {
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(name)) throw new Error('bad secret name');
  const obj = readRaw(file);
  if (PLAIN_BY_DESIGN[name]) obj[name] = String(value);
  else if (!value) delete obj[name];
  else {
    const sealer = sealerFor(keyFile);
    if (!sealer.available()) throw new Error('vault key not usable: ' + sealer.unavailableReason() + ' - refusing to store the value in clear');
    const e = sealer.seal(name, String(value)); obj[name] = { $sealed: MARK, iv: e.iv, tag: e.tag, ct: e.ct };
  }
  writeAtomic(file, obj);
}

// what is in the file, never the values
function fileStatus(file, keyFile) {
  const out = { file, exists: false, entries: [] };
  let st; try { st = fs.statSync(file); } catch (e) { out.error = e.code; return out; }
  out.exists = true; out.mode = (st.mode & 0o777).toString(8).padStart(3, '0'); out.uid = st.uid; out.gid = st.gid; out.other_readable = !!(st.mode & 0o007);
  let obj; try { obj = readRaw(file); } catch (e) { out.error = e.code === 'EACCES' ? 'not readable by the engine' : 'not valid JSON'; return out; }
  const sealer = sealerFor(keyFile);
  for (const [k, v] of Object.entries(obj)) {
    if (isSealed(v)) out.entries.push({ name: k, state: sealer.available() && openValue(k, v, sealer) ? 'sealed' : 'sealed-unopenable', alg: 'AES-256-GCM' });
    else if (typeof v === 'string' && v) out.entries.push({ name: k, state: PLAIN_BY_DESIGN[k] ? 'plain-by-design' : 'plaintext', why: PLAIN_BY_DESIGN[k] || null });
  }
  return out;
}

// a getter that re-reads the file when it changes (so `itam-secrets.js set` works without a restart); sealed or legacy
// plaintext; never logged, never returned
function fileValue(file, name, keyFile) {
  let cache = { mtime: -1, v: '' }, sealer = null;
  return () => {
    try {
      const st = fs.statSync(file);
      if (st.mtimeMs !== cache.mtime) { const o = readRaw(file); if (isSealed(o[name]) && !sealer) sealer = sealerFor(keyFile); cache = { mtime: st.mtimeMs, v: openValue(name, o[name], sealer) }; }
    } catch (e) { cache = { mtime: -1, v: '' }; }
    return cache.v;
  };
}

module.exports = { fileValue, MARK, PURPOSE, PLAIN_BY_DESIGN, isSealed, sealerFor, openValue, sealObject, sealFile, setValue, fileStatus, writeAtomic, DEFAULT_KEY };
