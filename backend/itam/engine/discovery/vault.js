// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Discovery credential vault — WRITE-ONLY, AES-256-GCM (same pattern as sentra-infra probe/vault.js).
 *   Master key: 32 random bytes as 64 hex characters in a 0600 file (config discovery.vault_key_file). Created on first
 *   use when the directory is writable; on the platform server install.sh creates it (see docs/DISCOVERY.md).
 *   Records (store collection "disc_credentials"): { id, kind, label, target{public, non-secret connection params},
 *   enc{iv, tag, ct}, version, fingerprint, created_*, updated_*, last_tested{at, ok, latency_ms, error_class} }.
 *   AAD = "sentra-itam-discovery|<id>|<version>" so ciphertexts cannot be swapped between records.
 *
 *   The API only ever sees view(): id, kind, label, target, set:true, fingerprint (HMAC of the secret under a key
 *   derived from the master key — shows that a value changed, reveals nothing), version, last_tested, who/when.
 *   open(id) returns the plaintext to engine code only, registers every secret string with the scrubber, and the
 *   caller must release() it when done. Secrets are never logged, audited or returned.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ID_RE = /^cr_[0-9a-f]{12}$/;
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const str = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

// kind → { secret fields (required unless optional), target (public) field validators }
const URL_RE = /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/[^\s]*)?$/;
const HOST_RE = /^[A-Za-z0-9.-]{1,253}$/;
const LDAP_URL_RE = /^ldaps?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/?$/;
const AWS_REGION_RE = /^[a-z]{2}(-gov)?-[a-z]+-\d$/;
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PATH_RE = /^\/[A-Za-z0-9._/-]{1,250}$/;
const FP_RE = /^([0-9A-Fa-f]{2}:?){32}$/;

const KINDS = {
  snmp_v2c: { secret: { community: { max: 128 } }, target: { port: 'port' } },
  snmp_v3: {
    secret: { user: { max: 64 }, auth_password: { max: 128, min: 8 }, priv_password: { max: 128, min: 8, optional: true } },
    target: { auth_protocol: ['sha', 'sha256'], priv_protocol: ['aes', 'none'], port: 'port' },
  },
  ssh: { secret: { username: { max: 64 }, password: { max: 256, optional: true }, private_key: { max: 16384, optional: true } }, target: { port: 'port' } },
  // read-only inventory logins used by the active scan (methods/login.js): one credential per database engine
  // tls: off (legacy, reported as unencrypted in transit) | require (encrypted, server certificate not checked) | verify
  // (encrypted, certificate checked against ca_file or the system CAs, host name matched). Oracle uses TCPS for both.
  db_login: { secret: { username: { max: 128 }, password: { max: 256 } }, target: { engine: ['oracle', 'mssql', 'mysql', 'postgres'], port: 'port', service: 'dbname', database: 'dbname', tls: ['off', 'require', 'verify'], ca_file: 'path' } },
  storage_api: { secret: { username: { max: 128 }, password: { max: 256 } }, target: { platform: ['ontap', 'msa'], port: 'port' } },
  winrm: { secret: { username: { max: 128 }, password: { max: 256 } }, target: { transport: ['https', 'http'], port: 'port' }, future: true },
  ldap: { secret: { bind_dn: { max: 512 }, password: { max: 256 } }, target: { servers: 'ldapurls', ip: 'ip', base_dn: 'dn', ca_file: 'path' } },
  vcenter: { secret: { username: { max: 128 }, password: { max: 256 } }, target: { base_url: 'url', ca_file: 'path', tls_fingerprint: 'fp' } },
  nutanix: { secret: { username: { max: 128 }, password: { max: 256 } }, target: { base_url: 'url', ca_file: 'path', tls_fingerprint: 'fp' } },
  cucm_axl: { secret: { username: { max: 128 }, password: { max: 256 } }, target: { host: 'host', port: 'port', axl_version: 'axlver', ca_file: 'path' } },
  azure: { secret: { client_secret: { max: 512 } }, target: { tenant_id: 'guid', client_id: 'guid', subscriptions: 'guids' } },
  aws: { secret: { access_key_id: { max: 128 }, secret_access_key: { max: 256 } }, target: { regions: 'regions' } },
};
// connection-target fields: changing any of them re-points where the stored secret is sent, so the secret must be
// re-entered in the same request (otherwise an admin session/CSRF could redirect a saved password to a new host).
const CONNECTION_TARGET_FIELDS = ['base_url', 'servers', 'host', 'ip', 'port', 'ca_file', 'tls_fingerprint', 'transport', 'tls'];
const REQUIRED_TARGET = { db_login: ['engine'], storage_api: ['platform'], ldap: ['servers', 'base_dn'], vcenter: ['base_url'], nutanix: ['base_url'], cucm_axl: ['host'], azure: ['tenant_id', 'client_id'], aws: ['regions'] };

function normTarget(kind, raw) {
  const spec = KINDS[kind].target;
  const b = isObj(raw) ? raw : {};
  const out = {};
  for (const [k, v] of Object.entries(spec)) {
    const x = b[k];
    if (x === undefined || x === null || x === '' || (Array.isArray(x) && !x.length)) continue;
    if (Array.isArray(v)) { const s = str(x, 20).toLowerCase(); if (!v.includes(s)) throw bad(`target.${k} must be one of ${v.join(', ')}`); out[k] = s; continue; }
    switch (v) {
      case 'port': { const n = Number(x); if (!Number.isInteger(n) || n < 1 || n > 65535) throw bad(`target.${k} must be a port 1-65535`); out[k] = n; break; }
      case 'url': { const s = str(x, 300).replace(/\/+$/, ''); if (!URL_RE.test(s)) throw bad(`target.${k} must be an https:// URL`); out[k] = s; break; }
      case 'host': { const s = str(x, 253); if (!HOST_RE.test(s)) throw bad(`target.${k} must be a host name or IP`); out[k] = s; break; }
      case 'ip': { const s = str(x, 40); if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) throw bad(`target.${k} must be an IPv4 address`); out[k] = s; break; }
      case 'path': { const s = str(x, 260); if (!PATH_RE.test(s)) throw bad(`target.${k} must be an absolute file path`); out[k] = s; break; }
      case 'fp': { const s = str(x, 100); if (!FP_RE.test(s)) throw bad(`target.${k} must be a SHA-256 fingerprint (64 hex)`); out[k] = s.replace(/:/g, '').toLowerCase(); break; }
      case 'dn': { const s = str(x, 512); if (!/^[A-Za-z]+=[^,]+(,\s*[A-Za-z]+=[^,]+)*$/.test(s)) throw bad(`target.${k} must be a DN such as DC=corp-hq,DC=com`); out[k] = s; break; }
      case 'guid': { const s = str(x, 40); if (!GUID_RE.test(s)) throw bad(`target.${k} must be a GUID`); out[k] = s.toLowerCase(); break; }
      case 'guids': { if (!Array.isArray(x) || x.length > 50) throw bad(`target.${k} must be a list of GUIDs`); out[k] = x.map((g) => { const s = str(g, 40); if (!GUID_RE.test(s)) throw bad(`target.${k} must be GUIDs`); return s.toLowerCase(); }); break; }
      case 'regions': { const arr = Array.isArray(x) ? x : [x]; if (arr.length > 20) throw bad('target.regions: at most 20'); out[k] = arr.map((r) => { const s = str(r, 30).toLowerCase(); if (!AWS_REGION_RE.test(s)) throw bad(`target.regions: "${s}" is not an AWS region`); return s; }); break; }
      case 'ldapurls': { const arr = Array.isArray(x) ? x : [x]; if (arr.length > 6) throw bad('target.servers: at most 6'); out[k] = arr.map((u) => { const s = str(u, 300); if (!LDAP_URL_RE.test(s)) throw bad(`target.servers: "${s}" must be ldaps://host:636 or ldap://host:389 (StartTLS)`); return s; }); break; }
      case 'dbname': { const s = str(x, 64); if (!/^[A-Za-z0-9_.$#-]{1,64}$/.test(s)) throw bad(`target.${k} must be a name (letters, digits, _ . $ # -)`); out[k] = s; break; }
      case 'axlver': { const s = str(x, 10); if (!/^\d{1,2}\.\d$/.test(s)) throw bad('target.axl_version must look like 12.5'); out[k] = s; break; }
      default: break;
    }
  }
  for (const r of REQUIRED_TARGET[kind] || []) if (out[r] === undefined) throw bad(`target.${r} is required for ${kind}`);
  return out;
}

function normSecret(kind, raw, prev) {
  const spec = KINDS[kind].secret;
  const b = isObj(raw) ? raw : {};
  const out = {};
  for (const [k, rule] of Object.entries(spec)) {
    let v = b[k];
    if ((v === undefined || v === '') && prev && prev[k] !== undefined) { out[k] = prev[k]; continue; } // update keeps
    if (v === undefined || v === null || v === '') { if (!rule.optional) throw bad(`secret.${k} is required for ${kind}`); continue; }
    if (typeof v !== 'string') throw bad(`secret.${k} must be a string`);
    if (k !== 'private_key' && /[\r\n\0]/.test(v)) throw bad(`secret.${k} must not contain line breaks`);
    if (v.length > rule.max) throw bad(`secret.${k} is too long`);
    if (rule.min && v.length < rule.min) throw bad(`secret.${k} must be at least ${rule.min} characters`);
    out[k] = v;
  }
  if (kind === 'ssh' && !out.password && !out.private_key) throw bad('secret.password or secret.private_key is required for ssh');
  return out;
}

function loadKey(file, create) {
  let hex;
  try { hex = fs.readFileSync(file, 'utf8').trim(); } catch (e) {
    if (e.code !== 'ENOENT' || !create) return { error: `vault key ${file} not readable (${e.code})` };
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      hex = crypto.randomBytes(32).toString('hex');
      fs.writeFileSync(file, hex + '\n', { mode: 0o600, flag: 'wx' });
    } catch (e2) { return { error: `vault key ${file} could not be created (${e2.code || 'error'})` }; }
  }
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return { error: 'vault key file must contain 64 hex characters' };
  if (process.platform !== 'win32') {
    try { const st = fs.statSync(file); if (st.mode & 0o077) return { error: `vault key ${file} must be mode 600` }; } catch { /* ignore */ }
  }
  return { key: Buffer.from(hex, 'hex') };
}

function createVault({ store, keyFile, createKey = true, scrubber }) {
  const col = store.collection('disc_credentials');
  const k = loadKey(keyFile, createKey);
  const key = k.key || null;
  const fpKey = key ? crypto.createHmac('sha256', key).update('sentra-itam-discovery-fingerprint').digest() : null;
  const aad = (id, version) => Buffer.from(`sentra-itam-discovery|${id}|${version}`);
  function need() { if (!key) throw bad(`credential vault unavailable: ${k.error}`, 503); }

  function seal(id, version, secret) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(aad(id, version));
    const ct = Buffer.concat([c.update(JSON.stringify(secret), 'utf8'), c.final()]);
    return { iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), ct: ct.toString('base64') };
  }
  function unseal(rec) {
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(rec.enc.iv, 'hex'), { authTagLength: 16 });
    d.setAAD(aad(rec.id, rec.version));
    d.setAuthTag(Buffer.from(rec.enc.tag, 'hex'));
    try { return JSON.parse(Buffer.concat([d.update(Buffer.from(rec.enc.ct, 'base64')), d.final()]).toString('utf8')); } catch { throw bad(`credential ${rec.id} failed authentication (vault key changed?)`, 500); }
  }
  function fingerprint(secret) {
    const canon = JSON.stringify(Object.keys(secret).sort().map((x) => [x, secret[x]]));
    return crypto.createHmac('sha256', fpKey).update(canon).digest('hex').slice(0, 16);
  }

  function view(rec) {
    if (!rec) return null;
    return {
      id: rec.id, kind: rec.kind, label: rec.label, target: rec.target, set: true, fingerprint: rec.fingerprint, version: rec.version,
      future: !!KINDS[rec.kind].future, last_tested: rec.last_tested || null,
      created_by: rec.created_by, created_at: rec.created_at, updated_by: rec.updated_by, updated_at: rec.updated_at,
    };
  }

  function create(body, who) {
    need();
    const b = isObj(body) ? body : {};
    const kind = str(b.kind, 20);
    if (!KINDS[kind]) throw bad(`kind must be one of ${Object.keys(KINDS).join(', ')}`);
    const label = str(b.label, 120);
    if (!label) throw bad('label is required');
    const target = normTarget(kind, b.target);
    const secret = normSecret(kind, b.secret, null);
    const id = `cr_${crypto.randomBytes(6).toString('hex')}`;
    const now = new Date().toISOString();
    const rec = { id, kind, label, target, version: 1, enc: seal(id, 1, secret), fingerprint: fingerprint(secret), created_by: who.user, created_at: now, updated_by: who.user, updated_at: now, last_tested: null };
    for (const x of Object.keys(secret)) secret[x] = null;
    col.put(rec);
    return view(rec);
  }

  function update(id, body, who) {
    need();
    const cur = col.get(id);
    if (!cur) throw bad('credential not found', 404);
    const b = isObj(body) ? body : {};
    const label = b.label !== undefined ? str(b.label, 120) : cur.label;
    if (!label) throw bad('label is required');
    const target = b.target !== undefined ? normTarget(cur.kind, Object.assign({}, cur.target, b.target)) : cur.target;
    const before = cur.target || {};
    const targetChanged = CONNECTION_TARGET_FIELDS.filter((f) => JSON.stringify(before[f]) !== JSON.stringify(target[f]));
    const prev = unseal(cur);
    let secret;
    if (targetChanged.length) {
      // the stored secret is NOT carried over to a new target: every secret field that is set must be supplied again
      const sb = isObj(b.secret) ? b.secret : {};
      const missing = Object.keys(prev).filter((x) => prev[x] !== undefined && prev[x] !== null && prev[x] !== '' && (sb[x] === undefined || sb[x] === null || sb[x] === ''));
      if (missing.length) { for (const x of Object.keys(prev)) prev[x] = null; throw bad(`changing the connection target (${targetChanged.join(', ')}) requires re-entering the secret in the same request (secret.${missing.join(', secret.')})`); }
      secret = normSecret(cur.kind, sb, null);
    } else secret = b.secret !== undefined ? normSecret(cur.kind, b.secret, prev) : prev;
    const version = cur.version + 1;
    const fp = fingerprint(secret);
    const rec = Object.assign({}, cur, { label, target, version, enc: seal(id, version, secret), fingerprint: fp, updated_by: who.user, updated_at: new Date().toISOString() });
    if (fp !== cur.fingerprint) rec.last_tested = null;
    for (const x of Object.keys(prev)) prev[x] = null;
    col.put(rec);
    return { credential: view(rec), secret_changed: fp !== cur.fingerprint, target_changed: targetChanged, target_before: before };
  }

  function remove(id) { const cur = col.get(id); if (!cur) throw bad('credential not found', 404); col.remove(id); return { removed: id, kind: cur.kind }; }

  // engine-internal: plaintext secret + target. Registers values with the scrubber; caller MUST call release().
  function open(id) {
    need();
    const rec = col.get(id);
    if (!rec) throw bad(`credential ${id} not found`, 404);
    const secret = unseal(rec);
    const values = Object.values(secret).filter((v) => typeof v === 'string');
    if (scrubber) scrubber.register(values);
    let released = false;
    return {
      id: rec.id, kind: rec.kind, target: rec.target, secret,
      release() { if (released) return; released = true; if (scrubber) scrubber.release(values); for (const x of Object.keys(secret)) secret[x] = null; },
    };
  }
  function recordTest(id, res) { col.patch(id, (r) => { r.last_tested = { at: new Date().toISOString(), ok: !!res.ok, latency_ms: res.latency_ms == null ? null : res.latency_ms, error_class: res.ok ? null : res.error_class || 'error' }; }); }

  return {
    available: () => !!key, unavailableReason: () => k.error || null,
    create, update, remove, open, recordTest,
    get: (id) => view(col.get(id)), meta: (id) => { const r = col.get(id); return r ? { id: r.id, kind: r.kind } : null; },
    list: () => col.all().map(view).sort((a, b) => (a.label < b.label ? -1 : 1)),
    KINDS,
  };
}

// Small AES-256-GCM sealer for OTHER engine secrets (legacy connector credentials in engine/settings.js) under the SAME
// master key file as the discovery vault. A purpose-specific subkey (HMAC(master, purpose)) gives domain separation and
// AAD = "<purpose>|<id>" binds each ciphertext to its record.
function createSealer({ keyFile, createKey = true, purpose }) {
  const k = loadKey(keyFile, createKey);
  const sub = k.key ? crypto.createHmac('sha256', k.key).update(`sentra-itam-sealer|${purpose}`).digest() : null;
  const aad = (id) => Buffer.from(`${purpose}|${id}`);
  function need() { if (!sub) throw bad(`credential vault unavailable: ${k.error}`, 503); }
  return {
    available: () => !!sub, unavailableReason: () => k.error || null,
    seal(id, plaintext) {
      need();
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv('aes-256-gcm', sub, iv);
      c.setAAD(aad(id));
      const ct = Buffer.concat([c.update(String(plaintext), 'utf8'), c.final()]);
      return { alg: 'aes-256-gcm', iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), ct: ct.toString('base64') };
    },
    unseal(id, enc) {
      need();
      const d = crypto.createDecipheriv('aes-256-gcm', sub, Buffer.from(enc.iv, 'hex'), { authTagLength: 16 });
      d.setAAD(aad(id));
      d.setAuthTag(Buffer.from(enc.tag, 'hex'));
      try { return Buffer.concat([d.update(Buffer.from(enc.ct, 'base64')), d.final()]).toString('utf8'); } catch { throw bad(`sealed value ${id} failed authentication (vault key changed?)`, 500); }
    },
  };
}

module.exports = { createSealer, createVault, KINDS, normTarget, normSecret, CONNECTION_TARGET_FIELDS };
