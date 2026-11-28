// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Optimizer — destinations (DATAOPT.md "Destinations"): archive + external forward targets with WRITE-ONLY
 * encrypted credentials (AES-256-GCM, like the existing credential vaults). Credentials are never returned by the API
 * and never logged; the public view only says which fields are set.
 *
 * Kinds: 'archive' (cold tier config), 'syslog' (udp/tcp), 'http' (JSON webhook). S3 forwarding is not implemented in
 * this version and is refused, so nothing is ever counted as forwarded without being sent.
 *   createDestinations({ state, dir, config, log, keyFile?, now }) →
 *     { list(), get(id), publicView(id), create(def, user), update(id, patch, user), remove(id, user),
 *       forward(idOrDef, ev), stats() }
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');

const KINDS = new Set(['archive', 'syslog', 'http']);
const ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;

// ---- minimal AES-256-GCM vault (self-contained; same construction as the other platform services)
function loadMasterKey(file) {
  let raw;
  try { raw = fs.readFileSync(file); }
  catch (e) {
    if (e.code !== 'ENOENT') throw e;
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const hex = crypto.randomBytes(32).toString('hex');
    try { fs.writeFileSync(file, hex + '\n', { mode: 0o600, flag: 'wx' }); raw = Buffer.from(hex + '\n'); }
    catch (e2) {
      // never overwrite: if another process created the key between our read and our write, use ITS key
      if (e2.code !== 'EEXIST') throw e2;
      raw = fs.readFileSync(file);
    }
  }
  if (process.platform !== 'win32') {
    const st = fs.statSync(file);
    if (st.mode & 0o077) throw new Error(`dataopt master key ${file} is readable by group or other users (mode ${(st.mode & 0o777).toString(8)}) - chmod 600 it`);
  }
  const txt = raw.toString('utf8').trim();
  if (/^[0-9a-fA-F]{64}$/.test(txt)) return Buffer.from(txt, 'hex');
  if (raw.length === 32) return Buffer.from(raw);
  throw new Error(`dataopt master key ${file} must contain 64 hex characters (32 bytes)`);
}
function createVault(key) {
  const k = Buffer.from(key);
  function seal(secret, aad) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', k, iv);
    c.setAAD(Buffer.from(String(aad || '')));
    const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(secret), 'utf8')), c.final()]);
    return { v: 1, alg: 'aes-256-gcm', iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64') };
  }
  function open(blob, aad) {
    if (!blob || blob.v !== 1 || blob.alg !== 'aes-256-gcm') throw new Error('credential blob missing or unsupported');
    const d = crypto.createDecipheriv('aes-256-gcm', k, Buffer.from(blob.iv, 'base64'), { authTagLength: 16 });
    d.setAAD(Buffer.from(String(aad || '')));
    d.setAuthTag(Buffer.from(blob.tag, 'base64'));
    return JSON.parse(Buffer.concat([d.update(Buffer.from(blob.ct, 'base64')), d.final()]).toString('utf8'));
  }
  return { seal, open };
}

function publicDest(d) {
  if (!d) return null;
  const { secret, secret_fields, ...rest } = d;
  const out = JSON.parse(JSON.stringify(rest));
  out.credentials = { set: !!secret, fields: Array.isArray(secret_fields) ? secret_fields.slice() : [] };
  return out;
}

function createDestinations({ state, dir, config = {}, log, keyFile, now = Date.now } = {}) {
  const col = state ? state.collection('dataopt_destination') : null;
  const mem = new Map(); // fallback when no state (tests)
  const kf = keyFile || (dir ? path.join(dir, 'dataopt.key') : null);
  let vault = null;
  function getVault() {
    if (vault) return vault;
    if (!kf) throw Object.assign(new Error('no key file for credential encryption'), { code: 500 });
    vault = createVault(loadMasterKey(kf));
    return vault;
  }
  const st = { forwarded: 0, forward_errors: 0, last_error: '' };

  function all() { return col ? col.all() : [...mem.values()]; }
  function getRaw(id) { return col ? col.get(id) : (mem.get(id) || null); }
  function store(d) { if (col) col.put(d); else mem.set(d.id, d); return d; }

  function validate(def) {
    if (!def || typeof def !== 'object') throw Object.assign(new Error('destination must be an object'), { code: 400 });
    if (!ID_RE.test(String(def.id || ''))) throw Object.assign(new Error('destination id invalid (letters, digits, _ . - ; max 64)'), { code: 400 });
    if (def.kind === 's3') throw Object.assign(new Error('S3 forwarding is not available in this version - use the archive tier, or an http/syslog destination'), { code: 400 });
    if (!KINDS.has(def.kind)) throw Object.assign(new Error(`destination kind must be one of ${[...KINDS].join('|')}`), { code: 400 });
    if (def.kind === 'syslog') {
      if (!def.host) throw Object.assign(new Error('syslog destination needs host'), { code: 400 });
      if (def.proto && !['udp', 'tcp'].includes(def.proto)) throw Object.assign(new Error('syslog proto must be udp|tcp'), { code: 400 });
    }
    if (def.kind === 'http' && !/^https?:\/\//.test(String(def.url || ''))) throw Object.assign(new Error('http destination needs url'), { code: 400 });
  }

  function create(def, user) {
    validate(def);
    if (getRaw(def.id)) throw Object.assign(new Error(`destination ${def.id} already exists`), { code: 409 });
    const d = sanitise(def);
    if (def.credentials && typeof def.credentials === 'object') applySecret(d, def.credentials);
    d.created = now(); d.created_by = user || ''; d.updated = d.created; d.updated_by = user || '';
    store(d);
    return publicDest(getRaw(d.id));
  }

  function update(id, patch, user) {
    const cur = getRaw(id);
    if (!cur) throw Object.assign(new Error('destination not found'), { code: 404 });
    const merged = Object.assign({}, cur, sanitise(patch), { id });
    validate(merged);
    // the stored secret belongs to the endpoint it was entered for: pointing the destination somewhere else drops it (the new
    // endpoint needs its credentials entered again), so a write-only token can never be redirected to another server
    const moved = ['url', 'host', 'port', 'kind'].some((k) => String(merged[k] == null ? '' : merged[k]) !== String(cur[k] == null ? '' : cur[k]));
    if (patch.credentials && typeof patch.credentials === 'object') applySecret(merged, patch.credentials);
    else if (moved) { delete merged.secret; merged.secret_fields = []; }
    else { merged.secret = cur.secret; merged.secret_fields = cur.secret_fields; }
    merged.updated = now(); merged.updated_by = user || '';
    store(merged);
    return publicDest(getRaw(id));
  }

  function remove(id, user) {
    if (!getRaw(id)) return false;
    if (col) col.remove(id); else mem.delete(id);
    if (log) log.info('dataopt: destination removed', { id, by: user || '' });
    return true;
  }

  function sanitise(def) {
    const { credentials, secret, secret_fields, created, created_by, ...rest } = def;
    return JSON.parse(JSON.stringify(rest));
  }
  function applySecret(d, creds) {
    const fields = Object.keys(creds).filter((k) => creds[k] !== '' && creds[k] !== null && creds[k] !== undefined);
    if (!fields.length) return;
    d.secret = getVault().seal(creds, d.id);
    d.secret_fields = fields;
  }
  function openSecret(d) { return d.secret ? getVault().open(d.secret, d.id) : {}; }

  // fire-and-forget forward (never throws into the pipeline). Returns true when a send was attempted.
  function forward(idOrDef, ev) {
    const d = typeof idOrDef === 'string' ? getRaw(idOrDef) : idOrDef;
    if (!d) { st.forward_errors++; st.last_error = 'unknown destination ' + idOrDef; return false; }
    const line = (ev && typeof ev.raw === 'string' && ev.raw) || JSON.stringify(ev);
    try {
      if (d.kind === 'syslog') sendSyslog(d, line);
      else if (d.kind === 'http') sendHttp(d, ev, line);
      else { st.forward_errors++; st.last_error = 'destination ' + d.id + ' (' + d.kind + ') cannot be used for forwarding'; return false; }
      st.forwarded++;
      return true;
    } catch (e) { st.forward_errors++; st.last_error = e.message; return false; }
  }

  function sendSyslog(d, line) {
    const port = Number(d.port) || 514;
    if ((d.proto || 'udp') === 'udp') {
      const sock = dgram.createSocket(net.isIPv6(d.host) ? 'udp6' : 'udp4');
      sock.send(Buffer.from(line + '\n'), port, d.host, () => { try { sock.close(); } catch { /* ignore */ } });
      sock.on('error', () => { try { sock.close(); } catch { /* ignore */ } });
    } else {
      const sock = net.connect({ host: d.host, port }, () => { sock.write(line + '\n'); sock.end(); });
      sock.setTimeout(5000, () => sock.destroy());
      sock.on('error', () => { try { sock.destroy(); } catch { /* ignore */ } });
    }
  }

  function sendHttp(d, ev, line) {
    const u = new URL(d.url);
    const mod = u.protocol === 'https:' ? https : http;
    const creds = openSecret(d);
    const headers = { 'Content-Type': 'application/json' };
    if (creds.token) headers.Authorization = 'Bearer ' + creds.token;
    if (creds.header && creds.header_value) headers[creds.header] = creds.header_value;
    const body = Buffer.from(JSON.stringify(d.send_raw ? { raw: line } : ev));
    headers['Content-Length'] = body.length;
    const req = mod.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method: 'POST', headers }, (res) => { res.resume(); });
    req.setTimeout(5000, () => req.destroy());
    req.on('error', () => {});
    req.end(body);
  }

  return {
    list: () => all().map(publicDest),
    get: (id) => publicDest(getRaw(id)),
    getRaw, publicView: publicDest,
    create, update, remove, forward,
    stats: () => ({ ...st, count: all().length }),
  };
}

module.exports = { createDestinations, publicDest, loadMasterKey, createVault, KINDS };
