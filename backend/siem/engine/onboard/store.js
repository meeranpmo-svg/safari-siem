// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Self-service source store: creates / rotates / revokes / removes `sources[]` entries in config.json and their ingest
// tokens in secrets.json, the same files install/sentra-siem-token edits.
//   createOnboardStore({config, log, paths?, now?, random?, onReload?})
//     .create({id, kind, type, match_ip?, label?, site?, allow_public?, by}) → {source, token?}  token = clear text, ONCE
//     .rotate(id, by) → {source, token}      .revoke(id, by) → {source}      .remove(id, by) → {removed: id}
//     .update(id, fields, by) → {source}     only the monitoring fields in UPDATABLE (pause state, SLA) - never match / type / kind
//     .list() → config.sources (live array)   .get(id)   .validateId / validateIp (pure)
//   Tokens are stored as "sha256:<hex>" (collect/http-ingest.js compares the sha256 of the presented token against
//   it in constant time); the clear token is returned to the caller exactly once and never logged.
//   Writes: read the file fresh → modify → write <file>.tmp (mode 600) → rename (atomic); a copy of the previous
//   content is kept as <file>.bak. After each write the in-memory config is updated IN PLACE (config.sources array,
//   config.secrets.ingest_tokens object) and onReload() is called so the listeners rebuild their source maps —
//   no restart needed. Nothing here touches the network.
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');

const ID_RE = /^[a-z0-9-]{3,40}$/;
const PRIVATE = [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16]];

class StoreError extends Error {
  constructor(code, msg, errors) { super(msg); this.code = code; this.status = code; this.errors = errors || [msg]; }
}

function ipToInt(ip) { return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0; }
function inBlock(ip, base, bits) { const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0; return ((ipToInt(ip) & mask) >>> 0) === ((ipToInt(base) & mask) >>> 0); }
function isPrivate(ip) { return PRIVATE.some(([b, n]) => inBlock(ip, b, n)); }

function validateId(id) {
  const s = String(id === undefined || id === null ? '' : id).trim().toLowerCase();
  if (!ID_RE.test(s)) throw new StoreError(400, 'source id must be 3-40 characters: lowercase letters, digits and dashes');
  if (s.startsWith('-') || s.endsWith('-')) throw new StoreError(400, 'source id must not start or end with a dash');
  return s;
}

// Accepts "a.b.c.d" or "a.b.c.d/nn" (IPv4). Returns {ip} or {cidr}. Private ranges only unless allowPublic.
function validateIp(v, allowPublic) {
  const s = String(v === undefined || v === null ? '' : v).trim();
  if (!s) throw new StoreError(400, 'device IP (or CIDR) required');
  const [addr, bitsStr] = s.split('/');
  if (net.isIPv4(addr) !== true) throw new StoreError(400, `"${s}" is not a valid IPv4 address or CIDR`);
  if (bitsStr === undefined) {
    if (!allowPublic && !isPrivate(addr)) throw new StoreError(400, `${addr} is not in a private range (10/8, 172.16/12, 192.168/16); set allow_public to accept it`);
    return { ip: addr };
  }
  const bits = Number(bitsStr);
  if (!/^\d{1,2}$/.test(bitsStr) || !Number.isInteger(bits) || bits < 8 || bits > 32) throw new StoreError(400, `CIDR prefix in "${s}" must be between /8 and /32`);
  if (!allowPublic && !PRIVATE.some(([b, n]) => bits >= n && inBlock(addr, b, n))) throw new StoreError(400, `${s} is not inside a private range (10/8, 172.16/12, 192.168/16); set allow_public to accept it`);
  return bits === 32 ? { ip: addr } : { cidr: `${addr}/${bits}` };
}

function readJson(file) {
  if (SF.isSecretsPath(file)) return SF.read(file);
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  return JSON.parse(text);
}

function writeJsonAtomic(file, obj) {
  try { return writeJsonAtomicRaw(file, obj); } catch (e) {
    if (e && ['EROFS', 'EACCES', 'EPERM'].includes(e.code)) { // say why instead of a bare "internal error"
      const msg = `the SIEM cannot write ${path.dirname(file)} (${e.code}): allow it in the service (sudo bash install/fix-config-write.sh)`;
      throw Object.assign(new Error(msg), { code: 500, status: 500, errors: [msg], cause: e.code });
    }
    throw e;
  }
}

function writeJsonAtomicRaw(file, obj) {
  if (SF.isSecretsPath(file)) { fs.mkdirSync(path.dirname(file), { recursive: true }); return SF.write(file, obj); }   // sealed, no plaintext .bak
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${file}.tmp-${process.pid}`;
  const data = JSON.stringify(obj, null, 2) + '\n';
  let st = null;
  try { st = fs.statSync(file); } catch { /* new file */ }
  if (st) { try { fs.copyFileSync(file, `${file}.bak`); fs.chmodSync(`${file}.bak`, 0o600); } catch { /* best effort backup */ } }
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  try { if (st && process.getuid && process.getuid() === 0) fs.chownSync(tmp, st.uid, st.gid); } catch { /* not root */ }
  fs.renameSync(tmp, file);
}

// extra fields a creator may set: parsing hints, silence threshold, and the asset-inventory link (onboard/collection.js)
const EXTRA_KEYS = ['tz_offset_min', 'silent_after_s', 'collector', 'asset_id', 'origin', 'auto_onboarded', 'sla_min', 'sla_class'];
const UPDATABLE = ['paused', 'paused_at', 'paused_by', 'paused_reason', 'sla_min', 'sla_class'];
const digest = (tok) => 'sha256:' + crypto.createHash('sha256').update(String(tok)).digest('hex');

function createOnboardStore({ config, log, paths, now = Date.now, random = () => crypto.randomBytes(32).toString('hex'), onReload } = {}) {
  if (!config) throw new Error('onboard store needs config');
  const p = paths || (config._paths ? { config: config._paths.config, secrets: config._paths.secrets } : null);
  if (!p || !p.config || !p.secrets) throw new Error('onboard store needs config/secrets paths');
  const lg = log || { info() {}, warn() {}, error() {} };
  if (!Array.isArray(config.sources)) config.sources = [];
  if (!config.secrets) Object.defineProperty(config, 'secrets', { value: { ingest_tokens: {} }, enumerable: false, writable: true });
  if (!config.secrets.ingest_tokens || typeof config.secrets.ingest_tokens !== 'object') config.secrets.ingest_tokens = {};

  function reload(what) {
    try { if (typeof onReload === 'function') onReload(what); } catch (e) { lg.error('onboard: reload hook failed', { err: e.message }); }
  }
  function syncSources(fileSources) {
    const live = config.sources;
    live.splice(0, live.length, ...fileSources);
  }
  function syncTokens(fileTokens) {
    const live = config.secrets.ingest_tokens;
    for (const k of Object.keys(live)) if (!(k in fileTokens)) delete live[k];
    for (const [k, v] of Object.entries(fileTokens)) live[k] = v;
  }

  function loadFiles() {
    const cfg = readJson(p.config) || {};
    const sec = readJson(p.secrets) || {};
    cfg.sources = Array.isArray(cfg.sources) ? cfg.sources : [];
    sec.ingest_tokens = sec.ingest_tokens && typeof sec.ingest_tokens === 'object' ? sec.ingest_tokens : {};
    return { cfg, sec };
  }
  function saveConfig(cfg) { writeJsonAtomic(p.config, cfg); syncSources(cfg.sources); }
  function saveSecrets(sec) { writeJsonAtomic(p.secrets, sec); syncTokens(sec.ingest_tokens); }

  function get(id) { return config.sources.find((s) => s && s.id === id) || null; }
  function tokenSet(id) { return !!(config.secrets.ingest_tokens && config.secrets.ingest_tokens[id]); }

  function create({ id, kind, type, match_ip, label, site, allow_public, by, needs_ip, mints_token, extra } = {}) {
    const sid = validateId(id);
    if (!/^[a-z0-9_-]{1,32}$/.test(String(type || ''))) throw new StoreError(400, 'source type missing');
    if (!/^[a-z0-9-]{2,32}$/.test(String(kind || ''))) throw new StoreError(400, 'connector kind missing');
    const { cfg, sec } = loadFiles();
    if (cfg.sources.some((s) => s && s.id === sid) || get(sid)) throw new StoreError(409, `source "${sid}" already exists`);
    if (sec.ingest_tokens[sid]) throw new StoreError(409, `source "${sid}" already has a token`);
    const entry = { id: sid, type: String(type), kind: String(kind), created_at: new Date(now()).toISOString(), created_by: String(by || 'unknown').slice(0, 200) };
    if (label !== undefined && label !== null && String(label).trim()) entry.label = String(label).trim().slice(0, 120);
    if (site !== undefined && site !== null && String(site).trim()) entry.site = String(site).trim().slice(0, 80);
    let m = null;
    if (match_ip !== undefined && match_ip !== null && String(match_ip).trim()) m = validateIp(match_ip, !!allow_public);
    else if (needs_ip) throw new StoreError(400, 'device IP (or CIDR) required for this connector');
    if (type === 'relay') {
      if (!m) throw new StoreError(400, 'relay sources need the site device range (CIDR) as device IP');
      entry.allowed_peers = [m.cidr || m.ip];
    } else if (m) entry.match = m.cidr ? { cidr: m.cidr } : { ip: m.ip };
    if (extra && typeof extra === 'object') for (const [k, v] of Object.entries(extra)) if (EXTRA_KEYS.includes(k)) entry[k] = v;
    let token = null;
    if (mints_token) { token = random(); sec.ingest_tokens[sid] = digest(token); saveSecrets(sec); }
    cfg.sources.push(entry);
    saveConfig(cfg);
    reload('sources');
    lg.info('onboard: source created', { src_id: sid, type: entry.type, kind: entry.kind, token: !!token, by: entry.created_by });
    return { source: Object.assign({}, entry), token };
  }

  function rotate(id, by) {
    const sid = validateId(id);
    const { sec } = loadFiles();
    if (!get(sid)) throw new StoreError(404, `source "${sid}" not found`);
    const token = random();
    sec.ingest_tokens[sid] = digest(token);
    saveSecrets(sec);
    reload('tokens');
    lg.info('onboard: token rotated', { src_id: sid, by });
    return { source: Object.assign({}, get(sid)), token };
  }

  function revoke(id, by) {
    const sid = validateId(id);
    const { sec } = loadFiles();
    if (!get(sid)) throw new StoreError(404, `source "${sid}" not found`);
    if (!sec.ingest_tokens[sid]) throw new StoreError(409, `source "${sid}" has no token`);
    delete sec.ingest_tokens[sid];
    saveSecrets(sec);
    reload('tokens');
    lg.info('onboard: token revoked', { src_id: sid, by });
    return { source: Object.assign({}, get(sid)) };
  }

  function remove(id, by) {
    const sid = validateId(id);
    const { cfg, sec } = loadFiles();
    const i = cfg.sources.findIndex((s) => s && s.id === sid);
    if (i < 0 && !get(sid)) throw new StoreError(404, `source "${sid}" not found`);
    if (i >= 0) cfg.sources.splice(i, 1);
    if (sec.ingest_tokens[sid]) { delete sec.ingest_tokens[sid]; saveSecrets(sec); }
    saveConfig(cfg);
    reload('sources');
    lg.info('onboard: source removed', { src_id: sid, by });
    return { removed: sid };
  }

  function update(id, fields, by) {
    const sid = validateId(id);
    const { cfg } = loadFiles();
    const i = cfg.sources.findIndex((s) => s && s.id === sid);
    if (i < 0) throw new StoreError(404, `source "${sid}" not found`);
    for (const [k, v] of Object.entries(fields || {})) {
      if (!UPDATABLE.includes(k)) continue;
      if (v === null || v === undefined) delete cfg.sources[i][k]; else cfg.sources[i][k] = v;
    }
    saveConfig(cfg);
    reload('sources');
    lg.info('onboard: source updated', { src_id: sid, fields: Object.keys(fields || {}).filter((k) => UPDATABLE.includes(k)), by });
    return { source: Object.assign({}, get(sid)) };
  }

  return { create, rotate, revoke, remove, update, get, list: () => config.sources, tokenSet, paths: p };
}

module.exports = { createOnboardStore, validateId, validateIp, isPrivate, digest, writeJsonAtomic, StoreError, ID_RE };
