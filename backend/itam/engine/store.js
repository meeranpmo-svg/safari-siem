// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * State store — append-only JSON-lines journals + snapshots plus a hash-chained audit journal.
 * Same proven implementation as sentra-grcai/engine/store.js (sentra-siem state.js lineage).
 *
 *   createStore({ dir, log, fsync })
 *     → { collection(name) → { get, all, put, patch, remove, size }, onChange(name, fn(id, op)),
 *         audit(entry) → rec, auditTail(n, filter), verifyAudit() → {ok, checked, bad_at?}, snapshot(), close() }
 *
 * Layout (dir = /var/lib/sentra-itam/state):
 *   <name>.jsonl / <name>.snap.json   collection journal + snapshot (compaction = snapshot, then truncate journal)
 *   audit-YYYYMM.jsonl                audit journal, never compacted. Each record carries seq, prev (hash of the
 *                                     previous record) and hash = sha256(prev + "\n" + JSON of the record without
 *                                     `hash`). Editing or deleting any line breaks the chain.
 *
 * Retire/dispose set a status and append a lifecycle event; the record and its audit trail stay. `remove` is used for
 * internal/ephemeral collections and by the admin asset delete (engine/asset-delete.js), which audits a snapshot.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const NAME_RE = /^[a-z][a-z0-9_-]{0,40}$/;
const GENESIS = '0'.repeat(64);
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function chainHash(rec) {
  const { hash, ...rest } = rec; // eslint-disable-line no-unused-vars
  return sha256(rest.prev + '\n' + JSON.stringify(rest));
}

function createStore(opts = {}) {
  const dir = opts.dir;
  if (!dir) throw new Error('createStore needs dir');
  const log = opts.log || { info() {}, warn() {}, error() {} };
  const doFsync = !!opts.fsync;
  fs.mkdirSync(dir, { recursive: true });
  const cols = new Map();
  const RING = 5000;
  const ring = [];
  let auditFd = null; let auditMonth = ''; let lastHash = GENESIS; let seq = 0;

  function auditFiles() { return fs.readdirSync(dir).filter((f) => /^audit-\d{6}\.jsonl$/.test(f)).sort(); }

  (function loadAuditTail() {
    const files = auditFiles();
    for (let i = Math.max(0, files.length - 2); i < files.length; i++) {
      const lines = fs.readFileSync(path.join(dir, files[i]), 'utf8').split('\n');
      for (const line of lines) {
        if (!line) continue;
        let rec; try { rec = JSON.parse(line); } catch { continue; }
        ring.push(rec); if (ring.length > RING) ring.shift();
        if (rec.hash) { lastHash = rec.hash; seq = rec.seq || seq; }
      }
    }
  })();

  function openCollection(name) {
    if (!NAME_RE.test(name)) throw new Error(`invalid collection name ${name}`);
    const jpath = path.join(dir, `${name}.jsonl`);
    const spath = path.join(dir, `${name}.snap.json`);
    const items = new Map();
    try {
      const snap = JSON.parse(fs.readFileSync(spath, 'utf8'));
      for (const o of snap.items || []) items.set(o.id, o);
    } catch (e) { if (e.code !== 'ENOENT') throw e; }
    let bad = 0;
    try {
      for (const line of fs.readFileSync(jpath, 'utf8').split('\n')) {
        if (!line) continue;
        let rec; try { rec = JSON.parse(line); } catch { bad++; continue; }
        if (rec.op === 'put' && rec.o && rec.o.id !== undefined) items.set(rec.o.id, rec.o);
        else if (rec.op === 'del') items.delete(rec.id);
      }
    } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (bad) log.warn('store: unreadable journal lines ignored', { name, bad });
    const col = { name, jpath, spath, items, fd: fs.openSync(jpath, 'a'), writes: 0 };
    cols.set(name, col);
    return col;
  }

  function append(col, rec) {
    fs.writeSync(col.fd, JSON.stringify(rec) + '\n');
    if (doFsync) fs.fsyncSync(col.fd);
    col.writes++;
    if (col.writes >= 5000) { try { snapshotCol(col); } catch (e) { log.error('store: snapshot failed', { name: col.name, err: e.message }); } }
  }

  function snapshotCol(col) {
    const tmp = col.spath + '.tmp';
    const fd = fs.openSync(tmp, 'w');
    try { fs.writeSync(fd, JSON.stringify({ at: Date.now(), items: [...col.items.values()] })); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, col.spath);
    fs.closeSync(col.fd);
    fs.writeFileSync(col.jpath, '');
    col.fd = fs.openSync(col.jpath, 'a');
    col.writes = 0;
  }

  // change listeners per collection (asset-propagate.js): called after a write, never able to fail it
  const listeners = new Map();
  function onChange(name, fn) { if (!listeners.has(name)) listeners.set(name, []); listeners.get(name).push(fn); }
  function notify(name, id, op) { for (const fn of listeners.get(name) || []) { try { fn(id, op); } catch (e) { /* a listener never breaks a write; it reports through its own guard */ } } }
  function collection(name) {
    const col = cols.get(name) || openCollection(name);
    return {
      get: (id) => col.items.get(id) || null,
      all(filter) { const out = []; for (const o of col.items.values()) if (!filter || filter(o)) out.push(o); return out; },
      size: () => col.items.size,
      put(obj) {
        if (!obj || obj.id === undefined || obj.id === null || obj.id === '') throw new Error(`put into ${name} needs id`);
        const o = JSON.parse(JSON.stringify(obj));
        append(col, { op: 'put', o });
        col.items.set(o.id, o);
        notify(name, o.id, 'put');
        return o;
      },
      patch(id, fn) {
        const cur = col.items.get(id);
        if (!cur) return null;
        const copy = JSON.parse(JSON.stringify(cur));
        const res = fn(copy);
        const next = res && typeof res === 'object' ? res : copy;
        next.id = id;
        append(col, { op: 'put', o: next });
        col.items.set(id, next);
        notify(name, id, 'put');
        return next;
      },
      remove(id) {
        if (!col.items.has(id)) return false;
        append(col, { op: 'del', id });
        col.items.delete(id);
        notify(name, id, 'del');
        return true;
      },
    };
  }

  function audit(entry) {
    const at = entry.at || new Date().toISOString();
    const rec = Object.assign({ seq: seq + 1, at }, entry, { seq: seq + 1, at, prev: lastHash });
    delete rec.hash;
    rec.hash = chainHash(rec);
    const month = at.slice(0, 7).replace('-', '');
    if (month !== auditMonth) {
      if (auditFd !== null) fs.closeSync(auditFd);
      auditFd = fs.openSync(path.join(dir, `audit-${month}.jsonl`), 'a');
      auditMonth = month;
    }
    fs.writeSync(auditFd, JSON.stringify(rec) + '\n');
    if (doFsync) fs.fsyncSync(auditFd);
    seq = rec.seq; lastHash = rec.hash;
    ring.push(rec); if (ring.length > RING) ring.shift();
    return rec;
  }

  function auditTail(n = 100, filter) {
    const out = [];
    for (let i = ring.length - 1; i >= 0 && out.length < n; i--) if (!filter || filter(ring[i])) out.push(ring[i]);
    return out;
  }

  function verifyAudit() {
    let prev = GENESIS; let checked = 0;
    for (const f of auditFiles()) {
      const lines = fs.readFileSync(path.join(dir, f), 'utf8').split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (!lines[i]) continue;
        let rec; try { rec = JSON.parse(lines[i]); } catch { return { ok: false, checked, bad_at: `${f}:${i + 1}`, reason: 'unreadable line' }; }
        if (rec.prev !== prev || chainHash(rec) !== rec.hash) return { ok: false, checked, bad_at: `${f}:${i + 1}`, reason: 'hash chain broken' };
        prev = rec.hash; checked++;
      }
    }
    return { ok: true, checked, head: prev };
  }

  function snapshot() {
    for (const col of cols.values()) {
      if (!col.writes) continue;
      try { snapshotCol(col); } catch (e) { log.error('store: snapshot failed', { name: col.name, err: e.message }); }
    }
  }

  return {
    collection, onChange, audit, auditTail, verifyAudit, snapshot, dir,
    close() {
      snapshot();
      for (const col of cols.values()) { try { fs.closeSync(col.fd); } catch { /* ignore */ } }
      cols.clear();
      if (auditFd !== null) { try { fs.closeSync(auditFd); } catch { /* ignore */ } auditFd = null; auditMonth = ''; }
    },
  };
}

module.exports = { createStore, sha256, chainHash, GENESIS };
