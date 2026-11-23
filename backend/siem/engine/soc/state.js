// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Engine workflow state — append-only JSON-lines journals + periodic snapshots (ARCH "Internal interfaces").
 *
 *   createState({ dir, log, snapshotEvery = 10000, snapshotMs = 300000, fsync = false })
 *     → { collection(name) → { get(id), all(filterFn?), put(obj), patch(id, fn), remove(id), size() },
 *         audit(entry), auditTail(n, filterFn?), auditSince(ms, n?, filterFn?), snapshot(), close() }
 *
 * Layout (dir = <data>/state):
 *   <name>.jsonl         journal: one line per write  {"op":"put","o":{…}} | {"op":"del","id":"…"}
 *   <name>.snap.json     snapshot: {"at":…, "items":[…]}
 *   audit-YYYYMM.jsonl   audit journal (never compacted; one file per month)
 * Snapshot procedure (crash-safe): write <name>.snap.json.tmp → fsync → rename over snap → truncate journal.
 * Replaying a journal on top of a newer snapshot is idempotent (puts carry full objects), so a crash between the
 * rename and the truncate loses nothing. A torn last journal line (crash mid-write) is ignored on load.
 *
 * Objects returned by get()/all() are the stored objects: treat them as read-only and change them through
 * put()/patch() only (patch() hands the callback a deep copy).
 */
const fs = require('fs');
const path = require('path');

const NAME_RE = /^[a-z][a-z0-9_-]{0,40}$/;

function createState(opts = {}) {
  const dir = opts.dir;
  if (!dir) throw new Error('createState needs dir');
  const log = opts.log || { info() {}, warn() {}, error() {} };
  const snapshotEvery = opts.snapshotEvery || 10000;
  const snapshotMs = opts.snapshotMs || 300000;
  const doFsync = !!opts.fsync;
  fs.mkdirSync(dir, { recursive: true });

  const cols = new Map();
  let auditFd = null; let auditMonth = '';
  const auditRing = [];
  const AUDIT_RING = 2000;

  function openCollection(name) {
    if (!NAME_RE.test(name)) throw new Error(`invalid collection name ${name}`);
    const jpath = path.join(dir, `${name}.jsonl`);
    const spath = path.join(dir, `${name}.snap.json`);
    const items = new Map();
    let bad = 0;
    try {
      const snap = JSON.parse(fs.readFileSync(spath, 'utf8'));
      for (const o of snap.items || []) items.set(o.id, o);
    } catch (e) { if (e.code !== 'ENOENT') { log.error('state snapshot unreadable', { name, err: e.message }); throw e; } }
    try {
      const text = fs.readFileSync(jpath, 'utf8');
      for (const line of text.split('\n')) {
        if (!line) continue;
        let rec;
        try { rec = JSON.parse(line); } catch { bad++; continue; }
        if (rec.op === 'put' && rec.o && rec.o.id !== undefined) items.set(rec.o.id, rec.o);
        else if (rec.op === 'del') items.delete(rec.id);
      }
    } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (bad) log.warn('state journal had unreadable lines (ignored)', { name, bad });
    const fd = fs.openSync(jpath, 'a');
    const col = { name, jpath, spath, items, fd, writes: 0 };
    cols.set(name, col);
    return col;
  }

  function append(col, rec) {
    const line = JSON.stringify(rec) + '\n';
    fs.writeSync(col.fd, line);
    if (doFsync) fs.fsyncSync(col.fd);
    col.writes++;
  }
  function maybeSnapshot(col) {
    if (col.writes >= snapshotEvery) {
      try { snapshotCol(col); } catch (e) { log.error('state snapshot failed', { name: col.name, err: e.message }); }
    }
  }

  function snapshotCol(col) {
    const tmp = col.spath + '.tmp';
    const data = JSON.stringify({ at: Date.now(), items: [...col.items.values()] });
    const fd = fs.openSync(tmp, 'w');
    try { fs.writeSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, col.spath);
    fs.closeSync(col.fd);
    fs.writeFileSync(col.jpath, '');
    col.fd = fs.openSync(col.jpath, 'a');
    col.writes = 0;
  }

  function collection(name) {
    const col = cols.get(name) || openCollection(name);
    return {
      get(id) { return col.items.get(id) || null; },
      all(filter) {
        const out = [];
        for (const o of col.items.values()) if (!filter || filter(o)) out.push(o);
        return out;
      },
      size() { return col.items.size; },
      put(obj) {
        if (!obj || obj.id === undefined || obj.id === null || obj.id === '') throw new Error(`put into ${name} needs obj.id`);
        const o = JSON.parse(JSON.stringify(obj));
        append(col, { op: 'put', o });
        col.items.set(o.id, o);
        maybeSnapshot(col);
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
        maybeSnapshot(col);
        return next;
      },
      remove(id) {
        if (!col.items.has(id)) return false;
        append(col, { op: 'del', id });
        col.items.delete(id);
        maybeSnapshot(col);
        return true;
      },
    };
  }

  function audit(entry) {
    const rec = Object.assign({ at: Date.now() }, entry);
    const d = new Date(rec.at);
    const month = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
    if (month !== auditMonth) {
      if (auditFd !== null) fs.closeSync(auditFd);
      auditFd = fs.openSync(path.join(dir, `audit-${month}.jsonl`), 'a');
      auditMonth = month;
    }
    fs.writeSync(auditFd, JSON.stringify(rec) + '\n');
    if (doFsync) fs.fsyncSync(auditFd);
    auditRing.push(rec);
    if (auditRing.length > AUDIT_RING) auditRing.shift();
    return rec;
  }

  function auditTail(n = 100, filter) {
    const out = [];
    for (let i = auditRing.length - 1; i >= 0 && out.length < n; i--) if (!filter || filter(auditRing[i])) out.push(auditRing[i]);
    return out;
  }

  // audit entries since a time, newest first, read from the monthly journals rather than the in-memory ring, so the
  // IT Audit period survives a restart and is not cut at the ring size. { items, capped } - capped says n was reached.
  function auditSince(since, n = 5000, filter) {
    const out = [], from = Number(since) || 0, d = new Date(from), months = [];
    for (let y = d.getUTCFullYear(), m = d.getUTCMonth(), end = new Date(); y < end.getUTCFullYear() || (y === end.getUTCFullYear() && m <= end.getUTCMonth()); m === 11 ? (y++, m = 0) : m++) months.push(`${y}${String(m + 1).padStart(2, '0')}`);
    if (months.length > 40) months.splice(0, months.length - 40);
    for (let i = months.length - 1; i >= 0; i--) {
      let lines; try { lines = fs.readFileSync(path.join(dir, `audit-${months[i]}.jsonl`), 'utf8').split('\n'); } catch { continue; }
      for (let j = lines.length - 1; j >= 0; j--) {
        if (!lines[j]) continue; let r; try { r = JSON.parse(lines[j]); } catch { continue; }
        if (!(r.at >= from) || (filter && !filter(r))) continue;
        if (out.length >= n) return { items: out, capped: true };
        out.push(r);
      }
    }
    return { items: out, capped: false };
  }

  function snapshot() {
    for (const col of cols.values()) {
      try { snapshotCol(col); } catch (e) { log.error('state snapshot failed', { name: col.name, err: e.message }); }
    }
  }

  const timer = setInterval(() => { for (const col of cols.values()) if (col.writes > 0) { try { snapshotCol(col); } catch (e) { log.error('state snapshot failed', { name: col.name, err: e.message }); } } }, snapshotMs);
  if (timer.unref) timer.unref();

  return {
    collection, audit, auditTail, auditSince, snapshot,
    close() {
      clearInterval(timer);
      snapshot();
      for (const col of cols.values()) { try { fs.closeSync(col.fd); } catch { /* ignore */ } }
      cols.clear();
      if (auditFd !== null) { try { fs.closeSync(auditFd); } catch { /* ignore */ } auditFd = null; auditMonth = ''; }
    },
  };
}

module.exports = { createState };
