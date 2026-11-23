// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The audit hash-chain check on a worker thread: the same check as verifyAudit() in engine/store.js (same chainHash,
// same answer), at V8 speed (50,000 records in about 0.3 s), but on its own thread, so the engine keeps answering every
// other request while it reads the audit files. (Python did the same off the engine in about 1 s; for this hot path the
// faster language wins - pyengine/store.py stays the step-9 implementation, audit.engine = "python".)
// The main thread may be appending while the worker reads: a last line without its newline is still being written - it
// is not read, and never reported as damage.
//   verifyInWorker(dir, timeoutMs) → Promise<{ok, checked, head} | {ok:false, checked, bad_at, reason} | null>  (null = use store.verifyAudit())
const path = require('node:path');

function verifyDir(dir) {
  const fs = require('node:fs');
  const { chainHash, GENESIS } = require('./store');
  const files = fs.readdirSync(dir).filter((f) => /^audit-\d{6}\.jsonl$/.test(f)).sort();
  let prev = GENESIS, checked = 0;
  for (let fi = 0; fi < files.length; fi++) {
    const f = files[fi], lines = fs.readFileSync(path.join(dir, f), 'utf8').split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i]) continue;
      if (fi === files.length - 1 && i === lines.length - 1) break;   // being written right now (no newline yet)
      let rec; try { rec = JSON.parse(lines[i]); } catch { return { ok: false, checked, bad_at: `${f}:${i + 1}`, reason: 'unreadable line' }; }
      if (rec.prev !== prev || chainHash(rec) !== rec.hash) return { ok: false, checked, bad_at: `${f}:${i + 1}`, reason: 'hash chain broken' };
      prev = rec.hash; checked++;
    }
  }
  return { ok: true, checked, head: prev };
}

function verifyInWorker(dir, timeoutMs) {
  return new Promise((resolve) => {
    let W; try { const { Worker } = require('node:worker_threads'); W = new Worker(__filename, { workerData: { dir } }); } catch (e) { return resolve(null); }
    let done = false; const fin = (v) => { if (done) return; done = true; clearTimeout(t); resolve(v); W.terminate().catch(() => { /* the worker is gone already: nothing to clean up */ }); };
    const t = setTimeout(() => fin(null), timeoutMs || 120000);
    W.on('message', (m) => fin(m && typeof m.ok === 'boolean' ? m : null));
    W.on('error', () => fin(null));
    W.on('exit', () => fin(null));
  });
}

const wt = (() => { try { return require('node:worker_threads'); } catch (e) { return {}; } })();
if (!wt.isMainThread && wt.parentPort && wt.workerData && wt.workerData.dir) {
  let r; try { r = verifyDir(wt.workerData.dir); } catch (e) { r = null; }
  wt.parentPort.postMessage(r);
}

module.exports = { verifyInWorker, verifyDir };
