// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The bridge to the Python modules (gradual move from Node.js - docs/PYTHON-MIGRATION.md). One request per call:
// python3 -I pyengine/run.py, ONE JSON request on stdin (credentials only travel there - never argv or the environment),
// ONE JSON answer on stdout, a time limit, a minimal environment. A missing Python / module is answered as
// {ok:false, error_class:'missing_python'} so the caller can fall back to the Node.js module and say so.
//   createPyEngine({python, timeoutMs}) → { call(op, body) → Promise<answer>, ping() }
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const http = require('node:http');

const RUN = path.join(__dirname, '..', 'pyengine', 'run.py');

// ---- the resident service (pyengine/serve.py, step 9a): ONE long-running Python per engine for the operations that read
// the store, on a Unix socket in a private 0700 folder. It keeps the store in memory and reads only what was appended, so
// a read route no longer pays a Python start-up and a full store read. Started on first use, restarted at most every
// 30 s if it dies; when it cannot answer the caller falls back to one process per call (below), then to Node.js.
const SERVE = path.join(__dirname, '..', 'pyengine', 'serve.py');
// an explicit list, never a prefix: 'virt.' would also match virt.vcenter / virt.nutanix, which carry credentials
const RESIDENT_OPS = new Set(['consent.apply', 'consent.get', 'consent.stats', 'consent.last', 'assets.create', 'ai.sanitise_pair', 'ai.validate', 'desk.config', 'desk.patch_request', 'desk.patch_endorse', 'budget.import', 'budget.line', 'budget.remove', 'budget.settings', 'support.put', 'support.verify', 'support.retire', 'support.settings', 'support.import', 'locations.create', 'locations.edit', 'locations.delete', 'ownership.assign', 'ownership.service', 'ownership.import', 'licences.save', 'licences.retire', 'stocktake.open', 'stocktake.scan', 'stocktake.close', 'findings.status', 'cmdb.add', 'assets.edit', 'assets.transition', 'assets.move', 'assets.assign', 'assets.list', 'assets.detail', 'assets.lookup', 'assets.software', 'assets.licences', 'assets.cmdb', 'roles.list', 'roles.me', 'roles.approvers', 'roles.save', 'roles.remove', 'roles.assign',
  'grc.drafts', 'grc.draft', 'grc.drills', 'grc.drill', 'grc.drill_systems', 'grc.drill_summary', 'grc.draft_put', 'grc.draft_status', 'grc.draft_upload', 'grc.draft_delete', 'grc.drill_put', 'grc.drill_result', 'grc.drill_signoff', 'grc.drill_cancel', 'grc.drill_upload', 'grc.drill_delete', 'virtplans.changes', 'virtplans.change', 'store.read', 'store.verify_audit', 'store.audit_tail']);
const residents = new Map();
function resident(python) {
  let r = residents.get(python);
  if (r) return r;
  r = { python, ready: null, sock: null, child: null, failedAt: 0, agent: new http.Agent({ keepAlive: true, maxSockets: 8 }) };
  residents.set(python, r);
  r.start = () => {
    if (r.ready) return r.ready;
    if (Date.now() - r.failedAt < 30000 || !fs.existsSync(SERVE)) return Promise.resolve(false);
    r.ready = new Promise((resolve) => {
      let dir; try { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-itam-py-')); fs.chmodSync(dir, 0o700); } catch (e) { r.failedAt = Date.now(); r.ready = null; return resolve(false); }
      r.sock = path.join(dir, 'py.sock');
      let c; try { c = spawn(python, ['-I', SERVE, r.sock], { stdio: ['pipe', 'pipe', 'ignore'], env: Object.assign({ PATH: process.env.PATH || '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1', LANG: 'C.UTF-8' }, process.env.TZ ? { TZ: process.env.TZ } : {}) }); } catch (e) { r.failedAt = Date.now(); r.ready = null; return resolve(false); }
      r.child = c;
      const fail = () => { if (r.child !== c) return; r.child = null; r.ready = null; r.failedAt = Date.now(); try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* gone */ } resolve(false); };
      const t = setTimeout(() => { try { c.kill('SIGKILL'); } catch (e) { /* gone */ } fail(); }, 15000);
      let buf = '';
      c.stdout.on('data', (d) => { buf += d; if (/^ready\n/.test(buf)) { clearTimeout(t); resolve(true); } });
      c.on('error', () => { clearTimeout(t); fail(); });
      c.on('exit', () => { clearTimeout(t); fail(); });
      c.stdin.on('error', () => { /* the service ended */ });
      // never keep the engine alive just for this child; it exits when our stdin closes
      c.unref(); for (const h of [c.stdin, c.stdout]) if (h && h.unref) h.unref();
    });
    return r.ready;
  };
  r.call = (op, body, timeoutMs) => new Promise((resolve) => {
    const data = Buffer.from(JSON.stringify(Object.assign({ op }, body || {})));
    const q = http.request({ socketPath: r.sock, method: 'POST', path: '/call', agent: r.agent, headers: { 'Content-Type': 'application/json', 'Content-Length': data.length } }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => { try { resolve(res.statusCode === 200 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null); } catch (e) { resolve(null); } });
      res.on('error', () => resolve(null));
    });
    q.setTimeout(timeoutMs, () => q.destroy());
    q.on('error', () => resolve(null));
    q.end(data);
  });
  return r;
}

function createPyEngine(o = {}) {
  const python = o.python || '/opt/sentra-siem/pyenv/bin/python3', timeoutMs = o.timeoutMs || 120000;
  // o.resident = false keeps one process per call for this caller (the device readers never use the resident service)
  async function call(op, body) {
    if (o.resident !== false && RESIDENT_OPS.has(op)) {
      const r = resident(python);
      if (await r.start()) { const a = await r.call(op, body, timeoutMs); if (a && a.ok !== false) return a; }
    }
    return callOnce(op, body);
  }
  function callOnce(op, body) {
    return new Promise((resolve) => {
      if (!fs.existsSync(RUN)) return resolve({ ok: false, error_class: 'missing_python', error: 'pyengine/run.py is not installed' });
      // no TZ passed = the server's own time zone, like Node (an empty TZ would mean UTC)
      let p; try { p = spawn(python, ['-I', RUN], { stdio: ['pipe', 'pipe', 'pipe'], env: Object.assign({ PATH: process.env.PATH || '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1', LANG: 'C.UTF-8' }, process.env.TZ ? { TZ: process.env.TZ } : {}) }); }
      catch (e) { return resolve({ ok: false, error_class: 'missing_python', error: `Python not found (${python})` }); }
      let out = '', err = '', done = false;
      const fin = (v) => { if (done) return; done = true; clearTimeout(t); resolve(v); };
      const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch (e) { /* gone */ } fin({ ok: false, error_class: 'timeout', error: `the Python module did not answer within ${Math.round(timeoutMs / 1000)} s` }); }, timeoutMs);
      p.on('error', () => fin({ ok: false, error_class: 'missing_python', error: `Python not found (${python})` }));
      p.stdout.on('data', (d) => { out += d; if (out.length > 32 * 1048576) { try { p.kill('SIGKILL'); } catch (e) { /* gone */ } fin({ ok: false, error_class: 'protocol', error: 'the Python answer is too large' }); } });
      p.stderr.on('data', (d) => { if (err.length < 4000) err += d; });
      p.on('close', (code) => {
        if (done) return;
        try { fin(JSON.parse(out)); } catch (e) { fin({ ok: false, error_class: /ModuleNotFoundError|ImportError/.test(err) ? 'missing_python' : 'protocol', error: `the Python module failed (exit ${code}): ${err.trim().split('\n').pop() || 'no answer'}`.slice(0, 400) }); }
      });
      p.stdin.on('error', () => { /* answered by close */ });
      p.stdin.end(JSON.stringify(Object.assign({ op }, body || {})));
    });
  }
  return { call, callOnce, ping: () => callOnce('ping', {}), RUN };
}

module.exports = { createPyEngine, RUN, SERVE, residentFor: (python) => resident(python || '/opt/sentra-siem/pyenv/bin/python3') };
