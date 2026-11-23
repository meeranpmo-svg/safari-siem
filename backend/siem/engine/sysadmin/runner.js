// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Runs read-only checks (checks.json) on a server through ps-helper.py (WinRM / PowerShell remoting, pypsrp).
 *   createRunner({ targets, state, config, log, exec? })
 *     .status() → {available, reason, pypsrp}       .catalogue(role?) → checks without their scripts
 *     .run(targetRef, checkId, params, {by, via}) → {server, check, data, errors, ms}
 *     .readCertificate(id) → {fingerprint, pinned, matches}   .trustCertificate(id, fingerprint, by)
 *     .log(limit)
 * Only checks in checks.json; the scope must match the server's roles. Every run (portal, AI, health poll) is recorded in
 * the state collection "sysadmin_runs" (who, server, check, result - never the output).
 */
const path = require('node:path');
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const CHECKS = require('./checks.json').checks;

class RunError extends Error { constructor(code, msg, kind) { super(msg); this.code = code; this.kind = kind || ''; } }
const BY_ID = Object.fromEntries(CHECKS.map((c) => [c.id, c]));
const CERT_TTL = 10 * 60 * 1000;

function realExec(config) {
  const c = (config && config.sysadmin) || {};
  const helper = c.helper || path.join(__dirname, 'ps-helper.py');
  const py = [c.python, '/opt/sentra-siem/pyenv/bin/python3', 'python3'].filter(Boolean).find((p) => p === 'python3' || fs.existsSync(p));
  return (req, timeoutMs) => new Promise((resolve) => {
    let child; try { child = spawn(py, [helper], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH || '/usr/bin:/bin', LANG: 'C.UTF-8', HOME: process.env.HOME || '/tmp', PYTHONDONTWRITEBYTECODE: '1' } }); }
    catch (e) { return resolve({ ok: false, kind: 'missing', error: 'cannot start Python: ' + e.message }); }
    let out = '', err = '', done = false;
    const fin = (r) => { if (!done) { done = true; clearTimeout(t); resolve(r); } };
    const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) { /* gone */ } fin({ ok: false, kind: 'timeout', error: `the check took longer than ${Math.round(timeoutMs / 1000)} s` }); }, timeoutMs);
    child.stdout.on('data', (d) => { if (out.length < 16e6) out += d; });
    child.stderr.on('data', (d) => { if (err.length < 4000) err += d; });
    child.on('error', (e) => fin({ ok: false, kind: 'missing', error: e.code === 'ENOENT' ? 'Python 3 is not installed on the SIEM server' : e.message }));
    child.on('close', () => { try { fin(JSON.parse(out)); } catch (e) { fin({ ok: false, kind: 'error', error: 'helper failed: ' + (err.trim().split('\n').pop() || 'no answer').slice(0, 300) }); } });
    child.stdin.end(JSON.stringify(req));
  });
}

function catalogue(role) {
  return CHECKS.filter((c) => !role || c.scope === role).map((c) => ({ id: c.id, scope: c.scope, title: c.title, params: c.params || {}, personal: !!c.personal, admin: !!c.admin, org: !!c.org, baseline: !!c.baseline }));
}

function createRunner({ targets, state, config, log, exec } = {}) {
  const L = log || { info() {}, warn() {} }, X = exec || realExec(config), runs = state.collection('sysadmin_runs');
  const cfg = () => (config && config.sysadmin) || {};
  const pendingCert = new Map(), busy = new Map();
  let probe = null, probeAt = 0, active = 0;

  async function status() {
    if (cfg().enabled === false) return { available: false, reason: 'switched off (config sysadmin.enabled)' };
    if (!probe || Date.now() - probeAt > 5 * 60 * 1000) {
      const r = await X({ op: 'version' }, 20000);
      probe = r.ok ? { available: true, pypsrp: r.pypsrp, python: r.python } : { available: false, reason: r.error || 'helper not available' }; probeAt = Date.now();
    }
    return probe;
  }
  function server(ref) { const t = targets.find(ref); if (!t) throw new RunError(404, `unknown server "${ref}"`); return t; }
  function record(e) { runs.put(e); const all = runs.all(); if (all.length > 1200) all.sort((a, b) => a.at - b.at).slice(0, all.length - 1000).forEach((x) => runs.remove(x.id)); }

  async function run(ref, checkId, params, { by, via } = {}) {
    const t = server(ref), c = BY_ID[checkId];
    if (!c) throw new RunError(400, `unknown check "${checkId}" - the checks are: ${CHECKS.map((x) => x.id).join(', ')}`);
    if (!(t.roles || []).includes(c.scope)) throw new RunError(400, `${t.name} is not an ${c.scope === 'exchange' ? 'Exchange' : 'Windows'} server in the list (roles: ${(t.roles || []).join(', ')})`);
    const st = await status(); if (!st.available) throw new RunError(503, st.reason, 'missing');
    const login = targets.login(t, c.scope);
    if (!login) throw new RunError(409, `no ${c.scope} login set - an administrator adds it under Logins (profile "${(t.logins && t.logins[c.scope]) || c.scope}")`, 'no-login');
    const w = t.winrm || { ssl: false, port: 5985 }, pin = targets.pin(t.id);
    if (w.ssl && !pin) throw new RunError(409, `the WinRM HTTPS certificate of ${t.name} is not trusted yet - an administrator reads and trusts it`, 'certificate');
    const n = busy.get(t.id) || 0;
    if (n >= 2) throw new RunError(429, `two checks are already running on ${t.name} - try again in a moment`);
    if (active >= (cfg().max_sessions || 4)) throw new RunError(429, 'too many checks running - try again in a moment');
    busy.set(t.id, n + 1); active++;
    const t0 = Date.now(); let r;
    try {
      r = await X({ op: 'run', host: t.ip, port: w.port, ssl: w.ssl, pin: pin ? pin.fingerprint : '', auth: login.auth, username: login.username, password: login.password, check: c.id, params: params || {}, timeout: cfg().timeout_s || 30 }, (cfg().check_timeout_s || 120) * 1000);
    } finally { busy.set(t.id, (busy.get(t.id) || 1) - 1); active--; }
    const ms = Date.now() - t0;
    record({ id: 'sr-' + t0.toString(36) + Math.random().toString(36).slice(2, 6), at: t0, server: t.id, name: t.name, check: c.id, params: c.personal ? Object.keys(params || {}) : params || {}, by: by || '', via: via || 'portal', ok: !!r.ok, ms, error: r.ok ? '' : String(r.error || '').slice(0, 300) });
    if (!r.ok) throw new RunError({ auth: 409, certificate: 409, denied: 403, missing: 503, input: 400, exchange: 409 }[r.kind] || 502, r.error || 'check failed', r.kind);
    return { server: t.name, server_id: t.id, check: c.id, title: c.title, data: r.data, errors: r.errors || [], ms, at: new Date(t0).toISOString() };
  }

  async function readCertificate(id) {
    const t = server(id), w = t.winrm || {};
    if (!w.ssl) throw new RunError(400, `${t.name} uses WinRM over HTTP (${w.port || 5985}, encrypted by Kerberos / NTLM) - there is no certificate to trust`);
    const r = await X({ op: 'certificate', host: t.ip, port: w.port || 5986 }, 30000);
    if (!r.ok) throw new RunError(r.kind === 'missing' ? 503 : 502, r.error, r.kind);
    pendingCert.set(t.id, { fingerprint: r.fingerprint, at: Date.now() });
    const p = targets.pin(t.id);
    return { server: t.id, fingerprint: r.fingerprint, pinned: p ? p.fingerprint : null, matches: p ? p.fingerprint === r.fingerprint : null };
  }
  function trustCertificate(id, fingerprint, by) {
    const t = server(id), p = pendingCert.get(t.id);
    if (!p || Date.now() - p.at > CERT_TTL) throw new RunError(409, 'read the certificate first (it is shown for 10 minutes), compare it, then trust it');
    if (String(fingerprint || '') !== p.fingerprint) throw new RunError(409, 'the fingerprint does not match the certificate that was read - read it again');
    pendingCert.delete(t.id); L.info('sysadmin certificate trusted', { id: t.id, by });
    return targets.setPin(t.id, p.fingerprint, by);
  }
  return { status, catalogue, run, readCertificate, trustCertificate, check: (id) => BY_ID[id] || null, log: (limit) => runs.all().sort((a, b) => b.at - a.at).slice(0, Math.min(300, limit || 50)) };
}

module.exports = { createRunner, catalogue, CHECKS, RunError };
