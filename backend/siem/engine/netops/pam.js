// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Privileged Access Management for approved network tasks (tasks.js). The device's WRITE account is not stored on the
 * platform: when an approved task runs, the password is CHECKED OUT from the organisation's PAM for that one SSH session
 * and CHECKED IN when the task ends (the PAM can rotate it). The read-only monitoring logins are unchanged.
 *
 * Works with any PAM through two small programs an administrator installs (the PAM's own CLI / credential-provider agent
 * wrapped in a few lines - see install/pam/zyb-pam-example.sh):
 *   checkout  stdin  {"action":"checkout","account":"<PAM reference set on the device>","device","ip","name","reason",
 *                     "plan","requested_by","approved_by","run_by"}
 *             stdout {"username","password","secret"?, "lease"?}            exit 0
 *   checkin   stdin  {"action":"checkin","account","lease","device","plan","outcome"}     exit 0 (failure is logged)
 * config netops.pam = { enabled: true, checkout: "/usr/local/sbin/zyb-pam-checkout", checkin: "/usr/local/sbin/zyb-pam-checkin",
 *                       required: true (default: no stored write password is used once PAM is on), timeout_s: 30 }
 * Both programs must be absolute paths, owned by root and not writable by group / others - the SIEM runs them, so they
 * must not be replaceable by the service account. The password never appears on a command line, in an environment
 * variable, a log or the plan: only "checked out <account> (lease …)" is recorded.
 *   createPam({ config, log, spawnImpl?, statImpl? }) → { status(), checkout(req) → {username, password, secret, lease}, checkin(req) }
 */
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

function createPam({ config, log, spawnImpl, statImpl } = {}) {
  const L = log || { info() {}, warn() {} };
  const cfg = () => (config && config.netops && config.netops.pam) || {};
  const sp = spawnImpl || spawn, st = statImpl || fs.statSync;

  function checkProgram(p, what) {
    if (!p) return `${what} program not set (config netops.pam.${what})`;
    if (!path.isAbsolute(p)) return `${what} program must be an absolute path`;
    let s; try { s = st(p); } catch (e) { return `${what} program ${p} not found`; }
    if (!s.isFile()) return `${what} program ${p} is not a file`;
    if (s.uid !== 0) return `${what} program ${p} must be owned by root`;
    if (s.mode & 0o022) return `${what} program ${p} must not be writable by group or others (chmod 755)`;
    if (!(s.mode & 0o111)) return `${what} program ${p} is not executable`;
    return null;
  }
  function status() {
    const c = cfg();
    if (!c.enabled) return { enabled: false, required: false, reason: 'PAM is not configured (config netops.pam) - stored write logins are used' };
    const e = checkProgram(c.checkout, 'checkout') || (c.checkin ? checkProgram(c.checkin, 'checkin') : null);
    return e ? { enabled: true, ready: false, required: c.required !== false, reason: e } : { enabled: true, ready: true, required: c.required !== false, checkin: !!c.checkin };
  }
  function run(prog, input) {
    const ms = (Number(cfg().timeout_s) || 30) * 1000;
    return new Promise((resolve) => {
      let child; try { child = sp(prog, [], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C.UTF-8' } }); }
      catch (e) { return resolve({ code: -1, out: '', err: e.message }); }
      let out = '', err = '', done = false;
      const fin = (r) => { if (!done) { done = true; clearTimeout(t); resolve(r); } };
      const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) { /* gone */ } fin({ code: -1, out: '', err: `no answer within ${ms / 1000} s` }); }, ms);
      child.stdout.on('data', (d) => { if (out.length < 65536) out += d; });
      child.stderr.on('data', (d) => { if (err.length < 2000) err += d; });
      child.on('error', (e) => fin({ code: -1, out: '', err: e.message }));
      child.on('close', (code) => fin({ code, out, err }));
      child.stdin.end(JSON.stringify(input));
    });
  }
  async function checkout(req) {
    const s = status(); if (!s.enabled || !s.ready) throw Object.assign(new Error('PAM: ' + s.reason), { code: 503 });
    const r = await run(cfg().checkout, Object.assign({ action: 'checkout' }, req));
    // stderr may come from the PAM's own tool: only its last line, and only when the checkout failed, is shown
    if (r.code !== 0) throw Object.assign(new Error('PAM checkout of "' + req.account + '" failed: ' + (String(r.err).trim().split('\n').pop() || 'exit ' + r.code).slice(0, 200)), { code: 502 });
    let j; try { j = JSON.parse(r.out); } catch (e) { throw Object.assign(new Error('PAM checkout program did not answer JSON'), { code: 502 }); }
    if (!j || typeof j.username !== 'string' || !j.username || typeof j.password !== 'string' || !j.password) throw Object.assign(new Error('PAM checkout answered without a username and password'), { code: 502 });
    L.info('pam checkout', { account: req.account, device: req.device, plan: req.plan, lease: j.lease ? String(j.lease).slice(0, 80) : null });
    return { username: j.username.slice(0, 128), password: j.password.slice(0, 512), secret: typeof j.secret === 'string' ? j.secret.slice(0, 512) : '', lease: j.lease ? String(j.lease).slice(0, 200) : '' };
  }
  async function checkin(req) {
    if (!cfg().checkin) return { ok: true, skipped: true };
    const r = await run(cfg().checkin, Object.assign({ action: 'checkin' }, req));
    if (r.code !== 0) L.warn('pam checkin failed', { account: req.account, device: req.device, plan: req.plan, err: String(r.err).trim().split('\n').pop() });
    return { ok: r.code === 0 };
  }
  return { status, checkout, checkin };
}

module.exports = { createPam };
