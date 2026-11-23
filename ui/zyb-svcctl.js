#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * zyb-svcctl - start / stop / restart a platform service when an administrator asks for it in the portal
 * (Platform Health & Backup > Services). Runs as root, started by zyb-svcctl.path when the SIEM drops a request file;
 * the web side never gets root rights.
 *   request  /var/lib/sentra-siem/platform/svc-request   {id, name, action, by, reason, at}   (written by the SIEM API)
 *   result   /var/lib/zyb-svcctl/history.json          newest first, last 100 actions (read by the SIEM API)
 *   settings /etc/zyb-svcctl.conf (JSON, optional)     {"allow": [...], "no_stop": [...]}
 * Only services in "allow" and only start / stop / restart. Services in "no_stop" (the SIEM and nginx - the portal runs
 * on them, stopping them from the portal would lock everyone out) can be restarted but not stopped.
 */
const fs = require('fs'), path = require('path'), { spawnSync } = require('child_process'), crypto = require('crypto');

const REQ = process.env.ZYB_SVC_REQUEST || '/var/lib/sentra-siem/platform/svc-request';
const DIR = process.env.ZYB_SVC_DIR || '/var/lib/zyb-svcctl';
const CONF = process.env.ZYB_SVC_CONF || '/etc/zyb-svcctl.conf';
const SYSTEMCTL = process.env.ZYB_SYSTEMCTL || 'systemctl';
const DEFAULTS = {
  allow: ['sentra-itam', 'sentra-siem', 'sentra-infra', 'clickhouse-server', 'nginx', 'docker', 'zyb-sysinfo.timer', 'zyb-health.timer', 'zyb-backup.timer'],
  no_stop: ['sentra-siem', 'nginx'],
};
const ACTIONS = ['start', 'stop', 'restart'];

function conf() { let c = {}; try { c = JSON.parse(fs.readFileSync(CONF, 'utf8')); } catch (e) { /* defaults */ } return { allow: Array.isArray(c.allow) ? c.allow.map(String) : DEFAULTS.allow, no_stop: Array.isArray(c.no_stop) ? c.no_stop.map(String) : DEFAULTS.no_stop }; }
function sc(args, timeout) { const r = spawnSync(SYSTEMCTL, args, { encoding: 'utf8', timeout: timeout || 120000 }); return { code: r.status, out: String(r.stdout || '').trim(), err: String(r.stderr || '').trim() || (r.error ? r.error.message : '') }; }
function state(name) { const p = {}; sc(['show', name, '-p', 'LoadState,ActiveState,SubState'], 15000).out.split('\n').forEach((l) => { const i = l.indexOf('='); if (i > 0) p[l.slice(0, i)] = l.slice(i + 1); }); return p; }
const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n || 120);

function history() { try { return JSON.parse(fs.readFileSync(path.join(DIR, 'history.json'), 'utf8')); } catch (e) { return []; } }
function record(entry) {
  fs.mkdirSync(DIR, { recursive: true, mode: 0o755 });
  const h = [entry].concat(history()).slice(0, 100), f = path.join(DIR, 'history.json'), tmp = f + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(h, null, 1), { mode: 0o644 }); fs.renameSync(tmp, f);
}

function main() {
  const work = REQ + '.work';
  try { fs.renameSync(REQ, work); } catch (e) { return 0; }   // nothing to do (or another run took it)
  let q = {};
  try { q = JSON.parse(fs.readFileSync(work, 'utf8')); } catch (e) { q = {}; }
  try { fs.unlinkSync(work); } catch (e) { /* gone */ }
  const c = conf(), name = clean(q.name, 80), action = clean(q.action, 10);
  const entry = { id: clean(q.id, 40) || crypto.randomBytes(6).toString('hex'), at: new Date().toISOString(), requested_at: clean(q.at, 40), by: clean(q.by, 100), reason: clean(q.reason, 300), name, action, ok: false, message: '' };
  if (!/^[A-Za-z0-9@._-]{1,80}$/.test(name) || !c.allow.includes(name)) entry.message = `refused: ${name || '(none)'} is not on the list of services the portal may control (/etc/zyb-svcctl.conf)`;
  else if (!ACTIONS.includes(action)) entry.message = `refused: action must be start, stop or restart`;
  else if (action === 'stop' && c.no_stop.includes(name)) entry.message = `refused: ${name} can be restarted but not stopped from the portal (the portal runs on it)`;
  else {
    const before = state(name);
    if (before.LoadState !== 'loaded') entry.message = `refused: ${name} is not installed on this server`;
    else {
      const r = sc([action, name]);
      const after = state(name);
      entry.before = before.ActiveState; entry.after = after.ActiveState + (after.SubState ? ' / ' + after.SubState : '');
      entry.ok = r.code === 0 && (action === 'stop' ? after.ActiveState !== 'active' : after.ActiveState === 'active' || /\.timer$/.test(name));
      entry.message = r.code === 0 ? `${action} done - now ${entry.after}` : `systemctl ${action} ${name} failed: ${(r.err || r.out).split('\n').slice(-2).join(' ').slice(0, 300)}`;
    }
  }
  record(entry);
  console.log(JSON.stringify(entry));
  sc(['start', '--no-block', 'zyb-health.service'], 10000);   // refresh the dashboard's service list
  return 0;
}

if (require.main === module) process.exit(main());
module.exports = { main, conf, DEFAULTS };
