// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Platform backup trigger for the "Platform Health & Backup" dashboard. The SIEM never runs the backup itself: it drops
 * a request file that systemd watches (zyb-backup.path → zyb-backup.service, root), so the web side gets no root rights.
 *   POST {P}/platform/backup        admin → {queued, status}    (409 while a request is already waiting)
 *   GET  {P}/platform/backup        any signed-in user → backup status + current settings (no secrets: file names,
 *                                   sizes, times, folders, the key's fingerprint - never the key)
 *   PUT  {P}/platform/backup/settings  admin {schedule HH:MM, keep_days, keep_min, events_days, verify, remote_dir,
 *                                   sftp_target, sftp_key, extra_paths} → queued; the root helper (zyb-backup
 *                                   --apply-settings, started by zyb-backup-settings.path) checks every value again
 * Paths: status in config.platform.backup_dir (default /var/lib/zyb-backup, read-only for the SIEM); the request file is
 * <data_dir>/platform/backup-request (inside the SIEM's writable sandbox), watched by zyb-backup.path (install-platform.sh).
 * Service control, same pattern (zyb-svcctl.path → zyb-svcctl.js, root, re-checks everything):
 *   GET  {P}/platform/service       operator → {available, allow[], no_stop[], queued, history[]}
 *   POST {P}/platform/service       admin {name, action: start|stop|restart, reason} → {queued, id}  (409 while one waits)
 * Allowed services come from /etc/zyb-svcctl.conf (read-only here); the SIEM refuses early, the root helper decides.
 */
const fs = require('node:fs');
const path = require('node:path');
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');

function register(api, deps) {
  const pc = (deps.config && deps.config.platform) || {}, P = prefixOf(deps), dir = pc.backup_dir || '/var/lib/zyb-backup';
  const qdir = pc.queue_dir || path.join((deps.config && deps.config.data_dir) || '/var/lib/sentra-siem', 'platform'), reqFile = path.join(qdir, 'backup-request');
  const status = () => { try { return JSON.parse(fs.readFileSync(path.join(dir, 'status.json'), 'utf8')); } catch { return null; } };
  const settings = () => { try { return JSON.parse(fs.readFileSync(path.join(dir, 'settings.json'), 'utf8')); } catch { return null; } };
  const setFile = path.join(qdir, 'backup-settings.json');
  api.route('GET', `${P}/platform/backup`, wrap(deps, null, (ctx) => ctx.ok({ status: status(), settings: settings(), queued: fs.existsSync(reqFile), settings_pending: fs.existsSync(setFile) })));
  api.route('PUT', `${P}/platform/backup/settings`, wrap(deps, 'admin', (ctx) => {
    if (!fs.existsSync(dir)) throw new HttpError(409, 'the backup service is not installed on this server (install-platform.sh)');
    const b = (ctx.body && typeof ctx.body === 'object') ? ctx.body : {}, s = {}, errs = [];
    const P2 = /^\/[A-Za-z0-9._\/-]+$/;
    // the same checks the root helper repeats - early, so the admin sees the problem on the page at once
    if ('schedule' in b) { if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(String(b.schedule))) errs.push('time must be HH:MM (24 h)'); else s.schedule = String(b.schedule); }
    for (const [k, lo, hi, label] of [['keep_days', 7, 365, 'days to keep'], ['keep_min', 3, 100, 'keep at least'], ['events_days', 0, 365, 'SIEM log days']]) if (k in b) { const n = Number(b[k]); if (!Number.isInteger(n) || n < lo || n > hi) errs.push(`${label} must be ${lo}-${hi}`); else s[k] = n; }
    if ('verify' in b) s.verify = b.verify === true;
    for (const k of ['remote_dir', 'sftp_key']) if (k in b) { const v = String(b[k] || '').trim(); if (v && (!P2.test(v) || v.includes('..'))) errs.push(`${k === 'remote_dir' ? 'share folder' : 'SFTP key'} must be an absolute path`); else s[k] = v; }
    // the root helper copies backups only under a backup mount root (and refuses links out of it); say so early
    if (s.remote_dir && !/^\/(mnt|media|srv|backup)\//.test(s.remote_dir)) { errs.push('share folder must be under /mnt, /media, /srv or /backup'); delete s.remote_dir; }
    if ('sftp_target' in b) { const v = String(b.sftp_target || '').trim(); if (v && !/^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.-]{1,253}:\/[A-Za-z0-9._\/-]*$/.test(v)) errs.push('SFTP target must look like user@host:/path'); else s.sftp_target = v; }
    if ('extra_paths' in b) { const L = String(b.extra_paths || '').split(/[\s,]+/).filter(Boolean); if (L.length > 20 || L.some((v) => !P2.test(v) || v.includes('..'))) errs.push('extra folders: absolute paths only, at most 20'); else s.extra_paths = L.join(' '); }
    if (errs.length) { const e = new HttpError(400, errs.join('; ')); e.errors = errs; throw e; }
    if (!Object.keys(s).length) throw new HttpError(400, 'nothing to change');
    try { fs.mkdirSync(qdir, { recursive: true, mode: 0o750 }); } catch (e) { throw new HttpError(500, `could not queue the settings (${e.code || 'error'})`); }
    if (fs.existsSync(setFile)) throw new HttpError(409, 'a settings change is already waiting to be applied - try again in a moment');
    try { fs.writeFileSync(setFile, JSON.stringify({ by: String(ctx.user || 'admin').replace(/[^A-Za-z0-9@._ :-]/g, '').slice(0, 100), at: new Date().toISOString(), settings: s }), { mode: 0o660 }); }
    catch (e) { throw new HttpError(500, `could not queue the settings (${e.code || 'error'})`); }
    audit(ctx, 'platform.backup.settings', 'zyb-backup', s);
    return ctx.ok({ queued: true, settings: settings() });
  }));
  api.route('POST', `${P}/platform/backup`, wrap(deps, 'admin', (ctx) => {
    if (!fs.existsSync(dir)) throw new HttpError(409, 'the backup service is not installed on this server (install-platform.sh)');
    const f = reqFile;
    try { fs.mkdirSync(qdir, { recursive: true, mode: 0o750 }); } catch (e) { throw new HttpError(500, `could not queue the backup (${e.code || 'error'})`); }
    if (fs.existsSync(f)) throw new HttpError(409, 'a backup has already been requested and will start in a moment');
    try { fs.writeFileSync(f, String(ctx.user || 'admin').replace(/[^A-Za-z0-9@._ :-]/g, '').slice(0, 100), { mode: 0o660 }); }
    catch (e) { throw new HttpError(500, `could not queue the backup (${e.code || 'error'})`); }
    audit(ctx, 'platform.backup.request', 'zyb-backup', {});
    return ctx.ok({ queued: true, status: status() });
  }));
}

const SVC_DEFAULTS = { allow: ['sentra-itam', 'sentra-siem', 'sentra-infra', 'clickhouse-server', 'nginx', 'docker', 'zyb-sysinfo.timer', 'zyb-health.timer', 'zyb-backup.timer'], no_stop: ['sentra-siem', 'nginx'] };
function registerServices(api, deps) {
  const pc = (deps.config && deps.config.platform) || {}, P = prefixOf(deps);
  const qdir = pc.queue_dir || path.join((deps.config && deps.config.data_dir) || '/var/lib/sentra-siem', 'platform'), reqFile = path.join(qdir, 'svc-request');
  const sdir = pc.svcctl_dir || '/var/lib/zyb-svcctl', confFile = pc.svcctl_conf || '/etc/zyb-svcctl.conf';
  const conf = () => { let c = {}; try { c = JSON.parse(fs.readFileSync(confFile, 'utf8')); } catch { c = {}; } return { allow: Array.isArray(c.allow) ? c.allow.map(String) : SVC_DEFAULTS.allow, no_stop: Array.isArray(c.no_stop) ? c.no_stop.map(String) : SVC_DEFAULTS.no_stop }; };
  const history = () => { try { return JSON.parse(fs.readFileSync(path.join(sdir, 'history.json'), 'utf8')); } catch { return []; } };
  const queued = () => { try { return JSON.parse(fs.readFileSync(reqFile, 'utf8')); } catch { return null; } };
  api.route('GET', `${P}/platform/service`, wrap(deps, 'operator', (ctx) => { const c = conf(); return ctx.ok({ available: fs.existsSync(sdir), allow: c.allow, no_stop: c.no_stop, queued: queued(), history: history().slice(0, 50) }); }));
  api.route('POST', `${P}/platform/service`, wrap(deps, 'admin', (ctx) => {
    const b = ctx.body || {}, name = String(b.name || ''), action = String(b.action || ''), reason = String(b.reason || '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 300);
    if (!fs.existsSync(sdir)) throw new HttpError(409, 'service control is not installed on this server (install-platform.sh)');
    const c = conf();
    if (!c.allow.includes(name)) throw new HttpError(400, `${name || 'that service'} is not on the list of services the portal may control`);
    if (!['start', 'stop', 'restart'].includes(action)) throw new HttpError(400, 'action must be start, stop or restart');
    if (action === 'stop' && c.no_stop.includes(name)) throw new HttpError(400, `${name} can be restarted but not stopped from the portal (the portal runs on it)`);
    if (reason.length < 3) throw new HttpError(400, 'give a reason (kept in the audit log)');
    if (fs.existsSync(reqFile)) throw new HttpError(409, 'another service action is waiting to run - try again in a few seconds');
    const id = require('node:crypto').randomBytes(6).toString('hex');
    try { fs.mkdirSync(qdir, { recursive: true, mode: 0o750 }); fs.writeFileSync(reqFile, JSON.stringify({ id, name, action, reason, by: String(ctx.user || 'admin').slice(0, 100), at: new Date().toISOString() }), { mode: 0o660 }); }
    catch (e) { throw new HttpError(500, `could not queue the action (${e.code || 'error'})`); }
    audit(ctx, 'platform.service.' + action, name, { reason, id });
    return ctx.ok({ queued: true, id });
  }));
}

function registerAll(api, deps) { register(api, deps); registerServices(api, deps); }

module.exports = { register: registerAll, registerBackupOnly: register, registerServices };
