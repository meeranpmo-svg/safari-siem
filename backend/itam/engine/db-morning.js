// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
/*
 * Databases -> Morning Health Check ({P} = /api/itam). The DBA's daily round - log in to every database server, check every
 * instance, Data Guard, the alert log, archive log and ASM space - done by the platform before the DBA arrives, as one
 * checklist with a PASS / WARN / FAIL per item and the evidence behind it.
 *
 * At settings.at (Riyadh time) on the working days (default Sun-Thu 07:00), and on demand ("Run now"):
 *   every monitored database: a fresh read with its read-only monitoring login (db-health readOne, dictionary scans included,
 *     plus the alert log since yesterday morning grouped by ORA- code) - instance, Data Guard (role, destinations, lag, MRP,
 *     archive gaps), tablespaces, recovery area, ASM disk groups, archiving (archiver, unarchived logs, destinations,
 *     logs / MB generated in 24 h), last RMAN backup, alert log, sessions, invalid objects
 *   every database server: a fresh read-only SSH read (db-servers pass) - file systems, memory / swap, load, instances in
 *     oratab vs running, listener, clock
 * A check the platform could not run says NOT CHECKED with the reason (a missing grant names it) - never PASS.
 * The report is kept (REPORTS_KEEP), e-mailed to the DBA recipients of the Database Dashboard through the SIEM's mail relay
 * (POST /api/soc/db/dba/morning-report, as system:itam-db-health), and signed off on the page by a person ("Reviewed").
 * Routes: GET /db-morning (operator) · GET /db-morning/reports/:id (operator) · POST /db-morning/run (operator)
 *         POST /db-morning/reports/:id/review {note} (operator, a person) · POST /db-morning/settings (admin, a person)
 */
const SC = require('./approve-scopes');

const SYS = { user: 'system:itam-db-health', role: 'admin', ip: '' };
const REPORTS_KEEP = 120, RIYADH_MS = 3 * 3600000;
const DEFAULTS = { enabled: true, at: '07:00', days: [0, 1, 2, 3, 4], mail: true,
  t: { ts_warn: 85, ts_crit: 95, fra_warn: 80, fra_crit: 90, asm_warn: 80, asm_crit: 90, dg_warn_s: 300, dg_crit_s: 1800, backup_warn_h: 26, backup_crit_h: 50, sess_warn: 85, sess_crit: 95, invalid_warn: 50, restart_h: 24 } };
// alert-log errors that need the DBA today (corruption, internal errors, memory, space, archiver stuck, Data Guard)
const ORA_CRITICAL = /^ORA-(00600|07445|04031|01578|00257|01652|01653|01654|01688|19809|19815|16\d{3}|00353|00312|00313|00314|27072|15\d{3}|01110|01113|01115)$/;
const RANK = { fail: 4, warn: 3, nc: 2, ok: 1, na: 0 };

function createDbMorning(app, opts = {}) {
  const store = app.store, meta = store.collection('db_morning_meta'), reps = store.collection('db_morning_reports');
  const H = () => opts.dbHealth || (app.addons && app.addons.dbHealth) || null;
  const SV = () => opts.dbServers || (app.addons && app.addons.dbServers) || null;
  const D = () => opts.discovery || app.discovery || null;
  const now = opts.now || Date.now;
  const lg = app.log || { info() {}, warn() {} };
  const bad = (m, status = 400) => Object.assign(new Error(m), { status });
  const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || SYS.user, role: (who && who.role) || 'system', ip: (who && who.ip) || '', action, target, detail }); };
  let running = null, timer = null;

  function settings() { const v = (meta.get('settings') || {}).value || {}; return Object.assign({}, DEFAULTS, v, { t: Object.assign({}, DEFAULTS.t, v.t || {}) }); }
  function setSettings(b, who) {
    if (!SC.isHuman(who && who.user)) throw bad('only a person changes this', 403);
    b = b || {}; const cur = settings(), n = JSON.parse(JSON.stringify(cur));
    if (b.enabled !== undefined) n.enabled = b.enabled === true;
    if (b.mail !== undefined) n.mail = b.mail === true;
    if (b.at !== undefined) { if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(String(b.at))) throw bad('at must be HH:MM (Riyadh time)'); n.at = String(b.at); }
    if (b.days !== undefined) { if (!Array.isArray(b.days) || !b.days.length || b.days.some((d) => !Number.isInteger(d) || d < 0 || d > 6)) throw bad('days: 0 (Sunday) - 6 (Saturday), at least one'); n.days = [...new Set(b.days)].sort(); }
    if (b.t && typeof b.t === 'object') for (const [k, v] of Object.entries(b.t)) { if (!(k in DEFAULTS.t)) throw bad('unknown threshold ' + clip(k, 30)); const x = Number(v); if (!Number.isFinite(x) || x < 0 || x > 100000) throw bad(k + ' must be a number'); n.t[k] = x; }
    for (const [w, c] of [['ts_warn', 'ts_crit'], ['fra_warn', 'fra_crit'], ['asm_warn', 'asm_crit'], ['dg_warn_s', 'dg_crit_s'], ['backup_warn_h', 'backup_crit_h'], ['sess_warn', 'sess_crit']]) if (n.t[w] > n.t[c]) throw bad(`${w} must not be above ${c}`);
    meta.put({ id: 'settings', value: Object.assign(n, { by: who.user, at_changed: new Date(now()).toISOString() }) });
    audit(who, 'db.morning.settings', 'db-morning', { enabled: n.enabled, at: n.at, days: n.days, mail: n.mail, t: n.t });
    return settings();
  }

  /* ---- the checks ---- */
  const pct = (v) => (v == null ? '—' : (Math.round(v * 10) / 10) + '%');
  const gb = (mb) => (mb == null ? '—' : mb >= 1024 ? Math.round(mb / 102.4) / 10 + ' GB' : Math.round(mb) + ' MB');
  const dur = (s) => (s == null ? '—' : s >= 86400 ? Math.round(s / 8640) / 10 + ' d' : s >= 3600 ? Math.round(s / 360) / 10 + ' h' : s >= 60 ? Math.round(s / 60) + ' min' : Math.round(s) + ' s');
  const lvl = (v, w, c) => (v == null ? null : v >= c ? 'fail' : v >= w ? 'warn' : 'ok');
  function dbChecks(g, T, server) {
    const R = g.recs || [], errs = g.errors || [], k = (kind) => R.filter((x) => x.kind === kind), one = (kind) => k(kind)[0] || null, out = [];
    const err = (q) => errs.find((e) => e.query === q);
    const nc = (q, label) => { const e = err(q); return e ? 'not readable' + (e.ora ? ' (' + e.ora + ')' : '') + ' - the monitoring account needs a grant (Databases → the database → Test shows which)' : 'no reading'; };
    const add = (area, check, status, value, detail, fix) => out.push({ area, check, status, value: value == null ? '' : String(value), detail: detail || '', fix: fix || '' });
    const inst = one('instance'), role = String((inst && inst.role) || '').toUpperCase(), standby = /STANDBY/.test(role);
    // 1 instance
    if (!inst) add('Instance', 'Instance open', 'nc', '', nc('instance'));
    else {
      const okOpen = standby ? /MOUNTED|READ ONLY/.test(String(inst.open_mode).toUpperCase()) : String(inst.status).toUpperCase() === 'OPEN' && /READ WRITE/.test(String(inst.open_mode).toUpperCase());
      const restricted = String(inst.logins || '').toUpperCase() === 'RESTRICTED';
      add('Instance', 'Instance open', okOpen && !restricted ? 'ok' : 'fail', `${inst.status || '?'} · ${inst.open_mode || '?'}${restricted ? ' · RESTRICTED' : ''}`, `${role || 'role ?'} · ${inst.version || ''}`, okOpen ? (restricted ? 'Logins are restricted: ALTER SYSTEM DISABLE RESTRICTED SESSION when the work is done.' : '') : 'Check the alert log and start / open the database (srvctl start database, or STARTUP).');
      const up = inst.uptime_s;
      add('Instance', 'Restarted recently', up != null && up < T.restart_h * 3600 ? 'warn' : up == null ? 'nc' : 'ok', up == null ? '' : 'up ' + dur(up), inst.startup_time ? 'started ' + inst.startup_time : '', up != null && up < T.restart_h * 3600 ? 'An unplanned restart? Check the alert log around the start time.' : '');
    }
    // 2 Data Guard
    const dests = k('archive_dest'), sbDest = dests.filter((d) => /STANDBY/i.test(d.target) || (d.dest_id > 1 && /^[A-Za-z0-9_.]+$/.test(d.destination || '') && !/^\//.test(d.destination || '')));
    if (!inst) add('Data Guard', 'Replication', 'nc', '', nc('instance'));
    else if (standby) {
      const dg = one('dataguard'), mrp = one('mrp'), gap = one('archive_gap');
      const lag = dg ? Math.max(dg.apply_lag_s || 0, dg.transport_lag_s || 0) : null;
      add('Data Guard', 'Apply / transport lag', dg ? lvl(lag, T.dg_warn_s, T.dg_crit_s) || 'nc' : 'nc', dg ? `apply ${dur(dg.apply_lag_s)} · transport ${dur(dg.transport_lag_s)}` : '', dg ? 'standby ' + (inst.db_unique_name || '') : nc('dataguard'), lag != null && lag >= T.dg_warn_s ? 'Check the network to the primary, archive destination errors on the primary, and that MRP is applying.' : '');
      add('Data Guard', 'Managed recovery (MRP)', mrp ? (mrp.running ? 'ok' : 'fail') : 'nc', mrp ? (mrp.running ? (mrp.status || 'running') + (mrp.sequence ? ' · seq ' + mrp.sequence : '') : 'not running') : '', mrp ? '' : nc('mrp'), mrp && !mrp.running ? 'Start apply: ALTER DATABASE RECOVER MANAGED STANDBY DATABASE DISCONNECT (or DGMGRL: EDIT DATABASE … SET STATE=APPLY-ON).' : '');
      add('Data Guard', 'Archive gap', gap ? (gap.gaps ? 'fail' : 'ok') : 'nc', gap ? (gap.gaps ? `${gap.gaps} gap(s), sequences ${gap.low_seq}-${gap.high_seq}` : 'none') : '', gap ? '' : nc('archive_gap'), gap && gap.gaps ? 'Copy / register the missing archive logs from the primary (FAL usually resolves it; check the primary\'s destination status).' : '');
    } else if (sbDest.length || dests.some((d) => d.dest_id > 1)) {
      // one row per destination (RAC instances and repeated readings report the same one); a local path or the recovery area is
      // not "shipping to standby"; DEFERRED / DISABLED is a destination a DBA switched off - shown, never a failure (Oracle keeps
      // the last error text on it, so its error is not counted either). Fail = an enabled standby destination in ERROR / BAD PARAM
      // or with an error; warn = no standby destination is shipping at all.
      const seen = new Set(), remote = dests.filter((d) => d.dest_id > 1).filter((d) => { const key = d.dest_id + '|' + d.destination; if (seen.has(key)) return false; seen.add(key); return true; });
      const isLocal = (d) => /^\/|^[A-Za-z]:\\|^\+|USE_DB_RECOVERY_FILE_DEST|LOCATION=/i.test(String(d.destination || '')) || /^(LOCAL|PRIMARY)$/i.test(String(d.target || ''));
      const off = (d) => /^(DEFERRED|DISABLED|INACTIVE)$/i.test(String(d.status || '').trim());
      const stb = remote.filter((d) => !isLocal(d)), loc = remote.filter(isLocal);
      const badD = stb.filter((d) => !off(d) && (String(d.status).toUpperCase() !== 'VALID' || d.error));
      const shipping = stb.filter((d) => !off(d) && String(d.status).toUpperCase() === 'VALID' && !d.error);
      const lab = (d) => `${d.dest_name || 'dest ' + d.dest_id} → ${d.destination}: ${d.status}${off(d) ? ' (switched off by a DBA)' : ''}`;
      const res = badD.length ? 'fail' : stb.length && !shipping.length ? 'warn' : 'ok';
      add('Data Guard', 'Shipping to standby', res, stb.map(lab).join('; ') + (loc.length ? (stb.length ? ' · ' : '') + 'local: ' + loc.map(lab).join('; ') : ''),
        badD.map((d) => d.error).filter(Boolean).join('; '),
        badD.length ? 'Fix the destination error (network, standby listener, password file), then ALTER SYSTEM SET log_archive_dest_state_N=ENABLE.'
          : res === 'warn' ? 'No standby destination is shipping redo (all are switched off): if the standby should be in sync, re-enable the destination (ALTER SYSTEM SET log_archive_dest_state_N=ENABLE).' : '');
    } else add('Data Guard', 'Replication', err('archive_dest') ? 'nc' : 'na', err('archive_dest') ? '' : 'no standby destination configured', err('archive_dest') ? nc('archive_dest') : '');
    // 3 tablespaces
    const ts = k('tablespace');
    if (!ts.length) add('Space', 'Tablespaces', 'nc', '', nc('tablespace'));
    else {
      const over = ts.filter((x) => x.used_pct != null && x.used_pct >= T.ts_warn).sort((a, b) => b.used_pct - a.used_pct), worst = ts.slice().sort((a, b) => (b.used_pct || 0) - (a.used_pct || 0))[0];
      add('Space', 'Tablespaces', over.length ? lvl(over[0].used_pct, T.ts_warn, T.ts_crit) : 'ok', over.length ? over.length + ' above ' + T.ts_warn + '%' : 'fullest ' + worst.name + ' ' + pct(worst.used_pct),
        over.slice(0, 8).map((x) => `${x.name} ${pct(x.used_pct)} (${gb(x.used_mb)} of ${gb(x.max_mb)})`).join('; '), over.length ? 'Add a datafile / resize (or enable autoextend with a sensible MAXSIZE); for TEMP find the session using it.' : '');
    }
    // 4 recovery area
    const fra = one('fra');
    if (fra) { const eff = fra.space_limit_mb ? (fra.space_used_mb - (fra.reclaimable_mb || 0)) / fra.space_limit_mb * 100 : null;
      add('Space', 'Recovery area (FRA)', lvl(eff, T.fra_warn, T.fra_crit) || 'nc', pct(eff) + ' after reclaimable', `${gb(fra.space_used_mb)} used of ${gb(fra.space_limit_mb)}, ${gb(fra.reclaimable_mb)} reclaimable · ${fra.name}`, eff != null && eff >= T.fra_warn ? 'Back up and delete archive logs (RMAN: BACKUP ARCHIVELOG ALL DELETE INPUT / DELETE OBSOLETE) or raise db_recovery_file_dest_size - a full FRA stops the database.' : ''); }
    else add('Space', 'Recovery area (FRA)', err('fra') ? 'nc' : 'na', err('fra') ? '' : 'not configured', err('fra') ? nc('fra') : '');
    // 5 ASM
    const asm = k('asm_diskgroup');
    if (asm.length) for (const d of asm) {
      const offline = (d.offline_disks || 0) > 0, mounted = /MOUNTED|CONNECTED/i.test(d.state || ''), noMirror = d.usable_file_mb != null && d.usable_file_mb < 0;
      const st = !mounted || offline ? 'fail' : noMirror ? 'warn' : lvl(d.used_pct, T.asm_warn, T.asm_crit) || 'ok';
      add('Space', 'ASM disk group ' + d.name, st, pct(d.used_pct) + ' used', `${d.type || ''} · ${gb(d.free_mb)} free of ${gb(d.total_mb)} · usable ${gb(d.usable_file_mb)} · ${d.state}${offline ? ' · ' + d.offline_disks + ' disk(s) OFFLINE' : ''}`,
        offline ? 'A disk is offline: check the storage paths (multipath), then ALTER DISKGROUP … ONLINE DISK before the repair timer drops it.' : noMirror ? 'Not enough free space to re-mirror after a disk failure (usable_file_mb < 0): add disks.' : st !== 'ok' ? 'Add disks to the disk group or move / purge files (archive logs, old backups).' : '');
    } else add('Space', 'ASM disk groups', err('asm') ? 'nc' : 'na', err('asm') ? '' : 'no ASM (file system storage)', err('asm') ? nc('asm') : '');
    // 6 archiving
    const redo = one('redo'), gen = one('archive');
    if (!inst || String(inst.log_mode || (redo && redo.log_mode) || '').toUpperCase() === 'NOARCHIVELOG') add('Archive logs', 'Archiving', inst ? 'warn' : 'nc', inst ? 'NOARCHIVELOG' : '', inst ? 'no point-in-time recovery and no Data Guard' : nc('instance'), inst ? 'Production databases should run in ARCHIVELOG mode.' : '');
    else {
      const stopped = /STOPPED|FAILED/i.test(inst.archiver || ''), local = dests.find((d) => d.dest_id === 1) || null, lerr = (redo && redo.dest_error) || (local && local.error);
      const st = stopped || lerr ? 'fail' : redo && redo.unarchived >= 2 ? 'warn' : redo ? 'ok' : 'nc';
      add('Archive logs', 'Archiver and local destination', st, `archiver ${inst.archiver || '?'}${redo ? ' · ' + (redo.unarchived || 0) + ' log(s) waiting to archive' : ''}`, [local ? 'destination ' + local.destination : '', lerr ? 'error: ' + lerr : ''].filter(Boolean).join(' · '),
        st === 'fail' ? 'The archiver is stuck (ORA-00257 follows): free space in the archive destination, then ALTER SYSTEM ARCHIVE LOG ALL.' : st === 'warn' ? 'Archiving is falling behind: check the destination\'s speed and space.' : '');
      // where the archive logs go decides which space check covers them
      const dpath = local && local.destination ? String(local.destination) : '';
      const where = /USE_DB_RECOVERY_FILE_DEST/i.test(dpath) || (!dpath && fra) ? 'the recovery area (above)' : /^\+/.test(dpath) ? 'ASM disk group ' + dpath.replace(/^\+/, '').split('/')[0] + ' (above)' : dpath ? 'file system ' + dpath : '';
      let fsSt = null, fsVal = '';
      if (dpath && /^\//.test(dpath) && server && server.filesystems) { const f = server.filesystems.filter((x) => dpath.indexOf(x.mount) === 0).sort((a, b) => b.mount.length - a.mount.length)[0]; if (f) { fsSt = lvl(f.used_pct, 85, 95); fsVal = `${f.mount} ${pct(f.used_pct)}`; } }
      add('Archive logs', 'Archive log space', fsSt || (where ? 'ok' : 'nc'), fsVal || (where ? 'checked as ' + where : ''), gen ? `${gen.logs_24h} log(s), ${gb(gen.mb_24h)} generated in 24 h${gen.last_age_s != null ? ' · last ' + dur(gen.last_age_s) + ' ago' : ''}` : nc('archive_gen'),
        fsSt && fsSt !== 'ok' ? 'Back up and delete archive logs with RMAN, or extend the file system, before the archiver stops.' : !where ? 'The archive destination could not be read.' : '');
    }
    // 7 backup
    const bk = one('backup');
    if (!bk) add('Backup', 'Last RMAN backup', 'nc', '', nc('backup'));
    else if (bk.status === 'NONE') add('Backup', 'Last RMAN backup', 'fail', 'no RMAN backup job found', 'backups taken outside RMAN (storage snapshots, Data Pump) are not seen', 'Confirm how this database is backed up; an RMAN job that runs elsewhere still records here.');
    else { const failed = /FAILED|ERRORS/i.test(bk.status || ''), age = bk.age_h;
      add('Backup', 'Last RMAN backup', failed ? 'fail' : lvl(age, T.backup_warn_h, T.backup_crit_h) || 'nc', `${bk.status} · ${bk.input_type || ''} · ${age == null ? '?' : age + ' h ago'}`, `${bk.end_time || bk.start_time || ''}${bk.output_mb ? ' · ' + gb(bk.output_mb) : ''}`, failed ? 'Read the RMAN log of the failed job and run it again.' : age >= T.backup_warn_h ? 'The scheduled backup did not run: check the scheduler / cron and the backup target.' : ''); }
    // 8 alert log
    const al = one('alertlog_24h');
    if (!al) add('Alert log', 'ORA- errors since yesterday', 'nc', '', nc('alert_errors_24h'));
    else { const crit = al.codes.filter((c) => ORA_CRITICAL.test(c.code));
      add('Alert log', 'ORA- errors since yesterday', crit.length ? 'fail' : al.lines ? 'warn' : 'ok', al.lines ? `${al.lines} line(s)${al.capped ? '+' : ''}, ${al.codes.length} code(s)` : 'none',
        al.codes.slice(0, 8).map((c) => `${c.code} ×${c.count} (last ${c.last}): ${c.sample}`).join('\n'), crit.length ? 'Critical: ' + crit.map((c) => c.code).join(', ') + ' - see the Error findings on the Database Dashboard for what each means and what to check.' : ''); }
    // 9 sessions
    const ss = one('sessions');
    if (ss) { const u = ss.max_sessions ? ss.total / ss.max_sessions * 100 : null;
      add('Sessions', 'Sessions used / blocked', ss.blocked ? 'warn' : lvl(u, T.sess_warn, T.sess_crit) || 'ok', `${ss.total} of ${ss.max_sessions || '?'} (${pct(u)}) · ${ss.blocked || 0} blocked`, `${ss.active || 0} active`, ss.blocked ? 'See Long-Running Queries for the blocker.' : u >= T.sess_warn ? 'Close to the sessions limit: look for connection-pool leaks before raising SESSIONS / PROCESSES.' : ''); }
    else add('Sessions', 'Sessions used / blocked', 'nc', '', nc('sessions'));
    // 10 invalid objects
    const inv = one('invalid_objects');
    if (inv) add('Objects', 'Invalid objects', inv.count > T.invalid_warn ? 'warn' : 'ok', String(inv.count), '', inv.count > T.invalid_warn ? 'Recompile (utlrp.sql) after checking what changed; new invalid objects after a release are the usual cause.' : '');
    else add('Objects', 'Invalid objects', 'nc', '', nc('invalid_objects'));
    return out;
  }
  function serverChecks(row, findings) {
    const out = [], add = (area, check, status, value, detail, fix) => out.push({ area, check, status, value: value == null ? '' : String(value), detail: detail || '', fix: fix || '' });
    const v = row && row.server;
    if (!v) { add('Server', 'Read over SSH', 'nc', '', (row && row.read_error) || (findings.find((f) => f.kind === 'not-read') || {}).recommendation || 'not read', 'Give the platform a read-only SSH login on this server (Databases → Database Servers).'); return out; }
    const F = (kind) => findings.filter((f) => f.kind === kind), st = (L) => (L.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'fail' : L.some((f) => f.severity === 'medium') ? 'warn' : 'ok');
    const fs = (v.filesystems || []).filter((f) => f.used_pct != null).sort((a, b) => b.used_pct - a.used_pct);
    add('Server', 'File systems', st(F('filesystem').concat(F('inodes'))), fs.length ? `fullest ${fs[0].mount} ${pct(fs[0].used_pct)}` : '—', F('filesystem').concat(F('inodes')).map((f) => f.title).join('; ') || fs.slice(0, 4).map((f) => `${f.mount} ${pct(f.used_pct)}`).join('; '), (F('filesystem')[0] || F('inodes')[0] || {}).recommendation || '');
    add('Server', 'Memory and swap', st(F('memory').concat(F('swap'))), v.mem_total_mb ? `${gb(v.mem_avail_mb)} available of ${gb(v.mem_total_mb)}${v.swap_total_mb ? ' · swap ' + gb(v.swap_used_mb) + ' used' : ''}` : '—', F('memory').concat(F('swap')).map((f) => f.title).join('; '), (F('memory')[0] || F('swap')[0] || {}).recommendation || '');
    add('Server', 'CPU load', st(F('load')), v.load5 != null ? `load ${v.load5} on ${v.ncpu || '?'} CPUs` : '—', F('load').map((f) => f.title).join('; '), (F('load')[0] || {}).recommendation || '');
    add('Server', 'Instances and listener', st(F('instance-down').concat(F('listener'))), `running: ${((v.oracle && v.oracle.pmon) || []).join(', ') || 'none'} · listeners: ${((v.oracle && v.oracle.listeners) || []).length}`, F('instance-down').concat(F('listener')).map((f) => f.title).join('; '), (F('instance-down')[0] || F('listener')[0] || {}).recommendation || '');
    add('Server', 'Clock (NTP)', v.ntp_synced === false ? 'warn' : v.ntp_synced ? 'ok' : 'nc', v.ntp_synced === false ? 'not synchronised' : v.ntp_synced ? 'synchronised' : '', '', v.ntp_synced === false ? (F('ntp')[0] || {}).recommendation || '' : '');
    return out;
  }
  const worst = (checks) => checks.reduce((m, c) => (RANK[c.status] > RANK[m] ? c.status : m), 'na');
  const count = (L, s) => L.reduce((a, x) => a + x.checks.filter((c) => c.status === s).length, 0);

  async function run(who, why) {
    if (running) return running;
    running = (async () => {
      const t0 = now(), T = settings().t, h = H(); if (!h) throw bad('Database health is not installed', 503);
      const id = 'MHC-' + new Date(t0 + RIYADH_MS).toISOString().slice(0, 16).replace(/[-:T]/g, '').replace(/^(\d{8})(\d{4})$/, '$1-$2');
      // servers first (one read-only SSH pass), then each database
      let srv = null, srvErr = null;
      if (SV()) { try { await SV().pass(); srv = SV().view(); } catch (e) { srvErr = String(e.message || e).slice(0, 200); } }
      const rows = (srv && srv.servers) || [], findings = (srv && srv.findings) || [];
      const dbs = [], push = [];
      for (const t of h.targets().list) {
        const row = rows.find((r) => r.ip === t.ip) || null;
        const d = { key: t.key, label: t.host || t.ip, ip: t.ip, service: t.service || '', instance: t.instance || '', role: '', checks: [] };
        try {
          const g = await h.readOne(t, { heavy: true, morning: true });
          const inst = g.recs.find((x) => x.kind === 'instance') || {};
          Object.assign(d, { instance: g.instance || d.instance, role: inst.role || '', db_unique_name: inst.db_unique_name || '', version: g.version || '' });
          d.checks = dbChecks(g, T, row && row.server);
          push.push(...g.recs.filter((x) => x.kind !== 'alertlog_24h'));
        } catch (e) { d.checks = [{ area: 'Connection', check: 'Read the database', status: 'fail', value: 'not read', detail: String(e.message || e).slice(0, 200), fix: e.cls === 'auth' ? 'The monitoring login was refused: test it in Databases (the database is paused until then).' : e.cls === 'unsafe' ? 'The monitoring account has more than read-only rights - use a read-only user.' : 'Check that the database and its listener are up and reachable from the platform.' }]; }
        d.status = worst(d.checks); dbs.push(d);
      }
      if (push.length) { try { await h.push(push); } catch (e) { /* the report stands on its own; the SIEM gets the next pass */ } }
      const servers = rows.map((r) => { const F = findings.filter((f) => f.ip === r.ip), c = serverChecks(r, F); return { ip: r.ip, host: r.host, databases: r.databases, os: r.os, read_at: r.read_at, checks: c, status: worst(c) }; });
      const all = dbs.concat(servers);
      const rep = { id, at: new Date(t0).toISOString(), day: new Date(t0 + RIYADH_MS).toISOString().slice(0, 10), by: (who && who.user) || SYS.user, why: why || 'manual', took_s: Math.round((now() - t0) / 1000),
        databases: dbs, servers, servers_error: srvErr, summary: { databases: dbs.length, servers: servers.length, fail: count(all, 'fail'), warn: count(all, 'warn'), nc: count(all, 'nc'), ok: count(all, 'ok'),
          status: all.length ? worst(all.map((x) => ({ status: x.status }))) : 'nc' }, review: null, mail: null };
      reps.put(rep);
      const old = reps.all().sort((a, b) => (a.at < b.at ? 1 : -1)).slice(REPORTS_KEEP); for (const o of old) reps.remove(o.id);
      audit(who, 'db.morning.run', id, { why: rep.why, databases: dbs.length, servers: servers.length, fail: rep.summary.fail, warn: rep.summary.warn, nc: rep.summary.nc });
      if (settings().mail) { rep.mail = await mail(rep); reps.put(rep); }
      return rep;
    })().finally(() => { running = null; });
    return running;
  }

  /* ---- the e-mail: through the SIEM's relay to the Database Dashboard's DBA recipients ---- */
  const esc = (x) => String(x == null ? '' : x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const LBL = { fail: 'FAIL', warn: 'WARN', nc: 'NOT CHECKED', ok: 'PASS', na: 'n/a' }, CLR = { fail: '#c62828', warn: '#b26a00', nc: '#555', ok: '#2e7d32', na: '#888' };
  function mailBody(rep) {
    const s = rep.summary, head = `${rep.day}: ${s.fail} fail, ${s.warn} warning, ${s.nc} not checked - ${s.databases} database(s), ${s.servers} server(s)`;
    const block = (x, kind) => { const bad = x.checks.filter((c) => c.status === 'fail' || c.status === 'warn' || c.status === 'nc');
      return `<h3 style="margin:14px 0 4px">${esc(kind)} ${esc(x.label || x.host)} ${x.instance ? '· ' + esc(x.instance) : ''} ${x.role ? '· ' + esc(x.role) : ''} <span style="color:${CLR[x.status]}">${LBL[x.status]}</span></h3>`
        + (bad.length ? '<table cellpadding="4" style="border-collapse:collapse;font-size:13px">' + bad.map((c) => `<tr><td style="color:${CLR[c.status]};font-weight:bold">${LBL[c.status]}</td><td>${esc(c.area)} · ${esc(c.check)}</td><td>${esc(c.value)}</td><td style="color:#555">${esc(c.detail).replace(/\n/g, '<br>')}</td></tr>`).join('') + '</table>' : '<p style="color:#2e7d32;margin:0">All checks passed.</p>'); };
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif"><h2 style="margin:0">Morning database health check</h2><p>${esc(head)}</p>${rep.databases.map((d) => block(d, 'Database')).join('')}${rep.servers.map((v) => block(v, 'Server')).join('')}<p style="color:#555;font-size:12px">Read-only checks run by the platform at ${esc(rep.at)} (${esc(rep.id)}). Open Databases → Morning Health Check for the evidence and to sign it off.</p></div>`;
    const text = [head, ''].concat(rep.databases.concat(rep.servers).map((x) => `${x.label || x.host} ${x.instance || ''}: ${LBL[x.status]}\n` + x.checks.filter((c) => c.status === 'fail' || c.status === 'warn' || c.status === 'nc').map((c) => `  ${LBL[c.status]} ${c.area} · ${c.check}: ${c.value} ${c.detail ? '- ' + c.detail.replace(/\n/g, ' | ') : ''}`).join('\n'))).join('\n');
    return { subject: `[DB] Morning health check ${rep.day}: ${s.fail ? s.fail + ' FAIL' : s.warn ? s.warn + ' warning(s)' : 'all passed'}`, text, html };
  }
  async function mail(rep) {
    const d = D(); if (!d || !d.siem || typeof d.siem.call !== 'function') return { ok: false, error: 'no link to the SIEM (mail relay)' };
    try { const r = await d.siem.call('POST', '/db/dba/morning-report', SYS, Object.assign({ id: rep.id, day: rep.day }, mailBody(rep)));
      return r && r.status >= 200 && r.status < 300 ? { ok: true, at: new Date(now()).toISOString(), recipients: (r.json && r.json.recipients) || null } : { ok: false, error: (r && r.json && r.json.error) || ('SIEM HTTP ' + (r && r.status)) }; }
    catch (e) { return { ok: false, error: String(e.message || e).slice(0, 200) }; }
  }

  function review(id, b, who) {
    if (!SC.isHuman(who && who.user)) throw bad('a person signs the health check off', 403);
    const r = reps.get(String(id || '')); if (!r) throw bad('report not found', 404);
    const note = clip(b && b.note, 500);
    if (r.summary.fail && !note) throw bad('the report has failed checks - say what was done or who is on it');
    r.review = { by: who.user, at: new Date(now()).toISOString(), note };
    reps.put(r); audit(who, 'db.morning.review', r.id, { note, fail: r.summary.fail, warn: r.summary.warn });
    return r;
  }
  function status() {
    const L = reps.all().sort((a, b) => (a.at < b.at ? 1 : -1));
    return { settings: settings(), running: !!running, next: nextRun(), latest: L[0] || null,
      history: L.slice(0, 60).map((r) => ({ id: r.id, at: r.at, day: r.day, by: r.by, why: r.why, summary: r.summary, reviewed: r.review ? { by: r.review.by, at: r.review.at } : null, mail: r.mail ? { ok: r.mail.ok, error: r.mail.error || null } : null })) };
  }
  function get(id) { const r = reps.get(String(id || '')); if (!r) throw bad('report not found', 404); return r; }

  // schedule: Riyadh local time; once per working day; a platform that was down at that time runs it when it comes back that day
  function localParts(t) { const d = new Date(t + RIYADH_MS); return { day: d.toISOString().slice(0, 10), dow: d.getUTCDay(), hm: d.toISOString().slice(11, 16) }; }
  function nextRun() {
    const S = settings(); if (!S.enabled) return null;
    for (let i = 0; i < 8; i++) { const t = now() + i * 86400000, p = localParts(t); if (!S.days.includes(p.dow)) continue; if (i === 0 && (p.hm >= S.at && reps.all((r) => r.day === p.day && r.why === 'schedule').length)) continue;
      if (i === 0 && p.hm >= S.at) return new Date(now()).toISOString(); return new Date(Date.parse(p.day + 'T' + S.at + ':00Z') - RIYADH_MS).toISOString(); }
    return null;
  }
  async function tick() {
    const S = settings(); if (!S.enabled || running) return null;
    const p = localParts(now()); if (!S.days.includes(p.dow) || p.hm < S.at) return null;
    if (reps.all((r) => r.day === p.day && r.why === 'schedule').length) return null;
    const last = (meta.get('last_try') || {}).value; if (last && last.day === p.day && now() - Date.parse(last.at) < 30 * 60000) return null;   // a failed run retries every 30 min
    meta.put({ id: 'last_try', value: { day: p.day, at: new Date(now()).toISOString() } });
    try { return await run(SYS, 'schedule'); } catch (e) { lg.warn('db-morning: scheduled run failed', { err: e.message }); return null; }
  }
  function start() { if (timer) return; timer = setInterval(guardOf(app, 'db-morning.tick', () => tick()), 60000); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  return { settings, setSettings, run, review, status, get, tick, start, stop, dbChecks, serverChecks, mailBody };
}

function registerDbMorning(srv, app, opts = {}) {
  const M = createDbMorning(app, opts);
  (app.addons = app.addons || {}).dbMorning = M;
  srv.route('GET', '/db-morning', (ctx) => { ctx.need('operator'); return M.status(); });
  srv.route('GET', '/db-morning/reports/:id', (ctx) => { ctx.need('operator'); return M.get(ctx.params.id); });
  srv.route('POST', '/db-morning/run', async (ctx) => { ctx.need('operator'); return M.run(ctx.who, 'manual'); });
  srv.route('POST', '/db-morning/reports/:id/review', (ctx) => { ctx.need('operator'); return M.review(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/db-morning/settings', (ctx) => { ctx.need('admin'); return M.setSettings(ctx.body || {}, ctx.who); });
  if (!opts.noTimer) M.start();
  return M;
}

module.exports = { createDbMorning, registerDbMorning, ORA_CRITICAL };
