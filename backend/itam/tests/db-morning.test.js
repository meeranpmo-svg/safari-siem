// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Morning Health Check (engine/db-morning.js): every database read fresh (dictionary scans + 24 h alert log) and every server,
// one checklist per database / server with PASS / WARN / FAIL / NOT CHECKED (a missing grant says so, never PASS): instance,
// Data Guard (primary destinations; standby lag, MRP, gaps), tablespaces, FRA, ASM, archiving + archive space on the right
// store, backup, alert-log codes, sessions, invalid objects; servers from the read-only SSH pass. Mailed through the SIEM as
// the service identity; signed off by a person (a note required when something failed); scheduled on Riyadh working days.
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createDbMorning } = require('../engine/db-morning');

const PRIMARY = { recs: [
  { kind: 'instance', instance: 'ESS', status: 'OPEN', database_status: 'ACTIVE', open_mode: 'READ WRITE', role: 'PRIMARY', log_mode: 'ARCHIVELOG', archiver: 'STARTED', logins: 'ALLOWED', uptime_s: 3600 * 5, version: '19.0.0.0.0', startup_time: '2026-10-21T02:00:00' },
  { kind: 'tablespace', name: 'USERS', used_pct: 96.2, used_mb: 9620, max_mb: 10000 }, { kind: 'tablespace', name: 'SYSTEM', used_pct: 60, used_mb: 600, max_mb: 1000 },
  { kind: 'fra', name: '+RECO', space_limit_mb: 100000, space_used_mb: 95000, reclaimable_mb: 30000 },
  { kind: 'asm_diskgroup', name: 'DATA', state: 'CONNECTED', type: 'NORMAL', total_mb: 1000000, free_mb: 150000, usable_file_mb: 60000, offline_disks: 0, used_pct: 85 },
  { kind: 'asm_diskgroup', name: 'RECO', state: 'CONNECTED', type: 'EXTERN', total_mb: 200000, free_mb: 120000, usable_file_mb: 120000, offline_disks: 1, used_pct: 40 },
  { kind: 'redo', log_mode: 'ARCHIVELOG', unarchived: 0, dest_status: 'VALID', dest_error: '' },
  { kind: 'archive', logs_24h: 96, mb_24h: 48000, last_age_s: 300 },
  { kind: 'archive_dest', dest_id: 1, dest_name: 'LOG_ARCHIVE_DEST_1', status: 'VALID', target: 'PRIMARY', destination: 'USE_DB_RECOVERY_FILE_DEST', error: '' },
  { kind: 'archive_dest', dest_id: 2, dest_name: 'LOG_ARCHIVE_DEST_2', status: 'ERROR', target: 'STANDBY', destination: 'ESS_DR', error: 'ORA-12541: TNS:no listener' },
  { kind: 'backup', status: 'COMPLETED', input_type: 'DB INCR', age_h: 7, end_time: '2026-10-21T01:00:00' },
  { kind: 'alertlog_24h', lines: 5, capped: false, codes: [{ code: 'ORA-00600', count: 1, last: '2026-10-21T03:00:00Z', sample: 'ORA-00600: internal error code [kcbz]' }, { code: 'ORA-12012', count: 4, last: '2026-10-21T04:00:00Z', sample: 'ORA-12012: error on auto execute of job' }] },
  { kind: 'sessions', total: 300, max_sessions: 1000, active: 20, blocked: 0 },
  { kind: 'invalid_objects', count: 3 }], errors: [], instance: 'ESS', version: '19.0.0.0.0' };
const STANDBY = { recs: [
  { kind: 'instance', instance: 'ESS', status: 'MOUNTED', open_mode: 'MOUNTED', role: 'PHYSICAL STANDBY', db_unique_name: 'ESS_DR', log_mode: 'ARCHIVELOG', archiver: 'STARTED', logins: 'ALLOWED', uptime_s: 86400 * 30 },
  { kind: 'dataguard', apply_lag_s: 2400, transport_lag_s: 30 }, { kind: 'mrp', running: false, status: '' }, { kind: 'archive_gap', gaps: 1, low_seq: 100, high_seq: 104 },
  { kind: 'redo', unarchived: 0 }, { kind: 'archive_dest', dest_id: 1, status: 'VALID', destination: '/u02/arch', error: '' }, { kind: 'archive', logs_24h: 90, mb_24h: 45000 }],
  errors: [{ query: 'tablespace', error: 'privilege', ora: 'ORA-00942' }, { query: 'alert_errors_24h', error: 'privilege', ora: 'ORA-00942' }, { query: 'backup', error: 'privilege' }], instance: 'ESS_DR' };

function setup(e, o = {}) {
  const pushed = [], siem = [], reads = [];
  const targets = [{ key: 'reg:p', ip: '10.0.0.5', host: 'ESS-PRIMARY', service: 'ESS' }, { key: 'reg:s', ip: '10.0.0.6', host: 'ESS-DR', service: 'ESS' }, { key: 'reg:x', ip: '10.0.0.7', host: 'OLD', service: 'X' }];
  const H = { targets: () => ({ list: targets }), readOne: async (t, opt) => { reads.push([t.key, opt]); if (t.key === 'reg:x') throw Object.assign(new Error('login refused'), { cls: 'auth' }); return JSON.parse(JSON.stringify(t.key === 'reg:p' ? PRIMARY : STANDBY)); }, push: async (r) => { pushed.push(...r); return r.length; } };
  const SV = { pass: async () => ({}), view: () => ({ servers: [
    { ip: '10.0.0.5', host: 'ess-db1', databases: ['ESS'], server: { filesystems: [{ mount: '/u01', used_pct: 70 }], mem_total_mb: 65536, mem_avail_mb: 2000, load5: 3, ncpu: 16, oracle: { pmon: ['ESS'], listeners: ['LISTENER'] }, ntp_synced: true } },
    { ip: '10.0.0.6', host: 'ess-dr1', databases: ['ESS_DR'], server: { filesystems: [{ mount: '/u02', used_pct: 96 }, { mount: '/', used_pct: 40 }], mem_total_mb: 65536, mem_avail_mb: 30000, load5: 1, ncpu: 16, oracle: { pmon: [], listeners: [] }, ntp_synced: false } },
    { ip: '10.0.0.7', host: 'old', databases: [], server: null, read_error: 'SSH host key not trusted' }],
    findings: [{ ip: '10.0.0.5', kind: 'memory', severity: 'medium', title: 'ess-db1: only 3% memory available', recommendation: 'Check SGA + PGA' },
      { ip: '10.0.0.6', kind: 'filesystem', severity: 'critical', title: 'ess-dr1 /u02 96% full (Oracle file system)', recommendation: 'free space' },
      { ip: '10.0.0.6', kind: 'instance-down', severity: 'critical', title: 'ess-dr1: instance ESS_DR is in oratab but not running', recommendation: 'start it' },
      { ip: '10.0.0.6', kind: 'ntp', severity: 'medium', title: 'clock', recommendation: 'fix chrony' }] }) };
  let clock = o.clock || Date.parse('2026-10-21T03:30:00Z');   // 06:30 Riyadh, Wednesday
  const M = createDbMorning(e.app, { dbHealth: H, dbServers: SV, now: () => clock, discovery: { siem: { call: async (m, p, who, body) => { siem.push({ m, p, who, body }); return o.siemFail ? { status: 400, json: { error: 'no DBA recipients set' } } : { status: 200, json: { ok: true, recipients: 2 } }; } } } });
  return { M, pushed, siem, reads, setClock: (t) => { clock = t; } };
}
const get = (d, check) => d.checks.find((c) => c.check === check || c.check.startsWith(check));

test('morning check: every database and server, the right status per item, evidence, mail, sign-off', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const { M, pushed, siem, reads } = setup(e);
  const r = await M.run({ user: 'ahmed', role: 'operator' }, 'manual');
  assert.ok(reads.every((x) => x[1].heavy && x[1].morning), 'fresh read with the dictionary scans and the 24 h alert log');
  const p = r.databases.find((d) => d.key === 'reg:p'), s = r.databases.find((d) => d.key === 'reg:s'), x = r.databases.find((d) => d.key === 'reg:x');
  assert.equal(get(p, 'Instance open').status, 'ok'); assert.equal(get(p, 'Restarted recently').status, 'warn');
  assert.equal(get(p, 'Shipping to standby').status, 'fail'); assert.match(get(p, 'Shipping to standby').detail, /ORA-12541/);
  assert.equal(get(p, 'Tablespaces').status, 'fail'); assert.match(get(p, 'Tablespaces').detail, /USERS 96\.2%/);
  assert.equal(get(p, 'Recovery area').status, 'ok', 'reclaimable space counted: 65% after reclaimable');
  assert.equal(get(p, 'ASM disk group DATA').status, 'warn'); assert.equal(get(p, 'ASM disk group RECO').status, 'fail', 'an offline disk fails');
  assert.equal(get(p, 'Archive log space').status, 'ok'); assert.match(get(p, 'Archive log space').value, /recovery area/); assert.match(get(p, 'Archive log space').detail, /96 log\(s\), 46\.9 GB generated in 24 h/);
  assert.equal(get(p, 'Last RMAN backup').status, 'ok');
  assert.equal(get(p, 'ORA- errors').status, 'fail'); assert.match(get(p, 'ORA- errors').fix, /ORA-00600/);
  assert.equal(get(p, 'Sessions').status, 'ok'); assert.equal(get(p, 'Invalid objects').status, 'ok');
  // standby
  assert.equal(get(s, 'Instance open').status, 'ok', 'a mounted standby is fine');
  assert.equal(get(s, 'Apply / transport lag').status, 'fail'); assert.equal(get(s, 'Managed recovery').status, 'fail'); assert.equal(get(s, 'Archive gap').status, 'fail');
  assert.equal(get(s, 'Archive log space').status, 'fail', 'archive destination on /u02 at 96%'); assert.match(get(s, 'Archive log space').value, /\/u02 96%/);
  assert.equal(get(s, 'Tablespaces').status, 'nc'); assert.match(get(s, 'Tablespaces').detail, /ORA-00942.*grant/);
  assert.equal(get(s, 'ORA- errors').status, 'nc'); assert.equal(get(s, 'Last RMAN backup').status, 'nc', 'not readable = NOT CHECKED, never PASS');
  assert.equal(x.status, 'fail'); assert.match(x.checks[0].fix, /refused/);
  // servers
  const s1 = r.servers.find((v) => v.ip === '10.0.0.5'), s2 = r.servers.find((v) => v.ip === '10.0.0.6'), s3 = r.servers.find((v) => v.ip === '10.0.0.7');
  assert.equal(get(s1, 'Memory and swap').status, 'warn'); assert.equal(get(s1, 'File systems').status, 'ok');
  assert.equal(get(s2, 'File systems').status, 'fail'); assert.equal(get(s2, 'Instances and listener').status, 'fail'); assert.equal(get(s2, 'Clock').status, 'warn');
  assert.equal(s3.checks[0].status, 'nc'); assert.match(s3.checks[0].detail, /host key/);
  assert.ok(r.summary.fail >= 10 && r.summary.nc >= 4);
  assert.ok(pushed.length && !pushed.some((x2) => x2.kind === 'alertlog_24h'), 'readings also go to the SIEM');
  // mail
  assert.equal(siem.length, 1); assert.equal(siem[0].p, '/db/dba/morning-report'); assert.equal(siem[0].who.user, 'system:itam-db-health');
  assert.match(siem[0].body.subject, /^\[DB\] Morning health check \d{4}-\d{2}-\d{2}: \d+ FAIL/); assert.match(siem[0].body.html, /ORA-12541/); assert.ok(r.mail.ok);
  // sign-off
  assert.throws(() => M.review(r.id, {}, { user: 'ahmed', role: 'operator' }), /failed checks/);
  assert.throws(() => M.review(r.id, { note: 'x' }, { user: 'system:x', role: 'admin' }), /a person/);
  const rv = M.review(r.id, { note: 'DR listener restarted, USERS extended' }, { user: 'ahmed', role: 'operator' });
  assert.equal(rv.review.by, 'ahmed'); assert.equal(M.status().history[0].reviewed.by, 'ahmed');
});

test('morning check: schedule on Riyadh working days, once a day; settings validated; mail failure recorded', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const { M, siem, setClock } = setup(e, { siemFail: true });
  assert.equal(await M.tick(), null, '06:30 Riyadh: before 07:00');
  setClock(Date.parse('2026-10-21T04:05:00Z'));   // 07:05 Riyadh Wednesday
  const r = await M.tick(); assert.equal(r.why, 'schedule'); assert.equal(r.mail.ok, false); assert.match(r.mail.error, /no DBA recipients/);
  assert.equal(await M.tick(), null, 'once per day');
  setClock(Date.parse('2026-10-23T04:05:00Z'));   // Friday
  assert.equal(await M.tick(), null, 'not on Friday');
  assert.throws(() => M.setSettings({ at: '7am' }, { user: 'syed', role: 'admin' }), /HH:MM/);
  assert.throws(() => M.setSettings({ t: { ts_warn: 99, ts_crit: 95 } }, { user: 'syed', role: 'admin' }), /must not be above/);
  assert.throws(() => M.setSettings({ days: [7] }, { user: 'syed', role: 'admin' }), /days/);
  const S = M.setSettings({ at: '06:45', days: [0, 1, 2, 3, 4, 6] }, { user: 'syed', role: 'admin' });
  assert.deepEqual([S.at, S.days], ['06:45', [0, 1, 2, 3, 4, 6]]);
  assert.equal(siem.length, 1);
});

test('morning check: a destination a DBA DEFERRED is not a failure; local paths are not "to standby"; repeated rows once', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const keep = PRIMARY.recs; t.after(() => { PRIMARY.recs = keep; });
  const base = keep.filter((r) => r.kind !== 'archive_dest');
  const dests = (d3) => [
    { kind: 'archive_dest', dest_id: 1, dest_name: 'LOG_ARCHIVE_DEST_1', status: 'VALID', target: 'PRIMARY', destination: 'USE_DB_RECOVERY_FILE_DEST', error: '' },
    { kind: 'archive_dest', dest_id: 2, dest_name: 'LOG_ARCHIVE_DEST_2', status: 'VALID', target: 'STANDBY', destination: 'ESX', error: '' },
    Object.assign({ kind: 'archive_dest', dest_id: 3, dest_name: 'LOG_ARCHIVE_DEST_3', target: 'PRIMARY', destination: '/backup/arch_test/arch_dest3' }, d3)];
  // as seen on ESX-AGGREGATOR: DEST_2 to the standby VALID, DEST_3 a local test path DEFERRED (with a stale error), each reported twice
  PRIMARY.recs = base.concat(dests({ status: 'DEFERRED', error: 'ORA-19504: failed to create file' }), dests({ status: 'DEFERRED', error: 'ORA-19504: failed to create file' }));
  let r = await setup(e).M.run({ user: 'ahmed', role: 'operator' }, 'manual');
  let c = get(r.databases.find((d) => d.key === 'reg:p'), 'Shipping to standby');
  assert.equal(c.status, 'ok', JSON.stringify(c));
  assert.equal((c.value.match(/LOG_ARCHIVE_DEST_2/g) || []).length, 1, 'each destination once: ' + c.value);
  assert.match(c.value, /local: LOG_ARCHIVE_DEST_3 → \/backup\/arch_test\/arch_dest3: DEFERRED \(switched off by a DBA\)/);
  // the only standby destination deferred: nothing ships - a warning, not a failure
  PRIMARY.recs = base.concat([{ kind: 'archive_dest', dest_id: 2, dest_name: 'LOG_ARCHIVE_DEST_2', status: 'DEFERRED', target: 'STANDBY', destination: 'ESX', error: 'ORA-12541: TNS:no listener' }]);
  r = await setup(e).M.run({ user: 'ahmed', role: 'operator' }, 'manual');
  c = get(r.databases.find((d) => d.key === 'reg:p'), 'Shipping to standby');
  assert.equal(c.status, 'warn'); assert.match(c.fix, /No standby destination is shipping redo/);
});
