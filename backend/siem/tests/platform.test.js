// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Platform backup trigger: queues a request file (no root), refuses duplicates / missing install, admin only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('platform backup: queue request, duplicate refused, status read', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zb-'));
  const R = {}; require('../engine/soc/platform').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: { platform: { backup_dir: path.join(dir, 'zb'), queue_dir: path.join(dir, 'q') } }, log: { error() {} } });
  const call = async (m, role) => { const o = {}; await R[m + ' /api/soc/platform/backup']({ role, user: 'siva<x>', need: (r) => { if (r === 'admin' && role !== 'admin') { o.s = 403; return false; } return true; }, audit() {}, ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }); return o; };
  assert.equal((await call('POST', 'admin')).s, 409, 'not installed');
  fs.mkdirSync(path.join(dir, 'zb')); fs.writeFileSync(path.join(dir, 'zb', 'status.json'), JSON.stringify({ last: { ok: true, file: 'x.enc' } }));
  assert.equal((await call('POST', 'viewer')).s, 403);
  const r = await call('POST', 'admin'); assert.equal(r.s, 200); assert.equal(r.b.queued, true); assert.equal(r.b.status.last.file, 'x.enc');
  assert.equal(fs.readFileSync(path.join(dir, 'q', 'backup-request'), 'utf8'), 'sivax');
  assert.equal((await call('POST', 'admin')).s, 409, 'already queued');
  const g = await call('GET', 'viewer'); assert.equal(g.b.queued, true);
});

test('platform services: allow list, start / stop / restart, no stop of the portal services, reason required, one at a time', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zs-'));
  const conf = path.join(dir, 'svc.conf'); fs.writeFileSync(conf, JSON.stringify({ allow: ['sentra-itam', 'sentra-siem'], no_stop: ['sentra-siem'] }));
  const R = {}; const audits = [];
  require('../engine/soc/platform').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: { platform: { backup_dir: path.join(dir, 'zb'), queue_dir: path.join(dir, 'q'), svcctl_dir: path.join(dir, 'svc'), svcctl_conf: conf } }, log: { error() {} } });
  const call = async (m, role, body) => { const o = {}; await R[m + ' /api/soc/platform/service']({ role, user: 'syed', body, need: (r) => { const rank = { viewer: 0, operator: 2, admin: 3 }; if (rank[role] < rank[r]) { o.s = 403; return false; } return true; }, audit: (a) => audits.push(a), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }); return o; };
  assert.equal((await call('POST', 'admin', { name: 'sentra-itam', action: 'restart', reason: 'not answering' })).s, 409, 'helper not installed');
  fs.mkdirSync(path.join(dir, 'svc'));
  assert.equal((await call('POST', 'operator', { name: 'sentra-itam', action: 'restart', reason: 'x y z' })).s, 403);
  assert.equal((await call('POST', 'admin', { name: 'sshd', action: 'stop', reason: 'abc' })).s, 400);
  assert.equal((await call('POST', 'admin', { name: 'sentra-siem', action: 'stop', reason: 'abc' })).s, 400);
  assert.equal((await call('POST', 'admin', { name: 'sentra-itam', action: 'reload', reason: 'abc' })).s, 400);
  assert.equal((await call('POST', 'admin', { name: 'sentra-itam', action: 'restart', reason: '' })).s, 400);
  const ok = await call('POST', 'admin', { name: 'sentra-itam', action: 'restart', reason: 'Asset Discovery not reachable' });
  assert.equal(ok.s, 200); const q = JSON.parse(fs.readFileSync(path.join(dir, 'q', 'svc-request'), 'utf8'));
  assert.deepEqual([q.name, q.action, q.by, q.reason, q.id], ['sentra-itam', 'restart', 'syed', 'Asset Discovery not reachable', ok.b.id]);
  assert.equal((await call('POST', 'admin', { name: 'sentra-siem', action: 'restart', reason: 'abc' })).s, 409, 'one at a time');
  const g = await call('GET', 'operator'); assert.equal(g.b.available, true); assert.deepEqual(g.b.no_stop, ['sentra-siem']); assert.equal(g.b.queued.name, 'sentra-itam');
  assert.equal((await call('GET', 'viewer')).s, 403);
});

test('platform backup settings: admin only, checked early, queued for the root helper, current settings read back', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zbs-'));
  const R = {}, audits = [];
  require('../engine/soc/platform').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: { platform: { backup_dir: path.join(dir, 'zb'), queue_dir: path.join(dir, 'q') } }, log: { error() {} } });
  const call = async (m, p, role, body) => { const o = {}; const rv = await R[m + ' /api/soc/platform/backup' + p]({ role, user: 'syed', body, need: (r) => { if (r === 'admin' && role !== 'admin') { o.s = 403; return false; } return true; }, audit: (a, t, d) => audits.push([a, d]), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }); if (rv !== undefined && !o.s) { o.s = 200; o.b = rv; } return o; };
  const good = { schedule: '02:15', keep_days: 30, keep_min: 5, events_days: 7, verify: true, remote_dir: '/mnt/backup', sftp_target: 'backup@10.1.1.5:/backups/as', sftp_key: '/root/.ssh/zyb', extra_paths: '/srv/portal, /etc/pki' };
  assert.equal((await call('PUT', '/settings', 'admin', good)).s, 409, 'not installed');
  fs.mkdirSync(path.join(dir, 'zb'));
  fs.writeFileSync(path.join(dir, 'zb', 'settings.json'), JSON.stringify({ schedule: '01:30', keep_days: 14, remote_dir: '', key_fingerprint: 'abcd1234abcd1234' }));
  assert.equal((await call('PUT', '/settings', 'operator', good)).s, 403);
  const bad = await call('PUT', '/settings', 'admin', { schedule: '25:00', remote_dir: 'relative/x', sftp_target: 'a@b:/x"; rm -rf /', extra_paths: '/x/../etc', keep_days: 0 });
  assert.equal(bad.s, 400); assert.match(bad.e, /HH:MM/); assert.match(bad.e, /share folder/); assert.match(bad.e, /SFTP target/); assert.match(bad.e, /extra folders/); assert.match(bad.e, /days to keep/);
  const low = await call('PUT', '/settings', 'admin', { keep_days: 1, keep_min: 1, remote_dir: '/var/lib/sentra-siem/x' });
  assert.equal(low.s, 400, 'retention floors and backup roots'); assert.match(low.e, /days to keep must be 7-365/); assert.match(low.e, /keep at least must be 3-100/); assert.match(low.e, /under \/mnt/);
  assert.equal((await call('PUT', '/settings', 'admin', {})).s, 400, 'nothing to change');
  const ok = await call('PUT', '/settings', 'admin', good);
  assert.equal(ok.s, 200); assert.equal(ok.b.queued, true);
  const q = JSON.parse(fs.readFileSync(path.join(dir, 'q', 'backup-settings.json'), 'utf8'));
  assert.equal(q.by, 'syed'); assert.deepEqual(q.settings, Object.assign({}, good, { extra_paths: '/srv/portal /etc/pki' }));
  assert.equal((await call('PUT', '/settings', 'admin', good)).s, 409, 'one change at a time');
  const g = await call('GET', '', 'viewer'); assert.equal(g.b.settings_pending, true); assert.equal(g.b.settings.key_fingerprint, 'abcd1234abcd1234');
  assert.ok(audits.some((a) => a[0] === 'platform.backup.settings'));
});

test('data optimisation dry run: operator and above only (it runs the caller\'s regexes over stored events)', async () => {
  const R = {}; let ran = 0;
  require('../engine/dataopt/api').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: {}, log: { error() {} }, dataopt: { simulate: async () => { ran++; return { scanned: 0 }; } } });
  const call = async (p, role) => { const o = {}; await R['POST ' + p]({ role, user: 'u', params: { id: 'x' }, body: { pipeline: { rules: [] } }, query: {}, need: (r) => { const rank = { viewer: 0, analyst: 1, operator: 2, admin: 3 }; if (rank[role] < rank[r]) { o.s = 403; return false; } return true; }, ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }); return o; };
  for (const p of ['/api/soc/dataopt/simulate', '/api/soc/dataopt/pipelines/:id/simulate']) {
    assert.equal((await call(p, 'viewer')).s, 403, p);
    assert.equal((await call(p, 'operator')).s, 200, p);
  }
  assert.equal(ran, 2);
});
