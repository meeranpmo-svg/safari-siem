// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Backup coverage: NetBackup (Administration API 14.0), Veeam and Cohesity read-only clients, matching to the inventory,
// verdicts (protected / stale / failed / none / exempt), unmatched objects, sealed credentials, read-only guard.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const S = require('../engine/backup-sources');
const { createBackup } = require('../engine/backup');
const { createSealer } = require('../engine/discovery/vault');

const NOW = Date.parse('2026-10-12T12:00:00Z'), H = 3600000;
const at = (h) => new Date(NOW - h * H).toISOString();
function fakeStore(init) {
  const cols = {};
  return { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map((init[n] || []).map((o) => [o.id, o])); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, remove: (id) => m.delete(id),
    patch: (id, fn) => { const c = JSON.parse(JSON.stringify(m.get(id))); const r = fn(c); m.set(id, r && typeof r === 'object' ? r : c); return m.get(id); } }; })()) };
}
function nbFake(calls, { status = 200 } = {}) {
  return async (url, o) => {
    calls.push([o.method, url, o.headers.Authorization, o.headers.Accept]);
    if (status !== 200) return { status, json: {} };
    const u = new URL(url);
    if (u.pathname === '/netbackup/admin/jobs') {
      const off = Number(u.searchParams.get('page[offset]'));
      if (off === 0) return { status: 200, json: { data: [
        { id: '1', attributes: { jobId: 1, jobType: 'BACKUP', policyName: 'WIN-DAILY', clientName: ('DC-HQA.' + 'corp-hq.com'), status: 0, state: 'DONE', startTime: at(10), endTime: at(9), kilobytesTransferred: 1024 } },
        { id: '2', attributes: { jobId: 2, jobType: 'BACKUP', policyName: 'ORA-RMAN', clientName: 'oradb01', status: 13, state: 'DONE', startTime: at(5), endTime: at(5) } }], meta: { pagination: { next: 2 } } } };
      return { status: 200, json: { data: [{ id: '3', attributes: { jobId: 3, jobType: 'BACKUP', policyName: 'ORA-RMAN', clientName: 'oradb01', status: 0, state: 'DONE', startTime: at(60), endTime: at(59) } }], meta: { pagination: { offset: 2, last: 2 } } } };
    }
    if (u.pathname === '/netbackup/catalog/images') return { status: 200, json: { data: [{ attributes: { clientName: 'legacy-ftp', backupTime: at(3), policyName: 'MISC', kilobytes: 2048 } }], meta: { pagination: {} } } };
    return { status: 404, json: {} };
  };
}

test('NetBackup: API key, media type version 14.0, OData filter, paging, job status 0/1/13, catalog images', async () => {
  const calls = [];
  const r = await S.netbackup({ target: { base_url: 'https://nbu-primary.corp.local' }, secret: { api_key: 'A1b2-key' } }, { request: nbFake(calls), now: NOW });
  assert.equal(r.ok, true, r.error); assert.equal(r.api_version, '14.0');
  assert.ok(calls.every((c) => c[0] === 'GET' && c[1].startsWith('https://nbu-primary.corp.local:1556/netbackup/') && c[2] === 'A1b2-key' && c[3] === 'application/vnd.netbackup+json;version=14.0'));
  assert.match(decodeURIComponent(calls[0][1]), /filter=jobType eq 'BACKUP' and startTime ge 2026-10-05T12:00:00.000Z/);
  const o = Object.fromEntries(r.objects.map((x) => [x.name, [x.last_status, x.last_success && x.last_success.slice(0, 13)]]));
  assert.deepEqual(o['oradb01'], ['failed', at(59).slice(0, 13)]);
  assert.deepEqual(o[('DC-HQA.' + 'corp-hq.com')], ['success', at(9).slice(0, 13)]);
  assert.deepEqual(o['legacy-ftp'], ['success', at(3).slice(0, 13)]);
  const bad = await S.netbackup({ target: { base_url: 'https://nbu' }, secret: { api_key: 'k' } }, { request: nbFake([], { status: 406 }) });
  assert.equal(bad.error_class, 'protocol'); assert.match(bad.error, /API version/);
  // a NetBackup that refuses the jobType filter (HTTP 400): the time-only filter is used, BACKUP jobs kept here
  const c2 = [], base = nbFake(c2);
  const picky = async (url, o) => { const f = decodeURIComponent(url); if (/jobType eq/.test(f)) return { status: 400, json: { errorCode: 9993, errorMessage: 'Invalid filter criteria' } }; return base(url, o); };
  const r2 = await S.netbackup({ target: { base_url: 'https://nbu' }, secret: { api_key: 'k' } }, { request: picky, now: NOW });
  assert.equal(r2.ok, true, r2.error); assert.equal(r2.objects.length, 3, 'same result through the fallback');
  // every variant refused: the server's own reason is in the error
  const r3 = await S.netbackup({ target: { base_url: 'https://nbu' }, secret: { api_key: 'k' } }, { request: async () => ({ status: 400, json: { errorMessage: 'Invalid filter criteria', errorDetails: ['startTime'] } }), now: NOW });
  assert.match(r3.error, /answered HTTP 400: Invalid filter criteria - startTime/);
  assert.throws(() => S.guard('netbackup', 'DELETE', '/netbackup/admin/jobs/1'), /read-only/);
  assert.throws(() => S.guard('netbackup', 'POST', '/netbackup/admin/jobs/1/cancel'), /read-only/);
});

test('Veeam: OAuth password grant, x-api-version, sessions + restore points, logout; Cohesity: API key, per-object run status', async () => {
  const calls = [];
  const veeamReq = async (url, o) => {
    calls.push([o.method, url.replace(/^https:\/\/[^/]+/, ''), o.headers]);
    if (url.endsWith('/api/oauth2/token')) { assert.match(o.body, /grant_type=password&username=svc-ro&password=Ve%23am/); return { status: 200, json: { access_token: 'T1' } }; }
    if (url.endsWith('/api/oauth2/logout')) return { status: 200, json: {} };
    if (url.includes('/api/v1/sessions')) return { status: 200, json: { data: [{ id: 's1', name: 'VM-Daily', state: 'Stopped', result: { result: 'Failed', message: 'datastore full' }, creationTime: at(2), endTime: at(1) }], pagination: { total: 1 } } };
    if (url.includes('/api/v1/restorePoints')) return { status: 200, json: { data: [{ name: 'WIN-APP1', platformName: 'VMware', creationTime: at(30) }, { name: 'WIN-APP1', platformName: 'VMware', creationTime: at(6) }], pagination: { total: 2 } } };
    return { status: 404, json: {} };
  };
  const v = await S.veeam({ target: { base_url: 'https://vbr01' }, secret: { username: 'svc-ro', password: 'Ve#am' } }, { request: veeamReq, now: NOW });
  assert.equal(v.ok, true, v.error);
  assert.equal(v.objects[0].last_success, at(6)); assert.equal(v.objects[0].kind, 'vm');
  assert.deepEqual(v.failed_jobs, ['VM-Daily']);
  assert.ok(calls.slice(1, 3).every((c) => c[2].Authorization === 'Bearer T1' && c[2]['x-api-version'] === '1.1-rev0'));
  assert.equal(calls[calls.length - 1][1], '/api/oauth2/logout');
  const cReq = async (url, o) => {
    assert.equal(o.headers.apiKey, 'coh-key');
    return { status: 200, json: [{ jobName: 'NAS-Daily', jobId: 7, backupRun: { status: 'kSuccess', jobRunId: 1, stats: { startTimeUsecs: (NOW - 4 * H) * 1000, endTimeUsecs: (NOW - 3 * H) * 1000 }, sourceBackupStatus: [{ source: { name: 'FS01' }, status: 'kSuccess', stats: { endTimeUsecs: (NOW - 3 * H) * 1000 } }, { source: { name: 'ERP-DB' }, status: 'kFailure', stats: { endTimeUsecs: (NOW - 3 * H) * 1000 } }] } }] };
  };
  const c = await S.cohesity({ target: { base_url: 'https://cohesity.corp.local' }, secret: { api_key: 'coh-key' } }, { request: cReq, now: NOW });
  assert.equal(c.ok, true, c.error);
  assert.deepEqual(c.objects.map((x) => [x.name, x.last_status]), [['FS01', 'success'], ['ERP-DB', 'failed']]);
});

test('coverage: verdicts across platforms, matching by short name, unmatched objects, exemptions, sealed credentials', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bk-'));
  const st = fakeStore({ assets: [
    { id: 'a1', name: 'DC-HQA', type: 'server', status: 'in_use' }, { id: 'a2', name: 'oradb01', type: 'vm', status: 'in_use' },
    { id: 'a3', name: 'WIN-APP1', type: 'vm', status: 'in_use' }, { id: 'a4', name: 'WEB-STATELESS', type: 'vm', status: 'in_use' },
    { id: 'a5', name: 'OLD', type: 'server', status: 'retired' }, { id: 'a6', name: 'PC-1', type: 'workstation', status: 'in_use' }, { id: 'a7', name: 'FS01', type: 'server', status: 'in_use' }] });
  const sources = Object.assign({}, S, {
    netbackup: async (c) => { assert.equal(c.secret.api_key, 'A1b2-key'); return S.netbackup(c, { request: nbFake([]), now: NOW }); },
    cohesity: async () => ({ ok: true, objects: [{ name: ('fs01.' + 'corp-hq.com'), last_status: 'success', last_attempt: at(40), last_success: at(40), job: 'NAS' }], jobs: [{ job: 'NAS', status: 'failed', end: at(2) }] }),
  });
  const B = createBackup({ store: st, config: { discovery: { vault_key_file: path.join(dir, 'k') } } }, { sources, now: () => NOW });
  const adm = { user: 'syed', role: 'admin' };
  assert.throws(() => B.save({ kind: 'netbackup', base_url: 'https://nbu', username: 'u', password: 'p' }, adm), /API key/);
  assert.throws(() => B.save({ kind: 'tsm', base_url: 'https://x', api_key: 'k' }, adm), /kind must be/);
  const nb = B.save({ kind: 'netbackup', label: 'NBU primary', base_url: 'https://nbu-primary.corp.local', api_key: 'A1b2-key' }, adm).platform;
  const co = B.save({ kind: 'cohesity', label: 'Cohesity', base_url: 'https://cohesity', api_key: 'coh' }, adm).platform;
  assert.ok(!JSON.stringify(B.view()).includes('A1b2-key'));
  assert.throws(() => B.save({ id: nb.id, base_url: 'https://elsewhere' }, adm), /secret again/);
  // a NetBackup primary saved as Cohesity: the type is corrected on Edit with the new type's secret; /webui is dropped
  const wrong = B.save({ kind: 'cohesity', label: 'NBU Primary', base_url: 'https://asbackup.example/webui', api_key: 'x' }, adm).platform;
  assert.throws(() => B.save({ id: wrong.id, kind: 'netbackup' }, adm), /type changed to .*NetBackup.*API key/);
  const fixed = B.save({ id: wrong.id, kind: 'netbackup', base_url: 'https://asbackup.example/webui', api_key: 'nb-key' }, adm).platform;
  assert.equal(fixed.kind, 'netbackup'); assert.equal(fixed.base_url, 'https://asbackup.example');
  assert.equal(B.save({ id: wrong.id, label: 'NBU Primary' }, adm).platform.kind, 'netbackup', 'an edit without kind keeps the type');
  assert.equal((await B.sync(nb.id, adm)).ok, true); assert.equal((await B.sync(co.id, adm)).ok, true);
  B.setExempt({ asset_id: 'a4', reason: 'stateless web node, rebuilt from template' }, adm);
  assert.throws(() => B.setExempt({ asset_id: 'a4', reason: '' }, adm), /reason/);
  const v = B.view();
  const by = Object.fromEntries(v.assets.map((r) => [r.name, r.status]));
  assert.equal(by['DC-HQA'], 'protected'); assert.equal(by['oradb01'], 'failed'); assert.equal(by['WIN-APP1'], 'none'); assert.equal(by['FS01'], 'stale'); assert.equal(by['WEB-STATELESS'], 'exempt');
  assert.ok(!('OLD' in by) && !('PC-1' in by));
  assert.deepEqual([v.summary.protected, v.summary.failed, v.summary.none, v.summary.stale, v.summary.exempt, v.summary.coverage_pct], [1, 1, 1, 1, 1, 25]);
  assert.deepEqual(v.unmatched.map((u) => u.name), ['legacy-ftp']);
  assert.equal(v.failed_jobs.length, 2);   // NetBackup oradb01 (5 h ago) + Cohesity NAS (2 h ago)
  assert.equal(v.assets[0].status, 'failed');
  const r = await createBackup({ store: st, config: { discovery: { vault_key_file: path.join(dir, 'k') } } }, { sources: Object.assign({}, sources, { cohesity: async () => ({ ok: false, error_class: 'auth', error: 'cohesity: the credentials were rejected (HTTP 401)' }) }), now: () => NOW }).sync(co.id, adm);
  assert.equal(r.ok, false); assert.match(r.error, /^auth:/);
  assert.equal(createSealer({ keyFile: path.join(dir, 'k'), purpose: 'sentra-itam-backup-platforms' }).available(), true);
});

test('coverage: a VM backed up under its UUID (NetBackup Nutanix AHV: "<uuid>_<cluster>") matches by the VM name or the discovery link', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bk-'));
  const U1 = '0579b919-6ecb-48ad-98f3-aab30b8a8132', U2 = '09d93101-d2cd-479e-92f3-2306cfebd2a1', U3 = '0a6cb8c2-bcbf-4830-80bc-f65ce81db541', U4 = '11111111-2222-4333-8444-555555555555';
  const st = fakeStore({
    assets: [{ id: 'a1', name: 'EXCH-HQ01', type: 'vm', status: 'in_use' }, { id: 'a2', name: 'IIRS-APP', type: 'vm', status: 'in_use' }, { id: 'a3', name: 'CRM-WEB', type: 'vm', status: 'in_use' }],
    virt_capacity: [{ id: 'p1', label: 'Nutanix HQ', kind: 'nutanix', vms: [{ id: U1, uuid: U1, name: 'EXCH-HQ01' }, { id: U2, uuid: U2, name: ('iirs-app.' + 'corp-hq.com') }] }],
    disc_devices: [{ id: 'd3', asset_id: 'a3', uids: ['ntnx:' + U3] }],
    backup_objects: [U1, U2, U3, U4].map((u, i) => ({ id: 'bp1:' + u, platform_id: 'bp1', platform_kind: 'netbackup', platform_label: 'NBU Primary', name: u + '_NTX-ASI-CLS-HO-01', job: 'Nutanix_' + i, last_status: 'success', last_success: at(5), last_attempt: at(5) })),
  });
  const B = createBackup({ store: st, config: { discovery: { vault_key_file: path.join(dir, 'k') } } }, { sources: S, now: () => NOW });
  const v = B.view(), stat = Object.fromEntries(v.assets.map((a) => [a.name, a.status]));
  assert.deepEqual(stat, { 'EXCH-HQ01': 'protected', 'IIRS-APP': 'protected', 'CRM-WEB': 'protected' }, 'by VM name (also its short name) and by the discovery link');
  assert.equal(v.unmatched.length, 1); assert.equal(v.unmatched[0].vm_uuid, U4); assert.equal(v.unmatched[0].vm_cluster, 'NTX-ASI-CLS-HO-01'); assert.equal(v.unmatched[0].vm_name, null, 'a UUID no platform knows stays unnamed - never guessed');
  assert.deepEqual(v.vm_names, { by_uuid: 4, resolved: 2 });
  fs.rmSync(dir, { recursive: true, force: true });
});
