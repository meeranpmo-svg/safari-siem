// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Leaver OneDrive hand-over (engine/offboarding.js, SharePoint Online through engine/exo.js -> exo/spo-run.ps1): the SharePoint
// runner gets everything on stdin (checked with a fake pwsh), only OneDrive sites and addresses; the disable approval carries the
// decision (manager by default, for an approved number of days); at the disable the manager becomes a site collection
// administrator, read back; at the end of the period exactly the people the platform added are removed (an administrator from
// before keeps it); extend (not the requester, not a person who has the access, at most 365 days), end early, decide after (four
// eyes), decline, no OneDrive, failures retried; validation, roles and audit. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createExo } = require('../engine/exo');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, REQ_ADMIN = { user: 'hana.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const APPID = '66666666-7777-8888-9999-000000000000', PFX_PW = 'Synthetic-Pfx-Pass-7';
const LEAVER = { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'resignation' };
const DAY = 86400000;
const siteOf = (upn) => 'https://corp-my.sharepoint.com/personal/' + upn.replace(/[@.]/g, '_');

test('the SharePoint runner: own script, admin address and password on stdin only, OneDrive sites only; settings validated', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'spo-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const fake = path.join(tmp, 'pwsh'), seen = path.join(tmp, 'stdin.json'), argv = path.join(tmp, 'argv.txt');
  fs.writeFileSync(fake, '#!/bin/sh\necho "$@" > ' + argv + '\ncat > ' + seen + '\necho \'{"ok":true,"data":{"found":false}}\'\n'); fs.chmodSync(fake, 0o755);
  const X = createExo(e.app, {});
  X.configure({ enabled: true, organization: 'corp.onmicrosoft.com', app_id: APPID, cert_path: '/etc/sentra/exo-app.pfx', cert_password: PFX_PW, pwsh: fake }, ADM);
  assert.match((await X.run('get-onedrive', { identity: 'a@corp.syn' })).error, /SharePoint is not set up/);
  assert.throws(() => X.configure({ spo_admin_url: 'https://evil.example.com' }, ADM), /spo_admin_url must be/);
  assert.throws(() => X.configure({ onedrive_days: 3 }, ADM), /onedrive_days must be at least 7/);
  assert.throws(() => X.configure({ onedrive_days: 7.5 }, ADM), /whole number/);
  const v = X.configure({ spo_admin_url: 'https://corp-admin.sharepoint.com/', onedrive_days: 45 }, ADM);
  assert.equal(v.spo_admin_url, 'https://corp-admin.sharepoint.com'); assert.equal(v.onedrive_days, 45); assert.equal(v.sharepoint_ready, true);
  assert.deepEqual(await X.run('get-onedrive', { identity: 'a@corp.syn' }), { ok: true, data: { found: false } });
  const args = fs.readFileSync(argv, 'utf8'), input = JSON.parse(fs.readFileSync(seen, 'utf8'));
  assert.ok(/spo-run\.ps1/.test(args) && !args.includes(PFX_PW), 'its own script, no secret on the command line');
  assert.equal(input.admin_url, 'https://corp-admin.sharepoint.com'); assert.equal(input.cert_password, PFX_PW); assert.equal(input.op, 'get-onedrive');
  assert.match((await X.run('add-site-admin', { site: 'https://corp.sharepoint.com/sites/finance', user: 'x@corp.syn' })).error, /OneDrive address/, 'a team site is refused');
  assert.match((await X.run('add-site-admin', { site: siteOf('k@corp.syn'), user: '; whoami' })).error, /user address/);
  assert.deepEqual(await X.run('delete-site', { site: siteOf('k@corp.syn') }), { ok: false, error: 'operation not allowed' });
  const a = e.app.store.auditTail(50).find((x) => x.action === 'offboarding.exo.settings' && x.detail.spo_admin_url);
  assert.equal(a.detail.spo_admin_url, 'https://corp-admin.sharepoint.com'); assert.ok(!JSON.stringify(e.app.store.auditTail(100)).includes(PFX_PW));
});

async function setup(t, o = {}) {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const calls = [], sites = {};
  let failAdd = o.failAdd || 0, failRemove = o.failRemove || 0;
  const exoRun = async (op, p) => {
    calls.push(op + ':' + (p.user || p.identity || ''));
    if (op === 'get-mailbox') return { ok: true, data: { found: false } };
    if (op === 'get-forwarding') return { ok: true, data: { found: false } };
    if (op === 'get-onedrive') {
      if (p.identity.startsWith('nodrive')) return { ok: true, data: { found: false } };
      const url = siteOf(p.identity); sites[url] = sites[url] || new Set([p.identity, ...(p.identity.startsWith('shared') ? ['faisal.syn@corp.syn'] : [])]);
      return { ok: true, data: { found: true, url, storage_mb: 2048, last_modified: '2026-10-20T10:00:00Z', lock: 'Unlock', owner: p.identity, admins: [...sites[url]] } };
    }
    if (op === 'add-site-admin') { if (failAdd > 0) { failAdd--; return { ok: false, error: 'Access denied - the app is missing Sites.FullControl.All' }; } sites[p.site].add(p.user); return { ok: true, data: { granted: true } }; }
    if (op === 'remove-site-admin') { if (failRemove > 0) { failRemove--; return { ok: false, error: 'The server is busy' }; } sites[p.site].delete(p.user); return { ok: true, data: { removed: true } }; }
    return { ok: false, error: 'unexpected ' + op };
  };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', exoRun });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  assert.equal((await post('/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM)).status, 200);
  const s = await post('/offboarding/exo', { enabled: true, organization: 'corp.onmicrosoft.com', app_id: APPID, cert_path: '/etc/sentra/exo-app.pfx', cert_password: PFX_PW, spo_admin_url: 'https://corp-admin.sharepoint.com' }, ADM);
  assert.equal(s.status, 200, JSON.stringify(s.json));
  async function leaver(extra = {}, approve = { decision: 'approve' }) {
    let x = await post('/offboarding', Object.assign({}, LEAVER, extra), HR); assert.equal(x.status, 200, JSON.stringify(x.json)); const id = x.json.id;
    await post('/offboarding/' + id + '/confirm', { decision: 'confirm' }, MGR);
    x = await post('/offboarding/' + id + '/approve', approve, ADM); assert.equal(x.status, 200, JSON.stringify(x.json));
    x = await post('/offboarding/' + id + '/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK); assert.equal(x.status, 200, JSON.stringify(x.json));
    return { id, v: x.json };
  }
  const tick = () => e.app.addons.offboarding.runDue(null);
  return { e, clock, calls, sites, post, get, leaver, tick };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);

test('default: the manager gets the OneDrive at the disable, read back; at the end of the period exactly that is taken back', async (t) => {
  const { e, clock, calls, sites, get, leaver, tick } = await setup(t);
  const { id, v } = await leaver();
  const o = v.onedrive, url = siteOf('khalid.harbi@corp.syn');
  assert.equal(o.status, 'granted', JSON.stringify(o)); assert.deepEqual(o.delegates, ['faisal.syn@corp.syn']); assert.deepEqual(o.added, ['faisal.syn@corp.syn']);
  assert.equal(o.url, url); assert.equal(o.storage_mb, 2048); assert.equal(o.decided_by, 'syed'); assert.equal(o.decided_with, 'disable approval');
  assert.equal(Date.parse(o.access_until) - Date.parse(o.granted_at), 60 * DAY, 'the default period');
  assert.ok(sites[url].has('faisal.syn@corp.syn') && sites[url].has('khalid.harbi@corp.syn'), 'added; the owner untouched');
  assert.ok(v.steps.find((s) => s.key === 'onedrive').done);
  const L = (await get('/offboarding')).json; assert.equal(L.counts.onedrive_active, 1); assert.equal(L.onedrive.automatic, true); assert.equal(L.onedrive.days, 60);
  assert.equal(auditOf(e, 'offboarding.disable.approve')[0].detail.onedrive, 'manager');
  const g = auditOf(e, 'offboarding.onedrive.granted')[0]; assert.equal(g.by, 'system:sharepoint-online'); assert.equal(g.detail.approved_by, 'syed'); assert.equal(g.detail.url, url);
  clock.t += 59 * DAY; await tick(); assert.ok(sites[url].has('faisal.syn@corp.syn'), 'still within the period');
  assert.equal((await get('/offboarding')).json.counts.onedrive_ending, 1, 'ending within 7 days');
  clock.t += 2 * DAY; await tick();
  const r = (await get('/offboarding/' + id)).json.onedrive;
  assert.equal(r.status, 'ended'); assert.deepEqual(r.removed, ['faisal.syn@corp.syn']); assert.ok(!sites[url].has('faisal.syn@corp.syn')); assert.ok(sites[url].has('khalid.harbi@corp.syn'), 'never the owner');
  assert.deepEqual(calls.filter((c) => /site-admin/.test(c)), ['add-site-admin:faisal.syn@corp.syn', 'remove-site-admin:faisal.syn@corp.syn']);
  assert.equal(auditOf(e, 'offboarding.onedrive.ended')[0].detail.reason, 'the approved period ended');
  // a manager who was already an administrator keeps it
  const s2 = await leaver({ username: 'shared.user', employee_id: 'E-2', last_day: new Date(clock.t).toISOString().slice(0, 10) });
  assert.equal(s2.v.onedrive.status, 'granted'); assert.deepEqual(s2.v.onedrive.added, []); assert.deepEqual(s2.v.onedrive.already, ['faisal.syn@corp.syn']);
  clock.t += 61 * DAY; await tick();
  assert.equal((await get('/offboarding/' + s2.id)).json.onedrive.status, 'ended'); assert.ok(sites[siteOf('shared.user@corp.syn')].has('faisal.syn@corp.syn'), 'what they had before stays');
});

test('extend: not the requester, not a person who has the access, at most 365 days, with a reason; end early by an operator', async (t) => {
  const { e, sites, post, leaver } = await setup(t);
  const { id, v } = await leaver({}, { decision: 'approve', onedrive: 'manager', onedrive_days: 14 });
  assert.equal(Date.parse(v.onedrive.access_until) - Date.parse(v.onedrive.granted_at), 14 * DAY);
  const X = (b, who) => post('/offboarding/' + id + '/onedrive/extend', b, who);
  assert.equal((await X({ days: 30, reason: 'audit work continues' }, DESK)).status, 403, 'administrators only');
  let r = await X({ days: 30, reason: 'audit work continues' }, REQ_ADMIN); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await X({ days: 30, reason: 'I need more time' }, { user: 'faisal.syn', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /has this access/);
  r = await X({ days: 30 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^reason is required/);
  r = await X({ days: 1.5, reason: 'audit work continues' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /days must be a whole number/);
  r = await X({ days: 360, reason: 'audit work continues' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /at most 365 days/);
  r = await X({ days: 30, reason: 'the claims audit runs to December' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(Date.parse(r.json.onedrive.access_until) - Date.parse(r.json.onedrive.granted_at), 44 * DAY); assert.equal(r.json.onedrive.extensions[0].by, 'syed');
  assert.equal(auditOf(e, 'offboarding.onedrive.extended')[0].detail.reason, 'the claims audit runs to December');
  assert.equal((await post('/offboarding/' + id + '/onedrive/end', { reason: 'done' }, VIEW)).status, 403);
  assert.equal((await post('/offboarding/' + id + '/onedrive/end', {}, MGR)).status, 400);
  r = await post('/offboarding/' + id + '/onedrive/end', { reason: 'the manager copied what was needed' }, MGR); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.onedrive.status, 'ended'); assert.equal(r.json.onedrive.ended_by, 'faisal.syn'); assert.ok(!sites[siteOf('khalid.harbi@corp.syn')].has('faisal.syn@corp.syn'));
  assert.equal((await X({ days: 30, reason: 'too late now' }, ADM)).status, 409);
  r = await post('/offboarding/' + id + '/approve', { decision: 'approve', onedrive: 'everyone' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^onedrive must be one of/);
});

test('decide after: four eyes, named people validated, approve gives access; decline at approval; no OneDrive', async (t) => {
  const { e, sites, post, leaver } = await setup(t);
  const { id, v } = await leaver({}, { decision: 'approve', onedrive: 'ask' });
  assert.equal(v.onedrive.status, 'proposed'); assert.deepEqual(v.onedrive.delegates, ['faisal.syn@corp.syn'], 'the manager suggested');
  const D = (b, who) => post('/offboarding/' + id + '/onedrive/decide', b, who);
  assert.equal((await D({ decision: 'approve' }, DESK)).status, 403);
  let r = await D({ decision: 'approve' }, REQ_ADMIN); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await D({ decision: 'approve' }, { user: 'khalid.harbi', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /leaver cannot/);
  r = await D({ decision: 'approve' }, { user: 'ai:assistant', role: 'admin' }); assert.equal(r.status, 403);
  r = await D({ decision: 'approve', delegates: ['khalid.harbi@corp.syn'] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /own OneDrive/);
  r = await D({ decision: 'approve', delegates: ['the team'] }, ADM); assert.match(r.json.error, /^delegates: the team is not a user address/);
  r = await D({ decision: 'approve', days: 400 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^days must be at most 365/);
  r = await D({ decision: 'reject' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await D({ decision: 'approve', delegates: ['faisal.syn@corp.syn', 'claims.lead@corp.syn'], days: 30 }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.onedrive.status, 'granted'); assert.deepEqual(r.json.onedrive.added, ['faisal.syn@corp.syn', 'claims.lead@corp.syn']);
  assert.ok(sites[siteOf('khalid.harbi@corp.syn')].has('claims.lead@corp.syn'));
  assert.equal(auditOf(e, 'offboarding.onedrive.approved')[0].detail.days, 30);
  const n = await leaver({ username: 'none.user', employee_id: 'E-3' }, { decision: 'approve', onedrive: 'none' });
  assert.equal(n.v.onedrive.status, 'declined'); assert.equal(n.v.onedrive.decided_with, 'disable approval'); assert.ok(sites[siteOf('none.user@corp.syn')].size === 1);
  const z = await leaver({ username: 'nodrive.user', employee_id: 'E-4' });
  assert.equal(z.v.onedrive.status, 'not_needed'); assert.ok(z.v.steps.find((s) => s.key === 'onedrive').done);
});

test('failures: a refused grant is retried hourly without repeating what worked; a failed take-back is retried; record by hand', async (t) => {
  const { e, clock, calls, post, get, leaver, tick } = await setup(t, { failAdd: 1, failRemove: 1 });
  const { id, v } = await leaver();
  assert.equal(v.onedrive.status, 'approved'); assert.match(v.onedrive.error, /Sites\.FullControl\.All/);
  assert.equal((await get('/offboarding')).json.counts.onedrive_failed, 1); assert.equal(auditOf(e, 'offboarding.onedrive.failed').length, 1);
  clock.t += 3601000; await tick();
  let o = (await get('/offboarding/' + id)).json.onedrive; assert.equal(o.status, 'granted');
  clock.t += 61 * DAY; await tick();
  o = (await get('/offboarding/' + id)).json.onedrive; assert.equal(o.status, 'granted'); assert.match(o.end_error, /server is busy/);
  assert.equal((await get('/offboarding')).json.counts.onedrive_failed, 1, 'a failed take-back counts');
  assert.equal((await post('/offboarding/' + id + '/onedrive/retry', {}, DESK)).status, 403);
  const r = await post('/offboarding/' + id + '/onedrive/retry', {}, ADM); assert.equal(r.status, 200); assert.equal(r.json.onedrive.status, 'ended');
  assert.equal(calls.filter((c) => c === 'remove-site-admin:faisal.syn@corp.syn').length, 2);
  // by hand
  const m = await leaver({ username: 'hand.user', employee_id: 'E-5', last_day: new Date(clock.t).toISOString().slice(0, 10) }, { decision: 'approve', onedrive: 'ask' });
  assert.equal((await post('/offboarding/' + m.id + '/onedrive/manual', { reference: 'given in the SharePoint admin centre' }, DESK)).status, 409, 'decided first');
});
