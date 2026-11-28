// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Exchange Online runner (engine/exo.js) and the leaver mailbox step (engine/offboarding.js): settings admin-only and
// validated, certificate password sealed and never returned; the runner starts PowerShell with no secret on its command line
// and hands everything on stdin (checked with a fake pwsh); only the fixed operations, addresses validated; a missing pwsh
// is named. The mailbox step: read after the disable, proposed with the manager as delegate and an automatic reply, warnings
// for hold / archive, approval by an administrator who did not raise the request, converted + read back, Full Access and the
// reply set, partial failure retried, an on-premises mailbox recorded by hand, rejected = kept; the licence reclaim accepts
// "converted" only when the platform verified it. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createExo } = require('../engine/exo');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' };
const APPID = '66666666-7777-8888-9999-000000000000', PFX_PW = 'Synthetic-Pfx-Pass-7';
const LEAVER = { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'resignation' };

test('the runner: settings sealed, no secret on the command line, stdin protocol, fixed operations, pwsh missing named', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'exo-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const fake = path.join(tmp, 'pwsh'), seen = path.join(tmp, 'stdin.json'), argv = path.join(tmp, 'argv.txt');
  fs.writeFileSync(fake, '#!/bin/sh\necho "$@" > ' + argv + '\ncat > ' + seen + '\necho \'{"ok":true,"data":{"organization":"Contoso Synthetic"}}\'\n'); fs.chmodSync(fake, 0o755);
  const X = createExo(e.app, {});
  const who = ADM;
  assert.throws(() => X.configure({ organization: 'contoso' }, who), /organization must be/);
  assert.throws(() => X.configure({ cert_path: 'C:\\certs\\app.pfx' }, who), /cert_path must be/);
  assert.throws(() => X.configure({ pwsh: 'pwsh; rm -rf /' }, who), /pwsh must be/);
  assert.throws(() => X.configure({ enabled: true, organization: 'contoso.onmicrosoft.com' }, who), /enabled needs/);
  const v = X.configure({ enabled: true, organization: 'contoso.onmicrosoft.com', app_id: APPID, cert_path: '/etc/sentra/exo-app.pfx', cert_password: PFX_PW, pwsh: fake }, who);
  assert.equal(v.cert_password_set, true); assert.ok(!JSON.stringify(v).includes(PFX_PW)); assert.ok(!JSON.stringify(e.app.store.collection('exo_cfg').all()).includes(PFX_PW), 'sealed');
  const r = await X.test(who); assert.equal(r.ok, true); assert.equal(r.organization, 'Contoso Synthetic');
  const args = fs.readFileSync(argv, 'utf8'), input = JSON.parse(fs.readFileSync(seen, 'utf8'));
  assert.ok(!args.includes(PFX_PW) && /-NonInteractive/.test(args) && /exo-run\.ps1/.test(args), 'no secret on the command line');
  assert.equal(input.cert_password, PFX_PW, 'the password travels on stdin'); assert.equal(input.op, 'test'); assert.equal(input.org, 'contoso.onmicrosoft.com');
  assert.deepEqual(await X.run('remove-mailbox', { identity: 'a@b.com' }), { ok: false, error: 'operation not allowed' });
  assert.match((await X.run('convert-shared', { identity: 'not an address' })).error, /identity must be a mailbox address/);
  assert.match((await X.run('add-fullaccess', { identity: 'a@corp.syn', user: '; whoami' })).error, /user must be a mailbox address/);
  X.configure({ pwsh: path.join(tmp, 'no-such-pwsh') }, who);
  assert.match((await X.test(who)).error, /PowerShell 7 \(pwsh\) is not installed/);
  assert.ok(!JSON.stringify(e.app.store.auditTail(100)).includes(PFX_PW));
});

async function setup(t, stub) {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const calls = [];
  const exoRun = async (op, p) => { calls.push(op + ':' + (p.user || p.identity || '')); return stub(op, p); };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', exoRun });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  assert.equal((await post('/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM)).status, 200);
  const r = await post('/offboarding/exo', { enabled: true, organization: 'corp.onmicrosoft.com', app_id: APPID, cert_path: '/etc/sentra/exo-app.pfx', cert_password: PFX_PW }, ADM);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  async function leaver(extra = {}) {
    let x = await post('/offboarding', Object.assign({}, LEAVER, extra), HR); const id = x.json.id;
    await post('/offboarding/' + id + '/confirm', { decision: 'confirm' }, MGR);
    await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM);
    x = await post('/offboarding/' + id + '/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK); assert.equal(x.status, 200, JSON.stringify(x.json));
    return { id, v: x.json };
  }
  return { e, clock, calls, post, get, leaver };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);

test('mailbox: proposed after the disable, approved by a second person, converted and read back, access and reply set', async (t) => {
  const state = { type: 'UserMailbox', perms: [], reply: null };
  const { e, calls, post, get, leaver } = await setup(t, (op, p) => {
    if (op === 'get-mailbox') return { ok: true, data: { found: true, type: state.type, litigation_hold: false, archive: 'None' } };
    if (op === 'convert-shared') { state.type = 'SharedMailbox'; return { ok: true, data: { type: state.type } }; }
    if (op === 'add-fullaccess') { state.perms.push(p.user); return { ok: true, data: { granted: true } }; }
    if (op === 'set-autoreply') { state.reply = p.message; return { ok: true, data: { autoreply: 'enabled' } }; }
    return { ok: false, error: 'unexpected' };
  });
  assert.equal((await get('/offboarding/exo', { user: 'vera.syn', role: 'viewer' })).status, 403);
  assert.equal((await post('/offboarding/exo', { enabled: false }, DESK)).status, 403, 'settings are admin only');
  const { id, v } = await leaver();
  assert.equal(v.mailbox.status, 'proposed'); assert.deepEqual(v.mailbox.delegates, ['faisal.syn@corp.syn'], 'the manager by default');
  assert.match(v.mailbox.auto_reply, /Khalid Al-Harbi no longer works.*faisal\.syn@corp\.syn/);
  assert.ok(v.steps.some((s) => s.key === 'mailbox' && !s.done));
  const D = (b, who) => post('/offboarding/' + id + '/mailbox/decide', b, who);
  assert.equal((await D({ decision: 'approve' }, DESK)).status, 403, 'administrators only');
  assert.equal((await D({ decision: 'approve' }, { user: 'hana.syn', role: 'admin' })).status, 403, 'not the person who raised the request');
  let r = await D({ decision: 'approve', delegates: ['khalid.harbi@corp.syn'] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /own delegate/);
  r = await D({ decision: 'approve', delegates: ['team lead'] }, ADM); assert.match(r.json.error, /^delegates: team lead is not a mailbox address/);
  r = await D({ decision: 'approve', delegates: ['faisal.syn@corp.syn', 'claims-team@corp.syn'] }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.mailbox.status, 'converted'); assert.equal(state.type, 'SharedMailbox');
  assert.deepEqual(state.perms, ['faisal.syn@corp.syn', 'claims-team@corp.syn']); assert.match(state.reply, /no longer works/);
  assert.deepEqual(calls.filter((c) => !c.startsWith('get-forwarding')), ['get-mailbox:khalid.harbi@corp.syn', 'convert-shared:khalid.harbi@corp.syn', 'add-fullaccess:faisal.syn@corp.syn', 'add-fullaccess:claims-team@corp.syn', 'set-autoreply:khalid.harbi@corp.syn']);
  assert.ok(r.json.steps.find((s) => s.key === 'mailbox').done);
  for (const a of ['offboarding.exo.settings', 'offboarding.mailbox.proposed', 'offboarding.mailbox.approved', 'offboarding.mailbox.converted']) assert.ok(auditOf(e, a).length >= 1, a);
});

test('mailbox: partial failure retried; hold warned; on-premises recorded by hand; kept; reclaim trusts only a verified conversion', async (t) => {
  let failAccess = true;
  const { e, clock, post, get, leaver } = await setup(t, (op, p) => {
    if (op === 'get-mailbox') {
      if (p.identity.startsWith('onprem')) return { ok: true, data: { found: false, recipient_type: 'MailUser' } };
      return { ok: true, data: { found: true, type: 'UserMailbox', litigation_hold: p.identity.startsWith('held'), archive: 'None' } };
    }
    if (op === 'convert-shared') return { ok: true, data: { type: 'SharedMailbox' } };
    if (op === 'add-fullaccess') return failAccess ? { ok: false, error: 'The operation could not be performed because object faisal could not be found' } : { ok: true, data: { granted: true } };
    if (op === 'set-autoreply') return { ok: true, data: {} };
    return { ok: false, error: 'x' };
  });
  const a = await leaver();
  let r = await post('/offboarding/' + a.id + '/mailbox/decide', { decision: 'approve', no_auto_reply: true }, ADM);
  assert.equal(r.json.mailbox.status, 'approved'); assert.match(r.json.mailbox.error, /partly done - access:faisal\.syn@corp\.syn/);
  assert.equal((await get('/offboarding')).json.counts.mailbox_failed, 1);
  failAccess = false; clock.t += 3601000; await e.app.addons.offboarding.runDue(null);
  r = await get('/offboarding/' + a.id); assert.equal(r.json.mailbox.status, 'converted', 'retried: the conversion is not repeated, the access is added');
  assert.equal(r.json.mailbox.steps.filter((s) => s.step === 'convert').length, 1);
  const h = await leaver({ username: 'held.user', employee_id: 'E-3' });
  assert.match(h.v.mailbox.warnings.join(' '), /litigation hold.*keep one/);
  const o = await leaver({ username: 'onprem.user', employee_id: 'E-4' });
  assert.equal(o.v.mailbox.status, 'on_premises');
  r = await post('/offboarding/' + o.id + '/mailbox/manual', { reference: 'Set-RemoteMailbox -Type Shared by the Exchange admin, CHG-9100' }, DESK); assert.equal(r.json.mailbox.status, 'converted_manually');
  const k = await leaver({ username: 'kept.user', employee_id: 'E-5' });
  assert.equal((await post('/offboarding/' + k.id + '/mailbox/decide', { decision: 'reject' }, ADM)).status, 400);
  r = await post('/offboarding/' + k.id + '/mailbox/decide', { decision: 'reject', note: 'mailbox exported to PST for legal, then deleted with the account' }, ADM); assert.equal(r.json.mailbox.status, 'kept');
  // licence reclaim: "converted" only when verified
  const TENANT = '11111111-2222-3333-4444-555555555555';
  await post('/onboarding/m365', { tenant_id: TENANT, client_id: APPID, client_secret: 'Synthetic-Graph-Secret-1', reclaim_enabled: true }, ADM);
  const L = e.app.addons.onboarding.lic;
  const orig = L.readUser; L.readUser = async () => ({ found: true, entra_id: 'id-x', licences: [{ sku_id: '05e9a617-0261-4cee-bb44-138d3ef5d965', name: 'E3' }] }); t.after(() => { L.readUser = orig; });
  const p = await leaver({ username: 'pending.user', employee_id: 'E-6' });
  assert.equal(p.v.mailbox.status, 'proposed'); assert.equal(p.v.reclaim.status, 'proposed');
  r = await post('/offboarding/' + p.id + '/reclaim/decide', { decision: 'approve', mailbox: 'converted_to_shared' }, ADM); assert.equal(r.status, 409); assert.match(r.json.error, /mailbox has not been converted yet/);
  r = await post('/offboarding/' + a.id + '/reclaim/refresh', {}, DESK); assert.equal(r.json.reclaim.status, 'proposed');
  r = await post('/offboarding/' + a.id + '/reclaim/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.reclaim.mailbox, 'converted_to_shared', 'filled from the verified conversion');
});

// bug fix (HTTP 502 on every page): offboarding.js required exo.js unguarded, so a server where the update had not copied
// exo.js could not start sentra-itam at all. Now the mailbox step turns off and says so; the rest of the platform answers.
test('exo.js missing on the server: sentra-itam still starts, the mailbox step is off and says why', async () => {
  const { spawnSync } = require('child_process');
  const script = `
    const Module = require('module'), orig = Module._resolveFilename;
    Module._resolveFilename = function (req, parent, ...rest) {
      if (req === './exo' && parent && /offboarding\\.js$/.test(parent.filename)) { const e = new Error("Cannot find module './exo'\\nRequire stack:\\n- " + parent.filename); e.code = 'MODULE_NOT_FOUND'; throw e; }
      return orig.call(this, req, parent, ...rest);
    };
    (async () => {
      const e = await require(${JSON.stringify(path.join(__dirname, 'helpers'))}).startApp({ noAi: true });
      require(${JSON.stringify(path.join(__dirname, '..', 'engine', 'duty'))}).registerDuty(e.app.srv, e.app, { noTimer: true });
      const A = { user: 'syed', role: 'admin' };
      const out = {};
      for (const [m, p] of [['GET', '/duty/kpis'], ['GET', '/offboarding'], ['GET', '/offboarding/exo'], ['POST', '/offboarding/exo'], ['POST', '/offboarding/exo/test']]) { const r = await e.req(m, p, Object.assign({ body: m === 'POST' ? {} : undefined }, A)); out[m + ' ' + p] = { status: r.status, json: r.json }; }
      const v = await e.req('GET', '/offboarding/exo', { user: 'viewer.one', role: 'viewer' }); out.viewer = v.status;
      console.log(JSON.stringify(out)); e.close(); process.exit(0);
    })().catch((x) => { console.log('ERR ' + x.stack); process.exit(1); });`;
  const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: 60000 });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const o = JSON.parse(r.stdout.trim().split('\n').pop());
  assert.equal(o['GET /duty/kpis'].status, 200);
  assert.equal(o['GET /offboarding'].status, 200);
  assert.equal(o['GET /offboarding'].json.mailbox.automatic, false);
  assert.equal(o['GET /offboarding/exo'].status, 200);
  assert.equal(o['GET /offboarding/exo'].json.installed, false);
  assert.match(o['GET /offboarding/exo'].json.note, /not installed.*re-run the update/);
  assert.equal(o['POST /offboarding/exo'].status, 409);
  assert.match(o['POST /offboarding/exo'].json.error, /re-run the update/);
  assert.equal(o['POST /offboarding/exo/test'].status, 409);
  assert.equal(o.viewer, 403);
});

test('the program given the certificate password must be one only root can change (a planted binary never gets it)', () => {
  const { trustedProgram } = require('../engine/exo');
  const st = (o) => () => Object.assign({ isFile: () => true, uid: 0, mode: 0o100755 }, o);
  assert.equal(trustedProgram('pwsh'), null, '"pwsh" from the service PATH');
  assert.equal(trustedProgram('/usr/bin/pwsh', st({})), null, 'root-owned, 755');
  assert.match(trustedProgram('/tmp/pwsh', st({ uid: 1001 })), /owned by root/);
  assert.match(trustedProgram('/opt/x/pwsh', st({ mode: 0o100777 })), /writable by group or others/);
  assert.match(trustedProgram('/opt/x/pwsh', st({ mode: 0o100644 })), /not executable/);
  assert.match(trustedProgram('/nope/pwsh', () => { throw new Error('ENOENT'); }), /not installed/);
});
