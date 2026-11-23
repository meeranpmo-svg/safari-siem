// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Leaver mail forwarding (engine/offboarding.js, Exchange Online through engine/exo.js - stubbed runner): the disable approval
// carries the forwarding decision (remove all by default / only outside the company / decide after); at the disable the
// mailbox forwarding is cleared and forwarding inbox rules are DISABLED (never deleted), each read back, then the whole
// forwarding read again; a forward that comes back within 30 days is removed under the same decision; "decide after" needs an
// administrator who did not raise the request; unknown accepted domains never count as internal; failures are retried; an
// on-premises mailbox is recorded by hand; the read-only check before the disable; validation, roles and audit. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, REQ_ADMIN = { user: 'hana.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const APPID = '66666666-7777-8888-9999-000000000000';
const LEAVER = { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'resignation' };
const DAY = 86400000;

function mailboxes() {
  const mk = () => ({ smtp: 'k.harbi.home@gmail.example', address: '', keep: true, accepted: ['corp.syn'], rules: [
    { id: '1001', name: 'copy to my gmail', enabled: true, targets: ['"Khalid" [SMTP:k.private@gmail.example]'] },
    { id: '1002', name: 'claims to the team', enabled: true, targets: ['"Claims team" [SMTP:claims-team@corp.syn]'] },
    { id: '1003', name: 'old rule', enabled: false, targets: ['someone@yahoo.com'] }] });
  const M = {};
  return { M, get: (id) => (M[id] = M[id] || mk()) };
}

async function setup(t, opts = {}) {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const calls = [], box = mailboxes();
  let failRule = opts.failRule || 0;
  const exoRun = async (op, p) => {
    calls.push(op + ':' + (p.rule || p.identity || ''));
    const id = String(p.identity || ''), m = box.get(id);
    if (op === 'get-mailbox') return { ok: true, data: { found: true, type: 'UserMailbox', litigation_hold: false, archive: 'None' } };
    if (op === 'get-forwarding') {
      if (id.startsWith('onprem')) return { ok: true, data: { found: false, recipient_type: 'MailUser' } };
      if (id.startsWith('nodom')) m.accepted = [];
      if (id.startsWith('clean')) { m.smtp = ''; m.rules = []; }
      return { ok: true, data: { found: true, smtp: m.smtp, address: m.address, keep_copy: m.keep, rules: m.rules.map((r) => Object.assign({}, r)), accepted_domains: m.accepted } };
    }
    if (op === 'clear-forwarding') { m.smtp = ''; m.address = ''; return { ok: true, data: { smtp: '', address: '' } }; }
    if (op === 'disable-inbox-rule') {
      if (failRule > 0) { failRule--; return { ok: false, error: 'The operation couldn\'t be performed because the rule is being updated' }; }
      const r = m.rules.find((x) => x.id === p.rule); if (!r) return { ok: false, error: 'no rule ' + p.rule };
      r.enabled = false; return { ok: true, data: { enabled: false } };
    }
    return { ok: false, error: 'unexpected ' + op };
  };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', exoRun });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  assert.equal((await post('/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM)).status, 200);
  assert.equal((await post('/offboarding/exo', { enabled: true, organization: 'corp.onmicrosoft.com', app_id: APPID, cert_path: '/etc/sentra/exo-app.pfx', cert_password: 'Synthetic-Pfx-Pass-7' }, ADM)).status, 200);
  async function raise(extra = {}) {
    const x = await post('/offboarding', Object.assign({}, LEAVER, extra), HR); assert.equal(x.status, 200, JSON.stringify(x.json));
    await post('/offboarding/' + x.json.id + '/confirm', { decision: 'confirm' }, MGR);
    return x.json.id;
  }
  async function leaver(extra = {}, approve = { decision: 'approve' }) {
    const id = await raise(extra);
    let x = await post('/offboarding/' + id + '/approve', approve, ADM); assert.equal(x.status, 200, JSON.stringify(x.json));
    x = await post('/offboarding/' + id + '/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK); assert.equal(x.status, 200, JSON.stringify(x.json));
    return { id, v: x.json };
  }
  return { e, clock, calls, box, post, get, raise, leaver, setFail: (n) => { failRule = n; } };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);

test('default: everything forwarding is removed at the disable, rules disabled not deleted, read back; counts; audit', async (t) => {
  const { e, calls, box, get, leaver } = await setup(t);
  const { id, v } = await leaver();
  const f = v.forwarding, m = box.get('khalid.harbi@corp.syn');
  assert.equal(f.status, 'removed', JSON.stringify(f));
  assert.equal(f.scope, 'all'); assert.equal(f.decided_by, 'syed'); assert.equal(f.decided_with, 'disable approval');
  assert.equal(m.smtp, ''); assert.equal(m.rules.length, 3, 'rules are kept as evidence');
  assert.deepEqual(m.rules.map((r) => r.enabled), [false, false, false]);
  assert.deepEqual(calls.filter((c) => /forwarding|inbox-rule/.test(c)), ['get-forwarding:khalid.harbi@corp.syn', 'clear-forwarding:khalid.harbi@corp.syn', 'disable-inbox-rule:1001', 'disable-inbox-rule:1002', 'get-forwarding:khalid.harbi@corp.syn'], 'the disabled old rule is left alone; read again at the end');
  assert.equal(f.removed.length, 3); assert.ok(f.removed.find((x) => x.kind === 'mailbox' && x.external && x.targets[0] === 'k.harbi.home@gmail.example' && x.keep_copy));
  assert.ok(f.removed.find((x) => x.name === 'copy to my gmail' && x.external)); assert.ok(f.removed.find((x) => x.name === 'claims to the team' && !x.external));
  const s = v.steps.find((x) => x.key === 'forwarding'); assert.ok(s && s.done);
  assert.ok(v.steps.findIndex((x) => x.key === 'forwarding') === v.steps.findIndex((x) => x.key === 'disabled') + 1, 'right after the disable');
  const L = (await get('/offboarding')).json; assert.equal(L.counts.forwarding_external, 1); assert.equal(L.forwarding.automatic, true);
  const ap = auditOf(e, 'offboarding.disable.approve')[0]; assert.equal(ap.detail.forwarding, 'remove');
  const rm = auditOf(e, 'offboarding.forwarding.removed')[0]; assert.equal(rm.by, 'system:exchange-online'); assert.equal(rm.detail.approved_by, 'syed'); assert.equal(rm.detail.removed.length, 3);
  assert.equal(auditOf(e, 'offboarding.forwarding.approved').length, 0, 'no second decision needed');
  assert.ok(id);
});

test('watch: a forward that comes back within 30 days is removed again under the same decision; not after', async (t) => {
  const { e, clock, box, get, leaver } = await setup(t);
  const { id } = await leaver();
  const m = box.get('khalid.harbi@corp.syn');
  m.rules[0].enabled = true;   // a delegate turns the gmail rule back on
  clock.t += 2 * 3600000; await e.app.addons.offboarding.runDue(null);
  assert.equal(m.rules[0].enabled, true, 'checked once a day, not every run');
  clock.t += DAY; await e.app.addons.offboarding.runDue(null);
  assert.equal(m.rules[0].enabled, false);
  let r = (await get('/offboarding/' + id)).json.forwarding;
  assert.equal(r.status, 'removed'); assert.equal(r.reappeared.length, 1); assert.equal(r.reappeared[0].items[0].name, 'copy to my gmail');
  const a = auditOf(e, 'offboarding.forwarding.reappeared'); assert.equal(a.length, 1); assert.equal(a[0].detail.removed[0].name, 'copy to my gmail');
  m.smtp = 'again@gmail.com'; clock.t += 31 * DAY; await e.app.addons.offboarding.runDue(null);
  assert.equal(m.smtp, 'again@gmail.com', 'the watch ends after 30 days');
  r = (await get('/offboarding/' + id)).json.forwarding; assert.equal(r.reappeared.length, 1);
});

test('only outside the company: internal forwarding kept; unknown accepted domains go to a person; only internal = nothing removed', async (t) => {
  const { box, leaver } = await setup(t);
  let x = await leaver({}, { decision: 'approve', forwarding: 'remove_external' });
  const m = box.get('khalid.harbi@corp.syn');
  assert.equal(x.v.forwarding.status, 'removed'); assert.equal(x.v.forwarding.scope, 'external');
  assert.equal(m.smtp, ''); assert.equal(m.rules[0].enabled, false); assert.equal(m.rules[1].enabled, true, 'the internal team rule stays');
  assert.deepEqual(x.v.forwarding.kept.map((k) => k.name), ['claims to the team']);
  x = await leaver({ username: 'nodom.user', employee_id: 'E-2' }, { decision: 'approve', forwarding: 'remove_external' });
  assert.equal(x.v.forwarding.status, 'proposed'); assert.match(x.v.forwarding.note, /accepted domains could not be read/);
  const n = box.get('nodom.user@corp.syn'); assert.equal(n.smtp, 'k.harbi.home@gmail.example', 'nothing removed on a guess');
  // only an internal rule left on this one
  const i = box.get('inside.user@corp.syn'); i.smtp = ''; i.rules = [i.rules[1]];
  x = await leaver({ username: 'inside.user', employee_id: 'E-3' }, { decision: 'approve', forwarding: 'remove_external' });
  assert.equal(x.v.forwarding.status, 'not_needed'); assert.match(x.v.forwarding.note, /only forwarding inside the company/); assert.equal(i.rules[0].enabled, true);
});

test('decide after: four eyes on the decision, validation, kept with a note, approve removes', async (t) => {
  const { e, box, post, leaver } = await setup(t);
  const { id, v } = await leaver({}, { decision: 'approve', forwarding: 'ask' });
  assert.equal(v.forwarding.status, 'proposed'); assert.equal(box.get('khalid.harbi@corp.syn').smtp, 'k.harbi.home@gmail.example');
  const D = (b, who) => post('/offboarding/' + id + '/forwarding/decide', b, who);
  assert.equal((await D({ decision: 'approve' }, DESK)).status, 403, 'administrators only');
  assert.equal((await D({ decision: 'approve' }, VIEW)).status, 403);
  let r = await D({ decision: 'approve' }, REQ_ADMIN); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await D({ decision: 'approve' }, { user: 'khalid.harbi', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /leaver cannot/);
  r = await D({ decision: 'approve' }, { user: 'svc:automation', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /service or AI identity/);
  r = await D({ decision: 'maybe' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^decision must be one of/);
  r = await D({ decision: 'approve', scope: 'some' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^scope must be one of/);
  r = await D({ decision: 'reject' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await D({ decision: 'approve', scope: 'all' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.forwarding.status, 'removed'); assert.equal(r.json.forwarding.decided_by, 'syed');
  assert.equal((await D({ decision: 'approve' }, ADM)).status, 409, 'already decided');
  assert.equal(auditOf(e, 'offboarding.forwarding.approved')[0].detail.scope, 'all');
  const k = await leaver({ username: 'keep.user', employee_id: 'E-5' }, { decision: 'approve', forwarding: 'ask' });
  r = await post('/offboarding/' + k.id + '/forwarding/decide', { decision: 'reject', note: 'legal hold: forwarding to the legal mailbox stays until the case closes' }, ADM);
  assert.equal(r.json.forwarding.status, 'kept'); assert.ok(r.json.steps.find((s) => s.key === 'forwarding').done);
  assert.equal(box.get('keep.user@corp.syn').smtp, 'k.harbi.home@gmail.example');
  assert.equal(auditOf(e, 'offboarding.forwarding.kept').length, 1);
  r = await post('/offboarding/' + k.id + '/approve', { decision: 'approve', forwarding: 'delete' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^forwarding must be one of/);
});

test('a failed rule is retried hourly without repeating what worked; on-premises recorded by hand; the check before the disable', async (t) => {
  const { e, clock, calls, box, post, get, raise, leaver } = await setup(t, { failRule: 1 });
  const { id, v } = await leaver();
  assert.equal(v.forwarding.status, 'approved'); assert.match(v.forwarding.error, /partly done - rule:1001/);
  assert.equal((await get('/offboarding')).json.counts.forwarding_failed, 1);
  assert.equal(auditOf(e, 'offboarding.forwarding.failed').length, 1);
  clock.t += 3601000; await e.app.addons.offboarding.runDue(null);
  const r = (await get('/offboarding/' + id)).json.forwarding;
  assert.equal(r.status, 'removed', JSON.stringify(r)); assert.equal(box.get('khalid.harbi@corp.syn').rules[0].enabled, false);
  assert.equal(calls.filter((c) => c === 'disable-inbox-rule:1002').length, 1, 'the rule that worked is not disabled twice');
  // on-premises mailbox
  const o = await leaver({ username: 'onprem.user', employee_id: 'E-4' });
  assert.equal(o.v.forwarding.status, 'on_premises');
  assert.equal((await post('/offboarding/' + o.id + '/forwarding/manual', { reference: 'x' }, DESK)).status, 400);
  let x = await post('/offboarding/' + o.id + '/forwarding/manual', { reference: 'Set-Mailbox -ForwardingSmtpAddress $null on EXCH01, CHG-9200' }, DESK);
  assert.equal(x.status, 200, JSON.stringify(x.json)); assert.equal(x.json.forwarding.status, 'removed_manually');
  // read-only check before the disable: operator yes, viewer no, audited, nothing changed
  const pid = await raise({ username: 'early.user', employee_id: 'E-7' });
  assert.equal((await post('/offboarding/' + pid + '/forwarding/check', {}, VIEW)).status, 403);
  x = await post('/offboarding/' + pid + '/forwarding/check', {}, DESK); assert.equal(x.status, 200, JSON.stringify(x.json));
  assert.equal(x.json.forwarding_check.items.filter((i) => i.active && i.external).length, 2);
  assert.equal(x.json.forwarding, undefined, 'a check is not the step');
  assert.equal(box.get('early.user@corp.syn').smtp, 'k.harbi.home@gmail.example');
  assert.equal(auditOf(e, 'offboarding.forwarding.check')[0].detail.external, 2);
  assert.equal((await post('/offboarding/' + pid + '/forwarding/check', { extra: 1 }, DESK)).status, 200, 'undeclared fields are dropped');
});
