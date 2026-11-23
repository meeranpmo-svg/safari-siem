// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Mail team alerts (engine/soc/mailnotify.js): recipients (admin, validated, audited), the send path only IT Asset
// Management's mail-route identity may use ([MAIL] subject, capped, recorded), relay failures reported, roles refused.
const test = require('node:test');
const assert = require('node:assert/strict');
const mn = require('../engine/soc/mailnotify');

function memState() {
  const cols = {};
  return { collection(n) { const m = cols[n] || (cols[n] = new Map()); return { get: (id) => m.get(id), put: (d) => m.set(d.id, d), remove: (id) => m.delete(id), all: (f) => [...m.values()].filter(f || (() => true)) }; } };
}
function harness(mailFn) {
  const routes = {}, audits = [], sent = [];
  const deps = { state: memState(), now: () => 1000, config: {}, reports: { schedules: { mail: async (m) => { sent.push(m); if (mailFn) await mailFn(m); }, mailProblems: () => [] } } };
  mn.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, deps);
  const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  const call = async (m, p, b, role = 'admin', user = 'syed') => {
    let out = null;
    const ctx = { body: b, query: {}, role, user, ip: '10.0.0.5', ok: (x) => { out = { status: 200, body: x }; return out; }, fail: (s, msg) => { out = { status: s, error: msg }; return out; },
      need: (r) => { if ((RANK[role] || 0) < RANK[r]) { out = { status: 403, error: 'requires ' + r }; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d }) };
    await routes[m + ' /api/soc' + p](ctx);
    return out;
  };
  return { call, audits, sent };
}

test('recipients: admin only, every address validated, saved lower-case and audited', async () => {
  const h = harness();
  assert.equal((await h.call('POST', '/mail/notify', { recipients: ['a@corpgroup.test'] }, 'operator')).status, 403, 'operator refused');
  assert.equal((await h.call('GET', '/mail/notify', null, 'viewer')).status, 403, 'viewer cannot read the list');
  const bad = await h.call('POST', '/mail/notify', { recipients: ['ok@corpgroup.test', 'not-an-address'] });
  assert.equal(bad.status, 400); assert.match(bad.error, /recipients: "not-an-address"/);
  assert.equal((await h.call('POST', '/mail/notify', { recipients: 'x@corpgroup.test' })).status, 400, 'must be a list');
  const r = await h.call('POST', '/mail/notify', { recipients: ['Mail.Admin@Corpgroup.test', 'mail.admin@corpgroup.test'], extra: 1 });
  assert.equal(r.status, 200); assert.deepEqual(r.body.recipients, ['mail.admin@corpgroup.test']);
  assert.deepEqual(h.audits.at(-1), { a: 'mail.notify.save', t: 'mail-notify', d: { recipients: 1 } });
  assert.deepEqual((await h.call('GET', '/mail/notify', null, 'operator')).body.recipients, ['mail.admin@corpgroup.test']);
});

test('send: only system:itam-mail-route, [MAIL] subject, recorded; no recipients and relay failure are clear errors', async () => {
  const h = harness();
  const msg = { id: 'mr-1', subject: 'SMTP certificate of mx1 expires in 9 days', text: 'line 1\nline 2' };
  assert.equal((await h.call('POST', '/mail/notify/send', msg)).status, 403, 'a person cannot use the service path');
  assert.equal((await h.call('POST', '/mail/notify/send', msg, 'operator', 'system:itam-mail-route')).status, 403, 'needs the admin role');
  let r = await h.call('POST', '/mail/notify/send', msg, 'admin', 'system:itam-mail-route');
  assert.equal(r.status, 400); assert.match(r.error, /no mail team recipients/);
  await h.call('POST', '/mail/notify', { recipients: ['mail.admin@corpgroup.test'] });
  assert.equal((await h.call('POST', '/mail/notify/send', { id: 'bad id!', subject: 's', text: 't' }, 'admin', 'system:itam-mail-route')).status, 400);
  assert.equal((await h.call('POST', '/mail/notify/send', { id: 'x', text: 't' }, 'admin', 'system:itam-mail-route')).status, 400, 'subject required');
  r = await h.call('POST', '/mail/notify/send', Object.assign({}, msg, { subject: '[MAIL] ' + msg.subject + '\r\nBcc: x@evil.test' }), 'admin', 'system:itam-mail-route');
  assert.equal(r.status, 200); assert.equal(h.sent.length, 1);
  assert.equal(h.sent[0].subject, '[MAIL] SMTP certificate of mx1 expires in 9 days Bcc: x@evil.test', 'one [MAIL] prefix, no header injection');
  assert.deepEqual(h.sent[0].to, ['mail.admin@corpgroup.test']); assert.match(h.sent[0].html, /<pre>line 1\nline 2<\/pre>/);
  assert.deepEqual(h.audits.at(-1), { a: 'mail.notify.send', t: 'mr-1', d: { recipients: 1 } });
  assert.equal((await h.call('GET', '/mail/notify', null, 'operator')).body.recent[0].status, 'ok');
  const f = harness(async () => { throw new Error('SMTP 550 relay denied'); });
  await f.call('POST', '/mail/notify', { recipients: ['mail.admin@corpgroup.test'] });
  r = await f.call('POST', '/mail/notify/test', {});
  assert.equal(r.status, 502); assert.match(r.error, /550 relay denied/);
  assert.equal((await f.call('GET', '/mail/notify', null, 'operator')).body.recent[0].status, 'failed', 'the failure is recorded');
});
