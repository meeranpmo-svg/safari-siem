// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The Reports SMTP relay used by IT Asset Management's Reporting Center / Notification centre (engine/reports/routes.js
// POST {P}/reports/deliver): only those service identities, admin role, every field validated, CSV / HTML attachments only,
// "not configured" is 424 with the reason, recipients counted (never listed) in the audit. SMTP is stubbed; data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const smtp = require('../engine/reports/smtp');
const routes = require('../engine/reports/routes');

function memState() {
  const cols = {};
  return { collection(n) { const m = cols[n] || (cols[n] = new Map()); return { get: (id) => m.get(id), put: (d) => m.set(d.id, d), remove: (id) => m.delete(id), all: (f) => [...m.values()].filter(f || (() => true)) }; } };
}
function harness() {
  const R = {}, audits = [];
  const deps = { state: memState(), config: { secrets: {} }, log: { info() {}, warn() {}, error() {}, child() { return this; } }, ch: null, alerts: null, cases: null };
  routes.register({ route: (m, p, fn) => { R[m + ' ' + p] = fn; } }, deps);
  const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  const call = async (m, p, b, role = 'admin', user = 'system:itam-report-center') => {
    let out = null;
    const ctx = { body: b, query: {}, params: {}, role, user, ip: '10.0.0.5', ok: (x) => { out = { status: 200, body: x }; return out; }, fail: (s, msg) => { out = { status: s, error: msg }; return out; },
      need: (r) => { if ((RANK[role] || 0) < RANK[r]) { out = { status: 403, error: 'requires ' + r }; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d }) };
    try { await R[m + ' /api/soc' + p](ctx); } catch (e) { out = { status: e.status || 500, error: e.message }; }
    return out;
  };
  return { call, audits };
}
const MSG = { id: 'RC-exec-1', subject: 'Executive report (synthetic)', text: 'synthetic', html: '<p>synthetic</p>', recipients: ['ciso.syn@corpgroup.test'] };

test('relay: service identities only, admin role, validation, not configured = 424 with the reason', async () => {
  const h = harness();
  assert.equal((await h.call('POST', '/reports/deliver', MSG, 'admin', 'syed')).status, 403, 'a person cannot use the service path');
  assert.equal((await h.call('POST', '/reports/deliver', MSG, 'operator')).status, 403, 'needs the admin role');
  let r = await h.call('POST', '/reports/deliver', Object.assign({}, MSG, { recipients: ['not-an-address'] }));
  assert.equal(r.status, 400); assert.match(r.error, /recipients: "not-an-address"/);
  r = await h.call('POST', '/reports/deliver', Object.assign({}, MSG, { attachments: [{ filename: 'x.exe', content: 'MZ', contentType: 'application/octet-stream' }] }));
  assert.equal(r.status, 400); assert.match(r.error, /attachments\[0\]\.filename/);
  assert.equal((await h.call('POST', '/reports/deliver', Object.assign({}, MSG, { subject: '' }))).status, 400, 'subject required');
  r = await h.call('POST', '/reports/deliver', MSG);
  assert.equal(r.status, 424, 'no SMTP relay configured: the caller can act on it'); assert.match(r.error, /not configured/);
  assert.deepEqual(h.audits.at(-1).d, { recipients: 1, ok: false, stage: 'config' });
  const st = await h.call('GET', '/reports/relay', null, 'admin', 'syed');
  assert.equal(st.body.ok, false); assert.ok(st.body.problems.length);
});

test('relay: a configured relay sends with CSV attachment, audit counts recipients only', async (t) => {
  const h = harness(), sent = [];
  const orig = smtp.sendMail; smtp.sendMail = async (s, m) => { sent.push({ s, m }); return { accepted: m.to, rejected: [] }; }; t.after(() => { smtp.sendMail = orig; });
  const s = await h.call('POST', '/reports/schedules', { smtp: { host: 'relay.corpgroup.test', port: 25, from: 'reports@corpgroup.test', starttls: false } }, 'admin', 'syed');
  assert.equal(s.status, 200, s.error);
  const r = await h.call('POST', '/reports/deliver', Object.assign({}, MSG, { recipients: ['CISO.syn@corpgroup.test', 'it.head.syn@corpgroup.test'], attachments: [{ filename: 'executive.csv', content: 'a,b\n1,2', contentType: 'text/csv' }], extra: 'dropped' }));
  assert.equal(r.status, 200, r.error); assert.equal(r.body.accepted, 2);
  assert.deepEqual(sent[0].m.to, ['ciso.syn@corpgroup.test', 'it.head.syn@corpgroup.test']);
  assert.equal(sent[0].m.attachments[0].filename, 'executive.csv'); assert.equal(sent[0].m.from, 'reports@corpgroup.test');
  const a = h.audits.at(-1); assert.equal(a.a, 'report.relay.deliver'); assert.deepEqual(a.d, { recipients: 2, attachments: 1, ok: true });
  assert.ok(!JSON.stringify(h.audits).includes('ciso.syn@'), 'addresses never in the audit');
});
