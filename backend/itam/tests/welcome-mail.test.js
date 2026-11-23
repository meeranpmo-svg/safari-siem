// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Welcome kit (engine/welcome-mail.js) with a stubbed e-mail relay and SYNTHETIC people: the e-mail carries the sign-in link, the user
// name, the role and job role and the first-sign-in steps - and never a password; it goes through POST /reports/deliver as
// system:itam-notify to exactly the one address; settings (https only, no credentials in the URL); roles (viewer / operator refused,
// an AI identity refused even as admin), validation (undeclared fields dropped), the audit and the send log keep the domain, not the
// address; a relay failure is a 424 that says the account is fine and how to resend; a hostile name is escaped in the HTML.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'view.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };
const T = Date.parse('2026-11-13T08:00:00Z');

async function setup(t, { fail } = {}) {
  const sent = [];
  const siem = async (method, path, b, user) => { sent.push({ method, path, b, user }); return fail ? { ok: false, error: 'relay host not set' } : { ok: true, status: 200, data: { ok: true } }; };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3', welcomeSiem: siem });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  return { e, sent, call, audits: (a) => e.app.store.auditTail(300).filter((x) => x.action === a) };
}

test('send: link, user name, role, job role and steps - never a password; one recipient; audited with the domain only', async (t) => {
  const s = await setup(t);
  const r = await s.call('POST', '/welcome/send', { user: 'alia.syn', email: 'Alia.Syn@Synthetic.test', name: 'Alia Synthetic', role: 'operator', job: 'Oracle DBA', password: 'Synthetic-Pass-1234' });
  assert.equal(r.status, 200, r.text); assert.equal(r.json.sent_to_domain, 'synthetic.test');
  assert.equal(s.sent.length, 1); const m = s.sent[0];
  assert.equal(m.path, '/reports/deliver'); assert.equal(m.user, 'system:itam-notify'); assert.deepEqual(m.b.recipients, ['alia.syn@synthetic.test']);
  assert.match(m.b.subject, /Welcome to Zyberon Sentra/);
  for (const part of [m.b.text, m.b.html]) {
    assert.match(part, new RegExp('https:\\/\\/' + ZYB_ORG.portal_host_re)); assert.match(part, /alia\.syn/); assert.match(part, /operator/); assert.match(part, /Oracle DBA/);
    assert.match(part, /two-step verification/i); assert.match(part, /never sent by e-mail/);
    assert.doesNotMatch(part, /Synthetic-Pass-1234/, 'the password is never in the e-mail, even when a caller sends one');
  }
  const a = s.audits('welcome.send'); assert.equal(a.length, 1); assert.equal(a[0].by, 'syed'); assert.equal(a[0].target, 'alia.syn');
  assert.equal(JSON.stringify(a[0]).includes('alia.syn@'), false, 'the audit keeps the domain, not the address');
  const v = await s.call('GET', '/welcome/settings'); assert.equal(v.json.sent[0].user, 'alia.syn'); assert.equal(v.json.sent[0].domain, 'synthetic.test'); assert.equal(JSON.stringify(v.json).includes('alia.syn@'), false);
});

test('roles: viewer and operator refused, an AI identity refused even as admin; nothing sent', async (t) => {
  const s = await setup(t), b = { user: 'alia.syn', email: 'alia.syn@synthetic.test' };
  assert.equal((await s.call('POST', '/welcome/send', b, VW)).status, 403);
  assert.equal((await s.call('POST', '/welcome/send', b, OP)).status, 403);
  const ai = await s.call('POST', '/welcome/send', b, BOT); assert.equal(ai.status, 403); assert.match(ai.json.error, /a person/);
  assert.equal((await s.call('GET', '/welcome/settings', undefined, OP)).status, 403);
  assert.equal((await s.call('POST', '/welcome/settings', { note: 'x' }, OP)).status, 403);
  assert.equal((await s.call('POST', '/welcome/preview', { user: 'alia.syn' }, OP)).status, 403);
  assert.equal(s.sent.length, 0);
});

test('validation: user name, e-mail address and role are checked and named', async (t) => {
  const s = await setup(t);
  const r1 = await s.call('POST', '/welcome/send', { user: 'bad name!', email: 'a@synthetic.test' }); assert.equal(r1.status, 400); assert.match(r1.json.error, /user/);
  const r2 = await s.call('POST', '/welcome/send', { user: 'alia.syn', email: 'not-an-address' }); assert.equal(r2.status, 400); assert.match(r2.json.error, /email/);
  const r3 = await s.call('POST', '/welcome/send', { user: 'alia.syn' }); assert.equal(r3.status, 400); assert.match(r3.json.error, /email/);
  const r4 = await s.call('POST', '/welcome/send', { user: 'alia.syn', email: 'a@synthetic.test', role: 'root' }); assert.equal(r4.status, 400); assert.match(r4.json.error, /role/);
  const r5 = await s.call('POST', '/welcome/send', { user: 'alia.syn', email: 'a@synthetic.test\r\nBcc: x@evil.test' }); assert.equal(r5.status, 400);
  assert.equal(s.sent.length, 0);
});

test('settings: the link (https only, no credentials), help contact and note appear in the e-mail; audited', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('POST', '/welcome/settings', { portal_url: 'http://soc.synthetic.test' })).status, 400);
  assert.equal((await s.call('POST', '/welcome/settings', { portal_url: 'https://u:p@soc.synthetic.test' })).status, 400);
  assert.equal((await s.call('POST', '/welcome/settings', { portal_url: 'not a url' })).status, 400);
  const ok = await s.call('POST', '/welcome/settings', { portal_url: 'https://soc.synthetic.test/', help_contact: 'IT service desk, ext. 0000', note: 'Training is on Sunday.' });
  assert.equal(ok.status, 200); assert.equal(ok.json.portal_url, 'https://soc.synthetic.test'); assert.equal(ok.json.updated_by, 'syed');
  assert.equal(s.audits('welcome.settings').length, 1);
  const p = await s.call('POST', '/welcome/preview', { user: 'badr.syn', name: 'Badr Synthetic', role: 'viewer' });
  assert.equal(p.status, 200); assert.match(p.json.text, /https:\/\/soc\.synthetic\.test/); assert.match(p.json.text, /ext\. 0000/); assert.match(p.json.text, /Training is on Sunday/);
  assert.equal(s.sent.length, 0, 'a preview sends nothing');
});

test('a relay failure: 424 saying the account is fine and how to resend; logged as not sent; audited ok:false', async (t) => {
  const s = await setup(t, { fail: true });
  const r = await s.call('POST', '/welcome/send', { user: 'alia.syn', email: 'alia.syn@synthetic.test' });
  assert.equal(r.status, 424); assert.match(r.json.error, /account is fine/); assert.match(r.json.error, /relay host not set/);
  const a = s.audits('welcome.send'); assert.equal(a.length, 1); assert.equal(a[0].detail.ok, false);
  const v = await s.call('GET', '/welcome/settings'); assert.equal(v.json.sent[0].ok, false);
});

test('a hostile name is escaped in the HTML and flattened in the text', async (t) => {
  const s = await setup(t);
  const p = await s.call('POST', '/welcome/preview', { user: 'coral.syn', name: '<img src=x onerror=alert(1)>Coral\r\nBcc: x' });
  assert.equal(p.status, 200); assert.doesNotMatch(p.json.html, /<img src=x/); assert.match(p.json.html, /&lt;img src=x/); assert.doesNotMatch(p.json.text, /\r/);
});

test('Arabic: by default one e-mail in Arabic (right-to-left, first) and English; the setting or a send picks one language', async (t) => {
  const s = await setup(t);
  await s.call('POST', '/welcome/send', { user: 'alia.syn', email: 'alia.syn@synthetic.test', name: 'Alia Synthetic', role: 'viewer', job: 'Oracle DBA' });
  const m = s.sent[0].b;
  assert.match(m.subject, /مرحباً بك في Zyberon Sentra/); assert.match(m.subject, /Welcome to Zyberon Sentra/);
  assert.match(m.html, /dir="rtl" lang="ar"/); assert.match(m.html, /dir="ltr" lang="en"/);
  assert.ok(m.html.indexOf('lang="ar"') < m.html.indexOf('lang="en"'), 'Arabic first');
  assert.ok(m.html.includes('تسجيل الدخول إلى Zyberon Sentra'), 'the Arabic button');
  assert.match(m.text, new RegExp('رابط تسجيل الدخول: https:\\/\\/' + ZYB_ORG.portal_host_re));
  for (const w of ['اسم المستخدم', 'فعّل التحقق بخطوتين', 'مشاهد', 'لا تُرسل أبداً بالبريد الإلكتروني', ('https://' + ZYB_ORG.portal_host), 'alia.syn', 'Oracle DBA']) assert.ok(m.html.includes(w) && m.text.includes(w), w);
  assert.match(m.html, /<meta charset="utf-8">/);
  assert.equal(s.audits('welcome.send')[0].detail.lang, 'both');
  const ar = await s.call('POST', '/welcome/preview', { user: 'alia.syn', lang: 'ar' });
  assert.match(ar.json.text, /مثل تطبيق Microsoft Authenticator أو تطبيق Google Authenticator، ثم/); assert.doesNotMatch(ar.json.text, /\((Microsoft|Google)/, 'no Latin app names inside brackets in the Arabic (they render out of order right-to-left)');
  assert.match(ar.json.text, /اسم المستخدم/); assert.doesNotMatch(ar.json.text, /User name/); assert.doesNotMatch(ar.json.subject, /Welcome/);
  assert.equal((await s.call('POST', '/welcome/settings', { language: 'en' })).json.language, 'en');
  const en = await s.call('POST', '/welcome/preview', { user: 'alia.syn' }); assert.doesNotMatch(en.json.text, /اسم المستخدم/); assert.match(en.json.text, /User name/);
  assert.equal((await s.call('POST', '/welcome/settings', { language: 'fr' })).status, 400);
  assert.equal((await s.call('POST', '/welcome/preview', { user: 'alia.syn', lang: 'fr' })).status, 400);
});

test('an AD account: the steps say to sign in with the Windows user name and password, never an initial password; validated', async (t) => {
  const s = await setup(t);
  let r = await s.call('POST', '/welcome/preview', { user: 'alia.syn', role: 'operator', lang: 'en', signin: 'ad' });
  assert.equal(r.status, 200);
  assert.match(r.json.text, /Sign in with your Windows account/); assert.match(r.json.text, /There is no separate password for the platform/);
  assert.doesNotMatch(r.json.text, /initial password/i, 'no initial password for an AD account');
  r = await s.call('POST', '/welcome/preview', { user: 'alia.syn', lang: 'ar', signin: 'ad' }); assert.match(r.json.text, /سجّل الدخول بحساب Windows/);
  r = await s.call('POST', '/welcome/preview', { user: 'alia.syn', lang: 'en' }); assert.match(r.json.text, /initial password/, 'a local account keeps its steps');
  r = await s.call('POST', '/welcome/preview', { user: 'alia.syn', signin: 'kerberos' }); assert.equal(r.status, 400); assert.match(r.text, /signin/);
});
