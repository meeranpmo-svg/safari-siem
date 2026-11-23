// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Privacy Office notifications (engine/pdpl-notify.js): settings are admin-only, the SMTP password and Teams webhook are
// write-only and sealed, the contact list is kept by an admin or the DPO, new critical / high tasks e-mail the assignee once,
// escalations e-mail the DPO / chair and post to Teams, transient failures retry, the daily summary goes on working days,
// nothing secret or any address reaches the audit trail, Teams text cannot carry markdown links. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { postTeams, plain } = require('../engine/pdpl-notify');

const PY = process.env.PYTHON || 'python3';
const DAY = 86400000;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' }, ST = { user: 'faisal.syn', role: 'viewer' };
const HOOK = 'https://prod-01.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=SyntheticSig123';

async function setup(t, sendImpl) {
  let clock = Date.parse('2026-10-20T08:00:00Z');   // a Tuesday, 11:00 in Riyadh
  const mails = [], cards = [];
  const send = sendImpl || (async (s, m) => { mails.push({ s, m }); return { accepted: m.to }; });
  const teams = async (url, payload) => { cards.push({ url, payload }); return { status: 202 }; };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, privacyOffice: { send: (s, m) => send(s, m), teams } });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' }, ADM);
  await post('/pdpl/stewards', { department: 'Claims', user: 'faisal.syn', role: 'data_steward' });
  await post('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', owner: 'Claims', data_categories: ['health'], legal_basis: 'legitimate_interest' }, ADM);
  return { e, post, get, mails, cards, tick: (d) => { clock += d * DAY; }, setClock: (v) => { clock = v; }, PO: e.app.addons.privacyOffice };
}
async function configure(post) {
  const r = await post('/pdpl/office/notify', { smtp: { host: 'mail.example.test', port: 587, from: 'privacy@example.test', user: 'svc-privacy' }, smtp_password: 'Winter2026!Synthetic', teams_webhook: HOOK, email_enabled: true, teams_enabled: true, portal_url: 'https://portal.example.test' }, ADM);
  assert.equal(r.status, 200, r.raw);
  assert.equal((await post('/pdpl/office/contacts', { contacts: [{ user: 'faisal.syn', email: 'faisal@example.test' }, { user: 'huda.syn', email: 'huda@example.test' }] }, DPO)).status, 200);
}

test('settings: admin only, secrets write-only and sealed, contacts by an admin or the DPO, audited without secrets or addresses', async (t) => {
  const { e, post, get } = await setup(t);
  assert.equal((await post('/pdpl/office/notify', { email_enabled: true }, OP)).status, 403);
  assert.equal((await post('/pdpl/office/notify', { teams_webhook: 'https://evil.example.com/hook' }, ADM)).status, 400, 'only Teams Workflows hosts');
  assert.equal((await post('/pdpl/office/notify', { teams_webhook: 'http://prod.logic.azure.com/x' }, ADM)).status, 400, 'https only');
  assert.equal((await post('/pdpl/office/notify', { email_enabled: true }, ADM)).status, 400, 'no relay yet');
  assert.equal((await post('/pdpl/office/notify', { smtp: { host: 'bad host!' } }, ADM)).status, 400);
  assert.equal((await post('/pdpl/office/notify', { smtp: { from: 'not-an-address' } }, ADM)).status, 400);
  assert.equal((await post('/pdpl/office/notify', { portal_url: 'javascript:alert(1)' }, ADM)).status, 400);
  await configure(post);
  const v = (await get('/pdpl/office/notify')).json;
  assert.equal(v.smtp_password_set, true); assert.equal(v.teams_webhook_set, true); assert.equal(v.teams_host, 'prod-01.westeurope.logic.azure.com');
  const raw = JSON.stringify(v) + JSON.stringify(e.app.store.collection('pdpl_office_notify').all());
  assert.ok(!raw.includes('Winter2026') && !raw.includes('SyntheticSig123'), 'secrets are sealed, never shown');
  assert.equal((await get('/pdpl/office/notify', ST)).status, 403);
  // contacts
  assert.equal((await post('/pdpl/office/contacts', { contacts: [{ user: 'x', email: 'x@example.test' }] }, OP)).status, 403, 'an operator who is not the DPO');
  assert.equal((await post('/pdpl/office/contacts', { contacts: [{ user: 'x', email: 'nope' }] }, DPO)).status, 400);
  assert.equal((await post('/pdpl/office/contacts', { contacts: [{ user: 'x', email: 'x@example.test' }] }, ST)).status, 403);
  const au = JSON.stringify(e.app.store.auditTail(80).filter((x) => /pdpl\.notify/.test(x.action)));
  assert.ok(au.includes('pdpl.notify.config') && au.includes('pdpl.notify.contacts'));
  assert.ok(!au.includes('Winter2026') && !au.includes('SyntheticSig') && !au.includes('@example.test'), 'no secret or address in the audit trail');
  // the test route: admin only; sends a real message through the injected relay
  assert.equal((await post('/pdpl/office/notify/test', { channel: 'email' }, OP)).status, 403);
  const tm = await post('/pdpl/office/notify/test', { channel: 'email', to: 'huda.syn' }, ADM); assert.equal(tm.json.status, 'sent', tm.raw);
  assert.equal((await post('/pdpl/office/notify/test', { channel: 'teams' }, ADM)).json.status, 'sent');
  assert.equal((await post('/pdpl/office/notify/test', { channel: 'sms' }, ADM)).status, 400);
});

test('events: new critical / high tasks e-mail the assignee once; escalation e-mails and posts to Teams; digest; retry', async (t) => {
  const { e, post, mails, cards, tick, setClock, PO } = await setup(t);
  await configure(post);
  await post('/pdpl/office/run', {});
  const toFaisal = mails.filter((x) => x.m.to.includes('faisal@example.test'));
  assert.ok(toFaisal.length >= 2 && toFaisal.every((x) => /^\[PDPL (critical|high)\] New task/.test(x.m.subject) && !/[\u0600-\u06ff]/.test(x.m.subject + x.m.html + x.m.text)), 'critical / high tasks e-mailed to the steward, English only by default (no Arabic anywhere)');
  assert.equal((await e.req('GET', '/pdpl/office/notify', ADM)).json.language, 'en', 'the office language reads English by default');
  assert.ok(mails.every((x) => x.s.password === 'Winter2026!Synthetic' && x.s.host === 'mail.example.test'), 'the relay gets the unsealed password');
  assert.ok(toFaisal[0].m.text.includes('https://portal.example.test/dashboards/pdpl-office.html') && /closes when the PDPL registers/.test(toFaisal[0].m.text));
  assert.ok(!mails.some((x) => /New task/.test(x.m.subject) && /PDPL (medium|low)/.test(x.m.subject)), 'medium / low wait for the summary');
  const n = mails.length; await post('/pdpl/office/run', {}); assert.equal(mails.length, n, 'never sent twice');
  // escalation to the DPO: e-mail to the DPO + the assignee, a Teams card
  tick(3); await post('/pdpl/office/run', {});
  const esc = mails.filter((x) => /escalated to the DPO/.test(x.m.subject));
  assert.ok(esc.length >= 1 && esc[0].m.to.includes('huda@example.test') && esc[0].m.to.includes('faisal@example.test'));
  assert.ok(cards.some((c) => c.url === HOOK && /escalated/.test(JSON.stringify(c.payload))));
  // daily summary: forced now; one message per person; on a Friday the timer sends nothing
  const before = mails.length;
  const d = await PO.digestNow(); assert.ok(d.sent >= 2);
  const dig = mails.slice(before).filter((x) => /Your Privacy Office tasks/.test(x.m.subject));
  assert.ok(dig.some((x) => x.m.to[0] === 'faisal@example.test') && dig.some((x) => x.m.to[0] === 'huda@example.test'));
  assert.ok(cards.some((c) => /Privacy Office - /.test(JSON.stringify(c.payload))));
  setClock(Date.parse('2026-10-30T09:00:00Z'));   // Friday
  assert.equal((await PO.notifier.digest(e.app.store.collection('pdpl_office_tasks').all())).sent, 0, 'no summary on the weekend');
  // a person with no address is skipped and says why
  const out = e.app.store.collection('pdpl_office_outbox').all();
  assert.ok(out.every((m) => ['sent', 'skipped'].includes(m.status)));
  assert.ok(!JSON.stringify(e.app.store.auditTail(300)).includes('@example.test'), 'no address in the audit trail');
});

test('delivery failures: transient retried with backoff, permanent marked failed; routing never stops', async (t) => {
  let fail = 'transient';
  const send = async (s, m) => { if (fail === 'transient') throw Object.assign(new Error('421 try later'), { transient: true }); if (fail === 'permanent') throw Object.assign(new Error('550 relay denied'), { transient: false }); return { accepted: m.to }; };
  const { e, post, tick, PO } = await setup(t, send);
  await configure(post);
  const r = await post('/pdpl/office/run', {}); assert.equal(r.status, 200, 'a relay that is down does not stop the routing');
  const box = () => e.app.store.collection('pdpl_office_outbox').all((m) => m.channel === 'email' && m.event === 'raised');
  assert.ok(box().length && box().every((m) => m.status === 'retry' && m.next_try && m.attempts === 1));
  fail = null; await PO.notifier.retry(); assert.ok(box().every((m) => m.status === 'retry'), 'not before next_try');
  tick(0.01); await PO.notifier.retry(); assert.ok(box().every((m) => m.status === 'sent'));
  fail = 'permanent'; tick(3); await post('/pdpl/office/run', {});
  const escm = e.app.store.collection('pdpl_office_outbox').all((m) => m.event === 'escalated' && m.channel === 'email');
  assert.ok(escm.length && escm.every((m) => m.status === 'failed' && /550/.test(m.error)));
});

test('Teams: allow-listed https hosts only; card text cannot carry markdown links', async () => {
  await assert.rejects(postTeams('https://example.com/hook', {}), /Workflows/);
  await assert.rejects(postTeams('http://x.logic.azure.com/hook', {}), /https/);
  const p = plain('[click](https://evil.example) **now** <b>');
  assert.ok(!/\[click\]\(/.test(p) && p.includes('\\[click\\]'));
});

test('engine/smtp.js is the SIEM\'s SMTP client', () => {
  const siem = path.resolve(__dirname, '../../siem/engine/reports/smtp.js');
  if (!fs.existsSync(siem)) return;   // the SIEM repository is not beside this one (CI of this repository alone)
  const norm = (f) => fs.readFileSync(f, 'utf8').split('\n').filter((l) => !/Same file as sentra-siem/.test(l)).join('\n');
  assert.equal(norm(path.join(__dirname, '../engine/smtp.js')), norm(siem));
});

test('Arabic: with both languages chosen Arabic comes first right-to-left, a person can choose Arabic or English only, Teams in Arabic', async (t) => {
  const { e, post, mails, cards, tick, PO } = await setup(t);
  await configure(post);
  assert.equal((await post('/pdpl/office/notify', { language: 'both' }, ADM)).status, 200);   // the administrator chooses both languages
  await post('/pdpl/office/run', {});
  const m = mails.find((x) => x.m.to.includes('faisal@example.test'));
  assert.match(m.m.subject, /^\[حماية البيانات - (حرجة|عالية)\] مهمة جديدة: .+ \| \[PDPL (critical|high)\] New task: /);
  assert.match(m.m.html, /<div dir="rtl" lang="ar"[^>]*>.*بصفتك مسؤول البيانات في إدارة Claims.*<\/div><hr><div dir="ltr" lang="en"/s, 'Arabic block first, right-to-left, the routing reason translated');
  assert.match(m.m.html, /<bdi dir="ltr">/, 'English titles keep their direction inside the Arabic text');
  assert.match(m.m.text, /تُغلق هذه المهمة تلقائياً[\s\S]*———[\s\S]*This task closes when/);
  // one person chooses Arabic, the DPO English; the office language set to Arabic only for Teams
  assert.equal((await post('/pdpl/office/contacts', { contacts: [{ user: 'faisal.syn', email: 'faisal@example.test', lang: 'ar' }, { user: 'huda.syn', email: 'huda@example.test', lang: 'en' }] }, DPO)).status, 200);
  assert.equal((await post('/pdpl/office/contacts', { contacts: [{ user: 'x.syn', email: 'x@example.test', lang: 'fr' }] }, DPO)).status, 400);
  assert.equal((await post('/pdpl/office/notify', { teams_language: 'ar' }, ADM)).status, 200);
  assert.equal((await post('/pdpl/office/notify', { language: 'de' }, ADM)).status, 400);
  const n0 = mails.length;
  await PO.digestNow();
  const dig = mails.slice(n0);
  const ar = dig.find((x) => x.m.to[0] === 'faisal@example.test'), en = dig.find((x) => x.m.to[0] === 'huda@example.test');
  assert.match(ar.m.subject, /^\[حماية البيانات\] مهامك في مكتب الخصوصية - \d+ مفتوحة، \d+ متأخرة$/); assert.doesNotMatch(ar.m.html, /dir="ltr" lang="en"/);
  assert.match(ar.m.html, /النشاط «Medical claims \(synthetic\)» يستند إلى المصلحة المشروعة/, 'task titles in Arabic'); assert.doesNotMatch(ar.m.text, /كما وردت في السجلات/, 'no "kept as recorded" note when Arabic exists');
  assert.match(en.m.subject, /^\[PDPL\] Your Privacy Office tasks/); assert.doesNotMatch(en.m.html, /dir="rtl"/);
  const tc = cards[cards.length - 1].payload.attachments[0].content;
  assert.equal(tc.version, '1.5'); assert.match(tc.body[0].text, /^مكتب الخصوصية - /);
  assert.ok(tc.body.slice(1).every((c) => c.type === 'Container' && c.rtl === true), 'Teams in Arabic: right-to-left containers only');
  assert.equal(tc.actions.length, 1); assert.equal(tc.actions[0].title, 'فتح مكتب الخصوصية');
  // escalation: mixed recipients (Arabic + English) fall back to the office language (both)
  tick(3); await post('/pdpl/office/run', {});
  const esc = mails.find((x) => /تصعيد مهمة متأخرة إلى مسؤول حماية البيانات/.test(x.m.subject));
  assert.ok(esc && /escalated to the DPO/.test(esc.m.subject), 'both languages when the recipients differ');
  const out = e.app.store.collection('pdpl_office_outbox').all();
  assert.ok(out.some((x) => x.lang === 'ar') && out.some((x) => x.lang === 'en') && out.some((x) => x.lang === 'both'), 'the outbox records the language sent');
});

test('Arabic wording: routing reasons, functions and duties translated; unknown text kept as written; markdown neutralised in Teams', () => {
  const { whyAr, composeTeams, composeMail } = require('../engine/pdpl-notify');
  assert.equal(whyAr('champion of Claims'), 'بصفتك سفير الخصوصية في إدارة Claims');
  assert.equal(whyAr('owner of Data subject requests'), 'بصفتك مالك وظيفة: طلبات أصحاب البيانات');
  assert.equal(whyAr('data owner of CLAIMS-SQL'), 'بصفتك مالك بيانات النظام CLAIMS-SQL');
  assert.match(whyAr('the DPO (nobody else is named for this)'), /مسؤول حماية البيانات/);
  assert.equal(whyAr('the committee meets at least quarterly'), 'تجتمع لجنة الخصوصية كل ربع سنة على الأقل');
  assert.equal(whyAr('something new'), 'something new');
  const t = { id: 'PO-00009', title: '[link](https://evil.example) <script>x</script>', severity: 'high', due: '2026-11-01T00:00:00Z', assignee: 'faisal.syn', why: 'data steward of Claims' };
  const c = composeTeams('escalated', t, { level: 2, to: 'syed' }, 'both');
  assert.match(c.subject, /رئيس اللجنة.*\| PDPL task escalated \(committee chair\)/);
  assert.ok(!JSON.stringify(c).includes('[link](https'), 'no markdown link from a title');
  const m = composeMail('raised', t, {}, 'ar', 'https://portal.example.test/dashboards/pdpl-office.html');
  assert.ok(!m.html.includes('<script>') && m.html.includes('&lt;script&gt;'), 'the title is escaped in the e-mail');
  assert.match(m.html, /فتح مكتب الخصوصية/);
  assert.match(m.text, /كما وردت في السجلات/, 'a task without Arabic keeps its English, marked as such');
  const m2 = composeMail('raised', Object.assign({}, t, { title_ar: 'عنوان عربي', recommendation_ar: 'إجراء عربي', recommendation: 'English step' }), {}, 'ar', '');
  assert.match(m2.subject, /مهمة جديدة: عنوان عربي$/); assert.match(m2.text, /المطلوب: إجراء عربي/); assert.doesNotMatch(m2.text, /English step|كما وردت/);
});
