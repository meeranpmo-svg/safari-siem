// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * Mail team alerts: the e-mail administrators' recipient list and the send path IT Asset Management's early warnings use
 * (route checks: an SMTP certificate about to expire, an MX / name-server change, an Exchange queue building up, the
 * availability budget running out). The mail goes out through the SIEM's SMTP relay (Reports), like the DBA alerts.
 *   GET  {P}/mail/notify            operator   recipients, last sends, relay problems
 *   POST {P}/mail/notify            admin      {recipients[]}  audited
 *   POST {P}/mail/notify/test       admin      a test mail to the list  audited
 *   POST {P}/mail/notify/send       admin, only system:itam-mail-route   {id, subject, text, html?}  audited
 * The subject always starts with [MAIL]; sizes are capped; recipients are plain addresses (no display names).
 */
const { wrap, audit, prefixOf, HttpError } = require('./routeutil');
const { body } = require('../util/check');

const EMAIL = /^[^\s@<>"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/;
const escH = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function createMailNotify({ state, mail, mailProblems, now = Date.now }) {
  const col = state.collection('mail_notify'), runs = state.collection('mail_notify_runs');
  const doc = () => col.get('settings') || { id: 'settings', recipients: [] };
  function settings() {
    const d = doc();
    return { recipients: d.recipients || [], by: d.by || null, at: d.at || null, problems: mailProblems ? mailProblems() : [],
      recent: runs.all().sort((a, b) => b.at - a.at).slice(0, 10).map((r) => ({ id: r.id, at: r.at, subject: r.subject, status: r.status, error: r.error || null })) };
  }
  function save(b, by) {
    const v = body(b).list('recipients', { max: 20, item: 'str', itemMax: 254, unique: true }).done();
    const list = [...new Set((v.recipients || []).map((x) => x.toLowerCase()))];
    const badOne = list.find((x) => !EMAIL.test(x)); if (badOne) throw new HttpError(400, `recipients: "${badOne.slice(0, 60)}" is not an e-mail address`);
    col.put({ id: 'settings', recipients: list, by, at: now() });
    return settings();
  }
  async function send(subject, text, html, id) {
    const d = doc();
    if (!(d.recipients || []).length) throw new HttpError(400, 'no mail team recipients set (Email Route Map → Alerts)');
    if (typeof mail !== 'function') throw new HttpError(503, 'e-mail is not available in this engine (Reports SMTP relay)');
    const s = '[MAIL] ' + String(subject || 'Mail service alert').replace(/^\[MAIL\]\s*/, '').replace(/[\r\n]+/g, ' ').slice(0, 200);
    const t = String(text || '').slice(0, 100000), h = html ? String(html).slice(0, 300000) : `<pre>${escH(t)}</pre>`;
    const rec = { id: String(id || 'mail-' + now()).slice(0, 60), at: now(), subject: s, recipients: d.recipients.length, status: 'ok' };
    try { await mail({ to: d.recipients, subject: s, text: t, html: h }); }
    catch (e) { rec.status = 'failed'; rec.error = String(e.message || e).slice(0, 200); }
    runs.put(rec);
    for (const old of runs.all().sort((a, b) => b.at - a.at).slice(100)) runs.remove(old.id);
    if (rec.status !== 'ok') throw new HttpError(502, `not sent: ${rec.error}`);
    return { ok: true, recipients: rec.recipients, id: rec.id };
  }
  return { settings, save, send };
}

function register(api, deps) {
  if (!deps.state) return null;
  const P = prefixOf(deps), sched = (deps.reports || {}).schedules || null;
  const N = deps.mailNotify || createMailNotify({ state: deps.state, mail: sched ? (m) => sched.mail(m) : null,
    mailProblems: sched ? () => sched.mailProblems() : () => ['the SMTP relay (Reports) is not running'], now: deps.now });
  api.route('GET', `${P}/mail/notify`, wrap(deps, 'operator', (ctx) => ctx.ok(N.settings())));
  api.route('POST', `${P}/mail/notify`, wrap(deps, 'admin', (ctx) => {
    const r = N.save(ctx.body, ctx.user); audit(ctx, 'mail.notify.save', 'mail-notify', { recipients: r.recipients.length }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/mail/notify/test`, wrap(deps, 'admin', async (ctx) => {
    const r = await N.send(('Test from the ' + ZYB_ORG.short + ' SIEM'), `This is a test of the mail team alert e-mail, sent by ${ctx.user}.`, null, 'test-' + Date.now());
    audit(ctx, 'mail.notify.test', 'mail-notify', { recipients: r.recipients }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/mail/notify/send`, wrap(deps, 'admin', async (ctx) => {
    if (String(ctx.user || '') !== 'system:itam-mail-route') throw new HttpError(403, 'only IT Asset Management (mail route early warnings) sends this');
    const b = body(ctx.body).str('id', { required: true, max: 60, re: /^[A-Za-z0-9_.:-]+$/, msg: 'id has an invalid format' }).str('subject', { required: true, max: 200 })
      .str('text', { required: true, max: 100000 }).str('html', { max: 300000 }).done();
    const r = await N.send(b.subject, b.text, b.html, b.id);
    audit(ctx, 'mail.notify.send', b.id, { recipients: r.recipients }); return ctx.ok(r);
  }));
  deps.mailNotify = N;
  return N;
}

module.exports = { register, createMailNotify };
