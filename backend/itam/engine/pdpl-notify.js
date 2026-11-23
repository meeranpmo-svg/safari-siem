// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * Privacy Office notifications: e-mail to the person a PDPL task is routed to, and a Microsoft Teams channel message for
 * escalations and the daily summary. The Privacy Office (engine/pdpl-office.js) decides WHAT happened; this file decides
 * who is told, sends it, retries and keeps an outbox as evidence.
 *
 *   e-mail   a new critical / high task           -> the assignee, at once
 *            an escalation                        -> the person it is escalated to, copy to the assignee
 *            an accepted risk that has ended      -> the assignee and the DPO
 *            daily summary (working days, Riyadh) -> each person with open tasks: one message listing them
 *   Teams    escalations, ended risk acceptances and the daily summary -> the Privacy Office channel (a Workflows webhook)
 *
 * The SMTP relay (engine/smtp.js) and the Teams webhook are security-integration settings: an administrator sets them; the
 * SMTP password and the webhook URL (it carries its own signature) are write-only and stored sealed in the vault. People's
 * work e-mail addresses are kept in the contact list (an administrator or the DPO), never written to a log or the audit
 * trail - only user names and counts are. A message is sent once per (event, task, level); transient failures are
 * retried three times with backoff; every attempt is in the outbox. Nothing here ever changes a task.
 *
 *   GET  /pdpl/office/notify            operator  settings (no secrets), contacts, recent outbox
 *   POST /pdpl/office/notify            admin     {email_enabled, teams_enabled, smtp{…}, smtp_password, clear_smtp_password,
 *                                                  teams_webhook, clear_teams_webhook, digest_hour, portal_url,
 *                                                  language, teams_language (both | ar | en; default en)}          audited
 *   POST /pdpl/office/contacts          admin or the DPO  {contacts[{user, email, lang?}]}  lang overrides the office language  audited
 *   POST /pdpl/office/notify/test       admin     {channel: email|teams, to?}                                            audited
 */
const https = require('node:https');
const smtp = require('./smtp');
const { createSealer } = require('./discovery/vault');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (v) => String(v || '').trim().toLowerCase();
const TEAMS_HOST = /^([a-z0-9-]+\.)*(logic\.azure\.com|powerplatform\.com|webhook\.office\.com|environment\.api\.powerplatform\.com)$/i;
const SMTP_KEYS = ['host', 'port', 'tls', 'starttls', 'user', 'from', 'from_name', 'ca_file', 'reject_unauthorized'];
const RIYADH = 3 * 3600000;   // UTC+3, no daylight saving
const WORKDAYS = [0, 1, 2, 3, 4];   // Sunday - Thursday
const RETRY_MS = [5 * 60000, 30 * 60000, 2 * 3600000];

// one Workflows (Power Automate) webhook POST; the URL host is allow-listed, https only, short timeout, bounded answer
function postTeams(url, payload, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(url); } catch (e) { return reject(Object.assign(new Error('the Teams webhook URL is not a URL'), { transient: false })); }
    if (u.protocol !== 'https:' || !TEAMS_HOST.test(u.hostname)) return reject(Object.assign(new Error('the Teams webhook must be an https Workflows / Office webhook URL'), { transient: false }));
    const data = Buffer.from(JSON.stringify(payload));
    const r = https.request({ hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method: 'POST', timeout: timeoutMs, headers: { 'Content-Type': 'application/json', 'Content-Length': data.length } }, (res) => {
      let size = 0; res.on('data', (c) => { size += c.length; if (size > 65536) res.destroy(); });
      res.on('end', () => (res.statusCode >= 200 && res.statusCode < 300 ? resolve({ status: res.statusCode })
        : reject(Object.assign(new Error('Teams answered HTTP ' + res.statusCode), { transient: res.statusCode >= 500 || res.statusCode === 429 }))));
      res.on('error', (e) => reject(Object.assign(new Error('Teams connection failed: ' + e.code), { transient: true })));
    });
    r.on('timeout', () => r.destroy(Object.assign(new Error('Teams did not answer in time'), { transient: true })));
    r.on('error', (e) => reject(Object.assign(new Error(e.message && /Teams/.test(e.message) ? e.message : 'Teams not reachable (' + (e.code || 'error') + ')'), { transient: true })));
    r.end(data);
  });
}
// sections: [{rtl, lines[]}] - an Arabic section is a right-to-left container (Adaptive Cards 1.5, which Teams renders)
const card = (title, sections, link, lang) => ({ type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', content: {
  $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.5',
  body: [{ type: 'TextBlock', text: title, weight: 'Bolder', size: 'Medium', wrap: true }].concat(sections.map((sec) => ({ type: 'Container', rtl: !!sec.rtl, separator: true,
    items: sec.lines.slice(0, 25).map((l) => ({ type: 'TextBlock', text: l, wrap: true, spacing: 'Small', horizontalAlignment: sec.rtl ? 'Right' : 'Left' })) }))),
  actions: link ? [{ type: 'Action.OpenUrl', title: lang === 'en' ? 'Open the Privacy Office' : lang === 'ar' ? 'فتح مكتب الخصوصية' : 'فتح مكتب الخصوصية / Open the Privacy Office', url: link }] : [] } }] });
// Teams Adaptive Card text is markdown: neutralise it so a task title cannot become a link or formatting
const plain = (s) => String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').replace(/([\\`*_{}[\]()#+!|<>~])/g, '\\$1').slice(0, 300);
const escH = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---- the words: Arabic and English. Task titles and recommendations come in Arabic from pyengine/pdpl_ar.py (title_ar,
// recommendation_ar); a finding the catalogue does not know keeps its English text, marked as such, inside the Arabic block.
const LANGS = ['both', 'ar', 'en'];
const SEV_AR = { critical: 'حرجة', high: 'عالية', medium: 'متوسطة', low: 'منخفضة' };
const FN_AR = { 'Data inventory and mapping': 'حصر البيانات وخرائطها', 'Processing approval and contracts': 'اعتماد المعالجة والعقود', 'Data subject requests': 'طلبات أصحاب البيانات',
  'Security incident and breach response': 'الاستجابة للحوادث وتسرّب البيانات', 'Staff training and awareness': 'تدريب الموظفين والتوعية', 'SDAIA liaison and documentation': 'التواصل مع سدايا والتوثيق' };
const DUTY_AR = { 'records of processing are reviewed at least yearly': 'تُراجَع سجلات أنشطة المعالجة مرة في السنة على الأقل',
  'access to sensitive data is reviewed every 6 months': 'تُراجَع صلاحيات الوصول إلى البيانات الحساسة كل 6 أشهر', 'the committee meets at least quarterly': 'تجتمع لجنة الخصوصية كل ربع سنة على الأقل',
  'the programme is reviewed at least once a year': 'يُراجَع برنامج حماية البيانات مرة في السنة على الأقل', 'staff who handle personal data are trained yearly': 'يُدرَّب الموظفون الذين يتعاملون مع البيانات الشخصية سنوياً',
  'processors are assessed periodically': 'يُقيَّم معالجو البيانات دورياً' };
const ROLE_AR = { 'data steward': 'مسؤول البيانات', deputy: 'نائب مسؤول البيانات', champion: 'سفير الخصوصية' };
// the routing reason (pyengine/pdpl_office.py route / duties) in Arabic; anything not recognised is kept as written
function whyAr(w) {
  const x = String(w || ''); let m;
  if ((m = /^(data steward|deputy|champion) of (.+)$/.exec(x))) return 'بصفتك ' + ROLE_AR[m[1]] + ' في إدارة ' + m[2];
  if ((m = /^data owner of (.+)$/.exec(x))) return 'بصفتك مالك بيانات النظام ' + m[1];
  if ((m = /^deputy owner of (.+)$/.exec(x))) return 'بصفتك نائب مالك وظيفة: ' + (FN_AR[m[1]] || m[1]);
  if ((m = /^owner of (.+)$/.exec(x))) return 'بصفتك مالك وظيفة: ' + (FN_AR[m[1]] || m[1]);
  if (/^the DPO/.test(x)) return 'بصفتك مسؤول حماية البيانات (لم يُسمَّ شخص آخر لهذه المهمة)';
  if ((m = /^assigned by ([^:]+): (.*)$/.exec(x))) return 'أسندها إليك ' + m[1] + ': ' + m[2];
  return DUTY_AR[x] || x;
}
const dt = (v) => String(v || '').slice(0, 10);
const TXT = {
  en: {
    tag: '[PDPL]', task: 'Task', sev: (s) => s, due: 'due', todo: 'What to do', open: 'Open the Privacy Office', overdue: 'OVERDUE',
    closes: 'This task closes when the PDPL registers show it is fixed.', dpo: 'the DPO', chair: 'the committee chair', nobody: 'nobody',
    raised: { subj: (t) => '[PDPL ' + t.severity + '] New task: ' + t.title, lead: (t) => 'A PDPL task was routed to you (' + (t.why || '') + ').' },
    escalated: { subj: (t, d) => '[PDPL] Overdue task escalated to ' + (d.level === 2 ? 'the committee chair' : 'the DPO') + ': ' + t.title,
      lead: (t, d) => 'This PDPL task is overdue and was escalated to ' + (d.to || 'nobody') + ' (level ' + d.level + '). Assigned to ' + (t.assignee || 'nobody') + '.' },
    risk: { subj: (t) => '[PDPL] Accepted risk ended: ' + t.title, lead: (t) => 'The risk accepted on this task ended ' + t.risk_until + '; the task is open again.' },
    digest: { subj: (t, d) => '[PDPL] Your Privacy Office tasks - ' + d.open + ' open, ' + d.overdue + ' overdue', lead: () => 'Your open PDPL tasks, earliest deadline first:' },
    test: { subj: () => 'Privacy Office test message', lead: () => ('This is a test from the ' + ZYB_ORG.short + ' Privacy Office. If you read it, notifications work.') },
    teams: { escalated: (d) => 'PDPL task escalated (' + (d.level === 2 ? 'committee chair' : 'DPO') + ')', risk: () => 'PDPL accepted risk ended', digest: (d) => 'Privacy Office - ' + d.day, test: () => 'Privacy Office test message',
      assigned: (a, to) => 'Assigned to ' + a + ' · escalated to ' + to, reopened: (id) => 'Task ' + id + ' is open again',
      totals: (d) => 'Open ' + d.open + ' · overdue ' + d.overdue + ' · escalated ' + d.escalated.length + ' · unassigned ' + d.unassigned, esc: 'Escalated', works: 'If you read this, Teams notifications work.' },
  },
  ar: {
    tag: '[حماية البيانات]', task: 'المهمة', sev: (s) => SEV_AR[s] || s, due: 'تاريخ الاستحقاق', todo: 'المطلوب', open: 'فتح مكتب الخصوصية', overdue: 'متأخرة',
    closes: 'تُغلق هذه المهمة تلقائياً عندما تُظهر سجلات حماية البيانات أنها عولجت.', dpo: 'مسؤول حماية البيانات', chair: 'رئيس لجنة الخصوصية', nobody: 'غير مُسندة',
    asis: 'عنوان المهمة وتفاصيلها كما وردت في السجلات:',
    raised: { subj: (t) => '[حماية البيانات - ' + (SEV_AR[t.severity] || t.severity) + '] مهمة جديدة: ' + t.title, lead: (t) => 'أُسندت إليك مهمة جديدة في برنامج حماية البيانات الشخصية (' + whyAr(t.why) + ').' },
    escalated: { subj: (t, d) => '[حماية البيانات] تصعيد مهمة متأخرة إلى ' + (d.level === 2 ? 'رئيس لجنة الخصوصية' : 'مسؤول حماية البيانات') + ': ' + t.title,
      lead: (t, d) => 'هذه المهمة تجاوزت موعدها وصُعّدت إلى ' + (d.to || 'غير محدد') + ' (المستوى ' + d.level + '). المكلَّف بها: ' + (t.assignee || 'غير مُسندة') + '.' },
    risk: { subj: (t) => '[حماية البيانات] انتهى قبول المخاطر: ' + t.title, lead: (t) => 'انتهت مدة قبول المخاطر لهذه المهمة في ' + t.risk_until + '، وأُعيد فتحها.' },
    digest: { subj: (t, d) => '[حماية البيانات] مهامك في مكتب الخصوصية - ' + d.open + ' مفتوحة، ' + d.overdue + ' متأخرة', lead: () => 'مهامك المفتوحة في حماية البيانات، الأقرب موعداً أولاً:' },
    test: { subj: () => 'رسالة تجريبية من مكتب الخصوصية', lead: () => ('هذه رسالة تجريبية من مكتب الخصوصية في ' + ZYB_ORG.short_ar + '. إذا وصلتك فالإشعارات تعمل.') },
    teams: { escalated: (d) => 'تصعيد مهمة حماية بيانات (' + (d.level === 2 ? 'رئيس اللجنة' : 'مسؤول حماية البيانات') + ')', risk: () => 'انتهى قبول المخاطر لمهمة حماية بيانات', digest: (d) => 'مكتب الخصوصية - ' + d.day, test: () => 'رسالة تجريبية من مكتب الخصوصية',
      assigned: (a, to) => 'المكلَّف: ' + a + ' · صُعّدت إلى: ' + to, reopened: (id) => 'أُعيد فتح المهمة ' + id,
      totals: (d) => 'مفتوحة ' + d.open + ' · متأخرة ' + d.overdue + ' · مُصعّدة ' + d.escalated.length + ' · غير مُسندة ' + d.unassigned, esc: 'مُصعّدة', works: 'إذا ظهرت هذه الرسالة فإشعارات Teams تعمل.' },
  },
};
const clip = (v, n) => String(v == null ? '' : v).slice(0, n);
// the Arabic block uses the task's Arabic title / recommendation (pyengine/pdpl_ar.py) and says so only when none exists
const arOf = (t) => (t ? Object.assign({}, t, t.title_ar ? { title: t.title_ar, _ar: true } : {}, t.recommendation_ar ? { recommendation: t.recommendation_ar } : {}) : t);
function block(lang, kind, t0, d, link) {
  const t = lang === 'ar' ? arOf(t0) : t0;
  if (lang === 'ar' && d && d.list) d = Object.assign({}, d, { list: d.list.map(arOf) });
  const L = TXT[lang], K = L[kind], lines = [K.lead(t, d)], html = ['<p>' + escH(K.lead(t, d)) + '</p>'];
  const ltr = (v) => (/[\u0600-\u06ff]/.test(String(v)) ? '<bdi>' + escH(v) + '</bdi>' : '<bdi dir="ltr">' + escH(v) + '</bdi>');   // English keeps its direction inside Arabic text
  if (t) {
    if (lang === 'ar' && !t._ar) { lines.push(L.asis); html.push('<p style="color:#666">' + escH(L.asis) + '</p>'); }
    lines.push('', t.title, L.task + ' ' + t.id + ' · ' + L.sev(t.severity) + ' · ' + L.due + ' ' + dt(t.due));
    html.push('<p><b>' + ltr(t.title) + '</b><br>' + escH(L.task) + ' ' + ltr(t.id) + ' · ' + escH(L.sev(t.severity)) + ' · ' + escH(L.due) + ' ' + ltr(dt(t.due)) + '</p>');
    if (t.recommendation) { lines.push(L.todo + ': ' + t.recommendation); html.push('<p>' + escH(L.todo) + ': ' + ltr(t.recommendation) + '</p>'); }
  }
  if (d && d.list) {
    for (const x of d.list) lines.push('- ' + x.id + ' [' + L.sev(x.severity) + (x.overdue ? ', ' + L.overdue : '') + '] ' + L.due + ' ' + dt(x.due) + ': ' + x.title);
    html.push('<ul>' + d.list.map((x) => '<li>' + ltr(x.id) + ' <b>' + escH(L.sev(x.severity)) + (x.overdue ? '، ' + escH(L.overdue) : '') + '</b> ' + escH(L.due) + ' ' + ltr(dt(x.due)) + ': ' + ltr(x.title) + '</li>').join('') + '</ul>');
  }
  if (link) { lines.push('', L.open + ': ' + link); html.push('<p><a href="' + escH(link) + '">' + escH(L.open) + '</a></p>'); }
  if (t) { lines.push('', L.closes); html.push('<p style="color:#666">' + escH(L.closes) + '</p>'); }
  return { text: lines.join('\n'), html: html.join('') };
}
function composeMail(kind, t, d, lang, link) {
  const T = t ? Object.assign({}, t, { title: clip(t.title, 300) }) : null;
  const subj = (l) => TXT[l][kind].subj(l === 'ar' ? arOf(T) : T, d);
  const ar = lang !== 'en' ? block('ar', kind, T, d, link) : null, en = lang !== 'ar' ? block('en', kind, T, d, link) : null;
  const subject = clip(lang === 'both' ? subj('ar') + ' | ' + subj('en') : subj(lang), 250);
  const wrapAr = (h) => '<div dir="rtl" lang="ar" style="text-align:right;font-family:Tahoma,Arial,sans-serif">' + h + '</div>';
  const wrapEn = (h) => '<div dir="ltr" lang="en" style="text-align:left;font-family:Segoe UI,Arial,sans-serif">' + h + '</div>';
  return { subject, text: [ar && ar.text, en && en.text].filter(Boolean).join('\n\n———\n\n') + '\n',
    html: '<!doctype html><html><body>' + [ar && wrapAr(ar.html), en && wrapEn(en.html)].filter(Boolean).join('<hr>') + '</body></html>' };
}
function composeTeams(kind, t, d, lang) {
  const sec = (l) => {
    const X = TXT[l].teams, L = TXT[l], lines = [];
    if (t) { lines.push(plain(l === 'ar' && t.title_ar ? t.title_ar : t.title), L.task + ' ' + t.id + ' · ' + L.sev(t.severity) + ' · ' + L.due + ' ' + dt(t.due)); }
    if (kind === 'escalated') lines.push(X.assigned(plain(t.assignee || L.nobody), plain(d.to || L.nobody)));
    if (kind === 'risk') lines.push(X.reopened(t.id));
    if (kind === 'digest') { lines.push(X.totals(d)); for (const x of d.escalated.slice(0, 10)) lines.push(X.esc + ': ' + plain(l === 'ar' && x.title_ar ? x.title_ar : x.title) + ' (' + plain(x.assignee || L.nobody) + ')'); }
    if (kind === 'test') lines.push(X.works);
    return { rtl: l === 'ar', lines };
  };
  const ttl = (l) => TXT[l].teams[kind](d || {});
  return { subject: clip(lang === 'both' ? ttl('ar') + ' | ' + ttl('en') : ttl(lang), 250), sections: (lang === 'both' ? ['ar', 'en'] : [lang]).map(sec) };
}

function createNotifier(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-pdpl-notify' });
  const send = opts.send || ((s, m) => smtp.sendMail(s, m));
  const teams = opts.teams || postTeams;
  const cfgC = () => store.collection('pdpl_office_notify'), outC = () => store.collection('pdpl_office_outbox');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('pdpl-notify:' + key, 3600000, 'warn', msg, detail); };
  const cfg = () => cfgC().get('cfg') || { id: 'cfg', email_enabled: false, teams_enabled: false, smtp: { port: 25, starttls: true, reject_unauthorized: true }, contacts: [], digest_hour: 8 };
  const iso = () => new Date(now()).toISOString();
  const emailOf = (u) => { const c = (cfg().contacts || []).find((x) => low(x.user) === low(u)); return c ? c.email : null; };

  function view() {
    const c = cfg();
    return { email_enabled: !!c.email_enabled, teams_enabled: !!c.teams_enabled, smtp: Object.assign({}, c.smtp), smtp_password_set: !!c.smtp_enc, teams_webhook_set: !!c.teams_enc,
      teams_host: c.teams_host || null, digest_hour: c.digest_hour, portal_url: c.portal_url || '', language: c.language || 'en', teams_language: c.teams_language || null, contacts: c.contacts || [], updated_by: c.updated_by || null, updated_at: c.updated_at || null,
      vault: sealer.available() ? 'available' : 'unavailable: ' + sealer.unavailableReason(),
      outbox: outC().all().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 50).map((m) => ({ id: m.id, at: m.at, channel: m.channel, event: m.event, task: m.task, to: m.to_users, lang: m.lang || null, status: m.status, error: m.error || null, attempts: m.attempts })) };
  }
  function configure(b, who) {
    if (who.role !== 'admin') throw httpErr(403, 'the e-mail relay and the Teams webhook are security-integration settings: an administrator sets them');
    const c = Object.assign({}, cfg());
    for (const k of ['email_enabled', 'teams_enabled', 'digest_hour', 'portal_url', 'language', 'teams_language']) if (b[k] !== undefined) c[k] = b[k];
    if (b.smtp) { c.smtp = Object.assign({}, c.smtp); for (const k of SMTP_KEYS) if (b.smtp[k] !== undefined) c.smtp[k] = b.smtp[k]; }
    const needVault = () => { if (!sealer.available()) throw httpErr(503, 'credential vault unavailable: ' + sealer.unavailableReason()); };
    if (b.smtp_password) { needVault(); c.smtp_enc = sealer.seal('smtp', b.smtp_password); c.smtp_password_at = iso(); }
    if (b.clear_smtp_password) delete c.smtp_enc;
    if (b.teams_webhook) {
      let u; try { u = new URL(b.teams_webhook); } catch (e) { throw httpErr(400, 'teams_webhook must be a URL'); }
      if (u.protocol !== 'https:' || !TEAMS_HOST.test(u.hostname)) throw httpErr(400, 'teams_webhook must be an https Teams Workflows webhook (*.logic.azure.com, *.powerplatform.com or *.webhook.office.com)');
      needVault(); c.teams_enc = sealer.seal('teams', b.teams_webhook); c.teams_host = u.hostname;
    }
    if (b.clear_teams_webhook) { delete c.teams_enc; delete c.teams_host; }
    if (c.email_enabled && !(c.smtp && c.smtp.host && c.smtp.from)) throw httpErr(400, 'e-mail needs smtp.host and smtp.from before it is switched on');
    if (c.teams_enabled && !c.teams_enc) throw httpErr(400, 'Teams needs the channel webhook before it is switched on');
    c.updated_by = who.user; c.updated_at = iso();
    cfgC().put(c);
    // never the password, the webhook or anyone's address
    audit(who, 'pdpl.notify.config', 'office', { email_enabled: !!c.email_enabled, teams_enabled: !!c.teams_enabled, smtp_host: (c.smtp && c.smtp.host) || null, smtp_password: b.smtp_password ? 'changed' : b.clear_smtp_password ? 'cleared' : 'unchanged',
      teams_webhook: b.teams_webhook ? 'changed' : b.clear_teams_webhook ? 'cleared' : 'unchanged', teams_host: c.teams_host || null, digest_hour: c.digest_hour, language: c.language || 'en', teams_language: c.teams_language || null });
    return view();
  }
  function setContacts(list, who, isDpo) {
    if (who.role !== 'admin' && !isDpo) throw httpErr(403, 'an administrator or the DPO keeps the Privacy Office contact list');
    const c = Object.assign({}, cfg(), { contacts: list, updated_by: who.user, updated_at: iso() });
    cfgC().put(c);
    audit(who, 'pdpl.notify.contacts', 'office', { contacts: list.length, users: list.map((x) => x.user).slice(0, 50) });
    return view();
  }
  function smtpConf() {
    const c = cfg(), s = Object.assign({ port: 25, starttls: true, reject_unauthorized: true, timeout_ms: 30000 }, c.smtp);
    if (c.smtp_enc) s.password = sealer.unseal('smtp', c.smtp_enc);
    return s;
  }
  async function deliver(m) {
    const c = cfg();
    try {
      if (m.channel === 'email') {
        const s = smtpConf();
        const to = [...new Set((m.to_emails || []).concat((m.to_users || []).map(emailOf)).filter(Boolean))];
        if (!to.length) { m.status = 'skipped'; m.error = 'no e-mail address in the contact list for ' + (m.to_users || []).join(', '); return m; }
        await send(s, { from: s.from, from_name: m.from_name || s.from_name || (ZYB_ORG.short + ' Privacy Office'), to, subject: m.subject, text: m.text, html: m.html });
      } else {
        await teams(sealer.unseal('teams', c.teams_enc), card(m.subject, m.sections || [{ rtl: false, lines: m.lines || [] }], c.portal_url ? c.portal_url.replace(/\/+$/, '') + '/dashboards/pdpl-office.html' : null, m.lang));
      }
      m.status = 'sent'; m.sent_at = iso(); m.error = null;
    } catch (e) {
      m.attempts = (m.attempts || 0) + 1;
      const transient = e.transient !== false && m.attempts <= RETRY_MS.length;
      m.status = transient ? 'retry' : 'failed'; m.error = String(e.message || e).slice(0, 200);
      if (transient) m.next_try = new Date(now() + RETRY_MS[m.attempts - 1]).toISOString();
      warn(m.channel, 'Privacy Office ' + m.channel + ' not delivered', { event: m.event, task: m.task, error: m.error, attempts: m.attempts });
    }
    return m;
  }
  function link() { const c = cfg(); return c.portal_url ? c.portal_url.replace(/\/+$/, '') + '/dashboards/pdpl-office.html' : ''; }
  // the language of a message: the recipients' own choice when they agree, otherwise the office setting (default English only:
  // the platform is English until Arabic is switched on; an administrator may still choose both or Arabic)
  function langFor(users) {
    const c = cfg(), d = LANGS.includes(c.language) ? c.language : 'en';
    const own = [...new Set((users || []).map((u) => ((c.contacts || []).find((x) => low(x.user) === low(u)) || {}).lang).filter(Boolean))];
    return own.length === 1 && LANGS.includes(own[0]) ? own[0] : d;
  }
  const teamsLang = () => { const c = cfg(); return LANGS.includes(c.teams_language) ? c.teams_language : LANGS.includes(c.language) ? c.language : 'en'; };
  function queue(key, m) {
    if (outC().get(key)) return null;   // once per (event, task, level)
    const rec = Object.assign({ id: key, at: iso(), attempts: 0, status: 'queued' }, m);
    outC().put(rec);
    return rec;
  }
  const mail = (kind, t, d, users) => Object.assign({ to_users: users, lang: langFor(users) }, composeMail(kind, t, d, langFor(users), link()));
  const tcard = (kind, t, d) => { const l = teamsLang(); return Object.assign({ lang: l }, composeTeams(kind, t, d, l)); };
  // the Privacy Office calls this after each routing run with the events it produced
  async function onEvents(events, tasks, org) {
    const c = cfg(); if (!c.email_enabled && !c.teams_enabled) return { queued: 0 };
    const byKey = new Map(tasks.map((t) => [t.key, t]));
    const q = [];
    for (const e of events) {
      const t = byKey.get(e.key); if (!t) continue;
      if (e.event === 'raised' && ['critical', 'high'].includes(t.severity) && t.assignee && c.email_enabled) {
        q.push(queue('raised|' + t.id + '|email', Object.assign({ channel: 'email', event: 'raised', task: t.id }, mail('raised', t, {}, [t.assignee]))));
      }
      if (e.event === 'escalated') {
        const d = { level: (e.detail && e.detail.level) || t.escalation, to: (e.detail && e.detail.to) || t.escalated_to };
        if (c.email_enabled && d.to) q.push(queue('escalated|' + t.id + '|' + d.level + '|email', Object.assign({ channel: 'email', event: 'escalated', task: t.id }, mail('escalated', t, d, [...new Set([d.to, t.assignee].filter(Boolean))]))));
        if (c.teams_enabled) q.push(queue('escalated|' + t.id + '|' + d.level + '|teams', Object.assign({ channel: 'teams', event: 'escalated', task: t.id, to_users: ['channel'] }, tcard('escalated', t, d))));
      }
      if (e.event === 'risk_expired') {
        if (c.email_enabled) q.push(queue('risk|' + t.id + '|' + String(t.risk_until) + '|email', Object.assign({ channel: 'email', event: 'risk_expired', task: t.id }, mail('risk', t, {}, [...new Set([t.assignee, org && org.dpo].filter(Boolean))]))));
        if (c.teams_enabled) q.push(queue('risk|' + t.id + '|' + String(t.risk_until) + '|teams', Object.assign({ channel: 'teams', event: 'risk_expired', task: t.id, to_users: ['channel'] }, tcard('risk', t, {}))));
      }
    }
    let n = 0; for (const m of q.filter(Boolean)) { outC().put(await deliver(m)); n++; }
    return { queued: n };
  }
  // daily summary, working days at digest_hour Riyadh time: one e-mail per person with open tasks, one Teams card
  async function digest(tasks, force) {
    const c = cfg(); if (!c.email_enabled && !c.teams_enabled) return { sent: 0 };
    const r = new Date(now() + RIYADH), day = r.toISOString().slice(0, 10);
    if (!force && (!WORKDAYS.includes(r.getUTCDay()) || r.getUTCHours() < (c.digest_hour == null ? 8 : c.digest_hour))) return { sent: 0 };
    const open = tasks.filter((t) => t.status !== 'closed');
    const per = new Map();
    for (const t of open) for (const u of [t.assignee, t.escalation ? t.escalated_to : null].filter(Boolean)) { if (!per.has(low(u))) per.set(low(u), { user: u, tasks: [] }); per.get(low(u)).tasks.push(t); }
    const q = [];
    if (c.email_enabled) for (const p of per.values()) {
      const list = p.tasks.sort((a, b) => String(a.due).localeCompare(String(b.due))).slice(0, 40);
      q.push(queue('digest|' + day + '|' + low(p.user), Object.assign({ channel: 'email', event: 'digest', task: null }, mail('digest', null, { list, open: p.tasks.length, overdue: p.tasks.filter((t) => t.overdue).length }, [p.user]))));
    }
    if (c.teams_enabled && open.length) q.push(queue('digest|' + day + '|teams', Object.assign({ channel: 'teams', event: 'digest', task: null, to_users: ['channel'] },
      tcard('digest', null, { day, open: open.length, overdue: open.filter((t) => t.overdue).length, escalated: open.filter((t) => t.escalation), unassigned: open.filter((t) => !t.assignee).length }))));
    let n = 0; for (const m of q.filter(Boolean)) { outC().put(await deliver(m)); n++; }
    return { sent: n };
  }
  async function retry() {
    let n = 0;
    for (const m of outC().all((x) => x.status === 'retry' && Date.parse(x.next_try) <= now())) { outC().put(await deliver(Object.assign({}, m))); n++; }
    return { retried: n };
  }
  async function test(b, who) {
    if (who.role !== 'admin') throw httpErr(403, 'an administrator tests the notification channels');
    const c = cfg();
    if (b.channel === 'email' && !(c.smtp && c.smtp.host && c.smtp.from)) throw httpErr(409, 'set smtp.host and smtp.from first');
    if (b.channel === 'teams' && !c.teams_enc) throw httpErr(409, 'set the Teams webhook first');
    const user = b.to || who.user;
    const body = b.channel === 'email' ? mail('test', null, {}, [user]) : Object.assign({ to_users: [user] }, tcard('test', null, {}));
    const m = await deliver(Object.assign({ id: 'test|' + now(), at: iso(), channel: b.channel, event: 'test', task: null, attempts: 99 }, body));
    outC().put(m);
    audit(who, 'pdpl.notify.test', b.channel, { to: b.channel === 'email' ? user : 'channel', status: m.status, error: m.error || null });
    return { channel: b.channel, status: m.status, error: m.error || null };
  }
  // another module's e-mail through the same relay and outbox (certificate expiry alerts): once per key, to platform users
  // (looked up in the contact list) and / or addresses; nothing is sent while e-mail is off
  async function sendPlatform(b) {
    const c = cfg();
    if (!c.email_enabled) return { status: 'skipped', error: 'e-mail is off (Privacy Office -> Notifications)' };
    const m = queue(String(b.key).slice(0, 300), { channel: 'email', event: String(b.event || 'platform').slice(0, 40), task: null, to_users: (b.users || []).slice(0, 50), to_emails: (b.emails || []).filter((x) => smtp.isAddr(String(x))).slice(0, 50),
      subject: String(b.subject || '').slice(0, 250), text: String(b.text || '').slice(0, 20000), from_name: b.from_name ? String(b.from_name).slice(0, 80) : undefined });
    if (!m) return { status: 'duplicate' };
    const r = await deliver(m); outC().put(r);
    return { status: r.status, error: r.error || null };
  }
  return { view, configure, setContacts, onEvents, digest, retry, test, sendPlatform };
}

function registerNotifyRoutes(srv, app, N, isDpo) {
  const { body } = require('./check');
  const USER = /^[A-Za-z0-9._@-]{1,80}$/;
  srv.route('GET', '/pdpl/office/notify', (ctx) => { ctx.need('operator'); return N.view(); });
  srv.route('POST', '/pdpl/office/notify', (ctx) => {
    ctx.need('admin');
    const b = body(ctx.body).bool('email_enabled').bool('teams_enabled').int('digest_hour', { min: 0, max: 23 }).oneOf('language', LANGS).oneOf('teams_language', LANGS)
      .str('portal_url', { max: 200, re: /^https:\/\/[A-Za-z0-9.-]+(:\d+)?(\/[A-Za-z0-9._~\/-]*)?$/, msg: 'portal_url must be the https address of the portal' })
      .str('smtp_password', { max: 256 }).bool('clear_smtp_password').str('teams_webhook', { max: 2000 }).bool('clear_teams_webhook')
      .rule((o) => { const s = (ctx.body || {}).smtp; if (s === undefined) return null; if (!s || typeof s !== 'object' || Array.isArray(s)) return 'smtp must be an object';
        const v = body(s).str('host', { max: 253, re: /^[A-Za-z0-9.-]{1,253}$|^\[?[0-9a-fA-F:.]+\]?$/, msg: 'smtp.host must be a host name or IP address' }).int('port', { min: 1, max: 65535 }).bool('tls').bool('starttls')
          .str('user', { max: 256, re: /^[^\r\n]*$/, msg: 'smtp.user invalid' }).str('from', { max: 254, email: true }).str('from_name', { max: 120, re: /^[^\r\n<>]*$/, msg: 'smtp.from_name invalid' })
          .str('ca_file', { max: 300, re: /^\/[^\0]+$/, msg: 'smtp.ca_file must be an absolute path' }).bool('reject_unauthorized').done();
        o.smtp = v; return null; }).done();
    return N.configure(b, ctx.who);
  });
  srv.route('POST', '/pdpl/office/contacts', (ctx) => {
    ctx.need('operator');   // an administrator or the DPO - checked in setContacts
    const b = body(ctx.body).list('contacts', { max: 500, required: true }).rule((o) => ((o.contacts || []).some((c) => !c || !USER.test(String(c.user || '')) || !require('./smtp').isAddr(String(c.email || '')))
      ? 'each contact needs {user (user name), email (work e-mail address)}' : (o.contacts || []).some((c) => c.lang !== undefined && c.lang !== null && c.lang !== '' && !LANGS.includes(c.lang)) ? 'a contact\'s lang must be both, ar or en' : null)).done();
    const seen = new Set(), list = [];
    for (const c of b.contacts) { const k = low(c.user); if (!seen.has(k)) { seen.add(k); list.push(Object.assign({ user: c.user, email: String(c.email).trim() }, LANGS.includes(c.lang) ? { lang: c.lang } : {})); } }
    return N.setContacts(list, ctx.who, isDpo(ctx.who));
  });
  srv.route('POST', '/pdpl/office/notify/test', (ctx) => {
    ctx.need('admin');
    return N.test(body(ctx.body).oneOf('channel', ['email', 'teams'], { required: true }).str('to', { max: 80, re: USER, msg: 'to must be a user name in the contact list' }).done(), ctx.who);
  });
}

module.exports = { createNotifier, registerNotifyRoutes, postTeams, TEAMS_HOST, plain, composeMail, composeTeams, whyAr };
