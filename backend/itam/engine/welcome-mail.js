// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Welcome kit ({P} = /api/itam; User Management -> Create account / a person's panel): the e-mail a new user receives when an
 * administrator creates their platform account - the sign-in link, their user name, their role and job role, and what to do at
 * the first sign-in (two-step verification, change the password, where to get help, how to recognise a fake). Sent through the
 * platform's one e-mail relay (the SIEM Reports relay, POST /reports/deliver as system:itam-notify), like every other e-mail.
 * NEVER the password: the initial password is handed over by the administrator separately, and the e-mail says so - an e-mail
 * that carried both would let anyone who reads the mailbox sign in.
 * In Arabic and English (one e-mail, Arabic first, right-to-left) by default; the settings or a send can choose one language.
 *   GET  /welcome/settings        admin   the link, the help contact, the extra note, the language, the last 50 sends (user names only)
 *   POST /welcome/settings        admin   {portal_url?, help_contact?, note?, language?: both|ar|en}                                   audited
 *   POST /welcome/preview         admin   {user, name?, role?, job?}  -> {subject, text, html}  (nothing sent)
 *   POST /welcome/send            admin   {user, email, name?, role?, job?, lang?}   a person only                     audited
 * The audit and the send log keep the user name and the recipient's domain - not the address (PDPL: personal data only as needed).
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DEFAULT_URL = ('https://' + ZYB_ORG.portal_host);
const PRODUCT = 'Zyberon Sentra', PLATFORM = (ZYB_ORG.short + ' IT Operations & Monitoring Platform');
const USER = /^[A-Za-z0-9._@-]{2,100}$/;
const ADDR = /^[^\s@<>"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/;
const LANGS = ['both', 'ar', 'en'];
// the texts, Arabic and English; {url} and {user} are filled in, every value is escaped in the HTML
const TXT = {
  en: {
    platform: PLATFORM, dear: (w) => 'Dear ' + w + ',', intro: 'Welcome to ' + PRODUCT + ', the ' + PLATFORM + '. An account has been created for you.',
    link: 'Sign-in link', user: 'User name', role: 'Role', job: 'Job role', button: 'Sign in to ' + PRODUCT,
    roles: {
      viewer: 'viewer - you can read the dashboards and reports; you cannot change anything',
      operator: 'operator - you can work on incidents, tickets and tasks and request changes; a second person approves changes to systems',
      admin: 'administrator - you manage users and settings; every change to a system is still approved by a second administrator' },
    first: 'Your first sign-in', safe: 'Keep your account safe',
    steps: [
      ['Open the platform', 'Go to {url} (save it as a bookmark; always type it or use the bookmark - never a link from an unexpected e-mail).'],
      ['Sign in', 'User name: {user}. Your initial password is given to you by your administrator in person or by phone - it is never sent by e-mail.'],
      ['Set up two-step verification', 'At the first sign-in, scan the code with an authenticator app (Microsoft Authenticator or Google Authenticator) and enter the 6-digit code. You will need it at every sign-in.'],
      ['Choose your own password', 'Change the initial password when asked: at least 12 characters, not used anywhere else.'],
      ['Find your way', 'The menu on the left shows only the pages your role allows. Your home page opens with what needs you today.']],
    // an account that signs in with Active Directory: the person's own Windows user name and password, no platform password
    stepsAd: [
      ['Open the platform', 'Go to {url} (save it as a bookmark; always type it or use the bookmark - never a link from an unexpected e-mail).'],
      ['Sign in with your Windows account', 'User name: {user} (the one you use to sign in to your Windows computer) and your usual Windows password. There is no separate password for the platform.'],
      ['Set up two-step verification', 'At the first sign-in, scan the code with an authenticator app (Microsoft Authenticator or Google Authenticator) and enter the 6-digit code. You will need it at every sign-in.'],
      ['Changing your password', 'Change it the usual way on a company computer (Ctrl+Alt+Del, Change a password). The platform follows your Windows password.'],
      ['Find your way', 'The menu on the left shows only the pages your role allows. Your home page opens with what needs you today.']],
    rules: [
      'Never share your password or your verification codes - IT will never ask for them.',
      'Sign out on shared computers. Report a lost phone at once, so your two-step verification can be reset.',
      'What you see on the platform is company and customer data: keep it inside the company (PDPL).'],
    help: 'Questions or problems signing in:', helpNone: 'contact your platform administrator.',
    foot: 'This message was sent because an administrator created your account. It contains no password.',
    subject: 'Welcome to ' + PRODUCT + ' - your account'
  },
  ar: {
    platform: ('منصة ' + ZYB_ORG.short_ar + ' لعمليات تقنية المعلومات والمراقبة'), dear: (w) => 'عزيزي/عزيزتي ' + w + '،', intro: 'مرحباً بك في ' + PRODUCT + ('، منصة ' + ZYB_ORG.short_ar + ' لعمليات تقنية المعلومات والمراقبة. تم إنشاء حساب لك.'),
    link: 'رابط تسجيل الدخول', user: 'اسم المستخدم', role: 'الصلاحية', job: 'الدور الوظيفي', button: 'تسجيل الدخول إلى ' + PRODUCT,
    roles: {
      viewer: 'مشاهد - يمكنك الاطلاع على لوحات المتابعة والتقارير، ولا يمكنك تغيير أي شيء',
      operator: 'مشغّل - يمكنك العمل على الحوادث والتذاكر والمهام وطلب التغييرات، ويعتمد شخص آخر أي تغيير على الأنظمة',
      admin: 'مسؤول - تدير المستخدمين والإعدادات، ويعتمد مسؤول آخر كل تغيير على الأنظمة' },
    first: 'تسجيل دخولك الأول', safe: 'حافظ على أمان حسابك',
    steps: [
      ['افتح المنصة', 'انتقل إلى {url} (احفظه في المفضلة، واكتبه بنفسك أو استخدم المفضلة دائماً - ولا تستخدم رابطاً من رسالة غير متوقعة).'],
      ['سجّل الدخول', 'اسم المستخدم: {user}. يسلّمك المسؤول كلمة المرور الأولية شخصياً أو عبر الهاتف - ولا تُرسل أبداً بالبريد الإلكتروني.'],
      ['فعّل التحقق بخطوتين', 'عند أول تسجيل دخول، امسح الرمز بتطبيق مصادقة مثل تطبيق Microsoft Authenticator أو تطبيق Google Authenticator، ثم أدخل الرمز المكوّن من 6 أرقام. ستحتاجه في كل تسجيل دخول.'],
      ['اختر كلمة مرور خاصة بك', 'غيّر كلمة المرور الأولية عند الطلب: 12 حرفاً على الأقل، ولا تستخدمها في أي مكان آخر.'],
      ['تعرّف على المنصة', 'تعرض القائمة الجانبية الصفحات التي تسمح بها صلاحيتك فقط، وتفتح صفحتك الرئيسية على ما يحتاج إلى متابعتك اليوم.']],
    stepsAd: [
      ['افتح المنصة', 'انتقل إلى {url} (احفظه في المفضلة، واكتبه بنفسك أو استخدم المفضلة دائماً - ولا تستخدم رابطاً من رسالة غير متوقعة).'],
      ['سجّل الدخول بحساب Windows', 'اسم المستخدم: {user} (الذي تسجّل به الدخول إلى جهازك) وكلمة مرور Windows المعتادة. لا توجد كلمة مرور منفصلة للمنصة.'],
      ['فعّل التحقق بخطوتين', 'عند أول تسجيل دخول، امسح الرمز بتطبيق مصادقة مثل تطبيق Microsoft Authenticator أو تطبيق Google Authenticator، ثم أدخل الرمز المكوّن من 6 أرقام. ستحتاج إليه في كل تسجيل دخول.'],
      ['تغيير كلمة المرور', 'غيّرها بالطريقة المعتادة على جهاز الشركة (Ctrl+Alt+Del ثم تغيير كلمة المرور). تتبع المنصة كلمة مرور Windows الخاصة بك.'],
      ['تعرّف على المنصة', 'تعرض القائمة الجانبية الصفحات التي تسمح بها صلاحيتك فقط، وتفتح صفحتك الرئيسية على ما يحتاج إلى متابعتك اليوم.']],
    rules: [
      'لا تشارك كلمة المرور أو رموز التحقق مع أحد - لن يطلبها منك فريق تقنية المعلومات أبداً.',
      'سجّل الخروج على الأجهزة المشتركة، وأبلغ فوراً عن فقدان هاتفك لإعادة تعيين التحقق بخطوتين.',
      'ما تراه على المنصة بيانات للشركة وعملائها: احتفظ بها داخل الشركة (نظام حماية البيانات الشخصية).'],
    help: 'للاستفسار أو عند مواجهة مشكلة في تسجيل الدخول:', helpNone: 'تواصل مع مسؤول المنصة.',
    foot: 'أُرسلت هذه الرسالة لأن مسؤولاً أنشأ حسابك. لا تحتوي على أي كلمة مرور.',
    subject: 'مرحباً بك في ' + PRODUCT + ' - حسابك'
  }
};
const escH = (s) => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const flat = (s) => String(s === undefined || s === null ? '' : s).replace(/[\r\n\t\0]+/g, ' ').trim();
const fill = (s, v) => s.replace('{url}', v.url).replace('{user}', v.user);

function compose(set, p) {
  const url = set.portal_url || DEFAULT_URL, who = flat(p.name) || p.user, job = flat(p.job), v = { url, user: p.user };
  const help = flat(set.help_contact), note = flat(set.note), G = '#0e7c4a';
  const lang = LANGS.includes(p.lang) ? p.lang : (LANGS.includes(set.language) ? set.language : 'both');
  const order = lang === 'both' ? ['ar', 'en'] : [lang];
  const textOf = (l) => { const X = TXT[l], role = X.roles[p.role] || X.roles.viewer;
    return [X.dear(who), '', X.intro, '', X.link + ': ' + url, X.user + ': ' + p.user, X.role + ': ' + role + (job ? '\n' + X.job + ': ' + job : ''), '',
      X.first, ...(p.signin === 'ad' ? X.stepsAd : X.steps).map((s, i) => (i + 1) + '. ' + s[0] + ': ' + fill(s[1], v)), '', X.safe, ...X.rules.map((r) => '- ' + r), '',
      ...(note ? [note, ''] : []), X.help + ' ' + (help || X.helpNone), '', PRODUCT + ' - ' + X.platform, X.foot].join('\n'); };
  const htmlOf = (l) => { const X = TXT[l], role = X.roles[p.role] || X.roles.viewer, rtl = l === 'ar', side = rtl ? 'right' : 'left';
    const lab = 'padding:10px 14px;color:#5a6b63;width:120px;text-align:' + side, val = 'padding:10px 14px;text-align:' + side, top = ';border-top:1px solid #e3ebe7';
    return '<div dir="' + (rtl ? 'rtl' : 'ltr') + '" lang="' + l + '" style="text-align:' + side + ';font-family:' + (rtl ? 'Tahoma,Arial' : 'Segoe UI,Arial') + ',sans-serif">'
      + '<p style="margin:0 0 12px;font-size:15px">' + escH(X.dear(who)) + '</p><p style="margin:0 0 18px;font-size:14px;line-height:1.6">' + escH(X.intro) + '</p>'
      + '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;font-size:14px;border:1px solid #e3ebe7;border-radius:8px;background:#f8fbf9">'
      + '<tr><td style="' + lab + '">' + escH(X.user) + '</td><td style="' + val + ';font-family:Consolas,monospace;font-weight:600" dir="ltr">' + escH(p.user) + '</td></tr>'
      + '<tr><td style="' + lab + top + '">' + escH(X.role) + '</td><td style="' + val + top + '">' + escH(role) + '</td></tr>'
      + (job ? '<tr><td style="' + lab + top + '">' + escH(X.job) + '</td><td style="' + val + top + '">' + escH(job) + '</td></tr>' : '') + '</table>'
      + '<p style="text-align:center;margin:22px 0"><a href="' + escH(url) + '" style="display:inline-block;background:' + G + ';color:#fff;text-decoration:none;font-weight:600;padding:12px 28px;border-radius:7px">' + escH(X.button) + '</a><br>'
      + '<span style="font-size:12px;color:#5a6b63" dir="ltr">' + escH(url) + '</span></p>'
      + '<h3 style="font-size:15px;margin:18px 0 8px;color:' + G + '">' + escH(X.first) + '</h3><ol style="margin:0;padding-' + side + ':20px;font-size:14px;line-height:1.6">'
      + (p.signin === 'ad' ? X.stepsAd : X.steps).map((s) => '<li style="margin-bottom:6px"><b>' + escH(s[0]) + '.</b> ' + escH(fill(s[1], v)) + '</li>').join('') + '</ol>'
      + '<h3 style="font-size:15px;margin:18px 0 8px;color:' + G + '">' + escH(X.safe) + '</h3><ul style="margin:0;padding-' + side + ':20px;font-size:14px;line-height:1.6">'
      + X.rules.map((r) => '<li style="margin-bottom:4px">' + escH(r) + '</li>').join('') + '</ul>'
      + (note ? '<p style="margin:16px 0 0;font-size:14px;line-height:1.6">' + escH(note) + '</p>' : '')
      + '<p style="margin:18px 0 0;font-size:14px">' + escH(X.help) + ' ' + escH(help || X.helpNone) + '</p>'
      + '<p style="margin:16px 0 0;font-size:11px;color:#6b7b74">' + escH(X.foot) + '</p></div>'; };
  const subject = order.map((l) => TXT[l].subject).join(' | ');
  const text = order.map(textOf).join('\n\n----------------------------------------\n\n') + '\n';
  const html = '<!doctype html><html><head><meta charset="utf-8"></head><body style="margin:0;background:#f3f5f4;color:#1d2a24">'
    + '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f5f4;padding:24px 0"><tr><td align="center">'
    + '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#fff;border:1px solid #dfe6e2;border-radius:10px;overflow:hidden">'
    + '<tr><td style="background:' + G + (';color:#fff;padding:22px 28px;font-family:Segoe UI,Tahoma,Arial,sans-serif"><div style="font-size:12px;letter-spacing:.12em;opacity:.85">' + ZYB_ORG.upper + ' · ' + ZYB_ORG.short_ar + '</div>')
    + '<div style="font-size:22px;font-weight:700;letter-spacing:.04em;margin-top:4px">ZYBERON SENTRA</div>'
    + '<div style="font-size:13px;opacity:.9;margin-top:2px">' + order.map((l) => escH(TXT[l].platform)).join(' · ') + '</div></td></tr>'
    + order.map((l) => '<tr><td style="padding:24px 28px">' + htmlOf(l) + '</td></tr>').join('<tr><td style="padding:0 28px"><hr style="border:0;border-top:1px solid #e3ebe7;margin:0"></td></tr>')
    + '<tr><td style="padding:14px 28px;background:#f8fbf9;border-top:1px solid #e3ebe7;font-size:11px;color:#6b7b74;font-family:Segoe UI,Tahoma,Arial,sans-serif">' + PRODUCT + (' - ' + ZYB_ORG.short + '</td></tr>')
    + '</table></td></tr></table></body></html>';
  return { subject, text, html, lang };
}

function createWelcomeMail(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const setC = () => store.collection('welcome_mail_settings'), logC = () => store.collection('welcome_mail_log');
  const settings = () => Object.assign({ portal_url: DEFAULT_URL, help_contact: '', note: '', language: 'both' }, setC().get('cfg') || {});
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  async function relay(b) {
    if (opts.siem) return opts.siem('POST', '/reports/deliver', b, 'system:itam-notify');
    const s = app.discovery && app.discovery.siem;
    if (!s || typeof s.call !== 'function' || (s.configured && !s.configured())) return { ok: false, error: 'the SIEM link is not configured, so the platform e-mail relay cannot be reached' };
    try {
      const r = await s.call('POST', '/reports/deliver', { user: 'system:itam-notify', role: 'admin' }, b);
      return r && r.status === 200 ? { ok: true } : { ok: false, error: (r && r.json && r.json.error) || 'the e-mail relay answered HTTP ' + (r && r.status) };
    } catch (e) { return { ok: false, error: String(e.message || 'the e-mail relay is not reachable') }; }
  }
  const person = (b0) => body(b0 || {}).str('user', { required: true, max: 100, re: USER, msg: 'user must be a user name: letters, digits and . _ @ - (2-100)' })
    .str('name', { max: 200 }).oneOf('role', ['viewer', 'operator', 'admin']).str('job', { max: 120 }).oneOf('lang', LANGS).oneOf('signin', ['ad', 'local']);

  function view(who) {
    if (who.role !== 'admin') throw httpErr(403, 'the welcome e-mail settings are for administrators');
    const s = settings();
    return { portal_url: s.portal_url, help_contact: s.help_contact, note: s.note, language: s.language, updated_by: s.updated_by || null, updated_at: s.updated_at || null,
      sent: logC().all().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 50).map((x) => ({ user: x.user, domain: x.domain, at: x.at, by: x.by, ok: x.ok, error: x.error || null })) };
  }
  function configure(b0, who) {
    if (who.role !== 'admin') throw httpErr(403, 'the welcome e-mail settings are for administrators');
    const b = body(b0 || {}).str('portal_url', { max: 300 }).str('help_contact', { max: 200 }).str('note', { max: 1000 }).oneOf('language', LANGS).done();
    if (b.portal_url !== undefined) {
      let u; try { u = new URL(b.portal_url); } catch (e) { throw httpErr(400, 'portal_url must be the sign-in address, e.g. ' + DEFAULT_URL); }
      if (u.protocol !== 'https:' || u.username || u.password) throw httpErr(400, 'portal_url must be an https address with no user name or password in it');
      b.portal_url = u.origin + u.pathname.replace(/\/+$/, '');
    }
    const prev = settings(), next = Object.assign({}, prev, b, { id: 'cfg', updated_by: who.user, updated_at: new Date(now()).toISOString() });
    setC().put(next);
    audit(who, 'welcome.settings', 'welcome-mail', { changed: Object.keys(b).filter((k) => b[k] !== prev[k]) });
    return view(who);
  }
  function preview(b0, who) {
    if (who.role !== 'admin') throw httpErr(403, 'the welcome e-mail is sent by an administrator');
    return compose(settings(), person(b0).done());
  }
  async function send(b0, who) {
    if (who.role !== 'admin') throw httpErr(403, 'the welcome e-mail is sent by an administrator');
    if (!isHuman(who.user)) throw httpErr(403, 'a person sends the welcome e-mail, not a service or AI identity');
    const b = person(b0).str('email', { required: true, max: 254 }).done();
    const to = b.email.trim().toLowerCase();
    if (!ADDR.test(to)) throw httpErr(400, 'email must be an e-mail address');
    const m = compose(settings(), b), at = new Date(now()).toISOString(), domain = to.split('@')[1];
    const id = ('welcome-' + b.user.replace(/[^A-Za-z0-9_.-]/g, '_') + '-' + now()).slice(0, 80);
    const r = await relay({ id, subject: m.subject, text: m.text, html: m.html, recipients: [to] });
    logC().put({ id, user: b.user, domain, at, by: who.user, ok: !!r.ok, error: r.ok ? null : String(r.error || '').slice(0, 300) });
    audit(who, 'welcome.send', b.user, { domain, ok: !!r.ok, role: b.role || null, job: b.job || null, lang: m.lang });
    if (!r.ok) {
      if (app.log && app.log.every) app.log.every('welcome-mail:fail', 600000, 'warn', 'welcome e-mail not sent', { user: b.user, error: String(r.error || '').slice(0, 200) });
      throw httpErr(424, 'The account is fine, but the welcome e-mail was not sent: ' + String(r.error || 'error').slice(0, 300) + '. Check the e-mail relay in Reporting Center -> Delivery, then send it again from the person\'s panel.');
    }
    return { ok: true, user: b.user, sent_to_domain: domain, lang: m.lang, at };
  }
  return { view, configure, preview, send, compose: (p) => compose(settings(), p) };
}

function registerWelcomeMail(srv, app, X) {
  srv.route('GET', '/welcome/settings', (ctx) => { ctx.need('admin'); return X.view(ctx.who); });
  srv.route('POST', '/welcome/settings', (ctx) => { ctx.need('admin'); return X.configure(ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('POST', '/welcome/preview', (ctx) => { ctx.need('admin'); return X.preview(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/welcome/send', (ctx) => { ctx.need('admin'); return X.send(ctx.body, ctx.who); }, { maxBody: 4096 });
}

module.exports = { createWelcomeMail, registerWelcomeMail, compose, DEFAULT_URL };
