// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test: each person chooses English or Arabic - on the sign-in page (login-skin/zyb-login.js) or in Customize - and the
// choice carries to every dashboard (zyb-dash-prefs) and the portal (noc_lang). The sign-in form itself is never changed by a
// language switch: the same form, fields, typed values and posted body. Nothing saved = English. Synthetic pages only.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node language-choice.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

// a stand-in for the portal page: its own Arabic switch (LANG / applyLang / the header button), as in its app.js
const PORTAL = '<!doctype html><html><head><meta charset="utf-8"><title>portal</title></head><body><header><button id="langToggle">عربي</button></header><main><h1 id="t">-</h1></main>'
  + '<script>let LANG = localStorage.getItem("noc_lang") || "en"; function applyLang(){ document.documentElement.dir = LANG === "ar" ? "rtl" : "ltr"; document.getElementById("t").textContent = LANG === "ar" ? "لوحة التحكم" : "Dashboard"; } applyLang();</script>'
  + '<script src="/dashboards/vendor/zyb-menu.js"></script></body></html>';
const SKIN = path.join(DASH, 'login-skin', 'zyb-login.js');
const LOGIN = '<!doctype html><html><head><title>Sign in</title><script src="/zyb-login/zyb-login.js"></script></head><body><div class="card"><h2>Sign in</h2><form method="POST" action="/login"><label>User</label><input name="user" autofocus><label>Password</label><input name="pass" type="password"><button type="submit">Sign in</button></form></div></body></html>';
const DASHPAGE = '<!doctype html><html><head><meta charset="utf-8"><title>Synthetic page</title><script src="vendor/zyb-dash.js"></script></head><body><main><h1>Assets</h1><p>Synthetic page for the language test.</p></main></body></html>';

(async () => {
  const posts = [];
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (req.method === 'POST') { let b = ''; req.on('data', (c) => { b += c; }); return req.on('end', () => { posts.push(b); res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<p id="done">posted</p>'); }); }
    if (u.pathname === '/login') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(LOGIN); }
    if (u.pathname === '/zyb-login/zyb-login.js') { res.writeHead(200, { 'Content-Type': 'application/javascript' }); return res.end(Buffer.concat([fs.readFileSync(path.join(DASH, 'vendor', 'zyb-org.js')), Buffer.from('\n'), fs.readFileSync(SKIN)])); }   // as installed: the brand setting built in
    if (u.pathname === '/portal') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(PORTAL); }
    if (u.pathname === '/dashboards/synthetic.html') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(DASHPAGE); }
    if (u.pathname.startsWith('/api/') || u.pathname === '/dashboards/whoami.json') { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{}'); }
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    // ---- the sign-in page: English by default, the choice saved for the whole platform
    let ctx = await browser.newContext(), p = await ctx.newPage(); p.on('pageerror', (e) => errs.push('login: ' + e.message));
    await p.goto(base + '/login'); await p.waitForSelector('html.zl-on');
    ok(await p.textContent('.zl-head h2') === 'Sign in' && await p.getAttribute('[data-zl-lang=en]', 'aria-pressed') === 'true', 'sign-in opens in English with English selected');
    ok(await p.isVisible('[data-zl-lang=ar]'), 'Arabic is offered on the sign-in page');
    await p.fill('input[name=user]', 'synthetic.user');
    await p.click('[data-zl-lang=ar]');
    const ar = await p.evaluate(() => ({ dir: document.documentElement.dir, h: document.querySelector('.zl-head h2').textContent, btn: document.querySelector('form button[type=submit]').textContent, forms: document.querySelectorAll('form').length, names: [...document.querySelectorAll('form input')].map((i) => i.name).join(','), user: document.querySelector('input[name=user]').value, prefs: localStorage.getItem('zyb-dash-prefs'), noc: localStorage.getItem('noc_lang'), side: document.querySelector('.zl-brand h1').textContent }));
    ok(ar.dir === 'rtl' && ar.h === 'تسجيل الدخول' && ar.btn === 'متابعة' && /[\u0600-\u06ff]/.test(ar.side), 'Arabic: right to left, heading, button and the platform name in Arabic: ' + JSON.stringify(ar));
    ok(ar.forms === 1 && ar.names === 'user,pass' && ar.user === 'synthetic.user', 'the same form, the same fields, the typed user name kept');
    ok(JSON.parse(ar.prefs).lang === 'ar' && ar.noc === 'ar', 'the choice is saved for the dashboards and the portal');
    await p.fill('input[name=pass]', 'Synthetic pass&1');
    await Promise.all([p.waitForSelector('#done'), p.click('form button[type=submit]')]);
    ok(posts[0] === 'user=synthetic.user&pass=Synthetic+pass%261', 'the posted body is unchanged by the language: ' + posts[0]);
    await p.goto(base + '/login'); await p.waitForSelector('html.zl-on');
    ok(await p.textContent('.zl-head h2') === 'تسجيل الدخول', 'the next visit remembers Arabic');
    await p.click('[data-zl-lang=en]'); ok(await p.textContent('.zl-head h2') === 'Sign in' && await p.evaluate(() => document.documentElement.dir) === 'ltr', 'back to English');
    // ---- after signing in: a dashboard in the chosen language, menu included, and Customize offers the language
    await p.click('[data-zl-lang=ar]');
    await p.goto(base + '/dashboards/synthetic.html'); await p.waitForTimeout(1500);
    const st = await p.evaluate(() => ({ dir: document.documentElement.getAttribute('dir'), lang: window.zybLang && window.zybLang.lang, menu: document.body.textContent.includes('مخاطر الأعمال'), sel: !!document.getElementById('zyb-de') }));
    ok(st.dir === 'rtl' && st.lang === 'ar', 'dashboard opens in Arabic, right to left: ' + JSON.stringify(st));
    ok(st.menu, 'the menu is in Arabic (Business Risk = مخاطر الأعمال)');
    ok(st.sel, 'Customize offers the language');
    await p.goto(base + '/portal'); await p.waitForTimeout(800);
    ok(await p.$eval('html', (h) => h.dir) === 'rtl' && await p.isVisible('#langToggle'), 'the portal opens in Arabic with its own button');
    await ctx.close();
    // ---- nothing saved: English
    ctx = await browser.newContext(); p = await ctx.newPage(); p.on('pageerror', (e) => errs.push('dashboard: ' + e.message));
    await p.goto(base + '/dashboards/synthetic.html?standalone=1'); await p.waitForTimeout(1200);
    ok(await p.evaluate(() => (document.documentElement.getAttribute('dir') || 'ltr') === 'ltr' && window.zybLang.lang === 'en' && !/[\u0600-\u06ff]/.test(document.querySelector('main').textContent)), 'nothing saved: English, left to right');
    await ctx.close();
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
