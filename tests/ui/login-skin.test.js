// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Browser test for the sign-in skin (dashboards/server/login-skin/zyb-login.js) on the sign-in service's real page
// (_login-preview/index.html, a copy of what /login sends) with the <script> line nginx adds: the new layout is drawn, the
// service's own form is kept (same action, method, field names, values reach the server unchanged), the policy chips
// and logo boxes are hidden, the service's error message is kept, the code step and an enrolment page (QR code) are
// handled, and a page with no form - or a skin that fails - shows the original page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node login-skin.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), SKIN = path.join(ROOT, 'ui/login-skin/zyb-login.js');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const TAG = '<script src="/zyb-login/zyb-login.js"></script>';
const inject = (html) => html.replace('</head>', TAG + '</head>');   // what nginx sub_filter does
const LIVE = fs.readFileSync(path.join(ROOT, 'tests/ui/fixtures/login-page.html'), 'utf8');
const PAGES = {
  '/login': inject(LIVE),
  '/login-err': inject(LIVE.replace('<label>Username</label>', '<div class="err">Wrong username or password.</div><label>Username</label>')),
  '/login/otp': inject(('<!doctype html><html><head><title>Code</title></head><body><div class="card"><img src="/logo.webp" alt="' + ZYB_ORG.short + '"><h2>Enter code</h2><form method="POST" action="/login/otp"><input type="hidden" name="t" value="abc123"><label>Code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><button type="submit">Verify</button></form></div></body></html>')),
  '/login/enrol': inject('<!doctype html><html><head><title>Enrol</title></head><body><form method="POST" action="/login/enrol"><h2>Set up your authenticator</h2><p>Scan this QR code with your authenticator app.</p><img id="qr" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt="QR code" width="160" height="160"><label>Code</label><input name="code" autocomplete="off"><button>Confirm</button></form></body></html>'),
  '/login-ad': inject(LIVE.replace('<label>Username</label>', '<a class="btn sso" href="/auth/sso/start"><svg width="18" height="18"></svg> Sign in with Microsoft Entra ID</a><div class="or">or use a local account</div><div class="sub" style="margin:-10px 0 12px;color:#9BC257;font-weight:600">Sign in with your CORP-HQ account</div><label>Username</label>').replace('<input name="user" autocomplete="username" autofocus>', ('<input name="user" autocomplete="username" placeholder="CORP\\username or username@' + 'corp-hq.com' + '">'))),
  '/noform': inject('<!doctype html><html><head><title>Locked</title></head><body><h1 id="orig">Your account is locked</h1></body></html>'),
  '/broken': '<!doctype html><html><head><script src="/zyb-login/broken.js"></script></head><body><form method="POST" action="/login"><input name="user"><input name="pass" type="password"><button>Sign in</button></form></body></html>'
};
(async () => {
  const posts = [];
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    if (req.method === 'POST') { let b = ''; req.on('data', (c) => { b += c; }); return req.on('end', () => { posts.push({ u, b }); res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<p id="done">posted</p>'); }); }
    if (u === '/zyb-login/zyb-login.js') { res.writeHead(200, { 'Content-Type': 'application/javascript' }); return res.end(Buffer.concat([fs.readFileSync(path.join(ROOT, 'ui/vendor/zyb-org.js')), Buffer.from('\n'), fs.readFileSync(SKIN)])); }   // as installed: the brand setting built in
    if (u === '/zyb-login/broken.js') { res.writeHead(200, { 'Content-Type': 'application/javascript' }); return res.end(fs.readFileSync(path.join(ROOT, 'ui/vendor/zyb-org.js'), 'utf8') + '\n' + fs.readFileSync(SKIN, 'utf8').replace("var form = document.querySelector('form');", "var form = document.querySelector('form'); throw new Error('x');")); }
    if (PAGES[u]) { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(PAGES[u]); }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } }); page.on('pageerror', (e) => errs.push(e.message));
  const vis = (sel) => page.evaluate((s) => { const e = document.querySelector(s); return !!e && !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length) && getComputedStyle(e).visibility !== 'hidden'; }, sel);

  // ---- the password step on the real page
  await page.goto(base + '/login'); await page.waitForSelector('html.zl-on');
  ok(await page.evaluate(() => !!document.querySelector('.zl .zl-card form')), 'the service form is inside the new card');
  const f = await page.evaluate(() => { const fm = document.querySelector('form'); return { action: fm.getAttribute('action'), method: fm.getAttribute('method'), names: [...fm.querySelectorAll('input')].map((i) => i.name), forms: document.querySelectorAll('form').length }; });
  ok(f.action === '/login' && /post/i.test(f.method) && f.names.join(',') === 'user,pass' && f.forms === 1, 'same form contract (POST /login, user + pass, one form): ' + JSON.stringify(f));
  ok(await page.textContent('.zl-head h2') === 'Sign in' && await vis('.zl-note'), 'heading Sign in and the two-step note');
  ok(!(await vis('.badges')) && !(await vis('.zyb-coab')) && !(await vis('#rdr')) && !(await vis('.hero')), 'policy chips, logo boxes and animated background hidden');
  ok(/^data:image\/(webp|png|jpeg|svg\+xml)/.test(await page.getAttribute('.zl-logo', 'src')) && /^data:image\/webp/.test(await page.getAttribute('.zl-foot img', 'src')), 'real logos inline (no login needed to load them)');
  ok((await page.textContent('.zl-brand h1')) === 'IT Operations & Cyber Security Automation and Monitoring Platform' && (await page.textContent('.zl-wm b')) === 'ZYBERON SENTRA' && await vis('.zl-brand .zl-mark'), 'brand: the Zyberon Sentra mark, word mark and platform name');
  const geo = await page.evaluate(() => { const c = document.querySelector('.zl-card').getBoundingClientRect(), b = document.querySelector('.zl-mark').getBoundingClientRect(); const h = document.querySelector('.zl-hero').getBoundingClientRect(); return { card: Math.round(c.left + c.width / 2), mark: b.right < c.left, hero: h.right <= c.left, fits: document.documentElement.scrollHeight <= innerHeight, vw: innerWidth, bg: !!document.querySelector('.zl-bg .zl-rings') && !!document.querySelector('.zl-bg .zl-floor') }; });
  ok(geo.hero && geo.mark && geo.bg && geo.card > geo.vw / 2, 'wide screen: the brand panel beside the sign-in card, animated background: ' + JSON.stringify(geo));
  ok(geo.fits, 'wide screen: everything on one screen, no scrolling');
  const rows = await page.evaluate(() => { const r = (s) => document.querySelector(s).getBoundingClientRect(); const t = r('.zl-top'), m = r('.zl-shell'), e = r('.zl-end'), c = r('.zl-card'), h = r('.zl-hero'); return { order: t.bottom <= m.top + 1 && m.bottom <= e.top + 1, brandInTop: !!document.querySelector('.zl-top .zl-brand .zl-mark') && !!document.querySelector('.zl-top .zl-pill'), footInEnd: !!document.querySelector('.zl-end .zl-trust') && !!document.querySelector('.zl-end .zl-clock') && !!document.querySelector('.zl-end .zl-foot'), centred: Math.abs((c.top + c.bottom) / 2 - (h.top + h.bottom) / 2) < 60 }; });
  ok(rows.order && rows.brandInTop && rows.footInEnd && rows.centred, 'three rows: top bar (brand, authorised-users pill), the message beside the card on one centre line, bottom bar (clock, trust, powered by): ' + JSON.stringify(rows));
  ok(!(await page.$('.zl-side')) && !(await page.$('.zl-mark rect')), 'no old side panel; the mark is a hexagon, not blocks');
  ok(/One platform for IT operations, security and compliance\./.test(await page.textContent('.zl-pitch')) && (await page.$$eval('.zl-caps li', (l) => l.length)) === 4, 'headline and the four things the platform does');
  ok((await page.$$eval('.zl-steps li', (l) => l.map((x) => x.className + ':' + x.textContent.replace(/^\d/, '')))).join('|') === 'on:Password|:Verification code', 'step indicator: 1 of 2 on the password step');
  ok(await page.evaluate(() => { const u = document.querySelector('input[name=user]'), q = document.querySelector('input[name=pass]'); return /svg/.test(getComputedStyle(u).backgroundImage) && /svg/.test(getComputedStyle(q).backgroundImage) && u.name === 'user' && q.name === 'pass' && q.type === 'password'; }), 'field icons drawn; the fields themselves unchanged');
  const trust = await page.textContent('.zl-trust'); ok(/Two-step verification/.test(trust) && /Sign-ins are recorded/.test(trust) && !/Encrypted connection/.test(trust), 'trust line; "Encrypted connection" is NOT claimed on plain http');
  ok(/^Riyadh time \d\d:\d\d · \w+ \d+ \w+$/.test((await page.textContent('.zl-clock')).trim()), 'Riyadh clock: ' + await page.textContent('.zl-clock'));
  await page.focus('input[name=pass]'); await page.evaluate(() => { const q = document.querySelector('input[name=pass]'); const e = new KeyboardEvent('keyup', { key: 'A', bubbles: true }); Object.defineProperty(e, 'getModifierState', { value: (k) => k === 'CapsLock' }); q.dispatchEvent(e); });
  ok(await vis('.zl-capsw') && /Caps Lock is on/.test(await page.textContent('.zl-capsw')), 'Caps Lock warning');
  await page.evaluate(() => { const q = document.querySelector('input[name=pass]'); const e = new KeyboardEvent('keyup', { key: 'a', bubbles: true }); Object.defineProperty(e, 'getModifierState', { value: () => false }); q.dispatchEvent(e); }); ok(!(await vis('.zl-capsw')), 'warning goes when Caps Lock is off');
  ok((await page.$$eval('.zl-chips b', (b) => b.map((x) => x.textContent))).join(',') === 'SAMA CSF,NCA ECC,PDPL,NDMO,Audit', 'framework badges');
  ok(/^Sign in — Zyberon Sentra · IT Operations & Cyber Security Automation and Monitoring Platform$/.test(await page.title()), 'page title: ' + await page.title());
  ok(await page.evaluate(() => getComputedStyle(document.querySelector('.zl form button[type=submit], .zl form button:not(.zl-eye)')).backgroundColor) === 'rgb(1, 87, 155)', ('default design: the ' + ZYB_ORG.short + ' colour'));
  await page.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ brand: 'as' }))); await page.reload(); await page.waitForSelector('.zl-card');
  ok(await page.evaluate(() => getComputedStyle(document.querySelector('.zl form button[type=submit], .zl form button:not(.zl-eye)')).backgroundColor) === 'rgb(1, 87, 155)' && /01579B/i.test(await page.evaluate(() => document.querySelector('.zl-mark').outerHTML)), (ZYB_ORG.short + ' colours chosen on the main page: the sign-in page follows (button and mark in the company colour)'));
  await page.evaluate(() => localStorage.removeItem('zyb-dash-prefs')); await page.reload(); await page.waitForSelector('.zl-card');
  ok(await page.evaluate(() => document.activeElement && document.activeElement.name) === 'user', 'username field focused');
  await page.fill('input[name=user]', 'syed'); await page.fill('input[name=pass]', 'S3cret pass&x');
  await page.click('.zl-eye');
  ok(await page.getAttribute('input[name=pass]', 'type') === 'text' && await page.getAttribute('.zl-eye', 'aria-label') === 'Hide password', 'show password works');
  await page.click('.zl-eye');
  ok(await page.getAttribute('input[name=pass]', 'type') === 'password', 'hide password again');
  ok(/Continue/.test(await page.textContent('form button[type=submit]')), 'submit reads Continue');
  await Promise.all([page.waitForSelector('#done'), page.click('form button[type=submit]')]);
  const p = posts.pop();
  ok(p && p.u === '/login' && p.b === 'user=syed&pass=S3cret+pass%26x', 'the server receives exactly user + pass: ' + JSON.stringify(p));
  await page.goto(base + '/login'); await page.waitForSelector('html.zl-on'); await page.fill('input[name=user]', 'a'); await page.fill('input[name=pass]', 'b');
  await Promise.all([page.waitForSelector('#done'), page.press('input[name=pass]', 'Enter')]);
  ok(posts.pop().b === 'user=a&pass=b', 'Enter in the password field submits');

  // ---- wrong password: the service's own message is kept and shown
  await page.goto(base + '/login-err'); await page.waitForSelector('html.zl-on');
  ok(await vis('.zl-msgs .err') && /Wrong username or password/.test(await page.textContent('.zl-msgs')) && await page.evaluate(() => document.querySelector('.zl-msgs .err').classList.contains('zl-bad')), 'error message kept, styled as an error, above the form');

  // ---- the code step
  await page.goto(base + '/login/otp'); await page.waitForSelector('html.zl-on');
  ok(await page.textContent('.zl-head h2') === 'Two-step verification' && await page.evaluate(() => document.querySelector('input[name=code]').classList.contains('zl-code')), 'code step: heading and large code field');
  ok(/Verify and sign in/.test(await page.textContent('form button')) && !(await vis('.zl-note')), 'code step button; no password note');
  ok((await page.$$eval('.zl-steps li', (l) => l.map((x) => x.className))).join('|') === 'done|on', 'code step: step 1 done, step 2 current');
  await page.fill('input[name=code]', '123456');
  await Promise.all([page.waitForSelector('#done'), page.click('form button')]);
  const q = posts.pop();
  ok(q.u === '/login/otp' && q.b === 't=abc123&code=123456', 'code step posts the hidden field and the code unchanged: ' + JSON.stringify(q));

  // ---- an enrolment page: its own heading, text and the QR code stay
  await page.goto(base + '/login/enrol'); await page.waitForSelector('html.zl-on');
  ok(await vis('#qr') && /Scan this QR code/.test(await page.textContent('form')) && await vis('form h2'), 'enrolment: QR code, instructions and its own heading kept');
  ok(await page.textContent('.zl-head h2') === 'Account security', 'enrolment: neutral heading');

  // ---- no form: the page as the service drew it
  await page.goto(base + '/noform'); await page.waitForTimeout(400);
  ok(await vis('#orig') && !(await page.$('.zl')), 'no form: original page shown, nothing built');

  // ---- the skin fails: the original form is shown and still works
  await page.goto(base + '/broken'); await page.waitForTimeout(500);
  ok(await vis('input[name=user]') && await page.evaluate(() => !document.documentElement.classList.contains('zl-pre')), 'skin error: original page visible');

  // ---- AD sign-in, in Arabic and back: the service's own words follow the language, the form does not change (pageerror-free)
  await page.goto(base + '/login-ad'); await page.waitForSelector('html.zl-on');
  ok(/Sign in with your CORP-HQ account/.test(await page.textContent('.zl-head p')), 'AD: the domain hint is the card\'s sub-heading (it was hidden as decoration)');
  await page.click('[data-zl-lang="ar"]'); await page.waitForSelector('html.zl-rtl');
  const ad = await page.evaluate(() => ({ labels: [...document.querySelectorAll('.zl form label')].map((l) => l.textContent.trim()), hint: document.querySelector('.zl-head p').textContent, sso: document.querySelector('.zl a.sso').textContent.trim(), or: document.querySelector('.zl .or').textContent.trim(), dir: document.querySelector('input[name=user]').getAttribute('dir'), pdir: document.querySelector('input[name=pass]').getAttribute('dir'), name: document.querySelector('input[name=user]').name, action: document.querySelector('.zl form').getAttribute('action') }));
  ok(JSON.stringify(ad.labels) === JSON.stringify(['\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645', '\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631']), 'AD in Arabic: Username / Password labels: ' + ad.labels);
  ok(/CORP-HQ/.test(ad.hint) && !/Sign in with your/.test(ad.hint), 'AD in Arabic: the hint is Arabic and keeps the domain: ' + ad.hint);
  ok(/Microsoft Entra ID/.test(ad.sso) && !/^Sign in with/.test(ad.sso) && !/use a local account/.test(ad.or), 'AD in Arabic: the single sign-on link and its "or" line: ' + ad.sso + ' / ' + ad.or);
  ok(ad.dir === 'ltr' && ad.pdir === 'ltr' && ad.name === 'user' && ad.action === '/login', 'AD in Arabic: the account fields stay left-to-right; same field names and action');
  await page.click('[data-zl-lang="en"]'); await page.waitForFunction(() => !document.documentElement.classList.contains('zl-rtl'));
  ok(JSON.stringify(await page.evaluate(() => [...document.querySelectorAll('.zl form label')].map((l) => l.textContent.trim()))) === '["Username","Password"]' && /Sign in with Microsoft Entra ID/.test(await page.textContent('.zl a.sso')), 'back to English: the original words return');
  await page.fill('input[name=user]', 'CORP\\rita.syn'); await page.fill('input[name=pass]', 'synthetic'); await page.click('.zl form button[type=submit]'); await page.waitForSelector('#done');
  ok(posts.some((x) => x.u === '/login' && /user=CORP%5Crita\.syn/.test(x.b) && /pass=synthetic/.test(x.b)), 'AD: the sign-in posts the same fields to the service');
  await page.evaluate(() => localStorage.removeItem('zyb-dash-prefs'));

  // ---- phone width
  const ph = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await ph.goto(base + '/login'); await ph.waitForSelector('html.zl-on');
  ok(await ph.evaluate(() => document.documentElement.scrollWidth <= 392), 'phone: no sideways scrolling');
  ok(await ph.evaluate(() => getComputedStyle(document.querySelector('.zl-pitch')).display === 'none' && document.querySelector('.zl-mark').getBoundingClientRect().bottom <= document.querySelector('.zl-card').getBoundingClientRect().top), 'phone: one column, the brand above the card');
  // the button shows it is working after a real submit, and is not disabled (its value still posts)
  await ph.fill('input[name=user]', 'busy.syn'); await ph.fill('input[name=pass]', 'synthetic');
  const busy = await ph.evaluate(() => new Promise((res) => { const f = document.querySelector('.zl form'); f.addEventListener('submit', (e) => { e.preventDefault(); setTimeout(() => res({ busy: document.querySelector('.zl').classList.contains('zl-busy'), disabled: f.querySelector('button:not(.zl-eye)').disabled }), 50); }); f.requestSubmit(); }));
  ok(busy.busy && !busy.disabled, 'submit: busy state shown, button not disabled');
  await page.goto(base + '/login'); await page.waitForSelector('html.zl-on');
  if (process.env.SHOT) { await page.waitForTimeout(1500); await ph.waitForTimeout(300); await page.screenshot({ path: process.env.SHOT + '/login-new.png' }); await ph.screenshot({ path: process.env.SHOT + '/login-phone.png' }); await page.goto(base + '/login/otp'); await page.waitForSelector('html.zl-on'); await page.waitForTimeout(1500); await page.screenshot({ path: process.env.SHOT + '/login-code.png' }); }
  ok(!errs.filter((e) => e !== 'x').length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
