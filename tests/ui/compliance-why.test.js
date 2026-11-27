// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Why Compliance (compliance-why.html) - the board briefing: the company's name from the brand, the five frameworks each with the
// issuer, who it applies to, the group's scope and the consequence; the capability x framework matrix; what is at stake; the
// 12-month path; the ask of the leadership; links to the live dashboards; the note to confirm with legal; readable in the dark
// and the light look; no page error; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node compliance-why.test.js   (SHOT=<dir> also saves screenshots)
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]);
    if (u.endsWith('whoami.json')) { r.writeHead(200, { 'Content-Type': 'application/json' }); return r.end('{"user":"ceo.syn","role":"viewer"}'); }
    if (u.startsWith('/api/')) { r.writeHead(404); return r.end('{}'); }
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/compliance-why.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const org = JSON.parse(/ZYB_ORG = Object\.freeze\((\{.*?\})\)/.exec(fs.readFileSync(path.join(DASH, 'vendor/zyb-org.js'), 'utf8'))[1]);
  try {
    for (const look of ['dark', 'light']) {
      const ctx = await browser.newContext({ viewport: { width: 1400, height: 1000 }, deviceScaleFactor: process.env.SHOT ? 2 : 1 });
      await ctx.addInitScript((lk) => { try { localStorage.setItem('zyb-dash-prefs', JSON.stringify({ brand: 'org', brandLook: lk })); } catch (e) { /* storage blocked */ } }, look);
      const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(url); await p.waitForSelector('#mx tr'); await p.waitForTimeout(800);
      if (look === 'dark') {
        ok((await p.textContent('#h1')).includes(org.short + ' Group'), 'the company from the brand: ' + await p.textContent('#h1'));
        const f = await p.$$eval('.f', (x) => x.map((c) => c.innerText));
        ok(f.length === 5 && /National Cybersecurity Authority/.test(f[0]) && /SDAIA/.test(f[1]) && /SAR 5 million/.test(f[1]) && /National Data Management Office/.test(f[2]) && /27001/.test(f[3]) && /Aramco/.test(f[4]), 'the five frameworks with issuer and consequence');
        ok(f.every((t) => /If we do not/.test(t) && /Applies to/.test(t) && /Our scope/.test(t)), 'each says who, our scope and the consequence');
        ok((await p.$$('#mx tr')).length === 11 && (await p.$$('#mx .dot')).length > 30, 'capability matrix');
        ok((await p.$$('#risk .rk')).length === 5 && (await p.$$('.road > div')).length === 3 && /accountable executive/.test(await p.textContent('.cta')), 'stakes, path and the ask');
        ok((await p.$$('#links a')).length >= 5 && /confirmed with the group's legal and compliance advisers/.test(await p.textContent('main')), 'live links and the legal note');
      }
      const lum = await p.evaluate(() => { const c = getComputedStyle(document.querySelector('.hero h1')).color.match(/\d+/g).map(Number); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; });
      ok(lum > 200, look + ' look: the hero title is light on the brand banner (' + Math.round(lum) + ')');
      const bl = await p.evaluate(() => { const c = getComputedStyle(document.querySelector('.hero .badges span')).color.match(/\d+/g).map(Number); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; });
      ok(bl > 200, look + ' look: the framework badges are light on the banner (' + Math.round(bl) + ')');
      if (process.env.SHOT) await p.screenshot({ path: path.join(process.env.SHOT, 'compliance-why-' + look + '.png'), fullPage: true });
      await ctx.close();
    }
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "compliance-why.html"') && / compliance-why\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' compliance-why checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
