// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// POC mode (vendor/zyb-poc.js, vendor/zyb-poc-data.js, the menu switch in vendor/zyb-dash.js), with a server that FAILS every API
// call: NDR (ndr.html) draws from the illustrative data with charts and the POC ribbon on every corner; a change (Run now) is
// refused in the browser and never reaches the server; with POC off the same page shows the server's answer (here an error) and
// no ribbon; the menu switch turns it on and off; a page without illustrative data says it shows live data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node poc-mode.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const seen = [];
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end('{"user":"analyst.syn","role":"admin"}'); }
    if (u.pathname.startsWith('/api/')) { seen.push(req.method + ' ' + u.pathname); res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end('{"error":"server down (synthetic)"}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1100 } });
    let p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept());
    await p.goto(base + 'ndr.html?poc=1'); await p.waitForSelector('#charts:not([hidden])', { timeout: 15000 });
    ok(!seen.some((s) => /\/ndr/.test(s)), 'NDR never asked the server in POC mode: ' + seen.join(', '));
    ok((await p.$$('.zyb-poc-r')).length === 4 && /Illustrative data/.test(await p.textContent('#zyb-poc-banner')), 'the POC ribbon on every corner and the banner');
    ok(/\(POC\)$/.test(await p.title()), 'the title says POC');
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' '); ok(/Hosts at risk \d+/.test(kp) && /Beaconing 3/.test(kp), 'tiles from the illustrative data: ' + kp);
    ok((await p.$$('#charts canvas')).length === 6, 'six charts');
    ok(/regular check-ins outside AND unusual outbound volume/.test(await p.textContent('#ins')) && /T1071/.test(await p.textContent('#body')), 'what the AI noticed and the ATT&CK technique');
    if (process.env.SHOT) { await p.waitForTimeout(900); await p.screenshot({ path: process.env.SHOT, fullPage: false }); }
    seen.length = 0; await p.click('#run'); await p.waitForTimeout(600); ok(!seen.length, 'a change never reaches the server in POC mode');
    await p.close();
    // attack surface draws from the illustrative data too, with its charts and the asset detail
    p = await ctx.newPage(); await p.goto(base + 'attack-surface.html?poc=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); await p.waitForTimeout(500);
    ok(/Exposed assets 15/.test((await p.$eval('#kk', (x) => x.innerText)).replace(/\s+/g, ' ')) && (await p.$$('.as4 canvas')).length === 4 && /management or database service/.test(await p.textContent('#ins')), 'attack surface: tiles, four charts, what the AI noticed');
    await p.click('[data-open="as-02"]'); await p.waitForSelector('#dlg[open]'); ok(/CVE-2023-27997/.test(await p.textContent('#dlgb')), 'attack surface: one asset with its required actions'); await p.close();
    // SOC overview: open alerts by site on the Saudi map, from the real SOC engine's output over synthetic alerts
    p = await ctx.newPage(); await p.goto(base + 'soc-overview.html?poc=1'); await p.waitForSelector('.zksa-pt', { timeout: 15000 });
    ok((await p.$$('.zksa-pt')).length >= 8 && /Riyadh Head Office/.test(await p.textContent('#bysite')), 'SOC: open alerts by site on the Saudi map');
    // IT Asset Management overview: assets by site on the Saudi map, from the real engine over synthetic assets
    const p2 = await ctx.newPage(); await p2.goto(base + 'itam-overview.html?poc=1'); await p2.waitForSelector('#ksa .zksa-pt', { timeout: 15000 });
    ok((await p2.$$('#ksa .zksa-pt')).length >= 9 && /Jubail Project Site/.test(await p2.textContent('#sitel')), 'assets by site on the Saudi map'); await p2.close();
    // every Refresh button shows it worked
    await p.click('#refresh'); await p.waitForSelector('#zyb-rf-note:not([hidden])', { timeout: 5000 }); ok(/Refreshed/.test(await p.textContent('#zyb-rf-note')), 'Refresh says it refreshed'); await p.close();
    // POC off: the same page shows the server's answer, no ribbon
    p = await ctx.newPage(); await p.goto(base + 'ndr.html'); await p.waitForTimeout(1500);
    ok(!(await p.$('.zyb-poc-r')) && seen.some((s) => /\/ndr/.test(s)), 'POC off: live request, no ribbon'); await p.close();
    // the menu switch stores the choice in this browser
    p = await ctx.newPage(); await p.goto(base + 'ndr.html'); await p.waitForSelector('[data-zyb-pocsw]', { timeout: 15000 });
    await Promise.all([p.waitForNavigation(), p.click('[data-zyb-pocsw]')]); await p.waitForSelector('.zyb-poc-r', { timeout: 15000 });
    ok(await p.evaluate(() => localStorage.getItem('zyb-poc') === '1'), 'the switch turns POC on');
    // a page with no illustrative data says it is live
    await p.goto(base + 'compliance-why.html'); await p.waitForTimeout(3500); ok(/no illustrative data - it shows LIVE data/.test(await p.textContent('body')) && !(await p.$('.zyb-poc-r')), 'a page without POC data says it is live');
    await p.goto(base + 'ndr.html'); await p.waitForSelector('[data-zyb-pocsw]'); await Promise.all([p.waitForNavigation(), p.click('[data-zyb-pocsw]')]); await p.waitForTimeout(1200);
    ok(await p.evaluate(() => localStorage.getItem('zyb-poc') === null) && !(await p.$('.zyb-poc-r')), 'the switch turns POC off');
    await p.close(); await ctx.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-poc-data.js'), 'utf8').match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g).every((ip) => /^(10\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip)), 'only private or documentation addresses in the illustrative data');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' poc-mode checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
