// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for solution-admin.html (Platform Admin -> Modules & Solutions) against stubs in the shape of the sign-in service
// (/auth/org, /auth/whoami, /auth/admin/org) and the ITAM licence route (/api/itam/licence), SYNTHETIC data only. Checks: no
// licence = Unlimited; choosing "Cyber Security" turns on its modules plus prerequisites and saves {base, modules, edition} while
// keeping resp / roles / assign; a 409 shows the other administrator's version again; a limit over the licence is shown as a
// warning; a non-administrator sees it read-only and the menu registry hides the modules switched off.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node solution-admin.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  let WHO = { user: 'syed.syn', role: 'admin' }, CONFLICT = false;
  let ORG = { modules: null, edition: null, updated: '2026-10-01T08:00:00Z', resp: { 'core-admin': 'syed.syn' }, roles: [{ id: 'r1' }], assign: [{ user: 'nora.syn', role: 'r1' }] };
  const UNL = { state: 'unlimited', customer: null, edition: 'Unlimited', modules: null, limits: { users: null, ips: null, servers: null }, usage: { users: 4, ips: 120, servers: 30 }, labels: { users: 'Named users', ips: 'Monitored IP addresses', servers: 'Servers' }, warnings: [], note: 'No licence is installed: every module and every limit is unlimited.' };
  let LIC = UNL; const posts = [], licPosts = [];
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (f) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => f(JSON.parse(b || '{}'))); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, WHO);
    if (u === '/auth/org') return json(200, ORG);
    if (u === '/auth/admin/org' && req.method === 'POST') return body((x) => {
      posts.push(x); if (WHO.role !== 'admin') return json(403, { error: 'admin only' });
      if (CONFLICT) { CONFLICT = false; return json(409, { error: 'changed by someone else', current: Object.assign({}, ORG, { edition: 'Network', modules: ['net-mon'], updated: '2026-10-02T08:00:00Z' }) }); }
      ORG = Object.assign({}, ORG, { modules: x.modules, edition: x.edition, updated: '2026-11-03T08:00:00Z' }); json(200, ORG);
    });
    if (u === '/api/itam/licence' && req.method === 'GET') return json(200, LIC);
    if (u === '/api/itam/licence' && req.method === 'POST') return body((x) => { licPosts.push(x); if (!x.licence || x.licence.signature !== 'SYNTHETIC-OK') return json(400, { error: 'licence.signature: the signature does not match' });
      LIC = { state: 'valid', customer: x.licence.customer, edition: 'Cyber Security', licence_id: 'CN-SYN-1', modules: null, issued: '2026-11-01', expires: '2027-11-01', limits: { users: 2, ips: 100, servers: null }, usage: UNL.usage, labels: UNL.labels, warnings: ['Monitored IP addresses: 120 in use, the licence allows 100. Nothing is switched off; extend the licence with Citynet.', 'Named users: 4 in use, the licence allows 2. Nothing is switched off; extend the licence with Citynet.'] }; json(200, LIC); });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } }); const page = await ctx.newPage(); const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));

  await page.goto(base + 'solution-admin.html'); await page.waitForSelector('#mods .mod');
  ok(/Unlimited/.test(await page.$eval('#lstate', (e) => e.innerText)), 'no licence installed: Unlimited');
  ok(/Unlimited/.test(await page.$eval('#lic', (e) => e.innerText)) && /120/.test(await page.$eval('#lic', (e) => e.innerText)), 'usage shown against unlimited');
  ok(await page.waitForFunction(() => /What the records say/.test((document.getElementById('recs') || {}).innerText || '')).then(() => true, () => false), 'the suggestions card renders');
  const rc = (await page.$eval('#recs', (e) => e.innerText)).replace(/\s+/g, ' ');
  ok(/3 module\(s\) added to the catalogue: Business risk & capital, Enterprise asset management, Workflow automation/.test(rc) && /nothing anyone used disappears/.test(rc), 'new modules named, with the keep-on rule: ' + rc.slice(0, 220));
  ok(await page.$$eval('#mods .mod', (L) => L.filter((x) => /Business risk & capital|Enterprise asset management|Workflow automation/.test(x.innerText) && /new/.test(x.innerText)).length === 3), 'the three new modules carry a "new" badge');
  ok(await page.evaluate(() => window.ZybModules.moduleOf('risk-start.html') === 'brisk' && window.ZybModules.moduleOf('eam.html') === 'eam' && window.ZybModules.moduleOf('workflow-automation.html') === 'workflow'), 'Business Risk, EAM and Workflow pages now belong to a module');
  ok(await page.evaluate(() => window.ZYB_NAV.every((a) => (a.pages || []).every((x) => !!window.ZybModules.moduleOf(x.h)))), 'every menu page belongs to a module');
  ok(await page.$eval('#linst', (e) => !e.hidden), 'admin: licence install form shown');
  const allOn = await page.$$eval('#mods input[data-mod]', (I) => I.every((i) => i.checked));
  ok(allOn, 'Enterprise (modules null): every module on');
  ok(await page.$eval('input[data-mod="core-dash"]', (e) => e.disabled && e.checked), 'core module always on, cannot be switched off');

  // choose the Cyber Security solution and save
  await page.click('[data-sol="Cyber Security"]');
  ok(await page.$eval('input[data-mod="incidents"]', (e) => e.checked) && !(await page.$eval('input[data-mod="net-mon"]', (e) => e.checked)), 'Cyber Security: incidents on, network monitoring off');
  ok(/unsaved/.test(await page.$eval('#dirty', (e) => e.innerText)), 'unsaved changes marked');
  await page.fill('#note', 'Synthetic: cyber security solution');
  await page.click('#sgo'); await page.waitForFunction(() => !/unsaved/.test(document.getElementById('dirty').innerText));
  const p = posts[0];
  ok(p && p.base === '2026-10-01T08:00:00Z' && p.edition === 'Cyber Security' && Array.isArray(p.modules), 'saved with base version, edition and modules: ' + JSON.stringify(p && { base: p.base, edition: p.edition }));
  ok(p && p.modules.includes('siem-core') && p.modules.includes('ai-guard') && !p.modules.includes('net-mon'), 'modules include prerequisites, exclude network');
  ok(p && JSON.stringify(p.resp) === JSON.stringify({ 'core-admin': 'syed.syn' }) && p.assign.length === 1 && p.note === 'Synthetic: cyber security solution', 'responsibilities, roles and assignments kept; note sent');

  // switching off a module another one needs keeps it on
  await page.click('input[data-mod="siem-core"]');
  ok(await page.$eval('input[data-mod="siem-core"]', (e) => e.checked), 'SIEM stays on while Incident response needs it');

  // a conflict shows the other administrator's version
  await page.click('[data-sol="Professional"]'); CONFLICT = true; await page.click('#sgo');
  await page.waitForFunction(() => /Another administrator/.test(document.getElementById('smsg').innerText));
  ok(await page.$eval('[data-sol="Network"]', (e) => e.classList.contains('on')), '409: the newer saved version is shown again');

  // install a licence: a bad one is refused, a signed one shows the warnings
  await page.fill('#ltext', JSON.stringify({ customer: 'Synthetic Co', signature: 'FORGED' })); await page.click('#lgo');
  await page.waitForFunction(() => /Not installed: licence\.signature/.test(document.body.innerText));
  await page.fill('#ltext', JSON.stringify({ customer: 'Synthetic Co', signature: 'SYNTHETIC-OK' })); await page.click('#lgo');
  await page.waitForFunction(() => /Valid/.test(document.getElementById('lstate').innerText));
  const lic = await page.$eval('#lic', (e) => e.innerText);
  ok(/over the limit/.test(lic) && /Nothing is switched off/.test(lic), 'over-limit shown as a warning, nothing switched off');
  ok(licPosts.length === 2, 'two install attempts sent');

  // a non-administrator: read-only, and the menu registry hides modules outside the subscription
  WHO = { user: 'vera.syn', role: 'viewer' }; ORG = Object.assign({}, ORG, { modules: ['siem-core', 'incidents'], edition: 'Custom' });
  const p2 = await ctx.newPage(); p2.on('pageerror', (e) => errs.push(e.message));
  await p2.goto(base + 'solution-admin.html'); await p2.waitForSelector('#mods .mod');
  ok(await p2.$eval('#linst', (e) => e.hidden) && await p2.$eval('#save', (e) => e.hidden), 'viewer: no install form, no save');
  ok(await p2.$$eval('#mods input[data-mod]', (I) => I.every((i) => i.disabled)), 'viewer: every checkbox read-only');
  await p2.waitForFunction(() => { const s = window.ZybModules && window.ZybModules.state(); return s && Array.isArray(s.modules) && !s.admin; });
  const nav = await p2.evaluate(() => ({ net: window.ZYB_NAV.some((a) => a.id === 'net'), adm: window.ZYB_NAV.some((a) => a.id === 'adm'), offNet: window.ZybModules.off('network-engineer.html'), offSoc: window.ZybModules.off('soc-alerts.html') }));
  ok(!nav.net && nav.adm && nav.offNet && !nav.offSoc, 'viewer menu: network area hidden, admin and SOC kept: ' + JSON.stringify(nav));
  ok(await p2.evaluate(() => !window.ZybModules.off('business-risk.html') && !window.ZybModules.off('eam.html')), 'a choice saved before the new modules existed keeps their pages visible');
  const rc2 = (await p2.$eval('#recs', (e) => e.innerText)).replace(/\s+/g, ' ');
  ok(/is off, but the platform holds 30 server\(s\) and VM\(s\)/.test(rc2), 'a module switched off while the platform holds its data is pointed out: ' + rc2.slice(0, 200));

  ok(errs.length === 0, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' solution-admin checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
