// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Email Logs page (m365-mail.html) driven by the REAL routes (backend/siem engine/collect/m365-mailtrace.js) over SYNTHETIC message
// trace events from the real parser: tiles, four charts, the hour strip, what the AI noticed, the unusual sender, personal webmail,
// large mail, the latest messages with the filters; an administrator pulls now (audited by the route), an analyst sees no Pull
// button, a viewer is told the page is for analysts; hostile text stays text; POC mode draws from the illustrative data with the
// ribbon and never asks the server; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node m365-mail.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), SIEM = path.resolve(__dirname, '../../backend/siem');
const M = require(path.join(SIEM, 'engine/collect/m365-mailtrace')), PM = require(path.join(SIEM, 'engine/parse/m365'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>@corp.example';
const H = 3600e3, DAY = 24 * H, NOW = Date.now();
(async () => {
  const L = [], add = (o) => L.push(PM.parse('', { obj: Object.assign({ id: 'x' + L.length, senderAddress: 'syn.lina@corp.example', recipientAddress: 'syn.omar@corp.example', receivedDateTime: new Date(NOW - H).toISOString(), size: 9000, status: 'Delivered', fromIP: '198.51.100.9' }, o) }));
  for (let d = 0; d < 20; d++) for (let i = 0; i < 5; i++) add({ receivedDateTime: new Date(NOW - d * DAY - i * 6e4 - H).toISOString() });
  for (let i = 0; i < 40; i++) add({ recipientAddress: 'p' + i + '@d' + (i % 6) + '.example', receivedDateTime: new Date(NOW - 2 * H - i * 3e4).toISOString() });
  add({ senderAddress: 'syn.omar@corp.example', recipientAddress: 'home.syn@gmail.com', size: 25 * 1048576 });
  for (let i = 0; i < 3; i++) add({ senderAddress: 'bad@phish.example', status: 'Quarantined' });
  add({ senderAddress: XSS, recipientAddress: 'syn.lina@corp.example', status: 'FilteredAsSpam' });
  const R = {}, RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 }, audits = []; let pulls = 0;
  M.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { search: { fetchEvents: async () => L }, m365Mail: { status: () => ({ enabled: true, ready: true, missing: [], last_poll_at: new Date().toISOString() }), enabled: () => true, pullNow: async () => { pulls++; return { ok: true, records: 7 }; } }, config: {}, log: { error() {} } });
  let WHO = { user: 'admin.syn', role: 'admin' };
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let raw = ''; req.on('data', (c) => { raw += c; }); req.on('end', async () => { const h = R[req.method + ' ' + u.pathname]; if (!h) return json(404, {});
      const o = {}, ctx = { role: WHO.role, user: WHO.user, body: raw ? JSON.parse(raw) : undefined, query: Object.fromEntries(u.searchParams), params: {}, audit(action, target, detail) { audits.push({ action, target, detail }); }, ok(x) { o.s = 200; o.b = x; }, fail(c, m) { o.s = c; o.b = { error: m }; }, need(r) { if ((RANK[WHO.role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
      try { const rv = await h(ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } } catch (e) { o.s = e.status || 500; o.b = { error: e.message }; } json(o.s, o.b); }); return; }
    if (u.pathname.startsWith('/api/')) return json(500, { error: 'down (synthetic)' });
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/m365-mail.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (q) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + (q || '?standalone=1')); return p; };
  try {
    let p = await open(); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 });
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Blocked 4/.test(kp) && /Unusual senders 1/.test(kp) && /To personal webmail 1/.test(kp), 'tiles: ' + kp);
    ok((await p.$$('.g3 canvas')).length === 4 && (await p.$$('#hm i')).length === 24, 'four charts and the hour strip');
    ok(/personal webmail/.test(await p.textContent('#ins')) && /syn\.lina@corp\.example/.test(await p.textContent('#spk')) && /gmail\.com/.test(await p.textContent('#pers')) && /25/.test(await p.textContent('#lrg')), 'insights, unusual sender, personal webmail, large mail');
    await p.selectOption('#fs', 'Quarantined'); ok((await p.$$('#rec tbody tr')).length === 3, 'filter by status');
    await p.selectOption('#fs', ''); await p.fill('#q', 'gmail'); await p.dispatchEvent('#q', 'input'); ok((await p.$$('#rec tbody tr')).length === 1, 'filter by address');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text');
    await p.click('#poll'); await p.waitForTimeout(700); ok(pulls === 1 && audits.some((a) => a.action === 'm365.mail.poll'), 'an administrator pulls now, audited');
    await p.close();
    WHO = { user: 'ana.syn', role: 'analyst' }; p = await open(); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); ok(await p.$eval('#poll', (x) => x.hidden), 'an analyst has no Pull button'); await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open(); await p.waitForSelector('#err .err', { timeout: 15000 }); ok(/analysts and above/.test(await p.textContent('#err')), 'a viewer is told it is for analysts'); await p.close();
    // POC mode: the illustrative data answers, the ribbon shows, the server is never asked
    WHO = { user: 'admin.syn', role: 'admin' }; const before = audits.length; p = await open('?poc=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 });
    ok((await p.$$('.zyb-poc-r.br')).length === 1 && /safari-poc\.example/.test(await p.textContent('#rec')) && audits.length === before, 'POC: illustrative mail, one ribbon, no server read');
    if (process.env.SHOT) { await p.waitForTimeout(900); await p.screenshot({ path: process.env.SHOT, fullPage: true }); }
    await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "m365-mail.html"') && / m365-mail\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-poc-mail.js'), 'utf8').match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g).every((ip) => /^(198\.51\.100\.|203\.0\.113\.)/.test(ip)), 'only documentation addresses in the POC data');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' m365-mail checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
