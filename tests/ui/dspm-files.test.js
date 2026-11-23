// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the three DSPM cards on data-posture.html against the REAL engine (engine/dspm-files.js) over a SYNTHETIC posture
// context: Prioritize sensitive data risks (KPIs, files table with format / system / elements +N / label / owner avatar, filter chips,
// grouped violations); Automate data tagging & labeling (Policy information, Logs, Policy stats tabs; an admin adds a policy with a reason
// and the file's label changes); Data breach analysis (radius diagram, impact tier, SDAIA 72-hour obligation, what-if ranking); an
// operator sees no policy editor; a viewer is told the role; hostile names stay text; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node dspm-files.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const DF = require(path.join(ITAM, 'engine/dspm-files'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const NOW = Date.now();
const KIND_LABEL = { national_id: 'National ID', iban: 'IBAN / bank account', email: 'E-mail address', health: 'Health / diagnosis', password: 'Password in text', name: 'Person name' };
function ctx() {
  const hr = { id: 'm365:hr', type: 'sharepoint', label: 'HR Site', files_seen: 4000 }, fin = { id: 'm365:fin', type: 'sharepoint', label: 'Finance', files_seen: 6000 }, od = { id: 'm365:od1', type: 'onedrive', label: 'Nora Syn', files_seen: 500 }, fs = { id: 'fs:srv1:d', type: 'fileshare', label: '\\\\srv1\\data', files_seen: 1500 };
  const rows = [
    { store: hr, name: 'employees-iqama.xlsx', path: '/HR', kinds: ['national_id', 'email'], shared: 'anonymous', modified: '2026-10-01' },
    { store: hr, name: 'Board minutes 2026.docx', path: '/HR', kinds: ['name'], shared: 'none', modified: '2026-10-01' },
    { store: fin, name: 'vendors.csv', path: '/Fin', kinds: ['iban'], shared: 'external', modified: '2020-01-01' },
    { store: od, name: 'my-passwords.txt', path: '/', kinds: ['password'], shared: 'organization', modified: '2026-11-01' },
    { store: fs, name: 'medical.pdf', path: 'd\\x', kinds: ['health', 'national_id'], shared: 'everyone', modified: '2026-09-01' }];
  for (let i = 0; i < 6; i++) rows.push({ store: fs, name: 'contacts' + i + '.csv', path: 'd\\c', kinds: ['email'], shared: 'none', modified: '2026-09-01' });
  return { src: { m365_files: { measured: true } }, rows, stores: [hr, fin, od, fs], cloudStores: [{ id: 'cloud:aws:b1', raw_id: 'b1', type: 'cloud:aws', label: 'exports-bucket', public: true, in_kingdom: false, objects_scanned: 300 }],
    cloudObjects: [{ store_id: 'b1', key: 'dump/customers.sql', kinds: ['national_id', 'iban'], modified: '2026-08-01' }] };
}
const P = { KIND_LABEL, build: async () => ({ C: ctx() }) };

(async () => {
  const e = await H.startApp({ noAi: true });
  const P2 = { KIND_LABEL, build: async () => { const c = ctx(); c.rows[1].name = 'Board minutes ' + XSS + '.docx'; return { C: c }; } };
  DF.registerDspmFiles(e.app.srv, e.app, P2, { now: () => NOW });
  let WHO = { user: 'syed', role: 'admin' };
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText, id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'data-posture.html');
    ok(await wait(p, () => /Sensitive data violations/.test((document.getElementById('sf') || {}).innerText || '')), 'Prioritize sensitive data risks drawn');
    const sf = await txt(p, 'sf');
    ok(/All files\s*12\.?\d?k/.test(sf) && /Sensitive files\s*12/.test(sf), 'KPIs: files scanned and sensitive files: ' + sf.slice(0, 120));
    ok(/employees-iqama\.xlsx/.test(sf) && /Excel/.test(sf) && /SharePoint/.test(sf) && /National ID/.test(sf) && /\+1/.test(sf), 'files table: format, system, element +N');
    ok(await p.$('#sf .av') && /NS/.test(await p.$eval('#sf .av', (x) => x.textContent)), 'OneDrive owner shown as an avatar');
    ok(/Restricted/.test(sf) && /not for Copilot/.test(sf) && /toxic/.test(sf), 'labels, Copilot exclusion and toxic flags');
    ok(/Fix once, close many/.test(sf) && /one fix/.test(sf), 'violations grouped');
    await p.click('[data-sff="violations"]'); ok(await wait(p, () => document.querySelector('[data-sff="violations"].on') && !/contacts0/.test(document.getElementById('sf').innerText)), 'violations filter');
    ok(await wait(p, () => /Restricted - identity, health and secrets/.test(document.getElementById('lb').innerText)), 'Policy information tab');
    await p.click('[data-lt="stats"]'); ok(await wait(p, () => /Not labelled \(sensitive\)/.test(document.getElementById('lb').innerText)), 'Policy stats tab');
    await p.click('[data-lt="logs"]'); ok(await wait(p, () => /employees-iqama\.xlsx/.test(document.getElementById('lb').innerText) && /Time stamp/.test(document.getElementById('lb').innerText)), 'Logs tab: data system, location, file, label, time');
    await p.click('[data-lt="info"]'); await p.click('#lpnew');
    await p.fill('#lp-n', 'HR documents are Highly Confidential'); await p.selectOption('#lp-l', 'Highly Confidential'); await p.fill('#lp-p', '5'); await p.fill('#lp-loc', 'HR'); await p.check('#lp-c'); await p.click('#lp-save');
    ok(await wait(p, () => /reason/.test(document.getElementById('lp-err').textContent)), 'a reason is required');
    await p.fill('#lp-r', 'DPO decision 2026-11'); await p.click('#lp-save');
    ok(await wait(p, () => /HR documents are Highly Confidential/.test(document.getElementById('lb').innerText)), 'policy added');
    ok(await wait(p, () => [...document.querySelectorAll('#sf tr')].some((r) => /employees-iqama/.test(r.innerText) && /Highly Confidential/.test(r.innerText))), 'the file label follows the new policy');
    ok(e.app.store.auditTail(50).some((a) => a.action === 'dspm.label.policy.create' && a.by === 'syed'), 'audited in the admin name');
    ok(await wait(p, () => /What if/.test(document.getElementById('br').innerText)), 'what-if ranking');
    await p.click('#brgo');
    ok(await wait(p, () => /risk impact/.test(document.getElementById('brres').innerText)), 'breach analysed');
    const br = await txt(p, 'brres');
    ok(/High risk impact/.test(br) && /within 72 hours of becoming aware/.test(br) && /SDAIA/.test(br), 'tier and the SDAIA 72-hour obligation');
    ok(await p.$('#brres svg circle'), 'radius diagram');
    ok(await p.evaluate(() => !window.__xss), 'hostile names stay text');
    WHO = { user: 'nora.syn', role: 'operator' };
    const o = await browser.newPage({ viewport: { width: 1300, height: 900 } }); o.on('pageerror', (x) => errs.push(x.message));
    await o.goto(base + 'data-posture.html'); await wait(o, () => /Restricted/.test((document.getElementById('lb') || {}).innerText || ''));
    ok(!(await o.$('#lpnew')) && !(await o.$('[data-lpe]')), 'an operator sees no policy editor'); await o.close();
    WHO = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 390, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'data-posture.html');
    ok(await wait(v, () => /for operators and administrators/.test((document.getElementById('sf') || {}).innerText || '')), 'a viewer is told the role');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await v.close();
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-dspm-files.png', fullPage: true });
  } finally { await browser.close(); web.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
