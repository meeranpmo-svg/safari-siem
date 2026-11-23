// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// dark-web-watch.html against the REAL SIEM module (sentra-siem engine/soc/darkweb.js) with a fake Have I Been Pwned and a fake
// directory, SYNTHETIC accounts: an administrator sets the domains and the key (never shown back); an operator reads HIBP and
// imports a provider CSV (passwords dropped, the count shown); exposures ranked with the risk explained on hover, the directory
// match (privileged, password not changed since the leak), filters; a reset attested with a note shows "attested, not
// verified"; a viewer sees counts only; a hostile source name stays text; phone width; menu entry and installer.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node dark-web-watch.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">', KEY = 'abcdef0123456789abcdef0123456789', DAY = 864e5, NOW = Date.now();
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { fakeApi, tmpDir, quietLog } = require(path.join(SIEM, 'tests/soc-fakes'));
(async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), alerts = createAlerts({ state, log: quietLog });
  const users = { 'omar.syn': { sam: 'omar.syn', privileged: true, disabled: false, pwd_last_set: NOW - 900 * DAY }, 'sara.syn': { sam: 'sara.syn', privileged: false, disabled: false, pwd_last_set: NOW - 2 * DAY } };
  const R = (status, j) => ({ status, ok: status < 300, json: async () => j });
  const fetchImpl = async (url, opt) => {
    if (url.endsWith('/breaches')) return R(200, [{ Name: 'SynCorp', Title: 'SynCorp ' + XSS, BreachDate: '2025-06-01', DataClasses: ['Email addresses', 'Passwords'] }]);
    if (opt.headers['hibp-api-key'] !== KEY) return R(401, {});
    if (url.includes('/breacheddomain/')) return R(200, { 'omar.syn': ['SynCorp'], 'sara.syn': ['SynCorp'] });
    return R(403, {});
  };
  const api = fakeApi({ realRanks: true });
  require(path.join(SIEM, 'engine/soc/darkweb')).register(api, { state, alerts, identity: { lookup: (x) => users[String(x).toLowerCase().split('@')[0]] || null }, config: { _paths: { secrets: path.join(dir, 'secrets.json') } }, log: quietLog, fetch: fetchImpl, noTimers: true });
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await api.call(req.method, u.pathname + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/dark-web-watch.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  const csvFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'dw-')), 'findings.csv');
  fs.writeFileSync(csvFile, 'email,source,type,password\nnew.syn@zs-syn.test,"Infostealer market (synthetic)",infostealer,Hunter2-synthetic\nx@gmail.example,y,breach,z\n');
  let answer = 'reset by the service desk, ticket SYN-9';
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(answer));
    await p.goto(url); ok(await wait(p, () => !document.getElementById('main').hidden && document.getElementById('doms')), 'opens; settings for the administrator');
    ok(/Set the company e-mail domains/.test(await p.textContent('#ex')), 'the empty state says what to do');
    await p.fill('#doms', 'zs-syn.test'); await p.fill('#hkey', KEY); await p.click('#saveset');
    ok(await wait(p, () => /\(set - leave empty to keep\)/.test(document.getElementById('set').textContent)), 'the key is saved');
    ok(!(await p.content()).includes(KEY), 'the key is never shown back');
    await p.click('#dosync'); ok(await wait(p, () => document.querySelectorAll('#ex tbody tr').length === 2), 'Have I Been Pwned read: two exposures');
    const ex = await p.textContent('#ex');
    ok(/omar\.syn@zs-syn\.test/.test(ex) && /privileged/.test(ex) && /password not changed since the leak/.test(ex), 'the directory match');
    ok(/password changed after the leak/.test(ex), 'sara changed hers after the leak');
    ok(await p.$eval('#ex tbody tr td:first-child', (td) => /privileged account/.test(td.title)), 'the top risk explains its points on hover');
    ok(!(await p.evaluate(() => window.__xss)) && /<img src=x/.test(ex), 'a hostile breach name stays text');
    // provider import
    await p.fill('#prov', 'SynIntel'); await p.setInputFiles('#file', csvFile); await p.click('#doimp');
    const toastOk = await wait(p, () => /2 password value\(s\) dropped, not stored/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' '))); if (!toastOk) console.log('toasts:', await p.$$eval('.toast', (L) => L.map((t) => t.textContent))); ok(toastOk, 'import: the dropped passwords counted');
    ok(await wait(p, () => document.querySelectorAll('#ex tbody tr').length === 3), 'the import added one exposure (the other domain is ignored)');
    ok(!(await p.content()).includes('Hunter2-synthetic'), 'the password never reaches the page');
    await p.selectOption('#fk', 'stealer'); ok(await wait(p, () => document.querySelectorAll('#ex tbody tr').length === 1 && /new\.syn/.test(document.getElementById('ex').textContent)), 'filter by kind');
    await p.selectOption('#fk', '');
    // a reset attested with a note
    const omarRow = await p.$('#ex tbody tr:has-text("omar.syn") [data-st="reset"]'); await omarRow.click();
    ok(await wait(p, () => /attested by a person, not verified/.test(document.getElementById('ex').textContent)), 'a reset without a directory change is shown as attested, not verified');
    ok(api.audits.some((a) => a.action === 'soc.darkweb.status' && a.detail.evidence === 'attested') && api.audits.some((a) => a.action === 'soc.darkweb.import'), 'audited');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    ok(/Account names are personal data/.test(await p.textContent('#ex')) && !/omar\.syn/.test(await p.content()), 'a viewer sees counts, no names');
    ok(!(await p.$('#dosync')) && !(await p.$('#saveset')) && !(await p.$('#doimp')), 'and no actions');
    WHO = { user: 'syed', role: 'admin' };
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => !document.getElementById('main').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "dark-web-watch.html"/.test(nav) && / dark-web-watch\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/'tiw-darkweb': 'dark-web-watch\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')), 'the module catalogue\'s dark-web view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
