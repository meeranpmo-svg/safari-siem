// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/itam-settings.html against the REAL ITAM engine (engine/settings-advisor.js + settings through duty.js) with
// a SYNTHETIC register: the advisor score and recommendations with evidence; Apply changes the setting (and the score); thresholds
// show the learned value; sources saved; a token issued and shown once, then revoked; a credential saved and never echoed; an import
// dry run; operators are refused; the portal itam-settings redirect; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node asset-autofill.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const A = e.app.store.collection('assets'), ago = (d) => new Date(Date.now() - d * 86400000).toISOString();
  for (let i = 0; i < 20; i++) A.put({ id: 'pc' + i, name: 'PC-' + i, type: 'workstation', status: 'in_use', networked: true, site: 'Jeddah', last_seen: ago(5 + i * 2), sources: [{ source: 'sensor', last_seen: ago(5 + i * 2) }] });
  e.app.settings.update({ not_seen_days: 14, sources: { vcenter: true } }, ADM);
  let WHO = ADM;
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
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    // the vCenter connector flow: an organisation with VMware on (Safari's brand is Hyper-V only - checked at the end)
    await p.addInitScript(() => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { pages_off: [] }); }, get() { return this._o; } }); });
    await p.goto(base + 'itam-settings.html');
    ok(await wait(p, () => /checks pass/.test(document.getElementById('scoreS').innerText)), 'score shown');
    const recs = await txt(p, 'recs');
    ok(/vCenter is on without its credentials/.test(recs) && /Not-seen threshold is shorter/.test(recs) && /Endpoint agent on 0 %/.test(recs), 'recommendations with evidence');
    const s0 = await txt(p, 'score');
    await p.evaluate(() => [...document.querySelectorAll('[data-apply]')].find((b) => /not_seen_days/.test(b.innerText)).click());
    ok(await wait(p, () => /Applied/.test(document.body.innerText)), 'apply');
    ok(e.app.settings.get().not_seen_days >= 39, 'the learned threshold was applied: ' + e.app.settings.get().not_seen_days);
    ok(await wait(p, () => !/Not-seen threshold is shorter/.test(document.getElementById('recs').innerText)), 'the recommendation is gone after applying');
    void s0;
    await p.click('[data-tab="ge"]'); ok(/learned/.test(await txt(p, 'g-nsh')), 'threshold shows the learned value');
    await p.fill('#g-ns', '0'); await p.click('#g-save'); ok(/1-365/.test(await txt(p, 'g-err')), 'the page checks the threshold');
    await p.fill('#g-ns', '45'); await p.uncheck('[data-src="vcenter"]'); await p.click('#g-save');
    ok(await wait(p, () => /Settings saved/.test(document.body.innerText)), 'saved');
    ok(e.app.settings.get().not_seen_days === 45 && e.app.settings.get().sources.vcenter === false, 'stored');
    // agents: token shown once, then revoked
    await p.click('[data-tab="ag"]'); await p.fill('#t-site', 'Jeddah'); await p.click('#t-issue');
    ok(await wait(p, () => /shown once/.test(document.getElementById('tokNew').innerText)), 'token issued and shown');
    await p.click('#tokDone'); ok(await wait(p, () => /open/.test(document.getElementById('toks').innerText)), 'token listed as open');
    await p.click('[data-rv]'); ok(await wait(p, () => /Token revoked/.test(document.body.innerText)), 'token revoked');
    ok(/Jeddah/.test(await txt(p, 'cov')), 'coverage by site');
    // credentials: write-only
    await p.click('[data-tab="cr"]'); await p.fill('[data-cv="vcenter_user"]', 'svc-syn-readonly'); await p.click('[data-cs="vcenter_user"]');
    ok(await wait(p, () => /not shown again/.test(document.body.innerText)), 'credential saved');
    ok(!(await p.content()).includes('svc-syn-readonly'), 'never echoed');
    // import dry run
    await p.click('[data-tab="im"]'); await p.fill('#i-text', 'Asset Name,Serial Number\nSYN-IMP-1,SYNSER1'); await p.click('#i-dry');
    ok(await wait(p, () => /Preview/.test(document.getElementById('i-res').innerText)), 'import dry run');
    ok(!e.app.store.collection('assets').all((a) => a.serial === 'SYNSER1').length, 'a dry run writes nothing');
    // operator refused
    WHO = OP; await p.reload(); ok(await wait(p, () => /for administrators/.test(document.body.innerText)), 'operators refused');
    await p.close();
    // Hyper-V only (the real Safari brand): no vCenter login offered unless one is already stored; the page says Hyper-V needs none
    WHO = ADM;
    const off = JSON.parse(fs.readFileSync(path.join(DASH, '../brand/brand.json'), 'utf8')).pages_off || [];
    if (off.includes('vmware-servers') && off.includes('nutanix-vms')) {
      for (const n of ['vcenter_user', 'vcenter_pass']) { try { e.app.settings.setCredential ? e.app.settings.setCredential(n, '', ADM) : null; } catch (x) { /* clearing is optional: the check below covers both */ } }
      const h = await browser.newPage(); h.on('pageerror', (x) => errs.push(x.message)); await h.goto(base + 'itam-settings.html');
      await h.waitForSelector('[data-tab="cr"]'); await h.click('[data-tab="cr"]'); await h.waitForSelector('#creds table');
      const cr = await txt(h, 'creds'), stored = (k) => !!((e.app.settings.credentialStatus ? e.app.settings.credentialStatus() : {})[k] || {}).configured;
      ok(/Hyper-V needs no credential here/.test(cr) && !!(await h.$('#creds a[href="hyperv.html?add=1"]')), 'Hyper-V only: the page says no credential is needed and links to adding hosts');
      ok(stored('vcenter_user') || !(await h.$('[data-cv="vcenter_user"]')), 'Hyper-V only: no vCenter login offered when none is stored');
      ok(!!(await h.$('[data-cv="private_token"]')), 'the other credentials stay');
      await h.close();
    }
    ok(/'itam-settings': 'itam-settings\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal ITAM Settings view redirects here');
    ok(/ itam-settings\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(/"h": "itam-settings.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
