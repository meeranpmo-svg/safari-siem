// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/cost-optimisation.html against the REAL ITAM engine (engine/platform-cost.js) over a SYNTHETIC
// collected estate: viewer told costs are for operators; nothing collected says what to connect; scenarios with saving, evidence,
// measured / assumed badges and the per-cluster table; an operator proposes a business case, the same person cannot decide it, a
// different administrator rejects without a reason (refused) then approves with one; assumptions admin-only and recalculate;
// escaped; the portal costopt redirect; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cost-optimisation.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const host = (name, cluster, used) => ({ platform: 'vc-syn', cluster, name, sockets: 2, cores: 32, cpu_ghz: 2.5, cpu_used_pct: used ? used[0] : null, mem_gb: 512, mem_used_pct: used ? used[1] : null });
  let ESTATE = null;
  e.app.addons.virtCapacity = { report: () => ESTATE || { platforms: [], hosts: [], vms: [] } };
  let WHO = VW;

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
    let p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'cost-optimisation.html');
    ok(await wait(p, () => /shown to operators and administrators/.test(document.getElementById('msg').innerText)), 'viewer: costs are for operators'); await p.close();
    WHO = OP; p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'cost-optimisation.html');
    ok(await wait(p, () => /No virtual estate collected yet/.test(document.getElementById('recs').innerText)), 'nothing collected: says what to connect'); await p.close();
    ESTATE = { platforms: [{ label: 'vc-syn', kind: 'vcenter', at: Date.now() }, { label: 'prism-syn', kind: 'nutanix', at: Date.now() }],
      hosts: [1, 2, 3, 4, 5, 6].map((i) => host('esx' + i, 'PROD', [12, 20])).concat([host('esx7', 'DMZ', null), { platform: 'prism-syn', cluster: 'NTX', name: 'ntx1', sockets: 2, cores: 24, cpu_ghz: 2.4, cpu_used_pct: 30, mem_gb: 384, mem_used_pct: 40 }]),
      vms: ['app-prod-01', 'uat-crm-01', 'dev-api' + XSS].map((nm) => ({ name: nm, platform: 'vc-syn', cluster: 'PROD', power: 'on', disk_gb: 100 })).concat([{ name: 'old-ftp', platform: 'vc-syn', cluster: 'PROD', power: 'off', disk_gb: 400 }]) };
    p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'cost-optimisation.html');
    ok(await wait(p, () => /Consolidate the VMware clusters/.test(document.getElementById('recs').innerText)), 'scenarios shown');
    let t = await txt(p, 'recs');
    ok(/measured: CPU and memory in use/.test(t) && /assumption: /.test(t), 'measured / assumed badges'); ok(/not measured/.test(t), 'a cluster without usage says not measured');
    ok(/SAR \d/.test(await txt(p, 'tot')), 'total savings'); ok(/VMware \(current\)/.test(await txt(p, 'hv')), 'hypervisor comparison');
    ok(await p.evaluate(() => !window.__xss), 'escaped');
    const ro = await p.evaluate(() => ({ n: document.querySelectorAll('#asm [data-a]').length, dis: [...document.querySelectorAll('#asm [data-a]')].every((i) => i.disabled), hid: document.getElementById('asmb').hidden }));
    ok(ro.n > 5 && ro.dis && ro.hid, 'assumptions read-only for an operator: ' + JSON.stringify(ro));
    await p.click('[data-prop="R1"]'); await p.fill('#p-note', 'synthetic case'); await p.click('#dlg-ok');
    ok(await wait(p, () => /Business case proposed/.test(document.body.innerText) && /awaiting approval · proposed by nora.syn/.test(document.getElementById('recs').innerText)), 'operator proposes');
    await p.close();
    // the proposer (an admin here) cannot decide their own; a different admin decides with a reason
    WHO = ADM; p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'cost-optimisation.html'); await wait(p, () => document.querySelector('[data-dec="approve"]'));
    await p.click('[data-dec="reject"]'); await p.click('#dlg-ok'); ok(/Give the reason/.test(await txt(p, 'dlg-e')), 'a decision needs a reason'); await p.click('#dlg-x');
    await p.click('[data-dec="approve"]'); await p.fill('#d-why', 'measured, N+1 kept (synthetic)'); await p.click('#dlg-ok');
    ok(await wait(p, () => /approved by syed/.test(document.getElementById('recs').innerText)), 'a different admin approves');
    await p.click('[data-prop="R4"]'); await p.click('#dlg-ok'); await wait(p, () => /awaiting approval · proposed by syed/.test(document.getElementById('recs').innerText));
    ok(/a different administrator decides/.test(await txt(p, 'recs')), 'the proposer cannot decide their own case');
    // assumptions
    const before = await txt(p, 'tot');
    await p.fill('[data-a="host_run_sar"]', '90000'); await p.click('#asave');
    ok(await wait(p, (b) => /Saved - 1 figure/.test(document.body.innerText) && document.getElementById('tot').innerText !== b, before), 'assumptions save and recalculate');
    ok(/changed; default 9000/.test(await txt(p, 'asm')), 'a changed figure is marked');
    await p.click('#areset'); ok(await wait(p, () => /reset to the defaults/.test(document.body.innerText)), 'reset');
    await p.close();
    ok(/ costopt: 'cost-optimisation\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal Cost Optimisation redirects here');
    ok(/ cost-optimisation\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(/"h": "cost-optimisation.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
