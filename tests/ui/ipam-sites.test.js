// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IP Plan by Site page (ipam-sites.html) against the REAL IT Asset Management engine, SYNTHETIC sites and addresses: the head office
// registered with a subnet and devices; tiles, the Saudi map, charts, what the AI noticed; an operator proposes a project site and sees
// its block and subnets waiting; the proposer cannot approve; another administrator approves and the site appears with its subnets;
// closing proposed; the CSV plan downloads; a viewer cannot propose or approve; hostile text stays text; menu and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ipam-sites.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ITAM = path.resolve(__dirname, '../../backend/itam');
const H = require(path.join(ITAM, 'tests/helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
(async () => {
  const e = await H.startApp({ noAi: true }); require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, copilotAiOff: true });
  const ADM = { user: 'admin.syn', role: 'admin' }, OPR = { user: 'net.syn', role: 'operator' };
  await e.req('PUT', '/ipam/sites/riyadh-ho', Object.assign({ body: { name: 'Riyadh Head Office', kind: 'head_office', city: 'Riyadh', block: '10.10.0.0/16', contact: XSS } }, ADM));
  await e.req('POST', '/ipam/subnets', Object.assign({ body: { cidr: '10.10.4.0/24', name: 'HQ users', site: 'Riyadh Head Office', vlan: 10, gateway: '10.10.4.1' } }, OPR));
  for (let i = 0; i < 8; i++) e.app.assets.create({ name: 'PC-SYN-' + i, type: 'workstation', status: 'in_use', site: 'Riyadh Head Office', mgmt_ip: '10.10.4.' + (20 + i) }, ADM);
  e.app.assets.create({ name: 'PC-JED-1', type: 'workstation', status: 'in_use', site: 'Jeddah Branch' }, ADM);
  let WHO = OPR;
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(WHO)); }
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ipam-sites.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  let PROMPTS = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(d.type() === 'prompt' ? (PROMPTS.shift() || '') : undefined)); await p.goto(url); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); return p; };
  try {
    let p = await open();
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Sites 1 1 head office/.test(kp) && /Not registered 1/.test(kp), 'tiles: ' + kp);
    ok((await p.$$('#ksa .zksa-pt')).length === 1 && (await p.$$('.g3 canvas')).length === 3, 'the map and three charts');
    ok(/not in the site register/.test(await p.textContent('#ins')) && /Jeddah Branch/.test(await p.textContent('#missing')), 'what the AI noticed; sites in use but not registered');
    ok(!(await p.evaluate(() => window.PWN)) && /<img src=x/.test(await p.textContent('#sites')), 'hostile text stays text');
    // propose a project site
    await p.fill('#nf [name=sname]', 'Jubail Project Site'); await p.selectOption('#nf [name=kind]', 'project_site'); await p.fill('#nf [name=city]', 'Jubail'); await p.fill('#nf [name=contact]', 'site.syn');
    await p.click('#nf button[type=submit]'); await p.waitForFunction(() => /waiting for another administrator/.test(document.getElementById('prev').textContent), null, { timeout: 8000 });
    ok(/gets 10\.\d+\.\d+\.0\/20 with 6 subnets/.test(await p.textContent('#prev')) && /pending/.test(await p.textContent('#props')), 'proposed: the block and the subnets');
    await p.close();
    // the proposer as administrator cannot approve; another administrator can
    WHO = { user: 'net.syn', role: 'admin' }; p = await open(); ok(!(await p.$('[data-dec]')) && /another administrator approves/.test(await p.textContent('#props')), 'the proposer cannot approve'); await p.close();
    WHO = { user: 'admin2.syn', role: 'admin' }; p = await open(); await p.click('[data-dec="approve"]');
    await p.waitForFunction(() => /Jubail Project Site/.test(document.getElementById('sites').textContent), null, { timeout: 8000 });
    ok(/applied/.test(await p.textContent('#props')) && (await p.$$('#ksa .zksa-pt')).length === 2, 'approved: the site appears on the map and in the table');
    const subs = e.app.store.collection('ipam_subnets').all().filter((x) => x.site === 'Jubail Project Site'); ok(subs.length === 6, 'six subnets created in the register: ' + subs.length);
    const dl = p.waitForEvent('download'); await p.click('[data-csv="jubail-project-site"]'); const f = await dl; ok(/ip-plan-jubail-project-site\.csv/.test(f.suggestedFilename()), 'the plan as CSV');
    PROMPTS = ['project handed over (synthetic)']; await p.click('[data-close="jubail-project-site"]'); await p.waitForTimeout(700); ok(/close/.test(await p.textContent('#props')), 'closure proposed');
    await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open(); ok(await p.$eval('#newc', (x) => x.hidden) && !(await p.$('[data-dec]')) && !(await p.$('[data-close]')), 'a viewer reads only'); await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "ipam-sites.html"') && / ipam-sites\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' ipam-sites checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
