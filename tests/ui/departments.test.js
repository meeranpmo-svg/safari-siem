// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Departments (departments.html) and HR onboarding with the register, against the REAL IT Asset Management engine, SYNTHETIC
// data: the register from the company setting; an administrator adds a department with its joiner template, renames it (the asset
// records follow), adds a name found in the data; HR's new-joiner form then lists only the register, and picking a department
// fills the template (laptop profile, VPN, the head as manager); several joiners at once with an error per row; a viewer has no
// edit; hostile text stays text; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node departments.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ITAM = path.resolve(__dirname, '../../backend/itam');
const H = require(path.join(ITAM, 'tests/helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
(async () => {
  const e = await H.startApp({ noAi: true }); require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const ADM = { user: 'admin.syn', role: 'admin' };
  e.app.assets.create({ name: 'PC-SYN-1', type: 'workstation', status: 'in_use', department: 'Site Crew' }, ADM);
  e.app.assets.create({ name: 'PC-SYN-2', type: 'workstation', status: 'in_use', department: XSS }, ADM);
  let WHO = ADM;
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(WHO)); }
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (pg, sel) => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(d.type() === 'prompt' ? 'reorg (synthetic)' : undefined)); await p.goto(base + pg + '?standalone=1'); await p.waitForSelector(sel, { timeout: 15000 }); return p; };
  try {
    let p = await open('departments.html', '#dl table');
    ok(/company setting/.test(await p.textContent('#src')) && /Site Crew/.test(await p.textContent('#sug')), 'from the company setting; names found in the data');
    ok(!(await p.evaluate(() => window.PWN)) && /<img src=x/.test(await p.textContent('#sug')), 'hostile text stays text');
    await p.click('#addd'); await p.fill('#df [name=name]', 'Field Crew'); await p.fill('#df [name=head]', 'mgr.syn'); await p.fill('#df [name=branches]', 'Jubail, Yanbu');
    await p.selectOption('#df [name=laptop_profile]', 'power'); await p.check('#df [name=vpn]'); await p.fill('#df [name=groups]', 'GG-Field'); await p.click('#df button[type=submit]');
    await p.waitForFunction(() => /Field Crew/.test(document.getElementById('dl').textContent), null, { timeout: 8000 });
    const F = e.app.store.collection('org_departments').get('field_crew'); ok(F && F.template.laptop_profile === 'power' && F.template.vpn === true && F.branches.join() === 'Jubail,Yanbu' && F.head === 'mgr.syn', 'saved with its template');
    await p.selectOption('[data-sm="0"]', 'field_crew'); await p.waitForTimeout(600);
    ok(e.app.store.collection('assets').all().find((a) => a.name === 'PC-SYN-1').department === 'Field Crew', 'a name from the data merged into the register: the record follows');
    await p.close();
    // HR onboarding uses the register
    WHO = { user: 'hr.syn', role: 'operator' }; p = await open('hr-onboarding.html', '#new');
    await p.click('#new'); await p.waitForSelector('#oform [name=department]');
    ok(await p.$eval('#oform [name=department]', (x) => x.tagName === 'SELECT' && [...x.options].some((o) => o.value === 'Field Crew')), 'the new-joiner form lists the register');
    await p.selectOption('#oform [name=department]', 'Field Crew'); await p.dispatchEvent('#oform [name=department]', 'change');
    ok((await p.$eval('#oform [name=laptop_profile]', (x) => x.value)) === 'power' && await p.$eval('#oform [name=vpn]', (x) => x.checked) && (await p.$eval('#oform [name=manager]', (x) => x.value)) === 'mgr.syn' && (await p.$eval('#oform [name=branch]', (x) => x.value)) === 'Jubail', 'the template fills the defaults');
    ok(/Filled from the Field Crew template/.test(await p.textContent('#tplnote')), 'and says so');
    await p.close();
    p = await open('hr-onboarding.html', '#bulk'); await p.click('#bulk'); await p.waitForSelector('#btx');
    const d = new Date(Date.now() + 20 * 86400000).toISOString().slice(0, 10);
    await p.fill('#btx', 'name,employee_id,job_title,department,start_date,manager\nAli Syn,E9001,Technician,Field Crew,' + d + ',mgr.syn\nSara Syn,E9002,Engineer,Field Crew,' + d + ',mgr.syn\nBad Syn,E9003,Clerk,No Such Dept,' + d + ',mgr.syn');
    await p.click('#bgo'); await p.waitForFunction(() => /raised/.test(document.getElementById('bmsg').textContent), null, { timeout: 10000 });
    ok(/2 raised, 1 not/.test(await p.textContent('#bmsg')) && /department/.test(await p.textContent('#bout')), 'several joiners at once, the bad row named: ' + await p.textContent('#bmsg'));
    ok(e.app.store.collection('onboarding').all().filter((r) => r.department === 'Field Crew' && r.laptop_profile === 'power').length === 2, 'created with the template');
    await p.close();
    // several leavers at once on the offboarding page: the dialog posts each row and names the failures
    p = await open('hr-offboarding.html', '#bulk'); await p.click('#bulk'); await p.waitForSelector('#btx');
    await p.fill('#btx', 'name,employee_id,username,department,last_day,manager,reason\nBad Row Syn,E-1,not valid!,Field Crew,' + d + ',mgr.syn,resignation');
    await p.click('#bgo'); await p.waitForFunction(() => /raised|not/.test(document.getElementById('bmsg').textContent), null, { timeout: 10000 });
    ok(/0 raised, 1 not/.test(await p.textContent('#bmsg')) && /rows\[0\]: username/.test(await p.textContent('#bout')), 'several leavers: the bad row named: ' + await p.textContent('#bout'));
    await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open('departments.html', '#dl table'); ok(await p.$eval('#addd', (x) => x.hidden) && !(await p.$('[data-ed]')), 'a viewer reads only'); await p.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'); ok(nav.includes('"h": "departments.html"') && / departments\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' departments checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
