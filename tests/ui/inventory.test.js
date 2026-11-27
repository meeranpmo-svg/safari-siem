// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/inventory.html against the REAL ITAM engine (engine/inventory-intel.js + the asset routes) with
// a SYNTHETIC register: KPI tiles filter (duplicates, not seen), facets, search, sort, columns, CSV export; the drawer shows the
// record with what is missing and the duplicate link; edit saves (and a stale edit is refused); lifecycle needs a reason; bulk set site;
// add an asset; #asset= opens one; viewers cannot change; escaped; the portal itam-assets redirect; menu + installer.
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
  const A = e.app.store.collection('assets'), ago = (d) => new Date(Date.now() - d * 86400000).toISOString(), now = new Date().toISOString();
  for (let i = 0; i < 6; i++) A.put({ id: 'w' + i, name: 'WS-' + i, type: 'workstation', status: 'in_use', networked: true, site: i < 3 ? 'Riyadh' : 'Jeddah', serial: 'SER' + i, mac: '00:11:22:33:44:0' + i, model: 'SYN-100', vendor: 'SynV', owner: 'o' + i, last_seen: ago(1), updated_at: now });
  A.put({ id: 'dup', name: 'WS-0 copy ' + XSS, type: 'workstation', status: 'in_use', serial: 'SER0', last_seen: ago(1), updated_at: now });
  A.put({ id: 'gone', name: 'SRV-GONE', type: 'server', status: 'in_use', networked: true, site: 'Jeddah', last_seen: ago(120), updated_at: now });
  let WHO = OP;
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
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'inventory.html');
    ok(await wait(p, () => /Possible duplicates/.test(document.getElementById('kp').innerText)), 'KPI tiles');
    ok(await p.evaluate(() => !window.__xss) && !(await p.$('#tbl img')), 'names escaped');
    ok(/SER0[\s\S]*serial/.test(await txt(p, 'dups')) || /WS-0/.test(await txt(p, 'dups')), 'duplicate pair listed');
    await p.click('[data-iss="duplicate"]'); let t = await txt(p, 'tbl'); ok(/WS-0/.test(t) && !/WS-3/.test(t), 'duplicates tile filters');
    await p.click('[data-iss="duplicate"]'); await p.click('[data-iss="stale"]'); t = await txt(p, 'tbl'); ok(/SRV-GONE/.test(t) && !/WS-1/.test(t), 'not-seen tile filters');
    await p.click('[data-iss="stale"]');
    await p.check('[data-fk="site"][data-fv="Jeddah"]'); t = await txt(p, 'tbl'); ok(/WS-4/.test(t) && !/WS-1\b/.test(t), 'site facet');
    await p.uncheck('[data-fk="site"][data-fv="Jeddah"]');
    await p.fill('#q', 'SER5'); t = await txt(p, 'tbl'); ok(/WS-5/.test(t) && !/WS-4/.test(t), 'search by serial'); await p.fill('#q', '');
    await p.click('#b-cols'); await p.check('[data-col="department"]'); ok(/Department/.test(await txt(p, 'tbl')), 'columns chosen'); await p.click('#b-cols');
    const dl = p.waitForEvent('download'); await p.click('#b-csv'); const d = await dl; ok(/itam-inventory-/.test(d.suggestedFilename()), 'CSV export');
    // Excel asset document: a real workbook with Summary, All assets (every field), a sheet per type, Warranty & end of life and Report
    const xd = p.waitForEvent('download'); await p.click('#b-xlsx'); const xf = await xd; ok(/^asset-register-\d{4}-\d{2}-\d{2}\.xlsx$/.test(xf.suggestedFilename()), 'Excel export: ' + xf.suggestedFilename());
    const book = JSON.parse(require('child_process').execFileSync('python3', ['-I', '-c', 'import sys,zipfile,json;z=zipfile.ZipFile(sys.argv[1]);print(json.dumps({n:z.read(n).decode("utf8") for n in z.namelist() if n.endswith(".xml")}))', await xf.path()]).toString());
    const wb = book['xl/workbook.xml'], names = [...wb.matchAll(/<sheet name="([^"]+)"/g)].map((m) => m[1]);
    ok(names[0] === 'Summary' && names[1] === 'All assets' && names.includes('workstation') && names.includes('server') && names.includes('Warranty &amp; end of life') && names[names.length - 1] === 'Report', 'sheets: ' + names.join(' | '));
    const all = book['xl/worksheets/sheet2.xml'], nRows = (all.match(/<row /g) || []).length - 1;
    ok(nRows === e.app.store.collection('assets').all().filter((x) => !['retired', 'disposed'].includes(x.status)).length, 'All assets: every active asset (' + nRows + ')');
    ok(/Platform ID/.test(all) && /Warranty end/.test(all) && /Purchased/.test(all) && /Memory GB/.test(all), 'All assets: every field, not only the columns on screen');
    ok(/By type/.test(book['xl/worksheets/sheet1.xml']) && /End of life/.test(book['xl/worksheets/sheet1.xml']), 'Summary: by type and the end-of-life position');
    const rep = book['xl/worksheets/sheet' + names.length + '.xml']; ok(/nora\.syn|unknown/.test(rep) && /active assets only/.test(rep) && /PDPL/.test(rep), 'Report: who, the filter and the PDPL note');
    ok(!/<img src=x/.test(all) || /&lt;img/.test(all), 'a hostile name is text in the workbook');
    // import: the export comes back with one new row - preview first (nothing written), then import; existing rows update, never duplicate
    const exp = fs.readFileSync(await d.path(), 'utf8'); ok(/^# ITAM inventory export/.test(exp), 'the export starts with its note line');
    const hdr = exp.split('\r\n')[1].split(','), row = hdr.map((h) => h === '"Name"' ? '"WS-NEW-SYN"' : h === '"Serial"' ? '"SER-NEW-SYN"' : '""');
    const before = e.app.store.collection('assets').all().length;
    await p.setInputFiles('#imp-file', { name: 'inv-back.csv', mimeType: 'text/csv', buffer: Buffer.from(exp + '\r\n' + row.join(',')) });
    ok(await wait(p, () => /preview, nothing written yet/.test((document.getElementById('imp') || {}).innerText || '')), 'import preview shown');
    ok(e.app.store.collection('assets').all().length === before, 'the preview wrote nothing');
    ok(/Quality/.test(await txt(p, 'imp')) && /Import \d+ asset/.test(await txt(p, 'imp')), 'computed columns listed as not imported; import button with the count');
    await p.click('#imp-go'); ok(await wait(p, () => /Imported/.test(document.getElementById('imp').innerText) && /1 new/.test(document.getElementById('imp').innerText)), 'imported: 1 new, the rest updated');
    ok(e.app.store.collection('assets').all().length === before + 1 && e.app.store.collection('assets').all().some((x) => x.serial === 'SER-NEW-SYN'), 'exactly one asset added');
    await p.click('#imp-x');
    // drawer
    await p.evaluate(() => document.querySelector('[data-id="gone"]').click());
    ok(await wait(p, () => /Missing/.test(document.getElementById('drw').innerText)), 'drawer: what is missing');
    await p.click('[data-dt="edit"]'); await p.fill('[data-e="serial"]', 'SYN-GONE-1'); await p.fill('[data-e="owner"]', 'infra.syn'); await p.click('#e-save');
    ok(await wait(p, () => /Saved/.test(document.body.innerText)), 'edit saved');
    ok(A.get('gone').serial === 'SYN-GONE-1' && A.get('gone').locked.serial, 'stored and locked');
    // a stale edit (someone changed it meanwhile)
    await p.click('[data-dt="edit"]'); A.put(Object.assign(A.get('gone'), { updated_at: new Date(Date.now() + 1000).toISOString() }));
    await p.fill('[data-e="owner"]', 'someone.else'); await p.click('#e-save');
    ok(await wait(p, () => /changed by someone else/.test((document.getElementById('e-err') || {}).innerText || '')), 'a conflicting edit is refused');
    // lifecycle
    await p.click('[data-dt="life"]'); await p.click('[data-life="retire"]'); ok(/reason first/.test(await txt(p, 'l-err')), 'lifecycle needs a reason');
    await p.fill('#l-why', 'decommissioned'); await p.click('[data-life="retire"]');
    ok(await wait(p, () => /Status changed/.test(document.body.innerText)), 'retired'); ok(A.get('gone').status === 'retired', 'stored');
    await p.click('#d-x');
    // bulk set site
    await p.check('[data-sel="w1"]'); await p.check('[data-sel="w2"]'); await p.fill('#bk-v', 'Dammam'); await p.click('#bk-go');
    ok(await wait(p, () => /2 asset\(s\) updated/.test(document.body.innerText)), 'bulk update'); ok(A.get('w1').site === 'Dammam' && A.get('w2').site === 'Dammam', 'stored');
    // merge and delete are offered on the selection; a merge needs exactly the two records of one machine
    await p.check('[data-sel="w1"]'); ok(!!(await p.$('#bk-merge')) && !!(await p.$('#bk-del')), 'merge and delete on the selection');
    await p.click('#bk-merge'); ok(await wait(p, () => /Select exactly the two records/.test(document.body.innerText)), 'a merge needs two records'); await p.click('#bk-x');
    // add
    await p.click('#b-add'); await p.click('#n-save'); ok(/Name is required/.test(await txt(p, 'n-err')), 'add checks the name');
    await p.fill('#n-name', 'LT-NEW-SYN'); await p.selectOption('#n-type', 'laptop'); await p.fill('#n-serial', 'SYNLT1'); await p.click('#n-save');
    ok(await wait(p, () => /LT-NEW-SYN/.test(document.getElementById('drw').innerText) && /Added/.test(document.body.innerText)), 'asset added and opened');
    // hash + viewer
    const q2 = await browser.newPage(); WHO = VW; q2.on('pageerror', (x) => errs.push(x.message)); await q2.goto(base + 'inventory.html#asset=w3');
    ok(await wait(q2, () => /WS-3/.test(document.getElementById('drw').innerText)), '#asset= opens it');
    await q2.click('[data-dt="edit"]'); await q2.fill('[data-e="owner"]', 'x'); await q2.click('#e-save');
    ok(await wait(q2, () => /Operators and administrators change assets/.test(document.getElementById('e-err').innerText)), 'viewer cannot change');
    await q2.close(); await p.close();
    ok(/'itam-assets': 'inventory\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal Inventory view redirects here');
    ok(/ inventory\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(/"h": "inventory.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
