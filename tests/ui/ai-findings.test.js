// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/ai-findings.html against the REAL ITAM engine (engine/findings-intel.js + the findings routes) with
// SYNTHETIC findings: KPI tiles filter (high, came back), the queue is ordered by priority, search, the drawer explains the priority
// and links to the fixing page, dismiss needs a reason, accept from the drawer, bulk dismiss with a reason, the Decided tab lists it and
// reopens it, learning flags a noisy kind, hotspots and trend, the AI tab says the model is not configured (runs disabled); viewers
// cannot decide; titles escaped; the portal itam-ai redirect; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-findings.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const A = e.app.store.collection('assets'), F = e.app.store.collection('findings'), ago = (d) => new Date(Date.now() - d * 86400000).toISOString(), now = new Date().toISOString();
  A.put({ id: 'core', name: 'SRV-SYN-CORE', type: 'server', status: 'in_use', site: 'Riyadh', owner: 'infra.syn', classification: 'secret', cia: { c: 'high', i: 'high', a: 'high' }, updated_at: now });
  A.put({ id: 'lt1', name: 'LT-SYN-1', type: 'laptop', status: 'in_use', site: 'Jeddah', updated_at: now });
  let k = 0; const put = (o) => { const id = 'fnd-syn-' + (++k); F.put(Object.assign({ id, key: 'k' + k, kind: 'missing_owner', severity: 'low', asset_id: 'lt1', licence_id: null, title: 'SYN finding ' + k, detail: 'synthetic', evidence: { field: 'owner' }, status: 'open', ai_label: 'AI — verify', created_at: ago(2) }, o, { id })); return id; };
  put({ kind: 'warranty_expired', severity: 'high', asset_id: 'core', title: 'Warranty expired on SRV-SYN-CORE', created_at: ago(45), reopened_at: ago(1) });
  put({ kind: 'missing_location', title: 'No location ' + XSS });
  put({ kind: 'missing_location', title: 'No location LT-SYN-1 (b)' });
  put({ kind: 'missing_owner', severity: 'medium', title: 'No owner on LT-SYN-1' });
  for (let i = 0; i < 6; i++) put({ kind: 'missing_location', status: 'dismissed', reason: 'remote worker', created_at: ago(20), dismissed_at: ago(18), title: 'old ' + i });
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
    await p.goto(base + 'ai-findings.html');
    ok(await wait(p, () => /Top priority/.test(document.getElementById('kp').innerText) && document.querySelector('#tbl tr.rw')), 'KPIs and queue');
    ok(await p.evaluate(() => !window.__xss) && !(await p.$('#tbl img')), 'titles escaped');
    ok(await p.evaluate(() => /SRV-SYN-CORE/.test(document.querySelector('#tbl tr.rw').innerText)), 'the critical, old, recurring finding is first');
    await p.click('[data-kp="high"]'); let t = await txt(p, 'tbl'); ok(/Warranty expired/.test(t) && !/No owner/.test(t), 'high tile filters');
    await p.click('[data-kp="high"]'); await p.click('[data-kp="rec"]'); t = await txt(p, 'tbl'); ok(/came back/.test(t) && !/No owner/.test(t), 'came-back tile filters'); await p.click('[data-kp="rec"]');
    await p.fill('#q', 'owner'); t = await txt(p, 'tbl'); ok(/No owner/.test(t) && !/Warranty/.test(t), 'search'); await p.fill('#q', '');
    // drawer
    await p.evaluate(() => document.querySelector('#tbl tr.rw td:nth-child(3)').click());
    ok(await wait(p, () => /Why priority/.test(document.getElementById('drw').innerText)), 'drawer opens');
    t = await txt(p, 'drw'); ok(/classified secret/.test(t) && /open 45 days/.test(t) && /came back/.test(t), 'priority explained');
    ok(/Fix in Renewals & Expiry/.test(t), 'links to the fixing page');
    await p.click('#d-d'); ok(/Say why/.test(await txt(p, 'd-e')), 'dismiss needs a reason');
    await p.click('#d-a'); ok(await wait(p, () => /1 finding accepted/.test(document.body.innerText)), 'accepted from the drawer');
    ok(F.get('fnd-syn-1').status === 'accepted' && F.get('fnd-syn-1').accepted_by === OP.user, 'stored with who');
    // bulk dismiss
    await p.waitForFunction(() => !/Warranty expired/.test(document.getElementById('tbl').innerText));
    await p.check('[data-sel="fnd-syn-2"]'); await p.check('[data-sel="fnd-syn-3"]'); ok(/2 selected/.test(await txt(p, 'bulkn')), 'selection counted');
    await p.click('#bk-d'); ok(await wait(p, () => /Say why/.test(document.body.innerText)), 'bulk dismiss needs a reason');
    await p.fill('#bk-r', 'remote worker, synthetic'); await p.click('#bk-d');
    ok(await wait(p, () => /2 findings dismissed/.test(document.body.innerText)), 'bulk dismissed'); ok(F.get('fnd-syn-3').status === 'dismissed' && F.get('fnd-syn-3').reason === 'remote worker, synthetic', 'stored with the reason');
    // decided + reopen
    await p.click('[data-t="done"]'); ok(await wait(p, () => /remote worker, synthetic/.test(document.getElementById('done').innerText)), 'decided tab lists it');
    await p.click('[data-reopen="fnd-syn-3"]'); ok(await wait(p, () => /1 finding reopened/.test(document.body.innerText)), 'reopened'); ok(F.get('fnd-syn-3').status === 'open', 'stored');
    // learning, hotspots
    await p.click('[data-t="learn"]'); t = await txt(p, 'learn'); ok(/No location/.test(t) && /noisy/.test(t) && /remote worker/.test(t), 'learning flags a noisy kind with its reason');
    await p.click('[data-t="hot"]'); ok(/LT-SYN-1/.test(await txt(p, 'h-a')) && /Jeddah/.test(await txt(p, 'h-s')), 'hotspots'); ok(await p.$('#trend .chart'), 'trend chart');
    // AI
    await p.click('[data-t="ai"]'); ok(await wait(p, () => !/Loading/.test(document.getElementById('ai-st').innerText)), 'AI status shown');
    ok(await p.evaluate(() => document.querySelector('[data-run="refresh"]').disabled), 'AI runs disabled while the model is not ready');
    ok(/No refresh plan yet/.test(await txt(p, 'plan')), 'honest empty refresh plan');
    // viewer
    const q2 = await browser.newPage(); WHO = VW; q2.on('pageerror', (x) => errs.push(x.message)); await q2.goto(base + 'ai-findings.html');
    await wait(q2, () => document.querySelector('#tbl tr.rw'));
    await q2.evaluate(() => document.querySelector('#tbl tr.rw td:nth-child(3)').click()); await wait(q2, () => document.getElementById('d-a'));
    await q2.click('#d-a'); ok(await wait(q2, () => /Operators and administrators decide/.test(document.getElementById('d-e').innerText)), 'viewer cannot decide');
    await q2.close(); await p.close();
    // honest empty page
    WHO = OP; for (const f of F.all()) F.put(Object.assign({}, f, { status: 'dismissed' }));
    const q3 = await browser.newPage(); q3.on('pageerror', (x) => errs.push(x.message)); await q3.goto(base + 'ai-findings.html');
    ok(await wait(q3, () => /No open findings/.test(document.getElementById('tbl').innerText)), 'empty state says what to connect'); await q3.close();
    ok(/'itam-ai': 'ai-findings\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal AI Findings view redirects here');
    ok(/ ai-findings\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(/"h": "ai-findings.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
