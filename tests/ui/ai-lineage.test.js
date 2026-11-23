// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for AI Data Lineage (ai-lineage.html) against the REAL engine (engine/ai-lineage.js over engine/data-posture.js) with a
// stubbed SIEM link and SYNTHETIC records (backend/itam/tests/data-posture-fixtures.js): the inline SVG graph renders actor / store /
// class nodes and edges, clicking a node (and Tab + Enter) shows what it is and the basis of each line, Microsoft 365 Copilot is drawn
// when licensed, the list view is a keyboard fallback, the store limit groups the rest as "+N more", a hostile AI app name stays
// text, a viewer sees store types and no names, the empty state when nothing is connected, phone width, no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-lineage.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers')), F = require(path.join(ITAM, 'tests', 'data-posture-fixtures'));
const DP = require(path.join(ITAM, 'engine', 'data-posture')), AL = require(path.join(ITAM, 'engine', 'ai-lineage'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const HOSTILE_APP = '<svg onload="window.__pwned=1">GPT-SYN';
(async () => {
  const T0 = Date.parse('2026-11-08T08:00:00Z');
  const e = await H.startApp({ noAi: true }), e2 = await H.startApp({ noAi: true });
  e.app.addons.pdpl = require(path.join(ITAM, 'engine', 'pdpl')).createPdpl(e.app, { now: () => T0 });
  F.seedLocal(e.app, T0);
  const reg = F.siemData(T0)['/shadow-ai/register']; reg.items[0].name = HOSTILE_APP;
  DP.registerDataPosture(e.app.srv, e.app, DP.createDataPosture(e.app, { now: () => T0, siem: F.fakeSiem(T0, { override: { '/shadow-ai/register': reg } }), noTimer: true }));
  AL.registerAiLineage(e.app.srv, e.app, AL.createAiLineage(e.app, { now: () => T0 }));
  DP.registerDataPosture(e2.app.srv, e2.app, DP.createDataPosture(e2.app, { now: () => T0, noTimer: true }));
  AL.registerAiLineage(e2.app.srv, e2.app, AL.createAiLineage(e2.app, { now: () => T0 }));
  let who = { user: 'nora.syn', role: 'operator' }, eng = e;
  const srv = http.createServer((req, res2) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res2.writeHead(code, { 'Content-Type': 'application/json' }); res2.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: eng.port, method: req.method, path: req.url, headers: h }, (r) => { res2.writeHead(r.statusCode, r.headers); r.pipe(res2); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res2.writeHead(403); return res2.end(); }
    fs.readFile(f, (err, d) => { if (err) { res2.writeHead(404); res2.end(); return; } res2.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res2.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const nodeSel = (label) => '#g .nd[aria-label^="' + label.replace(/"/g, '\\"') + ' - "]';
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'ai-lineage.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#g .nd').length >= 12 && document.querySelectorAll('#g path').length >= 15), 'graph renders nodes and edges');
    ok(await p.evaluate(() => ['AI actors', 'Data stores', 'Data classes'].every((h) => [...document.querySelectorAll('#g text.hd')].some((t) => t.textContent === h))), 'three columns');
    ok(await p.$(nodeSel('Microsoft 365 Copilot')) !== null, 'Microsoft 365 Copilot is drawn (licensed)');
    // click a node: its basis
    await p.click(nodeSel('Microsoft 365 Copilot'));
    ok(await wait(p, () => document.getElementById('detname') && document.getElementById('detname').textContent === 'Microsoft 365 Copilot' && /4 of 10 Copilot seat/.test(document.getElementById('det').textContent)), 'clicking Copilot shows why each line exists');
    ok(await p.evaluate(() => document.querySelectorAll('#g path.hl').length >= 2 && document.querySelectorAll('#g path.dim').length >= 1), 'its lines are highlighted, the rest dimmed');
    ok(/HR-Site-SYN/.test(await p.textContent('#det')), 'operator: store names');
    // keyboard: Tab to a node, Enter
    await p.focus(nodeSel('AI PDPL Consultant')); await p.keyboard.press('Enter');
    ok(await wait(p, () => document.getElementById('detname').textContent === 'AI PDPL Consultant' && /only the number of matches is kept/.test(document.getElementById('det').textContent)), 'Enter on a focused node shows its basis');
    // list view fallback
    await p.click('#list button[data-node="c.health"]');
    ok(await wait(p, () => document.getElementById('detname').textContent === 'Health' && /holding Health data/.test(document.getElementById('det').textContent)), 'the list view selects a node too');
    ok(/allowed by the Shadow AI register/.test(await p.textContent('#lgd')), 'legend');
    ok(/Other AI engineers/.test(await p.textContent('#notes')), 'what is not drawn is said');
    // hostile AI app name stays text
    ok(await p.evaluate((h) => [...document.querySelectorAll('#g .nd text')].some((t) => t.textContent.startsWith(h.slice(0, 20))) && document.getElementById('list').textContent.includes(h) && !document.querySelector('#g svg svg, #list svg') && !window.__pwned, HOSTILE_APP), 'a hostile AI app name stays text');
    // the store limit
    await p.selectOption('#max', '8');
    ok(await wait(p, () => !document.querySelector('#g .nd[aria-label^="+"]')), 'eight stores: all drawn');
    const before = await p.$$eval('#g .nd', (l) => l.length);
    ok(before >= 12, 'nodes at max 8');
    ok(e.app.store.auditTail(60).some((a) => a.action === 'ai.lineage.read' && a.by === 'nora.syn'), 'named read audited');
    // viewer: store types, no names
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'ai-lineage.html?standalone=1');
    ok(await wait(v, () => document.querySelectorAll('#g .nd').length > 0), 'viewer sees the graph');
    ok(await v.evaluate(() => !['HR-Site-SYN', 'alia.syn', 'claimsdocssyn', 'HRDB-SYN', 'CLAIMS-DB-SYN', 'owner.syn'].some((x) => document.body.textContent.includes(x))), 'viewer: no store or person name');
    ok(await v.evaluate(() => [...document.querySelectorAll('#g .nd')].some((g) => /^3 Azure storage accounts - /.test(g.getAttribute('aria-label')))), 'viewer: stores as types with counts');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: the page does not scroll sideways (the graph scrolls in its box)');
    // nothing connected
    eng = e2; who = { user: 'nora.syn', role: 'operator' };
    const z = await browser.newPage({ viewport: { width: 1300, height: 900 } }); z.on('pageerror', (x) => errs.push(x.message));
    await z.goto(base + 'ai-lineage.html?standalone=1');
    ok(await wait(z, () => /No AI actor reaches a data store yet/.test(document.getElementById('empty').textContent)), 'empty state says what to connect');
    ok(await z.evaluate(() => document.querySelectorAll('#g .nd').length === 0 && /Copilot is not judged/.test(document.getElementById('notes').textContent)), 'nothing drawn, and why');
    ok(!(await z.$('#zyb-err .ze')), 'no generic error banner');
  } finally { await browser.close(); srv.close(); await e.close(); await e2.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
