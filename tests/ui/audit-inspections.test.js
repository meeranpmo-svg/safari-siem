// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for IT Audit Inspections (dashboards/server/audit-inspections.html) against the REAL IT Asset Management engine
// (engine/audit-inspect.js) over SYNTHETIC records: starter + insurer checklists, start an inspection, answer yes / no / N/A, a
// photo upload, signatures on the pads, submit with a live score, a different person reviews, an action fixed and verified by
// two people, the dashboard with the site, the AI draft loaded into the builder (fake model) and saved, menu search, a viewer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-inspections.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true }), dir = fs.mkdtempSync(path.join(os.tmpdir(), 'insp-ui-'));
  class Fake { constructor() { this.messages = { create: async () => ({ model: 'synthetic-model', stop_reason: 'tool_use', usage: {}, content: [{ type: 'tool_use', id: 'a', name: 'draft_template', input: { name: 'Jeddah branch (synthetic)', category: 'Branch', pass_mark: 85, sections: [{ title: 'Cabinet', title_ar: 'الخزانة', items: [{ text: 'Cabinet locked', text_ar: 'الخزانة مقفلة', type: 'yesno', critical: true, evidence: 'on_fail', ref: 'NCA ECC 2-14' }] }] } }] }) }; } }
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }), inspectDir: dir, inspSdk: Fake, inspKey: () => 'k' });
  e.app.settings.update({ external_ai_allowed: true }, { user: 'syed', role: 'admin' });
  let who = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 30000 }).then(() => true, () => false);
  const sign = async (p, id) => { const b = await p.$eval('#' + id, (c) => { c.scrollIntoView({ block: 'center' }); const r = c.getBoundingClientRect(); return { x: r.left, y: r.top }; }); await p.mouse.move(b.x + 30, b.y + 40); await p.mouse.down(); await p.mouse.move(b.x + 120, b.y + 90, { steps: 6 }); await p.mouse.move(b.x + 200, b.y + 50, { steps: 6 }); await p.mouse.up(); };
  const png = path.join(dir, 'photo.png'); fs.writeFileSync(png, Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64'));
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'audit-inspections.html?standalone=1');
    ok(await wait(p, () => /No inspection submitted yet/.test(document.getElementById('v-dash').textContent)), 'empty dashboard says what to do');
    await p.click('[data-t="tpl"]');
    ok(await wait(p, () => /Claims & policy system access review/.test(document.getElementById('v-tpl').textContent) && /Third-party connectivity/.test(document.getElementById('v-tpl').textContent)), 'insurer checklists are in the library');
    // AI draft -> builder -> save
    await p.fill('#ai-req', 'Quarterly inspection of the Jeddah branch network cabinet'); await p.click('#ai-go');
    ok(await wait(p, () => !document.getElementById('builder').hidden && document.getElementById('b-name').value === 'Jeddah branch (synthetic)'), 'AI draft loaded into the builder');
    ok(await p.$eval('[data-k="text_ar"]', (x) => x.value === 'الخزانة مقفلة'), 'with Arabic');
    await p.click('#b-save'); ok(await wait(p, () => /Jeddah branch \(synthetic\)/.test(document.querySelector('#v-tpl table').textContent)), 'a person saved it');
    // run the branch inspection on the saved checklist
    await p.click('[data-t="ins"]');
    const tplId = await p.$eval('#n-tpl', (s) => [...s.options].find((o) => /Jeddah branch/.test(o.textContent)).value);
    await p.selectOption('#n-tpl', tplId); await p.fill('#n-site', 'JED-BRANCH-SYN'); await p.click('#n-go');
    ok(await wait(p, () => !document.getElementById('v-run').hidden && document.querySelectorAll('.it').length === 1), 'the runner opens');
    await p.click('[data-ans="i1_1"][data-v="no"]');
    ok(await wait(p, () => /1 failing/.test(document.querySelector('.score').textContent) && /critical failed/.test(document.querySelector('.score').textContent)), 'live score shows the critical failure');
    await p.fill('[data-note="i1_1"]', 'cabinet open, key in the lock (synthetic)'); await p.dispatchEvent('[data-note="i1_1"]', 'change');
    await p.waitForTimeout(900);
    await p.setInputFiles('[data-photo="i1_1"]', png);
    ok(await wait(p, () => document.querySelectorAll('.thumbs img').length === 1), 'photo evidence attached');
    await p.fill('#a-name', 'Branch Manager (synthetic)'); await sign(p, 'pad-i'); await sign(p, 'pad-a');
    await p.click('#submit');
    ok(await wait(p, () => /actions open/.test(document.querySelector('.score').textContent) && /Corrective actions \(1\)/.test(document.getElementById('v-run').textContent)), 'submitted: one corrective action');
    ok(/Another person reviews it/.test(await p.textContent('#v-run')), 'the inspector cannot review');
    // a different person reviews, the branch manager fixes, someone else verifies
    who = { user: 'omar.syn', role: 'operator' };
    await p.reload(); await p.click('[data-t="ins"]'); await p.click('[data-open]');
    ok(await wait(p, () => !!document.querySelector('[data-review="approve"]')), 'the reviewer sees approve / return');
    await p.click('[data-review="approve"]');
    ok(await wait(p, () => /Approved by/.test(document.getElementById('v-run').textContent)), 'approved');
    await p.fill('[data-act] [data-f="fixnote"]', 'cabinet locked, key with IT (synthetic)'); await p.click('[data-act] [data-a="fix"]');
    ok(await wait(p, () => /fix: cabinet locked/.test(document.getElementById('v-run').textContent)), 'fix recorded');
    ok(await p.$('[data-act] [data-a="verify"]') === null, 'the fixer cannot verify');
    who = { user: 'nora.syn', role: 'operator' };
    await p.reload(); await p.click('[data-t="ins"]'); await p.click('[data-open]');
    await wait(p, () => !!document.querySelector('[data-act] [data-a="verify"]')); await p.click('[data-act] [data-a="verify"]');
    ok(await wait(p, () => /Closed · report SHA-256/.test(document.getElementById('v-run').textContent)), 'closed with a hashed report');
    await p.click('#back'); await p.click('[data-t="dash"]');
    ok(await wait(p, () => /JED-BRANCH-SYN/.test(document.getElementById('v-dash').textContent)), 'the site is on the dashboard');
    await p.fill('#zs-q', 'goaudits'); await p.waitForTimeout(150);
    ok((await p.$$eval('#zs-best a b', (x) => x.map((y) => y.textContent))).includes('IT Audit Inspections'), 'menu search finds the page');
    // viewer
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'audit-inspections.html?standalone=1');
    ok(await wait(v, () => /JED-BRANCH-SYN/.test(document.getElementById('v-dash').textContent)), 'viewer sees site scores');
    ok(await v.evaluate(() => [...document.querySelectorAll('.tab[data-w]')].every((b) => b.hidden)), 'viewer: no work tabs');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
