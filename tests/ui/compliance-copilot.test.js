// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Compliance AI Assistant page (compliance-copilot.html) against the REAL IT Asset Management engine with SYNTHETIC registers:
// tiles, charts, what the AI noticed, the 90-day plan, priorities with why (Arabic when switched); raise an action; the owner
// submits evidence, another administrator verifies; a control activity recorded and verified by someone else; a bilingual policy
// preview (Arabic right-to-left) sent to GRC; ask in Arabic; an administrator adds a company; a viewer cannot act; hostile text
// stays text; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node compliance-copilot.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ITAM = path.resolve(__dirname, '../../backend/itam');
const H = require(path.join(ITAM, 'tests/helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const REGS = async () => ({
  nca: { installed: true, rows: [{ id: '2-2-1', title: 'Identity and access management requirements ' + XSS, result: 'gap', severity: 'high' }, { id: '2-12-1', title: 'Event logs and monitoring', result: 'compliant' }, { id: '4-1-1', title: 'Third-party cybersecurity in contracts', result: 'not_measured' }] },
  iso27001: { installed: true, rows: [{ id: 'A.5.34', title: 'Privacy and protection of personal identifiable information', result: 'gap' }] },
  pdpl: { installed: true, rows: [{ id: 'P-03', title: 'A privacy policy is published', result: 'compliant' }, { id: 'P-04', title: 'Records of processing activities are kept', result: 'not_assessed' }] },
  ndmo: { installed: true, rows: [] }, aramco: { installed: true, rows: [] } });
(async () => {
  const e = await H.startApp({ noAi: true }); require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, copilotAiOff: true, copilotRegisters: REGS });
  let WHO = { user: 'op.syn', role: 'operator' };
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(WHO)); }
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/compliance-copilot.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  let PROMPTS = [];
  const open = async (sel) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(d.type() === 'prompt' ? (PROMPTS.shift() || '') : undefined)); await p.goto(url); await p.waitForSelector(sel, { timeout: 15000 }); return p; };
  const day = (k) => new Date(Date.now() + k * 86400000).toISOString().slice(0, 10);
  try {
    let p = await open('#pri table');
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' '); ok(/Realistic position \d+%/.test(kp) && /As recorded \d+%/.test(kp) && /Control activities \d+/.test(kp), 'tiles: ' + kp);
    ok((await p.$$('.g3 canvas')).length === 2, 'two charts');
    ok(/PDPL: 100% as recorded, 50% realistic/.test(await p.textContent('#ins')), 'what the AI noticed: realistic vs recorded');
    ok((await p.$$('#plan .month')).length === 3, 'a 90-day plan');
    ok(/Matters for Safari because/.test(await p.textContent('#pri')) && !(await p.evaluate(() => window.PWN)), 'priorities with why; hostile text stays text');
    if (process.env.SHOT) { await p.waitForTimeout(800); await p.screenshot({ path: process.env.SHOT }); }   // optional: a picture for review
    await p.check('#lang'); ok(/أهميته لـ/.test(await p.textContent('#pri')), 'why in Arabic'); await p.uncheck('#lang');
    // raise an action for the first priority, owned by owner.syn
    PROMPTS = ['owner.syn', day(20)]; await p.click('[data-raise="0"]'); await p.waitForTimeout(700);
    await p.click('[data-t="act"]'); await p.waitForSelector('#acts table'); ok(/owner\.syn/.test(await p.textContent('#acts')) && /open/.test(await p.textContent('#acts')), 'action raised');
    // control activity recorded by the operator
    await p.click('[data-t="duty"]'); PROMPTS = ['Veeam restore report Q4 (synthetic)']; await p.click('[data-done="main__restore_test"]');
    await p.waitForFunction(() => /awaiting verification/.test(document.getElementById('duties').textContent), null, { timeout: 8000 }).catch(() => {}); ok(/awaiting verification/.test(await p.textContent('#duties')) && /another person verifies/.test(await p.textContent('#duties')), 'recorded; another person verifies');
    // bilingual policy preview and send to GRC
    await p.click('[data-t="pol"]'); await p.selectOption('#ptpl', 'access'); await p.fill('#o-pw', '14'); await p.click('#pprev'); await p.waitForFunction(() => document.getElementById('dar').textContent.length > 100, null, { timeout: 8000 });
    ok(/at least 14 characters/.test(await p.textContent('#den')) && /14 حرفاً/.test(await p.textContent('#dar')) && (await p.$eval('#dar', (x) => x.getAttribute('dir'))) === 'rtl', 'English and Arabic (right to left)');
    await p.click('#pdraft'); await p.waitForFunction(() => /DRAFT/.test(document.getElementById('pdrafts').textContent), null, { timeout: 8000 }).catch(() => {}); ok(/DRAFT/.test(await p.textContent('#pdrafts')) && /draft/.test(await p.textContent('#pdrafts')), 'sent to GRC');
    // ask in Arabic
    await p.click('[data-t="ask"]'); await p.fill('#q', 'ما هي أولويات نظام حماية البيانات الشخصية؟'); await p.click('#ask'); await p.waitForSelector('#ans:not([hidden])');
    ok(/النسبة الواقعية 50%/.test(await p.textContent('#ans')), 'answered in Arabic: ' + (await p.textContent('#ans')).slice(0, 120));
    await p.close();
    // the owner submits evidence, another administrator verifies
    WHO = { user: 'owner.syn', role: 'operator' }; p = await open('#pri table'); await p.click('[data-t="act"]'); PROMPTS = ['IAM standard v1.0 in GRC (synthetic)']; await p.click('[data-sub]'); await p.waitForTimeout(700); await p.close();
    WHO = { user: 'admin.syn', role: 'admin' }; p = await open('#pri table'); await p.click('[data-t="act"]'); await p.click('[data-ver][data-d="accept"]');
    await p.waitForFunction(() => /closed/.test(document.getElementById('acts').textContent), null, { timeout: 8000 }).catch(() => {}); ok(/closed/.test(await p.textContent('#acts')), 'verified and closed by another administrator');
    await p.click('[data-t="duty"]'); await p.click('[data-dv="main__restore_test"][data-d="accept"]'); await p.waitForTimeout(700); ok(/on track/.test(await p.textContent('#duties')), 'control activity verified');
    // an administrator adds a company
    await p.click('[data-t="cos"]'); await p.click('#addco'); await p.fill('#cf [name=cid]', 'sfs'); await p.fill('#cf [name=cname]', 'Safari Facility Services (synthetic)'); await p.fill('#cf [name=name_ar]', 'سفاري للخدمات'); await p.check('#cf [name=fw][value=pdpl]'); await p.check('#cf [name=ln][value=manpower]'); await p.click('#cf button[type=submit]');
    await p.waitForFunction(() => /Safari Facility Services/.test(document.getElementById('cos').textContent), null, { timeout: 8000 }).catch(() => {}); ok(/Safari Facility Services/.test(await p.textContent('#cos')) && /Safari Facility Services/.test(await p.textContent('#co')), 'company added and selectable');
    await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open('#pri table'); ok(!(await p.$('[data-raise]')), 'a viewer raises nothing'); await p.click('[data-t="pol"]'); ok(await p.$eval('#pform', (x) => x.hidden), 'a viewer builds no policy'); await p.click('[data-t="cos"]'); ok(!(await p.$('#addco')), 'a viewer adds no company'); await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "compliance-copilot.html"') && / compliance-copilot\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' compliance-copilot checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
