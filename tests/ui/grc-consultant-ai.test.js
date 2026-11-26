// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI GRC Consultant page (ai-grc-consultant.html): the organisation's frameworks (from the roadmap - the brand setting) drive
// the subtitle, the KPI tiles and the suggested questions - an organisation without SAMA / the Insurance Authority (Safari: NCA
// ECC, ISO 27001, PDPL, NDMO) sees neither; charts (gaps by urgency, by kind - a click fills the question, frameworks touched)
// and "What the AI noticed" with figures; no gaps: no charts; hostile text stays text. Stubbed API, SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node grc-consultant-ai.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const gap = (severity, kind, title, framework) => ({ ref: 'gap:' + kind + ':' + title, severity, kind, title, recommendation: 'Fix it (synthetic)', framework });
const SAFARI = ['NCA ECC', 'ISO 27001', 'PDPL', 'NDMO'], INSURER = ['SAMA CSF', 'NCA ECC', 'ISO 27001', 'PDPL', 'Insurance Authority'];
const ROAD = (fw, empty) => ({ generated: Date.now(), total: empty ? 0 : 5, frameworks: fw, horizons: empty ? { now: [], next: [], later: [] } : {
  now: [gap('critical', 'drill-failed', 'ERP DR test failed', 'NCA ECC 3-1 (cybersecurity resilience) · ISO 27001 A.5.30'), gap('high', 'control-fail', 'Control "mfa" failing', 'NCA ECC 2 · ISO 27001 Annex A')],
  next: [gap('medium', 'policy-review', 'POL-01 ' + XSS + ': review overdue', 'NCA ECC 1-3 (policies and procedures) · ISO 27001 5.2 / A.5.1'), gap('medium', 'control-partial', 'Control "edr" only partly met', 'NCA ECC 2 · ISO 27001 Annex A')],
  later: [gap('low', 'owner-it', 'No IT owner on 3 assets', 'ISO 27001 A.5.9 · NCA ECC 2-1')] } });
let R = ROAD(SAFARI);
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'op.syn', role: 'operator' });
    if (u === '/api/itam/grc/roadmap') return j(200, R);
    if (u === '/api/itam/grc/consults') return j(200, { consults: [] });
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ai-grc-consultant.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(url); await p.waitForFunction(() => /updated/.test(document.getElementById('gen').textContent), null, { timeout: 15000 }); return p; };
  try {
    let p = await open();
    const sub = await p.textContent('#sub'), kp = await p.$eval('#kpis', (e) => e.innerText), qs = await p.$eval('#qs', (e) => e.innerText);
    ok(/NCA ECC, ISO 27001, PDPL, NDMO/.test(sub) && !/SAMA|Insurance Authority/.test(sub), 'subtitle names the organisation\'s frameworks: ' + sub);
    ok(!/IA requirements/i.test(kp), 'no Insurance Authority tile');
    ok(/NCA ECC controls/.test(qs) && /PDPL/.test(qs) && !/SAMA|Insurance Authority/.test(qs), 'suggested questions for its frameworks: ' + qs.replace(/\s+/g, ' | '));
    ok(/NCA ECC/.test(await p.$eval('#q', (e) => e.placeholder)), 'the question hint speaks NCA ECC');
    const lab = await p.$$eval('#aiband canvas', (x) => x.map((c) => c.getAttribute('aria-label') || ''));
    ok(lab.length === 3 && /Gaps by urgency/.test(lab[0]) && /Gaps by kind/.test(lab[1]) && /Frameworks touched/.test(lab[2]) && /NCA ECC/.test(lab[2]) && /ISO 27001/.test(lab[2]), 'three charts: ' + lab.map((l) => l.slice(0, 60)).join(' | '));
    const ins = (await p.$eval('#ins', (e) => e.innerText)).replace(/\s+/g, ' ');
    ok(/1 critical gaps need action now/.test(ins) && /1 recovery-test gaps/.test(ins) && /2 automated controls are failing or only partly met/.test(ins) && /1 policies are past their review date/.test(ins) && /1 ownership gaps/.test(ins) && /Most gaps map to (NCA ECC|ISO 27001) \(5\)/.test(ins), 'noticed with figures: ' + ins);
    await p.click('[data-sugg], #qs button'); ok(/NCA ECC|fix first/.test(await p.$eval('#q', (e) => e.value)), 'a suggested question fills the box');
    ok(!(await p.evaluate(() => window.PWN)) && !(await p.$('#road img')), 'hostile text stays text');
    await p.close();
    // a SAMA / IA organisation keeps its own wording
    R = ROAD(INSURER); p = await open();
    ok(/IA requirements/i.test(await p.$eval('#kpis', (e) => e.innerText)) && /Insurance Authority/.test(await p.$eval('#qs', (e) => e.innerText)), 'an insurer keeps the IA tile and questions');
    await p.close();
    // no gaps: no charts, no noticed list
    R = ROAD(SAFARI, true); p = await open();
    ok(await p.$eval('#aiband', (e) => e.hidden) && await p.$eval('#inscard', (e) => e.hidden), 'no gaps: nothing to chart'); await p.close();
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' grc-consultant-ai checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
