// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Cyber Resilience Command hero on the home page (dashboards/index.html) against stubs in the shape of
// /api/itam/exec-dashboard and /api/soc/collection/live with SYNTHETIC figures: the gauge shows the index, grade and the 30-day
// forecast marker; the history chart draws the days plus the dashed forecast; ML badges (trend, forecast, unusual day); five
// pillars with "not measured" and its reason; key figures with their ML verdicts; feed / decision / risk chips link to their
// pages; with nothing installed the hero says so and shows no number; hostile labels stay text; no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node home-command.test.js [screenshot.png]
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const day = (i) => new Date(Date.UTC(2026, 9, 5 + i)).toISOString().slice(0, 10);
const EXEC = { at: '2026-11-03T08:00:00Z', index: 72, grade: 'adequate', measured: 4, withheld_why: null,
  pillars: [{ id: 'cyber', name: 'Cyber security posture', weight: 30, page: 'ciso-dashboard.html', score: 68, measured: true }, { id: 'compliance', name: 'Regulatory compliance', weight: 25, page: 'report-center.html', score: 81, measured: true },
    { id: 'resilience', name: 'Resilience (DR & backup)', weight: 20, page: 'dr-studio.html', score: null, measured: false, why: 'DR Studio not installed' }, { id: 'operations', name: 'IT operations', weight: 15, page: 'servers-dashboard.html', score: 77, measured: true },
    { id: 'risk', name: 'Enterprise IT risk', weight: 10, page: 'risk-studio.html', score: 64, measured: true }],
  ml: { days: 30, trend: { per_week: 1.4, verdict: 'improving', days: 30 }, forecast_30d: 78, unusual: { today: 72, usual: 66, z: 3.4, direction: 'up' }, pillar_change: { cyber: 3, compliance: -2 } },
  history: Array.from({ length: 30 }, (_, i) => ({ day: day(i), index: 60 + Math.round(i * 0.4) })),
  attention: [], decisions_waiting: 4, risks: { open: 12, high: 3, over_appetite: 1 },
  kpis: [{ section: 'soc', key: 'soc.open', label: 'Open offenses <img src=x onerror=alert(1)>', value: 37, unit: '' }, { section: 'compliance', key: 'compliance.nca', label: 'NCA ECC score', value: 74, unit: '%' }, { section: 'assets', key: 'assets.health', label: 'Asset register health', value: 88, unit: '%' }],
  insights: [{ key: 'soc.open', label: 'Open offenses', verdict: 'worsening', forecast: 44, unusual: false }, { key: 'compliance.nca', label: 'NCA ECC score', verdict: 'improving', forecast: 79, unusual: true }],
  sections: [], sources: {}, ai: { enabled: false, reason: 'synthetic' }, can_snapshot: true };
const LIVE = { live_pct: 56, counts: { live: 5, total: 9, paused: 0, silent: 2, late: 1 }, findings: [], collector: { quiet: false } };
(async () => {
  let INSTALLED = true;
  const srv = http.createServer((req, res) => { const u = req.url.split('?')[0];
    const j = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return j(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/exec-dashboard') return INSTALLED ? j(200, EXEC) : j(404, { error: 'not installed' });
    if (u === '/api/soc/collection/live') return INSTALLED ? j(200, LIVE) : j(404, { error: 'not installed' });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return j(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/index.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [], dialogs = [];
  const p = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: process.argv[2] ? 2 : 1 });
  p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });
  await p.goto(base); await p.waitForSelector('#cmdGauge svg'); await p.waitForFunction(() => document.querySelectorAll('#cmdPillars a').length === 5);
  const s = await p.evaluate(() => ({ gauge: document.querySelector('#cmdGauge svg').getAttribute('aria-label'), grade: document.querySelector('#cmdGauge').textContent,
    fc: !!document.querySelector('#cmdGauge circle title'), spark: (document.querySelector('#cmdSpark svg') || { getAttribute: () => '' }).getAttribute('aria-label'), dashed: !!document.querySelector('#cmdSpark line[stroke-dasharray]'),
    badges: document.getElementById('cmdBadges').textContent, pil: [...document.querySelectorAll('#cmdPillars a')].map((a) => a.innerText.replace(/\s+/g, ' ').trim()),
    kp: [...document.querySelectorAll('#cmdKpis .k')].map((k) => k.innerText.replace(/\s+/g, ' ').trim()), chips: [...document.querySelectorAll('#cmdChips a')].map((a) => a.getAttribute('href') + ' ' + a.textContent.trim()),
    img: !!document.querySelector('#cmdKpis img'), pulse: document.getElementById('cmdPulse').className, canvas: !!document.getElementById('cmdNet').width }));
  ok(/health index 72 of 100/.test(s.gauge) && /ADEQUATE/.test(s.grade) && s.fc, 'gauge: index, grade, forecast marker: ' + s.gauge);
  ok(/30 days, now 72, forecast 78 in 30 days/.test(s.spark) && s.dashed, 'history chart with the dashed 30-day forecast: ' + s.spark);
  ok(/improving \+1\.4 \/ week/.test(s.badges) && /30-day forecast 78/.test(s.badges) && /unusual today: 72 vs usual 66/.test(s.badges), 'ML badges: ' + s.badges);
  ok(/Cyber security posture 68 weight 30% · ▲ \+3 in 7 days/.test(s.pil[0]) && /▼ -2 in 7 days/.test(s.pil[1]) && /not measured DR Studio not installed/.test(s.pil[2]), 'pillars with change and not-measured reason: ' + s.pil.join(' | '));
  ok(/Open offenses <img src=x onerror=alert\(1\)> 37 ▼ worsening 30 d: 44/.test(s.kp[0]) && /unusual today/.test(s.kp[1]) && !s.img, 'key figures with ML verdicts; a hostile label stays text: ' + s.kp.join(' | '));
  ok(s.chips.some((c) => /^live-status\.html 5 \/ 9 data feeds live/.test(c)) && s.chips.some((c) => /^my-work\.html 4 decisions waiting/.test(c)) && s.chips.some((c) => /^risk-studio\.html 3 high risks · 1 over appetite/.test(c)), 'chips: ' + s.chips.join(' | '));
  ok(s.pulse === '' && s.canvas, 'live pulse on while feeds report; the constellation is drawn');
  if (process.argv[2]) await p.screenshot({ path: process.argv[2], clip: { x: 0, y: 0, width: 1440, height: 1000 } });
  // nothing installed: no number, the reason, and where to connect
  INSTALLED = false; await p.reload(); await p.waitForSelector('#cmdGauge svg'); await p.waitForTimeout(400);
  const t = await p.evaluate(() => ({ gauge: document.getElementById('cmdGauge').textContent, grade: document.getElementById('cmdGrade').textContent, pil: document.querySelectorAll('#cmdPillars a').length, chips: document.getElementById('cmdChips').textContent, big: [...document.querySelectorAll('.t2c .big b')].map((b) => b.className + ':' + b.textContent) }));
  ok(/not measured/.test(t.gauge) && /Executive Dashboard not installed/.test(t.grade) && t.pil === 0 && /Live Status not installed/.test(t.chips) && /Connections & Setup/.test(t.chips), 'not installed: no number, says why, points to Connections: ' + JSON.stringify(t));
  ok(t.big.every((b) => /^txt:/.test(b)), 'a "not installed" card is plain text, not a giant figure: ' + t.big);
  ok(!errs.length && !dialogs.length, 'no page errors or dialogs: ' + errs.concat(dialogs).join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
