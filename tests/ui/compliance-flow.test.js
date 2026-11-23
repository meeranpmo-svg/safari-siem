// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for compliance-flow.html (Compliance -> Compliance Automation Flow) against stubs in the shape of /api/itam/controls-intel
// (its chain), /api/itam/exec-dashboard and /api/soc/collection/live with SYNTHETIC data: the eight-stage flow lit from each source
// (a stage whose source is missing reads not connected); the Requirement -> Control -> Evidence chain with a break drawn in red; a
// framework filter; a control's detail; breaks list; ML reliability, regression and leverage; with the engine missing nothing is drawn;
// the portal's "chain" view maps to this page; menu entry and installer; hostile text stays text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node compliance-flow.test.js [screenshot.png]
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const R = (fw, id, title) => ({ fw, id, title });
const CHAIN = { chain: [
  { key: 'patch', name: 'Critical patches', state: 'pass', metric: '98% of servers patched', detail: '2 of 120 pending', reliability: 93, days: 30, policy_pct: 80, policies: ['POL-07 Patch management (80%)'], requirements: [R('sama', '3.3.17', 'SAMA CSF 3.3.17'), R('nca', '2-10-3', 'Vulnerability management'), R('iso', 'A.8.8', 'Technical vulnerabilities')], requirements_total: 3 },
  { key: 'backup', name: 'Backups', state: 'fail', metric: '3 critical servers without a backup <img src=x onerror=alert(1)>', detail: '', reliability: 40, days: 30, regression: '2026-10-20', policies: [], requirements: [R('sama', '3.3.13', 'SAMA CSF 3.3.13'), R('iso', 'A.8.13', 'Information backup')], requirements_total: 2 },
  { key: 'virt', name: 'Virtualization reporting', state: 'unknown', metric: '', detail: 'vCenter not connected', reliability: null, days: 0, policies: [], requirements: [R('nca', '2-3-1', 'Asset hardening')], requirements_total: 1 },
  { key: 'roles', name: 'Roles assigned', state: 'partial', metric: '7 of 10 people have a job role', detail: '', reliability: 70, days: 30, policies: [], requirements: [R('sama', '3.3.5', 'SAMA CSF 3.3.5'), R('iso', 'A.8.13', 'Information backup')], requirements_total: 2, open_action: true }],
  framework_names: { sama: 'SAMA CSF', nca: 'NCA ECC', iso: 'ISO 27001' }, ring: { value: 56 }, sections: [] };
const EXEC = { kpis: [{ key: 'compliance.sama', label: 'SAMA CSF + IA score', value: 71 }, { key: 'compliance.nca', label: 'NCA ECC score', value: 64 }], ml: { days: 30 }, ai: { enabled: false, reason: 'synthetic' } };
const LIVE = { counts: { live: 7, total: 9, paused: 0 }, collector: { quiet: false } };
(async () => {
  let CTRL = true;
  const srv = http.createServer((req, res) => { const u = req.url.split('?')[0];
    const j = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return j(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/controls-intel') return CTRL ? j(200, CHAIN) : j(404, { error: 'not installed' });
    if (u === '/api/itam/exec-dashboard') return j(200, EXEC);
    if (u === '/api/soc/collection/live') return j(200, LIVE);
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return j(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/compliance-flow.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [], dialogs = [];
  const p = await browser.newPage({ viewport: { width: 1500, height: 1100 }, deviceScaleFactor: process.argv[2] ? 2 : 1 });
  p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });
  await p.goto(base); await p.waitForSelector('#chain svg');
  const s = await p.evaluate(() => ({ stages: [...document.querySelectorAll('#flow [data-stage]')].map((a) => a.getAttribute('data-stage') + ':' + a.getAttribute('href')), flow: document.querySelector('#flow svg').getAttribute('aria-label'),
    ctl: document.querySelectorAll('#chain [data-ctl]').length, red: [...document.querySelectorAll('#chain path')].filter((x) => x.getAttribute('stroke') === '#ff7b72').length,
    breaks: document.getElementById('breaks').innerText, ml: document.getElementById('ml').innerText, kk: document.getElementById('kk').innerText.replace(/\s+/g, ' '), img: !!document.querySelector('main img'), tabs: document.getElementById('tabs').innerText }));
  ok(s.stages.length === 8 && s.stages[0] === 'src:live-status.html' && s.stages[4] === 'ctl:security-controls.html', 'eight stages, each linked to its page: ' + s.stages.join(' '));
  ok(/7 \/ 9 feeds live/.test(s.flow) && /3 \/ 4 measured/.test(s.flow) && /SAMA CSF \+ IA 71%/.test(s.flow) && /AI off/.test(s.flow), 'stages lit from their sources: ' + s.flow);
  ok(s.ctl === 4 && s.red >= 2, 'chain: four controls; the broken requirements drawn in red: ' + s.ctl + '/' + s.red);
  ok(/SAMA CSF 3\.3\.13/.test(s.breaks) && /NCA ECC 2-3-1/.test(s.breaks) && !/A\.8\.13/.test(s.breaks), 'breaks: only requirements with no working control (A.8.13 is kept up by a partial control): ' + s.breaks);
  ok(/Regressions/.test(s.ml) && /Backups \(passed 2026-10-20\)/.test(s.ml) && /fixing Backups restores 2 requirement/.test(s.ml) && /Critical patches/.test(s.ml), 'ML: regression, leverage, reliability: ' + s.ml.slice(0, 300));
  ok(/Controls measured 3 \/ 4/.test(s.kk) && /Breaks 2/.test(s.kk) && /Effective 56%/.test(s.kk) && !s.img, 'KPIs; hostile evidence text stays text: ' + s.kk);
  await p.click('#chain [data-ctl="roles"]'); const det = await p.textContent('#det');
  ok(/Roles assigned/.test(det) && /partial/.test(det) && /GRC action open/.test(det) && /SAMA CSF 3\.3\.5/.test(det), 'control detail: ' + det.slice(0, 200));
  await p.click('[data-fw="nca"]'); ok(await p.evaluate(() => document.querySelectorAll('#chain [data-ctl]').length === 2), 'framework filter: only controls reaching NCA ECC');
  if (process.argv[2]) { await p.click('[data-fw="all"]'); await p.screenshot({ path: process.argv[2], fullPage: true }); }
  CTRL = false; await p.reload(); await p.waitForSelector('#flow svg'); await p.waitForTimeout(300);
  ok(/not installed/.test(await p.textContent('#chain')) && /Security Controls not installed/.test(await p.getAttribute('#flow svg', 'aria-label')), 'engine missing: the chain says so, the stage reads not connected');
  const nav = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'), menu = fs.readFileSync(path.join(DASH, 'vendor/zyb-menu.js'), 'utf8'), early = fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8');
  ok(/"h": "compliance-flow\.html"/.test(nav) && /compliance-flow\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')) && /chain: 'compliance-flow\.html'/.test(menu) && /chain: 'compliance-flow\.html'/.test(early), 'menu, installer and the portal chain view mapped here');
  ok(!errs.length && !dialogs.length, 'no page errors or dialogs: ' + errs.concat(dialogs).join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
