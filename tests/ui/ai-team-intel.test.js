// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Engineering Team (ai-team.html) - the AI / ML tab, over the REAL duty-intel analysis (engine/duty-intel.js) of SYNTHETIC work items
// served as /api/soc/duty/intel and /api/itam/duty/intel: team tiles, engineers least trusted first with precision / verified fixes /
// MTTR / backlog sparkline, a row opens its trust points, needs-you ranked with the reason, noisy checks, one target in two queues,
// fixes that do not hold, a hostile title stays text, a side not installed is named, no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-team-intel.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
const DI = require('../../backend/itam/engine/duty-intel');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now(), H = 3600000, D = 86400000, XSS = '<img src=x onerror="window.__xss=1">';
const soc = [];
for (let k = 0; k < 5; k++) soc.push({ id: 'N' + k, engineer: 'network', kind: 'iface', severity: 'medium', status: 'closed', close_code: k < 4 ? 'false-positive' : 'fixed', detected_at: NOW - (20 + k) * D, resolved_at: NOW - (19 + k) * D, last_seen: NOW - H, target: { id: 'r1', name: 'R1-syn' } });
soc.push({ id: 'N9', engineer: 'network', kind: 'down', severity: 'critical', status: 'needs-human', title: 'Core switch down ' + XSS, detected_at: NOW - 3 * D, last_seen: NOW - H, target: { id: 'r1', name: 'R1-syn' }, reopened: 2 });
soc.push({ id: 'S1', engineer: 'security', kind: 'edr', severity: 'high', status: 'open', title: 'EDR missing', detected_at: NOW - 2 * H, last_seen: NOW - H, target: { id: 'r1', name: 'R1-syn' } });
const itam = []; for (let k = 0; k < 4; k++) itam.push({ id: 'D' + k, engineer: 'desktop', kind: 'patch', severity: 'high', status: 'resolved', resolution: 'verified-fixed', changes: ['c'], detected_at: NOW - (k + 1) * D, resolved_at: NOW - (k + 1) * D + 6 * H, last_seen: NOW - H });
let ITAM_UP = true;
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'nora.syn', role: 'operator' });
    if (u === '/api/soc/duty/intel') return json(200, DI.analyse({ items: soc, engineers: [{ id: 'network', name: 'AI Network Engineer (syn)' }, { id: 'security', name: 'AI Security Engineer (syn)' }], now: NOW, source: 'siem' }));
    if (u === '/api/itam/duty/intel') return ITAM_UP ? json(200, DI.analyse({ items: itam, engineers: [{ id: 'desktop', name: 'AI Desktop Support (syn)' }], now: NOW, source: 'itam' })) : json(404, { error: 'not found' });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ai-team.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 20000 }).then(() => true, () => false);
  try {
    let p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); });
    await p.goto(base); await p.click('#attabs [data-t="ai"]');
    ok(await wait(p, () => document.querySelector('#dieng tr[data-dieng]')), 'AI / ML tab shows the engineers');
    const tiles = await p.textContent('#ditiles'); ok(/Team trust/.test(tiles) && /Needs you/.test(tiles), 'team tiles');
    const first = await p.textContent('#dieng tr[data-dieng="0"]'); ok(/AI Network Engineer/.test(first), 'least trusted first: ' + first.slice(0, 60));
    ok(/29 %/.test(first) && /4 FP \/ 5/.test(first), 'precision with its counts');
    ok(/100 %/.test(await p.textContent('#dieng')), 'verified fixes'); ok(await p.$$eval('#dieng svg polyline', (x) => x.length >= 3), 'backlog sparklines');
    await p.click('#dieng tr[data-dieng="0"]'); ok(await wait(p, () => /precision 29 %/.test(document.body.innerText) && /past their SLA/.test(document.body.innerText)), 'a row opens its trust points');
    await p.keyboard.press('Escape');
    const need = await p.textContent('#dineed'); ok(/Core switch down/.test(need) && /needs a person · critical · past its 24 h SLA/.test(need) && /re-opened 2x/.test(need), 'needs you ranked with the reason');
    ok(await p.evaluate(() => !window.__xss && /<img src=x/.test(document.getElementById('dineed').textContent)), 'a hostile title stays text');
    ok(/iface/.test(await p.textContent('#dinoisy')), 'noisy check'); ok(/R1-syn/.test(await p.textContent('#diover')) && /agree one owner/.test(await p.textContent('#diover')), 'one target, two queues');
    ok(/re-opened 2 times/.test(await p.textContent('#direc')), 'fixes that do not hold');
    ok((await p.textContent('#tc-ai')).trim() === '1', 'tab badge counts what needs you');
    ITAM_UP = false; p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(base); await p.click('#attabs [data-t="ai"]');
    ok(await wait(p, () => /IT Asset side: the team intelligence is not installed/.test(document.getElementById('dinote').textContent)), 'a side not installed is named');
    ok(await wait(p, () => document.querySelector('#dieng tr[data-dieng]')), 'the other side still shows');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } catch (x) { console.error(x); bad++; } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'ai-team-intel: FAIL ' : 'ai-team-intel: OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
