// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Home page (dashboards/server/index.html) - the "Platform intelligence" band over stubbed, SYNTHETIC answers of the platform's own ML
// engines: infrastructure health with what fills up next, the AI engineers' trust (both engines, weighted) with what waits for a person,
// AI systems governed with paused / shadow AI, the last good backup; signals ranked across all four (a failed backup first, then a
// critical item waiting, then capacity forecasts...); each tile opens its page; a source that does not answer says why and gives no
// figure; a stale backup is flagged; hostile text stays text; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node home-intel.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">', iso = (h) => new Date(Date.now() - h * 3600000).toISOString();
let MODE = 'on';
const INFRA = { ring: { value: 72, why: 'synthetic' }, kpis: [{ label: 'Full within 14 days', value: 1 }, { label: 'High-risk targets', value: 2 }],
  sections: [{ id: 'actions', items: [{ title: 'Look at app-syn-01', sub: 'critical finding' }] }, { id: 'forecast', rows: [{ cells: ['app-syn-01 ' + XSS, 'fullest disk', '85 %', '+3 %', '2026-11-22 (2 d)', { text: '2026-11-25 (5 d)', tone: 'bad' }, 'R2 1'] }] }] };
const DUTY = (src, trust, needs) => ({ source: src, engineers: [{ id: src, name: 'AI ' + src, trust, open: 4, resolved_30d: 6 }], team: { over_sla: src === 'itam' ? 2 : 1, needs_you: needs.length }, needs, noisy: [], overlaps: [], recurring: [] });
const AIGOV = { ring: { value: 80 }, kpis: [{ label: 'Paused', value: 1 }, { label: 'Shadow AI', value: 2 }, { label: 'High-risk agents', value: 0 }] };
const BK = () => ({ status: MODE === 'stale' ? { last: { at: iso(40), ok: true, remote: 'ok' }, last_ok_at: iso(40), copies: 9, config: { remote: 'nas-syn:/b' } } : MODE === 'failed' ? { last: { at: iso(1), ok: false, error: 'disk full (synthetic)' }, last_ok_at: iso(30), copies: 9, config: { remote: 'nas-syn:/b' } } : { last: { at: iso(2), ok: true, remote: 'ok' }, last_ok_at: iso(2), copies: 14, config: { remote: 'nas-syn:/b' } }, queued: false });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x').pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed.syn', role: 'admin' });
    if (MODE !== 'off') {
      if (u === '/api/itam/infra-intel') return json(200, INFRA);
      if (u === '/api/itam/duty/intel') return json(200, DUTY('itam', 90, [{ id: 'DW-1', score: 12, severity: 'critical', title: 'SMB open to the internet', engineer_name: 'AI Pentester (syn)', why: 'needs a person · critical · past its 24 h SLA by 48 h' }]));
      if (u === '/api/soc/duty/intel') return json(200, DUTY('siem', 50, []));
      if (u === '/api/itam/aigov-intel') return json(200, AIGOV);
      if (u === '/api/soc/platform/backup') return json(200, BK());
    } else if (u === '/api/itam/aigov-intel') return json(403, { error: 'requires role viewer' });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : f.endsWith('.webp') ? 'image/webp' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/index.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(base); await p.waitForFunction(() => document.querySelectorAll('#pi-tiles a.pi-t').length === 4, null, { timeout: 20000 }); return p; };
  try {
    let p = await open();
    const tiles = await p.$$eval('#pi-tiles a.pi-t', (a) => a.map((x) => ({ href: x.getAttribute('href'), t: x.innerText.replace(/\s+/g, ' ') })));
    ok(tiles.map((t) => t.href).join(',') === 'infra-ai.html,ai-team.html,ai-governance.html,platform.html', 'four tiles, each opens its page');
    ok(/Infrastructure health.*72 \/ 100.*1 capacity limit\(s\) within 14 days · 2 high-risk/.test(tiles[0].t), 'infrastructure: ' + tiles[0].t);
    ok(/AI engineers · trust.*70 \/ 100.*1 item\(s\) waiting for a person · 3 past SLA/.test(tiles[1].t), 'AI engineers: trust weighted over both engines, needs and past SLA summed: ' + tiles[1].t);
    ok(/AI systems governed.*80 %.*1 paused · shadow AI 2/.test(tiles[2].t), 'AI governance: ' + tiles[2].t);
    ok(/Last good backup.*2 h ago.*copied off this server · 14 kept/.test(tiles[3].t), 'backup: ' + tiles[3].t);
    const sig = await p.$$eval('#pi-sig li', (l) => l.map((x) => x.innerText.replace(/\s+/g, ' ')));
    ok(/FORECAST|Forecast/.test(sig[0]) && /full 2026-11-25 \(5 d\)/.test(sig[0]), 'signals: the capacity forecast first: ' + sig[0]);
    ok(sig.some((s) => /SMB open to the internet/.test(s) && /past its 24 h SLA/.test(s)) && sig.some((s) => /1 AI feature\(s\) paused/.test(s)) && sig.some((s) => /2 unsanctioned AI product/.test(s)), 'signals from the AI engineers, governance and shadow AI');
    ok(sig.length <= 6 && await p.evaluate(() => !window.__xss && /<img src=x/.test(document.getElementById('pi-sig').innerText)), 'at most six signals; a hostile name stays text');
    MODE = 'failed'; p = await open();
    ok(/The last platform backup FAILED/.test(await p.textContent('#pi-sig li')) && /disk full/.test(await p.textContent('#pi-sig li')), 'a failed backup is the first signal, with its reason');
    ok(await p.$eval('#pi-tiles a[href="platform.html"]', (a) => a.classList.contains('bad')), 'backup tile marked bad');
    MODE = 'stale'; p = await open();
    ok(/No good backup in the last 26 hours/.test(await p.textContent('#pi-sig')), 'a stale backup is flagged');
    MODE = 'off'; p = await open();
    const off = await p.$$eval('#pi-tiles a.pi-t', (a) => a.map((x) => x.innerText.replace(/\s+/g, ' ')));
    ok(/not installed/.test(off[0]) && /not installed/.test(off[1]) && /no access/.test(off[2]) && /not installed/.test(off[3]), 'sources missing: each tile says why: ' + off.join(' | '));
    ok(!off.some((t) => /\d+ \/ 100|\d+ %/.test(t)), 'no figure without a source');
    ok(/No signal needs attention from the sources that answered/.test(await p.textContent('#pi-sig')), 'no invented signals');
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } catch (x) { console.error(x); bad++; } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'home-intel: FAIL ' : 'home-intel: OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
