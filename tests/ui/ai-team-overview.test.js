// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Engineering Team overview (ai-team.html + vendor/zyb-teamhome.js) over a STUBBED duty API with SYNTHETIC engineers and work:
// the readiness gauge and tiles add up both engines, what the team noticed names the critical desk / the approvals waiting / the late
// and not-connected engineers, the team is grouped by function with filters and a search, a tile opens the engineer's desk, the five
// charts draw, "For a person now" lists the items waiting with title and age and opens the item, an engineer the organisation does not
// have (brand engineers_off) is left out, a hostile engineer name and item title stay text, a side that is down is named; POC mode
// shows illustrative work items with one ribbon. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-team-overview.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now(), XSS = '<img src=x onerror=window.PWN=1>';
const eng = (id, name, o) => Object.assign({ id, name, on_duty: true, not_connected: false, late: false, last_error: null, last_patrol: NOW - 120000, open: 0, critical: 0, high: 0, resolved_24h: 0, by_status: {}, ai: { enabled: true, used_today: 2, cap: 50 } }, o);
const SOC = [eng('network', 'AI Network Engineer', { open: 4, critical: 1, by_status: { open: 1, investigating: 1, 'awaiting-approval': 2 }, resolved_24h: 2 }),
  eng('security', 'AI ' + XSS + ' Security', { open: 2, by_status: { diagnosed: 2 } }), eng('windows', 'AI Windows Admin', { late: true, open: 1, by_status: { 'fix-applied': 1 } }),
  eng('exchange', 'AI Exchange Admin', { open: 9, by_status: { open: 9 } })];
const ITAM = [eng('pdpl', 'AI PDPL Consultant', { open: 3, critical: 2, by_status: { 'needs-human': 1, open: 2 } }), eng('desktop', 'AI Desktop Support Engineer', { not_connected: true }),
  eng('itaudit', 'AI IT Auditor', { on_duty: false })];
const ITEMS = { soc: [{ id: 'DW-1', engineer: 'network', engineer_name: 'AI Network Engineer', severity: 'critical', status: 'awaiting-approval', title: 'core-syn-01: ' + XSS, first_seen: NOW - 3 * 3600e3 },
  { id: 'DW-2', engineer: 'exchange', engineer_name: 'AI Exchange Admin', severity: 'high', status: 'awaiting-approval', title: 'should not appear', first_seen: NOW }],
  itam: [{ id: 'DW-9', engineer: 'pdpl', engineer_name: 'AI PDPL Consultant', severity: 'high', status: 'needs-human', target: 'syn-share-01', created_at: new Date(NOW - 26 * 3600e3).toISOString() }] };
let ITAM_UP = true, opened = null;
(async () => {
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'syn.op', role: 'operator' });
    const m = /^\/api\/(soc|itam)\/duty\/(\w+)(?:\/([\w-]+))?/.exec(u.pathname);
    if (m) { if (m[1] === 'itam' && !ITAM_UP) return json(503, { error: 'down (synthetic)' });
      if (m[2] === 'engineers') return json(200, { engineers: m[1] === 'soc' ? SOC : ITAM, policy: { enabled: true } });
      if (m[2] === 'items' && m[3]) { opened = m[3]; return json(200, Object.assign({}, (ITEMS[m[1]] || []).find((x) => x.id === m[3]) || {}, { investigation: { summary: 'synthetic investigation' } })); }
      if (m[2] === 'items') return json(200, { items: ITEMS[m[1]] });
      if (m[2] === 'kpis') return json(200, { engineers: m[1] === 'soc' ? [{ engineer: 'network', name: 'AI Network Engineer', score: 72, kpis: [], domain: [] }] : [] });
      return json(200, { reports: [], engineers: [] }); }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ai-team.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (q) => { const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept());
    await p.goto(base + (q || '?standalone=1')); await p.waitForSelector('#zth-kp', { timeout: 20000 }); await p.waitForTimeout(400); return p; };
  try {
    let p = await open();
    const kp = (await p.textContent('#zth-kp')).replace(/\s+/g, ' ');
    ok(/5 \/ 6/.test(kp), 'engineers on duty, the organisation\'s only (exchange is off, one off duty): ' + kp);
    ok(/10 ?Open work/.test(kp) && /3 ?Critical/.test(kp) && /3 ?Waiting for a person/.test(kp) && /2 ?Fixed in 24 h/.test(kp), 'tiles add up both engines: ' + kp);
    ok(/50/.test(await p.textContent('#teamhome svg')), 'readiness: 3 of 6 on time = 50 %');
    const ins = await p.textContent('#zth-ins');
    ok(/3 critical item\(s\) open/.test(ins) && /PDPL Consultant \(2\)/.test(ins), 'noticed: the critical desks');
    ok(/Windows Admin/.test(ins) && /Desktop Support Engineer/.test(ins) && /off duty/.test(ins), 'noticed: late, not connected, off duty');
    ok(!/Exchange/.test(await p.textContent('#teamhome')), 'an engineer the organisation does not have is left out, with its work');
    const tm = await p.textContent('#zth-team');
    ok(/Security operations/.test(tm) && /GRC, compliance & risk/.test(tm) && /Audit/.test(tm), 'grouped by function');
    await p.click('[data-zth-fn="grc"]'); ok((await p.$$('#zth-team .zth-eng')).length === 1, 'filter by function');
    await p.click('[data-zth-fn=""]'); await p.fill('#zth-q', 'windows'); ok((await p.$$('#zth-team .zth-eng')).length === 1, 'search');
    await p.fill('#zth-q', ''); await p.selectOption('#zth-only', 'person'); ok((await p.$$('#zth-team .zth-eng')).length === 2, 'only those waiting for a person');
    await p.selectOption('#zth-only', 'attn'); ok((await p.$$('#zth-team .zth-eng')).length === 3, 'late, not connected or off');
    ok((await p.$$('#teamhome canvas')).length === 5, 'five charts');
    const need = (await p.textContent('#zth-need')).replace(/\s+/g, ' ');
    ok(/core-syn-01/.test(need) && /syn-share-01/.test(need) && /3 h ago/.test(need) && /26 h ago|1 d ago/.test(need), 'for a person now: title (or target) and age: ' + need.slice(0, 200));
    await p.click('#zth-need a.rowc'); await p.waitForTimeout(600); ok(opened === 'DW-1', 'a work item opens its investigation');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text'); await p.close();
    p = await open(); await Promise.all([p.waitForURL(/network-engineer\.html/), p.click('[data-zth-open="network"]')]); ok(/network-engineer\.html/.test(p.url()), 'a tile opens the desk'); await p.close();
    ITAM_UP = false; p = await open(); ok(/IT Asset side: /.test(await p.textContent('#teamhome')), 'a side that is down is named'); ITAM_UP = true; await p.close();
    p = await open('?poc=1&standalone=1'); await p.waitForTimeout(800);
    ok((await p.$$('.zyb-poc-r.br')).length === 1 && /\(POC\)/.test(await p.textContent('#zth-need')), 'POC: illustrative work items, one ribbon'); await p.close();
    ok(/ vendor\/zyb-teamhome\.js( |$)/m.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'installer ships the overview script');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
