// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Sentra Next-Gen SIEM (sentra-nextgen.html) with the REAL engine's answer (backend/siem engine/soc/nextgen.js) over SYNTHETIC counters:
// the wheel carries the three pillars with their share in place and nine segments with live figures, each linking to its page; the
// headline figures are shown with what they rest on, and a withheld figure says why; the pillar cards list state and next step; an
// empty installation says what to connect; a SIEM without the route says to update; hostile text stays text; POC mode with one ribbon;
// menu entry and installer. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sentra-nextgen.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), N = require(path.resolve(__dirname, '../../backend/siem/engine/soc/nextgen'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now(), MIN = 60000, H = 36e5;
function world() {
  const alerts = Array.from({ length: 10 }, (_, i) => ({ id: 'A' + i, created: NOW - (i + 1) * H, ack_at: NOW - (i + 1) * H + 4 * MIN, closed_at: NOW - (i + 1) * H + 30 * MIN, status: i < 1 ? 'closed-false-positive' : 'closed-true-positive' }));
  return { sources: [{ src_id: 'fw', src_type: 'fortigate', collector: 'syslog', last_seen: NOW - MIN, events_since_start: 500 }, { src_id: 'm365', src_type: 'm365', collector: 'graph', last_seen: NOW - MIN }],
    pipeline: { events: 900, eps_1m: 12.5, stages: [{ name: 'parse', calls: 900, errors: 0 }] }, detector: { rules_loaded: 2, rules: [{ id: 'r', matches: 100, suppressed: 80, alerts: 5 }, { id: 'q', matches: 0, suppressed: 0, alerts: 0 }] },
    intel: { ip: 10, domain: 5, hash: 0, lists: 1, hits: {} }, search: true, alerts, alertStats: { merged: 0 }, cases: [{ id: 'C', status: 'open', created: NOW - H }], soarRuns: [], dutyItems: [], aiLedger: [] };
}
(async () => {
  let V = N.analyse(world(), NOW), CODE = 200;
  V.segments[0].sub = '<img src=x onerror=window.PWN=1>';
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'vera.syn', role: 'viewer' });
    if (u.pathname === '/api/soc/soc/nextgen') return CODE === 200 ? json(200, V) : json(CODE, { error: 'not found' });
    if (u.pathname.startsWith('/api/')) return json(500, { error: 'down (synthetic)' });
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/sentra-nextgen.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (q, sel) => { const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + (q || '?standalone=1')); await p.waitForSelector(sel || '#main:not([hidden])', { timeout: 15000 }); await p.waitForTimeout(200); return p; };
  try {
    let p = await open();
    const svg = await p.textContent('#wheel svg');
    ok(/UNIFY · \d+%/.test(svg) && /HUNT & DETECT · 100%/.test(svg) && /RESPOND · \d+%/.test(svg) && /Sentra/.test(svg) && /Next-Gen SIEM/.test(svg), 'the wheel: three pillars and the centre');
    ok((await p.$$('#wheel a[data-seg]')).length === 9 && (await p.getAttribute('#wheel a[data-seg="cases"]', 'href')) === 'soc-cases.html', 'nine segments, each linking to its page');
    ok(/12\.5/.test(svg) && /2 \/ 2/.test(svg), 'live figures on the wheel');
    const hl = (await p.textContent('#hl')).replace(/\s+/g, ' ');
    ok(/80%/.test(hl) && /Noise removed/.test(hl) && /30 min/.test(hl) && /10%/.test(hl) && /1 of 10 closed/.test(hl) && /12\.5 eps/.test(hl), 'headline figures with their basis: ' + hl.slice(0, 260));
    const pc = await p.textContent('#pillars'); ok(/UNIFY/.test(pc) && /Governed SOAR/.test(pc) && /Switch on the first playbook/.test(pc) && /partial/.test(pc), 'pillar cards: state and next step');
    ok((await p.$$('#caps a')).length === 16 && (await p.getAttribute('#caps a:nth-child(13)', 'href')) === 'soc-hunt.html', 'sixteen capabilities, each to its page');
    for (const h of await p.$$eval('#caps a', (L) => L.map((a) => a.getAttribute('href')))) ok(fs.existsSync(path.join(DASH, h)), 'capability page exists: ' + h);
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text'); await p.close();
    const w = world(); w.alerts = []; V = N.analyse(w, NOW); p = await open();
    ok(/shown after 3 closed alerts/.test(await p.textContent('#hl')), 'a withheld figure says why'); await p.close();
    V = N.analyse({}, NOW); p = await open(); ok(/Connect the first log source/.test(await p.textContent('#pillars')) && /—/.test(await p.textContent('#hl')), 'an empty installation says what to connect'); await p.close();
    CODE = 404; p = await open('?standalone=1', '#err .err'); ok(/run the platform update/.test(await p.textContent('#err')), 'no route on the SIEM: update'); await p.close(); CODE = 200;
    p = await open('?poc=1&standalone=1'); ok((await p.$$('.zyb-poc-r.br')).length === 1 && /POC: illustrative/.test(await p.textContent('#note')) && /4870\.4/.test(await p.textContent('#hl')), 'POC: illustrative figures, one ribbon');
    if (process.env.SHOT) { await p.waitForTimeout(600); await p.screenshot({ path: process.env.SHOT, fullPage: true }); } await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "sentra-nextgen.html"') && / sentra-nextgen\.html( |$)/m.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' sentra-nextgen checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
