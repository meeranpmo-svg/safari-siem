// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// security-center.html with a stubbed SIEM (SYNTHETIC answers in the shapes of /soc/overview, /histogram + /top, /ksc/overview,
// /m365/security, /netops/rogue and /sources): the threat level with its reasons, the KPI row with each figure linking to its page,
// blocked and detected events by source / kind / host, act-now alerts, endpoint protection totals across servers, Secure Score and
// MFA, rogue devices, silent sources; one source failing shows its own message while the rest render; with nothing connected the
// cards say what to connect; a viewer (refused raw-event counts) still sees the rest; hostile text stays text; menu, installer,
// portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node security-center.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const NOW = Date.now(), H = 3600000;
let MODE = 'full', WHO = { user: 'nora.syn', role: 'analyst' };
const A = {
  '/api/soc/soc/overview': () => ({ open: { total: 9, by_severity: [1, 2, 3, 2, 1], unassigned: 4, new_24h: 5 }, act_now: [{ id: 'ALR-1', rule_name: 'Beacon to C2 ' + XSS, priority: 92, severity: 4, entities: ['pc-9', '198.51.100.9'] }],
    top_entities: [{ key: 'pc-9', count: 4 }, { key: 'dave.syn', count: 2 }], tactics: [{ key: 'Command and Control', count: 3 }], sources: [{ key: 'fortigate', count: 5 }, { key: 'windows', count: 4 }] }),
  '/api/soc/histogram': () => ({ buckets: Array.from({ length: 24 }, (_, i) => ({ t: NOW - (24 - i) * H, n: i % 6 })), step_ms: H }),
  '/api/soc/top': (b) => ({ values: b.field === 'src_type' ? [{ v: 'fortigate', n: 40 }, { v: 'edr-cef', n: 13 }] : b.field === 'action' ? [{ v: 'blocked', n: 41 }, { v: 'ips-detection', n: 9 }, { v: 'av-detection', n: 3 }] : [{ v: '10.0.5.77', n: 12 }] }),
  '/api/soc/ksc/overview': () => ({ servers: [{ id: 'ksc1', last: { summary: { hosts: 300, protected: 296, unprotected: 4, outdated: 7, infected: 1 } } }, { id: 'ksc2', last: { summary: { hosts: 20, protected: 20, unprotected: 0, outdated: 0, infected: 0 } } }], findings: [{}, {}] }),
  '/api/soc/m365/security': () => ({ configured: true, score: { current: 61.5, max: 100, pct: 62 }, mfa: { users: 400, registered: 380, pct: 95, not_registered: 20 }, actions: [{ title: '20 user(s) without MFA' }], coverage: [{ label: 'Risky users', ok: false, perm: 'IdentityRiskyUser.Read.All' }] }),
  '/api/soc/netops/rogue': () => ({ kpis: { devices: 140, rogue: 2, suspicious: 5, trusted: 120, unverified: 13, guest: 0, expired_guests: 0, unmanaged_ports: 1 } }),
  '/api/soc/sources': () => ({ sources: [{ src_id: 'fw-hq', src_type: 'fortigate', status: 'ok' }, { src_id: 'dc01', src_type: 'windows', status: 'ok' }, { src_id: 'ksc-syslog', src_type: 'edr-cef', status: 'silent', last_seen: NOW - 5 * H }] }),
};
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/')) {
      let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
        const body = b ? JSON.parse(b) : {};
        if (MODE === 'none') { if (u.pathname === '/api/soc/m365/security') return json(200, { configured: false, note: 'Microsoft 365 is not connected to the SIEM - connect it in Connections & Setup.' }); if (u.pathname === '/api/soc/ksc/overview') return json(200, { servers: [], findings: [] }); if (u.pathname === '/api/soc/netops/rogue') return json(200, { kpis: { devices: 0, rogue: 0, suspicious: 0, trusted: 0 } }); if (u.pathname === '/api/soc/sources') return json(200, { sources: [] }); if (/histogram/.test(u.pathname)) return json(200, { buckets: [], step_ms: H }); if (/top/.test(u.pathname)) return json(200, { values: [] }); if (/overview/.test(u.pathname)) return json(200, { open: { total: 0, by_severity: [0, 0, 0, 0, 0], new_24h: 0 }, act_now: [], top_entities: [], tactics: [], sources: [] }); }
        if (MODE === 'kscdown' && u.pathname === '/api/soc/ksc/overview') return json(500, { error: 'internal error' });
        if (WHO.role === 'viewer' && /\/api\/soc\/(histogram|top)$/.test(u.pathname)) return json(403, { error: 'requires role analyst' });
        const f = A[u.pathname]; return f ? json(200, f(body)) : json(404, { error: 'not found' });
      }); return;
    }
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/security-center.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const T = (p, id) => p.textContent('#' + id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); ok(await wait(p, () => /Updated/.test(document.getElementById('up').textContent)), 'every card read');
    const LV = await T(p, 'lvl'); ok(/critical/i.test(LV.slice(0, 10)) && /1 critical alert\(s\) open/.test(await T(p, 'lvl')) && /1 endpoint\(s\) with an active infection/.test(await T(p, 'lvl')) && /2 rogue device/.test(await T(p, 'lvl')) && /1 log source\(s\) silent/.test(await T(p, 'lvl')), 'threat level with every reason: ' + LV);
    const K = await T(p, 'kpis');
    ok(/9\s*open alerts/.test(K) && /60\s*blocked \/ detected 24 h/.test(K.replace(/,/g, '')) && /4\s*endpoints unprotected/.test(K) && /62%\s*Secure Score/.test(K) && /20\s*users without MFA/.test(K) && /2\s*rogue devices/.test(K) && /1\s*silent log sources/.test(K), 'KPI row from every source: ' + K.replace(/\s+/g, ' '));
    ok(await p.$eval('.kpi[href="rogue-detection.html"]', (a) => !!a) && await p.$eval('.kpi[href="m365-security.html"]', (a) => !!a), 'each figure links to its page');
    ok(/blocked by policy/.test(await T(p, 'blk')) && /IPS detection/.test(await T(p, 'blk')) && /10\.0\.5\.77/.test(await T(p, 'blk')) && await p.$('#blk svg.h rect'), 'blocked / detected: chart, source, kind, host');
    ok(/320/.test(await T(p, 'ep')) && /99%/.test(await T(p, 'ep')) && /2 finding/.test(await T(p, 'ep')), 'endpoint totals across two KSC servers');
    ok(/62%/.test(await T(p, 'm365')) && /95%/.test(await T(p, 'm365')) && /IdentityRiskyUser\.Read\.All/.test(await T(p, 'm365')), 'Secure Score, MFA and what is not read with its permission');
    ok(/ksc-syslog/.test(await T(p, 'src')) && /silent/.test(await T(p, 'src')), 'silent source named');
    ok(/Beacon to C2/.test(await T(p, 'act')) && /Command and Control/.test(await T(p, 'ent')) && /fortigate/.test(await T(p, 'bysrc')), 'act now, entities / tactics, alerts by source');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile text stayed text');
    // one source failing: its own message, the rest render
    MODE = 'kscdown'; await p.click('#refresh'); ok(await wait(p, () => /Could not be read/.test(document.getElementById('ep').textContent) && /internal error/.test(document.getElementById('ep').textContent)), 'a failing source says so');
    ok(/62%/.test(await T(p, 'm365')) && /—\s*endpoints unprotected/.test(await T(p, 'kpis')), 'the others still render; its KPI reads —');
    // nothing connected
    MODE = 'none'; await p.click('#refresh'); await wait(p, () => /No Kaspersky Security Center is connected/.test(document.getElementById('ep').textContent));
    ok(/Microsoft 365 is not connected/.test(await T(p, 'm365')) && /No device seen yet/.test(await T(p, 'rg')) && /No log source configured/.test(await T(p, 'src')) && /Nothing blocked or detected in 24 hours/.test(await T(p, 'blk')), 'empty states say what to connect');
    ok(/^\s*normal/i.test(await T(p, 'lvl')), 'nothing open: normal');
    // viewer: raw-event counts refused, the rest shown
    MODE = 'full'; WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => /Updated/.test(document.getElementById('up').textContent));
    ok(/analysts and above/.test(await T(p, 'blk')) && /62%/.test(await T(p, 'm365')), 'viewer: blocked counts need analyst, the rest is shown');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => /Updated/.test(document.getElementById('up').textContent));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "security-center.html"/.test(nav) && / security-center\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/security: 'security-center\.html', soc: 'security-center\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')), 'the portal\'s old "Security Center" and "SOC - Security Center" open this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})();
