// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the SAMA CSF page (dashboards/server/sama-compliance.html): each control names the platform tools that
// implement it (from the menu's framework tags, vendor/zyb-nav.js fw.sama), a control with none says so, the two tool filters,
// the drawer lists the tools as links, and a hostile value stays text. Stubbed SIEM answer, SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sama-compliance.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const CTL = [
  { id: '3.3.1', title: 'Human Resources security', domain: '3.3', domain_title: 'Cyber Security Operations & Technology', owner: 'HR', siem_evidenced: false, status: 'n/a' },
  { id: '3.3.3', title: 'Asset Management', domain: '3.3', domain_title: 'Cyber Security Operations & Technology', owner: 'IT', siem_evidenced: true, status: 'partial', capped: true },
  { id: '3.3.9', title: 'Cryptography', domain: '3.3', domain_title: 'Cyber Security Operations & Technology', owner: 'IT', siem_evidenced: false, status: 'n/a' },
  { id: '3.3.12', title: 'Payment Systems ' + XSS, domain: '3.3', domain_title: 'Cyber Security Operations & Technology', owner: 'Finance', siem_evidenced: false, status: 'n/a' },
];
const SUM = { framework: 'SAMA CSF', summary: { coverage_pct: 50, evidenced: 1, total: 4, counts: { covered: 0, partial: 1, gap: 0, 'n/a': 3 }, by_domain: { '3.3': { title: 'Cyber Security Operations & Technology', covered: 0, partial: 1, gap: 0, 'n/a': 3 } } }, controls: CTL };

(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'syed', role: 'admin' });
    if (u.pathname === '/api/soc/compliance/sama') return json(200, SUM);
    const m = /^\/api\/soc\/compliance\/sama\/(.+)$/.exec(u.pathname);
    if (m) { const c = CTL.find((x) => x.id === decodeURIComponent(m[1])); return c ? json(200, Object.assign({ reasons: ['synthetic'], checks: [] }, c)) : json(404, { error: 'unknown' }); }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'sama-compliance.html?standalone=1'); await p.waitForSelector('#controls table');
    await p.waitForFunction(() => window.ZYB_NAV && window.ZYB_NAV.length > 0, null, { timeout: 10000 }).catch(() => null);
    await p.waitForTimeout(600);   // the page redraws the tool column itself once the menu registry is there
    const row = async (id) => p.$eval('#controls tr[data-id="' + id + '"]', (r) => r.textContent);
    ok(/Implemented by/.test(await p.textContent('#controls thead')), 'an "Implemented by" column');
    const hr = await row('3.3.1');
    ok(/\d+ tools?/.test(hr) && /Staff Handover|User Management/.test(hr), 'HR security (not SIEM-evidenced) names its platform tools: ' + hr);
    ok(/\d+ tools?/.test(await row('3.3.9')) && /Certificates|Credential Security|Domains/.test(await p.$eval('#controls tr[data-id="3.3.9"] .stat.covered', (s) => s.title)), 'cryptography: certificates and sealed credentials');
    ok(/none in this platform/.test(await row('3.3.12')), 'payment systems: none in this platform');
    ok(!(await p.$('#controls img')) && (await row('3.3.12')).includes(XSS), 'a hostile title stays text');
    await p.selectOption('#fst', 'tools'); await p.waitForTimeout(150);
    let ids = await p.$$eval('#controls tbody tr', (r) => r.map((x) => x.getAttribute('data-id')));
    ok(ids.join() === '3.3.1,3.3.3,3.3.9', 'filter "implemented in the platform": ' + ids);
    await p.selectOption('#fst', 'notools'); await p.waitForTimeout(150);
    ids = await p.$$eval('#controls tbody tr', (r) => r.map((x) => x.getAttribute('data-id')));
    ok(ids.join() === '3.3.12', 'filter "no platform tool": ' + ids);
    await p.selectOption('#fst', '');
    await p.fill('#q', 'handover'); await p.waitForTimeout(150);
    ok((await p.$$eval('#controls tbody tr', (r) => r.map((x) => x.getAttribute('data-id')))).join() === '3.3.1', 'search finds a control by its tool name');
    await p.fill('#q', ''); await p.waitForTimeout(150);
    await p.click('#controls tr[data-id="3.3.1"]'); await p.waitForSelector('#zd a[href="handover.html"]', { timeout: 8000 });
    ok(/Implemented in this platform/i.test(await p.textContent('#zd')) && /not proof the control is effective/.test(await p.textContent('#zd')), 'the drawer lists the tools, with the caveat');
    await p.keyboard.press('Escape');
    await p.click('#controls tr[data-id="3.3.12"]'); await p.waitForTimeout(800);
    ok(/No tool in this platform implements this control/.test(await p.textContent('#zd')), 'the drawer says when no tool implements it');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
