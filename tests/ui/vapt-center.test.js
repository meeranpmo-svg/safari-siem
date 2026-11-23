// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the VAPT Center (dashboards/server/vapt-center.html) against the REAL ITAM engine (engine/vapt-center.js,
// pyengine/vapt_center_rules.py; the three finding sources stubbed) on SYNTHETIC findings: KPIs and the severity bar, merged rows with
// their reasons, filters, a lateral path, SLA, the scan wizard (choose targets -> one request, four-eyes note), report downloads, a
// hostile title stays text, a viewer refused, the admin SLA form, the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node vapt-center.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';
const DAY = 86400000, T0 = Date.now();

(async () => {
  const e = await H.startApp({ noAi: true }); const requests = [];
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const d = (k) => new Date(T0 - k * DAY).toISOString().slice(0, 10);
  e.app.addons.vulnscan = { findings: () => ({ items: [{ id: 'g1', host: '10.1.1.5', name: 'OpenSSH regreSSHion remote code execution', severity: 'high', score: 8.1, cves: ['CVE-2024-6387'], status: 'open', first_seen: d(40), last_seen: d(35) },
    { id: 'g2', host: '10.1.1.9', name: 'Weak cipher ' + XSS, severity: 'medium', score: 5, cves: [], status: 'open', first_seen: d(5), last_seen: d(1) }] }),
    view: () => ({ scope: { allowed: ['10.0.0.0/8'], exclude: [] } }), request: async (b, who) => { requests.push({ b, who }); return { id: 'SCAN-007', status: 'waiting_approval' }; } };
  e.app.addons.vaptStudio = { view: async () => ({ findings: [{ id: 't1', vendor: 'tenable', host: '10.1.1.5', title: 'OpenSSH < 9.8', severity: 'critical', cvss: 8.1, cves: ['CVE-2024-6387'], status: 'open', first_seen: d(10) },
    { id: 'f1', vendor: 'firecompass', host: '203.0.113.7', title: 'Exposed RDP', severity: 'high', cves: [], status: 'open', first_seen: d(20), exposure: 'external' }] }) };
  e.app.addons.pentest = { view: () => ({ findings: [] }), cadence: { schedule: () => [{ asset: 'CORE-DB', ip: '10.1.1.20', worst: 'overdue', tier: 'critical' }] } };
  e.app.store.collection('assets').put({ id: 'a1', name: 'CORE-SQL', mgmt_ip: '10.1.1.5', owner: 'DBA team', department: 'IT', tags: ['business-critical'], status: 'active' });
  e.app.store.collection('assets').put({ id: 'a2', name: 'DMZ-DB', mgmt_ip: '203.0.113.20', tags: ['crown-jewel'], status: 'active' });
  let WHO = OP;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, dd) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(dd); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (dd) => { errs.push('dialog: ' + dd.message()); dd.dismiss(); });
    await p.goto(base + 'dashboards/vapt-center.html');
    ok(await wait(p, () => document.querySelectorAll('#fl tr.f').length === 3), 'three open rows (the SSH CVE from two sources is one)');
    ok(/greenbone \+ tenable/.test(await p.textContent('#fl tr.f')), 'the top row lists both sources');
    ok(/known-exploited|remote code execution/.test(await p.textContent('#fl tr.f .why')), 'its reasons are shown');
    ok((await p.$$('#sevbar i')).length >= 2, 'severity bar');
    ok(/greenbone ✓/.test(await p.textContent('#srcs')), 'sources named');
    ok(!(await p.evaluate(() => window.__xss)) && (await p.textContent('#fl')).includes('<img') && !(await p.$('#fl img')), 'a hostile title stays text');
    await p.click('#chips [data-f="external"]'); ok((await p.$$('#fl tr.f')).length === 1 && /203\.0\.113\.7/.test(await p.textContent('#fl')), 'filter: internet-facing');
    await p.click('#chips [data-f="all"]');
    ok(/203\.0\.113\.7.*DMZ-DB/s.test(await p.textContent('#paths')), 'a lateral-movement path');
    ok(/First daily snapshot|first daily snapshot/i.test(await p.textContent('#delta')), 'no snapshot yet: says when changes appear');
    // scan wizard
    ok(/10\.1\.1\.20/.test(await p.textContent('#wiz')) && /test overdue/.test(await p.textContent('#wiz')) && /retest/.test(await p.textContent('#wiz')), 'wizard proposes overdue + retest');
    await p.check('#wiz [data-t="10.1.1.20"]'); await p.fill('#wextra', '10.1.1.30'); await p.fill('#wreason', 'quarterly (synthetic)'); await p.click('#wgo');
    ok(await wait(p, () => /SCAN-007/.test(document.body.textContent)), 'scan requested');
    ok(requests.length === 1 && requests[0].b.targets.join(',') === '10.1.1.20,10.1.1.30' && requests[0].who.user === 'nora.syn', 'one request with the chosen targets, as the person');
    // reports
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#reps [data-rep="compliance"][data-fmt="html"]')]);
    ok(/^vapt-compliance-\d{4}-\d{2}-\d{2}\.html$/.test(dl.suggestedFilename()), 'compliance report downloaded');
    const [dl2] = await Promise.all([p.waitForEvent('download'), p.click('#reps [data-rep="technical"][data-fmt="csv"]')]);
    ok(/\.csv$/.test(dl2.suggestedFilename()), 'technical CSV downloaded');
    ok((await p.$$('#reps [data-rep]')).length === 18, 'nine reports, two formats');
    ok(await p.isHidden('#slabox'), 'an operator has no SLA form');
    WHO = ADM; await p.reload(); await wait(p, () => document.querySelectorAll('#fl tr.f').length === 3);
    ok(await p.isVisible('#slabox'), 'admin: SLA form'); await p.fill('#sla-critical', '7'); await p.click('#slasave');
    ok(await wait(p, () => /SLA saved/.test(document.body.textContent)), 'SLA saved');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => /Operators and administrators/.test(document.getElementById('err').textContent)), 'a viewer is refused');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'pt'); return !!(a && a.pages.some((x) => x.h === 'vapt-center.html')); }), 'the menu has the page');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
