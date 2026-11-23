// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for SAMA IT Audit (dashboards/server/sama-it-audit.html) against the REAL ITAM engine (engine/sama-itaudit.js,
// pyengine/sama_itaudit_rules.py; IT Audit, VAPT Center and Certificates stubbed) on SYNTHETIC evidence: readiness ring and text, six
// areas with their checks (met / gap / not measured), a draft finding sent into an engagement, the regulator pack, a hostile name
// stays text, a viewer refused, the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sama-it-audit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true }); const sent = [];
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const A = e.app.addons, yr = new Date().getUTCFullYear();
  A.auditEngage = { plans: () => [{ year: yr, state: 'approved' }], listEngagements: () => [{ id: 'IA-ENG-001', title: 'ITGC ' + yr + ' ' + XSS, state: 'fieldwork', start: yr + '-09-01', auditee_owner: 'it.head.syn' }],
    addFinding: async (id, b, who) => { sent.push({ id, b, who }); return { id: 'IA-FND-009' }; } };
  A.vaptCenter = { analysis: async () => ({ ok: true, open: 12, counts: { critical: 2 }, sla: { breached: 7 } }) };
  A.certs = { view: () => ({ counts: { expired: 0, expiring: 1 } }) };
  e.app.store.collection('assets').put({ id: 'a1', name: 'CORE-SQL', mgmt_ip: '10.1.1.5', tags: ['business-critical'], status: 'active' });
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
    await p.goto(base + 'dashboards/sama-it-audit.html');
    ok(await wait(p, () => document.querySelectorAll('#areas .area').length === 6), 'six areas');
    ok(/\d+%/.test(await p.textContent('#ring b')) && /checks that have evidence/.test(await p.textContent('#rtext')), 'readiness and what it rests on');
    ok(/met/.test(await p.$eval('[data-check="gov-plan"] .pill', (x) => x.textContent)), 'approved plan: met');
    ok(/gap/.test(await p.$eval('[data-check="risk-vuln"] .pill', (x) => x.textContent)) && /7 past the SLA/.test(await p.textContent('[data-check="risk-vuln"]')), 'vulnerabilities past SLA: gap with evidence');
    ok(/not measured/.test(await p.$eval('[data-check="data-mfa"] .pill', (x) => x.textContent)), 'MFA: not measured, never met');
    ok(/VAPT Center -> Fix first/.test(await p.textContent('[data-check="risk-vuln"]')), 'what to do');
    ok((await p.$$('#finds .fd')).length >= 2, 'draft findings from the gaps');
    ok(!(await p.evaluate(() => window.__xss)) && (await p.textContent('#finds')).includes('<img') && !(await p.$('#finds img')), 'a hostile engagement title stays text');
    await p.click('#finds [data-send="risk-vuln"]');
    ok(await wait(p, () => /Raised as IA-FND-009 in IA-ENG-001/.test(document.body.textContent)), 'sent into the engagement');
    ok(sent.length === 1 && sent[0].b.owner === 'it.head.syn' && sent[0].who.user === 'nora.syn' && /Vulnerabilities remediated/.test(sent[0].b.title), 'with the owner, as the person');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#pack-html')]);
    ok(/^sama-it-audit-\d{4}-\d{2}-\d{2}\.html$/.test(dl.suggestedFilename()), 'regulator pack downloaded');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => /Operators and administrators/.test(document.getElementById('err').textContent)), 'a viewer is refused');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'aud'); return !!(a && a.pages.some((x) => x.h === 'sama-it-audit.html')); }), 'the Audit menu has the page');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
