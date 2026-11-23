// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for engineer access on the server (backend/itam/engine/access-scopes.js = sentra-siem engine/approvers/access.js):
// every page an engineer job role opens (Pentest & VAPT, Network, and the Virtualization / Windows / Exchange / Backup page
// lists of vendor/zyb-modules.js FN_PAGES), plus their home, My Work and My Workspace, is opened as that engineer with the
// API answering 403 exactly where the servers would. A page that needs a call the allow-list refuses fails this test - so
// the list and the pages cannot drift apart - except the few calls refused on purpose (the SIEM's log search, top and
// histogram: every event of every source). No page may crash. Stubbed API, SYNTHETIC user names.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node engineer-access.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const AC = require('../../backend/itam/engine/access-scopes');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ON_PURPOSE = /^soc\/(search|top|histogram)(\/|$)/;

global.window = { ZYB_ORG: require('../../brand/index') }; global.document = { addEventListener() {}, readyState: 'complete' };
eval(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'));   // the page registry, as the pages load it
const NAV = window.ZYB_NAV; delete global.window; delete global.document;
const area = (id) => NAV.find((a) => a.id === id).pages.map((p) => p.h.replace(/\.html$/, ''));
const FNP = (() => { const src = fs.readFileSync(path.join(DASH, 'vendor/zyb-modules.js'), 'utf8'), m = /var FN_PAGES = (\{[\s\S]*?\});/.exec(src); return Function('return ' + m[1])(); })();
const ENG = { vuln: area('pt'), network: area('net'), virtualization: FNP.virtualization, windows: FNP.windows, exchange: FNP.exchange, backup: FNP.backup, databases: FNP.databases };
const OWN = ['index', 'my-work', 'my-workspace'];

(async () => {
  let FN = 'windows'; const calls = [];
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), j = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return j(200, { user: 'eng.syn', role: 'operator' });
    if (u === '/auth/org') return j(200, { modules: null });
    const m = /^\/api\/(itam|soc)(\/.*)?$/.exec(u);
    if (m) {
      const svc = m[1], rel = m[2] || '/', allowed = AC.allows(svc, [FN], rel);
      calls.push({ fn: FN, svc, rel, allowed });
      if (!allowed) return j(403, { error: 'not part of your job role - an administrator can change it in Roles & Functions' });
      if (rel === '/roles/me') return j(200, { user: 'eng.syn', role: { id: FN + '-synthetic', name: 'Engineer (synthetic)', base: 'operator', functions: { [FN]: 'manage' } }, functions: [] });
      return j(503, { error: 'not in this test' });   // an allowed call answers like a server that is down: the shape every page must cope with (page-errors.test.js)
    }
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return j(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const missing = [], crashed = [], extra = new Set();
  for (const [fn, pages] of Object.entries(ENG)) {
    FN = fn;
    for (const pg of pages.concat(OWN)) {
      const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } }), p = await ctx.newPage(), errs = [];
      p.on('pageerror', (e) => errs.push(e.message));
      const c0 = calls.length;
      try { await p.goto(base + pg + '.html', { timeout: 20000 }); await p.waitForTimeout(1200);
        for (const t of (await p.$$('[data-tab],[role=tab]')).slice(0, 10)) { try { await t.click({ timeout: 400 }); await p.waitForTimeout(150); } catch (e) { /* a hidden tab: nothing to open */ } }
      } catch (e) { errs.push('load: ' + e.message); }
      for (const c of calls.slice(c0)) {
        if (c.allowed) continue;
        const key = c.svc + c.rel.replace(/\/[0-9a-f-]{8,}(\/|$)/gi, '/:id$1');
        if (ON_PURPOSE.test(c.svc + c.rel)) { extra.add(fn + ' ' + key); continue; }
        if (OWN.includes(pg)) continue;   // the shared pages ask for more than an engineer has; they must cope (checked below), not be allowed
        missing.push(fn + ': ' + pg + ' needs ' + key);
      }
      if (errs.length) crashed.push(fn + ': ' + pg + ' - ' + errs[0].slice(0, 120));
      const blank = await p.evaluate(() => (document.body && document.body.innerText || '').trim().length < 20).catch(() => true);
      if (blank) crashed.push(fn + ': ' + pg + ' is blank');
      await ctx.close();
    }
  }
  ok(!missing.length, 'every call an engineer page makes is on its allow-list (' + Object.values(ENG).reduce((a, b) => a + b.length, 0) + ' pages):\n  ' + [...new Set(missing)].join('\n  '));
  ok(!crashed.length, 'no engineer page crashes or stays blank with the server refusing what is not theirs:\n  ' + crashed.join('\n  '));
  ok(calls.some((c) => c.allowed && c.svc === 'soc') && calls.some((c) => c.allowed && c.svc === 'itam'), 'the pages reached both servers');
  ok([...extra].every((x) => /^(windows|exchange) soc\/(search|top|histogram)/.test(x)), 'only the AD & Exchange page asks for the SIEM log search, and it is refused on purpose: ' + [...extra].join(', '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
