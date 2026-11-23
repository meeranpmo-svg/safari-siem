// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for leaver mail forwarding on HR Offboarding (hr-offboarding.html) against the REAL ITAM engine (offboarding.js
// + exo.js) with a stubbed Exchange Online runner, SYNTHETIC data only: before the disable an operator checks the forwarding
// (read-only) and the page marks what goes outside the company; a hostile inbox-rule name stays text; the approval form offers
// the forwarding decision ("decide after" chosen here); after the disable the person who raised the request cannot decide;
// another administrator removes only what leaves the company, and the page shows it removed and verified, with the internal
// rule kept and the daily check; a tile counts the leaver whose mail went outside.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding-forwarding.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const st = { smtp: 'k.harbi.home@gmail.example', rules: [{ id: '1001', name: 'copy out ' + XSS, enabled: true, targets: ['"K" [SMTP:k.private@gmail.example]'] }, { id: '1002', name: 'claims to the team', enabled: true, targets: ['"Claims" [SMTP:claims-team@corp.syn]'] }] };
  const exoRun = async (op, p) => {
    if (op === 'get-mailbox') return { ok: true, data: { found: true, type: 'UserMailbox', litigation_hold: false, archive: 'None' } };
    if (op === 'get-forwarding') return { ok: true, data: { found: true, smtp: st.smtp, address: '', keep_copy: false, rules: st.rules.map((r) => Object.assign({}, r)), accepted_domains: ['corp.syn'] } };
    if (op === 'clear-forwarding') { st.smtp = ''; return { ok: true, data: { smtp: '', address: '' } }; }
    if (op === 'disable-inbox-rule') { const r = st.rules.find((x) => x.id === p.rule); r.enabled = false; return { ok: true, data: { enabled: false } }; }
    return { ok: false, error: 'x' };
  };
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', exoRun });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, HRA = { user: 'hana.syn', role: 'admin' }, DESK = { user: 'desk.syn', role: 'operator' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
  await api('POST', '/offboarding/exo', { enabled: true, organization: 'corp.onmicrosoft.com', app_id: '66666666-7777-8888-9999-000000000000', cert_path: '/etc/sentra/exo-app.pfx', cert_password: 'Synthetic-Pfx-Pass-7' }, ADM);
  await api('POST', '/offboarding', { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: new Date().toISOString().slice(0, 10), manager: 'faisal.syn', reason: 'resignation' }, HRA);
  await api('POST', '/offboarding/OFF-001/confirm', { decision: 'confirm' }, { user: 'faisal.syn', role: 'operator' });
  let WHO = DESK;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  const msg = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1]).test((document.querySelector(a[0] + ' [data-msg]') || {}).textContent || ''), [sel, re.source], { timeout: 8000 }).then(() => true, () => false);
  const openRow = async (p) => { await p.click('#list tr[data-id="OFF-001"]'); await p.waitForSelector('#zd .steps', { timeout: 8000 }); };
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); });
    await p.goto(base + 'hr-offboarding.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p);
    // the read-only check before the disable
    await Promise.all([p.waitForResponse((r) => /forwarding\/check$/.test(r.url())), p.click('[data-act="fcheck"]')]);
    await p.waitForSelector('#zd .steps', { timeout: 8000 });
    ok(await zd(p, /k\.harbi\.home@gmail\.example/) && await zd(p, /outside the company/) && await zd(p, /claims-team@corp\.syn/), 'the check shows the forwarding, outside marked');
    ok(!(await p.$('#zd img')) && await zd(p, /copy out <img/), 'a hostile rule name stays text');
    ok(st.smtp === 'k.harbi.home@gmail.example', 'a check changes nothing');
    // the approval carries the forwarding decision
    await as(p, ADM);
    ok(!!(await p.$('#ofappr [name=forwarding]')) && (await p.inputValue('#ofappr [name=forwarding]')) === 'remove', 'approval form offers the forwarding decision (remove by default)');
    ok(!!(await p.$('#ofappr .zyb-hint')) || !!(await p.$('#ofappr [data-hinted]')), 'helper text on the approval form');
    await p.selectOption('#ofappr [name=decision]', 'approve'); await p.selectOption('#ofappr [name=forwarding]', 'ask');
    await Promise.all([p.waitForResponse((r) => /\/approve$/.test(r.url())), p.click('#ofappr [type=submit]')]);
    await api('POST', '/offboarding/OFF-001/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK);
    // after the disable: the requester cannot decide
    await as(p, HRA);
    ok(await zd(p, /waiting for a decision/) && !!(await p.$('#offwd')), 'decision waiting after the disable');
    await p.selectOption('#offwd [name=decision]', 'approve');
    await Promise.all([p.waitForResponse((r) => /forwarding\/decide$/.test(r.url())), p.click('#offwd [type=submit]')]);
    ok(await msg(p, '#offwd', /four eyes/), 'the person who raised it cannot decide');
    // another administrator removes only what leaves the company
    await as(p, ADM);
    await p.selectOption('#offwd [name=decision]', 'approve'); await p.selectOption('#offwd [name=scope]', 'external');
    await Promise.all([p.waitForResponse((r) => /forwarding\/decide$/.test(r.url())), p.click('#offwd [type=submit]')]);
    ok(await zd(p, /removed and verified/) && await zd(p, /Kept \(inside the company\)/) && await zd(p, /Checked again once a day/), 'removed, internal kept, watched');
    ok(st.smtp === '' && st.rules[0].enabled === false && st.rules[1].enabled === true, 'done in Exchange Online: outside forwarding off, the team rule on');
    await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 });
    ok(/Mail forwarded outside the company/.test(await p.textContent('#kpis')), 'a tile counts it');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
