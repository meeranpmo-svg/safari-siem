// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the VAPT Workflow (dashboards/server/vapt-workflow.html, vendor/zyb-vaptwf.js) and the Network Assistant on
// Vulnerability Scans (vendor/zyb-vulnscan.js) against the REAL ITAM engine, SYNTHETIC data only: the scope form arrives filled from
// IP Address Management (planned subnets, fragile devices under "never scanned"); the scan request form arrives filled with the best
// proposal and another proposal can be picked; a new engagement takes its targets from the ticked subnets; the engagement is clicked
// through authorise -> approve by another person -> finding -> testing complete -> validate -> assign -> claim fixed -> independent
// retest -> final report -> issue -> sign-off by a person who did not write it; a hostile finding title stays text; a viewer sees counts
// only; the page is in the menu and the install list.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node vapt-workflow.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const c = (x) => e.app.store.collection(x), ADM = { user: 'syed', role: 'admin' };
  for (const s of [{ cidr: '10.0.5.0/24', name: 'Servers DC', site: 'Riyadh HQ' }, { cidr: '10.0.6.0/24', name: 'Users floor 2', site: 'Riyadh HQ' }]) await e.req('POST', '/ipam/subnets', Object.assign({ body: s }, ADM));
  c('assets').put({ id: 'A1', name: 'srv-app-01', type: 'server', mgmt_ip: '10.0.5.10', status: 'active' });
  c('assets').put({ id: 'A3', name: 'Floor2 MFP', type: 'printer', mgmt_ip: '10.0.6.50', status: 'active' });
  const seen = new Date().toISOString();
  c('disc_devices').put({ id: 'D1', ips: ['10.0.5.10'], macs: ['aa:00:00:00:00:10'], hostname: 'srv-app-01', last_seen: seen, status: 'approved' });
  c('disc_devices').put({ id: 'D2', ips: ['10.0.5.12'], macs: ['aa:00:00:00:00:12'], hostname: 'srv-app-12', last_seen: seen, status: 'new' });
  c('disc_devices').put({ id: 'D3', ips: ['10.0.6.20'], macs: ['aa:00:00:00:00:20'], hostname: 'pc-0620', last_seen: seen, status: 'new' });
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (code, b2) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u2.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u2.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u2.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u2.pathname.endsWith('.js') ? 'application/javascript' : u2.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1], 'i').test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  const as = async (p, who) => { WHO = who; await p.reload(); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    // ---- Vulnerability Scans: the scope arrives filled from IP Address Management
    await p.goto(base + 'vuln-scans.html?standalone=1'); await p.waitForSelector('#scopeb');
    await p.click('#scopeb'); await p.waitForFunction(() => { const el = document.querySelector('#scopef [name=allowed]'); return el && /10\.0\.5\.0\/24/.test(el.value); }, null, { timeout: 10000 }).catch(() => null);
    const allowed = await p.$eval('#scopef [name=allowed]', (x) => x.value), excl = await p.$eval('#scopef [name=exclude]', (x) => x.value);
    ok(/10\.0\.5\.0\/24/.test(allowed) && /10\.0\.6\.0\/24/.test(allowed), 'scope filled with the planned subnets: ' + allowed);
    ok(/10\.0\.6\.50/.test(excl), 'the printer goes under never scanned: ' + excl);
    ok(await has(p, '#scpbox', /Network Assistant/), 'the assistant says what it filled');
    await Promise.all([p.waitForResponse((r) => /\/vulnscan\/scope$/.test(r.url()) && r.request().method() === 'PUT'), p.click('#scopef [type=submit]')]);
    // the scan request arrives filled with the best proposal
    await p.waitForTimeout(300); await p.click('#newscan');
    await p.waitForFunction(() => { const el = document.querySelector('#scanf [name=targets]'); return el && el.value.length > 0; }, null, { timeout: 10000 }).catch(() => null);
    const tg = await p.$eval('#scanf [name=targets]', (x) => x.value), nm = await p.$eval('#scanf [name=name]', (x) => x.value), rs = await p.$eval('#scanf [name=reason]', (x) => x.value);
    ok(/10\.0\.[56]\./.test(tg) && !/\/24/.test(tg), 'targets are live addresses, not the whole subnet: ' + tg);
    ok(/^Scan /.test(nm) && /Network Assistant/.test(rs), 'name and reason filled');
    ok(!!(await p.$eval('#scanf [name=window_start]', (x) => x.value)), 'window filled');
    const props = await p.$$('[data-stg]'); ok(props.length === 2, 'two proposals: ' + props.length);
    await props[1].click(); const tg2 = await p.$eval('#scanf [name=targets]', (x) => x.value); ok(tg2 !== tg, 'picking another proposal refills the form');
    // ---- VAPT Workflow
    await p.goto(base + 'vapt-workflow.html?standalone=1'); await p.waitForSelector('#newb:not([hidden])');
    ok(await has(p, '#list', /No engagement yet/), 'empty state says what to do');
    await p.click('#newb'); await p.waitForSelector('#stgapply', { timeout: 10000 });
    await p.check('[data-sub="0"]'); await p.check('[data-sub="1"]'); await p.click('#stgapply');
    const tv = await p.$eval('#f-targets', (x) => x.value); ok(/10\.0\.5\.10/.test(tv) && /10\.0\.6\.20/.test(tv), 'targets from the ticked subnets: ' + tv.replace(/\n/g, ', '));
    ok(/10\.0\.6\.50/.test(await p.$eval('#f-out_of_scope', (x) => x.value)), 'fragile device out of scope');
    await p.fill('#f-name', 'Q4 internal VAPT (synthetic)'); await p.fill('#f-emergency_contact', 'NOC (synthetic)');
    await p.fill('#f-window_start', new Date().toISOString().slice(0, 10));
    await Promise.all([p.waitForResponse((r) => /\/vapt-workflow$/.test(r.url()) && r.request().method() === 'POST'), p.click('#dlgok')]);
    ok(await has(p, '#nextv', /Authorisation/), 'stage 2 next');
    await p.click('[data-a="authorise"]'); for (const k of ['roe_signed', 'soc_notified', 'backups_confirmed', 'emergency_contact']) await p.check('#f-' + k); await p.fill('#f-change_ref', 'CHG-2001');
    await Promise.all([p.waitForResponse((r) => /\/authorise$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, '#nextv', /Approval/), 'authorised');
    // the authoriser cannot approve
    await p.click('[data-a="approve"]'); await Promise.all([p.waitForResponse((r) => /\/approve$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, 'body', /four eyes|cannot approve/), 'the authoriser is refused');
    await p.click('#dlgx').catch(() => null);
    const id = (await p.textContent('#dk')).split(' ')[0];
    await as(p, { user: 'amal.syn', role: 'admin' }); await p.waitForSelector('tr[data-eng]'); await p.click('tr[data-eng]');
    await p.click('[data-a="approve"]'); await Promise.all([p.waitForResponse((r) => /\/approve$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, '#nextv', /Testing/), 'approved by another person');
    // testing: one manual finding
    WHO = ADM;
    await p.click('[data-a="finding"]'); await p.fill('#f-title', 'Admin panel ' + XSS); await p.selectOption('#f-severity', 'high'); await p.fill('#f-host', '10.0.5.10'); await p.fill('#f-evidence', 'screenshot ref S-1 (synthetic)');
    await Promise.all([p.waitForResponse((r) => /\/findings$/.test(r.url())), p.click('#dlgok')]);
    ok((await p.textContent('#finds')).includes(XSS) && !(await p.$('#finds img')), 'a hostile title stays text');
    await p.click('[data-a="done"]'); await Promise.all([p.waitForResponse((r) => /\/testing-done$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, '#nextv', /Validation/), 'testing complete');
    await p.click('[data-fa="validate"]'); await Promise.all([p.waitForResponse((r) => /\/validate$/.test(r.url())), p.click('#dlgok')]);
    await p.click('[data-fa="remediate"]'); await p.fill('#f-owner', 'owner.syn'); await Promise.all([p.waitForResponse((r) => /\/remediate$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, '#finds', /owner owner\.syn, due \d{4}/), 'owner and SLA due date');
    WHO = { user: 'owner.syn', role: 'operator' };
    await p.click('[data-fa="fixed"]'); await p.fill('#f-note', 'restricted to VPN'); await Promise.all([p.waitForResponse((r) => /\/fixed$/.test(r.url())), p.click('#dlgok')]);
    await p.click('[data-fa="retest"]'); await p.fill('#f-evidence', 'checked'); await Promise.all([p.waitForResponse((r) => /\/retest$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, 'body', /cannot retest/), 'the owner cannot retest'); await p.click('#dlgx').catch(() => null);
    WHO = { user: 'qa.syn', role: 'operator' };
    await p.click('[data-fa="retest"]'); await p.fill('#f-evidence', 'not reachable from outside (synthetic)'); await Promise.all([p.waitForResponse((r) => /\/retest$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, '#finds', /fixed - retest/), 'verified by an independent retest');
    ok(await has(p, '#nextv', /Report/), 'stage 8 next');
    WHO = ADM;
    await Promise.all([p.waitForResponse((r) => /\/report$/.test(r.url())), p.click('[data-a="final"]')]);
    ok(await has(p, '#reps', /v1 final/), 'final report generated');
    await Promise.all([p.waitForResponse((r) => /\/issue$/.test(r.url())), p.click('[data-issue="1"]')]);
    ok(await has(p, '#nextv', /Sign-off/), 'issued');
    WHO = { user: 'amal.syn', role: 'admin' };
    await p.click('[data-a="signoff"]'); await p.fill('#f-statement', 'Reviewed and accepted (synthetic)'); await Promise.all([p.waitForResponse((r) => /\/signoff$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, '#nextv', /Closed/), 'signed off and closed');
    ok((await p.$$('#steps .done')).length === 9, 'all nine stages done');
    // the report as delivered
    const rep = await e.req('GET', '/vapt-workflow/' + id + '/report/1?format=html', ADM);
    ok(rep.status === 200 && /Executive summary/.test(rep.json.html) && /CHG-2001/.test(rep.json.html) && !rep.json.html.includes(XSS), 'report content, escaped');
    // viewer: counts only
    await as(p, { user: 'vera.syn', role: 'viewer' }); await p.click('#back').catch(() => null);
    ok(await has(p, '#list', /operators and administrators/i) && (await p.$eval('#newb', (x) => x.hidden)), 'viewer: counts only, no new engagement');
    // menu and install list
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(nav.includes('"vapt-workflow.html"') && inst.includes('vapt-workflow.html') && inst.includes('vendor/zyb-vaptwf.js'), 'in the menu and installed');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
