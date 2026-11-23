// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the AI Windows Server Administrator's site filter and UAT checklist (windows-admin.html +
// vendor/zyb-sysadmin.js) against the REAL SIEM sysadmin routes (sentra-siem engine/sysadmin/routes.js + uat.js) with a fake
// WinRM helper and SYNTHETIC servers: the site filter narrows the server tables and the problem list, the UAT tab lists the
// UAT servers and tests, a result is recorded (a fail without a note is refused with the server's message), the tester
// cannot sign off, another admin can, a viewer only reads, and a hostile note stays text.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node windows-uat.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const routes = require(path.join(SIEM, 'engine/sysadmin/routes'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'win-uat-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') }), config = {};
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const exec = async (r) => (r.op === 'version' ? { ok: true } : r.op === 'run' ? { ok: true, data: r.check === 'disks' ? [{ drive: 'C:', size_gb: 100, free_gb: 3, free_pct: 3 }] : [], errors: [] } : { ok: false, kind: 'input', error: 'bad op' });
  const S = routes.createSysadmin({ state, config, log: { info() {}, warn() {}, error() {} }, sysadminExec: exec });
  const R = []; routes.register({ route: (m, p, h) => R.push({ m, re: new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), h }) }, { state, config, log: { error() {}, info() {} }, sysadmin: S });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  let WHO = { user: 'syed', role: 'admin' };
  // synthetic servers: two at site UAT, one in production
  S.targets.setProfile('windows', { username: 'SYN\\svc-ai-winread', password: 'Synthetic-1' }, 'syed');
  S.targets.put({ id: 'uat-app01', name: 'UAT-APP01', ip: '10.9.0.11', site: 'UAT' }, 'syed');
  S.targets.put({ id: 'uat-db01', name: 'UAT-DB01', ip: '10.9.0.12', site: 'UAT' }, 'syed');
  S.targets.put({ id: 'prod-fs01', name: 'PROD-FS01', ip: '10.1.0.10', site: 'HQ' }, 'syed');
  await S.health.pollServer('uat-app01', {}); await S.health.pollServer('prod-fs01', {});

  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/sysadmin')) {
      let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', async () => {
        const r = R.find((x) => x.m === req.method && x.re.test(u.pathname)); if (!r) return json(404, { error: 'not found' });
        const out = {}, role = WHO.role, ctx = { role, user: WHO.user, body: raw ? JSON.parse(raw) : undefined, params: Object.assign({}, u.pathname.match(r.re).groups), query: Object.fromEntries(u.searchParams), path: u.pathname,
          need(x) { if (RANK[role] < RANK[x]) { out.status = 403; out.error = 'requires ' + x + ' role'; return false; } return true; }, audit: (a, t, d) => audits.push([a, t, d, WHO.user]), ok(b) { out.status = 200; out.body = b; }, fail(c, m) { out.status = c; out.error = m; } };
        try { const rv = await r.h(ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } } catch (e) { out.status = e.status || e.code || 500; out.error = e.message; }
        json(out.status || 500, out.status === 200 ? out.body : { error: out.error });
      }); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept());
    await p.goto(base + 'windows-admin.html?standalone=1'); await p.waitForSelector('#sgrid table', { state: 'attached' });
    await p.evaluate(() => { try { localStorage.clear(); } catch (e) { /* storage may be unavailable */ } });
    const rows = (sel) => p.$$eval(sel + ' tbody tr', (r) => r.map((x) => x.textContent));
    ok((await rows('#sgrid')).length === 3, 'all three servers before filtering');
    ok((await p.$$eval('#site option', (o) => o.map((x) => x.value))).join() === ',HQ,UAT', 'site filter offers every site');
    await p.selectOption('#site', 'UAT'); await p.waitForTimeout(150);
    const g = await rows('#sgrid');
    ok(g.length === 2 && g.every((t) => /UAT-/.test(t)), 'site filter: only UAT servers in the overview: ' + g.length);
    ok((await rows('#findings')).every((t) => /UAT-/.test(t)) && (await rows('#findings')).length > 0, 'problems narrowed to UAT servers');
    ok(/Showing site UAT: 2 of 3/.test(await p.textContent('#sitenote')), 'the note says the figures above are estate-wide');
    await p.click('[data-tab="servers"]'); await p.waitForSelector('#servers table', { state: 'attached' });
    ok((await rows('#servers')).length === 2 && /2 of 3 servers · site UAT/.test(await p.textContent('#scount2')), 'servers tab follows the filter');
    await p.reload(); await p.waitForSelector('#sgrid table', { state: 'attached' });
    ok(await p.$eval('#site', (s) => s.value) === 'UAT' && (await rows('#sgrid')).length === 2, 'the filter is remembered');
    await p.click('[data-tab="overview"]'); await p.click('#siteall'); await p.waitForTimeout(150);
    ok((await rows('#sgrid')).length === 3, '"Show all sites" clears it');

    // UAT checklist, as an operator
    WHO = { user: 'tester.syn', role: 'operator' }; await p.reload(); await p.waitForSelector('[data-tab="uat"]');
    await p.click('[data-tab="uat"]'); await p.waitForSelector('#uatlist table', { state: 'attached' });
    ok(/UAT round 1 · site UAT/.test(await p.textContent('#uathead')) && /UAT-APP01/.test(await p.textContent('#uathead')) && /UAT-DB01/.test(await p.textContent('#uathead')), 'round header lists the UAT servers');
    ok((await p.$$eval('#uatlist tbody tr', (r) => r.length)) === 8, 'eight tests');
    ok(/1 of 2 UAT server\(s\) checked/.test(await p.textContent('#uatlist tr[data-u="connection"]')), 'platform evidence beside the connection test');
    ok(!(await p.$('#uatsign')), 'an operator has no sign-off button');
    await p.click('#uatlist tr[data-u="finding"]'); await p.waitForSelector('#urf');
    await p.selectOption('#urf [name="result"]', 'fail'); await p.click('#urf button[type=submit]');
    await p.waitForFunction(() => /note is required/.test((document.querySelector('#urf [data-msg]') || {}).textContent || ''), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'a fail without a note is refused with the server message'));
    await p.fill('#urf [name="note"]', XSS); await p.selectOption('#urf [name="server"]', 'uat-app01'); await p.click('#urf button[type=submit]');
    await p.waitForFunction(() => !!document.querySelector('#uatlist tr[data-u="finding"] .pill.bad'), null, { timeout: 8000 });
    ok(!(await p.$('#uatlist img')) && (await p.textContent('#uatlist tr[data-u="finding"]')).includes(XSS), 'a hostile note stays text');
    ok(/tester\.syn/.test(await p.textContent('#uatlist tr[data-u="finding"]')), 'who recorded it');
    for (const id of ['connection', 'finding', 'unreachable', 'badlogin', 'ai', 'foureyes', 'roles']) {
      await p.click('#uatlist tr[data-u="' + id + '"]'); await p.waitForSelector('#urf');
      await p.selectOption('#urf [name="result"]', 'pass'); await p.click('#urf button[type=submit]');
      await p.waitForFunction((x) => !!document.querySelector('#uatlist tr[data-u="' + x + '"] .pill.ok'), id, { timeout: 8000 });
    }
    ok(/7 \/ 7/.test(await p.textContent('#uathead')), 'all required tests passed');
    ok(audits.filter((a) => a[0] === 'sysadmin.uat.result').length === 8, 'each result is audited');

    // the tester (as admin) cannot sign off; another admin can
    WHO = { user: 'tester.syn', role: 'admin' }; await p.reload(); await p.click('[data-tab="uat"]'); await p.waitForSelector('#uatsign:not([disabled])');
    await p.click('#uatsign'); await p.waitForSelector('#usf'); await p.click('#usf button[type=submit]');
    await p.waitForFunction(() => /four eyes/.test((document.querySelector('#usf [data-msg]') || {}).textContent || ''), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'the tester cannot sign off'));
    await p.keyboard.press('Escape');
    WHO = { user: 'manager.syn', role: 'admin' }; await p.reload(); await p.click('[data-tab="uat"]'); await p.waitForSelector('#uatsign:not([disabled])');
    await p.click('#uatsign'); await p.waitForSelector('#usf'); await p.fill('#usf [name="note"]', 'accepted (synthetic)'); await p.click('#usf button[type=submit]');
    await p.waitForFunction(() => /Signed off/.test(document.getElementById('uathead').textContent), null, { timeout: 8000 });
    ok(/manager\.syn/.test(await p.textContent('#uathead')) && audits.some((a) => a[0] === 'sysadmin.uat.signoff' && a[3] === 'manager.syn'), 'signed off by another admin, audited');
    // a new round keeps the old one
    await p.click('#uatnew'); await p.waitForSelector('#unf'); await p.fill('#unf [name="note"]', 'second round (synthetic)'); await p.click('#unf button[type=submit]');
    await p.waitForFunction(() => /UAT round 2/.test(document.getElementById('uathead').textContent), null, { timeout: 8000 });
    ok(/Earlier rounds/.test(await p.textContent('#uatpast')) && /manager\.syn/.test(await p.textContent('#uatpast')), 'earlier round listed with its sign-off');
    // a viewer reads only
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.reload(); await p.click('[data-tab="uat"]'); await p.waitForSelector('#uatlist table', { state: 'attached' });
    ok(!(await p.$('#uatlist tr.click')) && !(await p.$('#uatnew')) && !(await p.$('#uatsign')), 'a viewer cannot record, sign off or start a round');
    // the Exchange page has no UAT tab
    await p.goto(base + 'exchange-admin.html?standalone=1'); await p.waitForSelector('.tabs');
    ok(!(await p.$('[data-tab="uat"]')), 'no UAT tab on the Exchange page');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
