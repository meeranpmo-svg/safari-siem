// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for pdpl-retention.html against the real IT Asset Management engine (engine/pdpl-retention.js with a stubbed
// count runner - no database): empty state, a hostile catalog name stays text and cannot be mapped, map a rule to a table
// and its date column, Scan now, the task for the data owner, the owner (viewer role) records the disposal, the DPO (another
// person) accepts, the next scan verifies the count fell; a viewer with no task is refused gracefully; no page errors.
// Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-retention.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'nora.syn', role: 'operator' };
const XSS = '<img src=x onerror=alert(1)>';
(async () => {
  const e = await H.startApp({ noAi: true });
  const S = e.app.store;
  S.collection('pdpl_records').put({ id: 'profile', kind: 'profile', dpo_user: 'dpo.syn', status: 'active' });
  S.collection('pdpl_records').put({ id: 'PD-RETENTION-001', kind: 'retention', status: 'active', name: 'Closed motor claims (synthetic)', period_months: 120, trigger: 'claim_closed', action: 'destroy', systems: ['CLAIMS-SYN'] });
  S.collection('pdpl_discovery').put({ id: 'mssql|10.99.0.5|1433', db: 'mssql|10.99.0.5|1433', engine: 'mssql', label: 'CLAIMS-SYN', host: '10.99.0.5', port: 1433, cred_id: 'syn-ro', ok: true, columns: [
    { owner: 'dbo', table: 'Claims', column: 'ClaimantNationalId', type: 'varchar', rows: 9000, kind: 'national_id', category: 'identity', confirmed: true },
    { owner: 'dbo', table: 'Claims', column: 'DateOfBirth', type: 'date', rows: 9000, kind: 'birth_date', category: 'identity' },
    { owner: 'dbo', table: XSS, column: 'Email', type: 'nvarchar', rows: 3, kind: 'email', category: 'contact' }] });
  S.collection('pdpl_office_cfg').put({ id: 'cfg', owners: [{ system: 'CLAIMS-SYN', user: 'owner.syn' }] });
  const COUNT = { Claims: 1200 }, asked = [];
  require(path.join(ITAM, 'engine/pdpl-retention')).registerPdplRetention(e.app.srv, e.app, { noTimer: true, now: ((t0, w0) => () => t0 + (Date.now() - w0))(Date.parse('2026-11-13T08:00:00Z'), Date.now()), runQuery: async (q) => { asked.push(q); return { ok: true, count: COUNT[q.table], oldest: '2011-02-03' }; } });
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, WHO);
    if (u.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.startsWith('/api/')) return json(404, {});
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/pdpl-retention.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = []; let dialogs = 0;
  const open = async (who) => { WHO = who; const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); }); await p.goto(base); return p; };
  const txt = (p, id) => p.$eval('#' + id, (x) => x.innerText);
  try {
    let p = await open({ user: 'nora.syn', role: 'operator' });
    await p.waitForFunction(() => /No table is mapped yet/.test(document.getElementById('maps').innerText));
    ok(/never scanned/.test(await txt(p, 'last')), 'empty state: never scanned, says what to do');
    ok(/No disposal task/.test(await txt(p, 'tasks')), 'no task yet - nothing invented');
    ok(/Counts only/.test(await p.$eval('main', (x) => x.innerText)), 'counts-only framing');
    // the hostile catalog name stays text
    const opts = await p.$$eval('#m-table option', (a) => a.map((o) => o.textContent));
    ok(opts.some((o) => o.includes(XSS) && /cannot be queried safely/.test(o)), 'hostile table name shown as text, marked: ' + opts.join(' | '));
    ok(await p.$$eval('main img', (a) => a.length) === 0, 'no element injected');
    await p.selectOption('#m-rule', 'PD-RETENTION-001');
    await p.selectOption('#m-table', { index: 2 }); await p.fill('#m-col', 'ClosedDate'); await p.click('#mform button[type=submit]');
    await p.waitForFunction(() => /table must be a database name/.test(document.querySelector('#mform [data-msg]').textContent));
    ok(true, 'mapping the hostile table refused with the server\'s reason');
    // map Claims: the catalog's date column is offered, the person types the one retention starts from
    await p.selectOption('#m-table', { index: 1 });
    ok(/DateOfBirth/.test(await p.$eval('#m-cols', (x) => x.innerHTML)) && /birth date/.test(await p.$eval('#m-cols', (x) => x.innerHTML)), 'catalog date column suggested, with the birth-date caution');
    ok(await p.$eval('#m-system', (x) => x.value) === 'CLAIMS-SYN', 'system name pre-filled from the catalog');
    await p.fill('#m-col', 'ClosedDate'); await p.click('#mform button[type=submit]');
    await p.waitForFunction(() => /ClosedDate/.test(document.getElementById('maps').innerText));
    ok(/not scanned yet/.test(await txt(p, 'maps')) && /owner\.syn/.test(await txt(p, 'maps')), 'mapped, owner from the Privacy Office');
    // scan now
    await p.click('#scan'); await p.waitForFunction(() => /1,200/.test(document.getElementById('maps').innerText));
    ok(asked.length === 1 && asked[0].op === 'retention_count' && asked[0].table === 'Claims' && asked[0].column === 'ClosedDate', 'one count requested: ' + JSON.stringify(asked));
    ok(/oldest 2011-02-03/.test(await txt(p, 'maps')), 'oldest date shown');
    ok(/RT-00001/.test(await txt(p, 'tasks')) && /open/.test(await txt(p, 'tasks')), 'task opened');
    ok(/1,200/.test(await txt(p, 'kpis')), 'KPI: rows past retention');
    await p.close();
    // the data owner (viewer role): sees their task, records the disposal
    p = await open({ user: 'owner.syn', role: 'viewer' });
    await p.waitForSelector('[data-attest="RT-00001"]');
    ok(/Your disposal tasks/.test(await txt(p, 'taskstitle')) && !(await p.isVisible('#mapcard')), 'owner view: own tasks only');
    await p.click('[data-attest="RT-00001"]'); await p.waitForSelector('#aform');
    await p.selectOption('#a-method', 'deletion'); await p.fill('#a-date', '2026-11-10'); await p.fill('#a-ref', 'CHG-SYN-501'); await p.fill('#a-note', 'Purged closed claims older than ten years (synthetic)');
    await p.click('#aform button[type=submit]');
    await p.waitForFunction(() => /waiting for the DPO/.test(document.getElementById('tasks').innerText));
    ok(/CHG-SYN-501/.test(await txt(p, 'tasks')) && /by owner\.syn/.test(await txt(p, 'tasks')), 'attestation recorded with who');
    await p.close();
    // an operator who is not the DPO cannot accept; the DPO (another person) accepts
    p = await open({ user: 'nora.syn', role: 'operator' });
    await p.waitForFunction(() => /waiting for the DPO/.test(document.getElementById('tasks').innerText));
    ok(!(await p.$('[data-accept]')), 'no Accept button for an operator who is not the DPO');
    await p.close();
    p = await open({ user: 'dpo.syn', role: 'operator' });
    await p.waitForSelector('[data-accept="RT-00001"]'); await p.click('[data-accept="RT-00001"]');
    await p.waitForFunction(() => /accepted - next scan verifies/.test(document.getElementById('tasks').innerText));
    ok(/accepted by dpo\.syn/.test(await txt(p, 'tasks')), 'accepted by the DPO');
    // the next scan verifies the count fell
    COUNT.Claims = 0;
    await p.click('#scan'); await p.waitForFunction(() => /verified/.test(document.getElementById('tasks').innerText) && !/not verified/.test(document.getElementById('tasks').innerText));
    ok(/1,200 → 0/.test(await txt(p, 'tasks')), 'verification shown: ' + (await txt(p, 'tasks')).slice(0, 300));
    ok(/1\s*Verified/i.test(await txt(p, 'kpis')), 'KPI verified: ' + (await txt(p, 'kpis')).replace(/\s+/g, ' '));
    // a hold: requested by the DPO, approve button shown only to another approver
    await p.click('[data-hold="RM-00001"]'); await p.waitForSelector('#aform');
    await p.fill('#a-note', 'Court case CASE-SYN-7 on these claims (synthetic)'); await p.fill('#a-date', '2027-06-30'); await p.click('#aform button[type=submit]');
    await p.waitForFunction(() => /waiting for approval/.test(document.getElementById('holds').innerText));
    await p.click('[data-happrove]'); await p.waitForTimeout(400);
    ok(/four-eyes/.test(await p.evaluate(() => [...document.querySelectorAll('.toast-zyb')].map((x) => x.textContent).join(' '))), 'the requester\'s own approval refused, the reason shown');
    await p.close();
    // a viewer with no task: refused gracefully
    p = await open({ user: 'v.syn', role: 'viewer' });
    await p.waitForFunction(() => /No disposal task is assigned to you/.test(document.getElementById('tasks').innerText));
    ok(/for operators/.test(await txt(p, 'msg')), 'viewer: what the page is and who sees it');
    ok(!(await p.isVisible('#scan')) && !(await p.isVisible('#mapcard')), 'viewer: no scan, no mapping');
    await p.close();
    // the store and the audit hold no personal data value and record who did what
    const acts = S.auditTail(200).map((x) => x.action);
    for (const a of ['pdpl.retention.map.add', 'pdpl.retention.scan', 'pdpl.retention.task.open', 'pdpl.retention.task.attest', 'pdpl.retention.task.accept', 'pdpl.retention.task.verified', 'pdpl.retention.hold.request']) ok(acts.includes(a), 'audited: ' + a);
    ok(!errs.length, 'page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
