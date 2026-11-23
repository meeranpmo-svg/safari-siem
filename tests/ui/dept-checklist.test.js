// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Department Checklist (dept-checklist.html) against the REAL ITAM engine, SYNTHETIC names only: with no head
// named every department reads not assessed; an admin names a head in the Department heads drawer; the head attests an
// obligation from its drawer (the evidence reference is required, a hostile reference stays text); the attestation reads "to
// verify", not compliant; an independent auditor verifies it and only then the department card shows a fully compliant share;
// the department card and the status filter narrow the list; the CSV export downloads and is recorded; a viewer sees statuses
// but no evidence; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node dept-checklist.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  const clock = Date.parse('2027-01-10T08:00:00Z');
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', eccFacts: async () => ({}), ndmoCatalogFiles: false });
  const ADM = { user: 'syed', role: 'admin' }, HEAD = { user: 'huda.syn', role: 'operator' }, AUD = { user: 'adel.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const fl = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!fl.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(fl, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const closeDrawer = async (p) => { await p.keyboard.press('Escape'); await p.waitForFunction(() => { const z = document.getElementById('zd'); return !z || !z.offsetParent || getComputedStyle(z).display === 'none'; }, null, { timeout: 5000 }).catch(() => {}); };
  const toast = (p) => p.waitForSelector('.toast-zyb', { timeout: 8000 }).then(() => p.$$eval('.toast-zyb', (x) => x.map((t) => t.textContent).join(' | ')));
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1100 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); });
    await p.goto(base + 'dept-checklist.html?standalone=1'); await p.waitForSelector('#list tr[data-ob]', { timeout: 20000 });
    const kp = (await p.textContent('#kpis')).replace(/\s+/g, ' ');
    ok(/Not assessed/.test(kp) && /100%/.test(kp) && /15\s*Departments with no head named/.test(kp), 'nothing named: not assessed, 15 departments without a head: ' + kp.slice(0, 200));
    ok((await p.$$('#depts [data-dept]')).length === 15 && (await p.$$('#fws [data-fwk]')).length === 5, 'a card per department and per framework');
    // the admin names the HR head
    await p.click('#heads'); await p.waitForSelector('#hdf');
    ok(/not named/.test(await p.textContent('#zd')), 'heads drawer lists departments with no head');
    await p.selectOption('#hdf select[name=dept]', 'hr'); await p.fill('#hdf input[name=head]', HEAD.user); await p.click('#hdf button[type=submit]');
    ok(/Human Resources: head huda\.syn/.test(await toast(p)), 'head named');
    await p.waitForFunction(() => /huda\.syn/.test(document.getElementById('zd').textContent), null, { timeout: 8000 }).then(() => ok(true, 'drawer refreshed'), () => ok(false, 'drawer refreshed'));
    ok(e.app.store.auditTail(30).some((x) => x.action === 'dept-checklist.owner' && x.by === ADM.user), 'naming is recorded');
    await closeDrawer(p);
    // the head attests DO-01
    WHO = HEAD; await p.reload(); await p.waitForSelector('#list tr[data-ob]');
    await p.click('#depts [data-dept="hr"]');
    ok((await p.$$('#list tr[data-ob]')).length === 5 && await p.inputValue('#fdept') === 'hr', 'the HR card filters the list');
    await p.click('#list tr[data-ob="DO-01"]'); await p.waitForSelector('#atf');
    await p.selectOption('#atf select[name=status]', 'done'); await p.click('#atf button[type=submit]');
    await p.waitForFunction(() => /evidence is required/.test((document.querySelector('#atf [data-msg]') || {}).textContent || ''), null, { timeout: 8000 }).then(() => ok(true, 'evidence required'), () => ok(false, 'evidence required'));
    await p.fill('#atf input[name=evidence]', XSS + ' DMS/HR/screening-2027-Q1'); await p.click('#atf button[type=submit]');
    ok(/DO-01: Attested · to verify/.test(await toast(p)), 'attested, waiting for the auditor');
    await p.waitForFunction(() => /screening-2027-Q1/.test(document.getElementById('zd').textContent), null, { timeout: 8000 }).catch(() => {});
    ok(/screening-2027-Q1/.test(await p.textContent('#zd')) && !(await p.$('img[src="x"]')), 'the evidence reference shows in the periods table, as text');
    await closeDrawer(p);
    ok(/Attested · to verify/.test(await p.textContent('#list tr[data-ob="DO-01"]')), 'the row reads to verify');
    const hr0 = await p.textContent('#depts [data-dept="hr"]'); ok(/Fully 0%/.test(hr0.replace(/\s+/g, ' ')), 'not compliant until verified: ' + hr0.replace(/\s+/g, ' '));
    // an independent auditor verifies
    WHO = AUD; await p.reload(); await p.waitForSelector('#list tr[data-ob]');
    await p.selectOption('#fres', 'awaiting_review');
    ok((await p.$$('#list tr[data-ob]')).length === 1, 'the to-verify filter shows the one attestation');
    await p.click('#list tr[data-ob="DO-01"]'); await p.waitForSelector('#rvf');
    await p.selectOption('#rvf select[name=decision]', 'verified'); await p.click('#rvf button[type=submit]');
    ok(/DO-01: Done · verified/.test(await toast(p)), 'verified');
    await closeDrawer(p);
    const hr1 = (await p.textContent('#depts [data-dept="hr"]')).replace(/\s+/g, ' ');
    ok(/Partially compliant/.test(hr1) && /Fully 20%/.test(hr1), 'HR: 1 of 5 fully compliant (20%): ' + hr1);
    ok(e.app.store.auditTail(30).some((x) => x.action === 'dept-checklist.review' && x.by === AUD.user && x.detail.attested_by === HEAD.user), 'the review is recorded with who attested');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#csv')]);
    ok(/^department-checklist-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'CSV downloaded: ' + dl.suggestedFilename());
    ok(e.app.store.auditTail(30).some((x) => x.action === 'dept-checklist.export' && x.by === AUD.user), 'the export is recorded');
    // a viewer sees statuses, not evidence or names
    WHO = VIEW; await p.reload(); await p.waitForSelector('#list tr[data-ob]');
    await p.click('#list tr[data-ob="DO-01"]'); await p.waitForSelector('#zd');
    const z = await p.textContent('#zd'); ok(/verified/.test(z) && !/screening-2027-Q1/.test(z) && !/huda\.syn/.test(z), 'viewer: status without evidence or names');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } catch (x) { ok(false, 'exception: ' + (x && x.stack || x)); }
  await browser.close(); srv.close(); await e.close();
  console.log(bad ? `${bad}/${n} FAILED` : `all ${n} checks passed`);
  process.exit(bad ? 1 : 0);
})();
