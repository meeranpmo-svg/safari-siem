// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the leaver mailbox conversion on HR Offboarding (hr-offboarding.html) against the REAL ITAM engine
// (offboarding.js + exo.js) with a stubbed Exchange Online runner, SYNTHETIC data only: an administrator saves the Exchange
// Online settings (helper text, password never filled back); a disabled leaver shows the mailbox proposed with the manager as
// delegate and the automatic reply; the person who raised the request cannot approve; another administrator approves with an
// extra delegate and the page shows it converted and verified with each step; a KPI tile counts the waiting conversion.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding-mailbox.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const PFX_PW = 'Synthetic-Pfx-Pass-7';

(async () => {
  const st = { type: 'UserMailbox', perms: [], reply: null };
  const exoRun = async (op, p) => {
    if (op === 'get-mailbox') return { ok: true, data: { found: true, type: st.type, litigation_hold: false, archive: 'None' } };
    if (op === 'convert-shared') { st.type = 'SharedMailbox'; return { ok: true, data: { type: st.type } }; }
    if (op === 'add-fullaccess') { st.perms.push(p.user); return { ok: true, data: { granted: true } }; }
    if (op === 'set-autoreply') { st.reply = p.message; return { ok: true, data: {} }; }
    if (op === 'test') return { ok: true, data: { organization: 'Corp Synthetic' } };
    return { ok: false, error: 'x' };
  };
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', exoRun });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, HRA = { user: 'hana.syn', role: 'admin' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
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
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'hr-offboarding.html?standalone=1'); await p.waitForSelector('#list', { timeout: 15000 });
    await p.click('#exoset'); await p.waitForSelector('#exoform .zyb-hint', { timeout: 8000 });
    ok(await p.$$eval('#exoform input[name]:not([type=checkbox]), #exoform textarea[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text on the settings');
    await p.check('#exoform [name=enabled]'); await p.fill('#exoform [name=organization]', 'corp.onmicrosoft.com'); await p.fill('#exoform [name=app_id]', '66666666-7777-8888-9999-000000000000');
    await p.fill('#exoform [name=cert_path]', '/etc/sentra/exo-app.pfx'); await p.fill('#exoform [name=cert_password]', PFX_PW);
    await Promise.all([p.waitForResponse((r) => /offboarding\/exo$/.test(r.url()) && r.request().method() === 'POST'), p.click('#exoform [type=submit]')]);
    ok(await zd(p, /set \(sealed, never shown\)/) && (await p.inputValue('#exoform [name=cert_password]')) === '' && !(await p.content()).includes(PFX_PW), 'saved; the password is never put back into the page');
    await Promise.all([p.waitForResponse((r) => /exo\/test$/.test(r.url())), p.click('[data-act="exotest"]')]);
    ok(await zd(p, /connected to Corp Synthetic/), 'connection test');
    // a leaver, disabled by hand
    await api('POST', '/offboarding', { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: new Date().toISOString().slice(0, 10), manager: 'faisal.syn', reason: 'resignation' }, HRA);
    await api('POST', '/offboarding/OFF-001/confirm', { decision: 'confirm' }, { user: 'faisal.syn', role: 'operator' });
    await api('POST', '/offboarding/OFF-001/approve', { decision: 'approve' }, ADM);
    await api('POST', '/offboarding/OFF-001/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, { user: 'desk.syn', role: 'operator' });
    WHO = HRA; await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 });
    ok(/Mailbox conversion waiting for approval/.test(await p.textContent('#kpis')), 'KPI tile');
    await openRow(p);
    ok(await zd(p, /waiting for approval/) && (await p.inputValue('#ofmbx [name=delegates]')) === 'faisal.syn@corp.syn' && /no longer works/.test(await p.inputValue('#ofmbx [name=auto_reply]')), 'proposed with the manager and the reply');
    await p.selectOption('#ofmbx [name=decision]', 'approve');
    await Promise.all([p.waitForResponse((r) => /mailbox\/decide$/.test(r.url())), p.click('#ofmbx [type=submit]')]);
    ok(await msg(p, '#ofmbx', /raised OFF-001 and cannot also approve/), 'the person who raised it cannot approve');
    WHO = ADM; await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p);
    await p.selectOption('#ofmbx [name=decision]', 'approve'); await p.fill('#ofmbx [name=delegates]', 'faisal.syn@corp.syn, claims-team@corp.syn');
    await Promise.all([p.waitForResponse((r) => /mailbox\/decide$/.test(r.url())), p.click('#ofmbx [type=submit]')]);
    ok(await zd(p, /converted to shared and verified/) && await zd(p, /Full Access for claims-team@corp\.syn: done/), 'converted, each step shown');
    ok(st.type === 'SharedMailbox' && st.perms.join() === 'faisal.syn@corp.syn,claims-team@corp.syn' && /no longer works/.test(st.reply), 'done in Exchange Online');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
