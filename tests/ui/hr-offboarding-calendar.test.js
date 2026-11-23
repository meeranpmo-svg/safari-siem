// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for leaver meetings on HR Offboarding (hr-offboarding.html) against the REAL ITAM engine (offboarding.js +
// m365-licensing.js) and an in-process fake Microsoft Graph calendar, SYNTHETIC data only: before the disable an operator checks
// the meetings (read-only) - outside attendees marked, a hostile subject kept as text; the approval form offers the meetings
// decision ("decide after" chosen); the person who raised the request cannot decide; another administrator leaves one meeting
// out and moves the other to the manager - created again by the manager, the leaver's one cancelled, the left-out one untouched.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding-calendar.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const TENANT = '11111111-2222-3333-4444-555555555555';
const A = (a) => ({ emailAddress: { address: a }, type: 'required' });

(async () => {
  const fut = (d) => new Date(Date.now() + d * 86400000).toISOString().slice(0, 19);
  const ev = { M1: { id: 'M1', subject: 'Broker review ' + XSS, type: 'singleInstance', isOrganizer: true, isCancelled: false, sensitivity: 'normal', start: { dateTime: fut(3), timeZone: 'UTC' }, end: { dateTime: fut(3.05), timeZone: 'UTC' }, attendees: [A('khalid.harbi@corp.syn'), A('ops@corp.syn'), A('agent@broker.example')], body: { content: 'agenda' } },
    M2: { id: 'M2', subject: 'Claims stand-up', type: 'singleInstance', isOrganizer: true, isCancelled: false, sensitivity: 'normal', start: { dateTime: fut(5), timeZone: 'UTC' }, end: { dateTime: fut(5.02), timeZone: 'UTC' }, attendees: [A('ops@corp.syn')], body: { content: 'x' } } };
  const made = {};
  const G = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), P = u.pathname.replace('/v1.0', ''), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '' : JSON.stringify(o)); };
    let m;
    if (u.pathname === '/' + TENANT + '/oauth2/v2.0/token') return J(200, { access_token: 'tok' });
    if (P === '/organization') return J(200, { value: [{ verifiedDomains: [{ name: 'corp.syn' }] }] });
    if ((m = /^\/users\/([^/]+)$/.exec(P))) return J(200, { id: 'id-' + decodeURIComponent(m[1]) });
    if (/^\/users\/khalid\.harbi(%40|@)corp\.syn\/events$/.test(P)) return J(200, { value: Object.values(ev) });
    if ((m = /^\/users\/[^/]+\/events\/([^/]+)\/cancel$/.exec(P))) { ev[m[1]].isCancelled = true; return J(202); }
    if ((m = /^\/users\/([^/]+)\/events\/([^/]+)$/.exec(P))) { const k = decodeURIComponent(m[2]); return decodeURIComponent(m[1]).startsWith('khalid') ? J(200, ev[k]) : J(200, made[k]); }
    if ((m = /^\/users\/([^/]+)\/events$/.exec(P)) && req.method === 'POST') { const p = JSON.parse(b), id = 'N' + Object.keys(made).length; made[id] = Object.assign({ id, owner: decodeURIComponent(m[1]) }, p); return J(201, made[id]); }
    J(404, { error: { code: 'x', message: 'x' } });
  }); });
  await new Promise((r) => G.listen(0, '127.0.0.1', r));
  const gb = 'http://127.0.0.1:' + G.address().port;
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, HRA = { user: 'hana.syn', role: 'admin' }, DESK = { user: 'desk.syn', role: 'operator' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
  await api('POST', '/onboarding/m365', { tenant_id: TENANT, client_id: '66666666-7777-8888-9999-000000000000', client_secret: 'Synthetic-Graph-Secret-1', calendar_enabled: true }, ADM);
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
    await Promise.all([p.waitForResponse((r) => /calendar\/check$/.test(r.url())), p.click('[data-act="ccheck"]')]);
    await p.waitForSelector('#zd .steps', { timeout: 8000 });
    ok(await zd(p, /Claims stand-up/) && await zd(p, /1 outside/), 'the check lists the meetings, outside attendees marked');
    ok(!(await p.$('#zd img')) && await zd(p, /Broker review <img/), 'a hostile subject stays text');
    ok(!Object.keys(made).length && !ev.M1.isCancelled, 'a check changes nothing');
    await as(p, ADM);
    ok((await p.inputValue('#ofappr [name=calendar]')) === 'transfer' && !!(await p.getAttribute('#ofappr [name=calendar]', 'data-hinted')), 'approval offers the meetings decision, with helper text');
    await p.selectOption('#ofappr [name=decision]', 'approve'); await p.selectOption('#ofappr [name=calendar]', 'ask');
    await Promise.all([p.waitForResponse((r) => /\/approve$/.test(r.url())), p.click('#ofappr [type=submit]')]);
    await api('POST', '/offboarding/OFF-001/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK);
    await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 });
    ok(/Meetings waiting to be handed over/.test(await p.textContent('#kpis')), 'a tile counts the meetings waiting');
    await as(p, HRA);
    await p.selectOption('#ocal [name=decision]', 'approve');
    await Promise.all([p.waitForResponse((r) => /calendar\/decide$/.test(r.url())), p.click('#ocal [type=submit]')]);
    ok(await msg(p, '#ocal', /four eyes/), 'the person who raised it cannot decide');
    await as(p, ADM);
    ok((await p.inputValue('#ocal [name=owner]')) === 'faisal.syn@corp.syn', 'the manager suggested');
    await p.selectOption('#ocal [name=decision]', 'approve');
    await p.check('#ocal input[name=exclude][value^="Claims stand-up"]');
    await Promise.all([p.waitForResponse((r) => /calendar\/decide$/.test(r.url())), p.click('#ocal [type=submit]')]);
    ok(await zd(p, /handed over and verified/) && await zd(p, /created again · cancelled/), 'handed over, each result shown');
    const nm = Object.values(made);
    ok(nm.length === 1 && nm[0].owner === 'faisal.syn@corp.syn' && /Broker review/.test(nm[0].subject) && ev.M1.isCancelled && !ev.M2.isCancelled, 'moved to the manager; the left-out meeting untouched');
  } finally { await browser.close(); srv.close(); G.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
