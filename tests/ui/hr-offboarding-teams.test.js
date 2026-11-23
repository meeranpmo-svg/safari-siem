// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for leaver groups and Teams on HR Offboarding (hr-offboarding.html) against the REAL ITAM engine (offboarding.js
// + m365-licensing.js) and an in-process fake Microsoft Graph, SYNTHETIC data only: the approval form offers the groups and Teams
// decision ("decide after" chosen); after the disable the page lists what the leaver owns, flags the team only the leaver owns,
// keeps a hostile group name as text; the person who raised the request cannot decide; another administrator hands them to the
// manager and the page shows each result; a tile counts groups only the leaver owns while the decision waits.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding-teams.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const TENANT = '11111111-2222-3333-4444-555555555555';
const id = (k) => '00000000-0000-4000-8000-' + String(k).padStart(12, '0');
const U = { k: id(1), f: id(2), o: id(3) };

(async () => {
  const users = { [U.k]: { id: U.k, userPrincipalName: 'khalid.harbi@corp.syn', accountEnabled: false }, [U.f]: { id: U.f, userPrincipalName: 'faisal.syn@corp.syn', accountEnabled: true }, [U.o]: { id: U.o, userPrincipalName: 'omar.syn@corp.syn', accountEnabled: true } };
  const groups = { [id(101)]: { id: id(101), displayName: 'Claims Team ' + XSS, groupTypes: ['Unified'], resourceProvisioningOptions: ['Team'], owners: [U.k], members: [U.k] },
    [id(102)]: { id: id(102), displayName: 'Finance Projects', groupTypes: ['Unified'], resourceProvisioningOptions: [], owners: [U.k, U.o], members: [U.k, U.o] } };
  const G = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '' : JSON.stringify(o)); };
    let m;
    if (u.pathname === '/' + TENANT + '/oauth2/v2.0/token') return J(200, { access_token: 'tok' });
    if ((m = /^\/v1\.0\/users\/([^/]+)$/.exec(u.pathname))) { const x = Object.values(users).find((y) => y.id === m[1] || y.userPrincipalName === decodeURIComponent(m[1])); return x ? J(200, x) : J(404, { error: { code: 'x', message: 'x' } }); }
    if ((m = /^\/v1\.0\/users\/([^/]+)\/ownedObjects\/microsoft\.graph\.group$/.exec(u.pathname))) return J(200, { value: Object.values(groups).filter((g) => g.owners.includes(m[1])) });
    if ((m = /^\/v1\.0\/groups\/([^/]+)\/(owners|members)\/\$ref$/.exec(u.pathname)) && req.method === 'POST') { const w = String(JSON.parse(b)['@odata.id']).split('/').pop(); if (!groups[m[1]][m[2]].includes(w)) groups[m[1]][m[2]].push(w); return J(204); }
    if ((m = /^\/v1\.0\/groups\/([^/]+)\/owners\/([^/]+)\/\$ref$/.exec(u.pathname))) { groups[m[1]].owners = groups[m[1]].owners.filter((x) => x !== m[2]); return J(204); }
    if ((m = /^\/v1\.0\/groups\/([^/]+)\/owners$/.exec(u.pathname))) return J(200, { value: groups[m[1]].owners.map((x) => users[x]) });
    J(404, { error: { code: 'x', message: 'x' } });
  }); });
  await new Promise((r) => G.listen(0, '127.0.0.1', r));
  const gb = 'http://127.0.0.1:' + G.address().port;
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, HRA = { user: 'hana.syn', role: 'admin' }, DESK = { user: 'desk.syn', role: 'operator' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
  await api('POST', '/onboarding/m365', { tenant_id: TENANT, client_id: '66666666-7777-8888-9999-000000000000', client_secret: 'Synthetic-Graph-Secret-1', teams_enabled: true }, ADM);
  await api('POST', '/offboarding', { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: new Date().toISOString().slice(0, 10), manager: 'faisal.syn', reason: 'resignation' }, HRA);
  await api('POST', '/offboarding/OFF-001/confirm', { decision: 'confirm' }, { user: 'faisal.syn', role: 'operator' });
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
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); });
    await p.goto(base + 'hr-offboarding.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p);
    ok((await p.inputValue('#ofappr [name=teams]')) === 'transfer' && !!(await p.getAttribute('#ofappr [name=teams]', 'data-hinted')), 'approval offers the groups and Teams decision, with helper text');
    await p.selectOption('#ofappr [name=decision]', 'approve'); await p.selectOption('#ofappr [name=teams]', 'ask');
    await Promise.all([p.waitForResponse((r) => /\/approve$/.test(r.url())), p.click('#ofappr [type=submit]')]);
    await api('POST', '/offboarding/OFF-001/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK);
    await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 });
    ok(/Groups \/ Teams only the leaver owns/.test(await p.textContent('#kpis')), 'a tile counts the groups only the leaver owns');
    await as(p, HRA);
    ok(await zd(p, /Groups and Teams/) && await zd(p, /none - only the leaver/) && await zd(p, /Finance Projects/), 'what the leaver owns, the orphan risk flagged');
    ok(!(await p.$('#zd img')) && await zd(p, /Claims Team <img/), 'a hostile group name stays text');
    await p.selectOption('#otm [name=decision]', 'approve');
    await Promise.all([p.waitForResponse((r) => /teams\/decide$/.test(r.url())), p.click('#otm [type=submit]')]);
    ok(await msg(p, '#otm', /four eyes/), 'the person who raised it cannot decide');
    await as(p, ADM);
    ok((await p.inputValue('#otm [name=owner]')) === 'faisal.syn@corp.syn', 'the manager suggested');
    await p.selectOption('#otm [name=decision]', 'approve');
    await Promise.all([p.waitForResponse((r) => /teams\/decide$/.test(r.url())), p.click('#otm [type=submit]')]);
    ok(await zd(p, /handed over and verified/) && await zd(p, /owner added · leaver removed/), 'handed over, each result shown');
    ok(groups[id(101)].owners.join() === U.f && groups[id(101)].members.includes(U.f) && groups[id(102)].owners.includes(U.o), 'done in Graph: the team now owned by the manager');
  } finally { await browser.close(); srv.close(); G.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
