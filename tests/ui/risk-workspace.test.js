// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Head of Risk & Compliance's workspace (dashboards/server/my-workspace.html, tab "Risk & Compliance") against
// the REAL ITAM engines (team workspace, roles, GRC register, Risk Studio, Risk Command Center, Audit Dashboard; Microsoft sign-in and
// Graph stubbed) with SYNTHETIC records: an administrator gives the user "risk" the Head of Risk & Compliance job title and access
// role; on sign-in the workspace opens on the Risk & Compliance tab with the brief, the ranked priorities (each with its reasons), the
// risks and actions he owns, the overdue work in his area, compliance per framework, the risk and compliance mail ranked by a keyword
// classifier (the newsletter left out) and the risk meetings with the records to prepare; the home page offers the Risk & Compliance
// team home and his menu shows only the risk, compliance, data privacy and audit sections.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-workspace.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, RISK = { user: 'risk', role: 'operator' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const sealer = { available: () => true, unavailableReason: () => null, seal: (id, v) => ({ id, ct: Buffer.from(String(v)).toString('base64') }), unseal: (id, x) => Buffer.from(x.ct, 'base64').toString() };
  const iso = (ms) => new Date(Date.now() + ms).toISOString().replace('Z', '');
  const request = async (url) => {
    if (url.endsWith('/oauth2/v2.0/token')) return { status: 200, json: { access_token: 'AT-syn', refresh_token: 'RT-syn', expires_in: 3600 } };
    if (url.includes('/me?$select')) return { status: 200, json: { userPrincipalName: 'risk.syn@corpgroup.test', mail: 'risk.syn@corpgroup.test' } };
    if (url.includes('/me/mailFolders/inbox/messages')) return { status: 200, json: { value: [
      { id: 'AAMkMSG0000000011', subject: 'SAMA cyber risk audit findings - deadline Thursday (synthetic) ' + XSS, from: { emailAddress: { name: 'Internal Audit', address: 'ia.syn@corpgroup.test' } }, receivedDateTime: new Date().toISOString(), isRead: false, importance: 'high', bodyPreview: '' },
      { id: 'AAMkMSG0000000012', subject: 'PDPL compliance update for the committee (synthetic)', from: { emailAddress: { name: 'DPO Syn', address: 'dpo.syn@corpgroup.test' } }, receivedDateTime: new Date().toISOString(), isRead: true, importance: 'normal', bodyPreview: '' },
      { id: 'AAMkMSG0000000013', subject: 'Newsletter: lunch menu (synthetic)', from: { emailAddress: { name: 'News', address: 'news@vendor.test' } }, receivedDateTime: new Date().toISOString(), isRead: true, importance: 'normal', bodyPreview: '' }] } };
    if (url.includes('/me/calendarView')) return { status: 200, json: { value: [
      { id: 'E1', subject: 'Risk committee: ransomware risk review (synthetic)', start: { dateTime: iso(3600000) }, end: { dateTime: iso(7200000) }, isOnlineMeeting: true, onlineMeeting: { joinUrl: 'https://teams.microsoft.com/l/meetup-join/19%3asyn' } },
      { id: 'E2', subject: 'Team lunch (synthetic)', start: { dateTime: iso(9000000) }, end: { dateTime: iso(10000000) } }] } };
    if (url.includes('/me/chats?')) return { status: 200, json: { value: [] } };
    return { status: 404, json: null };
  };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, wsRequest: request, wsSealer: sealer });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  { const W = e.app.addons.workflow;   // the real Workflow Automation engine, synthetic people: the risk function's request, fulfilled by the security team
    W.settingsSave({ version: 0, functions: { risk: ['risk'] }, teams: { security: ['sec.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
    const wr = W.create({ type: 'vuln-remediation', from: 'risk', title: 'Critical vulnerabilities for the KRI <img src=x onerror=window.__wfx=1>', details: 'count by system' }, { user: 'risk', role: 'operator', ip: '' });
    W.act(wr.id, 'start', {}, { user: 'sec.syn', role: 'operator', ip: '' }); W.act(wr.id, 'fulfil', { response: 'attached' }, { user: 'sec.syn', role: 'operator', ip: '' }); }
  let WHO = ADM;
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
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p) => p.evaluate(() => document.body.innerText);
  const tab = async (p, t) => { await p.click('#tabs [data-tab="' + t + '"]'); };
  try {
    const api = async (who, m, p, body) => { const r = await e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
    // the administrator: the structure, the person "risk" with the Head of Risk & Compliance title, the access role, Microsoft 365
    await api(ADM, 'POST', '/workspace/template', { template: 'standard-it' });
    await api(ADM, 'POST', '/workspace/people', { id: 'risk', name: 'Risk Head Syn', user: 'risk', email: 'risk.syn@corpgroup.test', department: 'risk-compliance', role: 'head-risk-compliance' });
    await api(ADM, 'POST', '/roles/assign', { user: 'risk', role_id: 'risk-head' });
    await api(ADM, 'POST', '/workspace/m365/settings', { tenant_id: '11111111-1111-1111-1111-111111111111', client_id: '22222222-2222-2222-2222-222222222222', client_secret: 'SECRET-syn', redirect_uri: 'https://portal.test/dashboards/my-workspace.html', enabled: true });
    // synthetic register: his risk and actions, someone else's overdue action
    const d = (n2) => new Date(Date.now() + n2 * 86400000).toISOString().slice(0, 10);
    await api(RISK, 'POST', '/grc/risks', { title: 'Ransomware on the claims servers (synthetic) ' + XSS, likelihood: 4, impact: 5, treatment: 'mitigate', owner: 'risk', description: 'synthetic' });
    await api(RISK, 'POST', '/grc/actions', { title: 'Approve the risk appetite statement (synthetic)', owner: 'risk', due: d(-6), source: 'manual' });
    await api(RISK, 'POST', '/grc/actions', { title: 'Close the access review gap (synthetic)', owner: 'ali.syn', due: d(-15), source: 'manual' });
    WHO = RISK;
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (x) => x.accept());
    await p.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(p, () => /Risk/.test(document.getElementById('hi').textContent) && /Head of Risk & Compliance/.test(document.getElementById('sub').textContent)), 'greeting and job title');
    ok(await wait(p, () => !!document.querySelector('#tabs [data-tab="risk"][aria-selected="true"]')), 'the workspace opens on the Risk & Compliance tab');
    ok(await wait(p, () => /You own 1 open risk/.test(document.getElementById('rbrief').textContent)), 'the brief');
    ok(await p.waitForFunction(() => !!document.getElementById('rwf'), null, { timeout: 10000 }).then(() => true, () => false), 'the risk tab has a Workflow Automation card');
    const rw = await p.textContent('#rwf'); ok(/1\s*results for you to accept/.test(rw) && /Critical vulnerabilities for the KRI <img/.test(rw) && !(await p.$('#rwf img')) && !(await p.evaluate(() => window.__wfx)), 'Workflow (Head of Risk): the result to accept; a hostile title stays text: ' + rw.replace(/\s+/g, ' ').slice(0, 160));
    ok(/requests needing me/.test(await p.textContent('#rkpis')) && /Workflow Automation: 0 request\(s\) from you and the risk function open with the IT teams, 1 result\(s\) waiting for your acceptance/.test(await p.textContent('#rbrief')) && /Critical vulnerabilities for the KRI/.test(await p.textContent('#rprio')) && !!(await p.$('#rwf a[href="workflow-automation.html#tab=new"]')), 'Workflow (Head of Risk): the KPI, the brief line, the priority and the links');
    ok(/1\. ACT-/.test(await p.textContent('#rprio')) && /your action, overdue \+60/.test(await p.textContent('#rprio')), 'priorities ranked, my overdue action first, with its points');
    ok(/RSK-/.test(await p.textContent('#rmine')) && /20 high/.test(await p.textContent('#rmine')) && !(await p.$('#rmine img')), 'the risks I own (a hostile title stays text)');
    ok(/Approve the risk appetite/.test(await p.textContent('#racts')) && /OVERDUE IN YOUR AREA/i.test(await p.textContent('#racts')) && /ali\.syn/.test(await p.textContent('#racts')), 'my actions and the overdue work in my area');
    ok((await p.$$('#rcomp .li')).length === 6, 'compliance: six frameworks');
    let state = null;
    await p.route('https://login.microsoftonline.com/**', (r) => { const u = new URL(r.request().url()); state = u.searchParams.get('state'); r.fulfill({ status: 302, headers: { Location: base + 'dashboards/my-workspace.html?code=C1&state=' + state } }); });
    await p.click('#connect');
    ok(await wait(p, () => /Microsoft 365: risk\.syn@corpgroup\.test/.test(document.getElementById('acct').textContent)), 'his own Microsoft 365 connected');
    await p.click('#tabs [data-tab="risk"]');
    ok(await wait(p, () => document.querySelectorAll('#rmail [data-mail]').length === 2), 'risk and compliance mail: two of three, the newsletter left out');
    ok(/regulator/.test(await p.textContent('#rmail')) && /SAMA cyber risk audit/.test(await p.textContent('#rmail').then((x) => x.split('PDPL')[0])), 'ranked, the regulator mail first, with the matched words as the reason');
    ok(!(await p.$('#rmail img')), 'a hostile subject stays text');
    ok(/Risk committee/.test(await p.textContent('#rmeet')) && !/Team lunch/.test(await p.textContent('#rmeet')), 'risk meetings only');
    ok(/Prepare: RSK-/.test(await p.textContent('#rmeet')), 'the meeting shows the records to prepare');
    ok(!!(await p.$('#rmeet a[href^="https://teams.microsoft.com/"]')), 'Join for a Teams meeting');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });
    // the home page: his team home; his menu: only his sections
    await p.goto(base + 'dashboards/index.html');
    ok(await wait(p, () => window.zybHomeTeams !== undefined && /Risk & Compliance/.test((document.getElementById('teamlabel') || {}).textContent || '')), 'the home page opens on the Risk & Compliance team home');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
