// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for My Workspace (dashboards/server/my-workspace.html) against the REAL ITAM engine (engine/team-workspace.js;
// Microsoft sign-in and Graph stubbed) with SYNTHETIC people: an administrator adds the standard structure (and later only what is missing), adds people
// in the form (a bad e-mail refused with the field named) and sets up Microsoft 365; an engineer connects their own account
// through the sign-in round trip, reads the inbox (a hostile subject stays text), opens and replies to a message, sees meetings
// (Join only for Teams addresses) and Teams chats and sends a message; the manager assigns a task, the engineer submits it, the
// manager approves it from "Waiting for my review"; a person without a profile is told so; the menu entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node my-workspace.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, MGR = { user: 'mgr.syn', role: 'operator' }, ENG = { user: 'eng.syn', role: 'viewer' }, NOBODY = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const sent = [];
  const sealer = { available: () => true, unavailableReason: () => null, seal: (id, v) => ({ id, ct: Buffer.from(String(v)).toString('base64') }), unseal: (id, x) => Buffer.from(x.ct, 'base64').toString() };
  const request = async (url, o) => {
    if (url.endsWith('/oauth2/v2.0/token')) return { status: 200, json: { access_token: 'AT-syn', refresh_token: 'RT-syn', expires_in: 3600 } };
    if (url.includes('/me?$select')) return { status: 200, json: { userPrincipalName: 'eng.syn@corpgroup.test', mail: 'eng.syn@corpgroup.test' } };
    if (url.includes('/me/mailFolders/inbox/messages')) return { status: 200, json: { value: [
      { id: 'AAMkMSG0000000001', subject: 'Core switch change ' + XSS, from: { emailAddress: { name: 'Mgr Syn', address: 'mgr.syn@corpgroup.test' } }, receivedDateTime: new Date().toISOString(), isRead: false, importance: 'normal', bodyPreview: 'please review' },
      { id: 'AAMkMSG0000000002', subject: 'Newsletter (synthetic)', from: { emailAddress: { name: 'News', address: 'news@vendor.test' } }, receivedDateTime: new Date().toISOString(), isRead: true, importance: 'normal', bodyPreview: '' }] } };
    if (/\/me\/messages\/AAMkMSG0000000001\/reply(All)?$/.test(url)) { sent.push({ url, body: JSON.parse(o.body) }); return { status: 202, json: null }; }
    if (url.includes('/me/messages/AAMkMSG0000000001')) return { status: 200, json: { id: 'AAMkMSG0000000001', subject: 'Core switch change ' + XSS, from: { emailAddress: { name: 'Mgr Syn', address: 'mgr.syn@corpgroup.test' } }, toRecipients: [{ emailAddress: { name: 'Eng Syn', address: 'eng.syn@corpgroup.test' } }], body: { content: 'Please review the change window. ' + XSS } } };
    if (url.includes('/me/calendarView')) { const s = new Date(Date.now() + 3600000), f = new Date(Date.now() + 7200000), g = new Date(Date.now() + 9000000); const d = (x) => x.toISOString().replace('Z', '');
      return { status: 200, json: { value: [{ id: 'E1', subject: 'Change Advisory Board (synthetic)', start: { dateTime: d(s) }, end: { dateTime: d(f) }, isOnlineMeeting: true, onlineMeeting: { joinUrl: 'https://teams.microsoft.com/l/meetup-join/19%3asyn' } },
        { id: 'E2', subject: 'Lookalike (synthetic)', start: { dateTime: d(f) }, end: { dateTime: d(g) }, isOnlineMeeting: true, onlineMeeting: { joinUrl: 'https://teams.microsoft.com.evil.test/x' } }] } }; }
    if (url.includes('/me/chats?')) return { status: 200, json: { value: [{ id: '19:abcdef0123@thread.v2', chatType: 'group', topic: 'Infra team (synthetic)', lastMessagePreview: { createdDateTime: new Date().toISOString(), from: { user: { displayName: 'Mgr Syn' } }, body: { content: '<p>stand-up at 9</p>' } } }] } };
    if (url.includes('/me/chats/19%3Aabcdef0123%40thread.v2/messages')) return { status: 200, json: { value: [{ messageType: 'message', createdDateTime: new Date().toISOString(), from: { user: { displayName: 'Mgr Syn' } }, body: { content: '<p>stand-up at 9 ' + XSS + '</p>' } }] } };
    if (url.includes('/chats/19%3Aabcdef0123%40thread.v2/messages') && o.method === 'POST') { sent.push({ url, body: JSON.parse(o.body) }); return { status: 201, json: {} }; }
    return { status: 404, json: null };
  };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, wsRequest: request, wsSealer: sealer });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
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
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept());
    await p.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(p, () => !document.getElementById('main').hidden), 'admin: page loads');
    ok(/no profile in Team Workspace/i.test(await p.textContent('#sub')), 'an admin without a profile is told so');
    await tab(p, 'org');
    ok(await wait(p, () => !!document.getElementById('tpl')), 'empty organisation offers the IT / Cyber Security structure');
    await p.click('#tpl');
    ok(await wait(p, () => document.getElementById('pp-name') && /Senior Network/.test(document.getElementById('pp-role').textContent)), 'roles added; the people form lists them');
    const addP = async (name, user, email, role) => { await p.fill('#pp-name', name); await p.fill('#pp-user', user); await p.fill('#pp-email', email); await p.selectOption('#pp-dept', 'infrastructure'); await p.selectOption('#pp-role', role); await p.click('#pp-go'); };
    await addP('Eng Syn', 'eng.syn', 'not-mail', 'senior-net-sec-engineer');
    ok(await wait(p, () => /email must be an e-mail/i.test(document.body.textContent)), 'a bad e-mail is refused with the field named');
    await addP('Eng Syn', 'eng.syn', 'eng.syn@corpgroup.test', 'senior-net-sec-engineer');
    ok(await wait(p, () => /Eng Syn/.test(document.querySelector('#view table').textContent)), 'person added');
    await addP('Mgr Syn', 'mgr.syn', 'mgr.syn@corpgroup.test', 'infra-manager');
    ok(await wait(p, () => document.querySelectorAll('#view table tbody tr').length === 2), 'second person added');
    await p.click('[data-ot="chart"]');
    ok(await wait(p, () => /Infrastructure Department/.test(document.body.textContent) && /head: Mgr Syn/.test(document.body.textContent)), 'org chart: department head from the role');
    ok(/Vacant:.*Infrastructure Associate Manager/i.test(await txt(p)), 'vacant roles are listed');
    // an install made before SOC / Applications / Audit were standard: the page offers only what is missing
    ok((await e.req('POST', '/workspace/departments', Object.assign({ body: { id: 'audit', name: 'IT & Cyber Security Audit', head_role: '' } }, ADM))).status === 200, 'department head unlinked first');
    for (const x of ['roles/it-auditor', 'roles/audit-head', 'departments/audit']) { const r = await e.req('POST', '/workspace/' + x + '/delete', Object.assign({ body: {} }, ADM)); ok(r.status === 200, 'removed ' + x + ': ' + r.status); }
    await p.reload(); await wait(p, () => !document.getElementById('main').hidden); await tab(p, 'org'); await p.waitForSelector('[data-ot="roles"]');
    await p.click('[data-ot="roles"]');
    ok(await wait(p, () => /not added yet/i.test(document.body.textContent) && !!document.getElementById('tpl')), 'missing standard departments are offered');
    ok(/IT & Cyber Security Audit/.test(await txt(p)) && /Head of IT Audit/.test(await txt(p)), 'it names what is missing');
    await p.click('#tpl');
    ok(await wait(p, () => document.getElementById('pp-name') && /IT \/ Cyber Security Auditor/.test(document.getElementById('pp-role').textContent)), 'added back; the people form lists them');
    const org2 = (await e.req('GET', '/workspace/org', ADM)).json;
    ok(org2.departments.filter((d) => d.id === 'audit').length === 1 && org2.people.length === 2, 'added once; the people already there are untouched');
    await tab(p, 'settings');
    await p.fill('#ms-ten', '11111111-1111-1111-1111-111111111111'); await p.fill('#ms-cli', '22222222-2222-2222-2222-222222222222'); await p.fill('#ms-sec', 'SECRET-syn');
    await p.fill('#ms-red', 'https://portal.test/dashboards/my-workspace.html'); await p.selectOption('#ms-en', '1'); await p.click('#ms-go');
    ok(await wait(p, () => /Saved/.test(document.body.textContent)), 'Microsoft 365 settings saved');
    ok(/DELEGATED/.test(await txt(p)) && !/SECRET-syn/.test(await p.content()), 'setup says delegated; the secret is never shown back');

    // the engineer connects their own account
    WHO = ENG; await p.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(p, () => /Eng/.test(document.getElementById('hi').textContent) && !document.getElementById('connect').hidden), 'engineer: greeting, connect offered');
    ok(/reports to Mgr Syn/.test(await p.textContent('#sub')), 'reporting line shown (vacant associate manager -> department head)');
    let state = null;
    await p.route('https://login.microsoftonline.com/**', (r) => { const u = new URL(r.request().url()); state = u.searchParams.get('state'); r.fulfill({ status: 302, headers: { Location: base + 'dashboards/my-workspace.html?code=C1&state=' + state } }); });
    await p.click('#connect');
    ok(await wait(p, () => /Microsoft 365: eng\.syn@corpgroup\.test/.test(document.getElementById('acct').textContent)), 'sign-in round trip: connected to the own account');
    ok(!/code=/.test(p.url()), 'the code is removed from the address bar');
    ok(await wait(p, () => /Core switch change/.test(document.body.textContent)), 'overview: mail that needs you (from the manager)');
    await tab(p, 'mail');
    ok(await wait(p, () => document.querySelectorAll('[data-mail]').length === 2), 'inbox listed');
    ok(/from your manager/.test(await txt(p)), 'the manager\'s mail is tagged');
    await p.click('[data-mail="AAMkMSG0000000001"]');
    ok(await wait(p, () => /Please review the change window/.test((document.getElementById('mdet') || {}).textContent || '')), 'message opened as text');
    await p.fill('#rtext', 'Reviewed - fine for Thursday (synthetic)'); await p.click('[data-reply="0"]');
    ok(await wait(p, () => /Reply sent/.test(document.body.textContent)), 'reply sent from the page');
    ok(sent.some((s) => /\/reply$/.test(s.url) && /Thursday/.test(s.body.comment)), 'Graph reply carried the text');
    await tab(p, 'meetings');
    ok(await wait(p, () => /Change Advisory Board/.test(document.body.textContent)), 'meetings listed');
    const joins = await p.$$eval('a[href]', (L) => L.map((a) => a.getAttribute('href')).filter((h) => /teams/.test(h)));
    ok(joins.length === 1 && /^https:\/\/teams\.microsoft\.com\//.test(joins[0]), 'Join only for the real Teams address');
    await tab(p, 'teams');
    ok(await wait(p, () => document.querySelector('[data-chat]')), 'Teams chats listed');
    await p.click('[data-chat]');
    ok(await wait(p, () => /stand-up at 9/.test((document.getElementById('cdet') || {}).textContent || '')), 'chat messages shown');
    await p.fill('#ctext', 'joining (synthetic)'); await p.click('[data-csend]');
    await wait(p, () => /Sent/.test(document.body.textContent));
    ok(sent.some((s) => s.body && s.body.body && s.body.body.content === 'joining (synthetic)'), 'Teams message sent');

    // the manager assigns, the engineer submits, the manager approves
    WHO = MGR; await p.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(p, () => !document.getElementById('main').hidden), 'manager: page loads');
    await tab(p, 'tasks');
    ok(await wait(p, () => document.getElementById('nt-title')), 'assign form offered');
    ok(/Eng Syn/.test(await p.textContent('#nt-who')), 'the engineer is assignable');
    await p.fill('#nt-title', 'Review VPN rules (synthetic)'); await p.selectOption('#nt-who', 'eng-syn'); await p.selectOption('#nt-pri', 'high'); await p.click('#nt-go');
    ok(await wait(p, () => /Review VPN rules/.test(document.body.textContent)), 'task assigned and listed under Assigned by me');
    WHO = ENG; await p.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(p, () => /Review VPN rules/.test(document.body.textContent)), 'engineer sees the task on the overview');
    await p.click('[data-task]');
    ok(await wait(p, () => document.querySelector('[data-ta="submit"]')), 'task opened with Submit');
    await p.click('[data-ta="submit"]');
    ok(await wait(p, () => /Waiting for Mgr Syn/.test(document.body.textContent)), 'submitted: waiting for the manager');
    ok(!(await p.$('[data-ta="approve"]')), 'the assignee gets no Approve button');
    WHO = MGR; await p.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(p, () => !!document.querySelector('#tabs [data-tab="itm"][aria-selected="true"]')), 'the Infrastructure Manager lands on IT Operations (engine/role-brief.js)');
    await tab(p, 'overview');
    ok(await wait(p, () => /Waiting for my review/i.test(document.body.innerText)), 'manager: waiting for my review');
    await p.click('[data-task]');
    ok(await wait(p, () => document.querySelector('[data-ta="approve"]')), 'Approve offered to the reviewer');
    await p.click('[data-ta="approve"]');
    ok(await wait(p, () => /Done/.test((document.getElementById('tdet') || {}).textContent || '')), 'approved: done');

    WHO = NOBODY; await p.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(p, () => /no profile in Team Workspace/i.test(document.getElementById('sub').textContent)), 'a person without a profile is told so');
    await tab(p, 'mail');
    ok(/administrator adds you/.test(await txt(p)), 'mail tab says what to do');
    ok(!(await p.$('#tabs [data-tab="settings"]')), 'no settings for a viewer');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile mail and chat text never ran');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "my-workspace.html"[\s\S]{0,900}"start": true/.test(nav), 'menu entry under Start here');
    ok(/my-workspace\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'installed by install-dashboards.sh');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
