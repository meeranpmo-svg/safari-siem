// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for user-management.html - "Create account" for a person in AD when the sign-in service has AD (LDAPS) sign-in:
// against stubs in the shape of the sign-in service (/auth/admin/config with an ldap block, /auth/admin/users {ad:true}), job roles
// and the welcome kit, SYNTHETIC people. Checks: the dialog defaults to "Their AD account", hides the password and MFA fields, says
// they sign in with their Windows user name and password; the request carries ad:true and no password; the job role is given under
// the account name the service returns; the welcome kit and its preview carry signin:'ad'; the result names no password; the local
// account stays available (password back, request without ad); with AD sign-in off the AD choice is disabled and local is the default;
// in "anyone in the SOC groups" mode the dialog says the role comes from the AD group. No browser dialog anywhere.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node user-management-ad.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString();
(async () => {
  let LDAP = { enabled: true, access: 'listed', netbios: ['SYN-HQ'], upnSuffix: ['synthetic.test'] };
  const users = [{ user: 'syed', name: 'Syed M', role: 'admin', mfa: true, last_login: ago(0) }];
  const created = [], assigned = [], welcomes = [], previews = [];
  const AD = { connection: { ok: true, servers: ['ldaps://dc01.synthetic.test:636'], base_dn: 'DC=synthetic,DC=test' }, settings: { group: '' }, note: 'Read only.', last: { at: new Date().toISOString(), by: 'syed', count: 3, truncated: false, group: '' },
    users: [{ sam: 'syed', upn: 'syed@synthetic.test', display_name: 'Syed M', department: 'IT', enabled: true, last_logon: ago(1), groups: 1 },
      { sam: 'nadia.syn', upn: 'nadia.syn@synthetic.test', display_name: 'Nadia Synthetic', department: 'Claims', mail: 'nadia.syn@synthetic.test', enabled: true, last_logon: ago(1), groups: 1 },
      { sam: 'omar.syn', upn: 'omar.syn@synthetic.test', display_name: 'Omar Synthetic', department: 'Finance', mail: 'omar.syn@synthetic.test', enabled: true, last_logon: ago(1), groups: 1 }] };
  const ROLES = { roles: [{ id: 'risk-head', name: 'Risk Head', base: 'operator', functions: {} }], assignments: [] };
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', () => {
      if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: 'admin' });
      if (u === '/auth/admin/config') return json(200, Object.assign({ users }, LDAP ? { ldap: LDAP } : {}));
      if (u === '/api/itam/ad-directory') return json(200, AD);
      if (u === '/api/itam/roles') return json(200, ROLES);
      if (u === '/api/itam/identity-advisor/status') return json(200, { enabled: false, reason: 'synthetic' });
      if (u === '/auth/admin/users' && req.method === 'POST') { const x = JSON.parse(raw); created.push(x); const key = x.ad ? x.user + '@synthetic.test' : x.user;
        users.push({ user: key, name: x.name, role: x.role, source: x.ad ? 'ad' : 'local', listed: x.ad ? true : undefined }); return json(200, { ok: true, user: key }); }
      if (u === '/api/itam/roles/assign' && req.method === 'POST') { assigned.push(JSON.parse(raw)); return json(200, { ok: true }); }
      if (u === '/api/itam/welcome/send' && req.method === 'POST') { welcomes.push(JSON.parse(raw)); return json(200, { ok: true }); }
      if (u === '/api/itam/welcome/preview' && req.method === 'POST') { const x = JSON.parse(raw); previews.push(x); return json(200, { subject: 'Welcome', lang: x.lang, html: '<p>' + (x.signin === 'ad' ? 'Sign in with your Windows account' : 'initial password') + '</p>' }); }
      if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
      fs.readFile(path.join(DASH, u), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/user-management.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const page = await browser.newPage({ viewport: { width: 1500, height: 950 } });
  page.on('pageerror', (e) => errs.push(e.message)); page.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, arg) => page.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 10000 }).then(() => true, () => false);
  try {
    await page.goto(base); await page.waitForSelector('[data-create="nadia.syn"]');
    await page.click('[data-create="nadia.syn"]'); await page.waitForSelector('#ca-how');
    ok(await page.$eval('#ca-how', (s) => s.value) === 'ad', 'AD sign-in on: the dialog defaults to their AD account');
    ok(await page.$eval('#ca-pwl', (l) => l.hidden) && await page.$eval('#ca-mfal', (l) => l.hidden), 'no password and no MFA field for an AD account');
    ok(/own Windows \(AD\) user name and password/.test(await page.textContent('#ca-intro')), 'the dialog says how they sign in');
    // preview carries signin
    await page.click('#ca-preview'); ok(await wait(() => true) && previews.length && previews[previews.length - 1].signin === 'ad', 'the welcome preview is the AD version');
    await page.keyboard.press('Escape');
    await page.selectOption('#ca-role', 'operator'); if (await page.$('#ca-job')) await page.selectOption('#ca-job', 'risk-head');
    await page.click('#dlgok');
    ok(await wait(() => /AD account added/.test(document.getElementById('dlgt').textContent)), 'added');
    const c = created[0] || {};
    ok(c.ad === true && c.user === 'nadia.syn' && c.role === 'operator' && !('password' in c) && !('mfa' in c), 'the request: ad:true, the AD name, the role - no password: ' + JSON.stringify(c));
    ok(assigned.some((a) => a.user === 'nadia.syn@synthetic.test' && a.role_id === 'risk-head'), 'the job role is given under the account name the service returned');
    ok(welcomes.some((w) => w.signin === 'ad' && w.user === 'nadia.syn' && w.email === 'nadia.syn@synthetic.test'), 'the welcome kit is the AD version');
    const res = await page.textContent('#dlgbg');
    ok(/own Windows \(AD\) user name and password/.test(res) && /No platform password was created/.test(res), 'the result names no password');
    await page.click('#dlgok').catch(() => { /* the result dialog may close by itself on reload */ });
    // the local account is still possible
    await page.waitForSelector('[data-create="omar.syn"]'); await page.click('[data-create="omar.syn"]'); await page.waitForSelector('#ca-how');
    await page.selectOption('#ca-how', 'local'); ok(!(await page.$eval('#ca-pwl', (l) => l.hidden)), 'choosing a local account brings the password back');
    await page.click('#dlgok'); ok(await wait(() => /Account created/.test(document.getElementById('dlgt').textContent)), 'local account created');
    const l = created[1] || {}; ok(!l.ad && typeof l.password === 'string' && l.password.length >= 12, 'the local request carries a password and no ad flag');
    // AD sign-in off: the AD choice is disabled, local is the default; groups mode explained
    await page.click('#dlgok').catch(() => { /* closed already */ });
    LDAP = null; users.length = 1; await page.reload(); await page.waitForSelector('[data-create="nadia.syn"]');
    await page.click('[data-create="nadia.syn"]'); await page.waitForSelector('#ca-how');
    ok(await page.$eval('#ca-how', (s) => s.value) === 'local' && await page.$eval('#ca-how option[value="ad"]', (o) => o.disabled), 'no AD sign-in on the server: local is the default, AD disabled');
    await page.keyboard.press('Escape');
    LDAP = { enabled: true, access: 'groups', netbios: ['SYN-HQ'], upnSuffix: ['synthetic.test'] }; await page.reload(); await page.waitForSelector('[data-create="nadia.syn"]');
    await page.click('[data-create="nadia.syn"]'); await page.waitForSelector('#ca-how');
    ok(/role comes from their AD group/.test(await page.textContent('#ca-adnote')), 'groups mode: the role comes from the AD group');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
