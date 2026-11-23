// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for identity-signin.html -> Users: "Who may sign in with their AD account". Against a stateful stub of the
// sign-in service (/auth/admin/config, /auth/admin/policy, /auth/admin/users), SYNTHETIC accounts: the administrator limits AD
// sign-in to people added here (the confirmation names how many lose access), adds an AD account with a role (no password
// field), allows an AD account that signed in before, removes access (type the name to confirm); AD accounts never offer a
// password; a hostile account name stays text; a refusal from the service is shown; switching back to the groups.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node identity-ad-access.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const at = (ms) => new Date(ms).toISOString(), NOW = Date.now();
const S = {
  ldap: { enabled: true, active: true, access: 'groups', netbios: ['CORP-HQ'], upnSuffix: ['corp-hq.com'], groupRoles: {} },
  users: [
    { user: 'localadmin', name: 'Local Admin Synthetic', role: 'admin', source: 'local', mfa: true, breakglass: true, lastLogin: at(NOW - 3600e3) },
    { user: ('carol.syn@' + 'corp-hq.com'), name: 'Carol Synthetic', role: 'viewer', source: 'ad', listed: false, mfa: true, lastLogin: at(NOW - 7200e3) },
    { user: ('<img src=x onerror=window.__x=1>@' + 'corp-hq.com'), name: 'Hostile', role: 'viewer', source: 'ad', listed: false },
  ],
};
const calls = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], j = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return j(200, { user: 'localadmin', role: 'admin' });
    if (u === '/auth/admin/config') return j(200, { users: S.users, events: [], sso: { enabled: false }, mfaPolicy: 'all', mfaRequired: true, localLogin: 'all', hours: 8, ldap: S.ldap, me: 'localadmin' });
    if (req.method === 'POST' && u.startsWith('/auth/admin/')) {
      let raw = ''; req.on('data', (c) => { raw += c; });
      req.on('end', () => {
        const b = JSON.parse(raw || '{}'); calls.push({ u, b });
        if (u === '/auth/admin/policy') { S.ldap.access = b.adAccess; return j(200, { ok: true, adAccess: b.adAccess }); }
        if (u === '/auth/admin/users' && b.ad) {
          if (/^OTHER\\/i.test(b.user)) return j(400, { error: ('user: an AD name like CORP-HQ\\jdoe, jdoe@' + 'corp-hq.com' + ' or jdoe') });
          const key = /@/.test(b.user) ? b.user.toLowerCase() : b.user.replace(/^.*\\/, '').toLowerCase() + ('@' + 'corp-hq.com');
          let x = S.users.find((y) => y.user === key);
          if (!x) { x = { user: key, source: 'ad', name: b.name || key }; S.users.push(x); }
          x.listed = true; x.role = b.role; return j(200, { ok: true, user: key });
        }
        const m = /^\/auth\/admin\/users\/([^/]+)\/update$/.exec(u);
        if (m) { const x = S.users.find((y) => y.user === decodeURIComponent(m[1])); if (b.listed === false) x.listed = false; if (b.role) x.role = b.role; return j(200, { ok: true }); }
        return j(404, { error: 'not in this test' });
      });
      return;
    }
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return j(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/identity-signin.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 8000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base); await p.waitForSelector('#kk .t'); await p.click('#tabs [data-tab="users"]');
    ok(await wait(p, () => /Who may sign in with their AD account/.test(document.getElementById('adacc').textContent)), 'the AD access choice is on the Users tab');
    ok(await p.$eval('[data-adacc="groups"]', (b) => b.getAttribute('aria-pressed') === 'true') && await p.$eval('#uaddad', (b) => b.hidden), 'today: anyone in the SOC groups; no "Add AD user" yet');
    ok(/AD/.test(await p.textContent('#users')) && !(await p.evaluate(() => window.__x)), 'AD accounts are marked; a hostile account name stays text');
    // limit to people added here: the confirmation says who loses access
    await p.click('[data-adacc="listed"]'); await p.waitForSelector('#dlgbg.open');
    ok(/2 AD account\(s\)/.test(await p.textContent('#dlgb')), 'the confirmation names how many accounts lose access: ' + (await p.textContent('#dlgb')));
    await p.click('#dlgok');
    ok(await wait(p, () => document.querySelector('[data-adacc="listed"]').getAttribute('aria-pressed') === 'true'), 'switched to: only people added here');
    ok(calls.some((c) => c.u === '/auth/admin/policy' && c.b.adAccess === 'listed'), 'saved through the sign-in service');
    ok(/not allowed/.test(await p.textContent('#users')) && !(await p.$eval('#uaddad', (b) => b.hidden)), 'accounts not added are flagged; "Add AD user" appears');
    // add an AD account: name + role, no password field
    await p.click('#uaddad'); await p.waitForSelector('#na-user');
    ok(!(await p.$('#uform input[type=password], #uform #nu-pw')), 'no password field for an AD account');
    await p.fill('#na-user', 'OTHER\\gina.syn'); await p.selectOption('#na-role', 'operator'); await p.click('#na-save');
    ok(await wait(p, () => /AD name like/.test([...document.querySelectorAll('.toast,#toast')].map((t) => t.textContent).join(' '))), 'the service\'s refusal is shown');
    await p.fill('#na-user', 'CORP-HQ\\gina.syn'); await p.fill('#na-name', 'Gina Synthetic'); await p.click('#na-save');
    ok(await wait(p, () => new RegExp('gina\\.syn@' + 'corp-hq\\.com').test(document.getElementById('users').textContent)), 'the added account is listed');
    const add = calls.find((c) => c.u === '/auth/admin/users' && c.b.user === 'CORP-HQ\\gina.syn');
    ok(add && add.b.ad === true && add.b.role === 'operator' && add.b.name === 'Gina Synthetic' && !('password' in add.b), 'sent: ad, the name, the role - no password');
    // allow an account that signed in before
    await p.click(('[data-adallow="carol.syn@' + 'corp-hq.com' + '"]'));
    ok(await wait(p, () => !document.querySelector(('[data-adallow="carol.syn@' + 'corp-hq.com' + '"]')) && !!document.querySelector(('[data-adrm="carol.syn@' + 'corp-hq.com' + '"]'))), '✓ Allow lets an existing AD account in');
    // the edit drawer of an AD account offers no password
    await p.click(('[data-uedit="gina.syn@' + 'corp-hq.com' + '"]')); await p.waitForSelector('#eu-name');
    ok(!(await p.$('#eu-pw')) && /kept in Active Directory/.test(await p.textContent('#users')) && !(await p.$eval('#eu-role', (s) => s.disabled)), 'AD account: no password field; the role can be set here');
    await p.click('#eu-x');
    // remove access: type the name to confirm
    await p.click(('[data-adrm="gina.syn@' + 'corp-hq.com' + '"]')); await p.waitForSelector('#dlgbg.open');
    await p.click('#dlgok'); ok(!calls.some((c) => /gina/.test(c.u) && c.b.listed === false), 'not removed without typing the name');
    await p.fill('#dlgin', ('gina.syn@' + 'corp-hq.com')); await p.click('#dlgok');
    ok(await wait(p, () => !!document.querySelector(('[data-adallow="gina.syn@' + 'corp-hq.com' + '"]'))), 'access removed: ✓ Allow is offered again');
    ok(calls.some((c) => c.u === ('/auth/admin/users/gina.syn%40' + 'corp-hq.com' + '/update') && c.b.listed === false), 'sent listed:false');
    // back to the groups
    await p.click('[data-adacc="groups"]'); await p.waitForSelector('#dlgbg.open'); await p.click('#dlgok');
    ok(await wait(p, () => document.querySelector('[data-adacc="groups"]').getAttribute('aria-pressed') === 'true' && document.getElementById('uaddad').hidden), 'back to: anyone in the SOC groups');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(base); await ph.waitForSelector('#kk .t'); await ph.click('#tabs [data-tab="users"]');
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
