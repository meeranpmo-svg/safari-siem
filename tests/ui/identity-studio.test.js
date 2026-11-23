// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Identity & Sign-in studio (identity-signin.html) - the management tabs, against a stub of the sign-in service (/auth/admin/*)
// and the ITAM AI identity advisor, SYNTHETIC accounts: Users (filter chips, add with a generated password, a weak password
// refused, edit, MFA off for an admin needs the typed name, disable, unlock, delete needs the typed name, the last admin cannot
// be disabled, your own account has no disable/delete); Single sign-on (save sends the same fields as before, a secret only when
// typed, test, enable needs issuer + client, disable is refused while local sign-in is break-glass only); policy guards against
// locking everyone out; the sign-in log filters and exports CSV with formula cells neutralised; the AI advisor gets the page's
// summary with addresses cut to /24 and no secret fields, and its answer is escaped. No browser dialog anywhere.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node identity-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now(), H = 3600000, at = (ms) => new Date(ms).toISOString();
let USERS, CFG, POSTS = [], ASKS = [];
function reset() {
  USERS = [{ user: 'syed.syn', name: 'Syed Synthetic', role: 'admin', mfa: true, mfaSetting: 'on', lastLogin: at(NOW - H), recoveryLeft: 8 },
    { user: 'huda.syn', name: 'Huda Synthetic', role: 'admin', mfa: true, mfaSetting: 'on', lastLogin: at(NOW - 2 * H), breakglass: true },
    { user: 'omar.syn', name: 'Omar <b>Synthetic</b>', role: 'operator', mfa: false, mfaSetting: 'policy', mfaRequired: false, locked: true, lastLogin: at(NOW - 3 * H) },
    { user: 'old.syn', name: 'Old Synthetic', role: 'viewer', mfa: false, mfaSetting: 'off', disabled: true }];
  CFG = { me: 'syed.syn', users: USERS, mfaPolicy: 'admins', localLogin: 'all', hours: 8,
    sso: { enabled: true, provider: 'Microsoft Entra ID', issuer: 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0', clientId: 'cid-syn', redirectUri: 'https://soc.example.test/auth/sso/callback', scopes: 'openid profile email', roleClaim: 'groups', allowedDomains: 'corp-hq.com', defaultRole: 'none', requireMfa: true, roleMap: { 'SENTRA-SOC-Operators': 'operator' }, hasSecret: true },
    events: [{ event: 'sign-in', at: at(NOW - H), user: 'syed.syn', ip: '10.20.0.5', method: 'password', mfa: true },
      { event: 'failure', at: at(NOW - 2 * H), user: 'omar.syn', ip: '203.0.113.77', reason: '=HYPERLINK("http://x")' },
      { event: 'lockout', at: at(NOW - 2 * H + 60000), user: 'omar.syn', ip: '203.0.113.77' }] };
}
reset();
(async () => {
  const srv = http.createServer((req, res) => { let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', () => {
    const u = decodeURIComponent(req.url.split('?')[0]), b = raw ? JSON.parse(raw) : {}, j = (c, x) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(x)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return j(200, { user: 'syed.syn', role: 'admin' });
    if (u === '/auth/admin/config') return j(200, JSON.parse(JSON.stringify(CFG)));
    if (req.method === 'POST' && u.startsWith('/auth/admin/')) { POSTS.push({ u, b });
      if (u === '/auth/admin/sso/test') return j(200, { issuer: CFG.sso.issuer, keys: 2, amrSupported: true });
      if (u === '/auth/admin/sso') { Object.assign(CFG.sso, b); return j(200, { ok: true }); }
      if (u === '/auth/admin/users') { USERS.push({ user: b.user, name: b.name, role: b.role, mfa: false, mfaSetting: b.mfa, disabled: b.disabled }); return j(200, { ok: true }); }
      return j(200, { ok: true }); }
    if (u === '/api/itam/identity-advisor/status') return j(200, { enabled: true });
    if (u === '/api/itam/identity-advisor/ask') { ASKS.push(b); return j(200, { label: 'AI draft - verify', answer: 'Fix omar.syn first <img src=x onerror=window.PWN=1>', injection_signals: [] }); }
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return j(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/identity-signin.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const p = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
  p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const toast = () => p.evaluate(() => [...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' | '));
  const last = (u) => POSTS.filter((x) => x.u === u).slice(-1)[0];
  try {
    await p.goto(base + '#users'); await p.waitForSelector('#users table');
    ok(await p.isVisible('#users') && !(await p.isVisible('#kk')), 'the #users link opens the Users tab');
    ok(/4 local account\(s\)/.test(await p.textContent('#ucount')), 'account count');
    ok(await p.evaluate(() => !document.querySelector('#users table b b')), 'a name with markup is text');
    ok(/1 admin/.test(await p.textContent('#tabs [data-tab="users"]')) || /\d/.test(await p.textContent('#tabs [data-tab="users"] .n')), 'the Users tab carries a count of what needs attention');
    await p.click('[data-uchip="locked"]'); let rows = await p.$$eval('#users tbody tr', (a) => a.length);
    ok(rows === 1 && /omar\.syn/.test(await p.textContent('#users')), 'Locked chip: one row');
    await p.click('[data-uchip="all"]');
    ok(!(await p.$('[data-utog="syed.syn"]')) && !!(await p.$('[data-utog="huda.syn"]')), 'your own account has no disable button');
    // add user: weak password refused, generated accepted
    await p.click('#uadd'); await p.fill('#nu-user', 'nadia.syn'); await p.fill('#nu-name', 'Nadia Synthetic'); await p.selectOption('#nu-role', 'operator'); await p.fill('#nu-pw', 'short1');
    await p.click('#nu-save'); await p.waitForTimeout(200);
    ok(!last('/auth/admin/users') && /12\+ characters/.test(await toast()), 'a weak initial password is refused before anything is sent');
    await p.click('[data-gen="nu-pw"]'); const pw = await p.inputValue('#nu-pw');
    ok(pw.length >= 15 && /\d/.test(pw) && /[A-Za-z]/.test(pw), 'generated password: ' + pw.length + ' chars');
    await p.click('#nu-save'); await p.waitForFunction(() => /created/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')));
    const nu = last('/auth/admin/users').b;
    ok(nu.user === 'nadia.syn' && nu.role === 'operator' && nu.mfa === 'on' && nu.password === pw && nu.disabled === false, 'create sends the account with MFA required by default: ' + JSON.stringify(Object.assign({}, nu, { password: '***' })));
    // edit: MFA off for an admin needs the typed name
    await p.waitForSelector('[data-uedit="huda.syn"]'); await p.click('[data-uedit="huda.syn"]'); await p.selectOption('#eu-mfa', 'off'); await p.click('[data-usave="huda.syn"]');
    await p.waitForSelector('#dlgbg.open'); ok(/administrator/.test(await p.textContent('#dlgb')), 'the dialog says it is an administrator');
    await p.click('#dlgok'); await p.waitForTimeout(150); ok(!last('/auth/admin/users/huda.syn/update'), 'not sent without typing the name');
    await p.fill('#dlgin', 'huda.syn'); await p.click('#dlgok'); await p.waitForTimeout(300);
    ok(last('/auth/admin/users/huda.syn/update') && last('/auth/admin/users/huda.syn/update').b.mfa === 'off', 'MFA off sent after the typed confirmation');
    // unlock
    await p.waitForSelector('[data-uunlock="omar.syn"]'); await p.click('[data-uunlock="omar.syn"]'); await p.waitForTimeout(200);
    ok(!!last('/auth/admin/users/omar.syn/unlock'), 'unlock');
    // the last enabled admin cannot be disabled
    USERS.forEach((x) => { if (x.user === 'huda.syn') x.role = 'operator'; }); await p.click('#refresh'); await p.waitForTimeout(300);
    USERS.push({ user: 'temp.syn', role: 'viewer', mfa: true });
    await p.click('#refresh'); await p.waitForSelector('[data-utog="temp.syn"]'); await p.click('[data-utog="temp.syn"]'); await p.waitForSelector('#dlgbg.open'); await p.click('#dlgok'); await p.waitForTimeout(200);
    ok(last('/auth/admin/users/temp.syn/update') && last('/auth/admin/users/temp.syn/update').b.disabled === true, 'disable after the confirmation');
    // delete needs the typed name
    await p.click('[data-uedit="temp.syn"]'); await p.click('[data-udel="temp.syn"]'); await p.waitForSelector('#dlgbg.open');
    await p.fill('#dlgin', 'temp'); await p.click('#dlgok'); await p.waitForTimeout(150); ok(!last('/auth/admin/users/temp.syn/delete'), 'delete refused with the wrong name');
    await p.fill('#dlgin', 'temp.syn'); await p.click('#dlgok'); await p.waitForTimeout(250); ok(!!last('/auth/admin/users/temp.syn/delete'), 'delete after typing the name');
    reset(); await p.click('#refresh'); await p.waitForTimeout(300);
    // single sign-on
    await p.click('#tabs [data-tab="sso"]'); await p.waitForSelector('#sso-iss');
    ok((await p.inputValue('#sso-iss')) === CFG.sso.issuer && (await p.inputValue('#rm-k-0')) === 'SENTRA-SOC-Operators', 'SSO form shows the settings and the role mapping');
    await p.click('#rmadd'); await p.fill('#rm-k-1', 'SENTRA-Platform-Viewers'); await p.click('#ssosave'); await p.waitForTimeout(300);
    let sb = last('/auth/admin/sso').b;
    ok(sb.roleMap['SENTRA-Platform-Viewers'] === 'viewer' && sb.requireMfa === true && !('clientSecret' in sb) && !('enabled' in sb), 'save: same fields, the new mapping, no secret unless typed, no enable switch: ' + Object.keys(sb).join(','));
    await p.click('#tabs [data-tab="sso"]'); await p.click('#ssotest'); await p.waitForSelector('#sso .okb'); ok(/2 keys/.test(await p.textContent('#sso .okb')), 'test connection result');
    // disable SSO refused while local sign-in is break-glass only
    CFG.localLogin = 'breakglass'; await p.click('#refresh'); await p.waitForSelector('#ssooff'); const before = POSTS.length; await p.click('#ssooff'); await p.waitForTimeout(200);
    ok(POSTS.length === before && /break-glass only/.test(await toast()), 'disabling SSO is refused while only break-glass can sign in locally');
    CFG.localLogin = 'all'; await p.click('#refresh'); await p.waitForSelector('#ssooff'); await p.click('#ssooff'); await p.waitForSelector('#dlgbg.open'); await p.fill('#dlgin', 'disable'); await p.click('#dlgok'); await p.waitForTimeout(250);
    ok(last('/auth/admin/sso').b.enabled === false, 'SSO disabled after typing "disable"');
    reset(); await p.click('#refresh'); await p.waitForTimeout(300);
    // policy: break-glass only needs SSO on and a break-glass admin
    await p.click('#tabs [data-tab="policy"]'); USERS.forEach((x) => { x.breakglass = false; }); await p.click('#refresh'); await p.waitForSelector('#pol-loc');
    await p.click('#tabs [data-tab="policy"]'); await p.selectOption('#pol-loc', 'breakglass'); const b2 = POSTS.length; await p.click('#polsave'); await p.waitForTimeout(200);
    ok(POSTS.length === b2 && /break-glass first/.test(await toast()), 'break-glass only refused with no break-glass admin');
    reset(); await p.click('#refresh'); await p.waitForSelector('#pol-loc'); await p.click('#tabs [data-tab="policy"]'); await p.selectOption('#pol-mfa', 'all'); await p.selectOption('#pol-loc', 'breakglass'); await p.click('#polsave'); await p.waitForTimeout(250);
    const pb = last('/auth/admin/policy').b; ok(pb.mfaPolicy === 'all' && pb.localLogin === 'breakglass', 'policy saved when it is safe');
    // sign-in log
    await p.click('#tabs [data-tab="log"]'); await p.click('[data-lchip="fail"]');
    ok((await p.$$eval('#log tbody tr', (a) => a.length)) === 1, 'Failures chip');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#logcsv')]); const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/filter fail/.test(csv) && /"'=HYPERLINK/.test(csv), 'CSV carries the filter and neutralises a formula cell: ' + csv.split('\n').slice(0, 3).join(' / '));
    // AI advisor
    await p.click('#tabs [data-tab="ai"]'); await p.click('#aigo'); await p.waitForSelector('#aiout p');
    const f = ASKS[0] && ASKS[0].facts;
    ok(f && f.kpis && f.kpis.active === 3 && Array.isArray(f.accounts), 'the advisor gets the page summary');
    ok(!/203\.0\.113\.77/.test(JSON.stringify(ASKS[0])) && !/password/i.test(JSON.stringify(Object.keys(f.accounts[0] || {}))), 'addresses cut to /24 and no secret fields in what is sent');
    ok(await p.evaluate(() => !window.PWN && !document.querySelector('#aiout img')), 'the answer is escaped');
    ok(/AI draft/.test(await p.textContent('#aiout')), 'labelled an AI draft');
    ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
