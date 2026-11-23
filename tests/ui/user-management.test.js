// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for user-management.html (the people register) against stubs in the shape of the sign-in service
// (/auth/admin/config, /auth/admin/users/:u/update), job roles (/api/itam/roles, with a job role from an AD group),
// Active Directory (/api/itam/ad-directory) and the AI advisor, SYNTHETIC people. Checks: one row per person merged from local
// account + SSO job role + AD, matched on the user name only; the ML review score with named reasons (leaver still able to sign
// in, admin without MFA, no AD account, peer-group outlier, role/base mismatch); the tiles filter; disable / bulk disable through
// an in-page dialog (typed count), never yourself; "Create account" for AD-only people; peer groups; the AI access review gets
// the review list and its answer is escaped; a field the service does not send shows "—"; an operator sees AD and SSO but no
// local accounts and no buttons; a viewer sees nothing personal. No browser dialog anywhere.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node user-management.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString();

(async () => {
  let WHO = { user: 'syed', role: 'admin' };
  const users = [
    { user: 'syed', name: 'Syed M', role: 'admin', mfa: true, last_login: ago(0) },
    { user: 'rasheed', name: 'Rasheed (DBA)', role: 'viewer', mfa: false, last_login: ago(1) },
    { user: 'siva', name: 'Siva', role: 'operator', disabled: true },
    { user: 'karim.syn', name: 'Karim Synthetic', role: 'admin', mfa: true, last_login: ago(2) },
    { user: 'ext.vendor', name: 'Vendor <b>Account</b>', role: 'viewer', mfa: true, last_login: ago(3) },
  ];
  const posts = [], asks = [];
  let adReads = 0, adSettings = null; const created = [], assigned = [], resets = [], welcomes = [], previews = [];
  const P = (sam, dn, dept, extra) => Object.assign({ sam, upn: sam + ('@' + 'corp-hq.com'), display_name: dn, department: dept, title: '', enabled: true, last_logon: ago(1), admin_count: false, groups: 1 }, extra);
  const AD = { connection: { ok: true, servers: ['ldaps://dc01.synthetic.test:636'], base_dn: 'DC=synthetic,DC=test' }, settings: { group: '' }, note: 'Read only.',
    last: { at: new Date().toISOString(), by: 'syed', count: 7, truncated: false, group: '' },
    users: [P('syed', 'Syed M', 'IT', { admin_count: true }), P('rasheed', 'Rasheed Synthetic', 'IT', { enabled: false }),
      P('karim.syn', 'Karim Synthetic', 'Claims', { title: 'Senior Claims Officer', groups: 14 }), P('c1.syn', 'Claims One', 'Claims', { title: 'Claims Officer' }), P('c2.syn', 'Claims Two', 'Claims', { title: 'Claims Officer' }), P('c3.syn', 'Claims Three', 'Claims', { title: 'Claims Officer', last_logon: ago(200) }),
      P('nadia.syn', 'Nadia <b>Synthetic</b>', 'Claims', { mail: 'nadia.syn@synthetic.test' }), P('Gf0b8450d3e4741d7', '1st Floor Finance Meeting Room', ''), P('$3DB000-53KT12UBBL5S', '$3DB000-53KT12UBBL5S', '')] };
  const ROLES = { roles: [{ id: 'r-dba', name: 'Database Administrator', base: 'operator', functions: {} }, { id: 'claims-viewer', name: 'Claims Viewer', base: 'viewer', functions: {} }],
    assignments: [{ user: 'rasheed', role_id: 'r-dba' },
      { user: ('c1.syn@' + 'corp-hq.com'), role_id: 'claims-viewer', source: 'sso-group', via: 'SENTRA-Claims' }, { user: 'c2.syn', role_id: 'claims-viewer', source: 'sso-group', via: 'SENTRA-Claims' }, { user: 'c3.syn', role_id: 'claims-viewer', source: 'sso-group', via: 'SENTRA-Claims' }] };
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', () => {
      if (u === '/dashboards/whoami.json') return json(200, WHO);
      if (u === '/auth/admin/config') return WHO.role === 'admin' ? json(200, { users }) : json(403, { error: 'admin only' });
      if (u === '/api/itam/ad-directory/settings') { adSettings = JSON.parse(raw || '{}'); AD.settings = adSettings; return json(200, AD); }
      if (u === '/api/itam/ad-directory' || u === '/api/itam/ad-directory/refresh') { if (u.endsWith('/refresh')) adReads++; return WHO.role === 'viewer' ? json(403, { error: 'operator' }) : json(200, AD); }
      if (u === '/api/itam/roles') return WHO.role === 'viewer' ? json(403, { error: 'operator' }) : json(200, ROLES);
      if (u === '/api/itam/identity-advisor/status') return WHO.role === 'admin' ? json(200, { enabled: true }) : json(403, { error: 'admin' });
      if (u === '/api/itam/identity-advisor/ask') { asks.push(JSON.parse(raw)); return json(200, { label: 'AI draft - verify', answer: 'Disable rasheed <img src=x onerror=window.PWN=1>' }); }
      if (u === '/auth/admin/users' && req.method === 'POST') { const x = JSON.parse(raw); created.push(x); if (users.some((y) => y.user === x.user)) return json(409, { error: 'user exists' }); users.push({ user: x.user, name: x.name, role: x.role, disabled: false, mfa: true }); return json(200, { ok: true }); }
      if (u === '/api/itam/welcome/preview' && req.method === 'POST') { const x = JSON.parse(raw); previews.push(x); return json(200, { subject: 'Welcome synthetic ' + x.lang, lang: x.lang, html: '<html><body><p id="wl">' + (x.lang === 'en' ? 'User name' : 'اسم المستخدم') + ' ' + x.user.replace(/</g, '&lt;') + '</p><script>parent.PWN=1<' + '/script></body></html>' }); }
      if (u === '/api/itam/welcome/send' && req.method === 'POST') { const x = JSON.parse(raw); welcomes.push(x); return x.email === 'fail@synthetic.test' ? json(424, { error: 'the e-mail relay is not configured' }) : json(200, { ok: true, user: x.user }); }
      if (u === '/api/itam/roles/assign' && req.method === 'POST') { assigned.push(JSON.parse(raw)); return json(200, { ok: true }); }
      const rm = /^\/auth\/admin\/users\/([^/]+)\/reset-mfa$/.exec(u); if (rm && req.method === 'POST') { resets.push(decodeURIComponent(rm[1])); return json(200, { ok: true }); }
      const m = /^\/auth\/admin\/users\/([^/]+)\/update$/.exec(u);
      if (m && req.method === 'POST') { const x = JSON.parse(raw); posts.push({ user: decodeURIComponent(m[1]), body: x, ct: req.headers['content-type'] }); const t = users.find((y) => y.user === decodeURIComponent(m[1])); if (t) t.disabled = x.disabled; return json(200, { ok: true }); }
      if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
      fs.readFile(path.join(DASH, u), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1500, height: 950 } }); const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  page.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const row = (k) => page.$eval('#users tr[data-k="' + k + '"]', (r) => r.innerText).catch(() => '');
  const shown = () => page.$$eval('#users tbody tr', (T) => T.map((x) => x.getAttribute('data-k')));

  await page.goto(base + 'user-management.html'); await page.waitForSelector('#users table');
  const all = await shown();
  ok(all.length === 9, 'one row per person: 5 local + 4 more from AD (c1-c3 via SSO, nadia): ' + all.join(','));
  ok(all.includes('ad:c1.syn') && !all.includes(('acct:c1.syn@' + 'corp-hq.com')), 'an SSO job role recorded under the UPN joins the AD person (matched on the user name)');
  ok(/LOCAL/.test(await row('ad:syed')) && /AD/.test(await row('ad:syed')) && /you/.test(await row('ad:syed')) && /on/.test(await row('ad:syed')), 'syed: local + AD, you, MFA on');
  ok(/SSO/.test(await row('ad:c2.syn')) && /Claims Viewer/.test(await row('ad:c2.syn')) && /from SENTRA-Claims/.test(await row('ad:c2.syn')) && /via Entra/.test(await row('ad:c2.syn')), 'c2: SSO job role from the AD group, MFA via Entra');
  ok(/—/.test((await row('acct:siva')).split('\t')[5] || '—') && /disabled/.test(await row('acct:siva')), 'siva: MFA not reported -> "—", disabled');
  ok(!/Disable/.test(await row('ad:syed')), 'no button to disable yourself');
  // ML review score with reasons
  const rr = await row('ad:rasheed');
  ok(/disabled in AD/.test(rr) && /^(?:[\s\S]*?)\b(1[0-9]{2}|[6-9][0-9])\b/.test(rr), 'rasheed: leaver still able to sign in, high score: ' + rr.replace(/\s+/g, ' '));
  ok(/no AD account/.test(await row('acct:ext.vendor')), 'a local account with no AD account is flagged');
  ok(/admin while 3 of 4 in Claims are viewer/.test(await row('ad:karim.syn')), 'peer-group outlier (ML): ' + (await row('ad:karim.syn')).replace(/\s+/g, ' '));
  const title = await page.getAttribute('#users tr[data-k="ad:rasheed"] .sc', 'title');
  ok(/differs from the job role Database Administrator/.test(title) && /no MFA/.test(title), 'the score tooltip names every reason: ' + title);
  ok(all[0] === 'ad:rasheed', 'sorted by review score: ' + all[0]);
  ok(await page.$eval('#users', (e) => !e.querySelector('b b') && /<b>Account<\/b>/.test(e.innerText)), 'a hostile display name stays text');
  // checks + tiles
  const find = await page.$eval('#find', (e) => e.innerText);
  ok(/Disabled in AD but can still sign in: rasheed/.test(find) && /without MFA: rasheed/.test(find) && /unusual for the department: karim\.syn/.test(find) && /no AD account: ext\.vendor/.test(find), 'checks: ' + find.replace(/\s+/g, ' ').slice(0, 400));
  ok(/Base level differs from the job role for: rasheed/.test(find), 'check: base level vs job role');
  await page.click('#kk [data-f="leaver"]'); ok(JSON.stringify(await shown()) === '["ad:rasheed"]', 'Leavers tile -> rasheed');
  await page.selectOption('#filt', 'outlier'); ok(JSON.stringify(await shown()) === '["ad:karim.syn"]', 'Peer outliers filter -> karim');
  await page.selectOption('#filt', 'sso'); ok((await shown()).length === 3, 'Single sign-on filter -> the 3 Claims people');
  await page.click('#kk [data-f="adonly"]'); ok(JSON.stringify(await shown()) === '["ad:nadia.syn"]' && /Create account/.test(await row('ad:nadia.syn')), 'In AD only -> nadia, with Create account');
  await page.click('#fclr'); ok((await shown()).length === 9, 'chip ✕ clears the filter');
  ok(/Claims/.test(await page.textContent('#peers')) && /⚠/.test(await page.textContent('#peers')), 'peer groups show Claims with an outlier');
  // AI access review
  // Insights (ML)
  await page.click('[data-tab="ml"]');
  ok(await page.isVisible('#pane-ml') && /What drives the review score/.test(await page.textContent('#mlbox')), 'insights tab renders');
  const ml = (await page.textContent('#mlbox')).replace(/\s+/g, ' ');
  ok(/Karim Synthetic/.test(ml) && /admin while 3 of 4 with this title are viewer/.test(ml), 'same job title, higher access (titles normalised: Senior Claims Officer = Claims Officer): ' + ml.slice(ml.indexOf('Same job title'), ml.indexOf('Same job title') + 200));
  ok(/14 groups against a usual 1 \(z /.test(ml), 'AD group creep against the department (robust z)');
  ok(/over 180 days/.test(ml) && /can still reach this platform/.test(ml) && /Claims Three/.test(ml), 'dormant directory account that still has platform access');
  ok(/Administrators/.test(ml) && /\d+%/.test(ml) && /least privilege/.test(ml), 'administrator share');
  ok(/no MFA/.test(ml) && /people/.test(ml), 'review-score drivers summed');
  ok(!(await page.$('#mlbox b:not(:only-child) img')) && !/<b>Synthetic<\/b>/.test(await page.innerHTML('#mlbox')), 'names stay text');
  await page.click('#mlbox [data-open]'); ok(await page.waitForFunction(() => document.getElementById('drawer').classList.contains('open')).then(() => true, () => false), 'a name opens the person');
  await page.keyboard.press('Escape'); await page.evaluate(() => { const x = document.getElementById('drx'); if (x && document.getElementById('drawer').classList.contains('open')) x.click(); });
  await page.click('[data-tab="ai"]'); await page.click('#aigo'); await page.waitForSelector('#aiout p');
  const f = asks[0] && asks[0].facts;
  ok(f && f.accounts.some((a) => a.user === 'karim.syn' && a.why.some((w) => /Claims are viewer/.test(w))) && /access review/.test(asks[0].question), 'the AI gets the review list with the reasons');
  ok(await page.evaluate(() => !window.PWN && !document.querySelector('#aiout img')), 'the AI answer is escaped');
  await page.click('[data-tab="people"]');
  // rooms and system accounts have their own switch; only people get "Create account"
  ok(/People9/.test((await page.textContent('#kind')).replace(/\s+/g, '')) && /Service&system1/.test((await page.textContent('#kind')).replace(/\s+/g, '')) && /Rooms&resources1/.test((await page.textContent('#kind')).replace(/\s+/g, '')), 'kind switch counts: ' + (await page.textContent('#kind')));
  await page.click('[data-kind="room"]'); ok(JSON.stringify(await shown()) === '["ad:gf0b8450d3e4741d7"]' && !(await page.$('[data-create]')), 'the meeting room is listed apart, with no Create account');
  await page.click('[data-kind="svc"]'); ok(JSON.stringify(await shown()) === '["ad:$3db000-53kt12ubbl5s"]', 'the $ system account is listed apart');
  await page.click('[data-kind="all"]'); ok((await shown()).length === 11 && (await page.$$('[data-create]')).length === 1, 'All: 11, Create account only for the person');
  await page.click('[data-kind="person"]');
  // the person's panel: details, reasons, actions
  await page.click('#users tr[data-k="ad:karim.syn"] td:nth-child(3)'); await page.waitForSelector('#drawer.open');
  const dr = await page.textContent('#drb');
  ok(/admin while 3 of 4 in Claims are viewer/.test(dr) && /Active Directory/.test(dr) && new RegExp('karim\\.syn@' + 'corp-hq\\.com').test(dr) && await page.$('#pa-role') && await page.$('#pa-mfa') !== undefined, 'the panel: account, AD, reasons and actions');
  await page.selectOption('#pa-role', 'viewer'); await page.click('#pa-saverole'); await page.waitForSelector('#dlgbg.open'); await page.click('#dlgok');
  await page.waitForFunction(() => /changed to viewer/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')));
  ok(posts.length === 1 && posts[0].user === 'karim.syn' && posts[0].body.role === 'viewer' && Object.keys(posts[0].body).length === 1, 'change level: POST update {role} only: ' + JSON.stringify(posts));
  posts.length = 0;
  await page.waitForSelector('#drawer.open #pa-job'); await page.selectOption('#pa-job', 'claims-viewer'); await page.click('#pa-savejob');
  await page.waitForFunction(() => /Job role Claims Viewer given/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')));
  ok(assigned.length === 1 && assigned[0].user === 'karim.syn' && assigned[0].role_id === 'claims-viewer', 'job role set from the panel');
  assigned.length = 0;
  const mfaBtn = await page.$('#pa-mfa');
  if (mfaBtn) { await mfaBtn.click(); await page.waitForSelector('#dlgbg.open'); await page.click('#dlgok'); await page.waitForTimeout(200); ok(resets.length === 0, 'reset MFA needs the typed user name');
    await page.fill('#dlgin', 'karim.syn'); await page.click('#dlgok'); await page.waitForFunction(() => /Two-step verification reset/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')));
    ok(resets.join() === 'karim.syn', 'reset two-step verification after a typed confirmation'); }
  // preview from the panel and from the send dialog
  previews.length = 0; await page.click('#pa-wpreview'); await page.waitForSelector('#wpbg.open');
  ok(await page.waitForFunction(() => /Welcome synthetic both/.test(document.getElementById('wps').textContent)).then(() => true, () => false) && previews[0].user === 'karim.syn' && /karim\.syn/.test(await page.textContent('#wp-for')), 'Preview welcome e-mail from the panel, Arabic and English by default');
  await page.click('#wpx'); ok(await page.$eval('#wpbg', (d) => !d.classList.contains('open')), 'Close closes the preview');
  await page.click('#pa-welcome'); await page.waitForSelector('#wl-preview'); await page.click('#wl-preview'); await page.waitForSelector('#wpbg.open');
  ok(previews.length === 2 && previews[1].user === 'karim.syn', 'Preview from the send dialog'); await page.click('#wpx'); await page.click('#dlgno');
  ok(!welcomes.length, 'previewing sent nothing');
  // the welcome kit again, from the panel
  const toasts = () => page.evaluate(() => [...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' '));
  await page.click('#pa-welcome'); await page.waitForSelector('#wl-mail'); await page.click('#dlgok');
  ok(await page.waitForFunction(() => /give an e-mail address/.test(document.body.innerText)).then(() => true, () => false) && !welcomes.length, 'Send welcome e-mail: an address is needed');
  await page.fill('#wl-mail', 'fail@synthetic.test'); await page.click('#dlgok');
  ok(await page.waitForFunction(() => /Not sent: the e-mail relay is not configured/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' '))).then(() => true, () => false), 'a relay failure is reported, not hidden');
  await page.click('#pa-welcome'); await page.waitForSelector('#wl-mail'); await page.fill('#wl-mail', 'karim.syn@synthetic.test'); await page.click('#dlgok');
  ok(await page.waitForFunction(() => /Welcome e-mail sent to karim\.syn@synthetic\.test/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' '))).then(() => true, () => false)
    && welcomes.length === 2 && welcomes[1].user === 'karim.syn' && !('password' in welcomes[1]), 'Send welcome e-mail from the panel: ' + (await toasts()).slice(-120));
  welcomes.length = 0;
  await page.click('#drx'); ok(await page.$eval('#drawer', (d) => !d.classList.contains('open')), 'the panel closes');
  // disable through the in-page dialog
  await page.click('#users tr[data-k="ad:rasheed"] [data-toggle]'); await page.waitForSelector('#dlgbg.open');
  ok(posts.length === 0, 'nothing sent before the confirmation');
  await page.click('#dlgok'); await page.waitForFunction(() => /disabled/.test((document.querySelector('#users tr[data-k="ad:rasheed"]') || {}).innerText || ''));
  ok(posts.length === 1 && posts[0].user === 'rasheed' && posts[0].body.disabled === true && /json/.test(posts[0].ct), 'POST update {disabled:true} as JSON: ' + JSON.stringify(posts));
  await page.click('#users tr[data-k="acct:siva"] [data-toggle]'); await page.waitForFunction(() => /active/.test((document.querySelector('#users tr[data-k="acct:siva"]') || {}).innerText || ''));
  ok(posts[1] && posts[1].user === 'siva' && posts[1].body.disabled === false, 'enable sends {disabled:false} (no confirmation needed to give access back)');
  // bulk disable: typed count
  await page.check('[data-sel="ext.vendor"]'); await page.check('[data-sel="karim.syn"]');
  ok(/2 selected/.test(await page.textContent('#bulkn')), 'two selected');
  await page.click('#bulkdis'); await page.waitForSelector('#dlgbg.open'); await page.fill('#dlgin', '3'); await page.click('#dlgok'); await page.waitForTimeout(200);
  ok(posts.length === 2, 'wrong count: nothing sent');
  await page.fill('#dlgin', '2'); await page.click('#dlgok'); await page.waitForFunction(() => /2 disabled/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')));
  ok(posts.slice(2).map((p) => p.user).sort().join(',') === 'ext.vendor,karim.syn' && posts.slice(2).every((p) => p.body.disabled === true), 'bulk disable sent for both');
  // search + AD read
  await page.fill('#q', 'claims'); ok((await shown()).length === 5, 'search by department: ' + (await shown()).length);
  await page.fill('#q', '');
  await page.click('[data-tab="dir"]'); await page.click('#adr'); await page.waitForFunction(() => /people read from the directory/.test(document.body.innerText));
  ok(adReads === 1, 'read the directory now');
  await page.selectOption('#adauto', '24'); await page.waitForFunction(() => /re-read every 24 h/.test(document.body.innerText));
  ok(adSettings && adSettings.auto_hours === 24 && adSettings.group === '', 'the automatic re-read is set from the page, the group kept');
  await page.click('[data-tab="people"]');
  // bulk: change the access level of several accounts
  await page.check('[data-sel="ext.vendor"]'); await page.check('[data-sel="siva"]'); await page.selectOption('#bulkrole', 'operator'); await page.waitForSelector('#dlgbg.open'); await page.click('#dlgok');
  await page.waitForFunction(() => /2 changed to operator/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')));
  ok(posts.slice(-2).map((p) => p.user).sort().join(',') === 'ext.vendor,siva' && posts.slice(-2).every((p) => p.body.role === 'operator'), 'bulk: both changed to operator');
  // Create account for a person in AD: in the page, prefilled, with a role and a job role
  const cb = await page.$('[data-create="nadia.syn"]'); ok(!!cb, 'Create account offered for an AD person with no access');
  await cb.click(); await page.waitForSelector('#ca-user');
  ok(await page.$eval('#ca-user', (i) => i.value) === 'nadia.syn' && await page.$eval('#ca-name', (i) => i.value) === 'Nadia <b>Synthetic</b>' && /^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$/.test(await page.$eval('#ca-pw', (i) => i.value)), 'prefilled from AD, a password generated');
  await page.fill('#ca-pw', 'short'); await page.click('#dlgok');
  ok(await page.waitForFunction(() => /12\+ characters/.test(document.body.innerText)).then(() => true, () => false) && await page.$('#ca-user') && await page.$eval('#dlgbg', (d) => d.classList.contains('open')), 'a weak password refused, the form stays open with what was typed');
  ok(await page.$eval('#ca-mail', (i) => i.value) === 'nadia.syn@synthetic.test' && await page.$eval('#ca-welcome', (c) => c.checked), 'the e-mail from AD, the welcome kit ticked');
  await page.fill('#ca-pw', 'Synthetic-Pass-2026'); await page.fill('#ca-mail', 'not-an-address'); await page.click('#dlgok');
  ok(await page.waitForFunction(() => /welcome kit, or untick it/.test(document.body.innerText)).then(() => true, () => false) && created.length === 0, 'a bad e-mail refused before anything is created');
  await page.fill('#ca-mail', 'nadia.syn@synthetic.test'); await page.selectOption('#ca-job', 'r-dba');
  ok(await page.$eval('#ca-lang', (s) => s.value) === 'both', 'the welcome kit in Arabic and English by default'); await page.selectOption('#ca-lang', 'ar');
  // preview from the form: the values typed so far, the language chosen, nothing sent, the form still open underneath
  previews.length = 0; await page.click('#ca-preview'); await page.waitForSelector('#wpbg.open');
  const pvText = () => page.frameLocator('#wpf').locator('#wl').textContent({ timeout: 5000 }).catch(() => '');
  ok(await page.waitForFunction(() => /Welcome synthetic ar/.test(document.getElementById('wps').textContent)).then(() => true, () => false) && /اسم المستخدم nadia\.syn/.test(await pvText())
    && previews[0].user === 'nadia.syn' && previews[0].role === 'operator' && previews[0].job === 'Database Administrator' && previews[0].lang === 'ar' && !('password' in previews[0]) && !welcomes.length, 'Preview the welcome e-mail from the form: its values and language, no password, nothing sent');
  await page.selectOption('#wp-lang', 'en');
  ok(await page.waitForFunction(() => /Welcome synthetic en/.test(document.getElementById('wps').textContent)).then(() => true, () => false) && /User name nadia\.syn/.test(await pvText()), 'the preview switches language');
  ok(await page.$eval('#wpf', (f) => f.getAttribute('sandbox') === '') && !(await page.evaluate(() => window.PWN)), 'the preview is sandboxed: its script does not run');
  await page.keyboard.press('Escape');
  ok(await page.$eval('#wpbg', (d) => !d.classList.contains('open')) && await page.$eval('#dlgbg', (d) => d.classList.contains('open')) && await page.$('#ca-user'), 'Escape closes the preview only - the form stays open');
  ok(await page.$eval('#ca-role', (s) => s.value) === 'operator', 'a job role sets its base role');
  await page.click('#dlgok'); await page.waitForFunction(() => /Account created/.test(document.getElementById('dlgt').textContent));
  ok(created.length === 1 && created[0].user === 'nadia.syn' && created[0].role === 'operator' && created[0].mfa === 'on' && created[0].password === 'Synthetic-Pass-2026' && created[0].disabled === false, 'created through the sign-in service with the role and MFA: ' + JSON.stringify(Object.assign({}, created[0], { password: '***' })));
  ok(assigned.length === 1 && assigned[0].user === 'nadia.syn' && assigned[0].role_id === 'r-dba', 'the job role assigned');
  ok(/Synthetic-Pass-2026/.test(await page.textContent('#dlgb')) && /not shown again/.test(await page.textContent('#dlgb')), 'the password shown once to hand over');
  ok(welcomes.length === 1 && welcomes[0].user === 'nadia.syn' && welcomes[0].email === 'nadia.syn@synthetic.test' && welcomes[0].role === 'operator' && welcomes[0].job === 'Database Administrator' && welcomes[0].lang === 'ar' && !('password' in welcomes[0]) && !JSON.stringify(welcomes[0]).includes('Synthetic-Pass-2026'), 'the welcome kit sent with the user name, role and job role - never the password');
  ok(/Welcome kit e-mailed to nadia\.syn@synthetic\.test/.test(await page.textContent('#dlgb')), 'the result says the welcome kit was sent');
  await page.click('#dlgok'); await page.waitForTimeout(400);
  ok(await page.$eval('#signin', (e) => !e.hidden && e.getAttribute('href') === 'identity-signin.html#users'), 'admin: Add user opens Identity & Sign-in');

  // an operator: AD + SSO people, no local accounts, no buttons, no AI
  WHO = { user: 'rasheed', role: 'operator' };
  await page.goto(base + 'user-management.html'); await page.waitForSelector('#users table');
  ok(/Only administrators see the platform accounts/.test(await page.textContent('#users')), 'operator: told local accounts are for administrators');
  ok(!(await page.$('[data-toggle]')) && !(await page.$('[data-create]')) && !(await page.$('[data-sel]')), 'operator: no enable / disable / create / select');
  ok(await page.$eval('#signin', (e) => e.hidden) && /for administrators/.test(await page.textContent('#aibox')), 'operator: no Add user link, no AI review');
  ok((await shown()).includes('ad:c1.syn'), 'operator: SSO people from AD are listed');
  // a viewer: nothing personal
  WHO = { user: 'vera', role: 'viewer' }; await page.goto(base + 'user-management.html'); await page.waitForSelector('#users .err');
  ok(/Only administrators/.test(await page.textContent('#users')) && !(await page.$('#users table')), 'viewer: no list');

  ok(!errs.length, 'page errors / dialogs: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
