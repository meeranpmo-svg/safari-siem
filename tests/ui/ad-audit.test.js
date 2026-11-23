// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AD Audit (ad-audit.html), stubbed SIEM API, SYNTHETIC accounts: the Account hygiene tiles, a finding's list and a privileged group
// row open the shared accounts drawer (vendor/zyb-adacct.js) with the right filter; an account opens with its groups and its recent
// directory events; back to the list; search; "Full list with CSV export" opens the Account hygiene table; a hostile name stays text;
// no browser dialog, no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ad-audit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const UQ = [], SEARCH = [];
const PEOPLE = [
  { sam: 'adm.syn', name: 'Admin Synthetic', department: 'IT', privileged: true, dormant: true, pwd_never_expires: true, privileged_groups: ['Domain Admins'], last_logon: '2026-01-02T08:00:00Z', pwd_age_days: 400, dn: 'CN=Admin Synthetic,OU=IT,DC=synthetic,DC=test' },
  { sam: 'ops.syn', name: '<img src=x onerror=window.PWN=1>Ops Synthetic', department: 'IT', privileged: true, privileged_groups: ['Server Operators'], last_logon: '2026-11-10T08:00:00Z' },
  { sam: 'fin.syn', name: 'Finance Synthetic', department: 'Finance', no_preauth: true, privileged_groups: [], last_logon: '2026-11-01T08:00:00Z' }];
const COUNTS = { users: 3, enabled: 3, privileged_enabled: 2, dormant_privileged: 1, pwd_never_expires: 1, privileged_pwd_never_expires: 1, pwd_not_required: 0, no_preauth: 1, delegation: 0, old_pwd: 1, never_logon: 0, dormant: 1, disabled: 0, admin_count_orphans: 0, expired: 0, service_accounts: 0 };
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    let raw = ''; q.on('data', (d) => { raw += d; }); q.on('end', () => {
      if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'admin' });
      if (u === '/api/soc/identity/summary') return j(200, { synced: '2026-11-12T17:19:35Z', domain: 'synthetic.test', dormant_days: 90, counts: COUNTS, privileged_groups: [{ name: 'Domain Admins', members: 1, nested_members: 0, dn: 'CN=Domain Admins,CN=Users,DC=synthetic,DC=test' }, { name: 'Server Operators', members: 1, nested_members: 0 }] });
      if (u === '/api/soc/identity/users') {
        const qs = new URLSearchParams(q.url.split('?')[1]); UQ.push(qs.toString()); const fl = qs.get('flag');
        const L = PEOPLE.filter((x) => (!qs.get('privileged') || !!x.privileged) && (!qs.get('dormant') || !!x.dormant) && (!fl || !!x[fl])); return j(200, { total: L.length, items: L });
      }
      if (u === '/api/soc/search') { const b = JSON.parse(raw || '{}'); SEARCH.push(b); return j(200, { rows: /adm\.syn/.test(b.q || '') ? [{ ts: '2026-11-11T09:00:00Z', event_code: '4728', host: 'DC01', user: 'someone.syn', target_user: 'adm.syn' }] : [], total: 0 }); }
      if (u === '/api/soc/histogram') return j(200, { buckets: [] });
      if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
      fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
    });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const p = await browser.newPage({ viewport: { width: 1500, height: 900 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, a) => p.waitForFunction(fn, a, { timeout: 10000 }).then(() => true, () => false);
  const body = () => p.evaluate(() => document.body.innerText);
  const shut = () => p.evaluate(() => window.zybDetail.close());
  try {
    await p.goto('http://127.0.0.1:' + srv.address().port + '/ad-audit.html?standalone=1');
    await p.waitForSelector('[data-act]');
    // a finding's list opens the drawer
    const fx = await p.$('[data-act="u:priv_dormant"]');
    if (fx) { await fx.click(); ok(await wait(() => !!document.querySelector('[data-zau="adm.syn"]')) && /privileged=1/.test(UQ[UQ.length - 1]) && /dormant=1/.test(UQ[UQ.length - 1]), 'a finding opens the dormant privileged accounts in the drawer'); await shut(); }
    // the Account hygiene tiles
    await p.click('[data-tab="acc"]'); await p.waitForSelector('#acck [data-act]');
    await p.click('#acck [data-act="u:no_preauth"]');
    ok(await wait(() => !!document.querySelector('[data-zau="fin.syn"]')) && /Kerberos pre-authentication off/.test(await body()) && /flag=no_preauth/.test(UQ[UQ.length - 1]), 'a tile opens its accounts in the drawer, asked by its flag');
    ok(await p.evaluate(() => document.getElementById('tab-acc').hidden === false) && !(await p.$('#acc tr[data-u]')), 'the page underneath is unchanged (the drawer, not the table)');
    await shut(); await p.click('#acck [data-act="u:all"]'); await wait(() => document.querySelectorAll('[data-zau]').length === 3);
    await p.fill('#zaq', 'finance'); ok((await p.$$('[data-zau]')).length === 1, 'search narrows the list');
    await p.fill('#zaq', ''); await p.click('[data-zau="adm.syn"]');
    ok(await wait(() => /Recent directory events/.test(document.body.innerText) && /4728/.test(document.body.innerText)), 'an account opens with its recent directory events (this page\'s extra)');
    ok(/Domain Admins/.test(await body()) && /CN=Admin Synthetic/.test(await body()) && !!(await p.$('a[href="ad-manage.html"]')) && SEARCH.some((s) => /adm\.syn/.test(s.q)), 'its groups, DN and where to change it');
    await p.click('[data-zaback]'); ok(await wait(() => !!document.querySelector('[data-zau="fin.syn"]')), 'back to the list');
    ok(!/<img src=x/.test('') && /<img src=x/.test(await body()) && !(await p.evaluate(() => window.PWN)), 'a hostile name stays text');
    await p.click('[data-zafull]'); ok(await wait(() => !!document.querySelector('#acc tr[data-u]')) && /3 accounts/.test(await p.textContent('#acc-c')), 'Full list with CSV export opens the Account hygiene table');
    // a privileged group row
    await p.click('[data-tab="grp"]'); await p.waitForSelector('tr[data-g]'); await p.click('tr[data-g="Server Operators"]');
    ok(await wait(() => /Members of Server Operators/.test(document.body.innerText) && !!document.querySelector('[data-zau]')) && (await p.$$eval('[data-zau]', (r) => r.map((x) => x.getAttribute('data-zau')))).join() === 'ops.syn', 'a privileged group opens its members in the drawer');
    ok(!errs.length, 'no page errors or dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
