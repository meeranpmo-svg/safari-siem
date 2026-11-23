// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for ad-exchange.html: a role guessed from the name can be confirmed, or rejected ("Not a DC") by saying what
// the server is - saved as its service, after which it is no longer guessed; Cancel leaves it as it was; admin only.
// Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ad-exchange.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let ROLE = 'admin'; const POSTS = [], UQ = [];
const PEOPLE = [
  { sam: 'adm.syn', name: 'Admin Synthetic', department: 'IT', privileged: true, dormant: true, privileged_groups: ['Domain Admins', 'Administrators'], last_logon: '2026-01-02T08:00:00Z', dn: 'CN=Admin Synthetic,OU=IT,DC=synthetic,DC=test' },
  { sam: 'ops.syn', name: '<img src=x onerror=window.PWN=1>Ops Synthetic', department: 'IT', privileged: true, privileged_groups: ['Server Operators'], last_logon: '2026-11-10T08:00:00Z' },
  { sam: 'old.syn', name: 'Old Synthetic', department: 'Finance', admin_orphan: true, privileged_groups: [], last_logon: '2026-10-01T08:00:00Z' }];
const HOSTS = [
  { id: 'h1', name: 'adconnect', ip: '192.168.12.47', status: 'online', service: '', availability: { d7: 100 } },
  { id: 'h2', name: 'amlprdco', ip: '192.168.12.108', status: 'online', service: '', availability: { d7: 100 } },
  { id: 'h3', name: 'DC-HQA', ip: '192.168.12.10', status: 'online', service: 'Active Directory', availability: { d7: 100 } }];
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: ROLE });
    if (u === '/api/soc/netops/avail/hosts' && q.method === 'POST') { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { const x = JSON.parse(b); POSTS.push(x); const h = HOSTS.find((y) => y.id === x.id); if (h && x.service !== undefined) h.service = x.service; j(200, h || {}); }); return; }
    if (u === '/api/soc/identity/summary') return j(200, { synced: '2026-11-12T17:19:35Z', domain: 'synthetic.test', dormant_days: 90, counts: { users: 990, enabled: 915, privileged_enabled: 2, dormant: 127, dormant_privileged: 1, service_accounts: 0, admin_count_orphans: 1 },
      privileged_groups: [{ name: 'Domain Admins', members: 1, nested_members: 0 }, { name: 'Server Operators', members: 1, nested_members: 0 }] });
    if (u === '/api/soc/identity/users') { const qs = new URLSearchParams(q.url.split('?')[1]); UQ.push(qs.toString());
      const L = PEOPLE.filter((x) => (!qs.get('privileged') || !!x.privileged) && (!qs.get('dormant') || !!x.dormant) && (qs.get('flag') !== 'admin_orphan' || x.admin_orphan)); return j(200, { total: L.length, items: L }); }
    if (u === '/api/soc/netops/avail') return j(200, { summary: { total: 3, online: 3, offline: 0, unknown: 0 }, items: HOSTS, groups: [] });
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1500, height: 900 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto('http://127.0.0.1:' + srv.address().port + '/ad-exchange.html'); await p.waitForSelector('tr[data-h]'); return p; };
  let p = await open();
  const row = (id) => p.evaluate((i) => (document.querySelector('tr[data-h="' + i + '"]') || {}).textContent || '', id);
  ok(/guessed/.test(await row('h1')) && await p.$('[data-notk="h1"]') && await p.$('[data-confirm="h1"]'), 'guessed row: Confirm and Not a DC');
  ok(!(await p.$('[data-notk="h3"]')), 'a role set by an administrator has no buttons');
  await p.click('[data-notk="h1"]'); await p.waitForSelector('#nk-s');
  await p.click('#nk-no'); await p.waitForTimeout(300);
  ok(!POSTS.length && /guessed/.test(await row('h1')), 'Cancel changes nothing');
  await p.click('[data-notk="h1"]'); await p.waitForSelector('#nk-s');
  await p.click('#nk-ok'); await p.waitForTimeout(300); ok(!POSTS.length, 'empty: refused');
  await p.fill('#nk-s', 'Domain controller'); await p.click('#nk-ok'); await p.waitForTimeout(300); ok(!POSTS.length, 'naming the same role: refused (use Confirm)');
  await p.fill('#nk-s', 'Azure AD Connect'); await p.click('#nk-ok'); await p.waitForTimeout(800);
  ok(POSTS.length === 1 && POSTS[0].id === 'h1' && POSTS[0].service === 'Azure AD Connect', 'saved as the server\'s service: ' + JSON.stringify(POSTS));
  ok(!(await p.$('tr[data-h="h1"]')) && /amlprdco/.test(await p.textContent('body')), 'no longer listed as a domain controller; the other guess stays');
  // directory accounts: every tile and every privileged group opens the accounts behind it
  await p.waitForSelector('#idn [data-idl]');
  ok((await p.$$('#idn [data-idl]')).length === 6 && (await p.$$('#idn [data-idg]')).length === 2, 'six tiles and the group rows are clickable');
  await p.click('#idn [data-idl="priv_dormant"]'); await p.waitForFunction(() => /Admin Synthetic/.test(document.body.innerText));
  ok(/Dormant privileged accounts/.test(await p.textContent('body')) && /privileged=1/.test(UQ[UQ.length - 1]) && /dormant=1/.test(UQ[UQ.length - 1]), 'Dormant privileged: the list asked for privileged + dormant: ' + UQ[UQ.length - 1]);
  await p.click('[data-zau="adm.syn"]'); await p.waitForFunction(() => /CN=Admin Synthetic/.test(document.body.innerText));
  ok(/Domain Admins, Administrators/.test(await p.textContent('body')) && await p.$('a[href="ad-manage.html"]'), 'an account opens with its groups and where to change it');
  await p.click('[data-zaback]'); ok(await p.waitForFunction(() => !!document.querySelector('[data-zau="adm.syn"]')).then(() => true, () => false), 'back to the list');
  const shut = () => p.evaluate(() => window.zybDetail.close());
  await shut(); await p.click('#idn [data-idg="Server Operators"]');
  // the heading shows while the members load: wait for the rows themselves (reading them earlier saw an empty list)
  await p.waitForFunction(() => /Members of Server Operators/.test(document.body.innerText) && !!document.querySelector('[data-zau]'));
  const gl = await p.$$eval('[data-zau]', (r) => r.map((x) => x.getAttribute('data-zau')));
  ok(gl.length === 1 && gl[0] === 'ops.syn' && /<img src=x/.test(await p.textContent('body')) && !(await p.evaluate(() => window.PWN)), 'a group shows only its members; a hostile name stays text');
  await shut(); await p.click('#idn [data-idl="admin_orphan"]'); await p.waitForFunction(() => /adminCount leftovers/.test(document.body.innerText) && !!document.querySelector('[data-zau="old.syn"]'));
  ok(/flag=admin_orphan/.test(UQ[UQ.length - 1]), 'adminCount leftovers: asked by its flag');
  await shut(); await p.click('#idn [data-idl="all"]'); await p.waitForSelector('[data-zau="old.syn"]'); await p.fill('#zaq', 'finance');
  ok((await p.$$('[data-zau]')).length === 1, 'search narrows the list');
  await p.close();
  ROLE = 'operator'; p = await open();
  ok(!(await p.$('[data-notk]')) && !(await p.$('[data-confirm]')), 'operator: no buttons');
  await p.close();
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
