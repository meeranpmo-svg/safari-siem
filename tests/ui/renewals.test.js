// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Renewal Autopilot card on Domains & DNS (domains.html #ren + vendor/zyb-renewals.js) against the REAL ITAM engine
// (engine/renewals.js) with a FAKE RDAP service and SYNTHETIC domains: the registry is read from the card, a later registry date
// corrects the register, a domain inside the lead time has a task, the tiles filter, the drawer lists every risk point and the
// registry reading, the renewal goes request -> approve (another admin; the requester refused) -> renewed -> verified by the
// registry, a lock removed shows as a hijack sign first in the actions, a hosting subscription is added (admin), a viewer sees no
// costs and no buttons, a hostile provider name stays text, menu installer lists the script.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node renewals.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { createRenewals, registerRenewals } = require(path.join(ITAM, 'engine', 'renewals'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const ADM = { user: 'syed.syn', role: 'admin' }, ADM2 = { user: 'fatima.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const day = (d) => new Date(Date.now() + d * 86400000).toISOString().slice(0, 10);
const doc = (name, expires, o = {}) => ({ ldhName: name, status: o.status || ['client transfer prohibited'], events: [{ eventAction: 'expiration', eventDate: expires + 'T00:00:00Z' }], entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', o.registrar || 'Synthetic Registrar LLC']]] }], nameservers: [] });

(async () => {
  const e = await H.startApp({ noAi: true });
  const REG = { 'corp2-syn.com': doc('corp2-syn.com', day(15)), 'brand-syn.net': doc('brand-syn.net', day(400)) };
  const fetch = async (url) => { if (url === 'https://data.iana.org/rdap/dns.json') return { status: 200, json: { services: [[['com', 'net'], ['https://rdap.syn.test/']]] } };
    const m = /domain\/(.+)$/.exec(url), d = m && REG[decodeURIComponent(m[1])]; return d ? { status: 200, json: d } : { status: 404, json: {} }; };
  const X = createRenewals(e.app, { fetch, noTimer: true }); e.app.addons.renewals = X; registerRenewals(e.app.srv, e.app, X);
  const api = async (who, m, p, body) => { const r = await e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  await api(ADM, 'POST', '/domains', { name: 'corp2-syn.com', expires: day(15), cost: 60, owner: 'it.syn' });
  await api(ADM, 'POST', '/domains', { name: 'brand-syn.net', expires: day(200), auto_renew: true, cost: 45 });
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/domains.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const zd = (p, re) => wait(p, (src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source);
  const ren = () => p.textContent('#ren');
  let p;
  try {
    p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base); ok(await wait(p, () => /Renewal Autopilot/.test(document.getElementById('ren').textContent) && !!document.getElementById('rn-rdap')), 'the card loads with Read the registry');
    ok(await wait(p, () => /Expire in 30 days/i.test(document.getElementById('ren').textContent) && document.querySelector('#ren [data-ri="domain:' + '"]') === null), 'tiles');
    await p.click('#rn-rdap');
    ok(await wait(p, () => /Synthetic Registrar LLC/.test(document.getElementById('ren').textContent) && /locked/.test(document.getElementById('ren').textContent)), 'the registry is read: registrar and lock shown');
    ok(/corp2-syn\.com/.test(await p.$eval('#ren tbody tr', (r) => r.textContent)) && /RN-0001 opened/.test(await ren()), 'the domain due in 15 days is first, with a task opened by itself');
    ok(new RegExp(day(400)).test(await ren()), 'a later registry date corrected the register (brand-syn.net)');
    // tiles filter
    await p.click('#ren [data-rf="due"]'); ok(await wait(p, () => document.querySelectorAll('#ren tbody tr').length === 1), 'Expire in 30 days filters');
    await p.click('#ren [data-rf="due"]');
    // drawer + request
    await p.click('#ren tr[data-ri^="domain:"] td:first-child');
    ok(await zd(p, /expires in 1[45] days/) && await zd(p, /auto-renew is off/) && await zd(p, /Transfer lock/), 'the drawer lists every risk point and the registry reading');
    await p.fill('#rn-adv textarea[name=note]', 'renew for 2 years (synthetic)'); await p.click('#rn-adv button[type=submit]');
    ok(await wait(p, () => /RN-0001 requested/.test(document.getElementById('ren').textContent)), 'requested');
    // the requester cannot approve
    await p.click('#ren tr[data-ri^="domain:"] td:first-child'); await p.waitForSelector('#rn-adv[data-to="approved"]');
    await p.fill('#rn-adv textarea[name=note]', 'budget ok'); await p.click('#rn-adv button[type=submit]');
    ok(await wait(p, () => /four eyes/.test(document.getElementById('rn-msg').textContent)), 'the requester cannot approve - the reason is shown');
    await p.evaluate(() => window.zybDetail.close());
    WHO = ADM2; await p.reload(); await p.waitForSelector('#ren tbody tr');
    await p.click('#ren tr[data-ri^="domain:"] td:first-child'); await p.waitForSelector('#rn-adv[data-to="approved"]');
    await p.fill('#rn-adv textarea[name=note]', 'budget ok (synthetic)'); await p.click('#rn-adv button[type=submit]');
    ok(await wait(p, () => /RN-0001 approved/.test(document.getElementById('ren').textContent)), 'approved by another admin');
    await p.click('#ren tr[data-ri^="domain:"] td:first-child'); await p.waitForSelector('#rn-adv[data-to="renewed"]');
    await p.fill('#rn-adv input[name=new_expiry]', day(745)); await p.fill('#rn-adv input[name=cost]', '75'); await p.fill('#rn-adv input[name=evidence]', 'ORDER-SYN-1'); await p.fill('#rn-adv textarea[name=note]', 'paid (synthetic)');
    await p.click('#rn-adv button[type=submit]'); ok(await wait(p, () => /RN-0001 renewed - awaiting proof/.test(document.getElementById('ren').textContent)), 'renewed, awaiting the registry');
    // the registry moves; a lock disappears elsewhere
    REG['corp2-syn.com'] = doc('corp2-syn.com', day(745)); REG['brand-syn.net'] = doc('brand-syn.net', day(400), { status: ['active'], registrar: 'Other Registrar ' + XSS });
    await p.click('#rn-rdap');
    ok(await wait(p, () => /RN-0001 verified/.test(document.getElementById('ren').textContent)), 'verified by the registry');
    ok(await wait(p, () => /registry change that looks like a hijack/.test(document.querySelector('#ren .fd').textContent)), 'the hijack sign is the first action');
    ok(await p.evaluate(() => !window.__xss) && /Other Registrar <img/.test(await ren()), 'a hostile registrar name stays text');
    // hosting subscription
    await p.click('#rn-host'); await p.waitForSelector('#rn-hf');
    await p.fill('#rn-hf input[name=provider]', 'Synthetic Cloud'); await p.fill('#rn-hf input[name=service]', 'Web hosting'); await p.fill('#rn-hf input[name=renews]', day(20)); await p.fill('#rn-hf input[name=cost]', '1200'); await p.fill('#rn-hf input[name=owner]', 'web.syn');
    await p.click('#rn-hf button[type=submit]'); ok(await wait(p, () => /Synthetic Cloud · Web hosting/.test(document.getElementById('ren').textContent) && /RN-0002 opened/.test(document.getElementById('ren').textContent)), 'hosting added, its renewal opened');
    // a viewer
    WHO = VIEW; await p.reload(); await p.waitForSelector('#ren tbody tr');
    ok(!(await p.$('#rn-rdap')) && !(await p.$('#rn-host')) && !/cost recorded/.test(await ren()), 'a viewer: no buttons, no costs');
    await p.click('#ren tr[data-ri^="hosting:"] td:first-child'); ok(await zd(p, /Risk/) && !(await p.$('#rn-adv')) && !/web\.syn/.test(await p.textContent('#zd')), 'a viewer cannot move a renewal and sees no owner');
    const inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8'); ok(/zyb-renewals\.js/.test(inst), 'the installer lists the script');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
