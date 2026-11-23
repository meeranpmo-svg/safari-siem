// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Browser test for domains.html with the REAL ITAM module (backend/itam engine/domains.js) over a fake resolver and fake
// certificates: add a domain and a hostname from the page, check, KPI tiles, mail-security chips, findings with what to do,
// certificate details, asset matched by IP, change history, Excel, viewer read-only, and "not installed".
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node domains.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const ITAM = process.env.SENTRA_ITAM_DIR || path.resolve(__dirname, '../../backend/itam');
const { startApp } = require(path.join(ITAM, 'tests/helpers')), { createDomains } = require(path.join(ITAM, 'engine/domains'));

let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const DAY = 86400000;

(async () => {
  const itam = await startApp({ noAi: true });
  const now = Date.now();
  const zone = {
    [ZYB_ORG.domain]: { NS: ['ns1.cloudflare.com', 'ns2.cloudflare.com'], MX: [{ priority: 0, exchange: 'x.mail.protection.outlook.com' }], TXT: [['v=spf1 include:spf.protection.outlook.com -all']], CAA: [{ critical: 0, issue: 'digicert.com' }] },
    ['_dmarc.' + ZYB_ORG.domain]: { TXT: [['v=DMARC1; p=none']] },
    ['portal.' + ZYB_ORG.domain]: { A: ['10.20.0.15'] },
  };
  const nod = () => Promise.reject(Object.assign(new Error('x'), { code: 'ENODATA' }));
  const get = (t) => (n0) => ((zone[n0] || {})[t] ? Promise.resolve(zone[n0][t]) : nod());
  const resolver = { resolveNs: get('NS'), resolveMx: get('MX'), resolveTxt: get('TXT'), resolveCaa: get('CAA'), resolve4: get('A'), resolve6: get('AAAA'), resolveCname: get('CNAME') };
  const D = createDomains(itam.app, { resolver, tlsPeek: async () => ({ subject: ('portal.' + ZYB_ORG.domain), issuer: 'DigiCert', valid_to: now + 12 * DAY, names: [('portal.' + ZYB_ORG.domain)], name_ok: true, trusted: true, trust_error: '' }) });
  itam.app.store.collection('assets').put({ id: 'a_portal', name: 'PORTAL-WEB01', type: 'server', mgmt_ip: '10.20.0.15', status: 'active' });
  let ROLE = 'admin', MISSING = false;
  const who = () => ({ user: 'syed', role: ROLE, ip: '' });
  const need = (r) => { const rk = { viewer: 0, operator: 2, admin: 3 }; if (rk[ROLE] < rk[r]) throw Object.assign(new Error('forbidden'), { status: 403 }); };

  const srv = http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c)); req.on('end', async () => {
      const [u0, qs] = req.url.split('?'), u = decodeURIComponent(u0), body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
      const J = (st, x) => { res.writeHead(st, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(x)); };
      if (u === '/dashboards/whoami.json') return J(200, { user: 'syed', role: ROLE });
      if (u.startsWith('/api/itam/domains')) {
        if (MISSING) return J(404, { error: 'not found' });
        try {
          const p = u.slice('/api/itam'.length);
          if (req.method === 'GET' && p === '/domains') return J(200, D.view(ROLE));
          if (req.method === 'GET' && p === '/domains/history') return J(200, D.history(Object.fromEntries(new URLSearchParams(qs || ''))));
          if (req.method === 'POST' && p === '/domains') { need('admin'); return J(200, D.putDomain(body, who())); }
          if (req.method === 'POST' && p === '/domains/hosts') { need('admin'); return J(200, D.putHost(body, who())); }
          if (req.method === 'POST' && p === '/domains/check') { need('operator'); await D.check(body.id || ''); return J(200, D.view(ROLE)); }
          const m = /^\/domains\/(hosts\/)?([^/]+)\/retire$/.exec(p); if (req.method === 'POST' && m) { need('admin'); return J(200, D.retire(m[1] ? 'host' : 'domain', m[2], body, who())); }
          return J(404, { error: 'no route' });
        } catch (e) { return J(e.status || 500, { error: e.message }); }
      }
      if (u.startsWith('/api/')) return J(404, { error: 'not in this test' });
      const f = path.join(DASH, u === '/' ? 'index.html' : u);
      if (!f.startsWith(DASH)) { res.writeHead(403); res.end(); return; }
      fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage(); const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  const tiles = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('#kk .t')].map((t) => [t.querySelector('.l').textContent, t.querySelector('.v').textContent])));

  await page.goto(base + 'domains.html'); await page.waitForSelector('#kk .t');
  ok(await page.evaluate(() => /No domain registered yet/.test(document.getElementById('body').textContent) && !document.getElementById('add-d').hidden), 'empty register, admin sees Add');

  // add a domain from the page -> saved and checked
  await page.click('#add-d'); await page.waitForSelector('#f-name');
  await page.fill('#f-name', ZYB_ORG.domain); await page.fill('#f-reg', 'SaudiNIC'); await page.fill('#f-exp', new Date(now + 60 * DAY).toISOString().slice(0, 10));
  await page.selectOption('#f-prov', 'cloudflare'); await page.fill('#f-ns', 'ns1.cloudflare.com, ns2.cloudflare.com'); await page.fill('#f-dk', 'selector1');
  await page.click('[data-saved]'); await page.waitForSelector('tr[data-d]');
  let t = await tiles();
  ok(t['Domains'] === '1' && t['Expiring in 90 days'] === '1', 'tiles after adding: ' + JSON.stringify(t));
  const row = await page.evaluate(() => document.querySelector('tr[data-d]').innerText);
  ok(new RegExp(ZYB_ORG.domain_re).test(row) && /SaudiNIC/.test(row) && /Cloudflare/.test(row) && /(59|60) d/.test(row), 'domain row: ' + row);
  ok(await page.evaluate(() => [...document.querySelectorAll('tr[data-d] .mc')].map((m) => m.textContent + ':' + m.className.split(' ')[1]).join(',')) === 'SPF:ok,DMARC:warn,DKIM:warn', 'mail chips SPF ok / DMARC p=none warn / DKIM selector missing warn');
  await page.click('tr[data-d]'); await page.waitForSelector('#zd:not([hidden])');
  const dd = await page.evaluate(() => document.getElementById('zd-b').innerText);
  ok(/DMARC policy is p=none/.test(dd) && /What to do: Move to p=quarantine/.test(dd) && /selector1/.test(dd) && /ns1\.cloudflare\.com/.test(dd), 'domain drawer: findings with what to do + records');
  await page.keyboard.press('Escape');

  // add a hostname -> certificate, asset matched by IP
  await page.click('#add-h'); await page.waitForSelector('#f-fqdn');
  await page.fill('#f-fqdn', ('portal.' + ZYB_ORG.domain)); await page.fill('#f-pur', 'Staff portal'); await page.fill('#f-host', 'Riyadh DC'); await page.selectOption('#f-loc', 'ksa');
  await page.click('[data-saveh]'); await page.waitForFunction(() => document.querySelector('#tabs button.on').getAttribute('data-tab') === 'd');
  await page.click('#tabs [data-tab="h"]'); await page.waitForSelector('tr[data-h]');
  const hr = await page.evaluate(() => document.querySelector('tr[data-h]').innerText);
  ok(/Staff portal/.test(hr) && /KSA/.test(hr) && /10\.20\.0\.15/.test(hr) && /1[12] d/.test(hr) && /DigiCert/.test(hr) && /PORTAL-WEB01/.test(hr) && /matched by IP/.test(hr), 'host row: ' + hr);
  const bp = await page.$eval('#brand', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/Brand Protection/.test(bp) && /(not synced|not installed|Not synced yet|in step)/.test(bp) && /Update Brand Protection/.test(bp), 'Brand Protection panel: ' + bp);
  t = await tiles(); ok(t['Certificates ≤ 30 days'] === '1', 'certificate tile: ' + JSON.stringify(t));
  await page.click('tr[data-h]'); await page.waitForSelector('#zd:not([hidden])');
  ok(/expires in 1[12] day\(s\)/.test(await page.evaluate(() => document.getElementById('zd-b').innerText)), 'host drawer: certificate finding');
  await page.keyboard.press('Escape');

  // a nameserver change: Check now -> flagged and in history
  zone[ZYB_ORG.domain].NS = ['ns1.evil.example'];
  await page.click('#check'); await page.waitForFunction(() => document.getElementById('check').textContent === '⟳ Check now');
  await page.click('#tabs [data-tab="d"]'); await page.click('tr[data-d]'); await page.waitForSelector('#zd:not([hidden])');
  await page.waitForFunction(() => /DNS changes seen \(1\)/i.test(document.getElementById('zd-b').innerText), null, { timeout: 8000 }).catch(() => {});
  const d2 = await page.evaluate(() => document.getElementById('zd-b').innerText);
  ok(/Nameservers differ from the ones recorded/.test(d2) && /possible domain hijack/.test(d2), 'hijack flagged');
  ok(/DNS changes seen \(1\)/i.test(d2) && /NS: \+ ns1\.evil\.example/.test(d2), 'change history in the drawer');
  await page.keyboard.press('Escape');

  // Excel
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#xlsx')]);
  const buf = fs.readFileSync(await dl.path()), txt = buf.toString('latin1');
  ok(buf.slice(0, 2).toString() === 'PK' && txt.includes('name="Domains"') && txt.includes('name="Hostnames"'), 'xlsx ' + dl.suggestedFilename());

  // viewer: read-only
  ROLE = 'viewer'; await page.goto(base + 'domains.html'); await page.waitForSelector('tr[data-d]');
  ok(await page.evaluate(() => document.getElementById('add-d').hidden && document.getElementById('check').hidden), 'viewer: no add / check buttons');
  await page.click('tr[data-d]'); await page.waitForSelector('#zd:not([hidden])');
  ok(await page.evaluate(() => !document.querySelector('#zd-b [data-editd]') && !document.querySelector('#zd-b [data-chk]')), 'viewer: no edit / check in the drawer');
  await page.keyboard.press('Escape');

  // module not installed
  MISSING = true; await page.goto('about:blank'); await page.goto(base + 'domains.html'); await page.waitForSelector('#body .err');
  ok(/not installed in IT Asset Management yet/.test(await page.evaluate(() => document.getElementById('body').textContent)), 'not installed says so');

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); itam.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
