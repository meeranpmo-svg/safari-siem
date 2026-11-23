// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for exchange-hybrid.html against the REAL SIEM sysadmin + hybrid routes (fake WinRM helper): readiness read
// from the servers, steps people confirm, mailbox inventory, MX / SPF from the Domains register, a wave created with its
// Exchange Online commands, status changes, the largest-mailbox read, viewer limits, the menu entry. SYNTHETIC names.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node exchange-hybrid.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), vm = require('vm');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../../backend/siem'), DASH = path.resolve(__dirname, '../../ui');
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const routes = require(path.join(SIEM, 'engine/sysadmin/routes'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const DATA = {
  ex_servers: [{ name: 'EXCH01', version: 'Version 15.2 (Build 1544.4)' }],
  ex_certificates: [{ subject: 'CN=mail.corp-synth.sa', services: 'IIS, SMTP', days_left: 200, self_signed: false, names: ['mail.corp-synth.sa'] }],
  ex_hybrid_ews: [{ server: 'EXCH01', external_url: 'https://mail.corp-synth.sa/EWS/Exchange.asmx', mrs_proxy: false }],
  ex_hybrid_domains: { accepted: [{ name: 'corp-synth.sa' }], remote: [], send_connectors: [] },
  ex_hybrid: { hybrid: false, org_relationships: [], intra_org_connectors: [], auth_servers: [] },
  ex_mailbox_counts: { on_premises: 420, by_type: [{ type: 'UserMailbox', count: 420 }], by_database: [{ database: 'DB01', count: 420 }], with_archive: 3, in_cloud: 0, in_cloud_by_type: [] },
  ex_large_mailboxes: [{ name: 'Synthetic Big User', database: 'DB01', size_gb: 112.4, items: 900000 }],
};
(async () => {
  const w = { ZYB_ORG: require('../../brand/index') }; vm.runInNewContext(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'), { window: w });
  const hit = w.ZYB_NAV.filter((a) => a.pages.some((p) => p.h === 'exchange-hybrid.html'));
  ok(hit.length === 1 && hit[0].id === 'usr', 'menu: once, under Identity & Microsoft 365');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-hybp-')), sec = path.join(dir, 's.json'); fs.writeFileSync(sec, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'st') });
  const config = {}; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets: sec }, enumerable: false });
  const exec = async (req) => req.op === 'version' ? { ok: true } : req.op === 'run' ? { ok: true, data: DATA[req.check] !== undefined ? DATA[req.check] : [], errors: [] } : { ok: false, kind: 'input', error: 'x' };
  const S = routes.createSysadmin({ state, config, log: { info() {}, warn() {}, error() {} }, sysadminExec: exec });
  const R = []; routes.register({ route: (m, p, h) => R.push([m, new RegExp('^' + p.replace(/:([a-z]+)/g, '(?<$1>[^/]+)') + '$'), h]) }, { state, config, log: { error() {}, info() {} }, sysadmin: S });
  let WHO = { user: 'syed', role: 'admin' };
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const srv = http.createServer((req, res) => {
    const [u, qs] = req.url.split('?'); const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    if (u === '/api/itam/domains') return json(200, { domains: [{ name: 'corp-synth.sa', check: { records: { MX: [{ exchange: 'mx.corp-synth.sa' }], SPF: ['v=spf1 mx -all'] } } }] });
    if (u.startsWith('/api/soc/')) {
      const r = R.find(([m, rx]) => m === req.method && rx.test(u)); if (!r) return json(404, { error: 'no route' });
      let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => {
        const out = {}; const ctx = { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : {}, params: (u.match(r[1]).groups || {}), query: Object.fromEntries(new URLSearchParams(qs || '')), need(x) { if (RANK[WHO.role] < RANK[x]) { out.status = 403; return false; } return true; }, audit() {}, ok(v) { out.status = 200; out.body = v; }, fail(c, msg) { out.status = c; out.error = msg; } };
        try { const rv = await r[2](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } } catch (e) { out.status = e.status || 500; out.error = e.message; }
        json(out.status || 200, out.body !== undefined ? out.body : { error: out.error });
      }); return;
    }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  // an Exchange server with a login, added the way an admin does
  const add = (m, p, body) => new Promise((res) => { const rq = http.request(base.slice(0, -1) + p, { method: m, headers: { 'Content-Type': 'application/json' } }, (r) => { let t = ''; r.on('data', (c) => { t += c; }); r.on('end', () => res(t)); }); rq.end(JSON.stringify(body)); });
  await add('POST', '/api/soc/sysadmin/targets', { id: 'exch01', name: 'EXCH01', ip: '10.0.1.20', roles: ['exchange'] });
  await add('PUT', '/api/soc/sysadmin/profiles/exchange', { username: 'CORP\\svc-exro', password: 'Pw-123456' });
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const page = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message)); page.on('console', (m) => { if (m.type() === 'error' && !/40[034]|409/.test(m.text())) errs.push(m.text()); });
  page.on('dialog', (d) => d.accept(d.type() === 'prompt' ? 'Entra Connect v2 checked' : undefined));
  const txt = (s) => page.$eval(s, (x) => x.innerText.replace(/\s+/g, ' '));
  await page.goto(base + 'exchange-hybrid.html?standalone=1'); await page.waitForSelector('#ready table');
  ok(/not read/.test(await txt('#ready')) && /Not fully read/.test(await txt('#kk')), 'before reading: not read, never ready');
  await page.click('#refresh'); await page.waitForFunction(() => /Not ready/.test(document.querySelector('#kk').innerText));
  const rd = await txt('#ready');
  ok(/MRS Proxy off/.test(rd) && /no hybrid configuration on-premises/.test(rd) && /Run the Hybrid Configuration Wizard/.test(rd), 'readiness from the servers: ' + rd.slice(0, 300));
  ok(/On-premises mailboxes 420/.test(await txt('#kk')) && /DB01 420/.test(await txt('#inv')), 'inventory');
  const dns = await txt('#dns'); ok(/mx\.corp-synth\.sa/.test(dns) && /on-premises \/ gateway/.test(dns) && /no/.test(dns), 'MX / SPF from Domains: ' + dns.slice(0, 200));
  await page.check('[data-man="entra"]'); await page.waitForFunction(() => /confirmed by syed/.test(document.querySelector('#manual').innerText));
  ok(/Entra Connect v2 checked/.test(await txt('#manual')), 'manual step with who + note');
  // settings, wave, commands
  await page.click('#set'); await page.waitForSelector('#s-t'); await page.fill('#s-t', 'corpsynth'); await page.click('#s-go'); await page.waitForTimeout(400);
  await page.click('#neww'); await page.fill('#w-n', 'Wave 1 - IT pilot'); await page.fill('#w-d', '2026-11-05'); await page.fill('#w-m', 'a.one@corp-synth.sa\nb.two@corp-synth.sa'); await page.click('#w-go');
  await page.waitForSelector('#waves table'); ok(/Wave 1 - IT pilot.*2026-11-05.*2.*planned/.test(await txt('#waves')), 'wave listed: ' + await txt('#waves'));
  await page.click('[data-cmd]'); await page.waitForSelector('#ps-txt');
  const ps = await page.$eval('#ps-txt', (x) => x.textContent);
  ok(/New-MigrationBatch -Name 'Wave 1 - IT pilot'/.test(ps) && /corpsynth\.mail\.onmicrosoft\.com/.test(ps) && /Complete-MigrationBatch/.test(ps), 'commands: ' + ps.slice(0, 200));
  await page.keyboard.press('Escape').catch(() => {}); await page.evaluate(() => window.zybDetail.close());
  await page.selectOption('[data-st]', 'syncing'); await page.waitForFunction(() => /syncing/.test(document.querySelector('#waves').innerText));
  ok(true, 'status set');
  await page.click('#lg'); await page.waitForFunction(() => /112\.4 GB/.test(document.querySelector('#large').innerText));
  ok(/Synthetic Big User/.test(await txt('#large')) && /Over 100 GB/.test(await txt('#large')), 'largest mailboxes');
  // viewer
  WHO = { user: 'viewer.one', role: 'viewer' };
  await page.goto(base + 'exchange-hybrid.html?standalone=1'); await page.waitForSelector('#waves table');
  ok(await page.$eval('#refresh', (b) => b.hidden) && !(await page.$('[data-cmd]')) && await page.$eval('[data-man="entra"]', (c) => c.disabled), 'viewer: read only');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
