// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/update-guardrails.html against the REAL ITAM engine (engine/update-guard.js) over a SYNTHETIC
// estate (two production FortiGates, one lab FortiGate): empty state says to register a sandbox; an admin registers the lab device
// from the asset search; an operator raises a firmware update (risk itemised, lab twin matched, guardrails deny until the sandbox
// passes); applies it in the sandbox, records the attested checks; the verdict is refused until the soak ends; the requester sees
// "another person approves"; a different admin approves the canary; viewer has no actions; values escaped; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node update-guardrails.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'sec.admin', role: 'admin' }, OP = { user: 'net.req', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';
let NOW = Date.parse('2026-11-05T20:00:00Z');

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW });
  const AS = e.app.store.collection('assets'), iso = (t) => new Date(t).toISOString();
  AS.put({ id: 'as_fw1', name: 'FW-SYN-HQ-1', type: 'firewall', vendor: 'Fortinet', model: 'FortiGate 600E', os: 'FortiOS 7.2.8', last_seen: iso(NOW - 3600000) });
  AS.put({ id: 'as_fw2', name: 'FW-SYN-HQ-2' + XSS, type: 'firewall', vendor: 'Fortinet', model: 'FortiGate 600E', os: 'FortiOS 7.2.8', last_seen: iso(NOW - 3600000) });
  AS.put({ id: 'as_lab', name: 'FW-SYN-LAB', type: 'firewall', vendor: 'Fortinet', model: 'FortiGate 600E', os: 'FortiOS 7.2.8', last_seen: iso(NOW - 3600000) });
  let WHO = VW;
  const web = http.createServer((req, res) => {
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
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const open = async (who) => { WHO = who; const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + 'update-guardrails.html'); await wait(p, () => !document.getElementById('main').hidden); return p; };
  const ok2 = (p) => p.click('#dlg-ok');
  try {
    let p = await open(VW);
    ok(await wait(p, () => /No update raised yet/.test(document.getElementById('list').innerText) && /Register a lab/.test(document.getElementById('list').innerText)), 'empty: says to raise one and register a sandbox');
    ok(await p.evaluate(() => document.querySelector('#tabs [data-tab="new"]').hidden), 'viewer cannot raise');
    await p.close();
    // admin registers the lab device
    p = await open(ADM); await p.click('[data-tab="cfg"]');
    await p.fill('#c-q', 'LAB'); ok(await wait(p, () => document.querySelector('#c-hits [data-a="as_lab"]')), 'asset search finds the lab device');
    await p.click('#c-hits [data-a="as_lab"]');
    ok(await wait(p, () => /FW-SYN-LAB/.test(document.getElementById('cfg').innerText) && /version 1/.test(document.getElementById('cfg').innerText)), 'sandbox registered (config v1)');
    await p.close();
    // operator raises
    p = await open(OP); await p.click('[data-tab="new"]');
    await p.fill('#n-title', 'FortiOS 7.4.4 SYN'); await p.selectOption('#n-kind', 'security'); await p.fill('#n-vendor', 'Fortinet'); await p.fill('#n-product', 'FortiOS');
    await p.fill('#n-from', '7.2.8'); await p.fill('#n-to', '7.4.4'); await p.fill('#n-chg', 'CHG-SYN-1'); await p.fill('#n-rb', 'boot alternate partition');
    await p.click('#n-go'); ok(await wait(p, () => /Add at least one production target/.test(document.getElementById('n-err').innerText)), 'page refuses without targets');
    for (const q of ['HQ-1', 'HQ-2']) { await p.fill('#n-q', q); await wait(p, () => document.querySelector('#n-hits [data-a]')); await p.click('#n-hits [data-a]'); }
    ok(await p.evaluate(() => document.querySelectorAll('#n-targets span').length === 2), 'two targets picked');
    await p.click('#n-go');
    ok(await wait(p, () => document.querySelector('.rec') && !document.getElementById('tab-upd').hidden), 'raised and shown');
    const card = () => p.evaluate(() => document.querySelector('.rec').innerText);
    let t = await card();
    ok(/feature release change/.test(t) && /no past Fortinet FortiOS updates/.test(t), 'risk itemised (version jump, prior)');
    ok(/FW-SYN-LAB/.test(t) && /\d+% match/.test(t), 'lab twin matched');
    ok(/deny/.test(t) && /UG-03/.test(t), 'guardrails deny until the sandbox passes');
    ok(/another person approves/.test(t), 'the requester cannot approve');
    ok(await p.evaluate(() => !window.__xss), 'asset name escaped');
    // sandbox
    await p.click('[data-act="sbstart"]'); ok(await p.evaluate(() => document.querySelector('[data-sb="as_lab"]').checked), 'matched twin preselected'); await ok2(p);
    ok(await wait(p, () => /In the sandbox/.test(document.querySelector('.rec').innerText)), 'in the sandbox');
    const cids = await p.$$eval('[data-act="check"]', (bs) => bs.map((b) => b.getAttribute('data-c')));
    ok(cids.length === 4, 'four attested checks for security firmware');
    for (const c of cids) { await p.click('[data-act="check"][data-c="' + c + '"]'); await p.fill('#d-ev', 'synthetic lab test ' + c); await ok2(p); await wait(p, () => !document.getElementById('dlg').open); }
    await p.click('[data-act="verdict"]'); await p.fill('#d-note', 'all green'); await ok2(p);
    ok(await wait(p, () => /Reports in|soak/.test(document.getElementById('dlg-e').innerText)), 'verdict refused before report-in / soak: ' + await p.evaluate(() => document.getElementById('dlg-e').innerText));
    await p.click('#dlg-x');
    NOW += 25 * 3600000; AS.put(Object.assign(AS.get('as_lab'), { last_seen: iso(NOW) }));
    await p.click('#rf'); await p.waitForTimeout(300);
    await p.click('[data-act="verdict"]'); await p.fill('#d-note', 'all green after soak (synthetic)'); await ok2(p);
    await p.waitForTimeout(400); if (await p.evaluate(() => document.getElementById('dlg').open)) { console.log('verdict error:', await p.evaluate(() => document.getElementById('dlg-e').innerText)); await p.click('#dlg-x'); }
    ok(await wait(p, () => /Sandbox passed/.test(document.querySelector('.rec').innerText)), 'sandbox passed');
    await p.click('[data-act="edit"]'); await p.check('#d-bk'); await p.fill('#d-bke', 'config backup 2026-11-06 (synthetic)'); await ok2(p);
    ok(await wait(p, () => /backup verified/.test(document.querySelector('.rec').innerText)), 'backup recorded');
    await p.close();
    // different admin approves canary
    p = await open(ADM);
    ok(await wait(p, () => document.querySelector('[data-act="approve"][data-n="1"]')), 'admin sees Approve on the canary');
    await p.click('[data-act="approve"][data-n="1"]'); await ok2(p);
    ok(await wait(p, () => /Rolling out/.test(document.querySelector('.rec').innerText) && document.querySelector('[data-act="applied"]')), 'canary approved, rolling out');
    await p.click('[data-tab="log"]'); ok(await wait(p, () => /sec\.admin/.test(document.getElementById('log').innerText)), 'decision logged');
    await p.click('[data-f="rolling"]'); ok(await wait(p, () => document.querySelectorAll('.rec').length === 1 && !document.getElementById('tab-upd').hidden), 'KPI tile filters');
    await p.close();
    p = await open(VW); ok(await wait(p, () => document.querySelector('.rec')) && !(await p.$('.rec button[data-act]')), 'viewer: no actions'); await p.close();
    const au = e.app.store.auditTail(80); ok(au.some((a) => a.action === 'update_guard.wave.approve' && a.by === 'sec.admin'), 'audited');
    ok(/ update-guardrails\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(/"h": "update-guardrails.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
