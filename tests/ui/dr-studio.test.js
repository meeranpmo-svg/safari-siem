// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for DR Studio (dashboards/server/dr-studio.html) against the REAL ITAM engine (engine/dr-studio.js,
// pyengine/dr_studio_rules.py, GRC DR & BCM Drills; the Virtualization DR view, the SIEM's Oracle summary and the model stubbed)
// on SYNTHETIC replication streams: overall state and readiness ring, the site-to-site picture, stream cards with lag lines, the
// forecast and unusual-lag notes, the 24-hour heat map, a cross-site conflict, the sources, a stream's explained readiness and
// last drill, admin settings (RPO + drill link) audited and hidden from operators, the read-only AI analyst, a hostile name
// stays text, nothing invented with no source, and a viewer can read but not ask.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node dr-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  const NOW = Date.now(); let T = NOW, lag = 120, connected = true, asked = 0;
  const create = async (req) => {
    asked++;
    if (!req.messages.some((m) => Array.isArray(m.content) && m.content.some((c) => c.type === 'tool_result'))) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u1', name: 'streams', input: {} }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'Not without data loss: PD-ERP is past its RPO (synthetic).' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  const pd = (name, age, status, why) => ({ name, rpo_min: 60, age_min: age, status, why, remote_sites: ['DR-SYN'], vms: [1, 2] });
  e.app.addons = e.app.addons || {};
  e.app.addons.virtCapacity = { report: () => (connected ? { dr: { sites: [{ platform_id: 'ntx1', platform: 'Prism HQ (synthetic)', site: 'Riyadh', at: new Date(T).toISOString(),
    protection_domains: [pd('PD-CLAIMS', 20, 'ok', 'last copy 20 min ago'), pd('PD-ERP', 150, 'late', 'last copy 150 min ago, RPO 60 min'), pd(XSS, 10, 'ok', 'synthetic hostile name')] }],
    cross: [{ name: 'PD-HR', status: 'both-active', why: 'active on both sites (split brain)' }] } } : {}) };
  const drSiem = async () => (connected ? { ok: true, data: { instances: [{ key: 'drdb|ORCLSB', host: 'drdb', instance: 'ORCLSB', db_name: 'SYNCLM', role: 'PHYSICAL STANDBY', dataguard: { role: 'PHYSICAL STANDBY', apply_lag_s: lag, transport_lag_s: 30, protection_mode: 'MAXIMUM PERFORMANCE' } }] } } : { ok: false, error: 'SIEM link not configured' });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3', drSiem, drSdk: sdk, drKey: () => 'sk-ant-synthetic' });
  const S = e.app.addons.drStudio;
  for (let i = 3 * 96; i > 24; i--) { T = NOW - i * 900000; lag = 100 + (i % 3) * 10; await S.sample(null); }
  for (let i = 24; i >= 0; i--) { T = NOW - i * 900000; lag = 200 + (24 - i) * 25; await S.sample(null); }
  T = NOW;
  const G = require(path.join(ITAM, 'engine/grc')).createGrc(e.app);
  const d1 = G.drillPut({ title: 'Switchover (synthetic)', system: 'SYNCLM', type: 'failover' }, OP); G.drillResult(d1.id, { result: 'pass', executed: new Date(NOW - 10 * 86400000).toISOString().slice(0, 10) }, OP);
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  let WHO = OP;
  const srv = http.createServer((req, res) => {
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
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'dashboards/dr-studio.html');
    ok(await wait(p, () => !document.getElementById('main').hidden && document.querySelectorAll('.st-card').length === 4), 'four streams (3 protection domains + 1 standby)');
    ok(/AT RISK/.test(await p.textContent('#state')), 'overall AT RISK (a stream past the RPO and a split brain)');
    ok(/^\d+$/.test((await p.textContent('#ring b')).trim()), 'readiness ring has a number');
    ok((await p.$$('#topo g.st')).length === 4 && (await p.$$('#topo .dash')).length >= 3, 'site-to-site picture: one animated line per stream');
    ok((await p.$$('#streams svg.spark')).length >= 4, 'lag lines drawn from the samples');
    const dgCard = await p.$('.st-card[data-key="dg:drdb|ORCLSB"]');
    ok(dgCard && /passes the RPO in about/.test(await dgCard.textContent()), 'rising lag forecast on the standby');
    ok(dgCard && /unusual for this stream/.test(await dgCard.textContent()), 'unusual lag flagged');
    ok((await p.$$('#heat tr')).length === 5 && (await p.$$('#heat td.c')).length === 96, '24-hour heat map, a row per stream');
    ok(/PD-HR/.test(await p.textContent('#conflicts')), 'the cross-site conflict is shown');
    const src = await p.textContent('#sources');
    ok(/1 cluster/.test(src) && /1 standby/.test(src) && /1 stream\(s\) matched/.test(src), 'sources: Nutanix, Data Guard, DR drills');
    ok(!(await p.evaluate(() => window.__xss)) && (await p.textContent('#streams')).includes(XSS) && !(await p.$('#streams img')), 'a hostile name stays text');
    await dgCard.click();
    ok(await wait(p, () => /SYNCLM standby/.test(document.getElementById('det').textContent)), 'stream detail opens');
    const det = await p.textContent('#det');
    ok(/Readiness \d+ \/ 100/.test(det) && /passes the RPO/.test(det), 'readiness explained point by point');
    ok(/DR & BCM Drills · SYNCLM/.test(det) && /pass/.test(det), 'last drill from DR & BCM Drills');
    ok(!(await p.$('#rsave')), 'an operator has no settings');
    // AI
    ok(/Claude claude-opus-5-5/.test(await p.textContent('#ais')), 'AI analyst on');
    await p.fill('#q', 'Can we fail over now?'); await p.click('#go');
    ok(await wait(p, () => /past its RPO/.test(document.getElementById('out').textContent)), 'the analyst answers');
    ok(/1 step\(s\): streams/.test(await p.textContent('#out')), 'its tool steps are shown');
    // admin settings
    WHO = ADM; await p.reload();
    ok(await wait(p, () => document.querySelectorAll('.st-card').length === 4), 'admin view loads');
    await p.click('.st-card[data-key="dg:drdb|ORCLSB"]');
    ok(await wait(p, () => !!document.getElementById('rsave')), 'an admin has settings');
    await p.fill('#rpo', '30'); await p.click('#rsave');
    ok(await wait(p, () => /lag [\d.]+ (s|min) \/ RPO 30 min/.test((document.querySelector('.st-card[data-key="dg:drdb|ORCLSB"]') || {}).textContent || '')), 'the RPO is saved and used');
    ok(e.app.store.auditTail(50).some((x) => x.action === 'dr.studio.settings' && x.by === 'syed' && x.detail.rpo_min.to === 30), 'audited with who');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'stor'); return !!(a && a.pages.some((x) => x.h === 'dr-studio.html')); }), 'the menu has the page');
    // viewer reads, cannot ask
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => document.querySelectorAll('.st-card').length === 4) && await p.isDisabled('#go'), 'a viewer reads but cannot ask');
    // nothing connected: an empty state, never a sample
    connected = false; await p.reload();
    ok(await wait(p, () => /NOT MEASURED/.test(document.getElementById('state').textContent)), 'nothing connected: NOT MEASURED');
    ok(/No replication stream reported/.test(await p.textContent('#streams')) && /no Nutanix cluster connected/.test(await p.textContent('#sources')), 'says what to connect');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
