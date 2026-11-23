// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Notification & Escalation (dashboards/server/notify-center.html) against the REAL ITAM engine
// (engine/notify-center.js, pyengine/notify_rules.py; the SIEM stubbed) on SYNTHETIC alerts: an administrator builds a team and a
// policy in the forms (a bad e-mail is refused with the field named), an alert is routed to the person on call and escalates, the
// ladder and the e-mails are shown, an operator acknowledges and resolves from the page, the ML panels learn from history, a noisy
// policy becomes a proposal the admin approves, a hostile alert title stays text, a viewer reads only, the menu and the portal entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node notify-center.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';
const MIN = 60000, T0 = Date.parse('2026-10-27T07:00:00Z');

(async () => {
  const e = await H.startApp({ noAi: true });
  let clock = T0; const alerts = [], sent = [];
  const siem = async (m, p, b, user) => {
    if (p.startsWith('/alerts')) return { ok: true, status: 200, data: { items: alerts.slice() } };
    if (p === '/reports/deliver') { sent.push({ b, user }); return { ok: true, status: 200, data: { ok: true } }; }
    return { ok: false, status: 0, error: 'no' };
  };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', ncSiem: siem });
  e.app.addons.updateHealth.view = () => ({ pages: [] });   // a healthy platform (the test engine lacks main.js's AI CISO routes)
  const N = e.app.addons.notifyCenter;
  // history for the ML: 25 noisy incidents of a policy that will exist
  const C = e.app.store.collection('nc_incidents');
  for (let i = 0; i < 25; i++) C.put({ id: 'NC-SYN-' + i, fp: 'soc:old' + i, source: 'soc', title: 'Port scan from 198.51.100.' + i, severity: 3, policy: 'soc-high', team: 'net', first: T0 - (i + 2) * 3600000, acked_at: T0 - (i + 2) * 3600000 + (4 + i) * MIN, resolved_at: T0 - (i + 2) * 3600000 + 8 * MIN, status: 'resolved', resolution: i < 20 ? 'false-positive' : 'fixed', notified: [{ at: T0 - (i + 2) * 3600000, to: ['Ali Syn'], after_hours: false }] });
  let WHO = ADM;
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
    await p.goto(base + 'dashboards/notify-center.html');
    ok(await wait(p, () => !document.getElementById('main').hidden && !document.getElementById('cfg').hidden), 'admin: the routing setup is shown');
    ok(/No team yet/.test(await p.textContent('#oncall')), 'no team yet - says so');
    // team through the form: a bad e-mail is refused, then saved
    await p.fill('#t-id', 'net'); await p.fill('#t-name', 'Network team'); await p.fill('#t-start', '2026-10-25');
    await p.fill('#t-mem', 'Ali Syn <ali.syn@corpgroup.test>\nOmar Syn <not-mail>'); await p.click('#t-save');
    ok(await wait(p, () => /members\[1\]\.email/.test(document.body.textContent)), 'a bad address is refused with the field named');
    await p.fill('#t-mem', 'Ali Syn <ali.syn@corpgroup.test>\nOmar Syn <omar.syn@corpgroup.test>'); await p.click('#t-save');
    ok(await wait(p, () => /Ali Syn/.test(document.getElementById('oncall').textContent)), 'on call now: Ali Syn (rota)');
    await p.click('#ctabs [data-c="policies"]');
    await p.fill('#p-id', 'soc-high'); await p.fill('#p-name', 'SOC high and critical'); await p.selectOption('#p-src', ['soc']); await p.selectOption('#p-sev', '3'); await p.fill('#p-steps', '0:oncall, 15:team');
    await p.click('#p-save');
    ok(await wait(p, () => /1\. SOC high and critical/.test(document.getElementById('cbody').textContent)), 'policy saved');
    // an alert arrives; the router pages the on-call person, then escalates
    alerts.push({ id: 'ALR-0007', rule_name: 'VPN brute force ' + XSS, severity: 3, status: 'new', summary: 'synthetic' });
    await N.tick(null); clock = T0 + 16 * MIN; await N.tick(null);
    await p.reload();
    ok(await wait(p, () => document.querySelectorAll('#incs tr.inc').length === 1), 'the incident is listed');
    ok(!(await p.evaluate(() => window.__xss)) && (await p.textContent('#incs')).includes('<img') && !(await p.$('#incs img')), 'a hostile alert title stays text');
    ok((await p.$$('#incs .lad i.on')).length === 2, 'the ladder shows two steps sent');
    ok(sent.length === 2 && sent[0].b.recipients[0] === 'ali.syn@corpgroup.test' && sent[1].b.recipients.length === 2 && sent[0].user === 'system:itam-notify', 'on-call first, then the team, through the relay');
    ok(/1/.test(await p.$eval('#kpis .kpi:nth-child(3) .n', (x) => x.textContent)), 'escalated counted');
    // detail
    await p.click('#incs tr.inc');
    ok(await wait(p, () => /Who was told/.test(document.getElementById('det').textContent) && /routed by "SOC high and critical"/.test(document.getElementById('det').textContent)), 'detail: who was told + timeline');
    // ML: learnt from history; noisy policy -> proposal; admin approves
    ok(await wait(p, () => /median/.test(document.getElementById('ml1').textContent) && /Ali Syn/.test(document.getElementById('ml2').textContent)), 'ML: time to acknowledge and fatigue');
    ok(/noisy/.test(await p.textContent('#ml2')), 'ML: the policy is noisy');
    await p.click('#refresh');
    ok(await wait(p, () => /ml:notify-noise/.test(document.getElementById('props').textContent)), 'a proposal from the learning');
    await p.click('#props [data-dec="approve"]');
    ok(await wait(p, () => /approved/.test(document.getElementById('props').textContent)), 'approved by a different person (the admin)');
    ok(N.view({ role: 'admin' }).policies[0].min_severity === 4, 'applied to the policy');
    // operator acknowledges and resolves from the page; a viewer reads only
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => document.querySelectorAll('#incs tr.inc').length === 1) && await p.isHidden('#cfg') && await p.isDisabled('#go'), 'viewer: no setup, no AI');
    await p.click('#incs tr.inc'); ok(!(await p.$('#ack')), 'viewer: no acknowledge button');
    WHO = OP; await p.reload(); await wait(p, () => document.querySelectorAll('#incs tr.inc').length === 1);
    await p.click('#incs tr.inc'); await p.fill('#note', 'on it'); await p.click('#ack');
    ok(await wait(p, () => /Acknowledged by nora\.syn/.test(document.getElementById('det').textContent)), 'acknowledged from the page');
    clock = T0 + 60 * MIN; await N.tick(null); ok(sent.length === 2, 'no more e-mails after the acknowledgement');
    await p.click('#incs tr.inc'); await p.selectOption('#resn', 'fixed'); await p.click('#res');
    ok(await wait(p, () => /Nothing needs anyone right now/.test(document.getElementById('incs').textContent)), 'resolved - the queue is clear');
    ok(e.app.store.auditTail(60).some((x) => x.action === 'notify.ack' && x.by === 'nora.syn') && e.app.store.auditTail(60).some((x) => x.action === 'notify.policies.save' && x.by === 'syed'), 'audited with who');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'cmd'); return !!(a && a.pages.some((x) => x.h === 'notify-center.html')); }), 'the menu has the page');
    ok(/notify: 'notify-center\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal\'s Notification & Escalation opens it');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
