// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Continuous Control Monitoring (dashboards/server/audit-ccm.html) against the REAL ITAM engine
// (engine/audit-ccm.js, engine/audit-engage.js) over a SYNTHETIC audit trail: the eight control cards with their status, a card
// filters the exceptions, a hostile target stays text, an exception explained in the drawer (a short note refused with the
// reason, an exception about yourself refused), a finding drafted from the rules and accepted into an IT Audit engagement,
// a draft discarded with a reason, the CSV export, a viewer refused without a broken page, the menu has the page under Audit.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-ccm.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const OP = { user: 'nora.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' }, HEAD = { user: 'hana.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const api = async (who, m, p, body) => { const r = await e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  const A = (minAgo, by, role, action, target, detail) => e.app.store.audit({ at: new Date(Date.now() - minAgo * 60000).toISOString(), by, role, ip: '10.0.0.9', action, target, detail: detail || null });
  A(50, 'adel.syn', 'operator', 'desk.patch.request', 'PATCH-1 ' + XSS);
  A(40, 'adel.syn', 'operator', 'desk.patch.approve', 'PATCH-1 ' + XSS);
  A(30, 'kamal.syn', 'admin', 'roles.assign', 'kamal.syn', { from: null, to: 'admin' });
  A(20, OP.user, 'operator', 'settings.credential', 'oracle');
  // the IT Audit Team and an engagement in fieldwork, for the accepted finding
  await api(ADM, 'POST', '/ia/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user] });
  const today = new Date().toISOString().slice(0, 10), later = new Date(Date.now() + 20 * 86400000).toISOString().slice(0, 10);
  const eng = await api(LEAD, 'POST', '/ia/engagements', { title: 'Change approvals (synthetic)', area: 'change', auditee_dept: 'IT', auditee_owner: OWNER.user, lead: LEAD.user, objectives: ['four-eyes'], scope: 's', start: today, fieldwork_end: later, report_due: later });
  await (await api(LEAD, 'POST', '/ia/engagements/' + eng.id + '/prior-none', { note: 'first audit of this area (synthetic)' }), api(LEAD, 'POST', '/ia/engagements/' + eng.id + '/advance', { to: 'fieldwork' }));
  await api(OP, 'POST', '/audit-ccm/run', {});
  let WHO = OP;
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 10000 }).then(() => true, () => false);
  const zd = (p, re) => wait(p, (src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'audit-ccm.html?standalone=1'); await p.waitForSelector('[data-ct]', { timeout: 15000 });
    ok((await p.$$('[data-ct]')).length === 8, 'eight control cards');
    ok(/exceptions/.test(await p.textContent('[data-ct="CT-01"]')) && /not testable/.test(await p.textContent('[data-ct="CT-05"]')), 'CT-01 has exceptions; CT-05 has nothing to test and says so');
    ok(/not proof of wrongdoing/.test(await p.textContent('.alert-info')), 'indicators, not proof');
    ok(/Controls with exceptions/.test(await p.textContent('#kpis')), 'KPIs');
    ok((await p.$$('#hs tr')).length === 8 && (await p.$$('#hm tr')).length === 8, 'the control heat strip and the weekday x hour map');
    ok(/lead, not a conclusion/.test(await p.textContent('#pp')) && (await p.$$('#pp .bx')).length >= 2, 'people in the exceptions');
    ok(/30\+ days/.test(await p.textContent('#ag')), 'open exceptions by age');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });
    await p.click('[data-ct="CT-01"]');
    ok(await wait(p, () => document.querySelectorAll('#xl tr[data-x]').length === 1), 'the card filters the exceptions');
    ok(!(await p.$('#xl img')) && (await p.textContent('#xl')).includes('<img'), 'a hostile target stays text');
    // CT-08 is about the signed-in person: refused
    await p.click('[data-ct="CT-01"]'); await p.click('[data-ct="CT-08"]');
    await p.click('#xl tr[data-x]'); ok(await zd(p, /Your conclusion/), 'the exception drawer');
    await p.fill('#fd-n', 'I changed it myself, it is fine'); await p.click('[data-dec="explained"]');
    ok(await zd(p, /about you/), 'an exception about yourself is refused');
    await p.keyboard.press('Escape');
    // CT-07: explained, after a short note is refused
    await p.click('[data-ct="CT-08"]'); await p.click('[data-ct="CT-07"]'); await p.click('#xl tr[data-x]');
    await p.fill('#fd-n', 'ok'); await p.click('[data-dec="explained"]'); ok(await zd(p, /note/), 'a short note is refused with the field named');
    await p.fill('#fd-n', 'CHG-1182 approved by the CIO; role reverted next day (synthetic)'); await p.click('[data-dec="explained"]');
    ok(await wait(p, () => /explained/.test(document.querySelector('#xl').textContent) && /nora\.syn/.test(document.querySelector('#xl').textContent)), 'explained by the person, shown in the table');
    // a finding drafted from CT-01 and accepted by an auditor on the engagement
    WHO = LEAD; await p.reload(); await p.waitForSelector('[data-ct]');
    await p.click('[data-ct="CT-01"]'); await p.click('[data-draft][data-ai="0"]');
    ok(await zd(p, /Drafted by the rules/), 'the draft opens');
    ok(/Continuous control test CT-01/.test(await p.inputValue('#fa-condition')) && (await p.inputValue('#fa-rating')) === 'high', 'the draft is pre-filled from the facts');
    await p.fill('#fa-eng', eng.id); await p.fill('#fa-owner', OWNER.user); await p.click('#fa button[type=submit]');
    ok(await wait(p, () => /accepted as a finding/.test(document.querySelector('#dl').textContent)), 'accepted');
    const f = e.app.addons.auditEngage.listFindings({}).find((x) => x.engagement === eng.id);
    ok(f && f.raised_by === LEAD.user && f.owner === OWNER.user, 'a real finding in the engagement, raised by the auditor');
    // a second draft discarded with a reason
    await p.click('[data-ct="CT-01"]'); await p.click('[data-ct="CT-08"]'); await p.click('[data-draft][data-ai="0"]'); ok(await zd(p, /Drafted by the rules/), 'second draft');
    await p.click('#fa-x'); await p.fill('#fa-xn', 'already raised in IA-F-0001 (synthetic)'); await p.click('#fa-xg');
    ok(await wait(p, () => /discarded/.test(document.querySelector('#dl').textContent)), 'discarded');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]);
    ok(/^control-monitoring-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'CSV export');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'aud'); return !!(a && a.pages.some((x) => x.h === 'audit-ccm.html')); }), 'the menu has the page under Audit');
    WHO = VIEW; await p.reload(); await p.waitForTimeout(1500);
    ok(/operator role|named person|HTTP 403|not loaded/.test(await p.textContent('body')) && !(await p.$('[data-ct]')), 'a viewer is refused and the page says why');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
