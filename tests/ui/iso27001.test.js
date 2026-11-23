// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the ISO 27001 ISMS page (dashboards/server/iso27001.html) against the REAL ITAM engine (engine/iso27001.js +
// pyengine/iso27001_rules.py) with SYNTHETIC facts: clause groups and Annex A themes with labelled bars, readiness, a theme tile
// filters the register, a requirement recorded in the drawer and approved by the ISMS manager, the SoA proposed and approved by
// someone else, the audit programme planned by the daily job with the working paper prepared, an auditor assigned and the
// report submitted and accepted (nonconformities raised), the corrective action planned, done and verified, the management
// review pack and record, a hostile value stays text, a viewer is refused, the menu has the page under Audit.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node iso27001.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2099-01-01' }],
    control_status: { assets: { state: 'pass', metric: '40 registered', detail: 'ok' }, patch: { state: 'fail', metric: '30/40', detail: '10 host(s) missing critical patches ' + XSS }, roles: { state: 'unknown' } } },
  risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 1, high: 0 }, internet_facing: 3, exposed_assets: 0 },
});
const MGR = { user: 'mona.syn', role: 'operator' }, AUD = { user: 'adel.syn', role: 'operator' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', eccFacts: async () => FACTS() });
  const api = async (who, m, p, body) => { const r = await e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  const today = new Date().toISOString().slice(0, 10);
  await api(ADM, 'POST', '/iso27001/profile', { isms_manager: MGR.user, scope: 'Head office IT and cyber security (synthetic)', scope_approved: today, context_reviewed: today, parties_reviewed: today, risk_method_approved: today, auditors: [AUD.user] });
  await e.app.addons.iso27001.tick();   // the daily job: plans the programme and prepares what is due within 30 days
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
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept('not enough evidence (synthetic)'));
    const reload = async (who) => { WHO = who; await p.goto(base + 'iso27001.html?standalone=1'); await p.waitForSelector('#list table', { state: 'attached', timeout: 15000 }); };
    await reload(OP);
    ok((await p.$$eval('#grps .sub', (x) => x.length)) === 11, '7 clause groups + 4 Annex A themes');
    ok(await p.$$eval('#grps .stack span', (x) => x.length > 0 && x.every((s) => s.getAttribute('title'))), 'every bar segment labelled');
    const kp = await p.textContent('#kpis');
    ok(/Certification readiness/.test(kp) && /Annex A controls implemented/.test(kp) && /Checked automatically/.test(kp) && /Counted from NCA ECC/.test(kp), 'KPIs: ' + kp.replace(/\s+/g, ' ').slice(0, 200));
    ok(/Stage 1/.test(await p.textContent('#ready')), 'readiness card');
    const list = await p.textContent('#list');
    ok(/A\.8\.19/.test(list) && list.includes(XSS) && !(await p.$('#list img')), 'a gap with its reason; a hostile value stays text');
    await p.click('[data-grp="a6"]');
    ok((await p.$$eval('#list tbody tr', (x) => x.length)) === 8 && /\(8 of 118\)/.test(await p.textContent('#filt')), 'the People theme tile filters 8 controls');
    await p.click('[data-grp="a6"]');
    // record a manual requirement; the ISMS manager approves it
    await p.selectOption('#fgrp', 'a7'); await p.click('#list tr[data-id="A.7.3"]'); await p.waitForSelector('#cform', { timeout: 8000 });
    await p.selectOption('#cform [name=status]', 'compliant'); await p.fill('#cform [name=evidence]', 'site security review Q3 (synthetic)'); await p.click('#cform [type=submit]');
    ok(await zd(p, /waiting for a second person/), 'recorded, waiting for approval');
    await p.keyboard.press('Escape');
    await reload(MGR);
    await p.selectOption('#fgrp', 'a7'); await p.click('#list tr[data-id="A.7.3"]'); await p.waitForSelector('[data-decide="approve"]', { timeout: 8000 }); await p.click('[data-decide="approve"]');
    ok(await zd(p, /Approved by mona\.syn/), 'approved by the ISMS manager');
    await p.keyboard.press('Escape');
    // SoA: the ISMS manager proposes, an administrator approves
    await p.click('[data-tab="soa"]'); await p.fill('#soaex', 'A.8.30 | No outsourced development: packaged applications only (synthetic)'); await p.click('#soaform [type=submit]');
    await p.waitForSelector('[data-soa="approve"]', { timeout: 10000 });
    ok(/waiting for approval/.test(await p.textContent('#soa')), 'SoA proposed');
    await reload(ADM); await p.click('[data-tab="soa"]'); await p.click('[data-soa="approve"]');
    await p.waitForFunction(() => /approved/.test(document.getElementById('soa').textContent) && !document.querySelector('[data-soa]'), null, { timeout: 10000 }).then(() => ok(true), () => ok(false, 'SoA approved'));
    ok(/excluded/.test(await p.textContent('#soalist')), 'the exclusion shows in the SoA table');
    // the programme: 12 audits, the first prepared by the daily job; assign, record and submit, accept
    await reload(MGR); await p.click('[data-tab="prog"]');
    ok((await p.$$eval('#audits tbody tr', (x) => x.length)) === 12, '12 audits planned');
    ok(/prepared/.test(await p.textContent('#audits')), 'one already prepared by the daily job');
    const first = await p.$eval('#audits tbody tr', (r) => r.getAttribute('data-aud'));
    await p.click('#audits tr[data-aud="' + first + '"]'); await p.waitForSelector('#aform', { timeout: 8000 });
    ok(await zd(p, /Working paper \(prepared/), 'the working paper is in the drawer');
    await p.fill('#aform [name=auditor]', AUD.user); await p.click('#aform [type=submit]');
    await p.waitForFunction(() => /adel\.syn/.test((document.getElementById('zd') || {}).textContent || '') && document.getElementById('fform'), null, { timeout: 10000 }).then(() => ok(true), () => ok(false, 'auditor assigned'));
    await p.keyboard.press('Escape');
    await reload(AUD); await p.click('[data-tab="prog"]'); await p.click('#audits tr[data-aud="' + first + '"]'); await p.waitForSelector('#fform', { timeout: 8000 });
    const cnt = await p.$eval('#fcount', (x) => +x.value);
    for (let i = 0; i < cnt; i++) { const g = await p.$eval('[name=grade' + i + ']', (s) => s.value); if (g === 'evidence_request') await p.selectOption('[name=grade' + i + ']', 'conforming'); }
    await p.selectOption('[name=grade0]', 'major');
    await p.click('#fsubmit');
    ok(await p.waitForFunction(() => /conclusion is required/.test((document.getElementById('fform') || {}).textContent || ''), null, { timeout: 8000 }).then(() => true, () => false), 'a conclusion is required');
    await p.fill('#fconc', 'ISMS core partly established (synthetic)'); await p.click('#fsubmit');
    ok(await zd(p, /Accept the report|awaiting acceptance/), 'report submitted');
    await p.keyboard.press('Escape');
    await reload(MGR); await p.click('[data-tab="prog"]'); await p.click('#audits tr[data-aud="' + first + '"]'); await p.waitForSelector('[data-accept]', { timeout: 8000 });
    await p.click('[data-accept]');
    await p.waitForFunction(() => /reported/.test(document.getElementById('audits').textContent), null, { timeout: 10000 }).then(() => ok(true), () => ok(false, 'report accepted'));
    // nonconformity: plan, done (owner), verify (auditor)
    await p.click('[data-tab="nc"]'); ok((await p.$$eval('#ncs tbody tr', (x) => x.length)) >= 1, 'nonconformities raised');
    const nc = await p.$eval('#ncs tbody tr', (r) => r.getAttribute('data-nc'));
    await p.click('#ncs tr[data-nc="' + nc + '"]'); await p.waitForSelector('#ncform', { timeout: 8000 });
    await p.fill('#ncform [name=root_cause]', 'No owner for the ISMS scope review (synthetic)'); await p.fill('#ncform [name=corrective_action]', 'Assign the owner and calendar the review (synthetic)'); await p.fill('#ncform [name=owner]', OP.user);
    await p.click('#ncform [type=submit]'); ok(await zd(p, /corrective action under way/), 'corrective action planned');
    await p.keyboard.press('Escape');
    await reload(OP); await p.click('[data-tab="nc"]'); await p.click('#ncs tr[data-nc="' + nc + '"]'); await p.waitForSelector('#ncdone', { timeout: 8000 });
    await p.fill('#ncdone [name=evidence]', 'calendar invite (synthetic)'); await p.click('#ncdone [type=submit]'); ok(await zd(p, /awaiting verification/), 'reported done');
    await p.keyboard.press('Escape');
    await reload(AUD); await p.click('[data-tab="nc"]'); await p.click('#ncs tr[data-nc="' + nc + '"]'); await p.waitForSelector('#ncver', { timeout: 8000 });
    await p.selectOption('#ncver [name=decision]', 'effective'); await p.fill('#ncver [name=note]', 'review held (synthetic)'); await p.click('#ncver [type=submit]');
    ok(await zd(p, /closed - verified effective/), 'verified by the auditor and closed');
    await p.keyboard.press('Escape');
    // management review: pack, then the record
    await reload(MGR); await p.click('[data-tab="mr"]'); await p.click('#pack');
    await p.waitForFunction(() => /\(g\) Opportunities/.test(document.getElementById('packout').textContent), null, { timeout: 10000 }).then(() => ok(true), () => ok(false, 'review pack with inputs a-g'));
    await p.fill('#mrf [name=held_on]', today); await p.fill('#mrf [name=chaired_by]', 'CEO (synthetic)'); await p.fill('#mrf [name=attendees]', 'mona.syn, nora.syn');
    await p.fill('#mrf [name=decisions]', 'Approve the ISMS objectives for 2027 (synthetic)'); await p.fill('#mrf [name=actions]', 'Publish the objectives');
    await p.click('#mrf [type=submit]');
    await p.waitForFunction(() => /MR-0001/.test(document.getElementById('mrlist').textContent), null, { timeout: 10000 }).then(() => ok(true), () => ok(false, 'review recorded'));
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#soacsv')]);
    ok(/^iso27001-soa-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'SoA CSV export');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => a.id === 'cmp' && a.pages.some((x) => x.h === 'iso27001.html' && x.g === 'ISO 27001'))), 'in the menu under Compliance -> ISO 27001');
    // a viewer reads but cannot record
    await reload({ user: 'v.syn', role: 'viewer' });
    await p.selectOption('#fgrp', 'a7'); await p.click('#list tr[data-id="A.7.5"]'); await p.waitForSelector('#cform', { timeout: 8000 });
    await p.selectOption('#cform [name=status]', 'compliant'); await p.fill('#cform [name=evidence]', 'x'); await p.click('#cform [type=submit]');
    await p.waitForFunction(() => /operator|not allowed|forbidden|403|role/i.test(document.getElementById('cform').textContent), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'a viewer is refused'));
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
