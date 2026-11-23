// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Start a PDPL Gap Assessment (dashboards/server/pdpl-gap-start.html, vendor/zyb-pdplgap.js) against the REAL ITAM
// engine, SYNTHETIC data: open the engagement, send the kick-off, record and accept evidence, take the baseline, link the
// self-assessment (answered and approved by the DPO through the API), rate the gap, publish the plan, sign as the lead, approve as
// the DPO; the report opens; a viewer is refused; in the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-gap-start.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  let WHO = { user: 'lina.syn', role: 'operator' };
  const api = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  await api('POST', '/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' }, { user: 'syed', role: 'admin' });
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (code, b2) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u2.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u2.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u2.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u2.pathname.endsWith('.js') ? 'application/javascript' : u2.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1], 'i').test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'pdpl-gap-start.html?standalone=1'); await p.waitForSelector('#g-save');
    ok(await has(p, '#steps', /Team & scope/) && await has(p, '#steps', /Report & sign-off/), 'seven steps listed');
    ok(await has(p, '#panel', /huda\.syn/), 'the DPO from the profile is named');
    // 1 open it
    await p.fill('#g-name', 'PDPL gap 2026 (synthetic)'); await p.fill('#g-ass', 'amir.syn'); await p.fill('#g-dept', 'Claims, HR'); await p.fill('#g-target', '2027-01-31');
    await p.click('#g-save'); await p.waitForSelector('#k-send');
    ok(await has(p, '#panel', /28 requests/), 'kick-off counts 2 departments x 14 items');
    // 2 kick-off and evidence
    await p.fill('#k-due', '2027-01-10'); await p.click('#k-send'); await p.waitForSelector('[data-ev="received"]');
    ok(await has(p, '#panel', /requested 28/), 'evidence requests sent');
    await p.click('[data-ev="received"]'); await p.fill('#d-x', 'DPO appointment letter (synthetic)'); await p.click('#dlgok');
    ok(await has(p, '#panel', /received 1/), 'evidence recorded as received');
    await p.click('[data-ev="accepted"]'); ok(await has(p, '#panel', /accepted 1/), 'evidence accepted');
    await p.selectOption('#k-dept', 'HR'); ok(!(await p.textContent('#panel')).includes('Claims</td>'), 'department filter');
    // 3 baseline
    await p.click('[data-step="3"]'); await p.click('#b-take'); ok(await has(p, '#panel', /empty/) && await has(p, '#panel', /Processing activities/), 'baseline shows empty registers as empty');
    // 4 questionnaire
    await p.click('[data-step="4"]'); await p.click('#a-start'); ok(await has(p, '#panel', /PA-\d{4}-\d{3}/) && await has(p, '#panel', /answer and submit/), 'self-assessment linked');
    const g = (await api('GET', '/pdpl/gap', undefined, { user: 'lina.syn', role: 'operator' })).json.current, aid = g.review.id;
    const qs = (await api('GET', '/pdpl/assessment?id=' + aid, undefined, { user: 'amir.syn', role: 'operator' })).json.assessment.questions;
    for (const q of qs) await api('POST', '/pdpl/assessment/' + aid + '/answer', Object.assign({ qid: q.id }, q.id === qs[0].id ? { answer: 'no', note: 'missing (synthetic)' } : { answer: 'yes', evidence: 'synthetic ' + q.id }), { user: 'amir.syn', role: 'operator' });
    await api('POST', '/pdpl/assessment/' + aid + '/submit', {}, { user: 'amir.syn', role: 'operator' });
    ok((await api('POST', '/pdpl/assessment/' + aid + '/decide', { decision: 'approve' }, { user: 'huda.syn', role: 'operator' })).status === 200, 'DPO approves the answers');
    // 5 rate the gap
    await p.click('#refresh'); await p.waitForTimeout(500); await p.click('[data-step="5"]'); await p.waitForSelector('[data-rate]');
    await p.click('[data-rate]'); await p.selectOption('#d-l', '4'); await p.selectOption('#d-i', '5'); await p.fill('#d-rc', 'no owner for the notice'); await p.fill('#d-rec', 'publish the privacy notice on the website'); await p.fill('#d-o', 'amir.syn'); await p.fill('#d-t', '2027-01-31'); await p.click('#dlgok');
    ok(await has(p, '#panel', /critical 20/), 'gap rated critical');
    // 6 plan
    await p.click('[data-step="6"]'); await p.click('#pl-pub'); ok(await has(p, '#panel', /GRC action\(s\) ACT-/), 'plan published to GRC actions');
    // 7 report
    await p.click('[data-step="7"]'); await p.fill('#r-sum', 'One critical gap: the privacy notice is not published (synthetic).'); await p.click('#r-sign');
    ok(await has(p, '#panel', /Signed by lina\.syn/), 'lead signs');
    ok(await has(p, '#panel', /a different person approves/), 'four-eyes note for the signer');
    const [pop] = await Promise.all([p.waitForEvent('popup'), p.click('#r-html')]); await pop.waitForLoadState();
    ok(/Gap Assessment/.test(await pop.textContent('h1')) && /not an SDAIA certificate/.test(await pop.content()), 'report opens'); await pop.close();
    WHO = { user: 'huda.syn', role: 'operator' }; await p.reload(); await p.waitForSelector('#steps'); await p.click('[data-step="7"]'); await p.click('#r-appr');
    ok(await has(p, '#panel', /Approved by huda\.syn/), 'DPO approves the report');
    ok((await p.$$eval('#steps li.done', (x) => x.length)) === 7, 'every step done');
    const v = await browser.newPage(); WHO = { user: 'vera.syn', role: 'viewer' }; await v.goto(base + 'pdpl-gap-start.html?standalone=1');
    ok(await has(v, '#err', /PDPL team/), 'viewer refused'); await v.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "pdpl-gap-start.html"/.test(nav) && inst.includes('pdpl-gap-start.html') && inst.includes('vendor/zyb-gapwiz.js'), 'in the menu and the install list');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
