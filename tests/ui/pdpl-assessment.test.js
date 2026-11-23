// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL Self-Assessment (pdpl-assessment.html) against the REAL IT Asset Management engine (engine/duty.js ->
// pdpl-assessment.js + pdpl.js + grc-registers.js, Python rules): the key-facts strip; an operator starts a cycle, is refused
// an answer without evidence, answers every question (one "no" with a note), sees the registers' suggestion and the chapter
// scores, submits; the submitter cannot approve; the DPO rejects without a note (refused), then approves - the requirement is
// confirmed and the gap becomes a GRC action; CSV export; a viewer sees only the approved score. SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-assessment.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'nora.syn', role: 'operator' }, n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const r0 = await e.req('POST', '/pdpl/records', { user: 'syed', role: 'admin', body: { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' } });
  if (r0.status !== 200) throw new Error('profile: ' + r0.text);
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/pdpl-assessment.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 950 }, acceptDownloads: true });
  let page;
  const as = async (who, sel) => { WHO = who; if (page) await page.close(); page = await ctx.newPage(); page.on('pageerror', (x) => errs.push(x.message)); await page.goto(url); await page.waitForSelector(sel || '#startc:not([hidden]), #status:not([hidden])'); };
  const txt = (sel) => page.$eval(sel, (x) => x.innerText.replace(/\s+/g, ' '));
  try {
    await as({ user: 'nora.syn', role: 'operator' });
    const facts = await txt('.facts');
    ok(/All data controllers/.test(facts) && /72-hour/.test(facts) && /SAR 5M/.test(facts) && /Art\. 36/.test(facts) && /14 September 2024/.test(facts), 'key-facts strip with references: ' + facts.slice(0, 200));
    ok(/Self-assessment/.test(await txt('#pdplnav')), 'listed in the PDPL page strip');
    await page.click('#start'); ok(/Name the cycle/.test(await txt('#startmsg')), 'a cycle name is needed');
    await page.fill('#cycle', '2026 annual'); await page.click('#start'); await page.waitForSelector('#status:not([hidden])');
    ok(/2026 annual/.test(await txt('#statusb')) && /0 \/ 40/.test(await txt('#statusb')), 'started, 0 of 40 answered');
    ok(/Registers: the registers show a gap: not published → suggests No/.test(await page.evaluate(() => { document.querySelector('[data-ch="Transparency"]').click(); return document.getElementById('qs').innerText; })), 'register suggestion shown');
    await page.click('[data-a="yes"][data-q="P03-1"]'); ok(/Write the evidence relied on first/.test(await txt('[data-qmsg="P03-1"]')), 'Yes without evidence is refused on the page');
    // answer every question through the page: yes + evidence, P09-1 "no" with a note
    const chapters = await page.$$eval('[data-ch]', (b) => b.map((x) => x.getAttribute('data-ch')));
    for (const c of chapters) {
      await page.click('[data-ch="' + c + '"]');
      const ids = await page.$$eval('[data-qbox]', (b) => b.map((x) => x.getAttribute('data-qbox')));
      for (const id of ids) {
        if (id === 'P09-1') { await page.fill('[data-nt="P09-1"]', 'no 72-hour procedure yet'); await page.click('[data-a="no"][data-q="P09-1"]'); }
        else { await page.fill('[data-ev="' + id + '"]', 'synthetic evidence ' + id); await page.click('[data-a="yes"][data-q="' + id + '"]'); }
        await page.waitForSelector('[data-qbox="' + id + '"] .on-' + (id === 'P09-1' ? 'no' : 'yes'));
      }
    }
    ok(/40 \/ 40/.test(await txt('#statusb')), 'every question answered');
    ok(/P09-1/.test(await txt('#gaps')) && /no 72-hour procedure yet/.test(await txt('#gaps')), 'the gap is listed with its note');
    ok(/This answer contradicts a gap the registers show/.test(await page.evaluate(() => { document.querySelector('[data-ch="Transparency"]').click(); return document.getElementById('qs').innerText; })), 'yes against a register gap is flagged');
    await page.click('#submit'); await page.waitForFunction(() => /waiting for approval/.test(document.getElementById('statusb').innerText));
    ok(/Submitted by you/.test(await txt('#statusb')) && !(await page.$('[data-decide]')), 'the submitter cannot approve');
    // CSV
    const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#csv')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/^# PDPL self-assessment PA-/.test(csv) && /"no"/.test(csv) && csv.split('\n').length >= 42, 'CSV of every answer');
    // the DPO decides
    await as({ user: 'huda.syn', role: 'operator' }, '#status:not([hidden])');
    await page.click('[data-decide="reject"]'); ok(/Write why it is rejected/.test(await txt('#dmsg')), 'reject needs a note');
    await page.click('[data-decide="approve"]'); await page.waitForFunction(() => /approved/.test(document.getElementById('statusb').innerText));
    ok(/GRC actions ACT-\d+/.test(await txt('#statusb')), 'the gap became a GRC action');
    const reqs = (await e.req('GET', '/pdpl', { user: 'huda.syn', role: 'operator' })).json.requirements;
    ok(reqs.find((r) => r.id === 'P-09').confirmation.status === 'non_compliant', 'P-09 confirmed non-compliant by the DPO');
    const log = e.app.store.auditTail(300).map((x) => x.action);
    ok(['pdpl.assessment.start', 'pdpl.assessment.answer', 'pdpl.assessment.submit', 'pdpl.assessment.approve', 'grc.action.create'].every((k) => log.includes(k)), 'audited');
    // viewer
    await as({ user: 'v.syn', role: 'viewer' }, '#viewerc:not([hidden])');
    const v = await txt('#viewer'); ok(/2026 annual/.test(v) && /Governance/.test(v) && !/synthetic evidence/.test(v), 'viewer: approved score per chapter, no answers');
    ok(!errs.length, 'page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); e.close(); }
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
