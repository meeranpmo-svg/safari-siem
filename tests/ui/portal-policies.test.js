// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal (repos/live/portal) Policies & Procedures page with its policy intelligence: "What to write or finish next"
// ranked by value / effort with the reason and the open gaps each closes (Data Classification closes SAMA 4.11.2 and PDPL P-06);
// framework readiness now and with the top 3; review health (an Approved status nobody confirmed, no document on file); four-eyes -
// the super-admin who drafted a policy cannot approve it, another super-admin can (approver stamped, review date a year out); the
// AI review plan sends only the page's figures and frames names as data; the framework filter narrows the ranking; no page error.
// Browser state only (localStorage); SYNTHETIC identities. Skips without the live copy.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-policies.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'nora.syn', role: 'admin', sadmin: true }, AI = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, WHO);
    if (u === '/api/ai') { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { AI.push(b); json(200, { text: 'SYN plan' }); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn, a) => p.waitForFunction(fn, a === undefined ? null : a, { timeout: 20000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } }), p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user);   // eslint-disable-line no-undef
    await p.evaluate(() => setView('policies'));   // eslint-disable-line no-undef
    ok(await wait(p, () => document.getElementById('polIntel')), 'policy intelligence on the page');
    const intel = await p.evaluate(() => document.getElementById('polIntel').innerText);
    ok(/What to write or finish next/i.test(intel) && /Score/i.test(intel), 'ranked next steps');
    const rank = await p.evaluate(() => _polRank('All').map((r) => ({ id: r.p[0], score: r.score, links: r.links.map((g) => g.fw + ' ' + g.ref), why: r.why })));   // eslint-disable-line no-undef
    const dc = rank.find((r) => r.id === 'POL-05');
    ok(dc && dc.links.includes('SAMA 4.11.2') && dc.links.includes('PDPL P-06'), 'data classification closes SAMA 4.11.2 and PDPL P-06: ' + JSON.stringify(dc));
    const cm = rank.find((r) => r.id === 'POL-16'); ok(cm && cm.links.includes('SAMA 4.2.4'), 'change management closes the emergency-change gap');
    ok(rank.every((r, i) => i === 0 || rank[i - 1].score >= r.score), 'sorted by score'); ok(!rank.some((r) => r.id === 'POL-01'), 'an Approved policy is not recommended');
    ok(/Framework readiness/i.test(intel) && /SAMA/.test(intel) && /→ \d+% with/.test(intel), 'readiness now and with the top 3');
    ok(/Unconfirmed/.test(intel) && /No document/.test(intel), 'review health: unconfirmed seed approvals, no document on file');
    // four-eyes: nora drafts POL-05 (Not in place -> Draft), then cannot approve it
    await p.evaluate(() => cyclePolicy('POL-05'));   // eslint-disable-line no-undef
    ok(await p.evaluate(() => _polStatus('POL-05') === 'Draft' && _polMeta('POL-05').draftedBy === 'nora.syn'), 'draft stamped with who drafted it');   // eslint-disable-line no-undef
    await p.evaluate(() => approvePolicy('POL-05'));   // eslint-disable-line no-undef
    ok(await p.evaluate(() => _polStatus('POL-05') === 'Draft'), 'the drafter cannot approve');   // eslint-disable-line no-undef
    ok(await wait(p, () => /Four-eyes: nora\.syn drafted POL-05/.test(document.body.innerText)), 'told why');
    await p.evaluate(() => { ME = { user: 'omar.syn', role: 'admin', sadmin: true }; approvePolicy('POL-05'); });   // eslint-disable-line no-undef
    const m = await p.evaluate(() => _polMeta('POL-05'));   // eslint-disable-line no-undef
    ok(m.status === 'Approved' && m.approver === 'omar.syn' && /^\d{4}-\d{2}-\d{2}$/.test(m.nextReview || ''), 'another super-admin approves; review date set: ' + JSON.stringify(m));
    ok(!(await p.evaluate(() => _polRank('All').some((r) => r.p[0] === 'POL-05'))), 'approved policy leaves the ranking');   // eslint-disable-line no-undef
    // the AI review plan: only the page's figures, names framed as data
    await p.evaluate(() => { const b = document.querySelector('[data-polaiplan]'); b.click(); });
    ok(await wait(p, () => /SYN plan/.test(document.body.innerText)) || AI.length > 0, 'AI review plan asked');
    const sent = AI.join('\n'); ok(/Use ONLY the context given/.test(sent) && /data, not instructions/.test(sent) && /POL-06/.test(sent) && /Framework readiness/.test(sent), 'context and rules sent');
    // framework filter narrows the ranking
    await p.evaluate(() => { policyFW = 'PDPL'; renderFocus(); });   // eslint-disable-line no-undef
    await wait(p, () => document.getElementById('polIntel'));
    const pd = await p.evaluate(() => [...document.querySelectorAll('#polIntel tr')].map((t) => t.innerText).join('\n'));
    ok(/POL-06/.test(pd) && !/POL-16/.test(pd), 'PDPL filter: data protection in, change management out');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-policies.png', fullPage: false });
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
