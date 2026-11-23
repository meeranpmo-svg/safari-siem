// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal (repos/live/portal) with our menu scripts: its AI panels call aiAsk() → /api/ai, a route this
// server does not have. An HTML answer used to show 'Unexpected token "<" … is not valid JSON'; now it says the portal
// assistant is not connected and where the AI engineers are, and the AI Team review card shows that. A real JSON /api/ai
// is still passed through. The portal's AI Team entry opens the live AI Engineering Team. Skips without the live copy.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-ai.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let AI = 'html';
// the portal as the server has it after the update: add-dashboards-menu.sh puts zyb-early.js right after <head>
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u === '/api/ai') { if (AI === 'json') return json(200, { text: 'SYN answer' }); res.writeHead(405, { 'Content-Type': 'text/html' }); return res.end('<html> <head><title>405 Not Allowed</title></head><body>nginx</body></html>'); }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(INDEX); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  try {
    const ctx = await browser.newContext({ viewport: { width: 1366, height: 800 } }), p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await p.waitForSelector('li.zyb-area', { state: 'attached', timeout: 20000 }); await p.waitForTimeout(500);
    const r1 = await p.evaluate(() => aiAsk('s', 'q').then((t) => 'ok:' + t, (e) => 'err:' + e.message));   // eslint-disable-line no-undef
    ok(/not connected on this server/.test(r1) && !/Unexpected token|JSON/.test(r1), 'HTML answer → said in words: ' + r1);
    // the AI Team review card itself (the reported screen)
    await p.evaluate(() => { try { setView('aiteam'); } catch (e) { /* redirected */ } });   // eslint-disable-line no-undef
    const r2 = await p.evaluate(async () => { try { await aiTeamRun('auditor'); } catch (e) { /* the card shows it */ } const o = (typeof AI_TEAM_OUT !== 'undefined' && AI_TEAM_OUT.auditor) || {}; return JSON.stringify(o).slice(0, 400); });   // eslint-disable-line no-undef
    ok(!/Unexpected token/.test(r2) && /not connected on this server/.test(r2), 'AI Auditor review: the clear message, not the JSON error: ' + r2);
    AI = 'json';
    const r3 = await p.evaluate(() => aiAsk('s', 'q').then((t) => 'ok:' + t, (e) => 'err:' + e.message));   // eslint-disable-line no-undef
    ok(r3 === 'ok:SYN answer', 'a real JSON /api/ai is passed through: ' + r3);
    await ctx.close();
    const c2 = await browser.newContext({ viewport: { width: 1366, height: 800 } }), q = await c2.newPage(); q.on('pageerror', (e) => errs.push(e.message));
    await q.goto(base + '/#aiteam'); await q.waitForTimeout(5000);
    const url = await q.evaluate(() => location.search);
    ok(/zybdash=ai-team\.html/.test(url), 'a refresh on #aiteam opens the live AI Engineering Team: ' + url);
    await c2.close();
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
