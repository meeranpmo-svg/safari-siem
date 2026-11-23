// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// The portal's Home tiles (the REAL portal: repos/live/portal index.html + app.js, with our menu scripts) follow
// the feeds that answer after the page opened: the SIEM feed answering late turns "SIEM not connected" into the open
// offense count; with the old feed not configured, the figures come from this server's SIEM and say so; with no SIEM at
// all the tile stays honest. Synthetic data. Skips when the live copy is not in the repository.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-home-live.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let MODE = 'wazuh';
const WZ = { configured: true, updated: new Date().toISOString(), wazuh: { stats: { total: 900, crit: 3, high: 9, byLevel: [{ key: 13, count: 3 }, { key: 9, count: 9 }], mitreTactics: [{ key: 'Initial Access', count: 4 }], topRules: [{ key: 'Brute force SYN', count: 40 }, { key: 'Malware SYN', count: 12 }], topAgents: [{ key: 'srv-syn-1', count: 30 }], compliance: {} }, agents: [], recentAlerts: [], vulnerabilities: { total: 0 } } };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u === '/api/wazuh') { if (MODE === 'wazuh') return setTimeout(() => json(200, WZ), 2500); return json(200, { configured: false }); }   // answers after Home was drawn
    if (u === '/api/soc/alerts') return MODE === 'siem' ? json(200, { items: [{ id: 'A1', severity: 4, rule_name: 'Ransomware SYN', host: 'srv-syn-2', count: 2 }, { id: 'A2', severity: 3, rule_name: 'Brute force SYN', host: 'srv-syn-3' }, { id: 'A3', severity: 2, rule_name: 'Port scan SYN' }] }) : json(404, {});
    if (u === '/api/soc/onboard/sources') return MODE === 'siem' ? json(200, { sources: [{ id: 's1', label: 'Firewall SYN', state: 'receiving', match_ip: '10.0.0.1' }] }) : json(404, {});
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const tiles = async (p) => p.evaluate(() => [...document.querySelectorAll('.zhome .zh-kpis .zk')].map((k) => k.innerText.replace(/\s+/g, ' ')));
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    await p.goto('http://127.0.0.1:' + srv.address().port + '/'); await p.waitForTimeout(400);
    await p.evaluate(() => { try { if (typeof currentView !== 'undefined' && currentView !== 'home') setView('home'); } catch (e) { /* home is the default */ } });   // eslint-disable-line no-undef
    await p.waitForSelector('.zhome .zh-kpis .zk', { timeout: 20000 }); return { p, errs }; };
  try {
    MODE = 'wazuh'; let { p, errs } = await open();
    const before = (await tiles(p))[0] || '';
    await p.waitForFunction(() => /\d/.test((document.querySelector('.zhome .zh-kpis .zk .zk-v') || {}).textContent || ''), null, { timeout: 30000 }).catch(() => {});
    const t = await tiles(p);
    ok(/SIEM not connected/.test(before) || /\d/.test(before), 'Home first drawn before the feed answered: ' + before);
    ok(/OPEN OFFENSES \d+/i.test(t[0]) && !/not connected/i.test(t[0]), 'the late SIEM feed reaches the Open Offenses tile: ' + t[0]);
    ok(!/No feeds configured/.test(t[3] || ''), 'Coverage counts the portal feeds once they are known: ' + t[3]);
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | ')); await p.close();

    MODE = 'siem'; ({ p, errs } = await open());
    await p.waitForFunction(() => new RegExp(ZYB_ORG.short + ' SIEM|critical need action').test((document.querySelector('.zhome .zh-kpis') || {}).textContent || ''), null, { timeout: 30000 }).catch(() => {});
    const a = await tiles(p);
    ok(/OPEN OFFENSES 3\b/i.test(a[0]) && /1 critical need action/.test(a[0]), 'old feed not configured: open / critical from this server\'s SIEM: ' + a[0]);
    ok(!/LogRhythm/.test(a.join(' ')), 'not labelled LogRhythm when the figures come from this server\'s SIEM');
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | ')); await p.close();

    MODE = 'none'; ({ p, errs } = await open()); await p.waitForTimeout(6000);
    ok(/SIEM not connected/.test((await tiles(p))[0]), 'no SIEM at all: still says not connected (nothing invented)');
    await p.close();
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
