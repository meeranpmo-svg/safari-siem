// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal Admin Panel: "Refresh modules & pages" re-reads the organisation's choice and the page catalogue (zyb-nav.js, cache
// bypassed) and says what changed (a page added on the server shows as "a -> b", with Ctrl+F5 for the menu); the Backup tab reads the
// platform backup status (/api/soc/platform/backup - SYNTHETIC status), shows last / last good / off-site copy / next and the history
// (an error text stays text), an administrator runs a backup after confirming (POST queued, polled until a new run lands, "Backup finished"),
// a viewer has no run button, the backup service missing is said; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-adminpanel-backup.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
const NAVSRC = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8');
let WHO = { user: 'syed.syn', role: 'admin' }, ORG = { modules: null, resp: {}, updated: null }, EXTRA_PAGE = false, BACKUP = true, POSTS = 0;
const now = Date.now(), iso = (t) => new Date(t).toISOString();
let STATUS = { last: { at: iso(now - 3600000), ok: true, by: 'timer', size: 734003200, seconds: 412, remote: 'ok' }, last_ok_at: iso(now - 3600000), next: iso(now + 20 * 3600000), copies: 14, dest_bytes: 9663676416,
  config: { dest: '/var/backups/sentra', keep_days: 30, keep_min: 7, remote: 'backup@nas-syn:/backups', encrypted: true, events_days: 7, verify: true },
  history: [{ at: iso(now - 3600000), ok: true, by: 'timer', size: 734003200, seconds: 412, remote: 'ok' }, { at: iso(now - 90000000), ok: false, by: 'timer', size: 0, seconds: 3, remote: '', error: 'disk full <img src=x onerror="window.__xss=1">' }] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, WHO);
    if (u === '/auth/org') return json(200, ORG);
    if (u === '/api/soc/platform/backup') {
      if (!BACKUP) { res.writeHead(404, { 'Content-Type': 'text/html' }); return res.end('<html>not found</html>'); }
      if (req.method === 'POST') { POSTS++; setTimeout(() => { const run = { at: new Date().toISOString(), ok: true, by: WHO.user, size: 800000000, seconds: 300, remote: 'ok' }; STATUS = Object.assign({}, STATUS, { last: run, last_ok_at: run.at, history: [run].concat(STATUS.history) }); }, 1500); return json(200, { queued: true }); }
      return json(200, { status: STATUS, settings: null, queued: false });
    }
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(INDEX); }
    if (u === '/dashboards/vendor/zyb-nav.js' && EXTRA_PAGE) { res.writeHead(200, { 'Content-Type': 'application/javascript' }); return res.end(NAVSRC + '\n;(function(){var w=(window.ZYB_NAV||[])[0];if(w)w.pages.push({h:"synthetic-new-page.html",s:"Synthetic new page",t:"Synthetic new page"});})();'); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn, a) => p.waitForFunction(fn, a === undefined ? null : a, { timeout: 25000 }).then(() => true, () => false);
  const open = async () => { const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => d.accept());
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user && window.ZYB_NAV); await p.evaluate(() => setView('adminpanel')); await wait(p, () => /Pages available/i.test(document.body.innerText)); return p; };   // eslint-disable-line no-undef
  try {
    let p = await open();
    ok(await p.$('[data-ssa-refresh]') !== null, 'refresh button for the administrator');
    await p.click('[data-ssa-refresh]'); ok(await wait(p, () => /Modules and pages refreshed/.test(document.body.innerText) && /platform pages, unchanged/.test(document.body.innerText)), 'refresh says nothing changed');
    EXTRA_PAGE = true; await p.click('[data-ssa-refresh]');
    ok(await wait(p, () => /platform pages \d+ → \d+ - press Ctrl\+F5/.test(document.body.innerText)), 'a page added on the server is counted and Ctrl+F5 is named');
    ORG = { modules: ['core-dash', 'core-admin', 'siem-core'], resp: {}, updated: '2026-11-19T10:00:00Z', by: 'huda.syn' }; await p.click('[data-ssa-refresh]');
    ok(await wait(p, () => /changed meanwhile by huda\.syn/.test(document.body.innerText)), 'a subscription changed by another administrator is said');
    // backup
    await p.click('[data-ssa-tab="ap:backup"]');
    ok(await wait(p, () => document.querySelector('[data-ssa-bk]')), 'Backup tab drawn');
    const t = await p.evaluate(() => document.querySelector('.x').innerText);
    ok(/Last backup/i.test(t) && /OK/.test(t) && /700\.0 MB/.test(t) && /Copy off this server/i.test(t) && /copied/.test(t), 'last backup, size and off-site copy');
    ok(/Next backup/i.test(t) && /14 kept/.test(t) && /9\.0 GB/.test(t), 'next backup and what is kept');
    ok(/FAILED/.test(t) && /disk full/.test(t), 'a failed run in the history with its reason');
    ok(await p.evaluate(() => !window.__xss && /<img src=x/.test(document.querySelector('.x').innerText)), 'an error text stays text');
    ok(/Keep a copy of the encryption key off the server/.test(t) && !!(await p.$('a[href="/dashboards/platform.html"]')), 'key warning and the link to settings and restore');
    await p.click('[data-ssa-bkrun]');
    ok(await wait(p, () => /queued or running/.test(document.body.innerText)), 'requested: the page says it is running'); ok(POSTS === 1, 'one POST');
    ok(await wait(p, () => /Backup finished/.test(document.body.innerText)) || await wait(p, () => /syed\.syn/.test(document.querySelector('.x').innerText)), 'the new run lands and is shown');
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open(); await p.click('[data-ssa-tab="ap:backup"]'); await wait(p, () => document.querySelector('[data-ssa-bk]'));
    ok(!(await p.$('[data-ssa-bkrun]')), 'a viewer sees the status, no run button'); ok(await p.$('[data-ssa-refresh]') !== null, 'a viewer can refresh');
    BACKUP = false; WHO = { user: 'syed.syn', role: 'admin' }; p = await open(); await p.click('[data-ssa-tab="ap:backup"]');
    ok(await wait(p, () => /backup service is not answering/.test(document.body.innerText)), 'backup service missing is said');
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } catch (x) { console.error(x); bad++; } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'portal-adminpanel-backup: FAIL ' : 'portal-adminpanel-backup: OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
