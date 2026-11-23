// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal (repos/live/portal) Infrastructure Automation module with its AI / ML tab. /api/infra/* is stubbed with
// SYNTHETIC targets; /api/itam/infra-intel is the REAL engine (engine/infra-intel.js) fed the same synthetic sentra-infra data: the
// overview's AI / ML insights card (ring, chips, top actions); the AI / ML tab (health and its points, ranked actions, risk with the
// points, a target opens its drawer, capacity forecast, flapping, noisy rule, response times, incidents per day, coverage); a hostile
// target name stays text; the advisor off until allowed, a viewer told it is for operators; the engine not installed is said;
// one menu entry (AI / ML is a tab inside Infrastructure Automation) and the Automate next list; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-infra-ai.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
const I = require('../../backend/itam/engine/infra-intel');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'nora.syn', role: 'operator' }, INTEL = true;
const H = 3600000, D = 86400000, NOW = Date.now(), iso = (t) => new Date(t).toISOString();
const XSS = '<img src=x onerror="window.__xss=1">';
const targets = [{ id: 't1', kind: 'host', name: 'app-syn-01', status: 'ok', enabled: true, last_seen: iso(NOW - 60000), open_findings: 1 }, { id: 't2', kind: 'host', name: XSS, status: 'ok', enabled: true, last_seen: iso(NOW - 6 * H) }, { id: 't3', kind: 'device', name: 'sw-syn-03', status: 'never', enabled: true }];
const hist = []; for (let h = 72; h >= 0; h -= 6) hist.push({ at: iso(NOW - h * H), disk_max_pct: 76 + (72 - h) / 24 * 3 });
const findings = [{ id: 'f0', target_id: 't1', rule: 'disk', subject: '/var', severity: 'critical', title: 'Disk almost full', status: 'open', first_seen: iso(NOW - H), value: 85 }];
for (let k = 0; k < 6; k++) findings.push({ id: 'l' + k, target_id: 't1', rule: 'load_high', subject: '', severity: 'warning', title: 'Load high', status: 'cleared', first_seen: iso(NOW - k * D - H) });
const incidents = []; for (let k = 0; k < 6; k++) incidents.push({ id: 'n' + k, target_id: 't1', title: 'Load high', severity: 'warning', status: 'resolved', resolution: 'auto', opened_at: iso(NOW - k * D - H), resolved_at: iso(NOW - k * D - H + 300000) });
const summary = { generated_at: iso(NOW), targets: { total: 3, enabled: 3, by_kind: { host: 2, device: 1, db: 0 }, by_status: { ok: 2, never: 1 } }, findings: { open: 1, critical: 1, warning: 0, info: 0 }, incidents: { open: 0, acknowledged: 0, resolved_24h: 1 }, probes: { total: 1, online: 1, stale: 0 }, fingerprints_pending: 0, configs: { devices_with_baseline: 0, drift: 0 }, ai: { provider: 'none', state: 'off' }, top_findings: [], recent_incidents: [], hosts: [] };
const infra = (p) => { if (p === '/health') return { ok: true, service: 'sentra-infra' }; if (p === '/summary') return summary; if (p === '/targets') return { targets }; if (p.startsWith('/findings')) return { findings }; if (p.startsWith('/incidents')) return { incidents }; if (p === '/probes') return { probes: [{ id: 'p1', online: true, last_seen: iso(NOW) }] };
  const m = p.match(/^\/hosts\/(.+)$/); if (m) return { target: targets.find((t) => t.id === m[1]) || targets[0], history: m[1] === 't1' ? { points: hist } : { points: [] }, findings: [], incidents: [], latest: null }; return null; };
const app = { store: { collection: () => ({ get: () => null, put() {}, all: () => [], remove() {} }) }, addons: { infraSync: { get: async (p) => infra(p.split('?')[0]) } }, log: { info() {}, warn() {}, every() {} }, config: {} };
const X = I.createInfraIntel(app, { noTimer: true });
(async () => {
  const srv = http.createServer(async (req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, WHO);
    if (u === '/api/itam/infra-intel') { if (!INTEL) { res.writeHead(404, { 'Content-Type': 'text/html' }); return res.end('<html>not found</html>'); } return json(200, await X.view(WHO)); }
    if (u.startsWith('/api/infra/')) { const r = infra(u.slice('/api/infra'.length)); return r ? json(200, r) : json(404, { error: 'not in this test' }); }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn, a) => p.waitForFunction(fn, a === undefined ? null : a, { timeout: 20000 }).then(() => true, () => false);
  const page = async () => { const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } }), p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); return p; };   // eslint-disable-line no-undef
  try {
    let p = await page();
    ok(await p.evaluate(() => !document.querySelector('li[data-view="infra-ai"]') && document.querySelectorAll('li[data-view="infra-overview"]').length === 1), 'one Infrastructure Automation menu entry - AI / ML is a tab inside it, not a second entry');
    await p.evaluate(() => setView('infra-overview'));   // eslint-disable-line no-undef
    ok(await wait(p, () => document.querySelector('[data-ainf-aicard] [data-ainf-ring]')), 'AI / ML insights card on the overview');
    const card = await p.evaluate(() => document.querySelector('[data-ainf-aicard]').innerText);
    ok(/Full within 14 days: 1/.test(card) && /Recurring: 1/.test(card) && /Noisy rules: 1/.test(card), 'chips: ' + card.slice(0, 200)); ok(/app-syn-01/.test(card), 'top actions');
    ok(/Automate next/.test(card) && await p.evaluate(() => document.querySelectorAll('[data-ainf-aicard] [data-ainf-auto]').length >= 1), 'Automate next: findings turned into automations, each opening where a person decides');
    await p.click('[data-ainf-aicard] [data-ainfgo="infra-ai"]');
    ok(await wait(p, () => /Capacity forecast/.test(document.body.innerText) && document.querySelector('[data-ainf-risk]')), 'AI / ML tab opens');
    const t = await p.evaluate(() => document.querySelector('[data-ainf-root]').innerText);
    ok(/Why this score/.test(t) && /open critical finding/.test(t), 'the index with its points');
    ok(/\+25 1 critical finding/.test(t), 'risk points itemised'); ok(/app-syn-01 · fullest disk/.test(t) && /\+3 % a day/.test(t), 'capacity forecast bar');
    ok(/flapping/.test(t) && /self-clearing/.test(t), 'flapping and noisy rule'); ok(/MTTA before/i.test(t) && /Incidents per day/i.test(t), 'response times and the chart');
    ok(/never polled/.test(t) && /no result for 6 h/.test(t), 'coverage gaps');
    ok(await p.evaluate(() => !window.__xss && /<img src=x/.test(document.querySelector('[data-ainf-root]').innerText)), 'a hostile target name stays text');
    ok(/Not available/.test(t), 'advisor off until allowed');
    await p.click('[data-ainf-risk="t1"] a[data-ainfopen]');
    ok(await wait(p, () => typeof currentView !== 'undefined' && currentView === 'infra-hosts'), 'a target opens its drawer on Hosts');   // eslint-disable-line no-undef
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await page(); await p.evaluate(() => setView('infra-ai'));   // eslint-disable-line no-undef
    ok(await wait(p, () => /for operators and administrators/.test(document.body.innerText)), 'a viewer reads; the advisor is for operators');
    INTEL = false; WHO = { user: 'nora.syn', role: 'operator' }; p = await page(); await p.evaluate(() => setView('infra-ai'));   // eslint-disable-line no-undef
    ok(await wait(p, () => /not installed yet/.test(document.body.innerText)), 'engine not installed is said');
    ok(await p.evaluate(() => !document.querySelector('[data-ainf-risk]')), 'no figures without the engine');
    await p.evaluate(() => setView('infra-overview'));   // eslint-disable-line no-undef
    ok(await wait(p, () => /Targets by type/.test(document.body.innerText)), 'the overview still works without the engine');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } catch (x) { console.error(x); bad++; } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'portal-infra-ai: FAIL ' : 'portal-infra-ai: OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
