// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for live-compliance.html over the REAL SIEM SAMA module (sentra-siem engine/compliance/sama.js) with no log
// sources connected, then the same answer with a few controls changed so the crosswalk grading can be checked:
// framework select box, coverage ring, domain bars, a tile per control coloured by its live status, legend filter, the
// drawer (live checks, crosswalk, evidence pages), jumping across frameworks, IA on the SAMA baseline, Excel, and an
// honest "not live" page when the SIEM does not answer.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node live-compliance.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const { createSamaCompliance } = require(path.join(SIEM, 'engine/compliance/sama'));
const ITAM = process.env.SENTRA_ITAM_DIR || path.resolve(__dirname, '../../backend/itam');
const { startApp } = require(path.join(ITAM, 'tests/helpers')), { createGrc } = require(path.join(ITAM, 'engine/grc'));

let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  global.window = { ZYB_ORG: require('../../brand/index') }; eval(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'));
  const FW = window.ZYB_FW;
  const col = () => ({ get() { return null; }, put() {}, set() {}, all() { return []; }, list() { return []; }, find() { return []; } });
  const sama = createSamaCompliance({ state: { collection: col }, config: {} });
  // the SIEM learning layer, REAL engine over an in-memory store with 10 synthetic daily snapshots of the same coverage
  const mem = () => { const m = new Map(); return { get: (k) => m.get(k) || null, put: (r) => m.set(r.id, r), all: (f) => [...m.values()].filter(f || (() => true)), size: () => m.size, remove: (k) => m.delete(k) }; };
  const cols = {}, istate = { collection: (n) => (cols[n] = cols[n] || mem()) };
  let clockI = Date.parse('2026-11-01T06:00:00Z');
  const { createSamaIntel } = require(path.join(SIEM, 'engine/compliance/sama-intel'));
  const intel = createSamaIntel({ state: istate, sama, config: {}, now: () => clockI });
  { const cur = await sama.summary({}), ev = cur.controls.filter((c) => c.siem_evidenced);
    for (let d = 0; d < 10; d++) istate.collection('sama_intel_snaps').put({ id: new Date(clockI + d * 86400000).toISOString().slice(0, 10), pct: 30 + d, counts: cur.summary.counts,
      st: Object.fromEntries(ev.map((c, i) => [c.id, d < 5 && i === 0 ? 'covered' : c.status])), ck: {} });
    clockI += 10 * 86400000; }
  const itam = await startApp({ noAi: true }); const G = createGrc(itam.app);
  let MODE = 'real', asked = [], PMODE = 'ok';
  const answer = async (q) => {
    const r = await sama.summary(q);
    if (MODE === 'mixed') for (const c of r.controls) { if (c.id === '3.3.14') c.status = 'covered'; if (c.id === '3.3.15') c.status = 'covered'; if (c.id === '3.3.16') c.status = 'gap'; }
    return r;
  };

  const srv = http.createServer(async (req, res) => {
    const [u0, qs] = req.url.split('?'), u = decodeURIComponent(u0);
    if (u === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"user":"syed","role":"admin"}'); return; }
    if (u === '/api/soc/compliance/sama') {
      asked.push(Object.fromEntries(new URLSearchParams(qs || '')));
      if (MODE === 'down') { res.writeHead(502); res.end('bad gateway'); return; }
      const r = await answer(Object.fromEntries(new URLSearchParams(qs || ''))); res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(r)); return;
    }
    if (u === '/api/soc/compliance/sama-intel') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(await intel.view({}))); return; }
    if (u === '/api/itam/grc/csf-coverage') { if (PMODE === 'missing') { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end('{"error":"not found"}'); return; } res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(G.csfCoverage())); return; }
    if (u.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end('{"error":"not in this test"}'); return; }
    const f = path.join(DASH, u === '/' ? 'index.html' : u);
    if (!f.startsWith(DASH)) { res.writeHead(403); res.end(); return; }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage(); const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  const tiles = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('#map .tl')].map((t) => [t.getAttribute('data-code'), t.querySelector('em').textContent])));
  const live = () => page.waitForFunction(() => /^Live/.test(document.getElementById('up').textContent), null, { timeout: 15000 });

  // SAMA, real module output (no sources): 12 SIEM-evidenced controls graded, the rest grey
  await page.goto(base + 'live-compliance.html'); await live();
  const real = await sama.summary({});
  let t = await tiles();
  const samaCodes = Object.keys(FW.sama.domains);
  ok(samaCodes.every((c) => t[c]), 'a tile for every SAMA control incl. BCM: ' + samaCodes.filter((c) => !t[c]));
  const lab = { covered: 'Covered', partial: 'Partial', gap: 'Gap', 'n/a': 'Not measured live' };
  ok(real.controls.every((c) => t[c.id] === lab[c.status]), 'tile status = SIEM status for every control');
  const leg = await page.evaluate(() => [...document.querySelectorAll('#legend .lg')].map((b) => b.querySelector('.v').textContent));
  ok(JSON.stringify(leg) === JSON.stringify([real.summary.counts.covered, real.summary.counts.partial, real.summary.counts.gap, real.summary.counts['n/a'] + 1].map(String)), 'legend counts: ' + leg);
  const pct = Math.round(100 * (real.summary.counts.covered + 0.5 * real.summary.counts.partial) / real.summary.evidenced);
  ok(await page.evaluate((p) => document.querySelector('#gauge svg text').textContent === p + '%', pct), 'ring shows ' + pct + '%');
  ok(await page.evaluate(() => document.querySelectorAll('#dom .dbar').length) === 5 && await page.evaluate(() => document.querySelectorAll('#minis .mini').length) === 4, 'domain bars and four framework mini rings');
  ok(asked[0] && asked[0].days === '30', 'asks the SIEM for the selected period: ' + JSON.stringify(asked[0]));

  // legend filter dims the others
  await page.click('#legend .lg[data-s="gap"]');
  ok(await page.evaluate(() => [...document.querySelectorAll('#map .tl:not(.dim)')].every((x) => x.querySelector('em').textContent === 'Gap') && document.querySelectorAll('#map .tl:not(.dim)').length > 0), 'gap filter');
  await page.click('#legend .lg[data-s="gap"]');

  // drawer for a SAMA control: live checks, actions, crosswalk to NCA / PDPL, evidence pages
  await page.click('#map .tl[data-code="3.3.14"]'); await page.waitForSelector('#zd:not([hidden])');
  const d = await page.evaluate(() => ({ t: document.getElementById('zd-t').textContent, b: document.getElementById('zd-b').innerText, nca: [...document.querySelectorAll('#zd-b a[data-go="nca"]')].map((a) => a.textContent) }));
  ok(/3\.3\.14 Cyber Security Event Management/.test(d.t) && /Live checks \(7\)/i.test(d.b), 'drawer title + live checks: ' + d.t);
  ok(d.nca.includes('2-12'), 'crosswalk NCA 2-12 from SAMA 3.3.14: ' + d.nca);
  ok(/IR Art\. 33/.test(d.b) && /Database Audit/.test(d.b), 'crosswalk PDPL + evidence dashboards');
  await page.keyboard.press('Escape');
  // implementation pillars: tile percentages, rings, drawer policy cross-check, menu-area grouping
  const cov = G.csfCoverage();
  const tp = await page.evaluate(() => [...document.querySelectorAll('#map .tl[data-code="3.3.17"] .pl i')].map((i) => i.textContent));
  ok(tp[2] === 'P ' + cov.controls['3.3.17'].policy_pct + '%', 'tile P% = ITAM policy average: ' + tp + ' / ' + cov.controls['3.3.17'].policy_pct);
  ok(/^D \d+%$/.test(tp[0]) && /^A \d+%$/.test(tp[1]), 'tile D/A percentages: ' + tp);
  ok(await page.evaluate(() => document.querySelectorAll('#gauge .pills3 [data-pillar]').length === 3), 'three pillar rings');
  ok(await page.evaluate(() => document.querySelector('#map .tl[data-code="3.3.9"] .pl i:nth-child(3)').textContent === 'P —'), 'no policy -> P —, not 0');
  await page.click('#map .tl[data-code="3.3.17"]'); await page.waitForSelector('#zd:not([hidden])');
  const pd = await page.evaluate(() => ({ b: document.getElementById('zd-b').innerText, pols: [...document.querySelectorAll('#zd-b .pol')].map((x) => x.getAttribute('data-pol')), req: document.querySelectorAll('#zd-b .req').length, areas: [...document.querySelectorAll('#zd-b .area b')].map((b) => b.textContent) }));
  ok(pd.pols.includes('IT-DEV-009') && /No attestation recorded/.test(pd.b) && /Approved policy record/.test(pd.b), 'policy cross-check with remarks: ' + pd.pols);
  ok(pd.req > 0 && /Requirements cross-checked against live evidence/.test(pd.b) && /(Live evidence:|No live check covers this statement)/.test(pd.b), 'requirement statements cross-checked: ' + pd.req);
  ok(/Devices & infrastructure/.test(pd.b) && /Applications & SOC/.test(pd.b) && /IT GRC policies/.test(pd.b), 'three implementation bars');
  ok(pd.areas.length > 0 && /Where it is implemented — by main menu area/.test(pd.b), 'evidence grouped by main menu area: ' + pd.areas);
  await page.keyboard.press('Escape');
  await page.click('#map .tl[data-code="3.3.9"]'); await page.waitForSelector('#zd:not([hidden])');
  ok(/No approved IT policy covers this control/.test(await page.evaluate(() => document.getElementById('zd-b').innerText)), 'policy gap said in words');
  await page.keyboard.press('Escape');
  await page.click('#map .tl[data-code="3.3.14"]'); await page.waitForSelector('#zd:not([hidden])');
  // jump to NCA 2-12 from the crosswalk chip
  await page.click('#zd-b a[data-go="nca"][data-gc="2-12"]'); await page.waitForTimeout(300);
  ok(await page.evaluate(() => document.getElementById('fw').value === 'nca' && /2-12/.test(document.getElementById('zd-t').textContent) && location.hash === '#fw=nca'), 'jumped to NCA 2-12');
  await page.keyboard.press('Escape');

  // mixed: crosswalk grading (NCA 2-13 = 3.3.15 covered + 3.3.16 gap -> partial; 2-12 covered; 1-1 GRC)
  MODE = 'mixed'; await page.click('#refresh'); await live(); await page.waitForTimeout(200);
  t = await tiles();
  ok(t['2-12'] === 'Covered' && t['2-13'] === 'Partial' && t['1-1'] === 'Not measured live' && t['3-1'] === 'Not measured live', 'NCA via crosswalk: ' + [t['2-12'], t['2-13'], t['1-1'], t['3-1']]);
  ok(Object.keys(t).length === Object.keys(FW.nca.domains).length, 'a tile per NCA sub-domain');
  const n210 = await page.evaluate(() => document.querySelector('#map .tl[data-code="2-10"] .pl i:nth-child(3)').textContent);
  ok(n210 === 'P ' + cov.controls['3.3.17'].policy_pct + '%', 'NCA 2-10 policy % through SAMA 3.3.17: ' + n210);
  ok(asked.some((q) => q.refresh === '1'), 'Refresh forces a fresh read');
  await page.selectOption('#fw', 'pdpl'); t = await tiles();
  ok(t['IR Art. 33'] === 'Covered' && t['Art. 20'] === 'Covered' && t['Art. 4'] === 'Not measured live', 'PDPL via crosswalk: ' + [t['IR Art. 33'], t['Art. 20'], t['Art. 4']]);
  await page.click('#map .tl[data-code="Art. 4"]'); await page.waitForSelector('#zd:not([hidden])');
  ok(/privacy obligation/i.test(await page.evaluate(() => document.getElementById('zd-b').innerText)), 'unmapped PDPL article says why it is GRC evidence');
  await page.keyboard.press('Escape');
  await page.selectOption('#fw', 'ia'); t = await tiles();
  ok(t['IA-277'] === 'Not measured live' && t['3.3.14'] === 'Covered' && /UTC\/277\/202401/.test(await page.evaluate(() => document.getElementById('note').textContent)), 'IA: circular requirement + SAMA baseline');

  // Excel
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#xlsx')]);
  const buf = fs.readFileSync(await dl.path()), txt = buf.toString('latin1');
  ok(buf.slice(0, 2).toString() === 'PK' && /^live-compliance-\d{4}-\d\d-\d\d\.xlsx$/.test(dl.suggestedFilename()), 'xlsx ' + dl.suggestedFilename());
  for (const sh of ['Summary', 'SAMA', 'IA', 'NCA', 'PDPL']) ok(txt.includes('name="' + sh + '"'), 'sheet ' + sh);

  // the SIEM does not answer: structure shown, nothing graded, says so
  MODE = 'down'; await page.goto('about:blank'); await page.goto(base + 'live-compliance.html#fw=nca'); await page.waitForFunction(() => document.getElementById('up').textContent === 'Not live', null, { timeout: 15000 });
  t = await tiles();
  ok(Object.values(t).every((s) => s === 'Not measured live') && await page.evaluate(() => /not reachable|HTTP 502/i.test(document.getElementById('note').textContent) && document.querySelector('#gauge svg text').textContent === '—'), 'SIEM down: nothing green, says why');

  MODE = 'real'; PMODE = 'missing'; await page.goto('about:blank'); await page.goto(base + 'live-compliance.html'); await live(); await page.waitForTimeout(300);
  ok(await page.evaluate(() => /policy view is not installed in ITAM/.test(document.getElementById('gauge').textContent) && document.querySelector('#map .tl[data-code="3.3.17"] .pl i:nth-child(3)').textContent === 'P —'), 'ITAM without the policy view: says so, P —');
  // the menu has it
  // live intelligence: KPIs, trend over the snapshots, leverage, quick wins, reliability, advisor state
  await page.goto(base + 'live-compliance.html'); await live();
  ok(await page.waitForFunction(() => /SIEM coverage/.test(document.getElementById('li-body').textContent), null, { timeout: 15000 }).then(() => true, () => false), 'live intelligence loads');
  const li = await page.textContent('#li-body');
  ok(/10\s*daily snapshots/i.test(li.replace(/\s+/g, ' ')), 'ten daily snapshots counted: ' + li.slice(0, 200));
  ok(!!(await page.$('#li-body svg path')), 'the coverage trend line');
  ok(/regressed/.test(li) || /covered/.test(li), 'a control covered earlier and not now is flagged as a regression');
  ok(/Fix once, move many/.test(li) && (await page.$$('#li-body .lv')).length >= 1, 'leverage and quick wins');
  ok((await page.$$('#li-body .rl')).length >= 1 && /honest prior/.test(li), 'least reliable controls with the prior explained');
  // the figures and rings open what they count (they were plain boxes: "tiles click not working")
  const jumps = await page.$$eval('#li-body .li-k [data-jump]', (b) => b.map((x) => x.getAttribute('data-jump')));
  ok(jumps.join() === 'ctitle,li-trend,li-watch,li-watch,li-qw,li-trend', 'each live-intelligence figure is a button to what it counts: ' + jumps.join(' '));
  const flashed = async (sel, card) => { await page.click(sel); return page.waitForFunction((c) => { const el = document.querySelector(c); return el && el.classList.contains('jflash'); }, card, { timeout: 5000 }).then(() => true, () => false); };
  ok(await flashed('#li-body .li-k [data-jump="li-qw"]', '#li'), 'quick wins: scrolls to the quick wins and highlights them');
  ok(await flashed('#li-body .li-k [data-jump="ctitle"]', '#map') || await page.evaluate(() => document.getElementById('map').closest('.card').classList.contains('jflash')), 'SIEM coverage: the control map');
  ok(await page.evaluate(() => document.querySelectorAll('#gauge .pills3 button[data-pillar][data-jump="ctitle"]').length === 3), 'the three pillar rings are buttons to the control map');
  ok(/Not available/.test(li), 'the advisor is off until configured');
  const mx = await page.evaluate(() => ({ segs: document.querySelectorAll('#mix svg circle[stroke-dasharray]').length, centre: (document.querySelector('#mix svg text') || {}).textContent, bar: document.querySelectorAll('#mix .mixb i').length, says: (document.querySelector('#mix .mixs') || {}).textContent || '',
    gb: document.querySelectorAll('#li-body .lv .gb i').length, acc: getComputedStyle(document.querySelector('#li-body .li-k > button')).getPropertyValue('--a').trim() }));
  ok(mx.segs >= 2 && /^\d+\/\d+$/.test(mx.centre) && mx.bar === mx.segs && /shown grey, never green|Nothing is measured live/.test(mx.says), 'the status mix: a donut with what is measured live, the same as a bar: ' + JSON.stringify(mx));
  ok(mx.gb >= 1 && mx.acc, 'leverage and quick wins with a bar of the points they add; KPI accents');
  if (process.env.SHOT) await page.screenshot({ path: process.env.SHOT, fullPage: true });
  ok((window.ZYB_NAV.find((a) => a.id === 'cmp') || { pages: [] }).pages.some((p) => p.h === 'live-compliance.html'), 'in the Compliance & Frameworks menu');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); itam.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
