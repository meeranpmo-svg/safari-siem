// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Pipeline Health (pipeline-health.html) against the REAL SIEM canary (sentra-siem engine/ops/canary.js) running through
// the real parser, pipeline, detector and alert store with an in-memory event store, and a SYNTHETIC IT Asset Management watcher: the
// status banner (healthy after a run, failing when the detector is taken out, naming the stage), the four stages timed, 24 h of runs
// labelled, the stage counters, the assurance chain linking the other checks, the watcher's view and its raised incident, "Run the
// canary now" for an operator, settings for an administrator, a viewer reads but cannot run, the SIEM not answering said plainly,
// the menu entry, phone width, no page errors.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pipeline-health.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const K = require(path.join(SIEM, 'engine/ops/canary'));
const { createParser } = require(path.join(SIEM, 'engine/parse'));
const { createPipeline } = require(path.join(SIEM, 'engine/pipeline'));
const { createDetector } = require(path.join(SIEM, 'engine/detect/engine'));
const { loadBuiltinRules } = require(path.join(SIEM, 'engine/detect/ruleset'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, every() {}, child() { return quiet; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph-'));
  const state = createState({ dir, log: quiet }), alerts = createAlerts({ state, log: quiet });
  const parser = createParser({ log: quiet, config: {} }), pipeline = createPipeline({ log: quiet });
  const detector = await createDetector({ rules: loadBuiltinRules(path.join(SIEM, 'engine/detect/rules')), now: Date.now, onAlert: (a) => alerts.raise(a), log: quiet });
  let detectOn = true, CLK = Date.now(); const stored = [];
  pipeline.use((ev) => { if (detectOn) detector.onEvent(ev); }, 'detect'); pipeline.use((ev) => { stored.push(ev); }, 'store');
  const search = { search: async (q) => { const id = (q.q.match(/"(CNY-[^"]+)"/) || [])[1]; return { rows: stored.filter((e) => e.fields && e.fields.canary_run === id).slice(0, 1) }; } };
  const deps = { state, alerts, parser, pipeline, search, config: { canary: { alert_within_s: 60 } }, log: quiet, noTimers: true, pollMs: 1, now: () => CLK, sleep: async () => { CLK += 5000; } };
  const api = fakeApi({ realRanks: true }); K.register(api, deps);
  await deps.canary.run('system:canary');   // one healthy run before the page opens
  let WHO = { user: 'nora.syn', role: 'operator' }, SIEM_UP = true, WATCH = { at: new Date().toISOString(), reachable: true, consecutive_failures: 0, error: null, last_ok_at: new Date().toISOString(), signals: [], note: 'Read every 5 minutes by IT Asset Management, a separate service.' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname === '/api/itam/pipeline-health') return json(200, WATCH);
    if (u.pathname.startsWith('/api/soc/')) { if (!SIEM_UP) return json(502, { error: 'bad gateway' }); let b = ''; req.on('data', (c) => (b += c)); req.on('end', async () => { const r = await api.call(req.method, u.pathname + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/pipeline-health.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 20000 }).then(() => true, () => false);
  const T = (p, id) => p.textContent('#' + id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => /^Healthy/.test(document.getElementById('stt').textContent)), 'healthy after a passing run');
    ok(/every run in 24 h passed/.test(await T(p, 'why')), 'why it is healthy');
    const fl = await T(p, 'flow'); ok(/✔ Parse/.test(fl) && /✔ Pipeline/.test(fl) && /✔ Alert/.test(fl) && /✔ Store/.test(fl) && /\d+ ms/.test(fl), 'four stages, each timed: ' + fl.slice(0, 160));
    ok(/100%/.test(await T(p, 'kpis')) && /1 of 1 runs/.test(await T(p, 'kpis')), 'runs passed KPI');
    ok(/1 runs, 0 failed/.test(await p.getAttribute('#hist', 'aria-label')), '24 h of runs labelled');
    ok(/detect/.test(await T(p, 'stages')) && /store/.test(await T(p, 'stages')), 'stage counters');
    ok(await p.$('a[href="log-assurance.html"]') && await p.$('a[href="soc-sources.html"]') && await p.$('a[href="detection-validation.html"]') && await p.$('a[href="notify-center.html"]'), 'the assurance chain links every check');
    ok(/SIEM answering\s*yes/.test(await T(p, 'watch')) && /Nothing raised/.test(await T(p, 'watch')), 'the independent watcher');
    ok(!(await p.$('#setw:not([hidden])')), 'an operator sees no settings');
    // take the detector out: the next run fails at "alert" and the page says so
    detectOn = false;
    await p.click('#runnow');
    ok(await wait(p, () => /^Failing/.test(document.getElementById('stt').textContent)), 'failing after the detector is taken out');
    ok(/failed at "alert"/.test(await T(p, 'why')) && /✖ Alert/.test(await T(p, 'flow')) && /raised no alert within 60 s/.test(await T(p, 'flow')), 'the failing stage named');
    ok(await wait(p, () => /Canary FAILED at alert/.test(document.body.innerText)), 'the run result toast');
    ok(/1 failed of 2/.test(await T(p, 'histn')), 'history counts the failure');
    // the watcher has raised it
    WATCH = Object.assign({}, WATCH, { signals: [{ title: 'SIEM pipeline failing at "alert"', severity: 4, text: 'synthetic' }] });
    await p.click('#refresh'); ok(await wait(p, () => /SIEM pipeline failing at "alert"/.test(document.getElementById('watch').textContent)), 'the watcher shows the platform incident it raised');
    // admin settings
    WHO = { user: 'syed', role: 'admin' }; await p.reload(); ok(await wait(p, () => !document.getElementById('setw').hidden), 'admin sees settings');
    await p.fill('#setf [name=every_min]', '10'); await p.click('#setf [type=submit]');
    ok(await wait(p, () => /Checked every\s*10 min/.test(document.getElementById('kpis').textContent)), 'settings saved');
    ok(api.audits.some((a) => a.action === 'ops.canary.settings' && a.user === 'syed') && api.audits.some((a) => a.action === 'ops.canary.run' && a.user === 'nora.syn'), 'run and settings audited in the person\'s name');
    // viewer and SIEM down
    WHO = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 1300, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base); await wait(v, () => /^Failing/.test(document.getElementById('stt').textContent));
    ok(await v.evaluate(() => document.getElementById('runnow').hidden && document.getElementById('setw').hidden), 'a viewer reads but cannot run or change');
    SIEM_UP = false; await v.click('#refresh');
    ok(await wait(v, () => /The SIEM did not answer/.test(document.getElementById('stt').textContent) && /independent watcher below raises this/.test(document.getElementById('why').textContent)), 'the SIEM not answering is said plainly');
    await v.close(); SIEM_UP = true;
    const nav = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "pipeline-health.html"/.test(nav) && /pipeline-health\.html/.test(inst), 'in the menu and the installer');
    WHO = { user: 'nora.syn', role: 'operator' };
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base); await wait(ph, () => !/Reading/.test(document.getElementById('stt').textContent));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    if (process.env.SHOT) { await p.screenshot({ path: process.env.SHOT + '-pipeline.png', fullPage: true }); }
  } finally { await browser.close(); srv.close(); alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
