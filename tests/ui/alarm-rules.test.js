// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Alarm Inbox Rules (alarm-rules.html), stubbed SIEM, SYNTHETIC rules and alerts: KPI tiles filter the rule list; the next
// steps name their evidence; a rule opens in a FORM editor (not only JSON), the proposed exclusion goes into the draft,
// backtest replays the draft, save sends the edited rule; the AI assistant's draft is shown with its compile result and
// opens in the editor disabled; hostile rule names and alert text stay text; a viewer / operator is told the role; an
// engine without the route says to update; the old in-browser rules are listed for conversion, never run.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node alarm-rules.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'syed.syn', role: 'admin' }, ROUTE = true, SAVED = [], TESTS = [], ASKS = [];
const series = (last) => { const a = new Array(30).fill(0); a[29] = last; return a; };
const RULE = { id: 'SENTRA-AUTH-001', name: 'Brute force against one account', type: 'threshold', severity: 3, tactic: 'credential-access', mitre: ['T1110.001'], enabled: true,
  match: { all: [{ field: 'action', op: 'eq', value: 'logon-failed' }] }, group_by: ['user'], window_s: 300, count: 10, suppress_s: 3600, description: 'synthetic' };
const item = (o) => Object.assign({ type: 'threshold', severity: 2, tactic: 'credential-access', mitre: [], origin: 'builtin', enabled: true, health: 'healthy', flags: [], load_error: null, fires_30d: 0, fires_7d: 0, per_day_7d: 0, today: 0,
  series: series(0), burst_z: null, last_fired: null, closures: { tp: 0, fp: 0, benign: 0, open: 0, closed: 0 }, fp_rate: null, exclusion: null, tune_score: 0 }, o);
const INTEL = () => ({ at: Date.now(), window_days: 30, counts: { total: 3, enabled: 3, broken: 0, noisy: 1, 'fp-heavy': 1, silent: 1, burst: 1, healthy: 0, disabled: 0 },
  items: [item({ id: 'SENTRA-AUTH-001', name: 'Brute force against one account', severity: 3, health: 'fp-heavy', flags: ['fp-heavy', 'burst'], fires_30d: 12, fires_7d: 12, per_day_7d: 1.7, today: 9, series: series(9), burst_z: 6.1,
      closures: { tp: 1, fp: 5, benign: 1, open: 5, closed: 7 }, fp_rate: 71, exclusion: { field: 'user', op: 'eq', value: 'svc.backup.syn', covers: 5, of: 5, pct: 100 }, tune_score: 61 }),
    item({ id: 'CUS-NOISY-1', name: '<img src=x onerror=alert(1)>Noisy custom', origin: 'custom', health: 'noisy', flags: ['noisy'], fires_30d: 300, fires_7d: 140, per_day_7d: 20, series: series(20), tune_score: 40 }),
    item({ id: 'SENTRA-EXF-009', name: 'Large upload', tactic: 'exfiltration', health: 'silent', flags: ['silent'] })],
  coverage: [{ tactic: 'credential-access', rules: 2, fired: 1, state: 'covered' }, { tactic: 'exfiltration', rules: 1, fired: 0, state: 'quiet' }, { tactic: 'lateral-movement', rules: 0, fired: 0, state: 'gap' }],
  overlaps: [{ a: 'SENTRA-AUTH-001', a_name: 'Brute force against one account', b: 'CUS-NOISY-1', b_name: 'Noisy custom', shared: 4, of: 5, pct: 80 }], fires: series(29),
  next: [{ kind: 'exclude', rule: 'SENTRA-AUTH-001', name: 'Brute force against one account', why: '5 of 5 false-positive closures (100 %) were user = svc.backup.syn.', do: 'Review the proposed exclusion, backtest, then save.' },
    { kind: 'gap', rule: null, name: 'lateral-movement', why: 'No enabled rule covers this ATT&CK tactic.', do: 'Draft a rule with the AI assistant, backtest it, then save it.' }],
  model: { min_closures: 3, z_burst: 4, exclusion_share: 60, overlap_share: 50, noisy_per_day: 20 }, note: 'Exclusions and overlaps are proposals - nothing here changes a rule.', ai: { enabled: true } });
const RINTEL = () => Object.assign({}, INTEL().items[0], { recent: [{ id: 'ALR-1', created: Date.now(), status: 'closed-false-positive', severity: 3, summary: '</td><script>window.PWN=1</script> 12 failures', group: { user: 'svc.backup.syn' }, count: 12 }], overlaps: [] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', () => {
      const body = raw ? JSON.parse(raw) : {};
      if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, WHO);
      if (!ROUTE && u.startsWith('/api/soc/rules')) return json(404, { error: 'no route' });
      if (u === '/api/soc/rules/intel') return json(200, INTEL());
      if (u === '/api/soc/rules/intel/SENTRA-AUTH-001') return json(200, RINTEL());
      if (u === '/api/soc/rules/SENTRA-AUTH-001' && req.method === 'GET') return json(200, Object.assign({}, RULE, { origin: 'builtin', stats: {}, alerts_24h: 3 }));
      if (u === '/api/soc/rules/test' && req.method === 'POST') { if (WHO.role === 'viewer') return json(403, { error: 'requires operator role' }); TESTS.push(body);
        return json(200, { events_scanned: 420, total_alerts: 2, alerts: [{ ts_first: Date.now(), count: 11, group: { user: 'ali.syn' }, summary: '<b>x</b>' }] }); }
      if (u === '/api/soc/rules' && req.method === 'POST') { if (WHO.role !== 'admin') return json(403, { error: 'requires admin role' }); SAVED.push(body.rule); return json(200, { rule: Object.assign({}, body.rule, { version: 2 }), load_error: null }); }
      if (u === '/api/soc/rules/assist' && req.method === 'POST') { if (WHO.role === 'viewer') return json(403, { error: 'requires operator role' }); ASKS.push(body);
        return json(200, { ok: true, label: 'AI draft - verify, backtest, then an administrator saves it', mode: body.mode, compile_error: null, why: 'Remote service creation <img src=x onerror=alert(2)>', noise_risk: 'admin jump hosts', test_hint: 'replay 7 days',
          rule: { id: 'AI-LAT-1', name: 'PsExec-style service install', type: 'single', severity: 3, tactic: 'lateral-movement', enabled: false, match: { all: [{ field: 'event_code', op: 'eq', value: '7045' }] } }, duplicates: [] }); }
      if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
      const f = path.join(DASH, u.replace(/^\/dashboards\//, '/'));
      if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
      fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/alarm-rules.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const open = async (pre) => { const p = await browser.newPage({ viewport: { width: 1440, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    if (pre) await p.addInitScript(pre); await p.goto(base); await p.waitForSelector('#kk .t', { timeout: 15000 }); return p; };
  try {
    let p = await open();
    const tiles = await p.$$eval('#kk .t', (a) => a.map((t) => t.textContent.replace(/\s+/g, ' ').trim()));
    ok(tiles.length === 7 && /Mostly false positives\s*1/.test(tiles.join('|')) && /ATT&CK gaps\s*1/.test(tiles.join('|')), 'KPI tiles from the engine: ' + tiles.join(' | '));
    ok(/5 of 5 false-positive closures/.test(await p.textContent('#panel')), 'next steps name their evidence');
    ok(/3 closures/.test(await p.textContent('#model')), 'the model and its thresholds are stated');
    // a tile is a filter on the rule list
    await p.click('#kk .t[data-f="noisy"]');
    let names = await p.$$eval('#rtab tbody tr td:first-child b', (a) => a.map((x) => x.textContent));
    ok(names.length === 1 && /Noisy custom/.test(names[0]), 'Noisy tile filters the rule list: ' + names.join(','));
    ok(await p.evaluate(() => !document.querySelector('#rtab img')), 'a hostile rule name is text, not markup');
    await p.selectOption('#fh', ''); await p.fill('#q', 'brute');
    names = await p.$$eval('#rtab tbody tr td:first-child b', (a) => a.map((x) => x.textContent));
    ok(names.length === 1 && /Brute force/.test(names[0]), 'search keeps focus and filters: ' + names.join(','));
    ok(await p.evaluate(() => document.activeElement && document.activeElement.id === 'q'), 'the search box keeps focus while typing');
    // open in the form editor
    await p.click('#rtab tr.rr'); await p.waitForSelector('#ed.open #f-name');
    ok((await p.inputValue('#f-name')) === RULE.name && (await p.inputValue('#f-count')) === '10', 'the rule opens in a form (name, count)');
    ok(await p.evaluate(() => !window.PWN), 'a hostile alert summary in recent alerts does not run');
    ok(/svc\.backup\.syn/.test(await p.textContent('#ed')), 'the proposed exclusion is shown in the editor');
    await p.click('#edexcl');
    ok(/Exclusion added/.test(await p.textContent('#edm')), 'exclusion goes into the draft (not saved)');
    ok(SAVED.length === 0, 'nothing saved by proposing');
    await p.fill('#f-count', '15');
    await p.click('#edtest'); await p.waitForFunction(() => /would have been raised/.test(document.getElementById('edm').textContent));
    ok(TESTS.length === 1 && TESTS[0].rule.count === 15 && TESTS[0].rule.match.none[0].value === 'svc.backup.syn', 'backtest replays the edited draft: ' + JSON.stringify(TESTS[0] && TESTS[0].rule.match));
    ok(/2 alarm\(s\) would have been raised from 420/.test(await p.textContent('#edm')), 'backtest result in words');
    ok(TESTS[0].to - TESTS[0].from === 86400000, 'default window is 24 h');
    await p.click('#edjson'); const j = JSON.parse(await p.inputValue('#edj'));
    ok(j.count === 15 && j.match.none.length === 1, 'the JSON tab shows the same draft');
    await p.click('#edform');
    await p.click('#edsave'); await p.waitForFunction(() => /Saved as version 2/.test(document.getElementById('edm') ? document.getElementById('edm').textContent : ''), null, { timeout: 8000 }).catch(() => {});
    ok(SAVED.length === 1 && SAVED[0].count === 15 && SAVED[0].id === 'SENTRA-AUTH-001' && !('stats' in SAVED[0]), 'save sends the edited rule only: ' + JSON.stringify(SAVED[0] || {}).slice(0, 160));
    ok(/Saved as version 2/.test(await p.textContent('#edm')), 'save confirmed with the version');
    await p.keyboard.press('Escape');
    // ATT&CK coverage → draft with AI
    await p.click('#tabs button[data-t="cov"]');
    ok(/lateral-movement/.test(await p.textContent('#panel .cov .gap')), 'a gap tactic is red');
    await p.click('#panel .cov .gap [data-gap]');
    ok(/lateral-movement/.test(await p.inputValue('#aiq')), 'Draft with AI fills the request');
    await p.click('#aigo'); await p.waitForSelector('#aiedit');
    ok(ASKS.length === 1 && ASKS[0].mode === 'draft', 'the assistant was asked once, mode draft');
    ok(/compiles/.test(await p.textContent('#aiout')) && /administrator saves it/.test(await p.textContent('#aiout')), 'the draft shows its compile result and the label');
    ok(await p.evaluate(() => !document.querySelector('#aiout img')), 'model text is escaped');
    await p.click('#aiedit'); await p.waitForSelector('#ed.open #f-name');
    ok((await p.inputValue('#f-name')) === 'PsExec-style service install' && !(await p.isChecked('#f-en')), 'the AI draft opens in the editor, disabled');
    ok(/AI draft/.test(await p.textContent('#edm')), 'labelled an AI draft');
    await p.click('#edx');
    // the old browser rules: listed for conversion, never run
    await p.close();
    p = await open(() => { try { localStorage.setItem('alarm_rules_ash', JSON.stringify([{ id: 'AR-1', name: 'Built-in', builtin: true }, { id: 'AR-X', name: 'Hand-written <b>rule</b>', builtin: false, type: 'threshold', by: 'omar.syn', match: { cat: 'auth' } }])); } catch (e) { /* storage blocked */ } });
    await p.click('#tabs button[data-t="old"]');
    const old = await p.textContent('#panel');
    ok(/Hand-written <b>rule<\/b>/.test(old) && !/Built-in/.test(old.replace('built-in ones', '')), 'hand-written browser rules are listed (as text), starters are not');
    await p.click('[data-old="0"]');
    ok(/Convert this older portal rule/.test(await p.inputValue('#aiq')), 'Convert with AI fills the request with the old rule');
    await p.close();
    // operator: backtest yes, save no (said in words); viewer: told the role
    WHO = { user: 'omar.syn', role: 'operator' }; p = await open();
    await p.click('#tabs button[data-t="rules"]'); await p.click('#rtab tr.rr >> nth=0'); await p.waitForSelector('#ed.open #f-name');
    await p.click('#edsave'); await p.waitForFunction(() => /admin role/.test(document.getElementById('edm').textContent));
    ok(/Saving a rule needs the admin role/.test(await p.textContent('#edm')), 'operator told saving needs admin');
    await p.close();
    WHO = { user: 'v.syn', role: 'viewer' }; p = await open();
    await p.click('#tabs button[data-t="ai"]'); await p.fill('#aiq', 'x'); await p.click('#aigo'); await p.waitForFunction(() => /operator role/.test(document.getElementById('aiout').textContent));
    ok(/needs the operator role/.test(await p.textContent('#aiout')), 'viewer told the assistant needs operator');
    await p.close();
    // engine without the route
    ROUTE = false; p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(base); await p.waitForSelector('#panel .err');
    ok(/run the update/.test(await p.textContent('#panel')), 'an engine without the routes says to run the update');
    await p.close();
    ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
