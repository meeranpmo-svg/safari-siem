// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/oracle-tuning.html: the SIEM's real tuning module (engine/db-audit/tuning.js, fake
// state + a fake Claude) and Top SQL stub behind /api/soc, the real IT Asset Management db-health (stub Oracle helper)
// behind /api/itam. Checks findings with their scripts, GoldenGate and statistics tabs, Top SQL -> live plan -> Ask the AI
// -> a recommendation with fix / rollback / check, the approval trail (four eyes, done with a note), the Diagnostics Pack
// switch (admin, reason required) and the viewer / operator gates.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node oracle-tuning.test.js
const http = require('http'), fs = require('fs'), path = require('path'), assert = require('assert/strict');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const H = require(path.join(ITAM, 'tests/helpers.js'));
const { createTuning } = require(path.join(SIEM, 'engine/db-audit/tuning.js'));
let WHO = { user: 'siva', role: 'operator' };
const NOW = Date.now();
let QS = new URLSearchParams();   // the query of the request being answered (the stub router sees the path only)

(async () => {
  // SIEM side
  const cols = {}; const state = { collection: (n) => { const m = cols[n] || (cols[n] = new Map()); return { get: (id) => m.get(id) || null, put: (r) => m.set(r.id, JSON.parse(JSON.stringify(r))), all: (f) => [...m.values()].filter((x) => !f || f(x)) }; } };
  const aiSeen = [];
  const sdk = function () { return { messages: { create: async (p) => { aiSeen.push(p); return { model: 'claude-opus-5-5', content: [{ type: 'text', text: JSON.stringify({ title: 'Pin the previous plan for a1b2c3d4e5f6g', problem: 'Plan 2222 does a full scan of ORDERS', evidence: ['TABLE ACCESS FULL ORDERS in the plan'], recommendation: 'Load plan 1111 as a SQL plan baseline', fix_sql: "DECLARE n PLS_INTEGER; BEGIN n := DBMS_SPM.LOAD_PLANS_FROM_CURSOR_CACHE(sql_id => 'a1b2c3d4e5f6g', plan_hash_value => 1111); END;", rollback_sql: 'DROP_SQL_PLAN_BASELINE (see check)', verify_sql: "SELECT plan_name FROM dba_sql_plan_baselines", risk: 'low', needs_change_window: false, expected_benefit: '40 ms -> 4 ms per execution', confidence: 'high', references: ['performance/explain-plan#identifying-bad-plans', 'performance/made-up#x'] }) }] }; } } }; };
  const T = createTuning({ state, config: { secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic' } } }, now: () => NOW, sdk });
  const ev = (action, f) => ({ src_type: 'oracle-health', action, ts: NOW - 60000, host: 'eskauat', fields: Object.assign({ instance: 'ESS' }, f) });
  T.stage(ev('gg-apply', { key: 'RPROD', status: 'ABORTED', error: 'ORA-01403: no data found' }));
  T.stage(ev('gg-capture', { key: 'EPROD', status: 'ENABLED', state: 'CAPTURING CHANGES', lag_s: '12' }));
  T.stage(ev('plan-change', { key: 'a1b2c3d4e5f6g', sql_id: 'a1b2c3d4e5f6g', old_plan: '1111', new_plan: '2222', old_ms_exec: '4', new_ms_exec: '40', ratio: '10' }));
  T.stage(ev('stale-statistics', { key: 'APP.ORDERS', owner: 'APP', table_name: 'ORDERS', num_rows: '5000000' }));
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const topsql = { instances: [], sql_text_visible: true, sql: [{ sql_id: 'a1b2c3d4e5f6g', plan_hash: '2222', plan_count: 2, plans: [{ plan_hash: '2222', executions: 60, elapsed_us: 2400000 }, { plan_hash: '1111', executions: 100, elapsed_us: 400000 }], executions: 160, elapsed_s: 2.8, cpu_s: 1.1, ela_ms_exec: 17.5, gets_exec: 4100, reads_exec: 3.2, module: 'ERP', user: 'APP', plan_change: { old_plan: '1111', new_plan: '2222', ratio: 10, worse: true }, sql_text: "select * from orders where customer_id = :n" }] };
  async function siem(method, u, body) {
    const need = (r) => { if (RANK[WHO.role] < RANK[r]) throw Object.assign(new Error('requires role ' + r), { code: 403 }); };
    if (method === 'GET' && u.split('?')[0] === '/api/soc/db/oracle/tuning') { need('analyst'); return T.view({ instance: 'ESS' }); }
    if (method === 'GET' && u.split('?')[0] === '/api/soc/db/oracle/tuning/intel') { need('analyst'); const v = await T.view({ instance: 'ESS' }), D = 864e5, LATER = NOW + 3 * D, pts = [];
      for (let t = NOW - 6 * D; t < LATER; t += 6 * 36e5) pts.push({ ts: t, executions: 40, ela_ms_exec: t < NOW ? 40 : 5 });
      return require(path.join(SIEM, 'engine/db-audit/tuning-intel.js')).analyse({ view: v, sql7d: { period_s: 604800, sql_text_visible: true, sql: topsql.sql.map((q) => Object.assign({ elapsed_s: 900 }, q)) }, details: { a1b2c3d4e5f6g: { plans: [{ plan_hash: '1111', points: pts }] } }, now: LATER }); }
    if (method === 'GET' && u === '/api/soc/db/oracle/topsql') return topsql;
    if (method === 'GET' && u.split('?')[0] === '/api/soc/db/oracle/reference') { need('analyst'); return T.reference({ id: QS.get('id') || '' }); }
    if (method === 'POST' && u === '/api/soc/db/oracle/tuning/advise') { need('operator'); return T.advise(Object.assign({}, body, { user: WHO.user, role: WHO.role })); }
    if (method === 'POST' && u === '/api/soc/db/oracle/tuning/proposals') { need('operator'); return T.proposeFromFinding(body, { user: WHO.user, role: WHO.role }); }
    const m = /^\/api\/soc\/db\/oracle\/tuning\/(TUN-\d+)\/decide$/.exec(u);
    if (method === 'POST' && m) { need('operator'); return T.decide(m[1], body, { user: WHO.user, role: WHO.role }, { state }); }
    throw Object.assign(new Error('not in this test'), { code: 404 });
  }
  // ITAM side
  const e = await H.startApp({ noAi: true });
  const helperCalls = [];
  const creds = [{ id: 'cr1', kind: 'db_login', label: 'oracle-ESS', target: { engine: 'oracle', port: 1521, service: 'ESS' }, _s: { username: 'zyb_monitor', password: 'Synthetic-1' } }];
  e.app.store.collection('db_health_targets').put({ id: 'odb_1', label: 'Eskauat', host: '192.168.9.30', port: 1521, service: 'ESS', cred_id: 'cr1', cred_label: 'oracle-ESS' });
  require(path.join(ITAM, 'engine/db-health')).registerDbHealth(e.app.srv, e.app, { discovery: { vault: { available: () => true, list: () => creds, get: (id) => creds.find((c) => c.id === id), open: (id) => { const c = creds.find((x) => x.id === id); return { target: c.target, secret: Object.assign({}, c._s), release() {} }; } } },
    invRun: async (r) => { helperCalls.push(r); return r.op === 'oracle_plan' ? { ok: true, found: true, lines: ['SQL_ID  a1b2c3d4e5f6g, child number 0', 'Plan hash value: 2222', '| Id | Operation         | Name   |', '|  1 |  TABLE ACCESS FULL| ORDERS |', '   1 - filter("CUSTOMER_ID"=:n)'] } : { ok: true, records: [], errors: [], sqlstats: [], tuning: true, version: '19.0.0.0.0' }; } });

  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; QS = new URL(req.url, 'http://x').searchParams;
    const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    if (u.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.startsWith('/api/soc/')) { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { siem(req.method, u, b ? JSON.parse(b) : {}).then((r) => json(200, r), (er) => json(er.code || 500, { error: er.message })); }); return; }
    if (u === '/') { res.writeHead(200); res.end('home'); return; }
    fs.readFile(path.join(DASH, u), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/oracle-tuning.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message)); page.on('console', (m) => { if (m.type() === 'error' && !/40[34]/.test(m.text())) errs.push(m.text()); });
  let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
  const open = async () => { await page.goto('about:blank'); await page.goto(base); await page.waitForSelector('#kk .t', { timeout: 15000 }); };

  await open();
  const fnd = await page.innerText('#find');
  ok(/Replicat RPROD is ABORTED/.test(fnd) && /10x slower after a plan change/.test(fnd) && /Stale optimizer statistics on APP.ORDERS/.test(fnd), 'findings: ' + fnd.slice(0, 300));
  ok(/LOAD_PLANS_FROM_CURSOR_CACHE/.test(await page.content()), 'the plan-baseline script is on the page');
  await page.click('[data-go="gg"]'); ok(/RPROD/.test(await page.innerText('#gg')) && /ABORTED/.test(await page.innerText('#gg')), 'GoldenGate tab');
  await page.click('#tabs [data-tab="stats"]'); ok(/APP.ORDERS/.test(await page.innerText('#stats')), 'statistics tab');
  // rule finding -> proposal
  await page.click('#tabs [data-tab="find"]'); await page.click('[data-prop="stats:APP.ORDERS"]'); await page.waitForTimeout(600);
  ok([...cols.ora_tuning.values()].some((p) => p.finding_key === 'stats:APP.ORDERS' && p.status === 'proposed'), 'sent for approval');
  // Top SQL -> plan -> AI
  await page.click('#tabs [data-tab="sql"]'); await page.waitForSelector('#sqlt tr[data-sqlopen]');
  ok(/10× slower/.test(await page.innerText('#sqlt')), 'plan change shown in Top SQL');
  await page.click('#sqlt tr[data-sqlopen]'); await page.click('#getplan'); await page.waitForSelector('#planbox pre');
  ok(/TABLE ACCESS FULL/.test(await page.innerText('#planbox')), 'live plan from the platform');
  ok(helperCalls.some((c) => c.op === 'oracle_plan' && c.sql_id === 'a1b2c3d4e5f6g'), 'plan read through IT Asset Management');
  await page.fill('#aiq', 'slow since Monday'); await page.click('#askai');
  await page.waitForFunction(() => /Recommendation TUN-/.test(document.body.innerText), null, { timeout: 15000 });
  ok(aiSeen.length === 1 && /TABLE ACCESS FULL/.test(aiSeen[0].messages[0].content) && /slow since Monday/.test(aiSeen[0].messages[0].content), 'the AI saw the plan and the question');
  await page.waitForSelector('#decbar'); ok(/DBMS_SPM.LOAD_PLANS_FROM_CURSOR_CACHE/.test(await page.innerText('#zd')), 'recommendation shows the change script');
  // the Oracle guide sections it drew on: sent as untrusted reference, cited ids only, opened from the recommendation
  ok(/<untrusted source="oracle-reference">/.test(aiSeen[0].messages[0].content) && /\[ref:performance\/explain-plan#/.test(aiSeen[0].messages[0].content), 'Oracle explain-plan guidance went with the question');
  ok(/Oracle guidance it drew on/.test(await page.innerText('#zd')) && !/made-up/.test(await page.innerText('#zd')), 'cited guide listed, an invented one dropped');
  await page.click('[data-oref="performance/explain-plan"]'); await page.waitForFunction(() => /Universal Permissive License/.test(document.getElementById('zd').innerText), null, { timeout: 8000 });
  ok(/Identifying Bad Plans/i.test(await page.innerText('#zd')) && (await page.$('#zd .hl')) !== null, 'the guide opens at the cited section, licence shown');
  await page.evaluate(() => window.zybDetail.close()); await page.click('[data-rec="' + [...cols.ora_tuning.values()].find((p) => p.source === 'ai').id + '"]'); await page.waitForSelector('#decbar');
  // four eyes: siva asked -> siva cannot approve
  await page.click('[data-dec="approve"]'); await page.fill('#dn', 'ok'); await page.click('#dok'); await page.waitForTimeout(500);
  ok(/four eyes|named approver/.test(await page.innerText('body')), 'the requester cannot approve');
  // admin approves, operator records done
  WHO = { user: 'syed', role: 'admin' }; await open(); await page.click('#tabs [data-tab="recs"]');
  const aiId = [...cols.ora_tuning.values()].find((p) => p.source === 'ai').id;
  await page.click('tr[data-rec="' + aiId + '"]'); await page.click('[data-dec="approve"]'); await page.click('#dok'); await page.waitForTimeout(500);
  ok(cols.ora_tuning.get(aiId).status === 'approved' && cols.ora_tuning.get(aiId).approve_by === 'syed', 'approved by the admin');
  await page.click('tr[data-rec="' + aiId + '"]'); await page.click('[data-dec="done"]'); await page.fill('#dn', 'baseline loaded 21:05, 4 ms/exec'); await page.click('#dok'); await page.waitForTimeout(500);
  ok(cols.ora_tuning.get(aiId).status === 'done' && /21:05/.test(cols.ora_tuning.get(aiId).done_note), 'done with what was run');
  // ✦ AI / ML: the done recommendation is measured from the SQL timings, the findings are ranked
  await page.click('#tabs [data-tab="ai"]');
  ok(await page.waitForFunction(() => /Did each fix work/.test((document.getElementById('tai') || {}).innerText || ''), null, { timeout: 15000 }).then(() => true, () => false), 'AI / ML tab drawn');
  const tai = await page.innerText('#tai');
  ok(/IMPROVED/.test(tai) && /8x faster per execution \(40 -> 5 ms\)/.test(tai), 'the done fix verified from the timings: ' + tai.slice(0, 200));
  ok(await page.$('#tai svg rect') && /DB time saved a day/i.test(tai), 'before / after bars and the DB time saved');
  ok(/Tune next/.test(tai) && /a1b2c3d4e5f6g is 10x slower|Stale optimizer statistics/.test(tai), 'findings ranked');
  ok(/What works here/.test(tai) && /\d+%/.test(tai), 'success learned per kind of fix');
    // Diagnostics Pack switch: admin, reason required
  await page.click('#tabs [data-tab="set"]'); await page.click('#packon'); await page.click('#pok'); await page.waitForTimeout(400);
  ok(/who confirmed/.test(await page.innerText('body')), 'a reason is required');
  await page.fill('#pn', 'CSI 1234567 confirmed by procurement'); await page.click('#pok'); await page.waitForTimeout(800);
  ok(/ON/.test(await page.innerText('#pack')) && /syed/.test(await page.innerText('#pack')), 'switched on, by whom shown');
  // viewer
  WHO = { user: 'guest', role: 'viewer' }; await page.goto('about:blank'); await page.goto(base); await page.waitForTimeout(1500);
  ok(/analyst role/.test(await page.innerText('#kk')), 'viewer told the role needed');
  ok(errs.length === 0, 'errors: ' + errs.join(' | '));
  console.log('OK', n, 'checks');
  await browser.close(); srv.close(); await e.close(); process.exit(0);
})().catch((x) => { console.error('FAIL', x.message, (x.stack || '').split('\n').find((l) => /oracle-tuning\.test/.test(l))); process.exit(1); });
