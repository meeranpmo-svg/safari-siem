// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the After-hours mode tab on soc-intel.html, after the same static build the server runs: status tiles,
// what was paged tonight, acknowledging a paged alert from the e-mail link (ack + take ownership), the morning brief in a
// sandboxed frame, settings (rota lines → JSON), and a viewer who sees status but no names.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node afterhours-mode.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'ahmode-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });
const now = Date.now();
const CFG = { enabled: true, enabled_at: now - 864e5, page: { min_severity: 3, to: ['soc@as.example'], quiet_rules: [], max_per_hour: 20, escalate_after_min: 30, escalate_to: [] },
  oncall: [{ name: 'Week A', days: [0, 1], to: ['ali@as.example'] }], prepare: { mode: 'prepare', min_severity: 3, max_per_night: 10 }, brief: { enabled: true, at: '07:30', to: [] }, version: 4, updated: now, by: 'syed' };
const DATA = {
  '/api/soc/after-hours/mode/status': { enabled: true, enabled_at: now - 864e5, after_hours_now: true, reason: 'after-hours', prepare_mode: 'prepare', brief: { enabled: true, at: '07:30' },
    tonight: { night: '2026-10-21', recipients: 2, rota: ['Week A'], handled: 3, paged: 2, failed: 0, held: 1, prepared: 1, unacknowledged: 1 }, mail: { ok: true, problems: [] }, last_tick: now, last_error: '' },
  '/api/soc/after-hours/mode/runs': { items: [
    { id: 'ALR-0000007', alert_id: 'ALR-0000007', created: now - 36e5, severity: 3, reason: 'after-hours', summary: 'Brute force against fahad', status: 'PAGED', to: 2, case_id: 'CASE-000003', approvals: 2, playbook: 'PB-BRUTE-FORCE', history: [{ at: now, by: 'system', what: 'page sent to 2 recipient(s)' }] },
    { id: 'ALR-0000008', alert_id: 'ALR-0000008', created: now - 30e5, severity: 4, reason: 'after-hours', summary: '<img src=x onerror=alert(1)>', status: 'HELD', history: [] }] },
  '/api/soc/after-hours/mode/briefs': { items: [{ id: '2026-10-21', at: now, counts: { alerts: 3 }, need: ['1 alert(s) raised after hours are still unacknowledged'], subject: 'After-hours brief 2026-10-21', sent: { status: 'ok', recipients: 2 } }] },
  '/api/soc/after-hours/mode/briefs/2026-10-21': { id: '2026-10-21', subject: 'After-hours brief 2026-10-21', html: '<h2>Brief body</h2><script>parent.document.title="pwned"</script>' },
  '/api/soc/after-hours/mode/config': CFG,
  '/api/soc/alerts/ALR-0000007': { id: 'ALR-0000007', severity: 3, summary: 'Brute force against fahad', rule_id: 'SENTRA-AUTH-001', status: 'in-progress', case_id: 'CASE-000003', created: now - 36e5 },
};
let ROLE = 'admin'; const POSTS = [];
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'rasheed', role: ROLE });
    if (u.startsWith('/api/')) {
      if (q.method === 'POST') { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { POSTS.push({ u, b: b ? JSON.parse(b) : null }); j(200, { ok: true, recipients: 2 }); }); return; }
      if (ROLE === 'viewer' && /mode\/(runs|briefs|config)/.test(u)) return j(403, { error: 'forbidden' });
      return DATA[u] ? j(200, DATA[u]) : j(200, { items: [] });
    }
    fs.readFile(path.join(B, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/soc-intel.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (url) => { const p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => d.accept()); await p.goto(url);
    await p.waitForFunction(() => document.getElementById('mk') && !/Loading/.test(document.getElementById('mk').innerText), null, { timeout: 8000 }).catch(() => {}); await p.waitForTimeout(300); return p; };

  // the link from the page e-mail
  let p = await open(base + '?alert=ALR-0000007#mode');
  let st = await p.evaluate(() => ({ hidden: document.getElementById('tab-mode').hidden, tab: document.querySelector('[data-tab="mode"]').classList.contains('on'), kpi: document.getElementById('mk').innerText.replace(/\s+/g, ' '),
    ack: document.getElementById('m-ack').innerText, runs: document.getElementById('mruns').innerText, briefs: document.getElementById('mbriefs').innerText, imgs: document.querySelectorAll('#mruns img').length, rota: (document.getElementById('m-rota') || {}).value }));
  ok(!st.hidden && st.tab, 'the e-mail link opens the After-hours mode tab');
  ok(/AFTER-HOURS MODE On/i.test(st.kpi) && /NOT ACKNOWLEDGED 1/i.test(st.kpi) && /Prepared for approval/i.test(st.kpi), 'status tiles: ' + st.kpi.slice(0, 200));
  ok(/ALR-0000007/.test(st.ack) && /Acknowledge and take it/.test(st.ack) && /approvals waiting/.test(st.ack), 'paged alert shown with acknowledge + approvals link');
  ok(/paged/.test(st.runs) && /held - storm guard/.test(st.runs) && /CASE-000003 · 2 waiting approval/.test(st.runs), 'runs: statuses and the prepared case');
  ok(st.imgs === 0 && /<img src=x/.test(st.runs), 'alert summaries are escaped');
  ok(/2026-10-21/.test(st.briefs) && /still unacknowledged/.test(st.briefs), 'brief list');
  ok(st.rota === 'Week A | Sun Mon | ali@as.example', 'rota rendered as editable lines: ' + st.rota);

  await p.click('#m-ackgo'); await p.waitForTimeout(400);
  ok(POSTS.some((x) => x.u === '/api/soc/alerts/ALR-0000007/ack') && POSTS.some((x) => x.u === '/api/soc/alerts/ALR-0000007/assign' && x.b.assignee === 'me'), 'acknowledge = ack + take ownership');

  await p.click('[data-mb="2026-10-21"]'); await p.waitForTimeout(400);
  st = await p.evaluate(() => { const f = document.querySelector('#mbview iframe'); return { sb: f && f.getAttribute('sandbox'), title: document.title }; });
  ok(st.sb === '', 'brief shown in a sandboxed frame (no scripts)');
  ok(st.title !== 'pwned', 'brief html cannot touch the page');

  await p.fill('#m-rota', 'Week A | Sun Mon | ali@as.example\nWeek B | Tue Wed Thu | sara@as.example, omar@as.example');
  await p.selectOption('#m-pm', 'shadow');
  await p.click('#m-save'); await p.waitForTimeout(400);
  const sv = POSTS.filter((x) => x.u === '/api/soc/after-hours/mode/config').pop();
  ok(sv && sv.b.base_version === 4 && sv.b.prepare.mode === 'shadow' && sv.b.oncall.length === 2 && sv.b.oncall[1].days.join() === '2,3,4' && sv.b.oncall[1].to.length === 2, 'save sends version, mode and the parsed rota');
  await p.fill('#m-rota', 'broken line');
  const before = POSTS.length; await p.click('#m-save'); await p.waitForTimeout(300);
  ok(POSTS.length === before, 'a malformed rota line is refused in the page');
  await p.click('#m-test'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u === '/api/soc/after-hours/mode/test-page'), 'test page');
  await p.close();

  // viewer: status only
  ROLE = 'viewer';
  p = await open(base + '#mode');
  st = await p.evaluate(() => ({ kpi: document.getElementById('mk').innerText, runs: document.getElementById('mruns').innerText, save: !!document.getElementById('m-save') }));
  ok(/After-hours mode/i.test(st.kpi), 'viewer sees the status');
  ok(/operators and administrators see them/.test(st.runs) && !st.save, 'viewer sees no names and cannot save');
  await p.close();

  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
