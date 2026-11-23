// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Reporting Center (dashboards/server/report-center.html) against the REAL ITAM engine (engine/report-center.js,
// pyengine/report_center_rules.py; the SIEM and the model stubbed) on SYNTHETIC figures: the catalogue, the executive report built from
// the modules, a section that is not connected says so, SOC locked for a viewer, ML "what changed" + sparklines from seeded history,
// CSV / HTML export and a sandboxed preview, a hostile name stays text, the admin schedule form (validation message, save, send now
// through the relay), the AI summary for an operator, the menu entry and the portal's Reports Center opening this page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node report-center.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';
const DAY = 86400000;

(async () => {
  const e = await H.startApp({ noAi: true });
  const NOW = Date.now(); let delivered = [];
  const siem = async (m, p, b) => {
    if (p.startsWith('/reports/attack-summary')) return { ok: true, data: { totals: { events: 1200, by_severity: { 3: 30, 4: 4 } }, alerts: { total: 50, open: 9 }, cases: { open_now: 3 }, response: { mtta: { median_ms: 900000 } }, top_attackers: [{ ip: '198.51.100.7', events: 40, targets: 3, country: XSS, classes: ['brute_force'] }] } };
    if (p === '/reports/deliver') { delivered.push(b); return { ok: true, status: 200, data: { ok: true } }; }
    return { ok: false, status: 0, error: 'not in this test' };
  };
  let asked = 0;
  const create = async (req) => {
    asked++;
    if (!req.messages.some((m) => Array.isArray(m.content) && m.content.some((c) => c.type === 'tool_result'))) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u1', name: 'insights', input: { report: 'executive' } }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'Headline: open VAPT findings rose to 80 (synthetic).' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', rcSiem: siem, rcSdk: sdk, rcKey: () => 'sk-ant-synthetic' });
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  delete e.app.addons.drStudio; delete e.app.addons.backup;   // DR / backup not on this server: the report must say so
  const R = e.app.addons.reportCenter;
  const sn = await R.snapshot(null), C = e.app.store.collection('rc_kpis'), today = C.get(sn.day);
  for (let i = 14; i >= 1; i--) { const d = new Date(NOW + 3 * 3600000 - i * DAY).toISOString().slice(0, 10); C.put({ id: d, day: d, at: NOW - i * DAY, values: { 'vapt.open': 10 + (14 - i), 'compliance.nca': 30 + (14 - i) }, labels: today.labels }); }
  C.put(Object.assign({}, today, { values: Object.assign({}, today.values, { 'vapt.open': 80, 'compliance.nca': 44 }) }));
  await R.snapshot(null); C.put(Object.assign({}, C.get(sn.day), { values: Object.assign({}, C.get(sn.day).values, { 'vapt.open': 80, 'compliance.nca': 44 }) }));
  let WHO = VIEW;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'dashboards/report-center.html');
    ok(await wait(p, () => !document.getElementById('main').hidden && document.querySelectorAll('#secs .kpi').length > 3), 'the executive report is drawn from the modules');
    ok((await p.$$('#cat .rp')).length >= 7, 'the catalogue lists every report');
    ok(await p.$eval('#cat [data-rep="soc"]', (b) => b.classList.contains('locked')), 'viewer: the SOC report is locked');
    ok(/Executive IT & security summary/.test(await p.textContent('#title')), 'executive report first');
    const secs = await p.textContent('#secs');
    ok(/DR & backup/.test(secs) && /DR Studio and Backup Status are not installed here/.test(secs), 'a source that is not there says so - never zero');
    ok(/Needs the operator role/.test(secs), 'the SOC part is withheld from a viewer');
    ok(/Open VAPT findings|VAPT findings open/.test(await p.textContent('#changes')) || /VAPT findings open/.test(await p.textContent('#changes')), 'ML: what changed names the VAPT jump');
    ok(/machine learning over 15 day/.test(await p.textContent('#mlnote')), 'says how much history it rests on');
    ok((await p.$$('#secs .kpi svg')).length >= 2, 'sparklines from the daily history');
    ok(await p.$eval('#secs .kpi[data-k="vapt.open"] .vd', (d) => /worsening/.test(d.textContent) && /unusual today/.test(d.textContent)), 'the VAPT figure: worsening, unusual today');
    ok(await p.$eval('#secs .kpi[data-k="compliance.nca"] .vd', (d) => /improving/.test(d.textContent)), 'NCA ECC improving');
    ok(await p.isDisabled('#summ'), 'a viewer cannot ask the AI');
    ok(await p.isHidden('#snap'), 'only an administrator records figures by hand');
    // compliance report, export and preview
    await p.click('#cat [data-rep="compliance"]');
    ok(await wait(p, () => /Compliance frameworks/.test(document.getElementById('title').textContent) && document.querySelectorAll('#secs table tr').length >= 6), 'compliance report with the frameworks table');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#xcsv')]);
    ok(/^report-compliance-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'CSV download');
    await p.click('#pv');
    ok(await wait(p, () => !document.getElementById('pvbox').hidden), 'preview shown');
    ok((await p.getAttribute('#pvf', 'sandbox')) === '', 'the preview is sandboxed (no scripts)');
    // operator: SOC report, hostile name stays text, AI summary
    WHO = OP; await p.goto(base + 'dashboards/report-center.html#report=soc'); await p.reload();
    ok(await wait(p, () => /Security operations/.test(document.getElementById('title').textContent) && document.querySelectorAll('#secs table tr').length === 2), 'operator: the SOC report from the SIEM');
    ok(/9/.test(await p.$eval('#secs .kpi[data-k="soc.alerts_open"] .n', (x) => x.textContent)), 'open alerts from the SIEM');
    ok(!(await p.evaluate(() => window.__xss)) && (await p.textContent('#secs')).includes('<img') && !(await p.$('#secs img')), 'a hostile name stays text');
    await p.click('#summ');
    ok(await wait(p, () => /Headline: open VAPT findings rose to 80/.test(document.getElementById('out').textContent)), 'AI executive summary');
    ok(/1 step\(s\): insights/.test(await p.textContent('#out')), 'its read-only steps are shown');
    // admin: schedule form, validation message, save, send now through the relay
    WHO = ADM; await p.reload();
    ok(await wait(p, () => !!document.getElementById('s-save')) && await p.isVisible('#snap'), 'admin: the schedule form');
    await p.fill('#s-name', 'Weekly executive (synthetic)'); await p.selectOption('#s-report', 'executive'); await p.fill('#s-at', '7:5'); await p.fill('#s-to', 'ciso.syn@corpgroup.test');
    await p.click('#s-save');
    ok(await wait(p, () => /at must be HH:MM/.test(document.body.textContent)), 'a bad time is refused with the field named');
    await p.fill('#s-at', '07:30'); await p.click('#s-save');
    ok(await wait(p, () => /Weekly executive \(synthetic\)/.test(document.getElementById('sched').textContent) && /1 recipient/.test(document.getElementById('sched').textContent)), 'schedule saved');
    await p.click('#sched [data-send]');
    ok(await wait(p, () => /Recent deliveries/.test(document.getElementById('sched').textContent)) && delivered.length === 1, 'sent now through the SIEM relay');
    ok(delivered[0].recipients[0] === 'ciso.syn@corpgroup.test' && delivered[0].attachments.length === 2, 'HTML + CSV attached');
    ok(e.app.store.auditTail(40).some((x) => x.action === 'report.center.schedules.save' && x.by === 'syed'), 'audited with who');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'cmd'); return !!(a && a.pages.some((x) => x.h === 'report-center.html')); }), 'the menu has the page');
    const early = fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8'); ok(/repcenter: 'report-center\.html'/.test(early), 'the portal\'s Reports Center opens it');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
