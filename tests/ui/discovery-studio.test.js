// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Discovery Studio (dashboards/server/discovery-studio.html) against the REAL ITAM engine (engine/discovery-studio.js,
// pyengine/discovery_studio_rules.py) and the REAL discovery devices / bulk / merge on SYNTHETIC devices (runs, scopes and credential
// metadata synthetic; the model stubbed): tabs, KPIs, the funnel and the recommendation donut, "do first", recommended bulk groups
// (one click adds a group), the device table with reasons, filters, select + sticky bulk bar, ignore with a reason, merge, runs with
// the median line and a drop flagged, failing methods, credential health (admin only) and coverage gaps, the AI analyst's proposal
// applied by a person, a hostile host name stays text, an operator reads but cannot apply, a viewer is refused.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node discovery-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';
const DAY = 86400000, iso = (t) => new Date(t).toISOString();

(async () => {
  const e = await H.startApp({ noAi: true });
  let propIds = [];
  const create = async (req) => {
    if (!req.messages.some((m) => Array.isArray(m.content) && m.content.some((c) => c.type === 'tool_result'))) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u1', name: 'propose_bulk', input: { action: 'ignore', ids: propIds, reason: 'guest printers are not company assets (synthetic)' } }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'Add the Dell servers; I proposed ignoring the guest printer (synthetic).' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', dsSdk: sdk, dsKey: () => 'sk-ant-synthetic' });
  const real = e.app.discovery, NOW = Date.now();
  const obs = (o, ctx) => real.devices.observe(o, Object.assign({ scope_id: 'sc_hq', site: 'Riyadh HQ' }, ctx || {}));
  for (let i = 0; i < 12; i++) { const ip = '10.99.0.' + (10 + i); obs({ method: 'arp', ip, mac: '02:99:00:00:00:' + String(10 + i).padStart(2, '0'), vendor: 'GuestPrint' }, { site: 'Guest' }); real.devices.ignore(real.devices.list((x) => x.ip === ip)[0].id, 'guest (synthetic)', ADM); }
  for (let i = 0; i < 8; i++) { const ip = '10.10.0.' + (10 + i); obs({ method: 'arp', ip, mac: '02:10:00:00:00:' + String(10 + i).padStart(2, '0'), hostname: 'SRV-SYN-' + i, vendor: 'Dell' }); real.devices.approve(real.devices.list((x) => x.ip === ip)[0].id, ADM); }
  for (let i = 0; i < 3; i++) for (let k = 0; k < 2; k++) obs({ method: 'arp', ip: '10.10.1.' + (10 + i), mac: '02:11:00:00:00:' + String(10 + i).padStart(2, '0'), hostname: i === 2 ? XSS : 'APP-SYN-' + i, vendor: 'Dell' });
  obs({ method: 'arp', ip: '10.99.0.50', mac: '02:99:00:00:00:50', vendor: 'GuestPrint' }, { site: 'Guest' });
  obs({ method: 'sweep', ip: '10.10.9.9' });
  e.app.assets.create({ name: 'EXIST-SYN', type: 'server', status: 'in_use', mac: '02:aa:bb:cc:dd:ee' }, ADM);
  obs({ method: 'arp', ip: '10.10.2.2', mac: '02:aa:bb:cc:dd:ee', hostname: 'EXIST-NIC2' });
  obs({ method: 'unix', ip: '10.10.3.3', mac: '02:33:00:00:00:01', hostname: 'NIX-SYN', extra: { unix: { ssh_banner: 'SSH-2.0-OpenSSH_9.0' } } });
  propIds = real.devices.list((x) => x.ip === '10.99.0.50').map((x) => x.id);
  const runs = [], scopes = [{ id: 'sc_hq', name: 'HQ (synthetic)', status: 'active', site: 'Riyadh HQ', targets: ['10.10.0.0/16'], methods: { sweep: { enabled: true }, snmp: { credential_ids: ['cr_snmp'] }, unix: { enabled: true } }, checklist: {} }];
  for (let i = 0; i < 6; i++) runs.push({ id: 'run' + i, scope_id: 'sc_hq', status: 'done', started_at: iso(NOW - (6 - i) * DAY), devices_seen: i < 5 ? 100 + i : 30, devices_new: i < 5 ? 1 : 0, stats: { sweep: { ok: true }, snmp: i < 5 ? { ok: true } : { ok: false, error_class: 'auth' } } });
  const creds = [{ id: 'cr_snmp', kind: 'snmp_v3', label: 'SNMP HQ (synthetic)', last_tested: { at: iso(NOW - 2 * DAY), ok: false, error_class: 'auth' }, updated_at: iso(NOW - 400 * DAY) }];
  e.app.discovery = Object.assign({}, real, { listRuns: () => runs.slice().reverse(), listScopes: () => scopes, credentials: () => creds });
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  let WHO = ADM;
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
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { if (d.type() === 'prompt') return d.accept('guest equipment (synthetic)'); errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'dashboards/discovery-studio.html');
    ok(await wait(p, () => !document.getElementById('main').hidden), 'page loads');
    ok(/7/.test(await p.textContent('#kpis')) && /ready to add/.test(await p.textContent('#kpis')), 'KPIs');
    ok((await p.$$('#funnel rect')).length === 4 && (await p.$$('#donut path')).length >= 3, 'funnel and recommendation donut');
    ok(/learning from 20 past decisions/.test(await p.textContent('#learn')), 'what the learning rests on');
    ok(/Merge 1 device/.test(await p.textContent('#first')) && /HQ \(synthetic\): devices seen fell/.test(await p.textContent('#first')), 'do first');
    // results
    await p.click('#tabs [data-t="res"]');
    ok(await wait(p, () => !document.querySelector('section[data-v="res"]').hidden) && /#view=res/.test(p.url()), 'results tab, in the address');
    ok(/3 × unknown · Dell/.test(await p.textContent('#groups')), 'recommended bulk group');
    ok((await p.$$('#rows tr input[data-sel]')).length === 7, 'seven new devices');
    ok((await p.textContent('#rows')).includes(XSS) && !(await p.$('#rows img')), 'a hostile host name stays text');
    ok(/people ignored devices like this before/.test(await p.textContent('#rows')) && /the same mac as EXIST-SYN/.test(await p.textContent('#rows')), 'reasons shown');
    await p.selectOption('#fr', 'review'); ok((await p.$$('#rows tr input[data-sel]')).length === 2, 'recommendation filter');
    await p.selectOption('#fr', ''); await p.selectOption('#fs', 'Guest'); ok((await p.$$('#rows tr input[data-sel]')).length === 1, 'site filter');
    await p.selectOption('#fs', '');
    // select + bulk bar: ignore with a reason
    await p.click('#rows tr input[data-sel]:nth-of-type(1)');
    ok(await p.isVisible('#bulk') && /1 selected/.test(await p.textContent('#bn')), 'sticky bulk bar');
    await p.click('#bclr'); ok(await p.isHidden('#bulk'), 'cleared');
    // one click adds the Dell group
    await p.click('#groups [data-gapp]');
    ok(await wait(p, () => document.querySelectorAll('#rows tr input[data-sel]').length === 4), 'the group was added');
    ok(e.app.store.auditTail(100).some((x) => x.action === 'discovery.studio.apply' && x.by === 'syed' && x.detail.approved === 3), 'audited with who and how many');
    // merge
    await p.click('#rows [data-merge]');
    ok(await wait(p, () => document.querySelectorAll('#rows tr input[data-sel]').length === 3), 'merged into the existing asset');
    // runs + creds
    await p.click('#tabs [data-t="runs"]');
    ok(/fell from about 10\d to 30/.test(await p.textContent('#runs')) && (await p.$$('#runs svg line')).length === 1, 'run drop flagged with the median line');
    ok(/snmp/.test(await p.textContent('#meth')) && /auth 1/.test(await p.textContent('#meth')), 'failing methods');
    await p.click('#tabs [data-t="cred"]');
    ok(/SNMP HQ/.test(await p.textContent('#creds')) && /last test failed/.test(await p.textContent('#creds')) && /rotate it/.test(await p.textContent('#creds')), 'credential health explained');
    ok(/HQ \(synthetic\)/.test(await p.textContent('#cov')) && /unix/.test(await p.textContent('#cov')), 'coverage gap');
    // AI proposal applied by a person
    await p.click('#tabs [data-t="ai"]');
    ok(/Claude claude-opus-5-5/.test(await p.textContent('#ais')), 'AI on');
    await p.fill('#aq', 'What should we add?'); await p.click('#go');
    ok(await wait(p, () => /AI proposal/.test(document.getElementById('out').textContent)), 'the proposal is shown');
    ok(real.devices.get(propIds[0]).status === 'new', 'nothing changed by the AI');
    await p.click('#out [data-papply]');
    let applied = false; for (let i = 0; i < 40 && !applied; i++) { await p.waitForTimeout(250); applied = real.devices.get(propIds[0]).status === 'ignored'; }
    ok(applied && e.app.store.auditTail(100).some((x) => x.action === 'discovery.bulk.ignore' && x.by === 'syed'), 'a person applied it (with a reason)');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'ast'); return !!(a && a.pages.some((x) => x.h === 'discovery-studio.html' && x.g === 'Discovery')); }), 'the menu has the page');
    // operator: reads, no apply, no credentials
    WHO = OP; await p.goto(base + 'dashboards/discovery-studio.html#view=res'); await p.reload(); await wait(p, () => !document.getElementById('main').hidden);
    ok(!(await p.$('#groups [data-gapp]')) && !(await p.$('#rows [data-merge]')), 'an operator cannot apply or merge');
    await p.click('#tabs [data-t="cred"]'); ok(/for administrators/.test(await p.textContent('#creds')), 'credential health hidden from operators');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => /operators and administrators only/.test(document.getElementById('err').textContent)), 'a viewer is refused');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(['discovery', 'discovery-results', 'discovery-runs', 'discovery-credentials', 'discovery-scopes'].every((v) => new RegExp("'" + v + "': '").test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && new RegExp("'" + v + "': '").test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8'))), 'the portal\'s Asset Discovery, Results, Runs, Credentials and Scopes open the rebuilt pages');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
