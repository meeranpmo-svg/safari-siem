// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for VAPT Studio (dashboards/server/vapt-studio.html) against the REAL ITAM engine (engine/vapt-studio.js,
// pyengine/firecompass_rules.py; Greenbone findings, the Tenable API, the vault and the model stubbed) on SYNTHETIC findings: the
// FireCompass import wizard (ML column mapping shown with confidence, changed by a person, then imported), the posture ring and
// KPIs, the three source cards, the overlap diagram, severity x exposure, the risk histogram, weakness families, the attack-surface
// map (a bubble filters the table), filters, a finding's drawer with its explained risk, the four-eyes false-positive request and
// decision by another person, the admin connections (Tenable saved, tested, pulled), the read-only AI analyst, a hostile title
// stays text, and a viewer is refused.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node vapt-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  const create = async (req) => {
    if (!req.messages.some((m) => Array.isArray(m.content) && m.content.some((c) => c.type === 'tool_result'))) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u1', name: 'findings', input: {} }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'Fix the internet-facing Apache first (synthetic).' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  const sealer = { seal: (id, p) => ({ ct: Buffer.from(String(p)).toString('base64') }), unseal: (id, x) => Buffer.from(x.ct, 'base64').toString() };
  const tnCalls = [];
  const request = async (url, o) => { tnCalls.push(url);
    if (/\/workbenches\/assets\?/.test(url)) return { status: 200, json: { assets: [{ id: '1b2c3d4e-0000-4000-8000-000000000001', ipv4: ['10.30.0.7'], fqdn: ['app07.syn.local'] }] } };
    if (/\/vulnerabilities/.test(url)) return { status: 200, json: { vulnerabilities: [{ plugin_id: 57582, plugin_name: 'SSL Self-Signed Certificate', severity: 2 }] } };
    return { status: 404, json: {} }; };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', fcSdk: sdk, fcKey: () => 'sk-ant-synthetic', fcSealer: sealer, fcRequest: request });
  e.app.addons.vulnscan = { findings: () => ({ items: [{ id: 'gb1', host: '10.20.0.5', hostname: 'ssh01', name: 'OpenSSH user enumeration vulnerability', severity: 'medium', score: 5.3, cves: ['CVE-2018-15473'] }, { id: 'gb9', host: '10.20.0.99', name: 'Other', severity: 'low', score: 2, cves: [] }] }) };
  e.app.assets.create({ name: 'SSH01', mgmt_ip: '10.20.0.5', type: 'server', status: 'in_use', tags: ['business-critical'] }, ADM);
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  const CSV = 'Ref,Target Host,Issue,Risk Level,Score,CVE List,Found\r\n'
    + 'R1,https://portal.syn-example.sa/login,Apache HTTP Server path traversal (remote code execution),Critical,9.8,CVE-2021-41773,2026-06-01\r\n'
    + 'R2,10.20.0.5,OpenSSH user enumeration,Medium,5.3,CVE-2018-15473,2026-10-20\r\n'
    + 'R3,mail.syn-example.sa,TLS 1.0 enabled,Low,3.1,,2026-10-25\r\n'
    + 'R4,vpn.syn-example.sa,TLS 1.0 enabled on VPN,Low,3.1,,2026-10-25\r\n'
    + 'R5,www.syn-example.sa,"' + XSS + '",High,7.5,,2026-10-25\r\n';
  const tmp = path.join(os.tmpdir(), 'fc-export-' + process.pid + '.csv'); fs.writeFileSync(tmp, CSV);
  let WHO = OP;
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
    p.on('dialog', (d) => { if (/Trust the scanner/.test(d.message())) return d.accept(); errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'dashboards/vapt-studio.html');
    ok(await wait(p, () => !document.getElementById('main').hidden), 'page loads');
    ok(/No finding yet/.test(await p.textContent('#rows')), 'empty: says how to start, never a sample');
    ok(/not connected/.test(await p.textContent('#srcs')), 'sources say not connected');
    // import wizard
    await p.click('#imp'); await p.setInputFiles('#mf', tmp);
    ok(await wait(p, () => !!document.querySelector('#mbox select[data-f="asset"]')), 'the wizard shows the proposed mapping');
    ok(await p.$eval('#mbox select[data-f="asset"]', (s) => s.value) === 'Target Host' && await p.$eval('#mbox select[data-f="title"]', (s) => s.value) === 'Issue' && await p.$eval('#mbox select[data-f="severity"]', (s) => s.value) === 'Risk Level', 'ML mapping: asset, title, severity');
    ok((await p.$$('#mbox .conf i')).length >= 5, 'confidence shown per field');
    ok(/portal\.syn-example\.sa\/login · Apache/.test(await p.textContent('#mw')), 'how the first rows read');
    await p.selectOption('#mbox select[data-f="first_seen"]', 'Found');
    await p.click('#mgo');
    ok(await wait(p, () => document.getElementById('mod').hidden && document.querySelectorAll('#rows tr[data-id]').length === 5), 'imported: five findings');
    ok(e.app.store.auditTail(50).some((x) => x.action === 'vapt.firecompass.import' && x.by === 'nora.syn' && x.detail.mapping.first_seen === 'Found'), 'the import is audited with the mapping a person confirmed');
    // graphics
    ok(/^\d+$/.test((await p.textContent('#ring b')).trim()) && /5/.test(await p.textContent('#kpis')), 'posture ring and KPIs');
    ok(/FireCompass/.test(await p.textContent('#srcs')) && /import/.test(await p.textContent('#srcs')), 'FireCompass source card');
    ok((await p.$$('#venn circle')).length === 2 && /both/.test(await p.textContent('#venn')), 'overlap diagram');
    ok((await p.$$('#sev .bar')).length === 4 && (await p.$$('#hist rect')).length === 10, 'severity x exposure and the risk histogram');
    ok(/tls enabled/.test(await p.textContent('#fams')), 'weakness family');
    ok((await p.$$('#map g.hb')).length === 5, 'attack-surface map, a bubble per asset');
    ok((await p.textContent('#rows')).includes(XSS) && !(await p.$('#rows img')), 'a hostile title stays text');
    const first = await p.$eval('#rows tr[data-id] td.risk', (td) => Number(td.textContent));
    ok(first >= 90, 'highest risk first: ' + first);
    // filters and map
    await p.selectOption('#fe', 'external'); ok((await p.$$('#rows tr[data-id]')).length === 4, 'exposure filter');
    await p.selectOption('#fe', ''); await p.click('#map g.hb[data-host="10.20.0.5"]', { force: true });
    ok(await wait(p, () => document.querySelectorAll('#rows tr[data-id]').length === 1), 'a bubble filters the table');
    ok(/Greenbone · same/.test(await p.textContent('#rows')), 'merged with the Greenbone finding');
    await p.click('#map g.hb[data-host="10.20.0.5"]', { force: true });
    // drawer + four-eyes
    await p.fill('#q', 'TLS 1.0 enabled on VPN'); await p.click('#rows tr[data-id]');
    ok(await wait(p, () => !document.getElementById('dr').hidden && /Risk \d+ \/ 100/.test(document.getElementById('dr').textContent)), 'drawer with the explained risk');
    ok(/exposed to the internet/.test(await p.textContent('#dr')), 'its reasons');
    await p.fill('#own', 'Network team (synthetic)'); await p.click('#owns');
    ok(await wait(p, () => /Network team/.test(document.getElementById('rows').textContent)), 'owner saved');
    await p.selectOption('#tw', 'false_positive'); await p.fill('#tr', 'the VPN only offers TLS 1.2 - checked by hand (synthetic)'); await p.click('#trs');
    ok(await wait(p, () => /Waiting for a decision/.test(document.getElementById('dr').textContent)) && /A different person decides/.test(await p.textContent('#dr')), 'request recorded; the requester cannot decide');
    await p.keyboard.press('Escape');
    ok(await p.isHidden('#admin'), 'an operator has no connection settings');
    // a source tile is clickable: an operator clicking FireCompass gets the export import; Tenable says an administrator connects it
    await p.click('#srcs [data-cfg="firecompass"]'); ok(await wait(p, () => { const m = document.getElementById('mod'); return m && !m.hidden; }) || await wait(p, () => document.querySelector('input[type=file]') !== null), 'FireCompass tile opens the import for an operator');
    await p.keyboard.press('Escape'); await p.evaluate(() => { const m = document.getElementById('mod'); if (m) m.hidden = true; });
    await p.click('#srcs [data-cfg="tenable"]'); ok(await wait(p, () => /administrator connects Tenable/.test(document.body.textContent)), 'Tenable tile tells an operator who configures it');
    WHO = OP2; await p.reload(); await wait(p, () => !document.getElementById('main').hidden);
    await p.selectOption('#fo', 'pending'); ok((await p.$$('#rows tr[data-id]')).length === 1, 'waiting-for-a-decision filter');
    await p.click('#rows tr[data-id]'); await wait(p, () => !!document.getElementById('dyes'));
    await p.fill('#dnote', 'agreed (synthetic)'); await p.click('#dyes');
    ok(await wait(p, () => /false positive approved by omar\.syn/.test(document.getElementById('dr').textContent)), 'decided by a different person');
    await p.keyboard.press('Escape');
    // admin: Tenable
    WHO = ADM; await p.reload(); await wait(p, () => !document.getElementById('admin').hidden);
    await p.click('#srcs [data-cfg="tenable"]'); ok(await wait(p, () => document.activeElement && document.activeElement.id === 'tnu'), 'Tenable tile takes an administrator to the Tenable connection form');
    await p.fill('#tna', 'AKSYNTHETIC0001'); await p.fill('#tns', 'SKSYNTHETIC0001'); await p.click('#tnsv');
    ok(await wait(p, () => /keys saved/.test(document.getElementById('tno').textContent)), 'Tenable keys saved (never shown again)');
    ok(await p.$eval('#tna', (i) => i.value) === '', 'the key field is cleared');
    await p.click('#tnt'); ok(await wait(p, () => /OK - 1 assets/.test(document.getElementById('tno').textContent)), 'Tenable test');
    await p.click('#tnl'); ok(await wait(p, () => /SSL Self-Signed/.test(document.getElementById('rows').textContent) || document.querySelectorAll('#rows tr[data-id]').length >= 5), 'Tenable pulled');
    await p.selectOption('#fo', ''); await p.selectOption('#fv', 'tenable'); ok(await wait(p, () => document.querySelectorAll('#rows tr[data-id]').length === 1), 'source filter: Tenable');
    ok(/Tenable cloud/.test(await p.textContent('#srcs')), 'Tenable source card');
    ok(tnCalls.every((u) => u.startsWith('https://cloud.tenable.com/')), 'only the Tenable cloud was called');
    // AI
    await p.fill('#aq', 'What should we fix first?'); await p.click('#go');
    ok(await wait(p, () => /internet-facing Apache/.test(document.getElementById('out').textContent)) && /1 step\(s\): findings/.test(await p.textContent('#out')), 'the analyst answers');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'pt'); return !!(a && a.pages.some((x) => x.h === 'vapt-studio.html')); }), 'the menu has the page');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => /operators and administrators only/.test(document.getElementById('err').textContent)), 'a viewer is refused');
  } finally { await browser.close(); srv.close(); await e.close(); try { fs.unlinkSync(tmp); } catch (x) { /* temp file already gone */ } }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
