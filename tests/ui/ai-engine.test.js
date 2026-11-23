// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for AI Engine (dashboards/server/ai-engine.html) against the REAL IT Asset Management engine (engine/ai-engine.js,
// engine/ai-backend.js) with a fake OpenAI-compatible gateway, and a stubbed SIEM half (synthetic): both engines shown, the admin
// picks Local model, fills the gateway and saves to both, the test shows a plain answer and a tool call per engine, a public
// address is refused with the reason, an operator reads but cannot change, a SIEM that is not updated is said, menu entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-engine.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' };

(async () => {
  const e = await H.startApp({ noAi: true });
  const gw = [];
  const fetch = async (url, init) => { const q = JSON.parse(init.body); gw.push(q);
    const body = q.tools ? { model: q.model, choices: [{ finish_reason: 'tool_calls', message: { content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: 'get_asset_count', arguments: '{"site":"HQ"}' } }] } }], usage: {} }
      : { model: q.model, choices: [{ finish_reason: 'stop', message: { content: 'OK' } }], usage: {} };
    return { status: 200, text: async () => JSON.stringify(body) }; };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', aiFetch: fetch, aiEngineSdk: null, aiLocalKey: () => '', aiAnthropicKey: () => '' });
  // the SIEM half, stubbed: same contract as engine/aiengine/routes.js
  let siemUp = true, siem = { mode: 'anthropic', data_leaves_network: true, local: { api: 'openai', base_url: '', host: '', model: '', tools: true, key_set: false, timeout_s: 180, max_tokens: 4096 }, anthropic: { key_set: false, sdk_installed: false }, effective: 'Claude selected but no Anthropic API key is set', calls_today: { total: 0 }, last_test: null };
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/ai-engine')) {
      if (!siemUp) return json(404, { error: 'not found' });
      const chunks = []; req.on('data', (c) => chunks.push(c)); req.on('end', () => {
        const b = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : null;
        if (req.method === 'PUT') { if (WHO.role !== 'admin') return json(403, { error: 'admin only' }); siem = Object.assign({}, siem, { mode: b.mode, routes: b.routes || [], routed: !!(b.routes && b.routes.length), data_leaves_network: b.mode === 'anthropic', local: Object.assign({}, siem.local, b.local, { host: b.local.base_url ? new URL(b.local.base_url).host : '' }), effective: b.mode === 'local' ? 'every AI feature uses the local model ' + b.local.model : 'changed', updated_by: WHO.user, updated_at: new Date().toISOString() }); return json(200, siem); }
        if (req.method === 'POST') { siem.last_test = { at: new Date().toISOString(), by: WHO.user, mode: siem.mode, model: siem.local.model, ok: true, steps: [{ name: 'answer', ok: true, ms: 12, text: 'OK' }, { name: 'tool use', ok: true, ms: 20, tool: 'get_asset_count' }] }; return json(200, siem.last_test); }
        return json(200, siem); });
      return;
    }
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
  const txt = (p, s) => p.textContent(s);
  try {
    const p = await browser.newPage({ viewport: { width: 1300, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'ai-engine.html?standalone=1');
    ok(await wait(p, () => !document.getElementById('main').hidden), 'the page loads');
    const eng = await txt(p, '#engines'); ok(/IT Asset Management/.test(eng) && /SIEM/.test(eng) && /data leaves the network/.test(eng), 'both engines, Claude by default, data leaves the network');
    ok(await p.isHidden('#localbox'), 'the local form shows only for the local model');
    await p.click('[data-mode="local"]'); ok(await p.isVisible('#localbox'), 'local model chosen');
    await p.fill('#base', 'http://8.8.8.8:8000/v1'); await p.fill('#model', 'synthetic-local-7b'); await p.click('#save');
    ok(await wait(p, () => /public address/.test(document.body.textContent)), 'a public address is refused with the reason');
    await p.fill('#base', 'http://10.20.0.40:8000/v1'); await p.click('#save');
    ok(await wait(p, () => /IT Asset Management: saved/.test(document.body.textContent) && /SIEM: saved/.test(document.body.textContent)), 'saved to both engines');
    ok(await wait(p, () => (document.getElementById('engines').textContent.match(/stays inside/g) || []).length === 2), 'both engines on the local model, nothing leaves the network');
    ok(/10\.20\.0\.40:8000/.test(await txt(p, '#engines')) && /synthetic-local-7b/.test(await txt(p, '#engines')), 'gateway and model shown');
    await p.click('#test');
    ok(await wait(p, () => (document.getElementById('engines').textContent.match(/called get_asset_count/g) || []).length === 2), 'the test shows the answer and the tool call per engine');
    ok(gw.length >= 2 && gw.every((q) => q.model === 'synthetic-local-7b'), 'the IT Asset Management probe reached the local gateway with the local model');
    ok(e.app.store.auditTail(40).some((x) => x.action === 'ai.engine.save' && x.by === 'syed') && e.app.store.auditTail(40).some((x) => x.action === 'ai.engine.test'), 'audited');
    // per-feature routing: Claude stays the default, one feature goes to the local model
    ok(/No AI feature has been used today/.test(await txt(p, '#feats')) && /No rule/.test(await txt(p, '#routes')), 'routing starts empty and says how features appear');
    await p.click('[data-mode="anthropic"]'); ok(await p.isHidden('#localbox'), 'Claude chosen: the local form hides');
    await p.click('#radd'); await p.fill('[data-rm="0"]', 'bad pattern'); ok(await p.isVisible('#localbox'), 'a rule to the local model brings the local form back');
    await p.click('#save'); ok(await wait(p, () => /routes\[0\]\.match must be a feature name/.test(document.body.textContent)), 'an invalid rule is refused with the reason');
    await p.fill('[data-rm="0"]', 'itam.synthetic-feature'); await p.click('#save');
    ok(await wait(p, () => /IT Asset Management: saved/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')) && /Routing/.test(document.getElementById('engines').textContent)), 'the rule is saved to both engines');
    ok(/1 rule\(s\): itam\.synthetic-feature → Local model/.test(await txt(p, '#engines')), 'the engine card shows the rule');
    ok(e.app.store.auditTail(40).some((x) => x.action === 'ai.engine.save' && JSON.stringify(x.detail.routes) === '[{"match":"itam.synthetic-feature","engine":"local"}]'), 'the rule is audited');
    { const B = require(path.join(ITAM, 'engine/ai-backend')), G = require(path.join(ITAM, 'engine/ai-guard')), n0 = gw.length;   // what a feature does: admit, then call
      G.sharedBudget({}).admit('syed', 'itam.synthetic-feature', 5); await new (B.wrap(null))({}).messages.create({ model: 'x', max_tokens: 20, messages: [{ role: 'user', content: 'synthetic' }] });
      ok(gw.length === n0 + 1, 'the routed feature reached the local gateway while Claude is the default'); }
    await p.click('#refresh'); ok(await wait(p, () => /itam\.synthetic-feature/.test(document.getElementById('feats').textContent) && /rule itam\.synthetic-feature/.test(document.getElementById('feats').textContent)), 'the feature used today is listed with its engine and rule');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => (a.pages || []).some((x) => x.h === 'ai-engine.html'))), 'the menu has the page');
    // operator: reads, cannot change
    WHO = OP; await p.reload(); ok(await wait(p, () => !document.getElementById('main').hidden), 'an operator opens the page');
    ok(await p.isHidden('#save') && await p.isDisabled('[data-mode="off"]') && await p.isVisible('#ro'), 'an operator cannot change the AI engine');
    // a SIEM that is not updated
    WHO = ADM; siemUp = false; await p.reload(); ok(await wait(p, () => /not reachable/.test(document.getElementById('engines').textContent) && /update this engine/.test(document.getElementById('engines').textContent)), 'a SIEM without the AI Engine is said');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
