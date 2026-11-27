// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Agent Workspace (agent-workspace.html) against the REAL engine (backend/siem engine/soc/workspace.js) behind a stub server, with a
// throw-away state, SYNTHETIC alerts and a scripted model: an operator starts from a template, sees the flow and its settings, adds a
// block, saves a draft and test-runs it (nothing changes); submits it; the author's publish is refused, a second administrator
// publishes; a real run waits for a person, the starter's approval is refused, an administrator approves and the case is opened; the
// agent's text stays text even when it carries markup; a viewer is told the page is for analysts and up; POC mode with one ribbon;
// menu entry and installer. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node agent-workspace.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), DASH = path.join(ROOT, 'ui'), E = path.join(ROOT, 'backend/siem/engine');
const W = require(path.join(E, 'soc/workspace.js')), { createState } = require(path.join(E, 'soc/state.js'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-ui-')), state = await createState({ dir, log: { info() {}, warn() {}, error() {} } });
  const NOW = Date.now(), alerts = [{ id: 'AL-1', created: NOW - 3600e3, severity: 4, rule_name: 'Syn brute force', summary: 'syn', status: 'new' }, { id: 'AL-2', created: NOW - 7200e3, severity: 3, rule_name: 'Syn scan', summary: 'syn', status: 'new' }];
  const cases = [];
  const X = W.createWorkspace({ state, noTimer: true, log: { info() {}, warn() {}, error() {}, every() {} }, model: async () => ({ text: '<img src=x onerror=window.PWN=1> Check AL-1 first.' }),
    alerts: { all: (f) => alerts.filter((a) => !f || f(a)), get: (id) => alerts.find((a) => a.id === id), note() {} }, cases: { create: (i) => { cases.push(i); return { id: 'CASE-9' }; } },
    detector: { stats: () => ({ rules: [{ id: 'r1', name: 'Syn noisy', matches: 500, suppressed: 450, alerts: 9 }] }) } });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    const m = /^\/api\/soc\/workspace(?:\/(workflows|runs)(?:\/([\w-]+))?(?:\/(\w+))?)?$/.exec(u.pathname);
    if (m) { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', async () => {
      const body = b ? JSON.parse(b) : {}, ctx = Object.assign({ audit() {} }, WHO), need = (r) => { if (RANK[WHO.role] < RANK[r]) throw Object.assign(new Error('requires role ' + r), { status: 403 }); };
      try { let out;
        if (!m[1]) { need('analyst'); out = X.view(); }
        else if (m[1] === 'runs' && !m[3]) { need('analyst'); out = X.getRun(m[2]); }
        else if (m[1] === 'runs') { need('operator'); out = await X.decideRun(m[2], body, ctx); }
        else if (!m[2]) { need('operator'); out = X.create(body, ctx); }
        else if (!m[3]) { need('operator'); out = X.update(m[2], body, ctx); }
        else if (m[3] === 'submit') { need('operator'); out = X.submit(m[2], ctx); }
        else if (m[3] === 'decide') { need('admin'); out = X.decide(m[2], body, ctx); }
        else if (m[3] === 'run') { need('operator'); out = await X.runNow(m[2], body, ctx); }
        else if (m[3] === 'disable') { need('admin'); out = X.disable(m[2], body, ctx); }
        else if (m[3] === 'delete') { need('admin'); out = X.remove(m[2], ctx); }
        json(200, out); } catch (e) { json(e.status || e.code || 500, { error: e.message }); } }); return; }
    if (u.pathname.startsWith('/api/')) return json(500, { error: 'down (synthetic)' });
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/agent-workspace.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (q, sel) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('synthetic reason')); await p.goto(base + (q || '?standalone=1')); await p.waitForSelector(sel || '#main:not([hidden])', { timeout: 15000 }); await p.waitForTimeout(200); return p; };
  const msg = (p, re) => p.waitForFunction((s) => new RegExp(s).test(document.getElementById('msg').textContent), re.source, { timeout: 8000 }).then(() => true, () => false);
  try {
    let p = await open();
    ok(/New workflow/.test(await p.textContent('#cv')) || (await p.$$('#cv .nd')).length >= 2, 'a new workflow to start from');
    await p.click('[data-tpl="tuning"]'); ok(await msg(p, /Draft made from the template/), 'a template makes a draft');
    ok(/Detection and alert tuning agent/.test(await p.textContent('#cv')) && /every 24 h/.test(await p.textContent('#cv')), 'the flow shows the trigger and the agent');
    await p.click('[data-blk="action"]'); ok((await p.$$('#cv .nd')).length === 6, 'a block is added at the end'); ok(/Step 5/.test(await p.textContent('#cfgh')), 'its settings open');
    await p.selectOption('#cfg select[data-s="action"]', 'create_case'); await p.click('#b-save'); ok(await msg(p, /changes the SIEM - put a "Person approves" step before it/), 'a change without an approval step is refused, the reason named');
    await p.click('#cv [data-rm="4"]'); await p.click('#b-save'); ok(await msg(p, /Saved as a draft/), 'saved'); ok(/draft/.test(await p.textContent('#wfst')), 'state: draft');
    await p.click('#b-test'); ok(await msg(p, /Test run done/), 'a test run'); await p.waitForSelector('#rdc:not([hidden])'); ok(/Syn noisy: 500 matches/.test(await p.textContent('#rd')), 'the run shows each step\'s output');
    await p.click('#b-submit'); ok(await msg(p, /Submitted/), 'submitted'); await p.close();
    WHO = { user: 'nora.syn', role: 'admin' }; p = await open(); await p.click('#b-publish'); ok(await msg(p, /four-eyes/), 'the author cannot publish'); await p.close();
    WHO = { user: 'syed.syn', role: 'admin' }; p = await open(); await p.click('#b-publish'); ok(await msg(p, /Published/), 'a second administrator publishes'); ok(/published/.test(await p.textContent('#wfst'))); await p.close();
    // a triage workflow with a person's approval and a case
    WHO = { user: 'nora.syn', role: 'operator' }; p = await open();
    await p.selectOption('#wfsel', ''); await p.fill('#cfg input[data-w="name"]', 'Syn triage'); await p.click('[data-blk="agent"]'); await p.click('[data-blk="approval"]'); await p.click('[data-blk="action"]'); await p.selectOption('#cfg select[data-s="action"]', 'create_case');
    await p.click('#b-save'); ok(await msg(p, /Saved as a draft/), 'a custom workflow saved'); await p.click('#b-submit'); await msg(p, /Submitted/); await p.close();
    WHO = { user: 'syed.syn', role: 'admin' }; p = await open(); await p.selectOption('#wfsel', { label: 'Syn triage · pending' }); await p.click('#b-publish'); await msg(p, /Published/); await p.close();
    WHO = { user: 'omar.syn', role: 'operator' }; p = await open(); await p.selectOption('#wfsel', { label: 'Syn triage · published' }); await p.click('#b-run'); ok(await msg(p, /Run started/), 'run started');
    await p.waitForSelector('#rd [data-dec="approve"]'); ok(/waiting for an operator/.test(await p.textContent('#rd')), 'the run waits for a person');
    ok(/Check AL-1 first/.test(await p.textContent('#rd')) && !(await p.evaluate(() => window.PWN)), 'the agent\'s text stays text');
    await p.click('#rd [data-dec="approve"]'); ok(await msg(p, /four-eyes/), 'the starter cannot approve'); await p.close();
    WHO = { user: 'syed.syn', role: 'admin' }; p = await open(); await p.selectOption('#wfsel', { label: 'Syn triage · published' }); await p.click('#runs [data-run]'); await p.waitForSelector('#rd [data-dec="approve"]');
    await p.click('#rd [data-dec="approve"]'); ok(await msg(p, /Approved - the run goes on/), 'an administrator approves'); ok(cases.length === 1 && cases[0].alert_ids.length === 2, 'the case is opened with the alerts'); await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open('?standalone=1', '#err .err'); ok(/for analysts, operators and administrators/.test(await p.textContent('#err')), 'a viewer is told who it is for'); await p.close();
    WHO = { user: 'nora.syn', role: 'operator' }; p = await open('?poc=1&standalone=1'); await p.waitForTimeout(500);
    ok((await p.$$('.zyb-poc-r.br')).length === 1 && /POC: illustrative/.test(await p.textContent('#note')) && /\(POC\)|nora\.poc/.test(await p.textContent('#main')), 'POC: illustrative workflows, one ribbon');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true }); await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "agent-workspace.html"') && / agent-workspace\.html( |$)/m.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' agent-workspace checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
