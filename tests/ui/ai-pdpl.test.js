// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// AI PDPL Consultant (ai-pdpl.html), stubbed ITAM, SYNTHETIC data: requirements with results and KPIs, the filter, the
// requirement drawer posting a confirmation, the registers (kind switch, add a processing activity: the body carries only
// the declared fields), the operator-only refusal, the compliance statement (not-a-certificate warning, blockers, sign as
// DPO then countersign, a refusal shown), escaping, and not installed. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-pdpl.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let ST = { status: 'none' }, READY = false, REC403 = false, GONE = false;
const rq = (id, title, result, o) => Object.assign({ id, area: 'Governance', title, ref: 'Implementing Regulation Art. 32', procedure: 'Inspect SYN', evidence_expected: 'SYN letter', automated: true, auto: { state: 'pass', detail: 'DPO huda.syn' }, confirmation: null, result, why: 'w', conflict: false }, o);
// the levels are computed with the engine's own helper, so the stub cannot disagree with the real view
const CLV = require(path.join(__dirname, '..', '..', 'backend', 'itam', 'engine', 'compliance-levels')), { PDPL_LEVEL } = require(path.join(__dirname, '..', '..', 'backend', 'itam', 'engine', 'pdpl'));
const withLevels = (v) => Object.assign(v, { levels: CLV.levels(v.requirements, PDPL_LEVEL), by_area: CLV.group(v.requirements, 'area', PDPL_LEVEL), requirements: v.requirements.map((r) => Object.assign({}, r, { level: CLV.levelOf(r.result, PDPL_LEVEL) })) });
const VIEW = () => withLevels({ engine: 'python', connected: true, compliance_pct: READY ? 100 : 12.5, counts: { compliant: READY ? 3 : 0, partial: 0, non_compliant: READY ? 0 : 1, not_applicable: 0, auto_pass: READY ? 0 : 1, not_assessed: READY ? 0 : 1 },
  requirements: [rq('P-01', 'DPO appointed', READY ? 'compliant' : 'auto_pass'), rq('P-09', '<img src=x onerror=alert(1)> breach in 72 h', READY ? 'compliant' : 'non_compliant', { conflict: !READY, auto: { state: 'fail', detail: '1 late notification' } }), rq('P-16', 'Minimum data', READY ? 'compliant' : 'not_assessed', { automated: false, auto: null })],
  findings: [], readiness: { ready: READY, blockers: READY ? [] : ['P-09 breach: late'], digest: 'sha256:' + 'a'.repeat(64) }, statement: ST, note: 'not an SDAIA certificate.' });
const RECS = [{ id: 'PD-ROPA-001', kind: 'ropa', name: 'Claims SYN', legal_basis: 'contract', data_categories: ['identity', 'health'], retention_months: 120, owner: 'Claims', reviewed: '2026-09-01', status: 'active' }, { id: 'profile', kind: 'profile', dpo_user: 'huda.syn' }];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => fn(JSON.parse(b || '{}'))); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/itam/pdpl') && GONE) return json(404, { error: 'not found' });
    if (u === '/api/itam/pdpl') return json(200, VIEW());
    if (u === '/api/itam/pdpl/records' && req.method === 'GET') return REC403 ? json(403, { error: 'requires operator' }) : json(200, { records: RECS });
    if (u === '/api/itam/pdpl/records') return body((b) => { POSTS.push(['rec', b]); json(200, Object.assign({ id: 'PD-ROPA-002' }, b)); });
    if (u === '/api/itam/pdpl/confirm') return body((b) => { POSTS.push(['confirm', b]); json(200, Object.assign(rq(b.id, 'x', 'compliant'), { id: b.id })); });
    if (u === '/api/itam/pdpl/statement') return json(200, { title: 'Personal Data Protection Law (PDPL) - Compliance Statement', organisation: ZYB_ORG.name, generated_at: new Date().toISOString(), basis: 'b', not_certificate: 'This statement is not a certificate issued by SDAIA.', dpo: 'huda.syn', sdaia_ref: 'SYN-REG', compliance_pct: READY ? 100 : 12.5, ready: READY, blockers: READY ? [] : ['P-09 breach: late'], digest: 'sha256:' + 'a'.repeat(64), requirements: VIEW().requirements.map((r) => ({ id: r.id, title: r.title, ref: r.ref, result: r.result, evidence: 'SYN-EV' })), statement: ST });
    if (u === '/api/itam/pdpl/statement/sign') return body((b) => { POSTS.push(['sign', b]); if (b.as === 'management' && ST.status !== 'awaiting_management') return json(409, { error: 'the DPO signs first' });
      ST = b.as === 'dpo' ? { status: 'awaiting_management', digest: b.digest, dpo: { user: 'huda.syn', at: new Date().toISOString() } } : Object.assign({}, ST, { status: 'attested', management: { user: 'cio.syn', at: new Date().toISOString() }, valid_until: new Date(Date.now() + 365 * 864e5).toISOString() }); json(200, ST); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/ai-pdpl.html?standalone=1'); await p.waitForSelector('[data-req]');
    const k = await p.$eval('#kpis', (e) => e.textContent.replace(/\s+/g, ' '));
    const lv = await p.$eval('#lvl', (e) => e.textContent.replace(/\s+/g, ' '));
    ok(/Overall \(fully \/ partially \/ not compliant\)/.test(lv) && /By area/.test(lv) && /Not assessed/.test(lv), 'PDPL in the compliance language: ' + lv.slice(0, 160));
    const asum = await p.$$eval('#lvl .zl-card .zl-pcts', (x) => x.map((e) => [...e.textContent.matchAll(/(\d+)%/g)].reduce((a, m) => a + Number(m[1]), 0)));
    ok(asum.length >= 1 && asum.every((n) => n === 100), 'each PDPL area: four shares adding up to 100: ' + asum.join(','));
    ok(await p.$$eval('#reqs tbody tr', (r) => r.every((x) => /Fully compliant|Partially compliant|Not compliant|Not assessed|Not applicable/.test(x.textContent))), 'every requirement shows its level');
    ok(/12.5%/.test(k) && /Not signed/.test(k), 'KPIs: ' + k);
    // AI / ML band: requirements by level, compliance by area, the registers; what the AI noticed with figures
    await p.waitForFunction(() => { const c = document.getElementById('pd-reg'); return c && c.getAttribute('aria-label'); }, null, { timeout: 8000 }).catch(() => {});
    const pdl = await p.$$eval('#pdband canvas', (x) => x.map((c) => c.getAttribute('aria-label') || ''));
    ok(!(await p.$eval('#pdband', (e) => e.hidden)) && pdl.length === 3 && /Requirements by level/.test(pdl[0]) && /Compliance by area/.test(pdl[1]) && pdl[2].length > 0, 'AI / ML band: ' + pdl.map((x) => x.slice(0, 40)).join(' | '));
    const pdi = (await p.$eval('#pdins', (e) => e.innerText)).replace(/\s+/g, ' ');
    ok(/requirements are not compliant|not assessed yet/.test(pdi) && /weakest area is/.test(pdi) && /compliance statement is not signed/.test(pdi), 'what the AI noticed: ' + pdi);
    ok(await p.$$eval('#reqs img', (a) => a.length) === 0 && /<img src=x/.test(await p.$eval('#reqs', (e) => e.textContent)) && /conflicts with the registers/.test(await p.$eval('#reqs', (e) => e.textContent)), 'requirements escaped, conflict shown');
    await p.selectOption('#filter', 'not_assessed'); ok((await p.$$eval('[data-req]', (a) => a.map((x) => x.dataset.req))).join() === 'P-16', 'filter'); await p.selectOption('#filter', '');
    await p.click('[data-req="P-16"]'); await p.waitForSelector('#cform');
    await p.selectOption('#cform select[name=status]', 'compliant'); await p.fill('#cform input[name=evidence]', 'data map v1'); await p.click('#cform button[type=submit]'); await p.waitForTimeout(400);
    const c = POSTS.find((x) => x[0] === 'confirm'); ok(c && c[1].id === 'P-16' && c[1].status === 'compliant' && c[1].evidence === 'data map v1', 'confirmation posted: ' + JSON.stringify(c));
    await p.keyboard.press('Escape');
    // registers
    await p.click('#tabs [data-tab="registers"]'); await p.waitForSelector('[data-kind]');
    ok(/Claims SYN/.test(await p.$eval('#recs', (e) => e.textContent)) && /health/.test(await p.$eval('#recs', (e) => e.textContent)), 'records of processing listed');
    await p.click('#addrec'); await p.waitForSelector('#rform');
    await p.fill('#rform input[name=name]', 'Motor SYN'); await p.selectOption('#rform select[name=legal_basis]', 'contract'); await p.check('#rform input[name=data_categories][value=identity]'); await p.fill('#rform input[name=retention_months]', '84');
    await p.click('#rform button[type=submit]'); await p.waitForTimeout(400);
    const r = POSTS.find((x) => x[0] === 'rec'); ok(r && r[1].kind === 'ropa' && r[1].name === 'Motor SYN' && r[1].retention_months === 84 && r[1].data_categories.join() === 'identity' && r[1].id === undefined, 'new processing activity posted: ' + JSON.stringify(r && r[1]));
    await p.keyboard.press('Escape');
    await p.click('[data-kind="dsr"]'); ok(/reference only/.test(await p.$eval('#kindhelp', (e) => e.textContent)), 'requests: reference only (PDPL)');
    // statement: not ready, then ready → DPO signs → management countersigns
    await p.click('#tabs [data-tab="statement"]'); await p.waitForFunction(() => /Compliance Statement/.test(document.getElementById('st').textContent));
    ok(/not a certificate issued by SDAIA/.test(await p.$eval('#st', (e) => e.textContent)) && /P-09 breach: late/.test(await p.$eval('#st', (e) => e.textContent)) && await p.$eval('#signdpo', (e) => e.disabled), 'not ready: warning, blockers, signing disabled');
    READY = true; await p.click('#refresh'); await p.waitForFunction(() => !document.getElementById('signdpo').disabled);
    ok(await p.$eval('#signmgmt', (e) => e.disabled), 'countersign disabled until the DPO signs');
    await p.click('#signdpo'); await p.waitForFunction(() => /awaiting the countersignature/.test(document.getElementById('ststate').textContent));
    await p.click('#signmgmt'); await p.waitForFunction(() => /Signed - valid until/.test(document.getElementById('ststate').textContent));
    const s = POSTS.filter((x) => x[0] === 'sign').map((x) => x[1].as + ':' + x[1].digest.slice(0, 9)); ok(s.join() === 'dpo:sha256:aa,management:sha256:aa', 'DPO then management, with the digest: ' + s);
    ok(/cio.syn/.test(await p.$eval('#st', (e) => e.textContent)), 'both signatures on the statement');
    // operator-only registers and not installed
    REC403 = true; await p.goto(base + '/dashboards/ai-pdpl.html?standalone=1&r=2#registers'); await p.waitForTimeout(800);
    ok(/operators and administrators/.test(await p.$eval('#recs', (e) => e.textContent)), 'registers refused for a viewer');
    GONE = true; await p.goto(base + '/dashboards/ai-pdpl.html?standalone=1'); await p.waitForTimeout(800);
    ok(/not installed/.test(await p.$eval('#reqs', (e) => e.textContent)), 'not installed state');
    ok(!errs.length && !dialogs, 'no page errors, no injected script: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
