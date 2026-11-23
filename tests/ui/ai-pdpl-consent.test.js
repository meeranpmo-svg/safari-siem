// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI PDPL Consultant → Consent ledger and Retention tabs (ai-pdpl.html), stubbed ITAM, SYNTHETIC data: purposes with
// counts and findings, ledger integrity badge, issue a key (shown once) and revoke, look up one person, the integration
// note; retention rules with next destruction, plan → approve / reject → record as done posting the right bodies, a
// four-eyes refusal shown, escaping, operator-only messages. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-pdpl-consent.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let APPROVE403 = false, RET403 = false;
const VIEW = { engine: 'python', connected: true, compliance_pct: 10, counts: { compliant: 0, partial: 0, non_compliant: 0, not_applicable: 0, auto_pass: 0, not_assessed: 1 }, requirements: [], findings: [], readiness: { ready: false, blockers: [], digest: 'sha256:' + 'a'.repeat(64) }, statement: { status: 'none' }, note: 'n' };
const CONSENT = () => ({ chain: { ok: true, length: 42 }, channels: ['web', 'app', 'call_centre'], api: { events: 'POST /agent/consent/events', check: 'GET /agent/consent/check', auth: 'Authorization: Bearer <consent key>' },
  findings: [{ key: 'P-05:consent:x:stale', severity: 'medium', title: '<img src=x onerror=alert(1)> 3 consent(s) under an older notice', recommendation: 'ask again' }],
  purposes: [{ id: 'PD-CONSENT_PURPOSE-001', title: 'Marketing offers (synthetic)', activity: 'Marketing', version: 2, explicit: true, marketing: true, active: 120, withdrawn: 9, stale_version: 3, events_30d: 17, channels: { web: 100, call_centre: 9 } }],
  keys: [{ id: 'CK-001', name: 'Customer portal', purposes: null, created_by: 'syed', created_at: '2026-10-01T00:00:00Z', last_used: '2026-10-20T07:00:00Z', revoked_at: null }] });
const RET = () => ({ overdue: 1, pending_approval: 1, note: 'The platform never deletes data.', rules: [{ id: 'PD-RETENTION-001', name: 'Marketing contacts', systems: ['CRM-SYN'], period_months: 24, trigger: 'last_contact', action: 'anonymise', legal_ref: 'PDPL Art. 18',
  due: { next_due: '2026-09-01T00:00:00.000Z', overdue: true }, runs: [{ id: 'PD-DESTRUCTION-001', status: 'planned', cutoff: '2024-06-30' }, { id: 'PD-DESTRUCTION-002', status: 'approved', cutoff: '2024-03-31', approved_by: 'huda.syn' }] }] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), q = new URLSearchParams(req.url.split('?')[1] || ''), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/pdpl') return json(200, VIEW);
    if (u === '/api/itam/pdpl/consent') return json(200, CONSENT());
    if (u === '/api/itam/pdpl/consent/keys') return body((b) => json(200, { id: 'CK-002', name: b.name, key: 'ck_' + 'a1'.repeat(24), note: 'Shown once' }));
    if (u === '/api/itam/pdpl/consent/keys/CK-001/revoke') return body(() => json(200, { id: 'CK-001', revoked: true }));
    if (u === '/api/itam/pdpl/consent/lookup') return json(200, { subject_ref: 'f'.repeat(40), note: 'The identifier you typed is not stored', current: [{ purpose: 'PD-CONSENT_PURPOSE-001', title: 'Marketing offers (synthetic)', status: 'withdrawn', version: 1, current_version: 2 }],
      history: [{ receipt: 'CE-7', at: '2026-10-01T10:00:00.000Z', purpose: 'PD-CONSENT_PURPOSE-001', action: 'grant', channel: 'web', evidence_ref: '<b>FORM-SYN</b>' }, { receipt: 'CE-9', at: '2026-10-10T10:00:00.000Z', purpose: 'PD-CONSENT_PURPOSE-001', action: 'withdraw', channel: 'call_centre' }], q: q.get('subject') });
    if (u === '/api/itam/pdpl/retention') return RET403 ? json(403, { error: 'requires operator' }) : json(200, RET());
    if (u === '/api/itam/pdpl/destruction') return body((b) => json(200, { id: 'PD-DESTRUCTION-003', status: 'planned' }));
    if (/^\/api\/itam\/pdpl\/destruction\/PD-DESTRUCTION-00\d\/(approve|reject|done)$/.test(u)) return body(() => (APPROVE403 && /approve$/.test(u) ? json(403, { error: 'four-eyes: the person who planned the destruction cannot approve it' }) : json(200, { id: u.split('/')[5], status: u.split('/').pop() === 'done' ? 'executed' : u.split('/').pop() + 'd' })));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/ai-pdpl.html?standalone=1#consent'); await p.waitForSelector('#cpur table');
    const ct = await p.$eval('#v-consent', (e) => e.innerText);
    ok(/intact · 42 entries/.test(ct) && /Marketing offers \(synthetic\)/.test(ct) && /explicit/.test(ct) && /web 100/.test(ct) && /older notice/.test(ct), 'purposes, integrity, findings');
    ok(/POST \/agent\/consent\/events/.test(ct) && /Bearer/.test(ct), 'integration note for the portal team');
    ok(await p.$$eval('#v-consent img', (a) => a.length) === 0, 'finding escaped');
    await p.fill('#ckname', 'Mobile app (synthetic)'); await p.click('#ckissue'); await p.waitForSelector('#cknewkey');
    ok(POSTS.find((x) => x[0].endsWith('/consent/keys'))[1].name === 'Mobile app (synthetic)' && /^ck_/.test(await p.$eval('#cknewkey', (e) => e.textContent)), 'key issued and shown once');
    await p.click('[data-ckrevoke="CK-001"]'); await p.waitForTimeout(300); ok(POSTS.some((x) => /CK-001\/revoke$/.test(x[0])), 'revoke posted');
    await p.fill('#csubj', '1012345678'); await p.click('#clook'); await p.waitForSelector('#clres table');
    const lr = await p.$eval('#clres', (e) => e.innerText);
    ok(/withdrawn/.test(lr) && /v1 \(older\)/.test(lr) && /CE-9/.test(lr) && /not stored/.test(lr), 'lookup result');
    ok(await p.$eval('#csubj', (e) => e.value) === '', 'identifier cleared from the box after the lookup');
    ok(await p.$$eval('#clres b', (a) => a.filter((x) => x.textContent === 'FORM-SYN').length) === 0, 'evidence reference escaped');
    // retention
    await p.click('#tabs [data-tab="retention"]'); await p.waitForSelector('#rbody table');
    const rt = await p.$eval('#v-retention', (e) => e.innerText);
    ok(/1 overdue/.test(rt) && /24 months from last_contact, then anonymise/.test(rt) && /\(overdue\)/.test(rt) && /never deletes/.test(rt), 'rules and due');
    await p.click('[data-dplan="PD-RETENTION-001"]'); await p.waitForSelector('#dform'); await p.fill('#dform input[name=cutoff]', '2024-09-30'); await p.click('#dform button[type=submit]'); await p.waitForTimeout(400);
    let last = POSTS[POSTS.length - 1]; ok(last[0].endsWith('/destruction') && last[1].retention_id === 'PD-RETENTION-001' && last[1].system === 'CRM-SYN' && last[1].cutoff === '2024-09-30', 'plan posted: ' + JSON.stringify(last[1]));
    APPROVE403 = true; await p.click('[data-dact="approve"][data-id="PD-DESTRUCTION-001"]'); await p.waitForSelector('#dform'); await p.click('#dform button[type=submit]'); await p.waitForTimeout(400);
    ok(/four-eyes/.test(await p.$eval('#dmsg', (e) => e.textContent)), 'four-eyes refusal shown');
    APPROVE403 = false; await p.click('#dform button[type=submit]'); await p.waitForTimeout(400);
    ok(POSTS.filter((x) => /001\/approve$/.test(x[0])).length === 2, 'approve posted');
    await p.click('[data-dact="reject"][data-id="PD-DESTRUCTION-001"]'); await p.waitForSelector('#dform'); await p.fill('#dform input[name=note]', 'legal hold'); await p.click('#dform button[type=submit]'); await p.waitForTimeout(400);
    last = POSTS[POSTS.length - 1]; ok(/001\/reject$/.test(last[0]) && last[1].note === 'legal hold', 'reject with a note');
    await p.click('[data-dact="done"][data-id="PD-DESTRUCTION-002"]'); await p.waitForSelector('#dform');
    await p.fill('#dform input[name=count]', '1840'); await p.selectOption('#dform select[name=method]', 'anonymised'); await p.fill('#dform input[name=evidence]', 'CHG-SYN-77'); await p.fill('#dform input[name=executed_at]', '2026-10-20T07:00'); await p.click('#dform button[type=submit]'); await p.waitForTimeout(400);
    last = POSTS[POSTS.length - 1]; ok(/002\/done$/.test(last[0]) && last[1].count === 1840 && last[1].method === 'anonymised' && last[1].evidence === 'CHG-SYN-77' && /^2026-10-20T/.test(last[1].executed_at), 'done posted: ' + JSON.stringify(last[1]));
    RET403 = true; const p2 = await browser.newPage(); p2.on('pageerror', (e) => errs.push(e.message));
    await p2.goto(base + '/dashboards/ai-pdpl.html?standalone=1#retention'); await p2.waitForFunction(() => /for operators/.test(document.getElementById('rbody').innerText)); ok(true, 'operator-only message');
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
