// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL Group Companies page: a viewer is told why it is closed; the DPO sees the companies with their status and findings
// (hostile text stays text), adds a company, records an agreement term by term, accepts an agreement, records a breach notice
// and that the company was told. Stub ITAM; companies and people are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-group.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let ROLE = 'viewer';
const TERMS = { instructions: 'Instructions', confidentiality: 'Confidentiality', security: 'Security', subprocessors: 'Sub-processors', breach: 'Breach notice', dsr: 'Data-subject help', deletion: 'Deletion', audit: 'Audit', transfer: 'Transfer' };
const VIEW = () => ({ org: 'Synthetic Co', scope: { nca: 'Synthetic Co only - the group companies are not under the NCA ECC <b>x</b>', pdpl: 'Synthetic Co and its group companies' }, dpo: 'huda.syn', can_manage: true, terms: TERMS, services: ['hr-payroll', 'it-services', 'fleet'],
  companies: [{ id: 'GRP-0001', name: 'Synthetic Trading <img src=x onerror=alert(1)>', cr_no: '1010000001', services: ['hr-payroll'], contact: 'privacy.syn', activities: [], frameworks: ['pdpl'], status: 'no agreement', dpa: null, findings: [{ severity: 'high', text: 'No data processing agreement' }] },
    { id: 'GRP-0002', name: 'Synthetic Logistics', services: ['fleet'], activities: ['r1'], status: 'watch', dpa: { ref: 'DPA-2', signed: '2026-01-01', breach_hours: 24, terms: ['instructions'], recorded_by: 'other.syn' }, findings: [{ severity: 'medium', text: 'not accepted' }] }],
  notices: [{ id: 'BRN-0001', company: 'GRP-0002', incident_ref: 'INC-SYN-1', detected: '2026-11-20T06:00', summary: 'Synthetic', notified_at: null }], kpis: { companies: 2, no_agreement: 1, attention: 0, ok: 0, open_notices: 1 } });
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: ROLE === 'viewer' ? 'vera.syn' : 'huda.syn', role: ROLE });
    if (u === '/api/itam/pdpl/group') return ROLE === 'viewer' ? json(403, { error: 'forbidden' }) : json(200, VIEW());
    if (u.startsWith('/api/itam/pdpl/group/')) return body(() => json(200, { ok: true }));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const URL0 = 'http://127.0.0.1:' + srv.address().port + '/pdpl-group.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const errs = []; let answers = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { const a = answers.length ? answers.shift() : ''; if (d.type() === 'confirm') { if (a === 'no') d.dismiss(); else d.accept(); } else d.accept(a); }); await p.goto(URL0); return p; };
  const toast = async (p) => { await p.waitForSelector('.toast', { timeout: 8000 }); const t = await p.$$eval('.toast', (x) => x.map((e) => e.textContent).join(' | ')); await p.$$eval('.toast', (x) => x.forEach((e) => e.remove())); return t; };
  let p = await open(); await p.waitForFunction(() => /names people/.test(document.body.innerText));
  ok(true, 'viewer told why'); await p.close();
  ROLE = 'operator'; p = await open(); await p.waitForSelector('.co');
  ok(!(await p.$('img[src="x"]')), 'hostile text stays text');
  ok(/NCA ECC: Synthetic Co only/.test(await p.textContent('#x-co')) && !(await p.$('#x-co p b b')) && /frameworks: PDPL/.test(await p.textContent('#x-co')), 'scope said, per company PDPL only');
  ok(/No data processing agreement/.test(await p.textContent('#x-co')) && /not accepted/.test(await p.textContent('#x-co')), 'status and findings');
  await p.fill('#g-n', 'Synthetic Services'); await p.fill('#g-cr', '1010000002'); await p.check('[data-gs="it-services"]'); await p.click('#g-add'); await toast(p);
  const add = posts.find((x) => x[1] === '/api/itam/pdpl/group/companies'); ok(add && add[2].name === 'Synthetic Services' && add[2].services.join() === 'it-services' && add[2].cr_no === '1010000002', 'company added: ' + JSON.stringify(add && add[2]));
  answers = ['DPA-SYN-1', '2026-01-01', '2027-01-01', '48', 'yes', 'yes', 'no', 'yes', 'yes', 'no', 'yes', 'yes', 'yes'];
  await p.click('[data-dpa="GRP-0001"]'); await toast(p);
  const dpa = posts.find((x) => /GRP-0001\/dpa$/.test(x[1])); ok(dpa && dpa[2].ref === 'DPA-SYN-1' && dpa[2].breach_hours === 48 && dpa[2].terms.length === 7 && !dpa[2].terms.includes('security') && !dpa[2].terms.includes('dsr'), 'agreement terms one by one: ' + JSON.stringify(dpa && dpa[2]));
  answers = ['yes']; await p.click('[data-acc="GRP-0002"]'); await toast(p); ok(posts.some((x) => /GRP-0002\/dpa\/accept$/.test(x[1])), 'accept');
  answers = ['2026-11-21T09:00', 'e-mail to privacy.syn']; await p.click('[data-told="BRN-0001"]'); await toast(p);
  ok(posts.some((x) => /BRN-0001\/notified$/.test(x[1]) && x[2].notified_at === '2026-11-21T09:00'), 'told recorded');
  await p.selectOption('#b-c', 'GRP-0002'); await p.fill('#b-r', 'INC-SYN-2'); await p.fill('#b-d', '2026-11-22T10:30'); await p.fill('#b-s', 'Synthetic incident'); await p.click('#b-add'); await toast(p);
  const br = posts.find((x) => x[1] === '/api/itam/pdpl/group/notices'); ok(br && br[2].company === 'GRP-0002' && br[2].detected === '2026-11-22T10:30', 'notice recorded');
  await p.close();
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
