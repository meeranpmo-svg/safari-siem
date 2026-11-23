// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the IT Audit Team page (audit-team.html) against the REAL ITAM engine, SYNTHETIC data only: an administrator
// names the Head of Audit (helper text on every field); the lead auditor proposes the plan (itemised reasons shown) and submits
// it; the Head of Audit approves; the lead opens an engagement, moves it to fieldwork, draws a judgemental sample, records the
// exceptions, adds and concludes a workpaper; the Head of Audit reviews it; a finding with a hostile title stays text; the
// lead writes the summary and signs; the Head of Audit approves and the report is final with its hash; the brief, the findings
// list and a viewer's refusal render without errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-team.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const ADM = { user: 'syed', role: 'admin' }, HEAD = { user: 'hana.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
  const off = e.app.store.collection('offboarding');
  for (let i = 1; i <= 6; i++) off.put({ id: 'OFF-000' + i, username: 'leaver' + i + '.syn', last_day: '2026-0' + i + '-15', requested_by: 'hr.syn', status: 'completed', disable: { approved_by: i === 2 ? 'hr.syn' : 'mgr.syn' }, disabled: { at: '2026-0' + i + '-15T20:00:00Z' } });
  e.app.store.collection('grc_risks').put({ id: 'RSK-0001', status: 'open', description: 'Leaver accounts stay enabled (synthetic)', category: 'People', likelihood: 4, impact: 5, owner: 'omar.syn' });
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
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
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  const posted = (p, re) => p.waitForResponse((r) => re.test(r.url()) && r.request().method() === 'POST', { timeout: 10000 });
  const as = async (p, who, tab) => { WHO = who; await p.reload(); await p.waitForSelector('#kpis .card', { timeout: 15000 }); if (tab) await p.click('[data-tab="' + tab + '"]'); };
  let dialogText = 'Confirmed against the offboarding record (synthetic)';
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept(dialogText));
    await p.goto(base + 'audit-team.html?standalone=1'); await p.waitForSelector('#kpis .card', { timeout: 15000 });
    ok(/Nothing due or overdue/.test(await p.textContent('#brief')), 'an empty brief says so, with no invented items');
    // profile (administrator)
    await p.click('[data-tab="profile"]'); await p.waitForSelector('#proff [name=head_of_audit]');
    ok(await p.$$eval('#proff input[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text on every profile field');
    await p.fill('#proff [name=head_of_audit]', HEAD.user); await p.fill('#proff [name=auditors]', 'laila.syn, adel.syn'); await p.fill('#proff [name=engagements_per_year]', '4');
    await Promise.all([posted(p, /ia\/profile$/), p.click('#proff [type=submit]')]);
    // the plan: proposed by the lead with itemised reasons, approved by the Head of Audit
    await as(p, LEAD, 'plan'); await p.fill('#pyear', '2027'); await p.dispatchEvent('#pyear', 'change');
    await Promise.all([posted(p, /plans\/propose$/), p.click('#propose')]);
    await p.waitForSelector('#plan table', { timeout: 10000 });
    const ptxt = await p.textContent('#plan');
    ok(/Joiners, movers and leavers/.test(ptxt) && /risk register: 1 linked risk/.test(ptxt) && /RSK-0001/.test(ptxt), 'the linked risk is named in the reasons');
    await Promise.all([posted(p, /\/submit$/), p.click('#psubmit')]);
    await as(p, HEAD, 'plan'); await p.fill('#pyear', '2027'); await p.dispatchEvent('#pyear', 'change'); await p.waitForSelector('[data-pdec="approve"]', { timeout: 10000 });
    await Promise.all([posted(p, /\/decide$/), p.click('[data-pdec="approve"]')]);
    await p.waitForFunction(() => /approved/.test(document.getElementById('plan').textContent), null, { timeout: 8000 });
    ok(true, 'plan approved by the Head of Audit');
    // an engagement, fieldwork, a judgemental sample with exceptions
    await as(p, LEAD, 'eng'); await p.click('#newEng'); await p.waitForSelector('#engf [name=title]');
    ok(await p.$$eval('#engf input[name], #engf select[name], #engf textarea[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text on every engagement field');
    await p.fill('#engf [name=title]', 'Leavers 2026 (synthetic)'); await p.selectOption('#engf [name=area]', 'joiners'); await p.fill('#engf [name=auditee_dept]', 'Human Resources');
    await p.fill('#engf [name=auditee_owner]', 'omar.syn'); await p.fill('#engf [name=lead]', LEAD.user); await p.fill('#engf [name=objectives]', 'Leavers lose access on their last day'); await p.fill('#engf [name=scope]', 'All 2026 leavers');
    await p.fill('#engf [name=start]', '2027-01-10'); await p.fill('#engf [name=fieldwork_end]', '2027-01-31'); await p.fill('#engf [name=report_due]', '2027-02-15'); await p.fill('#engf [name=plan_item]', 'PLAN-2027:joiners');
    await Promise.all([posted(p, /ia\/engagements$/), p.click('#engf [type=submit]')]);
    ok(await zd(p, /ENG-2027-001 · Leavers 2026/), 'the engagement opens after it is created');
    ok(await p.$eval('#zd', (x) => /no previous report on file/.test(x.textContent) && !!x.querySelector('a[href*="audit-start.html"]')), 'the missing previous report is named, with the way to upload it');
    { const id = await p.$eval('#zd', (x) => (/\b([A-Z]+-\d{4}-\d{3})\b/.exec(x.textContent) || [])[1] || '');
      const all = (await e.req('GET', '/ia/engagements', { user: LEAD.user, role: LEAD.role })).json, eng = all.find((x) => x.id === id) || all[0];
      await e.req('POST', '/ia/engagements/' + eng.id + '/prior-none', { body: { note: 'first audit of this area (synthetic)' }, user: LEAD.user, role: LEAD.role });
      await as(p, LEAD, 'eng'); await p.click('#engs tr[data-eng="' + eng.id + '"]'); await p.waitForSelector('#zd [data-adv="fieldwork"]');
      ok(await p.$eval('#zd', (x) => /Previous audit: none - first audit/.test(x.textContent)), 'the recorded "no previous audit" is shown'); }
    await Promise.all([posted(p, /advance$/), p.click('#zd [data-adv="fieldwork"]')]);
    await p.waitForSelector('#smpf [name=population]', { timeout: 10000 });
    await p.selectOption('#smpf [name=population]', 'leavers'); await p.fill('#smpf [name=size]', '2'); await p.selectOption('#smpf [name=method]', 'judgemental'); await p.fill('#smpf [name=refs]', 'OFF-0002, OFF-0004');
    await Promise.all([posted(p, /\/samples$/), p.click('#smpf [type=submit]')]);
    ok(await zd(p, /SMP-001 · Leavers/) && await zd(p, /2 of 6/), 'the sample states its size and population');
    ok(await p.$$eval('#zd .badge', (b) => b.some((x) => x.textContent === 'fail')), 'the suggested test fails for the self-approved leaver');
    await Promise.all([posted(p, /items\/OFF-0002$/), p.click('#zd [data-ref="OFF-0002"][data-r="exception"]')]);
    await p.waitForSelector('#zd [data-ref="OFF-0004"][data-r="pass"]'); await Promise.all([posted(p, /items\/OFF-0004$/), p.click('#zd [data-ref="OFF-0004"][data-r="pass"]')]);
    ok(await zd(p, /exception/) && await zd(p, /Confirmed against the offboarding record/), 'the auditor\'s result is recorded with the note');
    // a workpaper, concluded, then reviewed by the Head of Audit
    await p.waitForSelector('#wpf [name=title]'); await p.fill('#wpf [name=title]', 'Leaver approvals'); await p.fill('#wpf [name=objective]', 'Approved by a second person'); await p.fill('#wpf [name=procedure]', 'Inspect each sampled leaver'); await p.selectOption('#wpf [name=sample]', 'SMP-001');
    await Promise.all([posted(p, /\/workpapers$/), p.click('#wpf [type=submit]')]);
    await p.waitForSelector('#zd [data-wc]'); await p.click('#zd [data-wc]'); await p.waitForSelector('#wcf [name=conclusion]');
    await p.selectOption('#wcf [name=conclusion]', 'partially_effective'); await p.fill('#wcf [name=summary]', 'One of two leavers was approved by the requester (synthetic)');
    await Promise.all([posted(p, /conclude$/), p.click('#wcf [type=submit]')]);
    // a finding (hostile title stays text)
    await p.waitForSelector('#ffm [name=title]');
    for (const [k, v] of [['title', XSS + ' Self-approved leaver'], ['condition', '1 of 2 sampled leavers'], ['criteria', 'Four eyes'], ['cause', 'No check'], ['effect', 'Abuse possible'], ['recommendation', 'Block self-approval'], ['owner', 'omar.syn']]) await p.fill('#ffm [name=' + k + ']', v);
    await p.selectOption('#ffm [name=rating]', 'medium'); await p.check('#ffm [name=samples][value="SMP-001/OFF-0002"]');
    await Promise.all([posted(p, /\/findings$/), p.click('#ffm [type=submit]')]);
    ok(await zd(p, /IAF-001/) && !(await p.$('#zd img[src="x"]')), 'the hostile title is shown as text');
    await p.click('#zd [data-fo="IAF-001"]'); await p.waitForSelector('#fa-issue [type=submit]');
    await Promise.all([posted(p, /\/issue$/), p.click('#fa-issue [type=submit]')]);
    ok(await zd(p, /issued/), 'the finding is issued');
    await as(p, HEAD, 'eng'); await p.click('#engs tr[data-eng="ENG-2027-001"]'); await p.waitForSelector('#zd [data-wr][data-d="accept"]');
    await Promise.all([posted(p, /review$/), p.click('#zd [data-wr][data-d="accept"]')]);
    ok(await zd(p, /reviewed by hana.syn/), 'the Head of Audit reviewed the workpaper');
    // the report: summary, sign, approve
    await as(p, LEAD, 'eng'); await p.click('#engs tr[data-eng="ENG-2027-001"]'); await p.waitForSelector('#zd [data-adv="draft_report"]');
    await Promise.all([posted(p, /advance$/), p.click('#zd [data-adv="draft_report"]')]);
    await p.waitForSelector('#zd [data-rep]'); await p.click('#zd [data-rep]'); await p.waitForSelector('#sumf [name=summary]');
    ok(await zd(p, /Needs improvement/), 'the opinion follows the findings and conclusions');
    await p.fill('#sumf [name=summary]', 'The leaver approval control needs improvement: one self-approval was found (synthetic).');
    await Promise.all([posted(p, /summary$/), p.click('#sumf [type=submit]')]);
    await p.waitForSelector('#zd [data-sign]'); await Promise.all([posted(p, /sign$/), p.click('#zd [data-sign]')]);
    ok(await zd(p, /signed by laila.syn/), 'signed by the lead');
    await as(p, HEAD, 'eng'); await p.click('#engs tr[data-eng="ENG-2027-001"]'); await p.waitForSelector('#zd [data-rep]'); await p.click('#zd [data-rep]'); await p.waitForSelector('#zd [data-appr]');
    await Promise.all([posted(p, /approve$/), p.click('#zd [data-appr]')]);
    ok(await zd(p, /final/) && await zd(p, /approved by hana.syn · hash [0-9a-f]{16}/), 'the report is final, approved and hashed');
    // findings list and the brief
    await as(p, LEAD, 'find'); await p.waitForSelector('#finds table', { timeout: 10000 });
    ok(/IAF-001/.test(await p.textContent('#finds')) && !(await p.$('#finds img[src="x"]')), 'the findings list shows it, as text');
    await p.click('[data-tab="brief"]'); await p.waitForFunction(() => !/Loading/.test(document.getElementById('brief').textContent), null, { timeout: 8000 });
    ok(true, 'the brief renders');
    // a viewer is refused, with the reason, and nothing breaks
    WHO = VIEW; await p.reload(); await p.waitForFunction(() => /operator role/.test(document.getElementById('brief').textContent), null, { timeout: 10000 }).then(() => ok(true, 'viewer refused with the reason'), () => ok(false, 'viewer refused with the reason'));
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } catch (x) { ok(false, 'exception: ' + (x && x.stack || x)); }
  await browser.close(); srv.close(); await e.close();
  console.log(bad ? `${bad}/${n} FAILED` : `all ${n} checks passed`);
  process.exit(bad ? 1 : 0);
})();
