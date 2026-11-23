// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Privacy Office (pdpl-office.html), stubbed ITAM, SYNTHETIC data: the live route map (8 stations coloured by state, a phase
// opens its steps, evidence and resources), my tasks (acknowledge, mark done), all tasks with filters, reassign, accept risk,
// the organisation with its gaps, the calendar, settings (committee, data owners, deadlines), a steward's view without the
// operator tabs, escaping, no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-office.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let STEWARD = false, ADMIN = false;
const XSS = '<img src=x onerror=alert(1)>';
const PH = ['Mobilise and govern', 'Discover and map', 'Lawful basis and transparency', 'Risk controls', 'Rights and breach readiness', 'Vendors and retention', 'People and culture', 'Assure and maintain'];
const ROADMAP = { progress: 30, note: 'Each step reads the registers (synthetic).',
  phases: PH.map((name, i) => ({ phase: i + 1, name, goal: 'Goal ' + (i + 1), name_ar: 'المرحلة العربية ' + (i + 1), goal_ar: 'الهدف ' + (i + 1), resources_ar: ['مسؤول حماية البيانات'], when_ar: 'الأسابيع 0-4 (تقدير)', state: i === 0 ? 'done' : i < 3 ? 'active' : 'todo', done: i === 0 ? 5 : i < 3 ? 1 : 0, steps: i === 0 ? 5 : 3, progress: i === 0 ? 100 : i < 3 ? 33 : 0,
    resources: ['DPO', 'Data stewards'], when: 'Weeks 0-4 (estimate)', open_tasks: i === 1 ? 2 : 0, overdue_tasks: i === 1 ? 1 : 0 })),
  steps: [{ phase: 2, id: 'discover', label: 'Discover personal data ' + XSS, label_ar: 'اكتشاف البيانات الشخصية ' + XSS, evidence_ar: 'فُحص 2 مصدر، وقُرئ 1', state: 'active', evidence: '2 source(s) scanned, 1 read', open_findings: 1, requirements: [], page: 'pdpl-catalog.html' },
    { phase: 2, id: 'ropa', label: 'Complete the register', state: 'todo', evidence: '0 processing activities', open_findings: 0, requirements: ['P-04'], page: 'pdpl-ropa.html' }],
  maintain: [{ cadence: 'Daily', what: 'New tasks routed', who: 'DPO', cadence_ar: 'يومياً', what_ar: 'توجيه المهام', who_ar: 'مسؤول حماية البيانات' }, { cadence: 'Yearly', what: 'RoPA campaign', who: 'Stewards' }], note_ar: 'كل خطوة تُقرأ من السجلات' };
const T1 = { id: 'PO-00001', key: 'f:P-07:dpia:PD-ROPA-001', source: 'finding', title: 'DPIA missing for "Medical claims (synthetic)" ' + XSS, severity: 'high', requirement: 'P-07', department: 'Claims', assignee: 'faisal.syn',
  why: 'data steward of Claims', why_ar: 'بصفته مسؤول البيانات في إدارة Claims', title_ar: 'لا يوجد تقييم أثر ' + XSS, recommendation_ar: 'أكمل تقييم الأثر', due: '2026-10-27T08:00:00Z', status: 'open', overdue: true, escalation: 1, escalated_to: 'huda.syn', recommendation: 'Run the DPIA wizard', evidence: ['health data'], history: [{ at: '2026-10-20T08:00:00Z', by: 'system:privacy-office', what: 'raised' }, { at: '2026-10-28T08:00:00Z', by: 'system:privacy-office', what: 'overdue - escalated to the DPO huda.syn' }] };
const T2 = { id: 'PO-00002', key: 'duty:committee', source: 'duty', title: 'Privacy committee meeting (quarterly)', severity: 'medium', requirement: 'P-01', department: null, assignee: null, why: 'nobody named', due: '2026-11-19T08:00:00Z', status: 'claimed', overdue: false, escalation: 0, history: [] };
const ORG = { dpo: 'huda.syn', dpo_deputy: null, functions: [{ function: 'requests', label: 'Data subject requests', label_ar: 'طلبات أصحاب البيانات', user: 'mona.syn', deputy: null }, { function: 'sdaia', label: 'SDAIA liaison and documentation', user: null, deputy: null }],
  departments: [{ department: 'Claims', data_steward: 'faisal.syn', deputy: null, champion: null }], committee: { chair: null, members: [] }, owners: [] };
const VIEW = () => ({ org: ORG, gaps: ['Claims has no privacy champion', 'No privacy committee chair - level-2 escalations go to the DPO'], gaps_ar: ['لا يوجد سفير خصوصية في إدارة Claims'], calendar: [{ key: 'duty:committee', title: 'Privacy committee meeting (quarterly)', due: '2026-10-20T08:00:00Z', assignee: 'huda.syn', department: null, overdue: true, soon: false }],
  roadmap: ROADMAP, sla_days: { critical: 2, high: 7, medium: 30, low: 60 }, escalate_days: 7, tasks: [T1, T2], me: 'huda.syn', is_dpo: true, can_configure: true,
  totals: { open: 2, overdue: 1, escalated: 1, claimed: 1, accepted: 0, unassigned: 1 } });
const NTF = () => ({ email_enabled: true, teams_enabled: false, smtp: { host: 'mail.example.test', port: 587, from: 'privacy@example.test', starttls: true, reject_unauthorized: true }, smtp_password_set: true, teams_webhook_set: false, teams_host: null,
  digest_hour: 8, portal_url: 'https://portal.example.test', contacts: [{ user: 'faisal.syn', email: 'faisal@example.test', lang: 'ar' }], language: 'both', teams_language: null, vault: 'available',
  outbox: [{ id: 'm1', at: '2026-10-20T08:00:00Z', channel: 'email', event: 'raised', task: 'PO-00001', to: ['faisal.syn'], status: 'failed', error: '550 relay denied ' + XSS, attempts: 1, lang: 'ar' }] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: STEWARD ? 'faisal.syn' : ADMIN ? 'syed' : 'huda.syn', role: STEWARD ? 'viewer' : ADMIN ? 'admin' : 'operator' });
    if (u === '/api/itam/pdpl/office/mine') return json(200, { tasks: STEWARD ? [T1] : [T1], roadmap: ROADMAP, me: 'x', roles: STEWARD ? ['data steward - Claims'] : ['DPO'], maintain: ROADMAP.maintain });
    if (u === '/api/itam/pdpl/office') return STEWARD ? json(403, { error: 'requires operator' }) : json(200, VIEW());
    if (u === '/api/itam/pdpl/office/notify' && req.method === 'GET') return json(200, NTF());
    if (u === '/api/itam/pdpl/office/notify' || u === '/api/itam/pdpl/office/contacts') return body(() => json(200, NTF()));
    if (u === '/api/itam/pdpl/office/notify/test') return body((b) => json(200, { channel: b.channel, status: 'sent', error: null }));
    if (u === '/api/itam/pdpl/office/run') return body(() => json(200, { tasks: 2, events: 1 }));
    if (u === '/api/itam/pdpl/office/config') return body((b) => json(200, b));
    if (/^\/api\/itam\/pdpl\/office\/tasks\/PO-\d+\//.test(u)) return body(() => json(200, { id: 'PO-00001' }));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const last = (end) => [...POSTS].reverse().find((x) => x[0].endsWith(end));
  try {
    const p = await browser.newPage(); const errs = []; await p.addInitScript(() => { window.ZYB_ARABIC = false; }); let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/pdpl-office.html?standalone=1'); await p.waitForSelector('#route svg [data-phase="8"]');
    await p.waitForFunction(() => !document.querySelector('[data-tab="all"]').hidden);
    ok(await p.$$eval('#route svg [data-phase]', (a) => a.length) === 8, 'eight stations on the route');
    ok(await p.$eval('#route svg [data-phase="1"] circle:nth-of-type(3)', (c) => c.getAttribute('fill')) === '#2fb344' && await p.$eval('#route svg [data-phase="2"] circle:nth-of-type(3)', (c) => c.getAttribute('fill')) === '#f59f00'
      && await p.$eval('#route svg [data-phase="5"] circle:nth-of-type(3)', (c) => c.getAttribute('fill')) === '#5a6a80', 'stations coloured done / in progress / not started');
    const mk = await p.$eval('#mapk', (e) => e.innerText); ok(/30%/.test(mk) && /Discover and map/.test(mk), 'KPIs: progress and current phase');
    ok(/1 overdue/.test(await p.$eval('#route', (e) => e.textContent)), 'overdue tasks on the station');
    ok(/Daily/.test(await p.$eval('#cycle', (e) => e.innerText)), 'maintenance cycle');
    await p.click('#route svg [data-phase="2"]'); await p.waitForSelector('#zd-b .step');
    const ph = await p.$eval('#zd-b', (e) => e.innerText);
    ok(/2 source\(s\) scanned/.test(ph) && /planning estimate/i.test(ph) && /Data stewards/.test(ph) && /1 of 1 departments with a data steward/.test(ph), 'phase drawer: steps, evidence, resources, who is named');
    ok(await p.$$eval('#zd-b img', (a) => a.length) === 0, 'step labels escaped');
    await p.keyboard.press('Escape');
    // my tasks
    await p.click('[data-tab="mine"]'); await p.waitForSelector('#mylist [data-open="PO-00001"]');
    ok(/Your roles: DPO/.test(await p.$eval('#myroles', (e) => e.textContent)) && await p.$$eval('#mylist img', (a) => a.length) === 0, 'my tasks: roles, escaped');
    await p.click('#mylist [data-open="PO-00001"]'); await p.waitForSelector('#tack');
    const dr = await p.$eval('#zd-b', (e) => e.innerText); ok(/at the DPO/.test(dr) && /Run the DPIA wizard/.test(dr) && /raised/.test(dr), 'task drawer: status, what to do, history');
    ok(!/[\u0600-\u06ff]/.test(dr) && !(await p.$('#zd-b [dir="rtl"]')) && await p.$$eval('#zd-b img', (a) => a.length) === 0, 'English drawer: no Arabic copy while Arabic is switched off, escaped');
    await p.click('#tack'); await p.waitForTimeout(300); ok(last('/ack'), 'acknowledged');
    await p.click('#mylist [data-open="PO-00001"]'); await p.waitForSelector('#tdone');
    await p.fill('#tdone-note', 'DPIA drafted with the medical team (synthetic)'); await p.click('#tdone button[type=submit]'); await p.waitForTimeout(300);
    let x = last('/done'); ok(x && x[0].includes('PO-00001') && /medical team/.test(x[1].note), 'mark done posted');
    // all tasks, filters, reassign, accept risk
    await p.click('[data-tab="all"]'); await p.waitForSelector('#alllist [data-open]');
    ok(/Escalated/i.test(await p.$eval('#kpis', (e) => e.innerText)) && await p.$$eval('#alllist [data-open]', (a) => a.length) === 2, 'all tasks + KPIs');
    await p.selectOption('#fstat', 'overdue'); ok(await p.$$eval('#alllist [data-open]', (a) => a.length) === 1, 'overdue filter');
    await p.selectOption('#fstat', 'unassigned'); ok(await p.$eval('#alllist', (e) => /PO-00002/.test(e.innerText)), 'unassigned filter');
    await p.selectOption('#fstat', 'open'); await p.click('#alllist [data-open="PO-00001"]'); await p.waitForSelector('#treas');
    await p.fill('#treas-user', 'omar.syn'); await p.fill('#treas-reason', 'records manager'); await p.click('#treas button[type=submit]'); await p.waitForTimeout(300);
    x = last('/reassign'); ok(x && x[1].user === 'omar.syn' && x[1].reason === 'records manager', 'reassign posted');
    await p.click('#alllist [data-open="PO-00001"]'); await p.waitForSelector('#trisk');
    await p.fill('#trisk-reason', 'DPIA scheduled with the medical team next quarter'); await p.fill('#trisk-until', '2027-01-31'); await p.click('#trisk button[type=submit]'); await p.waitForTimeout(300);
    x = last('/accept-risk'); ok(x && x[1].until === '2027-01-31', 'accept risk posted');
    // organisation, calendar, settings
    await p.click('[data-tab="org"]'); const og = await p.$eval('#org', (e) => e.innerText);
    ok(/huda\.syn/.test(og) && /no champion/.test(og) && /no owner/.test(og) && /no chair/.test(og), 'organisation shows who is named and who is missing');
    ok(/no privacy champion/.test(await p.$eval('#gaps', (e) => e.innerText)), 'gaps listed');
    await p.click('[data-tab="cal"]'); ok(/Privacy committee meeting/.test(await p.$eval('#cal', (e) => e.innerText)), 'calendar');
    await p.click('[data-tab="cfg"]'); await p.waitForSelector('#cfgform');
    await p.fill('#cfgform-chair', 'syed'); await p.fill('#cfgform-members', 'faisal.syn, reem.syn'); await p.fill('#cfgform-owners', 'CLAIMS-SQL = omar.syn\nbad line'); await p.fill('#cfgform-sla_high', '5');
    await p.click('#cfgform button[type=submit]'); await p.waitForTimeout(300);
    x = last('/office/config'); ok(x && x[1].committee.chair === 'syed' && x[1].committee.members.join() === 'faisal.syn,reem.syn' && x[1].owners.length === 1 && x[1].owners[0].user === 'omar.syn' && x[1].sla_days.high === 5, 'settings posted: ' + JSON.stringify(x && x[1]));
    await p.click('#runnow'); await p.waitForTimeout(300); ok(last('/office/run'), 'route now');
    // notifications, as the DPO (operator): contacts editable, relay read-only
    await p.click('[data-tab="ntf"]'); await p.waitForSelector('#ctform');
    ok(!(await p.$('#ntform')) && /An administrator sets the mail relay/.test(await p.$eval('#ntfbody', (e) => e.innerText)), 'the DPO cannot change the relay');
    ok(/550 relay denied/.test(await p.$eval('#outbox', (e) => e.innerText)) && await p.$$eval('#outbox img', (a) => a.length) === 0, 'outbox shown, escaped');
    ok(/faisal\.syn = faisal@example\.test = ar/.test(await p.$eval('#ctform-contacts', (e) => e.value)), 'contact language shown');
    await p.fill('#ctform-contacts', 'faisal.syn = faisal@example.test = AR\nhuda.syn = huda@example.test\nnot a line'); await p.click('#ctform button[type=submit]'); await p.waitForTimeout(300);
    x = last('/office/contacts'); ok(x && x[1].contacts.length === 2 && x[1].contacts[1].email === 'huda@example.test' && x[1].contacts[0].lang === 'ar' && !('lang' in x[1].contacts[1]), 'contacts posted with their language');
    // as an administrator: the relay and the webhook (write-only fields), tests
    ADMIN = true; const p3 = await browser.newPage(); p3.on('pageerror', (e) => errs.push(e.message)); await p3.addInitScript(() => { window.ZYB_ARABIC = false; });
    await p3.goto(base + '/dashboards/pdpl-office.html?standalone=1'); await p3.waitForFunction(() => !document.querySelector('[data-tab="ntf"]').hidden);
    await p3.click('[data-tab="ntf"]'); await p3.waitForSelector('#ntform');
    ok(await p3.$eval('#ntform [name="smtp_password"]', (e) => e.type) === 'password' && await p3.$eval('#ntform [name="smtp_password"]', (e) => e.value) === '', 'password field write-only');
    ok(/SMTP password set/i.test(await p3.$eval('#ntfbody', (e) => e.innerText)), 'says the password is set without showing it');
    await p3.fill('#ntform [name="teams_webhook"]', 'https://prod.logic.azure.com/workflows/x?sig=synthetic'); await p3.check('#ntform [name="teams_enabled"]'); await p3.fill('#ntform [name="port"]', '25');
    ok(!(await p3.$('#ntform [name="language"]')) && !(await p3.$('#ntform [name="teams_language"]')), 'no message-language setting while Arabic is switched off');
    await p3.click('#ntform button[type=submit]'); await p3.waitForTimeout(300);
    x = last('/office/notify'); ok(x && x[1].teams_enabled === true && /sig=synthetic/.test(x[1].teams_webhook) && x[1].smtp.port === 25 && x[1].smtp.host === 'mail.example.test' && !('language' in x[1]) && !('teams_language' in x[1]) && !('smtp_password' in x[1]), 'settings posted (password untouched): ' + JSON.stringify(x && x[1]));
    await p3.click('[data-ntest="email"]'); await p3.waitForTimeout(300); ok(last('/notify/test') && last('/notify/test')[1].channel === 'email', 'test e-mail');
    ADMIN = false;
    // Arabic: the platform language set to Arabic - right-to-left, every label in Arabic, the route mirrored, data untouched
    const pa = await browser.newPage(); pa.on('pageerror', (e) => errs.push(e.message));
    await pa.addInitScript(() => { window.ZYB_ARABIC = true; });   // Arabic on (as shipped), set explicitly; the pages above run with it switched off
    await pa.addInitScript(() => { try { if (!localStorage.getItem('zyb-dash-prefs')) localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' })); } catch (e) { /* the test's own storage */ } });
    await pa.goto(base + '/dashboards/pdpl-office.html?standalone=1'); await pa.waitForSelector('#route svg [data-phase="8"]'); await pa.waitForFunction(() => !document.querySelector('[data-tab="all"]').hidden);
    ok(await pa.$eval('html', (e) => e.getAttribute('dir')) === 'rtl', 'Arabic: right-to-left');
    ok(await pa.$eval('.page-title', (e) => e.textContent) === 'مكتب الخصوصية' && await pa.$eval('[data-tab="map"]', (e) => e.textContent) === 'خريطة الطريق' && await pa.$eval('#langlbl', (e) => e.textContent) === 'English', 'Arabic: title, tabs, language button');
    ok(/يُدار نظام حماية البيانات الشخصية/.test(await pa.$eval('[data-t="intro"]', (e) => e.textContent)), 'Arabic: introduction');
    const rt = await pa.$eval('#route', (e) => e.textContent); ok(/المرحلة العربية 1/.test(rt) && /خطوات/.test(rt) && /متأخرة/.test(rt), 'Arabic: route map stations');
    const x1 = await pa.$eval('#route [data-phase="1"] circle:nth-of-type(3)', (c) => +c.getAttribute('cx')), x4 = await pa.$eval('#route [data-phase="4"] circle:nth-of-type(3)', (c) => +c.getAttribute('cx'));
    ok(x1 > x4, 'Arabic: the route runs right to left');
    ok(/الخطوات المكتملة/.test(await pa.$eval('#mapk', (e) => e.innerText)) && /يومياً/.test(await pa.$eval('#cycle', (e) => e.innerText)) && /كل خطوة تُقرأ من السجلات/.test(await pa.$eval('#routenote', (e) => e.textContent)), 'Arabic: KPIs, cycle, note');
    await pa.click('#route [data-phase="2"]'); await pa.waitForSelector('#zd-b .step');
    const pd = await pa.$eval('#zd-b', (e) => e.innerText); ok(/اكتشاف البيانات الشخصية/.test(pd) && /فُحص 2 مصدر/.test(pd) && /تقدير للتخطيط/.test(pd) && /مسؤول حماية البيانات/.test(pd) && /افتح الصفحة/.test(pd), 'Arabic: phase drawer');
    ok(await pa.$$eval('#zd-b img', (a) => a.length) === 0, 'Arabic: escaped'); await pa.keyboard.press('Escape');
    await pa.click('[data-tab="mine"]'); await pa.waitForSelector('#mylist [data-open="PO-00001"]');
    const ml = await pa.$eval('#mylist', (e) => e.innerText); ok(/لا يوجد تقييم أثر/.test(ml) && /بصفته مسؤول البيانات في إدارة Claims/.test(ml) && /عالية/.test(ml) && /المكلَّف/.test(ml), 'Arabic: my tasks (Arabic title, routing reason, severity, headers)');
    ok(/أدوارك: مسؤول حماية البيانات/.test(await pa.$eval('#myroles', (e) => e.textContent)), 'Arabic: roles');
    await pa.click('#mylist [data-open="PO-00001"]'); await pa.waitForSelector('#tack');
    const td = await pa.$eval('#zd-b', (e) => e.innerText);
    ok(/أكمل تقييم الأثر/.test(td) && /كما وردت في السجلات/.test(td) && /DPIA missing/.test(td) && /متأخرة - صُعّدت إلى مسؤول حماية البيانات huda\.syn/.test(td) && /اطلعت عليها/.test(td), 'Arabic: task drawer (recommendation, English for reference, history, actions)');
    await pa.keyboard.press('Escape');
    await pa.click('[data-tab="org"]'); const oa = await pa.$eval('#org', (e) => e.innerText);
    ok(/طلبات أصحاب البيانات/.test(oa) && /لا يوجد سفير خصوصية/.test(oa) && /huda\.syn/.test(oa), 'Arabic: organisation (function names, missing roles, names kept)');
    ok(/لا يوجد سفير خصوصية في إدارة Claims/.test(await pa.$eval('#gaps', (e) => e.innerText)), 'Arabic: gaps');
    await pa.click('[data-tab="ntf"]'); await pa.waitForSelector('#ctform'); ok(/يضبط مسؤول المنصة خادم البريد/.test(await pa.$eval('#ntfbody', (e) => e.innerText)) && /أُرسلت|فشلت/.test(await pa.$eval('#outbox', (e) => e.innerText)), 'Arabic: notifications');
    await pa.click('#langbtn'); await pa.waitForSelector('#route svg [data-phase]'); await pa.waitForTimeout(300);
    ok(await pa.$eval('html', (e) => e.getAttribute('dir')) !== 'rtl' && await pa.$eval('.page-title', (e) => e.textContent) === 'Privacy Office', 'the language button switches back to English');
    // a steward: the route map and their own tasks, no operator tabs
    STEWARD = true; const p2 = await browser.newPage(); p2.on('pageerror', (e) => errs.push(e.message)); await p2.addInitScript(() => { window.ZYB_ARABIC = false; });
    await p2.goto(base + '/dashboards/pdpl-office.html?standalone=1'); await p2.waitForSelector('#route svg [data-phase]'); await p2.waitForTimeout(400);
    ok(await p2.$eval('[data-tab="all"]', (e) => e.hidden) && await p2.$eval('[data-tab="cfg"]', (e) => e.hidden) && await p2.$eval('#runnow', (e) => e.hidden), 'a steward sees no operator tabs');
    await p2.click('[data-tab="mine"]'); ok(/data steward - Claims/.test(await p2.$eval('#myroles', (e) => e.textContent)), 'a steward sees their tasks and roles');
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
