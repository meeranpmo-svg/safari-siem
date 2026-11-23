// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Reporting Center (engine/report-center.js, pyengine/report_center_rules.py): reports built from the modules' own views, a module
// that is not there says so (never zero), the SOC report needs operator, daily KPI history -> trends / forecasts / unusual moves,
// exports (CSV formula-safe, HTML escaped), schedules (admin, validated, audited, recipients hidden from non-admins), delivery
// through the SIEM relay as the service identity with one retry, roles. The SIEM is stubbed; data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const DAY = 86400000;
async function setup(t, siemFn) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = Date.parse('2026-10-31T09:00:00Z');
  const calls = [];
  const siem = async (m, p, b, user) => { calls.push({ m, p, b, user }); return siemFn ? siemFn(m, p, b, user) : { ok: false, status: 0, error: 'SIEM link not configured' }; };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, rcSiem: siem });
  return { e, calls, setClock: (t2) => { clock = t2; }, now: () => clock };
}
const get = (e, p, who = VW) => e.req('GET', p, who);
const post = (e, p, body, who = ADM) => e.req('POST', p, Object.assign({ body }, who));

test('catalogue and reports: built from the modules, a missing source says so, SOC needs operator', async (t) => {
  const { e } = await setup(t);
  const h = (await get(e, '/report-center')).json;
  assert.ok(h.reports.length >= 7); assert.equal(h.reports.find((r) => r.id === 'soc').allowed, false, 'viewer: SOC report not allowed');
  assert.equal(h.can_schedule, false);
  const ex = await get(e, '/report-center/reports/executive');
  assert.equal(ex.status, 200, ex.raw);
  const sec = (id) => ex.json.sections.find((x) => x.id === id);
  assert.equal(sec('soc').state, 'restricted', 'the SOC part of the executive report is withheld from a viewer');
  assert.equal(sec('compliance').state, 'ok'); assert.ok(sec('compliance').kpis.some((k) => k.key === 'compliance.nca' && k.unit === '%'));
  assert.ok(!sec('compliance').rows, 'executive report is compact: no tables');
  assert.equal((await get(e, '/report-center/reports/soc')).status, 403);
  const soc = await get(e, '/report-center/reports/soc', OP);
  assert.equal(soc.status, 200); assert.equal(soc.json.sections[0].state, 'not_connected'); assert.match(soc.json.sections[0].note, /SIEM did not answer: SIEM link not configured/);
  assert.equal((await get(e, '/report-center/reports/nope')).status, 404);
  assert.equal((await get(e, '/report-center/reports/BAD!')).status, 400);
  // a module that is not loaded: not installed, never zero
  delete e.app.addons.drStudio; delete e.app.addons.backup;
  const rs = (await get(e, '/report-center/reports/resilience')).json.sections[0];
  assert.equal(rs.state, 'not_installed'); assert.equal(rs.kpis.length, 0);
});

test('SOC report from the SIEM Attack Summary; a hostile attacker name is escaped in HTML and neutralised in CSV', async (t) => {
  const { e, calls } = await setup(t, async (m, p) => (p.startsWith('/reports/attack-summary') ? { ok: true, data: { totals: { events: 900, by_severity: { 3: 20, 4: 5 } }, alerts: { total: 40, open: 7 }, cases: { open_now: 2 }, response: { mtta: { median_ms: 600000 } },
    top_attackers: [{ ip: '=HYPERLINK("http://x")', events: 30, targets: 2, country: '<img src=x onerror=alert(1)>', classes: ['brute_force'] }] } } : { ok: false, error: 'no' }));
  const r = (await get(e, '/report-center/reports/soc', OP)).json.sections[0];
  assert.equal(r.state, 'ok'); const k = (key) => r.kpis.find((x) => x.key === key).value;
  assert.equal(k('soc.high_events'), 25); assert.equal(k('soc.alerts_open'), 7); assert.equal(k('soc.mtta_min'), 10);
  assert.equal(calls[0].p, '/reports/attack-summary?period=7d');
  const csv = (await get(e, '/report-center/reports/soc/export?format=csv', OP)).json.csv;
  assert.ok(csv.includes('"\'=HYPERLINK'), 'a cell starting with = is prefixed (formula injection)');
  e.app.store.collection('pentest_settings').put({ id: 'report_brand', values: { org_name: (ZYB_ORG.short + ' (syn)'), letterhead: 'data:image/png;base64,AAAA' } });
  const html = (await get(e, '/report-center/reports/soc/export?format=html', OP)).json.html;
  assert.ok(!html.includes('<img src=x') && html.includes('&lt;img src=x'), 'escaped in the HTML report');
  assert.match(html, /background:#fff/, 'the report prints on a white background, not gray');
  assert.match(html, /print-color-adjust:exact/, 'section tints print exactly in the PDF');
  assert.match(html, /data:image\/png;base64,AAAA/, 'the company logo is on the report');
  assert.equal((await get(e, '/report-center/reports/soc/export?format=pdf', OP)).status, 400);
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'report.center.export' && x.by === 'nora.syn'));
});

test('ML: daily KPI history gives trend, change since last week, forecast and an unusual move; snapshot is admin-only and audited', async (t) => {
  const { e, now } = await setup(t);
  assert.equal((await post(e, '/report-center/snapshot', {}, OP)).status, 403);
  const sn = await post(e, '/report-center/snapshot', {}); assert.equal(sn.status, 200, sn.raw); assert.ok(sn.json.kpis > 0);
  assert.ok(e.app.store.auditTail(10).some((x) => x.action === 'report.center.snapshot' && x.by === 'syed'));
  const C = e.app.store.collection('rc_kpis'), today = C.get(sn.json.day);
  // 14 synthetic days before today: open VAPT findings rising steadily, then a jump today
  for (let i = 14; i >= 1; i--) { const d = new Date(now() + 3 * 3600000 - i * DAY).toISOString().slice(0, 10); C.put({ id: d, day: d, at: now() - i * DAY, values: { 'vapt.open': 10 + (14 - i), 'compliance.nca': 40 + (14 - i) }, labels: today.labels }); }
  C.put(Object.assign({}, today, { values: Object.assign({}, today.values, { 'vapt.open': 80, 'compliance.nca': 54 }) }));
  await post(e, '/report-center/snapshot', {});
  C.put(Object.assign({}, C.get(sn.json.day), { values: Object.assign({}, C.get(sn.json.day).values, { 'vapt.open': 80, 'compliance.nca': 54 }) }));
  const ins = await get(e, '/report-center/insights?report=security');
  assert.equal(ins.status, 200, ins.raw);
  const v = ins.json.kpis.find((k) => k.key === 'vapt.open');
  assert.ok(v, 'the VAPT figure is in the security insights'); assert.equal(v.days, 15);
  assert.equal(v.verdict, 'worsening'); assert.ok(v.change.better === false);
  assert.ok(v.unusual && v.unusual.flag, 'the jump today is unusual for this figure');
  assert.ok(ins.json.notable.some((n) => n.key === 'vapt.open'), 'listed first in what changed');
  assert.ok(!ins.json.kpis.some((k) => k.key === 'compliance.nca'), 'narrowed to the report asked for');
  const all = (await get(e, '/report-center/insights')).json;
  assert.equal(all.kpis.find((k) => k.key === 'compliance.nca').verdict, 'improving');
  assert.equal((await get(e, '/report-center/insights?report=../x')).status, 400);
});

test('schedules: admin only, every field validated, recipients hidden from non-admins, delivery through the SIEM relay with one retry', async (t) => {
  let fail = true; const sent = [];
  const { e, calls, setClock, now } = await setup(t, async (m, p, b) => {
    if (p === '/reports/deliver') { sent.push(b); return fail ? { ok: false, status: 424, error: 'e-mail not configured: smtp.host is not set' } : { ok: true, status: 200, data: { ok: true } }; }
    return { ok: false, status: 0, error: 'SIEM link not configured' };
  });
  const S = { name: 'Weekly executive', report: 'executive', period: 'weekly', weekday: 0, at: '08:00', recipients: ['CISO.syn@corpgroup.test'], format: 'html+csv' };
  assert.equal((await post(e, '/report-center/schedules', { schedules: [S] }, OP)).status, 403);
  let r = await post(e, '/report-center/schedules', { schedules: [Object.assign({}, S, { at: '25:00' })] }); assert.equal(r.status, 400); assert.match(r.json.error, /at must be HH:MM/);
  r = await post(e, '/report-center/schedules', { schedules: [Object.assign({}, S, { recipients: ['nope'] })] }); assert.equal(r.status, 400); assert.match(r.json.error, /recipients: "nope"/);
  r = await post(e, '/report-center/schedules', { schedules: [Object.assign({}, S, { report: 'everything' })] }); assert.equal(r.status, 400); assert.match(r.json.error, /report must be one of/);
  r = await post(e, '/report-center/schedules', { schedules: [Object.assign({}, S, { evil: 1 })] }); assert.equal(r.status, 200, r.raw);
  const sc = r.json.schedules[0]; assert.deepEqual(sc.recipients, ['ciso.syn@corpgroup.test']); assert.equal(sc.evil, undefined);
  assert.equal(new Date(sc.next_at + 3 * 3600000).getUTCDay(), 0, 'next run on Sunday (Riyadh)'); assert.equal(new Date(sc.next_at + 3 * 3600000).getUTCHours(), 8);
  const au = e.app.store.auditTail(10).find((x) => x.action === 'report.center.schedules.save'); assert.deepEqual(au.detail, { count: 1, recipients: 1 });
  assert.ok(!JSON.stringify(au).includes('ciso.syn@'), 'addresses never in the audit');
  const hv = (await get(e, '/report-center', OP)).json.schedules[0]; assert.equal(hv.recipients, undefined); assert.equal(hv.recipients_count, 1);
  // due -> delivered as the service identity; relay not configured -> failed with the reason, retried once after 15 min
  setClock(sc.next_at + 1000); await e.app.addons.reportCenter.tick();
  const d = calls.find((c) => c.p === '/reports/deliver'); assert.equal(d.user, 'system:itam-report-center');
  assert.deepEqual(sent[0].recipients, ['ciso.syn@corpgroup.test']); assert.deepEqual(sent[0].attachments.map((a) => a.contentType), ['text/html', 'text/csv']);
  let runs = (await get(e, '/report-center', ADM)).json.runs; assert.equal(runs[0].status, 'failed'); assert.match(runs[0].error, /smtp.host is not set/);
  fail = false; setClock(now() + 16 * 60000); await e.app.addons.reportCenter.tick();
  runs = (await get(e, '/report-center', ADM)).json.runs; assert.equal(runs[0].reason, 'retry'); assert.equal(runs[0].status, 'ok');
  const after = (await get(e, '/report-center', ADM)).json.schedules[0]; assert.ok(after.next_at > now(), 'the next weekly run is scheduled'); assert.equal(after.last.status, 'ok');
  // send now: admin only, audited
  assert.equal((await post(e, '/report-center/schedules/' + sc.id + '/send-now', {}, OP)).status, 403);
  r = await post(e, '/report-center/schedules/' + sc.id + '/send-now', {}); assert.equal(r.status, 200); assert.equal(r.json.status, 'ok');
  assert.ok(e.app.store.auditTail(10).some((x) => x.action === 'report.center.send-now' && x.by === 'syed'));
  assert.equal((await post(e, '/report-center/schedules/nope/send-now', {})).status, 404);
});

// the SIEM's Exchange Reports digest (engine/soc/exchange-reports.js), SYNTHETIC
const EXD = { summary: { status: { connected: true, online: { ready: true } },
  mailboxes: { total: 527, size_gb: 60.4, near_quota: 3, inactive: 4, hidden: 2, forwarding_outside: 1, features: { pop: 1, imap: 2 }, growth_30d: { days: 30, since: '2026-10-01', gb: 3.7 } },
  permissions: { mailboxes_with_delegates: 2, full_access: 3, send_as: 1, send_on_behalf: 1, holders_over_10: 0 }, groups: { total: 3, with_external: 2, empty: 1 },
  mobile: { devices: 2, stale: 1, unapproved: null, quarantined: 1 }, online: null },
  largest: [{ address: 'ceo.syn@corp-synth.sa', name: '=CMD|calc', type: 'UserMailbox', database: 'DB02', size_gb: 32.2, items: 1000, used_pct: null, last_logon: '2026-10-30T10:00:00Z' }],
  holders: [{ holder: 'CORP\\alice.syn', mailboxes: 1, full_access: 1, send_as: 1, send_on_behalf: 0 }],
  stale_devices: [{ owner: 'bob syn', model: 'SM-X900', os: 'Android 13', last_sync: '2026-09-01T00:00:00Z', days: 60 }],
  traffic: { exchange: true, status: { received: 3000, delivered: 2600, sent: 500, failed: 40, deferred: 12 }, split: { received_external: 1200, sent_external: 450, internal: 1400 }, average_kb: 48.2, top_senders: [{ address: 'alice.syn@corp-synth.sa', n: 120, mb: 50 }] },
  clients: { configured: true, totals: { owa_users: 40, eas_devices: 33, failed: 12 } } };

test('Exchange report: administrators only (it names people), built from the SIEM digest, schedulable, not connected says so', async (t) => {
  let digest = { ok: false, status: 0, error: 'SIEM link not configured' };
  const { e, calls, setClock, now } = await setup(t, async (m, p) => (p === '/exchange/reports/digest' ? digest : { ok: false, status: 0, error: 'SIEM link not configured' }));
  const h = (await get(e, '/report-center', OP)).json.reports.find((r) => r.id === 'exchange');
  assert.ok(h, 'in the catalogue'); assert.equal(h.role, 'admin'); assert.equal(h.allowed, false);
  const refused = await get(e, '/report-center/reports/exchange', OP);
  assert.equal(refused.status, 403); assert.match(refused.json.error, /needs the admin role \(it names mailbox owners/);
  assert.equal((await get(e, '/report-center/reports/exchange', VW)).status, 403);
  let r = (await get(e, '/report-center/reports/exchange', ADM)).json;
  assert.deepEqual(r.sections.map((x) => x.state), ['not_connected', 'not_connected', 'not_connected', 'not_connected', 'not_connected']);
  assert.match(r.sections[0].note, /SIEM did not answer: SIEM link not configured/); assert.ok(r.sections.every((x) => !x.kpis.length), 'nothing measured: no figure, never zero');
  assert.equal(calls.filter((c) => c.p === '/exchange/reports/digest').length, 1, 'one SIEM read for the five sections');
  // the SIEM answers now; a read is kept 60 s, then read again
  digest = { ok: true, status: 200, data: EXD };
  assert.equal((await get(e, '/report-center/reports/exchange', ADM)).json.sections[0].state, 'not_connected', 'within 60 s the same read is used');
  setClock(now() + 61000);
  r = (await get(e, '/report-center/reports/exchange', ADM)).json;
  assert.equal(r.sections[0].state, 'ok'); assert.equal(calls.filter((c) => c.p === '/exchange/reports/digest').length, 2);
  assert.equal(calls.find((c) => c.p === '/exchange/reports/digest').m, 'GET');
  // the daily KPI history records the Exchange figures (counts only)
  const sn = await post(e, '/report-center/snapshot', {}); assert.equal(sn.status, 200);
  const day = e.app.store.collection('rc_kpis').get(sn.json.day); assert.equal(day.values['exchange.mailboxes'], 527); assert.equal(day.labels['exchange.mailboxes'].section, 'ex_mailboxes');
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'report.center.snapshot'));
});

test('Exchange report: figures and tables from the digest; export escapes names; the AI gets figures, never the tables of names', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  const calls = [], seen = [];
  const siem = async (m, p, b, user) => { calls.push({ m, p, user }); return p === '/exchange/reports/digest' ? { ok: true, status: 200, data: EXD } : { ok: false, status: 0, error: 'no' }; };
  const turns = [() => ({ stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 't1', name: 'report', input: { id: 'exchange' } }] }), () => ({ stop_reason: 'end_turn', content: [{ type: 'text', text: 'Mailbox data grew 3.7 GB in 30 days.' }] })];
  const sdk = class { constructor() { this.messages = { create: async (params) => { seen.push(JSON.parse(JSON.stringify(params))); return Object.assign({ model: params.model, usage: { input_tokens: 10, output_tokens: 5 } }, turns.shift()(params)); } }; } };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-13T09:00:00Z'), python: PY, rcSiem: siem, rcSdk: sdk, rcKey: () => 'sk-ant-synthetic' });
  const r = (await get(e, '/report-center/reports/exchange', ADM)).json;
  const sec = (id) => r.sections.find((x) => x.id === id), k = (id, key) => (sec(id).kpis.find((x) => x.key === key) || {}).value;
  assert.deepEqual(r.sections.map((x) => x.state), ['ok', 'ok', 'ok', 'ok', 'not_connected']);
  assert.equal(k('ex_mailboxes', 'exchange.mailboxes'), 527); assert.equal(k('ex_mailboxes', 'exchange.growth_30d_gb'), 3.7); assert.equal(k('ex_mailboxes', 'exchange.pop_imap'), 3);
  assert.equal(k('ex_access', 'exchange.lists_external'), 2); assert.equal(k('ex_traffic', 'exchange.mail_failed'), 40); assert.equal(k('ex_traffic', 'exchange.mail_internal'), 1400);
  assert.equal(k('ex_clients', 'exchange.failed_logons'), 12); assert.equal(k('ex_clients', 'exchange.devices_unapproved'), null, 'no approved-model list: not measured');
  assert.match(sec('ex_online').note, /Reports\.Read\.All/);
  assert.deepEqual(sec('ex_access').rows.rows[0], ['CORP\\alice.syn', 1, 1, 1, 0]);
  assert.equal(calls.filter((c) => c.p === '/exchange/reports/digest').length, 1, 'one SIEM read for the five sections');
  const csv = (await get(e, '/report-center/reports/exchange/export?format=csv', ADM)).json.csv;
  assert.ok(csv.includes('"\'=CMD|calc"'), 'a name starting with = is neutralised in CSV');
  // schedulable like every report (administrators choose the recipients)
  const sv = await post(e, '/report-center/schedules', { schedules: [{ name: 'Weekly Exchange', report: 'exchange', period: 'weekly', weekday: 0, at: '07:00', recipients: ['messaging.syn@corpgroup.test'] }] });
  assert.equal(sv.status, 200, sv.raw); assert.equal(sv.json.schedules[0].report, 'exchange');
  // the AI analyst: operators are refused this report; an administrator's AI sees the figures without the names
  const a = await post(e, '/report-center/ai/ask', { question: 'How did Exchange change this month?', report: 'exchange' }, ADM);
  assert.equal(a.status, 200, a.raw); assert.deepEqual(a.json.steps.map((x) => x.tool + ':' + x.ok), ['report:true']);
  const toolText = JSON.stringify(seen[1].messages.at(-1));
  assert.ok(toolText.includes('527') && toolText.includes('tables naming people are not given to the AI'), 'figures reach the AI');
  for (const who of ['ceo.syn', 'alice.syn', 'bob syn', '=CMD']) assert.ok(!toolText.includes(who), 'no name reaches the AI: ' + who);
  assert.equal((await post(e, '/report-center/ai/ask', { question: 'Exchange summary please', report: 'exchange' }, OP)).status, 403);
});

test('AI analyst: switched off says why; viewers refused', async (t) => {
  const { e } = await setup(t);
  assert.equal((await post(e, '/report-center/ai/ask', { question: 'Summarise' }, VW)).status, 403);
  const r = await post(e, '/report-center/ai/ask', { question: 'Summarise' }, OP);
  assert.equal(r.status, 424); assert.match(r.json.error, /external AI is not allowed/);
  assert.equal((await post(e, '/report-center/ai/ask', { question: 'x' }, OP)).status, 400, 'too short');
});
