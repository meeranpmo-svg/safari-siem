// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI CISO (engine/ciso.js): with nothing connected it says so and withholds the score; with sources it builds an itemised
// posture, a risk register and the decisions list from records only; the board brief cites only record ids it was given
// (invented ids are stripped, an answer with none falls back to the labelled rule-based brief); patrol-all reaches both
// engines as the signed-in person; viewers read, operators act.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerCiso } = require('../engine/ciso');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin', ip: '' };
const notConnected = () => Promise.reject(Object.assign(new Error('SIEM link not configured'), { notConnected: true }));

function siemStub(calls) {
  return (method, path, body, who) => {
    calls.push({ method, path, who });
    if (method === 'POST' && path === '/duty/patrol') return Promise.resolve({ results: [{ engineer: 'network', opened: 2, errors: [] }, { engineer: 'security', opened: 0, errors: ['firewall API timeout'] }] });
    if (path === '/duty/engineers') return Promise.resolve({ engineers: [{ id: 'network', name: 'AI Network Engineer', open: 1, critical: 1, high: 0, last_patrol: 1, late: false }, { id: 'security', name: 'AI Security Engineer', open: 1, critical: 0, high: 1, late: true }] });
    if (path.startsWith('/duty/items')) return Promise.resolve({ items: [
      { id: 'DW-000101', engineer: 'network', severity: 'critical', status: 'awaiting-approval', title: 'core-sw-01: uplink errors', site: 'HQ', detected_at: Date.now() - 3600000 },
      { id: 'DW-000102', engineer: 'security', severity: 'high', status: 'needs-human', title: 'FW-JED: any-any rule', site: 'Jeddah', detected_at: Date.now() - 5 * 86400000 },
    ] });
    if (path === '/metrics') return Promise.resolve({ open_by_severity: { 4: 2, 3: 5 }, mttd_s: 120, mttr_s: 3600, sla: { breaching_now: [{ id: 'C-7', title: 'Brute force on VPN', severity: 4, resolve_breached: true }], resolve_compliance_pct: 80, ack_compliance_pct: 95 } });
    if (path === '/compliance/sama') return Promise.resolve({ summary: { coverage_pct: 72, counts: { covered: 20, partial: 8, gap: 4 } }, controls: [{ id: '3.3.14', title: 'Security event management', status: 'gap', owner: 'SOC' }, { id: '3.3.5', title: 'Identity', status: 'covered' }] });
    if (path === '/collection/assurance') return Promise.resolve({ summary: { required: 40, covered: 30, silent: 4, coverage_pct: 75 }, inventory: { connected: true }, collector: { quiet: false }, unknown_senders: [] });
    if (path.startsWith('/approvals')) return Promise.resolve({ items: [{ id: 'AP-1', title: 'Isolate PC-123', case_id: 'C-7' }] });
    return Promise.reject(new Error('unexpected ' + path));
  };
}

test('ciso: nothing connected - every source says so, the score is withheld, the brief is rule-based and says why', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const C = registerCiso(e.app.srv, e.app, { siem: notConnected });
  const v = await C.overview(true);
  assert.equal(v.posture.overall, null, 'no score from nothing');
  assert.match(v.posture.withheld_why, /domains measured/);
  assert.equal(v.sources.find((s) => s.id === 'soc').state, 'not_connected');
  assert.equal(v.posture.domains.find((d) => d.id === 'resilience').measured, false, 'no drills = not measured, never "fine"');
  assert.equal(v.risks.length, 0);
  const b = await C.brief(ADM);
  assert.equal(b.kind, 'rules'); assert.match(b.why_rules, /AI not available/);
  assert.match(b.headline, /not yet measurable/);
  assert.ok(b.not_measured.length >= 3);
});

test('ciso: with sources - itemised posture, risk register, decisions, BISO grouping by recorded site only', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const G = require('../engine/grc').createGrc(e.app);
  G.drillPut({ title: 'Core insurance DR', system: 'Core Insurance', type: 'failover', scheduled: '2025-01-10', frequency_months: 12 }, ADM);
  const calls = [];
  const C = registerCiso(e.app.srv, e.app, { siem: siemStub(calls) });
  const v = await C.overview(true);
  const dom = (id) => v.posture.domains.find((d) => d.id === id);
  assert.equal(dom('compliance').score, 72);
  assert.equal(dom('detection').measured, true);
  assert.ok(dom('detection').items.some((i) => /2 open critical alerts/.test(i.label) && i.points === -12));
  assert.ok(dom('detection').items.some((i) => /log coverage 75% of 40 assets/.test(i.label) && i.points === -20), 'blind spots count against detection');
  assert.ok(dom('detection').items.some((i) => /4 assets stopped sending logs/.test(i.label)));
  assert.ok(dom('resilience').items.some((i) => /overdue for a recovery test/.test(i.label)), 'never-tested system is overdue');
  assert.ok(v.posture.overall != null && v.posture.measured >= 3, 'score once 3 domains are measured');
  const refs = v.risks.map((r) => r.ref);
  for (const want of ['duty:DW-000101', 'duty:DW-000102', 'sama:3.3.14', 'drill-system:Core Insurance', 'case:C-7']) assert.ok(refs.includes(want), want);
  assert.equal(v.risks[0].severity, 'critical');
  const dk = v.decisions.map((d) => d.kind);
  assert.ok(dk.includes('approve-change') && dk.includes('approve-response') && dk.includes('needs-a-person'));
  assert.ok(v.areas.by_site.some((s) => s.site === 'HQ') && v.areas.by_site.some((s) => s.site === '(no site recorded)'), 'no site is never guessed');
  assert.equal(v.team.filter((x) => x.engine === 'siem').length, 2);
  assert.ok(calls.every((c) => !c.who), 'reads go as the system viewer');
});

test('ciso brief: AI cites only given record ids (invented stripped); an answer citing nothing falls back to rules', async (t) => {
  const e = await startApp({}); t.after(() => e.close());
  const C = registerCiso(e.app.srv, e.app, { siem: siemStub([]) });
  e.fake.override = () => ({ ok: true, model: 'synthetic-model-1', text: JSON.stringify({ headline: 'Two critical risks need action today', summary: 'SYNTHETIC',
    priorities: [{ action: 'Approve the uplink fix', why: 'critical', owner_role: 'CISO', horizon: 'today', refs: ['duty:DW-000101', 'duty:DW-999999'] }, { action: 'Invented', why: 'x', owner_role: 'CISO', horizon: 'today', refs: ['made-up:1'] }],
    board_points: [{ text: 'SAMA coverage 72%', refs: ['domain:compliance'] }], not_measured: [] }) });
  const b = await C.brief(ADM);
  assert.equal(b.kind, 'ai');
  assert.equal(b.priorities.length, 1, 'a priority with no real record is dropped');
  assert.deepEqual(b.priorities[0].refs, ['duty:DW-000101']);
  assert.equal(b.refs_dropped, 2);
  assert.ok(b.context_sha256 && /^[a-f0-9]{64}$/.test(b.context_sha256));
  const sent = e.fake.requests.at(-1).body;
  assert.match(sent.system, /No citation, no claim/); assert.match(sent.prompt, /duty:DW-000101/);
  e.fake.override = () => ({ ok: true, model: 'm', text: JSON.stringify({ headline: 'All good', summary: 'x', priorities: [{ action: 'Relax', refs: ['nope'] }], board_points: [] }) });
  const b2 = await C.brief(ADM);
  assert.equal(b2.kind, 'rules'); assert.match(b2.why_rules, /cited no record ids/);
  assert.equal(C.briefs().length, 2);
});

test('ciso routes: viewer reads, operator acts; patrol-all reaches both engines as the signed-in person', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true });
  const calls = [];
  registerCiso(e.app.srv, e.app, { siem: siemStub(calls) });
  const view = e.as('viewer.v', 'viewer');
  assert.equal((await view('GET', '/ciso/overview')).status, 200);
  assert.equal((await view('POST', '/ciso/brief', { body: {} })).status, 403);
  assert.equal((await view('POST', '/ciso/patrol', { body: {} })).status, 403);
  const r = await e.as('op.one', 'operator')('POST', '/ciso/patrol', { body: {} });
  assert.equal(r.status, 200);
  assert.ok(r.json.results.some((x) => x.engine === 'itam' && x.engineer === 'pentest'));
  const sec = r.json.results.find((x) => x.engine === 'siem' && x.engineer === 'security');
  assert.equal(sec.ok, false); assert.match(sec.error, /timeout/);
  const p = calls.find((c) => c.method === 'POST');
  assert.equal(p.who.user, 'op.one'); assert.equal(p.who.role, 'operator');
  const br = await e.as('op.one', 'operator')('POST', '/ciso/brief', { body: {} });
  assert.equal(br.status, 200);
  assert.equal((await view('GET', '/ciso/briefs/' + br.json.id)).json.id, br.json.id);
});

test('ciso operational: morning brief written once on a working day at the brief hour, never on Friday; posture history kept', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = Date.parse('2026-10-18T03:30:00Z');            // Sunday 06:30 Riyadh
  const C = registerCiso(e.app.srv, e.app, { siem: siemStub([]), noTimer: true, now: () => clock });
  await C.tick();
  assert.equal(C.briefs().length, 0, 'before 07:00 Riyadh: no brief yet');
  assert.equal(C.history().length, 1, 'posture recorded');
  assert.equal(new Date(C.status().next_brief).toISOString(), '2026-10-18T04:00:00.000Z', 'next brief 07:00 Riyadh today');
  clock = Date.parse('2026-10-18T04:10:00Z'); await C.tick();
  const b = C.briefs(); assert.equal(b.length, 1); assert.equal(b[0].by, 'ai-ciso'); assert.equal(b[0].auto, true);
  assert.equal(b[0].kind, 'rules', 'no AI here: the rule-based brief, labelled');
  clock += 20 * 60000; await C.tick(); assert.equal(C.briefs().length, 1, 'once per day');
  clock = Date.parse('2026-10-23T05:00:00Z'); await C.tick();   // Friday 08:00 Riyadh
  assert.equal(C.briefs().length, 1, 'no brief on Friday');
  assert.equal(new Date(C.status().next_brief).toISOString(), '2026-10-25T04:00:00.000Z', 'next brief Sunday 07:00 Riyadh');
  assert.equal(C.history().length, 2, 'one history row per day');
  const r = await e.as('viewer.v', 'viewer')('GET', '/ciso/status');
  assert.equal(r.status, 200); assert.equal(r.json.brief_hour, 7);
});

test('ciso insights: posture forecast from the kept history, domain movers, alert spike against its own baseline, focus; viewer reads', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const days = []; for (let i = 15; i >= 1; i--) days.push({ day: new Date(Date.now() - i * 86400000).toISOString().slice(0, 10), total: 5 + (i % 3) });
  days.push({ day: new Date().toISOString().slice(0, 10), total: 40 });
  const base = siemStub([]);
  const siem = (m, p, b, w) => (p === '/metrics' ? base(m, p, b, w).then((x) => Object.assign(x, { alerts_by_day: days })) : base(m, p, b, w));
  const C = registerCiso(e.app.srv, e.app, { siem, python: process.env.PYTHON || 'python3' });
  const H = e.app.store.collection('ciso_history');
  for (let i = 12; i >= 1; i--) { const day = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10); H.put({ id: day, day, at: Date.now() - i * 86400000, overall: 80 - (12 - i) * 2, domains: { detection: 90 - (12 - i) * 3, compliance: 72 } }); }
  const r = await e.req('GET', '/ciso/insights', { user: 'vera.syn', role: 'viewer' });
  assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.ok(v.forecast.days >= 7 && v.forecast.falling, 'a falling posture is forecast: ' + JSON.stringify(v.forecast));
  assert.match(v.forecast.text, /falling .* points a day/);
  assert.ok(v.movers.length && v.movers[0].id === 'detection' && v.movers[0].delta < 0, 'detection is the biggest faller');
  assert.equal(v.alerts.today, 40); assert.equal(v.alerts.unusual, true); assert.match(v.alerts.text, /unusual/);
  assert.equal(v.alerts.next_days.length, 7);
  assert.ok(v.focus.some((f) => f.kind === 'alerts') && v.focus.some((f) => f.kind === 'critical' && /2 critical/.test(f.text)) && v.focus.some((f) => f.kind === 'weakest'));
  const n = await (async () => { const e2 = await startApp({ noAi: true }); t.after(() => e2.close()); const C2 = registerCiso(e2.app.srv, e2.app, { siem: notConnected, python: process.env.PYTHON || 'python3' }); return (await e2.req('GET', '/ciso/insights', { user: 'vera.syn', role: 'viewer' })).json; })();
  assert.match(n.forecast.text, /needs 7 days/); assert.match(n.alerts.text, /needs 8 days/, 'nothing projected from no history');
});

test('ciso: the overview is answered at once from the last result while one background refresh reads the sources again', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let T = Date.parse('2026-11-19T08:00:00Z'); const calls = [];
  const C = registerCiso(e.app.srv, e.app, { siem: siemStub(calls), now: () => T });
  const v1 = await C.overview(false);
  assert.equal(v1.stale, false); const n1 = calls.length; assert.ok(n1 > 0);
  T += 10000; const v2 = await C.overview(false);
  assert.equal(calls.length, n1, 'fresh for 30 s: no source read'); assert.equal(v2.age_s, 10);
  T += 60000; const v3 = await C.overview(false);
  assert.equal(v3.stale, true, 'older than 30 s: answered from the last result, marked stale'); assert.equal(v3.age_s, 70);
  const [a, b] = [C.overview(false), C.overview(false)]; await Promise.all([a, b]);
  await new Promise((r) => setTimeout(r, 30));
  const reads = calls.slice(n1).filter((c) => c.path === '/metrics').length;
  assert.equal(reads, 1, 'one background refresh for three callers');
  T += 20 * 60000; const v4 = await C.overview(false);
  assert.equal(v4.stale, false, 'older than 15 min: computed again before answering');
  assert.ok(Array.isArray(v4.trend));
});
