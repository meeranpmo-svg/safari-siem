// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// DSPM intelligence (engine/dspm-intel.js) through the real routes on the SYNTHETIC posture sources (tests/data-posture-fixtures.js):
// store risk 0-100 with every point itemised, toxic combinations from named facts, anomalies only from 7 daily snapshots (a count
// that never moved and now jumps is flagged), the score forecast withheld below 3 snapshots, fixes ranked by points regained (a
// capped risk regains nothing until under its cap), roles (viewer counts and tiers only - no store names; operator items, audited),
// the AI advisor (operator, a person; store labels and counts only - never a file name; validation naming the field; audited).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const DP = require('../engine/data-posture');
const DI = require('../engine/dspm-intel');
const F = require('./data-posture-fixtures');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const T0 = Date.parse('2026-11-08T08:00:00Z'), DAY = 86400000;

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.addons.pdpl = require('../engine/pdpl').createPdpl(e.app, { now: () => T0 });
  F.seedLocal(e.app, T0);
  const P = DP.registerDataPosture(e.app.srv, e.app, DP.createDataPosture(e.app, { now: () => T0, siem: o.siem || F.fakeSiem(T0, {}), noTimer: true }));
  const I = DI.registerDspmIntel(e.app.srv, e.app, P, { now: () => T0, sdk: o.sdk, getKey: () => 'sk-ant-synthetic-itam' });
  const call = (m, p, who, b) => e.req(m, p, Object.assign({ body: b }, who));
  const audits = (a) => e.app.store.auditTail(300).filter((x) => x.action === a);
  return { e, P, I, call, audits };
}
const hist = (e, days, f) => { for (let i = days; i >= 1; i--) { const id = new Date(T0 + 3 * 3600000 - i * DAY).toISOString().slice(0, 10); e.app.store.collection('data_posture_hist').put(Object.assign({ id, at: id + 'T08:00:00.000Z' }, f(i))); } };

test('dspm intel: store risk itemised, toxic combinations, roles (viewer: no names), audit', async (t) => {
  const s = await setup(t);
  let r = await s.call('GET', '/data-posture/insights', OP); assert.equal(r.status, 200, r.text);
  const v = r.json, st = (l) => v.stores.items.find((x) => x.label === l);
  const az = st('claimsdocssyn');
  assert.ok(az, 'the public Azure store is ranked: ' + v.stores.items.map((x) => x.label).join(', '));
  const f = Object.fromEntries(az.why.map((w) => [w.factor, w.points]));
  assert.equal(f.exposure, 25, 'public store: 25'); assert.equal(f.location, 10, 'outside the Kingdom: 10'); assert.equal(f.sensitivity, 27, 'password (9) x 3');
  assert.equal(az.score, Math.min(100, Math.round(az.why.reduce((a, w) => a + w.points, 0))), 'the score is the sum of its itemised points');
  assert.deepEqual(az.toxic.map((x) => x.kind).sort(), ['credentials_exposed', 'shadow_exposed', 'strong_abroad'], 'public + secret, ID abroad, and no activity names it');
  assert.match(az.toxic.find((x) => x.kind === 'strong_abroad').why, /National ID/);
  const hr = st('HR-Site-SYN');
  assert.ok(hr.why.some((w) => w.factor === 'exposure' && /1 anonymous link/.test(w.reason)) && hr.why.some((w) => w.factor === 'governance' && w.points === 10), 'HR site: anonymous link and no processing activity names it');
  assert.ok(hr.toxic.some((x) => x.kind === 'shadow_exposed'), 'shadow data shared outside');
  assert.equal(st('unknownsyn').why.find((w) => w.factor === 'location').points, 3, 'location unknown: 3, said not safe');
  assert.ok(v.stores.items.every((x, i, a) => !i || a[i - 1].score >= x.score), 'riskiest first');
  assert.equal(Object.values(v.stores.tiers).reduce((a, b) => a + b, 0), v.stores.total);
  assert.equal(s.audits('data.posture.insights.read').length, 1);
  // a viewer: counts and tiers only
  r = await s.call('GET', '/data-posture/insights', VIEW); assert.equal(r.status, 200);
  assert.equal(r.json.stores.items, undefined); assert.equal(r.json.toxic_items, undefined); assert.ok(r.json.toxic.length >= 2);
  assert.ok(!/claimsdocssyn|HR-Site-SYN|payroll/.test(r.text), 'no store or file name for a viewer');
});

test('dspm intel: anomalies from 7 daily snapshots, forecast from 3, fixes ranked (a capped risk regains nothing)', async (t) => {
  const s = await setup(t);
  let v = (await s.call('GET', '/data-posture/insights', OP)).json;
  assert.ok(v.anomalies.every((a) => !a.judged && /needs 7 daily snapshots/.test(a.why)), 'no history: not judged');
  assert.match(v.forecast.why, /needs 3 daily snapshots/);
  hist(s.e, 10, (i) => ({ score: 9 - (10 - i) * 0.3, measured: 12, counts: { exposed: 0, credentials: 3, privacy: 3 } }));
  v = (await s.call('GET', '/data-posture/insights', OP)).json;
  const ex = v.anomalies.find((a) => a.risk === 'exposed');
  assert.equal(ex.flagged, true, JSON.stringify(ex)); assert.equal(ex.direction, 'up'); assert.match(ex.why, /never moved before/);
  assert.equal(v.anomalies.find((a) => a.risk === 'credentials').flagged, false, 'same as usual: not flagged');
  assert.equal(v.forecast.n, 11); assert.equal(v.forecast.direction, 'falling'); assert.match(v.forecast.why, /not moving toward the 8 target/);
  // fixes: the shadow risk is 3.1 against a cap of 2 - fixing the 1 undeclared category alone gives back nothing
  const und = v.fixes.find((x) => x.measure === 'undeclared_category');
  assert.equal(und.gain, 0); assert.match(und.why, /over its cap of 2/);
  const pub = v.fixes.find((x) => x.measure === 'public_store'); assert.equal(pub.gain, 0.75);
  assert.ok(v.fixes.every((x, i, a) => !i || a[i - 1].gain >= x.gain), 'ranked by points regained');
});

test('dspm advisor: operator and a person only, store labels and counts - never a file name; validation; audited', async (t) => {
  const seen = []; let n = 0;
  class Fake { constructor() { this.messages = { create: async (req) => { seen.push(JSON.parse(JSON.stringify(req)));
    if (n++ === 0) return { stop_reason: 'tool_use', usage: { input_tokens: 10, output_tokens: 5 }, content: [{ type: 'tool_use', id: 'a', name: 'dspm_insights', input: {} }] };
    return { stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 5 }, content: [{ type: 'text', text: 'Fix claimsdocssyn first.' }] }; } }; } }
  const s = await setup(t, { sdk: Fake });
  s.e.app.settings.update({ external_ai_allowed: true }, ADM);
  let r = await s.call('POST', '/data-posture/ask', VIEW, { question: 'which store first?' }); assert.equal(r.status, 403);
  r = await s.call('POST', '/data-posture/ask', OP, { question: 'x' }); assert.equal(r.status, 400); assert.match(r.text, /question/);
  r = await s.call('POST', '/data-posture/ask', OP, { question: 'which store should we fix first?' }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.answer, 'Fix claimsdocssyn first.'); assert.deepEqual(r.json.steps, [{ tool: 'dspm_insights', ok: true }]);
  const tool = JSON.stringify(seen[1].messages[2].content[0].content);
  assert.match(tool, /untrusted/i); assert.match(tool, /claimsdocssyn/); assert.match(tool, /OneDrive \(name withheld\)/);
  assert.ok(!/payroll-syn|passport-syn|keys-syn|alia\.syn/.test(tool), 'no file name or person reaches the model');
  assert.equal(s.audits('data-posture.ai.ask').length, 1);
  await assert.rejects(s.I.ask({ question: 'which store first?' }, { user: 'ai:dspm', role: 'operator' }), /service or AI identity/);
});

test('dspm intel: new and risen stores against yesterday, risk trends, peers unusual for their type', async (t) => {
  const s = await setup(t);
  let v = (await s.call('GET', '/data-posture/insights', OP)).json;
  assert.match(v.changes.why, /first daily snapshot/); assert.equal(v.changes.new, 0);
  // yesterday: HR-Site-SYN was low, claimsdocssyn did not exist
  const today = s.e.app.store.collection('dspm_store_hist').all()[0], hr = v.stores.items.find((x) => x.label === 'HR-Site-SYN');
  const prev = { id: '2026-11-07', at: '2026-11-07T08:00:00.000Z', stores: {} };
  for (const [id, x] of Object.entries(today.stores)) if (x.label !== 'claimsdocssyn') prev.stores[id] = x;
  prev.stores[hr.id] = { score: 10, tier: 'low', label: 'HR-Site-SYN', type: 'sharepoint', factors: { sensitivity: 10 } };
  s.e.app.store.collection('dspm_store_hist').put(prev);
  v = (await s.call('GET', '/data-posture/insights', OP)).json;
  assert.equal(v.changes.since, '2026-11-07');
  assert.ok(v.changes.new_items.some((x) => x.label === 'claimsdocssyn' && /not in the 2026-11-07 snapshot/.test(x.why)), 'a new high-risk store');
  const r = v.changes.risen_items.find((x) => x.label === 'HR-Site-SYN'); assert.ok(r && r.previous === 10 && /exposure 0 → /.test(r.why), 'risen with the factor that changed: ' + JSON.stringify(r));
  const vv = (await s.call('GET', '/data-posture/insights', VIEW)).json;
  assert.equal(vv.changes.new_items, undefined); assert.ok(vv.changes.new >= 1, 'viewer: counts only');
  assert.ok(v.trends.every((x) => /needs 3 daily snapshots/.test(x.why)), 'trend withheld without history');
  // peers (pure): a SharePoint site with 400 personal items among sites of about 10
  const sc = Array.from({ length: 8 }, (_, i) => ({ id: 's' + i, label: 'Site-SYN-' + i, type: 'sharepoint', personal_items: 8 + i, score: 20 }));
  sc.push({ id: 'big', label: 'Export-SYN', type: 'sharepoint', personal_items: 400, score: 40 });
  const pe = s.I._peers(sc);
  assert.deepEqual(pe.items.map((x) => x.label), ['Export-SYN']); assert.match(pe.items[0].why, /400 items .* typical sharepoint store has 1[12]/);
  assert.match(s.I._peers(sc.slice(0, 5)).why, /7 or more/);
});

test('dspm plans: drafted from the ranking, four-eyes by a person, verified only by the data, audited', async (t) => {
  let fixed = false; const base = F.fakeSiem(T0, {});
  const siem = async (m, p, who) => { const r = await base(m, p, who); if (fixed && p.startsWith('/cloud-data/stores') && r.json) { const j = JSON.parse(JSON.stringify(r.json)); j.stores[0].public = false; return Object.assign({}, r, { json: j }); } return r; };
  const s = await setup(t, { siem });
  const OP2 = { user: 'omar.syn', role: 'operator' };
  let r = await s.call('POST', '/data-posture/plans', VIEW, { due_days: 30 }); assert.equal(r.status, 403);
  r = await s.call('POST', '/data-posture/plans', OP, { due_days: 3 }); assert.equal(r.status, 400); assert.match(r.text, /due_days/);
  r = await s.call('POST', '/data-posture/plans', OP, { due_days: 30, note: 'Q4 clean-up' }); assert.equal(r.status, 200, r.text);
  const pl = r.json; assert.equal(pl.status, 'proposed'); assert.match(pl.id, /^DSPM-PLAN-0001$/);
  const pub = pl.items.find((x) => x.store === 'claimsdocssyn' && x.action === 'remove_public_access'); assert.ok(pub, 'public store: remove public access');
  assert.ok(pl.items.some((x) => x.store === 'claimsdocssyn' && x.action === 'rotate_and_remove_secrets') && pl.items.some((x) => x.store === 'HR-Site-SYN' && x.action === 'remove_anonymous_links'), 'actions from each store\'s own facts');
  assert.ok(pl.items.every((x) => Object.keys(s.I.ACTIONS).includes(x.action)), 'fixed list of actions');
  assert.equal((await s.call('POST', '/data-posture/plans', OP2, {})).status, 409, 'one plan waiting at a time');
  await assert.rejects(s.I.draftPlan({}, { user: 'ai:dspm', role: 'operator' }), /service or AI identity/);
  r = await s.call('POST', '/data-posture/plans/' + pl.id + '/decide', OP, { decision: 'approve' }); assert.equal(r.status, 403); assert.match(r.text, /four-eyes/);
  r = await s.call('POST', '/data-posture/plans/' + pl.id + '/decide', OP2, { decision: 'reject' }); assert.equal(r.status, 400); assert.match(r.text, /note is required/);
  r = await s.call('POST', '/data-posture/plans/' + pl.id + '/items/' + pub.n, OP2, { status: 'claimed' }); assert.equal(r.status, 409, 'items wait for approval');
  r = await s.call('POST', '/data-posture/plans/' + pl.id + '/decide', OP2, { decision: 'approve' }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.status, 'approved'); assert.equal(r.json.due_at, new Date(T0 + 30 * DAY).toISOString());
  r = await s.call('POST', '/data-posture/plans/' + pl.id + '/items/' + pub.n, OP, { status: 'accepted_risk' }); assert.equal(r.status, 400); assert.match(r.text, /note is required/);
  r = await s.call('POST', '/data-posture/plans/' + pl.id + '/items/' + pub.n, OP, { status: 'done' }); assert.equal(r.status, 400); assert.match(r.text, /status must be one of/);
  r = await s.call('POST', '/data-posture/plans/' + pl.id + '/items/' + pub.n, OP, { status: 'claimed', note: 'public access switched off' }); assert.equal(r.json.items.find((x) => x.n === pub.n).status, 'claimed', 'a claim is recorded, not verified');
  r = await s.call('GET', '/data-posture/plans', OP); assert.equal(r.json.items[0].items.find((x) => x.n === pub.n).status, 'claimed', 'not verified while the data still shows it');
  fixed = true; s.P.flush();
  r = await s.call('GET', '/data-posture/plans', OP);
  const it = r.json.items[0].items.find((x) => x.n === pub.n);
  assert.equal(it.status, 'verified'); assert.match(it.history.at(-1).note, /latest read no longer shows it/);
  assert.ok(r.json.items[0].items.filter((x) => x.store === 'claimsdocssyn' && x.action === 'rotate_and_remove_secrets').every((x) => x.status !== 'verified'), 'the secret is still there: not verified');
  assert.equal(r.json.items[0].progress.verified, 1);
  assert.equal((await s.call('POST', '/data-posture/plans/' + pl.id + '/items/' + pub.n, OP, { status: 'open' })).status, 409, 'a verified item stays verified');
  for (const a of ['data.posture.plan.draft', 'data.posture.plan.approve', 'data.posture.plan.item', 'data.posture.plan.verified']) assert.ok(s.audits(a).length >= 1, a + ' audited');
  assert.equal(s.audits('data.posture.plan.verified')[0].by, 'system:dspm-verify');
  assert.equal((await s.call('GET', '/data-posture/plans', VIEW)).status, 403);
  assert.equal((await s.call('POST', '/data-posture/plans/NOPE/decide', OP2, { decision: 'approve' })).status, 404);
});

test('dspm intel: access graph with risky paths, label suggestions with mismatches, redundant / obsolete data; viewer counts only', async (t) => {
  const D = F.siemData(T0), files = JSON.parse(JSON.stringify(D['/pii/files']));
  // a copy of the payroll file on the file share: the same name in two places
  files.fileshares.hosts[0].settings.roots[0].hits.push({ p: 'D:\\Public\\payroll-syn.xlsx', kinds: { iban: 1 }, name_kinds: [], open: false, modified: new Date(T0 - 5 * DAY).toISOString() });
  const s = await setup(t, { siem: F.fakeSiem(T0, { override: { '/pii/files': files } }) });
  const v = (await s.call('GET', '/data-posture/insights', OP)).json;
  const g = v.graph;
  assert.ok(g.classes.includes('identity') && g.classes.includes('credentials') && g.access.some((a) => a.id === 'public') && g.access.some((a) => a.id === 'abroad'));
  assert.ok(g.risky.some((r) => r.store === 'claimsdocssyn' && r.class === 'identity' && r.access === 'abroad'), 'identity data abroad is a risky path');
  assert.ok(g.risky.some((r) => r.store === 'HR-Site-SYN' && r.access === 'anonymous'), 'sensitive data behind an anonymous link');
  assert.ok(!g.risky.some((r) => r.access === 'wide'), 'organisation-wide is drawn but not called a path outside');
  assert.ok(g.edges.some((e) => e.from === 'identity' && e.to === g.stores.find((x) => x.label === 'claimsdocssyn').id));
  const L = Object.fromEntries(v.labels.items.map((x) => [x.store, x]));
  assert.equal(L.claimsdocssyn.suggested, 'Restricted'); assert.equal(L.claimsdocssyn.mismatch, true); assert.match(L.claimsdocssyn.why, /reachable outside/);
  assert.equal(L.ksaarchivesyn.suggested, 'Restricted'); assert.equal(L.ksaarchivesyn.mismatch, false, 'in the Kingdom and private: no mismatch');
  assert.equal(L.unknownsyn.suggested, 'Internal');
  assert.equal(L['HR-Site-SYN'].files.restricted >= 2, true, 'files counted per label');
  assert.equal(v.labels.mismatches >= 2, true);
  assert.equal(v.rot.redundant.groups, 1); assert.deepEqual(v.rot.redundant.items[0].stores.sort(), ['HR-Site-SYN', '\\\\FS-SYN-01\\Public']);
  assert.equal(v.rot.obsolete.files, 1, 'the file unchanged for 3 years'); assert.match(v.rot.note, /nothing is deleted/);
  const vv = (await s.call('GET', '/data-posture/insights', VIEW)).json;
  assert.equal(vv.graph.edges, undefined); assert.equal(vv.labels.items, undefined); assert.equal(vv.rot.redundant.items, undefined);
  assert.ok(vv.graph.risky_total >= 2 && vv.rot.redundant.groups === 1, 'viewer: counts only');
});
