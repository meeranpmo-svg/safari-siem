// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Data Lineage (engine/ai-lineage.js) on the same SYNTHETIC sources as Data Security Posture (tests/data-posture-fixtures.js):
// AI actors are only real ones - Shadow AI register apps (sanctioned / tolerated: allowed classes; DLP incidents let through: sent),
// Microsoft 365 Copilot only with a Copilot licence assigned (reaching the SharePoint / OneDrive stores), the platform's AI engineers
// from their read-only tools; every edge has its basis; viewers get stores grouped by type (no names), operators names (audited);
// the node limit groups the rest as "+N more"; validation of max; the empty and not-licensed states.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const DP = require('../engine/data-posture');
const AL = require('../engine/ai-lineage');
const F = require('./data-posture-fixtures');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };
const T0 = Date.parse('2026-11-08T08:00:00Z');

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.addons.pdpl = require('../engine/pdpl').createPdpl(e.app, { now: () => T0 });
  if (o.local !== false) F.seedLocal(e.app, T0);
  const siem = o.siem === null ? undefined : F.fakeSiem(T0, o.fake || {});
  DP.registerDataPosture(e.app.srv, e.app, DP.createDataPosture(e.app, { now: () => T0, siem, noTimer: true }));
  AL.registerAiLineage(e.app.srv, e.app, AL.createAiLineage(e.app, { now: () => T0 }));
  return { e, call: (p, who) => e.req('GET', p, who), audits: (a) => e.app.store.auditTail(200).filter((x) => x.action === a) };
}
const byLabel = (g, l) => g.nodes.find((n) => n.label === l);
const edges = (g, from, to) => g.edges.filter((e) => (!from || e.from === from.id) && (!to || e.to === to.id));

test('ai lineage: real actors only, each edge with its basis, stores with classes', async (t) => {
  const s = await setup(t);
  const r = await s.call('/ai-lineage', OP); assert.equal(r.status, 200, r.text);
  const g = r.json;
  assert.ok(g.edges.length && g.edges.every((e) => typeof e.basis === 'string' && e.basis.length > 20), 'every edge says why it exists');
  assert.ok(g.edges.every((e) => g.nodes.some((n) => n.id === e.from) && g.nodes.some((n) => n.id === e.to)), 'no dangling edge');
  // Microsoft 365 Copilot: licensed (4 of 10 seats) -> the SharePoint site and the OneDrive with findings
  const cop = byLabel(g, 'Microsoft 365 Copilot'); assert.ok(cop); assert.equal(cop.type, 'copilot'); assert.equal(cop.detail.assigned, 4); assert.equal(cop.detail.licensed_users, 1);
  const site = byLabel(g, 'HR-Site-SYN'), od = byLabel(g, 'OneDrive: alia.syn@example.invalid');
  assert.ok(site && od);
  const ce = edges(g, cop, site)[0]; assert.equal(ce.kind, 'reach'); assert.match(ce.basis, /4 of 10 Copilot seat/); assert.match(ce.basis, /Microsoft_365_Copilot/);
  assert.equal(edges(g, cop, od)[0].kind, 'reach');
  assert.ok(!edges(g, cop).some((e) => /claimsdocssyn|FS-SYN|DB/.test(g.nodes.find((n) => n.id === e.to).label)), 'Copilot reaches Microsoft 365 stores only');
  // Shadow AI: ChatGPT (tolerated) allowed confidential, actually sent personal; Microsoft Copilot (sanctioned) allowed personal + sent;
  // DeepSeek: blocked and its only incident was blocked - not an actor
  const gpt = byLabel(g, 'ChatGPT'), per = g.nodes.find((n) => n.id === 'c.personal'), conf = g.nodes.find((n) => n.id === 'c.confidential');
  assert.equal(edges(g, gpt, per)[0].kind, 'sent'); assert.equal(edges(g, gpt, per)[0].weight, 1); assert.match(edges(g, gpt, per)[0].basis, /let through/);
  assert.equal(edges(g, gpt, conf)[0].kind, 'allowed'); assert.match(edges(g, gpt, conf)[0].basis, /owner owner\.syn/);
  const mc = byLabel(g, 'Microsoft Copilot'); assert.deepEqual(edges(g, mc, per).map((e) => e.kind).sort(), ['allowed', 'sent']);
  assert.ok(!byLabel(g, 'DeepSeek'), 'a blocked app with nothing let through is not drawn');
  // the platform's AI engineers from their tools
  const pdpl = byLabel(g, 'AI PDPL Consultant'), claims = byLabel(g, 'CLAIMS-DB-SYN'), hr = byLabel(g, 'HRDB-SYN');
  assert.equal(edges(g, pdpl, claims)[0].kind, 'reads'); assert.match(edges(g, pdpl, claims)[0].basis, /only the number of matches is kept/);
  const sql = byLabel(g, 'AI Database Administrator'); assert.equal(edges(g, sql, hr)[0].kind, 'metadata'); assert.match(edges(g, sql, hr)[0].basis, /no table data/);
  assert.ok(!byLabel(g, 'AI Oracle DBA'), 'Database Health is not installed in this app: not drawn');
  assert.ok(g.not_drawn.some((x) => /Other AI engineers .*AI Network Engineer/.test(x)));
  // store -> class with counts; Azure store holds personal + credentials
  const az = byLabel(g, 'claimsdocssyn'), cred = g.nodes.find((n) => n.id === 'c.credentials');
  assert.equal(edges(g, az, per)[0].weight, 2); assert.equal(edges(g, az, cred)[0].weight, 1); assert.equal(edges(g, az, per)[0].kind, 'holds');
  assert.equal(edges(g, claims, g.nodes.find((n) => n.id === 'c.health'))[0].weight, 1);
  assert.deepEqual(g.nodes.filter((n) => n.column === 'class').map((n) => n.id.slice(2)).slice(0, 4), ['personal', 'health', 'financial', 'credentials'], 'classes ordered by sensitivity');
  assert.ok(byLabel(g, F.HOSTILE) === undefined, 'files are counted on their store, never drawn as nodes');
  const a = s.audits('ai.lineage.read').pop(); assert.equal(a.by, 'nora.syn'); assert.equal(a.role, 'operator'); assert.ok(a.detail.actors >= 5);
});

test('ai lineage: viewers get stores grouped by type, no names; the node limit groups the rest; max is validated', async (t) => {
  const s = await setup(t);
  const r = await s.call('/ai-lineage', VIEW); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.named, false);
  for (const n of ['HR-Site-SYN', 'alia.syn', 'claimsdocssyn', 'HRDB-SYN', 'CLAIMS-DB-SYN', 'FS-SYN-01', 'owner.syn', 'payroll-syn']) assert.ok(!r.text.includes(n), 'viewer graph has no ' + n);
  const stores = r.json.nodes.filter((n) => n.column === 'store');
  assert.ok(stores.length && stores.every((n) => n.group), 'every store node is a group');
  assert.ok(stores.some((n) => n.label === '3 Azure storage accounts'));
  assert.ok(r.json.nodes.some((n) => n.label === 'Microsoft 365 Copilot'), 'actors are not personal data');
  assert.ok(r.json.edges.some((e) => /merged into this group/.test(e.basis) || e.kind === 'holds'));
  assert.equal(s.audits('ai.lineage.read').length, 0, 'no named read for a viewer');
  const m = (await s.call('/ai-lineage?max=4', OP)).json, named = m.nodes.filter((n) => n.column === 'store' && !n.group), more = m.nodes.filter((n) => n.group);
  assert.equal(named.length, 4); assert.ok(more.length && more.every((n) => /^\+\d+ more /.test(n.label)));
  assert.equal(named.length + more.reduce((a, n) => a + n.members, 0), 8, 'every store is drawn or counted in a group');
  for (const [q, re] of [['max=2', /max must be at least 4/], ['max=99', /max must be at most 40/], ['max=lots', /max must be a whole number/]]) {
    const x = await s.call('/ai-lineage?' + q, OP); assert.equal(x.status, 400, q); assert.match(x.text, re);
  }
});

test('ai lineage: no Copilot licence, nothing connected, posture missing', async (t) => {
  const s = await setup(t, { fake: { noCopilot: true } });
  const g = (await s.call('/ai-lineage', OP)).json;
  assert.ok(!byLabel(g, 'Microsoft 365 Copilot')); assert.ok(g.notes.some((n) => /no Copilot licence with seats assigned/.test(n)));
  const s2 = await setup(t, { siem: null, local: false });
  const g2 = (await s2.call('/ai-lineage', VIEW)).json;
  assert.equal(g2.nodes.length, 0); assert.match(g2.empty, /No AI actor reaches a data store yet/);
  assert.ok(g2.notes.some((n) => /Copilot is not judged/.test(n)) && g2.notes.some((n) => /AI apps are not drawn/.test(n)));
  // the lineage without Data Security Posture says what to install
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  AL.registerAiLineage(e.app.srv, e.app, AL.createAiLineage(e.app, {}));
  const x = await e.req('GET', '/ai-lineage', OP); assert.equal(x.status, 409); assert.match(x.text, /Data Security Posture .* is not installed/);
  assert.equal((await e.req('GET', '/ai-lineage', { user: '', role: '' })).status === 200, false, 'a caller with no identity is refused');
});
