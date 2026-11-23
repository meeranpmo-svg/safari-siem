// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Governance (engine/aigov-intel.js) over the REAL installed modules and the REAL shared AI budget: the register is discovered from
// the modules with an AI advisor (none of them write-capable); a module with a write-capable tool is flagged; usage recorded from the
// budget (user, feature, tokens, flags, refusals - never the question); the injection-flag rate; an unusual day after a steady week;
// the yearly review recorded by an administrator (a person, validation naming the field, audited), overdue said; roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const G = require('../engine/ai-guard');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:grc', role: 'admin' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, A: e.app.addons.aigovIntel, post: (p, b, who = ADM) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}

test('the register is discovered, read-only; a write-capable tool is flagged', async (t) => {
  const s = await setup(t);
  let v = (await s.get('/aigov-intel', VIEW)).json;
  assert.ok(v.sections[0].items.length >= 10, 'discovered from the installed modules'); assert.ok(v.sections[0].items.every((i) => i.tags.includes('readonly')), 'every installed advisor is read-only');
  assert.ok(v.sections[0].items.some((i) => i.id === 'roadmap') && v.sections[0].items.every((i) => i.tags.includes('review_due')), 'never reviewed = review due');
  s.e.app.addons.rogueBot = { aiStatus: () => ({ enabled: true, model: 'synthetic' }), TOOLS: [{ name: 'read_things' }, { name: 'delete_asset' }, { name: 'propose_change' }] };
  v = (await s.get('/aigov-intel')).json; const rb = v.sections[0].items.find((i) => i.id === 'rogueBot');
  assert.ok(rb.tags.includes('write')); assert.deepEqual(rb.detail.lists.find((l) => /Write-capable/.test(l.title)).items, ['delete_asset'], 'a proposal is not a write');
  assert.match(v.sections.find((x) => x.id === 'controls').text, /mitigated, not solved/);
});

test('usage from the shared budget, flag rate, unusual day; the yearly review', async (t) => {
  const s = await setup(t), B = G.sharedBudget({});
  const at = (d) => new Date(Date.now() - d * DAY).toISOString();
  for (let d = 9; d >= 1; d--) for (let i = 0; i < 2; i++) s.A.onEntry({ at: at(d), user: 'nora.syn', feature: 'itam.synthetic-advisor', tokens: 100 });
  for (let i = 0; i < 12; i++) s.A.onEntry({ at: new Date().toISOString(), user: 'omar.syn', feature: 'itam.synthetic-advisor', tokens: 50, injection_signals: i < 3 ? [1] : undefined });
  s.A.onEntry({ at: new Date().toISOString(), user: 'omar.syn', feature: 'itam.synthetic-advisor', refused: 'you have asked the AI 30 times in the last hour' });
  B.record('huda.syn', 'itam.live-advisor', { input_tokens: 10, output_tokens: 5 }, []);   // through the real budget listener
  const v = (await s.get('/aigov-intel')).json, row = v.sections[1].rows.find((r) => r.id === 'itam.synthetic-advisor');
  assert.equal(row.cells[1], 30); assert.equal(row.cells[3], 2); assert.equal(row.cells[4], 1); assert.match(String(row.cells[5]), /^3 \(13 %\)/);
  assert.ok(row.tags.includes('unusual') && /usual 2/.test(row.cells[6].text), '12 today against a usual 2');
  assert.ok(v.sections[1].rows.some((r) => r.id === 'itam.live-advisor'), 'a real budget record is kept');
  assert.ok(!JSON.stringify(s.e.app.store.collection('aigov_usage').all()).includes('question'), 'no question text is kept');
  // review
  assert.equal((await s.post('/aigov-intel/roadmap/review', { note: 'tools and results reviewed (synthetic)' }, OP)).status, 403);
  assert.equal((await s.post('/aigov-intel/roadmap/review', { note: 'tools and results reviewed (synthetic)' }, BOT)).status, 403);
  let r = await s.post('/aigov-intel/roadmap/review', { note: 'short' }); assert.equal(r.status, 400); assert.match(r.json.error, /note/);
  assert.equal((await s.post('/aigov-intel/nope/review', { note: 'tools and results reviewed (synthetic)' })).status, 404);
  r = await s.post('/aigov-intel/roadmap/review', { note: 'tools and results reviewed (synthetic)' }); assert.equal(r.status, 200, r.raw);
  const v2 = (await s.get('/aigov-intel')).json; assert.ok(v2.sections[0].items.find((i) => i.id === 'roadmap').tags.includes('reviewed'));
  assert.equal(s.audit('aigov-intel.review').length, 1);
  assert.equal((await s.post('/aigov-intel/ask', { question: 'what governance gaps?' }, VIEW)).status, 403);
});

// agent commander: reach and itemised risk, pause refused by the real ai-guard, resume four-eyes, shadow AI from the software inventory,
// sanction (admin, a person, reason), framework checks; validation names the field; roles; audit records
test('posture, pause / four-eyes resume through ai-guard, shadow AI and framework checks', async (t) => {
  const s = await setup(t), B = G.sharedBudget({}), ADM2 = { user: 'huda.syn', role: 'admin' };
  s.e.app.addons.claimsBot = { aiStatus: () => ({ enabled: true, model: 'claude-synthetic', feature: 'itam.claims-synthetic' }), TOOLS: [{ name: 'claims_lookup', description: 'reads claims and customer records' }, { name: 'list_secrets', description: 'credential vault entries' }, { name: 'update_claim' }] };
  let v = (await s.get('/aigov-intel')).json; const cb = v.sections.find((x) => x.id === 'systems').items.find((i) => i.id === 'claimsBot');
  const pts = cb.detail.lists.find((l) => /Why this risk/.test(l.title)).items.join('|');
  assert.match(pts, /\+30 write-capable tool\(s\): update_claim/); assert.match(pts, /\+15 reads credentials/); assert.match(pts, /\+10 reads health/); assert.match(pts, /\+12 reads personal/); assert.match(pts, /\+10 no review/);
  assert.ok(cb.tags.includes('high_risk')); const bar = v.sections.find((x) => x.id === 'posture').items[0]; assert.equal(bar.id, 'claimsBot', 'riskiest first');
  // pause: roles, validation, unknown feature, a service identity
  const P = (a, b, who) => s.post('/aigov-intel/control/' + a, b, who);
  assert.equal((await P('pause', { feature: 'itam.claims-synthetic', reason: 'synthetic incident' }, OP)).status, 403);
  assert.equal((await P('pause', { feature: 'itam.claims-synthetic', reason: 'synthetic incident' }, BOT)).status, 403);
  let r = await P('pause', { feature: 'itam.claims-synthetic' }); assert.equal(r.status, 400); assert.match(r.json.error, /reason/);
  r = await P('pause', { feature: 'bad feature!', reason: 'synthetic incident' }); assert.equal(r.status, 400); assert.match(r.json.error, /feature/);
  assert.equal((await P('pause', { feature: 'itam.nope', reason: 'synthetic incident' })).status, 404);
  r = await P('pause', { feature: 'itam.claims-synthetic', reason: 'synthetic incident' }); assert.equal(r.status, 200, r.raw);
  assert.equal((await P('pause', { feature: 'itam.claims-synthetic', reason: 'synthetic incident' })).status, 409);
  // the real budget refuses the paused feature, and not another
  assert.throws(() => B.admit('nora.syn', 'itam.claims-synthetic', 10), (e) => e.status === 423 && /paused by syed/.test(e.message));
  assert.doesNotThrow(() => B.admit('pz1.syn', 'itam.other-synthetic', 10));
  v = (await s.get('/aigov-intel')).json; assert.equal(v.sections.find((x) => x.id === 'control').items[0].id, 'itam.claims-synthetic');
  // resume: request, the requester cannot approve, a different admin does
  assert.equal((await P('approve', { feature: 'itam.claims-synthetic' })).status, 409, 'nothing requested yet');
  r = await P('resume', { feature: 'itam.claims-synthetic', reason: 'tools reviewed (synthetic)' }); assert.equal(r.status, 200, r.raw);
  r = await P('approve', { feature: 'itam.claims-synthetic' }); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  assert.equal((await P('approve', { feature: 'itam.claims-synthetic' }, BOT)).status, 403, 'an AI identity never approves');
  r = await P('approve', { feature: 'itam.claims-synthetic' }, ADM2); assert.equal(r.status, 200, r.raw);
  assert.doesNotThrow(() => B.admit('pz2.syn', 'itam.claims-synthetic', 10), 'resumed');
  for (const a of ['pause', 'resume.request', 'resume.approve']) assert.equal(s.audit('aigov-intel.' + a).length, 1, a);
  // shadow AI from the software inventory
  v = (await s.get('/aigov-intel')).json; assert.match(v.sections.find((x) => x.id === 'shadow').caption, /no software inventory/);
  assert.equal(v.sections.find((x) => x.id === 'checks').rows.find((x) => x.id === 'shadow').cells[3].text, 'not measured');
  const A = s.e.app.store.collection('assets');
  A.put({ id: 'A-SYN-1', status: 'in_use', software: [{ name: 'Ollama', version: '0.5' }, { name: 'Microsoft Edge' }] });
  A.put({ id: 'A-SYN-2', status: 'in_use', software: [{ name: 'ChatGPT', publisher: 'OpenAI' }, { name: 'Wordpad' }] });
  v = (await s.get('/aigov-intel')).json; const sh = v.sections.find((x) => x.id === 'shadow').items;
  assert.deepEqual(sh.map((x) => x.title.split(' · ')[0]), ['Ollama', 'ChatGPT / OpenAI'], 'local runner first; Edge and Wordpad are not AI');
  assert.equal(v.sections.find((x) => x.id === 'checks').rows.find((x) => x.id === 'shadow').cells[3].text, 'gap');
  const key = sh[1].id;
  assert.equal((await s.post('/aigov-intel/shadow/sanction', { key, sanctioned: 'true', reason: 'enterprise tenant (synthetic)' }, OP)).status, 403);
  r = await s.post('/aigov-intel/shadow/sanction', { key, sanctioned: 'true' }); assert.equal(r.status, 400); assert.match(r.json.error, /reason/);
  assert.equal((await s.post('/aigov-intel/shadow/sanction', { key: 'nope', sanctioned: 'true', reason: 'enterprise tenant (synthetic)' })).status, 404);
  r = await s.post('/aigov-intel/shadow/sanction', { key, sanctioned: 'true', reason: 'enterprise tenant (synthetic)' }); assert.equal(r.status, 200, r.raw);
  v = (await s.get('/aigov-intel')).json; assert.ok(v.sections.find((x) => x.id === 'shadow').items.find((x) => x.id === key).badges[0].text === 'sanctioned');
  assert.equal(s.audit('aigov-intel.shadow.sanction').length, 1);
  const ch = v.sections.find((x) => x.id === 'checks').rows; assert.equal(ch.find((x) => x.id === 'oversight').cells[3].text, 'gap'); assert.equal(ch.find((x) => x.id === 'fairness').cells[3].text, 'not measured');
});
