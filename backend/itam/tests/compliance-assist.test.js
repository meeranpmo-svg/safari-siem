// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Compliance Assistant (engine/compliance-assist.js, pyengine/assist_rules.py) through the real routes over the REAL registers
// (SAMA + IA, NCA ECC, ISO 27001, NDMO, PDPL) on SYNTHETIC data: the intent model, the requirement search, the plain-language
// explanation, what to do first with every factor in words, a question it cannot match is not guessed, roles (viewer may ask,
// only the asker rates, admin sees what was learned), validation errors naming the field, the audit record, the learning
// (a correction teaches the intent; only compliance words are kept, never the question text or a name).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [], control_status: {} },
  hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: 2 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 0, high: 0 }, internet_facing: 3, exposed_assets: 0 },
  cadence: { available: true, assets: 12, out_of_policy: 3 },
  siem: { available: true, sama: { '3.3.14': 'covered' }, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } } });

async function setup(t) {
  const clock = Date.parse('2026-10-30T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, samaFacts: async () => FACTS(), eccFacts: async () => FACTS(), isoFacts: async () => FACTS(), ndmoCatalogFiles: false });
  const call = async (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, post: (p, b, who = VIEW) => call('POST', p, b, who), get: (p, who = VIEW) => call('GET', p, undefined, who) };
}
const auditOf = (e, action) => e.app.store.auditTail(200).filter((x) => x.action === action);

test('overview: every framework in one plain sentence and what to do first, with the reasons in words', async (t) => {
  const { get } = await setup(t);
  const r = await get('/assist/overview');
  assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.deepEqual(v.frameworks.map((f) => f.fw), ['sama', 'ecc', 'iso', 'ndmo', 'pdpl']);
  assert.ok(v.frameworks.every((f) => f.installed && f.counts.total > 0), 'all five registers read');
  assert.match(v.frameworks[0].sentence, /^SAMA CSF \+ IA: \d+ of \d+ applicable requirements are done \(\d+%\)\./);
  assert.ok(v.first.length >= 5 && v.first.every((x) => x.score > 0 && x.why.length >= 2 && x.todo), 'ranked, with reasons and a next step');
  assert.ok(v.first.some((x) => x.why.some((w) => /one fix also counts for/.test(w))), 'one fix closing several frameworks is said');
  for (let i = 1; i < v.first.length; i++) assert.ok(v.first[i - 1].score >= v.first[i].score, 'sorted by score');
  assert.match(v.method, /importance/);
  assert.deepEqual(v.not_installed, []);
});

test('ask: intent + requirement + plain explanation; a status question gets the overview; nonsense is not guessed', async (t) => {
  const { e, post } = await setup(t);
  let r = await post('/assist/ask', { question: 'Who approves the evidence for the cybersecurity strategy?' });
  assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.intent, 'who');
  const m = r.json.matches[0];
  assert.ok(m && /strategy/i.test(m.title), 'the strategy requirement is found: ' + (m && m.title));
  assert.match(r.json.summary, /Approved by the CISO/);
  for (const k of ['what', 'where', 'todo', 'evidence', 'who', 'checked', 'importance']) assert.ok(m[k], 'the explanation has ' + k);
  assert.match(r.json.ask_id, /^ask-[0-9a-f]{16}$/);
  assert.equal(r.json.tokens, undefined, 'the kept words are not sent back');
  assert.match(r.json.engine, /nothing is sent outside/);

  r = await post('/assist/ask', { question: 'Are we compliant with SAMA?' });
  assert.equal(r.json.intent, 'status'); assert.equal(r.json.fw, 'sama');
  assert.deepEqual(r.json.overview.frameworks.map((f) => f.fw), ['sama'], 'scoped to the framework named');
  assert.match(r.json.summary, /^SAMA CSF \+ IA: \d+ of/);

  r = await post('/assist/ask', { question: 'What should we fix first?' });
  assert.equal(r.json.intent, 'todo'); assert.ok(r.json.overview.first.length > 0);

  r = await post('/assist/ask', { question: 'what is a DPIA' });
  assert.equal(r.json.intent, 'explain'); assert.match(r.json.summary, /Data Protection Impact Assessment/);
  assert.ok(r.json.glossary.some((g) => g.term === 'dpia'));

  r = await post('/assist/ask', { question: 'how do we keep our backups safe' });
  assert.ok(r.json.matches.length && r.json.matches.some((x) => /backup/i.test(x.title + x.evidence)), 'plain word "backups" finds the backup requirements');

  r = await post('/assist/ask', { question: 'ما هي نسبة الامتثال' });
  assert.equal(r.json.intent, 'status', 'Arabic: what is the compliance percentage');

  r = await post('/assist/ask', { question: 'xyzzy plugh frobnicate' });
  assert.equal(r.json.matches.length, 0); assert.match(r.json.summary, /will not guess/);
  assert.ok(r.json.suggest.length > 0);

  r = await post('/assist/ask', { question: 'why is NDMO ZS-DG-01 a gap', fw: 'ndmo' });
  assert.equal(r.json.intent, 'why'); assert.equal(r.json.matches[0].id, 'ZS-DG-01', 'an exact id wins');
  assert.equal(r.json.matches[0].status, 'Not done');
  assert.equal(auditOf(e, 'assist.ask').length, 0, 'asking changes nothing, so nothing is audited');
});

test('explain one requirement; validation errors name the field', async (t) => {
  const { get, post } = await setup(t);
  let r = await get('/assist/explain/ecc/ZS-1-1-01');
  assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.framework, 'NCA ECC'); assert.match(r.json.what, /^It asks that: /); assert.ok(r.json.todo);
  assert.ok(!JSON.stringify(r.json).includes('confirmation'), 'no confirmation (who recorded / approved) in an answer');
  r = await get('/assist/explain/ecc/ZS-9-9-99'); assert.equal(r.status, 404); assert.match(r.json.error, /not in the NCA ECC register/);
  r = await get('/assist/explain/cobit/X-1'); assert.equal(r.status, 400); assert.match(r.json.error, /fw must be one of/);
  r = await post('/assist/ask', {}); assert.equal(r.status, 400); assert.match(r.json.error, /question is required/);
  r = await post('/assist/ask', { question: 'x'.repeat(501) }); assert.equal(r.status, 400); assert.match(r.json.error, /question is longer than 500/);
  r = await post('/assist/ask', { question: 'backups', fw: 'cobit' }); assert.equal(r.status, 400); assert.match(r.json.error, /fw must be one of/);
  r = await post('/assist/feedback', { ask_id: 'nope', helpful: true }); assert.equal(r.status, 400); assert.match(r.json.error, /ask_id is not an answer id/);
  r = await post('/assist/feedback', { ask_id: 'ask-0123456789abcdef', helpful: 'yes' }); assert.equal(r.status, 400); assert.match(r.json.error, /helpful must be true or false/);
  r = await get('/assist/glossary');
  assert.ok(r.json.terms.length >= 20 && r.json.states.length === 5 && r.json.frameworks.length === 5);
});

test('feedback: only the asker rates, once; a correction teaches the intent; only compliance words kept; audited; admin sees learning', async (t) => {
  const { e, post, get } = await setup(t);
  const q = 'Ahmed Alharbi asked: who looks after the encryption keys';
  let r = await post('/assist/ask', { question: q }, OP);
  const id = r.json.ask_id;
  r = await post('/assist/feedback', { ask_id: id, helpful: true }, VIEW); assert.equal(r.status, 403); assert.match(r.json.error, /only the person who asked/);
  r = await post('/assist/feedback', { ask_id: id, helpful: false, intent: 'evidence' }, OP);
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.intent, 'evidence'); assert.equal(r.json.learned, true);
  r = await post('/assist/feedback', { ask_id: id, helpful: true }, OP); assert.equal(r.status, 409);
  r = await post('/assist/feedback', { ask_id: 'ask-0123456789abcdef', helpful: true }, OP); assert.equal(r.status, 404);
  const kept = e.app.store.collection('assist_feedback').all(() => true);
  assert.equal(kept.length, 1);
  const blob = JSON.stringify(kept);
  assert.ok(!/ahmed|alharbi/i.test(blob), 'a name typed in the question is never kept');
  assert.ok(!blob.includes('looks after'), 'the question text is never kept');
  assert.ok(kept[0].tokens.some((x) => /encrypt|key/.test(x)), 'the compliance words are kept');
  const a = auditOf(e, 'assist.feedback');
  assert.equal(a.length, 1); assert.equal(a[0].by, 'nora.syn'); assert.equal(a[0].detail.corrected, true); assert.equal(a[0].detail.intent, 'evidence');
  assert.ok(!JSON.stringify(a).includes('Alharbi'), 'the audit names who rated, not who was asked about');
  r = await get('/assist/learning', OP); assert.equal(r.status, 403, 'operators cannot read what was learned');
  r = await get('/assist/learning', ADM); assert.equal(r.status, 200); assert.equal(r.json.ratings, 1); assert.equal(r.json.corrected, 1);
  // the correction is used: helpful examples train the intent model on the next question
  for (let i = 0; i < 4; i++) {
    const x = await post('/assist/ask', { question: 'encryption keys custody' }, OP);
    await post('/assist/feedback', { ask_id: x.json.ask_id, helpful: true, intent: 'evidence' }, OP);
  }
  r = await post('/assist/ask', { question: 'encryption keys custody' }, OP);
  assert.equal(r.json.intent, 'evidence', 'learned from the corrections');
});

test('a register not installed is named, never counted as passing; Python missing is a 409 the page can show', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const { registerComplianceAssist, createComplianceAssist } = require('../engine/compliance-assist');
  registerComplianceAssist(e.app.srv, e.app, createComplianceAssist(e.app, { python: PY }));
  let r = await e.req('GET', '/assist/overview', VIEW);
  assert.equal(r.status, 200, r.raw);
  assert.deepEqual(r.json.not_installed, ['SAMA CSF + IA', 'NCA ECC', 'ISO 27001', 'NDMO', 'PDPL']);
  assert.ok(r.json.frameworks.every((f) => !f.installed && /not installed/.test(f.sentence)));
  r = await e.req('POST', '/assist/ask', Object.assign({ body: { question: 'are we compliant' } }, VIEW));
  assert.match(r.json.summary, /No compliance register answered/);
  const e2 = await startApp({ noAi: true }); t.after(() => e2.close());
  registerComplianceAssist(e2.app.srv, e2.app, createComplianceAssist(e2.app, { py: { call: async () => ({ ok: false, error_class: 'missing_python' }) } }));
  r = await e2.req('GET', '/assist/overview', VIEW);
  assert.equal(r.status, 409); assert.match(r.json.error, /Python did not answer/);
});
