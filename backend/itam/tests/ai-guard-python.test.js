// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Migration step 9j-a (docs/PYTHON-MIGRATION.md): the AI guard rails in Python (pyengine/ai_guard.py) must mask and
// validate exactly like engine/ai/sanitise.js and engine/ai/validate.js. A privacy control is checked harder than the
// other ports: hand-written cases for every rule (e-mail, IBAN, card, KSA mobile, ID, IPv4 host octet, redaction terms
// in Arabic, with accents, next to digits / underscores / emoji, overlapping, upper / lower case), then thousands of
// random strings built from the characters the rules care about. And end to end: an AI job's prompt and result go
// through engine/ai/guard-py.js, which uses Python's answer only when it equals the Node.js one - no difference allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { sanitisePair } = require('../engine/ai/sanitise');
const { validateOutput } = require('../engine/ai/validate');
const { createPyEngine } = require('../engine/pyengine');
const { guardFor } = require('../engine/ai/guard-py');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const plain = (v) => JSON.parse(JSON.stringify(v));

test('AI guard rails: Python masks and validates exactly like Node.js', { skip: !hasPy && 'python3 not available' }, async () => {
  const py = createPyEngine({ python: PY, timeoutMs: 60000 });
  const terms = ['Project Falcon', 'محمد العتيبي', 'José', 'ACME', 'strasse', 'x', 'ab', 'Riyadh-DC1', 'falcon'];
  const texts = [
    ('Owner: ali.alqahtani@' + ZYB_ORG.domain + ', backup a.b+c@mail.co.uk; not@local'),
    'IBAN SA03 8000 0000 6080 1016 7519 and sa0380000000608010167519 and SA03 8000',
    'card 4111 1111 1111 1111 / 4111-1111-1111-1111-123 / 4111111111111111 / 12345678901234567890',
    'call +966 50 123 4567, 00966501234567, 966-5-0-1-2-3-4-5-6-7, 0501234567, 05012345678',
    'iqama 2123456789 and 12345678901 and 1234567890x',
    'hosts 10.1.2.3, 192.168.300.4, 1.2.3.4.5, v10.0.0.1, 999.999.999.999',
    'Project Falcon and project falcon and PROJECT FALCON_2 and falcon2 and _falcon and Falcon.',
    'محمد العتيبي يملك الجهاز، و محمد العتيبيX ليس هو',
    'José and JOSÉ and josé and Josés and 😀José😀',
    'ACME-1 ACME_1 1ACME ACMEACME acme Straße STRASSE strasse Riyadh-DC1 riyadh-dc1.',
    '', 'ab cd ab_ab ab1 ab', 'İstanbul ı i I',
  ];
  for (const t of texts) {
    const n = sanitisePair('System: ' + t, t, terms), p = await py.callOnce('ai.sanitise_pair', { system: 'System: ' + t, prompt: t, redact_terms: terms });
    delete p.ok;
    assert.deepEqual(p, n, t);
  }
  // random strings from the characters the rules look at
  let seed = 7; const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  const parts = ['0', '1', '5', '9', '966', '+966', '00966', ' ', '-', '.', '@', 'a', 'Z', 'SA', 'sa', '_', 'x.y', 'é', 'م', '😀', '\n', 'ACME', 'acme', 'José', 'ab'];
  const fuzz = [];
  for (let i = 0; i < 3000; i++) { let s = ''; const len = 1 + rnd(40); for (let k = 0; k < len; k++) s += parts[rnd(parts.length)]; fuzz.push(s); }
  // one Python process for the lot: the resident service when it runs, one call per string otherwise
  for (const s of fuzz) {
    const n = sanitisePair(s, s, terms), p = await py.call('ai.sanitise_pair', { system: s, prompt: s, redact_terms: terms });
    delete p.ok;
    assert.deepEqual(p, n, JSON.stringify(s));
  }
  // validation
  const ctx = { ids: ['a1', 'a2', 'a3'] };
  const out = [
    ['classify', '```json\n{"assets":[{"ref":"a1","type":"Server","vendor":" Dell ","confidence":"1.7"},{"ref":"zz"},{"id":"a2","type":"toaster","confidence":-1}],"merges":[{"keep":"a1","duplicate":"a2","confidence":0.5},{"keep":"a1","dup":"a1"}]}\n```'],
    ['classify', 'Here you go: {"assets":[{"ref":"a3","category":12,"rationale":true}],"merges":[],} trailing'],
    ['relate', '```\n{"relationships":[{"from":"a1","to":"a2","type":"RUNS_ON","confidence":0.9},{"from":"a1","to":"a1","type":"runs_on"},{"from":"a1","to":"a9","type":"runs_on"}]}\n```'],
    ['refresh', '{“summary”: “ok”, “items”: [{“asset_id”: “a1”, “action”: “Replace”, “estimated_cost”: “12000”}, {“asset_id”: “a2”, “estimated_cost”: null}], “risks”: [“eol”, “”, 5]}'],
    ['refresh', '{"items":{"asset_id":"a3","when":"2027-Q1","estimated_cost":"lots"},"risks":"one"}'],
    ['classify', ''], ['classify', 'no json at all'], ['relate', '```json\n[1,2]\n```'],
    ['classify', '{"assets": [{"ref": "a1", "confidence": 1e400}]}'],
    ['classify', '{"assets": [{"ref": "a1", "confidence": NaN}]}'],               // JSON.parse error: V8's own wording, Node.js answers
  ];
  let node = 0;
  for (const [kind, text] of out) {
    const n = validateOutput(kind, text, ctx, { truncated: kind === 'refresh' });
    const p = await py.callOnce('ai.validate', { kind, text, ctx, res: { truncated: kind === 'refresh' } });
    if (p.node) { node++; continue; }
    delete p.ok;
    assert.deepEqual(p, plain(n), kind + ' ' + text);
  }
  assert.equal(node, 1, 'only the V8 parse-error wording is handed back');

  // end to end: the guard compares and counts
  const g = guardFor({ discovery: { python_bin: PY } });
  for (const t of texts) assert.deepEqual(await g.sanitisePair(t, t, terms), sanitisePair(t, t, terms));
  for (const [kind, text] of out) assert.deepEqual(plain(await g.validateOutput(kind, text, ctx, {})), plain(validateOutput(kind, text, ctx, {})));
  const st = g.stats();
  assert.equal(st.different, 0, 'no difference: ' + JSON.stringify(st));
  assert.equal(st.python, texts.length + out.length - 1, 'Python answered all but the one handed back');
  const off = guardFor({ ai: { guard_engine: 'node' } });
  await off.sanitisePair('a@b.cc', 'x', []);
  assert.deepEqual(off.stats(), { python: 0, node: 1, different: 0, first_difference: null });
});
