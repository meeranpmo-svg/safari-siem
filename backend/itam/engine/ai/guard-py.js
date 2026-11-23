// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The AI guard rails answered by Python (pyengine/ai_guard.py, migration step 9j-a): the masking applied before anything
// leaves for the model (sanitise.js) and the parsing / anti-hallucination check of what comes back (validate.js).
// They are a privacy control, so a port must never weaken them: BOTH run on every call (AI calls are capped - a few dozen a
// day - so the cost is nothing) and Python's answer is used only when it is identical to the Node.js one. A difference is
// counted (stats().different, the first one kept in stats().first_difference without the text) and the Node.js answer
// used. That is the measurement step 5 of the plan asks for before the Node.js module is removed: one month, no difference.
// ai.guard_engine = "node" turns Python off. Never throws: without Python the Node.js functions answer as before.
//   guardFor(config) → { sanitisePair(system, prompt, terms) → Promise, validateOutput(kind, text, ctx, res) → Promise, stats() }
const { isDeepStrictEqual } = require('node:util');
const { sanitisePair } = require('./sanitise');
const { validateOutput } = require('./validate');

const guards = new Map();
function guardFor(config) {
  const off = ((config && config.ai) || {}).guard_engine === 'node';
  const python = ((config && config.discovery) || {}).python_bin || '';
  const key = off ? 'off' : python;
  if (guards.has(key)) return guards.get(key);
  let py = null;
  if (!off) { try { py = require('../pyengine').createPyEngine({ python: python || undefined, timeoutMs: 30000 }); } catch (e) { py = null; } }
  const stats = { python: 0, node: 0, different: 0, first_difference: null };
  const plain = (v) => JSON.parse(JSON.stringify(v));
  async function both(op, body, nodeFn) {
    const n = nodeFn();
    if (!py) { stats.node++; return n; }
    let r = null; try { r = await py.call(op, body); } catch (e) { r = null; }
    if (!r || r.ok === false || r.node) { stats.node++; return n; }
    delete r.ok;
    if (isDeepStrictEqual(r, plain(n))) { stats.python++; return r; }
    stats.different++; stats.node++;
    if (!stats.first_difference) stats.first_difference = { op, at: new Date().toISOString() };   // never the text: it may carry what was masked
    return n;
  }
  const g = {
    sanitisePair: (system, prompt, terms) => both('ai.sanitise_pair', { system: String(system == null ? '' : system), prompt: String(prompt == null ? '' : prompt), redact_terms: Array.isArray(terms) ? terms : [] }, () => sanitisePair(system, prompt, terms)),
    validateOutput: (kind, text, ctx, res) => both('ai.validate', { kind, text: String(text || ''), ctx: ctx || {}, res: { truncated: !!(res && res.truncated) } }, () => validateOutput(kind, text, ctx, res)),
    stats: () => Object.assign({}, stats),
  };
  guards.set(key, g);
  return g;
}

module.exports = { guardFor };
