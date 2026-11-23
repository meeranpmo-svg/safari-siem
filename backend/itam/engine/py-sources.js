// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// A device-reading module answered by Python (docs/PYTHON-MIGRATION.md): the same interface as the Node.js module it
// replaces - {baseOf, guard, <kind>(cred, opts), test(kind, cred, opts)} - each call one request to pyengine/run.py
// ("<module>.collect" / "<module>.test"). Credentials and options travel on stdin only. When Python or the module is not
// available the Node.js module answers instead and the result says engine:'node (python unavailable: …)'.
//   createPySources({module: 'backup', kinds: ['netbackup', …], node: require('./backup-sources'), python?, py?})
const { createPyEngine } = require('./pyengine');

// only plain values cross to Python (a test's request override, for example, stays in Node)
function plainOpts(o) { const out = {}; for (const [k, v] of Object.entries(o || {})) if (v !== undefined && (v === null || ['string', 'number', 'boolean'].includes(typeof v))) out[k] = v; return out; }

function createPySources(c) {
  const py = c.py || createPyEngine({ python: c.python }), node = c.node;
  async function run(op, kind, cred, opts, nodeFn) {
    const r = await py.call(`${c.module}.${op}`, { kind, cred: { target: (cred && cred.target) || {}, secret: (cred && cred.secret) || {} }, opts: plainOpts(opts) });
    if (r && r.error_class === 'missing_python') { const n = await nodeFn(); return Object.assign(n, { engine: 'node (python unavailable: ' + r.error + ')' }); }
    return Object.assign(r || {}, { engine: 'python' });
  }
  const out = { baseOf: node.baseOf, guard: node.guard, test: (kind, cred, opts) => run('test', kind, cred, opts, () => node.test(kind, cred, opts)) };
  for (const k of c.kinds) out[k] = (cred, opts) => run('collect', k, cred, opts, () => node[k](cred, opts));
  return out;
}

module.exports = { createPySources, plainOpts };
