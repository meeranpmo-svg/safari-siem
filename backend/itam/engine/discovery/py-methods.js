// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset Discovery inventory sources answered by Python (pyengine/discovery_sources.py, docs/PYTHON-MIGRATION.md step 5a):
// vcenter, esxi, nutanix, azure, aws, cucm (step 5a) and ad (step 5b). Each keeps the interface of its Node.js module - collect(cred, o) and
// test(cred, o), plus the module's other exports - and each call is one request to pyengine/run.py with the credential
// on stdin only. The Node.js module answers instead when: an injected request (tests) is passed, config
// discovery.engine = "node", or Python / the module is not installed (the answer then says engine:'node (python
// unavailable: …)').
//   configure({python, engine})   called once by createDiscovery with the IT Asset Management config
//   wrap(name, nodeModule)        → the module, answered by Python
const { createPyEngine } = require('../pyengine');
const { plainOpts } = require('../py-sources');

const st = { python: '/opt/sentra-siem/pyenv/bin/python3', engine: 'python', py: null };
function configure(o = {}) {
  if (o.python) st.python = o.python;
  if (o.engine) st.engine = o.engine === 'node' ? 'node' : 'python';
  st.py = o.py || null;
}
const engine = () => st.py || (st.py = createPyEngine({ python: st.python, timeoutMs: 15 * 60000 }));
const plainCred = (c) => Object.assign({ target: (c && c.target) || {}, secret: (c && c.secret) || {} }, c && c.kind ? { kind: c.kind } : {});

function wrap(name, node) {
  async function run(op, cred, o) {
    // an option that cannot cross to Python (an injected request, a CA held in memory) keeps the call in Node.js
    if (st.engine === 'node' || Object.keys(o || {}).some((k) => o[k] !== undefined && o[k] !== null && (typeof o[k] === 'object' || typeof o[k] === 'function'))) return node[op](cred, o);
    const r = await engine().call('discovery.' + op, { method: name, cred: plainCred(cred), opts: plainOpts(o) });
    if (r && r.error_class === 'missing_python') return Object.assign(await node[op](cred, o), { engine: 'node (python unavailable: ' + r.error + ')' });
    return Object.assign(r || { ok: false, error_class: 'protocol' }, { engine: 'python' });
  }
  return Object.assign({}, node, { collect: (cred, o = {}) => run('collect', cred, o), test: (cred, o = {}) => run('test', cred, o) });
}

/* SNMP (step 5c): collect(host, cred, o) - the per-device read - is answered by Python; probe() - the per-address liveness
   check of a sweep, thousands of them on one shared UDP socket - stays in Node.js */
function wrapSnmp(node) {
  async function collect(host, cred, o = {}) {
    if (st.engine === 'node' || Object.keys(o).some((k) => o[k] !== undefined && o[k] !== null && (typeof o[k] === 'object' || typeof o[k] === 'function'))) return node.collect(host, cred, o);
    const r = await engine().call('discovery.collect', { method: 'snmp', cred: plainCred(cred), opts: Object.assign(plainOpts(o), { host: String(host) }) });
    if (r && r.error_class === 'missing_python') return Object.assign(await node.collect(host, cred, o), { engine: 'node (python unavailable: ' + r.error + ')' });
    return Object.assign(r || { ok: false, error_class: 'protocol' }, { engine: 'python' });
  }
  return Object.assign({}, node, { collect });
}

module.exports = { configure, wrap, wrapSnmp, _state: st };
