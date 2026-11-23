// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Storage arrays read by the Python module (pyengine/storage_sources.py) - migration step 1 (docs/PYTHON-MIGRATION.md).
const { createPySources } = require('./py-sources');
// kinds the Python module does not read yet are read in Node.js (collect and test)
const NODE_ONLY = ['synology'];
function createStorageSourcesPy(o = {}) {
  const N = require('./storage-sources'), P = createPySources({ module: 'storage', kinds: ['ontap', 'msa'], node: N, python: o.python, py: o.py });
  for (const k of NODE_ONLY) P[k] = async (cred, opts) => Object.assign(await N[k](cred, opts), { engine: 'node' });
  const pyTest = P.test; P.test = (kind, cred, opts) => (NODE_ONLY.includes(kind) ? N.test(kind, cred, opts) : pyTest(kind, cred, opts));
  return P;
}
module.exports = { createStorageSourcesPy };
