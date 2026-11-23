// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/util/brand');
// POST /intel/check (Email / Phishing Analysis): which indicator lists hold the given values. Reference lists come back
// apart, a lookup is not counted as a hit, the audit records counts only, and the input is bounded.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), path = require('path');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createDetector } = require('../engine/detect/engine');
const { createIntel } = require('../engine/detect/intel');
const detectRoutes = require('../engine/detect/routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

test('intel/check: threat lists, reference lists apart, bounded, audited by count', async () => {
  const dir = tmpDir('sentra-intelchk-'), idir = path.join(dir, 'intel'); fs.mkdirSync(idir);
  fs.writeFileSync(path.join(idir, 'cert-sa.txt'), 'evil-login.example\n203.0.113.9\n');
  fs.writeFileSync(path.join(idir, 'internal-domains.txt'), (ZYB_ORG.domain + '\n'));
  const state = createState({ dir: path.join(dir, 'state'), log: quietLog });
  const alerts = createAlerts({ state, log: quietLog });
  const intel = createIntel({ dir: idir, log: quietLog, watch: false });
  const detector = createDetector({ rules: [], onAlert: (p) => alerts.raise(p), log: quietLog });
  const api = fakeApi();
  detectRoutes.register(api, { state, alerts, detector, intel, intelFeeds: { list: () => [], start() {} }, config: { data_dir: dir }, log: quietLog });
  try {
    const before = JSON.stringify(intel.stats().hits || {});
    let r = await api.call('POST', '/api/soc/intel/check', { role: 'viewer', body: { values: ['Evil-Login.example', '203.0.113.9', ZYB_ORG.domain, 'fine.example', ''] } });
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.results, { 'evil-login.example': ['cert-sa'], '203.0.113.9': ['cert-sa'] });
    assert.deepEqual(r.body.reference, { [ZYB_ORG.domain]: ['internal-domains'] });
    assert.equal(JSON.stringify(intel.stats().hits || {}), before, 'a lookup is not a hit');
    const a = api.audits.find((x) => x.action === 'intel.check');
    assert.deepEqual(a.detail, { values: 5, matches: 2 }, 'audit carries counts, not the indicators');
    r = await api.call('POST', '/api/soc/intel/check', { body: { values: new Array(201).fill('x.example') } }); assert.equal(r.status, 400);
    r = await api.call('POST', '/api/soc/intel/check', { body: {} }); assert.equal(r.status, 400);
  } finally { intel.stop && intel.stop(); alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
