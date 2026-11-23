// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The ITAM -> SIEM link (engine/discovery/siem.js call): admin and analyst reach the SIEM as they are - analyst is the
// read-only role of the platform's own audit jobs (Baseline Hardening, AI auditors), which the SIEM's evidence routes need;
// before this every non-admin role was sent as viewer and those reads were refused (HTTP 403). Operator and anything else
// still go as viewer, so a write in the SIEM still needs an administrator. Synthetic data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSiem } = require('../engine/discovery/siem');

test('SIEM link: admin and analyst sent as they are; operator, viewer and unknown roles as viewer; never the body role', async () => {
  const sent = [];
  const S = createSiem({ config: { discovery: { siem: { secret_file: '/x', base_url: 'http://127.0.0.1:1' } } }, readFile: () => 'a-synthetic-proxy-secret-1234', store: { collection: () => ({}) },
    request: async (url, r) => { sent.push([url, r.headers['X-Auth-User'], r.headers['X-Auth-Role']]); return { status: 200, json: {} }; } });
  for (const role of ['admin', 'analyst', 'operator', 'viewer', 'superuser', undefined]) await S.call('GET', '/hardening/snapshots', { user: 'system:itam-hardening', role });
  assert.deepEqual(sent.map((x) => x[2]), ['admin', 'analyst', 'viewer', 'viewer', 'viewer', 'viewer']);
  assert.equal(sent[0][0], 'http://127.0.0.1:1/api/soc/hardening/snapshots'); assert.equal(sent[1][1], 'system:itam-hardening');
});
