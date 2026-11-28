// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Findings providers (engine/findings.js) over SYNTHETIC findings: a provider whose source cannot be read (returns null - e.g. the
// SIEM is down) or that throws leaves its open findings OPEN, in the hourly regenerate and in syncKinds; the failure is logged once;
// when the source answers again and the gap is gone, the finding is resolved as before.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createFindings } = require('../engine/findings');

function store() { const m = new Map(); return { collection: () => ({ all: (f) => [...m.values()].filter((x) => !f || f(x)), get: (id) => m.get(id), put: (o) => { m.set(o.id, o); return o; }, remove: (id) => m.delete(id) }) }; }

test('a provider that cannot know (SIEM down) or throws keeps its findings open; a real answer still resolves them', async () => {
  const warned = [], log = { every: (k, ms, lvl, msg) => warned.push(msg) };
  const F = createFindings({ store: store(), audit: () => {}, settings: { get: () => ({}) }, assets: { all: () => [] }, getLicences: () => [], python: false, log });
  const GAP = { key: 'log_coverage_gap:A1', kind: 'log_coverage_gap', severity: 'medium', asset_id: 'A1', title: 'No SIEM logs from server: SRV-SYN', detail: 'synthetic', evidence: {} };
  let mode = 'gap';
  F.addProvider(() => { if (mode === 'down') return null; if (mode === 'throw') throw new Error('siem unreachable (synthetic)'); return mode === 'gap' ? [GAP] : []; }, ['log_coverage_gap']);
  const gap = () => F.list((x) => x.key === GAP.key)[0];
  await F.regenerate(); assert.equal(gap().status, 'open');
  mode = 'down'; await F.regenerate(); assert.equal(gap().status, 'open', 'SIEM down: not resolved by the hourly regenerate');
  F.syncKinds(['log_coverage_gap'], { user: 'system' }); assert.equal(gap().status, 'open', 'SIEM down: not resolved by syncKinds');
  mode = 'throw'; await F.regenerate(); assert.equal(gap().status, 'open', 'a provider that throws: kept'); assert.equal(warned.length, 1, 'and logged');
  mode = 'fixed'; await F.regenerate(); assert.equal(gap().status, 'resolved', 'the SIEM answers and the server sends logs now: resolved');
});
