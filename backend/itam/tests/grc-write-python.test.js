// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 9c (docs/PYTHON-MIGRATION.md): the GRC draft and DR-drill WRITES decided by pyengine/grc_write.py and
// committed by engine/grc.js must do exactly what the Node.js functions do, over HTTP, as the people the rules are about:
// four-eyes approval of drafts (whoever wrote or changed it cannot approve), independent drill sign-off (whoever ran it
// cannot sign it off), an approval / sign-off withdrawn by a later change, refused new records still using a number up,
// typed numbers ('', '30', -5, 'abc', 100), document / evidence kept inline or by reference. Same answers, same records,
// same counters - and Python decided every write.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z');

test('Python-decided GRC draft and drill writes do exactly what Node.js does', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const realNow = Date.now; Date.now = () => NOW;   // the "approval withdrawn" notes use Date.now()
  t.after(() => { Date.now = realNow; });
  const N = await startApp({ noAi: true, config: { grc: { engine: 'node' } } }), P = await startApp({ noAi: true, config: { discovery: { python_bin: PY } } });
  t.after(async () => { await N.close(); await P.close(); });
  for (const e of [N, P]) e.app.now = () => NOW;
  const as = { siva: { user: 'siva', role: 'operator' }, sivaAdm: { user: ' Siva ', role: 'admin' }, syed: { user: 'syed', role: 'admin' }, rasheed: { user: 'rasheed', role: 'admin' } };
  const big = 'A'.repeat(1300004);
  const steps = [
    ['siva', '/grc/drafts', { purpose: 'no title yet' }],
    ['siva', '/grc/drafts', { title: 'Cloud Security Policy', domain: 'Cyber', frameworks: 'SAMA, NCA', requirements: ' encrypt data \n\n  log access\n', owner: null }],
    ['siva', '/grc/drafts', { title: 'AI Use Policy', requirements: ['a', ' b ', '', null, 7] }],
    ['siva', '/grc/drafts/DRAFT-0002', { body: 'v2 text', title: 'Cloud Security Policy v2' }],
    ['siva', '/grc/drafts/DRAFT-0002/upload', { filename: 'cloud.docx', content_b64: 'UEsDBBQ=', sha256: 'ABCDEF0123456789' }],
    ['siva', '/grc/drafts/DRAFT-0003/upload', { filename: 'big.pdf', content_b64: big, size: '2000000' }],
    ['siva', '/grc/drafts/DRAFT-0003/upload', { content_b64: 'x' }],
    ['sivaAdm', '/grc/drafts/DRAFT-0002/status', { status: 'approved' }],
    ['syed', '/grc/drafts/DRAFT-0002/status', { status: 'approved' }],
    ['syed', '/grc/drafts/DRAFT-0002/status', { status: 'published' }],
    ['siva', '/grc/drafts/DRAFT-0002', { purpose: 'changed after approval' }],
    ['syed', '/grc/drafts/DRAFT-0003/status', { status: 'in-review' }],
    ['siva', '/grc/drafts/DRAFT-0003/upload', { filename: 'again.pdf', content_b64: 'JVBERi0=' }],
    ['siva', '/grc/drafts/nope', { title: 'x' }],
    ['syed', '/grc/drafts/DRAFT-0003/delete', {}],
    ['syed', '/grc/drafts/DRAFT-0003/delete', {}],
    ['siva', '/grc/drills', { system: 'Core Banking' }],
    ['siva', '/grc/drills', { title: 'Failover test' }],
    ['siva', '/grc/drills', { title: 'Failover test', system: 'Core Banking', type: 'chaos' }],
    ['siva', '/grc/drills', { title: 'Failover test', system: 'Core Banking', type: 'failover', rto_target_min: '30', rpo_target_min: '', frequency_months: 100, scheduled: '2026-11-01', objective: { x: 1 } }],
    ['siva', '/grc/drills', { title: 'Restore', system: 'Exchange', rto_target_min: -5, rpo_target_min: 'abc', frequency_months: '6' }],
    ['siva', '/grc/drills/DR-0004/result', { result: 'maybe' }],
    ['siva', '/grc/drills/DR-0004/result', { result: 'pass', rto_actual_min: '25', rpo_actual_min: null, findings: ' DNS slow \n\n failback manual ', actions: ['update runbook', ''], summary: 'ok' }],
    ['sivaAdm', '/grc/drills/DR-0004/signoff', { note: 'mine' }],
    ['syed', '/grc/drills/DR-0005/signoff', {}],
    ['rasheed', '/grc/drills/DR-0004/signoff', { note: 'reviewed the evidence' }],
    ['siva', '/grc/drills/DR-0004', { owner: 'Ops' }],
    ['rasheed', '/grc/drills/DR-0004/signoff', {}],
    ['siva', '/grc/drills/DR-0004/upload', { filename: 'evidence.pdf', content_b64: 'JVBERi0=', sha256: 'aa' }],
    ['siva', '/grc/drills/DR-0005/result', { result: 'fail', executed: '' }],
    ['siva', '/grc/drills/DR-0005/cancel', { note: 'replaced by the Q1 test' }],
    ['siva', '/grc/drills/nope/cancel', {}],
    ['syed', '/grc/drills/DR-0005/delete', {}],
  ];
  const strip = (j) => JSON.parse(JSON.stringify(j));
  let beforeHandler = 0;   // refused by the HTTP layer itself (body over the 1 MB limit: 413) - no write function runs
  for (const [who, path, body] of steps) {
    const opt = { body, user: as[who].user, role: as[who].role };
    const a = await N.req('POST', path, opt), b = await P.req('POST', path, opt);
    assert.equal(b.status, a.status, who + ' ' + path + ' status');
    assert.deepEqual(strip(b.json), strip(a.json), who + ' ' + path);
    if (a.status === 413) beforeHandler++;
  }
  assert.equal(beforeHandler, 1, 'the oversized upload is refused before any GRC code runs, in both');
  for (const c of ['grc_drafts', 'grc_drills', 'counters']) assert.deepEqual(P.app.store.collection(c).all(), N.app.store.collection(c).all(), c + ': the same records');
  const st = P.app.grcWriteStats();
  assert.equal(st.node, 0, 'no write redone in Node.js: ' + JSON.stringify(st)); assert.equal(st.python, steps.length - beforeHandler, 'Python decided every write that reached a handler');
  const d2 = P.app.store.collection('grc_drafts').get('DRAFT-0002');
  assert.equal(d2.status, 'draft', 'changed after approval: back to draft'); assert.equal(d2.approved_by, null);
  const dr = P.app.store.collection('grc_drills').get('DR-0004');
  assert.equal(dr.signoff, null, 'evidence replaced after sign-off: the sign-off is withdrawn');
});
