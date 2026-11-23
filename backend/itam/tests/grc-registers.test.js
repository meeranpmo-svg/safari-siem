// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// GRC registers (engine/grc-registers.js) over HTTP, as the people the rules are about: remediation actions with
// four-eyes closure (whoever marked it done cannot verify it), one open action per source gap, overdue computed from the
// date; risks scored 1-5 with acceptance only by an administrator who is not the owner, withdrawn when the rating
// changes; policy exceptions against a real policy, max 12 months, approved by someone other than the requester and
// "expired" by date; evidence files hashed on arrival (a damaged upload refused), SAMA coverage counting only current
// evidence; viewers read, operators write, administrators approve, service identities never; every change audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { startApp } = require('./helpers');

const NOW = Date.parse('2026-10-20T08:00:00Z');

test('GRC registers: actions, risks, exceptions, evidence - four eyes, dates, files, roles, audit', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.now = () => NOW;
  const as = (user, role) => (m, p, body) => e.req(m, p, { body, user, role });
  const siva = as('siva', 'operator'), rasheed = as('rasheed', 'operator'), syed = as('syed', 'admin'), viewer = as('guest', 'viewer'), bot = as('duty:grc', 'admin');
  const ok = (r, what) => { assert.ok(r.status >= 200 && r.status < 300, (what || '') + ' ' + r.status + ' ' + r.text); return r.json; };

  // ---- remediation actions
  const a1 = ok(await siva('POST', '/grc/actions', { title: 'Enable MFA for VPN', source: 'sama', ref: '3.3.5', owner: 'siva', due: '2026-10-01', priority: 'high' }));
  assert.equal(a1.id, 'ACT-0001'); assert.equal(a1.overdue, true, 'due before today and still open');
  assert.equal((await rasheed('POST', '/grc/actions', { title: 'Same gap again', source: 'sama', ref: '3.3.5' })).status, 409, 'one open action per gap');
  assert.equal((await siva('POST', '/grc/actions', { title: 'From a drill', source: 'drill' })).status, 400, 'a sourced action names its source');
  assert.equal((await siva('POST', '/grc/actions', { title: 'x', due: '2026-02-30' })).status, 400, 'a real date');
  assert.equal((await viewer('POST', '/grc/actions', { title: 'Viewer cannot' })).status, 403);
  assert.equal((await siva('POST', '/grc/actions/ACT-0001/status', { status: 'done' })).status, 400, 'done needs a note or evidence');
  const pdf = Buffer.from('%PDF-1.4 MFA enforced report');
  assert.equal((await siva('POST', '/grc/actions/ACT-0001/evidence', { filename: 'mfa.pdf', content_b64: pdf.toString('base64'), sha256: 'ab'.repeat(32) })).status, 400, 'damaged upload refused');
  const withEv = ok(await siva('POST', '/grc/actions/ACT-0001/evidence', { filename: 'mfa.pdf', content_b64: pdf.toString('base64'), sha256: crypto.createHash('sha256').update(pdf).digest('hex'), note: 'FortiGate config export' }));
  assert.equal(withEv.evidence[0].sha256, crypto.createHash('sha256').update(pdf).digest('hex'));
  ok(await siva('POST', '/grc/actions/ACT-0001/status', { status: 'done', note: 'MFA enforced on the VPN portal' }));
  assert.equal((await siva('POST', '/grc/actions/ACT-0001/status', { status: 'closed' })).status, 403, 'four eyes: the one who did it does not verify it');
  assert.equal((await bot('POST', '/grc/actions/ACT-0001/status', { status: 'closed' })).status, 403, 'a service identity never verifies');
  const closed = ok(await rasheed('POST', '/grc/actions/ACT-0001/status', { status: 'closed', note: 'checked the policy and a test login' }));
  assert.equal(closed.status, 'closed'); assert.equal(closed.closed_by, 'rasheed'); assert.equal(closed.overdue, false);
  const f = ok(await siva('GET', '/grc/files/' + encodeURIComponent(withEv.evidence[0].file_id)));
  assert.equal(Buffer.from(f.content_b64, 'base64').toString(), pdf.toString(), 'the stored bytes come back');
  assert.equal((await viewer('GET', '/grc/files/' + encodeURIComponent(withEv.evidence[0].file_id))).status, 403);
  ok(await siva('POST', '/grc/actions', { title: 'Enable MFA for VPN (again)', source: 'sama', ref: '3.3.5' }), 'the gap can be tracked again once closed');

  // ---- risks
  const r1 = ok(await siva('POST', '/grc/risks', { title: 'Ransomware on file servers', owner: 'siva', likelihood: 4, impact: 5, residual_likelihood: 2, residual_impact: 5, treatment: 'mitigate', controls: '3.3.5, 3.3.10', review_due: '2026-09-30' }));
  assert.equal(r1.inherent, 20); assert.equal(r1.inherent_band, 'high'); assert.equal(r1.residual, 10); assert.equal(r1.residual_band, 'medium'); assert.equal(r1.review_overdue, true);
  assert.deepEqual(r1.controls, ['3.3.5', '3.3.10']);
  assert.equal((await siva('POST', '/grc/risks', { title: 'Bad score', likelihood: 6, impact: 1 })).status, 400);
  assert.equal((await siva('POST', '/grc/risks', { title: 'Unknown asset', likelihood: 1, impact: 1, assets: ['as_nope'] })).status, 400);
  ok(await siva('POST', '/grc/actions', { title: 'Immutable backups', source: 'risk', ref: r1.id, owner: 'rasheed', due: '2026-12-31' }));
  const r2 = ok(await siva('POST', '/grc/risks', { title: 'Legacy app on Windows 2012', owner: 'syed', likelihood: 3, impact: 3, treatment: 'accept' }));
  assert.equal((await syed('POST', '/grc/risks/' + r2.id + '/accept', { note: 'replaced in Q1' })).status, 403, 'the owner does not accept his own risk');
  assert.equal((await rasheed('POST', '/grc/risks/' + r2.id + '/accept', { note: 'x' })).status, 403, 'an operator does not accept a risk');
  const r3 = ok(await siva('POST', '/grc/risks', { title: 'Vendor support ended', owner: 'siva', likelihood: 2, impact: 4, treatment: 'accept' }));
  assert.equal((await syed('POST', '/grc/risks/' + r3.id + '/accept', {})).status, 400, 'acceptance is reasoned');
  const acc = ok(await syed('POST', '/grc/risks/' + r3.id + '/accept', { note: 'replacement budgeted for 2027', until: '2027-03-31' }));
  assert.equal(acc.acceptance.by, 'syed');
  const bumped = ok(await siva('POST', '/grc/risks/' + r3.id, { impact: 5 }));
  assert.equal(bumped.acceptance, null, 'a re-rated risk is no longer the risk that was accepted');
  const rl = ok(await viewer('GET', '/grc/risks'));
  assert.equal(rl.items.find((x) => x.id === r1.id).open_actions, 1, 'the risk shows its actions');
  assert.equal(rl.heat.inherent['4x5'], 1);

  // ---- policy exceptions
  assert.equal((await siva('POST', '/grc/exceptions', { policy_id: 'NOPE-1', title: 'x', reason: 'y', expires: '2026-12-01' })).status, 400, 'only against an approved policy');
  const pol = ok(await viewer('GET', '/grc/exceptions')).policies[0].doc_id;
  assert.equal((await siva('POST', '/grc/exceptions', { policy_id: pol, title: 'Too long', reason: 'y', starts: '2026-10-20', expires: '2028-01-01' })).status, 400, 'max 12 months');
  const x1 = ok(await siva('POST', '/grc/exceptions', { policy_id: pol, title: 'Shared admin account on SCADA HMI', reason: 'vendor-locked HMI', compensating: 'jump host + session recording', starts: '2026-10-20', expires: '2026-11-10', scope: 'HMI-01' }));
  assert.equal(x1.state, 'requested'); assert.ok(x1.policy_title);
  assert.equal((await siva('POST', '/grc/exceptions/' + x1.id + '/decide', { decision: 'approve' })).status, 403, 'operators do not approve');
  const sx = ok(await syed('POST', '/grc/exceptions', { policy_id: pol, title: 'Admin asks for himself', reason: 'r', expires: '2026-12-01' }));
  assert.equal((await syed('POST', '/grc/exceptions/' + sx.id + '/decide', { decision: 'approve', note: 'ok' })).status, 403, 'never your own request');
  assert.equal((await syed('POST', '/grc/exceptions/' + x1.id + '/decide', { decision: 'reject' })).status, 400, 'a rejection is reasoned');
  const ap = ok(await syed('POST', '/grc/exceptions/' + x1.id + '/decide', { decision: 'approve' }));
  assert.equal(ap.state, 'approved'); assert.equal(ap.expiring_soon, true);
  e.app.now = () => Date.parse('2026-11-11T08:00:00Z');
  assert.equal(ok(await viewer('GET', '/grc/exceptions')).items.find((x) => x.id === x1.id).state, 'expired', 'expired by date, nobody has to set it');
  e.app.now = () => NOW;

  // ---- evidence
  assert.equal((await siva('POST', '/grc/evidence', { framework: 'SAMA ITGF', control: '9.9.9', title: 'x', url: 'https://x' })).status, 400, 'a real SAMA control');
  assert.equal((await siva('POST', '/grc/evidence', { framework: 'SAMA ITGF', control: '3.1.3', title: 'CMDB export', url: 'ftp://x' })).status, 400, 'http(s) references only');
  const ev = ok(await siva('POST', '/grc/evidence', { framework: 'SAMA ITGF', control: '3.1.3', title: 'CMDB reconciliation report Q3', kind: 'export', filename: 'cmdb.csv', content_b64: Buffer.from('id,name\n1,srv').toString('base64'), collected: '2026-07-01', valid_days: 90 }));
  assert.equal(ev.next_due, '2026-09-29'); assert.equal(ev.state, 'stale');
  ok(await siva('POST', '/grc/evidence', { framework: 'ISO 27001', control: 'A.5.9', title: 'Asset inventory policy', url: 'https://sharepoint.example/asset-policy' }));
  let el = ok(await viewer('GET', '/grc/evidence'));
  const c313 = el.coverage.find((c) => c.control === '3.1.3');
  assert.equal(c313.state, 'stale', 'only stale evidence: not counted as covered');
  assert.equal(el.coverage.filter((c) => c.state === 'missing').length, el.coverage.length - 1);
  ok(await siva('POST', '/grc/evidence', { framework: 'SAMA ITGF', control: '3.1.3', title: 'CMDB reconciliation report Q4', url: 'https://sharepoint.example/cmdb-q4', collected: '2026-10-15' }));
  el = ok(await viewer('GET', '/grc/evidence'));
  assert.equal(el.coverage.find((c) => c.control === '3.1.3').state, 'current');
  assert.equal((await siva('POST', '/grc/evidence/' + ev.id + '/retire', {})).status, 400, 'retiring is reasoned');
  ok(await siva('POST', '/grc/evidence/' + ev.id + '/retire', { note: 'superseded by the Q4 report' }));

  // ---- workspace: the numbers and what is waiting for whom
  const ws = ok(await rasheed('GET', '/grc/workspace'));
  assert.equal(ws.actions.open, 2); assert.equal(ws.risks.open, 3); assert.equal(ws.risks.review_overdue, 1); assert.equal(ws.risks.awaiting_acceptance, 2);
  assert.equal(ws.exceptions.requested, 1); assert.equal(ws.exceptions.active, 1); assert.equal(ws.evidence.sama_current, 1);
  assert.deepEqual(ws.mine.actions.map((x) => x.id), ['ACT-0003'], 'rasheed owns the backup action');
  // audit trail
  const acts = e.app.store.auditTail(500, (x) => /^grc\.(action|risk|exception|evidence)\./.test(x.action)).map((x) => x.action);
  for (const a of ['grc.action.create', 'grc.action.done', 'grc.action.closed', 'grc.action.evidence', 'grc.risk.accept', 'grc.exception.approved', 'grc.evidence.add', 'grc.evidence.retire']) assert.ok(acts.includes(a), a + ' audited');
});
