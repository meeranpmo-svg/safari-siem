// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Service Agreement (engine/service-agreement.js): cover-hours maths (Riyadh, Sun-Thu), terms admin-only and validated (signatory
// must be a member, nobody on both sides, version race), support cases by party (the Customer opens / closes, the Provider responds /
// resolves, exclusions decided by the other party), the monthly statement (response / resolution / audit-fix / availability / report
// targets, deductions, cap, amount only with a fee), issued by the Provider after the month and accepted or disputed by the Customer,
// SLA / NDA generated from the terms, approved by both signatories (two people) and published; audit records. SYNTHETIC parties.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { coverMinutes, coverDeadline, DEFAULTS } = require('../engine/service-agreement');

const ADM = { user: 'syed', role: 'admin' }, CUS = { user: 'cust.syn', role: 'operator' }, CSIG = { user: 'cust.sign', role: 'viewer' }, PRO = { user: 'prov.syn', role: 'viewer' }, PSIG = { user: 'prov.sign', role: 'viewer' }, OUT = { user: 'outsider', role: 'operator' };
const H = DEFAULTS.hours;
const R = (s) => Date.parse(s + '+03:00');   // Riyadh local time

test('cover hours: business hours Sun-Thu 08-17 Riyadh, 24x7 straight through', () => {
  assert.equal(coverMinutes(R('2026-10-29T16:00:00'), R('2026-11-01T09:00:00'), 'business', H), 120, 'Thursday 16:00 -> Sunday 09:00 = 1 h + 1 h');
  assert.equal(coverMinutes(R('2026-10-29T16:00:00'), R('2026-11-01T09:00:00'), '24x7', H), 65 * 60);
  assert.equal(new Date(coverDeadline(R('2026-10-29T16:00:00'), 240, 'business', H)).toISOString(), new Date(R('2026-11-01T11:00:00')).toISOString(), '4 business hours from Thursday 16:00 = Sunday 11:00');
  assert.equal(coverMinutes(R('2026-10-30T10:00:00'), R('2026-10-31T12:00:00'), 'business', H), 0, 'Friday and Saturday are not business days');
});

async function setup(t, clock) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t });
  return e;
}
const post = (e, p, body, who = ADM) => e.req('POST', p, Object.assign({ body }, who));
const TERMS = { members: { customer: ['cust.syn', 'cust.sign'], provider: ['prov.syn', 'prov.sign'] },
  parties: { customer: { cr: '1010000001', signatory: { name: 'Customer Signatory (synthetic)', title: 'CEO', user: 'cust.sign' } }, provider: { cr: '1010000002', signatory: { name: 'Provider Signatory (synthetic)', title: 'GM', user: 'prov.sign' } } },
  commercial: { monthly_fee_sar: 100000, cap_pct: 10, start: '2026-10-01' } };

test('terms: admin only, validated and named, signatory must be a member, nobody on both sides, version race refused, audited', async (t) => {
  const clock = { t: R('2026-10-05T10:00:00') }; const e = await setup(t, clock);
  assert.equal((await post(e, '/sla/terms', { terms: TERMS }, CUS)).status, 403);
  let r = await post(e, '/sla/terms', { terms: { priorities: { P1: { response_min: 600, resolve_h: 4 } } } }); assert.equal(r.status, 400); assert.match(r.json.error, /priorities\.P1: resolution must not be shorter/);
  r = await post(e, '/sla/terms', { terms: { priorities: { P2: { response_min: 1 } } } }); assert.equal(r.status, 400); assert.match(r.json.error, /^priorities\.P2\.response_min must be at least 5/, 'a nested field is named in full');
  r = await post(e, '/sla/terms', { terms: { members: { customer: ['a.syn'], provider: ['A.SYN'] } } }); assert.equal(r.status, 400); assert.match(r.json.error, /both sides/);
  r = await post(e, '/sla/terms', { terms: { parties: { customer: { signatory: { user: 'ghost' } } } } }); assert.equal(r.status, 400); assert.match(r.json.error, /signatory\.user must be one of the customer members/);
  r = await post(e, '/sla/terms', { terms: { audit: { days: { high: 90, medium: 60, low: 30 } } } }); assert.equal(r.status, 400); assert.match(r.json.error, /high finding must be due no later/);
  r = await post(e, '/sla/terms', { terms: { hours: { start: '17:00', end: '08:00' } } }); assert.equal(r.status, 400); assert.match(r.json.error, /hours\.end must be after/);
  r = await post(e, '/sla/terms', { terms: TERMS, baseVersion: 0 }); assert.equal(r.status, 200, r.text); assert.equal(r.json.version, 1);
  assert.equal((await post(e, '/sla/terms', { terms: { commercial: { cap_pct: 5 } }, baseVersion: 0 })).status, 409, 'saved from an old version');
  const v = (await e.req('GET', '/sla', OUT)).json; assert.equal(typeof v.terms.members.customer, 'number', 'member names hidden from non-members');
  assert.equal((await e.req('GET', '/sla', CUS)).json.party, 'customer');
  assert.ok(e.app.store.auditTail(20).some((a) => a.action === 'sla.terms.save' && a.detail.fee_set === true));
});

test('cases and statement: the parties act on their own steps, exclusions four-eyes, deductions capped, issued after the month and decided by the Customer', async (t) => {
  const clock = { t: R('2026-10-05T10:00:00') }; const e = await setup(t, clock);
  await post(e, '/sla/terms', { terms: TERMS });
  assert.equal((await post(e, '/sla/cases', { title: 'x', description: 'y', priority: 'P1' }, PRO)).status, 403, 'the Provider does not open Customer cases');
  assert.equal((await post(e, '/sla/cases', { title: 'x', description: 'y', priority: 'P1' }, OUT)).status, 403, 'a non-member cannot');
  let r = await post(e, '/sla/cases', { title: 'SIEM down (synthetic)', description: 'no alerts', priority: 'P9' }, CUS); assert.equal(r.status, 400); assert.match(r.json.error, /priority/);
  const c1 = (await post(e, '/sla/cases', { title: 'SIEM down (synthetic)', description: 'no alerts arriving', priority: 'P1' }, CUS)).json;
  assert.equal(c1.response_due, new Date(R('2026-10-05T10:30:00')).toISOString());
  assert.equal((await post(e, '/sla/cases/' + c1.id + '/respond', {}, CUS)).status, 403, 'the Customer does not respond to its own case');
  clock.t = R('2026-10-05T11:15:00'); await post(e, '/sla/cases/' + c1.id + '/respond', { note: 'looking' }, PRO);   // 75 min: response missed
  clock.t = R('2026-10-05T13:00:00'); r = await post(e, '/sla/cases/' + c1.id + '/resolve', {}, PRO); assert.equal(r.status, 400); assert.match(r.json.error, /say what was done/);
  r = await post(e, '/sla/cases/' + c1.id + '/resolve', { note: 'collector restarted' }, PRO); assert.equal(r.json.resolve_met, true); assert.equal(r.json.response_met, false);
  assert.equal((await post(e, '/sla/cases/' + c1.id + '/close', {}, PRO)).status, 403); assert.equal((await post(e, '/sla/cases/' + c1.id + '/close', {}, CUS)).json.status, 'closed');
  // a second case the Provider asks to exclude; it cannot decide its own request
  const c2 = (await post(e, '/sla/cases', { title: 'Report late (synthetic)', description: 'customer firewall change blocked the feed', priority: 'P2' }, CUS)).json;
  assert.equal((await post(e, '/sla/cases/' + c2.id + '/exclude', { reason: 'customer-caused', note: 'firewall change CHG-1 (synthetic)' }, PRO)).status, 200);
  assert.equal((await post(e, '/sla/cases/' + c2.id + '/decide-exclusion', { decision: 'accepted' }, PSIG)).status, 403, 'four eyes: the other party decides');
  assert.equal((await post(e, '/sla/cases/' + c2.id + '/decide-exclusion', { decision: 'accepted', note: 'agreed' }, CUS)).json.excluded, true);
  // an IT Audit finding issued 40 days before its 30-day target fell in October and still open
  e.app.store.collection('ia_findings').put({ id: 'IAF-SYN-1', title: 'Admin accounts not reviewed (synthetic)', rating: 'high', state: 'responded', issued_at: new Date(R('2026-09-01T09:00:00')).toISOString(), engagement: 'E1' });
  e.app.store.collection('csa_findings').put({ id: 'CSA-SYN-1', title: 'Logging gap (synthetic)', rating: 'low', state: 'implemented', issued_at: new Date(R('2026-07-20T09:00:00')).toISOString(), implemented_at: new Date(R('2026-10-01T09:00:00')).toISOString(), engagement: 'E2' });
  await post(e, '/sla/measures/2026-10', { availability_pct: 99.1 }, PRO);
  assert.equal((await post(e, '/sla/measures/2026-10', { confirm: true }, PSIG)).status, 403, 'the same party does not confirm its own figure');
  await post(e, '/sla/measures/2026-10', { confirm: true }, CUS);
  let s = (await e.req('GET', '/sla/statements/2026-10', CUS)).json;
  const kinds = (k) => s.lines.filter((l) => l.kind === k);
  assert.equal(kinds('response').find((l) => l.ref === c1.id).met, false); assert.equal(kinds('resolution').find((l) => l.ref === c1.id).met, true);
  assert.ok(s.lines.some((l) => l.ref === c2.id && /excluded: customer-caused/.test(l.why)), 'the excluded case carries no credit');
  assert.equal(kinds('audit').find((l) => l.ref === 'IAF-SYN-1').met, false); assert.equal(kinds('audit').find((l) => l.ref === 'CSA-SYN-1').met, true, 'implemented within 90 days');
  assert.equal(kinds('availability')[0].met, false);
  // P1 response 2% + audit high 1% + availability 5% = 8% (report not yet due in October) -> SAR 8 000
  assert.equal(s.summary.deduction_pct, 8); assert.equal(s.summary.deduction_sar, 8000); assert.equal(s.state, 'draft');
  assert.equal((await post(e, '/sla/statements/2026-10/issue', {}, PRO)).status, 409, 'not before the month ends');
  clock.t = R('2026-11-08T10:00:00');
  s = (await e.req('GET', '/sla/statements/2026-10', CUS)).json; assert.equal(s.summary.deduction_pct, 8.5, 'the report was due on the 5th and not recorded: +0.5%');
  assert.equal((await post(e, '/sla/statements/2026-10/issue', {}, CUS)).status, 403, 'the Provider issues it');
  assert.equal((await post(e, '/sla/statements/2026-10/issue', {}, PRO)).json.state, 'issued');
  assert.equal((await post(e, '/sla/statements/2026-10/decide', { decision: 'disputed' }, CUS)).status, 400, 'a dispute needs a reason');
  assert.equal((await post(e, '/sla/statements/2026-10/decide', { decision: 'accepted' }, PRO)).status, 403, 'the Customer decides');
  assert.equal((await post(e, '/sla/statements/2026-10/decide', { decision: 'accepted' }, CUS)).json.state, 'accepted');
  // cap: many misses never exceed the cap
  await post(e, '/sla/terms', { terms: { commercial: { cap_pct: 3 } } });
  assert.equal((await e.req('GET', '/sla/statements/2026-10', CUS)).json.summary.deduction_pct, 8.5, 'an issued statement is frozen');
  const acts = e.app.store.auditTail(100).map((a) => a.action);
  for (const a of ['sla.case.open', 'sla.case.respond', 'sla.case.resolve', 'sla.case.close', 'sla.case.exclude', 'sla.case.decide-exclusion', 'sla.measure.confirm', 'sla.statement.issue', 'sla.statement.accepted']) assert.ok(acts.includes(a), a);
});

test('documents: SLA and NDA from the terms, edited by an admin, approved by BOTH signatories, then published to everyone', async (t) => {
  const clock = { t: R('2026-10-05T10:00:00') }; const e = await setup(t, clock);
  assert.equal((await post(e, '/sla/documents', { kind: 'sla' }, CUS)).status, 403);
  let d = (await post(e, '/sla/documents', { kind: 'sla' })).json;
  const text = JSON.stringify(d.sections);
  assert.match(text, new RegExp(ZYB_ORG.name)); assert.match(text, /Citynet Work/); assert.match(text, /Zyberon Information Technology, Saudi Arabia/);
  assert.match(text, /P1 Critical[^\n]*response 30 minutes, resolution 4 hours/); assert.match(text, /capped at 10%/); assert.ok(d.placeholders > 0, 'missing party details stay visible placeholders');
  assert.equal((await post(e, '/sla/documents', { kind: 'sla' })).status, 409, 'one open draft per kind');
  assert.equal((await post(e, '/sla/documents/' + d.id + '/submit', {})).status, 424, 'signatories must be named first');
  await post(e, '/sla/terms', { terms: TERMS });
  let r = await post(e, '/sla/documents/' + d.id + '/edit', { sections: [{ h: '1. Parties', t: 'Edited parties (synthetic)' }, { h: 'X', t: '' }] }); assert.equal(r.status, 400); assert.match(r.json.error, /t is required/);
  r = await post(e, '/sla/documents/' + d.id + '/edit', { sections: d.sections.concat([{ h: '16. Special terms', t: 'On-site visit once a month (synthetic).' }]) }); assert.equal(r.status, 200);
  assert.equal((await post(e, '/sla/documents/' + d.id + '/submit', {})).json.state, 'review');
  assert.equal((await post(e, '/sla/documents/' + d.id + '/approve', {}, PRO)).status, 403, 'only the named signatory approves');
  assert.equal((await post(e, '/sla/documents/' + d.id + '/approve', {}, CSIG)).json.state, 'review');
  assert.equal((await post(e, '/sla/documents/' + d.id + '/approve', {}, CSIG)).status, 409, 'the same party approves once');
  d = (await post(e, '/sla/documents/' + d.id + '/approve', {}, PSIG)).json; assert.equal(d.state, 'published'); assert.deepEqual(d.approvals.map((a) => a.party), ['customer', 'provider']);
  const pub = (await e.req('GET', '/sla/documents', OUT)).json; assert.equal(pub.published[0].kind, 'sla'); assert.deepEqual(pub.versions, [], 'drafts are for the parties and admins');
  assert.match(JSON.stringify(pub.published[0].sections), /On-site visit once a month/);
  const nda = (await post(e, '/sla/documents', { kind: 'nda' })).json; assert.match(JSON.stringify(nda.sections), /within 24 hours of awareness/); assert.match(JSON.stringify(nda.sections), /property of Citynet Work and Zyberon/);
  assert.equal((await post(e, '/sla/documents/' + d.id + '/edit', { sections: d.sections })).status, 409, 'a published version is never edited');
  assert.ok(e.app.store.auditTail(50).some((a) => a.action === 'sla.document.approve' && a.detail.state === 'published'));
});
