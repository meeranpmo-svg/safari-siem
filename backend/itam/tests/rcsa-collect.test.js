// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// RCSA risk-owner links (engine/rcsa-collect.js) with SYNTHETIC data: Risk opens a campaign; owners come from the GRC register; an
// owner link is a signed token under the agent gateway (no login); the public page shows only that owner's own risks; a public submit
// stores PENDING proposals (never touching the register); a tampered / expired / revoked token is refused; rate limiting; a Risk
// officer accepts a proposal (applying the new rating to the register) or rejects it with a reason; roles and four-eyes; audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'ro.syn', role: 'operator' }, RISK = { user: 'risk.syn', role: 'admin' }, BOT = { user: 'ai:risk', role: 'admin' };

test('RCSA links: campaign, scoped token, public proposal, review/accept, security', async (t) => {
  let T = Date.parse('2026-11-22T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || RISK));
  // two register risks owned by two people
  const GR = e.app.addons.grcRegisters;
  const r1 = GR.riskCreate({ title: 'Single-source procurement', description: 'Single-source procurement (synthetic)', category: 'operational', owner: 'proc.head', likelihood: 3, impact: 4, treatment: 'reduce' }, RISK);
  const r2 = GR.riskCreate({ title: 'Key-person dependency', description: 'Key-person dependency (synthetic)', category: 'strategic', owner: 'hr.head', likelihood: 2, impact: 3, treatment: 'reduce' }, RISK);
  // open a campaign
  assert.equal((await call('POST', '/rcsa', { title: 'RCSA Q4', period: '2026-Q4', due: '2026-12-15' }, OP)).status, 403, 'opening needs the Risk approval scope / admin');
  assert.equal((await call('POST', '/rcsa', { title: 'RCSA Q4', period: '2026-Q4', due: '2026-12-15' }, BOT)).status, 403, 'a service identity never opens');
  assert.equal((await call('POST', '/rcsa', { title: 'RCSA Q4', period: '2026-Q4', due: '2020-01-01' }, RISK)).status, 400, 'due date in the past');
  let r = await call('POST', '/rcsa', { title: 'RCSA Q4 2026', period: '2026-Q4', due: '2026-12-15' }, RISK); assert.equal(r.status, 200, r.text);
  const id = r.json.id; assert.equal(r.json.owners.length, 2, 'owners taken from the register'); assert.equal(r.json.status, 'open');
  assert.equal((await call('GET', '/rcsa', undefined, VIEW)).status, 403, 'internal');
  // issue an owner link
  r = await call('POST', '/rcsa/' + id + '/link', { owner: 'proc.head' }, RISK); assert.equal(r.status, 200, r.text);
  const tok = r.json.token; assert.ok(tok && tok.indexOf('.') > 0); assert.match(r.json.path, /^\/agent\/rcsa\/form#t=/, 'the token rides in the URL fragment');
  // public view (no login, agent gateway): only this owner's risk
  r = await e.req('GET', '/agent/rcsa/view', { headers: { 'x-rcsa-token': tok } }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.owner, 'proc.head'); assert.equal(r.json.risks.length, 1); assert.equal(r.json.risks[0].id, r1.id);
  assert.ok(r.json.brand && r.json.brand.name, 'the company brand is on the page');
  // a tampered token is refused
  assert.equal((await e.req('GET', '/agent/rcsa/view', { headers: { 'x-rcsa-token': tok.slice(0, -2) + 'xx' } })).status, 403, 'bad signature');
  // public submit: a proposal, not applied; cannot submit a risk you do not own
  assert.equal((await e.req('POST', '/agent/rcsa/submit', { headers: { 'x-rcsa-token': tok }, body: { responses: [{ risk: r2.id, likelihood: 5, impact: 5 }] } })).status, 403, 'not your risk');
  r = await e.req('POST', '/agent/rcsa/submit', { headers: { 'x-rcsa-token': tok }, body: { responses: [{ risk: r1.id, likelihood: 5, impact: 5, residual_likelihood: 4, residual_impact: 4, controls: ['Committee approval'], comment: 'worsened (synthetic)' }], note: 'done' } });
  assert.equal(r.status, 200, r.text); assert.equal(r.json.received, 1);
  assert.equal(GR.riskList().items.find((x) => x.id === r1.id).likelihood, 3, 'the register is NOT changed by a public submit');
  // Risk reviews the pending proposal beside the current rating
  r = await call('GET', '/rcsa/' + id + '/responses', undefined, OP); assert.equal(r.status, 200);
  assert.equal(r.json.items.length, 1); const resp = r.json.items[0]; assert.equal(resp.status, 'pending'); assert.equal(resp.current.likelihood, 3); assert.equal(resp.proposed.likelihood, 5);
  // a re-submit replaces the pending one
  await e.req('POST', '/agent/rcsa/submit', { headers: { 'x-rcsa-token': tok }, body: { responses: [{ risk: r1.id, likelihood: 4, impact: 4 }] } });
  r = await call('GET', '/rcsa/' + id + '/responses', undefined, OP); assert.equal(r.json.items.length, 1, 're-submit replaced the pending response'); assert.equal(r.json.items[0].proposed.likelihood, 4);
  // accept applies to the register (four-eyes: Risk, not a service identity)
  const rid = r.json.items[0].id;
  assert.equal((await call('POST', '/rcsa/responses/' + rid + '/accept', {}, OP)).status, 403, 'accept needs the Risk scope / admin');
  assert.equal((await call('POST', '/rcsa/responses/' + rid + '/accept', {}, BOT)).status, 403);
  r = await call('POST', '/rcsa/responses/' + rid + '/accept', {}, RISK); assert.equal(r.status, 200, r.text);
  assert.equal(GR.riskList().items.find((x) => x.id === r1.id).likelihood, 4, 'accepted: the register now carries the re-assessed rating');
  assert.equal((await call('POST', '/rcsa/responses/' + rid + '/accept', {}, RISK)).status, 409, 'already accepted');
  // revoke a link, then it is refused
  r = await call('POST', '/rcsa/' + id + '/link/' + resp_key(tok) + '/revoke', {}, RISK); assert.equal(r.status, 200, r.text);
  assert.equal((await e.req('GET', '/agent/rcsa/view', { headers: { 'x-rcsa-token': tok } })).status, 403, 'revoked link refused');
  // reissue (un-revokes), then close the campaign refuses the link
  const tok2 = (await call('POST', '/rcsa/' + id + '/link', { owner: 'proc.head' }, RISK)).json.token;
  assert.equal((await e.req('GET', '/agent/rcsa/view', { headers: { 'x-rcsa-token': tok2 } })).status, 200);
  await call('POST', '/rcsa/' + id + '/close', {}, RISK);
  assert.equal((await e.req('GET', '/agent/rcsa/view', { headers: { 'x-rcsa-token': tok2 } })).status, 409, 'a closed campaign refuses the link');
  // reject path on a fresh campaign
  const id2 = (await call('POST', '/rcsa', { title: 'RCSA redo', period: '2026-Q4', due: '2026-12-20' }, RISK)).json.id;
  const t3 = (await call('POST', '/rcsa/' + id2 + '/link', { owner: 'hr.head' }, RISK)).json.token;
  await e.req('POST', '/agent/rcsa/submit', { headers: { 'x-rcsa-token': t3 }, body: { responses: [{ risk: r2.id, likelihood: 1, impact: 1 }] } });
  const rr = (await call('GET', '/rcsa/' + id2 + '/responses', undefined, OP)).json.items[0];
  assert.equal((await call('POST', '/rcsa/responses/' + rr.id + '/reject', {}, RISK)).status, 400, 'a reason is required');
  r = await call('POST', '/rcsa/responses/' + rr.id + '/reject', { reason: 'under-rated (synthetic)' }, RISK); assert.equal(r.status, 200);
  assert.equal(r.json.items[0].status, 'rejected');
  // the public page: strict CSP, no token in it; only a top-level navigation may come from another site
  let pg = await e.req('GET', '/agent/rcsa/form'); assert.equal(pg.status, 200);
  assert.match(pg.headers['content-security-policy'] || '', /script-src 'self'/); assert.equal(pg.headers['referrer-policy'], 'no-referrer'); assert.equal(pg.headers['x-frame-options'], 'DENY');
  assert.ok(!/eyJ/.test(pg.text || ''), 'the page carries no token');
  pg = await e.req('GET', '/agent/rcsa/form', { headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } }); assert.equal(pg.status, 200, 'a link clicked in Outlook Web opens the page');
  assert.equal((await e.req('GET', '/agent/rcsa/form', { headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'cors' } })).status, 403, 'a cross-site fetch of the page is still refused');
  assert.equal((await e.req('GET', '/agent/rcsa/view', { headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'x-rcsa-token': t3 } })).status, 403, 'the API is not navigable from another site');
  assert.equal((await e.req('POST', '/agent/rcsa/submit', { headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'x-rcsa-token': t3 }, body: { responses: [{ risk: r2.id, likelihood: 1, impact: 1 }] } })).status, 403, 'a cross-site POST is refused');
  assert.equal((await e.req('GET', '/agent/rcsa/view')).status, 400, 'no token');
  const js = await e.req('GET', '/agent/rcsa/form.js'); assert.equal(js.status, 200); assert.match(js.headers['content-type'], /javascript/); assert.ok(!/innerHTML/.test(js.text), 'the page script never uses innerHTML');
  // navigable is only for an exact agent GET route (the http server refuses anything wider)
  assert.throws(() => e.app.srv.route('POST', '/rcsa/x', () => ({}), { agent: true, navigable: true }), /navigable/);
  assert.throws(() => e.app.srv.route('GET', '/rcsa/:id/x', () => ({}), { agent: true, navigable: true }), /navigable/);
  assert.throws(() => e.app.srv.route('GET', '/rcsa-portal', () => ({}), { navigable: true }), /navigable/, 'a portal route can never be navigable');
  // audit
  const au = e.app.store.auditTail(200).filter((a) => /^rcsa\./.test(a.action));
  for (const a of ['open', 'link', 'submit', 'accept', 'revoke', 'close', 'reject']) assert.ok(au.some((x) => x.action === 'rcsa.' + a), 'audited: ' + a);
  assert.ok(au.some((x) => x.action === 'rcsa.submit' && /^rcsa-link:/.test(x.by)), 'a public submit is audited as a link, not a user');
});
function resp_key(tok) { const p = JSON.parse(Buffer.from(tok.slice(0, tok.indexOf('.')).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); return p.o; }
