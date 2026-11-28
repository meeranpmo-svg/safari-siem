// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// DNS fixes for mail (engine/dns-fix.js) against a mock Cloudflare API: the token admin-only, verified, sealed and never returned
// or logged; the SPF rewrite (add before "all", remove, nothing to do, 255 characters, one SPF record); four-eyes (the proposer
// cannot approve, service identities never act); a record changed since the proposal is not overwritten; read-back; reject;
// undo as a new proposal; roles and validation errors naming the field; the audit trail. SYNTHETIC domain and RFC 5737 addresses.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'omar.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'v.syn', role: 'viewer' };
const TOKEN = 'cfTOKENsynthetic0123456789abcdefABCDEF';
const sealer = { seal: (id, t) => 'SEALED:' + Buffer.from(t).toString('base64'), unseal: (id, e) => Buffer.from(String(e).slice(7), 'base64').toString() };
function mockCf(state) {
  return async (method, path, data, token) => {
    state.calls.push([method, path, data]);
    if (token !== TOKEN) { const e = new Error('Cloudflare: Invalid API Token'); e.status = 424; throw e; }
    if (path === '/user/tokens/verify') return { success: true, result: { status: state.tokenStatus || 'active' } };
    if (path.startsWith('/zones?name=')) { const n = decodeURIComponent(path.split('=')[1]); return { success: true, result: n === 'corpgroup.test' ? [{ id: 'Z1', name: n }] : [] }; }
    if (path.startsWith('/zones/Z1/dns_records?')) return { success: true, result: state.txt.map((t, i) => ({ id: 'R' + (i + 1), content: t })) };
    const m = /^\/zones\/Z1\/dns_records\/(R\d+)$/.exec(path);
    if (m && method === 'PATCH') { const i = Number(m[1].slice(1)) - 1; state.txt[i] = state.lieOnWrite ? state.txt[i] : data.content; return { success: true, result: { id: m[1] } }; }
    throw new Error('unexpected ' + method + ' ' + path);
  };
}
async function setup(t, state) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  state.calls = [];
  registerDuty(e.app.srv, e.app, { noTimer: true, mailSealer: sealer, dnsCf: mockCf(state) });
  return e;
}
const post = (e, p, body, who) => e.req('POST', p, Object.assign({ body }, who));

test('Cloudflare token: administrator only, verified before it is kept, sealed, never returned or logged', async (t) => {
  const st = { txt: ['"v=spf1 ip4:192.0.2.10 include:spf.protection.outlook.com -all"'] }; const e = await setup(t, st);
  assert.equal((await post(e, '/dns-fix/token', { token: TOKEN }, OP)).status, 403, 'operator refused');
  assert.equal((await post(e, '/dns-fix/token', { token: TOKEN }, { user: 'system:x', role: 'admin' })).status, 403, 'a service identity refused');
  let r = await post(e, '/dns-fix/token', { token: 'short' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /token/);
  r = await post(e, '/dns-fix/token', { token: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }, ADM); assert.equal(r.status, 424, 'a token Cloudflare refuses is not kept');
  assert.equal((await e.req('GET', '/dns-fix', VW)).json.connected, false);
  st.tokenStatus = 'disabled'; r = await post(e, '/dns-fix/token', { token: TOKEN }, ADM); assert.equal(r.status, 424); assert.match(r.text, /disabled/);
  st.tokenStatus = 'active'; r = await post(e, '/dns-fix/token', { token: TOKEN }, ADM); assert.equal(r.status, 200);
  const v = (await e.req('GET', '/dns-fix', VW)).json; assert.equal(v.connected, true); assert.ok(!JSON.stringify(v).includes(TOKEN), 'never returned');
  const stored = e.app.store.collection('dns_fix_cfg').get('cloudflare'); assert.ok(stored.enc.startsWith('SEALED:') && !JSON.stringify(stored).includes(TOKEN), 'sealed at rest');
  const a = e.app.store.auditTail(20); assert.ok(a.some((x) => x.action === 'dns-fix.token.set' && x.by === 'syed')); assert.ok(!JSON.stringify(a).includes(TOKEN), 'never in the audit trail');
});

test('SPF proposal, four-eyes approval, write and read-back, reject, undo; validation and roles', async (t) => {
  const st = { txt: ['"v=spf1 ip4:192.0.2.10 include:spf.protection.outlook.com -all"', '"MS=ms12345"'] }; const e = await setup(t, st);
  let r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.50'], reason: 'new outbound IP' }, OP); assert.equal(r.status, 424, 'not connected says so'); assert.match(r.text, /Cloudflare is not connected/);
  await post(e, '/dns-fix/token', { token: TOKEN }, ADM);
  assert.equal((await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.50'], reason: 'new outbound IP' }, VW)).status, 403, 'viewer refused');
  r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.999'], reason: 'new outbound IP' }, OP); assert.equal(r.status, 400); assert.match(r.text, /add/);
  r = await post(e, '/dns-fix/spf', { domain: 'not a domain', add: ['192.0.2.50'], reason: 'new outbound IP' }, OP); assert.equal(r.status, 400); assert.match(r.text, /domain/);
  r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.50'] }, OP); assert.equal(r.status, 400); assert.match(r.text, /reason/);
  r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', reason: 'nothing at all' }, OP); assert.equal(r.status, 400);
  r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.10'], reason: 'already listed' }, OP); assert.equal(r.status, 409, 'nothing to change');
  r = await post(e, '/dns-fix/spf', { domain: 'other.test', add: ['192.0.2.50'], reason: 'new outbound IP' }, OP); assert.equal(r.status, 424, 'a zone the token cannot see');
  r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.50'], remove: ['192.0.2.10'], reason: 'outbound IP moved from .10 to .50' }, OP);
  assert.equal(r.status, 200, r.text); const p = r.json;
  assert.equal(p.after, 'v=spf1 include:spf.protection.outlook.com ip4:192.0.2.50 -all', 'old ip4 removed, new one before -all'); assert.equal(p.status, 'pending');
  assert.ok(!st.calls.some((c) => c[0] === 'PATCH'), 'nothing written by a proposal');
  assert.equal((await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.60'], reason: 'another one' }, OP)).status, 409, 'one pending change per domain');
  // four-eyes
  assert.equal((await post(e, '/dns-fix/' + p.id + '/approve', {}, OP)).status, 403, 'an operator does not approve');
  const op2 = { user: 'nora.syn', role: 'admin' }; assert.equal((await post(e, '/dns-fix/' + p.id + '/approve', {}, op2)).status, 403, 'the proposer cannot approve');
  { const x = await post(e, '/dns-fix/' + p.id + '/approve', {}, { user: 'NORA.SYN', role: 'admin' }); assert.equal(x.status, 403); assert.match(x.json.error, /four-eyes/, 'the proposer under another spelling of their name'); }
  assert.equal((await post(e, '/dns-fix/' + p.id + '/approve', {}, { user: 'ai:engineer', role: 'admin' })).status, 403, 'an AI identity never approves');
  r = await post(e, '/dns-fix/' + p.id + '/approve', { note: 'checked with the network team' }, ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.status, 'applied'); assert.equal(r.json.approved_by, 'syed'); assert.equal(st.txt[0], '"v=spf1 include:spf.protection.outlook.com ip4:192.0.2.50 -all"', 'written in the same quoting');
  assert.equal(st.txt[1], '"MS=ms12345"', 'other TXT records untouched');
  assert.equal((await post(e, '/dns-fix/' + p.id + '/approve', {}, ADM2)).status, 409, 'cannot apply twice');
  // stale: someone edits the record after the proposal
  r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.70'], reason: 'second gateway' }, OP); const p2 = r.json;
  st.txt[0] = '"v=spf1 ip4:192.0.2.50 ip4:198.51.100.9 -all"';
  r = await post(e, '/dns-fix/' + p2.id + '/approve', {}, ADM); assert.equal(r.status, 409); assert.match(r.text, /changed since/);
  assert.equal(st.txt[0], '"v=spf1 ip4:192.0.2.50 ip4:198.51.100.9 -all"', 'someone else\'s edit is never overwritten');
  assert.equal(e.app.store.collection('dns_fix').get(p2.id).status, 'stale');
  // reject
  r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.80'], reason: 'test gateway' }, OP); const p3 = r.json;
  assert.equal((await post(e, '/dns-fix/' + p3.id + '/reject', {}, ADM)).status, 400, 'reason required');
  assert.equal((await post(e, '/dns-fix/' + p3.id + '/reject', { reason: 'not a production gateway' }, ADM)).json.status, 'rejected');
  // undo of the applied change: a new proposal, approved like any other
  r = await post(e, '/dns-fix/' + p.id + '/undo', { reason: 'mail from .50 bounced' }, OP); assert.equal(r.status, 200, r.text); assert.deepEqual(r.json.add, ['192.0.2.10']); assert.deepEqual(r.json.remove, ['192.0.2.50']); assert.equal(r.json.status, 'pending');
  // a write that does not stick is reported, not claimed
  st.lieOnWrite = true; r = await post(e, '/dns-fix/' + r.json.id + '/approve', {}, ADM2); assert.equal(r.json.status, 'unverified');
  const a = e.app.store.auditTail(40).map((x) => x.action);
  for (const k of ['dns-fix.propose', 'dns-fix.apply', 'dns-fix.stale', 'dns-fix.reject']) assert.ok(a.includes(k), k);
  const ap = e.app.store.auditTail(40).find((x) => x.action === 'dns-fix.apply' && x.target === p.id); assert.equal(ap.detail.before, 'v=spf1 ip4:192.0.2.10 include:spf.protection.outlook.com -all'); assert.equal(ap.detail.requested_by, 'nora.syn');
});

test('SPF safety: more than one SPF record, no SPF record, 255 characters', async (t) => {
  const st = { txt: ['"v=spf1 ip4:192.0.2.10 -all"', '"v=spf1 include:x.test -all"'] }; const e = await setup(t, st);
  await post(e, '/dns-fix/token', { token: TOKEN }, ADM);
  let r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.50'], reason: 'new outbound IP' }, OP); assert.equal(r.status, 409); assert.match(r.text, /2 SPF records/);
  st.txt = ['"MS=ms1"']; r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.50'], reason: 'new outbound IP' }, OP); assert.equal(r.status, 409); assert.match(r.text, /no SPF record/);
  st.txt = ['"v=spf1 ' + Array.from({ length: 13 }, (_, i) => 'ip4:198.51.100.' + (i + 10)).join(' ') + ' -all"'];
  r = await post(e, '/dns-fix/spf', { domain: 'corpgroup.test', add: ['192.0.2.50'], reason: 'new outbound IP' }, OP); assert.equal(r.status, 409); assert.match(r.text, /255/);
});
