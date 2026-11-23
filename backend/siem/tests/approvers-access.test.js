// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Engineer access in the SIEM (approvers/access.js, the same file as IT Asset Management's engine/access-scopes.js): IT Asset
// Management pushes {user: [engineer function]} beside the approver list (admin only, validated); the API server then refuses
// a restricted person's request outside their routes with 403 before the route runs, audits the refusal (once per person
// and route group per 10 minutes), and leaves administrators, everyone not on the list and service identities unchanged.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), http = require('node:http');
const { createApi } = require('../engine/api/server');
const { createState } = require('../engine/soc/state');
const approvers = require('../engine/approvers/routes');
const AC = require('../engine/approvers/access');

const SECRET = 'x'.repeat(32);
function req(port, method, p, { user, role, body } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const headers = Object.assign({ 'X-Sentra-Proxy-Secret': SECRET }, user ? { 'X-Auth-User': user } : {}, role ? { 'X-Auth-Role': role } : {}, data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {});
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers }, (res) => {
      const c = []; res.on('data', (d) => c.push(d)); res.on('end', () => { const t = Buffer.concat(c).toString(); let j = null; try { j = JSON.parse(t); } catch { /* not JSON */ } resolve({ status: res.statusCode, json: j }); });
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}

test('engineer access: pushed with the approvers, validated, enforced before every route, audited', async () => {
  const audits = [];
  const state = createState({ dir: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-acc-')), 'state') });
  const api = createApi({ port: 0, audit: (e) => audits.push(e), proxySecret: SECRET });
  approvers.register(api, { state, config: {}, log: { error() {} } });
  let ran = 0;
  for (const p of ['/api/soc/search', '/api/soc/sysadmin/targets', '/api/soc/netops/overview', '/api/soc/netops/avail', '/api/soc/duty/items', '/api/soc/approvals']) api.route('GET', p, () => { ran++; return { ok: true }; });
  const { port } = await api.start();
  const SYS = { user: 'system:itam-roles', role: 'admin' };
  try {
    // only IT Asset Management (as an administrator) sets it, and every entry is checked
    let r = await req(port, 'POST', '/api/soc/approvers', { user: 'fahad.syn', role: 'operator', body: { scopes: {}, access: { 'fahad.syn': [] } } }); assert.equal(r.status, 403);
    r = await req(port, 'POST', '/api/soc/approvers', Object.assign({ body: { scopes: {}, access: [] } }, SYS)); assert.equal(r.status, 400); assert.match(r.json.error, /access must be an object/);
    r = await req(port, 'POST', '/api/soc/approvers', Object.assign({ body: { scopes: {}, access: { 'bad user!': ['windows'] } } }, SYS)); assert.equal(r.status, 400); assert.match(r.json.error, /invalid user name/);
    r = await req(port, 'POST', '/api/soc/approvers', Object.assign({ body: { scopes: {}, access: { 'fahad.syn': ['soc'] } } }, SYS)); assert.equal(r.status, 400); assert.match(r.json.error, /unknown engineer function "soc"/);
    r = await req(port, 'POST', '/api/soc/approvers', Object.assign({ body: { scopes: {}, access: { 'Fahad.Syn': ['windows'], 'omar.syn': ['network'] } } }, SYS)); assert.equal(r.status, 200); assert.equal(r.json.access_changed, true);
    assert.ok(audits.some((a) => a.action === 'access.update' && a.by === 'system:itam-roles'), 'the change is audited');

    // the Windows admin: their routes run, the log search and SOC approvals are refused before the route runs
    const fahad = { user: 'fahad.syn', role: 'operator' }, omar = { user: 'omar.syn', role: 'operator' };
    r = await req(port, 'GET', '/api/soc/sysadmin/targets', fahad); assert.equal(r.status, 200);
    r = await req(port, 'GET', '/api/soc/netops/avail', fahad); assert.equal(r.status, 200, 'server availability is theirs');
    r = await req(port, 'GET', '/api/soc/duty/items', fahad); assert.equal(r.status, 200, 'their own work queue');
    const before = ran;
    r = await req(port, 'GET', '/api/soc/search', fahad); assert.equal(r.status, 403); assert.match(r.json.error, /not part of your job role/);
    r = await req(port, 'GET', '/api/soc/netops/overview', fahad); assert.equal(r.status, 403, 'the network overview is not a Windows route');
    r = await req(port, 'GET', '/api/soc/approvals', fahad); assert.equal(r.status, 403);
    assert.equal(ran, before, 'a refused route never ran');
    const ref = audits.filter((a) => a.action === 'access.refused' && a.by === 'fahad.syn');
    assert.equal(ref.length, 3); assert.equal(ref[0].role, 'operator'); assert.deepEqual(ref[0].detail.functions, ['windows']); assert.match(ref[0].target, /GET \/api\/soc\/search/);
    await req(port, 'GET', '/api/soc/search', fahad); assert.equal(audits.filter((a) => a.action === 'access.refused' && a.by === 'fahad.syn').length, 3, 'not audited again within 10 minutes');
    // the network engineer: netops yes, sysadmin no
    r = await req(port, 'GET', '/api/soc/netops/overview', omar); assert.equal(r.status, 200);
    r = await req(port, 'GET', '/api/soc/sysadmin/targets', omar); assert.equal(r.status, 403);
    // unchanged: an administrator, a person not on the list, a service identity
    r = await req(port, 'GET', '/api/soc/search', { user: 'fahad.syn', role: 'admin' }); assert.equal(r.status, 200, 'a gateway administrator is never restricted');
    r = await req(port, 'GET', '/api/soc/search', { user: 'sara.syn', role: 'operator' }); assert.equal(r.status, 200);
    r = await req(port, 'GET', '/api/soc/search', { user: 'system:itam-ciso', role: 'viewer' }); assert.equal(r.status, 200);
    // an older IT Asset Management pushes approvers only: the stored list stays; a push with an empty list lifts it
    r = await req(port, 'POST', '/api/soc/approvers', Object.assign({ body: { scopes: {} } }, SYS)); assert.equal(r.status, 200);
    r = await req(port, 'GET', '/api/soc/search', fahad); assert.equal(r.status, 403, 'a push without access leaves the list');
    r = await req(port, 'POST', '/api/soc/approvers', Object.assign({ body: { scopes: {}, access: {} } }, SYS)); assert.equal(r.status, 200);
    r = await req(port, 'GET', '/api/soc/search', fahad); assert.equal(r.status, 200, 'removed from the list: unchanged at once');
  } finally { await api.stop(); }
});

test('the allow-list: whole segments only, no dot paths, nothing outside the lists', () => {
  assert.equal(AC.allows('soc', ['exchange'], '/mail/stats'), true);
  assert.equal(AC.allows('soc', ['exchange'], '/mailbox'), false, 'a prefix matches whole segments only');
  assert.equal(AC.allows('soc', ['exchange'], '/mail/../search'), false);
  assert.equal(AC.allows('soc', ['backup'], '/sysadmin'), false);
  assert.equal(AC.allows('soc', [], '/duty/items'), true, 'the work queue is common');
  assert.equal(AC.allows('soc', ['nope'], '/netops'), false);
});
