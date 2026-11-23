// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Migration step 3 (docs/PYTHON-MIGRATION.md): pyengine/cisco_api.py must answer exactly like coverageFetch() in
// engine/cisco-support.js. Both talk to the same simulated Cisco token + coverage-summary API over real HTTP on loopback
// (covered / not covered / ErrorResponse / missing serial / several batches / wrong secret / no API entitlement / a
// non-Cisco token URL); answers and the requests they made are compared, then check() is run through the bridge.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawnSync } = require('node:child_process');
const { coverageFetch, createCiscoSupport } = require('../engine/cisco-support');
const { createPyEngine } = require('../engine/pyengine');
const { startApp } = require('./helpers');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;

function cisco(mode) {
  return (u, h, body) => {
    if (u.pathname === '/oauth2/default/v1/token' || u.pathname === '/as/token.oauth2') {
      if (!/^grant_type=client_credentials&client_id=corp-api&client_secret=/.test(body)) return [400, {}];
      if (mode === 'no-token') return [200, { token_type: 'Bearer' }];
      return body.endsWith('client_secret=R%26ght+s%2Fcret%21') ? [200, { access_token: 'tok-9', expires_in: 3600 }] : [401, { error: 'invalid_client' }];
    }
    if (h.authorization !== 'Bearer tok-9') return [401, {}];
    if (mode === 'no-api') return [403, { message: 'not entitled' }];
    const sns = u.pathname.split('/').pop().split(',');
    if (mode === 'fail-second' && sns.includes('FDO5')) return [500, {}];
    return [200, { pagination: {}, serial_numbers: sns.filter((x) => x !== 'FDO4').map((sn) =>
      sn === 'FDO1' ? { sr_no: sn, is_covered: 'YES', service_contract_number: 9001, service_line_descr: 'SNT\t24X7X4', coverage_end_date: '2027-03-15', orderable_pid_list: [{ orderable_pid: 'C9500-24Y4C' }], contract_site_customer_name: ZYB_ORG.upper }
        : sn === 'FDO2' ? { sr_no: sn.toLowerCase(), is_covered: 'NO', warranty_end_date: '15-Mar-2026', warranty_type: 'WARR-1YR', base_pid_list: 'ISR4331/K9' }
          : sn === 'FDO3' ? { sr_no: sn, ErrorResponse: { APIError: { ErrorCode: 'SNC0001', ErrorDescription: 'Invalid serial – غير صالح' } } }
            : sn === 'FDO5' ? { sr_no: sn, is_covered: true, covered_product_line_end_date: '25/12/2026T', orderable_pid_list: [{ pid: 'N9K-C93180' }] }
              : sn === 'FDO6' ? { sr_no: sn, error: 'temporarily unavailable' }
                : { sr_no: sn, is_covered: 'Y', coverage_end_date: '2026-11-01T00:00:00Z', orderable_pid_list: [{}], base_pid_list: ['x'] }).concat([{ sr_no: 'NOTASKED' }, null]) }];
  };
}
async function serve(api, calls) {
  const srv = http.createServer((q, r) => { let b = ''; q.on('data', (d) => (b += d)); q.on('end', () => { const u = new URL(q.url, 'http://x'); calls.push([q.method, u.pathname, q.headers['content-type'] || '', b]); const [st, body] = api(u, q.headers, b); r.writeHead(st, { 'content-type': 'application/json' }); r.end(JSON.stringify(body)); }); });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  return { base: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((ok) => srv.close(ok)) };
}

test('Python Cisco Support API exchange answers exactly like the Node.js one', { skip: !hasPy && 'python3 not available' }, async () => {
  const py = createPyEngine({ python: PY });
  const serials = ['FDO1', 'FDO2', 'FDO3', 'FDO4', 'FDO5', 'FDO6', 'FDO7'];
  const cases = [
    ['all good, 3 batches', 'ok', '/oauth2/default/v1/token', 'R&ght s/cret!', 3],
    ['old token URL, one batch', 'ok', '/as/token.oauth2', 'R&ght s/cret!', 50],
    ['wrong secret', 'ok', '/oauth2/default/v1/token', 'wrong', 50],
    ['token without access_token', 'no-token', '/oauth2/default/v1/token', 'x', 50],
    ['no API entitlement', 'no-api', '/oauth2/default/v1/token', 'R&ght s/cret!', 50],
    ['second batch fails, first kept', 'fail-second', '/oauth2/default/v1/token', 'R&ght s/cret!', 4],
    ['not a Cisco token URL', 'ok', '/login', 'R&ght s/cret!', 50],
  ];
  for (const [label, mode, tokPath, secret, per] of cases) {
    const nc = [], pc = [], s1 = await serve(cisco(mode), nc), s2 = await serve(cisco(mode), pc);
    try {
      const q = (b) => ({ token_url: b + tokPath, base_url: b, client_id: 'corp-api', client_secret: secret, serials, per_call: per });
      const n = await coverageFetch(q(s1.base));
      const p = await py.call('cisco.coverage', q(s2.base));
      assert.deepEqual(p, n, label + ': identical answers');
      assert.deepEqual(pc, nc, label + ': the same requests, in the same order');
      if (label === 'all good, 3 batches') {
        assert.equal(nc.length, 4, 'token + 3 coverage calls');
        assert.deepEqual(n.entries.map((e) => e[0] + ':' + e[2]), ['FDO1:covered', 'FDO2:not_covered', 'FDO3:unknown', 'FDO5:covered', 'FDO6:unknown', 'FDO4:unknown', 'FDO7:covered']);
        assert.match(n.entries[2][1].error, /غير صالح/);
      }
    } finally { await s1.close(); await s2.close(); }
  }
  // refused before anything is sent: a plain-http non-loopback URL, a base URL with a path
  for (const q of [{ token_url: 'http://id.cisco.com/oauth2/default/v1/token', base_url: 'https://apix.cisco.com' }]) {
    const r = await py.call('cisco.coverage', Object.assign({ client_id: 'a', client_secret: 'b', serials: ['X'] }, q));
    assert.deepEqual(r, await coverageFetch(Object.assign({ client_id: 'a', client_secret: 'b', serials: ['X'] }, q)));
    assert.equal(r.error, 'token URL is not a Cisco OAuth token endpoint');
  }
});

test('check() reads Cisco through the Python module and records the engine', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const e = await startApp({ noAi: true });
  const calls = [], s = await serve(cisco('ok'), calls);
  t.after(async () => { await s.close(); await e.close(); });
  const ADM = { user: 'syed', role: 'admin' };
  e.app.assets.create({ name: 'CORE-SW1', type: 'network', status: 'in_use', vendor: 'Cisco', model: 'C9500-24Y4C', serial: 'FDO1' }, ADM);
  e.app.assets.create({ name: 'JED-RTR', type: 'network', status: 'in_use', vendor: 'Cisco', model: 'ISR4331/K9', serial: 'fdo2' }, ADM);
  e.app.config.discovery = Object.assign({}, e.app.config.discovery, { python_bin: PY });
  const C = createCiscoSupport(e.app, { now: () => Date.parse('2026-10-14T08:00:00Z'), noTimer: true });
  C.saveConfig({ api: { enabled: true, client_id: 'corp-api', client_secret: 'R&ght s/cret!' } }, ADM); C.stop();
  const col = e.app.store.collection('cisco_support'), c = col.get('config');   // saveConfig only takes https addresses
  c.api.token_url = s.base + '/oauth2/default/v1/token'; c.api.base_url = s.base; col.put(c);
  const r = await C.check(ADM);
  assert.equal(r.engine, 'python');
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual([r.checked, r.covered, r.not_covered, r.unknown], [2, 1, 1, 0]);
  assert.equal(calls.length, 2);
});
