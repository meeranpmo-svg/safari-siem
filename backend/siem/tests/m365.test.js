// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// M365 Management Activity API collector against a local fake of login.microsoftonline.com + manage.office.com.
// Tenant/app ids, records and the certificate (tests/fixtures/synthetic-m365-test.*) are SYNTHETIC test material.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const m365 = require('../engine/collect/m365');
const { createParser } = require('../engine/parse');
const { createPipeline } = require('../engine/pipeline');

const TENANT = '00000000-1111-2222-3333-444444444444';
const CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const CERT = fs.readFileSync(path.join(__dirname, 'fixtures', 'synthetic-m365-test.crt'), 'utf8');
const KEY = fs.readFileSync(path.join(__dirname, 'fixtures', 'synthetic-m365-test.key'), 'utf8');
const b64uDec = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

function records() {
  return {
    blob1: [
      { CreationTime: '2024-05-01T10:00:00', Id: 'rec-a', Operation: 'Set-Mailbox', RecordType: 1, Workload: 'Exchange', UserId: 'admin@test.local', ClientIP: '203.0.113.5', ObjectId: 'bob', Parameters: [{ Name: 'Identity', Value: 'bob@test.local' }, { Name: 'ForwardingSmtpAddress', Value: 'smtp:x@test.invalid' }], ResultStatus: 'True' },
      { CreationTime: '2024-05-01T10:00:01', Id: 'rec-b', Operation: 'MailItemsAccessed', RecordType: 50, Workload: 'Exchange', UserId: 'svc@test.local', MailboxOwnerUPN: 'ceo@test.local', OperationProperties: [{ Name: 'MailAccessType', Value: 'Bind' }] },
    ],
    blob2: [
      { CreationTime: '2024-05-01T10:00:01', Id: 'rec-b', Operation: 'MailItemsAccessed', RecordType: 50, Workload: 'Exchange', UserId: 'svc@test.local' },
      { CreationTime: '2024-05-01T10:00:02', Id: 'rec-c', Operation: 'UserLoginFailed', RecordType: 15, Workload: 'AzureActiveDirectory', UserId: 'bob@test.local', ClientIP: '198.51.100.1', ResultStatus: 'Failed' },
    ],
  };
}

async function fakeMicrosoft({ throttleOnce = false, verifyAssertion = false } = {}) {
  const st = { calls: [], starts: [], tokens: 0, throttle: throttleOnce, assertions: [] };
  const recs = records();
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const body = Buffer.concat(chunks).toString();
      st.calls.push({ method: req.method, path: u.pathname, q: Object.fromEntries(u.searchParams), auth: req.headers.authorization });
      const json = (code, o, headers = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...headers }); res.end(JSON.stringify(o)); };
      if (u.pathname === `/${TENANT}/oauth2/v2.0/token`) {
        const f = Object.fromEntries(new URLSearchParams(body));
        if (f.grant_type !== 'client_credentials' || f.client_id !== CLIENT || f.scope !== `${st.base}/.default`) return json(400, { error: 'invalid_request' });
        if (verifyAssertion) {
          assert.equal(f.client_assertion_type, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
          const [h, p, sig] = f.client_assertion.split('.');
          const header = JSON.parse(b64uDec(h));
          const payload = JSON.parse(b64uDec(p));
          const cert = new crypto.X509Certificate(CERT);
          st.assertions.push({ header, payload, ok: crypto.verify('sha256', Buffer.from(h + '.' + p), { key: cert.publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, b64uDec(sig)), der: cert.raw });
        } else if (f.client_secret !== 'synthetic-secret') return json(401, { error: 'invalid_client' });
        st.tokens++;
        return json(200, { token_type: 'Bearer', expires_in: 3599, access_token: 'synthetic-token-' + st.tokens });
      }
      if (req.headers.authorization !== 'Bearer synthetic-token-' + st.tokens) return json(401, { error: { code: 'AF10001', message: 'bad token' } });
      const root = `/api/v1.0/${TENANT}/activity/feed`;
      if (u.pathname === root + '/subscriptions/list') return json(200, [{ contentType: 'Audit.Exchange', status: 'enabled', webhook: null }]);
      if (u.pathname === root + '/subscriptions/start') { st.starts.push(u.searchParams.get('contentType')); return json(200, { contentType: u.searchParams.get('contentType'), status: 'enabled', webhook: null }); }
      if (u.pathname === root + '/subscriptions/content') {
        if (st.throttle) { st.throttle = false; return json(429, { error: { code: 'AF429', message: 'Too many requests' } }, { 'Retry-After': '2' }); }
        const ct = u.searchParams.get('contentType');
        if (ct !== 'Audit.Exchange') return json(200, []);
        const item = (id) => ({ contentType: ct, contentId: id, contentUri: `${st.base}${root}/audit/${id}`, contentCreated: '2024-05-01T10:05:00.000Z', contentExpiration: new Date(Date.now() + 86400000).toISOString() });
        if (!u.searchParams.get('nextPage')) return json(200, [item('blob1')], { NextPageUri: `${st.base}${root}/subscriptions/content?contentType=${ct}&startTime=${u.searchParams.get('startTime')}&endTime=${u.searchParams.get('endTime')}&nextPage=p2` });
        return json(200, [item('blob2'), item('blob1')]);
      }
      const m = new RegExp(`^${root}/audit/(\\w+)$`).exec(u.pathname);
      if (m && recs[m[1]]) return json(200, recs[m[1]]);
      json(404, { error: { code: 'AF20050', message: 'not found' } });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  st.base = `http://127.0.0.1:${server.address().port}`;
  st.close = () => new Promise((r) => { server.closeAllConnections(); server.close(r); });
  return st;
}

function setup(ms, secrets, stateDir, extra = {}) {
  const config = { m365: { enabled: true, authority: ms.base, api_root: ms.base, content_types: ['Audit.Exchange', 'Audit.AzureActiveDirectory', 'DLP.All'], ...extra } };
  Object.defineProperty(config, 'secrets', { value: { m365: { tenant: TENANT, client_id: CLIENT, ...secrets } } });
  const events = [];
  const pipeline = createPipeline();
  pipeline.use((ev) => events.push(ev));
  const col = m365.start({ config, parser: createParser({ config: {} }), pipeline, stateDir, autoStart: false });
  return { col, events };
}

test('m365 collector: token, subscriptions, pagination, blob fetch, record de-dup, checkpoint, restart', async () => {
  const ms = await fakeMicrosoft();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-m365-'));
  try {
    const { col, events } = setup(ms, { client_secret: 'synthetic-secret' }, dir);
    await col.pollNow();
    assert.deepEqual(events.map((e) => e.fields.Id), ['rec-a', 'rec-b', 'rec-c']);
    assert.ok(events.every((e) => e.src_type === 'm365' && e.collector === 'm365' && e.src_id === 'm365'));
    assert.equal(events[0].action, 'mail-forwarding-set');
    assert.equal(events[1].action, 'mail-items-accessed');
    assert.equal(events[2].action, 'logon-failed');
    const st = col.stats();
    assert.equal(st.records, 3);
    assert.equal(st.duplicates, 1);
    assert.equal(st.blobs, 2);
    assert.deepEqual(ms.starts.sort(), ['Audit.AzureActiveDirectory', 'DLP.All']);
    const listCalls = ms.calls.filter((c) => c.path.endsWith('/subscriptions/content'));
    assert.ok(listCalls.every((c) => c.q.PublisherIdentifier === TENANT));
    const first = listCalls.find((c) => c.q.contentType === 'Audit.Exchange' && !c.q.nextPage);
    assert.match(first.q.startTime, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/);
    assert.ok(Date.parse(first.q.endTime + 'Z') - Date.parse(first.q.startTime + 'Z') <= 86400000);
    assert.ok(listCalls.some((c) => c.q.nextPage === 'p2'), 'followed NextPageUri');
    const cp = JSON.parse(fs.readFileSync(path.join(dir, 'm365-checkpoint.json'), 'utf8'));
    assert.ok(cp.types['Audit.Exchange'].last_end > Date.now() - 120000);
    assert.ok(cp.records.includes('rec-a'));
    // second poll: nothing new
    await col.pollNow();
    assert.equal(events.length, 3);
    await col.stop();
    // restart with the same state dir: blobs + records remembered
    const again = setup(ms, { client_secret: 'synthetic-secret' }, dir);
    await again.col.pollNow();
    assert.equal(again.events.length, 0);
    await again.col.stop();
  } finally { await ms.close(); }
});

test('m365 collector: 429 / AF429 → back-off honouring Retry-After, then recovers', async () => {
  const ms = await fakeMicrosoft({ throttleOnce: true });
  try {
    const { col, events } = setup(ms, { client_secret: 'synthetic-secret' }, null, { content_types: ['Audit.Exchange'] });
    await col.pollNow();
    assert.equal(events.length, 0);
    assert.ok(col.stats().backoff_ms >= 60000);
    assert.match(col.stats().last_error, /throttled/);
    await col.pollNow();
    assert.equal(events.length, 3);
    assert.equal(col.stats().backoff_ms, 0);
    await col.stop();
  } finally { await ms.close(); }
});

test('m365 collector: certificate client assertion (PS256, x5t#S256, aud = token URL)', async () => {
  const ms = await fakeMicrosoft({ verifyAssertion: true });
  try {
    const { col, events } = setup(ms, { cert_pem: CERT, key_pem: KEY }, null, { content_types: ['Audit.Exchange'] });
    await col.pollNow();
    assert.equal(events.length, 3);
    const a = ms.assertions[0];
    assert.equal(a.ok, true, 'signature verifies with the certificate public key');
    assert.equal(a.header.alg, 'PS256');
    assert.equal(a.header.typ, 'JWT');
    assert.equal(b64uDec(a.header['x5t#S256']).toString('hex'), crypto.createHash('sha256').update(a.der).digest('hex'));
    assert.equal(a.payload.aud, `${ms.base}/${TENANT}/oauth2/v2.0/token`);
    assert.equal(a.payload.iss, CLIENT);
    assert.equal(a.payload.sub, CLIENT);
    assert.ok(a.payload.exp - a.payload.nbf <= 600);
    assert.match(a.payload.jti, /^[0-9a-f-]{36}$/);
    await col.stop();
  } finally { await ms.close(); }
});

test('m365 collector: disabled / missing credentials → no-op with a clear status', async () => {
  const off = m365.start({ config: { m365: { enabled: false } }, autoStart: false });
  assert.deepEqual(off.stats(), { enabled: false });
  const cfg = { m365: { enabled: true } };
  Object.defineProperty(cfg, 'secrets', { value: { m365: { tenant: TENANT } } });
  const bad = m365.start({ config: cfg, autoStart: false });
  assert.match(bad.stats().error, /client_id/);
  assert.match(bad.stats().error, /client_secret or cert_file/);
});
