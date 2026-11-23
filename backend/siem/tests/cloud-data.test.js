// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Data Security Posture - cloud object stores (engine/collect/cloud-data.js, engine/collect/cloud-data-routes.js) through the
// REAL API server with STUBBED providers and SYNTHETIC data only: SigV4 against AWS's published test vectors, the OCI signature
// header, the Azure SharedKey string-to-sign; a full scan of Azure (ARM discovery + the Microsoft 365 app registration), AWS
// and OCI (public via policy / ACL / container / publicAccessType, private + customer-managed key), synthetic national IDs /
// IBAN / an API-key placeholder counted (never kept), in_kingdom true / false / null, truncation at max_objects, no redirect or
// foreign host followed, only GET calls (plus the Entra sign-in), roles (viewer counts only, analyst object names, operator scan,
// admin settings / credentials, refused cases 403), validation errors naming the field, credentials sealed in secrets.json and
// absent from every response / audit / log, audit records, 409 while a scan runs, the not-configured note.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-cd-')), keyFile = path.join(dir, 'secrets.key');
fs.writeFileSync(keyFile, crypto.randomBytes(32).toString('hex'), { mode: 0o440 });
process.env.SENTRA_SIEM_SECRETS_KEY = keyFile;
const SF = require('../engine/secretfile'); SF._reset();
const { createApi } = require('../engine/api/server');
const { createState } = require('../engine/soc/state');
const CD = require('../engine/collect/cloud-data');
const ROUTES = require('../engine/collect/cloud-data-routes');
const realClassify = require('../engine/pii/classify');

/* ---------------------------------------------------------------- signing */
test('SigV4: AWS published test vectors (S3 GetObject with Range, S3 ListObjects, IAM ListUsers)', () => {
  const S3 = { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', amzDate: '20130524T000000Z', region: 'us-east-1', service: 's3' };
  const E = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const a = CD.sigv4(Object.assign({ host: 'examplebucket.s3.amazonaws.com', path: '/test.txt', headers: { range: 'bytes=0-9', 'x-amz-content-sha256': E } }, S3));
  assert.equal(a.signature, 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
  assert.equal(a.headers.authorization, 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
  const b = CD.sigv4(Object.assign({ host: 'examplebucket.s3.amazonaws.com', path: '/', query: [['max-keys', '2'], ['prefix', 'J']], headers: { 'x-amz-content-sha256': E } }, S3));
  assert.equal(b.signature, '34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7');
  assert.equal(b.pathQuery, '/?max-keys=2&prefix=J');
  const c = CD.sigv4({ host: 'iam.amazonaws.com', path: '/', query: [['Action', 'ListUsers'], ['Version', '2010-05-08']], headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' }, region: 'us-east-1', service: 'iam', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', amzDate: '20150830T123600Z' });
  assert.equal(c.signature, '5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7');
  const t = CD.sigv4(Object.assign({ host: 'b.s3.amazonaws.com', path: '/', sessionToken: 'SYNTHETICSESSION' }, S3));
  assert.match(t.headers.authorization, /SignedHeaders=host;x-amz-date;x-amz-security-token,/, 'a session token is sent and signed');
});

test('OCI signature header: keyId, rsa-sha256, headers "date (request-target) host", verifies with the public key', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const r = CD.ociSign({ host: 'objectstorage.me-jeddah-1.oraclecloud.com', pathQuery: '/n/synns/b/?compartmentId=ocid1.compartment.oc1..aaaasynthetic&limit=1000', keyId: 'ocid1.tenancy.oc1..t/ocid1.user.oc1..u/aa:bb', privateKey: pem, date: 'Sat, 14 Nov 2026 10:00:00 GMT' });
  assert.match(r.headers.authorization, /^Signature version="1",keyId="ocid1\.tenancy\.oc1\.\.t\/ocid1\.user\.oc1\.\.u\/aa:bb",algorithm="rsa-sha256",headers="date \(request-target\) host",signature="[A-Za-z0-9+/=]{300,}"$/);
  assert.equal(r.signingString, 'date: Sat, 14 Nov 2026 10:00:00 GMT\n(request-target): get /n/synns/b/?compartmentId=ocid1.compartment.oc1..aaaasynthetic&limit=1000\nhost: objectstorage.me-jeddah-1.oraclecloud.com');
  const sig = /signature="([^"]+)"/.exec(r.headers.authorization)[1];
  assert.ok(crypto.verify('sha256', Buffer.from(r.signingString), publicKey, Buffer.from(sig, 'base64')));
  assert.equal(r.headers.date, 'Sat, 14 Nov 2026 10:00:00 GMT');
});

test('Azure SharedKey: string-to-sign as specified, HMAC-SHA256 with the base64 key', () => {
  const headers = { 'x-ms-date': 'Sat, 14 Nov 2026 10:00:00 GMT', 'x-ms-version': '2023-11-03', 'x-ms-range': 'bytes=0-2097151' };
  const sts = CD.azureStringToSign({ method: 'GET', account: 'synacct', pathEnc: '/hr/file%20a.txt', query: { maxresults: '5', comp: 'list' }, headers });
  assert.equal(sts, 'GET' + '\n'.repeat(12) + 'x-ms-date:Sat, 14 Nov 2026 10:00:00 GMT\nx-ms-range:bytes=0-2097151\nx-ms-version:2023-11-03\n/synacct/hr/file%20a.txt\ncomp:list\nmaxresults:5');
  const key = Buffer.from('SYNTHETIC-ACCOUNT-KEY-0123456789-SYNTHETIC').toString('base64');
  const r = CD.azureSharedKey({ method: 'GET', account: 'synacct', pathEnc: '/hr/file%20a.txt', query: { maxresults: '5', comp: 'list' }, headers, key });
  assert.equal(r.authorization, 'SharedKey synacct:' + crypto.createHmac('sha256', Buffer.from(key, 'base64')).update(sts).digest('base64'));
  assert.equal(CD.azureStringToSign({ account: 'a', headers: { 'Content-Length': '0' } }).split('\n')[3], '', 'Content-Length 0 is signed as empty');
});

/* ---------------------------------------------------------------- synthetic providers */
const IDS = 'id\n1000000001\n1000000002\n1000000003\n1000000004\n';                 // synthetic national IDs (pattern only)
const IBAN = 'beneficiary,iban\nSYNTHETIC,SA4420000001234567891234\n';               // synthetic IBAN (pattern only)
const APIKEY = 'service=syn\napi_key = "SYNTHETIC-API-KEY-0123456789ABCDEF"\n';     // a placeholder in an API-key shape
function zipStored(files) {   // a minimal stored-entry zip (what classify.textOf reads for .docx)
  const loc = [], cen = []; let off = 0;
  for (const [n, d0] of files) {
    const nb = Buffer.from(n), d = Buffer.from(d0), lh = Buffer.alloc(30), ch = Buffer.alloc(46);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt32LE(d.length, 18); lh.writeUInt32LE(d.length, 22); lh.writeUInt16LE(nb.length, 26);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt32LE(d.length, 20); ch.writeUInt32LE(d.length, 24); ch.writeUInt16LE(nb.length, 28); ch.writeUInt32LE(off, 42);
    loc.push(lh, nb, d); cen.push(ch, nb); off += 30 + nb.length + d.length;
  }
  const cd = Buffer.concat(cen), e = Buffer.alloc(22);
  e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(files.length, 8); e.writeUInt16LE(files.length, 10); e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(off, 16);
  return Buffer.concat([...loc, cd, e]);
}
const DOCX = zipStored([['[Content_Types].xml', '<Types/>'], ['word/document.xml', '<w:document><w:p>1000000011 1000000012 1000000013</w:p></w:document>']]);
const xml = (s) => ({ status: 200, headers: { 'content-type': 'application/xml' }, body: '<?xml version="1.0" encoding="UTF-8"?>' + s });
const err = (status, code, msg) => ({ status, headers: {}, body: `<?xml version="1.0"?><Error><Code>${code}</Code><Message>${msg}</Message></Error>` });
const json = (o, headers) => ({ status: 200, headers: Object.assign({ 'content-type': 'application/json' }, headers || {}), body: JSON.stringify(o) });
const bytes = (req, b) => { const m = /bytes=0-(\d+)/.exec(req.headers.range || req.headers['x-ms-range'] || ''); assert.ok(m, 'every object read is a ranged GET: ' + req.url); return { status: 206, headers: {}, body: Buffer.from(b).subarray(0, Number(m[1]) + 1) }; };

const SUB = '00000000-0000-4000-8000-000000000001', TENANT = '00000000-0000-4000-8000-0000000000aa', APP = '00000000-0000-4000-8000-0000000000bb';
const M365_SECRET = 'SYNTHETIC-M365-CLIENT-SECRET-VALUE', AWS_SECRET = 'SYNTHETICsecretKEY0123456789abcdefghijklmn', AWS_KEY = 'AKIASYNTHETIC0000001';
const { privateKey: OCI_KEY, publicKey: OCI_PUB } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const OCI_PEM = OCI_KEY.export({ type: 'pkcs8', format: 'pem' }).trim();

function providers(calls, gate) {
  return async (req) => {
    calls.push(req);
    const u = new URL(req.url), h = u.hostname, q = u.searchParams;
    if (gate && gate.wait && h === 's3.amazonaws.com') await gate.wait;
    /* Azure */
    if (h === 'login.microsoftonline.com') {
      const f = new URLSearchParams(req.body);
      assert.equal(u.pathname, `/${TENANT}/oauth2/v2.0/token`); assert.equal(f.get('client_id'), APP); assert.equal(f.get('client_secret'), M365_SECRET, 'the Microsoft 365 app registration is reused');
      return json({ access_token: 'SYNTHETIC-TOKEN-' + (f.get('scope').includes('management') ? 'ARM' : 'STORAGE'), expires_in: 3600 });
    }
    if (h === 'management.azure.com') {
      assert.equal(req.headers.authorization, 'Bearer SYNTHETIC-TOKEN-ARM');
      if (u.pathname === '/subscriptions') return json({ value: [{ subscriptionId: SUB, state: 'Enabled' }] });
      if (u.pathname === `/subscriptions/${SUB}/providers/Microsoft.Storage/storageAccounts`) return json({ nextLink: 'https://evil.example/steal', value: [
        { name: 'synstorage01', location: 'synksa', properties: { allowBlobPublicAccess: true, minimumTlsVersion: 'TLS1_2', networkAcls: { defaultAction: 'Allow' }, encryption: { keySource: 'Microsoft.Keyvault', services: { blob: { enabled: true } } } } },
        { name: 'synstorage02', location: 'westeurope', properties: { allowBlobPublicAccess: false, minimumTlsVersion: 'TLS1_0', networkAcls: { defaultAction: 'Deny' }, encryption: { keySource: 'Microsoft.Storage', services: { blob: { enabled: true } } } } }] });
    }
    if (h.endsWith('.blob.core.windows.net')) {
      assert.equal(req.headers.authorization, 'Bearer SYNTHETIC-TOKEN-STORAGE'); assert.equal(req.headers['x-ms-version'], '2023-11-03');
      const acct = h.split('.')[0];
      if (u.pathname === '/' && q.get('comp') === 'list') return xml(acct === 'synstorage01'
        ? '<EnumerationResults><Containers><Container><Name>public-docs</Name><Properties><PublicAccess>blob</PublicAccess></Properties></Container><Container><Name>hr</Name><Properties></Properties></Container></Containers><NextMarker/></EnumerationResults>'
        : '<EnumerationResults><Containers><Container><Name>archive</Name><Properties><PublicAccess>container</PublicAccess></Properties></Container></Containers><NextMarker/></EnumerationResults>');
      const blobs = { 'synstorage01/public-docs': [['staff.docx', DOCX]], 'synstorage01/hr': [['payroll-2026.xlsx', Buffer.alloc(0)], ['notes.txt', 'nothing to see here']], 'synstorage02/archive': [['iban-list.csv', IBAN]] };
      const [, cont, ...rest] = u.pathname.split('/'), list = blobs[acct + '/' + cont];
      if (q.get('comp') === 'list') return xml('<EnumerationResults><Blobs>' + list.map(([n, b]) => `<Blob><Name>${n}</Name><Properties><Last-Modified>Fri, 13 Nov 2026 08:00:00 GMT</Last-Modified><Content-Length>${Buffer.from(b).length}</Content-Length></Properties></Blob>`).join('') + '</Blobs><NextMarker/></EnumerationResults>');
      const hit = list.find(([n]) => n === decodeURIComponent(rest.join('/')));
      return bytes(req, hit[1]);
    }
    /* AWS */
    if (h.endsWith('.amazonaws.com')) {
      assert.match(req.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIASYNTHETIC0000001\//); assert.ok(req.headers['x-amz-content-sha256'] && req.headers['x-amz-date']);
      if (h === 's3.amazonaws.com') return xml('<ListAllMyBucketsResult><Owner><ID>synthetic-owner-id</ID><DisplayName>syn-owner</DisplayName></Owner><Buckets>'
        + '<Bucket><Name>syn-public-data</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate><BucketRegion>eu-west-1</BucketRegion></Bucket>'
        + '<Bucket><Name>syn-ksa-private</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket>'
        + '<Bucket><Name>syn-unknown</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>');
      const bucket = h.split('.s3')[0];
      if (bucket === 'syn-unknown') return err(403, 'AccessDenied', 'Access Denied');
      if (q.has('location')) return xml('<LocationConstraint>syn-ksa-1</LocationConstraint>');
      if (bucket === 'syn-public-data') {
        assert.equal(h, 'syn-public-data.s3.eu-west-1.amazonaws.com');
        if (q.has('publicAccessBlock')) return err(404, 'NoSuchPublicAccessBlockConfiguration', 'The public access block configuration was not found');
        if (q.has('policyStatus')) return xml('<PolicyStatus><IsPublic>true</IsPublic></PolicyStatus>');
        if (q.has('acl')) return xml('<AccessControlPolicy><AccessControlList><Grant><Grantee xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>');
        if (q.has('encryption')) return err(404, 'ServerSideEncryptionConfigurationNotFoundError', 'The server side encryption configuration was not found');
        if (q.get('list-type') === '2') return xml('<ListBucketResult><IsTruncated>false</IsTruncated>' + ['customers/ids.csv', 'finance/iban.txt', 'config/app-keys.txt', 'zz-beyond-limit.txt'].map((k) => `<Contents><Key>${k}</Key><Size>200</Size><LastModified>2026-11-01T00:00:00Z</LastModified></Contents>`).join('') + '</ListBucketResult>');
        return bytes(req, { '/customers/ids.csv': IDS, '/finance/iban.txt': IBAN, '/config/app-keys.txt': APIKEY }[u.pathname]);
      }
      if (bucket === 'syn-ksa-private') {
        assert.equal(h, 'syn-ksa-private.s3.syn-ksa-1.amazonaws.com');
        if (q.has('publicAccessBlock')) return xml('<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>');
        if (q.has('policyStatus')) return err(404, 'NoSuchBucketPolicy', 'The bucket policy does not exist');
        if (q.has('acl')) return xml('<AccessControlPolicy><AccessControlList><Grant><Grantee xsi:type="CanonicalUser"><ID>synthetic-owner-id</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>');
        if (q.has('encryption')) return xml('<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>arn:aws:kms:syn-ksa-1:000000000000:key/synthetic</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>');
        if (q.get('list-type') === '2') {
          const all = ['a.log', 'b.log', 'c.log', 'd.log', 'e.log'], start = q.get('continuation-token') ? 2 : 0, n = Number(q.get('max-keys')), page = all.slice(start, start + Math.min(n, 2));
          const more = start + page.length < all.length;
          return xml(`<ListBucketResult><IsTruncated>${more}</IsTruncated>${more ? '<NextContinuationToken>tok-' + (start + page.length) + '</NextContinuationToken>' : ''}` + page.map((k) => `<Contents><Key>${k}</Key><Size>10</Size><LastModified>2026-11-01T00:00:00Z</LastModified></Contents>`).join('') + '</ListBucketResult>');
        }
        if (u.pathname === '/a.log') return { status: 302, headers: { location: 'https://evil.example/x' }, body: '' };
        return bytes(req, 'plain log line');
      }
    }
    /* OCI */
    if (h === 'objectstorage.me-jeddah-1.oraclecloud.com') {
      const sig = /^Signature version="1",keyId="([^"]+)",algorithm="rsa-sha256",headers="date \(request-target\) host",signature="([^"]+)"$/.exec(req.headers.authorization);
      assert.ok(sig, 'OCI request signed'); assert.equal(sig[1], 'ocid1.tenancy.oc1..aaaasynthetictenancy/ocid1.user.oc1..aaaasyntheticuser01/' + FP);
      assert.ok(crypto.verify('sha256', Buffer.from(`date: ${req.headers.date}\n(request-target): get ${u.pathname}${u.search}\nhost: ${h}`), OCI_PUB, Buffer.from(sig[2], 'base64')), 'the signature verifies');
      if (u.pathname === '/n/') return json('synns');
      if (u.pathname === '/n/synns/b/') { assert.equal(q.get('compartmentId'), 'ocid1.compartment.oc1..aaaasyntheticcompartment'); return json([{ name: 'syn-oci-public' }, { name: 'syn-oci-private' }]); }
      if (u.pathname === '/n/synns/b/syn-oci-public') return json({ name: 'syn-oci-public', publicAccessType: 'ObjectRead', kmsKeyId: null });
      if (u.pathname === '/n/synns/b/syn-oci-private') return json({ name: 'syn-oci-private', publicAccessType: 'NoPublicAccess', kmsKeyId: 'ocid1.key.oc1..aaaasynthetickey' });
      if (u.pathname === '/n/synns/b/syn-oci-public/o') return json({ objects: [{ name: 'export/ids.json', size: 80, timeModified: '2026-11-01T00:00:00Z' }] });
      if (u.pathname === '/n/synns/b/syn-oci-private/o') return json({ objects: [{ name: 'readme.txt', size: 5 }] });
      if (u.pathname === '/n/synns/b/syn-oci-public/o/export%2Fids.json') return bytes(req, JSON.stringify({ ids: ['1000000021', '1000000022', '1000000023'] }));
      if (u.pathname === '/n/synns/b/syn-oci-private/o/readme.txt') return bytes(req, 'hello');
    }
    throw new Error('unexpected request in the stub: ' + req.method + ' ' + req.url);
  };
}
const FP = 'aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99';
// the coming credentials kinds (classify.js gains api_key etc.): emulated here when the real classifier does not yet report one,
// plus a kind the CATEGORY map does not know - both must flow through generically
const classify = Object.assign({}, realClassify, {
  CATEGORY: Object.assign({ api_key: 'credentials' }, realClassify.CATEGORY),
  classifyText(t) {
    const r = realClassify.classifyText(t), k = r.kinds;
    if (/SYNTHETIC-API-KEY-[0-9A-F]{16}/.test(t) && !Object.keys(k).some((x) => (realClassify.CATEGORY[x] || '') === 'credentials')) k.api_key = 1;
    if (/1000000021/.test(t)) k.brand_new_kind = 1;
    return r;
  },
});

const PROXY = 'P'.repeat(32);
const as = (role) => ({ 'X-Sentra-Proxy-Secret': PROXY, 'X-Auth-User': 'syn.' + role, 'X-Auth-Role': role });
function req(port, method, p, role, b) {
  return new Promise((ok, no) => {
    const data = b === undefined ? null : Buffer.from(JSON.stringify(b));
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: Object.assign({ 'Content-Type': 'application/json' }, data ? { 'Content-Length': data.length } : {}, as(role)) }, (res) => {
      let s = ''; res.on('data', (c) => { s += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(s); } catch (e) { j = null; } ok({ status: res.statusCode, json: j, raw: s }); });
    });
    r.on('error', no); if (data) r.write(data); r.end();
  });
}

test('end to end: not configured, settings + sealed credentials, scan of Azure / AWS / OCI, roles, audit, no secret anywhere', async () => {
  const sec = path.join(dir, 'secrets.json');
  SF.write(sec, { proxy_secret: PROXY, m365: { tenant: TENANT, client_id: APP, client_secret: M365_SECRET } });
  const config = { api_prefix: '/api/soc' };
  Object.defineProperty(config, 'secrets', { value: SF.read(sec), enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets: sec }, enumerable: false });
  const state = await createState({ dir: path.join(dir, 'state') });
  const audits = [], logs = [], calls = [], gate = {};
  const rec = (lvl) => (...a) => logs.push(lvl + ' ' + JSON.stringify(a));
  const log = { info: rec('info'), warn: rec('warn'), error: rec('error'), every: rec('every') };
  const api = createApi({ port: 0, audit: (e) => audits.push(e), proxySecret: PROXY, log });
  const deps = { state, config, log, noTimers: true, cloudHttp: providers(calls, gate), cloudClassify: classify };
  ROUTES.register(api, deps);
  const X = deps.cloudDataInstance, B = '/api/soc/cloud-data', responses = [];
  const call = async (...a) => { const r = await req(port, ...a); responses.push(r.raw); return r; };
  const { port } = await api.start();
  try {
    // nothing connected: an empty state that says what to connect, no fabricated row
    let r = await call('GET', B + '/stores', 'viewer');
    assert.equal(r.status, 200); assert.equal(r.json.configured, false); assert.match(r.json.note, /Connect Azure Blob Storage/); assert.deepEqual(r.json.stores, []);
    assert.deepEqual(r.json.providers.map((p) => p.provider), ['azure', 'aws', 'oci']);
    assert.equal((await call('POST', B + '/scan', 'operator', {})).status, 400, 'nothing to scan yet');

    // roles: settings and credentials are admin only, a scan needs an operator
    for (const role of ['viewer', 'analyst', 'operator']) {
      assert.equal((await call('GET', B + '/settings', role)).status, 403, role + ' cannot read the settings');
      assert.equal((await call('POST', B + '/settings', role, { schedule_hours: 1 })).status, 403);
      assert.equal((await call('POST', B + '/credentials', role, { provider: 'aws', access_key_id: AWS_KEY, secret_access_key: AWS_SECRET })).status, 403);
      assert.equal((await call('DELETE', B + '/credentials/aws', role)).status, 403);
      assert.equal((await call('POST', B + '/test', role, { provider: 'aws' })).status, 403);
    }
    for (const role of ['viewer', 'analyst']) assert.equal((await call('POST', B + '/scan', role, {})).status, 403, role + ' cannot start a scan');

    // validation errors name the field
    const bad = async (b, re, p = '/settings') => { const x = await call('POST', B + p, 'admin', b); assert.equal(x.status, 400, JSON.stringify(b)); assert.match(x.json.error, re); };
    await bad({ aws: { max_objects_per_store: 0 } }, /^aws\.max_objects_per_store must be at least 1/);
    await bad({ azure: { subscription_ids: ['not-a-guid'] } }, /^azure\.subscription_ids/);
    await bad({ azure: { accounts: [{ name: 'Bad_Name' }] } }, /^azure\.accounts\[0\]\.name/);
    await bad({ oci: { fingerprint: 'zz' } }, /^oci\.fingerprint/);
    await bad({ oci: { enabled: true, region: 'me-jeddah-1' } }, /^oci\.compartment_id is required/);
    await bad({ in_kingdom_regions: ['Riyadh City!'] }, /^in_kingdom_regions/);
    await bad({ schedule_hours: -1 }, /^schedule_hours must be at least 0/);
    await bad({ aws: 'yes' }, /^aws must be an object/);
    await bad({}, /nothing to change/);
    await bad({ provider: 'gcp' }, /^provider must be one of: azure, aws, oci/, '/credentials');
    await bad({ provider: 'aws', access_key_id: 'nope', secret_access_key: AWS_SECRET }, /^access_key_id/, '/credentials');
    await bad({ provider: 'aws', access_key_id: AWS_KEY }, /^secret_access_key is required/, '/credentials');
    await bad({ provider: 'azure', tenant_id: TENANT }, /^client_id is required/, '/credentials');
    await bad({ provider: 'oci', private_key_pem: 'not a key' }, /^private_key_pem/, '/credentials');
    await bad({ provider: 'oci', private_key_pem: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----' }, /^private_key_pem is not a readable PEM private key/, '/credentials');

    // settings (non-secret) and credentials (sealed)
    r = await call('POST', B + '/settings', 'admin', { in_kingdom_regions: ['syn-ksa-1', 'synksa'], schedule_hours: 24, mallory: 'x',
      azure: { enabled: true, use_m365_app: true },
      aws: { enabled: true, max_objects_per_store: 3, account_label: 'syn-aws' },
      oci: { enabled: true, region: 'me-jeddah-1', compartment_id: 'ocid1.compartment.oc1..aaaasyntheticcompartment', tenancy_id: 'ocid1.tenancy.oc1..aaaasynthetictenancy', user_id: 'ocid1.user.oc1..aaaasyntheticuser01', fingerprint: FP } });
    assert.equal(r.status, 200, r.raw);
    assert.ok(r.json.changed.includes('aws.max_objects_per_store') && r.json.changed.includes('in_kingdom_regions') && r.json.changed.includes('azure.use_m365_app'));
    assert.equal(r.json.settings.mallory, undefined, 'undeclared fields dropped');
    assert.deepEqual(r.json.in_kingdom_effective, ['me-jeddah-1', 'me-riyadh-1', 'syn-ksa-1', 'synksa']);
    assert.equal(r.json.m365_app_available, true);
    const setAudit = audits.find((a) => a.action === 'cloud-data.settings'); assert.equal(setAudit.by, 'syn.admin'); assert.equal(setAudit.role, 'admin'); assert.ok(setAudit.ip); assert.ok(setAudit.detail.changed.includes('oci.fingerprint'));

    assert.equal((await call('POST', B + '/credentials', 'admin', { provider: 'aws', access_key_id: AWS_KEY, secret_access_key: AWS_SECRET, extra: 'dropped' })).status, 200);
    r = await call('POST', B + '/credentials', 'admin', { provider: 'oci', private_key_pem: OCI_PEM });
    assert.equal(r.status, 200, r.raw); assert.equal(r.json.credentials.configured, true); assert.ok(r.json.credentials.set_at);
    const disk = fs.readFileSync(sec, 'utf8');
    assert.ok(SF.isSealed(JSON.parse(disk)), 'secrets.json sealed at rest');
    for (const s of [AWS_SECRET, AWS_KEY, OCI_PEM.split('\n')[1]]) assert.ok(!disk.includes(s), 'no credential in clear on disk');
    const stored = SF.read(sec);
    assert.equal(stored.cloud_data.aws.secret_access_key, AWS_SECRET); assert.equal(stored.cloud_data.aws.extra, undefined); assert.equal(stored.m365.client_secret, M365_SECRET, 'other secrets kept');
    const credAudit = audits.find((a) => a.action === 'cloud-data.credentials.set' && a.target === 'aws'); assert.deepEqual(credAudit.detail.fields, ['access_key_id', 'secret_access_key']);
    r = await call('GET', B + '/settings', 'admin');
    assert.deepEqual(Object.keys(r.json.credentials.aws).sort(), ['configured', 'set_at']); assert.equal(r.json.credentials.azure.configured, false, 'Azure needs no own secret: it reuses the Microsoft 365 app');

    // the test call: one read-only list per provider
    r = await call('POST', B + '/test', 'admin', { provider: 'aws' }); assert.deepEqual([r.json.ok, r.json.count, r.json.what], [true, 3, 'buckets']);
    r = await call('POST', B + '/test', 'admin', { provider: 'azure' }); assert.deepEqual([r.json.ok, r.json.count], [true, 2]);
    r = await call('POST', B + '/test', 'admin', { provider: 'oci' }); assert.deepEqual([r.json.ok, r.json.count], [true, 2]);
    assert.ok(audits.some((a) => a.action === 'cloud-data.test' && a.target === 'oci' && a.detail.ok === true));

    // a scan: one at a time
    let release; gate.wait = new Promise((ok) => { release = ok; });
    r = await call('POST', B + '/scan', 'operator', {});
    assert.equal(r.status, 200, r.raw); assert.deepEqual(r.json.providers, ['azure', 'aws', 'oci']); assert.equal(r.json.scan.by, 'syn.operator');
    r = await call('POST', B + '/scan', 'admin', {}); assert.equal(r.status, 409); assert.match(r.json.error, /already running/);
    r = await call('GET', B + '/stores', 'viewer'); assert.equal(r.json.scan.running, true);
    release(); gate.wait = null; await X.idle();
    assert.ok(audits.some((a) => a.action === 'cloud-data.scan' && a.by === 'syn.operator' && a.role === 'operator'));

    // read-only: every provider call is a GET, except the Entra sign-in; never a foreign host, never a redirect followed
    assert.deepEqual([...new Set(calls.filter((c) => c.method !== 'GET').map((c) => new URL(c.url).hostname))], ['login.microsoftonline.com']);
    assert.ok(!calls.some((c) => /evil\.example/.test(c.url)), 'no nextLink / redirect off the provider followed');

    r = await call('GET', B + '/stores', 'analyst');
    assert.equal(r.status, 200);
    const S = Object.fromEntries(r.json.stores.map((s) => [s.id, s]));
    // Azure: from Resource Manager, through the Microsoft 365 app
    const pubDocs = S['azure:synstorage01:public-docs'], hr = S['azure:synstorage01:hr'], arch = S['azure:synstorage02:archive'];
    assert.deepEqual([pubDocs.region, pubDocs.in_kingdom, pubDocs.public, pubDocs.public_why, pubDocs.encrypted, pubDocs.cmk], ['synksa', true, true, 'container public access: blob', true, true]);
    assert.equal(pubDocs.details.network_default_action, 'Allow'); assert.equal(pubDocs.details.location_source, 'arm');
    assert.deepEqual(pubDocs.kinds, { national_id: 1 }, 'the .docx text was read');
    assert.deepEqual(hr.kinds, { salary: 1 }, 'a file name alone counts (by name)'); assert.equal(hr.objects_scanned, 1, 'an empty object is not read');
    assert.deepEqual([arch.in_kingdom, arch.public, arch.cmk], [false, false, false]); assert.match(arch.public_why, /disallowed on the account/); assert.deepEqual(arch.categories, { financial: 1 });
    // AWS
    const pub = S['aws:syn-aws:syn-public-data'], priv = S['aws:syn-aws:syn-ksa-private'], unk = S['aws:syn-aws:syn-unknown'];
    assert.deepEqual([pub.region, pub.in_kingdom, pub.public, pub.encrypted], ['eu-west-1', false, true, false]);
    assert.equal(pub.public_why, 'bucket policy is public; ACL grants AllUsers');
    assert.deepEqual(pub.kinds, { national_id: 1, iban: 1, api_key: 1 }); assert.deepEqual(pub.categories, { identity: 1, financial: 1, credentials: 1 });
    assert.equal(pub.objects_seen, 3, 'max_objects_per_store = 3'); assert.equal(pub.truncated, true);
    assert.deepEqual([priv.region, priv.in_kingdom, priv.public, priv.encrypted, priv.cmk, priv.objects_seen, priv.truncated, priv.objects_with_findings], ['syn-ksa-1', true, false, true, true, 3, true, 0]);
    assert.equal(priv.objects_scanned, 2, 'the object that answered a redirect was not read');
    assert.deepEqual([unk.region, unk.in_kingdom, unk.public, unk.encrypted], [null, null, null, null], 'nothing readable: unknown, never guessed');
    assert.match(unk.error, /AccessDenied/);
    // OCI
    const op = S['oci:synns:syn-oci-public'], opr = S['oci:synns:syn-oci-private'];
    assert.deepEqual([op.region, op.in_kingdom, op.public, op.public_why, op.cmk], ['me-jeddah-1', true, true, 'OCI publicAccessType ObjectRead', false]);
    assert.deepEqual(op.categories, { identity: 1, other: 1 }, 'an unknown kind falls into "other"');
    assert.deepEqual([opr.public, opr.cmk, opr.encrypted], [false, true, true]);
    // totals and top objects
    const t = r.json.totals;
    assert.equal(t.stores, 8); assert.equal(t.public, 3); assert.equal(t.outside_kingdom, 2); assert.equal(t.unencrypted, 1);
    assert.equal(t.by_kind.national_id, 3); assert.equal(t.by_category.credentials, 1);
    const top = r.json.top_objects;
    assert.ok(Array.isArray(top) && top.length >= 6);
    assert.equal(top[0].exposure.score >= top[top.length - 1].exposure.score, true);
    const ids = top.find((o) => o.key === 'customers/ids.csv');
    assert.ok(ids.exposure.score >= 85 && ids.exposure.why.some((w) => /public/.test(w)) && ids.exposure.why.some((w) => /outside the Kingdom/.test(w)), JSON.stringify(ids.exposure));
    assert.deepEqual(ids.kinds, { national_id: 4 }, 'counts only');
    const p = r.json.providers.find((x) => x.provider === 'aws'); assert.equal(p.configured, true); assert.equal(p.error, null); assert.equal(p.stores, 3); assert.ok(p.last_ok);
    assert.equal(r.json.trend.length, 1);
    // never content: no matched value in any view or in state
    const all = r.raw + JSON.stringify(state.collection('cloud_data_stores').all());
    for (const v of ['1000000001', 'SA4420000001234567891234', 'SYNTHETIC-API-KEY', '1000000011']) assert.ok(!all.includes(v), 'no matched value kept: ' + v);

    // a viewer: counts and stores, no object names
    r = await call('GET', B + '/stores', 'viewer');
    assert.equal(r.json.top_objects.hidden, true); assert.equal(r.json.stores.length, 8); assert.ok(!r.raw.includes('customers/ids.csv'));
    assert.ok(audits.filter((a) => a.action === 'data.read' && a.target === B + '/stores').length >= 2, 'reads are audited');

    // delete credentials: OCI no longer configured; stores are kept until the next scan
    r = await call('DELETE', B + '/credentials/oci', 'admin'); assert.equal(r.status, 200);
    assert.equal(SF.read(sec).cloud_data.oci, undefined);
    assert.equal((await call('DELETE', B + '/credentials/oci', 'admin')).status, 404);
    assert.equal((await call('DELETE', B + '/credentials/gcp', 'admin')).status, 400);
    assert.ok(audits.some((a) => a.action === 'cloud-data.credentials.delete' && a.target === 'oci'));
    r = await call('POST', B + '/test', 'admin', { provider: 'oci' }); assert.equal(r.status, 400); assert.match(r.json.error, /no oci credentials/);

    // no credential in any response, audit record or log line
    const everything = responses.join('\n') + JSON.stringify(audits) + logs.join('\n');
    for (const s of [AWS_SECRET, M365_SECRET, 'SYNTHETIC-TOKEN-', OCI_PEM.split('\n')[1]]) assert.ok(!everything.includes(s), 'secret leaked: ' + s.slice(0, 12));
  } finally { await api.stop(); X.stop(); }
});

test('provider errors: a refused sign-in is reported with the provider message, scrubbed, and the scan goes on', async () => {
  const sd = path.join(dir, 'e2'); fs.mkdirSync(sd);
  const sec = path.join(sd, 'secrets.json'); SF.write(sec, {});
  const config = {}; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets: sec }, enumerable: false });
  const state = await createState({ dir: path.join(sd, 'state') });
  const AZ_SECRET = 'SYNTHETIC-OWN-APP-SECRET-1234';
  const X = CD.createCloudData({ config, state, httpRequest: async (q) => {
    if (/login\.microsoftonline/.test(q.url)) return { status: 401, headers: {}, body: JSON.stringify({ error: 'invalid_client', error_description: 'AADSTS7000215: Invalid client secret provided ' + AZ_SECRET }) };
    throw new Error('unexpected ' + q.url);
  } });
  X.saveSettings({ azure: { enabled: true } }, 'syn.admin');
  X.setCredentials('azure', { tenant_id: TENANT, client_id: APP, client_secret: AZ_SECRET });
  const t = await X.testProvider('azure');
  assert.equal(t.ok, false); assert.match(t.error, /invalid_client: AADSTS7000215/); assert.ok(!t.error.includes(AZ_SECRET), 'the secret is scrubbed from the provider message');
  X.startScan('syn.operator'); await X.idle();
  const v = X.view({ keys: true });
  assert.equal(v.providers[0].configured, true); assert.match(v.providers[0].error, /HTTP 401/); assert.equal(v.providers[0].last_ok, null);
  assert.ok(!JSON.stringify(v).includes(AZ_SECRET));
  // only the provider's own endpoints are reachable
  assert.ok(CD.HOSTS.azure.test('synacct.blob.core.windows.net') && !CD.HOSTS.azure.test('synacct.blob.core.windows.net.evil.example') && !CD.HOSTS.aws.test('s3.amazonaws.com.evil.example') && !CD.HOSTS.oci.test('evil.example'));
});

test('settings body: every field declared, nested errors name their place', () => {
  const b = ROUTES.settingsBody({ azure: { enabled: true, discover: false, accounts: [{ name: 'synacct', location: 'uaenorth', key: 'x' }], hacker: 1 }, schedule_hours: 0 });
  assert.deepEqual(b, { schedule_hours: 0, azure: { enabled: true, discover: false, accounts: [{ name: 'synacct', location: 'uaenorth' }] } });
  assert.throws(() => ROUTES.settingsBody({ aws: { regions: ['EU WEST'] } }), /aws\.regions\[0\]|aws\.regions/);
  assert.throws(() => ROUTES.settingsBody({ aws: { include: ['bad name;'] } }), /aws\.include/);
  const c = ROUTES.credentialsBody({ provider: 'azure', account_keys: [{ account: 'synacct', key: Buffer.alloc(64, 1).toString('base64') }] });
  assert.equal(c.value.account_keys[0].account, 'synacct');
  assert.throws(() => ROUTES.credentialsBody({ provider: 'azure', account_keys: [{ account: 'synacct', key: 'short' }] }), /account_keys\[0\]\.key/);
  assert.throws(() => ROUTES.credentialsBody({ provider: 'azure' }), /use_m365_app/);
  assert.equal(CD.exposureOf({ public: false, in_kingdom: true, encrypted: true }, {}, []).score, 0);
});
