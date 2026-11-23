// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Cloud object-store data discovery (Data Security Posture): READ-ONLY scan of Azure Blob Storage (first-class), AWS S3 and
 * Oracle Cloud Infrastructure Object Storage. No vendor SDK: node:https + node:crypto, every request signed here.
 * For each store (bucket / container) it records WHERE the data is (region → in the Kingdom true / false / null = not read,
 * never guessed), whether it is PUBLIC (and why) and ENCRYPTED (and whether with a customer-managed key), and, for objects
 * whose name is readable text or Office (.docx/.xlsx/.pptx), what kinds of personal data / credentials they hold - as COUNTS
 * per kind per object only (pii/classify.js). No content, no matched value is kept, logged or returned.
 *
 * Exactly these calls are made (all GET, except the Entra sign-in POST that obtains a token - it writes nothing):
 *   Azure (Entra client credentials; the SAME app registration as Microsoft 365 with use_m365_app, or its own):
 *     POST login.microsoftonline.com/<tenant>/oauth2/v2.0/token  scope https://management.azure.com/.default and
 *          https://storage.azure.com/.default (client_credentials; client secret or the M365 certificate assertion)
 *     GET  management.azure.com/subscriptions?api-version=2022-12-01                                 (list subscriptions)
 *     GET  management.azure.com/subscriptions/<id>/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01
 *          → name, location, allowBlobPublicAccess, minimumTlsVersion, encryption.keySource / services.blob.enabled,
 *            networkAcls.defaultAction, primaryEndpoints.blob                                         (nextLink paged)
 *     GET  <account>.blob.core.windows.net/?comp=list&maxresults=500                  (List Containers: PublicAccess)
 *     GET  <account>.blob.core.windows.net/<container>?restype=container&comp=list&maxresults=1000   (List Blobs, paged)
 *     GET  <account>.blob.core.windows.net/<container>/<blob>  x-ms-range: bytes=0-2097151           (Get Blob, first 2 MB)
 *     With an account key instead (SharedKey signing): only the three blob calls; region from the typed account location,
 *     else "not read"; public access at account level and encryption are then not read (null).
 *   AWS (Signature V4, access key + secret [+ session token]):
 *     GET s3.amazonaws.com/  (ListBuckets, paged)            GET <bucket>/?location (GetBucketLocation)
 *     GET <bucket>/?publicAccessBlock (GetPublicAccessBlock)  GET <bucket>/?policyStatus (GetBucketPolicyStatus)
 *     GET <bucket>/?acl (GetBucketAcl: grants to AllUsers / AuthenticatedUsers)   GET <bucket>/?encryption (GetBucketEncryption)
 *     GET <bucket>/?list-type=2 (ListObjectsV2, paged)        GET <bucket>/<key> Range: bytes=0-2097151 (GetObject)
 *   OCI (API-key request signing, rsa-sha256; tenancy / user OCID + fingerprint are settings, the PEM key is the secret):
 *     GET objectstorage.<region>.oraclecloud.com/n/ (GetNamespace, when not set)   GET /n/<ns>/b/?compartmentId=… (ListBuckets)
 *     GET /n/<ns>/b/<bucket> (GetBucket: publicAccessType, kmsKeyId)   GET /n/<ns>/b/<bucket>/o (ListObjects, paged)
 *     GET /n/<ns>/b/<bucket>/o/<object>  Range: bytes=0-2097151 (GetObject)
 *
 * Least privilege to grant (read only; nothing here needs more):
 *   Azure: "Reader" on the subscriptions (Azure Resource Manager discovery) + "Storage Blob Data Reader" on the storage
 *          accounts (or the subscription) for the Entra app - with use_m365_app, assign both roles to the Microsoft 365 app
 *          registration the SIEM already uses; no second secret. An account key grants FULL (write) access: prefer Entra.
 *   AWS:   an IAM user / role with only s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketPublicAccessBlock,
 *          s3:GetBucketPolicyStatus, s3:GetBucketAcl, s3:GetEncryptionConfiguration, s3:ListBucket, s3:GetObject
 *          (+ kms:Decrypt on the keys of SSE-KMS buckets to read their objects).
 *   OCI:   Allow group <siem-readers> to read buckets in compartment <c>
 *          Allow group <siem-readers> to read objects in compartment <c>
 *
 * Bounds: 30 s per request, never a redirect (3xx is an error; paging links are followed only on the provider's own host),
 *   host allow-list per provider, max_objects_per_store listed (default 2000), max_bytes_per_scan read per provider
 *   (default 256 MB), 2 MB per object, at most 500 stores per provider, page caps, 4 objects read at a time.
 * Results: state collections cloud_data_stores (latest snapshot per store), cloud_data_runs (last 60 runs, for the trend),
 *   cloud_data_meta (settings + per-provider last scan). Credentials: secrets.json → cloud_data.<provider>, sealed at rest
 *   (secretfile.js); never returned, never logged, never in an audit record; errors are scrubbed of them.
 */
const crypto = require('node:crypto');
const https = require('node:https');
const SF = require('../secretfile');
const { HttpError } = require('../soc/routeutil');

const PROVIDERS = ['azure', 'aws', 'oci'];
const DEFAULT_IN_KINGDOM = ['me-jeddah-1', 'me-riyadh-1'];
const OBJ_BYTES = 2 * 1024 * 1024, LIST_BYTES = 8 * 1024 * 1024, TIMEOUT_MS = 30000, CONCURRENCY = 4;
const MAX_STORES = 500, RUNS_KEPT = 60, TOP_PER_STORE = 25, TOP_TOTAL = 100;
const DEF = { max_objects_per_store: 2000, max_bytes_per_scan: 256 * 1024 * 1024 };
const HOSTS = {
  aws: /^([a-z0-9.-]+\.)?s3([.-][a-z0-9-]+)*\.amazonaws\.com$/,
  azure: /^(login\.microsoftonline\.com|management\.azure\.com|[a-z0-9]{3,24}\.blob\.core\.windows\.net)$/,
  oci: /^objectstorage\.[a-z0-9-]+\.oraclecloud\.com$/,
};
const ACS = 'http://acs.amazonaws.com/groups/global/';

/* ------------------------------------------------------------------ helpers */
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const hmac = (k, s) => crypto.createHmac('sha256', k).update(s).digest();
const enc = (s) => encodeURIComponent(String(s)).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const encPath = (p) => String(p).split('/').map(enc).join('/');
const ENT = { lt: '<', gt: '>', amp: '&', quot: '"', apos: '\'' };
const xmlDecode = (s) => String(s).replace(/&(#x[0-9a-f]+|#\d+|lt|gt|amp|quot|apos);/gi, (m, e) => (e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : ENT[e.toLowerCase()]));
const tags = (xml, t) => [...String(xml || '').matchAll(new RegExp(`<${t}(?:\\s[^>]*)?>([\\s\\S]*?)</${t}>`, 'g'))].map((m) => m[1]);
const tag1 = (xml, t) => { const a = tags(xml, t); return a.length ? xmlDecode(a[0]).trim() : null; };
const glob = (g) => new RegExp('^' + String(g).split('*').map((x) => x.replace(/[.+?^${}()|[\]\\/]/g, '\\$&')).join('.*') + '$', 'i');
function selected(names, s) {
  const inc = (s.include || []).map(glob), exc = (s.exclude || []).map(glob);
  if (inc.length && !names.some((n) => inc.some((r) => r.test(n)))) return false;
  return !names.some((n) => exc.some((r) => r.test(n)));
}
function scrubber(secrets) {
  const vals = secrets.filter((v) => typeof v === 'string' && v.length >= 6);
  return (msg) => { let m = String(msg || ''); for (const v of vals) m = m.split(v).join('[redacted]'); return m.replace(/(sig|signature|Signature|token|key)=([^&\s"]{8,})/g, '$1=[redacted]').slice(0, 300); };
}
async function pool(items, n, fn) {
  let i = 0;
  const run = async () => { while (i < items.length) { const k = i++; await fn(items[k], k); } };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, run));
}
const perr = (msg, status) => Object.assign(new Error(msg), { provider: true, httpStatus: status || 0 });

/* ------------------------------------------------------------------ signing */
/* AWS Signature Version 4. headers: the headers to send (all are signed; host is added). query: [[k, v], …] or {k: v}. */
function sigv4({ method = 'GET', host, path = '/', query = [], headers = {}, payloadHash, region, service = 's3', accessKeyId, secretAccessKey, sessionToken, amzDate }) {
  const date = amzDate || new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''), day = date.slice(0, 8);
  const h = { host };
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = String(v);
  h['x-amz-date'] = date;
  if (sessionToken) h['x-amz-security-token'] = sessionToken;
  const q = (Array.isArray(query) ? query : Object.entries(query)).map(([k, v]) => [enc(k), enc(v === undefined || v === null ? '' : v)]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1));
  const qs = q.map(([k, v]) => k + '=' + v).join('&');
  const names = Object.keys(h).sort(), signed = names.join(';');
  const canon = [method, encPath(path), qs, names.map((n) => n + ':' + h[n].trim().replace(/\s+/g, ' ') + '\n').join(''), signed, payloadHash || h['x-amz-content-sha256'] || sha256('')].join('\n');
  const scope = `${day}/${region}/${service}/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', date, scope, sha256(canon)].join('\n');
  const kSign = hmac(hmac(hmac(hmac('AWS4' + secretAccessKey, day), region), service), 'aws4_request');
  const signature = crypto.createHmac('sha256', kSign).update(sts).digest('hex');
  h.authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${signature}`;
  delete h.host;
  return { headers: h, canonicalRequest: canon, stringToSign: sts, signature, pathQuery: encPath(path) + (qs ? '?' + qs : '') };
}

/* Azure Storage SharedKey (version 2009-09-19 and later). pathEnc: the URL path as sent; query: {k: v} (decoded values). */
function azureStringToSign({ method = 'GET', account, pathEnc = '/', query = {}, headers = {} }) {
  const lc = {}; for (const [k, v] of Object.entries(headers)) lc[k.toLowerCase()] = String(v);
  const std = ['content-encoding', 'content-language', 'content-length', 'content-md5', 'content-type', 'date', 'if-modified-since', 'if-match', 'if-none-match', 'if-unmodified-since', 'range']
    .map((k) => (k === 'content-length' && lc[k] === '0' ? '' : lc[k] || ''));
  const xms = Object.keys(lc).filter((k) => k.startsWith('x-ms-')).sort().map((k) => k + ':' + lc[k].trim().replace(/\s+/g, ' ') + '\n').join('');
  const qk = Object.keys(query).map((k) => [k.toLowerCase(), query[k]]).sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const res = '/' + account + pathEnc + qk.map(([k, v]) => '\n' + k + ':' + (Array.isArray(v) ? v.slice().sort().join(',') : v)).join('');
  return [method, ...std].join('\n') + '\n' + xms + res;
}
function azureSharedKey(o) {
  const sts = azureStringToSign(o);
  return { stringToSign: sts, authorization: `SharedKey ${o.account}:${crypto.createHmac('sha256', Buffer.from(o.key, 'base64')).update(sts, 'utf8').digest('base64')}` };
}

/* OCI API request signing (draft-cavage HTTP signatures, rsa-sha256) for a GET: date (request-target) host */
function ociSign({ method = 'GET', host, pathQuery, keyId, privateKey, passphrase, date }) {
  const d = date || new Date().toUTCString();
  const signing = `date: ${d}\n(request-target): ${method.toLowerCase()} ${pathQuery}\nhost: ${host}`;
  const key = typeof privateKey === 'string' ? crypto.createPrivateKey({ key: privateKey, passphrase: passphrase || undefined }) : privateKey;
  const sig = crypto.sign('sha256', Buffer.from(signing), key).toString('base64');
  return { signingString: signing, headers: { date: d, authorization: `Signature version="1",keyId="${keyId}",algorithm="rsa-sha256",headers="date (request-target) host",signature="${sig}"` } };
}

/* ------------------------------------------------------------------ HTTP */
/* the default transport: https only, no redirect followed, a timeout, at most maxBytes kept */
function defaultHttp({ method, url, headers, body, timeoutMs = TIMEOUT_MS, maxBytes = LIST_BYTES }) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (u.protocol !== 'https:') { reject(new Error('https only')); return; }
    let done = false;
    const finish = (err, v) => { if (done) return; done = true; clearTimeout(deadline); if (err) reject(err); else resolve(v); };
    const req = https.request({ method, hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, headers }, (res) => {
      const chunks = []; let n = 0;
      res.on('data', (c) => {
        if (n >= maxBytes) return;
        const take = Math.min(c.length, maxBytes - n); chunks.push(take < c.length ? c.subarray(0, take) : c); n += take;
        if (n >= maxBytes) { finish(null, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), truncated: true }); res.destroy(); }
      });
      res.on('end', () => finish(null, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', (e) => finish(e));
    });
    const deadline = setTimeout(() => { req.destroy(new Error('timed out after ' + Math.round(timeoutMs / 1000) + ' s')); }, timeoutMs);
    req.on('error', (e) => finish(e));
    if (body) req.write(body);
    req.end();
  });
}
/* every request of a provider goes through here: host allow-list, no redirect, bounded, errors with the provider's message */
function transport(provider, httpRequest, scrub) {
  const call = httpRequest || defaultHttp;
  return async function request(o) {
    const u = new URL(o.url);
    if (u.protocol !== 'https:' || !HOSTS[provider].test(u.hostname)) throw perr(`refused: ${u.hostname} is not a ${provider} storage endpoint`);
    let r;
    try { r = await call({ method: o.method || 'GET', url: o.url, headers: o.headers || {}, body: o.body, timeoutMs: o.timeoutMs || TIMEOUT_MS, maxBytes: o.maxBytes || LIST_BYTES }); }
    catch (e) { throw perr(`${u.hostname}: ${scrub(e && e.message)}`); }
    const body = Buffer.isBuffer(r.body) ? r.body : Buffer.from(r.body === undefined || r.body === null ? '' : typeof r.body === 'string' ? r.body : JSON.stringify(r.body));
    const res = { status: r.status, headers: lower(r.headers), body, text: () => body.toString('utf8'), json: () => { try { return JSON.parse(body.toString('utf8').replace(/^﻿/, '')); } catch (e) { return null; /* not JSON: the caller reports the HTTP status */ } } };
    if (res.status >= 300 && res.status < 400) throw perr(`${u.hostname} answered a redirect (HTTP ${res.status}) - not followed`, res.status);
    if (res.status >= 400 && !(o.ok || []).includes(res.status)) throw perr(`${u.hostname}: HTTP ${res.status} ${scrub(errText(res))}`.trim(), res.status);
    return res;
  };
}
const lower = (h) => { const o = {}; for (const [k, v] of Object.entries(h || {})) o[k.toLowerCase()] = v; return o; };
function errText(res) {
  const t = res.text();
  const code = tag1(t, 'Code'), msg = tag1(t, 'Message');
  if (code || msg) return [code, msg].filter(Boolean).join(': ');
  const j = res.json();
  if (j && typeof j.error === 'object') return [j.error.code, j.error.message].filter(Boolean).join(': ');
  if (j && typeof j.error === 'string') return j.error + (j.error_description ? ': ' + String(j.error_description).split('\n')[0] : '');
  if (j && (j.code || j.message)) return [j.code, j.message].filter(Boolean).join(': ');
  return '';
}

/* ------------------------------------------------------------------ AWS S3 */
function awsClient({ creds, settings, request }) {
  const sign = (o) => sigv4(Object.assign({ accessKeyId: creds.access_key_id, secretAccessKey: creds.secret_access_key, sessionToken: creds.session_token, service: 's3' }, o));
  // virtual-hosted style; a bucket with a dot in its name uses path style (the TLS wildcard covers one label)
  const where = (bucket, region) => {
    const base = region && region !== 'us-east-1' ? `s3.${region}.amazonaws.com` : 's3.amazonaws.com';
    return bucket.includes('.') ? { host: base, prefix: '/' + bucket } : { host: `${bucket}.${base}`, prefix: '' };
  };
  async function get({ bucket, region, path = '/', query = [], headers = {}, ok, maxBytes }) {
    const w = bucket ? where(bucket, region) : { host: 's3.amazonaws.com', prefix: '' };
    const p = (w.prefix + (path === '/' && w.prefix ? '' : path)) || '/';
    const s = sign({ host: w.host, path: p, query, region: region || 'us-east-1', headers: Object.assign({ 'x-amz-content-sha256': sha256('') }, headers) });
    return request({ url: `https://${w.host}${s.pathQuery}`, headers: s.headers, ok, maxBytes });
  }
  async function listBuckets() {
    const out = []; let token = '';
    for (let page = 0; page < 10; page++) {
      const q = [['max-buckets', '1000']]; if (token) q.push(['continuation-token', token]);
      const x = (await get({ query: q })).text();
      const owner = tag1(tag1raw(x, 'Owner'), 'DisplayName') || tag1(tag1raw(x, 'Owner'), 'ID');
      for (const b of tags(x, 'Bucket')) out.push({ name: tag1(b, 'Name'), created: tag1(b, 'CreationDate'), region: tag1(b, 'BucketRegion'), owner });
      token = tag1(x, 'ContinuationToken') || '';
      if (!token) break;
    }
    return out;
  }
  async function storeOf(b) {
    let region = b.region || null;
    if (!region) {
      try { const x = (await get({ bucket: b.name, query: [['location', '']] })).text(); const c = tag1(x, 'LocationConstraint'); region = !c ? 'us-east-1' : c === 'EU' ? 'eu-west-1' : c; }
      catch (e) { region = null; /* not readable: region stays "not read", the bucket is still scanned through us-east-1 */ }
    }
    const opt = async (query, missing) => { try { const r = await get({ bucket: b.name, region, query, ok: [404] }); return r.status === 404 ? (errText(r).startsWith(missing) ? { none: true } : null) : { x: r.text() }; } catch (e) { return null; /* access denied / unreadable: unknown, never guessed */ } };
    const pab = await opt([['publicAccessBlock', '']], 'NoSuchPublicAccessBlockConfiguration');
    const pol = await opt([['policyStatus', '']], 'NoSuchBucketPolicy');
    const acl = await opt([['acl', '']], '__never__');
    const encr = await opt([['encryption', '']], 'ServerSideEncryptionConfigurationNotFoundError');
    const flag = (k) => (pab && pab.x ? tag1(pab.x, k) === 'true' : pab && pab.none ? false : null);
    const restrict = flag('RestrictPublicBuckets'), ignoreAcl = flag('IgnorePublicAcls');
    const why = [];
    let polPublic = pol ? (pol.none ? false : tag1(pol.x, 'IsPublic') === 'true') : null;
    if (polPublic && restrict === true) polPublic = false;
    if (polPublic) why.push('bucket policy is public');
    let aclPublic = null;
    if (acl && acl.x) {
      const grants = tags(acl.x, 'Grant').filter((g) => tag1(g, 'URI') && tag1(g, 'URI').startsWith(ACS));
      const groups = [...new Set(grants.map((g) => tag1(g, 'URI').slice(ACS.length)).filter((u) => u === 'AllUsers' || u === 'AuthenticatedUsers'))];
      aclPublic = groups.length > 0 && ignoreAcl !== true;
      if (aclPublic) groups.forEach((g) => why.push('ACL grants ' + g));
    }
    const pub = polPublic || aclPublic ? true : polPublic === false && aclPublic === false ? false : null;
    let encrypted = null, cmk = null;
    if (encr && encr.none) { encrypted = false; cmk = false; }
    else if (encr && encr.x) {
      const alg = tag1(encr.x, 'SSEAlgorithm'), kid = tag1(encr.x, 'KMSMasterKeyID');
      encrypted = !!alg; cmk = !!(alg && alg.startsWith('aws:kms') && kid && !/alias\/aws\/s3$/.test(kid));
    }
    return { provider: 'aws', account: settings.account_label || b.owner || 'aws', name: b.name, region, public: pub, public_why: why.length ? why.join('; ') : null, encrypted, cmk, _bucket: b.name };
  }
  async function listObjects(st, max) {
    const items = []; let token = '', truncated = false;
    for (let page = 0; page < Math.ceil(max / 1000) + 1; page++) {
      const q = [['list-type', '2'], ['max-keys', String(Math.min(1000, max - items.length))]]; if (token) q.push(['continuation-token', token]);
      const x = (await get({ bucket: st._bucket, region: st.region, query: q })).text();
      for (const c of tags(x, 'Contents')) items.push({ key: tag1(c, 'Key'), size: Number(tag1(c, 'Size')) || 0, modified: tag1(c, 'LastModified') });
      token = tag1(x, 'IsTruncated') === 'true' ? tag1(x, 'NextContinuationToken') || '' : '';
      if (!token) break;
      if (items.length >= max) { truncated = true; break; }
    }
    if ((token || items.length > max) && !truncated) truncated = true;
    return { items: items.slice(0, max), truncated };
  }
  const getObject = async (st, o, n) => (await get({ bucket: st._bucket, region: st.region, path: '/' + o.key, headers: { range: `bytes=0-${n - 1}` }, maxBytes: n })).body;
  async function stores() {
    const list = await listBuckets(), out = [];
    for (const b of list.slice(0, MAX_STORES)) {
      if (!selected([b.name], settings)) continue;
      const st = await storeOf(b);
      if ((settings.regions || []).length && !(settings.regions || []).includes(st.region)) continue;
      out.push(st);
    }
    return out;
  }
  return { stores, listObjects, getObject, test: async () => ({ count: (await listBuckets()).length, what: 'buckets' }) };
}
const tag1raw = (xml, t) => { const a = tags(xml, t); return a.length ? a[0] : ''; };

/* ------------------------------------------------------------------ Azure (ARM + Blob) */
const AZ_VER = '2023-11-03', ARM = 'https://management.azure.com';
function azureClient({ auth, settings, request, now }) {
  const tokens = {};
  async function token(scope) {
    const t = tokens[scope]; if (t && now() < t.exp - 300000) return t.v;
    const form = new URLSearchParams({ grant_type: 'client_credentials', client_id: auth.clientId, scope: scope + '/.default' });
    if (auth.certPem && auth.keyPem) {
      form.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      form.set('client_assertion', require('./m365').makeAssertion({ tenant: auth.tenant, clientId: auth.clientId, certPem: auth.certPem, keyPem: auth.keyPem, passphrase: auth.passphrase, authority: 'https://login.microsoftonline.com', nowMs: now() }));
    } else form.set('client_secret', auth.secret);
    const r = await request({ method: 'POST', url: `https://login.microsoftonline.com/${encodeURIComponent(auth.tenant)}/oauth2/v2.0/token`, headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    const j = r.json();
    if (!j || !j.access_token) throw perr('sign-in to Microsoft Entra ID failed: no token returned');
    tokens[scope] = { v: j.access_token, exp: now() + (Number(j.expires_in) || 3599) * 1000 };
    return j.access_token;
  }
  async function arm(path) {
    const out = []; let url = ARM + path;
    for (let page = 0; page < 20 && url; page++) {
      const j = (await request({ url, headers: { authorization: 'Bearer ' + await token('https://management.azure.com'), accept: 'application/json' } })).json() || {};
      out.push(...(Array.isArray(j.value) ? j.value : []));
      url = typeof j.nextLink === 'string' && j.nextLink.startsWith(ARM + '/') ? j.nextLink : '';   // never follow a link off ARM with the token
    }
    return out;
  }
  async function blob(account, pathEnc, query, extra = {}, maxBytes) {
    const host = `${account}.blob.core.windows.net`, qs = Object.entries(query).map(([k, v]) => enc(k) + '=' + enc(v)).join('&');
    const headers = Object.assign({ 'x-ms-version': AZ_VER, 'x-ms-date': new Date(now()).toUTCString() }, extra);
    if (auth.kind === 'entra') headers.authorization = 'Bearer ' + await token('https://storage.azure.com');
    else {
      const key = (auth.keys || {})[account];
      if (!key) throw perr(`no account key stored for ${account}`);
      headers.authorization = azureSharedKey({ method: 'GET', account, pathEnc, query, headers, key }).authorization;
    }
    return request({ url: `https://${host}${pathEnc}${qs ? '?' + qs : ''}`, headers, maxBytes });
  }
  // the storage accounts: from Azure Resource Manager (Reader) - location, public access, encryption come from Azure itself
  async function accounts() {
    const typed = new Map((settings.accounts || []).map((a) => [a.name, a]));
    const out = new Map();
    if (auth.kind === 'entra' && settings.discover !== false) {
      let subs = (settings.subscription_ids || []).slice();
      if (!subs.length) subs = (await arm('/subscriptions?api-version=2022-12-01')).filter((s) => !s.state || s.state === 'Enabled').map((s) => s.subscriptionId);
      for (const sid of subs.slice(0, 50)) {
        for (const a of await arm(`/subscriptions/${encodeURIComponent(sid)}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01`)) {
          const p = a.properties || {}, e = p.encryption || {}, blobEnc = ((e.services || {}).blob || {});
          if (!/^[a-z0-9]{3,24}$/.test(String(a.name || ''))) continue;
          out.set(a.name, { name: a.name, subscription: sid, location: a.location ? String(a.location).toLowerCase() : null, source: 'arm',
            allow_public: typeof p.allowBlobPublicAccess === 'boolean' ? p.allowBlobPublicAccess : null, min_tls: p.minimumTlsVersion || null,
            network_default: (p.networkAcls && p.networkAcls.defaultAction) || null,
            encrypted: typeof blobEnc.enabled === 'boolean' ? blobEnc.enabled : null, cmk: e.keySource ? e.keySource === 'Microsoft.Keyvault' : null });
        }
      }
    }
    for (const [name, a] of typed) if (!out.has(name)) out.set(name, { name, location: a.location || null, source: 'typed', allow_public: null, min_tls: null, network_default: null, encrypted: null, cmk: null });
    if (auth.kind === 'sharedkey') for (const name of Object.keys(auth.keys || {})) if (!out.has(name)) out.set(name, { name, location: null, source: 'typed', allow_public: null, min_tls: null, network_default: null, encrypted: null, cmk: null });
    return [...out.values()];
  }
  async function containers(account) {
    const out = []; let marker = '';
    for (let page = 0; page < 10; page++) {
      const q = { comp: 'list', maxresults: '500' }; if (marker) q.marker = marker;
      const x = (await blob(account, '/', q)).text();
      for (const c of tags(x, 'Container')) out.push({ name: tag1(c, 'Name'), access: tag1(c, 'PublicAccess') });
      marker = tag1(x, 'NextMarker') || '';
      if (!marker) break;
    }
    return out;
  }
  async function stores() {
    const out = [];
    for (const a of await accounts()) {
      if ((settings.regions || []).length && !(settings.regions || []).includes(a.location)) continue;
      let list;
      try { list = await containers(a.name); }
      catch (e) { out.push(base(a, null, { error: e.message })); continue; }
      for (const c of list) {
        if (out.length >= MAX_STORES) break;
        if (!selected([c.name, a.name + '/' + c.name, a.name], settings)) continue;
        out.push(base(a, c));
      }
    }
    return out;
  }
  function base(a, c, extra) {
    let pub = false, why = null;
    if (c && c.access) {
      if (a.allow_public === false) { pub = false; why = `container public access: ${c.access}, but anonymous access is disallowed on the account`; }
      else if (a.allow_public === true) { pub = true; why = `container public access: ${c.access}`; }
      else { pub = null; why = `container public access: ${c.access}; the account-level setting was not read`; }
    }
    return Object.assign({ provider: 'azure', account: a.name, name: c ? c.name : '(account)', region: a.location, public: pub, public_why: why, encrypted: a.encrypted, cmk: a.cmk,
      details: { subscription: a.subscription || null, location_source: a.location ? a.source : 'not read', min_tls: a.min_tls, network_default_action: a.network_default, allow_blob_public_access: a.allow_public },
      _account: a.name, _container: c ? c.name : null }, extra || {});
  }
  async function listObjects(st, max) {
    const items = []; let marker = '', truncated = false;
    for (let page = 0; page < Math.ceil(max / 1000) + 1; page++) {
      const q = { restype: 'container', comp: 'list', maxresults: String(Math.min(1000, max - items.length)) }; if (marker) q.marker = marker;
      const x = (await blob(st._account, '/' + enc(st._container), q)).text();
      for (const b of tags(x, 'Blob')) items.push({ key: tag1(b, 'Name'), size: Number(tag1(b, 'Content-Length')) || 0, modified: tag1(b, 'Last-Modified') });
      marker = tag1(x, 'NextMarker') || '';
      if (!marker) break;
      if (items.length >= max) { truncated = true; break; }
    }
    if ((marker || items.length > max) && !truncated) truncated = true;
    return { items: items.slice(0, max), truncated };
  }
  const getObject = async (st, o, n) => (await blob(st._account, '/' + enc(st._container) + '/' + encPath(o.key), {}, { 'x-ms-range': `bytes=0-${n - 1}` }, n)).body;
  async function test() {
    if (auth.kind === 'entra' && settings.discover !== false) { const a = await accounts(); return { count: a.length, what: 'storage accounts' }; }
    const a = await accounts(); if (!a.length) throw perr('no storage account to test: add one under Azure accounts');
    return { count: (await containers(a[0].name)).length, what: 'containers in ' + a[0].name };
  }
  return { stores, listObjects, getObject, test };
}

/* ------------------------------------------------------------------ OCI Object Storage */
function ociClient({ creds, settings, request }) {
  const keyId = `${settings.tenancy_id}/${settings.user_id}/${settings.fingerprint}`;
  const pk = crypto.createPrivateKey({ key: creds.private_key_pem, passphrase: creds.passphrase || undefined });
  async function get(region, pathQuery, extra = {}, o = {}) {
    const host = `objectstorage.${region}.oraclecloud.com`;
    const s = ociSign({ host, pathQuery, keyId, privateKey: pk });
    return request(Object.assign({ url: `https://${host}${pathQuery}`, headers: Object.assign({ accept: 'application/json' }, extra, s.headers) }, o));
  }
  const regions = () => [...new Set([settings.region].concat(settings.regions || []).filter(Boolean))];
  const nsCache = {};
  async function ns(region) {
    if (settings.namespace) return settings.namespace;
    if (!nsCache[region]) { const j = (await get(region, '/n/')).json(); if (typeof j !== 'string' || !j) throw perr('the namespace could not be read'); nsCache[region] = j; }
    return nsCache[region];
  }
  async function buckets(region) {
    const n = await ns(region), out = []; let page = '';
    for (let i = 0; i < 10; i++) {
      const r = await get(region, `/n/${enc(n)}/b/?compartmentId=${enc(settings.compartment_id)}&limit=1000${page ? '&page=' + enc(page) : ''}`);
      out.push(...(r.json() || []));
      page = r.headers['opc-next-page'] || '';
      if (!page) break;
    }
    return { n, list: out };
  }
  async function stores() {
    const out = [];
    for (const region of regions()) {
      const { n, list } = await buckets(region);
      for (const b of list) {
        if (out.length >= MAX_STORES) break;
        if (!b || !b.name || !selected([b.name], settings)) continue;
        let d = null;
        try { d = (await get(region, `/n/${enc(n)}/b/${enc(b.name)}`)).json(); } catch (e) { d = null; /* GetBucket refused: public access stays "not read" */ }
        const pat = d && d.publicAccessType;
        out.push({ provider: 'oci', account: n, name: b.name, region, public: pat ? pat !== 'NoPublicAccess' : null, public_why: pat && pat !== 'NoPublicAccess' ? 'OCI publicAccessType ' + pat : null,
          // OCI Object Storage always encrypts at rest (AES-256, Oracle-managed key unless a Vault key is set): a platform fact, not a guess
          encrypted: true, cmk: d ? !!d.kmsKeyId : null, details: { encryption: 'always on (Oracle Object Storage)' }, _ns: n, _region: region, _bucket: b.name });
      }
    }
    return out;
  }
  async function listObjects(st, max) {
    const items = []; let start = '', truncated = false;
    for (let page = 0; page < Math.ceil(max / 1000) + 1; page++) {
      const j = (await get(st._region, `/n/${enc(st._ns)}/b/${enc(st._bucket)}/o?limit=${Math.min(1000, max - items.length)}&fields=name,size,timeModified${start ? '&start=' + enc(start) : ''}`)).json() || {};
      for (const o of j.objects || []) items.push({ key: o.name, size: Number(o.size) || 0, modified: o.timeModified || null });
      start = j.nextStartWith || '';
      if (!start) break;
      if (items.length >= max) { truncated = true; break; }
    }
    if ((start || items.length > max) && !truncated) truncated = true;
    return { items: items.slice(0, max), truncated };
  }
  const getObject = async (st, o, n) => (await get(st._region, `/n/${enc(st._ns)}/b/${enc(st._bucket)}/o/${enc(o.key)}`, { range: `bytes=0-${n - 1}` }, { maxBytes: n })).body;
  const test = async () => { const r = settings.region; const { list } = await buckets(r); return { count: list.length, what: 'buckets in ' + r }; };
  return { stores, listObjects, getObject, test };
}

/* ------------------------------------------------------------------ the engine */
function exposureOf(store, kinds, cats) {
  let s = 0; const why = [];
  if (store.public === true) { s += 50; why.push('the store is public' + (store.public_why ? ' (' + store.public_why + ')' : '')); }
  else if (store.public === null) { s += 10; why.push('public access not read'); }
  if (store.in_kingdom === false) { s += 15; why.push('stored outside the Kingdom (' + store.region + ')'); }
  else if (store.in_kingdom === null) { s += 5; why.push('region not read'); }
  if (store.encrypted === false) { s += 10; why.push('no encryption at rest configured'); }
  const sens = { credentials: 25, financial: 20, identity: 20, health: 20, employment: 10, contact: 10 };
  const top = Math.max(0, ...cats.map((c) => sens[c] || 10));
  if (top) { s += top; why.push('holds ' + cats.join(', ') + ' data'); }
  const n = Object.values(kinds).reduce((a, b) => a + b, 0);
  if (n >= 100) { s += 10; why.push(n + ' matches in the first 2 MB'); }
  return { score: Math.min(100, s), why };
}

function createCloudData({ config = {}, state, log, now = Date.now, httpRequest, classify, secretsPath } = {}) {
  if (!state) throw new Error('cloud data discovery needs state');
  const C = classify || require('../pii/classify');
  const L = log || { info() {}, warn() {}, error() {}, every() {} };
  const stores = state.collection('cloud_data_stores'), runs = state.collection('cloud_data_runs'), meta = state.collection('cloud_data_meta');
  const secPath = () => secretsPath || (config._paths && config._paths.secrets);
  const secrets = () => (config.secrets && config.secrets.cloud_data) || {};
  let scan = { running: false, started: null, by: null, progress: null }, current = null;

  /* ---- settings (non-secret; state) */
  function settings() {
    const s = Object.assign({}, (meta.get('settings') || {}).s || {});
    for (const p of PROVIDERS) s[p] = Object.assign({ enabled: false, regions: [], include: [], exclude: [], max_objects_per_store: DEF.max_objects_per_store, max_bytes_per_scan: DEF.max_bytes_per_scan }, p === 'azure' ? { use_m365_app: false, discover: true, subscription_ids: [], accounts: [] } : {}, s[p] || {});
    s.in_kingdom_regions = s.in_kingdom_regions || [];
    s.schedule_hours = s.schedule_hours === undefined ? 0 : s.schedule_hours;
    return s;
  }
  const inKingdomList = (s) => [...new Set(DEFAULT_IN_KINGDOM.concat(s.in_kingdom_regions || []))];
  function saveSettings(patch, by) {
    const cur = settings(), next = JSON.parse(JSON.stringify(cur)), changed = [];
    for (const [k, v] of Object.entries(patch)) {
      if (PROVIDERS.includes(k)) { for (const [f, x] of Object.entries(v)) if (JSON.stringify(cur[k][f]) !== JSON.stringify(x)) { next[k][f] = x; changed.push(k + '.' + f); } }
      else if (JSON.stringify(cur[k]) !== JSON.stringify(v)) { next[k] = v; changed.push(k); }
    }
    if (next.oci.enabled) {
      const miss = ['region', 'compartment_id', 'tenancy_id', 'user_id', 'fingerprint'].filter((f) => !next.oci[f]);
      if (miss.length) throw new HttpError(400, 'oci.' + miss[0] + ' is required to enable OCI');
    }
    meta.put({ id: 'settings', s: next, updated: now(), by: by || '' });
    return { changed, settings: next };
  }

  /* ---- credentials (secrets.json, sealed) */
  function writeSecret(provider, value) {
    const p = secPath();
    if (!p) throw new HttpError(503, 'the secrets file path is unknown - the engine was not started with a secrets.json');
    let sec = {}; try { sec = SF.read(p) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    sec.cloud_data = Object.assign({}, sec.cloud_data || {});
    if (value === null) delete sec.cloud_data[provider]; else sec.cloud_data[provider] = Object.assign({}, value, { set_at: new Date(now()).toISOString() });
    require('../onboard/store').writeJsonAtomic(p, sec);   // sealed at rest (secretfile.js), no plaintext .bak
    if (!config.secrets) Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
    config.secrets.cloud_data = sec.cloud_data;
  }
  function setCredentials(provider, value) {
    if (provider === 'oci') {
      try { crypto.createPrivateKey({ key: value.private_key_pem, passphrase: value.passphrase || undefined }); }
      catch (e) { throw new HttpError(400, 'private_key_pem is not a readable PEM private key (or the passphrase is wrong)'); }
    }
    writeSecret(provider, value);
    return credentialsView()[provider];
  }
  function deleteCredentials(provider) { if (!secrets()[provider]) throw new HttpError(404, 'no ' + provider + ' credentials stored'); writeSecret(provider, null); return { removed: provider }; }
  function m365App() { const c = require('./m365-graph').credsOf(config); return c.errs.length ? null : c; }
  function azureAuth(s) {
    if (s.azure.use_m365_app) { const c = m365App(); return c ? { kind: 'entra', source: 'm365', tenant: c.tenant, clientId: c.clientId, secret: c.secret, certPem: c.certPem, keyPem: c.keyPem, passphrase: c.passphrase } : null; }
    const z = secrets().azure || {};
    if (z.client_secret && z.tenant_id && z.client_id) return { kind: 'entra', source: 'own', tenant: z.tenant_id, clientId: z.client_id, secret: z.client_secret };
    if (Array.isArray(z.account_keys) && z.account_keys.length) return { kind: 'sharedkey', keys: Object.fromEntries(z.account_keys.map((k) => [k.account, k.key])) };
    return null;
  }
  const hasCreds = (p, s) => (p === 'azure' ? !!azureAuth(s) : !!secrets()[p]);
  function credentialsView() {
    const out = {};
    for (const p of PROVIDERS) { const x = secrets()[p]; out[p] = { configured: !!x, set_at: (x && x.set_at) || null }; }
    return out;
  }
  function secretValues() {
    const v = [];
    for (const x of Object.values(secrets())) for (const [k, y] of Object.entries(x || {})) { if (k === 'account_keys' && Array.isArray(y)) y.forEach((a) => v.push(a.key)); else if (k !== 'set_at' && typeof y === 'string' && !/^(tenant_id|client_id)$/.test(k)) v.push(y); }
    const m = config.secrets && config.secrets.m365; if (m) v.push(m.client_secret, m.key_passphrase);
    return v;
  }
  function client(p, s) {
    const scrub = scrubber(secretValues()), request = transport(p, httpRequest, scrub);
    if (p === 'aws') return { scrub, c: awsClient({ creds: secrets().aws, settings: s.aws, request }) };
    if (p === 'azure') return { scrub, c: azureClient({ auth: azureAuth(s), settings: s.azure, request, now }) };
    return { scrub, c: ociClient({ creds: secrets().oci, settings: s.oci, request }) };
  }

  /* ---- scanning */
  function classifyObject(o, buf) {
    const kinds = {}, by = [];
    if (buf) { const t = C.textOf(o.key, buf); if (t) { const r = C.classifyText(t); for (const [k, n] of Object.entries(r.kinds || {})) kinds[k] = n; if (Object.keys(r.kinds || {}).length) by.push('content'); } }
    const nk = C.classifyName(o.key) || [];
    for (const k of nk) if (!kinds[k]) kinds[k] = 1;
    if (nk.length) by.push('name');
    const cats = [...new Set(Object.keys(kinds).map((k) => (C.CATEGORY && C.CATEGORY[k]) || 'other'))];
    return { kinds, cats, by };
  }
  async function scanStore(p, cli, st, s, budget) {
    const ps = s[p], max = ps.max_objects_per_store || DEF.max_objects_per_store;
    const rec = Object.assign({}, st, { id: [p, st.account, st.name].join(':'), in_kingdom: st.region ? inKingdomList(s).includes(st.region) : null, objects_seen: 0, objects_scanned: 0, objects_with_findings: 0, objects_skipped: 0, kinds: {}, categories: {}, truncated: false, last_scan: new Date(now()).toISOString(), error: st.error || null, top: [] });
    for (const k of Object.keys(rec)) if (k.startsWith('_')) delete rec[k];
    if (!st.error) {
      try {
        const { items, truncated } = await cli.listObjects(st, max);
        rec.objects_seen = items.length; rec.truncated = truncated;
        const found = [];
        await pool(items, CONCURRENCY, async (o) => {
          let buf = null;
          if (C.readable(o.key) && o.size > 0) {
            const n = Math.min(OBJ_BYTES, o.size);
            if (budget.left < n) { rec.objects_skipped++; rec.truncated = true; }
            else {
              budget.left -= n;
              try { buf = await cli.getObject(st, o, n); rec.objects_scanned++; scan.progress.objects_scanned++; }
              catch (e) { rec.objects_skipped++; L.every('cloud-data-object-' + p, 600000, 'warn', 'cloud data: an object could not be read', { provider: p, store: rec.id, err: e.message }); }
            }
          }
          const r = classifyObject(o, buf);
          if (!Object.keys(r.kinds).length) return;
          rec.objects_with_findings++;
          for (const k of Object.keys(r.kinds)) rec.kinds[k] = (rec.kinds[k] || 0) + 1;
          for (const c of r.cats) rec.categories[c] = (rec.categories[c] || 0) + 1;
          found.push({ o, r });
        });
        rec.top = found.map(({ o, r }) => ({ store_id: rec.id, key: String(o.key).slice(0, 1024), size: o.size, modified: o.modified, kinds: r.kinds, categories: r.cats, by: r.by, exposure: exposureOf(rec, r.kinds, r.cats) }))
          .sort((a, b) => b.exposure.score - a.exposure.score).slice(0, TOP_PER_STORE);
      } catch (e) { rec.error = e.message; }
    }
    return rec;
  }
  async function scanProvider(p, s) {
    const at = new Date(now()).toISOString(), budget = { left: s[p].max_bytes_per_scan || DEF.max_bytes_per_scan };
    let res;
    try {
      const { c } = client(p, s), list = await c.stores();
      scan.progress.stores_total += list.length;
      const keep = new Set();
      for (const st of list) {
        const rec = await scanStore(p, c, st, s, budget);
        stores.put(rec); keep.add(rec.id); scan.progress.stores_done++;
      }
      for (const old of stores.all((x) => x.provider === p && !keep.has(x.id))) stores.remove(old.id);   // gone from the account
      res = { last_scan: at, last_ok: at, error: null, stores: keep.size };
    } catch (e) {
      const msg = e && e.provider ? e.message : 'internal error (recorded)';
      if (!(e && e.provider)) L.error('cloud data scan failed', { provider: p, err: e && e.message });
      else L.every('cloud-data-' + p, 3600000, 'warn', 'cloud data: provider scan failed', { provider: p, err: msg });
      const prev = (meta.get('providers') || {})[p] || {};
      res = { last_scan: at, last_ok: prev.last_ok || null, error: msg, stores: stores.all((x) => x.provider === p).length };
    }
    meta.patch('providers', (m) => { m[p] = res; return m; }) || meta.put({ id: 'providers', [p]: res });
    return res;
  }
  function startScan(by) {
    if (scan.running) throw new HttpError(409, 'a scan is already running (started ' + scan.started + ' by ' + scan.by + ')');
    const s = settings(), list = PROVIDERS.filter((p) => s[p].enabled && hasCreds(p, s));
    if (!list.length) throw new HttpError(400, 'nothing to scan: enable a provider and store its credentials first');
    scan = { running: true, started: new Date(now()).toISOString(), by: by || 'schedule', progress: { provider: null, providers: list, stores_done: 0, stores_total: 0, objects_scanned: 0 } };
    current = (async () => {
      const out = {};
      try {
        for (const p of list) { scan.progress.provider = p; out[p] = await scanProvider(p, s); }
        const t = totals(stores.all());
        runs.put({ id: 'run-' + now(), at: scan.started, finished: new Date(now()).toISOString(), by: scan.by, providers: out, totals: t });
        const old = runs.all().sort((a, b) => String(a.at).localeCompare(String(b.at)));
        for (const r of old.slice(0, Math.max(0, old.length - RUNS_KEPT))) runs.remove(r.id);
        meta.put(Object.assign({}, meta.get('schedule') || {}, { id: 'schedule', last_run: now() }));
        L.info('cloud data scan finished', { by: scan.by, providers: list, stores: t.stores, objects_scanned: t.objects_scanned });
        return out;
      } finally { scan = { running: false, started: null, by: null, progress: null }; }
    })();
    current.catch((e) => L.error('cloud data scan failed', { err: e && e.message }));
    return { started: true, providers: list, scan: Object.assign({}, scan, { progress: Object.assign({}, scan.progress) }) };
  }
  async function testProvider(p) {
    const s = settings();
    if (!hasCreds(p, s)) throw new HttpError(400, p === 'azure' && s.azure.use_m365_app ? 'the Microsoft 365 app registration is not configured (Microsoft 365 settings)' : 'no ' + p + ' credentials stored');
    if (p === 'oci') { const miss = ['region', 'compartment_id', 'tenancy_id', 'user_id', 'fingerprint'].filter((f) => !s.oci[f]); if (miss.length) throw new HttpError(400, 'oci.' + miss[0] + ' is required'); }
    try { const { c } = client(p, s), r = await c.test(); return { ok: true, provider: p, count: r.count, what: r.what }; }
    catch (e) { if (!(e && e.provider)) throw e; return { ok: false, provider: p, error: e.message }; }
  }

  /* ---- views */
  function totals(list) {
    const t = { stores: list.length, public: 0, outside_kingdom: 0, unencrypted: 0, objects_scanned: 0, objects_with_findings: 0, by_category: {}, by_kind: {} };
    for (const x of list) {
      if (x.public === true) t.public++; if (x.in_kingdom === false) t.outside_kingdom++; if (x.encrypted === false) t.unencrypted++;
      t.objects_scanned += x.objects_scanned || 0; t.objects_with_findings += x.objects_with_findings || 0;
      for (const [k, n] of Object.entries(x.kinds || {})) t.by_kind[k] = (t.by_kind[k] || 0) + n;
      for (const [k, n] of Object.entries(x.categories || {})) t.by_category[k] = (t.by_category[k] || 0) + n;
    }
    return t;
  }
  const NOTE = 'No cloud storage is connected. Connect Azure Blob Storage (reuse the Microsoft 365 app registration with the "Reader" and "Storage Blob Data Reader" roles, or an Entra app of its own), AWS S3 (a read-only IAM access key) or OCI Object Storage (an API key with read buckets / read objects) under Data Security Posture → Settings, then run a scan.';
  function view({ keys }) {
    const s = settings(), pm = meta.get('providers') || {}, list = stores.all().sort((a, b) => a.id.localeCompare(b.id));
    const providers = PROVIDERS.map((p) => ({ provider: p, configured: !!(s[p].enabled && hasCreds(p, s)), last_scan: (pm[p] || {}).last_scan || null, last_ok: (pm[p] || {}).last_ok || null, error: (pm[p] || {}).error || null, stores: list.filter((x) => x.provider === p).length }));
    const configured = providers.some((x) => x.configured);
    const out = {
      configured, note: configured ? null : NOTE, providers,
      stores: list.map((x) => ({ id: x.id, provider: x.provider, account: x.account, name: x.name, region: x.region, in_kingdom: x.in_kingdom, public: x.public, public_why: x.public_why, encrypted: x.encrypted, cmk: x.cmk,
        objects_seen: x.objects_seen, objects_scanned: x.objects_scanned, objects_with_findings: x.objects_with_findings, kinds: x.kinds, categories: x.categories, truncated: x.truncated, error: x.error || null, details: x.details || null, last_scan: x.last_scan })),
      totals: totals(list),
      top_objects: keys ? list.flatMap((x) => x.top || []).sort((a, b) => b.exposure.score - a.exposure.score).slice(0, TOP_TOTAL) : { hidden: true, reason: 'object names are shown to analysts and above' },
      trend: runs.all().sort((a, b) => String(a.at).localeCompare(String(b.at))).slice(-30).map((r) => ({ at: r.at, stores: r.totals.stores, public: r.totals.public, outside_kingdom: r.totals.outside_kingdom, objects_with_findings: r.totals.objects_with_findings })),
      scan: Object.assign({}, scan, { progress: scan.progress ? Object.assign({}, scan.progress) : null }),
    };
    return out;
  }
  function settingsView() {
    const s = settings(), m = m365App();
    return { settings: s, in_kingdom_effective: inKingdomList(s), in_kingdom_defaults: DEFAULT_IN_KINGDOM, m365_app_available: !!m, credentials: credentialsView(), providers: PROVIDERS };
  }

  /* ---- schedule: guard('cloud-data.scan'), rescheduled in finally */
  let timer = null;
  function schedule(guardFn) {
    const tick = guardFn('cloud-data.scan', async () => {
      try {
        const s = settings(), h = s.schedule_hours, last = (meta.get('schedule') || {}).last_run || 0;
        if (h > 0 && !scan.running && now() - last >= h * 3600000 && PROVIDERS.some((p) => s[p].enabled && hasCreds(p, s))) {
          const r = startScan('schedule');
          if (typeof state.audit === 'function') state.audit({ by: 'schedule', role: 'system', ip: '', action: 'cloud-data.scan', target: 'scheduled', detail: { providers: r.providers, every_hours: h } });
          await current;
        }
      } finally { timer = setTimeout(tick, 10 * 60000); if (timer.unref) timer.unref(); }
    });
    timer = setTimeout(tick, 5 * 60000); if (timer.unref) timer.unref();
  }
  const stop = () => { if (timer) clearTimeout(timer); timer = null; };

  return { settings, saveSettings, setCredentials, deleteCredentials, credentialsView, startScan, testProvider, view, settingsView, schedule, stop, idle: () => current || Promise.resolve(), isRunning: () => scan.running };
}

module.exports = { createCloudData, sigv4, azureStringToSign, azureSharedKey, ociSign, defaultHttp, exposureOf, PROVIDERS, DEFAULT_IN_KINGDOM, HOSTS };
