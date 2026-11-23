// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AWS Signature Version 4 (stdlib crypto). Implements the documented algorithm:
//   canonical request = METHOD \n canonicalURI \n canonicalQuery \n canonicalHeaders \n signedHeaders \n hex(sha256(payload))
//   string to sign    = "AWS4-HMAC-SHA256" \n amzDate \n scope \n hex(sha256(canonical request))
//   signing key       = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
// Verified in tests against the AWS documentation / aws-sig-v4-test-suite vectors (get-vanilla, IAM ListUsers example).
//   sign({method, url, headers, body, region, service, accessKeyId, secretAccessKey, sessionToken?, amzDate?})
//     → {headers (with Authorization, X-Amz-Date, host…), canonicalRequest, stringToSign, signature}
const crypto = require('node:crypto');

const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hmac = (k, s) => crypto.createHmac('sha256', k).update(s).digest();
// RFC 3986 encoding as AWS requires (unreserved: A-Z a-z 0-9 - _ . ~)
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

function canonicalQuery(searchParams) {
  const pairs = [];
  for (const [k, v] of searchParams) pairs.push([enc(k), enc(v)]);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
}
function canonicalUri(pathname) {
  return (pathname || '/').split('/').map((seg) => enc(decodeURIComponent(seg))).join('/') || '/';
}
function signingKey(secret, date, region, service) {
  return hmac(hmac(hmac(hmac('AWS4' + secret, date), region), service), 'aws4_request');
}

function sign(o) {
  const u = new URL(o.url);
  const amzDate = o.amzDate || new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = amzDate.slice(0, 8);
  const body = o.body === undefined || o.body === null ? '' : o.body;
  const headers = {};
  for (const [k, v] of Object.entries(o.headers || {})) headers[k.toLowerCase()] = String(v).trim().replace(/\s+/g, ' ');
  if (!headers.host) headers.host = u.host;
  headers['x-amz-date'] = amzDate;
  if (o.sessionToken) headers['x-amz-security-token'] = o.sessionToken;
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((n) => `${n}:${headers[n]}\n`).join('');
  const signedHeaders = names.join(';');
  const payloadHash = sha256hex(body);
  const canonicalRequest = [String(o.method || 'GET').toUpperCase(), canonicalUri(u.pathname), canonicalQuery(u.searchParams), canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${date}/${o.region}/${o.service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');
  const signature = crypto.createHmac('sha256', signingKey(o.secretAccessKey, date, o.region, o.service)).update(stringToSign).digest('hex');
  const out = Object.assign({}, o.headers || {}, { 'X-Amz-Date': amzDate, Authorization: `AWS4-HMAC-SHA256 Credential=${o.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` });
  if (o.sessionToken) out['X-Amz-Security-Token'] = o.sessionToken;
  return { headers: out, canonicalRequest, stringToSign, signature, signedHeaders };
}

module.exports = { sign, signingKey, canonicalQuery, canonicalUri, sha256hex };
