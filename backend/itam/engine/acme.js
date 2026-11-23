// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * ACME client (RFC 8555) - Let's Encrypt, or a commercial CA's ACME service (DigiCert, Sectigo) with External Account
 * Binding. Node.js crypto + https only. The account key is EC P-256 (ES256 JWS); the caller keeps it SEALED.
 * Steps, each one short so a request can be advanced over several calls (validation can take minutes):
 *   account(dir, {accountKeyPem, contact, eab})            → {kid}
 *   newOrder(names)                                        → {url, authorizations, finalize, status}
 *   authorizations(order)                                  → [{name, status, challenges:{http01, dns01}}]
 *       http-01: token + keyAuthorization (served at /.well-known/acme-challenge/<token>)
 *       dns-01 : TXT value for _acme-challenge.<name>
 *   respond(challengeUrl) · poll(url) · finalize(order, csrDer) · download(certUrl) → PEM chain
 * Only https directory URLs. A badNonce is retried once.
 */
const https = require('node:https');
const crypto = require('node:crypto');

const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ub64u = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

function request(url, { method = 'GET', body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(url); } catch (e) { return reject(new Error('invalid ACME URL')); }
    if (u.protocol !== 'https:') return reject(new Error('the ACME server must use HTTPS'));
    const r = https.request({ method, hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, timeout: 20000,
      headers: Object.assign({ 'User-Agent': 'sentra-itam-acme/1', Accept: 'application/json, application/pem-certificate-chain' }, body ? { 'Content-Type': 'application/jose+json', 'Content-Length': Buffer.byteLength(body) } : {}, headers) }, (res) => {
      let d = ''; res.setEncoding('utf8'); res.on('data', (c) => { d += c; if (d.length > 2e6) r.destroy(new Error('ACME answer too large')); });
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch (e) { /* PEM or empty */ } resolve({ status: res.statusCode, headers: res.headers, json: j, text: d }); });
    });
    r.on('timeout', () => r.destroy(new Error('ACME server timeout'))); r.on('error', reject);
    if (body) r.write(body); r.end();
  });
}
const acmeErr = (res, what) => Object.assign(new Error(what + ': ' + String((res.json && (res.json.detail || res.json.type)) || ('HTTP ' + res.status)).slice(0, 300)), { status: res.status, acmeType: res.json && res.json.type });

function jwkOf(keyObj) { const j = crypto.createPublicKey(keyObj).export({ format: 'jwk' }); return { crv: j.crv, kty: j.kty, x: j.x, y: j.y }; }
function thumbprint(jwk) { return b64u(crypto.createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest()); }
function newAccountKey() { return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' }); }

function createAcme(directoryUrl, { accountKeyPem, kid: knownKid, request: req = request } = {}) {
  const key = crypto.createPrivateKey(accountKeyPem), jwk = jwkOf(key), thumb = thumbprint(jwk);
  let dir = null, nonce = null, kid = knownKid || null;
  async function directory() { if (dir) return dir; const r = await req(directoryUrl); if (r.status !== 200 || !r.json || !r.json.newOrder) throw acmeErr(r, 'ACME directory not readable'); dir = r.json; return dir; }
  async function getNonce() { if (nonce) { const n = nonce; nonce = null; return n; } const d = await directory(); const r = await req(d.newNonce, { method: 'HEAD' }); if (!r.headers['replay-nonce']) throw acmeErr(r, 'no nonce from the ACME server'); return r.headers['replay-nonce']; }
  function jws(url, payload, n, useJwk) {
    const prot = { alg: 'ES256', nonce: n, url }; if (useJwk || !kid) prot.jwk = jwk; else prot.kid = kid;
    const p = b64u(JSON.stringify(prot)), pl = payload === '' ? '' : b64u(JSON.stringify(payload));
    const sig = crypto.sign('sha256', Buffer.from(p + '.' + pl), { key, dsaEncoding: 'ieee-p1363' });
    return JSON.stringify({ protected: p, payload: pl, signature: b64u(sig) });
  }
  async function post(url, payload, useJwk, retried) {
    const r = await req(url, { method: 'POST', body: jws(url, payload, await getNonce(), useJwk) });
    if (r.headers['replay-nonce']) nonce = r.headers['replay-nonce'];
    if (r.status === 400 && r.json && /badNonce/.test(r.json.type || '') && !retried) return post(url, payload, useJwk, true);
    return r;
  }
  async function account({ contact, eab } = {}) {
    if (kid) return { kid };
    const d = await directory();
    const payload = { termsOfServiceAgreed: true }; if (contact) payload.contact = ['mailto:' + contact];
    if (eab && eab.kid && eab.hmac) {   // External Account Binding: the account key, MAC-ed with the CA's HMAC key (HS256)
      const p = b64u(JSON.stringify({ alg: 'HS256', kid: eab.kid, url: d.newAccount })), pl = b64u(JSON.stringify(jwk));
      payload.externalAccountBinding = { protected: p, payload: pl, signature: b64u(crypto.createHmac('sha256', ub64u(eab.hmac)).update(p + '.' + pl).digest()) };
    }
    const r = await post(d.newAccount, payload, true);
    if (r.status !== 200 && r.status !== 201) throw acmeErr(r, 'ACME account refused');
    kid = r.headers.location; if (!kid) throw new Error('the ACME server gave no account URL');
    return { kid };
  }
  async function newOrder(names) {
    const d = await directory();
    const r = await post(d.newOrder, { identifiers: names.map((n) => ({ type: 'dns', value: n })) });
    if (r.status !== 201) throw acmeErr(r, 'ACME order refused');
    return Object.assign({ url: r.headers.location }, r.json);
  }
  const getAs = async (url) => { const r = await post(url, ''); if (r.status !== 200) throw acmeErr(r, 'ACME read failed'); return r; };
  async function authorizations(order) {
    const out = [];
    for (const u of order.authorizations || []) {
      const a = (await getAs(u)).json, ch = {};
      for (const c of a.challenges || []) {
        if (!/^[A-Za-z0-9_-]{16,}$/.test(String(c.token || ''))) continue;   // the token becomes a file name: strict
        const ka = c.token + '.' + thumb;
        if (c.type === 'http-01') ch.http01 = { url: c.url, token: c.token, keyAuthorization: ka, status: c.status };
        if (c.type === 'dns-01') ch.dns01 = { url: c.url, token: c.token, txt: b64u(crypto.createHash('sha256').update(ka).digest()), status: c.status };
      }
      out.push({ url: u, name: (a.wildcard ? '*.' : '') + (a.identifier && a.identifier.value), wildcard: !!a.wildcard,   /* RFC 8555 reports a wildcard without its *. */ status: a.status, challenges: ch });
    }
    return out;
  }
  async function respond(challengeUrl) { const r = await post(challengeUrl, {}); if (r.status !== 200) throw acmeErr(r, 'ACME challenge refused'); return r.json; }
  async function poll(url) { return (await getAs(url)).json; }
  async function finalize(order, csrDer) {
    const r = await post(order.finalize, { csr: b64u(csrDer) });
    if (r.status !== 200) throw acmeErr(r, 'ACME finalize refused');
    return Object.assign({ url: order.url }, r.json);
  }
  async function download(certUrl) { const r = await post(certUrl, ''); if (r.status !== 200 || !/BEGIN CERTIFICATE/.test(r.text)) throw acmeErr(r, 'ACME certificate download failed'); return r.text; }
  return { account, newOrder, authorizations, respond, poll, finalize, download, thumbprint: thumb, get kid() { return kid; } };
}

module.exports = { createAcme, newAccountKey, thumbprint, jwkOf, b64u, request };
