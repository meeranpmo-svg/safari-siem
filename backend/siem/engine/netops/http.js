// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Read-only HTTPS client for device APIs (FortiOS, PAN-OS, Genian NAC, EdgeConnect Orchestrator). Node stdlib.
 *   getRaw(url, { headers, timeoutMs=10000, tls:{ ca, fingerprint256, insecure } , maxBytes=8MB }) → {status, text, json}
 * TLS: devices usually present self-signed certificates. Prefer `fingerprint256` (pin the device certificate's SHA-256,
 * "AA:BB:…" as shown by the browser) or `ca` (PEM). `insecure: true` skips verification and is reported on the device.
 * Only GET; redirects are not followed; the URL must be https:// unless `allow_http` is set (lab only).
 */
const https = require('node:https');
const http = require('node:http');
const tls = require('node:tls');

function normFp(fp) { return String(fp || '').replace(/[^0-9a-f]/gi, '').toUpperCase(); }

function getRaw(url, opts = {}) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(url); } catch (e) { return reject(new Error('bad URL')); }
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && opts.allow_http)) return reject(new Error('device APIs must use https'));
    const t = opts.tls || {}, pin = normFp(t.fingerprint256);
    const lib = u.protocol === 'https:' ? https : http;
    const o = { method: opts.method === 'POST' ? 'POST' : 'GET', headers: Object.assign({ Accept: 'application/json, text/xml;q=0.9, */*;q=0.5', 'User-Agent': 'sentra-siem-netops/1' }, opts.headers || {}), timeout: opts.timeoutMs || 10000 };
    if (lib === https) {
      o.ca = t.ca || undefined;
      o.rejectUnauthorized = !(t.insecure || pin); // a pinned certificate is checked below instead of the CA chain
      if (pin) o.checkServerIdentity = (host, cert) => (normFp(cert.fingerprint256) === pin ? undefined : new Error('device certificate does not match the pinned fingerprint'));
      o.agent = false;
    }
    const req = lib.request(u, o, (res) => {
      if (lib === https && pin) { const c = res.socket.getPeerCertificate(); if (!c || normFp(c.fingerprint256) !== pin) { req.destroy(new Error('device certificate does not match the pinned fingerprint')); return; } }
      const max = opts.maxBytes || 8 * 1048576; let size = 0; const chunks = [];
      res.on('data', (c) => { size += c.length; if (size > max) { req.destroy(new Error('response too large')); return; } chunks.push(c); });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8'); let json = null;
        if (/json/i.test(res.headers['content-type'] || '') || /^\s*[[{]/.test(text)) { try { json = JSON.parse(text); } catch (e) { json = null; } }
        resolve({ status: res.statusCode, text, json });
      });
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    // a pinned device gets nothing - no header, no API key - until its certificate has been compared with the pin
    if (lib === https && pin) req.on('socket', (sock) => sock.once('secureConnect', () => { const c = sock.getPeerCertificate(); if (!c || normFp(c.fingerprint256) !== pin) { req.destroy(new Error('device certificate does not match the pinned fingerprint')); return; } req.end(opts.body); }));
    else req.end(opts.body);   // a body only for POST (Cisco UCS XML API); GET sends none
  });
}

async function getJSON(url, opts) {
  const r = await getRaw(url, opts);
  if (r.status === 401 || r.status === 403) throw new Error('API refused the credentials (HTTP ' + r.status + ')');
  if (r.status !== 200) throw new Error('HTTP ' + r.status);
  if (r.json === null) throw new Error('response is not JSON');
  return r.json;
}

module.exports = { getRaw, getJSON, normFp, _tls: tls };
