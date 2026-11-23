// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Read-only HTTPS client shared by the security-API connectors (Zscaler ZIA/ZPA, Kaspersky KSC OpenAPI).
 * Unlike netops/http.js (GET only) these vendor APIs authenticate and read with POST, so POST is allowed - but the
 * CONNECTORS decide which paths are ever called, exactly as the PAN-OS collector whitelists only <show> commands.
 *   request({ url, method='GET', headers, body, tls:{ca, fingerprint256, insecure}, timeoutMs=15000, maxBytes=8MB })
 *     → { status, headers, text, json, cookie }   (cookie = the set-cookie values joined "name=value; …")
 * TLS: cloud APIs present a valid certificate (verified by default); an on-prem KSC usually presents a self-signed one,
 * so prefer fingerprint256 (pin its SHA-256) over insecure. Nothing here can change anything on the vendor side.
 */
const https = require('node:https');
const http = require('node:http');

function normFp(fp) { return String(fp || '').replace(/[^0-9a-f]/gi, '').toUpperCase(); }

function request(opts = {}) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(opts.url); } catch (e) { return reject(new Error('bad URL')); }
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && opts.allow_http)) return reject(new Error('security APIs must use https'));
    const t = opts.tls || {}, pin = normFp(t.fingerprint256);
    const lib = u.protocol === 'https:' ? https : http;
    const data = opts.body == null ? null : (typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body));
    const headers = Object.assign({ Accept: 'application/json', 'User-Agent': 'sentra-siem-secops/1' }, opts.headers || {});
    if (data != null && !headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'application/json';
    if (data != null) headers['Content-Length'] = Buffer.byteLength(data);
    const o = { method: opts.method || 'GET', headers, timeout: opts.timeoutMs || 15000 };
    if (lib === https) {
      o.ca = t.ca || undefined;
      o.rejectUnauthorized = !(t.insecure || pin);               // a pinned certificate is checked below instead of the CA chain
      if (pin) o.checkServerIdentity = (host, cert) => (normFp(cert.fingerprint256) === pin ? undefined : new Error('certificate does not match the pinned fingerprint'));
      o.agent = false;
    }
    const req = lib.request(u, o, (res) => {
      if (lib === https && pin) { const c = res.socket.getPeerCertificate(); if (!c || normFp(c.fingerprint256) !== pin) { req.destroy(new Error('certificate does not match the pinned fingerprint')); return; } }
      const max = opts.maxBytes || 8 * 1048576; let size = 0; const chunks = [];
      res.on('data', (c) => { size += c.length; if (size > max) { req.destroy(new Error('response too large')); return; } chunks.push(c); });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8'); let json = null;
        if (/json/i.test(res.headers['content-type'] || '') || /^\s*[[{]/.test(text)) { try { json = JSON.parse(text); } catch (e) { json = null; } }
        const sc = res.headers['set-cookie']; const cookie = sc ? (Array.isArray(sc) ? sc : [sc]).map((c) => String(c).split(';')[0]).join('; ') : '';
        resolve({ status: res.statusCode, headers: res.headers, text, json, cookie });
      });
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    const send = () => { if (data != null) req.write(data); req.end(); };
    // a pinned endpoint gets nothing - no header, no token, no body - until its certificate has been compared with the pin
    if (lib === https && pin) req.on('socket', (sock) => sock.once('secureConnect', () => { const c = sock.getPeerCertificate(); if (!c || normFp(c.fingerprint256) !== pin) { req.destroy(new Error('certificate does not match the pinned fingerprint')); return; } send(); }));
    else send();
  });
}

module.exports = { request, normFp };
