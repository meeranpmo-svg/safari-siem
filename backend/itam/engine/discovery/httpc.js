// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Small HTTP(S) client for the passive discovery connectors (vCenter, CUCM AXL/RIS, Azure, AWS).
//   request(url, {method, headers, body, timeoutMs, caFile, pin, captureUntrusted, maxBytes, servername}) → {status, headers, text, json}
//   - servername: the TLS name (SNI / certificate check) when the URL holds an IP address but the appliance answers to a host name
//   - https only; plain http is accepted ONLY for loopback hosts (127.0.0.1 / localhost / ::1 — in-process test fakes).
//   - TLS verification is never switched off: either the system CAs, a CA PEM file (caFile), or an admin-approved
//     SHA-256 certificate fingerprint (pin) for appliances with self-signed certificates. With a pin, headers and body
//     (credentials) are only written AFTER the presented certificate matched the pin.
//   - captureUntrusted (test / Connect Wizard only): still FAILS CLOSED — nothing is ever sent to a server that did not
//     verify — but when the chain is not trusted it captures the PRESENTED certificate (subject/issuer/validity/
//     fingerprint256) on the rejection error so the wizard can show it and offer Trust & pin (TOFU). Credentials are
//     never written on this path either; the socket is destroyed the moment the handshake proves untrusted.
//   - one socket per request (no keep-alive pooling), 16 MB response cap.
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
const fail = (code, message, extra) => Object.assign(new Error(message), { code }, extra || {});

// Presented-certificate summary for the wizard (Node getPeerCertificate → subject, issuer, valid_from, valid_to,
// fingerprint256). Never includes the public key or raw DER — only what an admin needs to recognise the appliance.
function dn(o) {
  if (!o || typeof o !== 'object') return '';
  const parts = [];
  ['CN', 'O', 'OU', 'L', 'ST', 'C'].forEach((k) => { if (o[k]) parts.push(k + '=' + o[k]); });
  return parts.join(', ') || (o.CN || '');
}
function certInfo(cert) {
  if (!cert || typeof cert !== 'object' || !cert.subject) return null;
  return {
    subject: dn(cert.subject),
    issuer: dn(cert.issuer),
    valid_from: cert.valid_from || null,
    valid_to: cert.valid_to || null,
    fingerprint256: cert.fingerprint256 ? cert.fingerprint256.replace(/:/g, '').toLowerCase() : null,
    serial: cert.serialNumber || null,
    self_signed: !!(cert.subject && cert.issuer && dn(cert.subject) === dn(cert.issuer)),
  };
}

function request(url, o = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(fail('config', 'invalid URL')); }
    const isHttps = u.protocol === 'https:';
    if (!isHttps && !(u.protocol === 'http:' && LOOPBACK.has(u.hostname))) return reject(fail('config', 'only https:// endpoints are allowed'));
    const body = o.body === undefined || o.body === null ? null : Buffer.isBuffer(o.body) ? o.body : Buffer.from(String(o.body));
    const headers = Object.assign({}, o.headers || {});
    if (body) headers['Content-Length'] = body.length;
    if (o.servername !== undefined && !/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(String(o.servername))) return reject(fail('config', 'invalid servername'));
    const opts = { protocol: u.protocol, hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || (isHttps ? 443 : 80), path: u.pathname + u.search, method: o.method || 'GET', headers, agent: false, timeout: o.timeoutMs || 30000 };
    if (o.servername) opts.servername = String(o.servername);
    const pin = o.pin ? String(o.pin).replace(/:/g, '').toLowerCase() : '';
    const capture = !pin && !!o.captureUntrusted;
    if (isHttps) {
      opts.minVersion = 'TLSv1.2';
      if (pin) opts.rejectUnauthorized = false;               // replaced by the fingerprint check below
      else if (capture) {
        opts.rejectUnauthorized = false;                      // verified manually in secureConnect; nothing sent until trusted
        if (o.caFile) { try { opts.ca = fs.readFileSync(o.caFile); } catch (e) { return reject(fail('config', `CA file not readable (${e.code})`)); } }
      } else {
        opts.rejectUnauthorized = true;
        if (o.caFile) { try { opts.ca = fs.readFileSync(o.caFile); } catch (e) { return reject(fail('config', `CA file not readable (${e.code})`)); } }
      }
    }
    const max = o.maxBytes || 16 * 1024 * 1024;
    const mod = isHttps ? https : http;
    const req = mod.request(opts, (res) => {
      const chunks = []; let size = 0;
      res.on('data', (c) => { size += c.length; if (size > max) { req.destroy(fail('protocol', 'response too large')); return; } chunks.push(c); });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null; try { json = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
      res.on('error', (e) => reject(fail('unreachable', e.message)));
    });
    req.on('timeout', () => req.destroy(fail('timeout', 'request timed out')));
    req.on('error', (e) => {
      if (e.code === 'timeout' || e.code === 'tls' || e.code === 'protocol' || e.code === 'config') return reject(e);
      const c = String(e.code || '');
      if (/CERT|SELF_SIGNED|UNABLE_TO|ERR_TLS|HOSTNAME|ALTNAME/.test(c) || /certificate/i.test(e.message)) return reject(fail('tls', 'TLS certificate not trusted', { authError: c || null }));
      if (c === 'ETIMEDOUT') return reject(fail('timeout', 'connection timed out', { sys: c }));
      return reject(fail('unreachable', `connection failed (${c || 'error'})`, { sys: c || null }));   // sys: the OS code, so a caller can say what to fix
    });
    const send = () => { if (body) req.write(body); req.end(); };
    if (isHttps && (pin || capture)) {
      req.on('socket', (sock) => sock.once('secureConnect', () => {
        const cert = sock.getPeerCertificate();
        if (pin) {
          const fp = cert && cert.fingerprint256 ? cert.fingerprint256.replace(/:/g, '').toLowerCase() : '';
          if (fp !== pin) { req.destroy(fail('tls', 'certificate fingerprint does not match the approved pin', { pinMismatch: true, presented: certInfo(cert) })); return; }
          send(); return;
        }
        // captureUntrusted: trust ONLY what Node verified against the system/caFile chain; otherwise capture and refuse.
        if (sock.authorized) { send(); return; }
        req.destroy(fail('tls', 'TLS certificate not trusted', { authError: sock.authorizationError ? String(sock.authorizationError) : null, presented: certInfo(cert) }));
      }));
    } else send();
  });
}

module.exports = { request, LOOPBACK, certInfo };
