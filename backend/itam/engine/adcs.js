// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Microsoft AD CS through its web enrolment pages (certsrv), HTTPS + Basic authentication with a service account that may
 * enrol on the named template (nothing more: no CA manager rights). submit() posts the CSR to certfnsh.asp; the CA either
 * issues at once (→ the certificate, base64) or holds it for a CA manager (→ pending, with the request id); fetch() reads a
 * held request again. The CA's trust is checked like any HTTPS server (an internal root can be given as caPem).
 *   createAdcs({url, template, username, password, caPem?}) → { submit(csrPem), fetch(reqId) }
 *     → {status: 'issued', reqId, pem} | {status: 'pending', reqId} | throws (refused, with the CA's message)
 */
const https = require('node:https');

const URL_RE = /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/certsrv\/?$/i;
const TEMPLATE_RE = /^[A-Za-z0-9 _.-]{1,64}$/;

function createAdcs({ url, template, username, password, caPem, request } = {}) {
  if (!URL_RE.test(String(url || ''))) throw Object.assign(new Error('AD CS URL must be https://<ca-host>/certsrv'), { status: 400 });
  if (!TEMPLATE_RE.test(String(template || ''))) throw Object.assign(new Error('AD CS template name is not valid'), { status: 400 });
  const base = String(url).replace(/\/?$/, '/'), auth = 'Basic ' + Buffer.from(String(username) + ':' + String(password)).toString('base64');
  const call = request || function (u, { method = 'GET', body } = {}) {
    return new Promise((resolve, reject) => {
      const x = new URL(u);
      const r = https.request({ method, hostname: x.hostname, port: x.port || 443, path: x.pathname + x.search, timeout: 30000, ca: caPem || undefined,
        headers: Object.assign({ Authorization: auth, 'User-Agent': 'sentra-itam-adcs/1' }, body ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {}) }, (res) => {
        let d = ''; res.setEncoding('utf8'); res.on('data', (c) => { d += c; if (d.length > 1e6) r.destroy(new Error('AD CS answer too large')); }); res.on('end', () => resolve({ status: res.statusCode, text: d }));
      });
      r.on('timeout', () => r.destroy(new Error('AD CS timeout'))); r.on('error', reject); if (body) r.write(body); r.end();
    });
  };
  const failed = (r, what) => { const m = /(Denied by Policy Module|The request was denied[^<]*|Your certificate request was denied[^<]*|0x[0-9a-f]{8}[^<]{0,160})/i.exec(r.text || ''); return Object.assign(new Error(what + (r.status === 401 ? ': the service account was refused (401)' : m ? ': ' + m[1].trim() : ': HTTP ' + r.status)), { status: r.status === 401 ? 401 : 502 }); };
  async function fetch(reqId) {
    const r = await call(base + 'certnew.cer?ReqID=' + encodeURIComponent(reqId) + '&Enc=b64');
    if (r.status === 200 && /-----BEGIN CERTIFICATE-----/.test(r.text)) return { status: 'issued', reqId: String(reqId), pem: r.text.trim() + '\n' };
    if (r.status === 200 && /pending|taken under submission/i.test(r.text)) return { status: 'pending', reqId: String(reqId) };
    throw failed(r, 'AD CS did not return the certificate');
  }
  async function submit(csrPem) {
    const body = new URLSearchParams({ Mode: 'newreq', CertRequest: csrPem, CertAttrib: 'CertificateTemplate:' + template, TargetStoreFlags: '0', SaveCert: 'yes', ThumbPrint: '' }).toString();
    const r = await call(base + 'certfnsh.asp', { method: 'POST', body });
    if (r.status !== 200) throw failed(r, 'AD CS refused the request');
    const id = /certnew\.cer\?ReqID=(\d+)/i.exec(r.text) || /Request\s*Id[^0-9]{0,20}(\d+)/i.exec(r.text);
    if (/taken under submission|pending/i.test(r.text) && id) return { status: 'pending', reqId: id[1] };
    if (!id) throw failed(r, 'AD CS refused the request');
    return fetch(id[1]);
  }
  return { submit, fetch };
}

module.exports = { createAdcs, URL_RE, TEMPLATE_RE };
