// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Hikvision (and ISAPI-compatible) NVR - read-only client for recorder and camera health.
 *   GET /ISAPI/System/deviceInfo                          model, serial, firmware, name
 *   GET /ISAPI/ContentMgmt/InputProxy/channels            the camera channels (name, camera IP)
 *   GET /ISAPI/ContentMgmt/InputProxy/channels/status     each channel online / offline
 *   GET /ISAPI/ContentMgmt/Storage                        disks: capacity, free, status
 * Only these four GET paths, ever (PATHS below is the whole list) - no PTZ, no live view, no playback, no reboot, no settings.
 * HTTP Digest authentication (Hikvision's default; Basic is used only when the recorder asks for it). The password is read from
 * secrets.json by the caller and never logged. Fields the recorder does not send stay null ("not reported"), never a guess.
 * No video and no image is ever read into the platform (PDPL: CCTV shows people).
 */
const crypto = require('node:crypto');
const { request } = require('../secops/https');

const PATHS = { info: '/ISAPI/System/deviceInfo', channels: '/ISAPI/ContentMgmt/InputProxy/channels', status: '/ISAPI/ContentMgmt/InputProxy/channels/status', storage: '/ISAPI/ContentMgmt/Storage' };
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
const txt = (v, max = 120) => (v == null ? null : String(v).replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, max) || null);

// tiny XML reader for the ISAPI shapes: tag text, and repeated blocks
const tag = (xml, name) => { const m = new RegExp('<(?:\\w+:)?' + name + '\\b[^>]*>([\\s\\S]*?)</(?:\\w+:)?' + name + '>', 'i').exec(xml || ''); return m ? m[1].trim() : null; };
const blocks = (xml, name) => { const out = [], re = new RegExp('<(?:\\w+:)?' + name + '\\b[^>]*>([\\s\\S]*?)</(?:\\w+:)?' + name + '>', 'gi'); let m; while ((m = re.exec(xml || ''))) out.push(m[1]); return out; };
const bool = (v) => (v == null ? null : /^(true|1|online|connected)$/i.test(String(v).trim()) ? true : /^(false|0|offline|disconnected)$/i.test(String(v).trim()) ? false : null);
const num = (v) => { const n = Number(v); return v == null || v === '' || !Number.isFinite(n) ? null : n; };

function parseInfo(x) { return { name: txt(tag(x, 'deviceName')), model: txt(tag(x, 'model'), 60), serial: txt(tag(x, 'serialNumber'), 80), firmware: txt(tag(x, 'firmwareVersion'), 60), mac: txt(tag(x, 'macAddress'), 20) }; }
function parseChannels(x) { return blocks(x, 'InputProxyChannel').map((b) => { const src = tag(b, 'sourceInputPortDescriptor') || ''; return { id: txt(tag(b, 'id'), 10), name: txt(tag(b, 'name'), 80), ip: txt(tag(src, 'ipAddress'), 45), protocol: txt(tag(src, 'proxyProtocol'), 20) }; }); }
function parseStatus(x) { return blocks(x, 'InputProxyChannelStatus').map((b) => { const src = tag(b, 'sourceInputPortDescriptor') || ''; return { id: txt(tag(b, 'id'), 10), online: bool(tag(b, 'online')), ip: txt(tag(src, 'ipAddress'), 45), detail: txt(tag(b, 'chanDetectResult'), 40) }; }); }
function parseStorage(x) { return blocks(x, 'hdd').map((b) => { const cap = num(tag(b, 'capacity')), free = num(tag(b, 'freeSpace')); return { id: txt(tag(b, 'id'), 10), name: txt(tag(b, 'hddName'), 40), capacity_gb: cap == null ? null : Math.round(cap / 1024), free_gb: free == null ? null : Math.round(free / 1024), status: txt(tag(b, 'status'), 30), property: txt(tag(b, 'property'), 20) }; }); }

function digestHeader(www, { user, pass, method, uri, cnonce, nc = '00000001' }) {
  const p = {}; String(www).replace(/^Digest\s+/i, '').replace(/(\w+)=("([^"]*)"|[^,\s]*)/g, (m0, k, v, q) => { p[k.toLowerCase()] = q != null ? q : v; return m0; });
  const qop = (p.qop || '').split(',').map((s) => s.trim()).includes('auth') ? 'auth' : null, algo = (p.algorithm || 'MD5').toUpperCase();
  let ha1 = md5(user + ':' + p.realm + ':' + pass); if (algo === 'MD5-SESS') ha1 = md5(ha1 + ':' + p.nonce + ':' + cnonce);
  const ha2 = md5(method + ':' + uri), resp = qop ? md5(ha1 + ':' + p.nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2) : md5(ha1 + ':' + p.nonce + ':' + ha2);
  return 'Digest username="' + user + '", realm="' + p.realm + '", nonce="' + p.nonce + '", uri="' + uri + '", response="' + resp + '"' + (p.opaque ? ', opaque="' + p.opaque + '"' : '') + (qop ? ', qop=' + qop + ', nc=' + nc + ', cnonce="' + cnonce + '"' : '') + (p.algorithm ? ', algorithm=' + p.algorithm : '');
}

function createClient({ host, port, https: useHttps = true, user, pass, tls = {}, timeoutMs = 15000, req = request }) {
  const base = (useHttps ? 'https://' : 'http://') + host + (port ? ':' + port : '');
  async function get(key) {
    const uri = PATHS[key]; if (!uri) throw new Error('not an allowed path');            // the whole list of what may be read
    const o = { url: base + uri, method: 'GET', tls, timeoutMs, allow_http: !useHttps, headers: { Accept: 'application/xml' } };
    let r = await req(o);
    if (r.status === 401) { const www = String((r.headers && (r.headers['www-authenticate'] || r.headers['WWW-Authenticate'])) || '');
      const auth = /^digest/i.test(www) ? digestHeader(www, { user, pass, method: 'GET', uri, cnonce: crypto.randomBytes(8).toString('hex') }) : /^basic/i.test(www) ? 'Basic ' + Buffer.from(user + ':' + pass).toString('base64') : null;
      if (!auth) throw new Error('the recorder asked for an authentication this client does not speak');
      r = await req(Object.assign({}, o, { headers: Object.assign({}, o.headers, { Authorization: auth }) })); }
    if (r.status === 401) throw new Error('login refused (user name / password, or the account is locked on the recorder)');
    if (r.status === 403) throw new Error('the account may not read ' + uri + ' - give it an operator / read-only user with remote parameter view rights');
    if (r.status === 404) return null;                                                      // this model does not have that resource
    if (r.status < 200 || r.status >= 300) throw new Error('HTTP ' + r.status + ' on ' + uri);
    return r.text;
  }
  async function snapshot(now = Date.now()) {
    const out = { at: now, errors: [] };
    const step = async (key, parse, field) => { try { const x = await get(key); out[field] = x == null ? null : parse(x); } catch (e) { if (key === 'info') throw e; out.errors.push(key + ': ' + e.message); out[field] = null; } };
    await step('info', parseInfo, 'info'); await step('channels', parseChannels, 'channels'); await step('status', parseStatus, 'status'); await step('storage', parseStorage, 'disks');
    return out;
  }
  return { get, snapshot };
}

module.exports = { createClient, PATHS, digestHeader, parseInfo, parseChannels, parseStatus, parseStorage };
