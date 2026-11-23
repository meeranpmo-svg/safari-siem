// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/* check.js - input validation at the boundary, written with the business logic, not after it (the same file as sentra-siem
 * engine/util/check.js). Every rule throws a 400 that names the field and what is wrong, so the caller can fix it and the
 * handler never sees a value it did not expect.
 *
 *   const { body } = require('./check');
 *   const b = body(ctx.body)
 *     .str('label', { required: true, max: 120 })
 *     .str('host', { required: true, host: true })
 *     .int('port', { min: 1, max: 65535, def: 1521 })
 *     .oneOf('kind', ['oracle', 'mssql'], { required: true })
 *     .date('due', {})                    // YYYY-MM-DD
 *     .list('asset_ids', { max: 500, item: 'id' })
 *     .bool('enabled', { def: true })
 *     .done();                            // → a NEW object with only the declared fields (anything else is dropped)
 *
 * Strings are trimmed and control characters refused; a field not declared never reaches the logic (no mass assignment).
 */
function bad(msg) { return Object.assign(new Error(msg), { status: 400 }); }
const CTRL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const HOST = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const ID = /^[A-Za-z0-9_.:-]{1,80}$/;
const EMAIL = /^[^\s@<>"']{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/;

function isIp(v) { return IPV4.test(v) || (/^[0-9a-fA-F:]+$/.test(v) && v.includes(':') && v.length <= 39); }

function body(src) {
  if (src !== undefined && src !== null && (typeof src !== 'object' || Array.isArray(src))) throw bad('the request body must be a JSON object');
  const b = src || {}, out = {};
  const has = (k) => b[k] !== undefined && b[k] !== null && b[k] !== '';
  const api = {
    str(k, o = {}) {
      if (!has(k)) { if (o.required) throw bad(`${k} is required`); if (o.def !== undefined) out[k] = o.def; return api; }
      if (typeof b[k] !== 'string' && typeof b[k] !== 'number') throw bad(`${k} must be text`);
      const v = String(b[k]).trim();
      if (!v && o.required) throw bad(`${k} is required`);
      if (CTRL.test(v)) throw bad(`${k} contains control characters`);
      if (v.length > (o.max || 500)) throw bad(`${k} is longer than ${o.max || 500} characters`);
      if (o.min && v.length < o.min) throw bad(`${k} must be at least ${o.min} characters`);
      if (o.host && (/^[\d.]+$/.test(v) ? !isIp(v) : !(HOST.test(v) || isIp(v)))) throw bad(`${k} must be a host name or IP address`);   // 999.1.1.1 is neither
      if (o.ip && !isIp(v)) throw bad(`${k} must be an IP address`);
      if (o.email && !EMAIL.test(v)) throw bad(`${k} must be an e-mail address`);
      if (o.id && !ID.test(v)) throw bad(`${k} is not a valid id`);
      if (o.re && !o.re.test(v)) throw bad(o.msg || `${k} has an invalid format`);
      out[k] = v; return api;
    },
    int(k, o = {}) {
      if (!has(k)) { if (o.required) throw bad(`${k} is required`); if (o.def !== undefined) out[k] = o.def; return api; }
      const n = typeof b[k] === 'number' ? b[k] : /^-?\d+$/.test(String(b[k]).trim()) ? Number(b[k]) : NaN;
      if (!Number.isInteger(n)) throw bad(`${k} must be a whole number`);
      if (o.min !== undefined && n < o.min) throw bad(`${k} must be at least ${o.min}`);
      if (o.max !== undefined && n > o.max) throw bad(`${k} must be at most ${o.max}`);
      out[k] = n; return api;
    },
    num(k, o = {}) {
      if (!has(k)) { if (o.required) throw bad(`${k} is required`); if (o.def !== undefined) out[k] = o.def; return api; }
      const n = Number(b[k]);
      if (!Number.isFinite(n)) throw bad(`${k} must be a number`);
      if (o.min !== undefined && n < o.min) throw bad(`${k} must be at least ${o.min}`);
      if (o.max !== undefined && n > o.max) throw bad(`${k} must be at most ${o.max}`);
      out[k] = n; return api;
    },
    bool(k, o = {}) {
      if (!has(k)) { if (o.required) throw bad(`${k} is required`); if (o.def !== undefined) out[k] = o.def; return api; }
      if (typeof b[k] !== 'boolean') throw bad(`${k} must be true or false`);
      out[k] = b[k]; return api;
    },
    oneOf(k, allowed, o = {}) {
      if (!has(k)) { if (o.required) throw bad(`${k} is required`); if (o.def !== undefined) out[k] = o.def; return api; }
      if (!allowed.includes(b[k])) throw bad(`${k} must be one of: ${allowed.join(', ')}`);
      out[k] = b[k]; return api;
    },
    date(k, o = {}) {
      if (!has(k)) { if (o.required) throw bad(`${k} is required`); if (o.def !== undefined) out[k] = o.def; return api; }
      const v = String(b[k]).trim();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(v) || Number.isNaN(Date.parse(v + 'T00:00:00Z')) || new Date(v + 'T00:00:00Z').toISOString().slice(0, 10) !== v) throw bad(`${k} must be a date (YYYY-MM-DD)`);
      if (o.notFuture && Date.parse(v + 'T00:00:00Z') > (o.now || Date.now())) throw bad(`${k} cannot be in the future`);
      out[k] = v; return api;
    },
    list(k, o = {}) {
      if (!has(k)) { if (o.required) throw bad(`${k} is required`); if (o.def !== undefined) out[k] = o.def; return api; }
      if (!Array.isArray(b[k])) throw bad(`${k} must be a list`);
      if (o.required && !b[k].length) throw bad(`${k} needs at least one entry`);
      if (b[k].length > (o.max || 1000)) throw bad(`${k} has more than ${o.max || 1000} entries`);
      out[k] = b[k].map((x, i) => {
        if (o.item === 'id') { if (typeof x !== 'string' || !ID.test(x)) throw bad(`${k}[${i}] is not a valid id`); return x; }
        if (o.item === 'str') { if (typeof x !== 'string' || CTRL.test(x) || x.length > (o.itemMax || 200)) throw bad(`${k}[${i}] is not valid text`); return x.trim(); }
        if (Array.isArray(o.item)) { if (!o.item.includes(x)) throw bad(`${k}[${i}] must be one of: ${o.item.join(', ')}`); return x; }
        return x;
      });
      if (o.unique) out[k] = [...new Set(out[k])];
      return api;
    },
    // a rule that needs more than one field: fn(out) returns an error message or nothing
    rule(fn) { const m = fn(out); if (m) throw bad(m); return api; },
    done() { return out; },
  };
  return api;
}
/* an uploaded file: the name is cleaned (no path, no control or reserved characters), the extension must be allowed and the
   bytes must really be that kind of file (magic bytes) - a renamed .exe / .html / .svg is refused, whatever the browser
   called its content type. Returns { name, ext, kind, mime } to store with the bytes. */
const FILE_KINDS = {
  pdf: ['application/pdf', (b) => b.slice(0, 5).toString('latin1') === '%PDF-'],
  png: ['image/png', (b) => b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))],
  jpg: ['image/jpeg', (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff], jpeg: ['image/jpeg', (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff],
  gif: ['image/gif', (b) => /^GIF8[79]a/.test(b.slice(0, 6).toString('latin1'))],
  docx: ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', ooxml], xlsx: ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ooxml],
  pptx: ['application/vnd.openxmlformats-officedocument.presentationml.presentation', ooxml],
  doc: ['application/msword', ole], xls: ['application/vnd.ms-excel', ole], ppt: ['application/vnd.ms-powerpoint', ole], msg: ['application/vnd.ms-outlook', ole],
  csv: ['text/csv', text], txt: ['text/plain', text], log: ['text/plain', text], eml: ['message/rfc822', text], json: ['application/json', text], xml: ['application/xml', text],
};
function ooxml(b) { return b.slice(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04])) && b.indexOf('[Content_Types].xml', 0, 'latin1') >= 0; }
function ole(b) { return b.slice(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])); }
/* plain text as Windows saves it too: UTF-8 (with or without BOM), UTF-16 LE / BE with a BOM (Excel "Unicode Text",
   PowerShell 5.1 Out-File), or 8-bit text (Windows-1252). Refused: control bytes, i.e. a binary file renamed to .csv */
function decodeText(b) {
  if (b[0] === 0xff && b[1] === 0xfe) return b.slice(2).toString('utf16le');
  if (b[0] === 0xfe && b[1] === 0xff) { const c = Buffer.from(b.slice(2)); for (let i = 0; i + 1 < c.length; i += 2) { const x = c[i]; c[i] = c[i + 1]; c[i + 1] = x; } return c.toString('utf16le'); }
  const u = b.toString('utf8');
  return u.includes('\ufffd') && !b.includes(Buffer.from([0xef, 0xbf, 0xbd])) ? b.toString('latin1') : u;
}
function text(b) { return !/[\u0000-\u0008\u000e-\u001f]/.test(decodeText(b).slice(0, 65536)); }
function fileCheck(name, buf, o = {}) {
  const allow = o.allow || Object.keys(FILE_KINDS), max = o.max || 8 * 1024 * 1024;
  let n = String(name || '').normalize('NFC').split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '').replace(/^\.+/, '').trim().slice(0, 200);
  if (!n) throw bad('a file name is required');
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(n), ext = m ? m[1].toLowerCase() : '';
  if (!ext || !allow.includes(ext) || !FILE_KINDS[ext]) throw bad(`files of type .${ext || '?'} are not accepted - allowed: ${allow.map((x) => '.' + x).join(' ')}`);
  if (!Buffer.isBuffer(buf) || !buf.length) throw bad('the file is empty');
  if (buf.length > max) throw bad(`the file is larger than ${Math.round(max / 1048576)} MB`);
  if (!FILE_KINDS[ext][1](buf)) throw bad(`the content is not a real .${ext} file (it may have been renamed) - upload the original`);
  if (['csv', 'txt', 'log', 'xml', 'json'].includes(ext) && /<\s*([a-z]+:)?(script|iframe|object|embed)\b|javascript:/i.test(decodeText(buf.slice(0, 1048576)))) throw bad('the file contains script content and was refused');
  return { name: n, ext, mime: FILE_KINDS[ext][0], size: buf.length };
}

// one path parameter (an id from the URL)
function param(v, name = 'id') { if (typeof v !== 'string' || !ID.test(v)) throw bad(`${name} is not a valid id`); return v; }

module.exports = { body, param, bad, isIp, fileCheck, FILE_KINDS };
