// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Shared helpers for parsers.
const net = require('node:net');

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

// syslog severity (0 emerg … 7 debug) → engine severity (0 info … 4 critical)
const SYSLOG_SEV = [4, 4, 3, 2, 1, 0, 0, 0];
function sevFromSyslog(n) { return n >= 0 && n <= 7 ? SYSLOG_SEV[n] : 0; }

const NAMED_SEV = {
  emergency: 4, emerg: 4, alert: 4, critical: 4, crit: 4, 'very-high': 4, veryhigh: 4,
  error: 3, err: 3, high: 3,
  warning: 2, warn: 2, medium: 2,
  notice: 1, low: 1,
  information: 0, informational: 0, info: 0, debug: 0, none: 0, unknown: 0,
};
function sevFromName(s, dflt = 0) {
  if (s === undefined || s === null || s === '') return dflt;
  const v = NAMED_SEV[String(s).toLowerCase().trim()];
  return v === undefined ? dflt : v;
}

function toInt(v) {
  if (v === undefined || v === null || v === '') return 0;
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function pad(n) { return n < 10 ? '0' + n : String(n); }

// Epoch number in s / ms / µs / ns → ms
function epochToMs(n) {
  if (!Number.isFinite(n) || n <= 0) return 0;
  if (n > 1e17) return Math.floor(n / 1e6);
  if (n > 1e14) return Math.floor(n / 1e3);
  if (n > 1e11) return Math.floor(n);
  return Math.floor(n * 1000);
}

function tzToMin(tz) {
  // "+0300", "+03:00", "-05", "Z"
  if (!tz) return null;
  if (tz === 'Z' || tz === 'z' || /^(utc|gmt)$/i.test(tz)) return 0;
  const m = /^([+-])(\d{2}):?(\d{2})?$/.exec(tz);
  if (!m) return null;
  const v = Number(m[2]) * 60 + Number(m[3] || 0);
  return m[1] === '-' ? -v : v;
}

// Local wall-clock components at a fixed UTC offset → epoch ms
function wallToMs(y, mo, d, h, mi, s, ms, offMin) {
  return Date.UTC(y, mo, d, h, mi, s, ms || 0) - (offMin || 0) * 60000;
}

// Parse most timestamp shapes seen in logs. Returns epoch ms or 0.
// offMin: assumed UTC offset (minutes) when the string carries no zone.
function parseTime(v, offMin = 0, refMs = Date.now()) {
  if (v === undefined || v === null || v === '') return 0;
  if (typeof v === 'number') return epochToMs(v);
  let s = String(v).trim();
  let m;
  if (/^\d{9,19}(\.\d+)?$/.test(s)) return epochToMs(Number(s));
  if ((m = /^\/Date\((-?\d+)(?:[+-]\d{4})?\)\/$/.exec(s))) return Number(m[1]);
  // ISO 8601 / "YYYY-MM-DD HH:MM:SS(.fff)(zone)"
  if ((m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}(?::?\d{2})?|UTC|GMT)?$/i.exec(s))) {
    const ms = m[7] ? Number((m[7] + '00').slice(0, 3)) : 0;
    const off = m[8] ? tzToMin(m[8].toUpperCase() === 'UTC' || m[8].toUpperCase() === 'GMT' ? 'Z' : m[8]) : offMin;
    return wallToMs(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms, off);
  }
  // Apache: 10/Oct/2023:13:55:36 +0300
  if ((m = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:\s+([+-]\d{4}))?$/.exec(s))) {
    const mo = MONTHS[m[2].toLowerCase()];
    if (mo === undefined) return 0;
    const off = m[8] ? tzToMin(m[8]) : offMin;
    return wallToMs(+m[3], mo, +m[1], +m[4], +m[5], +m[6], m[7] ? Number((m[7] + '00').slice(0, 3)) : 0, off);
  }
  // "May 01 2024 10:00:00(.123)( zone)" (CEF rt, Cisco ASA) or "May  1 10:00:00" (syslog, year inferred)
  if ((m = /^([A-Za-z]{3})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:\s+(Z|UTC|GMT|[+-]\d{2}:?\d{2}))?$/.exec(s))) {
    const mo = MONTHS[m[1].toLowerCase()];
    if (mo === undefined) return 0;
    const off = m[8] ? tzToMin(/^(utc|gmt)$/i.test(m[8]) ? 'Z' : m[8]) : offMin;
    const ms = m[7] ? Number((m[7] + '00').slice(0, 3)) : 0;
    if (m[3]) return wallToMs(+m[3], mo, +m[2], +m[4], +m[5], +m[6], ms, off);
    return inferYear(mo, +m[2], +m[4], +m[5], +m[6], ms, off, refMs);
  }
  const d = Date.parse(s);
  return Number.isFinite(d) ? d : 0;
}

// Year-less timestamps: pick the year that puts the event closest to (and not > 1 day after) the receive time.
function inferYear(mo, d, h, mi, s, ms, off, refMs) {
  const y = new Date(refMs + (off || 0) * 60000).getUTCFullYear();
  let t = wallToMs(y, mo, d, h, mi, s, ms, off);
  if (t > refMs + 86400000) t = wallToMs(y - 1, mo, d, h, mi, s, ms, off);
  return t;
}

// key=value parser; values may be "double quoted" (with \" escapes) or 'single quoted'. Returns {key: value}.
function parseKV(s, { lowerKeys = false } = {}) {
  const out = {};
  const n = s.length;
  let i = 0;
  while (i < n) {
    while (i < n && (s.charCodeAt(i) === 32 || s.charCodeAt(i) === 9 || s[i] === ',' || s[i] === ';')) i++;
    const ks = i;
    while (i < n && s[i] !== '=' && s.charCodeAt(i) !== 32 && s.charCodeAt(i) !== 9) i++;
    if (i >= n || s[i] !== '=') { continue; }
    let key = s.slice(ks, i);
    i++; // '='
    let val = '';
    const q = s[i];
    if (q === '"' || q === "'") {
      i++;
      let buf = '';
      while (i < n && s[i] !== q) {
        if (s[i] === '\\' && i + 1 < n && (s[i + 1] === q || s[i + 1] === '\\')) { buf += s[i + 1]; i += 2; continue; }
        buf += s[i++];
      }
      i++;
      val = buf;
    } else {
      const vs = i;
      while (i < n && s.charCodeAt(i) !== 32 && s.charCodeAt(i) !== 9) i++;
      val = s.slice(vs, i);
    }
    if (key) { if (lowerKeys) key = key.toLowerCase(); out[key] = val; }
  }
  return out;
}

const NULLISH = new Set(['', '-', 'n/a', 'na', '(null)', 'null', 'none', 'unknown', '?']);
function clean(v) {
  if (v === undefined || v === null) return '';
  const s = String(v).trim();
  return NULLISH.has(s.toLowerCase()) ? '' : s;
}

// "CORP\jdoe" → {user:'jdoe', domain:'corp'}; "jdoe@corp.com" → {user:'jdoe@corp.com', domain:'corp.com'}
function splitUser(u, dom) {
  let user = clean(u);
  let domain = clean(dom);
  const bs = user.indexOf('\\');
  if (bs >= 0) { if (!domain) domain = user.slice(0, bs); user = user.slice(bs + 1); }
  else if (!domain) { const at = user.lastIndexOf('@'); if (at > 0) domain = user.slice(at + 1); }
  return { user: user.toLowerCase(), domain: domain.toLowerCase() };
}

function ipOrEmpty(v) {
  let s = clean(v);
  if (!s) return '';
  if (s.startsWith('::ffff:')) s = s.slice(7);
  if (s[0] === '[' && s.endsWith(']')) s = s.slice(1, -1);
  return net.isIP(s) ? s : '';
}

const PROTO_NUM = { 1: 'icmp', 6: 'tcp', 17: 'udp', 47: 'gre', 50: 'esp', 51: 'ah', 58: 'ipv6-icmp', 132: 'sctp' };
function protoName(p) {
  if (p === undefined || p === null || p === '') return '';
  const s = String(p).trim().toLowerCase();
  if (/^\d+$/.test(s)) return PROTO_NUM[s] || s;
  return s;
}

function firstLine(s, max = 300) {
  if (!s) return '';
  s = String(s);
  const nl = s.search(/\r?\n/);
  if (nl >= 0) s = s.slice(0, nl);
  return s.length > max ? s.slice(0, max) : s;
}

function safeJson(s) {
  if (typeof s !== 'string') return null;
  const c = s.charCodeAt(0);
  if (c !== 123 && c !== 91) return null;
  try { const o = JSON.parse(s); return o && typeof o === 'object' ? o : null; } catch { return null; }
}

// Flatten nested objects into dotted keys (max depth), arrays JSON-encoded.
function flatten(obj, prefix = '', out = {}, depth = 0) {
  for (const [k, v] of Object.entries(obj || {})) {
    const key = prefix ? prefix + '.' + k : k;
    if (v === null || v === undefined) continue;
    if (typeof v === 'object' && !Array.isArray(v) && depth < 4) flatten(v, key, out, depth + 1);
    else out[key] = typeof v === 'object' ? JSON.stringify(v) : String(v);
  }
  return out;
}

// Returns {hdr, body}: parsed syslog header (router supplies meta.syslog; parsers called directly parse it themselves)
function split(line, meta) {
  if (meta && meta.syslog !== undefined) return { hdr: meta.syslog, body: line };
  const hdr = syslogHeader(line, meta || {});
  return { hdr, body: hdr ? hdr.msg : line };
}

// RFC 5424 first, then RFC 3164 (incl. ISO-timestamp and PRI-only variants). null = no syslog header.
let r5424 = null;
let r3164 = null;
function syslogHeader(line, meta = {}) {
  if (typeof line !== 'string' || !line) return null;
  if (!r5424) { r5424 = require('./rfc5424'); r3164 = require('./rfc3164'); } // lazy (circular import), then cached
  return r5424.parseHeader(line) || r3164.parseHeader(line, meta.tz_offset_min || 0, meta.rts || Date.now());
}

module.exports = {
  MONTHS, sevFromSyslog, sevFromName, toInt, parseTime, epochToMs, tzToMin, wallToMs, inferYear, parseKV,
  clean, splitUser, ipOrEmpty, protoName, firstLine, safeJson, flatten, split, syslogHeader, pad,
};
