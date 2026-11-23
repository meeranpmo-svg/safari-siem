// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IPv4 helpers for discovery scopes — pure, no I/O.
//   parseIp('10.1.2.3') → uint32 | null          ipStr(n) → dotted
//   parseTarget('10.0.0.0/24' | '10.0.0.5-10.0.0.40' | '10.0.0.5-40' | '10.0.0.7') → {kind, first, last, text, count} | throws
//   isPrivate(n|str) → RFC 1918 (10/8, 172.16/12, 192.168/16)      isSpecial(n) → loopback/link-local/multicast/reserved/0/8
//   expand(targets, exclusions, {max}) → uint32[] (host addresses, network/broadcast of /0../30 CIDRs skipped)
//   contains(targets, ip) → bool
const PRIVATE = [[0x0a000000, 8], [0xac100000, 12], [0xc0a80000, 16]];
const SPECIAL = [[0x00000000, 8], [0x7f000000, 8], [0xa9fe0000, 16], [0xe0000000, 4], [0xf0000000, 4], [0x64400000, 10]];

const bad = (msg) => Object.assign(new Error(msg), { status: 400 });

function parseIp(s) {
  const t = String(s == null ? '' : s).trim();
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(t);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((x) => x > 255)) return null;
  if (m.slice(1).some((x) => x.length > 1 && x[0] === '0')) return null; // no leading zeros (octal ambiguity)
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}
function ipStr(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
function maskOf(bits) { return bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0; }
function inCidr(n, base, bits) { return ((n & maskOf(bits)) >>> 0) === ((base & maskOf(bits)) >>> 0); }
function isPrivate(v) { const n = typeof v === 'number' ? v : parseIp(v); return n !== null && PRIVATE.some(([b, l]) => inCidr(n, b, l)); }
function isSpecial(v) { const n = typeof v === 'number' ? v : parseIp(v); return n === null || SPECIAL.some(([b, l]) => inCidr(n, b, l)) || n === 0xffffffff; }

// one scope target → inclusive range
function parseTarget(raw) {
  const text = String(raw == null ? '' : raw).trim();
  if (!text) throw bad('empty target');
  let m = /^([\d.]+)\/(\d{1,2})$/.exec(text);
  if (m) {
    const base = parseIp(m[1]); const bits = Number(m[2]);
    if (base === null || bits > 32) throw bad(`invalid CIDR "${text}"`);
    const net = (base & maskOf(bits)) >>> 0;
    if (net !== base) throw bad(`"${text}" is not a network address (did you mean ${ipStr(net)}/${bits}?)`);
    const last = (net | (~maskOf(bits) >>> 0)) >>> 0;
    return { kind: 'cidr', first: net, last, bits, text: `${ipStr(net)}/${bits}`, count: last - net + 1 };
  }
  m = /^([\d.]+)\s*-\s*([\d.]+)$/.exec(text);
  if (m) {
    const a = parseIp(m[1]);
    let b = parseIp(m[2]);
    if (b === null && /^\d{1,3}$/.test(m[2]) && a !== null && Number(m[2]) <= 255) b = ((a & 0xffffff00) >>> 0) + Number(m[2]); // 10.0.0.5-40
    if (a === null || b === null) throw bad(`invalid range "${text}"`);
    if (b < a) throw bad(`range "${text}" ends before it starts`);
    return { kind: 'range', first: a, last: b, text: `${ipStr(a)}-${ipStr(b)}`, count: b - a + 1 };
  }
  const n = parseIp(text);
  if (n === null) throw bad(`"${text}" is not an IPv4 address, CIDR or range`);
  return { kind: 'ip', first: n, last: n, text: ipStr(n), count: 1 };
}

function within(ranges, n) { for (const r of ranges) if (n >= r.first && n <= r.last) return true; return false; }
function contains(targets, ip) {
  const n = typeof ip === 'number' ? ip : parseIp(ip);
  if (n === null) return false;
  return within(targets.map((t) => (typeof t === 'string' ? parseTarget(t) : t)), n);
}

// expand targets minus exclusions into host addresses (ascending, de-duplicated). For CIDRs /0-/30 the network and
// broadcast addresses are skipped. Throws when the result would exceed `max`.
function expand(targets, exclusions = [], { max = 4096 } = {}) {
  const inc = targets.map((t) => (typeof t === 'string' ? parseTarget(t) : t));
  const exc = exclusions.map((t) => (typeof t === 'string' ? parseTarget(t) : t));
  const set = new Set();
  for (const r of inc) {
    let first = r.first; let last = r.last;
    if (r.kind === 'cidr' && r.bits <= 30) { first += 1; last -= 1; }
    for (let n = first; n <= last; n++) {
      if (within(exc, n) || isSpecial(n)) continue;
      set.add(n);
      if (set.size > max) throw bad(`scope expands to more than ${max} host addresses — split it or raise discovery.max_hosts_per_scope`);
    }
  }
  return [...set].sort((a, b) => a - b);
}

module.exports = { parseIp, ipStr, parseTarget, isPrivate, isSpecial, expand, contains, inCidr, maskOf };
