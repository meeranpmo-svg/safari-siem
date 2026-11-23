// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IPv4 / IPv6 parsing and CIDR set matching (Node standard library only).
// IPv4 addresses are handled as unsigned numbers (0 … 2^32-1), IPv6 as BigInt.
// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are treated as IPv4.

function parseV4(s) {
  let n = 0, part = 0, dots = 0, digits = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 46) {
      if (!digits || part > 255) return -1;
      n = n * 256 + part; part = 0; digits = 0;
      if (++dots > 3) return -1;
    } else if (c >= 48 && c <= 57) {
      part = part * 10 + (c - 48);
      if (++digits > 3) return -1;
    } else return -1;
  }
  if (dots !== 3 || !digits || part > 255) return -1;
  return n * 256 + part;
}

const HEX4 = /^[0-9a-f]{1,4}$/i;
function parseV6(s) {
  let str = s;
  if (str.charCodeAt(0) === 91) { const e = str.indexOf(']'); if (e < 0) return null; str = str.slice(1, e); }
  const pct = str.indexOf('%'); if (pct >= 0) str = str.slice(0, pct);
  if (str.indexOf(':') < 0) return null;
  let v4tail = -1;
  const lastColon = str.lastIndexOf(':');
  const tail = str.slice(lastColon + 1);
  if (tail.indexOf('.') >= 0) {
    v4tail = parseV4(tail);
    if (v4tail < 0) return null;
    str = str.slice(0, lastColon + 1) + '0:0';
  }
  const dbl = str.split('::');
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(':') : [];
  let parts;
  if (dbl.length === 1) {
    if (head.length !== 8) return null;
    parts = head;
  } else {
    const tl = dbl[1] ? dbl[1].split(':') : [];
    const fill = 8 - head.length - tl.length;
    if (fill < 1) return null;
    parts = head.concat(new Array(fill).fill('0'), tl);
  }
  let n = 0n;
  for (const p of parts) {
    if (!HEX4.test(p)) return null;
    n = (n << 16n) | BigInt(parseInt(p, 16));
  }
  if (v4tail >= 0) n = (n & ~0xffffffffn) | BigInt(v4tail);
  return n;
}

const MAPPED_PREFIX = 0xffffn;
/** parseIP('10.1.2.3') → {v:4, n:number}; parseIP('2001:db8::1') → {v:6, n:bigint}; invalid → null */
function parseIP(s) {
  if (typeof s !== 'string') { if (s === undefined || s === null) return null; s = String(s); }
  s = s.trim();
  if (!s) return null;
  const v4 = parseV4(s);
  if (v4 >= 0) return { v: 4, n: v4 };
  const v6 = parseV6(s);
  if (v6 === null) return null;
  if ((v6 >> 32n) === MAPPED_PREFIX) return { v: 4, n: Number(v6 & 0xffffffffn) };
  return { v: 6, n: v6 };
}

/** parseCidr('10.0.0.0/8') → {v, bits, key}; a bare address is a /32 or /128. Throws on invalid input. */
function parseCidr(s) {
  const str = String(s).trim();
  const slash = str.indexOf('/');
  const ip = parseIP(slash >= 0 ? str.slice(0, slash) : str);
  if (!ip) throw new Error(`invalid CIDR: ${s}`);
  const max = ip.v === 4 ? 32 : 128;
  let bits = slash >= 0 ? Number(str.slice(slash + 1)) : max;
  // an IPv4-mapped IPv6 prefix (::ffff:10.0.0.0/104) becomes the IPv4 prefix
  if (slash >= 0 && ip.v === 4 && str.slice(0, slash).indexOf(':') >= 0) bits -= 96;
  if (!Number.isInteger(bits) || bits < 0 || bits > max) throw new Error(`invalid CIDR prefix: ${s}`);
  const key = ip.v === 4 ? Math.floor(ip.n / 2 ** (32 - bits)) : ip.n >> BigInt(128 - bits);
  return { v: ip.v, bits, key };
}

/** createCidrSet(['10.0.0.0/8','fc00::/7','1.2.3.4']) → { has(ipString), size } — O(#distinct prefix lengths) per lookup. */
function createCidrSet(list) {
  const v4 = new Map(); // bits → Set(key)
  const v6 = new Map();
  let size = 0;
  for (const s of list) {
    const c = parseCidr(s);
    const m = c.v === 4 ? v4 : v6;
    let set = m.get(c.bits);
    if (!set) { set = new Set(); m.set(c.bits, set); }
    if (!set.has(c.key)) { set.add(c.key); size++; }
  }
  const v4e = [...v4.entries()].map(([bits, set]) => [2 ** (32 - bits), set]);
  const v6e = [...v6.entries()].map(([bits, set]) => [BigInt(128 - bits), set]);
  function hasParsed(ip) {
    if (!ip) return false;
    if (ip.v === 4) {
      for (let i = 0; i < v4e.length; i++) if (v4e[i][1].has(Math.floor(ip.n / v4e[i][0]))) return true;
      return false;
    }
    for (let i = 0; i < v6e.length; i++) if (v6e[i][1].has(ip.n >> v6e[i][0])) return true;
    return false;
  }
  return {
    size,
    has(s) { return hasParsed(parseIP(s)); },
    hasParsed,
  };
}

const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10',
  '0.0.0.0/8', '::1/128', '::/128', 'fc00::/7', 'fe80::/10'];
const privateSet = createCidrSet(PRIVATE_RANGES);
function isPrivate(s) { return privateSet.has(s); }

module.exports = { parseV4, parseV6, parseIP, parseCidr, createCidrSet, isPrivate, PRIVATE_RANGES };
