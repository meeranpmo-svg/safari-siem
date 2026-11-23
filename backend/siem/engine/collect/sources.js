// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Maps a peer IP (and collector) to a configured source:
//   config.sources: [{id, type, match: {ip: "a.b.c.d" | [...], cidr: "10.0.0.0/8" | [...]}, token?, tz_offset_min?}]
// Exact IP matches win over CIDR matches; CIDRs are tried in config order. Unmatched peers get the collector's default source.
const net = require('node:net');

function normPeer(ip) {
  let s = String(ip || '');
  if (s.startsWith('::ffff:') && net.isIPv4(s.slice(7))) s = s.slice(7);
  return s.toLowerCase();
}

function createSourceMap(sources = [], defaults = {}) {
  const byIp = new Map();
  const cidrs = [];
  const byId = new Map();
  for (const s of sources) {
    byId.set(s.id, s);
    const m = s.match || {};
    for (const ip of [].concat(m.ip || [])) if (!byIp.has(normPeer(ip))) byIp.set(normPeer(ip), s);
    for (const c of [].concat(m.cidr || [])) {
      const [addr, bits] = String(c).split('/');
      const fam = net.isIP(addr);
      if (!fam) continue;
      const bl = new net.BlockList();
      bl.addSubnet(addr, Number(bits), fam === 4 ? 'ipv4' : 'ipv6');
      cidrs.push({ bl, fam, src: s });
    }
  }
  const cache = new Map();

  function lookup(peer, collector) {
    const ip = normPeer(peer);
    const hit = cache.get(ip);
    if (hit !== undefined) return hit || defaults[collector] || { id: collector || 'unknown', type: 'syslog' };
    let s = byIp.get(ip) || null;
    if (!s) {
      const fam = net.isIP(ip);
      if (fam) for (const c of cidrs) { if (c.fam === fam && c.bl.check(ip, fam === 4 ? 'ipv4' : 'ipv6')) { s = c.src; break; } }
    }
    if (cache.size > 50000) cache.clear();
    cache.set(ip, s);
    return s || defaults[collector] || { id: collector || 'unknown', type: 'syslog' };
  }

  return { lookup, byId: (id) => byId.get(id) || null, list: () => [...byId.values()] };
}

module.exports = { createSourceMap, normPeer };
