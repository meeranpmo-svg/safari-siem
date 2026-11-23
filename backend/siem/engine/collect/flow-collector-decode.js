// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Flow export decoders: NetFlow v5, NetFlow v9, IPFIX (RFC 7011) and sFlow v5. A datagram is UNTRUSTED input from the
 * network: every length is checked against the bytes really there before it is read, every count is capped, and a
 * malformed datagram throws a FlowDecodeError (the collector counts it and drops it) - it can never crash the engine or
 * make it allocate more than the datagram itself.
 *
 *   decode(buf, { exporter, cache, now }) → { version, records[], domain, sampling?, counters, no_template, templates,
 *                                            app_names[[id, name]], agent? }
 *   createTemplateCache({ ttlMs, maxPerExporter, maxTotal, now })  templates per exporter + source id / observation domain,
 *                                            with expiry (re-sent templates refresh it); also the sampling rate and the
 *                                            application names (NBAR / IPFIX options data) an exporter announced
 *
 * A record: { src, dst, sport, dport, proto, tos, tcp_flags, if_in, if_out, bytes, packets, sampling?, app_id?, app_name? }
 * src / dst are canonical strings (IPv4 dotted, IPv6 compressed). Records without both addresses or with implausible
 * values (a port above 65535 from a wide template field, more than 10 TB in one flow) are dropped and counted.
 * Enterprise-specific IPFIX fields are skipped by their length (fixed or variable), never interpreted.
 */
const MAX_FIELDS = 128;           // fields per template (IPFIX allows 65535; nobody sends that many)
const MAX_RECORDS = 4096;         // records per datagram (a 64 KB datagram cannot hold more of the smallest record)
const MAX_SFLOW_SAMPLES = 512;
const MAX_SFLOW_RECORDS = 64;     // flow records per sample
const MAX_BYTES_PER_FLOW = 1e13;
const MAX_PACKETS_PER_FLOW = 1e11;

class FlowDecodeError extends Error { constructor(msg) { super(msg); this.code = 'EFLOW'; } }
const bad = (m) => new FlowDecodeError(m);

function ip4(b, o) { return b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3]; }
function ip6(b, o) {
  const g = []; for (let i = 0; i < 8; i++) g.push(b.readUInt16BE(o + i * 2));
  if (!g[0] && !g[1] && !g[2] && !g[3] && !g[4] && g[5] === 0xffff) return ip4(b, o + 12);   // IPv4-mapped
  let bs = -1, bl = 0;
  for (let i = 0; i < 8;) { if (g[i] === 0) { let j = i; while (j < 8 && g[j] === 0) j++; if (j - i > bl && j - i > 1) { bs = i; bl = j - i; } i = j; } else i++; }
  const h = g.map((x) => x.toString(16));
  return bs < 0 ? h.join(':') : h.slice(0, bs).join(':') + '::' + h.slice(bs + bl).join(':');
}
// unsigned big-endian integer of 1..8 bytes; wider → null (never guessed)
function uint(b, o, len) {
  if (len < 1 || len > 8) return null;
  if (len <= 6) return b.readUIntBE(o, len);
  let v = 0n; for (let i = 0; i < len; i++) v = (v << 8n) | BigInt(b[o + i]);
  return v > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(v);
}
const CTRL = /[\u0000-\u001f\u007f]/g;
function str(b, o, len) { return b.toString('utf8', o, o + Math.min(len, 128)).replace(/\u0000+$/, '').replace(CTRL, '').trim().slice(0, 64); }

// ---------------------------------------------------------------------------------------------------- template cache
function createTemplateCache({ ttlMs = 1800000, maxPerExporter = 512, maxTotal = 20000, now = Date.now } = {}) {
  const T = new Map(), perExp = new Map(), meta = new Map();
  const st = { added: 0, expired: 0, refused: 0, withdrawn: 0 };
  const k = (e, d, id) => e + '|' + d + '|' + id;
  function get(e, d, id) {
    const t = T.get(k(e, d, id)); if (!t) return null;
    if (now() - t.at > ttlMs) { del(e, d, id); st.expired++; return null; }
    return t;
  }
  function del(e, d, id) { if (T.delete(k(e, d, id))) perExp.set(e, Math.max(0, (perExp.get(e) || 1) - 1)); }
  function set(e, d, id, tpl) {
    const key = k(e, d, id), had = T.has(key);
    if (!had && ((perExp.get(e) || 0) >= maxPerExporter || T.size >= maxTotal)) { st.refused++; return false; }
    T.set(key, Object.assign(tpl, { at: now() }));
    if (!had) { perExp.set(e, (perExp.get(e) || 0) + 1); st.added++; }
    return true;
  }
  function sweep() {
    const t = now(); let n = 0;
    for (const [key, v] of T) if (t - v.at > ttlMs) { const [e, d, id] = key.split('|'); del(e, d, id); n++; }
    st.expired += n;
    for (const [key, m] of meta) if (t - m.at > ttlMs * 4) meta.delete(key);
    return n;
  }
  // exporter + domain level facts from options data: sampling rate, application id → name (bounded)
  function metaOf(e, d, create) {
    const key = e + '|' + d; let m = meta.get(key);
    if (!m && create) { if (meta.size >= maxTotal) return null; m = { sampling: null, apps: new Map(), at: now() }; meta.set(key, m); }
    if (m && create) m.at = now();
    return m || null;
  }
  return { get, set, del, sweep, metaOf, count: (e) => perExp.get(e) || 0, size: () => T.size, stats: () => Object.assign({ templates: T.size, domains: meta.size }, st) };
}

// ---------------------------------------------------------------------------------------------------- record checks
function finish(rec, out) {
  if (!rec.src || !rec.dst) { out.invalid++; return; }
  const n = (v) => (v == null ? 0 : v);
  rec.bytes = n(rec.bytes); rec.packets = n(rec.packets);
  rec.sport = n(rec.sport); rec.dport = n(rec.dport); rec.proto = n(rec.proto); rec.tos = n(rec.tos); rec.tcp_flags = n(rec.tcp_flags);
  rec.if_in = n(rec.if_in); rec.if_out = n(rec.if_out);
  if (rec.sport > 65535 || rec.dport > 65535 || rec.proto > 255 || rec.tos > 255 || rec.if_in > 4294967295 || rec.if_out > 4294967295
    || rec.bytes > MAX_BYTES_PER_FLOW || rec.packets > MAX_PACKETS_PER_FLOW) { out.invalid++; return; }
  if (out.records.length >= MAX_RECORDS) { out.invalid++; return; }
  out.records.push(rec);
}

// ---------------------------------------------------------------------------------------------------- NetFlow v5
function decodeV5(b) {
  if (b.length < 24) throw bad('v5: header truncated');
  const count = b.readUInt16BE(2);
  if (count < 1 || count > 30) throw bad('v5: record count ' + count + ' out of range (1-30)');
  if (b.length < 24 + count * 48) throw bad('v5: ' + count + ' records announced, ' + Math.floor((b.length - 24) / 48) + ' present');
  const si = b.readUInt16BE(22), interval = si & 0x3fff;
  const out = { version: 5, domain: String((b[20] << 8) | b[21]), records: [], invalid: 0, sampling: interval > 1 ? interval : null };
  for (let i = 0; i < count; i++) {
    const o = 24 + i * 48;
    finish({ src: ip4(b, o), dst: ip4(b, o + 4), if_in: b.readUInt16BE(o + 12), if_out: b.readUInt16BE(o + 14), packets: b.readUInt32BE(o + 16), bytes: b.readUInt32BE(o + 20),
      sport: b.readUInt16BE(o + 32), dport: b.readUInt16BE(o + 34), tcp_flags: b[o + 37], proto: b[o + 38], tos: b[o + 39], sampling: out.sampling }, out);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------- NetFlow v9 / IPFIX
// field ids shared by v9 and IPFIX (IANA IPFIX information elements 1-433 keep the v9 numbers)
function readRecord(b, o, end, tpl, ipfix) {
  const f = {};
  for (const fld of tpl.fields) {
    let len = fld.len;
    if (len === 65535) {   // IPFIX variable length (RFC 7011 7): 1 byte, or 255 + 2 bytes
      if (!ipfix || o + 1 > end) return null;
      len = b[o]; o += 1;
      if (len === 255) { if (o + 2 > end) return null; len = b.readUInt16BE(o); o += 2; }
    }
    if (o + len > end) return null;
    if (!fld.ent) {
      switch (fld.id) {
        case 1: case 2: case 23: case 24: case 85: case 86: case 4: case 5: case 6: case 7: case 11: case 10: case 14: case 34: case 50: case 61: case 195: case 305: case 306: case 48: case 302:
          f[fld.id] = uint(b, o, len); break;
        case 8: case 12: if (len === 4) f[fld.id] = ip4(b, o); break;
        case 27: case 28: if (len === 16) f[fld.id] = ip6(b, o); break;
        case 95: if (len >= 2 && len <= 9) { const sel = uint(b, o + 1, len - 1); if (sel !== null) f[95] = b[o] + ':' + sel; } break;
        case 96: if (len) f[96] = str(b, o, len); break;
        default: break;   // not used for traffic analytics
      }
    }
    o += len;   // enterprise fields: skipped by their length, never interpreted
  }
  return { f, o };
}
function recordOf(f) {
  const r = { src: f[8] || f[27] || null, dst: f[12] || f[28] || null, bytes: f[1] != null ? f[1] : f[85] != null ? f[85] : f[23], packets: f[2] != null ? f[2] : f[86] != null ? f[86] : f[24],
    proto: f[4], tos: f[5] != null ? f[5] : f[195] != null ? (f[195] & 63) << 2 : 0, tcp_flags: f[6], sport: f[7], dport: f[11], if_in: f[10], if_out: f[14] };
  const s = samplingOf(f); if (s) r.sampling = s;
  if (f[95]) r.app_id = f[95];
  if (f[96]) r.app_name = f[96];
  return r;
}
function samplingOf(f) {
  if (f[305] > 0) return Math.round((f[305] + (f[306] || 0)) / f[305]);   // packet interval + space (RFC 5477)
  const v = f[34] || f[50];
  return v > 1 ? v : null;
}
function parseTemplates(b, o, end, ipfix, options, exporter, domain, cache, out) {
  while (o + 4 <= end) {
    const id = b.readUInt16BE(o), cnt = b.readUInt16BE(o + 2); let p = o + 4, scope = 0;
    if (ipfix && cnt === 0) { cache.del(exporter, domain, id); out.withdrawn++; o = p; continue; }   // template withdrawal (RFC 7011 8.1)
    let total = cnt;
    if (options) {
      if (ipfix) { if (p + 2 > end) throw bad('options template truncated'); scope = b.readUInt16BE(p); p += 2; if (scope > cnt) throw bad('options template: more scope fields than fields'); }
      else { const scopeLen = cnt, optLen = b.readUInt16BE(o + 4); p = o + 6; if (scopeLen % 4 || optLen % 4) throw bad('v9 options template: lengths not a multiple of 4'); scope = scopeLen / 4; total = scope + optLen / 4; }
    }
    if (id < 256) throw bad('template id ' + id + ' below 256');
    if (!total || total > MAX_FIELDS) throw bad('template ' + id + ': ' + total + ' fields (1-' + MAX_FIELDS + ')');
    const fields = []; let min = 0;
    for (let i = 0; i < total; i++) {
      if (p + 4 > end) throw bad('template ' + id + ' truncated');
      let fid = b.readUInt16BE(p); const len = b.readUInt16BE(p + 2); p += 4; let ent = 0;
      if (ipfix && fid & 0x8000) { if (p + 4 > end) throw bad('template ' + id + ': enterprise number truncated'); ent = b.readUInt32BE(p) || 1; p += 4; fid &= 0x7fff; }
      if (!len) throw bad('template ' + id + ': field ' + fid + ' has length 0');
      if (len === 65535 && !ipfix) throw bad('v9 template ' + id + ': variable length is IPFIX only');
      min += len === 65535 ? 1 : len;
      fields.push({ id: fid, len, ent });
    }
    if (min > 65535) throw bad('template ' + id + ': record longer than a datagram');
    if (cache.set(exporter, domain, id, { fields, min, options: !!options, scope })) out.templates++; else out.templates_refused++;
    o = p;   // padding after the last template is under 4 bytes (RFC 3954 5.2), so the loop ends there
  }
}
function parseData(b, o, end, tpl, ipfix, exporter, domain, cache, out) {
  if (tpl.min < 1) return;
  while (end - o >= tpl.min) {
    const r = readRecord(b, o, end, tpl, ipfix);
    if (!r) { out.truncated++; return; }
    if (r.o === o) return;   // a zero-length record would never end
    o = r.o;
    if (tpl.options) {
      const m = cache.metaOf(exporter, domain, true); if (!m) continue;
      const s = samplingOf(r.f); if (s) m.sampling = s;
      if (r.f[95] && r.f[96] && m.apps.size < 5000) { m.apps.set(r.f[95], r.f[96]); out.app_names.push([r.f[95], r.f[96]]); }
      continue;
    }
    finish(recordOf(r.f), out);
    if (out.records.length >= MAX_RECORDS) return;
  }
}
function decodeV9orIpfix(b, ipfix, ctx) {
  const hl = ipfix ? 16 : 20;
  if (b.length < hl) throw bad((ipfix ? 'IPFIX' : 'v9') + ': header truncated');
  let end = b.length;
  if (ipfix) { const L = b.readUInt16BE(2); if (L < 16 || L > b.length) throw bad('IPFIX: message length ' + L + ' does not match the datagram (' + b.length + ')'); end = L; }
  const domain = String(b.readUInt32BE(ipfix ? 12 : 16)), exporter = ctx.exporter, cache = ctx.cache;
  const out = { version: ipfix ? 10 : 9, domain, records: [], invalid: 0, truncated: 0, no_template: 0, templates: 0, templates_refused: 0, withdrawn: 0, app_names: [] };
  let o = hl, sets = 0;
  while (o + 4 <= end) {
    const id = b.readUInt16BE(o), len = b.readUInt16BE(o + 2);
    if (len < 4 || o + len > end) throw bad('set ' + id + ': length ' + len + ' runs past the datagram');
    if (++sets > 1024) throw bad('too many sets');
    const s = o + 4, e = o + len;
    if ((!ipfix && id === 0) || (ipfix && id === 2)) parseTemplates(b, s, e, ipfix, false, exporter, domain, cache, out);
    else if ((!ipfix && id === 1) || (ipfix && id === 3)) parseTemplates(b, s, e, ipfix, true, exporter, domain, cache, out);
    else if (id >= 256) {
      const tpl = cache.get(exporter, domain, id);
      if (!tpl) out.no_template++;
      else parseData(b, s, e, tpl, ipfix, exporter, domain, cache, out);
    }   // ids 2-255 (v9) / 4-255 (IPFIX) are reserved: skipped
    o = e;
  }
  const m = cache.metaOf(exporter, domain, false);
  out.sampling = m && m.sampling ? m.sampling : null;
  if (m && m.apps.size) for (const r of out.records) if (r.app_id && !r.app_name && m.apps.has(r.app_id)) r.app_name = m.apps.get(r.app_id);
  for (const r of out.records) if (!r.sampling && out.sampling) r.sampling = out.sampling;
  return out;
}

// ---------------------------------------------------------------------------------------------------- sFlow v5
function rd(b, start, end) {
  let o = start;
  return {
    u32() { if (o + 4 > end) throw bad('sFlow: truncated'); const v = b.readUInt32BE(o); o += 4; return v; },
    skip(n) { if (n < 0 || o + n > end) throw bad('sFlow: truncated'); o += n; },
    at: () => o, end,
  };
}
function parseSampledHeader(proto, h, rec) {
  let o = 0, et;
  if (proto === 1) {   // Ethernet
    if (h.length < 14) return false;
    et = h.readUInt16BE(12); o = 14;
    for (let k = 0; k < 2 && (et === 0x8100 || et === 0x88a8); k++) { if (h.length < o + 4) return false; et = h.readUInt16BE(o + 2); o += 4; }
  } else if (proto === 11) et = 0x0800; else if (proto === 12) et = 0x86dd; else return false;
  if (et === 0x0800) {
    if (h.length < o + 20 || h[o] >> 4 !== 4) return false;
    const ihl = (h[o] & 15) * 4; if (ihl < 20) return false;
    rec.tos = h[o + 1]; rec.proto = h[o + 9]; rec.src = ip4(h, o + 12); rec.dst = ip4(h, o + 16);
    if (h.readUInt16BE(o + 6) & 0x1fff) return true;   // a later fragment carries no ports
    o += ihl;
  } else if (et === 0x86dd) {
    if (h.length < o + 40 || h[o] >> 4 !== 6) return false;
    rec.tos = (h.readUInt16BE(o) >> 4) & 0xff; rec.proto = h[o + 6]; rec.src = ip6(h, o + 8); rec.dst = ip6(h, o + 24); o += 40;
    for (let k = 0; k < 4 && (rec.proto === 0 || rec.proto === 43 || rec.proto === 60); k++) { if (h.length < o + 2) return true; rec.proto = h[o]; o += (h[o + 1] + 1) * 8; }
  } else return false;
  if ((rec.proto === 6 || rec.proto === 17 || rec.proto === 132) && h.length >= o + 4) {
    rec.sport = h.readUInt16BE(o); rec.dport = h.readUInt16BE(o + 2);
    if (rec.proto === 6 && h.length >= o + 14) rec.tcp_flags = h[o + 13];
  }
  return true;
}
function decodeSflow(b) {
  const r = rd(b, 0, b.length);
  if (r.u32() !== 5) throw bad('sFlow: not version 5');
  const at = r.u32(); let agent;
  if (at === 1) { r.skip(4); agent = ip4(b, r.at() - 4); } else if (at === 2) { r.skip(16); agent = ip6(b, r.at() - 16); } else throw bad('sFlow: agent address type ' + at);
  r.u32(); r.u32(); r.u32();   // sub-agent, sequence, uptime
  const n = r.u32(); if (n > MAX_SFLOW_SAMPLES) throw bad('sFlow: ' + n + ' samples announced');
  const out = { version: 'sflow5', domain: agent, agent, records: [], invalid: 0, counters: 0, unknown: 0, sampling: null };
  for (let i = 0; i < n; i++) {
    const fmt = r.u32(), len = r.u32(), s = r.at(); r.skip(len);
    const ent = fmt >>> 12, kind = fmt & 0xfff;
    if (ent !== 0) { out.unknown++; continue; }
    if (kind === 2 || kind === 4) { out.counters++; continue; }   // counter samples: interface counters come from the SNMP poller
    if (kind !== 1 && kind !== 3) { out.unknown++; continue; }
    const q = rd(b, s, s + len);
    q.u32();   // sequence
    if (kind === 1) q.u32(); else { q.u32(); q.u32(); }   // source id (compact | type + index)
    const rate = q.u32(); q.u32(); q.u32();   // sampling rate, sample pool, drops
    let ifIn, ifOut;
    if (kind === 1) { ifIn = q.u32() & 0x3fffffff; ifOut = q.u32() & 0x3fffffff; } else { q.u32(); ifIn = q.u32(); q.u32(); ifOut = q.u32(); }
    const nr = q.u32(); if (nr > MAX_SFLOW_RECORDS) throw bad('sFlow: ' + nr + ' flow records in one sample');
    if (rate > 1) out.sampling = rate;
    for (let j = 0; j < nr; j++) {
      const rf = q.u32(), rl = q.u32(), rs = q.at(); q.skip(rl);
      if (rf >>> 12 !== 0) continue;
      const rk = rf & 0xfff, x = rd(b, rs, rs + rl);
      const rec = { if_in: ifIn === 0x3fffffff ? 0 : ifIn, if_out: ifOut === 0x3fffffff ? 0 : ifOut, sampling: rate > 1 ? rate : null, packets: 1 };
      if (rk === 1) {   // raw packet header
        const hp = x.u32(), frame = x.u32(); x.u32(); const hl = x.u32();
        if (hl > rl - 16) throw bad('sFlow: header length past the record');
        const h = b.subarray(x.at(), x.at() + hl);
        rec.bytes = frame;
        if (!parseSampledHeader(hp, h, rec)) { out.invalid++; continue; }
      } else if (rk === 3) {   // sampled IPv4
        rec.bytes = x.u32(); rec.proto = x.u32(); x.skip(8); const p = x.at() - 8; rec.src = ip4(b, p); rec.dst = ip4(b, p + 4);
        rec.sport = x.u32(); rec.dport = x.u32(); rec.tcp_flags = x.u32(); rec.tos = x.u32();
      } else if (rk === 4) {   // sampled IPv6
        rec.bytes = x.u32(); rec.proto = x.u32(); x.skip(32); const p = x.at() - 32; rec.src = ip6(b, p); rec.dst = ip6(b, p + 16);
        rec.sport = x.u32(); rec.dport = x.u32(); rec.tcp_flags = x.u32(); rec.tos = x.u32();
      } else continue;   // switch / router / gateway / user records: not needed for the 5-tuple
      finish(rec, out);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------- entry point
function decode(buf, ctx) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) throw bad('datagram too short');
  if (buf.length > 65535) throw bad('datagram too long');
  const v = buf.readUInt16BE(0);
  if (v === 5) return decodeV5(buf);
  if (v === 9) return decodeV9orIpfix(buf, false, ctx);
  if (v === 10) return decodeV9orIpfix(buf, true, ctx);
  if (v === 0 && buf.readUInt32BE(0) === 5) return decodeSflow(buf);
  throw bad('unknown export version ' + v);
}

module.exports = { decode, createTemplateCache, FlowDecodeError, ip4, ip6, uint, parseSampledHeader, LIMITS: { MAX_FIELDS, MAX_RECORDS, MAX_SFLOW_SAMPLES, MAX_SFLOW_RECORDS } };
