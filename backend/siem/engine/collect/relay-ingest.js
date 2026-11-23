// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Relay envelopes (relay/sentra-relay.js, agentless collection inside the customer network) arriving on the HTTPS ingest.
//
// A relay is a configured source  {"id":"as-relay-01","type":"relay","allowed_peers":["10.10.0.0/16", …],
//                                  "file_sources"?: {"exchange-msgtrk":"exchange-onprem","iis":"exchange-iis","text":"relay-files"}}
// with its own token (secrets.ingest_tokens[<relay id>]). A relay token may ONLY submit envelopes:
//   {"_relay":{"peer":"<sender ip>","proto":"udp|tcp|tls|file","at":<ms>,"relay":"<relay id>",
//              "file_type"?: "exchange-msgtrk|iis|text","path"?: "...","host"?: "<origin host>",
//              "truncated"?: 1, "replay"?: 1},"raw":"<line>"}
//   - syslog items (udp/tcp/tls) are handled exactly as if the engine's own syslog listener had received `raw` from
//     `peer`: source mapping (config.sources match ip/cidr, else syslog.default_sources) by the ORIGINAL sender IP,
//     same parser chain (syslog / CEF / LEEF / FortiGate / Cisco / Linux …), host_ip = peer.
//   - file items go to the Exchange message tracking / IIS parsers (or content sniffing for "text"); host = _relay.host;
//     src_id = file_sources[file_type] or "<relay id>-msgtrk" / "-iis" / "-files". #Fields headers are learned per
//     file (parser meta.stream = "<host>|<path>"). Items with replay:1 are header lines the relay re-sends so a restarted
//     engine re-learns the field layout: parsed (learned) but not stored again.
//   - every event gets collector "relay:<relay id>"; `at` (receive time on the relay) is used as rts.
//   - scope: a non-empty peer must be inside allowed_peers (no allowed_peers → every syslog envelope is rejected).
//     File items may carry an empty peer (the relay read the file itself).
const net = require('node:net');
const { createSourceMap, normPeer } = require('./sources');

const PROTOS = new Set(['udp', 'tcp', 'tls', 'file']);
const FILE_TYPES = { 'exchange-msgtrk': { type: 'exchange', suffix: 'msgtrk' }, iis: { type: 'iis', suffix: 'iis' }, text: { type: '', suffix: 'files' } };
const MAX_PEERS = 2000;
const MAX_FILES = 2000;
const MAX_RAW = 65536;
const MAX_SKEW_PAST_MS = 30 * 24 * 3600 * 1000; // a relay spool can hold days of backlog
const MAX_SKEW_FUTURE_MS = 5 * 60 * 1000;

function compileCidrs(list) {
  const out = [];
  for (const c of [].concat(list || [])) {
    const s = String(c).trim();
    const [addr, bitsRaw] = s.split('/');
    const fam = net.isIP(addr);
    if (!fam) continue;
    const bits = bitsRaw === undefined ? (fam === 4 ? 32 : 128) : Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0 || bits > (fam === 4 ? 32 : 128)) continue;
    const bl = new net.BlockList();
    bl.addSubnet(addr, bits, fam === 4 ? 'ipv4' : 'ipv6');
    out.push({ bl, fam });
  }
  return out;
}

function createRelayIngest({ config, parser, pipeline, log }) {
  const all = config.sources || [];
  const syslogSources = createSourceMap(all.filter((s) => s && s.type !== 'relay'), (config.syslog && config.syslog.default_sources) || {});
  const byId = new Map(all.map((s) => [s.id, s]));
  const scopes = new Map(); // relay id → compiled allowed_peers
  const relays = new Map(); // relay id → live stats
  const sysTz = (config.syslog && config.syslog.tz_offset_min) || 0;

  function scope(src) {
    let s = scopes.get(src.id);
    if (!s) { s = compileCidrs(src.allowed_peers); scopes.set(src.id, s); }
    return s;
  }
  function peerAllowed(src, ip) {
    const fam = net.isIP(ip);
    if (!fam) return false;
    for (const c of scope(src)) if (c.fam === fam && c.bl.check(ip, fam === 4 ? 'ipv4' : 'ipv6')) return true;
    return false;
  }

  function rs(id) {
    let r = relays.get(id);
    if (!r) {
      r = { relay_id: id, first_seen: Date.now(), last_batch: 0, batches: 0, events: 0, rejected: 0, header_replays: 0, last_rejection: '', min: 0, cur: 0, prev: 0, peers: new Map(), files: new Map() };
      relays.set(id, r);
    }
    return r;
  }
  function tick(r, now, n) {
    const m = Math.floor(now / 60000);
    if (m !== r.min) { r.prev = m === r.min + 1 ? r.cur : 0; r.cur = 0; r.min = m; }
    r.cur += n;
  }
  function track(map, key, max, init, now) {
    let p = map.get(key);
    if (!p) {
      if (map.size >= max) map.delete(map.keys().next().value);
      p = { ...init, events: 0, last_seen: 0 };
      map.set(key, p);
    }
    p.events++;
    p.last_seen = now;
    return p;
  }

  // One envelope. Returns true when accepted (emitted or learned), false when rejected (reason via reject()).
  function handle(src, obj, reject) {
    const r = obj && obj._relay;
    if (!r || typeof r !== 'object' || Array.isArray(r) || typeof obj.raw !== 'string') { reject('relay token may only submit envelopes {"_relay":{…},"raw":"…"}'); return false; }
    let raw = obj.raw;
    if (!raw) { reject('empty raw'); return false; }
    const proto = String(r.proto || '');
    if (!PROTOS.has(proto)) { reject('invalid _relay.proto'); return false; }
    const peer = r.peer === undefined || r.peer === null ? '' : normPeer(r.peer);
    if (peer && !net.isIP(peer)) { reject('invalid _relay.peer'); return false; }
    if (proto !== 'file' && !peer) { reject('missing _relay.peer'); return false; }
    if (peer && !peerAllowed(src, peer)) {
      const why = (src.allowed_peers && [].concat(src.allowed_peers).length) ? `peer ${peer} outside allowed_peers of relay ${src.id}` : `relay ${src.id} has no allowed_peers configured`;
      if (log) log.every('relay-scope-' + src.id, 60000, 'warn', 'relay: envelope rejected (peer scope)', { relay: src.id, peer });
      reject(why);
      return false;
    }
    const now = Date.now();
    const at = Number(r.at);
    const rts = Number.isFinite(at) && at > now - MAX_SKEW_PAST_MS && at < now + MAX_SKEW_FUTURE_MS ? Math.floor(at) : now;
    let truncated = !!r.truncated;
    if (raw.length > MAX_RAW) { raw = raw.slice(0, MAX_RAW); truncated = true; }
    const collector = 'relay:' + src.id;
    const st = rs(src.id);
    let meta;
    let host = '';
    let filePath = '';
    if (proto === 'file') {
      const ft = FILE_TYPES[String(r.file_type || '')];
      if (!ft) { reject('invalid _relay.file_type'); return false; }
      host = String(r.host || '').trim().toLowerCase().slice(0, 255);
      filePath = String(r.path || '').slice(0, 1024);
      const map = (src.file_sources && typeof src.file_sources === 'object') ? src.file_sources : {};
      const srcId = typeof map[r.file_type] === 'string' && map[r.file_type] ? map[r.file_type] : `${src.id}-${ft.suffix}`;
      const cfg = byId.get(srcId);
      const srcType = ft.type || (cfg && cfg.type && cfg.type !== 'relay' ? cfg.type : 'syslog');
      const tz = ft.type ? 0 : (cfg && cfg.tz_offset_min !== undefined ? cfg.tz_offset_min : sysTz); // W3C / message tracking times are UTC
      meta = { collector, src_id: srcId, src_type: srcType, peer_ip: peer, rts, tz_offset_min: tz, stream: `${host}|${filePath}` };
      track(st.files, `${host}|${filePath}`, MAX_FILES, { host, path: filePath, file_type: String(r.file_type), src_id: srcId }, now);
    } else {
      const s = syslogSources.lookup(peer, 'syslog-' + proto);
      meta = { collector, src_id: s.id, src_type: s.type || 'syslog', peer_ip: peer, rts, tz_offset_min: s.tz_offset_min !== undefined ? s.tz_offset_min : sysTz };
      track(st.peers, `${proto}|${peer}`, MAX_PEERS, { peer, proto, src_id: s.id }, now);
    }
    if (proto === 'udp') { raw = raw.replace(/[\r\n\0]+$/, ''); if (!raw) { reject('empty raw'); return false; } }
    const ev = parser.parse(raw, meta);
    if (r.replay) { st.header_replays++; return true; } // header re-sent for learning only — already stored once
    if (host) ev.host = host;
    if (filePath) ev.fields.log_file = filePath;
    if (truncated) ev.fields.truncated = '1';
    pipeline.emit(ev);
    st.events++;
    tick(st, now, 1);
    return true;
  }

  function batchDone(srcId, accepted, rejected, lastReject) {
    const st = rs(srcId);
    st.batches++;
    st.last_batch = Date.now();
    st.rejected += rejected;
    if (rejected) st.last_rejection_at = st.last_batch;
    if (lastReject) st.last_rejection = lastReject;
  }

  // Data Optimizer: the relay reports its own drop/keep counters (X-Sentra-Pipeline-Counters) so the portal can show edge
  // enforcement. Stored as-is (opaque, bounded) and surfaced in stats().
  function recordPipelineCounters(srcId, obj) {
    if (!obj || typeof obj !== 'object') return;
    const st = rs(srcId);
    const pick = (k) => (Number.isFinite(Number(obj[k])) ? Number(obj[k]) : 0);
    st.pipeline = { version: obj.version || 0, etag: String(obj.etag || '').slice(0, 32), rules: pick('rules'), kept: pick('kept'), dropped: pick('dropped'), sampled_out: pick('sampled_out'), trimmed: pick('trimmed'), forwarded: pick('forwarded'), at: Date.now() };
  }

  function stats() {
    const now = Date.now();
    const m = Math.floor(now / 60000);
    const out = [];
    for (const r of relays.values()) {
      const lastMin = r.min === m ? r.prev : (r.min === m - 1 ? r.cur : 0);
      const peers = [...r.peers.values()].sort((a, b) => b.last_seen - a.last_seen).slice(0, 200);
      const files = [...r.files.values()].sort((a, b) => b.last_seen - a.last_seen).slice(0, 200);
      out.push({
        relay_id: r.relay_id, collector: 'relay:' + r.relay_id, first_seen: r.first_seen, last_batch: r.last_batch || null,
        batches: r.batches, events: r.events, rejected: r.rejected, header_replays: r.header_replays, last_rejection: r.last_rejection || undefined, last_rejection_at: r.last_rejection_at || null,
        eps_1m: Math.round((lastMin / 60) * 100) / 100, peers_seen: r.peers.size, files_seen: r.files.size, peers, files,
        pipeline: r.pipeline || null,
      });
    }
    return out;
  }

  return { handle, batchDone, recordPipelineCounters, stats, peerAllowed };
}

module.exports = { createRelayIngest, compileCidrs, FILE_TYPES };
