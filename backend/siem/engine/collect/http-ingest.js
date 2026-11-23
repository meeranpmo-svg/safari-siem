// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// HTTP(S) ingest: POST /ingest/<src_id>   (behind nginx at /ingest/, or directly on the API port)
//   Header  X-Sentra-Token: <token>   — compared (constant time, sha256 digests + crypto.timingSafeEqual) with
//           secrets.ingest_tokens[src_id]   (or sources[].token from config as a fallback)
//   Body    NDJSON (one JSON object or raw text line per line) or a JSON array (objects or strings); max 5 MB.
//           Content-Encoding: gzip accepted (decompressed size capped by ingest.max_decompressed_mb).
//   Reply   {ok: true, accepted, rejected, errors: [first 5]}
//   De-duplication: an optional X-Sentra-Batch-Id header (sent by the Windows agent on every POST, re-sent on retries) is
//           remembered per src_id (bounded LRU: 50k ids, 24 h). A repeated id → {ok: true, duplicate: true} and nothing is
//           re-ingested.
// Events get collector "agent" for windows sources (our Windows agent), "http" otherwise.
// Relay sources (sources[].type "relay", relay/sentra-relay.js): the token may only submit relay envelopes
//   {"_relay":{peer, proto, at, relay, file_type?, path?, host?},"raw":"<line>"} — see relay-ingest.js. Each envelope is
//   processed as if the built-in syslog listener had received it from _relay.peer (or, for file items, by the Exchange
//   message tracking / IIS parsers), collector "relay:<relay id>". Envelopes whose peer is outside the relay's
//   allowed_peers are rejected (counted in `rejected`, reason in `errors`). Envelopes sent with a NON-relay token are
//   treated like any other JSON object (no peer spoofing).
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { createSourceMap } = require('./sources');
const { createRelayIngest } = require('./relay-ingest');

const ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const BATCH_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const DEDUP_MAX = 50000;
const DEDUP_TTL_MS = 24 * 3600 * 1000;
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const DUMMY = sha('sentra-siem-no-token');

// expected is either the clear token (install/sentra-siem-token) or "sha256:<hex>" — the digest stored by the
// self-service Connect hub (engine/onboard/store.js); both are compared in constant time against sha256(given).
const DIGEST_RE = /^sha256:([0-9a-f]{64})$/i;
function tokenOk(given, expected) {
  if (typeof expected !== 'string' || !expected) { crypto.timingSafeEqual(sha(given || ''), DUMMY); return false; }
  const m = DIGEST_RE.exec(expected);
  return crypto.timingSafeEqual(sha(given || ''), m ? Buffer.from(m[1], 'hex') : sha(expected));
}

function createHttpIngest({ config, parser, pipeline, log, getRelayConfig }) {
  const ic = config.ingest || {};
  const maxItems = ic.max_items || 50000;
  const maxInflate = (ic.max_decompressed_mb || 20) * 1024 * 1024;
  let sources = createSourceMap(config.sources || [], {});
  let relay = createRelayIngest({ config, parser, pipeline, log });
  const st ={ requests: 0, accepted: 0, rejected: 0, auth_failures: 0, bad_requests: 0, duplicates: 0, by_source: {} };
  const seen = new Map(); // src_id → Map(batch_id → ts)  (insertion order = age → cheap LRU eviction)

  function isDuplicate(srcId, batchId, now) {
    const m = seen.get(srcId);
    if (!m) return false;
    const t = m.get(batchId);
    return t !== undefined && now - t < DEDUP_TTL_MS;
  }
  function remember(srcId, batchId, now) {
    let m = seen.get(srcId);
    if (!m) { m = new Map(); seen.set(srcId, m); }
    m.delete(batchId);
    m.set(batchId, now);
    while (m.size > DEDUP_MAX) m.delete(m.keys().next().value);
    for (const [k, t] of m) { if (now - t < DEDUP_TTL_MS) break; m.delete(k); } // drop expired from the old end
  }

  // Runs from the headers alone, BEFORE the server reads the body: an unauthenticated client cannot make the engine
  // buffer up to max_mb per request. Returns true when the request may continue.
  function preAuth(ctx) {
    st.requests++;
    const srcId = ctx.params.src_id;
    if (!ID_RE.test(srcId || '')) { st.bad_requests++; ctx.fail(400, 'invalid source id'); return false; }
    const src = sources.byId(srcId);
    const tokens = (config.secrets && config.secrets.ingest_tokens) || {};
    const expected = tokens[srcId] || (src && src.token) || '';
    if (!tokenOk(ctx.headers['x-sentra-token'], expected)) {
      st.auth_failures++;
      if (log) log.every('ingest-auth-' + srcId, 60000, 'warn', 'ingest: rejected token', { src_id: srcId, ip: ctx.ip });
      ctx.fail(401, 'invalid or missing X-Sentra-Token');
      return false;
    }
    return true;
  }

  function handler(ctx) {
    const srcId = ctx.params.src_id;
    const src = sources.byId(srcId);
    const rawBatch = ctx.headers['x-sentra-batch-id'];
    const batchId = typeof rawBatch === 'string' && BATCH_ID_RE.test(rawBatch) ? rawBatch : '';
    if (rawBatch !== undefined && !batchId) { st.bad_requests++; return ctx.fail(400, 'invalid X-Sentra-Batch-Id'); }
    if (batchId && isDuplicate(srcId, batchId, Date.now())) {
      st.duplicates++;
      return ctx.ok({ ok: true, duplicate: true, accepted: 0, rejected: 0, errors: [] });
    }
    let buf = ctx.rawBody || Buffer.alloc(0);
    if (/gzip/i.test(ctx.headers['content-encoding'] || '')) {
      try { buf = zlib.gunzipSync(buf, { maxOutputLength: maxInflate }); } catch (e) { st.bad_requests++; return ctx.fail(400, 'invalid gzip body (or larger than ' + (maxInflate >> 20) + ' MB)'); }
    }
    const text = buf.toString('utf8');
    const srcType = (src && src.type) || 'syslog'; // unconfigured source: content sniffing (Windows / M365 / JSON / text formats)
    const collector = (src && src.collector) || (srcType === 'windows' ? 'agent' : 'http');
    const tz = src && src.tz_offset_min !== undefined ? src.tz_offset_min : (config.syslog && config.syslog.tz_offset_min) || 0;
    const rts = Date.now();
    const errors = [];
    let accepted = 0;
    let rejected = 0;
    let lastReject = '';
    const reject = (why) => { rejected++; lastReject = why; if (errors.length < 5) errors.push(why); };
    const isRelay = !!(src && src.type === 'relay');
    let idx = 0; // item index (array position / line number - 1) for error messages
    const emitOne = isRelay
      ? (line, obj) => { const i = idx; if (relay.handle(src, obj, (why) => reject(`item ${i}: ${why}`))) accepted++; }
      : (line, obj) => {
        const ev = parser.parse(line, { collector, src_id: srcId, src_type: srcType, peer_ip: ctx.ip, rts, tz_offset_min: tz, obj });
        pipeline.emit(ev);
        accepted++;
      };

    const first = text.search(/\S/);
    if (first < 0) { if (batchId) remember(srcId, batchId, rts); return ctx.ok({ ok: true, accepted: 0, rejected: 0, errors: [] }); }
    if (text[first] === '[') {
      let arr;
      try { arr = JSON.parse(text); } catch (e) { st.bad_requests++; return ctx.fail(400, 'invalid JSON array: ' + e.message.slice(0, 120)); }
      if (!Array.isArray(arr)) { st.bad_requests++; return ctx.fail(400, 'expected a JSON array'); }
      if (arr.length > maxItems) { st.bad_requests++; return ctx.fail(413, `too many items (max ${maxItems})`); }
      for (let i = 0; i < arr.length; i++) {
        const it = arr[i];
        idx = i;
        if (typeof it === 'string') { if (it) emitOne(it, undefined); else reject(`item ${i}: empty string`); }
        else if (it && typeof it === 'object' && !Array.isArray(it)) emitOne(JSON.stringify(it), it);
        else reject(`item ${i}: expected object or string`);
      }
    } else {
      let n = 0;
      let start = 0;
      while (start <= text.length) {
        let nl = text.indexOf('\n', start);
        if (nl < 0) nl = text.length;
        let line = text.slice(start, nl);
        start = nl + 1;
        if (line.endsWith('\r')) line = line.slice(0, -1);
        if (!line.trim()) { if (start > text.length) break; continue; }
        if (++n > maxItems) { reject(`more than ${maxItems} lines; rest ignored`); break; }
        idx = n - 1;
        let obj;
        if (line[0] === '{') { try { obj = JSON.parse(line); } catch { obj = undefined; } }
        emitOne(line, obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : undefined);
      }
    }
    st.accepted += accepted;
    st.rejected += rejected;
    const b = st.by_source[srcId] || (st.by_source[srcId] = { requests: 0, accepted: 0, rejected: 0, last_seen: 0 });
    b.requests++; b.accepted += accepted; b.rejected += rejected; b.last_seen = rts;
    if (isRelay) {
      relay.batchDone(srcId, accepted, rejected, lastReject);
      const pc = ctx.headers['x-sentra-pipeline-counters'];
      if (pc && typeof relay.recordPipelineCounters === 'function') { try { relay.recordPipelineCounters(srcId, JSON.parse(pc)); } catch { /* ignore malformed */ } }
    }
    if (batchId) remember(srcId, batchId, rts);
    const reply = { ok: true, accepted, rejected, errors };
    // Data Optimizer: deliver the compiled relay pipeline on the relay's existing config-pull channel (the ingest reply).
    // The relay sends its current etag via X-Sentra-Pipeline-Etag; the full pipeline is returned only when it differs.
    if (isRelay && typeof getRelayConfig === 'function') {
      try {
        const cfg2 = getRelayConfig();
        if (cfg2) {
          reply.pipeline_etag = cfg2.etag || '';
          const have = ctx.headers['x-sentra-pipeline-etag'];
          if ((have || '') !== (cfg2.etag || '')) reply.pipeline = { version: cfg2.version, etag: cfg2.etag || '', rules: cfg2.rules || [] };
        }
      } catch (e) { if (log) log.every('ingest-relaycfg', 60000, 'warn', 'ingest: relay pipeline config unavailable', { err: e.message }); }
    }
    return ctx.ok(reply);
  }

  function register(api) {
    api.route('POST', '/ingest/:src_id', handler, { raw: true, maxBody: (ic.max_mb || 5) * 1024 * 1024, preAuth });
  }

  // relayStats(): [{relay_id, collector:"relay:<id>", last_batch, batches, events, rejected, eps_1m, peers_seen, peers[], files[]}]
  // reload(): rebuild the source maps from config.sources after the Connect hub edited them in place (no restart)
  function reload() { sources = createSourceMap(config.sources || [], {}); relay = createRelayIngest({ config, parser, pipeline, log }); }
  // the exported handler authenticates by itself (the registered route authenticates in preAuth, before the body)
  return { handler: (ctx) => (preAuth(ctx) ? handler(ctx) : undefined), register, stats: () => ({ ...st }), relayStats: () => relay.stats(), reload, tokenOk };
}

module.exports = { createHttpIngest, tokenOk };
