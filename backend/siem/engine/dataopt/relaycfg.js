// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Optimizer — relay enforcement compiler (DATAOPT.md "Enforcement" → relay). Compiles a pipeline into the small
 * JSON subset the relay can run BEFORE egress — no ClickHouse-side actions, no secrets, no detection logic.
 *
 * The relay sees only the envelope, not parsed events. A rule is relay-eligible only when every match leaf references a
 * relay-knowable field and its action is one the relay can do:
 *   fields: raw (the line), proto, peer, file_type, host, path, relay  (also accept the "relay."/"_relay." prefix)
 *   ops: eq/in/neq/contains/startswith/endswith/re/exists  (on raw/peer/… — no cidr/numeric here; those need parsing)
 *   actions: drop, sample {rate}, trim {truncate:{raw:len}}, forward {host, port, proto}  (forward only to an inline
 *            cleartext syslog target — a destination with NO stored credentials; otherwise forward stays ingest-only).
 *
 *   compileRelayPipeline(def, { resolveDest?, tzOffsetMin? }) → { version, etag, generated_at, rules:[…], excluded:[…] }
 */
const crypto = require('node:crypto');

const RELAY_FIELDS = new Set(['raw', 'proto', 'peer', 'file_type', 'host', 'path', 'relay']);
const RELAY_OPS = new Set(['eq', 'in', 'neq', 'contains', 'startswith', 'endswith', 're', 'exists']);

function canonField(f) {
  if (typeof f !== 'string') return null;
  let x = f;
  if (x.startsWith('_relay.')) x = x.slice(7);
  else if (x.startsWith('relay.')) x = x.slice(6);
  return RELAY_FIELDS.has(x) ? x : null;
}

// Returns a rewritten match (relay field names) or null if any leaf is not relay-eligible.
function rewriteMatch(m) {
  if (m === undefined || m === null) return null;
  if (Array.isArray(m)) return rewriteMatch({ all: m });
  if (typeof m !== 'object') return null;
  if (m.field !== undefined || m.op !== undefined) {
    const f = canonField(m.field);
    if (!f || !RELAY_OPS.has(m.op)) return null;
    const out = { field: f, op: m.op, value: m.value };
    if (m.not === true) out.not = true;
    return out;
  }
  const out = {};
  for (const k of ['all', 'any', 'none']) {
    if (!m[k]) continue;
    if (!Array.isArray(m[k])) return null;
    const arr = [];
    for (const x of m[k]) { const r = rewriteMatch(x); if (!r) return null; arr.push(r); }
    out[k] = arr;
  }
  if (!out.all && !out.any && !out.none) return null;
  return out;
}

function compileRelayPipeline(def, opts = {}) {
  const resolveDest = opts.resolveDest || (() => null);
  const rules = [];
  const excluded = [];
  for (const r of (def && Array.isArray(def.rules) ? def.rules : [])) {
    if (!r || r.enabled === false) continue;
    const action = String(r.action || 'keep').toLowerCase().replace(/^route:/, '');
    const match = rewriteMatch(r.match);
    if (!match) { if (r.id) excluded.push({ id: r.id, reason: 'match uses fields the relay cannot see (runs at ingest)' }); continue; }
    if (action === 'drop') { rules.push({ id: r.id, action: 'drop', match, reason: r.reason || '', stub: r.stub !== false }); }
    else if (action === 'sample') {
      const rate = Number(r.rate !== undefined ? r.rate : r.sample);
      if (!(rate > 0 && rate <= 1)) { excluded.push({ id: r.id, reason: 'invalid sample rate' }); continue; }
      rules.push({ id: r.id, action: 'sample', match, rate });
    } else if (action === 'trim') {
      const t = (r.truncate && typeof r.truncate === 'object') ? r.truncate : {};
      const rawLen = Number(t.raw);
      if (!(rawLen > 0)) { excluded.push({ id: r.id, reason: 'relay trim can only truncate raw (set truncate.raw)' }); continue; }
      rules.push({ id: r.id, action: 'trim', match, truncate: { raw: rawLen } });
    } else if (action === 'forward') {
      const d = resolveDest(r.destination);
      if (d && d.kind === 'syslog' && d.host && !(d.credentials && d.credentials.set)) {
        rules.push({ id: r.id, action: 'forward', match, forward: { host: d.host, port: Number(d.port) || 514, proto: d.proto || 'udp' } });
      } else { excluded.push({ id: r.id, reason: 'forward target needs credentials or is not an inline cleartext syslog target — kept ingest-only' }); }
    } else {
      excluded.push({ id: r.id, reason: `action ${action} runs at ingest only` });
    }
  }
  const payload = { version: (def && def.version) || 1, pipeline_id: def && def.id, rules };
  const etag = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex').slice(0, 16);
  return { version: payload.version, pipeline_id: payload.pipeline_id, etag, generated_at: Date.now(), rules, excluded };
}

module.exports = { compileRelayPipeline, rewriteMatch, RELAY_FIELDS, RELAY_OPS };
