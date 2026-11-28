// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// POST /api/soc/lr/alarms   (operator) — manual import of LogRhythm alarms for the parallel-run comparison.
// Body: JSON array, {alarms: [...]}, or NDJSON. Each item is either
//   simple:  {ts, alarm_name, rule_id?, host?, user?, src_ip?, dst_ip?, severity? (0-4), priority? (LR 0-100), alarm_id?}
//   native:  the LogRhythm Alarm API shape understood by engine/soc/lrcompare.js ({alarm_id, alarm_rule_name, alarm_date, …})
// Every item becomes alerts.raise(partial) with partial.source = 'logrhythm' (ARCH alert interface). Items already imported
// (same LR alarm id; for simple items a stable hash of ts|alarm_name|rule_id|host|user|src_ip) are skipped.
// This route is registered before engine/soc/routes.js, so it also serves the native shape that module documents.
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const { parseTimeValue } = require('./query');

const MAX_ITEMS = 10000;

function loadLrCompare() {
  const f = path.join(__dirname, '..', 'soc', 'lrcompare.js');
  if (!fs.existsSync(f)) return null;
  try { return require(f); } catch { return null; }
}

function parseItems(buf) {
  const text = (buf || Buffer.alloc(0)).toString('utf8').trim();
  if (!text) return [];
  if (text[0] === '[' || text[0] === '{') {
    try {
      const j = JSON.parse(text);
      if (Array.isArray(j)) return j;
      if (j && Array.isArray(j.alarms)) return j.alarms;
      if (j && typeof j === 'object') return [j];
    } catch { if (text[0] === '[') throw Object.assign(new Error('invalid JSON array'), { status: 400 }); }
  }
  return text.split('\n').map((l) => l.trim()).filter(Boolean).map((l, i) => {
    try { return JSON.parse(l); } catch { throw Object.assign(new Error(`line ${i + 1}: invalid JSON`), { status: 400 }); }
  });
}

function toNative(it) {
  if (it && it.alarm_id !== undefined && it.alarm_rule_name) return { native: it, severity: undefined };
  if (!it || typeof it !== 'object') throw new Error('item must be an object');
  if (!it.alarm_name) throw new Error('alarm_name required');
  if (it.ts === undefined || it.ts === null || it.ts === '') throw new Error('ts required');
  const ts = parseTimeValue(it.ts);
  const id = it.alarm_id !== undefined && it.alarm_id !== '' ? String(it.alarm_id)
    : 'm-' + crypto.createHash('sha256').update([ts, it.alarm_name, it.rule_id, it.host, it.user, it.src_ip].map((x) => (x === undefined ? '' : String(x))).join('|')).digest('hex').slice(0, 20);
  const sev = it.severity === undefined || it.severity === '' ? undefined : Math.max(0, Math.min(4, Math.trunc(Number(it.severity)) || 0));
  return {
    native: {
      alarm_id: id, alarm_rule_name: String(it.alarm_name), alarm_rule_id: it.rule_id !== undefined ? String(it.rule_id) : undefined,
      alarm_date: new Date(ts).toISOString(), host: it.host, user: it.user, src_ip: it.src_ip, dst_ip: it.dst_ip,
      priority: it.priority !== undefined ? Number(it.priority) : undefined, event_count: it.event_count, mitre: it.mitre,
    },
    severity: sev,
  };
}

function fallbackPartial(n) {
  const at = Date.parse(n.alarm_date);
  const group = {};
  for (const k of ['user', 'src_ip', 'dst_ip', 'host']) if (n[k]) group[k] = String(n[k]).trim();
  return {
    rule_id: `LR-${n.alarm_rule_id || n.alarm_rule_name}`, rule_name: String(n.alarm_rule_name), rule_type: 'logrhythm', severity: 2,
    mitre: Array.isArray(n.mitre) ? n.mitre.map(String) : [], group, group_key: `lr:${n.alarm_id}`, count: 1, ts_first: at, ts_last: at,
    sample_event_ids: [], summary: `LogRhythm: ${n.alarm_rule_name}`, source: 'logrhythm', lr_alarm_id: String(n.alarm_id), suppress_s: 0,
  };
}

function loadCollectorHealth() {
  try { return require('../soc/collector-health'); } catch { return null; }
}

function register(api, { alerts, log, state, config } = {}) {
  const lrc = loadLrCompare();
  const chMod = loadCollectorHealth();
  // Collector-health flood remediation (LogRhythm parallel-run noise). Needs state for the operator setting + health view.
  let health = null;
  if (state && chMod && typeof chMod.createCollectorHealth === 'function') {
    try { health = chMod.createCollectorHealth({ state, config }); } catch (e) { if (log) log.warn('collector-health init failed', { err: e.message }); }
  }
  api.route('POST', '/api/soc/lr/alarms', (ctx) => {
    ctx.need('operator');
    if (!alerts || typeof alerts.raise !== 'function') return ctx.fail(503, 'SOC alerts module not loaded');
    const items = parseItems(ctx.rawBody);
    if (!items.length) return ctx.fail(400, 'no alarms in body (JSON array, {alarms:[…]} or NDJSON)');
    if (items.length > MAX_ITEMS) return ctx.fail(413, `at most ${MAX_ITEMS} alarms per request`);
    let known;
    try {
      const all = typeof alerts.all === 'function' ? alerts.all((a) => a.source === 'logrhythm') : (alerts.list({ source: 'logrhythm', limit: 1e9 }).items || []);
      known = new Set(all.map((a) => String(a.lr_alarm_id)));
    } catch { known = new Set(); }
    const out = { ok: true, imported: 0, skipped: 0, health: 0, suppressed_health: 0, errors: [] };
    items.forEach((it, i) => {
      try {
        const { native, severity } = toNative(it);
        // Collapse LogRhythm collector self-diagnostics into one aggregated low-severity health signal per failing source.
        const h = health ? health.ingest(native) : { action: 'passthrough' };
        if (h.action === 'suppress') { out.suppressed_health++; return; }
        let p;
        if (h.action === 'aggregate') {
          p = h.partial; // low-severity, operational, group_key per failing source; alerts.raise() dedupes/aggregates
        } else {
          p = lrc && typeof lrc.lrAlarmToPartial === 'function' ? lrc.lrAlarmToPartial(native) : fallbackPartial(native);
          if (severity !== undefined) p.severity = severity;
        }
        p.source = 'logrhythm';
        if (known.has(String(p.lr_alarm_id))) { out.skipped++; return; }
        alerts.raise(p);
        known.add(String(p.lr_alarm_id));
        if (h.action === 'aggregate') out.health++; else out.imported++;
      } catch (e) {
        if (out.errors.length < 50) out.errors.push(`item ${i}: ${e.message}`);
      }
    });
    ctx.audit('lr.import', `${items.length} alarms`, { imported: out.imported, skipped: out.skipped, health: out.health, suppressed_health: out.suppressed_health, errors: out.errors.length });
    if (log && (out.imported || out.health)) log.info('lr: alarms imported', { imported: out.imported, health: out.health, suppressed_health: out.suppressed_health, skipped: out.skipped, by: ctx.user });
    return out;
  }, { raw: true, maxBody: 20 * 1024 * 1024 });

  // Rolled-up collector-health view + operator mode control (only when state is available).
  if (health) {
    api.route('GET', '/api/soc/lr/collector-health', (ctx) => {
      if (typeof ctx.need === 'function') ctx.need('viewer');
      return ctx.ok ? ctx.ok({ mode: health.getMode(), modes: health.MODES, sources: health.view() }) : { mode: health.getMode(), modes: health.MODES, sources: health.view() };
    });
    api.route('POST', '/api/soc/lr/collector-health/mode', (ctx) => {
      ctx.need('admin');
      let body = ctx.body;
      if ((body === undefined || body === null) && ctx.rawBody) { try { body = JSON.parse(ctx.rawBody.toString('utf8') || '{}'); } catch { body = {}; } }
      const mode = body && body.mode;
      try { health.setMode(mode, ctx.user); } catch (e) { return ctx.fail(e.status || 400, e.message); }
      ctx.audit('lr.collector_health.mode', mode, { by: ctx.user });
      return ctx.ok ? ctx.ok({ ok: true, mode: health.getMode() }) : { ok: true, mode: health.getMode() };
    }, { raw: true });
  }
}

module.exports = { register, toNative, parseItems };
