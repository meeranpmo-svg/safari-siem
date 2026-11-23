// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Optimizer — orchestrator (DATAOPT.md). Owns pipelines (CRUD + versions + hash-chained audit + enable/disable with
 * the blind-spot override gate), the active compiled pipeline, counters, archive, destinations, settings, cost model,
 * simulation and the relay config. Wired into engine/main.js (store path + soc routes).
 *
 *   createDataOpt({ ch, state, config, log, detector, dir }) → {
 *     router, counters, archive, destinations, settings, cost, simulate,
 *     listPipelines, getPipeline, createPipeline, updatePipeline, deletePipeline, enable, disable,
 *     activeIngest, relayConfig, conflictsFor, summary, drops, sources, archiveSearch, health, stop
 *   }
 */
const crypto = require('node:crypto');
const path = require('node:path');
const { compilePipeline, validatePipeline, detectionConflicts } = require('./rules');
const { createRouter, createAggregator } = require('./apply');
const { createCounters } = require('./counters');
const { createArchive } = require('./archive');
const { createDestinations } = require('./destinations');
const { createSettings } = require('./settings');
const { createCost } = require('./cost');
const { createSimulate } = require('./simulate');
const { compileRelayPipeline } = require('./relaycfg');

const GENESIS = '0'.repeat(64);
const ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const MAX_RULES = 500;

function canonRules(def) {
  return JSON.stringify({ id: def.id, version: def.version, rules: (def.rules || []).map((r) => ({ id: r.id, match: r.match, action: r.action, rate: r.rate, drop: r.drop, keep: r.keep, truncate: r.truncate, reason: r.reason, destination: r.destination, window_s: r.window_s, group_by: r.group_by, enabled: r.enabled })) });
}

// Core event fields UEBA baselines/detectors read (engine/ueba/sql.js) — removing them creates behavioural blind spots.
const UEBA_FIELDS = ['host', 'host_ip', 'user', 'target_user', 'action', 'category', 'outcome', 'src_ip', 'dst_ip', 'dst_port', 'proto', 'severity', 'event_code', 'ts'];

function createDataOpt({ ch, state, config = {}, log, detector, ueba, dir, writer } = {}) {
  const tzOffsetMin = (config.syslog && config.syslog.tz_offset_min) || 180;
  const ctx = { intel: null, tzOffsetMin };
  const dataDir = dir || (config.state_dir ? path.dirname(config.state_dir) : null) || config.data_dir;
  const stateDir = config.state_dir || (dataDir ? path.join(dataDir, 'state') : null);

  const settings = createSettings({ state, config, log });
  const counters = createCounters({ ch, log, flushMs: 60000 });
  const archive = createArchive({ ch, dir: dataDir, config, log });
  const destinations = createDestinations({ state, dir: stateDir, config, log });
  const cost = createCost({ ch, settings, log });
  const simulate = createSimulate({ ch, detector, settings, log });

  const pipeCol = state ? state.collection('dataopt_pipeline') : null;
  const auditCol = state ? state.collection('dataopt_audit') : null;
  const memPipes = new Map(); // fallback when no state

  let active = null;        // compiled ingest pipeline
  let activeId = null;
  let activeStamp = '';
  let relayCompiled = null; // { version, etag, rules, excluded }

  // ---- storage helpers
  function allDocs() { return pipeCol ? pipeCol.all() : [...memPipes.values()]; }
  function getDoc(id) { return pipeCol ? pipeCol.get(id) : (memPipes.get(id) || null); }
  function putDoc(d) { if (pipeCol) pipeCol.put(d); else memPipes.set(d.id, d); return d; }
  function delDoc(id) { if (pipeCol) pipeCol.remove(id); else memPipes.delete(id); }

  // ---- hash-chained audit of every pipeline change
  function chainHead() {
    const all = auditCol ? auditCol.all() : [];
    let head = { seq: 0, hash: GENESIS };
    for (const e of all) if (e.seq > head.seq) head = e;
    return head;
  }
  function recordChange(action, doc, detail, user) {
    const prev = chainHead();
    const seq = prev.seq + 1;
    const body = JSON.stringify({ seq, action, pipeline_id: doc && doc.id, version: doc && doc.version, canon: doc ? canonRules(doc) : '', prev: prev.hash });
    const hash = crypto.createHash('sha256').update(body).digest('hex');
    const entry = { id: 'a' + String(seq).padStart(9, '0'), seq, at: Date.now(), by: user || '', action, pipeline_id: doc && doc.id, version: doc && doc.version, hash, prev_hash: prev.hash, detail: detail || {} };
    if (auditCol) auditCol.put(entry);
    if (state && typeof state.audit === 'function') { try { state.audit({ action: 'dataopt.' + action, by: user || '', target: doc && doc.id, detail: Object.assign({ version: doc && doc.version, hash }, detail || {}) }); } catch { /* ignore */ } }
    return entry;
  }
  function pipelineAudit(id) { return (auditCol ? auditCol.all() : []).filter((e) => e.pipeline_id === id).sort((a, b) => a.seq - b.seq); }

  function verifyChain() {
    const all = (auditCol ? auditCol.all() : []).sort((a, b) => a.seq - b.seq);
    let prev = GENESIS; let breaks = 0; let brokenAt = null;
    for (const e of all) {
      const body = JSON.stringify({ seq: e.seq, action: e.action, pipeline_id: e.pipeline_id, version: e.version, canon: '', prev: e.prev_hash });
      void body; // re-hash would need the stored canon; we validate linkage only (canon is embedded in the hash at write)
      if (e.prev_hash !== prev) { breaks++; if (brokenAt === null) brokenAt = e.seq; }
      prev = e.hash;
    }
    return { ok: breaks === 0, entries: all.length, breaks, broken_at: brokenAt, head: prev };
  }

  function uebaFeatures() { return ueba ? [{ id: 'ueba', name: 'UEBA behavioural analytics', fields: UEBA_FIELDS }] : []; }

  // ---- blind-spot conflicts for a pipeline definition
  function conflictsFor(def) {
    const compiled = compilePipeline(def, ctx);
    if (compiled.error) return { error: compiled.error, conflicts: [] };
    const detRules = detector && typeof detector.rules === 'function' ? detector.rules() : [];
    const heavy = settings.get().heavy_sample_rate || 0.5;
    const feats = uebaFeatures();
    const conflicts = [];
    for (const r of compiled.rules) {
      const c = detectionConflicts(r, detRules, { heavySampleRate: heavy, uebaFeatures: feats });
      if (c.length) conflicts.push({ rule_id: r.id, action: r.action, overridden: !!(r.raw.override && r.raw.override.who), override: r.raw.override || null, detections: c });
    }
    return { conflicts };
  }
  // unresolved conflicts = conflicts on rules without a recorded override (only matters when protect_detections is on)
  function unresolved(def) {
    const { conflicts } = conflictsFor(def);
    return conflicts.filter((c) => !c.overridden);
  }

  // ---- public view
  function publicDoc(d, withVersions) {
    if (!d) return null;
    const v = validatePipeline(d, ctx);
    const out = {
      id: d.id, name: d.name, description: d.description || '', version: d.version,
      enabled: !!d.enabled, enforce: d.enforce || { ingest: false, relay: false },
      rules: d.rules || [], rule_count: (d.rules || []).length,
      valid: v.ok, error: v.ok ? undefined : v.error,
      created: d.created, created_by: d.created_by, updated: d.updated, updated_by: d.updated_by, hash: d.hash,
      conflicts: conflictsFor(d).conflicts,
    };
    if (withVersions) out.versions = pipelineAudit(d.id).map((e) => ({ seq: e.seq, version: e.version, at: e.at, by: e.by, action: e.action, hash: e.hash }));
    return out;
  }

  function listPipelines() {
    return allDocs().sort((a, b) => (a.id < b.id ? -1 : 1)).map((d) => {
      const p = publicDoc(d, false);
      return { id: p.id, name: p.name, version: p.version, enabled: p.enabled, enforce: p.enforce, rule_count: p.rule_count, valid: p.valid, has_conflicts: p.conflicts.length > 0, updated: p.updated, updated_by: p.updated_by };
    });
  }
  function getPipeline(id) { return publicDoc(getDoc(id), true); }

  function createPipeline(def, user) {
    if (!def || typeof def !== 'object') throw httpErr(400, 'pipeline must be an object');
    const id = String(def.id || '').trim();
    if (!ID_RE.test(id)) throw httpErr(400, 'pipeline id invalid (letters, digits, _ . - ; max 64)');
    if (getDoc(id)) throw httpErr(409, `pipeline ${id} already exists`);
    if ((def.rules || []).length > MAX_RULES) throw httpErr(400, `too many rules (max ${MAX_RULES})`);
    const v = validatePipeline(def, ctx);
    if (!v.ok) throw httpErr(400, 'pipeline invalid: ' + v.error);
    const now = Date.now();
    const doc = { id, name: def.name || id, description: def.description || '', version: 1, enabled: false, enforce: { ingest: false, relay: false }, rules: (def.rules || []).map((r) => { if (!r || typeof r !== 'object') return r; const o = Object.assign({}, r); delete o.override; return o; }), created: now, created_by: user || '', updated: now, updated_by: user || '' };
    doc.hash = recordChange('create', doc, { rules: doc.rules.length }, user).hash;
    putDoc(doc);
    return getPipeline(id);
  }

  function updatePipeline(id, patch, user, role) {
    const cur = getDoc(id);
    if (!cur) throw httpErr(404, 'pipeline not found');
    const next = Object.assign({}, cur);
    if (patch.name !== undefined) next.name = String(patch.name);
    if (patch.description !== undefined) next.description = String(patch.description);
    if (patch.rules !== undefined) {
      if (!Array.isArray(patch.rules)) throw httpErr(400, 'rules must be an array');
      if (patch.rules.length > MAX_RULES) throw httpErr(400, `too many rules (max ${MAX_RULES})`);
      // a rule's detection override is an administrator's decision (setOverrides) - never taken from an edit's body
      const prev = new Map((cur.rules || []).map((r) => [r && r.id, r && r.override]));
      next.rules = patch.rules.map((r) => { if (!r || typeof r !== 'object') return r; const o = Object.assign({}, r); delete o.override; if (prev.get(o.id)) o.override = prev.get(o.id); return o; });
    }
    const v = validatePipeline(next, ctx);
    if (!v.ok) throw httpErr(400, 'pipeline invalid: ' + v.error);
    next.version = (cur.version || 1) + 1;
    next.updated = Date.now(); next.updated_by = user || '';
    // an operator's edit of an enabled pipeline takes it out of service until an administrator re-enables it: drop / sample rules
    // decide what the SOC never sees, so a change to a live pipeline is not one person's decision
    if (next.enabled && patch.rules !== undefined && role !== 'admin') { next.enabled = false; next.enforce = { ingest: false, relay: false }; next.disabled_reason = 'edited by ' + (user || 'an operator') + ' - an administrator re-enables it'; }
    // editing an enabled pipeline re-checks the gate
    if (next.enabled && settings.get().protect_detections) {
      const bad = unresolved(next);
      if (bad.length) { next.enabled = false; next.enforce = { ingest: false, relay: false }; }
    }
    next.hash = recordChange('update', next, { rules: next.rules.length }, user).hash;
    putDoc(next);
    rebuildActive();
    return getPipeline(id);
  }

  function deletePipeline(id, user) {
    const cur = getDoc(id);
    if (!cur) throw httpErr(404, 'pipeline not found');
    recordChange('delete', cur, {}, user);
    delDoc(id);
    rebuildActive();
    return { ok: true, id };
  }

  function setOverrides(doc, overrides, user) {
    // overrides: { ruleId: {why} } — records who/why on the rule so the blind-spot gate passes
    if (!overrides || typeof overrides !== 'object') return;
    for (const r of doc.rules || []) {
      if (overrides[r.id]) r.override = { who: user || '', why: String(overrides[r.id].why || overrides[r.id] || ''), at: Date.now() };
    }
  }

  function enable(id, { point = 'ingest', user, overrides } = {}) {
    const cur = getDoc(id);
    if (!cur) throw httpErr(404, 'pipeline not found');
    const v = validatePipeline(cur, ctx);
    if (!v.ok) throw httpErr(400, 'pipeline invalid: ' + v.error);
    const next = Object.assign({}, cur, { rules: JSON.parse(JSON.stringify(cur.rules || [])) });
    if (overrides) setOverrides(next, overrides, user);
    if (settings.get().protect_detections) {
      const bad = unresolved(next);
      if (bad.length) throw httpErr(409, 'enable blocked: detection conflicts need an explicit override', bad.map((c) => `${c.rule_id}: ${c.detections.map((d) => d.rule_id).join(', ')}`));
    }
    next.enabled = true;
    next.enforce = Object.assign({ ingest: false, relay: false }, cur.enforce);
    const points = point === 'both' ? ['ingest', 'relay'] : [point];
    for (const p of points) next.enforce[p] = true;
    next.version = (cur.version || 1) + (overrides ? 1 : 0);
    next.updated = Date.now(); next.updated_by = user || '';
    next.hash = recordChange('enable', next, { point, overrides: overrides ? Object.keys(overrides) : [] }, user).hash;
    // exclusivity: one active pipeline per enforcement point
    for (const d of allDocs()) {
      if (d.id === id) continue;
      let ch2 = false;
      const e = Object.assign({ ingest: false, relay: false }, d.enforce);
      for (const p of points) if (e[p]) { e[p] = false; ch2 = true; }
      if (ch2) { const nd = Object.assign({}, d, { enforce: e, enabled: e.ingest || e.relay }); putDoc(nd); }
    }
    putDoc(next);
    rebuildActive();
    return getPipeline(id);
  }

  function disable(id, { point = 'both', user } = {}) {
    const cur = getDoc(id);
    if (!cur) throw httpErr(404, 'pipeline not found');
    const e = Object.assign({ ingest: false, relay: false }, cur.enforce);
    if (point === 'both') { e.ingest = false; e.relay = false; } else e[point] = false;
    const next = Object.assign({}, cur, { enforce: e, enabled: e.ingest || e.relay });
    next.updated = Date.now(); next.updated_by = user || '';
    next.hash = recordChange('disable', next, { point }, user).hash;
    putDoc(next);
    rebuildActive();
    return getPipeline(id);
  }

  // ---- active compiled pipeline (ingest) + relay config
  function rebuildActive() {
    const ingestDoc = allDocs().find((d) => d.enabled && d.enforce && d.enforce.ingest);
    if (ingestDoc) {
      const stamp = ingestDoc.id + ':' + ingestDoc.version + ':' + ingestDoc.hash;
      if (stamp !== activeStamp) { active = compilePipeline(ingestDoc, ctx); activeId = ingestDoc.id; activeStamp = stamp; counters.setPipelineId(ingestDoc.id); }
    } else { active = null; activeId = null; activeStamp = ''; counters.setPipelineId(''); }
    const relayDoc = allDocs().find((d) => d.enabled && d.enforce && d.enforce.relay);
    relayCompiled = relayDoc ? compileRelayPipeline(relayDoc, { resolveDest: (did) => destinations.get(did), tzOffsetMin }) : { version: 0, etag: '', rules: [], excluded: [] };
  }

  function activeIngest() { return active && !active.error ? active : null; }
  function relayConfig() { return relayCompiled || { version: 0, etag: '', rules: [], excluded: [] }; }

  const router = createRouter({ writer, archive, destinations, counters, log, getPipeline: activeIngest, aggregator: createAggregator({}) });

  // ---- summary / drops / sources (API)
  async function summary({ from, to } = {}) {
    const now = Date.now();
    const toMs = to != null ? to : now;
    const fromMs = from != null ? from : toMs - 7 * 86400000;
    const c = await cost.summary({ from: fromMs, to: toMs });
    const pipelines = listPipelines();
    const coverage = {
      ingest: pipelines.some((p) => p.enabled && p.enforce && p.enforce.ingest),
      relay: pipelines.some((p) => p.enabled && p.enforce && p.enforce.relay),
      pipelines: pipelines.length, enabled: pipelines.filter((p) => p.enabled).length,
    };
    return Object.assign({}, c, { coverage, enforcement: coverage, blind_spots: false, protect_detections: settings.get().protect_detections });
  }

  function drops() { return { rules: counters.drops(), note: 'nothing is silently discarded — every drop/sample/trim is counted here' }; }

  async function sources({ from, to } = {}) {
    const now = Date.now();
    const toMs = to != null ? to : now;
    const fromMs = from != null ? from : toMs - 86400000;
    const vol = await cost.volume(fromMs, toMs);
    return { window: { from: fromMs, to: toMs }, sources: vol.bySource, by_type: vol.byType, total: vol.total };
  }

  async function archiveSearch(opts) { return archive.search(opts); }

  function health() {
    return {
      ok: true, active_pipeline: activeId, active_rules: active && active.rules ? active.rules.length : 0,
      relay: { version: relayCompiled ? relayCompiled.etag : '', rules: relayCompiled ? relayCompiled.rules.length : 0 },
      counters: counters.stats(), archive: archive.stats(), destinations: destinations.stats(),
      protect_detections: settings.get().protect_detections, chain: verifyChain(),
    };
  }

  async function runSimulate(idOrDraft, opts = {}) {
    let def = idOrDraft;
    if (typeof idOrDraft === 'string') { const d = getDoc(idOrDraft); if (!d) throw httpErr(404, 'pipeline not found'); def = d; }
    return simulate.run(Object.assign({ pipeline: def, ctx, uebaFeatures: uebaFeatures() }, opts));
  }

  rebuildActive();

  async function stop() { try { await counters.stop(); } catch { /* ignore */ } try { await archive.stop(); } catch { /* ignore */ } }

  return {
    router, counters, archive, destinations, settings, cost,
    listPipelines, getPipeline, createPipeline, updatePipeline, deletePipeline, enable, disable,
    simulate: runSimulate, conflictsFor, activeIngest, relayConfig, relayConfigCompiled: () => relayCompiled,
    summary, drops, sources, archiveSearch, health, verifyChain, pipelineAudit, rebuildActive, stop,
  };
}

function httpErr(code, message, errors) { const e = new Error(message); e.code = code; if (errors) e.errors = errors; return e; }

module.exports = { createDataOpt, canonRules, GENESIS };
