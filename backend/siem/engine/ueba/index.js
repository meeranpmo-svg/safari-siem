// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UEBA engine — createUeba(deps) ties entities + baselines + detectors + risk into the sentra-siem engine.
 *
 *   createUeba({ state, ch, alerts, log, config, settings?, search?, plans?, now? }) → {
 *     // scheduler hooks (engine/main.js)
 *     runBaselines(nowMs),            // nightly: SQL aggregation → robust baselines (ClickHouse path)
 *     runDetectors(nowMs),            // every few minutes: recent events vs baselines → findings → risk → alerts
 *     // test / offline path (no ClickHouse)
 *     rebuildFromEvents(events, now), detectFromEvents(events, now),
 *     // API data (engine/ueba/api.js)
 *     summary(q), entities(q), entity(id), findings(q), getSettings(), setSettings(patch, by),
 *     markFinding(id, action, by, note), health(),
 *     // internals exposed for tests
 *     identifier, stats(), stop()
 *   }
 *
 * Live state (served synchronously by the API) lives in engine state collections (ueba_entities / ueba_findings /
 * ueba_tuning / ueba_settings), mirrored best-effort to ClickHouse (ueba_entity / ueba_finding / ueba_baseline /
 * ueba_feature_daily / ueba_risk / ueba_tuning) for history & reporting. No auto-response: high risk only raises an
 * alert into the existing queue (rule family UEBA-*), which still passes the SOC/SOAR approval gates.
 * Standard library only.
 */
const { defaultSettings, mergeSettings, validateSettings, detectorConfig, detectorNames } = require('./settings');
const { createIdentifier } = require('./entities');
const { buildAggregates, computeBaseline, observedWindow, baselineFromSql } = require('./baseline');
const { runDetectors } = require('./detectors');
const { scoreEntity, TIER_RANK } = require('./risk');
const sql = require('./sql');

const DAY_MS = 86400000;
function chTime(ms) { return ms ? new Date(ms).toISOString().replace('T', ' ').replace('Z', '') : null; }
function chDate(dayIndex) { return new Date(dayIndex * DAY_MS).toISOString().slice(0, 10); }

function createUeba(deps = {}) {
  const state = deps.state;
  if (!state) throw new Error('createUeba needs deps.state');
  const ch = deps.ch || null;
  const alerts = deps.alerts || null;
  const log = deps.log || { info() {}, warn() {}, error() {}, debug() {} };
  const now = deps.now || Date.now;
  const plans = deps.plans || null;
  const search = typeof deps.search === 'function' ? deps.search : null;

  const entitiesCol = state.collection('ueba_entities');
  const findingsCol = state.collection('ueba_findings');
  const tuningCol = state.collection('ueba_tuning');
  const settingsCol = state.collection('ueba_settings');
  const counters = state.collection('ueba_counters');

  // ---- settings
  let settings = mergeSettings(defaultSettings(), (settingsCol.get('ueba') || {}).value || deps.settings || {});
  try { validateSettings(settings); } catch (e) { log.warn('ueba settings invalid, using defaults', { err: e.message }); settings = defaultSettings(); }
  let identifier = createIdentifier(settings);

  const st = { baseline_runs: 0, detect_runs: 0, findings_created: 0, findings_merged: 0, alerts_raised: 0, mirror_errors: 0, last_baseline_run: 0, last_detect_run: 0 };

  function nextId() {
    const n = ((counters.get('finding') || {}).n || 0) + 1;
    counters.put({ id: 'finding', n });
    return `UEB-${String(n).padStart(7, '0')}`;
  }

  // ---- ClickHouse mirror (best effort)
  async function mirror(table, rows) {
    if (!ch || typeof ch.insertRows !== 'function' || !rows.length) return;
    try { await ch.insertRows(table, rows); } catch (e) { st.mirror_errors++; log.warn('ueba mirror failed', { table, err: e.message }); }
  }
  function entityRow(e) {
    return { id: e.id, type: e.type, name: e.name, peer_group: e.peer_group || '', tags: e.tags || [],
      first_seen: chTime(e.first_seen), last_seen: chTime(e.last_seen), days_observed: e.days_observed || 0,
      state: e.state, risk_score: (e.risk && e.risk.score) || 0, risk_tier: (e.risk && e.risk.tier) || 'low',
      open_findings: e.open_findings || 0, updated: chTime(now()) };
  }
  function findingRow(f) {
    return { id: f.id, entity_id: f.entity_id, entity_type: f.entity_type, entity_name: f.entity_name, detector: f.detector,
      severity: f.severity, weight: f.weight, status: f.status, mitre: f.mitre || [], explanation: f.explanation || '',
      observed_json: JSON.stringify(f.observed || {}), baseline_json: JSON.stringify(f.baseline || {}), evidence: f.evidence || [],
      ts_first: chTime(f.ts_first), ts_last: chTime(f.ts_last), count: f.count || 1, alert_id: f.alert_id || '',
      created: chTime(f.created), updated: chTime(f.updated) };
  }

  // ---- entity upsert
  function upsertEntity(base) {
    const cur = entitiesCol.get(base.id) || {};
    const e = Object.assign({
      id: base.id, type: base.type, name: base.name, peer_group: '', tags: [],
      first_seen: 0, last_seen: 0, days_observed: 0, span_days: 0, state: 'learning',
      baseline: null, current: null, risk: { score: 0, tier: 'low', contributions: [], updated: 0 },
      risk_timeline: [], open_findings: 0, last_finding_at: 0, alerted_tier: 'low', updated: 0,
    }, cur, base);
    e.updated = now();
    entitiesCol.put(e);
    return e;
  }

  // ---- peer-group distribution for peer_group_outlier
  function buildPeers() {
    const groups = new Map(); // peer_group → { metric → [values] }
    for (const e of entitiesCol.all((x) => x.state === 'established' && x.baseline)) {
      const g = e.peer_group || `${e.type}/default`;
      let m = groups.get(g);
      if (!m) { m = { events: [], distinct_hosts: [], privileged: [], auth_fail: [] }; groups.set(g, m); }
      for (const k of Object.keys(m)) if (e.baseline.metrics[k]) m[k].push(e.baseline.metrics[k].median);
    }
    const { median, mad, quantile } = require('./baseline');
    const statFor = (g, metric) => {
      const arr = (groups.get(g) || {})[metric] || [];
      return { median: median(arr), mad: mad(arr), p95: quantile(arr, 0.95), n: arr.length };
    };
    return (peerGroup) => (metric) => statFor(peerGroup, metric);
  }

  // ---- tuning / allow-list
  function tuningFor(entityId, detector) { return tuningCol.get(`${entityId}\u0001${detector}`) || null; }
  function isSuppressed(entityId, detector, dedupKey) {
    const t = tuningFor(entityId, detector);
    if (!t || t.action !== 'benign') return false;
    if (t.scope === 'detector') return true;
    return Array.isArray(t.values) && t.values.includes(dedupKey);
  }

  // ---- record a finding (with dedup)
  function recordFinding(entity, partial, winFrom, winTo) {
    const nowMs = now();
    const dedupKey = partial.dedup_key || partial.detector;
    const windowMs = (settings.risk.window_h || 168) * 3600000;
    // dedup: an existing non-benign finding with same entity+dedup_key within the risk window
    const existing = findingsCol.all((f) => f.entity_id === entity.id && f.dedup_key === dedupKey && f.status !== 'benign' && (nowMs - (f.last_seen || f.created || 0)) < windowMs)[0];
    const suppressed = isSuppressed(entity.id, partial.detector, dedupKey);
    if (existing) {
      const f = findingsCol.patch(existing.id, (x) => {
        x.count = (x.count || 1) + 1;
        x.ts_last = winTo || partial.window.to || nowMs; x.last_seen = nowMs; x.updated = nowMs;
        x.observed = partial.observed; x.baseline = partial.baseline; x.explanation = partial.explanation;
        if (partial.evidence && partial.evidence.length) x.evidence = partial.evidence.slice(0, 20);
        x.severity = Math.max(x.severity, partial.severity);
      });
      st.findings_merged++;
      return { finding: f, created: false };
    }
    const f = {
      id: nextId(), entity_id: entity.id, entity_type: entity.type, entity_name: entity.name, peer_group: entity.peer_group || '',
      detector: partial.detector, mitre: partial.mitre || [], severity: partial.severity, weight: partial.weight, confidence: 1,
      observed: partial.observed, baseline: partial.baseline, window: partial.window || { from: winFrom, to: winTo },
      evidence: (partial.evidence || []).slice(0, 20), explanation: partial.explanation, dedup_key: dedupKey,
      status: suppressed ? 'benign' : 'open', count: 1, ts_first: partial.window ? partial.window.from : winFrom,
      ts_last: partial.window ? partial.window.to : winTo, created: nowMs, updated: nowMs, last_seen: nowMs, alert_id: '',
    };
    findingsCol.put(f);
    st.findings_created++;
    return { finding: f, created: true };
  }

  // ---- risk recompute + alerting
  function recomputeRisk(entityId) {
    const e = entitiesCol.get(entityId);
    if (!e) return null;
    const windowMs = (settings.risk.window_h || 168) * 3600000;
    const nowMs = now();
    const fs = findingsCol.all((f) => f.entity_id === entityId && (nowMs - (f.last_seen || f.created || 0)) < windowMs);
    const r = scoreEntity(fs, e, settings, nowMs);
    const openCount = fs.filter((f) => f.status !== 'benign').length;
    const lastAt = fs.reduce((m, f) => Math.max(m, f.last_seen || f.created || 0), 0);
    const updated = upsertEntity({ id: entityId, risk: r, open_findings: openCount, last_finding_at: lastAt });
    const tl = (updated.risk_timeline || []).slice();
    tl.push({ at: nowMs, score: r.score, tier: r.tier });
    while (tl.length > (settings.risk.max_timeline || 500)) tl.shift();
    entitiesCol.patch(entityId, (x) => { x.risk_timeline = tl; });
    return updated;
  }

  function raiseFindingAlert(entity, f) {
    if (!alerts || typeof alerts.raise !== 'function') return;
    if (f.status === 'benign') return;
    if (f.severity < (settings.risk.alert_min_severity || 3)) return;
    if (f.alert_id) return;
    try {
      const r = alerts.raise({
        rule_id: `UEBA-${f.detector.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`, rule_name: `UEBA ${f.detector.replace(/_/g, ' ')}`,
        rule_type: 'ueba', severity: f.severity, mitre: f.mitre || [], tactic: '',
        summary: f.explanation, group: { entity: entity.id, entity_type: entity.type, detector: f.detector },
        group_key: `ueba:${entity.id}:${f.detector}:${f.dedup_key}`, sample_event_ids: f.evidence || [],
        ts_first: f.ts_first, ts_last: f.ts_last, source: 'ueba', src_id: entity.name,
        host: entity.type === 'host' ? entity.name : '', count: f.count || 1,
        fields: { entity_id: entity.id, entity_type: entity.type, detector: f.detector, finding_id: f.id, risk_tier: (entity.risk && entity.risk.tier) || 'low' },
      });
      const alertId = r && r.alert ? r.alert.id : (r && r.id) || '';
      if (alertId) findingsCol.patch(f.id, (x) => { x.alert_id = alertId; });
      st.alerts_raised++;
    } catch (e) { log.warn('ueba alert raise failed', { detector: f.detector, err: e.message }); }
  }
  function maybeRiskAlert(entity) {
    if (!alerts || typeof alerts.raise !== 'function' || !entity.risk) return;
    const alertTier = settings.risk.alert_tier || 'high';
    if (TIER_RANK[entity.risk.tier] < TIER_RANK[alertTier]) return;
    if (TIER_RANK[entity.risk.tier] <= TIER_RANK[entity.alerted_tier || 'low']) return;
    try {
      alerts.raise({
        rule_id: 'UEBA-RISK', rule_name: `UEBA risk ${entity.risk.tier}`, rule_type: 'ueba',
        severity: entity.risk.tier === 'critical' ? 4 : 3, mitre: [], tactic: '',
        summary: `${entity.type} ${entity.name} reached ${entity.risk.tier} risk (score ${entity.risk.score})`,
        group: { entity: entity.id, entity_type: entity.type }, group_key: `ueba-risk:${entity.id}`,
        sample_event_ids: [], ts_first: now(), ts_last: now(), source: 'ueba', src_id: entity.name,
        host: entity.type === 'host' ? entity.name : '', count: 1,
        fields: { entity_id: entity.id, risk_tier: entity.risk.tier, risk_score: String(entity.risk.score), top: (entity.risk.contributions[0] || {}).detector || '' },
      });
      st.alerts_raised++;
      upsertEntity({ id: entity.id, alerted_tier: entity.risk.tier });
    } catch (e) { log.warn('ueba risk alert failed', { err: e.message }); }
  }

  // ---- baseline building (shared folding)
  function storeBaselines(baselineMap, featureRows) {
    const entRows = [], baseRows = [];
    for (const [id, b] of baselineMap) {
      const e = upsertEntity({
        id, type: b.type, name: b.name, first_seen: b.first_seen, last_seen: b.last_seen,
        days_observed: b.days_observed, span_days: b.span_days, state: b.state, tags: b.tags, baseline: b,
        peer_group: (entitiesCol.get(id) || {}).peer_group || `${b.type}/default`,
      });
      entRows.push(entityRow(e));
      baseRows.push({ entity_id: id, type: b.type, name: b.name, days_observed: b.days_observed, state: b.state, baseline_json: JSON.stringify(b), computed_at: chTime(now()) });
    }
    mirror('ueba_entity', entRows);
    mirror('ueba_baseline', baseRows);
    if (featureRows && featureRows.length) mirror('ueba_feature_daily', featureRows);
  }

  function featureRowsFromAgg(aggMap) {
    const rows = [];
    for (const [id, a] of aggMap) {
      for (const [day, d] of a.days) {
        rows.push({ entity_id: id, type: a.type, name: a.name, day: chDate(day), events: d.events, auth_fail: d.auth_fail,
          auth_success: d.auth_success, egress_bytes: d.egress_bytes, privileged: d.privileged,
          distinct_hosts: d.distinct_hosts !== undefined ? d.distinct_hosts : (d.hosts ? d.hosts.size : 0), updated: chTime(now()) });
      }
    }
    return rows;
  }

  // ---- public: rebuild baselines from in-memory events (tests / offline)
  function rebuildFromEvents(events, atMs) {
    const t0 = atMs || now();
    const opts = { identifier, tzOffsetMin: settings.timezone_offset_min, maxSet: settings.max_set_size };
    const aggs = buildAggregates(events, opts);
    const baselineMap = new Map();
    for (const [id, a] of aggs) baselineMap.set(id, computeBaseline(a, settings));
    storeBaselines(baselineMap, featureRowsFromAgg(aggs));
    st.baseline_runs++; st.last_baseline_run = t0;
    return { entities: baselineMap.size };
  }

  // ---- public: production baselines via ClickHouse aggregation
  async function runBaselines(atMs) {
    const t0 = atMs || now();
    if (!ch || typeof ch.query !== 'function') { log.warn('ueba runBaselines: no ClickHouse — skipped'); return { entities: 0, skipped: true }; }
    const from = chTime(t0 - (settings.learning_window_days || 30) * DAY_MS);
    const to = chTime(t0);
    const params = { from: { type: "DateTime64(3,'UTC')", value: from }, to: { type: "DateTime64(3,'UTC')", value: to } };
    let numericRows = [], valueRows = [];
    try {
      numericRows = await ch.query(sql.dailyNumericSQL({ database: ch.database, settings }), params, { readonly: true });
      valueRows = await ch.query(sql.knownValuesSQL({ database: ch.database, settings }), params, { readonly: true });
    } catch (e) { log.error('ueba runBaselines query failed', { err: e.message }); return { entities: 0, error: e.message }; }
    const baselineMap = baselineFromSql(numericRows, valueRows, settings);
    const featureRows = numericRows.map((r) => ({ entity_id: r.entity_id, type: r.entity_type, name: r.entity_name,
      day: typeof r.day === 'number' ? chDate(r.day) : r.day, events: Number(r.events) || 0, auth_fail: Number(r.auth_fail) || 0,
      auth_success: Number(r.auth_success) || 0, egress_bytes: Number(r.egress_bytes) || 0, privileged: Number(r.privileged) || 0,
      distinct_hosts: Number(r.distinct_hosts) || 0, updated: chTime(now()) }));
    storeBaselines(baselineMap, featureRows);
    st.baseline_runs++; st.last_baseline_run = t0;
    return { entities: baselineMap.size };
  }

  // ---- detection core (shared by events / CH paths)
  function detectOnWindow(events, atMs) {
    const t0 = atMs || now();
    const opts = { identifier, tzOffsetMin: settings.timezone_offset_min, maxSet: settings.max_set_size };
    const observed = observedWindow(events, opts);
    // group raw events per entity for the detectors
    const byEntity = new Map();
    const domainCount = new Map();
    for (const ev of events) {
      for (const ent of identifier.entitiesOf(ev)) {
        let arr = byEntity.get(ent.id); if (!arr) { arr = []; byEntity.set(ent.id, arr); }
        arr.push(ev);
        if (ev.domain) { const dk = `${ent.id}\u0001${ev.domain}`; domainCount.set(dk, (domainCount.get(dk) || 0) + 1); }
      }
    }
    const peerFor = buildPeers();
    const windowMs = Math.max(1, (settings.detect_lookback_min || 60) * 60000);
    const touched = new Set();
    for (const [id, evts] of byEntity) {
      evts.sort((a, b) => (a.ts || 0) - (b.ts || 0));
      const obs = observed.get(id);
      // ensure an entity record exists (learning if no baseline yet)
      let e = entitiesCol.get(id);
      const obsEnt = evts[0] ? identifier.entitiesOf(evts[0]).find((x) => x.id === id) : null;
      // derive peer group from the most common domain for this entity
      let peerGroup = (e && e.peer_group) || '';
      if (!peerGroup) {
        let best = '', bestN = 0;
        for (const [dk, n] of domainCount) if (dk.startsWith(id + '\u0001') && n > bestN) { bestN = n; best = dk.split('\u0001')[1]; }
        peerGroup = `${(e && e.type) || (obsEnt && obsEnt.type) || 'user'}/${best || 'default'}`;
      }
      e = upsertEntity({
        id, type: (e && e.type) || (obsEnt && obsEnt.type) || 'user', name: (e && e.name) || (obsEnt && obsEnt.name) || id.split(':')[1],
        peer_group: peerGroup,
        last_seen: Math.max((e && e.last_seen) || 0, obs ? obs.last_seen : 0),
        first_seen: (e && e.first_seen) || (obs ? obs.first_seen : 0),
        current: obs || null,
        tags: (e && e.baseline && e.baseline.tags) || (e && e.tags) || [],
      });
      const ctx = {
        entity: e, baseline: e.baseline, recent: evts, observed: obs || { events: 0, known: {}, action_types: [], targets: [] },
        now: t0, windowMs, settings, peers: peerFor(e.peer_group), plans, identifier, tz: settings.timezone_offset_min, log,
      };
      const partials = runDetectors(ctx);
      for (const p of partials) {
        const { finding, created } = recordFinding(e, p, t0 - windowMs, t0);
        if (created && finding.status !== 'benign') raiseFindingAlert(e, finding);
      }
      touched.add(id);
    }
    // recompute risk for touched entities and raise risk alerts
    const findingRows = [];
    for (const id of touched) {
      const e = recomputeRisk(id);
      if (e) { maybeRiskAlert(entitiesCol.get(id)); }
    }
    // mirror new/updated findings + entities + risk points for touched entities
    const riskRows = [], entRows = [];
    for (const id of touched) {
      const e = entitiesCol.get(id);
      if (!e) continue;
      entRows.push(entityRow(e));
      if (e.risk) riskRows.push({ entity_id: id, at: chTime(e.risk.updated || t0), score: e.risk.score, tier: e.risk.tier });
      for (const f of findingsCol.all((x) => x.entity_id === id && (t0 - (x.updated || 0)) < windowMs + 1000)) findingRows.push(findingRow(f));
    }
    mirror('ueba_entity', entRows);
    mirror('ueba_finding', findingRows);
    mirror('ueba_risk', riskRows);
    st.detect_runs++; st.last_detect_run = t0;
    return { entities: touched.size };
  }

  function detectFromEvents(events, atMs) { return detectOnWindow(events, atMs); }

  async function runDetectors_(atMs) {
    const t0 = atMs || now();
    const events = await loadRecentEvents(t0);
    if (events === null) { log.warn('ueba runDetectors: no event source — skipped'); return { entities: 0, skipped: true }; }
    return detectOnWindow(events, t0);
  }

  async function loadRecentEvents(t0) {
    const from = t0 - Math.max(1, (settings.detect_lookback_min || 60)) * 60000;
    if (ch && typeof ch.query === 'function') {
      const out = []; const page = 5000; let offset = 0;
      const params = { from: { type: "DateTime64(3,'UTC')", value: chTime(from) }, to: { type: "DateTime64(3,'UTC')", value: chTime(t0) } };
      try {
        for (;;) {
          const rows = await ch.query(sql.recentEventsSQL({ database: ch.database }), Object.assign({}, params, { limit: { type: 'UInt32', value: page }, offset: { type: 'UInt32', value: offset } }), { readonly: true });
          for (const r of rows) out.push(rowToEvent(r));
          if (rows.length < page) break;
          offset += rows.length;
          if (out.length > 500000) break;
        }
        return out;
      } catch (e) { log.error('ueba loadRecentEvents failed', { err: e.message }); return []; }
    }
    if (search) {
      try { const res = await search('', from, t0, { limit: 100000, order: 'asc' }); return (Array.isArray(res) ? res : (res && res.rows) || []).map(rowToEvent); } catch (e) { log.error('ueba search failed', { err: e.message }); return []; }
    }
    return null;
  }
  function rowToEvent(r) {
    const ev = Object.assign({}, r);
    ev.ts = typeof r.ts === 'number' ? r.ts : (r.ts ? Date.parse(String(r.ts).replace(' ', 'T') + 'Z') : 0);
    if (typeof ev.fields === 'string') { try { ev.fields = JSON.parse(ev.fields); } catch { ev.fields = {}; } }
    if (!ev.fields || typeof ev.fields !== 'object') ev.fields = {};
    if (!Array.isArray(ev.tags)) ev.tags = ev.tags ? [ev.tags] : [];
    return ev;
  }

  // ====================================================================== API data
  function entityBrief(e) {
    return { id: e.id, type: e.type, name: e.name, peer_group: e.peer_group || '', tags: e.tags || [], state: e.state,
      first_seen: e.first_seen, last_seen: e.last_seen, days_observed: e.days_observed || 0,
      risk_score: (e.risk && e.risk.score) || 0, tier: (e.risk && e.risk.tier) || 'low',
      open_findings: e.open_findings || 0, last_finding_at: e.last_finding_at || 0 };
  }

  function summary(q = {}) {
    const limit = Math.max(1, Math.min(100, Number(q.limit) || 10));
    const ents = entitiesCol.all();
    const tiers = { critical: 0, high: 0, elevated: 0, low: 0 };
    const byType = { user: 0, host: 0, service_account: 0, ai_agent: 0 };
    let learning = 0, established = 0;
    for (const e of ents) {
      tiers[(e.risk && e.risk.tier) || 'low']++;
      if (byType[e.type] !== undefined) byType[e.type]++;
      if (e.state === 'established') established++; else learning++;
    }
    const top = ents.slice().sort((a, b) => ((b.risk && b.risk.score) || 0) - ((a.risk && a.risk.score) || 0))
      .filter((e) => ((e.risk && e.risk.score) || 0) > 0).slice(0, limit).map(entityBrief);
    const since = now() - DAY_MS;
    const recent = findingsCol.all((f) => (f.created || 0) >= since && f.status !== 'benign')
      .sort((a, b) => (b.created || 0) - (a.created || 0)).slice(0, 50)
      .map((f) => ({ id: f.id, entity_id: f.entity_id, entity_name: f.entity_name, entity_type: f.entity_type, detector: f.detector, severity: f.severity, created: f.created, explanation: f.explanation }));
    const detector_health = detectorNames().map((d) => {
      const dc = detectorConfig(settings, d);
      const all = findingsCol.all((f) => f.detector === d && (f.created || 0) >= since);
      return { detector: d, enabled: dc.enabled !== false, findings_24h: all.filter((f) => f.status !== 'benign').length, benign_24h: all.filter((f) => f.status === 'benign').length };
    });
    return {
      generated_at: now(),
      tiers,
      entity_counts: { total: ents.length, by_type: byType, learning, established },
      coverage: { learning, established, pct_established: ents.length ? Math.round((established / ents.length) * 100) : 0 },
      top_risky: top, new_findings: recent, detector_health,
      learning_status: { learning_window_days: settings.learning_window_days, min_days_established: settings.min_days_established },
    };
  }

  function entities(q = {}) {
    let items = entitiesCol.all();
    if (q.type) items = items.filter((e) => e.type === q.type);
    if (q.tier) items = items.filter((e) => ((e.risk && e.risk.tier) || 'low') === q.tier);
    if (q.state) items = items.filter((e) => e.state === q.state);
    if (q.peer) items = items.filter((e) => (e.peer_group || '') === q.peer);
    if (q.q) { const s = String(q.q).toLowerCase(); items = items.filter((e) => `${e.id} ${e.name} ${e.peer_group}`.toLowerCase().includes(s)); }
    items.sort((a, b) => ((b.risk && b.risk.score) || 0) - ((a.risk && a.risk.score) || 0));
    const total = items.length;
    const limit = Math.max(1, Math.min(500, Number(q.limit) || 100));
    const offset = Math.max(0, Number(q.offset) || 0);
    return { total, items: items.slice(offset, offset + limit).map(entityBrief) };
  }

  function featureComparison(e) {
    const b = e.baseline, c = e.current;
    if (!b) return [];
    const out = [];
    for (const m of ['events', 'auth_fail', 'auth_success', 'egress_bytes', 'privileged', 'distinct_hosts']) {
      const bm = b.metrics[m] || {};
      const observed = c ? c[m] : null;
      out.push({ feature: m, baseline: { median: bm.median, p95: bm.p95, mad: bm.mad }, observed, unit: m === 'egress_bytes' ? 'bytes/window' : 'per_window' });
    }
    for (const k of ['countries', 'subnets', 'hosts', 'services', 'logon_types']) {
      const known = (b.known && b.known[k]) || [];
      const obs = (c && c.known && c.known[k]) || [];
      const fresh = obs.filter((v) => v && !known.includes(v));
      out.push({ feature: k, baseline: { known_count: known.length, sample: known.slice(0, 8) }, observed: { seen: obs.length, new: fresh } });
    }
    out.push({ feature: 'active_hours', baseline: { histogram: b.active_hours.histogram, active: b.active_hours.active }, observed: c ? c.active_hours : null });
    return out;
  }

  function entity(id) {
    const e = entitiesCol.get(id);
    if (!e) return null;
    const fs = findingsCol.all((f) => f.entity_id === id).sort((a, b) => (b.last_seen || b.created || 0) - (a.last_seen || a.created || 0));
    const peerFor = buildPeers()(e.peer_group);
    const peer_comparison = [];
    if (e.baseline) for (const m of ['events', 'distinct_hosts', 'privileged']) {
      const p = peerFor(m); const mine = (e.baseline.metrics[m] && e.baseline.metrics[m].median) || 0;
      peer_comparison.push({ feature: m, entity_value: mine, peer_median: p.median, peer_p95: p.p95, peers: p.n, outlier: p.n >= 4 && p.mad >= 0 && (mine - p.median) / Math.max(p.mad, 1) >= 3.5 });
    }
    const linked_alerts = [];
    if (alerts && typeof alerts.get === 'function') for (const f of fs) if (f.alert_id) { const a = alerts.get(f.alert_id); if (a) linked_alerts.push({ id: a.id, rule_id: a.rule_id, severity: a.severity, status: a.status, case_id: a.case_id || '' }); }
    return {
      entity: { id: e.id, type: e.type, name: e.name, peer_group: e.peer_group || '', tags: e.tags || [], state: e.state,
        first_seen: e.first_seen, last_seen: e.last_seen, days_observed: e.days_observed || 0, span_days: e.span_days || 0 },
      risk: e.risk || { score: 0, tier: 'low', contributions: [], updated: 0 },
      risk_timeline: e.risk_timeline || [],
      baseline: e.baseline, current: e.current,
      features: featureComparison(e),
      findings: fs, peer_comparison, linked_alerts,
    };
  }

  function findings(q = {}) {
    let items = findingsCol.all();
    if (q.entity_id) items = items.filter((f) => f.entity_id === q.entity_id);
    if (q.type || q.detector) items = items.filter((f) => f.detector === (q.detector || q.type));
    if (q.status) { const set = new Set(String(q.status).split(',')); items = items.filter((f) => set.has(f.status)); }
    else items = items.filter((f) => f.status !== 'benign' || q.include_benign);
    if (q.severity_min !== undefined && q.severity_min !== '') items = items.filter((f) => f.severity >= Number(q.severity_min));
    if (q.entity_type) items = items.filter((f) => f.entity_type === q.entity_type);
    if (q.q) { const s = String(q.q).toLowerCase(); items = items.filter((f) => `${f.id} ${f.entity_name} ${f.detector} ${f.explanation}`.toLowerCase().includes(s)); }
    const from = q.from ? Number(q.from) : null, to = q.to ? Number(q.to) : null;
    if (from) items = items.filter((f) => (f.ts_last || f.created) >= from);
    if (to) items = items.filter((f) => (f.ts_first || f.created) <= to);
    const sort = String(q.sort || '-last_seen');
    const key = sort.replace(/^[-+]/, ''); const desc = sort.startsWith('-');
    const allowed = { last_seen: 'last_seen', created: 'created', severity: 'severity', count: 'count' };
    const sk = allowed[key] || 'last_seen';
    items.sort((a, b) => { const x = a[sk] || 0, y = b[sk] || 0; return desc ? (y - x) : (x - y); });
    const total = items.length;
    const limit = Math.max(1, Math.min(500, Number(q.limit) || 100));
    const offset = Math.max(0, Number(q.offset) || 0);
    return { total, items: items.slice(offset, offset + limit) };
  }

  // "benign" writes a lasting suppression for the entity and detector, so it is four-eyes: the first mark is a PROPOSAL (nothing is
  // suppressed), a second named person confirms it; the proposer does not confirm their own, nobody marks a finding about their own
  // account, a service / AI identity does neither. "confirm" (it is real) only raises the risk and stays one person's call.
  function markFinding(id, action, by, note) {
    const f = findingsCol.get(id);
    if (!f) return { error: 'not found', code: 404 };
    if (action !== 'benign' && action !== 'confirm') return { error: 'action must be benign|confirm', code: 400 };
    const me = String(by || '').trim().toLowerCase();
    if (!require('../approvers/scopes').isHuman(me)) return { error: 'only a person reviews a behaviour finding: ' + (by || 'this identity') + ' is a service / AI identity', code: 403 };
    const ent = String(f.entity_id || '').toLowerCase().replace(/^(user|account|host):/, '');
    if (ent && (ent === me || ent.split('@')[0] === me.split('@')[0] || ent.split('\\').pop() === me)) return { error: 'a finding about your own account is reviewed by someone else', code: 403 };
    note = note == null ? '' : String(note).slice(0, 2000);
    if (action === 'benign' && f.status === 'benign') return { error: 'this finding is already marked benign', code: 409 };
    if (action === 'benign' && f.status !== 'benign-proposed') {
      const nowP = now();
      findingsCol.patch(id, (x) => { x.status = 'benign-proposed'; x.updated = nowP; x.proposed_by = by; x.proposed_note = note; });
      mirror('ueba_finding', [findingRow(findingsCol.get(id))]);
      return { finding: findingsCol.get(id), pending: 'a second person confirms it before the detector is tuned for this entity' };
    }
    if (action === 'benign' && String(f.proposed_by || '').toLowerCase() === me) return { error: 'four-eyes: who proposed "benign" does not confirm it', code: 403 };
    const nowMs = now();
    const updated = findingsCol.patch(id, (x) => {
      x.status = action === 'benign' ? 'benign' : 'confirmed';
      x.updated = nowMs; x.reviewed_by = by || ''; if (note) x.note = String(note).slice(0, 2000);
    });
    if (action === 'benign') {
      const tid = `${f.entity_id}\u0001${f.detector}`;
      const t = tuningCol.get(tid) || { id: tid, entity_id: f.entity_id, detector: f.detector, action: 'benign', values: [], scope: 'value', by: by || '', proposed_by: f.proposed_by || '', note: note || f.proposed_note || '' };
      if (!t.values.includes(f.dedup_key)) t.values.push(f.dedup_key);
      t.action = 'benign'; t.by = by || t.by; t.updated = nowMs;
      tuningCol.put(t);
      mirror('ueba_tuning', [{ id: t.id, entity_id: t.entity_id, detector: t.detector, action: t.action, values: t.values, by: t.by, note: t.note || '', updated: chTime(nowMs) }]);
    }
    const e = recomputeRisk(f.entity_id);
    mirror('ueba_finding', [findingRow(findingsCol.get(id))]);
    if (e) mirror('ueba_entity', [entityRow(e)]);
    return { finding: findingsCol.get(id), entity: e ? entityBrief(e) : null, tuning: action === 'benign' ? tuningCol.get(`${f.entity_id}\u0001${f.detector}`) : undefined };
  }

  function listTuning() { return tuningCol.all(); }

  function getSettings() { return { settings, defaults: defaultSettings(), detectors: detectorNames() }; }
  function setSettings(patch, by) {
    const merged = mergeSettings(settings, patch || {});
    validateSettings(merged);
    settings = merged;
    identifier = createIdentifier(settings);
    settingsCol.put({ id: 'ueba', value: settings, updated: now(), by: by || '' });
    return { settings };
  }

  function health() {
    return {
      enabled: settings.enabled !== false,
      last_baseline_run: st.last_baseline_run, last_detect_run: st.last_detect_run,
      entities: entitiesCol.size(), findings_open: findingsCol.all((f) => f.status === 'open').length,
      findings_total: findingsCol.size(), tuning: tuningCol.size(),
      clickhouse: { mirror: !!ch, mirror_errors: st.mirror_errors },
      detectors: detectorNames().reduce((o, d) => { o[d] = detectorConfig(settings, d).enabled !== false; return o; }, {}),
      stats: Object.assign({}, st),
    };
  }

  return {
    runBaselines, runDetectors: runDetectors_, rebuildFromEvents, detectFromEvents,
    summary, entities, entity, findings, markFinding, getSettings, setSettings, health, listTuning,
    recomputeRisk, identifier, get settings() { return settings; }, stats: () => Object.assign({}, st),
    stop() { /* no timers owned here; scheduler in main.js */ },
  };
}

module.exports = { createUeba };
