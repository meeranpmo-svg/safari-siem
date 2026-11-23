// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const { createModel, runLoop } = require('./ai-loop');
/*
 * User and entity behaviour (UEBA) for the rebuilt User Behaviour page - on top of engine/ueba (the baselines, detectors and
 * risk scores are unchanged; this reads them).
 *
 *   createBehaviour({ state, ueba, alerts?, search?, config, log, sdk?, now? })
 *     insights()        14-day findings by severity, detector precision LEARNED from analysts' reviews (confirmed vs benign,
 *                       withheld below 3 reviews), the risk-score distribution, peer groups, the riskiest entities with their
 *                       recent risk timeline, learning coverage
 *     assess(id, who)   Claude reads one entity's behaviour (profile, findings, linked alerts, a few events) and writes an
 *                       assessment: what is unusual, innocent explanations to rule out, questions for the person's manager or
 *                       the service owner, and a recommendation (watch / investigate / open a case / likely benign). Behaviour
 *                       is an INDICATOR, never proof (PDPL); the AI changes nothing and accuses no one. Refs no tool returned
 *                       are marked unverified.
 */
const DAY = 86400000, H = 3600000;
const MIN_REVIEWS = 3;
const httpErr = (code, msg) => Object.assign(new Error(msg), { code, status: code });
const S = (o) => Object.assign({ type: 'object', additionalProperties: false }, o);
const STR = (max) => ({ type: 'string', maxLength: max || 4000 });

const SYSTEM = `You assess the behaviour of ONE user, service account or host for ${ZYB_ORG.short}'s SOC from its UEBA profile.
UEBA compares the entity with its own history and with its peers. A deviation is an INDICATOR to look into, never proof of wrongdoing. Do not accuse, judge or speculate about a person's intent, character or private life (Saudi PDPL); describe activity only.
Read the profile (entity_profile), its findings (entity_findings), linked alerts (entity_alerts) and, when offered, a few events (search_events with narrow queries). Then call submit_assessment once:
- summary: what is unusual, in two or three neutral sentences;
- concerns: each with the ref (finding id, alert id, entity key or event id) a tool returned;
- benign_explanations: ordinary reasons that would explain it (travel, a new role, a migration, a scheduled job) to rule out first;
- questions: what to ask the manager or service owner to confirm or rule it out;
- recommendation: likely_benign / watch / investigate / open_case.
Never invent numbers, hosts or times. If the profile is still learning (few days of history), say the baseline is immature.`;

function createBehaviour(deps = {}) {
  const { ueba } = deps;
  const L = deps.log || { info() {}, warn() {} };
  const now = deps.now || Date.now;
  const store = deps.state ? deps.state.collection('soc_ai_ueba') : null;
  const AI = createModel({ config: deps.config, deps, log: L });
  const need = () => { if (!ueba) throw httpErr(503, 'UEBA is not running on this SIEM'); };

  function allFindings() { return ueba.findings({ include_benign: true, limit: 500, sort: '-created' }).items; }

  function insights() {
    need();
    const t = now(), sum = ueba.summary({ limit: 10 }), F = allFindings();
    const off = 3 * H, days = 14, d0 = Math.floor((t + off) / DAY) - days + 1;
    const series = Array.from({ length: days }, (_, i) => ({ day: new Date((d0 + i) * DAY).toISOString().slice(0, 10), low: 0, medium: 0, high: 0, critical: 0 }));
    const sevKey = (s) => (s >= 4 ? 'critical' : s >= 3 ? 'high' : s >= 2 ? 'medium' : 'low');
    for (const f of F) { const k = Math.floor(((f.created || 0) + off) / DAY) - d0; if (k >= 0 && k < days && f.status !== 'benign') series[k][sevKey(f.severity || 0)]++; }
    // what analysts' reviews say about each detector: confirmed vs benign in 30 days
    const by = new Map();
    for (const f of F.filter((x) => (x.created || 0) >= t - 30 * DAY)) {
      const d = by.get(f.detector) || { detector: f.detector, findings: 0, open: 0, confirmed: 0, benign: 0 };
      d.findings++; if (f.status === 'confirmed') d.confirmed++; else if (f.status === 'benign') d.benign++; else d.open++;
      by.set(f.detector, d);
    }
    const detectors = [...by.values()].map((d) => { const rev = d.confirmed + d.benign;
      return Object.assign(d, { reviewed: rev, precision: rev >= MIN_REVIEWS ? Math.round((d.confirmed / rev) * 100) : null }); })
      .sort((a, b) => b.findings - a.findings);
    const ents = ueba.entities({ limit: 500 }).items;
    const hist = Array.from({ length: 10 }, (_, i) => ({ from: i * 10, to: i * 10 + 9, n: 0 }));
    for (const e of ents) if (e.risk_score > 0) hist[Math.min(9, Math.floor(e.risk_score / 10))].n++;
    const peers = new Map();
    for (const e of ents) { const p = peers.get(e.peer_group || 'none') || { peer_group: e.peer_group || 'none', entities: 0, sum: 0, max: 0, elevated: 0 };
      p.entities++; p.sum += e.risk_score || 0; p.max = Math.max(p.max, e.risk_score || 0); if (e.tier !== 'low') p.elevated++; peers.set(p.peer_group, p); }
    const top = sum.top_risky.slice(0, 8).map((e) => {
      let tl = [];
      try { const x = ueba.entity(e.id); tl = ((x && x.risk_timeline) || []).filter((p) => p.at >= t - 14 * DAY).slice(-60).map((p) => ({ at: p.at, score: p.score })); }
      catch (err) { L.warn('ueba insights: timeline not read', { entity: e.id, err: err.message }); }
      return Object.assign({}, e, { timeline: tl });
    });
    return { generated_at: t, tiers: sum.tiers, entity_counts: sum.entity_counts, coverage: sum.coverage, learning: sum.learning_status, series, detectors,
      min_reviews: MIN_REVIEWS, score_histogram: hist, peers: [...peers.values()].map((p) => ({ peer_group: p.peer_group, entities: p.entities, avg: Math.round(p.sum / p.entities), max: p.max, elevated: p.elevated })).sort((a, b) => b.avg - a.avg).slice(0, 12),
      top, new_findings_24h: sum.new_findings.length, ai: AI.status(),
      note: 'Behaviour scores are indicators to look into, not proof of wrongdoing. Precision is learned from analysts\' reviews and shown once a detector has ' + MIN_REVIEWS + ' reviews.' };
  }

  const TOOLS = [
    { name: 'entity_profile', description: 'The entity: type, peer group, days observed, risk score and its contributions, baseline vs current behaviour per feature, peer comparison.', input_schema: S({ properties: { id: STR(200) }, required: ['id'] }) },
    { name: 'entity_findings', description: 'The entity\'s behaviour findings (detector, severity, explanation, observed vs baseline, status, review note).', input_schema: S({ properties: { id: STR(200) }, required: ['id'] }) },
    { name: 'entity_alerts', description: 'Alerts linked to the entity\'s findings.', input_schema: S({ properties: { id: STR(200) }, required: ['id'] }) },
    { name: 'search_events', description: 'A few events (at most 20) for the entity over the last N hours, matching a query in the platform query language.', role: 'analyst',
      input_schema: S({ properties: { q: STR(1000), hours: { type: 'integer', minimum: 1, maximum: 168 } }, required: ['q'] }) },
    { name: 'submit_assessment', description: 'Submit the assessment. Call once, last.', input_schema: S({ properties: {
      summary: STR(2000), recommendation: { type: 'string', enum: ['likely_benign', 'watch', 'investigate', 'open_case'] },
      concerns: { type: 'array', maxItems: 10, items: S({ properties: { point: STR(500), ref: STR(200) }, required: ['point', 'ref'] }) },
      benign_explanations: { type: 'array', maxItems: 8, items: STR(400) }, questions: { type: 'array', maxItems: 8, items: STR(400) } },
      required: ['summary', 'recommendation', 'concerns'] }) },
  ];
  async function run(name, i, seen) {
    if (name === 'entity_profile') {
      const e = ueba.entity(i.id); if (!e) throw new Error('no UEBA entity ' + i.id); seen.add(e.entity.id);
      return { entity: e.entity, risk: { score: e.risk.score, tier: e.risk.tier, contributions: (e.risk.contributions || []).slice(0, 12) }, features: e.features, peer_comparison: e.peer_comparison };
    }
    if (name === 'entity_findings') {
      // the most severe first, then the newest: a burst of low-severity findings must not push the important one out of the 30
      const L2 = ueba.findings({ entity_id: i.id, include_benign: true, limit: 500 }).items.sort((x, y) => (y.severity || 0) - (x.severity || 0) || (y.last_seen || y.created || 0) - (x.last_seen || x.created || 0)).slice(0, 30);
      for (const f of L2) seen.add(f.id);
      return { findings: L2.map((f) => ({ id: f.id, detector: f.detector, severity: f.severity, status: f.status, explanation: f.explanation, observed: f.observed, baseline: f.baseline, count: f.count, note: f.note, mitre: f.mitre, first: new Date(f.ts_first || f.created).toISOString(), last: new Date(f.ts_last || f.created).toISOString() })) };
    }
    if (name === 'entity_alerts') { const e = ueba.entity(i.id); const A = (e && e.linked_alerts) || []; for (const a of A) seen.add(a.id); return { alerts: A }; }
    if (name === 'search_events') {
      if (!deps.search) return { note: 'the event store is not available' };
      deps.search.parse(i.q);
      const r = await deps.search.search({ q: i.q, from: now() - (i.hours || 24) * H, to: now(), limit: 20, fields: ['host', 'user', 'src_ip', 'dst_ip', 'category', 'action', 'outcome', 'process', 'message'] });
      for (const e of r.rows || []) seen.add(String(e.id));
      return { rows: (r.rows || []).map((e) => Object.assign({}, e, { message: String(e.message || '').slice(0, 300) })) };
    }
    throw new Error('unknown tool ' + name);
  }

  async function assess(id, who) {
    need();
    const e = ueba.entity(id); if (!e) throw httpErr(404, 'UEBA has no entity ' + id);
    const st = AI.status(); if (!st.enabled) throw httpErr(503, st.reason);
    const r = await runLoop({ client: AI.client(), model: AI.model(), effort: AI.effort(), system: SYSTEM, tools: TOOLS, role: who.role || 'analyst', user: who.user || 'unknown',
      feature: 'soc.ueba-assess', config: deps.config, log: L, prompt: `Assess the behaviour of ${e.entity.id} (${e.entity.type}). Use the tools, then call submit_assessment.`, run, final: 'submit_assessment', maxSteps: 8 });
    if (!r.result) throw httpErr(502, 'the AI did not return an assessment (' + r.note + ')');
    const d = r.result;
    const rec = { id: e.entity.id, at: now(), by: AI.model(), requested_by: who.user, summary: d.summary, recommendation: d.recommendation,
      concerns: (d.concerns || []).map((c) => ({ point: c.point, ref: c.ref, verified: r.seen.has(String(c.ref).trim()) })),
      benign_explanations: d.benign_explanations || [], questions: d.questions || [], steps: r.steps, usage: r.usage, injection_signals: r.flags };
    rec.unverified = rec.concerns.filter((c) => !c.verified).length;
    if (store) store.put(rec);
    L.info('ueba assessment', { entity: e.entity.id, user: who.user, recommendation: rec.recommendation, unverified: rec.unverified });
    return rec;
  }
  function lastAssessment(id) { return store ? store.get(id) || null : null; }

  return { insights, assess, lastAssessment, TOOLS };
}

module.exports = { createBehaviour, MIN_REVIEWS };
