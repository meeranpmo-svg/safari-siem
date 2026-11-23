// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UEBA risk scoring — a rolling, explainable risk score per entity.
 *
 *   scoreEntity(findings, entity, settings, now) → {
 *     score, tier, contributions:[{finding_id, detector, severity, base_weight, confidence, sensitivity, decay, age_h,
 *                                   points, explanation}],
 *     updated
 *   }
 *
 * score = Σ (base_weight × confidence × sensitivity × time_decay) over the entity's recent, non-benign findings.
 *   - time_decay = 0.5 ^ (age_hours / half_life_h)     (default half-life 24 h)
 *   - confidence: a confirmed finding is multiplied by confirm_multiplier; a benign finding is excluded entirely.
 *   - sensitivity: per entity-type / admin-tag / peer-group multiplier (asset & role sensitivity).
 * Findings older than risk.window_h drop out. Tiers: low < elevated < high < critical (configurable thresholds).
 * Pure functions; standard library only.
 */

function tierForScore(score, tiers) {
  if (score >= tiers.critical) return 'critical';
  if (score >= tiers.high) return 'high';
  if (score >= tiers.elevated) return 'elevated';
  return 'low';
}

const TIER_RANK = { low: 0, elevated: 1, high: 2, critical: 3 };

function sensitivityFor(entity, settings) {
  const s = settings.sensitivity || {};
  let mult = s[entity.type] !== undefined ? Number(s[entity.type]) : 1;
  if (entity.tags && entity.tags.includes('admin') && s.admin_tag) mult = Math.max(mult, Number(s.admin_tag));
  if (entity.peer_group && s.by_peer_group && s.by_peer_group[entity.peer_group] !== undefined) {
    mult *= Number(s.by_peer_group[entity.peer_group]);
  }
  return Number.isFinite(mult) && mult > 0 ? mult : 1;
}

function scoreEntity(findings, entity, settings, now = Date.now()) {
  const rcfg = (settings && settings.risk) || {};
  const halfLife = rcfg.half_life_h || 24;
  const windowMs = (rcfg.window_h || 168) * 3600000;
  const confirmMult = rcfg.confirm_multiplier || 2;
  const tiers = rcfg.tiers || { elevated: 15, high: 40, critical: 80 };
  const sensitivity = sensitivityFor(entity, settings);

  const contributions = [];
  let score = 0;
  for (const f of findings) {
    if (f.status === 'benign') continue;
    const at = f.last_seen || f.created || f.at || now;
    const ageMs = Math.max(0, now - at);
    if (ageMs > windowMs) continue;
    const ageH = ageMs / 3600000;
    const decay = Math.pow(0.5, ageH / halfLife);
    const confidence = f.status === 'confirmed' ? confirmMult : (f.confidence || 1);
    const base = f.weight || 3;
    const points = base * confidence * sensitivity * decay;
    score += points;
    contributions.push({
      finding_id: f.id, detector: f.detector, severity: f.severity,
      base_weight: base, confidence, sensitivity, decay: Math.round(decay * 1000) / 1000,
      age_h: Math.round(ageH * 10) / 10, points: Math.round(points * 100) / 100,
      explanation: f.explanation || '',
    });
  }
  contributions.sort((a, b) => b.points - a.points);
  score = Math.round(score * 100) / 100;
  return { score, tier: tierForScore(score, tiers), contributions, updated: now };
}

module.exports = { scoreEntity, tierForScore, sensitivityFor, TIER_RANK };
