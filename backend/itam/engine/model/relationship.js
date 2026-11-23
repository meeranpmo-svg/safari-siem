// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// CMDB configuration-item relationships. Pure helpers.
//   relationship {id, from, to, type(runs_on|connected_to|depends_on|member_of|installed_on), status(proposed|confirmed),
//                 source(sensor|vcenter|agent|manual|ai), confidence(0-1)?, rationale?, by?, at}
// AI-inferred relationships land as status:'proposed'; a human confirms high-impact ones (ARCH). Nothing is destructive.
const { s, num, isObj } = require('./asset');

const REL_TYPES = ['runs_on', 'connected_to', 'depends_on', 'member_of', 'installed_on'];
const REL_STATUS = ['proposed', 'confirmed'];
const REL_SOURCE = ['sensor', 'vcenter', 'agent', 'manual', 'ai', 'import'];
// symmetric relationship types (undirected) — normalise endpoint order so a<->b dedupes
const SYMMETRIC = new Set(['connected_to']);

function relKey(from, to, type) {
  if (SYMMETRIC.has(type)) { const [a, b] = [from, to].sort(); return `${type}|${a}|${b}`; }
  return `${type}|${from}|${to}`;
}

function normRelationship(raw) {
  const o = isObj(raw) ? raw : {};
  const from = s(o.from, 80); const to = s(o.to, 80);
  const type = REL_TYPES.includes(s(o.type).toLowerCase()) ? s(o.type).toLowerCase() : null;
  if (!from || !to || !type || from === to) return null;
  const status = REL_STATUS.includes(s(o.status).toLowerCase()) ? s(o.status).toLowerCase() : 'proposed';
  const source = REL_SOURCE.includes(s(o.source).toLowerCase()) ? s(o.source).toLowerCase() : 'manual';
  let confidence = num(o.confidence);
  if (confidence !== null) confidence = Math.max(0, Math.min(1, confidence));
  return {
    id: s(o.id, 80) || null, from, to, type, status, source, confidence,
    rationale: s(o.rationale, 2000) || null, by: s(o.by, 200) || null, at: s(o.at, 40) || null,
    key: relKey(from, to, type),
  };
}

// a relationship is "high impact" (needs human confirm before it counts as confirmed) when it asserts a dependency
// or hosting link — those drive change-impact analysis. connected_to/member_of are informational.
function isHighImpact(rel) { return rel.type === 'depends_on' || rel.type === 'runs_on' || rel.type === 'installed_on'; }

// build the neighbourhood graph for one asset from a flat relationship list (optionally only confirmed)
function graphFor(assetId, relationships, { confirmedOnly = false } = {}) {
  const nodes = new Set([assetId]);
  const edges = [];
  for (const r of relationships) {
    if (confirmedOnly && r.status !== 'confirmed') continue;
    if (r.from === assetId || r.to === assetId) { nodes.add(r.from); nodes.add(r.to); edges.push(r); }
  }
  return { center: assetId, nodes: [...nodes], edges };
}

module.exports = { REL_TYPES, REL_STATUS, REL_SOURCE, SYMMETRIC, relKey, normRelationship, isHighImpact, graphFor };
