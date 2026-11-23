// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI feature builders + appliers. Each build*() returns {system, prompt, ctx, meta}; the system prompt carries a
// stable "TASK:" marker (the test's fake /draft branches on it). Every applier writes ADVISORY output only —
// proposed relationships (human-confirm), or findings labelled "AI — verify". Nothing changes an asset directly.
const { TYPES } = require('../model/asset');

const JSON_RULE = 'Reply with ONE JSON object inside a ```json fence and nothing else. Do not invent ids: use only the ids given below.';

function assetLine(a) {
  return `id=${a.id} | type=${a.type} | name=${a.name || '?'} | vendor=${a.vendor || '?'} | model=${a.model || '?'} | os=${a.os || '?'} | serial=${a.serial ? 'yes' : 'no'} | sources=${(a.sources || []).map((s) => s.source).join(',')}`;
}

// ---- classify / normalise + merge tie-break -----------------------------------------------------------------------
function buildClassify(assets) {
  const cands = assets.filter((a) => a.type === 'other' || !a.vendor || !a.model).slice(0, 60);
  const ids = cands.map((a) => a.id);
  const system = [
    'You are an IT asset-management analyst. TASK: classify and normalise raw asset discovery.',
    `For each asset pick the best "type" from: ${TYPES.join(', ')}. Normalise vendor/model where you can infer them.`,
    'Also propose "merges": pairs that are the SAME physical/virtual asset seen twice (tie-break for the de-dup engine).',
    'All output is advisory; a human confirms it. ' + JSON_RULE,
    'Schema: {"assets":[{"ref","type","vendor","model","category","confidence","rationale"}],"merges":[{"keep","duplicate","confidence","rationale"}]}',
  ].join('\n');
  const prompt = `Assets to classify:\n${cands.map(assetLine).join('\n')}`;
  return { system, prompt, ctx: { ids }, meta: { title: `Classify ${cands.length} assets`, count: cands.length } };
}
function applyClassify(result, { findings }) {
  const ai = result.ai || {}; let n = 0;
  for (const a of ai.assets || []) {
    if (!a.type && !a.vendor && !a.model) continue;
    findings.upsertAi({ key: `ai_classify:${a.ref}`, kind: 'ai_classify', severity: 'low', asset_id: a.ref, title: `Suggested classification for ${a.ref}`, detail: a.rationale || 'Model classification suggestion.', evidence: { type: a.type, vendor: a.vendor, model: a.model, category: a.category, confidence: a.confidence }, suggestion: { type: a.type, vendor: a.vendor, model: a.model } });
    n++;
  }
  for (const m of ai.merges || []) {
    findings.upsertAi({ key: `ai_merge:${[m.keep, m.duplicate].sort().join(':')}`, kind: 'ai_merge', severity: 'medium', asset_id: m.keep, title: `Possible duplicate: ${m.duplicate} = ${m.keep}`, detail: m.rationale || 'Model believes these are the same asset.', evidence: { keep: m.keep, duplicate: m.duplicate, confidence: m.confidence }, suggestion: { merge: [m.keep, m.duplicate] } });
    n++;
  }
  return n;
}

// ---- relationship inference (topology / vcenter / agent) ---------------------------------------------------------
function buildRelate(assets, relationships) {
  const sample = assets.slice(0, 80);
  const ids = sample.map((a) => a.id);
  const known = relationships.filter((r) => r.status === 'confirmed').slice(0, 100).map((r) => `${r.from} ${r.type} ${r.to}`);
  const system = [
    'You are a CMDB analyst. TASK: infer configuration-item relationships between the assets below.',
    'Use types: runs_on (VM->host), connected_to (network peer), depends_on (service dependency), member_of (cluster/group), installed_on (software->device).',
    'Only infer well-supported links. High-impact links (runs_on, depends_on, installed_on) will require human confirmation. ' + JSON_RULE,
    'Schema: {"relationships":[{"from","to","type","confidence","rationale"}]}',
  ].join('\n');
  const prompt = `Assets:\n${sample.map(assetLine).join('\n')}\n\nAlready-confirmed relationships:\n${known.join('\n') || '(none)'}`;
  return { system, prompt, ctx: { ids }, meta: { title: `Infer relationships for ${sample.length} assets`, count: sample.length } };
}
function applyRelate(result, { assets }) {
  const ai = result.ai || {}; let n = 0;
  for (const r of ai.relationships || []) {
    try { assets.addRelationship({ from: r.from, to: r.to, type: r.type, source: 'ai', confidence: r.confidence, rationale: (r.rationale || '') + ' [AI — verify]' }, { user: 'ai', role: 'system' }, { source: 'ai', autoConfirm: false }); n++; } catch { /* endpoint gone */ }
  }
  return n;
}

// ---- refresh / EOL planning narrative ---------------------------------------------------------------------------
function buildRefresh(assets) {
  const cands = assets.filter((a) => a.status !== 'disposed' && a.status !== 'retired' && (a.eol || (a.warranty && a.warranty.end) || a.purchase)).slice(0, 80);
  const ids = cands.map((a) => a.id);
  const line = (a) => `id=${a.id} | type=${a.type} | name=${a.name || '?'} | purchased=${a.purchase && a.purchase.date ? a.purchase.date.slice(0, 10) : '?'} | warranty_end=${a.warranty && a.warranty.end ? a.warranty.end.slice(0, 10) : '?'} | eol=${a.eol ? a.eol.slice(0, 10) : '?'}`;
  const system = [
    'You are an IT asset lifecycle planner. TASK: build a refresh plan from asset age, warranty and end-of-life.',
    'For each asset choose action replace|renew|monitor|retire with a target window (e.g. "2027-Q1") and a reason.',
    'All output is advisory. ' + JSON_RULE,
    'Schema: {"summary","items":[{"asset_id","action","when","reason","estimated_cost"}],"risks":[]}',
  ].join('\n');
  const prompt = `Assets in scope:\n${cands.map(line).join('\n')}\nToday: ${new Date().toISOString().slice(0, 10)}`;
  return { system, prompt, ctx: { ids }, meta: { title: `Refresh plan for ${cands.length} assets`, count: cands.length } };
}
function applyRefresh(result, { store }) {
  const ai = result.ai || {};
  const rec = { id: 'latest', at: new Date().toISOString(), summary: ai.summary || '', items: ai.items || [], risks: ai.risks || [], ai_label: 'AI — verify' };
  store.collection('refresh_plans').put(rec);
  return (ai.items || []).length;
}

const BUILDERS = { classify: buildClassify, relate: buildRelate, refresh: buildRefresh };

module.exports = { buildClassify, buildRelate, buildRefresh, applyClassify, applyRelate, applyRefresh, BUILDERS };
