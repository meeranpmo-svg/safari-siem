// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Parse + validate model output for the ITAM AI features. Never throws on model output; coerces and drops bad data.
//   extractJson(text) → {obj, how, error?}
//   validateOutput(kind, text, ctx, res) → {ai, validation:{ok, parsed_by, errors[], warnings[]}}
// kinds: classify | relate | refresh. Refs that were not supplied to the model are dropped (anti-hallucination).
const { TYPES } = require('../model/asset');
const { REL_TYPES } = require('../model/relationship');

function tryParse(s) {
  try { return { ok: true, v: JSON.parse(s) }; } catch { /* repair */ }
  const repaired = s.replace(/,\s*([}\]])/g, '$1').replace(/[“”]/g, '"');
  try { return { ok: true, v: JSON.parse(repaired) }; } catch (e) { return { ok: false, error: e.message }; }
}
function firstBalanced(s) {
  const start = s.indexOf('{'); if (start < 0) return null;
  let depth = 0; let inStr = false; let esc = false;
  for (let i = start; i < s.length; i++) {
    const ch = s[i];
    if (inStr) { if (esc) esc = false; else if (ch === '\\') esc = true; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') inStr = true; else if (ch === '{') depth++; else if (ch === '}') { depth--; if (depth === 0) return s.slice(start, i + 1); }
  }
  return null;
}
function extractJson(text) {
  const s = String(text || '');
  if (!s.trim()) return { obj: null, how: null, error: 'the model returned an empty answer' };
  const fence = /```(?:json|JSON)?\s*\n?([\s\S]*?)```/g; let m;
  while ((m = fence.exec(s))) { const body = m[1].trim(); if (!body.startsWith('{')) continue; const r = tryParse(body); if (r.ok && r.v && typeof r.v === 'object' && !Array.isArray(r.v)) return { obj: r.v, how: 'fence' }; }
  const b = firstBalanced(s);
  if (b) { const r = tryParse(b); if (r.ok && r.v && typeof r.v === 'object' && !Array.isArray(r.v)) return { obj: r.v, how: 'brace' }; return { obj: null, how: null, error: `the JSON object could not be parsed (${r.error})` }; }
  return { obj: null, how: null, error: 'no JSON object found in the answer' };
}

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const arr = (v) => (v == null || v === '' ? [] : Array.isArray(v) ? v : [v]);
function str(v, max = 4000) { if (v == null) return ''; const t = typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : ''; return t.trim().slice(0, max); }
function conf(v) { const n = Number(v); return Number.isFinite(n) ? Math.max(0, Math.min(1, n)) : null; }
function en(v, allowed, dflt) { const k = str(v).toLowerCase(); return allowed.includes(k) ? k : dflt; }

function vClassify(o, ctx, W) {
  const ids = new Set(ctx.ids || []);
  const d = { assets: [], merges: [] };
  for (const a of arr(o.assets).filter(isObj)) {
    const ref = str(a.ref || a.id, 80);
    if (!ids.has(ref)) { W.push(`classify: ref "${ref.slice(0, 40)}" was not supplied — dropped`); continue; }
    const type = en(a.type, TYPES, null);
    d.assets.push({ ref, type, vendor: str(a.vendor, 200) || null, model: str(a.model, 200) || null, category: str(a.category, 120) || null, confidence: conf(a.confidence), rationale: str(a.rationale, 2000) });
  }
  for (const mg of arr(o.merges).filter(isObj)) {
    const keep = str(mg.keep, 80); const dup = str(mg.duplicate || mg.dup, 80);
    if (!ids.has(keep) || !ids.has(dup) || keep === dup) { W.push('classify: a merge references an id that was not supplied — dropped'); continue; }
    d.merges.push({ keep, duplicate: dup, confidence: conf(mg.confidence), rationale: str(mg.rationale, 2000) });
  }
  return d;
}
function vRelate(o, ctx, W) {
  const ids = new Set(ctx.ids || []);
  const d = { relationships: [] };
  for (const r of arr(o.relationships).filter(isObj)) {
    const from = str(r.from, 80); const to = str(r.to, 80); const type = en(r.type, REL_TYPES, null);
    if (!ids.has(from) || !ids.has(to) || from === to || !type) { W.push('relate: a relationship references an unknown id or type — dropped'); continue; }
    d.relationships.push({ from, to, type, confidence: conf(r.confidence), rationale: str(r.rationale, 2000) });
  }
  return d;
}
function vRefresh(o, ctx, W) {
  const ids = new Set(ctx.ids || []);
  const d = { summary: str(o.summary, 6000), items: [], risks: arr(o.risks).map((x) => str(x, 1000)).filter(Boolean).slice(0, 30) };
  for (const it of arr(o.items).filter(isObj)) {
    const aid = str(it.asset_id, 80);
    if (!ids.has(aid)) { W.push(`refresh: asset_id "${aid.slice(0, 40)}" was not supplied — dropped`); continue; }
    d.items.push({ asset_id: aid, action: en(it.action, ['replace', 'renew', 'monitor', 'retire'], 'monitor'), when: str(it.when, 60), reason: str(it.reason, 2000), estimated_cost: Number.isFinite(Number(it.estimated_cost)) ? Number(it.estimated_cost) : null });
  }
  return d;
}

const V = { classify: vClassify, relate: vRelate, refresh: vRefresh };

function validateOutput(kind, text, ctx = {}, res = {}) {
  const x = extractJson(text);
  const pre = [];
  if (res.truncated) pre.push('the model answer was truncated (max tokens) — content may be incomplete');
  if (!x.obj) return { ai: { raw: String(text || '').slice(0, 100000) }, validation: { ok: false, parsed_by: null, errors: [x.error], warnings: pre } };
  if (x.how === 'brace') pre.push('the JSON was not inside a ```json fence (recovered from the first {...} block)');
  const fn = V[kind]; if (!fn) return { ai: x.obj, validation: { ok: false, parsed_by: x.how, errors: [`no validator for ${kind}`], warnings: pre } };
  const W = [];
  let data; try { data = fn(x.obj, ctx, W); } catch (e) { return { ai: { raw: JSON.stringify(x.obj).slice(0, 100000) }, validation: { ok: false, parsed_by: x.how, errors: [`validation failed: ${e.message}`], warnings: pre } }; }
  return { ai: data, validation: { ok: true, parsed_by: x.how, errors: [], warnings: pre.concat(W) } };
}

module.exports = { extractJson, validateOutput };
