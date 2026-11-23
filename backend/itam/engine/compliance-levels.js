// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * One compliance language for every register page (PDPL, NDMO; NCA ECC computes the same in pyengine/nca_ecc_rules.py):
 * each applicable item is fully compliant, partially compliant, not compliant, or not assessed yet - and a group (a domain, a
 * chapter, the whole register) gets the share of its items at each level, in whole percentages that add up to exactly 100,
 * and a status: fully compliant only when every item is; partially when some are met (fully or partly); not compliant when
 * none is met and at least one was found not compliant; otherwise not assessed. "Not assessed" (no evidence, a source not
 * connected, waiting for approval, an automated pass still to confirm) is never counted as compliant.
 *   levels(rows, map)            → { status, counts, pct, applicable }     map: result → fully|partially|not|not_assessed|na
 *   group(rows, key, map, names) → [{ key, name, ...levels }] in the order of names (or first seen)
 *   levelOf(result, map)         → the level of one item ('not_applicable' for na)
 */
const KEYS = ['fully', 'partially', 'not', 'not_assessed'];
const levelOf = (result, map) => { const l = map[result]; return l === 'na' ? 'not_applicable' : (KEYS.includes(l) ? l : 'not_assessed'); };

function pct(cnt, total) {
  if (!total) return { fully: 0, partially: 0, not: 0, not_assessed: 0 };
  const raw = {}, out = {};
  for (const k of KEYS) { raw[k] = 100 * (cnt[k] || 0) / total; out[k] = Math.floor(raw[k]); }
  let left = 100 - KEYS.reduce((a, k) => a + out[k], 0);
  for (const k of KEYS.slice().sort((a, b) => (raw[b] - out[b]) - (raw[a] - out[a]))) { if (left <= 0) break; out[k]++; left--; }   // largest remainder
  return out;
}

function levels(rows, map) {
  const counts = { fully: 0, partially: 0, not: 0, not_assessed: 0 };
  let n = 0;
  for (const r of rows || []) { const l = levelOf(r.result, map); if (l === 'not_applicable') continue; counts[l]++; n++; }
  const status = !n ? 'not_applicable' : counts.fully === n ? 'fully_compliant' : (counts.fully || counts.partially) ? 'partially_compliant' : counts.not ? 'not_compliant' : 'not_assessed';
  return { status, counts, pct: pct(counts, n), applicable: n };
}

function group(rows, key, map, names) {
  const order = names ? names.map((x) => x[0]) : [...new Set((rows || []).map((r) => r[key]))];
  const nm = new Map((names || []).map((x) => [x[0], x[1]]));
  return order.map((k) => Object.assign({ key: k, name: nm.get(k) || k }, levels((rows || []).filter((r) => r[key] === k), map)));
}

module.exports = { levels, group, levelOf, pct, KEYS };
