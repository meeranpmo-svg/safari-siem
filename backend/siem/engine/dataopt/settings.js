// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Optimizer — settings (DATAOPT.md "/dataopt/settings"): cost per GB, retention tiers, protect-detections toggle.
 * Stored as a single document in the state collection "dataopt_settings" (id "settings"), merged over defaults.
 *   createSettings({ state, config, log }) → { get(), set(patch, user) → settings, DEFAULTS }
 */
const DEFAULTS = {
  currency: 'SAR',
  cost_per_gb_month: 1.5,        // hot-store SAR per GB per month (configurable)
  archive_cost_per_gb_month: 0.1, // cold tier SAR per GB per month
  hot_retention_days: 365,
  archive_retention_days: 730,
  protect_detections: true,       // blind-spot guard: drop/heavy-sample/trim needs an override when it hurts detection
  heavy_sample_rate: 0.5,         // sample rate at/below which a sample rule is treated as "heavy" by the guard
  drop_stub_default: true,
};

const NUM_KEYS = new Set(['cost_per_gb_month', 'archive_cost_per_gb_month', 'hot_retention_days', 'archive_retention_days', 'heavy_sample_rate']);
const BOOL_KEYS = new Set(['protect_detections', 'drop_stub_default']);

function createSettings({ state, config = {}, log } = {}) {
  const col = state ? state.collection('dataopt_settings') : null;
  // seed defaults from engine config where sensible
  const seeded = Object.assign({}, DEFAULTS);
  if (Number.isFinite(config.retention_days)) seeded.hot_retention_days = config.retention_days;

  function get() {
    const stored = col ? col.get('settings') : null;
    const { id, ...rest } = stored || {};
    return Object.assign({}, seeded, rest);
  }

  function set(patch, user) {
    if (!patch || typeof patch !== 'object') throw Object.assign(new Error('settings patch must be an object'), { code: 400 });
    const next = get();
    for (const [k, v] of Object.entries(patch)) {
      if (k === 'currency') { next.currency = String(v).slice(0, 8); continue; }
      if (NUM_KEYS.has(k)) { const n = Number(v); if (!Number.isFinite(n) || n < 0) throw Object.assign(new Error(`${k} must be a non-negative number`), { code: 400 }); next[k] = n; continue; }
      if (BOOL_KEYS.has(k)) { next[k] = !!v; continue; }
      // ignore unknown keys
    }
    if (next.heavy_sample_rate > 1) next.heavy_sample_rate = 1;
    if (col) col.put(Object.assign({ id: 'settings' }, next, { updated: Date.now(), updated_by: user || '' }));
    if (log) log.info('dataopt: settings updated', { by: user || '', keys: Object.keys(patch) });
    return get();
  }

  return { get, set, DEFAULTS };
}

module.exports = { createSettings, DEFAULTS };
