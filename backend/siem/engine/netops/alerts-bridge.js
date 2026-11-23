// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Network and support conditions → SIEM alerts, so they reach the alert queue, the SOC's routing and notifications like
 * any detection. Before this the AI Network Engineer's findings were only on its own page.
 *   Raised (rule ids netops-<kind>):
 *     support-expired / support-expiring / license-expired / license-expiring   what FortiGate and PAN-OS report about
 *        their own support contract and security subscriptions (an expired AV / IPS / URL subscription = that protection
 *        is no longer updated)
 *     unreachable (critical devices: core, WAN edge, firewall)
 *     + any kind listed in config.netops.alerts.kinds
 *   and from IT Asset Management (support contracts register, every 6 h): support-contract-expired / -expiring for every
 *   contract that has ended or ends within contract_warn_days (default 30).
 * One alert per condition (group_key = finding id / contract id); while it stays open, later sightings merge into it
 * (count, last seen). Nothing is closed automatically: a person closes the alert, and a condition that comes back after
 * that raises a new one. Severity: high = 3, medium = 2, critical = 4.
 *   createNetopsAlerts({ alerts, findings: () => [...], contracts?: async () => view, config, log, now })
 *     .tick() → {raised, merged}   .contractsTick() → {raised, merged, error?}   .start() .stop() .stats()
 */
const SEV = { low: 1, medium: 2, high: 3, critical: 4 };
const ALWAYS = ['support-expired', 'support-expiring', 'license-expired', 'license-expiring'];
const LABEL = { 'support-expired': 'Device support contract expired', 'support-expiring': 'Device support contract ending', 'license-expired': 'Security subscription expired',
  'license-expiring': 'Security subscription ending', unreachable: 'Critical network device unreachable' };

function createNetopsAlerts({ alerts, findings, contracts, config, log, now } = {}) {
  const cfg = Object.assign({ enabled: true, kinds: [], interval_s: 300, contracts_interval_s: 21600, contract_warn_days: 30 }, (config && config.netops && config.netops.alerts) || {});
  const L = log || { info() {}, warn() {} }, NOW = now || Date.now;
  const st = { ticks: 0, raised: 0, merged: 0, last: 0, contracts_last: 0, contracts_error: '' };
  let t1 = null, t2 = null;
  function wanted(f) {
    if (ALWAYS.includes(f.kind)) return true;
    if (f.kind === 'unreachable') return f.severity === 'critical';
    return (cfg.kinds || []).includes(f.kind);
  }
  function raise(p) { const r = alerts.raise(p); if (r.created) st.raised++; else st.merged++; return r; }
  function tick() {
    if (!cfg.enabled || !alerts) return { raised: 0, merged: 0 };
    const t = NOW(), before = st.raised, m0 = st.merged;
    for (const f of findings()) {
      if (!wanted(f)) continue;
      try {
        raise({ rule_id: 'netops-' + f.kind, rule_name: LABEL[f.kind] || 'Network: ' + f.kind, rule_type: 'netops', severity: SEV[f.severity] || 2, ts_first: t, ts_last: t, count: 1,
          group: { device: f.device_name || f.device, site: f.site || '' }, group_key: f.id, summary: f.title, host: f.device_name || '', source: 'netops', src_type: 'netops', src_id: f.device,
          suppress_s: 7 * 86400, fields: { evidence: (f.evidence || []).slice(0, 6), recommendation: f.recommendation || '', vendor: f.vendor || '', kind: f.kind } });
      } catch (e) { L.warn('netops alert not raised', { id: f.id, err: e.message }); }
    }
    st.ticks++; st.last = t;
    return { raised: st.raised - before, merged: st.merged - m0 };
  }
  async function contractsTick() {
    if (!cfg.enabled || !alerts || !contracts) return { raised: 0, merged: 0 };
    const t = NOW(), before = st.raised, m0 = st.merged;
    let v; try { v = await contracts(); st.contracts_error = ''; } catch (e) { st.contracts_error = String(e.message || e).slice(0, 200); return { raised: 0, merged: 0, error: st.contracts_error }; }
    for (const c of (v && v.contracts) || []) {
      if (c.state === 'retired' || c.days_left == null) continue;
      const expired = c.days_left < 0;
      if (!expired && c.days_left > cfg.contract_warn_days) continue;
      raise({ rule_id: expired ? 'support-contract-expired' : 'support-contract-expiring', rule_name: expired ? 'Support contract expired' : 'Support contract ending', rule_type: 'support', severity: 3, ts_first: t, ts_last: t, count: 1,
        group: { vendor: c.vendor, contract: c.contract_number || c.id }, group_key: c.id + ':' + c.end, summary: `${c.vendor} ${c.product}${c.contract_number ? ' (' + c.contract_number + ')' : ''} ${expired ? 'expired ' + c.end : 'ends ' + c.end + ' (' + c.days_left + ' days)'} - covers ${c.covered_count} asset(s)`,
        source: 'itam', src_type: 'support-contract', src_id: c.id, suppress_s: 30 * 86400, fields: { owner: c.owner || '', portal: c.portal || '', issues: (c.issues || []).map((i) => i.text).slice(0, 6) } });
    }
    st.contracts_last = t;
    return { raised: st.raised - before, merged: st.merged - m0 };
  }
  function start() {
    stop(); if (!cfg.enabled || !alerts) return;
    t1 = setInterval(() => { try { tick(); } catch (e) { L.warn('netops alerts tick failed', { err: e.message }); } }, Math.max(60, cfg.interval_s) * 1000);
    t2 = setInterval(guardJob('netops.alerts-bridge.contractsTick', () => contractsTick()), Math.max(3600, cfg.contracts_interval_s) * 1000);
    const first = setTimeout(() => { guardJob('netops.alerts-bridge.tick', tick)(); guardJob('netops.alerts-bridge.contractsTick', () => contractsTick())(); }, 120000);
    for (const x of [t1, t2, first]) if (x && x.unref) x.unref();
  }
  function stop() { if (t1) clearInterval(t1); if (t2) clearInterval(t2); t1 = t2 = null; }
  return { tick, contractsTick, start, stop, stats: () => Object.assign({ enabled: cfg.enabled }, st), wanted };
}

module.exports = { createNetopsAlerts, ALWAYS };
