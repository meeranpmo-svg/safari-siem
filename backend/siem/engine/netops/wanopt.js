// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body: check } = require('../util/check');
const { guard: guardJob } = require('../util/errors');
/*
 * WAN Optimization (HPE Aruba EdgeConnect / Silver Peak) - what the optimisation saves and whether the overlay is healthy, from
 * the Orchestrator the AI Network Engineer already polls (collectors.js edgeconnect: appliances, active alarms and - read-only -
 * the aggregate statistics of the last window). Nothing is changed on an appliance or on the Orchestrator.
 *   reduction   per appliance and per application: LAN-side bytes (before optimisation) against WAN-side bytes (after):
 *               saved = LAN - WAN, reduction = 1 - WAN / LAN. Only when BOTH sides are reported - a missing counter is "not
 *               reported", never zero; the Orchestrator field names used are shown (they differ between releases).
 *   tunnels     loss / latency / jitter (and a down state) against thresholds an administrator sets.
 *   alarms      the Orchestrator's active alarms by severity.
 *   learning    one reduction sample per appliance per day (60 days): a day far below the appliance's own usual reduction (median
 *               less max(10 points, 3 x MAD), 7+ days of history) is "optimisation dropped" - typically traffic that became
 *               encrypted, a bypassed / pass-through appliance or a policy change. Low reduction on heavy traffic is noted too.
 *   actions     ranked: what to do first.
 *   GET  /netops/wanopt          any role
 *   POST /netops/wanopt/config   admin  {loss_warn, loss_crit, lat_warn, lat_crit, jit_warn, jit_crit}
 */
const DEF = { loss_warn: 2, loss_crit: 10, lat_warn: 150, lat_crit: 400, jit_warn: 30, jit_crit: 60 };
const KEEP_DAYS = 60, RIYADH = 3 * 3600000;
const r1 = (x) => (x == null || !isFinite(x) ? null : Math.round(x * 10) / 10);
const low = (s) => String(s == null ? '' : s).toLowerCase();
const sum = (...a) => (a.some((x) => x == null) ? null : a.reduce((n, x) => n + x, 0));
const median = (a) => { const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length ? (s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2) : null; };
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
function red(lan, wan) { if (lan == null || wan == null || lan <= 0) return { saved: null, reduction: null }; return { saved: Math.max(0, lan - wan), reduction: r1((1 - wan / lan) * 100) }; }
const both = (r) => ({ lan: r.lan_tx == null && r.lan_rx == null ? null : (r.lan_tx || 0) + (r.lan_rx || 0), wan: r.wan_tx == null && r.wan_rx == null ? null : (r.wan_tx || 0) + (r.wan_rx || 0) });

function analyse({ orchestrators = [], th = DEF, hist = {}, now = Date.now() }) {
  const T = Object.assign({}, DEF, th), apps = {}, appliances = [], tunnels = [], alarms = [], keys = {}, errors = [];
  let polled = false;
  for (const o of orchestrators) {
    const s = o.snapshot || {}, sd = s.sdwan || {}, W = s.wanopt || null;
    if (s.at) polled = true;
    for (const e of (W && W.errors) || []) errors.push(o.name + ': ' + e);
    if (W) for (const [k, v] of Object.entries(W.keys || {})) keys[k] = (keys[k] || []).concat(v || []);
    const statBy = new Map(); for (const r of (W && W.appliances) || []) { statBy.set(low(r.name), r); if (r.appliance) statBy.set(low(r.appliance), r); }
    const seen = new Set();
    for (const a of sd.appliances || []) {
      const st = statBy.get(low(a.name)) || null; if (st) seen.add(st);
      const b = st ? both(st) : { lan: null, wan: null }, rr = red(b.lan, b.wan);
      appliances.push({ name: a.name, site: a.site || '', model: a.model || '', version: a.version || '', up: !!a.up, state: a.state, orchestrator: o.name, lan_bytes: b.lan, wan_bytes: b.wan, saved_bytes: rr.saved, reduction: rr.reduction });
    }
    for (const st of (W && W.appliances) || []) if (!seen.has(st)) { const b = both(st), rr = red(b.lan, b.wan); appliances.push({ name: st.name || st.appliance, site: '', model: '', version: '', up: null, state: null, orchestrator: o.name, lan_bytes: b.lan, wan_bytes: b.wan, saved_bytes: rr.saved, reduction: rr.reduction, stats_only: true }); }
    for (const r of (W && W.applications) || []) { const b = both(r), k = r.name || '(unnamed)', A = apps[k] || (apps[k] = { name: k, lan: null, wan: null }); if (b.lan != null) A.lan = (A.lan || 0) + b.lan; if (b.wan != null) A.wan = (A.wan || 0) + b.wan; }
    for (const t of (W && W.tunnels) || []) {
      const why = []; let lvl = 'ok';
      const set = (l, w) => { why.push(w); if (l === 'critical' || lvl === 'ok') lvl = l; };
      if (t.state && /down|dead|fail/i.test(String(t.state))) set('critical', 'state ' + t.state);
      if (t.loss_pct != null) { if (t.loss_pct >= T.loss_crit) set('critical', 'loss ' + r1(t.loss_pct) + '%'); else if (t.loss_pct >= T.loss_warn) set('warning', 'loss ' + r1(t.loss_pct) + '%'); }
      if (t.latency_ms != null) { if (t.latency_ms >= T.lat_crit) set('critical', 'latency ' + r1(t.latency_ms) + ' ms'); else if (t.latency_ms >= T.lat_warn) set('warning', 'latency ' + r1(t.latency_ms) + ' ms'); }
      if (t.jitter_ms != null) { if (t.jitter_ms >= T.jit_crit) set('critical', 'jitter ' + r1(t.jitter_ms) + ' ms'); else if (t.jitter_ms >= T.jit_warn) set('warning', 'jitter ' + r1(t.jitter_ms) + ' ms'); }
      tunnels.push({ name: t.name, appliance: t.appliance, orchestrator: o.name, state: t.state, loss_pct: r1(t.loss_pct), latency_ms: r1(t.latency_ms), jitter_ms: r1(t.jitter_ms), level: lvl, why: why.join(', ') || 'within the thresholds' });
    }
    for (const a of sd.alarms || []) alarms.push(Object.assign({ orchestrator: o.name }, a));
  }
  const LV = { critical: 2, warning: 1, ok: 0 };
  tunnels.sort((a, b) => LV[b.level] - LV[a.level] || (b.loss_pct || 0) - (a.loss_pct || 0) || (b.latency_ms || 0) - (a.latency_ms || 0));
  const application = Object.values(apps).map((a) => Object.assign({ name: a.name, lan_bytes: a.lan, wan_bytes: a.wan }, (() => { const x = red(a.lan, a.wan); return { saved_bytes: x.saved, reduction: x.reduction }; })()))
    .sort((a, b) => (b.lan_bytes || 0) - (a.lan_bytes || 0)).slice(0, 25);
  // learning: today's reduction against the appliance's own days
  for (const a of appliances) {
    const d = (hist[a.name] || []).filter((x) => x.red != null), today = a.reduction;
    if (d.length < 7) { a.learning = 'needs 7 days of samples - has ' + d.length; continue; }
    const m = median(d.map((x) => x.red)), mad = median(d.map((x) => Math.abs(x.red - m))) || 0, floor = m - Math.max(10, 3 * 1.4826 * mad);
    a.usual = r1(m); a.dropped = today != null && today < floor;
  }
  const sev = (s0) => { const s = low(s0); return (/crit/.test(s) ? 'critical' : /major/.test(s) ? 'major' : /minor/.test(s) ? 'minor' : /warn/.test(s) ? 'warning' : 'info'); };
  const alarmBy = { critical: 0, major: 0, minor: 0, warning: 0, info: 0 }; for (const a of alarms) alarmBy[sev(a.severity)]++;
  const tot = appliances.reduce((n, a) => { if (a.lan_bytes != null && a.wan_bytes != null) { n.lan += a.lan_bytes; n.wan += a.wan_bytes; n.n++; } return n; }, { lan: 0, wan: 0, n: 0 });
  const tr = tot.n ? red(tot.lan, tot.wan) : { saved: null, reduction: null };
  const kpis = { appliances: appliances.length, down: appliances.filter((a) => a.up === false).length, measured: tot.n, lan_bytes: tot.n ? tot.lan : null, wan_bytes: tot.n ? tot.wan : null, saved_bytes: tr.saved, reduction: tr.reduction,
    tunnels: tunnels.length, tunnels_critical: tunnels.filter((t) => t.level === 'critical').length, tunnels_warning: tunnels.filter((t) => t.level === 'warning').length,
    alarms_critical: alarmBy.critical, alarms_major: alarmBy.major, dropped: appliances.filter((a) => a.dropped).length };
  const actions = [], names = (L, f) => L.slice(0, 4).map(f).join(', ') + (L.length > 4 ? ' +' + (L.length - 4) : '');
  const dn = appliances.filter((a) => a.up === false); if (dn.length) actions.push({ priority: 100, title: dn.length + ' appliance(s) down', detail: names(dn, (a) => a.name + (a.site ? ' (' + a.site + ')' : '')) + ' - the site runs without the overlay or not at all; check power, the WAN links and the Orchestrator.', filter: 'appliances' });
  const tc = tunnels.filter((t) => t.level === 'critical'); if (tc.length) actions.push({ priority: 90, title: tc.length + ' tunnel(s) over the critical threshold', detail: names(tc, (t) => t.name + ': ' + t.why), filter: 'tunnels' });
  if (alarmBy.critical + alarmBy.major) actions.push({ priority: 80, title: (alarmBy.critical + alarmBy.major) + ' critical / major Orchestrator alarm(s)', detail: names(alarms.filter((a) => /crit|major/.test(sev(a.severity))), (a) => a.appliance + ': ' + a.text), filter: 'alarms' });
  const dr = appliances.filter((a) => a.dropped); if (dr.length) actions.push({ priority: 60, title: 'Optimisation dropped on ' + dr.length + ' appliance(s)', detail: names(dr, (a) => a.name + ' ' + a.reduction + '% (usually ' + a.usual + '%)') + ' - encrypted traffic, pass-through, or a policy change.', filter: 'appliances' });
  const tw = tunnels.filter((t) => t.level === 'warning'); if (tw.length) actions.push({ priority: 40, title: tw.length + ' tunnel(s) over the warning threshold', detail: names(tw, (t) => t.name + ': ' + t.why), filter: 'tunnels' });
  const weak = appliances.filter((a) => a.reduction != null && a.reduction < 5 && (a.lan_bytes || 0) > 1e9); if (weak.length) actions.push({ priority: 30, title: weak.length + ' busy appliance(s) with almost no reduction', detail: names(weak, (a) => a.name + ' ' + a.reduction + '%') + ' - mostly encrypted or already-compressed traffic; check the application mix.', filter: 'applications' });
  if (errors.length) actions.push({ priority: 20, title: 'Some statistics were not read from the Orchestrator', detail: errors.slice(0, 3).join(' · ') + ' - the API key may lack the right, or this release uses other paths (set them on the device in Network Onboarding).', filter: 'connections' });
  actions.sort((a, b) => b.priority - a.priority);
  const configured = orchestrators.length > 0;
  return { configured, reason: configured ? null : 'No Silver Peak / EdgeConnect Orchestrator is connected - add it in Network Onboarding (vendor edgeconnect, API key), then its appliances and statistics appear here.',
    polled, at: now, thresholds: T, kpis, appliances: appliances.sort((a, b) => (b.up === false) - (a.up === false) || (b.lan_bytes || 0) - (a.lan_bytes || 0)), applications: application, tunnels: tunnels.slice(0, 500),
    alarms: alarms.slice(0, 200), alarm_counts: alarmBy, keys, errors, actions,
    note: 'Reduction = 1 - WAN bytes / LAN bytes over the last statistics window, only where the Orchestrator reports both sides. Read only: nothing is changed on an appliance.' };
}

function createWanopt({ inventory, poller, state, now } = {}) {
  const NOW = now || Date.now, dayC = state.collection('wanopt_daily'), cfgC = state.collection('wanopt_cfg');
  const th = () => Object.assign({}, DEF, (cfgC.get('cfg') || {}).th || {});
  const orchestrators = () => inventory.list().filter((d) => d.vendor === 'edgeconnect' || d.role === 'sdwan-orchestrator').map((d) => ({ id: d.id, name: d.name, snapshot: poller.snapshot(d.id) }));
  const hist = () => { const h = {}; for (const r of dayC.all()) h[r.id] = r.d || []; return h; };
  function view() { return analyse({ orchestrators: orchestrators(), th: th(), hist: hist(), now: NOW() }); }
  function record() {
    const v = view(), day = new Date(NOW() + RIYADH).toISOString().slice(0, 10); let n = 0;
    for (const a of v.appliances) {
      if (a.reduction == null) continue;
      const r = dayC.get(a.name) || { id: a.name, d: [] }, last = r.d[r.d.length - 1];
      if (last && last.day === day) last.red = a.reduction; else r.d.push({ day, red: a.reduction });
      r.d = r.d.slice(-KEEP_DAYS); dayC.put(r); n++;
    }
    return n;
  }
  function setConfig(b0, user) {
    const c = check(b0 || {}), o = {};
    for (const [k, lo, hi] of [['loss_warn', 0, 100], ['loss_crit', 0, 100], ['lat_warn', 1, 5000], ['lat_crit', 1, 5000], ['jit_warn', 1, 2000], ['jit_crit', 1, 2000]]) c.num(k, { min: lo, max: hi });
    Object.assign(o, c.done());
    const next = Object.assign({}, th(), o);
    for (const p of ['loss', 'lat', 'jit']) if (next[p + '_warn'] >= next[p + '_crit']) throw bad(p + '_warn must be below ' + p + '_crit');
    const before = th(); cfgC.put({ id: 'cfg', th: next, updated_by: user, updated_at: NOW() });
    return { thresholds: next, before };
  }
  let timer = null;
  function start({ firstMs = 300000, everyMs = 3600000 } = {}) {
    stop(); const run = guardJob('netops.wanopt.record', record);
    const loop = async () => { try { await run(); } finally { timer = setTimeout(loop, everyMs); if (timer.unref) timer.unref(); } };
    timer = setTimeout(loop, firstMs); if (timer.unref) timer.unref();
  }
  function stop() { if (timer) clearTimeout(timer); timer = null; }
  return { view, record, setConfig, start, stop, thresholds: th };
}

module.exports = { createWanopt, analyse, red, DEF };
