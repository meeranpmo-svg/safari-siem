// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * UPS / power - every UPS the AI Network Engineer polls (inventory role "ups", SNMP), read through the standard UPS-MIB (collectors.js
 * upsCollect). Nothing is changed on a UPS: no self-test, no shutdown, no setting.
 *   state      on battery / low or depleted battery / on bypass / fault (alarm) / online / not answering / not polled - from what the UPS
 *              reports, never assumed; a value the SNMP card does not give stays "not reported".
 *   runtime    minutes left at the present load; below the site's need (default 15 min) is a finding.
 *   ageing     one sample a day per UPS (90 days) of the runtime it reports at full charge (>= 95 %) and its load. When today's runtime,
 *              at a load within 10 points of the samples', is 20 % or more below their median (7+ comparable days), the battery is
 *              likely ageing - plan the replacement. Said with the numbers; not a battery test.
 *   actions    ranked: on battery now, low / depleted, fault alarms, short runtime, failed self-test, ageing, not answering.
 *   GET /netops/ups   any role
 */
const KEEP = 90, MIN_RUNTIME = 15, RIYADH = 3 * 3600000;
const median = (a) => { const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length ? (s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2) : null; };
const FAULT = /bad|fail|fault|overload|output off|system off|shutdown|communications lost|temperature/i;

function stateOf(dev, snap) {
  const u = snap && snap.ups;
  if (!dev.poll || !dev.poll.snmp) return { state: 'not-polled', why: 'SNMP polling is off for this device (AI Network Engineer -> device -> poll)' };
  if (!snap) return { state: 'unknown', why: 'not polled yet since the engine started' };
  if (!u) return { state: 'not-answering', why: String((snap.errors || []).find((e) => /ups-mib|snmp/.test(e)) || 'no UPS-MIB answer').slice(0, 200) };
  if (u.output_source === 'battery' || (u.seconds_on_battery || 0) > 0) return { state: 'on-battery', why: 'running on battery' + (u.minutes_left != null ? ' - about ' + u.minutes_left + ' min left' : '') };
  if (u.battery === 'depleted') return { state: 'depleted', why: 'battery depleted' };
  if (u.battery === 'low') return { state: 'low', why: 'battery low' };
  if (u.output_source === 'bypass') return { state: 'bypass', why: 'output on bypass - the load is not protected' };
  const f = (u.alarms || []).filter((a) => FAULT.test(a));
  if (f.length) return { state: 'fault', why: f.join(', ') };
  if (u.output_source === 'normal' || u.battery === 'normal') return { state: 'online', why: 'on mains' + (u.battery ? ', battery ' + u.battery : '') };
  return { state: 'unknown', why: 'the UPS did not report its output source or battery status' };
}

function analyse({ devices = [], snapshot = () => null, hist = {}, minRuntime = MIN_RUNTIME, now = Date.now() }) {
  const ups = devices.filter((d) => d.role === 'ups').map((d) => {
    const s = snapshot(d.id), u = (s && s.ups) || {}, st = stateOf(d, s);
    const h = (hist[d.id] || []).filter((x) => x.runtime != null && x.load != null), ageing = { samples: h.length };
    if (u.minutes_left != null && u.load_pct != null && (u.charge_pct == null || u.charge_pct >= 95)) {
      const near = h.filter((x) => Math.abs(x.load - u.load_pct) <= 10);
      if (near.length >= 7) { const m = median(near.map((x) => x.runtime)); ageing.usual = m; ageing.flag = m > 0 && u.minutes_left <= m * 0.8; if (ageing.flag) ageing.why = u.minutes_left + ' min at ' + u.load_pct + '% load - usually ' + m + ' min at a similar load (' + near.length + ' days)'; }
      else ageing.learning = 'needs 7 days at a similar load - has ' + near.length;
    } else ageing.learning = 'needs runtime and load reported at full charge';
    return { id: d.id, name: d.name, ip: d.ip, site: d.site || '', state: st.state, why: st.why, manufacturer: u.manufacturer || '', model: u.model || '',
      battery: u.battery || null, charge_pct: u.charge_pct != null ? u.charge_pct : null, minutes_left: u.minutes_left != null ? u.minutes_left : null, load_pct: u.load_pct != null ? u.load_pct : null,
      temp_c: u.temp_c != null ? u.temp_c : null, input_voltage: u.input_voltage != null ? u.input_voltage : null, output_source: u.output_source || null, alarms: u.alarms || [], last_test: u.last_test || null,
      short_runtime: u.minutes_left != null && u.minutes_left < minRuntime, ageing, at: s ? s.at : null };
  });
  const RANK = { 'on-battery': 9, depleted: 8, low: 7, fault: 6, bypass: 5, 'not-answering': 4, unknown: 2, 'not-polled': 1, online: 0 };
  ups.sort((a, b) => RANK[b.state] - RANK[a.state] || String(a.site).localeCompare(String(b.site)) || String(a.name).localeCompare(String(b.name)));
  const c = (f) => ups.filter(f).length;
  const kpis = { ups: ups.length, online: c((u) => u.state === 'online'), on_battery: c((u) => u.state === 'on-battery'), low: c((u) => u.state === 'low' || u.state === 'depleted'),
    fault: c((u) => u.state === 'fault' || u.state === 'bypass'), not_answering: c((u) => u.state === 'not-answering' || u.state === 'unknown' || u.state === 'not-polled'),
    short_runtime: c((u) => u.short_runtime), ageing: c((u) => u.ageing.flag), test_failed: c((u) => u.last_test === 'failed'),
    min_runtime: (() => { const v = ups.map((u) => u.minutes_left).filter((x) => x != null); return v.length ? Math.min(...v) : null; })() };
  const names = (L) => L.slice(0, 4).map((u) => u.name + (u.site ? ' (' + u.site + ')' : '')).join(', ') + (L.length > 4 ? ' +' + (L.length - 4) : '');
  const actions = [], A = (p, f, t, d) => { const L = ups.filter(f); if (L.length) actions.push({ priority: p, title: L.length + ' ' + t, detail: names(L) + d }); };
  A(100, (u) => u.state === 'on-battery', 'UPS on battery now', ' - mains is lost at the site; check the supply and plan a graceful shutdown before the runtime ends.');
  A(90, (u) => u.state === 'low' || u.state === 'depleted', 'UPS with a low or depleted battery', ' - the load will drop on the next outage.');
  A(80, (u) => u.state === 'fault' || u.state === 'bypass', 'UPS with a fault or on bypass', ' - the load is not protected; call the vendor.');
  A(60, (u) => u.short_runtime, 'UPS with less than ' + minRuntime + ' minutes of runtime', ' - not enough to ride through or shut down cleanly.');
  A(50, (u) => u.last_test === 'failed', 'UPS whose last self-test failed', ' - replace or service the battery.');
  A(40, (u) => u.ageing.flag, 'UPS battery likely ageing', ' - runtime well below its own usual at a similar load; plan the replacement.');
  A(30, (u) => u.state === 'not-answering' || u.state === 'unknown', 'UPS not answering the UPS-MIB', ' - check the SNMP card, the community / user and that the role is "ups".');
  actions.sort((a, b) => b.priority - a.priority);
  return { configured: ups.length > 0, reason: ups.length ? null : 'No UPS is monitored. Add each UPS in Network Onboarding with role "ups" and its SNMP community or v3 user (read only) - the UPS-MIB is then read on every poll.',
    at: now, min_runtime_need: minRuntime, kpis, ups, actions, note: 'Read from each UPS through the standard UPS-MIB. Nothing is sent to a UPS. Ageing is a trend in the runtime the UPS reports, not a battery test.' };
}

function createUps({ inventory, poller, state, now } = {}) {
  const NOW = now || Date.now, dayC = state.collection('ups_daily');
  const hist = () => { const h = {}; for (const r of dayC.all()) h[r.id] = r.d || []; return h; };
  const view = () => analyse({ devices: inventory.list(), snapshot: (id) => poller.snapshot(id), hist: hist(), now: NOW() });
  function record() {
    const day = new Date(NOW() + RIYADH).toISOString().slice(0, 10); let n = 0;
    for (const d of inventory.list().filter((x) => x.role === 'ups')) {
      const u = (poller.snapshot(d.id) || {}).ups; if (!u || u.minutes_left == null || u.load_pct == null || (u.charge_pct != null && u.charge_pct < 95) || u.output_source === 'battery') continue;
      const r = dayC.get(d.id) || { id: d.id, d: [] }, last = r.d[r.d.length - 1];
      if (last && last.day === day) { last.runtime = u.minutes_left; last.load = u.load_pct; } else r.d.push({ day, runtime: u.minutes_left, load: u.load_pct });
      r.d = r.d.slice(-KEEP); dayC.put(r); n++;
    }
    return n;
  }
  let timer = null;
  function start({ firstMs = 600000, everyMs = 6 * 3600000 } = {}) {
    stop(); const run = guardJob('netops.ups.record', record);
    const loop = async () => { try { await run(); } finally { timer = setTimeout(loop, everyMs); if (timer.unref) timer.unref(); } };
    timer = setTimeout(loop, firstMs); if (timer.unref) timer.unref();
  }
  function stop() { if (timer) clearTimeout(timer); timer = null; }
  return { view, record, start, stop };
}

module.exports = { createUps, analyse, stateOf };
