// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Applications Manager insights - analysis over what the APM integration (integrations/me-apm.js) already reads and what the web tier
 * already samples every 5 minutes (integrations/webtier.js, state webtier_samples: every monitor, databases included). Nothing here talks
 * to Applications Manager; every fix is a Poll now or a maintenance request through the existing four-eyes actions.
 *   reliability   per monitor from the samples: availability over the kept window (7 days), outage episodes, MTTR (mean minutes down per
 *                 episode), MTBF (hours between episodes), flapping (3+ state changes in the last 24 samples), chronic (< 95 % available)
 *   problems      every managed monitor down / critical / warning, or with an open critical alarm, scored with every point named: state,
 *                 database, open for how long, chronic, flapping, recurring (3+ episodes), several monitors down on the same host (the host
 *                 is the probable cause - its monitors are grouped and counted once)
 *   alarms        alarm episodes kept per monitor + attribute (state apm_alarm_hist): NOISY (5+ episodes in 7 days - tune the threshold
 *                 in APM), LONG OPEN (critical for 24 h+)
 *   hygiene       monitors not polled for 3 poll intervals (stale), left unmanaged with no maintenance request open
 *   trend         one sample a day (apm_daily): monitors down + critical against the last 30 days (robust z on median / MAD, 7+ days)
 *   GET {P}/integrations/apm/insights    any signed-in role (monitor names and hosts only - no personal data)
 */
const { wrap, prefixOf } = require('../soc/routeutil');
const { guard: guardJob } = require('../util/errors');
const DAY = 86400000, SLOT = 5 * 60000, RIYADH = 3 * 3600000;
const median = (a) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };
const dayOf = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
const isUp = (m) => m.availability === 'up' && m.health !== 'critical';
function tsOf(v) { if (v == null || v === '') return null; const n = Number(v); if (Number.isFinite(n) && n > 1e11) return n; if (Number.isFinite(n) && n > 1e9) return n * 1000; const t = Date.parse(v); return Number.isFinite(t) ? t : null; }

// reliability from one monitor's 5-minute samples [{t, up, h}]
function reliability(s) {
  const L = (s || []).slice().sort((a, b) => a.t - b.t);
  if (!L.length) return { samples: 0 };
  const up = L.filter((x) => x.up).length, eps = []; let cur = null;
  for (const x of L) { if (!x.up) { if (!cur) cur = { from: x.t, to: x.t + SLOT }; else cur.to = x.t + SLOT; } else if (cur) { eps.push(cur); cur = null; } }
  if (cur) eps.push(Object.assign(cur, { open: true }));
  const span = (L[L.length - 1].t - L[0].t + SLOT) / 3600000, last24 = L.slice(-24); let changes = 0;
  for (let i = 1; i < last24.length; i++) if (last24[i].up !== last24[i - 1].up || last24[i].h !== last24[i - 1].h) changes++;
  const closed = eps.filter((e) => !e.open);
  return { samples: L.length, hours: Math.round(span * 10) / 10, availability: L.length >= 12 ? Math.round(up / L.length * 1000) / 10 : null, episodes: eps.length,
    mttr_min: closed.length ? Math.round(closed.reduce((a, e) => a + (e.to - e.from), 0) / closed.length / 60000) : null, mtbf_h: eps.length ? Math.round(span / eps.length * 10) / 10 : null,
    flapping: changes >= 3, changes_24: changes, down_since: cur || (eps.length && eps[eps.length - 1].open) ? eps[eps.length - 1].from : null };
}

function analyse(c, hist, now) {
  const t = now || Date.now(), out = { installed: !!c.installed, configured: !!(c.status && c.status.configured), status: c.status || null, kpis: {}, problems: [], hosts: [], noisy: [], long_open: [], stale: [], unmanaged: [], reliability: [], actions: [] };
  if (!out.installed) { out.reason = 'the Applications Manager integration is not installed - run the SIEM update'; return out; }
  if (!out.configured) { out.reason = 'Applications Manager is not connected - an administrator adds its address and API key on the Connection tab'; return out; }
  const M = c.monitors || [], A = c.alarms || [], S = c.samples || new Map(), AH = c.alarmHist || [], pollMin = (c.status && c.status.poll_min) || 5, openActs = c.openActions || [];
  const rel = new Map(M.map((m) => [m.id, reliability((S.get(m.id) || {}).s)]));
  // hosts with 2+ managed monitors down at once: the probable cause
  const byHost = new Map(); for (const m of M) if (m.managed && !isUp(m) && m.host) { const k = String(m.host).toLowerCase(); if (!byHost.has(k)) byHost.set(k, []); byHost.get(k).push(m); }
  const causeHosts = new Map([...byHost].filter(([, L]) => L.length >= 2));
  out.hosts = [...causeHosts].map(([h, L]) => ({ host: L[0].host, monitors: L.map((m) => ({ id: m.id, name: m.name, type: m.type })), why: L.length + ' monitors on this host are down or critical together - look at the host first' }));
  const openAl = A.filter((a) => a.severity !== 'clear');
  for (const m of M) {
    if (!m.managed) continue;
    const r = rel.get(m.id), al = openAl.filter((a) => a.resource_id === m.id), crit = al.filter((a) => a.severity === 'critical');
    if (isUp(m) && m.health !== 'warning' && !crit.length) continue;
    const why = [], add = (p, txt) => why.push({ points: p, text: txt });
    if (m.availability === 'down') add(40, 'down'); else if (m.health === 'critical') add(30, 'health critical'); else if (m.health === 'warning') add(10, 'health warning'); else if (crit.length) add(20, crit.length + ' critical alarm(s) open');
    if (m.db) add(10, 'a database - applications depend on it');
    const since = (r && r.down_since) || Math.min(...al.map((a) => tsOf(a.time) || t), t);
    const hrs = Math.max(0, Math.round((t - since) / 3600000 * 10) / 10); if (hrs >= 1) add(Math.min(20, Math.round(hrs / 2)), 'open for ' + hrs + ' h');
    if (r && r.availability != null && r.availability < 95) add(10, 'chronic: ' + r.availability + ' % available over ' + r.hours + ' h');
    if (r && r.flapping) add(10, 'flapping: ' + r.changes_24 + ' state changes in the last 2 h');
    if (r && r.episodes >= 3) add(10, r.episodes + ' outages in ' + r.hours + ' h');
    const ch = m.host && causeHosts.get(String(m.host).toLowerCase()); if (ch) add(10, 'host ' + m.host + ' has ' + ch.length + ' monitors down - probably the host');
    const score = Math.min(100, why.reduce((s, w) => s + w.points, 0));
    out.problems.push({ id: m.id, name: m.name, type: m.type, host: m.host, db: !!m.db, state: m.availability === 'down' ? 'down' : m.health, score, level: score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low', why, since: new Date(since).toISOString(), alarms: al.length, cause_host: ch ? m.host : null, message: m.message || '', suggest: ch ? 'host' : r && r.flapping ? 'tune' : 'poll' });
  }
  out.problems.sort((a, b) => b.score - a.score);
  // alarm noise and long-open alarms (episodes in apm_alarm_hist)
  for (const h of AH) {
    const recent = (h.episodes || []).filter((e) => t - e.from < 7 * DAY);
    if (recent.length >= 5) out.noisy.push({ resource_id: h.resource_id, name: h.name, attribute: h.attribute, episodes_7d: recent.length, median_min: median(recent.filter((e) => e.to).map((e) => Math.round((e.to - e.from) / 60000))) });
    if (h.open && h.open.severity === 'critical' && t - h.open.from > DAY) out.long_open.push({ resource_id: h.resource_id, name: h.name, attribute: h.attribute, hours: Math.round((t - h.open.from) / 3600000), message: h.open.message || '' });
  }
  out.noisy.sort((a, b) => b.episodes_7d - a.episodes_7d); out.long_open.sort((a, b) => b.hours - a.hours);
  // hygiene
  for (const m of M) {
    const lp = tsOf(m.last_polled);
    if (m.managed && lp && t - lp > 3 * pollMin * 60000 && t - lp > 30 * 60000) out.stale.push({ id: m.id, name: m.name, host: m.host, last_polled: new Date(lp).toISOString(), minutes: Math.round((t - lp) / 60000) });
    if (!m.managed) out.unmanaged.push({ id: m.id, name: m.name, host: m.host, maintenance_request: openActs.some((x) => x.resource_id === m.id && x.action === 'unmanage') });
  }
  // reliability table (worst first)
  out.reliability = M.map((m) => Object.assign({ id: m.id, name: m.name, type: m.type, host: m.host, db: !!m.db }, rel.get(m.id))).filter((x) => x.samples).sort((a, b) => (a.availability == null ? 101 : a.availability) - (b.availability == null ? 101 : b.availability)).slice(0, 300);
  const R = out.reliability.filter((x) => x.availability != null);
  out.kpis = { monitors: M.length, managed: M.filter((m) => m.managed).length, down: M.filter((m) => m.managed && m.availability === 'down').length, critical: M.filter((m) => m.managed && m.health === 'critical').length,
    warning: M.filter((m) => m.managed && m.health === 'warning').length, unmanaged: out.unmanaged.length, stale: out.stale.length, alarms_critical: openAl.filter((a) => a.severity === 'critical').length, alarms_warning: openAl.filter((a) => a.severity === 'warning').length,
    availability: R.length ? Math.round(R.reduce((s, x) => s + x.availability, 0) / R.length * 10) / 10 : null, flapping: out.reliability.filter((x) => x.flapping).length, cause_hosts: out.hosts.length, noisy: out.noisy.length, long_open: out.long_open.length };
  // trend: today's down + critical against the last 30 days
  const H = (hist || []).slice().sort((a, b) => String(a.day).localeCompare(String(b.day))), prev = H.filter((h) => h.day !== dayOf(t)).slice(-30).map((h) => h.bad), bad = M.filter((m) => m.managed && (m.availability === 'down' || m.health === 'critical')).length;   // each monitor once, even when down AND critical
  let z = null; if (prev.length >= 7) { const md = median(prev), mad = median(prev.map((v) => Math.abs(v - md))); z = Math.round((bad - md) / (1.4826 * (mad || 0.5)) * 10) / 10; }
  out.trend = { days: H.length, today_bad: bad, usual: prev.length ? median(prev) : null, z, unusual: z != null && z >= 3, history: H.slice(-60).map((h) => ({ day: h.day, bad: h.bad, availability: h.availability })), why: prev.length < 7 ? 'needs 7 days of history (' + prev.length + ' so far)' : null };
  // what to do first
  const Ac = (p, title, detail, n, filter) => { if (n) out.actions.push({ priority: p, title, detail, count: n, filter }); };
  Ac(100, out.hosts.length + ' host(s) with several monitors down together', 'Fix the host first - its monitors are one problem, not many. Check the server or VM, then Poll now to confirm.', out.hosts.length, 'hosts');
  Ac(95, out.problems.filter((p) => p.state === 'down' && p.db).length + ' database monitor(s) down', 'Applications depend on them: confirm with the DBA and the Database Dashboard.', out.problems.filter((p) => p.state === 'down' && p.db).length, 'down');
  Ac(90, out.problems.filter((p) => p.level === 'high').length + ' high-impact problem(s)', 'Each is scored with its reasons; open one to Poll now or plan maintenance.', out.problems.filter((p) => p.level === 'high').length, 'problems');
  Ac(80, out.long_open.length + ' critical alarm(s) open for more than a day', 'An alarm nobody acts on is a monitor nobody trusts: fix the cause or correct the threshold in Applications Manager.', out.long_open.length, 'long');
  Ac(70, out.trend.unusual ? 'Today ' + bad + ' monitors are down or critical (usually about ' + out.trend.usual + ')' : '', 'Far from the last 30 days (robust z ' + z + '): look for a shared cause - network, storage, a change.', out.trend.unusual ? 1 : 0, 'trend');
  Ac(60, out.kpis.flapping + ' flapping monitor(s)', 'Up / down every few minutes: a threshold too tight, a timeout too short, or a real intermittent fault. Tune it in Applications Manager.', out.kpis.flapping, 'flapping');
  Ac(50, out.noisy.length + ' noisy alarm(s) (5+ times in 7 days)', 'Raise the threshold or add a consecutive-poll condition in Applications Manager so a real problem stands out.', out.noisy.length, 'noisy');
  Ac(45, out.stale.length + ' monitor(s) not polled recently', 'Poll now; if it stays stale the APM data collector or credentials for it are failing.', out.stale.length, 'stale');
  Ac(40, out.unmanaged.filter((u) => !u.maintenance_request).length + ' monitor(s) unmanaged with no maintenance request', 'Left unmanaged after maintenance? Request Manage (resume) - an unmanaged monitor alerts nobody.', out.unmanaged.filter((u) => !u.maintenance_request).length, 'unmanaged');
  out.actions.sort((a, b) => b.priority - a.priority);
  out.note = 'Built from Applications Manager\'s own monitors and alarms and the 5-minute samples the SIEM keeps (7 days). Thresholds are changed in Applications Manager; from here a person can Poll now or request maintenance (four eyes).';
  return out;
}

function createApmInsights({ state, apm, now } = {}) {
  const NOW = now || Date.now, samples = state.collection('webtier_samples'), AH = state.collection('apm_alarm_hist'), D = state.collection('apm_daily');
  // alarm episodes: an alarm key (monitor + attribute) opens when first seen not clear, closes when it clears or disappears
  function record() {
    if (!apm) return 0; const st = apm.status(); if (!st.configured || !st.last_sync) return 0;
    const t = NOW(), open = apm.alarms({ all: '1' }).filter((a) => a.severity !== 'clear'), keys = new Set(); let n = 0;
    for (const a of open) {
      const id = a.resource_id + '|' + (a.attribute || '-'); keys.add(id);
      const h = AH.get(id) || { id, resource_id: a.resource_id, name: a.name, attribute: a.attribute || '', episodes: [], open: null };
      if (!h.open) { h.open = { from: tsOf(a.time) || t, severity: a.severity, message: String(a.message || '').slice(0, 300) }; n++; } else { h.open.severity = a.severity === 'critical' ? 'critical' : h.open.severity; }
      h.name = a.name; AH.put(h);
    }
    for (const h of AH.all((x) => x.open && !keys.has(x.id))) { h.episodes = (h.episodes || []).concat([{ from: h.open.from, to: t, severity: h.open.severity }]).filter((e) => t - e.from < 30 * DAY).slice(-200); h.open = null; AH.put(h); }
    return n;
  }
  function current() {
    if (!apm) return { installed: false };
    const st = Object.assign({}, apm.status(), { poll_min: (apm.settings && apm.settings().poll_min) || 5 }), smap = new Map(samples.all().map((d) => [d.id, d]));
    let openActions = []; try { openActions = apm.actions({}).filter((x) => /pending|approved/.test(x.status)); } catch (e) { openActions = []; /* actions not readable: maintenance requests unknown, said by the count */ }
    return { installed: true, status: st, monitors: apm.monitors({}), alarms: apm.alarms({ all: '1' }), samples: smap, alarmHist: AH.all(), openActions };
  }
  function view() {
    const t = NOW(), a = analyse(current(), D.all(), t);
    if (a.configured && a.status && a.status.last_sync) { const id = dayOf(t), cur = D.get(id); if (!cur || cur.at < t - 3600000) D.put({ id, day: id, at: t, bad: a.trend.today_bad, availability: a.kpis.availability, monitors: a.kpis.monitors }); }
    return a;
  }
  return { view, record, analyse };
}

function register(api, deps) {
  if (!deps.state) return null;
  const P = prefixOf(deps), X = createApmInsights({ state: deps.state, apm: deps.meApm || null });
  api.route('GET', `${P}/integrations/apm/insights`, wrap(deps, null, (ctx) => ctx.ok(X.view())));
  let TIMER = null;
  const tick = guardJob('apm-insights.record', async () => { try { X.record(); } finally { TIMER = setTimeout(tick, SLOT); if (TIMER.unref) TIMER.unref(); } });
  if (!deps.noTimers) { TIMER = setTimeout(tick, 120000); if (TIMER.unref) TIMER.unref(); }
  return X;
}

module.exports = { register, analyse, reliability, createApmInsights };
