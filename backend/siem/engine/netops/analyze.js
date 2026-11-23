// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network health findings (pure functions, no I/O).
 *   findings(devices[], snapshots{id: snap}, opts) → [{id, severity:'critical'|'high'|'medium'|'low', kind, device, site,
 *       title, evidence:[…], recommendation}]   sorted most severe first
 *   sites(devices, snapshots, findings) → [{site, status:'down'|'degraded'|'ok'|'unknown', devices, reachable, worst, ...}]
 *   dailyReport({devices, snapshots, findings, sitesList, now}) → {summary, sites, top_findings, capacity, text}
 * Thresholds (opts.thresholds, config.netops.thresholds): util 80/95 %, cpu 85/95 %, mem 90 %, loss 2/10 %,
 * rtt 150 ms, jitter 30 ms, errors 10/min, stale 15 min.
 */
const SEV = { critical: 4, high: 3, medium: 2, low: 1 };
const DEF = { util_warn: 80, util_crit: 95, cpu_warn: 85, cpu_crit: 95, mem_warn: 90, loss_warn: 2, loss_crit: 10, rtt_warn: 150, jitter_warn: 30, err_warn: 10, stale_min: 15 };

function fmtBps(b) { if (b == null) return '–'; const u = ['bps', 'Kbps', 'Mbps', 'Gbps']; let i = 0; while (b >= 1000 && i < 3) { b /= 1000; i++; } return b.toFixed(b >= 100 ? 0 : 1) + ' ' + u[i]; }

function findings(devices, snapshots, opts = {}) {
  const th = Object.assign({}, DEF, opts.thresholds || {}), now = opts.now || Date.now(), out = [];
  const add = (sev, kind, d, title, evidence, rec, key) => out.push({ id: d.id + ':' + kind + (key ? ':' + key : ''), severity: sev, kind, device: d.id, device_name: d.name, site: d.site, vendor: d.vendor, title, evidence, recommendation: rec });
  for (const d of devices) {
    const s = snapshots[d.id];
    if (!s) { add('low', 'not-polled', d, `${d.name} has not been polled yet`, [], 'Wait for the next poll cycle or run "Poll now".'); continue; }
    if (now - s.at > th.stale_min * 60000) add('medium', 'stale', d, `${d.name}: data is ${Math.round((now - s.at) / 60000)} min old`, [], 'Check that the SIEM engine poller is running (Network Engineer → Status).');
    const r = s.reach;
    if (r && r.received === 0 && !(s.sources || []).some((x) => x !== 'ping')) {
      add(d.criticality >= 3 || /core|wan-edge|firewall/.test(d.role) ? 'critical' : 'high', 'unreachable', d, `${d.name} (${d.ip}) is not reachable`, [`${r.sent} pings, 0 replies`].concat((s.errors || []).slice(0, 3)),
        'Check power and the uplink / WAN circuit for this device; if only ICMP is blocked by policy, disable the ping check and rely on SNMP/API.');
      continue;
    }
    if (r && r.received === 0) { add('low', 'icmp-blocked', d, `${d.name} does not answer ping but answers ${(s.sources || []).filter((x) => x !== 'ping').join('/')}`, [], 'ICMP is probably filtered on the path; allow ping from the SIEM server or turn the ping check off for this device.'); }
    else if (r && r.loss_pct >= th.loss_warn) add(r.loss_pct >= th.loss_crit ? 'high' : 'medium', 'loss', d, `${d.name}: ${r.loss_pct} % packet loss to ${d.ip}`, [`rtt avg ${r.rtt_avg_ms} ms, jitter ${r.jitter_ms} ms`], 'Look for errors or saturation on the path (WAN link, uplink interface) and for ISP issues at this site.');
    if (r && r.rtt_avg_ms >= th.rtt_warn) add('medium', 'latency', d, `${d.name}: high latency ${r.rtt_avg_ms} ms`, [`jitter ${r.jitter_ms} ms`], 'Compare with the SD-WAN path measurements; congestion or a backup path being used are the usual causes.');
    if (r && r.jitter_ms >= th.jitter_warn) add('low', 'jitter', d, `${d.name}: jitter ${r.jitter_ms} ms`, [], 'Voice and video suffer above 30 ms; apply QoS for real-time traffic on the WAN edge.');
    for (const e of s.errors || []) if (/credentials|refused|certificate|authentication|unknown SNMPv3 user/i.test(e)) add('medium', 'collector', d, `${d.name}: monitoring access problem`, [e], 'Fix the read-only credentials or certificate pin in Network Engineer → Devices → Credentials.', e.slice(0, 20));
    const sy = s.system || {};
    if (sy.cpu_pct >= th.cpu_warn) add(sy.cpu_pct >= th.cpu_crit ? 'high' : 'medium', 'cpu', d, `${d.name}: CPU ${sy.cpu_pct} %`, [], 'Find the busy process (show processes cpu sorted / diagnose sys top); high CPU on firewalls is often logging, IPS or a traffic surge.');
    if (sy.mem_pct >= th.mem_warn) add('medium', 'memory', d, `${d.name}: memory ${sy.mem_pct} %`, [], 'Check for memory leaks or conserve mode (FortiGate); plan a maintenance reload if it keeps growing.');
    for (const i of s.interfaces || []) {
      const important = i.alias || /uplink|wan|isp|mpls|trunk|core|port-channel|ae\d|po\d/i.test(i.name + ' ' + (i.alias || ''));
      if (i.admin === 'up' && i.oper === 'down' && important) add(d.criticality >= 3 ? 'high' : 'medium', 'if-down', d, `${d.name}: ${i.name}${i.alias ? ' (' + i.alias + ')' : ''} is down`, [i.changed ? 'changed ' + i.changed + ' in the last poll' : 'admin up, link down'], 'Check the cable/optic and the device on the other side; see SIEM events for link up/down messages.', i.name);
      const u = Math.max(i.util_in || 0, i.util_out || 0);
      if (u >= th.util_warn) add(u >= th.util_crit ? 'high' : 'medium', 'utilization', d, `${d.name}: ${i.name}${i.alias ? ' (' + i.alias + ')' : ''} at ${u} % of ${i.speed_mbps} Mbps`, [`in ${fmtBps(i.in_bps)}, out ${fmtBps(i.out_bps)}`],
        'Find the top talkers/applications on this link (ask the AI Network Engineer), apply QoS, or plan a bandwidth upgrade if it is sustained.', i.name);
      if (i.err_per_min >= th.err_warn) add('medium', 'errors', d, `${d.name}: ${i.name} has ${i.err_per_min} errors/min`, [`discards ${i.disc_per_min || 0}/min`], 'Interface errors usually mean a bad cable, optic or a duplex mismatch; check both ends.', i.name);
    }
    for (const t of s.tunnels || []) if (t.status !== 'up') add(d.criticality >= 2 ? 'high' : 'medium', 'tunnel-down', d, `${d.name}: VPN tunnel ${t.name} is down`, [t.peer ? 'peer ' + t.peer : '', t.changed ? 'changed ' + t.changed : ''].filter(Boolean), 'Check the peer\'s WAN reachability, then phase 1/2 settings (proposal, PSK, IDs) in the SIEM VPN events.', t.name);
    if (s.ha && s.ha.enabled && s.ha.in_sync === false) add('high', 'ha-sync', d, `${d.name}: HA cluster is out of sync`, [s.ha.state || '', s.ha.peer_state ? 'peer ' + s.ha.peer_state : ''].filter(Boolean), 'Compare configuration checksums and resynchronise from the primary during a quiet period; a failover now could load an older config.');
    for (const nb of s.neighbors || []) if (!nb.up) add(nb.proto === 'bgp' ? 'high' : 'medium', 'neighbor-down', d, `${d.name}: ${nb.proto.toUpperCase()} neighbor ${nb.peer} is ${nb.state}`, [nb.remote_as ? 'remote AS ' + nb.remote_as : '', nb.changed ? 'changed ' + nb.changed : ''].filter(Boolean), 'Check reachability to the neighbor, then timers/authentication/AS settings; SIEM routing events show when it dropped.', nb.proto + nb.peer);
    for (const p of s.paths || []) {
      if (/down|dead|fail/i.test(p.status)) add('high', 'path-down', d, `${d.name}: SD-WAN path ${p.member} (${p.name}) is down`, [], 'Traffic has moved to the remaining links; check this circuit with the provider.', p.name + p.member);
      else if (p.loss_pct >= th.loss_warn || p.latency_ms >= th.rtt_warn || p.jitter_ms >= th.jitter_warn) add('medium', 'path-quality', d, `${d.name}: SD-WAN path ${p.member} (${p.name}) is degraded`, [`loss ${p.loss_pct} %, latency ${p.latency_ms} ms, jitter ${p.jitter_ms} ms`], 'Check the SLA thresholds and steer critical applications (ERP, voice) to the better link.', p.name + p.member);
    }
    for (const it of (s.security && s.security.items) || []) add(it.severity, 'sec-' + it.kind, d, it.title, it.evidence || [], it.rec, it.key);
    // support contract + subscriptions the device reports (FortiGate / PAN-OS): an expired security subscription means that
    // protection is no longer updated; an expired support contract means no RMA, no TAC and no firmware
    const today = new Date(now).toISOString().slice(0, 10);
    for (const it of (s.licenses && s.licenses.items) || []) {
      if (!it.expires && !it.expired) continue;
      const left = it.expires ? Math.round((Date.parse(it.expires + 'T00:00:00Z') - Date.parse(today + 'T00:00:00Z')) / 86400000) : -1;
      const what = it.kind === 'support' ? 'support' : 'subscription', ev = [`${it.name}: ${it.expires ? (left < 0 ? 'expired ' + it.expires : 'ends ' + it.expires + ' (' + left + ' days)') : 'expired'}${it.level ? ' · ' + it.level : ''}`];
      if (it.expired || left < 0) add('high', it.kind === 'support' ? 'support-expired' : 'license-expired', d, `${d.name}: ${it.name} ${what} expired`, ev, it.kind === 'support' ? 'Renew the support contract: without it there is no hardware replacement, no vendor support case and no firmware download.' : 'Renew the subscription: the protection it provides (signatures, URL / threat database) is no longer updated.', it.name);
      else if (left <= (th.license_warn_days || 60)) add(left <= 30 ? 'high' : 'medium', it.kind === 'support' ? 'support-expiring' : 'license-expiring', d, `${d.name}: ${it.name} ${what} ends in ${left} days`, ev, 'Start the renewal with the partner now; record the new term in Support Contracts.', it.name);
    }
    if (s.nac) {
      if (s.nac.quarantined) add('medium', 'nac-quarantine', d, `${s.nac.quarantined} endpoints quarantined by Genian NAC`, s.nac.items.filter((x) => /quarant|isolat/.test(x.status)).slice(0, 5).map((x) => `${x.ip || '?'} ${x.mac} ${x.host}`), 'Review each quarantined endpoint (ask the AI Network Engineer to correlate it with the switch port and firewall logs) before releasing it.');
      if (s.nac.unauthorized) add('low', 'nac-unauth', d, `${s.nac.unauthorized} unauthorized / unknown endpoints on the network`, s.nac.items.filter((x) => /unauth|unknown|unreg/.test(x.status)).slice(0, 5).map((x) => `${x.ip || '?'} ${x.mac} ${x.host}`), 'Register legitimate devices or block them by policy.');
    }
    if (s.sdwan) {
      for (const a of s.sdwan.appliances || []) if (!a.up) add('high', 'sdwan-appliance', d, `EdgeConnect ${a.name}${a.site ? ' (' + a.site + ')' : ''} is ${a.state || 'unreachable'}`, [], 'The branch is likely offline or the appliance lost contact with Orchestrator; check the site\'s circuits and power.', a.name);
      const crit = (s.sdwan.alarms || []).filter((a) => /critical|major/.test(a.severity));
      if (crit.length) add('medium', 'sdwan-alarms', d, `${crit.length} critical/major EdgeConnect alarms`, crit.slice(0, 5).map((a) => `${a.appliance}: ${a.text}`), 'Open Orchestrator alarms for details; tunnel-down alarms usually point to a WAN circuit problem.');
    }
  }
  return out.sort((a, b) => SEV[b.severity] - SEV[a.severity] || String(a.site || '').localeCompare(String(b.site || '')));
}

function sites(devices, snapshots, fnd) {
  const m = new Map();
  for (const d of devices) {
    const e = m.get(d.site) || { site: d.site, devices: 0, reachable: 0, polled: 0, critical: 0, high: 0, medium: 0, low: 0, rtt: [], loss: [] };
    e.devices++; const s = snapshots[d.id];
    if (s) { e.polled++; if (!s.reach || s.reach.received > 0 || s.ok) e.reachable++; if (s.reach && s.reach.rtt_avg_ms != null) e.rtt.push(s.reach.rtt_avg_ms); if (s.reach) e.loss.push(s.reach.loss_pct); }
    m.set(d.site, e);
  }
  for (const f of fnd) { const e = m.get(f.site); if (e) e[f.severity]++; }
  return [...m.values()].map((e) => {
    const status = !e.polled ? 'unknown' : e.reachable === 0 ? 'down' : e.critical || e.high || e.reachable < e.polled ? 'degraded' : e.medium ? 'warning' : 'ok';
    const avg = (a) => (a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length * 10) / 10 : null);
    return { site: e.site, status, devices: e.devices, polled: e.polled, reachable: e.reachable, findings: { critical: e.critical, high: e.high, medium: e.medium, low: e.low }, rtt_avg_ms: avg(e.rtt), loss_avg_pct: avg(e.loss) };
  }).sort((a, b) => ['down', 'degraded', 'warning', 'unknown', 'ok'].indexOf(a.status) - ['down', 'degraded', 'warning', 'unknown', 'ok'].indexOf(b.status) || String(a.site || '').localeCompare(String(b.site || '')));
}

function dailyReport({ devices, snapshots, findings: fnd, sitesList, trends, now }) {
  const t = now || Date.now(), c = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of fnd) c[f.severity]++;
  const down = sitesList.filter((s) => s.status === 'down'), deg = sitesList.filter((s) => s.status === 'degraded');
  const busiest = [];
  for (const d of devices) for (const i of (snapshots[d.id] || {}).interfaces || []) { const u = Math.max(i.util_in || 0, i.util_out || 0); if (u) busiest.push({ device: d.name, site: d.site, interface: i.name + (i.alias ? ' (' + i.alias + ')' : ''), util_pct: u, speed_mbps: i.speed_mbps }); }
  busiest.sort((a, b) => b.util_pct - a.util_pct);
  const lines = [
    `Network health report — ${new Date(t).toISOString().slice(0, 10)}`,
    `${devices.length} devices at ${sitesList.length} sites. Sites down: ${down.length}, degraded: ${deg.length}.`,
    `Findings: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low.`,
  ];
  if (down.length) lines.push('Down: ' + down.map((s) => s.site).join(', '));
  for (const f of fnd.slice(0, 10)) lines.push(`- [${f.severity}] ${f.title} — ${f.recommendation}`);
  if (busiest.length) lines.push('Busiest links: ' + busiest.slice(0, 5).map((b) => `${b.device} ${b.interface} ${b.util_pct} %`).join('; '));
  for (const tr of (trends || []).slice(0, 5)) if (tr.days_to_full != null) lines.push(`Capacity: ${tr.device} ${tr.key} reaches ${tr.limit} % in about ${tr.days_to_full} days at the current growth.`);
  return { at: t, summary: { devices: devices.length, sites: sitesList.length, sites_down: down.length, sites_degraded: deg.length, findings: c }, sites: sitesList, top_findings: fnd.slice(0, 20), busiest: busiest.slice(0, 10), capacity: trends || [], text: lines.join('\n') };
}

/* capacity forecast: least-squares slope of daily peak utilisation → days until `limit` % */
function forecast(points, limit = 90) {
  if (!points || points.length < 5) return null;
  const xs = points.map((p) => p[0] / 86400000), ys = points.map((p) => p[1]), nn = xs.length;
  const mx = xs.reduce((a, b) => a + b, 0) / nn, my = ys.reduce((a, b) => a + b, 0) / nn;
  let num = 0, den = 0; for (let i = 0; i < nn; i++) { num += (xs[i] - mx) * (ys[i] - my); den += (xs[i] - mx) ** 2; }
  if (!den) return null; const slope = num / den, last = ys[nn - 1];
  if (slope <= 0.05 || last >= limit) return { slope_per_day: Math.round(slope * 100) / 100, days_to_full: last >= limit ? 0 : null };
  return { slope_per_day: Math.round(slope * 100) / 100, days_to_full: Math.round((limit - last) / slope) };
}

module.exports = { findings, sites, dailyReport, forecast, fmtBps, DEF, SEV };
