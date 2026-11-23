// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Deterministic troubleshooting workflow ("why is the Jeddah branch slow?", "branch cannot reach the ERP").
 *   diagnose({ inventory, poller, evidence, findingsFn }, { site?, device?, target_ip?, symptom? }) →
 *     { scope:{site, devices[]}, checks:[{name, status:'ok'|'warn'|'fail'|'skip', detail, evidence[]}],
 *       causes:[{rank, cause, confidence:'high'|'medium'|'low', evidence[], fix}], summary }
 * Checks, in the order an engineer would: device reachability → WAN interfaces and utilisation → VPN / SD-WAN paths →
 * routing neighbours → HA → recent link/routing events → recent configuration changes → firewall blocks to the target →
 * NAC. Uses only the latest poll snapshots and the SIEM's logs; changes nothing. The AI uses the same result as evidence.
 */
const net = require('node:net');

async function diagnose(deps, input = {}) {
  const { inventory, poller, evidence, findingsFn } = deps;
  const all = inventory.list();
  let devs = [];
  if (input.device) devs = all.filter((d) => d.id === input.device || d.name.toLowerCase() === String(input.device).toLowerCase());
  else if (input.site) devs = all.filter((d) => d.site.toLowerCase() === String(input.site).toLowerCase() || d.site.toLowerCase().includes(String(input.site).toLowerCase()));
  if (!devs.length && (input.site || input.device)) return { scope: { site: input.site || '', devices: [] }, checks: [], causes: [], summary: `No devices found for "${input.device || input.site}". Add the site's devices in Network Engineer → Devices.` };
  if (!devs.length) devs = all;
  const site = input.site || (devs[0] && devs[0].site) || '', ids = new Set(devs.map((d) => d.id));
  const snap = (d) => poller.snapshot(d.id) || {}, checks = [], causes = [];
  const add = (name, status, detail, ev) => checks.push({ name, status, detail, evidence: (ev || []).filter(Boolean).slice(0, 8) });
  const cause = (c, confidence, ev, fix, w) => causes.push({ cause: c, confidence, evidence: (ev || []).filter(Boolean).slice(0, 6), fix, w });

  // 1 reachability
  const unreach = devs.filter((d) => { const r = snap(d).reach; return r && r.received === 0; }), lossy = devs.filter((d) => { const r = snap(d).reach; return r && r.received > 0 && r.loss_pct >= 2; });
  const unpolled = devs.filter((d) => !poller.snapshot(d.id));
  if (unreach.length) { add('Device reachability', 'fail', `${unreach.length} of ${devs.length} devices do not answer`, unreach.map((d) => `${d.name} ${d.ip}`)); cause(unreach.length === devs.length ? `The whole site (${site}) is unreachable — WAN circuit, edge device or power` : `${unreach.map((d) => d.name).join(', ')} unreachable`, 'high', unreach.map((d) => `${d.name}: 0 of ${snap(d).reach.sent} pings answered`), unreach.length === devs.length ? 'Call the circuit provider and check the site edge router / SD-WAN appliance power and uplinks.' : 'Check the device power, its uplink port and the switch it connects to.', 100); }
  else if (lossy.length) { add('Device reachability', 'warn', 'reachable, with packet loss', lossy.map((d) => `${d.name}: ${snap(d).reach.loss_pct} % loss, ${snap(d).reach.rtt_avg_ms} ms`)); cause('Packet loss on the path to the site', 'medium', lossy.map((d) => `${d.name}: ${snap(d).reach.loss_pct} % loss`), 'Look at WAN link utilisation and errors; open a ticket with the provider if the circuit is clean on our side.', 60); }
  else add('Device reachability', unpolled.length === devs.length ? 'skip' : 'ok', unpolled.length === devs.length ? 'not polled yet' : `all ${devs.length - unpolled.length} polled devices answer`, devs.filter((d) => snap(d).reach).map((d) => `${d.name}: ${snap(d).reach.rtt_avg_ms} ms`));

  // 2 interfaces / utilisation
  const busy = [], down = [], errs = [];
  for (const d of devs) for (const i of snap(d).interfaces || []) {
    const u = Math.max(i.util_in || 0, i.util_out || 0), label = `${d.name} ${i.name}${i.alias ? ' (' + i.alias + ')' : ''}`;
    if (u >= 80) busy.push([label, u, i]); if (i.admin === 'up' && i.oper === 'down' && (i.alias || /wan|uplink|isp|mpls|trunk|po\d|ae\d/i.test(i.name + i.alias))) down.push(label); if (i.err_per_min >= 10) errs.push(`${label}: ${i.err_per_min} errors/min`);
  }
  busy.sort((a, b) => b[1] - a[1]);
  add('Links and utilisation', down.length ? 'fail' : busy.length || errs.length ? 'warn' : 'ok', down.length ? `${down.length} uplink(s) down` : busy.length ? `${busy.length} link(s) above 80 %` : 'no saturated or failed uplinks', down.concat(busy.map((b) => `${b[0]}: ${b[1]} %`), errs));
  if (down.length) cause('Uplink / WAN interface down', 'high', down, 'Check the cable/optic and the far end; traffic is running on the remaining links if any.', 90);
  if (busy.length) cause(`Link congestion: ${busy[0][0]} at ${busy[0][1]} %`, busy[0][1] >= 95 ? 'high' : 'medium', busy.slice(0, 4).map((b) => `${b[0]}: ${b[1]} % of ${b[2].speed_mbps} Mbps`), 'Find the top talkers on this link (top_talkers), apply QoS for business applications, or upgrade the circuit if it is sustained.', busy[0][1] >= 95 ? 85 : 55);
  if (errs.length) cause('Interface errors (cabling, optics or duplex)', 'medium', errs, 'Replace the cable/optic and check speed/duplex on both ends.', 50);

  // 3 VPN / SD-WAN
  const siteIps = new Set(devs.map((d) => d.ip)), siteName = site.toLowerCase();
  const tunnelsDown = [], paths = [];
  for (const d of all) {
    const s = snap(d);
    for (const t of s.tunnels || []) if ((ids.has(d.id) || siteIps.has(t.peer) || (siteName && t.name.toLowerCase().includes(siteName.split(/\s+/)[0]))) && t.status !== 'up') tunnelsDown.push(`${d.name}: ${t.name}${t.peer ? ' → ' + t.peer : ''} down`);
    for (const p of s.paths || []) if (ids.has(d.id) && (/down|dead/i.test(p.status) || p.loss_pct >= 2 || p.latency_ms >= 150 || p.jitter_ms >= 30)) paths.push(`${d.name} ${p.name}/${p.member}: ${p.status}, loss ${p.loss_pct} %, ${p.latency_ms} ms, jitter ${p.jitter_ms} ms`);
    if (s.sdwan) for (const a of s.sdwan.appliances || []) if (!a.up && (!site || String(a.site).toLowerCase().includes(siteName.split(/\s+/)[0] || '\u0000') || siteIps.has(a.ip))) tunnelsDown.push(`EdgeConnect ${a.name} is ${a.state}`);
  }
  add('VPN tunnels and SD-WAN paths', tunnelsDown.length ? 'fail' : paths.length ? 'warn' : 'ok', tunnelsDown.length ? `${tunnelsDown.length} tunnel(s)/appliance(s) down` : paths.length ? 'degraded paths' : 'tunnels up, paths within SLA', tunnelsDown.concat(paths));
  if (tunnelsDown.length) cause('VPN / SD-WAN overlay down for this site', 'high', tunnelsDown, 'Check the underlay first (WAN reachability of both peers), then IPsec phase 1/2 and the Orchestrator alarms.', 88);
  if (paths.length) cause('SD-WAN path quality is poor (loss/latency/jitter)', 'medium', paths, 'Steer ERP/voice to the healthier member, and raise it with the provider of the degraded circuit.', 58);

  // 4 routing / HA
  const nbDown = [], ha = [];
  for (const d of devs) { const s = snap(d); for (const n of s.neighbors || []) if (!n.up) nbDown.push(`${d.name}: ${n.proto.toUpperCase()} ${n.peer} ${n.state}`); if (s.ha && s.ha.enabled && s.ha.in_sync === false) ha.push(`${d.name}: HA out of sync`); }
  add('Routing neighbours and HA', nbDown.length || ha.length ? 'fail' : 'ok', nbDown.length ? `${nbDown.length} neighbour(s) not established` : ha.length ? 'HA out of sync' : 'neighbours established', nbDown.concat(ha));
  if (nbDown.length) cause('Routing adjacency down — routes to/from the site may be missing', 'high', nbDown, 'Check the link to the neighbour and the BGP/OSPF settings; compare with the routing events below.', 80);
  if (ha.length) cause('Firewall HA out of sync', 'medium', ha, 'Resynchronise the cluster in a maintenance window.', 40);

  // 5 events and changes from the SIEM
  if (evidence) {
    const since = Math.max(30, Math.min(1440, Number(input.minutes) || 180));
    try {
      const ev = []; for (const d of devs.slice(0, 15)) { const rows = await evidence.deviceEvents({ ip: d.ip, host: d.name, minutes: since, limit: 10, kind: 'link' }); for (const r of rows) ev.push(`${r.ts} ${d.name}: ${r.message}`); }
      add('Link and routing events (SIEM)', ev.length ? 'warn' : 'ok', ev.length ? `${ev.length} up/down events in the last ${since} min` : `no up/down events in the last ${since} min`, ev.slice(0, 8));
      if (ev.length >= 3) cause('Flapping link, tunnel or routing session', 'medium', ev.slice(0, 5), 'A flapping circuit or tunnel causes intermittent slowness; check the provider circuit and DPD/keepalive settings.', 65);
    } catch (e) { add('Link and routing events (SIEM)', 'skip', 'log search unavailable: ' + e.message); }
    try {
      const ch = []; for (const d of devs.slice(0, 15)) for (const r of await evidence.configChanges({ ip: d.ip, hours: 24, limit: 5 })) ch.push(`${r.ts} ${d.name}${r.user ? ' by ' + r.user : ''}: ${r.message}`);
      add('Configuration changes, last 24 h (SIEM)', ch.length ? 'warn' : 'ok', ch.length ? `${ch.length} change(s)` : 'no recorded changes', ch.slice(0, 8));
      if (ch.length) cause('A recent configuration change may have caused it', 'medium', ch.slice(0, 4), 'Review the change with the person who made it; roll back if the problem started right after it.', 62);
    } catch (e) { add('Configuration changes, last 24 h (SIEM)', 'skip', 'log search unavailable: ' + e.message); }
    if (input.target_ip && net.isIP(String(input.target_ip))) {
      try {
        const b = await evidence.blocked({ dst: input.target_ip, minutes: since, limit: 10 });
        add(`Firewall blocks to ${input.target_ip}`, b.length ? 'fail' : 'ok', b.length ? `${b.reduce((a, r) => a + Number(r.hits), 0)} blocked connections` : 'no blocked connections found', b.map((r) => `${r.src_ip} → ${r.dst_ip}:${r.dst_port}/${r.proto} ${r.hits}× on ${r.firewall}`));
        if (b.length) cause(`Firewall policy is blocking traffic to ${input.target_ip}`, 'high', b.slice(0, 4).map((r) => `${r.src_ip} → ${r.dst_ip}:${r.dst_port} blocked ${r.hits}× (${r.firewall})`), 'Check which rule denies it (policy lookup on the firewall) and request a policy change through change approval.', 92);
      } catch (e) { add(`Firewall blocks to ${input.target_ip}`, 'skip', 'log search unavailable: ' + e.message); }
    }
  }

  // 6 NAC
  const nac = devs.concat(all.filter((d) => d.vendor === 'genian')).map((d) => snap(d).nac).find(Boolean);
  if (nac) add('Genian NAC', nac.quarantined ? 'warn' : 'ok', `${nac.nodes} endpoints, ${nac.quarantined} quarantined, ${nac.unauthorized} unauthorized`, (nac.items || []).filter((x) => /quarant|isolat/.test(x.status)).slice(0, 5).map((x) => `${x.ip} ${x.mac} ${x.host}`));

  const fnd = findingsFn ? findingsFn().filter((f) => ids.has(f.device)) : [];
  causes.sort((a, b) => b.w - a.w);
  const ranked = causes.map((c, i) => ({ rank: i + 1, cause: c.cause, confidence: c.confidence, evidence: c.evidence, fix: c.fix }));
  const summary = ranked.length ? `Most likely: ${ranked[0].cause}.` : checks.every((c) => c.status === 'skip') ? 'No monitoring data for this scope yet.' : 'No network fault found on the monitored devices; the problem may be on the application/server side or on a device that is not monitored.';
  return { scope: { site, devices: devs.map((d) => ({ id: d.id, name: d.name, vendor: d.vendor, ip: d.ip })) }, symptom: input.symptom || '', checks, causes: ranked, findings: fnd.slice(0, 15), summary };
}

module.exports = { diagnose };
