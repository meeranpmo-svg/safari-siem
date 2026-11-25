// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body: check } = require('../util/check');
const { guard: guardJob } = require('../util/errors');
const A = require('./analyze');
/*
 * WAN / LAN route map - the organisation's network as a map the network administrator draws (or accepts from the platform's
 * proposal), measured live from what the AI Network Engineer already polls. Nothing new is polled and nothing is changed
 * on a device.
 *   map      sites {id, name, kind: hq|dc|dr|branch|cloud}, nodes {id, label, kind, site, device?, appliance?}, links {id, a, b,
 *            kind: internet|mpls|sdwan|ipsec|lan|ha, a_if?, b_if?, tunnel?, path?, capacity_mbps?, isp?, circuit?}, thresholds
 *            node kinds: internet, isp, edge-firewall (Palo Alto), firewall (FortiGate, user level), core, distribution, access,
 *            sdwan (Silver Peak / EdgeConnect), router, wan-cloud, servers
 *   measure  a node from its device's poll (reach / sources) or, for a Silver Peak appliance, the Orchestrator's appliance
 *            state; a link from the interface named on either end (status, rate, utilisation of the contracted capacity or
 *            the port speed, errors), the IPsec tunnel or the SD-WAN health-check member (latency, jitter, loss). A link with
 *            none of these is "not measured" - never shown as up.
 *   root cause  a down node or link takes everything behind it with it: the nodes that lose their way to the internet / the
 *            data centre only because of it are covered by that one incident and are not raised again.
 *   machine learning  per link and metric (utilisation, latency, loss) a baseline per hour of the week (running mean / spread,
 *            adapts after 50 samples); a value far above what is usual for this hour is an anomaly, said with the baseline.
 *            Daily peak utilisation -> least-squares capacity forecast (days until the critical threshold).
 *   users    FortiGate's signed-in firewall users (user, IP, traffic) at the congested site - analysts and above only (PDPL).
 *   alerts   high and critical incidents are raised as SIEM alerts (rule netops-routemap-<kind>), so the alert queue and
 *            Notification & Escalation page whoever is on call; an incident is acknowledged by a person.
 *   proposal the platform proposes a map from the inventory: IPsec tunnel and BGP peers that are other monitored devices (high
 *            confidence), SD-WAN appliances to the hub, and layer order within a site (lower) - each link with its reason. An
 *            administrator reviews and saves it.
 */
const SITE_KINDS = ['hq', 'dc', 'dr', 'branch', 'cloud'];
const NODE_KINDS = ['internet', 'isp', 'edge-firewall', 'firewall', 'core', 'distribution', 'access', 'sdwan', 'router', 'wan-cloud', 'servers', 'nac', 'compute'];
const LINK_KINDS = ['internet', 'mpls', 'sdwan', 'ipsec', 'lan', 'ha'];
const ID = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const DEF_TH = { util_warn: 70, util_crit: 90, loss_warn: 2, loss_crit: 10, lat_warn: 150, lat_crit: 400 };
const SEVN = { low: 1, medium: 2, high: 3, critical: 4 };
const RIYADH = 3 * 3600000;
const bad = (msg, code = 400) => Object.assign(new Error(msg), { code });
const low = (s) => String(s == null ? '' : s).toLowerCase();
const r1 = (x) => (x == null ? null : Math.round(x * 10) / 10);
const hourOfWeek = (t) => { const d = new Date(t + RIYADH); return d.getUTCDay() * 24 + d.getUTCHours(); };
const DAY = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const FLOOR = { util: 3, lat: 5, loss: 0.5 };

// vendor-specific, read-only diagnostics and the fix steps a network engineer follows
function runbook(kind, vendor, ctx) {
  const t = ctx.tunnel || '<tunnel>', i = ctx.iface || '<interface>';
  const D = {
    paloalto: { node: ['show system info', 'show high-availability state', 'show interface all', 'show routing route'], link: ['show interface ' + i, 'show counter interface ' + i, 'show routing route'], ipsec: ['show vpn ike-sa', 'show vpn ipsec-sa', 'show vpn flow'], quality: ['show interface ' + i, 'show session info'] },
    fortigate: { node: ['get system status', 'get system performance status', 'diagnose sys ha status'], link: ['diagnose hardware deviceinfo nic ' + i, 'get system interface physical', 'get router info routing-table all'], ipsec: ['diagnose vpn ike gateway list name ' + t, 'diagnose vpn tunnel list name ' + t, 'get vpn ipsec tunnel summary'], quality: ['diagnose sys sdwan health-check', 'diagnose sys sdwan member', 'diagnose sys session stat'] },
    edgeconnect: { node: ['Orchestrator > Monitoring > Appliances: state and alarms of this appliance', 'show interfaces', 'show alarms'], link: ['show interfaces', 'Orchestrator > Monitoring > Tunnels: underlay state'], ipsec: ['Orchestrator > Monitoring > Tunnels', 'show tunnel'], quality: ['Orchestrator > Monitoring > Tunnels: loss / latency / jitter', 'Orchestrator > Path Conditioning'] },
    'cisco-ios': { node: ['show version', 'show processes cpu sorted', 'show logging | include changed|down'], link: ['show interfaces ' + i, 'show interfaces ' + i + ' counters errors', 'show cdp neighbors ' + i + ' detail'], ipsec: ['show crypto isakmp sa', 'show crypto ipsec sa'], quality: ['show interfaces ' + i, 'show policy-map interface ' + i] },
  };
  const d = D[vendor] || D['cisco-ios'];
  const F = {
    'site-down': ['Call the site: is there power, are the comms room and the UPS up?', 'Check the site\'s WAN circuits with each ISP (circuit ids on the links).', 'If it is a planned outage, acknowledge it here so it is not escalated.', 'When the first device answers again the map shows which part came back.'],
    'node-down': ['Check the device is powered and reachable from its own site (console / out-of-band).', 'If it is an HA pair, check the peer took over (HA state) - fail over only after a change approval.', 'Check the upstream link and port it hangs on; replace a failed cable / SFP.', 'When it is back, confirm the map turns green and the covered sites recover.'],
    'link-down': ['Check the interface on both ends (status, errors, SFP light levels).', ctx.isp ? 'If it is the ' + ctx.isp + ' circuit' + (ctx.circuit ? ' (' + ctx.circuit + ')' : '') + ', open a ticket with the ISP with the circuit id and the time it dropped.' : 'If it is a carrier circuit, open a ticket with the carrier.', 'Check traffic failed over to the other link / path (SD-WAN members, routing).', 'Record the outage window for the SLA report.'],
    'tunnel-down': ['Check phase 1 / phase 2 on both peers (the commands below).', 'Check the underlay internet link of both ends is up and the peer IP answers.', 'Check for a recent change: pre-shared key, proposals, peer IP, certificate expiry.', 'Bring it up again only through an approved change if renegotiation needs a reset.'],
    congestion: ['See who and what is using the link: the users below (FortiGate) and the top talkers (AI Network Engineer).', 'Steer bulk traffic to another WAN member or apply / tighten a QoS / SD-WAN rule - propose it as a change for approval.', 'If it repeats at this hour, the forecast below says when to upgrade the circuit.'],
    quality: ['Compare the other members / paths: if only one is bad, steer business-critical traffic away from it (approved change).', 'Open a ticket with the ISP with the loss / latency figures and times.', 'Check the interface for errors and duplex mismatches on the local side.'],
    errors: ['Interface errors mean a physical problem: re-seat or replace the cable / SFP, check duplex and speed on both ends.', 'Watch the error counter after the fix - it should stop increasing.'],
    anomaly: ['This is unusual for this hour - check what changed (configuration changes, new backups or replication, a large download).', 'If it is expected (a new job), it becomes the baseline within a few weeks.'],
    capacity: ['Plan a circuit upgrade or move traffic before the forecast date.', 'Check whether the growth is business traffic or something that can be scheduled out of hours.'],
  };
  return { fix: F[kind] || [], diagnostics: (kind === 'site-down' ? [] : (kind === 'tunnel-down' ? d.ipsec : kind === 'node-down' ? d.node : kind === 'quality' || kind === 'congestion' ? d.quality : d.link).slice()), vendor: vendor || 'other' };
}

function createRouteMap({ inventory, poller, state, log, now, alerts, config, fmg } = {}) {
  // FortiGates managed by FortiManager (netops/fmg.js): a node names one with `fortigate`; its health, tunnels and SD-WAN members
  // come from the FortiManager poll. fmg() returns the fleet API or null (FortiManager not connected).
  const FM = () => { try { return typeof fmg === 'function' ? fmg() : null; } catch (e) { return null; /* FortiManager not set up: nodes are measured from the poller only */ } };
  const fgOf = (n) => { const F = FM(); if (!F || !n || !n.fortigate) return null; try { return F.device(n.fortigate); } catch (e) { return null; /* no longer managed: the node says so */ } };
  const NOW = now || Date.now, L = log || { info() {}, warn() {} };
  const cfgC = state.collection('netops_routemap'), mlC = state.collection('netops_routemap_ml'), incC = state.collection('netops_routemap_inc');
  const acfg = Object.assign({ enabled: true, interval_s: 120 }, (config && config.netops && config.netops.routemap) || {});
  const st = { ticks: 0, raised: 0, merged: 0, last: 0 };
  let timer = null;
  const map = () => Object.assign({ version: 0, sites: [], nodes: [], links: [], thresholds: Object.assign({}, DEF_TH) }, cfgC.get('map') || {});

  // ---------- configuration (administrators)
  function validate(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw bad('map must be an object {sites, nodes, links, thresholds}');
    const b = check(input).list('sites', { max: 200, def: [] }).list('nodes', { max: 600, def: [] }).list('links', { max: 1200, def: [] }).done();
    const ids = new Set();
    const uid = (k, i, v) => { if (!ID.test(String(v || ''))) throw bad(k + '[' + i + '].id must be lower-case letters, digits and . _ - (max 64)'); if (ids.has(k + ':' + v)) throw bad(k + '[' + i + '].id "' + v + '" is used twice'); ids.add(k + ':' + v); };
    const obj = (k, i, x) => { if (!x || typeof x !== 'object' || Array.isArray(x)) throw bad(k + '[' + i + '] must be an object'); return x; };
    const sites = b.sites.map((x, i) => { const e = check(obj('sites', i, x)).str('id', { required: true, max: 64 }).str('name', { required: true, max: 80 }).oneOf('kind', SITE_KINDS, { def: 'branch' }).str('city', { max: 60 }).done(); uid('sites', i, e.id); return e; });
    const siteOk = (s) => !s || sites.some((x) => x.id === s);
    const devs = new Set(inventory.list().map((d) => d.id));
    const nodes = b.nodes.map((x, i) => {
      const e = check(obj('nodes', i, x)).str('id', { required: true, max: 64 }).str('label', { required: true, max: 80 }).oneOf('kind', NODE_KINDS, { required: true }).str('site', { max: 64 })
        .str('device', { max: 80 }).str('appliance', { max: 120 }).str('fortigate', { max: 63 }).done();
      uid('nodes', i, e.id);
      if (!siteOk(e.site)) throw bad('nodes[' + i + '].site: there is no site "' + e.site + '"');
      if (e.device && !devs.has(e.device)) throw bad('nodes[' + i + '].device: "' + e.device + '" is not a device in the AI Network Engineer inventory');
      return e;
    });
    const nodeOk = (n) => nodes.some((x) => x.id === n);
    const pair = new Set();
    const links = b.links.map((x, i) => {
      const e = check(obj('links', i, x)).str('id', { required: true, max: 64 }).str('a', { required: true, max: 64 }).str('b', { required: true, max: 64 }).oneOf('kind', LINK_KINDS, { required: true })
        .str('a_if', { max: 80 }).str('b_if', { max: 80 }).str('tunnel', { max: 120 }).str('path', { max: 160 }).num('capacity_mbps', { min: 0.1, max: 400000 }).str('isp', { max: 80 }).str('circuit', { max: 80 }).done();
      uid('links', i, e.id);
      if (!nodeOk(e.a)) throw bad('links[' + i + '].a: there is no node "' + e.a + '"');
      if (!nodeOk(e.b)) throw bad('links[' + i + '].b: there is no node "' + e.b + '"');
      if (e.a === e.b) throw bad('links[' + i + ']: a link needs two different nodes');
      const k = [e.a, e.b].sort().join('|') + '|' + e.kind + '|' + (e.tunnel || e.path || e.a_if || '');
      if (pair.has(k)) throw bad('links[' + i + '] repeats another link between the same nodes'); pair.add(k);
      return e;
    });
    const th = Object.assign({}, DEF_TH);
    if (input.thresholds !== undefined) {
      const t = check(input.thresholds).num('util_warn', { min: 10, max: 99 }).num('util_crit', { min: 20, max: 100 }).num('loss_warn', { min: 0.1, max: 50 }).num('loss_crit', { min: 0.5, max: 100 })
        .num('lat_warn', { min: 5, max: 5000 }).num('lat_crit', { min: 10, max: 10000 }).done();
      Object.assign(th, t);
      if (th.util_warn >= th.util_crit) throw bad('thresholds.util_warn must be below util_crit');
      if (th.loss_warn >= th.loss_crit) throw bad('thresholds.loss_warn must be below loss_crit');
      if (th.lat_warn >= th.lat_crit) throw bad('thresholds.lat_warn must be below lat_crit');
    }
    return { sites, nodes, links, thresholds: th };
  }
  function save(input, user, baseVersion) {
    const cur = map();
    if (baseVersion !== undefined && baseVersion !== null && Number(baseVersion) !== cur.version) throw bad('the map was changed by ' + (cur.updated_by || 'someone') + ' since you opened it - reload and apply your change again', 409);
    const m = validate(input);
    const next = Object.assign({ id: 'map' }, m, { version: cur.version + 1, updated_by: user, updated_at: NOW() });
    cfgC.put(next);
    const gone = new Set(cur.links.map((l) => l.id).filter((id) => !m.links.some((l) => l.id === id)));
    for (const id of gone) mlC.remove(id);
    return { map: next, summary: { version: next.version, sites: m.sites.length, nodes: m.nodes.length, links: m.links.length, learning_reset: gone.size } };
  }

  // ---------- measurement
  const devOf = (n) => (n && n.device ? inventory.get ? inventory.get(n.device) : inventory.list().find((d) => d.id === n.device) : null);
  function appliances() { const out = []; for (const d of inventory.list()) { const s = poller.snapshot(d.id); for (const a of (s && s.sdwan && s.sdwan.appliances) || []) out.push(Object.assign({ via: d.name }, a)); } return out; }
  function nodeState(n, apps) {
    if (n.kind === 'internet' || n.kind === 'wan-cloud' || n.kind === 'isp') return { state: 'virtual', why: 'not a device - its links say whether it is reachable' };
    if (n.appliance) { const a = apps.find((x) => low(x.name) === low(n.appliance)); if (a) return { state: a.up ? 'up' : 'down', why: 'Silver Peak Orchestrator (' + a.via + '): appliance state ' + a.state, src: 'orchestrator' }; }
    if (n.fortigate && !n.device) { const g = fgOf(n); if (!g) return { state: 'unknown', why: 'FortiGate ' + n.fortigate + ' is not in the FortiManager poll', vendor: 'fortigate' };
      const m = g.metrics || {}; return { state: g.conn === 'down' ? 'down' : g.health === 'attention' ? 'degraded' : 'up', why: g.conn === 'down' ? 'FortiManager cannot reach it' : 'FortiManager: ' + (g.findings[0] ? g.findings[0].title : 'healthy'), vendor: 'fortigate', src: 'fortimanager', cpu: m.cpu, mem: m.mem, sessions: m.sessions }; }
    const d = devOf(n); if (!d) return { state: n.device ? 'unknown' : 'unmonitored', why: n.device ? 'device ' + n.device + ' is no longer in the inventory' : 'no device on this node - map one to measure it' };
    const s = poller.snapshot(d.id); if (!s) return { state: 'unknown', why: 'not polled yet since the engine started', vendor: d.vendor };
    const r = s.reach;
    if (s.ok === false || (r && r.received === 0 && (s.sources || []).length <= 1)) return { state: 'down', why: r && r.received === 0 ? 'no reply to ping (' + (r.sent || 0) + ' sent)' : String((s.errors || [])[0] || 'no source answered').slice(0, 200), vendor: d.vendor, at: s.at };
    const sys = s.system || {};
    if ((sys.cpu_pct || 0) >= 90 || (sys.mem_pct || 0) >= 95) return { state: 'degraded', why: 'CPU ' + Math.round(sys.cpu_pct || 0) + '% / memory ' + Math.round(sys.mem_pct || 0) + '%', vendor: d.vendor, at: s.at, cpu: sys.cpu_pct, mem: sys.mem_pct };
    return { state: 'up', why: 'answers (' + (s.sources || []).join(', ') + ')', vendor: d.vendor, at: s.at, rtt_ms: r ? r.rtt_avg_ms : null, cpu: sys.cpu_pct, mem: sys.mem_pct, sessions: sys.sessions };
  }
  function ifOf(n, name) { const d = devOf(n); if (!d || !name) return null; const s = poller.snapshot(d.id); return ((s && s.interfaces) || []).find((i) => low(i.name) === low(name) || (i.alias && low(i.alias) === low(name))) || null; }
  function tunnelOf(n, name) { const g = !n.device && fgOf(n); if (g && name) { const t = (g.tunnels || []).find((x) => low(x.name) === low(name)); return t ? { name: t.name, status: t.up ? 'up' : 'down', peer: t.peer } : null; }
    const d = devOf(n); if (!d || !name) return null; const s = poller.snapshot(d.id); return ((s && s.tunnels) || []).find((t) => low(t.name) === low(name)) || null; }
  function pathOf(n, name) { const g = !n.device && fgOf(n); if (g && name) { const l = (g.links || []).find((x) => low(x.check + ':' + x.member) === low(name) || low(x.member) === low(name)); return l ? { name: l.check, member: l.member, latency_ms: l.latency, jitter_ms: l.jitter, loss_pct: l.loss, status: l.state === 'down' ? 'down' : l.sla_ok === false ? 'sla-missed' : 'up' } : null; }
    const d = devOf(n); if (!d || !name) return null; const s = poller.snapshot(d.id); return ((s && s.paths) || []).find((p) => low(p.name + ':' + p.member) === low(name) || low(p.member) === low(name)) || null; }
  function linkState(l, N, th) {
    const a = N[l.a], b = N[l.b], m = { sources: [] }, why = [];
    for (const [node, nm] of [[a, l.a_if], [b, l.b_if]]) {
      const i = ifOf(node, nm); if (!i) { if (nm && node.device) why.push('interface ' + nm + ' not found on ' + node.label); continue; }
      m.sources.push('interface ' + node.label + ' ' + i.name);
      if (i.admin !== 'down' && i.oper === 'down') m.down = 'interface ' + i.name + ' on ' + node.label + ' is down';
      const cap = l.capacity_mbps ? l.capacity_mbps * 1e6 : (i.speed_mbps ? i.speed_mbps * 1e6 : null);
      if (i.in_bps != null || i.out_bps != null) { m.in_bps = Math.max(m.in_bps || 0, i.in_bps || 0); m.out_bps = Math.max(m.out_bps || 0, i.out_bps || 0); if (cap) m.util = r1(Math.max(m.util || 0, Math.max(i.in_bps || 0, i.out_bps || 0) / cap * 100)); m.capacity_basis = l.capacity_mbps ? 'contracted ' + l.capacity_mbps + ' Mb/s' : 'port speed ' + i.speed_mbps + ' Mb/s'; }
      else if (i.util_in != null || i.util_out != null) m.util = r1(Math.max(m.util || 0, i.util_in || 0, i.util_out || 0));
      if (i.err_per_min) m.err_per_min = Math.max(m.err_per_min || 0, i.err_per_min);
      m.iface = m.iface || i.name;
    }
    if (l.tunnel) { const ta = tunnelOf(a, l.tunnel), t = ta || tunnelOf(b, l.tunnel); if (t) { m.vendor = (ta ? a : b)._st.vendor; m.sources.push('IPsec tunnel ' + t.name); m.tunnel = t.status; if (t.status !== 'up') m.down = 'IPsec tunnel ' + t.name + ' is ' + (t.status || 'down'); } else why.push('tunnel ' + l.tunnel + ' not reported by either end'); }
    if (l.path) { const p = pathOf(a, l.path) || pathOf(b, l.path); if (p) { m.sources.push('SD-WAN health check ' + p.name + ' / ' + p.member); m.lat = p.latency_ms; m.jitter = p.jitter_ms; m.loss = p.loss_pct; if (/down|dead|fail/i.test(p.status || '') || p.loss_pct === 100) m.down = 'SD-WAN member ' + p.member + ' (' + p.name + ') is ' + (p.status || 'down'); } else why.push('SD-WAN member ' + l.path + ' not reported'); }
    const ends = [a._st, b._st];
    if (!m.sources.length) {
      if (ends.some((s) => s.state === 'down')) return Object.assign(m, { state: 'down', end_down: true, why: 'an end is down: ' + (a._st.state === 'down' ? a.label : b.label) });
      if (a.appliance && b.appliance && ends.every((s) => s.state === 'up')) return Object.assign(m, { state: 'up', why: 'both Silver Peak appliances are up (the Orchestrator reports no tunnel detail here)', sources: ['orchestrator'] });
      return Object.assign(m, { state: 'unmeasured', why: why[0] || 'nothing measures this link - name an interface, tunnel or SD-WAN member in the map' });
    }
    if (m.down) return Object.assign(m, { state: 'down', why: m.down });
    const w = [];
    let s = 'up';
    if (m.util != null && m.util >= th.util_crit) { s = 'critical'; w.push('utilisation ' + m.util + '%'); } else if (m.util != null && m.util >= th.util_warn) { s = 'degraded'; w.push('utilisation ' + m.util + '%'); }
    if (m.loss != null && m.loss >= th.loss_crit) { s = 'critical'; w.push('loss ' + m.loss + '%'); } else if (m.loss != null && m.loss >= th.loss_warn) { if (s === 'up') s = 'degraded'; w.push('loss ' + m.loss + '%'); }
    if (m.lat != null && m.lat >= th.lat_crit) { s = 'critical'; w.push('latency ' + m.lat + ' ms'); } else if (m.lat != null && m.lat >= th.lat_warn) { if (s === 'up') s = 'degraded'; w.push('latency ' + m.lat + ' ms'); }
    if (m.err_per_min) { if (s === 'up') s = 'degraded'; w.push(Math.round(m.err_per_min) + ' errors / min'); }
    return Object.assign(m, { state: s, why: w.length ? w.join(', ') : 'up (' + m.sources.join('; ') + ')' });
  }
  // which nodes still reach a root (the internet, else the data-centre edge / core) with some elements failed
  function reach(M, deadNodes, deadLinks) {
    const roots = M.nodes.filter((n) => n.kind === 'internet').map((n) => n.id);
    const R = roots.length ? roots : M.nodes.filter((n) => n.kind === 'edge-firewall' || n.kind === 'core').map((n) => n.id);
    const seen = new Set(R.filter((id) => !deadNodes.has(id))), q = [...seen];
    while (q.length) { const x = q.shift(); for (const l of M.links) { if (deadLinks.has(l.id)) continue; const y = l.a === x ? l.b : l.b === x ? l.a : null; if (y && !seen.has(y) && !deadNodes.has(y)) { seen.add(y); q.push(y); } } }
    return seen;
  }
  const users = (siteId, M) => {
    const L2 = [];
    for (const n of M.nodes) { if (n.site !== siteId || !n.device) continue; const d = devOf(n); if (!d || d.vendor !== 'fortigate') continue; const s = poller.snapshot(d.id); for (const u of (s && s.users) || []) L2.push(Object.assign({ firewall: d.name }, u)); }
    return L2.sort((a, b) => (b.bytes || 0) - (a.bytes || 0));
  };

  // ---------- machine learning (baselines per hour of the week, daily peaks)
  function learn(M, t) {
    const how = hourOfWeek(t), day = Math.floor((t + RIYADH) / 86400000);
    for (const l of M.links) {
      const s = l._st; if (!['up', 'degraded', 'critical'].includes(s.state)) continue;
      const rec = mlC.get(l.id) || { id: l.id, b: {}, peaks: [] };
      for (const [k, v] of [['util', s.util], ['lat', s.lat], ['loss', s.loss]]) {
        if (v == null) continue;
        const key = how + ':' + k, x = rec.b[key] || { n: 0, mean: 0, m2: 0 };
        const n = Math.min(x.n + 1, 50), d = v - x.mean; x.mean += d / n; x.m2 = Math.max(0, x.m2 * (x.n >= 50 ? 49 / 50 : 1) + d * (v - x.mean)); x.n = n; rec.b[key] = x;
      }
      if (s.util != null) { const p = rec.peaks.find((z) => z[0] === day); if (p) p[1] = Math.max(p[1], s.util); else rec.peaks.push([day, s.util]); rec.peaks = rec.peaks.slice(-60); }
      mlC.put(rec);
    }
  }
  function judge(l, t, th) {
    const rec = mlC.get(l.id), s = l._st, how = hourOfWeek(t), out = { anomalies: [], baseline: {}, forecast: null };
    if (!rec) return Object.assign(out, { learning: 'no history yet' });
    for (const [k, v, lab, unit] of [['util', s.util, 'utilisation', '%'], ['lat', s.lat, 'latency', ' ms'], ['loss', s.loss, 'loss', '%']]) {
      const x = rec.b[how + ':' + k]; if (!x) continue;
      const sd = x.n > 1 ? Math.sqrt(x.m2 / (x.n - 1)) : 0;
      out.baseline[k] = { mean: r1(x.mean), sd: r1(sd), n: x.n };
      if (v == null || x.n < 6) continue;
      const z = (v - x.mean) / Math.max(sd, FLOOR[k]);
      if (z >= 3 && v - x.mean >= FLOOR[k] * 2) out.anomalies.push({ metric: k, value: r1(v), usual: r1(x.mean), z: r1(z), text: lab + ' ' + r1(v) + unit + ' - usually ' + r1(x.mean) + unit + ' on ' + DAY[Math.floor(how / 24)] + 's at ' + (how % 24) + ':00 (' + x.n + ' samples)' });
    }
    if (rec.peaks.length >= 5) { const f = A.forecast(rec.peaks.map((p) => [p[0] * 86400000, p[1]]), th.util_crit); if (f) out.forecast = Object.assign({ days: rec.peaks.length, limit: th.util_crit }, f); }
    return out;
  }

  // ---------- the live map, incidents and their root cause
  function evaluate(opts = {}) {
    const t = NOW(), base = map(), th = Object.assign({}, DEF_TH, base.thresholds), apps = appliances();
    const M = { nodes: base.nodes.map((n) => Object.assign({}, n)), links: base.links.map((l) => Object.assign({}, l)), _N: {} };
    for (const n of M.nodes) { n._st = nodeState(n, apps); M._N[n.id] = n; }
    for (const l of M.links) l._st = linkState(l, M._N, th);
    if (opts.learn) learn(M, t);
    const downN = new Set(M.nodes.filter((n) => n._st.state === 'down').map((n) => n.id));
    const downL = new Set(M.links.filter((l) => l._st.state === 'down' && !l._st.end_down).map((l) => l.id));
    const all = reach(M, downN, downL), whole = reach(M, new Set(), new Set());
    const behindOf = (dn, dl) => { const r = reach(M, dn, dl); return M.nodes.filter((x) => whole.has(x.id) && !r.has(x.id) && !dn.has(x.id)).map((x) => x.id); };
    const inc = [], covered = {};
    for (const n of M.nodes) {
      if (n._st.state !== 'down') continue;
      const behind = behindOf(new Set([n.id]), new Set());
      const crit = ['edge-firewall', 'core', 'sdwan'].includes(n.kind) || behind.length >= 3;
      inc.push({ id: 'node:' + n.id, kind: 'node-down', severity: crit ? 'critical' : 'high', title: n.label + ' is down' + (behind.length ? ' - ' + behind.length + ' more cut off behind it' : ''), node: n.id, site: n.site, why: n._st.why, affects: behind, vendor: n._st.vendor });
      for (const b of behind) (covered[b] = covered[b] || []).push('node:' + n.id);
    }
    for (const l of M.links) {
      const s = l._st, a = M._N[l.a], b = M._N[l.b], vendor = (s.vendor || a._st.vendor || b._st.vendor || ''), ctx = { tunnel: l.tunnel, iface: s.iface || l.a_if, isp: l.isp, circuit: l.circuit };
      const label = a.label + ' ⇄ ' + b.label;
      if (s.state === 'down' && !s.end_down) {
        const behind = behindOf(new Set(), new Set([l.id]));
        const cov = [...new Set([].concat(covered[l.a] || [], covered[l.b] || []))];
        for (const x of behind) if (!covered[x]) (covered[x] = []).push('link:' + l.id);
        inc.push({ id: 'link:' + l.id, kind: l.tunnel && /tunnel/i.test(s.why) ? 'tunnel-down' : 'link-down', severity: behind.length ? 'critical' : 'high', title: (l.kind === 'internet' ? 'Internet link ' : l.kind === 'ipsec' ? 'VPN ' : l.kind === 'sdwan' ? 'SD-WAN path ' : 'Link ') + label + ' is down' + (behind.length ? ' - ' + behind.length + ' cut off' : ' (traffic should be on the other path)'), link: l.id, site: a.site || b.site, why: s.why, affects: behind, vendor, ctx, covered_by: cov.length ? cov : undefined });
        continue;
      }
      if (s.util != null && s.util >= th.util_warn) inc.push({ id: 'cong:' + l.id, kind: 'congestion', severity: s.util >= th.util_crit ? 'high' : 'medium', title: 'Bandwidth: ' + label + ' at ' + s.util + '%' + (s.capacity_basis ? ' of ' + s.capacity_basis : ''), link: l.id, site: a.site || b.site, why: s.why, vendor, ctx });
      if ((s.loss != null && s.loss >= th.loss_warn) || (s.lat != null && s.lat >= th.lat_warn)) inc.push({ id: 'qual:' + l.id, kind: 'quality', severity: (s.loss >= th.loss_crit || s.lat >= th.lat_crit) ? 'high' : 'medium', title: 'Quality: ' + label + ' - ' + [s.loss != null ? 'loss ' + s.loss + '%' : null, s.lat != null ? 'latency ' + s.lat + ' ms' : null, s.jitter != null ? 'jitter ' + s.jitter + ' ms' : null].filter(Boolean).join(', '), link: l.id, site: a.site || b.site, why: s.why, vendor, ctx });
      if (s.err_per_min) inc.push({ id: 'err:' + l.id, kind: 'errors', severity: 'medium', title: 'Errors on ' + label + ': ' + Math.round(s.err_per_min) + ' / min', link: l.id, site: a.site || b.site, why: s.why, vendor, ctx });
      const j = judge(l, t, th); l._ml = j;
      for (const an of j.anomalies) inc.push({ id: 'anom:' + l.id + ':' + an.metric, kind: 'anomaly', severity: an.metric === 'util' && s.util != null && s.util < th.util_warn ? 'low' : 'medium', title: 'Unusual on ' + label + ': ' + an.text, link: l.id, site: a.site || b.site, why: 'baseline for this hour of the week', vendor, ctx });
      if (j.forecast && j.forecast.days_to_full != null && j.forecast.days_to_full <= 30) inc.push({ id: 'cap:' + l.id, kind: 'capacity', severity: j.forecast.days_to_full <= 7 ? 'high' : 'medium', title: 'Capacity: ' + label + (j.forecast.days_to_full === 0 ? ' already reaches ' : ' reaches ') + th.util_crit + '% at peak' + (j.forecast.days_to_full ? ' in about ' + j.forecast.days_to_full + ' days' : ''), link: l.id, site: a.site || b.site, why: 'daily peaks over ' + j.forecast.days + ' days, +' + j.forecast.slope_per_day + '% a day', vendor, ctx });
    }
    // an incident on a node that is cut off by another one is covered, not raised again
    for (const x of inc) { const n = x.node && covered[x.node]; if (n && n.length && x.kind === 'node-down') x.covered_by = n.filter((c) => c !== x.id); if (x.covered_by && !x.covered_by.length) delete x.covered_by; }
    // a whole site dark with more than one independent root inside it (power, building, every WAN path): one site incident
    for (const st2 of base.sites) {
      const ns = M.nodes.filter((n) => n.site === st2.id && !['unmonitored', 'virtual', 'unknown'].includes(n._st.state));
      if (ns.length < 2 || !ns.every((n) => n._st.state === 'down')) continue;
      const roots = inc.filter((x) => x.kind === 'node-down' && !x.covered_by && ns.some((n) => n.id === x.node));
      if (roots.length < 2) continue;
      inc.push({ id: 'site:' + st2.id, kind: 'site-down', severity: 'critical', title: st2.name + ' is down - every monitored device there is unreachable', site: st2.id, why: ns.map((n) => n.label).join(', ') + ' all unreachable: power, the building or every WAN path at once', affects: ns.map((n) => n.id), vendor: '' });
      for (const x of roots) x.covered_by = ['site:' + st2.id];
    }
    // tracking: first seen, acknowledged
    const known = new Map(incC.all().map((r) => [r.id, r]));
    for (const x of inc) {
      const r = known.get(x.id);
      if (!r || r.cleared_at) { const rec = { id: x.id, first: t, last: t, severity: x.severity, title: x.title }; if (opts.track) incC.put(rec); x.first = t; }
      else { x.first = r.first; x.acked_by = r.acked_by || null; x.acked_at = r.acked_at || null; if (opts.track) incC.put(Object.assign({}, r, { last: t, severity: x.severity, title: x.title })); }
      Object.assign(x, runbook(x.kind, x.vendor, x.ctx || {}));
      if (x.kind === 'congestion' && x.site) { x.users = users(x.site, M).slice(0, 15); x.users_total = users(x.site, M).length; }
    }
    if (opts.track) { const now = new Set(inc.map((x) => x.id)); for (const r of known.values()) if (!now.has(r.id) && !r.cleared_at) incC.put(Object.assign({}, r, { cleared_at: t })); for (const r of incC.all()) if (r.cleared_at && t - r.cleared_at > 7 * 86400000) incC.remove(r.id); }
    inc.sort((p, q) => (!!p.covered_by - !!q.covered_by) || SEVN[q.severity] - SEVN[p.severity] || p.first - q.first);
    const cleared = incC.all().filter((r) => r.cleared_at && t - r.cleared_at < 86400000).sort((p, q) => q.cleared_at - p.cleared_at).slice(0, 30);
    const count = (L2, k) => L2.filter((x) => x._st.state === k).length;
    const sitesView = base.sites.map((s) => { const ns = M.nodes.filter((n) => n.site === s.id); const worst = ns.some((n) => n._st.state === 'down') ? 'down' : ns.some((n) => n._st.state === 'degraded') ? 'degraded' : ns.every((n) => ['unmonitored', 'unknown', 'virtual'].includes(n._st.state)) ? 'unknown' : 'up';
      const fw = users(s.id, M); return Object.assign({}, s, { state: worst, nodes: ns.length, users: fw.length, users_bytes: fw.reduce((a, u) => a + (u.bytes || 0), 0) }); });
    return {
      version: base.version, updated_by: base.updated_by || null, updated_at: base.updated_at || null, thresholds: th, at: t, sites: sitesView,
      nodes: M.nodes.map((n) => Object.assign({ id: n.id, label: n.label, kind: n.kind, site: n.site || '', device: n.device || null, appliance: n.appliance || null, reachable: all.has(n.id) }, n._st)),
      links: M.links.map((l) => Object.assign({ id: l.id, a: l.a, b: l.b, kind: l.kind, isp: l.isp || null, circuit: l.circuit || null, capacity_mbps: l.capacity_mbps || null, a_if: l.a_if || null, b_if: l.b_if || null, tunnel: l.tunnel || null, path: l.path || null }, l._st, { ml: l._ml || null })),
      incidents: inc, cleared,
      summary: { nodes: M.nodes.length, links: M.links.length, nodes_down: count(M.nodes, 'down'), links_down: count(M.links, 'down'), degraded: count(M.links, 'degraded') + count(M.links, 'critical'), unmeasured: count(M.links, 'unmeasured'), unmonitored: count(M.nodes, 'unmonitored'),
        incidents: inc.filter((x) => !x.covered_by).length, critical: inc.filter((x) => !x.covered_by && x.severity === 'critical').length, covered: inc.filter((x) => x.covered_by).length },
      polled: inventory.list().some((d) => poller.snapshot(d.id)), poller: poller.stats ? poller.stats() : null,
    };
  }
  function view(role) {
    const v = evaluate({});
    if (role === 'viewer') for (const x of v.incidents) if (x.users) { x.users = []; x.users_hidden = true; }
    return v;
  }
  function ack(id, user, note) {
    if (!incC.get(id)) evaluate({ track: true });   // seen on the page before the background check recorded it
    const r = incC.get(id); if (!r || r.cleared_at) throw bad('there is no open incident "' + id + '"', 404);
    if (/^(system|svc|service|ai|bot|duty|agent)[:._-]/i.test(String(user || ''))) throw bad('a person acknowledges an incident, not a service identity', 403);
    incC.put(Object.assign({}, r, { acked_by: user, acked_at: NOW(), ack_note: note || null }));
    return { ok: true, id };
  }
  function history(linkId) { const rec = mlC.get(linkId); if (!map().links.some((l) => l.id === linkId)) throw bad('there is no link "' + linkId + '"', 404); return { link: linkId, peaks: rec ? rec.peaks : [], buckets: rec ? Object.keys(rec.b).length : 0, baseline: rec ? rec.b : {} }; }

  // ---------- tick: learn, track, raise alerts
  function tick() {
    if (!acfg.enabled) return { raised: 0, merged: 0 };
    const v = evaluate({ learn: true, track: true }), t = NOW(); let raised = 0, merged = 0;
    if (alerts && typeof alerts.raise === 'function') for (const x of v.incidents) {
      if (x.covered_by || SEVN[x.severity] < 3) continue;
      try { const r = alerts.raise({ rule_id: 'netops-routemap-' + x.kind, rule_name: 'Network route map: ' + x.kind.replace('-', ' '), rule_type: 'netops', severity: SEVN[x.severity], ts_first: x.first || t, ts_last: t, count: 1, group: { site: x.site || '' }, group_key: 'routemap:' + x.id,
        summary: x.title, source: 'netops', src_type: 'netops-routemap', src_id: x.id, suppress_s: 86400, fields: { why: x.why, fix: x.fix.slice(0, 4), affects: (x.affects || []).length, kind: x.kind } });
        if (r && r.created) raised++; else merged++; } catch (e) { L.warn('route map alert not raised', { id: x.id, err: e.message }); }
    }
    st.ticks++; st.last = t; st.raised += raised; st.merged += merged;
    return { raised, merged, incidents: v.incidents.length };
  }
  function start() { stop(); if (!acfg.enabled) return; timer = setInterval(guardJob('netops.routemap.tick', tick), Math.max(60, acfg.interval_s) * 1000); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }

  // ---------- proposal from the inventory
  function propose() {
    const devs = inventory.list(), apps = appliances(), reasons = [], unmatched = [];
    const sid = (s) => low(s || 'unassigned').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'unassigned';
    const sites = new Map();
    const addSite = (name) => { const id = sid(name); if (!sites.has(id)) { const n = String(name || 'Unassigned'); sites.set(id, { id, name: n.slice(0, 80), kind: /\b(dc|data ?cent(er|re))\b/i.test(n) ? 'dc' : /\bdr\b|disaster/i.test(n) ? 'dr' : /\bhq\b|head ?office|headquarter/i.test(n) ? 'hq' : 'branch' }); } return id; };
    const KIND = (d) => (d.vendor === 'paloalto' ? 'edge-firewall' : d.vendor === 'fortigate' ? 'firewall' : d.vendor === 'edgeconnect' && d.role !== 'sdwan-orchestrator' ? 'sdwan' : d.role === 'sdwan-appliance' || d.role === 'wan-edge' ? 'sdwan' : ['core', 'distribution', 'access'].includes(d.role) ? d.role : d.role === 'branch-router' || d.role === 'router' ? 'router' : d.role === 'firewall' ? 'firewall' : d.vendor === 'genian' || d.role === 'nac' ? 'nac' : d.vendor === 'cisco-ucs' || d.role === 'compute' ? 'compute' : null);
    const nodes = [], links = [], seen = new Set();
    for (const d of devs) { const k = KIND(d); if (!k) continue; nodes.push({ id: sid(d.id), label: d.name.slice(0, 80), kind: k, site: addSite(d.site), device: d.id }); }
    for (const a of apps) { if (nodes.some((n) => low(n.label) === low(a.name))) { const n = nodes.find((x) => low(x.label) === low(a.name)); n.appliance = a.name; continue; } nodes.push({ id: sid('sp-' + a.name), label: String(a.name).slice(0, 80), kind: 'sdwan', site: addSite(a.site), appliance: a.name }); }
    const byDev = (id) => nodes.find((n) => n.device === id);
    const ipOwner = (ip) => devs.find((d) => d.ip === ip || d.api_host === ip);
    const add = (a, b, kind, extra, why, confidence) => { if (!a || !b || a.id === b.id) return; const k = [a.id, b.id].sort().join('|') + kind + (extra.tunnel || '') + (extra.path || ''); if (seen.has(k)) return; seen.add(k); const id = (kind + '-' + a.id + '-' + b.id + (extra.tunnel || extra.path ? '-' + low(extra.tunnel || extra.path) : '')).replace(/[^a-z0-9_.-]/g, '-').slice(0, 64); links.push(Object.assign({ id, a: a.id, b: b.id, kind }, extra)); reasons.push({ link: id, why, confidence }); };
    for (const d of devs) {
      const s = poller.snapshot(d.id), me = byDev(d.id); if (!s || !me) continue;
      for (const t of s.tunnels || []) { const o = ipOwner(t.peer); if (o && byDev(o.id)) add(me, byDev(o.id), 'ipsec', { tunnel: t.name }, 'IPsec tunnel ' + t.name + ' on ' + d.name + ' has peer ' + t.peer + ' = ' + o.name, 'high'); else if (t.peer) unmatched.push(d.name + ': tunnel ' + t.name + ' to ' + t.peer + ' (not a monitored device)'); }
      for (const nb of s.neighbors || []) { const o = ipOwner(nb.peer); if (o && byDev(o.id)) add(me, byDev(o.id), o.site === d.site ? 'lan' : 'mpls', {}, nb.proto.toUpperCase() + ' neighbour ' + nb.peer + ' of ' + d.name + ' = ' + o.name, 'high'); }
    }
    const edges = nodes.filter((n) => n.kind === 'edge-firewall');
    if (edges.length) {
      nodes.unshift({ id: 'internet', label: 'Internet', kind: 'internet', site: '' });
      for (const e of edges) { const s = poller.snapshot(e.device), wan = ((s && s.interfaces) || []).find((i) => i.oper === 'up' && /untrust|wan|isp|internet|outside|ethernet1\/1$/i.test(i.name + ' ' + (i.alias || ''))); add(nodes[0], e, 'internet', wan ? { b_if: wan.name } : {}, 'the Palo Alto ' + e.label + ' is the internet edge' + (wan ? '; its interface ' + wan.name + (wan.alias ? ' (' + wan.alias + ')' : '') + ' looks like the WAN port' : ' - name its WAN interface to measure it'), wan ? 'medium' : 'low'); }
    }
    // FortiGates FortiManager manages: one node each at its site; an IPsec tunnel whose peer is another managed FortiGate's address
    // is a link (high confidence); each SD-WAN member is a link to the Internet measured by its health check
    const F = FM(); let fl = null; if (F) { try { fl = F.fleet(); } catch (e) { fl = null; reasons.push('FortiManager fleet not readable: ' + e.message); } }
    if (fl && fl.devices.length) {
      for (const g of fl.devices) { const ex = nodes.find((n) => low(n.label) === low(g.name)); if (ex) { ex.fortigate = g.name; continue; } nodes.push({ id: sid('fg-' + g.name), label: String(g.name).slice(0, 80), kind: 'firewall', site: addSite(g.site || g.adom), fortigate: g.name }); }
      const byFg = (name) => nodes.find((n) => n.fortigate === name), fgByIp = new Map(fl.devices.filter((g) => g.ip).map((g) => [g.ip, g]));
      const pairs = new Set();   // a tunnel is named differently at each end: one link per pair of FortiGates
      for (const g of fl.devices) for (const t of g.tunnels || []) { const o = fgByIp.get(t.peer), pk = o ? [g.name, o.name].sort().join('|') : ''; if (o && pairs.has(pk)) continue; if (o) pairs.add(pk); if (o && o.name !== g.name) add(byFg(g.name), byFg(o.name), 'ipsec', { tunnel: t.name }, 'IPsec tunnel ' + t.name + ' on ' + g.name + ' has peer ' + t.peer + ' = ' + o.name + ' (FortiManager)', 'high'); else if (t.peer) unmatched.push({ device: g.name, tunnel: t.name, peer: t.peer }); }
      if (fl.devices.some((g) => (g.links || []).length)) {
        let inet = nodes.find((n) => n.id === 'internet'); if (!inet) { inet = { id: 'internet', label: 'Internet', kind: 'internet', site: '' }; nodes.unshift(inet); }
        for (const g of fl.devices) for (const l of g.links || []) add(inet, byFg(g.name), 'sdwan', { path: l.check + ':' + l.member }, 'SD-WAN member ' + l.member + ' (health check ' + l.check + ') on ' + g.name + ' (FortiManager)', 'high');
      }
    }
    const ORDER = ['edge-firewall', 'firewall', 'sdwan', 'router', 'core', 'distribution', 'access'];
    for (const site of sites.keys()) {
      const here = nodes.filter((n) => n.site === site);
      const tier = (k) => here.filter((n) => n.kind === k);
      const up = (k) => { for (const u of ORDER.slice(0, ORDER.indexOf(k))) { const c = tier(u); if (c.length) return c; } return []; };
      for (const k of ['core', 'distribution', 'access', 'sdwan', 'router', 'firewall', 'nac', 'compute']) for (const n of tier(k)) { const u = k === 'nac' || k === 'compute' ? (tier('core').length ? tier('core') : tier('distribution').length ? tier('distribution') : up('core')) : k === 'access' ? (tier('distribution').length ? tier('distribution') : tier('core').length ? tier('core') : up(k)) : k === 'distribution' ? (tier('core').length ? tier('core') : up(k)) : up(k); if (u[0]) add(u[0], n, 'lan', {}, 'same site ' + site + ': ' + n.kind + ' below ' + u[0].kind + ' (layer order - check the ports)', 'low'); }
    }
    const hubs = nodes.filter((n) => n.kind === 'sdwan' && ['dc', 'hq'].includes((sites.get(n.site) || {}).kind));
    if (hubs.length) for (const n of nodes.filter((x) => x.kind === 'sdwan' && !hubs.includes(x))) add(n, hubs[0], 'sdwan', {}, 'Silver Peak appliance at ' + n.site + ' overlays to the hub at ' + hubs[0].site + ' (assumed hub = data centre / HQ)', 'medium');
    return { map: { sites: [...sites.values()], nodes, links, thresholds: map().thresholds }, reasons, unmatched: unmatched.slice(0, 100), note: 'A proposal from the inventory and what the devices report. Nothing is saved until an administrator saves the map.' };
  }


  // ---- route analysis: the path traffic takes between two devices now, hop by hop, and how fragile it is. Deterministic, read-only;
  // the AI Network Engineer explains it (route /netops/routemap/route/ai) but never decides it.
  //   path       least-cost over the map: a down link / device costs 1000 (taken only when no other way exists), degraded 6,
  //              not measured 3, up 1 - so the route is the one that works now
  //   single points of failure  each link / intermediate device of the path removed in turn: if no other way remains between
  //              the two ends (down elements excluded), it is a single point of failure
  //   alternate  the best path avoiding every link of the route that can be avoided (single-point links are shared), and its state
  //   score      100 minus itemised penalties: route down 60, each single point 10 (WAN 15), each hop over the utilisation /
  //              latency / loss warning 8 (critical 15), each hop not measured 4, each anomaly 5, capacity full within 30 days 8
  const PCOST = { up: 1, virtual: 1, degraded: 6, critical: 8, unmeasured: 3, unknown: 3, unmonitored: 3, down: 1000 };
  const WAN = ['internet', 'mpls', 'sdwan', 'ipsec'];
  function analyzeRoute(from, to) {
    const v = evaluate({}), th = v.thresholds, N = {}, L = {};
    for (const n of v.nodes) N[n.id] = n; for (const l of v.links) L[l.id] = l;
    if (!N[from]) throw bad('from: there is no device "' + String(from).slice(0, 64) + '" in the map');
    if (!N[to]) throw bad('to: there is no device "' + String(to).slice(0, 64) + '" in the map');
    if (from === to) throw bad('to: choose a different device from "from"');
    const adj = {}; for (const l of v.links) { (adj[l.a] = adj[l.a] || []).push({ n: l.b, l }); (adj[l.b] = adj[l.b] || []).push({ n: l.a, l }); }
    function best(skipL, skipN, usable) {
      const dist = { [from]: 0 }, prev = {}, done = new Set(), Q = [from];
      while (Q.length) {
        Q.sort((x, y) => dist[x] - dist[y]); const u = Q.shift(); if (done.has(u)) continue; done.add(u); if (u === to) break;
        for (const e of adj[u] || []) {
          if (skipL.has(e.l.id) || skipN.has(e.n)) continue;
          if (usable && (e.l.state === 'down' || N[e.n].state === 'down')) continue;
          const w = (PCOST[e.l.state] || 3) + (PCOST[N[e.n].state] || 3) - 1;
          if (dist[e.n] == null || dist[u] + w < dist[e.n]) { dist[e.n] = dist[u] + w; prev[e.n] = { u, l: e.l }; Q.push(e.n); }
        }
      }
      if (dist[to] == null) return null;
      const hops = []; let x = to; while (x !== from) { hops.unshift({ node: x, link: prev[x].l }); x = prev[x].u; }
      return hops;
    }
    const hops = best(new Set(), new Set(), false);
    const label = (id) => (N[id] ? N[id].label : id);
    if (!hops) return { found: false, from, to, from_label: label(from), to_label: label(to), verdict: 'no-route', score: 0, hops: [], single_points: [], alternate: null,
      findings: [{ severity: 'critical', text: 'No route between ' + label(from) + ' and ' + label(to) + ' in the map.', fix: 'Add the missing link under Map setup, or check that both devices are in the right sites.' }], at: v.at };
    const H = hops.map((h, i) => { const l = h.link, a = i ? hops[i - 1].node : from;
      return { from: a, from_label: label(a), to: h.node, to_label: label(h.node), node_state: N[h.node].state, link: l.id, kind: l.kind, state: l.state, why: l.why || '', util: l.util == null ? null : l.util,
        lat: l.lat == null ? null : l.lat, loss: l.loss == null ? null : l.loss, jitter: l.jitter == null ? null : l.jitter, capacity_mbps: l.capacity_mbps || null, isp: l.isp || null, wan: WAN.includes(l.kind),
        anomalies: l.ml && l.ml.anomalies ? l.ml.anomalies.map((x) => x.text) : [], days_to_full: l.ml && l.ml.forecast ? l.ml.forecast.days_to_full : null }; });
    const states = [N[from].state].concat(H.map((h) => h.state), H.map((h) => h.node_state));
    const down = states.includes('down'), unmeas = H.filter((h) => ['unmeasured', 'unknown'].includes(h.state));
    // single points of failure: removing it leaves no working way between the two ends
    const usableNow = best(new Set(), new Set(), true) != null, spof = [];
    if (usableNow) {
      for (const h of H) if (!best(new Set([h.link]), new Set(), true)) spof.push({ type: 'link', id: h.link, label: h.from_label + ' ⇄ ' + h.to_label + ' (' + h.kind + ')', wan: h.wan });
      for (const h of H.slice(0, -1)) if (!best(new Set(), new Set([h.to]), true)) spof.push({ type: 'device', id: h.to, label: h.to_label, wan: ['sdwan', 'edge-firewall', 'router', 'firewall'].includes(N[h.to].kind) });
    }
    // the alternate avoids every link of the route that can be avoided (an unavoidable single point is shared by any route)
    const unavoidable = new Set(spof.filter((x) => x.type === 'link').map((x) => x.id));
    const altHops = H.some((h) => !unavoidable.has(h.link)) ? best(new Set(H.map((h) => h.link).filter((id) => !unavoidable.has(id))), new Set(), false) : null;
    const alternate = altHops ? { hops: altHops.length, state: altHops.some((x) => x.link.state === 'down' || N[x.node].state === 'down') ? 'down' : altHops.some((x) => ['degraded', 'critical'].includes(x.link.state)) ? 'degraded' : altHops.some((x) => ['unmeasured', 'unknown'].includes(x.link.state)) ? 'not measured' : 'up',
      via: altHops.map((x) => label(x.node)) } : null;
    // findings and the itemised score
    const F = [], pen = []; const P = (pts, why) => pen.push({ points: pts, why });
    if (down) { const d = H.find((h) => h.state === 'down' || h.node_state === 'down'); const where = N[from].state === 'down' ? label(from) : d.node_state === 'down' ? d.to_label : d.from_label + ' ⇄ ' + d.to_label;   // a link reads down when the device at its end is: name the device
      F.push({ severity: 'critical', text: 'The route is down at ' + where + (alternate && alternate.state !== 'down' ? '; another way exists (' + alternate.state + ', via ' + alternate.via.slice(0, 4).join(' → ') + ').' : ' and no other way exists in the map.'), fix: 'Open the incident for it on this page for the fix steps.' }); P(60, 'route down at ' + where); }
    for (const x of spof) { F.push({ severity: x.wan ? 'high' : 'medium', text: 'Single point of failure: ' + x.label + ' - if it fails, ' + label(from) + ' loses ' + label(to) + '.', fix: x.type === 'link' ? 'Add a second path (another ISP / SD-WAN member / IPsec backup) and record it in the map.' : 'Consider an HA pair or a second device on another path.' }); P(x.wan ? 15 : 10, 'single point of failure: ' + x.label); }
    for (const h of H) {
      const lbl = h.from_label + ' ⇄ ' + h.to_label;
      if (h.util != null && h.util >= th.util_warn) { const c = h.util >= th.util_crit; F.push({ severity: c ? 'high' : 'medium', text: 'Bottleneck: ' + lbl + ' at ' + h.util + '% utilisation.', fix: 'See who uses it (the congestion incident lists the users) and steer bulk traffic or raise the capacity - as an approved change.' }); P(c ? 15 : 8, 'utilisation ' + h.util + '% on ' + lbl); }
      if (h.lat != null && h.lat >= th.lat_warn) { const c = h.lat >= th.lat_crit; F.push({ severity: c ? 'high' : 'medium', text: 'Latency ' + h.lat + ' ms on ' + lbl + '.', fix: 'Compare the other members / paths and open a ticket with the ISP with the figures.' }); P(c ? 15 : 8, 'latency ' + h.lat + ' ms on ' + lbl); }
      if (h.loss != null && h.loss >= th.loss_warn) { const c = h.loss >= th.loss_crit; F.push({ severity: c ? 'high' : 'medium', text: 'Packet loss ' + h.loss + '% on ' + lbl + '.', fix: 'Check the interface errors on both ends, then the carrier.' }); P(c ? 15 : 8, 'loss ' + h.loss + '% on ' + lbl); }
      for (const a of h.anomalies) { F.push({ severity: 'low', text: 'Unusual on ' + lbl + ': ' + a, fix: 'Compare with the same hour last week; a lasting change is worth a look.' }); P(5, 'anomaly on ' + lbl); }
      if (h.days_to_full != null && h.days_to_full <= 30) { F.push({ severity: h.days_to_full <= 7 ? 'high' : 'medium', text: lbl + ' reaches ' + th.util_crit + '% at peak ' + (h.days_to_full === 0 ? 'already' : 'in about ' + h.days_to_full + ' days') + ' at the current growth.', fix: 'Plan the upgrade or the traffic shift before then.' }); P(8, 'capacity on ' + lbl); }
    }
    for (const h of unmeas) { F.push({ severity: 'low', text: 'Not measured: ' + h.from_label + ' ⇄ ' + h.to_label + ' (' + h.kind + ') - its state is not known, so the route cannot be vouched for there.', fix: 'Name the interface, IPsec tunnel or SD-WAN member of this link under Map setup → Links.' }); P(4, 'not measured: ' + h.from_label + ' ⇄ ' + h.to_label); }
    const score = Math.max(0, 100 - pen.reduce((a, x) => a + x.points, 0));
    const lat = H.filter((h) => h.lat != null), util = H.filter((h) => h.util != null);
    const bott = util.length ? util.reduce((m, h) => (h.util > m.util ? h : m)) : null;
    const SEV = { critical: 4, high: 3, medium: 2, low: 1 }; F.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
    return { found: true, from, to, from_label: label(from), to_label: label(to), at: v.at,
      verdict: down ? 'down' : F.some((f) => f.severity === 'high') ? 'at-risk' : unmeas.length ? 'partly-measured' : F.some((f) => f.severity === 'medium') ? 'degraded' : 'healthy',
      score, penalties: pen, hops: H, latency_ms: lat.length ? Math.round(lat.reduce((a, h) => a + h.lat, 0) * 10) / 10 : null, latency_measured_hops: lat.length,
      max_loss: H.reduce((m, h) => (h.loss != null && h.loss > (m == null ? -1 : m) ? h.loss : m), null), bottleneck: bott ? { link: bott.link, label: bott.from_label + ' ⇄ ' + bott.to_label, util: bott.util } : null,
      single_points: spof, alternate, findings: F };
  }
  // the AI Network Engineer's view (read-only tool)
  function forAi(i) {
    const v = evaluate({}), site = low(i && i.site);
    const inc = v.incidents.filter((x) => !site || low(x.site).includes(site)).slice(0, 30).map((x) => ({ id: x.id, kind: x.kind, severity: x.severity, title: x.title, why: x.why, covered_by: x.covered_by, affects: x.affects, first: new Date(x.first || v.at).toISOString(), acked_by: x.acked_by, users_top: (x.users || []).slice(0, 5).map((u) => ({ user: u.user, ip: u.ip, bytes: u.bytes })) }));
    const links = v.links.filter((l) => !(i && i.only_problems) || !['up'].includes(l.state)).slice(0, 80).map((l) => ({ id: l.id, a: l.a, b: l.b, kind: l.kind, state: l.state, why: l.why, util: l.util, loss: l.loss, lat: l.lat, isp: l.isp, anomalies: l.ml ? l.ml.anomalies : [], forecast: l.ml ? l.ml.forecast : null }));
    return { summary: v.summary, incidents: inc, links, nodes_down: v.nodes.filter((n) => n.state === 'down').map((n) => n.label) };
  }
  return { map, save, validate, evaluate, view, ack, history, tick, start, stop, propose, forAi, analyzeRoute, stats: () => Object.assign({ enabled: acfg.enabled }, st) };
}

module.exports = { createRouteMap, runbook, DEF_TH, NODE_KINDS, LINK_KINDS, SITE_KINDS, hourOfWeek };
