// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
const { shortIf, longIf } = require('./portmap');
/*
 * Intelligent Network Map - the organisation's physical network as the devices themselves report it: every switch the port map
 * reads (read-only SSH, portmap.js) names its CDP / LLDP neighbours, and every inventory device carries its live state from the
 * poller. The map is built from those two facts only - nothing new is polled, nothing is drawn by hand, nothing is changed on a
 * device. (The WAN / LAN Route Map, routemap.js, is the map an administrator draws; this one is discovered.)
 *   nodes     inventory devices (state from the poll: up / degraded / down / unknown / not polled) and the network devices a
 *             neighbour table names that are NOT in the inventory (unmanaged switches, routers, access points). Phones and
 *             hosts are counted per switch, not drawn.
 *   links     one per neighbour pair, joined on the neighbour's IP or its exact host name (domain removed) - never on a similar
 *             name. A link seen from both ends is confirmed; from one end only it is said (LLDP / CDP off on the far end, or
 *             something unmanaged in between). Link state = the local interface's operational state from the poll, else
 *             "not measured" - never shown as up.
 *   layers    from the device's role: edge (firewall, WAN edge, routers, SD-WAN) -> core -> distribution -> access -> wireless
 *             and other. A device whose role is "other" takes its layer from what its neighbours' CDP / LLDP call it.
 *   intelligence
 *             single points of failure: a device whose loss alone cuts devices off from the edge (computed, with the list);
 *             blast radius of every down device and down link (what is cut off now); unmanaged network devices found in the
 *             neighbour tables; links seen from one side only; switches whose neighbour table is empty or stale; devices
 *             never placed on the map; changes since the last snapshot (links added / removed, devices appeared / gone).
 *   path      the shortest path between two devices, hop by hop with the ports, and whether every hop is up.
 *   layout    an operator may pin node positions; the positions are only presentation and are audited.
 * Viewers see the map without IP addresses; analysts and above see addresses, paths and impact.
 */
const DAY = 86400000;
const low = (s) => String(s == null ? '' : s).toLowerCase();
const hostOf = (n) => low(n).split('.')[0].trim();
const LAYER_OF_ROLE = { firewall: 0, 'wan-edge': 0, router: 0, 'branch-router': 0, 'sdwan-appliance': 0, 'sdwan-orchestrator': 0, core: 1, distribution: 2, access: 3, nac: 3, wlc: 3, fc_switch: 3, compute: 4, ups: 4 };
const LAYERS = ['Edge (firewall / WAN)', 'Core', 'Distribution', 'Access', 'Wireless and other'];
const ID_RE = /^[a-z0-9][a-z0-9_.:-]{0,79}$/;

// what a neighbour is, from its CDP / LLDP capabilities and platform (phones and hosts are endpoints, not nodes)
function kindOf(nb) {
  const caps = low((nb.caps || []).join(' ')), plat = low(nb.platform);
  if (/phone/.test(caps) || /\bip phone\b|\bcp-\d/.test(plat)) return 'phone';
  if (/wlan|trans-bridge/.test(caps) || /\bair-|access point|aironet|\baruba ap\b/.test(plat)) return 'ap';
  if (/router/.test(caps) && !/switch|bridge/.test(caps)) return 'router';
  if (/switch|bridge/.test(caps)) return 'switch';
  return 'host';
}
const LAYER_OF_KIND = { router: 0, switch: 3, ap: 4 };

// articulation-style impact: the nodes that stop reaching a root when `dead` nodes / links are removed
function reachable(adj, roots, deadN, deadL) {
  const seen = new Set(), q = [];
  for (const r of roots) if (!deadN.has(r)) { seen.add(r); q.push(r); }
  while (q.length) {
    const x = q.shift();
    for (const [y, lid] of adj.get(x) || []) { if (seen.has(y) || deadN.has(y) || deadL.has(lid)) continue; seen.add(y); q.push(y); }
  }
  return seen;
}

function createNetMap({ inventory, poller, state, log, now }) {
  const L = log || { info() {}, warn() {} }, clock = now || Date.now;
  const C = { reads: state.collection('portmap_reads'), snaps: state.collection('netmap_snaps'), layout: state.collection('netmap_layout') };
  let timer = null;

  function devState(d) {
    const s = poller.snapshot(d.id);
    if (d.poll && d.poll.ping === false && d.poll.snmp === false && d.poll.api === false) return { state: 'not polled', why: 'no polling switched on for this device' };
    if (!s) return { state: 'unknown', why: 'not polled yet since the engine started' };
    const r = s.reach;
    if (s.ok === false || (r && r.received === 0 && (s.sources || []).length <= 1)) return { state: 'down', why: r && r.received === 0 ? 'no reply to ping' : String((s.errors || [])[0] || 'no source answered').slice(0, 200), at: s.at };
    const sys = s.system || {};
    if ((sys.cpu_pct || 0) >= 90 || (sys.mem_pct || 0) >= 95) return { state: 'degraded', why: 'CPU ' + Math.round(sys.cpu_pct || 0) + '% / memory ' + Math.round(sys.mem_pct || 0) + '%', at: s.at };
    return { state: 'up', why: 'answers (' + (s.sources || []).join(', ') + ')', at: s.at, rtt_ms: r ? r.rtt_avg_ms : null };
  }
  function ifState(devId, port) {
    const s = poller.snapshot(devId); if (!s || !port) return null;
    const lp = low(longIf(port)), sp = low(shortIf(port));
    const i = (s.interfaces || []).find((x) => low(x.name) === lp || low(shortIf(x.name)) === sp);
    return i ? { oper: i.oper || null, util_in: i.util_in != null ? i.util_in : null, util_out: i.util_out != null ? i.util_out : null, err_per_min: i.err_per_min != null ? i.err_per_min : null } : null;
  }

  // ---- build the graph from the inventory and the port map's latest reads
  function build() {
    const t = clock(), devs = inventory.list(), nodes = new Map(), links = new Map();
    const byIp = new Map(), byName = new Map();
    for (const d of devs) {
      if (d.ip) byIp.set(d.ip, d.id);
      for (const k of [d.name, d.id]) if (k && !byName.has(hostOf(k))) byName.set(hostOf(k), d.id);
      const st = devState(d);
      nodes.set(d.id, { id: d.id, name: d.name, ip: d.ip || '', site: d.site || '', role: d.role || 'other', vendor: d.vendor || '', criticality: d.criticality || null, managed: true,
        layer: LAYER_OF_ROLE[d.role] != null ? LAYER_OF_ROLE[d.role] : null, state: st.state, why: st.why, rtt_ms: st.rtt_ms != null ? st.rtt_ms : null, read: null, endpoints: { phones: 0, aps: 0, hosts: 0 }, links: 0 });
    }
    const reads = new Map(); for (const r of C.reads.all()) if (nodes.has(r.id)) reads.set(r.id, r);
    const resolve = (nb) => (nb.ip && byIp.get(nb.ip)) || (nb.name && byName.get(hostOf(nb.name))) || null;
    const callKinds = new Map();   // what neighbours call each managed device (for role "other")
    for (const [id, rec] of reads) {
      const me = nodes.get(id), trunks = new Set(rec.trunks || []);
      me.read = { at: rec.at, neighbours: (rec.neighbours || []).length, errors: (rec.errors || []).length, macs: (rec.macs || []).filter((m) => !trunks.has(low(m.port))).length };
      for (const nb of rec.neighbours || []) {
        const kind = kindOf(nb); let peer = resolve(nb);
        if (peer === id) continue;
        if (!peer) {
          if (kind === 'phone') { me.endpoints.phones++; continue; }
          if (kind === 'host') { me.endpoints.hosts++; continue; }
          if (kind === 'ap') me.endpoints.aps++;
          peer = 'nb:' + (hostOf(nb.name) || nb.ip || 'unknown');
          if (!nodes.has(peer)) nodes.set(peer, { id: peer, name: String(nb.name || nb.ip || 'unknown').slice(0, 120), ip: nb.ip || '', site: me.site, role: kind, vendor: '', platform: String(nb.platform || '').slice(0, 160), managed: false,
            layer: LAYER_OF_KIND[kind] != null ? LAYER_OF_KIND[kind] : 4, state: 'unmanaged', why: 'named by ' + me.name + ' (' + String(nb.via || '').toUpperCase() + ') - not in the network inventory', read: null, endpoints: { phones: 0, aps: 0, hosts: 0 }, links: 0 });
        } else { if (!callKinds.has(peer)) callKinds.set(peer, []); callKinds.get(peer).push(kind); }
        const a = id < peer ? id : peer, b = id < peer ? peer : id, aPort = id === a ? nb.local : nb.remote_port, bPort = id === a ? nb.remote_port : nb.local;
        const key = a + '|' + b + '|' + low(shortIf(aPort || '')) + '|' + low(shortIf(bPort || ''));
        let l = links.get(key);
        if (!l) {
          // the same pair on the same local port, reported from the other end with its own port names, is one link
          l = [...links.values()].find((x) => x.a === a && x.b === b && ((id === a && low(shortIf(x.a_port || '')) === low(shortIf(nb.local || ''))) || (id === b && low(shortIf(x.b_port || '')) === low(shortIf(nb.local || '')))));
        }
        if (!l) { l = { id: 'l' + (links.size + 1), a, b, a_port: shortIf(aPort || '') || '', b_port: shortIf(bPort || '') || '', via: [], seen_from: [] }; links.set(key, l); }
        if (id === a && nb.local) l.a_port = shortIf(nb.local); if (id === b && nb.local) l.b_port = shortIf(nb.local);
        if (!l.via.includes(nb.via)) l.via.push(nb.via);
        if (!l.seen_from.includes(id)) l.seen_from.push(id);
      }
    }
    // layer for role "other" from what the neighbours call it
    for (const [id, kinds] of callKinds) { const n = nodes.get(id); if (n.layer != null) continue; n.layer = kinds.includes('router') ? 0 : kinds.includes('switch') ? 3 : kinds.includes('ap') ? 4 : 4; n.layer_from = 'neighbours'; }
    for (const n of nodes.values()) if (n.layer == null) n.layer = 4;
    // link state from the local interfaces of either end
    const L2 = [...links.values()];
    for (const l of L2) {
      const ia = nodes.get(l.a).managed ? ifState(l.a, l.a_port) : null, ib = nodes.get(l.b).managed ? ifState(l.b, l.b_port) : null;
      const opers = [ia && ia.oper, ib && ib.oper].filter(Boolean);
      l.state = opers.includes('down') ? 'down' : opers.includes('up') ? 'up' : 'not measured';
      l.util_pct = Math.max(...[ia, ib].filter(Boolean).flatMap((x) => [x.util_in, x.util_out]).filter((v) => v != null), -1); if (l.util_pct < 0) l.util_pct = null;
      l.errors_per_min = Math.max(...[ia, ib].filter(Boolean).map((x) => x.err_per_min).filter((v) => v != null), -1); if (l.errors_per_min < 0) l.errors_per_min = null;
      const both = nodes.get(l.a).read && nodes.get(l.b).read;
      l.confirmed = l.seen_from.length === 2;
      l.one_sided = !!both && !l.confirmed;
      nodes.get(l.a).links++; nodes.get(l.b).links++;
    }
    return { at: t, nodes: [...nodes.values()], links: L2, reads };
  }

  function adjacency(M) { const adj = new Map(); for (const n of M.nodes) adj.set(n.id, []); for (const l of M.links) { adj.get(l.a).push([l.b, l.id]); adj.get(l.b).push([l.a, l.id]); } return adj; }
  function rootsOf(M) {
    const placed = M.nodes.filter((n) => n.links > 0);
    let r = placed.filter((n) => n.managed && n.layer === 0);
    if (!r.length) r = placed.filter((n) => n.managed && n.layer === 1);
    if (!r.length && placed.length) r = [placed.slice().sort((x, y) => y.links - x.links)[0]];
    return { ids: r.map((n) => n.id), basis: !r.length ? 'none' : r[0].layer === 0 ? 'edge devices' : r[0].layer === 1 ? 'core switches (no edge device on the map)' : 'the most connected device (no edge or core role set)' };
  }
  function cutOff(M, adj, roots, deadN, deadL) {
    const whole = reachable(adj, roots, new Set(), new Set()), now2 = reachable(adj, roots, deadN, deadL);
    return M.nodes.filter((n) => whole.has(n.id) && !now2.has(n.id) && !deadN.has(n.id)).map((n) => n.id);
  }

  function analyse(M) {
    const F = [], adj = adjacency(M), R = rootsOf(M), byId = new Map(M.nodes.map((n) => [n.id, n])), name = (id) => (byId.get(id) || {}).name || id, t = clock();
    const add = (sev, kind, title, why, o) => F.push(Object.assign({ id: kind + ':' + (o && o.key ? o.key : title).slice(0, 120), severity: sev, kind, title, why }, o || {}));
    const roots = R.ids;
    // what is cut off right now by down devices and down links
    const downN = new Set(M.nodes.filter((n) => n.state === 'down').map((n) => n.id)), downL = new Set(M.links.filter((l) => l.state === 'down').map((l) => l.id));
    for (const id of downN) {
      const cut = roots.length ? cutOff(M, adj, roots, new Set([id]), new Set()) : [];
      const n = byId.get(id); add(cut.length || n.layer <= 1 ? 'critical' : 'high', 'device-down', name(id) + ' is down' + (cut.length ? ' - ' + cut.length + ' device' + (cut.length > 1 ? 's' : '') + ' cut off behind it' : ''), n.why, { key: id, node: id, cut_off: cut.map(name) });
    }
    for (const l of M.links) if (l.state === 'down') {
      const cut = roots.length ? cutOff(M, adj, roots, new Set(), new Set([l.id])) : [];
      add(cut.length ? 'high' : 'medium', 'link-down', 'Link ' + name(l.a) + ' ' + l.a_port + ' ↔ ' + name(l.b) + ' ' + l.b_port + ' is down' + (cut.length ? ' - ' + cut.length + ' cut off' : ' - a redundant path carries the traffic'),
        'the interface reports operationally down in the last poll', { key: l.id, link: l.id, cut_off: cut.map(name) });
    }
    // single points of failure: a device or a link whose loss alone cuts devices off from the edge
    const spof = [];
    if (roots.length) for (const n of M.nodes) {
      if (n.links < 2 && !roots.includes(n.id)) continue;
      const cut = cutOff(M, adj, roots, new Set([n.id]), new Set());
      if (cut.length) spof.push({ id: n.id, name: n.name, cut_off: cut.length, devices: cut.map(name) });
    }
    spof.sort((a, b) => b.cut_off - a.cut_off);
    for (const s of spof) add(s.cut_off >= 3 ? 'high' : 'medium', 'single-point', s.name + ' is a single point of failure: ' + s.cut_off + ' device' + (s.cut_off > 1 ? 's' : '') + ' lose their path to the ' + (R.basis === 'edge devices' ? 'edge' : 'core') + ' if it fails',
      'no second path exists in what the neighbour tables report; add a redundant uplink or check that CDP / LLDP is on so a hidden second path is seen', { key: s.id, node: s.id, cut_off: s.devices });
    for (const n of M.nodes) if (!n.managed && (n.role === 'switch' || n.role === 'router')) {
      const by = M.links.filter((l) => l.a === n.id || l.b === n.id).map((l) => (l.a === n.id ? name(l.b) + ' ' + l.b_port : name(l.a) + ' ' + l.a_port));
      add('medium', 'unmanaged', 'Unmanaged ' + n.role + ' ' + n.name + ' is on the network', 'named in the neighbour table of ' + by.join(', ') + ' but not in the network inventory - it is not polled, backed up or audited. Add it to the inventory, or remove it if it should not be there.', { key: n.id, node: n.id });
    }
    for (const l of M.links) if (l.one_sided) {
      const from = l.seen_from[0], other = from === l.a ? l.b : l.a;
      add('low', 'one-sided', 'Link ' + name(l.a) + ' ↔ ' + name(l.b) + ' is seen only by ' + name(from), name(other) + ' does not report ' + name(from) + ' - CDP / LLDP is off on that port, or an unmanaged device sits between them.', { key: l.id, link: l.id });
    }
    for (const n of M.nodes) {
      if (!n.read) continue;
      const age = Math.floor((t - n.read.at) / DAY);
      if (age >= 7) add('low', 'stale', n.name + ': neighbour table is ' + age + ' days old', 'the map shows what was read on ' + new Date(n.read.at).toISOString().slice(0, 10) + '; read the switch again on the Switch Port Map', { key: n.id, node: n.id });
      if (!n.read.neighbours) add('low', 'no-neighbours', n.name + ' reports no CDP / LLDP neighbour', 'enable CDP or LLDP on its uplinks so the map can place it', { key: 'nn:' + n.id, node: n.id });
    }
    const SEV = { critical: 4, high: 3, medium: 2, low: 1 };
    F.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
    return { findings: F, spof, roots: R };
  }

  function edgeSet(M) { return M.links.map((l) => l.a + '|' + l.b).sort(); }
  function snapshot(by) {
    const M = build(), t = clock(), rec = { id: 's' + t, at: t, by: by || 'system', nodes: M.nodes.map((n) => n.id).sort(), edges: [...new Set(edgeSet(M))] };
    C.snaps.put(rec);
    const all = C.snaps.all().sort((a, b) => b.at - a.at); for (const old of all.slice(30)) C.snaps.remove(old.id);
    return { at: t, nodes: rec.nodes.length, links: rec.edges.length };
  }
  function changes(M) {
    const S = C.snaps.all().sort((a, b) => b.at - a.at); if (!S.length) return { since: null, items: [] };
    const last = S[0], nowE = new Set(edgeSet(M)), thenE = new Set(last.edges), nowN = new Set(M.nodes.map((n) => n.id)), thenN = new Set(last.nodes);
    const nm = new Map(M.nodes.map((n) => [n.id, n.name])), pretty = (e) => e.split('|').map((x) => nm.get(x) || x.replace(/^nb:/, '')).join(' ↔ ');
    const items = [];
    for (const e of nowE) if (!thenE.has(e)) items.push({ kind: 'link-added', what: 'New link ' + pretty(e) });
    for (const e of thenE) if (!nowE.has(e)) items.push({ kind: 'link-removed', what: 'Link gone ' + pretty(e) });
    for (const n of nowN) if (!thenN.has(n)) items.push({ kind: 'device-appeared', what: 'Appeared: ' + (nm.get(n) || n) });
    for (const n of thenN) if (!nowN.has(n)) items.push({ kind: 'device-gone', what: 'No longer on the map: ' + n.replace(/^nb:/, '') });
    return { since: last.at, items };
  }

  function view(role) {
    const M = build(), A = analyse(M), lay = (C.layout.get('positions') || {}).value || {}, priv = role === 'viewer';
    const nodes = M.nodes.map((n) => Object.assign({}, n, priv ? { ip: '' } : {}, { pos: lay[n.id] || null, spof: A.spof.some((s) => s.id === n.id) }));
    const managed = M.nodes.filter((n) => n.managed), switches = managed.filter((n) => n.read);
    const sev = (s) => A.findings.filter((f) => f.severity === s).length;
    return {
      at: M.at, layers: LAYERS, roots: A.roots, nodes, links: M.links, findings: A.findings, changes: changes(M),
      summary: { devices: managed.length, placed: managed.filter((n) => n.links > 0).length, switches_read: switches.length, unmanaged: M.nodes.filter((n) => !n.managed).length, links: M.links.length,
        links_confirmed: M.links.filter((l) => l.confirmed).length, down: managed.filter((n) => n.state === 'down').length, spof: A.spof.length, critical: sev('critical'), high: sev('high'), medium: sev('medium'), low: sev('low'),
        phones: M.nodes.reduce((s, n) => s + n.endpoints.phones, 0), endpoints: M.nodes.reduce((s, n) => s + ((n.read && n.read.macs) || 0), 0) },
      not_placed: managed.filter((n) => n.links === 0).map((n) => ({ id: n.id, name: n.name, role: n.role, why: n.read ? 'its neighbour table names no device on the map' : n.vendor === 'cisco-ios' ? 'not read yet on the Switch Port Map' : 'the map reads Cisco IOS switches; this ' + (n.vendor || 'device') + ' is placed when a switch names it as a neighbour' })),
      layout_saved: Object.keys(lay).length > 0, private: priv, role: role || 'viewer',
      can: { analyse: role === 'analyst' || role === 'operator' || role === 'admin', edit: role === 'operator' || role === 'admin' },
    };
  }
  function need(M, id, what) { if (!ID_RE.test(String(id || ''))) throw Object.assign(new Error(what + ' is not a device id from the map'), { status: 400 }); const n = M.nodes.find((x) => x.id === id); if (!n) throw Object.assign(new Error(what + ' ' + id + ' is not on the map'), { status: 404 }); return n; }
  function impact(id) {
    const M = build(), n = need(M, id, 'device'), adj = adjacency(M), R = rootsOf(M);
    if (!R.ids.length) return { device: n.name, cut_off: [], basis: R.basis, note: 'no link on the map yet - read the switches on the Switch Port Map' };
    const cut = cutOff(M, adj, R.ids, new Set([id]), new Set()), byId = new Map(M.nodes.map((x) => [x.id, x]));
    return { device: n.name, root: R.ids.includes(id), basis: R.basis, cut_off: cut.map((x) => ({ id: x, name: byId.get(x).name, role: byId.get(x).role, state: byId.get(x).state })) };
  }
  function path(from, to) {
    const M = build(), a = need(M, from, 'from'), b = need(M, to, 'to'), adj = adjacency(M), byL = new Map(M.links.map((l) => [l.id, l])), byId = new Map(M.nodes.map((n) => [n.id, n]));
    const prev = new Map([[a.id, null]]), q = [a.id];
    while (q.length && !prev.has(b.id)) { const x = q.shift(); for (const [y, lid] of adj.get(x) || []) if (!prev.has(y)) { prev.set(y, [x, lid]); q.push(y); } }
    if (!prev.has(b.id)) return { from: a.name, to: b.name, found: false, hops: [], note: 'no path between them in what the neighbour tables report' };
    const hops = []; let cur = b.id;
    while (prev.get(cur)) { const [p, lid] = prev.get(cur), l = byL.get(lid); hops.unshift({ from: byId.get(p).name, from_port: l.a === p ? l.a_port : l.b_port, to: byId.get(cur).name, to_port: l.a === cur ? l.a_port : l.b_port, link: lid, state: l.state, to_state: byId.get(cur).state }); cur = p; }
    const bad = hops.filter((h) => h.state === 'down' || h.to_state === 'down');
    return { from: a.name, to: b.name, found: true, hops, healthy: !bad.length, problems: bad.map((h) => h.state === 'down' ? 'link ' + h.from + ' ' + h.from_port + ' is down' : h.to + ' is down') };
  }
  function saveLayout(positions, by) {
    const M = build(), ids = new Set(M.nodes.map((n) => n.id)), cur = (C.layout.get('positions') || {}).value || {}, next = Object.assign({}, cur);
    let n = 0;
    for (const [id, p] of Object.entries(positions)) { if (!ids.has(id)) throw Object.assign(new Error('positions: ' + id + ' is not on the map'), { status: 400 }); next[id] = { x: p.x, y: p.y }; n++; }
    C.layout.put({ id: 'positions', value: next, by, at: clock() });
    return { saved: n, total: Object.keys(next).length };
  }
  function resetLayout(by) { const had = Object.keys(((C.layout.get('positions') || {}).value) || {}).length; C.layout.put({ id: 'positions', value: {}, by, at: clock() }); return { cleared: had }; }
  function start() { if (timer) return; timer = setInterval(guardJob('netops.netmap.snapshot', () => { snapshot('system'); }), DAY); if (timer.unref) timer.unref(); L.info('netops netmap started'); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  return { build, analyse, view, impact, path, snapshot, saveLayout, resetLayout, start, stop };
}

module.exports = { createNetMap, kindOf, LAYERS, ID_RE };
