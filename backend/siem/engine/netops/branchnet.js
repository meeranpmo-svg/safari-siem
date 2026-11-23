// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * Branch Connectivity - every site in one window: its WAN links, whether it reaches the data centre and the DR site right
 * now, and the quality of each path. Built on the WAN / LAN route map (routemap.js evaluate()), which already measures every
 * node and link from what the AI Network Engineer polls: nothing new is polled and nothing is changed on a device.
 *   path to DC / DR  a breadth-first walk from the site over the map (to the DR site WITHOUT passing the DC, so a path that
 *            hairpins through the data centre does not count as DR): "yes" only through links that are measured up (or
 *            degraded), "no" when even the links nobody measures cannot get there, otherwise "not proven". A site with no
 *            DC / DR site on the map says so - never "reachable".
 *   health   down (cannot reach the DC) > partial (DC but not DR) > backup (a WAN path lost, still through the other) >
 *            degraded (a path's quality / utilisation is over the threshold) > ok; "not measured" when no WAN link is.
 *   design   single WAN path, both paths with one ISP, both paths on one edge device, no route to the DR site even with
 *            everything up - each a resilience finding with what to do.
 *   history  a 5-minute sample per site (health, DC reach, best latency) and per WAN link (up / down) for 7 days:
 *            availability to the DC, outages, MTTR, time on fewer paths, failovers, flapping; per ISP availability and
 *            outages against the SLA target an administrator sets; latency against the site's own week (robust z,
 *            median / MAD, 36+ samples).
 *   ISP ticket  a draft (circuit, since when, what was measured, outages this week) for a person to send to the ISP.
 *   actions  ranked: what to do first, each pointing at its section.
 */
const { guard: guardJob } = require('../util/errors');

const KEEP = 7 * 86400000, SLOT = 300000, MAXS = Math.ceil(KEEP / SLOT) + 12;
const WAN = new Set(['internet', 'mpls', 'sdwan', 'ipsec']);
const VIRT = new Set(['internet', 'isp', 'wan-cloud']);
const RANKH = { down: 5, partial: 4, backup: 3, degraded: 2, unmeasured: 1, ok: 0, self: 0 };
const UPS = new Set(['up', 'degraded', 'critical']);
const r1 = (x) => (x == null || !isFinite(x) ? null : Math.round(x * 10) / 10);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const median = (a) => { const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length ? (s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2) : null; };

// the nodes a site reaches: through links whose state is in `ok`, never through a node that is down
function walk(ev, from, ok, blocked) {
  const N = new Map(ev.nodes.map((n) => [n.id, n])), no = blocked || new Set(), seen = new Set(from.filter((id) => N.get(id) && N.get(id).state !== 'down' && !no.has(id))), q = [...seen];
  while (q.length) {
    const x = q.shift();
    for (const l of ev.links) {
      if (!ok(l)) continue;
      const y = l.a === x ? l.b : l.b === x ? l.a : null;
      if (y && !seen.has(y) && !no.has(y) && N.get(y) && N.get(y).state !== 'down') { seen.add(y); q.push(y); }
    }
  }
  return seen;
}
const reachTo = (proven, possible, targets) => (!targets.length ? 'n/a' : targets.some((t) => proven.has(t)) ? 'yes' : targets.some((t) => possible.has(t)) ? 'unproven' : 'no');

// reliability from 5-minute samples [{t, h, dc, lat}] (dc: 1 reached, 0 not, null unknown)
function reliability(s) {
  const known = s.filter((x) => x.dc === 0 || x.dc === 1), out = { samples: s.length, hours: r1(s.length * SLOT / 3600000) };
  out.availability = known.length >= 12 ? r1(known.filter((x) => x.dc === 1).length / known.length * 100) : null;
  let ep = 0, downMs = 0, start = null, fail = 0, prevB = false;
  for (let i = 0; i < known.length; i++) {
    const x = known[i];
    if (x.dc === 0 && start == null) { start = x.t; ep++; }
    if (x.dc === 1 && start != null) { downMs += x.t - start; start = null; }
  }
  if (start != null) downMs += (known.length ? known[known.length - 1].t : start) - start + SLOT;
  for (const x of s) { const b = x.h === 'backup'; if (b && !prevB) fail++; prevB = b; }
  out.outages = ep; out.mttr_min = ep ? Math.round(downMs / ep / 60000) : null;
  out.backup_pct = s.length >= 12 ? r1(s.filter((x) => x.h === 'backup').length / s.length * 100) : null;
  out.failovers = fail;
  const last = s.slice(-24); let ch = 0; for (let i = 1; i < last.length; i++) if (last[i].h !== last[i - 1].h) ch++;
  out.changes_24 = ch; out.flapping = ch >= 3;
  if (start != null) out.down_since = start;
  return out;
}
// up/down episodes of a link from [{t, up}]
function linkEpisodes(s) {
  const k = s.filter((x) => x.up === 0 || x.up === 1); let ep = 0, open = null, last = null;
  for (const x of k) { if (x.up === 0 && open == null) { open = x.t; ep++; } if (x.up === 1) { if (open != null) last = { from: open, to: x.t }; open = null; } }
  return { known: k.length, up: k.filter((x) => x.up === 1).length, outages: ep, down_since: open, last_outage: last };
}
function latencyAnomaly(s, cur) {
  const L = s.map((x) => x.lat).filter((v) => v != null);
  if (cur == null || L.length < 36) return { learning: L.length < 36 ? 'needs 36 samples (3 hours) - has ' + L.length : null };
  const m = median(L), mad = median(L.map((v) => Math.abs(v - m))) || 0, z = (cur - m) / Math.max(1.4826 * mad, 2);
  return { usual: r1(m), z: r1(z), unusual: z >= 3 && cur - m >= 20 };
}

function analyse(ev, hist = {}, cfg = {}, now = Date.now()) {
  const sla = cfg.sla_target_pct || 99.5;
  const site = (id) => ev.sites.find((s) => s.id === id);
  const N = new Map(ev.nodes.map((n) => [n.id, n]));
  const nodesOf = (sid) => ev.nodes.filter((n) => n.site === sid).map((n) => n.id);
  const dcT = [].concat(...ev.sites.filter((s) => s.kind === 'dc').map((s) => nodesOf(s.id)));
  const drT = [].concat(...ev.sites.filter((s) => s.kind === 'dr').map((s) => nodesOf(s.id)));
  const isDcSite = (x) => x.kind === 'dc', allUp = () => true, provenOk = (l) => UPS.has(l.state), possibleOk = (l) => l.state !== 'down';
  const branches = [];
  for (const s of ev.sites) {
    const mine = new Set(nodesOf(s.id)), hub = s.kind === 'dc' || s.kind === 'dr';
    // a hub's own WAN view is its internet / hub-to-hub links: a branch's tunnel into the hub belongs to that branch
    const branchSide = (l) => { const o = N.get(mine.has(l.a) ? l.b : l.a) || {}, os = o.site && site(o.site); return !!os && os.kind !== 'dc' && os.kind !== 'dr'; };
    const wan = ev.links.filter((l) => (mine.has(l.a) !== mine.has(l.b)) && (WAN.has(l.kind) || (N.get(l.a) || {}).site !== (N.get(l.b) || {}).site) && !(hub && branchSide(l))).map((l) => {
      const inner = mine.has(l.a) ? l.a : l.b, outer = inner === l.a ? l.b : l.a, o = N.get(outer) || {};
      return { id: l.id, kind: l.kind, isp: l.isp, circuit: l.circuit, capacity_mbps: l.capacity_mbps, state: l.state, why: l.why, util: l.util, lat: l.lat, jitter: l.jitter, loss: l.loss,
        edge: (N.get(inner) || {}).label || inner, edge_id: inner, to: o.label || outer, to_site: o.site ? ((site(o.site) || {}).name || o.site) : (VIRT.has(o.kind) ? o.label : '') };
    });
    const from = [...mine], proven = walk(ev, from, provenOk), possible = walk(ev, from, possibleOk);
    // the DR site must be reachable WITHOUT the data centre - a path that hairpins through the DC is gone when the DC is
    const noDc = new Set(isDcSite(s) ? [] : dcT), provenDr = walk(ev, from, provenOk, noDc), possibleDr = walk(ev, from, possibleOk, noDc), design0 = walk(ev, from, allUp, noDc);
    const isDc = isDcSite(s), isDr = s.kind === 'dr';
    const dc = isDc ? 'self' : reachTo(proven, possible, dcT), dr = isDr ? 'self' : reachTo(provenDr, possibleDr, drT);
    const measured = wan.filter((w) => w.state !== 'unmeasured'), lost = wan.filter((w) => w.state === 'down'), weak = wan.filter((w) => w.state === 'degraded' || w.state === 'critical');
    const anyNodeDown = from.some((id) => (N.get(id) || {}).state === 'down');
    let health, why;
    if (!from.length) { health = 'unmeasured'; why = 'no node on the map is in this site'; }
    else if (dc === 'no') { health = 'down'; why = 'cannot reach the data centre' + (lost.length ? ': ' + lost.map((w) => w.kind + ' to ' + w.to + (w.circuit ? ' (' + w.circuit + ')' : '') + ' down').join(', ') : anyNodeDown ? ': a device at the site is down' : ''); }
    else if (dr === 'no' && drT.length) { health = 'partial'; why = 'reaches the data centre but not the DR site'; }
    else if (!measured.length && !(isDc || isDr)) { health = 'unmeasured'; why = wan.length ? 'no WAN link here is measured - name an interface, tunnel or SD-WAN member on the route map' : 'no WAN link on the map for this site'; }
    else if (lost.length) { health = 'backup'; why = lost.map((w) => (w.isp ? w.isp + ' ' : '') + w.kind + ' to ' + w.to + (w.circuit ? ' (' + w.circuit + ')' : '') + ' down').join(', ') + ' - traffic is on the remaining path'; }
    else if (weak.length) { health = 'degraded'; why = weak.map((w) => w.kind + ' to ' + w.to + ': ' + w.why).join('; '); }
    else if (dc === 'unproven' && !isDc) { health = 'unmeasured'; why = 'the path to the data centre goes through links nobody measures'; }
    else { health = 'ok'; why = 'every WAN path up' + (dc === 'yes' ? ', reaches the data centre' : '') + (dr === 'yes' ? ' and the DR site' : ''); }
    const lats = measured.map((w) => w.lat).filter((v) => v != null), best = lats.length ? Math.min(...lats) : null;
    const losses = measured.map((w) => w.loss).filter((v) => v != null), utils = measured.map((w) => w.util).filter((v) => v != null);
    // resilience design (with everything up)
    const design = [];
    if (!isDc && from.length) {
      if (wan.length === 1) design.push({ kind: 'single-path', text: 'one WAN path only - when it fails the site is cut off', fix: 'add a second link from a different ISP (SD-WAN or LTE backup)' });
      const named = wan.filter((w) => w.isp), isps = [...new Set(named.map((w) => w.isp))];
      if (named.length >= 2 && isps.length === 1) design.push({ kind: 'same-isp', text: 'both WAN paths are with ' + isps[0] + ' - one ISP outage takes both', fix: 'move one circuit to a different ISP' });
      const edges = [...new Set(wan.map((w) => w.edge_id))];
      if (wan.length >= 2 && edges.length === 1) design.push({ kind: 'single-edge', text: 'every WAN path ends on ' + wan[0].edge + ' - one device failure cuts the site off', fix: 'an HA pair, or the second link on a second edge device' });
      if (drT.length && !isDr && !drT.some((t) => design0.has(t))) design.push({ kind: 'no-dr-route', text: 'no route to the DR site even with everything up', fix: 'add the DR tunnel / SD-WAN path, or the link on the route map if it exists' });
      if (!drT.length && !isDr) design.push({ kind: 'no-dr-site', text: 'no DR site on the route map - DR reachability cannot be checked', fix: 'add the DR site (kind dr) on the WAN / LAN route map' });
    }
    const h = hist[s.id] || [], rel = reliability(h), an = latencyAnomaly(h, best);
    const inc = (ev.incidents || []).filter((x) => !x.covered_by && (x.site === s.id || mine.has(x.node) || wan.some((w) => w.id === x.link)));
    branches.push({ id: s.id, name: s.name, kind: s.kind, city: s.city || '', health, why, dc, dr, wan, wan_up: wan.filter((w) => UPS.has(w.state)).length, wan_total: wan.length,
      latency_ms: best, loss_pct: losses.length ? Math.max(...losses) : null, util_pct: utils.length ? Math.max(...utils) : null, users: s.users || 0,
      design, reliability: rel, latency: an, incidents: inc.map((x) => ({ id: x.id, kind: x.kind, severity: x.severity, title: x.title, first: x.first, acked_by: x.acked_by || null, fix: x.fix || [] })) });
  }
  branches.sort((a, b) => RANKH[b.health] - RANKH[a.health] || (b.kind === 'branch') - (a.kind === 'branch') || a.name.localeCompare(b.name));
  // ISP scorecard from the link samples
  const lh = hist._links || {}, isp = {}, seenL = new Set();
  // a circuit is counted once, from the branch end (the DC end sees every branch's link too)
  for (const b of branches.slice().sort((x, y) => (x.kind === 'dc') - (y.kind === 'dc'))) for (const w of b.wan) {
    if (seenL.has(w.id)) continue; seenL.add(w.id);
    const key = w.isp || '(ISP not named)', g = isp[key] || (isp[key] = { isp: key, links: 0, known: 0, up: 0, outages: 0, down_now: 0, sites: new Set(), circuits: [] });
    const e = linkEpisodes((lh[w.id] || {}).s || []);
    g.links++; g.known += e.known; g.up += e.up; g.outages += e.outages; if (w.state === 'down') g.down_now++; g.sites.add(b.name);
    g.circuits.push({ link: w.id, site: b.name, circuit: w.circuit, state: w.state, outages: e.outages, availability: e.known >= 12 ? r1(e.up / e.known * 100) : null, down_since: e.down_since });
  }
  const isps = Object.values(isp).map((g) => { const av = g.known >= 12 ? r1(g.up / g.known * 100) : null; return { isp: g.isp, links: g.links, sites: g.sites.size, outages: g.outages, down_now: g.down_now, availability: av, below_sla: av != null && av < sla, circuits: g.circuits }; })
    .sort((a, b) => (b.below_sla - a.below_sla) || (b.down_now - a.down_now) || (b.outages - a.outages) || a.isp.localeCompare(b.isp));
  const br = branches.filter((b) => b.kind !== 'dc');
  const cnt = (h) => br.filter((b) => b.health === h).length;
  const kpis = { sites: branches.length, ok: cnt('ok'), down: cnt('down'), partial: cnt('partial'), backup: cnt('backup'), degraded: cnt('degraded'), unmeasured: cnt('unmeasured'),
    wan_up: br.reduce((a, b) => a + b.wan_up, 0), wan_total: br.reduce((a, b) => a + b.wan_total, 0),
    worst_latency: Math.max(0, ...br.map((b) => b.latency_ms || 0)) || null, design: br.reduce((a, b) => a + b.design.length, 0),
    flapping: br.filter((b) => b.reliability.flapping).length, isp_below_sla: isps.filter((x) => x.below_sla).length,
    availability: (() => { const v = br.map((b) => b.reliability.availability).filter((x) => x != null); return v.length ? r1(v.reduce((a, x) => a + x, 0) / v.length) : null; })() };
  const actions = [];
  const add = (priority, title, detail, filter, count) => actions.push({ priority, title, detail, filter, count });
  const names = (L) => L.slice(0, 4).map((b) => b.name).join(', ') + (L.length > 4 ? ' +' + (L.length - 4) : '');
  const L = (h) => br.filter((b) => b.health === h);
  if (L('down').length) add(100, L('down').length + ' site(s) cannot reach the data centre', names(L('down')) + ' - users there cannot issue policies or settle claims. Check the edge device and both circuits; call the ISPs with the drafted ticket.', 'down', L('down').length);
  if (L('partial').length) add(85, L('partial').length + ' site(s) reach the DC but not the DR site', names(L('partial')) + ' - a DR failover would cut them off. Check the DR tunnel / SD-WAN path.', 'partial', L('partial').length);
  if (L('backup').length) add(75, L('backup').length + ' site(s) running on fewer paths', names(L('backup')) + ' - one more failure cuts them off. Raise the lost circuit with the ISP (draft on the site).', 'backup', L('backup').length);
  const below = isps.filter((x) => x.below_sla); if (below.length) add(65, below.length + ' ISP(s) below the ' + sla + ' % availability target', below.map((x) => x.isp + ' ' + x.availability + ' %').join(', ') + ' over the samples kept - evidence for the service review.', 'isp', below.length);
  if (L('degraded').length) add(55, L('degraded').length + ' site(s) with a degraded path', names(L('degraded')) + ' - loss, latency or utilisation over the threshold.', 'degraded', L('degraded').length);
  const unus = br.filter((b) => b.latency.unusual); if (unus.length) add(50, 'Latency unusual at ' + unus.length + ' site(s)', unus.map((b) => b.name + ' ' + b.latency_ms + ' ms (usually ' + b.latency.usual + ')').join(', '), 'latency', unus.length);
  const fl = br.filter((b) => b.reliability.flapping); if (fl.length) add(45, fl.length + ' site(s) flapping', names(fl) + ' - the state changed 3+ times in the last 2 hours: an unstable circuit or a failover loop.', 'flapping', fl.length);
  const des = br.filter((b) => b.design.length); if (des.length) add(30, des.length + ' site(s) with a resilience gap', names(des) + ' - single path, one ISP, one edge device or no DR route.', 'design', des.length);
  if (L('unmeasured').length) add(20, L('unmeasured').length + ' site(s) not measured', names(L('unmeasured')) + ' - map their WAN links to an interface, tunnel or SD-WAN member on the route map.', 'unmeasured', L('unmeasured').length);
  actions.sort((a, b) => b.priority - a.priority);
  const configured = ev.sites.length > 0;
  return { configured, reason: configured ? null : 'No sites on the WAN / LAN route map yet - an administrator draws (or accepts the proposed) map on Network → WAN / LAN Route Map, then every site appears here.',
    at: now, kpis, branches, isps, actions, sla_target_pct: sla, dc_sites: ev.sites.filter((s) => s.kind === 'dc').map((s) => s.name), dr_sites: ev.sites.filter((s) => s.kind === 'dr').map((s) => s.name),
    polled: !!ev.polled, map_version: ev.version || 0,
    note: 'Measured from the route map and what the AI Network Engineer polls. Availability needs 12 samples (1 hour); latency "unusual" needs 3 hours. A link nobody measures is "not measured", never up.' };
}

function ispDraft(v, linkId, user, now = Date.now()) {
  for (const b of v.branches) for (const w of b.wan) {
    if (w.id !== linkId) continue;
    const g = v.isps.find((x) => x.circuits.some((c) => c.link === linkId)) || {}, c = (g.circuits || []).find((x) => x.link === linkId) || {};
    const since = c.down_since ? new Date(c.down_since).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : null;
    const lines = [
      'To: ' + (w.isp || '<ISP service desk>'),
      'Subject: ' + (w.state === 'down' ? 'Fault' : 'Service quality') + ' - circuit ' + (w.circuit || '<circuit id>') + (' - ' + ZYB_ORG.short + ' ') + b.name,
      '',
      'Site: ' + b.name + (b.city ? ' (' + b.city + ')' : ''),
      'Circuit: ' + (w.circuit || '<circuit id not on the route map>') + ' · ' + w.kind + (w.capacity_mbps ? ' · ' + w.capacity_mbps + ' Mb/s contracted' : ''),
      'State now: ' + w.state + (since ? ' since ' + since : ''),
      'What we measure: ' + (w.why || '-'),
      [w.loss != null ? 'loss ' + w.loss + ' %' : null, w.lat != null ? 'latency ' + w.lat + ' ms' : null, w.jitter != null ? 'jitter ' + w.jitter + ' ms' : null, w.util != null ? 'utilisation ' + w.util + ' %' : null].filter(Boolean).join(' · ') || 'no quality figures reported for this path',
      'Outages in the last 7 days on this circuit: ' + (c.outages || 0) + (c.availability != null ? ' · availability ' + c.availability + ' %' : ''),
      '',
      'Please open a fault ticket, confirm the circuit status from your side and give us an estimated restoration time.',
      '',
      'Raised by ' + user + (' from the ' + ZYB_ORG.short + ' platform (Branch Connectivity), ') + new Date(now).toISOString().slice(0, 16).replace('T', ' ') + ' UTC.',
    ];
    return { link: linkId, site: b.name, isp: w.isp || null, circuit: w.circuit || null, text: lines.join('\n'), note: 'A draft - nothing was sent. Check it and send it from your mailbox or the ISP portal.' };
  }
  throw bad('there is no WAN link "' + linkId + '" on a site', 404);
}

function createBranches({ routemap, state, now } = {}) {
  const NOW = now || Date.now;
  const sC = state.collection('branchnet_samples'), cfgC = state.collection('branchnet_cfg');
  const cfg = () => Object.assign({ sla_target_pct: 99.5 }, cfgC.get('cfg') || {});
  const hist = () => { const h = { _links: {} }; for (const r of sC.all()) { if (r.id.startsWith('link:')) h._links[r.id.slice(5)] = r; else h[r.id] = r.s || []; } return h; };
  const view = () => analyse(routemap.evaluate({}), hist(), cfg(), NOW());
  function record() {
    const t = NOW(), v = analyse(routemap.evaluate({}), hist(), cfg(), t), cut = t - KEEP;
    const push = (id, x, extra) => { const r = sC.get(id) || Object.assign({ id, s: [] }, extra); r.s = r.s.filter((y) => y.t >= cut); const l = r.s[r.s.length - 1]; if (l && t - l.t < SLOT / 2) return; r.s.push(x); if (r.s.length > MAXS) r.s = r.s.slice(-MAXS); sC.put(r); };
    let n = 0;
    for (const b of v.branches) {
      push(b.id, { t, h: b.health, dc: b.dc === 'yes' || b.dc === 'self' ? 1 : b.dc === 'no' ? 0 : null, lat: b.latency_ms }); n++;
      for (const w of b.wan) push('link:' + w.id, { t, up: UPS.has(w.state) ? 1 : w.state === 'down' ? 0 : null }, { isp: w.isp || null });
    }
    const live = new Set(v.branches.map((b) => b.id).concat(...v.branches.map((b) => b.wan.map((w) => 'link:' + w.id))));
    for (const r of sC.all()) if (!live.has(r.id) && !(r.s || []).some((y) => y.t >= cut)) sC.remove(r.id);
    return n;
  }
  function detail(id) {
    const v = view(), b = v.branches.find((x) => x.id === id); if (!b) throw bad('there is no site "' + id + '" on the route map', 404);
    const s = hist()[id] || [], hours = {};
    for (const x of s) { const k = Math.floor(x.t / 3600000); const H = hours[k] || (hours[k] = { t: k * 3600000, worst: 'ok', lat: [] }); if (RANKH[x.h] > RANKH[H.worst]) H.worst = x.h; if (x.lat != null) H.lat.push(x.lat); }
    const strip = Object.values(hours).sort((a, c) => a.t - c.t).map((H) => ({ t: H.t, worst: H.worst, lat: H.lat.length ? r1(median(H.lat)) : null }));
    return Object.assign({}, b, { strip, isps: v.isps.filter((g) => g.circuits.some((c) => b.wan.some((w) => w.id === c.link))), sla_target_pct: v.sla_target_pct });
  }
  function setConfig(c, user) { const next = Object.assign({}, cfg(), c, { id: 'cfg', updated_by: user, updated_at: NOW() }); cfgC.put(next); return next; }
  let timer = null;
  function start({ firstMs = 120000, everyMs = SLOT } = {}) {
    stop();
    const run = guardJob('netops.branches.record', record);
    const loop = async () => { try { await run(); } finally { timer = setTimeout(loop, everyMs); if (timer.unref) timer.unref(); } };
    timer = setTimeout(loop, firstMs); if (timer.unref) timer.unref();
  }
  function stop() { if (timer) clearTimeout(timer); timer = null; }
  return { view, record, detail, draft: (link, user) => ispDraft(view(), link, user, NOW()), config: cfg, setConfig, start, stop };
}

module.exports = { createBranches, analyse, reliability, linkEpisodes, latencyAnomaly, ispDraft, walk };
