// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Advanced Rogue Detection - every device on the organisation's LANs, joined by MAC address from what the platform already reads, and
 * the ones that should not be there. Nothing is polled here and nothing is changed on a device.
 *   sources   the switch port map (MAC per access port, the switch ARP table, VLAN names; the IEEE OUI list for the vendor),
 *             FortiGate DHCP leases and ARP table (read-only REST, collectors.js), and Genian NAC (status, host name). A device
 *             one source sees is still listed; each source's count is shown so a silent one is visible.
 *   risk      0-100, every point itemised: NAC refused / quarantined it, NAC has never seen it, a maker board (Raspberry Pi,
 *             Espressif ...) or a vendor the OUI list does not know, a private (randomised) MAC, behind a port with 3+ MACs (an
 *             unmanaged switch or hub), on a server / management VLAN, first seen in the last 24 h, moved ports twice in 24 h,
 *             no host name anywhere. >= 50 rogue, 25-49 suspicious, below that low.
 *   labels    an operator marks a device Trusted (a note is required), Guest for 1-30 days (it falls back when it expires and the
 *             expiry is said), or Suspect; in bulk too. Every label is audited. A label never hides the risk points.
 *   block     a proposal, never an action: the switch port the device is on becomes a port shut-down change plan (the port map's
 *             four-eyes task - a trunk is refused there). A device on no read switch port is refused with what to do instead.
 * PDPL: MAC, IP and host names identify people's devices - the list is analysts and above; a viewer sees the counts.
 */
const DAY = 86400000, HOUR = 3600000;
const low = (s) => String(s == null ? '' : s).toLowerCase();
const hex = (m) => { const h = low(m).replace(/[^0-9a-f]/g, ''); return h.length === 12 ? h : ''; };
const fmt = (h) => (h ? h.match(/../g).join(':') : '');
const randomised = (h) => h.length === 12 && /[26ae]/.test(h[1]);
const MAKER = /\b(raspberry|espressif|arduino|particle industries|tuya|shenzhen|hangzhou|seeed|beaglebone|banana pi|orange pi)\b/i;
const MGMT_VLAN = /\b(server|servers|srv|mgmt|management|infra|infrastructure|dc|datacent(er|re)|oob|core|ilo|idrac|ipmi)\b/i;
const LABELS = ['trusted', 'guest', 'suspect'];
const NAC_STATE = (s) => { const t = low(s); return /quarant|isolat/.test(t) ? 'quarantined' : /unauth|reject|deny|block|unknown|unreg|violat/.test(t) ? 'unauthorised' : /auth|permit|allow|registered|normal|online|ok/.test(t) ? 'authorised' : 'other'; };

function createRogue({ inventory, poller, state, portmap, now } = {}) {
  const clock = now || Date.now, LAB = state.collection('rogue_labels');
  const vendorOf = (h) => { try { return portmap && portmap.vendor ? portmap.vendor(h) : ''; } catch (e) { return ''; /* OUI list unreadable: vendor blank, said by ouiLoaded */ } };

  function collect() {
    const D = new Map(), src = { switch_ports: 0, switch_arp: 0, firewall_dhcp: 0, firewall_arp: 0, nac: 0 }, devs = inventory.list(), byId = new Map(devs.map((d) => [d.id, d]));
    const get = (h) => { let d = D.get(h); if (!d) { d = { mac: h, ips: new Set(), hosts: new Set(), seen: [], vlan: null, vlan_name: '', port: null, nac: null, first: null, last: null, moves_24h: 0, port_macs: 0, dhcp_vci: '' }; D.set(h, d); } return d; };
    let reads = [], macs = [];
    try { reads = state.collection('portmap_reads').all(); macs = state.collection('portmap_macs').all(); } catch (e) { reads = []; macs = []; /* port map not installed: other sources still answer */ }
    const t = clock(), perPort = new Map(), vlanOf = new Map();
    for (const r of reads) {
      const trunks = new Set(r.trunks || []);
      for (const m of r.macs || []) { const k = r.id + '|' + low(m.port); if (trunks.has(low(m.port)) || /^po/i.test(m.port)) continue; perPort.set(k, (perPort.get(k) || 0) + 1); vlanOf.set(m.mac, { vlan: m.vlan, name: (r.vlans || {})[m.vlan] || '' }); }
      for (const a of r.arp || []) { const h = hex(a.mac); if (!h) continue; get(h).ips.add(a.ip); src.switch_arp++; }
    }
    for (const m of macs) {
      const h = hex(m.id); if (!h) continue; const d = get(h), sw = byId.get(m.device);
      d.port = { switch_id: m.device, switch: sw ? sw.name : m.device, port: m.port, site: sw ? sw.site || '' : '' }; d.first = m.first; d.last = m.last;
      d.moves_24h = (m.moves || []).filter((x) => t - x.at <= DAY).length; d.port_macs = perPort.get(m.device + '|' + low(m.port)) || 0;
      const v = vlanOf.get(h); if (v) { d.vlan = v.vlan; d.vlan_name = v.name; }
      d.seen.push('switch port'); src.switch_ports++;
    }
    for (const dv of devs) {
      const s = poller.snapshot(dv.id); if (!s) continue;
      for (const l of s.dhcp || []) { const h = hex(l.mac); if (!h) continue; const d = get(h); if (l.ip) d.ips.add(l.ip); if (l.host) d.hosts.add(l.host); if (l.vci) d.dhcp_vci = l.vci; if (!d.seen.includes('firewall DHCP')) d.seen.push('firewall DHCP'); d.fw = dv.name; src.firewall_dhcp++; }
      for (const a of s.arp || []) { const h = hex(a.mac); if (!h) continue; const d = get(h); if (a.ip) d.ips.add(a.ip); if (!d.seen.includes('firewall ARP')) d.seen.push('firewall ARP'); d.fw = d.fw || dv.name; if (!d.iface) d.iface = a.iface; src.firewall_arp++; }
      for (const n of (s.nac && s.nac.items) || []) { const h = hex(n.mac); if (!h) continue; const d = get(h); if (n.ip) d.ips.add(n.ip); if (n.host) d.hosts.add(n.host); d.nac = { state: NAC_STATE(n.status), status: String(n.status || '').slice(0, 40) }; if (!d.seen.includes('NAC')) d.seen.push('NAC'); src.nac++; }
    }
    const nacOn = devs.some((d) => d.vendor === 'genian' && poller.snapshot(d.id));
    return { D, src, nacOn };
  }

  function score(d, nacOn, t) {
    const P = [], add = (pts, why) => P.push({ points: pts, why });
    if (d.nac && d.nac.state === 'unauthorised') add(30, 'NAC refused it (' + d.nac.status + ')');
    else if (d.nac && d.nac.state === 'quarantined') add(20, 'NAC quarantined it');
    else if (!d.nac && nacOn) add(15, 'NAC has never seen it');
    if (d.vendor && MAKER.test(d.vendor)) add(25, 'a maker board / IoT module (' + d.vendor + ')');
    else if (!d.vendor && !randomised(d.mac) && d.vendor_known) add(10, 'the OUI list does not know this vendor');
    if (randomised(d.mac)) add(10, 'a private (randomised) MAC - a phone or laptop, not a company-built device');
    if (d.port_macs >= 3) add(20, d.port_macs + ' MACs behind ' + d.port.switch + ' ' + d.port.port + ' - an unmanaged switch or hub');
    if (d.vlan_name && MGMT_VLAN.test(d.vlan_name)) add(25, 'on VLAN ' + d.vlan + ' ' + d.vlan_name + ' (servers / management)');
    if (d.first && t - d.first <= DAY) add(15, 'first seen in the last 24 hours');
    if (d.moves_24h >= 2) add(10, 'moved ports ' + d.moves_24h + ' times in 24 hours');
    if (!d.hosts.size) add(5, 'no host name from DHCP or NAC');
    return { risk: Math.min(100, P.reduce((s, x) => s + x.points, 0)), why: P };
  }

  function list() {
    const t = clock(), { D, src, nacOn } = collect(), ouiOk = portmap && portmap.ouiLoaded ? portmap.ouiLoaded() : false, out = [];
    for (const d of D.values()) {
      d.vendor = vendorOf(d.mac); d.vendor = /private|unknown vendor/.test(d.vendor) ? '' : d.vendor; d.vendor_known = ouiOk;
      const S = score(d, nacOn, t), L = LAB.get(d.mac);
      let cls, label = null, note = '';
      if (L && L.label === 'guest' && L.until && L.until < t) note = 'guest access expired ' + new Date(L.until).toISOString().slice(0, 10);
      else if (L) label = L;
      if (label) cls = label.label;
      else if (d.nac && d.nac.state === 'authorised') cls = 'trusted';
      else cls = S.risk >= 50 ? 'rogue' : S.risk >= 25 ? 'suspicious' : 'unverified';
      out.push({ mac: fmt(d.mac), class: cls, risk: S.risk, why: S.why, trusted_by: label ? 'label' : cls === 'trusted' ? 'NAC' : null, label: label ? { label: label.label, by: label.by, at: label.at, until: label.until || null, note: label.note || '' } : null, note,
        vendor: d.vendor || (ouiOk ? 'unknown vendor' : ''), randomised: randomised(d.mac), ips: [...d.ips].slice(0, 6), hosts: [...d.hosts].slice(0, 4), port: d.port, vlan: d.vlan, vlan_name: d.vlan_name, port_macs: d.port_macs,
        nac: d.nac, firewall: d.fw || '', iface: d.iface || '', seen_by: d.seen, first: d.first, last: d.last, dhcp_vci: d.dhcp_vci, can_block: !!d.port });
    }
    out.sort((a, b) => b.risk - a.risk);
    return { out, src, nacOn, ouiOk };
  }

  function view(role) {
    const { out, src, nacOn, ouiOk } = list(), n = (c) => out.filter((x) => x.class === c).length;
    const kpis = { devices: out.length, rogue: n('rogue'), suspicious: n('suspicious'), unverified: n('unverified'), trusted: n('trusted'), guest: n('guest'), suspect: n('suspect'), expired_guests: out.filter((x) => x.note).length, unmanaged_ports: new Set(out.filter((x) => x.port_macs >= 3).map((x) => x.port.switch_id + x.port.port)).size };
    const base = { generated_at: new Date(clock()).toISOString(), kpis, sources: src, nac_connected: nacOn, oui_loaded: ouiOk,
      note: 'Risk is a set of reasons to look, each itemised - not proof a device is hostile. Blocking is a change plan a second person approves.' };
    if (role === 'viewer') return Object.assign(base, { devices: [], private: true });
    return Object.assign(base, { devices: out.slice(0, 3000), private: false });
  }

  function setLabel(macs, b, who) {
    const t = clock(), seen = new Set(list().out.map((x) => hex(x.mac))), done = [];
    for (const m of macs) {
      const h = hex(m); if (!h) throw Object.assign(new Error('mac ' + m + ' is not a MAC address'), { status: 400 });
      if (!seen.has(h)) throw Object.assign(new Error('mac ' + fmt(h) + ' is not on the network as last read'), { status: 404 });
    }
    for (const m of macs) {
      const h = hex(m), was = LAB.get(h);
      if (b.label === 'clear') { if (was) LAB.remove(h); done.push({ mac: fmt(h), from: was ? was.label : null, to: null }); continue; }
      LAB.put({ id: h, label: b.label, until: b.label === 'guest' ? t + b.days * DAY : null, note: b.note || '', by: who.user, at: t });
      done.push({ mac: fmt(h), from: was ? was.label : null, to: b.label });
    }
    return { changed: done };
  }

  function block(mac, reason, who) {
    const h = hex(mac); if (!h) throw Object.assign(new Error('mac is not a MAC address'), { status: 400 });
    const d = list().out.find((x) => hex(x.mac) === h); if (!d) throw Object.assign(new Error('mac ' + fmt(h) + ' is not on the network as last read'), { status: 404 });
    if (!d.port) throw Object.assign(new Error(fmt(h) + ' is not on a switch port the port map reads - block it in Genian NAC or with a firewall address object, by hand'), { status: 409 });
    if (!portmap || typeof portmap.propose !== 'function') throw Object.assign(new Error('the switch port map is not available on this engine'), { status: 503 });
    const r = portmap.propose({ device: d.port.switch_id, port: d.port.port, type: 'port-shutdown', reason: '[rogue detection] ' + fmt(h) + (d.vendor ? ' (' + d.vendor + ')' : '') + ' risk ' + d.risk + ': ' + reason }, who, 'user');
    return Object.assign({ mac: fmt(h), switch: d.port.switch, port: d.port.port }, r);
  }
  return { view, list, setLabel, block, collect };
}

module.exports = { createRogue, LABELS, NAC_STATE, MAKER, MGMT_VLAN };
