// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Hyper-V VIRTUAL NETWORK MAP ({P} = /api/itam). Read from what each Hyper-V host REPORTS (install/hyperv-report.ps1 - read-only:
 * Get-VMSwitch / Get-VMSwitchTeam / Get-NetAdapter -Physical / Get-VMNetworkAdapter -All / Get-VMNetworkAdapterVlan); the platform
 * never logs on to a host and changes nothing.
 *   map        per host: virtual switches (external / internal / private), their uplinks (SET or NIC team) with link state and
 *              speed, the management-OS adapters, every VM adapter with its switch, VLAN (access / trunk / untagged), MAC and IPs
 *   baseline   hosts are grouped by name (the name without its trailing number: HQPSUPERM01 + HQPSUPERM02 = HQPSUPERM) or by the
 *              site an administrator gives; the switches most hosts of a group have are its learned baseline - a host without one
 *              is where a VM live-migrated or failed over loses its network
 *   findings   (each says why and what to do) uplink down, an external switch with one uplink (no redundancy), uplinks of mixed
 *              speed, a link under 1 Gbps, a running VM's adapter on no switch, the management OS untagged on the switch the VMs
 *              use (NCA ECC 2-5 segmentation), VM adapters in trunk mode, a MAC or an IP on two adapters, a missing baseline switch
 *   vlans      VLAN x host matrix with the VM adapters on each
 *   trace      one VM: adapter -> VLAN -> virtual switch -> uplinks -> link, with the other VMs on its VLAN
 *   changes    what changed between two reports of a host (switch added / removed, uplinks, a VM adapter's switch or VLAN)
 *   GET /hyperv/network               viewer
 *   GET /hyperv/network/trace?vm=     viewer
 */
const DAY = 86400000;
const s = (v, m = 200) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, m);
const n = (v, max = 1e9) => { const x = Number(v); return v != null && v !== '' && Number.isFinite(x) && x >= 0 && x <= max ? x : null; };
const lc = (x) => String(x || '').toLowerCase();
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const mac = (m) => { const x = s(m, 40).replace(/[^0-9a-f]/gi, '').toUpperCase(); return x.length === 12 ? x.match(/../g).join('-') : ''; };
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

// the network part of a host report (tolerant: what a host does not send stays empty, never invented)
function normNetwork(raw) {
  const b = raw && typeof raw === 'object' ? raw : null; if (!b) return null;
  const arr = (x, k) => (Array.isArray(x) ? x : (x && typeof x === 'object') || (typeof x === 'string' && x) ? [x] : []).slice(0, k);   // ConvertTo-Json sends a lone item as an object
  const physical = arr(b.physical, 64).map((p) => ({ name: s(p.name, 120), desc: s(p.desc, 200), status: s(p.status, 20), link_mbps: n(p.link_mbps, 1e6), mac: mac(p.mac) })).filter((p) => p.name);
  const switches = arr(b.switches, 64).map((w) => ({ name: s(w.name, 120), type: lc(s(w.type, 20)) || 'external', mgmt_os: !!w.mgmt_os, set: !!w.set, uplinks: arr(w.uplinks, 16).map((u) => s(u, 200)).filter(Boolean) })).filter((w) => w.name);
  const adapters = arr(b.adapters, 4000).map((a) => {
    const mode = lc(s(a.vlan_mode, 20));
    return { vm: s(a.vm, 200), mgmt_os: !!a.mgmt_os, name: s(a.name, 120), switch: s(a.switch, 120), mac: mac(a.mac), status: s(a.status, 40),
      ips: arr(a.ips, 16).map((x) => s(x, 15)).filter((x) => IPV4.test(x)), mode: mode === 'access' || mode === 'trunk' ? mode : mode === 'untagged' || !mode ? 'untagged' : mode,
      vlan: n(a.vlan, 4094), allowed: s(a.allowed, 200), native: n(a.native, 4094) };
  }).filter((a) => a.vm || a.mgmt_os);
  return { switches, physical, adapters };
}

const groupOf = (name, sites) => { const h = lc(name); if (sites && sites[h]) return s(sites[h], 80); const g = h.split('.')[0].replace(/[-_]?\d+$/, ''); return g || h; };
const vlanOf = (a) => a.mode === 'access' && a.vlan ? String(a.vlan) : a.mode === 'trunk' ? 'trunk' : 'untagged';
const sig = (net) => {
  const m = new Map();
  for (const w of net.switches) m.set('switch:' + w.name, w.type + ' uplinks ' + w.uplinks.slice().sort().join(' + ') + (w.mgmt_os ? ' +management OS' : ''));
  for (const a of net.adapters) m.set('adapter:' + (a.mgmt_os ? 'management OS' : a.vm) + '/' + a.name, (a.switch || 'no switch') + ' VLAN ' + vlanOf(a));
  return m;
};
// what changed between two network reports of a host (for the change history)
function diff(prev, cur) {
  if (!prev || !cur) return [];
  const a = sig(prev), b = sig(cur), out = [];
  for (const [k, v] of b) if (!a.has(k)) out.push({ what: k, change: 'added', now: v }); else if (a.get(k) !== v) out.push({ what: k, change: 'changed', was: a.get(k), now: v });
  for (const [k, v] of a) if (!b.has(k)) out.push({ what: k, change: 'removed', was: v });
  return out.slice(0, 200);
}

function analyse(reports, o = {}) {
  const now = o.now || Date.now(), F = [], add = (severity, code, host, target, title, fix) => F.push({ severity, code, host, target, title, fix });
  const hosts = reports.filter((r) => r && r.host && r.host.network).map((r) => ({ name: r.host.name, at: r.at, stale: now - Date.parse(r.at) > DAY, group: groupOf(r.host.name, o.sites), net: r.host.network,
    vms: new Map((r.vms || []).map((v) => [lc(v.name), v])) })).sort((a, b) => a.name.localeCompare(b.name));
  const noNet = reports.filter((r) => r && r.host && !r.host.network).map((r) => r.host.name);
  // ---- per host
  const macs = new Map(), ips = new Map();
  for (const h of hosts) {
    const phy = new Map(h.net.physical.map((p) => [lc(p.desc), p])), phyByName = new Map(h.net.physical.map((p) => [lc(p.name), p]));
    h.switches = h.net.switches.map((w) => {
      const up = w.uplinks.map((u) => phy.get(lc(u)) || phyByName.get(lc(u)) || { name: u, desc: u, status: 'unknown', link_mbps: null });
      const ad = h.net.adapters.filter((a) => lc(a.switch) === lc(w.name));
      return Object.assign({}, w, { uplinks: up, vm_adapters: ad.filter((a) => !a.mgmt_os).length, mgmt_adapters: ad.filter((a) => a.mgmt_os).map((a) => ({ name: a.name, vlan: vlanOf(a), ips: a.ips })),
        vlans: [...new Set(ad.filter((a) => !a.mgmt_os).map(vlanOf))].sort() });
    });
    for (const w of h.switches) {
      if (w.type !== 'external') continue;
      for (const u of w.uplinks) if (lc(u.status) !== 'up') add('high', 'uplink-down', h.name, w.name + ' / ' + (u.name || u.desc), 'Uplink ' + (u.name || u.desc) + ' of switch ' + w.name + ' is ' + (u.status || 'not up'), 'Check the cable, the switch port and the NIC; while it is down the VMs on ' + w.name + ' run on the remaining uplinks only');
      const live = w.uplinks.filter((u) => lc(u.status) === 'up');
      if (w.vm_adapters && w.uplinks.length === 1) add('medium', 'single-uplink', h.name, w.name, 'Switch ' + w.name + ' carries ' + w.vm_adapters + ' VM adapter(s) over ONE uplink - no redundancy', 'Add a second NIC to a Switch Embedded Team (New-VMSwitch -EnableEmbeddedTeaming, Add-VMSwitchTeamMember) - one cable or port takes the VMs off the network today');
      const sp = [...new Set(live.map((u) => u.link_mbps).filter((x) => x != null))];
      if (sp.length > 1) add('medium', 'mixed-speed', h.name, w.name, 'Uplinks of ' + w.name + ' run at different speeds (' + sp.map((x) => x >= 1000 ? x / 1000 + ' Gbps' : x + ' Mbps').join(' / ') + ')', 'A team balances across members - a slower member slows the VMs hashed to it; set the switch ports / NICs to the same speed');
      for (const u of live) if (u.link_mbps != null && u.link_mbps < 1000) add('medium', 'slow-link', h.name, w.name + ' / ' + u.name, 'Uplink ' + u.name + ' of ' + w.name + ' is linked at ' + u.link_mbps + ' Mbps', 'A server uplink under 1 Gbps is usually auto-negotiation or a cable fault - check both ends');
      const mg = w.mgmt_adapters.filter((m) => m.vlan === 'untagged');
      if (w.vm_adapters && mg.length) add('medium', 'mgmt-untagged', h.name, w.name, 'The management OS is UNTAGGED on ' + w.name + ', the switch the VMs use', 'Put the host management on its own VLAN (Set-VMNetworkAdapterVlan -ManagementOS -Access -VlanId <mgmt>) or its own NIC - management traffic separated from the VMs (NCA ECC 2-5)');
    }
    for (const a of h.net.adapters) {
      if (a.mgmt_os) continue;
      const vm = h.vms.get(lc(a.vm)), running = vm ? vm.state === 'running' : true;
      if (!a.switch && running) add('medium', 'not-connected', h.name, a.vm + ' / ' + a.name, 'VM ' + a.vm + ': network adapter ' + a.name + ' is on no virtual switch', 'Connect it (Connect-VMNetworkAdapter -VMName ... -SwitchName ...) or remove the adapter if it is not used');
      if (a.mode === 'trunk') add('low', 'trunk', h.name, a.vm + ' / ' + a.name, 'VM ' + a.vm + ' receives a VLAN trunk (' + (a.allowed || 'all VLANs') + ')', 'A trunk is for a firewall / router VM only - check it needs every VLAN in the list');
      if (a.mac) { const k = a.mac; (macs.get(k) || macs.set(k, []).get(k)).push(h.name + ' / ' + a.vm); }
      for (const ip of a.ips) (ips.get(ip) || ips.set(ip, []).get(ip)).push(h.name + ' / ' + a.vm);
    }
    const ints = h.switches.filter((w) => w.type !== 'external' && w.vm_adapters);
    for (const w of ints) add('low', 'isolated', h.name, w.name, w.vm_adapters + ' VM adapter(s) on the ' + w.type + ' switch ' + w.name + ' - no path to the physical network', 'Expected for a lab or a cluster heartbeat; otherwise move them to an external switch');
  }
  for (const [m, at] of macs) if (new Set(at).size > 1) add('high', 'dup-mac', at[0].split(' / ')[0], m, 'MAC ' + m + ' on ' + at.length + ' adapters: ' + at.slice(0, 4).join(', '), 'Duplicate MACs drop traffic at random - give the VMs dynamic MACs or widen the host MAC pools (Set-VMHost -MacAddressMinimum/-Maximum) so they do not overlap');
  for (const [ip, at] of ips) if (new Set(at).size > 1) add('high', 'dup-ip', at[0].split(' / ')[0], ip, 'IP ' + ip + ' on ' + at.length + ' VMs: ' + at.slice(0, 4).join(', '), 'An IP conflict - fix the static address or the DHCP reservation');
  // ---- the per-group baseline learned from the hosts: the external switches most hosts of a group have
  const groups = new Map(); for (const h of hosts) (groups.get(h.group) || groups.set(h.group, []).get(h.group)).push(h);
  const baselines = [];
  for (const [g, L] of groups) {
    if (L.length < 2) { baselines.push({ group: g, hosts: L.map((h) => h.name), switches: [], note: 'one host - no baseline to compare' }); continue; }
    const cnt = new Map(); for (const h of L) for (const w of new Set(h.switches.filter((x) => x.type === 'external').map((x) => x.name))) cnt.set(w, (cnt.get(w) || 0) + 1);
    const base = [...cnt.entries()].filter(([, c]) => c / L.length > 0.5).map(([w]) => w).sort();
    baselines.push({ group: g, hosts: L.map((h) => h.name), switches: base });
    for (const h of L) { const have = new Set(h.switches.map((x) => x.name)); for (const w of base) if (!have.has(w)) add('high', 'baseline', h.name, w, h.name + ' has no switch "' + w + '" that ' + cnt.get(w) + ' of ' + L.length + ' hosts of ' + g + ' have', 'A VM moved or failed over to ' + h.name + ' from another host of ' + g + ' loses its network - create the switch with the same name on the same uplinks'); }
    // VLANs VMs use on one host of the group and no other host has a VM adapter for (informational: live migration keeps the VLAN setting on the adapter)
  }
  // ---- VLAN matrix
  const vl = new Map();
  for (const h of hosts) for (const a of h.net.adapters) { if (a.mgmt_os) continue; const v = vlanOf(a); const x = vl.get(v) || vl.set(v, { vlan: v, hosts: {}, adapters: 0, vms: new Set() }).get(v); x.hosts[h.name] = (x.hosts[h.name] || 0) + 1; x.adapters++; x.vms.add(a.vm); }
  const vlans = [...vl.values()].map((x) => ({ vlan: x.vlan, hosts: x.hosts, adapters: x.adapters, vms: x.vms.size })).sort((a, b) => (isNaN(a.vlan) ? 1e5 : +a.vlan) - (isNaN(b.vlan) ? 1e5 : +b.vlan));
  const SEV = { high: 3, medium: 2, low: 1 }; F.sort((a, b) => SEV[b.severity] - SEV[a.severity] || a.host.localeCompare(b.host));
  const allAd = hosts.flatMap((h) => h.net.adapters);
  const kpis = { hosts: hosts.length, switches: hosts.reduce((t, h) => t + h.switches.length, 0), vm_adapters: allAd.filter((a) => !a.mgmt_os).length, vlans: vlans.filter((v) => /^\d+$/.test(v.vlan)).length,
    uplinks: hosts.reduce((t, h) => t + h.switches.reduce((u, w) => u + w.uplinks.length, 0), 0), uplinks_down: F.filter((f) => f.code === 'uplink-down').length,
    high: F.filter((f) => f.severity === 'high').length, findings: F.length, untagged: allAd.filter((a) => !a.mgmt_os && a.mode === 'untagged').length };
  const ins = [];
  if (!hosts.length) ins.push(noNet.length ? noNet.length + ' Hyper-V host(s) report, but not their virtual network yet - update the report script on them (Hyper-V Servers > Add Hyper-V hosts gives the current command).' : 'No Hyper-V host reports yet - add the hosts on the Hyper-V Servers page.');
  else {
    const bad = F.filter((f) => f.code === 'baseline'); if (bad.length) ins.push(bad.length + ' switch(es) missing against the learned baseline of their host group - live migration to those hosts would cut VMs off.');
    const one = F.filter((f) => f.code === 'single-uplink'); if (one.length) ins.push(one.length + ' VM switch(es) hang on a single uplink - one cable away from an outage.');
    const mg = F.filter((f) => f.code === 'mgmt-untagged'); if (mg.length) ins.push('Host management shares the VM switch untagged on ' + mg.length + ' switch(es) - separate it with its own VLAN.');
    if (kpis.untagged) ins.push(kpis.untagged + ' VM adapter(s) are untagged - they land on the uplink\'s native VLAN; tag them so every VM sits in a known network segment.');
    if (!F.length) ins.push('Every host matches its group, every VM switch has redundant uplinks up, no duplicates found.');
  }
  return { at: new Date(now).toISOString(), kpis, insights: ins, findings: F.slice(0, 500), baselines, vlans,
    hosts: hosts.map((h) => ({ name: h.name, group: h.group, at: h.at, stale: h.stale, switches: h.switches, physical: h.net.physical,
      adapters: h.net.adapters.map((a) => ({ vm: a.vm, mgmt_os: a.mgmt_os, name: a.name, switch: a.switch, vlan: vlanOf(a), mode: a.mode, allowed: a.allowed, mac: a.mac, ips: a.ips, status: a.status, state: a.mgmt_os ? '' : ((h.vms.get(lc(a.vm)) || {}).state || '') })) })),
    without_network: noNet,
    note: 'From each Hyper-V host\'s own read-only report (every 15 minutes). Hosts are grouped by name without its number, or by the site an administrator sets. Nothing is changed from here.' };
}

function trace(view, vmName) {
  const v = lc(vmName); const out = [];
  for (const h of view.hosts) for (const a of h.adapters) {
    if (a.mgmt_os || lc(a.vm) !== v) continue;
    const w = h.switches.find((x) => lc(x.name) === lc(a.switch));
    const peers = h.adapters.filter((b) => !b.mgmt_os && lc(b.vm) !== v && b.switch === a.switch && b.vlan === a.vlan).map((b) => b.vm);
    const elsewhere = view.hosts.filter((x) => x !== h && x.adapters.some((b) => !b.mgmt_os && b.vlan === a.vlan)).map((x) => x.name);
    const steps = [{ hop: 'VM', name: a.vm, detail: (a.state || '') + (a.ips.length ? ' · ' + a.ips.join(', ') : '') }, { hop: 'Adapter', name: a.name, detail: (a.mac || '') + (a.status ? ' · ' + a.status : '') },
      { hop: 'VLAN', name: a.vlan === 'untagged' ? 'untagged (native VLAN of the uplink)' : a.vlan === 'trunk' ? 'trunk ' + (a.allowed || '') : 'VLAN ' + a.vlan, detail: peers.length + ' other VM(s) here' + (elsewhere.length ? ', also on ' + elsewhere.join(', ') : '') },
      { hop: 'Virtual switch', name: a.switch || '(none)', detail: w ? w.type + (w.set ? ' · Switch Embedded Team' : '') + (w.mgmt_os ? ' · shared with management OS' : '') : 'the adapter is not connected' }];
    if (w && w.type === 'external') for (const u of w.uplinks) steps.push({ hop: 'Uplink', name: u.name || u.desc, detail: (u.status || '?') + (u.link_mbps != null ? ' · ' + (u.link_mbps >= 1000 ? u.link_mbps / 1000 + ' Gbps' : u.link_mbps + ' Mbps') : ''), bad: lc(u.status) !== 'up' });
    else steps.push({ hop: 'Physical network', name: 'none', detail: w ? 'an ' + w.type + ' switch does not reach the physical network' : 'not connected', bad: true });
    out.push({ host: h.name, adapter: a.name, steps, peers: peers.slice(0, 50) });
  }
  if (!out.length) throw httpErr(404, 'vm: no reported VM adapter named ' + s(vmName, 80));
  return { vm: vmName, paths: out };
}

function createHypervNetmap(app, opts = {}) {
  const now = opts.now || Date.now, C = (x) => app.store.collection(x);
  const changes = () => C('hv_netchanges');
  // called by the Hyper-V manager with a host's previous and new report: keep what changed (90 days)
  function onReport(prev, cur) {
    const p = prev && prev.host && prev.host.network, c = cur && cur.host && cur.host.network; if (!p || !c) return 0;
    const d = diff(p, c); if (!d.length) return 0;
    changes().put({ id: lc(cur.host.name) + '|' + cur.at, host: cur.host.name, at: cur.at, changes: d });
    for (const o of changes().all((x) => now() - Date.parse(x.at) > 90 * DAY)) changes().remove(o.id);
    return d.length;
  }
  const sites = () => { const m = app.store.collection('hv_settings').get('sites'); return (m && m.map) || {}; };
  function view() {
    const r = analyse(C('hv_latest').all(), { now: now(), sites: sites() });
    r.changes = changes().all().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 50);
    return r;
  }
  return { onReport, view, trace: (vm) => trace(view(), vm) };
}

function registerHypervNetmap(srv, app, X) {
  srv.route('GET', '/hyperv/network', (ctx) => { ctx.need('viewer'); return X.view(); });
  srv.route('GET', '/hyperv/network/trace', (ctx) => {
    ctx.need('viewer'); const vm = s((ctx.query || {}).vm, 200);
    if (!vm) throw httpErr(400, 'vm is required'); if (/[\u0000-\u001f]/.test(String((ctx.query || {}).vm))) throw httpErr(400, 'vm is not valid text');
    return X.trace(vm);
  });
}

module.exports = { createHypervNetmap, registerHypervNetmap, normNetwork, analyse, trace, diff, groupOf };
