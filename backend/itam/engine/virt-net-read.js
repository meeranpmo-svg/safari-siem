// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const X = require('./discovery/xml');
/*
 * Virtual networking as vCenter / ESXi and Nutanix Prism report it, normalised for the Virtual Network Map (virt-network.js).
 * Pure functions over what the read-only readers in virt-capacity.js fetched (vSphere RetrievePropertiesEx, Prism GET):
 *   {clusters[{id, name}], hosts[{id, name, cluster_id, state, maintenance, pnics[{device, mac, speed_mb|null, up, driver}],
 *     switches[{id, kind: standard|dvs|ovs, name, mtu, uplinks[], active[], standby[], security{promiscuous, mac_changes, forged}}],
 *     portgroups[{name, vlan, trunk, switch, security}], vmks[{device, portgroup, ip, mtu, services[]}]}],
 *    dvs[{id, uuid, name, mtu}], networks[{id, name, kind, vlan, trunk, switch}], vms[{id, name, host_id, power, nics[{network, mac,
 *    connected, ips[]}]}], read_errors[]}
 * A part that could not be read is listed in read_errors and its fields stay null - never shown as healthy.
 */
const kids = (n, name) => (n && n.children ? n.children.filter((c) => c.name === name) : []);
const txt = (n, name) => X.childText(n, name);
const bool = (v) => (v === 'true' ? true : v === 'false' ? false : null);
const num = (v) => (v === '' || v == null || !Number.isFinite(Number(v)) ? null : Number(v));
const after = (s, sep) => { const t = String(s || ''); const i = t.lastIndexOf(sep); return i >= 0 ? t.slice(i + sep.length) : t; };
const str = (v) => (typeof v === 'string' ? v : '');
function sec(pol) {
  const s = pol && X.child(pol, 'security'); if (!s) return null;
  return { promiscuous: bool(txt(s, 'allowPromiscuous')), mac_changes: bool(txt(s, 'macChanges')), forged: bool(txt(s, 'forgedTransmits')) };
}
function vlanOf(cfg) {
  const v = cfg && X.find(cfg, 'vlan'); if (!v) return { vlan: null, trunk: null };
  const id = X.child(v, 'vlanId'), pv = X.child(v, 'pvlanId');
  if (pv) return { vlan: num(pv.text.trim()), trunk: null, pvlan: true };
  const ranges = kids(v, 'vlanId').filter((x) => x.children.length).map((r) => [num(txt(r, 'start')), num(txt(r, 'end'))]);
  if (ranges.length) return { vlan: null, trunk: ranges };
  return { vlan: id ? num(id.text.trim()) : null, trunk: null };
}

function fromVsphere(R, errors) {
  const out = { kind: 'vsphere', clusters: [], hosts: [], dvs: [], networks: [], vms: [], read_errors: errors || [] };
  for (const c of R.clusters || []) out.clusters.push({ id: c._id, name: str(c.name) });
  const byHost = new Map();
  for (const h of R.hosts || []) { const x = { id: h._id, name: str(h.name), cluster_id: str(h.parent) || null, state: str(h['runtime.connectionState']) || null, maintenance: bool(str(h['runtime.inMaintenanceMode'])), pnics: null, switches: null, portgroups: null, vmks: null }; out.hosts.push(x); byHost.set(x.id, x); }
  for (const n of R.net || []) {
    const h = byHost.get(n._id); if (!h) continue;
    const pn = n['config.network.pnic'], vs = n['config.network.vswitch'], pg = n['config.network.portgroup'], vn = n['config.network.vnic'], px = n['config.network.proxySwitch'];
    h.pnics = X.findAll(pn && typeof pn === 'object' ? pn : null, 'PhysicalNic').map((p) => { const ls = X.child(p, 'linkSpeed'); return { device: txt(p, 'device'), mac: txt(p, 'mac').toLowerCase(), driver: txt(p, 'driver'), speed_mb: ls ? num(txt(ls, 'speedMb')) : null, up: !!ls }; });
    h.switches = X.findAll(vs && typeof vs === 'object' ? vs : null, 'HostVirtualSwitch').map((s) => {
      const sp = X.child(s, 'spec'), pol = sp && X.child(sp, 'policy'), team = pol && X.child(pol, 'nicTeaming'), order = team && X.child(team, 'nicOrder');
      return { id: 'vss:' + txt(s, 'name'), kind: 'standard', name: txt(s, 'name'), mtu: num(txt(s, 'mtu')), uplinks: kids(s, 'pnic').map((k) => after(k.text.trim(), 'PhysicalNic-')),
        active: order ? kids(order, 'activeNic').map((k) => k.text.trim()) : [], standby: order ? kids(order, 'standbyNic').map((k) => k.text.trim()) : [], security: sec(pol) };
    });
    for (const p of X.findAll(px && typeof px === 'object' ? px : null, 'HostProxySwitch')) {
      const pn2 = kids(p, 'pnic').map((k) => after(k.text.trim(), 'PhysicalNic-'));
      const bk = X.findAll(p, 'pnicDevice').map((k) => k.text.trim());
      h.switches.push({ id: 'dvs:' + txt(p, 'dvsUuid'), kind: 'dvs', name: txt(p, 'dvsName'), dvs_uuid: txt(p, 'dvsUuid'), mtu: num(txt(p, 'mtu')), uplinks: [...new Set(pn2.concat(bk))].filter(Boolean), active: [], standby: [], security: null });
    }
    h.portgroups = X.findAll(pg && typeof pg === 'object' ? pg : null, 'HostPortGroup').map((g) => { const sp = X.child(g, 'spec'); return { name: txt(sp, 'name'), vlan: num(txt(sp, 'vlanId')), trunk: num(txt(sp, 'vlanId')) === 4095 ? [[0, 4094]] : null, switch: 'vss:' + txt(sp, 'vswitchName'), security: sec(sp && X.child(sp, 'policy')) }; });
    h.vmks = X.findAll(vn && typeof vn === 'object' ? vn : null, 'HostVirtualNic').map((v) => { const sp = X.child(v, 'spec'), ip = sp && X.child(sp, 'ip'), dp = sp && X.child(sp, 'distributedVirtualPort');
      return { device: txt(v, 'device'), portgroup: txt(v, 'portgroup') || null, dvs_uuid: dp ? txt(dp, 'switchUuid') : null, dvpg_key: dp ? txt(dp, 'portgroupKey') : null, ip: ip ? txt(ip, 'ipAddress') || null : null, mask: ip ? txt(ip, 'subnetMask') || null : null, mtu: num(txt(sp, 'mtu')), services: [] }; });
  }
  for (const n of R.nicmgr || []) {
    const h = byHost.get(n._id); if (!h || !h.vmks) continue;
    for (const c of X.findAll(n['config.virtualNicManagerInfo.netConfig'] && typeof n['config.virtualNicManagerInfo.netConfig'] === 'object' ? n['config.virtualNicManagerInfo.netConfig'] : null, 'VirtualNicManagerNetConfig')) {
      const type = txt(c, 'nicType');
      for (const k of kids(c, 'selectedVnic')) { const dev = after(k.text.trim(), 'VirtualNic-'); const v = h.vmks.find((x) => x.device === dev); if (v && type && !v.services.includes(type)) v.services.push(type); }
    }
  }
  for (const d of R.dvs || []) out.dvs.push({ id: d._id, uuid: str(d['config.uuid']), name: str(d.name), mtu: num(str(d['config.maxMtu'])) });
  const dvpg = new Map();
  for (const g of R.dvpg || []) { const v = vlanOf(g['config.defaultPortConfig'] && typeof g['config.defaultPortConfig'] === 'object' ? g['config.defaultPortConfig'] : null), sw = out.dvs.find((x) => x.id === str(g['config.distributedVirtualSwitch']));
    dvpg.set(g._id, { id: g._id, name: str(g.name), kind: 'dvpg', vlan: v.vlan, trunk: v.trunk, pvlan: !!v.pvlan, uplink: str(g['config.uplink']) === 'true', switch: sw ? 'dvs:' + sw.uuid : null, switch_name: sw ? sw.name : null }); }
  for (const n of R.nets || []) { if (dvpg.has(n._id)) out.networks.push(dvpg.get(n._id)); else out.networks.push({ id: n._id, name: str(n.name), kind: 'standard' }); }
  for (const g of dvpg.values()) if (!out.networks.some((x) => x.id === g.id)) out.networks.push(g);
  for (const v of R.vms || []) {
    if (str(v['config.template']) === 'true') continue;
    const refs = kids(v.network && typeof v.network === 'object' ? v.network : null, 'ManagedObjectReference').map((r) => r.text.trim());
    const gn = X.findAll(v['guest.net'] && typeof v['guest.net'] === 'object' ? v['guest.net'] : null, 'GuestNicInfo').map((g) => ({ network: txt(g, 'network') || null, mac: txt(g, 'macAddress').toLowerCase() || null, connected: bool(txt(g, 'connected')), ips: kids(g, 'ipAddress').map((i) => i.text.trim()).filter((i) => i.includes('.')).slice(0, 8) }));
    out.vms.push({ id: v._id, name: str(v.name), host_id: str(v['runtime.host']) || null, power: /poweredOn/.test(str(v['runtime.powerState'])) ? 'on' : 'off', network_ids: refs, nics: gn, guest_read: gn.length > 0 });
  }
  return out;
}

function fromNutanix(R, errors) {
  const out = { kind: 'nutanix', clusters: [], hosts: [], dvs: [], networks: [], vms: [], read_errors: errors || [], vswitches: [] };
  const c = R.cluster || {}; out.clusters.push({ id: String(c.uuid || 'cluster'), name: String(c.name || 'Nutanix cluster') });
  for (const h of R.hosts || []) {
    const nics = (R.nics && R.nics[h.uuid]) || null;
    out.hosts.push({ id: String(h.uuid), name: String(h.name || ''), cluster_id: out.clusters[0].id, state: String(h.state || '').toLowerCase() === 'normal' ? 'connected' : String(h.state || '').toLowerCase() || null, maintenance: h.host_in_maintenance_mode == null ? null : !!h.host_in_maintenance_mode,
      pnics: nics ? nics.map((n) => { const kb = num(n.link_speed_in_kbps); const up = n.is_link_up != null ? !!n.is_link_up : n.link_detected != null ? !!n.link_detected : kb != null ? kb > 0 : null;
        return { device: String(n.name || n.uid || ''), mac: String(n.mac_address || '').toLowerCase(), driver: String(n.driver_name || ''), speed_mb: kb ? Math.round(kb / 1000) : null, up, mtu: num(n.mtu_in_bytes), bridge: n.bridge_name ? String(n.bridge_name) : null }; }) : null,
      switches: null, portgroups: null, vmks: null });
  }
  for (const s of R.vswitches || []) out.vswitches.push({ name: String(s.name || ''), bond_mode: String(s.bondMode || s.bond_mode || '') || null, mtu: num(s.mtu), default: !!(s.isDefault || s.is_default) });
  for (const n of R.networks || []) out.networks.push({ id: String(n.uuid), name: String(n.name || ''), kind: 'ahv', vlan: num(n.vlan_id), trunk: null, switch: n.vswitch_name ? 'ovs:' + n.vswitch_name : null, ipam: !!(n.ip_config && n.ip_config.network_address) });
  for (const v of R.vms || []) {
    const nics = (Array.isArray(v.vm_nics) ? v.vm_nics : []).map((n) => ({ network: (out.networks.find((x) => x.id === String(n.network_uuid)) || {}).name || null, network_id: n.network_uuid ? String(n.network_uuid) : null, mac: String(n.mac_address || '').toLowerCase() || null,
      connected: n.is_connected == null ? null : !!n.is_connected, ips: [].concat(n.ip_address ? [n.ip_address] : [], Array.isArray(n.ip_addresses) ? n.ip_addresses : []).filter((x) => String(x).includes('.')).slice(0, 8) }));
    out.vms.push({ id: String(v.uuid), name: String(v.name || ''), host_id: v.host_uuid ? String(v.host_uuid) : null, power: String(v.power_state || '').toLowerCase() === 'on' ? 'on' : 'off', network_ids: nics.map((n) => n.network_id).filter(Boolean), nics, guest_read: true });
  }
  return out;
}

module.exports = { fromVsphere, fromNutanix, vlanOf };
