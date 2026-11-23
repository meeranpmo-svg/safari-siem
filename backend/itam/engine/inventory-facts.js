// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Extra inventory columns for IT Asset Management: IP address, the host a VM runs on, the VM name and its power state -
// read from what the platform already holds, nothing is contacted:
//   IP       the asset's management IP, else the addresses discovery saw for it
//   host     the runs_on relationship the vCenter / Nutanix sync writes (VM → host asset), else the host name the
//            hypervisor reported for the VM
//   VM name  the name the VM has in vCenter / Prism (it often differs from the guest host name)
//   power    the VM's power state at the last vCenter / Prism sync, with when that was (a stale sync says so: "as of")
//   GET /inventory-facts      {assets: {assetId: {ip, ips[], host_id, host_name, vm_name, power, power_raw, power_at,
//                              platform, source}}}      any role (the same people who can read the asset list)
// Online/offline by ping is Server Availability's job; the portal overlay (zyb-itamcols.js) shows that next to this.
// Self-contained, added to an existing install with one registration line (install/add-inventory-facts.sh).
const CLOSED = { retired: 1, disposed: 1 };

function normPower(v) {
  const t = String(v || '').toLowerCase().replace(/[^a-z]/g, '');
  if (!t) return null;
  if (/suspend|paused/.test(t)) return 'suspended';
  if (/off$|poweredoff|^off/.test(t)) return 'off';
  if (/on$|poweredon|^on/.test(t)) return 'on';
  return 'unknown';
}
const ts = (v) => { const n = typeof v === 'number' ? v : Date.parse(v || ''); return Number.isFinite(n) ? n : 0; };

function createInventoryFacts(app) {
  const { store } = app;
  const assets = store.collection('assets'), devs = store.collection('disc_devices'), rels = store.collection('relationships');
  function all() {
    const names = new Map(), out = {};
    for (const a of assets.all()) { if (CLOSED[a.status]) continue; names.set(a.id, a.name || a.asset_tag || a.id); out[a.id] = { ip: a.mgmt_ip || null, ips: a.mgmt_ip ? [a.mgmt_ip] : [], host_id: null, host_name: null, vm_name: null, power: null, power_raw: null, power_at: null, platform: null, source: null }; }
    for (const d of devs.all((x) => x.asset_id)) {
      const f = out[d.asset_id]; if (!f) continue;
      for (const ip of d.ips || []) if (f.ips.indexOf(ip) < 0 && f.ips.length < 8) f.ips.push(ip);
      if (!f.ip && f.ips.length) f.ip = f.ips[0];
      const x = d.extra || {};
      for (const kind of ['vcenter', 'nutanix']) {
        const v = x[kind]; if (!v || v.kind !== 'vm') continue;
        const at = ts(d.methods && d.methods[kind] && d.methods[kind].last_seen) || ts(d.last_seen);
        if (f.power_at && ts(f.power_at) > at) continue;   // two sightings of one VM: the newest sync wins
        f.vm_name = v.name || f.vm_name; f.host_name = v.host || f.host_name; f.platform = v.platform || f.platform; f.source = kind;
        f.power_raw = v.power_state || null; f.power = normPower(v.power_state); f.power_at = at ? new Date(at).toISOString() : null;
      }
    }
    for (const r of rels.all((x) => x.type === 'runs_on' && x.status !== 'rejected')) {
      const f = out[r.from]; if (!f || !names.has(r.to)) continue;
      f.host_id = r.to; f.host_name = names.get(r.to);
    }
    return { assets: out };
  }
  return { all, normPower };
}

function registerInventoryFacts(srv, app) {
  const F = createInventoryFacts(app);
  (app.addons = app.addons || {}).inventoryFacts = F;
  srv.route('GET', '/inventory-facts', (ctx) => void ctx.need('viewer') || F.all());
  return F;
}

module.exports = { createInventoryFacts, registerInventoryFacts, normPower };
