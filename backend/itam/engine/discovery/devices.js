// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Discovery RESULTS: one record per real device, correlated across methods and runs, awaiting an admin decision.
//   observe(obs, ctx) → device        obs = {method, ip?, ips?, mac?, macs?, hostname?, fqdn?, serial?, model?, vendor?, os?,
//                                     sys?{descr, object_id, name, location}, open_ports?, neighbours?, uid?, extra?{…}}
//                                     ctx = {scope_id, site, vlan, run_id, at}
//   Correlation: MAC, serial and a stable source id (VM uuid, cloud instance id, AD DN, CUCM device name) are STRONG keys;
//   the IP address joins observations only inside the same scope and only when no MAC contradicts it; the host name is
//   never used to join (it is only a weak duplicate hint against the CMDB).
//   Review (admin): approve → adopted into ITAM via the existing ingest stage + adopt flow (de-duplicated by the merge
//   engine against existing assets); ignore (reason required; remembered by MAC/serial/id so a re-discovery stays
//   ignored); merge into a chosen existing asset; restore an ignored device.
const crypto = require('node:crypto');
const mergeModel = require('../model/merge');
const { classify, ITAM_TYPE, hex12 } = require('./classify');
const ip4 = require('./ipv4');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const str = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
const macFmt = (m) => { const h = hex12(m); return h && /[1-9a-f]/.test(h) && h !== 'ffffffffffff' ? h.match(/.{2}/g).join(':') : null; };
// which method's value wins for descriptive fields (higher = more authoritative)
const RANK = { cucm: 9, vcenter: 9, nutanix: 9, proxmox: 9, unix: 5, db: 4, storage: 4, hyperv: 8, azure: 9, aws: 9, ad: 7, snmp: 6, sweep: 3, arp: 2 };

function createDevices({ store, assets, ingest, audit, config }) {
  const col = store.collection('disc_devices');
  const ignores = store.collection('disc_ignores');
  const index = new Map(); // key → device id
  const cfg = (config && config.discovery) || {};

  function keysOf(d) {
    const k = [];
    for (const m of d.macs || []) k.push(`mac:${hex12(m)}`);
    if (d.serial) k.push(`ser:${d.serial.toLowerCase()}`);
    for (const u of d.uids || []) k.push(`uid:${u}`);
    return k;
  }
  function reindex(d) { for (const k of keysOf(d)) index.set(k, d.id); for (const ip of d.ips || []) index.set(`ip:${d.scope_id || ''}:${ip}`, d.id); }
  for (const d of col.all()) reindex(d);

  function ignoredBy(keys) { for (const k of keys) { const r = ignores.get(k); if (r) return r; } return null; }

  function normObs(o) {
    const macs = [...new Set([o.mac].concat(o.macs || []).map(macFmt).filter(Boolean))];
    const ips = [...new Set([o.ip].concat(o.ips || []).filter((x) => x && ip4.parseIp(x) !== null))];
    const serial = str(o.serial, 120);
    return {
      method: o.method, untrusted: o.untrusted === true, macs, ips, serial: serial.length >= 3 && !/^(n\/?a|none|unknown|0+)$/i.test(serial) ? serial : '',
      uid: o.uid ? str(o.uid, 200).toLowerCase() : '', hostname: str(o.hostname, 255).toLowerCase(), fqdn: str(o.fqdn, 255).toLowerCase(),
      model: str(o.model, 200), vendor: str(o.vendor, 120), os: str(o.os, 200), sys: o.sys || null,
      open_ports: Array.isArray(o.open_ports) ? o.open_ports.filter((p) => Number.isInteger(p)).slice(0, 64) : [],
      neighbours: Array.isArray(o.neighbours) ? o.neighbours.slice(0, 200) : null, extra: o.extra || null,
    };
  }

  function find(n, scopeId) {
    for (const m of n.macs) { const id = index.get(`mac:${hex12(m)}`); if (id) return col.get(id); }
    if (n.serial) { const id = index.get(`ser:${n.serial.toLowerCase()}`); if (id) return col.get(id); }
    if (n.uid) { const id = index.get(`uid:${n.uid}`); if (id) return col.get(id); }
    for (const ip of n.ips) {
      const id = index.get(`ip:${scopeId || ''}:${ip}`);
      if (!id) continue;
      const d = col.get(id);
      // the IP joins only if no MAC contradicts it (a DHCP lease reused by another machine is a different device)
      if (d && !(n.macs.length && d.macs.length && !n.macs.some((m) => d.macs.includes(m)))) return d;
    }
    return null;
  }

  function setField(d, field, value, method) {
    if (!value) return;
    d.rank = d.rank || {};
    const r = RANK[method] || 1;
    if (!d[field] || (d.rank[field] || 0) <= r) { d[field] = value; d.rank[field] = r; }
  }

  function observe(obs, ctx = {}) {
    const n = normObs(obs);
    if (!n.macs.length && !n.ips.length && !n.serial && !n.uid) return null;
    const now = ctx.at || new Date().toISOString();
    let d = find(n, ctx.scope_id);
    const isNew = !d;
    if (!d) {
      d = { id: `dd_${crypto.randomBytes(6).toString('hex')}`, status: 'new', first_seen: now, last_seen: now, seen_count: 0, macs: [], ips: [], uids: [], methods: {}, open_ports: [], neighbours: [], extra: {}, scope_id: ctx.scope_id || null, site: ctx.site || null, vlan: ctx.vlan || null, runs: [] };
    }
    d.macs = [...new Set(d.macs.concat(n.macs))].slice(0, 16);
    d.ips = [...new Set(n.ips.concat(d.ips))].slice(0, 16);
    if (n.uid && !d.uids.includes(n.uid)) d.uids = d.uids.concat(n.uid).slice(0, 8);
    d.mac = d.macs[0] || null;
    d.ip = n.ips[0] || d.ip || d.ips[0] || null;
    setField(d, 'serial', n.serial, n.method);
    setField(d, 'hostname', n.hostname || (n.fqdn ? n.fqdn.split('.')[0] : ''), n.method);
    setField(d, 'fqdn', n.fqdn, n.method);
    setField(d, 'model', n.model, n.method);
    setField(d, 'os', n.os, n.method);
    setField(d, 'vendor_hint', n.vendor, n.method);
    if (n.sys) {
      if (n.sys.descr) d.sys_descr = str(n.sys.descr, 500);
      if (n.sys.object_id) d.sys_object_id = str(n.sys.object_id, 120);
      if (n.sys.name) setField(d, 'hostname', str(n.sys.name, 255).toLowerCase(), n.method);
      if (n.sys.location) d.location = str(n.sys.location, 200);
    }
    if (n.open_ports.length) d.open_ports = [...new Set(d.open_ports.concat(n.open_ports))].sort((a, b) => a - b);
    if (n.neighbours) d.neighbours = n.neighbours.map((x) => ({ via: x.via, local_port: x.local_port || null, remote_name: x.remote_name || null, remote_port: x.remote_port || null, remote_ip: x.remote_ip || null, remote_mac: x.remote_mac || null, remote_platform: x.remote_platform || null }));
    if (n.extra) for (const [k, v] of Object.entries(n.extra)) d.extra[k] = v;
    const m = d.methods[n.method] || { first_seen: now, count: 0 };
    // a method sighting stays 'untrusted' (self-asserted, e.g. agent-key Hyper-V) until a trusted observation of it arrives
    d.methods[n.method] = Object.assign({ first_seen: m.first_seen, last_seen: now, count: m.count + 1 }, n.untrusted && (m.count === 0 || m.untrusted) ? { untrusted: true } : {});
    if (ctx.run_id && !d.runs.includes(ctx.run_id)) { d.runs = d.runs.concat(ctx.run_id).slice(-20); d.seen_count = (d.seen_count || 0) + 1; }
    else if (!ctx.run_id) d.seen_count = (d.seen_count || 0) + 1;
    d.last_seen = now;
    if (ctx.scope_id && !d.scope_id) d.scope_id = ctx.scope_id;
    if (ctx.site && !d.site) d.site = ctx.site;
    if (ctx.vlan && !d.vlan) d.vlan = ctx.vlan;
    // classification + vendor
    const c = classify(Object.assign({}, d, { hostname: d.hostname }));
    d.type = c.type; d.vendor = d.vendor_hint || c.vendor; d.os = d.os || c.os; d.confidence = c.confidence; d.reasons = c.reasons;
    // ignore memory
    if (isNew) { const ig = ignoredBy(keysOf(d).concat(!d.macs.length && !d.serial && !d.uids.length && d.ip ? [`ipo:${d.scope_id || ''}:${d.ip}`] : [])); if (ig) { d.status = 'ignored'; d.ignore_reason = ig.reason; d.decided_by = ig.by; d.decided_at = ig.at; } }
    col.put(d);
    reindex(d);
    return d;
  }

  // ---- views ---------------------------------------------------------------------------------------------------------
  function assetFields(d) {
    const extra = d.extra || {};
    const f = {
      name: d.hostname || d.fqdn || (extra.cloud && extra.cloud.name) || d.ip || d.mac,
      type: ITAM_TYPE[d.type] || 'other', vendor: d.vendor || null, model: d.model || null, serial: d.serial || null,
      mgmt_ip: d.ip || null, mac: d.mac || null, macs: d.macs, os: d.os || null, site: d.site || null,
      networked: true, tags: ['discovery', `disc:${d.type}`].concat(d.type === 'cloud' ? ['cloud'] : []),
    };
    if (extra.vcenter && extra.vcenter.uuid) f.uuid = extra.vcenter.uuid;
    if (d.location) f.location = { building: d.location, room: null, rack: null };
    return f;
  }
  function duplicates(d) {
    const f = assetFields(d);
    return mergeModel.duplicateCandidates({ mac: f.mac, macs: f.macs, serial: f.serial, hostname: d.hostname || d.fqdn }, assets.all()).slice(0, 5);
  }
  function view(d, withDup) {
    if (!d) return null;
    const { rank, vendor_hint, runs, ...pub } = d; // eslint-disable-line no-unused-vars
    pub.methods_seen = Object.keys(d.methods || {});
    if (withDup) { pub.duplicates = d.status === 'new' ? duplicates(d) : []; pub.in_cmdb = !!d.asset_id || pub.duplicates.some((x) => x.strength === 'strong'); }
    return pub;
  }
  function list(filter) { return col.all(filter); }
  function get(id) { return col.get(id); }

  // ---- decisions -----------------------------------------------------------------------------------------------------
  function need(id) { const d = col.get(id); if (!d) throw bad('device not found', 404); return d; }
  function audited(who, action, target, detail) { if (audit) audit({ by: who.user, role: who.role, ip: who.ip, action, target, detail }); }

  function linkNeighbours(d, who) {
    if (!d.asset_id) return 0;
    let n = 0;
    const approved = col.all((x) => x.asset_id && x.id !== d.id);
    const matches = (x, nb) => (nb.remote_mac && x.macs.includes(nb.remote_mac)) || (nb.remote_ip && x.ips.includes(nb.remote_ip)) || (nb.remote_name && x.hostname && x.hostname === String(nb.remote_name).toLowerCase().split('.')[0]);
    const link = (from, to, nb) => {
      try { assets.addRelationship({ from, to, type: 'connected_to', source: 'discovery', rationale: `${String(nb.via || 'lldp').toUpperCase()} neighbour${nb.local_port ? ' on ' + nb.local_port : ''}` }, { user: who.user, role: who.role }, { source: 'discovery', autoConfirm: false }); n++; } catch { /* endpoint missing */ }
    };
    for (const nb of d.neighbours || []) { const peer = approved.find((x) => matches(x, nb)); if (peer) link(d.asset_id, peer.asset_id, nb); }
    for (const x of approved) for (const nb of x.neighbours || []) if (matches(d, nb)) link(x.asset_id, d.asset_id, nb);
    return n;
  }

  function stamp(assetId, d) {
    store.collection('assets').patch(assetId, (a) => { a.discovery = { device_id: d.id, class: d.type, vendor: d.vendor || null, os: d.os || null, is_dc: !!(d.extra && d.extra.ad && d.extra.ad.is_dc), confidence: d.confidence }; });
  }

  function approve(id, who) {
    const d = need(id);
    if (d.status === 'approved' || d.status === 'merged') throw bad(`device already ${d.status}`, 409);
    const fields = assetFields(d);
    const staged = ingest.stage('discovery', d.id, fields, d.last_seen);
    const r = ingest.adopt(staged.id, who);
    const before = assets.raw(r.assetId);
    const mergedExisting = !!(before && before.sources && before.sources.some((s) => s.source !== 'discovery'));
    stamp(r.assetId, d);
    col.patch(id, (x) => { x.status = 'approved'; x.asset_id = r.assetId; x.decided_by = who.user; x.decided_at = new Date().toISOString(); });
    const rel = linkNeighbours(col.get(id), who);
    audited(who, 'discovery.approve', id, { asset_id: r.assetId, merged_into_existing: mergedExisting, type: d.type, ip: d.ip, mac: d.mac, relationships: rel });
    return { device: view(col.get(id), true), asset_id: r.assetId, merged_into_existing: mergedExisting, relationships: rel };
  }

  function ignore(id, reason, who) {
    const d = need(id);
    const why = str(reason, 500);
    if (why.length < 3) throw bad('a reason is required to ignore a device (min 3 characters)');
    if (d.status === 'approved' || d.status === 'merged') throw bad(`device already ${d.status} — retire the asset instead`, 409);
    const at = new Date().toISOString();
    for (const k of keysOf(d).concat(d.ips.length && !d.macs.length && !d.serial && !d.uids.length ? [`ipo:${d.scope_id || ''}:${d.ip}`] : [])) ignores.put({ id: k, device_id: id, reason: why, by: who.user, at });
    col.patch(id, (x) => { x.status = 'ignored'; x.ignore_reason = why; x.decided_by = who.user; x.decided_at = at; });
    audited(who, 'discovery.ignore', id, { reason: why, ip: d.ip, mac: d.mac });
    return { device: view(col.get(id), true) };
  }

  function restore(id, who) {
    const d = need(id);
    if (d.status !== 'ignored') throw bad('only an ignored device can be restored', 409);
    for (const r of ignores.all((x) => x.device_id === id)) ignores.remove(r.id);
    col.patch(id, (x) => { x.status = 'new'; x.ignore_reason = null; x.decided_by = who.user; x.decided_at = new Date().toISOString(); });
    audited(who, 'discovery.restore', id, { ip: d.ip, mac: d.mac });
    return { device: view(col.get(id), true) };
  }

  function mergeInto(id, assetId, who) {
    const d = need(id);
    if (d.status === 'approved' || d.status === 'merged') throw bad(`device already ${d.status}`, 409);
    const target = assets.raw(String(assetId || ''));
    if (!target) throw bad('asset_id must be an existing asset', 404);
    if (target.status === 'disposed') throw bad('cannot merge into a disposed asset', 409);
    const fields = assetFields(d);
    const r = assets.upsert(fields, 'discovery', { source_id: d.id, at: d.last_seen }, { forceAssetId: target.id });
    stamp(target.id, d);
    col.patch(id, (x) => { x.status = 'merged'; x.asset_id = target.id; x.decided_by = who.user; x.decided_at = new Date().toISOString(); });
    const rel = linkNeighbours(col.get(id), who);
    audited(who, 'discovery.merge', id, { asset_id: target.id, changed: r.changed, ip: d.ip, mac: d.mac });
    return { device: view(col.get(id), true), asset_id: target.id, changed: r.changed };
  }

  return { observe, list, get, view, approve, ignore, restore, mergeInto, assetFields, duplicates, keysOf, col };
}

module.exports = { createDevices, macFmt };
