// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Read-only collectors. Each returns a partial NORMALISED snapshot (merged by poller.js):
 *   system {name, model, version, serial, uptime_s, cpu_pct, mem_pct, sessions}
 *   interfaces [{name, alias, admin:'up'|'down', oper:'up'|'down', speed_mbps, in_octets, out_octets (strings — 64-bit),
 *                in_errors, out_errors, in_discards, out_discards}]
 *   tunnels [{name, type:'ipsec'|'overlay', peer, status:'up'|'down', in_bytes, out_bytes}]
 *   ha {enabled, mode, state, peer_state, in_sync}
 *   neighbors [{proto:'bgp'|'ospf', peer, state, up:boolean, remote_as}]
 *   paths [{name, member, status, latency_ms, jitter_ms, loss_pct}]          SD-WAN health checks / overlay paths
 *   users [{user, ip, group, method, bytes, duration_s}]                      FortiGate signed-in firewall users (route map, user level)
 *   nac {nodes, unauthorized, quarantined, items:[{ip, mac, host, status, switch, port, vlan}]}
 *   sdwan {appliances:[{name, site, ip, state, up}], alarms:[{severity, appliance, text, at}]}
 *   reach {sent, received, loss_pct, rtt_avg_ms, rtt_max_ms, jitter_ms}
 *   licenses {at, serial, items:[{name, kind:'support'|'subscription', status, expires:'YYYY-MM-DD'|null, expired}]}
 *     what the device itself reports about its support contract and security subscriptions (licenses(dev, cred), run by
 *     the poller every few hours, not on every poll): FortiGate GET /api/v2/monitor/license/status, PAN-OS
 *     "request license info" (lists the installed licences; it is the one non-"show" command allowed, and it is read-only:
 *     it does not fetch or install anything). Field names differ between FortiOS / PAN-OS versions: read defensively.
 * Every API call is a GET (or a PAN-OS "show" operational command); nothing here can change a device.
 */
const { execFile } = require('node:child_process');
const net = require('node:net');
const { createSnmp, str } = require('./snmp');
const { getJSON, getRaw } = require('./http');
const X = require('./xml');

/* ---------------- reachability (system ping, no shell) */
function ping(ip, { count = 5, timeoutMs = 8000 } = {}) {
  return new Promise((resolve) => {
    if (!net.isIP(ip)) return resolve({ sent: 0, received: 0, loss_pct: 100, error: 'bad IP' });
    const args = net.isIPv6(ip) ? ['-6'] : [];
    execFile('ping', args.concat(['-n', '-q', '-c', String(count), '-i', '0.2', '-W', '1', ip]), { timeout: timeoutMs }, (err, out) => {
      const m = /(\d+) packets transmitted, (\d+) (?:packets )?received/.exec(out || '');
      const r = /= ([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+) ms/.exec(out || '');
      if (err && (err.code === 'ENOENT' || /Operation not permitted|permission denied|socket: /i.test(String(out) + String(err.message)))) return resolve({ unavailable: true, error: err.code === 'ENOENT' ? 'ping is not installed on the SIEM server' : 'the SIEM service may not send ICMP (ping permission)' });
      if (!m) return resolve({ sent: count, received: 0, loss_pct: 100, error: 'no reply' });
      const sent = +m[1], rec = +m[2];
      resolve({ sent, received: rec, loss_pct: Math.round((1 - rec / sent) * 1000) / 10, rtt_avg_ms: r ? +r[2] : null, rtt_max_ms: r ? +r[3] : null, jitter_ms: r ? +r[4] : null });
    });
  });
}

/* ---------------- SNMP (all vendors; Cisco CPU/memory MIBs) */
const OID = {
  sysDescr: '1.3.6.1.2.1.1.1.0', sysUpTime: '1.3.6.1.2.1.1.3.0', sysName: '1.3.6.1.2.1.1.5.0',
  ifDescr: '1.3.6.1.2.1.2.2.1.2', ifAdmin: '1.3.6.1.2.1.2.2.1.7', ifOper: '1.3.6.1.2.1.2.2.1.8', ifInDisc: '1.3.6.1.2.1.2.2.1.13', ifInErr: '1.3.6.1.2.1.2.2.1.14',
  ifOutDisc: '1.3.6.1.2.1.2.2.1.19', ifOutErr: '1.3.6.1.2.1.2.2.1.20', ifName: '1.3.6.1.2.1.31.1.1.1.1', ifHCIn: '1.3.6.1.2.1.31.1.1.1.6', ifHCOut: '1.3.6.1.2.1.31.1.1.1.10',
  ifHighSpeed: '1.3.6.1.2.1.31.1.1.1.15', ifAlias: '1.3.6.1.2.1.31.1.1.1.18',
  ciscoCpu5m: '1.3.6.1.4.1.9.9.109.1.1.1.1.8', ciscoMemUsed: '1.3.6.1.4.1.9.9.48.1.1.1.5', ciscoMemFree: '1.3.6.1.4.1.9.9.48.1.1.1.6',
  fgCpu: '1.3.6.1.4.1.12356.101.4.1.3.0', fgMem: '1.3.6.1.4.1.12356.101.4.1.4.0', fgSessions: '1.3.6.1.4.1.12356.101.4.1.8.0',
  panSessions: '1.3.6.1.4.1.25461.2.1.2.3.3.0', hrProcLoad: '1.3.6.1.2.1.25.3.3.1.2',
  bgpPeerState: '1.3.6.1.2.1.15.3.1.2', bgpPeerAs: '1.3.6.1.2.1.15.3.1.9', ospfNbrState: '1.3.6.1.2.1.14.10.1.6',
};
const BGP = { 1: 'idle', 2: 'connect', 3: 'active', 4: 'opensent', 5: 'openconfirm', 6: 'established' };
const OSPF = { 1: 'down', 2: 'attempt', 3: 'init', 4: 'two-way', 5: 'exstart', 6: 'exchange', 7: 'loading', 8: 'full' };
const ST = { 1: 'up', 2: 'down', 3: 'testing', 5: 'dormant', 6: 'notPresent', 7: 'lowerLayerDown' };

function idx(oid, base) { return oid.slice(base.length + 1); }
function col(rows, base) { const m = new Map(); for (const [o, v] of rows) m.set(idx(o, base), v); return m; }

async function snmpCollect(dev, cred) {
  const s = createSnmp(Object.assign({ host: dev.ip, port: cred.port || 161, timeoutMs: 2500, retries: 1 }, cred));
  try {
    const g = await s.get([OID.sysDescr, OID.sysUpTime, OID.sysName]);
    const out = { system: { name: str(g[OID.sysName]), version: str(g[OID.sysDescr]).split(/\r?\n/)[0].slice(0, 200), uptime_s: g[OID.sysUpTime] != null ? Math.round(g[OID.sysUpTime] / 100) : null } };
    const W = async (o) => { try { return await s.walk(o, { maxRows: 4000 }); } catch (e) { return []; } };
    const [descr, admin, oper, inD, inE, outD, outE, name, hin, hout, hs, alias] = await Promise.all(
      [OID.ifDescr, OID.ifAdmin, OID.ifOper, OID.ifInDisc, OID.ifInErr, OID.ifOutDisc, OID.ifOutErr, OID.ifName, OID.ifHCIn, OID.ifHCOut, OID.ifHighSpeed, OID.ifAlias].map(W));
    const c = { descr: col(descr, OID.ifDescr), admin: col(admin, OID.ifAdmin), oper: col(oper, OID.ifOper), inD: col(inD, OID.ifInDisc), inE: col(inE, OID.ifInErr), outD: col(outD, OID.ifOutDisc), outE: col(outE, OID.ifOutErr),
      name: col(name, OID.ifName), hin: col(hin, OID.ifHCIn), hout: col(hout, OID.ifHCOut), hs: col(hs, OID.ifHighSpeed), alias: col(alias, OID.ifAlias) };
    out.interfaces = [...c.descr.keys()].map((i) => ({
      index: Number(i), name: str(c.name.get(i)) || str(c.descr.get(i)), alias: str(c.alias.get(i)),
      admin: ST[c.admin.get(i)] || 'unknown', oper: ST[c.oper.get(i)] || 'unknown', speed_mbps: c.hs.get(i) || null,
      in_octets: c.hin.has(i) ? String(c.hin.get(i)) : null, out_octets: c.hout.has(i) ? String(c.hout.get(i)) : null,
      in_errors: c.inE.get(i) || 0, out_errors: c.outE.get(i) || 0, in_discards: c.inD.get(i) || 0, out_discards: c.outD.get(i) || 0,
    })).filter((x) => !/^(lo|null|loopback|nu0|ifb\d|sit\d|tunl\d|vlan-if-lo)/i.test(x.name));
    if (dev.vendor === 'cisco-ios' || dev.vendor === 'cisco-asa') {
      const cpu = await W(OID.ciscoCpu5m); if (cpu.length) out.system.cpu_pct = Math.max(...cpu.map((r) => Number(r[1]) || 0));
      const mu = await W(OID.ciscoMemUsed), mf = await W(OID.ciscoMemFree);
      if (mu.length && mf.length) { const u = Number(mu[0][1]), f = Number(mf[0][1]); if (u + f > 0) out.system.mem_pct = Math.round(u / (u + f) * 1000) / 10; }
    } else if (dev.vendor === 'fortigate') {
      const v = await s.get([OID.fgCpu, OID.fgMem, OID.fgSessions]).catch(() => ({}));
      if (v[OID.fgCpu] != null) out.system.cpu_pct = v[OID.fgCpu]; if (v[OID.fgMem] != null) out.system.mem_pct = v[OID.fgMem]; if (v[OID.fgSessions] != null) out.system.sessions = v[OID.fgSessions];
    } else if (dev.vendor === 'paloalto') {
      const v = await s.get([OID.panSessions]).catch(() => ({})); if (v[OID.panSessions] != null) out.system.sessions = v[OID.panSessions];
      const cpu = await W(OID.hrProcLoad); if (cpu.length) out.system.cpu_pct = Math.round(cpu.reduce((a, r) => a + (Number(r[1]) || 0), 0) / cpu.length);
    }
    const bs = await W(OID.bgpPeerState), ba = col(await W(OID.bgpPeerAs), OID.bgpPeerAs);
    const os = await W(OID.ospfNbrState);
    out.neighbors = bs.map(([o, v]) => { const p = idx(o, OID.bgpPeerState); return { proto: 'bgp', peer: p, state: BGP[v] || String(v), up: v === 6, remote_as: ba.get(p) || null }; })
      .concat(os.map(([o, v]) => { const p = idx(o, OID.ospfNbrState).split('.').slice(0, 4).join('.'); return { proto: 'ospf', peer: p, state: OSPF[v] || String(v), up: v === 8 || v === 4 }; }));
    return out;
  } finally { s.close(); }
}

/* ---------------- FortiGate (FortiOS REST API, read-only API admin) */
async function fortigate(dev, cred) {
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 443}`, o = { headers: { Authorization: 'Bearer ' + cred.token }, tls: cred.tls, timeoutMs: 10000 };
  const vd = cred.vdom ? '?vdom=' + encodeURIComponent(cred.vdom) : '';
  const q = (p, extra) => getJSON(base + p + (vd ? vd + (extra ? '&' + extra : '') : (extra ? '?' + extra : '')), o);
  const out = { system: {}, errors: [] };
  const step = async (n, fn) => { try { await fn(); } catch (e) { out.errors.push(n + ': ' + e.message); } };
  await step('status', async () => { const j = await q('/api/v2/monitor/system/status'); const r = j.results || {}; Object.assign(out.system, { name: r.hostname || j.hostname || '', model: r.model_name ? r.model_name + ' ' + (r.model_number || '') : (r.model || ''), version: j.version || r.version || '', serial: j.serial || r.serial || '' }); });
  await step('resources', async () => { const r = (await q('/api/v2/monitor/system/resource/usage', 'interval=1-min')).results || {}; const cur = (k) => (r[k] && r[k][0] ? r[k][0].current : null); out.system.cpu_pct = cur('cpu'); out.system.mem_pct = cur('mem'); out.system.sessions = cur('session'); });
  await step('interfaces', async () => {
    const r = (await q('/api/v2/monitor/system/interface', 'include_vlan=true')).results || {};
    out.interfaces = Object.values(r).map((i) => ({ name: i.name, alias: i.alias || '', admin: i.status === 'down' ? 'down' : 'up', oper: i.link ? 'up' : 'down', speed_mbps: i.speed || null,
      in_octets: i.rx_bytes != null ? String(i.rx_bytes) : null, out_octets: i.tx_bytes != null ? String(i.tx_bytes) : null, in_errors: i.rx_errors || 0, out_errors: i.tx_errors || 0, in_discards: 0, out_discards: 0 }));
  });
  await step('ipsec', async () => {
    const r = (await q('/api/v2/monitor/vpn/ipsec')).results || [];
    out.tunnels = r.map((t) => { const p = t.proxyid || []; return { name: t.name, type: 'ipsec', peer: t.rgwy || '', status: p.length && p.some((x) => x.status === 'up') ? 'up' : 'down', in_bytes: t.incoming_bytes || 0, out_bytes: t.outgoing_bytes || 0 }; });
  });
  await step('ha', async () => {
    const peers = (await q('/api/v2/monitor/system/ha-peer')).results || [];
    if (!peers.length || peers.length < 2) { out.ha = { enabled: peers.length > 1, mode: peers.length > 1 ? 'a-p' : 'standalone', in_sync: null }; return; }
    let sync = null; try { const c = (await q('/api/v2/monitor/system/ha-checksums')).results || []; const sums = c.map((x) => x.checksum && x.checksum.all).filter(Boolean); sync = sums.length > 1 ? sums.every((s) => s === sums[0]) : null; } catch (e) { /* older FortiOS */ }
    out.ha = { enabled: true, mode: 'cluster', state: 'members ' + peers.length, peer_state: peers.map((p) => p.hostname).join(', '), in_sync: sync };
  });
  await step('sdwan', async () => {
    const r = (await q('/api/v2/monitor/virtual-wan/health-check')).results || {};
    out.paths = [];
    for (const [hc, members] of Object.entries(r)) for (const [m, v] of Object.entries(members || {})) out.paths.push({ name: hc, member: m, status: v.status || 'unknown', latency_ms: v.latency != null ? +v.latency : null, jitter_ms: v.jitter != null ? +v.jitter : null, loss_pct: v.packet_loss != null ? +v.packet_loss : null });
  });
  // signed-in firewall users (FSSO / RADIUS / local) with their traffic - the route map's user level; field names differ by version
  await step('users', async () => {
    const r = (await q('/api/v2/monitor/user/firewall')).results || [];
    out.users = (Array.isArray(r) ? r : []).slice(0, 2000).map((u) => ({ user: String(u.username || u.user_name || u.name || '').slice(0, 120), ip: String(u.ipaddr || u.ip || '').slice(0, 45), group: String(u.usergroup || u.group || (Array.isArray(u.groups) ? u.groups.join(', ') : '') || '').slice(0, 120),
      method: String(u.method || u.type || '').slice(0, 40), bytes: Number(u.traffic_vol_bytes != null ? u.traffic_vol_bytes : u.bytes != null ? u.bytes : (u.rx_bytes || 0) + (u.tx_bytes || 0)) || 0, duration_s: Number(u.duration || 0) || null })).filter((u) => u.user || u.ip);
  });
  // DHCP leases and the ARP table - every device on the firewall's LANs (Advanced Rogue Detection, rogue.js); read only. A token
  // whose profile cannot read them gets an error for these two steps only.
  await step('dhcp', async () => {
    const r = (await q('/api/v2/monitor/system/dhcp')).results || [];
    out.dhcp = (Array.isArray(r) ? r : []).slice(0, 5000).map((l) => ({ ip: String(l.ip || '').slice(0, 45), mac: String(l.mac || '').slice(0, 20), host: String(l.hostname || '').slice(0, 120), iface: String(l.interface || '').slice(0, 40),
      vci: String(l.vci || '').slice(0, 80), expires: Number(l.expire_time || 0) || null, reserved: !!l.reserved })).filter((l) => l.mac);
  });
  await step('arp', async () => {
    const r = (await q('/api/v2/monitor/network/arp')).results || [];
    out.arp = (Array.isArray(r) ? r : []).slice(0, 10000).map((a) => ({ ip: String(a.ip || '').slice(0, 45), mac: String(a.mac || '').slice(0, 20), iface: String(a.interface || '').slice(0, 40), age: Number(a.age || 0) || null })).filter((a) => a.mac && !/^0{2}([:-]?0{2}){5}$/.test(a.mac));
  });
  await step('bgp', async () => {
    const r = (await q('/api/v2/monitor/router/bgp/neighbors')).results || [];
    out.neighbors = r.map((n) => ({ proto: 'bgp', peer: n.neighbor_ip, state: String(n.state || '').toLowerCase(), up: /established/i.test(n.state || ''), remote_as: n.remote_as || null }));
  });
  if (out.errors.length >= 10) throw new Error('FortiGate API unreachable: ' + out.errors[0]);   // every step failed
  return out;
}

/* ---------------- Palo Alto (PAN-OS XML API, operational "show" commands only) */
const PAN_LICENSE_INFO = '<request><license><info></info></license></request>';
async function paloalto(dev, cred) {
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 443}/api/`, o = { headers: { 'X-PAN-KEY': cred.token }, tls: cred.tls, timeoutMs: 15000 };
  const op = async (cmd) => {
    if (!/^<show>/.test(cmd) && cmd !== PAN_LICENSE_INFO) throw new Error('only show commands are allowed');
    const r = await getRaw(base + '?type=op&cmd=' + encodeURIComponent(cmd), o);
    if (r.status === 403 || r.status === 401) throw new Error('API refused the key (HTTP ' + r.status + ')');
    if (r.status !== 200) throw new Error('HTTP ' + r.status);
    const doc = X.parse(r.text); if (doc.attrs.status !== 'success') throw new Error(X.txt(doc, 'msg/line') || X.txt(doc, 'msg') || 'API error');
    return doc;
  };
  const out = { system: {}, errors: [] };
  const step = async (n, fn) => { try { await fn(); } catch (e) { out.errors.push(n + ': ' + e.message); } };
  await step('info', async () => {
    const d = await op('<show><system><info></info></system></show>'), s = X.find(d, 'result/system');
    const up = X.txt(s, 'uptime'), m = /(\d+) days?, (\d+):(\d+):(\d+)/.exec(up);
    Object.assign(out.system, { name: X.txt(s, 'hostname'), model: X.txt(s, 'model'), version: X.txt(s, 'sw-version'), serial: X.txt(s, 'serial'), uptime_s: m ? +m[1] * 86400 + +m[2] * 3600 + +m[3] * 60 + +m[4] : null });
  });
  await step('resources', async () => {
    const t = X.txt(await op('<show><system><resources></resources></system></show>'), 'result');
    const c = /%Cpu\(s\):\s*([\d.]+)\s*us,\s*([\d.]+)\s*sy,.*?([\d.]+)\s*id/.exec(t); if (c) out.system.cpu_pct = Math.round((100 - +c[3]) * 10) / 10;
    const m = /(?:KiB|MiB) Mem\s*:\s*([\d.]+)\s*total,\s*([\d.]+)\s*free,\s*([\d.]+)\s*used/.exec(t); if (m) out.system.mem_pct = Math.round(+m[3] / +m[1] * 1000) / 10;
  });
  await step('sessions', async () => { const d = await op('<show><session><info></info></session></show>'); const n = X.txt(d, 'result/num-active'); if (n) out.system.sessions = +n; });
  await step('interfaces', async () => {
    const d = await op('<show><interface>all</interface></show>'), counters = new Map();
    try { const c = await op('<show><counter><interface>all</interface></counter></show>'); for (const e of X.all(c, 'result/ifnet/ifnet/entry').concat(X.all(c, 'result/ifnet/entry'))) counters.set(X.txt(e, 'name'), e); } catch (e) { /* counters optional */ }
    out.interfaces = X.all(d, 'result/hw/entry').map((e) => { const n = X.txt(e, 'name'), c = counters.get(n); const sp = parseInt(X.txt(e, 'speed'), 10);
      return { name: n, alias: '', admin: 'up', oper: X.txt(e, 'state') === 'up' ? 'up' : 'down', speed_mbps: Number.isFinite(sp) ? sp : null,
        in_octets: c ? X.txt(c, 'ibytes') || null : null, out_octets: c ? X.txt(c, 'obytes') || null : null, in_errors: c ? +X.txt(c, 'ierrors') || 0 : 0, out_errors: c ? +X.txt(c, 'oerrors') || 0 : 0, in_discards: c ? +X.txt(c, 'idrops') || 0 : 0, out_discards: 0 }; });
  });
  await step('ipsec', async () => {
    const d = await op('<show><vpn><flow></flow></vpn></show>');
    out.tunnels = X.all(d, 'result/IPSec/entry').map((e) => ({ name: X.txt(e, 'name'), type: 'ipsec', peer: X.txt(e, 'peerip'), status: X.txt(e, 'state') === 'active' ? 'up' : 'down', in_bytes: 0, out_bytes: 0 }));
  });
  await step('ha', async () => {
    const d = await op('<show><high-availability><state></state></high-availability></show>');
    const en = X.txt(d, 'result/enabled') === 'yes';
    out.ha = en ? { enabled: true, mode: X.txt(d, 'result/group/mode'), state: X.txt(d, 'result/group/local-info/state'), peer_state: X.txt(d, 'result/group/peer-info/state'), in_sync: /^synchronized$/i.test(X.txt(d, 'result/group/running-sync')) } : { enabled: false, mode: 'standalone', in_sync: null };
  });
  await step('bgp', async () => {
    const d = await op('<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>');
    out.neighbors = X.all(d, 'result/entry').map((e) => ({ proto: 'bgp', peer: (X.txt(e, 'peer-address') || '').split(':')[0] || e.attrs.peer, state: X.txt(e, 'status').toLowerCase(), up: /established/i.test(X.txt(e, 'status')), remote_as: +X.txt(e, 'remote-as') || null }));
  });
  if (out.errors.length >= 7) throw new Error('PAN-OS API unreachable: ' + out.errors[0]);
  return out;
}

/* ---------------- Genian NAC (REST API key). Field names differ between versions: matched loosely. */
function pick(o, re) { for (const k of Object.keys(o || {})) if (re.test(k) && o[k] != null && o[k] !== '') return o[k]; return ''; }
async function genian(dev, cred) {
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 8443}`, path = cred.nodes_path || '/mc2/rest/nodes';
  const url = base + path + (path.includes('?') ? '&' : '?') + 'page=1&pageSize=' + (cred.page_size || 500) + (cred.token ? '&apiKey=' + encodeURIComponent(cred.token) : '');
  const j = await getJSON(url, { tls: cred.tls, timeoutMs: 15000, headers: cred.token ? { 'X-Api-Key': cred.token } : {} });
  const list = Array.isArray(j) ? j : j.result || j.results || j.data || j.list || j.nodes || [];
  const items = (Array.isArray(list) ? list : []).slice(0, 5000).map((n) => {
    const status = String(pick(n, /status|auth|state|perm/i)).toLowerCase();
    return { ip: String(pick(n, /^(nl_)?ip(str|addr)?$|ipaddress/i)), mac: String(pick(n, /mac/i)), host: String(pick(n, /host|name/i)), status,
      switch: String(pick(n, /switch|sw_?ip|nas/i)), port: String(pick(n, /port|ifname/i)), vlan: String(pick(n, /vlan/i)) };
  });
  const unauth = items.filter((i) => /unauth|reject|deny|block|unknown|unreg/.test(i.status)).length, quar = items.filter((i) => /quarant|isolat/.test(i.status)).length;
  return { nac: { nodes: items.length, unauthorized: unauth, quarantined: quar, items: items.slice(0, 2000) } };
}

/* ---------------- UPS: the standard UPS-MIB (RFC 1628, 1.3.6.1.2.1.33), read only. Every UPS with an SNMP card answers it (APC,
 * Eaton, Vertiv, Riello ...). A value the card does not report stays null - never zero, never "normal". */
const UPS = '1.3.6.1.2.1.33.1';
const UPS_OID = { mfr: UPS + '.1.1.0', model: UPS + '.1.2.0', name: UPS + '.1.5.0', battStatus: UPS + '.2.1.0', onBattS: UPS + '.2.2.0', minLeft: UPS + '.2.3.0', charge: UPS + '.2.4.0',
  temp: UPS + '.2.7.0', lineBads: UPS + '.3.1.0', outSource: UPS + '.4.1.0', alarmsPresent: UPS + '.6.1.0', testResult: UPS + '.7.3.0',
  inVoltage: UPS + '.3.3.1.3', outLoad: UPS + '.4.4.1.5', alarmDescr: UPS + '.6.2.1.2' };
const UPS_BATT = { 1: 'unknown', 2: 'normal', 3: 'low', 4: 'depleted' };
const UPS_SRC = { 1: 'other', 2: 'none', 3: 'normal', 4: 'bypass', 5: 'battery', 6: 'booster', 7: 'reducer' };
const UPS_TEST = { 1: 'passed', 2: 'warning', 3: 'failed', 4: 'aborted', 5: 'in progress', 6: 'never run' };
const UPS_ALARM = { 1: 'battery bad', 2: 'on battery', 3: 'low battery', 4: 'battery depleted', 5: 'temperature out of range', 6: 'input bad', 7: 'output bad', 8: 'output overload',
  9: 'on bypass', 10: 'bypass bad', 11: 'output off as requested', 12: 'UPS off as requested', 13: 'charger failed', 14: 'output off', 15: 'UPS system off', 16: 'fan failure',
  17: 'fuse failure', 18: 'general fault', 19: 'self-test failed', 20: 'communications lost', 21: 'awaiting power', 22: 'shutdown pending', 23: 'shutdown imminent', 24: 'self-test in progress' };
const upsNum = (v) => (v == null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
function upsParse(g, walks) {
  const vals = (rows) => (rows || []).map((r) => upsNum(r[1])).filter((v) => v != null);
  const loads = vals(walks.outLoad), volts = vals(walks.inVoltage);
  const alarms = (walks.alarmDescr || []).map((r) => { const m = /1\.3\.6\.1\.2\.1\.33\.1\.6\.3\.(\d+)$/.exec(String(r[1])); return m ? (UPS_ALARM[m[1]] || 'alarm ' + m[1]) : String(r[1]).slice(0, 80); }).slice(0, 30);
  return { manufacturer: str(g[UPS_OID.mfr]).slice(0, 80), model: str(g[UPS_OID.model]).slice(0, 80), name: str(g[UPS_OID.name]).slice(0, 80),
    battery: UPS_BATT[g[UPS_OID.battStatus]] || null, seconds_on_battery: upsNum(g[UPS_OID.onBattS]), minutes_left: upsNum(g[UPS_OID.minLeft]), charge_pct: upsNum(g[UPS_OID.charge]),
    temp_c: upsNum(g[UPS_OID.temp]), input_line_bads: upsNum(g[UPS_OID.lineBads]), output_source: UPS_SRC[g[UPS_OID.outSource]] || null,
    load_pct: loads.length ? Math.max(...loads) : null, input_voltage: volts.length ? Math.min(...volts) : null, alarms_present: upsNum(g[UPS_OID.alarmsPresent]), alarms,
    last_test: UPS_TEST[g[UPS_OID.testResult]] || null, at: Date.now() };
}
async function upsCollect(dev, cred, mk = createSnmp) {
  const s = mk(Object.assign({ host: dev.ip, port: cred.port || 161, timeoutMs: 2500, retries: 1 }, cred));
  try {
    const keys = ['mfr', 'model', 'name', 'battStatus', 'onBattS', 'minLeft', 'charge', 'temp', 'lineBads', 'outSource', 'alarmsPresent', 'testResult'];
    const g = await s.get(keys.map((k) => UPS_OID[k]));
    // a table the card does not implement is an empty list (its values stay null), not a failed poll
    const W = async (o) => { try { return await s.walk(o, { maxRows: 100 }); } catch (e) { return []; } };
    const [inVoltage, outLoad, alarmDescr] = await Promise.all([W(UPS_OID.inVoltage), W(UPS_OID.outLoad), W(UPS_OID.alarmDescr)]);
    const r = upsParse(g, { inVoltage, outLoad, alarmDescr });
    if (r.battery == null && r.charge_pct == null && r.output_source == null) throw new Error('the device does not answer the UPS-MIB (1.3.6.1.2.1.33) - check the SNMP card and the community / user');
    return r;
  } finally { s.close(); }
}

/* ---------------- HPE Aruba EdgeConnect (Silver Peak) Orchestrator REST */
// Calls are made the way Aruba's own SDK (pyedgeconnect) makes them: API key in X-Auth-Token (no login, so no
// username / password and no CSRF cookie) and ?source=menu_rest_apis_id on every request. An Orchestrator that answers
// 406 to one Accept header is asked once more with Accept: */*.
const ecSrc = (u) => (/[?&]source=/.test(u) ? u : u + (u.includes('?') ? '&' : '?') + 'source=menu_rest_apis_id');
async function ecGet(url, o) {
  try { return await getJSON(ecSrc(url), o); }
  catch (e) { if (!/HTTP 406/.test(e.message)) throw e; return getJSON(ecSrc(url), Object.assign({}, o, { headers: Object.assign({}, o.headers, { Accept: '*/*' }) })); }
}
async function edgeconnect(dev, cred) {
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 443}`, o = { headers: { 'X-Auth-Token': cred.token }, tls: cred.tls, timeoutMs: 15000 };
  const out = { sdwan: { appliances: [], alarms: [] }, errors: [] };
  try {
    const a = await ecGet(base + (cred.appliances_path || '/gms/rest/appliance'), o);
    out.sdwan.appliances = (Array.isArray(a) ? a : []).map((x) => {
      const st = String(x.state === undefined ? x.status : x.state);
      return { name: x.hostName || x.hostname || x.name || '', site: x.site || x.group || '', ip: x.IP || x.ip || '', model: x.model || '', version: x.softwareVersion || '', state: st, up: /^(1|normal|up|reachable)$/i.test(st) };
    });
  } catch (e) { out.errors.push('appliances: ' + e.message); }
  try {
    const al = await ecGet(base + (cred.alarms_path || '/gms/rest/alarm/appliance?view=active'), o);
    const list = Array.isArray(al) ? al : Object.values(al || {}).flat();
    out.sdwan.alarms = list.slice(0, 500).map((x) => ({ severity: String(x.severity || x.severityLevel || '').toLowerCase(), appliance: x.hostName || x.applianceName || x.nePk || '', text: String(x.description || x.name || x.text || '').slice(0, 300), at: x.timeOccurredInMills || x.time || null }));
  } catch (e) { out.errors.push('alarms: ' + e.message); }
  if (out.errors.length >= 2) throw new Error('Orchestrator API unreachable: ' + out.errors[0]);
  // WAN optimisation (read-only aggregate statistics, last window): LAN-side vs WAN-side bytes per appliance and per application,
  // and loss / latency / jitter per tunnel. Field names differ between Orchestrator releases, so they are read by pattern and
  // the keys actually used are kept (wanopt.keys); a call that fails is noted, never fatal, and never read as zero.
  if (cred.wanopt !== false) {
    const win = Math.max(300, Math.min(86400, Number(cred.stats_window_s) || 3600)), end = Math.floor(Date.now() / 1000), q = `startTime=${end - win}&endTime=${end}&granularity=${win > 7200 ? 'hour' : 'minute'}`;
    const W = { at: Date.now(), window_s: win, appliances: [], applications: [], tunnels: [], keys: {}, errors: [] };
    const read = async (what, path, parse) => { try { const r = parse(await ecGet(base + path + (path.includes('?') ? '&' : '?') + q, o)); W[what] = r.rows; W.keys[what] = r.keys; } catch (e) { W.errors.push(what + ': ' + e.message); } };
    await read('appliances', cred.stats_appliance_path || '/gms/rest/stats/aggregate/appliance', ecStatRows);
    await read('applications', cred.stats_application_path || '/gms/rest/stats/aggregate/application', ecStatRows);
    await read('tunnels', cred.stats_tunnel_path || '/gms/rest/stats/aggregate/tunnel', ecTunnelRows);
    out.wanopt = W;
  }
  return out;
}
/* Orchestrator aggregate statistics come as an array of rows, or an object keyed by appliance (nePk) holding a row, an array of
 * rows, or an object keyed by application / tunnel. Rows are flattened with their keys; byte counters are found by pattern
 * (LAN_TX_BYTES, lanTxBytes, lan_rx ...; packet counters ignored). */
const ecNorm = (k) => String(k).toLowerCase().replace(/[^a-z0-9]/g, '');
function ecFlatten(j, depth = 0, ctx = {}) {
  const out = [];
  if (Array.isArray(j)) { for (const x of j) if (x && typeof x === 'object') out.push(...ecFlatten(x, depth + 1, ctx)); return out; }
  if (!j || typeof j !== 'object') return out;
  const vals = Object.values(j);
  if (vals.some((v) => typeof v === 'number' || (typeof v === 'string' && /^-?\d+(\.\d+)?$/.test(v)))) return [Object.assign({}, ctx, j)];
  if (depth > 3) return out;
  for (const [k, v] of Object.entries(j)) if (v && typeof v === 'object') out.push(...ecFlatten(v, depth + 1, Object.assign({}, ctx, ctx._k1 === undefined ? { _k1: k } : { _k2: k })));
  return out;
}
function ecPick(row, test) { for (const k of Object.keys(row)) { const n = ecNorm(k); if (test(n)) { const v = Number(row[k]); if (Number.isFinite(v)) return [k, v]; } } return [null, null]; }
const ecBytes = (side, dir) => (n) => n.startsWith(side + dir) && !/pkt|packet|count|rate/.test(n);
function ecStatRows(j) {
  const keys = {}, rows = ecFlatten(j).map((r) => {
    const [k1, lanTx] = ecPick(r, ecBytes('lan', 'tx')), [k2, lanRx] = ecPick(r, ecBytes('lan', 'rx')), [k3, wanTx] = ecPick(r, ecBytes('wan', 'tx')), [k4, wanRx] = ecPick(r, ecBytes('wan', 'rx'));
    for (const k of [k1, k2, k3, k4]) if (k) keys[k] = 1;
    const name = String(r.applicationName || r.application || r.appName || r.hostName || r.hostname || r.applianceName || r.name || r._k2 || r._k1 || '').slice(0, 120);
    return { name, appliance: String(r.hostName || r.applianceName || r.nePk || r._k1 || '').slice(0, 120), lan_tx: lanTx, lan_rx: lanRx, wan_tx: wanTx, wan_rx: wanRx };
  }).filter((r) => r.lan_tx != null || r.lan_rx != null || r.wan_tx != null || r.wan_rx != null);
  return { rows: rows.slice(0, 2000), keys: Object.keys(keys) };
}
function ecTunnelRows(j) {
  const keys = {}, rows = ecFlatten(j).map((r) => {
    const [kl, loss] = ecPick(r, (n) => /loss/.test(n) && !/pre/.test(n) && !/pkt|packet|count|bytes/.test(n) || /lossp(ct|ercent)/.test(n));
    const [kt, lat] = ecPick(r, (n) => /latency|rtt/.test(n) && !/count/.test(n)), [kj, jit] = ecPick(r, (n) => /jitter/.test(n));
    for (const k of [kl, kt, kj]) if (k) keys[k] = 1;
    return { name: String(r.tunnelName || r.tunnelId || r.tunnel || r.name || r._k2 || r._k1 || '').slice(0, 160), appliance: String(r.hostName || r.applianceName || r.nePk || r._k1 || '').slice(0, 120),
      state: r.operStatus || r.status || r.state || null, loss_pct: loss, latency_ms: lat, jitter_ms: jit };
  }).filter((r) => r.name && (r.loss_pct != null || r.latency_ms != null || r.jitter_ms != null || r.state));
  return { rows: rows.slice(0, 2000), keys: Object.keys(keys) };
}

/* ---- support contract + subscriptions as the device reports them ---- */
const day = (v) => { if (v == null || v === '' || /^never$/i.test(String(v))) return null; const n = typeof v === 'number' || /^\d{9,13}$/.test(String(v)) ? Number(v) * (String(v).length <= 10 ? 1000 : 1) : Date.parse(String(v)); return Number.isFinite(n) && n > 0 ? new Date(n).toISOString().slice(0, 10) : null; };
const SUPPORT_RE = /forticare|support|premium|platinum|standard support|partner enabled|hardware|firmware|enhanced/i;
function licItem(name, v, kindHint) {
  const expires = day(v.expires != null ? v.expires : v.expiry_date != null ? v.expiry_date : v.expiration);
  const status = String(v.status || v.type || '').toLowerCase();
  const expired = /expired/.test(status) || (!!expires && expires < new Date().toISOString().slice(0, 10));
  return { name: String(name).slice(0, 80), kind: kindHint || (SUPPORT_RE.test(name) ? 'support' : 'subscription'), status: status.slice(0, 40), expires, expired, level: v.level ? String(v.level).slice(0, 40) : undefined };
}
async function fortigateLicenses(dev, cred) {
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 443}`, o = { headers: { Authorization: 'Bearer ' + cred.token }, tls: cred.tls, timeoutMs: 15000 };
  const j = await getJSON(base + '/api/v2/monitor/license/status', o), r = j.results || {}, items = [];
  for (const [k, v] of Object.entries(r)) {
    if (!v || typeof v !== 'object') continue;
    if (k === 'forticare' && v.support && typeof v.support === 'object') {   // FortiCare: hardware / firmware / enhanced support entitlements
      for (const [sk, sv] of Object.entries(v.support)) if (sv && typeof sv === 'object') items.push(licItem('FortiCare ' + sk, sv, 'support'));
      if (v.status) items.push({ name: 'FortiCare registration', kind: 'support', status: String(v.status).toLowerCase().slice(0, 40), expires: null, expired: false });
      continue;
    }
    if (v.expires == null && v.expiry_date == null && v.status == null) continue;
    if (/^(unlicensed|none)$/i.test(String(v.status || '')) && v.expires == null) continue;   // a service never bought is not "expired"
    items.push(licItem(k.replace(/_/g, ' '), v));
  }
  return { at: Date.now(), serial: j.serial || '', items };
}
async function paloaltoLicenses(dev, cred) {
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 443}/api/`, o = { headers: { 'X-PAN-KEY': cred.token }, tls: cred.tls, timeoutMs: 20000 };
  const r = await getRaw(base + '?type=op&cmd=' + encodeURIComponent(PAN_LICENSE_INFO), o);
  if (r.status === 403 || r.status === 401) throw new Error('API refused the key (HTTP ' + r.status + ')');
  if (r.status !== 200) throw new Error('HTTP ' + r.status);
  const doc = X.parse(r.text); if (doc.attrs.status !== 'success') throw new Error(X.txt(doc, 'msg/line') || X.txt(doc, 'msg') || 'API error');
  const items = X.all(doc, 'result/licenses/entry').map((e) => {
    const name = X.txt(e, 'feature') || X.txt(e, 'description') || 'licence', it = licItem(name, { expires: X.txt(e, 'expires') });
    if (/^yes$/i.test(X.txt(e, 'expired'))) it.expired = true; it.status = it.expired ? 'expired' : 'valid';
    return it;
  });
  return { at: Date.now(), serial: (X.all(doc, 'result/licenses/entry')[0] && X.txt(X.all(doc, 'result/licenses/entry')[0], 'serial')) || '', items };
}
const licenses = (dev, cred) => (dev.vendor === 'fortigate' ? fortigateLicenses(dev, cred) : dev.vendor === 'paloalto' ? paloaltoLicenses(dev, cred) : Promise.resolve(null));


/* ---------------- Cisco UCS Manager XML API (read-only) */
// POST https://<ucsm>/nuova: aaaLogin (a read-only local user) -> configResolveClass for the chassis, blades, rack servers,
// running firmware and active faults -> aaaLogout (always, in finally). The login's own privileges (outPriv) are kept: an
// account with admin / aaa / any write privilege is over-privileged for monitoring and onboarding refuses it.
const ucsAttrs = (tag) => { const o = {}; String(tag).replace(/([A-Za-z_][\w.-]*)="([^"]*)"/g, (m, k, v) => { o[k] = v.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'); return m; }); return o; };
function ucsParse(xml, cls) { const out = []; const re = new RegExp('<' + cls + '\\s([^>]*?)/?>', 'g'); let m; while ((m = re.exec(String(xml || ''))) && out.length < 5000) out.push(ucsAttrs(m[1])); return out; }
const ucsEsc = (v) => String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const UCS_WRITE_PRIV = /(^|,)\s*(admin|aaa|ls-config|ls-server|ls-network|ls-storage|ls-security|pod-config|pod-security|ext-lan-config|ext-san-config|service-profile-config|fault|operations|power-mgmt)\s*(,|$)/i;
async function ucs(dev, cred, opts = {}) {
  const url = `https://${dev.api_host || dev.ip}:${cred.port || 443}/nuova`;
  const post = opts.post || ((body) => getRaw(url, { method: 'POST', body, headers: { 'Content-Type': 'application/xml' }, tls: cred.tls, timeoutMs: 15000 }));
  const out = { ucs: { chassis: [], blades: [], racks: [], firmware: [], faults: [] }, errors: [] };
  const login = await post(`<aaaLogin inName="${ucsEsc(cred.username)}" inPassword="${ucsEsc(cred.password)}" />`);
  const L = ucsParse(login.text, 'aaaLogin')[0] || {};
  if (login.status !== 200 || !L.outCookie) throw new Error('UCS Manager login failed' + (L.errorDescr ? ': ' + L.errorDescr : login.status !== 200 ? ' (HTTP ' + login.status + ')' : ''));
  const cookie = L.outCookie;
  out.ucs.privileges = String(L.outPriv || '').split(',').map((x) => x.trim()).filter(Boolean);
  out.ucs.read_only = out.ucs.privileges.length > 0 && !UCS_WRITE_PRIV.test(out.ucs.privileges.join(','));
  try {
    const q = async (cls) => { const r = await post(`<configResolveClass cookie="${ucsEsc(cookie)}" classId="${cls}" inHierarchical="false" />`); if (r.status !== 200) throw new Error(cls + ': HTTP ' + r.status); const e = ucsParse(r.text, 'configResolveClass')[0] || {}; if (e.errorCode) throw new Error(cls + ': ' + (e.errorDescr || e.errorCode)); return ucsParse(r.text, cls); };
    const step = async (cls, fn) => { try { fn(await q(cls)); } catch (e) { out.errors.push(String(e.message).slice(0, 200)); } };
    await step('topSystem', (r) => { const t = r[0] || {}; out.system = { name: t.name || '', address: t.address || '', uptime: t.systemUpTime || '', mode: t.mode || '' }; });
    await step('equipmentChassis', (r) => { out.ucs.chassis = r.map((c) => ({ dn: c.dn, model: c.model, serial: c.serial, oper: c.operState })); });
    await step('computeBlade', (r) => { out.ucs.blades = r.map((b) => ({ dn: b.dn, model: b.model, serial: b.serial, oper: b.operState, power: b.operPower, assigned: b.assignedToDn || '', cpus: +b.numOfCpus || null, mem_mb: +b.totalMemory || null })); });
    await step('computeRackUnit', (r) => { out.ucs.racks = r.map((b) => ({ dn: b.dn, model: b.model, serial: b.serial, oper: b.operState, power: b.operPower, assigned: b.assignedToDn || '', cpus: +b.numOfCpus || null, mem_mb: +b.totalMemory || null })); });
    await step('firmwareRunning', (r) => { out.ucs.firmware = r.filter((f) => /sys\/mgmt\/fw-system|fw-boot-loader|sys\/switch-[ab]\/mgmt\/fw-system/.test(f.dn || '')).map((f) => ({ dn: f.dn, version: f.version, type: f.type || '' })).slice(0, 50);
      const m = out.ucs.firmware.find((f) => /^sys\/mgmt\/fw-system$/.test(f.dn)); out.system = Object.assign(out.system || {}, { version: m ? 'UCS Manager ' + m.version : '' }); });
    await step('faultInst', (r) => { out.ucs.faults = r.filter((f) => !/cleared|info/i.test(f.severity || '')).map((f) => ({ severity: (f.severity || '').toLowerCase(), code: f.code, descr: String(f.descr || '').slice(0, 300), dn: f.dn, created: f.created, ack: f.ack === 'yes' })).slice(0, 500); });
    if (out.system) out.system.model = (out.ucs.chassis[0] && out.ucs.chassis[0].model) || (out.ucs.racks[0] && out.ucs.racks[0].model) || 'Cisco UCS';
  } finally {
    try { await post(`<aaaLogout inCookie="${ucsEsc(cookie)}" />`); } catch (e) { out.errors.push('logout: ' + String(e.message).slice(0, 120)); /* the session times out by itself on UCS Manager */ }
  }
  return out;
}

module.exports = { upsParse, upsCollect, UPS_OID, ecStatRows, ecTunnelRows, ucs, ucsParse, ping, snmpCollect, fortigate, paloalto, genian, edgeconnect, OID, licenses, fortigateLicenses, paloaltoLicenses, PAN_LICENSE_INFO };
