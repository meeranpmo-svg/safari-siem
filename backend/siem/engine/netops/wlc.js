// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Wireless LAN controllers (inventory role "wlc") over SNMP, read only - the community / SNMPv3 user the poller already
 * holds for the device (inventory credentials). Vendors are plugins: VENDORS[name] = { match(sysObjectID), collect(snmp) }.
 *   collect(dev, cred, mk?)   → { vendor, aps[], ssids[], summary, at }      (called by poller.js for role "wlc")
 *   createWlcView({ inventory, poller, state, now? }).view()   → every controller, its APs, SSIDs, radios and channels
 * Cisco (AireOS controllers, and Catalyst 9800 where it answers the same tables): AIRESPACE-WIRELESS-MIB, enterprise 14179
 *   bsnAPTable           1.3.6.1.4.1.14179.2.2.1.1   .3 name  .4 location  .6 operation status (1 associated, 2 disassociating,
 *                                                     3 downloading)  .16 model  .17 serial  .19 IP           index = AP MAC
 *   bsnAPIfTable         1.3.6.1.4.1.14179.2.2.2.1   .2 radio type (1 802.11b/g = 2.4 GHz, 2 802.11a = 5 GHz)  .4 channel
 *                                                     .12 oper status (1 down, 2 up)  .15 clients on the radio   index = MAC.slot
 *   bsnAPIfLoadParameters 1.3.6.1.4.1.14179.2.2.13.1 .3 channel utilisation %                                index = MAC.slot
 *   bsnDot11EssTable     1.3.6.1.4.1.14179.2.1.1.1   .2 SSID  .6 admin status (1 enabled)  .38 clients       index = WLAN id
 * An AP that loses its controller drops out of bsnAPTable, so "down" APs are the ones this controller listed before and no
 * longer lists (kept per controller for 7 days, state "wlc_known"). No client MAC, name or IP is read - client COUNTS only
 * (per radio and per SSID), so no personal data leaves the controller (PDPL).
 * Aruba / HPE (WLSX-WLAN-MIB, enterprise 14823) is recognised and reported as "not supported yet": its table layout is not
 * verified against a real controller here, and the platform does not show numbers it cannot vouch for.
 */
const { createSnmp, str } = require('./snmp');

const SYS_OID = '1.3.6.1.2.1.1.2.0', SYS_DESCR = '1.3.6.1.2.1.1.1.0';
const B = '1.3.6.1.4.1.14179.2';
const CISCO = {
  apName: B + '.2.1.1.3', apLocation: B + '.2.1.1.4', apOper: B + '.2.1.1.6', apModel: B + '.2.1.1.16', apSerial: B + '.2.1.1.17', apIp: B + '.2.1.1.19',
  ifType: B + '.2.2.1.2', ifChannel: B + '.2.2.1.4', ifOper: B + '.2.2.1.12', ifUsers: B + '.2.2.1.15', chUtil: B + '.2.13.1.3',
  essSsid: B + '.1.1.1.2', essAdmin: B + '.1.1.1.6', essClients: B + '.1.1.1.38',
};
const AP_OPER = { 1: 'up', 2: 'disassociating', 3: 'downloading' };
const BAND = { 1: '2.4 GHz', 2: '5 GHz' };
const KNOWN_DAYS = 7;

const idx = (oid, base) => oid.slice(base.length + 1);
const col = (rows, base) => { const m = new Map(); for (const [o, v] of rows || []) m.set(idx(o, base), v); return m; };
const macOf = (i) => i.split('.').slice(0, 6).map((x) => Number(x).toString(16).padStart(2, '0')).join(':');
const num = (v) => (v == null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
const txt = (v, n) => str(v).replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, n || 120);

/* pure: walks → controller view (Cisco AIRESPACE) */
function parseCisco(w) {
  const name = col(w.apName, CISCO.apName), loc = col(w.apLocation, CISCO.apLocation), oper = col(w.apOper, CISCO.apOper), model = col(w.apModel, CISCO.apModel), serial = col(w.apSerial, CISCO.apSerial), ip = col(w.apIp, CISCO.apIp);
  const ifType = col(w.ifType, CISCO.ifType), ifCh = col(w.ifChannel, CISCO.ifChannel), ifOper = col(w.ifOper, CISCO.ifOper), ifUsers = col(w.ifUsers, CISCO.ifUsers), util = col(w.chUtil, CISCO.chUtil);
  const aps = new Map();
  for (const [i, v] of name) aps.set(i, { mac: macOf(i), name: txt(v, 80) || macOf(i), location: txt(loc.get(i), 120), model: txt(model.get(i), 60), serial: txt(serial.get(i), 60), ip: ip.has(i) ? String(ip.get(i)) : '',
    status: AP_OPER[oper.get(i)] || (oper.has(i) ? 'state ' + oper.get(i) : 'up'), clients: 0, radios: [] });
  const radioKeys = new Set([...ifType.keys(), ...ifCh.keys(), ...ifUsers.keys()]);
  for (const k of radioKeys) {
    const parts = k.split('.'), apKey = parts.slice(0, 6).join('.'), slot = Number(parts[6]);
    const ap = aps.get(apKey); if (!ap) continue;
    const t = ifType.get(k), users = num(ifUsers.get(k));
    const r = { slot, band: BAND[t] || (t != null ? 'type ' + t : 'unknown'), channel: num(ifCh.get(k)), oper: ifOper.get(k) === 2 ? 'up' : ifOper.get(k) === 1 ? 'down' : 'unknown', clients: users, ch_util_pct: num(util.get(k)) };
    ap.radios.push(r); if (users != null) ap.clients += users;
  }
  for (const ap of aps.values()) ap.radios.sort((a, b) => a.slot - b.slot);
  const ssidM = col(w.essSsid, CISCO.essSsid), adm = col(w.essAdmin, CISCO.essAdmin), cl = col(w.essClients, CISCO.essClients);
  const ssids = [...ssidM.entries()].map(([i, v]) => ({ wlan_id: Number(i), ssid: txt(v, 64), enabled: adm.has(i) ? adm.get(i) === 1 : null, clients: num(cl.get(i)) })).sort((a, b) => (b.clients || 0) - (a.clients || 0));
  const list = [...aps.values()].sort((a, b) => a.name.localeCompare(b.name));
  return { vendor: 'cisco', aps: list, ssids, summary: summarise(list, ssids) };
}
function summarise(aps, ssids) {
  const radios = aps.flatMap((a) => a.radios), utils = radios.map((r) => r.ch_util_pct).filter((v) => v != null);
  const channels = {}; for (const r of radios) if (r.channel != null && r.oper !== 'down') { const k = r.band + ' ch ' + r.channel; channels[k] = (channels[k] || 0) + 1; }
  return { aps: aps.length, aps_up: aps.filter((a) => a.status === 'up').length, aps_down: aps.filter((a) => a.status !== 'up').length, radios: radios.length, radios_down: radios.filter((r) => r.oper === 'down').length,
    clients: aps.reduce((n, a) => n + a.clients, 0), ssids: ssids.length, ssid_clients: ssids.some((s) => s.clients != null) ? ssids.reduce((n, s) => n + (s.clients || 0), 0) : null,
    max_ch_util_pct: utils.length ? Math.max(...utils) : null, busy_radios: utils.filter((u) => u >= 70).length, channels };
}

const VENDORS = {
  cisco: {
    label: 'Cisco (AIRESPACE-WIRELESS-MIB)',
    match: (oid, descr) => /^1\.3\.6\.1\.4\.1\.(9|14179)\./.test(oid) || /cisco/i.test(descr),
    async collect(s) {
      const W = async (o) => { try { return await s.walk(o, { maxRows: 20000 }); } catch (e) { return []; /* a table this controller does not implement: its values stay empty */ } };
      const keys = Object.keys(CISCO), rows = await Promise.all(keys.map((k) => W(CISCO[k])));
      const w = Object.fromEntries(keys.map((k, i) => [k, rows[i]]));
      if (!w.apName.length && !w.essSsid.length) throw new Error('the controller does not answer the AIRESPACE-WIRELESS-MIB (1.3.6.1.4.1.14179) - check the SNMP view / community allows it');
      return parseCisco(w);
    },
  },
  aruba: {
    label: 'Aruba / HPE (WLSX-WLAN-MIB)',
    match: (oid, descr) => /^1\.3\.6\.1\.4\.1\.14823\./.test(oid) || /aruba/i.test(descr),
    async collect() { throw new Error('Aruba / HPE controllers are recognised but not supported yet (WLSX-WLAN-MIB not verified here) - nothing is shown rather than unverified numbers'); },
  },
};
function vendorFor(oid, descr) { for (const [k, v] of Object.entries(VENDORS)) if (v.match(String(oid || ''), String(descr || ''))) return k; return null; }

async function collect(dev, cred, mk = createSnmp) {
  const s = mk(Object.assign({ host: dev.ip, port: cred.port || 161, timeoutMs: 3000, retries: 1 }, cred));
  try {
    const g = await s.get([SYS_OID, SYS_DESCR]);
    const oid = String(g[SYS_OID] || ''), descr = str(g[SYS_DESCR]);
    const v = vendorFor(oid, descr) || 'cisco';   // unknown: try the Cisco tables; a controller that lacks them says so
    const r = await VENDORS[v].collect(s);
    return Object.assign(r, { at: Date.now(), sys_object_id: oid });
  } finally { s.close(); }
}

/* the view: every controller (role wlc) with its last poll; APs it listed before and no longer lists are "not joined" */
function createWlcView({ inventory, poller, state, now } = {}) {
  const clock = now || Date.now, known = state ? state.collection('wlc_known') : null;
  function remember(id, wlc) {
    if (!known || !wlc || !wlc.at) return {};
    const k = known.get(id) || { id, aps: {}, at: 0 };
    if (k.at === wlc.at) return k.aps;
    const aps = Object.assign({}, k.aps), cut = clock() - KNOWN_DAYS * 86400000;
    for (const a of wlc.aps) aps[a.mac] = { name: a.name, model: a.model, location: a.location, last_seen: wlc.at };
    for (const [m, a] of Object.entries(aps)) if (a.last_seen < cut) delete aps[m];
    known.put({ id, aps, at: wlc.at });
    return aps;
  }
  function view() {
    const devs = inventory.list().filter((d) => d.role === 'wlc');
    const controllers = devs.map((d) => {
      const snap = poller.snapshot(d.id), w = snap && snap.wlc;
      const errs = ((snap && snap.errors) || []).filter((e) => /^wlc|snmp|credentials/.test(e));
      const polled = !!(d.poll && d.poll.snmp), credSet = !!(inventory.credentialSummary && inventory.credentialSummary(d.id).snmp);
      const base = { id: d.id, name: d.name, ip: d.ip, site: d.site, polled, credentials: credSet, last_poll: snap ? snap.at : null, errors: errs.slice(0, 3) };
      if (!w) return Object.assign(base, { state: !polled ? 'not-polled' : !credSet ? 'no-credentials' : !snap ? 'waiting' : 'error', aps: [], ssids: [], summary: null });
      const kn = remember(d.id, w), seen = new Set(w.aps.map((a) => a.mac));
      const missing = Object.entries(kn).filter(([m]) => !seen.has(m)).map(([m, a]) => ({ mac: m, name: a.name, model: a.model, location: a.location, ip: '', status: 'not-joined', last_seen: a.last_seen, clients: 0, radios: [] }));
      const aps = w.aps.concat(missing), sm = Object.assign({}, w.summary, { aps: aps.length, aps_down: w.summary.aps_down + missing.length, not_joined: missing.length });
      return Object.assign(base, { state: 'ok', vendor: w.vendor, at: w.at, aps, ssids: w.ssids, summary: sm });
    });
    const ok = controllers.filter((c) => c.summary), tot = (k) => ok.reduce((n, c) => n + (c.summary[k] || 0), 0);
    const ssidAgg = {}; for (const c of ok) for (const s of c.ssids) { const x = ssidAgg[s.ssid] = ssidAgg[s.ssid] || { ssid: s.ssid, controllers: 0, clients: null, enabled: false }; x.controllers++; if (s.clients != null) x.clients = (x.clients || 0) + s.clients; if (s.enabled) x.enabled = true; }
    const channels = {}; for (const c of ok) for (const [k, v] of Object.entries(c.summary.channels || {})) channels[k] = (channels[k] || 0) + v;
    const utils = ok.map((c) => c.summary.max_ch_util_pct).filter((v) => v != null);
    return { configured: devs.length > 0, reason: devs.length ? '' : 'No device with role "wlc" in the network inventory (AI Network Engineer → devices): add the controller with SNMP polling and read-only SNMP credentials.',
      controllers, summary: { controllers: devs.length, reporting: ok.length, aps: tot('aps'), aps_up: tot('aps_up'), aps_down: tot('aps_down'), not_joined: tot('not_joined'), clients: tot('clients'), ssids: Object.keys(ssidAgg).length,
        radios: tot('radios'), radios_down: tot('radios_down'), busy_radios: tot('busy_radios'), max_ch_util_pct: utils.length ? Math.max(...utils) : null },
      ssids: Object.values(ssidAgg).sort((a, b) => (b.clients || 0) - (a.clients || 0)), channels: Object.entries(channels).map(([k, v]) => ({ channel: k, radios: v })).sort((a, b) => b.radios - a.radios),
      vendors: Object.entries(VENDORS).map(([k, v]) => ({ id: k, label: v.label, supported: k === 'cisco' })) };
  }
  return { view };
}

module.exports = { collect, parseCisco, summarise, vendorFor, createWlcView, VENDORS, CISCO };
