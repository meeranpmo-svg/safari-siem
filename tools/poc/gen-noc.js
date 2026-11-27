#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-noc.js - writes ui/vendor/zyb-poc-noc.js: the POC data of the NOC Summary, made by the REAL NOC engine (netops/noc-intel.js:
 * health, probable causes, anomalies, flapping) over a SYNTHETIC inventory of the head office, branches and project sites (H3C core and
 * access switches, FortiGates, site gateways) and 40 poll cycles of synthetic readings - one site gateway down, an interface that
 * flaps, a firewall whose CPU climbs, links running hot. The NPM node list is built the way the /netops/npm route builds it.
 *   node tools/poc/gen-noc.js
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), { createNocIntel } = require(path.join(ROOT, 'backend/siem/engine/netops/noc-intel.js'));
let seed = 5; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const SITES = [['Riyadh', 10, 'HQ'], ['Jeddah', 20, 'BR'], ['Dammam', 30, 'BR'], ['Jubail', 40, 'SITE'], ['Yanbu', 50, 'SITE'], ['Tabuk', 60, 'SITE'], ['Khobar', 80, 'OF'], ['Madinah', 90, 'OF']];
const devs = [];
for (const [site, oct, kind] of SITES) {
  const ab = site.slice(0, 3).toUpperCase();
  devs.push({ id: 'fw-' + ab.toLowerCase(), name: 'FW-' + ab + '-' + kind + '-POC', vendor: 'fortigate', ip: '10.' + oct + '.0.1', site, role: 'firewall', model: kind === 'HQ' ? 'FortiGate-200F' : 'FortiGate-60F' });
  devs.push({ id: 'core-' + ab.toLowerCase(), name: 'SW-' + ab + '-CORE-POC', vendor: 'h3c-comware', ip: '10.' + oct + '.0.2', site, role: kind === 'HQ' ? 'core' : 'distribution', model: 'H3C S6520X' });
  const acc = kind === 'HQ' ? 6 : kind === 'BR' ? 3 : 2;
  for (let i = 1; i <= acc; i++) devs.push({ id: 'acc-' + ab.toLowerCase() + i, name: 'SW-' + ab + '-ACC' + i + '-POC', vendor: 'h3c-comware', ip: '10.' + oct + '.0.' + (10 + i), site, role: 'access', model: 'H3C S5130S' });
  if (kind === 'SITE') devs.push({ id: 'gw-' + ab.toLowerCase(), name: 'GW-' + ab + '-SITE-POC', vendor: 'other', ip: '10.' + oct + '.0.254', site, role: 'gateway', model: '4G/LTE router' });
}
for (const d of devs) d.poll = { ping: true, snmp: d.vendor !== 'other', api: d.vendor === 'fortigate' };
const T_END = Date.now(), STEP = 5 * 60000, N = 40;
let clock = T_END - N * STEP, cycle = 0;
function snap(d) {
  const late = cycle >= N - 3, down = late && (d.id === 'gw-yan' || d.id === 'acc-yan1' || d.id === 'acc-yan2' || d.id === 'core-yan');
  const base = { at: clock, ok: !down, errors: [], reach: down ? { sent: 3, received: 0, loss_pct: 100, rtt_avg_ms: null } : { sent: 3, received: 3, loss_pct: 0, rtt_avg_ms: (d.site === 'Riyadh' ? 2 : 18) + rnd() * 4 } };
  if (down) return Object.assign(base, { errors: ['no reply to ping from the engine server (3 sent)'] });
  let cpu = 12 + rnd() * 15; if (d.id === 'fw-jed' && cycle > N - 6) cpu = 88 + rnd() * 6; if (d.role === 'core') cpu += 10;
  const sys = { cpu_pct: cpu, mem_pct: 40 + rnd() * 20 + (d.vendor === 'fortigate' ? 15 : 0), model: d.model, version: d.vendor === 'fortigate' ? '7.2.8' : '7.1.070' };
  const ifs = [];
  const nIf = d.role === 'access' ? 4 : 6;
  for (let i = 1; i <= nIf; i++) {
    let util = 8 + rnd() * 30, oper = 'up';
    if (d.id === 'core-riy' && i === 1) util = 82 + rnd() * 8;
    if (d.id === 'fw-riy' && i === 2) util = 74 + rnd() * 6;
    if (d.id === 'acc-jed2' && i === 3 && cycle >= N - 12) oper = cycle % 2 ? 'down' : 'up';
    ifs.push({ name: (d.vendor === 'fortigate' ? 'port' : 'GE1/0/') + i, oper, util_in: util, util_out: util * 0.6, err_per_min: d.id === 'acc-dam1' && i === 2 ? 14 : 0, speed_mbps: 1000 });
  }
  if (d.id === 'acc-jed2' && cycle >= N - 12 && cycle % 2) base.errors = ['GE1/0/3 down'];
  return Object.assign(base, { ok: true, system: sys, interfaces: ifs });
}
const SN = new Map();
const inventory = { list: () => devs, get: (id) => devs.find((d) => d.id === id) || null };
const poller = { snapshot: (id) => SN.get(id) || null, stats: () => ({ cycles: N, devices: devs.length, last_cycle_at: new Date(T_END).toISOString(), interval_s: 300 }) };
const NOC = createNocIntel({ inventory, poller, config: {}, log: { info() {}, warn() {}, error() {} }, now: () => clock });
for (cycle = 0; cycle < N; cycle++) { clock = T_END - (N - cycle) * STEP; for (const d of devs) { const s = snap(d); s.at = new Date(clock).toISOString(); SN.set(d.id, s); } NOC.sample(); }
clock = T_END;
const noc = Object.assign(NOC.view(), { ai: { enabled: false, reason: 'POC: the AI shift brief needs the AI engine' } });

// the NPM node list, built the way GET /netops/npm builds it (netops/routes.js)
const VLAB = { fortigate: 'Fortinet', 'h3c-comware': 'H3C Comware', other: 'Other' };
const nodes = devs.map((d) => { const s = SN.get(d.id), errs = (s.errors || []).length, state = s.ok === false ? 'critical' : errs ? 'warning' : 'up', e0 = (s.errors || [])[0];
  return { id: d.id, name: d.name, vendor: d.vendor, ip: d.ip, site: d.site, role: d.role, state, reason: state === 'critical' ? e0 || 'no source answered' : state === 'warning' ? e0 : '',
    response_ms: s.reach && s.reach.rtt_avg_ms != null ? Math.round(s.reach.rtt_avg_ms) : null, cpu: s.system ? Math.round(s.system.cpu_pct) : null, mem: s.system ? Math.round(s.system.mem_pct) : null, model: d.model, last: s.at }; });
const counts = { up: 0, warning: 0, critical: 0, unknown: 0, unpolled: 0 }; for (const n of nodes) counts[n.state]++;
const byV = {}; for (const n of nodes) (byV[VLAB[n.vendor] || 'Other'] = byV[VLAB[n.vendor] || 'Other'] || []).push(n);
const ifaces = []; for (const d of devs) for (const i of (SN.get(d.id).interfaces || [])) { const util = Math.max(i.util_in || 0, i.util_out || 0); ifaces.push({ node: d.name, node_id: d.id, name: i.name, oper: i.oper, rx: Math.round(i.util_in), tx: Math.round(i.util_out), util: Math.round(util), err_per_min: i.err_per_min }); }
ifaces.sort((a, b) => b.util - a.util);
const npm = { counts, total: nodes.length, vendors: Object.keys(byV).sort().map((v) => ({ vendor: v, count: byV[v].length, nodes: byV[v].sort((a, b) => a.name.localeCompare(b.name)) })), interfaces: ifaces.slice(0, 200), high_interfaces: ifaces.filter((i) => i.util >= 70).length, polled: true, poller: poller.stats() };
const GEO = require(path.join(ROOT, 'tools/build-poc-geomap.js')).data();   // the live office map in POC mode: the same illustrative offices as the POC office map
const dev = {}; for (const d of devs) dev[d.id] = { device: d, snapshot: SN.get(d.id) };
const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
  + '/* zyb-poc-noc.js - GENERATED by tools/poc/gen-noc.js (the real NOC engine over SYNTHETIC devices and poll readings) - do not edit by hand. POC mode only. */\n'
  + '(function () {\n  var NOC = ' + JSON.stringify(noc) + ', NPM = ' + JSON.stringify(npm) + ', DEV = ' + JSON.stringify(dev) + ', AT = ' + T_END + ';\n'
  + '  var mv = function (x) { var sh = Date.now() - AT, ISO = /^\\d{4}-\\d{2}-\\d{2}T/; (function w(o) { if (Array.isArray(o)) return o.forEach(w); if (o && typeof o === "object") for (var k in o) { var v = o[k]; if (typeof v === "number" && v > 1.5e12 && v < 2.5e12) o[k] = v + sh; else if (typeof v === "string" && ISO.test(v)) { var t = Date.parse(v); if (!isNaN(t)) o[k] = new Date(t + sh).toISOString(); } else if (v && typeof v === "object") w(v); } })(x); return x; };\n'
  + '  var C = function (o) { return function () { return mv(JSON.parse(JSON.stringify(o))); }; }, P = [\'npm-summary.html\', \'noc-overview.html\'];\n'
  + '  window.ZYB_POC = (window.ZYB_POC || []).concat([\n'
  + '    { re: /^\\/api\\/soc\\/netops\\/noc$/, data: C(NOC), pages: P },\n'
  + '    { re: /^\\/api\\/soc\\/netops\\/npm$/, data: C(NPM), pages: P },\n'
  + '    { re: /^\\/api\\/soc\\/netops\\/devices\\/[^/]+$/, data: function (u) { var id = decodeURIComponent(u.pathname.split(\'/\').pop()); return mv(JSON.parse(JSON.stringify(DEV[id] || DEV[Object.keys(DEV)[0]]))); }, pages: P },\n'
  + '    { re: /^\\/api\\/soc\\/netops\\/geomap$/, data: ' + JSON.stringify(GEO) + ', pages: [\'network-geomap.html\'] },\n'
  + '  ]);\n})();\n';
fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-noc.js'), out);
console.log('wrote ui/vendor/zyb-poc-noc.js: ' + devs.length + ' devices, health ' + (noc.health && (noc.health.score != null ? noc.health.score : JSON.stringify(noc.health).slice(0, 60))) + ', causes ' + ((noc.causes || []).length) + ', ' + Math.round(out.length / 1024) + ' KB');
