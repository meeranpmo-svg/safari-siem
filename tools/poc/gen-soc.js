#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-soc.js - writes ui/vendor/zyb-poc-soc.js: the POC data of the Security Operations pages, made by the REAL SIEM engines
 * (soc/alerts.js, soc/cases.js, soc/analyst.js through analyst-routes.js) from 45 days of SYNTHETIC alerts at the organisation's
 * head office, branches and project sites - so the overview, its insights, the alert queue and the map by location look exactly as
 * they will with real alerts. Addresses are private (10.x) per site; users and hosts are invented. Also the IP address plan
 * (/api/itam/ipam) that places the alerts on the Saudi map.   node tools/poc/gen-soc.js
 */
const fs = require('fs'), os = require('os'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), SIEM = path.join(ROOT, 'backend/siem');
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
const routes = require(path.join(SIEM, 'engine/soc/analyst-routes'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));

const SITES = [['Riyadh Head Office', '10.10.0.0/16', 9], ['Jeddah Branch', '10.20.0.0/16', 4], ['Dammam Branch', '10.30.0.0/16', 3], ['Jubail Project Site', '10.40.0.0/16', 4], ['Yanbu Project Site', '10.50.0.0/16', 2],
  ['Tabuk Project Site', '10.60.0.0/16', 2], ['Jazan Project Site', '10.70.0.0/16', 1], ['Khobar Office', '10.80.0.0/16', 2], ['Madinah Office', '10.90.0.0/16', 1]];
const RULES = [['BF-01', 'Brute force against a domain account', 3, 'credential-access', ['T1110']], ['EDR-02', 'Malware detected and quarantined', 2, 'execution', ['T1204']], ['PH-03', 'User clicked a phishing link', 3, 'initial-access', ['T1566']],
  ['NDR-04', 'Beaconing to an outside address', 4, 'command-and-control', ['T1071']], ['ADM-05', 'Administrator sign-in outside working hours', 2, 'privilege-escalation', ['T1078']], ['PS-06', 'Encoded PowerShell command', 3, 'execution', ['T1059.001']],
  ['VPN-07', 'VPN sign-in from a new country', 3, 'initial-access', ['T1133']], ['GRP-08', 'User added to a privileged group', 4, 'persistence', ['T1098']], ['USB-09', 'Mass storage device connected', 1, 'exfiltration', ['T1052']],
  ['SCAN-10', 'Internal port scan', 2, 'discovery', ['T1046']], ['EXF-11', 'Unusual outbound volume', 3, 'exfiltration', ['T1041']], ['IT-12', 'Impossible travel', 3, 'initial-access', ['T1078']]];
const USERS = ['a.harbi.poc', 's.qahtani.poc', 'm.shehri.poc', 'k.otaibi.poc', 'f.zahrani.poc', 'n.dosari.poc', 'h.ghamdi.poc', 'site.supervisor.poc', 'svc.backup.poc', 'admin.it.poc'];
let seed = 7; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const pick = (L) => L[Math.floor(rnd() * L.length)];
const DAY = 864e5, H = 36e5, NOW = Date.now();

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'poc-soc-'));
  let clock = NOW - 45 * DAY;
  const state = createState({ dir, log: { info() {}, warn() {}, error() {} } });
  const alerts = createAlerts({ state, now: () => clock }), cases = createCases({ state, alerts, now: () => clock });
  const api = fakeApi({ realRanks: true });
  routes.register(api, { state, alerts, cases, config: { soc_analyst: {} }, log: { info() {}, warn() {}, error() {} }, noTimers: true, now: () => NOW });
  const weight = SITES.reduce((s, x) => s + x[2], 0), site = () => { let r = rnd() * weight; for (const s of SITES) { r -= s[2]; if (r <= 0) return s; } return SITES[0]; };
  for (let d = 45; d >= 0; d--) {
    const wd = new Date(NOW - d * DAY + 3 * H).getUTCDay(), n = (wd === 5 || wd === 6 ? 6 : 16) + Math.floor(rnd() * 8) + (d < 3 ? 10 : 0);
    for (let i = 0; i < n; i++) {
      const [rid, rname, sev0, tactic, mitre] = pick(RULES), s = site(), oct = s[1].split('.')[1], ip = '10.' + oct + '.' + (1 + Math.floor(rnd() * 20)) + '.' + (10 + Math.floor(rnd() * 200)), user = pick(USERS);
      const host = s[0].split(' ')[0].slice(0, 3).toUpperCase() + '-PC-' + String(100 + Math.floor(rnd() * 800)) + '-POC';
      clock = NOW - d * DAY + Math.floor(rnd() * 20 * H) - 10 * H; if (clock > NOW - 5 * 60000) clock = NOW - 5 * 60000 - Math.floor(rnd() * H);
      const sev = Math.max(1, Math.min(4, sev0 + (rnd() < 0.15 ? 1 : 0) - (rnd() < 0.2 ? 1 : 0)));
      const { alert } = alerts.raise({ rule_id: 'POC-' + rid, rule_name: rname, severity: sev, tactic, mitre, group: { src_ip: ip, user, host }, fields: { site: s[0] }, summary: rname + ' - ' + user + ' on ' + host + ' (' + ip + ')', ts_first: clock, ts_last: clock, source: 'engine', src_type: pick(['fortigate', 'windows', 'm365', 'edr', 'ndr']), count: 1 + Math.floor(rnd() * 5) });
      // older alerts are worked: acknowledged, then closed true / false positive or benign; the last days stay open
      if (d >= 2 || rnd() < 0.3) {
        clock += Math.floor((0.2 + rnd() * 3) * H); if (clock > NOW) clock = NOW - 60000;
        try { alerts.setStatus(alert.id, 'in-progress', 'analyst.poc'); } catch (e) { /* already merged into an open alert */ }
        if (d >= 2 && rnd() < 0.85) { clock += Math.floor((1 + rnd() * 20) * H); if (clock > NOW) clock = NOW - 60000; const r = rnd(); try { alerts.setStatus(alert.id, r < 0.25 ? 'closed-true-positive' : r < 0.75 ? 'closed-false-positive' : 'closed-benign', 'analyst.poc'); } catch (e) { /* merged */ } }
      }
    }
  }
  // today: the alerts that need a person now - critical, repeated, on the busiest sites
  for (const [rid, rname, tactic, mitre, si, user] of [['NDR-04', 'Beaconing to an outside address', 'command-and-control', ['T1071'], 1, 'm.shehri.poc'], ['GRP-08', 'User added to a privileged group', 'persistence', ['T1098'], 0, 'admin.it.poc'], ['EXF-11', 'Unusual outbound volume', 'exfiltration', ['T1041'], 3, 'site.supervisor.poc'], ['BF-01', 'Brute force against a domain account', 'credential-access', ['T1110'], 0, 'svc.backup.poc'], ['PS-06', 'Encoded PowerShell command', 'execution', ['T1059.001'], 1, 'm.shehri.poc']]) {
    clock = NOW - Math.floor((1 + rnd() * 5) * H); const s = SITES[si], ip = '10.' + s[1].split('.')[1] + '.4.' + (30 + si);
    alerts.raise({ rule_id: 'POC-' + rid + '-NOW', rule_name: rname, severity: 4, tactic, mitre, group: { src_ip: ip, user, host: s[0].slice(0, 3).toUpperCase() + '-PC-0417-POC' }, fields: { site: s[0] }, summary: rname + ' - ' + user + ' (' + ip + ')', ts_first: clock - 3 * H, ts_last: clock, source: 'engine', src_type: 'edr', count: 40 + Math.floor(rnd() * 60) });
  }
  const get = async (p) => { const r = await api.call('GET', '/api/soc' + p, { role: 'admin', user: 'admin.poc' }); if (r.status !== 200) throw new Error(p + ' ' + r.status + ' ' + JSON.stringify(r.body).slice(0, 200)); return r.body; };
  const overview = await get('/soc/overview'), insights = await get('/soc/overview/insights');
  const list = alerts.list({ status: 'open', limit: 500 });
  const ipam = { subnets: SITES.map((s, i) => ({ id: 'sn' + (i + 1), cidr: s[1], name: s[0] + ' LAN', site: s[0], vlan: 10 + i, gateway: s[1].replace('0.0/16', '0.1'), purpose: 'users and servers', owner: 'network.poc', size: 65534, used: 300 + i * 40, free: 65234 - i * 40, util_pct: 1 })),
    kpis: { subnets: SITES.length }, proposed: [], reservations: [], findings: [], observed: [] };
  const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
    + '/* zyb-poc-soc.js - GENERATED by tools/poc/gen-soc.js (the real SIEM engines over SYNTHETIC alerts) - do not edit by hand. POC mode only. */\n'
    + '(function () {\n  var D = ' + JSON.stringify({ at: new Date(NOW).toISOString(), overview, insights, list, ipam }) + ';\n'
    + '  // epoch-millisecond times move forward with the page so the overview looks current\n'
    + '  var shift = Date.now() - Date.parse(D.at), mv = function (x) { if (Array.isArray(x)) return x.map(mv); if (x && typeof x === \'object\') { for (var k in x) { var v = x[k]; if (typeof v === \'number\' && v > 1.5e12 && v < 2.5e12) x[k] = v + shift; else if (v && typeof v === \'object\') mv(v); } } return x; };\n'
    + '  var S = function (o) { return function () { return mv(JSON.parse(JSON.stringify(o))); }; };\n'
    + '  window.ZYB_POC = (window.ZYB_POC || []).concat([\n'
    + '    { re: /^\\/api\\/soc\\/soc\\/overview$/, data: S(D.overview), pages: [\'soc-overview.html\'] },\n'
    + '    { re: /^\\/api\\/soc\\/soc\\/overview\\/insights$/, data: S(D.insights), pages: [\'soc-overview.html\'] },\n'
    + '    { re: /^\\/api\\/soc\\/alerts$/, data: S(D.list), pages: [\'soc-overview.html\'] },\n'
    + '    { re: /^\\/api\\/itam\\/ipam$/, data: D.ipam, pages: [\'soc-overview.html\'] },\n'
    + '  ]);\n})();\n';
  fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-soc.js'), out);
  fs.rmSync(dir, { recursive: true, force: true });
  console.log('wrote ui/vendor/zyb-poc-soc.js: ' + alerts.list({ status: 'all', limit: 500 }).total + ' synthetic alerts, ' + list.total + ' open, ' + Math.round(out.length / 1024) + ' KB');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
