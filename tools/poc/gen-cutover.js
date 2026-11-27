#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-cutover.js - writes ui/vendor/zyb-poc-cutover.js: the POC data of SIEM Cutover (siem-cutover.html), made by the REAL comparison
 * (engine/soc/cutover.js) over a SYNTHETIC 21-day parallel run: NewEvol exports and our side for invented sources of the head office,
 * branches and project sites (FortiGate, H3C, Windows, Hyper-V, Microsoft 365) with a few gaps to close. Every name is invented;
 * addresses are private (10.x) or documentation ranges.   node tools/poc/gen-cutover.js
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), C = require(path.join(ROOT, 'backend/siem/engine/soc/cutover.js'));
let seed = 33; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const DAY = 864e5, NOW = Date.parse('2026-11-26T09:00:00Z'), day = (k) => new Date(NOW - k * DAY + 3 * 36e5).toISOString().slice(0, 10);
const SITES = [['RUH', 1], ['JED', 2], ['DMM', 3], ['KHB', 4], ['JUB', 5], ['YNB', 6], ['TBK', 7], ['JZN', 8], ['MED', 9], ['ABH', 10]];
const SRC = [];
for (const [s, n] of SITES) { SRC.push(['FGT-' + s + '-01', '10.' + n + '.0.1', 'FortiGate', n === 1 ? 260000 : 60000]); SRC.push(['H3C-' + s + '-CORE', '10.' + n + '.0.2', 'H3C Comware', 9000]); }
for (let i = 1; i <= 4; i++) SRC.push(['DC0' + i + '-POC', '10.1.10.' + i, 'Windows Security', 90000]);
for (let i = 1; i <= 6; i++) SRC.push(['HV-RUH-0' + i, '10.1.20.' + i, 'Hyper-V host', 14000]);
SRC.push(['FMG-POC', '10.1.0.5', 'FortiManager', 3000], ['M365-TENANT', '', 'Microsoft 365', 45000], ['AX-ERP-POC', '10.1.30.4', 'Dynamics AX', 8000], ['EXCH-RELAY-POC', '10.1.30.9', 'SMTP relay', 6000], ['OLD-PROXY-POC', '10.1.0.9', 'Squid proxy', 22000], ['FAX-GW-POC', '10.1.40.2', 'Fax gateway', 300]);
const MISSING = new Set(['OLD-PROXY-POC', 'FAX-GW-POC']), LOW = { 'H3C-TBK-CORE': 0.55 }, SILENT = { 'FGT-JZN-01': [4, 5] }, DRIFT = { 'DC03-POC': 2 };
const ne = { sources: [], alerts: [], rules: [] }, ours = { volumes: [], alerts: [], rules: [] };
for (let k = 0; k < 21; k++) for (const [name, ip, type, base] of SRC) {
  const wd = new Date(NOW - k * DAY + 3 * 36e5).getUTCDay(), v = Math.round(base * (wd === 5 || wd === 6 ? 0.55 : 1) * (0.9 + rnd() * 0.2));
  ne.sources.push({ source: name, ip, type, day: day(k), events: v });
  if (MISSING.has(name)) continue;
  let r = (LOW[name] || 1) * (0.97 + rnd() * 0.06); if (SILENT[name] && SILENT[name].includes(k)) r = 0; if (DRIFT[name] === k) r = 0.45;
  ours.volumes.push({ d: day(k), host: name.toLowerCase().replace(/-poc$/, '') + '.safari-poc.example', ip, src_type: type.split(' ')[0].toLowerCase(), n: Math.round(v * r) });
}
for (let k = 0; k < 21; k++) ours.volumes.push({ d: day(k), host: 'ueba-poc', ip: '', src_type: 'ueba', n: 4000 }, { d: day(k), host: 'exchange-mailflow', ip: '', src_type: 'm365', n: 26000 });
const RULES = [['Brute force against domain controller', 'T1110', 'high', 'Password spraying / brute force', 'T1110.003'], ['Port scan from the internet', 'T1046', 'medium', 'Inbound port scan detection', 'T1046'],
  ['Admin group membership changed', 'T1098', 'high', 'Privileged group change', 'T1098'], ['Malware detected by FortiGate AV', 'T1204', 'high', 'FortiGate antivirus detection', 'T1204'],
  ['VPN login from new country', 'T1078', 'medium', 'Impossible travel / new country sign-in', 'T1078'], ['Firewall policy changed outside change window', 'T1562', 'high', 'Firewall configuration change off-hours', 'T1562'],
  ['Mass file deletion on file server', 'T1485', 'high', 'Mass deletion on file share', 'T1485'], ['Proxy category bypass', 'T1090', 'high', null], ['Fax gateway login failure', '', 'low', null],
  ['DNS tunnelling suspected', 'T1071', 'high', 'DNS tunnelling (entropy)', 'T1071.004'], ['Service account interactive logon', 'T1078', 'medium', 'Service account used interactively', 'T1078'], ['Hyper-V VM deleted', 'T1485', 'medium', 'Hyper-V virtual machine removed', 'T1485']];
for (const [n, t, s, o, ot] of RULES) { ne.rules.push({ name: n, technique: t, severity: s, enabled: 'true' }); if (o) ours.rules.push({ id: 'R-' + ours.rules.length, name: o, mitre: [ot] }); }
ours.rules.push({ id: 'R-UEBA', name: 'UEBA unusual behaviour', mitre: [] }, { id: 'R-NDR', name: 'NDR beaconing', mitre: ['T1071'] });
let id = 0;
for (let h = 3; h < 21 * 24; h += 3 + Math.floor(rnd() * 6)) {
  const r = RULES[Math.floor(rnd() * RULES.length)], host = SRC[Math.floor(rnd() * 26)][0], ts = NOW - h * 36e5, user = 'poc.user' + Math.floor(rnd() * 20);
  ne.alerts.push({ id: 'NE-' + (++id), time: new Date(ts).toISOString(), rule: r[0], severity: r[2], host, user, technique: r[1] });
  if (r[3] && rnd() < 0.93) ours.alerts.push({ id: 'ALR-POC-' + id, ts: ts + Math.floor(rnd() * 12) * 6e4, rule: r[3], host: host.toLowerCase().replace(/-poc$/, '') + '.safari-poc.example', user });
}
for (let i = 0; i < 26; i++) ours.alerts.push({ id: 'ALR-POC-U' + i, ts: NOW - Math.floor(rnd() * 20 * 24) * 36e5, rule: i % 2 ? 'UEBA unusual behaviour' : 'NDR beaconing', host: 'hv-ruh-0' + (1 + (i % 6)) + '.safari-poc.example', user: 'poc.user' + i });
const clean = (k, rows) => C.cleanRows(k, rows).rows;
const v = C.compare({ ne: { sources: clean('sources', ne.sources), alerts: clean('alerts', ne.alerts), rules: clean('rules', ne.rules) }, ours, now: NOW, days: 14 });
const at = new Date(NOW - 2 * DAY).toISOString();
v.imported = { sources: { rows: ne.sources.length, imported_at: at, by: 'admin.poc', file: 'newevol-sources-poc.csv', skipped: 0 }, alerts: { rows: ne.alerts.length, imported_at: at, by: 'admin.poc', file: 'newevol-alerts-poc.csv', skipped: 0 }, rules: { rows: ne.rules.length, imported_at: at, by: 'admin.poc', file: 'newevol-rules-poc.json', skipped: 0 } };
v.signoff = []; v.note = 'POC: an illustrative parallel run with invented sources. ' + v.note;
const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
  + '/* zyb-poc-cutover.js - GENERATED by tools/poc/gen-cutover.js (the real cutover comparison over a SYNTHETIC parallel run) - do not edit by hand. POC mode only. */\n'
  + '(function () {\n  var V = ' + JSON.stringify(v) + ', AT = ' + JSON.stringify(new Date(NOW).toISOString()) + ';\n'
  + '  function shift(x) { var d = Date.now() - Date.parse(AT); return JSON.parse(JSON.stringify(x), function (k, s) { if (typeof s !== \'string\') return s; var m = /^\\d{4}-\\d{2}-\\d{2}(T[\\d:.]+Z)?$/.exec(s); if (!m) return s; var n = new Date(Date.parse(m[1] ? s : s + \'T00:00:00Z\') + d).toISOString(); return m[1] ? n : n.slice(0, 10); }); }\n'
  + '  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\\/api\\/soc\\/cutover$/, pages: [\'siem-cutover.html\'], data: function () { return shift(V); } }, { re: /^\\/api\\/soc\\/cutover\\/signoff$/, data: { items: [] } }]);\n})();\n';
fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-cutover.js'), out);
console.log('wrote ui/vendor/zyb-poc-cutover.js: score ' + v.score + ', sources ' + v.kpis.ne_sources + ' (' + v.kpis.missing + ' missing), detections ' + v.kpis.matched_alerts + '/' + v.kpis.ne_alerts + ', rules ' + v.kpis.mapped_rules + '/' + v.kpis.ne_rules);
