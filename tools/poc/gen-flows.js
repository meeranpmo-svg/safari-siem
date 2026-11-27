#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-flows.js - writes ui/vendor/zyb-poc-flows.js: the POC data of Network Flows, made by the REAL flow engine (soc/flows.js
 * summary() and drill()) over a stand-in database that answers each of its queries with SYNTHETIC firewall traffic of the head
 * office, branches and project sites - so every chart of the page looks exactly as it will with real FortiGate logs. Inside addresses
 * are 10.x; outside addresses come from the documentation ranges. Every range (15 min, 1 h, 24 h, 7 days) and both directions.
 *   node tools/poc/gen-flows.js
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), F = require(path.join(ROOT, 'backend/siem/engine/soc/flows.js'));
let seed = 3; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const FWS = [['FW-RUH-HQ-POC', 'fortigate', 1], ['FW-JED-BR-POC', 'fortigate', 0.45], ['FW-DMM-BR-POC', 'fortigate', 0.35], ['FW-JUB-SITE-POC', 'fortigate', 0.3], ['FW-YNB-SITE-POC', 'fortigate', 0.18], ['FW-TBK-SITE-POC', 'fortigate', 0.12]];
const IN_C = [['China', 0.22, 0.9], ['Russia', 0.14, 0.95], ['United States', 0.16, 0.35], ['Netherlands', 0.1, 0.6], ['India', 0.08, 0.7], ['Germany', 0.06, 0.4], ['Brazil', 0.05, 0.85], ['Viet Nam', 0.05, 0.9], ['Saudi Arabia', 0.09, 0.05], ['Iran', 0.05, 0.98]];
const OUT_C = [['United States', 0.3, 0.02], ['Ireland', 0.18, 0.01], ['Saudi Arabia', 0.2, 0.01], ['Netherlands', 0.08, 0.03], ['United Arab Emirates', 0.06, 0.02], ['Germany', 0.05, 0.02], ['Singapore', 0.04, 0.05], ['United Kingdom', 0.04, 0.02], ['Seychelles', 0.01, 0.6], ['Moldova', 0.005, 0.8]];
const APPS = [['Microsoft.Office.365', 0.24, 0], ['Oracle.Fusion.Cloud', 0.12, 0], ['SSL', 0.12, 0.02], ['DNS', 0.1, 0.01], ['Windows.Update', 0.08, 0], ['Microsoft.Teams', 0.07, 0], ['Google.Services', 0.05, 0.02], ['WhatsApp', 0.04, 0.3], ['YouTube', 0.03, 0.6], ['BitTorrent', 0.01, 1], ['Tor', 0.003, 1], ['Zoom', 0.03, 0]];
const PORTS = [['tcp', 443, 0.55, 0.01], ['udp', 53, 0.12, 0.01], ['tcp', 80, 0.08, 0.05], ['udp', 443, 0.06, 0.02], ['tcp', 3389, 0.03, 0.97], ['tcp', 22, 0.03, 0.92], ['tcp', 445, 0.02, 0.99], ['tcp', 25, 0.02, 0.2], ['udp', 123, 0.02, 0], ['tcp', 8443, 0.02, 0.1], ['tcp', 1433, 0.01, 1], ['tcp', 23, 0.01, 1]];
const ZONES = [['wan', 0.45, 0.68], ['lan', 0.3, 0.02], ['site-vpn', 0.12, 0.05], ['dmz', 0.08, 0.2], ['guest', 0.05, 0.15]];
const DOC = ['203.0.113.', '198.51.100.', '192.0.2.'];

function fakeCh(o) {
  const scale = { 15: 0.25, 60: 1, 1440: 24, 10080: 168 }[o.range] * 52000 * (o.dir === 'out' ? 1.6 : 1), dirIn = o.dir === 'in';
  const split = (L, k) => L.map(([name, w, deny]) => { const n = Math.round(scale * w * (0.85 + rnd() * 0.3)), d = Math.round(n * deny); return Object.assign({ n, a: n - d, d }, k(name)); });
  return { async query(sql) {
    const tag = (/\/\*q:(\w+)\*\//.exec(sql) || [])[1];
    switch (tag) {
      case 'hist': return Array.from({ length: o.buckets }, (_, b) => { const t = o.from + b * o.step, h = (new Date(t).getUTCHours() + 3) % 24, wd = new Date(t + 3 * 3600e3).getUTCDay(), work = (wd !== 5 && wd !== 6 && h >= 7 && h <= 18) ? 1 : 0.35;
        const n = Math.round(scale / o.buckets * work * (0.8 + rnd() * 0.4) * (b === o.buckets - 6 ? 2.4 : 1)), d = Math.round(n * (dirIn ? 0.62 : 0.04) * (b === o.buckets - 6 ? 1.8 : 1)); return { b, a: n - d, d, by: n * (dirIn ? 9000 : 42000) }; });
      case 'countries': return split(dirIn ? IN_C : OUT_C, (c) => ({ c })).map((r) => Object.assign(r, { by: r.n * 30000 }));
      case 'zsrc': return split(ZONES, (z) => ({ z }));
      case 'zdst': return split(ZONES.slice().reverse(), (z) => ({ z }));
      case 'ports': { const out = []; for (const [proto, port, w, deny] of PORTS) { const n = Math.round(scale * w), d = Math.round(n * deny); if (n - d) out.push({ action: 'allowed', proto, port, n: n - d }); if (d) out.push({ action: 'blocked', proto, port, n: d }); } return out.sort((a, b) => b.n - a.n); }
      case 'apps': { const out = []; for (const [app, w, deny] of APPS) { const n = Math.round(scale * w), d = Math.round(n * deny); if (n - d) out.push({ action: 'allowed', app, n: n - d }); if (d) out.push({ action: 'blocked', app, n: d }); } return out.sort((a, b) => b.n - a.n); }
      case 'firewalls': return FWS.map(([host, src_type, w]) => ({ host, src_type, n: Math.round(1.4e6 * w), last: Date.now() - Math.floor(rnd() * 60000) }));
      case 'talkers': return Array.from({ length: 10 }, (_, i) => { const L = dirIn ? IN_C : OUT_C, P = PORTS[i % PORTS.length], A = APPS[i % APPS.length], ext = DOC[i % 3] + (10 + i * 7), int = '10.' + [10, 20, 30, 40][i % 4] + '.' + (2 + i) + '.' + (20 + i * 3), n = Math.round(scale * 0.02 / (i + 1));
        return { src_ip: dirIn ? ext : int, c: L[i % L.length][0], dst_ip: dirIn ? int : ext, proto: P[0], port: P[1], app: A[0], flows: n, deny: dirIn ? Math.round(n * P[3]) : 0, by: n * 52000 }; });
      case 'conv': return Array.from({ length: 12 }, (_, i) => ({ src_ip: '10.' + [10, 20, 30, 40, 50][i % 5] + '.' + (3 + i) + '.' + (11 + i * 5), fw: FWS[i % FWS.length][0], app: APPS[i % APPS.length][0], dst_ip: DOC[i % 3] + (40 + i), flows: Math.round(scale * 0.01 / (i + 1)), by: Math.round(9e9 / (i + 1)) }));
      case 'dev_port': return [].concat(...PORTS.map(([, port, w]) => [{ cur: 1, v: String(port), n: Math.round(1000 * w * (port === 3389 ? 3 : 1)) }, { cur: 0, v: String(port), n: Math.round(1000 * w) }]));
      case 'dev_country': return [].concat(...(dirIn ? IN_C : OUT_C).map(([c, w]) => [{ cur: 1, v: c, n: Math.round(1000 * w * (c === 'Iran' || c === 'Seychelles' ? 4 : 1)) }, { cur: 0, v: c, n: Math.round(1000 * w) }]));
      case 'dev_app': return [].concat(...APPS.map(([a, w]) => [{ cur: 1, v: a, n: Math.round(1000 * w * (a === 'BitTorrent' ? 5 : 1)) }, { cur: 0, v: a, n: Math.round(1000 * w) }]));
      case 'd_total': return [{ a: Math.round(scale * 0.08), d: Math.round(scale * 0.03), by: scale * 4e5, first: o.from + 60000, last: o.to - 30000 }];
      case 'd_src': return Array.from({ length: 8 }, (_, i) => ({ v: dirIn ? DOC[i % 3] + (60 + i) : '10.10.' + (4 + i) + '.' + (30 + i), n: Math.round(scale * 0.01 / (i + 1)), d: dirIn ? Math.round(scale * 0.006 / (i + 1)) : 0 }));
      case 'd_dst': return Array.from({ length: 8 }, (_, i) => ({ v: dirIn ? '10.10.1.' + (10 + i) : DOC[i % 3] + (80 + i), n: Math.round(scale * 0.01 / (i + 1)), d: dirIn ? Math.round(scale * 0.005 / (i + 1)) : 0 }));
      case 'd_svc': return PORTS.slice(0, 8).map(([proto, port, w, deny], i) => ({ v: proto + '/' + port + (APPS[i] ? ' ' + APPS[i][0] : ''), n: Math.round(scale * w * 0.1), d: Math.round(scale * w * 0.1 * deny) }));
      case 'd_country': return (dirIn ? IN_C : OUT_C).slice(0, 8).map(([c, w, deny]) => ({ v: c, n: Math.round(scale * w * 0.1), d: Math.round(scale * w * 0.1 * deny) }));
      case 'd_zones': return ZONES.map(([z, w]) => ({ v: z, n: Math.round(scale * w * 0.1), d: Math.round(scale * w * 0.02) }));
      case 'netflow': default: return [];
    }
  } };
}

(async () => {
  const NOW = Date.now(), S = {}, Dr = {};
  for (const range of [15, 60, 1440, 10080]) for (const dir of ['in', 'out']) {
    const o = F.options({ range: String(range), dir }, NOW), ch = fakeCh(o);
    const s = F.analyse(await F.summary(ch, 'siem', o, true)); s.source = 'fw'; s.netflow_available = false; S[range + dir] = s;
    Dr[range + dir] = await F.drill(ch, 'siem', o, { country: 'POC' });
  }
  const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
    + '/* zyb-poc-flows.js - GENERATED by tools/poc/gen-flows.js (the real flow engine over SYNTHETIC firewall traffic) - do not edit by hand. POC mode only. */\n'
    + '(function () {\n  var S = ' + JSON.stringify(S) + ', DR = ' + JSON.stringify(Dr) + ', AT = ' + NOW + ';\n'
    + '  var pick = function (M, u) { var r = u.searchParams.get(\'range\') || \'60\', d = u.searchParams.get(\'dir\') === \'out\' ? \'out\' : \'in\', x = JSON.parse(JSON.stringify(M[r + d] || M[\'60\' + d])), sh = Date.now() - AT;\n'
    + '    (function mv(o) { if (Array.isArray(o)) return o.forEach(mv); if (o && typeof o === \'object\') for (var k in o) { var v = o[k]; if (typeof v === \'number\' && v > 1.5e12 && v < 2.5e12) o[k] = v + sh; else if (v && typeof v === \'object\') mv(v); } })(x); return x; };\n'
    + '  window.ZYB_POC = (window.ZYB_POC || []).concat([\n'
    + '    { re: /^\\/api\\/soc\\/flows\\/summary$/, data: function (u) { return pick(S, u); }, pages: [\'network-flows.html\'] },\n'
    + '    { re: /^\\/api\\/soc\\/flows\\/drill$/, data: function (u) { return pick(DR, u); }, pages: [\'network-flows.html\'] },\n'
    + '  ]);\n})();\n';
  fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-flows.js'), out);
  console.log('wrote ui/vendor/zyb-poc-flows.js: 8 summaries and drill-downs, ' + Math.round(out.length / 1024) + ' KB');
})().catch((e) => { console.error(e); process.exit(1); });
