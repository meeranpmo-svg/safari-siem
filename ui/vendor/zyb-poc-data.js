// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-poc-data.js - ILLUSTRATIVE data for POC mode (vendor/zyb-poc.js), used only while the "POC data" switch is on. Invented host
 * names, internal 10.x addresses, outside addresses from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
 * no person's data. Each entry: re (the API path it answers), data (the response, or a function of the URL). Times are relative to
 * now so the pages look current. Add a page by adding the responses its own API returns. */
(function () {
  'use strict';
  var now = Date.now(), H = 3600000, D = 24 * H, iso = function (ms) { return new Date(ms).toISOString(); };
  
  // ---------- Network Detection & Response (ndr.html: /api/soc/ndr, /api/soc/ndr/suppressions) ----------
  var det = [
    { kind: 'beacon', host: '10.20.4.37', dst: '203.0.113.45:443', severity: 'high', why: '288 connections every ~300 s (spread 0.02) to 203.0.113.45:443', evidence: { period_s: 300, spread: 0.02, connections: 288 } },
    { kind: 'exfil', host: '10.20.4.37', dst: '', severity: 'high', why: '2,140 MB out today, usual 85 MB (z 11.4)', evidence: { today: 2140e6, usual: 85e6, z: 11.4 } },
    { kind: 'beacon', host: '10.40.2.15', dst: '198.51.100.23:8443', severity: 'medium', why: '96 connections every ~900 s (spread 0.09) to 198.51.100.23:8443', evidence: { period_s: 900, spread: 0.09, connections: 96 } },
    { kind: 'lateral', host: '10.10.8.21', dst: '', severity: 'high', why: '34 internal hosts reached on admin ports today (usual 2)', evidence: { today: 34, usual: 2, z: 15.2 } },
    { kind: 'lateral', host: '10.10.12.9', dst: '', severity: 'medium', why: '7 internal hosts reached on admin ports today - it never did this before', evidence: { today: 7, usual: 0 } },
    { kind: 'exfil', host: '10.10.3.44', dst: '', severity: 'medium', why: '640 MB out today, usual 120 MB (z 5.1)', evidence: { today: 640e6, usual: 120e6, z: 5.1 } },
    { kind: 'country', host: '10.30.1.12', dst: 'Seychelles', severity: 'low', why: 'First traffic to Seychelles in 30 days (42 connections, 380 KB)', evidence: { connections: 42, bytes: 380e3 } },
    { kind: 'country', host: '10.20.4.37', dst: 'Moldova', severity: 'low', why: 'First traffic to Moldova in 30 days (12 connections, 95 KB)', evidence: { connections: 12, bytes: 95e3 } },
    { kind: 'beacon', host: '10.50.1.8', dst: '192.0.2.77:53', severity: 'medium', why: '144 connections every ~600 s (spread 0.11) to 192.0.2.77:53', evidence: { period_s: 600, spread: 0.11, connections: 144 } },
    { kind: 'country', host: '10.40.2.15', dst: 'Belize', severity: 'low', why: 'First traffic to Belize in 30 days (8 connections, 41 KB)', evidence: { connections: 8, bytes: 41e3 } },
  ];
  var pts = { beacon: 35, exfil: 30, lateral: 30, country: 10 }, hosts = {};
  det.forEach(function (d) { var h = hosts[d.host] = hosts[d.host] || { host: d.host, risk: 0, reasons: [] }; h.risk = Math.min(100, h.risk + pts[d.kind]); h.reasons.push({ kind: d.kind, points: pts[d.kind], why: d.why }); });
  var hostList = Object.keys(hosts).map(function (k) { return hosts[k]; }).sort(function (a, b) { return b.risk - a.risk; });
  var trend = []; for (var i = 13; i >= 0; i--) { var day = new Date(now - i * D).toISOString().slice(0, 10), base = [2, 1, 0, 3, 1, 2, 1, 0, 2, 3, 1, 2, 4, 0][13 - i]; trend.push({ date: day, beacon: i < 3 ? 3 : base % 2, exfil: i < 2 ? 2 : 0, lateral: i < 1 ? 2 : (base > 2 ? 1 : 0), country: base % 3 === 0 ? 1 : 0 }); }
  var NDR = { ran: true, at: iso(now - 12 * 60000), detections: det, hosts: hostList, suppressed: 3, errors: [], trend: trend };
  var SUP = { suppressions: [
    { id: 'SUP-00003', host: '10.10.1.20', dst: '198.51.100.10:443', reason: 'Antivirus update server (POC)', status: 'approved', proposed_by: 'analyst.poc', decided_by: 'secmgr.poc', expires: iso(now + 60 * D).slice(0, 10) },
    { id: 'SUP-00002', host: '10.10.1.31', kind: 'exfil', reason: 'Nightly backup to the DR site (POC)', status: 'approved', proposed_by: 'analyst.poc', decided_by: 'secmgr.poc', expires: iso(now + 90 * D).slice(0, 10) },
    { id: 'SUP-00004', host: '10.50.1.8', dst: '192.0.2.77:53', reason: 'Site gateway DNS forwarder? (POC)', status: 'proposed', proposed_by: 'analyst.poc', expires: iso(now + 30 * D).slice(0, 10) }] };

  window.ZYB_POC = (window.ZYB_POC || []).concat([
    { re: /^\/api\/soc\/ndr$/, data: NDR, pages: ['ndr.html'] },
    { re: /^\/api\/soc\/ndr\/suppressions$/, data: SUP, pages: ['ndr.html'] },
  ]);
})();
