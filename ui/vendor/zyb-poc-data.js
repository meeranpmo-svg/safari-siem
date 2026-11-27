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

  // ---------- Continuous Attack Surface (attack-surface.html: /api/itam/attack-surface, /api/itam/attack-surface/:id) ----------
  var SV = { 22: ['SSH', 1], 80: ['HTTP', 0, 1], 443: ['HTTPS', 0, 1], 3389: ['RDP', 1], 445: ['SMB', 1], 1433: ['SQL Server', 1, 0, 1], 8443: ['HTTPS-alt', 0, 1], 25: ['SMTP'], 21: ['FTP', 1], 10443: ['FortiGate SSL-VPN', 0, 1], 5986: ['WinRM', 1], 8080: ['HTTP-alt', 0, 1] };
  var svc = function (ports) { return ports.map(function (p) { var m = SV[p] || ['port ' + p]; return { port: p, name: m[0], risk: !!m[1], db: !!m[3], api: !!m[2], evidence: 'Asset Discovery saw port ' + p + ' open' }; }); };
  var AS = [
    ['as-01', 'web-portal-poc', 'server', 'Riyadh Head Office', 'it.poc', '203.0.113.10', [80, 443], { title: 'Apache HTTP Server path traversal', severity: 'critical', cvss: 9.8, cves: ['CVE-2021-41773'] }, 3, true, false],
    ['as-02', 'vpn-gw-poc', 'firewall', 'Riyadh Head Office', 'network.poc', '203.0.113.2', [443, 10443], { title: 'FortiOS SSL-VPN heap overflow', severity: 'critical', cvss: 9.6, cves: ['CVE-2023-27997'] }, 1, true, false],
    ['as-03', 'mail-gw-poc', 'server', 'Riyadh Head Office', 'it.poc', '203.0.113.25', [25, 443], { title: 'TLS 1.0 enabled on SMTP', severity: 'medium', cvss: 5.3, cves: [] }, 2, false, true],
    ['as-04', 'erp-api-poc', 'application', 'Riyadh Head Office', 'apps.poc', '203.0.113.40', [443, 8443], { title: 'API without rate limiting', severity: 'high', cvss: 7.5, cves: [] }, 2, true, true],
    ['as-05', 'jed-rdp-poc', 'server', 'Jeddah Branch', 'it.poc', '198.51.100.14', [3389], { title: 'RDP exposed to the internet', severity: 'high', cvss: 8.1, cves: ['CVE-2019-0708'] }, 1, false, false],
    ['as-06', 'jub-site-nvr-poc', 'cctv', 'Jubail Project Site', 'site.poc', '198.51.100.31', [80, 8080], { title: 'NVR default credentials', severity: 'high', cvss: 8.8, cves: [] }, 1, false, false],
    ['as-07', 'hr-portal-poc', 'application', 'Riyadh Head Office', 'hr.poc', '203.0.113.60', [443], { title: 'Outdated jQuery (XSS)', severity: 'medium', cvss: 6.1, cves: ['CVE-2020-11023'] }, 1, false, true],
    ['as-08', 'dmm-ftp-poc', 'server', 'Dammam Branch', 'it.poc', '198.51.100.52', [21, 22], { title: 'Anonymous FTP allowed', severity: 'high', cvss: 7.5, cves: [] }, 2, false, false],
    ['as-09', 'careers-site-poc', 'application', 'Riyadh Head Office', 'hr.poc', '203.0.113.71', [80, 443], null, 0, false, true],
    ['as-10', 'yanbu-gw-poc', 'firewall', 'Yanbu Project Site', 'network.poc', '198.51.100.90', [443], { title: 'Firmware behind the supported release', severity: 'medium', cvss: 5.9, cves: [] }, 1, false, false],
    ['as-11', 'sql-reports-poc', 'database', 'Riyadh Head Office', 'dba.poc', '203.0.113.80', [1433], { title: 'SQL Server reachable from the internet', severity: 'critical', cvss: 9.1, cves: [] }, 1, true, true],
    ['as-12', 'tabuk-site-pc-poc', 'workstation', 'Tabuk Project Site', 'site.poc', '198.51.100.110', [5986, 445], { title: 'SMBv1 enabled', severity: 'high', cvss: 8.1, cves: ['CVE-2017-0144'] }, 1, false, false],
  ];
  var band = function (e) { return e >= 75 ? 'critical' : e >= 50 ? 'high' : e >= 25 ? 'medium' : 'low'; };
  var surface = AS.map(function (a) { var S0 = svc(a[6]), sev = a[7] ? a[7].severity : null, e = Math.min(100, (sev === 'critical' ? 45 : sev === 'high' ? 30 : sev === 'medium' ? 15 : 0) + (a[7] && a[7].cves.length ? 10 : 0) + S0.length * 5 + (S0.some(function (x) { return x.risk; }) ? 20 : 0) + (a[9] ? 10 : 0) + (a[10] ? 10 : 0));
    var why = []; if (a[7]) why.push({ points: sev === 'critical' ? 45 : sev === 'high' ? 30 : 15, text: 'worst open finding: ' + a[7].title + ' (' + sev + (a[7].cvss ? ', CVSS ' + a[7].cvss : '') + ')' }); if (a[7] && a[7].cves.length) why.push({ points: 10, text: 'a known CVE (' + a[7].cves[0] + ')' }); why.push({ points: S0.length * 5, text: S0.length + ' exposed service(s)' });
    if (S0.some(function (x) { return x.risk; })) why.push({ points: 20, text: 'a risky service open to the internet: ' + S0.filter(function (x) { return x.risk; }).map(function (x) { return x.name; }).join(', ') }); if (a[9]) why.push({ points: 10, text: 'business-critical asset' }); if (a[10]) why.push({ points: 10, text: 'holds sensitive data' });
    return { id: a[0], name: a[1], type: a[2], site: a[3], owner: a[4], ips: [a[5]], host: a[1] + '.example.com', services: S0, apis: S0.filter(function (x) { return x.api; }).map(function (x) { return Object.assign({ why: 'web port open' }, x); }), open_findings: a[8], external_findings: a[8], worst: a[7], critical: a[9], sensitive: a[10], exposure: e, band: band(e), why: why, last_seen: iso(now - (a[8] + 1) * H), shadow: false }; });
  [['192.0.2.14', [3389, 443]], ['192.0.2.88', [8080]], ['198.51.100.200', [22, 80]]].forEach(function (x, i) { var S0 = svc(x[1]), e = Math.min(100, S0.length * 5 + (S0.some(function (y) { return y.risk; }) ? 20 : 0) + 15);
    surface.push({ id: 'shadow:' + x[0], name: x[0], type: 'unknown', site: '', owner: null, ips: [x[0]], host: null, services: S0, apis: S0.filter(function (y) { return y.api; }), open_findings: 0, external_findings: 0, worst: null, critical: false, sensitive: false, exposure: e, band: band(e), why: [{ points: 15, text: 'reachable but in no asset record (shadow)' }, { points: S0.length * 5, text: S0.length + ' exposed service(s)' }], last_seen: iso(now - (i + 2) * H), shadow: true }); });
  surface.sort(function (a, b) { return b.exposure - a.exposure; });
  var apis = []; surface.forEach(function (r) { r.apis.forEach(function (x) { apis.push({ asset_id: r.id, asset: r.name, ip: r.ips[0], port: x.port, name: x.name, why: x.why || 'web port open', exposure: r.exposure }); }); });
  var asTrend = []; for (var t = 29; t >= 0; t--) asTrend.push({ day: new Date(now - t * D).toISOString().slice(0, 10), exposed: 10 + Math.round(5 * (1 - t / 29)) + (t % 7 === 0 ? 1 : 0), apis: 9 + Math.round(4 * (1 - t / 29)), critical: t > 20 ? 1 : t > 8 ? 2 : 4 });
  var ASV = { generated_at: iso(now - 4 * 60000), connected: true, source_status: {}, surface: surface, apis: apis, chain_link: '/ai-pentest',
    kpis: { exposed: surface.length, shadow: 3, apis: apis.length, risky_services: surface.reduce(function (n, r) { return n + r.services.filter(function (x) { return x.risk; }).length; }, 0), critical: surface.filter(function (r) { return r.band === 'critical'; }).length, with_findings: surface.filter(function (r) { return r.open_findings > 0; }).length, changes: 4 },
    changes: { first: false, since: iso(now - 6 * H).slice(0, 16), items: [
      { kind: 'new_service', id: 'as-12', name: 'tabuk-site-pc-poc', text: 'New risky service on tabuk-site-pc-poc: SMB (port 445)', severity: 'high' },
      { kind: 'new_shadow', id: 'shadow:192.0.2.14', name: '192.0.2.14', text: 'New shadow surface 192.0.2.14 - RDP, HTTPS', severity: 'high' },
      { kind: 'new_finding', id: 'as-02', name: 'vpn-gw-poc', text: '1 new open finding(s) on vpn-gw-poc', severity: 'critical' },
      { kind: 'service_closed', id: 'as-03', name: 'mail-gw-poc', text: 'POP3 (port 110) closed on mail-gw-poc', severity: 'info' }] },
    trend: asTrend, note: 'Passive and read-only (POC: illustrative assets on documentation addresses). Nothing here sends a packet, scans or exploits.' };
  var asOne = function (u) { var id = decodeURIComponent(u.pathname.split('/').pop()), r = surface.filter(function (x) { return x.id === id; })[0] || surface[0], acts = [];
    if (r.worst) acts.push({ severity: r.worst.severity, action: 'Remediate "' + r.worst.title + '"' + (r.worst.cves.length ? ' (' + r.worst.cves.join(', ') + ')' : '') + ' - apply the vendor fix.', why: 'Reachable from the internet and known to attackers.', verify: 'Rescan the host after the fix.', finding: r.worst.title, source: 'scanner (POC)', cves: r.worst.cves });
    r.services.filter(function (x) { return x.risk; }).forEach(function (x) { acts.push({ severity: 'high', action: 'Close port ' + x.port + ' (' + x.name + ') or restrict it to the hosts that need it.', why: x.name + ' is a commonly attacked service.', verify: 'Confirm from outside that the port is closed.', finding: null, source: 'Asset Discovery' }); });
    return Object.assign({}, r, { chain_entry: [], actions: acts, actions_note: acts.length ? null : 'No action required.', note: 'POC: illustrative asset. To test an exposed service, file an engagement on the VAPT Workflow (four-eyes).' }); };

  window.ZYB_POC = (window.ZYB_POC || []).concat([
    { re: /^\/api\/itam\/attack-surface$/, data: ASV, pages: ['attack-surface.html'] },
    { re: /^\/api\/itam\/attack-surface\/[^/]+$/, data: asOne, pages: ['attack-surface.html'] },
    { re: /^\/api\/soc\/ndr$/, data: NDR, pages: ['ndr.html'] },
    { re: /^\/api\/soc\/ndr\/suppressions$/, data: SUP, pages: ['ndr.html'] },
  ]);
})();
