// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-servers.js - the server pages of Servers & Virtualization (servers.html, vmware-servers.html, windows-servers.html,
 * exchange-servers.html, solaris-servers.html, oracle-linux-servers.html). The page names its platform in
 * <main data-platform="…">; everything else is here so the six pages cannot drift apart.
 *   IT Asset Management GET /api/itam/servers?platform=  - every server / VM in the asset register on that platform, with its
 *     backup, end of life, patches and (Solaris / Linux) the operating system read over SSH, findings with the fix
 *   VMware: /api/itam/virt/capacity (ESXi hosts, datastores from vCenter); Windows / Exchange: the SIEM's AI administrators
 *     (/api/soc/sysadmin/targets?role=) - their own health checks over WinRM.
 * A source that is not connected says so and what to connect; nothing on these pages is sample data. No inline handlers.
 * Estate intelligence (computed here from the same answer, nothing new on the server): physical / virtual / private-cloud mix by
 * site; a 0-100 health score per server, itemised from its findings; compound risk (2+ of end of support, no or failed backup,
 * critical patches missing, OS reading failing); readings far worse than the same platform's peers (robust z on the median and
 * MAD - early warning below the fixed thresholds); hardware refresh by quarter from warranty end and OS end of support within a
 * year; consolidation candidates (physical, one reading, light load and memory - an indicator, check the peak) and powered-off
 * VMs; how much of the estate each source covers. */
(function () {
  'use strict';
  var main = document.querySelector('main[data-platform]'); if (!main) return;
  var P = main.getAttribute('data-platform') || '', D = window.zybDetail, esc = D.esc, $ = function (id) { return document.getElementById(id); };
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', V = null, Q = { q: '', f: '' }, SIEM = null, VC = null, RUNMSG = '', ADDRMSG = '';
  var UNIX = { solaris: 1, oracle_linux: 1, linux: 1 };
  var PAGES = { '': 'servers.html', vmware: 'vmware-servers.html', windows: 'windows-servers.html', exchange: 'exchange-servers.html', solaris: 'solaris-servers.html', oracle_linux: 'oracle-linux-servers.html' };
  var css = '.sv-k{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:0 0 12px}.sv-t{background:var(--raise,#1A1D25);border:1px solid var(--edge,#252933);border-radius:10px;padding:10px 12px;text-align:left;font:inherit;color:inherit}'
    + 'button.sv-t{cursor:pointer}.sv-t .l{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mute,#8C93A1)}.sv-t .v{font-size:24px;font-weight:700}.sv-t .s{font-size:12px;color:var(--mute,#8C93A1)}'
    + '.sv-t.bad .v{color:#ff7b72}.sv-t.warn .v{color:#e3b341}.sv-t.ok .v{color:#3fb950}.sv-t.na .v{color:var(--mute,#8C93A1);font-size:15px}.sv-t.on{outline:2px solid #79b8ff}'
    + '.sv-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 8px}.sv-p{display:inline-block;font-size:11px;font-weight:600;padding:1px 8px;border-radius:9px;background:rgba(255,255,255,.08);white-space:nowrap;margin:1px 2px 1px 0}'
    + '.sv-p.critical,.sv-p.bad{background:rgba(248,81,73,.18);color:#ff7b72}.sv-p.high,.sv-p.warn{background:rgba(227,179,65,.16);color:#e3b341}.sv-p.ok{background:rgba(63,185,80,.16);color:#3fb950}.sv-p.medium{background:rgba(121,184,255,.15);color:#79b8ff}'
    + '.sv-na{color:var(--mute,#8C93A1);background:var(--raise,#1A1D25);border:1px dashed var(--border,#2E3440);border-radius:9px;padding:10px;font-size:13px}.sv-m{color:var(--mute,#8C93A1);font-size:12px}tr.sv-r{cursor:pointer}tr.sv-r:hover td{background:rgba(255,255,255,.03)}'
    + '#sv-q,#sv-cred{font:inherit;background:var(--raise,#1A1D25);color:var(--text,#ECEEF2);border:1px solid var(--border,#2E3440);border-radius:7px;padding:5px 9px}'
    + '.sv-fix{font-size:12px;color:var(--mute,#8C93A1);margin-top:2px}.sv-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 12px}.sv-tabs a{font-size:13px;padding:5px 11px;border-radius:8px;border:1px solid var(--border,#2E3440);color:inherit;text-decoration:none}.sv-tabs a.on{border-color:#79b8ff;color:#79b8ff}';
  var st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);

  function get(url) {
    return new Promise(function (ok) {
      var x = new XMLHttpRequest(); x.zybQuiet = true; x.open('GET', url); x.withCredentials = true; x.timeout = 90000;
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; } ok({ status: x.status, json: j && typeof j === 'object' ? j : null }); };
      x.onerror = x.ontimeout = function () { ok({ status: 0, json: null }); }; x.send();
    });
  }
  function post(url, b) {
    return new Promise(function (ok) {
      var x = new XMLHttpRequest(); x.zybQuiet = true; x.open('POST', url); x.withCredentials = true; x.timeout = 300000; x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; } ok({ status: x.status, json: j }); };
      x.onerror = x.ontimeout = function () { ok({ status: 0, json: null }); }; x.send(JSON.stringify(b || {}));
    });
  }
  function why(r, what) { return r.status === 403 ? what + ' needs the operator role (server names, addresses and owners)' : r.status === 404 ? what + ' is not installed on the server - run the update (update-platform.ps1)' : r.status === 0 ? what + ' did not answer' : r.json && r.json.error ? String(r.json.error) : what + ' did not answer with data (HTTP ' + r.status + ')'; }
  function na(t) { return '<div class="sv-na">' + esc(t) + '</div>'; }
  function pill(t, k) { return '<span class="sv-p ' + esc(k || '') + '">' + esc(t) + '</span>'; }
  function tile(l, v, s, c, f) { return '<' + (f ? 'button type="button" data-f="' + esc(f) + '"' : 'div') + ' class="sv-t ' + (c || '') + (f && Q.f === f ? ' on' : '') + '"><div class="l">' + esc(l) + '</div><div class="v">' + esc(String(v)) + '</div><div class="s">' + esc(s || '') + '</div></' + (f ? 'button' : 'div') + '>'; }
  function dt(t) { if (!t) return '–'; var d = new Date(t); return isNaN(d) ? esc(String(t)).slice(0, 16) : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }); }
  function ago(t) { var d = typeof t === 'number' ? t : Date.parse(t); if (!isFinite(d)) return '–'; var m = Math.round((Date.now() - d) / 60000); return m < 60 ? m + ' min ago' : m < 2880 ? Math.round(m / 60) + ' h ago' : Math.round(m / 1440) + ' d ago'; }
  var LBL = { vmware: 'VMware', windows: 'Windows', exchange: 'Exchange', solaris: 'Solaris', oracle_linux: 'Oracle Linux', linux: 'Linux', nutanix: 'Nutanix', unknown: 'OS unknown' };
  var BK = { protected: ['backed up', 'ok'], stale: ['backup old', 'warn'], failed: ['backup failed', 'bad'], none: ['no backup', 'bad'], exempt: ['exempt', ''] };

  function tabs() {
    var h = '<nav class="sv-tabs" aria-label="Server platforms">' + Object.keys(PAGES).map(function (k) { return '<a href="' + PAGES[k] + '"' + (k === P ? ' class="on" aria-current="page"' : '') + '>' + esc(k ? LBL[k] : 'All servers') + (V && V.platforms && k && V.platforms[k] ? ' · ' + V.platforms[k].servers : '') + '</a>'; }).join('') + '</nav>';
    $('sv-tabs').innerHTML = h;
  }
  function osCell(x) {
    var r = x.os_read || {}, v = r.server;
    if (!UNIX[(x.platforms || []).filter(function (p) { return UNIX[p]; })[0]]) return '';
    if (!v) return '<div class="sv-m">OS not read' + (x.ssh && !x.ssh.credential ? ' - no SSH login' : x.ssh && x.ssh.host_key !== 'trusted' ? ' - host key ' + esc(x.ssh.host_key) : r.error_class ? ' - ' + esc(r.error_class) : '') + '</div>';
    var f = x.fs_fullest, m = v.mem_total_mb && v.mem_avail_mb != null ? Math.round(v.mem_avail_mb / v.mem_total_mb * 100) : null;
    return '<div class="sv-m">' + (f ? esc(f.mount) + ' ' + esc(f.used_pct) + '% · ' : '') + (m != null ? m + '% mem free · ' : '') + (v.load5 != null ? 'load ' + esc(v.load5) + (v.ncpu ? '/' + esc(v.ncpu) : '') + ' · ' : '') + 'read ' + esc(ago(r.at)) + (r.via ? ' (' + esc(r.via) + ')' : '') + '</div>';
  }
  function visible() {
    var q = Q.q.toLowerCase();
    return V.servers.filter(function (x) {
      if (q && [x.name, x.ip, x.os_shown, x.owner, x.site, x.vm_name, x.host_name].join(' ').toLowerCase().indexOf(q) < 0) return false;
      if (Q.f === 'issues') return x.worst === 'critical' || x.worst === 'high';
      if (Q.f === 'eol') return x.lifecycle && x.lifecycle.status === 'eol';
      if (Q.f === 'backup') return x.backup && (x.backup.status === 'none' || x.backup.status === 'failed');
      if (Q.f === 'notread') return (x.platforms || []).some(function (p) { return UNIX[p]; }) && !(x.os_read && x.os_read.server);
      if (Q.f === 'off') return x.power === 'off';
      if (Q.f === 'on') return x.power === 'on';
      return true;
    });
  }
  // ---- estate intelligence
  var IQ = { tab: 'risk' }, SW = { critical: 30, high: 15, medium: 6, low: 2 };
  function med(a) { var x = a.slice().sort(function (p, q) { return p - q; }), n = x.length; return n ? (n % 2 ? x[(n - 1) / 2] : (x[n / 2 - 1] + x[n / 2]) / 2) : null; }
  function kindOf(x) { return x.type === 'vm' || x.hypervisor || x.vm_name ? (x.hypervisor === 'nutanix' ? 'Nutanix VM' : x.hypervisor === 'vcenter' ? 'VMware VM' : 'Virtual machine') : 'Physical'; }
  function intel() {
    var S = V.servers, F = V.findings, now = Date.now(), byId = {};
    S.forEach(function (x) { byId[x.id] = { x: x, f: [] }; }); F.forEach(function (f) { if (byId[f.asset_id]) byId[f.asset_id].f.push(f); });
    var rows = S.map(function (x) { var b = byId[x.id], pts = {}, why = [], sc = 100;
      b.f.forEach(function (f) { var w = SW[f.severity] || 0; pts[f.kind] = (pts[f.kind] || 0) + w; });
      Object.keys(pts).sort(function (p, q) { return pts[q] - pts[p]; }).forEach(function (k) { var w = Math.min(pts[k], 40); sc -= w; why.push(k + ' -' + w); });
      var bk = x.backup && x.backup.status, risk = [];
      if (x.lifecycle && x.lifecycle.status === 'eol') risk.push('end of support'); if (bk === 'none' || bk === 'failed') risk.push(bk === 'none' ? 'no backup' : 'backup failed');
      if (x.patch && x.patch.critical) risk.push(x.patch.critical + ' critical patches'); if (x.os_read && x.os_read.error) risk.push('OS reading failing');
      var v = (x.os_read && x.os_read.server) || null;
      return { x: x, kind: kindOf(x), score: Math.max(0, sc), why: why, risk: risk, mem: v && v.mem_total_mb ? Math.round(100 * (v.mem_avail_mb || 0) / v.mem_total_mb) : null,
        lpc: v && v.ncpu && v.load5 != null ? Math.round(100 * v.load5 / v.ncpu) / 100 : null, fs: x.fs_fullest ? x.fs_fullest.used_pct : null, up: v && v.uptime_s != null ? Math.round(v.uptime_s / 86400) : null, plat: (x.platforms || [])[0] || 'unknown' }; });
    // peers: same platform, 5+ readings, robust z
    var out = [], groups = {}; rows.forEach(function (r) { (groups[r.plat] = groups[r.plat] || []).push(r); });
    Object.keys(groups).forEach(function (g) { var G = groups[g];
      [['fs', 'fullest file system', '%', 1], ['lpc', 'load per CPU', '', 1], ['mem', 'memory available', '%', -1]].forEach(function (m) {
        var vals = G.map(function (r) { return r[m[0]]; }).filter(function (v) { return v != null; }); if (vals.length < 5) return;
        var md = med(vals), mad = med(vals.map(function (v) { return Math.abs(v - md); })) || Math.max(0.05, Math.abs(md) * 0.1);
        G.forEach(function (r) { var v = r[m[0]]; if (v == null) return; var z = m[3] * 0.6745 * (v - md) / mad; if (z >= 3.5) out.push({ r: r, t: r.x.name + ': ' + m[1] + ' ' + v + m[2] + ' against a usual ' + md + m[2] + ' on ' + (LBL[g] || g), z: Math.round(z * 10) / 10 }); }); }); });
    // refresh forecast: physical servers by warranty end quarter, OS end of support within a year
    var q = {}, qk = function (t) { var d = new Date(t); return d.getUTCFullYear() + ' Q' + (Math.floor(d.getUTCMonth() / 3) + 1); }, expired = 0;
    rows.forEach(function (r) { if (r.kind !== 'Physical' || !r.x.warranty_end) return; var t = Date.parse(r.x.warranty_end); if (!isFinite(t)) return; if (t < now) { expired++; return; } if (t < now + 2 * 365 * 864e5) { var k = qk(t); q[k] = (q[k] || 0) + 1; } });
    var eol12 = rows.filter(function (r) { return r.x.lifecycle && r.x.lifecycle.days != null && r.x.lifecycle.days >= 0 && r.x.lifecycle.days <= 365; });
    var consol = rows.filter(function (r) { return r.kind === 'Physical' && r.lpc != null && r.lpc < 0.1 && r.mem != null && r.mem >= 60; });
    var off = rows.filter(function (r) { return r.x.power === 'off'; });
    var cov = [['Backup known', function (x) { return !!x.backup; }], ['Patches known', function (x) { return !!x.patch; }], ['End of support known', function (x) { return !!x.lifecycle; }],
      ['OS read (Unix)', function (x) { return !(x.platforms || []).some(function (p) { return UNIX[p]; }) || !!(x.os_read && x.os_read.server); }], ['Owner recorded', function (x) { return !!x.owner; }], ['Site recorded', function (x) { return !!x.site; }]]
      .map(function (c) { var n = S.filter(c[1]).length; return { l: c[0], n: n, pct: S.length ? Math.round(100 * n / S.length) : 0 }; });
    return { rows: rows, peers: out.sort(function (a, b) { return b.z - a.z; }), q: q, expired: expired, eol12: eol12, consol: consol, off: off, cov: cov };
  }
  function drawIntel() {
    var el = $('sv-intel'); if (!el) { el = document.createElement('div'); el.id = 'sv-intel'; el.className = 'card'; el.style.marginTop = '12px'; var kk = $('sv-kk'); kk.parentNode.insertBefore(el, kk.nextSibling); }
    if (!V || !V.servers.length) { el.hidden = true; return; } el.hidden = false;
    var I = intel(), R = I.rows, n = R.length, kinds = {}, sites = {};
    R.forEach(function (r) { kinds[r.kind] = (kinds[r.kind] || 0) + 1; var st = r.x.site || 'no site'; (sites[st] = sites[st] || {})[r.kind] = (sites[st][r.kind] || 0) + 1; });
    var KC = { 'Physical': '#e3b341', 'VMware VM': '#79b8ff', 'Nutanix VM': '#3fb950', 'Virtual machine': '#a5a5ff' };
    var mix = '<div style="display:flex;height:14px;border-radius:7px;overflow:hidden;margin:6px 0">' + Object.keys(kinds).map(function (k) { return '<i title="' + esc(k + ': ' + kinds[k]) + '" style="display:block;width:' + (kinds[k] / n * 100).toFixed(1) + '%;background:' + (KC[k] || '#8C93A1') + '"></i>'; }).join('') + '</div>'
      + '<div class="sv-m">' + Object.keys(kinds).map(function (k) { return '<span style="color:' + (KC[k] || '#8C93A1') + '">■</span> ' + esc(k + ' ' + kinds[k]); }).join(' · ') + '</div>';
    var hs = [0, 0, 0, 0]; R.forEach(function (r) { hs[r.score >= 85 ? 0 : r.score >= 60 ? 1 : r.score >= 30 ? 2 : 3]++; });
    var avg = Math.round(R.reduce(function (a, r) { return a + r.score; }, 0) / n);
    var comp = R.filter(function (r) { return r.risk.length >= 2; }).sort(function (a, b) { return b.risk.length - a.risk.length || a.score - b.score; });
    var srow = function (r, extra) { return '<tr class="sv-r" data-id="' + esc(r.x.id) + '"><td><b>' + esc(r.x.name) + '</b><div class="sv-m">' + esc(r.kind + (r.x.site ? ' · ' + r.x.site : '')) + '</div></td><td title="' + esc(r.why.join(', ') || 'no finding') + '">' + pill(String(r.score), r.score >= 85 ? 'ok' : r.score >= 60 ? 'warn' : 'bad') + '</td><td>' + extra + '</td></tr>'; };
    var T = { risk: ['Compound risk', comp.length], health: ['Lowest health', R.filter(function (r) { return r.score < 60; }).length], peers: ['Worse than peers', I.peers.length], life: ['Refresh & end of support', I.expired + I.eol12.length], cap: ['Consolidate / reclaim', I.consol.length + I.off.length], cov: ['Data coverage', ''] };
    var body = '';
    if (IQ.tab === 'risk') body = comp.length ? '<div class="tw"><table><thead><tr><th>Server</th><th>Health</th><th>Risks together</th></tr></thead><tbody>' + comp.slice(0, 50).map(function (r) { return srow(r, r.risk.map(function (k) { return pill(k, 'bad'); }).join('')); }).join('') + '</tbody></table></div><p class="sv-m">Two or more of these on one server is the worst place to be: an unsupported system with no recovery path or open critical patches. Start here.</p>' : na('No server carries two of: end of support, no or failed backup, critical patches missing, OS reading failing.');
    if (IQ.tab === 'health') body = '<div class="tw"><table><thead><tr><th>Server</th><th>Health</th><th>What took the points</th></tr></thead><tbody>' + R.slice().sort(function (a, b) { return a.score - b.score; }).slice(0, 40).map(function (r) { return srow(r, '<span class="sv-m">' + esc(r.why.join(', ') || 'no finding') + '</span>'); }).join('') + '</tbody></table></div><p class="sv-m">100 minus the findings: critical 30, high 15, medium 6, low 2 points each, at most 40 per kind. Hover the number for the breakdown.</p>';
    if (IQ.tab === 'peers') body = I.peers.length ? I.peers.slice(0, 30).map(function (p) { return '<div style="margin:0 0 6px">' + pill('z ' + p.z, p.z >= 6 ? 'bad' : 'warn') + ' <a href="#" data-sv-open="' + esc(p.r.x.id) + '">' + esc(p.t) + '</a></div>'; }).join('') + '<p class="sv-m">A reading far from the same platform\'s other servers (robust z ≥ 3.5) is an early warning, even below the fixed thresholds. Needs 5 readings on the platform.</p>' : na('No reading stands out from its peers (needs 5 OS readings on a platform - Solaris and Linux read over SSH).');
    if (IQ.tab === 'life') { var qs = Object.keys(I.q).sort(), mx = Math.max.apply(null, qs.map(function (k) { return I.q[k]; }).concat([I.expired, 1]));
      body = '<div style="display:grid;grid-template-columns:110px 1fr 40px;gap:4px 10px;align-items:center;font-size:12.5px">' + [['Expired', I.expired, '#ff7b72']].concat(qs.map(function (k) { return [k, I.q[k], '#e3b341']; })).map(function (b) { return '<span>' + esc(b[0]) + '</span><span style="height:10px;border-radius:5px;background:rgba(255,255,255,.08);overflow:hidden"><i style="display:block;height:100%;width:' + (b[1] / mx * 100).toFixed(1) + '%;background:' + b[2] + '"></i></span><b>' + esc(b[1]) + '</b>'; }).join('') + '</div>'
        + '<p class="sv-m">Physical servers by hardware warranty end (next 2 years). ' + esc(R.filter(function (r) { return r.kind === 'Physical' && !r.x.warranty_end; }).length + ' physical server(s) have no warranty date recorded.') + '</p>'
        + (I.eol12.length ? '<div class="tw"><table><thead><tr><th>Server</th><th>Health</th><th>Operating system support ends</th></tr></thead><tbody>' + I.eol12.sort(function (a, b) { return a.x.lifecycle.days - b.x.lifecycle.days; }).map(function (r) { return srow(r, esc((r.x.lifecycle.product || 'OS') + ' in ' + r.x.lifecycle.days + ' days' + (r.x.lifecycle.eol ? ' (' + r.x.lifecycle.eol + ')' : ''))); }).join('') + '</tbody></table></div>' : '<p class="sv-m">No operating system reaches end of support in the next 12 months' + (V.sources && !V.sources.lifecycle ? ' - End of Life is not connected, so this is not measured' : '') + '.</p>'); }
    if (IQ.tab === 'cap') body = '<div style="font-weight:700;margin:0 0 4px">Virtualisation candidates</div>' + (I.consol.length ? '<div class="tw"><table><thead><tr><th>Server</th><th>Health</th><th>Reading</th></tr></thead><tbody>' + I.consol.map(function (r) { return srow(r, esc('load ' + r.lpc + ' per CPU · ' + r.mem + '% memory free')); }).join('') + '</tbody></table></div>' : na('No physical server reads as lightly used (needs an OS reading).'))
      + '<p class="sv-m">From one reading: a light moment is not the peak. Check the month-end and backup windows before moving it to a VM.</p><div style="font-weight:700;margin:10px 0 4px">Powered-off VMs</div>' + (I.off.length ? '<div class="tw"><table><thead><tr><th>Server</th><th>Health</th><th>Power</th></tr></thead><tbody>' + I.off.map(function (r) { return srow(r, esc('off' + (r.x.power_at ? ' since ' + dt(r.x.power_at) : ''))); }).join('') + '</tbody></table></div><p class="sv-m">Confirm with the owner, then archive or delete to reclaim storage and licences.</p>' : na('No VM is powered off at the last vCenter / Prism sync.'));
    if (IQ.tab === 'cov') body = '<div style="display:grid;grid-template-columns:170px 1fr 70px;gap:6px 10px;align-items:center;font-size:12.5px">' + I.cov.map(function (c) { return '<span>' + esc(c.l) + '</span><span style="height:10px;border-radius:5px;background:rgba(255,255,255,.08);overflow:hidden"><i style="display:block;height:100%;width:' + c.pct + '%;background:' + (c.pct >= 90 ? '#3fb950' : c.pct >= 60 ? '#e3b341' : '#ff7b72') + '"></i></span><b>' + esc(c.n + ' · ' + c.pct + '%') + '</b>'; }).join('') + '</div><p class="sv-m">What the page can say about the estate is only as good as what each source covers. A gap here means "not measured", never "fine".</p>';
    var siteRows = Object.keys(sites).sort().slice(0, 12).map(function (k) { return '<div class="sv-m">' + esc(k) + ': ' + Object.keys(sites[k]).map(function (t) { return esc(t + ' ' + sites[k][t]); }).join(' · ') + '</div>'; }).join('');
    el.innerHTML = '<h2>✦ Estate intelligence <span class="c">computed from this page\'s data · every number explained</span></h2>'
      + '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:0 0 12px"><div><div class="sv-m">Physical · virtual · private cloud</div>' + mix + siteRows + '</div>'
      + '<div><div class="sv-m">Average health</div><div style="font-size:30px;font-weight:800;color:' + (avg >= 85 ? '#3fb950' : avg >= 60 ? '#e3b341' : '#ff7b72') + '">' + avg + '</div><div class="sv-m">' + esc(hs[0] + ' healthy · ' + hs[1] + ' watch · ' + hs[2] + ' poor · ' + hs[3] + ' critical') + '</div></div>'
      + '<div><div class="sv-m">Compound risk</div><div style="font-size:30px;font-weight:800;color:' + (comp.length ? '#ff7b72' : '#3fb950') + '">' + comp.length + '</div><div class="sv-m">servers with 2+ serious risks together</div></div></div>'
      + '<nav class="sv-tabs" aria-label="Estate intelligence">' + Object.keys(T).map(function (k) { return '<a href="#" data-sv-itab="' + k + '"' + (IQ.tab === k ? ' class="on" aria-current="true"' : '') + '>' + esc(T[k][0]) + (T[k][1] !== '' ? ' <span class="sv-m">' + esc(T[k][1]) + '</span>' : '') + '</a>'; }).join('') + '</nav>' + body;
    D.mark(el, 'tr.sv-r');
  }
  function drawList() {
    var L = visible(), sm = V.summary;
    $('sv-kk').innerHTML = tile('Servers', sm.servers, P ? V.label : 'in the asset register', '', '')
      + tile('Critical / high', sm.critical + ' / ' + sm.high, 'findings with a fix', sm.critical ? 'bad' : sm.high ? 'warn' : 'ok', 'issues')
      + tile('Past end of support', V.sources.lifecycle ? sm.eol : '–', V.sources.lifecycle ? 'End of Life & Isolation' : 'End of Life not installed', V.sources.lifecycle ? (sm.eol ? 'bad' : 'ok') : 'na', 'eol')
      + tile('No / failed backup', sm.no_backup == null ? '–' : sm.no_backup, sm.no_backup == null ? 'no backup platform connected' : 'Backup Status', sm.no_backup == null ? 'na' : sm.no_backup ? 'bad' : 'ok', 'backup')
      + (sm.unix || UNIX[P] ? tile('OS read over SSH', sm.read + ' / ' + sm.unix, 'Solaris / Linux servers', sm.read < sm.unix ? 'warn' : 'ok', 'notread') : '')
      + tile('Powered on', V.servers.filter(function (x) { return x.power === 'on'; }).length, 'VMs at the last vCenter / Prism sync', '', 'on')
      + tile('Powered off', sm.powered_off, 'VMs', sm.powered_off ? 'warn' : '', 'off');
    $('sv-list').innerHTML = !V.servers.length ? na(P === 'exchange' ? 'No Exchange server recognised yet. A server counts as Exchange from: Microsoft Exchange Server in its installed software, a tag "exchange", an Exchange host name (EXCH01, MBX02 …), sending Exchange message-tracking logs to the SIEM (read by the sysadmin sync every 5 minutes - an administrator can press Sync with the SIEM now), Business Services finding Outlook on the web on it, or the Email Route Map mail server register (role Exchange / Hybrid / Edge with its internal IP). The server must also be in the asset register.' : P ? 'No ' + V.label + ' server in the asset register. Servers come from Asset Discovery, vCenter / Nutanix syncs or Add Server / Device; the platform is read from the OS each one reports.' : 'No server or VM in the asset register yet - start with Asset Discovery or Add Server / Device.')
      : !L.length ? na('Nothing matches the filter.')
      : '<div class="tw"><table><thead><tr><th>Server</th><th>Operating system</th><th>Address</th><th>Platform</th><th>Power</th><th>Backup</th><th>Support</th><th>Findings</th></tr></thead><tbody>' + L.slice(0, 1000).map(function (x) {
        var b = x.backup && BK[x.backup.status], lc = x.lifecycle;
        return '<tr class="sv-r" data-id="' + esc(x.id) + '" tabindex="0"><td><b>' + esc(x.name) + '</b><div class="sv-m">' + esc([x.type === 'vm' ? 'VM' + (x.host_name ? ' on ' + x.host_name : '') : 'physical', x.site, x.owner].filter(Boolean).join(' · ')) + '</div></td>'
          + '<td>' + esc(x.os_shown || '–') + osCell(x) + '</td><td class="mono">' + ipCell(x) + '</td>'
          + '<td>' + (x.platforms || []).map(function (p) { return pill(LBL[p] || p, p === 'unknown' ? 'warn' : ''); }).join('') + '</td>'
          + '<td>' + (x.power ? pill(x.power, x.power === 'on' ? 'ok' : x.power === 'off' ? 'warn' : '') : '<span class="sv-m">–</span>') + '</td>'
          + '<td>' + (b ? pill(b[0], b[1]) : '<span class="sv-m">' + (V.sources.backup ? 'not matched' : '–') + '</span>') + '</td>'
          + '<td>' + (lc && lc.status === 'eol' ? pill('past end of support', 'bad') : lc && lc.status === 'soon' ? pill('ends soon', 'warn') : '<span class="sv-m">' + (lc ? 'supported' : '–') + '</span>') + '</td>'
          + '<td>' + (x.findings ? pill(x.findings + (x.worst ? ' · ' + x.worst : ''), x.worst) : pill('none', 'ok')) + '</td></tr>';
      }).join('') + '</tbody></table></div>' + (L.length > 1000 ? '<p class="sv-m">First 1000 shown - narrow with the search.</p>' : '');
    D.mark($('sv-list'), 'tr.sv-r');
    var F = V.findings.filter(function (f) { return L.some(function (x) { return x.id === f.asset_id; }); });
    $('sv-find').innerHTML = F.length ? '<div class="tw"><table><thead><tr><th>Severity</th><th>Finding</th><th>What to do</th></tr></thead><tbody>' + F.slice(0, 300).map(function (f) {
      return '<tr class="sv-r" data-id="' + esc(f.asset_id) + '"><td>' + pill(f.severity, f.severity) + '</td><td>' + esc(f.title) + (f.evidence && f.evidence.length ? '<div class="sv-m">' + esc(f.evidence.join(' · ')) + '</div>' : '') + '</td><td class="sv-fix">' + esc(f.recommendation) + '</td></tr>';
    }).join('') + '</tbody></table></div>' : (V.servers.length ? '<div class="sv-m">No finding on the servers shown.</div>' : '');
  }
  function detail(id) {
    var x = V && V.servers.filter(function (s) { return s.id === id; })[0]; if (!x) return;
    var F = V.findings.filter(function (f) { return f.asset_id === id; }), r = x.os_read || {}, v = r.server;
    var h = D.kv([['Platform', (x.platforms || []).map(function (p) { return pill(LBL[p] || p); }).join('') + '<div class="sv-m">' + esc((x.platform_why || []).join(' · ')) + '</div>'],
      ['Operating system', esc(x.os_shown || '–')], ['Address', esc(x.ip || '–')], ['Type', esc(x.type === 'vm' ? 'virtual machine' + (x.vm_name && x.vm_name !== x.name ? ' (' + x.vm_name + ')' : '') : 'physical server')],
      ['Runs on', esc(x.host_name || '–')], ['Power', esc(x.power ? x.power + (x.power_at ? ' (as of ' + dt(x.power_at) + ')' : '') : 'not reported')],
      ['Vendor / model', esc([x.vendor, x.model].filter(Boolean).join(' ') || '–')], ['Serial', esc(x.serial || '–')], ['Warranty ends', esc(x.warranty_end ? dt(x.warranty_end) : '–')],
      ['Owner / site', esc([x.owner, x.site].filter(Boolean).join(' · ') || '–')],
      ['Backup', x.backup ? esc((BK[x.backup.status] || [x.backup.status])[0] + (x.backup.last_success ? ' · last good ' + dt(x.backup.last_success) : '')) : esc(V.sources.backup ? 'not matched to a backup job' : 'no backup platform connected')],
      ['End of support', x.lifecycle ? esc(x.lifecycle.status + (x.lifecycle.product ? ' · ' + x.lifecycle.product : '') + (x.lifecycle.eol ? ' · ' + x.lifecycle.eol : '')) : '–'],
      ['Patches (Endpoint Central)', x.patch ? esc(x.patch.missing + ' missing, ' + x.patch.critical + ' critical') : '–']]);
    h += D.sec('Findings', F.length ? F.map(function (f) { return '<div style="margin:0 0 8px">' + pill(f.severity, f.severity) + ' ' + esc(f.title) + '<div class="sv-fix">' + esc(f.recommendation) + '</div></div>'; }).join('') : '<div class="sv-m">None.</div>');
    if ((x.platforms || []).some(function (p) { return UNIX[p]; })) {
      var os = v ? D.kv([['Read', esc(ago(r.at)) + (r.via ? ' via ' + esc(r.via) : '')], ['Kernel', esc(v.kernel || '–')], ['Uptime', esc(v.uptime_s != null ? Math.round(v.uptime_s / 86400) + ' days' : 'not reported')],
        ['CPU / load (5 min)', esc((v.ncpu || '–') + ' / ' + (v.load5 != null ? v.load5 : 'not reported'))], ['Memory', esc(v.mem_total_mb ? Math.round(v.mem_total_mb / 1024) + ' GB, ' + (v.mem_avail_mb != null ? Math.round(v.mem_avail_mb / 1024) + ' GB free' : 'free not reported') : 'not reported')],
        ['Swap', esc(v.swap_total_mb ? (v.swap_used_mb || 0) + ' of ' + v.swap_total_mb + ' MB used' : 'not reported')], ['NTP', esc(v.ntp_synced == null ? 'not reported' : v.ntp_synced ? 'synchronised' : 'NOT synchronised')],
        ['Last OS update', esc(v.last_patch || 'not reported')], ['Failed services', esc((v.failed_services || []).map(function (s) { return s.name + ' (' + s.state + ')'; }).join(', ') || 'none')]])
        + ((v.filesystems || []).length ? D.tbl(['File system', 'Used %', 'Free MB'], v.filesystems.slice(0, 30).map(function (f) { return [esc(f.mount), esc(f.used_pct == null ? '–' : f.used_pct + '%'), esc(f.avail_kb == null ? '–' : Math.round(f.avail_kb / 1024))]; })) : '')
        : '<div class="sv-m">' + esc(r.error ? 'Last attempt failed: ' + (r.error_class || '') + ' ' + r.error : 'Not read yet.') + '</div>';
      os += '<p class="sv-m">SSH login: ' + esc(x.ssh.credential || 'none') + (x.ssh.via ? ' (' + esc(x.ssh.via) + ')' : '') + ' · host key ' + esc(x.ssh.host_key) + '</p>';
      if (RANK[ROLE] >= 3) os += '<label class="sv-m" for="sv-cred">Choose the read-only SSH login for this server</label><div class="sv-bar"><select id="sv-cred" data-asset="' + esc(x.id) + '"><option value="">Use the login Asset Discovery proved</option>'
        + (V.ssh_logins || []).map(function (c) { return '<option value="' + esc(c.id) + '"' + (c.label === x.ssh.credential && x.ssh.via === 'chosen here' ? ' selected' : '') + '>' + esc(c.label) + '</option>'; }).join('') + '</select><button type="button" id="sv-cred-save">Save</button><span id="sv-cred-msg" class="sv-m"></span></div>';
      h += D.sec('Operating system (read over SSH)', os);
    }
    D.open(LBL[(x.platforms || [])[0]] || 'Server', x.name, h);
  }
  // platform-specific card: ESXi hosts from vCenter, or the AI Windows / Exchange administrators' own checks
  function drawExtra() {
    var el = $('sv-extra'); if (!el) return;
    if (P === 'vmware') {
      if (!VC) { el.innerHTML = na('Loading vCenter…'); return; }
      if (VC.status !== 200 || !VC.json) { el.innerHTML = na(why(VC, 'Capacity (vCenter / Prism collection)')); return; }
      var pl = (VC.json.platforms || []).filter(function (p) { return /vcenter|esxi/.test(p.kind); }), names = pl.map(function (p) { return p.label; });
      var H = (VC.json.hosts || []).filter(function (h) { return names.indexOf(h.platform) >= 0; }), DS = (VC.json.datastores || []).filter(function (d) { return names.indexOf(d.platform) >= 0; });
      if (!pl.length) { el.innerHTML = na('No vCenter or ESXi host is connected - add it on Virtualization (read-only account), then run a capacity collection.'); return; }
      el.innerHTML = (H.length ? '<div class="tw"><table><thead><tr><th>ESXi host</th><th>Management IP</th><th>Cluster</th><th>Version</th><th>State</th><th>CPU used</th><th>Memory used</th><th>VMs on</th></tr></thead><tbody>' + H.map(function (h) {
        var c = function (v) { return v == null ? '<span class="sv-m">–</span>' : pill(v + '%', v >= 90 ? 'bad' : v >= 80 ? 'warn' : 'ok'); };
        return '<tr><td><b>' + esc(h.name) + '</b><div class="sv-m">' + esc([h.vendor, h.model].filter(Boolean).join(' ')) + '</div></td><td class="mono">' + (h.ip ? esc(h.ip) : '<span class="sv-m">not reported</span>') + (h.vmks || []).filter(function (v) { return v.ip && v.ip !== h.ip; }).map(function (v) { return '<div class="sv-m">' + esc(v.ip) + ' · ' + esc([v.vmk, v.portgroup].filter(Boolean).join(' ')) + '</div>'; }).join('') + '</td><td>' + esc(h.cluster || '–') + '</td><td class="sv-m">' + esc(h.version || '–') + '</td><td>' + (h.maintenance ? pill('maintenance', 'warn') : h.state && !/connected/i.test(h.state) ? pill(h.state, 'bad') : pill(h.state || 'unknown', h.state ? 'ok' : '')) + '</td><td>' + c(h.cpu_used_pct) + '</td><td>' + c(h.mem_used_pct) + '</td><td>' + esc(h.vms_on + ' / ' + h.vms) + '</td></tr>';
      }).join('') + '</tbody></table></div>' : na('vCenter is connected but no host has been collected yet - run a capacity collection on Capacity Planning.'))
        + (DS.length ? '<p class="sv-m">Datastores: ' + DS.slice(0, 12).map(function (d) { return esc(d.name) + ' ' + esc(d.used_pct == null ? '–' : d.used_pct + '%'); }).join(' · ') + '</p>' : '')
        + '<p class="sv-m">From the last capacity collection' + (VC.json.last_run && VC.json.last_run.at ? ' (' + esc(ago(VC.json.last_run.at)) + ')' : '') + '. Power actions: Power Control. Per-VM utilisation: Capacity Planning.</p>';
    } else if (P === 'windows' || P === 'exchange') {
      if (!SIEM) { el.innerHTML = na('Loading the AI ' + LBL[P] + ' Administrator…'); return; }
      if (SIEM.status !== 200 || !SIEM.json || !Array.isArray(SIEM.json.items)) { el.innerHTML = na(why(SIEM, 'The AI ' + LBL[P] + ' Administrator (SIEM)')); return; }
      var T = SIEM.json.items;
      // every IPv4 address the server itself reports (read-only network check over WinRM) - a second NIC shows; never guessed
      // without a WinRM reading, every address another source already reported (VMware Tools via vCenter, Nutanix, discovery,
      // the asset register) is shown with its source - the server is not read again, nothing is guessed
      var known = function (t, reg, note) {
        var L = reg && Array.isArray(reg.ips) ? reg.ips.filter(function (i) { return i && i.ip; }) : [];
        if (L.length <= 1) return esc(t.ip || '–') + '<div class="sv-m">' + esc(note) + '</div>';
        return L.map(function (i) { return '<div>' + esc(i.ip) + ' <span class="sv-m">' + esc(srcName(i.src)) + (i.ip === t.ip ? ' · managed by' : '') + '</span></div>'; }).join('') + '<div class="sv-m">' + esc(L.length + ' addresses from the platform\'s own sources - ' + note) + '</div>';
      };
      var addrs = function (t, reg) {
        var A = t.addresses, it = A && A.items || [];
        if (!A) return known(t, reg, 'WinRM has not read the server yet');
        if (A.error) return known(t, reg, 'WinRM: ' + A.error);
        if (!it.length) return esc(t.ip || '–');
        return it.map(function (x) { return '<div>' + esc(x.ip) + (x.prefix != null ? '/' + esc(x.prefix) : '') + ' <span class="sv-m">' + esc(x.interface || '') + (x.ip === t.ip ? ' · managed by' : '') + '</span></div>'; }).join('') + '<div class="sv-m">read ' + esc(ago(A.at)) + '</div>';
      };
      var bar = RANK[ROLE] >= 2 ? '<div class="sv-bar"><button type="button" id="sv-addr">Fetch IP addresses from every server</button><span id="sv-addrmsg" class="sv-m">' + esc(ADDRMSG) + '</span></div>' : '';
      el.innerHTML = bar + (T.length ? '<div class="tw"><table><thead><tr><th>Server</th><th>Addresses</th><th>WinRM login</th><th>Last health check</th><th>Findings</th><th>In the asset register</th></tr></thead><tbody>' + T.map(function (t) {
        var reg = V && V.servers.filter(function (x) { return (t.ip && x.ip === t.ip) || String(x.name || '').toLowerCase().split('.')[0] === String(t.name || t.id || '').toLowerCase().split('.')[0]; })[0];
        var login = (t.logins && Object.keys(t.logins).some(function (k) { return t.logins[k]; })) || t.login_set || t.has_login;
        return '<tr><td><b>' + esc(t.name || t.id) + '</b></td><td class="mono">' + addrs(t, reg) + '</td><td>' + (login ? pill('set', 'ok') : pill('not set', 'warn')) + '</td><td class="sv-m">' + esc(t.last_check ? ago(t.last_check.at || t.last_check) : 'never') + '</td><td>' + (t.findings ? pill(t.findings + (t.worst ? ' · ' + t.worst : ''), t.worst) : pill('none', 'ok')) + '</td><td>' + (reg ? pill('yes', 'ok') : pill('not found', 'warn')) + '</td></tr>';
      }).join('') + '</tbody></table></div><p class="sv-m">Health checks over WinRM by the AI ' + esc(LBL[P]) + ' Administrator (read-only). Open it for the checks, the findings and proposed changes. The addresses are read with the WinRM login: a server whose login is "not set" cannot report them - set it there (Logins, then the server\'s login profile).</p>'
        : na('No server is in the AI ' + LBL[P] + ' Administrator\'s list yet. IT Asset Management adds ' + LBL[P] + ' servers there automatically (sysadmin sync) once they have an IP address; the WinRM login is set there by an administrator.'));
    }
  }
  // every address a source reported for the server (asset register, discovery, VMware Tools / Nutanix / Hyper-V), its source on hover
  var SRCN = { vcenter: 'VMware Tools (vCenter)', prism: 'Nutanix', nutanix: 'Nutanix', hyperv: 'Hyper-V', inventory: 'inventory', 'asset register': 'asset register', snmp: 'SNMP', nmap: 'network scan', ping: 'network scan', winrm: 'WinRM', ssh: 'SSH', ad: 'Active Directory', dns: 'DNS' };
  function srcName(s2) { return SRCN[s2] || s2 || 'discovery'; }
  function ipCell(x) {
    var L = (x.ips || []).filter(function (i) { return i && i.ip; });
    if (L.length <= 1) return esc(x.ip || (L[0] && L[0].ip) || '–');
    var main = x.ip || L[0].ip;
    return '<div>' + esc(main) + '</div>' + L.filter(function (i) { return i.ip !== main; }).map(function (i) { return '<div class="sv-m" title="' + esc('reported by ' + srcName(i.src)) + '">' + esc(i.ip) + '</div>'; }).join('');
  }
  function draw(r) {
    $('sv-up').textContent = 'updated ' + new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    if (r.status !== 200 || !r.json || !Array.isArray(r.json.servers)) {
      V = null; var w = why(r, 'Servers by platform (IT Asset Management)');
      $('sv-kk').innerHTML = ''; $('sv-list').innerHTML = na(w); $('sv-find').innerHTML = ''; $('sv-tabs').innerHTML = ''; tabs(); return;
    }
    V = r.json; tabs(); drawList(); try { drawIntel(); } catch (e) { var ie = $('sv-intel'); if (ie) ie.innerHTML = na('Estate intelligence could not be drawn: ' + e.message); /* shown on the page; the list below still works */ } drawExtra();
    var lp = V.last_pass; $('sv-pass').textContent = RUNMSG ? RUNMSG : lp ? 'Solaris / Linux last read ' + ago(lp.at) + ': ' + lp.read + ' read, ' + (lp.shared || 0) + ' from Database Servers, ' + lp.skipped + ' without a login or trusted key, ' + lp.failed + ' failed' : '';
  }
  function load() {
    get('/api/itam/servers' + (P ? '?platform=' + encodeURIComponent(P) : '')).then(draw);
    if (P === 'vmware') get('/api/itam/virt/capacity').then(function (r) { VC = r; drawExtra(); });
    if (P === 'windows' || P === 'exchange') get('/api/soc/sysadmin/targets?role=' + P).then(function (r) { SIEM = r; drawExtra(); });
  }
  document.addEventListener('click', function (e) {
    var t = e.target;
    var go = t.closest && t.closest('[data-go]'); if (go) { location.href = go.getAttribute('data-go'); return; }
    var f = t.closest && t.closest('.sv-t[data-f]'); if (f && V) { var k = f.getAttribute('data-f'); Q.f = Q.f === k ? '' : k; drawList(); return; }
    var it = t.closest && t.closest('[data-sv-itab]'); if (it && V) { e.preventDefault(); IQ.tab = it.getAttribute('data-sv-itab'); drawIntel(); return; }
    var so = t.closest && t.closest('[data-sv-open]'); if (so && V) { e.preventDefault(); detail(so.getAttribute('data-sv-open')); return; }
    var tr = t.closest && t.closest('tr.sv-r[data-id]'); if (tr && V) { detail(tr.getAttribute('data-id')); return; }
    if (t.id === 'sv-addr') {
      t.disabled = true; ADDRMSG = 'Reading the addresses on every server (read-only)…'; $('sv-addrmsg').textContent = ADDRMSG;
      post('/api/soc/sysadmin/addresses/refresh', {}).then(function (r) {
        var it = (r.json && r.json.items) || [], ok = it.filter(function (x) { return x.status === 'ok'; }), nl = it.filter(function (x) { return x.status === 'no-login'; }), bad = it.filter(function (x) { return x.status === 'failed'; });
        ADDRMSG = r.status === 200 ? ok.length + ' of ' + it.length + ' server(s) read' + (nl.length ? ' · no WinRM login for ' + nl.map(function (x) { return x.name; }).join(', ') + ' - set it on the AI ' + LBL[P] + ' Administrator page (Logins)' : '') + (bad.length ? ' · failed: ' + bad.map(function (x) { return x.name + ' (' + x.error + ')'; }).join('; ') : '')
          : (r.json && r.json.error) || why(r, 'Reading the addresses');
        get('/api/soc/sysadmin/targets?role=' + P).then(function (x) { SIEM = x; drawExtra(); });
      });
      return;
    }
    if (t.id === 'sv-cred-save') {
      var sel = $('sv-cred'), msg = $('sv-cred-msg'); t.disabled = true; msg.textContent = 'Saving…';
      post('/api/itam/servers/ssh', { asset_id: sel.getAttribute('data-asset'), cred_id: sel.value || null }).then(function (r) { t.disabled = false; msg.textContent = r.status === 200 ? 'Saved - read on the next pass (or Read now).' : (r.json && r.json.error) || 'not saved (HTTP ' + r.status + ')'; if (r.status === 200) load(); });
    }
  });
  $('sv-q').addEventListener('input', function () { Q.q = this.value.trim(); if (V) drawList(); });
  $('sv-refresh').addEventListener('click', load);
  // Exchange: the SIEM's Exchange log senders are read by the sysadmin sync - an administrator can run it now
  if (P === 'exchange') {
    var xb = document.createElement('button'); xb.type = 'button'; xb.id = 'sv-exsync'; xb.hidden = true; xb.textContent = '⇄ Sync with the SIEM now';
    $('sv-refresh').parentNode.insertBefore(xb, $('sv-refresh'));
    xb.addEventListener('click', function () { xb.disabled = true; var m = $('sv-pass'); m.textContent = 'Syncing Exchange servers with the SIEM…';
      post('/api/itam/sysadmin-sync/run', {}).then(function (r) { xb.disabled = false; var j = r.json || {}, l = j.last || j;
        RUNMSG = m.textContent = r.status === 200 ? 'Synced: ' + ((l.added || []).length) + ' added to the AI administrators, ' + (l.exchange_log_senders != null ? l.exchange_log_senders + ' server(s) send Exchange logs to the SIEM' : 'the SIEM Exchange log senders could not be read' + (l.exchange_logs_error ? ' (' + l.exchange_logs_error + ')' : '')) : (j.error || why(r, 'The sysadmin sync'));
        load(); }); });
  }
  $('sv-run').addEventListener('click', function () {
    var b = this, m = $('sv-pass'); b.disabled = true; m.textContent = 'Reading Solaris / Linux servers over SSH…';
    post('/api/itam/servers/run', {}).then(function (r) { b.disabled = false; RUNMSG = m.textContent = r.status === 200 ? 'Read ' + r.json.read + ', from Database Servers ' + (r.json.shared || 0) + ', without a login or trusted key ' + r.json.skipped + ', failed ' + r.json.failed : (r.json && r.json.error) || why(r, 'Reading'); load(); });
  });
  var w = new XMLHttpRequest(); w.zybQuiet = true; w.open('GET', '/dashboards/whoami.json');
  w.onload = function () { try { var j = JSON.parse(w.responseText), rl = String(j.role || '').toLowerCase(); if (RANK[rl] != null) ROLE = rl; } catch (e) { /* no identity: viewer, the server decides anyway */ } $('sv-run').hidden = !(RANK[ROLE] >= 2 && (UNIX[P] || !P)); if ($('sv-exsync')) $('sv-exsync').hidden = !(RANK[ROLE] >= 3); load(); };
  w.onerror = function () { load(); }; w.send();
  setInterval(function () { if (!document.hidden) load(); }, 300000);
})();
