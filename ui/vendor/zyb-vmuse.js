// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-vmuse.js - per-VM resource utilisation for the virtualization pages (Nutanix VMs, Capacity).
   window.zybVmUse = { line, hbars, dist, ubar, openVm, history }
   Charts are inline SVG strings (no library, prints cleanly). Usage values come from /api/itam/virt/capacity; a value the
   platform did not report is null and is drawn as "not reported", never as 0. */
(function () {
  'use strict';
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var f = function (n, d) { return n == null ? '—' : Number(n).toLocaleString(undefined, { maximumFractionDigits: d == null ? 0 : d }); };
  var COL = { cpu: '#58a6ff', mem: '#bc8cff', iops: '#3fb950', lat: '#e3b341' };
  function lvl(p) { return p == null ? '' : p >= 90 ? '#f85149' : p >= 75 ? '#e3b341' : '#3fb950'; }

  // small inline bar with the value (table cells)
  function ubar(p) {
    if (p == null) return '<span style="color:var(--mute,#8c93a1)">—</span>';
    return '<span style="display:inline-flex;align-items:center;gap:6px;min-width:110px"><span style="flex:1;height:7px;border-radius:4px;background:rgba(255,255,255,.08);overflow:hidden;min-width:60px"><i style="display:block;height:100%;width:' + Math.min(100, Math.max(2, p)) + '%;background:' + lvl(p) + '"></i></span><span style="width:44px;text-align:right">' + f(p, 1) + '%</span></span>';
  }

  // time series: series = [{name, color, points:[{t, v}]}]; o = {max, unit, h}
  function line(series, o) {
    o = o || {}; var W = 640, H = o.h || 190, L = 42, R = 10, T = 12, B = 26;
    var pts = [].concat.apply([], series.map(function (s) { return s.points.filter(function (p) { return p.v != null; }); }));
    if (!pts.length) return '<div style="color:var(--mute,#8c93a1);padding:18px 0">' + esc(o.empty || 'No samples yet - one is taken every collection (hourly by default).') + '</div>';
    var t0 = Math.min.apply(null, pts.map(function (p) { return p.t; })), t1 = Math.max.apply(null, pts.map(function (p) { return p.t; }));
    if (t1 === t0) { t0 -= 1800000; t1 += 1800000; }
    var vmax = o.max || Math.max.apply(null, pts.map(function (p) { return p.v; })) * 1.15 || 1;
    var X = function (t) { return L + (t - t0) / (t1 - t0) * (W - L - R); }, Y = function (v) { return T + (1 - Math.min(v, vmax) / vmax) * (H - T - B); };
    var g = '';
    for (var i = 0; i <= 4; i++) { var v = vmax * i / 4, y = Y(v); g += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + y + '" y2="' + y + '" stroke="rgba(255,255,255,.07)"/><text x="' + (L - 6) + '" y="' + (y + 4) + '" text-anchor="end" font-size="10" fill="#8c93a1">' + f(v, vmax < 10 ? 1 : 0) + (o.unit || '') + '</text>'; }
    var day = function (t) { var d = new Date(t); return (t1 - t0 > 2 * 864e5) ? d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) : d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }); };
    g += '<text x="' + L + '" y="' + (H - 6) + '" font-size="10" fill="#8c93a1">' + esc(day(t0)) + '</text><text x="' + (W - R) + '" y="' + (H - 6) + '" font-size="10" fill="#8c93a1" text-anchor="end">' + esc(day(t1)) + '</text>';
    if (o.limit != null && o.limit <= vmax) g += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + Y(o.limit) + '" y2="' + Y(o.limit) + '" stroke="#f85149" stroke-dasharray="4 4" opacity=".6"/>';
    series.forEach(function (s) {
      var p = s.points.filter(function (x) { return x.v != null; }); if (!p.length) return;
      var d = p.map(function (x, i) { return (i ? 'L' : 'M') + X(x.t).toFixed(1) + ' ' + Y(x.v).toFixed(1); }).join(' ');
      if (series.length === 1) g += '<path d="' + d + ' L' + X(p[p.length - 1].t).toFixed(1) + ' ' + Y(0) + ' L' + X(p[0].t).toFixed(1) + ' ' + Y(0) + 'Z" fill="' + s.color + '" opacity=".12"/>';
      g += '<path d="' + d + '" fill="none" stroke="' + s.color + '" stroke-width="2" stroke-linejoin="round"/>';
      if (p.length === 1) g += '<circle cx="' + X(p[0].t) + '" cy="' + Y(p[0].v) + '" r="3.5" fill="' + s.color + '"/>';
    });
    var leg = series.map(function (s) { var p = s.points.filter(function (x) { return x.v != null; }), last = p.length ? p[p.length - 1].v : null; return '<span style="display:inline-flex;align-items:center;gap:6px;margin-right:14px;font-size:12px"><i style="width:10px;height:10px;border-radius:2px;background:' + s.color + ';display:inline-block"></i>' + esc(s.name) + ' <b>' + f(last, 1) + (last == null ? '' : (o.unit || '')) + '</b></span>'; }).join('');
    return '<div>' + leg + '</div><svg viewBox="0 0 ' + W + ' ' + H + '" width="100%" role="img" aria-label="' + esc(series.map(function (s) { return s.name; }).join(', ')) + ' over time" style="display:block;max-height:' + (H + 20) + 'px">' + g + '</svg>';
  }

  // ranked horizontal bars: rows = [{label, sub, v, click}], o = {max, unit, color, empty}
  function hbars(rows, o) {
    o = o || {};
    if (!rows.length) return '<div style="color:var(--mute,#8c93a1);padding:10px 0">' + esc(o.empty || 'Not reported.') + '</div>';
    var mx = o.max || Math.max.apply(null, rows.map(function (r) { return r.v; })) || 1;
    return rows.map(function (r) {
      var c = o.color || lvl(r.v);
      return '<div' + (r.key != null ? ' data-vm="' + esc(r.key) + '" class="zd-click" tabindex="0"' : '') + ' style="display:grid;grid-template-columns:minmax(90px,38%) 1fr 64px;gap:8px;align-items:center;padding:3px 2px;border-radius:5px" title="' + esc(r.label + (r.sub ? ' · ' + r.sub : '')) + '">'
        + '<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12.5px">' + esc(r.label) + '</span>'
        + '<span style="height:10px;border-radius:4px;background:rgba(255,255,255,.06);overflow:hidden"><i style="display:block;height:100%;width:' + Math.max(1.5, Math.min(100, r.v / mx * 100)).toFixed(1) + '%;background:' + c + '"></i></span>'
        + '<span style="text-align:right;font-size:12.5px;font-variant-numeric:tabular-nums">' + f(r.v, o.dec == null ? 1 : o.dec) + esc(o.unit || '') + '</span></div>';
    }).join('');
  }

  // distribution of running VMs over utilisation bands (0-20 … 80-100 %)
  function dist(vals, label) {
    var b = [0, 0, 0, 0, 0], n = 0;
    vals.forEach(function (v) { if (v == null) return; n++; b[Math.min(4, Math.floor(v / 20))]++; });
    if (!n) return '<div style="color:var(--mute,#8c93a1);padding:10px 0">' + esc(label) + ': not reported.</div>';
    var mx = Math.max.apply(null, b) || 1, cols = ['#3fb950', '#3fb950', '#58a6ff', '#e3b341', '#f85149'], names = ['0–20%', '20–40%', '40–60%', '60–80%', '80–100%'];
    return '<div style="font-size:12px;color:var(--mute,#8c93a1);margin-bottom:6px">' + esc(label) + ' · ' + n + ' VMs</div><div style="display:flex;gap:8px;align-items:flex-end;height:110px">'
      + b.map(function (c, i) { return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;height:100%;justify-content:flex-end" title="' + c + ' VMs at ' + names[i] + '"><span style="font-size:12px">' + c + '</span><i style="display:block;width:100%;border-radius:4px 4px 0 0;background:' + cols[i] + ';height:' + (c ? Math.max(4, c / mx * 80) : 1) + 'px;opacity:.85"></i><span style="font-size:10.5px;color:var(--mute,#8c93a1)">' + names[i] + '</span></div>'; }).join('') + '</div>';
  }

  function history(q) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(), s = Object.keys(q).filter(function (k) { return q[k] != null && q[k] !== ''; }).map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(q[k]); }).join('&');
      x.open('GET', '/api/itam/virt/capacity/vm-history' + (s ? '?' + s : '')); x.withCredentials = true; x.timeout = 60000;
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: treated as no data */ } if (x.status >= 200 && x.status < 300 && j) ok(j); else bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('IT Asset Management could not be reached')); }; x.send();
    });
  }

  // where a VM's address came from: the platform itself, or a fallback that is named so nobody reads it as Prism's word
  var IPSRC = { prism: 'reported by Prism', vcenter: 'reported by vCenter (VMware Tools)', discovery: 'from Asset Discovery', asset: 'asset register management IP', mac: 'Network Discovery, matched on the VM\'s MAC' };
  function ipCell(v, long) {
    var ips = v.ips || [];
    if (!ips.length) return '<span class="zd-dim muted" title="Nutanix reports a VM\'s address only with Nutanix Guest Tools (NGT), IPAM on the VM network, or a learned address">' + (long ? 'No IP reported - install Nutanix Guest Tools (NGT) or use an IPAM-managed network; Network Discovery can also match it by MAC' : 'not reported') + '</span>';
    var src = IPSRC[v.ip_src] || '';
    return esc(long ? ips.join(', ') : ips[0] + (ips.length > 1 ? ' +' + (ips.length - 1) : '')) + (src && (long || v.ip_src !== 'prism') ? ' <span class="zd-dim muted" style="font-size:11px">(' + esc(long ? src : v.ip_src) + ')</span>' : '');
  }

  // VM detail panel: configuration, current usage, and its own graphs
  function openVm(v, days) {
    var Z = window.zybDetail; if (!Z) return;
    days = days || 7;
    var on = v.power === 'on';
    var head = Z.kv([['IP address', ipCell(v, true)], ['Power', on ? Z.pill('on', 'ok') : Z.pill(v.power || 'off', 'info')], ['Platform', esc(v.platform || '—')], ['Cluster', esc(v.cluster || '—')], ['Host', esc(v.host || '—')],
      ['vCPU', esc(f(v.vcpus))], ['Memory', esc(v.mem_gb == null ? '—' : f(v.mem_gb, 1) + ' GB')], ['Disk', esc(v.disk_gb == null ? '—' : f(v.disk_gb) + ' GB')], ['Guest OS', esc(v.guest_os || '—')], ['MAC', esc((v.macs || []).join(', ') || '—')]]);
    var now = !on ? '<p class="zd-dim">The VM is not running - a stopped VM has no utilisation.</p>' : Z.kv([['CPU in use', ubar(v.cpu_pct)], ['Memory in use', ubar(v.mem_used_pct)], ['IOPS', esc(f(v.iops))], ['IO latency', esc(v.io_latency_ms == null ? '—' : f(v.io_latency_ms, 1) + ' ms')], ['IO bandwidth', esc(v.io_kbps == null ? '—' : f(v.io_kbps / 1024, 1) + ' MB/s')]])
      + (v.cpu_pct == null && v.mem_used_pct == null && v.iops == null ? '<p class="zd-dim">This platform connection did not report usage for the VM. For Nutanix the account needs read access to the Prism VM list (v1 API); Prism Central on some releases does not report it - add the cluster (Prism Element) address.</p>' : '');
    var pick = '<div style="margin:0 0 8px">' + [1, 7, 31].map(function (d) { return '<button type="button" data-vmdays="' + d + '" class="zd-back" style="padding:4px 10px;margin-right:6px' + (d === days ? ';border-color:var(--accent,#5794f2)' : '') + '">' + (d === 1 ? '24 h' : d + ' days') + '</button>'; }).join('') + '</div>';
    Z.open('VM · ' + (v.platform || ''), v.name || 'VM', head + Z.sec('Now', now) + Z.sec('Utilisation over time', pick + '<div id="vmuG">Loading…</div>'));
    var b = document.getElementById('zd-b');
    [].forEach.call(b.querySelectorAll('[data-vmdays]'), function (x) { x.addEventListener('click', function () { openVm(v, +x.getAttribute('data-vmdays')); }); });
    if (!v.pid || !v.id) { document.getElementById('vmuG').innerHTML = '<p class="zd-dim">History needs the server update (IT Asset Management) - run update-platform.ps1.</p>'; return; }
    history({ pid: v.pid, vm: v.id, days: days }).then(function (r) {
      var P = r.points || [], s = function (k) { return P.map(function (p) { return { t: p.t, v: p[k] }; }); }, el = document.getElementById('vmuG'); if (!el) return;
      el.innerHTML = line([{ name: 'CPU', color: COL.cpu, points: s('cpu') }, { name: 'Memory', color: COL.mem, points: s('mem') }], { max: 100, unit: '%', empty: 'No samples for this VM yet - one is taken at every collection while it runs.' })
        + (P.some(function (p) { return p.iops != null; }) ? '<div style="margin-top:12px"></div>' + line([{ name: 'IOPS', color: COL.iops, points: s('iops') }], {}) : '')
        + (P.some(function (p) { return p.lat != null; }) ? '<div style="margin-top:12px"></div>' + line([{ name: 'IO latency', color: COL.lat, points: s('lat') }], { unit: ' ms' }) : '')
        + '<p class="zd-dim" style="margin-top:8px">' + P.length + ' samples over ' + r.days + ' day(s). Hourly at most; kept 31 days.</p>';
    }).catch(function (e) { var el = document.getElementById('vmuG'); if (el) el.innerHTML = '<p class="zd-dim">' + esc(e.status === 404 ? 'History needs the server update (IT Asset Management) - run update-platform.ps1.' : e.message) + '</p>'; });
  }

  window.zybVmUse = { line: line, hbars: hbars, dist: dist, ubar: ubar, openVm: openVm, ipCell: ipCell, history: history, COL: COL, f: f, esc: esc };
})();
