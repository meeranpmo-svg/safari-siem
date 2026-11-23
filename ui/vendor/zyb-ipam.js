// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* IP Address Management page (ipam.html) over GET /api/itam/ipam. Subnets with utilisation, a /24-style address grid, next free
 * address and learned growth; findings with fixes; proposed networks (one click fills the subnet form); reservations; every address
 * with its sources; CSV export; read-only AI advisor. No inline handlers: delegated listeners. Every value is escaped. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var Z = window.zybDetail;
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var V = null, ROLE = 'viewer', Q = '', AF = '', SF = '';
  var op = function () { return ROLE === 'operator' || ROLE === 'admin'; };
  function req(m, p, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, '/api/itam' + p); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: reported below */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('IT Asset Management is not reachable')); }; x.send(b ? JSON.stringify(b) : null);
    });
  }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast-zyb'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 5000); }
  var col = function (p) { return p >= 90 ? '#d63939' : p >= 80 ? '#f59f00' : p >= 50 ? '#4299e1' : '#0ca678'; };
  function tile(v, l, cls, f, t) { return '<div class="col-6 col-md-3 col-xl"><div class="card card-sm"' + (f ? ' data-f="' + esc(f) + '" role="button" tabindex="0" aria-pressed="' + (AF === f) + '" title="' + esc(t || 'Show these') + '"' : '') + '><div class="card-body"><div class="au-num' + (cls ? ' ' + cls : '') + '">' + esc(v) + '</div><div class="au-lbl">' + esc(l) + '</div></div></div></div>'; }
  function ip2n(ip) { var p = String(ip).split('.').map(Number); return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]; }
  function grid(s) {
    if (s.usable > 254) return '';
    var used = {}, base = ip2n(s.cidr.split('/')[0]);
    (V.addresses || []).forEach(function (a) { if (a.subnet === s.id) used[ip2n(a.ip) - base] = 'u'; });
    (V.reservations || []).forEach(function (r) { if (r.subnet === s.id) used[ip2n(r.ip) - base] = 'r'; });
    if (s.gateway) used[ip2n(s.gateway) - base] = 'g';
    var ds = s.dhcp_start ? ip2n(s.dhcp_start) - base : -1, de = s.dhcp_end ? ip2n(s.dhcp_end) - base : -2, out = '';
    for (var i = 1; i <= s.usable; i++) out += '<span class="' + (used[i] || (i >= ds && i <= de ? 'd' : '')) + '" title=".' + i + '"></span>';
    return '<div class="grid mt-2" aria-label="address map">' + out + '</div><div class="mut mt-1"><span style="color:#4299e1">■</span> in use <span style="color:#ae3ec9">■</span> reserved <span style="color:#f59f00">■</span> gateway <span style="color:#0ca678">■</span> DHCP range</div>';
  }
  function draw() {
    var k = V.kpis;
    $('kpis').innerHTML = tile(k.subnets, 'Subnets in the plan', '', '') + tile(k.addresses, 'Addresses in use', '', '', '') + tile(k.addresses ? Math.round(k.in_plan / k.addresses * 100) + '%' : '—', 'Covered by the plan', '', 'unplanned', 'Show addresses in no subnet')
      + tile(k.conflicts, 'Conflicts', k.conflicts ? 'text-red' : '', 'conflict', 'One address, two devices') + tile(k.unknown, 'Not in the asset register', k.unknown ? 'text-yellow' : '', 'unknown') + tile(k.stale, 'Stale', '', '') + tile(k.nearly_full, 'Subnets 80 %+ full', k.nearly_full ? 'text-orange' : '', '') + tile(k.reserved, 'Reserved', '', '');
    var S = V.subnets;
    $('subn').textContent = S.length + ' subnet(s)';
    $('subs').innerHTML = S.length ? '<table class="table table-vcenter card-table"><thead><tr><th>Subnet</th><th>Site · VLAN</th><th>Used</th><th>Free</th><th>Next free</th><th>Growth (learned)</th><th></th></tr></thead><tbody>' + S.slice().sort(function (a, b) { return b.pct - a.pct; }).map(function (s) {
      var L = s.learning || {};
      return '<tr class="rowc" data-sub="' + esc(s.id) + '"><td><b class="mono">' + esc(s.cidr) + '</b><div class="mut">' + esc(s.name) + (s.purpose ? ' · ' + esc(s.purpose) : '') + '</div></td><td>' + esc(s.site || '—') + (s.vlan ? ' · VLAN ' + esc(s.vlan) : '') + '</td>'
        + '<td style="min-width:150px"><div class="d-flex align-items-center gap-2"><div class="bar flex-fill"><i style="width:' + Math.min(100, s.pct) + '%;background:' + col(s.pct) + '"></i></div><b>' + esc(s.pct) + '%</b></div><div class="mut">' + esc(s.used) + ' of ' + esc(s.usable) + (s.dhcp_size ? ' · DHCP ' + esc(s.dhcp_used) + '/' + esc(s.dhcp_size) : '') + '</div></td>'
        + '<td>' + esc(s.free) + '</td><td class="mono">' + esc(s.next_free || 'none') + '</td><td class="small">' + (L.growth_per_day != null ? (L.growth_per_day > 0 ? '+' : '') + esc(L.growth_per_day) + ' a day' + (L.days_to_full != null ? '<div class="' + (L.days_to_full < 60 ? 'text-orange' : 'mut') + '">full in about ' + esc(L.days_to_full) + ' days</div>' : '') : '<span class="mut">' + esc(L.why || '') + '</span>') + '</td>'
        + '<td>' + (op() && s.next_free ? '<button type="button" class="btn btn-sm" data-res="' + esc(s.next_free) + '">Reserve ' + esc(s.next_free) + '</button>' : '') + '</td></tr>';
    }).join('') + '</tbody></table>' : '<div class="card-body text-secondary">No subnet registered yet.' + (op() ? ' Add the first one, or register a proposed network below.' : '') + '</div>';
    if (!V.can_details) {
      ['finds', 'props', 'resv'].forEach(function (id) { $(id).innerHTML = '<span class="text-secondary">Addresses and host names are internal: operators and administrators see them.</span>'; });
      $('addr').innerHTML = '<div class="card-body text-secondary">Operators and administrators see the addresses.</div>';
    } else {
      $('finds').innerHTML = V.findings.length ? V.findings.slice(0, 60).map(function (f) { return '<div class="fd s-' + esc(f.severity) + '"><b>' + esc(f.title) + '</b><div class="mut">' + esc(f.fix) + '</div></div>'; }).join('') : '<span class="text-secondary">Nothing - the plan and what the network shows agree.</span>';
      $('props').innerHTML = V.proposals.length ? V.proposals.map(function (p) { return '<div class="d-flex align-items-center mb-2"><div class="me-auto"><b class="mono">' + esc(p.cidr) + '</b> <span class="mut">' + esc(p.addresses) + ' address(es) · e.g. ' + esc(p.sample.join(', ')) + '</span></div>' + (op() ? '<button type="button" class="btn btn-sm" data-prop="' + esc(p.cidr) + '">Register</button>' : '') + '</div>'; }).join('') : '<span class="text-secondary">Every address in use is inside a registered subnet.</span>';
      $('resv').innerHTML = V.reservations.length ? '<table class="table table-sm"><tbody>' + V.reservations.map(function (r) { return '<tr><td class="mono">' + esc(r.ip) + '</td><td>' + esc(r.name) + '<div class="mut">' + esc(r.purpose || '') + (r.until ? ' · until ' + esc(r.until) : '') + ' · by ' + esc(r.by) + '</div></td><td>' + (op() ? '<button type="button" class="btn btn-sm btn-ghost-danger" data-rel="' + esc(r.id) + '">Release</button>' : '') + '</td></tr>'; }).join('') + '</tbody></table>' : '<span class="text-secondary">No reservation.</span>';
      drawAddr();
    }
    $('ais').textContent = V.ai && V.ai.enabled ? 'read-only' : 'not available: ' + ((V.ai && V.ai.reason) || '');
    $('ago').disabled = !(V.ai && V.ai.enabled) || !op();
    $('addsub').hidden = !op(); $('note').textContent = V.note;
  }
  function addrMatch(a) {
    if (AF === 'conflict' && a.macs.length < 2) return false; if (AF === 'unplanned' && a.subnet) return false; if (AF === 'unknown' && a.assets.length) return false; if (AF === 'asset' && !a.assets.length) return false;
    if (SF && a.subnet !== SF) return false;
    return !Q || [a.ip, a.hosts.join(' '), a.macs.join(' '), a.assets.map(function (x) { return x.name; }).join(' ')].join(' ').toLowerCase().indexOf(Q) >= 0;
  }
  function drawAddr() {
    var L = (V.addresses || []).filter(addrMatch), sn = {}; V.subnets.forEach(function (s) { sn[s.id] = s.cidr; });
    $('addr').innerHTML = (SF ? '<div class="card-body py-2">Showing ' + esc(sn[SF]) + ' <a href="#" data-sf="">show all</a></div>' : '') + (L.length ? '<table class="table table-vcenter card-table table-sm"><thead><tr><th>Address</th><th>Host</th><th>MAC</th><th>Asset</th><th>Subnet</th><th>Seen by</th><th>Last seen</th></tr></thead><tbody>' + L.slice(0, 1000).map(function (a) {
      return '<tr><td class="mono"><b>' + esc(a.ip) + '</b>' + (a.reserved ? ' <span class="badge bg-purple-lt">reserved</span>' : '') + '</td><td>' + esc(a.hosts.join(', ') || '—') + '</td><td class="mono small">' + (a.macs.length > 1 ? '<span class="badge bg-red-lt">conflict</span> ' : '') + esc(a.macs.join(', ') || '—') + '</td>'
        + '<td>' + (a.assets.length ? a.assets.map(function (x) { return esc(x.name); }).join(', ') : '<span class="badge bg-yellow-lt">not registered</span>') + '</td><td class="mono small">' + (a.subnet ? esc(sn[a.subnet]) : '<span class="badge bg-orange-lt">not in the plan</span>') + '</td><td class="small">' + esc(a.sources.join(', ')) + '</td><td class="small">' + esc(a.last_seen ? a.last_seen.slice(0, 10) : '—') + '</td></tr>';
    }).join('') + '</tbody></table>' + (L.length > 1000 ? '<div class="card-footer mut">First 1,000 of ' + L.length + ' - search to narrow.</div>' : '') : '<div class="card-body text-secondary">' + ((V.addresses || []).length ? 'No address matches.' : 'No address seen yet - the asset register and Asset Discovery feed this list.') + '</div>');
  }
  function subForm(pre) {
    pre = pre || {};
    var f = function (n, l, v, h, extra) { return '<label class="form-label mb-1">' + esc(l) + '</label><input class="form-control mb-1" name="' + n + '" value="' + esc(v || '') + '"' + (extra || '') + '><div class="mut mb-2">' + esc(h || '') + '</div>'; };
    Z.open('IP Address Management', pre.id ? 'Edit subnet ' + pre.cidr : 'Add a subnet', '<form id="sf">' + (pre.id ? '<input type="hidden" name="id" value="' + esc(pre.id) + '">' : '')
      + f('cidr', 'Network (CIDR)', pre.cidr, 'e.g. 10.20.5.0/24 - /8 to /30', ' required maxlength="18"') + f('name', 'Name', pre.name, 'what people call it', ' required maxlength="80"') + f('site', 'Site', pre.site, 'e.g. Riyadh HQ, DR site') + f('vlan', 'VLAN', pre.vlan, '1 - 4094', ' inputmode="numeric"')
      + f('gateway', 'Gateway', pre.gateway, 'an address inside the network, outside the DHCP range') + f('dhcp_start', 'DHCP range start', pre.dhcp_start, 'leave both empty when the subnet has no DHCP') + f('dhcp_end', 'DHCP range end', pre.dhcp_end, '') + f('purpose', 'Purpose', pre.purpose, 'e.g. users floor 5, servers, CCTV') + f('owner', 'Owner', pre.owner, 'the person or team responsible')
      + '<button type="submit" class="btn btn-primary">Save</button>' + (pre.id ? ' <button type="button" class="btn btn-ghost-danger" data-retire="' + esc(pre.id) + '">Retire this subnet</button>' : '') + '<div class="mut mt-2" id="sfm"></div></form>');
  }
  function load() {
    var w = new Promise(function (ok) { var x = new XMLHttpRequest(); x.open('GET', '/dashboards/whoami.json'); x.onload = function () { try { ok(JSON.parse(x.responseText)); } catch (e) { ok(null); } }; x.onerror = function () { ok(null); }; x.send(); });
    return w.then(function (me) { ROLE = String((me && me.role) || 'viewer').toLowerCase(); return req('GET', '/ipam'); }).then(function (v) { V = v; $('err').hidden = true; $('main').hidden = false; draw(); $('up').textContent = 'updated ' + new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }); })
      .catch(function (e) { $('main').hidden = true; $('err').hidden = false; $('err').textContent = e.status === 404 ? 'IP Address Management is not installed on the server yet - run the update.' : 'Could not load: ' + e.message; });
  }
  document.addEventListener('click', function (ev) {
    var t = ev.target; if (!t.closest) return;
    var f = t.closest('[data-f]'); if (f && f.getAttribute('data-f')) { var v = f.getAttribute('data-f'); AF = AF === v ? '' : v; $('af').value = AF; draw(); $('addr').scrollIntoView({ behavior: 'smooth' }); return; }
    var sf = t.closest('[data-sf]'); if (sf) { ev.preventDefault(); SF = sf.getAttribute('data-sf'); drawAddr(); return; }
    var rs = t.closest('[data-res]'); if (rs) { ev.stopPropagation(); var ip = rs.getAttribute('data-res'); Z.open('IP Address Management', 'Reserve ' + ip, '<form id="rf"><input type="hidden" name="ip" value="' + esc(ip) + '"><label class="form-label">For (device or host name)</label><input class="form-control mb-2" name="name" required maxlength="80"><label class="form-label">Purpose</label><input class="form-control mb-2" name="purpose" maxlength="200"><label class="form-label">Until (optional)</label><input class="form-control mb-2" name="until" type="date"><button type="submit" class="btn btn-primary">Reserve</button><div class="mut mt-2" id="rfm"></div></form>'); return; }
    var pr = t.closest('[data-prop]'); if (pr) { subForm({ cidr: pr.getAttribute('data-prop') }); return; }
    var rl = t.closest('[data-rel]'); if (rl) { var why = window.prompt('Why is this reservation released?'); if (!why) return; req('POST', '/ipam/reservations/' + encodeURIComponent(rl.getAttribute('data-rel')) + '/release', { reason: why }).then(function () { toast('Released'); load(); }, function (e) { toast(e.message); }); return; }
    var rt = t.closest('[data-retire]'); if (rt) { var r2 = window.prompt('Why is this subnet retired?'); if (!r2) return; req('POST', '/ipam/subnets/' + encodeURIComponent(rt.getAttribute('data-retire')) + '/retire', { reason: r2 }).then(function () { toast('Subnet retired'); if (Z.close) Z.close(); load(); }, function (e) { toast(e.message); }); return; }
    var sr = t.closest('[data-sub]'); if (sr) { var s = V.subnets.filter(function (x) { return x.id === sr.getAttribute('data-sub'); })[0]; if (!s) return;
      if (!op()) { SF = s.id; return; }
      subForm(s); var b = document.getElementById('sf'); if (b) b.insertAdjacentHTML('beforebegin', '<div class="mb-3"><b>' + esc(s.used) + ' of ' + esc(s.usable) + ' used</b> · next free <span class="mono">' + esc(s.next_free || 'none') + '</span> <a href="#" data-sf="' + esc(s.id) + '">show its addresses</a>' + grid(s) + '</div>'); return; }
    if (t.id === 'addsub') { subForm(null); return; }
    if (t.id === 'refresh' || t.closest('#refresh')) { load(); return; }
    if (t.id === 'csv' || t.closest('#csv')) { if (!V || !V.addresses) { toast('Operators and administrators export the addresses'); return; }
      var sn = {}; V.subnets.forEach(function (x) { sn[x.id] = x.cidr; }); var cell = function (v) { v = String(v == null ? '' : v); if (/^[=+\-@]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
      var rows = [['address', 'subnet', 'hosts', 'macs', 'assets', 'sources', 'last_seen', 'reserved']].concat(V.addresses.map(function (a) { return [a.ip, sn[a.subnet] || '', a.hosts.join(' '), a.macs.join(' '), a.assets.map(function (x) { return x.name; }).join(' '), a.sources.join(' '), a.last_seen || '', a.reserved || '']; }));
      var blob = new Blob([rows.map(function (r) { return r.map(cell).join(','); }).join('\r\n')], { type: 'text/csv' }), u = URL.createObjectURL(blob), l = document.createElement('a'); l.href = u; l.download = 'ip-addresses-' + new Date().toISOString().slice(0, 10) + '.csv'; document.body.appendChild(l); l.click(); setTimeout(function () { URL.revokeObjectURL(u); l.remove(); }, 500); }
  });
  document.addEventListener('submit', function (ev) {
    var f = ev.target;
    var el = function (k) { var x = f.elements.namedItem(k); return x ? String(x.value || '').trim() : ''; };   // f.id / f.name are the form's own attributes, not its inputs
    if (f.id === 'sf') { ev.preventDefault(); var b = {}; ['id', 'cidr', 'name', 'site', 'gateway', 'dhcp_start', 'dhcp_end', 'purpose', 'owner'].forEach(function (k) { if (el(k)) b[k] = el(k); }); if (el('vlan')) b.vlan = Number(el('vlan'));
      $('sfm').textContent = 'Saving…'; req('POST', '/ipam/subnets', b).then(function (r) { toast('Saved ' + r.cidr); if (Z.close) Z.close(); load(); }, function (e) { $('sfm').textContent = e.message; }); }
    if (f.id === 'rf') { ev.preventDefault(); var r = { ip: el('ip'), name: el('name') }; if (el('purpose')) r.purpose = el('purpose'); if (el('until')) r.until = el('until');
      $('rfm').textContent = 'Reserving…'; req('POST', '/ipam/reserve', r).then(function (x) { toast(x.ip + ' reserved for ' + x.name); if (Z.close) Z.close(); load(); }, function (e) { $('rfm').textContent = e.message; }); }
    if (f.id === 'af2') { ev.preventDefault(); var q = $('aq').value.trim(); if (!q) return; $('aa').innerHTML = '<span class="text-secondary">Thinking…</span>';
      req('POST', '/ipam/ask', { question: q }).then(function (r) { $('aa').innerHTML = '<div style="white-space:pre-wrap">' + esc(r.answer) + '</div>'; }, function (e) { $('aa').innerHTML = '<span class="text-red">' + esc(e.message) + '</span>'; }); }
  });
  $('q').addEventListener('input', function () { Q = this.value.trim().toLowerCase(); drawAddr(); });
  $('af').addEventListener('change', function () { AF = this.value; draw(); });
  load();
})();
