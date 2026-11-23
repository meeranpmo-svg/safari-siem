// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-netinv.js - keeps the portal's "Infrastructure Inventory" (NET_ASSETS, shared via /api/netassets) up to date
 * from IT Asset Management automatically: firewalls, switches / routers, servers (physical, VM, storage) and cloud
 * servers, plus workstations / laptops and printers / scanners (own tabs), found by discovery, vCenter, agents or added
 * in ITAM appear without anyone typing them in.
 *   - synced rows have id "itam-<asset id>" and source "itam"; they are refreshed every 5 minutes and when the page opens
 *   - rows added by hand are kept; an ITAM asset with the same IP or name as a hand-made row is not added twice
 *   - assets retired / disposed / deleted in ITAM drop out of the inventory on the next sync
 *   - only operators / admins write the shared list (the portal's own rule for changes); nothing is written when
 *     ITAM is unreachable, so an outage never empties the inventory
 * Loaded by zyb-menu.js. */
(function () {
  'use strict';
  if (window.__zybNetinv) return; window.__zybNetinv = true;
  var EVERY = 5 * 60000, CLOSED = { retired: 1, disposed: 1 };
  var FW = /forti|palo ?alto|pa-\d|check ?point|sophos|asa\b|firepower|sonicwall|watchguard|juniper srx|srx\d/i;
  var LAST = { at: 0, n: 0, err: '' }, BUSY = false, LIFE = null;

  function has() { try { return typeof NET_ASSETS !== 'undefined' && Array.isArray(NET_ASSETS); } catch (e) { return false; } }   // eslint-disable-line no-undef
  function canWrite() { try { return typeof _can !== 'function' || _can('operate'); } catch (e) { return false; } }            // eslint-disable-line no-undef
  function get(p) {
    return fetch(p, { credentials: 'include', cache: 'no-store' }).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
  }
  function low(v) { return String(v || '').trim().toLowerCase(); }

  /* ITAM asset -> inventory row (or null when it does not belong in the infrastructure inventory) */
  function toRow(a) {
    if (!a || !a.id || CLOSED[a.status]) return null;
    var tags = (a.tags || []).map(low), vm = a.type === 'vm';
    var vendor = [a.vendor, a.model].filter(Boolean).join(' ');
    var cat = null, role = '';
    if (tags.indexOf('cloud') >= 0 || (a.discovery && a.discovery['class'] === 'cloud')) {
      if (['server', 'vm', 'storage'].indexOf(a.type) < 0) return null; cat = 'cloud';
    } else if (a.type === 'network') {
      var fw = tags.indexOf('firewall') >= 0 || (tags.indexOf('switch') < 0 && tags.indexOf('router') < 0 && FW.test(vendor + ' ' + (a.name || '')));
      cat = fw ? 'firewall' : 'switch';
      ['core', 'distribution', 'access', 'router', 'access-point', 'wireless-controller', 'load-balancer', 'sd-wan', 'vpn', 'firewall', 'switch'].some(function (r) { if (tags.indexOf(r) >= 0) { role = r.replace(/-/g, ' ') + (/^(core|distribution|access)$/.test(r) ? ' switch' : ''); return true; } return false; });
    } else if (a.type === 'server' || vm || a.type === 'storage') cat = 'server';
    else if (a.type === 'workstation' || a.type === 'laptop') { cat = 'workstation'; role = [a.owner, a.type === 'laptop' ? 'Laptop' : 'Workstation'].filter(Boolean).join(' · '); }
    else if (a.type === 'printer') { cat = 'printer'; role = 'Printer'; }
    else if (a.type === 'peripheral' && /scan/i.test([a.name, a.model, a.vendor].concat(tags).join(' '))) { cat = 'printer'; role = 'Scanner'; }
    if (!cat) return null;
    if (cat === 'workstation') role = [role, a.os].filter(Boolean).join(' · ');
    if (a.type === 'network' && /\d+\s*ports/i.test(a.notes || '')) return { id: 'itam-' + a.id, cat: cat, name: a.name || a.mgmt_ip || a.id, vendor: vendor, ip: a.mgmt_ip || '', spec: (/(\d+)\s*ports/i.exec(a.notes) || [])[1] + ' ports', role: role, site: a.site || '', source: 'itam', asset_id: a.id };
    var spec = [vm ? 'VM' : a.type === 'storage' ? 'Storage' : '', a.cpu ? a.cpu + (/^\d+$/.test(String(a.cpu)) ? ' vCPU' : '') : '', a.mem_gb ? a.mem_gb + ' GB' : '', a.os || ''].filter(Boolean).join(' · ');
    return { id: 'itam-' + a.id, cat: cat, name: a.name || a.asset_tag || a.mgmt_ip || a.id, vendor: vendor, ip: a.mgmt_ip || '', spec: spec,
      role: role || (a.department || ''), site: a.site || '', source: 'itam', asset_id: a.id };
  }

  var AUTO = { itam: 1, disc: 1, siem: 1 };
  /* discovered but not yet approved workstations / printers (Asset Discovery, decision "New") */
  /* Cisco family from the sysDescr software image when SNMP gave no model ("CAT9K_IOSXE" → Catalyst 9000 series) */
  function family(t) {
    if (!/cisco/i.test(t)) return '';
    var m = /\(([A-Z0-9_]+?)(?:-[A-Z0-9]+)*-M\)|\((CAT\d+K[A-Z0-9_]*)\)|\b(C\d{4}[A-Z]{0,3})\s+Software/i.exec(t); if (!m) return '';
    var c = (m[1] || m[2] || m[3]).toUpperCase(), f = /^CAT(\d+)K/.exec(c), g = /^C(\d{4})([A-Z]{0,3})/.exec(c);
    return f ? 'Catalyst ' + f[1] + '000 series' : g ? 'Catalyst ' + g[1] + (g[2] ? '-' + g[2] : '') + ' series' : '';
  }
  function discRow(d) {
    if (!d || !d.id || d.asset_id || d.status !== 'new') return null;
    var cat = d.type === 'workstation' ? 'workstation' : d.type === 'printer' ? 'printer' : d.type === 'firewall' ? 'firewall' : (d.type === 'switch' || d.type === 'router' || d.type === 'ap') ? 'switch' : null; if (!cat) return null;
    var model = d.model || family(d.os || (d.sys && d.sys.descr) || ''), vend = d.vendor || '';
    return { id: 'disc-' + d.id, cat: cat, name: d.hostname || d.ip || d.id, vendor: model ? (low(model).indexOf(low(vend)) === 0 ? model : [vend, model].filter(Boolean).join(' ')) : vend, ip: d.ip || '', spec: '', model: d.model || '', role: ['discovered · not approved yet', d.os || ''].filter(Boolean).join(' · '), site: d.site || '', source: 'disc' };
  }
  /* switches, routers and firewalls the AI Network Engineer monitors (SIEM netops inventory) */
  function netopsRows(devs) {
    return ((devs && devs.items) || []).filter(function (d) { return d.vendor !== 'edgeconnect' && d.vendor !== 'genian' && d.role !== 'nac' && !/^sdwan/.test(d.role || ''); }).map(function (d) {
      var fw = d.role === 'firewall' || /fortigate|paloalto|asa/.test(d.vendor || '');
      return { id: 'svc-net-' + d.id, cat: fw ? 'firewall' : 'switch', name: d.name || d.id, vendor: ({ 'cisco-ios': 'Cisco IOS', 'cisco-asa': 'Cisco ASA', fortigate: 'Fortinet FortiGate', paloalto: 'Palo Alto' })[d.vendor] || d.vendor || '', ip: d.ip || '',
        spec: '', role: [d.role || '', d.last ? (d.last.ok ? 'monitored · reachable' : 'monitored · ' + ((d.last.errors || [])[0] || 'not reachable')) : 'monitored'].filter(Boolean).join(' · '), site: d.site || '', source: 'siem' };
    });
  }
  /* Zscaler, Silver Peak and Cloudflare as the SIEM knows them (log sources, SD-WAN orchestrator, Cloudflare pull) */
  function svcRows(src, devs, cf) {
    var out = [], S = (src && src.sources) || [], add = function (o) { out.push(Object.assign({ cat: 'service', spec: '', source: 'siem' }, o)); };
    var st = function (s) { return s.state === 'receiving' ? 'connected · logs arriving' : s.state === 'silent' ? 'connected · no logs recently' : 'waiting for first logs'; };
    var zs = S.filter(function (s) { return /zscaler/i.test(s.kind + ' ' + s.id + ' ' + s.label); });
    zs.forEach(function (s) { add({ id: 'svc-src-' + s.id, name: s.label || s.id, vendor: /zpa/i.test(s.kind + s.id) ? 'Zscaler Private Access (ZPA)' : 'Zscaler Internet Access (ZIA)', ip: s.match_ip || '', role: st(s), site: s.site || '' }); });
    if (!zs.length) add({ id: 'svc-zscaler', name: 'Zscaler', vendor: 'Zscaler ZIA / ZPA', ip: '', role: 'not connected to the SIEM (Connect & Onboard → Zscaler)', site: '' });
    var sp = 0;
    ((devs && devs.items) || []).filter(function (d) { return d.vendor === 'edgeconnect'; }).forEach(function (d) {
      sp++; add({ id: 'svc-nd-' + d.id, name: d.name || d.id, vendor: 'HPE Aruba EdgeConnect (Silver Peak) Orchestrator', ip: d.ip || '', role: d.last ? (d.last.ok ? 'API connected' : 'API error: ' + ((d.last.errors || [])[0] || 'unreachable')) : 'not polled yet', site: d.site || '' });
      ((d.appliances) || []).forEach(function (a) { add({ id: 'svc-sp-' + d.id + '-' + (a.name || a.ip), name: a.name || a.ip, vendor: ['EdgeConnect', a.model].filter(Boolean).join(' '), ip: a.ip || '', role: (a.up ? 'up' : 'down') + (a.state ? ' · ' + a.state : '') + (a.version ? ' · ' + a.version : ''), site: a.site || '' }); });
    });
    S.filter(function (s) { return /silver|edgeconnect/i.test(s.kind + ' ' + s.id); }).forEach(function (s) { sp++; add({ id: 'svc-src-' + s.id, name: s.label || s.id, vendor: 'Silver Peak / EdgeConnect logs', ip: s.match_ip || '', role: st(s), site: s.site || '' }); });
    if (!sp) add({ id: 'svc-silverpeak', name: 'Silver Peak SD-WAN', vendor: 'HPE Aruba EdgeConnect (Silver Peak)', ip: '', role: 'not connected (AI Network Engineer → add the Orchestrator)', site: '' });
    if (cf && (cf.account_id || (cf.zones || []).length)) {
      var e = cf.status && (cf.status.last_error || cf.status.error);
      add({ id: 'svc-cf-acct', name: 'Cloudflare account', vendor: 'Cloudflare', ip: cf.account_id ? cf.account_id.slice(0, 8) + '…' : '', role: !cf.enabled ? 'configured · collection off' : e ? 'error: ' + e : 'connected · audit + security events', site: '' });
      (cf.zones || []).forEach(function (z) { add({ id: 'svc-cf-' + z, name: 'Cloudflare zone ' + String(z).slice(0, 8) + '…', vendor: 'Cloudflare WAF / CDN', ip: '', role: cf.enabled && !e ? 'security events collected' : 'not collecting', site: '' }); });
    } else if (cf !== undefined) add({ id: 'svc-cloudflare', name: 'Cloudflare', vendor: 'Cloudflare', ip: '', role: cf === null ? 'status visible to SIEM admins only' : 'not connected (Cloud sources → Cloudflare)', site: '' });
    return out;
  }
  function merge(cur, assets, extra) {
    var manual = cur.filter(function (r) { return r && !AUTO[r.source] && !/^(itam|disc|svc)-/.test(String(r.id || '')); });
    var seenIp = {}, seenName = {};
    manual.forEach(function (r) { if (r.ip) seenIp[low(r.ip)] = 1; if (r.name) seenName[low(r.name)] = 1; });
    var synced = [];
    assets.forEach(function (a) {
      var r = toRow(a); if (!r) return;
      if ((r.ip && seenIp[low(r.ip)]) || seenName[low(r.name)]) return;   // already registered by hand
      if (r.ip) seenIp[low(r.ip)] = 1; seenName[low(r.name)] = 1;
      synced.push(r);
    });
    (extra || []).forEach(function (r) {
      var dev = r.source === 'disc' || /^svc-net-/.test(r.id);   // devices (not services): never listed twice
      if (dev && ((r.ip && seenIp[low(r.ip)]) || seenName[low(r.name)])) return;   // already an asset or registered
      if (dev) { if (r.ip) seenIp[low(r.ip)] = 1; seenName[low(r.name)] = 1; }
      synced.push(r);
    });
    synced.sort(function (x, y) { return x.cat === y.cat ? (x.name < y.name ? -1 : 1) : (x.cat < y.cat ? -1 : 1); });
    return { list: manual.concat(synced), n: synced.length };
  }

  function sync(force) {
    if (BUSY || !has()) return Promise.resolve();
    if (!force && Date.now() - LAST.at < EVERY - 5000) return Promise.resolve();
    BUSY = true;
    var opt = function (p) { return get(p).catch(function () { return null; }); };
    return Promise.all([get('/api/itam/assets?limit=5000'), opt('/api/itam/discovery/results?status=new&type=workstation&limit=5000'), opt('/api/itam/discovery/results?status=new&type=printer&limit=2000'),
      opt('/api/soc/onboard/sources'), opt('/api/soc/netops/devices'), get('/api/soc/cloud/cloudflare').catch(function (e) { return /403|401/.test(e.message) ? null : false; }), opt('/api/itam/lifecycle'), opt('/api/itam/discovery/results?status=new&type=switch&limit=2000'), opt('/api/itam/discovery/results?status=new&type=firewall&limit=500')]).then(function (R) {
      var j = R[0]; LIFE = R[6] || LIFE;
      if (!j || !Array.isArray(j.assets)) throw new Error('unexpected answer from IT Asset Management');
      var extra = [];
      [R[1], R[2], R[7], R[8]].forEach(function (x) { ((x && x.devices) || []).forEach(function (d) { var r = discRow(d); if (r) extra.push(r); }); });
      extra = extra.concat(netopsRows(R[4]));
      if (R[3] || R[4]) return detailSp(R[4]).then(function () { return finish(j, extra.concat(svcRows(R[3], R[4], R[5] === false ? undefined : R[5]))); });
      var keep = NET_ASSETS.filter(function (r) { return r.source === 'siem'; });   // eslint-disable-line no-undef
      return finish(j, extra.concat(keep));
    }).catch(function (e) { LAST.err = e.message || String(e); LAST.at = Date.now(); }).then(function () { BUSY = false; banner(); });
  }
  /* EdgeConnect appliances come from each Orchestrator's last poll */
  function detailSp(devs) {
    var sp = ((devs && devs.items) || []).filter(function (d) { return d.vendor === 'edgeconnect'; });
    return Promise.all(sp.map(function (d) { return get('/api/soc/netops/devices/' + encodeURIComponent(d.id)).then(function (x) { d.appliances = (x && x.snapshot && x.snapshot.sdwan && x.snapshot.sdwan.appliances) || []; }).catch(function () { d.appliances = []; }); }));
  }
  function finish(j, extra) {
    {
      var m = merge(NET_ASSETS, j.assets, extra);   // eslint-disable-line no-undef
      if (LIFE && LIFE.items) {   // flag end-of-support devices in their row
        var eos = {}; LIFE.items.forEach(function (i) { if (i.status === 'eol' || i.status === 'soon') eos[(i.source === 'discovery' ? 'disc-' : 'itam-') + i.id] = i; });
        m.list.forEach(function (r) { var i = eos[r.id]; if (i) { r.eos = i.status; r.role = (i.status === 'eol' ? '⚠ END OF SUPPORT' : '⏳ support ends ' + (i.eol || 'soon')) + ' (' + i.product + ')' + (r.role ? ' · ' + r.role : ''); } });
      }
      LAST = { at: Date.now(), n: m.n, err: '' };
      if (JSON.stringify(m.list) === JSON.stringify(NET_ASSETS)) return;   // eslint-disable-line no-undef
      NET_ASSETS = m.list;   // eslint-disable-line no-undef
      if (canWrite() && typeof _saveNet === 'function') _saveNet();   // eslint-disable-line no-undef
      else { try { localStorage.setItem('net_assets_ash', JSON.stringify(m.list)); } catch (e) { /* private window */ } }
      try { if (typeof currentView !== 'undefined' && currentView === 'netinv' && typeof renderFocus === 'function') renderFocus(); } catch (e) { /* portal redraws later */ }   // eslint-disable-line no-undef
    }
  }

  /* a line in the Infrastructure Inventory page that says where the rows come from, plus "Sync now" */
  function onPage() { try { return typeof currentView !== 'undefined' && currentView === 'netinv'; } catch (e) { return false; } }   // eslint-disable-line no-undef
  function banner() {
    if (!onPage()) return;
    var add = document.querySelector('[data-netaddtoggle]'); if (!add) return;
    var bar = add.parentNode, b = document.getElementById('zyb-netsync');
    if (!b) { b = document.createElement('span'); b.id = 'zyb-netsync'; b.style.cssText = 'font-size:11px;color:var(--muted);display:inline-flex;gap:8px;align-items:center'; bar.insertBefore(b, add); }
    var when = LAST.at ? new Date(LAST.at).toLocaleTimeString() : '…';
    b.innerHTML = (LAST.err ? '<span class="stpill" style="font-size:10px;border-color:#f85149;color:#f85149" title="' + LAST.err.replace(/"/g, '&quot;') + '">● ITAM sync failed</span>'
      : '<span class="stpill ok" style="font-size:10px">● auto-synced from IT Asset Management</span>')
      + '<span>' + LAST.n + ' assets · last sync ' + when + '</span>'
      + '<button type="button" data-zybnetsync style="border:1px solid var(--line);background:transparent;color:var(--txt);border-radius:6px;padding:4px 10px;cursor:pointer;font-size:11px">⟳ Sync now</button>';
    [].forEach.call(document.querySelectorAll('[data-netrem^="itam-"]'), function (x) { x.title = 'Delete from IT Asset Management'; });
    clickable(bar);
  }

  /* tiles open their section (an empty one opens "Add Asset" with that category), rows open the server's live status,
     and a search box filters every section */
  var TILE = { 'total assets': '', isps: 'isp', firewalls: 'firewall', switches: 'switch', servers: 'server', cloud: 'cloud', workstations: 'workstation', 'printers & scanners': 'printer', 'cloud services': 'service' };
  var EXTRA = [{ k: 'workstation', label: 'Workstation / Laptop', icon: '💻', cols: ['Hostname', 'Vendor / Model', 'IP', 'User · type · OS', 'Site'], tile: 'Workstations' },
    { k: 'printer', label: 'Printer / Scanner', icon: '🖨️', cols: ['Name', 'Vendor / Model', 'IP', 'Type', 'Site'], tile: 'Printers & scanners' },
    { k: 'service', label: 'Cloud & Network Services (Zscaler, Silver Peak, Cloudflare)', icon: '🌐', cols: ['Name', 'Vendor / Product', 'IP / ID', 'Status', 'Site'], tile: 'Cloud services' }];
  var TABS = [['infra', '🏢 Infrastructure', ['isp', 'firewall', 'switch', 'server', 'cloud']], ['users', '💻 Workstations & laptops', ['workstation']], ['print', '🖨️ Printers & scanners', ['printer']], ['svc', '🌐 Cloud & network services', ['service']], ['all', 'All', null]];
  var TAB = 'infra', Q = '';
  try { TAB = sessionStorage.getItem('zyb-nettab') || 'infra'; } catch (e) { /* private window */ }
  /* the portal draws one section per NET_CATS entry: add the two end-user categories (the add form gets them too) */
  function extendCats() {
    try {
      if (typeof NET_CATS === 'undefined' || !Array.isArray(NET_CATS)) return;   // eslint-disable-line no-undef
      EXTRA.forEach(function (c) { if (!NET_CATS.some(function (x) { return x.k === c.k; })) NET_CATS.push({ k: c.k, label: c.label, icon: c.icon, cols: c.cols }); });   // eslint-disable-line no-undef
      if (typeof NET_HINTS !== 'undefined') { NET_HINTS.workstation = NET_HINTS.workstation || ['Hostname (PC-0123)', 'Vendor / model (Dell OptiPlex)', 'IP address', '—', 'User · OS', 'Site']; NET_HINTS.printer = NET_HINTS.printer || ['Name (PRN-HQ-2F)', 'Vendor / model (Xerox AltaLink)', 'IP address', '—', 'Printer / Scanner', 'Site'];  NET_HINTS.service = NET_HINTS.service || ['Name (Zscaler ZIA tenant)', 'Vendor / product', 'IP / tenant ID', '—', 'Status / notes', 'Site']; }   // eslint-disable-line no-undef
    } catch (e) { /* older portal */ }
  }
  function catLabel(cat) { try { var c = (typeof NET_CATS !== 'undefined' ? NET_CATS : []).filter(function (x) { return x.k === cat; })[0]; return c ? c.label : cat; } catch (e) { return cat; } }   // eslint-disable-line no-undef
  function catOfTitle(t) { try { var c = (typeof NET_CATS !== 'undefined' ? NET_CATS : []).filter(function (x) { return t.textContent.indexOf(x.label) >= 0; }); return c.length ? c[0].k : ''; } catch (e) { return ''; } }   // eslint-disable-line no-undef
  function sectionOf(cat) {
    var t = [].filter.call(document.querySelectorAll('.section-title'), function (x) { return catOfTitle(x) === cat; })[0];
    return t || null;
  }
  function tabOf(cat) { for (var i = 0; i < TABS.length; i++) if (TABS[i][2] && TABS[i][2].indexOf(cat) >= 0) return TABS[i][0]; return 'all'; }
  function applyTab() {
    var tb = TABS.filter(function (x) { return x[0] === TAB; })[0] || TABS[0];
    [].forEach.call(document.querySelectorAll('[data-zybtab]'), function (b) { var on = b.getAttribute('data-zybtab') === TAB; b.setAttribute('aria-selected', String(on)); b.style.borderBottomColor = on ? 'var(--accent,#4D8DFF)' : 'transparent'; b.style.color = on ? 'var(--txt)' : 'var(--muted)'; });
    [].forEach.call(document.querySelectorAll('.section-title'), function (t) {
      var cat = catOfTitle(t); if (!cat) return; var show = !tb[2] || tb[2].indexOf(cat) >= 0;
      t.style.display = show ? '' : 'none'; var n = t.nextElementSibling; if (n && !n.classList.contains('section-title')) n.style.display = show ? '' : 'none';
    });
  }
  function setTab(t) { TAB = t; try { sessionStorage.setItem('zyb-nettab', t); } catch (e) { /* private window */ } applyTab(); }
  function rowsOf(t) { var n = t && t.nextElementSibling; while (n && !n.querySelector('table') && n.tagName !== 'TABLE') { if (n.classList.contains('section-title')) return []; n = n.nextElementSibling; } return n ? [].slice.call(n.querySelectorAll('tbody tr, tr')).filter(function (r) { return r.querySelector('td'); }) : []; }
  function clickable(bar) {
    var host = add0(); if (!host) return;
    var stats = host.querySelector('.noc-stats');
    if (stats && !stats.querySelector('[data-zybextra]')) {
      stats.style.gridTemplateColumns = 'repeat(auto-fit,minmax(140px,1fr))';
      EXTRA.forEach(function (c) { var n = NET_ASSETS.filter(function (a) { return a.cat === c.k; }).length; var d = document.createElement('div'); d.className = 'noc-stat'; d.setAttribute('data-zybextra', c.k); d.innerHTML = '<div class="v">' + n + '</div><div class="k">' + c.tile + '</div>'; stats.appendChild(d); });   // eslint-disable-line no-undef
      if (LIFE && LIFE.summary) {   // end of service: opens the End of Life & Isolation page
        var e = document.createElement('div'), S = LIFE.summary; e.className = 'noc-stat'; e.setAttribute('data-zybextra', 'eos'); e.setAttribute('data-zybgo-page', '/dashboards/lifecycle.html'); e.setAttribute('role', 'link'); e.setAttribute('tabindex', '0');
        e.style.cursor = 'pointer'; e.title = 'Open End of Life & Isolation'; if (S.eol) e.style.borderColor = '#f85149';
        e.innerHTML = '<div class="v" style="' + (S.eol ? 'color:#ff7b72' : '') + '">' + S.eol + '</div><div class="k">End of service</div><div style="font-size:10px;color:var(--muted)">' + S.soon + ' ending in 180 days' + (S.isolated ? ' · ' + S.isolated + ' isolated' : '') + '</div>';
        stats.appendChild(e);
      }
    }
    if (stats && !document.getElementById('zyb-nettabs')) {
      var tabs = document.createElement('div'); tabs.id = 'zyb-nettabs'; tabs.setAttribute('role', 'tablist'); tabs.style.cssText = 'display:flex;gap:4px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin:4px 0 14px';
      tabs.innerHTML = TABS.map(function (t) { var n = t[2] ? NET_ASSETS.filter(function (a) { return t[2].indexOf(a.cat) >= 0; }).length : NET_ASSETS.length; return '<button type="button" role="tab" data-zybtab="' + t[0] + '" style="background:none;border:0;border-bottom:2px solid transparent;padding:8px 14px;cursor:pointer;font-size:13px;font-weight:600">' + t[1] + ' <span style="font-size:11px;opacity:.7">' + n + '</span></button>'; }).join('');   // eslint-disable-line no-undef
      stats.parentNode.insertBefore(tabs, stats.nextSibling);
    }
    if (stats) [].forEach.call(stats.children, function (el) {
      if (el.getAttribute('data-zybtile')) return;
      var k = (el.querySelector('.k') || el).textContent.trim().toLowerCase(); if (!(k in TILE)) return;
      el.setAttribute('data-zybtile', TILE[k] || 'all'); el.setAttribute('role', 'button'); el.setAttribute('tabindex', '0'); el.style.cursor = 'pointer';
      el.title = TILE[k] ? 'Show the ' + k : 'Show everything';
    });
    if (!document.getElementById('zyb-netq')) {
      var q = document.createElement('input'); q.id = 'zyb-netq'; q.type = 'search'; q.placeholder = 'Search name, IP, vendor, site…'; q.setAttribute('aria-label', 'Search the inventory');
      q.style.cssText = 'padding:6px 10px;border:1px solid var(--line);border-radius:7px;background:transparent;color:var(--txt);font-size:12px;width:220px'; q.value = Q;
      q.addEventListener('input', function () { Q = q.value.trim().toLowerCase(); filter(); });
      bar.insertBefore(q, document.getElementById('zyb-netsync'));
    }
    [].forEach.call(document.querySelectorAll('.section-title'), function (t) {
      rowsOf(t).forEach(function (r) {
        if (r.getAttribute('data-zybrow')) return; r.setAttribute('data-zybrow', '1');
        var rm = r.querySelector('[data-netrem]'), id = rm && rm.getAttribute('data-netrem'), a = id && NET_ASSETS.filter(function (x) { return x.id === id; })[0];   // eslint-disable-line no-undef
        if (a && a.ip && (a.cat === 'server' || a.cat === 'cloud')) { r.style.cursor = 'pointer'; r.title = 'Open live status in Server Availability'; r.setAttribute('data-zybgo', '/dashboards/server-availability.html#' + encodeURIComponent(a.ip)); }
      });
    });
    filter(); applyTab();
  }
  function add0() { var b = document.querySelector('[data-netaddtoggle]'); var n = b; while (n && n.parentNode && !(n.parentNode.querySelector && n.parentNode.querySelector('.noc-stats'))) n = n.parentNode; return n && n.parentNode; }
  function filter() {
    [].forEach.call(document.querySelectorAll('[data-zybrow]'), function (r) { r.style.display = !Q || r.textContent.toLowerCase().indexOf(Q) >= 0 ? '' : 'none'; });
  }
  function openTile(cat) {
    if (cat === 'all') { setTab('all'); var f = document.querySelector('.section-title'); if (f) f.scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
    if (TAB !== 'all' && tabOf(cat) !== TAB) setTab(tabOf(cat));
    var t = sectionOf(cat), rows = rowsOf(t);
    if (!rows.length || (rows.length === 1 && /none yet/.test(rows[0].textContent))) {   // nothing there yet: add one
      var form = document.getElementById('naForm'); if (form && form.style.display !== 'block') { var tg = document.querySelector('[data-netaddtoggle]'); if (tg) tg.click(); }
      setTimeout(function () { var sel = document.getElementById('naCat'); if (sel) { sel.value = cat; sel.dispatchEvent(new Event('change', { bubbles: true })); try { if (typeof _netApplyHints === 'function') _netApplyHints(); } catch (e) { /* hints optional */ } var nm = document.getElementById('naName'); if (nm) nm.focus(); } }, 50);   // eslint-disable-line no-undef
      return;
    }
    t.scrollIntoView({ behavior: 'smooth', block: 'start' });
    t.style.transition = 'background .4s'; t.style.background = 'rgba(88,166,255,.18)'; setTimeout(function () { t.style.background = ''; }, 1400);
  }

  document.addEventListener('click', function (e) {
    var tt = e.target && e.target.closest && e.target.closest('[data-zybtab]'); if (tt && onPage()) { setTab(tt.getAttribute('data-zybtab')); return; }
    var pg = e.target && e.target.closest && e.target.closest('[data-zybgo-page]'); if (pg && onPage()) { window.location.href = pg.getAttribute('data-zybgo-page'); return; }
    var tl = e.target && e.target.closest && e.target.closest('[data-zybtile]'); if (tl && onPage()) { openTile(tl.getAttribute('data-zybtile')); return; }
    var gr = e.target && e.target.closest && e.target.closest('tr[data-zybgo]'); if (gr && !e.target.closest('button') && onPage()) { window.location.href = gr.getAttribute('data-zybgo'); return; }
    var t = e.target && e.target.closest && e.target.closest('[data-zybnetsync],[data-netrem^="itam-"],[data-zybedit],[data-zybdel]'); if (!t) return;
    e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation();
    if (t.hasAttribute('data-zybnetsync')) { t.disabled = true; t.textContent = 'Syncing…'; sync(true); return; }
    if (t.hasAttribute('data-zybedit')) { editForm(t.getAttribute('data-zybedit')); return; }
    delAsk(t.getAttribute('data-zybdel') || t.getAttribute('data-netrem'));
  }, true);

  /* Switches / Firewall pages: "Add switch" / "Add firewall" right there. Saved in IT Asset Management (network device
     with the role tag) so it appears everywhere; without ITAM rights it goes into the shared inventory list instead. */
  function curView() { try { return typeof currentView !== 'undefined' ? currentView : ''; } catch (e) { return ''; } }   // eslint-disable-line no-undef
  var ADDV = { switches: { cat: 'switch', label: 'switch', roles: [['switch', 'Switch'], ['core', 'Core switch'], ['distribution', 'Distribution switch'], ['access', 'Access switch'], ['router', 'Router'], ['access-point', 'Access point']] },
    firewall: { cat: 'firewall', label: 'firewall', roles: [['firewall', 'Firewall'], ['vpn', 'VPN gateway'], ['load-balancer', 'Load balancer']] } };
  function addButton() {
    var v = ADDV[curView()]; if (!v) return;
    var head = document.querySelector('.vhead'); if (!head || head.querySelector('[data-zybadd]')) return;
    var b = document.createElement('button'); b.type = 'button'; b.className = 'btn'; b.setAttribute('data-zybadd', curView()); b.style.cssText = 'padding:6px 14px;font-size:12px;font-weight:700;margin-left:8px';
    b.textContent = '➕ Add ' + v.label; var sp = head.querySelector('.vspacer'); head.insertBefore(b, sp ? sp.nextSibling : null);
  }
  function addForm(view) {
    var v = ADDV[view]; if (!v) return;
    var old = document.getElementById('zyb-addov'); if (old) { old.remove(); return; }
    var I = 'style="padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:transparent;color:var(--txt);font-size:12px;width:100%"';
    var f = document.createElement('div'); f.id = 'zyb-addf'; f.setAttribute('data-cat', v.cat);
    f.style.cssText = 'background:var(--panel,#13151B);color:var(--txt,#ECEEF2);border:1px solid var(--line,#2E3440);border-radius:12px;padding:16px;width:min(760px,100%);display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:9px;align-items:end;box-shadow:0 20px 60px rgba(0,0,0,.5)';
    f.setAttribute('role', 'dialog'); f.setAttribute('aria-modal', 'true');
    f.innerHTML = '<div style="grid-column:1/-1;font-size:15px;font-weight:700">➕ Add ' + v.label + '</div><label style="font-size:11px;color:var(--muted)">Hostname *<input id="za-n" ' + I + ' placeholder="SW-CORE-01"></label><label style="font-size:11px;color:var(--muted)">Management IP *<input id="za-ip" ' + I + ' placeholder="192.168.1.2"></label>'
      + '<label style="font-size:11px;color:var(--muted)">Vendor<input id="za-v" ' + I + ' placeholder="Cisco / Aruba / Huawei"></label><label style="font-size:11px;color:var(--muted)">Model<input id="za-m" ' + I + ' placeholder="Catalyst 9300-48P"></label>'
      + '<label style="font-size:11px;color:var(--muted)">Role<select id="za-r" ' + I + '>' + v.roles.map(function (r) { return '<option value="' + r[0] + '">' + r[1] + '</option>'; }).join('') + '</select></label>'
      + (v.cat === 'switch' ? '<label style="font-size:11px;color:var(--muted)">Ports<input id="za-p" ' + I + ' placeholder="48"></label>' : '')
      + '<label style="font-size:11px;color:var(--muted)">Site<input id="za-s" ' + I + ' placeholder="Riyadh HQ" list="zyb-sites"></label><datalist id="zyb-sites"></datalist>'
      + snmpBlock(I, v.label)
      + '<div style="display:flex;gap:8px"><button type="button" class="btn" data-zybaddsave style="padding:7px 16px">Add</button><button type="button" class="btn ghost" data-zybaddcancel style="padding:7px 14px">Cancel</button></div>'
      + '<div id="za-msg" style="grid-column:1/-1;font-size:11px;color:var(--muted)">Saved in IT Asset Management as a network device, so it shows up in the inventory, here and on Server / network dashboards. Reachability goes live once it is monitored (AI Network Engineer or SNMP).</div>';
    var ov = document.createElement('div'); ov.id = 'zyb-addov'; ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100000;display:flex;align-items:flex-start;justify-content:center;padding:60px 16px;overflow:auto';
    ov.addEventListener('click', function (e) { if (e.target === ov) ov.remove(); }); ov.appendChild(f); document.body.appendChild(ov); document.getElementById('za-n').focus();
    snmpWire();
    get('/api/itam/locations').then(function (j) { var dl = document.getElementById('zyb-sites'); if (dl) dl.innerHTML = ((j && j.locations) || []).map(function (l) { return '<option value="' + String(l.name).replace(/"/g, '&quot;') + '">'; }).join(''); }).catch(function () { /* no list */ });
  }
  function addSave(btn) {
    var f = document.getElementById('zyb-addf'); if (!f) return;
    var g = function (id) { var e = document.getElementById(id); return e ? String(e.value || '').trim() : ''; }, msg = document.getElementById('za-msg');
    var name = g('za-n'), ip = g('za-ip'), cat = f.getAttribute('data-cat'), role = g('za-r');
    if (!name) { msg.textContent = 'Enter the hostname.'; msg.style.color = '#ff7b72'; return; }
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || ip.split('.').some(function (o) { return +o > 255; })) { msg.textContent = 'Enter a valid management IP (e.g. 192.168.1.2).'; msg.style.color = '#ff7b72'; return; }
    var dup = (has() ? NET_ASSETS : []).filter(function (r) { return low(r.ip) === low(ip) || low(r.name) === low(name); })[0];   // eslint-disable-line no-undef
    if (dup) { msg.textContent = '"' + dup.name + '" (' + (dup.ip || 'no IP') + ') is already in the inventory.'; msg.style.color = '#ff7b72'; return; }
    var snErr = snmpCheck(); if (snErr) { msg.textContent = snErr; msg.style.color = '#ff7b72'; return; }
    btn.disabled = true; btn.textContent = 'Saving…';
    var body = { type: 'network', name: name, mgmt_ip: ip, vendor: g('za-v'), model: g('za-m'), site: g('za-s'), status: 'in_use', tags: [cat === 'firewall' ? 'firewall' : (role === 'router' ? 'router' : 'switch')].concat(role && role !== 'switch' && role !== 'firewall' ? [role] : []), notes: g('za-p') ? g('za-p') + ' ports' : '' };
    fetch('/api/itam/assets', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { if (!r.ok) throw Object.assign(new Error(j.error || ('HTTP ' + r.status)), { status: r.status }); return j; });
    }).then(function (j) {
      var aid = j && (j.asset ? j.asset.id : j.id), sn = snmpChoice();
      if (sn && aid) { btn.textContent = 'SNMP…'; return snmpScan(aid, ip, name, sn, msg).then(function (r) { closeAdd(); toastMsg('Added "' + name + '"' + r); return sync(true); }, function (er) { closeAdd(); toastMsg('Added "' + name + '" - SNMP not completed: ' + er.message); return sync(true); }); }
      closeAdd(); toastMsg('Added "' + name + '" to IT Asset Management'); return sync(true);
    }).catch(function (e) {
      if (e.status === 403 || e.status === 401 || e.status === 404 || e.status === 0) {   // no ITAM rights: keep it in the shared inventory list
        if (!canWrite()) { btn.disabled = false; btn.textContent = 'Add'; msg.textContent = 'Your role cannot add devices.'; msg.style.color = '#ff7b72'; return; }
        NET_ASSETS.push({ id: 'na-' + Date.now().toString(36), cat: cat, name: name, vendor: [g('za-v'), g('za-m')].filter(Boolean).join(' '), ip: ip, spec: g('za-p') ? g('za-p') + ' ports' : '', role: role, site: g('za-s') });   // eslint-disable-line no-undef
        try { if (typeof _saveNet === 'function') _saveNet(); if (typeof renderFocus === 'function') renderFocus(); } catch (er) { /* portal redraws later */ }   // eslint-disable-line no-undef
        closeAdd(); toastMsg('Added "' + name + '" to the shared inventory list');
      } else { btn.disabled = false; btn.textContent = 'Add'; msg.textContent = 'Not added: ' + e.message; msg.style.color = '#ff7b72'; }
    });
  }

  /* SNMP while adding a switch / firewall (System Admin - the discovery credential vault and scans are admin-only):
     pick a saved SNMP credential or enter a new v2c community / v3 user (stored encrypted in the discovery vault), then
     one scan of that IP reads name, model, serial, firmware, location and LLDP / CDP neighbours, and the result is
     merged into the device just added. The scan goes through the same safety gate (approval) as every other scan. */
  var SN = { creds: null, sites: null, user: '', admin: null };
  function snmpBlock(I, label) {
    var L = function (t, inner, cls) { return '<label class="' + (cls || '') + '" style="font-size:11px;color:var(--muted)">' + t + inner + '</label>'; };
    return '<div id="za-snmp" style="grid-column:1/-1;border:1px solid var(--line);border-radius:10px;padding:10px;display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:9px;align-items:end">'
      + '<label style="grid-column:1/-1;display:flex;gap:8px;align-items:center;font-size:12.5px;font-weight:700"><input type="checkbox" id="za-sn-on" checked> SNMP - read the ' + label + '\'s model, serial, firmware and neighbours</label>'
      + '<div id="za-sn-body" style="display:contents">'
      + L('SNMP credential', '<select id="za-sn-c" ' + I + '><option value="new">New credential…</option></select>')
      + L('Version', '<select id="za-sn-v" ' + I + '><option value="v2c">v2c (community)</option><option value="v3">v3 (user)</option></select>', 'zsn-new')
      + L('Community *', '<input id="za-sn-cm" type="password" autocomplete="new-password" ' + I + '>', 'zsn-new zsn-2')
      + L('User *', '<input id="za-sn-u" ' + I + '>', 'zsn-new zsn-3')
      + L('Authentication', '<select id="za-sn-a" ' + I + '><option value="sha">SHA</option><option value="sha256">SHA-256</option></select>', 'zsn-new zsn-3')
      + L('Auth password * (8+)', '<input id="za-sn-ap" type="password" autocomplete="new-password" ' + I + '>', 'zsn-new zsn-3')
      + L('Privacy', '<select id="za-sn-p" ' + I + '><option value="aes">AES</option><option value="none">None</option></select>', 'zsn-new zsn-3')
      + L('Privacy password * (8+)', '<input id="za-sn-pp" type="password" autocomplete="new-password" ' + I + '>', 'zsn-new zsn-3 zsn-pv')
      + L('UDP port', '<input id="za-sn-port" type="number" value="161" ' + I + '>', 'zsn-new')
      + L('Discovery site *', '<select id="za-sn-site" ' + I + '><option value="">Loading…</option></select>')
      + ('<label style="grid-column:1/-1;display:flex;gap:8px;align-items:flex-start;font-size:11.5px;color:var(--muted)"><input type="checkbox" id="za-sn-fw"> <span>The network allows the platform server (' + ZYB_ORG.platform_addr + ') to reach this ') + label + ' on SNMP UDP 161 and ping.</span></label>'
      + L('Security team / SOC told *', '<input id="za-sn-soc" ' + I + '>') + L('Approved by *', '<input id="za-sn-ap2" ' + I + '>')
      + '</div><div id="za-sn-note" style="grid-column:1/-1;font-size:11px;color:var(--muted)">Stored encrypted; never shown again. The ' + label + ' also needs this SNMP community / user configured (read-only).</div></div>';
  }
  function snShow() {
    var on = document.getElementById('za-sn-on'); if (!on) return;
    var body = document.getElementById('za-sn-body'); body.style.display = on.checked ? 'contents' : 'none';
    var isNew = document.getElementById('za-sn-c').value === 'new', v3 = document.getElementById('za-sn-v').value === 'v3', np = document.getElementById('za-sn-p').value === 'none';
    [].forEach.call(document.querySelectorAll('#za-snmp .zsn-new'), function (x) { x.style.display = isNew ? '' : 'none'; });
    [].forEach.call(document.querySelectorAll('#za-snmp .zsn-2'), function (x) { if (isNew) x.style.display = v3 ? 'none' : ''; });
    [].forEach.call(document.querySelectorAll('#za-snmp .zsn-3'), function (x) { if (isNew) x.style.display = v3 ? '' : 'none'; });
    [].forEach.call(document.querySelectorAll('#za-snmp .zsn-pv'), function (x) { if (isNew && v3) x.style.display = np ? 'none' : ''; });
  }
  function snmpWire() {
    ['za-sn-on', 'za-sn-c', 'za-sn-v', 'za-sn-p'].forEach(function (id) { var e = document.getElementById(id); if (e) e.onchange = snShow; });
    snShow();
    var fill = function () {
      var c = document.getElementById('za-sn-c'), st = document.getElementById('za-sn-site'); if (!c) return;
      if (SN.admin === false) { document.getElementById('za-sn-on').checked = false; document.getElementById('za-sn-on').disabled = true; document.getElementById('za-sn-note').textContent = 'SNMP setup needs the System Admin role (it stores a credential and scans the network). The device is still added; an admin can add SNMP later under Asset Discovery.'; snShow(); return; }
      c.innerHTML = '<option value="new">New credential…</option>' + (SN.creds || []).filter(function (x) { return /^snmp_/.test(x.kind); }).map(function (x) { return '<option value="' + esc(x.id) + '">' + esc(x.label) + ' (' + (x.kind === 'snmp_v3' ? 'v3' : 'v2c') + ')</option>'; }).join('');
      if ((SN.creds || []).some(function (x) { return /^snmp_/.test(x.kind); })) c.selectedIndex = 1;
      st.innerHTML = (SN.sites || []).length ? (SN.sites.length > 1 ? '<option value="">Choose…</option>' : '') + SN.sites.map(function (x) { return '<option>' + esc(x) + '</option>'; }).join('') : '<option value="">No discovery sites - add one in Asset Discovery settings</option>';
      var ap = document.getElementById('za-sn-ap2'); if (ap && !ap.value) ap.value = SN.user || '';
      snShow();
    };
    if (SN.admin !== null) { fill(); return; }
    Promise.all([api('GET', '/api/itam/discovery/credentials').catch(function (e) { return { err: e }; }), api('GET', '/api/itam/discovery/scopes').catch(function () { return {}; }), fetch('/auth/whoami', { credentials: 'include' }).then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; })]).then(function (r) {
      SN.admin = !(r[0].err && (r[0].err.status === 403 || r[0].err.status === 401)); SN.creds = r[0].credentials || []; SN.sites = r[1].sites || []; SN.user = (r[2] && (r[2].name || r[2].user)) || ''; fill();
    });
  }
  function snmpChoice() { var on = document.getElementById('za-sn-on'); return on && on.checked && !on.disabled ? { cred: document.getElementById('za-sn-c').value } : null; }
  function gv(id) { var e = document.getElementById(id); return e ? String(e.value || '').trim() : ''; }
  function snmpCheck() {
    if (!snmpChoice()) return '';
    if (gv('za-sn-c') === 'new') {
      if (gv('za-sn-v') === 'v2c') { if (!gv('za-sn-cm')) return 'Enter the SNMP community (or untick SNMP).'; }
      else if (!gv('za-sn-u') || gv('za-sn-ap').length < 8 || (gv('za-sn-p') === 'aes' && gv('za-sn-pp').length < 8)) return 'SNMP v3 needs the user and 8+ character passwords.';
    }
    if (!gv('za-sn-site')) return 'Choose the discovery site for the SNMP scan.';
    if (!document.getElementById('za-sn-fw').checked || !gv('za-sn-soc') || !gv('za-sn-ap2')) return 'The SNMP scan needs the approval: tick the network confirmation, and fill who in the SOC was told and the approver.';
    return '';
  }
  function snmpScan(assetId, ip, name, sn, msg) {
    var D = '/api/itam/discovery', say = function (t) { msg.textContent = t; msg.style.color = 'var(--muted)'; };
    var credP = sn.cred !== 'new' ? Promise.resolve(sn.cred) : (function () {
      var v3 = gv('za-sn-v') === 'v3', port = +gv('za-sn-port') || 161, body;
      if (v3) { var sec = { user: gv('za-sn-u'), auth_password: document.getElementById('za-sn-ap').value }; if (gv('za-sn-p') === 'aes') sec.priv_password = document.getElementById('za-sn-pp').value; body = { kind: 'snmp_v3', label: 'SNMP v3 ' + gv('za-sn-u') + ' (' + name + ')', secret: sec, target: { auth_protocol: gv('za-sn-a'), priv_protocol: gv('za-sn-p'), port: port } }; }
      else body = { kind: 'snmp_v2c', label: 'SNMP v2c (' + name + ')', secret: { community: document.getElementById('za-sn-cm').value }, target: { port: port } };
      say('Saving the SNMP credential…');
      return api('POST', D + '/credentials', body).then(function (j) { SN.creds = (SN.creds || []).concat([j.credential]); return j.credential.id; });
    })();
    var scopeName = 'Network device ' + ip, scope;
    return credP.then(function (cid) {
      say('Preparing the SNMP scan…');
      var body = { name: scopeName, site: gv('za-sn-site'), targets: [ip], infra: true, methods: { sweep: { enabled: true }, snmp: { enabled: true, credential_ids: [cid] } } };
      return api('GET', D + '/scopes').then(function (j) {
        var ex = (j.scopes || []).filter(function (x) { return x.name === scopeName && x.status !== 'archived'; })[0];
        return api('POST', ex ? D + '/scopes/' + ex.id : D + '/scopes', body);
      });
    }).then(function (j) {
      scope = j.scope;
      return scope.status && scope.status !== 'active' ? api('POST', D + '/scopes/' + scope.id + '/enable', {}) : null;
    }).then(function () {
      return api('POST', D + '/scopes/' + scope.id + '/checklist', { firewall: { snmp_161: true, ssh_22: true, winrm_5985_5986: true, icmp: true }, soc_notified_name: gv('za-sn-soc'), soc_notified_date: new Date().toISOString().slice(0, 10), approved_by: gv('za-sn-ap2'), note: 'Added from the ' + name + ' form' });
    }).then(function () { say('Scanning ' + ip + ' over SNMP…'); return api('POST', D + '/scopes/' + scope.id + '/run', {}); }).then(function (j) {
      var t0 = Date.now(), id = j.run.id;
      var poll = function () {
        return api('GET', D + '/runs/' + encodeURIComponent(id)).then(function (x) {
          var r = x.run || {};
          if (r.status === 'running' || r.status === 'queued') { if (Date.now() - t0 > 180000) throw new Error('the scan is still running - check Asset Discovery → Runs'); return new Promise(function (ok) { setTimeout(ok, 2500); }).then(poll); }
          return r;
        });
      };
      return poll();
    }).then(function (r) {
      if (r.status !== 'finished') throw new Error('scan ' + r.status + (r.error ? ': ' + r.error : ''));
      return api('GET', D + '/results?status=all&limit=50&scope_id=' + encodeURIComponent(scope.id));
    }).then(function (j) {
      var d = (j.devices || []).filter(function (x) { return x.ip === ip; })[0];
      if (!d) return (' - it did not answer ping or SNMP from ' + ZYB_ORG.platform_addr);
      var gotSnmp = (d.methods_seen || []).indexOf('snmp') >= 0;
      var merge = d.status === 'new' ? api('POST', D + '/results/' + encodeURIComponent(d.id) + '/merge', { asset_id: assetId }).catch(function () { return null; }) : Promise.resolve(null);
      return merge.then(function () { return gotSnmp ? ' - SNMP read: ' + [d.vendor, d.model, d.serial ? 'serial ' + d.serial : '', d.os].filter(Boolean).join(', ') : ' - it answered ping but not SNMP with this credential (check the community / user on the device)'; });
    });
  }
  function closeAdd() { var o = document.getElementById('zyb-addov'); if (o) o.remove(); }
  function toastMsg(m) { try { if (typeof infoToast === 'function') { infoToast(m); return; } } catch (e) { /* none */ } }   // eslint-disable-line no-undef
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest && e.target.closest('[data-zybadd]'); if (a) { e.preventDefault(); e.stopPropagation(); addForm(a.getAttribute('data-zybadd')); return; }
    if (e.target && e.target.closest && e.target.closest('[data-zybaddsave]')) { e.preventDefault(); addSave(e.target.closest('[data-zybaddsave]')); return; }
    if (e.target && e.target.closest && e.target.closest('[data-zybaddcancel]')) closeAdd();
  }, true);

  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeAdd(); });
  document.addEventListener('keydown', function (e) { if ((e.key === 'Enter' || e.key === ' ') && e.target && e.target.getAttribute && e.target.getAttribute('data-zybtile')) { e.preventDefault(); openTile(e.target.getAttribute('data-zybtile')); } });

  /* Edit / Delete. A row synced from IT Asset Management is changed there - edit needs Operator, delete needs Admin and a
     reason (engine/asset-delete.js keeps who / when / why in the audit trail) - and the inventory follows on the next
     sync. A row typed into the shared list is changed in that list. Infrastructure Inventory gets ✎ beside each ✕; the
     Switches and Firewall pages, which list the same rows with no buttons at all, get ✎ and ✕. */
  var ROLE_TAGS = ['core', 'distribution', 'access', 'router', 'access-point', 'wireless-controller', 'load-balancer', 'sd-wan', 'vpn', 'firewall', 'switch'];
  function rowById(id) { return has() ? NET_ASSETS.filter(function (x) { return x.id === id; })[0] || null : null; }   // eslint-disable-line no-undef
  function api(m, p, b) {
    return fetch(p, { method: m, credentials: 'include', headers: b ? { 'Content-Type': 'application/json' } : {}, body: b ? JSON.stringify(b) : undefined }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { if (!r.ok) throw Object.assign(new Error(j.error || ('HTTP ' + r.status)), { status: r.status, j: j }); return j; });
    });
  }
  function esc(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  var EI = 'style="padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:transparent;color:var(--txt);font-size:12px;width:100%;box-sizing:border-box"';
  function dialog(html) {
    closeEd();
    var ov = document.createElement('div'); ov.id = 'zyb-edov'; ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100000;display:flex;align-items:flex-start;justify-content:center;padding:60px 16px;overflow:auto';
    var f = document.createElement('div'); f.setAttribute('role', 'dialog'); f.setAttribute('aria-modal', 'true');
    f.style.cssText = 'background:var(--panel,#13151B);color:var(--txt,#ECEEF2);border:1px solid var(--line,#2E3440);border-radius:12px;padding:16px;width:min(760px,100%);display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:9px;align-items:end;box-shadow:0 20px 60px rgba(0,0,0,.5)';
    f.innerHTML = html; ov.appendChild(f); ov.addEventListener('click', function (e) { if (e.target === ov) closeEd(); }); document.body.appendChild(ov);
    return f;
  }
  function closeEd() { var o = document.getElementById('zyb-edov'); if (o) o.remove(); }
  function say(t, bad) { var m = document.getElementById('ze-msg'); if (m) { m.textContent = t; m.style.color = bad ? '#ff7b72' : 'var(--muted)'; } }
  function lab(t, inner) { return '<label style="font-size:11px;color:var(--muted)">' + t + inner + '</label>'; }
  function rolesFor(cat) { var v = cat === 'firewall' ? ADDV.firewall : cat === 'switch' ? ADDV.switches : null; return v ? v.roles : null; }
  function editForm(id) {
    var r = rowById(id); if (!r) return;
    if (!canWrite()) { toastMsg('🔒 Read-only role - ask an admin for Operator rights.'); return; }
    var roles = rolesFor(r.cat), itam = r.source === 'itam' && r.asset_id;
    var f = dialog('<div style="grid-column:1/-1;font-size:15px;font-weight:700">✎ Edit ' + esc(r.name) + '</div>'
      + lab('Hostname *', '<input id="ze-n" ' + EI + ' value="' + esc(r.name) + '">') + lab('Management IP' + (roles ? ' *' : ''), '<input id="ze-ip" ' + EI + ' value="' + esc(r.ip) + '" dir="ltr">')
      + lab('Vendor', '<input id="ze-v" ' + EI + ' value="' + esc(itam ? '' : r.vendor) + '">') + lab('Model', '<input id="ze-m" ' + EI + '>')
      + (roles ? lab('Role', '<select id="ze-r" ' + EI + '>' + roles.map(function (x) { return '<option value="' + x[0] + '">' + x[1] + '</option>'; }).join('') + '</select>') : '')
      + (r.cat === 'switch' ? lab('Ports', '<input id="ze-p" ' + EI + ' value="' + esc((/(\d+)/.exec(r.spec || '') || [])[1] || '') + '">') : '')
      + lab('Site', '<input id="ze-s" ' + EI + ' value="' + esc(r.site) + '">')
      + '<div style="display:flex;gap:8px"><button type="button" class="btn" id="ze-save" style="padding:7px 16px">Save</button><button type="button" class="btn ghost" id="ze-cancel" style="padding:7px 14px">Cancel</button></div>'
      + '<div id="ze-msg" style="grid-column:1/-1;font-size:11px;color:var(--muted)">' + (itam ? 'Saved in IT Asset Management; discovery will not overwrite the values you change here.' : 'Saved in the shared inventory list.') + '</div>');
    var cur = null, g = function (k) { var e = document.getElementById(k); return e ? String(e.value || '').trim() : ''; };
    if (roles) { var rs = document.getElementById('ze-r'), rv = low(r.role).replace(/ switch$/, '').replace(/ /g, '-'); if ([].some.call(rs.options, function (o) { return o.value === rv; })) rs.value = rv; }
    if (itam) api('GET', '/api/itam/assets/' + encodeURIComponent(r.asset_id)).then(function (j) {
      cur = j.asset || j; document.getElementById('ze-v').value = cur.vendor || ''; document.getElementById('ze-m').value = cur.model || '';
      if (roles) { var t = (cur.tags || []).map(low), hit = roles.filter(function (x) { return t.indexOf(x[0]) >= 0 && x[0] !== 'switch' && x[0] !== 'firewall'; })[0]; if (hit) document.getElementById('ze-r').value = hit[0]; }
    }).catch(function (e) { say('Could not load the asset: ' + e.message, true); });
    document.getElementById('ze-cancel').onclick = closeEd;
    document.getElementById('ze-save').onclick = function () {
      var btn = this, name = g('ze-n'), ip = g('ze-ip'), role = g('ze-r');
      if (!name) { say('Enter the hostname.', true); return; }
      if ((ip || roles) && (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || ip.split('.').some(function (o) { return +o > 255; }))) { say('Enter a valid management IP (e.g. 192.168.1.2).', true); return; }
      var dup = NET_ASSETS.filter(function (x) { return x.id !== r.id && ((ip && low(x.ip) === low(ip)) || low(x.name) === low(name)); })[0];   // eslint-disable-line no-undef
      if (dup) { say('"' + dup.name + '" (' + (dup.ip || 'no IP') + ') already has this name or IP.', true); return; }
      btn.disabled = true; btn.textContent = 'Saving…';
      if (!itam) {
        r.name = name; r.ip = ip; r.vendor = [g('ze-v'), g('ze-m')].filter(Boolean).join(' '); r.site = g('ze-s'); if (roles) r.role = role; if (r.cat === 'switch') r.spec = g('ze-p') ? g('ze-p') + ' ports' : '';
        try { if (typeof _saveNet === 'function') _saveNet(); if (typeof renderFocus === 'function') renderFocus(); } catch (er) { /* portal redraws later */ }   // eslint-disable-line no-undef
        closeEd(); toastMsg('Saved "' + name + '"'); return;
      }
      var body = { name: name, mgmt_ip: ip, vendor: g('ze-v'), model: g('ze-m'), site: g('ze-s') };
      if (roles) {
        var keep = ((cur && cur.tags) || []).filter(function (t) { return ROLE_TAGS.indexOf(low(t)) < 0; });
        body.tags = keep.concat([r.cat === 'firewall' ? 'firewall' : (role === 'router' ? 'router' : 'switch')]).concat(role && role !== 'switch' && role !== 'firewall' && role !== 'router' ? [role] : []);
      }
      if (r.cat === 'switch') { var notes = String((cur && cur.notes) || '').replace(/\s*\d+\s*ports\b/i, '').trim(); body.notes = [g('ze-p') ? g('ze-p') + ' ports' : '', notes].filter(Boolean).join(' · '); }
      api('POST', '/api/itam/assets/' + encodeURIComponent(r.asset_id), body).then(function () { closeEd(); toastMsg('Saved "' + name + '" in IT Asset Management'); return sync(true); })
        .catch(function (e) { btn.disabled = false; btn.textContent = 'Save'; say(e.status === 403 ? 'Your role cannot change assets in IT Asset Management (Operator or Admin needed).' : 'Not saved: ' + e.message, true); });
    };
    document.getElementById('ze-n').focus();
  }
  function delAsk(id) {
    var r = rowById(id); if (!r) return;
    if (!(r.source === 'itam' && r.asset_id)) { if (typeof _netRemove === 'function') _netRemove(id); return; }   // eslint-disable-line no-undef
    var f = dialog('<div style="grid-column:1/-1;font-size:15px;font-weight:700;color:#ff8a95">✕ Delete ' + esc(r.name) + (r.ip ? ' <span style="font-weight:400;font-size:12px;color:var(--muted)">' + esc(r.ip) + '</span>' : '') + '</div>'
      + '<div style="grid-column:1/-1;font-size:12px;color:var(--muted)">This removes the device from IT Asset Management (and so from this inventory). The audit trail keeps who deleted it, when and why. To keep its history instead, retire it in IT Asset Management.</div>'
      + '<div style="grid-column:1/-1">' + lab('Reason *', '<input id="ze-why" ' + EI + ' placeholder="e.g. replaced by SW-CORE-02 / added by mistake">') + '</div>'
      + '<div style="grid-column:1/-1">' + lab('If discovery finds it again', '<select id="ze-disc" ' + EI + '><option value="review">Show it again for review</option><option value="ignore">Ignore it (keep it out)</option></select>') + '</div>'
      + '<div style="display:flex;gap:8px"><button type="button" class="btn" id="ze-del" style="padding:7px 16px;background:#c62f3e;border-color:#c62f3e;color:#fff">Delete</button><button type="button" class="btn ghost" id="ze-cancel" style="padding:7px 14px">Cancel</button></div>'
      + '<div id="ze-msg" style="grid-column:1/-1;font-size:11px;color:var(--muted)"></div>');
    var force = false;
    document.getElementById('ze-cancel').onclick = closeEd;
    document.getElementById('ze-del').onclick = function () {
      var btn = this, why = String(document.getElementById('ze-why').value || '').trim();
      if (why.length < 3) { say('Enter the reason.', true); return; }
      btn.disabled = true; btn.textContent = 'Deleting…';
      api('POST', '/api/itam/assets/' + encodeURIComponent(r.asset_id) + '/delete', { reason: why, discovery: document.getElementById('ze-disc').value, force: force }).then(function () {
        NET_ASSETS = NET_ASSETS.filter(function (x) { return x.id !== r.id; });   // eslint-disable-line no-undef
        try { if (typeof renderFocus === 'function') renderFocus(); } catch (er) { /* portal redraws later */ }   // eslint-disable-line no-undef
        closeEd(); toastMsg('Deleted "' + r.name + '" from IT Asset Management'); return sync(true);
      }).catch(function (e) {
        btn.disabled = false; btn.textContent = 'Delete';
        if (e.status === 409 && e.j && /siem/i.test(e.message)) { force = true; btn.textContent = 'Delete anyway'; say(e.message, true); return; }
        if (e.status === 404 && e.j && e.j.error === 'asset not found') { NET_ASSETS = NET_ASSETS.filter(function (x) { return x.id !== r.id; }); closeEd(); sync(true); return; }   // eslint-disable-line no-undef
        say(e.status === 403 ? 'Only an administrator can delete from IT Asset Management. Ask an admin, or retire the asset there.' : e.status === 404 ? 'Delete is not installed on this server yet (run the server update).' : 'Not deleted: ' + e.message, true);
      });
    };
    document.getElementById('ze-why').focus();
  }
  var BTN = 'border:1px solid var(--line);background:transparent;border-radius:6px;padding:3px 9px;cursor:pointer;font-size:11px;margin-inline-end:4px';
  function rowButtons() {
    if (!has()) return;
    if (onPage()) [].forEach.call(document.querySelectorAll('[data-netrem]'), function (x) {
      if (x.previousElementSibling && x.previousElementSibling.hasAttribute('data-zybedit')) return;
      var b = document.createElement('button'); b.type = 'button'; b.setAttribute('data-zybedit', x.getAttribute('data-netrem')); b.title = 'Edit'; b.textContent = '✎'; b.style.cssText = BTN + ';color:var(--txt)';
      x.parentNode.insertBefore(b, x);
    });
    var v = ADDV[curView()]; if (!v) return;
    var mine = NET_ASSETS.filter(function (a) { return a.cat === v.cat; });   // eslint-disable-line no-undef
    if (!mine.length) return;
    [].forEach.call(document.querySelectorAll('#viewFocus table'), function (t) {
      var trs = t.querySelectorAll('tbody tr'), hit = 0;
      [].forEach.call(trs, function (tr) {
        if (tr.querySelector('[data-zybedit]')) { hit++; return; }
        var b = tr.querySelector('td b'); if (!b) return;
        var nm = low(b.textContent), txt = tr.textContent || '';
        var a = mine.filter(function (x) { return low(x.name) === nm && (!x.ip || txt.indexOf(x.ip) >= 0); })[0]; if (!a) return;
        var td = document.createElement('td'); td.style.cssText = 'text-align:right;white-space:nowrap';
        td.innerHTML = '<button type="button" data-zybedit="' + esc(a.id) + '" title="Edit" style="' + BTN + ';color:var(--txt)">✎</button><button type="button" data-zybdel="' + esc(a.id) + '" title="Delete" style="' + BTN + ';color:var(--offline,#ff7b72)">✕</button>';
        tr.appendChild(td); hit++;
      });
      var hr = t.querySelector('thead tr'); if (hit && hr && !hr.querySelector('[data-zybeh]')) { var th = document.createElement('th'); th.setAttribute('data-zybeh', '1'); hr.appendChild(th); }
    });
  }
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeEd(); });

  function start() {
    if (!has()) { if ((start.n = (start.n || 0) + 1) < 40) setTimeout(start, 500); return; }
    extendCats(); try { if (onPage() && typeof renderFocus === 'function') renderFocus(); } catch (e) { /* portal redraws later */ }   // eslint-disable-line no-undef
    setTimeout(function () { sync(true); }, 3000);   // after the portal's own pullNet()
    setInterval(function () { sync(false); }, 60000);
    setInterval(banner, 1500);
    setInterval(addButton, 1000);
    setInterval(rowButtons, 1000);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
  window.__zybNetinvTest = { toRow: toRow, merge: merge, discRow: discRow, rowButtons: rowButtons };
})();
