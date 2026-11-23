// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* ===================== ZS-SOC — the organisation SIEM: SOC console =====================
   Front end for the the organisation SIEM engine (/api/soc/*, see sentra-siem/ARCH.md). Six pages:
     soc-dashboard  SOC command centre — engine status bar (state, EPS, detection, ClickHouse, spool, integrity, collectors), KPI cards,
                    alert trend (area) and open alerts by severity (ring), collectors, log sources, response and SLA, top talkers, ATT&CK heat, LogRhythm
     soc-search     event search — query language, time range, histogram with click-to-zoom, columns, top values, CSV, bookmarks, live tail
     soc-alerts     alert queue — filters, bulk acknowledge / assign / close with reason, detail drawer, create / add to case
     soc-cases      cases — status workflow, owner, SLA timers, playbook tasks, timeline, notes, evidence, linked alerts
     soc-rules      detection rules — enable, JSON editor with validation, Sigma import, dry-run test over a past range
     soc-sources    log source health and engine health (ClickHouse, spool, integrity chain)
   Everything shown comes from the engine. When the engine cannot be reached the page says so and shows nothing
   else — no sample or cached figures stand in for live data. Recommended response actions are displayed as
   "requires approval"; this console never executes them. Operators and admins can act; viewers read only
   (the engine enforces the same rules). Needs window.ASX (as-twin-module.js) and window.ASXC (as-xcharts-module.js)
   to be appended before this file.                                                                                  */
(function () {
  if (typeof viewHTML !== 'function') return;
  var VIEWS = { 'soc-dashboard': 1, 'soc-search': 1, 'soc-alerts': 1, 'soc-cases': 1, 'soc-rules': 1, 'soc-sources': 1 };
  var API = '/api/soc';
  var X = null, C = null;

  /* ─────────────────────────── language, escaping, role ─────────────────────────── */
  function isAr() { try { return typeof LANG !== 'undefined' && LANG === 'ar'; } catch (e) { return false; } }
  function T(en) {
    var r = en;
    try { if (typeof t === 'function') r = t(en); } catch (e) {}
    if (r === en && isAr() && window.X_AR) {   // the dictionary (sentra-soc.ar.json) names the company as {{org.*}} tokens
      var F = window.zybOrgFill || function (t) { return t; }; if (!T.ar) { T.ar = {}; for (var k in window.X_AR) if (Object.prototype.hasOwnProperty.call(window.X_AR, k)) T.ar[F(k)] = F(String(window.X_AR[k])); }
      if (Object.prototype.hasOwnProperty.call(T.ar, en)) r = T.ar[en];
    }
    return r;
  }
  function TF(tpl, o) { return T(tpl).replace(/\{(\w+)\}/g, function (m, k) { return o && o[k] != null ? String(o[k]) : m; }); }
  function N(s) { return s; }   // marks a static label for the dictionary check; it is translated where it is displayed
  function E(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function role() { try { return typeof _role === 'function' ? _role() : 'viewer'; } catch (e) { return 'viewer'; } }
  function canAct() { var r = role(); return r === 'admin' || r === 'operator'; }
  function isAdmin() { return role() === 'admin'; }
  function me() { try { return (typeof ME !== 'undefined' && ME && (ME.user || ME.upn)) || ''; } catch (e) { return ''; } }
  function cur() { try { return typeof currentView !== 'undefined' ? currentView : ''; } catch (e) { return ''; } }
  function toast(m) { try { if (typeof infoToast === 'function') infoToast(E(m)); } catch (e) {} }
  function go(v) { try { setView(v); } catch (e) {} }
  function arr(x) { if (Array.isArray(x)) return x; if (!x || typeof x !== 'object') return []; for (var i = 1; i < arguments.length; i++) if (Array.isArray(x[arguments[i]])) return x[arguments[i]]; return []; }
  function num(v) { var n = +v; return isFinite(n) ? n : 0; }
  function fmtN(n) { n = num(n); if (Math.abs(n) < 10 && n % 1) return String(Math.round(n * 100) / 100); if (Math.abs(n) < 100 && n % 1) return String(Math.round(n * 10) / 10); return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
  function pct(v) { return (Math.round(v * 10) / 10) + '%'; }

  /* ─────────────────────────── time ─────────────────────────── */
  function toMs(v) {
    if (v == null || v === '') return NaN;
    if (typeof v === 'number') return v < 1e11 ? v * 1000 : v;
    var s = String(v);
    if (/^\d+(\.\d+)?$/.test(s)) { var n = +s; return n < 1e11 ? n * 1000 : n; }
    if (/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d(:\d\d(\.\d+)?)?$/.test(s)) s = s.replace(' ', 'T') + 'Z';   // ClickHouse DateTime text is UTC
    return Date.parse(s);
  }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmtTs(v, ms) {
    var x = toMs(v); if (isNaN(x)) return '—'; var d = new Date(x);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) + (ms ? '.' + ('00' + d.getMilliseconds()).slice(-3) : '');
  }
  function fmtShort(x, spanMs) { var d = new Date(x); return spanMs > 2 * 864e5 ? pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) : pad(d.getHours()) + ':' + pad(d.getMinutes()) + (spanMs < 36e5 ? ':' + pad(d.getSeconds()) : ''); }
  function iso(ms) { return new Date(ms).toISOString(); }
  function localInput(ms) { var d = new Date(ms); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }
  function dur(sec) {
    sec = Math.max(0, Math.round(num(sec))); var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    if (d) return d + ' ' + T('d') + (h ? ' ' + h + ' ' + T('h') : '');
    if (h) return h + ' ' + T('h') + (m ? ' ' + m + ' ' + T('min') : '');
    if (m) return m + ' ' + T('min');
    return sec + ' ' + T('s');
  }
  function ago(v) { var x = toMs(v); if (isNaN(x)) return '—'; var s = (Date.now() - x) / 1000; if (s < 45) return T('just now'); return TF('{t} ago', { t: dur(s) }); }
  var RANGES = [['15m', 9e5, N('15 min')], ['1h', 36e5, N('1 hour')], ['24h', 864e5, N('24 hours')], ['7d', 6048e5, N('7 days')], ['30d', 2592e6, N('30 days')]];
  /* KPI tiles are filters: data-soct names what the tile counts; click (or Enter) shows exactly those records, click again clears. */
  var AF0 = { status: 'open', sev: '0', rule: '', who: 'any', range: '7d' };
  var SOCT = {
    'al:open': [function () { return S.af.status === 'open' && S.af.sev === '0' && S.af.who === 'any' && !S.af.rule; }, function () { S.af = Object.assign({}, AF0); }],
    'al:new': [function () { return S.af.status === 'new'; }, function () { S.af = Object.assign({}, AF0, { status: 'new' }); }],
    'al:ack': [function () { return S.af.status === 'acknowledged'; }, function () { S.af = Object.assign({}, AF0, { status: 'acknowledged' }); }],
    'al:prog': [function () { return S.af.status === 'in-progress'; }, function () { S.af = Object.assign({}, AF0, { status: 'in-progress' }); }],
    'al:crit': [function () { return S.af.status === 'open' && S.af.sev === '3'; }, function () { S.af = Object.assign({}, AF0, { sev: '3' }); }],
    'al:none': [function () { return S.af.status === 'open' && S.af.who === 'none'; }, function () { S.af = Object.assign({}, AF0, { who: 'none' }); }],
    'al:all': [function () { return S.af.status === 'all' && S.af.sev === '0' && S.af.who === 'any'; }, function () { S.af = Object.assign({}, AF0, { status: 'all' }); }],
    'al:closed': [function () { return S.af.status === 'closed'; }, function () { S.af = Object.assign({}, AF0, { status: 'closed', range: '30d' }); }],
    'ca:active': [function () { return S.cf.status === 'active' && !S.cf.flag; }, function () { S.cf = { status: 'active' }; }],
    'ca:sla': [function () { return S.cf.flag === 'sla'; }, function () { S.cf = { status: 'active', flag: 'sla' }; }],
    'ca:crit': [function () { return S.cf.flag === 'crit'; }, function () { S.cf = { status: 'active', flag: 'crit' }; }],
    'ca:noown': [function () { return S.cf.flag === 'noown'; }, function () { S.cf = { status: 'active', flag: 'noown' }; }],
    'ru:all': [function () { return S.rf === 'all'; }, function () { S.rf = 'all'; }],
    'ru:enabled': [function () { return S.rf === 'enabled'; }, function () { S.rf = 'enabled'; }],
    'ru:noisy': [function () { return S.rf === 'noisy'; }, function () { S.rf = 'noisy'; }],
    'so:all': [function () { return S.sf === 'all'; }, function () { S.sf = 'all'; }],
    'so:ok': [function () { return S.sf === 'ok'; }, function () { S.sf = 'ok'; }],
    'so:silent': [function () { return S.sf === 'silent'; }, function () { S.sf = 'silent'; }],
    'so:errors': [function () { return S.sf === 'errors'; }, function () { S.sf = 'errors'; }],
  };
  var SOCT_VIEW = { al: 'soc-alerts', ca: 'soc-cases', ru: 'soc-rules', so: 'soc-sources' };
  function ctile(act, label, val, sub) {
    var h = X.tile(label, val, sub), d = SOCT[act]; if (!d) return h;
    var on = cur() === SOCT_VIEW[act.split(':')[0]] && d[0]();
    var attr = ' data-soct="' + E(act) + '" role="button" tabindex="0" title="' + E(T(on ? 'Showing these - click to clear' : 'Click to show these')) + '"' + (on ? ' aria-pressed="true"' : '');
    var m = /^(\s*<[a-zA-Z][\w-]*)([^>]*?)(\sclass="([^"]*)")?/.exec(h);
    if (!m) return '<div class="soc-ct' + (on ? ' on' : '') + '"' + attr + '>' + h + '</div>';
    return m[3] ? h.replace(m[3], ' class="' + m[4] + ' soc-ct' + (on ? ' on' : '') + '"' + attr) : h.replace(m[1], m[1] + ' class="soc-ct' + (on ? ' on' : '') + '"' + attr);
  }
  function soct(act) {
    var d = SOCT[act]; if (!d) return; var k = act.split(':')[0], v = SOCT_VIEW[k], here = cur() === v;
    if (here && d[0]()) { (SOCT[k === 'al' ? 'al:open' : k === 'ca' ? 'ca:active' : k + ':all'] || d)[1](); } else d[1]();
    S.alertId = null; if (k === 'ca') S.caseId = null; if (k === 'ru') { S.ruleId = null; S.ruleNew = false; }
    if (k === 'al') load('alerts', true);
    if (!here) go(v); else rerender(true);
  }
  /* for the portal's own tiles (dashboards/vendor/zyb-tiles.js): open a SIEM view with the same filter a tile here applies */
  window.asSocTile = function (act) { if (SOCT[act]) soct(act); };
  window.asSocSearch = function (q, range) { S.q = String(q || ''); S.range = RANGES.some(function (r) { return r[0] === range; }) ? range : '24h'; S.zoom = []; S.alertId = null; go('soc-search'); runSearch(); };
  function rangeMs(k) { for (var i = 0; i < RANGES.length; i++) if (RANGES[i][0] === k) return RANGES[i][1]; return 864e5; }

  /* ─────────────────────────── severity & statuses ─────────────────────────── */
  var SEV = [['info', N('Info'), '', '○'], ['low', N('Low'), 'info', '●'], ['medium', N('Medium'), 'warn', '!'], ['high', N('High'), 'ser', '▲'], ['critical', N('Critical'), 'crit', '✕']];
  var SEVCOL = ['#8fa3c0', 'var(--x-info)', 'var(--x-warn)', 'var(--x-ser)', 'var(--x-crit)'];
  function sevIdx(s) { if (s == null || s === '') return 0; if (typeof s === 'number' || /^\d$/.test(String(s))) return Math.max(0, Math.min(4, Math.round(+s))); var i = ['info', 'low', 'medium', 'high', 'critical'].indexOf(String(s).toLowerCase()); return i < 0 ? 0 : i; }
  function sevPill(s) { var k = SEV[sevIdx(s)]; return X.pill(T(k[1]), k[2], k[3]); }
  var AST = { 'new': [N('New'), 'crit'], 'acknowledged': [N('Acknowledged'), 'warn'], 'in-progress': [N('In progress'), 'info'], 'closed-true-positive': [N('Closed — true positive'), 'ok'], 'closed-false-positive': [N('Closed — false positive'), ''], 'closed-benign': [N('Closed — benign'), ''] };
  function astPill(s) { var k = AST[s] || [s || 'new', '']; return X.pill(T(k[0]), k[1]); }
  var REASONS = [['true-positive', N('True positive')], ['false-positive', N('False positive')], ['benign', N('Benign')]];
  var CST = [['open', N('Open')], ['investigating', N('Investigating')], ['contained', N('Contained')], ['eradicated', N('Eradicated')], ['recovered', N('Recovered')], ['closed', N('Closed')]];
  function cstIdx(s) { for (var i = 0; i < CST.length; i++) if (CST[i][0] === s) return i; return 0; }
  function cstPill(s) { var i = cstIdx(s); return X.pill(T(CST[i][1]), i === 5 ? 'ok' : i === 0 ? 'crit' : i === 1 ? 'warn' : 'info'); }

  /* ─────────────────────────── MITRE ATT&CK v20 (public tactic list + common technique → tactic map) ─────────────────────────── */
  var TACTICS = [['TA0043', N('Reconnaissance')], ['TA0042', N('Resource Development')], ['TA0001', N('Initial Access')], ['TA0002', N('Execution')], ['TA0003', N('Persistence')], ['TA0004', N('Privilege Escalation')], ['TA0005', N('Stealth')], ['TA0112', N('Defense Impairment')],
    ['TA0006', N('Credential Access')], ['TA0007', N('Discovery')], ['TA0008', N('Lateral Movement')], ['TA0009', N('Collection')], ['TA0011', N('Command and Control')], ['TA0010', N('Exfiltration')], ['TA0040', N('Impact')]];
  // technique -> tactics from MITRE ATT&CK Enterprise v20.0 (2-digit = TA00xx); T1562 was revoked in v20 (now T1685)
  var TECH = {
    T1595: '43', T1592: '43', T1590: '43', T1589: '43', T1598: '43', T1583: '42', T1584: '42', T1585: '42', T1586: '42', T1587: '42', T1588: '42',
    T1190: '01', T1133: '01 03', T1566: '01', T1078: '01 03 04 05', T1189: '01', T1195: '01', T1199: '01', T1200: '01', T1091: '01 08', T1059: '02',
    T1203: '02', T1204: '02', T1047: '02', T1053: '02 03 04', T1569: '02', T1106: '02', T1129: '02', T1559: '02', T1136: '03', T1098: '03 04',
    T1543: '03 04', T1547: '03 04', T1505: '03', T1546: '03 04', T1137: '03', T1197: '02 03 05', T1574: '02 05', T1548: '04', T1068: '04',
    T1055: '04 05', T1134: '04 05', T1484: '04 TA0112', T1070: '05', T1112: '03 TA0112', T1027: '05', T1218: '05', T1036: '05', T1140: '05',
    T1202: '05', T1222: 'TA0112', T1564: '05', T1497: '05 07', T1550: '08', T1556: '03 TA0112 06', T1110: '06', T1003: '06', T1552: '06', T1555: '06',
    T1558: '06', T1621: '06', T1040: '06 07', T1557: '06 09', T1212: '06', T1528: '06', T1539: '06', T1087: '07', T1069: '07', T1082: '07', T1018: '07',
    T1083: '07', T1046: '07', T1049: '07', T1016: '07', T1057: '07', T1033: '07', T1135: '07', T1482: '07', T1518: '07', T1007: '07', T1012: '07',
    T1021: '08', T1570: '08', T1210: '08', T1534: '08', T1563: '08', T1005: '09', T1114: '09', T1119: '09', T1560: '09', T1039: '09', T1025: '09',
    T1074: '09', T1113: '09', T1056: '06 09', T1213: '09', T1071: '11', T1105: '11', T1090: '11', T1572: '11', T1571: '11', T1568: '11', T1573: '11',
    T1095: '11', T1219: '11', T1102: '11', T1132: '11', T1001: '11', T1041: '10', T1048: '10', T1567: '10', T1020: '10', T1030: '10', T1052: '10',
    T1537: '10', T1486: '40', T1490: '40', T1489: '40', T1485: '40', T1499: '40', T1498: '40', T1531: '40', T1565: '40', T1491: '40', T1496: '40',
    T1529: '40', T1561: '40', T1685: 'TA0112', T1686: 'TA0112', T1684: '05'
  };
  function techTactics(id) {
    id = String(id || '').toUpperCase();
    if (/^TA\d{4}$/.test(id)) return [id];
    var base = id.split('.')[0]; base = ({ T1562: 'T1685', T1656: 'T1684' })[base] || base;   // revoked in ATT&CK v20
    var m = TECH[base]; if (!m) return [];
    return m.split(' ').map(function (s) { return s.length === 2 ? 'TA00' + s : s; });
  }
  function mitreLink(id) {
    id = String(id || '').toUpperCase();
    if (/^T\d{4}(\.\d{3})?$/.test(id)) return '<a class="x-tag" target="_blank" rel="noopener noreferrer" href="https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/">' + E(id) + '</a>';
    if (/^TA\d{4}$/.test(id)) return '<a class="x-tag" target="_blank" rel="noopener noreferrer" href="https://attack.mitre.org/tactics/' + id + '/">' + E(id) + '</a>';
    return '<span class="x-tag">' + E(id) + '</span>';
  }

  /* ─────────────────────────── design additions (scoped to .soc) ─────────────────────────── */
  function css() {
    if (document.getElementById('sentra-soc-css')) return;
    var st = document.createElement('style'); st.id = 'sentra-soc-css';
    st.textContent = [
      '[data-soct]{cursor:pointer;transition:border-color .15s,transform .15s}[data-soct]:hover{transform:translateY(-1px);border-color:var(--x-info,#4D8DFF)!important}[data-soct]:focus-visible{outline:2px solid #fff;outline-offset:2px}[data-soct].on{box-shadow:inset 0 0 0 2px var(--x-info,#4D8DFF)}',
      '.soc-head{display:flex;justify-content:space-between;align-items:flex-end;gap:14px;flex-wrap:wrap;margin-bottom:12px}',
      '.soc-h1{font-size:23px;margin:4px 0 4px}',
      '.soc .soc-nav{display:flex;flex-wrap:wrap;margin-bottom:14px;width:fit-content;max-width:100%}.soc .soc-nav button{padding:7px 12px;font-size:12px}',
      '.soc-qbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;position:relative}',
      '.soc-q{flex:1 1 360px;font-family:"IBM Plex Mono",ui-monospace,monospace!important;font-size:13px!important}',
      '.soc-pop{position:absolute;top:100%;left:0;z-index:40;margin-top:8px;width:min(700px,100%);background:var(--panel,#0d1522);border:1px solid var(--x-line);border-radius:12px;padding:14px 16px;box-shadow:0 14px 34px rgba(0,0,0,.35)}',
      'html[dir="rtl"] .soc-pop{left:auto;right:0}',
      '.soc-pop table{width:100%;border-collapse:collapse}.soc-pop td{padding:5px 8px;font-size:12px;vertical-align:top;border-bottom:1px solid var(--x-line)}.soc-pop td:first-child{white-space:nowrap}',
      '.soc-hist{display:block;width:100%;height:auto}.soc-hist rect.b{cursor:zoom-in;fill:var(--x-info)}.soc-hist rect.b:hover{fill:var(--x-acc)}',
      '.soc-val{cursor:pointer;border-bottom:1px dotted color-mix(in srgb,var(--x-mute) 70%,transparent)}.soc-val:hover{color:var(--x-acc);border-bottom-color:var(--x-acc)}',
      '.soc-rows td{font-size:11.5px;padding:6px 8px;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.soc-rows tr.r{cursor:pointer}',
      '.soc-rows tr.soc-exp>td{white-space:normal;background:var(--x-soft);max-width:none;padding:12px 14px}',
      '.soc-kv{display:grid;grid-template-columns:minmax(120px,max-content) minmax(0,1fr);gap:4px 14px;font-size:12px;margin-bottom:10px}.soc-kv>div:nth-child(odd){color:var(--x-mute);font-family:"IBM Plex Mono",monospace;font-size:11px}',
      '.soc-kv>div{min-width:0;overflow-wrap:anywhere}.soc-mini{font:inherit;font-size:10px;font-weight:800;border:1px solid var(--x-line);background:var(--x-soft);color:var(--x-ink);border-radius:5px;padding:0 5px;margin-inline-start:6px;cursor:pointer}',
      '.soc-raw{white-space:pre-wrap;word-break:break-all;max-height:260px;overflow:auto;background:var(--x-soft);border:1px solid var(--x-line);border-radius:8px;padding:10px;margin:0;font-family:"IBM Plex Mono",monospace;font-size:11px;direction:ltr;text-align:left}',
      '.soc-grid{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:14px;align-items:start}@media(max-width:1150px){.soc-grid{grid-template-columns:1fr}}',
      '.soc-g4{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}@media(max-width:1300px){.soc-g4{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:720px){.soc-g4{grid-template-columns:1fr}}',
      '.soc-drawer-bg{position:fixed;inset:0;background:rgba(0,0,0,.38);z-index:900}',
      '.soc-drawer{position:fixed;top:0;right:0;bottom:0;width:min(640px,100vw);z-index:901;overflow:auto;background:var(--panel,#0d1522);color:var(--x-ink);border-left:1px solid var(--x-line);padding:18px 20px 40px;box-shadow:-14px 0 34px rgba(0,0,0,.3)}',
      'html[dir="rtl"] .soc-drawer{right:auto;left:0;border-left:0;border-right:1px solid var(--x-line)}',
      '.soc-drawer h4{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--x-mute);margin:18px 0 8px;font-weight:800}html[lang="ar"] .soc-drawer h4{letter-spacing:0}',
      '.soc-x{font:inherit;font-size:18px;line-height:1;border:1px solid var(--x-line);background:var(--x-soft);color:var(--x-ink);border-radius:9px;width:34px;height:34px;cursor:pointer}',
      'tr.soc-sil>td{background:color-mix(in srgb,var(--x-crit) 10%,transparent)!important}tr.soc-warnrow>td{background:color-mix(in srgb,var(--x-warn) 9%,transparent)!important}',
      '.soc-over{color:var(--x-crit);font-weight:800}.soc-ok{color:var(--x-ok);font-weight:700}',
      '.soc-steps{display:flex;gap:6px;flex-wrap:wrap;margin:4px 0 10px}.soc-step{flex:1;min-width:90px;text-align:center;padding:7px 6px;border-radius:9px;border:1px solid var(--x-line);font-size:11px;font-weight:700;color:var(--x-mute)}',
      '.soc-step.done{color:var(--x-ink);background:color-mix(in srgb,var(--x-acc) 12%,transparent);border-color:color-mix(in srgb,var(--x-acc) 40%,transparent)}.soc-step.on{color:#fff;background:linear-gradient(180deg,var(--x-acc),var(--x-acc2));border-color:transparent}',
      '.soc-editor{font-family:"IBM Plex Mono",ui-monospace,monospace!important;font-size:12px!important;min-height:340px;tab-size:2;white-space:pre;direction:ltr;text-align:left;resize:vertical}',
      '.soc-mitre{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:8px}@media(max-width:1200px){.soc-mitre{grid-template-columns:repeat(4,minmax(0,1fr))}}@media(max-width:640px){.soc-mitre{grid-template-columns:repeat(2,minmax(0,1fr))}}',
      '.soc-mt{border:1px solid var(--x-line);border-radius:10px;padding:9px 10px;min-height:86px;min-width:0}.soc-mt .n{font-family:"Plus Jakarta Sans",Inter,sans-serif;font-size:20px;font-weight:800;line-height:1.1}.soc-mt .k{font-size:10.5px;font-weight:800;margin-bottom:4px}',
      '.soc-chk{width:16px;height:16px;accent-color:var(--x-acc);cursor:pointer}',
      '.soc-bulk{position:sticky;top:0;z-index:5;background:var(--panel,#0d1522);border:1px solid var(--x-acc);border-radius:12px;padding:10px 12px;margin-bottom:12px}',
      '.soc .x-in.sm,.soc select.x-in{padding:6px 9px;font-size:12px;width:auto}',
      '.soc-saved{display:inline-flex;align-items:center;border:1px solid var(--x-line);border-radius:999px;background:var(--x-soft);overflow:hidden}.soc-saved button{border:0;background:transparent;color:var(--x-ink);font:inherit;font-size:11.5px;font-weight:600;padding:4px 10px;cursor:pointer}.soc-saved button+button{border-left:1px solid var(--x-line);padding:4px 8px;color:var(--x-mute)}',
      '.soc-task{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-bottom:1px solid var(--x-line)}.soc-task:last-child{border-bottom:0}.soc-task.done .tt{text-decoration:line-through;color:var(--x-mute)}',
      '.soc .x-tbl td .x-tag+.x-tag{margin-inline-start:4px}',
      '@media print{.soc-drawer,.soc-drawer-bg,.soc-nav,.soc-bulk{display:none!important}}'
    ].join('\n');
    document.head.appendChild(st);
  }
  function tbl(heads, rows, cls, attrs) {   // heads are HTML (already escaped); data-alert-wired stops the portal's generic alert-row wiring
    return '<table class="x-tbl ' + (cls || '') + '" data-alert-wired="1"' + (attrs || '') + '><thead><tr>' + heads.map(function (h) { return '<th>' + h + '</th>'; }).join('') + '</tr></thead><tbody>'
      + (rows.length ? rows.join('') : '<tr><td colspan="' + heads.length + '" class="x-muted" style="text-align:center;padding:18px">' + E(T('Nothing to show')) + '</td></tr>') + '</tbody></table>';
  }
  function H(list) { return list.map(function (h) { return E(T(h)); }); }
  function empty(icon, msg, sub) { return '<div class="x-empty"><b>' + icon + '</b>' + E(msg) + (sub ? '<br><span class="x-small">' + E(sub) + '</span>' : '') + '</div>'; }

  /* ─────────────────────────── API client ─────────────────────────── */
  function apiErr(kind, status, msg) { var e = new Error(msg || kind); e.kind = kind; e.status = status || 0; return e; }
  function req(method, path, body) {
    var opt = { method: method, cache: 'no-store', credentials: 'same-origin', headers: { 'Accept': 'application/json' } };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    return fetch(API + path, opt).then(function (r) {
      var ct = r.headers.get('content-type') || '';
      if (r.status === 502 || r.status === 503 || r.status === 504) throw apiErr('offline', r.status, 'HTTP ' + r.status);
      if (r.status === 401) throw apiErr('auth', 401, 'HTTP 401');
      if (ct.indexOf('json') < 0) throw apiErr('html', r.status, 'HTTP ' + r.status + ' ' + (ct.split(';')[0] || ''));
      return r.json().then(function (j) {
        if (!r.ok) { var e = apiErr(r.status === 403 ? 'forbidden' : r.status === 404 ? 'missing' : r.status >= 500 ? 'server' : 'bad', r.status, (j && (j.error || j.message)) || ('HTTP ' + r.status)); e.detail = j; throw e; }
        return j;
      });
    }, function (err) { throw apiErr('offline', 0, err && err.message); });
  }
  function isDown(e) { return !!e && (e.kind === 'offline' || e.kind === 'html'); }
  function errText(e) {
    if (!e) return '';
    if (e.kind === 'offline') return T('No answer from /api/soc — the engine is stopped or the gateway returned an error') + (e.status ? ' (HTTP ' + e.status + ')' : '');
    if (e.kind === 'html') return T('The portal answered with a web page instead of engine data — the nginx /api/soc/ route is missing or the session has expired') + ' (' + e.message + ')';
    if (e.kind === 'auth') return T('Your session has expired — sign in again.');
    if (e.kind === 'forbidden') return T('Your role is not allowed to do this.') + (e.message && !/^HTTP/.test(e.message) ? ' ' + e.message : '');
    return e.message || String(e);
  }
  function act(method, path, body, okMsg, after, busyKey) {
    if (busyKey) { S.busy[busyKey] = 1; rerender(true); }
    return req(method, path, body).then(function (j) { if (okMsg) toast(T(okMsg)); if (after) after(j); return j; }, function (e) {
      var extra = e.detail && Array.isArray(e.detail.errors) ? ' — ' + e.detail.errors.join('; ') : '';
      toast(T('The action failed') + ': ' + errText(e) + extra); return null;
    }).then(function (j) { if (busyKey) delete S.busy[busyKey]; rerender(true); return j; });
  }
  function qs(o) { return Object.keys(o).filter(function (k) { return o[k] !== '' && o[k] != null; }).map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(o[k]); }).join('&'); }

  /* ─────────────────────────── state & cached data ─────────────────────────── */
  var S = {
    q: '', range: '1h', from: 0, to: 0, zoom: [], help: false, cols: null, colsOpen: false, res: null, resErr: null, hist: null, histErr: null, span: null, busyS: 0, exp: {},
    topField: '', top: null, topErr: null, topBusy: false, live: false, liveState: '', liveRows: [], liveN: 0, saved: null, searched: false,
    af: { status: 'open', sev: '0', rule: '', who: 'any', range: '7d' }, sel: {}, alertId: null, samples: {},
    cf: { status: 'active' }, caseId: null, caseNew: false,
    rq: '', rf: 'all', ruleId: null, ruleNew: false, ruleMsg: null, ruleDirty: false, testRange: '24h', test: null, testErr: null, sigmaRes: null,
    sf: 'all', busy: {}
  };
  var DR = {};    // text typed into inputs, kept across redraws
  var VIS = [];   // event rows as last drawn — value clicks index into this snapshot
  var PIV = [];   // pivots (top lists) as last drawn
  var D = {}, ERR = {}, LOAD = {}, AT = {}, OKAT = {}, SEQ = {};
  var SRC = {
    health: function () { return '/health'; },
    metrics: function () { return '/metrics'; },
    lr: function () { return '/lr-compare'; },
    sources: function () { return '/sources'; },
    rules: function () { return '/rules'; },
    alerts: function () { return '/alerts?' + qs(alertQuery()); },
    alertDetail: function () { return S.alertId ? '/alerts/' + encodeURIComponent(S.alertId) : null; },
    openCases: function () { return '/cases?' + qs({ status: 'active', limit: 200 }); },
    cases: function () { return '/cases?' + qs({ status: S.cf.status === 'all' ? '' : S.cf.status, limit: 500 }); },
    caseDetail: function () { return S.caseId ? '/cases/' + encodeURIComponent(S.caseId) : null; },
    caseAlerts: function () { return S.caseId ? '/alerts?' + qs({ case_id: S.caseId, status: 'all', limit: 200 }) : null; },
    dashAlerts: function () { return '/alerts?' + qs({ status: 'all', from: iso(Date.now() - 2592e6), limit: 1000 }); }
  };
  var NEEDS = { 'soc-dashboard': ['health', 'metrics', 'lr', 'sources'], 'soc-search': ['health'], 'soc-alerts': ['health', 'alerts', 'rules', 'openCases'], 'soc-cases': ['health', 'cases'], 'soc-rules': ['health', 'rules'], 'soc-sources': ['health', 'sources'] };
  var POLL = { health: 30, metrics: 60, lr: 300, sources: 30, rules: 120, alerts: 20, openCases: 60, cases: 30, caseDetail: 30, caseAlerts: 60, alertDetail: 20, dashAlerts: 120 };
  function load(key, force) {
    if (!SRC[key]) return;
    if (!force && (D[key] || LOAD[key] || (ERR[key] && Date.now() - (AT[key] || 0) < 10000))) return;
    var p = SRC[key](); if (!p) return;
    var n = SEQ[key] = (SEQ[key] || 0) + 1; LOAD[key] = 1;
    req('GET', p).then(function (j) { if (SEQ[key] !== n) return; D[key] = j; delete ERR[key]; AT[key] = OKAT[key] = Date.now(); },
      function (e) { if (SEQ[key] !== n) return; ERR[key] = e; AT[key] = Date.now(); })
      .then(function () { if (SEQ[key] !== n) return; LOAD[key] = 0; rerender(); });
  }
  function gate(keys) {
    for (var i = 0; i < keys.length; i++) if (!D[keys[i]] && ERR[keys[i]]) return pageError(ERR[keys[i]]);
    for (i = 0; i < keys.length; i++) if (!D[keys[i]]) return loadingCard();
    return '';
  }
  function stale(keys) {
    var bad = keys.filter(function (k) { return D[k] && isDown(ERR[k]); });
    if (!bad.length) return '';
    var t0 = Math.min.apply(null, bad.map(function (k) { return OKAT[k] || Date.now(); }));
    return '<div class="x-note crit" style="margin-bottom:12px">⛓️ ' + E(T('The SIEM engine stopped answering. The figures below are from the last successful refresh at')) + ' <b>' + E(fmtTs(t0)) + '</b>. ' + E(T('They will update when the engine is back.')) + '</div>';
  }

  /* ─────────────────────────── redraw (never while the user is typing) ─────────────────────────── */
  var PENDING = false;
  function typing() {
    var a = document.activeElement; if (!a || !a.tagName) return false;
    var host = document.getElementById('viewFocus'); if (!host || !host.contains(a)) return false;
    return /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) && a.type !== 'checkbox' && a.type !== 'button';
  }
  function rerender(force) {
    if (!VIEWS[cur()]) return;
    if (!force && typing()) { PENDING = true; return; }
    PENDING = false;
    var a = document.activeElement, fid = a && a.id && /^soc-/.test(a.id) ? a.id : null, s0 = null, s1 = null;
    try { if (fid && (a.tagName === 'TEXTAREA' || /^(text|search)$/.test(a.type || ''))) { s0 = a.selectionStart; s1 = a.selectionEnd; } } catch (e) {}
    var sc = {}; Array.prototype.forEach.call(document.querySelectorAll('[data-socscroll]'), function (el) { sc[el.getAttribute('data-socscroll')] = el.scrollTop; });
    var y = window.scrollY;
    try { renderFocus(); } catch (e) { console.error('[sentra-soc]', e); }
    window.scrollTo(0, y);
    Object.keys(sc).forEach(function (k) { var el = document.querySelector('[data-socscroll="' + k + '"]'); if (el) el.scrollTop = sc[k]; });
    if (fid) { var b = document.getElementById(fid); if (b) { try { b.focus({ preventScroll: true }); if (s0 != null && b.setSelectionRange) b.setSelectionRange(s0, s1); } catch (e) {} } }
  }
  var LAZY = 0;
  function lazyRerender() { if (LAZY) return; LAZY = setTimeout(function () { LAZY = 0; rerender(); }, 1000); }

  /* ─────────────────────────── shared page parts ─────────────────────────── */
  var TABS = [['soc-dashboard', N('Overview'), '🛡️'], ['soc-search', N('Search'), '🔎'], ['soc-alerts', N('Alerts'), '🚨'], ['soc-cases', N('Cases'), '🗂️'], ['soc-rules', N('Detection rules'), '📐'], ['soc-sources', N('Log sources'), '🔌']];
  function chOk(h) { var c = h && (h.clickhouse || h.ch); if (c == null) return null; if (typeof c === 'boolean') return c; if (typeof c === 'string') return /^(ok|up|healthy|connected)$/i.test(c); if (c.ok != null) return !!c.ok; if (c.status) return /^(ok|up|healthy|connected)$/i.test(c.status); return null; }
  function engPill() {
    var h = D.health, e = ERR.health;
    if (isDown(e)) return X.pill(T('Engine not connected'), 'crit', '✕');
    if (!h) return X.pill(T('Checking the engine…'), '', '…');
    var ch = chOk(h);
    return X.pill(T('Engine connected'), 'ok', '✓') + (ch === false ? ' ' + X.pill(T('ClickHouse down'), 'crit', '✕') : ch ? ' ' + X.pill('ClickHouse', 'ok', '✓') : '');
  }
  function head(v, title, sub) {
    var nav = '<div class="x-seg soc-nav" role="tablist">' + TABS.map(function (tb) { return '<button role="tab" aria-selected="' + (tb[0] === v) + '" data-socgo="' + tb[0] + '" class="' + (tb[0] === v ? 'on' : '') + '">' + tb[2] + ' ' + E(T(tb[1])) + '</button>'; }).join('') + '</div>';
    return '<div class="soc-head"><div><div class="x-eye">' + E(T((ZYB_ORG.short + ' SIEM'))) + '</div><h1 class="x-h1 soc-h1">' + E(title) + '</h1>' + (sub ? '<div class="x-small x-muted">' + E(sub) + '</div>' : '') + '</div>'
      + '<div class="x-row">' + engPill() + (canAct() ? '' : ' ' + X.pill(T('Read-only'), 'info', '🔒')) + '</div></div>' + nav;
  }
  function loadingCard() { return '<div class="x-card"><div class="x-skel" style="width:55%"></div><div class="x-skel"></div><div class="x-skel" style="width:78%"></div><div class="x-small x-muted">' + E(T('Loading from the SIEM engine…')) + '</div></div>'; }
  function offlineCard(e) {
    return '<div class="x-card"><h3>⛓️ ' + E(T('SIEM engine not connected')) + '<span class="x-r">' + X.pill(T('No data shown'), 'crit', '✕') + '</span></h3>'
      + '<p class="x-lead">' + E(T(('The SOC console could not reach the ' + ZYB_ORG.short + ' SIEM engine, so nothing is displayed. This console never shows sample or placeholder figures in place of live data.'))) + '</p>'
      + '<div class="x-small"><b>' + E(T('What the portal saw')) + ':</b> <span class="x-mono">' + E(errText(e)) + '</span></div><div class="x-sep"></div>'
      + '<b class="x-small">' + E(T('What to check on the SIEM server')) + '</b><ol class="x-small" style="margin:8px 0 0;padding-inline-start:20px;line-height:2">'
      + '<li>' + E(T('The engine service is running')) + ' — <span class="x-mono">systemctl status sentra-siem</span></li>'
      + '<li>' + E(T('The engine API answers locally')) + ' — <span class="x-mono">curl -s http://127.0.0.1:9120/api/soc/health</span></li>'
      + '<li>' + E(T('nginx forwards /api/soc/ to the engine behind the portal sign-in')) + ' — <span class="x-mono">nginx -t</span></li>'
      + '<li>' + E(T('ClickHouse is running (the engine reports it in its health check)')) + ' — <span class="x-mono">systemctl status clickhouse-server</span></li>'
      + '<li>' + E(T('The engine log shows no start-up errors')) + ' — <span class="x-mono">journalctl -u sentra-siem -n 100</span></li></ol>'
      + '<div style="margin-top:14px"><button class="x-btn ghost sm" data-soc="retry">↻ ' + E(T('Retry')) + '</button></div></div>';
  }
  function pageError(e) {
    if (isDown(e)) return offlineCard(e);
    if (e.kind === 'auth') return '<div class="x-card">' + empty('🔑', T('Your session has expired — sign in again.'), '') + '<div style="text-align:center"><a class="x-btn sm" href="/auth/login">' + E(T('Sign in')) + '</a></div></div>';
    return '<div class="x-card"><h3>⚠️ ' + E(T('The SIEM engine returned an error')) + '</h3><div class="x-small x-mono">' + E(errText(e)) + '</div><div style="margin-top:12px"><button class="x-btn ghost sm" data-soc="retry">↻ ' + E(T('Retry')) + '</button></div></div>';
  }
  function inlineErr(e) { return '<div class="x-note ' + (isDown(e) ? 'crit' : 'warn') + '">' + E(errText(e)) + '</div>'; }
  function opt(v, label, sel) { return '<option value="' + E(v) + '"' + (String(v) === String(sel) ? ' selected' : '') + '>' + E(label) + '</option>'; }
  function busy(k) { return S.busy[k] ? ' disabled aria-busy="true"' : ''; }

  /* ═══════════════════════════ 1. SEARCH ═══════════════════════════ */
  var SCHEMA = ['ts', 'rts', 'id', 'src_type', 'src_id', 'collector', 'host', 'host_ip', 'category', 'action', 'outcome', 'severity', 'user', 'target_user', 'domain', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto',
    'process', 'parent_process', 'cmdline', 'hash', 'url', 'http_method', 'http_status', 'user_agent', 'dns_query', 'event_code', 'message', 'tags', 'raw'];
  var DEFCOLS = ['ts', 'src_id', 'host', 'category', 'action', 'outcome', 'user', 'src_ip', 'dst_ip', 'message'];
  function cols() { if (S.lsUser !== me()) { S.lsUser = me(); S.cols = null; S.saved = null; } if (!S.cols) { var c = lsGet('cols', null); S.cols = Array.isArray(c) && c.length ? c.filter(function (x) { return typeof x === 'string'; }) : DEFCOLS.slice(); } return S.cols; }
  function lsKey(k) { return 'as_soc_' + k + ':' + (me() || 'local'); }
  function lsGet(k, def) { try { var v = localStorage.getItem(lsKey(k)); return v ? JSON.parse(v) : def; } catch (e) { return def; } }
  function lsSet(k, v) { try { localStorage.setItem(lsKey(k), JSON.stringify(v)); } catch (e) {} }
  function saved() { if (S.lsUser !== me()) { S.lsUser = me(); S.cols = null; S.saved = null; } if (!S.saved) { var s = lsGet('saved', []); S.saved = Array.isArray(s) ? s.filter(function (x) { return x && typeof x.q === 'string'; }) : []; } return S.saved; }
  function getF(r, c) {
    if (!r) return '';
    if (c.indexOf('fields.') === 0) { var k = c.slice(7); return r.fields && r.fields[k] != null ? r.fields[k] : ''; }
    var v = r[c]; if (Array.isArray(v)) return v.join(', '); if (v && typeof v === 'object') return JSON.stringify(v); return v == null ? '' : v;
  }
  function qv(v) { v = String(v); return /^[\w.@\/-]+$/.test(v) && !/^(AND|OR|NOT|TO)$/i.test(v) ? v : '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }
  function fieldOk(f) { return SCHEMA.indexOf(f) >= 0 || /^fields\.[\w.-]+$/.test(f); }
  function addTerm(field, value, neg) {
    if (!fieldOk(field) || field === 'raw') { toast(T('This field cannot be added to the query.')); return; }
    if (value === '' || value == null) { toast(T('This field is empty in the event.')); return; }
    if (field === 'ts' || field === 'rts') { toast(T('Use the time range to filter by time.')); return; }
    var term = (neg ? 'NOT ' : '') + field + ':' + qv(value), q = (S.q || '').trim();
    S.q = q ? (/\bOR\b/i.test(q) ? '(' + q + ')' : q) + ' AND ' + term : term;
    runSearch();
  }
  function span() { if (S.range === 'custom' && S.from && S.to) return [S.from, S.to]; var n = Date.now(); return [n - rangeMs(S.range), n]; }
  function runSearch() {
    if (S.live) tailStop();
    var sp = span(), q = (S.q || '').trim(), n = SEQ.search = (SEQ.search || 0) + 1;
    S.span = sp; S.busyS = 1; S.resErr = null; S.histErr = null; S.exp = {}; S.searched = true; rerender(true);
    var body = { q: q, from: iso(sp[0]), to: iso(sp[1]) };
    var p1 = req('POST', '/search', { q: q, from: body.from, to: body.to, limit: 500, order: 'desc' }).then(function (j) { if (SEQ.search === n) S.res = j; }, function (e) { if (SEQ.search === n) { S.res = null; S.resErr = e; } });
    var p2 = req('POST', '/histogram', { q: q, from: body.from, to: body.to, buckets: 60 }).then(function (j) { if (SEQ.search === n) S.hist = j; }, function (e) { if (SEQ.search === n) { S.hist = null; S.histErr = e; } });
    Promise.all([p1, p2]).then(function () { if (SEQ.search !== n) return; S.busyS = 0; rerender(true); });
    if (S.topField) loadTop();
  }
  function loadTop() {
    if (!S.topField) { S.top = null; rerender(true); return; }
    var sp = S.span || span(), n = SEQ.top = (SEQ.top || 0) + 1; S.topBusy = true; S.topErr = null; rerender(true);
    req('POST', '/top', { q: (S.q || '').trim(), from: iso(sp[0]), to: iso(sp[1]), field: S.topField, limit: 15 })
      .then(function (j) { if (SEQ.top === n) S.top = j; }, function (e) { if (SEQ.top === n) { S.top = null; S.topErr = e; } })
      .then(function () { if (SEQ.top === n) { S.topBusy = false; rerender(true); } });
  }
  var TAIL = null;
  function tailStart() {
    if (typeof EventSource !== 'function') { toast(T('This browser cannot open a live stream.')); return; }
    tailStop(); S.live = true; S.liveRows = []; S.liveN = 0; S.liveState = 'connecting'; S.exp = {};
    var es = TAIL = new EventSource(API + '/tail?q=' + encodeURIComponent((S.q || '').trim()));
    function onMsg(m) {
      if (TAIL !== es) return; var j; try { j = JSON.parse(m.data); } catch (e) { return; }
      var list = Array.isArray(j) ? j : j && Array.isArray(j.rows) ? j.rows : [j];
      list.forEach(function (ev) { if (ev && typeof ev === 'object' && !ev.heartbeat) { S.liveRows.unshift(ev); S.liveN++; } });
      if (S.liveRows.length > 500) S.liveRows.length = 500;
      S.liveState = 'on'; lazyRerender();
    }
    es.onopen = function () { if (TAIL !== es) return; S.liveState = 'on'; lazyRerender(); };
    es.onmessage = onMsg; es.addEventListener('event', onMsg);
    es.onerror = function () { if (TAIL !== es) return; S.liveState = es.readyState === 2 ? 'closed' : 'reconnecting'; lazyRerender(); };
  }
  function tailStop() { if (TAIL) { try { TAIL.close(); } catch (e) {} } TAIL = null; S.live = false; S.liveState = ''; }
  function csvCell(v) { var s = v == null ? '' : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; }
  function exportCsv() {
    var cs = cols(), rows = VIS;
    if (!rows.length) { toast(T('Nothing to export — run a search first.')); return; }
    var lines = [cs.map(csvCell).join(',')];
    rows.forEach(function (r) { lines.push(cs.map(function (c) { return csvCell(c === 'ts' || c === 'rts' ? fmtTs(r[c], true) : getF(r, c)); }).join(',')); });
    var d = new Date(), name = 'soc-search-' + d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + '-' + pad(d.getHours()) + pad(d.getMinutes()) + '.csv';
    var blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }), a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click();
    setTimeout(function () { try { URL.revokeObjectURL(a.href); a.parentNode.removeChild(a); } catch (e) {} }, 800);
    toast(TF('Exported {n} rows', { n: rows.length }));
  }

  function helpPop() {
    var ex = [['action:logon-failed', N('Field equals a value')], ['user:"john smith"', N('Exact phrase in a field')], ['host:web*', N('Prefix match')], ['severity:>=3', N('Numeric comparison (>, >=, <, <=)')],
      ['dst_port:[1 TO 1024]', N('Range (numbers or time)')], ['ip:10.0.0.0/8', N('Network range on src_ip or dst_ip')], ['fields.logid:0100032001', N('Vendor-specific parsed field')],
      ['mimikatz', N('Free text in the raw line and the message')], ['"access denied"', N('Free-text phrase')], ['action:logon-failed AND NOT user:svc*', N('AND, OR, NOT and parentheses — AND is the default')], ['(src_ip:203.0.113.5 OR dst_ip:203.0.113.5) outcome:failure', N('Grouping')]];
    return '<div class="soc-pop" role="dialog" aria-label="' + E(T('Query syntax')) + '"><div class="x-row" style="justify-content:space-between;margin-bottom:8px"><b>' + E(T('Query syntax')) + '</b><button class="soc-x" data-soc="help" aria-label="' + E(T('Close help')) + '">×</button></div>'
      + '<table>' + ex.map(function (x) { return '<tr><td class="x-mono"><span class="soc-val" data-socex="' + E(x[0]) + '">' + E(x[0]) + '</span></td><td class="x-muted">' + E(T(x[1])) + '</td></tr>'; }).join('') + '</table>'
      + '<div class="x-small x-muted" style="margin-top:8px">' + E(T('Fields:')) + ' <span class="x-mono">' + E(SCHEMA.join(', ')) + ', fields.&lt;key&gt;</span></div>'
      + '<div class="x-small x-muted" style="margin-top:6px">' + E(T('Unknown field names are rejected by the engine. Click an example to use it.')) + '</div></div>';
  }
  function histo(h, sp) {
    var b = arr(h, 'buckets').map(function (x) { return { t: toMs(x.t != null ? x.t : x.ts), n: num(x.n != null ? x.n : x.count) }; }).filter(function (x) { return !isNaN(x.t); });
    if (!b.length) return '<div class="x-small x-muted">' + E(T('No events in this time range.')) + '</div>';
    var n = b.length, bw = n > 1 ? b[1].t - b[0].t : (sp[1] - sp[0]), W = 900, H = 130, pl = 42, pr = 8, pt = 8, pb = 20, slot = (W - pl - pr) / n;
    var mx = C.niceMax(Math.max.apply(null, b.map(function (x) { return x.n; })) || 1), Y = function (v) { return pt + (H - pt - pb) * (1 - v / mx); }, s = '';
    for (var k = 0; k <= 3; k++) { var yv = mx * k / 3, yy = Y(yv); s += '<line x1="' + pl + '" x2="' + (W - pr) + '" y1="' + yy.toFixed(1) + '" y2="' + yy.toFixed(1) + '" stroke="var(--x-line)"/><text x="' + (pl - 6) + '" y="' + (yy + 3.5).toFixed(1) + '" text-anchor="end" font-size="9.5" fill="var(--x-mute)">' + C.num(yv) + '</text>'; }
    var step = Math.max(1, Math.round(n / 7)), spanMs = b[n - 1].t + bw - b[0].t;
    b.forEach(function (x, i) {
      var xx = pl + i * slot, hh = Math.max(x.n ? 1.5 : 0, H - pb - Y(x.n));
      s += '<rect class="b" data-sochz="' + i + '" x="' + (xx + 1).toFixed(1) + '" y="' + (H - pb - hh).toFixed(1) + '" width="' + Math.max(1, slot - 2).toFixed(1) + '" height="' + hh.toFixed(1) + '" rx="1.5"><title>' + E(fmtTs(x.t) + ' – ' + fmtTs(x.t + bw) + ': ' + fmtN(x.n)) + '</title></rect>';
      s += '<rect data-sochz="' + i + '" x="' + xx.toFixed(1) + '" y="' + pt + '" width="' + slot.toFixed(1) + '" height="' + (H - pt - pb - hh).toFixed(1) + '" fill="transparent" style="cursor:zoom-in"/>';
      if (i % step === 0) s += '<text x="' + (xx + slot / 2).toFixed(1) + '" y="' + (H - 5) + '" text-anchor="middle" font-size="9.5" fill="var(--x-mute)">' + E(fmtShort(x.t, spanMs)) + '</text>';
    });
    S._hb = { b: b, bw: bw };
    return '<svg class="soc-hist" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' + E(T('Events over time')) + '">' + s + '</svg>';
  }
  function cellHTML(r, c, i) {
    var v = getF(r, c);
    if (c === 'ts' || c === 'rts') return '<td class="x-mono" style="white-space:nowrap">' + E(fmtTs(r[c], true)) + '</td>';
    if (c === 'severity') return '<td><span class="soc-val" data-socadd="' + i + '|' + c + '">' + sevPill(v) + '</span></td>';
    if (v === '' || v == null) return '<td class="x-muted">—</td>';
    var mono = /ip$|_port$|hash|event_code|^id$|cmdline/.test(c);
    return '<td' + (mono ? ' class="x-mono"' : '') + ' title="' + E(String(v).slice(0, 400)) + '"><span class="soc-val" data-socadd="' + i + '|' + E(c) + '">' + E(String(v).slice(0, 300)) + '</span></td>';
  }
  function expandHTML(r, i, ncol) {
    var kv = '';
    SCHEMA.forEach(function (f) {
      if (f === 'raw' || f === 'fields') return; var v = getF(r, f); if (v === '' || v == null || (f === 'tags' && !v)) return;
      var disp = f === 'ts' || f === 'rts' ? fmtTs(r[f], true) : String(v);
      var tools = f === 'ts' || f === 'rts' || f === 'tags' ? '' : '<button class="soc-mini" data-socadd="' + i + '|' + f + '" title="' + E(T('Add to query')) + '">+</button><button class="soc-mini" data-socnot="' + i + '|' + f + '" title="' + E(T('Exclude from query')) + '">−</button>';
      kv += '<div>' + E(f) + '</div><div>' + E(disp) + tools + '</div>';
    });
    if (r.fields && typeof r.fields === 'object') Object.keys(r.fields).sort().forEach(function (k) {
      var ok = /^[\w.-]+$/.test(k);
      kv += '<div>fields.' + E(k) + '</div><div>' + E(r.fields[k]) + (ok ? '<button class="soc-mini" data-socadd="' + i + '|fields.' + E(k) + '" title="' + E(T('Add to query')) + '">+</button><button class="soc-mini" data-socnot="' + i + '|fields.' + E(k) + '" title="' + E(T('Exclude from query')) + '">−</button>' : '') + '</div>';
    });
    return '<tr class="soc-exp"><td colspan="' + ncol + '"><div class="soc-kv">' + kv + '</div><div class="x-small x-muted" style="margin-bottom:4px">' + E(T('Raw')) + '</div><pre class="soc-raw">' + E(r.raw || '') + '</pre></td></tr>';
  }
  function vSearch() {
    var cs = cols(), h = head('soc-search', T('Event search'), T('Search every normalised event stored by the engine, then pivot, count and export.'));
    var rangeSeg = '<div class="x-seg" role="group" aria-label="' + E(T('Time range')) + '">' + RANGES.map(function (r) { return '<button data-socrange="' + r[0] + '" class="' + (S.range === r[0] ? 'on' : '') + '">' + E(T(r[2])) + '</button>'; }).join('')
      + '<button data-socrange="custom" class="' + (S.range === 'custom' ? 'on' : '') + '">' + E(T('Custom')) + '</button></div>';
    var sp = span();
    var custom = S.range === 'custom' ? '<div class="x-row" style="margin-top:10px"><label class="x-f" style="flex-direction:row;align-items:center;gap:8px">' + E(T('From')) + ' <input type="datetime-local" class="x-in sm" id="soc-from" data-socin="from" value="' + E(DR.from || localInput(sp[0])) + '"></label>'
      + '<label class="x-f" style="flex-direction:row;align-items:center;gap:8px">' + E(T('To')) + ' <input type="datetime-local" class="x-in sm" id="soc-to" data-socin="to" value="' + E(DR.to || localInput(sp[1])) + '"></label>'
      + '<button class="x-btn ghost sm" data-soc="setrange">' + E(T('Set range')) + '</button>' + (S.zoom.length ? '<button class="x-btn ghost sm" data-soc="zoomout">⤢ ' + E(T('Zoom out')) + '</button>' : '') + '</div>' : '';
    var sv = saved(), savedRow = sv.length ? '<div class="x-row" style="margin-top:10px;gap:6px"><span class="x-small x-muted">' + E(T('Bookmarked searches')) + ':</span>' + sv.map(function (x, i) {
      return '<span class="soc-saved"><button data-socsaved="' + i + '" title="' + E(x.q) + '">' + E(x.name) + '</button><button data-socsaveddel="' + i + '" aria-label="' + E(T('Remove bookmark')) + '">×</button></span>'; }).join('') + '</div>' : '';
    var qerr = S.resErr && !isDown(S.resErr) && S.resErr.kind === 'bad' ? '<div class="x-note crit" style="margin-top:10px"><b>' + E(T('The engine rejected the query')) + ':</b> ' + E(S.resErr.message) + '</div>' : '';
    var qcard = '<div class="x-card" style="position:relative;z-index:3"><div class="soc-qbar">'
      + '<input id="soc-q" class="x-in soc-q" data-socin="q" value="' + E(S.q) + '" placeholder="' + E(T('e.g. action:logon-failed AND user:admin*')) + '" autocomplete="off" spellcheck="false" aria-label="' + E(T('Query')) + '" dir="ltr">'
      + '<button class="x-btn ghost sm" data-soc="help" aria-expanded="' + (S.help ? 'true' : 'false') + '" title="' + E(T('Query syntax')) + '">?</button>' + rangeSeg
      + '<button class="x-btn sm" data-soc="search"' + (S.busyS ? ' disabled' : '') + '>🔎 ' + E(T('Search')) + '</button>'
      + '<button class="x-btn ' + (S.live ? '' : 'ghost ') + 'sm" data-soc="tail" aria-pressed="' + (S.live ? 'true' : 'false') + '">' + (S.live ? '● ' + E(T('Live tail on')) : '◌ ' + E(T('Live tail'))) + '</button></div>'
      + (S.help ? helpPop() : '') + custom + qerr + savedRow + '</div>';
    if (!S.searched && !S.live) {
      var pre = isDown(ERR.health) ? offlineCard(ERR.health) : '<div class="x-card">' + empty('🔎', T('Type a query and press Search.'), T('Leave the box empty to list the newest events in the time range.')) + '</div>';
      return h + qcard + pre;
    }
    if (S.resErr && isDown(S.resErr) && !S.live) return h + qcard + offlineCard(S.resErr);

    var rows = S.live ? S.liveRows : arr(S.res, 'rows'); VIS = rows.slice();
    var ssp = S.span || sp;
    var histCard = S.live ? '' : '<div class="x-card"><h3>📊 ' + E(T('Events over time')) + '<span class="x-r"><span class="x-small x-muted">' + E(fmtTs(ssp[0])) + ' → ' + E(fmtTs(ssp[1])) + '</span>'
      + (S.zoom.length ? '<button class="x-btn ghost sm" data-soc="zoomout">⤢ ' + E(T('Zoom out')) + '</button>' : '') + '<span class="x-tag">' + E(T('click a bar to zoom in')) + '</span></span></h3>'
      + (S.histErr ? (S.histErr.kind === 'bad' ? '<div class="x-small x-muted">' + E(T('No events in this time range.')) + '</div>' : inlineErr(S.histErr)) : S.hist ? histo(S.hist, ssp) : '<div class="x-skel"></div>') + '</div>';
    var info = S.live ? X.pill(S.liveState === 'on' ? T('Live tail on') : S.liveState === 'closed' ? T('Live stream closed') : S.liveState === 'reconnecting' ? T('Reconnecting…') : T('Connecting…'), S.liveState === 'on' ? 'ok' : 'warn', '●') + ' <span class="x-small x-muted">' + E(TF('{n} events received', { n: fmtN(S.liveN) })) + '</span>'
      : S.busyS ? '<span class="x-small x-muted">' + E(T('Searching…')) + '</span>'
      : S.res ? '<span class="x-small x-muted">' + E(TF('{n} shown of about {t} matching events · {ms} ms', { n: fmtN(rows.length), t: fmtN(S.res.total_estimate != null ? S.res.total_estimate : rows.length), ms: fmtN(S.res.took_ms) })) + '</span>' : '';
    var tools = '<button class="x-btn ghost sm" data-soc="cols" aria-expanded="' + (S.colsOpen ? 'true' : 'false') + '">▦ ' + E(T('Columns')) + '</button>'
      + '<button class="x-btn ghost sm" data-soc="csv">⬇ ' + E(T('Export CSV')) + '</button><button class="x-btn ghost sm" data-soc="bookmark">☆ ' + E(T('Bookmark')) + '</button>';
    var chooser = '';
    if (S.colsOpen) {
      var extra = {}; rows.slice(0, 200).forEach(function (r) { if (r.fields && typeof r.fields === 'object') Object.keys(r.fields).forEach(function (k) { if (/^[\w.-]+$/.test(k)) extra['fields.' + k] = 1; }); });
      var all = SCHEMA.filter(function (f) { return f !== 'raw'; }).concat(Object.keys(extra).sort().slice(0, 60));
      cs.forEach(function (c) { if (all.indexOf(c) < 0) all.push(c); });
      chooser = '<div class="x-note" style="margin-bottom:12px"><div class="x-small x-muted" style="margin-bottom:8px">' + E(T('Choose the columns to show. Your choice is remembered on this browser.')) + '</div><div class="x-chips">'
        + all.map(function (f) { return '<button class="x-chip' + (cs.indexOf(f) >= 0 ? ' on' : '') + '" data-soccol="' + E(f) + '" aria-pressed="' + (cs.indexOf(f) >= 0) + '">' + E(f) + '</button>'; }).join('')
        + '</div><div style="margin-top:8px"><button class="x-btn ghost sm" data-soc="colsdef">' + E(T('Default columns')) + '</button></div></div>';
    }
    var trs = [];
    rows.forEach(function (r, i) {
      var key = r.id || ('i' + i), open = !!S.exp[key];
      trs.push('<tr class="r" data-socrow="' + i + '" aria-expanded="' + open + '"><td class="x-muted" style="width:18px">' + (open ? '▾' : '▸') + '</td>' + cs.map(function (c) { return cellHTML(r, c, i); }).join('') + '</tr>');
      if (open) trs.push(expandHTML(r, i, cs.length + 1));
    });
    var tableCard = '<div class="x-card"><h3>📜 ' + E(T('Events')) + '<span class="x-r">' + info + tools + '</span></h3>' + chooser
      + (S.resErr && !S.live && S.resErr.kind !== 'bad' ? inlineErr(S.resErr) : '')
      + '<div class="x-scroll" data-socscroll="rows" style="max-height:640px">' + tbl([''].concat(cs.map(E)), trs, 'soc-rows') + '</div>'
      + '<div class="x-small x-muted" style="margin-top:8px">' + E(T('Click a row to see every field and the raw line. Click a value to add it to the query.')) + '</div></div>';
    var topOpts = ['<option value="">' + E(T('Choose a field…')) + '</option>'].concat(SCHEMA.filter(function (f) { return ['ts', 'rts', 'id', 'raw', 'message', 'cmdline'].indexOf(f) < 0; }).map(function (f) { return opt(f, f, S.topField); })).join('');
    PIV = [];
    var topBody = !S.topField ? '<div class="x-small x-muted">' + E(T('Pick a field to see its most frequent values for the current query and time range.')) + '</div>'
      : S.topErr ? inlineErr(S.topErr) : S.topBusy && !S.top ? '<div class="x-skel"></div>' : (function () {
        var vals = arr(S.top, 'values'), mx = Math.max.apply(null, vals.map(function (v) { return num(v.n); }).concat([1]));
        if (!vals.length) return '<div class="x-small x-muted">' + E(T('No values.')) + '</div>';
        return vals.map(function (v, i) {
          return '<div class="xc-hb" style="grid-template-columns:minmax(0,1fr) 70px auto"><div class="l" title="' + E(v.v) + '"><span class="soc-val" data-soctop="' + i + '">' + (v.v === '' || v.v == null ? '<i class="x-muted">(' + E(T('empty')) + ')</i>' : E(v.v)) + '</span></div><div class="t"><i style="width:' + (num(v.n) / mx * 100).toFixed(1) + '%;background:var(--x-info)"></i></div><div class="v">' + E(fmtN(v.n)) + '</div></div>';
        }).join('') + '<div class="x-small x-muted" style="margin-top:8px">' + E(T('Click a value to add it to the query.')) + '</div>';
      })();
    var topCard = '<div class="x-card"><h3>🏷️ ' + E(T('Top values')) + '</h3><select class="x-in" id="soc-topf" data-socsel="topfield" style="width:100%;margin-bottom:10px" aria-label="' + E(T('Field')) + '">' + topOpts + '</select>' + topBody + '</div>';
    var sql = S.res && S.res.sql_hint ? '<details class="x-small" style="margin-top:-6px;margin-bottom:12px"><summary class="x-muted">' + E(T('Compiled query (parameterised)')) + '</summary><pre class="soc-raw">' + E(S.res.sql_hint) + '</pre></details>' : '';
    return h + qcard + histCard + '<div class="soc-grid"><div style="min-width:0">' + tableCard + sql + '</div>' + topCard + '</div>';
  }

  /* ═══════════════════════════ 2. ALERTS ═══════════════════════════ */
  function alertQuery() {
    var f = S.af, o = { limit: 500 };
    if (f.status !== 'all') o.status = f.status;
    if (+f.sev > 0) o.min_severity = f.sev;
    if (f.rule) o.rule_id = f.rule;
    if (f.who === 'me') o.assignee = me(); else if (f.who === 'none') o.unassigned = 1; else if (f.who !== 'any') o.assignee = f.who;
    if (f.range !== 'all') o.from = iso(Date.now() - rangeMs(f.range));
    return o;
  }
  function allAlerts() { return arr(D.alerts, 'alerts', 'items', 'rows'); }
  function alertList() {
    var f = S.af, minT = f.range === 'all' ? 0 : Date.now() - rangeMs(f.range), mine = me();
    return allAlerts().filter(function (x) {
      var st = x.status || 'new';
      if (f.status === 'open' && /^closed/.test(st)) return false;
      if (f.status === 'closed' && !/^closed/.test(st)) return false;
      if (['open', 'closed', 'all'].indexOf(f.status) < 0 && st !== f.status) return false;
      if (sevIdx(x.severity) < +f.sev) return false;
      if (f.rule && x.rule_id !== f.rule) return false;
      if (f.who === 'me' && (x.assignee || '') !== mine) return false;
      if (f.who === 'none' && x.assignee) return false;
      if (['any', 'me', 'none'].indexOf(f.who) < 0 && x.assignee !== f.who) return false;
      var tl = toMs(x.ts_last || x.ts_first); if (minT && !isNaN(tl) && tl < minT) return false;
      return true;
    }).sort(function (a, b) { return sevIdx(b.severity) - sevIdx(a.severity) || (toMs(b.ts_last) || 0) - (toMs(a.ts_last) || 0); });
  }
  function findAlert(id) { var a = allAlerts().filter(function (x) { return x.id === id; })[0]; if (D.alertDetail && D.alertDetail.id === id) { var d = D.alertDetail.alert || D.alertDetail; return d; } return a || (D.caseAlerts ? arr(D.caseAlerts, 'alerts', 'items').filter(function (x) { return x.id === id; })[0] : null); }
  function ruleById(id) { return arr(D.rules, 'rules', 'items').filter(function (r) { return r.id === id; })[0]; }
  function groupTxt(g) { if (!g || typeof g !== 'object') return ''; return Object.keys(g).map(function (k) { return k + '=' + g[k]; }).join(' · '); }
  function openCases() { return arr(D.openCases, 'cases', 'items').filter(function (c) { return c.status !== 'closed'; }); }
  function caseSelect(id) { return '<select class="x-in sm" id="' + id + '" aria-label="' + E(T('Case')) + '">' + '<option value="">' + E(T('Choose a case…')) + '</option>' + openCases().map(function (c) { return opt(c.id, c.id + ' — ' + (c.title || ''), ''); }).join('') + '</select>'; }
  function names() { var s = {}; allAlerts().forEach(function (a) { if (a.assignee) s[a.assignee] = 1; }); arr(D.cases, 'cases', 'items').forEach(function (c) { if (c.owner) s[c.owner] = 1; }); if (me()) s[me()] = 1; return Object.keys(s).sort(); }
  function namesList(id) { return '<datalist id="' + id + '">' + names().map(function (n) { return '<option value="' + E(n) + '">'; }).join('') + '</datalist>'; }
  function openAlert(id) { S.alertId = id; D.alertDetail = null; load('alertDetail', true); load('openCases'); rerender(true); }
  function loadSamples(a) {
    if (!a || S.samples[a.id]) return;
    var ids = arr(a.sample_event_ids).slice(0, 20).filter(function (x) { return /^[\w-]+$/.test(String(x)); });
    if (!ids.length) { S.samples[a.id] = { rows: [] }; return; }
    var f = toMs(a.ts_first), l = toMs(a.ts_last);
    var from = isNaN(f) ? Date.now() - 2592e6 : f - 864e5, to = isNaN(l) ? Date.now() : Math.min(Date.now(), l + 36e5);
    S.samples[a.id] = { busy: true };
    req('POST', '/search', { q: ids.map(function (x) { return 'id:' + qv(x); }).join(' OR '), from: iso(from), to: iso(to), limit: 50, order: 'asc' })
      .then(function (j) { S.samples[a.id] = { rows: arr(j, 'rows') }; }, function (e) { S.samples[a.id] = { err: e }; }).then(function () { rerender(); });
  }
  function pivotAlert(a) {
    var g = a.group || {}, keys = Object.keys(g).filter(function (k) { return fieldOk(k) && g[k] !== '' && g[k] != null; });
    S.q = keys.map(function (k) { return k + ':' + qv(g[k]); }).join(' AND ');
    var f = toMs(a.ts_first), l = toMs(a.ts_last);
    if (!isNaN(f)) { S.range = 'custom'; S.from = f - 9e5; S.to = Math.min(Date.now(), (isNaN(l) ? f : l) + 9e5); DR.from = localInput(S.from); DR.to = localInput(S.to); }
    S.alertId = null; go('soc-search'); runSearch();
  }
  function vAlerts() {
    var h = head('soc-alerts', T('Alert queue'), T('Triage what the detection rules raised: acknowledge, assign, close with a reason, or escalate to a case.'));
    var g = gate(['alerts']); if (g) return h + g;
    var list = alertList(), all = allAlerts(), ops = canAct();
    Object.keys(S.sel).forEach(function (id) { if (!list.some(function (a) { return a.id === id; })) delete S.sel[id]; });
    var selIds = Object.keys(S.sel), openA = all.filter(function (a) { return !/^closed/.test(a.status || 'new'); });
    var tiles = '<div class="x-tiles" style="margin-bottom:14px">' + ctile('al:new', T('New'), '<span style="color:var(--x-crit)">' + fmtN(openA.filter(function (a) { return (a.status || 'new') === 'new'; }).length) + '</span>')
      + ctile('al:ack', T('Acknowledged'), fmtN(openA.filter(function (a) { return a.status === 'acknowledged'; }).length)) + ctile('al:prog', T('In progress'), fmtN(openA.filter(function (a) { return a.status === 'in-progress'; }).length))
      + ctile('al:crit', T('Critical or high, open'), '<span style="color:var(--x-ser)">' + fmtN(openA.filter(function (a) { return sevIdx(a.severity) >= 3; }).length) + '</span>')
      + ctile('al:none', T('Unassigned, open'), fmtN(openA.filter(function (a) { return !a.assignee; }).length)) + ctile('al:open', T('Shown'), fmtN(list.length)) + '</div>';
    var rules = {}; arr(D.rules, 'rules', 'items').forEach(function (r) { rules[r.id] = r.name || r.id; }); all.forEach(function (a) { if (a.rule_id && !rules[a.rule_id]) rules[a.rule_id] = a.rule_name || a.rule_id; });
    var f = S.af, who = names();
    var filters = '<div class="x-row" style="gap:8px">'
      + '<label class="x-small x-muted">' + E(T('Status')) + ' <select class="x-in sm" data-socaf="status">' + [['open', N('Open (not closed)')], ['all', N('All')], ['new', N('New')], ['acknowledged', N('Acknowledged')], ['in-progress', N('In progress')], ['closed', N('Closed (any reason)')], ['closed-true-positive', N('Closed — true positive')], ['closed-false-positive', N('Closed — false positive')], ['closed-benign', N('Closed — benign')]].map(function (o) { return opt(o[0], T(o[1]), f.status); }).join('') + '</select></label>'
      + '<label class="x-small x-muted">' + E(T('Severity')) + ' <select class="x-in sm" data-socaf="sev">' + [['0', N('Any')], ['4', N('Critical')], ['3', N('High and above')], ['2', N('Medium and above')], ['1', N('Low and above')]].map(function (o) { return opt(o[0], T(o[1]), f.sev); }).join('') + '</select></label>'
      + '<label class="x-small x-muted">' + E(T('Rule')) + ' <select class="x-in sm" data-socaf="rule" style="max-width:260px">' + opt('', T('Any rule'), f.rule) + Object.keys(rules).sort(function (a, b) { return String(rules[a]).localeCompare(String(rules[b])); }).map(function (id) { return opt(id, rules[id] + ' (' + id + ')', f.rule); }).join('') + '</select></label>'
      + '<label class="x-small x-muted">' + E(T('Assignee')) + ' <select class="x-in sm" data-socaf="who">' + opt('any', T('Anyone'), f.who) + (me() ? opt('me', T('Me'), f.who) : '') + opt('none', T('Unassigned'), f.who) + who.map(function (n) { return opt(n, n, f.who); }).join('') + '</select></label>'
      + '<label class="x-small x-muted">' + E(T('Last seen')) + ' <select class="x-in sm" data-socaf="range">' + [['24h', N('24 hours')], ['7d', N('7 days')], ['30d', N('30 days')], ['all', N('Any time')]].map(function (o) { return opt(o[0], T(o[1]), f.range); }).join('') + '</select></label>'
      + '<button class="x-btn ghost sm" data-soc="refresh">↻ ' + E(T('Refresh')) + '</button></div>';
    var bulk = ops && selIds.length ? '<div class="soc-bulk"><div class="x-row" style="gap:8px"><b class="x-small">' + E(TF('{n} selected', { n: selIds.length })) + '</b>'
      + '<button class="x-btn ghost sm" data-soc="bulkack"' + busy('bulk') + '>✓ ' + E(T('Acknowledge')) + '</button>'
      + '<span class="x-row" style="gap:4px"><input class="x-in sm" id="soc-bassign" data-socin="bassign" list="soc-names" value="' + E(DR.bassign || '') + '" placeholder="' + E(T('user name')) + '" style="width:150px"><button class="x-btn ghost sm" data-soc="bulkassign"' + busy('bulk') + '>' + E(T('Assign')) + '</button></span>'
      + '<span class="x-row" style="gap:4px"><select class="x-in sm" id="soc-breason" aria-label="' + E(T('Close reason')) + '">' + REASONS.map(function (r) { return opt(r[0], T(r[1]), DR.breason || 'true-positive'); }).join('') + '</select>'
      + '<input class="x-in sm" id="soc-bnote" data-socin="bnote" value="' + E(DR.bnote || '') + '" placeholder="' + E(T('reason note')) + '" style="width:170px"><button class="x-btn danger sm" data-soc="bulkclose"' + busy('bulk') + '>' + E(T('Close alerts')) + '</button></span>'
      + '<button class="x-btn sm" data-soc="bulkcase"' + busy('bulk') + '>🗂️ ' + E(T('Create case')) + '</button>'
      + '<span class="x-row" style="gap:4px">' + caseSelect('soc-bcase') + '<button class="x-btn ghost sm" data-soc="bulkaddcase"' + busy('bulk') + '>' + E(T('Add to case')) + '</button></span>'
      + '<button class="x-btn ghost sm" data-soc="selnone">' + E(T('Deselect')) + '</button></div>' + namesList('soc-names') + '</div>' : '';
    var allSel = list.length && list.every(function (a) { return S.sel[a.id]; });
    var heads = (ops ? ['<input type="checkbox" class="soc-chk" data-socselall="1" aria-label="' + E(T('Select all')) + '"' + (allSel ? ' checked' : '') + '>'] : []).concat(H([N('Severity'), N('Rule'), N('Grouped by'), N('Count'), N('First seen'), N('Last seen'), N('Status'), N('Assignee'), N('Case')]));
    var rows = list.slice(0, 500).map(function (a) {
      return '<tr style="cursor:pointer" data-socalert="' + E(a.id) + '"' + (a.id === S.alertId ? ' class="soc-warnrow"' : '') + '>' + (ops ? '<td><input type="checkbox" class="soc-chk" data-socsel="' + E(a.id) + '"' + (S.sel[a.id] ? ' checked' : '') + ' aria-label="' + E(T('Select')) + '"></td>' : '')
        + '<td>' + sevPill(a.severity) + '</td><td><b>' + E(a.rule_name || a.rule_id) + '</b><div class="x-small x-muted">' + E(a.rule_id || '') + ' ' + arr(a.mitre).map(function (m) { return '<span class="x-tag">' + E(m) + '</span>'; }).join('') + '</div></td>'
        + '<td class="x-small" style="max-width:280px">' + E(groupTxt(a.group) || a.summary || '—') + '</td><td class="n"><b>' + E(fmtN(a.count || 1)) + '</b></td>'
        + '<td class="x-small" style="white-space:nowrap">' + E(fmtTs(a.ts_first)) + '</td><td class="x-small" style="white-space:nowrap" title="' + E(fmtTs(a.ts_last)) + '">' + E(ago(a.ts_last)) + '</td>'
        + '<td>' + astPill(a.status || 'new') + '</td><td class="x-small">' + (a.assignee ? E(a.assignee) : '<span class="x-muted">—</span>') + '</td><td class="x-small x-mono">' + (a.case_id ? '<span class="soc-val" data-soccase="' + E(a.case_id) + '">' + E(a.case_id) + '</span>' : '<span class="x-muted">—</span>') + '</td></tr>';
    });
    var more = list.length > 500 ? '<div class="x-small x-muted" style="margin-top:8px">' + E(T('Showing the first 500 — narrow the filters to see the rest.')) + '</div>' : '';
    return h + stale(['alerts']) + tiles + '<div class="x-card"><h3>🚨 ' + E(T('Alerts')) + '<span class="x-r">' + filters + '</span></h3>' + bulk
      + '<div class="x-scroll" data-socscroll="alerts" style="max-height:680px">' + tbl(heads, rows) + '</div>' + more + '</div>' + (S.alertId ? drawer() : '');
  }
  function drawer() {
    var a = findAlert(S.alertId);
    var close = '<button class="soc-x" data-soc="closedrawer" aria-label="' + E(T('Close panel')) + '">×</button>';
    if (!a) {
      var e = ERR.alertDetail;
      return '<div class="soc-drawer-bg" data-soc="closedrawer"></div><aside class="soc-drawer" role="dialog" aria-modal="true" data-socscroll="drawer"><div class="x-row" style="justify-content:flex-end">' + close + '</div>' + (e ? pageError(e) : loadingCard()) + '</aside>';
    }
    loadSamples(a);
    var r = ruleById(a.rule_id) || {}, ops = canAct(), g = a.group || {}, st = a.status || 'new', closed = /^closed/.test(st);
    var gk = Object.keys(g);
    var out = '<div class="soc-drawer-bg" data-soc="closedrawer"></div><aside class="soc-drawer" role="dialog" aria-modal="true" aria-label="' + E(T('Alert detail')) + '" data-socscroll="drawer">'
      + '<div class="x-row" style="justify-content:space-between;flex-wrap:nowrap;align-items:flex-start"><div><div class="x-row" style="gap:8px">' + sevPill(a.severity) + astPill(st) + '</div><h2 style="margin:8px 0 4px;font-size:18px">' + E(a.rule_name || a.rule_id) + '</h2><div class="x-small x-muted x-mono">' + E(a.id) + '</div></div>' + close + '</div>'
      + (a.summary ? '<p class="x-small" style="margin:10px 0 0">' + E(a.summary) + '</p>' : '')
      + '<div class="x-tiles" style="margin-top:12px">' + X.tile(T('Events'), E(fmtN(a.count || 1))) + X.tile(T('First seen'), '<span style="font-size:13px">' + E(fmtTs(a.ts_first)) + '</span>') + X.tile(T('Last seen'), '<span style="font-size:13px">' + E(fmtTs(a.ts_last)) + '</span>')
      + X.tile(T('Assignee'), '<span style="font-size:14px">' + E(a.assignee || '—') + '</span>') + X.tile(T('Case'), a.case_id ? '<span class="soc-val" style="font-size:14px" data-soccase="' + E(a.case_id) + '">' + E(a.case_id) + '</span>' : '—') + '</div>';
    if (ops) {
      out += '<h4>' + E(T('Actions')) + '</h4><div class="x-row" style="gap:8px">'
        + (st === 'new' ? '<button class="x-btn sm" data-soc="ack"' + busy('al') + '>✓ ' + E(T('Acknowledge')) + '</button>' : '')
        + '<span class="x-row" style="gap:4px"><input class="x-in sm" id="soc-aassign" data-socin="aassign" list="soc-names2" value="' + E(DR.aassign != null ? DR.aassign : (a.assignee || me())) + '" style="width:170px" aria-label="' + E(T('Assignee')) + '"><button class="x-btn ghost sm" data-soc="assign"' + busy('al') + '>' + E(T('Assign')) + '</button></span>' + namesList('soc-names2') + '</div>'
        + (closed ? '' : '<div class="x-row" style="gap:6px;margin-top:8px"><select class="x-in sm" id="soc-areason" aria-label="' + E(T('Close reason')) + '">' + REASONS.map(function (x) { return opt(x[0], T(x[1]), DR.areason || 'true-positive'); }).join('') + '</select>'
          + '<input class="x-in sm" id="soc-anote" data-socin="anote" value="' + E(DR.anote || '') + '" placeholder="' + E(T('reason note')) + '" style="flex:1;min-width:140px"><button class="x-btn danger sm" data-soc="closealert"' + busy('al') + '>' + E(T('Close alert')) + '</button></div>')
        + '<div class="x-row" style="gap:6px;margin-top:8px">' + (a.case_id ? '' : '<button class="x-btn ghost sm" data-soc="alertcase"' + busy('al') + '>🗂️ ' + E(T('Create case')) + '</button>' + caseSelect('soc-acase') + '<button class="x-btn ghost sm" data-soc="alertaddcase"' + busy('al') + '>' + E(T('Add to case')) + '</button>') + '</div>';
    }
    out += '<h4>' + E(T('Grouped fields')) + '</h4>' + (gk.length ? '<div class="soc-kv">' + gk.map(function (k) { return '<div>' + E(k) + '</div><div>' + E(g[k]) + '</div>'; }).join('') + '</div>' : '<div class="x-small x-muted">—</div>')
      + '<button class="x-btn ghost sm" data-soc="pivot">🔎 ' + E(T('Search these events')) + '</button>';
    var ds = arr(r.mitre).length ? r.mitre : arr(a.mitre);
    out += '<h4>' + E(T('Detection rule')) + '</h4><div class="x-small"><b>' + E(r.name || a.rule_name || a.rule_id) + '</b> <span class="x-mono x-muted">' + E(a.rule_id || '') + '</span>' + (r.type ? ' · ' + E(r.type) : '') + '</div>'
      + '<p class="x-small" style="margin:6px 0">' + (r.description ? E(r.description) : '<span class="x-muted">' + E(T('No description recorded for this rule.')) + '</span>') + '</p>'
      + (ds.length ? '<div class="x-row" style="gap:6px">' + ds.map(function (m) { var tt = techTactics(m).map(function (ta) { var n = TACTICS.filter(function (x) { return x[0] === ta; })[0]; return n ? T(n[1]) : ta; }).join(', '); return mitreLink(m) + (tt ? '<span class="x-small x-muted">' + E(tt) + '</span>' : ''); }).join('') + '</div>' : '')
      + '<div style="margin-top:8px"><button class="x-btn ghost sm" data-socrulego="' + E(a.rule_id || '') + '">📐 ' + E(T('Open rule')) + '</button></div>';
    var sm = S.samples[a.id] || {};
    out += '<h4>' + E(T('Sample events')) + '</h4>' + (sm.err ? inlineErr(sm.err) : sm.busy ? '<div class="x-skel"></div>' : !arr(sm.rows).length ? '<div class="x-small x-muted">' + E(arr(a.sample_event_ids).length ? T('The sample events were not found in the search index (they may be past retention).') : T('This alert carries no sample event ids.')) + '</div>'
      : arr(sm.rows).map(function (ev) { return '<details style="border:1px solid var(--x-line);border-radius:9px;padding:7px 10px;margin-bottom:6px"><summary class="x-small"><span class="x-mono">' + E(fmtTs(ev.ts, true)) + '</span> · ' + E(ev.host || '') + ' · ' + E(ev.action || '') + ' · ' + E(ev.message || '') + '</summary><div class="soc-kv" style="margin-top:8px">'
        + SCHEMA.filter(function (f) { return f !== 'raw' && f !== 'ts' && getF(ev, f) !== ''; }).map(function (f) { return '<div>' + E(f) + '</div><div>' + E(getF(ev, f)) + '</div>'; }).join('') + '</div><pre class="soc-raw">' + E(ev.raw || '') + '</pre></details>'; }).join(''));
    var notes = arr(a.notes);
    out += '<h4>' + E(T('Notes')) + '</h4>' + (notes.length ? '<div class="x-list">' + notes.map(function (n) { return '<div><div class="x-small x-muted">' + E(fmtTs(n.at)) + ' · ' + E(n.by || '') + '</div><div class="x-small" style="white-space:pre-wrap">' + E(n.text) + '</div></div>'; }).join('') + '</div>' : '<div class="x-small x-muted">' + E(T('No notes yet.')) + '</div>')
      + (ops ? '<textarea class="x-in" id="soc-alnote" data-socin="alnote" rows="3" style="margin-top:8px" placeholder="' + E(T('Add an investigation note…')) + '">' + E(DR.alnote || '') + '</textarea><div style="margin-top:6px"><button class="x-btn ghost sm" data-soc="alertnote"' + busy('al') + '>' + E(T('Add note')) + '</button></div>' : '');
    var hist = arr(a.history);
    out += '<h4>' + E(T('History')) + '</h4>' + (hist.length ? '<div class="x-tl">' + hist.slice().reverse().map(function (x) { return '<div><div class="x-small"><b>' + E(x.action) + '</b>' + (x.detail ? ' — ' + E(typeof x.detail === 'object' ? JSON.stringify(x.detail) : x.detail) : '') + '</div><div class="x-small x-muted">' + E(fmtTs(x.at)) + ' · ' + E(x.by || '') + '</div></div>'; }).join('') + '</div>' : '<div class="x-small x-muted">—</div>');
    return out + '</aside>';
  }

  /* ═══════════════════════════ 3. CASES ═══════════════════════════ */
  function caseList() { return arr(D.cases, 'cases', 'items'); }
  function slaState(c) {
    var s = c.sla || {}, now = Date.now(), i = cstIdx(c.status), o = {};
    var ad = toMs(s.ack_due), rd = toMs(s.resolve_due);
    o.ack = isNaN(ad) ? null : { due: ad, over: i === 0 && now > ad, done: i > 0 };
    o.res = isNaN(rd) ? null : { due: rd, over: i < 5 && now > rd, done: i === 5 };
    o.over = !!((o.ack && o.ack.over) || (o.res && o.res.over));
    return o;
  }
  function slaTxt(x) {
    if (!x) return '<span class="x-muted">—</span>';
    if (x.done) return '<span class="soc-ok">✓ ' + E(T('met')) + '</span>';
    var d = (x.due - Date.now()) / 1000;
    return x.over ? '<span class="soc-over">' + E(TF('overdue by {t}', { t: dur(-d) })) + '</span>' : '<span>' + E(TF('due in {t}', { t: dur(d) })) + '</span>';
  }
  function vCases() {
    var h = head('soc-cases', T('Cases'), T('Investigations built from alerts, worked through the incident workflow with playbook tasks and SLA timers.'));
    var g = gate(['cases']); if (g) return h + g;
    var list = caseList().slice().sort(function (a, b) { return (slaState(b).over ? 1 : 0) - (slaState(a).over ? 1 : 0) || sevIdx(b.severity) - sevIdx(a.severity) || (toMs(b.created) || 0) - (toMs(a.created) || 0); });
    if (S.cf.status === 'active') list = list.filter(function (c) { return c.status !== 'closed'; }); else if (S.cf.status !== 'all') list = list.filter(function (c) { return c.status === S.cf.status; });
    if (S.cf.flag === 'sla') list = list.filter(function (c) { return slaState(c).over; }); else if (S.cf.flag === 'crit') list = list.filter(function (c) { return sevIdx(c.severity) >= 3; }); else if (S.cf.flag === 'noown') list = list.filter(function (c) { return !c.owner; });
    var all = caseList(), act = all.filter(function (c) { return c.status !== 'closed'; });
    var tiles = '<div class="x-tiles" style="margin-bottom:14px">' + ctile('ca:active', T('Open cases'), fmtN(act.length)) + ctile('ca:sla', T('SLA overdue'), '<span style="color:var(--x-crit)">' + fmtN(act.filter(function (c) { return slaState(c).over; }).length) + '</span>')
      + ctile('ca:crit', T('Critical or high'), fmtN(act.filter(function (c) { return sevIdx(c.severity) >= 3; }).length)) + ctile('ca:noown', T('Without owner'), fmtN(act.filter(function (c) { return !c.owner; }).length)) + '</div>';
    var filt = '<select class="x-in sm" data-soccf="status" aria-label="' + E(T('Status')) + '">' + opt('active', T('Active (not closed)'), S.cf.status) + opt('all', T('All'), S.cf.status) + CST.map(function (s) { return opt(s[0], T(s[1]), S.cf.status); }).join('') + '</select>';
    var newForm = canAct() ? (S.caseNew ? '<div class="x-note" style="margin-bottom:10px"><div class="x-form" style="grid-template-columns:1fr"><label class="x-f">' + E(T('Title')) + '<input id="soc-ctitle" data-socin="ctitle" value="' + E(DR.ctitle || '') + '"></label>'
      + '<label class="x-f">' + E(T('Severity')) + '<select id="soc-csev">' + SEV.map(function (s, i) { return opt(i, T(s[1]), DR.csev != null ? DR.csev : 2); }).slice().reverse().join('') + '</select></label></div>'
      + '<div class="x-row" style="margin-top:8px"><button class="x-btn sm" data-soc="casecreate"' + busy('cnew') + '>' + E(T('Create case')) + '</button><button class="x-btn ghost sm" data-soc="casenew">' + E(T('Cancel')) + '</button></div></div>' : '<button class="x-btn ghost sm" data-soc="casenew">＋ ' + E(T('New case')) + '</button>') : '';
    var left = '<div class="x-card"><h3>🗂️ ' + E(T('Cases')) + '<span class="x-r">' + filt + '</span></h3>' + newForm + '<div data-socscroll="caselist" style="max-height:760px;overflow:auto;margin-top:8px">'
      + (list.length ? list.map(function (c) {
        var sl = slaState(c);
        return '<div class="x-case' + (c.id === S.caseId ? ' on' : '') + '" data-soccase="' + E(c.id) + '" role="button" tabindex="0"' + (sl.over ? ' style="border-color:var(--x-crit)"' : '') + '><div class="x-row" style="justify-content:space-between;flex-wrap:nowrap"><span class="x-mono x-small">' + E(c.id) + '</span>' + sevPill(c.severity) + '</div>'
          + '<b style="display:block;margin:5px 0;font-size:13px">' + E(c.title || '—') + '</b><div class="x-row" style="gap:6px">' + cstPill(c.status) + '<span class="x-small x-muted">' + E(c.owner || T('no owner')) + '</span>' + (sl.over ? X.pill(T('SLA overdue'), 'crit', '!') : '') + '</div></div>';
      }).join('') : empty('🗂️', T('No cases match this filter.'), '')) + '</div></div>';
    var right = S.caseId ? caseDetail() : '<div class="x-card">' + empty('👈', T('Select a case to see its workflow, tasks and timeline.'), '') + '</div>';
    return h + stale(['cases']) + tiles + '<div class="x-gside">' + left + '<div style="min-width:0">' + right + '</div></div>';
  }
  function caseDetail() {
    var c = D.caseDetail && (D.caseDetail.case || D.caseDetail);
    if (!c || c.id !== S.caseId) { var e = ERR.caseDetail; return e ? pageError(e) : loadingCard(); }
    var ops = canAct(), i = cstIdx(c.status), sl = slaState(c);
    var steps = '<div class="soc-steps">' + CST.map(function (s, k) { return '<div class="soc-step' + (k < i ? ' done' : k === i ? ' on' : '') + '">' + E(T(s[1])) + '</div>'; }).join('') + '</div>';
    var wf = '';
    if (ops && i < 5) {
      var nx = CST[i + 1];
      wf = '<div class="x-row" style="gap:8px">' + (nx[0] !== 'closed' ? '<button class="x-btn sm" data-soccst="' + nx[0] + '"' + busy('case') + '>→ ' + E(TF('Move to {s}', { s: T(nx[1]) })) + '</button>' : '')
        + '<select class="x-in sm" id="soc-cst" aria-label="' + E(T('Status')) + '">' + CST.map(function (s) { return opt(s[0], T(s[1]), DR.cst || (i < 4 ? CST[i + 1][0] : 'closed')); }).join('') + '</select>'
        + '<input class="x-in sm" id="soc-cres" data-socin="cres" value="' + E(DR.cres || '') + '" placeholder="' + E(T('resolution (required to close)')) + '" style="flex:1;min-width:180px"><button class="x-btn ghost sm" data-soc="casestatus"' + busy('case') + '>' + E(T('Set status')) + '</button></div>';
    } else if (ops && i === 5) wf = '<div class="x-row"><button class="x-btn ghost sm" data-soccst="investigating"' + busy('case') + '>↺ ' + E(T('Reopen as investigating')) + '</button></div>';
    var hdr = '<div class="x-card"><div class="x-row" style="justify-content:space-between"><div><span class="x-mono x-small x-muted">' + E(c.id) + '</span><h2 style="margin:4px 0 6px;font-size:19px">' + E(c.title || '—') + '</h2><div class="x-row" style="gap:6px">' + sevPill(c.severity) + cstPill(c.status) + (sl.over ? X.pill(T('SLA overdue'), 'crit', '!') : '') + '</div></div>'
      + '<div class="x-small x-muted" style="text-align:end">' + E(T('Created')) + ' ' + E(fmtTs(c.created)) + (c.closed ? '<br>' + E(T('Closed')) + ' ' + E(fmtTs(c.closed)) : '') + '</div></div>'
      + '<div class="x-sep"></div>' + steps + wf + (c.resolution ? '<div class="x-note" style="margin-top:10px"><b>' + E(T('Resolution')) + ':</b> ' + E(c.resolution) + '</div>' : '') + '</div>';
    var owner = '<div class="x-card"><h3>👤 ' + E(T('Owner and SLA')) + '</h3><div class="x-tiles">' + X.tile(T('Owner'), '<span style="font-size:15px">' + E(c.owner || '—') + '</span>')
      + X.tile(T('Acknowledge by'), '<span style="font-size:13px">' + E(sl.ack ? fmtTs(sl.ack.due) : '—') + '</span>', slaTxt(sl.ack)) + X.tile(T('Resolve by'), '<span style="font-size:13px">' + E(sl.res ? fmtTs(sl.res.due) : '—') + '</span>', slaTxt(sl.res)) + '</div>'
      + (ops ? '<div class="x-row" style="gap:6px;margin-top:10px"><input class="x-in sm" id="soc-cowner" data-socin="cowner" list="soc-names3" value="' + E(DR.cowner != null ? DR.cowner : (c.owner || me())) + '" style="width:200px" aria-label="' + E(T('Owner')) + '"><button class="x-btn ghost sm" data-soc="caseowner"' + busy('case') + '>' + E(T('Assign owner')) + '</button>' + namesList('soc-names3') + '</div>' : '') + '</div>';
    var tasks = arr(c.tasks), done = tasks.filter(function (x) { return x.done; }).length;
    var taskCard = '<div class="x-card"><h3>☑️ ' + E(T('Playbook tasks')) + '<span class="x-r">' + (c.playbook_id ? '<span class="x-tag">' + E(c.playbook_name || c.playbook_id) + '</span>' : '') + X.pill(done + ' / ' + tasks.length, done === tasks.length && tasks.length ? 'ok' : 'info') + '</span></h3>'
      + (tasks.length ? X.meter(tasks.length ? done / tasks.length * 100 : 0, 'acc') + '<div style="margin-top:8px">' + tasks.map(function (x) {
        return '<div class="soc-task' + (x.done ? ' done' : '') + '">' + (ops ? '<input type="checkbox" class="soc-chk" data-soctask="' + E(x.id) + '"' + (x.done ? ' checked' : '') + ' aria-label="' + E(x.title) + '">' : '<span>' + (x.done ? '✓' : '○') + '</span>')
          + '<div><div class="tt x-small">' + E(x.title) + '</div>' + (x.done && (x.by || x.at) ? '<div class="x-small x-muted">' + E(x.by || '') + ' · ' + E(fmtTs(x.at)) + '</div>' : '') + '</div></div>';
      }).join('') + '</div>' : '<div class="x-small x-muted">' + E(T('No playbook tasks on this case.')) + '</div>') + '</div>';
    var ra = arr(c.recommended_actions).length ? c.recommended_actions : arr(c.actions);
    var raCard = '<div class="x-card"><h3>🤖 ' + E(T('Recommended automated actions')) + '<span class="x-r">' + X.pill(T('Requires approval'), 'warn', '!') + '</span></h3>'
      + '<p class="x-lead">' + E(T('Suggested by the playbook. This console only displays them — approval and execution happen through the change and response process, never from this page.')) + '</p>'
      + (ra.length ? '<div class="x-list">' + ra.map(function (x) { x = typeof x === 'string' ? { title: x } : x || {}; return '<div class="x-row" style="justify-content:space-between;flex-wrap:nowrap"><div><b class="x-small">' + E(x.title || x.name || x.action || '—') + '</b>' + (x.target ? ' <span class="x-tag">' + E(x.target) + '</span>' : '') + (x.description ? '<div class="x-small x-muted">' + E(x.description) + '</div>' : '') + '</div>' + X.pill(T('Requires approval'), 'warn', '!') + '</div>'; }).join('') + '</div>' : '<div class="x-small x-muted">' + E(T('No automated actions recommended for this case.')) + '</div>') + '</div>';
    var ca = arr(D.caseAlerts, 'alerts', 'items'), ids = arr(c.alerts).map(function (x) { return typeof x === 'object' && x ? x.id : x; });
    var alertRows = ca.length ? ca.map(function (a) { return '<tr style="cursor:pointer" data-socalertgo="' + E(a.id) + '"><td>' + sevPill(a.severity) + '</td><td class="x-small"><b>' + E(a.rule_name || a.rule_id) + '</b><div class="x-muted">' + E(groupTxt(a.group)) + '</div></td><td class="n">' + E(fmtN(a.count || 1)) + '</td><td class="x-small">' + E(ago(a.ts_last)) + '</td><td>' + astPill(a.status) + '</td></tr>'; })
      : ids.map(function (id) { return '<tr style="cursor:pointer" data-socalertgo="' + E(id) + '"><td colspan="5" class="x-mono x-small">' + E(id) + '</td></tr>'; });
    var alCard = '<div class="x-card"><h3>🚨 ' + E(T('Linked alerts')) + '<span class="x-r">' + X.pill(String(Math.max(ca.length, ids.length)), 'info') + '</span></h3>' + (ERR.caseAlerts && !ca.length && !ids.length ? inlineErr(ERR.caseAlerts) : tbl(H([N('Severity'), N('Rule'), N('Count'), N('Last seen'), N('Status')]), alertRows)) + '</div>';
    var ev = arr(c.evidence);
    var evCard = '<div class="x-card"><h3>📎 ' + E(T('Evidence')) + '</h3>' + (ev.length ? '<div class="x-list">' + ev.map(function (x) { var u = /^https?:\/\//i.test(String(x.ref || '')); return '<div><b class="x-small">' + E(x.name || '—') + '</b> ' + (u ? '<a class="x-small x-mono" href="' + E(x.ref) + '" target="_blank" rel="noopener noreferrer">' + E(x.ref) + '</a>' : '<span class="x-small x-mono">' + E(x.ref || '') + '</span>') + '<div class="x-small x-muted">' + E(fmtTs(x.at)) + ' · ' + E(x.by || '') + '</div></div>'; }).join('') + '</div>' : '<div class="x-small x-muted">' + E(T('No evidence linked yet.')) + '</div>')
      + (ops ? '<div class="x-row" style="gap:6px;margin-top:10px"><input class="x-in sm" id="soc-evname" data-socin="evname" value="' + E(DR.evname || '') + '" placeholder="' + E(T('evidence name')) + '" style="width:180px"><input class="x-in sm" id="soc-evref" data-socin="evref" value="' + E(DR.evref || '') + '" placeholder="' + E(T('link, file path or hash')) + '" style="flex:1;min-width:180px" dir="ltr"><button class="x-btn ghost sm" data-soc="caseevidence"' + busy('case') + '>' + E(T('Add evidence')) + '</button></div>' : '') + '</div>';
    var tl = arr(c.timeline);
    var tlCard = '<div class="x-card"><h3>🕒 ' + E(T('Timeline and notes')) + '</h3>'
      + (ops ? '<textarea class="x-in" id="soc-cnote" data-socin="cnote" rows="3" placeholder="' + E(T('Add a note to the case timeline…')) + '">' + E(DR.cnote || '') + '</textarea><div style="margin:6px 0 12px"><button class="x-btn ghost sm" data-soc="casenote"' + busy('case') + '>' + E(T('Add note')) + '</button></div>' : '')
      + (tl.length ? '<div class="x-tl">' + tl.slice().reverse().map(function (x) { return '<div><div class="x-small">' + (x.kind ? '<span class="x-tag">' + E(x.kind) + '</span> ' : '') + '<span style="white-space:pre-wrap">' + E(x.text) + '</span></div><div class="x-small x-muted">' + E(fmtTs(x.at)) + ' · ' + E(x.by || '') + '</div></div>'; }).join('') + '</div>' : '<div class="x-small x-muted">—</div>') + '</div>';
    return hdr + '<div class="x-g2e">' + owner + taskCard + '</div>' + raCard + alCard + '<div class="x-g2e">' + evCard + tlCard + '</div>';
  }
  function openCase(id) { S.caseId = id; D.caseDetail = null; D.caseAlerts = null; delete ERR.caseDetail; load('caseDetail', true); load('caseAlerts', true); }

  /* ═══════════════════════════ 4. RULES ═══════════════════════════ */
  var OPS = ['eq', 'neq', 'in', 'contains', 'startswith', 'endswith', 're', 'exists', 'gt', 'gte', 'lt', 'lte', 'cidr', 'intel'];
  var TYPES = ['single', 'threshold', 'distinct', 'sequence'];
  var RKEYS = ['id', 'name', 'enabled', 'severity', 'mitre', 'description', 'author', 'version', 'type', 'match', 'group_by', 'window_s', 'count', 'distinct_field', 'distinct_count', 'steps', 'by', 'suppress_s', 'fields_in_alert', 'references', 'tags', 'falsepositives', 'sigma_id'];
  var RUNTIME = ['alerts_24h', 'noisy', 'origin', 'source', 'stats', 'updated', 'updated_by', 'created', 'created_by', 'last_alert', 'last_alert_at'];
  function ruleList() { return arr(D.rules, 'rules', 'items'); }
  function noisy(r) { if (r.noisy != null) return !!r.noisy; var m = D.metrics && arr(D.metrics.noisy_rules); return !!(m && m.some(function (x) { return (x.rule_id || x.id) === r.id; })); }
  function lineCol(txt, pos) { var l = 1, c = 1; for (var i = 0; i < pos && i < txt.length; i++) { if (txt[i] === '\n') { l++; c = 1; } else c++; } return { l: l, c: c }; }
  function validateRule(txt) {
    var out = { errors: [], warnings: [], rule: null };
    function er(tpl, o) { out.errors.push(TF(tpl, o)); }
    function wr(tpl, o) { out.warnings.push(TF(tpl, o)); }
    if (!String(txt || '').trim()) { er('The editor is empty.'); return out; }
    var r;
    try { r = JSON.parse(txt); } catch (e) {
      var m = /position (\d+)/.exec(e.message), m2 = /line (\d+) column (\d+)/.exec(e.message), lc = m2 ? { l: m2[1], c: m2[2] } : m ? lineCol(txt, +m[1]) : null;
      out.errors.push(lc ? TF('JSON syntax error at line {l}, column {c}', lc) : T('JSON syntax error')); out.detail = e.message; return out;
    }
    if (!r || typeof r !== 'object' || Array.isArray(r)) { er('A rule must be a JSON object.'); return out; }
    out.rule = r;
    if (typeof r.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(r.id)) er('"id" is required: 3 to 64 letters, digits, dots, dashes or underscores.');
    if (typeof r.name !== 'string' || !r.name.trim()) er('"name" is required.');
    if (typeof r.severity !== 'number' || r.severity % 1 || r.severity < 0 || r.severity > 4) er('"severity" must be a whole number from 0 (info) to 4 (critical).');
    if (TYPES.indexOf(r.type) < 0) er('"type" must be one of: {v}.', { v: TYPES.join(', ') });
    if (r.enabled != null && typeof r.enabled !== 'boolean') er('"enabled" must be true or false.');
    if (r.mitre != null) { if (!Array.isArray(r.mitre)) er('"mitre" must be a list of ATT&CK ids.'); else r.mitre.forEach(function (x) { if (!/^(T\d{4}(\.\d{3})?|TA\d{4})$/.test(String(x))) wr('"{v}" does not look like an ATT&CK id (T1110, T1110.001 or TA0006).', { v: x }); }); }
    else wr('No "mitre" ids — the alert will not appear in the ATT&CK view.');
    if (!r.description) wr('No "description" — analysts see it in the alert panel.');
    function field(f, p) { if (typeof f !== 'string' || !fieldOk(f)) er('{p}: unknown field "{v}" — use a schema field or fields.<key>.', { p: p, v: f }); }
    function cond(c, p) {
      if (!c || typeof c !== 'object') { er('{p}: a condition must be an object with field, op and value.', { p: p }); return; }
      field(c.field, p);
      if (OPS.indexOf(c.op) < 0) { er('{p}: unknown operator "{v}".', { p: p, v: c.op }); return; }
      if (c.op !== 'exists' && c.value === undefined) er('{p}: "value" is required for "{v}".', { p: p, v: c.op });
      if (c.op === 'in' && !Array.isArray(c.value)) er('{p}: "in" needs a list of values.', { p: p });
      if (/^(gt|gte|lt|lte)$/.test(c.op) && !isFinite(+c.value)) er('{p}: "{v}" needs a number.', { p: p, v: c.op });
      if (c.op === 're') { try { new RegExp(String(c.value), 'i'); } catch (e) { er('{p}: invalid regular expression.', { p: p }); } }
      if (c.op === 'cidr' && !/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(String(c.value))) er('{p}: "cidr" needs a network such as 10.0.0.0/8.', { p: p });
    }
    function match(m, p) {
      if (!m || typeof m !== 'object' || Array.isArray(m)) { er('{p}: "match" must be an object with "all", "any" and/or "none" lists.', { p: p }); return; }
      var n = 0;
      ['all', 'any', 'none'].forEach(function (k) { if (m[k] == null) return; if (!Array.isArray(m[k])) { er('{p}.{k} must be a list.', { p: p, k: k }); return; } n += m[k].length; m[k].forEach(function (c, i) { cond(c, p + '.' + k + '[' + i + ']'); }); });
      Object.keys(m).forEach(function (k) { if (['all', 'any', 'none'].indexOf(k) < 0) wr('{p}: "{v}" is ignored.', { p: p, v: k }); });
      if (!n) er('{p}: add at least one condition.', { p: p });
    }
    function list(v, p) { if (!Array.isArray(v) || !v.length) { er('"{p}" must be a non-empty list of fields.', { p: p }); return; } v.forEach(function (f, i) { field(f, p + '[' + i + ']'); }); }
    function pos(v, p, min) { if (typeof v !== 'number' || !(v >= (min || 1))) er('"{p}" must be a number of at least {n}.', { p: p, n: min || 1 }); }
    if (r.type === 'sequence') {
      if (!Array.isArray(r.steps) || r.steps.length < 2) er('A sequence rule needs "steps" with at least two steps.');
      else r.steps.forEach(function (s, i) { match(s && s.match, 'steps[' + i + '].match'); });
      pos(r.window_s, 'window_s'); if (r.by != null) list(r.by, 'by'); else wr('No "by" fields — steps from different users or hosts will be chained together.');
    } else if (TYPES.indexOf(r.type) >= 0) {
      match(r.match, 'match');
      if (r.type === 'threshold') { pos(r.count, 'count', 2); pos(r.window_s, 'window_s'); if (r.group_by != null) list(r.group_by, 'group_by'); else wr('No "group_by" — the threshold counts all matching events together.'); }
      if (r.type === 'distinct') { field(r.distinct_field, 'distinct_field'); pos(r.distinct_count, 'distinct_count', 2); pos(r.window_s, 'window_s'); if (r.group_by != null) list(r.group_by, 'group_by'); }
    }
    if (r.suppress_s != null) { if (typeof r.suppress_s !== 'number' || r.suppress_s < 0) er('"suppress_s" must be zero or a positive number of seconds.'); }
    else wr('No "suppress_s" — every match raises a new alert.');
    if (r.fields_in_alert != null) list(r.fields_in_alert, 'fields_in_alert');
    Object.keys(r).forEach(function (k) { if (RKEYS.indexOf(k) < 0 && RUNTIME.indexOf(k) < 0) wr('Unknown key "{v}" will be ignored.', { v: k }); });
    return out;
  }
  function valHTML(v) {
    if (!v) return '';
    return (v.errors.length ? '<div class="x-note crit"><b>' + E(TF('{n} problems to fix', { n: v.errors.length })) + '</b><ul class="x-small" style="margin:6px 0 0;padding-inline-start:18px">' + v.errors.map(function (x) { return '<li>' + E(x) + '</li>'; }).join('') + '</ul>' + (v.detail ? '<div class="x-small x-muted x-mono" style="margin-top:4px">' + E(v.detail) + '</div>' : '') + '</div>'
      : '<div class="x-note">✓ ' + E(T('The rule is valid.')) + '</div>')
      + (v.warnings.length ? '<div class="x-note warn" style="margin-top:8px"><ul class="x-small" style="margin:0;padding-inline-start:18px">' + v.warnings.map(function (x) { return '<li>' + E(x) + '</li>'; }).join('') + '</ul></div>' : '');
  }
  function editableRule(r) { var o = {}; Object.keys(r).forEach(function (k) { if (RUNTIME.indexOf(k) < 0) o[k] = r[k]; }); return o; }
  function openRule(id) {
    var r = ruleList().filter(function (x) { return x.id === id; })[0];
    S.ruleId = id; S.ruleNew = false; S.ruleMsg = null; S.test = null; S.testErr = null; S.ruleDirty = false;
    DR.rulejson = r ? JSON.stringify(editableRule(r), null, 2) : '';
    req('GET', '/rules/' + encodeURIComponent(id)).then(function (j) { var full = j && (j.rule || j); if (S.ruleId === id && !S.ruleDirty && full && full.id === id) { DR.rulejson = JSON.stringify(editableRule(full), null, 2); rerender(); } }, function () {});
  }
  var NEWRULE = { id: 'SENTRA-CUSTOM-001', name: 'New rule', enabled: false, severity: 2, mitre: [], description: '', author: '', version: 1, type: 'threshold',
    match: { all: [{ field: 'action', op: 'eq', value: 'logon-failed' }], any: [], none: [] }, group_by: ['user'], window_s: 300, count: 10, suppress_s: 3600, fields_in_alert: ['user', 'src_ip', 'host'] };
  function vRules() {
    var h = head('soc-rules', T('Detection rules'), T('Real-time rules run by the engine on every event. Test a change over past data before enabling it.'));
    var g = gate(['rules']); if (g) return h + g;
    var all = ruleList(), q = (S.rq || '').toLowerCase(), admin = isAdmin(), ops = canAct();
    var list = all.filter(function (r) {
      if (S.rf === 'enabled' && r.enabled === false) return false; if (S.rf === 'disabled' && r.enabled !== false) return false; if (S.rf === 'noisy' && !noisy(r)) return false;
      return !q || (r.id + ' ' + r.name + ' ' + arr(r.mitre).join(' ') + ' ' + (r.description || '')).toLowerCase().indexOf(q) >= 0;
    }).sort(function (a, b) { return num(b.alerts_24h) - num(a.alerts_24h) || String(a.id).localeCompare(String(b.id)); });
    var tiles = '<div class="x-tiles" style="margin-bottom:14px">' + ctile('ru:all', T('Rules'), fmtN(all.length)) + ctile('ru:enabled', T('Enabled'), fmtN(all.filter(function (r) { return r.enabled !== false; }).length))
      + ctile('ru:noisy', T('Noisy'), '<span style="color:var(--x-warn)">' + fmtN(all.filter(noisy).length) + '</span>') + ctile('ru:all', T('Alerts in 24 h'), fmtN(all.reduce(function (s, r) { return s + num(r.alerts_24h); }, 0))) + '</div>';
    var bar = '<div class="x-row" style="gap:8px"><input class="x-in sm" id="soc-rq" data-socin="rq" value="' + E(S.rq) + '" placeholder="' + E(T('Filter by id, name or ATT&CK id')) + '" style="width:240px">'
      + '<select class="x-in sm" data-socrf="1" aria-label="' + E(T('Show')) + '">' + [['all', N('All rules')], ['enabled', N('Enabled')], ['disabled', N('Disabled')], ['noisy', N('Noisy')]].map(function (o) { return opt(o[0], T(o[1]), S.rf); }).join('') + '</select>'
      + (admin ? '<button class="x-btn sm" data-soc="rulenew">＋ ' + E(T('New rule')) + '</button>' : '') + '</div>';
    var rows = list.map(function (r) {
      var on = r.enabled !== false;
      return '<tr style="cursor:pointer" data-socrule="' + E(r.id) + '"' + (r.id === S.ruleId ? ' class="soc-warnrow"' : '') + '><td>' + (admin ? '<button class="x-btn ' + (on ? '' : 'ghost ') + 'sm" data-socruleon="' + E(r.id) + '" data-on="' + (on ? '0' : '1') + '" aria-pressed="' + on + '" title="' + E(on ? T('Click to turn off') : T('Click to turn on')) + '"' + busy('r' + r.id) + '>' + (on ? '● ' + E(T('On')) : '○ ' + E(T('Off'))) + '</button>' : X.pill(on ? T('On') : T('Off'), on ? 'ok' : ''))
        + '</td><td><b>' + E(r.name || r.id) + '</b><div class="x-small x-muted x-mono">' + E(r.id) + '</div></td><td class="x-small">' + E(r.type || '') + '</td><td>' + sevPill(r.severity) + '</td><td>' + arr(r.mitre).map(function (m) { return '<span class="x-tag">' + E(m) + '</span>'; }).join('') + '</td>'
        + '<td class="n"><b>' + E(fmtN(r.alerts_24h)) + '</b></td><td>' + (noisy(r) ? X.pill(T('Noisy'), 'warn', '!') : '') + '</td><td class="x-small x-muted">' + E(r.origin || r.source || (r.sigma_id ? 'sigma' : '')) + '</td></tr>';
    });
    var listCard = '<div class="x-card"><h3>📐 ' + E(T('Rules')) + '<span class="x-r">' + bar + '</span></h3><div class="x-scroll" data-socscroll="rules" style="max-height:520px">'
      + tbl(H([N('State'), N('Rule'), N('Type'), N('Severity'), N('ATT&CK'), N('Alerts 24 h'), N('Noisy'), N('Origin')]), rows) + '</div></div>';
    return h + stale(['rules']) + tiles + listCard + editorCard() + (ops ? sigmaCard() : '');
  }
  function editorCard() {
    if (!S.ruleId && !S.ruleNew) return '<div class="x-card">' + empty('📐', T('Select a rule to view, edit or test it.'), isAdmin() ? T('Or start a new rule, or convert a Sigma rule below.') : '') + '</div>';
    var admin = isAdmin(), ops = canAct(), v = validateRule(DR.rulejson || '');
    var r = S.ruleId ? ruleList().filter(function (x) { return x.id === S.ruleId; })[0] : null;
    var title = S.ruleNew ? T('New rule') : (r ? r.name : S.ruleId);
    var msg = S.ruleMsg ? '<div class="x-note ' + (S.ruleMsg.ok ? '' : 'crit') + '" style="margin-top:8px">' + E(S.ruleMsg.text) + (S.ruleMsg.list ? '<ul class="x-small" style="margin:6px 0 0;padding-inline-start:18px">' + S.ruleMsg.list.map(function (x) { return '<li>' + E(x) + '</li>'; }).join('') + '</ul>' : '') + '</div>' : '';
    var ed = '<div class="x-card"><h3>🧾 ' + E(title || '') + '<span class="x-r">' + (r && r.sigma_id ? X.pill(T('Converted from Sigma'), 'info') : '') + (admin ? '' : X.pill(T('Only an admin can save rule changes'), 'info', '🔒')) + '<button class="soc-x" data-soc="ruleclose" aria-label="' + E(T('Close editor')) + '">×</button></span></h3>'
      + '<div class="x-g2"><div style="min-width:0"><textarea class="x-in soc-editor" id="soc-rulejson" data-socin="rulejson" spellcheck="false" aria-label="' + E(T('Rule JSON')) + '"' + (admin || ops ? '' : ' readonly') + '>' + E(DR.rulejson || '') + '</textarea></div>'
      + '<div style="min-width:0"><div id="soc-ruleval" aria-live="polite">' + valHTML(v) + '</div>' + msg
      + '<div class="x-row" style="gap:8px;margin-top:12px">' + (admin ? '<button class="x-btn sm" data-soc="rulesave"' + busy('rsave') + '>💾 ' + E(T('Save rule')) + '</button>' : '') + '<button class="x-btn ghost sm" data-soc="ruleformat">' + E(T('Format JSON')) + '</button></div>'
      + (ops ? '<div class="x-sep"></div><b class="x-small">' + E(T('Test over past events')) + '</b><div class="x-small x-muted" style="margin:4px 0 8px">' + E(T('Runs the rule in the editor over stored events. Nothing is raised or saved — you see the alerts it would have produced.')) + '</div>'
        + '<div class="x-row" style="gap:8px"><select class="x-in sm" data-soctestr="1" aria-label="' + E(T('Time range')) + '">' + RANGES.slice(1).map(function (x) { return opt(x[0], T(x[2]), S.testRange); }).join('') + '</select><button class="x-btn ghost sm" data-soc="ruletest"' + busy('rtest') + '>🧪 ' + E(T('Test rule')) + '</button></div>' : '')
      + '<div class="x-small x-muted" style="margin-top:12px">' + E(T('Operators:')) + ' <span class="x-mono">' + OPS.join(', ') + '</span></div></div></div></div>';
    return ed + testCard();
  }
  function testCard() {
    if (S.busy.rtest) return '<div class="x-card">' + loadingCard() + '</div>';
    if (S.testErr) return '<div class="x-card"><h3>🧪 ' + E(T('Test result')) + '</h3>' + inlineErr(S.testErr) + (S.testErr.detail && Array.isArray(S.testErr.detail.errors) ? '<ul class="x-small">' + S.testErr.detail.errors.map(function (x) { return '<li>' + E(x) + '</li>'; }).join('') + '</ul>' : '') + '</div>';
    if (!S.test) return '';
    var al = arr(S.test, 'alerts', 'would_be_alerts');
    return '<div class="x-card"><h3>🧪 ' + E(T('Test result')) + '<span class="x-r"><span class="x-tag">' + E(T('dry run — nothing was raised')) + '</span></span></h3><div class="x-tiles" style="margin-bottom:12px">'
      + X.tile(T('Would-be alerts'), fmtN(al.length)) + X.tile(T('Events scanned'), S.test.events_scanned != null ? fmtN(S.test.events_scanned) : '—') + X.tile(T('Took'), S.test.took_ms != null ? fmtN(S.test.took_ms) + ' ms' : '—') + '</div>'
      + (S.test.truncated ? '<div class="x-note warn" style="margin-bottom:10px">' + E(T('The test stopped early — the range holds more events than one test may scan. Narrow the range for a complete answer.')) + '</div>' : '')
      + '<div class="x-scroll" style="max-height:420px">' + tbl(H([N('First seen'), N('Last seen'), N('Grouped by'), N('Count'), N('Summary')]), al.slice(0, 300).map(function (a) {
        return '<tr><td class="x-small">' + E(fmtTs(a.ts_first)) + '</td><td class="x-small">' + E(fmtTs(a.ts_last)) + '</td><td class="x-small">' + E(groupTxt(a.group)) + '</td><td class="n">' + E(fmtN(a.count || 1)) + '</td><td class="x-small">' + E(a.summary || '') + '</td></tr>';
      })) + '</div></div>';
  }
  function sigmaCard() {
    var admin = isAdmin(), res = S.sigmaRes;
    return '<div class="x-card"><h3>🔁 ' + E(T('Import a Sigma rule')) + '</h3><p class="x-lead">' + E(T('Paste Sigma YAML. The engine converts it into a native rule and shows it in the editor above for review and testing before it is saved.')) + '</p>'
      + '<textarea class="x-in soc-editor" id="soc-sigma" data-socin="sigma" spellcheck="false" style="min-height:200px" placeholder="title: …&#10;logsource:&#10;  product: windows&#10;detection:&#10;  selection:&#10;    EventID: 4625&#10;  condition: selection" aria-label="' + E(T('Sigma YAML')) + '">' + E(DR.sigma || '') + '</textarea>'
      + '<div class="x-row" style="gap:8px;margin-top:10px"><button class="x-btn ghost sm" data-soc="sigmaconv"' + busy('sigma') + '>⇄ ' + E(T('Convert to native rule')) + '</button>' + (admin ? '<button class="x-btn sm" data-soc="sigmaimport"' + busy('sigma') + '>' + E(T('Import and save')) + '</button>' : '') + '</div>'
      + (res ? (res.err ? '<div style="margin-top:10px">' + inlineErr(res.err) + (res.err.detail && Array.isArray(res.err.detail.errors) ? '<ul class="x-small">' + res.err.detail.errors.map(function (x) { return '<li>' + E(x) + '</li>'; }).join('') + '</ul>' : '') + '</div>'
        : '<div class="x-note" style="margin-top:10px">✓ ' + E(res.saved ? T('Imported and saved as a native rule.') : T('Converted — review it in the editor above, test it, then save.')) + (arr(res.warnings).length ? '<ul class="x-small" style="margin:6px 0 0;padding-inline-start:18px">' + arr(res.warnings).map(function (x) { return '<li>' + E(x) + '</li>'; }).join('') + '</ul>' : '') + '</div>') : '') + '</div>';
  }

  /* ═══════════════════════════ 5. SOURCES & ENGINE HEALTH ═══════════════════════════ */
  function srcList() { return arr(D.sources, 'sources', 'items'); }
  function srcState(s) {
    var st = String(s.status || '').toLowerCase(); if (st === 'ok' || st === 'silent' || st === 'errors') return st;
    var ls = toMs(s.last_seen); if (isNaN(ls) || Date.now() - ls > 9e5) return 'silent';
    return errRate(s) >= 5 ? 'errors' : 'ok';
  }
  function errRate(s) {
    if (s.parse_error_rate != null) { var r = num(s.parse_error_rate); return r <= 1 ? r * 100 : r; }
    var ev = num(s.events_today), pe = num(s.parse_errors_today != null ? s.parse_errors_today : s.parse_errors); return ev ? pe / ev * 100 : 0;
  }
  function stPill(ok, okTxt, badTxt, warn) { return ok === true ? X.pill(T(okTxt), 'ok', '✓') : ok === false ? X.pill(T(badTxt), warn ? 'warn' : 'crit', warn ? '!' : '✕') : X.pill(T('Unknown'), '', '?'); }
  function bytes(n) { n = num(n); return n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' GB' : n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n >= 1024 ? Math.round(n / 1024) + ' KB' : n + ' B'; }
  function healthCard() {
    var h = D.health;
    if (!h) return ERR.health ? '<div class="x-card"><h3>🩺 ' + E(T('Engine health')) + '</h3>' + inlineErr(ERR.health) + '</div>' : '<div class="x-card">' + loadingCard() + '</div>';
    var eg = typeof h.engine === 'object' && h.engine ? h.engine : { status: h.engine || h.status };
    var ch = typeof h.clickhouse === 'object' && h.clickhouse ? h.clickhouse : {};
    var sp = h.spool || {}, ig = h.integrity || h.chain || {}, eps = h.eps, det = h.detector || h.detection || {};
    var egOk = eg.status ? /^(ok|up|running|healthy)$/i.test(eg.status) : true;
    var igSt = String(ig.status || '').toLowerCase(), igOk = igSt ? /^(ok|verified|intact|valid)$/.test(igSt) : null;
    var spB = num(sp.bytes), spN = num(sp.files != null ? sp.files : sp.batches);
    var rows = [
      [N('Engine'), stPill(egOk, N('Running'), N('Degraded'), true), [eg.version ? T('version') + ' ' + eg.version : '', eg.uptime_s != null ? T('up for') + ' ' + dur(eg.uptime_s) : ''].filter(Boolean).join(' · ')],
      [N('ClickHouse'), stPill(chOk(h), N('Connected'), N('Unreachable')), [ch.version ? T('version') + ' ' + ch.version : '', ch.latency_ms != null ? T('latency') + ' ' + fmtN(ch.latency_ms) + ' ms' : '', ch.error || ''].filter(Boolean).join(' · ')],
      [N('Spool (events waiting for ClickHouse)'), stPill(!spB && !spN, N('Empty'), N('Events waiting'), true), spB || spN ? [spN ? fmtN(spN) + ' ' + T('files') : '', spB ? bytes(spB) : '', sp.oldest ? T('oldest') + ' ' + fmtTs(sp.oldest) : ''].filter(Boolean).join(' · ') : T('Everything has been written to ClickHouse.')],
      [N('Integrity chain'), stPill(igOk, N('Verified'), N('Broken')), [ig.batches != null ? fmtN(ig.batches) + ' ' + T('batches') : '', ig.last_verified || ig.verified_at ? T('verified') + ' ' + ago(ig.last_verified || ig.verified_at) : '', ig.broken_at ? T('break at batch') + ' ' + ig.broken_at : '', ig.last_hash ? String(ig.last_hash).slice(0, 16) + '…' : ''].filter(Boolean).join(' · ')],
      [N('Detection'), stPill(det.running != null ? !!det.running : null, N('Running'), N('Stopped')), [det.rules != null ? fmtN(det.rules) + ' ' + T('rules loaded') : '', det.alerts_24h != null ? fmtN(det.alerts_24h) + ' ' + T('alerts in 24 h') : ''].filter(Boolean).join(' · ')]
    ];
    var epsTxt = eps == null ? '—' : typeof eps === 'object' ? fmtN(eps.now != null ? eps.now : eps.m1 != null ? eps.m1 : eps['1m']) : fmtN(eps);
    var colls = arr(h.collectors);
    return '<div class="x-card"><h3>🩺 ' + E(T('Engine health')) + '<span class="x-r"><span class="x-small x-muted">' + E(T('events per second now')) + ': <b>' + E(epsTxt) + '</b></span></span></h3>'
      + tbl(H([N('Component'), N('State'), N('Detail')]), rows.map(function (r) { return '<tr><td><b class="x-small">' + E(T(r[0])) + '</b></td><td>' + r[1] + '</td><td class="x-small">' + E(r[2] || '') + '</td></tr>'; }))
      + (colls.length ? '<div class="x-sep"></div><b class="x-small">' + E(T('Collectors')) + '</b>' + tbl(H([N('Collector'), N('State'), N('Listening on'), N('EPS')]), colls.map(function (c) {
        var ok = c.ok != null ? !!c.ok : c.listening != null ? !!c.listening : c.status ? /^(ok|up|listening|running)$/i.test(c.status) : null;
        return '<tr><td class="x-small"><b>' + E(c.name || c.id || '') + '</b>' + (c.error ? '<div class="x-muted">' + E(c.error) + '</div>' : '') + '</td><td>' + (c.enabled === false ? X.pill(T('Off'), '') : stPill(ok, N('Listening'), N('Down'))) + '</td><td class="x-small x-mono">' + E(c.bind || c.port || '') + '</td><td class="n">' + E(c.eps != null ? fmtN(c.eps) : '—') + '</td></tr>';
      })) : '') + '</div>';
  }
  function vSources() {
    var h = head('soc-sources', T('Log sources and engine health'), T('Which devices are sending, how fast, and whether the engine is storing everything intact.'));
    var g = gate(['sources']); if (g) return h + (D.health ? healthCard() : '') + g;
    var all = srcList().map(function (s) { return { s: s, st: srcState(s), er: errRate(s) }; });
    var cnt = function (k) { return all.filter(function (x) { return x.st === k; }).length; };
    var eps1 = all.reduce(function (a, x) { return a + num(x.s.eps_1m); }, 0), today = all.reduce(function (a, x) { return a + num(x.s.events_today); }, 0);
    var tiles = '<div class="x-tiles" style="margin-bottom:14px">' + ctile('so:all', T('Log sources'), fmtN(all.length)) + ctile('so:ok', T('Reporting'), '<span style="color:var(--x-ok)">' + fmtN(cnt('ok')) + '</span>')
      + ctile('so:silent', T('Silent'), '<span style="color:var(--x-crit)">' + fmtN(cnt('silent')) + '</span>') + ctile('so:errors', T('Parse errors'), '<span style="color:var(--x-warn)">' + fmtN(cnt('errors')) + '</span>')
      + ctile('so:ok', T('Events per second (1 min)'), fmtN(eps1)) + ctile('so:all', T('Events today'), C.num(today)) + '</div>';
    var seg = '<div class="x-seg">' + [['all', N('All')], ['ok', N('Reporting')], ['silent', N('Silent')], ['errors', N('Parse errors')]].map(function (c) { return '<button data-socsf="' + c[0] + '" class="' + (S.sf === c[0] ? 'on' : '') + '">' + E(T(c[1])) + ' ' + (c[0] === 'all' ? all.length : cnt(c[0])) + '</button>'; }).join('') + '</div>';
    var ord = { silent: 0, errors: 1, ok: 2 };
    var list = all.filter(function (x) { return S.sf === 'all' || x.st === S.sf; }).sort(function (a, b) { return ord[a.st] - ord[b.st] || String(a.s.src_id || a.s.id).localeCompare(String(b.s.src_id || b.s.id)); });
    var rows = list.map(function (x) {
      var s = x.s, er = x.er;
      return '<tr' + (x.st === 'silent' ? ' class="soc-sil"' : x.st === 'errors' ? ' class="soc-warnrow"' : '') + '><td>' + (x.st === 'ok' ? X.pill(T('Reporting'), 'ok', '✓') : x.st === 'silent' ? X.pill(T('Silent'), 'crit', '✕') : X.pill(T('Parse errors'), 'warn', '!')) + '</td>'
        + '<td><b>' + E(s.src_id || s.id || '—') + '</b><div class="x-small x-muted">' + E(s.src_type || '') + (s.host ? ' · ' + E(s.host) : '') + '</div></td><td class="x-small">' + E(s.collector || '—') + '</td>'
        + '<td class="x-small' + (x.st === 'silent' ? ' soc-over' : '') + '" title="' + E(fmtTs(s.last_seen)) + '">' + E(s.last_seen ? ago(s.last_seen) : T('never')) + '</td>'
        + '<td class="n">' + E(fmtN(s.eps_1m)) + '</td><td class="n">' + E(fmtN(s.eps_1h)) + '</td><td class="n">' + E(fmtN(s.events_today)) + '</td>'
        + '<td style="min-width:110px">' + X.meter(Math.min(100, er * 5), er >= 5 ? 'crit' : er >= 1 ? 'warn' : 'ok') + '<div class="x-small x-muted">' + E(pct(er)) + '</div></td>'
        + '<td><button class="x-btn ghost sm" data-socsrcq="' + E(s.src_id || s.id || '') + '" title="' + E(T('Search this source')) + '">🔎</button></td></tr>';
    });
    return h + stale(['sources', 'health']) + tiles + '<div class="x-card"><h3>🔌 ' + E(T('Log sources')) + '<span class="x-r">' + seg + '</span></h3><div class="x-scroll" data-socscroll="src" style="max-height:620px">'
      + tbl(H([N('State'), N('Source'), N('Collector'), N('Last seen'), N('EPS 1 min'), N('EPS 1 h'), N('Events today'), N('Parse error rate'), '']), rows) + '</div>'
      + '<div class="x-small x-muted" style="margin-top:8px">' + E(T('A source is silent when nothing has arrived for 15 minutes (or the engine marks it silent). Silent sources are listed first.')) + '</div></div>' + healthCard();
  }

  /* ═══════════════════════════ 6. SOC OVERVIEW ═══════════════════════════ */
  function sevCounts(o) { var r = [0, 0, 0, 0, 0]; if (Array.isArray(o)) { o.forEach(function (x) { r[sevIdx(x.severity != null ? x.severity : x.k)] += num(x.n != null ? x.n : x.count); }); return r; } Object.keys(o || {}).forEach(function (k) { r[sevIdx(k)] += num(o[k]); }); return r; }
  function topCard(title, icon, list, keys, pivot) {
    var items = arr(list).slice(0, 8).map(function (it) { var l = ''; for (var i = 0; i < keys.length; i++) if (it[keys[i]] != null && it[keys[i]] !== '') { l = it[keys[i]]; break; } return { it: it, l: String(l), n: num(it.n != null ? it.n : it.count) }; });
    var mx = Math.max.apply(null, items.map(function (x) { return x.n; }).concat([1]));
    return '<div class="x-card"><h3>' + icon + ' ' + E(title) + '</h3>' + (items.length ? items.map(function (x) {
      var pi = PIV.length; PIV.push({ kind: pivot, v: x.it.rule_id || x.it.id || x.l });
      return '<div class="xc-hb"><div class="l" title="' + E(x.l) + '"><span class="soc-val" data-socpiv="' + pi + '">' + E(x.l || '—') + '</span>' + (pivot === 'rule' && noisy({ id: x.it.rule_id || x.it.id, noisy: x.it.noisy }) ? ' ' + X.pill(T('Noisy'), 'warn', '!') : '') + '</div><div class="t"><i style="width:' + (x.n / mx * 100).toFixed(1) + '%;background:var(--x-info)"></i></div><div class="v">' + E(C.num(x.n)) + '</div></div>';
    }).join('') : '<div class="x-small x-muted">' + E(T('Nothing in this period.')) + '</div>') + '</div>';
  }
  function mitreCard(m) {
    var tc = {}, src = '';
    if (m && m.mitre && typeof m.mitre === 'object') { src = 'metrics'; if (Array.isArray(m.mitre)) m.mitre.forEach(function (x) { tc[String(x.id || x.t || x.v).toUpperCase()] = (tc[String(x.id || x.t || x.v).toUpperCase()] || 0) + num(x.n != null ? x.n : x.count); }); else Object.keys(m.mitre).forEach(function (k) { tc[k.toUpperCase()] = num(m.mitre[k]); }); }
    else if (D.dashAlerts) { src = 'alerts'; arr(D.dashAlerts, 'alerts', 'items').forEach(function (a) { arr(a.mitre).forEach(function (id) { id = String(id).toUpperCase(); tc[id] = (tc[id] || 0) + 1; }); }); }
    else { load('dashAlerts'); if (ERR.dashAlerts) return '<div class="x-card"><h3>🧬 ' + E(T('MITRE ATT&CK tactics')) + '</h3>' + inlineErr(ERR.dashAlerts) + '</div>'; return '<div class="x-card"><h3>🧬 ' + E(T('MITRE ATT&CK tactics')) + '</h3><div class="x-skel"></div></div>'; }
    var by = {}, techBy = {}, unm = 0;
    Object.keys(tc).forEach(function (id) { var ts = techTactics(id); if (!ts.length) { unm += tc[id]; return; } ts.forEach(function (ta) { by[ta] = (by[ta] || 0) + tc[id]; (techBy[ta] = techBy[ta] || []).push([id, tc[id]]); }); });
    var mx = Math.max.apply(null, TACTICS.map(function (x) { return by[x[0]] || 0; }).concat([1]));
    var grid = '<div class="soc-mitre">' + TACTICS.map(function (x) {
      var n = by[x[0]] || 0, p = n ? Math.round(12 + 70 * n / mx) : 0, tech = (techBy[x[0]] || []).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 3);
      return '<div class="soc-mt" style="background:' + (n ? 'color-mix(in srgb,var(--x-crit) ' + p + '%,transparent)' : 'var(--x-soft)') + (p > 55 ? ';color:#fff' : '') + '" title="' + E(x[0]) + '"><div class="k">' + E(T(x[1])) + '</div><div class="n">' + (n ? E(C.num(n)) : '·') + '</div>'
        + '<div style="font-size:10px;line-height:1.5;opacity:.85">' + tech.map(function (tt) { return E(tt[0]) + ' ×' + E(tt[1]); }).join('<br>') + '</div></div>';
    }).join('') + '</div>';
    return '<div class="x-card"><h3>🧬 ' + E(T('MITRE ATT&CK tactics')) + '<span class="x-r"><span class="x-tag">' + E(src === 'metrics' ? T('from alert ATT&CK ids') : T('from alerts in the last 30 days')) + '</span></span></h3>' + grid
      + (unm ? '<div class="x-small x-muted" style="margin-top:8px">' + E(TF('{n} alert technique hits could not be placed on a tactic (technique not in the built-in map).', { n: fmtN(unm) })) + '</div>' : '') + '</div>';
  }
  function lrCard() {
    var l = D.lr, e = ERR.lr, ttl = '<h3>⚖️ ' + E(T('LogRhythm parallel run')) + '<span class="x-r"><span class="x-tag">' + E(T('same period, both SIEMs')) + '</span></span></h3>';
    if (!l) return '<div class="x-card">' + ttl + (e ? (e.kind === 'missing' ? '<div class="x-small x-muted">' + E(T('The comparison feed is not available on this engine yet.')) + '</div>' : inlineErr(e)) : '<div class="x-skel"></div>') + '</div>';
    if (l.configured === false) return '<div class="x-card">' + ttl + '<div class="x-note warn">' + E(T('The LogRhythm alarm feed is not configured, so there is nothing to compare yet.')) + '</div></div>';
    var both = num(l.both), ours = num(l.only_ours), lr = num(l.only_lr), tot = both + ours + lr;
    var w = l.window || {};
    function t2(list, keys) { return tbl(H([N('Name'), N('Both'), N('Only ours'), N('Only LogRhythm')]), arr(list).slice(0, 10).map(function (x) { var nm = ''; for (var i = 0; i < keys.length; i++) if (x[keys[i]]) { nm = x[keys[i]]; break; } return '<tr><td class="x-small">' + E(nm) + '</td><td class="n">' + E(fmtN(x.both)) + '</td><td class="n">' + E(fmtN(x.only_ours)) + '</td><td class="n"' + (num(x.only_lr) ? ' style="color:var(--x-warn);font-weight:800"' : '') + '>' + E(fmtN(x.only_lr)) + '</td></tr>'; })); }
    return '<div class="x-card">' + ttl + (w.from ? '<div class="x-small x-muted" style="margin:-6px 0 10px">' + E(fmtTs(w.from)) + ' → ' + E(fmtTs(w.to)) + '</div>' : '')
      + '<div class="x-g2e"><div>' + (tot ? C.donut([{ label: T('Detected by both'), v: both, color: 'var(--x-ok)' }, { label: T('Only our engine'), v: ours, color: 'var(--x-info)' }, { label: T('Only LogRhythm'), v: lr, color: 'var(--x-warn)' }], { center: tot ? Math.round(both / tot * 100) + '%' : '—', centerLabel: T('agreement'), size: 150 }) : '<div class="x-small x-muted">' + E(T('No detections in the comparison window yet.')) + '</div>')
      + '<div class="x-small x-muted" style="margin-top:8px">' + E(T('"Only LogRhythm" detections are the ones to review before LogRhythm is retired: each needs a matching rule or a documented reason.')) + '</div></div>'
      + '<div style="min-width:0"><b class="x-small">' + E(T('By rule')) + '</b>' + t2(l.per_rule, ['rule', 'name', 'rule_name', 'rule_id']) + '</div></div>'
      + (arr(l.per_source).length ? '<div class="x-sep"></div><b class="x-small">' + E(T('By log source')) + '</b>' + t2(l.per_source, ['src', 'src_id', 'source', 'name']) : '') + '</div>';
  }
  /* ─────────────────────────── command-centre overview (own charts, works with or without the portal chart layer) ─────────────────────────── */
  function css2() {
    if (document.getElementById('sentra-soc-css2')) return;
    var st = document.createElement('style'); st.id = 'sentra-soc-css2';
    st.textContent = [
      /* design layer for all six tabs: deeper cards, calmer type, one accent; colours come from the portal theme variables */
      '.x.soc{--cc-panel:var(--panel,#0f1623);--cc-line:var(--x-line,#1f2a3c);--cc-ink:var(--x-ink,#e6ebf3);--cc-mute:var(--x-mute,#8b97ab);--cc-acc:var(--x-acc,#6366f1);--cc-crit:var(--x-crit,#ef4444);--cc-ser:var(--x-ser,#f97316);--cc-warn:var(--x-warn,#eab308);--cc-ok:var(--x-ok,#22c55e);--cc-info:var(--x-info,#3b82f6)}',
      '.x.soc .x-card{border-radius:14px;border:1px solid var(--cc-line);background:linear-gradient(180deg,color-mix(in srgb,var(--cc-panel) 92%,#fff 3%),var(--cc-panel));box-shadow:0 1px 0 rgba(255,255,255,.03) inset,0 8px 24px rgba(0,0,0,.18)}',
      '.x.soc .x-card h3{font-size:13px;letter-spacing:.01em}',
      '.x.soc .soc-head{padding:14px 16px;border:1px solid var(--cc-line);border-radius:16px;background:radial-gradient(1200px 120px at 0 0,color-mix(in srgb,var(--cc-acc) 16%,transparent),transparent),var(--cc-panel);margin-bottom:12px}',
      '.x.soc .soc-h1{font-size:24px;font-weight:800;letter-spacing:-.01em}',
      '.x.soc .soc-nav{gap:4px;padding:4px;border:1px solid var(--cc-line);border-radius:12px;background:var(--cc-panel)}',
      '.x.soc .soc-nav button{border:0!important;border-radius:9px!important;background:transparent!important;color:var(--cc-mute)!important;font-weight:600;padding:8px 14px!important}',
      '.x.soc .soc-nav button:hover{color:var(--cc-ink)!important;background:color-mix(in srgb,var(--cc-ink) 6%,transparent)!important}',
      '.x.soc .soc-nav button.on{color:#fff!important;background:linear-gradient(180deg,var(--cc-acc),color-mix(in srgb,var(--cc-acc) 70%,#000))!important;box-shadow:0 4px 14px color-mix(in srgb,var(--cc-acc) 35%,transparent)}',
      '.x.soc .x-tiles .x-tile,.x.soc [data-soct]{border-radius:12px}',
      '.x.soc table th{font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--cc-mute)}html[lang="ar"] .x.soc table th{letter-spacing:0;text-transform:none}',
      '.x.soc table tbody tr:hover>td{background:color-mix(in srgb,var(--cc-ink) 4%,transparent)}',
      /* command centre */
      '.cc-bar{display:grid;grid-template-columns:auto repeat(6,minmax(0,1fr));gap:1px;background:var(--cc-line);border:1px solid var(--cc-line);border-radius:14px;overflow:hidden;margin-bottom:14px}',
      '@media(max-width:1200px){.cc-bar{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:640px){.cc-bar{grid-template-columns:1fr 1fr}}',
      '.cc-bar>div{background:var(--cc-panel);padding:10px 14px;min-width:0}.cc-bar .l{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--cc-mute);font-weight:700}html[lang="ar"] .cc-bar .l{letter-spacing:0}',
      '.cc-bar .v{font-size:18px;font-weight:800;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.cc-bar .s{font-size:11px;color:var(--cc-mute);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
      '.cc-state{display:flex;align-items:center;gap:12px;min-width:220px}.cc-state .dot{width:14px;height:14px;border-radius:50%;flex:0 0 auto;box-shadow:0 0 0 4px color-mix(in srgb,currentColor 22%,transparent)}',
      '.cc-state.ok{color:var(--cc-ok)}.cc-state.warn{color:var(--cc-warn)}.cc-state.crit{color:var(--cc-crit)}.cc-state .dot{background:currentColor;animation:ccPulse 2.4s ease-in-out infinite}.cc-state .t{color:var(--cc-ink)}',
      '@keyframes ccPulse{50%{box-shadow:0 0 0 8px color-mix(in srgb,currentColor 0%,transparent)}}@media(prefers-reduced-motion:reduce){.cc-state .dot{animation:none}}',
      '.cc-kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-bottom:14px}@media(max-width:1300px){.cc-kpis{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:640px){.cc-kpis{grid-template-columns:1fr 1fr}}',
      '.cc-kpi{position:relative;text-align:start;font:inherit;color:var(--cc-ink);border:1px solid var(--cc-line);border-radius:14px;padding:12px 14px 12px 16px;background:linear-gradient(180deg,color-mix(in srgb,var(--k,var(--cc-acc)) 10%,var(--cc-panel)),var(--cc-panel));overflow:hidden;cursor:pointer;min-height:96px}',
      '.cc-kpi::before{content:"";position:absolute;inset-block:10px;inset-inline-start:0;width:3px;border-radius:0 3px 3px 0;background:var(--k,var(--cc-acc))}',
      '.cc-kpi:hover{border-color:color-mix(in srgb,var(--k,var(--cc-acc)) 55%,var(--cc-line));transform:translateY(-1px)}.cc-kpi:focus-visible{outline:2px solid var(--k,var(--cc-acc));outline-offset:2px}',
      '.cc-kpi .l{font-size:11.5px;color:var(--cc-mute);font-weight:600}.cc-kpi .v{font-size:30px;font-weight:800;line-height:1.1;margin-top:4px;font-variant-numeric:tabular-nums}.cc-kpi .s{font-size:11px;color:var(--cc-mute);margin-top:2px}',
      '.cc-kpi .ic{position:absolute;inset-inline-end:12px;top:10px;font-size:18px;opacity:.55}',
      '.cc-sevbar{display:flex;height:6px;border-radius:3px;overflow:hidden;margin-top:8px;background:color-mix(in srgb,var(--cc-ink) 8%,transparent)}.cc-sevbar i{display:block;height:100%}',
      '.cc-g{display:grid;gap:14px;margin-bottom:14px}.cc-g.a{grid-template-columns:minmax(0,2fr) minmax(280px,1fr)}.cc-g.b{grid-template-columns:repeat(3,minmax(0,1fr))}.cc-g.c{grid-template-columns:repeat(4,minmax(0,1fr))}',
      '@media(max-width:1200px){.cc-g.a,.cc-g.b{grid-template-columns:1fr}.cc-g.c{grid-template-columns:1fr 1fr}}@media(max-width:640px){.cc-g.c{grid-template-columns:1fr}}',
      '.cc-g>.x-card{margin:0}',
      '.cc-chart{display:block;width:100%;height:auto;overflow:visible}.cc-chart text{fill:var(--cc-mute);font-size:10px;font-family:inherit}.cc-chart .grid{stroke:var(--cc-line);stroke-width:1}',
      '.cc-legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:11.5px;color:var(--cc-mute);margin-top:6px}.cc-legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-inline-end:5px;vertical-align:-1px}',
      '.cc-ring{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.cc-ring svg{flex:0 0 auto}.cc-rl{flex:1;min-width:150px}',
      '.cc-rl button{display:flex;width:100%;justify-content:space-between;align-items:center;gap:8px;font:inherit;font-size:12.5px;color:var(--cc-ink);background:transparent;border:0;border-bottom:1px solid var(--cc-line);padding:7px 2px;cursor:pointer}.cc-rl button:hover{color:#fff}.cc-rl b{font-variant-numeric:tabular-nums}',
      '.cc-row{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--cc-line);font-size:12.5px}.cc-row:last-child{border-bottom:0}',
      '.cc-row .n{font-variant-numeric:tabular-nums;color:var(--cc-mute);white-space:nowrap}.cc-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-inline-end:7px;vertical-align:0}',
      '.cc-mbar{height:5px;border-radius:3px;background:color-mix(in srgb,var(--cc-ink) 8%,transparent);overflow:hidden;margin-top:4px}.cc-mbar i{display:block;height:100%;border-radius:3px}',
      '.cc-rank{display:grid;grid-template-columns:20px minmax(0,1fr) auto;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--cc-line);font-size:12.5px}.cc-rank:last-child{border-bottom:0}',
      '.cc-rank .no{font-size:11px;font-weight:800;color:var(--cc-mute);text-align:center}.cc-rank .nm{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.cc-rank .ct{font-variant-numeric:tabular-nums;font-weight:700}',
      '.cc-rank .tr{grid-column:2/4;height:4px;border-radius:2px;background:color-mix(in srgb,var(--cc-ink) 7%,transparent);overflow:hidden;margin-top:-2px}.cc-rank .tr i{display:block;height:100%;background:linear-gradient(90deg,var(--cc-acc),var(--cc-info))}',
      '.cc-gauge{display:grid;grid-template-columns:1fr 1fr;gap:12px}.cc-gauge>div{border:1px solid var(--cc-line);border-radius:12px;padding:10px;text-align:center}.cc-gauge .v{font-size:22px;font-weight:800}.cc-gauge .l{font-size:11px;color:var(--cc-mute)}'
    ].join('');
    document.head.appendChild(st);
  }
  var SEVK = ['var(--cc-mute)', 'var(--cc-info)', 'var(--cc-warn)', 'var(--cc-ser)', 'var(--cc-crit)'];
  function kpi(act, icon, label, val, sub, color, extra) {
    var on = act && SOCT[act];
    return '<' + (on ? 'button type="button" data-soct="' + act + '"' : 'div') + ' class="cc-kpi" style="--k:' + (color || 'var(--cc-acc)') + '"><span class="ic" aria-hidden="true">' + icon + '</span><div class="l">' + E(label) + '</div><div class="v">' + val + '</div>' + (sub ? '<div class="s">' + sub + '</div>' : '') + (extra || '') + '</' + (on ? 'button' : 'div') + '>';
  }
  /* stacked area chart, one series per severity, days on the x axis */
  function areaChart(groups) {
    var W = 720, Hh = 210, L = 34, B = 22, T0 = 8, n = groups.length; if (!n) return '';
    var tot = groups.map(function (g) { return [0, 1, 2, 3, 4].reduce(function (a, i) { return a + num(g['s' + i]); }, 0); }), mx = Math.max.apply(null, tot.concat([1]));
    var nice = mx <= 5 ? 5 : Math.ceil(mx / 5) * 5, x = function (i) { return L + (n === 1 ? (W - L) / 2 : i * (W - L - 6) / (n - 1)); }, y = function (v) { return T0 + (Hh - T0 - B) * (1 - v / nice); };
    var acc = groups.map(function () { return 0; }), paths = '';
    [0, 1, 2, 3, 4].forEach(function (s) {
      var lo = acc.slice(); groups.forEach(function (g, i) { acc[i] += num(g['s' + s]); });
      if (!groups.some(function (g) { return num(g['s' + s]); })) return;
      var top = acc.map(function (v, i) { return x(i).toFixed(1) + ',' + y(v).toFixed(1); }), bot = lo.map(function (v, i) { return x(i).toFixed(1) + ',' + y(v).toFixed(1); }).reverse();
      paths += '<polygon points="' + top.concat(bot).join(' ') + '" fill="' + SEVK[s] + '" fill-opacity="' + (s >= 3 ? .78 : .55) + '"><title>' + E(T(SEV[s][1])) + '</title></polygon>';
    });
    var grid = [0, .5, 1].map(function (f) { var v = Math.round(nice * f); return '<line class="grid" x1="' + L + '" x2="' + W + '" y1="' + y(v) + '" y2="' + y(v) + '"/><text x="' + (L - 6) + '" y="' + (y(v) + 3) + '" text-anchor="end">' + v + '</text>'; }).join('');
    var step = Math.max(1, Math.ceil(n / 7)), lab = groups.map(function (g, i) { return i % step && i !== n - 1 ? '' : '<text x="' + x(i) + '" y="' + (Hh - 6) + '" text-anchor="middle">' + E(g.x) + '</text>'; }).join('');
    var hit = groups.map(function (g, i) { return '<rect x="' + (x(i) - (W - L) / n / 2) + '" y="' + T0 + '" width="' + ((W - L) / n) + '" height="' + (Hh - T0 - B) + '" fill="transparent"><title>' + E(g.x) + ': ' + tot[i] + ' ' + E(T('alerts')) + '</title></rect>'; }).join('');
    return '<svg class="cc-chart" viewBox="0 0 ' + W + ' ' + Hh + '" role="img" aria-label="' + E(T('Alerts per day, by severity')) + '">' + grid + paths + lab + hit + '</svg>'
      + '<div class="cc-legend">' + [4, 3, 2, 1, 0].map(function (s) { return '<span><i style="background:' + SEVK[s] + '"></i>' + E(T(SEV[s][1])) + '</span>'; }).join('') + '</div>';
  }
  function ring(parts, center, label) {
    var R = 54, C2 = 2 * Math.PI * R, tot = parts.reduce(function (a, p) { return a + p.v; }, 0), off = 0;
    var seg = tot ? parts.filter(function (p) { return p.v; }).map(function (p) { var l = C2 * p.v / tot, s = '<circle cx="70" cy="70" r="' + R + '" fill="none" stroke="' + p.c + '" stroke-width="16" stroke-dasharray="' + l.toFixed(2) + ' ' + (C2 - l).toFixed(2) + '" stroke-dashoffset="' + (-off).toFixed(2) + '" transform="rotate(-90 70 70)"><title>' + E(p.l) + ': ' + p.v + '</title></circle>'; off += l; return s; }).join('') : '';
    return '<svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label="' + E(label) + '"><circle cx="70" cy="70" r="' + R + '" fill="none" stroke="var(--cc-line)" stroke-width="16"/>' + seg
      + '<text x="70" y="68" text-anchor="middle" style="font-size:26px;font-weight:800;fill:var(--cc-ink)">' + E(center) + '</text><text x="70" y="88" text-anchor="middle" style="font-size:11px;fill:var(--cc-mute)">' + E(label) + '</text></svg>';
  }
  function rankList(title, icon, list, keys, pivot) {
    var items = arr(list).slice(0, 7).map(function (it) { var l = ''; for (var i = 0; i < keys.length; i++) if (it[keys[i]] != null && it[keys[i]] !== '') { l = it[keys[i]]; break; } return { it: it, l: String(l), n: num(it.n != null ? it.n : it.count) }; });
    var mx = Math.max.apply(null, items.map(function (x) { return x.n; }).concat([1]));
    return '<div class="x-card"><h3>' + icon + ' ' + E(title) + '</h3>' + (items.length ? items.map(function (x, i) {
      var pi = PIV.length; PIV.push({ kind: pivot, v: x.it.rule_id || x.it.id || x.l });
      return '<div class="cc-rank"><span class="no">' + (i + 1) + '</span><span class="nm" title="' + E(x.l) + '"><span class="soc-val" data-socpiv="' + pi + '">' + E(x.l || '—') + '</span>' + (pivot === 'rule' && noisy({ id: x.it.rule_id || x.it.id, noisy: x.it.noisy }) ? ' ' + X.pill(T('Noisy'), 'warn', '!') : '') + '</span><span class="ct">' + E(fmtN(x.n)) + '</span><span class="tr"><i style="width:' + Math.max(3, x.n / mx * 100).toFixed(1) + '%"></i></span></div>';
    }).join('') : '<div class="x-small x-muted">' + E(T('Nothing in this period.')) + '</div>') + '</div>';
  }
  function statusBar() {
    var h = D.health, e = ERR.health;
    if (!h) return '<div class="cc-bar"><div class="cc-state ' + (isDown(e) ? 'crit' : 'warn') + '"><span class="dot"></span><div><div class="l">' + E(T('SIEM engine')) + '</div><div class="v t">' + E(isDown(e) ? T('Not connected') : T('Checking…')) + '</div></div></div></div>';
    var eng = h.engine || {}, ch = h.clickhouse || {}, sp = h.spool || {}, ig = h.integrity || {}, eps = h.eps || {}, dt = h.detector || {};
    var cols = arr(h.collectors), bad = cols.filter(function (c) { return c.status === 'error' || (c.enabled !== false && c.listening === false); }).length;
    var lvl = String(eng.status || '').toLowerCase() !== 'ok' || ch.ok === false || dt.running === false ? 'crit' : bad || num(sp.files) > 0 || (ig.status && ig.status !== 'verified') ? 'warn' : 'ok';
    var word = lvl === 'ok' ? T('All systems normal') : lvl === 'warn' ? T('Needs attention') : T('Degraded');
    return '<div class="cc-bar"><div class="cc-state ' + lvl + '"><span class="dot"></span><div><div class="l">' + E(T('SIEM engine')) + '</div><div class="v t">' + E(word) + '</div><div class="s">' + E(T('up')) + ' ' + E(eng.uptime_s != null ? dur(eng.uptime_s) : '—') + (eng.version ? ' · v' + E(eng.version) : '') + '</div></div></div>'
      + '<div><div class="l">' + E(T('Events / second')) + '</div><div class="v">' + E(fmtN(eps.now != null ? eps.now : eps.m1)) + '</div><div class="s">' + E(T('1 min')) + ' ' + E(fmtN(eps.m1)) + ' · ' + E(T('1 h')) + ' ' + E(fmtN(eps.h1)) + '</div></div>'
      + '<div><div class="l">' + E(T('Detection')) + '</div><div class="v" style="color:' + (dt.running === false ? 'var(--cc-crit)' : 'var(--cc-ok)') + '">' + E(dt.running === false ? T('Stopped') : T('Running')) + '</div><div class="s">' + E(TF('{n} rules', { n: fmtN(dt.rules) })) + ' · ' + E(TF('{n} alerts in 24 h', { n: fmtN(dt.alerts_24h) })) + '</div></div>'
      + '<div><div class="l">ClickHouse</div><div class="v" style="color:' + (ch.ok === false ? 'var(--cc-crit)' : 'var(--cc-ok)') + '">' + E(ch.ok === false ? T('Down') : ch.latency_ms != null ? ch.latency_ms + ' ms' : T('OK')) + '</div><div class="s">' + E(ch.version || '') + '</div></div>'
      + '<div><div class="l">' + E(T('Spool (backlog)')) + '</div><div class="v" style="color:' + (num(sp.files) ? 'var(--cc-warn)' : 'var(--cc-ok)') + '">' + E(fmtN(sp.files)) + '</div><div class="s">' + E(num(sp.files) ? T('events waiting to be stored') : T('nothing waiting')) + '</div></div>'
      + '<div><div class="l">' + E(T('Integrity chain')) + '</div><div class="v" style="color:' + (ig.status === 'verified' ? 'var(--cc-ok)' : 'var(--cc-warn)') + '">' + E(ig.status === 'verified' ? T('Verified') : ig.status ? T(ig.status) : '—') + '</div><div class="s">' + E(ig.last_verified ? ago(ig.last_verified) : '') + (ig.batches != null ? ' · ' + E(TF('{n} batches', { n: fmtN(ig.batches) })) : '') + '</div></div>'
      + '<div><div class="l">' + E(T('Collectors')) + '</div><div class="v" style="color:' + (bad ? 'var(--cc-crit)' : 'var(--cc-ok)') + '">' + E(fmtN(cols.length - bad)) + ' / ' + E(fmtN(cols.length)) + '</div><div class="s">' + E(bad ? TF('{n} with a problem', { n: bad }) : T('all listening')) + '</div></div></div>';
  }
  function collectorsCard() {
    var cols = arr(D.health && D.health.collectors), mx = Math.max.apply(null, cols.map(function (c) { return num(c.eps); }).concat([1]));
    return '<div class="x-card"><h3>📡 ' + E(T('Collectors')) + '<span class="x-r"><button class="x-btn ghost sm" data-socgo="soc-sources">' + E(T('Log sources')) + ' →</button></span></h3>' + (cols.length ? cols.map(function (c) {
      var st = c.status === 'error' ? ['var(--cc-crit)', T('Error')] : c.enabled === false ? ['var(--cc-mute)', T('Off')] : c.listening === false ? ['var(--cc-crit)', T('Not listening')] : ['var(--cc-ok)', T('Listening')];
      return '<div class="cc-row"><span><span class="cc-dot" style="background:' + st[0] + '"></span><b>' + E(c.name) + '</b> <span class="x-muted x-small">' + E(c.port || '') + '</span>' + (c.error ? '<div class="x-small" style="color:var(--cc-crit)">' + E(c.error) + '</div>' : '') + '</span><span class="n" style="min-width:110px">' + E(st[1]) + (c.eps != null ? ' · ' + E(fmtN(c.eps)) + ' eps<div class="cc-mbar"><i style="width:' + (num(c.eps) / mx * 100).toFixed(1) + '%;background:var(--cc-info)"></i></div>' : '') + '</span></div>';
    }).join('') : '<div class="x-small x-muted">' + E(T('The engine reported no collectors.')) + '</div>') + '</div>';
  }
  function sourcesCard() {
    var ttl = '<h3>🔌 ' + E(T('Log sources')) + '<span class="x-r"><button class="x-btn ghost sm" data-socgo="soc-sources">' + E(T('All sources')) + ' →</button></span></h3>';
    if (!D.sources) return '<div class="x-card">' + ttl + (ERR.sources ? inlineErr(ERR.sources) : '<div class="x-skel"></div><div class="x-skel"></div>') + '</div>';
    var all = srcList().map(function (s) { return { s: s, st: srcState(s) }; }), c = function (k) { return all.filter(function (x) { return x.st === k; }).length; };
    var worst = all.filter(function (x) { return x.st !== 'ok'; }).slice(0, 5);
    return '<div class="x-card">' + ttl + '<div class="cc-gauge" style="margin-bottom:10px"><div data-soct="so:ok" role="button" tabindex="0"><div class="v" style="color:var(--cc-ok)">' + fmtN(c('ok')) + '</div><div class="l">' + E(T('Reporting')) + '</div></div><div data-soct="so:silent" role="button" tabindex="0"><div class="v" style="color:' + (c('silent') ? 'var(--cc-crit)' : 'var(--cc-ok)') + '">' + fmtN(c('silent')) + '</div><div class="l">' + E(T('Silent')) + '</div></div></div>'
      + (worst.length ? worst.map(function (x) { return '<div class="cc-row"><span><span class="cc-dot" style="background:' + (x.st === 'silent' ? 'var(--cc-crit)' : 'var(--cc-warn)') + '"></span>' + E(x.s.src_id || x.s.id || '') + ' <span class="x-muted x-small">' + E(x.s.src_type || '') + '</span></span><span class="n">' + E(x.st === 'silent' ? T('last seen') + ' ' + ago(x.s.last_seen) : T('parse errors')) + '</span></div>'; }).join('') : '<div class="x-small" style="color:var(--cc-ok)">✓ ' + E(T('Every log source is reporting.')) + '</div>') + '</div>';
  }
  function responseCard(m, mttd, mttr, sla) {
    var ab = num(sla.ack_breaches), rb = num(sla.resolve_breaches);
    return '<div class="x-card"><h3>⏱️ ' + E(T('Response and SLA')) + '</h3><div class="cc-gauge"><div><div class="v">' + E(mttd == null ? '—' : dur(mttd)) + '</div><div class="l">' + E(T('Mean time to detect')) + '</div></div><div><div class="v">' + E(mttr == null ? '—' : dur(mttr)) + '</div><div class="l">' + E(T('Mean time to respond')) + '</div></div></div>'
      + '<div class="cc-row" style="margin-top:8px"><span>' + E(T('Acknowledge SLA breaches')) + '</span><span class="n" style="color:' + (ab ? 'var(--cc-crit)' : 'var(--cc-ok)') + '"><b>' + fmtN(ab) + '</b></span></div>'
      + '<div class="cc-row"><span>' + E(T('Resolve SLA breaches')) + '</span><span class="n" style="color:' + (rb ? 'var(--cc-crit)' : 'var(--cc-ok)') + '"><b>' + fmtN(rb) + '</b></span></div>'
      + '<div class="cc-row"><span>' + E(T('Open cases')) + '</span><span class="n"><button class="x-btn ghost sm" data-socgo="soc-cases">' + E(fmtN(m.open_cases != null ? m.open_cases : sla.open_cases)) + ' →</button></span></div></div>';
  }
  function vDash() {
    css2();
    var g = gate(['metrics']);
    var hd = head('soc-dashboard', T('SOC command centre'), T('Live engine health, alert load, response times, log sources and ATT&CK coverage - straight from the SIEM engine.'));
    if (g) return hd + statusBar() + g;
    PIV = [];
    var m = D.metrics, ob = sevCounts(m.open_by_severity || m.open_alerts_by_severity || {}), open = ob.reduce(function (a, b) { return a + b; }, 0);
    var mttd = m.mttd_s != null ? m.mttd_s : m.mttd_min != null ? m.mttd_min * 60 : null, mttr = m.mttr_s != null ? m.mttr_s : m.mttr_min != null ? m.mttr_min * 60 : null;
    var sla = m.sla || {}, breaches = sla.breaches != null ? num(sla.breaches) : num(sla.ack_breaches) + num(sla.resolve_breaches);
    var openCases = m.open_cases != null ? m.open_cases : sla.open_cases, crit = ob[4] + ob[3];
    var sevbar = open ? '<div class="cc-sevbar">' + [4, 3, 2, 1, 0].map(function (i) { return ob[i] ? '<i style="width:' + (ob[i] / open * 100).toFixed(1) + '%;background:' + SEVK[i] + '" title="' + E(T(SEV[i][1])) + ' ' + ob[i] + '"></i>' : ''; }).join('') + '</div>' : '';
    var kpis = '<div class="cc-kpis">' + kpi('al:open', '🚨', T('Open alerts'), fmtN(open), E(T('all severities')), 'var(--cc-info)', sevbar)
      + kpi('al:crit', '🔥', T('Critical or high, open'), fmtN(crit), E(crit ? T('handle these first') : T('none open')), crit ? 'var(--cc-crit)' : 'var(--cc-ok)')
      + kpi(null, '🎯', T('Mean time to detect'), mttd == null ? '—' : E(dur(mttd)), E(T('event to alert')), 'var(--cc-acc)')
      + kpi('al:closed', '🛠️', T('Mean time to respond'), mttr == null ? '—' : E(dur(mttr)), E(T('alert to closure')), 'var(--cc-acc)')
      + kpi('ca:sla', '⏰', T('SLA breaches'), fmtN(breaches), sla.ack_breaches != null ? E(T('acknowledge')) + ' ' + fmtN(sla.ack_breaches) + ' · ' + E(T('resolve')) + ' ' + fmtN(sla.resolve_breaches) : '', breaches ? 'var(--cc-crit)' : 'var(--cc-ok)')
      + kpi('ca:active', '🗂️', T('Open cases'), openCases == null ? '—' : fmtN(openCases), E(T('investigations in progress')), 'var(--cc-ser)') + '</div>';
    var days = arr(m.alerts_by_day, 'days');
    var groups = days.map(function (d) { var src = d.by_severity || d.by_sev || d, c = sevCounts(Object.keys(src).filter(function (k) { return /^([0-4]|info|low|medium|high|critical)$/i.test(k); }).reduce(function (o, k) { o[k] = src[k]; return o; }, {})); var dd = String(d.day || d.date || d.t || ''); return { x: /^\d{4}-\d\d-\d\d/.test(dd) ? dd.slice(5, 10) : dd, s0: c[0], s1: c[1], s2: c[2], s3: c[3], s4: c[4] }; });
    var totalP = groups.reduce(function (a, g) { return a + g.s0 + g.s1 + g.s2 + g.s3 + g.s4; }, 0);
    var trend = '<div class="x-card"><h3>📈 ' + E(T('Alerts over time')) + '<span class="x-r"><span class="x-tag">' + E(TF('{n} alerts in {d} days', { n: fmtN(totalP), d: groups.length })) + '</span></span></h3>' + (groups.length ? areaChart(groups) : empty('📉', T('No alerts in this period.'), '')) + '</div>';
    var parts = [4, 3, 2, 1, 0].map(function (i) { return { l: T(SEV[i][1]), v: ob[i], c: SEVK[i], i: i }; });
    var sevCard = '<div class="x-card"><h3>🎚️ ' + E(T('Open alerts by severity')) + '<span class="x-r"><button class="x-btn ghost sm" data-socgo="soc-alerts">' + E(T('Open queue')) + ' →</button></span></h3>' + (open ? '<div class="cc-ring">' + ring(parts, fmtN(open), T('open'))
      + '<div class="cc-rl">' + parts.map(function (p) { return '<button type="button" data-soct="' + (p.i >= 3 ? 'al:crit' : 'al:open') + '"><span><span class="cc-dot" style="background:' + p.c + '"></span>' + E(p.l) + '</span><b>' + fmtN(p.v) + '</b></button>'; }).join('') + '</div></div>' : empty('✅', T('No open alerts.'), '')) + '</div>';
    var tops = '<div class="cc-g c">' + rankList(T('Top rules'), '📐', m.top_rules, ['rule_name', 'name', 'rule_id', 'id', 'v'], 'rule') + rankList(T('Top log sources'), '🔌', m.top_sources, ['src_id', 'source', 'name', 'v'], 'src_id')
      + rankList(T('Top hosts'), '🖥️', m.top_hosts, ['host', 'name', 'v'], 'host') + rankList(T('Top users'), '👤', m.top_users, ['user', 'name', 'v'], 'user') + '</div>';
    var noisyL = arr(m.noisy_rules);
    var noisyCard = noisyL.length ? '<div class="x-card"><h3>📢 ' + E(T('Noisy rules')) + '<span class="x-r"><span class="x-tag">' + E(T('candidates for tuning')) + '</span></span></h3>' + tbl(H([N('Rule'), N('Alerts'), N('Closed as false positive')]), noisyL.slice(0, 10).map(function (x) {
      return '<tr style="cursor:pointer" data-socrulego="' + E(x.rule_id || x.id || '') + '"><td class="x-small"><b>' + E(x.rule_name || x.name || x.rule_id) + '</b> <span class="x-mono x-muted">' + E(x.rule_id || '') + '</span></td><td class="n">' + E(fmtN(x.n != null ? x.n : x.count)) + '</td><td class="n">' + E(x.fp_rate != null ? Math.round(num(x.fp_rate) * 100) + '%' : '—') + '</td></tr>';
    })) + '</div>' : '';
    var upd = m.generated ? '<div class="x-small x-muted" style="margin-top:4px">' + E(T('Engine figures computed at')) + ' ' + E(fmtTs(m.generated)) + ' · ' + E(T('refreshed automatically')) + '</div>' : '';
    return hd + stale(['metrics']) + statusBar() + kpis + '<div class="cc-g a">' + trend + sevCard + '</div>' + '<div class="cc-g b">' + collectorsCard() + sourcesCard() + responseCard(m, mttd, mttr, sla) + '</div>'
      + tops + mitreCard(m) + noisyCard + lrCard() + upd;
  }

  /* ─────────────────────────── routing ─────────────────────────── */
  var RENDER = { 'soc-dashboard': vDash, 'soc-search': vSearch, 'soc-alerts': vAlerts, 'soc-cases': vCases, 'soc-rules': vRules, 'soc-sources': vSources };
  var LASTV = null;
  var _prev = viewHTML;
  viewHTML = function (v) {
    if (LASTV === 'soc-search' && v !== 'soc-search' && S.live) tailStop();
    LASTV = v;
    if (!VIEWS[v]) return _prev.apply(this, arguments);
    if (!window.ASX || !window.ASXC) return '<div class="card"><div class="muted">' + E(T('The SOC console needs the shared design layer — append this module after as-twin-module.js and as-xcharts-module.js.')) + '</div></div>';
    X = window.ASX; C = window.ASXC; X.css(); C.css(); css();
    (NEEDS[v] || []).forEach(function (k) { load(k); });
    if (v === 'soc-cases' && S.caseId) { load('caseDetail'); load('caseAlerts'); }
    if (v === 'soc-alerts' && S.alertId) load('alertDetail');
    try { return '<div class="x soc">' + RENDER[v]() + '</div>'; }
    catch (e) { console.error('[sentra-soc ' + v + ']', e); return '<div class="x soc">' + pageError({ kind: 'client', message: T('This page hit an error') + ': ' + e.message }) + '</div>'; }
  };

  /* ─────────────────────────── events ─────────────────────────── */
  function val(id) { var el = document.getElementById(id); return el ? el.value : ''; }
  function reloadView() { (NEEDS[cur()] || []).forEach(function (k) { delete ERR[k]; load(k, true); }); if (cur() === 'soc-cases' && S.caseId) { load('caseDetail', true); load('caseAlerts', true); } if (cur() === 'soc-alerts' && S.alertId) load('alertDetail', true); }
  function afterAlertWrite() { load('alerts', true); if (S.alertId) load('alertDetail', true); load('openCases', true); }
  function bulk(action, extra) {
    var ids = Object.keys(S.sel); if (!ids.length) return;
    var body = { ids: ids, action: action }; for (var k in extra) body[k] = extra[k];
    act('POST', '/alerts/bulk', body, N('Done'), function () { S.sel = {}; afterAlertWrite(); }, 'bulk');
  }
  function createCaseFrom(ids) {
    var al = ids.map(findAlert).filter(Boolean).sort(function (a, b) { return sevIdx(b.severity) - sevIdx(a.severity); }), top = al[0] || {};
    var title = (top.rule_name || top.rule_id || T('Investigation')) + (al.length > 1 ? ' (+' + (al.length - 1) + ')' : '') + (groupTxt(top.group) ? ' — ' + groupTxt(top.group) : '');
    act('POST', '/cases', { title: title.slice(0, 200), severity: sevIdx(top.severity), alert_ids: ids }, N('Case created'), function (j) {
      var c = j && (j.case || j); S.sel = {}; afterAlertWrite(); load('cases', true);
      if (c && c.id) { S.alertId = null; openCase(c.id); go('soc-cases'); }
    }, ids.length > 1 ? 'bulk' : 'al');
  }
  function addToCase(caseId, ids) {
    if (!caseId) { toast(T('Choose a case first.')); return; }
    act('POST', '/cases/' + encodeURIComponent(caseId) + '/alerts', { alert_ids: ids }, N('Added to the case'), function () { S.sel = {}; afterAlertWrite(); }, ids.length > 1 ? 'bulk' : 'al');
  }
  function caseAct(path, body, msg, after) { var id = S.caseId; return act('POST', '/cases/' + encodeURIComponent(id) + path, body, msg, function (j) { if (after) after(j); load('caseDetail', true); load('cases', true); }, 'case'); }

  if (!window._asSocWired) {
    window._asSocWired = true;
    document.addEventListener('click', function (ev) {
      if (!VIEWS[cur()] || !ev.target.closest) return;
      var t = ev.target, b;
      if ((b = t.closest('[data-socgo]'))) { ev.preventDefault(); go(b.getAttribute('data-socgo')); return; }
      if ((b = t.closest('[data-socex]'))) { S.q = b.getAttribute('data-socex'); S.help = false; rerender(true); var q = document.getElementById('soc-q'); if (q) q.focus(); return; }
      if ((b = t.closest('[data-socadd],[data-socnot]'))) {
        ev.stopPropagation(); var neg = b.hasAttribute('data-socnot'), p = (b.getAttribute(neg ? 'data-socnot' : 'data-socadd') || '').split('|'), r = VIS[+p[0]];
        if (r) addTerm(p[1], getF(r, p[1]), neg); return;
      }
      if ((b = t.closest('[data-soctop]'))) { var tv = arr(S.top, 'values')[+b.getAttribute('data-soctop')]; if (tv) addTerm(S.topField, tv.v, false); return; }
      if ((b = t.closest('[data-sochz]'))) {
        var hb = S._hb, i = +b.getAttribute('data-sochz'); if (!hb || !hb.b[i]) return;
        S.zoom.push({ range: S.range, from: S.from, to: S.to }); S.range = 'custom'; S.from = hb.b[i].t; S.to = hb.b[i].t + hb.bw; DR.from = localInput(S.from); DR.to = localInput(S.to); runSearch(); return;
      }
      if ((b = t.closest('[data-socrange]'))) { var rg = b.getAttribute('data-socrange'); if (rg === 'custom') { var sp0 = span(); S.from = sp0[0]; S.to = sp0[1]; DR.from = localInput(S.from); DR.to = localInput(S.to); S.range = 'custom'; rerender(true); return; } S.range = rg; S.zoom = []; if (S.searched) runSearch(); else rerender(true); return; }
      if ((b = t.closest('[data-soccol]'))) { var cn = b.getAttribute('data-soccol'), cs = cols(), ix = cs.indexOf(cn); if (ix >= 0) { if (cs.length > 1) cs.splice(ix, 1); } else cs.push(cn); lsSet('cols', cs); rerender(true); return; }
      if ((b = t.closest('[data-socsaved]'))) { var s = saved()[+b.getAttribute('data-socsaved')]; if (s) { S.q = s.q; S.range = RANGES.some(function (x) { return x[0] === s.range; }) ? s.range : '1h'; S.zoom = []; if (Array.isArray(s.cols) && s.cols.length) { S.cols = s.cols.slice(); lsSet('cols', S.cols); } runSearch(); } return; }
      if ((b = t.closest('[data-socsaveddel]'))) { var sv = saved(), si = +b.getAttribute('data-socsaveddel'); if (sv[si] && confirm(T('Remove this bookmark?'))) { sv.splice(si, 1); lsSet('saved', sv); rerender(true); } return; }
      if ((b = t.closest('[data-socrow]'))) { if (t.closest('.soc-val,button,a,input,select')) return; var ri = +b.getAttribute('data-socrow'), rr = VIS[ri], key = rr && rr.id ? rr.id : 'i' + ri; S.exp[key] = !S.exp[key]; rerender(true); return; }
      if ((b = t.closest('[data-socalertgo]'))) { var aid = b.getAttribute('data-socalertgo'); go('soc-alerts'); openAlert(aid); return; }
      if ((b = t.closest('[data-socsel],[data-socselall]'))) return;   // handled on change
      if ((b = t.closest('[data-soccase]'))) { ev.stopPropagation(); var cid = b.getAttribute('data-soccase'); S.alertId = null; S.caseNew = false; openCase(cid); if (cur() !== 'soc-cases') go('soc-cases'); else rerender(true); return; }
      if ((b = t.closest('[data-socalert]'))) { if (t.closest('input,button,a,select')) return; openAlert(b.getAttribute('data-socalert')); return; }
      if ((b = t.closest('[data-socrulego]'))) { var rid = b.getAttribute('data-socrulego'); S.alertId = null; if (rid) openRule(rid); go('soc-rules'); return; }
      if ((b = t.closest('[data-socruleon]'))) {
        ev.stopPropagation(); var rid2 = b.getAttribute('data-socruleon'), on = b.getAttribute('data-on') === '1';
        act('POST', '/rules/' + encodeURIComponent(rid2) + '/enable', { enabled: on }, on ? N('Rule turned on') : N('Rule turned off'), function () { load('rules', true); }, 'r' + rid2); return;
      }
      if ((b = t.closest('[data-socrule]'))) { openRule(b.getAttribute('data-socrule')); rerender(true); return; }
      if ((b = t.closest('[data-soccst]'))) { var ns = b.getAttribute('data-soccst'); caseAct('/status', { status: ns }, N('Case status updated')); return; }
      if ((b = t.closest('[data-soct]'))) { soct(b.getAttribute('data-soct')); return; }
      if ((b = t.closest('[data-socsf]'))) { S.sf = b.getAttribute('data-socsf'); rerender(true); return; }
      if ((b = t.closest('[data-socsrcq]'))) { S.q = 'src_id:' + qv(b.getAttribute('data-socsrcq')); S.range = '1h'; S.zoom = []; go('soc-search'); runSearch(); return; }
      if ((b = t.closest('[data-socpiv]'))) {
        var pv = PIV[+b.getAttribute('data-socpiv')]; if (!pv) return;
        if (pv.kind === 'rule') { S.af = { status: 'all', sev: '0', rule: pv.v, who: 'any', range: '7d' }; load('alerts', true); go('soc-alerts'); return; }
        if (!fieldOk(pv.kind)) return; S.q = pv.kind + ':' + qv(pv.v); S.range = '24h'; S.zoom = []; go('soc-search'); runSearch(); return;
      }
      if (!(b = t.closest('[data-soc]'))) return;
      var x = b.getAttribute('data-soc'); ev.preventDefault();
      switch (x) {
        case 'retry': case 'refresh': reloadView(); rerender(true); return;
        case 'help': S.help = !S.help; rerender(true); return;
        case 'search': S.q = val('soc-q'); DR.q = S.q; runSearch(); return;
        case 'setrange': {
          var f = new Date(val('soc-from')).getTime(), to = new Date(val('soc-to')).getTime();
          if (isNaN(f) || isNaN(to) || f >= to) { toast(T('Choose a start time before the end time.')); return; }
          S.zoom.push({ range: S.range, from: S.from, to: S.to }); S.range = 'custom'; S.from = f; S.to = to; DR.from = val('soc-from'); DR.to = val('soc-to'); runSearch(); return;
        }
        case 'zoomout': { var z = S.zoom.pop(); if (z) { S.range = z.range; S.from = z.from; S.to = z.to; if (z.from) { DR.from = localInput(z.from); DR.to = localInput(z.to); } } else { S.range = '24h'; } runSearch(); return; }
        case 'cols': S.colsOpen = !S.colsOpen; rerender(true); return;
        case 'colsdef': S.cols = DEFCOLS.slice(); lsSet('cols', S.cols); rerender(true); return;
        case 'tail': if (S.live) { tailStop(); rerender(true); } else { S.q = val('soc-q') || S.q; tailStart(); rerender(true); } return;
        case 'csv': exportCsv(); return;
        case 'bookmark': {
          var nm = prompt(T('Name this search:'), (S.q || '').slice(0, 40)); if (nm == null) return; nm = nm.trim().slice(0, 60); if (!nm) return;
          var list = saved(); list.unshift({ name: nm, q: S.q || '', range: S.range === 'custom' ? '24h' : S.range, cols: cols().slice(), at: Date.now() }); if (list.length > 30) list.length = 30; lsSet('saved', list); toast(T('Search bookmarked')); rerender(true); return;
        }
        /* alerts */
        case 'closedrawer': S.alertId = null; DR.aassign = null; DR.anote = ''; DR.alnote = ''; rerender(true); return;
        case 'selnone': S.sel = {}; rerender(true); return;
        case 'bulkack': bulk('ack', {}); return;
        case 'bulkassign': { var who = (val('soc-bassign') || '').trim(); if (!who) { toast(T('Type a user name to assign to.')); return; } bulk('assign', { assignee: who }); return; }
        case 'bulkclose': { var rs = val('soc-breason'); DR.breason = rs; if (!confirm(TF('Close {n} alerts as "{r}"?', { n: Object.keys(S.sel).length, r: T(REASONS.filter(function (q) { return q[0] === rs; })[0][1]) }))) return; bulk('close', { reason: rs, note: (val('soc-bnote') || '').trim() }); DR.bnote = ''; return; }
        case 'bulkcase': createCaseFrom(Object.keys(S.sel)); return;
        case 'bulkaddcase': addToCase(val('soc-bcase'), Object.keys(S.sel)); return;
        case 'ack': act('POST', '/alerts/' + encodeURIComponent(S.alertId) + '/ack', {}, N('Alert acknowledged'), afterAlertWrite, 'al'); return;
        case 'assign': { var w2 = (val('soc-aassign') || '').trim(); if (!w2) { toast(T('Type a user name to assign to.')); return; } act('POST', '/alerts/' + encodeURIComponent(S.alertId) + '/assign', { assignee: w2 }, N('Alert assigned'), function () { DR.aassign = null; afterAlertWrite(); }, 'al'); return; }
        case 'closealert': { var r2 = val('soc-areason'); DR.areason = r2; act('POST', '/alerts/' + encodeURIComponent(S.alertId) + '/close', { reason: r2, note: (val('soc-anote') || '').trim() }, N('Alert closed'), function () { DR.anote = ''; afterAlertWrite(); }, 'al'); return; }
        case 'alertnote': { var tx = (val('soc-alnote') || '').trim(); if (!tx) { toast(T('Write the note first.')); return; } act('POST', '/alerts/' + encodeURIComponent(S.alertId) + '/note', { text: tx }, N('Note added'), function () { DR.alnote = ''; afterAlertWrite(); }, 'al'); return; }
        case 'alertcase': createCaseFrom([S.alertId]); return;
        case 'alertaddcase': addToCase(val('soc-acase'), [S.alertId]); return;
        case 'pivot': { var pa = findAlert(S.alertId); if (pa) pivotAlert(pa); return; }
        /* cases */
        case 'casenew': S.caseNew = !S.caseNew; rerender(true); return;
        case 'casecreate': { var ct = (val('soc-ctitle') || '').trim(), sv2 = +val('soc-csev'); DR.csev = sv2; if (!ct) { toast(T('Give the case a title.')); return; }
          act('POST', '/cases', { title: ct.slice(0, 200), severity: sv2, alert_ids: [] }, N('Case created'), function (j) { var c = j && (j.case || j); S.caseNew = false; DR.ctitle = ''; load('cases', true); if (c && c.id) openCase(c.id); }, 'cnew'); return; }
        case 'casestatus': { var st = val('soc-cst'), res = (val('soc-cres') || '').trim(); DR.cst = st; if (st === 'closed' && !res) { toast(T('Write the resolution before closing the case.')); return; } caseAct('/status', st === 'closed' ? { status: st, resolution: res } : { status: st }, N('Case status updated'), function () { DR.cres = ''; DR.cst = ''; }); return; }
        case 'caseowner': { var ow = (val('soc-cowner') || '').trim(); if (!ow) { toast(T('Type the owner\'s user name.')); return; } caseAct('/owner', { owner: ow }, N('Owner assigned'), function () { DR.cowner = null; }); return; }
        case 'casenote': { var cn2 = (val('soc-cnote') || '').trim(); if (!cn2) { toast(T('Write the note first.')); return; } caseAct('/notes', { text: cn2 }, N('Note added'), function () { DR.cnote = ''; }); return; }
        case 'caseevidence': { var en = (val('soc-evname') || '').trim(), er = (val('soc-evref') || '').trim(); if (!en || !er) { toast(T('Give the evidence a name and a reference.')); return; } caseAct('/evidence', { name: en, ref: er }, N('Evidence added'), function () { DR.evname = ''; DR.evref = ''; }); return; }
        /* rules */
        case 'rulenew': S.ruleId = null; S.ruleNew = true; S.ruleMsg = null; S.test = null; S.testErr = null; DR.rulejson = JSON.stringify(NEWRULE, null, 2); rerender(true); return;
        case 'ruleclose': S.ruleId = null; S.ruleNew = false; S.ruleMsg = null; S.test = null; S.testErr = null; rerender(true); return;
        case 'ruleformat': { var vf = validateRule(val('soc-rulejson')); if (vf.rule) { DR.rulejson = JSON.stringify(vf.rule, null, 2); rerender(true); } else toast(T('Fix the JSON syntax first.')); return; }
        case 'rulesave': {
          DR.rulejson = val('soc-rulejson'); var vs = validateRule(DR.rulejson); if (vs.errors.length) { toast(T('Fix the problems listed next to the editor first.')); rerender(true); return; }
          S.ruleMsg = null;
          req('POST', '/rules', { rule: vs.rule }).then(function (j) { S.ruleMsg = { ok: true, text: T('Rule saved.') }; S.ruleId = vs.rule.id; S.ruleNew = false; S.ruleDirty = false; load('rules', true); toast(T('Rule saved.')); },
            function (e) { S.ruleMsg = { ok: false, text: T('The engine did not save the rule') + ': ' + errText(e), list: e.detail && Array.isArray(e.detail.errors) ? e.detail.errors : null }; })
            .then(function () { delete S.busy.rsave; rerender(true); });
          S.busy.rsave = 1; rerender(true); return;
        }
        case 'ruletest': {
          DR.rulejson = val('soc-rulejson'); var vt = validateRule(DR.rulejson); if (!vt.rule || vt.errors.length) { toast(T('Fix the problems listed next to the editor first.')); rerender(true); return; }
          var now = Date.now(), n2 = SEQ.rtest = (SEQ.rtest || 0) + 1; S.test = null; S.testErr = null; S.busy.rtest = 1; rerender(true);
          req('POST', '/rules/test', { rule: vt.rule, from: iso(now - rangeMs(S.testRange)), to: iso(now) }).then(function (j) { if (SEQ.rtest === n2) S.test = j; }, function (e) { if (SEQ.rtest === n2) S.testErr = e; })
            .then(function () { if (SEQ.rtest === n2) { delete S.busy.rtest; rerender(true); } }); return;
        }
        case 'sigmaconv': case 'sigmaimport': {
          var y = val('soc-sigma'); DR.sigma = y; if (!y.trim()) { toast(T('Paste a Sigma rule first.')); return; }
          var dry = x === 'sigmaconv'; S.busy.sigma = 1; S.sigmaRes = null; rerender(true);
          req('POST', '/rules/sigma', { yaml: y, dry_run: dry }).then(function (j) {
            var rule = j && (j.rule || j); S.sigmaRes = { warnings: arr(j && j.warnings), saved: !dry };
            if (rule && typeof rule === 'object' && rule.id) { DR.rulejson = JSON.stringify(editableRule(rule), null, 2); S.ruleDirty = true; if (dry) { S.ruleNew = true; S.ruleId = null; } else { S.ruleId = rule.id; S.ruleNew = false; load('rules', true); } S.test = null; S.testErr = null; }
          }, function (e) { S.sigmaRes = { err: e }; }).then(function () { delete S.busy.sigma; rerender(true); }); return;
        }
      }
    });
    document.addEventListener('change', function (ev) {
      var el = ev.target; if (!VIEWS[cur()] || !el || !el.getAttribute) return;
      var k;
      if ((k = el.getAttribute('data-socaf'))) { S.af[k] = el.value; S.sel = {}; load('alerts', true); rerender(true); return; }
      if (el.hasAttribute('data-soccf')) { S.cf.status = el.value; load('cases', true); rerender(true); return; }
      if (el.hasAttribute('data-socrf')) { S.rf = el.value; rerender(true); return; }
      if (el.hasAttribute('data-soctestr')) { S.testRange = el.value; return; }
      if (el.getAttribute('data-socsel') === 'topfield') { S.topField = el.value; S.top = null; loadTop(); return; }
      if (el.hasAttribute('data-socselall')) { alertList().slice(0, 500).forEach(function (a) { if (el.checked) S.sel[a.id] = 1; else delete S.sel[a.id]; }); rerender(true); return; }
      if (el.hasAttribute('data-socsel')) { var id = el.getAttribute('data-socsel'); if (el.checked) S.sel[id] = 1; else delete S.sel[id]; rerender(true); return; }
      if (el.hasAttribute('data-soctask')) { var tid = el.getAttribute('data-soctask'); caseAct('/tasks/' + encodeURIComponent(tid), { done: !!el.checked }, el.checked ? N('Task done') : N('Task reopened')); return; }
      if (el.id === 'soc-breason') DR.breason = el.value; else if (el.id === 'soc-areason') DR.areason = el.value; else if (el.id === 'soc-cst') DR.cst = el.value; else if (el.id === 'soc-csev') DR.csev = el.value;
    });
    var VT = 0;
    document.addEventListener('input', function (ev) {
      var el = ev.target; if (!VIEWS[cur()] || !el || !el.getAttribute) return;
      var k = el.getAttribute('data-socin'); if (!k) return;
      DR[k] = el.value;
      if (k === 'q') S.q = el.value;
      else if (k === 'rq') { S.rq = el.value; rerender(true); }
      else if (k === 'rulejson') { S.ruleDirty = true; clearTimeout(VT); VT = setTimeout(function () { var box = document.getElementById('soc-ruleval'); if (box) box.innerHTML = valHTML(validateRule(DR.rulejson)); }, 250); }
    });
    document.addEventListener('keydown', function (ev) {
      if (!VIEWS[cur()]) return;
      var el = ev.target;
      if ((ev.key === 'Enter' || ev.key === ' ') && el && el.getAttribute && el.getAttribute('data-soct')) { ev.preventDefault(); soct(el.getAttribute('data-soct')); return; }
      if (ev.key === 'Enter' && el && el.id === 'soc-q') { ev.preventDefault(); S.q = el.value; runSearch(); return; }
      if (ev.key === 'Enter' && el && el.getAttribute && el.getAttribute('data-soccase') && el.classList.contains('x-case')) { el.click(); return; }
      if (ev.key === 'Escape') { if (S.alertId) { S.alertId = null; rerender(true); } else if (S.help) { S.help = false; rerender(true); } }
      if (ev.key === 'Tab' && el && el.id === 'soc-rulejson' && !ev.shiftKey) { ev.preventDefault(); var s0 = el.selectionStart; el.value = el.value.slice(0, s0) + '  ' + el.value.slice(el.selectionEnd); el.selectionStart = el.selectionEnd = s0 + 2; DR.rulejson = el.value; }
    });
    document.addEventListener('focusout', function () { if (PENDING) setTimeout(function () { if (PENDING && !typing()) rerender(); }, 200); });

    /* polling — each dataset on its own interval, only for the page on screen, never while the tab is hidden */
    setInterval(function () {
      var v = cur(); if (!VIEWS[v] || document.hidden) return;
      var keys = (NEEDS[v] || []).slice();
      if (v === 'soc-cases' && S.caseId) keys.push('caseDetail', 'caseAlerts');
      if (v === 'soc-alerts' && S.alertId) keys.push('alertDetail');
      if (v === 'soc-dashboard' && D.dashAlerts) keys.push('dashAlerts');
      var now = Date.now();
      if (PENDING && !typing()) rerender();   // a redraw deferred while the user was typing
      if (v === 'soc-search' && S.lsUser !== undefined && S.lsUser !== me()) rerender();   // signed-in user became known → their bookmarks / columns
      keys.forEach(function (k) { if (!LOAD[k] && now - (AT[k] || 0) >= (POLL[k] || 60) * 1000) load(k, true); });
      if (v === 'soc-cases' && S.caseId && now - (window._asSocSla || 0) >= 30000) { window._asSocSla = now; rerender(); }   // SLA countdowns
    }, 5000);
  }

  /* the portal boots before modules are appended — draw now if the page was opened on a SOC view */
  if (VIEWS[cur()]) setTimeout(function () { rerender(true); }, 0);
})();
/* ===================== /ZS-SOC ===================== */
