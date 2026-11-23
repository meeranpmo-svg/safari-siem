// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-siem.js - the portal's SIEM tiles (Open Offenses, Critical), the SOC console and the CISO / risk pages read
 * /api/wazuh (an older LogRhythm / Wazuh feed). When that feed is not configured, the same view is built from the
 * the organisation SIEM on this server: open alerts (/api/soc/alerts), log sources (/api/soc/onboard/sources) - so the
 * pages show the SIEM's real offenses instead of "SIEM not connected". Open / critical counts are the real numbers of
 * open alerts and open critical alerts (severity 4), not an estimate. Nothing is written. Loaded by zyb-menu.js. */
(function () {
  'use strict';
  if (window.__zybSiem || typeof window.fetch !== 'function') return; window.__zybSiem = true;
  var orig = window.fetch.bind(window), LIVE = null;
  var LEVEL = [3, 3, 6, 10, 13];   // SIEM severity 0-4 -> Wazuh-style level (>=12 critical, 8-11 high, 5-7 medium)
  var TAC = { TA0001: 'Initial Access', TA0002: 'Execution', TA0003: 'Persistence', TA0004: 'Privilege Escalation', TA0005: 'Stealth', TA0112: 'Defense Impairment', TA0006: 'Credential Access', TA0007: 'Discovery', TA0008: 'Lateral Movement', TA0009: 'Collection', TA0010: 'Exfiltration', TA0011: 'Command & Control', TA0040: 'Impact', TA0042: 'Resource Development', TA0043: 'Reconnaissance' };

  function j(u) { return orig(u, { credentials: 'include', cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }); }
  function top(map, n) { return Object.keys(map).map(function (k) { return { key: k, count: map[k] }; }).sort(function (a, b) { return b.count - a.count; }).slice(0, n); }
  function tactic(a) { var t = a.tactic || ''; if (t === 'defense-evasion') t = 'stealth';   /* ATT&CK v20 renamed TA0005 */
    if (TAC[t]) return TAC[t]; if (t) return t.replace(/[-_]/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); }); var m = (a.mitre || [])[0]; return m && TAC[m] ? TAC[m] : ''; }

  function build() {
    return Promise.all([j('/api/soc/alerts?status=open&limit=5000&sort=-ts_last'), j('/api/soc/onboard/sources')]).then(function (r) {
      var al = r[0], src = r[1];
      if (!al || !Array.isArray(al.items)) return null;   // SIEM not reachable from this session
      var items = al.items, lv = {}, tac = {}, rules = {}, hosts = {}, crit = 0, high = 0;
      items.forEach(function (a) {
        var l = LEVEL[Math.max(0, Math.min(4, a.severity | 0))]; lv[l] = (lv[l] || 0) + 1;
        if (a.severity >= 4) crit++; else if (a.severity === 3) high++;
        var t = tactic(a); if (t) tac[t] = (tac[t] || 0) + 1;
        var n = a.rule_name || a.rule_id || 'alert'; rules[n] = (rules[n] || 0) + (a.count || 1);
        var h = a.host || (a.group && (a.group.host || a.group.src_ip || a.group.user)) || a.src_id || ''; if (h) hosts[h] = (hosts[h] || 0) + 1;
      });
      var agents = ((src && src.sources) || []).map(function (s) { return { name: s.label || s.id, ip: s.match_ip || (s.hosts || [])[0] || '', status: s.state === 'receiving' ? 'active' : s.state === 'silent' ? 'disconnected' : 'never_connected', os: { name: s.kind || s.type || '' } }; });
      LIVE = { open: items.length, crit: crit, high: high, at: Date.now() };
      return {
        configured: true, source: 'sentra-siem', updated: new Date().toISOString(),
        wazuh: {
          stats: { total: items.reduce(function (s, a) { return s + (a.count || 1); }, 0), crit: crit, high: high, byLevel: Object.keys(lv).map(function (k) { return { key: +k, count: lv[k] }; }),
            mitreTactics: top(tac, 12), topRules: top(rules, 10), topAgents: top(hosts, 10), compliance: {} },
          agents: agents,
          recentAlerts: items.slice(0, 30).map(function (a) { return { ts: a.ts_last, agent: { name: a.host || a.src_id || '' }, rule: a.rule_name || a.rule_id, level: LEVEL[Math.max(0, Math.min(4, a.severity | 0))], id: a.id }; }),
          vulnerabilities: { total: 0 },
        },
      };
    });
  }

  window.fetch = function (input, init) {
    var u = typeof input === 'string' ? input : input && input.url, m = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
    var path = ''; try { path = new URL(u, location.href).pathname; } catch (e) { /* not a URL */ }
    if (path !== '/api/wazuh' || m !== 'GET') return orig(input, init);
    var json = function (o) { return new Response(JSON.stringify(o), { status: 200, headers: { 'Content-Type': 'application/json' } }); };
    return orig(input, init).then(function (r) {
      var mine = function () { return build().then(function (o) { return o ? json(o) : r; }); };
      if (!r.ok) return mine();
      return r.clone().json().then(function (h) { if (h && h.configured && h.wazuh) { LIVE = null; return r; } return mine(); }).catch(mine);
    }, function () { return build().then(function (o) { if (o) return json(o); throw new Error('SIEM not reachable'); }); });
  };

  /* the portal estimates "open" / "critical" from the top rules; use the SIEM's real counts */
  function patchModel() {
    if (typeof window._wzModel !== 'function' || window._wzModel.__zyb) return;
    var o = window._wzModel;
    window._wzModel = function () { var M = o.apply(this, arguments); if (LIVE && M && M.live) { M.openOff = LIVE.open; M.critOff = LIVE.crit; } return M; };
    window._wzModel.__zyb = true;
  }
  function pull() {
    patchModel();
    try { if (typeof pullWazuh === 'function') pullWazuh().then(function () { try { if (typeof renderKPIs === 'function') renderKPIs(); } catch (e) { /* not on the overview */ } }); } catch (e) { /* portal not ready */ }   // eslint-disable-line no-undef
  }
  /* Home's four tiles (Open Offenses, Monitored Assets, Log Sources, Coverage) are drawn once, when the portal opens -
     before the SIEM feed and the other feeds have answered - so they kept "SIEM not connected" / "No feeds configured"
     while the header showed live figures. Redraw just that tile row (nothing else on the page, so no lost focus or
     scroll) whenever its figures change: a few times while the feeds arrive, then every minute. */
  function refreshHome() {
    try {
      if (typeof currentView === 'undefined' || currentView !== 'home' || typeof _homeView !== 'function') return;   // eslint-disable-line no-undef
      var host = document.querySelector('.zhome .zh-kpis'); if (!host) return;
      var tmp = document.createElement('div'); tmp.innerHTML = _homeView();   // eslint-disable-line no-undef
      var k = tmp.querySelector('.zh-kpis'); if (!k) return;
      var html = LIVE ? k.innerHTML.replace(/LogRhythm SIEM/g, (ZYB_ORG.short + ' SIEM')) : k.innerHTML;   // the figures came from this server's SIEM
      if (html !== host.innerHTML) host.innerHTML = html;
    } catch (e) { /* the portal's home is not ready yet: the next tick tries again */ }
  }
  [1500, 4000, 9000, 20000].forEach(function (ms) { setTimeout(function () { pull(); setTimeout(refreshHome, 600); }, ms); });
  setInterval(function () { if (!document.hidden) { pull(); setTimeout(refreshHome, 600); } }, 60000);
  document.addEventListener('click', function () { setTimeout(refreshHome, 400); });   // back to Home from another page
})();
