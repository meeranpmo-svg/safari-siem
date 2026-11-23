// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Infrastructure Automation AI (infra-ai.html) against the REAL ITAM engines (engine/infra-intel.js) with a SYNTHETIC Infrastructure
// Automation link: health ring and KPIs, ranked actions, risk cards with their points, capacity forecast, recurring / flapping, noisy
// rules, response times, coverage gaps, a hostile target name stays text, the advisor off until allowed; not connected is said;
// menu entry, installer, portal view.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node infra-ai.test.js
const H = 3600000, D = 86400000;
let LINK = true;
require('./intel-harness')({ file: 'infra-ai.html', view: 'infraai',
  after: async (e) => {
    const now = Date.now(), iso = (t) => new Date(t).toISOString();
    const targets = [{ id: 't1', kind: 'host', name: 'app-syn-01', status: 'ok', enabled: true, last_seen: iso(now - 60000) }, { id: 't2', kind: 'host', name: '<img src=x onerror="window.__xss=1">', status: 'ok', enabled: true, last_seen: iso(now - 6 * H) }, { id: 't3', kind: 'device', name: 'sw-syn-03', status: 'never', enabled: true }];
    const hist = []; for (let h = 72; h >= 0; h -= 6) hist.push({ at: iso(now - h * H), disk_max_pct: 76 + (72 - h) / 24 * 3 });
    const findings = [{ id: 'f0', target_id: 't1', rule: 'disk', severity: 'critical', title: 'Disk almost full', status: 'open', first_seen: iso(now - H) }];
    for (let k = 0; k < 6; k++) findings.push({ id: 'l' + k, target_id: 't1', rule: 'load_high', severity: 'warning', title: 'Load high', status: 'cleared', first_seen: iso(now - k * D - H) });
    const incidents = []; for (let k = 0; k < 6; k++) incidents.push({ id: 'n' + k, target_id: 't1', title: 'Load high', severity: 'warning', status: 'resolved', resolution: 'auto', opened_at: iso(now - k * D - H), resolved_at: iso(now - k * D - H + 300000) });
    e.app.addons.infraSync = { get: async (p) => { if (!LINK) throw Object.assign(new Error('Infrastructure Automation not reachable (ECONNREFUSED)'), { status: 503 });
      if (p === '/summary') return { targets: { by_kind: { device: 1 } }, configs: { devices_with_baseline: 0 }, fingerprints_pending: 0 }; if (p === '/targets') return { targets }; if (p.startsWith('/findings')) return { findings }; if (p.startsWith('/incidents')) return { incidents }; if (p === '/probes') return { probes: [] };
      return { history: p === '/hosts/t1' ? { points: hist } : { points: [] } }; } };
  } },
async (h) => {
  let p = await h.page();
  const hero = await h.text(p, '#zi-hero'); h.ok(/Infrastructure health/.test(hero) && /Full within 14 days/.test(hero) && /Noisy rules/.test(hero), 'ring and KPIs');
  h.ok(/open critical finding/.test(hero), 'the index says its points');
  h.ok(/app-syn-01/.test(await h.text(p, '#sec-actions')), 'ranked actions');
  await h.openCard(p, 'risk', 't1'); const dlg = await h.text(p, '#zi-dlgb'); h.ok(/\+25 1 critical finding/.test(dlg) && /fullest disk reaches/.test(dlg), 'risk points itemised'); await h.closeDlg(p);
  const fc = await h.text(p, '#sec-forecast'); h.ok(/app-syn-01/.test(fc) && /\+3 %/.test(fc) && /not a promise/.test(fc), 'capacity forecast');
  h.ok(/flapping/.test(await h.text(p, '#sec-recurring')), 'flapping found');
  h.ok(/self-clearing/.test(await h.text(p, '#sec-noise')), 'noisy rule');
  h.ok(/MTTA/.test(await h.text(p, '#sec-response')), 'response times');
  const cv = await h.text(p, '#sec-coverage'); h.ok(/never polled/.test(cv) && /no result for 6 h/.test(cv) && /baseline/.test(cv), 'coverage gaps');
  h.ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('sec-coverage').textContent)), 'a hostile target name stays text');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page(); h.ok(/Infrastructure health/.test(await h.text(p, '#zi-hero')), 'a viewer reads');
  LINK = false; h.who('nora.syn', 'operator'); p = await h.page();
  h.ok(await h.wait(p, () => /not reachable/.test(document.body.textContent)), 'Infrastructure Automation unreachable is said');
  h.ok(await p.evaluate(() => !document.querySelector('#sec-risk .zi-it')), 'no figures without a source');
  LINK = true;
});
