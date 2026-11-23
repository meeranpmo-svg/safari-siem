// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { entitiesOf } = require('../xdr/xdr');
/*
 * Threat intelligence for the Threat Intelligence page - on top of detect/intel.js (the lists) and detect/intel-feeds.js
 * (the feeds); nothing here changes them.
 *
 *   createIntelView({ state, alerts, intel?, search?, xdr?, now? })
 *     overview()        lists and indicator counts, hits per list since load, and SIGHTINGS: every alert in 30 days whose
 *                       IPs / domains / URL hosts / hashes are on a threat list - per indicator: lists, alerts, open alerts,
 *                       hosts and users involved, first / last seen; per day; per list
 *     retro({hours})    a retro-hunt of recent TRAFFIC (not only alerts): the 200 most-contacted destination IPs and the most
 *                       queried domains / file hashes in the event store, each checked against the lists - an indicator
 *                       added to a feed today is found in yesterday's traffic even if no rule alerted
 * Reference lists (allow-*, internal-*) are context, never a threat: they are reported apart.
 */
const DAY = 86400000, H = 3600000;
const isRef = (n) => /^(allow|internal)-/.test(n);
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1$|f[cd][0-9a-f]{2}:)/i;
const httpErr = (code, msg) => Object.assign(new Error(msg), { code, status: code });

function indicatorsOf(a) {
  const f = Object.assign({}, a.fields || {}, a.group || {}), out = new Set();
  for (const k of ['src_ip', 'dst_ip', 'remote_ip', 'client_ip', 'domain', 'dns_query', 'url_host', 'sender_domain', 'hash', 'sha256', 'md5', 'file_hash']) {
    const v = String(f[k] || '').trim().toLowerCase(); if (v && v !== '-' && !PRIVATE.test(v)) out.add(v.slice(0, 300));
  }
  const u = String(f.url || '').trim(); const m = /^[a-z]+:\/\/([^/:?#]+)/i.exec(u); if (m) out.add(m[1].toLowerCase());
  return [...out];
}

function createIntelView(deps = {}) {
  const { alerts } = deps;
  const now = deps.now || Date.now;
  const allAlerts = () => (alerts ? (typeof alerts.all === 'function' ? alerts.all() : []) : []);
  const ints = () => new Set(((deps.xdr && deps.xdr.settings && deps.xdr.settings().internal_domains) || []).map((d) => String(d).toLowerCase()));

  function overview() {
    const intel = deps.intel;
    if (!intel) return { enabled: false, note: 'threat intelligence is not loaded on this SIEM (detect.intel_dir)' };
    const t = now(), st = intel.stats(), lists = intel.lists();
    const sight = new Map(), I = ints();
    const days = 30, off = 3 * H, d0 = Math.floor((t + off) / DAY) - days + 1;
    const series = Array.from({ length: days }, (_, i) => ({ day: new Date((d0 + i) * DAY).toISOString().slice(0, 10), sightings: 0 }));
    const byList = new Map();
    for (const a of allAlerts()) {
      if ((a.ts_last || a.created || 0) < t - days * DAY) continue;
      let hit = false;
      for (const v of indicatorsOf(a)) {
        const L = (intel.lookup(v) || []).filter((n) => !isRef(n)); if (!L.length) continue;
        hit = true;
        const s = sight.get(v) || { indicator: v, lists: new Set(), alerts: 0, open: 0, ids: [], entities: new Set(), first: Infinity, last: 0 };
        L.forEach((n) => s.lists.add(n)); s.alerts++; if (!String(a.status).startsWith('closed-')) s.open++;
        if (s.ids.length < 10) s.ids.push(a.id);
        for (const e of entitiesOf(a, I)) s.entities.add(e.replace(/^xip:/, 'ip:'));
        s.first = Math.min(s.first, a.ts_first || a.created || t); s.last = Math.max(s.last, a.ts_last || a.created || 0);
        sight.set(v, s);
        for (const n of L) byList.set(n, (byList.get(n) || 0) + 1);
      }
      if (hit) { const k = Math.floor(((a.ts_last || a.created || 0) + off) / DAY) - d0; if (k >= 0 && k < days) series[k].sightings++; }
    }
    const items = [...sight.values()].map((s) => ({ indicator: s.indicator, lists: [...s.lists], alerts: s.alerts, open: s.open, alert_ids: s.ids,
      entities: [...s.entities].filter((e) => !e.endsWith(s.indicator)).slice(0, 12), first: s.first === Infinity ? null : s.first, last: s.last }))
      .sort((a, b) => b.open - a.open || b.last - a.last);
    return { enabled: true, generated_at: t, loaded_at: st.loaded_at, totals: { ip: st.ip, domain: st.domain, hash: st.hash, lists: st.lists, invalid_lines: st.invalid_lines },
      lists: lists.map((l) => Object.assign({}, l, { reference: isRef(l.name), hits: (st.hits || {})[l.name] || 0, sightings: byList.get(l.name) || 0 })).sort((a, b) => b.sightings - a.sightings || (b.ip + b.domain + b.hash) - (a.ip + a.domain + a.hash)),
      sightings: items.slice(0, 200), sightings_total: items.length, open_sightings: items.filter((x) => x.open).length, series,
      note: 'A sighting is an alert in the last 30 days carrying an indicator that is on a threat list. Reference lists (allow-*, internal-*) are context, not threats.' };
  }

  async function retro(o = {}) {
    if (!deps.intel) throw httpErr(503, 'threat intelligence is not loaded on this SIEM');
    if (!deps.search) throw httpErr(503, 'the event store is not available on this SIEM');
    const hours = Math.max(1, Math.min(168, Number(o.hours) || 24)), to = now(), from = to - hours * H;
    const out = [], checked = {};
    for (const [field, limit] of [['dst_ip', 100], ['dns_query', 100], ['domain', 50], ['hash', 50]]) {
      let vals = [];
      try { vals = (await deps.search.top({ q: '', from, to, field, limit })).values || []; }
      catch (e) { checked[field] = { error: String(e.message).slice(0, 160) }; continue; }
      checked[field] = { values: vals.length };
      for (const v of vals) {
        const s = String(v.v || '').trim().toLowerCase(); if (!s || PRIVATE.test(s)) continue;
        const L = (deps.intel.lookup(s) || []).filter((n) => !isRef(n));
        if (L.length) out.push({ field, indicator: s, events: v.n, lists: L, query: field + ':"' + s + '"' });
      }
    }
    return { hours, checked, hits: out.sort((a, b) => b.events - a.events), note: 'The most frequent destinations, DNS names, domains and file hashes in the window, checked against the threat lists. A rare indicator may be outside the top values - search for it directly.' };
  }

  return { overview, retro };
}

module.exports = { createIntelView, indicatorsOf };
