// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Per-source live statistics (pipeline stage): last seen, EPS over the last minute / hour, events since start,
// parse error rate. Feeds GET /api/soc/sources together with siem.stats_minute (events today).
function createSourceTracker({ now = Date.now } = {}) {
  const src = new Map(); // src_id → state

  function stage(ev) {
    const t = now();
    const id = ev.src_id || 'unknown';
    let s = src.get(id);
    if (!s) {
      if (src.size >= 10000) return;
      s = { src_id: id, src_type: ev.src_type, collector: ev.collector, first_seen: t, last_seen: 0, events: 0, parse_errors: 0, mins: new Array(60).fill(0), errs: new Array(60).fill(0), minKeys: new Array(60).fill(-1), hosts: new Set() };
      src.set(id, s);
    }
    s.last_seen = t;
    s.events++;
    s.src_type = ev.src_type;
    s.collector = ev.collector;
    const perr = ev._perr || ev.action === 'unparsed';
    if (perr) s.parse_errors++;
    const m = Math.floor(t / 60000);
    const slot = m % 60;
    if (s.minKeys[slot] !== m) { s.minKeys[slot] = m; s.mins[slot] = 0; s.errs[slot] = 0; }
    s.mins[slot]++;
    if (perr) s.errs[slot]++;
    if (s.hosts.size < 100 && ev.host) s.hosts.add(ev.host);
  }

  function summary() {
    const t = now();
    const m = Math.floor(t / 60000);
    const out = [];
    for (const s of src.values()) {
      let lastMin = 0;
      let hour = 0;
      let hourErr = 0;
      for (let i = 0; i < 60; i++) {
        const k = s.minKeys[i];
        if (k > m - 60 && k < m) { hour += s.mins[i]; hourErr += s.errs[i]; if (k === m - 1) lastMin = s.mins[i]; }
        if (k === m) { hour += s.mins[i]; hourErr += s.errs[i]; }
      }
      out.push({
        src_id: s.src_id, src_type: s.src_type, collector: s.collector, first_seen: s.first_seen, last_seen: s.last_seen,
        events_since_start: s.events, parse_errors_since_start: s.parse_errors,
        eps_1m: Math.round((lastMin / 60) * 100) / 100, eps_1h: Math.round((hour / 3600) * 100) / 100,
        parse_error_rate_1h: hour ? Math.round((hourErr / hour) * 1000) / 1000 : 0,
        hosts: [...s.hosts].slice(0, 20),
      });
    }
    return out;
  }

  return { stage, summary };
}

module.exports = { createSourceTracker };
