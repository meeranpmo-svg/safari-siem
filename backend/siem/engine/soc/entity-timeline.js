// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Threat Hunting - entity timeline: one user, host or IP address, and every record the platform holds about it merged into one
 * timeline, newest first. Read only; each source is read on its own, so one that is missing or failing is named and the rest still
 * answer (never shown as "nothing happened").
 *   events     the SIEM's events naming the entity (user / target_user / host for a name, src_ip / dst_ip / host_ip for an address),
 *              the newest `limit` of them, with the total in the window and the busiest source types
 *   alerts     SIEM alerts whose host, grouping values or fields name the entity (exact, case-insensitive; a host with its domain
 *              dropped - never a similar name), with the cases they belong to
 *   UEBA       the behaviour entity of that name: risk score and its open findings
 *   intel      threat-intelligence lists the value is on (an IP or domain)
 *   network    the network device of that name or address: its state in the latest poll; and the changes carried out on it
 *              (Change Log & NOC <-> SOC correlation)
 * Raw events and named people are personal data (PDPL): analysts and above, every look-up audited.
 */
const net = require('node:net');
const H = 3600000;
const low = (s) => String(s == null ? '' : s).trim().toLowerCase();
const hk = (s) => low(s).split('.')[0];
const SEVW = ['info', 'low', 'medium', 'high', 'critical'];

function kindOf(v) { if (net.isIP(v)) return 'ip'; if (/[@\\]/.test(v)) return 'user'; return 'name'; }

function createEntityTimeline(deps) {
  const now = deps.now || Date.now;
  async function timeline({ entity, hours = 168, limit = 200 }) {
    const t = now(), from = t - hours * H, kind = kindOf(entity), key = low(entity), items = [], sources = {};
    const q = kind === 'ip' ? 'ip:' + entity : 'user:"' + entity + '" OR target_user:"' + entity + '" OR host:"' + entity + '"' + (kind === 'name' && !entity.includes('.') ? ' OR host:' + entity + '.*' : '');
    // exact, or the record's host name with its domain dropped (core-syn.as.local = core-syn); the looked-up name is never cut,
    // so dave.syn is not dave.synx
    const same = (v) => v != null && v !== '' && (low(v) === key || (kind !== 'ip' && hk(v) === key));
    const step = async (name, fn) => { try { const r = await fn(); sources[name] = r === undefined ? 'ok' : r; } catch (e) { sources[name] = 'failed: ' + String(e.message || e).slice(0, 160); } };
    let events = { total: 0, shown: 0, top_sources: [] };
    await step('events', async () => {
      if (!deps.search) return 'not available';
      const [r, h, top] = await Promise.all([deps.search.search({ q, from, to: t, limit, order: 'desc' }), deps.search.histogram({ q, from, to: t, buckets: 48 }), deps.search.top({ q, from, to: t, field: 'src_type', limit: 6 })]);
      const total = h.buckets.reduce((s, b) => s + b.n, 0);
      events = { total, shown: r.rows.length, top_sources: top.values, histogram: h.buckets, step_ms: h.step_ms };
      for (const e of r.rows) items.push({ t: typeof e.ts === 'number' ? e.ts : Date.parse(e.ts), source: 'event', type: e.src_type || '', severity: e.severity || 0,
        title: [e.action, e.outcome].filter(Boolean).join(' ') || e.category || 'event', detail: String(e.message || '').slice(0, 300), host: e.host || '', user: e.user || '', src_ip: e.src_ip || '', dst_ip: e.dst_ip || '', ref: e.id });
      return 'ok';
    });
    const caseIds = new Set();
    await step('alerts', () => {
      if (!deps.alerts || typeof deps.alerts.all !== 'function') return 'not available';
      const hit = (a) => [a.host, ...(a.group ? Object.values(a.group) : []), ...(a.fields ? Object.values(a.fields) : [])].some(same);
      for (const a of deps.alerts.all((a) => (a.ts_last || a.created) >= from && hit(a))) {
        if (a.case_id) caseIds.add(a.case_id);
        items.push({ t: a.ts_first || a.created, source: 'alert', type: a.rule_type || 'rule', severity: a.severity || 0, title: a.rule_name || a.rule_id, detail: String(a.summary || '').slice(0, 300), status: a.status, ref: a.id, case_id: a.case_id || '', count: a.count || 1 });
      }
    });
    await step('cases', () => {
      if (!deps.cases || typeof deps.cases.get !== 'function') return 'not available';
      for (const id of caseIds) { const c = deps.cases.get(id); if (c) items.push({ t: c.created || c.opened_at || t, source: 'case', severity: c.severity != null ? c.severity : 2, title: c.title || id, detail: 'status ' + (c.status || '') + (c.assignee ? ' · ' + c.assignee : ''), status: c.status, ref: c.id }); }
    });
    let ueba = null;
    await step('ueba', () => {
      if (!deps.ueba || typeof deps.ueba.entities !== 'function') return 'not available';
      const hits = (deps.ueba.entities({ q: entity, limit: 20 }).items || []).filter((e) => same(e.name));
      if (!hits.length) return 'no behaviour profile';
      const e = deps.ueba.entity(hits[0].id) || hits[0];
      const rk = (e && e.risk) || {}, tsOf = (f) => f.ts_last || f.last_seen || f.ts_first || f.created || 0;
      ueba = { id: hits[0].id, name: hits[0].name, type: hits[0].type, risk: rk.score != null ? rk.score : null, tier: rk.tier || null, peer_group: hits[0].peer_group || '' };
      for (const f of (e.findings || []).filter((f) => tsOf(f) >= from)) items.push({ t: tsOf(f), source: 'ueba', severity: f.severity != null ? f.severity : 2, title: f.detector, detail: String(f.explanation || '').slice(0, 300), status: f.status, ref: f.id });
    });
    let intel = [];
    await step('intel', () => {
      if (!deps.intel || typeof deps.intel.lookup !== 'function') return 'not available';
      if (kind === 'user') return 'not applicable to a user';
      intel = (deps.intel.lookup(entity) || []).slice(0, 20);
      return intel.length ? 'on ' + intel.length + ' list(s)' : 'not on any list';
    });
    let device = null;
    await step('network', () => {
      const N = deps.netopsInstance; if (!N || !N.inventory) return 'not available';
      const d = N.inventory.list().find((x) => same(x.name) || same(x.id) || x.ip === entity);
      if (!d) return 'not a network device';
      const s = N.poller && N.poller.snapshot(d.id);
      device = { id: d.id, name: d.name, ip: d.ip, role: d.role, site: d.site || '', state: !s ? 'not polled' : s.ok === false || (s.reach && s.reach.received === 0 && (s.sources || []).length <= 1) ? 'down' : 'up' };
      if (N.changelog) for (const c of N.changelog.view({ days: Math.max(1, Math.ceil(hours / 24)), window_h: 24 }, 'analyst').changes.filter((c) => same(c.target) || c.ip === entity))
        items.push({ t: c.at, source: 'change', severity: c.risk === 'high' ? 3 : c.risk === 'medium' ? 2 : 1, title: c.what, detail: c.source + (c.by ? ' · ' + c.by : '') + (c.soc.alerts ? ' · ' + c.soc.alerts + ' alert(s) after' : ''), ref: c.id });
    });
    items.sort((a, b) => b.t - a.t);
    const by = {}; for (const i of items) by[i.source] = (by[i.source] || 0) + 1;
    const worst = items.reduce((m, i) => Math.max(m, i.severity || 0), 0);
    return { entity, kind, hours, from, to: t, query: q, sources, counts: by, events, ueba, intel, device, worst: SEVW[worst] || 'info', items: items.slice(0, 600),
      note: items.length > 600 ? 'the newest 600 of ' + items.length + ' records' : null };
  }
  return { timeline, kindOf };
}

module.exports = { createEntityTimeline, kindOf };
