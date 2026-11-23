// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Change Log & NOC <-> SOC correlation - every change made to the organisation's systems in one register, and what the NOC and the SOC
 * saw on the same system afterwards. Nothing is changed on a device; the register reads what the platform already records.
 *   sources   change plans that were carried out (applied / validated / executed / failed) from the network (netops_changes), server
 *             (sysadmin_changes), Kaspersky (ksc_changes) and Zscaler (zscaler_changes) desks; configuration changes NCM found on a
 *             device, authorised (an approved plan was applied) or unauthorised; and changes a person records here (an emergency
 *             change, a vendor visit, an application release) - who, what, on which system, risk, ticket, roll-back.
 *   SOC side  the SIEM alerts on the same system (host name, device name or IP - exact, case-insensitive; never a similar name)
 *             raised within the window after the change (default 24 h), with how many minutes after. It is a lead for the analyst:
 *             an alert after a change is not proof the change caused it, and the page says so.
 *   NOC side  the device's state in the latest poll (up / degraded / down), and whether the change plan's own validation failed.
 *   KPIs      changes in the period, by source; changes followed by alerts; unauthorised configuration changes; failed changes; high
 *             risk; outside working hours (Sun-Thu 07:00-18:00 Riyadh); the share of changes followed by an alert.
 *   GET  /netops/changelog?days=&window_h=   viewer    the register (viewers: alert counts only, no alert text)
 *   POST /netops/changelog                   operator  {what, target, category, risk, at?, ticket?, rollback?, note?}   audited
 */
const DAY = 86400000, HOUR = 3600000;
const PLAN_SOURCES = [['netops_changes', 'network'], ['sysadmin_changes', 'server'], ['ksc_changes', 'endpoint (Kaspersky)'], ['zscaler_changes', 'web security (Zscaler)']];
const MADE = new Set(['applied', 'validated', 'executing', 'execution-failed', 'failed-validation']);
const CATEGORIES = ['network', 'server', 'security', 'application', 'database', 'identity', 'cloud', 'facility', 'other'];
const RISKS = ['low', 'medium', 'high'];
const low = (s) => String(s == null ? '' : s).trim().toLowerCase();
const hostKey = (s) => low(s).split('.')[0];
// Riyadh working hours: Sunday-Thursday 07:00-18:00 (UTC+3, no DST)
function offHours(t) { const d = new Date(t + 3 * HOUR), wd = d.getUTCDay(), h = d.getUTCHours(); return wd === 5 || wd === 6 || h < 7 || h >= 18; }

function createChangeCorr({ state, inventory, poller, ncm, alerts, now } = {}) {
  const clock = now || Date.now, LOG = state.collection('change_log');
  const devOf = (id) => { try { return inventory && (inventory.get ? inventory.get(id) : inventory.list().find((d) => d.id === id)); } catch (e) { return null; /* inventory unavailable: the device is named as recorded */ } };
  // the system's own names, whole: an alert host with a domain (core-syn.as.local) matches through hostKey() of the ALERT value;
  // a recorded name is never cut, so app.syn01 is not app.other
  function keysFor(target, dev) { const k = new Set(); for (const v of [target, dev && dev.name, dev && dev.ip, dev && dev.id]) if (v) k.add(low(v)); k.delete(''); return k; }

  function planChanges(from) {
    const out = [];
    for (const [col, src] of PLAN_SOURCES) {
      let items = []; try { items = state.collection(col).all(); } catch (e) { items = []; /* desk not installed: no plans from it */ }
      for (const c of items) {
        if (!MADE.has(c.status)) continue;
        const at = c.applied_at || (c.run && (c.run.finished || c.run.started)) || c.decided_at || c.proposed_at; if (!at || at < from) continue;
        const dev = devOf(c.device);
        out.push({ id: c.id, source: src, kind: 'plan', at, what: c.title, target: (dev && dev.name) || c.device, device: c.device, ip: (dev && dev.ip) || '', risk: c.risk || 'medium', by: c.applied_by || c.proposed_by || '',
          approved_by: c.decided_by || '', status: c.status, failed: c.status === 'execution-failed' || c.status === 'failed-validation', ticket: c.ticket || '', rollback: (c.rollback || []).length ? c.rollback.join('\n').slice(0, 600) : '',
          authorised: true, keys: keysFor(c.device, dev) });
      }
    }
    return out;
  }
  function configChanges(from) {
    if (!ncm || typeof ncm.view !== 'function') return { items: [], error: 'not installed' };
    let V; try { V = ncm.view(); } catch (e) { return { items: [], error: e.message }; }
    return { items: (V.recent || []).filter((r) => r.first_seen >= from).map((r) => { const dev = devOf(r.device);
      return { id: 'CFG-' + r.device + '-' + String(r.sha256).slice(0, 8), source: 'configuration (NCM)', kind: 'config', at: r.first_seen, what: r.kind === 'authorised' ? 'Configuration changed under plan ' + (r.plan ? r.plan.id : '') : 'Configuration changed with no approved change plan',
        target: r.name || r.device, device: r.device, ip: (dev && dev.ip) || '', risk: r.kind === 'unauthorised' ? 'high' : 'medium', by: '', status: r.kind, failed: false, authorised: r.kind === 'authorised', plan: r.plan || null, keys: keysFor(r.device, dev) }; }) };
  }
  function manualChanges(from) {
    return LOG.all((c) => c.at >= from).map((c) => Object.assign({}, c, { source: 'recorded', kind: 'manual', failed: c.outcome === 'failed', authorised: true, keys: keysFor(c.target, devOf(c.target)) }));
  }
  function alertsAfter(ch, windowMs) {
    if (!alerts || (typeof alerts.all !== 'function' && typeof alerts.list !== 'function')) return [];
    const end = ch.at + windowMs, inWin = (a) => { const t0 = a.ts_first || a.created; return t0 >= ch.at && t0 <= end; };
    let L = []; try { L = typeof alerts.all === 'function' ? alerts.all(inWin) : (alerts.list({ status: 'all', from: ch.at, to: end, limit: 500 }).items || []); } catch (e) { L = []; /* alert store unavailable: the change shows no SOC side */ }
    const hit = (a) => { const vals = [a.host, ...(a.group ? Object.values(a.group) : []), ...(a.fields ? [a.fields.src_ip, a.fields.dst_ip, a.fields.host, a.fields.host_ip] : [])].filter(Boolean);
      return vals.some((v) => ch.keys.has(low(v)) || ch.keys.has(hostKey(v))); };
    return L.filter((a) => (a.ts_first || a.created) >= ch.at && (a.ts_first || a.created) <= ch.at + windowMs && hit(a))
      .map((a) => ({ id: a.id, rule: a.rule_name, severity: a.severity, status: a.status, minutes_after: Math.round(((a.ts_first || a.created) - ch.at) / 60000), summary: String(a.summary || '').slice(0, 300) }))
      .sort((x, y) => x.minutes_after - y.minutes_after);
  }
  function nocState(ch) {
    if (!poller || !ch.device) return null;
    const s = poller.snapshot(ch.device); if (!s) return null;
    const r = s.reach, down = s.ok === false || (r && r.received === 0 && (s.sources || []).length <= 1);
    return { state: down ? 'down' : 'up', at: s.at || null };
  }

  function view(q = {}, role) {
    const t = clock(), days = q.days || 30, windowMs = (q.window_h || 24) * HOUR, from = t - days * DAY, priv = role === 'viewer';
    const cfg = configChanges(from), list = planChanges(from).concat(cfg.items, manualChanges(from)).sort((a, b) => b.at - a.at);
    const rows = list.map((c) => {
      const A = alertsAfter(c, windowMs), noc = nocState(c), worst = A.reduce((m, a) => Math.max(m, a.severity || 0), 0);
      const row = { id: c.id, source: c.source, kind: c.kind, at: c.at, what: c.what, target: c.target, ip: priv ? '' : c.ip || '', category: c.category || (c.kind === 'manual' ? 'other' : c.source.split(' ')[0]),
        risk: c.risk, by: c.by, approved_by: c.approved_by || '', status: c.status || '', failed: !!c.failed, authorised: c.authorised !== false, off_hours: offHours(c.at), ticket: c.ticket || '', rollback: priv ? '' : c.rollback || '',
        note: c.note || '', plan: c.plan || null, noc, soc: { alerts: A.length, worst, first_after_min: A.length ? A[0].minutes_after : null, items: priv ? [] : A.slice(0, 20) } };
      return row;
    });
    const n = rows.length, withA = rows.filter((r) => r.soc.alerts).length, by = {};
    for (const r of rows) by[r.source] = (by[r.source] || 0) + 1;
    return {
      at: t, days, window_h: windowMs / HOUR, private: priv, sources: { by_source: by, ncm: cfg.error ? 'not available: ' + cfg.error : 'ok', alerts: alerts && (typeof alerts.all === 'function' || typeof alerts.list === 'function') ? 'ok' : 'not available' },
      kpis: { changes: n, with_alerts: withA, with_alerts_pct: n ? Math.round((withA / n) * 100) : 0, unauthorised: rows.filter((r) => !r.authorised).length, failed: rows.filter((r) => r.failed).length,
        high_risk: rows.filter((r) => r.risk === 'high').length, off_hours: rows.filter((r) => r.off_hours).length, noc_down_now: rows.filter((r) => r.noc && r.noc.state === 'down').length },
      changes: rows,
      note: 'An alert on the same system after a change is a lead to look into, not proof the change caused it. Changes are only as complete as what the desks and people record.',
    };
  }

  function record(b, who) {
    const t = clock(), at = b.at != null ? b.at : t;
    if (at > t + 5 * 60000) throw Object.assign(new Error('at: a change is recorded when it has been made - not in the future'), { status: 400 });
    if (at < t - 365 * DAY) throw Object.assign(new Error('at: more than a year ago'), { status: 400 });
    const n = LOG.all().reduce((m, c) => { const x = /^CHG-(\d+)$/.exec(c.id); return x ? Math.max(m, Number(x[1])) : m; }, 0);
    const rec = { id: 'CHG-' + String(n + 1).padStart(6, '0'), at, what: b.what, target: b.target, category: b.category, risk: b.risk, ticket: b.ticket || '', rollback: b.rollback || '', note: b.note || '', outcome: b.outcome || 'done', by: who.user, recorded_at: t };
    LOG.put(rec); return rec;
  }
  return { view, record, offHours, CATEGORIES, RISKS };
}

module.exports = { createChangeCorr, offHours, CATEGORIES, RISKS };
