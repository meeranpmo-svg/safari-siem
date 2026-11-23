// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Application Audit (Applications -> Application Audit): one audit report per application - the servers grouped as one
 * business service in Server Availability (netops/availability.js groups) - over a period:
 *   availability & resilience  per server availability 24 h / 7 d / 30 d, outages (avail_events), single point of failure,
 *                              running without redundancy, no DR copy, restarts overdue, unexpected shutdowns
 *   changes                    server change plans (sysadmin_changes, SCHG-) and network change plans (netops_changes) on its
 *                              servers: who proposed, who approved (four eyes), who applied, validated or not
 *   security activity          from the SIEM's events on its servers: failed logons (by account / source), account and
 *                              group changes (category iam), audit-policy events (policy - incl. a cleared security log),
 *                              high-severity events
 *   log coverage               a server that sent NO log in the period is a finding - "no events" is never "nothing happened"
 *   createAppAudit({ av, state, ch, now, table }) -> { list(q), report(q) };  summarize(...) is pure (tested)
 */
const MAX_ROWS = 50000;
const num = (v) => { const n = Number(v); return v === '' || v === null || v === undefined || !Number.isFinite(n) ? null : n; };
const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
const short = (v) => low(v).split('.')[0];
const SEV = { critical: 4, high: 3, medium: 2, low: 1 };

function membersOf(g, items) { const ids = new Set(g.members || []); return items.filter((i) => ids.has(i.id)); }
// a change plan is on this application when its device is one of the servers (id, IP or short host name)
function changeMatches(c, servers) { const d = low(c.device); return !!d && servers.some((s) => d === low(s.id) || d === low(s.ip) || d === short(s.name) || short(d) === short(s.name)); }

function summarize({ group, servers, changes, events, coverage, outages, hours, now, capped }) {
  const findings = [], add = (severity, area, title, rec, evidence) => findings.push({ severity, area, title, recommendation: rec, evidence: (evidence || []).filter(Boolean).slice(0, 6) });
  const G = group || {}, I = G.issues || [];
  if (I.includes('single-server')) add('high', 'Resilience', `${G.name}: runs on a single server`, 'A failure of that server stops the application: add a second server or document the accepted risk (SAMA BCM).');
  if (I.includes('no-redundancy-now')) add('high', 'Resilience', `${G.name}: running without redundancy now`, 'A production server of the pair is offline - bring it back before the next failure.');
  if (I.includes('no-dr')) add('medium', 'Resilience', `${G.name}: no DR copy`, 'No member is at the DR site or marked as DR: set it up, or record why it is not needed.');
  for (const s of servers) {
    const a30 = s.availability && num(s.availability.d30);
    if (a30 !== null && a30 < 99) add(a30 < 95 ? 'high' : 'medium', 'Availability', `${s.name}: ${a30}% available over 30 days`, 'Review the outages below and their causes.', [`7 d ${s.availability.d7 == null ? '?' : s.availability.d7}%`]);
    if ((s.flags || []).includes('reboot-overdue')) add('low', 'Patching', `${s.name}: no restart for ${s.days_since_boot} days`, 'Patches that need a restart are not in effect: restart in the next window.');
    if (s.unexpected_shutdowns_30d) add('medium', 'Availability', `${s.name}: ${s.unexpected_shutdowns_30d} unexpected shutdown(s) in 30 days`, 'Find the cause (power, hardware, OS crash).');
    const cv = coverage.find((c) => c.server === s.id);
    if (!cv || !cv.events) add('medium', 'Log coverage', `${s.name}: no log received in the period`, 'The SIEM cannot audit what it does not receive: connect the server\'s logs (Log Sources & Agents).');
  }
  // changes: four eyes and completion
  const ch = changes.map((c) => ({ id: c.id, kind: c.id.startsWith('SCHG') ? 'server' : 'network', device: c.device, title: c.title, status: c.status, source: c.source || '', risk: c.risk || '',
    proposed_by: c.proposed_by || '', proposed_at: c.proposed_at ? new Date(c.proposed_at).toISOString() : null, decided_by: c.decided_by || '', decided_at: c.decided_at ? new Date(c.decided_at).toISOString() : null,
    applied_by: c.applied_by || '', applied_at: c.applied_at ? new Date(c.applied_at).toISOString() : null, validated: c.status === 'validated', comment: c.comment || '' }));
  for (const c of ch) {
    if ((c.status === 'applied' || c.status === 'validated') && c.decided_by && c.proposed_by && low(c.decided_by) === low(c.proposed_by) && c.source === 'user') add('high', 'Change control', `${c.id} was approved by its own author (${c.decided_by})`, 'Four-eyes control broken: review the change after the fact.', [c.title]);
    if (c.status === 'applied') add('low', 'Change control', `${c.id} applied but not validated`, 'Record the validation (the device was re-checked after the change).', [c.title, 'applied by ' + c.applied_by]);
    if (c.status === 'failed-validation' || c.status === 'execution-failed') add('high', 'Change control', `${c.id} ${c.status}`, 'Check the rollback and the service state.', [c.title]);
  }
  // security activity
  const E = events, failed = {}, acct = [], pol = [], high = [];
  for (const e of E) {
    if (e.category === 'authentication' && e.outcome === 'failure') { const k = [e.host, e.user, e.src_ip].join('|'); const x = failed[k] || (failed[k] = { host: e.host, user: e.user, src_ip: e.src_ip, count: 0, last: e.ts }); x.count++; if (e.ts > x.last) x.last = e.ts; }
    if (e.category === 'iam') acct.push(e);
    if (e.category === 'policy') pol.push(e);
    if ((num(e.severity) || 0) >= 3) high.push(e);
  }
  const failedL = Object.values(failed).sort((a, b) => b.count - a.count);
  for (const f of failedL.filter((x) => x.count >= 20)) add(f.count >= 100 ? 'high' : 'medium', 'Authentication', `${f.count} failed logons for ${f.user || '?'} on ${f.host}${f.src_ip ? ' from ' + f.src_ip : ''}`, 'Password guessing or a service with an old password: check the source.');
  for (const p of pol.filter((x) => /clear|1102|104\b|disabled/i.test(x.action + ' ' + x.event_code + ' ' + x.message))) add('critical', 'Audit trail', `Security log cleared / auditing changed on ${p.host} by ${p.user || '?'}`, 'Clearing the security log hides activity: find out who and why.', [p.ts, p.message]);
  for (const a of acct.filter((x) => /group|admin|privilege/i.test(x.action + ' ' + x.message)).slice(0, 20)) add('medium', 'Accounts', `${a.action} on ${a.host} by ${a.user || '?'}`, 'Check it against an access request.', [a.ts, a.message]);
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const worst = findings.length ? findings[0].severity : null;
  return { generated_at: new Date(now).toISOString(), hours, capped: !!capped,
    application: { key: G.key, name: G.name, inferred: !!G.inferred, critical: !!G.critical, status: G.status || null, ha: !!G.ha, issues: I, production: G.production, dr: G.dr },
    servers: servers.map((s) => ({ id: s.id, name: s.name, ip: s.ip, role: s.role || '', status: s.status, site: s.site || '', dr_site: !!s.dr_site, availability: s.availability || null, days_since_boot: s.days_since_boot, unexpected_shutdowns_30d: s.unexpected_shutdowns_30d || 0,
      logs: (coverage.find((c) => c.server === s.id) || { events: 0, last: null }) })),
    outages: outages.slice(0, 200), changes: ch.sort((a, b) => String(b.proposed_at).localeCompare(String(a.proposed_at))), failed_logons: failedL.slice(0, 100),
    account_changes: acct.slice(0, 300), audit_policy: pol.slice(0, 300), high_severity: high.slice(0, 300),
    summary: { servers: servers.length, online: servers.filter((s) => s.status === 'online').length, outages: outages.length, changes: ch.length, changes_self_approved: findings.filter((f) => /approved by its own author/.test(f.title)).length,
      failed_logons: failedL.reduce((n, f) => n + f.count, 0), account_changes: acct.length, high_severity: high.length, servers_without_logs: servers.filter((s) => !((coverage.find((c) => c.server === s.id) || {}).events)).length,
      critical: findings.filter((f) => f.severity === 'critical').length, high: findings.filter((f) => f.severity === 'high').length, worst },
    findings };
}

function createAppAudit({ av, state, ch, now = Date.now, table = 'siem.events' } = {}) {
  const hoursOf = (q) => Math.min(24 * 90, Math.max(1, Number(q && q.hours) || 168));
  const toMs = (v) => (typeof v === 'number' ? v : Date.parse(String(v).replace(' ', 'T') + (/[Zz]$/.test(String(v)) ? '' : 'Z')));
  const allChanges = () => [].concat(state ? state.collection('sysadmin_changes').all() : [], state ? state.collection('netops_changes').all() : []);
  async function list() {
    const v = await av.view();
    return { generated_at: new Date(now()).toISOString(), applications: v.groups.map((g) => { const m = membersOf(g, v.items); return { key: g.key, name: g.name, inferred: !!g.inferred, critical: !!g.critical, status: g.status, issues: g.issues || [], servers: m.length, online: m.filter((s) => s.status === 'online').length }; }).sort((a, b) => a.name.localeCompare(b.name)) };
  }
  async function report(q = {}) {
    const v = await av.view(), key = String(q.app || ''), g = v.groups.find((x) => x.key === key || low(x.name) === low(key));
    if (!g) throw Object.assign(new Error('application not found'), { code: 404 });
    const servers = membersOf(g, v.items), h = hoursOf(q), since = now() - h * 3600000;
    // a change belongs to the period when it was proposed, decided or applied inside it
    const changes = allChanges().filter((c) => changeMatches(c, servers) && ((c.proposed_at || 0) >= since || (c.decided_at || 0) >= since || (c.applied_at || 0) >= since));
    const ids = new Set(servers.map((s) => s.id));
    const outages = state ? state.collection('avail_events').all((e) => ids.has(e.host) && (e.at || 0) >= since).sort((a, b) => b.at - a.at).map((e) => ({ server: (servers.find((s) => s.id === e.host) || {}).name || e.host, at: new Date(e.at).toISOString(), from: e.from || '', to: e.to || e.status || '', duration_s: e.duration_s || null })) : [];
    let events = [], coverage = servers.map((s) => ({ server: s.id, events: 0, last: null })), capped = false;
    if (ch && typeof ch.query === 'function' && servers.length) {
      const names = servers.map((s) => short(s.name)).filter(Boolean), ips = servers.map((s) => s.ip).filter(Boolean);
      const P = { h: { type: 'UInt32', value: h }, names: { type: 'Array(String)', value: names }, ips: { type: 'Array(String)', value: ips } };
      const where = `ts >= now() - INTERVAL {h:UInt32} HOUR AND (splitByChar('.', lower(host))[1] IN {names:Array(String)} OR host_ip IN {ips:Array(String)})`;
      const cov = await ch.query(`/* app-audit:coverage */ SELECT splitByChar('.', lower(host))[1] AS h, host_ip AS ip, count() AS c, max(ts) AS t FROM ${table} WHERE ${where} GROUP BY h, ip`, P, { readonly: true, timeout_ms: 20000 });
      coverage = servers.map((s) => { const m = cov.filter((r) => r.h === short(s.name) || (s.ip && r.ip === s.ip)); return { server: s.id, events: m.reduce((n, r) => n + Number(r.c || 0), 0), last: m.length ? new Date(Math.max(...m.map((r) => toMs(r.t)))).toISOString() : null }; });
      const r = await ch.query(`/* app-audit:events */ SELECT ts, host, host_ip, category, action, outcome, severity, user, src_ip, event_code, message FROM ${table}
        WHERE ${where} AND (category IN ('authentication', 'iam', 'policy') OR severity >= 3) ORDER BY ts DESC LIMIT ${MAX_ROWS + 1}`, P, { readonly: true, timeout_ms: 30000 });
      capped = r.length > MAX_ROWS;
      events = r.slice(0, MAX_ROWS).map((e) => ({ ts: new Date(toMs(e.ts)).toISOString(), host: e.host, host_ip: e.host_ip, category: e.category, action: e.action, outcome: e.outcome, severity: Number(e.severity) || 0, user: e.user, src_ip: e.src_ip, event_code: e.event_code, message: String(e.message || '').slice(0, 300) }));
    }
    return summarize({ group: g, servers, changes, events, coverage, outages, hours: h, now: now(), capped });
  }
  return { list, report };
}

module.exports = { createAppAudit, summarize, changeMatches };
