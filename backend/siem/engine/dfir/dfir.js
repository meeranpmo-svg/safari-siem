// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * DFIR — digital-forensics & incident-response investigation, built on the events the SIEM already holds and the
 * cases the SOC already runs (engine/soc/cases.js). Nothing here changes an endpoint: the timeline and triage are
 * read-only queries over the event store; a triage collection is a *request* that an operator runs through Endpoint
 * Central / the response agent and attaches to the case — this engine records the request and the decision, it never
 * executes anything (same rule as soc/cases.js approvals and xdr).
 *
 *   createDfir({ search, state, cases, config, log, now })
 *     → { timeline({entity,type,hours,limit}), triage({entity,type,hours}), overview(),
 *         collectCatalog(), requestCollection(input, by), collections(filter), decideCollection(id, decision, by, note),
 *         classify(row), entityType(v) }
 *
 * Super-timeline: one row per event, classified into a forensic lane (execution, auth, persistence, defense impairment,
 * account, network, web, dns, file, email, detection, other) from the event's category + action — the EDR-grade
 * fields the schema already carries (process / parent_process / cmdline / hash / dns_query / logon type) make it a real
 * process/logon/network timeline, not just an alert list.
 */

// lane = [id, label, icon]; the first predicate that matches wins, most investigation-relevant first.
const LANES = {
  detection: ['detection', 'Detection', '🛡️'], execution: ['execution', 'Process execution', '⚙️'],
  persistence: ['persistence', 'Persistence', '📌'], evasion: ['evasion', 'Defense impairment', '🧹'],   // ATT&CK v20: log clearing / auditing off / agent tamper = TA0112
  auth: ['auth', 'Authentication', '🔑'], account: ['account', 'Account / privilege', '👤'],
  network: ['network', 'Network', '🌐'], web: ['web', 'Web', '🕸️'], dns: ['dns', 'DNS', '📡'],
  file: ['file', 'File / registry', '📄'], email: ['email', 'Email', '✉️'], other: ['other', 'Other', '•'],
};
const DET_ACTIONS = new Set(['av-detection', 'ips-detection', 'edr-detection', 'waf-detection', 'dlp-incident']);
const PERSIST_ACTIONS = new Set(['service-installed', 'scheduled-task-created', 'cron', 'inbox-rule-created', 'mail-forwarding-set', 'transport-rule-created', 'registry-set']);
const EVASION_ACTIONS = new Set(['audit-log-cleared', 'audit-disabled', 'agent-tamper']);
const AUTH_ACTIONS = new Set(['logon', 'logon-failed', 'logoff', 'logon-explicit', 'credential-validated', 'session-opened', 'session-closed', 'kerberos-tgt', 'kerberos-service-ticket', 'sudo', 'su']);
const ACCOUNT_ACTIONS = new Set(['user-created', 'user-deleted', 'user-enabled', 'user-disabled', 'user-modified', 'password-change', 'password-reset', 'account-locked', 'group-member-added', 'group-member-removed', 'role-assigned', 'privileges-assigned']);

function laneOf(row) {
  const c = String(row.category || '').toLowerCase(), a = String(row.action || '').toLowerCase(), sev = Number(row.severity) || 0;
  if (c === 'malware' || DET_ACTIONS.has(a) || sev >= 3) return 'detection';
  if (EVASION_ACTIONS.has(a)) return 'evasion';
  if (PERSIST_ACTIONS.has(a)) return 'persistence';
  if (c === 'process' || a === 'process-start' || a === 'process-access' || a === 'script-block') return 'execution';
  if (c === 'authentication' || AUTH_ACTIONS.has(a)) return 'auth';
  if (c === 'iam' || ACCOUNT_ACTIONS.has(a)) return 'account';
  if (c === 'dns' || a === 'dns-query') return 'dns';
  if (c === 'web' || a === 'http-request') return 'web';
  if (c === 'network' || a === 'connection' || a === 'blocked' || a === 'allowed' || a === 'vpn-event') return 'network';
  if (c === 'email' || a.startsWith('mail') || a.startsWith('inbox') || a.startsWith('transport')) return 'email';
  if (c === 'file' || c === 'registry' || a === 'file-created') return 'file';
  return 'other';
}

function privVal(v) { return v == null ? '' : String(v); }
function isInternalIp(ip) { return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80:|fc|fd)/i.test(String(ip || '')); }

// a short human line for the event, from whichever fields the row carries
function titleOf(row, lane) {
  const a = row.action || row.event_code || '', out = row.outcome && row.outcome !== 'unknown' ? ` (${row.outcome})` : '';
  if (lane === 'execution') { const p = row.process || '(process)'; return `${p}${row.parent_process ? ' ← ' + row.parent_process : ''}${row.cmdline ? ' : ' + String(row.cmdline).slice(0, 160) : ''}`; }
  if (lane === 'auth') { const who = row.target_user || row.user || ''; const lt = row.fields && (row.fields.logon_type || row.fields.LogonType); return `${a}${lt ? ' type ' + lt : ''}${who ? ' as ' + who : ''}${row.src_ip ? ' from ' + row.src_ip : ''}${out}`; }
  if (lane === 'account') return `${a}${row.target_user ? ' → ' + row.target_user : ''}${row.user ? ' by ' + row.user : ''}${out}`;
  if (lane === 'network') return `${a || 'connection'} ${row.src_ip || ''}${row.dst_ip ? ' → ' + row.dst_ip : ''}${row.dst_port ? ':' + row.dst_port : ''}${row.proto ? '/' + row.proto : ''}${out}`;
  if (lane === 'dns') return `DNS ${row.dns_query || ''}${row.dst_ip ? ' → ' + row.dst_ip : ''}`;
  if (lane === 'web') return `${row.http_method || 'HTTP'} ${row.url || ''}${out}`;
  if (lane === 'detection') return `${a || 'detection'}${row.process ? ' · ' + row.process : ''}${row.hash ? ' · ' + String(row.hash).slice(0, 16) : ''} — ${String(row.message || '').slice(0, 160)}`;
  if (lane === 'email') return `${a}${row.user ? ' · ' + row.user : ''} — ${String(row.message || '').slice(0, 140)}`;
  return `${a || row.category || 'event'}${out}${row.message ? ' — ' + String(row.message).slice(0, 140) : ''}`;
}

// Triage collection catalogue — what a forensic triage package pulls. Collected by the endpoint agent (Endpoint Central
// script / response agent), NEVER by this engine. kind 'quick' = minutes, light; 'full' = heavier / larger.
const COLLECT = [
  { id: 'processes', name: 'Running processes + loaded modules', os: 'win,linux,mac', kind: 'quick' },
  { id: 'netstat', name: 'Active network connections (netstat)', os: 'win,linux,mac', kind: 'quick' },
  { id: 'services', name: 'Services and drivers', os: 'win,linux', kind: 'quick' },
  { id: 'schtasks', name: 'Scheduled tasks / cron', os: 'win,linux,mac', kind: 'quick' },
  { id: 'autoruns', name: 'Autoruns / persistence locations', os: 'win', kind: 'quick' },
  { id: 'local-users', name: 'Local users and groups', os: 'win,linux,mac', kind: 'quick' },
  { id: 'dns-arp', name: 'DNS cache + ARP table', os: 'win,linux,mac', kind: 'quick' },
  { id: 'evtx', name: 'Event logs (Security / System / Application / PowerShell)', os: 'win', kind: 'full' },
  { id: 'prefetch', name: 'Prefetch', os: 'win', kind: 'full' },
  { id: 'amcache-shimcache', name: 'Amcache + Shimcache (program execution)', os: 'win', kind: 'full' },
  { id: 'srum', name: 'SRUM (per-app network / resource usage)', os: 'win', kind: 'full' },
  { id: 'mft-usn', name: 'MFT + USN journal (file-system timeline)', os: 'win', kind: 'full' },
  { id: 'registry-hives', name: 'Registry hives (SYSTEM / SOFTWARE / NTUSER)', os: 'win', kind: 'full' },
  { id: 'browser-history', name: 'Browser history / downloads', os: 'win,linux,mac', kind: 'full' },
  { id: 'bash-history', name: 'Shell history + auth.log / syslog', os: 'linux,mac', kind: 'full' },
  { id: 'memory', name: 'Full memory image', os: 'win,linux', kind: 'full' },
];
const COLLECT_IDS = new Set(COLLECT.map((c) => c.id));

const TIMELINE_FIELDS = ['ts', 'src_type', 'host', 'host_ip', 'user', 'target_user', 'src_ip', 'dst_ip', 'dst_port', 'proto',
  'action', 'category', 'outcome', 'severity', 'process', 'parent_process', 'cmdline', 'hash', 'dns_query', 'url', 'http_method', 'event_code', 'message', 'fields'];

function createDfir({ search, state, cases, config, log, now } = {}) {
  const clk = now || (() => Date.now());
  const counters = state && state.collection ? state.collection('counters') : null;
  const col = state && state.collection ? state.collection('dfir_collections') : null;
  function nextId(prefix, name) { const cur = (counters && (counters.get(name) || {}).n) || 0; const n = cur + 1; if (counters) counters.put({ id: name, n }); return `${prefix}-${String(n).padStart(6, '0')}`; }

  function entityType(v) { const s = String(v || '').trim();
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(s)) return 'ip';
    if (s.includes('@') || s.includes('\\')) return 'user';
    return 'host'; }

  function queryFor(entity, type) {
    const e = String(entity || '').replace(/"/g, '').trim();
    if (type === 'ip') return `(src_ip:${e} OR dst_ip:${e} OR host_ip:${e})`;
    if (type === 'user') { const u = e.includes('\\') ? e.split('\\').pop() : (e.includes('@') ? e.split('@')[0] : e); return `(user:"${u}" OR target_user:"${u}")`; }
    return `host:"${e}"`;
  }

  async function runSearch(entity, type, hours, limit) {
    if (!search) throw Object.assign(new Error('event search is not available'), { code: 503 });
    const to = clk(), from = to - Math.max(1, Math.min(2160, Number(hours) || 24)) * 3600000;
    const lim = Math.max(1, Math.min(5000, Number(limit) || 1500));
    const r = await search({ q: queryFor(entity, type), from, to, limit: lim, fields: TIMELINE_FIELDS, order: 'ts' });
    return { rows: r.rows || [], total: r.total_estimate != null ? r.total_estimate : (r.rows || []).length, took_ms: r.took_ms, from, to, limit: lim };
  }

  async function timeline({ entity, type, hours, limit } = {}) {
    const t = type || entityType(entity); if (!entity) throw Object.assign(new Error('entity is required'), { code: 400 });
    const s = await runSearch(entity, t, hours, limit);
    const laneCounts = {}; const rows = s.rows.map((row) => { const lane = laneOf(row); laneCounts[lane] = (laneCounts[lane] || 0) + 1;
      const L = LANES[lane] || LANES.other;
      return { ts: row.ts, lane, lane_label: L[1], icon: L[2], sev: Number(row.severity) || 0, src_type: row.src_type || '',
        host: row.host || '', user: row.target_user || row.user || '', src_ip: row.src_ip || '', dst_ip: row.dst_ip || '',
        action: row.action || row.event_code || '', title: titleOf(row, lane), outcome: row.outcome || '',
        process: row.process || '', hash: row.hash || '',
        // the fields the DFIR machine learning reads (ml.js): parent / command line, the destination name, logon type / protocol
        parent_process: row.parent_process || '', cmdline: row.cmdline ? String(row.cmdline).slice(0, 2000) : '', dns_query: row.dns_query || '', url: row.url ? String(row.url).slice(0, 500) : '', proto: row.proto || '',
        fields: row.fields && (row.fields.logon_type || row.fields.LogonType) ? { logon_type: String(row.fields.logon_type || row.fields.LogonType) } : undefined };
    }).sort((a, b) => String(a.ts).localeCompare(String(b.ts)));
    return { entity, type: t, from: s.from, to: s.to, total: s.total, shown: rows.length, truncated: s.total > rows.length,
      lanes: Object.keys(laneCounts).map((k) => ({ lane: k, label: (LANES[k] || LANES.other)[1], icon: (LANES[k] || LANES.other)[2], count: laneCounts[k] })).sort((a, b) => b.count - a.count),
      rows, took_ms: s.took_ms };
  }

  async function triage({ entity, type, hours } = {}) {
    const t = type || entityType(entity); if (!entity) throw Object.assign(new Error('entity is required'), { code: 400 });
    const s = await runSearch(entity, t, hours, 3000);
    const byCat = {}, byOut = {}, procs = {}, logons = {}, net = {}, dns = {}, dets = [], accts = [];
    let maxSev = 0, first = null, last = null;
    for (const row of s.rows) {
      const lane = laneOf(row), sev = Number(row.severity) || 0; if (sev > maxSev) maxSev = sev;
      const ts = row.ts; if (ts && (!first || ts < first)) first = ts; if (ts && (!last || ts > last)) last = ts;
      byCat[row.category || 'other'] = (byCat[row.category || 'other'] || 0) + 1;
      byOut[row.outcome || 'unknown'] = (byOut[row.outcome || 'unknown'] || 0) + 1;
      if (lane === 'execution' && (row.process || row.cmdline)) { const k = (row.process || '') + '|' + (row.hash || ''); const p = procs[k] || (procs[k] = { process: row.process || '', hash: row.hash || '', count: 0, cmdline: '', parents: {} }); p.count++; if (!p.cmdline && row.cmdline) p.cmdline = String(row.cmdline).slice(0, 200); if (row.parent_process) p.parents[row.parent_process] = 1; }
      if (lane === 'auth') { const who = row.target_user || row.user || ''; const lt = (row.fields && (row.fields.logon_type || row.fields.LogonType)) || ''; const k = who + '|' + (row.src_ip || '') + '|' + lt; const g = logons[k] || (logons[k] = { user: who, src_ip: row.src_ip || '', type: lt, success: 0, fail: 0 }); if (/fail/.test(row.action || '') || row.outcome === 'failure') g.fail++; else g.success++; }
      if (row.dst_ip) { const k = row.dst_ip + '|' + (row.dst_port || '') + '|' + (row.proto || ''); const g = net[k] || (net[k] = { dst_ip: row.dst_ip, port: row.dst_port || '', proto: row.proto || '', count: 0, internal: isInternalIp(row.dst_ip) }); g.count++; }
      if (row.dns_query) { dns[row.dns_query] = (dns[row.dns_query] || 0) + 1; }
      if (lane === 'detection') dets.push({ ts, sev, action: row.action || '', process: row.process || '', hash: row.hash || '', src_type: row.src_type || '', message: String(row.message || '').slice(0, 200) });
      if (lane === 'account') accts.push({ ts, action: row.action || '', target: row.target_user || '', by: row.user || '', outcome: row.outcome || '' });
    }
    const top = (obj, map, n) => Object.keys(obj).map((k) => map(k, obj[k])).sort((a, b) => b.count - a.count).slice(0, n);
    return { entity, type: t, from: s.from, to: s.to, total: s.total, sampled: s.rows.length, truncated: s.total > s.rows.length,
      summary: { max_severity: maxSev, first_seen: first, last_seen: last, by_category: byCat, by_outcome: byOut },
      processes: Object.keys(procs).map((k) => ({ process: procs[k].process, hash: procs[k].hash, count: procs[k].count, cmdline: procs[k].cmdline, parents: Object.keys(procs[k].parents) })).sort((a, b) => b.count - a.count).slice(0, 25),
      logons: Object.values(logons).sort((a, b) => (b.success + b.fail) - (a.success + a.fail)).slice(0, 25),
      network: top(net, (k, v) => v, 25),
      dns: Object.keys(dns).map((k) => ({ query: k, count: dns[k] })).sort((a, b) => b.count - a.count).slice(0, 25),
      detections: dets.sort((a, b) => b.sev - a.sev || String(b.ts).localeCompare(String(a.ts))).slice(0, 25),
      accounts: accts.slice(0, 25) };
  }

  function overview() {
    const out = { cases: { total: 0, open: 0, by_status: {}, by_severity: {}, items: [] }, approvals: { pending: 0, items: [] }, collections: { requested: 0, items: [] } };
    try {
      if (cases && cases.list) { const r = cases.list({ limit: 500 }); const items = (r.items || r) || [];
        out.cases.total = items.length;
        for (const c of items) { const st = c.status || 'open'; out.cases.by_status[st] = (out.cases.by_status[st] || 0) + 1; if (st !== 'closed') out.cases.open++;
          const sv = c.severity != null ? c.severity : ''; out.cases.by_severity[sv] = (out.cases.by_severity[sv] || 0) + 1; }
        out.cases.items = items.filter((c) => c.status !== 'closed').slice(0, 25).map((c) => ({ id: c.id, title: c.title, severity: c.severity, status: c.status, owner: c.owner || '', created: c.created })); }
    } catch (e) { if (log) log.warn('dfir overview: cases', { err: e && e.message }); }
    try { if (cases && cases.approvals && cases.approvals.list) { const a = cases.approvals.list({ status: 'pending' }); const items = (a.items || a) || []; out.approvals.pending = items.length; out.approvals.items = items.slice(0, 25); } } catch (e) { if (log) log.warn('dfir overview: approvals', { err: e && e.message }); }
    try { if (col) { const cs = col.all().filter((x) => x.status === 'requested'); out.collections.requested = cs.length; out.collections.items = cs.slice(0, 25); } } catch (e) { /* none */ }
    return out;
  }

  function collectCatalog() { return { items: COLLECT.map((c) => Object.assign({}, c)), note: 'Collected by the endpoint agent (Endpoint Central script / response agent) and attached to the case. This engine records the request and the decision only — it never runs anything on an endpoint.' }; }

  function requestCollection(input = {}, by) {
    const entity = String(input.entity || '').trim(); if (!entity) throw Object.assign(new Error('entity is required'), { code: 400 });
    const type = input.type || entityType(entity);
    const items = Array.isArray(input.items) ? input.items.filter((i) => COLLECT_IDS.has(i)) : [];
    if (!items.length) throw Object.assign(new Error('select at least one collection item from the catalogue'), { code: 400 });
    const rationale = String(input.rationale || '').slice(0, 1000); if (!rationale) throw Object.assign(new Error('a rationale is required (PDPL: forensic collection of a named person/host must be justified)'), { code: 400 });
    let case_id = ''; if (input.case_id && cases && cases.get) { const c = cases.get(input.case_id); if (!c) throw Object.assign(new Error('case not found'), { code: 404 }); case_id = c.id; }
    const rec = { id: nextId('DFC', 'dfir_collections'), entity, type, items, case_id, rationale,
      status: 'requested', requested_by: (by && by.user) || by || '', requested_at: clk(), decided_by: '', decided_at: 0, decision: '', note: '',
      execution: 'not-executed-by-engine — an operator runs it via Endpoint Central / the response agent; results are attached to the case as evidence' };
    if (col) col.put(rec);
    if (log) log.info('dfir collection requested', { id: rec.id, entity, items: items.length, case_id });
    return rec;
  }

  function collections(filter = {}) { if (!col) return { items: [] }; let items = col.all(); if (filter.status) items = items.filter((x) => x.status === filter.status); if (filter.case_id) items = items.filter((x) => x.case_id === filter.case_id); items.sort((a, b) => b.requested_at - a.requested_at); return { items: items.slice(0, Number(filter.limit) || 200) }; }

  function decideCollection(id, decision, by, note) {
    if (!col) throw Object.assign(new Error('collection store not available'), { code: 503 });
    const rec = col.get(id); if (!rec) throw Object.assign(new Error('collection request not found'), { code: 404 });
    if (!['approved', 'rejected', 'collected', 'cancelled'].includes(decision)) throw Object.assign(new Error('decision must be approved, rejected, collected or cancelled'), { code: 400 });
    if (decision === 'rejected' && !note) throw Object.assign(new Error('a reason is required to reject'), { code: 400 });
    // four-eyes: the person who asked for the collection may not approve it (they may still cancel their own request)
    const me = String((by && by.user) || by || '').trim().toLowerCase();
    if (decision === 'approved' && me && String(rec.requested_by || '').trim().toLowerCase() === me) throw Object.assign(new Error('four-eyes: the person who requested this collection cannot approve it'), { code: 403 });
    rec.status = decision; rec.decision = decision; rec.decided_by = (by && by.user) || by || ''; rec.decided_at = clk(); if (note) rec.note = String(note).slice(0, 1000);
    col.put(rec); if (log) log.info('dfir collection decided', { id, decision, by: rec.decided_by });
    return rec;
  }

  return { timeline, triage, overview, collectCatalog, requestCollection, collections, decideCollection, classify: laneOf, entityType, queryFor, LANES, COLLECT };
}

module.exports = { createDfir, laneOf, titleOf, isInternalIp, LANES, COLLECT };
