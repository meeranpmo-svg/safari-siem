// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
// Local test harness for the SOC console (sentra-soc-module.js). NOT part of the product.
// Serves the built the organisation portal (dist/index.html + dist/app.js) with the SOC module and its Arabic
// dictionary appended, plus a mock of the SIEM engine API under /api/soc/* that returns CLEARLY SYNTHETIC
// test data (TEST-NET addresses, "test-" host names, "[SYNTHETIC]" messages). Node standard library only.
//
//   node server.js [port]                      → http://localhost:8791/#soc-dashboard
//   GET /__role/admin|operator|viewer          → change the signed-in test role
//   GET /__offline/on|off                      → make /api/soc/* answer 502 (engine not connected)
//   GET /__state                               → current mock state
'use strict';
const http = require('http'), fs = require('fs'), path = require('path');
const PORT = +process.argv[2] || +process.env.PORT || 8791;
const PORTAL = process.env.PORTAL_DIST || 'C:/Users/Syed/AppData/Local/Temp/claude/C--Users-Syed-Desktop-Montessori/fd22e11b-4709-4d80-83b9-e20c1a591a45/scratchpad/as/dist';
const UI = path.resolve(__dirname, '..');
const ST = { role: 'operator', offline: false, user: 'test.analyst@example.test' };

/* ── deterministic pseudo-random ── */
let seed = 42; const rnd = () => { seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };   // mulberry32
const pick = a => a[Math.floor(rnd() * a.length)];
const uuid = () => 'xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx'.replace(/x/g, () => Math.floor(rnd() * 16).toString(16));
const NOW = Date.now(), H = 36e5, DAY = 864e5;

/* ── synthetic events ── */
const SOURCES = [
  { src_id: 'test-fw-01', src_type: 'fortigate', collector: 'syslog-udp', host: 'test-fw-01' },
  { src_id: 'test-dc-01', src_type: 'windows', collector: 'agent', host: 'test-dc-01' },
  { src_id: 'test-web-01', src_type: 'nginx', collector: 'syslog-tcp', host: 'test-web-01' },
  { src_id: 'test-lnx-01', src_type: 'linux', collector: 'syslog-tcp', host: 'test-lnx-01' },
  { src_id: 'test-m365', src_type: 'm365', collector: 'm365', host: 'graph.test' },
  { src_id: 'test-core-sw', src_type: 'cisco', collector: 'syslog-udp', host: 'test-core-sw' },
  { src_id: 'test-proxy-01', src_type: 'cef', collector: 'syslog-tls', host: 'test-proxy-01' },
  { src_id: 'test-lr-feed', src_type: 'json', collector: 'lr', host: 'test-lr' }
];
const USERS = ['test.user01', 'test.user02', 'test.admin', 'test.svc-backup', 'test.user03'];
const EXT = ['203.0.113.5', '203.0.113.77', '198.51.100.23', '198.51.100.140'], INT = ['192.0.2.10', '192.0.2.11', '192.0.2.25', '192.0.2.40'];
const ACTS = [['authentication', 'logon', 'success'], ['authentication', 'logon-failed', 'failure'], ['network', 'blocked', 'success'], ['network', 'allowed', 'success'], ['web', 'http-request', 'success'], ['process', 'process-start', 'success'], ['iam', 'group-member-added', 'success'], ['network', 'ips-detection', 'success']];
function mkEvent(ts) {
  const s = pick(SOURCES.slice(0, 7)), a = pick(ACTS), u = pick(USERS), sip = pick(EXT.concat(INT)), dip = pick(INT);
  const ev = { ts, rts: ts + 40, id: uuid(), src_type: s.src_type, src_id: s.src_id, collector: s.collector, host: s.host, host_ip: '192.0.2.' + (1 + Math.floor(rnd() * 50)),
    category: a[0], action: a[1], outcome: a[2], severity: a[1] === 'ips-detection' ? 3 : a[1] === 'logon-failed' ? 2 : 0, user: u, target_user: '', domain: 'test',
    src_ip: sip, dst_ip: dip, src_port: 1024 + Math.floor(rnd() * 60000), dst_port: pick([22, 443, 80, 3389, 445]), proto: 'tcp', process: a[0] === 'process' ? 'powershell.exe' : '',
    parent_process: '', cmdline: a[0] === 'process' ? 'powershell.exe -nop -c "Write-Output SYNTHETIC"' : '', hash: '', url: a[0] === 'web' ? '/test/path?id=' + Math.floor(rnd() * 99) : '', http_method: a[0] === 'web' ? 'GET' : '',
    http_status: a[0] === 'web' ? pick([200, 404, 403]) : 0, user_agent: '', dns_query: '', event_code: a[1] === 'logon-failed' ? '4625' : a[1] === 'logon' ? '4624' : '0100032001',
    message: rnd() < 0.08 ? '=HYPERLINK("http://example.test","[SYNTHETIC] formula-injection test")' : '[SYNTHETIC] ' + a[1] + ' ' + u + ' from ' + sip, tags: a[1] === 'logon-failed' ? ['T1110'] : [], fields: { test_marker: 'synthetic', logid: '0100032001' } };
  ev.raw = '<134>' + new Date(ts).toISOString() + ' ' + s.host + ' SYNTHETIC-TEST action=' + a[1] + ' user=' + u + ' src=' + sip + ' dst=' + dip + (rnd() < 0.05 ? ' note="=cmd|\' /C calc\'!A0"' : '');
  return ev;
}
const EVENTS = [];
for (let i = 0; i < 4000; i++) { const age = Math.pow(rnd(), 3) * 30 * DAY; EVENTS.push(mkEvent(NOW - age)); }
EVENTS.sort((a, b) => b.ts - a.ts);

/* ── rules, alerts, cases ── */
const RULES = [
  { id: 'SENTRA-AUTH-001', name: '[TEST] Brute force against one account', enabled: true, severity: 3, mitre: ['T1110'], description: 'Synthetic test rule: 10 failed logons for one user in 5 minutes.', type: 'threshold', match: { all: [{ field: 'action', op: 'eq', value: 'logon-failed' }], any: [], none: [] }, group_by: ['user'], window_s: 300, count: 10, suppress_s: 3600, fields_in_alert: ['user', 'src_ip'], alerts_24h: 14, noisy: true, origin: 'built-in', version: 1 },
  { id: 'SENTRA-AUTH-002', name: '[TEST] Password spray from one source', enabled: true, severity: 4, mitre: ['T1110.003'], description: 'Synthetic test rule: one source IP fails against many users.', type: 'distinct', match: { all: [{ field: 'action', op: 'eq', value: 'logon-failed' }] }, group_by: ['src_ip'], distinct_field: 'user', distinct_count: 5, window_s: 600, suppress_s: 3600, alerts_24h: 2, origin: 'built-in', version: 1 },
  { id: 'SENTRA-IAM-001', name: '[TEST] Member added to a privileged group', enabled: true, severity: 3, mitre: ['T1098'], description: 'Synthetic test rule.', type: 'single', match: { all: [{ field: 'action', op: 'eq', value: 'group-member-added' }] }, suppress_s: 600, alerts_24h: 3, origin: 'built-in', version: 1 },
  { id: 'SENTRA-NET-001', name: '[TEST] IPS detection from the internet', enabled: true, severity: 2, mitre: ['T1190'], description: 'Synthetic test rule.', type: 'single', match: { all: [{ field: 'action', op: 'eq', value: 'ips-detection' }] }, suppress_s: 900, alerts_24h: 31, noisy: true, origin: 'native', version: 2 },
  { id: 'SENTRA-PROC-001', name: '[TEST] Encoded PowerShell', enabled: false, severity: 3, mitre: ['T1059.001', 'T1027'], description: 'Synthetic test rule.', type: 'single', match: { all: [{ field: 'process', op: 'endswith', value: 'powershell.exe' }, { field: 'cmdline', op: 'contains', value: '-enc' }] }, suppress_s: 3600, alerts_24h: 0, origin: 'sigma', sigma_id: '00000000-test', version: 1 },
  { id: 'SENTRA-SYS-001', name: '[TEST] Audit log cleared', enabled: true, severity: 4, mitre: ['T1070.001'], description: 'Synthetic test rule.', type: 'single', match: { all: [{ field: 'action', op: 'eq', value: 'audit-log-cleared' }] }, suppress_s: 0, alerts_24h: 1, origin: 'built-in', version: 1 }
];
const ASTS = ['new', 'new', 'new', 'acknowledged', 'in-progress', 'closed-true-positive', 'closed-false-positive', 'closed-benign'];
const ALERTS = [];
for (let i = 0; i < 28; i++) {
  const r = RULES[i % RULES.length], t1 = NOW - rnd() * 6 * DAY, st = ASTS[i % ASTS.length], u = pick(USERS), ip = pick(EXT);
  const sample = EVENTS.filter(e => e.ts < t1 + H).slice(0, 3).map(e => e.id);
  ALERTS.push({ id: 'AL-' + String(1000 + i), rule_id: r.id, rule_name: r.name, severity: r.severity, mitre: r.mitre, ts_first: new Date(t1 - 20 * 6e4).toISOString(), ts_last: new Date(t1).toISOString(), count: 1 + Math.floor(rnd() * 40),
    group: r.group_by && r.group_by[0] === 'src_ip' ? { src_ip: ip } : { user: u }, sample_event_ids: sample, summary: '[SYNTHETIC] ' + r.name.replace('[TEST] ', '') + ' — ' + (r.group_by && r.group_by[0] === 'src_ip' ? ip : u),
    status: st, assignee: st === 'new' ? '' : pick(['test.analyst@example.test', 'test.lead@example.test']), case_id: '', notes: i % 5 === 0 ? [{ at: new Date(t1 + 6e5).toISOString(), by: 'test.lead@example.test', text: 'Synthetic note <b>not bold</b>' }] : [],
    history: [{ at: new Date(t1).toISOString(), by: 'engine', action: 'raised', detail: '' }] });
}
const PB = [['Confirm the alert is not a known test or change', false], ['Identify affected accounts and hosts', true], ['Reset or disable the affected account', false], ['Block the source address at the perimeter', false], ['Document findings and close', false]];
const CASES = [];
function mkCase(n, title, sev, status, alerts, ackDue, resDue) {
  const c = { id: 'CASE-' + String(n).padStart(6, '0'), title, severity: sev, status, owner: status === 'open' ? '' : 'test.lead@example.test', alerts, timeline: [{ at: new Date(NOW - 5 * H).toISOString(), by: 'test.analyst@example.test', kind: 'created', text: 'Case created from alerts (synthetic)' }],
    evidence: [{ at: new Date(NOW - 4 * H).toISOString(), by: 'test.analyst@example.test', name: 'Firewall export', ref: 'https://evidence.example.test/case/1' }, { at: new Date(NOW - 3 * H).toISOString(), by: 'test.analyst@example.test', name: 'Memory image hash', ref: 'sha256:0000test' }],
    playbook_id: 'PB-BRUTEFORCE', playbook_name: 'Brute force response (test)', tasks: PB.map((p, i) => ({ id: 't' + (i + 1), title: p[0], done: p[1], by: p[1] ? 'test.analyst@example.test' : '', at: p[1] ? new Date(NOW - 2 * H).toISOString() : '' })),
    sla: { ack_due: new Date(ackDue).toISOString(), resolve_due: new Date(resDue).toISOString() }, created: new Date(NOW - 5 * H).toISOString(), closed: status === 'closed' ? new Date(NOW - H).toISOString() : '', resolution: status === 'closed' ? 'Synthetic: confirmed test activity.' : '',
    recommended_actions: [{ id: 'ra1', title: 'Disable the account in Active Directory', target: 'test.user01', description: 'Synthetic recommendation — requires approval.' }, { id: 'ra2', title: 'Block source IP on the perimeter firewall', target: '203.0.113.5' }] };
  alerts.forEach(id => { const a = ALERTS.find(x => x.id === id); if (a) a.case_id = c.id; });
  CASES.push(c); return c;
}
mkCase(121, '[TEST] Brute force against test.user01', 3, 'open', ['AL-1000', 'AL-1006'], NOW - 30 * 6e4, NOW + 20 * H);
mkCase(122, '[TEST] Password spray from 203.0.113.77', 4, 'investigating', ['AL-1001'], NOW - 3 * H, NOW - 10 * 6e4);
mkCase(123, '[TEST] Privileged group change', 3, 'closed', ['AL-1002'], NOW - 4 * H, NOW + 30 * H);

/* ── mock query language (enough for the UI tests) ── */
const FIELDS = ['ts', 'rts', 'id', 'src_type', 'src_id', 'collector', 'host', 'host_ip', 'category', 'action', 'outcome', 'severity', 'user', 'target_user', 'domain', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'process', 'parent_process', 'cmdline', 'hash', 'url', 'http_method', 'http_status', 'user_agent', 'dns_query', 'event_code', 'message', 'tags', 'raw', 'ip'];
function compile(q) {
  q = String(q || '').replace(/[()]/g, ' ').trim(); if (!q) return () => true;
  const alts = q.split(/\s+OR\s+/).map(part => {
    const toks = part.match(/NOT\s+\S+?:"(?:[^"\\]|\\.)*"|NOT\s+\S+|\S+?:"(?:[^"\\]|\\.)*"|"(?:[^"\\]|\\.)*"|\S+/g) || [];
    return toks.filter(t => t !== 'AND').map(t => {
      let neg = false; if (/^NOT\s+/.test(t)) { neg = true; t = t.replace(/^NOT\s+/, ''); }
      const m = /^([\w.]+):(.*)$/.exec(t);
      if (m) {
        const f = m[1]; let v = m[2]; if (FIELDS.indexOf(f) < 0 && !/^fields\./.test(f)) { const e = new Error('Unknown field "' + f + '"'); e.code = 400; throw e; }
        v = v.replace(/^"|"$/g, '').replace(/\\"/g, '"'); const pre = v.endsWith('*'); if (pre) v = v.slice(0, -1);
        const cmp = /^(>=|<=|>|<)(\d+)$/.exec(v);
        const get = ev => f === 'ip' ? [ev.src_ip, ev.dst_ip] : f.startsWith('fields.') ? [(ev.fields || {})[f.slice(7)]] : [Array.isArray(ev[f]) ? ev[f].join(' ') : ev[f]];
        const test = ev => get(ev).some(x => { x = x == null ? '' : String(x); if (cmp) { const a = +x, b = +cmp[2]; return cmp[1] === '>=' ? a >= b : cmp[1] === '<=' ? a <= b : cmp[1] === '>' ? a > b : a < b; } return pre ? x.toLowerCase().startsWith(v.toLowerCase()) : f === 'tags' ? x.split(' ').indexOf(v) >= 0 : x.toLowerCase() === v.toLowerCase(); });
        return ev => neg ? !test(ev) : test(ev);
      }
      const w = t.replace(/^"|"$/g, '').toLowerCase();
      return ev => { const hit = (ev.raw + ' ' + ev.message).toLowerCase().indexOf(w) >= 0; return neg ? !hit : hit; };
    });
  });
  return ev => alts.some(fs => fs.every(fn => fn(ev)));
}
function window_(b) { const f = Date.parse(b.from) || NOW - H, t = Date.parse(b.to) || Date.now(); return [f, t]; }
const outEv = e => Object.assign({}, e, { ts: new Date(e.ts).toISOString().replace('T', ' ').replace('Z', ''), rts: new Date(e.rts).toISOString().replace('T', ' ').replace('Z', '') });

/* ── HTTP ── */
function send(res, code, obj, type) { const body = typeof obj === 'string' || Buffer.isBuffer(obj) ? obj : JSON.stringify(obj); res.writeHead(code, { 'Content-Type': type || 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(body); }
function readBody(req) { return new Promise(r => { let d = ''; req.on('data', c => d += c); req.on('end', () => { try { r(d ? JSON.parse(d) : {}); } catch (e) { r({ __bad: true }); } }); }); }
function hist(a, id, by, action, detail) { a.history.push({ at: new Date().toISOString(), by, action, detail: detail || '' }); }
const isWrite = m => m !== 'GET';
function metrics() {
  const open = ALERTS.filter(a => !/^closed/.test(a.status)), ob = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 }; open.forEach(a => ob[a.severity]++);
  const days = []; for (let d = 13; d >= 0; d--) { const day = new Date(NOW - d * DAY).toISOString().slice(0, 10), o = { day }; [0, 1, 2, 3, 4].forEach(s => o[s] = 0); ALERTS.filter(a => a.ts_last.slice(0, 10) === day).forEach(a => o[a.severity] += 1); days.push(o); }
  const cnt = (list, key) => { const c = {}; list.forEach(x => { c[x[key]] = (c[x[key]] || 0) + 1; }); return Object.keys(c).map(k => ({ v: k, n: c[k] })).sort((a, b) => b.n - a.n).slice(0, 8); };
  const mitre = {}; ALERTS.forEach(a => a.mitre.forEach(m => mitre[m] = (mitre[m] || 0) + 1)); mitre['T9999'] = 1;
  return { generated: new Date().toISOString(), open_by_severity: ob, alerts_by_day: days, mttd_s: 94, mttr_s: 4 * 3600 + 1200, sla: { ack_breaches: 1, resolve_breaches: 1 }, open_cases: CASES.filter(c => c.status !== 'closed').length,
    top_rules: RULES.map(r => ({ rule_id: r.id, rule_name: r.name, n: ALERTS.filter(a => a.rule_id === r.id).length, noisy: !!r.noisy })).sort((a, b) => b.n - a.n),
    top_sources: cnt(EVENTS.slice(0, 800), 'src_id').map(x => ({ src_id: x.v, n: x.n })), top_hosts: cnt(EVENTS.slice(0, 800), 'host').map(x => ({ host: x.v, n: x.n })), top_users: cnt(EVENTS.slice(0, 800), 'user').map(x => ({ user: x.v, n: x.n })),
    noisy_rules: RULES.filter(r => r.noisy).map(r => ({ rule_id: r.id, rule_name: r.name, n: r.alerts_24h, fp_rate: 0.62 })), mitre };
}
async function api(req, res, u) {
  if (ST.offline) return send(res, 502, '<html><body><h1>502 Bad Gateway</h1>nginx</body></html>', 'text/html');
  const p = u.pathname.replace(/^\/api\/soc/, ''), m = req.method, by = ST.user;
  if (isWrite(m) && ST.role === 'viewer' && !/^\/(search|histogram|top)$/.test(p)) return send(res, 403, { error: 'Read-only role' });
  const b = isWrite(m) ? await readBody(req) : {};
  if (b.__bad) return send(res, 400, { error: 'Invalid JSON body' });
  let mm;
  if (p === '/health') return send(res, 200, { engine: { status: 'ok', version: '0.1.0-test', uptime_s: 86400 * 2 + 3600 }, clickhouse: { ok: true, version: '24.8 (test)', latency_ms: 3 }, spool: { files: 0, bytes: 0 },
    integrity: { status: 'verified', batches: 18234, last_verified: new Date(NOW - 5 * 6e4).toISOString(), last_hash: 'aa11bb22cc33dd44ee55ff66' }, eps: { now: 812, m1: 790, h1: 655 }, detector: { running: true, rules: RULES.filter(r => r.enabled).length, alerts_24h: 51 },
    collectors: [{ name: 'syslog-udp', listening: true, port: '127.0.0.1:5514', eps: 400 }, { name: 'syslog-tcp', listening: true, port: '127.0.0.1:5514', eps: 300 }, { name: 'syslog-tls', enabled: false, port: '6514' }, { name: 'http', listening: true, port: '/ingest/', eps: 90 }, { name: 'm365', status: 'error', error: 'SYNTHETIC: token expired' }] });
  if (p === '/search' && m === 'POST') {
    let fn; try { fn = compile(b.q); } catch (e) { return send(res, 400, { error: e.message }); }
    const [f, t] = window_(b), all = EVENTS.filter(e => e.ts >= f && e.ts <= t && fn(e)); if (b.order === 'asc') all.reverse();
    return send(res, 200, { rows: all.slice(0, Math.min(1000, b.limit || 100)).map(outEv), total_estimate: all.length, took_ms: 7, sql_hint: 'SELECT … FROM siem.events WHERE ts BETWEEN {p1:DateTime64} AND {p2:DateTime64} AND action = {p3:String} (synthetic)' });
  }
  if (p === '/histogram' && m === 'POST') {
    let fn; try { fn = compile(b.q); } catch (e) { return send(res, 400, { error: e.message }); }
    const [f, t] = window_(b), n = b.buckets || 60, w = (t - f) / n, out = []; for (let i = 0; i < n; i++) out.push({ t: new Date(f + i * w).toISOString(), n: 0 });
    EVENTS.forEach(e => { if (e.ts >= f && e.ts < t && fn(e)) out[Math.min(n - 1, Math.floor((e.ts - f) / w))].n++; });
    return send(res, 200, { buckets: out });
  }
  if (p === '/top' && m === 'POST') {
    let fn; try { fn = compile(b.q); } catch (e) { return send(res, 400, { error: e.message }); }
    const [f, t] = window_(b), c = {}; EVENTS.forEach(e => { if (e.ts >= f && e.ts <= t && fn(e)) { const v = String(e[b.field] == null ? '' : e[b.field]); c[v] = (c[v] || 0) + 1; } });
    return send(res, 200, { values: Object.keys(c).map(v => ({ v, n: c[v] })).sort((x, y) => y.n - x.n).slice(0, b.limit || 10) });
  }
  if (p === '/tail') {
    let fn; try { fn = compile(u.searchParams.get('q')); } catch (e) { return send(res, 400, { error: e.message }); }
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' }); res.write(': synthetic tail\n\n');
    const iv = setInterval(() => { for (let i = 0; i < 3; i++) { const e = mkEvent(Date.now()); if (fn(e)) res.write('data: ' + JSON.stringify(outEv(e)) + '\n\n'); } }, 1000);
    req.on('close', () => clearInterval(iv)); return;
  }
  if (p === '/sources') return send(res, 200, { sources: SOURCES.map((s, i) => Object.assign({}, s, { last_seen: new Date(i === 5 ? NOW - 3 * H : i === 7 ? NOW - 2 * DAY : Date.now() - i * 7000).toISOString(), eps_1m: i === 5 || i === 7 ? 0 : 5 + i * 13.4, eps_1h: 4 + i * 11.2, events_today: i === 7 ? 0 : 20000 + i * 5311, parse_error_rate: i === 6 ? 0.084 : i === 2 ? 0.012 : 0.0004 })) });
  if (p === '/metrics') return send(res, 200, metrics());
  if (p === '/lr-compare') return send(res, 200, { configured: true, window: { from: new Date(NOW - 7 * DAY).toISOString(), to: new Date(NOW).toISOString() }, both: 41, only_ours: 9, only_lr: 4,
    per_rule: [{ rule: '[TEST] Brute force against one account', both: 20, only_ours: 5, only_lr: 1 }, { rule: '[TEST] IPS detection from the internet', both: 15, only_ours: 4, only_lr: 0 }, { rule: 'LR: Impossible travel (test)', both: 0, only_ours: 0, only_lr: 3 }],
    per_source: [{ src: 'test-fw-01', both: 25, only_ours: 6, only_lr: 1 }, { src: 'test-dc-01', both: 16, only_ours: 3, only_lr: 3 }] });
  /* rules */
  if (p === '/rules' && m === 'GET') return send(res, 200, { rules: RULES });
  if (p === '/rules' && m === 'POST') { if (ST.role !== 'admin') return send(res, 403, { error: 'Rule changes need the admin role' }); const r = b.rule || {}; if (!r.id || !r.name) return send(res, 400, { error: 'Invalid rule', errors: ['id and name are required'] }); const i = RULES.findIndex(x => x.id === r.id); const nr = Object.assign({ alerts_24h: 0, origin: 'native' }, i >= 0 ? { alerts_24h: RULES[i].alerts_24h, origin: RULES[i].origin } : {}, r); if (i >= 0) RULES[i] = nr; else RULES.push(nr); return send(res, 200, { ok: true, rule: nr }); }
  if (p === '/rules/test' && m === 'POST') { const r = b.rule || {}; return send(res, 200, { events_scanned: 12840, took_ms: 212, truncated: false, alerts: [0, 1, 2].map(i => ({ ts_first: new Date(NOW - (i + 2) * H).toISOString(), ts_last: new Date(NOW - (i + 1) * H).toISOString(), group: { user: USERS[i] }, count: 10 + i, summary: '[SYNTHETIC] would-be alert for ' + (r.id || '?') })) }); }
  if (p === '/rules/sigma' && m === 'POST') { if (!/detection:/.test(b.yaml || '')) return send(res, 400, { error: 'Not a Sigma rule', errors: ['missing "detection" section'] }); if (!b.dry_run && ST.role !== 'admin') return send(res, 403, { error: 'Rule changes need the admin role' }); const rule = { id: 'SENTRA-SIGMA-' + (100 + RULES.length), name: '[TEST] ' + ((/title:\s*(.+)/.exec(b.yaml) || [])[1] || 'Imported Sigma rule'), enabled: false, severity: 2, mitre: ['T1110'], description: 'Converted from Sigma (synthetic)', type: 'single', match: { all: [{ field: 'event_code', op: 'eq', value: '4625' }], any: [], none: [] }, suppress_s: 3600, sigma_id: 'test' }; if (!b.dry_run) RULES.push(Object.assign({ alerts_24h: 0, origin: 'sigma' }, rule)); return send(res, 200, { rule, warnings: ['logsource.product "windows" mapped to src_type windows (synthetic warning)'] }); }
  if ((mm = /^\/rules\/([^/]+)\/enable$/.exec(p)) && m === 'POST') { if (ST.role !== 'admin') return send(res, 403, { error: 'Rule changes need the admin role' }); const r = RULES.find(x => x.id === decodeURIComponent(mm[1])); if (!r) return send(res, 404, { error: 'No such rule' }); r.enabled = !!b.enabled; return send(res, 200, { ok: true }); }
  if ((mm = /^\/rules\/([^/]+)$/.exec(p)) && m === 'GET') { const r = RULES.find(x => x.id === decodeURIComponent(mm[1])); return r ? send(res, 200, { rule: r }) : send(res, 404, { error: 'No such rule' }); }
  /* alerts */
  if (p === '/alerts' && m === 'GET') {
    const q = u.searchParams; let l = ALERTS.slice();
    const st = q.get('status'); if (st === 'open') l = l.filter(a => !/^closed/.test(a.status)); else if (st === 'closed') l = l.filter(a => /^closed/.test(a.status)); else if (st && st !== 'all') l = l.filter(a => a.status === st);
    if (q.get('min_severity')) l = l.filter(a => a.severity >= +q.get('min_severity')); if (q.get('rule_id')) l = l.filter(a => a.rule_id === q.get('rule_id')); if (q.get('case_id')) l = l.filter(a => a.case_id === q.get('case_id'));
    if (q.get('assignee')) l = l.filter(a => a.assignee === q.get('assignee')); if (q.get('unassigned')) l = l.filter(a => !a.assignee); if (q.get('from')) l = l.filter(a => Date.parse(a.ts_last) >= Date.parse(q.get('from')));
    return send(res, 200, { alerts: l, total: l.length });
  }
  if (p === '/alerts/bulk' && m === 'POST') {
    (b.ids || []).forEach(id => { const a = ALERTS.find(x => x.id === id); if (!a) return; if (b.action === 'ack' && a.status === 'new') { a.status = 'acknowledged'; hist(a, id, by, 'acknowledged'); } if (b.action === 'assign') { a.assignee = b.assignee; if (a.status === 'new') a.status = 'acknowledged'; hist(a, id, by, 'assigned', b.assignee); } if (b.action === 'close') { a.status = 'closed-' + b.reason; hist(a, id, by, 'closed', b.reason + (b.note ? ': ' + b.note : '')); } });
    return send(res, 200, { ok: true, updated: (b.ids || []).length });
  }
  if ((mm = /^\/alerts\/([^/]+)(?:\/(ack|assign|close|note))?$/.exec(p))) {
    const a = ALERTS.find(x => x.id === decodeURIComponent(mm[1])); if (!a) return send(res, 404, { error: 'No such alert' });
    if (m === 'GET') return send(res, 200, a);
    if (mm[2] === 'ack') { a.status = 'acknowledged'; hist(a, a.id, by, 'acknowledged'); }
    if (mm[2] === 'assign') { a.assignee = b.assignee; hist(a, a.id, by, 'assigned', b.assignee); }
    if (mm[2] === 'close') { if (['true-positive', 'false-positive', 'benign'].indexOf(b.reason) < 0) return send(res, 400, { error: 'reason must be true-positive, false-positive or benign' }); a.status = 'closed-' + b.reason; hist(a, a.id, by, 'closed', b.reason); }
    if (mm[2] === 'note') { a.notes.push({ at: new Date().toISOString(), by, text: b.text }); hist(a, a.id, by, 'note'); }
    return send(res, 200, a);
  }
  /* cases */
  if (p === '/cases' && m === 'GET') { const st = u.searchParams.get('status'); let l = CASES.slice(); if (st === 'active') l = l.filter(c => c.status !== 'closed'); else if (st && st !== 'all') l = l.filter(c => c.status === st); return send(res, 200, { cases: l.map(c => Object.assign({}, c, { timeline: undefined })) }); }
  if (p === '/cases' && m === 'POST') { const c = mkCase(124 + CASES.length, b.title || 'Untitled', b.severity || 2, 'open', b.alert_ids || [], Date.now() + H, Date.now() + DAY); c.timeline[0].by = by; return send(res, 200, { case: c }); }
  if ((mm = /^\/cases\/([^/]+)(?:\/(status|owner|notes|evidence|alerts|tasks)(?:\/([^/]+))?)?$/.exec(p))) {
    const c = CASES.find(x => x.id === decodeURIComponent(mm[1])); if (!c) return send(res, 404, { error: 'No such case' });
    if (m === 'GET') return send(res, 200, c);
    const tl = (kind, text) => c.timeline.push({ at: new Date().toISOString(), by, kind, text });
    if (mm[2] === 'status') { if (b.status === 'closed' && !b.resolution) return send(res, 400, { error: 'resolution required' }); c.status = b.status; if (b.status === 'closed') { c.closed = new Date().toISOString(); c.resolution = b.resolution; } tl('status', 'Status → ' + b.status); }
    if (mm[2] === 'owner') { c.owner = b.owner; tl('owner', 'Owner → ' + b.owner); }
    if (mm[2] === 'notes') tl('note', b.text);
    if (mm[2] === 'evidence') { c.evidence.push({ at: new Date().toISOString(), by, name: b.name, ref: b.ref }); tl('evidence', 'Evidence added: ' + b.name); }
    if (mm[2] === 'alerts') { (b.alert_ids || []).forEach(id => { if (c.alerts.indexOf(id) < 0) c.alerts.push(id); const a = ALERTS.find(x => x.id === id); if (a) a.case_id = c.id; }); tl('alerts', 'Alerts linked: ' + (b.alert_ids || []).join(', ')); }
    if (mm[2] === 'tasks') { const t = c.tasks.find(x => x.id === decodeURIComponent(mm[3] || '')); if (!t) return send(res, 404, { error: 'No such task' }); t.done = !!b.done; t.by = by; t.at = new Date().toISOString(); tl('task', (t.done ? 'Done: ' : 'Reopened: ') + t.title); }
    return send(res, 200, { case: c });
  }
  return send(res, 404, { error: 'No such endpoint (mock)' });
}
function portalIndex() {
  let s = fs.readFileSync(path.join(PORTAL, 'index.html'), 'utf8');
  const nav = JSON.parse(fs.readFileSync(path.join(UI, 'sentra-soc-nav.json'), 'utf8'));
  nav.forEach(([anchor, view, icon, label]) => {
    if (s.indexOf('data-view="' + view + '"') >= 0) return;
    const re = new RegExp('<li data-view="' + anchor.replace(/[-]/g, '\\-') + '"[^>]*>.*?</li>|<li [^>]*data-view="' + anchor.replace(/[-]/g, '\\-') + '"[^>]*>.*?</li>');
    const m = re.exec(s); if (!m) { console.warn('anchor not found', anchor); return; }
    s = s.replace(m[0], m[0] + '\n      <li data-view="' + view + '" data-en="' + label + '"><span class="ico">' + icon + '</span> ' + label + '</li>');
  });
  return s.replace(/src="app\.js\?v=\d+"/, 'src="app.js?v=mock' + Date.now() + '"');
}
function portalApp() {
  const base = fs.readFileSync(path.join(PORTAL, 'app.js'), 'utf8');
  const dict = fs.readFileSync(path.join(UI, 'sentra-soc.ar.json'), 'utf8');
  const mod = fs.readFileSync(path.join(UI, 'sentra-soc-module.js'), 'utf8');
  const wrap = '/* ===================== ZS-AR-DICT (SOC) ===================== */\n(function () { var D = window.X_AR = window.X_AR || {}; var o = ' + dict.trim() + '; for (var k in o) D[k] = o[k]; try { if (typeof AR === "object" && AR) for (var j in o) if (!(j in AR)) AR[j] = o[j]; } catch (e) {} })();\n/* ===================== /ZS-AR-DICT (SOC) ===================== */\n';
  return base.replace(/\n?$/, '\n') + wrap + mod;
}
http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost');
  try {
    if (u.pathname.startsWith('/api/soc')) return api(req, res, u).catch(e => send(res, 500, { error: String(e && e.message || e) }));
    if (u.pathname.startsWith('/__role/')) { ST.role = u.pathname.slice(8); return send(res, 200, ST); }
    if (u.pathname.startsWith('/__offline/')) { ST.offline = u.pathname.endsWith('/on'); return send(res, 200, ST); }
    if (u.pathname === '/__state') return send(res, 200, ST);
    if (u.pathname === '/auth/whoami') return send(res, 200, { user: ST.user, role: ST.role, method: 'mock' });
    if (u.pathname === '/' || u.pathname === '/index.html') return send(res, 200, portalIndex(), 'text/html; charset=utf-8');
    if (u.pathname === '/app.js') return send(res, 200, portalApp(), 'application/javascript; charset=utf-8');
    if (u.pathname.startsWith('/api/') || u.pathname.startsWith('/auth/')) return send(res, 404, { error: 'not mocked' });
    const f = path.join(PORTAL, path.normalize(u.pathname).replace(/^([\\/]\.\.)+/, ''));
    if (f.startsWith(PORTAL.replace(/\//g, path.sep)) && fs.existsSync(f) && fs.statSync(f).isFile()) { const ext = path.extname(f); return send(res, 200, fs.readFileSync(f), { '.webp': 'image/webp', '.js': 'application/javascript', '.html': 'text/html', '.css': 'text/css' }[ext] || 'application/octet-stream'); }
    return send(res, 404, 'not found', 'text/plain');
  } catch (e) { console.error(e); send(res, 500, { error: String(e.message) }); }
}).listen(PORT, () => console.log('SOC mock on http://localhost:' + PORT + '/#soc-dashboard  (synthetic test data only)'));
