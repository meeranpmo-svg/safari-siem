// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * XDR - one incident per attack across every security domain the SIEM already collects.
 *
 * The detection rules raise alerts per source (an EDR detection, a risky Microsoft 365 sign-in, an IPS hit, a forwarding
 * rule in Exchange). XDR joins the alerts that are about the same thing - the same user, host or internal IP within the
 * link window - into one incident, and says which domains it crosses (endpoint, identity, network, email, web, data,
 * server), which ATT&CK tactics it walks through, and why it scores what it scores. Nothing is invented: an incident is
 * built only from alerts the engine raised; an entity the portal has no record of adds nothing to the score.
 *
 *   createXdr({ alerts, cases, ueba?, playbooks, ch?, config?, log? })
 *     → { incidents(q), incident(id), promote(id, by), coverage(), hunts(), runHunt(id, {from,to}), beacons({hours}),
 *         leads(), autoTick(), settings(), domainOf(alert) }
 *
 * Correlation (pure, see correlate()):
 *   - alerts considered: not LogRhythm-imported, not operational (Oracle performance, infrastructure faults, "source
 *     went silent"), last seen inside lookback_h (default 72 h);
 *   - entities: user (DOMAIN\ prefix dropped, lower-case; UPN reduced to its account only for config.xdr.internal_domains),
 *     host (lower-case, DNS suffix dropped), IP (internal and external);
 *   - two alerts link when they share an entity and are at most link_window_h (default 24 h) apart;
 *   - an entity value seen in more than hub_max alerts (default 40) is a hub (a scanner IP, a proxy, the domain
 *     controller) and does not link - otherwise one busy server would merge every incident into one. Hubs are listed.
 * Score 0-100, every point itemised in why[]: worst severity x15 (max 60), +10 per extra domain (max 30), +5 per extra
 * ATT&CK tactic (max 20), +10 threat-intel match, +10 an entity UEBA rates high/critical. Capped at 100.
 *
 * Response never executes anything: promote() opens a case with the incident's alerts and the suggested playbook; the
 * case raises the playbook's approval requests (engine/soc/cases.js), exactly as an analyst-opened case does. The
 * optional auto-case (config.xdr.auto_case_score, off by default) does the same for incidents at or above that score.
 */
const crypto = require('node:crypto');
const XML = require('./xdr-ml');

const DOMAINS = ['endpoint', 'identity', 'network', 'email', 'web', 'data', 'server', 'cloud', 'other'];
const DOMAIN_NAMES = { endpoint: 'Endpoint', identity: 'Identity', network: 'Network', email: 'Email', web: 'Web', data: 'Data', server: 'Server / database', cloud: 'Cloud', other: 'Other' };
// rule family (SENTRA-<FAMILY>-nnn) → domain
const FAMILY = {
  EDR: 'endpoint', EXEC: 'endpoint', CRED: 'endpoint', SYS: 'endpoint', SOM: 'data',
  AUTH: 'identity', AD: 'identity', IAM: 'identity', M365: 'identity', NPS: 'identity', VPN: 'identity', SCH: 'identity',
  FW: 'network', FGT: 'network', PAN: 'network', NSC: 'network', INTEL: 'network', SP: 'network',
  MAIL: 'email', EXO: 'email', WEB: 'web', WAF: 'web', ZSC: 'web', DLP: 'data', EXFIL: 'data',
  LNX: 'server', ORA: 'server', SQL: 'server', UEBA: 'identity',
};
const OPERATIONAL = new Set(['ORAP', 'OPS']);
const SRC_DOMAIN = [
  [/edr|kaspersky|sentinel|crowdstrike|defender.?endpoint|sysmon|somansa/i, 'endpoint'],
  [/exchange|mail|smtp|o365.?mail|proofpoint|mimecast/i, 'email'],
  [/m365|entra|azure.?ad|windows|ad\b|ldap|radius|nps/i, 'identity'],
  [/forti|palo|pan-?os|firewall|cisco|aruba|huawei|switch|netscaler|silverpeak|ips|netflow|syslog/i, 'network'],
  [/waf|proxy|zscaler|web|nginx|iis|apache|cloudflare/i, 'web'],
  [/dlp/i, 'data'],
  [/linux|oracle|mssql|sql|unix|solaris/i, 'server'],
  [/sharepoint|onedrive|cloud|aws|gcp/i, 'cloud'],
];
const SEVN = ['info', 'low', 'medium', 'high', 'critical'];

function familyOf(a) { const m = /^SENTRA-([A-Z0-9]+)-/.exec(String(a.rule_id || '')); return m ? m[1] : (/^UEBA-/.test(String(a.rule_id || '')) ? 'UEBA' : ''); }
function isOperational(a) {
  const f = familyOf(a);
  if (OPERATIONAL.has(f)) return true;
  if (a.rule_type === 'health' || a.rule_type === 'operational') return true;
  return /went silent|log source .*silent|collector health/i.test(String(a.rule_name || ''));
}
function domainOf(a) {
  const f = familyOf(a);
  if (FAMILY[f]) return FAMILY[f];
  const s = `${a.src_type || ''} ${a.src_id || ''} ${(a.fields && a.fields.src_type) || ''}`;
  for (const [re, d] of SRC_DOMAIN) if (re.test(s)) return d;
  return 'other';
}

function isPrivateIp(ip) {
  const s = String(ip || '');
  if (/^10\.|^192\.168\.|^127\.|^169\.254\./.test(s)) return true;
  const m = /^172\.(\d+)\./.exec(s); if (m && +m[1] >= 16 && +m[1] <= 31) return true;
  return /^(fc|fd|fe80)/i.test(s);
}
function normUser(u, internal) {
  let s = String(u || '').trim().toLowerCase(); if (!s || s === '-' || s === 'system' || s.endsWith('$')) return '';
  const bs = s.lastIndexOf('\\'); if (bs >= 0) s = s.slice(bs + 1);
  const at = s.indexOf('@'); if (at > 0 && internal.has(s.slice(at + 1))) s = s.slice(0, at);
  return s;
}
function normHost(h) {
  let s = String(h || '').trim().toLowerCase(); if (!s || s === '-' || s === 'localhost') return '';
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(s)) s = s.split('.')[0];
  return s;
}
/** entity keys of one alert: ['user:alice', 'host:pc-17', 'ip:10.1.2.3', …] */
function entitiesOf(a, internal) {
  const bag = Object.assign({}, a.fields || {}, a.group || {});
  const out = new Set();
  for (const k of ['user', 'target_user', 'account', 'upn']) { const u = normUser(bag[k], internal); if (u) out.add('user:' + u); }
  for (const k of ['host', 'computer', 'device', 'hostname']) { const h = normHost(k === 'host' ? (a.host || bag.host) : bag[k]); if (h) out.add('host:' + h); }
  // UEBA alerts name their entity as "<type>:<name>" (engine/ueba/entities.js entityId)
  for (const v of [bag.entity, bag.entity_id]) {
    const m = /^(user|service_account|host):(.+)$/.exec(String(v || ''));
    if (m) { const e = m[1] === 'host' ? normHost(m[2]) : normUser(m[2], internal); if (e) out.add((m[1] === 'host' ? 'host:' : 'user:') + e); }
  }
  for (const k of ['src_ip', 'dst_ip', 'host_ip', 'client_ip']) { const ip = String(bag[k] || '').trim(); if (ip && ip !== '0.0.0.0' && ip !== '-') out.add((isPrivateIp(ip) ? 'ip:' : 'xip:') + ip); }
  return [...out];
}

/** technique / rule tactic → ATT&CK tactic key; catalog = bas/attack-catalog.json */
function makeTactics(catalog, ruleTactic) {
  const tech = (catalog && catalog.techniques) || {};
  const order = new Map(((catalog && catalog.tactics) || []).map((t) => [t.key, t]));
  const revoked = (catalog && catalog.revoked) || {}, aliases = (catalog && catalog.tactic_aliases) || {};   // ATT&CK v20 renames
  return {
    of(a) {
      const out = new Set();
      const rt = ruleTactic(a.rule_id); if (rt) out.add(aliases[rt] || rt);
      for (const m0 of Array.isArray(a.mitre) ? a.mitre : []) { const m = revoked[m0] || m0; const t = tech[m] || tech[String(m).split('.')[0]]; if (t && t.tactic) out.add(t.tactic); }
      return [...out];
    },
    sort(keys) { return [...keys].sort((x, y) => ((order.get(x) || {}).order || 99) - ((order.get(y) || {}).order || 99)); },
    name(k) { return (order.get(k) || {}).name || k; },
  };
}

/**
 * correlate(alerts[], { now, lookbackH, linkWindowH, hubMax, internalDomains, tactics, riskOf(entityKey)→tier }) →
 *   { incidents[], hubs[], considered, excluded{operational, lr, old} }
 */
function correlate(list, o = {}) {
  const now = o.now || Date.now();
  const lookback = (o.lookbackH || 72) * 3600e3, win = (o.linkWindowH || 24) * 3600e3, hubMax = o.hubMax || 40;
  const internal = new Set((o.internalDomains || []).map((d) => String(d).toLowerCase()));
  const tactics = o.tactics || { of: () => [], sort: (k) => k, name: (k) => k };
  const excluded = { operational: 0, lr: 0, old: 0 };
  const al = [];
  for (const a of list) {
    if (a.source === 'logrhythm') { excluded.lr++; continue; }
    if (isOperational(a)) { excluded.operational++; continue; }
    if ((a.ts_last || a.ts_first || 0) < now - lookback) { excluded.old++; continue; }
    al.push({ a, ents: entitiesOf(a, internal), t0: a.ts_first || a.ts_last || 0, t1: a.ts_last || a.ts_first || 0 });
  }
  // entity → alert indices; hubs are entities in more than hubMax alerts
  const byEnt = new Map();
  al.forEach((x, i) => x.ents.forEach((e) => { if (!byEnt.has(e)) byEnt.set(e, []); byEnt.get(e).push(i); }));
  const hubs = [];
  const parent = al.map((_, i) => i);
  const find = (i) => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; };
  const join = (i, j) => { const a = find(i), b = find(j); if (a !== b) parent[Math.max(a, b)] = Math.min(a, b); };
  for (const [e, idx] of byEnt) {
    if (idx.length > hubMax) { hubs.push({ entity: e, alerts: idx.length }); continue; }
    const s = idx.slice().sort((p, q) => al[p].t0 - al[q].t0);
    let reach = al[s[0]].t1, head = s[0];
    for (let k = 1; k < s.length; k++) {
      const x = al[s[k]];
      if (x.t0 - reach <= win) join(head, s[k]); else head = s[k];
      reach = Math.max(reach, x.t1);
    }
  }
  const groups = new Map();
  al.forEach((x, i) => { const r = find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(x); });
  const incidents = [];
  for (const g of groups.values()) incidents.push(buildIncident(g, tactics, o.riskOf, hubs));
  incidents.sort((x, y) => y.score - x.score || y.last - x.last);
  hubs.sort((x, y) => y.alerts - x.alerts);
  return { incidents, hubs, considered: al.length, excluded };
}

function buildIncident(g, tactics, riskOf, hubs) {
  const hubSet = new Set(hubs.map((h) => h.entity));
  const alerts = g.map((x) => x.a).sort((p, q) => (p.ts_first || 0) - (q.ts_first || 0));
  const ids = alerts.map((a) => a.id).sort();
  const domains = {}, tacs = new Set(), techs = new Set(), ents = { users: new Set(), hosts: new Set(), ips: new Set(), external_ips: new Set() };
  let sev = 0, intel = false, open = false, first = Infinity, last = 0;
  const cases = new Set();
  for (const x of g) {
    const a = x.a, d = domainOf(a);
    domains[d] = (domains[d] || 0) + 1;
    tactics.of(a).forEach((t) => tacs.add(t));
    (Array.isArray(a.mitre) ? a.mitre : []).forEach((m) => techs.add(String(m)));
    sev = Math.max(sev, Number(a.severity) || 0);
    if (familyOf(a) === 'INTEL' || (a.fields && (a.fields.intel_list || a.fields.ioc))) intel = true;
    if (!/^closed/.test(String(a.status || 'new'))) open = true;
    if (a.case_id) cases.add(a.case_id);
    first = Math.min(first, a.ts_first || a.ts_last || 0); last = Math.max(last, a.ts_last || a.ts_first || 0);
    for (const e of x.ents) {
      const [k, v] = [e.slice(0, e.indexOf(':')), e.slice(e.indexOf(':') + 1)];
      (k === 'user' ? ents.users : k === 'host' ? ents.hosts : k === 'ip' ? ents.ips : ents.external_ips).add(v);
    }
  }
  const nd = Object.keys(domains).filter((d) => d !== 'other').length || 1;
  const why = [];
  const add = (pts, reason) => { if (pts) why.push({ points: pts, reason }); return pts; };
  let score = add(sev * 15, `worst alert severity ${SEVN[sev]} (${sev} x 15)`);
  score += add(Math.min(30, (nd - 1) * 10), nd > 1 ? `crosses ${nd} domains (${Object.keys(domains).filter((d) => d !== 'other').join(', ')})` : '');
  score += add(Math.min(20, Math.max(0, tacs.size - 1) * 5), tacs.size > 1 ? `${tacs.size} ATT&CK tactics: ${tactics.sort(tacs).map((t) => tactics.name(t)).join(' → ')}` : '');
  if (intel) score += add(10, 'threat-intelligence match (known-bad IP / domain)');
  if (riskOf) {
    const risky = [...ents.users].map((u) => ['user', u]).concat([...ents.hosts].map((h) => ['host', h]))
      .map(([k, v]) => ({ k, v, tier: riskOf(k, v) })).filter((r) => r.tier === 'high' || r.tier === 'critical');
    if (risky.length) score += add(10, `UEBA rates ${risky.map((r) => `${r.v} ${r.tier}`).slice(0, 3).join(', ')}`);
  }
  score = Math.min(100, score);
  const root = ids[0];
  const title = alerts.length === 1 ? alerts[0].rule_name
    : `${tactics.sort(tacs).map((t) => tactics.name(t)).slice(-1)[0] || 'Correlated activity'} - ${[...ents.users][0] || [...ents.hosts][0] || [...ents.ips][0] || [...ents.external_ips][0] || 'multiple entities'}`;
  return {
    id: 'XDR-' + crypto.createHash('sha256').update(root).digest('hex').slice(0, 10).toUpperCase(),
    root_alert: root, title: String(title || 'Correlated activity').slice(0, 160), score, why, severity: sev,
    status: open ? 'open' : 'closed', alerts: alerts.length, alert_ids: alerts.map((a) => a.id),
    domains, domain_count: nd, tactics: tactics.sort(tacs), techniques: [...techs].sort(), intel,
    entities: { users: [...ents.users], hosts: [...ents.hosts], ips: [...ents.ips], external_ips: [...ents.external_ips] },
    linked_by: [...new Set(g.flatMap((x) => x.ents))].filter((e) => !hubSet.has(e) && g.filter((y) => y.ents.includes(e)).length > 1),
    cases: [...cases], first: first === Infinity ? 0 : first, last,
  };
}

// ---------------------------------------------------------------- hunting
// Each hunt is a query in the engine's own search language (engine/api/query.js), run over the event store - never
// a new parser, never a write. A hit is a lead to look at, not a detection.
const HUNTS = [
  { id: 'H-PS-ENC', name: 'Encoded or obfuscated PowerShell', tactic: 'execution', mitre: ['T1059.001', 'T1027'], q: 'cmdline:"-enc" OR cmdline:"-encodedcommand" OR cmdline:"FromBase64String" OR cmdline:"IEX"', why: 'Attackers hide PowerShell payloads in base64. Admin scripts rarely need it.' },
  { id: 'H-LOLBIN', name: 'Living-off-the-land binaries', tactic: 'stealth', mitre: ['T1218'], q: 'process:(*certutil.exe *mshta.exe *regsvr32.exe *rundll32.exe *bitsadmin.exe *wmic.exe)', why: 'Signed Windows tools abused to download or run code without dropping malware.' },
  { id: 'H-ADMINSHARE', name: 'Remote execution over admin shares (PsExec style)', tactic: 'lateral-movement', mitre: ['T1021.002', 'T1569.002'], q: 'process:*psexec* OR cmdline:"admin$" OR cmdline:"\\\\c$"', why: 'Lateral movement from one server to another with administrator credentials.' },
  { id: 'H-PERSIST', name: 'New services and scheduled tasks', tactic: 'persistence', mitre: ['T1543.003', 'T1053.005'], q: 'action:(service-installed scheduled-task-created)', why: 'How malware survives a reboot. Expected after a planned installation only.' },
  { id: 'H-PRIV', name: 'Privileged group and privilege changes', tactic: 'privilege-escalation', mitre: ['T1098'], q: 'action:(group-member-added privilege-granted user-created)', why: 'Every change should match a change ticket.' },
  { id: 'H-TAMPER', name: 'Audit log cleared or auditing disabled', tactic: 'defense-impairment', mitre: ['T1685.005', 'T1685.001'], q: 'action:(audit-log-cleared audit-disabled)', why: 'An attacker covering tracks. Almost never legitimate.' },
  { id: 'H-RDP-EXT', name: 'Remote desktop logons from outside the network', tactic: 'initial-access', mitre: ['T1133', 'T1021.001'], q: 'action:logon fields.logon_type:10 NOT src_ip:10.0.0.0/8 NOT src_ip:172.16.0.0/12 NOT src_ip:192.168.0.0/16 NOT src_ip:127.0.0.1', why: 'RDP should arrive through the VPN, from an internal address.' },
  { id: 'H-C2-PORTS', name: 'Outbound traffic to common backdoor ports', tactic: 'command-and-control', mitre: ['T1571'], q: 'dst_port:(4444 1337 6667 6697 8081 9001 31337) NOT dst_ip:10.0.0.0/8 NOT dst_ip:172.16.0.0/12 NOT dst_ip:192.168.0.0/16', why: 'Ports used by default by Metasploit, IRC bots and Tor.' },
  { id: 'H-FAIL-OK', name: 'Failed logons followed by success (all accounts)', tactic: 'credential-access', mitre: ['T1110'], q: 'action:logon-failed', why: 'Below the brute-force threshold, but worth pivoting by user to see who then got in.' },
];

function createXdr(deps = {}) {
  const { alerts, cases, ueba, playbooks, ch, log = { info() {}, warn() {}, error() {} } } = deps;
  // settings: defaults <- config.json "xdr" <- what an administrator saved on the XDR page (state collection xdr_settings)
  const store = deps.state && typeof deps.state.collection === 'function' ? deps.state.collection('xdr_settings') : null;
  const saved = () => { try { const r = store && store.get('settings'); return (r && r.values) || {}; } catch { return {}; } };
  const cfg = () => Object.assign({ lookback_h: 72, link_window_h: 24, hub_max: 40, internal_domains: [], auto_case_score: 0 }, (deps.config && deps.config.xdr) || {}, saved());
  let lastTick = null, autoOpened = 0;
  let catalog = null; try { catalog = require('../bas/attack-catalog.json'); } catch { catalog = null; }
  const ruleTactic = (id) => {
    try { const d = deps.detector; const rs = d && typeof d.rules === 'function' ? d.rules() : []; const r = (rs || []).find((x) => x.id === id); return r && r.tactic ? String(r.tactic) : ''; } catch { return ''; }
  };
  const tactics = makeTactics(catalog, ruleTactic);
  const riskOf = (kind, v) => {
    if (!ueba || typeof ueba.entities !== 'function') return '';
    try { const r = ueba.entities({ type: kind, q: v, limit: 5 }); const e = (r.items || []).find((x) => String(x.name || '').toLowerCase() === v || String(x.id || '').toLowerCase().endsWith(':' + v)); return e ? e.risk_tier : ''; } catch { return ''; }
  };
  let cache = null;
  function run() {
    if (cache && Date.now() - cache.at < 15000) return cache.r;
    const c = cfg();
    const list = typeof alerts.all === 'function' ? alerts.all() : (alerts.list({ status: 'all', limit: 500 }).items || []);
    const r = correlate(list, { lookbackH: c.lookback_h, linkWindowH: c.link_window_h, hubMax: c.hub_max, internalDomains: c.internal_domains, tactics, riskOf });
    cache = { at: Date.now(), r };
    return r;
  }

  // ---- machine learning over 90 days of correlated incidents (xdr-ml.js): next tactic, similar past incidents, trend
  function intel() {
    const c = cfg(), now = Date.now(), get = (id) => alerts.get(id);
    const list = typeof alerts.all === 'function' ? alerts.all() : (alerts.list({ status: 'all', limit: 500 }).items || []);
    const hist = correlate(list, { lookbackH: 90 * 24, linkWindowH: c.link_window_h, hubMax: c.hub_max, internalDomains: c.internal_domains, tactics }).incidents.filter((i) => i.alerts > 1 || i.severity >= 3);
    const seqOf = (i) => { const out = []; for (const a of i.alert_ids.map(get).filter(Boolean).sort((p, q) => (p.ts_first || 0) - (q.ts_first || 0))) for (const t of tactics.of(a)) if (out[out.length - 1] !== t) out.push(t); return out; };
    const rulesOf = (i) => [...new Set(i.alert_ids.map(get).filter(Boolean).map((a) => a.rule_id))];
    for (const i of hist) { i.seq = seqOf(i); i.rules = rulesOf(i); }
    const chain = XML.learnChain(hist.map((i) => i.seq));
    const verdictOf = (p) => { const n = { 'true-positive': 0, 'false-positive': 0, benign: 0 }; for (const a of p.alert_ids.map(get).filter(Boolean)) { const s = String(a.status || '').replace(/^closed-/, ''); if (n[s] !== undefined) n[s]++; }
      const k = Object.keys(n).sort((x, y) => n[y] - n[x])[0]; return { verdict: n[k] ? k : 'unknown', counts: n, cases: p.cases }; };
    const past = hist.filter((i) => i.status !== 'open'), open = hist.filter((i) => i.status === 'open').sort((a, b) => b.score - a.score).slice(0, 50);
    const name = (t) => tactics.name(t);
    const per = {};
    for (const i of open) per[i.id] = { next: i.seq.length ? XML.predictNext(chain, i.seq[i.seq.length - 1], name, i.seq) : null, similar: XML.similarPast(i, past, verdictOf), sequence: i.seq.map(name) };
    const top = [];
    for (const [a, m] of chain.T) for (const [b, n] of m) top.push({ from: name(a), to: name(b), n });
    return { generated_at: now, history: { incidents: hist.length, closed: past.length, transitions: chain.total }, trend: XML.trend(hist, now), incidents: per,
      transitions: top.sort((x, y) => y.n - x.n).slice(0, 12),
      note: 'Learned from this SIEM\'s own correlated incidents over 90 days. The next tactic is a statistical lead to watch for, not a prediction of what the attacker will do; similar past incidents are there to read, not a verdict.' };
  }
  function brief(i) { const x = Object.assign({}, i); delete x.alert_ids; return x; }
  function incidents(q = {}) {
    const r = run(); let L = r.incidents;
    const scope = q.scope || 'correlated';
    if (scope === 'correlated') L = L.filter((i) => i.alerts > 1 || i.severity >= 3);
    else if (scope === 'multi') L = L.filter((i) => i.domain_count > 1);
    if (q.status && q.status !== 'all') L = L.filter((i) => i.status === q.status);
    if (q.domain) L = L.filter((i) => i.domains[q.domain]);
    if (q.min_score) L = L.filter((i) => i.score >= Number(q.min_score));
    if (q.q) { const s = String(q.q).toLowerCase(); L = L.filter((i) => `${i.id} ${i.title} ${i.entities.users.join(' ')} ${i.entities.hosts.join(' ')} ${i.entities.ips.join(' ')} ${i.entities.external_ips.join(' ')}`.toLowerCase().includes(s)); }
    const lim = Math.max(1, Math.min(500, Number(q.limit) || 200));
    const all = r.incidents;
    return {
      total: L.length, items: L.slice(0, lim).map(brief),
      summary: {
        incidents: all.filter((i) => i.alerts > 1 || i.severity >= 3).length, open: all.filter((i) => i.status === 'open' && (i.alerts > 1 || i.severity >= 3)).length,
        cross_domain: all.filter((i) => i.domain_count > 1).length, high: all.filter((i) => i.score >= 70 && i.status === 'open').length,
        alerts_considered: r.considered, alerts_correlated: all.filter((i) => i.alerts > 1).reduce((s, i) => s + i.alerts, 0),
        without_case: all.filter((i) => i.status === 'open' && !i.cases.length && (i.alerts > 1 || i.severity >= 3)).length,
      },
      excluded: r.excluded, hubs: r.hubs.slice(0, 20), settings: cfg(), domain_names: DOMAIN_NAMES,
      tactic_names: catalog ? Object.fromEntries((catalog.tactics || []).map((t) => [t.key, t.name])) : {},
    };
  }
  function incident(id) {
    const i = run().incidents.find((x) => x.id === id); if (!i) return null;
    const list = i.alert_ids.map((a) => alerts.get(a)).filter(Boolean);
    const pbId = playbooks && typeof playbooks.suggest === 'function' ? playbooks.suggest(list) : '';
    const pb = pbId && playbooks.get(pbId);
    let recommended = [];
    try { if (pb) recommended = playbooks.recommendations(playbooks.instantiate(pbId), playbooks.entitiesFrom(list)); } catch { recommended = []; }
    return Object.assign({}, i, {
      timeline: list.map((a) => ({ id: a.id, ts_first: a.ts_first, ts_last: a.ts_last, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, status: a.status, domain: domainOf(a), tactics: tactics.of(a), entities: entitiesOf(a, new Set((cfg().internal_domains || []).map((d) => String(d).toLowerCase()))), summary: a.summary, case_id: a.case_id || '', count: a.count || 1, src_id: a.src_id || '' })),
      playbook: pb ? { id: pb.id, name: pb.name, description: pb.description } : null, recommended,
    });
  }
  function promote(id, by, opts = {}) {
    const i = incident(id); if (!i) { const e = new Error('incident not found'); e.code = 404; throw e; }
    const free = i.timeline.filter((a) => !a.case_id).map((a) => a.id);
    const existing = i.cases[0];
    if (existing) {
      if (free.length) cases.addAlerts(existing, free, by);
      return { case_id: existing, added: free.length, created: false };
    }
    if (!free.length) { const e = new Error('every alert of this incident is already in a case'); e.code = 409; throw e; }
    const c = cases.create({ title: `[${i.id}] ${i.title}`, severity: i.severity, alert_ids: free, description: `XDR incident ${i.id}: ${i.alerts} alerts across ${i.domain_count} domain(s) (${Object.keys(i.domains).join(', ')}); ATT&CK ${i.tactics.join(' → ') || 'n/a'}; score ${i.score} - ${i.why.map((w) => `${w.reason} (+${w.points})`).join('; ')}.${opts.auto ? ' Opened automatically by the XDR auto-case policy.' : ''}` }, by);
    cache = null;
    return { case_id: c.id, added: free.length, created: true, approvals: (c.approvals || []).length };
  }
  function autoTick() {
    const r = autoTickRun();
    autoOpened += r.opened.length;
    lastTick = { at: Date.now(), enabled: r.enabled, threshold: r.threshold || 0, opened: r.opened.length };
    return r;
  }
  function autoTickRun() {
    const th = Number(cfg().auto_case_score) || 0; if (!th) return { enabled: false, opened: [] };
    const opened = [];
    for (const i of run().incidents) {
      if (i.status !== 'open' || i.score < th || i.cases.length || i.alerts < 2) continue;
      try { const r = promote(i.id, 'xdr:auto-case', { auto: true }); opened.push({ incident: i.id, case_id: r.case_id }); } catch (e) { log.warn('xdr auto-case failed', { incident: i.id, err: e.message }); }
      if (opened.length >= 5) break;   // a burst never opens more than 5 cases per minute
    }
    if (opened.length) log.info('xdr auto-case', { opened: opened.length });
    return { enabled: true, threshold: th, opened };
  }
  function coverage() {
    const now = Date.now(), r = run(); const by = {};
    DOMAINS.forEach((d) => { by[d] = { domain: d, name: DOMAIN_NAMES[d], alerts_72h: 0, last: 0 }; });
    const list = typeof alerts.all === 'function' ? alerts.all((a) => a.source !== 'logrhythm' && (a.ts_last || 0) > now - 72 * 3600e3) : [];
    for (const a of list) { if (isOperational(a)) continue; const d = by[domainOf(a)]; d.alerts_72h++; d.last = Math.max(d.last, a.ts_last || 0); }
    return { domains: DOMAINS.filter((d) => d !== 'other' || by.other.alerts_72h).map((d) => by[d]), considered: r.considered, note: 'A domain with no alerts may be quiet or may have no log source connected - Log Sources shows which.' };
  }
  /** an administrator's settings, validated; saved in the SIEM state (survives restarts and updates) */
  function putSettings(b, by) {
    if (!store) { const e = new Error('settings cannot be saved: the SOC state store is not available'); e.code = 503; throw e; }
    const cur = saved(), o = {};
    const num = (k, lo, hi, zeroOk) => {
      if (!(k in b)) return;
      const v = Number(b[k]);
      if (!Number.isFinite(v) || (!(zeroOk && v === 0) && (v < lo || v > hi))) { const e = new Error(`${k} must be ${zeroOk ? '0 (off) or ' : ''}between ${lo} and ${hi}`); e.code = 400; throw e; }
      o[k] = Math.round(v);
    };
    num('auto_case_score', 40, 100, true); num('lookback_h', 6, 336); num('link_window_h', 1, 168); num('hub_max', 5, 1000);
    if ('internal_domains' in b) {
      const L = (Array.isArray(b.internal_domains) ? b.internal_domains : String(b.internal_domains || '').split(/[\s,;]+/)).map((d) => String(d).trim().toLowerCase()).filter(Boolean);
      for (const d of L) if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d) || d.length > 120) { const e = new Error(`"${d.slice(0, 60)}" is not a domain name`); e.code = 400; throw e; }
      if (L.length > 20) { const e = new Error('at most 20 internal domains'); e.code = 400; throw e; }
      o.internal_domains = [...new Set(L)];
    }
    if (o.link_window_h && o.link_window_h > (o.lookback_h || cfg().lookback_h)) { const e = new Error('the link window cannot be longer than the look-back'); e.code = 400; throw e; }
    store.put({ id: 'settings', values: Object.assign({}, cur, o), updated_by: String(by || ''), updated_at: Date.now() });
    cache = null;
    return { settings: cfg(), changed: o };
  }
  /** is XDR able to do its job? Each check says what it found and, when it fails, what to connect */
  function status() {
    const c = cfg(), cov = coverage(), r = run();
    const live = cov.domains.filter((d) => d.alerts_72h > 0 && d.domain !== 'other');
    const KEY = { endpoint: 'EDR / antivirus (Kaspersky agent logs, Windows Defender)', identity: 'Active Directory / Microsoft 365 sign-ins (domain controller event logs, Microsoft 365 audit)', network: 'firewall / IPS (FortiGate, Palo Alto syslog)', email: 'Exchange / Microsoft 365 mail' };
    const missing = Object.keys(KEY).filter((k) => !live.some((d) => d.domain === k));
    const checks = [
      { id: 'alerts', ok: r.considered > 0, text: r.considered ? `${r.considered} security alerts in the last ${c.lookback_h} h to correlate` : `no security alerts in the last ${c.lookback_h} h - XDR has nothing to join`, fix: r.considered ? '' : 'connect log sources (Log Sources page) and check the detection rules are loaded (Engine health)' },
      { id: 'domains', ok: live.length >= 2, text: `${live.length} security domain(s) raising alerts${live.length ? ': ' + live.map((d) => d.name).join(', ') : ''}`, fix: live.length >= 2 ? '' : 'cross-domain correlation needs at least two: connect ' + missing.map((k) => KEY[k]).join('; ') },
      { id: 'coverage', ok: !missing.length, level: 'warn', text: missing.length ? 'no alerts from: ' + missing.map((k) => DOMAIN_NAMES[k]).join(', ') : 'endpoint, identity, network and email all reporting', fix: missing.length ? 'quiet or not connected - Log Sources shows which' : '' },
      { id: 'ueba', ok: !!(ueba && typeof ueba.entities === 'function'), level: 'warn', text: ueba ? 'user and host risk (UEBA) adds to the score' : 'UEBA is not running - risky users and hosts add nothing to the score', fix: ueba ? '' : 'enable UEBA in the SIEM configuration' },
      { id: 'search', ok: !!deps.search, level: 'warn', text: deps.search ? 'hunts can search the event store' : 'event search not available - hunts cannot run', fix: '' },
      { id: 'beacons', ok: !!(ch && typeof ch.query === 'function'), level: 'warn', text: ch ? 'beacon statistics read the event store' : 'event store not reachable - no beacon statistics', fix: '' },
      { id: 'domains_set', ok: (c.internal_domains || []).length > 0, level: 'info', text: (c.internal_domains || []).length ? 'internal mail domains: ' + c.internal_domains.join(', ') : 'internal mail domains not set - alice@yourdomain and DOMAIN\\alice are treated as two different users', fix: (c.internal_domains || []).length ? '' : 'set them under Settings on this page' },
      { id: 'auto_case', ok: !!c.auto_case_score, level: 'info', text: c.auto_case_score ? `incidents scoring ${c.auto_case_score}+ open a case automatically (its playbook asks for approval - nothing runs by itself)` : 'auto-case is off - an analyst opens a case from each incident', fix: c.auto_case_score ? '' : 'switch it on under Settings (70 is a sensible start)' },
    ];
    const ready = checks.filter((x) => !x.level).every((x) => x.ok);
    return { ready, operational: ready ? (missing.length ? 'partial' : 'full') : 'not-ready', checks, settings: c, domains: cov.domains,
      auto_case: { enabled: !!c.auto_case_score, threshold: c.auto_case_score || 0, last_tick: lastTick, opened_since_start: autoOpened },
      hubs: r.hubs.length, incidents_open: r.incidents.filter((i) => i.status === 'open' && (i.alerts > 1 || i.severity >= 3)).length };
  }
  function hunts() { return { items: HUNTS.map((h) => Object.assign({}, h)) }; }
  async function runHunt(id, o = {}) {
    const h = HUNTS.find((x) => x.id === id); if (!h) { const e = new Error('unknown hunt'); e.code = 404; throw e; }
    if (!deps.search) { const e = new Error('event search is not available'); e.code = 503; throw e; }
    const to = o.to || Date.now(), from = o.from || to - 7 * 864e5;
    const r = await deps.search({ q: h.q, from, to, limit: 50, fields: ['ts', 'src_type', 'src_id', 'host', 'user', 'src_ip', 'dst_ip', 'dst_port', 'action', 'process', 'cmdline', 'message'] });
    return { hunt: h, from, to, total: r.total_estimate, rows: r.rows, took_ms: r.took_ms };
  }
  /** beaconing: connections from one internal host to one external address at a near-constant interval (coefficient of
   *  variation of the gaps below 0.15, at least 20 connections in the window). Statistics only; a hit is a lead. */
  async function beacons(o = {}) {
    if (!ch || typeof ch.query !== 'function') return { available: false, items: [], note: 'the event store is not reachable' };
    const hours = Math.max(1, Math.min(72, Number(o.hours) || 24));
    const db = ch.database || 'siem';
    const sql = `SELECT src_ip, dst_ip, dst_port, count() AS n, arraySort(groupArray(toUnixTimestamp(ts))) AS t FROM ${db}.events
      WHERE ts >= now() - toIntervalHour({h:UInt32}) AND dst_ip != '' AND src_ip != '' GROUP BY src_ip, dst_ip, dst_port HAVING n BETWEEN 20 AND 20000 ORDER BY n DESC LIMIT 3000`;
    let rows;
    try { rows = await ch.query(sql, { h: { type: 'UInt32', value: hours } }, { readonly: true }); } catch (e) { return { available: false, items: [], note: 'query failed: ' + e.message }; }
    const items = [];
    for (const r of rows) {
      if (!isPrivateIp(r.src_ip) || isPrivateIp(r.dst_ip)) continue;
      const t = (r.t || []).map(Number), gaps = [];
      for (let i = 1; i < t.length; i++) { const g = t[i] - t[i - 1]; if (g > 0) gaps.push(g); }
      if (gaps.length < 19) continue;
      const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length; if (mean < 10) continue;   // sub-10 s = streaming, not a beacon
      const sd = Math.sqrt(gaps.reduce((s, g) => s + (g - mean) * (g - mean), 0) / gaps.length), cv = sd / mean;
      if (cv < 0.15) items.push({ src_ip: r.src_ip, dst_ip: r.dst_ip, dst_port: Number(r.dst_port) || 0, connections: Number(r.n), interval_s: Math.round(mean), jitter: Math.round(cv * 100) / 100 });
    }
    items.sort((a, b) => a.jitter - b.jitter || b.connections - a.connections);
    return { available: true, hours, items: items.slice(0, 50), scanned: rows.length };
  }
  /** leads the queue would otherwise miss: open UEBA findings with no alert, and chains of low-severity alerts that
   *  cross domains (each one below the paging threshold on its own) */
  function leads() {
    const out = { ueba: [], low_chains: [] };
    try { if (ueba) out.ueba = (ueba.findings({ status: 'open', limit: 100 }).items || []).filter((f) => !f.alert_id).slice(0, 25).map((f) => ({ id: f.id, entity: f.entity_name, entity_type: f.entity_type, detector: f.detector, severity: f.severity, explanation: f.explanation, last: f.ts_last || f.last_seen || f.created })); } catch { /* ueba off */ }
    out.low_chains = run().incidents.filter((i) => i.status === 'open' && i.severity <= 2 && i.domain_count > 1).slice(0, 25).map(brief);
    return out;
  }
  // alert id -> the correlated incident it belongs to (the SOC analyst's priority score reads it)
  function byAlert() {
    const m = new Map();
    for (const i of run().incidents) if (i.alerts > 1 || i.severity >= 3) for (const id of i.alert_ids) m.set(id, { id: i.id, score: i.score, domains: Object.keys(i.domains) });
    return m;
  }
  return { incidents, incident, intel, promote, autoTick, coverage, hunts, runHunt, beacons, leads, settings: cfg, putSettings, status, domainOf, byAlert, invalidate() { cache = null; } };
}

module.exports = { createXdr, correlate, domainOf, entitiesOf, isOperational, makeTactics, HUNTS, DOMAINS, DOMAIN_NAMES };
