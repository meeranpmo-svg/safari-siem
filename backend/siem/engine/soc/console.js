// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SOC Console (the LogRhythm / QRadar-style console of the old portal, rebuilt on the SIEM's own stores). Offenses come from the
 * alert queue (soc/analyst.js - the explainable priority); this module adds what the queue does not show:
 *   agents   every host whose the organisation agent sent a heartbeat in the last 7 days: active (within 3 heartbeat intervals),
 *            delayed (within 2 hours), disconnected (longer); the agent version against the newest version running in the
 *            estate (outdated = behind it); degraded (the agent reported a full queue or dropped batches). An operator can retire
 *            an agent that was removed on purpose (reason recorded) - it then stops counting as disconnected, and shows as
 *            active again by itself the moment it sends a heartbeat. A host with no agent is not listed: this is the agent's own
 *            view, not an asset inventory.
 *   fim      file-integrity monitoring over the change events the sources ALREADY log (Sysmon file create / registry set,
 *            Windows object-access auditing, Linux audit forwarded by syslog): changes on the watched paths (an administrator's
 *            list of path fragments - hosts file, startup folders, Run keys, scheduled tasks, web roots, /etc/passwd, sudoers,
 *            authorized_keys ...), grouped per host + path. Coverage is stated: the hosts that send file / registry events at
 *            all. A watched path with no event is NOT proof it did not change - only that nothing logged a change.
 *   ingest   events per minute over the last hour against the hour's own median (robust z, MAD), the busiest sources, and
 *            the most recent events (analyst and above: raw events are personal data).
 *   GET  {P}/soc/console                any signed-in user   agents summary, ingest, FIM summary (counts only for viewers)
 *   GET  {P}/soc/console/agents         analyst              the agent list
 *   GET  {P}/soc/console/fim            analyst              ?hours=1-168  watched-path changes and coverage
 *   GET  {P}/soc/console/live           analyst              the latest 25 events
 *   GET  {P}/soc/console/intel          analyst              the console's statistics (below)
 * intel - statistics over the same stores, every point itemised, nothing assumed:
 *   sources  each log source's last hour against the same hour on each of the previous 7 days (median): QUIET (usual 20+, now
 *            under 20 % of it - collection may have stopped), LOUD (3x usual and 50+ more - a burst, a loop, a new device), NEW
 *            (nothing at this hour in 7 days). Judged once 4 of the 7 days had events at this hour.
 *   fim      each watched-path change scored 0-100: ATT&CK technique on the event (+30), first time this host + path is seen by the
 *            console (+25; the console keeps first-seen dates, 90 days), outside Riyadh working hours Sun-Thu 07-18 (+15), a process
 *            that is not an installer / updater / system service (+15), a high-impact path (hosts, Run / Winlogon keys, startup,
 *            authorized_keys, sudoers, passwd / shadow: +15). A lead to check, not proof of tampering.
 *   stability  agents whose heartbeats in 24 h show 3+ gaps longer than 3 intervals (flapping) - a network or a host problem
 *            before it becomes "disconnected".
 *   hosts    the hosts needing attention, fusing the open offenses (highest priority x 0.5), the riskiest file change (x 0.3) and the
 *            agent (disconnected +15, flapping +10); at most 100, every part named.
 *   POST {P}/soc/console/agents/retire  operator             {host, reason} / POST .../restore {host, reason}
 *   POST {P}/soc/console/fim/watch      admin                {paths[]} - the watched path fragments
 */
const { wrap, audit, prefixOf, HttpError } = require('./routeutil');
const { body } = require('../util/check');

const MIN = 60e3, H = 60 * MIN, DAY = 24 * H;
const DEF_WATCH = [
  '\\windows\\system32\\drivers\\etc\\hosts', '\\start menu\\programs\\startup\\', '\\windows\\system32\\tasks\\', '\\windows\\system32\\drivers\\',
  '\\currentversion\\run', '\\currentversion\\winlogon\\', '\\currentcontrolset\\services\\', '\\inetpub\\wwwroot\\',
  '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config', '/.ssh/authorized_keys', '/etc/crontab', '/etc/cron.d/', '/var/www/',
];
const lc = (s) => String(s == null ? '' : s).toLowerCase();
const tsOf = (v) => (typeof v === 'number' ? v : Date.parse(/Z$|[+-]\d\d:?\d\d$/.test(String(v)) ? v : String(v).replace(' ', 'T') + 'Z'));
const median = (a) => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
function cmpVer(a, b) { const pa = String(a).split(/[^0-9]+/).filter(Boolean).map(Number), pb = String(b).split(/[^0-9]+/).filter(Boolean).map(Number); for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d < 0 ? -1 : 1; } return 0; }
const verOf = (ev) => (ev.fields && ev.fields.agent_version) || ((/Agent heartbeat v([0-9][0-9A-Za-z.\-]{0,19})/.exec(ev.message || '') || [])[1]) || '';

function createConsole(deps = {}) {
  const { search, state } = deps, now = deps.now || Date.now, L = deps.log || { info() {}, warn() {} };
  const C = state.collection('soc_console'), R = state.collection('soc_console_retired');
  const cfg = () => Object.assign({ heartbeat_min: 5 }, (deps.config && deps.config.soc_console) || {});
  const watch = () => ((C.get('fim') || {}).paths) || DEF_WATCH;
  const need = () => { if (!search || typeof search.rare !== 'function') throw new HttpError(503, 'the event store is not available'); };

  async function agents() {
    need();
    const t = now(), from = t - 7 * DAY, iv = cfg().heartbeat_min * MIN;
    const r = await search.rare({ q: 'action:agent-heartbeat', from, to: t, field: 'host', limit: 200 });
    const recent = await search.fetchEvents({ q: 'action:agent-heartbeat', from: t - Math.max(30 * MIN, 3 * iv), to: t, limit: 20000, order: 'desc' });
    const latest = new Map(); for (const e of recent) if (e.host && !latest.has(lc(e.host))) latest.set(lc(e.host), e);
    const list = r.values.map((v) => {
      const host = String(v.v), last = tsOf(v.last), e = latest.get(lc(host)), age = t - last, ret = R.get(lc(host));
      const status = age <= 3 * iv ? 'active' : age <= 2 * H ? 'delayed' : 'disconnected';
      const retired = ret && !(last > ret.at) ? { by: ret.by, at: ret.at, reason: ret.reason } : null;
      return { host, last_seen: new Date(last).toISOString(), minutes_ago: Math.round(age / MIN), status: retired ? 'retired' : status, heartbeats_7d: v.n,
        version: e ? verOf(e) : '', degraded: !!(e && (e.tags || []).includes('agent-degraded')), queue_files: e && e.fields ? Number(e.fields.queue_files || 0) || 0 : null, retired };
    });
    // the agent version: the newest one running among active agents is the reference
    const vers = list.filter((a) => a.status === 'active' && a.version).map((a) => a.version), newest = vers.length ? vers.sort(cmpVer)[vers.length - 1] : null;
    for (const a of list) a.outdated = !!(newest && a.version && cmpVer(a.version, newest) < 0);
    const order = { disconnected: 0, delayed: 1, active: 2, retired: 3 };
    list.sort((a, b) => order[a.status] - order[b.status] || (b.degraded - a.degraded) || (b.outdated - a.outdated) || a.host.localeCompare(b.host));
    const cnt = (f) => list.filter(f).length;
    const byVer = {}; for (const a of list) if (a.version && a.status !== 'retired') byVer[a.version] = (byVer[a.version] || 0) + 1;
    return { at: new Date(t).toISOString(), heartbeat_min: cfg().heartbeat_min, newest_version: newest, versions: Object.entries(byVer).map(([version, hosts]) => ({ version, hosts })).sort((a, b) => cmpVer(b.version, a.version)),
      summary: { total: cnt((a) => a.status !== 'retired'), active: cnt((a) => a.status === 'active'), delayed: cnt((a) => a.status === 'delayed'), disconnected: cnt((a) => a.status === 'disconnected'), retired: cnt((a) => a.status === 'retired'), degraded: cnt((a) => a.degraded && a.status !== 'retired'), outdated: cnt((a) => a.outdated && a.status !== 'retired') },
      agents: list, truncated: r.values.length >= 200,
      note: 'Active = a heartbeat within ' + 3 * cfg().heartbeat_min + ' minutes. Only hosts whose agent has reported in the last 7 days are listed - a host with no agent is not shown here (see Infrastructure Inventory).' };
  }
  function retire(b0, who, restore) {
    const b = body(b0 || {}).str('host', { required: true, max: 253 }).str('reason', { required: true, max: 500 }).done();
    if (b.reason.length < 5) throw new HttpError(400, 'reason: say why (at least 5 characters)');
    const k = lc(b.host);
    if (restore) { const x = R.get(k); if (!x) throw new HttpError(404, b.host + ' is not retired'); R.remove(k); return { host: b.host, restored: true }; }
    if (R.get(k)) throw new HttpError(409, b.host + ' is already retired');
    const rec = { id: k, host: b.host, reason: b.reason, by: who, at: now() }; R.put(rec); return rec;
  }

  async function fim(hours) {
    need();
    const t = now(), h = hours || 24, from = t - h * H, W = watch().map(lc);
    const [evs, cov] = await Promise.all([
      search.fetchEvents({ q: '(category:file OR category:registry) -action:agent-heartbeat', from, to: t, limit: 20000, order: 'desc' }),
      search.top({ q: 'category:file OR category:registry', from: t - 7 * DAY, to: t, field: 'host', limit: 100 }),
    ]);
    const groups = new Map();
    for (const e of evs) {
      const f = e.fields || {}, path = f.target_filename || f.target_object || f.object_name || f.file_path || f.path || '', hay = lc(path || e.message);
      const hit = W.find((w) => hay.includes(w)); if (!hit) continue;
      const k = lc(e.host) + '|' + lc(path || e.message).slice(0, 300), g = groups.get(k);
      if (g) { g.count++; g.first = Math.min(g.first, e.ts); continue; }
      groups.set(k, { host: e.host || '', path: path || String(e.message || '').slice(0, 300), watched: hit, action: e.action || '', process: e.process || '', user: e.user || '', first: e.ts, last: e.ts, count: 1, severity: e.severity || 0, techniques: (e.tags || []).filter((x) => /^T\d{4}/.test(x)) });
    }
    const changes = [...groups.values()].sort((a, b) => b.last - a.last).map((g) => Object.assign(g, { first: new Date(g.first).toISOString(), last: new Date(g.last).toISOString() }));
    const byPath = {}; for (const c of changes) byPath[c.watched] = (byPath[c.watched] || 0) + c.count;
    return { at: new Date(t).toISOString(), hours: h, watched: watch(), changes: changes.slice(0, 500), hosts_changed: new Set(changes.map((c) => lc(c.host))).size, by_watch: Object.entries(byPath).map(([path, events]) => ({ path, events })).sort((a, b) => b.events - a.events),
      coverage: { hosts: cov.values.length, top: cov.values.slice(0, 20).map((v) => ({ host: v.v, events_7d: v.n })) }, scanned: evs.length, truncated: evs.length >= 20000,
      note: 'Built from the file and registry change events the sources already log (Sysmon 11 / 13, Windows object-access auditing, Linux audit via syslog). A watched path with no event is not proof it is unchanged - only that no source logged a change. Only the hosts listed under coverage send such events at all.' };
  }
  function setWatch(b0, who) {
    const b = body(b0 || {}).list('paths', { required: true, max: 50 }).done();
    const paths = b.paths.map((p, i) => { if (typeof p !== 'string' || !p.trim()) throw new HttpError(400, 'paths[' + i + '] must be text'); const v = p.trim(); if (v.length < 4 || v.length > 200) throw new HttpError(400, 'paths[' + i + '] must be 4-200 characters'); if (/[\u0000-\u001f]/.test(v)) throw new HttpError(400, 'paths[' + i + '] contains control characters'); return v; });
    if (!paths.length) throw new HttpError(400, 'paths: watch at least one path');
    const uniq = [...new Set(paths.map(lc))].map((x) => paths.find((p) => lc(p) === x));
    C.put({ id: 'fim', paths: uniq, by: who, at: now() }); return { paths: uniq };
  }

  async function ingest() {
    need();
    const t = now(), from = t - 60 * MIN;
    const [hst, src] = await Promise.all([search.histogram({ q: '', from, to: t, buckets: 60 }), search.top({ q: '', from, to: t, field: 'src_type', limit: 10 })]);
    const s = hst.buckets.map((b) => b.n), full = s.slice(0, -1), cur = full.length ? full[full.length - 1] : 0, prev = full.slice(0, -1);
    const med = median(prev), mad = median(prev.map((x) => Math.abs(x - med))), z = prev.length >= 10 ? Math.round(((cur - med) / (1.4826 * (mad || Math.max(1, Math.sqrt(med || 1))))) * 10) / 10 : null;
    return { per_minute: cur, median: med, z, quiet: prev.length >= 10 && med >= 5 && cur === 0, series: hst.buckets, total_hour: s.reduce((a, b) => a + b, 0), sources: src.values.map((v) => ({ source: v.v, events: v.n })),
      note: z == null ? 'needs 10 minutes of history' : z <= -3 ? 'far below the hour\'s normal - check that collection is running' : z >= 3 ? 'far above the hour\'s normal - a burst or a new source' : 'within the hour\'s normal' };
  }
  async function live() { need(); const t = now(); const r = await search.search({ q: '-action:agent-heartbeat', from: t - DAY, to: t, limit: 25, order: 'desc', fields: ['ts', 'host', 'src_type', 'category', 'action', 'severity', 'user', 'src_ip', 'message'] }); return { events: r.rows }; }


  // ---- intel: source health, FIM risk, agent stability, host fusion
  const SEEN = state.collection('soc_console_fim_seen');
  const SYS_PROC = /\\(msiexec|trustedinstaller|tiworker|wuauclt|usoclient|svchost|services|system|mrt|msmpeng|ccmexec|setup)\.exe$|^\/usr\/bin\/(dpkg|apt|apt-get|yum|dnf|rpm|unattended-upgrade)|^(dpkg|apt|yum|dnf|rpm)$/i;
  const HIGH = /drivers\\etc\\hosts|currentversion\\run|currentversion\\winlogon|start menu\\programs\\startup|authorized_keys|\/etc\/sudoers|\/etc\/passwd|\/etc\/shadow/i;
  const offHours = (ms) => { const d = new Date(ms + 3 * H), wd = d.getUTCDay(), h = d.getUTCHours(); return wd === 5 || wd === 6 || h < 7 || h >= 18; };
  async function sourceHealth() {
    const t = now(), wins = [];
    for (let d = 0; d <= 7; d++) wins.push(search.top({ q: '', from: t - d * DAY - H, to: t - d * DAY, field: 'src_type', limit: 50 }));
    const res = await Promise.all(wins), cur = new Map(res[0].values.map((v) => [String(v.v), v.n])), past = res.slice(1).map((r) => new Map(r.values.map((v) => [String(v.v), v.n])));
    const names = new Set([...cur.keys()]); for (const m of past) for (const k of m.keys()) names.add(k);
    const out = [];
    for (const k of names) {
      const hist = past.map((m) => m.get(k) || 0), withData = hist.filter((x) => x > 0).length, usual = median(hist), n = cur.get(k) || 0;
      let state = 'normal', why = n + ' events in the last hour, usual ' + usual + ' at this hour';
      if (withData < 4) { if (n && !withData) { state = 'new'; why = n + ' events in the last hour; nothing at this hour in 7 days'; } else { state = 'learning'; why = 'judged once 4 of 7 days had events at this hour (' + withData + ' so far)'; } }
      else if (usual >= 20 && n < 0.2 * usual) { state = 'quiet'; why = n + ' events in the last hour against a usual ' + usual + ' - check that collection is running'; }
      else if (n >= 3 * usual && n - usual >= 50) { state = 'loud'; why = n + ' events in the last hour, ' + Math.round(n / Math.max(1, usual)) + 'x the usual ' + usual + ' - a burst, a loop or a new device'; }
      out.push({ source: k, last_hour: n, usual, state, why });
    }
    const order = { quiet: 0, loud: 1, new: 2, learning: 3, normal: 4 };
    return out.sort((a, b) => order[a.state] - order[b.state] || b.last_hour - a.last_hour);
  }
  function fimRisk(changes) {
    const t = now();
    return changes.map((c) => {
      const key = lc(c.host) + '|' + lc(c.path).slice(0, 300), seen = SEEN.get(key), first = !seen, why = [];
      if (!seen) SEEN.put({ id: key, first: t }); else if (t - seen.first > 90 * DAY) SEEN.put({ id: key, first: t });
      const add = (pts, f, r) => why.push({ points: pts, factor: f, reason: r });
      if ((c.techniques || []).length) add(30, 'technique', c.techniques.join(', ') + ' on the event');
      if (first) add(25, 'first seen', 'the first change to this path on this host the console has seen');
      if (offHours(Date.parse(c.last))) add(15, 'off hours', 'outside Riyadh working hours (Sun-Thu 07-18)');
      const proc = String(c.process || '').trim(); if (proc && !SYS_PROC.test(proc.toLowerCase().replace(/\//g, '/'))) add(15, 'process', String(proc).split(/[\\/]/).pop() + ' is not an installer, updater or system service');
      if (HIGH.test(c.path)) add(15, 'path', 'a path attackers use to persist or redirect');
      const score = Math.min(100, why.reduce((a, w) => a + w.points, 0));
      return Object.assign({}, c, { risk: score, risk_why: why });
    }).sort((a, b) => b.risk - a.risk);
  }
  async function stability() {
    const t = now(), iv = cfg().heartbeat_min * MIN, evs = await search.fetchEvents({ q: 'action:agent-heartbeat', from: t - DAY, to: t, limit: 20000, order: 'asc' });
    const by = new Map(); for (const e of evs) if (e.host) (by.get(lc(e.host)) || by.set(lc(e.host), { host: e.host, ts: [] }).get(lc(e.host))).ts.push(typeof e.ts === 'number' ? e.ts : tsOf(e.ts));
    const out = [];
    for (const x of by.values()) { const ts = x.ts.sort((a, b) => a - b); let gaps = 0, longest = 0; for (let i = 1; i < ts.length; i++) { const g = ts[i] - ts[i - 1]; if (g > 3 * iv) { gaps++; longest = Math.max(longest, g); } }
      if (gaps >= 3) out.push({ host: x.host, gaps, longest_min: Math.round(longest / MIN), heartbeats: ts.length, why: gaps + ' gaps longer than ' + Math.round(3 * iv / MIN) + ' min in 24 h (longest ' + Math.round(longest / MIN) + ' min) - a network or host problem before it disconnects' }); }
    return out.sort((a, b) => b.gaps - a.gaps).slice(0, 20);
  }
  async function intel() {
    need();
    const safe = async (fn) => { try { return await fn(); } catch (e) { L.warn('soc console intel: a part could not be read', { err: e.message }); return { error: e.status === 503 ? e.message : 'could not be read' }; } };
    const [src, f, stab, ag] = await Promise.all([safe(sourceHealth), safe(() => fim(24)), safe(stability), safe(agents)]);
    const risk = f.error ? f : fimRisk(f.changes.slice(0, 200));
    // host fusion: offenses (from the alert queue, when the analyst module is loaded) + FIM + agent
    let offenses = []; try { if (deps.analyst && typeof deps.analyst.queue === 'function') offenses = deps.analyst.queue({ status: 'open', limit: 500 }).items; } catch (e) { L.warn('soc console intel: the queue could not be read', { err: e.message }); }
    const H2 = new Map(), host = (h) => { const k = lc(h); if (!k) return null; return H2.get(k) || H2.set(k, { host: h, parts: [], off: 0, fim: 0, agent: 0 }).get(k); };
    for (const a of offenses) for (const e of (a.entities || []).filter((x) => x.startsWith('host:')).concat(a.host ? ['host:' + a.host] : [])) { const x = host(e.slice(5)); if (x && a.priority > x.off) { x.off = a.priority; x.offWhy = a.rule_name + ' (priority ' + a.priority + ')'; } }
    if (Array.isArray(risk)) for (const c of risk) { const x = host(c.host); if (x && c.risk > x.fim) { x.fim = c.risk; x.fimWhy = String(c.path).slice(0, 120) + ' (risk ' + c.risk + ')'; } }
    if (!ag.error) for (const a of ag.agents) if (a.status === 'disconnected') { const x = host(a.host); x.agent = 15; x.agentWhy = 'agent disconnected ' + a.minutes_ago + ' min'; }
    if (Array.isArray(stab)) for (const s of stab) { const x = host(s.host); if (x.agent < 10) { x.agent = 10; x.agentWhy = 'agent flapping (' + s.gaps + ' gaps in 24 h)'; } }
    const hosts = [...H2.values()].map((x) => { const why = [];
      if (x.off) why.push({ points: Math.round(x.off * 0.5), factor: 'offense', reason: x.offWhy }); if (x.fim) why.push({ points: Math.round(x.fim * 0.3), factor: 'file change', reason: x.fimWhy }); if (x.agent) why.push({ points: x.agent, factor: 'agent', reason: x.agentWhy });
      return { host: x.host, score: Math.min(100, why.reduce((a, w) => a + w.points, 0)), signals: why.length, why }; }).filter((x) => x.score > 0).sort((a, b) => b.signals - a.signals || b.score - a.score).slice(0, 15);
    return { at: new Date(now()).toISOString(), sources: src, fim: Array.isArray(risk) ? risk.slice(0, 50) : risk, stability: stab, hosts,
      note: 'Statistics over this SIEM\'s own events, offenses and agents: leads for an analyst to check, not proof. Hosts with more than one kind of signal come first.' };
  }

  async function overview(role) {
    const named = ['analyst', 'operator', 'admin'].includes(role);
    const safe = async (fn) => { try { return await fn(); } catch (e) { L.warn('soc console: read failed', { err: e.message }); return { error: e.status === 503 ? e.message : 'could not be read' }; } };
    const [a, g, f] = await Promise.all([safe(agents), safe(ingest), safe(() => fim(24))]);
    return { at: new Date(now()).toISOString(), named, agents: a.error ? a : { summary: a.summary, newest_version: a.newest_version, versions: a.versions, heartbeat_min: a.heartbeat_min }, ingest: g,
      fim: f.error ? f : { hours: f.hours, changes: f.changes.length, hosts_changed: f.hosts_changed, by_watch: f.by_watch, coverage_hosts: f.coverage.hosts } };
  }
  return { overview, agents, retire, fim, setWatch, ingest, live, intel, DEF_WATCH };
}

function register(api, deps) {
  if (!deps.state) return;   // retired agents and the watch list are stored state
  const P = prefixOf(deps), K = createConsole(deps);
  const hours = (ctx) => { const v = (ctx.query || {}).hours; if (v === undefined || v === '') return 24; const n = Number(v); if (!Number.isInteger(n) || n < 1 || n > 168) throw new HttpError(400, 'hours must be a whole number 1-168'); return n; };
  api.route('GET', `${P}/soc/console`, wrap(deps, null, async (ctx) => ctx.ok(await K.overview(String(ctx.role || '').toLowerCase()))));
  api.route('GET', `${P}/soc/console/agents`, wrap(deps, 'analyst', async (ctx) => ctx.ok(await K.agents())));
  api.route('GET', `${P}/soc/console/fim`, wrap(deps, 'analyst', async (ctx) => { const h = hours(ctx), r = await K.fim(h); audit(ctx, 'soc.console.fim', 'fim', { hours: h, changes: r.changes.length }); return ctx.ok(r); }));
  api.route('GET', `${P}/soc/console/intel`, wrap(deps, 'analyst', async (ctx) => ctx.ok(await K.intel())));
  api.route('GET', `${P}/soc/console/live`, wrap(deps, 'analyst', async (ctx) => ctx.ok(await K.live())));
  api.route('POST', `${P}/soc/console/agents/retire`, wrap(deps, 'operator', (ctx) => { const r = K.retire(ctx.body, ctx.user, false); audit(ctx, 'soc.console.agent.retire', r.host, { reason: r.reason }); return ctx.ok(r); }));
  api.route('POST', `${P}/soc/console/agents/restore`, wrap(deps, 'operator', (ctx) => { const b = ctx.body || {}; const r = K.retire(b, ctx.user, true); audit(ctx, 'soc.console.agent.restore', r.host, { reason: String(b.reason || '').slice(0, 500) }); return ctx.ok(r); }));
  api.route('POST', `${P}/soc/console/fim/watch`, wrap(deps, 'admin', (ctx) => { const r = K.setWatch(ctx.body, ctx.user); audit(ctx, 'soc.console.fim.watch', 'fim', { paths: r.paths.length }); return ctx.ok(r); }));
}

module.exports = { register, createConsole, cmpVer, DEF_WATCH };
