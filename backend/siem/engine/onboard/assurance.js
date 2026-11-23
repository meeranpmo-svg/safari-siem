// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Log-flow assurance: is every asset that should send logs actually sending them, and is the flow healthy?
 * Joins three things the platform already holds - nothing is guessed:
 *   inventory   IT Asset Management's log coverage (GET /api/itam/discovery/log-coverage): every active asset matched to
 *               a SIEM source by source id, IP, host name, MAC or by its own host name in the logs
 *   sources     collection.health(): per source state against its class threshold, EPS, parse errors, lag
 *   logs        hosts that sent logs in the last 24 h (soc/hostmap.js reportingHosts) and the collectors' catch-all
 * Per required asset: covered | silent | waiting (source registered, nothing received) | not-onboarded | no-connector |
 * paused | unknown (inventory says so). "Required" = in use and of a type in policy.required_types (workstations only when
 * policy.require_workstations: endpoints usually report through the EDR, not one by one).
 * Also: unknown senders (log senders that are not in the inventory), sources silent that no asset explains, high parse
 * error rates, lag, and the collectors going quiet altogether.
 *   createAssurance(deps, collection) → { model({fresh}), adapter }   adapter = duty engineer 'siem' (AI SIEM Engineer)
 */
const { reportingHosts } = require('../soc/hostmap');

const CACHE_MS = 60000;
const TYPE_CLASS = { firewall: 'firewall', server: 'server', vm: 'server', network: 'network', storage: 'other', workstation: 'endpoint', laptop: 'endpoint' };
const lc = (s) => String(s || '').trim().toLowerCase();

function createAssurance(deps, C) {
  const cfg = deps.config || {}, db = (cfg.clickhouse && cfg.clickhouse.database) || 'siem';
  const clock = typeof deps.now === 'function' ? deps.now : Date.now;
  let cache = null;

  async function inventory() {
    const dc = deps.discoveryClient;
    if (!dc || typeof dc.logCoverage !== 'function') return { connected: false, error: 'the IT Asset Management link is not configured (onboard.discovery in the SIEM config)', assets: [] };
    try { const j = await dc.logCoverage({ user: 'system:siem-assurance', role: 'viewer' }); return { connected: true, error: null, assets: (j && j.assets) || [], generated_at: j && j.generated_at }; } catch (e) { return { connected: false, error: e.message, assets: [] }; }
  }
  async function senders() {
    if (!deps.ch || typeof deps.ch.query !== 'function') return { ok: false, hosts: [] };
    try { return { ok: true, hosts: (await reportingHosts(deps.ch, db, 24)).hosts }; } catch (e) { return { ok: false, hosts: [], error: e.message }; }
  }
  const typeOf = (a) => (lc(a.class) === 'firewall' ? 'firewall' : lc(a.type) || 'other');
  function required(a, pol) {
    if (a.asset_status && a.asset_status !== 'in_use') return false;
    const t = typeOf(a);
    if ((t === 'workstation' || t === 'laptop') && !pol.require_workstations) return false;
    return pol.required_types.includes(t) || (t === 'firewall' && pol.required_types.includes('network'));
  }
  const ms = (v) => { if (v == null) return 0; const t = typeof v === 'number' ? v : Date.parse(v); return Number.isFinite(t) ? t : 0; };

  async function build() {
    const now = clock(), pol = C.policy();
    const [h, inv, snd] = await Promise.all([C.health(), inventory(), senders()]);
    const srcById = new Map(h.sources.map((s) => [s.src_id, s]));
    const linked = new Set();
    const assets = [];
    for (const a of inv.assets) {
      const t = typeOf(a), req = required(a, pol);
      const src = a.source_id ? srcById.get(a.source_id) || null : null;
      if (src) linked.add(src.src_id);
      if (!req) continue;
      const cls = src ? src.sla_class : a.is_dc ? 'dc' : a.suggested_kind ? C.slaClassOf(a.suggested_kind) : TYPE_CLASS[t] || 'other';
      const sla = (src && src.sla_min) || pol.sla_min[cls] || 120;
      const last = ms(a.last_seen) || (src && src.last_seen) || 0;
      let state;
      if (src && src.paused) state = 'paused';
      else if (last && now - last <= sla * 60000) state = 'covered';
      else if (last) state = 'silent';
      else if (src || a.source_id) state = 'waiting';
      else if (a.status === 'unknown') state = 'unknown';
      else if (!a.suggested_kind) state = 'no-connector';
      else state = 'not-onboarded';
      assets.push({ asset_id: a.asset_id, name: a.name || a.mgmt_ip || a.asset_id, type: t, sla_class: cls, sla_min: sla, site: a.site || '', mgmt_ip: a.mgmt_ip || '', hostname: a.hostname || '',
        state, last_seen: last || null, source_id: a.source_id || null, source_kind: (src && src.kind) || a.source_kind || null, suggested_kind: a.suggested_kind || null, matched_by: a.matched_by || null,
        waiting_since: src && src.created_at ? ms(src.created_at) : null, auto_onboarded: !!(src && src.auto_onboarded) });
    }
    const S = { required: assets.length, covered: 0, silent: 0, waiting: 0, 'not-onboarded': 0, 'no-connector': 0, paused: 0, unknown: 0 };
    for (const a of assets) S[a.state] = (S[a.state] || 0) + 1;
    const denom = S.required - S.paused - S.unknown;
    S.coverage_pct = inv.connected && denom > 0 ? Math.round(S.covered / denom * 1000) / 10 : null;
    const group = (k) => { const m = {}; for (const a of assets) { const g = m[a[k] || '-'] = m[a[k] || '-'] || { key: a[k] || '-', required: 0, covered: 0, silent: 0, waiting: 0, missing: 0 }; g.required++; if (a.state === 'covered') g.covered++; else if (a.state === 'silent') g.silent++; else if (a.state === 'waiting') g.waiting++; else if (a.state === 'not-onboarded' || a.state === 'no-connector') g.missing++; } return Object.values(m).sort((x, y) => y.required - x.required); };

    // log senders the inventory does not know (by host name, short name or IP)
    const known = new Set();
    for (const a of inv.assets) for (const v of [a.name, a.hostname, a.mgmt_ip]) { const x = lc(v); if (x) { known.add(x); if (x.indexOf('.') > 0 && !/^\d+\.\d+\.\d+\.\d+$/.test(x)) known.add(x.split('.')[0]); } }
    const unknown = !inv.connected ? [] : snd.hosts.filter((x) => (x.events || 0) >= pol.unknown_min_events && !known.has(lc(x.host)) && !known.has(lc(x.host).split('.')[0]) && !(x.ip && known.has(x.ip)))
      .slice(0, 200).map((x) => ({ host: x.host, ip: x.ip || '', src_id: x.src_id || '', events_24h: x.events, last_seen: x.last_seen }));

    // sources no inventory asset explains (cloud feeds, appliances not in the inventory): their own silence counts
    const unlinked = h.sources.filter((s) => !linked.has(s.src_id) && !s.asset_id);
    const lastAny = Math.max(0, ...h.sources.map((s) => s.last_seen || 0), ...h.unconfigured.map((u) => u.last_seen || 0));
    const collector = { last_event: lastAny || null, quiet: !!lastAny && now - lastAny > 15 * 60000, eps_1h: Math.round((h.sources.reduce((t, s) => t + (s.eps_1h || 0), 0) + h.unconfigured.reduce((t, u) => t + (u.eps_1h || 0), 0)) * 100) / 100 };
    const quality = h.sources.filter((s) => !s.paused && s.eps_1h > 0 && ((s.parse_error_rate_1h || 0) >= pol.parse_error_warn || (s.lag_p95_s != null && s.lag_p95_s >= pol.lag_warn_s)))
      .map((s) => ({ src_id: s.src_id, kind: s.kind, site: s.site, parse_error_rate_1h: s.parse_error_rate_1h, lag_p95_s: s.lag_p95_s, bad_parse: (s.parse_error_rate_1h || 0) >= pol.parse_error_warn, bad_lag: s.lag_p95_s != null && s.lag_p95_s >= pol.lag_warn_s }));
    return { generated_at: new Date(now).toISOString(), policy: pol, inventory: { connected: inv.connected, error: inv.error, assets_total: inv.assets.length },
      summary: S, by_class: group('sla_class'), by_site: group('site'), assets, sources: h.sources, unlinked_sources: unlinked.map((s) => s.src_id), unconfigured: h.unconfigured,
      unknown_senders: unknown, senders_readable: snd.ok, collector, quality, stats_available: h.stats_available };
  }
  async function model(opts = {}) {
    if (!opts.fresh && cache && clock() - cache.at < CACHE_MS) return cache.v;
    const v = await build(); cache = { at: clock(), v }; return v;
  }

  /* ---- the AI SIEM Engineer on the duty desk */
  const SEV_SILENT = { firewall: 'critical', dc: 'critical', server: 'high', hypervisor: 'high', endpoint: 'medium', network: 'medium', cloud: 'high', oob: 'low', app: 'medium', other: 'medium' };
  const SEV_MISSING = { firewall: 'high', dc: 'high', server: 'high', hypervisor: 'medium', network: 'medium', cloud: 'medium', oob: 'low', endpoint: 'low', app: 'medium', other: 'low' };
  const ago = (t, now) => { if (!t) return 'never'; const m = Math.round((now - t) / 60000); return m < 120 ? m + ' min ago' : m < 2880 ? Math.round(m / 60) + ' h ago' : Math.round(m / 1440) + ' d ago'; };
  function setupLine(srcId) {
    const s = (cfg.sources || []).find((x) => x && x.id === srcId); if (!s) return '';
    const st = C.setupFor(s); return st && st.summary ? st.summary.en : '';
  }
  async function current(fresh) {
    const m = await model({ fresh }), now = clock(), out = [];
    if (!m.inventory.connected && !m.sources.length) return null;            // nothing to assure yet: not connected, never "healthy"
    if (m.collector.quiet) out.push({ key: 'collector-quiet', severity: 'critical', kind: 'collector-quiet', title: 'No logs arriving at the SIEM at all (last event ' + ago(m.collector.last_event, now) + ')',
      evidence: ['every source silent at once: the collector, its listener or the network path is down, not the devices'], recommendation: 'Check the sentra-siem service and its syslog listeners (systemctl status sentra-siem; ss -lntup | grep 5514), the host firewall and disk space; then confirm events arrive again (Log Sources → Test).',
      target: { type: 'collector', id: 'siem', name: 'SIEM collectors' } });
    for (const a of m.assets) {
      const base = { target: { type: 'asset', id: a.asset_id, name: a.name }, site: a.site };
      const ev = [a.type + ' · ' + a.sla_class + ' class (silent after ' + a.sla_min + ' min)', a.mgmt_ip, a.source_id ? 'source ' + a.source_id : '', a.matched_by ? 'matched by ' + a.matched_by : ''].filter(Boolean);
      if (a.state === 'silent') out.push(Object.assign({ key: 'silent:' + a.asset_id, kind: 'asset-silent', severity: m.collector.quiet ? 'medium' : SEV_SILENT[a.sla_class] || 'medium', title: `${a.name}: stopped sending logs (last ${ago(a.last_seen, now)})`,
        evidence: ev.concat(['last event ' + new Date(a.last_seen).toISOString()]), recommendation: 'Check the device is up and its logging is still pointed at the SIEM (a reboot, firmware upgrade or config restore often drops the syslog setting); for a server, check the SIEM agent service. ' + (a.source_id ? setupLine(a.source_id) : '') }, base));
      else if (a.state === 'waiting' && (!a.waiting_since || now - a.waiting_since > m.policy.waiting_grace_h * 3600000)) out.push(Object.assign({ key: 'waiting:' + a.asset_id, kind: 'never-received', severity: a.sla_class === 'firewall' || a.sla_class === 'dc' ? 'high' : 'medium',
        title: `${a.name}: registered in the SIEM but no log ever received`, evidence: ev.concat([a.auto_onboarded ? 'enrolled automatically from the inventory' : 'registered by an administrator']),
        recommendation: 'The SIEM side is ready; the device still has to be configured. ' + (setupLine(a.source_id) || 'Open the source in Connect & Onboard for the exact configuration.') + ' Then use Log Sources → Test.' }, base));
      else if (a.state === 'not-onboarded') out.push(Object.assign({ key: 'absent:' + a.asset_id, kind: 'not-onboarded', severity: SEV_MISSING[a.sla_class] || 'low', title: `${a.name}: in the inventory, no logs in the SIEM`,
        evidence: ev.concat(['suggested connector: ' + a.suggested_kind]), recommendation: 'Enable log collection for the asset (IT Asset Management → asset → Log collection, or it is enrolled automatically on the next pass), then apply the device configuration the SIEM gives.' }, base));
      else if (a.state === 'no-connector') out.push(Object.assign({ key: 'noconn:' + a.asset_id, kind: 'no-connector', severity: 'low', title: `${a.name}: no logs, and no automatic connector for this kind of asset`,
        evidence: ev, recommendation: 'Choose the connector in Connect & Onboard (syslog or CEF covers most appliances) or record the vendor / OS in the inventory so it can be mapped.' }, base));
    }
    const srcSev = (s) => SEV_SILENT[s.sla_class] || 'medium';
    for (const id of m.unlinked_sources) {
      const s = m.sources.find((x) => x.src_id === id); if (!s || s.paused) continue;
      if (s.state === 'silent') out.push({ key: 'src-silent:' + s.src_id, kind: 'source-silent', severity: srcSev(s), title: `Source ${s.label || s.src_id}: silent (last ${ago(s.last_seen, now)})`, evidence: [s.kind, s.match_ip || '', 'class ' + s.sla_class + ', silent after ' + s.sla_min + ' min'].filter(Boolean),
        recommendation: 'Check the sender is up and still forwarding to the SIEM. ' + setupLine(s.src_id), target: { type: 'source', id: s.src_id, name: s.label || s.src_id }, site: s.site });
      else if (s.state === 'never-seen' && (!s.created_at || now - ms(s.created_at) > m.policy.waiting_grace_h * 3600000)) out.push({ key: 'src-waiting:' + s.src_id, kind: 'never-received', severity: 'medium', title: `Source ${s.label || s.src_id}: registered, no log ever received`, evidence: [s.kind, s.match_ip || ''].filter(Boolean),
        recommendation: setupLine(s.src_id) || 'Configure the sender (Connect & Onboard shows how).', target: { type: 'source', id: s.src_id, name: s.label || s.src_id }, site: s.site });
    }
    for (const q of m.quality) out.push({ key: 'quality:' + q.src_id + ':' + (q.bad_parse ? 'parse' : 'lag'), kind: q.bad_parse ? 'parse-errors' : 'lag', severity: 'medium',
      title: q.bad_parse ? `Source ${q.src_id}: ${Math.round(q.parse_error_rate_1h * 100)}% of its logs are not parsed` : `Source ${q.src_id}: logs arrive ${q.lag_p95_s} s late (p95)`,
      evidence: [q.kind, q.bad_parse ? 'parse error rate (1 h) ' + q.parse_error_rate_1h : 'lag p95 ' + q.lag_p95_s + ' s over 15 min'],
      recommendation: q.bad_parse ? 'Check the device sends the format its connector expects (e.g. FortiGate "set format default", CEF for CEF connectors); unparsed events are kept but detection rules cannot use them.' : 'Lag is receive time minus event time: check the device clock (NTP) first - a clock that is wrong looks like lag - then the forwarding path / relay queue.',
      target: { type: 'source', id: q.src_id, name: q.src_id }, site: q.site });
    for (const u of m.unknown_senders.slice(0, 50)) out.push({ key: 'unknown:' + lc(u.host), kind: 'unknown-sender', severity: 'low', title: `${u.host}${u.ip ? ' (' + u.ip + ')' : ''}: sends logs but is not in the asset inventory`,
      evidence: [u.events_24h + ' events in 24 h', 'via source ' + (u.src_id || '-')], recommendation: 'Add it to the inventory (Asset Discovery approves it) so its owner, criticality and coverage are known - or, if it should not exist, investigate it as a shadow asset.',
      target: { type: 'host', id: lc(u.host), name: u.host } });
    return out;
  }
  const adapter = {
    id: 'siem', name: 'AI SIEM Engineer',
    findings: () => current(true),
    async investigate(it) {
      const m = await model({ fresh: true }), now = clock();
      const a = it.target.type === 'asset' ? m.assets.find((x) => x.asset_id === it.target.id) : null;
      const s = it.target.type === 'source' ? m.sources.find((x) => x.src_id === it.target.id) : a && a.source_id ? m.sources.find((x) => x.src_id === a.source_id) : null;
      const checks = [];
      if (a) checks.push({ name: 'Asset log state', status: a.state === 'covered' ? 'ok' : 'fail', detail: `${a.state}, last event ${ago(a.last_seen, now)}, threshold ${a.sla_min} min (${a.sla_class})` });
      if (s) checks.push({ name: 'SIEM source ' + s.src_id, status: s.state === 'receiving' ? 'ok' : 'fail', detail: `${s.state} · ${s.events_24h || 0} events 24 h · ${s.eps_1h} eps (1 h)${s.lag_p95_s != null ? ' · lag p95 ' + s.lag_p95_s + ' s' : ''}` });
      checks.push({ name: 'SIEM collectors', status: m.collector.quiet ? 'fail' : 'ok', detail: m.collector.quiet ? 'no event from any source for 15 min' : 'receiving (' + m.collector.eps_1h + ' eps overall)' });
      const setup = s ? setupLine(s.src_id) : '';
      if (setup) checks.push({ name: 'Device configuration', status: 'warn', detail: setup });
      return { summary: it.title + '. ' + (m.collector.quiet && it.kind !== 'collector-quiet' ? 'Every source is quiet, so the collector is the more likely cause.' : ''), checks, causes: [{ cause: it.title, confidence: m.collector.quiet && it.kind !== 'collector-quiet' ? 'low' : 'high', fix: it.recommendation || '' }] };
    },
    async verify(it) {
      const f = await current(true);
      if (f === null) return { present: null, note: 'inventory and sources not readable now' };
      const m = await model();
      if (!m.inventory.connected && /^(silent|waiting|absent|noconn):/.test(it.key)) return { present: null, note: 'IT Asset Management not reachable - not yet known' };
      const present = f.some((x) => x.key === it.key);
      return { present, note: present ? 'still reported by the log-flow check' : 'the log-flow check no longer reports it' };
    },
  };
  return { model, adapter, current };
}

module.exports = { createAssurance };
