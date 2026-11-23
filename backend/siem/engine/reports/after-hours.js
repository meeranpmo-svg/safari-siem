// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * After-hours activity monitoring — who logs on, administers and moves data outside business hours.
 * Business hours = the shared calendar (engine/util/business-hours.js: working days, start/end, holidays, per-site
 * overrides, Asia/Riyadh), the SAME one the rule engine uses for SENTRA-AUTH-007 / SENTRA-ORA-002.
 * Ported from the earlier portal's after-hours features and adapted to SIEM data:
 *   - per-user file roll-up (active days, after-hours downloads, after-hours days, busiest day, mass-download flag,
 *     sharing / external sharing counts) for SharePoint / OneDrive (M365 unified audit) and DLP;
 *   - configurable business hours (working days, start/end, Riyadh offset) incl. the SLA clock that rolls over
 *     weekends (business-hours.js addBusinessMinutes);
 *   - after-hours alerting: toggles for the existing rules / UEBA detector (nothing is enabled implicitly).
 * Data: ClickHouse siem.events only (read-only, bounded). No figures are estimated; a failed query → null panel.
 *
 *   createAfterHours({ ch, state, config, log, now, store (business-hours store), ruleAdmin?() , ueba?, alerts? })
 *     → { summary(query), events(query), settings(), setSettings(body, by), alerting(), setAlerting(id, enabled, by), SQL(calendar) }
 *
 * summary → { generated_at, period, business_hours (describe()), clickhouse{ok, errors[]},
 *   kinds[{kind, events, after_hours}] | null, logons[{user, host, src_ip, kind, success, failed, first_ms, last_ms}] | null,
 *   admin_actions[{user, host, kind, src_type, events, example, event_code, last_ms}] | null,
 *   files[{user, files, after_hours_files, after_hours_days, active_days, busiest_day, busiest_day_files, mass_download,
 *          shares, external, dlp, last_after_hours_ms}] | null, files_available,
 *   users[{user, active_days, after_hours_days, after_hours_events, logons, admin, file, busiest_day, busiest_day_events, last_after_hours_ms}] | null,
 *   hosts[same with host] | null, heat[{dow, hour, events}] | null, mass_download_threshold }
 * events(query: period|from&to, user?, host?, group? logon|admin|file, limit ≤ 200) → { items[{ts, user, host, src_ip, src_id,
 *   src_type, action, outcome, event_code, kind, message, reason, site}] }
 */
const { resolvePeriod, TIME_WHERE, tparams, runQueries, toMs, DAY } = require('./common');
const { detectorConfig } = require('../ueba/settings');

const ADMIN_RE = '^(adm[-_.]|admin|administrator$|root$)|([-_.]adm|admin)$';
const ADMIN_ACTIONS = ['user-created', 'user-deleted', 'user-modified', 'user-enabled', 'password-change', 'privileges-assigned', 'role-assigned', 'service-installed', 'audit-log-cleared', 'scheduled-task-created'];
const q = (a) => a.map((s) => `'${s}'`).join(', ');
const SPO = `(src_type = 'm365' AND host IN ('sharepoint', 'onedrive'))`;
const KIND = `multiIf(
    action = 'logon' AND outcome = 'success' AND (has(tags, 'admin') OR match(lower(user), '${ADMIN_RE}')) AND NOT endsWith(user, '$') AND fields['logon_type'] NOT IN ('3', '4', '5'), 'admin_logon',
    action IN ('logon', 'logon-failed') AND (has(tags, 'vpn') OR fields['subtype'] = 'vpn' OR positionCaseInsensitive(fields['logdesc'], 'vpn') > 0), 'logon_vpn',
    action IN ('logon', 'logon-failed') AND fields['logon_type'] = '10', 'logon_remote',
    action IN ('logon', 'logon-failed') AND fields['logon_type'] IN ('2', '7', '11'), 'logon_interactive',
    action IN ('logon', 'logon-failed') AND user != '' AND NOT endsWith(user, '$') AND fields['logon_type'] NOT IN ('3', '4', '5'), 'logon_other',
    action = 'config-change', 'admin_config',
    action = 'exchange-cmdlet' OR (src_type = 'm365' AND host = 'exchange' AND match(event_code, '^[A-Za-z]+-[A-Za-z]')), 'admin_exchange',
    action IN ('group-member-added', 'group-member-removed'), 'admin_group',
    action IN (${q(ADMIN_ACTIONS)}), 'admin_account',
    action = 'dlp-incident', 'file_dlp',
    (category = 'file' OR ${SPO}) AND positionCaseInsensitive(event_code, 'download') > 0, 'file_download',
    ${SPO} AND match(event_code, '(?i)sharing|anonymouslink|securelink|companylink'), 'file_share',
    category = 'file' OR ${SPO}, 'file_other',
    '')`;
const EXT = `toUInt8(match(event_code, '(?i)anonymouslink') OR fields['TargetUserOrGroupType'] = 'Guest')`;
const ACTIVITY = `(action IN ('logon', 'logon-failed', 'config-change', 'exchange-cmdlet', 'group-member-added', 'group-member-removed', 'dlp-incident', ${q(ADMIN_ACTIONS)})
    OR category = 'file' OR (src_type = 'm365' AND host IN ('sharepoint', 'onedrive', 'exchange')))`;
const LOGON = `(startsWith(kind, 'logon_') OR kind = 'admin_logon')`;
const KINDS = ['logon_interactive', 'logon_remote', 'logon_vpn', 'logon_other', 'admin_logon', 'admin_config', 'admin_exchange', 'admin_group', 'admin_account', 'file_download', 'file_share', 'file_dlp', 'file_other'];
const GROUPS = { logon: LOGON, admin: `startsWith(kind, 'admin_')`, file: `startsWith(kind, 'file_')` };

const ALERTING = [
  { id: 'SENTRA-AUTH-007', kind: 'rule', title: 'Admin account logon outside business hours' },
  { id: 'SENTRA-ORA-002', kind: 'rule', title: 'Oracle DBA logon outside business hours' },
  { id: 'ueba:off_hours_activity', kind: 'ueba', detector: 'off_hours_activity', title: 'UEBA: activity outside the user\'s normal hours' },
];

function sqlFor(cal, db = 'siem') {
  const ah = cal.sql({ ts: 'ts', src: 'src_id' });
  const AHQ = `SELECT ts, user, host, src_ip, src_id, src_type, action, outcome, event_code, message, ${KIND} AS kind, ${ah.expr} AS ah, ${EXT} AS ext,
      intDiv(toUnixTimestamp64Milli(ts) + {t_off:Int64}, ${DAY}) AS d, intDiv((toUnixTimestamp64Milli(ts) + {t_off:Int64}) % ${DAY}, 3600000) AS hr
    FROM ${db}.events WHERE ${TIME_WHERE} AND ${ACTIVITY}`;
  const perEntity = (ent, tag) => `/* sentra:${tag} */ SELECT ${ent}, count() AS active_days, countIf(n_ah > 0) AS ah_days, sum(n_ah) AS ah_events,
      sum(n_logon) AS ah_logons, sum(n_admin) AS ah_admin, sum(n_file) AS ah_file, argMax(d, n_ah) AS busiest_d, max(n_ah) AS busiest_n, max(last_ah) AS last_ah_ms
    FROM (SELECT ${ent}, d, countIf(ah = 1) AS n_ah, countIf(ah = 1 AND ${LOGON}) AS n_logon, countIf(ah = 1 AND startsWith(kind, 'admin_')) AS n_admin,
        countIf(ah = 1 AND startsWith(kind, 'file_')) AS n_file, maxIf(toUnixTimestamp64Milli(ts), ah = 1) AS last_ah
      FROM (${AHQ}) WHERE kind != '' AND ${ent} != ''${ent === 'user' ? " AND NOT endsWith(user, '$')" : ''} GROUP BY ${ent}, d)
    GROUP BY ${ent} HAVING ah_events > 0 ORDER BY ah_events DESC LIMIT 200`;
  return {
    params: ah.params,
    kinds: `/* sentra:ah-kinds */ SELECT kind, count() AS n, countIf(ah = 1) AS n_ah FROM (${AHQ}) WHERE kind != '' GROUP BY kind`,
    logons: `/* sentra:ah-logons */ SELECT user, host, src_ip, kind, countIf(action = 'logon' AND outcome != 'failure') AS n_ok,
        countIf(action = 'logon-failed' OR outcome = 'failure') AS n_fail, toUnixTimestamp64Milli(min(ts)) AS first_ms, toUnixTimestamp64Milli(max(ts)) AS last_ms
      FROM (${AHQ}) WHERE ah = 1 AND ${LOGON} GROUP BY user, host, src_ip, kind ORDER BY last_ms DESC LIMIT 200`,
    admin: `/* sentra:ah-admin */ SELECT user, host, kind, src_type, count() AS n, any(message) AS example, any(event_code) AS code, toUnixTimestamp64Milli(max(ts)) AS last_ms
      FROM (${AHQ}) WHERE ah = 1 AND startsWith(kind, 'admin_') GROUP BY user, host, kind, src_type ORDER BY last_ms DESC LIMIT 200`,
    files: `/* sentra:ah-files */ SELECT user, sum(n_dl) AS files, sum(n_dl_ah) AS ah_files, countIf(n_dl_ah > 0) AS ah_days, count() AS active_days,
        max(n_dl) AS max_day, argMax(d, n_dl) AS busiest_d, sum(n_share) AS shares, sum(n_ext) AS n_external, sum(n_dlp) AS dlp, max(last_ah) AS last_ah_ms
      FROM (SELECT user, d, countIf(kind = 'file_download') AS n_dl, countIf(kind = 'file_download' AND ah = 1) AS n_dl_ah, countIf(kind = 'file_share') AS n_share,
          countIf(ext = 1) AS n_ext, countIf(kind = 'file_dlp') AS n_dlp, maxIf(toUnixTimestamp64Milli(ts), ah = 1) AS last_ah
        FROM (${AHQ}) WHERE startsWith(kind, 'file_') AND user != '' GROUP BY user, d)
      GROUP BY user ORDER BY ah_files DESC, files DESC LIMIT 100`,
    users: perEntity('user', 'ah-users'),
    hosts: perEntity('host', 'ah-hosts'),
    heat: `/* sentra:ah-heat */ SELECT (d + 4) % 7 AS dow, hr, count() AS n FROM (${AHQ}) WHERE ah = 1 AND kind != '' GROUP BY dow, hr`,
    events: (group, byUser, byHost) => `/* sentra:ah-events */ SELECT toUnixTimestamp64Milli(ts) AS t_ms, user, host, src_ip, src_id, src_type, action, outcome, event_code, kind, message
      FROM (${AHQ}) WHERE ah = 1 AND kind != ''${group ? ` AND ${GROUPS[group]}` : ''}${byUser ? ' AND user = {f_user:String}' : ''}${byHost ? ' AND host = {f_host:String}' : ''}
      ORDER BY t_ms DESC LIMIT {lim:UInt16}`,
  };
}

const n = (v) => Number(v) || 0;
const dateOf = (d) => (Number.isFinite(Number(d)) && Number(d) > 0 ? new Date(Number(d) * DAY).toISOString().slice(0, 10) : '');

function createAfterHours({ ch, state, config = {}, log, now = Date.now, store, ruleAdmin, ueba, alerts, detector } = {}) {
  if (!store) throw new Error('createAfterHours needs the business-hours store');
  const L = log || { info() {}, warn() {}, error() {} };
  const db = (config.clickhouse && config.clickhouse.database) || 'siem';
  const col = state ? state.collection('business_hours') : null;
  const offMin = () => store.calendar().config.utc_offset_min;
  const extra = () => { const d = col && col.get('after-hours'); return Object.assign({ mass_download_threshold: 50 }, d && d.value ? d.value : {}); };

  function settings() {
    return { business_hours: store.get(), mass_download_threshold: extra().mass_download_threshold, defaults: Object.assign(store.defaults(), { mass_download_threshold: 50 }), sites: siteList(), effective: store.calendar().describe() };
  }
  function siteList() {
    const known = (config.onboard && Array.isArray(config.onboard.sites)) ? config.onboard.sites : [];
    return store.sites().map((id) => { const s = known.find((x) => x && x.id === id) || {}; return { id, name: s.name || id, kind: s.kind || '' }; });
  }
  function setSettings(body, by) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw Object.assign(new Error('body must be an object'), { code: 400 });
    const unknown = Object.keys(body).filter((k) => !['business_hours', 'mass_download_threshold'].includes(k));
    if (unknown.length) throw Object.assign(new Error(`unknown setting(s): ${unknown.join(', ')}`), { code: 400 });
    if (body.mass_download_threshold !== undefined) {
      const t = Number(body.mass_download_threshold);
      if (!Number.isInteger(t) || t < 1 || t > 100000) throw Object.assign(new Error('mass_download_threshold must be an integer 1-100000'), { code: 400 });
    }
    if (body.business_hours !== undefined) store.set(body.business_hours, by); // validates; throws 400 with errors[]
    if (body.mass_download_threshold !== undefined && col) col.put({ id: 'after-hours', value: Object.assign(extra(), { mass_download_threshold: Number(body.mass_download_threshold) }), updated: now(), by: by || '' });
    return settings();
  }

  async function summary(query = {}) {
    const p = resolvePeriod(query, now());
    const cal = store.calendar();
    const S = sqlFor(cal, db);
    const params = Object.assign(tparams(p, offMin()), S.params);
    const { results: R, errors } = await runQueries(ch, { kinds: [S.kinds, params], logons: [S.logons, params], admin: [S.admin, params], files: [S.files, params], users: [S.users, params], hosts: [S.hosts, params], heat: [S.heat, params] });
    const thr = extra().mass_download_threshold;
    const ent = (key) => (r) => ({ [key]: String(r[key]), active_days: n(r.active_days), after_hours_days: n(r.ah_days), after_hours_events: n(r.ah_events), logons: n(r.ah_logons), admin: n(r.ah_admin), file: n(r.ah_file), busiest_day: dateOf(r.busiest_d), busiest_day_events: n(r.busiest_n), last_after_hours_ms: toMs(r.last_ah_ms) || 0 });
    const out = {
      generated_at: new Date(now()).toISOString(), period: { from: p.from, to: p.to, label: p.label, utc_offset_min: offMin() },
      business_hours: cal.describe(), clickhouse: { ok: !errors.length, errors }, mass_download_threshold: thr,
      kinds: R.kinds ? KINDS.map((k) => { const r = R.kinds.find((x) => x.kind === k); return { kind: k, events: r ? n(r.n) : 0, after_hours: r ? n(r.n_ah) : 0 }; }) : null,
      logons: R.logons ? R.logons.map((r) => ({ user: String(r.user || ''), host: String(r.host || ''), src_ip: String(r.src_ip || ''), kind: String(r.kind), success: n(r.n_ok), failed: n(r.n_fail), first_ms: toMs(r.first_ms), last_ms: toMs(r.last_ms) })) : null,
      admin_actions: R.admin ? R.admin.map((r) => ({ user: String(r.user || ''), host: String(r.host || ''), kind: String(r.kind), src_type: String(r.src_type || ''), events: n(r.n), example: String(r.example || '').slice(0, 300), event_code: String(r.code || ''), last_ms: toMs(r.last_ms) })) : null,
      files: R.files ? R.files.map((r) => ({ user: String(r.user), files: n(r.files), after_hours_files: n(r.ah_files), after_hours_days: n(r.ah_days), active_days: n(r.active_days), busiest_day: dateOf(r.busiest_d), busiest_day_files: n(r.max_day), mass_download: n(r.max_day) >= thr, shares: n(r.shares), external: n(r.n_external), dlp: n(r.dlp), last_after_hours_ms: toMs(r.last_ah_ms) || 0 })) : null,
      users: R.users ? R.users.map(ent('user')) : null,
      hosts: R.hosts ? R.hosts.map(ent('host')) : null,
      heat: R.heat ? R.heat.map((r) => ({ dow: n(r.dow), hour: n(r.hr), events: n(r.n) })) : null,
    };
    out.files_available = R.kinds ? R.kinds.some((x) => String(x.kind).startsWith('file_') && n(x.n) > 0) : null;
    if (errors.length) L.warn('after-hours: some panels unavailable', { failed: errors.map((e) => e.panel) });
    return out;
  }

  async function events(query = {}) {
    const p = resolvePeriod(query, now());
    const group = query.group ? String(query.group) : '';
    if (group && !GROUPS[group]) throw Object.assign(new Error('group must be logon, admin or file'), { code: 400 });
    const user = query.user ? String(query.user).slice(0, 256) : '';
    const host = query.host ? String(query.host).slice(0, 256) : '';
    const lim = Math.max(1, Math.min(200, Number(query.limit) || 100));
    const cal = store.calendar();
    const S = sqlFor(cal, db);
    const params = Object.assign(tparams(p, offMin()), S.params, { lim: { type: 'UInt16', value: lim } });
    if (user) params.f_user = { type: 'String', value: user };
    if (host) params.f_host = { type: 'String', value: host };
    if (!ch || typeof ch.query !== 'function') throw Object.assign(new Error('ClickHouse client not available'), { code: 503 });
    const rows = await ch.query(S.events(group, !!user, !!host), params, { readonly: true, timeout_ms: 20000 });
    return {
      period: { from: p.from, to: p.to, label: p.label },
      items: rows.map((r) => {
        const t = toMs(r.t_ms); const site = cal.siteOf({ src_id: r.src_id });
        return { ts: t, user: String(r.user || ''), host: String(r.host || ''), src_ip: String(r.src_ip || ''), src_id: String(r.src_id || ''), src_type: String(r.src_type || ''), action: String(r.action || ''), outcome: String(r.outcome || ''), event_code: String(r.event_code || ''), kind: String(r.kind || ''), message: String(r.message || '').slice(0, 500), reason: cal.reason(t, site), site };
      }),
    };
  }

  // ---------------- after-hours alerting toggles (existing rules / UEBA detector; changed only by an explicit admin call)
  function ruleList() {
    try { const ra = typeof ruleAdmin === 'function' ? ruleAdmin() : ruleAdmin; if (ra && typeof ra.list === 'function') return ra.list(); } catch { /* below */ }
    try { if (detector && typeof detector.rules === 'function') return detector.rules(); } catch { /* none */ }
    return [];
  }
  function alerting() {
    const rules = ruleList();
    const since = now() - 7 * DAY;
    const counts = new Map();
    if (alerts && typeof alerts.all === 'function') for (const a of alerts.all((x) => x.created >= since)) counts.set(a.rule_id, (counts.get(a.rule_id) || 0) + 1);
    return ALERTING.map((t) => {
      if (t.kind === 'rule') {
        const r = rules.find((x) => x && x.id === t.id);
        return { id: t.id, kind: 'rule', title: r ? r.name : t.title, available: !!r, enabled: r ? r.enabled !== false : false, severity: r ? r.severity : null, uses_business_hours: r ? JSON.stringify(r.match || {}).includes('outside_business_hours') : false, alerts_7d: counts.get(t.id) || 0 };
      }
      let enabled = false; let available = false;
      try { if (ueba && typeof ueba.getSettings === 'function') { available = true; enabled = detectorConfig(ueba.getSettings().settings, t.detector).enabled !== false; } } catch { available = false; }
      return { id: t.id, kind: 'ueba', title: t.title, available, enabled, severity: null, uses_business_hours: false, alerts_7d: null };
    });
  }
  function setAlerting(id, enabled, by) {
    const t = ALERTING.find((x) => x.id === id);
    if (!t) throw Object.assign(new Error(`unknown after-hours alert ${id}`), { code: 404 });
    if (typeof enabled !== 'boolean') throw Object.assign(new Error('enabled must be true or false'), { code: 400 });
    if (t.kind === 'rule') {
      const ra = typeof ruleAdmin === 'function' ? ruleAdmin() : ruleAdmin;
      if (!ra || typeof ra.setEnabled !== 'function') throw Object.assign(new Error('rule administration is not available'), { code: 503 });
      ra.setEnabled(t.id, enabled, by);
    } else {
      if (!ueba || typeof ueba.setSettings !== 'function') throw Object.assign(new Error('UEBA is not active'), { code: 503 });
      ueba.setSettings({ detectors: { [t.detector]: { enabled } } }, by);
    }
    L.info('after-hours alerting changed', { id, enabled, by: by || '' });
    return alerting().find((x) => x.id === id);
  }

  return { summary, events, settings, setSettings, alerting, setAlerting, SQL: (cal) => sqlFor(cal || store.calendar(), db), KINDS };
}

module.exports = { createAfterHours, sqlFor, KINDS, ALERTING };
