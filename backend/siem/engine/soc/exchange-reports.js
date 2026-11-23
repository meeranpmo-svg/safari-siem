// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Exchange Reports ({P} = /api/soc; page dashboards/server/exchange-reports.html, Reporting Center "exchange").
 * Built on the AI Exchange Server Administrator's READ-ONLY, allow-listed checks (engine/sysadmin/checks.json, run over
 * WinRM by ps-helper.py - the platform never runs a script of its own and never changes Exchange):
 *   ex_inv_databases · ex_inv_mailboxes (per database, paged) · ex_inv_cas (paged) · ex_inv_permissions (per database,
 *   paged) · ex_inv_groups (paged) · ex_inv_public_folders · ex_inv_mobile (paged)
 * Once a day (Riyadh hour settings.collect_hour, default 02:00) and on "Collect now" (operator) the inventory is read from
 * the first Exchange server that has a login; each part is kept with its own time and error, so a part that failed keeps
 * its last good copy marked with its age - never an empty list shown as "nothing there". Every day's mailbox sizes are
 * kept (exrep_daily, settings.keep_days, default 180) so SIZE GROWTH per mailbox and per database is a trend.
 * Exchange Online (where Microsoft 365 is connected): Microsoft Graph reports getMailboxUsageDetail and
 * getEmailActivityUserDetail (Reports.Read.All) through the SIEM's existing app registration (collect/m365-graph.js).
 * Mail traffic is GET {P}/mail/traffic (engine/soc/mailstats.js); OWA / ActiveSync logons come from the IIS logs
 * (engine/parse/iis.js tags exchange-owa / exchange-microsoft-server-activesync and the ActiveSync device fields).
 *
 * PDPL: mailbox owners, delegates, list members and device owners are personal data - only an ADMINISTRATOR sees names
 * (and every named view is audited); every other role sees counts. Message bodies and subjects are never read.
 *
 *   GET  {P}/exchange/reports/status            viewer    what is collected, when, from which server, errors, settings
 *   GET  {P}/exchange/reports/summary           viewer    counts, trends, distributions (no names)
 *   GET  {P}/exchange/reports/mailboxes         admin     ?view=all|largest|growing|quota|inactive|hidden|forwarding|features
 *                                                         &q &type &database &days &feature &limit                  audited
 *   GET  {P}/exchange/reports/permissions       admin     ?view=mailbox|holders &right &q &limit                         audited
 *   GET  {P}/exchange/reports/groups            admin     ?view=all|external|empty|nested|dynamic &q &limit             audited
 *   GET  {P}/exchange/reports/public-folders    admin     ?q &limit                                                     audited
 *   GET  {P}/exchange/reports/devices           admin     ?view=all|stale|unapproved|blocked &q &limit (Get-MobileDevice) audited
 *   GET  {P}/exchange/reports/clients           viewer    ?range=1|7|30  OWA / ActiveSync from IIS (names: admin)
 *   GET  {P}/exchange/reports/online            viewer    Exchange Online usage (names: admin)
 *   GET  {P}/exchange/reports/digest            admin     KPIs + top tables for the Reporting Center                   audited
 *   PUT  {P}/exchange/reports/settings          admin     thresholds, approved device models, our domains, schedule    audited
 *   POST {P}/exchange/reports/collect           operator  {parts?} read the inventory now (read-only checks)          audited
 */
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');
const { body } = require('../util/check');
const { guard } = require('../util/errors');
const mailstats = require('./mailstats');

const RIYADH = 3 * 3600000, DAY = 86400000;
const PARTS = ['databases', 'mailboxes', 'cas', 'permissions', 'groups', 'public_folders', 'mobile', 'online'];
const DEFAULTS = { enabled: true, collect_hour: 2, inactive_days: 90, stale_device_days: 30, near_quota_pct: 90, keep_days: 180, approved_models: [], internal_domains: [] };
const DOMAIN_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const GROUP_TYPE = /group$|^roomlist$/i;
const STOP_KINDS = /^(auth|missing|no-login|certificate)$/;
const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n || 300);
const mb = (b) => (b == null || b === '' || !Number.isFinite(Number(b)) ? null : Math.round(Number(b) / 104857.6) / 10);
const gb = (m) => (m == null ? null : Math.round(m / 102.4) / 10);
const riyadhDay = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
const iso = (v) => { const t = Date.parse(v || ''); return Number.isFinite(t) && t > 0 ? new Date(t).toISOString() : null; };
const smtp = (v) => { const x = s(v, 320).replace(/^smtp:/i, '').toLowerCase(); return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x) ? x : ''; };
const domainOf = (a) => { const i = String(a || '').lastIndexOf('@'); return i > 0 ? String(a).slice(i + 1).toLowerCase() : ''; };
const nameOf = (canon) => { const x = s(canon, 300); const i = x.lastIndexOf('/'); return i >= 0 ? x.slice(i + 1) : x; };   // corp.sa/Users/Jane Doe -> Jane Doe
const bytesOf = (str) => { const m = /\(([\d,.\s]+) bytes\)/i.exec(String(str || '')); return m ? Number(m[1].replace(/[^\d]/g, '')) : null; };
const bool = (v) => (v === true || v === 'True' || v === 'true' ? true : v === false || v === 'False' || v === 'false' ? false : null);
const pct = (a, b) => (a == null || !b ? null : Math.round(a / b * 1000) / 10);

/* ---------------------------------------------------------------- normalisation (what the checks return -> what we keep) */
function normMailbox(x) {
  const address = smtp(x.address);
  if (!address) return null;
  const size = mb(x.size_bytes), quota = mb(x.prohibit_send_bytes);
  return { address, name: s(x.name, 200), type: s(x.type, 60) || 'UserMailbox', database: s(x.database, 100), size_mb: size, deleted_mb: mb(x.deleted_bytes),
    items: Number.isFinite(Number(x.items)) && x.items !== null && x.items !== '' ? Number(x.items) : null, last_logon: iso(x.last_logon),
    quota_mb: quota, warning_mb: mb(x.warning_bytes), quota_from_database: !!x.quota_from_database, used_pct: pct(size, quota),
    archive: /^active$/i.test(s(x.archive, 20)), hidden: !!x.hidden, litigation_hold: !!x.litigation_hold,
    forwarding: smtp(x.forwarding_smtp) || smtp(x.forwarding_recipient) || null, deliver_and_forward: !!x.deliver_and_forward, created: iso(x.created) };
}
function normCas(x) {
  const address = smtp(x.address); if (!address) return null;
  return { address, owa: bool(x.owa), eas: bool(x.eas), pop: bool(x.pop), imap: bool(x.imap), mapi: bool(x.mapi), ews: bool(x.ews), eas_policy: s(x.eas_policy, 100) };
}
function normPerm(x) {
  const mailbox = smtp(x.mailbox); if (!mailbox) return null;
  const list = (v) => [...new Set(arr(v).map((u) => s(u, 200)).filter(Boolean))];
  return { mailbox, name: s(x.name, 200), type: s(x.type, 60), full_access: list(x.full_access), send_as: list(x.send_as), send_on_behalf: list(x.send_on_behalf).map((u) => smtp(u) || u) };
}
function normGroup(x) {
  const address = smtp(x.address); if (!address) return null;
  return { address, name: s(x.name, 200), type: s(x.type, 60), hidden: !!x.hidden, accepts_external: !!x.accepts_external, managed_by: arr(x.managed_by).map((m) => nameOf(m)).filter(Boolean),
    members: arr(x.members).slice(0, 5000).map((m) => ({ address: smtp(m.address) || '', name: s(m.name, 200), type: s(m.type, 60), external: smtp(m.external) || '' })) };
}
function normFolder(x) {
  return { path: s(x.path, 400), mail_enabled: !!x.mail_enabled, content_mailbox: s(x.content_mailbox, 120), items: Number.isFinite(Number(x.items)) && x.items !== null ? Number(x.items) : null, size_mb: mb(bytesOf(x.size)), last_modified: iso(x.last_modified) };
}
function normDevice(x) {
  return { owner: nameOf(x.owner), device_id: s(x.device_id, 64), model: s(x.model, 80), type: s(x.type, 60), os: s(x.os, 80), client: s(x.client, 30), access: s(x.access, 30), access_reason: s(x.access_reason, 40),
    policy: s(x.policy, 100), policy_status: s(x.policy_status, 40), first_sync: iso(x.first_sync), last_sync: iso(x.last_sync) };
}

/* ---------------------------------------------------------------- analysis (pure: tested directly) */
function internalDomains(settings, inv) {
  const set = new Set((settings.internal_domains || []).map((d) => d.toLowerCase()));
  const derived = !set.size;
  if (derived) for (const m of (inv.mailboxes && inv.mailboxes.data) || []) { const d = domainOf(m.address); if (d) set.add(d); }
  return { set, derived };
}
// our domains and their sub-domains (a remote mailbox in Exchange Online keeps its primary address in our domain)
const isInternal = (dom, set) => !!dom && [...set].some((d) => dom === d || dom.endsWith('.' + d));

// the daily snapshot nearest to (on or before) `day`, else the oldest one older than today
function refSnapshot(daily, today, days) {
  const want = riyadhDay(Date.parse(today + 'T12:00:00Z') - RIYADH - days * DAY);
  const older = daily.filter((d) => d.day < today).sort((a, b) => a.day.localeCompare(b.day));
  if (!older.length) return null;
  const on = older.filter((d) => d.day <= want);
  return on.length ? on[on.length - 1] : older[0];
}
function growthOf(mailboxes, daily, today, days) {
  const ref = refSnapshot(daily, today, days);
  if (!ref) return { ref: null, days: 0, by: new Map() };
  const then = new Map(arr(ref.mb).map((r) => [r[0], r[1]])), by = new Map();
  for (const m of mailboxes) if (m.size_mb != null && then.has(m.address) && then.get(m.address) != null) { const g = Math.round((m.size_mb - then.get(m.address)) * 10) / 10; by.set(m.address, { mb: g, pct: then.get(m.address) ? Math.round(g / then.get(m.address) * 1000) / 10 : null }); }
  const actual = Math.round((Date.parse(today) - Date.parse(ref.day)) / DAY);
  return { ref: ref.day, days: actual, by };
}

const SIZE_BANDS = [['< 1 GB', 0, 1024], ['1-5 GB', 1024, 5120], ['5-10 GB', 5120, 10240], ['10-25 GB', 10240, 25600], ['25-50 GB', 25600, 51200], ['> 50 GB', 51200, Infinity]];
function inactiveOf(m, days, now) { return /^UserMailbox$/i.test(m.type) && (!m.last_logon || now - Date.parse(m.last_logon) > days * DAY); }

// expand distribution lists: direct members, nested lists followed (bounded: depth 5, 5000 people, cycles stopped)
function expandGroups(groups, internal) {
  const byAddr = new Map(groups.map((g) => [g.address, g]));
  return groups.map((g) => {
    const people = new Map(), nested = new Set(); let truncated = false;
    const queue = [[g, 0]], seen = new Set([g.address]);
    while (queue.length) {
      const [cur, depth] = queue.shift();
      for (const m of cur.members) {
        if (GROUP_TYPE.test(m.type)) {
          nested.add(m.address || m.name);
          const sub = byAddr.get(m.address);
          if (sub && !seen.has(sub.address)) { if (depth >= 5) { truncated = true; continue; } seen.add(sub.address); queue.push([sub, depth + 1]); }
          continue;
        }
        const key = m.address || m.external || m.name; if (!key || people.has(key)) continue;
        if (people.size >= 5000) { truncated = true; break; }
        // a contact / mail user is delivered to its external address; anyone else (mailbox, remote mailbox in Exchange Online)
        // is ours when the primary address is in our domains
        const contact = /^(MailContact|MailUser|GuestMailUser)$/i.test(m.type), addr = contact ? (m.external || m.address) : (m.address || m.external), dom = domainOf(addr);
        const external = contact ? !dom || !isInternal(dom, internal) : !!dom && !isInternal(dom, internal);
        people.set(key, { address: addr, name: m.name, type: m.type, external, via: cur === g ? '' : cur.name });
      }
    }
    const list = [...people.values()];
    return { address: g.address, name: g.name, type: g.type, hidden: g.hidden, accepts_external: g.accepts_external, managed_by: g.managed_by, direct: g.members.length,
      nested: [...nested], members: list.length, external: list.filter((p) => p.external), truncated, people: list };
  });
}

function holdersOf(perms) {
  const by = new Map();
  const add = (h, right, p) => { const k = h.toLowerCase(); const x = by.get(k) || { holder: h, mailboxes: new Set(), full_access: 0, send_as: 0, send_on_behalf: 0, list: [] }; x.mailboxes.add(p.mailbox); x[right]++; x.list.push({ mailbox: p.mailbox, name: p.name, right }); by.set(k, x); };
  for (const p of perms) { p.full_access.forEach((h) => add(h, 'full_access', p)); p.send_as.forEach((h) => add(h, 'send_as', p)); p.send_on_behalf.forEach((h) => add(h, 'send_on_behalf', p)); }
  return [...by.values()].map((x) => ({ holder: x.holder, mailboxes: x.mailboxes.size, full_access: x.full_access, send_as: x.send_as, send_on_behalf: x.send_on_behalf, grants: x.list.slice(0, 200) })).sort((a, b) => b.mailboxes - a.mailboxes || a.holder.localeCompare(b.holder));
}

function deviceFlags(d, settings, now) {
  const stale = !d.last_sync || now - Date.parse(d.last_sync) > settings.stale_device_days * DAY;
  const models = (settings.approved_models || []).map((m) => m.toLowerCase());
  const unapproved = models.length ? !models.some((m) => (d.model + ' ' + d.type + ' ' + d.os).toLowerCase().includes(m)) : null;
  return { stale, unapproved, blocked: /blocked|quarantined/i.test(d.access) };
}

/* ---------------------------------------------------------------- Exchange Online (Graph usage reports, CSV) */
function parseCsv(text) {
  const t = String(text || '').replace(/^﻿/, ''), rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === '"') { if (t[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; continue; }
    if (c === '"') q = true; else if (c === ',') { row.push(cell); cell = ''; } else if (c === '\n' || c === '\r') { if (c === '\r' && t[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; } else cell += c;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  const head = (rows.shift() || []).map((h) => h.trim().toLowerCase());
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] == null ? '' : r[i]])));
}
const n0 = (v) => (v === '' || v == null || !Number.isFinite(Number(v)) ? null : Number(v));
function onlineFrom(usageCsv, activityCsv) {
  const usage = parseCsv(usageCsv), act = new Map(parseCsv(activityCsv).map((r) => [String(r['user principal name'] || '').toLowerCase(), r]));
  const items = usage.filter((r) => !/^true$/i.test(r['is deleted'] || '')).map((r) => {
    const upn = String(r['user principal name'] || '').toLowerCase(), a = act.get(upn) || {};
    const used = mb(n0(r['storage used (byte)'])), quota = mb(n0(r['prohibit send quota (byte)']));
    return { upn: s(upn, 200), name: s(r['display name'], 200), type: s(r['recipient type'], 40), last_activity: r['last activity date'] || null, items: n0(r['item count']), size_mb: used, quota_mb: quota, used_pct: pct(used, quota),
      has_archive: /^true$/i.test(r['has archive'] || ''), sent: n0(a['send count']), received: n0(a['receive count']), read: n0(a['read count']), mail_last_activity: a['last activity date'] || null };
  });
  const refresh = (usage[0] && usage[0]['report refresh date']) || null;
  const concealed = items.length > 0 && items.filter((x) => /^[0-9a-f]{32}$/i.test(x.upn)).length > items.length / 2;
  return { refreshed: refresh, concealed, items };
}

/* ---------------------------------------------------------------- the collector */
function createExchangeReports({ state, sysadmin, graph, ch, config, log, now: nowFn } = {}) {
  if (!state) throw new Error('exchange reports need state');
  const L = log || { info() {}, warn() {}, every() {} }, now = nowFn || Date.now;
  const parts = state.collection('exrep_parts'), daily = state.collection('exrep_daily'), meta = state.collection('exrep_meta');
  const db = (config && config.clickhouse && config.clickhouse.database) || 'siem';
  let running = null, timer = null, stopped = false;
  const settings = () => Object.assign({}, DEFAULTS, ((config && config.exchange_reports) || {}), (meta.get('settings') || {}).values || {});
  const inv = () => Object.fromEntries(PARTS.map((p) => [p, parts.get(p) || null]));
  const warn = (key, msg, f) => { if (typeof L.every === 'function') L.every('exrep:' + key, 3600000, 'warn', msg, f); else L.warn(msg, f); };

  function servers() {
    if (!sysadmin || !sysadmin.targets) return [];
    return sysadmin.targets.list('exchange').filter((t) => t.poll !== false && sysadmin.targets.login(t, 'exchange'));
  }
  // one read-only check; on a connection / login failure the next Exchange server with a login is tried
  async function run(check, params, by) {
    const list = servers(); if (!list.length) throw Object.assign(new Error('no Exchange server with a login - add one under AI Exchange Server Administrator (Servers, Logins)'), { kind: 'no-login' });
    let last = null;
    for (const t of list) {
      try { const r = await sysadmin.runner.run(t.id, check, params, { by: by || 'exchange-reports', via: 'exchange-reports' }); return Object.assign(r, { server: t.name }); }
      catch (e) { last = e; if (!/^(auth|timeout|refused|certificate|error|no-login)$/.test(e.kind || '') && e.code !== 502 && e.code !== 409) throw e; }
    }
    throw last;
  }
  async function paged(check, base, take, by) {
    const items = []; let skip = 0, total = 0, pages = 0, first = null, server = '';
    do {
      const r = await run(check, Object.assign({}, base, { skip, take }), by), d = r.data || {};
      if (!first) first = d; server = r.server;
      const list = arr(d.items); total = Number(d.total) || 0; items.push(...list); skip += take; pages++;
      if (!list.length) break;
    } while (skip < total && pages < 400);
    return { items, total, first, server };
  }
  function keep(part, fn) {
    return async (by, ctx) => {
      const t0 = now();
      try { const r = await fn(by, ctx); parts.put(Object.assign({ id: part, at: t0, ms: now() - t0, ok: true, error: '' }, r)); return { part, ok: true }; }
      catch (e) {
        const prev = parts.get(part), err = s(e.message, 300);
        // a failed read keeps the last good data, marked with its age and the error
        parts.put(Object.assign({}, prev || { id: part, data: null }, { id: part, ok: false, error: err, failed_at: t0, kind: e.kind || '' }));
        warn(part, 'exchange report part failed', { part, err, kind: e.kind || '' });
        return { part, ok: false, error: err, kind: e.kind || '' };
      }
    };
  }
  const COLLECT = {
    databases: keep('databases', async (by, c) => { const r = await run('ex_inv_databases', {}, by); c.dbs = arr(r.data).filter((d) => d && d.name); return { server: r.server, data: c.dbs.map((d) => ({ name: s(d.name, 100), server: s(d.server, 100), mounted: d.mounted !== false, file_mb: mb(d.size_bytes), whitespace_mb: mb(d.whitespace_bytes), quota_mb: mb(d.prohibit_send_bytes), warning_mb: mb(d.warning_bytes) })) }; }),
    mailboxes: keep('mailboxes', async (by, c) => {
      const names = (c.dbs || arr((parts.get('databases') || {}).data)).map((d) => d.name).filter(Boolean);
      if (!names.length) throw new Error('no mailbox database was read - the databases part must succeed first');
      const out = [], errs = []; let server = '';
      for (const name of names) { try { const r = await paged('ex_inv_mailboxes', { database: name }, 500, by); server = r.server; out.push(...r.items.map(normMailbox).filter(Boolean)); } catch (e) { errs.push(name + ': ' + s(e.message, 120)); if (STOP_KINDS.test(e.kind || '')) throw e; } }
      if (errs.length === names.length) throw new Error(errs[0]);
      return { server, data: out, partial: errs };
    }),
    cas: keep('cas', async (by) => { const r = await paged('ex_inv_cas', {}, 1000, by); return { server: r.server, data: r.items.map(normCas).filter(Boolean) }; }),
    permissions: keep('permissions', async (by, c) => {
      const names = (c.dbs || arr((parts.get('databases') || {}).data)).map((d) => d.name).filter(Boolean);
      if (!names.length) throw new Error('no mailbox database was read - the databases part must succeed first');
      const out = [], errs = []; let server = '';
      for (const name of names) { try { const r = await paged('ex_inv_permissions', { database: name }, 100, by); server = r.server; out.push(...r.items.map(normPerm).filter(Boolean)); } catch (e) { errs.push(name + ': ' + s(e.message, 120)); if (STOP_KINDS.test(e.kind || '')) throw e; } }
      if (errs.length === names.length) throw new Error(errs[0]);
      return { server, data: out, partial: errs };
    }),
    groups: keep('groups', async (by) => { const r = await paged('ex_inv_groups', {}, 100, by); return { server: r.server, data: r.items.map(normGroup).filter(Boolean), dynamic: arr(r.first && r.first.dynamic).map((d) => ({ address: smtp(d.address), name: s(d.name, 200), hidden: !!d.hidden, accepts_external: !!d.accepts_external })).filter((d) => d.address) }; }),
    public_folders: keep('public_folders', async (by) => { const r = await run('ex_inv_public_folders', {}, by), d = r.data || {}; return { server: r.server, present: !!d.present, total: Number(d.total) || 0, data: arr(d.items).map(normFolder).filter((f) => f.path) }; }),
    mobile: keep('mobile', async (by) => { const r = await paged('ex_inv_mobile', {}, 200, by); return { server: r.server, data: r.items.map(normDevice).filter((d) => d.device_id || d.model) }; }),
    online: keep('online', async () => {
      if (!graph || typeof graph.graphContent !== 'function') throw Object.assign(new Error('Microsoft 365 is not connected to the SIEM'), { kind: 'not-connected' });
      const st = typeof graph.status === 'function' ? graph.status() : { ready: true };
      if (!st.ready) throw Object.assign(new Error('Microsoft 365 is not connected: ' + arr(st.missing).join('; ')), { kind: 'not-connected' });
      const get = async (fn) => { try { return (await graph.graphContent(`/reports/${fn}(period='D30')`, 50 * 1048576)).toString('utf8'); } catch (e) { if (e.status === 403) throw Object.assign(new Error('permission not granted: Reports.Read.All (application permission with admin consent)'), { kind: 'denied' }); throw e; } };
      const [u, a] = await Promise.all([get('getMailboxUsageDetail'), get('getEmailActivityUserDetail')]);
      const o = onlineFrom(u, a); return { server: 'Microsoft Graph', data: o.items, refreshed: o.refreshed, concealed: o.concealed };
    }),
  };

  // the day's sizes: per mailbox and per database (mailbox total + file size), for the growth trend
  function recordDay() {
    const m = parts.get('mailboxes'), d = parts.get('databases');
    if (!m || !m.ok || !Array.isArray(m.data)) return null;
    const day = riyadhDay(now()), dbs = {};
    for (const x of m.data) { const k = x.database || '?'; const e = dbs[k] || (dbs[k] = { mailbox_mb: 0, mailboxes: 0, file_mb: null, whitespace_mb: null }); e.mailbox_mb += x.size_mb || 0; e.mailboxes++; }
    for (const x of arr(d && d.data)) { const e = dbs[x.name] || (dbs[x.name] = { mailbox_mb: 0, mailboxes: 0 }); e.file_mb = x.file_mb; e.whitespace_mb = x.whitespace_mb; }
    for (const k of Object.keys(dbs)) dbs[k].mailbox_mb = Math.round(dbs[k].mailbox_mb * 10) / 10;
    daily.put({ id: day, day, at: now(), mb: m.data.map((x) => [x.address, x.size_mb, x.items]), db: dbs, totals: { mailboxes: m.data.length, size_mb: Math.round(m.data.reduce((t, x) => t + (x.size_mb || 0), 0) * 10) / 10 } });
    const cut = riyadhDay(now() - Math.min(400, Math.max(30, settings().keep_days)) * DAY);
    for (const old of daily.all((x) => x.day < cut)) daily.remove(old.id);
    return day;
  }

  async function collect(by, only) {
    if (running) return running;
    running = (async () => {
      const want = only && only.length ? PARTS.filter((p) => only.includes(p) || (p === 'databases' && (only.includes('mailboxes') || only.includes('permissions')))) : PARTS;
      const c = {}, results = [], t0 = now();
      meta.put(Object.assign({}, meta.get('run') || {}, { id: 'run', running: true, started_at: t0, by: by || '' }));
      try {
        for (const p of want) {
          const r = await COLLECT[p](by, c); results.push(r);
          if (!r.ok && STOP_KINDS.test(r.kind || '') && p !== 'online') {   // the login / helper is the problem: the other Exchange parts would fail the same way
            for (const q of want.filter((x) => x !== 'online' && !results.some((y) => y.part === x))) { const prev = parts.get(q); parts.put(Object.assign({}, prev || { id: q, data: null }, { id: q, ok: false, error: 'not read: ' + r.error, failed_at: now(), kind: r.kind })); results.push({ part: q, ok: false, error: 'not read: ' + r.error }); }
            if (want.includes('online') && !results.some((y) => y.part === 'online')) results.push(await COLLECT.online(by, c));
            break;
          }
        }
        const day = want.includes('mailboxes') ? recordDay() : null;
        if (!only || !only.length) meta.put(Object.assign({}, meta.get('run') || {}, { id: 'run', last_day: riyadhDay(t0) }));
        return { started_at: t0, ms: now() - t0, day, results };
      } finally { meta.put(Object.assign({}, meta.get('run') || {}, { id: 'run', running: false, finished_at: now() })); }
    })().finally(() => { running = null; });
    return running;
  }

  // once a day after settings.collect_hour (Riyadh); self-rescheduling, guarded, rescheduled in finally
  const daily_tick = guard('exchange.reports.daily', async () => {
    const st = settings(); if (st.enabled === false || !servers().length) return;
    const t = now(), hour = new Date(t + RIYADH).getUTCHours(), run0 = meta.get('run') || {};
    if (hour < st.collect_hour || run0.last_day === riyadhDay(t)) return;
    const r = await collect('system:exchange-reports');
    const failed = r.results.filter((x) => !x.ok && x.part !== 'online');
    if (failed.length && failed.length === r.results.filter((x) => x.part !== 'online').length) throw new Error('every Exchange inventory part failed: ' + failed[0].error);
  });
  function start() {
    if (timer || stopped) return;
    const loop = (ms) => { timer = setTimeout(async () => { try { await daily_tick(); } finally { if (!stopped) loop(30 * 60000); } }, ms); if (timer.unref) timer.unref(); };
    loop(3 * 60000);
  }
  function stop() { stopped = true; if (timer) clearTimeout(timer); timer = null; }

  /* ---- views */
  const partInfo = (p) => { const x = parts.get(p); return x ? { at: x.at || null, ok: !!x.ok, error: x.error || '', failed_at: x.failed_at || null, server: x.server || '', count: Array.isArray(x.data) ? x.data.length : null, partial: arr(x.partial).length } : { at: null, ok: false, error: '', count: null, never: true }; };
  function status() {
    const list = servers(), st = settings(), run0 = meta.get('run') || {};
    const gs = graph && typeof graph.status === 'function' ? graph.status() : null;
    return { connected: list.length > 0, servers: list.map((t) => t.name), reason: list.length ? '' : 'No Exchange server with a login: an administrator adds the Exchange servers and an Exchange login (read-only role groups: View-Only Organization Management) under AI Exchange Server Administrator.',
      parts: Object.fromEntries(PARTS.map((p) => [p, partInfo(p)])), running: !!running || !!run0.running, last_day: run0.last_day || null, started_at: run0.started_at || null, finished_at: run0.finished_at || null,
      days_held: daily.size(), settings: st, online: gs ? { ready: !!gs.ready, missing: arr(gs.missing) } : { ready: false, missing: ['the Microsoft 365 collector is not loaded'] } };
  }
  function mailboxesJoined() {
    const m = parts.get('mailboxes'), c = parts.get('cas'), cas = new Map(arr(c && c.data).map((x) => [x.address, x]));
    return arr(m && m.data).map((x) => Object.assign({}, x, { features: cas.get(x.address) || null }));
  }
  function summary() {
    const st = settings(), t = now(), today = riyadhDay(t), all = mailboxesJoined(), I = internalDomains(st, inv());
    const days = daily.all(() => true).sort((a, b) => a.day.localeCompare(b.day));
    const g30 = growthOf(all, days, today, 30);
    const has = (p) => { const x = parts.get(p); return !!(x && Array.isArray(x.data)); };
    const out = { generated_at: new Date(t).toISOString(), status: status(), domains: [...I.set].sort(), domains_derived: I.derived };
    if (has('mailboxes')) {
      const sz = all.reduce((a, x) => a + (x.size_mb || 0), 0), by_type = {}, by_db = {};
      for (const x of all) { by_type[x.type] = (by_type[x.type] || 0) + 1; const d = by_db[x.database] || (by_db[x.database] = { database: x.database, mailboxes: 0, size_mb: 0 }); d.mailboxes++; d.size_mb += x.size_mb || 0; }
      for (const d of arr((parts.get('databases') || {}).data)) { const e = by_db[d.name] || (by_db[d.name] = { database: d.name, mailboxes: 0, size_mb: 0 }); e.file_mb = d.file_mb; e.whitespace_mb = d.whitespace_mb; e.mounted = d.mounted; e.server = d.server; }
      const withF = all.filter((x) => x.features), feat = (k) => (withF.length ? withF.filter((x) => x.features[k] === true).length : null);
      out.mailboxes = { total: all.length, size_gb: gb(sz), by_type, by_database: Object.values(by_db).map((d) => ({ database: d.database, server: d.server || '', mounted: d.mounted, mailboxes: d.mailboxes, size_gb: gb(d.size_mb), file_gb: gb(d.file_mb), whitespace_gb: gb(d.whitespace_mb) })).sort((a, b) => (b.size_gb || 0) - (a.size_gb || 0)),
        size_bands: SIZE_BANDS.map(([label, lo, hi]) => ({ label, n: all.filter((x) => x.size_mb != null && x.size_mb >= lo && x.size_mb < hi).length })),
        near_quota: all.filter((x) => x.used_pct != null && x.used_pct >= st.near_quota_pct).length, over_warning: all.filter((x) => x.warning_mb && x.size_mb >= x.warning_mb).length, unlimited: all.filter((x) => x.quota_mb == null).length,
        inactive: all.filter((x) => inactiveOf(x, st.inactive_days, t)).length, never_logged_on: all.filter((x) => /^UserMailbox$/i.test(x.type) && !x.last_logon).length,
        hidden: all.filter((x) => x.hidden).length, litigation_hold: all.filter((x) => x.litigation_hold).length, archive: all.filter((x) => x.archive).length,
        forwarding: all.filter((x) => x.forwarding).length, forwarding_outside: all.filter((x) => x.forwarding && !isInternal(domainOf(x.forwarding), I.set)).length,
        features: { owa: feat('owa'), eas: feat('eas'), pop: feat('pop'), imap: feat('imap'), mapi: feat('mapi'), ews: feat('ews') },
        growth_30d: g30.ref ? { days: g30.days, since: g30.ref, gb: gb([...g30.by.values()].reduce((a, x) => a + x.mb, 0)) } : null, thresholds: { near_quota_pct: st.near_quota_pct, inactive_days: st.inactive_days } };
    } else out.mailboxes = null;
    out.trend = days.map((d) => ({ day: d.day, mailboxes: d.totals ? d.totals.mailboxes : null, size_gb: d.totals ? gb(d.totals.size_mb) : null }));
    out.db_trend = {}; for (const d of days) for (const [k, v] of Object.entries(d.db || {})) (out.db_trend[k] = out.db_trend[k] || []).push({ day: d.day, size_gb: gb(v.mailbox_mb), file_gb: gb(v.file_mb) });
    if (has('permissions')) { const P0 = arr(parts.get('permissions').data), H = holdersOf(P0); out.permissions = { mailboxes_read: P0.length, mailboxes_with_delegates: P0.filter((p) => p.full_access.length || p.send_as.length || p.send_on_behalf.length).length, full_access: P0.reduce((a, p) => a + p.full_access.length, 0), send_as: P0.reduce((a, p) => a + p.send_as.length, 0), send_on_behalf: P0.reduce((a, p) => a + p.send_on_behalf.length, 0), holders: H.length, holders_over_10: H.filter((h) => h.mailboxes > 10).length }; } else out.permissions = null;
    if (has('groups')) { const E = expandGroups(arr(parts.get('groups').data), I.set); out.groups = { total: E.length, dynamic: arr(parts.get('groups').dynamic).length, empty: E.filter((g) => !g.direct).length, with_external: E.filter((g) => g.external.length).length, nested: E.filter((g) => g.nested.length).length, accepts_external: E.filter((g) => g.accepts_external).length, hidden: E.filter((g) => g.hidden).length, truncated: E.filter((g) => g.truncated).length, size_bands: [['empty', 0, 1], ['1-10', 1, 11], ['11-50', 11, 51], ['51-200', 51, 201], ['> 200', 201, Infinity]].map(([label, lo, hi]) => ({ label, n: E.filter((g) => g.members >= lo && g.members < hi).length })) }; } else out.groups = null;
    if (has('public_folders')) { const F = parts.get('public_folders'); out.public_folders = { present: !!F.present, total: F.total || arr(F.data).length, mail_enabled: arr(F.data).filter((f) => f.mail_enabled).length, size_gb: gb(arr(F.data).reduce((a, f) => a + (f.size_mb || 0), 0)) }; } else out.public_folders = null;
    if (has('mobile')) {
      const D = arr(parts.get('mobile').data).map((d) => Object.assign({}, d, deviceFlags(d, st, t))), cnt = (k) => { const o = {}; for (const d of D) { const v = d[k] || 'unknown'; o[v] = (o[v] || 0) + 1; } return Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([label, n]) => ({ label, n })); };
      out.mobile = { devices: D.length, stale: D.filter((d) => d.stale).length, unapproved: (st.approved_models || []).length ? D.filter((d) => d.unapproved).length : null, blocked: D.filter((d) => /blocked/i.test(d.access)).length, quarantined: D.filter((d) => /quarantined/i.test(d.access)).length, by_os: cnt('os'), by_model: cnt('model'), by_access: cnt('access'), stale_days: st.stale_device_days };
    } else out.mobile = null;
    const on = parts.get('online');
    out.online = on && Array.isArray(on.data) ? { refreshed: on.refreshed || null, concealed: !!on.concealed, mailboxes: on.data.length, size_gb: gb(on.data.reduce((a, x) => a + (x.size_mb || 0), 0)), near_quota: on.data.filter((x) => x.used_pct != null && x.used_pct >= st.near_quota_pct).length,
      inactive_30d: on.data.filter((x) => !x.last_activity || t - Date.parse(x.last_activity) > 30 * DAY).length, sent: on.data.reduce((a, x) => a + (x.sent || 0), 0), received: on.data.reduce((a, x) => a + (x.received || 0), 0), read: on.data.reduce((a, x) => a + (x.read || 0), 0) } : null;
    return out;
  }

  /* named reports (administrator) */
  const match = (q, ...xs) => !q || xs.some((x) => String(x || '').toLowerCase().includes(q));
  function mailboxReport(o) {
    const st = settings(), t = now(), today = riyadhDay(t), I = internalDomains(st, inv()), q = (o.q || '').toLowerCase();
    let rows = mailboxesJoined().filter((x) => match(q, x.address, x.name) && (!o.type || x.type === o.type) && (!o.database || x.database === o.database));
    const G = growthOf(rows, daily.all(() => true), today, o.days || 30);
    rows = rows.map((x) => Object.assign({}, x, { growth_mb: G.by.has(x.address) ? G.by.get(x.address).mb : null, growth_pct: G.by.has(x.address) ? G.by.get(x.address).pct : null,
      inactive_days: x.last_logon ? Math.floor((t - Date.parse(x.last_logon)) / DAY) : null, forwarding_outside: !!(x.forwarding && !isInternal(domainOf(x.forwarding), I.set)) }));
    const v = o.view;
    if (v === 'largest') rows = rows.filter((x) => x.size_mb != null).sort((a, b) => b.size_mb - a.size_mb);
    else if (v === 'growing') rows = rows.filter((x) => x.growth_mb != null).sort((a, b) => b.growth_mb - a.growth_mb);
    else if (v === 'quota') rows = rows.filter((x) => x.used_pct != null && x.used_pct >= st.near_quota_pct).sort((a, b) => b.used_pct - a.used_pct);
    else if (v === 'inactive') rows = rows.filter((x) => inactiveOf(x, o.days || st.inactive_days, t)).sort((a, b) => (b.inactive_days == null ? 1e9 : b.inactive_days) - (a.inactive_days == null ? 1e9 : a.inactive_days));
    else if (v === 'hidden') rows = rows.filter((x) => x.hidden);
    else if (v === 'forwarding') rows = rows.filter((x) => x.forwarding).sort((a, b) => Number(b.forwarding_outside) - Number(a.forwarding_outside));
    else if (v === 'features') rows = rows.filter((x) => x.features && (o.feature ? x.features[o.feature] === true : (x.features.pop || x.features.imap)));
    else rows = rows.sort((a, b) => a.address.localeCompare(b.address));
    return { view: v, total: rows.length, items: rows.slice(0, o.limit), growth: { since: G.ref, days: G.days }, thresholds: { near_quota_pct: st.near_quota_pct, inactive_days: o.days || st.inactive_days },
      databases: [...new Set(mailboxesJoined().map((x) => x.database))].sort(), types: [...new Set(mailboxesJoined().map((x) => x.type))].sort(), part: partInfo('mailboxes'), cas: partInfo('cas') };
  }
  function permissionReport(o) {
    const P0 = arr((parts.get('permissions') || {}).data), q = (o.q || '').toLowerCase(), r = o.right;
    const has = (p) => (!r ? p.full_access.length || p.send_as.length || p.send_on_behalf.length : p[r].length);
    if (o.view === 'holders') { const H = holdersOf(P0).filter((h) => (!r || h[r]) && match(q, h.holder, ...h.grants.map((g) => g.mailbox))); return { view: 'holders', total: H.length, items: H.slice(0, o.limit), part: partInfo('permissions') }; }
    const rows = P0.filter((p) => has(p) && match(q, p.mailbox, p.name, ...p.full_access, ...p.send_as, ...p.send_on_behalf)).sort((a, b) => (b.full_access.length + b.send_as.length + b.send_on_behalf.length) - (a.full_access.length + a.send_as.length + a.send_on_behalf.length));
    return { view: 'mailbox', total: rows.length, items: rows.slice(0, o.limit), part: partInfo('permissions') };
  }
  function groupReport(o) {
    const g = parts.get('groups'), I = internalDomains(settings(), inv()), q = (o.q || '').toLowerCase();
    if (o.view === 'dynamic') { const D = arr(g && g.dynamic).filter((x) => match(q, x.address, x.name)); return { view: 'dynamic', total: D.length, items: D.slice(0, o.limit), part: partInfo('groups') }; }
    let E = expandGroups(arr(g && g.data), I.set).filter((x) => match(q, x.address, x.name, ...x.people.map((p) => p.address)));
    if (o.view === 'external') E = E.filter((x) => x.external.length).sort((a, b) => b.external.length - a.external.length);
    else if (o.view === 'empty') E = E.filter((x) => !x.direct);
    else if (o.view === 'nested') E = E.filter((x) => x.nested.length).sort((a, b) => b.nested.length - a.nested.length);
    else E = E.sort((a, b) => b.members - a.members);
    return { view: o.view, total: E.length, items: E.slice(0, o.limit).map((x) => Object.assign({}, x, { people: x.people.slice(0, 300) })), domains_derived: I.derived, part: partInfo('groups') };
  }
  function folderReport(o) {
    const F = parts.get('public_folders'), q = (o.q || '').toLowerCase(), rows = arr(F && F.data).filter((f) => match(q, f.path)).sort((a, b) => (b.size_mb || 0) - (a.size_mb || 0));
    return { present: F ? !!F.present : null, total: rows.length, items: rows.slice(0, o.limit), part: partInfo('public_folders') };
  }
  function deviceReport(o) {
    const st = settings(), t = now(), q = (o.q || '').toLowerCase();
    let D = arr((parts.get('mobile') || {}).data).map((d) => Object.assign({}, d, deviceFlags(d, st, t), { days_since_sync: d.last_sync ? Math.floor((t - Date.parse(d.last_sync)) / DAY) : null })).filter((d) => match(q, d.owner, d.model, d.os, d.type, d.device_id));
    if (o.view === 'stale') D = D.filter((d) => d.stale); else if (o.view === 'unapproved') D = D.filter((d) => d.unapproved); else if (o.view === 'blocked') D = D.filter((d) => d.blocked);
    D.sort((a, b) => (b.days_since_sync == null ? 1e9 : b.days_since_sync) - (a.days_since_sync == null ? 1e9 : a.days_since_sync));
    return { view: o.view, total: D.length, items: D.slice(0, o.limit), approved_models: st.approved_models, stale_days: st.stale_device_days, part: partInfo('mobile') };
  }
  function onlineReport(o, named) {
    const on = parts.get('online'), st = settings(), t = now(), sum = summary().online;
    if (!on || !Array.isArray(on.data)) return { state: 'not_connected', part: partInfo('online'), note: onlineNote(on), summary: null };
    let rows = named ? on.data.filter((x) => match((o.q || '').toLowerCase(), x.upn, x.name)) : [];
    if (o.view === 'inactive') rows = rows.filter((x) => !x.last_activity || t - Date.parse(x.last_activity) > 30 * DAY);
    else if (o.view === 'quota') rows = rows.filter((x) => x.used_pct != null && x.used_pct >= st.near_quota_pct);
    rows.sort((a, b) => (b.size_mb || 0) - (a.size_mb || 0));
    return { state: 'ok', named, summary: sum, total: named ? rows.length : null, items: named ? rows.slice(0, o.limit) : null, part: partInfo('online'),
      note: (sum.concealed ? 'Microsoft 365 conceals user names in usage reports: a Global Administrator turns this off in the Microsoft 365 admin center (Settings, Org settings, Reports) to see who is who. ' : '') + (named ? '' : 'Names are shown to administrators only (PDPL).') };
  }
  function onlineNote(on) {
    const gs = graph && typeof graph.status === 'function' ? graph.status() : null;
    if (!graph) return 'The Microsoft 365 collector is not loaded on this SIEM.';
    if (gs && !gs.ready) return 'Microsoft 365 is not connected (' + arr(gs.missing).join('; ') + '): add the app registration under Connect & Onboard, Microsoft 365, and grant it Reports.Read.All (application, admin consent).';
    if (on && on.error) return 'Exchange Online usage could not be read: ' + on.error;
    return 'Exchange Online usage has not been read yet - it is read with the daily inventory, or with Collect now.';
  }

  /* OWA / ActiveSync from the IIS logs */
  async function clients(o, named) {
    if (!ch) return { configured: false, note: 'The SIEM event store is not available.' };
    const p = { t_from: { type: 'Int64', value: o.from }, t_to: { type: 'Int64', value: o.to }, b: { type: 'Int64', value: o.bucket } };
    const T = `${db}.events`, W = "ts >= fromUnixTimestamp64Milli({t_from:Int64}) AND ts < fromUnixTimestamp64Milli({t_to:Int64}) AND src_type = 'iis'";
    const OWA = "has(tags, 'exchange-owa')", EAS = "has(tags, 'exchange-microsoft-server-activesync')", X = `${W} AND (${OWA} OR ${EAS})`;
    const SIGNIN = `${OWA} AND http_method = 'POST' AND lower(url) LIKE '/owa/auth.owa%'`, FAIL = "http_status = 401 AND user != ''", DEV = "fields['eas_device_id']";
    const q = (tag, sql) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true });
    const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
    const [tot, series, byVdir, users, failed, devices] = await Promise.all([
      q('cl_tot', `SELECT countIf(${OWA}) AS owa, countIf(${EAS}) AS eas, uniqExactIf(user, ${OWA} AND user != '' AND http_status < 400) AS owa_users, countIf(${SIGNIN}) AS signins, uniqExactIf(user, ${EAS} AND user != '' AND http_status < 400) AS eas_users, uniqExactIf(${DEV}, ${EAS} AND ${DEV} != '') AS devices, countIf(${FAIL}) AS failed, uniqExactIf(user, ${FAIL}) AS failed_users, uniqExactIf(src_ip, ${FAIL}) AS failed_ips FROM ${T} WHERE ${X}`),
      q('cl_series', `SELECT intDiv(toUnixTimestamp64Milli(ts) - {t_from:Int64}, {b:Int64}) AS k, uniqExactIf(user, ${OWA} AND user != '' AND http_status < 400) AS ou, uniqExactIf(${DEV}, ${EAS} AND ${DEV} != '') AS ed, countIf(${FAIL}) AS fl FROM ${T} WHERE ${X} GROUP BY k ORDER BY k`),
      q('cl_vdir', `SELECT if(${OWA}, 'OWA', 'ActiveSync') AS v, countIf(${FAIL}) AS fl, countIf(http_status >= 500) AS err, count() AS n FROM ${T} WHERE ${X} GROUP BY v`),
      named ? q('cl_users', `SELECT user AS u, any(domain) AS d, countIf(${SIGNIN}) AS signins, countIf(${OWA}) AS owa, countIf(${EAS} AND fields['eas_cmd'] = 'Sync') AS syncs, countIf(${FAIL}) AS failed, uniqExactIf(${DEV}, ${DEV} != '') AS devices, uniqExact(src_ip) AS ips, max(ts) AS last FROM ${T} WHERE ${X} AND user != '' GROUP BY u ORDER BY (owa + syncs) DESC LIMIT 300`) : [],
      named ? q('cl_failed', `SELECT user AS u, src_ip AS ip, if(${OWA}, 'OWA', 'ActiveSync') AS v, count() AS n, max(ts) AS last FROM ${T} WHERE ${X} AND ${FAIL} GROUP BY u, ip, v ORDER BY n DESC LIMIT 100`) : [],
      named ? q('cl_devices', `SELECT ${DEV} AS id, any(fields['eas_device_type']) AS type, any(user) AS u, any(user_agent) AS ua, count() AS n, countIf(http_status >= 400) AS err, max(ts) AS last FROM ${T} WHERE ${X} AND ${EAS} AND ${DEV} != '' GROUP BY id ORDER BY last DESC LIMIT 500`) : [],
    ]);
    const t0 = tot[0] || {}, configured = num(t0.owa) + num(t0.eas) > 0;
    const byK = new Map(series.map((r) => [num(r.k), r])), S = [];
    for (let i = 0; i < o.buckets; i++) { const r = byK.get(i) || {}; S.push({ t: o.from + i * o.bucket, owa_users: num(r.ou), eas_devices: num(r.ed), failed: num(r.fl) }); }
    return { configured, range_days: o.days, bucket_ms: o.bucket, named,
      totals: configured ? { owa_requests: num(t0.owa), eas_requests: num(t0.eas), owa_users: num(t0.owa_users), owa_signins: num(t0.signins), eas_users: num(t0.eas_users), eas_devices: num(t0.devices), failed: num(t0.failed), failed_users: num(t0.failed_users), failed_ips: num(t0.failed_ips) } : null,
      series: S, by_service: byVdir.map((r) => ({ service: String(r.v), requests: num(r.n), failed: num(r.fl), errors: num(r.err) })),
      users: named ? users.map((r) => ({ user: String(r.u), domain: String(r.d || ''), owa_signins: num(r.signins), owa_requests: num(r.owa), eas_syncs: num(r.syncs), failed: num(r.failed), devices: num(r.devices), ips: num(r.ips), last: String(r.last || '') })) : null,
      failed: named ? failed.map((r) => ({ user: String(r.u), ip: String(r.ip || ''), service: String(r.v), n: num(r.n), last: String(r.last || '') })) : null,
      devices_seen: named ? devices.map((r) => ({ device_id: String(r.id), type: String(r.type || ''), user: String(r.u || ''), user_agent: s(r.ua, 160), requests: num(r.n), errors: num(r.err), last: String(r.last || '') })) : null,
      note: !configured ? 'No OWA or ActiveSync request from the Exchange IIS logs has reached the SIEM for this period: forward the IIS logs of the Exchange servers (agents/exchange, u_ex*.log) to see logons and devices.'
        : 'Logons from the Exchange IIS logs: OWA sign-ins are form posts to /owa/auth.owa; a failed logon is an HTTP 401 that names the account (the first, anonymous leg of NTLM is not counted).' + (named ? '' : ' Names are shown to administrators only (PDPL).') };
  }

  /* the Reporting Center's digest: counts + the top rows of each report (administrator) */
  async function digest() {
    const S0 = summary(), st = settings(), lim = 15;
    const take = (r, f) => r.items.slice(0, lim).map(f);
    let traffic = null, cl = null;
    try { if (ch) traffic = await mailstats.traffic(ch, db, mailstats.trafficOptions({ range: '7', domains: S0.domains.slice(0, 20).join(','), limit: '10' }, now()), { named: true }); } catch (e) { traffic = { error: s(e.message, 200) }; }
    try { cl = await clients(clientOptions({ range: '7' }, now()), false); } catch (e) { cl = { error: s(e.message, 200) }; }
    return { summary: S0,
      largest: take(mailboxReport({ view: 'largest', limit: lim }), (x) => ({ address: x.address, name: x.name, type: x.type, database: x.database, size_gb: gb(x.size_mb), items: x.items, used_pct: x.used_pct, last_logon: x.last_logon })),
      growing: take(mailboxReport({ view: 'growing', days: 30, limit: lim }), (x) => ({ address: x.address, name: x.name, size_gb: gb(x.size_mb), growth_mb: x.growth_mb, growth_pct: x.growth_pct })),
      near_quota: take(mailboxReport({ view: 'quota', limit: lim }), (x) => ({ address: x.address, name: x.name, size_gb: gb(x.size_mb), quota_gb: gb(x.quota_mb), used_pct: x.used_pct })),
      forwarding_outside: mailboxReport({ view: 'forwarding', limit: 200 }).items.filter((x) => x.forwarding_outside).slice(0, lim).map((x) => ({ address: x.address, name: x.name, forwarding: x.forwarding, deliver_and_forward: x.deliver_and_forward })),
      holders: take(permissionReport({ view: 'holders', limit: lim }), (h) => ({ holder: h.holder, mailboxes: h.mailboxes, full_access: h.full_access, send_as: h.send_as, send_on_behalf: h.send_on_behalf })),
      external_groups: take(groupReport({ view: 'external', limit: lim }), (g) => ({ address: g.address, name: g.name, members: g.members, external: g.external.length })),
      empty_groups: take(groupReport({ view: 'empty', limit: lim }), (g) => ({ address: g.address, name: g.name })),
      stale_devices: take(deviceReport({ view: 'stale', limit: lim }), (d) => ({ owner: d.owner, model: d.model, os: d.os, last_sync: d.last_sync, days: d.days_since_sync })),
      traffic: traffic && !traffic.error ? { exchange: traffic.exchange, status: traffic.status, split: traffic.split, average_kb: traffic.average_kb, top_senders: (traffic.top_senders || []).slice(0, 10), top_recipients: (traffic.top_recipients || []).slice(0, 10) } : traffic,
      clients: cl && !cl.error ? { configured: cl.configured, totals: cl.totals } : cl, thresholds: { near_quota_pct: st.near_quota_pct, inactive_days: st.inactive_days, stale_device_days: st.stale_device_days } };
  }

  function saveSettings(input, who) {
    const b = body(input).bool('enabled').int('collect_hour', { min: 0, max: 23 }).int('inactive_days', { min: 7, max: 730 }).int('stale_device_days', { min: 7, max: 365 })
      .int('near_quota_pct', { min: 50, max: 100 }).int('keep_days', { min: 30, max: 400 }).list('approved_models', { max: 100, item: 'str', itemMax: 80, unique: true })
      .list('internal_domains', { max: 50, item: 'str', itemMax: 200, unique: true })
      .rule((o) => { const bad = (o.internal_domains || []).find((d) => !DOMAIN_RE.test(d.toLowerCase().replace(/\.$/, ''))); return bad ? 'internal_domains: "' + s(bad, 60) + '" is not a domain name' : ''; })
      .rule((o) => (Object.keys(o).length ? '' : 'nothing to change - send at least one setting')).done();
    if (b.internal_domains) b.internal_domains = [...new Set(b.internal_domains.map((d) => d.toLowerCase().replace(/\.$/, '')))];
    if (b.approved_models) b.approved_models = b.approved_models.filter(Boolean);
    const prev = (meta.get('settings') || {}).values || {};
    meta.put({ id: 'settings', values: Object.assign({}, prev, b), by: who || '', at: now() });
    return { changed: Object.keys(b), settings: settings() };
  }

  return { collect, start, stop, tick: daily_tick, status, summary, mailboxReport, permissionReport, groupReport, folderReport, deviceReport, onlineReport, clients, digest, saveSettings, settings, idle: () => running || Promise.resolve() };
}

function clientOptions(q, now) {
  const b = body(q || {}).oneOf('range', ['1', '7', '30'], { def: '7' }).done(), days = Number(b.range), bucket = days === 1 ? 3600000 : DAY;
  return { days, from: now - days * DAY, to: now, bucket, buckets: days === 1 ? 24 : days };
}

function register(api, deps) {
  const P = prefixOf(deps), now = deps.now || Date.now;
  const S = deps.sysadminInstance || deps.sysadmin || null;   // set by engine/sysadmin/routes.js (registered before this module)
  const X = deps.exchangeReports || createExchangeReports({ state: deps.state, sysadmin: S, graph: deps.m365Graph, ch: deps.ch, config: deps.config, log: deps.log, now });
  deps.exchangeReportsInstance = X;
  if (!deps.exchangeReports && !(deps.config && deps.config.exchange_reports && deps.config.exchange_reports.enabled === false)) X.start();
  const Q = (ctx) => ctx.query || {};
  const LIMIT = { min: 1, max: 5000, def: 500 };
  const named = (ctx, view, target, n) => audit(ctx, 'exchange.reports.view', target, { view, rows: n });

  api.route('GET', `${P}/exchange/reports/status`, wrap(deps, null, () => X.status()));
  api.route('GET', `${P}/exchange/reports/summary`, wrap(deps, null, () => X.summary()));
  api.route('GET', `${P}/exchange/reports/mailboxes`, wrap(deps, 'admin', (ctx) => {
    const o = body(Q(ctx)).oneOf('view', ['all', 'largest', 'growing', 'quota', 'inactive', 'hidden', 'forwarding', 'features'], { def: 'largest' }).str('q', { max: 120 }).str('type', { max: 60, re: /^[A-Za-z]{1,60}$/ })
      .str('database', { max: 100, re: /^[A-Za-z0-9 _.()-]{1,100}$/ }).int('days', { min: 1, max: 730 }).oneOf('feature', ['owa', 'eas', 'pop', 'imap', 'mapi', 'ews']).int('limit', LIMIT).done();
    const r = X.mailboxReport(o); named(ctx, 'mailboxes.' + o.view, 'mailboxes', r.items.length); return r;
  }));
  api.route('GET', `${P}/exchange/reports/permissions`, wrap(deps, 'admin', (ctx) => {
    const o = body(Q(ctx)).oneOf('view', ['mailbox', 'holders'], { def: 'mailbox' }).oneOf('right', ['full_access', 'send_as', 'send_on_behalf']).str('q', { max: 120 }).int('limit', LIMIT).done();
    const r = X.permissionReport(o); named(ctx, 'permissions.' + o.view, 'permissions', r.items.length); return r;
  }));
  api.route('GET', `${P}/exchange/reports/groups`, wrap(deps, 'admin', (ctx) => {
    const o = body(Q(ctx)).oneOf('view', ['all', 'external', 'empty', 'nested', 'dynamic'], { def: 'all' }).str('q', { max: 120 }).int('limit', LIMIT).done();
    const r = X.groupReport(o); named(ctx, 'groups.' + o.view, 'groups', r.items.length); return r;
  }));
  api.route('GET', `${P}/exchange/reports/public-folders`, wrap(deps, 'admin', (ctx) => {
    const o = body(Q(ctx)).str('q', { max: 120 }).int('limit', LIMIT).done();
    const r = X.folderReport(o); named(ctx, 'public-folders', 'public-folders', r.items.length); return r;
  }));
  api.route('GET', `${P}/exchange/reports/devices`, wrap(deps, 'admin', (ctx) => {
    const o = body(Q(ctx)).oneOf('view', ['all', 'stale', 'unapproved', 'blocked'], { def: 'all' }).str('q', { max: 120 }).int('limit', LIMIT).done();
    const r = X.deviceReport(o); named(ctx, 'devices.' + o.view, 'devices', r.items.length); return r;
  }));
  api.route('GET', `${P}/exchange/reports/clients`, wrap(deps, null, async (ctx) => {
    const o = clientOptions(Q(ctx), now()), isAdmin = ctx.role === 'admin';
    const r = await X.clients(o, isAdmin); if (isAdmin) named(ctx, 'clients', 'owa-activesync', (r.users || []).length); return r;
  }));
  api.route('GET', `${P}/exchange/reports/online`, wrap(deps, null, (ctx) => {
    const o = body(Q(ctx)).oneOf('view', ['all', 'inactive', 'quota'], { def: 'all' }).str('q', { max: 120 }).int('limit', LIMIT).done(), isAdmin = ctx.role === 'admin';
    const r = X.onlineReport(o, isAdmin); if (isAdmin && r.items) named(ctx, 'online.' + o.view, 'exchange-online', r.items.length); return r;
  }));
  api.route('GET', `${P}/exchange/reports/digest`, wrap(deps, 'admin', async (ctx) => { const r = await X.digest(); named(ctx, 'digest', 'reporting-center', r.largest.length); return r; }));
  api.route('PUT', `${P}/exchange/reports/settings`, wrap(deps, 'admin', (ctx) => {
    const r = X.saveSettings(ctx.body, ctx.user); audit(ctx, 'exchange.reports.settings', 'settings', { changed: r.changed }); return r;
  }));
  api.route('POST', `${P}/exchange/reports/collect`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx.body).list('parts', { max: PARTS.length, item: PARTS, unique: true }).done();
    if (!X.status().connected && !(b.parts && b.parts.length === 1 && b.parts[0] === 'online')) throw new HttpError(409, 'no Exchange server with a login - an administrator adds one under AI Exchange Server Administrator (Servers, Logins)');
    const job = guard('exchange.reports.collect', () => X.collect(ctx.user || 'operator', b.parts));
    job();   // runs in the background: the page polls the status
    audit(ctx, 'exchange.reports.collect', 'inventory', { parts: b.parts || PARTS });
    return { started: true, parts: b.parts || PARTS };
  }));
  return X;
}

module.exports = { register, createExchangeReports, normMailbox, normCas, normPerm, normGroup, normDevice, expandGroups, holdersOf, growthOf, refSnapshot, deviceFlags, parseCsv, onlineFrom, internalDomains, clientOptions, PARTS };
