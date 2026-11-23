// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SharePoint & OneDrive ACTIVITY over the Office 365 unified audit log the SIEM already collects (collect/m365.js -> parse/m365.js:
 * src_type m365, host = the workload, event_code = the Operation, the record's fields kept). It answers the four questions the old
 * portal page asked of file activity - now from the SIEM, with each user measured against their own history:
 *   sharing      every sharing operation (SharingSet, SharingInvitationCreated, AnonymousLinkCreated, CompanyLinkCreated,
 *                SecureLinkCreated, AddedToSecureLink...) with its scope: anonymous (anyone with the link), external (a guest or an
 *                address outside the tenant's own domains), organisation, or specific people inside
 *   external     the anonymous and external ones, and anonymous links USED (AnonymousLinkUsed) - data that left the tenant
 *   downloads    MASS DOWNLOAD: a user's downloads (FileDownloaded, FileSyncDownloadedFull) in one hour against the most they
 *                downloaded in any hour of the 14 days before - 50+ files and 5x their own usual (or 50+ with no history) - the
 *                classic data-theft precursor
 *   afterhours   file activity outside Riyadh working hours (Sun-Thu 07:00-18:00): a user with 20+ such events whose after-hours
 *                share is 3x their own share in the 14 days before (or new) - not every late worker, only a change in behaviour
 * The tenant's own domains are the domains of the people who act in it (or config m365.internal_domains). Personal data (PDPL):
 * analysts and above, every read audited. Indicators, not proof of wrongdoing.
 *   GET {P}/m365/files/activity   ?days=1-30 (default 7)   analyst
 */
const { wrap, audit, prefixOf, HttpError } = require('../soc/routeutil');
const H = 3600000, DAY = 24 * H;
const SHARE_OPS = /^(sharingset|sharinginvitationcreated|anonymouslinkcreated|anonymouslinkupdated|companylinkcreated|securelinkcreated|addedtosecurelink|addedtogroup|sharingpolicychanged)$/i;
const DL_OPS = /^(filedownloaded|filesyncdownloadedfull)$/i;
const FILE_OPS = /^file|^folder|download|upload|sharing|link/i;
const lc = (s) => String(s == null ? '' : s).toLowerCase();
const fld = (e, ...k) => { const f = e.fields || {}; for (const x of k) if (f[x] != null && f[x] !== '') return String(f[x]); return ''; };
const fileOf = (e) => fld(e, 'SourceFileName', 'ObjectId').split(/[\\/]/).pop().slice(0, 200) || '(no name)';
const siteOf = (e) => fld(e, 'SiteUrl', 'SourceRelativeUrl').slice(0, 300);
const offHours = (ms) => { const d = new Date(ms + 3 * H), wd = d.getUTCDay(), h = d.getUTCHours(); return wd === 5 || wd === 6 || h < 7 || h >= 18; };
const domainOf = (u) => { const m = /@([^@\s]+)$/.exec(lc(u)); return m ? m[1] : ''; };

function analyse(events, now, o = {}) {
  const days = o.days || 7, from = now - days * DAY, base0 = from - 14 * DAY;
  const ev = events.filter((e) => /sharepoint|onedrive/.test(lc(e.host)) && e.ts >= base0 && e.ts <= now);
  const internal = new Set((o.internal || []).map(lc)); if (!internal.size) for (const e of ev) { const d = domainOf(e.user); if (d) internal.add(d); }
  const win = ev.filter((e) => e.ts >= from), base = ev.filter((e) => e.ts < from);
  // sharing
  const sharing = [];
  for (const e of win) {
    const op = String(e.event_code || ''); if (!SHARE_OPS.test(op)) continue;
    const target = lc(fld(e, 'TargetUserOrGroupName')), ttype = lc(fld(e, 'TargetUserOrGroupType'));
    const scope = /anonymous/i.test(op) ? 'anonymous' : /companylink/i.test(op) ? 'organisation' : (ttype === 'guest' || /#ext#/.test(target) || (domainOf(target) && !internal.has(domainOf(target)))) ? 'external' : 'internal';
    sharing.push({ at: new Date(e.ts).toISOString(), user: e.user, operation: op, scope, target: target || null, file: fileOf(e), site: siteOf(e), workload: lc(e.host) });
  }
  const used = new Map(); for (const e of win) if (/^anonymouslinkused$/i.test(e.event_code || '')) { const k = fileOf(e); used.set(k, (used.get(k) || 0) + 1); }
  // mass downloads: per user, per hour, against their own 14 days
  const hourly = (L) => { const m = new Map(); for (const e of L) { if (!DL_OPS.test(e.event_code || '')) continue; const k = lc(e.user) + '|' + Math.floor(e.ts / H); const x = m.get(k) || m.set(k, { user: lc(e.user), hour: Math.floor(e.ts / H) * H, n: 0, files: new Set(), sites: new Set() }).get(k); x.n++; x.files.add(fileOf(e)); x.sites.add(siteOf(e)); } return m; };
  const bmax = new Map(); for (const x of hourly(base).values()) bmax.set(x.user, Math.max(bmax.get(x.user) || 0, x.n));
  const downloads = [];
  for (const x of hourly(win).values()) {
    const usual = bmax.get(x.user) || 0;
    if (x.n >= 50 && x.n >= 5 * Math.max(1, usual)) downloads.push({ user: x.user, hour: new Date(x.hour).toISOString(), files: x.n, distinct: x.files.size, sites: [...x.sites].filter(Boolean).slice(0, 4), usual_max: usual,
      why: x.n + ' downloads in one hour' + (usual ? ' against at most ' + usual + ' in any hour of the 14 days before' : ' with no download history in 14 days') });
  }
  downloads.sort((a, b) => b.files - a.files);
  // after hours: change in the user's own after-hours share
  const share = (L) => { const m = new Map(); for (const e of L) { if (!FILE_OPS.test(e.event_code || '')) continue; const u = lc(e.user); if (!u) continue; const x = m.get(u) || m.set(u, { n: 0, off: 0 }).get(u); x.n++; if (offHours(e.ts)) x.off++; } return m; };
  const sw = share(win), sb = share(base), after = [];
  for (const [u, x] of sw) {
    if (x.off < 20) continue;
    const b = sb.get(u), now_s = x.off / x.n, was = b && b.n >= 20 ? b.off / b.n : null;
    if (was == null || now_s >= 3 * Math.max(0.02, was)) after.push({ user: u, after_hours: x.off, total: x.n, share_pct: Math.round(100 * now_s), usual_pct: was == null ? null : Math.round(100 * was),
      why: x.off + ' of ' + x.n + ' file actions outside Riyadh working hours (' + Math.round(100 * now_s) + '%)' + (was == null ? ' - no history to compare' : ' against ' + Math.round(100 * was) + '% in the 14 days before') });
  }
  after.sort((a, b) => b.after_hours - a.after_hours);
  const external = sharing.filter((x) => x.scope === 'anonymous' || x.scope === 'external');
  const byScope = { anonymous: 0, external: 0, organisation: 0, internal: 0 }; for (const s of sharing) byScope[s.scope]++;
  const series = Array.from({ length: Math.min(days, 30) }, (_, i) => { const d0 = from + i * DAY; return { day: new Date(d0 + 3 * H).toISOString().slice(0, 10), events: 0, downloads: 0, shares: 0 }; });
  for (const e of win) { const k = Math.floor((e.ts - from) / DAY); if (k >= 0 && k < series.length) { series[k].events++; if (DL_OPS.test(e.event_code || '')) series[k].downloads++; if (SHARE_OPS.test(e.event_code || '')) series[k].shares++; } }
  return { days, from: new Date(from).toISOString(), events: win.length, baseline_events: base.length, internal_domains: [...internal].slice(0, 10),
    kpis: { shares: sharing.length, external: external.length, anonymous_used: [...used.values()].reduce((a, b) => a + b, 0), mass_downloads: downloads.length, after_hours_users: after.length, active_users: new Set(win.map((e) => lc(e.user)).filter(Boolean)).size },
    by_scope: byScope, sharing: sharing.sort((a, b) => b.at.localeCompare(a.at)).slice(0, 200), external: external.slice(0, 100), anonymous_used: [...used.entries()].map(([file, n]) => ({ file, uses: n })).sort((a, b) => b.uses - a.uses).slice(0, 30),
    downloads: downloads.slice(0, 30), after_hours: after.slice(0, 30), series,
    note: 'From the Office 365 unified audit log the SIEM collects (SharePoint and OneDrive workloads). Each user is compared with their own 14 days before the window. Behavioural indicators for a person to review, not proof of wrongdoing (PDPL).' };
}

function register(api, deps) {
  const P = prefixOf(deps);
  api.route('GET', `${P}/m365/files/activity`, wrap(deps, 'analyst', async (ctx) => {
    const v = (ctx.query || {}).days, days = v === undefined || v === '' ? 7 : Number(v);
    if (!Number.isInteger(days) || days < 1 || days > 30) throw new HttpError(400, 'days must be a whole number 1-30');
    if (!deps.search || typeof deps.search.fetchEvents !== 'function') throw new HttpError(503, 'the event store is not available');
    const now = (deps.now || Date.now)();
    const evs = await deps.search.fetchEvents({ q: 'src_type:m365 AND host:(sharepoint OR onedrive)', from: now - (days + 14) * DAY, to: now, limit: 200000 });
    const r = analyse(evs, now, { days, internal: ((deps.config || {}).m365 || {}).internal_domains });
    r.truncated = evs.length >= 200000;
    audit(ctx, 'm365.files.activity.read', 'all', { days, events: r.events, shares: r.kpis.shares, mass_downloads: r.kpis.mass_downloads });
    return ctx.ok(r);
  }));
}

module.exports = { register, analyse };
