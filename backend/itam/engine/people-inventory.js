// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { param, body } = require('./check');
const { guardOf } = require('./errors');
const { normSoftwareEntry, productKey } = require('./model/software');
const { RISKY, FREEWARE, CAT } = require('./software-studio');
/*
 * User Inventory ({P} = /api/itam; IT Assets -> User Inventory): each person, the devices they hold or sign in to, and the
 * applications installed on those devices - joined from what the platform already reads, READ ONLY:
 *   people       the last Active Directory read (Directory users: name, user name, UPN, department, title, enabled, last sign-in)
 *   devices      the asset register: custodian on any asset, owner on end-user devices (workstation, laptop, mobile, phone)
 *                ("owner" on a server is a service owner, not a user); Endpoint Central: the user signed in on each computer
 *   applications the installed software the agents and imports report on those devices, with the software policy
 *                (approved / blocked) and the remote-access / tunnelling list from Software & Licences
 * A name is linked to a directory account only on an exact match (user name, UPN, mail or display name, case-insensitive, the
 * DOMAIN\ prefix and @domain suffix removed) - never on a similar name: two people called Mohammed are two people.
 *   flags        named, each with its reason: disabled in AD but still holding devices (leaver), no sign-in for 90+ days but holding
 *                devices, named on devices but not in the directory, remote-access / tunnelling tools, blocked software,
 *                more than 3 end-user devices, and (learned per department) an application unusual for the department - on <= 10 %
 *                of its people where 5+ people report software. Indicators for review, not proof of anything.
 *   Microsoft 365  per user, read through the HR-onboarding Graph connection (GET only, every 12 h or on Read): licences, the
 *                Microsoft 365 apps used in the last 30 days (Outlook, Word, Excel, PowerPoint, OneNote, Teams) and on which
 *                platforms, and the last activity in Exchange, OneDrive, SharePoint and Teams (usage reports, Reports.Read.All).
 *                Joined on the UPN / mail. A tenant that conceals user names in reports is detected and said, never guessed.
 *                Flags: a disabled directory account that still has Microsoft 365 licences; licences with no activity in 30 days.
 *   GET  /people-inventory          operator  the list, the sources read, unassigned end-user devices, departments
 *   GET  /people-inventory/:key     operator  one person: devices (and how each is linked) and applications - audited (PDPL)
 *   POST /people-inventory/m365/read operator a person reads Microsoft 365 now (audited)
 * Names, departments, sign-ins and installed software of employees are personal data (PDPL): operators and administrators only.
 */
const DAY = 86400000, CLOSED = { retired: 1, disposed: 1 };
const END_USER = { workstation: 1, laptop: 1, mobile: 1, phone: 1 };
const NOT_PERSON = /\b(department|dept|team|division|section|unit|it|infrastructure|operations|helpdesk|service desk|shared|common|meeting|reception|training|kiosk|spare|stock|store|pool|n\/a|none|unknown|test|administrator|admin|localadmin|system|guest)\b/i;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const clip = (x, n = 200) => String(x == null ? '' : x).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
// "CORP-HQ\jdoe" -> "jdoe"; "jdoe@corp.com" -> "jdoe"; "Jane Doe (joiner HR-12)" -> "jane doe"
function norm(v) {
  let s = clip(v, 200).toLowerCase().replace(/\s*\((joiner|leaver)[^)]*\)\s*$/, '');
  if (s.includes('\\')) s = s.split('\\').pop();
  if (/^[^\s@]+@[^\s@]+$/.test(s)) s = s.split('@')[0];
  return s.replace(/\s+/g, ' ').trim();
}
const M365_APPS = ['outlook', 'word', 'excel', 'powerPoint', 'oneNote', 'teams'], M365_PLAT = ['windows', 'mac', 'mobile', 'web'];
const M365_SVC = [['exchange', 'exchangeLastActivityDate'], ['onedrive', 'oneDriveLastActivityDate'], ['sharepoint', 'sharePointLastActivityDate'], ['teams', 'teamsLastActivityDate']];
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const keyOf = (s) => 'p_' + crypto.createHash('sha256').update(s).digest('hex').slice(0, 16);
const catOf = (label) => (CAT.find(([, re]) => re.test(label)) || ['other'])[0];

function createPeopleInventory(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const col = (n) => { try { return store.collection(n).all(); } catch (e) { return []; /* a module that is not installed has no collection: nothing to read */ } };
  const m365C = () => store.collection('m365_user_apps');
  const LIC = () => opts.m365 || (app.addons && app.addons.onboarding && app.addons.onboarding.lic) || null;
  // read Microsoft 365 per user and keep the normalised result (no tokens, no message content: licences, app flags, dates)
  async function readM365(who, scheduled) {
    if (!scheduled && isService(who.user)) throw httpErr(403, 'a person reads Microsoft 365, not a service or AI identity');
    const L = LIC(); if (!L || !L.userApps) throw httpErr(424, 'HR onboarding (which holds the Microsoft 365 connection) is not installed - run the update');
    if (!L.connected()) throw httpErr(409, 'Microsoft 365 is not connected - an administrator sets the tenant, app and secret in HR Onboarding -> Microsoft 365');
    let r; try { r = await L.userApps(); } catch (e) { if (e.status) throw e; throw httpErr(424, 'Microsoft 365 could not be read: ' + clip(e.message, 200)); }
    const part = new Map((r.skus || []).map((k) => [String(k.sku_id).toLowerCase(), k.part]));
    const low = (x) => String(x || '').toLowerCase();
    const act = new Map((r.act || []).map((a) => [low(a.userPrincipalName), a])), use = new Map((r.apps || []).map((a) => [low(a.userPrincipalName), a]));
    const repUpns = [...(r.act || []), ...(r.apps || [])].map((a) => String(a.userPrincipalName || ''));
    const concealed = repUpns.length > 0 && !repUpns.some((u) => u.includes('@'));
    const users = (r.users || []).filter((u) => u.userPrincipalName).slice(0, 20000).map((u) => {
      const upn = low(u.userPrincipalName), a = act.get(upn), p = use.get(upn), d = p && Array.isArray(p.details) ? (p.details.find((x) => /30/.test(String(x.reportPeriod))) || p.details[0]) : null;
      const lic = a && Array.isArray(a.assignedProducts) && a.assignedProducts.length ? a.assignedProducts.map((x) => clip(x, 80)) : (u.assignedLicenses || []).map((l) => part.get(low(l.skuId)) || 'licence ' + clip(l.skuId, 40));
      return { upn, mail: low(u.mail), name: clip(u.displayName, 120), enabled: u.accountEnabled !== false, licences: lic.slice(0, 20),
        apps: d ? Object.fromEntries(M365_APPS.map((k) => [k, !!d[k]])) : null, platforms: d ? Object.fromEntries(M365_PLAT.map((k) => [k, !!d[k]])) : null,
        services: a ? Object.fromEntries(M365_SVC.map(([k, f]) => [k, a[f] || null])) : null, last_activity: (p && p.lastActivityDate) || (a && [a.exchangeLastActivityDate, a.oneDriveLastActivityDate, a.sharePointLastActivityDate, a.teamsLastActivityDate].filter(Boolean).sort().pop()) || null };
    });
    const rec = { id: 'last', at: new Date(now()).toISOString(), by: who.user, users, concealed, usage: !!(r.apps || r.act), errors: (r.errors || []).map((x) => clip(x, 240)) };
    m365C().put(rec);
    audit(who, scheduled ? 'people.m365.auto_read' : 'people.m365.read', 'm365', { users: users.length, licensed: users.filter((u) => u.licences.length).length, usage: rec.usage, concealed, errors: rec.errors.length });
    return { at: rec.at, users: users.length, concealed, errors: rec.errors };
  }
  const RUN = { timer: null, stopped: false };
  function start() {
    if (opts.noTimer || app.noTimers || RUN.timer) return;
    const job = guardOf(app, 'people-inventory.m365', async () => { const L = LIC(); if (L && L.connected && L.connected()) await readM365({ user: 'system:people-inventory', role: 'admin' }, true); });
    const loop = () => { RUN.timer = setTimeout(async () => { try { await job(); } finally { if (!RUN.stopped) loop(); } }, 12 * 3600000); if (RUN.timer.unref) RUN.timer.unref(); };
    loop();
  }
  function stop() { RUN.stopped = true; if (RUN.timer) clearTimeout(RUN.timer); RUN.timer = null; }
  function build() {
    const t = now();
    const dir = (() => { try { return store.collection('ad_directory').get('last'); } catch (e) { return null; /* directory module not installed */ } })();
    const people = new Map(), index = new Map();
    const mk = (key, base) => { let p = people.get(key); if (!p) { p = Object.assign({ key, name: '', sam: '', upn: '', mail: '', department: '', title: '', enabled: null, last_logon: null, privileged: false, in_directory: false, devices: new Map(), named_as: new Set() }, base); people.set(key, p); } return p; };
    for (const u of (dir && dir.users) || []) {
      const k = keyOf('ad:' + String(u.sam).toLowerCase());
      mk(k, { name: clip(u.display_name || u.sam, 120), sam: clip(u.sam, 64), upn: clip(u.upn, 200), mail: clip(u.mail, 200), department: clip(u.department, 120), title: clip(u.title, 120),
        enabled: u.enabled == null ? null : !!u.enabled, last_logon: u.last_logon || null, privileged: !!u.admin_count, in_directory: true });
      for (const v of [u.sam, u.upn, u.mail, u.display_name]) { const n = norm(v); if (n && !index.has(n)) index.set(n, k); }
    }
    const assets = col('assets'), byId = new Map(assets.map((a) => [a.id, a]));
    const link = (raw, asset, how, at) => {
      for (const part of String(raw || '').split(/[,;]+/)) {
        const n = norm(part); if (!n || n.length < 2 || NOT_PERSON.test(n)) continue;
        let k = index.get(n);
        if (!k) { k = keyOf('name:' + n); mk(k, { name: clip(part.replace(/\s*\((joiner|leaver)[^)]*\)\s*$/i, '').replace(/^.*\\/, ''), 120) }); index.set(n, k); }
        const p = people.get(k); p.named_as.add(clip(part, 120));
        const d = p.devices.get(asset.id) || { id: asset.id, links: [], seen: null }; if (!d.links.includes(how)) d.links.push(how); if (at && (!d.seen || at > d.seen)) d.seen = at; p.devices.set(asset.id, d);
      }
    };
    const active = assets.filter((a) => !CLOSED[a.status]);
    for (const a of active) {
      if (a.custodian) link(a.custodian, a, 'custodian');
      if (a.owner && END_USER[a.type]) link(a.owner, a, 'owner');
    }
    const ec = col('me_ec_computers');
    for (const c of ec) { const a = c.asset_id && byId.get(c.asset_id); if (a && !CLOSED[a.status] && c.user) link(c.user, a, 'signed in (Endpoint Central)', c.last_contact || null); }
    const pol = Object.fromEntries(col('software_policy').map((p) => [p.id, p]));
    // per person: applications on their devices
    const appsOf = (p) => {
      const m = new Map();
      for (const d of p.devices.values()) { const a = byId.get(d.id); if (!a) continue;
        for (const sw0 of a.software || []) { const sw = normSoftwareEntry(sw0); if (!sw || FREEWARE.test(sw.name)) continue;
          const k = productKey(sw); let e = m.get(k);
          if (!e) { const label = (sw.publisher || '') + ' ' + sw.name; e = { key: k, name: sw.name, publisher: sw.publisher || '', versions: new Set(), on: new Set(), category: catOf(label), risky: RISKY.test(sw.name), policy: (pol[k] && pol[k].status) || null }; m.set(k, e); }
          if (sw.version) e.versions.add(sw.version); e.on.add(a.name || a.asset_tag || a.id); } }
      return m;
    };
    const list = [...people.values()].map((p) => Object.assign(p, { apps: appsOf(p) }));
    const m365 = (() => { try { return m365C().get('last'); } catch (e) { return null; /* not read yet */ } })();
    let m365Matched = 0;
    if (m365) for (const u of m365.users || []) { const k = index.get(norm(u.upn)) || (u.mail && index.get(norm(u.mail))); const p = k && people.get(k); if (p && !p.m365) { p.m365 = u; m365Matched++; } }
    // learned per department: how common each application is among its people (5+ people reporting software)
    const dept = new Map();
    for (const p of list) { if (!p.department || !p.apps.size) continue; const d = dept.get(p.department) || { n: 0, c: new Map() }; d.n++; for (const k of p.apps.keys()) d.c.set(k, (d.c.get(k) || 0) + 1); dept.set(p.department, d); }
    for (const p of list) {
      const d = p.department && dept.get(p.department); p.unusual = [];
      if (d && d.n >= 5) for (const [k, e] of p.apps) { const share = (d.c.get(k) || 0) / d.n; if (share <= 0.1 && e.category !== 'runtime') { e.unusual = Math.round(share * 100); p.unusual.push(e.name); } }
      const devs = [...p.devices.values()].map((x) => byId.get(x.id)).filter(Boolean), eu = devs.filter((a) => END_USER[a.type]).length;
      const F = [];
      if (p.in_directory && p.enabled === false && devs.length) F.push({ k: 'leaver', sev: 'bad', why: 'disabled in Active Directory but still holds ' + devs.length + ' device(s) - recover them' });
      if (p.in_directory && p.enabled !== false && p.last_logon && t - Date.parse(p.last_logon) > 90 * DAY && devs.length) F.push({ k: 'stale', sev: 'warn', why: 'no directory sign-in for ' + Math.round((t - Date.parse(p.last_logon)) / DAY) + ' days but holds devices' });
      if (dir && !p.in_directory) F.push({ k: 'nodir', sev: 'warn', why: 'named on devices as "' + [...p.named_as].slice(0, 2).join('", "') + '" but no matching directory account' });
      const risky = [...p.apps.values()].filter((e) => e.risky && e.policy !== 'approved'), blocked = [...p.apps.values()].filter((e) => e.policy === 'blocked');
      if (risky.length) F.push({ k: 'risky', sev: 'warn', why: 'remote-access / tunnelling tools not approved: ' + risky.slice(0, 4).map((e) => e.name).join(', ') });
      if (blocked.length) F.push({ k: 'blocked', sev: 'bad', why: 'software the policy blocks: ' + blocked.slice(0, 4).map((e) => e.name).join(', ') });
      if (eu > 3) F.push({ k: 'many', sev: 'info', why: eu + ' end-user devices assigned' });
      if (p.m365 && p.m365.licences.length && p.in_directory && p.enabled === false) F.push({ k: 'm365_leaver', sev: 'bad', why: 'disabled in Active Directory but still has Microsoft 365 licences: ' + p.m365.licences.slice(0, 3).join(', ') });
      else if (p.m365 && p.m365.licences.length && m365.usage && (!p.m365.last_activity || t - Date.parse(p.m365.last_activity) > 30 * DAY)) F.push({ k: 'm365_unused', sev: 'info', why: 'Microsoft 365 licence(s) with no activity in 30 days: ' + p.m365.licences.slice(0, 3).join(', ') + ' - a candidate to reclaim' });
      if (p.unusual.length) F.push({ k: 'unusual', sev: 'info', why: p.unusual.length + ' application(s) unusual for ' + p.department + ': ' + p.unusual.slice(0, 3).join(', ') });
      p.flags = F; p.device_list = devs; p.end_user = eu;
    }
    const unassigned = active.filter((a) => END_USER[a.type] && !list.some((p) => p.devices.has(a.id)));
    return { t, dir, list, unassigned, ec, active, dept, m365, m365Matched };
  }
  function view() {
    const B = build();
    const people = B.list.filter((p) => p.in_directory || p.devices.size).map((p) => ({ key: p.key, name: p.name || p.sam, sam: p.sam, upn: p.upn, department: p.department, title: p.title, enabled: p.enabled, last_logon: p.last_logon, privileged: p.privileged, in_directory: p.in_directory,
      devices: p.devices.size, end_user: p.end_user, types: p.device_list.reduce((m, a) => { m[a.type] = (m[a.type] || 0) + 1; return m; }, {}), apps: p.apps.size, m365: p.m365 ? { licences: p.m365.licences.length, used: p.m365.apps ? M365_APPS.filter((k) => p.m365.apps[k]) : null, last_activity: p.m365.last_activity } : null, risky: [...p.apps.values()].filter((e) => e.risky && e.policy !== 'approved').length, flags: p.flags }))
      .sort((a, b) => (b.flags.filter((f) => f.sev === 'bad').length - a.flags.filter((f) => f.sev === 'bad').length) || (b.devices - a.devices) || String(a.name).localeCompare(String(b.name)));
    const eu = B.active.filter((a) => END_USER[a.type]);
    const depts = [...new Set(people.map((p) => p.department).filter(Boolean))].sort().map((d) => ({ name: d, people: people.filter((p) => p.department === d).length, devices: people.filter((p) => p.department === d).reduce((s, p) => s + p.devices, 0) }));
    return { at: new Date(B.t).toISOString(),
      sources: { directory: B.dir ? { read_at: B.dir.at, users: (B.dir.users || []).length, group: B.dir.group || '', truncated: !!B.dir.truncated } : null,
        m365: B.m365 ? { read_at: B.m365.at, users: (B.m365.users || []).length, matched: B.m365Matched, concealed: !!B.m365.concealed, usage: !!B.m365.usage, errors: B.m365.errors || [] } : null,
        m365_connected: (() => { try { const L = LIC(); return !!(L && L.connected && L.connected()); } catch (e) { return false; /* connection unreadable: not connected */ } })(),
        endpoint_central: { computers: B.ec.length, with_user: B.ec.filter((c) => c.user).length }, assets: { active: B.active.length, end_user: eu.length, with_software: B.active.filter((a) => (a.software || []).length).length } },
      kpis: { people: people.length, with_devices: people.filter((p) => p.devices).length, end_user_devices: eu.length, assigned_pct: eu.length ? Math.round(100 * (eu.length - B.unassigned.length) / eu.length) : null, unassigned: B.unassigned.length,
        leavers: people.filter((p) => p.flags.some((f) => f.k === 'leaver')).length, risky: people.filter((p) => p.risky).length, not_in_directory: people.filter((p) => p.flags.some((f) => f.k === 'nodir')).length,
        m365_licensed: people.filter((p) => p.m365 && p.m365.licences).length, m365_unused: people.filter((p) => p.flags.some((f) => f.k === 'm365_unused' || f.k === 'm365_leaver')).length },
      people, departments: depts,
      unassigned: B.unassigned.slice(0, 200).map((a) => ({ id: a.id, name: a.name || a.asset_tag || a.id, type: a.type, status: a.status, site: a.site || '', last_seen: a.last_seen || null })),
      note: B.dir ? 'Indicators for review, not proof: a link is an exact name match, and installed software is what the devices report.' : 'Active Directory has not been read yet (Platform Administration -> User Management -> Directory users -> Read): people come from the names on the devices only.' };
  }
  function person(key, who) {
    param(key, 'key');
    const B = build(), p = B.list.find((x) => x.key === key);
    if (!p) throw httpErr(404, 'no such person in the inventory');
    audit(who, 'people.view', key, { name: p.name || p.sam, devices: p.devices.size });
    const ecBy = new Map(B.ec.filter((c) => c.asset_id).map((c) => [c.asset_id, c]));
    return { key: p.key, name: p.name || p.sam, sam: p.sam, upn: p.upn, mail: p.mail, department: p.department, title: p.title, enabled: p.enabled, last_logon: p.last_logon, privileged: p.privileged, in_directory: p.in_directory, named_as: [...p.named_as], flags: p.flags,
      devices: p.device_list.map((a) => { const d = p.devices.get(a.id), c = ecBy.get(a.id); return { id: a.id, name: a.name || a.asset_tag || a.id, asset_tag: a.asset_tag || '', type: a.type, status: a.status, vendor: a.vendor || '', model: a.model || '', serial: a.serial || '', os: a.os || '', site: a.site || '', ip: a.mgmt_ip || '', last_seen: a.last_seen || null, linked_by: d.links, ec: c ? { last_contact: c.last_contact || null, health: c.health || null, missing: c.missing == null ? null : c.missing } : null, apps: (a.software || []).length }; }),
      m365: p.m365 || null,
      apps: [...p.apps.values()].map((e) => ({ name: e.name, publisher: e.publisher, versions: [...e.versions].slice(0, 6), on: [...e.on], category: e.category, risky: e.risky, policy: e.policy, unusual: e.unusual == null ? null : e.unusual }))
        .sort((a, b) => (Number(b.policy === 'blocked') - Number(a.policy === 'blocked')) || (Number(b.risky) - Number(a.risky)) || a.category.localeCompare(b.category) || a.name.localeCompare(b.name)) };
  }
  return { view, person, readM365, start, stop };
}

function registerPeopleInventory(srv, app, X0) {
  const X = X0 && X0.view ? X0 : createPeopleInventory(app, X0 || {});
  (app.addons = app.addons || {}).peopleInventory = X;
  srv.route('GET', '/people-inventory', (ctx) => { ctx.need('operator'); return X.view(); });
  srv.route('POST', '/people-inventory/m365/read', async (ctx) => { ctx.need('operator'); body(ctx.body).done(); return X.readM365(Object.assign({ ip: ctx.ip }, ctx.who)); });
  srv.route('GET', '/people-inventory/:key', (ctx) => { ctx.need('operator'); return X.person(ctx.params.key, Object.assign({ ip: ctx.ip }, ctx.who)); });
  X.start();
  return X;
}
module.exports = { createPeopleInventory, registerPeopleInventory, norm };
