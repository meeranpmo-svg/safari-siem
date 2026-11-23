// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body, param } = require('./check');
// User Desktops ({P} = /api/itam): one place for the desktop engineers - every user desktop / laptop, filtered by branch,
// with its Endpoint Central agent and patch state, Patch Management, and remote support with a logged reason.
//   Desktops       the Endpoint Central computers ManageEngine syncs (not servers) + every user desktop in the asset register
//                  (workstation / laptop, or any asset with a client OS such as Windows 10 / 11 or macOS, VDI included) that has
//                  no Endpoint Central agent (listed so the gap is visible). Branch = Endpoint Central
//                  branch office, else the asset's site, else "Unassigned".
//   Patches        the Endpoint Central patch catalogue (missing / installed counts), one computer's patches on demand; a
//                  deployment or a patch scan is an Endpoint Central action request that a different person approves
//                  (engine/manageengine.js requestA / approveA - four eyes, unchanged), split per 200 computers.
//   Remote support the engineer gives a reason (and the ticket); the session is logged and audited, then the page offers the
//                  Endpoint Central remote-control link (admin sets its URL template) and the Windows commands (msra /offerra
//                  asks the user to accept; mstsc). Nothing is started on a desktop by the platform itself.
//   Branches       an administrator assigns branches to each desktop engineer; their view opens on those branches.
// Desktop names and logged-on user names are personal data (PDPL): the list is operator and above; viewers see counts.
//   GET  /desktops?branch=&q=&state=        operator  desktops + branch summary (+ my_branches)
//   GET  /desktops/summary                  viewer    counts per branch, no names
//   GET  /desktops/patches                  operator  patch catalogue
//   GET  /desktops/:id/patches              operator  one computer's patches (read live from Endpoint Central)
//   POST /desktops/patches/deploy {patch_ids[], branch? | desktop_ids[], reason}   operator → approval requests
//   POST /desktops/patches/scan   {branch? | desktop_ids[], reason}                operator → approval requests
//   POST /desktops/:id/remote     {reason, ticket?}           operator  start (log) a remote support session → links
//   POST /desktops/remote/:sid/end {outcome, note?}           operator  the engineer who started it, or an admin
//   GET  /desktops/remote/sessions?mine=1                     operator
//   GET/POST /desktops/settings   {remote:{ec_url, msra, rdp}, engineers:[{user, branches[]}]}  operator read / admin write
const CLOSED = { retired: 1, disposed: 1, lost: 1, stolen: 1, archived: 1 };
const DESK_TYPES = ['desktop', 'laptop', 'workstation', 'pc', 'thin_client'];
const OUTCOMES = ['resolved', 'escalated', 'not_resolved', 'user_unavailable'];
const MAX_PER_ACTION = 200;
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const s = (v, n = 200) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);
const low = (v) => s(v).toLowerCase();
const isServerOs = (os) => /server|esxi|linux|unix|solaris|aix/i.test(String(os || ''));
// a user desktop in the asset register: typed workstation / laptop / desktop, or any other / VM asset (VDI) whose OS is a
// client OS - Discovery and imports often leave a user PC as "other" with "Windows 11 Pro" in the OS field
const CLIENT_OS = /windows\s*(xp|vista|7|8(\.1)?|10|11)\b|mac\s?os|os x|chrome\s?os/i;
function isDesktopAsset(a) {
  if (!a || CLOSED[a.status]) return false;
  if (DESK_TYPES.includes(a.type)) return true;
  const os = [a.os, a.discovery && a.discovery.os].join(' ');
  return ['other', 'vm', 'unknown', '', null, undefined].includes(a.type) && CLIENT_OS.test(os) && !isServerOs(os);
}
const HOST = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/;

function createDesktops(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const ecCol = store.collection('me_ec_computers'), assets = store.collection('assets'), tickets = store.collection('me_tickets');
  const sessions = store.collection('desktop_remote_sessions'), conf = store.collection('desktop_settings');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const ME = () => { const m = app.addons && app.addons.manageengine; if (!m) throw bad('the ManageEngine Endpoint Central integration is not installed (install/add-manageengine.sh)', 409); return m; };

  function settings() {
    const c = conf.get('settings') || {};
    return { remote: Object.assign({ ec_url: '', msra: true, rdp: true }, c.remote || {}), engineers: Array.isArray(c.engineers) ? c.engineers : [], updated_by: c.updated_by || null, updated_at: c.updated_at || null };
  }
  function myBranches(user) { const e = settings().engineers.find((x) => low(x.user) === low(user)); return e ? e.branches : []; }

  // ---- the desktop list ----
  function list() {
    const byAsset = new Map(assets.all().map((a) => [a.id, a]));
    const openT = new Map();
    for (const t of tickets.all((x) => x.asset_id && !/closed|resolved|rejected|failed/.test(String(x.status || '')) && !/closed|resolved/i.test(String(x.sdp_status || '')))) openT.set(t.asset_id, (openT.get(t.asset_id) || 0) + 1);
    const out = [], seenAssets = new Set();
    for (const c of ecCol.all((x) => !x.gone_since && !isServerOs(x.os))) {
      const a = c.asset_id ? byAsset.get(c.asset_id) : null;
      if (a && CLOSED[a.status]) continue;
      if (a) seenAssets.add(a.id);
      out.push({ id: c.asset_id || 'ec:' + c.id, asset_id: c.asset_id || null, resource_id: c.id, name: c.name, fqdn: c.fqdn || '', user: c.user || (a && (a.custodian || a.owner)) || '', branch: c.branch || (a && a.site) || 'Unassigned',
        ip: c.ip || (a && a.mgmt_ip) || '', os: c.os || (a && a.os) || '', type: (a && a.type) || 'desktop', agent: c.live === 'live' ? 'live' : c.live === 'down' ? 'offline' : 'unknown', last_contact: c.last_contact || null,
        patch: { health: c.health || null, missing: c.missing, critical: c.critical }, tickets: (c.asset_id && openT.get(c.asset_id)) || 0 });
    }
    for (const a of assets.all((x) => isDesktopAsset(x) && !seenAssets.has(x.id))) {
      out.push({ id: a.id, asset_id: a.id, resource_id: null, name: a.name || a.asset_tag || a.id, fqdn: a.hostname || '', user: a.custodian || a.owner || '', branch: a.site || 'Unassigned', ip: a.mgmt_ip || '', os: a.os || '', type: a.type,
        agent: 'missing', last_contact: null, patch: { health: null, missing: null, critical: null }, tickets: openT.get(a.id) || 0 });
    }
    return out.sort((x, y) => (x.branch === y.branch ? (x.name < y.name ? -1 : 1) : x.branch < y.branch ? -1 : 1));
  }
  const atRisk = (d) => (d.patch.critical || 0) > 0 || d.patch.health === 'highly vulnerable';
  function branchesOf(rows) {
    const by = new Map();
    for (const d of rows) {
      const b = by.get(d.branch) || { branch: d.branch, desktops: 0, agent_offline: 0, agent_missing: 0, critical_missing: 0, with_patch_data: 0, compliant: 0, tickets: 0 };
      b.desktops++; if (d.agent === 'offline') b.agent_offline++; if (d.agent === 'missing') b.agent_missing++; if (atRisk(d)) b.critical_missing++; b.tickets += d.tickets;
      if (d.patch.critical != null || d.patch.health) { b.with_patch_data++; if (!atRisk(d)) b.compliant++; }
      by.set(d.branch, b);
    }
    return [...by.values()].map((b) => Object.assign(b, { compliance_pct: b.with_patch_data ? Math.round((100 * b.compliant) / b.with_patch_data) : null })).sort((a, c) => (a.branch < c.branch ? -1 : 1));
  }
  const STATES = { offline: (d) => d.agent === 'offline', no_agent: (d) => d.agent === 'missing', critical: atRisk, tickets: (d) => d.tickets > 0 };
  function view(q, who) {
    const all = list(), mine = myBranches(who.user);
    const want = q.branch === 'mine' ? mine.map(low) : q.branch ? [low(q.branch)] : null;
    const text = low(q.q);
    const rows = all.filter((d) => (!want || want.includes(low(d.branch))) && (!q.state || (STATES[q.state] && STATES[q.state](d)))
      && (!text || [d.name, d.user, d.ip, d.fqdn].some((v) => low(v).includes(text))));
    const ec = (app.addons && app.addons.manageengine && typeof app.addons.manageengine.status === 'function') ? app.addons.manageengine.status() : null;
    return { generated_at: new Date(now()).toISOString(), branches: branchesOf(all), my_branches: mine, total: all.length, shown: rows.length, desktops: rows.slice(0, 3000),
      source: ec ? { ec_configured: !!(ec.ec && ec.ec.base_url), last_sync: ec.ec && ec.ec.last_sync ? ec.ec.last_sync : null } : { ec_configured: false, last_sync: null } };
  }
  function summary() { const b = branchesOf(list()); return { branches: b.map((x) => ({ branch: x.branch, desktops: x.desktops, agent_offline: x.agent_offline, agent_missing: x.agent_missing, critical_missing: x.critical_missing, compliance_pct: x.compliance_pct })) }; }
  function must(id) { const d = list().find((x) => x.id === id); if (!d) throw bad('desktop not found', 404); return d; }

  // ---- patches ----
  function patches() {
    let rows = []; try { rows = ME().patches(); } catch (e) { if (e.status === 409) return { available: false, reason: e.message, patches: [] }; throw e; }
    const SEV = { critical: 0, important: 1, moderate: 2, low: 3, unrated: 4 };
    rows = rows.slice().sort((a, b) => (SEV[a.severity] ?? 5) - (SEV[b.severity] ?? 5) || (b.missing || 0) - (a.missing || 0));
    const missing = rows.filter((p) => (p.missing || 0) > 0);
    return { available: true, patches: rows.slice(0, 5000), counts: { patches: rows.length, missing: missing.length, critical_missing: missing.filter((p) => p.severity === 'critical').length, important_missing: missing.filter((p) => p.severity === 'important').length } };
  }
  async function desktopPatches(id) {
    const d = must(id);
    if (!d.resource_id) throw bad('this desktop has no Endpoint Central agent - install the agent first', 409);
    const rows = await ME().systemPatches(d.resource_id);
    return { desktop: { id: d.id, name: d.name, branch: d.branch }, patches: rows, missing: rows.filter((p) => /missing|not.?installed/.test(p.status) || p.status === '').length };
  }
  function targets(b) {
    let rows;
    if (b.desktop_ids && b.desktop_ids.length) { rows = b.desktop_ids.map((i) => must(i)); }
    else if (b.branch) { rows = list().filter((d) => low(d.branch) === low(b.branch)); if (!rows.length) throw bad('branch: no desktop in "' + b.branch + '"'); }
    else throw bad('choose a branch or desktops');
    const ec = rows.filter((d) => d.resource_id);
    if (!ec.length) throw bad('none of these desktops has an Endpoint Central agent', 409);
    return { ec, skipped: rows.length - ec.length };
  }
  function chunks(a) { const out = []; for (let i = 0; i < a.length; i += MAX_PER_ACTION) out.push(a.slice(i, i + MAX_PER_ACTION)); return out; }
  function request(kind, input, who) {
    const v = body(input || {}).list('patch_ids', { max: 100, item: 'str' }).str('branch', { max: 80 }).list('desktop_ids', { max: 2000, item: 'str' }).str('reason', { required: true, max: 500 }).done();
    if (v.reason.length < 5) throw bad('reason: say why (at least 5 characters)');
    if (kind === 'ec-install-patches' && !(v.patch_ids || []).length) throw bad('patch_ids: choose at least one patch');
    if ((v.patch_ids || []).some((p) => !/^\d{1,12}$/.test(p))) throw bad('patch_ids: Endpoint Central patch ids are numbers');
    if ((v.desktop_ids || []).some((x) => !/^[A-Za-z0-9_.:-]{1,80}$/.test(x))) throw bad('desktop_ids: not a desktop id');
    const t = targets(v), M = ME(), made = [];
    const scope = v.branch ? 'branch ' + v.branch : (v.desktop_ids || []).length + ' desktop(s)';
    for (const part of chunks(t.ec)) made.push(M.requestA({ action: kind, resource_ids: part.map((d) => d.resource_id), patch_ids: v.patch_ids, reason: `${v.reason} [User Desktops: ${scope}]` }, who).action);
    audit(who, kind === 'ec-install-patches' ? 'desktops.patch.deploy_request' : 'desktops.patch.scan_request', v.branch || 'desktops', { branch: v.branch || null, computers: t.ec.length, without_agent: t.skipped, patch_ids: v.patch_ids || null, requests: made.map((a) => a.id) });
    return { requests: made.map((a) => ({ id: a.id, label: a.label, computers: a.resource_ids.length, status: a.status })), computers: t.ec.length, without_agent: t.skipped, approval: 'a different person approves each request in ManageEngine → Actions (or AI Desktop Support) before Endpoint Central runs it' };
  }

  // ---- remote support ----
  function startRemote(id, input, who) {
    const v = body(input || {}).str('reason', { required: true, max: 500 }).str('ticket', { max: 40 }).done();
    if (v.reason.length < 5) throw bad('reason: describe the user\'s problem (at least 5 characters)');
    if (v.ticket && !/^[A-Za-z0-9_#.-]{1,40}$/.test(v.ticket)) throw bad('ticket: letters, digits and - only');
    const d = must(id), st = settings();
    const host = [d.fqdn, d.name, d.ip].find((x) => x && HOST.test(x)) || '';
    const links = [], commands = [];
    if (st.remote.ec_url && d.resource_id) links.push({ kind: 'endpointcentral', label: 'Endpoint Central remote control', url: st.remote.ec_url.replace(/\{resource_id\}/g, encodeURIComponent(d.resource_id)).replace(/\{name\}/g, encodeURIComponent(d.name)) });
    if (st.remote.msra && host) commands.push({ kind: 'msra', label: 'Windows Remote Assistance (the user is asked to accept)', command: 'msra /offerra ' + host });
    if (st.remote.rdp && host) commands.push({ kind: 'rdp', label: 'Remote Desktop (signs the user out of the console)', command: 'mstsc /v:' + host });
    if (!links.length && !commands.length) throw bad('no remote support method is set up - an administrator sets the Endpoint Central remote-control link or enables Remote Assistance in User Desktops → Settings', 409);
    const sess = { id: 'rs_' + crypto.randomBytes(5).toString('hex'), desktop_id: d.id, desktop: d.name, branch: d.branch, end_user: d.user || '', engineer: who.user, reason: v.reason, ticket: v.ticket || null, status: 'open', started_at: new Date(now()).toISOString() };
    sessions.put(sess);
    audit(who, 'desktops.remote.start', d.id, { session: sess.id, desktop: d.name, branch: d.branch, ticket: sess.ticket, reason: v.reason });
    return { session: sess, links, commands, consent: 'Tell the user before you connect; Remote Assistance asks them to accept. Do not open their files beyond the problem (PDPL).' };
  }
  function endRemote(sid, input, who) {
    const v = body(input || {}).oneOf('outcome', OUTCOMES, { required: true }).str('note', { max: 1000 }).done();
    const x = sessions.get(sid); if (!x) throw bad('session not found', 404);
    if (x.status !== 'open') throw bad('this session is already closed', 409);
    if (low(x.engineer) !== low(who.user) && who.role !== 'admin') throw bad('only the engineer who started the session (or an administrator) closes it', 403);
    const y = sessions.patch(sid, (r) => Object.assign(r, { status: 'closed', outcome: v.outcome, note: v.note || '', ended_at: new Date(now()).toISOString(), ended_by: who.user }));
    audit(who, 'desktops.remote.end', x.desktop_id, { session: sid, outcome: v.outcome });
    return { session: y };
  }
  function listSessions(q, who) {
    const rows = sessions.all((x) => q.mine !== '1' || low(x.engineer) === low(who.user)).sort((a, b) => (a.started_at < b.started_at ? 1 : -1)).slice(0, 500);
    return { sessions: rows };
  }

  // ---- settings ----
  function saveSettings(input, who) {
    const b = input || {};
    if (b.remote !== undefined && (typeof b.remote !== 'object' || Array.isArray(b.remote))) throw bad('remote must be an object');
    const r = body(b.remote || {}).str('ec_url', { max: 500 }).bool('msra', { def: true }).bool('rdp', { def: true }).done();
    if (r.ec_url && !/^https:\/\/[^\s"'<>]+$/.test(r.ec_url)) throw bad('remote.ec_url must be an https:// address (use {resource_id} where the computer id goes)');
    if (b.engineers !== undefined && !Array.isArray(b.engineers)) throw bad('engineers must be a list');
    const engineers = (b.engineers || []).slice(0, 500).map((e, i) => {
      const x = body(e).str('user', { required: true, max: 120 }).list('branches', { max: 100, item: 'str' }).done();
      if (!x.branches || !x.branches.length) throw bad(`engineers[${i}].branches: give at least one branch`);
      return { user: x.user, branches: x.branches.map((v) => s(v, 80)).filter(Boolean) };
    });
    conf.put({ id: 'settings', remote: r, engineers, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit(who, 'desktops.settings', 'settings', { ec_url_set: !!r.ec_url, msra: r.msra, rdp: r.rdp, engineers: engineers.map((e) => e.user + ':' + e.branches.length) });
    return settings();
  }

  return { list, view, summary, patches, desktopPatches, request, startRemote, endRemote, listSessions, settings, saveSettings, myBranches };
}

function registerDesktops(srv, app) {
  const D = createDesktops(app);
  const id = (ctx) => param(ctx.params.id, 'id');
  srv.route('GET', '/desktops', (ctx) => { ctx.need('operator'); const q = ctx.query || {}; if (q.state && !['offline', 'no_agent', 'critical', 'tickets'].includes(q.state)) throw bad('state must be offline, no_agent, critical or tickets'); return D.view({ branch: s(q.branch, 80), q: s(q.q, 80), state: q.state || '' }, ctx.who); });
  srv.route('GET', '/desktops/summary', (ctx) => { ctx.need('viewer'); return D.summary(); });
  srv.route('GET', '/desktops/patches', (ctx) => { ctx.need('operator'); return D.patches(); });
  srv.route('POST', '/desktops/patches/deploy', (ctx) => { ctx.need('operator'); return D.request('ec-install-patches', ctx.body, ctx.who); });
  srv.route('POST', '/desktops/patches/scan', (ctx) => { ctx.need('operator'); return D.request('ec-patch-scan', ctx.body, ctx.who); });
  srv.route('GET', '/desktops/remote/sessions', (ctx) => { ctx.need('operator'); return D.listSessions(ctx.query || {}, ctx.who); });
  srv.route('POST', '/desktops/remote/:sid/end', (ctx) => { ctx.need('operator'); return D.endRemote(param(ctx.params.sid, 'sid'), ctx.body, ctx.who); });
  srv.route('GET', '/desktops/settings', (ctx) => { ctx.need('operator'); return D.settings(); });
  srv.route('POST', '/desktops/settings', (ctx) => { ctx.need('admin'); return D.saveSettings(ctx.body, ctx.who); });
  srv.route('GET', '/desktops/:id/patches', async (ctx) => { ctx.need('operator'); return D.desktopPatches(id(ctx)); });
  srv.route('POST', '/desktops/:id/remote', (ctx) => { ctx.need('operator'); return D.startRemote(id(ctx), ctx.body, ctx.who); });
  (app.addons = app.addons || {}).desktops = D;
  return D;
}

module.exports = { createDesktops, registerDesktops, isServerOs, isDesktopAsset };
