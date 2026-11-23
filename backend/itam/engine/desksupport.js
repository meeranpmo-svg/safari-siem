// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const SR = require('./saferegex');
const { guardOf } = require('./errors');
// AI Desktop Support Engineer — automates IT service management on top of the ManageEngine integration (engine/manageengine.js):
//   • Ticket triage in ServiceDesk Plus: set priority, assign a technician / group, move status, add a first-response note.
//   • Desktop monitoring: desktop health from the Endpoint Central computers ManageEngine already syncs (offline agent,
//     missing critical patches, highly vulnerable) PLUS every user desktop / laptop in the asset register (desktops.js
//     isDesktopAsset - the same rule as User Desktops) that has no Endpoint Central agent: listed with that gap, so desktop
//     support covers every desktop the register holds, with or without ManageEngine.
//     (was:
//     missing critical patches, highly vulnerable).
//   • Patch management: proposes installing missing critical patches; the device-changing install is APPROVAL-GATED by
//     default (an admin may arm auto-approval within a maintenance window and threshold).
// Modes: off / suggest (records a proposal for a human to apply) / auto (applies triage itself). Everything is audited.
// It reuses ManageEngine's sealed ServiceDesk Plus / Endpoint Central credentials (shared me_config + the same vault
// purpose) — no second credential setup. Ticket updates are the only new write; a small allow-list client does them.
//   GET  /me/desk                          status, config, triage queue, desktop health, patch proposals   operator
//   POST /me/desk/config    {mode, technicians[], priority_rules, groups, ack_status, patch{…}, max_per_run} admin
//   POST /me/desk/scan                      run triage now (apply in auto, propose in suggest)              admin
//   POST /me/desk/triage/:id/apply {priority,group,technician,status,note}  apply a proposed triage        operator
//   POST /me/desk/patch/:resource/request  propose installing missing patches on a computer                operator
//   POST /me/desk/patch/:id/approve        approve + run a patch install (four-eyes with the requester)     admin
// Self-contained (stored collections); one registration line in main.js (install/add-desksupport.sh).
// four-eyes: names compared trimmed and case-insensitive (one sign-in method may send "Alice", another "alice"); requests the
// platform raised itself (duty:<engineer>, system:<job>) have no human requester
const normUser = (u) => String(u == null ? '' : u).trim().toLowerCase();
const sameUser = (a, b) => !!normUser(a) && normUser(a) === normUser(b);
const isSystem = (u) => /^(duty|system):/i.test(String(u || '').trim());
const crypto = require('node:crypto');
const httpc = require('./discovery/httpc');
const { createSealer } = require('./discovery/vault');
const { ecClient, ecComputer, ecPatch } = require('./manageengine');
// The user-desktop rule, kept IN this file: add-desksupport.sh installs desksupport.js on its own (it must load without
// desktops.js - a require of './desktops' stopped sentra-itam starting on 2026-11-14 and the update rolled back). It is the same
// rule as desktops.js isDesktopAsset / isServerOs, and tests/desksupport.test.js checks the two agree on every case.
const DS_CLOSED = { retired: 1, disposed: 1, lost: 1, stolen: 1, archived: 1 };
const DS_TYPES = ['desktop', 'laptop', 'workstation', 'pc', 'thin_client'];
const DS_CLIENT_OS = /windows\s*(xp|vista|7|8(\.1)?|10|11)\b|mac\s?os|os x|chrome\s?os/i;
const isServerOs = (os) => /server|esxi|linux|unix|solaris|aix/i.test(String(os || ''));
function isDesktopAsset(a) {
  if (!a || DS_CLOSED[a.status]) return false;
  if (DS_TYPES.includes(a.type)) return true;
  const os = [a.os, a.discovery && a.discovery.os].join(' ');
  return ['other', 'vm', 'unknown', '', null, undefined].includes(a.type) && DS_CLIENT_OS.test(os) && !isServerOs(os);
}

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const err = (code, msg) => Object.assign(new Error(msg), { code });
const s = (v, max = 200) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
const low = (v) => s(v).toLowerCase();
const SYS = { user: 'system:desk-support', role: 'admin' };
const PRIORITIES = ['Low', 'Medium', 'High', 'Urgent'];
const MODES = ['off', 'suggest', 'auto'];
// default keyword → priority (first match wins, most urgent first). Editable in config.priority_rules.
const DEF_PRIORITY = [
  ['Urgent', 'down|outage|cannot work|production|ransom|breach|all users|data loss|urgent|p1'],
  ['High', 'not working|error|crash|blocked|vpn|email down|cannot access|locked out|asap|important'],
  ['Low', 'how to|how do i|question|request|please install|rename|cosmetic|enhancement|when you can'],
];
// default category keyword → ServiceDesk group. Editable in config.groups.
const DEF_GROUPS = [
  ['Network', 'network|wifi|wi-fi|vpn|internet|lan|switch|router|firewall'],
  ['Messaging', 'email|outlook|exchange|mailbox|calendar|teams|sharepoint'],
  ['Identity & Access', 'password|account|login|mfa|access|permission|locked|ad |active directory'],
  ['Desktop Support', 'laptop|desktop|pc|printer|monitor|keyboard|mouse|install|software|office|windows|slow|screen'],
];
// SDP v3 calls this module is allowed to make (read open requests, read one, update one, add a note)
const SDP_RW = [
  ['GET', /^\/api\/v3\/requests(\?input_data=[^\s]*)?$/],
  ['GET', /^\/api\/v3\/requests\/\d+$/],
  ['PUT', /^\/api\/v3\/requests\/\d+$/],
  ['POST', /^\/api\/v3\/requests\/\d+\/notes$/],
];
function sdpRW(conn, key, o = {}) {
  const req = o.request || httpc.request;
  async function call(method, path, input) {
    const full = method === 'GET' && input ? `${path}?input_data=${encodeURIComponent(JSON.stringify(input))}` : path;
    if (!SDP_RW.some(([m, re]) => m === method && re.test(full))) throw err('config', `ServiceDesk Plus: refusing ${method} ${path}`);
    const body = method === 'GET' ? null : 'input_data=' + encodeURIComponent(JSON.stringify(input || {}));
    const r = await req(conn.base_url + full, { method, headers: Object.assign({ Accept: 'application/vnd.manageengine.sdp.v3+json', authtoken: key }, body ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
      body, caFile: conn.ca_file || undefined, pin: conn.tls_fingerprint || undefined, timeoutMs: o.timeoutMs || 30000 });
    const j = r.json, rs = j && j.response_status, st = rs && (Array.isArray(rs) ? rs[0] : rs);
    const msg = st && st.messages && st.messages[0] ? s(st.messages[0].message || st.messages[0].status_code, 300) : '';
    if (r.status === 401) throw err('auth', 'ServiceDesk Plus refused the technician key' + (msg ? ` (${msg})` : ''));
    if (!j || typeof j !== 'object') throw err('protocol', `ServiceDesk Plus ${path}: HTTP ${r.status}, not JSON`);
    if (r.status < 200 || r.status >= 300 || (st && String(st.status).toLowerCase() === 'failed')) throw err(r.status === 403 ? 'authz' : 'protocol', `ServiceDesk Plus ${path}: ${msg || 'HTTP ' + r.status}`);
    return j;
  }
  return { call };
}

function createDeskSupport(app, opts = {}) {
  const { store } = app;
  const meCfg = store.collection('me_config'), ecCol = store.collection('me_ec_computers');
  const confCol = store.collection('desk_config'), triageCol = store.collection('desk_triage'), patchCol = store.collection('desk_patch');
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-manageengine' });
  const audit = (e) => { if (app.audit) app.audit(Object.assign({ target: 'desk' }, e)); };
  const now = opts.now || Date.now;
  const iso = () => new Date(now()).toISOString();

  function config() {
    const c = (confCol.get('cfg') || {}).values || {};
    return {
      mode: MODES.includes(c.mode) ? c.mode : 'off',
      technicians: Array.isArray(c.technicians) ? c.technicians : [],
      priority_rules: Array.isArray(c.priority_rules) && c.priority_rules.length ? c.priority_rules : DEF_PRIORITY,
      groups: Array.isArray(c.groups) && c.groups.length ? c.groups : DEF_GROUPS,
      ack_status: c.ack_status || 'In Progress',
      first_response: c.first_response || 'Thank you for contacting IT support. Your ticket has been received and assigned; a technician will update you shortly.',
      max_per_run: c.max_per_run || 25,
      rr_index: c.rr_index || 0,
      patch: Object.assign({ mode: 'off', min_critical: 1, window_start: '20:00', window_end: '06:00', max_per_run: 10, auto_approve: false }, c.patch || {}),
    };
  }
  function meKey(sys) {
    const c = meCfg.get('cfg') || {}; const x = c[sys] || {};
    if (!x.base_url || !x.enc) throw bad((sys === 'ec' ? 'Endpoint Central' : 'ServiceDesk Plus') + ' is not set up in ManageEngine yet', 409);
    return { conn: x, key: sealer.unseal('me-' + (sys === 'ec' ? 'Endpoint Central' : 'ServiceDesk Plus'), x.enc) };
  }
  const sdp = (o) => { const k = meKey('sdp'); return sdpRW(k.conn, k.key, Object.assign({ request: opts.request }, o)); };
  const ec = (o) => { const k = meKey('ec'); return ecClient(k.conn, k.key, Object.assign({ request: opts.request }, o)); };

  // ---- triage derivation (pure) ----
  // admin patterns run against ticket text anyone writes: only patterns that cannot backtrack catastrophically (saferegex)
  function rxList(rules) { return rules.map(([v, re]) => { try { return [v, new RegExp(SR.checkRegex(re), 'i')]; } catch { return [v, null]; /* refused or invalid: the rule is skipped, saving it was refused already */ } }); }
  function derivePriority(text, urgency, impact, rules) {
    text = String(text || '').slice(0, SR.MAX_REGEX_INPUT);
    for (const [p, re] of rxList(rules)) if (re && re.test(text)) return p;
    const u = low(urgency), i = low(impact);
    if (/high|urgent/.test(u) && /high|enterprise|department/.test(i)) return 'Urgent';
    if (/high|urgent/.test(u) || /high|enterprise|department/.test(i)) return 'High';
    return 'Medium';
  }
  function deriveGroup(text, groups) { text = String(text || '').slice(0, SR.MAX_REGEX_INPUT); for (const [g, re] of rxList(groups)) if (re && re.test(text)) return g; return 'Desktop Support'; }
  function pickTech(text, techs, rrIndex) {
    if (!techs.length) return { tech: null, rr: rrIndex };
    const t = low(text);
    for (const tech of techs) { const sk = (tech.skills || []).map(low); if (sk.some((k) => k && t.indexOf(k) >= 0)) return { tech, rr: rrIndex }; }
    const idx = rrIndex % techs.length; return { tech: techs[idx], rr: rrIndex + 1 };
  }
  // one proposed triage for a ServiceDesk request
  function planFor(reqObj, cfg) {
    const subj = s(reqObj.subject, 400), desc = s(String(reqObj.description || '').replace(/<[^>]+>/g, ' '), 2000);
    const text = subj + ' ' + desc;
    const curPr = reqObj.priority && reqObj.priority.name ? s(reqObj.priority.name, 40) : '';
    const curTech = reqObj.technician && (reqObj.technician.name || reqObj.technician.email_id) ? s(reqObj.technician.name || reqObj.technician.email_id, 120) : '';
    const curStatus = reqObj.status && reqObj.status.name ? s(reqObj.status.name, 40) : '';
    const priority = derivePriority(text, reqObj.urgency && reqObj.urgency.name, reqObj.impact && reqObj.impact.name, cfg.priority_rules);
    const group = deriveGroup(text, cfg.groups);
    const picked = pickTech(text, cfg.technicians, cfg.rr_index);
    return { request_id: s(reqObj.id, 20), subject: subj, requester: s(reqObj.requester && reqObj.requester.name, 120),
      current: { priority: curPr, technician: curTech, status: curStatus },
      proposed: { priority, group, technician: picked.tech ? (picked.tech.name || picked.tech.email) : '', technician_email: picked.tech ? picked.tech.email : '', status: curTech ? curStatus : cfg.ack_status },
      rr_next: picked.rr,
      reason: `priority ${priority} (keyword/impact); group ${group}; ${picked.tech ? 'assigned ' + (picked.tech.name || picked.tech.email) : 'no technician configured'}`,
      needs_triage: !curTech || !curPr || curPr === 'Unassigned' };
  }

  async function openRequests() {
    const r = await sdp().call('GET', '/api/v3/requests', { list_info: { row_count: 100, start_index: 1, sort_field: 'created_time', sort_order: 'desc',
      search_criteria: [{ field: 'status.name', condition: 'is', values: ['Open'] }] } });
    return Array.isArray(r.requests) ? r.requests : [];
  }
  async function applyTriage(reqId, patch, who, note) {
    const request = {};
    if (patch.priority) request.priority = { name: patch.priority };
    if (patch.group) request.group = { name: patch.group };
    if (patch.technician_email) request.technician = { email_id: patch.technician_email };
    else if (patch.technician) request.technician = { name: patch.technician };
    if (patch.status) request.status = { name: patch.status };
    if (Object.keys(request).length) await sdp().call('PUT', `/api/v3/requests/${reqId}`, { request });
    if (note) await sdp().call('POST', `/api/v3/requests/${reqId}/notes`, { request_note: { description: s(note, 4000), show_to_requester: true, notify_technician: false } });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'desk.triage.apply', target: reqId, detail: { priority: patch.priority || '', group: patch.group || '', technician: patch.technician || patch.technician_email || '', status: patch.status || '' } });
  }

  async function scan(who = SYS) {
    const cfg = config();
    const out = { at: iso(), mode: cfg.mode, triaged: 0, proposed: 0, failed: [], items: [] };
    if (cfg.mode === 'off') return out;
    let reqs; try { reqs = await openRequests(); } catch (e) { out.error = s(e.message, 300); return out; }
    let rr = cfg.rr_index, n = 0;
    for (const r of reqs) {
      if (n >= cfg.max_per_run) break;
      const plan = planFor(Object.assign({}, r, { }), Object.assign({}, cfg, { rr_index: rr }));
      if (!plan.needs_triage) continue;
      rr = plan.rr_next; n++;
      if (cfg.mode === 'auto') {
        try { await applyTriage(plan.request_id, plan.proposed, who, cfg.first_response + ' (' + plan.reason + ')'); out.triaged++; triageCol.put({ id: plan.request_id, state: 'applied', at: iso(), by: who.user, plan }); out.items.push(Object.assign({ state: 'applied' }, plan)); }
        catch (e) { out.failed.push({ request_id: plan.request_id, error: s(e.message, 200) }); }
      } else { // suggest
        triageCol.put({ id: plan.request_id, state: 'proposed', at: iso(), plan }); out.proposed++; out.items.push(Object.assign({ state: 'proposed' }, plan));
      }
    }
    const c = (confCol.get('cfg') || { id: 'cfg', values: {} }); c.id = 'cfg'; c.values = Object.assign({}, c.values, { rr_index: rr }); confCol.put(c);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'desk.scan', detail: { mode: cfg.mode, triaged: out.triaged, proposed: out.proposed, failed: out.failed.length } });
    return out;
  }
  async function applyProposed(reqId, b, who) {
    const rec = triageCol.get(s(reqId, 20));
    // only a request the desk triaged: otherwise any operator could close or annotate any ServiceDesk ticket as IT
    if (!rec || !rec.plan) throw bad('request ' + s(reqId, 20) + ' has no proposed triage here - change it in ServiceDesk Plus', 404);
    const base = rec.plan.proposed || {};
    const patch = { priority: s(b.priority, 40) || base.priority, group: s(b.group, 80) || base.group,
      technician: s(b.technician, 120) || base.technician, technician_email: s(b.technician_email, 160) || base.technician_email, status: s(b.status, 40) || base.status };
    await applyTriage(s(reqId, 20), patch, who, s(b.note, 4000) || config().first_response);
    triageCol.put({ id: s(reqId, 20), state: 'applied', at: iso(), by: who.user, plan: rec && rec.plan });
    return { request_id: s(reqId, 20), applied: patch };
  }

  // ---- desktop health (from the computers ManageEngine already synced) ----
  function desktops() {
    const cfg = config(), staleMs = 7 * 86400000, rows = ecCol.all((c) => !c.gone_since && !isServerOs(c.os));
    const items = rows.map((c) => {
      const stale = c.last_contact ? (now() - c.last_contact > staleMs) : false;
      const issues = [];
      if (c.live === 'down' || stale) issues.push('agent not reporting');
      if (c.critical != null && c.critical >= cfg.patch.min_critical) issues.push(c.critical + ' critical patch(es) missing');
      if (c.health === 'highly vulnerable') issues.push('highly vulnerable');
      else if (c.health === 'vulnerable' && !(c.critical >= cfg.patch.min_critical)) issues.push('vulnerable');
      return { resource_id: c.resource_id, name: c.name, user: c.user || '', os: c.os || '', ip: c.ip || '', branch: c.branch || '',
        last_contact: c.last_contact || null, live: c.live || 'unknown', health: c.health || null, missing: c.missing != null ? c.missing : null, critical: c.critical != null ? c.critical : null,
        issues, worst: issues.length ? (issues.some((x) => /critical|highly/.test(x)) ? 'high' : 'medium') : 'ok' };
    });
    // every user desktop in the asset register with no Endpoint Central computer joined to it: added, with the gap named
    const joined = new Set(rows.map((c) => c.asset_id).filter(Boolean)), names = new Set(rows.map((c) => low(c.name)).filter(Boolean));
    for (const a of store.collection('assets').all((x) => isDesktopAsset(x) && !joined.has(x.id) && !names.has(low(x.name)) && !names.has(low(x.hostname)))) {
      items.push({ resource_id: null, asset_id: a.id, name: a.name || a.asset_tag || a.id, user: a.custodian || a.owner || '', os: a.os || '', ip: a.mgmt_ip || '', branch: a.site || '',
        last_contact: null, live: 'no agent', health: null, missing: null, critical: null, source: 'asset register', issues: ['no Endpoint Central agent - not patched or monitored by the platform'], worst: 'medium' });
    }
    const order = { high: 0, medium: 1, ok: 2 };
    items.sort((a, b) => order[a.worst] - order[b.worst] || String(a.name).localeCompare(String(b.name)));
    return { items, summary: { total: items.length, offline: items.filter((i) => i.issues.includes('agent not reporting')).length,
      needs_patch: items.filter((i) => i.critical != null && i.critical >= cfg.patch.min_critical).length, vulnerable: items.filter((i) => /vulnerable/.test(i.health || '')).length, healthy: items.filter((i) => i.worst === 'ok').length,
      no_agent: items.filter((i) => i.source === 'asset register').length, from_assets: items.filter((i) => i.source === 'asset register').length } };
  }

  // ---- patch management (device-changing → approval-gated) ----
  function patchProposals() { return patchCol.all().sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 500); }
  function requestPatch(resourceId, who) {
    const rid = s(resourceId, 40); const c = ecCol.get(rid) || ecCol.all((x) => x.resource_id === rid)[0];
    if (!c) throw bad('computer not found', 404);
    const id = 'dp_' + crypto.randomBytes(4).toString('hex');
    const rec = { id, resource_id: rid, name: c.name, critical: c.critical, missing: c.missing, state: 'requested', requested_by: who.user, requested_at: iso(), history: [{ at: iso(), by: who.user, what: 'patch install requested' }] };
    patchCol.put(rec);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'desk.patch.request', target: rid, detail: { critical: c.critical } });
    return rec;
  }
  // a person takes over a request the AI engineer raised; from then on that person is the requester (four-eyes applies)
  function endorsePatch(id, who) {
    const rec = patchCol.get(s(id, 20)); if (!rec) throw bad('patch request not found', 404);
    if (rec.state !== 'requested') throw bad('already ' + rec.state, 409);
    if (!isSystem(rec.requested_by)) throw bad('this request was made by ' + rec.requested_by + ' - nothing to take over', 409);
    rec.raised_by = rec.requested_by; rec.requested_by = who.user; rec.history.push({ at: iso(), by: who.user, what: 'taken over from ' + rec.raised_by + ' - a different administrator must approve' });
    patchCol.put(rec);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'desk.patch.endorse', target: rec.resource_id, detail: { from: rec.raised_by } });
    return rec;
  }
  async function sendInstall(rec, by, what) {
    try {
      await ec({ write: true }).call('POST', '/api/1.4/patch/installpatch', { resource_ids: [rec.resource_id] });
      rec.state = 'deploying'; rec.approved_by = by; rec.approved_at = iso(); rec.history.push({ at: iso(), by, what });
    } catch (e) { rec.state = 'failed'; rec.error = s(e.message, 200); rec.history.push({ at: iso(), by, what: 'failed: ' + rec.error }); }
    patchCol.put(rec);
    return rec;
  }
  // Riyadh time (UTC+3, no DST); a window like 20:00-06:00 runs across midnight
  function inWindow(p, t) {
    const m = Math.floor(((t / 60000) + 180) % 1440), hm = (x) => { const a = String(x || '').split(':'); return (+a[0] || 0) * 60 + (+a[1] || 0); };
    const a = hm(p.window_start), b = hm(p.window_end);
    return a === b ? true : a < b ? m >= a && m < b : m >= a || m < b;
  }
  // Automated patching, armed by an administrator on the Desk Support page (patch mode + auto-approve), never by default:
  //   suggest  a patch request for every computer missing critical patches (an operator takes it over, an admin approves)
  //   auto     the same, and inside the Riyadh maintenance window the requests are approved and sent to Endpoint Central
  //            by the desk - at most max_per_run computers per 12 h, only while the computer still lacks critical patches.
  //            Auto-approval needs patch mode "auto" AND auto_approve: one switch alone does nothing.
  async function autoPatch() {
    const cfg = config(), p = cfg.patch, out = { mode: p.mode, requested: 0, approved: 0, failed: 0, skipped: '' };
    if (p.mode === 'off') { out.skipped = 'patch mode off'; return out; }
    if (!meConfigured().ec) { out.skipped = 'Endpoint Central not configured'; return out; }
    const open = new Set(patchCol.all((x) => x.state === 'requested' || x.state === 'deploying').map((x) => x.resource_id));
    for (const c of ecCol.all()) {
      if (c.critical != null && c.critical >= p.min_critical && !open.has(c.resource_id)) { try { requestPatch(c.resource_id, SYS); out.requested++; open.add(c.resource_id); } catch (e) { /* computer gone */ } }
    }
    if (p.mode !== 'auto' || !p.auto_approve) { out.skipped = p.mode === 'auto' ? 'auto-approve not armed - requests wait for approval' : 'requests wait for approval'; return out; }
    if (!inWindow(p, now())) { out.skipped = 'outside the maintenance window ' + p.window_start + '-' + p.window_end + ' (Riyadh)'; return out; }
    const since = now() - 12 * 3600000;
    let used = patchCol.all((x) => x.auto_approved && Date.parse(x.approved_at || 0) >= since).length;
    for (const rec of patchCol.all((x) => x.state === 'requested').sort((a, b) => (a.requested_at < b.requested_at ? -1 : 1))) {
      if (used >= p.max_per_run) { out.skipped = 'limit of ' + p.max_per_run + ' automatic installs per 12 h reached'; break; }
      const c = ecCol.get(rec.resource_id) || ecCol.all((x) => x.resource_id === rec.resource_id)[0];
      if (!c || !(c.critical >= p.min_critical)) continue;          // patched meanwhile, or gone: nothing to install
      rec.auto_approved = true;
      await sendInstall(rec, 'system:desk-support', 'approved automatically inside the maintenance window (auto-approval armed by ' + (p.armed_by || '?') + ' ' + (p.armed_at || '') + ') - install requested in Endpoint Central');
      audit({ by: 'system:desk-support', role: 'system', ip: '', action: 'desk.patch.auto-approve', target: rec.resource_id, detail: { id: rec.id, state: rec.state, armed_by: p.armed_by || '' } });
      used++; if (rec.state === 'deploying') out.approved++; else out.failed++;
    }
    return out;
  }
  async function approvePatch(id, who) {
    const rec = patchCol.get(s(id, 20)); if (!rec) throw bad('patch request not found', 404);
    if (rec.state !== 'requested') throw bad('already ' + rec.state);
    // raised by the AI engineer (duty:desktop): no person has asked for it yet - an operator takes it over first, so that
    // approving it is always a SECOND person (the approval starts the install at once)
    if (isSystem(rec.requested_by)) throw bad('raised by ' + rec.requested_by + ': an operator must take it over first (Take over), then a different administrator approves', 409);
    if (rec.requested_by && sameUser(rec.requested_by, who.user)) throw bad('four eyes: the approver must be a different person from the requester', 403);
    await sendInstall(rec, who.user, 'approved — install requested in Endpoint Central');
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'desk.patch.approve', target: rec.resource_id, detail: { state: rec.state } });
    return rec;
  }

  // checked on the route too, before the Python writer saves the config (it does not compile the patterns)
  function checkPatterns(b) {
    for (const r of [].concat(Array.isArray(b && b.priority_rules) ? b.priority_rules : [], Array.isArray(b && b.groups) ? b.groups : [])) if (Array.isArray(r) && r[1]) { try { SR.checkRegex(String(r[1])); new RegExp(String(r[1]), 'i'); } catch (e) { throw Object.assign(new Error('pattern "' + String(r[1]).slice(0, 60) + '": ' + e.message), { status: 400 }); } }
  }
  function setConfig(b, who) {
    const cur = config(), v = {};
    v.mode = MODES.includes(low(b.mode)) ? low(b.mode) : cur.mode;
    if (Array.isArray(b.technicians)) v.technicians = b.technicians.slice(0, 200).map((t) => ({ name: s(t.name, 120), email: s(t.email, 160), skills: (Array.isArray(t.skills) ? t.skills : String(t.skills || '').split(',')).map((x) => s(x, 40)).filter(Boolean).slice(0, 20) })).filter((t) => t.name || t.email);
    else v.technicians = cur.technicians;
    checkPatterns(b);
    v.priority_rules = Array.isArray(b.priority_rules) ? b.priority_rules.filter((r) => Array.isArray(r) && PRIORITIES.includes(r[0])).slice(0, 40).map((r) => [r[0], s(r[1], 300)]) : cur.priority_rules;
    v.groups = Array.isArray(b.groups) ? b.groups.filter((r) => Array.isArray(r)).slice(0, 40).map((r) => [s(r[0], 80), s(r[1], 300)]) : cur.groups;
    v.ack_status = s(b.ack_status, 40) || cur.ack_status;
    v.first_response = s(b.first_response, 1000) || cur.first_response;
    if (b.max_per_run != null) { const n = Number(b.max_per_run); if (!Number.isInteger(n) || n < 1 || n > 200) throw bad('max_per_run must be 1-200'); v.max_per_run = n; } else v.max_per_run = cur.max_per_run;
    const p = b.patch && typeof b.patch === 'object' ? b.patch : {};
    v.patch = { mode: ['off', 'suggest', 'auto'].includes(low(p.mode)) ? low(p.mode) : cur.patch.mode,
      min_critical: Number.isInteger(Number(p.min_critical)) && Number(p.min_critical) >= 1 ? Number(p.min_critical) : cur.patch.min_critical,
      window_start: s(p.window_start, 5) || cur.patch.window_start, window_end: s(p.window_end, 5) || cur.patch.window_end,
      max_per_run: Number.isInteger(Number(p.max_per_run)) && Number(p.max_per_run) >= 1 ? Number(p.max_per_run) : cur.patch.max_per_run,
      auto_approve: p.auto_approve === true };
    // who armed automatic installs and when: the auto-approvals name them (the four-eyes decision was made here, once)
    if (v.patch.auto_approve) { v.patch.armed_by = cur.patch.auto_approve && cur.patch.armed_by ? cur.patch.armed_by : who.user; v.patch.armed_at = cur.patch.auto_approve && cur.patch.armed_at ? cur.patch.armed_at : iso(); }
    if (p.window_start !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/.test(v.patch.window_start)) throw bad('window_start must be HH:MM (Riyadh time)');
    if (p.window_end !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/.test(v.patch.window_end)) throw bad('window_end must be HH:MM (Riyadh time)');
    v.rr_index = cur.rr_index;
    confCol.put({ id: 'cfg', values: v });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'desk.config', detail: { mode: v.mode, patch_mode: v.patch.mode, auto_approve: v.patch.auto_approve, technicians: v.technicians.length } });
    return config();
  }

  function meConfigured() { const c = meCfg.get('cfg') || {}; return { sdp: !!(c.sdp && c.sdp.enc), ec: !!(c.ec && c.ec.enc) }; }
  function status() {
    const cfg = config(), me = meConfigured(), d = me.ec ? desktops().summary : null;
    const tr = triageCol.all();
    return { configured: me, mode: cfg.mode, patch_mode: cfg.patch.mode, technicians: cfg.technicians.length,
      proposed: tr.filter((x) => x.state === 'proposed').length, applied: tr.filter((x) => x.state === 'applied').length,
      desktops: d, last_auto_patch: lastAuto, patch_requests: patchCol.all().reduce((m, x) => { m[x.state] = (m[x.state] || 0) + 1; return m; }, {}) };
  }
  function view() {
    const me = meConfigured();
    return { status: status(), config: config(), modes: MODES, priorities: PRIORITIES,
      triage: triageCol.all().filter((x) => x.state === 'proposed').map((x) => x.plan).filter(Boolean),
      // Endpoint Central not connected: the asset register's desktops are still listed (all of them with no agent to report)
      desktops: me.ec ? desktops() : Object.assign(desktops(), { not_connected: true }),
      patch_proposals: patchProposals() };
  }
  let lastAuto = null;
  async function tick() {
    try { if (config().mode !== 'off') await scan(); } catch (e) { /* swallow */ }
    try { lastAuto = Object.assign({ at: iso() }, await autoPatch()); } catch (e) { lastAuto = { at: iso(), error: s(e.message, 200) }; }
  }

  return { view, status, config, setConfig, checkPatterns, scan, autoPatch, inWindow, applyProposed, applyTriage, desktops, requestPatch, approvePatch, endorsePatch, patchProposals, planFor, derivePriority, deriveGroup, pickTech, tick };
}

function registerDeskSupport(srv, app) {
  const D = createDeskSupport(app);
  srv.route('GET', '/me/desk', (ctx) => { ctx.need('operator'); return D.view(); });
  // the store writes decided in Python (pyengine/desk_budget_write.py, migration step 9h), committed by engine/py-writer.js;
  // triage and patch approval call ServiceDesk Plus / Endpoint Central with the sealed credentials and stay here.
  // deskSupport.engine = "node", or a missing Python bridge, keeps Node.js for all of it
  const W = (() => { try { return require('./py-writer').createPyWriter(app, { off: ((app.config && app.config.deskSupport) || {}).engine === 'node' }); } catch (e) { return null; } })();
  const w = (op, spec, who, node) => (W ? W.write(op, Object.assign({ own: ['desk_config', 'desk_patch'], reads: ['me_ec_computers'] }, spec), who, node) : node());
  app.deskWriteStats = () => (W ? W.stats() : null);
  srv.route('POST', '/me/desk/config', (ctx) => { ctx.need('admin'); const b = ctx.body || {}; D.checkPatterns(b); return w('desk.config', { extra: { body: b }, after: () => D.config() }, ctx.who, () => D.setConfig(b, ctx.who)); });
  srv.route('POST', '/me/desk/scan', async (ctx) => { ctx.need('admin'); const r = await D.scan(ctx.who); r.patch = await D.autoPatch(); return r; });
  srv.route('POST', '/me/desk/triage/:id/apply', async (ctx) => { ctx.need('operator'); return D.applyProposed(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/me/desk/patch/:resource/request', (ctx) => { ctx.need('operator'); return w('desk.patch_request', { extra: { id: ctx.params.resource }, newId: () => 'dp_' + crypto.randomBytes(4).toString('hex') }, ctx.who, () => D.requestPatch(ctx.params.resource, ctx.who)); });
  srv.route('POST', '/me/desk/patch/:id/endorse', (ctx) => { ctx.need('operator'); return w('desk.patch_endorse', { extra: { id: ctx.params.id } }, ctx.who, () => D.endorsePatch(ctx.params.id, ctx.who)); });
  srv.route('POST', '/me/desk/patch/:id/approve', async (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:desktop') : ctx.need('admin')); return D.approvePatch(ctx.params.id, ctx.who); });
  const t = setInterval(guardOf(app, 'desksupport.tick', () => D.tick()), 5 * 60000); if (t.unref) t.unref();
  (app.addons = app.addons || {}).deskSupport = D;
  return D;
}

module.exports = { isDesktopAsset, isServerOs, createDeskSupport, registerDeskSupport, sdpRW, DEF_PRIORITY, DEF_GROUPS, MODES };
