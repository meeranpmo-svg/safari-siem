// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { guardOf } = require('./errors');
// ManageEngine Endpoint Central + ServiceDesk Plus (both on-premises), for IT Asset Management.
//
//   Endpoint Central (read)  every interval (default 60 min) the computers and their patch health are read and fed to
//                            Asset Discovery as sightings (method "endpointcentral"); with "add automatically" (default
//                            on) new computers go straight into IT Asset Management. Read with GET only.
//   ServiceDesk Plus (write) tickets (requests) are opened from rules over the inventory and Endpoint Central, and by hand.
//                            Each rule is "open automatically" or "wait for approval"; a hand-made ticket always waits for a
//                            second person. Open tickets are re-read every 10 min so the page shows the desk's status.
//   Endpoint Central actions inventory scan, patch scan, install named patches. ALWAYS approved by an administrator who
//                            is not the person who asked (four eyes), then sent; the result is noted on the linked ticket.
//
//   GET  /me/status                   config (no secrets), counts, last sync / test                       operator
//   POST /me/config                   {ec:{base_url, api_key, ca_file, interval_min, auto_add, site},
//                                      sdp:{base_url, technician_key, ca_file, requester, poll_min},
//                                      rules:{<rule>:{enabled, mode, param, priority, group, category}},
//                                      manual_priority, max_per_run}                                     admin
//   POST /me/test  {system: ec|sdp}   connection test (an untrusted certificate is shown for Trust & pin)  admin
//   POST /me/pin   {system, fingerprint}                                                                  admin
//   POST /me/ec/sync                  read Endpoint Central now                                           admin
//   GET  /me/ec/computers             what Endpoint Central reported (+ asset link)                       operator
//   POST /me/rules/run                evaluate the ticket rules now                                       admin
//   GET  /me/tickets?status=          tickets                                                             operator
//   POST /me/tickets                  {title, description, asset_id?, priority?}  (waits for approval)    operator
//   POST /me/tickets/:id/approve | /reject {reason} | /retry                                             operator
//   GET  /me/actions                  Endpoint Central action requests                                    operator
//   POST /me/actions                  {action, resource_ids[], reason, patch_ids?, ticket_id?}           operator
//   POST /me/actions/:id/approve      four eyes, sends it                                                 admin
//   POST /me/actions/:id/reject       {reason}                                                            operator
//
// The API key and the technician key are sealed (AES-256-GCM, discovery vault key), never returned, logged or audited;
// changing an address or CA file needs the key again. TLS is never switched off (system CAs, a CA file, or a pinned
// certificate). Only the calls listed in EC_READ / EC_WRITE / SDP_CALLS can be made. Every decision is audited
// (me.*) with who and when. Added to an existing install with one registration line (install/add-manageengine.sh).
const crypto = require('node:crypto');
const httpc = require('./discovery/httpc');
const { createSealer } = require('./discovery/vault');

const SYS = { user: 'system:manageengine', role: 'admin', ip: '' };
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').trim().slice(0, max || 200);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const err = (code, msg) => Object.assign(new Error(msg), { code });
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const DAY = 86400000;
const CLOSED_ASSET = { retired: 1, disposed: 1 };
const PRIORITIES = ['Low', 'Medium', 'High', 'Urgent'];

// ---- what each product may be asked --------------------------------------------------------------------------------
const EC_READ = /^\/api\/1\.4\/((som\/computers|inventory\/scancomputers|patch\/allsystems|patch\/allpatches)\?|patch\/systemreport\?resid=\d{1,12}&)page=\d+&pagelimit=\d+$/;
const EC_WRITE = { 'ec-inventory-scan': '/api/1.4/inventory/computers/scan', 'ec-patch-scan': '/api/1.4/patch/computers/scan', 'ec-install-patches': '/api/1.4/patch/installpatch' };
const SDP_CALLS = [['GET', /^\/api\/v3\/requests(\/\d+)?(\?input_data=[^\s]*)?$/], ['POST', /^\/api\/v3\/requests$/], ['POST', /^\/api\/v3\/requests\/\d+\/notes$/]];
const ACTIONS = {
  'ec-inventory-scan': { label: 'Inventory scan', needs_patches: false },
  'ec-patch-scan': { label: 'Patch scan', needs_patches: false },
  'ec-install-patches': { label: 'Install patches', needs_patches: true },
};
const RULES = {
  warranty: { label: 'Warranty ends within (days)', param: 60, priority: 'Medium' },
  eol: { label: 'End-of-life within (days)', param: 90, priority: 'Medium' },
  ec_silent: { label: 'Endpoint Central agent not reporting for (days)', param: 7, priority: 'High' },
  ec_vulnerable: { label: 'Highly vulnerable, or missing critical patches at least', param: 1, priority: 'High' },
};
const REARM_DAYS = 7;            // a closed ticket's condition may open a new ticket after this
const REJECT_HOLD_DAYS = 30;     // a rejected one stays quiet this long

// ---- Endpoint Central client ---------------------------------------------------------------------------------------
function ecClient(conn, key, o = {}) {
  const req = o.request || httpc.request;
  async function call(method, path, body) {
    if (method === 'GET' ? !EC_READ.test(path) : !(method === 'POST' && Object.values(EC_WRITE).includes(path) && o.write)) throw err('config', `Endpoint Central: refusing ${method} ${path}`);
    const r = await req(conn.base_url + path, { method, headers: Object.assign({ Accept: 'application/json', Authorization: key }, body ? { 'Content-Type': 'application/json' } : {}),
      body: body ? JSON.stringify(body) : null, caFile: conn.ca_file || undefined, pin: conn.tls_fingerprint || undefined, captureUntrusted: !!o.capture, timeoutMs: o.timeoutMs || 60000 });
    if (r.status === 401 || r.status === 403) throw err('auth', `Endpoint Central refused the API key (HTTP ${r.status})`);
    if (r.status < 200 || r.status >= 300) throw err('protocol', `Endpoint Central ${path.split('?')[0]}: HTTP ${r.status}`);
    const j = r.json;
    if (!j || typeof j !== 'object') throw err('protocol', `Endpoint Central ${path.split('?')[0]}: the answer is not JSON (is this the Endpoint Central server and port?)`);
    if (String(j.status || '').toLowerCase() === 'error') throw err(/auth|token|key/i.test(String(j.error_description || '')) ? 'auth' : 'protocol', `Endpoint Central: ${s(j.error_description || j.error_code || 'error', 300)}`);
    return j;
  }
  async function pages(kind, max = 50000) {
    const out = [];
    for (let page = 1; out.length < max; page++) {
      const j = await call('GET', `/api/1.4/${kind}${kind.includes('?') ? '&' : '?'}page=${page}&pagelimit=1000`);
      const mr = j.message_response || {};
      const list = mr.computers || mr.scancomputers || mr.allsystems || mr[Object.keys(mr).find((k) => Array.isArray(mr[k]))] || [];
      out.push(...list);
      const total = Number(mr.total || mr.total_count || 0);
      if (list.length < 1000 || (total && out.length >= total)) break;
    }
    return out;
  }
  return { call, pages };
}
const firstIp = (v) => String(v || '').split(/[,;\s]+/).find((x) => IPV4.test(x)) || null;
const allIps = (v) => String(v || '').split(/[,;\s]+/).filter((x) => IPV4.test(x)).slice(0, 8);
const ms = (v) => { const n = Number(v); if (Number.isFinite(n) && n > 1e11) return n; const t = Date.parse(v || ''); return Number.isFinite(t) ? t : null; };
const HEALTH = { 0: 'unknown', 1: 'healthy', 2: 'vulnerable', 3: 'highly vulnerable' };
const SEVERITY = { 0: 'unrated', 1: 'low', 2: 'moderate', 3: 'important', 4: 'critical' };
// one patch from patch/allpatches or patch/systemreport (field names differ between Endpoint Central builds: read defensively)
function ecPatchRow(c) {
  const num = (...k) => { for (const x of k) if (c[x] != null && c[x] !== '' && Number.isFinite(Number(c[x]))) return Number(c[x]); return null; };
  const sevRaw = c.severity != null ? c.severity : c.patch_severity;
  const sev = sevRaw == null ? 'unrated' : SEVERITY[Number(sevRaw)] || s(c.severity_name || sevRaw, 20).toLowerCase();
  return { patch_id: s(c.patch_id || c.patchid, 20), bulletin: s(c.bulletin_id || c.bulletinid, 40), name: s(c.patch_name || c.patch_description || c.description || c.bulletin_id, 200),
    severity: sev, missing: num('missing_count', 'missing_systems', 'missing', 'missingcount'), installed: num('installed_count', 'installed_systems', 'installed'),
    released: ms(c.patch_released_time || c.release_date || c.released_time), reboot: c.reboot_required == null ? null : !!Number(c.reboot_required) || c.reboot_required === true,
    status: s(c.patch_status || c.status || '', 20).toLowerCase() };
}
function ecComputer(c) {
  const live = Number(c.computer_live_status);
  return {
    resource_id: s(c.resource_id || c.resourceid || c.resource_id_string, 40), name: s(c.resource_name || c.computer_name || c.name, 120),
    fqdn: s(c.fqdn_name || c.full_name, 200), ip: firstIp(c.ip_address), ips: allIps(c.ip_address),
    macs: String(c.mac_address || '').split(/[,;\s]+/).filter((m) => /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i.test(m)).slice(0, 8),
    os: s(c.os_name, 120), os_version: s(c.os_version, 60), domain: s(c.domain_netbios_name, 80), agent_version: s(c.agent_version, 40),
    last_contact: ms(c.agent_last_contact_time), live: live === 1 ? 'live' : live === 2 ? 'down' : 'unknown',
    branch: s(c.branch_office_name || c.remote_office_name, 80), user: s(c.agent_logged_on_users || c.owner_name || c.last_logged_on_user, 120),
  };
}
function ecPatch(c) {
  const h = c.health_status != null ? (HEALTH[Number(c.health_status)] || s(c.health_status, 30).toLowerCase()) : null;
  const num = (...k) => { for (const x of k) if (c[x] != null && Number.isFinite(Number(c[x]))) return Number(c[x]); return null; };
  return { resource_id: s(c.resource_id || c.resourceid, 40), health: h, missing: num('missing_patches', 'missing_patch_count', 'missing'), critical: num('critical_missing_patches', 'missing_critical_patches', 'critical_patches_missing', 'critical'), installed: num('installed_patches', 'installed_patch_count') };
}
const serverOs = (os) => /server|linux|ubuntu|red ?hat|rhel|centos|suse|debian|oracle linux|solaris|aix/i.test(os || '');

// ---- ServiceDesk Plus client ---------------------------------------------------------------------------------------
function sdpClient(conn, key, o = {}) {
  const req = o.request || httpc.request;
  async function call(method, path, input) {
    const full = method === 'GET' && input ? `${path}?input_data=${encodeURIComponent(JSON.stringify(input))}` : path;
    if (!SDP_CALLS.some(([m, re]) => m === method && re.test(full))) throw err('config', `ServiceDesk Plus: refusing ${method} ${path}`);
    const r = await req(conn.base_url + full, { method, headers: Object.assign({ Accept: 'application/vnd.manageengine.sdp.v3+json', authtoken: key }, method === 'POST' ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
      body: method === 'POST' ? 'input_data=' + encodeURIComponent(JSON.stringify(input || {})) : null, caFile: conn.ca_file || undefined, pin: conn.tls_fingerprint || undefined, captureUntrusted: !!o.capture, timeoutMs: o.timeoutMs || 30000 });
    const j = r.json, rs = j && j.response_status;
    const st = rs && (Array.isArray(rs) ? rs[0] : rs);
    const msg = st && st.messages && st.messages[0] ? s(st.messages[0].message || st.messages[0].status_code, 300) : '';
    if (r.status === 401 || (st && Number(st.status_code) === 4001 && /auth|key/i.test(msg))) throw err('auth', 'ServiceDesk Plus refused the technician key' + (msg ? ` (${msg})` : ''));
    if (!j || typeof j !== 'object') throw err('protocol', `ServiceDesk Plus ${path}: HTTP ${r.status}, the answer is not JSON (is this the ServiceDesk Plus server and port?)`);
    if (r.status < 200 || r.status >= 300 || (st && String(st.status).toLowerCase() === 'failed')) throw err(r.status === 403 ? 'authz' : 'protocol', `ServiceDesk Plus ${path}: ${msg || 'HTTP ' + r.status}`);
    return j;
  }
  return { call };
}
const htmlText = (t) => s(t, 20000).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])).replace(/\n/g, '<br>');

// ---- the add-on ----------------------------------------------------------------------------------------------------
function createManageEngine(app, opts = {}) {
  const { store } = app;
  const cfgCol = store.collection('me_config'), ecCol = store.collection('me_ec_computers'), patchCol = store.collection('me_ec_patches');
  const tickets = store.collection('me_tickets'), actions = store.collection('me_actions');
  const assets = store.collection('assets'), devs = store.collection('disc_devices');
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-manageengine' });
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  const iso = () => new Date(now()).toISOString();
  const disc = () => app.discovery || null;
  const id = (p) => p + crypto.randomBytes(5).toString('hex');
  let syncing = null, polling = null, lastRules = 0, lastPoll = 0;

  function cfg() {
    const c = cfgCol.get('cfg') || { id: 'cfg' };
    c.ec = c.ec || {}; c.sdp = c.sdp || {}; c.rules = c.rules || {};
    for (const k of Object.keys(RULES)) c.rules[k] = Object.assign({ enabled: false, mode: 'approve', param: RULES[k].param, priority: RULES[k].priority, group: '', category: '' }, c.rules[k]);
    if (!c.max_per_run) c.max_per_run = 20;
    if (!c.manual_priority) c.manual_priority = 'Medium';
    return c;
  }
  function pubSys(x) { const { enc, ...p } = x; return Object.assign(p, { key_set: !!enc }); }
  function status() {
    const c = cfg(), t = tickets.all(), a = actions.all();
    const by = (L) => L.reduce((m, x) => { m[x.status] = (m[x.status] || 0) + 1; return m; }, {});
    return { ec: pubSys(c.ec), sdp: pubSys(c.sdp), rules: c.rules, rule_labels: Object.fromEntries(Object.entries(RULES).map(([k, v]) => [k, v.label])), actions: ACTIONS, priorities: PRIORITIES,
      manual_priority: c.manual_priority, max_per_run: c.max_per_run, tickets: by(t), action_requests: by(a), computers: ecCol.all().length, sites: disc() && disc().sites ? disc().sites() : [] };
  }
  function url(v, label) {
    const u = s(v, 300).replace(/\/+$/, '');
    if (!/^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/.test(u)) throw bad(`${label}: the address must be https://<server>[:port], e.g. https://ec01.${ZYB_ORG.domain}:8383`);
    return u;
  }
  function setSys(cur, b, label, keyField, who) {
    const o = Object.assign({}, cur); let moved = false;
    if ('base_url' in b) { const u = b.base_url ? url(b.base_url, label) : ''; if (u !== (cur.base_url || '')) { moved = !!cur.enc; o.tls_fingerprint = ''; o.presented = null; } o.base_url = u; }
    if ('ca_file' in b) { const f = s(b.ca_file, 250); if (f && !/^\/[A-Za-z0-9._/-]+$/.test(f)) throw bad(`${label}: the CA file must be an absolute path`); if (f !== (cur.ca_file || '')) moved = moved || !!cur.enc; o.ca_file = f; }
    const k = b[keyField] == null ? '' : String(b[keyField]).trim();
    if (k) {
      if (k.length < 8 || k.length > 512 || /\s/.test(k)) throw bad(`${label}: that does not look like a key`);
      if (!sealer.available()) throw bad('credential vault unavailable: ' + sealer.unavailableReason(), 503);
      o.enc = sealer.seal('me-' + label, k); o.key_at = iso(); o.key_by = who.user;
    } else if (moved) throw bad(`${label}: the address or CA file changed - enter the key again`);
    return o;
  }
  function saveConfig(b, who) {
    const c = cfg();
    if (b.ec) {
      c.ec = setSys(c.ec, b.ec, 'Endpoint Central', 'api_key', who);
      if ('interval_min' in b.ec) { const m = Number(b.ec.interval_min); if (!Number.isFinite(m) || m < 15 || m > 1440) throw bad('Endpoint Central: interval must be 15 to 1440 minutes'); c.ec.interval_min = Math.round(m); }
      if ('auto_add' in b.ec) c.ec.auto_add = b.ec.auto_add !== false;
      if ('site' in b.ec) c.ec.site = s(b.ec.site, 80);
    }
    if (b.sdp) {
      c.sdp = setSys(c.sdp, b.sdp, 'ServiceDesk Plus', 'technician_key', who);
      if ('requester' in b.sdp) c.sdp.requester = s(b.sdp.requester, 120);
      if ('poll_min' in b.sdp) { const m = Number(b.sdp.poll_min); if (!Number.isFinite(m) || m < 5 || m > 240) throw bad('ServiceDesk Plus: status check must be 5 to 240 minutes'); c.sdp.poll_min = Math.round(m); }
    }
    if (b.rules && typeof b.rules === 'object') for (const [k, r] of Object.entries(b.rules)) {
      if (!RULES[k] || !r || typeof r !== 'object') continue;
      const x = c.rules[k];
      if ('enabled' in r) x.enabled = r.enabled === true;
      if ('mode' in r) { if (!['auto', 'approve'].includes(r.mode)) throw bad('rule mode must be auto or approve'); x.mode = r.mode; }
      if ('param' in r) { const n = Number(r.param); if (!Number.isFinite(n) || n < 0 || n > 3650) throw bad(`${RULES[k].label}: number out of range`); x.param = Math.round(n); }
      if ('priority' in r) { if (!PRIORITIES.includes(r.priority)) throw bad('priority must be ' + PRIORITIES.join(' / ')); x.priority = r.priority; }
      if ('group' in r) x.group = s(r.group, 100);
      if ('category' in r) x.category = s(r.category, 100);
    }
    if ('manual_priority' in b) { if (!PRIORITIES.includes(b.manual_priority)) throw bad('priority must be ' + PRIORITIES.join(' / ')); c.manual_priority = b.manual_priority; }
    if ('max_per_run' in b) { const n = Number(b.max_per_run); if (!Number.isFinite(n) || n < 1 || n > 200) throw bad('at most 1 to 200 new tickets per run'); c.max_per_run = Math.round(n); }
    c.updated_by = who.user; c.updated_at = iso();
    cfgCol.put(c);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.config', target: 'manageengine', detail: { ec: c.ec.base_url || '', sdp: c.sdp.base_url || '', ec_key_changed: !!(b.ec && b.ec.api_key), sdp_key_changed: !!(b.sdp && b.sdp.technician_key), rules: Object.fromEntries(Object.entries(c.rules).map(([k, v]) => [k, v.enabled ? v.mode : 'off'])) } });
    return status();
  }
  function keyOf(sys) {
    const c = cfg(), x = c[sys];
    if (!x.base_url || !x.enc) throw bad(`${sys === 'ec' ? 'Endpoint Central' : 'ServiceDesk Plus'} is not set up yet`, 409);
    return { conn: x, key: sealer.unseal('me-' + (sys === 'ec' ? 'Endpoint Central' : 'ServiceDesk Plus'), x.enc) };
  }
  const ec = (o) => { const k = keyOf('ec'); return ecClient(k.conn, k.key, Object.assign({ request: opts.request }, o)); };
  const sdp = (o) => { const k = keyOf('sdp'); return sdpClient(k.conn, k.key, Object.assign({ request: opts.request }, o)); };

  // a connection that never got an HTTP answer: say the OS cause and what to change - "connection failed (EAI_AGAIN)" fixes nothing
  function netReason(e, baseUrl) {
    const sys = String(e.sys || ''), host = (() => { try { return new URL(baseUrl).hostname; } catch (x) { return 'the server'; } })(), port = (() => { try { return new URL(baseUrl).port || '443'; } catch (x) { return '443'; } })();
    if (e.code === 'timeout' || sys === 'ETIMEDOUT') return `no answer from ${host}:${port} - a firewall between the platform server and ${host} is dropping it; allow TCP ${port} from the platform server`;
    if (sys === 'ENOTFOUND' || sys === 'EAI_AGAIN') return `${host} does not resolve on the platform server (${sys}${sys === 'EAI_AGAIN' ? ', DNS did not answer' : ', DNS has no such name'}) - on the server check "getent hosts ${host}" and /etc/resolv.conf; fix the DNS server it asks, or add "<IP> ${host}" to /etc/hosts. Keep the name in the address so the certificate still matches`;
    if (sys === 'ECONNREFUSED') return `${host}:${port} refused the connection (ECONNREFUSED) - the service is not listening there: check the address and port (Endpoint Central 8383 / 8443, ServiceDesk Plus 8080 / 443)`;
    if (sys === 'EHOSTUNREACH' || sys === 'ENETUNREACH') return `no route from the platform server to ${host} (${sys}) - check the address and the routing / firewall between them`;
    if (sys === 'ECONNRESET' || sys === 'EPIPE') return `${host} closed the connection (${sys}) - a firewall or proxy may be cutting HTTPS, or the port is not the HTTPS one`;
    return null;
  }
  async function test(sys, who) {
    if (!['ec', 'sdp'].includes(sys)) throw bad('system must be ec or sdp');
    let r;
    try {
      if (sys === 'ec') { const j = await ec({ capture: true }).call('GET', '/api/1.4/som/computers?page=1&pagelimit=1'); const mr = j.message_response || {}; r = { ok: true, message: `connected - ${mr.total != null ? mr.total + ' computers' : 'answering'}` }; }
      else { await sdp({ capture: true }).call('GET', '/api/v3/requests', { list_info: { row_count: 1 } }); r = { ok: true, message: 'connected - the technician key can read requests' }; }
    } catch (e) {
      if (e.status) throw e;
      r = { ok: false, error_class: e.sys || e.code || 'protocol', message: s(netReason(e, (cfg()[sys] || {}).base_url) || e.message, 400), presented: e.presented || null };
    }
    const c = cfg(); c[sys].last_test = { at: iso(), ok: r.ok, message: r.message, error_class: r.error_class || null }; c[sys].presented = r.presented || null; cfgCol.put(c);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.test', target: sys, detail: { ok: r.ok, error_class: r.error_class || null } });
    return { result: r, status: status() };
  }
  function pin(sys, b, who) {
    if (!['ec', 'sdp'].includes(sys)) throw bad('system must be ec or sdp');
    const c = cfg(), x = c[sys];
    const fp = s(b.fingerprint, 120).replace(/:/g, '').toLowerCase(), seen = x.presented && String(x.presented.fingerprint256 || '').replace(/:/g, '').toLowerCase();
    if (!fp || fp !== seen) throw bad('pin only the certificate shown by the last test (run Test again)', 409);
    x.tls_fingerprint = fp; x.presented = null; x.pinned_by = who.user; x.pinned_at = iso(); cfgCol.put(c);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.pin', target: sys, detail: { fingerprint256: fp } });
    return status();
  }

  // ---- Endpoint Central → inventory ----
  function observe(c, site, at) {
    const D = disc(); if (!D || !D.devices) return null;
    const d = D.devices.observe({ method: 'endpointcentral', hostname: (c.name || '').toLowerCase(), fqdn: c.fqdn, ips: c.ips, macs: c.macs, os: [c.os, c.os_version].filter(Boolean).join(' '), uid: `ec:${c.resource_id}`,
      extra: { endpointcentral: { resource_id: c.resource_id, domain: c.domain, agent_version: c.agent_version, last_contact: c.last_contact, live: c.live, user: c.user, branch: c.branch } } }, { site: site || null, scope_id: null, at });
    if (!d) return null;
    const type = serverOs(c.os) ? 'server' : 'workstation', why = `Endpoint Central computer → ${type}`;
    devs.patch(d.id, (x) => { if (!x.asset_id || !x.type || x.type === 'unknown') x.type = type; x.confidence = Math.max(x.confidence || 0, 85); x.reasons = [why].concat((x.reasons || []).filter((r) => r !== why)).slice(0, 12); return x; });
    return devs.get(d.id);
  }
  async function syncEc(who = SYS) {
    if (syncing) return syncing;
    syncing = (async () => {
      const c = cfg(), out = { at: iso(), ok: true, computers: 0, added: 0, add_errors: 0, patch_rows: 0 };
      try {
        const cl = ec();
        let raw;
        try { raw = await cl.pages('som/computers'); } catch (e) { if (e.code === 'auth') throw e; raw = await cl.pages('inventory/scancomputers'); }
        let patch = [];
        try { patch = await cl.pages('patch/allsystems'); } catch (e) { out.patch_error = s(e.message, 200); }
        const P = new Map(patch.map(ecPatch).filter((x) => x.resource_id).map((x) => [x.resource_id, x]));
        out.patch_rows = P.size;
        const seen = new Set();
        for (const r of raw) {
          const x = ecComputer(r); if (!x.resource_id || !x.name) continue;
          seen.add(x.resource_id); out.computers++;
          const p = P.get(x.resource_id) || {};
          const d = observe(x, c.ec.site, out.at);
          let assetId = d && d.asset_id;
          if (d && !assetId && c.ec.auto_add !== false && d.status === 'new') { try { assetId = disc().approve(d.id, SYS).asset_id; out.added++; } catch (e) { out.add_errors++; } }
          ecCol.put(Object.assign(x, { id: x.resource_id, health: p.health || null, missing: p.missing == null ? null : p.missing, critical: p.critical == null ? null : p.critical, installed: p.installed == null ? null : p.installed, asset_id: assetId || null, device_id: d ? d.id : null, seen_at: out.at }));
        }
        for (const r of ecCol.all()) if (!seen.has(r.id)) ecCol.patch(r.id, (x) => { x.gone_since = x.gone_since || out.at; return x; });
        // the patch catalogue (Patch Management): which patches are missing on how many computers - best effort
        try {
          const pl = (await cl.pages('patch/allpatches', 20000)).map(ecPatchRow).filter((x) => x.patch_id);
          for (const x of pl) patchCol.put(Object.assign(x, { id: x.patch_id, seen_at: out.at }));
          for (const r of patchCol.all()) if (r.seen_at !== out.at) patchCol.remove(r.id);
          out.patches = pl.length;
        } catch (e) { out.patches_error = s(e.message, 200); }
      } catch (e) {
        if (e.status) throw e;
        out.ok = false; out.error = s(netReason(e, (cfg().ec || {}).base_url) || e.message, 400); out.error_class = e.sys || e.code || 'protocol';
      }
      const cc = cfg(); cc.ec.last_sync = out; cfgCol.put(cc);
      if (who !== SYS || !out.ok || out.added) audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.ec.sync', target: 'ec', detail: out });
      return out;
    })().finally(() => { syncing = null; });
    return syncing;
  }
  // the patches one computer is missing / has (Patch Management, on demand): GET patch/systemreport for that resource
  async function systemPatches(rid) {
    const id2 = s(rid, 20); if (!/^\d{1,12}$/.test(id2)) throw bad('resource id must be the Endpoint Central computer id');
    if (!ecCol.get(id2)) throw bad('computer not in the Endpoint Central list - sync first', 404);
    return (await ec().pages('patch/systemreport?resid=' + id2, 5000)).map(ecPatchRow).filter((x) => x.patch_id);
  }
  function patches() { return patchCol.all(); }
  function computers() {
    const names = new Map(assets.all().map((a) => [a.id, a.name || a.asset_tag || a.id]));
    return { computers: ecCol.all().map((x) => Object.assign({}, x, { asset_name: x.asset_id ? names.get(x.asset_id) || null : null })).sort((a, b) => (a.name < b.name ? -1 : 1)) };
  }

  // ---- tickets ----
  function hist(t, who, what, extra) { t.history = (t.history || []).concat([Object.assign({ at: iso(), by: who.user, what }, extra || {})]).slice(-50); }
  function pubT(t) { return t; }
  function raise(key, f, mode, who) {
    const open = tickets.all((t) => t.key === key && ['pending', 'sending', 'open', 'failed'].includes(t.status));
    if (open.length) return null;
    const last = tickets.all((t) => t.key === key).sort((a, b) => (a.requested_at < b.requested_at ? 1 : -1))[0];
    if (last && last.status === 'closed' && now() - Date.parse(last.closed_at || last.requested_at) < REARM_DAYS * DAY) return null;
    if (last && last.status === 'rejected' && now() - Date.parse(last.rejected_at || last.requested_at) < REJECT_HOLD_DAYS * DAY) return null;
    const t = Object.assign({ id: id('mt_'), key, status: mode === 'auto' ? 'sending' : 'pending', mode, requested_by: who.user, requested_at: iso() }, f);
    hist(t, who, mode === 'auto' ? 'raised - opens automatically' : 'raised - waits for approval');
    tickets.put(t);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.ticket.raise', target: t.id, detail: { key, rule: t.rule, mode, title: t.title } });
    return t;
  }
  function manual(b, who) {
    const title = s(b.title, 250); if (title.length < 4) throw bad('enter a title');
    const a = b.asset_id ? assets.get(String(b.asset_id)) : null;
    if (b.asset_id && !a) throw bad('asset not found', 404);
    const pr = b.priority ? String(b.priority) : cfg().manual_priority;
    if (!PRIORITIES.includes(pr)) throw bad('priority must be ' + PRIORITIES.join(' / '));
    const t = raise('manual:' + id(''), { rule: 'manual', title, description: s(b.description, 8000), asset_id: a ? a.id : null, asset_name: a ? a.name || a.asset_tag : null, priority: pr, group: '', category: '' }, 'approve', who);
    return { ticket: pubT(t) };
  }
  function describe(t) {
    const L = [t.description || ''];
    if (t.asset_id) { const a = assets.get(t.asset_id); if (a) L.push('', `Asset: ${a.name || a.asset_tag || a.id}${a.mgmt_ip ? ' (' + a.mgmt_ip + ')' : ''}${a.serial ? ', serial ' + a.serial : ''}${a.site ? ', site ' + a.site : ''}`); }
    L.push('', `Opened by IT Asset Management (${t.rule === 'manual' ? 'requested by ' + t.requested_by : 'rule: ' + (RULES[t.rule] ? RULES[t.rule].label.replace(/ \(days\)| at least/g, '') : t.rule)})${t.approved_by ? ', approved by ' + t.approved_by : ''}.`);
    return L.join('\n').trim();
  }
  async function send(tid) {
    const t = tickets.get(tid); if (!t || t.status !== 'sending') return t;
    const c = cfg();
    const input = { request: { subject: t.title, description: htmlText(describe(t)), priority: { name: t.priority || 'Medium' } } };
    if (c.sdp.requester) input.request.requester = /@/.test(c.sdp.requester) ? { email_id: c.sdp.requester } : { name: c.sdp.requester };
    if (t.group) input.request.group = { name: t.group };
    if (t.category) input.request.category = { name: t.category };
    try {
      const j = await sdp().call('POST', '/api/v3/requests', input);
      const rid = j.request && j.request.id;
      if (!rid) throw err('protocol', 'ServiceDesk Plus did not return a request id');
      tickets.patch(tid, (x) => { x.status = 'open'; x.sdp_id = String(rid); x.sdp_url = `${c.sdp.base_url}/WorkOrder.do?woMode=viewWO&woID=${encodeURIComponent(rid)}`; x.sdp_status = (j.request.status && j.request.status.name) || 'Open'; x.sent_at = iso(); x.error = null; hist(x, SYS, `opened in ServiceDesk Plus as #${rid}`); return x; });
    } catch (e) {
      tickets.patch(tid, (x) => { x.status = 'failed'; x.error = s(e.message, 300); hist(x, SYS, 'not opened: ' + x.error); return x; });
    }
    audit({ by: SYS.user, role: SYS.role, action: 'me.ticket.send', target: tid, detail: { ok: tickets.get(tid).status === 'open', sdp_id: tickets.get(tid).sdp_id || null, error: tickets.get(tid).error || null } });
    return tickets.get(tid);
  }
  function mustT(tid) { const t = tickets.get(String(tid)); if (!t) throw bad('ticket not found', 404); return t; }
  async function approveT(tid, who) {
    const t = mustT(tid);
    if (t.status !== 'pending') throw bad(`this ticket is ${t.status}, not waiting for approval`, 409);
    if (t.requested_by === who.user) throw bad('a second person has to approve a ticket you asked for', 403);
    keyOf('sdp');
    tickets.patch(t.id, (x) => { x.status = 'sending'; x.approved_by = who.user; x.approved_at = iso(); hist(x, who, 'approved'); return x; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.ticket.approve', target: t.id, detail: { title: t.title } });
    return { ticket: await send(t.id) };
  }
  function rejectT(tid, b, who) {
    const t = mustT(tid), reason = s(b && b.reason, 500);
    if (t.status !== 'pending' && t.status !== 'failed') throw bad(`this ticket is ${t.status}`, 409);
    if (reason.length < 3) throw bad('give the reason');
    tickets.patch(t.id, (x) => { x.status = 'rejected'; x.rejected_by = who.user; x.rejected_at = iso(); x.reason = reason; hist(x, who, 'rejected: ' + reason); return x; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.ticket.reject', target: t.id, detail: { reason } });
    return { ticket: tickets.get(t.id) };
  }
  async function retryT(tid, who) {
    const t = mustT(tid);
    if (t.status !== 'failed') throw bad('only a ticket that failed to open can be sent again', 409);
    tickets.patch(t.id, (x) => { x.status = 'sending'; hist(x, who, 'sent again'); return x; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.ticket.retry', target: t.id });
    return { ticket: await send(t.id) };
  }
  function listT(q) {
    const st = s(q && q.status, 20);
    return { tickets: tickets.all((t) => !st || st === 'all' || t.status === st).sort((a, b) => (a.requested_at < b.requested_at ? 1 : -1)).slice(0, 1000) };
  }
  async function pollSdp() {
    if (polling) return polling;
    polling = (async () => {
      const open = tickets.all((t) => t.status === 'open' && t.sdp_id), out = { checked: 0, closed: 0, errors: 0 };
      if (!open.length) return out;
      let cl; try { cl = sdp(); } catch (e) { return out; }
      for (const t of open.slice(0, 200)) {
        try {
          const j = await cl.call('GET', `/api/v3/requests/${encodeURIComponent(t.sdp_id)}`);
          const st = j.request && j.request.status ? s(j.request.status.name, 60) : '';
          out.checked++;
          tickets.patch(t.id, (x) => {
            if (st && st !== x.sdp_status) hist(x, SYS, `ServiceDesk Plus status: ${st}`);
            x.sdp_status = st || x.sdp_status; x.sdp_checked_at = iso();
            if (/closed|resolved|cancel/i.test(st)) { x.status = 'closed'; x.closed_at = iso(); out.closed++; }
            return x;
          });
        } catch (e) { out.errors++; }
      }
      return out;
    })().finally(() => { polling = null; });
    return polling;
  }
  async function note(t, text) {
    if (!t || !t.sdp_id) return;
    try { await sdp().call('POST', `/api/v3/requests/${encodeURIComponent(t.sdp_id)}/notes`, { note: { description: htmlText(text), show_to_requester: false } }); } catch (e) { /* the action result is still recorded here */ }
  }

  // ---- rules ----
  function evalRules(who = SYS) {
    const c = cfg(), out = { at: iso(), raised: 0, held_back: 0, by_rule: {} };
    if (!c.sdp.base_url || !c.sdp.enc) { out.skipped = 'ServiceDesk Plus is not set up'; return out; }
    const t = now(), budget = { n: c.max_per_run };
    const add = (rule, key, f) => {
      const r = c.rules[rule];
      if (budget.n <= 0) { if (!tickets.all((x) => x.key === key && ['pending', 'sending', 'open', 'failed'].includes(x.status)).length) out.held_back++; return; }
      const made = raise(key, Object.assign({ rule, priority: r.priority, group: r.group, category: r.category }, f), r.mode, who);
      if (made) { budget.n--; out.raised++; out.by_rule[rule] = (out.by_rule[rule] || 0) + 1; }
    };
    const live = assets.all((a) => !CLOSED_ASSET[a.status]);
    if (c.rules.warranty.enabled) for (const a of live) {
      const end = a.warranty && Date.parse(a.warranty.end); if (!end || a.status !== 'in_use') continue;
      const days = Math.ceil((end - t) / DAY);
      if (days <= c.rules.warranty.param && days >= -30) add('warranty', `warranty:${a.id}:${a.warranty.end}`, { asset_id: a.id, asset_name: a.name || a.asset_tag, title: `Warranty ${days < 0 ? 'ended' : 'ends'} ${days < 0 ? -days + ' days ago' : 'in ' + days + ' days'}: ${a.name || a.asset_tag}`, description: `The warranty of ${a.name || a.asset_tag} ${days < 0 ? 'ended' : 'ends'} on ${String(a.warranty.end).slice(0, 10)}${a.warranty.provider ? ' (' + a.warranty.provider + ')' : ''}. Renew it, or plan the replacement.` });
    }
    if (c.rules.eol.enabled) for (const a of live) {
      const end = a.eol && Date.parse(a.eol); if (!end) continue;
      const days = Math.ceil((end - t) / DAY);
      if (days <= c.rules.eol.param) add('eol', `eol:${a.id}:${a.eol}`, { asset_id: a.id, asset_name: a.name || a.asset_tag, title: `End-of-life ${days < 0 ? 'reached' : 'in ' + days + ' days'}: ${a.name || a.asset_tag}`, description: `${a.name || a.asset_tag}${a.model ? ' (' + a.model + ')' : ''} reaches end-of-life on ${String(a.eol).slice(0, 10)}. Plan the replacement or extended support.` });
    }
    const ecRows = ecCol.all((x) => !x.gone_since);
    if (c.rules.ec_silent.enabled) for (const x of ecRows) {
      if (!x.last_contact) continue;
      const days = Math.floor((t - x.last_contact) / DAY);
      if (days >= c.rules.ec_silent.param) add('ec_silent', `ec_silent:${x.id}`, { asset_id: x.asset_id, asset_name: x.name, ec_resource_id: x.id, title: `Endpoint Central agent silent for ${days} days: ${x.name}`, description: `The Endpoint Central agent on ${x.name}${x.ip ? ' (' + x.ip + ')' : ''} last contacted the server on ${new Date(x.last_contact).toISOString().slice(0, 16).replace('T', ' ')} UTC. Patches and inventory are not reaching it. Check whether the computer is in use, and repair or reinstall the agent.` });
    }
    if (c.rules.ec_vulnerable.enabled) for (const x of ecRows) {
      const crit = x.critical != null && x.critical >= Math.max(1, c.rules.ec_vulnerable.param);
      if (x.health === 'highly vulnerable' || crit) add('ec_vulnerable', `ec_vulnerable:${x.id}`, { asset_id: x.asset_id, asset_name: x.name, ec_resource_id: x.id, title: `Missing patches on ${x.name}${x.critical != null ? ': ' + x.critical + ' critical' : ''}`, description: `Endpoint Central reports ${x.name}${x.ip ? ' (' + x.ip + ')' : ''} as ${x.health || 'missing critical patches'}${x.missing != null ? ', ' + x.missing + ' missing patches' : ''}${x.critical != null ? ' (' + x.critical + ' critical)' : ''}. Deploy the missing patches.` });
    }
    lastRules = t;
    if (out.raised || who !== SYS) audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.rules.run', target: 'rules', detail: out });
    return out;
  }
  async function flush() { for (const t of tickets.all((x) => x.status === 'sending')) await send(t.id); }

  // ---- Endpoint Central actions (four eyes) ----
  function mustA(aid) { const a = actions.get(String(aid)); if (!a) throw bad('action request not found', 404); return a; }
  function requestA(b, who) {
    const def = ACTIONS[b && b.action]; if (!def) throw bad('action must be ' + Object.keys(ACTIONS).join(' / '));
    const ids = [...new Set((Array.isArray(b.resource_ids) ? b.resource_ids : []).map((x) => s(x, 40)).filter(Boolean))];
    if (!ids.length || ids.length > 200) throw bad('choose 1 to 200 computers');
    const rows = ids.map((x) => ecCol.get(x));
    if (rows.some((r) => !r)) throw bad('a computer is not in the Endpoint Central list - sync first', 404);
    const reason = s(b.reason, 500); if (reason.length < 3) throw bad('give the reason');
    let patchIds = null;
    if (def.needs_patches) {
      patchIds = [...new Set((Array.isArray(b.patch_ids) ? b.patch_ids : String(b.patch_ids || '').split(/[\s,;]+/)).map((x) => String(x).trim()).filter((x) => /^\d{1,12}$/.test(x)))];
      if (!patchIds.length || patchIds.length > 100) throw bad('enter 1 to 100 Endpoint Central patch IDs (numbers, from Patch Mgmt → Missing Patches)');
    }
    const t = b.ticket_id ? tickets.get(String(b.ticket_id)) : null;
    if (b.ticket_id && !t) throw bad('ticket not found', 404);
    const a = { id: id('ma_'), action: b.action, label: def.label, resource_ids: ids, names: rows.map((r) => r.name), patch_ids: patchIds, reason, ticket_id: t ? t.id : null, status: 'pending', requested_by: who.user, requested_at: iso() };
    hist(a, who, 'requested: ' + reason);
    actions.put(a);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.action.request', target: a.id, detail: { action: a.action, computers: a.names, patch_ids: patchIds, reason } });
    return { action: a };
  }
  async function approveA(aid, who) {
    const a = mustA(aid);
    if (a.status !== 'pending') throw bad(`this request is ${a.status}`, 409);
    if (a.requested_by && String(a.requested_by || '').trim().toLowerCase() === String(who.user || '').trim().toLowerCase()) throw bad('four eyes: an administrator other than the person who asked has to approve it', 403);
    const cl = ec({ write: true });
    actions.patch(a.id, (x) => { x.status = 'running'; x.approved_by = who.user; x.approved_at = iso(); hist(x, who, 'approved'); return x; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.action.approve', target: a.id, detail: { action: a.action, computers: a.names } });
    const ids = a.resource_ids.map((x) => (/^\d+$/.test(x) ? Number(x) : x));
    const body = a.action === 'ec-install-patches' ? { PatchIDs: a.patch_ids.map(Number), ResourceIDs: ids, actionToPerform: 'Deploy' } : { resourceids: ids };
    let ok = true, result = '';
    try { const j = await cl.call('POST', EC_WRITE[a.action], body); result = s(JSON.stringify(j.message_response || j.status || 'accepted'), 500); } catch (e) { ok = false; result = s(e.message, 300); }
    actions.patch(a.id, (x) => { x.status = ok ? 'done' : 'failed'; x.result = result; x.done_at = iso(); hist(x, SYS, (ok ? 'sent to Endpoint Central: ' : 'failed: ') + result); return x; });
    audit({ by: SYS.user, role: SYS.role, action: 'me.action.result', target: a.id, detail: { ok, result } });
    await note(a.ticket_id && tickets.get(a.ticket_id), `Endpoint Central action "${a.label}" on ${a.names.join(', ')}${a.patch_ids ? ' (patches ' + a.patch_ids.join(', ') + ')' : ''}: requested by ${a.requested_by} (${a.reason}), approved by ${who.user} - ${ok ? 'sent' : 'FAILED: ' + result}.`);
    return { action: actions.get(a.id) };
  }
  function rejectA(aid, b, who) {
    const a = mustA(aid), reason = s(b && b.reason, 500);
    if (a.status !== 'pending') throw bad(`this request is ${a.status}`, 409);
    if (reason.length < 3) throw bad('give the reason');
    actions.patch(a.id, (x) => { x.status = 'rejected'; x.rejected_by = who.user; x.rejected_at = iso(); x.reject_reason = reason; hist(x, who, 'rejected: ' + reason); return x; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'me.action.reject', target: a.id, detail: { reason } });
    return { action: actions.get(a.id) };
  }
  function listA() { return { actions: actions.all().sort((a, b) => (a.requested_at < b.requested_at ? 1 : -1)).slice(0, 500), kinds: ACTIONS }; }

  // ---- schedule: Endpoint Central every interval, then the rules; open tickets re-read every poll_min ----
  async function tick() {
    const c = cfg(), t = now();
    try {
      if (c.ec.base_url && c.ec.enc && !syncing) {
        const last = c.ec.last_sync ? Date.parse(c.ec.last_sync.at) : 0;
        if (t - last >= (c.ec.interval_min || 60) * 60000) await syncEc();
      }
      if (t - lastRules >= 30 * 60000) evalRules();
      await flush();
      if (c.sdp.base_url && c.sdp.enc && t - lastPoll >= (c.sdp.poll_min || 10) * 60000) { lastPoll = t; await pollSdp(); }
    } catch (e) { /* the next tick tries again; errors are on the status */ }
  }
  return { status, saveConfig, test, pin, syncEc, computers, patches, systemPatches, manual, approveT, rejectT, retryT, listT, pollSdp, evalRules, flush, requestA, approveA, rejectA, listA, tick, RULES, ACTIONS };
}

function registerManageEngine(srv, app) {
  const M = createManageEngine(app);
  (app.addons = app.addons || {}).manageengine = M;
  // `you`: the role the portal sent with THIS request - the page trusts it over /dashboards/whoami.json, which on some
  // installs carries no role and left an administrator looking at a read-only Settings tab
  srv.route('GET', '/me/status', (ctx) => { ctx.need('operator'); return Object.assign({}, M.status(), { you: { user: ctx.who.user, role: ctx.who.role } }); });
  srv.route('POST', '/me/config', (ctx) => { ctx.need('admin'); return M.saveConfig(ctx.body || {}, ctx.who); });
  srv.route('POST', '/me/test', async (ctx) => { ctx.need('admin'); return M.test((ctx.body || {}).system, ctx.who); });
  srv.route('POST', '/me/pin', (ctx) => { ctx.need('admin'); return M.pin((ctx.body || {}).system, ctx.body || {}, ctx.who); });
  srv.route('POST', '/me/ec/sync', async (ctx) => { ctx.need('admin'); const r = await M.syncEc(ctx.who); M.evalRules(); await M.flush(); return { sync: r }; });
  srv.route('GET', '/me/ec/computers', (ctx) => { ctx.need('operator'); return M.computers(); });
  srv.route('POST', '/me/rules/run', async (ctx) => { ctx.need('admin'); const r = M.evalRules(ctx.who); await M.flush(); return { rules: r }; });
  srv.route('GET', '/me/tickets', (ctx) => { ctx.need('operator'); return M.listT(ctx.query); });
  srv.route('POST', '/me/tickets', (ctx) => { ctx.need('operator'); return M.manual(ctx.body || {}, ctx.who); });
  srv.route('POST', '/me/tickets/:id/approve', async (ctx) => { ctx.need('operator'); return M.approveT(ctx.params.id, ctx.who); });
  srv.route('POST', '/me/tickets/:id/reject', (ctx) => { ctx.need('operator'); return M.rejectT(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/me/tickets/:id/retry', async (ctx) => { ctx.need('operator'); return M.retryT(ctx.params.id, ctx.who); });
  srv.route('GET', '/me/actions', (ctx) => { ctx.need('operator'); return M.listA(); });
  srv.route('POST', '/me/actions', (ctx) => { ctx.need('operator'); return M.requestA(ctx.body || {}, ctx.who); });
  srv.route('POST', '/me/actions/:id/approve', async (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:desktop') : ctx.need('admin')); return M.approveA(ctx.params.id, ctx.who); });
  srv.route('POST', '/me/actions/:id/reject', (ctx) => { ctx.need('operator'); return M.rejectA(ctx.params.id, ctx.body || {}, ctx.who); });
  const t1 = setTimeout(guardOf(app, 'manageengine.tick', M.tick), 120000), t2 = setInterval(guardOf(app, 'manageengine.tick', M.tick), 60000);
  if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  return M;
}

module.exports = { createManageEngine, registerManageEngine, ecComputer, ecPatch, ecPatchRow, ecClient, sdpClient, RULES, ACTIONS };
