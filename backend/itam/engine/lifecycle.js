// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// End of life / end of support for server and PC operating systems and for switch, router and firewall firmware, found
// from what discovery and the inventory already know (OS name + build, SNMP sysDescr, firmware version) - plus
// isolation of such a device with a second-person (CISO) approval.
//   GET  /lifecycle                       {summary, items[], requests[], isolation{method, approvers}}       operator
//        ?all=1 also lists supported / unknown items
//   POST /lifecycle/isolate               {key, reason}  request isolation of an end-of-life device              admin
//   POST /lifecycle/requests/:id/decide   {decision: approved|rejected, comment}                                approver
//        approver = a user named in discovery.isolation.approvers (the CISO), else any other admin; never the requester
//   POST /lifecycle/requests/:id/applied  {comment}   manual method: the network team confirms it is isolated     admin
//   POST /lifecycle/requests/:id/release  {reason}    lift the isolation                                         admin
//   PUT  /lifecycle/settings              {approvers: ["ciso", …]}  who approves isolation (empty = any other admin)  admin
//   POST /lifecycle/exceptions            {key, reason, compensating, owner, expires}  risk exception for a device that
//                                         cannot be isolated / upgraded yet (max 365 days)                            operator
//   POST /lifecycle/exceptions/:id/decide {decision, comment}  same approvers as isolation, never the requester         approver
//   POST /lifecycle/exceptions/:id/revoke {reason}                                                                    admin
//   An approved, unexpired exception replaces "isolation required" with "exception until <date>"; when it expires the
//   device is required again - nothing is renewed silently.
// Isolation method (config.json discovery.isolation):
//   fortigate: {base_url: "https://<fortigate>", token_file: "/etc/sentra-itam/fortigate-isolation.token", ca_file?, expiry_s?}
//     → FortiGate quarantine (monitor API user/banned add_users / clear_users): the address can no longer pass the firewall
//       (internet, other VLANs, other sites). The API token needs an admin profile allowed to quarantine (User & Device: write).
//   otherwise "manual": the approved request shows the exact FortiGate / switch commands and waits for "applied".
// Lifecycle rules: built-in table below (vendor lifecycle pages), extended / overridden by discovery.lifecycle.rules
// [{pattern: "regex", product: "...", eol: "YYYY-MM-DD" | null}]  (null = end of life already passed, date not recorded).
// Self-contained (stored collections), added to an existing install with one registration line (install/add-lifecycle.sh).
const fs = require('node:fs');
const https = require('node:https');
const crypto = require('node:crypto');

const DAY = 86400000, SOON_DAYS = 180;
const CLOSED = { retired: 1, disposed: 1 };
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max || 500);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });

// Windows 11 feature updates: build → [Home/Pro end, Enterprise/Education end]
const WIN11 = { 22000: ['21H2', '2023-10-10', '2024-10-08'], 22621: ['22H2', '2024-10-08', '2025-10-14'], 22631: ['23H2', '2025-11-11', '2026-11-10'], 26100: ['24H2', '2026-10-13', '2027-10-12'], 26200: ['25H2', '2027-10-12', '2028-10-10'] };
const WIN10_LTSC = { 14393: ['LTSB 2016', '2026-10-13'], 17763: ['LTSC 2019', '2029-01-09'], 19044: ['LTSC 2021', '2027-01-12'] };
// [regex, product, eol]  - first match wins; eol null = passed (date not recorded here)
const RULES = [
  [/windows\s*server\s*2003/i, 'Windows Server 2003', '2015-07-14'],
  [/windows\s*server\s*2008/i, 'Windows Server 2008 / 2008 R2', '2020-01-14'],
  [/windows\s*server\s*2012/i, 'Windows Server 2012 / 2012 R2', '2023-10-10'],
  [/windows\s*server\s*2016/i, 'Windows Server 2016', '2027-01-12'],
  [/windows\s*server\s*2019/i, 'Windows Server 2019', '2029-01-09'],
  [/windows\s*server\s*2022/i, 'Windows Server 2022', '2031-10-14'],
  [/windows\s*server\s*2025/i, 'Windows Server 2025', '2034-10-10'],
  [/windows\s*xp/i, 'Windows XP', '2014-04-08'],
  [/windows\s*vista/i, 'Windows Vista', '2017-04-11'],
  [/windows\s*7\b/i, 'Windows 7', '2020-01-14'],
  [/windows\s*8(\.1)?\b/i, 'Windows 8.1', '2023-01-10'],
  [/centos( linux)?\s*(release\s*)?6\b/i, 'CentOS 6', '2020-11-30'],
  [/centos( linux)?\s*(release\s*)?7\b/i, 'CentOS 7', '2024-06-30'],
  [/centos\s*stream\s*8/i, 'CentOS Stream 8', '2024-05-31'],
  [/centos( linux)?\s*(release\s*)?8\b/i, 'CentOS Linux 8', '2021-12-31'],
  [/(red\s*hat|rhel)[^0-9]{0,30}\b6(\.\d+)?\b/i, 'Red Hat Enterprise Linux 6', '2020-11-30'],
  [/(red\s*hat|rhel)[^0-9]{0,30}\b7(\.\d+)?\b/i, 'Red Hat Enterprise Linux 7', '2024-06-30'],
  [/(red\s*hat|rhel)[^0-9]{0,30}\b8(\.\d+)?\b/i, 'Red Hat Enterprise Linux 8', '2029-05-31'],
  [/ubuntu\s*14\.04/i, 'Ubuntu 14.04 LTS', '2019-04-30'],
  [/ubuntu\s*16\.04/i, 'Ubuntu 16.04 LTS', '2021-04-30'],
  [/ubuntu\s*18\.04/i, 'Ubuntu 18.04 LTS', '2023-05-31'],
  [/ubuntu\s*20\.04/i, 'Ubuntu 20.04 LTS', '2025-05-31'],
  [/debian[^0-9]{0,20}\b8\b/i, 'Debian 8', '2020-06-30'],
  [/debian[^0-9]{0,20}\b9\b/i, 'Debian 9', '2022-06-30'],
  [/debian[^0-9]{0,20}\b10\b/i, 'Debian 10', '2024-06-30'],
  [/debian[^0-9]{0,20}\b11\b/i, 'Debian 11', '2026-08-31'],
  // Oracle Solaris (Oracle Lifetime Support Policy: Solaris 11.4 Extended Support to Nov 2034; 11.3 and older are past support)
  [/solaris\s*11\.4|sunos[^\n]{0,30}5\.11[^\n]{0,20}11\.4/i, 'Oracle Solaris 11.4', '2034-11-30'],
  [/solaris\s*11(\.[0-3])?\b|sunos[^\n]{0,30}5\.11\b/i, 'Oracle Solaris 11.0 - 11.3', null],
  [/solaris\s*([2-9]|10)\b|sunos[^\n]{0,30}5\.([5-9]|10)\b/i, 'Oracle Solaris 10 or older', null],
  [/esxi?\s*(server\s*)?5\.\d/i, 'VMware ESXi 5.x', null],
  [/esxi?\s*(server\s*)?6\.0/i, 'VMware ESXi 6.0', '2020-03-12'],
  [/esxi?\s*(server\s*)?6\.[57]/i, 'VMware ESXi 6.5 / 6.7', '2022-10-15'],
  [/esxi?\s*(server\s*)?7\.0/i, 'VMware ESXi 7.0', '2025-10-02'],
  [/fortios\s*v?5\.|fortigate[^\n]{0,40}\bv5\.\d/i, 'FortiOS 5.x', null],
  [/fortios\s*v?6\.0\b|fortigate[^\n]{0,40}\bv6\.0\./i, 'FortiOS 6.0', null],
  [/fortios\s*v?6\.2\b|fortigate[^\n]{0,40}\bv6\.2\./i, 'FortiOS 6.2', '2024-09-28'],
  [/fortios\s*v?6\.4\b|fortigate[^\n]{0,40}\bv6\.4\./i, 'FortiOS 6.4', '2025-09-30'],
  [/cisco ios software[^\n]{0,80}version 12\./i, 'Cisco IOS 12.x', null],
  [/cisco ios software[^\n]{0,80}version 15\.[01]\b/i, 'Cisco IOS 15.0 / 15.1', null],
  [/ios-xe[^\n]{0,40}\b3\.\d+\./i, 'Cisco IOS XE 3.x', null],
  [/pan-?os\s*[5-8]\.|pan-?os\s*9\.0/i, 'PAN-OS 9.0 or older', null],
  [/pan-?os\s*9\.1|pan-?os\s*10\.0/i, 'PAN-OS 9.1 / 10.0', null],
];

function compile(extra) {
  const out = [];
  for (const r of Array.isArray(extra) ? extra : []) { try { if (r && r.pattern) out.push([new RegExp(require('./saferegex').checkRegex(String(r.pattern)), 'i'), s(r.product, 120) || String(r.pattern), r.eol ? String(r.eol).slice(0, 10) : null]); } catch { /* invalid regex: skipped */ } }
  return out.concat(RULES);
}

/* text = OS name + version / sysDescr; returns {product, eol, status: eol|soon|supported|unknown, days} */
function evaluate(text, rules, now = Date.now()) {
  const t = s(text, 2000); if (!t) return { status: 'unknown', product: '', eol: null, days: null };
  const res = (product, eol, note) => {
    if (eol === null) return { product, eol: null, status: 'eol', days: null, note: note || 'vendor end of support has passed' };
    const days = Math.round((Date.parse(eol + 'T00:00:00Z') - now) / DAY);
    return { product, eol, days, status: days < 0 ? 'eol' : days <= SOON_DAYS ? 'soon' : 'supported', note: note || '' };
  };
  const build = (/\b10\.0[.\s(]+(\d{5})\b/.exec(t) || /\bbuild\s*(\d{5})\b/i.exec(t) || /\((\d{5})\)/.exec(t) || [])[1];
  if (/windows\s*11/i.test(t) && build && WIN11[build]) { const w = WIN11[build], ent = /enterprise|education/i.test(t); return res(`Windows 11 ${w[0]} (${ent ? 'Enterprise / Education' : 'Home / Pro'})`, ent ? w[2] : w[1]); }
  if (/windows\s*10/i.test(t) && !/server/i.test(t)) {
    if (/ltsc|ltsb/i.test(t) && build && WIN10_LTSC[build]) return res(`Windows 10 Enterprise ${WIN10_LTSC[build][0]}`, WIN10_LTSC[build][1]);
    return res('Windows 10', '2025-10-14', 'paid Extended Security Updates (ESU) may still cover it');
  }
  for (const [re, product, eol] of rules) if (re.test(t)) return res(product, eol);
  return { status: 'unknown', product: '', eol: null, days: null };
}

function createLifecycle(app, opts = {}) {
  const { store } = app;
  const cfg = (app.config && app.config.discovery) || {};
  const iso = cfg.isolation || {};
  const rules = compile((cfg.lifecycle || {}).rules);
  const now = opts.now || Date.now;
  const audit = (e) => { if (app.audit) app.audit(e); };
  const reqs = store.collection('isolation_requests');
  const exc = store.collection('lifecycle_exceptions');
  const sets = store.collection('lifecycle_settings');
  // approvers: set on the End of Life page (stored), else discovery.isolation.approvers in config.json
  const approversOf = () => { const d = sets.get('isolation'); const a = d && Array.isArray(d.approvers) ? d.approvers : (Array.isArray(iso.approvers) ? iso.approvers : []); return a.map((u) => String(u).toLowerCase()).filter(Boolean); };
  const fg = iso.fortigate && iso.fortigate.base_url && iso.fortigate.token_file ? iso.fortigate : null;

  function textOf(x) { return [x.os, x.os_version, x.firmware, x.sys_descr, x.model].filter(Boolean).join(' · '); }
  const ser = (v) => s(v, 80).toUpperCase();
  // every device the platform knows: the inventory, Asset Discovery (not yet approved), the virtualization hosts read from
  // vCenter / Prism and the storage arrays (NetApp / HPE MSA) - each with its serial number where the source reports one.
  // A device already in the inventory (same serial) is listed once, from the inventory.
  function items(all) {
    const out = [], seen = new Set();
    const add = (o, text) => {
      const e = evaluate(text, rules, now()); if (!all && (e.status === 'supported' || e.status === 'unknown')) return;
      if (o.serial) { if (seen.has(o.serial)) return; seen.add(o.serial); }
      out.push(Object.assign(o, { os: text }, e));
    };
    for (const a of store.collection('assets').all((x) => !CLOSED[x.status])) add({ key: 'asset:' + a.id, source: 'inventory', id: a.id, name: a.name || a.asset_tag || a.mgmt_ip || a.id, type: a.type || '', ip: a.mgmt_ip || '', mac: a.mac || '', site: a.site || '', serial: ser(a.serial), vendor: s(a.vendor, 80), model: s(a.model, 120), asset_tag: s(a.asset_tag, 60) }, textOf(a));
    for (const d of store.collection('disc_devices').all((x) => x.status !== 'ignored' && !x.asset_id)) add({ key: 'disc:' + d.id, source: 'discovery', id: d.id, name: d.hostname || d.ip || d.id, type: d.type || '', ip: d.ip || '', mac: d.mac || (d.macs || [])[0] || '', site: d.site || '', serial: ser(d.serial || (d.extra && d.extra.serial)), vendor: s(d.vendor, 80), model: s(d.model, 120), decision: d.status }, textOf(d));
    for (const m of store.collection('virt_capacity').all()) for (const h of m.hosts || []) add({ key: 'virt:' + m.id + ':' + h.id, source: 'virtualization', id: h.id, name: h.name || h.id, type: 'hypervisor', ip: h.ip || '', mac: '', site: m.site || '', serial: ser(h.serial), vendor: s(h.vendor, 80), model: s(h.model, 120), platform: m.label || '' }, [h.version, h.model].filter(Boolean).join(' · '));
    for (const sn of store.collection('storage_snapshots').all()) {
      const y = sn.system || {}; if (!y.name && !y.serial) continue;
      add({ key: 'storage:' + sn.id, source: 'storage', id: sn.id, name: y.name || sn.id, type: 'storage', ip: '', mac: '', site: '', serial: ser(y.serial), vendor: '', model: s(y.model, 120) }, [y.model, y.version].filter(Boolean).join(' · '));
      for (const c of sn.controllers || []) if (c.serial) add({ key: 'storage:' + sn.id + ':' + c.name, source: 'storage', id: sn.id, name: (y.name || sn.id) + ' / ' + (c.name || 'controller'), type: 'storage', ip: '', mac: '', site: '', serial: ser(c.serial), vendor: '', model: s(c.model, 120) }, [c.model, y.version].filter(Boolean).join(' · '));
    }
    const open = {}; for (const r of reqs.all((r) => r.state !== 'released' && r.state !== 'rejected')) open[r.key] = { id: r.id, state: r.state };
    const today = new Date(now()).toISOString().slice(0, 10), ex = {};
    for (const x of exc.all((x) => x.state === 'pending' || x.state === 'approved')) { const st = x.state === 'approved' && x.expires < today ? 'expired' : x.state; if (st !== 'expired' || !ex[x.key]) ex[x.key] = { id: x.id, state: st, expires: x.expires, owner: x.owner }; }
    out.forEach((i) => {
      if (open[i.key]) i.isolation = open[i.key];
      if (ex[i.key]) i.exception = ex[i.key];
      // isolation required: out of vendor support and not isolated yet. A hypervisor or a storage array is not isolated
      // from the network (everything on it would stop) - it needs an upgrade / replacement plan instead.
      const infra = i.type === 'hypervisor' || i.type === 'storage' || /esxi|nutanix|\bahv\b/i.test((i.product || '') + ' ' + (i.os || ''));
      const excOk = i.exception && i.exception.state === 'approved';
      i.isolation_required = i.status === 'eol' && !infra && !excOk && !(i.isolation && i.isolation.state === 'isolated');
      if (i.status === 'eol' && excOk) i.action = 'risk exception until ' + i.exception.expires + (i.exception.owner ? ' (owner ' + i.exception.owner + ')' : '') + ' - then isolate, upgrade or renew';
      else if (i.status === 'eol' && infra) i.action = 'upgrade or replace (cannot be isolated without stopping its workloads)';
      else if (i.isolation_required) i.action = i.isolation ? 'isolation ' + i.isolation.state : (i.ip || i.mac ? 'isolate until upgraded or replaced' : 'isolate - no IP / MAC known, find it on the network first');
      else if (i.status === 'eol') i.action = 'isolated - plan the upgrade / replacement';
      else if (i.status === 'soon') i.action = 'plan the upgrade before ' + (i.eol || 'end of support');
    });
    return out.sort((x, y) => (x.status === y.status ? (x.eol || '') < (y.eol || '') ? -1 : 1 : x.status === 'eol' ? -1 : 1));
  }
  function view(q) {
    const list = items(q && (q.all === '1' || q.all === true));
    const by = (st) => list.filter((i) => i.status === st).length;
    return { summary: { exceptions: list.filter((i) => i.exception && i.exception.state === 'approved').length, exceptions_pending: exc.all((x) => x.state === 'pending').length, isolation_required: list.filter((i) => i.isolation_required).length, without_serial: list.filter((i) => (i.status === 'eol' || i.status === 'soon') && !i.serial).length, eol: by('eol'), soon: by('soon'), servers: list.filter((i) => i.status === 'eol' && /server|vm/.test(i.type)).length, network: list.filter((i) => i.status === 'eol' && /network|switch|router|firewall/.test(i.type)).length, isolated: reqs.all((r) => r.state === 'isolated').length, pending: reqs.all((r) => r.state === 'pending').length },
      exceptions: exc.all().map((x) => Object.assign({}, x, { state: x.state === 'approved' && x.expires < new Date(now()).toISOString().slice(0, 10) ? 'expired' : x.state })).sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).slice(0, 300),
      items: list, requests: reqs.all().sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).slice(0, 200),
      isolation: { method: fg ? 'fortigate' : 'manual', approvers: approversOf().length ? approversOf() : ['any other administrator'], soon_days: SOON_DAYS } };
  }

  function fortigate(path, body) {
    if (opts.fortigate) return opts.fortigate(path, body);
    return new Promise((ok, fail) => {
      let token; try { token = String(fs.readFileSync(fg.token_file, 'utf8')).trim(); } catch (e) { fail(new Error(`FortiGate token file not readable (${e.code || 'error'})`)); return; }
      const u = new URL(String(fg.base_url).replace(/\/+$/, '') + path), data = JSON.stringify(body);
      const o = { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }, timeout: 20000 };
      if (fg.ca_file) { try { o.ca = fs.readFileSync(fg.ca_file); } catch (e) { fail(new Error('FortiGate CA file not readable')); return; } }
      const r = https.request(u, o, (res) => { let t = ''; res.on('data', (c) => { t += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(t); } catch { j = null; } if (res.statusCode >= 200 && res.statusCode < 300 && (!j || j.status !== 'error')) ok(j); else fail(new Error(`FortiGate HTTP ${res.statusCode}${j && j.error ? ' error ' + j.error : ''}`)); }); });
      r.on('timeout', () => r.destroy(new Error('FortiGate timeout'))); r.on('error', fail); r.end(data);
    });
  }
  function manualSteps(r) {
    return [`FortiGate CLI: diagnose user banned-ip add src4 ${r.ip || '<ip>'} 0 admin   (0 = until released)`,
      r.mac ? `or switch port: find MAC ${r.mac} (show mac address-table address ${r.mac}) and shut the port / move it to the quarantine VLAN` : 'or switch port: shut the port / move it to the quarantine VLAN',
      'then press "Mark as isolated"'];
  }

  function isolate(body, who) {
    const key = s(body && body.key, 100), reason = s(body && body.reason, 500);
    if (!reason) throw bad('a reason is required');
    const it = items(true).filter((i) => i.key === key)[0];
    if (!it) throw bad('device not found', 404);
    if (it.isolation) throw bad(`an isolation request is already ${it.isolation.state} for this device`, 409);
    if (!it.ip && !it.mac) throw bad('the device has no IP or MAC address to isolate', 409);
    const r = { id: 'iso_' + crypto.randomBytes(6).toString('hex'), key, name: it.name, ip: it.ip, mac: it.mac, type: it.type, site: it.site, product: it.product, eol: it.eol, os: it.os,
      reason, state: 'pending', method: fg ? 'fortigate' : 'manual', requested_by: who.user, created_at: new Date(now()).toISOString(), history: [] };
    r.history.push({ at: r.created_at, by: who.user, action: 'requested', note: reason });
    reqs.put(r);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'lifecycle.isolate.request', target: key, detail: { request: r.id, name: r.name, ip: r.ip, product: r.product, reason } });
    return r;
  }
  function need(id) { const r = reqs.get(String(id || '')); if (!r) throw bad('request not found', 404); return r; }
  async function decide(id, body, who) {
    const r = need(id), decision = s(body && body.decision, 20), comment = s(body && body.comment, 500), at = new Date(now()).toISOString();
    if (r.state !== 'pending') throw bad(`request is ${r.state}`, 409);
    if (!['approved', 'rejected'].includes(decision)) throw bad('decision must be approved or rejected');
    const u = String(who.user || '').toLowerCase(), approvers = approversOf();
    if (u === String(r.requested_by || '').toLowerCase()) throw bad('the person who requested the isolation cannot approve it', 403);
    if (approvers.length ? !approvers.includes(u) : who.role !== 'admin') throw bad(approvers.length ? `only ${approvers.join(', ')} can approve isolation` : 'only an administrator can approve isolation', 403);
    let state = decision === 'rejected' ? 'rejected' : r.method === 'fortigate' ? 'isolating' : 'approved', error = '';
    reqs.patch(r.id, (x) => { x.state = state; x.decided_by = who.user; x.decided_at = at; x.history.push({ at, by: who.user, action: decision, note: comment }); });
    if (decision === 'approved' && r.method === 'fortigate') {
      try { if (!r.ip) throw new Error('no IP address'); await fortigate('/api/v2/monitor/user/banned/add_users', { ip_addresses: [r.ip], expiry: Number(iso.fortigate.expiry_s) || 0 }); state = 'isolated'; }
      catch (e) { state = 'failed'; error = e.message; }
      reqs.patch(r.id, (x) => { x.state = state; x.error = error || undefined; x.history.push({ at: new Date(now()).toISOString(), by: 'system', action: state === 'isolated' ? 'quarantined on FortiGate' : 'FortiGate failed', note: error }); });
    }
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'lifecycle.isolate.' + decision, target: r.key, detail: { request: r.id, ip: r.ip, state, error: error || undefined, comment } });
    return Object.assign(need(r.id), state === 'approved' ? { steps: manualSteps(r) } : {});
  }
  function applied(id, body, who) {
    const r = need(id); if (!['approved', 'failed'].includes(r.state)) throw bad(`request is ${r.state}`, 409);
    const at = new Date(now()).toISOString();
    reqs.patch(r.id, (x) => { x.state = 'isolated'; x.history.push({ at, by: who.user, action: 'isolated (applied by the network team)', note: s(body && body.comment, 500) }); });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'lifecycle.isolate.applied', target: r.key, detail: { request: r.id, ip: r.ip } });
    return need(r.id);
  }
  async function release(id, body, who) {
    const r = need(id), reason = s(body && body.reason, 500); if (!reason) throw bad('a reason is required');
    if (!['isolated', 'approved', 'failed', 'pending'].includes(r.state)) throw bad(`request is ${r.state}`, 409);
    let note = '';
    if (r.state === 'isolated' && r.method === 'fortigate') { try { await fortigate('/api/v2/monitor/user/banned/clear_users', { ip_addresses: [r.ip] }); note = 'removed from the FortiGate quarantine'; } catch (e) { throw bad('FortiGate: ' + e.message, 502); } }
    const at = new Date(now()).toISOString();
    reqs.patch(r.id, (x) => { x.state = 'released'; x.history.push({ at, by: who.user, action: 'released', note: [reason, note].filter(Boolean).join(' · ') }); });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'lifecycle.isolate.release', target: r.key, detail: { request: r.id, ip: r.ip, reason } });
    return need(r.id);
  }
  function setApprovers(body, who) {
    const list = (Array.isArray(body && body.approvers) ? body.approvers : String((body && body.approvers) || '').split(/[\s,;]+/)).map((u) => s(u, 100).toLowerCase()).filter(Boolean);
    if (list.length > 20) throw bad('at most 20 approvers');
    if (list.some((u) => !/^[a-z0-9._@\\-]+$/.test(u))) throw bad('approvers are portal user names, separated by commas');
    const before = approversOf();
    sets.put({ id: 'isolation', approvers: list, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'lifecycle.approvers', target: 'isolation', detail: { before, after: list } });
    return view({});
  }
  /* ---- risk exceptions: a device that cannot be isolated or upgraded yet - reasoned, owned, compensated, time-boxed and
     approved by a second person (the isolation approvers) */
  function needX(id) { const x = exc.get(String(id || '')); if (!x) throw bad('exception not found', 404); return x; }
  function requestException(body, who) {
    const key = s(body && body.key, 100), reason = s(body && body.reason, 1000), comp = s(body && body.compensating, 1000), owner = s(body && body.owner, 100), expires = s(body && body.expires, 10);
    if (!reason) throw bad('a business reason is required'); if (!comp) throw bad('the compensating controls are required (what reduces the risk meanwhile)'); if (!owner) throw bad('a risk owner is required');
    const today = new Date(now()).toISOString().slice(0, 10), max = new Date(now() + 365 * DAY).toISOString().slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expires) || expires <= today || expires > max) throw bad(`expiry must be a date after today and at most one year ahead (${max})`);
    const it = items(true).filter((i) => i.key === key)[0]; if (!it) throw bad('device not found', 404);
    if (it.status !== 'eol' && it.status !== 'soon') throw bad('only an end-of-life or ending-soon device needs an exception');
    if (exc.all((x) => x.key === key && (x.state === 'pending' || (x.state === 'approved' && x.expires >= today))).length) throw bad('an exception is already pending or active for this device', 409);
    const at = new Date(now()).toISOString(), x = { id: 'EXC-' + crypto.randomBytes(4).toString('hex'), key, name: it.name, serial: it.serial || '', product: it.product, eol: it.eol, ip: it.ip, reason, compensating: comp, owner, expires,
      state: 'pending', requested_by: who.user, created_at: at, history: [{ at, by: who.user, action: 'requested', note: reason }] };
    exc.put(x);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'lifecycle.exception.request', target: key, detail: { exception: x.id, owner, expires } });
    return x;
  }
  function decideException(id, body, who) {
    const x = needX(id), decision = s(body && body.decision, 20), comment = s(body && body.comment, 500), at = new Date(now()).toISOString();
    if (x.state !== 'pending') throw bad(`exception is ${x.state}`, 409);
    if (!['approved', 'rejected'].includes(decision)) throw bad('decision must be approved or rejected');
    if (decision === 'rejected' && !comment) throw bad('say why it is rejected');
    const u = String(who.user || '').toLowerCase(), approvers = approversOf();
    if (u === String(x.requested_by || '').toLowerCase()) throw bad('the person who requested the exception cannot approve it', 403);
    if (approvers.length ? !approvers.includes(u) : who.role !== 'admin') throw bad(approvers.length ? `only ${approvers.join(', ')} can approve an exception` : 'only an administrator can approve an exception', 403);
    exc.patch(x.id, (y) => { y.state = decision; y.decided_by = who.user; y.decided_at = at; y.history.push({ at, by: who.user, action: decision, note: comment }); return y; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'lifecycle.exception.' + decision, target: x.key, detail: { exception: x.id, comment } });
    return needX(x.id);
  }
  function revokeException(id, body, who) {
    const x = needX(id), reason = s(body && body.reason, 500); if (!reason) throw bad('a reason is required');
    if (!['pending', 'approved'].includes(x.state)) throw bad(`exception is ${x.state}`, 409);
    const at = new Date(now()).toISOString();
    exc.patch(x.id, (y) => { y.state = 'revoked'; y.history.push({ at, by: who.user, action: 'revoked', note: reason }); return y; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'lifecycle.exception.revoke', target: x.key, detail: { exception: x.id, reason } });
    return needX(x.id);
  }
  // the page's view with the rules run in Python (pyengine/lifecycle_rules.py, step 6d): the same inputs view() reads, only
  // the fields the rules use. A missing or failing Python, or lifecycle.engine = "node" → view() above.
  const py = opts.request || ((app.config && app.config.lifecycle) || {}).engine === 'node' ? null
    : (() => { try { return require('./pyengine').createPyEngine({ python: cfg.python_bin || undefined, timeoutMs: 120000 }); } catch (e) { return null; } })();
  const pick = (o, ks) => { const r = {}; for (const k of ks) if (o[k] !== undefined) r[k] = o[k]; return r; };
  function inputs(q) {
    return {
      all: !!(q && (q.all === '1' || q.all === true)), now: now(), extra_rules: (cfg.lifecycle || {}).rules || [],
      assets: store.collection('assets').all((x) => !CLOSED[x.status]).map((a) => pick(a, ['id', 'name', 'asset_tag', 'mgmt_ip', 'type', 'mac', 'site', 'serial', 'vendor', 'model', 'os', 'os_version', 'firmware', 'sys_descr', 'status'])),
      devices: store.collection('disc_devices').all((x) => x.status !== 'ignored' && !x.asset_id).map((d) => Object.assign(pick(d, ['id', 'hostname', 'ip', 'type', 'mac', 'macs', 'site', 'serial', 'vendor', 'model', 'status', 'asset_id', 'os', 'os_version', 'firmware', 'sys_descr']), d.extra && d.extra.serial !== undefined ? { extra: { serial: d.extra.serial } } : {})),
      virt: store.collection('virt_capacity').all().map((m) => ({ id: m.id, site: m.site, label: m.label, hosts: (m.hosts || []).map((h) => pick(h, ['id', 'name', 'ip', 'serial', 'vendor', 'model', 'version'])) })),
      storage: store.collection('storage_snapshots').all().map((sn) => ({ id: sn.id, system: sn.system ? pick(sn.system, ['name', 'serial', 'model', 'version']) : sn.system, controllers: Array.isArray(sn.controllers) ? sn.controllers.map((c) => pick(c || {}, ['name', 'serial', 'model'])) : sn.controllers })),
      requests: reqs.all(), exceptions: exc.all(), fortigate: !!fg, approvers: approversOf(),
    };
  }
  async function viewAuto(q) {
    if (py) {
      const r = await py.call('rules.lifecycle', inputs(q));
      if (r && Array.isArray(r.items)) return r;
    }
    return view(q);
  }

  return { view, viewAuto, inputs, items, isolate, decide, applied, release, manualSteps, setApprovers, requestException, decideException, revokeException };
}

function registerLifecycle(srv, app) {
  const L = createLifecycle(app);
  (app.addons = app.addons || {}).lifecycle = L;   // read by the IT Infrastructure Manager overview (engine/infra-overview.js)
  srv.route('GET', '/lifecycle', (ctx) => { ctx.need('operator'); return L.viewAuto(ctx.query || {}); });
  srv.route('PUT', '/lifecycle/settings', (ctx) => { ctx.need('admin'); return L.setApprovers(ctx.body || {}, ctx.who); });
  srv.route('POST', '/lifecycle/isolate', (ctx) => { ctx.need('admin'); return L.isolate(ctx.body || {}, ctx.who); });
  srv.route('POST', '/lifecycle/requests/:id/decide', (ctx) => { ctx.need('operator'); return L.decide(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/lifecycle/requests/:id/applied', (ctx) => { ctx.need('admin'); return L.applied(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/lifecycle/exceptions', (ctx) => { ctx.need('operator'); return L.requestException(ctx.body || {}, ctx.who); });
  srv.route('POST', '/lifecycle/exceptions/:id/decide', (ctx) => { ctx.need('operator'); return L.decideException(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/lifecycle/exceptions/:id/revoke', (ctx) => { ctx.need('admin'); return L.revokeException(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/lifecycle/requests/:id/release', (ctx) => { ctx.need('admin'); return L.release(ctx.params.id, ctx.body || {}, ctx.who); });
  return L;
}

module.exports = { createLifecycle, registerLifecycle, evaluate, compile, RULES };
