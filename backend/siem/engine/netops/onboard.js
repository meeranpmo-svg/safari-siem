// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body: check } = require('../util/check');
/*
 * Network onboarding and architecture - a network engineer adds a Palo Alto, FortiGate, Genian NAC, Cisco UCS, Cisco switch
 * or Cisco router in one form; the platform verifies it, places it in the WAN / LAN route map, draws the architecture and
 * checks its configuration against the security baseline. Monitoring is read-only; every fix is a change plan another person
 * approves.
 *   guide      per vendor: the read-only account to create (exact steps), the credentials it needs, how to send its logs to
 *              the SIEM. Credentials go to secrets.json through inventory.setCredentials (mode 600, never returned).
 *   verify     reachable · read works (API / SNMP / SSH) · least privilege (UCS: the login's own privileges; Cisco IOS:
 *              "show privilege" must not be 15; the others cannot tell from a read, said so) · SSH host key read (an
 *              administrator compares and trusts the fingerprint) · model / version · security baseline · in the route map.
 *              An over-privileged account is refused: onboarding stops and says which read-only role to use.
 *   route map  the platform's proposal (routemap.propose: IPsec peers, routing neighbours, layer order) narrowed to the
 *              links of this device; an administrator adds them (versioned save, the map's own validation).
 *   architecture  layers (internet, edge, WAN / SD-WAN, branch firewalls, core, distribution, access, compute, NAC) with the
 *              devices, their state, the route-map links and the CDP / LLDP neighbours the port map read.
 *   configuration architecture  per device the baseline controls (secure management, exposure, certificate, encrypted
 *              monitoring, read-only account, firewall policy, logging, default admin, configuration captured, documented,
 *              monitored, hardware faults), each mapped to NCA ECC and CIS Controls v8. Pass / fail / not measured / n/a.
 *   fixes      every failing control has its fix and rollback for that vendor. Cisco IOS management hardening runs as an
 *              approved task (vty-ssh-only, http-server-off: prechecks, verification, rollback). Firewalls, NAC and UCS: the
 *              approved plan is applied by an engineer and the next poll verifies it.
 */
const bad = (msg, code = 400) => Object.assign(new Error(msg), { code });
const low = (s) => String(s == null ? '' : s).toLowerCase();
const DAY = 86400000;
const SIEM = (config) => (config && config.netops && config.netops.syslog_target) || '<SIEM collector IP>';

const GUIDES = {
  paloalto: { label: 'Palo Alto Networks firewall', roles: ['firewall', 'wan-edge'], role: 'firewall', creds: ['api'], poll: { ping: true, api: true },
    account: ['Device > Admin Roles > Add: role "sentra-readonly" - Web UI: none; XML API: Configuration, Operational Requests, Report only (no Commit, no Import / Export); CLI: none.',
      'Device > Administrators > Add: user "sentra-ro" with role profile "sentra-readonly".',
      'Generate the API key: https://<firewall>/api/?type=keygen with that user (POST, not in a browser history), and paste the key here.',
      'Copy the management certificate SHA-256 fingerprint and paste it here - the platform pins it.'],
    logs: (c) => ['Device > Server Profiles > Syslog: ' + SIEM(c) + ', TLS 6514 (or UDP 514), format BSD/IETF.', 'Objects > Log Forwarding: forward traffic, threat, URL and system logs to that profile; attach it to the security rules.'] },
  fortigate: { label: 'Fortinet FortiGate', roles: ['firewall', 'wan-edge', 'branch-router'], role: 'firewall', creds: ['api'], poll: { ping: true, api: true },
    account: ['System > Admin Profiles > Create New: "sentra-readonly" with every permission set to Read (none to Read/Write).',
      'System > Administrators > Create New > REST API Admin: "sentra-ro", profile sentra-readonly, Trusted Hosts = the SIEM server only.',
      'Copy the API key shown once and paste it here, with the VDOM if you use VDOMs, and the certificate SHA-256 fingerprint.'],
    logs: (c) => ['config log syslogd setting', '  set status enable', '  set server ' + SIEM(c), '  set mode reliable    (TCP; or udp)', 'end', 'Log traffic on every policy (logtraffic all).'] },
  genian: { label: 'Genian NAC', roles: ['nac'], role: 'nac', creds: ['api'], poll: { ping: true, api: true },
    account: ['In the Genian NAC console create an administrator for the platform with a monitoring (read-only) role - no policy or node control rights.', 'Issue an API key for that administrator and paste it here (port 8443 unless changed).'],
    logs: (c) => ['Management > Syslog / Log forwarding: send audit and node events to ' + SIEM(c) + ' (UDP 514 or TCP).'] },
  'cisco-ucs': { label: 'Cisco UCS (UCS Manager)', roles: ['compute'], role: 'compute', creds: ['api_user'], poll: { ping: true, api: true },
    account: ['UCS Manager CLI (or Admin > User Management > Local Users):', 'scope security', 'create local-user sentra-ro', 'set password', 'create role read-only', 'commit-buffer',
      'Give the user only the "read-only" role - an account with admin or any configuration privilege is refused by onboarding.'],
    logs: (c) => ['Admin > Faults, Events and Audit Log > Syslog: Server 1 = ' + SIEM(c) + ', level information, facility local7.'] },
  'cisco-ios': { label: 'Cisco switch or router (IOS / IOS-XE)', roles: ['core', 'distribution', 'access', 'router', 'branch-router', 'wan-edge'], role: 'access', creds: ['snmp', 'ssh'], poll: { ping: true, snmp: true },
    account: ['SNMPv3 (monitoring, encrypted):', 'snmp-server view SENTRA-RO iso included', 'snmp-server group SENTRA-RO v3 priv read SENTRA-RO', 'snmp-server user sentra-snmp SENTRA-RO v3 auth sha <auth-password> priv aes 128 <priv-password>',
      'SSH login for the show commands (not privilege 15 - onboarding refuses it):', 'ip ssh version 2', 'username sentra-ro privilege 1 secret <password>',
      'For the daily configuration audit allow only "show running-config" at that level, e.g. a parser view with "commands exec include show running-config" - never configure / enable.'],
    logs: (c) => ['logging host ' + SIEM(c), 'logging trap informational', 'service timestamps log datetime msec localtime show-timezone', 'ntp server <your NTP>'] },
  'cisco-asa': { label: 'Cisco ASA', roles: ['firewall'], role: 'firewall', creds: ['snmp', 'ssh'], poll: { ping: true, snmp: true },
    account: ['snmp-server group SENTRA-RO v3 priv', 'snmp-server user sentra-snmp SENTRA-RO v3 auth sha <auth> priv aes 128 <priv>', 'username sentra-ro password <password> privilege 2 (show only)'],
    logs: (c) => ['logging enable', 'logging host inside ' + SIEM(c), 'logging trap informational'] },
  // a UPS is read through the standard UPS-MIB (RFC 1628) on its network card; nothing is ever written to it
  other: { label: 'UPS with an SNMP network card (UPS-MIB)', roles: ['ups'], role: 'ups', creds: ['snmp'], poll: { ping: true, snmp: true },
    account: ['On the UPS network card (web page of the card): SNMPv3 -> add a user with authentication SHA and privacy AES, access READ ONLY.',
      'Limit SNMP access to the SIEM collector address; switch SNMPv1 / v2c off.', 'The card must publish the standard UPS-MIB (1.3.6.1.2.1.33) - most cards do; on some it is a setting called "RFC 1628" or "UPS-MIB".'],
    logs: (c) => ['Syslog server: ' + SIEM(c) + ' (UDP 514), facility local0, level informational', 'Time: the same NTP server as the network devices'] },
};

// ---------- the configuration baseline (NCA ECC subdomains; CIS Controls v8)
const SECURE_MGMT = ['telnet-open', 'http-open', 'mgmt-telnet', 'mgmt-http', 'pa-mgmt-telnet', 'pa-mgmt-http'];
const CONTROLS = [
  { id: 'MGMT', name: 'Secure management (SSH / HTTPS only)', refs: 'NCA ECC 2-5, 2-8 · CIS 4.6 / 12.3', kinds: SECURE_MGMT },
  { id: 'EXPOSURE', name: 'Management not reachable from the internet or from anywhere', refs: 'NCA ECC 2-5 · CIS 4.4 / 12.2', kinds: ['mgmt-wan', 'fw-admin-anywhere'] },
  { id: 'CERT', name: 'Management certificate valid and pinned', refs: 'NCA ECC 2-8 · CIS 3.10', kinds: ['cert-expired', 'cert-expiring', 'cert-changed', 'mon-insecure-tls'] },
  { id: 'MONITOR-CRYPTO', name: 'Encrypted monitoring (SNMPv3 with privacy / TLS API)', refs: 'NCA ECC 2-8 · CIS 3.10', kinds: ['snmp-v2c', 'snmp-nopriv'] },
  { id: 'LEAST-PRIV', name: 'Read-only monitoring account', refs: 'NCA ECC 2-2 · CIS 5.4 / 6.8' },
  { id: 'FW-POLICY', name: 'No any-to-any or internet-to-any allow rule', refs: 'NCA ECC 2-5 · CIS 4.5 / 13.4', kinds: ['fw-any-any', 'fw-internet-any', 'pa-any-any'], fw: true },
  { id: 'FW-LOG', name: 'Every allow rule logs to the SIEM', refs: 'NCA ECC 2-12 · CIS 8.2 / 13.6', kinds: ['fw-nolog', 'pa-nolog'], fw: true },
  { id: 'DEFAULT-ADMIN', name: 'No default administrator account', refs: 'NCA ECC 2-2 · CIS 4.7', kinds: ['fw-default-admin'], fw: true },
  { id: 'CONFIG-AUDIT', name: 'Configuration captured for audit', refs: 'NCA ECC 2-3 · CIS 4.1' },
  { id: 'DOCUMENTED', name: 'Documented in the network architecture (route map)', refs: 'NCA ECC 2-1 · CIS 12.4' },
  { id: 'MONITORED', name: 'Reachable and monitored', refs: 'NCA ECC 2-12 · CIS 1.1 / 8.2' },
  { id: 'HW-FAULTS', name: 'No critical or major hardware fault', refs: 'NCA ECC 2-3 · CIS 1.1', ucs: true },
];
const LAYER = (d) => (d.vendor === 'paloalto' || d.role === 'wan-edge' && d.vendor !== 'edgeconnect' ? 'edge' : d.vendor === 'edgeconnect' || /sdwan/.test(d.role) || d.role === 'router' || d.role === 'branch-router' ? 'wan'
  : d.vendor === 'fortigate' || d.vendor === 'cisco-asa' || d.role === 'firewall' ? 'firewall' : d.vendor === 'genian' || d.role === 'nac' ? 'nac' : d.vendor === 'cisco-ucs' || d.role === 'compute' ? 'compute'
  : ['core', 'distribution', 'access'].includes(d.role) ? d.role : 'other');
const LAYERS = [['internet', 'Internet'], ['edge', 'Edge firewalls'], ['wan', 'WAN / SD-WAN / routers'], ['firewall', 'Internal & branch firewalls'], ['core', 'Core'], ['distribution', 'Distribution'], ['access', 'Access'], ['compute', 'Compute (UCS)'], ['nac', 'Network access control'], ['other', 'Other']];

function createOnboarding({ inventory, poller, cli, tasks, changes, routemap, state, config, log, now } = {}) {
  const L = log || { info() {}, warn() {} }, clock = now || Date.now;
  const col = state.collection('netops_onboarding');
  const slug = (s) => low(s).replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);

  function catalogue() {
    return { vendors: Object.entries(GUIDES).map(([k, g]) => ({ vendor: k, label: g.label, roles: g.roles, role: g.role, creds: g.creds, account: g.account, logs: g.logs(config) })), syslog_target: SIEM(config) };
  }
  // ---------- onboard: device + credentials in one step, then verify
  async function onboard(input, who) {
    const b = check(input || {}).oneOf('vendor', Object.keys(GUIDES), { required: true }).str('name', { required: true, max: 80 }).str('ip', { required: true, max: 45 }).str('site', { max: 60 })
      .str('role', { max: 40 }).int('criticality', { min: 1, max: 3 }).str('api_host', { max: 253 }).done();
    const G = GUIDES[b.vendor], role = b.role || G.role;
    if (!G.roles.includes(role)) throw bad('role: a ' + G.label + ' is one of ' + G.roles.join(', '));
    const id = slug(b.name); if (id.length < 2) throw bad('name: at least 2 letters or digits');
    const cr = (input && input.credentials) || {};
    const creds = {};
    if (G.creds.includes('api')) { if (!cr.api || !cr.api.token) throw bad('credentials.api.token: the read-only API key is required for a ' + G.label); creds.api = cr.api; }
    if (G.creds.includes('api_user')) { if (!cr.api || !cr.api.username || !cr.api.password) throw bad('credentials.api: the read-only username and password are required for ' + G.label); creds.api = { username: cr.api.username, password: cr.api.password, fingerprint256: cr.api.fingerprint256, insecure: cr.api.insecure }; }
    if (G.creds.includes('snmp') && cr.snmp) { if (String(cr.snmp.version || '3') !== '3') throw bad('credentials.snmp: use SNMPv3 (v2c sends the community in clear text)'); creds.snmp = cr.snmp; }
    if (G.creds.includes('ssh') && cr.ssh) creds.ssh = cr.ssh;
    if (G.creds.includes('snmp') && !creds.snmp && !creds.ssh) throw bad('credentials: an SNMPv3 user (monitoring) and / or a read-only SSH login is required for a ' + G.label);
    const existing = inventory.get(id);
    const dev = inventory.put(Object.assign({ id: existing ? existing.id : id, name: b.name, vendor: b.vendor, ip: b.ip, site: b.site || 'Unassigned', role, criticality: b.criticality || 2, poll: { ping: true, snmp: !!creds.snmp, api: !!creds.api } }, b.api_host ? { api_host: b.api_host } : {}), who.user);
    inventory.setCredentials(dev.id, creds, who.user);
    const rec = { id: dev.id, vendor: b.vendor, by: who.user, at: clock(), status: 'verifying', steps: [] };
    col.put(rec);
    return verify(dev.id, who);
  }
  async function verify(id, who) {
    const d = inventory.get(id); if (!d) throw bad('device not found', 404);
    const G = GUIDES[d.vendor] || null, steps = [], add = (key, label, st, detail, fix) => steps.push({ key, label, state: st, detail: String(detail || '').slice(0, 400), fix: fix || null });
    let snap = null; try { snap = await poller.pollDevice(id, { forceSecurity: true }); } catch (e) { add('poll', 'First poll', 'fail', e.message); }
    const sum = inventory.credentialSummary(id) || {};
    if (snap) {
      add('reach', 'Reachable from the SIEM', snap.reach && snap.reach.received > 0 ? 'ok' : snap.reach ? 'fail' : 'skip', snap.reach ? (snap.reach.received > 0 ? 'ping ' + Math.round(snap.reach.rtt_avg_ms || 0) + ' ms' : 'no reply to ping - check the route and that ICMP from the SIEM is allowed') : 'ping not enabled');
      const read = snap.sources.filter((s) => s !== 'ping'), errs = snap.errors.filter((e) => !/^security checks/.test(e));
      add('read', 'Read with the monitoring account', read.length ? (errs.length ? 'warn' : 'ok') : 'fail', read.length ? 'read over ' + read.join(' + ') + (errs.length ? '; ' + errs.slice(0, 3).join('; ') : '') : (errs[0] || 'nothing read') , read.length ? null : 'Check the credentials, the account\'s rights and that the SIEM\'s address is allowed (trusted hosts / management ACL).');
    }
    // least privilege
    if (d.vendor === 'cisco-ucs') {
      const u = snap && snap.ucs;
      if (!u) add('privilege', 'Read-only account', 'pending', 'not read yet');
      else if (u.read_only) add('privilege', 'Read-only account', 'ok', 'privileges: ' + u.privileges.join(', '));
      else add('privilege', 'Read-only account', 'fail', 'over-privileged: ' + u.privileges.join(', '), 'Remove every role except "read-only" from the user in UCS Manager (Admin > User Management), then verify again.');
    } else if (d.vendor === 'cisco-ios' && sum.ssh) {
      if (!cli.hostKey(id)) {
        let fp = ''; try { fp = (await cli.fetchHostKey(id)).fingerprint; } catch (e) { fp = ''; /* shown as not read below */ }
        add('hostkey', 'SSH host key trusted', 'pending', fp ? 'fingerprint ' + fp + ' - an administrator compares it with the device ("show crypto key mypubkey rsa") and trusts it' : 'could not read the host key - check SSH reachability', fp ? 'AI Network Engineer > device > SSH host key > Trust' : null);
        add('privilege', 'Read-only account', 'pending', 'checked once the host key is trusted');
      } else {
        add('hostkey', 'SSH host key trusted', 'ok', 'pinned');
        try {
          const r = await cli.run(id, ['show privilege'], { by: (who && who.user) || 'system:onboarding', via: 'onboarding' }), lvl = +((/privilege level is (\d+)/i.exec((r.results[0] || {}).output || '') || [])[1]);
          if (!lvl && lvl !== 0) add('privilege', 'Read-only account', 'warn', 'privilege level not reported');
          else if (lvl >= 15) add('privilege', 'Read-only account', 'fail', 'the SSH login has privilege 15 (full configuration rights)', 'Use "username sentra-ro privilege 1 secret …" (and a parser view for show running-config), then verify again.');
          else add('privilege', 'Read-only account', 'ok', 'privilege level ' + lvl);
        } catch (e) { add('privilege', 'Read-only account', 'warn', 'could not run show privilege: ' + e.message); }
      }
    } else if (G) add('privilege', 'Read-only account', 'manual', 'a ' + G.label + ' does not tell its account\'s rights to a read - use the read-only role in the guide; the account is audited on the device');
    // facts, baseline, route map
    const sys = snap && snap.system;
    add('facts', 'Model and version', sys && (sys.model || sys.version) ? 'ok' : 'warn', sys ? [sys.model, sys.version].filter(Boolean).join(' · ') || 'not reported' : 'not reported yet');
    const items = (snap && snap.security && snap.security.items) || [], high = items.filter((x) => x.severity === 'high').length;
    add('baseline', 'Security baseline', !snap || !snap.security ? 'pending' : high ? 'fail' : items.length ? 'warn' : 'ok', !snap || !snap.security ? 'checked on the first poll' : items.length ? items.length + ' finding(s), ' + high + ' high - see Configuration architecture' : 'no finding');
    const inMap = routemap.map().nodes.some((n) => n.device === id);
    add('routemap', 'In the WAN / LAN route map', inMap ? 'ok' : 'pending', inMap ? 'placed' : 'not placed yet - "Add to the route map" adds it with the links the platform can see', null);
    const failed = steps.some((s) => s.state === 'fail' && ['privilege', 'read', 'poll'].includes(s.key));
    const rec = Object.assign(col.get(id) || { id, vendor: d.vendor, by: (who && who.user) || '', at: clock() }, { verified_at: clock(), status: failed ? 'blocked' : steps.some((s) => ['pending', 'fail'].includes(s.state)) ? 'in progress' : 'onboarded', steps });
    if (failed && steps.some((s) => s.key === 'privilege' && s.state === 'fail')) {   // an over-privileged account is not kept: polling stops until it is replaced
      inventory.put({ id, poll: { ping: true, snmp: false, api: false } }, 'system:onboarding');
      rec.note = 'Polling with this account was switched off because it is over-privileged. Replace it with a read-only account and verify again.';
    }
    col.put(rec);
    L.info('netops onboarding verified', { device: id, status: rec.status });
    return rec;
  }
  function list() { return { items: col.all().sort((a, b) => b.at - a.at).map((r) => Object.assign({}, r, { device: inventory.get(r.id) || null })) }; }
  // ---------- route map: the proposal's links that touch this device
  function routeMapPlan(id) {
    const d = inventory.get(id); if (!d) throw bad('device not found', 404);
    const p = routemap.propose(), cur = routemap.map(), node = p.map.nodes.find((n) => n.device === id);
    if (!node) throw bad(d.name + ' (' + d.vendor + ', role ' + d.role + ') has no place in the route map - set its role (core, distribution, access, router, firewall, compute, nac)', 409);
    const links = p.map.links.filter((l) => l.a === node.id || l.b === node.id), ids = new Set(links.flatMap((l) => [l.a, l.b]));
    const nodes = p.map.nodes.filter((n) => ids.has(n.id) || n.id === node.id), sites = p.map.sites.filter((s) => nodes.some((n) => n.site === s.id));
    return { device: id, version: cur.version, node, nodes, links, sites, reasons: p.reasons.filter((r) => links.some((l) => l.id === r.link)) };
  }
  function addToRouteMap(id, input, who) {
    const b = check(input || {}).int('baseVersion', { min: 0 }).done(), plan = routeMapPlan(id), cur = routemap.map();
    const has = (arr, x) => arr.some((y) => y.id === x.id);
    const nodeByDev = new Map(cur.nodes.filter((n) => n.device).map((n) => [n.device, n.id]));
    // the device's existing node keeps its id; proposed peers map onto nodes already in the map for the same device
    const remap = (nid) => { const pn = plan.nodes.find((n) => n.id === nid); return pn && pn.device && nodeByDev.has(pn.device) ? nodeByDev.get(pn.device) : nid; };
    const next = { sites: cur.sites.slice(), nodes: cur.nodes.slice(), links: cur.links.slice(), thresholds: cur.thresholds };
    for (const s of plan.sites) if (!has(next.sites, s)) next.sites.push(s);
    for (const n of plan.nodes) { if (n.device && nodeByDev.has(n.device)) continue; if (!has(next.nodes, n)) next.nodes.push(n); }
    let added = 0; for (const l of plan.links) { const x = Object.assign({}, l, { a: remap(l.a), b: remap(l.b) }); if (x.a === x.b || next.links.some((y) => y.id === x.id || ([y.a, y.b].sort().join('|') === [x.a, x.b].sort().join('|') && y.kind === x.kind))) continue; next.links.push(x); added++; }
    const r = routemap.save(next, who.user, b.baseVersion === undefined ? cur.version : b.baseVersion);
    return { version: r.map.version, node: remap(plan.node.id), links_added: added, reasons: plan.reasons };
  }

  // ---------- architecture + configuration architecture
  function neighbours() {
    const out = [], devs = inventory.list(), byName = (n) => devs.find((d) => low(d.name) === low(n) || low(d.name) === low(String(n).split('.')[0]) || low(d.id) === slug(String(n).split('.')[0])), byIp = (ip) => devs.find((d) => d.ip === ip);
    for (const r of state.collection('portmap_reads').all()) for (const nb of r.neighbours || []) { const o = (nb.ip && byIp(nb.ip)) || byName(nb.name); if (o && o.id !== r.id) out.push({ a: r.id, b: o.id, via: nb.via, port: nb.local }); }
    return out;
  }
  function controlsFor(d, snap, rec, inMap, cfgAudit) {
    const items = (snap && snap.security && snap.security.items) || [], measured = !!(snap && snap.security), fw = ['paloalto', 'fortigate', 'cisco-asa'].includes(d.vendor), t = clock();
    return CONTROLS.map((c) => {
      if (c.fw && !fw) return { control: c.id, state: 'n/a' };
      if (c.ucs && d.vendor !== 'cisco-ucs') return { control: c.id, state: 'n/a' };
      if (c.kinds) { if (!measured) return { control: c.id, state: 'not measured', detail: 'not polled with the security checks yet' }; const f = items.filter((x) => c.kinds.includes(x.kind)); return { control: c.id, state: f.length ? 'fail' : 'pass', detail: f.length ? f.map((x) => x.title).slice(0, 4).join(' · ') : 'no finding', findings: f }; }
      if (c.id === 'LEAST-PRIV') { const s = rec && rec.steps.find((x) => x.key === 'privilege'); return { control: c.id, state: !s ? 'not measured' : s.state === 'ok' ? 'pass' : s.state === 'fail' ? 'fail' : 'not measured', detail: s ? s.detail : 'not onboarded through the onboarding page' }; }
      if (c.id === 'CONFIG-AUDIT') {
        if (['cisco-ios', 'cisco-asa'].includes(d.vendor)) { const a = cfgAudit(d.id); return { control: c.id, state: a && a.at && t - a.at < 2 * DAY ? 'pass' : 'fail', detail: a && a.at ? 'running-config read ' + new Date(a.at).toISOString().slice(0, 10) : 'running-config not read - needs an SSH login with a trusted host key' }; }
        if (fw) return { control: c.id, state: snap && snap.security && snap.security.facts ? 'pass' : 'fail', detail: snap && snap.security && snap.security.facts ? 'configuration facts read' : 'configuration not readable with this API role (needs Configuration read)' };
        return { control: c.id, state: 'n/a' };
      }
      if (c.id === 'DOCUMENTED') return { control: c.id, state: inMap ? 'pass' : 'fail', detail: inMap ? 'in the route map' : 'not in the route map' };
      if (c.id === 'MONITORED') return { control: c.id, state: !snap ? 'not measured' : snap.ok && t - snap.at < 30 * 60000 ? 'pass' : 'fail', detail: !snap ? 'not polled yet' : snap.ok ? 'polled ' + new Date(snap.at).toISOString().slice(11, 16) + ' UTC' : (snap.errors[0] || 'poll failed') };
      if (c.id === 'HW-FAULTS') { const f = ((snap && snap.ucs && snap.ucs.faults) || []).filter((x) => ['critical', 'major'].includes(x.severity)); return { control: c.id, state: !snap || !snap.ucs ? 'not measured' : f.length ? 'fail' : 'pass', detail: f.length ? f.slice(0, 3).map((x) => x.severity + ': ' + x.descr).join(' · ') : 'no critical / major fault' }; }
      return { control: c.id, state: 'not measured' };
    });
  }
  function architecture() {
    const devs = inventory.list(), recs = new Map(col.all().map((r) => [r.id, r])), map = routemap.map(), nodeDev = new Map(map.nodes.filter((n) => n.device).map((n) => [n.id, n.device]));
    const cfgCol = state.collection('netops_config_audit'), cfgAudit = (id) => cfgCol.get(id);
    const nodes = devs.map((d) => { const s = poller.snapshot(d.id); return { id: d.id, name: d.name, vendor: d.vendor, role: d.role, site: d.site, ip: d.ip, layer: LAYER(d), state: !s ? 'unknown' : s.ok ? 'up' : 'down', model: (s && s.system && s.system.model) || '', onboarding: (recs.get(d.id) || {}).status || null }; });
    const links = [], seen = new Set(), push = (a, b, kind, via) => { if (!a || !b || a === b) return; const k = [a, b].sort().join('|'); if (seen.has(k)) return; seen.add(k); links.push({ a, b, kind, via }); };
    for (const l of map.links) push(nodeDev.get(l.a), nodeDev.get(l.b), l.kind, 'route map');
    for (const n of neighbours()) push(n.a, n.b, 'lan', n.via + ' neighbour (' + n.port + ')');
    const internet = map.nodes.some((n) => n.kind === 'internet') || devs.some((d) => LAYER(d) === 'edge');
    const matrix = devs.map((d) => { const s = poller.snapshot(d.id), inMap = map.nodes.some((n) => n.device === d.id); const c = controlsFor(d, s, recs.get(d.id), inMap, cfgAudit);
      return { device: d.id, name: d.name, vendor: d.vendor, site: d.site, controls: c, fails: c.filter((x) => x.state === 'fail').length, passes: c.filter((x) => x.state === 'pass').length }; });
    const all = [].concat(...matrix.map((m) => m.controls)), app = all.filter((x) => x.state !== 'n/a'), measured = app.filter((x) => x.state === 'pass' || x.state === 'fail');
    return { at: clock(), layers: LAYERS.map(([id, label]) => ({ id, label, nodes: id === 'internet' ? (internet ? [{ id: 'internet', name: 'Internet', layer: 'internet', state: 'up' }] : []) : nodes.filter((n) => n.layer === id) })).filter((l) => l.nodes.length),
      links, controls: CONTROLS.map((c) => ({ id: c.id, name: c.name, refs: c.refs, firewall_only: !!c.fw, ucs_only: !!c.ucs })), matrix,
      summary: { devices: devs.length, onboarded: [...recs.values()].filter((r) => r.status === 'onboarded').length, blocked: [...recs.values()].filter((r) => r.status === 'blocked').length, in_map: devs.filter((d) => map.nodes.some((n) => n.device === d.id)).length,
        compliance_pct: measured.length ? Math.round(measured.filter((x) => x.state === 'pass').length / measured.length * 100) : null, failing_controls: all.filter((x) => x.state === 'fail').length, not_measured: app.filter((x) => x.state === 'not measured').length, map_version: map.version } };
  }
  // ---------- fixes: a change plan per failing control; Cisco IOS management hardening runs as an approved task
  function fixFor(d, control, ctl) {
    const f = ctl.findings || [];
    if (control === 'MGMT' && d.vendor === 'cisco-ios') {
      const tl = f.some((x) => x.kind === 'telnet-open'), ht = f.some((x) => x.kind === 'http-open');
      return { auto: true, tasks: [].concat(tl ? [{ type: 'vty-ssh-only', title: 'Allow only SSH on the VTY lines' }] : [], ht ? [{ type: 'http-server-off', title: 'Turn off the HTTP server' }] : []) };
    }
    const cmds = [], rb = [];
    for (const x of f) {
      if (d.vendor === 'fortigate' && /^mgmt-(telnet|http)$/.test(x.kind)) { const ev = (x.evidence || []).join(' '), acc = (/allowaccess: (.+)/.exec(ev) || [])[1] || ''; const now2 = acc.split(/\s+/).filter((a) => a && a !== 'telnet' && a !== 'http');
        cmds.push('config system interface', '  edit "' + x.key + '"', '    set allowaccess ' + (now2.join(' ') || 'ping'), '  next', 'end'); rb.push('config system interface', '  edit "' + x.key + '"', '    set allowaccess ' + acc, '  next', 'end'); continue; }
      if (d.vendor === 'paloalto' && /^pa-mgmt-(telnet|http)$/.test(x.kind)) { const p = x.kind.slice(8), prof = x.key.slice(0, -p.length); cmds.push('set network profiles interface-management-profile "' + prof + '" ' + p + ' no'); rb.push('set network profiles interface-management-profile "' + prof + '" ' + p + ' yes'); continue; }
      if (d.vendor === 'paloalto' && x.kind === 'telnet-open') { cmds.push('set deviceconfig system service disable-telnet yes'); rb.push('set deviceconfig system service disable-telnet no'); continue; }
      if (d.vendor === 'paloalto' && x.kind === 'http-open') { cmds.push('set deviceconfig system service disable-http yes'); rb.push('set deviceconfig system service disable-http no'); continue; }
      cmds.push('# ' + x.title, '# ' + (x.rec || 'see the finding'));
    }
    if (d.vendor === 'paloalto' && cmds.some((c) => /^set /.test(c))) { cmds.push('commit'); rb.push('commit'); }
    if (!cmds.length) { const c = CONTROLS.find((x) => x.id === control); cmds.push('# ' + c.name + ': ' + (ctl.detail || 'see the control'), '# follow the onboarding guide for ' + ((GUIDES[d.vendor] || {}).label || d.vendor)); }
    return { auto: false, commands: cmds, rollback: rb.length ? rb : ['# no configuration change to undo'] };
  }
  function proposeFix(input, who) {
    const b = check(input || {}).str('device', { required: true, max: 64 }).oneOf('control', CONTROLS.map((c) => c.id), { required: true }).str('reason', { max: 1000 }).done();
    const d = inventory.get(b.device); if (!d) throw bad('device not found', 404);
    const m = architecture().matrix.find((x) => x.device === d.id), ctl = m.controls.find((c) => c.control === b.control);
    if (!ctl || ctl.state !== 'fail') throw bad(b.control + ' is not failing on ' + d.name + ' (' + (ctl ? ctl.state : 'n/a') + ') - there is nothing to fix', 409);
    const c = CONTROLS.find((x) => x.id === b.control), fx = fixFor(d, b.control, ctl), reason = '[configuration architecture] ' + c.name + ' (' + c.refs + '): ' + (b.reason || ctl.detail);
    if (fx.auto) {
      if (!fx.tasks.length) throw bad('no automatic task covers this finding on ' + d.name, 409);
      const plans = fx.tasks.map((t) => tasks.propose({ device: d.id, type: t.type, params: {}, reason, source: 'user' }, who.user));
      return { device: d.id, control: b.control, automatic: true, plans: plans.map((p) => ({ id: p.id, title: p.title, status: p.status, risk: p.risk })), note: 'After another person approves, "Run" executes it with prechecks, verification and automatic rollback.' };
    }
    const plan = changes.propose({ device: d.id, title: ('Fix ' + c.name + ' on ' + d.name).slice(0, 160), reason, risk: ['MGMT', 'EXPOSURE', 'FW-POLICY'].includes(b.control) ? 'medium' : 'low', commands: fx.commands, rollback: fx.rollback, prechecks: ['read: the finding is still present on the latest poll'], source: 'user' }, who.user);
    return { device: d.id, control: b.control, automatic: false, plans: [{ id: plan.id, title: plan.title, status: plan.status, risk: plan.risk }], commands: fx.commands, rollback: fx.rollback, note: 'After another person approves, an engineer applies it on the ' + ((GUIDES[d.vendor] || {}).label || d.vendor) + ' and the next poll verifies the control.' };
  }
  return { catalogue, onboard, verify, list, routeMapPlan, addToRouteMap, architecture, proposeFix, GUIDES, CONTROLS };
}

module.exports = { createOnboarding, GUIDES, CONTROLS, LAYER };
