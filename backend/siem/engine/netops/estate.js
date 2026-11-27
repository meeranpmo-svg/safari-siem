// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network Estate & Licensing - the firewalls (FortiGate fleet through FortiManager / standalone FortiGates), the switches (H3C,
 * Cisco ...) and every support / security licence in one read-only view, with AI / ML:
 *   firewalls    health, connection, configuration sync, HA, firmware against the target per model, CPU / memory against each
 *                device's OWN baseline (robust z from fmg.js), SD-WAN links out of SLA, tunnels
 *   switches     reachability, CPU / memory, ports up, ports with errors and hot ports (over 80 % utilisation) from the poller
 *   licences     FortiCare (support) and FortiGuard (security services) per device with the date each ends: expired, due in 30 /
 *                90 days, the renewal calendar for the next 12 months and the months to co-term renewals into
 *   risk         an explainable score per device (0-100): down, findings, out of sync, firmware behind, licence expired or due, HA
 *                degraded, links out of SLA, CPU / memory unusual for that device - each point with its reason
 *   automation   the open FortiManager changes (four-eyes) and suggested change plans (firmware per model, renewal bundles) - a
 *                suggestion for a person; nothing here changes a device
 *   GET /netops/estate   any signed-in user (read)
 */
const { wrap } = require('../soc/routeutil');

const DAY = 86400000;
const SUPPORT = /forticare|support|hardware|firmware|enhanced|premium|platinum/i;
const LNAME = { forticare: 'FortiCare support', fortiguard: 'FortiGuard', antivirus: 'Antivirus', ips: 'IPS', web_filtering: 'Web filtering', webfilter: 'Web filtering',
  appctrl: 'Application control', antispam: 'Anti-spam', botnet_domain: 'Botnet domains', botnet_ip: 'Botnet IPs', security_rating: 'Security rating', industrial_db: 'Industrial DB',
  forticloud: 'FortiCloud', fortisandbox_cloud: 'Sandbox cloud', outbreak_prevention: 'Outbreak prevention', mobile_malware: 'Mobile malware', dlp: 'DLP', iot_detection: 'IoT detection',
  fortitoken: 'FortiToken', fortitoken_cloud: 'FortiToken Cloud', sdwan_network_monitor: 'SD-WAN monitor', ai_based_malware_detection: 'AI malware detection' };
const lname = (k) => LNAME[String(k).toLowerCase()] || String(k).replace(/[_-]+/g, ' ').replace(/^./, (c) => c.toUpperCase());
const SWITCH = new Set(['core', 'distribution', 'access', 'fc_switch']);

function createEstate(deps) {
  const now = deps.now || Date.now;
  const fleet = () => { const F = deps.fmgApi; try { return F && F.status && F.status().configured ? F.fleet() : null; } catch (e) { (deps.log || { warn() {} }).warn('estate: FortiManager fleet not readable', { err: String(e.message).slice(0, 160) }); return null; } };
  const net = () => deps.netopsInstance || null;

  function build() {
    const t = now(), FL = fleet(), N = net(), R = [], today = Date.parse(new Date(t).toISOString().slice(0, 10) + 'T00:00:00Z');   // days left counted in whole days from today
    // ---- firewalls (FortiManager) with an explainable risk score
    const fw = (FL ? FL.devices : []).map((d) => {
      const why = [], add = (n, r) => { if (n > 0) why.push({ points: n, reason: r }); };
      if (d.conn === 'down' || d.health === 'down') add(40, 'not connected to FortiManager');
      const sev = { high: 8, medium: 4, low: 1 }, f = (d.findings || []).filter((x) => !['licence', 'firmware'].includes(x.code));
      add(Math.min(20, f.reduce((a, x) => a + (sev[x.severity] || 0), 0)), f.length + ' open finding(s)');
      if (d.conf === 'modified') add(10, 'configuration out of sync with FortiManager');
      if ((d.findings || []).some((x) => x.code === 'firmware')) add(10, 'firmware behind the target for ' + (d.model || 'the model'));
      const lic = (d.licences || []).map((l) => ({ name: l.name, expires: l.expires, days: l.expires ? Math.round((Date.parse(l.expires) - today) / DAY) : null, status: l.status }));
      if (lic.some((l) => l.days != null && l.days < 0)) add(25, 'a licence has expired'); else if (lic.some((l) => l.days != null && l.days <= 30)) add(10, 'a licence ends within 30 days');
      if ((d.ha_members || []).some((m) => m.status !== 'up')) add(15, 'an HA member is not up');
      const sla = (d.links || []).filter((l) => l.state === 'up' && l.sla_ok === false).length + (d.links || []).filter((l) => l.state === 'down').length; add(Math.min(20, sla * 10), sla + ' SD-WAN link(s) down or out of SLA');
      const z = d.z || {}; if (Math.abs(z.cpu || 0) >= 3) add(10, 'CPU unusual for this firewall (z ' + Math.round(z.cpu * 10) / 10 + ')'); if (Math.abs(z.mem || 0) >= 3) add(10, 'memory unusual for this firewall (z ' + Math.round(z.mem * 10) / 10 + ')');
      const risk = Math.min(100, why.reduce((a, w) => a + w.points, 0));
      R.push({ kind: 'firewall', name: d.name, site: d.site || '', model: d.model || '', risk, why });
      return { name: d.name, serial: d.serial, site: d.site || '', model: d.model || '', firmware: d.firmware || '', health: d.health, conn: d.conn, conf: d.conf, ha: d.ha_mode,
        cpu: d.res ? d.res.cpu : null, mem: d.res ? d.res.mem : null, z: { cpu: z.cpu == null ? null : z.cpu, mem: z.mem == null ? null : z.mem }, risk, licences: lic };
    });
    // ---- switches (the netops poller): reachability, load, ports
    const sw = []; const extraLic = [];
    if (N && N.inventory) for (const d of N.inventory.list()) {
      const s = N.poller && N.poller.snapshot ? N.poller.snapshot(d.id) : null;
      if (s && s.licenses && Array.isArray(s.licenses.items) && !(FL && FL.devices.some((x) => x.serial && x.serial === (s.licenses.serial || '')))) extraLic.push({ device: d.name, site: d.site || '', vendor: d.vendor, items: s.licenses.items });
      if (!SWITCH.has(d.role) && !/h3c|cisco-ios/.test(d.vendor)) continue;
      if (d.role && !SWITCH.has(d.role) && d.role !== 'other') continue;
      const ifs = (s && s.interfaces) || [], phys = ifs.filter((i) => !/vlan|loop|null|tunnel|bridge|aggregat|port-channel|^po\d/i.test(i.name || ''));
      const up = s ? !!(s.ok || (s.reach && s.reach.loss_pct != null && s.reach.loss_pct < 100)) : null;
      const errs = phys.filter((i) => (i.err_per_min || 0) > 0).length, hot = phys.filter((i) => Math.max(i.util_in || 0, i.util_out || 0) >= 80).length;
      const why = []; if (up === false) why.push({ points: 40, reason: 'not answering' }); if (errs) why.push({ points: Math.min(20, errs * 4), reason: errs + ' port(s) with errors' });
      if (hot) why.push({ points: Math.min(15, hot * 5), reason: hot + ' port(s) over 80 % busy' }); const cpu = s && s.system ? s.system.cpu_pct : null, mem = s && s.system ? s.system.mem_pct : null;
      if (cpu != null && cpu >= 85) why.push({ points: 10, reason: 'CPU ' + cpu + ' %' }); if (mem != null && mem >= 90) why.push({ points: 10, reason: 'memory ' + mem + ' %' });
      const risk = Math.min(100, why.reduce((a, w) => a + w.points, 0));
      R.push({ kind: 'switch', name: d.name, site: d.site || '', model: (s && s.system && s.system.model) || d.vendor, risk, why });
      sw.push({ name: d.name, ip: d.ip, site: d.site || '', vendor: d.vendor, role: d.role || '', model: (s && s.system && s.system.model) || '', version: (s && s.system && s.system.version) || '', up, polled: s ? s.at : null,
        cpu, mem, ports: phys.length, ports_up: phys.filter((i) => i.oper === 'up').length, err_ports: errs, hot_ports: hot, risk });
    }
    // ---- licences: every FortiCare / FortiGuard item with its end date
    const L = [];
    for (const d of fw) for (const l of d.licences) L.push({ device: d.name, site: d.site, model: d.model, key: l.name, name: lname(l.name), kind: SUPPORT.test(l.name) ? 'support' : 'security', expires: l.expires, days: l.days, status: l.status });
    for (const x of extraLic) for (const l of x.items) { const days = l.expires ? Math.round((Date.parse(l.expires) - today) / DAY) : null; L.push({ device: x.device, site: x.site, model: x.vendor, key: l.name, name: lname(l.name), kind: l.kind || (SUPPORT.test(l.name) ? 'support' : 'security'), expires: l.expires || null, days, status: l.status || '' }); }
    const months = []; for (let i = 0; i < 12; i++) { const d = new Date(t); d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() + i); months.push(d.toISOString().slice(0, 7)); }
    const cal = months.map((m) => ({ month: m, support: L.filter((l) => l.kind === 'support' && l.expires && l.expires.slice(0, 7) === m).length, security: L.filter((l) => l.kind === 'security' && l.expires && l.expires.slice(0, 7) === m).length }));
    const busy = cal.filter((c) => c.support + c.security).sort((a, b) => (b.support + b.security) - (a.support + a.security));
    const devNoSupport = fw.filter((d) => d.licences.length && !d.licences.some((l) => SUPPORT.test(l.name) && (l.days == null || l.days >= 0))).map((d) => d.name);
    const lic = { items: L.sort((a, b) => (a.days == null) - (b.days == null) || (a.days || 0) - (b.days || 0)), calendar: cal,
      expired: L.filter((l) => l.days != null && l.days < 0).length, due30: L.filter((l) => l.days != null && l.days >= 0 && l.days <= 30).length, due90: L.filter((l) => l.days != null && l.days > 30 && l.days <= 90).length,
      devices_without_support: devNoSupport, devices_unknown: fw.filter((d) => !d.licences.length).map((d) => d.name), coterm: busy.slice(0, 2).map((c) => c.month) };
    // ---- firmware compliance per model (fmg.js targets)
    const models = FL ? FL.models.map((m) => ({ model: m.model, devices: m.devices, target: m.target, newest: m.newest, on_target: m.target ? (m.versions[m.target] || 0) : null, versions: m.versions })) : [];
    const risk = R.filter((r) => r.risk > 0).sort((a, b) => b.risk - a.risk).slice(0, 15);
    // ---- what the AI noticed, with the figures
    const N2 = [], down = fw.filter((d) => d.conn === 'down').length, swDown = sw.filter((s) => s.up === false).length;
    if (down) N2.push({ tone: 'bad', text: down + ' FortiGates are not connected to FortiManager.' });
    if (swDown) N2.push({ tone: 'bad', text: swDown + ' switches are not answering.' });
    if (lic.expired) N2.push({ tone: 'bad', text: lic.expired + ' FortiCare / FortiGuard licences have expired - those protections or support no longer work.' });
    if (lic.due30) N2.push({ tone: 'warn', text: lic.due30 + ' licences end within 30 days; ' + lic.due90 + ' more within 90 days.' });
    if (devNoSupport.length) N2.push({ tone: 'bad', text: devNoSupport.length + ' FortiGates have no active FortiCare support: ' + devNoSupport.slice(0, 5).join(', ') + (devNoSupport.length > 5 ? '…' : '') + '.' });
    if (lic.coterm.length && L.length >= 10) N2.push({ tone: 'info', text: 'Most renewals fall in ' + lic.coterm.join(' and ') + ' - co-terming the others to those months gives one renewal order.' });
    const behind = models.filter((m) => m.target && m.on_target != null && m.on_target < m.devices);
    if (behind.length) N2.push({ tone: 'warn', text: behind.reduce((a, m) => a + (m.devices - m.on_target), 0) + ' FortiGates are not on their model\'s target firmware (' + behind.slice(0, 3).map((m) => m.model).join(', ') + ').' });
    const unusual = fw.filter((d) => Math.abs(d.z.cpu || 0) >= 3 || Math.abs(d.z.mem || 0) >= 3); if (unusual.length) N2.push({ tone: 'warn', text: unusual.length + ' FortiGates show CPU or memory unusual for their own baseline: ' + unusual.slice(0, 4).map((d) => d.name).join(', ') + '.' });
    const errSw = sw.filter((s) => s.err_ports), hotSw = sw.filter((s) => s.hot_ports);
    if (errSw.length) N2.push({ tone: 'warn', text: errSw.reduce((a, s) => a + s.err_ports, 0) + ' switch ports are logging errors on ' + errSw.length + ' switches - check cables and duplex.' });
    if (hotSw.length) N2.push({ tone: 'warn', text: hotSw.reduce((a, s) => a + s.hot_ports, 0) + ' switch ports run over 80 % busy - a candidate for an uplink upgrade.' });
    if (risk.length) N2.push({ tone: risk[0].risk >= 50 ? 'bad' : 'warn', text: 'Highest risk: ' + risk[0].name + ' (' + risk[0].risk + '/100 - ' + risk[0].why.slice(0, 2).map((w) => w.reason).join('; ') + ').' });
    // ---- automation: what is waiting for a person, and suggested change plans (a person proposes them in FortiGate Fleet)
    const sug = [];
    for (const m of behind) sug.push({ kind: 'firmware', title: 'Upgrade ' + (m.devices - m.on_target) + ' ' + m.model + ' to ' + m.target, where: 'fortigate-fleet.html', note: 'FortiGate Fleet -> Changes: propose the upgrade; a second administrator approves; run in a maintenance window.' });
    if (lic.expired + lic.due30) sug.push({ kind: 'renewal', title: 'Renew ' + (lic.expired + lic.due30) + ' FortiCare / FortiGuard licences', where: 'support-contracts.html', note: 'Support Contracts: record the renewal with its reference; the dates refresh from the devices after the renewal is applied.' });
    if (errSw.length) sug.push({ kind: 'switch', title: 'Check ' + errSw.length + ' switches with port errors', where: 'switch-port-map.html', note: 'Switch Port Map shows the port and what is connected.' });
    return { at: new Date(t).toISOString(), fortimanager: { connected: !!FL, status: FL ? FL.status : null },
      kpis: { firewalls: fw.length, fw_ok: fw.filter((d) => d.health === 'ok').length, fw_down: down, out_of_sync: fw.filter((d) => d.conf === 'modified').length, switches: sw.length, sw_up: sw.filter((s) => s.up).length, sw_down: swDown,
        licences: L.length, expired: lic.expired, due30: lic.due30, changes_open: FL ? FL.changes_open || 0 : 0, tunnels: FL ? FL.kpis.tunnels : null },
      firewalls: fw.sort((a, b) => b.risk - a.risk || a.name.localeCompare(b.name)), switches: sw.sort((a, b) => b.risk - a.risk || a.name.localeCompare(b.name)), licences: lic, models, risk, noticed: N2, suggestions: sug,
      note: !FL && !sw.length ? 'Nothing is connected yet: connect FortiManager (or add standalone FortiGates) on Connections, and add the switches on the AI Network Engineer -> Devices.' : '' };
  }
  return { build };
}

function register(api, deps) {
  const P = deps.prefix || '/api/soc', E = createEstate(deps);
  deps.estateApi = E;
  api.route('GET', `${P}/netops/estate`, wrap(deps, null, () => E.build()));
}

module.exports = { register, createEstate, lname };
