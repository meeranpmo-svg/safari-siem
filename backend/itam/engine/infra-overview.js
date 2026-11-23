// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * IT Infrastructure Manager overview (dashboards/infra-manager.html): the asset register's own figures in one answer, so
 * the manager's page shows the same numbers as the pages it opens - never sample telemetry.
 *
 *   createInfraOverview(app) -> { view(role) }
 *   GET /infra-overview   operator (names servers, contracts and devices)
 *
 * Each section comes from the add-on that owns it, read at request time: the register (servers, network devices, storage,
 * warranty), End of Life (lifecycle), Backup Status (backup), Endpoint Central (manageengine - missing patches per
 * computer), Storage (storage arrays), Support Contracts (support-contracts), Database Health (db-health). A section whose
 * add-on is not installed, or whose source has reported nothing yet, is { available: false, why } - it never becomes 0 %,
 * and the page says what to connect. Percentages are only given when there is something to divide by.
 * The SIEM's figures (host / device availability, Oracle instances, Applications Manager, change plans) are read by the
 * page from the SIEM directly.
 */
const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const pct = (n, d) => (d > 0 ? Math.round((n / d) * 1000) / 10 : null);
const s = (v, n = 160) => String(v == null ? '' : v).slice(0, n);

function createInfraOverview(app) {
  const store = app.store, assets = store.collection('assets'), A = () => app.addons || {};
  const off = (why) => ({ available: false, why });
  function safe(name, fn) {
    try { return fn(); } catch (e) {
      try { if (app.log && app.log.every) app.log.every('infra-overview:' + name, 600000, 'warn', 'infra overview: ' + name + ' could not be read', { err: e.message }); } catch (x) { /* logging never stops the answer */ }
      return off('could not be read: ' + s(e.message, 200));
    }
  }

  function register() {
    const live = assets.all((a) => !CLOSED[a.status]);
    const servers = live.filter((a) => a.type === 'server' || a.type === 'vm'), network = live.filter((a) => a.type === 'network');
    const osFam = (a) => { const t = String(a.os || '').toLowerCase(); return /windows/.test(t) ? 'Windows' : /solaris|sunos/.test(t) ? 'Solaris' : /esxi|vmware/.test(t) ? 'ESXi' : /ahv|nutanix/.test(t) ? 'Nutanix AHV' : /linux|red hat|rhel|ubuntu|centos|oracle linux|suse|debian|rocky|alma/.test(t) ? 'Linux' : t ? 'Other' : 'OS not recorded'; };
    const byOs = {}; for (const a of servers) { const k = osFam(a); byOs[k] = (byOs[k] || 0) + 1; }
    const today = new Date(app.now ? app.now() : Date.now()).toISOString().slice(0, 10), in90 = new Date((app.now ? app.now() : Date.now()) + 90 * 86400000).toISOString().slice(0, 10);
    const warranty = live.filter((a) => a.warranty && a.warranty.end && a.warranty.end <= in90 && (a.type === 'server' || a.type === 'network' || a.type === 'storage'));
    return {
      available: true, total: live.length,
      servers: { total: servers.length, physical: servers.filter((a) => a.type === 'server').length, virtual: servers.filter((a) => a.type === 'vm').length, by_os: byOs },
      network: { total: network.length, by_vendor: network.reduce((m, a) => { const v = a.vendor || 'vendor not recorded'; m[v] = (m[v] || 0) + 1; return m; }, {}) },
      storage: { total: live.filter((a) => a.type === 'storage').length },
      warranty: { expired: warranty.filter((a) => a.warranty.end < today).length, within_90d: warranty.filter((a) => a.warranty.end >= today).length,
        items: warranty.sort((x, y) => (x.warranty.end < y.warranty.end ? -1 : 1)).slice(0, 10).map((a) => ({ id: a.id, name: s(a.name || a.asset_tag || a.id), type: a.type, end: a.warranty.end })) },
    };
  }
  function backup() {
    const B = A().backup; if (!B) return off('Backup Status is not installed (install/add-backup.sh)');
    const v = B.view(), m = v.summary || {};
    if (!(m.assets > 0)) return off('no servers in the register to check');
    if (!(m.protected || m.stale || m.failed) && !(v.platforms || []).length) return off('no backup platform is connected - add Veeam / Nutanix / Commvault on Backup Status');
    const scope = (m.assets || 0) - (m.exempt || 0);
    return { available: true, assets: m.assets, protected: m.protected || 0, stale: m.stale || 0, failed: m.failed || 0, none: m.none || 0, exempt: m.exempt || 0, protected_pct: pct(m.protected || 0, scope) };
  }
  function patch() {
    const M = A().manageengine; if (!M) return off('ManageEngine is not installed (install/add-manageengine.sh)');
    const list = (M.computers().computers || []), rep = list.filter((x) => x.missing != null);
    if (!list.length) return off('Endpoint Central has not reported any computer - connect it on ManageEngine');
    if (!rep.length) return off('Endpoint Central reported computers but no patch status yet');
    const ok = rep.filter((x) => Number(x.missing) === 0).length, crit = rep.filter((x) => Number(x.critical) > 0).length;
    return { available: true, computers: list.length, reported: rep.length, compliant: ok, critical_missing: crit, compliant_pct: pct(ok, rep.length),
      worst: rep.filter((x) => Number(x.missing) > 0).sort((a, b) => (Number(b.critical) || 0) - (Number(a.critical) || 0) || Number(b.missing) - Number(a.missing)).slice(0, 8)
        .map((x) => ({ name: s(x.asset_name || x.name), missing: Number(x.missing), critical: Number(x.critical) || 0, health: s(x.health, 40) })) };
  }
  function lifecycle() {
    const L = A().lifecycle; if (!L) return off('End of Life is not installed (install/add-lifecycle.sh)');
    const v = L.view({}), it = (v.items || []).filter((i) => i.status === 'eol' || i.status === 'soon'), m = v.summary || {};
    return { available: true, eol: m.eol || 0, soon: m.soon || 0, servers_eol: m.servers || 0, network_eol: m.network || 0, isolation_required: m.isolation_required || 0,
      items: it.sort((a, b) => (a.status === b.status ? (a.days == null ? -1 : b.days == null ? 1 : a.days - b.days) : a.status === 'eol' ? -1 : 1)).slice(0, 10)
        .map((i) => ({ name: s(i.name || i.hostname || i.serial || '—'), type: s(i.type, 30), product: s(i.product, 80), status: i.status, eol: i.eol || null, days: i.days == null ? null : i.days })) };
  }
  function storage() {
    const S = A().storage; if (!S) return off('Storage is not installed (install/add-storage.sh)');
    const v = S.view(), m = v.summary || {};
    if (!m.arrays) return off('no storage array is connected - add NetApp / HPE MSA / Synology on Storage');
    if (!m.read) return off(m.arrays + ' storage array(s) configured but not read yet');
    return { available: true, arrays: m.arrays, read: m.read, used_pct: m.used_pct, size_bytes: m.size_bytes, used_bytes: m.used_bytes, failed_disks: m.failed_disks || 0, critical: m.critical || 0, high: m.high || 0,
      list: (v.arrays || []).filter((x) => x.at).map((x) => ({ name: s(x.platform && (x.platform.label || x.platform.id)), used_pct: x.capacity.used_pct, size_bytes: x.capacity.size_bytes, failed_disks: x.disks ? x.disks.failed : 0, worst: x.worst })) };
  }
  function contracts(role) {
    const C = A().supportContracts; if (!C) return off('Support Contracts is not installed (install/add-support-contracts.sh)');
    const v = C.view(role), m = v.summary || {};
    if (!m.contracts) return off('no support contract recorded - add them on Support Contracts');
    return { available: true, contracts: m.contracts, expired: m.expired || 0, expiring: m.expiring || 0, uncovered_assets: m.uncovered_assets || 0,
      renewing: (v.contracts || []).filter((c) => c.state === 'expired' || c.state === 'expiring').slice(0, 8).map((c) => ({ vendor: s(c.vendor, 60), product: s(c.product, 80), end: c.end || null, days_left: c.days_left == null ? null : c.days_left, state: c.state })) };
  }
  function databases() {
    const H = A().dbHealth; if (!H) return off('Database Health is not installed (install/add-db-health.sh)');
    const list = (H.databases().databases || []);
    if (!list.length) return off('no database registered for monitoring - add one on All Databases');
    return { available: true, registered: list.length };
  }
  function view(role) {
    return { at: new Date(app.now ? app.now() : Date.now()).toISOString(), register: safe('register', register), backup: safe('backup', backup), patch: safe('patch', patch), lifecycle: safe('lifecycle', lifecycle),
      storage: safe('storage', storage), contracts: safe('contracts', () => contracts(role)), databases: safe('databases', databases) };
  }
  return { view };
}

function registerInfraOverview(srv, app) {
  const O = createInfraOverview(app);
  srv.route('GET', '/infra-overview', (ctx) => { ctx.need('operator'); return O.view(ctx.who && ctx.who.role); });
  (app.addons = app.addons || {}).infraOverview = O;
  return O;
}

module.exports = { createInfraOverview, registerInfraOverview };
