// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Which servers are Exchange servers, from what the platform already found - shared by Servers by platform (engine/servers.js)
// and the sync to the AI Exchange Administrator (engine/sysadmin-sync.js), so the Exchange page and that list agree.
//   Business Services (engine/service-map.js): Outlook on the web answered on HTTPS, or Microsoft Exchange Server installed
//   Email Route Map server register (mail-reputation route_profile): a server recorded with role exchange / hybrid / edge
//   SIEM: the hosts that sent Exchange message-tracking logs in the last 7 days (saved by engine/sysadmin-sync.js every run)
//   SIEM Windows / Exchange Admin: the servers that already carry the Exchange role there (saved by the same sync)
//   Active Directory: the Exchange organisation's server objects (SIEM AD sync, saved by the same sync) - the authoritative list
//   SIEM: hosts whose Windows agent sends the MSExchange Management (cmdlet) log
//   Asset Discovery: TCP 2525, or 444 beside 443, open on the host
// Each hint carries its reason (shown on the page and sent with the server). Matched to an asset by its link, its IP, then the
// name an administrator recorded in the register; the asset record's own facts (software, tag, host name pattern) stay in
// exchangeWhy. Read-only, no route of its own.
const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
const short = (v) => low(v).split('.')[0];

function exchangeHints(app) {
  const byIp = new Map(), byName = new Map(), byAsset = new Map();
  const put = (ip, names, assetId, why) => {
    if (ip && !byIp.has(ip)) byIp.set(ip, why);
    for (const n of names) { const k = short(n); if (k.length >= 3 && !byName.has(k)) byName.set(k, why); }
    if (assetId && !byAsset.has(assetId)) byAsset.set(assetId, why);
  };
  try {
    const S = app.addons && app.addons.serviceMap;
    if (S && typeof S.view === 'function') {
      for (const r of (S.view('operator').servers || [])) {
        const x = (r.services || []).find((v) => v.id === 'exchange' && v.confidence === 'confirmed'); if (!x) continue;
        const ev = (x.evidence || [])[0];
        put(r.ip, [r.host], r.asset && r.asset.id, 'Business Services: ' + (ev ? ev.detail : 'Microsoft Exchange found'));
      }
    }
  } catch (e) {
    try { if (app.log && app.log.every) app.log.every('exchange-evidence:svc', 600000, 'warn', 'Exchange evidence: Business Services could not be read', { err: e.message }); } catch (x) { /* logging never stops the answer */ }
  }
  try {
    const prof = app.store.collection('mailrep').get('route_profile');
    for (const sv of (prof && prof.servers) || []) {
      if (!/^(exchange|hybrid|edge)$/i.test(String(sv.role || ''))) continue;
      put(sv.private_ip || null, [sv.name, sv.dns_name], null, 'Email Route Map register: role ' + low(sv.role));
      for (const ip of sv.public_ips || []) if (!byIp.has(ip)) byIp.set(ip, 'Email Route Map register: role ' + low(sv.role));
    }
  } catch (e) {
    try { if (app.log && app.log.every) app.log.every('exchange-evidence:route', 600000, 'warn', 'Exchange evidence: the mail server register could not be read', { err: e.message }); } catch (x) { /* logging never stops the answer */ }
  }
  try {
    const seen = app.store.collection('exchange_seen').get('siem');
    if (seen) {
      const why = 'SIEM: sends Exchange message-tracking logs';
      for (const ip of seen.ips || []) if (ip && !byIp.has(ip)) byIp.set(ip, why);
      for (const n of seen.names || []) { const k = short(n); if (k.length >= 3 && !byName.has(k)) byName.set(k, why); }
    }
  } catch (e) {
    try { if (app.log && app.log.every) app.log.every('exchange-evidence:siem', 600000, 'warn', 'Exchange evidence: the SIEM log senders could not be read', { err: e.message }); } catch (x) { /* logging never stops the answer */ }
  }
  try {
    const adm = app.store.collection('exchange_seen').get('siem-admin');
    if (adm) {
      const why = 'Windows / Exchange Admin (SIEM): has the Exchange role';
      for (const ip of adm.ips || []) if (ip && !byIp.has(ip)) byIp.set(ip, why);
      for (const n of adm.names || []) { const k = short(n); if (k.length >= 3 && !byName.has(k)) byName.set(k, why); }
      for (const id of adm.assets || []) if (id && !byAsset.has(id)) byAsset.set(id, why);
    }
  } catch (e) {
    try { if (app.log && app.log.every) app.log.every('exchange-evidence:admin', 600000, 'warn', 'Exchange evidence: the SIEM Exchange servers could not be read', { err: e.message }); } catch (x) { /* logging never stops the answer */ }
  }
  try {
    const adx = app.store.collection('exchange_seen').get('ad');
    for (const sv of (adx && adx.servers) || []) {
      const why = 'Active Directory: Exchange server object' + (sv.version ? ' (' + sv.version + ')' : '') + (sv.roles && sv.roles.length ? ', ' + sv.roles.join(' / ') : '');
      for (const n of [sv.name, sv.fqdn]) { const k = short(n); if (k.length >= 3 && !byName.has(k)) byName.set(k, why); }
    }
    const cm = app.store.collection('exchange_seen').get('siem-cmdlets');
    if (cm) {
      const why = 'SIEM: Exchange management cmdlet log (Windows agent)';
      for (const ip of cm.ips || []) if (ip && !byIp.has(ip)) byIp.set(ip, why);
      for (const n of cm.names || []) { const k = short(n); if (k.length >= 3 && !byName.has(k)) byName.set(k, why); }
    }
  } catch (e) {
    try { if (app.log && app.log.every) app.log.every('exchange-evidence:ad', 600000, 'warn', 'Exchange evidence: the AD / cmdlet lists could not be read', { err: e.message }); } catch (x) { /* logging never stops the answer */ }
  }
  // Asset Discovery's port sweep: 2525 (mailbox transport) or 444 (back-end HTTPS) open next to 443 is Exchange's own layout
  try {
    for (const d of app.store.collection('disc_devices').all((x) => Array.isArray(x.open_ports) && (x.open_ports.includes(2525) || (x.open_ports.includes(444) && x.open_ports.includes(443))))) {
      const why = 'Asset Discovery: Exchange ports open (' + d.open_ports.filter((p) => [25, 443, 444, 587, 2525].includes(p)).join(', ') + ')';
      if (d.asset_id && !byAsset.has(d.asset_id)) byAsset.set(d.asset_id, why);
      for (const ip of [d.ip].concat(d.ips || [])) if (ip && !byIp.has(ip)) byIp.set(ip, why);
    }
  } catch (e) {
    try { if (app.log && app.log.every) app.log.every('exchange-evidence:ports', 600000, 'warn', 'Exchange evidence: discovery ports could not be read', { err: e.message }); } catch (x) { /* logging never stops the answer */ }
  }
  // the hint for one asset: by asset link, then its IP(s), then its name / DNS name
  function forAsset(a, ips) {
    if (!a) return '';
    if (byAsset.has(a.id)) return byAsset.get(a.id);
    for (const ip of [a.mgmt_ip].concat(ips || [])) if (ip && byIp.has(ip)) return byIp.get(ip);
    for (const n of [a.name, a.hostname, a.dns_name]) { const k = short(n); if (k.length >= 3 && byName.has(k)) return byName.get(k); }
    return '';
  }
  return { forAsset, count: byIp.size + byName.size + byAsset.size };
}

module.exports = { exchangeHints };
