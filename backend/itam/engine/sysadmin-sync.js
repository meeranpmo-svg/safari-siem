// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Windows servers → the AI Windows Server Administrator, Exchange servers → the AI Exchange Server Administrator (SIEM
// sysadmin server list). Once a server or VM is in IT Asset Management (approved from Asset Discovery, vCenter, Nutanix
// or added by hand) with a Windows OS and an IP address, it is added there automatically; an Exchange server is added
// to both (it is a Windows server too).
//   GET  /sysadmin-sync          {settings, last, pending[], sent[]}       operator
//   POST /sysadmin-sync/run      send now                                   admin
//   PUT  /sysadmin-sync/settings {auto: true|false}                         admin
// Exchange is recognised only from facts in the asset record, and the reason is sent with it (shown on the page):
// installed software "Microsoft Exchange Server", a tag "exchange", the OS / model / notes naming Exchange, or a host
// name such as EXCH01 / MBX02 / EX2019-1, or a Windows server named MAIL01 / CORP-MAIL; and from engine/exchange-evidence.js
// (Active Directory's Exchange server objects, Exchange cmdlet logs from the Windows agent, Exchange ports, Business Services). An asset recognised as Exchange counts as a Windows server even when its OS is
// not filled in (Exchange runs only on Windows). The IP is the asset's own, else the address Asset Discovery saw for it.
// Runs every 5 minutes when auto is on (default). A server already in the list (same IP) is not added twice; when it is
// recognised as Exchange it gains the Exchange role (once - if an administrator takes the role away again it stays away).
// A server an administrator removed there is not sent again. A server-looking asset that is NOT sent is listed with the
// reason (GET → skipped[]). No credentials are copied: the WinRM logins are set once in
// the SIEM (write-only). Uses the same SIEM link as Connect to SIEM (config discovery.siem).
// Self-contained (stored collections), added with one registration line (install/add-sysadmin-sync.sh).
const fs = require('node:fs');

const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const low = (v) => String(v || '').toLowerCase();
const SYS = { user: 'system:itam-sysadmin-sync', role: 'admin' };
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function ipOf(a) { return [a.mgmt_ip, a.ip, a.discovery && a.discovery.ip].find((x) => IP_RE.test(String(x || ''))) || ''; }
const winOs = (a) => /windows/.test(low([a.os, a.discovery && a.discovery.os].join(' '))) || (a.software || []).some((x) => /windows server/i.test(String(x && (x.name || x))));
/* {ok, why} for one asset: why it is (not) sent. ipFn: the IP to use (asset, else discovery) */
function winCheck(a, ipFn, exFn) {
  if (!a || CLOSED[a.status]) return { ok: false, why: 'retired' };
  const ex = (exFn || exchangeWhy)(a), win = winOs(a);
  if (!ex && !win) return { ok: false, why: 'not a Windows server' };
  if (!['server', 'vm'].includes(a.type)) return { ok: false, why: `type is "${a.type}" - set the type to Server or VM` };
  if (!(ipFn ? ipFn(a) : ipOf(a))) return { ok: false, why: 'no IP address - add the management IP' };
  return { ok: true };
}
function isWindows(a) { return winCheck(a).ok; }
function exchangeWhy(a) {
  const sw = (a.software || []).find((s) => /microsoft exchange server/i.test(String(s && (s.name || s))));
  if (sw) return 'software: ' + String(sw.name || sw).slice(0, 80);
  if ((a.tags || []).map(low).includes('exchange')) return 'tag: exchange';
  const txt = [a.os, a.model, a.notes].map(String).join(' ');
  if (/\bexchange\b/i.test(txt)) return 'asset record mentions Exchange';
  const host = low(a.name).split('.')[0];
  if (/^(exch|exchange|mbx|exc|ex20\d\d|ex1[369])[-_]?\d*[a-z]?$|[-_](exch|mbx|exchange)\d*$/.test(host)) return 'host name ' + a.name;
  // a Windows server named MAIL01 / CORP-MAIL / MAILSRV2: on Windows, a mail server is Exchange
  if (/(^|[-_])mail(srv|svr|server)?[-_]?\d*[a-z]?($|[-_])/.test(host) && winOs(a)) return 'host name ' + a.name + ' (Windows mail server)';
  return '';
}
function idOf(a, taken) {
  let base = low(a.name || ipOf(a)).split('.')[0].replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 34);
  if (base.length < 2) base = 'srv-' + ipOf(a).replace(/[^0-9]+/g, '-');
  if (!/^[a-z0-9]/.test(base)) base = 's' + base;
  let id = base.slice(0, 40), n = 2;
  while (taken.has(id)) id = `${base.slice(0, 36)}-${n++}`;
  return id;
}

function createSysadminSync(app, opts = {}) {
  const { store } = app;
  const col = store.collection('sysadmin_sync'), conf = store.collection('sysadmin_sync_settings'), assets = store.collection('assets');
  const sc = ((app.config && app.config.discovery) || {}).siem || {};
  const base = String(sc.base_url || 'http://127.0.0.1:9120').replace(/\/+$/, ''), prefix = sc.prefix || '/api/soc';
  const request = opts.request || require('./discovery/httpc').request;
  const read = opts.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  let last = (conf.get('last') || {}).value || null, running = null;   // kept across a restart so the page shows the last result

  function settings() { return Object.assign({ auto: true }, (conf.get('settings') || {}).values || {}); }
  function secret() {
    if (!sc.secret_file) throw bad('SIEM link not configured (discovery.siem.secret_file)', 503);
    let v; try { v = String(read(sc.secret_file)).trim(); } catch (e) { throw bad(`SIEM proxy secret file not readable (${e.code || 'error'})`, 503); }
    if (v.startsWith('{')) { try { v = String(JSON.parse(v).proxy_secret || ''); } catch { v = ''; } }
    if (v.length < 16) throw bad('SIEM proxy secret missing', 503);
    return v;
  }
  async function call(method, path, who, body) {
    const headers = { 'X-Sentra-Proxy-Secret': secret(), 'X-Auth-User': String(who.user).slice(0, 200), 'X-Auth-Role': 'admin', Accept: 'application/json' };
    if (body) headers['Content-Type'] = 'application/json';
    let r; try { r = await request(base + prefix + path, { method, headers, body: body ? JSON.stringify(body) : null, timeoutMs: 20000 }); } catch (e) { throw bad(`SIEM not reachable (${e.code || e.message || 'error'})`, 502); }
    if (r.status === 401 || r.status === 403) throw bad('the SIEM refused the platform credentials (check the proxy secret file)', 502);
    if (r.status === 404) throw bad('the SIEM does not have the AI Server Administrators yet - update the SIEM engine', 502);
    return r;
  }
  const devs = store.collection('disc_devices');
  const ipFor = (a) => ipOf(a) || ((devs.all((d) => d.asset_id === a.id && d.ip)[0] || {}).ip || '');
  // Exchange from the asset's own facts, else from what Business Services / the Email Route Map register found (one read per call)
  const exFnOf = () => {
    let H = null;
    try { H = require('./exchange-evidence').exchangeHints(app); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; /* an older install without the shared evidence: the asset's own facts only */ }
    return (a) => exchangeWhy(a) || (H ? H.forAsset(a, [ipFor(a)]) : '');
  };
  const candidates = (exFn = exFnOf()) => assets.all((a) => winCheck(a, ipFor, exFn).ok);
  const skipped = (exFn = exFnOf()) => assets.all((a) => !CLOSED[a.status]).map((a) => ({ a, r: winCheck(a, ipFor, exFn) })).filter((x) => !x.r.ok && x.r.why !== 'not a Windows server' && x.r.why !== 'retired')
    .map((x) => ({ asset_id: x.a.id, name: x.a.name, type: x.a.type, os: x.a.os || '', exchange: exFn(x.a) || null, why: x.r.why }));

  async function run(who = SYS) {
    if (running) return running;
    running = (async () => {
      const at = new Date(now()).toISOString(), out = { at, by: who.user, ok: true, added: [], upgraded: [], already: 0, skipped_removed: 0, failed: [] };
      try {
        // the servers that SEND Exchange message-tracking logs to the SIEM are Exchange servers - kept for the Exchange page and
        // this sync (engine/exchange-evidence.js). A SIEM without the search, or no such logs, only means no evidence from here.
        try {
          const ask = (field) => call('POST', '/top', who, { q: 'src_type:exchange', field, from: 'now-7d', to: 'now', limit: 100 });
          const vals = (x) => (x && x.status === 200 && x.json && Array.isArray(x.json.values) ? x.json.values.map((v) => String(v.v || '').trim()).filter(Boolean).slice(0, 100) : null);
          const [h, ip] = await Promise.all([ask('host'), ask('host_ip')]);
          if (vals(h) || vals(ip)) store.collection('exchange_seen').put({ id: 'siem', names: vals(h) || [], ips: vals(ip) || [], at });
          out.exchange_log_senders = (vals(h) || []).length;
          // Windows agent: the "MSExchange Management" log exists only on Exchange servers (Exchange runs cmdlets there all day)
          const cm = (field) => call('POST', '/top', who, { q: 'action:exchange-cmdlet', field, from: 'now-30d', to: 'now', limit: 200 });
          const [ch, ci] = await Promise.all([cm('host'), cm('host_ip')]);
          if (vals(ch) || vals(ci)) store.collection('exchange_seen').put({ id: 'siem-cmdlets', names: vals(ch) || [], ips: vals(ci) || [], at });
        } catch (e) { out.exchange_logs_error = String(e.message || e).slice(0, 200); }
        // Active Directory's own list of the Exchange organisation's servers (SIEM AD sync, configuration partition)
        try {
          const x = await call('GET', '/identity/exchange-servers', who);
          if (x.status === 200 && x.json && x.json.available) {
            const items = (x.json.items || []).slice(0, 200);
            store.collection('exchange_seen').put({ id: 'ad', names: items.map((i) => i.name).concat(items.map((i) => i.fqdn)).filter(Boolean), servers: items, at });
            out.exchange_in_ad = items.length;
          } else if (x.status === 200) out.exchange_in_ad = null;
        } catch (e) { out.exchange_ad_error = String(e.message || e).slice(0, 200); }
        const r = await call('GET', '/sysadmin/targets', who);
        if (r.status !== 200) throw bad(`SIEM: HTTP ${r.status}`, 502);
        const list = (r.json && r.json.items) || [];
        // the servers the SIEM's Windows / Exchange Admin already treats as Exchange: the Servers pages count them too
        const exT = list.filter((t) => (t.roles || []).includes('exchange'));
        store.collection('exchange_seen').put({ id: 'siem-admin', names: exT.map((t) => String(t.name || '')).filter(Boolean).slice(0, 200), ips: exT.map((t) => t.ip).filter(Boolean).slice(0, 200), assets: exT.map((t) => t.asset_id).filter(Boolean).slice(0, 200), at });
        out.exchange_servers = exT.length;
        const byIp = new Map(list.map((t) => [t.ip, t])), taken = new Set(list.map((t) => t.id));
        const exFn = exFnOf();
        for (const a of candidates(exFn)) {
          const ip = ipFor(a), why = exFn(a), roles = why ? ['windows', 'exchange'] : ['windows'], rec = col.get(a.id), cur = byIp.get(ip);
          if (cur) {
            out.already++;
            // recognised as Exchange (later, or a server someone added by hand): gains the role once; an administrator who
            // takes it away again is not overruled (rec.exchange_sent)
            if (why && !(cur.roles || []).includes('exchange') && !(rec && rec.exchange_sent)) {
              const nr = [...new Set((cur.roles || ['windows']).concat(['windows', 'exchange']))];
              const u = await call('POST', '/sysadmin/targets', who, { id: cur.id, roles: nr, detected_by: why });
              if (u.status < 300) { out.upgraded.push({ asset_id: a.id, server_id: cur.id, name: cur.name, why }); col.put(Object.assign({}, rec || {}, { id: a.id, server_id: cur.id, ip, roles: nr, why, state: rec ? rec.state : 'present', exchange_sent: true, at })); }
              else out.failed.push({ asset_id: a.id, name: a.name, ip, error: 'Exchange role: ' + ((u.json && (u.json.error || (u.json.errors || []).join('; '))) || `HTTP ${u.status}`) });
            } else if (!rec) col.put({ id: a.id, server_id: cur.id, ip, roles: cur.roles, state: 'present', at });
            continue;
          }
          if (rec && rec.state === 'sent') { out.skipped_removed++; continue; }   // removed by an administrator on purpose
          const id = idOf(a, taken);
          const body = { id, name: String(a.name || ip).slice(0, 80), ip, roles, site: a.site || 'Unassigned', criticality: 2, source: 'itam', asset_id: String(a.id).slice(0, 80),
            detected_by: why || 'Windows: ' + String(a.os || 'software').slice(0, 80), notes: `from IT Asset Management ${a.id}${a.os ? ' · ' + a.os : ''}`.slice(0, 500) };
          const p = await call('POST', '/sysadmin/targets', who, body);
          if (p.status >= 300) { out.failed.push({ asset_id: a.id, name: a.name, ip, error: (p.json && (p.json.error || (p.json.errors || []).join('; '))) || `HTTP ${p.status}` }); continue; }
          taken.add(id); byIp.set(ip, body);
          col.put({ id: a.id, server_id: id, ip, roles, why, state: 'sent', exchange_sent: !!why, at });
          out.added.push({ asset_id: a.id, server_id: id, name: body.name, ip, roles, why: body.detected_by });
        }
      } catch (e) { out.ok = false; out.error = e.message; }
      if (out.added.length || out.upgraded.length || out.failed.length || who !== SYS) audit({ by: who.user, role: who.role, ip: who.ip, action: 'sysadmin_sync.run', target: 'sysadmin', detail: { added: out.added.length, upgraded: out.upgraded.length, failed: out.failed.length, error: out.error || null } });
      last = out; running = null; try { conf.put({ id: 'last', value: out }); } catch (e) { /* status only */ }
      return out;
    })();
    return running;
  }
  function view() {
    const sent = col.all(), seen = new Set(sent.map((s) => s.id)), exF = exFnOf();
    return { settings: settings(), last, sent, pending: candidates(exF).filter((a) => !seen.has(a.id)).map((a) => ({ asset_id: a.id, name: a.name, ip: ipFor(a), os: a.os || '', exchange: exF(a) || null, site: a.site || '' })), skipped: skipped() };
  }
  function putSettings(b, who) {
    const v = Object.assign(settings(), 'auto' in b ? { auto: b.auto === true } : {});
    conf.put({ id: 'settings', values: v, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'sysadmin_sync.settings', target: 'settings', detail: v });
    return view();
  }
  function tick() { return settings().auto ? run() : undefined; }   // a failure reaches the job register (engine/errors.js)
  return { run, view, putSettings, tick, candidates, skipped };
}

function registerSysadminSync(srv, app) {
  const S = createSysadminSync(app);
  srv.route('GET', '/sysadmin-sync', (ctx) => { ctx.need('operator'); return S.view(); });
  srv.route('POST', '/sysadmin-sync/run', async (ctx) => { ctx.need('admin'); return S.run(ctx.who); });
  srv.route('PUT', '/sysadmin-sync/settings', (ctx) => { ctx.need('admin'); return S.putSettings(ctx.body || {}, ctx.who); });
  const t1 = setTimeout(guardOf(app, 'sysadmin-sync.tick', S.tick), 75000), t2 = setInterval(guardOf(app, 'sysadmin-sync.tick', S.tick), 5 * 60000);
  if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  (app.addons = app.addons || {}).sysadminSync = S;   // reachable from Sync all now (engine/reconcile.js)
  return S;
}

module.exports = { createSysadminSync, registerSysadminSync, isWindows, exchangeWhy, ipOf, winCheck };
