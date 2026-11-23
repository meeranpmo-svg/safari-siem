// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ip4 = require('./discovery/ipv4');
/*
 * Scan-target planner - the Network Assistant ({P} = /api/itam; used by Vulnerability Scans -> Request a scan and by the VAPT
 * Workflow scoping). Nobody should have to type a scan target by hand: the targets are built from IP Address Management
 * (engine/ipam.js: the subnets people registered, with the addresses the asset register and Asset Discovery actually see) and the
 * assistant proposes what to scan next and what to leave out. It reads; it never files a scan, never changes the scope - a person
 * picks a proposal, the form fills, and the scan still goes through the scope and the four-eyes approval of Vulnerability Scans.
 *   per subnet   live addresses (observed), the addresses inside the approved internal scan scope, FRAGILE devices to leave out
 *                (printers, IP phones, cameras / recorders, door controllers, UPS, OT - from the asset record's type / name / model or
 *                the discovered host name, word-bounded), the last finished Greenbone scan that covered it, open high / critical
 *                findings (a retest), devices in no asset record
 *   targets      the live, non-fragile addresses inside the scope, folded into ranges (10.0.5.10-20) - never the whole subnet, so
 *                an empty address is not probed; at most MAX_HOSTS (the Vulnerability Scans limit) per proposal
 *   priority     0-100, every point itemised: never scanned 40 / last scan over 90 days 35 / over 30 days 25, open high / critical
 *                findings 15 (retest), devices in no asset record 2 each (up to 20), a server / data-centre / DMZ / production subnet 10;
 *                a subnet outside the scope is listed with what the administrator has to add, not proposed
 *   scope        for the administrator: private subnets of the address plan the scan scope does not cover, networks in use that are
 *                not in the plan (register them first), and the fragile addresses to add to the scope exclusions
 *   GET  /scan-targets                 operator  {assistant, subnets, recommendations, scope_proposal, unplanned, limits}
 *   GET  /scan-targets?within=a,b      operator  only the addresses inside these targets (the VAPT Workflow's scope)
 * Host names are internal: operators and administrators.
 */
const DAY = 86400000, MAX_HOSTS = 4096;
const FRAGILE = /\b(printer|mfp|plotter|ip[ _-]?phone|phone|voip|cisco[ _-]?(?:cp|ip[ _-]?phone)|camera|cctv|nvr|dvr|hikvision|door|access[ _-]?control|zkteco|badge|ups|pdu|plc|scada|hmi|ot|bms|hvac|medical)\b/i;
const CORE = /\b(server|servers|dc|data ?cent(?:er|re)|dmz|prod|production|core|db|database)\b/i;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

function fold(nums) {   // ascending numbers -> ['a', 'a-b', ...]
  const out = []; let a = null, b = null;
  for (const n of nums) { if (a === null) { a = b = n; continue; } if (n === b + 1) { b = n; continue; } out.push(a === b ? ip4.ipStr(a) : ip4.ipStr(a) + '-' + ip4.ipStr(b)); a = b = n; }
  if (a !== null) out.push(a === b ? ip4.ipStr(a) : ip4.ipStr(a) + '-' + ip4.ipStr(b));
  return out;
}

function createScanTargets(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const A = () => app.addons || {};
  const col = (n) => { try { return store.collection(n); } catch (e) { return null; /* a module that is not installed has no collection */ } };
  const all = (n, f) => { const c = col(n); return c ? c.all(f || (() => true)) : []; };
  const parse = (L) => (L || []).map((t) => { try { return ip4.parseTarget(t); } catch (e) { return null; /* a malformed entry in the stored scope is ignored here; Vulnerability Scans refuses it on save */ } }).filter(Boolean);
  const inR = (R, n) => R.some((r) => n >= r.first && n <= r.last);

  function ipamView() {
    const X = A().ipam || (() => { try { return require('./ipam').createIpam(app, { noTimer: true }); } catch (e) { return null; /* IP Address Management not installed */ } })();
    if (!X) return null;
    return X.view({ role: 'operator' });
  }

  function plan(q) {
    const v = ipamView();
    if (!v) return { installed: false, note: 'IP Address Management is not installed - targets have to be typed until it is.', subnets: [], recommendations: [], unplanned: [] };
    const scope = (col('vulnscan') && col('vulnscan').get('scope')) || { allowed: [], exclude: [] };
    const allowed = parse(scope.allowed), excluded = parse(scope.exclude);
    const within = q && q.within ? parse(String(q.within).split(',').map((x) => x.trim()).filter(Boolean)) : null;
    // the asset behind each address, to judge fragility
    const assets = new Map(all('assets').map((a) => [a.id, a]));
    const fragileWhy = (addr) => {
      for (const ref of addr.assets || []) { const a = assets.get(ref.id) || {}; const t = [a.type, a.subtype, a.category, a.name, a.model, a.make].filter(Boolean).join(' '); const m = FRAGILE.exec(t); if (m) return 'asset ' + (a.name || ref.id) + ' (' + m[1].toLowerCase() + ')'; }
      for (const h of addr.hosts || []) { const m = FRAGILE.exec(String(h).replace(/[-_.]/g, ' ')); if (m) return 'host name ' + h + ' (' + m[1].toLowerCase() + ')'; }
      return null;
    };
    // last finished scan per address, and open high / critical findings per host
    const scans = all('vulnscan_scans', (x) => (x.state === 'done' || x.state === 'stopped') && x.finished_at).map((x) => ({ id: x.id, at: Date.parse(x.finished_at), R: parse(x.targets), X: parse(x.exclude) }));
    const lastScan = (n) => { let best = null; for (const s of scans) if (inR(s.R, n) && !inR(s.X, n) && (!best || s.at > best.at)) best = s; return best; };
    const hot = new Set(all('vulnscan_findings', (f) => f.status === 'open' && ['critical', 'high'].includes(f.severity)).map((f) => f.host));
    const addrs = (v.addresses || []).map((a) => Object.assign({}, a, { n: ip4.parseIp(a.ip) })).filter((a) => a.n !== null && ip4.isPrivate(a.n));
    const t = now(), subs = [];
    for (const s of v.subnets || []) {
      const base = ip4.parseIp(String(s.cidr).split('/')[0]), bits = Number(String(s.cidr).split('/')[1]);
      const live = addrs.filter((a) => a.subnet === s.id && (!within || inR(within, a.n)));
      if (within && !live.length) continue;
      const fragile = [], scan = [], outside = [];
      for (const a of live) { const why = fragileWhy(a); if (why) { fragile.push({ ip: a.ip, why }); continue; } if (inR(excluded, a.n)) continue; if (allowed.length && inR(allowed, a.n)) scan.push(a); else outside.push(a); }
      scan.sort((x, y) => x.n - y.n);
      const last = live.map((a) => lastScan(a.n)).filter(Boolean).sort((x, y) => y.at - x.at)[0] || null;
      const never = live.filter((a) => !lastScan(a.n)).length, days = last ? Math.floor((t - last.at) / DAY) : null;
      const unknown = live.filter((a) => !(a.assets || []).length).length, retest = live.filter((a) => hot.has(a.ip)).length;
      const why = []; let p = 0;
      if (!last) { p += 40; why.push('never scanned (+40)'); } else if (days > 90) { p += 35; why.push('last scanned ' + days + ' days ago (+35)'); } else if (days > 30) { p += 25; why.push('last scanned ' + days + ' days ago (+25)'); }
      if (last && never) why.push(never + ' live address(es) never scanned');
      if (retest) { p += 15; why.push(retest + ' host(s) with open high / critical findings - retest (+15)'); }
      if (unknown) { const k = Math.min(20, unknown * 2); p += k; why.push(unknown + ' device(s) in no asset record (+' + k + ')'); }
      if (CORE.test([s.name, s.purpose, s.site].join(' '))) { p += 10; why.push('server / data-centre / production network (+10)'); }
      const targets = fold(scan.slice(0, MAX_HOSTS).map((a) => a.n));
      const pPrivate = base !== null && ip4.isPrivate(base);
      subs.push({ id: s.id, cidr: s.cidr, name: s.name, site: s.site, vlan: s.vlan, purpose: s.purpose, live: live.length, to_scan: scan.length, outside_scope: outside.length, fragile, unknown, retest,
        last_scan: last ? { id: last.id, at: new Date(last.at).toISOString(), days } : null, priority: Math.min(100, p), why, targets, exclude: fragile.map((f) => f.ip), private: pPrivate,
        truncated: scan.length > MAX_HOSTS, blocked: !live.length ? 'no live address seen in this subnet' : !scan.length ? (outside.length ? (allowed.length ? 'outside the approved scan scope - an administrator adds ' + s.cidr : 'no internal scan scope yet - an administrator sets it') : 'every live address is fragile or excluded') : null, bits });
    }
    subs.sort((a, b) => b.priority - a.priority || b.live - a.live);
    const recommendations = subs.filter((s) => !s.blocked && s.priority > 0).slice(0, 8).map((s) => ({ subnet: s.id, name: s.name + ' (' + s.cidr + ')', site: s.site, targets: s.targets, exclude: s.exclude, hosts: s.to_scan, priority: s.priority, why: s.why,
      suggested_name: (s.retest && s.last_scan ? 'Retest ' : 'Scan ') + s.name + (s.site ? ' - ' + s.site : ''), suggested_reason: s.why.join('; ') + ' (proposed by the Network Assistant from IP Address Management)' }));
    // for the administrator: what the scope does not cover, and what to exclude
    const notCovered = subs.filter((s) => s.private && s.outside_scope > 0).map((s) => s.cidr);
    const exclAdd = [...new Set(subs.flatMap((s) => s.exclude))].filter((ip) => !inR(excluded, ip4.parseIp(ip)));
    const unplanned = (v.proposals || []).filter((p) => ip4.isPrivate(ip4.parseIp(String(p.cidr).split('/')[0]))).map((p) => ({ cidr: p.cidr, addresses: p.addresses, sample: p.sample, note: 'in use but not in the address plan - register it in IP Address Management, then it can be proposed' }));
    return { installed: true, generated_at: new Date(t).toISOString(), assistant: 'Network Assistant - proposes targets from IP Address Management; a person files the scan and a different person approves it',
      scope: { allowed: scope.allowed || [], exclude: scope.exclude || [], set: allowed.length > 0 }, limits: { max_hosts: MAX_HOSTS },
      kpis: { subnets: subs.length, live: subs.reduce((a, s) => a + s.live, 0), never_scanned: subs.filter((s) => !s.last_scan && s.live).length, fragile: subs.reduce((a, s) => a + s.fragile.length, 0), outside_scope: notCovered.length },
      subnets: subs.map(({ bits, ...x }) => x), recommendations, unplanned,
      scope_proposal: { add_allowed: notCovered, add_allowed_unplanned: unplanned.map((u) => u.cidr).filter((c) => !inR(allowed, ip4.parseIp(c.split('/')[0]) + 1)), add_exclude: exclAdd, why: notCovered.length || exclAdd.length ? 'Private subnets of the address plan with live devices the scope does not cover, and fragile devices to keep out of every scan. An administrator reviews and saves the scope on Vulnerability Scans.' : 'The scope covers every planned subnet with live devices.' },
      note: 'Targets are the live addresses only (never the empty part of a subnet). Fragile devices are left out; check the list before scanning.' };
  }
  return { plan, FRAGILE, fold };
}

function registerScanTargets(srv, app, P0) {
  const P = P0 && P0.plan ? P0 : createScanTargets(app, P0 || {});
  app.addons = app.addons || {}; app.addons.scanTargets = P;
  srv.route('GET', '/scan-targets', (ctx) => { ctx.need('operator'); const w = ctx.query && ctx.query.within; if (w && String(w).length > 4000) throw httpErr(400, 'within is longer than 4000 characters'); return P.plan(w ? { within: String(w) } : null); });
  return P;
}
module.exports = { createScanTargets, registerScanTargets, fold, FRAGILE };
