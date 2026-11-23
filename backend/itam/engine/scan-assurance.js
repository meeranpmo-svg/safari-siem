// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const ip4 = require('./discovery/ipv4');
const { body } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
const { fold, FRAGILE } = require('./scan-targets');
/*
 * Scan Coverage Assurance ({P} = /api/itam; Pentest & Vulnerability Management -> Scan Coverage Assurance). Proves that every
 * connected asset was scanned, and for every one that was not, says WHY and WHAT FIXES IT - then prepares the rescan.
 *   connected   every active asset in the register with an address (management IP or any IP)
 *   evidence    Greenbone (the hosts each finished scan actually reported - vulnscan_results - and every scan request with its
 *               state, error and window), Tenable / Nessus (vapt_scanned), Asset Discovery (when the device last answered)
 *   status      scanned (inside stale_days) | pending (in a requested / approved / running scan) | excluded (left out on purpose) |
 *               failed - with ONE reason, first match wins:
 *                 no_ip            no address in the record                      -> add it, or approve the device in Discovery Studio
 *                 no_scanner       Greenbone is not connected                    -> an admin configures and tests the connection
 *                 out_of_scope     outside the internal scan scope               -> an admin adds the subnet (proposed below)
 *                 rejected         its last scan request was rejected            -> read the approver's note, change and re-request
 *                 scan_failed      its last scan failed / expired                -> the Greenbone error, or approve inside the window
 *                 cut_short        a partial scan ended before reaching it       -> rescan in a smaller batch / longer window
 *                 blocked          scanned but not reported while Discovery saw it answering within 7 days of the scan
 *                                  -> allow the scanner address through the firewall / host firewall, then rescan
 *                 offline          scanned but not reported, and Discovery has not seen it either -> confirm it is in service
 *                 stale            last scanned more than stale_days ago         -> rescan
 *                 never_scanned    in scope, never in a scan                     -> rescan
 *   persistent  failed in 2+ daily snapshots in a row - the fix has not happened; listed first
 *   rescan      every in-scope, non-excluded asset whose fix is a rescan (never_scanned, stale, cut_short, scan_failed, blocked after
 *               its firewall fix) folded into batches of at most 1024 addresses. POST /scan-assurance/rescan FILES them in
 *               Vulnerability Scans (a person; a different person approves there - a scan is a change to systems)
 *   trend       one snapshot a day ('scanassure.snapshot'): coverage % and failures by reason
 *   GET  /scan-assurance                       operator  KPIs, assets with status / reason / fix, rescan batches, scope proposal, trend
 *   GET  /scan-assurance/report?format=        operator  html | csv - the coverage statement                          audited
 *   POST /scan-assurance/rescan                operator  {batches?: [n], hours?}  files the prepared batches            audited
 *   POST /scan-assurance/settings              admin     {stale_days}                                                  audited
 *   forTargets(targets)   used by the VAPT Workflow report: coverage of an engagement's targets
 */
const DAY = 86400000, BATCH = 1024;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const csvCell = (v) => { let t = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return /[",\r\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
const REASON = {
  no_ip: ['No address in the asset record', 'Add the management IP to the asset, or approve the device in Discovery Studio so its address is known.'],
  no_scanner: ['Greenbone is not connected', 'An administrator configures the Greenbone connection on Vulnerability Scans and runs Test the connection.'],
  out_of_scope: ['Outside the internal scan scope', 'An administrator adds the subnet to the scan scope (Vulnerability Scans -> Scope; the Network Assistant fills it).'],
  rejected: ['Its last scan request was rejected', 'Read the approver\'s note on the scan, change what they asked and file the rescan.'],
  scan_failed: ['Its last scan failed or expired', 'Fix the Greenbone error shown, or have the scan approved before its window ends; then file the rescan.'],
  cut_short: ['A partial scan ended before reaching it', 'Rescan in a smaller batch or with a longer window (the prepared batches are smaller).'],
  blocked: ['The device answers the network but not the scanner', 'Allow the Greenbone scanner address through the firewall / host firewall for this device, then file the rescan.'],
  offline: ['Not reported by the scan and not seen by Discovery', 'Confirm the device is still in service; if it is gone, retire it in the asset register.'],
  stale: ['Last scan is older than the policy', 'Included in the prepared rescan.'],
  never_scanned: ['In scope but never scanned', 'Included in the prepared rescan.'],
};
const RESCAN = ['never_scanned', 'stale', 'cut_short', 'scan_failed', 'blocked'];

function createScanAssurance(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const A = () => app.addons || {};
  const col = (n) => { try { return store.collection(n); } catch (e) { return null; /* module not installed: no collection */ } };
  const all = (n, f) => { const c = col(n); return c ? c.all(f || (() => true)) : []; };
  const cfg = () => (col('scan_assurance') && col('scan_assurance').get('settings')) || { stale_days: 30 };
  const iso = (t) => new Date(t == null ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'scanassure.' + action, target, detail }); };
  const parse = (L) => (L || []).map((t) => { try { return ip4.parseTarget(t); } catch (e) { return null; /* a malformed stored target is skipped; Vulnerability Scans validates on save */ } }).filter(Boolean);
  const inR = (R, n) => R.some((r) => n >= r.first && n <= r.last);
  const ipsOf = (a) => [...new Set([a.mgmt_ip].concat(a.ips || [], a.ip ? [a.ip] : []).map((x) => String(x || '').trim()).filter((x) => ip4.parseIp(x) !== null))];

  function evaluate() {
    const t = now(), stale = cfg().stale_days, vs = col('vulnscan'), conn = vs && vs.get('cfg'), scope = (vs && vs.get('scope')) || { allowed: [], exclude: [] };
    const allowed = parse(scope.allowed), excl = parse(scope.exclude);
    const scans = all('vulnscan_scans').map((x) => ({ x, at: Date.parse(x.finished_at || x.requested_at || 0), R: parse(x.targets), X: parse(x.exclude) })).sort((a, b) => b.at - a.at);
    const reported = new Map(); for (const r of all('vulnscan_results')) reported.set(r.id, new Set(r.hosts || []));
    const tenable = new Map(); for (const r of all('vapt_scanned')) for (const ip of r.ips || []) { const at = Date.parse(r.at); if (!tenable.get(ip) || at > tenable.get(ip)) tenable.set(ip, at); }
    const seen = new Map(); for (const d of all('disc_devices', (x) => x.status !== 'ignored')) for (const ip of d.ips || []) { const at = Date.parse(d.last_seen); if (isFinite(at) && (!seen.get(ip) || at > seen.get(ip))) seen.set(ip, at); }
    const prev = (col('scan_assurance_hist') && col('scan_assurance_hist').all().sort((a, b) => String(b.id).localeCompare(String(a.id)))) || [];
    const failedBefore = new Set((prev[0] && prev[0].failed_ids) || []);
    const rows = [];
    for (const a of all('assets', (x) => !['disposed', 'retired', 'lost', 'stolen'].includes(x.status))) {
      const ips = ipsOf(a), base = { asset_id: a.id, name: a.name || a.asset_tag || a.id, type: a.type || '', site: a.site || '', owner: a.owner || '', ips };
      const out = (status, reason, extra) => rows.push(Object.assign(base, { status, reason: reason || null, why: reason ? REASON[reason][0] : null, fix: reason ? REASON[reason][1] : null, persistent: status === 'failed' && failedBefore.has(a.id) }, extra || {}));
      if (!ips.length) { out('failed', 'no_ip'); continue; }
      // best evidence across the asset's addresses
      let lastOk = null, tool = null;
      for (const ip of ips) { for (const s of scans) { if (!['done', 'stopped'].includes(s.x.state)) continue; const rep = reported.get(s.x.id); if (rep && rep.has(ip) && (!lastOk || s.at > lastOk)) { lastOk = s.at; tool = 'Greenbone ' + s.x.id; } }
        const tn = tenable.get(ip); if (tn && (!lastOk || tn > lastOk)) { lastOk = tn; tool = 'Tenable'; } }
      const days = lastOk ? Math.floor((t - lastOk) / DAY) : null;
      if (lastOk && days <= stale) { out('scanned', null, { last_scan: iso(lastOk), days, tool }); continue; }
      const n = ip4.parseIp(ips[0]), fr = FRAGILE.exec([a.type, a.name, a.model].filter(Boolean).join(' ').replace(/[-_.]/g, ' '));
      if (inR(excl, n) || fr) { out('excluded', null, { why: fr ? 'Fragile device (' + fr[1].toLowerCase() + ') - left out of network scans on purpose' : 'In the scope exclusions - left out on purpose', fix: 'Cover it another way: an authenticated agent check, a vendor firmware review, or a supervised manual scan.', last_scan: lastOk ? iso(lastOk) : null, days }); continue; }
      const open = scans.find((s) => ['requested', 'approved', 'running', 'stopping'].includes(s.x.state) && inR(s.R, n) && !inR(s.X, n));
      if (open) { out('pending', null, { why: 'In scan ' + open.x.id + ' (' + open.x.state + ')', scan: open.x.id, last_scan: lastOk ? iso(lastOk) : null, days }); continue; }
      if (!conn) { out('failed', 'no_scanner', { last_scan: lastOk ? iso(lastOk) : null, days }); continue; }
      if (!allowed.length || !inR(allowed, n)) { out('failed', 'out_of_scope', { subnet: ips[0].split('.').slice(0, 3).join('.') + '.0/24', last_scan: lastOk ? iso(lastOk) : null, days }); continue; }
      const last = scans.find((s) => inR(s.R, n) && !inR(s.X, n) && (!lastOk || s.at > lastOk));
      if (last) {
        const st = last.x.state, ex = { scan: last.x.id, last_scan: lastOk ? iso(lastOk) : null, days };
        if (st === 'rejected') { out('failed', 'rejected', Object.assign(ex, { detail: last.x.decision_note || '' })); continue; }
        if (st === 'failed' || st === 'expired') { out('failed', 'scan_failed', Object.assign(ex, { detail: last.x.error || (st === 'expired' ? 'the approved window ended before it could start' : '') })); continue; }
        if (st === 'stopped' && last.x.partial) { out('failed', 'cut_short', Object.assign(ex, { detail: last.x.stop_reason || '' })); continue; }
        if (st === 'done' || st === 'stopped') { const s0 = seen.get(ips[0]); const near = s0 && Math.abs(s0 - last.at) <= 7 * DAY;
          out('failed', near ? 'blocked' : 'offline', Object.assign(ex, { detail: s0 ? 'Discovery last saw it ' + iso(s0).slice(0, 10) : 'Discovery never saw it' })); continue; }
      }
      out('failed', lastOk ? 'stale' : 'never_scanned', { last_scan: lastOk ? iso(lastOk) : null, days });
    }
    // rescan batches: what a rescan fixes, in scope, folded
    const nums = []; for (const r of rows) if (r.status === 'failed' && RESCAN.includes(r.reason)) for (const ip of r.ips) { const n = ip4.parseIp(ip); if (inR(allowed, n) && !inR(excl, n)) nums.push(n); }
    const uniq = [...new Set(nums)].sort((x, y) => x - y), batches = [];
    for (let i = 0; i < uniq.length; i += BATCH) batches.push({ n: batches.length + 1, hosts: uniq.slice(i, i + BATCH).length, targets: fold(uniq.slice(i, i + BATCH)) });
    const count = (s) => rows.filter((r) => r.status === s).length, measured = rows.length - count('excluded');
    const byReason = {}; for (const r of rows) if (r.reason) byReason[r.reason] = (byReason[r.reason] || 0) + 1;
    const ord = { failed: 0, pending: 1, excluded: 2, scanned: 3 };
    rows.sort((x, y) => (y.persistent - x.persistent) || ord[x.status] - ord[y.status] || String(x.name).localeCompare(String(y.name)));
    return { generated_at: iso(t), stale_days: stale, kpis: { connected: rows.length, scanned: count('scanned'), pending: count('pending'), excluded: count('excluded'), failed: count('failed'), persistent: rows.filter((r) => r.persistent).length,
      coverage: measured ? Math.round(count('scanned') / measured * 1000) / 10 : null }, by_reason: Object.keys(byReason).map((k) => ({ reason: k, n: byReason[k], why: REASON[k][0], fix: REASON[k][1] })).sort((a, b) => b.n - a.n),
      assets: rows, rescan: { batches, hosts: uniq.length, note: uniq.length ? 'Filed in Vulnerability Scans; a different person approves each before anything is sent.' : 'Nothing to rescan.' },
      scope_proposal: [...new Set(rows.filter((r) => r.reason === 'out_of_scope').map((r) => r.subnet))].filter((c) => ip4.isPrivate(ip4.parseIp(c.split('/')[0]))),
      trend: prev.slice(0, 60).reverse().map((h) => ({ day: h.id, coverage: h.coverage, failed: h.failed })),
      note: 'Coverage = scanned within ' + stale + ' days / connected assets not excluded on purpose. A failed scan is never counted as scanned; a device that does not answer the scanner is never assumed clean.' };
  }
  function snapshot() { const v = evaluate(), h = col('scan_assurance_hist'); if (!h) return null;
    const rec = { id: iso().slice(0, 10), coverage: v.kpis.coverage, failed: v.kpis.failed, by_reason: v.by_reason.map((r) => [r.reason, r.n]), failed_ids: v.assets.filter((r) => r.status === 'failed').map((r) => r.asset_id) };
    h.put(rec); for (const x of h.all((y) => Date.parse(y.id) < now() - 400 * DAY)) if (h.remove) h.remove(x.id); return rec; }
  async function rescan(src, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person files a rescan, not a service or AI identity');
    const b = body(src || {}).list('batches', { max: 50, unique: true }).int('hours', { min: 1, max: 12, def: 6 }).done();
    const V = A().vulnscan; if (!V) throw httpErr(424, 'Vulnerability Scans (Greenbone) is not installed');
    const v = evaluate(), pick = b.batches ? v.rescan.batches.filter((x) => b.batches.includes(x.n)) : v.rescan.batches;
    if (!pick.length) throw httpErr(409, 'nothing to rescan - every assessable asset is scanned, pending or needs another fix first');
    const reasons = v.by_reason.filter((r) => RESCAN.includes(r.reason)).map((r) => r.n + ' ' + r.reason.replace('_', ' ')).join(', ');
    const filed = [];
    for (const x of pick) { const st = now() + 15 * 60000 + (x.n - 1) * b.hours * 3600000;
      const r = await V.request({ name: 'Coverage rescan ' + iso().slice(0, 10) + ' batch ' + x.n + '/' + v.rescan.batches.length, targets: x.targets, exclude: [], profile: 'full', window_start: iso(st), window_end: iso(st + b.hours * 3600000), reason: 'Scan Coverage Assurance: ' + reasons }, who);
      filed.push({ batch: x.n, scan: r && r.id, hosts: x.hosts }); }
    audit(who, 'rescan', 'coverage', { batches: filed.map((f) => f.scan), hosts: filed.reduce((a, f) => a + f.hosts, 0) });
    return { filed, note: 'Filed in Vulnerability Scans - a different person approves each scan there; the windows are staggered so batches do not overlap.' };
  }
  function setSettings(src, who) { const b = body(src || {}).int('stale_days', { required: true, min: 7, max: 365 }).done(); col('scan_assurance').put(Object.assign({ id: 'settings' }, b, { by: who.user, at: iso() })); audit(who, 'settings', 'settings', b); return cfg(); }
  function report(fmt, who) {
    const f = fmt || 'html'; if (!['html', 'csv'].includes(f)) throw httpErr(400, 'format must be html or csv');
    const v = evaluate(); audit(who, 'report', 'coverage', { format: f, coverage: v.kpis.coverage });
    const cols = ['Asset', 'Type', 'Site', 'Owner', 'Addresses', 'Status', 'Reason', 'Fix', 'Last scan', 'Tool', 'Detail', 'Persistent'];
    const row = (r) => [r.name, r.type, r.site, r.owner, r.ips.join(' '), r.status, r.why || '', r.fix || '', r.last_scan ? r.last_scan.slice(0, 10) : '', r.tool || '', r.detail || '', r.persistent ? 'yes' : ''];
    if (f === 'csv') return { filename: 'scan-coverage-' + v.generated_at.slice(0, 10) + '.csv', csv: ['# Scan coverage statement ' + v.generated_at + ' - coverage ' + v.kpis.coverage + '%', cols.join(',')].concat(v.assets.map((r) => row(r).map(csvCell).join(','))).join('\r\n') };
    const k = v.kpis, tbl = (c, rs) => '<table><thead><tr>' + c.map((x) => '<th>' + esc(x) + '</th>').join('') + '</tr></thead><tbody>' + (rs.length ? rs.map((r) => '<tr>' + r.map((x) => '<td>' + esc(x) + '</td>').join('') + '</tr>').join('') : '<tr><td colspan="' + c.length + '">None</td></tr>') + '</tbody></table>';
    const html = '<!doctype html><html><head><meta charset="utf-8"><title>Scan coverage statement</title><style>body{font:13px/1.5 Arial,sans-serif;margin:32px;color:#111}h2{border-bottom:2px solid #1f3a5f;font-size:16px;margin-top:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eef2f7}</style></head><body>'
      + (() => { const bv = (store.collection('pentest_settings').get('report_brand') || {}).values || {}; return bv.letterhead && /^data:image\/(png|jpe?g|webp|svg\+xml);base64,/.test(bv.letterhead) ? '<img src="' + esc(bv.letterhead) + '" alt="" style="max-height:46px;max-width:200px;margin-bottom:8px"><br>' : ''; })()
      + '<h1 style="font-size:21px">Scan coverage statement</h1><div>' + esc(((store.collection('pentest_settings').get('report_brand') || {}).values || {}).org_name || ZYB_ORG.name) + ' - generated ' + esc(v.generated_at.slice(0, 16).replace('T', ' ')) + ' UTC by ' + esc(who.user) + ' - CONFIDENTIAL</div>'
      + '<h2>Summary</h2><p><b>' + esc(k.coverage == null ? 'not measurable' : k.coverage + '%') + '</b> of ' + esc(k.connected - k.excluded) + ' assessable connected assets were scanned within ' + esc(v.stale_days) + ' days. ' + esc(k.failed) + ' not scanned (' + esc(k.persistent) + ' for two days or more), ' + esc(k.pending) + ' in a scan now, ' + esc(k.excluded) + ' left out on purpose.</p><p>' + esc(v.note) + '</p>'
      + '<h2>Why assets were not scanned, and the fix</h2>' + tbl(['Reason', 'Assets', 'Fix'], v.by_reason.map((r) => [r.why, r.n, r.fix]))
      + '<h2>Not scanned</h2>' + tbl(cols, v.assets.filter((r) => r.status === 'failed').map(row)) + '<h2>Left out on purpose</h2>' + tbl(cols, v.assets.filter((r) => r.status === 'excluded').map(row))
      + '<h2>Scanned</h2>' + tbl(cols, v.assets.filter((r) => r.status === 'scanned' || r.status === 'pending').map(row)) + '</body></html>';
    return { filename: 'scan-coverage-' + v.generated_at.slice(0, 10) + '.html', html };
  }
  function forTargets(targets) {   // the VAPT Workflow report: coverage of an engagement's IPv4 targets
    const R = parse((targets || []).filter((x) => /^[\d./-]+$/.test(x))); if (!R.length) return null;
    const v = evaluate(), L = v.assets.filter((r) => r.ips.some((ip) => inR(R, ip4.parseIp(ip))));
    return { assets: L.length, scanned: L.filter((r) => r.status === 'scanned').length, rows: L.filter((r) => r.status !== 'scanned').map((r) => ({ name: r.name, ips: r.ips.join(' '), status: r.status, why: r.why || '', fix: r.fix || '' })) };
  }
  let timer = null;
  const runSnap = guardOf(app, 'scanassure.snapshot', () => snapshot());
  function start() { if (opts.noTimer || timer) return; const loop = () => { Promise.resolve(runSnap()).finally(() => { timer = setTimeout(loop, 6 * 3600000); if (timer.unref) timer.unref(); }); }; timer = setTimeout(loop, 60000); if (timer.unref) timer.unref(); }
  return { evaluate, snapshot, rescan, setSettings, report, forTargets, start, REASON };
}

function registerScanAssurance(srv, app, S0) {
  const S = S0 && S0.evaluate ? S0 : createScanAssurance(app, S0 || {});
  app.addons = app.addons || {}; app.addons.scanAssurance = S; S.start();
  const who = (ctx) => Object.assign({ ip: ctx.ip }, ctx.who);
  srv.route('GET', '/scan-assurance', (ctx) => { ctx.need('operator'); return S.evaluate(); });
  srv.route('GET', '/scan-assurance/report', (ctx) => { ctx.need('operator'); return S.report(ctx.query && ctx.query.format, who(ctx)); });
  srv.route('POST', '/scan-assurance/rescan', (ctx) => { ctx.need('operator'); return S.rescan(ctx.body, who(ctx)); }, { maxBody: 2048 });
  srv.route('POST', '/scan-assurance/settings', (ctx) => { ctx.need('admin'); return S.setSettings(ctx.body, who(ctx)); }, { maxBody: 1024 });
  return S;
}
module.exports = { createScanAssurance, registerScanAssurance, REASON };
