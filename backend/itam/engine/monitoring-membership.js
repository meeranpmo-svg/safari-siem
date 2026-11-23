// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Monitoring membership — the asset inventory's LOG COLLECTION link to the SIEM (sentra-siem). An asset is a member of
 * SIEM log collection when it has a SIEM log source. This module never talks to the SIEM on its own: every call goes
 * through the existing authenticated loopback link in engine/discovery/siem.js (siem.call → proxy secret + identity),
 * and the source itself is created by the SIEM's own idempotent path (POST {siem}/api/soc/collection/sources/ensure —
 * the same template + store path the SIEM's auto-onboarding and Connect hub use).
 *
 *   createMembership({ assets, store, audit, discovery, log, now }) → {
 *     list()            → { siem_reachable, error, summary{status:n}, assets[{asset_id, status, source_id, kind, last_seen,
 *                           eps_1m, lag_p95_s, auto_onboarded, paused, matched_by}] }   (cached 20 s)
 *     detail(id)        → one asset's status + SIEM source row (kind, last event, lag p50/p95, SLA)
 *     setup(id)         → the device-side setup snippet stored on the SIEM source
 *     enable(id, who)   → creates (or re-uses) the SIEM source; idempotent (an asset with a source is not re-created)
 *     pause / resume(id, who, reason)   → pause/resume the SIEM source (kept, never deleted)
 *     stop(id, who, {confirm:true})     → deregister: the SIEM removes the source (or pauses it while it still had events
 *                                          in the last 24 h); the asset is marked "stopped" and is never auto-onboarded again
 *     bulk(ids, action, who)            → enable | pause for up to 200 assets
 *     onLifecycle(id, action, who)      → retire / dispose pauses the asset's SIEM source (best effort, never throws)
 *   }
 * Per-asset status: covered | silent | never-seen | awaiting-config (auto-onboarded, no event yet) | not-collected |
 * paused | stopped | unknown (SIEM unreachable). Every write is admin-only at the route and audited (asset.log-collection.*).
 */
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const BULK_MAX = 200;
const CACHE_MS = 20000;

function createMembership({ assets, store, audit, discovery, log, now = Date.now } = {}) {
  const lg = log || { info() {}, warn() {}, error() {} };
  const siem = discovery && discovery.siem;
  const col = () => store.collection('assets');
  let cache = null;

  function A(who, action, target, detail) { if (audit) audit({ by: who && who.user, role: who && who.role, ip: who && who.ip, action, target, detail }); }
  function invalidate() { cache = null; }

  async function siemCall(method, path, who, body) {
    if (!siem || typeof siem.call !== 'function') throw bad('SIEM link not available', 503);
    // 5xx messages are masked by the HTTP layer, so the reason travels as a machine code (e.code2 → body.code)
    const fail = (msg, status, code) => Object.assign(bad(msg, status), { code2: code });
    let r;
    try { r = await siem.call(method, path, who, body); } catch (e) { throw fail(e.status === 503 ? e.message : `SIEM not reachable — ${e.message}`, e.status || 502, e.status === 503 ? 'siem_not_configured' : 'siem_unreachable'); }
    if (r.status === 401 || r.status === 403) throw fail(r.status === 403 ? 'the SIEM refused: administrator role required' : 'the SIEM refused the platform credentials (check the proxy secret file)', 502, 'siem_refused');
    if (r.status >= 300 || !r.json) throw fail(`SIEM: ${(r.json && r.json.error) || `HTTP ${r.status}`}`, r.status === 404 || r.status === 409 || r.status === 400 ? r.status : 502, 'siem_error');
    return r.json;
  }
  const SYS = { user: 'system:itam-log-collection', role: 'viewer' };
  // the SIEM is told the caller's REAL role: a source is created, paused or removed only for an administrator (the routes
  // check too; this keeps a non-admin path - e.g. a retire by an operator - from acting with admin rights on the SIEM)
  function mustAdmin(who) { if (!who || who.role !== 'admin') throw bad('only an administrator can change SIEM log collection', 403); }

  function mustAsset(id) {
    const a = assets.raw(String(id || ''));
    if (!a) throw bad('asset not found', 404);
    return a;
  }
  function sourceOf(a) { return (a.siem && a.siem.source_id) || null; }
  function patch(id, fn) { col().patch(id, fn); invalidate(); }

  function statusOf(a, cov, row, reachable) {
    const lc = a.log_collection || {};
    if (lc.state === 'stopped' && !sourceOf(a)) return 'stopped';
    if ((row && row.paused) || lc.state === 'paused') return 'paused';
    if (!reachable) return 'unknown';
    // matched on the host's own logs: authoritative even when the (shared) source as a whole is receiving
    if (cov && cov.matched_by === 'host-logs') return cov.status === 'covered' ? 'covered' : 'silent';
    if (row && row.state === 'never-seen') return row.auto_onboarded ? 'awaiting-config' : 'never-seen';
    if (row && row.state === 'receiving') return 'covered';
    if (row && row.state === 'silent') return 'silent';
    if (!cov) return 'unknown';
    if (cov.status === 'covered') return 'covered';
    if (cov.status === 'silent') return 'silent';
    if (cov.status === 'absent') return 'not-collected';
    return 'unknown';
  }

  async function build() {
    if (cache && now() - cache.at < CACHE_MS) return cache.v;
    const cov = await discovery.logCoverage();
    const byAsset = new Map((cov.assets || []).map((p) => [p.asset_id, p]));
    let rows = new Map(); let healthErr = null;
    if (cov.siem_reachable) {
      try { const h = await siemCall('GET', '/collection/health', SYS); rows = new Map((h.sources || []).map((r) => [r.src_id, r])); } catch (e) { healthErr = e.message; }
    }
    const items = [];
    const summary = {};
    for (const a of assets.all()) {
      if (a.status === 'disposed') continue;
      const p = byAsset.get(a.id) || null;
      const sid = (p && p.source_id) || sourceOf(a);
      const row = sid ? rows.get(sid) || null : null;
      const status = statusOf(a, p, row, !!cov.siem_reachable);
      summary[status] = (summary[status] || 0) + 1;
      items.push({
        asset_id: a.id, status, source_id: sid, kind: (row && row.kind) || (p && p.source_kind) || (a.siem && a.siem.kind) || null,
        last_seen: row && row.last_seen ? new Date(row.last_seen).toISOString() : (p && p.last_seen) || null,
        eps_1m: row ? row.eps_1m : null, lag_p50_s: row ? row.lag_p50_s : null, lag_p95_s: row ? row.lag_p95_s : null,
        sla_min: row ? row.sla_min : null, sla_class: row ? row.sla_class : null, auto_onboarded: !!(row && row.auto_onboarded),
        paused: status === 'paused', matched_by: p ? p.matched_by : null,
      });
    }
    const v = { siem_reachable: !!cov.siem_reachable, error: cov.siem_reachable ? healthErr : (cov.error || 'SIEM unreachable'), summary, assets: items, generated_at: new Date(now()).toISOString() };
    cache = { at: now(), v };
    return v;
  }

  async function list() { return build(); }
  async function detail(id) {
    const a = mustAsset(id);
    const v = await build();
    const it = v.assets.find((x) => x.asset_id === a.id) || { asset_id: a.id, status: 'unknown' };
    return Object.assign({ siem_reachable: v.siem_reachable, error: v.error, log_collection: a.log_collection || null, siem: a.siem || null }, it);
  }

  async function setup(id) {
    const a = mustAsset(id);
    const sid = sourceOf(a) || ((await detail(id)).source_id);
    if (!sid) throw bad('this asset has no SIEM log source yet — enable log collection first', 409);
    const j = await siemCall('GET', `/collection/sources/${encodeURIComponent(sid)}/setup`, SYS);
    return { asset_id: a.id, source_id: sid, setup: j.setup || null };
  }

  async function enable(id, who) {
    mustAdmin(who);
    const a = mustAsset(id);
    if (a.status === 'disposed' || a.status === 'retired') throw bad(`asset is ${a.status}`, 409);
    const cur = sourceOf(a);
    if (cur && !(a.log_collection && a.log_collection.state === 'stopped')) return { asset_id: a.id, source_id: cur, created: false, already: true };
    const siteMap = (siem && siem.siteMap) || {};
    const disc = a.discovery || {};
    const body = { asset: { asset_id: a.id, name: a.name || a.asset_tag || '', mgmt_ip: a.mgmt_ip || '', type: a.type || '', vendor: disc.vendor || a.vendor || '', os: disc.os || a.os || '', class: disc.class || '', is_dc: !!disc.is_dc, hostname: a.hostname || '', site: siteMap[a.site] || a.site || '' } };
    const j = await siemCall('POST', '/collection/sources/ensure', { user: who.user, role: 'admin', ip: who.ip }, body);
    const wasStopped = !!(a.log_collection && a.log_collection.state === 'stopped');
    if (wasStopped && !j.created) { try { await siemCall('POST', `/collection/sources/${encodeURIComponent(j.source_id)}/resume`, { user: who.user, role: 'admin', ip: who.ip }, {}); } catch (e) { lg.warn('log collection: resume after re-enable failed', { asset_id: a.id, err: e.message }); } }
    const at = new Date(now()).toISOString();
    patch(a.id, (x) => {
      x.siem = { source_id: j.source_id, kind: j.kind, site: j.site, connected_at: at, connected_by: who.user, state: 'waiting', last_seen: null, checked_at: null, alert: false, origin: 'inventory' };
      x.log_collection = { state: 'enabled', at, by: who.user, source_id: j.source_id };
    });
    A(who, 'asset.log-collection.enable', a.id, { source_id: j.source_id, kind: j.kind, created: !!j.created });
    return { asset_id: a.id, source_id: j.source_id, kind: j.kind, created: !!j.created, setup: j.setup || null };
  }

  async function setPaused(id, who, paused, reason) {
    mustAdmin(who);
    const a = mustAsset(id);
    const sid = sourceOf(a);
    if (!sid) throw bad('this asset has no SIEM log source', 409);
    const j = await siemCall('POST', `/collection/sources/${encodeURIComponent(sid)}/${paused ? 'pause' : 'resume'}`, { user: who.user, role: 'admin', ip: who.ip }, paused ? { reason: String(reason || 'paused from the asset inventory').slice(0, 300) } : {});
    const at = new Date(now()).toISOString();
    patch(a.id, (x) => { x.log_collection = Object.assign({}, x.log_collection || {}, { state: paused ? 'paused' : 'enabled', at, by: who.user, source_id: sid, reason: paused ? String(reason || '') : undefined }); });
    A(who, paused ? 'asset.log-collection.pause' : 'asset.log-collection.resume', a.id, { source_id: sid, reason: paused ? String(reason || '') : undefined });
    return { asset_id: a.id, source_id: sid, paused, siem: j };
  }

  async function stop(id, who, opts) {
    mustAdmin(who);
    const a = mustAsset(id);
    if (!opts || opts.confirm !== true) throw bad('confirm:true is required to stop log collection for this asset', 400);
    const sid = sourceOf(a) || ((await detail(id)).source_id);
    let res = { removed: false, paused: false };
    if (sid) res = await siemCall('POST', `/collection/sources/${encodeURIComponent(sid)}/stop`, { user: who.user, role: 'admin', ip: who.ip }, {});
    const at = new Date(now()).toISOString();
    patch(a.id, (x) => {
      x.siem = null; // deregistered from SIEM monitoring
      x.log_collection = { state: 'stopped', at, by: who.user, source_id: sid || null, source_removed: !!res.removed, source_paused: !!res.paused, reason: String((opts && opts.reason) || '').slice(0, 300) };
    });
    A(who, 'asset.log-collection.stop', a.id, { source_id: sid || null, removed: !!res.removed, paused: !!res.paused });
    return { asset_id: a.id, source_id: sid || null, removed: !!res.removed, paused: !!res.paused, note: res.reason || null };
  }

  async function bulk(ids, action, who) {
    if (!Array.isArray(ids) || !ids.length) throw bad('ids[] required');
    if (ids.length > BULK_MAX) throw bad(`at most ${BULK_MAX} assets per bulk action`);
    if (!['enable', 'pause'].includes(action)) throw bad('action must be enable or pause');
    const results = [];
    for (const id of ids) {
      try {
        const r = action === 'enable' ? await enable(id, who) : await setPaused(id, who, true, 'bulk pause from the asset inventory');
        results.push({ asset_id: id, ok: true, source_id: r.source_id, created: r.created, already: r.already });
      } catch (e) {
        results.push({ asset_id: id, ok: false, error: e.message, status: e.status || 500 });
        if (e.status === 502 || e.status === 503) { for (const rest of ids.slice(ids.indexOf(id) + 1)) results.push({ asset_id: rest, ok: false, error: 'skipped — SIEM unreachable', status: e.status }); break; }
      }
    }
    A(who, `asset.log-collection.bulk-${action}`, 'bulk', { total: ids.length, ok: results.filter((r) => r.ok).length });
    return { action, total: ids.length, ok: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length, results };
  }

  function onLifecycle(id, action, who) {
    if (action !== 'retire' && action !== 'dispose') return;
    const a = assets.raw(String(id || ''));
    if (!a || !sourceOf(a)) return;
    // retired / disposed by someone who is not an administrator: collection keeps running and the asset is flagged for an
    // administrator to pause it (an operator must not be able to switch a server's logs off by retiring it)
    if (!who || who.role !== 'admin') {
      patch(a.id, (x) => { x.log_collection = Object.assign({}, x.log_collection || {}, { review: { reason: `asset ${action === 'retire' ? 'retired' : 'disposed'} by ${(who && who.user) || 'unknown'} - an administrator decides whether to pause its SIEM source`, at: new Date(now()).toISOString(), by: (who && who.user) || '' } }); });
      A(who || SYS, 'asset.log-collection.pause-pending', a.id, { action });
      return;
    }
    setPaused(id, who, true, `asset ${action === 'retire' ? 'retired' : 'disposed'} in the inventory`).catch((e) => lg.warn('log collection: lifecycle pause failed', { asset_id: id, err: e.message }));
  }

  return { list, detail, setup, enable, pause: (id, who, reason) => setPaused(id, who, true, reason), resume: (id, who) => setPaused(id, who, false), stop, bulk, onLifecycle, invalidate, statusOf, BULK_MAX };
}

module.exports = { createMembership };
