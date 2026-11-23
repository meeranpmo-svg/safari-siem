// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
/*
 * Automatic SIEM enrolment of discovered assets ({P} = /api/itam): everything the inventory knows that should send logs
 * gets a SIEM log source, without waiting for someone to click "Enable log collection" asset by asset.
 * Every pass (config.log_collection.interval_min, default 15) reads the inventory's log coverage and, for each asset that
 *   is in use · of a required type (log_collection.types: server, network, storage, vm - firewalls are network) · has no
 *   logs and no SIEM source · has a connector the SIEM can create · was not stopped by an administrator
 * calls the same enable path as the inventory button (monitoring-membership.js → SIEM /collection/sources/ensure) as
 * system:itam-auto-enrol, audited. A source only labels what arrives: the device still has to be configured, and the
 * SIEM's AI SIEM Engineer opens a work item with the exact configuration until logs arrive.
 * A refusal (no management IP, public IP, unknown kind) is remembered and retried after retry_h (24 h).
 * Workstations are not enrolled (endpoints report through the EDR); add 'workstation' to types to change that.
 * Routes:  GET /log-collection/auto (viewer) - settings, last pass, assets waiting for a retry
 *          POST /log-collection/auto/run (admin) - run a pass now
 */
const PRIV = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
const AUTO = { user: 'system:itam-auto-enrol', role: 'admin', ip: '' };

function createLogEnrol(app, opts = {}) {
  const M = opts.membership || app.membership, D = opts.discovery || app.discovery, now = opts.now || Date.now;
  const lg = app.log || { warn() {}, info() {} };
  const tries = app.store.collection('log_enrol_attempts');
  const cfg = () => Object.assign({ auto_enroll: true, types: ['server', 'network', 'storage', 'vm'], max_per_pass: 25, interval_min: 15, retry_h: 24 }, (app.config && app.config.log_collection) || {});
  const audit = (action, target, detail) => { if (app.audit) app.audit({ by: AUTO.user, role: 'system', ip: '', action, target, detail }); };
  let last = null, timer = null, running = false;

  function wanted(p, c) {
    if (p.status !== 'absent' || p.source_id || p.auto_onboard === false || !p.suggested_kind) return false;
    if (p.asset_status && p.asset_status !== 'in_use') return false;
    if (!(c.types.includes(p.type) || (p.class === 'firewall' && c.types.includes('network')))) return false;
    return PRIV.test(String(p.mgmt_ip || '')) || /^(windows|dc)$/.test(p.suggested_kind);   // agents need no IP; syslog needs a private one
  }
  async function pass() {
    const c = cfg(), t = now(), res = { at: new Date(t).toISOString(), enabled: c.auto_enroll !== false, candidates: 0, enrolled: [], refused: [], waiting_retry: 0, error: null };
    if (c.auto_enroll === false) return (last = res);
    if (running) return Object.assign(res, { error: 'a pass is already running' });
    running = true;
    try {
      let cov;
      try { cov = await D.logCoverage(); } catch (e) { res.error = e.message; return (last = res); }
      if (!cov || !cov.siem_reachable) { res.error = (cov && cov.error) || 'SIEM not reachable'; return (last = res); }
      const list = (cov.assets || []).filter((p) => wanted(p, c));
      res.candidates = list.length;
      for (const p of list) {
        if (res.enrolled.length + res.refused.length >= (Number(c.max_per_pass) || 25)) break;
        const prev = tries.get(p.asset_id);
        if (prev && t - prev.at < (Number(c.retry_h) || 24) * 3600000) { res.waiting_retry++; continue; }
        try {
          const r = await M.enable(p.asset_id, AUTO);
          res.enrolled.push({ asset_id: p.asset_id, name: p.name, source_id: r.source_id, kind: r.kind || p.suggested_kind });
          if (prev) tries.remove(p.asset_id);
        } catch (e) {
          if (e.status === 502 || e.status === 503) { res.error = e.message; break; }   // SIEM down: retry next pass, not in 24 h
          res.refused.push({ asset_id: p.asset_id, name: p.name, error: e.message });
          tries.put({ id: p.asset_id, name: p.name || '', at: t, error: String(e.message).slice(0, 300) });
        }
      }
      if (res.enrolled.length || res.refused.length) audit('asset.log-collection.auto-enrol', 'auto', { enrolled: res.enrolled.map((x) => x.asset_id), refused: res.refused.length, candidates: res.candidates });
      if (M.invalidate) M.invalidate();
      return (last = res);
    } finally { running = false; }
  }
  function start() {
    if (timer) return;
    const ms = Math.max(5, Number(cfg().interval_min) || 15) * 60000;
    timer = setInterval(guardOf(app, 'log-enrol.pass', () => pass()), ms);
    if (timer.unref) timer.unref();
  }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  function status() {
    const c = cfg();
    return { enabled: c.auto_enroll !== false, types: c.types, interval_min: c.interval_min, max_per_pass: c.max_per_pass, retry_h: c.retry_h, running: !!timer, last_pass: last,
      waiting_retry: tries.all().map((x) => ({ asset_id: x.id, name: x.name, at: new Date(x.at).toISOString(), error: x.error })) };
  }
  return { pass, start, stop, status, wanted };
}

function registerLogEnrol(srv, app, opts = {}) {
  if (!app.membership || !app.discovery) { if (app.log) app.log.warn('log enrol: inventory log collection not available - not registered'); return null; }
  const E = createLogEnrol(app, opts);
  srv.route('GET', '/log-collection/auto', (ctx) => void ctx.need('viewer') || E.status());
  srv.route('POST', '/log-collection/auto/run', (ctx) => { ctx.need('admin'); return E.pass(); });
  if (!opts.noTimer && cfgOn(app)) { E.start(); setTimeout(guardOf(app, 'log-enrol.pass', () => E.pass()), 90000).unref(); }   // first pass shortly after start
  (app.addons = app.addons || {}).logEnrol = E;
  return E;
}
const cfgOn = (app) => !(app.config && app.config.log_collection && app.config.log_collection.auto_enroll === false);

module.exports = { createLogEnrol, registerLogEnrol };
