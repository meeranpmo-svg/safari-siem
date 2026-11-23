// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// An asset added or changed in IT Asset Management reaches every related list within a minute, not at each sync's own
// 5-minute / hourly schedule: the AI Windows / Exchange Server Administrators (sysadmin-sync), the AI Network Engineer
// (netops-sync), Infrastructure Automation (infra-sync), SIEM log collection enrolment and the Baseline Hardening view.
// It watches the assets collection (store.onChange) and runs those syncs once, DEBOUNCE_MS after the last change (at most
// MAX_WAIT_MS after the first). Changes made while its own run is going are the syncs' own write-backs and do not start
// another run. Each sync keeps its own rules (what is sent, removed-on-purpose stays removed); this only says "now".
//   GET /asset-propagate   {pending, last}  operator
const DEBOUNCE_MS = 20000, MAX_WAIT_MS = 120000;
const SYS = { user: 'system:asset-propagate', role: 'admin' };
// addon key, label, method (looked up when the run starts: the add-ons register after this module)
const TARGETS = [['sysadminSync', 'AI Windows / Exchange Server Administrators', 'run'], ['netopsSync', 'AI Network Engineer', 'run'], ['infraSync', 'Infrastructure Automation', 'run'],
  ['logEnrol', 'SIEM log collection', 'pass'], ['hardening', 'Baseline Hardening', 'refresh']];

function createAssetPropagate(app, opts = {}) {
  const debounce = opts.debounceMs || DEBOUNCE_MS, maxWait = opts.maxWaitMs || MAX_WAIT_MS, clock = opts.now || Date.now;
  let first = 0, timer = null, busy = false, changed = 0, last = null;
  const run = guardOf(app, 'asset-propagate.run', async () => {
    timer = null; first = 0; busy = true;
    const n = changed; changed = 0;
    const ad = app.addons || {}, out = { at: new Date(clock()).toISOString(), changes: n, steps: [] };
    try {
      for (const [key, label, fn] of TARGETS) {
        const m = ad[key];
        if (!m || typeof m[fn] !== 'function') continue;
        try { const r = await m[fn](SYS); out.steps.push({ name: label, ok: !(r && r.ok === false), detail: r && r.error ? String(r.error).slice(0, 200) : '' }); }
        catch (e) { out.steps.push({ name: label, ok: false, detail: String(e.message || e).slice(0, 200) }); if (app.log && app.log.every) app.log.every('asset-propagate:' + key, 600000, 'warn', 'asset propagation: a sync failed', { sync: key, err: String(e.message || e).slice(0, 200) }); }
      }
      last = out;
      if (out.steps.some((s) => !s.ok) || out.steps.length) app.audit && app.audit({ by: SYS.user, role: SYS.role, ip: '', action: 'assets.propagate', target: 'assets', detail: { changes: n, steps: out.steps.map((s) => s.name + (s.ok ? '' : ' (failed)')) } });
    } finally { busy = false; }   // the next change starts the next run
    return out;
  });
  function changedNow() {
    if (busy) return;   // the syncs' own write-backs while running
    changed++;
    const t = clock();
    if (!first) first = t;
    if (timer) clearTimeout(timer);
    timer = setTimeout(run, Math.max(0, Math.min(debounce, first + maxWait - t)));
    if (timer.unref) timer.unref();
  }
  return { changedNow, run, view: () => ({ pending: changed, scheduled: !!timer, last }), stop: () => { if (timer) clearTimeout(timer); timer = null; } };
}

function registerAssetPropagate(srv, app) {
  const P = createAssetPropagate(app);
  if (app.store && typeof app.store.onChange === 'function') app.store.onChange('assets', () => P.changedNow());
  srv.route('GET', '/asset-propagate', (ctx) => { ctx.need('operator'); return P.view(); });
  (app.addons = app.addons || {}).assetPropagate = P;
  return P;
}

module.exports = { createAssetPropagate, registerAssetPropagate, TARGETS };
