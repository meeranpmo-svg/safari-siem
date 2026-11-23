// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { guardOf } = require('./errors');
/*
 * SIEM pipeline watcher ({P} = /api/itam): the out-of-band half of the SIEM pipeline canary. The SIEM proves its own pipeline every
 * 15 minutes (sentra-siem engine/ops/canary.js: a labelled test line through parse -> pipeline -> detect -> alert -> store); a SIEM that
 * is stalled or down cannot be trusted to report that, so THIS service - a separate process - reads GET /ops/pipeline every 5
 * minutes and turns a problem into a platform incident in Notification & Escalation (engine/notify-center.js), with its on-call and
 * escalation ladder:
 *   SIEM not answering     two reads in a row failed (10 minutes)                                           severity 4
 *   pipeline failing       the latest canary run failed - the stage that failed is named                    severity 4
 *   canary stopped         no canary run for 3 intervals (the SIEM answers but its own test is not running)  severity 4
 *   pipeline degraded      a run failed in 24 h but the latest passed                                        severity 2
 * A condition that clears resolves its incident (notify-center). What it cannot do: when the SIEM is down, mail still goes through
 * the SIEM's SMTP relay - the incident is recorded and shown here and on Notification & Escalation either way, and the page says so.
 *   GET  /pipeline-health     viewer   the watcher's last read, consecutive failures, the SIEM's own view when it answered
 *   POST /pipeline-health/check  operator   read now                                                        audited
 * Background: guardOf('pipeline-health.poll'), rescheduled in finally.
 */
const MIN = 60000;
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n || 300);

function createPipelineHealth(app, opts = {}) {
  const now = opts.now || Date.now, L = app.log || { info() {}, warn() {}, every() {} };
  const link = () => opts.siem || ((app.discovery && app.discovery.siem && typeof app.discovery.siem.call === 'function') ? app.discovery.siem.call : null);
  const st = { at: null, ok: null, fails: 0, error: null, view: null, last_ok_at: null };
  async function check() {
    const call = link(), t = now();
    if (!call) { Object.assign(st, { at: t, ok: false, error: 'IT Asset Management has no link to the SIEM (discovery.siem is not configured)', fails: st.fails + 1 }); return st; }
    try {
      const r = await call('GET', '/ops/pipeline', { user: 'system:itam-pipeline', role: 'analyst' });
      if (r && r.status === 200 && r.json && r.json.status) { Object.assign(st, { at: t, ok: true, fails: 0, error: null, view: r.json, last_ok_at: t }); return st; }
      const why = r && r.status === 404 ? 'the SIEM has no pipeline canary yet - run the SIEM update' : 'the SIEM answered HTTP ' + (r ? r.status : 0);
      Object.assign(st, { at: t, ok: r && r.status === 404 ? true : false, fails: r && r.status === 404 ? 0 : st.fails + 1, error: why, view: r && r.status === 404 ? { status: 'not_installed', why } : st.view });
    } catch (e) {
      Object.assign(st, { at: t, ok: false, fails: st.fails + 1, error: 'the SIEM did not answer: ' + s(e.message, 200) });
      L.every('pipeline-health:down', 600000, 'warn', 'pipeline watcher: the SIEM did not answer', { err: s(e.message, 200) });
    }
    return st;
  }
  function signals() {
    const out = [], v = st.view;
    if (st.fails >= 2) out.push({ fp: 'platform:siem:unreachable', source: 'platform', title: 'The SIEM is not answering', severity: 4, condition: true,
      text: st.fails + ' reads in a row failed since ' + new Date(st.last_ok_at || st.at || now()).toISOString().slice(0, 16).replace('T', ' ') + ' UTC (' + (st.error || 'no answer') + '). Logs may not be analysed or alerted on. Check the sentra-siem service on the server (systemctl status sentra-siem).' });
    else if (st.ok && v) {
      if (v.status === 'failing') out.push({ fp: 'platform:siem:pipeline', source: 'platform', title: 'SIEM pipeline failing at "' + s(v.last && v.last.failed_stage, 40) + '"', severity: 4, condition: true, text: s(v.why, 400) + ' - the SIEM canary proves parse, pipeline, detection, alert and store every few minutes; open Pipeline Health.' });
      else if (v.status === 'stale') out.push({ fp: 'platform:siem:canary-stopped', source: 'platform', title: 'SIEM pipeline canary stopped', severity: 4, condition: true, text: s(v.why, 400) + ' - the SIEM answers, but its own test has not run; the engine may be stalled.' });
      else if (v.status === 'degraded') out.push({ fp: 'platform:siem:pipeline-degraded', source: 'platform', title: 'SIEM pipeline had failures in the last 24 hours', severity: 2, condition: true, text: s(v.why, 400) });
    }
    return out;
  }
  function view() {
    return { at: st.at ? new Date(st.at).toISOString() : null, reachable: st.ok, consecutive_failures: st.fails, error: st.error, last_ok_at: st.last_ok_at ? new Date(st.last_ok_at).toISOString() : null, siem: st.view,
      signals: signals().map((x) => ({ title: x.title, severity: x.severity, text: x.text })),
      note: 'Read every 5 minutes by IT Asset Management, a separate service, so a stalled or stopped SIEM is still noticed. Incidents go to Notification & Escalation; e-mail goes through the SIEM\'s SMTP relay, so while the SIEM is down the incident is recorded and shown here but may not be mailed.' };
  }
  let timer = null, stopped = false;
  const job = guardOf(app, 'pipeline-health.poll', check);
  function schedule(ms) { if (stopped) return; timer = setTimeout(async () => { try { await job(); } finally { schedule(5 * MIN); } }, ms); if (timer.unref) timer.unref(); }
  function start() { if (opts.noTimer || app.noTimers || timer) return; schedule(30000); }
  function stop() { stopped = true; if (timer) clearTimeout(timer); }
  return { check, signals, view, start, stop };
}

function registerPipelineHealth(srv, app, opts) {
  const X = createPipelineHealth(app, opts || {});
  (app.addons = app.addons || {}).pipelineHealth = X;
  srv.route('GET', '/pipeline-health', (ctx) => { ctx.need('viewer'); body(ctx.query || {}).done(); return X.view(); });
  srv.route('POST', '/pipeline-health/check', async (ctx) => {
    ctx.need('operator'); body(ctx.body || {}).done();
    await X.check();
    if (app.audit) app.audit({ by: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip || '', action: 'pipeline-health.check', target: 'siem', detail: { reachable: X.view().reachable } });
    return X.view();
  });
  X.start();
  return X;
}

module.exports = { createPipelineHealth, registerPipelineHealth };
