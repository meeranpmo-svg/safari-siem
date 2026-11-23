// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const { guard: guardJob } = require('../util/errors');
/*
 * After-hours mode — what the SOC does between the end of the working day and the next morning, when nobody has the
 * portal open. the organisation works official hours (business-hours calendar, default Sun–Thu Riyadh) with no night shift.
 * The detection engine already raises alerts 24/7; this module makes sure a person hears about the ones that matter.
 *
 *   1. Page      an alert first raised outside working hours, at or above page.min_severity, is e-mailed once to the
 *                on-call (page.to + tonight's rota entry). Storm guard: page.max_per_hour; beyond it the alert is HELD
 *                (counted, in the brief, never silently dropped). An alert nobody acknowledged within
 *                page.escalate_after_min is paged again to page.escalate_to.
 *   2. Prepare   prepare.mode off | shadow | prepare. "prepare" opens a case from the alert with its suggested playbook,
 *                so the containment steps are waiting as APPROVAL REQUESTS when someone opens the page (engine/soc/cases.js).
 *                Nothing is executed - the engine never executes actions, and an approval needs a named person
 *                (routeutil wrap 'approve:…' refuses service / AI identities). "shadow" only records what it would open.
 *   3. Brief     each working day at brief.at (Riyadh), one e-mail covering end of the previous working day → now:
 *                alerts raised after hours, pages sent / failed / held / escalated, cases prepared, approvals waiting,
 *                and "Needs you today" (still unacknowledged). Stored, shown on the page.
 *
 * Switching the mode on stamps enabled_at: only alerts raised AFTER it are handled - the backlog is never paged.
 * Working hours are the shared calendar (engine/util/business-hours.js), never a second definition.
 *
 *   createAfterHoursMode({ state, alerts, cases, playbooks, calendar() , mail(msg), mailProblems(), log, now, portalUrl })
 *     → { config(), save(patch, by, baseVersion), status(), runs(limit), briefs(limit), brief(day), makeBrief(now),
 *         sendBrief(by), testPage(by), tick(), start(ms), stop(), nightKey(ms) }
 *
 * State: collection ah_mode (doc "config", doc "cursor"), ah_runs (one per handled alert), ah_briefs (one per day).
 * Logs and runs carry alert ids and recipient COUNTS - never addresses.
 */

const SEV = ['info', 'low', 'medium', 'high', 'critical'];
const MODES = ['off', 'shadow', 'prepare'];
const ADDR_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const RULE_RE = /^[A-Za-z0-9_.:-]{1,80}$/;
const HM_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;
const STEP = 15 * 60000;
const MAX_AGE_MS = 3 * 3600000;   // an alert older than this when first seen (engine was down) is recorded, not paged
const DEFAULTS = Object.freeze({
  enabled: false, enabled_at: 0,
  page: { min_severity: 3, to: [], quiet_rules: [], max_per_hour: 20, escalate_after_min: 30, escalate_to: [] },
  oncall: [],                     // [{ name, days:[0-6] (the weekday the night STARTS on), to:[addr] }]
  prepare: { mode: 'off', min_severity: 3, max_per_night: 10 },
  brief: { enabled: true, at: '07:30', to: [] },
  version: 0, updated: 0, by: '',
});

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const clone = (o) => JSON.parse(JSON.stringify(o));
const bad = (msg, errors) => Object.assign(new Error(msg), { code: 400, errors: errors || [msg] });
const escH = (s) => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sevName = (n) => SEV[Math.max(0, Math.min(4, Number(n) || 0))];
const uniq = (a) => [...new Set(a)];

function addrList(v, name, errs) {
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || v.length > 50) { errs.push(`${name}: a list of up to 50 e-mail addresses`); return []; }
  const out = uniq(v.map((x) => String(x).trim().toLowerCase()).filter(Boolean));
  for (const a of out) if (!ADDR_RE.test(a)) errs.push(`${name}: "${a.slice(0, 60)}" is not an e-mail address`);
  return out;
}
function intIn(v, lo, hi, name, errs) {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < lo || n > hi) { errs.push(`${name} must be a whole number ${lo}-${hi}`); return undefined; }
  return n;
}

function normalize(base, patch) {
  const errs = [];
  const c = clone(base);
  const allowed = ['enabled', 'page', 'oncall', 'prepare', 'brief'];
  for (const k of Object.keys(patch)) if (!allowed.includes(k)) errs.push(`unknown setting "${String(k).slice(0, 30)}"`);
  if (patch.enabled !== undefined) { if (typeof patch.enabled !== 'boolean') errs.push('enabled must be true or false'); else c.enabled = patch.enabled; }
  if (patch.page !== undefined) {
    const p = patch.page;
    if (!isObj(p)) errs.push('page must be an object');
    else {
      const set = (k, v) => { if (v !== undefined) c.page[k] = v; };
      set('min_severity', intIn(p.min_severity, 1, 4, 'page.min_severity', errs));
      set('to', addrList(p.to, 'page.to', errs));
      set('escalate_to', addrList(p.escalate_to, 'page.escalate_to', errs));
      set('max_per_hour', intIn(p.max_per_hour, 1, 500, 'page.max_per_hour', errs));
      set('escalate_after_min', intIn(p.escalate_after_min, 5, 720, 'page.escalate_after_min', errs));
      if (p.quiet_rules !== undefined) {
        if (!Array.isArray(p.quiet_rules) || p.quiet_rules.length > 200) errs.push('page.quiet_rules: a list of up to 200 rule ids');
        else { const q = uniq(p.quiet_rules.map((x) => String(x).trim()).filter(Boolean)); for (const r of q) if (!RULE_RE.test(r)) errs.push(`page.quiet_rules: invalid rule id "${r.slice(0, 40)}"`); c.page.quiet_rules = q; }
      }
    }
  }
  if (patch.oncall !== undefined) {
    if (!Array.isArray(patch.oncall) || patch.oncall.length > 14) errs.push('oncall: a list of up to 14 rota entries');
    else c.oncall = patch.oncall.map((o, i) => {
      const n = `oncall[${i}]`;
      if (!isObj(o)) { errs.push(`${n} must be an object`); return null; }
      const days = Array.isArray(o.days) ? uniq(o.days.map(Number)).sort() : [];
      if (!days.length || days.some((d) => !Number.isInteger(d) || d < 0 || d > 6)) errs.push(`${n}.days: weekdays 0-6 (0 = Sunday; the day the night starts)`);
      const to = addrList(o.to, `${n}.to`, errs) || [];
      if (!to.length) errs.push(`${n}.to: at least one address`);
      return { name: String(o.name || '').trim().slice(0, 60), days, to };
    }).filter(Boolean);
  }
  if (patch.prepare !== undefined) {
    const p = patch.prepare;
    if (!isObj(p)) errs.push('prepare must be an object');
    else {
      if (p.mode !== undefined) { if (!MODES.includes(p.mode)) errs.push(`prepare.mode must be one of ${MODES.join(', ')}`); else c.prepare.mode = p.mode; }
      const ms = intIn(p.min_severity, 2, 4, 'prepare.min_severity', errs); if (ms !== undefined) c.prepare.min_severity = ms;
      const mx = intIn(p.max_per_night, 1, 100, 'prepare.max_per_night', errs); if (mx !== undefined) c.prepare.max_per_night = mx;
    }
  }
  if (patch.brief !== undefined) {
    const b = patch.brief;
    if (!isObj(b)) errs.push('brief must be an object');
    else {
      if (b.enabled !== undefined) { if (typeof b.enabled !== 'boolean') errs.push('brief.enabled must be true or false'); else c.brief.enabled = b.enabled; }
      if (b.at !== undefined) { if (!HM_RE.test(String(b.at))) errs.push('brief.at must be HH:MM (Riyadh time)'); else c.brief.at = String(b.at); }
      const to = addrList(b.to, 'brief.to', errs); if (to !== undefined) c.brief.to = to;
    }
  }
  if (c.enabled && !c.page.to.length && !c.oncall.length) errs.push('switching on needs at least one page recipient (page.to or an on-call rota entry)');
  if (errs.length) throw bad(errs[0], errs);
  return c;
}

function createAfterHoursMode(o = {}) {
  const { state } = o;
  if (!state) throw new Error('after-hours mode needs the state store');
  const log = o.log || { info() {}, warn() {}, error() {} };
  const now = o.now || Date.now;
  const cal = typeof o.calendar === 'function' ? o.calendar : () => null;
  const portal = String(o.portalUrl || '').replace(/\/+$/, '');
  const col = state.collection('ah_mode');
  const runs = state.collection('ah_runs');
  const briefsCol = state.collection('ah_briefs');
  const auditFn = (e) => { try { if (typeof state.audit === 'function') state.audit(e); } catch (x) { /* audit must not stop paging */ } };
  let timer = null; let busy = false; let lastTick = 0; let lastError = '';

  function config() {
    const d = col.get('config');
    const c = clone(DEFAULTS);
    if (d) for (const k of ['enabled', 'enabled_at', 'oncall', 'version', 'updated', 'by']) if (d[k] !== undefined) c[k] = d[k];
    if (d) for (const k of ['page', 'prepare', 'brief']) if (isObj(d[k])) c[k] = Object.assign(c[k], d[k]);
    return c;
  }
  function save(patch, by, baseVersion) {
    if (!isObj(patch)) throw bad('settings must be an object');
    const cur = config();
    if (baseVersion !== undefined && baseVersion !== null && Number(baseVersion) !== cur.version) {
      throw Object.assign(new Error(`settings changed meanwhile (version ${cur.version}) - reload and try again`), { code: 409 });
    }
    const next = normalize(cur, patch);
    if (next.enabled && !cur.enabled) next.enabled_at = now();        // no backlog: only alerts raised from now on
    if (!next.enabled) next.enabled_at = 0;
    next.version = cur.version + 1; next.updated = now(); next.by = by || '';
    col.put(Object.assign({ id: 'config' }, next));
    if (next.enabled && !cur.enabled) col.put({ id: 'cursor', created: next.enabled_at });
    log.info('after-hours mode saved', { by: by || '', enabled: next.enabled, prepare: next.prepare.mode, version: next.version });
    return config();
  }

  // ---------------------------------------------------------------- calendar helpers
  function afterHoursReason(ms) { const c = cal(); return c ? c.reason(ms) : ''; }
  function isBusiness(ms) { const c = cal(); return c ? c.isBusiness(ms) : false; }
  function local(ms) { const c = cal(); const off = ((c && c.config && c.config.utc_offset_min) || 180) * 60000; const d = new Date(ms + off); return { date: d.toISOString().slice(0, 10), dow: d.getUTCDay(), min: d.getUTCHours() * 60 + d.getUTCMinutes() }; }
  // the night an instant belongs to = the local date it started on (before noon belongs to the previous evening)
  function nightKey(ms) { const l = local(ms); return l.min >= 720 ? l.date : local(ms - 86400000).date; }
  function nightDow(ms) { const l = local(ms); return l.min >= 720 ? l.dow : (l.dow + 6) % 7; }
  function recipients(c, ms) {
    const rota = (c.oncall || []).filter((r) => r.days.includes(nightDow(ms)));
    return { to: uniq(c.page.to.concat(...rota.map((r) => r.to))), rota: rota.map((r) => r.name).filter(Boolean) };
  }
  // end of the previous working day: step back out of the current business period, then through the after-hours one
  function previousDayEnd(t) {
    const limit = t - 8 * 86400000;
    let x = t;
    while (x > limit && isBusiness(x)) x -= STEP;
    while (x > limit && !isBusiness(x)) x -= STEP;
    if (x <= limit) return t - 86400000;
    let y = Math.floor(x / 60000) * 60000;                 // x is the last business step: find the exact closing minute
    while (y < x + STEP && isBusiness(y)) y += 60000;
    return y;
  }

  // ---------------------------------------------------------------- mail
  function link(path) { return portal ? `${portal}/${path}` : ''; }
  function alertLines(a) {
    const g = Object.entries(a.group || {}).map(([k, v]) => `${k}=${v}`).join(', ');
    return [`${a.id} · ${sevName(a.severity).toUpperCase()} · ${a.rule_name || a.rule_id}`, a.summary || '', g ? `Entity: ${g}` : '', a.host ? `Host: ${a.host}` : '', `First seen: ${new Date(a.ts_first || a.created).toISOString()} (count ${a.count || 1})`].filter(Boolean);
  }
  async function send(to, subject, text, html) {
    if (typeof o.mail !== 'function') throw Object.assign(new Error('e-mail is not available in this engine'), { transient: false });
    return o.mail({ to, subject, text, html });
  }
  function pageText(a, run, kind) {
    const L = alertLines(a);
    const ack = link(`soc-intel.html?alert=${encodeURIComponent(a.id)}#mode`);
    const extra = [];
    if (run.case_id) extra.push(`Case ${run.case_id} is open with playbook ${run.playbook}: ${run.approvals} containment step(s) are waiting for your approval. Nothing has been executed.`);
    else if (run.shadow) extra.push(`Shadow mode: a case with playbook ${run.playbook} would have been prepared (nothing was opened).`);
    if (kind === 'escalation') extra.unshift(`Nobody has acknowledged this alert ${Math.round((now() - run.paged_at) / 60000)} minutes after the first page.`);
    const text = [...extra, '', ...L, '', `Why after hours: ${run.reason}`, ack ? `Acknowledge / open: ${ack}` : 'Acknowledge it on SOC → Threat Intel & After-hours → After-hours mode.',
      '', ('Sent by the ' + ZYB_ORG.short + ' SIEM after-hours mode. Reply to nobody - this mailbox is not read.')].join('\n');
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111">${extra.map((x) => `<p><b>${escH(x)}</b></p>`).join('')}`
      + `<table style="border-collapse:collapse">${L.map((x) => `<tr><td style="padding:2px 0">${escH(x)}</td></tr>`).join('')}</table>`
      + `<p>Why after hours: ${escH(run.reason)}</p>${ack ? `<p><a href="${escH(ack)}">Acknowledge / open in the portal</a> (sign-in required)</p>` : ''}`
      + ('<p style="color:#666;font-size:12px">' + ZYB_ORG.short + ' SIEM · after-hours mode</p></div>');
    return { text, html };
  }

  // ---------------------------------------------------------------- the scan
  // newest-500 cap of alerts.list; sorted by creation so the cursor never skips one
  function alertsSince(from) { const r = o.alerts.list({ status: 'all', from, sort: 'created', limit: 500 }); return (r && Array.isArray(r.items) ? r.items : Array.isArray(r) ? r : []).filter((a) => a.created >= from); }
  // a PERSON acted on the alert (status / assignment / note by someone who is not a system identity). Our own prepared
  // case moves the alert to in-progress as system:after-hours - that is not an acknowledgement.
  function personActed(a) {
    const h = (a.history || []).filter((x) => x.by && !/^(system|engine)(:|$)/i.test(String(x.by)) && ['status', 'assign', 'note'].includes(x.action));
    return h.length ? h[h.length - 1] : null;
  }
  function putRun(r) { r.updated = now(); runs.put(r); return r; }
  function hist(r, by, what) { r.history = (r.history || []).concat([{ at: now(), by, what }]).slice(-50); }

  async function handleNew(c, a) {
    const reason = afterHoursReason(a.created);
    if (!reason) return null;                                                  // raised in working hours: not ours
    const r = { id: a.id, alert_id: a.id, at: now(), created: a.created, night: nightKey(a.created), severity: a.severity, rule_id: a.rule_id,
      summary: String(a.summary || a.rule_name || '').slice(0, 300), reason, status: '', to: 0, history: [] };
    if (a.severity < c.page.min_severity) return null;                         // below the bar: the brief still lists it
    if (c.page.quiet_rules.includes(a.rule_id)) { r.status = 'QUIET'; hist(r, 'system', `rule ${a.rule_id} is on the quiet list - raised and briefed, not paged`); return putRun(r); }
    if (now() - a.created > MAX_AGE_MS) { r.status = 'LATE'; hist(r, 'system', 'first seen more than 3 h after it was raised (engine down?) - not paged, in the brief'); return putRun(r); }
    const pa = personActed(a);
    if (pa) { r.status = 'ACKED'; r.acked_by = pa.by; hist(r, 'system', `already handled by ${pa.by} before the page went out`); return putRun(r); }

    // prepare containment (approval requests only)
    const pb = o.playbooks && typeof o.playbooks.suggest === 'function' ? o.playbooks.suggest([a]) : null;
    if (pb && c.prepare.mode !== 'off' && a.severity >= c.prepare.min_severity && !a.case_id) {
      const tonight = runs.all((x) => x.night === r.night && (x.case_id || x.shadow)).length;
      r.playbook = pb;
      if (tonight >= c.prepare.max_per_night) hist(r, 'system', `prepare limit reached (${c.prepare.max_per_night} tonight) - no case prepared`);
      else if (c.prepare.mode === 'shadow') { r.shadow = true; hist(r, 'system', `shadow: would open a case with playbook ${pb}`); }
      else if (o.cases) {
        try {
          const cs = o.cases.create({ alert_ids: [a.id], playbook_id: pb, title: `[After hours] ${r.summary}`.slice(0, 300),
            description: `Prepared by after-hours mode at ${new Date(now()).toISOString()} for ${a.id} (${reason}). The playbook's containment steps are approval requests; nothing has been executed.` }, 'system:after-hours');
          r.case_id = cs.id; r.approvals = (cs.approvals || []).length;
          hist(r, 'system:after-hours', `case ${cs.id} prepared with playbook ${pb}: ${r.approvals} approval request(s) waiting`);
        } catch (e) { hist(r, 'system', `case could not be prepared: ${String(e.message).slice(0, 160)}`); }
      }
    }

    // storm guard
    const hourAgo = now() - 3600000;
    const sent = runs.all((x) => x.paged_at && x.paged_at > hourAgo).length;
    if (sent >= c.page.max_per_hour) { r.status = 'HELD'; hist(r, 'system', `storm guard: ${sent} pages in the last hour (limit ${c.page.max_per_hour}) - held, in the brief`); return putRun(r); }
    return page(c, a, r, 'page');
  }

  async function page(c, a, r, kind) {
    const rc = kind === 'escalation' ? { to: c.page.escalate_to, rota: [] } : recipients(c, a.created);
    if (!rc.to.length) { r.status = 'FAILED'; r.error = 'no recipient for tonight'; hist(r, 'system', 'no page recipient (page.to empty and no rota entry for tonight)'); return putRun(r); }
    const { text, html } = pageText(a, r, kind);
    const subj = `[After hours]${kind === 'escalation' ? '[ESCALATION]' : ''}[${sevName(a.severity).toUpperCase()}] ${r.summary}`.slice(0, 200);
    r.attempts = (r.attempts || 0) + 1;
    try {
      const res = await send(rc.to, subj, text, html);
      const refused = res && res.rejected ? res.rejected.length : 0;
      if (kind === 'escalation') { r.status = 'ESCALATED'; r.escalated_at = now(); r.escalated_to = rc.to.length; }
      else { r.status = 'PAGED'; r.paged_at = now(); r.to = rc.to.length; r.rota = rc.rota; }
      delete r.error; delete r.retry_at;
      hist(r, 'system', `${kind === 'escalation' ? 'escalation' : 'page'} sent to ${rc.to.length} recipient(s)${rc.rota.length ? ` (rota: ${rc.rota.join(', ')})` : ''}${refused ? `, ${refused} refused by the relay` : ''}`);
      auditFn({ at: now(), user: 'system:after-hours', action: kind === 'escalation' ? 'after-hours.escalate' : 'after-hours.page', target: a.id, detail: { recipients: rc.to.length, severity: a.severity, case_id: r.case_id || '' } });
    } catch (e) {
      const transient = e && e.transient !== false;
      r.error = `${e.stage ? e.stage + ': ' : ''}${String(e.message).slice(0, 200)}`;
      if (kind !== 'escalation') { r.status = transient && r.attempts < 3 ? 'RETRY' : 'FAILED'; r.retry_at = now() + r.attempts * 60000; }
      hist(r, 'system', `${kind} failed (attempt ${r.attempts}): ${r.error}`);
      log.warn('after-hours: page failed', { alert: a.id, kind, attempt: r.attempts, stage: e.stage || '', transient });
    }
    return putRun(r);
  }

  async function tick() {
    if (busy) return { busy: true };
    busy = true; lastTick = now();
    const out = { handled: 0, escalated: 0, acked: 0, brief: null };
    try {
      const c = config();
      if (c.enabled && o.alerts) {
        // 1. alerts raised since the cursor, oldest first
        const cur = col.get('cursor') || { id: 'cursor', created: c.enabled_at || now() };
        const fresh = alertsSince(cur.created).filter((a) => a.created > cur.created).sort((x, y) => x.created - y.created).slice(0, 200);
        let maxC = cur.created;
        for (const a of fresh) {
          if (!runs.get(a.id)) { const r = await handleNew(c, a); if (r) out.handled++; }
          maxC = Math.max(maxC, a.created);
        }
        if (maxC > cur.created) col.put({ id: 'cursor', created: maxC });
        // 2. follow up: retries, acknowledgements, escalation
        for (const r of runs.all((x) => ['PAGED', 'RETRY'].includes(x.status))) {
          const a = o.alerts.get(r.alert_id);
          if (!a) continue;
          const pa = personActed(a);
          if (pa) {
            r.status = 'ACKED'; r.acked_at = pa.at || now(); r.acked_by = pa.by;
            hist(r, pa.by, `alert ${a.status} by ${pa.by} - after-hours mode stands down`); putRun(r); out.acked++; continue;
          }
          if (r.status === 'RETRY') { if (now() >= (r.retry_at || 0)) await page(c, a, r, 'page'); continue; }
          if (c.page.escalate_to.length && !r.escalated_at && now() - r.paged_at >= c.page.escalate_after_min * 60000) { await page(c, a, r, 'escalation'); out.escalated++; }
        }
      }
      // 3. morning brief (independent of paging: the brief is useful even with paging off)
      if (c.brief.enabled) out.brief = await briefDue(c);
      lastError = '';
    } catch (e) {
      lastError = String(e.message).slice(0, 200);
      log.error('after-hours tick failed', { err: e.message });
    } finally { busy = false; }
    return out;
  }

  // ---------------------------------------------------------------- morning brief
  function isWorkingDay(ms) {
    const c = cal(); if (!c) return false;
    const p = c.parts(ms); const w = c.window();
    return w.daySet.has(p.dow) && !w.holSet.has(p.dn);
  }
  async function briefDue(c) {
    const t = now(); const l = local(t);
    const [h, m] = c.brief.at.split(':').map(Number);
    if (!isWorkingDay(t) || l.min < h * 60 + m) return null;
    if (briefsCol.get(l.date)) return null;
    const b = makeBrief(t);
    if (l.min > h * 60 + m + 360) {   // engine was down at brief time: record it, do not mail yesterday's night at 20:00
      b.sent = { status: 'missed', at: t, error: 'the engine was not running at the brief time - open it here or use Send now' };
      briefsCol.put(b); return b.sent;
    }
    briefsCol.put(b);
    return deliverBrief(c, b, 'system:after-hours');
  }
  function makeBrief(t) {
    t = t || now();
    const from = previousDayEnd(t);
    const all = o.alerts ? alertsSince(from).filter((a) => a.created <= t && afterHoursReason(a.created)) : [];
    all.sort((x, y) => (y.severity - x.severity) || (x.created - y.created));
    const R = runs.all((r) => r.created >= from && r.created <= t);
    const count = (s) => R.filter((r) => r.status === s).length;
    const bySev = [4, 3, 2, 1, 0].map((s) => [sevName(s), all.filter((a) => a.severity === s).length]);
    const open = all.filter((a) => a.status === 'new');
    const prepared = R.filter((r) => r.case_id);
    let waiting = [];
    try { waiting = o.cases && o.cases.approvals ? o.cases.approvals.list({}).filter((x) => x.status === 'pending' && prepared.some((r) => r.case_id === x.case_id)) : []; } catch (e) { waiting = []; }
    const counts = { alerts: all.length, paged: count('PAGED') + count('ACKED') + count('ESCALATED'), escalated: R.filter((r) => r.escalated_at).length,
      failed: count('FAILED'), held: count('HELD'), quiet: count('QUIET'), late: count('LATE'), prepared: prepared.length, shadow: R.filter((r) => r.shadow).length,
      approvals_waiting: waiting.length, unacknowledged: open.length };
    const day = local(t).date;
    const fmt = (ms) => { const x = new Date(ms + 180 * 60000); return x.toISOString().slice(0, 16).replace('T', ' '); };
    const need = [];
    if (open.length) need.push(`${open.length} alert(s) raised after hours are still unacknowledged`);
    if (waiting.length) need.push(`${waiting.length} containment step(s) are waiting for approval (${uniq(waiting.map((x) => x.case_id)).join(', ')})`);
    if (counts.failed) need.push(`${counts.failed} page(s) could not be delivered - check the mail relay under Reports → Schedules`);
    if (counts.held) need.push(`${counts.held} alert(s) were held by the storm guard and nobody was paged for them`);
    const rows = all.slice(0, 60);
    const text = [`After-hours brief ${day}`, `Window: ${fmt(from)} → ${fmt(t)} (Riyadh)`, '',
      `Alerts raised after hours: ${counts.alerts} (${bySev.filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(', ') || 'none'})`,
      `Pages sent: ${counts.paged} · escalated: ${counts.escalated} · failed: ${counts.failed} · held: ${counts.held} · quiet rules: ${counts.quiet}`,
      `Cases prepared: ${counts.prepared}${counts.shadow ? ` (shadow: ${counts.shadow} would have been)` : ''} · approvals waiting: ${counts.approvals_waiting}`,
      '', 'Needs you today:', ...(need.length ? need.map((x) => `- ${x}`) : ['- nothing']), '',
      ...rows.map((a) => `${fmt(a.created)}  ${sevName(a.severity).padEnd(8)} ${a.id}  ${a.status}${a.assignee ? ` (${a.assignee})` : ''}  ${a.summary || a.rule_name}`),
      all.length > rows.length ? `… and ${all.length - rows.length} more on the portal` : ''].join('\n');
    const th = 'style="text-align:left;padding:4px 8px;border-bottom:1px solid #ccc"', td = 'style="padding:4px 8px;border-bottom:1px solid #eee"';
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111"><h2 style="margin:0 0 4px">After-hours brief · ${escH(day)}</h2>`
      + `<p style="color:#555;margin:0 0 12px">${escH(fmt(from))} → ${escH(fmt(t))} (Riyadh)</p>`
      + `<p><b>${counts.alerts}</b> alert(s) raised after hours${bySev.filter(([, n]) => n).length ? ` - ${escH(bySev.filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(', '))}` : ''}.<br>`
      + `Pages sent ${counts.paged} · escalated ${counts.escalated} · failed ${counts.failed} · held ${counts.held} · quiet ${counts.quiet}<br>`
      + `Cases prepared ${counts.prepared}${counts.shadow ? ` (shadow ${counts.shadow})` : ''} · approvals waiting ${counts.approvals_waiting}</p>`
      + `<h3 style="margin:16px 0 4px">Needs you today</h3><ul>${need.length ? need.map((x) => `<li>${escH(x)}</li>`).join('') : '<li>Nothing.</li>'}</ul>`
      + (rows.length ? `<table style="border-collapse:collapse;font-size:13px"><tr><th ${th}>Time</th><th ${th}>Severity</th><th ${th}>Alert</th><th ${th}>Status</th><th ${th}>Summary</th></tr>`
        + rows.map((a) => `<tr><td ${td}>${escH(fmt(a.created))}</td><td ${td}>${escH(sevName(a.severity))}</td><td ${td}>${escH(a.id)}</td><td ${td}>${escH(a.status)}${a.assignee ? ` (${escH(a.assignee)})` : ''}</td><td ${td}>${escH(a.summary || a.rule_name)}</td></tr>`).join('') + '</table>' : '')
      + (all.length > rows.length ? `<p>… and ${all.length - rows.length} more on the portal.</p>` : '')
      + `${link('soc-intel.html#mode') ? `<p><a href="${escH(link('soc-intel.html#mode'))}">Open After-hours mode</a></p>` : ''}<p style="color:#666;font-size:12px">${ZYB_ORG.short} SIEM · after-hours mode</p></div>`;
    return { id: day, at: t, window: { from, to: t }, counts, need, subject: `After-hours brief ${day}: ${counts.alerts} alert(s), ${need.length ? need.length + ' item(s) need you' : 'nothing needs you'}`, text, html, sent: null };
  }
  async function deliverBrief(c, b, by) {
    const to = c.brief.to.length ? c.brief.to : c.page.to;
    if (!to.length) { b.sent = { status: 'failed', at: now(), error: 'no brief recipient (brief.to and page.to are empty)' }; briefsCol.put(b); return b.sent; }
    try {
      await send(to, b.subject, b.text, b.html);
      b.sent = { status: 'ok', at: now(), recipients: to.length, by };
    } catch (e) { b.sent = { status: 'failed', at: now(), error: `${e.stage ? e.stage + ': ' : ''}${String(e.message).slice(0, 200)}`, by }; }
    briefsCol.put(b);
    auditFn({ at: now(), user: by, action: 'after-hours.brief', target: b.id, detail: { status: b.sent.status, recipients: to.length, alerts: b.counts.alerts } });
    return b.sent;
  }
  async function sendBrief(by) { const b = makeBrief(now()); b.manual = true; briefsCol.put(b); await deliverBrief(config(), b, by); return briefsCol.get(b.id); }
  async function testPage(by) {
    const c = config(); const rc = recipients(c, now());
    if (!rc.to.length) throw bad('no page recipient configured (page.to or a rota entry for tonight)');
    await send(rc.to, ('[After hours] Test page from the ' + ZYB_ORG.short + ' SIEM'), `This is a test of after-hours paging, sent by ${by}. No alert is behind it.`, `<p>This is a test of after-hours paging, sent by ${escH(by)}. No alert is behind it.</p>`);
    return { ok: true, recipients: rc.to.length, rota: rc.rota };
  }

  // ---------------------------------------------------------------- read side
  function status() {
    const c = config(); const t = now(); const reason = afterHoursReason(t);
    const night = nightKey(t); const R = runs.all((r) => r.night === night);
    let mailProblems = [];
    try { mailProblems = typeof o.mailProblems === 'function' ? o.mailProblems() : (typeof o.mail === 'function' ? [] : ['e-mail not available']); } catch (e) { mailProblems = [e.message]; }
    const rc = recipients(c, t);
    return { enabled: c.enabled, enabled_at: c.enabled_at, after_hours_now: !!reason, reason, prepare_mode: c.prepare.mode, brief: { enabled: c.brief.enabled, at: c.brief.at },
      tonight: { night, recipients: rc.to.length, rota: rc.rota, handled: R.length, paged: R.filter((r) => r.paged_at).length, failed: R.filter((r) => r.status === 'FAILED').length,
        held: R.filter((r) => r.status === 'HELD').length, prepared: R.filter((r) => r.case_id).length, unacknowledged: R.filter((r) => ['PAGED', 'ESCALATED', 'RETRY'].includes(r.status)).length },
      mail: { ok: !mailProblems.length, problems: mailProblems }, last_tick: lastTick, last_error: lastError, timer: !!timer,
      calendar: cal() ? cal().describe() : null };
  }
  function listRuns(limit = 200) { return runs.all().sort((x, y) => y.created - x.created).slice(0, Math.max(1, Math.min(1000, Number(limit) || 200))); }
  function listBriefs(limit = 30) { return briefsCol.all().sort((x, y) => y.at - x.at).slice(0, limit).map((b) => ({ id: b.id, at: b.at, window: b.window, counts: b.counts, need: b.need, subject: b.subject, sent: b.sent, manual: !!b.manual })); }
  function brief(day) { return briefsCol.get(String(day)) || null; }

  function start(ms = 30000) { if (!timer) { timer = setInterval(guardJob('afterhours.mode.tick', () => tick()), ms); if (timer.unref) timer.unref(); } return api; }
  function stop() { if (timer) clearInterval(timer); timer = null; }

  const api = { config, save, status, runs: listRuns, briefs: listBriefs, brief, makeBrief, sendBrief, testPage, tick, start, stop, nightKey, previousDayEnd };
  return api;
}

module.exports = { createAfterHoursMode, normalize, DEFAULTS, MODES };
