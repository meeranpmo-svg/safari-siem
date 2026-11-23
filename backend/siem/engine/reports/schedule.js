// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * Scheduled Attack Summary e-mails: schedule math (Asia/Riyadh, fixed UTC+3), settings (schedules + SMTP, the SMTP
 * password write-only in secrets.json), the in-engine scheduler (retries with back-off, audit, run history).
 *
 *   nextRun(schedule, afterMs, offMin = 180) → epoch ms of the next run strictly after afterMs
 *   reportPeriod(schedule, runMs, offMin) → {from, to, label}   daily = 24 h before the run, weekly = 7 days before,
 *                                                               monthly = the previous calendar month (local time)
 *   createReportSchedules({ state, config, log, now, summary, render, send, sleep, audit, retry })
 *     → { view(), save(body, by), sendNow(id, by), history(limit), tick(), start(), stop(), status() }
 *
 * Schedule  { id, name, period: daily|weekly|monthly, at: 'HH:MM' (Riyadh), weekday: 0-6 (weekly; 0 = Sunday),
 *             day_of_month: 1-31 (monthly; clamped to the month's last day), recipients[], lang: en|ar, enabled }
 * SMTP      { host, port, tls (implicit TLS), starttls, user, from, from_name, ca_file, reject_unauthorized, timeout_ms, helo,
 *             allow_insecure_auth } + password (write-only: POST {smtp:{password}}; GET shows password_set / set_at / set_by only)
 * Storage   state collections report_settings (doc "attack-summary": schedules, smtp, next_at per schedule) and
 *           report_runs (one doc per delivery: id, schedule_id, name, reason, at, period, status ok|failed|missed, attempts,
 *           recipients (count only), error, bytes, duration_ms); history keeps the newest 200.
 * Missed runs (engine down at the time): caught up once if missed by < catchup_h (default 12 h), else recorded as "missed".
 * Logs carry schedule ids, counts and SMTP stages — never credentials or recipient addresses.
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const crypto = require('node:crypto');
const { hm } = require('../util/business-hours');
const { isAddr, SmtpError } = require('./smtp');

const DAY = 86400000;
const PERIODS = ['daily', 'weekly', 'monthly'];
const SMTP_DEFAULTS = { host: '', port: 25, tls: false, starttls: true, user: '', from: '', from_name: (ZYB_ORG.short + ' SIEM'), ca_file: '', reject_unauthorized: true, timeout_ms: 30000, helo: '', allow_insecure_auth: false };
const SMTP_KEYS = Object.keys(SMTP_DEFAULTS);
const RETRY_DEFAULT = [60000, 5 * 60000, 15 * 60000]; // 3 retries after the first attempt
const ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }
function bad(msg, errors) { return Object.assign(new Error(msg), { code: 400, errors: errors || [msg] }); }

// ---------------------------------------------------------------- schedule math (fixed offset: Riyadh has no DST)
function localDate(ms, off) { const d = new Date(ms + off); return { y: d.getUTCFullYear(), m: d.getUTCMonth(), d: d.getUTCDate(), dow: d.getUTCDay() }; }
const daysIn = (y, m) => new Date(Date.UTC(y, m + 1, 0)).getUTCDate();

function nextRun(s, afterMs, offMin = 180) {
  const off = offMin * 60000;
  const at = hm(s.at); if (at === null || at >= 1440) return null;
  const L = localDate(afterMs, off);
  const atLocal = (y, m, d) => Date.UTC(y, m, d) + at * 60000 - off;
  if (s.period === 'daily') {
    let t = atLocal(L.y, L.m, L.d);
    while (t <= afterMs) t += DAY;
    return t;
  }
  if (s.period === 'weekly') {
    const wd = Number(s.weekday);
    let t = atLocal(L.y, L.m, L.d) + (((wd - L.dow) % 7) + 7) % 7 * DAY;
    while (t <= afterMs) t += 7 * DAY;
    return t;
  }
  if (s.period === 'monthly') {
    const want = Number(s.day_of_month) || 1;
    for (let i = 0; i < 3; i++) {
      const y = L.y + Math.floor((L.m + i) / 12); const m = (L.m + i) % 12;
      const t = atLocal(y, m, Math.min(want, daysIn(y, m)));
      if (t > afterMs) return t;
    }
  }
  return null;
}

function reportPeriod(s, runMs, offMin = 180) {
  const to = Math.floor(runMs / 60000) * 60000;
  if (s.period === 'daily') return { from: to - DAY, to, label: '24h' };
  if (s.period === 'weekly') return { from: to - 7 * DAY, to, label: '7d' };
  const off = offMin * 60000; const L = localDate(runMs, off);
  const end = Date.UTC(L.y, L.m, 1) - off;
  const start = Date.UTC(L.m === 0 ? L.y - 1 : L.y, (L.m + 11) % 12, 1) - off;
  return { from: start, to: end, label: 'custom' };
}

function normSchedule(x, i) {
  const errs = []; const p = `schedules[${i}]`;
  if (!isObj(x)) return { errs: [`${p} must be an object`] };
  const s = {
    id: x.id === undefined || x.id === '' ? `sch-${crypto.randomBytes(4).toString('hex')}` : String(x.id).toLowerCase(),
    name: String(x.name || '').trim().slice(0, 80),
    period: String(x.period || ''), at: String(x.at || ''), weekday: x.weekday === undefined ? 0 : Number(x.weekday),
    day_of_month: x.day_of_month === undefined ? 1 : Number(x.day_of_month),
    recipients: Array.isArray(x.recipients) ? [...new Set(x.recipients.map((r) => String(r).trim().toLowerCase()).filter(Boolean))] : [],
    lang: x.lang === 'ar' ? 'ar' : x.lang === undefined || x.lang === 'en' ? 'en' : String(x.lang), enabled: x.enabled === true,
  };
  if (!ID_RE.test(s.id)) errs.push(`${p}.id must be 1-40 lowercase letters, digits or dashes`);
  if (!s.name) errs.push(`${p}.name required`);
  if (!PERIODS.includes(s.period)) errs.push(`${p}.period must be daily, weekly or monthly`);
  const at = hm(s.at); if (at === null || at >= 1440) errs.push(`${p}.at must be HH:MM (00:00-23:59, Asia/Riyadh)`);
  if (!Number.isInteger(s.weekday) || s.weekday < 0 || s.weekday > 6) errs.push(`${p}.weekday must be 0-6 (0 = Sunday)`);
  if (!Number.isInteger(s.day_of_month) || s.day_of_month < 1 || s.day_of_month > 31) errs.push(`${p}.day_of_month must be 1-31`);
  if (!['en', 'ar'].includes(s.lang)) errs.push(`${p}.lang must be en or ar`);
  if (s.recipients.length > 50) errs.push(`${p}: at most 50 recipients`);
  const badR = s.recipients.filter((r) => !isAddr(r));
  if (badR.length) errs.push(`${p}.recipients: ${badR.length} invalid e-mail address(es)`);
  if (s.enabled && !s.recipients.length) errs.push(`${p}: an enabled schedule needs at least one recipient`);
  if (at !== null) s.at = `${String(Math.floor(at / 60)).padStart(2, '0')}:${String(at % 60).padStart(2, '0')}`;
  return { s, errs };
}

function normSmtp(base, patch) {
  const errs = [];
  const unknown = Object.keys(patch).filter((k) => !SMTP_KEYS.includes(k) && k !== 'password' && k !== 'clear_password');
  if (unknown.length) errs.push(`unknown smtp setting(s): ${unknown.join(', ')}`);
  const s = Object.assign({}, base);
  for (const k of SMTP_KEYS) if (patch[k] !== undefined) s[k] = patch[k];
  s.host = String(s.host || '').trim(); s.user = String(s.user || '').trim(); s.from = String(s.from || '').trim().toLowerCase();
  s.from_name = String(s.from_name || '').replace(/[\r\n]/g, ' ').slice(0, 80); s.ca_file = String(s.ca_file || '').trim(); s.helo = String(s.helo || '').trim();
  s.port = Number(s.port); s.timeout_ms = Number(s.timeout_ms);
  for (const k of ['tls', 'starttls', 'reject_unauthorized', 'allow_insecure_auth']) s[k] = s[k] === true || s[k] === 'true';
  if (s.host && !/^[A-Za-z0-9.-]{1,253}$|^\[?[0-9a-fA-F:.]+\]?$/.test(s.host)) errs.push('smtp.host must be a host name or IP address');
  if (!Number.isInteger(s.port) || s.port < 1 || s.port > 65535) errs.push('smtp.port must be 1-65535');
  if (s.from && !isAddr(s.from)) errs.push('smtp.from must be an e-mail address');
  if (s.user.length > 256 || /[\r\n]/.test(s.user)) errs.push('smtp.user invalid');
  if (s.ca_file && !/^\/[^\0]+$/.test(s.ca_file)) errs.push('smtp.ca_file must be an absolute path');
  if (s.helo && !/^[A-Za-z0-9.-]{1,253}$/.test(s.helo)) errs.push('smtp.helo must be a host name');
  if (!(s.timeout_ms >= 1000 && s.timeout_ms <= 300000)) errs.push('smtp.timeout_ms must be 1000-300000');
  if (s.tls && s.starttls) s.starttls = false; // implicit TLS already encrypts the session
  return { s, errs };
}

function writeJson600(file, obj) {
  if (SF.isSecretsPath(file)) return SF.write(file, obj);   // sealed at rest
  let st = null; try { st = fs.statSync(file); } catch { /* new file */ }
  const tmp = file + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
  try { if (st && process.getuid && process.getuid() === 0) fs.chownSync(tmp, st.uid, st.gid); } catch { /* not root */ }
  fs.renameSync(tmp, file);
}

function createReportSchedules(o = {}) {
  const { state } = o;
  if (!state) throw new Error('createReportSchedules needs state');
  const cfg = o.config || {};
  const log = o.log || { info() {}, warn() {}, error() {}, debug() {} };
  const now = o.now || Date.now;
  const offMin = cfg.tz_offset_min !== undefined ? Number(cfg.tz_offset_min) : 180;
  const sleep = o.sleep || ((ms) => new Promise((r) => { const t = setTimeout(r, ms); if (t.unref) t.unref(); }));
  const retry = Array.isArray(o.retry) ? o.retry : RETRY_DEFAULT;
  const catchupMs = ((cfg.reports && cfg.reports.catchup_h) || 12) * 3600000;
  const col = state.collection('report_settings');
  const runs = state.collection('report_runs');
  const auditFn = typeof o.audit === 'function' ? o.audit : (e) => { if (typeof state.audit === 'function') state.audit(e); };
  let timer = null; const running = new Map();

  function doc() { return col.get('attack-summary') || { id: 'attack-summary', schedules: [], smtp: {}, next: {}, cred: {} }; }
  function smtpSettings() { return Object.assign({}, SMTP_DEFAULTS, doc().smtp || {}); }
  function password() { const s = cfg.secrets && cfg.secrets.reports; return s && typeof s.smtp_password === 'string' ? s.smtp_password : ''; }
  function setPassword(pw, by) {
    const file = cfg._paths && cfg._paths.secrets;
    if (file) {
      let sec = {}; try { sec = SF.read(file) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
      sec.reports = Object.assign({}, sec.reports || {});
      if (pw) sec.reports.smtp_password = pw; else delete sec.reports.smtp_password;
      writeJson600(file, sec);
    }
    if (!cfg.secrets) Object.defineProperty(cfg, 'secrets', { value: {}, enumerable: false, writable: true });
    cfg.secrets.reports = Object.assign({}, cfg.secrets.reports || {});
    if (pw) cfg.secrets.reports.smtp_password = pw; else delete cfg.secrets.reports.smtp_password;
    log.info(pw ? 'reports: SMTP password stored (write-only)' : 'reports: SMTP password removed', { by: by || '', file: file || '(memory only)' });
    return pw ? { set_at: now(), set_by: by || '' } : {};
  }
  function smtpView() {
    const c = doc().cred || {};
    return Object.assign(smtpSettings(), { password_set: !!password(), password_set_at: c.set_at || 0, password_set_by: c.set_by || '' });
  }
  function problems() {
    const s = smtpSettings(); const p = [];
    if (!s.host) p.push('SMTP host not set');
    if (!s.from) p.push('sender (from) address not set');
    if (s.user && !password()) p.push('SMTP user set but no password stored');
    return p;
  }
  function schedules() { return (doc().schedules || []).map((s) => Object.assign({}, s, { next_at: s.enabled ? ((doc().next || {})[s.id] || nextRun(s, now(), offMin)) : null })); }
  function history(limit = 50) {
    return runs.all().sort((a, b) => b.at - a.at).slice(0, Math.max(1, Math.min(200, Number(limit) || 50)));
  }
  function view() {
    return { schedules: schedules(), smtp: smtpView(), problems: problems(), history: history(50), timezone: cfg.timezone || 'Asia/Riyadh', utc_offset_min: offMin, retry_ms: retry.slice() };
  }

  function save(body, by) {
    if (!isObj(body)) throw bad('body must be an object');
    const d = doc(); const errs = [];
    let list = d.schedules || [];
    if (body.schedules !== undefined) {
      if (!Array.isArray(body.schedules) || body.schedules.length > 20) throw bad('schedules must be an array (at most 20)');
      list = []; const ids = new Set();
      body.schedules.forEach((x, i) => { const r = normSchedule(x, i); errs.push(...r.errs); if (r.s) { if (ids.has(r.s.id)) errs.push(`schedules[${i}].id duplicate`); ids.add(r.s.id); list.push(r.s); } });
    }
    let smtp = d.smtp || {};
    let cred = d.cred || {};
    let pwChange = null;
    if (body.smtp !== undefined) {
      if (!isObj(body.smtp)) throw bad('smtp must be an object');
      const r = normSmtp(smtpSettings(), body.smtp);
      errs.push(...r.errs);
      smtp = r.s;
      if (typeof body.smtp.password === 'string' && body.smtp.password !== '') {
        if (body.smtp.password.length > 512 || /[\r\n\0]/.test(body.smtp.password)) errs.push('smtp.password invalid');
        else pwChange = body.smtp.password;
      } else if (body.smtp.clear_password === true) pwChange = '';
    }
    if (errs.length) throw bad(errs[0], errs);
    if (pwChange !== null) cred = setPassword(pwChange, by);
    const next = {};
    for (const s of list) if (s.enabled) next[s.id] = nextRun(s, now(), offMin);
    col.put({ id: 'attack-summary', schedules: list, smtp, cred, next, updated: now(), updated_by: by || '' });
    return { view: view(), password_changed: pwChange === null ? null : pwChange ? 'set' : 'cleared' };
  }

  function record(r) {
    runs.put(r);
    const all = runs.all();
    if (all.length > 200) for (const x of all.sort((a, b) => a.at - b.at).slice(0, all.length - 200)) runs.remove(x.id);
  }

  async function deliver(s, reason, by) {
    const t0 = now();
    const per = reportPeriod(s, t0, offMin);
    const run = { id: `run-${t0}-${crypto.randomBytes(3).toString('hex')}`, schedule_id: s.id, name: s.name, reason, by: by || 'scheduler', at: t0, period: { from: per.from, to: per.to },
      status: 'running', attempts: 0, recipients: (s.recipients || []).length, lang: s.lang, error: '', bytes: 0, duration_ms: 0 };
    record(run);
    let html = ''; let text = ''; let subject = '';
    try {
      const rep = await o.summary({ from: per.from, to: per.to, label: per.label, refresh: '1' });
      ({ html, text, subject } = o.render(rep, { lang: s.lang, period: s.period, name: s.name }));
    } catch (e) {
      Object.assign(run, { status: 'failed', error: `report generation failed: ${String(e.message).slice(0, 200)}`, duration_ms: now() - t0 });
      record(run); auditRun(run, by); return run;
    }
    const p = problems();
    if (p.length) { Object.assign(run, { status: 'failed', error: `not configured: ${p.join('; ')}`, duration_ms: now() - t0 }); record(run); auditRun(run, by); return run; }
    const smtp = Object.assign({}, smtpSettings(), { password: password() });
    const day = new Date(per.to - 1 + offMin * 60000).toISOString().slice(0, 10);
    const msg = { from: smtp.from, from_name: smtp.from_name, to: s.recipients, subject, text, html,
      attachments: [{ filename: `attack-summary-${day}${s.lang === 'ar' ? '-ar' : ''}.html`, content: html, contentType: 'text/html; charset=utf-8' }] };
    for (let i = 0; ; i++) {
      run.attempts = i + 1;
      try {
        const r = await o.send(smtp, msg);
        Object.assign(run, { status: 'ok', error: r.rejected && r.rejected.length ? `${r.rejected.length} recipient(s) refused` : '', accepted: (r.accepted || []).length, bytes: r.bytes || 0, duration_ms: now() - t0 });
        break;
      } catch (e) {
        const transient = !(e instanceof SmtpError) || e.transient;
        const errText = `${e.stage ? e.stage + ': ' : ''}${String(e.message).slice(0, 240)}`;
        log.warn('reports: delivery attempt failed', { schedule: s.id, attempt: i + 1, stage: e.stage || '', code: e.code || 0, transient });
        if (!transient || i >= retry.length) { Object.assign(run, { status: 'failed', error: errText, duration_ms: now() - t0 }); break; }
        Object.assign(run, { status: 'retrying', error: errText, retry_at: now() + retry[i] }); record(run);
        await sleep(retry[i]);
      }
    }
    delete run.retry_at;
    record(run);
    log.info('reports: attack summary delivery', { schedule: s.id, status: run.status, attempts: run.attempts, recipients: run.recipients, reason });
    auditRun(run, by);
    return run;
  }
  function auditRun(run, by) {
    try {
      auditFn({ at: new Date(now()).toISOString(), by: by || 'scheduler', role: by ? 'admin' : 'system', ip: '', action: run.status === 'ok' ? 'report.attack-summary.sent' : 'report.attack-summary.failed',
        target: run.schedule_id, detail: { run: run.id, reason: run.reason, attempts: run.attempts, recipients: run.recipients, error: run.error || '' } });
    } catch (e) { log.error('reports: audit write failed', { err: e.message }); }
  }

  function startRun(s, reason, by) {
    if (running.has(s.id)) return running.get(s.id);
    const p = deliver(s, reason, by).catch((e) => { log.error('reports: delivery crashed', { schedule: s.id, err: e.message }); return { status: 'failed', error: e.message }; })
      .finally(() => running.delete(s.id));
    running.set(s.id, p);
    return p;
  }

  async function sendNow(id, by) {
    const s = (doc().schedules || []).find((x) => x.id === id);
    if (!s) throw Object.assign(new Error(`schedule ${id} not found`), { code: 404 });
    if (!s.recipients.length) throw bad('the schedule has no recipients');
    if (running.has(id)) throw Object.assign(new Error('a delivery for this schedule is already running'), { code: 409 });
    return startRun(s, 'send-now', by);
  }

  /** One scheduler pass: run every enabled schedule whose time has come (catching up once after downtime). */
  function tick() {
    const d = doc(); const t = now(); const next = Object.assign({}, d.next || {}); let changed = false; const started = [];
    for (const s of d.schedules || []) {
      if (!s.enabled) continue;
      const due = next[s.id] || nextRun(s, t - 1, offMin);
      if (!next[s.id]) { next[s.id] = due; changed = true; }
      if (due > t) continue;
      next[s.id] = nextRun(s, t, offMin); changed = true;
      if (t - due > catchupMs) {
        record({ id: `run-${t}-${crypto.randomBytes(3).toString('hex')}`, schedule_id: s.id, name: s.name, reason: 'schedule', by: 'scheduler', at: t, period: null, status: 'missed', attempts: 0, recipients: s.recipients.length, error: `engine was not running at ${new Date(due).toISOString()}`, bytes: 0, duration_ms: 0 });
        continue;
      }
      started.push(startRun(s, t - due > 120000 ? 'catch-up' : 'schedule'));
    }
    if (changed) col.put(Object.assign({}, d, { next }));
    return started;
  }

  function start(intervalMs = 30000) {
    if (timer) return;
    timer = setInterval(() => { try { tick(); } catch (e) { log.error('reports: scheduler tick failed', { err: e.message }); } }, intervalMs);
    if (timer.unref) timer.unref();
  }
  function stop() { if (timer) clearInterval(timer); timer = null; return Promise.all([...running.values()]).then(() => undefined); }
  function status() { return { running: [...running.keys()], timer: !!timer, problems: problems() }; }

  // the same relay for other engine mail (after-hours pages, morning brief): one SMTP setting, password never leaves here
  async function mail(message) {
    const p = problems();
    if (p.length) throw Object.assign(new Error(`e-mail not configured: ${p.join('; ')}`), { stage: 'config', transient: false });
    const smtp = Object.assign({}, smtpSettings(), { password: password() });
    return o.send(smtp, Object.assign({ from: smtp.from, from_name: smtp.from_name }, message));
  }
  return { view, save, sendNow, history, tick, start, stop, status, smtpSettings, mail, mailProblems: problems, password: () => (password() ? '[set]' : '') };
}

module.exports = { createReportSchedules, nextRun, reportPeriod, normSchedule, SMTP_DEFAULTS };
