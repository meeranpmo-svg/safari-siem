// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Scan schedules in Riyadh time. Asia/Riyadh is UTC+03:00 all year (no daylight saving since 1980s), so a fixed
// offset is exact and needs no tz database.
//   normSchedule(raw) → {type:'manual'} | {type:'once', at:'YYYY-MM-DDTHH:MM'} | {type:'daily', time:'HH:MM'}
//                       | {type:'weekly', day:0-6 (0 = Sunday), time:'HH:MM'}             (throws 400 on bad input)
//   nextRun(schedule, fromMs) → epoch ms of the next start strictly after fromMs (null for manual / a past 'once')
//   normWindow(raw) → null | {start:'HH:MM', end:'HH:MM'}  (end < start = window crosses midnight)
//   inWindow(window, ms) → bool          riyadh(ms) → {y, mo, d, h, mi, dow}         label(schedule) → text
const OFFSET_MS = 3 * 3600 * 1000;
const DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });

function hhmm(v, what) {
  const m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(String(v == null ? '' : v).trim());
  if (!m) throw bad(`${what} must be HH:MM (24-hour, Riyadh time)`);
  return { h: Number(m[1]), mi: Number(m[2]), text: `${m[1]}:${m[2]}` };
}
function riyadh(ms) {
  const d = new Date(ms + OFFSET_MS);
  return { y: d.getUTCFullYear(), mo: d.getUTCMonth() + 1, d: d.getUTCDate(), h: d.getUTCHours(), mi: d.getUTCMinutes(), dow: d.getUTCDay() };
}
// Riyadh wall-clock → epoch ms
function fromRiyadh(y, mo, d, h, mi) { return Date.UTC(y, mo - 1, d, h, mi) - OFFSET_MS; }

function normSchedule(raw) {
  const s = raw && typeof raw === 'object' ? raw : { type: raw || 'manual' };
  const type = String(s.type || 'manual').toLowerCase();
  if (type === 'manual') return { type: 'manual' };
  if (type === 'once') {
    const m = /^(\d{4})-(\d{2})-(\d{2})[T ]([01]\d|2[0-3]):([0-5]\d)$/.exec(String(s.at || '').trim());
    if (!m) throw bad('schedule.at must be YYYY-MM-DDTHH:MM (Riyadh time)');
    const ms = fromRiyadh(+m[1], +m[2], +m[3], +m[4], +m[5]);
    const back = riyadh(ms);
    if (back.mo !== +m[2] || back.d !== +m[3]) throw bad('schedule.at is not a valid date');
    return { type: 'once', at: `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}` };
  }
  if (type === 'daily') return { type: 'daily', time: hhmm(s.time, 'schedule.time').text };
  if (type === 'weekly') {
    let day = s.day;
    if (typeof day === 'string' && DAYS.indexOf(day.slice(0, 3).toLowerCase()) >= 0) day = DAYS.indexOf(day.slice(0, 3).toLowerCase());
    day = Number(day);
    if (!Number.isInteger(day) || day < 0 || day > 6) throw bad('schedule.day must be 0-6 (0 = Sunday) or sun..sat');
    return { type: 'weekly', day, time: hhmm(s.time, 'schedule.time').text };
  }
  throw bad('schedule.type must be manual, once, daily or weekly');
}

function nextRun(schedule, fromMs = Date.now()) {
  const s = schedule || { type: 'manual' };
  if (s.type === 'manual') return null;
  if (s.type === 'once') {
    const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(s.at);
    const ms = fromRiyadh(+m[1], +m[2], +m[3], +m[4], +m[5]);
    return ms > fromMs ? ms : null;
  }
  const t = hhmm(s.time, 'schedule.time');
  const now = riyadh(fromMs);
  for (let add = 0; add <= 8; add++) {
    const cand = fromRiyadh(now.y, now.mo, now.d + add, t.h, t.mi);
    if (cand <= fromMs) continue;
    if (s.type === 'weekly' && riyadh(cand).dow !== s.day) continue;
    return cand;
  }
  return null;
}

function normWindow(raw) {
  if (raw === null || raw === undefined || raw === '' || (typeof raw === 'object' && !raw.start && !raw.end)) return null;
  if (typeof raw !== 'object') throw bad('window must be {start:"HH:MM", end:"HH:MM"}');
  const a = hhmm(raw.start, 'window.start'); const b = hhmm(raw.end, 'window.end');
  if (a.text === b.text) throw bad('window start and end must differ');
  return { start: a.text, end: b.text };
}
function inWindow(win, ms = Date.now()) {
  if (!win) return true;
  const r = riyadh(ms); const cur = r.h * 60 + r.mi;
  const [sh, sm] = win.start.split(':').map(Number); const [eh, em] = win.end.split(':').map(Number);
  const s = sh * 60 + sm; const e = eh * 60 + em;
  return s < e ? cur >= s && cur < e : cur >= s || cur < e;
}
function label(s) {
  if (!s || s.type === 'manual') return 'manual';
  if (s.type === 'once') return `once ${s.at.replace('T', ' ')} (Riyadh)`;
  if (s.type === 'daily') return `daily ${s.time} (Riyadh)`;
  return `weekly ${DAYS[s.day]} ${s.time} (Riyadh)`;
}

module.exports = { normSchedule, nextRun, normWindow, inWindow, riyadh, fromRiyadh, label, DAYS, OFFSET_MS };
