// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
const zlib = require('node:zlib');
const fs = require('node:fs');
const path = require('node:path');
// Mimecast collector - pull model, Mimecast API 2.0 (read-only):
//   token   POST {base}/oauth/token                      form: client_id, client_secret, grant_type=client_credentials
//   batch   GET  {base}/siem/v1/batch/events/cg?type=<log type>&dateRangeStartsAt=YYYY-MM-DD&pageSize=<n>[&nextPage=<token>]
//           → { value: [ { url, ... } ], '@nextPage': '<token>', isCaughtUp: true|false }; each url is a pre-signed link to a
//           file of events (JSON lines, possibly gzip) - downloaded WITHOUT the Mimecast token (it is another host).
// Mimecast allows 50 batch calls per 15 minutes (calls that return nothing new do not count) and keeps 7 days: the collector
// polls every poll_min (default 15) and makes at most max_calls per poll. Progress per log type is the @nextPage token,
// kept in <state_dir>/mimecast-cursor.json, so a restart neither repeats nor skips files.
// The API application (Mimecast Administration → Integrations → API and Platform Integrations) needs read access to the
// SIEM / security events only. Exact field names of the response are read defensively and must be confirmed against the
// customer's tenant on the first run (Test shows what came back).
// config.json  "mimecast": { "enabled": true, "base_url": "https://api.services.mimecast.com", "types": [...], "poll_min": 15 }
// secrets.json "mimecast": { "client_id": "...", "client_secret": "..." }   (sealed at rest, never returned, never logged)

const DEFAULT_BASE = 'https://api.services.mimecast.com';
const DEFAULT_TYPES = ['receipt', 'process', 'delivery', 'av', 'spam', 'impersonation protect', 'url protect', 'attachment protect', 'internal email protect', 'journal'];
const TYPE_RE = /^[a-z][a-z ]{1,39}$/;
const MAX_FILE = 100 * 1024 * 1024;

// the API host must be Mimecast's: the client secret is never sent anywhere else
function baseOk(u) { try { const x = new URL(u); return x.protocol === 'https:' && /(^|\.)mimecast\.com$/i.test(x.hostname) && !x.username && !x.password; } catch { return false; } }

function noop(stats) { return { stop: async () => {}, stats: () => stats, pollNow: async () => {}, testConnection: async () => ({ ok: false, steps: [{ ok: false, text: stats.error || 'the Mimecast collector is off' }] }) }; }

// one downloaded file → event objects (gzip or plain; JSON lines, a JSON array, or {data|value|logs:[…]})
function decodeFile(buf) {
  let b = Buffer.from(buf);
  if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) b = zlib.gunzipSync(b, { maxOutputLength: MAX_FILE * 4 });
  const text = b.toString('utf8').replace(/^﻿/, '').trim();
  if (!text) return { items: [], bad: 0 };
  if (text[0] === '[' || text[0] === '{') {
    try {
      const j = JSON.parse(text);
      if (Array.isArray(j)) return { items: j.filter((x) => x && typeof x === 'object'), bad: 0 };
      const arr = j.data || j.value || j.logs || j.events;
      if (Array.isArray(arr)) return { items: arr.filter((x) => x && typeof x === 'object'), bad: 0 };
      return { items: [j], bad: 0 };
    } catch { /* not one JSON document: read it as JSON lines below */ }
  }
  const items = []; let bad = 0;
  for (const line of text.split(/\r?\n/)) { const l = line.trim(); if (!l) continue; try { const o = JSON.parse(l); if (o && typeof o === 'object' && !Array.isArray(o)) items.push(o); else bad++; } catch { bad++; } }
  return { items, bad };
}
// the download links in one batch answer: value[].url, or any https string in an item (the key is to be confirmed per tenant)
function linksOf(j) {
  const v = j && (Array.isArray(j.value) ? j.value : Array.isArray(j.data) ? j.data : []);
  const out = [];
  for (const it of v || []) {
    if (typeof it === 'string' && /^https:\/\//.test(it)) { out.push(it); continue; }
    if (!it || typeof it !== 'object') continue;
    const u = it.url || it.downloadUrl || it.link || Object.values(it).find((x) => typeof x === 'string' && /^https:\/\//.test(x));
    if (u) out.push(u);
  }
  return out;
}

function start({ config = {}, parser, pipeline, log, stateDir, fetchImpl, now = Date.now, autoStart = true } = {}) {
  const lg = log || { info() {}, warn() {}, error() {} };
  const mc = Object.assign({ enabled: false, base_url: DEFAULT_BASE, types: DEFAULT_TYPES, poll_min: 15, first_lookback_days: 1, page_size: 100, max_calls: 40, src_id: 'mimecast' }, config.mimecast || {});
  const sec = (config.secrets && config.secrets.mimecast) || {};
  const id = String(sec.client_id || ''), secret = String(sec.client_secret || '');
  if (!mc.enabled) return noop({ enabled: false });
  const errs = [];
  if (!id || !secret) errs.push('the Mimecast client ID and secret are not set');
  if (!baseOk(mc.base_url)) errs.push('mimecast.base_url must be an https address on mimecast.com');
  const types = (Array.isArray(mc.types) ? mc.types : []).map((t) => String(t).toLowerCase().trim()).filter((t) => TYPE_RE.test(t));
  if (!types.length) errs.push('no log type selected');
  if (errs.length) { lg.error('mimecast collector: not started - ' + errs.join('; ')); return noop({ enabled: true, error: errs.join('; ') }); }
  const base = mc.base_url.replace(/\/+$/, ''), doFetch = fetchImpl || fetch;
  const cursorFile = stateDir ? path.join(stateDir, 'mimecast-cursor.json') : '';
  let cursor = {}; try { if (cursorFile) cursor = JSON.parse(fs.readFileSync(cursorFile, 'utf8')) || {}; } catch { cursor = {}; /* first run, or an unreadable cursor: start from the look-back */ }
  const st = { enabled: true, polls: 0, calls: 0, files: 0, records: 0, bad_lines: 0, errors: 0, last_poll_at: null, last_error: '', by_type: {}, caught_up: {}, base_url: base };
  let token = '', tokenUntil = 0, timer = null, stopped = false, running = null, backoff = 0;
  const save = () => { if (!cursorFile) return; try { fs.writeFileSync(cursorFile + '.tmp', JSON.stringify(cursor)); fs.renameSync(cursorFile + '.tmp', cursorFile); } catch (e) { lg.warn('mimecast cursor not saved', { err: e.message }); } };
  const day = (ms) => new Date(ms).toISOString().slice(0, 10);
  const emit = (obj, type) => { const o = Object.assign({ _mc: type }, obj); const ev = parser.parse(JSON.stringify(o), { collector: 'mimecast', src_id: mc.src_id, src_type: 'mimecast', peer_ip: '', rts: now(), obj: o }); pipeline.emit(ev); st.records++; st.by_type[type] = (st.by_type[type] || 0) + 1; };

  async function getToken(force) {
    if (!force && token && now() < tokenUntil) return token;
    let res;
    try { res = await doFetch(base + '/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: new URLSearchParams({ client_id: id, client_secret: secret, grant_type: 'client_credentials' }).toString(), signal: AbortSignal.timeout(30000) }); }
    catch (e) { throw Object.assign(new Error(`cannot reach ${new URL(base).hostname}: ${(e.cause && e.cause.code) || e.message} (outbound HTTPS from the SIEM server is needed)`), { retry: true }); }
    let j = null; try { j = await res.json(); } catch { j = null; /* an error page instead of JSON: the status says enough */ }
    if (res.status === 400 || res.status === 401 || res.status === 403) throw new Error('Mimecast refused the client ID / secret (HTTP ' + res.status + ') - check them in Mimecast Administration → API and Platform Integrations');
    if (!res.ok || !j || !j.access_token) throw Object.assign(new Error('Mimecast token request failed (HTTP ' + res.status + ')'), { retry: res.status === 429 || res.status >= 500 });
    token = String(j.access_token); tokenUntil = now() + Math.max(60, Number(j.expires_in) || 1800) * 1000 - 60000;
    return token;
  }
  async function api(url, retried) {
    const t = await getToken(false);
    let res;
    try { res = await doFetch(url, { headers: { Authorization: 'Bearer ' + t, Accept: 'application/json' }, signal: AbortSignal.timeout(60000) }); }
    catch (e) { throw Object.assign(new Error(`cannot reach ${new URL(base).hostname}: ${(e.cause && e.cause.code) || e.message}`), { retry: true }); }
    st.calls++;
    if (res.status === 401 && !retried) { token = ''; return api(url, true); }   // the token expired early: one fresh token, then give up
    let j = null; try { j = await res.json(); } catch { j = null; /* not JSON: handled by the status below */ }
    if (res.status === 429) throw Object.assign(new Error('Mimecast rate limit reached (50 calls / 15 min) - the next poll continues'), { retry: true, rate: true });
    if (res.status === 403) throw new Error('the Mimecast API application may not read SIEM events (HTTP 403) - give it the SIEM / security events read permission');
    if (res.status >= 500) throw Object.assign(new Error('Mimecast API HTTP ' + res.status), { retry: true });
    if (!res.ok) { const m = j && (j.fail && j.fail[0] && (j.fail[0].message || (j.fail[0].errors && j.fail[0].errors[0] && j.fail[0].errors[0].message)) || j.message || j.error); throw Object.assign(new Error('Mimecast API HTTP ' + res.status + (m ? ': ' + String(m).slice(0, 200) : '')), { perType: true }); }
    return j || {};
  }
  async function download(u) {
    // the pre-signed link is for another host (cloud storage): no Mimecast token goes with it
    if (!/^https:\/\//.test(u)) throw new Error('a download link that is not https was refused');
    const res = await doFetch(u, { signal: AbortSignal.timeout(120000) });
    if (!res.ok) throw Object.assign(new Error('download HTTP ' + res.status + (res.status === 403 ? ' (the link expired - it is fetched again on the next poll)' : '')), { retry: true });
    const len = Number(res.headers && res.headers.get ? res.headers.get('content-length') : 0);
    if (len > MAX_FILE) throw new Error('a Mimecast log file larger than 100 MB was skipped');
    return Buffer.from(await res.arrayBuffer());
  }
  // one log type: follow @nextPage until caught up or the call budget is spent; the cursor moves only after a file is in
  async function pullType(type, budget) {
    const cur = cursor[type] || {};
    let calls = 0, next = cur.next || '';
    while (calls < budget && !stopped) {
      const q = new URLSearchParams({ type, pageSize: String(mc.page_size) });
      if (next) q.set('nextPage', next); else q.set('dateRangeStartsAt', cur.date || day(now() - mc.first_lookback_days * 86400000));
      const j = await api(base + '/siem/v1/batch/events/cg?' + q.toString()); calls++;
      for (const u of linksOf(j)) {
        const { items, bad } = decodeFile(await download(u));
        for (const o of items) emit(o, type);
        st.files++; st.bad_lines += bad;
      }
      const nx = j['@nextPage'] || j.nextPage || (j.meta && j.meta.pagination && j.meta.pagination.next) || '';
      if (nx) { next = String(nx); cursor[type] = { next, date: cur.date || '' }; save(); }
      const caught = j.isCaughtUp === true || (j.meta && j.meta.isCaughtUp === true) || !nx;
      st.caught_up[type] = caught;
      if (caught) break;
    }
    return calls;
  }
  async function poll() {
    if (running) return running;
    running = (async () => {
      st.polls++; st.last_poll_at = new Date(now()).toISOString();
      const problems = [];
      try {
        let left = mc.max_calls;
        for (const t of types) {
          if (stopped || left <= 0) break;
          try { left -= await pullType(t, Math.max(1, Math.min(left, Math.ceil(mc.max_calls / types.length) + 2))); }
          catch (e) { if (!e.perType) throw e; problems.push(t + ': ' + e.message); }   // one unknown / refused log type does not stop the others
        }
        st.last_error = problems.join(' · ').slice(0, 600); backoff = 0;
      } catch (e) { st.errors++; st.last_error = e.message; lg.warn('mimecast collector: poll failed', { err: e.message }); if (e.retry) backoff = Math.min(60 * 60000, backoff ? backoff * 2 : 15 * 60000); }
      finally { save(); running = null; }
    })();
    return running;
  }
  // Test: the token, then one batch call for the first log type (no files downloaded); every step says what it found
  async function testConnection() {
    const steps = [];
    try { await getToken(true); steps.push({ ok: true, text: 'signed in to ' + new URL(base).hostname + ' with the client ID / secret' }); }
    catch (e) { steps.push({ ok: false, text: e.message }); return { ok: false, steps }; }
    try {
      const q = new URLSearchParams({ type: types[0], pageSize: '1', dateRangeStartsAt: day(now() - 86400000) });
      const j = await api(base + '/siem/v1/batch/events/cg?' + q.toString());
      steps.push({ ok: true, text: `SIEM batch readable for "${types[0]}": ${linksOf(j).length} file link(s), answer keys: ${Object.keys(j).slice(0, 8).join(', ') || 'none'}` });
    } catch (e) { steps.push({ ok: false, text: e.message }); }
    return { ok: steps.every((s) => s.ok), steps };
  }
  const job = () => guardJob('collect.mimecast.poll', async () => { await poll(); if (st.last_error) throw new Error(st.last_error); })();
  function schedule() { if (stopped) return; timer = setTimeout(async () => { try { await job(); } finally { schedule(); } }, mc.poll_min * 60000 + backoff); if (timer.unref) timer.unref(); }
  if (autoStart) { const t0 = setTimeout(() => { job().finally(schedule); }, 30000); if (t0.unref) t0.unref(); }
  lg.info('mimecast collector: started', { base: new URL(base).hostname, types: types.length, poll_min: mc.poll_min });
  return { stop: async () => { stopped = true; if (timer) clearTimeout(timer); if (running) await running.catch(() => { /* the poll records its own error in stats; stopping only waits for it */ }); save(); }, stats: () => st, pollNow: poll, testConnection };
}

module.exports = { start, decodeFile, linksOf, baseOk, DEFAULT_TYPES, DEFAULT_BASE, TYPE_RE };
