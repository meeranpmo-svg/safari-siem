// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
// Cloudflare collector - pull model (the SIEM is not reachable from the internet, so Logpush-to-HTTP is not used).
//   Account audit log   GET  https://api.cloudflare.com/client/v4/accounts/{account_id}/audit_logs?since=…&direction=asc&per_page=…&page=…
//   Security events     POST https://api.cloudflare.com/client/v4/graphql   firewallEventsAdaptive per zone (WAF, rate limiting,
//                       bot management, IP access rules, custom rules): datetime, action, client IP / country / ASN, host,
//                       path, method, user agent, source, rule id, ray id
// API token (Cloudflare dashboard → My Profile → API Tokens → Create custom token), READ-ONLY permissions:
//   Account → Account Settings: Read (audit log)   ·   Zone → Analytics: Read (security events, every selected zone)
// config.json  "cloudflare": { "enabled": true, "account_id": "…", "zones": ["<zone id>", …], "poll_s": 300, "src_id": "cloudflare" }
// secrets.json "cloudflare": { "api_token": "…" }
// Every record → parser (src_type cloudflare, parse/cloudflare.js) → pipeline.emit(). Cursor per stream in <state_dir>/
// cloudflare-cursor.json (last timestamp seen); first run looks back first_lookback_h (default 24 h). 429 / 5xx → back-off.
const fs = require('node:fs');
const path = require('node:path');

const API = 'https://api.cloudflare.com/client/v4';
const ID_RE = /^[0-9a-f]{32}$/i;
const SEC_FIELDS = 'datetime action clientIP clientCountryName clientAsn clientASNDescription clientRequestHTTPHost clientRequestPath clientRequestQuery clientRequestHTTPMethodName source ruleId rayName userAgent edgeResponseStatus description';

function noop(stats) { return { stop: async () => {}, stats: () => stats, pollNow: async () => {} }; }

function start({ config = {}, parser, pipeline, log, stateDir, fetchImpl, now = Date.now, autoStart = true } = {}) {
  const lg = log || { info() {}, warn() {}, error() {} };
  const cc = Object.assign({ enabled: false, account_id: '', zones: [], poll_s: 300, first_lookback_h: 24, src_id: 'cloudflare', max_pages: 20 }, config.cloudflare || {});
  const token = String((config.secrets && config.secrets.cloudflare && config.secrets.cloudflare.api_token) || '');
  if (!cc.enabled) return noop({ enabled: false });
  const errs = [];
  if (!token) errs.push('secrets.cloudflare.api_token missing');
  if (cc.account_id && !ID_RE.test(cc.account_id)) errs.push('cloudflare.account_id must be the 32-character account ID');
  const zones = (Array.isArray(cc.zones) ? cc.zones : []).filter((z) => ID_RE.test(String(z)));
  if (!cc.account_id && !zones.length) errs.push('set cloudflare.account_id and/or cloudflare.zones');
  if (errs.length) { lg.error('cloudflare collector: not started - ' + errs.join('; ')); return noop({ enabled: true, error: errs.join('; ') }); }
  const doFetch = fetchImpl || fetch;
  const cursorFile = stateDir ? path.join(stateDir, 'cloudflare-cursor.json') : '';
  let cursor = {}; try { if (cursorFile) cursor = JSON.parse(fs.readFileSync(cursorFile, 'utf8')); } catch { cursor = {}; }
  const st = { enabled: true, polls: 0, records: 0, audit: 0, security: 0, errors: 0, last_poll_at: null, last_error: '', zones: zones.length, account: !!cc.account_id };
  let timer = null, stopped = false, running = null, backoff = 0;
  const save = () => { if (!cursorFile) return; try { fs.writeFileSync(cursorFile + '.tmp', JSON.stringify(cursor)); fs.renameSync(cursorFile + '.tmp', cursorFile); } catch (e) { lg.warn('cloudflare cursor not saved', { err: e.message }); } };
  const since = (k) => cursor[k] || new Date(now() - cc.first_lookback_h * 3600000).toISOString();
  const emit = (obj) => { const ev = parser.parse(JSON.stringify(obj), { collector: 'cloudflare', src_id: cc.src_id, src_type: 'cloudflare', peer_ip: '', rts: now(), obj }); pipeline.emit(ev); st.records++; };

  async function call(url, opts) {
    const res = await doFetch(url, Object.assign({ headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' }, signal: AbortSignal.timeout(30000) }, opts || {}));
    let j = null; try { j = await res.json(); } catch { j = null; }
    if (res.status === 429 || res.status >= 500) throw Object.assign(new Error(`Cloudflare API HTTP ${res.status}`), { retry: true });
    if (!res.ok || (j && j.success === false)) { const m = j && j.errors && j.errors[0] ? `${j.errors[0].code}: ${j.errors[0].message}` : `HTTP ${res.status}`; throw new Error(`Cloudflare API ${m}${res.status === 403 ? ' (token permission missing?)' : ''}`); }
    return j;
  }
  async function pullAudit() {
    const k = 'audit', from = since(k); let last = from, page = 1;
    for (; page <= cc.max_pages; page++) {
      const q = new URLSearchParams({ since: from, direction: 'asc', per_page: '1000', page: String(page) });
      const j = await call(`${API}/accounts/${cc.account_id}/audit_logs?${q}`);
      const rows = (j && j.result) || [];
      for (const r of rows) { if (r.when && r.when <= from) continue; emit(Object.assign({ _cf: 'audit' }, r)); st.audit++; if (r.when > last) last = r.when; }
      if (rows.length < 1000) break;
    }
    cursor[k] = last;
  }
  async function pullSecurity(zone) {
    const k = 'sec:' + zone, from = since(k), to = new Date(now()).toISOString();
    const query = `query($zone:String!,$from:Time!,$to:Time!){viewer{zones(filter:{zoneTag:$zone}){firewallEventsAdaptive(filter:{datetime_gt:$from,datetime_leq:$to},limit:10000,orderBy:[datetime_ASC]){${SEC_FIELDS}}}}}`;
    const j = await call(`${API}/graphql`, { method: 'POST', body: JSON.stringify({ query, variables: { zone, from, to } }) });
    if (j && j.errors && j.errors.length) throw new Error('Cloudflare GraphQL: ' + String(j.errors[0].message || '').slice(0, 200));
    const rows = (((j || {}).data || {}).viewer || {}).zones;
    let last = from;
    for (const r of (rows && rows[0] && rows[0].firewallEventsAdaptive) || []) { emit(Object.assign({ _cf: 'security', _zone: zone }, r)); st.security++; if (r.datetime > last) last = r.datetime; }
    cursor[k] = last;
  }
  async function poll() {
    if (running) return running;
    running = (async () => {
      st.polls++; st.last_poll_at = new Date(now()).toISOString();
      try {
        if (cc.account_id) await pullAudit();
        for (const z of zones) { if (stopped) break; await pullSecurity(z); }
        st.last_error = ''; backoff = 0;
      } catch (e) { st.errors++; st.last_error = e.message; lg.warn('cloudflare collector: poll failed', { err: e.message }); if (e.retry) backoff = Math.min(15 * 60000, backoff ? backoff * 2 : 60000); }
      finally { save(); running = null; }
    })();
    return running;
  }
  function schedule() { if (stopped) return; timer = setTimeout(async () => { try { await guardJob('collect.cloudflare.poll', async () => { await poll(); if (st.last_error) throw new Error(st.last_error); })(); } finally { schedule(); } }, Math.max(60000, cc.poll_s * 1000) + backoff); if (timer.unref) timer.unref(); }
  if (autoStart) { setTimeout(() => { guardJob('collect.cloudflare.poll', async () => { await poll(); if (st.last_error) throw new Error(st.last_error); })().finally(schedule); }, 20000).unref(); }
  lg.info('cloudflare collector: started', { account: !!cc.account_id, zones: zones.length, poll_s: cc.poll_s });
  return { stop: async () => { stopped = true; if (timer) clearTimeout(timer); if (running) await running.catch(() => { /* the poll records its own error in stats; stopping only waits for it */ }); save(); }, stats: () => st, pollNow: poll };
}

module.exports = { start, SEC_FIELDS };
