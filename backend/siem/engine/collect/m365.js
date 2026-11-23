// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
// Microsoft 365 collector — Office 365 Management Activity API (unified audit log: Entra ID, Exchange Online,
// SharePoint/OneDrive, general workloads, DLP). Pull model (no webhook: the engine is not reachable from the internet).
//
// Verified against Microsoft's documentation (2026-09):
//   API reference   https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference
//   Record schema   https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
//   App setup/auth  https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis
//   Cert assertion  https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
//   Client-cred.    https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
//
// Entra ID app registration (single tenant is enough): API permissions → "Office 365 Management APIs" →
//   Application permissions: ActivityFeed.Read (all audit content types) and ActivityFeed.ReadDlp (DLP.All incl. sensitive
//   data), then "Grant admin consent". Unified audit logging must be turned on in Microsoft Purview.
//   Credentials: a client secret, or (preferred) a certificate uploaded to the app registration.
// secrets.json:  "m365": { "tenant": "<tenant GUID>", "client_id": "<app GUID>", "client_secret": "…" }
//            or  "m365": { "tenant": "…", "client_id": "…", "cert_file": "/etc/sentra-siem/m365.crt", "key_file": "/etc/sentra-siem/m365.key", "key_passphrase"?: "…" }
// config.json:   "m365": { "enabled": true, "content_types": [...], "poll_s": 300, "publisher_id": "<tenant GUID>" }
//
// Protocol (per content type):
//   token     POST {authority}/{tenant}/oauth2/v2.0/token  grant_type=client_credentials, scope=https://manage.office.com/.default,
//             client_secret — or client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer + client_assertion
//             (JWT, alg PS256, header x5t#S256 = base64url SHA-256 of the certificate DER; aud = the token URL; iss = sub = client id)
//   subscribe GET  {root}/subscriptions/list; POST {root}/subscriptions/start?contentType=X for missing/disabled ones
//             (Microsoft asks for ≥ 15 min between start requests)
//   list      GET  {root}/subscriptions/content?contentType=X&startTime=…&endTime=… (≤ 24 h apart, start ≤ 7 days back;
//             window is on contentCreated, start inclusive / end exclusive); follow the NextPageUri response header
//   fetch     GET  <contentUri> → JSON array of audit records
//   {root} = {api_root}/api/v1.0/{tenant}/activity/feed; PublisherIdentifier=<tenant GUID> is added to every call (own quota).
// Robustness: records de-duplicated by record Id (bounded LRU) and blobs by contentId; checkpoint (last window end per
// content type + recent ids) in <state>/m365-checkpoint.json; each poll re-reads `overlap_min` before the checkpoint;
// HTTP 429 / AF429 / 5xx → back-off honouring Retry-After (exponential 60 s … 15 min); 401 → token refresh once.
// Records go through parser.parse(..., {collector: 'm365', src_type: 'm365', obj: record}) → pipeline.emit().
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ALL_TYPES = ['Audit.AzureActiveDirectory', 'Audit.Exchange', 'Audit.SharePoint', 'Audit.General', 'DLP.All'];
const DAY = 86400000;
const MAX_RECORD_IDS = 200000;
const PERSIST_RECORD_IDS = 50000;

class ThrottleError extends Error { constructor(msg, retryAfterMs) { super(msg); this.retryAfterMs = retryAfterMs; } }

const b64u = (b) => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
const isoMin = (ms) => new Date(ms).toISOString().slice(0, 19); // YYYY-MM-DDTHH:MM:SS (documented format)

function makeAssertion({ tenant, clientId, certPem, keyPem, passphrase, authority, nowMs }) {
  const der = new crypto.X509Certificate(certPem).raw;
  const header = { alg: 'PS256', typ: 'JWT', 'x5t#S256': b64u(crypto.createHash('sha256').update(der).digest()), x5t: b64u(crypto.createHash('sha1').update(der).digest()) };
  const t = Math.floor(nowMs / 1000);
  const payload = { aud: `${authority}/${tenant}/oauth2/v2.0/token`, iss: clientId, sub: clientId, jti: crypto.randomUUID(), nbf: t, iat: t, exp: t + 600 };
  const input = b64u(JSON.stringify(header)) + '.' + b64u(JSON.stringify(payload));
  const key = crypto.createPrivateKey(passphrase ? { key: keyPem, passphrase } : keyPem);
  const sig = crypto.sign('sha256', Buffer.from(input), { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST });
  return input + '.' + b64u(sig);
}

function retryAfterMs(res) {
  const v = res.headers.get('retry-after');
  if (!v) return 0;
  if (/^\d+$/.test(v)) return Number(v) * 1000;
  const t = Date.parse(v);
  return Number.isFinite(t) ? Math.max(0, t - Date.now()) : 0;
}

function noop(stats) { return { stop: async () => {}, stats: () => stats, pollNow: async () => {} }; }

function start({ config = {}, parser, pipeline, log, stateDir, fetchImpl, now = Date.now, autoStart = true } = {}) {
  const lg = log || { info() {}, warn() {}, error() {}, every() {} };
  const mc = { ...require('../config').DEFAULTS.m365, ...(config.m365 || {}) };
  const sec = (config.secrets && config.secrets.m365) || {};
  if (!mc.enabled) { lg.info('m365 collector: disabled'); return noop({ enabled: false }); }
  const tenant = String(sec.tenant || mc.tenant || '');
  const clientId = String(sec.client_id || mc.client_id || '');
  let certPem = sec.cert_pem || '';
  let keyPem = sec.key_pem || '';
  try {
    if (!certPem && sec.cert_file) certPem = fs.readFileSync(sec.cert_file, 'utf8');
    if (!keyPem && sec.key_file) keyPem = fs.readFileSync(sec.key_file, 'utf8');
  } catch (e) { lg.error('m365 collector: cannot read certificate/key', { err: e.message }); return noop({ enabled: true, error: 'certificate/key unreadable' }); }
  const useCert = !!(certPem && keyPem);
  const errs = [];
  if (!/^[0-9a-f-]{36}$/i.test(tenant) && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(tenant)) errs.push('secrets.m365.tenant (tenant GUID) missing/invalid');
  if (!/^[0-9a-f-]{36}$/i.test(clientId)) errs.push('secrets.m365.client_id (application GUID) missing/invalid');
  if (!useCert && !sec.client_secret) errs.push('secrets.m365.client_secret or cert_file + key_file required');
  if (errs.length) { lg.error('m365 collector: not started — ' + errs.join('; ')); return noop({ enabled: true, error: errs.join('; ') }); }
  const types = (Array.isArray(mc.content_types) && mc.content_types.length ? mc.content_types : ALL_TYPES).filter((t) => {
    if (!ALL_TYPES.includes(t)) { lg.warn('m365 collector: unknown content type ignored', { type: t }); return false; }
    return true;
  });
  const doFetch = fetchImpl || fetch;
  const authority = String(mc.authority).replace(/\/+$/, '');
  const apiRoot = String(mc.api_root).replace(/\/+$/, '');
  const apiOrigin = new URL(apiRoot).origin;
  const root = `${apiRoot}/api/v1.0/${tenant}/activity/feed`;
  const publisher = mc.publisher_id || (/^[0-9a-f-]{36}$/i.test(tenant) ? tenant : '');
  const srcId = mc.src_id || 'm365';
  const pollMs = Math.max(60, Number(mc.poll_s) || 300) * 1000;
  const overlapMs = Math.max(0, Number(mc.overlap_min) || 15) * 60000;
  const firstLookbackMs = Math.min(7 * DAY - 3600000, Math.max(1, Number(mc.first_lookback_h) || 24) * 3600000);
  const cpFile = stateDir ? path.join(stateDir, 'm365-checkpoint.json') : null;

  // ---------------------------------------------------------------- state
  let cp = { types: {}, content: [], records: [] };
  if (cpFile) { try { cp = { ...cp, ...JSON.parse(fs.readFileSync(cpFile, 'utf8')) }; } catch { /* first run */ } }
  const seenContent = new Map((cp.content || []).map(([id, exp]) => [id, exp]));
  const seenRecords = new Map((cp.records || []).map((id) => [id, 1]));
  const st = { enabled: true, implemented: true, auth: useCert ? 'certificate' : 'client_secret', types: {}, polls: 0, records: 0, duplicates: 0, blobs: 0, errors: 0, last_error: '', last_poll: 0, backoff_ms: 0, next_poll: 0, token_refreshes: 0 };
  for (const t of types) st.types[t] = { records: 0, blobs: 0, last_end: cp.types[t] ? cp.types[t].last_end : 0, subscribed: false, last_error: '' };

  function persist() {
    if (!cpFile) return;
    const t = now();
    for (const [id, exp] of seenContent) if (exp && exp < t) seenContent.delete(id);
    const recs = [...seenRecords.keys()].slice(-PERSIST_RECORD_IDS);
    const data = { types: cp.types, content: [...seenContent.entries()], records: recs, saved: new Date(t).toISOString() };
    try {
      fs.mkdirSync(path.dirname(cpFile), { recursive: true });
      fs.writeFileSync(cpFile + '.tmp', JSON.stringify(data));
      fs.renameSync(cpFile + '.tmp', cpFile);
    } catch (e) { lg.every('m365-persist', 60000, 'error', 'm365 collector: cannot write checkpoint', { err: e.message }); }
  }

  // ---------------------------------------------------------------- HTTP
  let token = null;
  let tokenExp = 0;
  async function getToken(force) {
    if (!force && token && now() < tokenExp - 300000) return token;
    const tokenUrl = `${authority}/${tenant}/oauth2/v2.0/token`;
    const form = new URLSearchParams({ client_id: clientId, scope: `${apiRoot}/.default`, grant_type: 'client_credentials' });
    if (useCert) {
      form.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      form.set('client_assertion', makeAssertion({ tenant, clientId, certPem, keyPem, passphrase: sec.key_passphrase, authority, nowMs: now() }));
    } else form.set('client_secret', sec.client_secret);
    const res = await doFetch(tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString(), signal: AbortSignal.timeout(30000) });
    const text = await res.text();
    let j = {};
    try { j = JSON.parse(text); } catch { /* non-JSON error page */ }
    if (res.status === 429) throw new ThrottleError('token endpoint throttled', retryAfterMs(res));
    if (!res.ok || !j.access_token) throw new Error(`token request failed: HTTP ${res.status} ${j.error || ''} ${String(j.error_description || '').split('\n')[0].slice(0, 200)}`.trim());
    token = j.access_token;
    tokenExp = now() + (Number(j.expires_in) || 3599) * 1000;
    st.token_refreshes++;
    return token;
  }

  function withPublisher(u) {
    const url = new URL(u);
    if (publisher && !url.searchParams.has('PublisherIdentifier')) url.searchParams.set('PublisherIdentifier', publisher);
    return url.toString();
  }

  async function api(method, u) {
    const url = withPublisher(u);
    if (new URL(url).origin !== apiOrigin) throw new Error(`refusing to call non-API origin ${new URL(url).origin}`);
    for (let attempt = 0; ; attempt++) {
      const res = await doFetch(url, { method, headers: { Authorization: 'Bearer ' + (await getToken(attempt > 0)), ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) }, body: method === 'POST' ? '' : undefined, signal: AbortSignal.timeout(60000) });
      const text = await res.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch { json = null; }
      const code = json && json.error ? json.error.code : '';
      if (res.status === 401 && attempt === 0) { token = null; continue; }
      if (res.status === 429 || code === 'AF429') throw new ThrottleError(`throttled (${code || 429})`, retryAfterMs(res));
      if (res.status >= 500 && attempt === 0 && code !== 'AF20022') { await new Promise((r) => setTimeout(r, 500)); continue; }
      if (!res.ok) { const e = new Error(`HTTP ${res.status} ${code} ${json && json.error ? String(json.error.message || '').slice(0, 200) : text.slice(0, 200)}`.trim()); e.code = code; e.status = res.status; throw e; }
      return { json, headers: res.headers };
    }
  }

  // ---------------------------------------------------------------- subscriptions
  const lastStart = new Map();
  async function ensureSubscriptions() {
    const r = await api('GET', `${root}/subscriptions/list`);
    const enabled = new Set((Array.isArray(r.json) ? r.json : []).filter((s) => String(s.status || '').toLowerCase() === 'enabled').map((s) => s.contentType));
    for (const t of types) {
      if (enabled.has(t)) { st.types[t].subscribed = true; continue; }
      if (now() - (lastStart.get(t) || 0) < 15 * 60000) continue;
      lastStart.set(t, now());
      try {
        await api('POST', `${root}/subscriptions/start?contentType=${encodeURIComponent(t)}`);
        st.types[t].subscribed = true;
        lg.info('m365 collector: subscription started (first content can take up to 12 h)', { content_type: t });
      } catch (e) {
        if (e instanceof ThrottleError) throw e;
        st.types[t].last_error = e.message;
        lg.error('m365 collector: cannot start subscription', { content_type: t, err: e.message });
      }
    }
  }

  // ---------------------------------------------------------------- records
  function emit(rec) {
    const id = rec && rec.Id ? String(rec.Id) : '';
    if (id) {
      if (seenRecords.has(id)) { st.duplicates++; return false; }
      seenRecords.set(id, 1);
      while (seenRecords.size > MAX_RECORD_IDS) seenRecords.delete(seenRecords.keys().next().value);
    }
    const ev = parser.parse(JSON.stringify(rec), { collector: 'm365', src_id: srcId, src_type: 'm365', peer_ip: '', rts: now(), obj: rec });
    pipeline.emit(ev);
    st.records++;
    return true;
  }

  async function pollType(t) {
    const ts = st.types[t];
    const tcp = cp.types[t] || (cp.types[t] = { last_end: 0 });
    const oldest = now() - 7 * DAY + 3600000;
    let from = Math.max(oldest, tcp.last_end ? tcp.last_end - overlapMs : now() - firstLookbackMs);
    while (!stopped && from < now() - 60000) {
      const to = Math.min(from + DAY, now());
      let url = `${root}/subscriptions/content?contentType=${encodeURIComponent(t)}&startTime=${isoMin(from)}&endTime=${isoMin(to)}`;
      for (let page = 0; url && page < 1000 && !stopped; page++) {
        let r;
        try { r = await api('GET', url); } catch (e) {
          if (e.code === 'AF20022' || e.code === 'AF20023') { ts.subscribed = false; lastStart.delete(t); throw new Error(`${t}: subscription missing/disabled (${e.code}) — will re-subscribe`); }
          throw e;
        }
        for (const item of Array.isArray(r.json) ? r.json : []) {
          if (!item || !item.contentUri || seenContent.has(item.contentId)) continue;
          const blob = await api('GET', item.contentUri);
          let n = 0;
          for (const rec of Array.isArray(blob.json) ? blob.json : []) if (emit(rec)) n++;
          seenContent.set(item.contentId, Date.parse(item.contentExpiration) || now() + 7 * DAY);
          ts.blobs++; st.blobs++; ts.records += n;
        }
        const next = r.headers.get('nextpageuri');
        url = next || null;
      }
      tcp.last_end = to;
      ts.last_end = to;
      persist();
      from = to;
    }
    ts.last_error = '';
  }

  // ---------------------------------------------------------------- loop
  let stopped = false;
  let timer = null;
  let running = null;
  let backoff = 0;

  async function pollNow() {
    if (running) return running;
    running = (async () => {
      st.polls++;
      st.last_poll = now();
      const errorsBefore = st.errors;
      try {
        await ensureSubscriptions();
        for (const t of types) {
          if (stopped) break;
          try { await pollType(t); } catch (e) {
            if (e instanceof ThrottleError) throw e;
            st.errors++; st.last_error = e.message; st.types[t].last_error = e.message;
            lg.every('m365-type-' + t, 300000, 'warn', 'm365 collector: poll failed', { content_type: t, err: e.message });
          }
        }
        backoff = 0;
        if (st.errors === errorsBefore) st.last_error = '';   // a clean poll clears the status (it used to show the last error for ever)
      } catch (e) {
        st.errors++;
        st.last_error = e.message;
        backoff = e instanceof ThrottleError ? Math.max(e.retryAfterMs || 0, backoff ? Math.min(backoff * 2, 900000) : 60000) : Math.min(backoff ? backoff * 2 : 60000, 900000);
        lg.every('m365-poll', 300000, 'warn', 'm365 collector: backing off', { err: e.message, backoff_ms: backoff });
      } finally {
        st.backoff_ms = backoff;
        persist();
        running = null;
      }
    })();
    return running;
  }

  function schedule(ms) {
    if (stopped) return;
    st.next_poll = now() + ms;
    timer = setTimeout(async () => { try { await guardJob('collect.m365.poll', async () => { const e0 = st.errors; await pollNow(); if (st.errors > e0) throw new Error(st.last_error || 'poll failed'); })(); } finally { schedule(backoff || pollMs); } }, ms);   // the next poll is always scheduled
    if (timer.unref) timer.unref();
  }

  if (autoStart) {
    lg.info('m365 collector: starting', { tenant, content_types: types, auth: st.auth, poll_s: pollMs / 1000 });
    schedule(2000);
  }

  return {
    pollNow,
    stats: () => ({ ...st, types: JSON.parse(JSON.stringify(st.types)) }),
    async stop() { stopped = true; if (timer) clearTimeout(timer); if (running) await running.catch(() => { /* the poll records its own error; stopping only waits for it */ }); persist(); },
  };
}

module.exports = { start, makeAssertion, ALL_TYPES };
