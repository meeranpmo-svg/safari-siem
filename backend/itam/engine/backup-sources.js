// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Read-only clients for the backup platforms. Each collect(cred, opts) returns
//   {ok, platform, version?, objects: [{name, kind, job, last_attempt, last_status: success|warning|failed|running,
//    last_success, size_bytes?, policy?}], jobs: [{id, job, client?, status, start, end, error?}]} | {ok:false, error_class, error}
// covering the last `days` days (default 7). Only GET requests, plus each platform's own sign-in POST; guard() refuses
// anything else before a socket is opened.
//   NetBackup (Administration API, OAS 3.0): https://<primary>:1556/netbackup, API key in the Authorization header,
//     media type application/vnd.netbackup+json;version=<api_version> (default 14.0). GET /admin/jobs (backup jobs),
//     GET /catalog/images (successful images). JSON:API paging (page[offset] / page[limit]).
//   Veeam Backup & Replication REST: https://<server>:9419, POST /api/oauth2/token (password grant), header
//     x-api-version (default 1.1-rev0). GET /api/v1/sessions (job runs), GET /api/v1/restorePoints (per object).
//   Cohesity (cluster public API v1): https://<cluster>, an API key (header apiKey) or POST
//     /irisservices/api/v1/public/accessTokens; GET /irisservices/api/v1/public/protectionRuns (runs with per-object status).
// cred = {target: {base_url, ca_file?, tls_fingerprint?, api_version?, domain?}, secret: {api_key? | username + password}}
const httpc = require('./discovery/httpc');

const DAY = 86400000;
const ERR = (code, message, extra) => Object.assign(new Error(message), { code }, extra || {});
const cls = (e) => (['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol'].includes(e && e.code) ? e.code : 'protocol');
const iso = (v) => { if (v == null || v === '') return null; const t = typeof v === 'number' ? v : Date.parse(v); return Number.isFinite(t) && t > 0 ? new Date(t).toISOString() : null; };
const low = (v) => String(v || '').trim().toLowerCase();

const ALLOW = {
  netbackup: (m, p) => m === 'GET' && /^\/netbackup\/(admin\/jobs|catalog\/images)(\?|$)/.test(p),
  veeam: (m, p) => (m === 'POST' && p === '/api/oauth2/token') || (m === 'POST' && p === '/api/oauth2/logout') || (m === 'GET' && /^\/api\/v1\/(sessions|restorePoints|serverInfo)(\?|$)/.test(p)),
  cohesity: (m, p) => (m === 'POST' && p === '/irisservices/api/v1/public/accessTokens') || (m === 'GET' && /^\/irisservices\/api\/v1\/public\/(protectionRuns|basicClusterInfo)(\?|$)/.test(p)),
};
function guard(kind, method, path) {
  if (ALLOW[kind] && ALLOW[kind](method, path)) return;
  throw ERR('config', `${kind} backup reading is read-only; refusing ${method} ${path}`);
}
function baseOf(url, port) {
  let b = String(url || '').trim().replace(/\/+$/, '');
  // https; plain http only for a loopback test server (httpc refuses http to anything else anyway)
  if (!/^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/.*)?$/.test(b) && !/^http:\/\/(127\.0\.0\.1|localhost)(:\d{1,5})?(\/.*)?$/.test(b)) throw ERR('config', 'the address must be https://<host or IP>[:port]');
  const u = new URL(b);
  return `${u.protocol}//${u.hostname}:${u.port || port}`;
}

// a 404 on the product's own API path usually means the system was saved with the wrong type (the cluster answered, but it
// is another product) - say which one the address points to when it is recognisable (NetBackup's web console is /webui)
function wrongType(kind, url) {
  const u = String(url || '');
  if (kind !== 'netbackup' && /\/webui\b/i.test(u)) return ' - this address is the NetBackup web console (/webui): the system looks like a NetBackup primary server, so choose the type NetBackup (its API answers on port 1556)';
  if (kind === 'cohesity') return ' - the server answered but has no Cohesity API: check the type (NetBackup / Veeam / Cohesity) and that this is the Cohesity cluster address';
  if (kind === 'netbackup') return ' - the server answered but has no NetBackup API at /netbackup: check the type and that this is the primary server (port 1556)';
  if (kind === 'veeam') return ' - the server answered but has no Veeam REST API: check the type and that this is the Veeam Backup server (port 9419)';
  return '';
}
function client(kind, cred, o, port) {
  const t = cred.target || {};
  const base = baseOf(t.base_url, port);
  const req = o.request || httpc.request;
  async function call(method, path, headers, body) {
    guard(kind, method, path);
    const r = await req(base + path, { method, headers: Object.assign({ Accept: 'application/json' }, headers || {}), body: body == null ? null : body,
      caFile: t.ca_file || undefined, pin: t.tls_fingerprint || undefined, captureUntrusted: !!o.captureUntrusted, timeoutMs: o.timeoutMs || 60000 });
    if (r.status === 401) throw ERR('auth', `${kind}: the credentials were rejected (HTTP 401)`, { http: 401, tlsTrusted: true });
    if (r.status === 403) throw ERR('authz', `${kind}: the account may not read ${path.split('?')[0]} (HTTP 403)`, { http: 403, tlsTrusted: true });
    if (r.status === 406 || r.status === 415) throw ERR('protocol', `${kind}: the server refused the API version / media type (HTTP ${r.status}) - set the API version to the one your server shows`, { http: r.status, tlsTrusted: true });
    if (r.status < 200 || r.status >= 300) {
      // the product's own reason (NetBackup: errorMessage / errorDetails, Veeam: message, Cohesity: message) says what it refused
      const j = r.json && typeof r.json === 'object' ? r.json : {}, why = [j.errorMessage, j.message, j.error && typeof j.error === 'string' ? j.error : '', Array.isArray(j.errorDetails) ? j.errorDetails.join('; ') : ''].filter(Boolean).join(' - ');
      throw ERR('protocol', `${kind}: ${method} ${path.split('?')[0]} answered HTTP ${r.status}${why ? ': ' + String(why).replace(/[\u0000-\u001f]/g, ' ').slice(0, 240) : ''}${r.status === 404 ? wrongType(kind, t.base_url) : ''}`, { http: r.status, tlsTrusted: true });
    }
    return r.json;
  }
  return { call, base, t };
}

// ---------------------------------------------------------------- NetBackup -----------------------------------------
const NB_DONE_OK = (st) => st === 0;
function nbStatus(a) {
  const state = String(a.state || '').toUpperCase();
  if (state && state !== 'DONE') return 'running';
  const st = Number(a.status);
  return st === 0 ? 'success' : st === 1 ? 'warning' : 'failed';     // NetBackup status 1 = partially successful
}
async function netbackup(cred, o = {}) {
  const t0 = Date.now();
  try {
    if (!cred.secret || !cred.secret.api_key) throw ERR('config', 'NetBackup needs an API key');
    const c = client('netbackup', cred, o, 1556);
    const ver = String(c.t.api_version || '14.0').replace(/[^0-9.]/g, '') || '14.0';
    const H = { Authorization: cred.secret.api_key, Accept: `application/vnd.netbackup+json;version=${ver}` };
    const sinceMs = (o.now || Date.now()) - (o.days || 7) * DAY, since = new Date(sinceMs).toISOString();   // with milliseconds, as the NetBackup API documents
    async function pages(path, filter, max, sort) {
      const out = []; let offset = 0;
      for (let i = 0; i < 200 && out.length < max; i++) {
        const q = (filter ? `filter=${encodeURIComponent(filter)}&` : '') + (sort ? `sort=${sort}&` : '') + `page%5Blimit%5D=100&page%5Boffset%5D=${offset}`;
        const j = await c.call('GET', `/netbackup/${path}?${q}`, H) || {};
        const d = Array.isArray(j.data) ? j.data : [];
        out.push(...d);
        const pg = j.meta && j.meta.pagination;
        if (!d.length || (pg && (pg.next === undefined || pg.next === null || pg.next <= offset)) || (!pg && d.length < 100)) break;
        offset = pg && pg.next != null ? pg.next : offset + d.length;
        if (!filter && sort && d.length && Date.parse((d[d.length - 1].attributes || {})[sort.replace(/^-/, '')]) < sinceMs) break;   // newest first: stop past the window
      }
      return out;
    }
    // NetBackup versions differ in the filters they accept (HTTP 400 "invalid filter"): try the precise filter first, then a
    // time-only filter, then newest-first with no filter; the type and the window are applied here either way
    async function tryPages(path, variants, max) {
      let last;
      for (const v of variants) { try { return await pages(path, v[0], max, v[1]); } catch (e) { if (e.http !== 400) throw e; last = e; } }
      throw last;
    }
    const inWin = (v) => { const x = Date.parse(v); return !Number.isFinite(x) || x >= sinceMs; };
    const jobsRaw = (await tryPages('admin/jobs', [[`jobType eq 'BACKUP' and startTime ge ${since}`], [`startTime ge ${since}`], ['', '-startTime']], o.maxJobs || 20000))
      .filter((x) => { const a = x.attributes || {}; return (!a.jobType || String(a.jobType).toUpperCase() === 'BACKUP') && inWin(a.startTime); });
    let images = [];
    try { images = (await tryPages('catalog/images', [[`backupTime ge ${since}`], ['', '-backupTime']], o.maxImages || 20000)).filter((x) => inWin((x.attributes || {}).backupTime)); }
    catch (e) { if (e.code !== 'authz' && e.http !== 400) throw e; }   // the images are a supplement to the jobs
    const jobs = jobsRaw.map((x) => { const a = x.attributes || {}; return { id: String(a.jobId || x.id || ''), job: a.policyName || '', schedule: a.scheduleName || '', client: a.clientName || '', display_name: a.assetDisplayableName && a.assetDisplayableName !== a.clientName ? String(a.assetDisplayableName).slice(0, 200) : '', status: nbStatus(a), code: a.status != null ? Number(a.status) : null, start: iso(a.startTime), end: iso(a.endTime), size_bytes: a.kilobytesTransferred ? Number(a.kilobytesTransferred) * 1024 : null }; });
    const objs = new Map();
    const get = (name) => { const k = low(name); if (!objs.has(k)) objs.set(k, { name, kind: 'client', job: '', last_attempt: null, last_status: null, last_success: null, size_bytes: null, policy: '' }); return objs.get(k); };
    for (const j of jobs.filter((x) => x.client).sort((a, b) => String(a.start).localeCompare(String(b.start)))) {
      const ob = get(j.client); ob.job = j.job; ob.policy = j.job; if (j.display_name) ob.display_name = j.display_name;   // a VM backup's client is the VM uuid; NetBackup 9+ also sends the VM's name
      if (j.status !== 'running') { ob.last_attempt = j.end || j.start; ob.last_status = j.status; }
      else if (!ob.last_status) ob.last_status = 'running';
      if ((j.status === 'success' || j.status === 'warning') && (!ob.last_success || j.end > ob.last_success)) { ob.last_success = j.end || j.start; ob.size_bytes = j.size_bytes; }
    }
    for (const x of images) { const a = x.attributes || {}; if (!a.clientName) continue; const ob = get(a.clientName); const bt = iso(a.backupTime); if (bt && (!ob.last_success || bt > ob.last_success)) { ob.last_success = bt; if (!ob.policy) ob.policy = a.policyName || ''; if (a.kilobytes) ob.size_bytes = Number(a.kilobytes) * 1024; } if (!ob.last_status) ob.last_status = 'success'; }
    return { ok: true, platform: 'netbackup', api_version: ver, objects: [...objs.values()], jobs, ms: Date.now() - t0 };
  } catch (e) { return { ok: false, error_class: cls(e), error: e.message, presented: e.presented || null, ms: Date.now() - t0 }; }
}

// ---------------------------------------------------------------- Veeam ---------------------------------------------
function veeamStatus(r) { const s = low((r && (r.result || r)) || ''); return s === 'success' ? 'success' : s === 'warning' ? 'warning' : s === 'failed' ? 'failed' : s === 'none' || !s ? 'running' : s; }
async function veeam(cred, o = {}) {
  const t0 = Date.now();
  let c = null, token = null;
  try {
    if (!cred.secret || !cred.secret.username || !cred.secret.password) throw ERR('config', 'Veeam needs a user name and password');
    c = client('veeam', cred, o, 9419);
    const ver = String(c.t.api_version || '1.1-rev0').replace(/[^0-9A-Za-z.-]/g, '');
    const form = new URLSearchParams({ grant_type: 'password', username: cred.secret.username, password: cred.secret.password }).toString();
    const tok = await c.call('POST', '/api/oauth2/token', { 'x-api-version': ver, 'Content-Type': 'application/x-www-form-urlencoded' }, form);
    token = tok && tok.access_token; if (!token) throw ERR('auth', 'Veeam returned no access token');
    const H = { 'x-api-version': ver, Authorization: `Bearer ${token}` };
    const since = new Date((o.now || Date.now()) - (o.days || 7) * DAY).toISOString();
    async function pages(path, max) {
      const out = [];
      for (let skip = 0; skip < max; skip += 500) {
        const j = await c.call('GET', `${path}${path.includes('?') ? '&' : '?'}skip=${skip}&limit=500`, H) || {};
        const d = Array.isArray(j.data) ? j.data : []; out.push(...d);
        const total = j.pagination && Number(j.pagination.total);
        if (d.length < 500 || (total && out.length >= total)) break;
      }
      return out;
    }
    const sess = await pages(`/api/v1/sessions?typeFilter=BackupJob&createdAfterFilter=${encodeURIComponent(since)}&orderColumn=CreationTime&orderAsc=false`, o.maxJobs || 20000);
    const rps = await pages(`/api/v1/restorePoints?createdAfterFilter=${encodeURIComponent(since)}&orderColumn=CreationTime&orderAsc=false`, o.maxImages || 50000);
    const jobs = sess.map((s) => ({ id: s.id, job: s.name || '', status: s.state && low(s.state) !== 'stopped' ? 'running' : veeamStatus(s.result), start: iso(s.creationTime), end: iso(s.endTime), error: (s.result && s.result.message) || null }));
    const objs = new Map();
    for (const r of rps) {
      const k = low(r.name); if (!k) continue;
      const ct = iso(r.creationTime);
      const ob = objs.get(k) || { name: r.name, kind: low(r.platformName) === 'vmware' || low(r.platformName) === 'hyperv' ? 'vm' : 'object', job: '', last_attempt: null, last_status: 'success', last_success: null, size_bytes: null, policy: '' };
      if (ct && (!ob.last_success || ct > ob.last_success)) { ob.last_success = ct; ob.last_attempt = ct; }
      objs.set(k, ob);
    }
    // a failed run: the job's last session failed after the object's newest restore point
    const lastByJob = new Map(); for (const j of jobs) if (j.status !== 'running' && (!lastByJob.has(j.job) || j.start > lastByJob.get(j.job).start)) lastByJob.set(j.job, j);
    return { ok: true, platform: 'veeam', api_version: ver, objects: [...objs.values()], jobs, failed_jobs: [...lastByJob.values()].filter((j) => j.status === 'failed').map((j) => j.job), ms: Date.now() - t0 };
  } catch (e) { return { ok: false, error_class: cls(e), error: e.message, presented: e.presented || null, ms: Date.now() - t0 }; }
  finally { if (c && token) { try { await c.call('POST', '/api/oauth2/logout', { 'x-api-version': String(c.t.api_version || '1.1-rev0'), Authorization: `Bearer ${token}` }, ''); } catch { /* best effort */ } } }
}

// ---------------------------------------------------------------- Cohesity ------------------------------------------
function cohStatus(s) { const v = String(s || '').replace(/^k/, '').toLowerCase(); return v === 'success' ? 'success' : v === 'warning' ? 'warning' : /fail|cancel/.test(v) ? 'failed' : 'running'; }
async function cohesity(cred, o = {}) {
  const t0 = Date.now();
  try {
    const c = client('cohesity', cred, o, 443);
    let H;
    if (cred.secret && cred.secret.api_key) H = { apiKey: cred.secret.api_key };
    else if (cred.secret && cred.secret.username && cred.secret.password) {
      const j = await c.call('POST', '/irisservices/api/v1/public/accessTokens', { 'Content-Type': 'application/json' }, JSON.stringify({ username: cred.secret.username, password: cred.secret.password, domain: c.t.domain || 'LOCAL' }));
      if (!j || !j.accessToken) throw ERR('auth', 'Cohesity returned no access token');
      H = { Authorization: `${j.tokenType || 'Bearer'} ${j.accessToken}` };
    } else throw ERR('config', 'Cohesity needs an API key, or a user name and password');
    const sinceUs = ((o.now || Date.now()) - (o.days || 7) * DAY) * 1000;
    const runs = await c.call('GET', `/irisservices/api/v1/public/protectionRuns?startTimeUsecs=${sinceUs}&numRuns=${o.maxJobs || 5000}&excludeTasks=false&excludeNonRestoreableRuns=false`, H) || [];
    const jobs = [], objs = new Map();
    for (const r of Array.isArray(runs) ? runs : []) {
      const b = r.backupRun || {}, st = b.stats || {};
      const start = st.startTimeUsecs ? iso(Math.round(st.startTimeUsecs / 1000)) : null, end = st.endTimeUsecs ? iso(Math.round(st.endTimeUsecs / 1000)) : null;
      jobs.push({ id: String(r.jobId || '') + ':' + (b.jobRunId || ''), job: r.jobName || '', status: cohStatus(b.status), start, end, error: (b.error || '') || null });
      for (const sb of b.sourceBackupStatus || []) {
        const name = (sb.source && (sb.source.displayName || sb.source.name)) || ''; if (!name) continue;
        const k = low(name), s = cohStatus(sb.status), sst = sb.stats || {};
        const at = sst.endTimeUsecs ? iso(Math.round(sst.endTimeUsecs / 1000)) : end;
        const ob = objs.get(k) || { name, kind: 'object', job: r.jobName || '', last_attempt: null, last_status: null, last_success: null, size_bytes: null, policy: r.jobName || '' };
        if (s !== 'running' && (!ob.last_attempt || (at && at > ob.last_attempt))) { ob.last_attempt = at; ob.last_status = s; ob.job = r.jobName || ob.job; }
        if (!ob.last_status) ob.last_status = s;
        if ((s === 'success' || s === 'warning') && at && (!ob.last_success || at > ob.last_success)) { ob.last_success = at; if (sst.totalLogicalBackupSizeBytes) ob.size_bytes = Number(sst.totalLogicalBackupSizeBytes); }
        objs.set(k, ob);
      }
    }
    return { ok: true, platform: 'cohesity', objects: [...objs.values()], jobs, ms: Date.now() - t0 };
  } catch (e) { return { ok: false, error_class: cls(e), error: e.message, presented: e.presented || null, ms: Date.now() - t0 }; }
}

// connection test: the same calls, a short window; an untrusted certificate is captured for Trust & pin
async function test(kind, cred, o = {}) {
  const fn = { netbackup, veeam, cohesity }[kind];
  if (!fn) return { ok: false, error_class: 'config', error: 'unknown platform' };
  const r = await fn(cred, Object.assign({ captureUntrusted: true, days: 1, maxJobs: 200, maxImages: 200 }, o));
  return r.ok ? { ok: true, message: `Connected: ${r.jobs.length} backup runs and ${r.objects.length} protected objects in the last 24 hours.` } : r;
}

module.exports = { netbackup, veeam, cohesity, test, guard, baseOf, NB_DONE_OK };
