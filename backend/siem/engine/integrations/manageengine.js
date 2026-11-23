// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * ManageEngine ServiceDesk Plus (on-prem) incident integration — REST API v3 (docs/MANAGEENGINE.md).
 *
 *   createManageEngine({ state, alerts, cases, config, log, now, transport })
 *     → { settings(), setSettings(patch, by), setCredential(key, by), clearCredential(by), credentialState(),
 *         test(), createTicket({kind:'alert'|'case', id, by, force}), linkTicket({kind, id, request_id, by}),
 *         linkBulk(items, by), comment(ticketId, text, by), sync(), processQueue(), status(), tickets(filter),
 *         alertsWithoutTickets(filter), ticketFor(kind, id), buildPayload(kind, obj), scrub(text), start(), stop() }
 *
 * SDP v3 contract (ON-PREM build — "verify" against the customer's SDP version, see docs/MANAGEENGINE.md):
 *   header  authtoken: <technician API key>        (Cloud variant: Authorization: Zoho-oauthtoken <token> — future)
 *   POST  {base}/api/v3/requests                   body application/x-www-form-urlencoded  input_data={"request":{…}}
 *   GET   {base}/api/v3/requests/{id}              → {request:{id, status:{name}, technician:{name}, resolution:{content}}}
 *   POST  {base}/api/v3/requests/{id}/notes        input_data={"note":{"description":"…","show_to_requester":false}}   (v3 "request_note" on some builds — verify)
 *   PUT   {base}/api/v3/requests/{id}              input_data={"request":{"status":{"name":"Open"}}}                   (re-open on recurrence)
 *   GET   {base}/api/v3/requests?input_data={"list_info":{"row_count":1}}                                            (connection test)
 *   Replies carry response_status {status_code: 2000 = ok, 4000 = failure, messages[]} (an array for list calls).
 *
 * State (engine/soc/state.js collections): integrations (doc "manageengine" = settings + credential metadata),
 *   me_tickets ({id:"alert:ALR-…"|"case:CASE-…", kind, ref_id, request_id, url, subject, sdp_status, technician, resolution,
 *   created_at, created_by, updated_at, last_synced, last_sync_error, alert_count, notes_seen, linked, reopened, comments,
 *   siem_status_applied}), me_queue ({id, op:create|comment|reopen, kind, ref_id, payload, attempts, next_at, last_error, dead}).
 * The API key lives ONLY in secrets.json integrations.manageengine.api_key (mode 600, written atomically) and in memory;
 * it is never returned by settings()/status(), never written to state, never logged and scrubbed from every outbound
 * payload. Every system-side change (ticket created, alert closed from SDP…) is audited with by:"manageengine".
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const SEV_NAME = (s) => (s >= 4 ? 'critical' : s === 3 ? 'high' : s === 2 ? 'medium' : 'low');
const isClosedAlert = (s) => typeof s === 'string' && s.startsWith('closed-');

const DEFAULTS = {
  enabled: false,
  variant: 'onprem',                 // onprem (authtoken) | cloud (OAuth, future — verify)
  base_url: '',                      // https://sdp.the organisation:8080
  api_version: 'v3',
  ca_file: '',                       // PEM of the customer's internal CA, e.g. /etc/ssl/corp-hq/corp-ca.pem
  ca_pin: '',                        // optional sha256 fingerprint of the SDP server certificate (hex, colons optional)
  verify_tls: true,
  timeout_ms: 15000,
  default_requester: '',             // requester name or e-mail in SDP (empty = the API key's technician)
  site: '',
  group: '',
  technician: '',
  group_by_severity: {},             // {critical: 'SOC L2', high: 'SOC L1', …} overrides `group`
  technician_by_severity: {},
  priority_map: { critical: 'High', high: 'High', medium: 'Medium', low: 'Low' },
  category: 'Security Incident',
  subcategory: '',
  item: '',
  template_id: '',
  dedupe_window_h: 24,               // one SDP request per alert id; a closed ticket older than this → a new request
  on_recurrence: 'comment',          // comment | reopen  (what to do when a ticketed alert recurs)
  auto_create: { enabled: true, severities: [3, 4], rule_ids: [] },
  sync_interval_s: 120,
  portal_url: ('https://' + ZYB_ORG.portal_host),
  status_map: { open: 'in-progress', 'in progress': 'in-progress', 'on hold': 'in-progress', assigned: 'in-progress', resolved: 'closed', closed: 'closed', cancelled: 'closed', canceled: 'closed' },
  close_reason_default: 'true-positive',
  retry: { base_s: 30, max_s: 1800, max_attempts: 60 },
  readback_batch: 50,
};
const ALLOWED_KEYS = Object.keys(DEFAULTS);
const SECRET_KEY_RE = /(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|authtoken|authorization|credential|private[_-]?key|cookie)/i;
const SECRET_TEXT_RE = /\b(password|passwd|pass|pw|pwd|passphrase|secret|token|authtoken|api[_-]?key|authorization|client[_-]?secret)\b(\s*[:=]\s*|\s+)("[^"]*"|'[^']*'|\S+)/gi;
const BEARER_RE = /\b(Bearer|Zoho-oauthtoken|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/g;

function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }
function merge(base, over) {
  if (!isObj(over)) return base;
  const out = Object.assign({}, base);
  for (const [k, v] of Object.entries(over)) out[k] = isObj(v) && isObj(base[k]) ? merge(base[k], v) : v;
  return out;
}
function writeJson600(file, obj) {
  if (SF.isSecretsPath(file)) return SF.write(file, obj);   // sealed at rest
  let st = null; try { st = fs.statSync(file); } catch { /* new file */ }
  const tmp = file + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
  try { if (st && process.getuid && process.getuid() === 0) fs.chownSync(tmp, st.uid, st.gid); } catch { /* not root */ }
  fs.renameSync(tmp, file);
}
function fingerprint(key) { return crypto.createHash('sha256').update(String(key)).digest('hex').slice(0, 8); }
function normPin(p) { return String(p || '').replace(/[^0-9a-fA-F]/g, '').toUpperCase(); }

class SdpError extends Error {
  constructor(message, { status, retriable, code, body } = {}) {
    super(message); this.name = 'SdpError'; this.status = status || 0; this.retriable = !!retriable; this.code = code || 'SDP'; this.body = body;
  }
}

/** Default transport: node http/https. opts = {method, url, headers, body, timeout_ms, ca, pin, verify_tls} → {status, headers, text}. */
function defaultTransport(opts) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(opts.url); } catch { return reject(new SdpError('invalid base_url', { code: 'CONFIG' })); }
    const secure = u.protocol === 'https:';
    const mod = secure ? https : http;
    const ro = { method: opts.method, hostname: u.hostname, port: u.port || (secure ? 443 : 80), path: u.pathname + u.search, headers: opts.headers, timeout: opts.timeout_ms };
    if (secure) {
      if (opts.ca) ro.ca = opts.ca;
      ro.rejectUnauthorized = opts.verify_tls !== false;
      ro.servername = u.hostname;
      if (opts.pin) {
        const want = normPin(opts.pin);
        ro.checkServerIdentity = (host, cert) => {
          const got = normPin(cert.fingerprint256 || '');
          if (got !== want) return new Error(`certificate pin mismatch for ${host}`);
          return undefined;
        };
      }
    }
    const req = mod.request(ro, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new SdpError('timeout', { retriable: true, code: 'TIMEOUT' })));
    req.on('error', (e) => reject(e instanceof SdpError ? e : new SdpError(e.message, { retriable: true, code: e.code || 'NET' })));
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function createManageEngine(opts = {}) {
  const { state, alerts, cases } = opts;
  if (!state) throw new Error('createManageEngine needs state');
  const cfg = opts.config || {};
  const log = opts.log || { info() {}, warn() {}, error() {}, debug() {} };
  const now = opts.now || Date.now;
  const transport = opts.transport || defaultTransport;
  const ruleLookup = typeof opts.ruleLookup === 'function' ? opts.ruleLookup : () => null;
  const col = state.collection('integrations');
  const tcol = state.collection('me_tickets');
  const qcol = state.collection('me_queue');
  const counters = state.collection('counters');
  const st = { created: 0, linked: 0, comments: 0, reopened: 0, readbacks: 0, closed_from_sdp: 0, in_progress_from_sdp: 0, errors: 0, queued: 0, dead: 0, last_sync: 0, last_sync_ms: 0, last_sync_error: '', last_test: null, last_error: '' };
  let timer = null;
  let syncing = null;

  // ---------------- settings & credential
  function doc() { return col.get('manageengine') || { id: 'manageengine', settings: {}, cred: {} }; }
  function settings() { return merge(DEFAULTS, doc().settings || {}); }
  function validate(s) {
    const errs = [];
    if (s.base_url) {
      let u = null; try { u = new URL(s.base_url); } catch { /* below */ }
      if (!u || (u.protocol !== 'https:' && u.protocol !== 'http:')) errs.push('base_url must be an http(s) URL');
      else if (u.protocol === 'http:' && !/^(127\.0\.0\.1|localhost|\[::1\])$/.test(u.hostname)) errs.push('base_url must use https (http is only allowed for 127.0.0.1 test servers)');
    }
    if (!['onprem', 'cloud'].includes(s.variant)) errs.push('variant must be onprem or cloud');
    if (s.api_version !== 'v3') errs.push('api_version: only v3 is supported');
    if (!['comment', 'reopen'].includes(s.on_recurrence)) errs.push('on_recurrence must be comment or reopen');
    if (!isObj(s.priority_map)) errs.push('priority_map must be an object');
    else for (const k of ['critical', 'high', 'medium', 'low']) if (typeof s.priority_map[k] !== 'string' || !s.priority_map[k]) errs.push(`priority_map.${k} required`);
    if (!isObj(s.status_map)) errs.push('status_map must be an object');
    else for (const [k, v] of Object.entries(s.status_map)) if (!['in-progress', 'closed', 'ignore'].includes(v)) errs.push(`status_map["${k}"] must be in-progress, closed or ignore`);
    if (!['true-positive', 'false-positive', 'benign'].includes(s.close_reason_default)) errs.push('close_reason_default must be true-positive, false-positive or benign');
    if (!(Number(s.dedupe_window_h) >= 0)) errs.push('dedupe_window_h must be >= 0');
    if (!(Number(s.sync_interval_s) >= 30)) errs.push('sync_interval_s must be >= 30');
    if (!(Number(s.timeout_ms) >= 1000)) errs.push('timeout_ms must be >= 1000');
    if (!isObj(s.auto_create) || !Array.isArray(s.auto_create.severities) || !Array.isArray(s.auto_create.rule_ids)) errs.push('auto_create needs {enabled, severities[], rule_ids[]}');
    else if (s.auto_create.severities.some((x) => !(Number.isInteger(x) && x >= 0 && x <= 4))) errs.push('auto_create.severities must be integers 0-4');
    if (s.ca_file && !/^\/[^\0]+$/.test(s.ca_file)) errs.push('ca_file must be an absolute path');
    if (s.ca_pin && normPin(s.ca_pin).length !== 64) errs.push('ca_pin must be a sha256 fingerprint (64 hex digits)');
    return errs;
  }
  function setSettings(patch, by) {
    if (!isObj(patch)) throw Object.assign(new Error('settings body must be an object'), { code: 400 });
    const unknown = Object.keys(patch).filter((k) => !ALLOWED_KEYS.includes(k));
    if (unknown.length) throw Object.assign(new Error(`unknown settings: ${unknown.join(', ')}`), { code: 400, errors: unknown.map((k) => `unknown setting ${k}`) });
    if ('api_key' in patch || 'authtoken' in patch) throw Object.assign(new Error('the API key is set through POST …/credential'), { code: 400 });
    const cur = settings();
    const next = merge(cur, patch); // nested maps (priority_map, status_map, auto_create…) merge key by key
    if (isObj(patch.status_map)) next.status_map = Object.fromEntries(Object.entries(next.status_map).map(([k, v]) => [String(k).toLowerCase(), v]));
    const errs = validate(next);
    if (errs.length) throw Object.assign(new Error(errs[0]), { code: 400, errors: errs });
    if (next.enabled && !cur.enabled) next.auto_since = now(); // auto-create never back-fills alerts older than the enable time
    const d = doc();
    const stored = {}; for (const k of Object.keys(next)) if (JSON.stringify(next[k]) !== JSON.stringify(DEFAULTS[k])) stored[k] = next[k];
    col.put({ id: 'manageengine', settings: stored, cred: d.cred || {}, updated: now(), updated_by: by || '' });
    if (timer) { stop(); start(); }
    return settings();
  }
  function credentialState() {
    const c = doc().cred || {};
    const key = currentKey();
    return { api_key_set: !!key, key_fingerprint: key ? fingerprint(key) : '', key_set_at: c.set_at || 0, key_set_by: c.set_by || '', key_source: key ? (c.set_at ? 'secrets.json (set from the portal)' : 'secrets.json') : '' };
  }
  function currentKey() {
    const s = cfg.secrets && cfg.secrets.integrations && cfg.secrets.integrations.manageengine;
    return s && typeof s.api_key === 'string' && s.api_key ? s.api_key : '';
  }
  function setCredential(key, by) {
    if (typeof key !== 'string' || key.trim().length < 8 || /[\r\n\0]/.test(key)) throw Object.assign(new Error('api_key must be a string of at least 8 characters without line breaks'), { code: 400 });
    key = key.trim();
    const file = cfg._paths && cfg._paths.secrets;
    if (file) {
      let sec = {}; try { sec = SF.read(file) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
      sec.integrations = Object.assign({}, sec.integrations || {}, { manageengine: Object.assign({}, (sec.integrations || {}).manageengine || {}, { api_key: key }) });
      writeJson600(file, sec);
    }
    if (!cfg.secrets) Object.defineProperty(cfg, 'secrets', { value: {}, enumerable: false, writable: true });
    cfg.secrets.integrations = Object.assign({}, cfg.secrets.integrations || {}, { manageengine: Object.assign({}, (cfg.secrets.integrations || {}).manageengine || {}, { api_key: key }) });
    const d = doc();
    col.put({ id: 'manageengine', settings: d.settings || {}, cred: { set_at: now(), set_by: by || '', fp: fingerprint(key) }, updated: now(), updated_by: by || '' });
    log.info('manageengine: API key stored (write-only)', { by: by || '', file: file || '(memory only)' });
    return credentialState();
  }
  function clearCredential(by) {
    const file = cfg._paths && cfg._paths.secrets;
    if (file) {
      let sec = {}; try { sec = SF.read(file) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
      if (sec.integrations && sec.integrations.manageengine) { delete sec.integrations.manageengine.api_key; writeJson600(file, sec); }
    }
    if (cfg.secrets && cfg.secrets.integrations && cfg.secrets.integrations.manageengine) delete cfg.secrets.integrations.manageengine.api_key;
    const d = doc();
    col.put({ id: 'manageengine', settings: d.settings || {}, cred: {}, updated: now(), updated_by: by || '' });
    return credentialState();
  }

  // ---------------- scrubbing (secrets never reach SDP, logs or state)
  function scrub(text) {
    let s = String(text === undefined || text === null ? '' : text);
    const key = currentKey();
    if (key) s = s.split(key).join('[redacted]');
    s = s.replace(BEARER_RE, '$1 [redacted]');
    s = s.replace(SECRET_TEXT_RE, (m, k, sep) => `${k}${sep.trim() ? sep : ' '}[redacted]`);
    return s;
  }
  function scrubMap(obj) {
    const out = {};
    for (const [k, v] of Object.entries(obj || {})) out[k] = SECRET_KEY_RE.test(k) ? '[redacted]' : scrub(typeof v === 'object' ? JSON.stringify(v) : v);
    return out;
  }

  // ---------------- payloads
  function portalLink(kind, id) {
    const s = settings();
    const base = String(s.portal_url || '').replace(/\/+$/, '');
    return kind === 'case' ? `${base}/#soc-cases?case=${encodeURIComponent(id)}` : `${base}/#soc-alerts?alert=${encodeURIComponent(id)}`; // verify: portal deep-link format
  }
  function sevFields(s, sevName) {
    const group = (s.group_by_severity || {})[sevName] || s.group;
    const tech = (s.technician_by_severity || {})[sevName] || s.technician;
    return { priority: s.priority_map[sevName] || s.priority_map.medium, group, technician: tech };
  }
  function nameObj(v) { return v ? { name: String(v) } : undefined; }
  function compact(o) { for (const k of Object.keys(o)) if (o[k] === undefined || o[k] === '' || (isObj(o[k]) && !Object.keys(o[k]).length)) delete o[k]; return o; }

  function alertDescription(a) {
    const g = scrubMap(a.group || {});
    const f = scrubMap(a.fields || {});
    const pick = (keys) => { for (const k of keys) { if (g[k]) return g[k]; if (f[k]) return f[k]; } return ''; };
    const host = pick(['host', 'hostname', 'computer']) || a.host || '';
    const user = pick(['user', 'target_user', 'account']);
    const ip = pick(['src_ip', 'ip', 'host_ip', 'dst_ip']);
    const lines = [
      `SIEM alert ${a.id} — ${scrub(a.rule_name || a.rule_id)}`,
      `Severity: ${SEV_NAME(a.severity)} (${a.severity})    Status in SIEM: ${a.status}    Events: ${a.count || 1}`,
      `First seen: ${new Date(a.ts_first || 0).toISOString()}    Last seen: ${new Date(a.ts_last || 0).toISOString()}`,
      `Rule: ${a.rule_id}${a.rule_type ? ` (${a.rule_type})` : ''}    Source: ${a.source || 'engine'}${a.src_type ? ` / ${a.src_type}` : ''}${a.src_id ? ` / ${a.src_id}` : ''}`,
      `Affected host: ${host || '-'}    User: ${user || '-'}    IP: ${ip || '-'}`,
      `MITRE ATT&CK: ${(a.mitre || []).join(', ') || '-'}${a.tactic ? ` (${a.tactic})` : ''}`,
      `SAMA CSF: ${(a.sama || (ruleLookup(a.rule_id) || {}).sama || []).join(', ') || '-'}`,
      '',
      'Summary:',
      scrub(a.summary || ''),
      '',
      'Evidence summary:',
      ...Object.keys(g).map((k) => `  ${k} = ${g[k]}`),
      ...Object.keys(f).filter((k) => !(k in g)).slice(0, 25).map((k) => `  ${k} = ${f[k]}`),
      `  sample events: ${(a.sample_event_ids || []).length} (open the alert in the SOC portal to search them)`,
      ...((a.notes || []).slice(-3).map((n) => `  note (${n.by || 'system'} ${new Date(n.at || 0).toISOString()}): ${scrub(n.text)}`)),
      '',
      `SOC portal: ${portalLink('alert', a.id)}`,
    ];
    return lines.join('\n').slice(0, 30000);
  }
  function caseDescription(c) {
    const al = (c.alerts || []).map((id) => (alerts ? alerts.get(id) : null)).filter(Boolean);
    const lines = [
      `SIEM case ${c.id} — ${scrub(c.title)}`,
      `Severity: ${SEV_NAME(c.severity)} (${c.severity})    Status in SIEM: ${c.status}    Owner: ${c.owner || '-'}    Playbook: ${c.playbook_id || '-'}`,
      `Created: ${new Date(c.created || 0).toISOString()}`,
      '',
      'Description:',
      scrub(c.description || '-'),
      '',
      `Linked alerts (${(c.alerts || []).length}):`,
      ...al.slice(0, 50).map((a) => `  ${a.id} [${SEV_NAME(a.severity)}] ${scrub(a.rule_name)} — ${scrub(a.summary)} (${a.count || 1} events, MITRE ${(a.mitre || []).join(', ') || '-'})`),
      '',
      'Evidence:',
      ...((c.evidence || []).slice(0, 20).map((e) => `  ${scrub(e.name)}: ${scrub(e.ref)}`)),
      '',
      `SOC portal: ${portalLink('case', c.id)}`,
    ];
    return lines.join('\n').slice(0, 30000);
  }
  function buildPayload(kind, obj) {
    const s = settings();
    const X = KINDS[kind];
    const sevName = SEV_NAME(X && X.severity ? Number(X.severity(obj)) || 0 : Number(obj.severity) || 0);
    const sf = sevFields(s, sevName);
    const subject = X ? scrub(X.subject(obj) || '') : kind === 'case'
      ? `[SIEM ${obj.id}] ${scrub(obj.title || '')}`
      : `[SIEM ${obj.id}] ${scrub(obj.rule_name || obj.rule_id || '')}${obj.summary && obj.summary !== obj.rule_name ? ` — ${scrub(obj.summary)}` : ''}`;
    const request = compact({
      subject: subject.slice(0, 250),
      description: X ? String(X.description(obj) || '').slice(0, 30000) : kind === 'case' ? caseDescription(obj) : alertDescription(obj),
      requester: s.default_requester ? (s.default_requester.includes('@') ? { email_id: s.default_requester } : { name: s.default_requester }) : undefined,
      priority: nameObj(sf.priority),
      category: nameObj(s.category), subcategory: nameObj(s.subcategory), item: nameObj(s.item),
      group: nameObj(sf.group), technician: nameObj(sf.technician), site: nameObj(s.site),
      template: s.template_id ? { id: String(s.template_id) } : undefined,
      status: { name: 'Open' },
      udf_fields: compact({ udf_siem_ref: obj.id, udf_siem_kind: kind, udf_siem_severity: sevName }), // verify: UDF API names in the customer's SDP
    });
    return { request };
  }

  // ---------------- SDP HTTP
  function headers(s, extra) {
    const key = currentKey();
    const h = Object.assign({ Accept: 'application/vnd.manageengine.sdp.v3+json', 'User-Agent': 'sentra-siem-manageengine/1.0' }, extra || {});
    if (s.variant === 'cloud') h.Authorization = `Zoho-oauthtoken ${key}`; // future: OAuth refresh flow (verify)
    else h.authtoken = key;
    return h;
  }
  function parseReply(res) {
    let j = null;
    try { j = JSON.parse(res.text || '{}'); } catch { j = null; }
    if (res.status === 401 || res.status === 403) throw new SdpError(`SDP refused the API key (HTTP ${res.status})`, { status: res.status, code: 'AUTH' });
    if (res.status >= 500 || res.status === 429 || res.status === 408) throw new SdpError(`SDP unavailable (HTTP ${res.status})`, { status: res.status, retriable: true, code: 'UPSTREAM' });
    if (!j) throw new SdpError(`SDP returned a non-JSON reply (HTTP ${res.status})`, { status: res.status, retriable: res.status >= 500, code: 'BAD_REPLY' });
    const rs = Array.isArray(j.response_status) ? j.response_status[0] : j.response_status;
    const code = rs && Number(rs.status_code);
    if (res.status >= 400 || (code && code !== 2000)) {
      const msgs = rs && Array.isArray(rs.messages) ? rs.messages.map((m) => m.message || m.field || JSON.stringify(m)).join('; ') : '';
      throw new SdpError(`SDP error ${code || res.status}${msgs ? `: ${msgs}` : ''}`, { status: res.status, code: 'SDP', body: j });
    }
    return j;
  }
  async function sdp(method, path, { input, query } = {}) {
    const s = settings();
    if (!s.base_url) throw new SdpError('ManageEngine base_url is not configured', { code: 'CONFIG' });
    if (!currentKey()) throw new SdpError('ManageEngine API key is not set (POST …/credential)', { code: 'CONFIG' });
    const base = s.base_url.replace(/\/+$/, '');
    const q = new URLSearchParams(query || {});
    let body = null;
    const hdr = {};
    if (method === 'GET' || method === 'DELETE') { if (input) q.set('input_data', JSON.stringify(input)); }
    else { body = new URLSearchParams({ input_data: JSON.stringify(input || {}) }).toString(); hdr['Content-Type'] = 'application/x-www-form-urlencoded'; hdr['Content-Length'] = String(Buffer.byteLength(body)); }
    const qs = q.toString();
    const url = `${base}/api/${s.api_version}${path}${qs ? `?${qs}` : ''}`;
    let ca = null;
    if (s.ca_file) { try { ca = fs.readFileSync(s.ca_file); } catch (e) { throw new SdpError(`cannot read ca_file ${s.ca_file}: ${e.code}`, { code: 'CONFIG' }); } }
    const t0 = now();
    let res;
    try { res = await transport({ method, url, headers: headers(s, hdr), body, timeout_ms: s.timeout_ms, ca, pin: s.ca_pin, verify_tls: s.verify_tls }); }
    catch (e) { throw e instanceof SdpError ? e : new SdpError(e.message, { retriable: true, code: e.code || 'NET' }); }
    const j = parseReply(res);
    log.debug('manageengine: sdp call', { method, path, status: res.status, ms: now() - t0 });
    return j;
  }
  function requestUrl(id) {
    const s = settings();
    return `${String(s.base_url).replace(/\/+$/, '')}/WorkOrder.do?woMode=viewWO&woID=${encodeURIComponent(id)}`; // on-prem UI link (verify: /app/itdesk/ui/requests/{id}/details on newer builds)
  }

  async function test() {
    const t0 = now();
    const out = { ok: false, at: t0, ms: 0, error: '', base_url: settings().base_url, variant: settings().variant, api_key_set: !!currentKey() };
    try {
      const j = await sdp('GET', '/requests', { input: { list_info: { row_count: 1 } } });
      out.ok = true;
      out.requests_visible = Array.isArray(j.requests) ? j.requests.length : 0;
      out.has_more = !!(j.list_info && j.list_info.has_more_rows);
    } catch (e) { out.error = scrub(e.message); out.code = e.code; }
    out.ms = now() - t0;
    st.last_test = out;
    return out;
  }

  // ---------------- tickets
  const tid = (kind, id) => `${kind}:${id}`;
  function ticketFor(kind, id) { return tcol.get(tid(kind, id)); }
  function nextQ() { const c = counters.get('me_queue') || { id: 'me_queue', n: 0 }; c.n++; counters.put(c); return `MEQ-${String(c.n).padStart(6, '0')}`; }
  function audit(action, target, detail) { try { if (typeof state.audit === 'function') state.audit({ by: 'manageengine', role: 'system', ip: '', action, target, detail: detail || {} }); } catch (e) { log.warn('manageengine: audit failed', { err: e.message }); } }
  // other modules can raise tickets for their own records (e.g. the AI engineers' work items) with the same settings,
  // de-duplication and retry queue: registerKind(kind, { get(id), subject(obj), description(obj), severity(obj) 1-4, note(id, text) })
  const KINDS = {};
  function registerKind(kind, def) {
    if (!/^[a-z][a-z0-9-]{1,20}$/.test(String(kind)) || kind === 'alert' || kind === 'case') throw new Error('invalid ticket kind');
    if (!def || typeof def.get !== 'function' || typeof def.subject !== 'function' || typeof def.description !== 'function') throw new Error('ticket kind needs get, subject, description');
    KINDS[kind] = def;
  }
  function must(kind, id) {
    if (KINDS[kind]) { const o = KINDS[kind].get(id); if (!o) throw Object.assign(new Error(`${kind} ${id} not found`), { code: 404 }); return o; }
    if (kind !== 'alert' && kind !== 'case') throw Object.assign(new Error('kind must be alert or case'), { code: 400 });
    const obj = kind === 'alert' ? (alerts && alerts.get(id)) : (cases && cases.get(id));
    if (!obj) throw Object.assign(new Error(`${kind} ${id} not found`), { code: 404 });
    return obj;
  }
  function enqueue(op, kind, refId, payload, err) {
    const s = settings();
    const q = { id: nextQ(), op, kind, ref_id: refId, payload, attempts: 1, next_at: now() + s.retry.base_s * 1000, last_error: scrub(err && err.message), created: now(), dead: false };
    qcol.put(q);
    st.queued++;
    log.warn('manageengine: SDP unreachable — queued', { op, kind, ref: refId, queue_id: q.id, err: q.last_error });
    return q;
  }
  function recordTicket(kind, obj, reqObj, by, extra) {
    const t = Object.assign({
      id: tid(kind, obj.id), kind, ref_id: obj.id, request_id: String(reqObj.id), url: requestUrl(reqObj.id),
      subject: (reqObj.subject || '').slice(0, 250), sdp_status: (reqObj.status && reqObj.status.name) || 'Open', technician: (reqObj.technician && reqObj.technician.name) || '',
      resolution: '', created_at: now(), created_by: by || 'manageengine', updated_at: now(), last_synced: 0, last_sync_error: '',
      alert_count: kind === 'alert' ? (obj.count || 1) : 0, notes_seen: kind === 'alert' ? (obj.notes || []).length : (obj.timeline || []).length,
      linked: false, reopened: 0, comments: 0, siem_status_applied: '',
    }, extra || {});
    tcol.put(t);
    return t;
  }
  function noteBack(kind, id, text) {
    try {
      if (kind === 'alert' && alerts) alerts.note(id, text, 'manageengine');
      else if (kind === 'case' && cases) cases.note(id, text, 'manageengine');
      else if (KINDS[kind] && typeof KINDS[kind].note === 'function') KINDS[kind].note(id, text);
    } catch (e) { log.warn('manageengine: could not note back', { kind, id, err: e.message }); }
  }
  async function doCreate(kind, obj, by) {
    const payload = buildPayload(kind, obj);
    const j = await sdp('POST', '/requests', { input: payload });
    const r = j.request || {};
    if (!r.id) throw new SdpError('SDP reply had no request.id', { code: 'BAD_REPLY', body: j });
    const t = recordTicket(kind, obj, r, by);
    st.created++;
    noteBack(kind, obj.id, `ServiceDesk Plus request #${t.request_id} created (${t.url})`);
    if (kind === 'case' && cases) { try { cases.addEvidence(obj.id, { name: `SDP request #${t.request_id}`, ref: t.url, kind: 'ticket' }, 'manageengine'); } catch { /* ignore */ } }
    audit('manageengine.ticket.create', t.id, { request_id: t.request_id, by: by || 'auto', priority: payload.request.priority && payload.request.priority.name });
    log.info('manageengine: request created', { kind, ref: obj.id, request_id: t.request_id, by: by || 'auto' });
    return t;
  }
  /** createTicket({kind, id, by, force}) → {ticket, created, existing?, queued?, queue_id?} */
  async function createTicket({ kind, id, by, force } = {}) {
    const obj = must(kind, id);
    const s = settings();
    const ex = ticketFor(kind, id);
    if (ex && !force) {
      const closed = /^(closed|resolved|cancell?ed)$/i.test(ex.sdp_status || '');
      const fresh = now() - (ex.created_at || 0) <= Number(s.dedupe_window_h) * 3600000;
      if (!closed || fresh || s.dedupe_window_h === 0) return { ticket: ex, created: false, existing: true };
    }
    const pending = qcol.all((q) => !q.dead && q.op === 'create' && q.kind === kind && q.ref_id === id)[0];
    if (pending && !force) return { ticket: null, created: false, queued: true, queue_id: pending.id };
    try {
      const t = await doCreate(kind, obj, by);
      return { ticket: t, created: true };
    } catch (e) {
      if (e.retriable) { const q = enqueue('create', kind, id, { by: by || '' }, e); return { ticket: null, created: false, queued: true, queue_id: q.id, error: scrub(e.message) }; }
      st.errors++; st.last_error = scrub(e.message);
      throw Object.assign(new Error(scrub(e.message)), { code: e.code === 'CONFIG' ? 409 : 502, errors: [scrub(e.message)] });
    }
  }
  function linkTicket({ kind, id, request_id, by } = {}) {
    const obj = must(kind, id);
    const rid = String(request_id === undefined || request_id === null ? '' : request_id).trim();
    if (!/^[0-9]{1,20}$/.test(rid)) throw Object.assign(new Error('request_id must be numeric'), { code: 400 });
    const t = recordTicket(kind, obj, { id: rid, subject: kind === 'case' ? obj.title : obj.rule_name, status: { name: 'Open' } }, by, { linked: true });
    st.linked++;
    noteBack(kind, id, `Linked to ServiceDesk Plus request #${rid} by ${by || 'operator'} (${t.url})`);
    if (kind === 'case' && cases) { try { cases.addEvidence(id, { name: `SDP request #${rid}`, ref: t.url, kind: 'ticket' }, by || 'manageengine'); } catch { /* ignore */ } }
    return t;
  }
  function linkBulk(items, by) {
    if (!Array.isArray(items) || !items.length) throw Object.assign(new Error('items[] required: [{kind, id, request_id}]'), { code: 400 });
    if (items.length > 500) throw Object.assign(new Error('max 500 items per call'), { code: 400 });
    const results = items.map((it) => {
      try { const t = linkTicket({ kind: it.kind || 'alert', id: it.id, request_id: it.request_id, by }); return { id: it.id, ok: true, request_id: t.request_id, url: t.url }; }
      catch (e) { return { id: it.id, ok: false, error: e.message }; }
    });
    return { ok: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length, results };
  }
  async function sdpNote(requestId, text) {
    return sdp('POST', `/requests/${encodeURIComponent(requestId)}/notes`, { input: { note: { description: scrub(text).slice(0, 20000), show_to_requester: false, mark_first_response: false, add_to_linked_requests: false } } });
  }
  /** comment(ticketId, text, by) → {ok, queued?} — adds an SDP note (queued when SDP is unreachable). */
  async function comment(ticketId, text, by) {
    const t = tcol.get(ticketId);
    if (!t) throw Object.assign(new Error('ticket not found'), { code: 404 });
    const tx = String(text || '').trim();
    if (!tx) throw Object.assign(new Error('text required'), { code: 400 });
    try {
      await sdpNote(t.request_id, tx);
      tcol.patch(t.id, (x) => { x.comments = (x.comments || 0) + 1; x.updated_at = now(); });
      st.comments++;
      audit('manageengine.ticket.comment', t.id, { request_id: t.request_id, by: by || 'auto' });
      return { ok: true };
    } catch (e) {
      if (e.retriable) { const q = enqueue('comment', t.kind, t.ref_id, { ticket_id: t.id, text: scrub(tx) }, e); return { ok: false, queued: true, queue_id: q.id }; }
      st.errors++; st.last_error = scrub(e.message);
      throw Object.assign(new Error(scrub(e.message)), { code: 502 });
    }
  }
  async function reopenRequest(t, why) {
    await sdp('PUT', `/requests/${encodeURIComponent(t.request_id)}`, { input: { request: { status: { name: 'Open' } } } });
    await sdpNote(t.request_id, why);
    tcol.patch(t.id, (x) => { x.sdp_status = 'Open'; x.reopened = (x.reopened || 0) + 1; x.updated_at = now(); });
    st.reopened++;
    audit('manageengine.ticket.reopen', t.id, { request_id: t.request_id });
  }

  // ---------------- queue
  async function processQueue(limit = 20) {
    const s = settings();
    const t = now();
    const due = qcol.all((q) => !q.dead && q.next_at <= t).sort((a, b) => a.next_at - b.next_at).slice(0, limit);
    let ok = 0; let failed = 0;
    for (const q of due) {
      try {
        if (q.op === 'create') {
          const obj = q.kind === 'alert' ? alerts && alerts.get(q.ref_id) : cases && cases.get(q.ref_id);
          if (!obj) { qcol.remove(q.id); continue; }
          if (!ticketFor(q.kind, q.ref_id)) await doCreate(q.kind, obj, q.payload && q.payload.by);
        } else if (q.op === 'comment') {
          const tk = tcol.get(q.payload.ticket_id);
          if (tk) { await sdpNote(tk.request_id, q.payload.text); tcol.patch(tk.id, (x) => { x.comments = (x.comments || 0) + 1; }); st.comments++; }
        } else if (q.op === 'reopen') {
          const tk = tcol.get(q.payload.ticket_id);
          if (tk) await reopenRequest(tk, q.payload.text);
        }
        qcol.remove(q.id);
        ok++;
      } catch (e) {
        failed++;
        const attempts = (q.attempts || 1) + 1;
        const delay = Math.min(s.retry.max_s, s.retry.base_s * Math.pow(2, Math.min(attempts, 20))) * 1000;
        const dead = !e.retriable || attempts >= s.retry.max_attempts;
        qcol.patch(q.id, (x) => { x.attempts = attempts; x.next_at = now() + delay; x.last_error = scrub(e.message); x.dead = dead; });
        if (dead) { st.dead++; st.errors++; audit('manageengine.queue.dead', q.id, { op: q.op, ref: q.ref_id, error: scrub(e.message) }); log.error('manageengine: queue item gave up', { queue_id: q.id, op: q.op, attempts, err: scrub(e.message) }); }
        if (!e.retriable) break; // auth/config problem: stop hammering
      }
    }
    return { processed: due.length, ok, failed };
  }
  function retryDead() { let n = 0; for (const q of qcol.all((x) => x.dead)) { qcol.patch(q.id, (x) => { x.dead = false; x.attempts = 0; x.next_at = now(); }); n++; } return n; }
  function purgeQueue() { let n = 0; for (const q of qcol.all()) { qcol.remove(q.id); n++; } return n; }

  // ---------------- sync: auto-create, recurrence, read back
  function autoWanted(a, s) {
    const ac = s.auto_create || {};
    if (!ac.enabled) return false;
    if (isClosedAlert(a.status)) return false;
    if ((a.created || 0) < (s.auto_since || 0)) return false;
    if (a.source === 'manual') return false;
    return (ac.severities || []).includes(Number(a.severity)) || (ac.rule_ids || []).includes(a.rule_id);
  }
  async function autoCreate(s) {
    if (!alerts || !s.enabled) return 0;
    let n = 0;
    const cands = alerts.all((a) => autoWanted(a, s) && !ticketFor('alert', a.id)).sort((a, b) => (b.severity - a.severity) || (a.created - b.created)).slice(0, 25);
    for (const a of cands) {
      if (qcol.all((q) => !q.dead && q.op === 'create' && q.ref_id === a.id).length) continue;
      try { const r = await createTicket({ kind: 'alert', id: a.id, by: '' }); if (r.created) n++; if (r.queued) break; }
      catch (e) { log.warn('manageengine: auto-create failed', { alert: a.id, err: scrub(e.message) }); break; }
    }
    return n;
  }
  function mapStatus(s, sdpStatus) {
    const k = String(sdpStatus || '').toLowerCase().trim();
    return s.status_map[k] || 'ignore';
  }
  function closeReason(s, resolutionText) {
    const r = String(resolutionText || '').toLowerCase();
    if (/false[\s-]*positive/.test(r)) return 'false-positive';
    if (/\bbenign\b|expected behaviou?r|authori[sz]ed change/.test(r)) return 'benign';
    return s.close_reason_default;
  }
  function stripHtml(h) { return String(h || '').replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim(); }
  function applySdpState(t, s, sdpStatus, technician, resolution) {
    const mapped = mapStatus(s, sdpStatus);
    const changed = sdpStatus !== t.sdp_status || technician !== t.technician || resolution !== t.resolution;
    if (changed) tcol.patch(t.id, (x) => { x.sdp_status = sdpStatus; x.technician = technician; x.resolution = resolution; x.updated_at = now(); });
    if (mapped === 'ignore' || t.siem_status_applied === `${mapped}:${sdpStatus}`) return mapped;
    try {
      if (t.kind === 'alert' && alerts) {
        const a = alerts.get(t.ref_id);
        if (!a) return mapped;
        if (mapped === 'in-progress' && (a.status === 'new' || a.status === 'acknowledged')) {
          alerts.setStatus(a.id, 'in-progress', 'manageengine', `SDP #${t.request_id} ${sdpStatus}${technician ? ` (${technician})` : ''}`);
          st.in_progress_from_sdp++;
          audit('manageengine.alert.in-progress', a.id, { request_id: t.request_id, sdp_status: sdpStatus, technician });
        } else if (mapped === 'closed' && !isClosedAlert(a.status)) {
          alerts.close(a.id, closeReason(s, resolution), 'manageengine', `SDP #${t.request_id} ${sdpStatus}${technician ? ` by ${technician}` : ''}${resolution ? `: ${resolution.slice(0, 2000)}` : ''}`);
          st.closed_from_sdp++;
          audit('manageengine.alert.close', a.id, { request_id: t.request_id, sdp_status: sdpStatus, reason: closeReason(s, resolution) });
        }
      } else if (t.kind === 'case' && cases) {
        const c = cases.get(t.ref_id);
        if (!c) return mapped;
        if (mapped === 'in-progress' && c.status === 'open') cases.setStatus(c.id, 'investigating', 'manageengine', { note: `SDP #${t.request_id} ${sdpStatus}` });
        else if (mapped === 'closed' && c.status !== 'closed') {
          cases.setStatus(c.id, 'closed', 'manageengine', { resolution: closeReason(s, resolution), note: `SDP #${t.request_id} ${sdpStatus}${resolution ? `: ${resolution.slice(0, 2000)}` : ''}`, close_alerts: true });
          st.closed_from_sdp++;
          audit('manageengine.case.close', c.id, { request_id: t.request_id, sdp_status: sdpStatus });
        }
      }
      tcol.patch(t.id, (x) => { x.siem_status_applied = `${mapped}:${sdpStatus}`; });
    } catch (e) { log.warn('manageengine: could not reflect SDP status', { ticket: t.id, err: e.message }); }
    return mapped;
  }
  async function readback(s) {
    const open = tcol.all((t) => !/^(closed|cancell?ed)$/i.test(t.sdp_status || '') || (now() - (t.updated_at || 0)) < 3600000)
      .sort((a, b) => (a.last_synced || 0) - (b.last_synced || 0)).slice(0, s.readback_batch);
    let n = 0;
    for (const t of open) {
      try {
        const j = await sdp('GET', `/requests/${encodeURIComponent(t.request_id)}`);
        const r = j.request || {};
        const sdpStatus = (r.status && r.status.name) || t.sdp_status || '';
        const technician = (r.technician && (r.technician.name || r.technician.email_id)) || '';
        const resolution = stripHtml(r.resolution && (r.resolution.content || r.resolution.description || r.resolution) || '');
        applySdpState(t, s, sdpStatus, technician, resolution);
        tcol.patch(t.id, (x) => { x.last_synced = now(); x.last_sync_error = ''; });
        st.readbacks++; n++;
      } catch (e) {
        tcol.patch(t.id, (x) => { x.last_synced = now(); x.last_sync_error = scrub(e.message); });
        if (e.retriable || e.code === 'AUTH' || e.code === 'CONFIG') throw e; // SDP down / key invalid: stop this pass
        if (e.status === 404) { tcol.patch(t.id, (x) => { x.sdp_status = 'Deleted'; }); }
      }
    }
    return n;
  }
  async function recurrence(s) {
    if (!alerts) return 0;
    let n = 0;
    for (const t of tcol.all((x) => x.kind === 'alert')) {
      const a = alerts.get(t.ref_id);
      if (!a) continue;
      const grew = (a.count || 1) > (t.alert_count || 0);
      const newNotes = (a.notes || []).slice(t.notes_seen || 0).filter((x) => x.by !== 'manageengine');
      if (!grew && !newNotes.length) continue;
      const closed = /^(closed|resolved|cancell?ed)$/i.test(t.sdp_status || '');
      const parts = [];
      if (grew) parts.push(`SIEM alert ${a.id} recurred: ${t.alert_count || 0} → ${a.count} events, last seen ${new Date(a.ts_last || 0).toISOString()}.`);
      for (const x of newNotes) parts.push(`SOC note (${x.by || 'system'}, ${new Date(x.at || 0).toISOString()}): ${scrub(x.text)}`);
      parts.push(portalLink('alert', a.id));
      const text = parts.join('\n');
      try {
        if (grew && closed && s.on_recurrence === 'reopen') await reopenRequest(t, text);
        else { await sdpNote(t.request_id, text); tcol.patch(t.id, (x) => { x.comments = (x.comments || 0) + 1; }); st.comments++; audit('manageengine.ticket.comment', t.id, { request_id: t.request_id, by: 'auto', recurrence: grew, notes: newNotes.length }); }
        tcol.patch(t.id, (x) => { x.alert_count = a.count || 1; x.notes_seen = (a.notes || []).length; x.updated_at = now(); });
        n++;
      } catch (e) {
        if (e.retriable) { enqueue(grew && closed && s.on_recurrence === 'reopen' ? 'reopen' : 'comment', 'alert', a.id, { ticket_id: t.id, text }, e); tcol.patch(t.id, (x) => { x.alert_count = a.count || 1; x.notes_seen = (a.notes || []).length; }); throw e; }
        log.warn('manageengine: recurrence update failed', { ticket: t.id, err: scrub(e.message) });
      }
    }
    return n;
  }
  async function sync() {
    if (syncing) return syncing;
    syncing = (async () => {
      const t0 = now();
      const s = settings();
      const out = { at: t0, enabled: s.enabled, queue: null, auto_created: 0, recurrence: 0, readback: 0, error: '' };
      try {
        if (!s.enabled) return out;
        out.queue = await processQueue();
        out.auto_created = await autoCreate(s);
        out.recurrence = await recurrence(s);
        out.readback = await readback(s);
        st.last_sync_error = '';
      } catch (e) {
        out.error = scrub(e.message); st.last_sync_error = out.error; st.errors++;
        log.warn('manageengine: sync stopped early', { err: out.error, code: e.code });
      } finally { st.last_sync = now(); st.last_sync_ms = now() - t0; syncing = null; }
      return out;
    })();
    return syncing;
  }

  // ---------------- views
  function status() {
    const s = settings();
    const q = qcol.all();
    const live = q.filter((x) => !x.dead);
    const tk = tcol.all();
    const closedRe = /^(closed|resolved|cancell?ed|deleted)$/i;
    return {
      enabled: s.enabled, variant: s.variant, base_url: s.base_url, api_version: s.api_version,
      configured: !!(s.base_url && currentKey()), credential: credentialState(),
      queue: { depth: live.length, dead: q.length - live.length, next_at: live.length ? Math.min(...live.map((x) => x.next_at)) : 0, oldest: live.length ? Math.min(...live.map((x) => x.created)) : 0,
        items: q.sort((a, b) => a.created - b.created).slice(0, 50).map((x) => ({ id: x.id, op: x.op, kind: x.kind, ref_id: x.ref_id, attempts: x.attempts, next_at: x.next_at, last_error: x.last_error, dead: !!x.dead })) },
      tickets: { total: tk.length, open: tk.filter((t) => !closedRe.test(t.sdp_status || '')).length, closed: tk.filter((t) => closedRe.test(t.sdp_status || '')).length, linked: tk.filter((t) => t.linked).length },
      last_sync: st.last_sync, last_sync_ms: st.last_sync_ms, last_sync_error: st.last_sync_error, last_test: st.last_test, last_error: st.last_error,
      counters: { created: st.created, linked: st.linked, comments: st.comments, reopened: st.reopened, readbacks: st.readbacks, closed_from_sdp: st.closed_from_sdp, in_progress_from_sdp: st.in_progress_from_sdp, errors: st.errors, queued: st.queued, dead: st.dead },
      mappings: { priority_map: s.priority_map, status_map: s.status_map, close_reason_default: s.close_reason_default, category: s.category, subcategory: s.subcategory, item: s.item, group: s.group, technician: s.technician, site: s.site, template_id: s.template_id, auto_create: s.auto_create, on_recurrence: s.on_recurrence, dedupe_window_h: s.dedupe_window_h },
      sync_interval_s: s.sync_interval_s, running: !!timer,
    };
  }
  function tickets(f = {}) {
    let items = tcol.all((t) => (!f.kind || t.kind === f.kind) && (!f.ref_id || t.ref_id === f.ref_id));
    if (f.open === '1' || f.open === true) items = items.filter((t) => !/^(closed|resolved|cancell?ed|deleted)$/i.test(t.sdp_status || ''));
    items.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
    const limit = Math.min(500, Math.max(1, Number(f.limit) || 100));
    return { total: items.length, items: items.slice(0, limit) };
  }
  function alertsWithoutTickets(f = {}) {
    if (!alerts) return { total: 0, items: [] };
    const minSev = Number(f.min_severity) || 0;
    // an alert counts as ticketed when it has its own SDP request or belongs to a case that has one
    const items = alerts.all((a) => !isClosedAlert(a.status) && a.severity >= minSev && !ticketFor('alert', a.id) && !(a.case_id && ticketFor('case', a.case_id)))
      .sort((a, b) => (b.severity - a.severity) || ((b.ts_last || 0) - (a.ts_last || 0)))
      .map((a) => ({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, status: a.status, count: a.count, ts_last: a.ts_last, summary: a.summary, assignee: a.assignee, case_id: a.case_id, queued: qcol.all((q) => !q.dead && q.op === 'create' && q.ref_id === a.id).length > 0 }));
    const limit = Math.min(500, Math.max(1, Number(f.limit) || 100));
    return { total: items.length, items: items.slice(0, limit) };
  }

  function start() {
    if (timer) return;
    const s = settings();
    timer = setInterval(() => { sync().catch((e) => log.error('manageengine: sync failed', { err: scrub(e.message) })); }, Math.max(30, Number(s.sync_interval_s) || 120) * 1000);
    if (timer.unref) timer.unref();
  }
  function stop() { if (timer) { clearInterval(timer); timer = null; } }

  // ---------------- queue pickup for other desks (AI Network Engineer ticket desk, netops/tickets.js)
  // Requests assigned in SDP to a technician / group are read with list_info.search_criteria (verify the field names on
  // the customer's build: technician.name, group.name, status.name). Only reads, notes and re-assignment: nothing is closed.
  function slimRequest(r) {
    r = r || {};
    const v = (x) => (x && typeof x === 'object' ? x.name || x.value || x.display_value || '' : x || '');
    return { id: String(r.id || ''), subject: scrub(String(r.subject || '')).slice(0, 300), description: scrub(stripHtml(r.description || r.short_description || '')).slice(0, 8000),
      status: v(r.status), priority: v(r.priority), group: v(r.group), technician: v(r.technician), category: v(r.category), subcategory: v(r.subcategory),
      site: v(r.site), requester: r.requester ? String(r.requester.name || r.requester.email_id || '') : '', created_at: Number(r.created_time && r.created_time.value) || null, url: requestUrl(r.id) };
  }
  /** queueRequests({technician?, group?, limit?}) → open SDP requests assigned to that technician or group */
  async function queueRequests({ technician, group, limit } = {}) {
    if (!technician && !group) throw new SdpError('a technician or a group is required', { code: 'CONFIG' });
    const crit = [];
    if (technician) crit.push({ field: 'technician.name', condition: 'is', value: String(technician) });
    if (group) crit.push(Object.assign({ field: 'group.name', condition: 'is', value: String(group) }, crit.length ? { logical_operator: 'OR' } : {}));
    const all = [];
    for (const c of crit) {   // one query per criterion: OR groups are not supported the same way on every build
      const j = await sdp('GET', '/requests', { input: { list_info: { row_count: Math.min(100, Number(limit) || 50), start_index: 1, sort_field: 'created_time', sort_order: 'desc', search_criteria: [Object.assign({}, c, { logical_operator: undefined })] } } });
      for (const r of j.requests || []) if (!all.some((x) => String(x.id) === String(r.id))) all.push(r);
    }
    return all.map(slimRequest).filter((r) => !/^(closed|resolved|cancel)/i.test(r.status));
  }
  async function getRequest(id) {
    if (!/^\d{1,20}$/.test(String(id))) throw new SdpError('request id must be a number', { code: 'INPUT' });
    const j = await sdp('GET', `/requests/${encodeURIComponent(id)}`);
    return slimRequest(j.request);
  }
  async function noteRequest(id, text) { if (!/^\d{1,20}$/.test(String(id))) throw new SdpError('request id must be a number', { code: 'INPUT' }); await sdpNote(id, text); return { ok: true }; }
  async function assignRequest(id, { group, technician } = {}) {
    if (!/^\d{1,20}$/.test(String(id))) throw new SdpError('request id must be a number', { code: 'INPUT' });
    // a new group without a named technician clears the technician, so the request lands in that group's queue
    const r = compact({ group: nameObj(group), technician: technician ? nameObj(technician) : undefined });
    if (group && !technician) r.technician = null;
    await sdp('PUT', `/requests/${encodeURIComponent(id)}`, { input: { request: r } });
    return { ok: true };
  }
  function configured() { const s = settings(); return !!(s.base_url && currentKey()); }

  return {
    settings, setSettings, setCredential, clearCredential, credentialState, test, createTicket, linkTicket, linkBulk, comment, sync, processQueue, retryDead, purgeQueue,
    status, tickets, alertsWithoutTickets, ticketFor, buildPayload, scrub, start, stop, DEFAULTS, SdpError, registerKind,
    queueRequests, getRequest, noteRequest, assignRequest, configured, requestUrl,
  };
}

module.exports = { createManageEngine, DEFAULTS, SdpError, defaultTransport };
