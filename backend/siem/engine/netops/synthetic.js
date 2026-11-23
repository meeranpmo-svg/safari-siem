// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Synthetic monitoring + Apdex (Synthetic Monitoring & Apdex page).
 *   createSynthetic({ state, config, log, ch?, now?, resolve?, lookup? })
 *     .start() .stop() .list() .get(id) .put(input, by) .remove(id) .runNow(id) .runDue()
 *     .settings() .setSettings(s, by) .view(opts) .detail(id) .portalApdex(q)
 * A check is one URL (or up to 10 "transaction" steps) fetched with GET or HEAD only - the engine never sends a body, never
 * posts a form and never logs in: a transaction step either names a URL or follows a link (an <a href>) found by its text
 * on the previous page. Per run: HTTP status against the expected status, optional expected text in the first 512 KB of
 * the body, the TLS certificate (valid, issuer, days to expiry) and the time spent in DNS, connect, TLS, first byte and total.
 * SSRF safety (resolveTarget): an administrator lists the allowed hosts (exact or *.domain) and networks (CIDR / IP).
 *   - loopback, link-local (169.254/16 - cloud metadata), multicast and "this network" are never reached;
 *   - a private address (RFC 1918, 100.64/10, fc00::/7) only when "allow private networks" is on AND the address is inside
 *     a network the administrator listed;
 *   - a public address when its host name or its network is on the list;
 *   - every address the name resolves to must pass, and the engine connects to the address it checked (no second lookup,
 *     so a DNS answer cannot change between the check and the connection); every redirect is checked again the same way.
 * Results: each run is classified for Apdex against the check's T (satisfied <= T, tolerating <= 4T, frustrated above or
 * failed) and added to an hourly aggregate (state "syn_hourly", 90 days: counts, errors, time histogram), the latest result
 * and the last 60 runs ("syn_last"), and - with ClickHouse - net_metrics rows (device "syn:<id>") like every netops metric.
 * p50 / p95 come from the hourly histogram: they are the upper bound of the bucket (marked approximate on the page).
 * Portal Apdex (portalApdex): the same Apdex over the web server access logs the Portal Traffic page reads (request time
 * from $request_time; a 5xx answer is frustrated). Nothing is estimated: no request time in the log format = no Apdex.
 */
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const net = require('node:net');
const crypto = require('node:crypto');

const DEFAULTS = { enabled: true, tick_s: 15, concurrency: 8, max_body_kb: 512, keep_days: 90 };
const HIST = [50, 100, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 7500, 10000, 15000, 20000, 30000, 60000];   // ms, upper bounds; one more bucket = above
const RIYADH = 3 * 3600000, HOUR = 3600000, DAY = 86400000;
const ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;

function bad(msg, status) { return Object.assign(new Error(msg), { status: status || 400 }); }
function clean(v, max) { return String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, max); }

/* ---------------- address policy (pure) */
function v4(ip) { return ip.split('.').reduce((a, o) => a * 256 + Number(o), 0); }
function inCidr4(ip, cidr) { const [b, bits] = cidr.split('/'); const n = Number(bits); const size = 2 ** (32 - n); return Math.floor(v4(ip) / size) === Math.floor(v4(b) / size); }
function norm(ip) { const s = String(ip || '').toLowerCase(); const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s); return m ? m[1] : s; }
const NEVER4 = ['127.0.0.0/8', '0.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4'];
const PRIVATE4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '198.18.0.0/15'];
function never(ip) {
  ip = norm(ip);
  if (net.isIPv4(ip)) return NEVER4.some((c) => inCidr4(ip, c));
  return ip === '::1' || ip === '::' || /^fe[89ab]/.test(ip) || /^ff/.test(ip);
}
function isPrivate(ip) { ip = norm(ip); return net.isIPv4(ip) ? PRIVATE4.some((c) => inCidr4(ip, c)) : /^f[cd]/.test(ip); }
/* allow-list entries: "portal.example.com", "*.example.com", "10.20.0.0/16", "203.0.113.7" */
function parseAllow(list) {
  if (!Array.isArray(list)) throw bad('allow must be a list');
  if (list.length > 200) throw bad('allow has more than 200 entries');
  return list.map((x, i) => {
    const s = String(x == null ? '' : x).trim().toLowerCase();
    if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(s)) { const [b, bits] = s.split('/'); if (!net.isIPv4(b) || !(Number(bits) >= 8 && Number(bits) <= 32)) throw bad(`allow[${i}] is not a valid network (CIDR /8 - /32)`); return { kind: 'net', v: s }; }
    if (net.isIP(s)) return { kind: 'ip', v: norm(s) };
    if (/^\*\.[a-z0-9.-]+$/.test(s) && /^\*\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(s)) return { kind: 'suffix', v: s.slice(1) };
    if (/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(s)) return { kind: 'host', v: s };
    throw bad(`allow[${i}] must be a host name, *.domain, an IP address or a network (CIDR)`);
  });
}
function nameAllowed(host, allow) { const h = String(host || '').toLowerCase(); return allow.some((a) => (a.kind === 'host' && a.v === h) || (a.kind === 'suffix' && h.endsWith(a.v) && h.length > a.v.length)); }
function netAllowed(ip, allow) { ip = norm(ip); return allow.some((a) => (a.kind === 'ip' && a.v === ip) || (a.kind === 'net' && net.isIPv4(ip) && inCidr4(ip, a.v))); }
/* decide one host + its resolved addresses; returns the address to connect to or throws (status 403, why) */
function decide(host, addresses, settings) {
  const allow = parseAllow(settings.allow || []);
  if (!allow.length) throw bad('no allowed hosts / networks are set (an administrator sets them under Settings)', 403);
  if (!addresses.length) throw bad(`${host} did not resolve`, 403);
  const byName = nameAllowed(host, allow);
  for (const a of addresses) {
    if (never(a)) throw bad(`${host} resolves to ${norm(a)} (loopback / link-local / multicast) - never allowed`, 403);
    if (isPrivate(a)) {
      if (!settings.allow_private) throw bad(`${host} resolves to the private address ${norm(a)} - private networks are not allowed`, 403);
      if (!netAllowed(a, allow)) throw bad(`${host} resolves to the private address ${norm(a)}, which is not inside a network on the allow-list`, 403);
    } else if (!byName && !netAllowed(a, allow)) throw bad(`${host} (${norm(a)}) is not on the allow-list`, 403);
  }
  return norm(addresses[0]);
}
const defaultLookup = (host) => new Promise((ok, no) => dns.lookup(host, { all: true, verbatim: true }, (e, list) => (e ? no(e) : ok(list.map((x) => x.address)))));

/* ---------------- Apdex (pure) */
function classify(ok, ms, T) { if (!ok) return 'f'; if (ms <= T) return 's'; if (ms <= 4 * T) return 't'; return 'f'; }
function apdex(a) { return a && a.n ? Math.round((a.s + a.t / 2) / a.n * 100) / 100 : null; }
function rating(score) { return score == null ? null : score >= 0.94 ? 'excellent' : score >= 0.85 ? 'good' : score >= 0.7 ? 'fair' : score >= 0.5 ? 'poor' : 'unacceptable'; }
function bucketOf(ms) { for (let i = 0; i < HIST.length; i++) if (ms <= HIST[i]) return i; return HIST.length; }
function pctl(hist, q) {
  const n = (hist || []).reduce((a, b) => a + b, 0); if (!n) return null;
  let c = 0; for (let i = 0; i < hist.length; i++) { c += hist[i]; if (c >= q * n) return i < HIST.length ? HIST[i] : HIST[HIST.length - 1]; }
  return HIST[HIST.length - 1];
}
function sum(rows) {
  const o = { n: 0, s: 0, t: 0, f: 0, err: 0, ms: 0, ok_n: 0, hist: new Array(HIST.length + 1).fill(0) };
  for (const r of rows) { o.n += r.n; o.s += r.s; o.t += r.t; o.f += r.f; o.err += r.err; o.ms += r.ms || 0; o.ok_n += r.ok_n || 0; (r.hist || []).forEach((v, i) => { o.hist[i] += v; }); }
  return o;
}
function stats(a) {
  if (!a || !a.n) return { runs: 0, apdex: null, rating: null, uptime_pct: null, error_rate_pct: null, avg_ms: null, p50_ms: null, p95_ms: null, satisfied: 0, tolerating: 0, frustrated: 0 };
  const sc = apdex(a);
  return { runs: a.n, apdex: sc, rating: rating(sc), uptime_pct: Math.round((a.n - a.err) / a.n * 10000) / 100, error_rate_pct: Math.round(a.err / a.n * 10000) / 100,
    avg_ms: a.ok_n ? Math.round(a.ms / a.ok_n) : null, p50_ms: pctl(a.hist, 0.5), p95_ms: pctl(a.hist, 0.95), satisfied: a.s, tolerating: a.t, frustrated: a.f };
}

/* ---------------- links (transaction steps follow a link by its text) */
function findLink(html, text, base) {
  const want = String(text || '').toLowerCase().trim(); if (!want) return null;
  const re = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi; let m, k = 0;
  while ((m = re.exec(html)) && k++ < 5000) {
    const href = (m[1] || m[2] || m[3] || '').replace(/&amp;/g, '&').trim(), label = m[4].replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
    if (!href || /^(javascript|mailto|tel|data):/i.test(href) || label.indexOf(want) < 0) continue;
    try { const u = new URL(href, base); if (u.protocol === 'http:' || u.protocol === 'https:') return u; } catch (e) { /* a malformed href is skipped: the next link may match */ }
  }
  return null;
}

/* ---------------- check validation (semantic; the route declares the fields with check.js) */
function validUrl(s, field) {
  let u; try { u = new URL(String(s)); } catch (e) { throw bad(`${field} is not a valid URL`); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw bad(`${field} must start with http:// or https://`);
  if (u.username || u.password) throw bad(`${field} may not carry a user name or password`);
  if (String(s).length > 1000) throw bad(`${field} is longer than 1000 characters`);
  return u.toString();
}
function normStatus(v, field) {
  if (v === undefined || v === null || v === '') return [];
  const arr = Array.isArray(v) ? v : [v];
  if (arr.length > 10) throw bad(`${field} has more than 10 codes`);
  return arr.map((x) => { const n = Number(x); if (!Number.isInteger(n) || n < 100 || n > 599) throw bad(`${field} must be HTTP status codes (100-599)`); return n; });
}
function normSteps(steps) {
  if (steps === undefined || steps === null) return [];
  if (!Array.isArray(steps)) throw bad('steps must be a list');
  if (steps.length > 10) throw bad('steps has more than 10 entries (a transaction is at most 10 GET requests)');
  return steps.map((s, i) => {
    if (!s || typeof s !== 'object' || Array.isArray(s)) throw bad(`steps[${i}] must be an object`);
    const allowed = ['url', 'link_text', 'expect_status', 'expect_text', 'name'];
    const extra = Object.keys(s).filter((k) => !allowed.includes(k)); if (extra.length) throw bad(`steps[${i}].${extra[0]} is not a step field (url, link_text, expect_status, expect_text, name) - steps are GET requests only`);
    const o = { name: clean(s.name, 80) };
    if (s.url) o.url = validUrl(s.url, `steps[${i}].url`);
    else if (s.link_text) { o.link_text = clean(s.link_text, 120); if (i === 0) throw bad('steps[0] needs a url (a link can only be followed from a page already fetched)'); }
    else throw bad(`steps[${i}] needs a url or link_text`);
    o.expect_status = normStatus(s.expect_status, `steps[${i}].expect_status`);
    if (s.expect_text) { o.expect_text = clean(s.expect_text, 200); }
    return o;
  });
}

function createSynthetic({ state, config, log, ch, now, resolve, lookup } = {}) {
  if (!state) throw new Error('synthetic needs state');
  const L = log || { info() {}, warn() {}, every() {} }, clock = now || Date.now;
  const opt = Object.assign({}, DEFAULTS, ((config && config.netops) || {}).synthetic || {});
  const checks = state.collection('syn_checks'), hourly = state.collection('syn_hourly'), last = state.collection('syn_last'), cfg = state.collection('syn_settings');
  const db = (config && config.clickhouse && config.clickhouse.database) || 'siem';
  const running = new Set(); let timer = null, stopped = true;
  const st = { runs: 0, failures: 0, blocked: 0, last_tick_at: 0 };

  function settings() { const v = (cfg.get('settings') || {}).value || {}; return { allow: Array.isArray(v.allow) ? v.allow : [], allow_private: v.allow_private === true, default_t_ms: v.default_t_ms || 500, updated: (cfg.get('settings') || {}).updated || null, updated_by: (cfg.get('settings') || {}).updated_by || '' }; }
  function setSettings(s, by) {
    const cur = settings(), v = { allow: cur.allow, allow_private: cur.allow_private, default_t_ms: cur.default_t_ms };
    if (s.allow !== undefined) v.allow = parseAllow(s.allow).map((a) => (a.kind === 'suffix' ? '*' + a.v : a.v));
    if (s.allow_private !== undefined) v.allow_private = s.allow_private === true;
    if (s.default_t_ms !== undefined) v.default_t_ms = s.default_t_ms;
    cfg.put({ id: 'settings', value: v, updated: clock(), updated_by: by || '' });
    return { before: { allow: cur.allow, allow_private: cur.allow_private, default_t_ms: cur.default_t_ms }, settings: settings() };
  }
  const resolver = resolve || (async (u) => decide(u.hostname.replace(/^\[|\]$/g, ''), net.isIP(u.hostname.replace(/^\[|\]$/g, '')) ? [u.hostname.replace(/^\[|\]$/g, '')] : await (lookup || defaultLookup)(u.hostname), settings()));

  function put(input, by) {
    const ex = input.id ? checks.get(input.id) : null;
    const c = Object.assign({}, ex || {});
    if (!ex) {
      c.id = input.id || (clean(input.name, 30).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'check') + '-' + crypto.randomBytes(3).toString('hex');
      if (!ID_RE.test(c.id)) throw bad('id: 2-40 lowercase letters, digits and dashes');
      if (checks.size() >= 500) throw bad('at most 500 checks');
    }
    for (const k of ['name', 'app']) if (input[k] !== undefined) c[k] = clean(input[k], k === 'name' ? 120 : 80);
    if (!c.name) throw bad('name is required');
    if (input.url !== undefined || !ex) c.url = validUrl(input.url || '', 'url');
    if (input.method !== undefined) c.method = input.method; if (!c.method) c.method = 'GET';
    if (!['GET', 'HEAD'].includes(c.method)) throw bad('method must be GET or HEAD (synthetic checks never send a body)');
    if (input.expect_status !== undefined) c.expect_status = normStatus(input.expect_status, 'expect_status'); if (!c.expect_status) c.expect_status = [];
    if (input.expect_text !== undefined) c.expect_text = clean(input.expect_text, 200);
    if (c.expect_text && c.method === 'HEAD') throw bad('expect_text needs method GET (HEAD has no body)');
    for (const [k, d] of [['timeout_ms', 10000], ['interval_s', 300], ['apdex_t_ms', settings().default_t_ms], ['max_redirects', 5], ['cert_warn_days', 30]]) { if (input[k] !== undefined) c[k] = input[k]; if (c[k] === undefined) c[k] = d; }
    for (const [k, d] of [['follow_redirects', true], ['tls_verify', true], ['enabled', true]]) { if (input[k] !== undefined) c[k] = input[k] === true; if (c[k] === undefined) c[k] = d; }
    if (input.steps !== undefined) c.steps = normSteps(input.steps); if (!c.steps) c.steps = [];
    if (c.steps.length && c.method === 'HEAD') throw bad('a transaction needs method GET');
    if (!settings().allow.length) throw bad('set the allowed hosts / networks first (Settings) - a check can only reach hosts an administrator allowed');
    c.updated = clock(); c.updated_by = by || ''; if (!ex) { c.created = c.updated; c.created_by = by || ''; }
    checks.put(c);
    return { check: c, before: ex };
  }
  function remove(id) {
    if (!checks.get(id)) throw bad('check not found', 404);
    checks.remove(id); last.remove(id);
    for (const h of hourly.all((x) => x.check === id)) hourly.remove(h.id);
    return { removed: id };
  }

  /* ---------------- one HTTP request to an already-vetted address */
  function fetchOnce(u, method, c, t0) {
    return resolver(u).then((address) => new Promise((resolveP) => {
      const tDns = clock(), isTls = u.protocol === 'https:', mod = isTls ? https : http, maxBytes = opt.max_body_kb * 1024;
      const host = u.hostname.replace(/^\[|\]$/g, '');
      const o = { method, host: address, port: Number(u.port) || (isTls ? 443 : 80), path: u.pathname + u.search, agent: false,
        headers: { Host: u.host, 'User-Agent': 'Sentra-Synthetic/1.0', Accept: '*/*', 'Accept-Encoding': 'identity', Connection: 'close' } };
      if (isTls) { o.servername = net.isIP(host) ? undefined : host; o.rejectUnauthorized = false; }   // verified below, so an invalid certificate is reported, not just a reset
      const r = { url: u.toString(), status: 0, ms: { dns: tDns - t0 }, bytes: 0, body: '' };
      let done = false; const tStart = tDns;
      const finish = (err) => { if (done) return; done = true; clearTimeout(tm); r.ms.total = clock() - tStart; if (err) r.error = err; resolveP(r); };
      const tm = setTimeout(() => { req.destroy(new Error('timed out after ' + c.timeout_ms + ' ms')); }, c.timeout_ms);
      const req = mod.request(o, (res) => {
        r.first_at = clock(); r.ms.ttfb = r.first_at - tStart; r.status = res.statusCode; r.location = res.headers.location || '';
        const chunks = []; let size = 0;
        res.on('data', (d) => { if (size < maxBytes) { chunks.push(d); size += d.length; } r.bytes += d.length; if (r.bytes > maxBytes * 4) res.destroy(); });
        res.on('end', () => { r.body = Buffer.concat(chunks).slice(0, maxBytes).toString('utf8'); finish(); });
        res.on('close', () => { r.body = r.body || Buffer.concat(chunks).slice(0, maxBytes).toString('utf8'); finish(); });
        res.on('error', (e) => finish(e.message));
      });
      req.on('socket', (s) => {
        s.once('connect', () => { r.ms.connect = clock() - tDns; });
        if (isTls) s.once('secureConnect', () => {
          r.ms.tls = clock() - tDns - (r.ms.connect || 0);
          const pc = s.getPeerCertificate() || {}, to = Date.parse(pc.valid_to);
          r.cert = { subject: clean(pc.subject && pc.subject.CN, 200), issuer: clean(pc.issuer && (pc.issuer.O || pc.issuer.CN), 200), valid_from: Date.parse(pc.valid_from) || null, valid_to: to || null,
            days_left: to ? Math.floor((to - clock()) / DAY) : null, authorized: s.authorized === true, error: s.authorized ? '' : clean(s.authorizationError, 120), fingerprint256: clean(pc.fingerprint256, 120) };
          if (c.tls_verify !== false && !s.authorized) req.destroy(new Error('TLS certificate not trusted: ' + (s.authorizationError || 'unknown')));
        });
      });
      req.on('error', (e) => finish(e.message));
      req.end();
    }), (e) => { st.blocked += e.status === 403 ? 1 : 0; return { url: u.toString(), status: 0, ms: { dns: clock() - t0, total: clock() - t0 }, error: e.message, blocked: e.status === 403 }; });
  }

  async function runCheck(c) {
    const t0 = clock(), steps = c.steps && c.steps.length ? c.steps : [{ url: c.url, expect_status: c.expect_status, expect_text: c.expect_text }];
    const out = { at: t0, ok: true, steps: [], redirects: 0 }; let prev = null;
    for (let i = 0; i < steps.length; i++) {
      const sp = steps[i];
      let u = sp.url ? new URL(sp.url) : prev ? findLink(prev.body, sp.link_text, prev.url) : null;
      const sr = { name: sp.name || '', url: u ? u.toString() : '', ok: false };
      if (!u) { sr.error = 'no link with the text "' + sp.link_text + '" on the previous page'; out.steps.push(sr); out.ok = false; out.error = (steps.length > 1 ? 'step ' + (i + 1) + ': ' : '') + sr.error; break; }
      const tS = clock(); let r, hops = 0;
      for (;;) {
        r = await fetchOnce(u, i === 0 && steps.length === 1 ? c.method : 'GET', c, clock());
        if (hops === 0) { if (i === 0) { out.ms = { dns: r.ms.dns, connect: r.ms.connect, tls: r.ms.tls }; } }
        if (r.cert && !out.cert) out.cert = r.cert;
        if (r.error || !(r.status >= 300 && r.status < 400 && r.location && c.follow_redirects !== false)) break;
        if (++hops > (c.max_redirects == null ? 5 : c.max_redirects)) { r.error = 'more than ' + c.max_redirects + ' redirects'; break; }
        let nx; try { nx = new URL(r.location, u); } catch (e) { r.error = 'invalid redirect location'; break; }
        if (nx.protocol !== 'http:' && nx.protocol !== 'https:') { r.error = 'redirect to ' + nx.protocol + ' refused'; break; }
        if (nx.protocol === 'http:' && u.protocol === 'https:') sr.downgrade = true;
        out.redirects++; u = nx;   // the next fetchOnce checks the new host against the allow-list again
      }
      sr.url = u.toString(); sr.status = r.status; sr.ms = clock() - tS; sr.bytes = r.bytes || 0;
      if (r.blocked) { sr.blocked = true; out.blocked = true; }
      const want = sp.expect_status && sp.expect_status.length ? sp.expect_status : null;
      if (r.error) sr.error = r.error;
      else if (want ? !want.includes(r.status) : !(r.status >= 200 && r.status < 400)) sr.error = 'HTTP ' + r.status + (want ? ' (expected ' + want.join(', ') + ')' : '');
      else if (sp.expect_text && String(r.body || '').indexOf(sp.expect_text) < 0) sr.error = 'expected text not found';
      sr.ok = !sr.error;
      out.steps.push(sr); prev = { body: r.body || '', url: u };
      if (i === steps.length - 1) { out.status = r.status; out.final_url = u.toString(); out.ms = Object.assign(out.ms || {}, { ttfb: r.first_at ? r.first_at - t0 : null }); }
      if (!sr.ok) { out.ok = false; out.error = (steps.length > 1 ? 'step ' + (i + 1) + ': ' : '') + sr.error; out.status = r.status; break; }
    }
    out.ms = Object.assign({ dns: null, connect: null, tls: null, ttfb: null }, out.ms || {}, { total: clock() - t0 });
    for (const k of Object.keys(out.ms)) if (out.ms[k] != null) out.ms[k] = Math.max(0, Math.round(out.ms[k]));
    if (out.cert && out.cert.days_left != null && out.cert.days_left < 0 && out.ok) { out.ok = false; out.error = 'TLS certificate expired'; }
    out.apdex = classify(out.ok, out.ms.total, c.apdex_t_ms || 500);
    return out;
  }

  function record(c, r) {
    const hour = Math.floor(r.at / HOUR) * HOUR, id = c.id + ':' + hour, h = hourly.get(id) || { id, check: c.id, hour, n: 0, s: 0, t: 0, f: 0, err: 0, ms: 0, ok_n: 0, hist: new Array(HIST.length + 1).fill(0) };
    const x = Object.assign({}, h, { hist: h.hist.slice() });
    x.n++; x[r.apdex]++; if (!r.ok) x.err++; else { x.ms += r.ms.total; x.ok_n++; x.hist[bucketOf(r.ms.total)]++; }
    hourly.put(x);
    const prev = last.get(c.id) || { id: c.id, recent: [] };
    const recent = [{ at: r.at, ok: r.ok, ms: r.ms.total, status: r.status || 0, apdex: r.apdex }].concat(prev.recent || []).slice(0, 60);
    last.put({ id: c.id, last: r, recent, cert: r.cert || prev.cert || null });
    if (ch) {
      const ts = Math.floor(r.at / 1000), rows = [], add = (metric, v) => { if (v != null && Number.isFinite(Number(v))) rows.push({ ts, device: 'syn:' + c.id, site: c.app || '', key: '', metric, value: Number(v) }); };
      add('syn_up', r.ok ? 1 : 0); add('syn_total_ms', r.ms.total); add('syn_ttfb_ms', r.ms.ttfb); add('syn_dns_ms', r.ms.dns); add('syn_connect_ms', r.ms.connect); add('syn_tls_ms', r.ms.tls);
      if (r.cert) add('syn_cert_days', r.cert.days_left);
      ch.insertRows(db + '.net_metrics', rows).catch((e) => L.every('synthetic-metrics', 60000, 'warn', 'synthetic metrics insert failed', { err: e.message }));
    }
    if (Math.random() < 0.01) prune();
  }
  function prune() { const cut = clock() - opt.keep_days * DAY; for (const h of hourly.all((x) => x.hour < cut)) hourly.remove(h.id); }

  async function runOne(c) {
    if (running.has(c.id)) return null; running.add(c.id);
    try {
      const r = await runCheck(c); st.runs++; if (!r.ok) st.failures++;
      record(c, r);
      if (!r.ok) L.every('synthetic-fail-' + c.id, 600000, 'warn', 'synthetic check failed', { check: c.id, err: String(r.error || '').slice(0, 200) });
      return r;
    } finally { running.delete(c.id); }
  }
  async function runDue() {
    const t = clock(), due = checks.all((c) => c.enabled !== false && !running.has(c.id) && t - (((last.get(c.id) || {}).last || {}).at || 0) >= (c.interval_s || 300) * 1000);
    let i = 0; const worker = async () => { while (i < due.length) { const c = due[i++]; await runOne(c); } };
    await Promise.all(Array.from({ length: Math.min(opt.concurrency, due.length) }, worker));
    st.last_tick_at = t; return due.length;
  }
  const tick = guardJob('netops.synthetic.tick', async () => {
    try { await runDue(); } finally { if (!stopped) { timer = setTimeout(tick, Math.max(5, opt.tick_s) * 1000); if (timer.unref) timer.unref(); } }
  });

  /* ---------------- views */
  function windowOf(id, from) { return sum(hourly.all((h) => h.check === id && h.hour >= from)); }
  function rowOf(c, t) {
    const l = last.get(c.id) || {}, r = l.last || null, cert = l.cert || null;
    const d1 = stats(windowOf(c.id, t - DAY)), d7 = stats(windowOf(c.id, t - 7 * DAY)), d30 = stats(windowOf(c.id, t - 30 * DAY));
    const certState = !cert || cert.days_left == null ? null : cert.days_left < 0 ? 'expired' : !cert.authorized ? 'untrusted' : cert.days_left <= (c.cert_warn_days || 30) ? 'expiring' : 'ok';
    const status = !r ? 'pending' : !r.ok ? 'down' : (d1.apdex != null && d1.apdex < 0.7) || certState === 'expiring' || certState === 'untrusted' ? 'degraded' : 'up';
    return { id: c.id, name: c.name, app: c.app || '', url: c.url, method: c.method, steps: (c.steps || []).length, step_list: c.steps || [], enabled: c.enabled !== false, interval_s: c.interval_s, apdex_t_ms: c.apdex_t_ms, timeout_ms: c.timeout_ms,
      expect_status: c.expect_status, expect_text: c.expect_text || '', follow_redirects: c.follow_redirects !== false, max_redirects: c.max_redirects, tls_verify: c.tls_verify !== false, cert_warn_days: c.cert_warn_days,
      status, last: r ? { at: r.at, ok: r.ok, status: r.status || 0, error: r.error || '', ms: r.ms, redirects: r.redirects || 0, blocked: !!r.blocked } : null,
      cert: cert ? Object.assign({ state: certState }, cert) : null, d1, d7, d30, recent: (l.recent || []).slice(0, 30).reverse() };
  }
  function view() {
    const t = clock(), rows = checks.all().map((c) => rowOf(c, t)).sort((a, b) => ({ down: 0, degraded: 1, pending: 2, up: 3 }[a.status] - { down: 0, degraded: 1, pending: 2, up: 3 }[b.status]) || a.name.localeCompare(b.name));
    const all = sum(checks.all().map((c) => windowOf(c.id, t - DAY))), apps = {};
    for (const r of rows) { const k = r.app || r.name; (apps[k] = apps[k] || { app: k, checks: 0, down: 0, agg: [] }); apps[k].checks++; if (r.status === 'down') apps[k].down++; apps[k].agg.push(windowOf(r.id, t - DAY)); }
    const certs = rows.filter((r) => r.cert).map((r) => ({ id: r.id, name: r.name, url: r.url, state: r.cert.state, days_left: r.cert.days_left, valid_to: r.cert.valid_to, issuer: r.cert.issuer, subject: r.cert.subject, error: r.cert.error })).sort((a, b) => a.days_left - b.days_left);
    return {
      summary: Object.assign({ checks: rows.length, up: rows.filter((r) => r.status === 'up').length, degraded: rows.filter((r) => r.status === 'degraded').length, down: rows.filter((r) => r.status === 'down').length, pending: rows.filter((r) => r.status === 'pending').length,
        certs_expiring: certs.filter((c) => c.state === 'expiring').length, certs_bad: certs.filter((c) => c.state === 'expired' || c.state === 'untrusted').length }, { d1: stats(all) }),
      checks: rows, apps: Object.values(apps).map((a) => Object.assign({ app: a.app, checks: a.checks, down: a.down }, stats(sum(a.agg)))).sort((a, b) => (a.apdex == null) - (b.apdex == null) || (a.apdex || 0) - (b.apdex || 0)),
      certs, engine: Object.assign({ enabled: opt.enabled !== false, running: !stopped, tick_s: opt.tick_s }, st),
    };
  }
  function detail(id) {
    const c = checks.get(id); if (!c) throw bad('check not found', 404);
    const t = clock(), from48 = Math.floor((t - 48 * HOUR) / HOUR) * HOUR, H = hourly.all((h) => h.check === id);
    const byH = new Map(H.map((h) => [h.hour, h])), hours = [];
    for (let h = from48; h <= t; h += HOUR) { const x = byH.get(h); hours.push(Object.assign({ hour: h }, x ? stats(x) : stats(null))); }
    const byD = {}; for (const h of H) { if (h.hour < t - 30 * DAY) continue; const d = new Date(h.hour + RIYADH).toISOString().slice(0, 10); (byD[d] = byD[d] || []).push(h); }
    const days = Object.keys(byD).sort().map((d) => Object.assign({ day: d }, stats(sum(byD[d]))));
    const l = last.get(id) || {};
    return { check: rowOf(c, t), hours, days, last_result: l.last || null, recent: l.recent || [] };
  }

  /* Apdex over the web server access logs (src_type nginx, request time from the log line - the Portal Traffic data) */
  const RT = "toFloat64OrNull(extract(fields['extra'], '(?:^|\\\\s|rt=|request_time=)([0-9]+\\\\.[0-9]{1,6})(?:\\\\s|$)'))";
  const SITE = "if(fields['vhost'] != '', fields['vhost'], host)";
  async function portalApdex(q) {
    if (!ch) throw bad('the event store (ClickHouse) is not connected', 503);
    const p = { f: { type: 'Int64', value: clock() - q.hours * HOUR }, t: { type: 'Int64', value: clock() }, T: { type: 'Float64', value: q.t_ms / 1000 }, s: { type: 'String', value: q.site || '' } };
    const W = `ts >= fromUnixTimestamp64Milli({f:Int64}) AND ts < fromUnixTimestamp64Milli({t:Int64}) AND src_type = 'nginx'` + (q.site ? ` AND ${SITE} = {s:String}` : '');
    const SEL = `count() AS n, countIf(${RT} IS NOT NULL) AS timed, countIf(${RT} IS NOT NULL AND http_status < 500 AND ${RT} <= {T:Float64}) AS s,
      countIf(${RT} IS NOT NULL AND http_status < 500 AND ${RT} > {T:Float64} AND ${RT} <= 4 * {T:Float64}) AS t, countIf(http_status >= 500) AS e5,
      quantileIf(0.5)(${RT}, ${RT} IS NOT NULL) AS p50, quantileIf(0.95)(${RT}, ${RT} IS NOT NULL) AS p95`;
    const rq = (tag, sql) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true, timeout_ms: 30000 });
    const [sites, series] = await Promise.all([
      rq('syn_portal_sites', `SELECT ${SITE} AS site, ${SEL} FROM ${db}.events WHERE ${W} GROUP BY site ORDER BY n DESC LIMIT 30`),
      rq('syn_portal_series', `SELECT toStartOfHour(ts) AS h, ${SEL} FROM ${db}.events WHERE ${W} GROUP BY h ORDER BY h`),
    ]);
    const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
    const one = (r) => { const timed = num(r.timed), e5 = num(r.e5), s = num(r.s), t = num(r.t), n = timed + 0; const f = Math.max(0, n - s - t);
      return { requests: num(r.n), timed, satisfied: s, tolerating: t, frustrated: f, server_errors: e5, apdex: n ? Math.round((s + t / 2) / n * 100) / 100 : null, rating: n ? rating(Math.round((s + t / 2) / n * 100) / 100) : null,
        error_rate_pct: num(r.n) ? Math.round(e5 / num(r.n) * 10000) / 100 : null, p50_ms: n && r.p50 != null && Number.isFinite(Number(r.p50)) ? Math.round(Number(r.p50) * 1000) : null, p95_ms: n && r.p95 != null && Number.isFinite(Number(r.p95)) ? Math.round(Number(r.p95) * 1000) : null }; };
    const S = sites.map((r) => Object.assign({ site: r.site }, one(r))), timed = S.some((x) => x.timed > 0);
    return { hours: q.hours, t_ms: q.t_ms, site: q.site || null, sites: S, series: series.map((r) => Object.assign({ hour: Date.parse(String(r.h).replace(' ', 'T') + 'Z') || null }, one(r))),
      measured: timed, note: timed ? 'Apdex counts only requests whose log line carries the request time; a 5xx answer is frustrated.' : (S.length ? 'The web server log format has no request time ($request_time) - Apdex cannot be measured. Add $request_time to the nginx log_format.' : 'No web server access logs (src_type nginx) in this window.') };
  }

  return {
    start() { if (!stopped || opt.enabled === false) return; stopped = false; timer = setTimeout(tick, 20000); if (timer.unref) timer.unref(); },
    stop() { stopped = true; if (timer) clearTimeout(timer); timer = null; },
    list: () => checks.all(), get: (id) => checks.get(id) || null, put, remove, settings, setSettings, view, detail, portalApdex, runDue, runCheck,
    async runNow(id) { const c = checks.get(id); if (!c) throw bad('check not found', 404); const r = await runOne(c); if (!r) throw bad('this check is running now - try again in a moment', 409); return r; },
    stats: () => Object.assign({ checks: checks.size(), running: !stopped }, st),
  };
}

module.exports = { createSynthetic, decide, parseAllow, never, isPrivate, classify, apdex, rating, pctl, stats, sum, bucketOf, findLink, normSteps, validUrl, HIST, DEFAULTS };
