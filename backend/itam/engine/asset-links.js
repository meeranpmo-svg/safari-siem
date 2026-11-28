// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Web addresses of an asset: the applications a server hosts, its management consoles (ILOM / iLO / iDRAC / vCenter /
// Prism), APIs and documentation - kept with the asset so the inventory says where to reach it, not only its IP.
//   GET  /asset-links/:assetId            {asset_id, links[], checked{}}                                   any role
//   POST /asset-links/:assetId            {links: [{label, url, kind}]}  replaces the list (max 20)        operator
//   POST /asset-links/:assetId/check      reachability of each address: HTTP status, time, TLS certificate  operator
//   GET  /asset-links                     {assets: {assetId: links[]}}  every asset's addresses (export)     operator
// Addresses must be http(s) with a host; a user name or password inside the URL is refused (no secrets stored here).
// The check sends one GET per address from the platform server (no redirects followed - the Location is reported, no
// body kept), so it only reaches what the platform server can reach. Self-contained (stored collection), added to an
// existing install with one registration line (install/add-asset-links.sh).
const crypto = require('node:crypto');

const KINDS = { app: 'Application', mgmt: 'Management console', api: 'API', docs: 'Documentation', other: 'Other' };
const MAX = 20;
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max || 200);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const CLOSED = { disposed: 1 };

function normUrl(raw) {
  const t = s(raw, 2000);
  if (!t) throw bad('url is required');
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : 'https://' + t); } catch { throw bad(`"${t.slice(0, 80)}" is not a web address`); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw bad('only http:// and https:// addresses');
  if (!u.hostname) throw bad(`"${t.slice(0, 80)}" has no host`);
  if (u.username || u.password) throw bad('remove the user name / password from the address - logins are not stored with web addresses');
  u.hash = '';
  return u.toString();
}

// addresses a link check never connects to: this host (loopback, unspecified), link-local (incl. 169.254.169.254 metadata)
// an IPv4-mapped IPv6 address (::ffff:127.0.0.1, its hex form ::ffff:7f00:1 that the URL parser produces, or written out in full) is
// the IPv4 address it carries - turned back into dotted form before it is checked, so [::ffff:127.0.0.1] cannot reach this server
function unmap(v) {
  const m = /^(?:0{0,4}:){0,5}:?ffff:(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/.exec(v);
  if (!m) return v;
  if (m[1]) return m[1];
  const hi = parseInt(m[2], 16), lo = parseInt(m[3], 16);
  return [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.');
}
function blockedAddr(ip) {
  const v = unmap(String(ip || '').toLowerCase());
  if (/^127\./.test(v) || v === '0.0.0.0' || /^169\.254\./.test(v) || /^0\./.test(v)) return true;
  if (v === '::1' || v === '::' || /^fe[89ab][0-9a-f]:/.test(v) || /^fd00:ec2::/.test(v)) return true;
  return false;
}

function createAssetLinks(app, opts = {}) {
  const { store } = app;
  const col = store.collection('asset_links'), assets = store.collection('assets');
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  const guard = opts.blocked || blockedAddr;   // tests that run a web server on 127.0.0.1 pass their own guard; production never does
  const fetchOne = opts.fetch || ((url) => realCheck(url, guard));

  function asset(id) { const a = assets.get(String(id || '')); if (!a || CLOSED[a.status]) throw bad('asset not found', 404); return a; }
  function get(assetId) {
    const a = asset(assetId), r = col.get(a.id) || {};
    return { asset_id: a.id, name: a.name || a.id, links: r.links || [], checked: r.checked || {}, kinds: KINDS };
  }
  function put(assetId, body, who) {
    const a = asset(assetId);
    const list = Array.isArray(body && body.links) ? body.links : null;
    if (!list) throw bad('links must be a list');
    if (list.length > MAX) throw bad(`at most ${MAX} web addresses per asset`);
    const cur = col.get(a.id) || { id: a.id, links: [] }, at = new Date(now()).toISOString();
    const byUrl = new Map((cur.links || []).map((l) => [l.url, l]));
    const seen = new Set(), links = [];
    for (const it of list) {
      const url = normUrl(it && it.url);
      if (seen.has(url)) continue; seen.add(url);
      const kind = KINDS[s(it.kind, 10)] ? s(it.kind, 10) : 'other';
      const prev = byUrl.get(url);
      links.push({ id: prev ? prev.id : 'ln_' + crypto.randomBytes(4).toString('hex'), label: s(it.label, 80) || new URL(url).hostname, url, kind,
        added_by: prev ? prev.added_by : who.user, added_at: prev ? prev.added_at : at });
    }
    const checked = {}; for (const l of links) if (cur.checked && cur.checked[l.url]) checked[l.url] = cur.checked[l.url];
    col.put({ id: a.id, links, checked, updated_by: who.user, updated_at: at });
    const before = new Set((cur.links || []).map((l) => l.url));
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'asset.links', target: a.id, detail: { added: links.filter((l) => !before.has(l.url)).map((l) => l.url), removed: [...before].filter((u) => !seen.has(u)) } });
    return get(a.id);
  }
  async function check(assetId, who) {
    const a = asset(assetId), r = col.get(a.id);
    if (!r || !(r.links || []).length) return get(a.id);
    const out = {};
    await Promise.all(r.links.map(async (l) => { try { out[l.url] = Object.assign({ at: new Date(now()).toISOString() }, await fetchOne(l.url)); } catch (e) { out[l.url] = { at: new Date(now()).toISOString(), ok: false, error: s(e.message, 200) }; } }));
    col.patch(a.id, (x) => { x.checked = out; return x; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'asset.links.check', target: a.id, detail: { checked: Object.keys(out).length, failing: Object.values(out).filter((c) => !c.ok).length } });
    return get(a.id);
  }
  function all() { const m = {}; for (const r of col.all()) if ((r.links || []).length) m[r.id] = r.links; return { assets: m, kinds: KINDS }; }
  return { get, put, check, all, normUrl, KINDS };
}

// one GET, no redirect following, 6 s; the certificate is read even when it is not trusted (and reported as such)
function realCheck(url, blocked = blockedAddr) {
  return new Promise((resolve) => {
    const u = new URL(url), mod = u.protocol === 'https:' ? require('node:https') : require('node:http'), t0 = Date.now();
    const lit = u.hostname.replace(/^\[|\]$/g, '');
    if (require('node:net').isIP(lit) && blocked(lit)) return resolve({ ok: false, error: 'refused: ' + lit + ' is this server, link-local or cloud metadata' });   // an IP literal skips lookup()
    // the server itself, link-local and cloud-metadata addresses are never fetched (SSRF): the name is resolved here and the
    // connection goes to that same address, so a DNS answer cannot change between the check and the request
    const lookup = (host, o, cb) => require('node:dns').lookup(host, { all: true }, (err, addrs) => {
      if (err) return cb(err);
      const bad = (addrs || []).find((a) => blocked(a.address));
      if (bad) return cb(Object.assign(new Error('refused: ' + host + ' resolves to ' + bad.address + ' (this server, link-local or cloud metadata)'), { code: 'EBLOCKED' }));
      const a = addrs[0]; if (o && o.all) return cb(null, addrs); cb(null, a.address, a.family);
    });
    const req = mod.request(u, { method: 'GET', timeout: 6000, rejectUnauthorized: false, lookup, headers: { 'User-Agent': 'sentra-itam-link-check', Accept: '*/*' } }, (res) => {
      const out = { ok: res.statusCode < 400 || res.statusCode === 401 || res.statusCode === 403, status: res.statusCode, ms: Date.now() - t0 };
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) out.redirect = String(res.headers.location).slice(0, 300);
      const sock = res.socket;
      if (sock && typeof sock.getPeerCertificate === 'function') {
        const c = sock.getPeerCertificate();
        if (c && c.valid_to) {
          const days = Math.floor((Date.parse(c.valid_to) - Date.now()) / 86400000);
          out.tls = { trusted: !!sock.authorized, error: sock.authorized ? null : String(sock.authorizationError || ''), valid_to: new Date(Date.parse(c.valid_to)).toISOString().slice(0, 10), days_left: days, subject: (c.subject && c.subject.CN) || null };
        }
      }
      res.resume(); resolve(out);
    });
    req.on('timeout', () => { req.destroy(Object.assign(new Error('no answer within 6 s'), { code: 'ETIMEDOUT' })); });
    req.on('error', (e) => resolve({ ok: false, error: e.code === 'EBLOCKED' ? e.message : e.code === 'ECONNREFUSED' ? 'connection refused' : e.code === 'ENOTFOUND' ? 'name not found in DNS' : e.code === 'ETIMEDOUT' ? 'no answer within 6 s' : (e.code || e.message), ms: Date.now() - t0 }));
    req.end();
  });
}

function registerAssetLinks(srv, app, opts = {}) {
  const L = createAssetLinks(app, { blocked: opts.blocked });
  (app.addons = app.addons || {}).assetLinks = L;
  srv.route('GET', '/asset-links', (ctx) => { ctx.need('operator'); return L.all(); });
  srv.route('GET', '/asset-links/:id', (ctx) => void ctx.need('viewer') || L.get(ctx.params.id));
  srv.route('POST', '/asset-links/:id/check', async (ctx) => { ctx.need('operator'); return L.check(ctx.params.id, ctx.who); });
  srv.route('POST', '/asset-links/:id', (ctx) => { ctx.need('operator'); return L.put(ctx.params.id, ctx.body || {}, ctx.who); });
  return L;
}

module.exports = { blockedAddr, createAssetLinks, registerAssetLinks, normUrl, KINDS };
