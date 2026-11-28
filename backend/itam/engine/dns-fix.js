// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const https = require('node:https');
const { body, param } = require('./check');
/*
 * DNS fixes for mail ({P} = /api/itam) - the SPF record changes the Email Route Map finds (an outbound IP not authorised, an old IP
 * still listed) made at the DNS host through its API, with four-eyes approval. Nothing is changed without a named person approving.
 *   provider   Cloudflare DNS API, with an API token an administrator saves (sealed; never returned, logged or shown). Create it in
 *              Cloudflare as "Edit zone DNS" limited to the mail domains' zones - nothing broader is needed.
 *   propose    operator (a person): {domain, add[], remove[], reason}. The platform reads the domain's TXT records from Cloudflare,
 *              requires exactly one v=spf1 record, and writes the proposed record: ip4 entries added before the "all" (or redirect)
 *              term, ip4 entries removed. ip4 adds no DNS lookup, so the 10-lookup limit cannot be broken by this; the record must
 *              stay within 255 characters (one TXT string). The before / after text is kept on the proposal.
 *   approve    administrator, a person, never the one who proposed it. The record is read again: if it changed since the proposal
 *              the change is refused (409) - never overwrite someone else's edit. Then written and read back to verify.
 *   reject     administrator, with a reason.   undo   a new proposal that restores the "before" text - it goes through approval too.
 * Every step is audited (who, role, IP, domain, before / after). Spamhaus PBL removal has no API: the route map gives the steps.
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DOMAIN = /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const IP4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const unq = (s) => String(s || '').replace(/^"|"$/g, '').replace(/"\s+"/g, '');

function createDnsFix(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, warn() {} };
  const col = () => store.collection('dns_fix'), cfg = () => store.collection('dns_fix_cfg');
  const dc = (app.config && app.config.discovery) || {};
  let S0 = null; const sealer = () => S0 || (S0 = opts.sealer || require('./discovery/vault').createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-dns-cloudflare' }));
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const human = (who, what) => { if (!who || !who.user || /^(system|service|svc|ai)[:-]/i.test(who.user)) throw httpErr(403, 'a person ' + what + ' - service and AI identities cannot'); };
  function token() { const c = cfg().get('cloudflare'); if (!c || !c.enc) throw httpErr(424, 'Cloudflare is not connected - an administrator saves an API token (Edit zone DNS) on the Email Route Map'); return sealer().unseal('cloudflare', c.enc); }
  // Cloudflare API: injected in tests; never logs the token
  function cf(method, path, data) {
    if (opts.cf) return opts.cf(method, path, data, token());
    const tk = token();
    return new Promise((ok, bad) => {
      const b = data ? JSON.stringify(data) : null;
      const r = https.request({ host: 'api.cloudflare.com', path: '/client/v4' + path, method, timeout: 20000, headers: Object.assign({ Authorization: 'Bearer ' + tk, Accept: 'application/json' }, b ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) } : {}) }, (res) => {
        let buf = ''; res.on('data', (c) => { buf += c; if (buf.length > 4e6) r.destroy(new Error('answer too large')); });
        res.on('end', () => { let j = null; try { j = JSON.parse(buf); } catch (e) { j = null; /* not JSON: reported below with the status */ }
          if (!j) return bad(httpErr(502, 'Cloudflare ' + method + ' ' + path.split('?')[0] + ': HTTP ' + res.statusCode + ' (not JSON)'));
          if (!j.success) return bad(httpErr(res.statusCode === 403 || res.statusCode === 401 ? 424 : 502, 'Cloudflare: ' + ((j.errors || []).map((e) => e.message).join('; ') || 'HTTP ' + res.statusCode).slice(0, 300)));
          ok(j); });
      });
      r.on('timeout', () => r.destroy(new Error('timeout'))); r.on('error', (e) => bad(httpErr(502, 'Cloudflare not reachable: ' + e.message)));
      if (b) r.write(b); r.end();
    });
  }
  async function readSpf(domain) {
    const z = await cf('GET', '/zones?name=' + encodeURIComponent(domain.split('.').slice(-2).join('.')));
    let zone = (z.result || [])[0];
    if (!zone) { const z2 = await cf('GET', '/zones?name=' + encodeURIComponent(domain)); zone = (z2.result || [])[0]; }
    if (!zone) throw httpErr(424, domain + ' is not a zone this Cloudflare token can see - check the token covers it, or the domain is hosted elsewhere');
    const r = await cf('GET', '/zones/' + zone.id + '/dns_records?type=TXT&name=' + encodeURIComponent(domain) + '&per_page=100');
    const spf = (r.result || []).filter((x) => /^v=spf1(\s|$)/i.test(unq(x.content)));
    if (!spf.length) throw httpErr(409, domain + ' has no SPF record - create it first (one v=spf1 TXT record)');
    if (spf.length > 1) throw httpErr(409, domain + ' has ' + spf.length + ' SPF records - receivers treat that as a permanent error; merge them into one by hand first');
    return { zone_id: zone.id, record_id: spf[0].id, raw: spf[0].content, text: unq(spf[0].content), quoted: /^"/.test(String(spf[0].content)) };
  }
  function rewrite(text, add, remove) {
    let toks = text.trim().split(/\s+/);
    const has = (ip) => toks.some((t) => new RegExp('^[+]?ip4:' + ip.replace(/\./g, '\\.') + '(/32)?$', 'i').test(t));
    const rm = new Set(remove);
    toks = toks.filter((t) => { const m = /^[+]?ip4:([0-9.]+)(\/32)?$/i.exec(t); return !(m && rm.has(m[1])); });
    const at = toks.findIndex((t) => /^[+~?-]?all$/i.test(t) || /^redirect=/i.test(t)), ins = add.filter((ip) => !has(ip)).map((ip) => 'ip4:' + ip);
    if (at < 0) toks.push(...ins); else toks.splice(at, 0, ...ins);
    return toks.join(' ');
  }
  const lookups = (t) => t.split(/\s+/).filter((x) => /^[+~?-]?(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)/i.test(x)).length;
  async function propose(input, who, kind) {
    human(who, 'proposes a DNS change');
    const b = body(input || {}).str('domain', { required: true, max: 253 }).list('add', { item: 'str', itemMax: 15, max: 10, unique: true }).list('remove', { item: 'str', itemMax: 15, max: 10, unique: true })
      .str('reason', { required: true, min: 5, max: 300 }).done();
    const domain = b.domain.toLowerCase(); if (!DOMAIN.test(domain)) throw httpErr(400, 'domain must be a domain name');
    const add = b.add || [], remove = b.remove || [];
    for (const ip of add.concat(remove)) if (!IP4.test(ip)) throw httpErr(400, (add.includes(ip) ? 'add' : 'remove') + ': ' + ip + ' is not an IPv4 address');
    if (!add.length && !remove.length) throw httpErr(400, 'add or remove: name at least one IP');
    if (add.some((ip) => remove.includes(ip))) throw httpErr(400, 'an IP cannot be both added and removed');
    const cur = await readSpf(domain), after = rewrite(cur.text, add, remove);
    if (after === cur.text) throw httpErr(409, 'the SPF record of ' + domain + ' already says that - nothing to change');
    if (after.length > 255) throw httpErr(409, 'the new SPF record would be ' + after.length + ' characters (one TXT string holds 255) - move addresses into an include first');
    if (lookups(after) > 10) throw httpErr(409, 'the new SPF record needs more than 10 DNS lookups');
    if (col().all((x) => x.domain === domain && x.status === 'pending').length) throw httpErr(409, 'a change to ' + domain + ' is already waiting for approval - approve or reject it first');
    const n = col().all().length + 1, id = 'DNS-' + String(n).padStart(4, '0');
    const rec = { id, kind: kind || 'spf', domain, zone_id: cur.zone_id, record_id: cur.record_id, before: cur.text, after, quoted: cur.quoted, add, remove, reason: b.reason, status: 'pending', requested_by: who.user, requested_role: who.role, at: new Date(now()).toISOString() };
    col().put(rec); audit(who, 'dns-fix.propose', id, { domain, add, remove, before: cur.text, after, reason: b.reason });
    return rec;
  }
  async function approve(id0, input, who) {
    human(who, 'approves a DNS change');
    const id = param(id0, 'id'); if (!/^DNS-\d{4,}$/.test(id)) throw httpErr(400, 'id must be a DNS change id (DNS-nnnn)');
    const b = body(input || {}).str('note', { max: 300 }).done();
    const p = col().get(id); if (!p) throw httpErr(404, 'no DNS change ' + id); if (p.status !== 'pending') throw httpErr(409, id + ' is ' + p.status);
    if (String(p.requested_by || '').trim().toLowerCase() === String(who.user || '').trim().toLowerCase()) throw httpErr(403, 'the person who proposed a change cannot approve it (four-eyes)');
    const cur = await readSpf(p.domain);
    if (cur.record_id !== p.record_id || cur.text !== p.before) { p.status = 'stale'; p.stale = { at: new Date(now()).toISOString(), found: cur.text }; col().put(p); audit(who, 'dns-fix.stale', id, { domain: p.domain, expected: p.before, found: cur.text }); throw httpErr(409, 'the SPF record of ' + p.domain + ' changed since this was proposed - nothing was written; propose again'); }
    await cf('PATCH', '/zones/' + p.zone_id + '/dns_records/' + p.record_id, { content: p.quoted ? '"' + p.after + '"' : p.after });
    const back = await readSpf(p.domain), verified = back.text === p.after;
    Object.assign(p, { status: verified ? 'applied' : 'unverified', approved_by: who.user, approved_role: who.role, approved_at: new Date(now()).toISOString(), note: b.note || '', read_back: back.text });
    col().put(p); audit(who, 'dns-fix.apply', id, { domain: p.domain, before: p.before, after: p.after, verified, requested_by: p.requested_by });
    if (!verified) L.warn('dns-fix: read-back differs', { id, domain: p.domain });
    return p;
  }
  function reject(id0, input, who) {
    human(who, 'rejects a DNS change');
    const id = param(id0, 'id'); if (!/^DNS-\d{4,}$/.test(id)) throw httpErr(400, 'id must be a DNS change id (DNS-nnnn)');
    const b = body(input || {}).str('reason', { required: true, min: 3, max: 300 }).done();
    const p = col().get(id); if (!p) throw httpErr(404, 'no DNS change ' + id); if (p.status !== 'pending') throw httpErr(409, id + ' is ' + p.status);
    Object.assign(p, { status: 'rejected', rejected_by: who.user, rejected_at: new Date(now()).toISOString(), reject_reason: b.reason }); col().put(p);
    audit(who, 'dns-fix.reject', id, { domain: p.domain, reason: b.reason }); return p;
  }
  async function undo(id0, input, who) {
    human(who, 'proposes undoing a DNS change');
    const id = param(id0, 'id'); if (!/^DNS-\d{4,}$/.test(id)) throw httpErr(400, 'id must be a DNS change id (DNS-nnnn)');
    const b = body(input || {}).str('reason', { required: true, min: 5, max: 300 }).done();
    const p = col().get(id); if (!p || p.status !== 'applied') throw httpErr(409, 'only an applied change can be undone');
    return propose({ domain: p.domain, add: p.remove, remove: p.add, reason: 'undo ' + id + ': ' + b.reason }, who, 'spf-undo');
  }
  async function saveToken(input, who) {
    human(who, 'connects Cloudflare');
    const b = body(input || {}).str('token', { max: 200 }).bool('clear').done();
    if (b.clear) { cfg().remove('cloudflare'); audit(who, 'dns-fix.token.clear', 'cloudflare', {}); return { connected: false }; }
    if (!b.token || !/^[A-Za-z0-9_-]{30,200}$/.test(b.token)) throw httpErr(400, 'token must be a Cloudflare API token');
    const prev = cfg().get('cloudflare');
    cfg().put({ id: 'cloudflare', enc: sealer().seal('cloudflare', b.token), set_by: who.user, set_at: new Date(now()).toISOString() });
    try { const v = await cf('GET', '/user/tokens/verify'); if (!v.result || v.result.status !== 'active') throw httpErr(424, 'Cloudflare says the token is ' + ((v.result && v.result.status) || 'not active')); }
    catch (e) { if (prev) cfg().put(prev); else cfg().remove('cloudflare'); throw e; }
    audit(who, 'dns-fix.token.set', 'cloudflare', { length: b.token.length });   // never the token itself
    return { connected: true };
  }
  function view() {
    const c = cfg().get('cloudflare');
    return { connected: !!(c && c.enc), set_by: c ? c.set_by : null, set_at: c ? c.set_at : null, changes: col().all().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 100) };
  }
  return { view, propose, approve, reject, undo, saveToken, rewrite };
}

function registerDnsFix(srv, app, D0) {
  const D = D0 || createDnsFix(app);
  app.addons = app.addons || {}; app.addons.dnsFix = D;
  srv.route('GET', '/dns-fix', (ctx) => { ctx.need('viewer'); return D.view(); });   // public DNS text and who decided - no secret
  srv.route('POST', '/dns-fix/spf', (ctx) => { ctx.need('operator'); return D.propose(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/dns-fix/:id/approve', (ctx) => { ctx.need('admin'); return D.approve(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/dns-fix/:id/reject', (ctx) => { ctx.need('admin'); return D.reject(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/dns-fix/:id/undo', (ctx) => { ctx.need('operator'); return D.undo(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/dns-fix/token', (ctx) => { ctx.need('admin'); return D.saveToken(ctx.body, ctx.who); }, { maxBody: 2048 });
  return D;
}

module.exports = { createDnsFix, registerDnsFix };
