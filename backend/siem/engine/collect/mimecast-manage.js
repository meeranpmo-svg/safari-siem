// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Mimecast management (four-eyes). The log collector (collect/mimecast.js) stays read-only with its own API application;
 * actions use a SEPARATE Mimecast API 2.0 application ("manage" client ID / secret, secrets.json mimecast.manage_*), and
 * only when an administrator switches actions on.
 *   held queue   POST {base}/api/gateway/get-hold-message-list   read: messages held for review (operator view)
 *   actions      a fixed list, built here from validated values - never from free text or a model's wording:
 *     block-sender / permit-sender   POST /api/managedsender/permit-or-block-sender  {sender, to, action}
 *     release-held / reject-held     POST /api/gateway/hold-release | /api/gateway/hold-reject  {id}
 *     block-url                      POST /api/ttp/url/create-managed-url  {url, action:'block', matchType}
 *   PROPOSED by an operator → APPROVED by a different PERSON with the security approver scope → RUN by an operator.
 * Answers: {meta:{status}, data:[…], fail:[{errors:[{message}]}]} - a "fail" entry is the action's failure, said in words.
 *   GET  {P}/cloud/mimecast/held               the held queue                                                    operator
 *   GET  {P}/cloud/mimecast/actions            plans, kinds, whether actions are on                              operator
 *   POST {P}/cloud/mimecast/actions            propose {kind, sender?, to?, id?, url?, match?, reason}           operator
 *   POST {P}/cloud/mimecast/actions/:id/decide {decision, comment}                                    approve:security
 *   POST {P}/cloud/mimecast/actions/:id/run                                                                     operator
 */
const { body, param } = require('../util/check');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const MC = require('./mimecast');
const BRAND = require('../util/brand');

const KINDS = { 'block-sender': 'Block a sender', 'permit-sender': 'Permit a sender', 'release-held': 'Release a held message', 'reject-held': 'Reject a held message', 'block-url': 'Block a URL (URL Protect)' };
const EMAIL = /^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;
const DOMAIN = /^(?:\*\.)?[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}$/;
const HELD = /^[A-Za-z0-9_=+/-]{8,400}$/;

function createManage({ config, state, fetchImpl, now } = {}) {
  const NOW = now || Date.now, doFetch = fetchImpl || fetch, col = state.collection('mimecast_actions');
  const C = () => config.mimecast || {}, S = () => (config.secrets && config.secrets.mimecast) || {};
  let token = '', until = 0;
  function base() { const b = (C().base_url || MC.DEFAULT_BASE).replace(/\/+$/, ''); if (!MC.baseOk(b)) throw new HttpError(409, 'the Mimecast address is not a mimecast.com https address'); return b; }
  async function getToken(force) {
    if (!force && token && NOW() < until) return token;
    const id = S().manage_client_id, sec = S().manage_client_secret;
    if (!id || !sec) throw new HttpError(409, 'no Mimecast management application is stored - an administrator adds its client ID / secret in the Integration Hub');
    let r; try { r = await doFetch(base() + '/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: new URLSearchParams({ client_id: id, client_secret: sec, grant_type: 'client_credentials' }).toString() }); }
    catch (e) { throw new HttpError(502, 'cannot reach Mimecast: ' + ((e.cause && e.cause.code) || e.message)); }
    let j = null; try { j = await r.json(); } catch { j = null; /* an error page instead of JSON: the status says enough */ }
    if (r.status === 400 || r.status === 401 || r.status === 403) throw new HttpError(502, 'Mimecast refused the management client ID / secret (HTTP ' + r.status + ')');
    if (!r.ok || !j || !j.access_token) throw new HttpError(502, 'Mimecast token request failed (HTTP ' + r.status + ')');
    token = String(j.access_token); until = NOW() + Math.max(60, Number(j.expires_in) || 1800) * 1000 - 60000; return token;
  }
  async function post(path, data, retried) {
    const t = await getToken(false);
    let r; try { r = await doFetch(base() + path, { method: 'POST', headers: { Authorization: 'Bearer ' + t, 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ data: [data] }) }); }
    catch (e) { throw new HttpError(502, 'cannot reach Mimecast: ' + ((e.cause && e.cause.code) || e.message)); }
    if (r.status === 401 && !retried) { token = ''; return post(path, data, true); }
    if (r.status === 403) throw new HttpError(502, 'the Mimecast management application lacks the permission for ' + path);
    if (r.status === 429) throw new HttpError(429, 'Mimecast rate limit - try again in a few minutes');
    let j = null; try { j = await r.json(); } catch { j = null; /* reported below by the status */ }
    if (!r.ok || !j) throw new HttpError(502, 'Mimecast ' + path + ' answered HTTP ' + r.status);
    const fail = (j.fail || []).flatMap((f) => (f.errors || []).map((e) => e.message || e.code)).filter(Boolean);
    if (fail.length) throw new HttpError(502, 'Mimecast refused it: ' + fail.slice(0, 3).join('; '));
    return j.data || [];
  }
  async function held() {
    const end = new Date(NOW()), start = new Date(NOW() - 7 * 86400000), iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, '+0000');
    const rows = await post('/api/gateway/get-hold-message-list', { admin: true, start: iso(start), end: iso(end) });
    return rows.slice(0, 500).map((m) => ({ id: String(m.id || ''), received: m.dateReceived || null, from: (m.fromHeader && m.fromHeader.emailAddress) || (m.from && m.from.emailAddress) || '', to: (m.to && m.to.emailAddress) || '',
      subject: String(m.subject || '').slice(0, 200), reason: String(m.reason || m.reasonCode || ''), attachments: !!m.hasAttachments }));
  }
  function nextId() { let max = 0; for (const c of col.all()) { const n = Number(String(c.id).slice(5)); if (n > max) max = n; } return 'MCAC-' + String(max + 1).padStart(6, '0'); }
  function propose(p, by) {
    if (!KINDS[p.kind]) throw new HttpError(400, 'kind: one of ' + Object.keys(KINDS).join(', '));
    const a = { id: nextId(), kind: p.kind, title: KINDS[p.kind], reason: String(p.reason || '').slice(0, 600), status: 'proposed', proposed_by: by, proposed_at: new Date(NOW()).toISOString() };
    if (a.reason.length < 10) throw new HttpError(400, 'reason: say why, in at least 10 characters');
    if (p.kind === 'block-sender' || p.kind === 'permit-sender') {
      const s = String(p.sender || '').toLowerCase(); if (!EMAIL.test(s) && !DOMAIN.test(s)) throw new HttpError(400, 'sender: an e-mail address or a domain');
      const to = String(p.to || '').toLowerCase(); if (!EMAIL.test(to)) throw new HttpError(400, 'to: the internal recipient the rule is for (an address)');
      const dom = String(config.brand_domain || BRAND.domain || '').toLowerCase(); if (p.kind === 'permit-sender' && dom && (s === dom || s.endsWith('@' + dom))) throw new HttpError(400, 'sender: your own domain is never permitted from outside (spoofing)');
      Object.assign(a, { sender: s, to });
    } else if (p.kind === 'release-held' || p.kind === 'reject-held') {
      if (!HELD.test(String(p.id || ''))) throw new HttpError(400, 'id: the held message id from the held queue');
      Object.assign(a, { message_id: p.id, subject: String(p.subject || '').slice(0, 200), from: String(p.from || '').slice(0, 200) });
    } else {
      let u; try { u = new URL(String(p.url || '')); } catch { u = null; /* reported below */ }
      if (!u || !/^https?:$/.test(u.protocol) || !DOMAIN.test(u.hostname)) throw new HttpError(400, 'url: an http(s) address with a host name');
      const match = p.match === 'domain' ? 'domain' : 'explicit';
      Object.assign(a, { url: u.toString().slice(0, 500), match });
    }
    a.history = [{ at: a.proposed_at, by, what: 'proposed' }];
    return col.put(a);
  }
  function must(id) { const c = col.get(id); if (!c) throw new HttpError(404, 'action not found'); return c; }
  function decide(id, decision, by, comment) {
    const c = must(id);
    if (c.status !== 'proposed') throw new HttpError(409, 'only a proposed action is decided (this one is ' + c.status + ')');
    if (String(by).toLowerCase() === String(c.proposed_by).toLowerCase()) throw new HttpError(403, 'four-eyes: the person who proposed an action does not approve it');
    if (decision === 'rejected' && !(comment && comment.trim().length >= 5)) throw new HttpError(400, 'comment: say why it is rejected');
    return col.patch(id, (x) => { x.status = decision; x.decided_by = by; x.decided_at = new Date(NOW()).toISOString(); x.comment = String(comment || '').slice(0, 400); x.history.push({ at: x.decided_at, by, what: decision }); return x; });
  }
  async function run(id, by) {
    const c = must(id);
    if (c.status !== 'approved') throw new HttpError(409, 'an action runs only once approved (this one is ' + c.status + ')');
    if (!C().manage_enabled) throw new HttpError(409, 'Mimecast actions are switched off - an administrator switches them on in the Integration Hub');
    const call = c.kind === 'block-sender' || c.kind === 'permit-sender' ? ['/api/managedsender/permit-or-block-sender', { sender: c.sender, to: c.to, action: c.kind === 'block-sender' ? 'block' : 'permit' }]
      : c.kind === 'release-held' ? ['/api/gateway/hold-release', { id: c.message_id }] : c.kind === 'reject-held' ? ['/api/gateway/hold-reject', { id: c.message_id, reasonType: 'MESSAGE CONTAINS UNDESIRABLE CONTENT', notify: false }]
        : ['/api/ttp/url/create-managed-url', { url: c.url, action: 'block', matchType: c.match, comment: 'approved ' + c.id }];
    try { await post(call[0], call[1]); return col.patch(id, (x) => { x.status = 'done'; x.run_by = by; x.done_at = new Date(NOW()).toISOString(); x.history.push({ at: x.done_at, by, what: 'done in Mimecast' }); return x; }); }
    catch (e) { col.patch(id, (x) => { x.status = 'failed'; x.error = e.message; x.history.push({ at: new Date(NOW()).toISOString(), by, what: 'failed: ' + e.message }); return x; }); throw e; }
  }
  return { held, propose, decide, run, list: () => col.all().sort((a, b) => String(b.id).localeCompare(String(a.id))), KINDS };
}

function register(api, deps) {
  if (!deps.state) throw new Error('mimecast actions need deps.state');
  const P = prefixOf(deps), cfg = deps.config;
  const M = createManage({ config: cfg, state: deps.state, fetchImpl: deps.mimecastFetch, now: deps.now });
  api.route('GET', `${P}/cloud/mimecast/held`, wrap(deps, 'operator', async () => ({ held: await M.held() })));
  api.route('GET', `${P}/cloud/mimecast/actions`, wrap(deps, 'operator', () => ({ actions: M.list(), kinds: M.KINDS, enabled: !!(cfg.mimecast && cfg.mimecast.manage_enabled), app_set: !!(cfg.secrets && cfg.secrets.mimecast && cfg.secrets.mimecast.manage_client_secret) })));
  api.route('POST', `${P}/cloud/mimecast/actions`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx.body).oneOf('kind', Object.keys(KINDS), { required: true }).str('sender', { max: 254 }).str('to', { max: 254 }).str('id', { max: 400 }).str('subject', { max: 200 }).str('from', { max: 200 })
      .str('url', { max: 500 }).oneOf('match', ['explicit', 'domain']).str('reason', { required: true, max: 600 }).done();
    const a = M.propose(b, ctx.user);
    audit(ctx, 'cloud.mimecast.action.propose', a.id, { kind: a.kind, sender: a.sender || null, to: a.to || null, url_host: a.url ? new URL(a.url).hostname : null });
    return a;
  }));
  const id = (ctx) => param(String(ctx.params.id || ''), 'id');
  api.route('POST', `${P}/cloud/mimecast/actions/:id/decide`, wrap(deps, 'approve:security', async (ctx) => {
    const b = body(ctx.body).oneOf('decision', ['approved', 'rejected'], { required: true }).str('comment', { max: 400 }).done();
    const a = M.decide(id(ctx), b.decision, ctx.user, b.comment);
    audit(ctx, 'cloud.mimecast.action.' + (b.decision === 'approved' ? 'approve' : 'reject'), a.id, { kind: a.kind, proposed_by: a.proposed_by });
    return a;
  }));
  api.route('POST', `${P}/cloud/mimecast/actions/:id/run`, wrap(deps, 'operator', async (ctx) => {
    body(ctx.body).done();
    try { const a = await M.run(id(ctx), ctx.user); audit(ctx, 'cloud.mimecast.action.run', a.id, { kind: a.kind, status: a.status }); return a; }
    catch (e) { audit(ctx, 'cloud.mimecast.action.run', String(ctx.params.id), { status: 'failed', error: e.message.slice(0, 200) }); throw e; }
  }));
  return M;
}

module.exports = { register, createManage, KINDS };
