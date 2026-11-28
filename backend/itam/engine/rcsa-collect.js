// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const crypto = require('crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * RCSA risk-owner links (Business Risk -> RCSA Collection). The Risk & Control Self-Assessment round, run WITHOUT a login for every
 * department. The Risk function opens a campaign; each risk owner gets a signed link scoped to their own register risks; they open it,
 * re-assess, and submit. A submission is a PROPOSAL - it NEVER changes the register by itself. A Risk officer reviews each proposal
 * and accepts it into the GRC register (engine/grc-registers.js, which keeps its own four-eyes for Class III / IV acceptance) or
 * rejects it with a reason. Everything is audited.
 *
 *   campaign     opened by Risk (approval scope 'risk') for a period with a due date. Owners are taken from the register (the distinct
 *                owners of open risks), each with the risk ids they own. A per-campaign random secret signs the owner links.
 *   link         a stateless HMAC token = base64url({c,o,e}).sig; it carries the campaign, the owner key and an expiry (the due date,
 *                at most 30 days out). No login. A link can be revoked (the owner's issued record carries a revoked flag). The public
 *                routes live under the agent gateway (no portal identity, proxy secret only), so a browser reaches them without a session.
 *                The link is /agent/rcsa/form#t=<token>: the token is in the URL fragment (never logged, never in a Referer).
 *   public       GET  /agent/rcsa/form     the response page (strict CSP; may be opened from another site - a top-level navigation)
 *                GET  /agent/rcsa/view     (X-RCSA-Token) the owner's own risks + the campaign and the brand
 *                POST /agent/rcsa/submit   (X-RCSA-Token) {responses:[{risk, likelihood, impact, controls?, comment?}], note?} -> PENDING
 *                rate-limited per token; refused when the campaign is closed, the link is expired or revoked. Nothing is applied here.
 *   review       Risk lists the pending proposals beside the register's current rating, and ACCEPTS (riskUpdate applies the new rating /
 *                controls to the register) or REJECTS with a reason. Never a service / AI identity. Audited.
 *   RAS / RBC    the same link mechanism carries a department's RAS metric figures and RBC inputs as proposals (kind 'ras' / 'rbc');
 *                a person accepts them into the RAS cockpit / the solvency collection. (This module issues and collects; the accept
 *                step for ras/rbc records the figures for the owning module to read.)
 *   GET  /rcsa                           operator  campaigns, KPIs
 *   POST /rcsa                           risk      {title, period, due, kind?}  open a campaign (owners from the register)   audited
 *   GET  /rcsa/:id                       operator  owners, link + response status
 *   POST /rcsa/:id/link                  risk      {owner}  issue / re-issue an owner link (returns the path)               audited
 *   POST /rcsa/:id/link/:key/revoke      risk      revoke an owner link                                                     audited
 *   POST /rcsa/:id/close                 risk      close the campaign                                                       audited
 *   GET  /rcsa/:id/responses             operator  pending proposals beside the register's current rating
 *   POST /rcsa/responses/:rid/accept     risk      apply the proposal to the register                                      audited
 *   POST /rcsa/responses/:rid/reject     risk      {reason}                                                                 audited
 */
const DAY = 86400000, MAX_EXPIRY_DAYS = 30;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).slice(0, n || 200);
const b64u = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (str) => Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const ownerKey = (name) => crypto.createHash('sha1').update(String(name || '').trim().toLowerCase()).digest('hex').slice(0, 12);

function createRcsaCollect(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const C = () => store.collection('rcsa_campaigns'), R = () => store.collection('rcsa_responses');
  const A = () => app.addons || {};
  const iso = (t) => new Date(t == null ? now() : t).toISOString(), day = (t) => iso(t).slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'rcsa.' + action, target, detail }); };
  const human = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const brand = () => { const bv = (store.collection('pentest_settings').get('report_brand') || {}).values || {}; return { name: bv.org_name || ZYB_ORG.name, logo_url: bv.letterhead || '' }; };
  const rlimit = new Map();   // per-token submit throttle (in memory; a burst does not reach the store)

  function registerRisks() { try { const GR = A().grcRegisters; if (GR && GR.riskList) { const L = GR.riskList(); return (Array.isArray(L) ? L : L.items || []).filter((r) => r.status === 'open'); } } catch (e) { /* GRC register optional */ } return []; }
  function ownersFrom(risks) { const m = new Map(); for (const r of risks) { const o = String(r.owner || '').trim(); if (!o) continue; const k = ownerKey(o); if (!m.has(k)) m.set(k, { key: k, name: o, risks: [] }); m.get(k).risks.push(r.id); } return [...m.values()].sort((a, b) => a.name.localeCompare(b.name)); }

  function sign(camp, payload) { return crypto.createHmac('sha256', camp.secret).update(payload).digest(); }
  function token(camp, key, nonce) { const exp = Math.min(Date.parse(camp.due + 'T23:59:59Z'), now() + MAX_EXPIRY_DAYS * DAY); const p = b64u(JSON.stringify({ c: camp.id, o: key, e: exp, n: nonce })); return p + '.' + b64u(sign(camp, p)); }
  function verify(tok) {
    const t = String(tok || ''); const dot = t.indexOf('.'); if (dot < 1) throw httpErr(400, 'invalid link');
    let p; try { p = JSON.parse(unb64u(t.slice(0, dot)).toString()); } catch (e) { throw httpErr(400, 'invalid link'); }
    const camp = C().get(String(p.c || '')); if (!camp) throw httpErr(404, 'this link is not valid');
    const expect = b64u(sign(camp, t.slice(0, dot))), got = t.slice(dot + 1);
    const a = Buffer.from(expect), b = Buffer.from(got); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw httpErr(403, 'this link is not valid');
    if (camp.status !== 'open') throw httpErr(409, 'this assessment is closed');
    if (!p.e || now() > p.e) throw httpErr(410, 'this link has expired - ask the Risk team for a new one');
    const own = (camp.owners || []).find((o) => o.key === p.o); if (!own) throw httpErr(404, 'this link is not valid');
    if (own.revoked) throw httpErr(403, 'this link was revoked - ask the Risk team for a new one');
    // every issue rotates the owner's nonce: only the newest link carries it, so a revoked or superseded link never works again
    const nb = Buffer.from(String(p.n || '')), ob = Buffer.from(String(own.nonce || ''));
    if (!own.nonce || !p.n || nb.length !== ob.length || !crypto.timingSafeEqual(nb, ob)) throw httpErr(403, 'this link was revoked or replaced - ask the Risk team for a new one');
    return { camp, own };
  }

  // ---- Risk function (authenticated) --------------------------------------------------------------------------------
  function open(src, who) {
    human(who, 'opens an RCSA campaign');
    const b = body(src || {}).str('title', { required: true, min: 4, max: 160 }).str('period', { required: true, max: 20 }).date('due', { required: true }).oneOf('kind', ['rcsa', 'ras', 'rbc'], { def: 'rcsa' }).done();
    if (Date.parse(b.due + 'T00:00:00Z') < now()) throw httpErr(400, 'the due date is in the past');
    const owners = ownersFrom(registerRisks());
    if (b.kind === 'rcsa' && !owners.length) throw httpErr(409, 'no open register risk has an owner yet - set owners in the GRC register first');
    const rec = Object.assign({ id: 'RC-' + day().slice(0, 7).replace('-', '') + '-' + crypto.randomBytes(2).toString('hex'), status: 'open', secret: crypto.randomBytes(32).toString('hex'), owners: owners.map((o) => Object.assign({}, o, { revoked: false, issued_at: null })), by: who.user, created_at: iso() }, b);
    C().put(rec); audit(who, 'open', rec.id, { kind: rec.kind, period: rec.period, owners: owners.length }); return detail(rec.id, who);
  }
  function issueLink(id0, src, who) {
    human(who, 'issues a link'); const camp = C().get(param(id0, 'id')); if (!camp) throw httpErr(404, 'campaign not found'); if (camp.status !== 'open') throw httpErr(409, 'the campaign is closed');
    const b = body(src || {}).str('owner', { required: true, max: 120 }).done(); const key = ownerKey(b.owner);
    let own = (camp.owners || []).find((o) => o.key === key);
    if (!own) { own = { key, name: b.owner.trim(), risks: [], revoked: false, issued_at: null }; camp.owners.push(own); }   // an owner added by hand (e.g. for RAS / RBC)
    own.revoked = false; own.nonce = crypto.randomBytes(8).toString('hex'); own.issued_at = iso(); C().put(camp); const tok = token(camp, key, own.nonce);
    audit(who, 'link', camp.id + ':' + key, { owner: own.name }); return { owner: own.name, key, path: '/agent/rcsa/form#t=' + tok, token: tok, expires: iso(Math.min(Date.parse(camp.due + 'T23:59:59Z'), now() + MAX_EXPIRY_DAYS * DAY)) };
  }
  function revoke(id0, key0, who) { human(who, 'revokes a link'); const camp = C().get(param(id0, 'id')); if (!camp) throw httpErr(404, 'campaign not found'); const key = param(key0, 'key'); const own = (camp.owners || []).find((o) => o.key === key); if (!own) throw httpErr(404, 'owner not found');
    own.revoked = true; delete own.nonce; C().put(camp); audit(who, 'revoke', camp.id + ':' + key, { owner: own.name }); return detail(camp.id, who); }
  function close(id0, who) { human(who, 'closes a campaign'); const camp = C().get(param(id0, 'id')); if (!camp) throw httpErr(404, 'campaign not found'); C().put(Object.assign({}, camp, { status: 'closed', closed_by: who.user, closed_at: iso() })); audit(who, 'close', camp.id, {}); return detail(camp.id, who); }

  function respSummary(campId) { const L = R().all((x) => x.campaign === campId); return { total: L.length, pending: L.filter((x) => x.status === 'pending').length, accepted: L.filter((x) => x.status === 'accepted').length, rejected: L.filter((x) => x.status === 'rejected').length }; }
  function detail(id0, who) {
    const camp = C().get(param(id0, 'id')); if (!camp) throw httpErr(404, 'campaign not found');
    const resp = R().all((x) => x.campaign === camp.id);
    const owners = (camp.owners || []).map((o) => { const mine = resp.filter((x) => x.owner === o.key); return { key: o.key, name: o.name, risks: o.risks.length, revoked: !!o.revoked, issued: !!o.issued_at, responded: mine.length, pending: mine.filter((x) => x.status === 'pending').length }; });
    return { id: camp.id, title: camp.title, period: camp.period, kind: camp.kind, due: camp.due, status: camp.status, by: camp.by, created_at: camp.created_at, owners, responses: respSummary(camp.id),
      note: 'Each owner link is scoped to that owner\'s own register risks and carries an expiry. A submitted response is a proposal; a Risk officer accepts it into the register - the link never changes the register by itself.' };
  }
  function view(who) {
    const camps = C().all().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    const rows = camps.map((c) => Object.assign({ id: c.id, title: c.title, period: c.period, kind: c.kind, due: c.due, status: c.status, owners: (c.owners || []).length }, respSummary(c.id)));
    const kpis = { campaigns: rows.length, open: rows.filter((r) => r.status === 'open').length, pending: rows.reduce((a, r) => a + r.pending, 0), owners: rows.reduce((a, r) => a + r.owners, 0) };
    return { generated_at: iso(), campaigns: rows, kpis, note: 'RCSA without a login: every risk owner gets a scoped, expiring link; their responses arrive as proposals a Risk officer accepts into the register.' };
  }
  function responses(id0, who) {
    const camp = C().get(param(id0, 'id')); if (!camp) throw httpErr(404, 'campaign not found');
    const reg = new Map(registerRisks().map((r) => [r.id, r]));
    const L = R().all((x) => x.campaign === camp.id).sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1) || String(b.submitted_at).localeCompare(String(a.submitted_at)));
    return { campaign: { id: camp.id, title: camp.title, kind: camp.kind, status: camp.status }, items: L.map((x) => { const r = reg.get(x.risk) || null;
      return { id: x.id, owner_name: x.owner_name, risk: x.risk, new_risk: !!x.new_risk, title: x.title || (r ? r.title || r.description || r.id : x.risk), status: x.status, submitted_at: x.submitted_at, proposed: x.proposed,
        current: r ? { likelihood: r.likelihood, impact: r.impact, residual_likelihood: r.residual_likelihood, residual_impact: r.residual_impact, residual: r.residual, band: r.residual_band || r.inherent_band } : null, reason: x.reason || null, decided_by: x.decided_by || null }; }) };
  }
  function accept(rid0, who) {
    human(who, 'accepts a response'); const rid = param(rid0, 'rid'), x = R().get(rid); if (!x) throw httpErr(404, 'response not found'); if (x.status !== 'pending') throw httpErr(409, 'already ' + x.status);
    const camp = C().get(x.campaign) || {};
    if ((camp.kind || 'rcsa') === 'rcsa' && !x.new_risk) { const GR = A().grcRegisters; if (!GR || !GR.riskUpdate) throw httpErr(424, 'the GRC register is not installed');
      const p = x.proposed || {}, patch = {}; for (const k of ['likelihood', 'impact', 'residual_likelihood', 'residual_impact']) if (p[k] != null) patch[k] = p[k];
      if (Array.isArray(p.controls) && p.controls.length) patch.controls = p.controls;   // the comment stays on the response, never forced onto the register
      if (!Object.keys(patch).length) throw httpErr(400, 'the response has nothing to apply');
      try { GR.riskUpdate(x.risk, patch, { user: who.user, role: who.role, ip: who.ip }); } catch (e) { throw httpErr(e.status || 400, 'could not apply to the register: ' + s(e.message, 160)); } }
    R().put(Object.assign({}, x, { status: 'accepted', decided_by: who.user, decided_at: iso() })); audit(who, 'accept', x.campaign + ':' + x.id, { risk: x.risk, owner: x.owner_name }); return responses(x.campaign, who);
  }
  function reject(rid0, src, who) { human(who, 'rejects a response'); const rid = param(rid0, 'rid'), x = R().get(rid); if (!x) throw httpErr(404, 'response not found'); if (x.status !== 'pending') throw httpErr(409, 'already ' + x.status);
    const b = body(src || {}).str('reason', { required: true, min: 3, max: 500 }).done(); R().put(Object.assign({}, x, { status: 'rejected', decided_by: who.user, decided_at: iso(), reason: b.reason })); audit(who, 'reject', x.campaign + ':' + x.id, { risk: x.risk }); return responses(x.campaign, who); }

  // ---- public (agent gateway: no login, proxy secret only) ----------------------------------------------------------
  function publicView(tok) {
    const { camp, own } = verify(tok); const reg = new Map(registerRisks().map((r) => [r.id, r]));
    const mine = R().all((x) => x.campaign === camp.id && x.owner === own.key);
    const risks = own.risks.map((id) => { const r = reg.get(id); const done = mine.find((m) => m.risk === id && m.status !== 'rejected');
      return r ? { id, title: r.title || r.description || r.id, category: r.category || '', current_likelihood: r.likelihood, current_impact: r.impact, residual_likelihood: r.residual_likelihood, residual_impact: r.residual_impact, submitted: !!done } : null; }).filter(Boolean);
    return { campaign: { title: camp.title, period: camp.period, due: camp.due, kind: camp.kind }, owner: own.name, brand: brand(), risks,
      note: 'Please re-assess the likelihood and impact (1-5) of each risk you own and add any new control. Your responses are reviewed by the Risk team before anything changes.' };
  }
  function publicSubmit(tok, src, ip) {
    const { camp, own } = verify(tok);
    const sig = String(tok).slice(String(tok).indexOf('.') + 1), nowt = now();
    const hits = (rlimit.get(sig) || []).filter((t) => nowt - t < 3600000); if (hits.length >= 30) throw httpErr(429, 'too many submissions - please wait a while'); hits.push(nowt); rlimit.set(sig, hits);
    const b = body(src || {}).str('note', { max: 1000 }).done();
    const list = (src && src.responses); if (!Array.isArray(list) || !list.length) throw httpErr(400, 'responses: submit at least one re-assessment');
    if (list.length > 200) throw httpErr(400, 'too many responses in one submission');
    const owned = new Set(own.risks), out = [];
    for (const item of list) {
      const r = body(item || {}).str('risk', { required: true, max: 40 }).int('likelihood', { required: true, min: 1, max: 5 }).int('impact', { required: true, min: 1, max: 5 })
        .int('residual_likelihood', { min: 1, max: 5 }).int('residual_impact', { min: 1, max: 5 }).list('controls', { max: 20, item: 'str', itemMax: 200 }).str('comment', { max: 1000 }).done();
      if (!owned.has(r.risk)) throw httpErr(403, 'risk ' + s(r.risk, 40) + ' is not assigned to you');
      // replace a previous pending response for the same risk from this owner (re-submit)
      for (const prev of R().all((x) => x.campaign === camp.id && x.owner === own.key && x.risk === r.risk && x.status === 'pending')) { if (R().remove) R().remove(prev.id); }
      const rec = { id: 'RR-' + crypto.randomBytes(5).toString('hex'), campaign: camp.id, owner: own.key, owner_name: own.name, risk: r.risk, new_risk: false,
        proposed: { likelihood: r.likelihood, impact: r.impact, residual_likelihood: r.residual_likelihood == null ? null : r.residual_likelihood, residual_impact: r.residual_impact == null ? null : r.residual_impact, controls: r.controls || [], comment: r.comment || '' },
        note: b.note || '', status: 'pending', submitted_at: iso(), ip: s(ip, 64) };
      R().put(rec); out.push(rec.id);
    }
    if (app.audit) app.audit({ by: 'rcsa-link:' + own.name, role: '', ip: s(ip, 64), action: 'rcsa.submit', target: camp.id + ':' + own.key, detail: { responses: out.length } });
    return { ok: true, received: out.length, note: 'Thank you. The Risk team will review your re-assessment.' };
  }
  return { view, open, detail, issueLink, revoke, close, responses, accept, reject, publicView, publicSubmit, verify, _token: token, ownerKey };
}

function registerRcsaCollect(srv, app, X0) {
  const X = X0 && X0.view ? X0 : createRcsaCollect(app, X0 || {});
  app.addons = app.addons || {}; app.addons.rcsaCollect = X;
  const who = (ctx) => Object.assign({ ip: ctx.ip }, ctx.who);
  srv.route('GET', '/rcsa', (ctx) => { ctx.need('operator'); return X.view(who(ctx)); });
  srv.route('POST', '/rcsa', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return X.open(ctx.body, who(ctx)); }, { maxBody: 4096 });
  srv.route('GET', '/rcsa/:id/responses', (ctx) => { ctx.need('operator'); return X.responses(ctx.params.id, who(ctx)); });
  srv.route('GET', '/rcsa/:id', (ctx) => { ctx.need('operator'); return X.detail(ctx.params.id, who(ctx)); });
  srv.route('POST', '/rcsa/:id/link', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return X.issueLink(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 1024 });
  srv.route('POST', '/rcsa/:id/link/:key/revoke', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return X.revoke(ctx.params.id, ctx.params.key, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/rcsa/:id/close', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return X.close(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/rcsa/responses/:rid/accept', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return X.accept(ctx.params.rid, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/rcsa/responses/:rid/reject', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return X.reject(ctx.params.rid, ctx.body, who(ctx)); }, { maxBody: 1024 });
  // public, token-gated, NO portal identity (agent gateway): the risk owner's link. The page is the only route a browser may open
  // from another site (navigable: a top-level GET navigation, e.g. from Outlook Web); the token travels in X-RCSA-Token.
  const F = require('./rcsa-form'), tokOf = (ctx) => String((ctx.headers && ctx.headers['x-rcsa-token']) || '').trim().slice(0, 1024);
  srv.route('GET', '/rcsa/form', (ctx) => ctx.raw(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': F.CSP, 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' }, F.html), { agent: true, navigable: true });
  srv.route('GET', '/rcsa/form.js', (ctx) => ctx.raw(200, { 'Content-Type': 'application/javascript; charset=utf-8' }, F.js), { agent: true });
  srv.route('GET', '/rcsa/view', (ctx) => X.publicView(tokOf(ctx)), { agent: true });
  srv.route('POST', '/rcsa/submit', (ctx) => X.publicSubmit(tokOf(ctx), ctx.body, ctx.ip), { agent: true, maxBody: 65536 });
  return X;
}
module.exports = { createRcsaCollect, registerRcsaCollect };
