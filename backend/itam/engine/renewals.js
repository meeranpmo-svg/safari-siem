// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * Renewal Autopilot for domains and hosting ({P} = /api/itam, Network -> Domains & DNS). The platform never logs in to a registrar or a
 * hosting provider and never pays: it finds the real dates, opens the renewal in time, runs it through people, and proves it happened.
 *   registry     every domain in the register (engine/domains.js) is read from public RDAP - the registry's own record: expiry,
 *                registration, last change, registrar, status codes (transfer lock), nameservers. GET only, https only, the RDAP server
 *                chosen from IANA's bootstrap file, 8 s timeout, 1 MB cap. A registry that publishes no RDAP (some ccTLDs) is said.
 *                A later registry expiry than the register's = renewed at the registrar: the register date is corrected (audited).
 *   hosting      hosting / DNS / CDN subscriptions (provider, service, renews, term, auto-renew, cost, owner, the hostnames it serves)
 *   tasks        an item inside its lead time opens a renewal task by itself. open -> requested (operator) -> approved (an admin who
 *                did not request it) -> renewed (operator: new expiry, cost, the order / invoice reference) -> verified: a domain is
 *                verified BY THE REGISTRY when RDAP shows the new expiry; hosting (no registry) by a second person with evidence.
 *                A renewed domain whose registry date never moves is flagged. Every step audited, a person only (never AI / service).
 *   learning     lead time from this platform's own completed renewals (90th percentile of open -> renewed, + 14 days) instead of a
 *                fixed 60; the late rate (Beta-smoothed); price change against the last renewal (> 15 % flagged); 12-month cost forecast
 *   risk         one score per item, every point named: days left, no auto-renew, in use (mail / hostnames), transfer lock missing at
 *                the registry, register and registry dates disagree, a task stuck, this platform's late rate
 *   hijack       lock removed, registrar changed, expiry moved earlier - compared with the last RDAP reading
 *   escalation   overdue / at-risk renewals are signals for Notification & Escalation (on-call, ladders)
 *   advisor      the read-only AI renewal advisor (intel kit): it explains and drafts, never moves a task
 *   GET  /renewals                          viewer (costs, owners and people: operator+)
 *   POST /renewals/rdap                     operator  {domain?}   read the registry now
 *   POST /renewals/hosting                  admin     {id?, provider, service, plan?, renews, term_months, auto_renew, cost?, currency?, owner, hosts[]?, notes?}
 *   POST /renewals/hosting/:id/retire       admin     {reason}
 *   POST /renewals/tasks/:id/advance        operator / admin  {to, note, new_expiry?, cost?, evidence?}
 *   POST /renewals/settings                 admin     {lead_days, version}
 *   POST /renewals/ask                      operator  {question}
 */
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { createIntelKit, beta, DAY } = require('./intel-kit');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const same = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
const day = (t) => new Date(t).toISOString().slice(0, 10);
const daysTo = (d, t) => (d ? Math.floor((Date.parse(d) - t) / DAY) : null);
const BOOT = 'https://data.iana.org/rdap/dns.json', MAX_BYTES = 1048576;
const LOCK = /client ?transfer ?prohibited|server ?transfer ?prohibited/i;
const FLOW = { open: ['requested', 'cancelled'], requested: ['approved', 'cancelled'], approved: ['renewed', 'cancelled'], renewed: ['verified', 'cancelled'], verified: [], cancelled: [] };
const DEF = { lead_days: 60 };
const pctl = (a, p) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y); return b[Math.min(b.length - 1, Math.floor(p * (b.length - 1) + 0.5))]; };

// RDAP domain object -> the facts kept
function parseRdap(j) {
  const ev = (a) => ((j.events || []).find((e) => String(e.eventAction).toLowerCase() === a) || {}).eventDate || null;
  const reg = (j.entities || []).find((e) => (e.roles || []).includes('registrar'));
  const fn = reg && Array.isArray(reg.vcardArray) && Array.isArray(reg.vcardArray[1]) ? (reg.vcardArray[1].find((v) => v[0] === 'fn') || [])[3] : null;
  const status = (j.status || []).map((x) => String(x).slice(0, 60));
  return { expires: ev('expiration') ? ev('expiration').slice(0, 10) : null, registered: ev('registration') ? ev('registration').slice(0, 10) : null, last_changed: ev('last changed') ? ev('last changed').slice(0, 10) : null,
    registrar: String(fn || (reg && reg.handle) || '').slice(0, 120) || null, status, locked: status.some((x) => LOCK.test(x)), ns: (j.nameservers || []).map((n) => String(n.ldhName || '').toLowerCase()).filter(Boolean).sort().slice(0, 13) };
}

function createRenewals(app, opts = {}) {
  let K;
  const st = app.store, D = () => st.collection('dom_domains'), HO = () => st.collection('dom_hosts'), CK = () => st.collection('dom_checks');
  const HS = () => st.collection('ren_hosting'), RD = () => st.collection('ren_rdap'), TK = () => st.collection('ren_tasks'), CF = () => st.collection('ren_cfg');
  const now = () => (opts.now ? opts.now() : Date.now()), iso = () => new Date(now()).toISOString();
  const SYS = { user: 'system:renewals', role: 'admin', ip: '' };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'renewals.' + action, target, detail }); };
  const person = (who, what) => { if (!who || !who.user || isService(who.user)) throw httpErr(403, 'a named person ' + what + ' - not a service or AI identity'); };
  const warn = (k, msg, x) => { if (app.log && app.log.every) app.log.every('renewals:' + k, 3600000, 'warn', msg, x); };
  const nextId = () => { let n = TK().all(() => true).length + 1, id; do { id = 'RN-' + String(n++).padStart(4, '0'); } while (TK().get(id)); return id; };
  const hist = (rec, who, what) => { rec.history = (rec.history || []).concat([{ at: iso(), by: who.user, what: String(what).slice(0, 500) }]).slice(-100); };

  /* ---------- RDAP (read-only, https GET) ---------- */
  const doFetch = opts.fetch || (async (url) => {
    const ac = new AbortController(), tm = setTimeout(() => ac.abort(), 8000);
    try {
      const r = await fetch(url, { headers: { accept: 'application/rdap+json, application/json' }, redirect: 'follow', signal: ac.signal });
      const buf = Buffer.from(await r.arrayBuffer()); if (buf.length > MAX_BYTES) throw new Error('answer larger than 1 MB');
      let j = null; try { j = JSON.parse(buf.toString('utf8')); } catch (e) { j = null; /* not JSON: reported by the caller as the status */ }
      return { status: r.status, json: j };
    } finally { clearTimeout(tm); }
  });
  async function bootstrap() {
    const c = CF().get('bootstrap'); if (c && now() - c.at < 7 * DAY && c.services) return c.services;
    const r = await doFetch(BOOT); if (r.status !== 200 || !r.json || !Array.isArray(r.json.services)) throw new Error('IANA RDAP bootstrap not readable (HTTP ' + r.status + ')');
    const services = r.json.services.map((s) => [s[0].map((t) => String(t).toLowerCase()), s[1].filter((u) => /^https:\/\//i.test(u))]).filter((s) => s[1].length);
    CF().put({ id: 'bootstrap', at: now(), services }); return services;
  }
  async function readOne(name) {
    const prev = RD().get(name), at = now();
    let rec;
    try {
      const svc = await bootstrap(), labels = name.split('.'); let base = null;
      for (let i = 1; i < labels.length && !base; i++) { const tld = labels.slice(i).join('.'); const s = svc.find((x) => x[0].includes(tld)); if (s) base = s[1][0]; }
      if (!base) rec = { id: name, at, ok: false, error: 'the .' + labels[labels.length - 1] + ' registry publishes no RDAP service - keep the expiry date in the register by hand', no_rdap: true };
      else {
        const r = await doFetch(base.replace(/\/?$/, '/') + 'domain/' + encodeURIComponent(name));
        if (r.status === 404) rec = { id: name, at, ok: false, error: 'the registry has no record of ' + name + ' - expired, deleted or never registered?', not_found: true };
        else if (r.status !== 200 || !r.json) rec = { id: name, at, ok: false, error: 'RDAP answered HTTP ' + r.status };
        else rec = Object.assign({ id: name, at, ok: true }, parseRdap(r.json));
      }
    } catch (e) { rec = { id: name, at, ok: false, error: String(e.name === 'AbortError' ? 'RDAP did not answer in 8 s' : e.message).slice(0, 200) }; }
    // what changed since the last good reading - the hijack indicators
    const last = prev && prev.ok ? prev : prev && prev.last_good ? prev.last_good : null;
    rec.changes = [];
    if (rec.ok && last) {
      if (last.locked && !rec.locked) rec.changes.push({ level: 'bad', text: 'the transfer lock was removed at the registry' });
      if (last.registrar && rec.registrar && !same(last.registrar, rec.registrar)) rec.changes.push({ level: 'bad', text: 'the registrar changed from ' + last.registrar + ' to ' + rec.registrar });
      if (last.expires && rec.expires && rec.expires < last.expires) rec.changes.push({ level: 'bad', text: 'the registry expiry moved earlier, from ' + last.expires + ' to ' + rec.expires });
      if (last.expires && rec.expires && rec.expires > last.expires) rec.changes.push({ level: 'info', text: 'renewed at the registry: expiry ' + last.expires + ' -> ' + rec.expires });
    }
    if (!rec.ok && last) rec.last_good = last.last_good || last;
    rec.history = ((prev && prev.history) || []).concat(rec.ok ? [{ at, expires: rec.expires, registrar: rec.registrar, locked: rec.locked }] : []).slice(-30);
    RD().put(rec);
    return rec;
  }
  async function refresh(b0, who) {
    const b = body(b0 || {}).str('domain', { max: 253 }).done();
    const doms = D().all((d) => d.status !== 'retired' && (!b.domain || d.name === b.domain.toLowerCase()));
    if (b.domain && !doms.length) throw httpErr(404, 'domain: ' + b.domain + ' is not in the register');
    const out = []; for (const d of doms) out.push(await readOne(d.name));
    sync(who);
    if (who !== SYS) audit(who, 'rdap.read', b.domain || 'all', { domains: out.length, ok: out.filter((x) => x.ok).length });
    return { read: out.length, ok: out.filter((x) => x.ok).length, failed: out.filter((x) => !x.ok).map((x) => ({ domain: x.id, error: x.error })) };
  }

  /* ---------- register <- registry, tasks opened and verified ---------- */
  function items() {
    const L = [];
    for (const d of D().all((x) => x.status !== 'retired')) L.push({ kind: 'domain', id: d.id, name: d.name, expires: d.expires || null, auto_renew: !!d.auto_renew, cost: d.cost == null ? null : d.cost, currency: d.currency || 'SAR', owner: d.owner || '', provider: d.registrar || '', ref: d });
    for (const h of HS().all((x) => x.status !== 'retired')) L.push({ kind: 'hosting', id: h.id, name: h.provider + ' · ' + h.service, expires: h.renews, auto_renew: !!h.auto_renew, cost: h.cost, currency: h.currency || 'SAR', owner: h.owner, provider: h.provider, ref: h });
    return L;
  }
  function leadDays() {
    const S = K.settings(DEF), done = TK().all((t) => t.state === 'verified' && t.renewed_at && t.opened_at).map((t) => Math.max(0, Math.round((Date.parse(t.renewed_at) - Date.parse(t.opened_at)) / DAY)));
    const p90 = done.length >= 3 ? pctl(done, 0.9) : null;
    return { configured: S.lead_days, learned: p90 == null ? null : p90 + 14, used: Math.max(S.lead_days, p90 == null ? 0 : p90 + 14), basis: done.length >= 3 ? done.length + ' completed renewal(s): 90 % took ' + p90 + ' day(s) or less, + 14 days margin' : 'needs 3 completed renewals (' + done.length + ' so far) - the configured lead time is used' };
  }
  function sync(who) {
    const t = now(), lead = leadDays().used, actor = who || SYS;
    // a later registry date than the register's = renewed at the registrar: correct the register (the registry is the source of truth)
    for (const d of D().all((x) => x.status !== 'retired')) {
      const r = RD().get(d.name); if (!r || !r.ok || !r.expires) continue;
      if (!d.expires || r.expires > d.expires) { const old = d.expires; d.expires = r.expires; d.expires_source = 'registry'; d.updated_at = t; D().put(d); audit(SYS, 'expiry.sync', d.id, { domain: d.name, from: old, to: r.expires }); }
      if (!d.registrar && r.registrar) { d.registrar = r.registrar; D().put(d); }
    }
    for (const it of items()) {
      const open = TK().all((x) => x.item === it.kind + ':' + it.id && !['verified', 'cancelled'].includes(x.state))[0], dl = daysTo(it.expires, t);
      // a renewed domain is verified by the registry itself
      if (open && open.state === 'renewed' && it.kind === 'domain') {
        const r = RD().get(it.name);
        if (r && r.ok && r.expires && r.expires > open.due) { open.state = 'verified'; open.verified_at = iso(); open.verified_by = 'registry (RDAP)'; open.verified_expiry = r.expires; hist(open, SYS, 'verified by the registry: expiry is now ' + r.expires); TK().put(open); audit(SYS, 'task.verified', open.id, { by: 'rdap', expires: r.expires }); }
      }
      if (!open && it.expires && dl != null && dl <= lead) {
        const done = TK().all((x) => x.item === it.kind + ':' + it.id && x.state === 'verified' && x.due === it.expires)[0];
        if (done) continue;   // this expiry was already renewed (the register date moves on verification)
        const tk = { id: nextId(), item: it.kind + ':' + it.id, kind: it.kind, name: it.name, due: it.expires, state: 'open', opened_at: iso(), opened_by: actor.user, owner: it.owner, auto_renew: it.auto_renew, last_cost: it.cost, currency: it.currency };
        hist(tk, actor, 'opened by the autopilot: ' + it.name + ' expires ' + it.expires + ' (' + dl + ' day(s), lead time ' + lead + ' days)'); TK().put(tk);
        audit(actor, 'task.open', tk.id, { item: tk.item, due: tk.due, days: dl });
      }
    }
  }

  /* ---------- the people steps ---------- */
  function advance(id, b0, who) {
    person(who, 'moves a renewal'); const tk = TK().get(param(id, 'id')); if (!tk) throw httpErr(404, 'no renewal ' + String(id).slice(0, 40));
    const b = body(b0 || {}).oneOf('to', ['requested', 'approved', 'renewed', 'verified', 'cancelled'], { required: true }).str('note', { required: true, min: 3, max: 1000 }).date('new_expiry').num('cost', { min: 0, max: 100000000 }).str('evidence', { max: 500 }).done();
    if (!FLOW[tk.state].includes(b.to)) throw httpErr(409, 'to: ' + tk.id + ' is ' + tk.state + ' - it can go to ' + (FLOW[tk.state].join(' or ') || 'nothing (finished)'));
    const admin = String(who.role).toLowerCase() === 'admin';
    if ((b.to === 'approved' || b.to === 'cancelled') && !admin) throw httpErr(403, b.to + ' needs an administrator');
    if (b.to === 'approved' && same(who.user, tk.requested_by)) throw httpErr(403, 'four eyes: the renewal is approved by someone other than ' + tk.requested_by + ', who requested it');
    if (b.to === 'renewed') {
      if (!b.new_expiry) throw httpErr(400, 'new_expiry: the expiry date after the renewal is required');
      if (b.new_expiry <= tk.due) throw httpErr(400, 'new_expiry: ' + b.new_expiry + ' is not after the current expiry ' + tk.due);
      if (!b.evidence) throw httpErr(400, 'evidence: the order / invoice reference is required');
      Object.assign(tk, { renewed_at: iso(), renewed_by: who.user, new_expiry: b.new_expiry, cost: b.cost == null ? null : b.cost, evidence: b.evidence });
    }
    if (b.to === 'verified') {
      if (!admin) throw httpErr(403, 'a manual verification needs an administrator');
      if (same(who.user, tk.renewed_by)) throw httpErr(403, 'four eyes: the renewal is verified by someone other than ' + tk.renewed_by + ', who renewed it');
      if (!b.evidence) throw httpErr(400, 'evidence: what you checked (the provider\'s portal, the invoice) is required');
      if (tk.kind === 'domain') { const r = RD().get(tk.name); if (r && r.ok) throw httpErr(409, 'this domain is verified by the registry (RDAP) automatically - the registry still shows ' + (r.expires || 'no expiry') + '; read it again after the registrar updates'); }
      Object.assign(tk, { verified_at: iso(), verified_by: who.user, verified_evidence: b.evidence });
      // the register now carries the new date
      const [k, rid] = tk.item.split(':'), col = k === 'domain' ? D() : HS(), rec = col.get(rid);
      if (rec) { if (k === 'domain') rec.expires = tk.new_expiry; else rec.renews = tk.new_expiry; rec.updated_at = now(); col.put(rec); }
    }
    if (b.to === 'requested') { tk.requested_by = who.user; tk.requested_at = iso(); }
    if (b.to === 'approved') { tk.approved_by = who.user; tk.approved_at = iso(); }
    if (b.to === 'cancelled') { tk.cancelled_by = who.user; tk.cancel_reason = b.note; }
    const from = tk.state; tk.state = b.to; hist(tk, who, from + ' -> ' + b.to + ' - ' + b.note + (b.evidence ? ' (evidence: ' + b.evidence + ')' : '')); TK().put(tk);
    audit(who, 'task.' + b.to, tk.id, { item: tk.item, from, note: b.note.slice(0, 200), new_expiry: b.new_expiry || null, cost: b.cost == null ? null : b.cost });
    return tview(tk, true);
  }
  function putHosting(b0, who) {
    person(who, 'records a hosting subscription');
    const b = body(b0 || {}).str('id', { id: true }).str('provider', { required: true, min: 2, max: 120 }).str('service', { required: true, min: 2, max: 120 }).str('plan', { max: 120 }).date('renews', { required: true })
      .int('term_months', { min: 1, max: 120, def: 12 }).bool('auto_renew').num('cost', { min: 0, max: 100000000 }).str('currency', { max: 8 }).str('owner', { required: true, min: 2, max: 120 }).list('hosts', { max: 50, item: 'str', itemMax: 40, unique: true }).str('notes', { max: 1000 }).done();
    for (const h of b.hosts || []) if (!HO().get(h)) throw httpErr(400, 'hosts: ' + h + ' is not a hostname in the register');
    const prev = b.id ? HS().get(b.id) : null; if (b.id && !prev) throw httpErr(404, 'no hosting subscription ' + b.id);
    const rec = Object.assign({}, prev || { id: 'hs_' + require('node:crypto').randomBytes(5).toString('hex'), created_at: iso(), created_by: who.user, status: 'active' }, b, { currency: b.currency || 'SAR', hosts: b.hosts || [], auto_renew: !!b.auto_renew, updated_at: iso(), updated_by: who.user });
    HS().put(rec); audit(who, prev ? 'hosting.update' : 'hosting.create', rec.id, { provider: rec.provider, service: rec.service, renews: rec.renews }); sync(who);
    return rec;
  }
  function retireHosting(id, b0, who) {
    person(who, 'retires a hosting subscription'); const b = body(b0 || {}).str('reason', { required: true, min: 5, max: 300 }).done();
    const h = HS().get(param(id, 'id')); if (!h) throw httpErr(404, 'no hosting subscription ' + String(id).slice(0, 40));
    h.status = 'retired'; h.retired = { at: iso(), by: who.user, reason: b.reason }; HS().put(h);
    for (const tk of TK().all((x) => x.item === 'hosting:' + h.id && !['verified', 'cancelled'].includes(x.state))) { tk.state = 'cancelled'; tk.cancel_reason = 'subscription retired: ' + b.reason; hist(tk, who, 'cancelled: subscription retired'); TK().put(tk); }
    audit(who, 'hosting.retire', h.id, { reason: b.reason }); return h;
  }

  /* ---------- the view: risk, learning, forecast ---------- */
  function tview(t, named) { const o = Object.assign({}, t); if (!named) { for (const k of ['requested_by', 'approved_by', 'renewed_by', 'verified_by', 'opened_by', 'cancelled_by', 'owner', 'evidence', 'verified_evidence', 'cost', 'last_cost']) delete o[k]; o.history = (t.history || []).map((h) => ({ at: h.at, what: h.what.replace(/\(evidence:[^)]*\)/, '') })); } return o; }
  function view(who) {
    sync(null);
    const t = now(), named = who && ['operator', 'admin'].includes(String(who.role).toLowerCase()), lead = leadDays();
    const T = TK().all(() => true), done = T.filter((x) => x.state === 'verified'), late = done.filter((x) => x.renewed_at && x.renewed_at.slice(0, 10) > x.due).length, lateP = beta(late, done.length);
    const inUse = (d) => { const c = CK().get('d:' + d.id), mx = c && c.records && Array.isArray(c.records.MX) && c.records.MX.length; return { mx: !!mx, hosts: HO().all((h) => h.status !== 'retired' && h.domain_id === d.id).length }; };
    const out = items().map((it) => {
      const dl = daysTo(it.expires, t), why = [], add = (p, txt) => why.push({ points: p, text: txt });
      if (dl == null) add(25, 'no expiry date known'); else if (dl < 0) add(50, 'expired ' + -dl + ' day(s) ago'); else if (dl <= 7) add(40, 'expires in ' + dl + ' day(s)'); else if (dl <= 30) add(30, 'expires in ' + dl + ' days'); else if (dl <= lead.used) add(15, 'inside the ' + lead.used + '-day lead time'); else if (dl <= 120) add(5, 'expires in ' + dl + ' days');
      if (!it.auto_renew) add(10, 'auto-renew is off');
      let rd = null, use = null;
      if (it.kind === 'domain') {
        rd = RD().get(it.name) || null; use = inUse(it.ref);
        if (use.mx) add(15, 'receives e-mail (MX)'); if (use.hosts) add(Math.min(15, use.hosts * 5), use.hosts + ' hostname(s) in the register use it');
        if (rd && rd.ok && !rd.locked) add(15, 'no transfer lock at the registry (clientTransferProhibited) - easier to hijack');
        if (rd && rd.ok && rd.expires && it.expires && rd.expires < it.expires) add(10, 'the register says ' + it.expires + ' but the registry says ' + rd.expires);
        if (rd && (rd.changes || []).some((c) => c.level === 'bad')) add(25, rd.changes.filter((c) => c.level === 'bad').map((c) => c.text).join('; '));
      } else if ((it.ref.hosts || []).length) add(Math.min(15, it.ref.hosts.length * 5), it.ref.hosts.length + ' hostname(s) served');
      const task = T.filter((x) => x.item === it.kind + ':' + it.id && !['verified', 'cancelled'].includes(x.state))[0] || null;
      // a renewal verified in the last 30 days stays on its row, so the proof is seen, not just the absence of a task
      const recent = task ? null : T.filter((x) => x.item === it.kind + ':' + it.id && x.state === 'verified' && t - Date.parse(x.verified_at || 0) < 30 * DAY).sort((a, b) => String(b.verified_at).localeCompare(String(a.verified_at)))[0] || null;
      if (task) { const age = Math.round((t - Date.parse(task.history[task.history.length - 1].at)) / DAY); if (age > 7 && dl != null && dl <= 30) add(10, 'the renewal task has not moved for ' + age + ' days'); }
      if (done.length >= 3 && lateP >= 0.3) add(Math.round(lateP * 10), Math.round(lateP * 100) + ' % of past renewals here were done after the expiry date');
      const prev = done.filter((x) => x.item === it.kind + ':' + it.id && x.cost != null).sort((a, b) => String(b.renewed_at).localeCompare(String(a.renewed_at)))[0];
      const price = prev && it.cost != null && prev.cost ? Math.round((it.cost - prev.cost) / prev.cost * 1000) / 10 : null;
      const score = Math.min(100, why.reduce((s, w) => s + w.points, 0));
      return { kind: it.kind, id: it.id, name: it.name, provider: it.provider, expires: it.expires, days_left: dl, auto_renew: it.auto_renew, cost: named ? it.cost : undefined, currency: it.currency, owner: named ? it.owner : undefined,
        score, level: score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low', why, task: task || recent ? tview(task || recent, named) : null, price_change_pct: named ? price : undefined,
        registry: it.kind === 'domain' ? (rd ? { ok: rd.ok, at: rd.at, expires: rd.expires || null, registrar: rd.registrar || null, locked: rd.ok ? rd.locked : null, status: rd.status || [], error: rd.error || null, changes: rd.changes || [], no_rdap: !!rd.no_rdap } : null) : undefined,
        in_use: use || undefined, hosts: it.kind === 'hosting' ? (it.ref.hosts || []).map((h) => (HO().get(h) || {}).fqdn || h) : undefined, plan: it.kind === 'hosting' ? it.ref.plan || '' : undefined, term_months: it.kind === 'hosting' ? it.ref.term_months : undefined };
    }).sort((a, b) => b.score - a.score || (a.days_left == null ? -1 : a.days_left) - (b.days_left == null ? -1 : b.days_left));
    // 12-month cost forecast by the month each item renews (its recorded cost; unknown costs counted, not guessed)
    const months = Array.from({ length: 12 }, (_, i) => { const d = new Date(t); d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() + i); return d.toISOString().slice(0, 7); });
    const fc = months.map((m) => { const L = out.filter((x) => x.expires && x.expires.slice(0, 7) === m); return { month: m, items: L.length, cost: named ? Math.round(L.reduce((s, x) => s + (x.cost || 0), 0) * 100) / 100 : undefined, unknown_cost: L.filter((x) => x.cost == null).length }; });
    const open = T.filter((x) => !['verified', 'cancelled'].includes(x.state));
    const kpis = { items: out.length, domains: out.filter((x) => x.kind === 'domain').length, hosting: out.filter((x) => x.kind === 'hosting').length, expired: out.filter((x) => x.days_left != null && x.days_left < 0).length,
      due_30: out.filter((x) => x.days_left != null && x.days_left >= 0 && x.days_left <= 30).length, high: out.filter((x) => x.level === 'high').length, open_tasks: open.length,
      awaiting_approval: open.filter((x) => x.state === 'requested').length, unlocked: out.filter((x) => x.registry && x.registry.ok && x.registry.locked === false).length, no_date: out.filter((x) => !x.expires).length,
      verified_12m: done.filter((x) => t - Date.parse(x.verified_at || x.renewed_at || 0) < 365 * DAY).length, late_rate: done.length ? Math.round(lateP * 100) : null };
    const actions = [], A = (p, title, detail, n, filter) => { if (n) actions.push({ priority: p, title, detail, count: n, filter }); };
    A(100, kpis.expired + ' item(s) already expired', 'Renew now - an expired domain stops web and mail and can be registered by someone else; an expired hosting plan takes the site down.', kpis.expired, 'expired');
    A(95, out.filter((x) => x.registry && (x.registry.changes || []).some((c) => c.level === 'bad')).length + ' domain(s) with a registry change that looks like a hijack', 'Lock removed, registrar changed or expiry moved earlier since the last reading: confirm with the registrar today.', out.filter((x) => x.registry && (x.registry.changes || []).some((c) => c.level === 'bad')).length, 'hijack');
    A(90, kpis.due_30 + ' item(s) expire within 30 days', 'Each has a renewal task: request, approve (a second person), renew, and the registry confirms it.', kpis.due_30, 'due');
    A(80, kpis.awaiting_approval + ' renewal(s) waiting for approval', 'An administrator other than the requester approves.', kpis.awaiting_approval, 'approval');
    A(70, open.filter((x) => x.state === 'renewed' && x.kind === 'domain').length + ' domain renewal(s) not yet confirmed by the registry', 'The registrar may still be processing; if the registry date has not moved after a few days, call the registrar.', open.filter((x) => x.state === 'renewed' && x.kind === 'domain').length, 'unverified');
    A(60, kpis.unlocked + ' domain(s) without a transfer lock', 'Ask the registrar to set clientTransferProhibited (registrar lock) - it stops an unauthorised transfer.', kpis.unlocked, 'unlocked');
    A(50, kpis.no_date + ' item(s) with no expiry date', 'Read the registry (domains) or enter the date from the provider (hosting).', kpis.no_date, 'nodate');
    A(40, out.filter((x) => x.price_change_pct != null && x.price_change_pct > 15).length + ' item(s) cost more than 15 % above the last renewal', 'Check the plan and compare providers before approving.', out.filter((x) => x.price_change_pct != null && x.price_change_pct > 15).length, 'price');
    A(30, out.filter((x) => x.kind === 'domain' && x.registry && !x.registry.ok && !x.registry.no_rdap).length + ' domain(s) the registry could not be read for', 'Outbound HTTPS to the RDAP server may be blocked from this server - the dates come from the register until it is read.', out.filter((x) => x.kind === 'domain' && x.registry && !x.registry.ok && !x.registry.no_rdap).length, 'rdap');
    actions.sort((a, b) => b.priority - a.priority);
    if (named) audit(who, 'view', 'renewals', { items: out.length });
    return { generated_at: iso(), named: !!named, settings: K.settings(DEF), lead, kpis, actions, items: out, forecast: fc, hosts: named ? HO().all((h) => h.status !== 'retired').map((h) => ({ id: h.id, fqdn: h.fqdn })) : [],
      tasks: T.sort((a, b) => String(b.opened_at).localeCompare(String(a.opened_at))).slice(0, 200).map((x) => tview(x, named)), ai: K.aiStatus(),
      note: 'The platform never logs in to a registrar or provider and never pays: it reads the registry (RDAP), opens each renewal in time, takes it through a requester and a different approver, and proves it - a domain by the registry\'s new expiry date.' };
  }
  function signals() {
    const v = view(null), out = [];
    for (const x of v.items) {
      if (x.days_left != null && x.days_left < 0) out.push({ fp: 'renewal:expired:' + x.kind + ':' + x.id, source: 'platform', title: x.name + ' has expired', text: 'expired ' + x.expires + ' - renew now (Domains & DNS, Renewals)', severity: 4, condition: true });
      else if (x.days_left != null && x.days_left <= 14 && !(x.task && x.task.state === 'renewed')) out.push({ fp: 'renewal:due:' + x.kind + ':' + x.id, source: 'platform', title: x.name + ' expires in ' + x.days_left + ' day(s)', text: 'renewal ' + (x.task ? x.task.id + ' is ' + x.task.state : 'not started'), severity: x.days_left <= 7 ? 3 : 2, condition: true });
      if (x.registry && (x.registry.changes || []).some((c) => c.level === 'bad')) out.push({ fp: 'renewal:hijack:' + x.id, source: 'platform', title: 'Registry change on ' + x.name, text: x.registry.changes.filter((c) => c.level === 'bad').map((c) => c.text).join('; '), severity: 4, condition: true });
    }
    return out;
  }
  function saveSettings(b0, who) { person(who, 'changes renewal settings'); const b = body(b0 || {}).int('lead_days', { required: true, min: 14, max: 365 }).int('version', { required: true, min: 0 }).done(); return K.saveSettings(DEF, { lead_days: b.lead_days }, b.version, who); }

  // daily: read the registry (every 20 h at most), correct the register, open / verify tasks; rescheduled in finally
  let timer = null;
  const tick = guardOf(app, 'renewals.daily', async () => {
    try { const last = CF().get('last_rdap'); if (!last || now() - last.at > 20 * 3600000) { CF().put({ id: 'last_rdap', at: now() }); await refresh({}, SYS); } else sync(null); }
    catch (e) { warn('tick', 'renewals: the daily round failed', { err: String(e.message).slice(0, 200) }); }
  });
  function start() { if (timer || app.noTimers || opts.noTimer) return; const loop = () => { timer = setTimeout(async () => { try { await tick(); } finally { loop(); } }, 3600000); if (timer.unref) timer.unref(); }; loop(); }

  K = createIntelKit(app, { key: 'renewals', feature: 'itam.renewal-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: true,
    system: ('You are the renewal advisor for ' + ZYB_ORG.short + '\'s internet domains and hosting subscriptions. You see the register, what the registries (RDAP) report, the renewal tasks and their history, the risk scores and the cost forecast. Explain what is at risk and why, what to renew first, how to prevent a lapse or a hijack (registrar lock, auto-renew, valid payment, admin contacts), and draft the message to the registrar or the finance approver. You never move a task, approve, pay or change a register record - people do. Never invent a date or a price: use the tools.'),
    tools: [{ name: 'renewals', description: 'Every domain and hosting item with expiry, days left, auto-renew, the registry reading, the risk score and its reasons, the open task, and the KPIs and actions.', run: async () => { const v = view({ user: 'ai:renewals', role: 'operator' }); return { kpis: v.kpis, lead: v.lead, actions: v.actions, items: v.items.map((x) => ({ kind: x.kind, name: x.name, expires: x.expires, days_left: x.days_left, auto_renew: x.auto_renew, score: x.score, why: x.why.map((w) => w.text), registry: x.registry ? { expires: x.registry.expires, registrar: x.registry.registrar, locked: x.registry.locked, changes: x.registry.changes } : null, task: x.task ? { id: x.task.id, state: x.task.state } : null, cost: x.cost, currency: x.currency })) }; } },
      { name: 'forecast', description: 'Renewal cost per month for the next 12 months (recorded costs; items without a cost counted separately).', run: async () => view({ user: 'ai:renewals', role: 'operator' }).forecast }] });

  return { view, refresh, advance, putHosting, retireHosting, saveSettings, signals, sync, readOne, tick, start, ask: K.ask, aiStatus: K.aiStatus, TOOLS: K.TOOLS };
}

function registerRenewals(srv, app, X) {
  srv.route('GET', '/renewals', (ctx) => { ctx.need('viewer'); return X.view(ctx.who); });
  srv.route('POST', '/renewals/rdap', async (ctx) => { ctx.need('operator'); return X.refresh(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/renewals/hosting', (ctx) => { ctx.need('admin'); return X.putHosting(ctx.body, ctx.who); }, { maxBody: 16384 });
  srv.route('POST', '/renewals/hosting/:id/retire', (ctx) => { ctx.need('admin'); return X.retireHosting(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/renewals/tasks/:id/advance', (ctx) => { ctx.need('operator'); return X.advance(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/renewals/settings', (ctx) => { ctx.need('admin'); return X.saveSettings(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('GET', '/renewals/ai/status', (ctx) => { ctx.need('operator'); return X.aiStatus(); });
  srv.route('POST', '/renewals/ask', (ctx) => { ctx.need('operator'); return X.ask(ctx.body, ctx.who); }, { maxBody: 8192 });
}

module.exports = { createRenewals, registerRenewals, parseRdap };
