// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Renewals & Expiry (IT Assets -> Renewals & Expiry, {P} = /api/itam). One calendar of everything that expires, read from the module
 * that owns it - nothing is copied in by hand:
 *   licence           licences (expiry, cost)                    support contract   Support Contracts (end, cost, verified)
 *   certificate       the certificate scans (not after)          domain / hosting   Domains & Hosting (registry expiry, renews)
 *   app secret        non-human identities (secret / credential expiry, and the rotation due date from the NHI policy)
 *   warranty / support  asset warranty and support end dates    Cisco Smart Net    Cisco coverage by serial
 * Tracking per item (operators, a person, audited): owner, in progress, renewed (new date, cost, reference), not renewing (reason).
 * "Renewed" is a CLAIM until the owning module shows a date later than the old expiry - then VERIFIED; it is never marked verified
 * by the claim alone.
 * Machine learning (from this platform only, counts shown):
 *   lead time   per kind, the median days BEFORE expiry that renewals were verified (>= 3); default per kind until then
 *   risk 0-100  itemised: days left against the learned lead time, already expired, no owner, auto-renew off / unknown, critical
 *               kind (certificate, domain, app secret), an earlier renewal of the same kind that was late
 *   price       a renewal cost >= 20 % above the item's previous cost is flagged
 *   storms      weeks with >= 5 expiries (a week the team will be overloaded), and a 12-month cost forecast from known costs
 *   GET  /expiry                     viewer   (costs: operator and up)
 *   POST /expiry/track               operator {key, action: owner|in_progress|renewed|not_renewing, owner?, new_expiry?, cost?, reference?, note?}
 */
const DAY = 86400000;
const KINDS = { licence: 'Licence', support: 'Support contract', certificate: 'Certificate', domain: 'Domain', hosting: 'Hosting', secret: 'App secret / credential', warranty: 'Warranty', asset_support: 'Asset support', cisco: 'Cisco Smart Net' };
const LEAD_DEFAULT = { licence: 60, support: 60, certificate: 30, domain: 30, hosting: 30, secret: 14, warranty: 60, asset_support: 60, cisco: 60 };
const CRITICAL = { certificate: 1, domain: 1, secret: 1 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const d10 = (v) => { if (v == null || v === '') return null; if (typeof v === 'number') return new Date(v).toISOString().slice(0, 10); const t = Date.parse(String(v).length <= 10 ? v + 'T00:00:00Z' : v); return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : null; };
const ms = (d) => Date.parse(d + 'T00:00:00Z');
const median = (a) => { const x = a.slice().sort((p, q) => p - q), m = x.length >> 1; return x.length ? (x.length % 2 ? x[m] : (x[m - 1] + x[m]) / 2) : null; };
const r2 = (n) => Math.round(n * 100) / 100;

function createExpiryHub(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const TR = () => store.collection('expiry_tracking');
  const C = (n) => store.collection(n);
  async function collect() {
    const out = [], errs = {}, A = (o) => { if (o.expires) out.push(o); };
    const safe = async (k, fn) => { try { await fn(); } catch (e) { errs[k] = e.message; } };
    await safe('licence', () => { for (const l of C('licences').all((x) => x.status !== 'inactive')) A({ kind: 'licence', id: l.id, name: l.product, expires: d10(l.expiry), cost: l.cost == null ? null : l.cost, owner: l.owner || null, source: 'Software & Licences', href: 'software-studio.html' }); });
    await safe('support', () => { for (const c of C('support_contracts').all((x) => x.status !== 'retired')) A({ kind: 'support', id: c.id, name: [c.vendor, c.product, c.contract_number].filter(Boolean).join(' · '), expires: d10(c.end), cost: c.cost == null ? null : c.cost, owner: c.owner || null, verified_source: !!c.verified, source: 'Support Contracts', href: 'support-contracts.html' }); });
    await safe('certificate', () => { const eps = Object.fromEntries(C('cert_endpoints').all((x) => !x.retired).map((e) => [e.id, e]));
      for (const sc of C('cert_scans').all()) { const e = eps[sc.id], s = sc.scan || {}; if (!e || !s.ok) continue; A({ kind: 'certificate', id: sc.id, name: (s.subject || e.host || sc.id) + (e.host ? ' @ ' + e.host + (e.port ? ':' + e.port : '') : ''), expires: d10(s.not_after_iso || s.not_after), cost: null, owner: e.owner || null, auto_renew: e.acme ? true : null, source: 'Certificates', href: 'certificates.html' }); } });
    await safe('domain', () => { for (const d of C('dom_domains').all((x) => x.status !== 'retired')) A({ kind: 'domain', id: d.id, name: d.name, expires: d10(d.expires), cost: d.cost == null ? null : d.cost, owner: d.owner || null, auto_renew: d.auto_renew === undefined ? null : !!d.auto_renew, source: 'Domains & Hosting', href: 'domains.html' });
      for (const h of C('ren_hosting').all((x) => x.status !== 'retired')) A({ kind: 'hosting', id: h.id, name: [h.provider, h.service].filter(Boolean).join(' · '), expires: d10(h.renews), cost: h.cost == null ? null : h.cost, owner: h.owner || null, auto_renew: h.auto_renew === undefined ? null : !!h.auto_renew, source: 'Domains & Hosting', href: 'domains.html' }); });
    await safe('secret', async () => { const N = app.addons && app.addons.nhi; if (!N || typeof N.view !== 'function') return; const v = await N.view(); const P = v.policy || {};
      for (const it of v.items || []) {
        const exp = d10(it.expires), rot = it.secret_age_days != null && (P.secret_max_days || P.rotation_days) ? d10(now() + ((it.privileged ? P.privileged_rotation_days || P.rotation_days : P.rotation_days || P.secret_max_days) - it.secret_age_days) * DAY) : null;
        if (exp) A({ kind: 'secret', id: it.id, name: (it.kind_name || 'identity') + ' ' + it.name + ' - secret expires', expires: exp, cost: null, owner: it.owner || null, source: 'Non-human identities', href: 'nhi.html' });
        else if (rot) A({ kind: 'secret', id: it.id + ':rotate', name: (it.kind_name || 'identity') + ' ' + it.name + ' - rotation due', expires: rot, cost: null, owner: it.owner || null, rotation: true, source: 'Non-human identities (policy)', href: 'nhi.html' });
      } });
    await safe('asset', () => { for (const a of C('assets').all((x) => !['retired', 'disposed', 'lost'].includes(x.status))) {
      if (a.warranty && a.warranty.end) A({ kind: 'warranty', id: a.id, name: (a.name || a.id) + ' warranty' + (a.warranty.provider ? ' (' + a.warranty.provider + ')' : ''), expires: d10(a.warranty.end), cost: null, owner: a.owner || a.custodian || null, source: 'Asset register', href: 'asset-studio.html' });
      if (a.support && a.support.end) A({ kind: 'asset_support', id: a.id, name: (a.name || a.id) + ' support' + (a.support.provider ? ' (' + a.support.provider + ')' : ''), expires: d10(a.support.end), cost: null, owner: a.owner || null, verified_source: !!a.support.verified, source: 'Asset register', href: 'asset-autofill.html' }); } });
    await safe('cisco', () => { for (const c of C('cisco_coverage').all()) { const end = d10(c.end || (c.api && c.api.end)); if (end) A({ kind: 'cisco', id: c.id, name: 'Smart Net ' + (c.contract || '') + ' serial ' + c.id, expires: end, cost: null, owner: null, source: 'Cisco support', href: 'cisco-update.html' }); } });
    return { items: out, errors: errs };
  }

  async function view(role) {
    const priv = ['operator', 'admin'].includes(role), T = now(), today = new Date(T).toISOString().slice(0, 10);
    const { items, errors } = await collect(), trk = Object.fromEntries(TR().all().map((t) => [t.id, t]));
    // renewals verified by the source moving its date past the claimed old expiry
    const leadHist = {}, lateHist = {};
    for (const t of Object.values(trk)) if (t.renewed && t.verified_at && t.old_expiry) { const lead = Math.round((ms(t.old_expiry) - Date.parse(t.renewed.at)) / DAY); (leadHist[t.kind] = leadHist[t.kind] || []).push(lead); if (lead < 0) lateHist[t.kind] = (lateHist[t.kind] || 0) + 1; }
    const lead = {}; for (const k of Object.keys(KINDS)) { const h = leadHist[k] || []; lead[k] = { days: h.length >= 3 ? Math.round(median(h)) : LEAD_DEFAULT[k], learned: h.length >= 3, n: h.length, late: lateHist[k] || 0 }; }
    const list = items.map((it) => {
      const key = it.kind + ':' + it.id, t = trk[key] || null, days = Math.round((ms(it.expires) - ms(today)) / DAY), L = lead[it.kind];
      let state = days < 0 ? 'expired' : days <= L.days ? 'due' : days <= L.days * 3 ? 'upcoming' : 'later';
      let verified = false;
      if (t && t.renewed && t.old_expiry && it.expires > t.old_expiry) { verified = true; state = 'renewed'; if (!t.verified_at) { t.verified_at = new Date(T).toISOString(); t.new_seen = it.expires; TR().put(t); app.audit && app.audit({ by: 'system:expiry', role: 'system', ip: '', action: 'expiry.verified', target: key, detail: { from: t.old_expiry, to: it.expires } }); } }
      else if (t && t.renewed && !verified) state = 'claimed';
      if (t && t.not_renewing) state = 'not renewing';
      const why = [], add = (p, w) => { why.push({ points: p, why: w }); return p; };
      let risk = 0;
      if (!['renewed', 'not renewing'].includes(state)) {
        if (days < 0) risk += add(50, 'expired ' + -days + ' day(s) ago');
        else if (days <= L.days) risk += add(Math.round(40 * (1 - days / Math.max(1, L.days)) + 10), days + ' days left, inside the ' + L.days + '-day lead time' + (L.learned ? ' learned from ' + L.n + ' renewals' : ' (default)'));
        if (!(t && t.owner) && !it.owner) risk += add(15, 'no owner');
        if (it.auto_renew === false) risk += add(10, 'auto-renew off'); else if (it.auto_renew == null && ['domain', 'hosting', 'licence', 'support'].includes(it.kind)) risk += add(5, 'auto-renew not recorded');
        if (CRITICAL[it.kind] && days <= L.days) risk += add(15, KINDS[it.kind].toLowerCase() + ' - an outage when it lapses');
        if (L.late) risk += add(Math.min(10, L.late * 5), L.late + ' earlier ' + KINDS[it.kind].toLowerCase() + ' renewal(s) were late');
        if (t && t.in_progress && risk > 0) { add(-10, 'renewal in progress'); risk -= 10; }
      }
      risk = Math.max(0, Math.min(100, risk));
      const o = { key, kind: it.kind, kind_label: KINDS[it.kind], name: it.name, expires: it.expires, days_left: days, state, risk, why, owner: (t && t.owner) || it.owner || null, auto_renew: it.auto_renew == null ? null : it.auto_renew,
        source: it.source, href: it.href, rotation: !!it.rotation, tracking: t ? { owner: t.owner || null, in_progress: t.in_progress || null, renewed: t.renewed || null, not_renewing: t.not_renewing || null, verified_at: t.verified_at || null } : null };
      if (priv) { o.cost = it.cost; if (t && t.renewed && t.renewed.cost != null && it.cost) { const ch = Math.round((t.renewed.cost / it.cost - 1) * 100); o.price_change_pct = ch; if (ch >= 20) o.why.push({ points: 0, why: 'renewal price ' + ch + ' % above the previous ' + it.cost }); } }
      return o;
    }).sort((a, b) => b.risk - a.risk || a.days_left - b.days_left);
    // storms + cost forecast
    const weeks = {}; for (const x of list) if (x.days_left >= 0 && x.days_left <= 365 && !['renewed', 'not renewing'].includes(x.state)) { const w = new Date(ms(x.expires) - ((new Date(ms(x.expires)).getUTCDay() + 6) % 7) * DAY).toISOString().slice(0, 10); (weeks[w] = weeks[w] || []).push(x.key); }
    const storms = Object.entries(weeks).filter(([, v]) => v.length >= 5).map(([w, v]) => ({ week_of: w, count: v.length })).sort((a, b) => a.week_of.localeCompare(b.week_of));
    const months = []; for (let i = 0; i < 12; i++) { const d = new Date(T); d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() + i); const m = d.toISOString().slice(0, 7); const its = list.filter((x) => x.expires.slice(0, 7) === m && x.state !== 'not renewing');
      months.push({ month: m, count: its.length, by_kind: its.reduce((r, x) => { r[x.kind] = (r[x.kind] || 0) + 1; return r; }, {}), cost: priv ? r2(its.reduce((n, x) => n + (x.cost || 0), 0)) : undefined, unpriced: its.filter((x) => x.cost == null).length }); }
    const by = (f) => list.filter(f).length;
    return { at: new Date(T).toISOString(), costs_visible: priv,
      kpis: { items: list.length, expired: by((x) => x.state === 'expired'), due: by((x) => x.state === 'due'), d30: by((x) => x.days_left >= 0 && x.days_left <= 30 && !['renewed', 'not renewing'].includes(x.state)), d90: by((x) => x.days_left >= 0 && x.days_left <= 90 && !['renewed', 'not renewing'].includes(x.state)),
        no_owner: by((x) => !x.owner && x.days_left <= 90), claimed: by((x) => x.state === 'claimed'), high_risk: by((x) => x.risk >= 60), cost_90: priv ? r2(list.filter((x) => x.days_left >= 0 && x.days_left <= 90).reduce((n, x) => n + (x.cost || 0), 0)) : undefined },
      by_kind: Object.keys(KINDS).map((k) => ({ kind: k, label: KINDS[k], count: by((x) => x.kind === k), due: by((x) => x.kind === k && ['due', 'expired'].includes(x.state)), lead_days: lead[k].days, lead_learned: lead[k].learned, lead_n: lead[k].n })).filter((k) => k.count),
      lead_times: lead, items: list, storms, months, errors,
      note: 'Read from the modules that own each date. "Renewed" stays a claim until that module shows the new date. Lead times are learned from renewals verified here (at least 3 per kind), otherwise a default per kind.' };
  }

  async function track(input, who) {
    if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot record renewals: a person does');
    const b = body(input).str('key', { required: true, max: 300 }).oneOf('action', ['owner', 'in_progress', 'renewed', 'not_renewing', 'clear'], { required: true })
      .str('owner', { max: 120 }).date('new_expiry').num('cost', { min: 0, max: 1e11 }).str('reference', { max: 200 }).str('note', { max: 500 }).done();
    const v = await view(who.role), it = v.items.find((x) => x.key === b.key); if (!it) throw httpErr(404, 'no item ' + b.key + ' in the calendar');
    const at = new Date(now()).toISOString(), t = TR().get(b.key) || { id: b.key, kind: it.kind, history: [] };
    if (b.action === 'owner') { if (!b.owner) throw httpErr(400, 'owner: who renews it'); t.owner = b.owner; }
    if (b.action === 'in_progress') t.in_progress = { by: who.user, at, note: b.note || null };
    if (b.action === 'renewed') {
      if (!b.reference) throw httpErr(400, 'reference: the order, invoice or registrar reference');
      if (b.new_expiry && b.new_expiry <= it.expires) throw httpErr(400, 'new_expiry must be later than the current expiry ' + it.expires);
      t.renewed = { by: who.user, at, new_expiry: b.new_expiry || null, cost: b.cost == null ? null : b.cost, reference: b.reference, note: b.note || null }; t.old_expiry = it.expires; t.verified_at = null; t.not_renewing = null;
    }
    if (b.action === 'not_renewing') { if (!b.note) throw httpErr(400, 'note: why it is not renewed (decommissioned, replaced ...)'); t.not_renewing = { by: who.user, at, note: b.note }; }
    if (b.action === 'clear') { t.in_progress = null; t.renewed = null; t.not_renewing = null; t.old_expiry = null; t.verified_at = null; }
    t.history = (t.history || []).concat([{ at, by: who.user, action: b.action, note: b.note || null }]).slice(-50);
    TR().put(t);
    app.audit && app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'expiry.' + b.action, target: b.key, detail: { owner: b.owner, new_expiry: b.new_expiry, cost: b.cost, reference: b.reference, note: b.note } });
    return { key: b.key, tracking: t };
  }
  return { view, track, collect };
}

function registerExpiryHub(srv, app, H) {
  srv.route('GET', '/expiry', (ctx) => { ctx.need('viewer'); return H.view(ctx.who && ctx.who.role); });
  srv.route('POST', '/expiry/track', (ctx) => { ctx.need('operator'); return H.track(ctx.body, Object.assign({ ip: ctx.ip }, ctx.who)); });
}

module.exports = { createExpiryHub, registerExpiryHub, KINDS, LEAD_DEFAULT };
