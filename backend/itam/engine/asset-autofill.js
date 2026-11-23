// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');
/*
 * Asset Data Autopilot (IT Assets -> Asset Data Autopilot, {P} = /api/itam). For every active asset it works out the record
 * data a person used to type in - serial, MAC, warranty, support, end of life, information classification and CIA - from
 * what the platform already holds, and proposes the missing or disagreeing values with the source and the reason:
 *   serial / MAC      already written by agent, sensor, vCenter and discovery; here: which assets still lack them and why
 *   support           the support contract that covers the asset (Support Contracts) or Cisco's own answer by serial (Cisco
 *                     Support API) - VERIFIED when the vendor confirmed it or a person verified the contract
 *   warranty          start = the purchase date on record (verified); end = start + the warranty term LEARNED from peers of the
 *                     same vendor and type (median of >= 3 assets that carry both dates) - an ESTIMATE with its confidence
 *   end of life       the vendor end-of-support date of the OS / firmware (lifecycle table, VERIFIED) and the hardware life
 *                     LEARNED from this register's own retirements per type (median, >= 3) or the life set in policy,
 *                     from purchase / warranty start / first seen; the earlier one is proposed, with both shown
 *   classification /  ML: the classified peers of the same type and department / type (majority >= 70 % / 80 %) and facts on
 *   CIA               the record (database or directory software -> confidentiality and integrity high; a configuration item
 *                     many others depend on -> availability high); a SUGGESTION, never verified
 * Nothing is written by the analysis. A PERSON accepts (one, a selection, or every verified proposal) - the value is written as
 * that person's edit, which locks it. Optional (admin): auto-fill verified vendor values into EMPTY fields only, daily, as
 * source "autofill" - lowest precedence, so any person or import overrides it; estimates and suggestions are never auto-filled.
 * A dismissed proposal stays dismissed until the proposed value changes.
 *   GET  /asset-autofill                 viewer     coverage per field, proposals, gaps, what was learned
 *   POST /asset-autofill/accept          operator   {keys[]} | {verified: true, fields?[]}   a person          audited
 *   POST /asset-autofill/dismiss         operator   {key, reason}                           a person          audited
 *   PUT  /asset-autofill/settings        admin      {lifespan_years{type: n}, auto_fill_verified, min_peers}  audited
 */
const DAY = 86400000, YEAR = 365.25 * DAY;
const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const FIELDS = ['serial', 'mac', 'warranty', 'support', 'eol', 'classification', 'cia'];
// a name family: the name without its trailing number ('as-nagg-vdi3' -> 'as-nagg-vdi'); too short a stem says nothing
const famKey = (n) => { const k = String(n || '').toLowerCase().trim().replace(/[\s_.-]*\d+$/, ''); return k.length >= 4 && k !== String(n || '').toLowerCase().trim() ? k : null; };
const CLS = ['top_secret', 'secret', 'restricted', 'public'], CIA = ['high', 'medium', 'low'];
// the hardware life the organisation plans with when the register holds too few retirements to learn it (editable by an admin)
const POLICY_YEARS = { server: 5, storage: 5, network: 7, workstation: 5, laptop: 4, printer: 5, phone: 5, ups: 6, mobile: 3, peripheral: 5 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n || 200);
const low = (v) => String(v || '').toLowerCase();
const day = (t) => (t == null ? null : new Date(t).toISOString().slice(0, 10));
const ms = (v) => { if (!v) return null; const t = Date.parse(String(v).length <= 10 ? v + 'T00:00:00Z' : v); return Number.isFinite(t) ? t : null; };
const median = (a) => { const x = a.slice().sort((p, q) => p - q), m = x.length >> 1; return x.length ? (x.length % 2 ? x[m] : (x[m - 1] + x[m]) / 2) : null; };
const addMonths = (d0, n) => { const d = new Date(ms(d0)); const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + n, 1)); t.setUTCDate(Math.min(d.getUTCDate(), new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth() + 1, 0)).getUTCDate())); return t.toISOString().slice(0, 10); };
const same = (a, b) => JSON.stringify(a == null ? null : a) === JSON.stringify(b == null ? null : b);

function createAssetAutofill(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, warn() {}, every() {} };
  const A = () => store.collection('assets'), cfgC = store.collection('autofill_cfg'), disC = store.collection('autofill_dismissed');
  const settings = () => Object.assign({ lifespan_years: Object.assign({}, POLICY_YEARS), auto_fill_verified: false, min_peers: 3 }, cfgC.get('cfg') || {});
  const addon = (k, mk) => { app.addons = app.addons || {}; if (app.addons[k]) return app.addons[k]; try { return (app.addons[k] = mk()); } catch (e) { L.every && L.every('autofill.addon.' + k, 3600000, 'warn', 'asset autofill: ' + k + ' not available', { err: e.message }); return null; } };
  const support = () => addon('supportContracts', () => require('./support-contracts').createSupportContracts(app));
  const cisco = () => (app.addons && app.addons.ciscoSupport) || null;
  const LC = (() => { try { return require('./lifecycle'); } catch (e) { return null; } })();
  const lcRules = () => { try { return LC.compile((((app.config || {}).discovery || {}).lifecycle || {}).rules); } catch (e) { return LC ? LC.RULES : []; } };

  // ---- what the register teaches: hardware life per type (retirements) and warranty term per vendor|type
  function learn(assets, st) {
    const life = {}, term = {};
    for (const a of assets) {
      if (a.status === 'retired' || a.status === 'disposed') {
        const ret = (a.lifecycle || []).filter((e) => /^(retire|retired|dispose|disposed)$/.test(e.event)).map((e) => ms(e.at)).filter(Boolean)[0];
        const st0 = ms(a.purchase && a.purchase.date) || ms(a.warranty && a.warranty.start);
        if (ret && st0 && ret > st0) (life[a.type || 'other'] = life[a.type || 'other'] || []).push((ret - st0) / YEAR);
      }
      const ws = ms(a.warranty && a.warranty.start), we = ms(a.warranty && a.warranty.end);
      if (ws && we && we > ws) { const k = low(a.vendor) + '|' + (a.type || 'other'); (term[k] = term[k] || []).push(Math.round((we - ws) / (YEAR / 12))); }
    }
    const lifespan = {}, terms = {};
    for (const [t, v] of Object.entries(life)) lifespan[t] = { n: v.length, years: v.length >= st.min_peers ? Math.round(median(v) * 10) / 10 : null };
    for (const [k, v] of Object.entries(term)) { const m = median(v); terms[k] = { n: v.length, months: v.length >= st.min_peers ? m : null, agree: v.filter((x) => Math.abs(x - m) <= 3).length }; }
    return { lifespan, terms };
  }

  function propose(a, ctx) {
    const out = [], P = (field, value, source, verified, confidence, why, also) => {
      if (value == null || same(a[field], value)) return;
      const key = a.id + '|' + field, d = ctx.dismissed[key];
      if (d && same(d.value, value)) return;
      out.push(Object.assign({ key, asset_id: a.id, name: a.name || a.asset_tag || a.id, type: a.type, field, current: a[field] == null ? null : a[field], value, source, verified, confidence, why, replaces: !(a[field] == null) }, also || {}));
    };
    // support: a covering support contract, else Cisco's own answer by serial
    let sup = null;
    try { const c = ctx.support && ctx.support.coverage({ asset_id: a.id });
      if (c && c.found) {
        const live = (c.contracts || []).filter((x) => x.state === 'active' || x.state === 'expiring').sort((x, y) => String(y.end || '').localeCompare(String(x.end || '')))[0];
        if (live) sup = { v: { provider: live.vendor || null, contract: live.contract_number || null, level: live.level || null, start: null, end: live.end || null, verified: !!live.verified }, source: 'support contract ' + (live.contract_number || live.id), verified: !!live.verified, why: (live.product || live.vendor || 'contract') + ' covers this asset' + (live.verified ? ' (verified with the vendor)' : ' (contract on record, not verified with the vendor)') };
        else if (c.cisco && c.cisco.device && /covered|expiring/.test(c.cisco.device.status || '')) { const r = c.cisco.device;
          sup = { v: { provider: 'Cisco', contract: r.contract || null, level: r.service_level || null, start: null, end: r.end ? day(ms(r.end)) : null, verified: !!r.validated }, source: 'Cisco Support API', verified: !!r.validated, why: 'Cisco reports serial ' + (r.serial || a.serial) + ' covered' + (r.end ? ' until ' + day(ms(r.end)) : '') }; }
      } } catch (e) { ctx.errors.support = e.message; }
    if (sup) {
      const cur = a.support || {};
      if (!(cur.contract === sup.v.contract && cur.end === sup.v.end && cur.provider === sup.v.provider)) P('support', sup.v, sup.source, sup.verified, sup.verified ? 0.99 : 0.8, sup.why);
    }
    // warranty: the purchase date is the start; the end from the term learned for the vendor and type
    const w = a.warranty || {}, pd = a.purchase && a.purchase.date;
    if (!w.end || !w.start) {
      const start = w.start || (pd ? day(ms(pd)) : null);
      const k = low(a.vendor) + '|' + (a.type || 'other'), t = ctx.learned.terms[k];
      let end = w.end || null, why = [], conf = 0.95, verified = !!start && !!w.end;
      if (!w.start && pd) why.push('start = purchase date ' + day(ms(pd)));
      if (!w.end && start && t && t.months) { end = addMonths(start, t.months); conf = Math.round((t.agree + 1) / (t.n + 2) * 100) / 100; verified = false; why.push('end = start + ' + t.months + ' months, the term on ' + t.agree + ' of ' + t.n + ' ' + (a.vendor || '') + ' ' + (a.type || '') + ' assets'); }
      if (start || end) { const v = { start: start || null, end: end || null, provider: w.provider || a.vendor || null };
        if (why.length) P('warranty', v, !w.end && end ? 'learned warranty term' : 'purchase record', verified || (!!w.end), conf, why.join('; ')); }
    }
    // end of life: vendor OS / firmware end of support, and hardware life learned or from policy
    const cands = [];
    if (LC && (a.os || a.firmware)) { const r = LC.evaluate([a.os, a.firmware].filter(Boolean).join(' '), ctx.rules, now());
      if (r && r.eol) cands.push({ date: r.eol, source: 'vendor lifecycle', verified: true, conf: 0.99, why: r.product + ' end of support ' + r.eol }); }
    const anchor = ms(pd) ? ['purchase', ms(pd)] : ms(w.start) ? ['warranty start', ms(w.start)] : ms(a.first_seen) ? ['first seen', ms(a.first_seen)] : null;
    if (anchor && a.type && a.type !== 'vm' && a.type !== 'software' && a.type !== 'licence') {
      const lr = ctx.learned.lifespan[a.type], yrs = lr && lr.years ? lr.years : ctx.st.lifespan_years[a.type];
      if (yrs) cands.push({ date: day(anchor[1] + yrs * YEAR), source: lr && lr.years ? 'learned hardware life' : 'policy hardware life', verified: false,
        conf: lr && lr.years ? Math.min(0.9, 0.5 + lr.n / 40) : anchor[0] === 'first seen' ? 0.4 : 0.6,
        why: (a.type) + ' life ' + yrs + ' years (' + (lr && lr.years ? 'median of ' + lr.n + ' retirements in this register' : (ZYB_ORG.short + ' policy')) + ') from ' + anchor[0] + ' ' + day(anchor[1]) + (anchor[0] === 'first seen' ? ' - first seen is later than purchase, so this is late' : '') });
    }
    if (cands.length) { cands.sort((x, y) => x.date.localeCompare(y.date)); const c = cands[0];
      const curE = a.eol ? day(ms(a.eol)) : null;
      if (curE !== c.date && !(curE && !c.verified)) P('eol', c.date, c.source, c.verified, c.conf, c.why, { candidates: cands.map((x) => ({ date: x.date, source: x.source, verified: x.verified })) }); }
    // classification + CIA: classified peers, and facts on the record
    if (!CLS.includes(a.classification)) {
      const dep = low(a.department), p1 = dep ? ctx.peers[(a.type || 'other') + '|' + dep] : null, p2 = ctx.peersT[a.type || 'other'];
      const best = (m) => { const e = Object.entries(m || {}), n = e.reduce((x, [, v]) => x + v, 0); if (!n) return null; const [lv, k] = e.sort((x, y) => y[1] - x[1])[0]; return { lv, k, n }; };
      const b1 = best(p1), b2 = best(p2), pick = b1 && b1.n >= 3 && b1.k / b1.n >= 0.7 ? [b1, 'type + department'] : b2 && b2.n >= 5 && b2.k / b2.n >= 0.8 ? [b2, 'type'] : null;
      if (pick) P('classification', pick[0].lv, 'classified peers (' + pick[1] + ')', false, Math.round((pick[0].k + 1) / (pick[0].n + 2) * 100) / 100, pick[0].k + ' of ' + pick[0].n + ' classified ' + (a.type || 'other') + ' assets' + (pick[1] === 'type' ? '' : ' in ' + a.department) + ' are ' + pick[0].lv.replace('_', ' '));
    }
    const sw = (a.software || []).map((x) => low(x && (x.name || x))).join(' | ') + ' ' + low(a.os) + ' ' + (a.tags || []).join(' ').toLowerCase();
    const cia = Object.assign({}, a.cia || {}), why = [];
    if (/\b(oracle database|sql server|postgres|mysql|mariadb|db2)\b/.test(sw)) { if (!cia.c) { cia.c = 'high'; } if (!cia.i) cia.i = 'high'; why.push('runs a database'); }
    if (/active directory|domain controller|\bad ds\b/.test(sw)) { if (!cia.c) cia.c = 'high'; if (!cia.i) cia.i = 'high'; if (!cia.a) cia.a = 'high'; why.push('directory / domain controller'); }
    const dependents = ctx.deps[a.id] || 0; if (dependents >= 5 && !cia.a) { cia.a = 'high'; why.push(dependents + ' configuration items depend on it'); }
    const pc = ctx.peerCia[(a.type || 'other') + '|' + low(a.department)];
    if (pc && pc.n >= 3) for (const k of ['c', 'i', 'a']) if (!cia[k]) { const e = Object.entries(pc[k] || {}).sort((x, y) => y[1] - x[1])[0]; if (e && e[1] / pc.n >= 0.7) { cia[k] = e[0]; why.push(k.toUpperCase() + ' ' + e[0] + ' like ' + e[1] + ' of ' + pc.n + ' peers'); } }
    // availability = the business criticality other modules read (Scanned Assets, VAPT Center, CMDB): when the record has none, the
    // evidence below proposes one; a person accepts it. Strongest first; nothing decides -> no proposal (the asset stays unrated).
    if (!cia.a) {
      const RK = { low: 1, medium: 2, high: 3 }, crit = ctx.depCrit[a.id];
      const nm = low([a.name, a.hostname, (a.tags || []).join(' ')].join(' ')).replace(/[-_.]/g, ' ');
      const fam = ctx.family[(a.type || 'other') + '|' + famKey(a.name)];
      const famBest = fam && fam.n >= 2 ? Object.entries(fam.a).sort((x, y) => y[1] - x[1])[0] : null;
      if (crit) { cia.a = crit.level; why.push('availability ' + crit.level + ': ' + crit.from + ' (' + crit.level + ') depends on it'); }
      else if (famBest && famBest[1] / fam.n >= 0.7) { cia.a = famBest[0]; why.push('availability ' + famBest[0] + ': ' + famBest[1] + ' of ' + fam.n + ' rated assets of the same family (' + famKey(a.name) + '*) are ' + famBest[0]); }
      else if (/\b(fw|firewall|core|dc|domain controller|exchange|mail|backup|vcenter|esxi|nutanix|prism|san|nas|storage|dns|dhcp|radius|nac)\b/.test(nm) || ['network', 'storage'].includes(a.type)) { cia.a = 'high'; why.push('availability high: infrastructure role (' + (a.type === 'network' || a.type === 'storage' ? a.type : 'name') + ')'); }
      else if (/\b(test|dev|uat|lab|sandbox|poc|temp)\b/.test(nm)) { cia.a = 'low'; why.push('availability low: test / development system (name)'); }
      else if (/\b(vdi|desktop|kiosk|pc|laptop|workstation)\b|vdi\d/.test(nm) || ['desktop', 'laptop'].includes(a.type)) { cia.a = 'low'; why.push('availability low: end-user desktop / VDI - one user affected'); }
      else if (a.exposure === 'internet' || (a.tags || []).some((t) => /internet|dmz|public/i.test(t))) { cia.a = 'medium'; why.push('availability medium: internet-facing'); }
      void RK;
    }
    if (why.length && !same(cia, a.cia || {})) P('cia', cia, 'record facts + peers', false, why.some((w) => /depends on it|family/.test(w)) ? 0.8 : 0.6, why.join('; '));
    return out;
  }

  function analyse() {
    const st = settings(), all = A().all(), act = all.filter((a) => !CLOSED[a.status]);
    const learned = learn(all, st), dismissed = {};
    for (const d of disC.all()) dismissed[d.id] = d;
    const peers = {}, peersT = {}, peerCia = {}, deps = {};
    for (const a of act) {
      const k = (a.type || 'other') + '|' + low(a.department);
      if (CLS.includes(a.classification)) { (peers[k] = peers[k] || {})[a.classification] = (peers[k][a.classification] || 0) + 1; (peersT[a.type || 'other'] = peersT[a.type || 'other'] || {})[a.classification] = (peersT[a.type || 'other'][a.classification] || 0) + 1; }
      if (a.cia && (a.cia.c || a.cia.i || a.cia.a)) { const p = peerCia[k] = peerCia[k] || { n: 0, c: {}, i: {}, a: {} }; p.n++; for (const x of ['c', 'i', 'a']) if (a.cia[x]) p[x][a.cia[x]] = (p[x][a.cia[x]] || 0) + 1; }
    }
    try { for (const r of store.collection('relationships').all((x) => x.status !== 'proposed' && x.status !== 'rejected')) { const t = r.to || r.target || r.target_id; if (t) deps[t] = (deps[t] || 0) + 1; } } catch (e) { /* no CMDB yet */ }
    // criticality evidence: the highest-rated asset that depends on each asset (CMDB), and rated assets of the same name family
    const depCrit = {}, family = {}, RKV = { low: 1, medium: 2, high: 3 }, byId = new Map(act.map((x) => [x.id, x]));
    const levelOf = (x) => { const c = low(x && (x.criticality || (x.cia && x.cia.a))); return c === 'critical' ? 'high' : RKV[c] ? c : null; };
    try { for (const r of store.collection('relationships').all((x) => x.status !== 'rejected')) { const from = byId.get(r.from || r.source), to = r.to || r.target || r.target_id; const lv = levelOf(from); if (!lv || !to) continue;
      if (!depCrit[to] || RKV[lv] > RKV[depCrit[to].level]) depCrit[to] = { level: lv, from: from.name || from.id }; } } catch (e) { /* no CMDB relationships collection yet: no dependency evidence */ }
    for (const x of act) { const lv = x.cia && x.cia.a; const k = famKey(x.name); if (!lv || !k) continue; const f = family[(x.type || 'other') + '|' + k] = family[(x.type || 'other') + '|' + k] || { n: 0, a: {} }; f.n++; f.a[lv] = (f.a[lv] || 0) + 1; }
    const ctx = { st, learned, dismissed, peers, peersT, peerCia, deps, depCrit, family, support: support(), rules: lcRules(), errors: {} };
    void cisco;
    const proposals = [], gaps = [], cov = Object.fromEntries(FIELDS.map((f) => [f, { have: 0, proposed: 0 }]));
    for (const a of act) {
      const ps = propose(a, ctx); proposals.push(...ps);
      for (const f of FIELDS) { const v = a[f]; if (v != null && !(f === 'cia' && !(v.c || v.i || v.a))) cov[f].have++; }
      for (const p of ps) if (!p.replaces) cov[p.field].proposed++;
      const seen = (a.sources || []).concat(a.seen_by || []).map(String);
      if (!a.serial && a.type !== 'vm' && a.type !== 'software' && a.type !== 'licence') gaps.push({ asset_id: a.id, name: a.name || a.id, field: 'serial', why: seen.length ? 'no source reports it - ' + seen.join(', ') + ' see the asset but not its serial; install the agent (servers / PCs) or add SNMP / API credentials (devices)' : 'only entered by hand: no agent, discovery or vCenter sees it' });
      if (!a.mac && a.networked !== false && a.type !== 'software' && a.type !== 'licence') gaps.push({ asset_id: a.id, name: a.name || a.id, field: 'mac', why: a.mgmt_ip ? 'IP known but no MAC: run discovery on its subnet (ARP / SNMP) or install the agent' : 'not seen on the network yet' });
    }
    const RANKV = (p) => (p.verified ? 0 : 1);
    proposals.sort((x, y) => RANKV(x) - RANKV(y) || y.confidence - x.confidence || x.name.localeCompare(y.name));
    const n = act.length;
    const coverage = FIELDS.map((f) => ({ field: f, have: cov[f].have, total: n, pct: n ? Math.round(100 * cov[f].have / n) : null, proposed: cov[f].proposed, after_pct: n ? Math.round(100 * Math.min(n, cov[f].have + cov[f].proposed) / n) : null }));
    return { at: new Date(now()).toISOString(), assets: n, coverage, proposals, verified: proposals.filter((p) => p.verified).length, gaps: gaps.slice(0, 500), gap_count: gaps.length,
      learned: { lifespan: Object.entries(learned.lifespan).map(([type, v]) => Object.assign({ type, policy_years: st.lifespan_years[type] || null }, v)),
        warranty_terms: Object.entries(learned.terms).map(([k, v]) => Object.assign({ vendor: k.split('|')[0], type: k.split('|')[1] }, v)).sort((x, y) => y.n - x.n).slice(0, 40) },
      settings: st, errors: ctx.errors,
      note: 'Proposals only: nothing is written until a person accepts. Verified = the vendor or a verified contract says so; estimates are learned from this register and say how many assets they come from.' };
  }

  const person = (who) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot accept asset data: a person does'); };
  function apply(p, who) {
    const a = A().get(p.asset_id); if (!a) return null;
    const patch = { [p.field]: p.value };
    app.assets.edit(a.id, patch, who);
    app.audit && app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'asset.autofill.accept', target: a.id, detail: { field: p.field, from: p.current, to: p.value, source: p.source, verified: p.verified, confidence: p.confidence } });
    return a.id;
  }
  function accept(input, who) {
    person(who);
    const src = input || {}, b = body(src).list('keys', { max: 500, unique: true, item: 'str' }).bool('verified').list('fields', { max: 7, unique: true, item: ['serial', 'mac', 'warranty', 'support', 'eol', 'classification', 'cia'] }).done();
    if (b.fields) for (const f of b.fields) if (!FIELDS.includes(f)) throw httpErr(400, 'fields: ' + f + ' is not one of ' + FIELDS.join(', '));
    if (!b.keys && b.verified !== true) throw httpErr(400, 'give keys[] or verified: true');
    const cur = analyse().proposals;
    const pick = b.keys ? cur.filter((p) => b.keys.includes(p.key)) : cur.filter((p) => p.verified && (!b.fields || b.fields.includes(p.field)));
    if (b.keys) { const gone = b.keys.filter((k) => !cur.some((p) => p.key === k)); if (gone.length === b.keys.length) throw httpErr(409, 'these proposals are no longer current - refresh the page'); }
    const done = []; for (const p of pick) { const id = apply(p, who); if (id) done.push(p.key); }
    L.info('asset autofill accepted', { by: who.user, n: done.length });
    return { accepted: done.length, keys: done };
  }
  function dismiss(input, who) {
    person(who);
    const b = body(input).str('key', { required: true, max: 200 }).str('reason', { required: true, max: 500 }).done();
    const p = analyse().proposals.find((x) => x.key === b.key); if (!p) throw httpErr(404, 'no current proposal ' + b.key);
    disC.put({ id: p.key, value: p.value, reason: b.reason, by: who.user, at: new Date(now()).toISOString() });
    app.audit && app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'asset.autofill.dismiss', target: p.asset_id, detail: { field: p.field, value: p.value, reason: b.reason } });
    return { dismissed: p.key };
  }
  function putSettings(input, who) {
    const src = input || {}, b = body(src).bool('auto_fill_verified').int('min_peers', { min: 2, max: 50 }).done(), st = settings();
    if (src.lifespan_years !== undefined) {
      if (!src.lifespan_years || typeof src.lifespan_years !== 'object' || Array.isArray(src.lifespan_years)) throw httpErr(400, 'lifespan_years must be an object {type: years}');
      const ly = {}; for (const [t, v] of Object.entries(src.lifespan_years)) { if (!POLICY_YEARS[t]) throw httpErr(400, 'lifespan_years: unknown type ' + s(t, 30)); const n = Number(v); if (!Number.isFinite(n) || n < 1 || n > 20) throw httpErr(400, 'lifespan_years.' + t + ' must be 1-20 years'); ly[t] = Math.round(n * 10) / 10; }
      st.lifespan_years = Object.assign({}, st.lifespan_years, ly);
    }
    if (b.auto_fill_verified !== undefined) st.auto_fill_verified = b.auto_fill_verified;
    if (b.min_peers !== undefined) st.min_peers = b.min_peers;
    cfgC.put(Object.assign({ id: 'cfg' }, st, { updated_by: who.user, updated_at: new Date(now()).toISOString() }));
    app.audit && app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'asset.autofill.settings', target: 'autofill', detail: { auto_fill_verified: st.auto_fill_verified, min_peers: st.min_peers, lifespan_years: st.lifespan_years } });
    return settings();
  }
  // admin-enabled: verified vendor values into EMPTY fields only, as source "autofill" (lowest precedence, never locked)
  function autoFill() {
    if (!settings().auto_fill_verified) return 0;
    let n = 0;
    for (const p of analyse().proposals) {
      if (!p.verified || p.replaces || !['support', 'eol', 'warranty'].includes(p.field)) continue;
      const a = A().get(p.asset_id); if (!a || a[p.field] != null) continue;
      a[p.field] = p.value; a.prov = a.prov || {}; a.prov[p.field] = 'autofill'; a.updated_at = new Date(now()).toISOString();
      a.lifecycle = Array.isArray(a.lifecycle) ? a.lifecycle : []; a.lifecycle.push({ event: 'autofilled', at: a.updated_at, by: 'system:asset-autofill', detail: { field: p.field, source: p.source } });
      A().put(a); n++;
      app.audit && app.audit({ by: 'system:asset-autofill', role: 'system', ip: '', action: 'asset.autofill.auto', target: a.id, detail: { field: p.field, to: p.value, source: p.source } });
    }
    if (n) L.info('asset autofill wrote verified values', { n });
    return n;
  }
  let timer = null;
  function start() {
    if (opts.noTimer || timer) return;
    const run = guardOf(app, 'asset.autofill', autoFill);
    const loop = async () => { try { await run(); } finally { timer = setTimeout(loop, 24 * 3600000); if (timer.unref) timer.unref(); } };
    timer = setTimeout(loop, 15 * 60000); if (timer.unref) timer.unref();
  }
  function stop() { if (timer) clearTimeout(timer); timer = null; }
  return { analyse, accept, dismiss, settings, putSettings, autoFill, start, stop };
}

function registerAssetAutofill(srv, app, F) {
  srv.route('GET', '/asset-autofill', (ctx) => { ctx.need('viewer'); return F.analyse(); });
  srv.route('POST', '/asset-autofill/accept', (ctx) => { ctx.need('operator'); return F.accept(ctx.body, Object.assign({ ip: ctx.ip }, ctx.who)); });
  srv.route('POST', '/asset-autofill/dismiss', (ctx) => { ctx.need('operator'); return F.dismiss(ctx.body, Object.assign({ ip: ctx.ip }, ctx.who)); });
  srv.route('PUT', '/asset-autofill/settings', (ctx) => { ctx.need('admin'); return F.putSettings(ctx.body, Object.assign({ ip: ctx.ip }, ctx.who)); });
}

module.exports = { createAssetAutofill, registerAssetAutofill, POLICY_YEARS, FIELDS };
