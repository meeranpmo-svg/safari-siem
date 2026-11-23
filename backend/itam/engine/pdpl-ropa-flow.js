// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { body } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * RoPA workflow automation ({P} = /api/itam, PDPL -> RoPA by department). It drives the existing campaign (engine/pdpl-ropa.js:
 * stewards draft, submit; the DPO reviews four-eyes) instead of replacing it - every write still goes through those rules.
 *   machine learning (pyengine/ropa_flow_rules.py): per department a completion forecast from its own pace against the due date
 *     (on track / at risk / late), per activity a risk score with its reasons and whether a DPIA is required, the same processing
 *     described by two departments, retention far above the register's norm for the same data, and for every system the Data
 *     Catalog found with personal data but no activity yet, the closest template - a PROPOSED draft
 *   automation: proposed drafts accepted in one click by the steward (or an operator) - each becomes an ordinary draft through
 *     the campaign's own putDraft (validation, steward check, audit); reminders e-mailed to the stewards before the due date
 *     (7, 3, 1 days) and every 2 days when late, through the SIEM relay; late departments are handed to Notification &
 *     Escalation (source "pdpl") so its ladder chases them; a department waiting for review over 5 days reminds the DPO
 *   GET  /pdpl/ropa-flow/:campaign                  viewer (scoped like the campaign)  campaign + ML + reminders + settings
 *   POST /pdpl/ropa-flow/:campaign/accept           steward of the department / operator  {department, items:[{system, template?}]}  audited
 *   POST /pdpl/ropa-flow/:campaign/settings         operator  {reminders, before_days[], late_every_days, dpo_email?}            audited
 *   POST /pdpl/ropa-flow/:campaign/remind-now       operator  send the due reminders now                                       audited
 */
const RIYADH = 3 * 3600000, DAY = 86400000;
const EMAIL = /^[^\s@<>"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const low = (v) => String(v || '').trim().toLowerCase();

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createRopaFlow(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, every() {} };
  const PD = () => opts.pdpl || (app.addons && app.addons.pdpl) || null;
  const R = () => { const p = PD(); if (!p || !p.ropaCampaigns) throw httpErr(424, 'RoPA by department is not installed on this server - run the update'); return p.ropaCampaigns; };
  const setC = () => store.collection('pdpl_ropa_flow'), remC = () => store.collection('pdpl_ropa_reminders');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'pdpl.ropa.flow.' + action, target, detail }); };
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const isOp = (who) => who.role === 'operator' || who.role === 'admin';
  const settings = (id) => Object.assign({ reminders: true, before_days: [7, 3, 1], late_every_days: 2, dpo_email: '' }, setC().get(id) || {});

  const sc = ((app.config && app.config.discovery) || {}).siem || {};
  async function relay(b) {
    if (opts.siem) return opts.siem('POST', '/reports/deliver', b, 'system:itam-notify');
    if (!sc.secret_file) return { ok: false, error: 'SIEM link not configured (discovery.siem.secret_file)' };
    let sec; try { sec = String(fs.readFileSync(sc.secret_file, 'utf8')).trim(); if (sec.startsWith('{')) sec = String(JSON.parse(sec).proxy_secret || ''); } catch (e) { return { ok: false, error: 'SIEM secret not readable (' + (e.code || 'error') + ')' }; }
    try {
      const base = String(sc.base_url || 'http://127.0.0.1:9120').replace(/\/+$/, ''), prefix = sc.prefix || '/api/soc';
      const r = await require('./discovery/httpc').request(base + prefix + '/reports/deliver', { method: 'POST', headers: { 'X-Sentra-Proxy-Secret': sec, 'X-Auth-User': 'system:itam-notify', 'X-Auth-Role': 'admin', 'Content-Type': 'application/json' }, body: JSON.stringify(b), timeoutMs: 30000 });
      return r.status === 200 ? { ok: true } : { ok: false, error: (r.json && r.json.error) || 'HTTP ' + r.status };
    } catch (e) { return { ok: false, error: 'SIEM not reachable (' + (e.code || e.message || 'error') + ')' }; }
  }

  /* ---- the facts the ML reads: the campaign view, its audit trail, the register, the Data Catalog, the templates */
  async function facts(id, who) {
    const v = await R().view(id, who);
    const c = store.collection('pdpl_ropa_campaigns').get(id);
    const drafts = [];
    for (const d of v.departments) for (const r of d.drafts) drafts.push(Object.assign({ id: r.id, department: d.department, complete: r.complete, name: r.name }, r.fields || {}));
    const events = [];
    try { for (const a of (app.store.auditTail ? app.store.auditTail(5000) : [])) { const det = a.detail || {}; if (/ropa/.test(a.action || '') && (a.target === id || det.campaign === id) && det.department) events.push({ department: det.department, at: Date.parse(a.at) || a.ts || 0, kind: a.action }); } } catch (e) { /* no audit trail readable: the forecast says it needs activity */ }
    for (const d of drafts) { const r = (v.departments.find((x) => x.department === d.department) || { drafts: [] }).drafts.find((x) => x.id === d.id); const at = r && Date.parse(r.updated_at); if (at) events.push({ department: d.department, at, kind: 'save' }); }
    const records = PD().records('ropa').filter((r) => r.status !== 'archived').map((r) => ({ id: r.id, owner: r.owner, name: r.name, systems: r.systems || [], data_categories: r.data_categories || [], purpose: r.purpose, retention_months: r.retention_months }));
    const catalog = [];
    for (const d of v.departments) for (const x of d.suggest_systems || []) catalog.push({ system: x.system, department: d.department, categories: x.categories || [] });
    let tpl = {}; const keys = {};
    try { const t = await R().templates(); for (const dep of t.departments || []) tpl[dep.key] = (dep.activities || []).map((a) => ({ key: a.key, name: a.name, data_categories: a.data_categories || [], systems_hint: a.systems || [] })); } catch (e) { tpl = {}; /* no templates: drafts are proposed without one */ }
    for (const d of v.departments) keys[d.department] = d.template_key;
    return { v, c, drafts, events, records, catalog, tpl, keys };
  }
  async function flow(id, who) {
    const F = await facts(id, who);
    let ml;
    try { ml = await py().call('ropa.flow', { campaign: F.c, drafts: F.drafts, events: F.events, records: F.records, catalog: F.catalog, templates: F.tpl, dept_keys: F.keys, now: now() }); }
    catch (e) { ml = { ok: false, error: 'the ML rules could not run: ' + s(e.message, 200) }; }
    return { campaign: F.v.campaign, departments: F.v.departments, totals: F.v.totals, fields: F.v.fields, can_manage: F.v.can_manage, me: F.v.me, ml,
      settings: isOp(who) ? settings(id) : undefined, reminders: remC().all((r) => r.campaign === id).sort((a, b) => b.at - a.at).slice(0, 40).map((r) => Object.assign({}, r, { to: isOp(who) ? r.to : undefined })) };
  }

  /* ---- accept proposed drafts: each becomes an ordinary draft through the campaign's own rules */
  async function accept(id, input, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person accepts proposed drafts, not a service or AI identity');
    const b = body(input).str('department', { required: true, max: 120 }).list('items', { required: true, max: 30 }).done();
    const F = await facts(id, who), dep = F.v.departments.find((d) => low(d.department) === low(b.department));
    if (!dep) throw httpErr(404, b.department + ' is not in this campaign (or not yours)');
    let ml; try { ml = await py().call('ropa.flow', { campaign: F.c, drafts: F.drafts, events: [], records: F.records, catalog: F.catalog, templates: F.tpl, dept_keys: F.keys, now: now() }); } catch (e) { throw httpErr(424, 'the ML rules could not run: ' + s(e.message, 200)); }
    const proposed = (ml.autodraft && ml.autodraft[dep.department]) || [];
    const out = [];
    for (const [i, it] of b.items.entries()) {
      const x = body(it && typeof it === 'object' && !Array.isArray(it) ? it : (() => { throw httpErr(400, 'items[' + i + '] must be an object'); })()).str('system', { required: true, max: 200 }).str('template', { max: 80 }).done();
      const p = proposed.find((q) => low(q.system) === low(x.system));
      if (!p) throw httpErr(400, 'items[' + i + ']: "' + s(x.system, 60) + '" is not a proposed system for ' + dep.department);
      const t = (F.tpl[F.keys[dep.department]] || []).find((q) => q.key === (x.template || p.template));
      const draft = { campaign: id, department: dep.department, name: t ? t.name : 'Processing in ' + p.system, data_categories: [...new Set([].concat(p.categories || [], t ? t.data_categories : []))], systems: [p.system], owner: dep.department };
      if (t) draft.template = t.key;
      out.push(await R().putDraft(draft, who));   // the campaign's own validation, steward check and audit
    }
    audit(who, 'accept', id, { department: dep.department, drafts: out.length });
    return { created: out.length, drafts: out.map((d) => ({ id: d.id, name: d.name })) };
  }
  function saveSettings(id, input, who) {
    if (!isOp(who)) throw httpErr(403, 'an operator (the DPO) sets the campaign automation');
    store.collection('pdpl_ropa_campaigns').get(id) || (() => { throw httpErr(404, 'no RoPA campaign ' + id); })();
    const b = body(input).bool('reminders', { def: true }).list('before_days', { max: 5, def: [7, 3, 1] }).int('late_every_days', { min: 1, max: 14, def: 2 }).str('dpo_email', { max: 254 }).done();
    if (b.before_days.some((d) => !Number.isInteger(d) || d < 1 || d > 60)) throw httpErr(400, 'before_days must be whole days from 1 to 60');
    if (b.dpo_email && !EMAIL.test(b.dpo_email)) throw httpErr(400, 'dpo_email must be an e-mail address');
    setC().put(Object.assign({ id }, b, { by: who.user, at: now() })); audit(who, 'settings', id, { reminders: b.reminders, before_days: b.before_days, late_every_days: b.late_every_days });
    return settings(id);
  }

  /* ---- reminders (daily) and late departments for Notification & Escalation */
  const day = (t) => Math.floor((t + RIYADH) / DAY);
  function stewardEmails(dept) {
    const p = PD(); if (!p) return [];
    return p.records('steward').filter((x) => x.status !== 'archived' && low(x.department) === low(dept)).map((x) => ({ user: x.user, email: x.email && EMAIL.test(x.email) ? x.email.toLowerCase() : null }));
  }
  async function remind(id, who) {
    const c = store.collection('pdpl_ropa_campaigns').get(id); if (!c) throw httpErr(404, 'no RoPA campaign ' + id);
    if (c.status !== 'open') return { sent: 0, note: 'the campaign is closed' };
    const st = settings(id), due = Date.parse(c.due + 'T23:59:00Z') - RIYADH, t = now(), left = day(due) - day(t);   // calendar days in Riyadh
    let sent = 0;
    for (const [name, d] of Object.entries(c.departments || {})) {
      const status = d.status || 'not_started', k = id + '|' + low(name);
      let why = null, to = [];
      if (['not_started', 'in_progress', 'returned'].includes(status)) {
        const last = remC().all((r) => r.key === k && r.kind === 'steward').sort((a, b) => b.at - a.at)[0];
        if (left >= 0 && st.before_days.includes(left) && !(last && day(last.at) === day(t))) why = left + ' day(s) to the due date';
        if (left < 0 && (!last || day(t) - day(last.at) >= st.late_every_days)) why = 'past the due date (' + c.due + ')';
        to = stewardEmails(name);
        if (why) {
          const emails = to.map((x) => x.email).filter(Boolean);
          const rec = { id: 'rr-' + t.toString(36) + Math.random().toString(36).slice(2, 5), campaign: id, key: k, department: name, kind: 'steward', at: t, why, to: to.map((x) => x.user), status: 'sent' };
          if (!emails.length) { rec.status = 'failed'; rec.error = to.length ? 'the steward has no e-mail address on the Programme page' : 'no data steward named for ' + name; }
          else { const r = await relay({ id: rec.id, subject: '[PDPL] RoPA for ' + s(name, 80) + ': ' + why, text: 'The Records of Processing Activities of ' + name + ' are ' + (status === 'returned' ? 'returned with comments' : status.replace('_', ' ')) + ' in campaign "' + c.name + '" - ' + why + '.\nOpen PDPL -> RoPA by department to complete and submit it.', recipients: emails }); if (!r.ok) { rec.status = 'failed'; rec.error = s(r.error, 200); } }
          remC().put(rec); if (rec.status === 'sent') sent++;
        }
      }
      if (status === 'submitted' && d.submitted_at && t - Date.parse(d.submitted_at) > 5 * DAY && st.dpo_email) {
        const last = remC().all((r) => r.key === k && r.kind === 'dpo').sort((a, b) => b.at - a.at)[0];
        if (!last || day(t) - day(last.at) >= st.late_every_days) {
          const rec = { id: 'rr-' + t.toString(36) + Math.random().toString(36).slice(2, 5), campaign: id, key: k, department: name, kind: 'dpo', at: t, why: 'submitted over 5 days ago, waiting for review', to: ['DPO'], status: 'sent' };
          const r = await relay({ id: rec.id, subject: '[PDPL] RoPA of ' + s(name, 80) + ' waits for your review', text: name + ' submitted its RoPA in campaign "' + c.name + '" on ' + d.submitted_at.slice(0, 10) + '. Approve or return it with comments (PDPL -> RoPA by department).', recipients: [st.dpo_email] });
          if (!r.ok) { rec.status = 'failed'; rec.error = s(r.error, 200); } remC().put(rec); if (rec.status === 'sent') sent++;
        }
      }
    }
    for (const old of remC().all((r) => r.at < t - 365 * DAY)) remC().remove(old.id);
    if (who) audit(who, 'remind-now', id, { sent });
    return { sent };
  }
  async function tick() {
    const t = now(), h = new Date(t + RIYADH).getUTCHours();
    if (h < 9) return;
    for (const c of store.collection('pdpl_ropa_campaigns').all((x) => x.status === 'open')) { if (settings(c.id).reminders) { try { await remind(c.id, null); } catch (e) { if (L.every) L.every('ropa-flow:remind', 3600000, 'warn', 'RoPA reminders failed', { campaign: c.id, err: s(e.message, 200) }); } } }
  }
  if (!(app.noTimers || opts.noTimer)) { const tm = setInterval(guardOf(app, 'pdpl.ropa.reminders', tick), 60 * 60000); if (tm.unref) tm.unref(); }
  // for Notification & Escalation: a department past the due date and not approved is a condition (clears when approved / closed)
  function signals() {
    const out = [], t = now();
    for (const c of store.collection('pdpl_ropa_campaigns').all((x) => x.status === 'open')) {
      const due = Date.parse(c.due + 'T23:59:00Z') - RIYADH; if (t <= due) continue;
      for (const [name, d] of Object.entries(c.departments || {})) if ((d.status || 'not_started') !== 'approved') out.push({ fp: 'pdpl:ropa:' + c.id + ':' + low(name), source: 'pdpl', title: 'RoPA of ' + name + ' is late (campaign "' + c.name + '", due ' + c.due + ')', text: 'status ' + (d.status || 'not started'), severity: 2, condition: true });
    }
    return out;
  }
  return { flow, accept, saveSettings, remind, tick, signals };
}

function registerRopaFlow(srv, app, F0) {
  const F = F0 && F0.flow ? F0 : createRopaFlow(app, F0 || {});
  app.addons = app.addons || {}; app.addons.ropaFlow = F;
  const CID = (ctx) => { const id = String(ctx.params.campaign || ''); if (!/^[A-Za-z0-9_.:-]{1,60}$/.test(id)) throw httpErr(400, 'campaign has an invalid format'); return id; };
  srv.route('GET', '/pdpl/ropa-flow/:campaign', (ctx) => { ctx.need('viewer'); return F.flow(CID(ctx), ctx.who); });
  srv.route('POST', '/pdpl/ropa-flow/:campaign/accept', (ctx) => { ctx.need('viewer'); return F.accept(CID(ctx), ctx.body, ctx.who); }, { anyRole: 'a data steward (any role) accepts drafts for their own department; putDraft checks the steward', maxBody: 32768 });
  srv.route('POST', '/pdpl/ropa-flow/:campaign/settings', (ctx) => { ctx.need('operator'); return F.saveSettings(CID(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/pdpl/ropa-flow/:campaign/remind-now', (ctx) => { ctx.need('operator'); return F.remind(CID(ctx), ctx.who); });
  return F;
}

module.exports = { createRopaFlow, registerRopaFlow };
