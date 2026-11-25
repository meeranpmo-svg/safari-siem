// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const ORG = require('./brand');
/*
 * PDPL across a group of companies ({P} = /api/itam). The organisation runs operations, maintenance and shared services for its
 * group companies: for its own staff and business it is the CONTROLLER; for what it does on a group company's instructions the
 * group company is the controller and this organisation the PROCESSOR (PDPL Art. 8: a controller uses only a processor that
 * gives enough guarantees, under an agreement). This register keeps, per group company:
 *   the company       name, commercial registration, its own DPO / privacy contact, what this organisation does for it
 *   the agreement     the data processing agreement: signed / expires, the terms the DPO checks (instructions, confidentiality,
 *                     security, sub-processors, breach notice and its hours, data-subject help, return / deletion, audit right,
 *                     transfers outside the Kingdom), and its acceptance by the DPO - a DIFFERENT person from who recorded it
 *   the activities    the RoPA activities run for it (ids from the RoPA register, checked)
 *   breach notices    an incident touching its data: detected, the controller told when, within the agreed hours or late
 * Findings: no agreement, expired / expiring in 60 days, a term not covered, not accepted, no contact, no activity, a notice late.
 *   GET  /pdpl/group                               operator  every company with its status and findings (names people: PDPL)
 *   POST /pdpl/group/companies                     operator  DPO / admin  {id?, name, cr_no?, services[], contact, contact_email?}
 *   POST /pdpl/group/companies/:id/remove          operator  DPO / admin
 *   POST /pdpl/group/companies/:id/dpa             operator  DPO / admin  {signed, expires, ref, terms[], breach_hours}
 *   POST /pdpl/group/companies/:id/dpa/accept      operator  the DPO / an admin who did NOT record the agreement
 *   POST /pdpl/group/companies/:id/activities      operator  DPO / admin  {ropa_ids[]}
 *   POST /pdpl/group/notices                       operator  {company, incident_ref, detected, summary}
 *   POST /pdpl/group/notices/:id/notified          operator  {notified_at, how}
 */
const TERMS = {
  instructions: 'Processing only on the group company\'s documented instructions, for the stated purposes',
  confidentiality: 'Staff who process the data are bound to confidentiality',
  security: 'Security measures stated (access control, encryption, logging)',
  subprocessors: 'Sub-processors only with the group company\'s prior approval',
  breach: 'Breach notice to the group company within an agreed number of hours',
  dsr: 'Help answering data-subject requests',
  deletion: 'Return or destruction of the data when the service ends',
  audit: 'The group company may audit or inspect',
  transfer: 'No transfer outside the Kingdom without the group company\'s approval and the PDPL conditions',
};
const SERVICES = ['hr-payroll', 'it-services', 'operations-maintenance', 'facility-management', 'fleet', 'security-services', 'procurement', 'finance', 'other'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DAY = 86400000;

function createPdplGroup(app, PD, opts = {}) {
  const now = opts.now || Date.now, C = (n) => app.store.collection(n), comp = () => C('pdpl_group'), notes = () => C('pdpl_group_notices');
  const iso = () => new Date(now()).toISOString(), today = () => iso().slice(0, 10), low = (x) => String(x || '').toLowerCase();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'pdpl.group.' + action, target, detail }); };
  const dpo = () => ((PD && PD.records('profile')[0]) || {}).dpo_user || '';
  const isDpo = (who) => dpo() && low(dpo()) === low(who.user);
  const needDpo = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); if (!isDpo(who) && who.role !== 'admin') throw httpErr(403, 'the DPO (' + (dpo() || 'not named') + ') or an administrator ' + what); };
  const nextId = (col, pfx) => { let m = 0; for (const x of col.all()) { const n = Number(String(x.id).slice(pfx.length)); if (n > m) m = n; } return pfx + String(m + 1).padStart(4, '0'); };
  const must = (id) => { param(id); const c = comp().get(id); if (!c) throw httpErr(404, 'group company not found'); return c; };

  function assess(c) {
    const f = [], add = (sev, text) => f.push({ severity: sev, text }), d = c.dpa;
    if (!c.contact) add('medium', 'No privacy contact at the group company');
    if (!d) add('high', 'No data processing agreement - this organisation processes the company\'s data without one');
    else {
      if (d.expires && d.expires < today()) add('high', 'The agreement expired on ' + d.expires);
      else if (d.expires && Date.parse(d.expires) - Date.parse(today()) <= 60 * DAY) add('medium', 'The agreement expires on ' + d.expires + ' - renew it');
      const miss = Object.keys(TERMS).filter((k) => !(d.terms || []).includes(k)); if (miss.length) add('medium', miss.length + ' term(s) not covered: ' + miss.map((k) => TERMS[k]).join('; '));
      if (!d.accepted_by) add('medium', 'The agreement is recorded but not accepted by the DPO');
    }
    if (!(c.activities || []).length) add('low', 'No RoPA activity is linked - record what is processed for this company');
    const late = notes().all((n) => n.company === c.id && n.late); if (late.length) add('high', late.length + ' breach notice(s) sent late');
    const open = notes().all((n) => n.company === c.id && !n.notified_at); for (const n of open) { const h = (now() - Date.parse(n.detected)) / 3600000, lim = (d && d.breach_hours) || 72; if (h > lim) add('high', 'Breach ' + n.incident_ref + ': the company not yet told, ' + Math.floor(h) + ' h after detection (agreed ' + lim + ' h)'); }
    const SEV = { high: 3, medium: 2, low: 1 }; f.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
    return { findings: f, status: !d ? 'no agreement' : f.some((x) => x.severity === 'high') ? 'attention' : f.some((x) => x.severity === 'medium') ? 'watch' : 'ok' };
  }
  function view(who) {
    // a group company is under PDPL here; the NCA ECC covers the organisation itself only when framework_scope.nca says so
    const ncaSelfOnly = /only/i.test(String((ORG.framework_scope || {}).nca || ''));
    const list = comp().all().sort((a, b) => a.name.localeCompare(b.name)).map((c) => Object.assign({}, c, assess(c), { frameworks: ncaSelfOnly ? ['pdpl'] : ['pdpl', 'nca'] }));
    const scope = (ORG.framework_scope || {});
    return { org: ORG.name, scope: { nca: scope.nca || '', pdpl: scope.pdpl || '' }, dpo: dpo(), can_manage: isDpo(who) || who.role === 'admin', terms: TERMS, services: SERVICES, companies: list,
      notices: notes().all().sort((a, b) => String(b.detected).localeCompare(String(a.detected))).slice(0, 200),
      kpis: { companies: list.length, no_agreement: list.filter((c) => !c.dpa).length, attention: list.filter((c) => c.status === 'attention').length, ok: list.filter((c) => c.status === 'ok').length, open_notices: notes().all((n) => !n.notified_at).length } };
  }
  function saveCompany(b0, who) {
    needDpo(who, 'records a group company');
    const b = body(b0).str('id', { id: true }).str('name', { required: true, max: 160 }).str('cr_no', { max: 20, re: /^[0-9]{6,20}$/, msg: 'cr_no: the commercial registration number (digits)' }).list('services', { required: true, max: 9, item: SERVICES, unique: true })
      .str('contact', { max: 120 }).str('contact_email', { max: 200, email: true }).str('notes', { max: 600 }).done();
    if (b.id) must(b.id);
    const dup = comp().all((c) => low(c.name) === low(b.name) && c.id !== b.id); if (dup.length) throw httpErr(409, 'name: ' + b.name + ' is already in the register');
    const c = comp().put(Object.assign(b.id ? comp().get(b.id) : { activities: [] }, b, { id: b.id || nextId(comp(), 'GRP-'), updated_by: who.user, updated_at: iso() }));
    audit(who, b.id ? 'company.update' : 'company.add', c.id, { name: c.name, services: c.services }); return c;
  }
  function removeCompany(id, who) { needDpo(who, 'removes a group company'); const c = must(id); comp().remove(id); audit(who, 'company.remove', id, { name: c.name }); return { removed: id }; }
  function saveDpa(id, b0, who) {
    needDpo(who, 'records a data processing agreement');
    must(id); const b = body(b0).date('signed', { required: true }).date('expires').str('ref', { required: true, max: 120 }).list('terms', { max: 9, item: Object.keys(TERMS), unique: true, def: [] }).int('breach_hours', { min: 1, max: 720, def: 72 }).done();
    if (b.signed > today()) throw httpErr(400, 'signed: not in the future');
    if (b.expires && b.expires <= b.signed) throw httpErr(400, 'expires: after the signing date');
    const c = comp().patch(id, (x) => { x.dpa = Object.assign(b, { recorded_by: who.user, recorded_at: iso(), accepted_by: null, accepted_at: null }); return x; });
    audit(who, 'dpa.record', id, { ref: b.ref, terms: b.terms.length, breach_hours: b.breach_hours }); return c;
  }
  function acceptDpa(id, who) {
    needDpo(who, 'accepts a data processing agreement');
    const c = must(id); if (!c.dpa) throw httpErr(409, 'no agreement recorded for ' + c.name);
    if (c.dpa.accepted_by) throw httpErr(409, 'already accepted by ' + c.dpa.accepted_by);
    if (low(c.dpa.recorded_by) === low(who.user)) throw httpErr(403, 'four-eyes: the person who recorded the agreement does not accept it');
    const n = comp().patch(id, (x) => { x.dpa.accepted_by = who.user; x.dpa.accepted_at = iso(); return x; });
    audit(who, 'dpa.accept', id, { ref: c.dpa.ref, recorded_by: c.dpa.recorded_by }); return n;
  }
  function linkActivities(id, b0, who) {
    needDpo(who, 'links RoPA activities');
    must(id); const b = body(b0).list('ropa_ids', { required: true, max: 200, item: 'id', unique: true }).done();
    const known = new Set(((PD && PD.records('ropa')) || []).map((r) => r.id)); const miss = b.ropa_ids.filter((x) => !known.has(x)); if (miss.length) throw httpErr(400, 'ropa_ids: not in the RoPA register: ' + miss.slice(0, 5).join(', '));
    const c = comp().patch(id, (x) => { x.activities = b.ropa_ids; return x; });
    audit(who, 'activities', id, { count: b.ropa_ids.length }); return c;
  }
  function addNotice(b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person records a breach notice');
    const b = body(b0).str('company', { required: true, id: true }).str('incident_ref', { required: true, max: 60 }).str('detected', { required: true, max: 30, re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/, msg: 'detected: date and time, YYYY-MM-DDTHH:MM' }).str('summary', { required: true, max: 600 }).done();
    must(b.company); if (Date.parse(b.detected) > now()) throw httpErr(400, 'detected: not in the future');
    const n = notes().put(Object.assign(b, { id: nextId(notes(), 'BRN-'), created_by: who.user, created_at: iso(), notified_at: null, late: false }));
    audit(who, 'notice.add', n.id, { company: b.company, incident_ref: b.incident_ref }); return n;
  }
  function notified(id, b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person records that the company was told');
    param(id); const n = notes().get(id); if (!n) throw httpErr(404, 'notice not found'); if (n.notified_at) throw httpErr(409, 'already recorded as told on ' + n.notified_at);
    const b = body(b0).str('notified_at', { required: true, max: 30, re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/, msg: 'notified_at: date and time, YYYY-MM-DDTHH:MM' }).str('how', { required: true, max: 200 }).done();
    if (Date.parse(b.notified_at) < Date.parse(n.detected)) throw httpErr(400, 'notified_at: after the detection time');
    const c = comp().get(n.company), lim = (c && c.dpa && c.dpa.breach_hours) || 72, hours = Math.round((Date.parse(b.notified_at) - Date.parse(n.detected)) / 360000) / 10;
    const out = notes().patch(id, (x) => { x.notified_at = b.notified_at; x.how = b.how; x.hours = hours; x.limit_hours = lim; x.late = hours > lim; x.notified_by = who.user; return x; });
    audit(who, 'notice.notified', id, { company: n.company, hours, late: out.late }); return out;
  }
  return { view, saveCompany, removeCompany, saveDpa, acceptDpa, linkActivities, addNotice, notified, TERMS };
}

function registerPdplGroup(srv, app, G) {
  srv.route('GET', '/pdpl/group', (ctx) => { ctx.need('operator'); return G.view(ctx.who); });
  srv.route('POST', '/pdpl/group/companies', (ctx) => { ctx.need('operator'); return G.saveCompany(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/pdpl/group/companies/:id/remove', (ctx) => { ctx.need('operator'); return G.removeCompany(ctx.params.id, ctx.who); });
  srv.route('POST', '/pdpl/group/companies/:id/dpa', (ctx) => { ctx.need('operator'); return G.saveDpa(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/pdpl/group/companies/:id/dpa/accept', (ctx) => { ctx.need('operator'); return G.acceptDpa(ctx.params.id, ctx.who); });
  srv.route('POST', '/pdpl/group/companies/:id/activities', (ctx) => { ctx.need('operator'); return G.linkActivities(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 16384 });
  srv.route('POST', '/pdpl/group/notices', (ctx) => { ctx.need('operator'); return G.addNotice(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/pdpl/group/notices/:id/notified', (ctx) => { ctx.need('operator'); return G.notified(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
}

module.exports = { createPdplGroup, registerPdplGroup, TERMS };
