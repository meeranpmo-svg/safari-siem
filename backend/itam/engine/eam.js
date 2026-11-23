// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const crypto = require('node:crypto');
const { body: body0, param } = require('./check');
// check.js lists validate ids, text and fixed values; EAM's lists hold objects (parts, purchase lines, receipts) and user names, so a
// function item check is applied here, entry by entry, after the declared fields - every entry is validated, none passes unchecked
function body(src) {
  const a = body0(src), fns = {}, w = {};
  for (const m of Object.keys(a)) w[m] = (...args) => {
    if (m === 'list' && args[1] && typeof args[1].item === 'function') { fns[args[0]] = args[1].item; a.list(args[0], Object.assign({}, args[1], { item: undefined })); return w; }
    if (m === 'done') { const out = a.done(); for (const k of Object.keys(fns)) if (Array.isArray(out[k])) out[k] = out[k].map((x, i) => fns[k](x, i)); return out; }
    a[m](...args); return w;
  };
  return w;
}
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');
const { untrusted, UNTRUSTED_RULE } = require('./ai-guard');
/*
 * Enterprise Asset Management ({P} = /api/itam, IT Assets -> Enterprise Asset Management): the whole life of an asset in one place -
 * plan and buy, receive into stock, deploy, maintain, retire and dispose - for asset managers, field technicians, the warehouse,
 * procurement and facilities, each with a workspace. It DRIVES the asset register (engine/assets.js: create, transition, assign,
 * move - validated and audited there); it keeps only what the register does not: work orders, maintenance plans, stock, purchase
 * requests and retirement requests. Nothing here changes a device: a work order records the work a person did.
 *
 *   lifecycle      plan (purchase request) -> receive (stock / new assets in_stock) -> deploy (in_use, owner, site) -> maintain (work
 *                  orders; in_repair while a corrective one is open) -> retire / dispose (four-eyes: a different administrator approves)
 *   work orders    corrective | preventive | inspection; it | facilities | field; new -> assigned -> in_progress -> done -> verified
 *                  (by a person who did not do the work) | cancelled (with a reason). Done needs notes; parts used come out of stock.
 *   maintenance    plans per asset (every N days); the background job (guardOf 'eam.tick') raises the work order when a plan is due and
 *                  says which stock items fell to their reorder point.
 *   stock          spares, consumables and device models per site with quantity, reorder point, lead time and unit cost; every
 *                  movement (receive / issue / adjust) is kept - it is the history the demand forecast learns from.
 *   purchase       requested -> approved (procurement or an administrator, not the requester) -> ordered -> received (stock goes up;
 *                  device lines with serials become assets in_stock) | rejected (with a reason).
 *   ML             (from this platform's own records - below its minimum it says "not enough history", never a guess)
 *                  failure risk 0-100 per asset, itemised: corrective work orders in 365 days against the median of the same model /
 *                  type (3+ peers), age against the lifespan learned from retired assets of the same type (3+), open corrective work,
 *                  overdue maintenance, warranty expired; MTBF / MTTR per model (3+ failures); next failure projected from MTBF;
 *                  stock demand (daily usage by exponential smoothing over 90 days, 3+ issues) -> days of cover, reorder quantity with
 *                  safety stock (z 1.65 over the lead time); work-order cost outliers (robust z >= 3.5, 5+ costs per model);
 *                  technician suggestion (fewest open work orders weighted by on-time rate, Beta(1,1)); duplicate open work orders on
 *                  one asset (Jaccard >= 0.6 on title words).
 *   AI             an advisor over the EAM summary (app.provider: budget, redaction, UNTRUSTED_RULE; names from records are untrusted
 *                  data); it proposes, a person acts.
 * Roles: reading is any signed-in role; work is an operator; retirement approval and settings an administrator. Membership (Settings)
 * narrows who works what: technicians, warehouse, procurement, facilities; an empty list leaves it to any operator. Service and AI
 * identities never approve, complete or verify.
 *
 *   GET  /eam[?ws=manager|field|warehouse|procurement|facilities]  viewer   KPIs, lifecycle, workspace lists, ML
 *   GET  /eam/assets/:id                                          viewer   the asset's record, work orders, plans, risk and why
 *   GET  /eam/wo/:id                                              viewer   one work order with its history
 *   POST /eam/wo  ·  /eam/wo/:id/assign|start|complete|verify|cancel|comment                       operator     audited
 *   POST /eam/pm  ·  /eam/pm/:id/delete                                                            operator     audited
 *   POST /eam/stock  ·  /eam/stock/:id/adjust                                                      operator     audited
 *   POST /eam/deploy                                                                               operator     audited
 *   POST /eam/po  ·  /eam/po/:id/approve|reject|order|receive                                      operator     audited
 *   POST /eam/retire  ·  /eam/retire/:id/approve|reject                                            operator / admin (approve, reject) audited
 *   POST /eam/ai/ask                                                                               operator     audited
 *   GET|POST /eam/settings                                                                         admin        audited
 */
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (s) => String(s || '').toLowerCase();
const r1 = (n) => (n == null || !Number.isFinite(n) ? null : Math.round(n * 10) / 10);
const median = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const STOP = new Set('a an the of and or for to in on at by with from is are be this that it its - /'.split(' '));
const words = (s) => low(s).replace(/[^a-z0-9؀-ۿ]+/g, ' ').split(' ').filter((w) => w.length > 2 && !STOP.has(w));
const jaccard = (a, b) => { const A = new Set(a), B = new Set(b); if (!A.size || !B.size) return 0; let i = 0; for (const x of A) if (B.has(x)) i++; return i / (A.size + B.size - i); };
const WO_KINDS = ['corrective', 'preventive', 'inspection'], CATS = ['it', 'facilities', 'field'], PRI = ['low', 'normal', 'high', 'critical'];
const SLA_H = { low: 120, normal: 72, high: 24, critical: 8 };
const STOCK_KINDS = ['spare', 'consumable', 'device-model'];
const ROLES = ['technicians', 'warehouse', 'procurement', 'facilities'];
const WS = ['manager', 'field', 'warehouse', 'procurement', 'facilities'];
const USER = { required: true, max: 100, re: /^[A-Za-z0-9._@-]{2,100}$/, msg: 'must be a user name' };

function createEam(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, A = app.assets;
  const WO = () => store.collection('eam_wo'), PM = () => store.collection('eam_pm'), ST = () => store.collection('eam_stock'), MV = () => store.collection('eam_moves');
  const PO = () => store.collection('eam_po'), RT = () => store.collection('eam_retire'), CF = () => store.collection('eam_cfg');
  const iso = (t) => new Date(t === undefined ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'eam.' + action, target, detail }); };
  const cfg = () => Object.assign({ technicians: [], warehouse: [], procurement: [], facilities: [], version: 0 }, CF().get('cfg') || {});
  const inList = (l, u) => (l || []).some((x) => low(x) === low(u));
  const isAdmin = (who) => who.role === 'admin';
  const may = (who, role) => isAdmin(who) || (who.role === 'operator' && (!(cfg()[role] || []).length || inList(cfg()[role], who.user)));
  const need = (who, role, what) => { if (!may(who, role)) throw httpErr(403, what + ': ' + ((cfg()[role] || []).length ? 'a member of ' + role + ' (Settings) or an administrator' : 'an operator or an administrator')); };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const seq = (prefix, col) => { const y = new Date(now()).getUTCFullYear(), re = new RegExp('^' + prefix + '-' + y + '-(\\d+)$'); let n = 0; for (const x of col.all()) { const m = re.exec(x.id); if (m) n = Math.max(n, Number(m[1])); } return prefix + '-' + y + '-' + String(n + 1).padStart(4, '0'); };
  const mustAsset = (id) => { const a = A.raw(id); if (!a) throw httpErr(404, 'asset ' + String(id).slice(0, 80) + ' not found'); return a; };
  const hist = (rec, who, action, note) => { (rec.history = rec.history || []).push({ at: iso(), by: who.user, action, note: note || null }); };
  const assetName = (id) => { const a = A.raw(id); return a ? (a.name || a.asset_tag || a.serial || id) : id; };
  const typeOf = (a) => low(a.type || a.category || 'other');
  const modelOf = (a) => [a.vendor, a.model].filter(Boolean).join(' ') || null;

  // ------------------------------------------------------------------------------------------------- work orders ---
  function woCreate(b0, who, sys) {
    const b = body(b0 || {}).str('asset_id', { required: true, max: 80, re: /^[A-Za-z0-9_.:-]+$/, msg: 'asset_id must be an asset id' }).oneOf('kind', WO_KINDS, { required: true })
      .oneOf('category', CATS, { def: 'it' }).str('title', { required: true, max: 200 }).str('details', { max: 4000 }).oneOf('priority', PRI, { def: 'normal' }).date('due', {}).done();
    const a = mustAsset(b.asset_id);
    if (['retired', 'disposed'].includes(a.status)) throw httpErr(409, 'the asset is ' + a.status + ': no work orders on it');
    const t = now(), w = { id: seq('WO', WO()), asset_id: a.id, asset_name: assetName(a.id), kind: b.kind, category: b.category, title: b.title, details: b.details || '', priority: b.priority,
      due: b.due ? b.due + 'T23:59:00.000Z' : iso(t + SLA_H[b.priority] * 3600000), status: 'new', created_by: who.user, created_at: iso(t), assignee: null, parts: [], cost: null, downtime_h: null, plan_id: sys ? sys.plan_id : null, history: [], comments: [] };
    hist(w, who, 'created', b.kind + ' · ' + b.priority);
    WO().put(w); audit(who, 'wo.create', w.id, { asset: a.id, kind: w.kind, category: w.category, priority: w.priority, plan: w.plan_id });
    return woView(w);
  }
  const woGet = (id) => { const w = WO().get(String(id)); if (!w) throw httpErr(404, 'work order not found'); return w; };
  function woAct(id, act, b0, who) {
    const w = woGet(id), role = w.category === 'facilities' ? 'facilities' : 'technicians', mine = low(w.assignee) === low(who.user);
    const state = (from, to) => { if (!from.includes(w.status)) throw httpErr(409, 'the work order is ' + w.status + ' - it cannot be ' + act + (act.endsWith('e') ? 'd' : 'ed') + ' now'); w.status = to; };
    if (act === 'assign') {
      need(who, role, 'assigning work'); const b = body(b0 || {}).str('assignee', USER).done();
      const team = cfg()[role] || []; if (team.length && !inList(team, b.assignee)) throw httpErr(400, 'assignee must be a member of ' + role + ' (Settings)');
      state(['new', 'assigned', 'in_progress'], w.status === 'in_progress' ? 'in_progress' : 'assigned'); w.assignee = b.assignee; hist(w, who, 'assigned', b.assignee);
    } else if (act === 'start') {
      person(who, 'does the work'); if (!mine && !isAdmin(who)) { if (w.assignee) throw httpErr(403, 'the assignee (' + w.assignee + ') starts it'); need(who, role, 'taking work'); w.assignee = who.user; }
      state(['new', 'assigned'], 'in_progress'); w.started_at = iso(); hist(w, who, 'started');
      if (w.kind === 'corrective') { const a = A.raw(w.asset_id); if (a && a.status === 'in_use') { A.transition(a.id, 'repair', who, 'work order ' + w.id); w.set_in_repair = true; } }
    } else if (act === 'complete') {
      person(who, 'completes work'); if (!mine && !isAdmin(who)) throw httpErr(403, 'the assignee (' + (w.assignee || 'nobody') + ') completes it');
      const b = body(b0 || {}).str('notes', { required: true, max: 4000 }).num('cost', { min: 0, max: 1e9 }).num('downtime_h', { min: 0, max: 10000 }).str('failure_code', { max: 80 })
        .list('parts', { max: 30, item: (p, i) => body(p).str('stock_id', { required: true, max: 80, re: /^[A-Za-z0-9_.:-]+$/, msg: 'parts[' + i + '].stock_id must be a stock id' }).int('qty', { required: true, min: 1, max: 100000 }).done() }).done();
      if (w.status !== 'in_progress') throw httpErr(409, 'start the work order first (it is ' + w.status + ')');
      for (const p of b.parts || []) { const s = ST().get(p.stock_id); if (!s) throw httpErr(400, 'stock item ' + p.stock_id + ' not found'); if (s.qty < p.qty) throw httpErr(409, s.name + ': only ' + s.qty + ' in stock'); }
      for (const p of b.parts || []) { const s = ST().get(p.stock_id); s.qty -= p.qty; s.updated_at = iso(); ST().put(s); move(s, -p.qty, 'issue', who, w.id); w.parts.push({ stock_id: s.id, name: s.name, qty: p.qty, unit_cost: s.unit_cost }); }
      w.status = 'done'; w.done_at = iso(); w.done_by = who.user; w.notes = b.notes; w.cost = b.cost == null ? null : b.cost; w.downtime_h = b.downtime_h == null ? null : b.downtime_h; w.failure_code = b.failure_code || null;
      hist(w, who, 'completed', b.notes.slice(0, 200));
      if (w.set_in_repair) { const a = A.raw(w.asset_id); if (a && a.status === 'in_repair') A.transition(a.id, 'activate', who, 'work order ' + w.id + ' done'); }
    } else if (act === 'verify') {
      person(who, 'verifies work'); if (who.role === 'viewer') throw httpErr(403, 'an operator or an administrator verifies');
      if (low(w.done_by) === low(who.user)) throw httpErr(403, 'the person who did the work does not verify it (four-eyes)');
      const b = body(b0 || {}).str('note', { max: 1000 }).done(); state(['done'], 'verified'); w.verified_by = who.user; w.verified_at = iso(); hist(w, who, 'verified', b.note);
    } else if (act === 'cancel') {
      const b = body(b0 || {}).str('reason', { required: true, max: 1000 }).done();
      if (low(w.created_by) !== low(who.user) && !isAdmin(who)) throw httpErr(403, 'the person who raised it or an administrator cancels it');
      state(['new', 'assigned', 'in_progress'], 'cancelled'); hist(w, who, 'cancelled', b.reason);
      if (w.set_in_repair) { const a = A.raw(w.asset_id); if (a && a.status === 'in_repair') A.transition(a.id, 'activate', who, 'work order ' + w.id + ' cancelled'); }
    } else if (act === 'comment') {
      const b = body(b0 || {}).str('text', { required: true, max: 2000 }).done(); w.comments.push({ at: iso(), by: who.user, text: b.text });
    } else throw httpErr(404, 'unknown action');
    WO().put(w); audit(who, 'wo.' + act, w.id, { status: w.status, assignee: w.assignee, parts: act === 'complete' ? w.parts.length : undefined, cost: act === 'complete' ? w.cost : undefined });
    return woView(w);
  }
  function woView(w) {
    const t = now(), open = !['done', 'verified', 'cancelled'].includes(w.status);
    return Object.assign({}, w, { overdue: open && Date.parse(w.due) < t, open });
  }

  // ------------------------------------------------------------------------------------------- maintenance plans ---
  function pmCreate(b0, who) {
    const b = body(b0 || {}).str('asset_id', { required: true, max: 80, re: /^[A-Za-z0-9_.:-]+$/, msg: 'asset_id must be an asset id' }).str('title', { required: true, max: 200 })
      .int('every_days', { required: true, min: 1, max: 1825 }).date('next', { required: true }).oneOf('category', CATS, { def: 'it' }).oneOf('kind', ['preventive', 'inspection'], { def: 'preventive' }).done();
    const a = mustAsset(b.asset_id);
    const p = { id: 'PM-' + crypto.randomBytes(4).toString('hex'), asset_id: a.id, asset_name: assetName(a.id), title: b.title, every_days: b.every_days, next: b.next, category: b.category, kind: b.kind, created_by: who.user, created_at: iso(), runs: 0, last_wo: null };
    PM().put(p); audit(who, 'pm.create', p.id, { asset: a.id, every_days: p.every_days, next: p.next }); return p;
  }
  function pmDelete(id, who) { const p = PM().get(String(id)); if (!p) throw httpErr(404, 'plan not found'); PM().remove(p.id); audit(who, 'pm.delete', p.id, { asset: p.asset_id }); return { ok: true }; }

  // ------------------------------------------------------------------------------------------------------- stock ---
  function move(s, delta, kind, who, ref) { MV().put({ id: 'MV-' + crypto.randomBytes(5).toString('hex'), stock_id: s.id, delta, kind, ref: ref || null, by: who.user, at: iso() }); }
  function stockCreate(b0, who) {
    need(who, 'warehouse', 'adding stock');
    const b = body(b0 || {}).str('name', { required: true, max: 160 }).str('sku', { max: 80 }).oneOf('kind', STOCK_KINDS, { required: true }).str('site', { required: true, max: 120 })
      .int('qty', { min: 0, max: 1e7, def: 0 }).int('reorder_point', { min: 0, max: 1e7, def: 0 }).int('lead_days', { min: 1, max: 365, def: 14 }).num('unit_cost', { min: 0, max: 1e9 }).done();
    if (ST().all().some((s) => low(s.name) === low(b.name) && low(s.site) === low(b.site))) throw httpErr(409, b.name + ' already exists at ' + b.site + ' - adjust its quantity instead');
    const s = Object.assign({ id: 'ST-' + crypto.randomBytes(4).toString('hex'), created_by: who.user, created_at: iso(), updated_at: iso(), unit_cost: null }, b);
    ST().put(s); if (s.qty) move(s, s.qty, 'receive', who, 'opening balance'); audit(who, 'stock.create', s.id, { name: s.name, site: s.site, qty: s.qty }); return s;
  }
  function stockAdjust(id, b0, who) {
    need(who, 'warehouse', 'adjusting stock'); const s = ST().get(String(id)); if (!s) throw httpErr(404, 'stock item not found');
    const b = body(b0 || {}).int('delta', { required: true, min: -1e7, max: 1e7 }).str('reason', { required: true, max: 500 }).oneOf('kind', ['adjust', 'issue', 'receive'], { def: 'adjust' }).done();
    if (!b.delta) throw httpErr(400, 'delta must not be 0');
    if (s.qty + b.delta < 0) throw httpErr(409, 'only ' + s.qty + ' in stock');
    s.qty += b.delta; s.updated_at = iso(); ST().put(s); move(s, b.delta, b.kind, who, b.reason);
    audit(who, 'stock.adjust', s.id, { delta: b.delta, kind: b.kind, reason: b.reason, qty: s.qty }); return s;
  }
  function deploy(b0, who) {
    need(who, 'warehouse', 'deploying an asset'); person(who, 'deploys an asset');
    const b = body(b0 || {}).str('asset_id', { required: true, max: 80, re: /^[A-Za-z0-9_.:-]+$/, msg: 'asset_id must be an asset id' }).str('owner', { required: true, max: 200 })
      .str('department', { max: 200 }).str('site', { max: 200 }).str('note', { max: 500 }).done();
    const a = mustAsset(b.asset_id); if (a.status !== 'in_stock') throw httpErr(409, 'only an asset in stock is deployed (this one is ' + a.status + ')');
    A.transition(a.id, 'activate', who, 'deployed to ' + b.owner + (b.note ? ' - ' + b.note : ''));
    A.assign(a.id, Object.assign({ owner: b.owner }, b.department ? { department: b.department } : {}), who);
    if (b.site) A.move(a.id, { site: b.site }, who);
    audit(who, 'deploy', a.id, { owner: b.owner, site: b.site || null }); return { ok: true, asset: A.get(a.id) };
  }

  // ---------------------------------------------------------------------------------------------------- purchase ---
  function poCreate(b0, who) {
    person(who, 'raises a purchase request');
    const b = body(b0 || {}).str('title', { required: true, max: 200 }).str('justification', { required: true, max: 3000 }).str('vendor', { max: 160 })
      .list('items', { required: true, max: 50, item: (x, i) => body(x).str('name', { required: true, max: 160 }).int('qty', { required: true, min: 1, max: 100000 }).num('unit_cost', { min: 0, max: 1e9 })
        .str('stock_id', { max: 80, re: /^[A-Za-z0-9_.:-]+$/, msg: 'items[' + i + '].stock_id must be a stock id' }).oneOf('kind', ['device', 'spare', 'consumable', 'service'], { def: 'device' }).str('type', { max: 60 }).done() }).done();
    if (!b.items.length) throw httpErr(400, 'items: at least one line');
    for (const it of b.items) if (it.stock_id && !ST().get(it.stock_id)) throw httpErr(400, 'stock item ' + it.stock_id + ' not found');
    const total = b.items.reduce((n, x) => n + (x.unit_cost || 0) * x.qty, 0);
    const p = { id: seq('PR', PO()), title: b.title, justification: b.justification, vendor: b.vendor || null, items: b.items, total: Math.round(total * 100) / 100, status: 'requested', requester: who.user, created_at: iso(), history: [] };
    hist(p, who, 'requested'); PO().put(p); audit(who, 'po.create', p.id, { lines: p.items.length, total: p.total }); return p;
  }
  function poAct(id, act, b0, who) {
    const p = PO().get(String(id)); if (!p) throw httpErr(404, 'purchase request not found');
    const state = (from, to) => { if (!from.includes(p.status)) throw httpErr(409, 'the request is ' + p.status); p.status = to; };
    if (act === 'approve' || act === 'reject') {
      need(who, 'procurement', 'deciding a purchase'); person(who, 'decides a purchase');
      if (low(p.requester) === low(who.user)) throw httpErr(403, 'the requester does not ' + act + ' their own request (four-eyes)');
      const b = act === 'reject' ? body(b0 || {}).str('reason', { required: true, max: 1000 }).done() : body(b0 || {}).str('note', { max: 1000 }).done();
      state(['requested'], act === 'approve' ? 'approved' : 'rejected'); p.decision = { by: who.user, at: iso(), note: b.reason || b.note || null }; hist(p, who, act === 'approve' ? 'approved' : 'rejected', b.reason || b.note);
    } else if (act === 'order') {
      need(who, 'procurement', 'placing an order'); const b = body(b0 || {}).str('order_ref', { required: true, max: 120 }).date('expected', {}).done();
      state(['approved'], 'ordered'); p.order_ref = b.order_ref; p.expected = b.expected || null; p.ordered_at = iso(); hist(p, who, 'ordered', b.order_ref);
    } else if (act === 'receive') {
      need(who, 'warehouse', 'receiving goods'); person(who, 'receives goods');
      const b = body(b0 || {}).str('site', { required: true, max: 120 }).list('lines', { required: true, max: 50, item: (x, i) => body(x).int('line', { required: true, min: 0, max: 49 }).int('qty', { required: true, min: 1, max: 100000 })
        .list('serials', { max: 500, item: (s) => { const v = String(s || '').trim(); if (!/^[A-Za-z0-9._/-]{2,80}$/.test(v)) throw httpErr(400, 'lines[' + i + '].serials: letters, digits, . _ / - only'); return v; } }).done() }).done();
      if (p.status !== 'ordered') throw httpErr(409, 'the request is ' + p.status);
      // every line is checked before anything changes: a refused receipt leaves the request, the stock and the register as they were
      const seen = new Set();
      for (const L of b.lines) {
        const it = p.items[L.line]; if (!it) throw httpErr(400, 'line ' + L.line + ' is not on the request');
        if (L.serials && L.serials.length && L.serials.length !== L.qty) throw httpErr(400, 'line ' + L.line + ': ' + L.qty + ' received but ' + L.serials.length + ' serial(s)');
        if (it.stock_id && !ST().get(it.stock_id)) throw httpErr(409, 'stock item ' + it.stock_id + ' no longer exists');
        for (const sn of L.serials || []) { if (seen.has(low(sn))) throw httpErr(400, 'serial ' + sn + ' is listed twice'); seen.add(low(sn)); if (A.all().some((a) => low(a.serial) === low(sn))) throw httpErr(409, 'serial ' + sn + ' is already in the asset register'); }
      }
      p.status = 'received';
      const made = [];
      for (const L of b.lines) {
        const it = p.items[L.line];
        if (it.stock_id) { const s = ST().get(it.stock_id); s.qty += L.qty; s.updated_at = iso(); ST().put(s); move(s, L.qty, 'receive', who, p.id); }
        if (it.kind === 'device' && L.serials) for (const sn of L.serials) {
          const r = A.create({ name: it.name + ' ' + sn, serial: sn, type: it.type || undefined, site: b.site, purchase_date: iso().slice(0, 10), cost: it.unit_cost == null ? undefined : it.unit_cost, vendor: p.vendor || undefined }, who);
          const id = (r.asset || r).id; A.transition(id, 'restock', who, 'received on ' + p.id); made.push(id);
        }
      }
      p.received = { at: iso(), by: who.user, site: b.site, lines: b.lines.map((l) => ({ line: l.line, qty: l.qty })), assets: made }; hist(p, who, 'received', made.length + ' asset(s) into stock');
    } else throw httpErr(404, 'unknown action');
    PO().put(p); audit(who, 'po.' + act, p.id, { status: p.status, assets: act === 'receive' ? p.received.assets.length : undefined }); return p;
  }

  // ------------------------------------------------------------------------------------------- retire / dispose ---
  function rtCreate(b0, who) {
    if (who.role === 'viewer') throw httpErr(403, 'an operator or an administrator requests a retirement');
    const b = body(b0 || {}).str('asset_id', { required: true, max: 80, re: /^[A-Za-z0-9_.:-]+$/, msg: 'asset_id must be an asset id' }).oneOf('action', ['retire', 'dispose'], { required: true })
      .str('reason', { required: true, max: 2000 }).oneOf('method', ['resale', 'donation', 'recycle', 'destruction-certificate', 'return-to-lessor'], {}).bool('data_wiped', { def: false }).done();
    const a = mustAsset(b.asset_id);
    if (b.action === 'retire' && ['retired', 'disposed'].includes(a.status)) throw httpErr(409, 'the asset is already ' + a.status);
    if (b.action === 'dispose') { if (a.status === 'disposed') throw httpErr(409, 'already disposed'); if (!b.method) throw httpErr(400, 'method is required to dispose'); if (!b.data_wiped) throw httpErr(400, 'data_wiped: confirm the storage was wiped or destroyed before disposal'); }
    if (RT().all().some((x) => x.asset_id === a.id && x.status === 'pending')) throw httpErr(409, 'a request for this asset is already waiting');
    const openWo = WO().all().filter((w) => w.asset_id === a.id && !['done', 'verified', 'cancelled'].includes(w.status));
    const r = { id: seq('RT', RT()), asset_id: a.id, asset_name: assetName(a.id), action: b.action, reason: b.reason, method: b.method || null, data_wiped: b.data_wiped, status: 'pending', requester: who.user, created_at: iso(), open_work_orders: openWo.map((w) => w.id), history: [] };
    hist(r, who, 'requested', b.action); RT().put(r); audit(who, 'retire.request', r.id, { asset: a.id, action: r.action, method: r.method }); return r;
  }
  function rtAct(id, act, b0, who) {
    if (!isAdmin(who)) throw httpErr(403, 'an administrator decides a retirement'); person(who, 'decides a retirement');
    const r = RT().get(String(id)); if (!r) throw httpErr(404, 'request not found'); if (r.status !== 'pending') throw httpErr(409, 'the request is ' + r.status);
    if (low(r.requester) === low(who.user)) throw httpErr(403, 'the requester does not decide their own request (four-eyes)');
    const b = act === 'reject' ? body(b0 || {}).str('reason', { required: true, max: 1000 }).done() : body(b0 || {}).str('note', { max: 1000 }).done();
    if (act === 'approve') { A.transition(r.asset_id, r.action, who, r.reason + (r.method ? ' · ' + r.method : '') + ' · ' + r.id); r.status = 'approved'; }
    else if (act === 'reject') r.status = 'rejected'; else throw httpErr(404, 'unknown action');
    r.decision = { by: who.user, at: iso(), note: b.reason || b.note || null }; hist(r, who, r.status, b.reason || b.note); RT().put(r);
    audit(who, 'retire.' + act, r.id, { asset: r.asset_id, action: r.action }); return r;
  }

  // -------------------------------------------------------------------------------------------------------- ML ---
  function ml() {
    const t = now(), assets = A.all(), wos = WO().all(), live = assets.filter((a) => !['retired', 'disposed'].includes(a.status));
    const corr = wos.filter((w) => w.kind === 'corrective' && w.status !== 'cancelled');
    // lifespan learned per type from retired / disposed assets with a purchase date
    const lifeByType = {}; for (const a of assets) if (['retired', 'disposed'].includes(a.status) && a.purchase_date) { const end = Date.parse(a.updated_at || ''), st = Date.parse(a.purchase_date); if (end > st) (lifeByType[typeOf(a)] = lifeByType[typeOf(a)] || []).push((end - st) / DAY / 365); }
    const life = {}; for (const [k, v] of Object.entries(lifeByType)) life[k] = v.length >= 3 ? { years: r1(median(v)), n: v.length } : { years: null, n: v.length, why: 'not enough retirements (' + v.length + ' of 3)' };
    // corrective work orders per asset in 365 days, and the median of its peers (same model, else same type; 3+ peers)
    const yr = corr.filter((w) => t - Date.parse(w.created_at) <= 365 * DAY), cnt = {}; for (const w of yr) cnt[w.asset_id] = (cnt[w.asset_id] || 0) + 1;
    const groupOf = (a) => modelOf(a) || ('type:' + typeOf(a)), groups = {}; for (const a of live) (groups[groupOf(a)] = groups[groupOf(a)] || []).push(cnt[a.id] || 0);
    // MTBF / MTTR per model from corrective work orders (3+ failures)
    const byModel = {}; for (const w of corr) { const a = A.raw(w.asset_id); if (!a) continue; const m = modelOf(a) || typeOf(a); (byModel[m] = byModel[m] || { fails: [], repair: [] }).fails.push({ asset: a.id, at: Date.parse(w.created_at) }); if (w.done_at && w.started_at) byModel[m].repair.push((Date.parse(w.done_at) - Date.parse(w.started_at)) / 3600000); }
    const reliability = Object.entries(byModel).map(([m, g]) => {
      const gaps = []; const per = {}; for (const f of g.fails) (per[f.asset] = per[f.asset] || []).push(f.at);
      for (const L of Object.values(per)) { L.sort((x, y) => x - y); for (let i = 1; i < L.length; i++) gaps.push((L[i] - L[i - 1]) / DAY); }
      return { model: m, failures: g.fails.length, mtbf_days: gaps.length >= 3 ? r1(median(gaps)) : null, mttr_h: g.repair.length >= 3 ? r1(median(g.repair)) : null, why: gaps.length >= 3 ? 'median days between failures of the same asset (' + gaps.length + ' intervals)' : 'not enough repeat failures (' + gaps.length + ' of 3 intervals)' };
    }).sort((a, b) => b.failures - a.failures);
    const relOf = Object.fromEntries(reliability.map((r) => [r.model, r]));
    const pmLate = new Set(PM().all().filter((p) => Date.parse(p.next + 'T23:59:00Z') < t).map((p) => p.asset_id));
    const openCorr = new Set(wos.filter((w) => w.kind === 'corrective' && !['done', 'verified', 'cancelled'].includes(w.status)).map((w) => w.asset_id));
    const risk = live.map((a) => {
      const items = [], add = (p, why) => { if (p > 0) items.push({ p: Math.round(p), why }); };
      const peers = groups[groupOf(a)] || [], c = cnt[a.id] || 0, md = peers.length >= 3 ? median(peers) : null;
      if (c) { if (md != null) add(Math.min(35, (c - md) * 12), c + ' corrective work order(s) in 365 days, peers median ' + md); else add(Math.min(25, c * 8), c + ' corrective work order(s) in 365 days (fewer than 3 peers to compare)'); }
      const L = life[typeOf(a)]; if (a.purchase_date && L && L.years) { const age = (t - Date.parse(a.purchase_date)) / DAY / 365; if (age > L.years * 0.8) add(Math.min(30, (age / L.years - 0.8) * 75), 'age ' + r1(age) + ' y against a learned lifespan of ' + L.years + ' y (' + L.n + ' retired ' + typeOf(a) + ')'); }
      if (openCorr.has(a.id)) add(15, 'corrective work is open now');
      if (pmLate.has(a.id)) add(10, 'maintenance is overdue');
      if (a.warranty_end && Date.parse(a.warranty_end) < t) add(10, 'warranty ended ' + String(a.warranty_end).slice(0, 10));
      const m = relOf[modelOf(a) || typeOf(a)], last = corr.filter((w) => w.asset_id === a.id).map((w) => Date.parse(w.created_at)).sort((x, y) => y - x)[0];
      const next = m && m.mtbf_days && last ? iso(last + m.mtbf_days * DAY).slice(0, 10) : null;
      const score = Math.min(100, items.reduce((n, i) => n + i.p, 0));
      return { asset_id: a.id, name: assetName(a.id), type: typeOf(a), model: modelOf(a), status: a.status, site: a.site || null, score, items, next_failure: next, next_why: next ? 'last failure + MTBF of ' + (modelOf(a) || typeOf(a)) + ' (' + m.mtbf_days + ' d) - a projection, not a promise' : null };
    }).sort((a, b) => b.score - a.score);
    // stock demand: daily usage by exponential smoothing of issues over 90 days (3+ issues), days of cover, reorder with safety stock
    const moves = MV().all();
    const stock = ST().all().map((s) => {
      const iss = moves.filter((m) => m.stock_id === s.id && m.kind === 'issue' && t - Date.parse(m.at) <= 90 * DAY);
      const out = { id: s.id, name: s.name, site: s.site, kind: s.kind, qty: s.qty, reorder_point: s.reorder_point, lead_days: s.lead_days, below_reorder: s.qty <= s.reorder_point, issues_90d: iss.length };
      if (iss.length < 3) return Object.assign(out, { daily: null, why: 'not enough usage history (' + iss.length + ' of 3 issues in 90 days)' });
      const days = []; for (let d = 89; d >= 0; d--) { const d0 = t - (d + 1) * DAY, d1 = t - d * DAY; days.push(iss.filter((m) => { const x = Date.parse(m.at); return x > d0 && x <= d1; }).reduce((n, m) => n - m.delta, 0)); }
      let e = days[0]; for (const v of days.slice(1)) e = 0.1 * v + 0.9 * e;
      const mean = days.reduce((n, v) => n + v, 0) / days.length, sd = Math.sqrt(days.reduce((n, v) => n + (v - mean) ** 2, 0) / days.length), daily = Math.max(e, mean / 2);
      const safety = 1.65 * sd * Math.sqrt(s.lead_days), cover = daily > 0 ? s.qty / daily : null, order = Math.max(0, Math.ceil(daily * s.lead_days + safety - s.qty));
      return Object.assign(out, { daily: r1(daily), cover_days: cover == null ? null : Math.floor(cover), safety: Math.ceil(safety), suggest_order: order, why: 'smoothed daily usage ' + r1(daily) + ' over 90 days, lead time ' + s.lead_days + ' d, safety stock ' + Math.ceil(safety) + ' (z 1.65)' });
    }).sort((a, b) => (a.cover_days == null ? 1e9 : a.cover_days) - (b.cover_days == null ? 1e9 : b.cover_days));
    // cost outliers per model (5+ costed work orders, robust z >= 3.5)
    const costBy = {}; for (const w of wos) if (w.cost != null) { const a = A.raw(w.asset_id); const m = a ? (modelOf(a) || typeOf(a)) : 'unknown'; (costBy[m] = costBy[m] || []).push(w); }
    const outliers = []; for (const [m, L] of Object.entries(costBy)) { if (L.length < 5) continue; const c = L.map((w) => w.cost), md = median(c), mad = median(c.map((x) => Math.abs(x - md))) || 1;
      for (const w of L) { const z = 0.6745 * (w.cost - md) / mad; if (z >= 3.5) outliers.push({ wo: w.id, asset: w.asset_name, cost: w.cost, median: md, z: r1(z), why: 'cost ' + w.cost + ' against a median of ' + md + ' for ' + m }); } }
    // technician suggestion: fewest open work orders weighted by on-time rate (Beta(1,1))
    const techs = (cfg().technicians || []).length ? cfg().technicians : [...new Set(wos.map((w) => w.assignee).filter(Boolean))];
    const tech = techs.map((u) => { const mine = wos.filter((w) => low(w.assignee) === low(u)), open = mine.filter((w) => !['done', 'verified', 'cancelled'].includes(w.status)).length;
      const done = mine.filter((w) => w.done_at), ok = done.filter((w) => Date.parse(w.done_at) <= Date.parse(w.due)).length, rate = (ok + 1) / (done.length + 2);
      return { user: u, open, done: done.length, on_time: r1(rate * 100), load: r1(open / rate) }; }).sort((a, b) => a.load - b.load || b.on_time - a.on_time);
    // duplicate open work orders on one asset
    const openW = wos.filter((w) => !['done', 'verified', 'cancelled'].includes(w.status)), dups = [];
    for (let i = 0; i < openW.length; i++) for (let j = i + 1; j < openW.length; j++) if (openW[i].asset_id === openW[j].asset_id) { const s = jaccard(words(openW[i].title), words(openW[j].title)); if (s >= 0.6) dups.push({ a: openW[i].id, b: openW[j].id, similarity: r1(s), asset: openW[i].asset_name }); }
    return { risk, reliability, lifespan: life, stock, outliers, technicians: tech, suggest_technician: tech[0] ? tech[0].user : null, duplicates: dups };
  }

  // ------------------------------------------------------------------------------------------------------ views ---
  function view(q0, who) {
    const q = { ws: WS.includes(String((q0 || {}).ws || '')) ? q0.ws : 'manager' };
    const t = now(), assets = A.all(), wos = WO().all().map(woView), M = ml();
    const lc = { planned: PO().all().filter((p) => ['requested', 'approved', 'ordered'].includes(p.status)).reduce((n, p) => n + p.items.filter((i) => i.kind === 'device').reduce((k, i) => k + i.qty, 0), 0) };
    for (const s of ['in_stock', 'in_use', 'in_repair', 'retired', 'disposed', 'lost']) lc[s] = assets.filter((a) => a.status === s).length;
    const open = wos.filter((w) => w.open), pmDue = PM().all().filter((p) => Date.parse(p.next + 'T23:59:00Z') - t <= 7 * DAY).sort((a, b) => a.next.localeCompare(b.next));
    const kpis = { assets: assets.length, open_wo: open.length, overdue_wo: open.filter((w) => w.overdue).length, unassigned_wo: open.filter((w) => !w.assignee).length, pm_due_7d: pmDue.length,
      below_reorder: M.stock.filter((s) => s.below_reorder).length, po_waiting: PO().all().filter((p) => p.status === 'requested').length, retire_waiting: RT().all().filter((r) => r.status === 'pending').length,
      high_risk: M.risk.filter((r) => r.score >= 50).length, done_30d: wos.filter((w) => w.done_at && t - Date.parse(w.done_at) <= 30 * DAY).length };
    const doneW = wos.filter((w) => w.done_at); kpis.on_time = doneW.length ? Math.round(100 * doneW.filter((w) => Date.parse(w.done_at) <= Date.parse(w.due)).length / doneW.length) : null;
    const sortWo = (L) => L.sort((a, b) => (b.overdue - a.overdue) || PRI.indexOf(b.priority) - PRI.indexOf(a.priority) || a.due.localeCompare(b.due));
    const ws = {
      manager: { risk: M.risk.slice(0, 25), retirements: RT().all().filter((r) => r.status === 'pending'), open: sortWo(open.slice()).slice(0, 50) },
      field: { mine: sortWo(open.filter((w) => low(w.assignee) === low(who.user))), unassigned: sortWo(open.filter((w) => !w.assignee && w.category !== 'facilities')), pm_due: pmDue },
      warehouse: { stock: M.stock, in_stock: assets.filter((a) => a.status === 'in_stock').map((a) => ({ id: a.id, name: assetName(a.id), serial: a.serial || null, site: a.site || null, type: typeOf(a) })).slice(0, 300), to_receive: PO().all().filter((p) => p.status === 'ordered') },
      procurement: { requests: PO().all().sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 200), reorder: M.stock.filter((s) => s.below_reorder || (s.suggest_order || 0) > 0) },
      facilities: { open: sortWo(open.filter((w) => w.category === 'facilities')), pm: PM().all().filter((p) => p.category === 'facilities') },
    };
    return { generated_at: iso(t), me: { user: who.user, role: who.role, can: { work: who.role !== 'viewer', admin: isAdmin(who) }, member: ROLES.filter((r) => inList(cfg()[r], who.user)) },
      ws: q.ws, kpis, lifecycle: lc, workspace: ws[q.ws], ml: { reliability: M.reliability.slice(0, 20), lifespan: M.lifespan, outliers: M.outliers, technicians: M.technicians, suggest_technician: M.suggest_technician, duplicates: M.duplicates },
      plans: PM().all(), settings: isAdmin(who) ? cfg() : null, roles: ROLES, kinds: WO_KINDS, categories: CATS, priorities: PRI, stock_kinds: STOCK_KINDS,
      ai: aiStatus() };
  }
  function assetView(id) {
    const a = mustAsset(param(id, 'id')), M = ml();
    return { asset: A.get(a.id), work_orders: WO().all().filter((w) => w.asset_id === a.id).map(woView).sort((x, y) => y.created_at.localeCompare(x.created_at)),
      plans: PM().all().filter((p) => p.asset_id === a.id), retirements: RT().all().filter((r) => r.asset_id === a.id), risk: M.risk.find((r) => r.asset_id === a.id) || null };
  }

  // -------------------------------------------------------------------------------------------------------- AI ---
  function aiStatus() { return app.provider ? { available: true } : { available: false, why: 'AI is not configured on this server' }; }
  async function aiAsk(b0, who) {
    person(who, 'asks the advisor'); const b = body(b0 || {}).str('question', { required: true, max: 1500 }).done();
    const P = app.provider; if (!P) throw httpErr(409, 'AI is not configured on this server');
    const st = await P.status(); if (st.state !== 'ready') throw httpErr(409, 'AI is not ready: ' + (st.message || st.state));
    const v = view({ ws: 'manager' }, who), M = ml();
    const summary = JSON.stringify({ kpis: v.kpis, lifecycle: v.lifecycle, top_risk: M.risk.slice(0, 15).map((r) => ({ name: r.name, model: r.model, score: r.score, why: r.items.map((i) => i.why), next_failure: r.next_failure })),
      reliability: M.reliability.slice(0, 10), stock: M.stock.slice(0, 20).map((s) => ({ name: s.name, site: s.site, qty: s.qty, cover_days: s.cover_days, suggest_order: s.suggest_order, below_reorder: s.below_reorder })),
      outliers: M.outliers.slice(0, 10), technicians: M.technicians.slice(0, 10) }).slice(0, 14000);
    const system = ('You are the enterprise asset management advisor for ' + ZYB_ORG.short + '. Answer from the summary only: which assets need attention and why, what maintenance to do first, what to reorder, what to replace. ')
      + 'Never invent assets, figures or dates; forecasts are projections from this platform\'s own history. You change nothing - every action is a work order, purchase or retirement request a person raises and another approves. Reply in the language of the question (Arabic or English).\n' + UNTRUSTED_RULE;
    const prompt = untrusted('question', b.question) + '\n' + untrusted('eam-summary', summary);
    const out = await P.call({ system, prompt, who, feature: 'itam.eam_advisor' }); if (!out || out.ok === false) throw httpErr(409, (out && out.message) || 'the AI did not answer');
    const text = String(out.text || '').slice(0, 6000); audit(who, 'ai.ask', 'eam', { chars: text.length, model: out.model || null });
    return { label: 'AI advice - check it against the records before you act', text, model: out.model || null };
  }

  // -------------------------------------------------------------------------------------------- settings / tick ---
  function settingsSave(b0, who) {
    person(who, 'changes EAM settings');
    let o = body(b0 || {}).int('version', { required: true, min: 0, max: 1e9 }); for (const r of ROLES) o = o.list(r, { max: 200, item: (u) => { const v = String(u || '').trim(); if (!/^[A-Za-z0-9._@-]{2,100}$/.test(v)) throw httpErr(400, r + ': ' + v.slice(0, 40) + ' is not a user name'); return v; } });
    const b = o.done(), cur = cfg(); if (b.version !== cur.version) throw httpErr(409, 'the settings were changed meanwhile - reload');
    const next = { id: 'cfg', version: cur.version + 1, updated_by: who.user, updated_at: iso() }; for (const r of ROLES) next[r] = b[r] || cur[r] || [];
    CF().put(next); audit(who, 'settings', 'eam', Object.fromEntries(ROLES.map((r) => [r, next[r].length]))); return cfg();
  }
  const SYS = { user: 'system:eam', role: 'admin', ip: '' };
  function tick() {
    const t = now(), raised = [];
    for (const p of PM().all()) {
      if (Date.parse(p.next + 'T00:00:00Z') > t) continue;
      const a = A.raw(p.asset_id); if (!a || ['retired', 'disposed'].includes(a.status)) continue;
      if (WO().all().some((w) => w.plan_id === p.id && !['done', 'verified', 'cancelled'].includes(w.status))) continue;
      const w = woCreate({ asset_id: p.asset_id, kind: p.kind, category: p.category, title: p.title, details: 'Raised by maintenance plan ' + p.id + ' (every ' + p.every_days + ' days)', priority: 'normal' }, SYS, { plan_id: p.id });
      p.runs++; p.last_wo = w.id; p.next = iso(Date.parse(p.next + 'T00:00:00Z') + p.every_days * DAY).slice(0, 10); PM().put(p); raised.push(w.id);
    }
    const low = ST().all().filter((s) => s.qty <= s.reorder_point).map((s) => s.id);
    return { raised, below_reorder: low };
  }
  const run = guardOf(app, 'eam.tick', () => tick());
  let timer = null;
  function start() {
    if (opts.noTimer || timer) return;
    const loop = async () => { try { await run(); } finally { timer = setTimeout(loop, 15 * 60000); if (timer.unref) timer.unref(); } };
    timer = setTimeout(loop, 60000); if (timer.unref) timer.unref();
  }
  const woOne = (id) => woView(woGet(param(id, 'id')));
  return { view, assetView, woOne, woCreate, woAct, pmCreate, pmDelete, stockCreate, stockAdjust, deploy, poCreate, poAct, rtCreate, rtAct, aiAsk, settingsSave, settings: cfg, tick, ml, start };
}

function registerEam(srv, app, E) {
  srv.route('GET', '/eam', (ctx) => { ctx.need('viewer'); return E.view(ctx.query || {}, ctx.who); });
  srv.route('GET', '/eam/assets/:id', (ctx) => { ctx.need('viewer'); return E.assetView(ctx.params.id); });
  srv.route('GET', '/eam/wo/:id', (ctx) => { ctx.need('viewer'); return E.woOne(ctx.params.id); });
  srv.route('POST', '/eam/wo', (ctx) => { ctx.need('operator'); return E.woCreate(ctx.body, ctx.who); }, { maxBody: 16384 });
  for (const a of ['assign', 'start', 'complete', 'verify', 'cancel', 'comment']) srv.route('POST', '/eam/wo/:id/' + a, (ctx) => { ctx.need('operator'); return E.woAct(ctx.params.id, a, ctx.body, ctx.who); }, { maxBody: 16384 });
  srv.route('POST', '/eam/pm', (ctx) => { ctx.need('operator'); return E.pmCreate(ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('POST', '/eam/pm/:id/delete', (ctx) => { ctx.need('operator'); return E.pmDelete(ctx.params.id, ctx.who); });
  srv.route('POST', '/eam/stock', (ctx) => { ctx.need('operator'); return E.stockCreate(ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('POST', '/eam/stock/:id/adjust', (ctx) => { ctx.need('operator'); return E.stockAdjust(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/eam/deploy', (ctx) => { ctx.need('operator'); return E.deploy(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/eam/po', (ctx) => { ctx.need('operator'); return E.poCreate(ctx.body, ctx.who); }, { maxBody: 65536 });
  for (const a of ['approve', 'reject', 'order', 'receive']) srv.route('POST', '/eam/po/:id/' + a, (ctx) => { ctx.need('operator'); return E.poAct(ctx.params.id, a, ctx.body, ctx.who); }, { maxBody: 65536 });
  srv.route('POST', '/eam/retire', (ctx) => { ctx.need('operator'); return E.rtCreate(ctx.body, ctx.who); }, { maxBody: 8192 });
  for (const a of ['approve', 'reject']) srv.route('POST', '/eam/retire/:id/' + a, (ctx) => { ctx.need('admin'); return E.rtAct(ctx.params.id, a, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/eam/ai/ask', (ctx) => { ctx.need('operator'); return E.aiAsk(ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('GET', '/eam/settings', (ctx) => { ctx.need('admin'); return E.settings(); });
  srv.route('POST', '/eam/settings', (ctx) => { ctx.need('admin'); return E.settingsSave(ctx.body, ctx.who); }, { maxBody: 32768 });
  E.start();
}

module.exports = { createEam, registerEam, WO_KINDS, CATS, ROLES };
