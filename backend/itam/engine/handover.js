// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * Staff handover ({P} = /api/itam): when an IT or cyber security employee leaves, one record holds everything they are
 * responsible for in the platform, who takes each part over, the access that must be removed, and their knowledge notes.
 *   1. scan       what the platform names after the person: assets they own or hold, business services (IT / business
 *                 owner), risks and actions they own, support contracts, domains, their job role and approval rights,
 *                 change / power plans they asked for that are still open, credentials they saved
 *   2. reassign   a successor per item (or for all); the successor ACCEPTS (or declines with a reason) - in person
 *   3. access     a removal checklist (platform account, job role, AD, privileged accounts, VPN, Microsoft 365, MFA,
 *                 shared passwords to rotate, badge, equipment), each item done or n/a with evidence - by someone other
 *                 than the leaver. The platform tracks this; it never disables an account or sets a password itself.
 *   4. notes      systems and duties, runbooks, open issues, vendor contacts, where secrets are kept (never the secrets:
 *                 text that looks like a password is refused)
 *   5. sign-off   the named manager (not the leaver, never a service identity) signs off when every item is accepted or
 *                 not applicable, every access item is closed and the notes exist. Only then the owner fields of assets,
 *                 business services, risks, actions, contracts and domains move to the successors - each one audited.
 * Personal data (PDPL): operators and administrators only; viewers are refused.
 * Routes:
 *   GET  /handover                          operator  list
 *   GET  /handover/people                   operator  names known to the platform (role assignments, owners) for pickers
 *   GET  /handover/:id                      operator
 *   POST /handover                          operator  {leaver, leaver_name?, team, last_day, manager, reason?}
 *   POST /handover/:id/scan                 operator  find what the leaver owns again (decisions already made are kept)
 *   POST /handover/:id/assign               operator  {keys[] | all:true, successor}   not the leaver as successor
 *   POST /handover/:id/items/:key/accept    operator  {note?}   only the named successor
 *   POST /handover/:id/items/:key/decline   operator  {reason}  only the named successor
 *   POST /handover/:id/items/:key/na        operator  {reason}  the manager: nothing to hand over
 *   POST /handover/:id/access/:aid          operator  {state: done|na|open, evidence?}   not the leaver
 *   PUT  /handover/:id/notes                operator  {systems, runbooks, issues, vendors, secrets_location, other}
 *   POST /handover/:id/signoff              operator  {comment?}   only the named manager (an administrator if the manager cannot)
 *   POST /handover/:id/cancel               operator  {reason}     the manager, the creator or an administrator
 */
const { body, param, bad } = require('./check');
const G = require('./ai-guard');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || '').trim());
const USER = /^[A-Za-z0-9][A-Za-z0-9 ._@\\-]{0,119}$/;
const TEAMS = ['IT Operations', 'Cyber Security', 'IT Governance', 'Applications', 'Other'];
const NOTE_FIELDS = ['systems', 'runbooks', 'issues', 'vendors', 'secrets_location', 'other'];
const ACCESS = [
  ['platform', (ZYB_ORG.short + ' platform account'), 'Identity & Sign-in → Users: disable the account on the last day (an administrator)'],
  ['ad', 'Active Directory account', 'disable the account (User Desktops -> HR Offboarding does it on the last day after two approvals); move it to the leavers OU; remove group memberships'],
  ['privileged', 'Privileged / admin accounts', 'domain admin, server local admin, network device, database (DBA), firewall and backup console accounts - disable or remove'],
  ['pam', 'PAM vault and shared accounts', 'remove from the PAM safes; rotate every shared password the person could see'],
  ['vpn', 'VPN and remote access', 'revoke the VPN account / certificate and any jump-host access'],
  ['m365', 'Microsoft 365', 'block sign-in, revoke sessions, convert or delegate the mailbox, move OneDrive data, remove licences'],
  ['mfa', 'MFA tokens and devices', 'remove the authenticator registrations; collect hardware tokens'],
  ['vendors', 'Vendor and cloud portals', 'support portals, registrars, cloud consoles, licensing portals - remove or transfer the login'],
  ['physical', 'Badge and physical access', 'deactivate the badge, data centre and server room access'],
  ['equipment', 'Equipment returned', 'laptop, phone, tokens and any asset the person holds (see the assets in this handover)'],
];

// a value written next to a secret word (password / passphrase / pwd / secret / community / PIN / key / token), in the
// "is" / "=" / ":" forms, that contains a digit = a credential; tokens and private keys the shared masker knows too.
// "the password is kept in CyberArk safe NET-FW" passes - that is where it is, which is what the notes should say.
const SECRET_NEAR = /\b(pass(?:word|wd|phrase|code)?s?|pwd|secret|community|pin|api[ _-]?key|token|psk|pre-shared[ -]key)\b\s*(?:is|was|=|:|-)?\s*["'`]?([^\s"'`]{6,})/gi;
// ... and "PSK for the Riyadh tunnel: <value>": the word, a few words, then ":" / "="
const SECRET_SEP = /\b(pass(?:word|wd|phrase|code)?s?|pwd|secret|community|pin|api[ _-]?key|token|psk|pre-shared[ -]key)\b[^:=\n]{0,40}[:=]\s*["'`]?([^\s"'`]{6,})/gi;
function looksSecret(t) {
  for (const m of [...String(t).matchAll(SECRET_NEAR), ...String(t).matchAll(SECRET_SEP)]) if (/\d/.test(m[2]) && !/^(\d{1,2}|safe|vault|folder|entry)$/i.test(m[2])) return true;
  return /\[(token|private key) removed\]/.test(G.redactSecrets(t));
}

function createHandover(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const col = store.collection('handovers');
  const iso = () => new Date(now()).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const c = (name) => store.collection(name);

  /* ---- what the platform names after the person. kind 'reassign' = an owner field that moves to the successor at
     sign-off; 'follow-up' = a responsibility only (a request stays the leaver's; the successor follows it up) */
  function scan(h) {
    const who = [h.leaver, h.leaver_name].filter(Boolean), mine = (v) => who.some((w) => same(v, w));
    const out = [], add = (o) => out.push(Object.assign({ state: 'pending', successor: '' }, o));
    for (const a of c('assets').all((x) => x.status !== 'disposed' && x.status !== 'retired')) for (const f of ['owner', 'custodian'])
      if (mine(a[f])) add({ key: `assets:${a.id}:${f}`, source: 'Asset', kind: 'reassign', label: `${a.name || a.asset_tag || a.id}`, detail: `${f === 'owner' ? 'owner' : 'holds it (custodian)'} · ${a.type || ''}${a.asset_tag ? ' · ' + a.asset_tag : ''}`, ref: a.id, field: f, coll: 'assets' });
    for (const s of c('ownership_services').all()) for (const f of ['it_owner', 'business_owner'])
      if (mine(s[f])) add({ key: `ownership_services:${s.id}:${f}`, source: 'Business service', kind: 'reassign', label: s.business_service || s.id, detail: f === 'it_owner' ? 'IT owner' : 'business owner', ref: s.id, field: f, coll: 'ownership_services' });
    for (const r of c('grc_risks').all((x) => x.status !== 'closed')) if (mine(r.owner)) add({ key: `grc_risks:${r.id}:owner`, source: 'Risk', kind: 'reassign', label: `${r.id} ${String(r.description || '').slice(0, 80)}`, detail: 'risk owner', ref: r.id, field: 'owner', coll: 'grc_risks' });
    for (const r of c('grc_actions').all((x) => x.status !== 'closed' && x.status !== 'done')) if (mine(r.owner)) add({ key: `grc_actions:${r.id}:owner`, source: 'GRC action', kind: 'reassign', label: `${r.id} ${String(r.description || '').slice(0, 80)}`, detail: `action owner${r.due ? ' · due ' + r.due : ''}`, ref: r.id, field: 'owner', coll: 'grc_actions' });
    for (const r of c('support_contracts').all()) if (mine(r.owner)) add({ key: `support_contracts:${r.id}:owner`, source: 'Support contract', kind: 'reassign', label: r.vendor ? `${r.vendor} ${r.contract_no || r.name || ''}`.trim() : r.id, detail: `contract owner${r.end ? ' · ends ' + r.end : ''}`, ref: r.id, field: 'owner', coll: 'support_contracts' });
    for (const r of c('dom_domains').all()) if (mine(r.owner)) add({ key: `dom_domains:${r.id}:owner`, source: 'Domain', kind: 'reassign', label: r.name || r.id, detail: `domain owner${r.expires ? ' · expires ' + r.expires : ''}`, ref: r.id, field: 'owner', coll: 'dom_domains' });
    for (const r of c('role_assignments').all()) if (mine(r.user)) {
      const role = c('job_roles').get(r.role_id) || {};
      add({ key: `role_assignments:${r.id}:role`, source: 'Job role', kind: 'follow-up', label: role.name || r.role_id, detail: (role.approves || []).length ? 'approves: ' + role.approves.join(', ') : 'portal functions of the role', ref: r.id });
    }
    for (const [name, label, open] of [['virt_changes', 'Virtualization change plan', ['proposed', 'approved']], ['virt_power', 'Power plan', ['proposed', 'approved', 'applied']]])
      for (const p of c(name).all((x) => open.includes(x.state) && mine(x.requested_by))) add({ key: `${name}:${p.id}:requested`, source: label, kind: 'follow-up', label: `${p.id} ${String(p.title || '').slice(0, 90)}`, detail: `asked by the leaver · ${p.state}`, ref: p.id });
    for (const v of c('disc_credentials').all()) if (mine(v.created_by) || mine(v.updated_by)) add({ key: `disc_credentials:${v.id}:creator`, source: 'Saved credential', kind: 'follow-up', label: v.label || v.id, detail: `${v.kind || 'login'} saved / changed by the leaver - rotate the password and re-save it`, ref: v.id });
    return out;
  }
  function merge(h) {
    const found = scan(h), prev = new Map((h.items || []).map((i) => [i.key, i]));
    // decisions already made are kept; items no longer found stay only if someone already acted on them
    const items = found.map((i) => (prev.has(i.key) ? Object.assign(i, pick(prev.get(i.key))) : i));
    for (const [k, i] of prev) if (!found.some((f) => f.key === k) && i.state !== 'pending') items.push(Object.assign({}, i, { gone: true }));
    return items;
  }
  const pick = (i) => { const o = {}; for (const k of ['state', 'successor', 'assigned_by', 'assigned_at', 'accepted_at', 'note', 'decline_reason', 'na_reason', 'applied']) if (i[k] !== undefined) o[k] = i[k]; return o; };

  function nextId() { const ct = c('counters'), n = ((ct.get('handover') || {}).n || 0) + 1; ct.put({ id: 'handover', n }); return 'HO-' + String(n).padStart(4, '0'); }
  function must(id) { const h = col.get(id); if (!h) throw httpErr(404, 'handover not found'); return h; }
  const open = (h) => { if (h.state !== 'open') throw httpErr(409, `the handover is ${h.state}`); };
  const isAdmin = (who) => who.role === 'admin';
  const leaverOf = (h, who) => same(h.leaver, who.user) || (h.leaver_name && same(h.leaver_name, who.user));
  const managerOf = (h, who) => same(h.manager, who.user);

  function create(b, who) {
    if (same(b.leaver, b.manager)) throw bad('manager: the manager who signs off cannot be the person leaving');
    if (isService(b.leaver) || isService(b.manager)) throw bad('leaver / manager must be named people, not service identities');
    const dup = col.all((x) => x.state === 'open' && same(x.leaver, b.leaver))[0];
    if (dup) throw httpErr(409, `an open handover already exists for ${b.leaver} (${dup.id})`);
    const accessCount = c('disc_credentials').all((v) => same(v.created_by, b.leaver) || same(v.updated_by, b.leaver)).length;
    const h = { id: nextId(), state: 'open', leaver: b.leaver, leaver_name: b.leaver_name || '', team: b.team, last_day: b.last_day, manager: b.manager, reason: b.reason || '',
      created_by: who.user, created_at: iso(), notes: {}, items: [],
      access: ACCESS.map(([id, name, how]) => ({ id, name, how: id === 'pam' && accessCount ? how + ` (${accessCount} credential(s) in the platform were saved by this person - see the items)` : how, state: 'open' })) };
    h.items = merge(h);
    col.put(h);
    audit(who, 'handover.create', h.id, { leaver: h.leaver, team: h.team, last_day: h.last_day, manager: h.manager, items: h.items.length });
    return view(h);
  }
  function rescan(id, who) {
    const h = must(id); open(h);
    const items = merge(h);
    col.patch(id, (x) => { x.items = items; x.scanned_at = iso(); return x; });
    audit(who, 'handover.scan', id, { items: items.length });
    return view(col.get(id));
  }
  function assign(id, b, who) {
    const h = must(id); open(h);
    if (same(b.successor, h.leaver) || (h.leaver_name && same(b.successor, h.leaver_name))) throw bad('successor: the person leaving cannot take over their own items');
    if (isService(b.successor)) throw bad('successor must be a named person');
    if (!(leaverOf(h, who) || managerOf(h, who) || isAdmin(who))) throw httpErr(403, 'only the leaver, their manager or an administrator assigns successors');
    const keys = b.all ? h.items.filter((i) => i.state === 'pending' || i.state === 'declined').map((i) => i.key) : b.keys || [];
    if (!keys.length) throw bad('keys: choose at least one item (or all)');
    const known = new Set(h.items.map((i) => i.key)), unknown = keys.filter((k) => !known.has(k));
    if (unknown.length) throw bad('keys: not in this handover: ' + unknown.slice(0, 5).join(', '));
    const at = iso();
    col.patch(id, (x) => { for (const i of x.items) if (keys.includes(i.key) && i.state !== 'accepted' && i.state !== 'na') { i.successor = b.successor; i.state = 'assigned'; i.assigned_by = who.user; i.assigned_at = at; delete i.decline_reason; } return x; });
    audit(who, 'handover.assign', id, { successor: b.successor, items: keys.length });
    return view(col.get(id));
  }
  function item(id, key, who, act, text) {
    const h = must(id); open(h);
    const i = h.items.find((x) => x.key === key); if (!i) throw httpErr(404, 'item not in this handover');
    if (act === 'na') {
      if (!(managerOf(h, who) || isAdmin(who))) throw httpErr(403, 'only the manager marks an item as nothing to hand over');
      if (leaverOf(h, who)) throw httpErr(403, 'the person leaving cannot close their own items');
    } else {
      if (i.state !== 'assigned') throw httpErr(409, i.state === 'pending' ? 'no successor has been named for this item yet' : `the item is ${i.state}`);
      if (!same(i.successor, who.user)) throw httpErr(403, `only ${i.successor} (the named successor) can ${act} this item`);
    }
    const at = iso();
    col.patch(id, (x) => { const y = x.items.find((z) => z.key === key);
      if (act === 'accept') { y.state = 'accepted'; y.accepted_at = at; y.note = text || ''; }
      else if (act === 'decline') { y.state = 'declined'; y.decline_reason = text; y.declined_by = who.user; y.declined_at = at; }
      else { y.state = 'na'; y.na_reason = text; y.na_by = who.user; y.na_at = at; }
      return x; });
    audit(who, 'handover.item.' + act, id, { item: key, successor: i.successor || '', text: text || '' });
    return view(col.get(id));
  }
  function access(id, aid, b, who) {
    const h = must(id); open(h);
    if (leaverOf(h, who)) throw httpErr(403, 'the person leaving cannot confirm their own access was removed');
    const a = h.access.find((x) => x.id === aid); if (!a) throw httpErr(404, 'checklist item not found');
    if (b.state === 'done' && !b.evidence) throw bad('evidence: say how it was done (ticket, change or note)');
    if (b.state === 'na' && !b.evidence) throw bad('evidence: say why it does not apply');
    col.patch(id, (x) => { const y = x.access.find((z) => z.id === aid); y.state = b.state; y.evidence = b.evidence || ''; y.by = who.user; y.at = iso(); return x; });
    audit(who, 'handover.access', id, { item: aid, state: b.state, evidence: b.evidence || '' });
    return view(col.get(id));
  }
  function notes(id, b, who) {
    const h = must(id); open(h);
    if (!(leaverOf(h, who) || managerOf(h, who) || isAdmin(who))) throw httpErr(403, 'only the leaver, their manager or an administrator writes the notes');
    for (const k of NOTE_FIELDS) if (b[k] && looksSecret(b[k])) throw bad(`${k}: this looks like it contains a password, key or token - write WHERE it is kept (PAM safe, vault entry), never the value`);
    col.patch(id, (x) => { x.notes = Object.assign({}, x.notes, b); x.notes_by = who.user; x.notes_at = iso(); return x; });
    audit(who, 'handover.notes', id, { fields: Object.keys(b) });   // the text itself stays in the record, not in the audit line
    return view(col.get(id));
  }
  function blockers(h) {
    const out = [];
    const left = h.items.filter((i) => i.state !== 'accepted' && i.state !== 'na');
    if (left.length) out.push(`${left.length} item(s) not accepted by a successor or marked nothing to hand over`);
    const acc = h.access.filter((a) => a.state !== 'done' && a.state !== 'na');
    if (acc.length) out.push(`access not closed: ${acc.map((a) => a.name).join(', ')}`);
    if (!h.notes || !String(h.notes.systems || '').trim()) out.push('the knowledge notes are empty (at least "systems and duties")');
    return out;
  }
  function signoff(id, b, who) {
    const h = must(id); open(h);
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot sign off a handover');
    if (leaverOf(h, who)) throw httpErr(403, 'the person leaving cannot sign off their own handover');
    if (!managerOf(h, who) && !isAdmin(who)) throw httpErr(403, `only the manager named on the handover (${h.manager}) or an administrator signs it off`);
    const block = blockers(h);
    if (block.length) throw Object.assign(httpErr(409, 'not ready to sign off: ' + block.join('; ')), { blockers: block });
    // move the owner fields: each record changed is audited with from / to; a record that has changed hands since is left
    const applied = [], skipped = [];
    for (const i of h.items.filter((x) => x.state === 'accepted' && x.kind === 'reassign')) {
      const rec = c(i.coll).get(i.ref);
      if (!rec || !same(rec[i.field], h.leaver) && !(h.leaver_name && same(rec[i.field], h.leaver_name))) { skipped.push(i.key); continue; }
      if (i.coll === 'assets' && app.assets && typeof app.assets.assign === 'function') app.assets.assign(i.ref, { [i.field]: i.successor }, who);
      else { c(i.coll).patch(i.ref, (x) => { x[i.field] = i.successor; x.updated_at = iso(); return x; }); audit(who, 'handover.reassign', i.ref, { collection: i.coll, field: i.field, from: rec[i.field], to: i.successor, handover: id }); }
      applied.push(i.key);
    }
    col.patch(id, (x) => { x.state = 'signed-off'; x.signoff = { by: who.user, role: who.role, at: iso(), comment: b.comment || '' };
      for (const y of x.items) if (applied.includes(y.key)) y.applied = true; else if (skipped.includes(y.key)) y.applied = 'changed since - not moved'; return x; });
    audit(who, 'handover.signoff', id, { leaver: h.leaver, reassigned: applied.length, skipped: skipped.length, comment: b.comment || '' });
    return view(col.get(id));
  }
  function cancel(id, reason, who) {
    const h = must(id); open(h);
    if (!(managerOf(h, who) || same(h.created_by, who.user) || isAdmin(who))) throw httpErr(403, 'only the manager, the person who opened it or an administrator cancels a handover');
    col.patch(id, (x) => { x.state = 'cancelled'; x.cancelled_by = who.user; x.cancelled_at = iso(); x.cancel_reason = reason; return x; });
    audit(who, 'handover.cancel', id, { reason });
    return view(col.get(id));
  }
  const view = (h) => Object.assign({}, h, { blockers: h.state === 'open' ? blockers(h) : [], progress: { items: h.items.length, done: h.items.filter((i) => i.state === 'accepted' || i.state === 'na').length, access: h.access.length, access_done: h.access.filter((a) => a.state === 'done' || a.state === 'na').length } });
  function list() { return col.all().sort((a, b2) => (a.created_at < b2.created_at ? 1 : -1)).map((h) => { const v = view(h); return { id: v.id, state: v.state, leaver: v.leaver, leaver_name: v.leaver_name, team: v.team, last_day: v.last_day, manager: v.manager, progress: v.progress, blockers: v.blockers.length, created_at: v.created_at }; }); }
  function people() {
    const s = new Set();
    for (const r of c('role_assignments').all()) if (r.user) s.add(r.user);
    for (const a of c('assets').all((x) => x.status !== 'disposed')) for (const f of ['owner', 'custodian']) if (a[f] && USER.test(a[f])) s.add(a[f]);
    return [...s].sort((a, b2) => a.localeCompare(b2)).slice(0, 2000);
  }
  return { create, rescan, assign, item, access, notes, signoff, cancel, list, people, get: (id) => view(must(id)), TEAMS, NOTE_FIELDS };
}

function registerHandover(srv, app, opts = {}) {
  const H = createHandover(app, opts);
  const person = (k, req) => [k, { required: req, max: 120, re: USER, msg: `${k} must be a user name (letters, digits, . _ @ - space)` }];
  srv.route('GET', '/handover', (ctx) => { ctx.need('operator'); return { handovers: H.list(), teams: H.TEAMS }; });
  srv.route('GET', '/handover/people', (ctx) => { ctx.need('operator'); return { people: H.people() }; });
  srv.route('GET', '/handover/:id', (ctx) => { ctx.need('operator'); return H.get(param(ctx.params.id)); });
  srv.route('POST', '/handover', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str(...person('leaver', true)).str('leaver_name', { max: 120 }).oneOf('team', H.TEAMS, { required: true }).date('last_day', { required: true })
      .str(...person('manager', true)).str('reason', { max: 500 }).done();
    return H.create(b, ctx.who);
  });
  srv.route('POST', '/handover/:id/scan', (ctx) => { ctx.need('operator'); return H.rescan(param(ctx.params.id), ctx.who); });
  srv.route('POST', '/handover/:id/assign', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str(...person('successor', true)).list('keys', { max: 2000, item: 'str', itemMax: 200 }).bool('all', { def: false }).done();
    return H.assign(param(ctx.params.id), b, ctx.who);
  });
  for (const act of ['accept', 'decline', 'na']) {
    srv.route('POST', '/handover/:id/items/:key/' + act, (ctx) => {
      ctx.need('operator');
      const b = act === 'accept' ? body(ctx.body).str('note', { max: 1000 }).done() : body(ctx.body).str('reason', { required: true, min: 5, max: 1000 }).done();
      const key = String(ctx.params.key || ''); if (!/^[a-z_]+:[A-Za-z0-9_.:-]{1,120}:[a-z_]+$/.test(key)) throw bad('key is not a valid item key');
      return H.item(param(ctx.params.id), key, ctx.who, act, act === 'accept' ? b.note : b.reason);
    });
  }
  srv.route('POST', '/handover/:id/access/:aid', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).oneOf('state', ['done', 'na', 'open'], { required: true }).str('evidence', { max: 1000 }).done();
    return H.access(param(ctx.params.id), param(ctx.params.aid, 'aid'), b, ctx.who);
  });
  srv.route('PUT', '/handover/:id/notes', (ctx) => {
    ctx.need('operator');
    let v = body(ctx.body); for (const k of H.NOTE_FIELDS) v = v.str(k, { max: 8000 });
    return H.notes(param(ctx.params.id), v.done(), ctx.who);
  });
  srv.route('POST', '/handover/:id/signoff', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('comment', { max: 1000 }).done(); return H.signoff(param(ctx.params.id), b, ctx.who); });
  srv.route('POST', '/handover/:id/cancel', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('reason', { required: true, min: 5, max: 500 }).done(); return H.cancel(param(ctx.params.id), b.reason, ctx.who); });
  (app.addons = app.addons || {}).handover = H;
  return H;
}

module.exports = { createHandover, registerHandover, ACCESS, TEAMS };
