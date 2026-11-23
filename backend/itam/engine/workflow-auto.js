// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');
const { untrusted } = require('./ai-guard');
/*
 * Workflow Automation ({P} = /api/itam; Command & Leadership -> Workflow Automation): what the business functions (CISO office, risk,
 * audit, HR, administration, GRC, IT governance, the DPO) need from the IT infrastructure teams (network, servers - Windows / Linux /
 * Solaris -, databases, security engineering, identity & access, backup & DR, desktop & endpoint, applications), as tracked requests:
 *   catalogue    29 request types (CATALOGUE), each with its team, kind and SLA hours; a change or an access request is approved first
 *                by a team lead or an administrator who is not the requester (four-eyes) - nothing here changes a system: the team does
 *                the work in its own tools, this records who asked, who approved, who did it, the evidence and who accepted it
 *   lifecycle    awaiting_approval -> open -> in_progress -> fulfilled -> closed (accepted by the requesting side, never by the person who
 *                fulfilled it) | returned (with a reason) -> in_progress again; rejected (with a reason); cancelled (by the requester)
 *   evidence     where the platform already holds the records (backups, patches, hardening, databases, privileged access, joiners and
 *                leavers, vulnerabilities, certificates, DR, assets, device management), "Collect evidence" assembles them into a pack:
 *                record counts, the latest update and up to 20 rows of ALLOW-LISTED fields (never credentials), fingerprinted SHA-256.
 *                A source the platform has no records for says so - it is never shown as compliant. The team can add references/notes.
 *   automation   scheduled requests (weekly / monthly / quarterly) are raised by the platform on their date with the evidence pack
 *                attached; overdue requests are escalated to Notification & Escalation (source "requests"); a background job
 *                (guardOf 'workflow.tick') does both.
 *   ML           (from this platform's own request history - never invented: below its minimum it says "not enough history")
 *                route suggestion for a free-text need (multinomial naive Bayes over past requests, 20+; the catalogue's words before
 *                that), turnaround per type (median / p80, 5+), breach risk of each open request (of closed requests of the same type
 *                - else team - still open at this age, the share that missed their SLA, 5+), on-time rate per team and person
 *                (Beta(1,1)), assignment suggestion (fewest open requests weighted by on-time rate), duplicates (Jaccard >= 0.6 on the
 *                words of open requests to one team), recurring demand (same type and function 3+ times in 90 days) -> a proposed schedule
 *   flow (rev 2) where the time goes and what comes next, per team (counts only - no names): the median hours in each stage of the
 *                life of a request, from its own history (waiting for approval, waiting to be started, the work, waiting for the requester
 *                to accept; 5+ samples a stage) and the stage that takes longest (the bottleneck); rework (returned / fulfilled, 5+);
 *                weekly demand over 12 weeks, next week's forecast (Holt's linear smoothing, 4+ weeks with requests) against the weekly
 *                throughput (median of the last 4 weeks) - the backlog grows when demand exceeds it; the expected wait for a new request
 *                (Little's law: open / weekly throughput); automation candidates per type (volume x steady turnaround x evidence the
 *                platform already collects, 5+ fulfilled) - a schedule or an auto-evidence pack takes the manual work out
 *   attention    attention(who): what needs one person, read by the role briefs of My Workspace (CISO, IT Manager, Head of Risk)
 *   AI           drafts the team's response from the request and its evidence summary (app.provider: budget, redaction, untrusted
 *                data rule); labelled a draft, it changes nothing - a person edits and fulfils.
 * Membership (admin, Settings): the people of each function and team and each team's leads. A function with no members configured
 * accepts any signed-in person, and the request says the function is declared, not verified. A team with no members is worked by
 * an administrator. Service and AI identities never approve, fulfil or accept.
 *
 *   GET  /workflow                               viewer   catalogue, my requests, my team queue, KPIs, ML (requests of others: admin)
 *   GET  /workflow/attention                     viewer   what needs this person (attention below) - for the workspaces and Risks & Actions
 *   POST /workflow/classify                      any      {text} -> suggested type and team (nothing stored)
 *   POST /workflow/requests                      any      {type, from, title, details, target?, priority?, due?, team?}     audited
 *   POST /workflow/requests/:id/approve|reject   operator {note? | reason}  team lead / admin, not the requester              audited
 *   POST /workflow/requests/:id/assign           operator {assignee}  team member / lead / admin                             audited
 *   POST /workflow/requests/:id/start            operator team member                                                         audited
 *   POST /workflow/requests/:id/evidence         operator {kind: auto | reference | note, text?}  team member                 audited
 *   POST /workflow/requests/:id/fulfil           operator {response}  team member, not the requester                         audited
 *   POST /workflow/requests/:id/accept|return    any      {note? | reason}  requester / function member, not the fulfiller    audited
 *   POST /workflow/requests/:id/cancel           any      {reason}  the requester or an admin                                 audited
 *   POST /workflow/requests/:id/comment          any      {text}  a participant                                               audited
 *   POST /workflow/requests/:id/ai-draft         operator team member: a draft response                                       audited
 *   POST /workflow/schedules | /schedules/:id/delete   operator  {type, from, title, details, every, next}                     audited
 *   GET|POST /workflow/settings                  admin    {functions, teams, leads, escalate}                                 audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const H = 3600000, DAY = 24 * H;
const FUNCS = { ciso: 'CISO office', risk: 'Risk management', audit: 'Audit (internal / IT / cyber)', hr: 'Human resources', admin: 'Administration', grc: 'GRC & compliance', governance: 'IT governance', dpo: 'Data protection (DPO)' };
const TEAMS = { network: 'Network team', servers: 'Server team (Windows / Linux / Solaris)', dba: 'Database team (DBA)', security: 'Security engineering', identity: 'Identity & access (AD)', backup: 'Backup & DR', endpoint: 'Desktop & endpoint', apps: 'Applications' };
const KINDS = { evidence: 'Evidence', report: 'Report', change: 'Change', access: 'Access', assessment: 'Assessment', info: 'Request' };
const APPROVAL = new Set(['change', 'access', 'assessment']);
const ALL = Object.keys(FUNCS);
// [id, title, from[], team, kind, sla hours, evidence sources[], page]
const CATALOGUE = [
  ['fw-rule-review', 'Firewall rule review evidence', ['ciso', 'audit', 'grc'], 'network', 'evidence', 72, ['network'], 'network-config-audit.html'],
  ['net-config-backup', 'Network device configuration backups', ['audit', 'grc'], 'network', 'evidence', 72, ['network'], 'ncm.html'],
  ['net-change', 'Network change (firewall rule, VLAN, route)', ['ciso', 'admin'], 'network', 'change', 48, [], 'network-dashboard.html'],
  ['server-hardening', 'Server hardening status (CIS baseline)', ['ciso', 'audit', 'grc'], 'servers', 'evidence', 72, ['hardening'], 'hardening.html'],
  ['patch-compliance', 'Patch compliance report', ['ciso', 'risk', 'audit', 'governance'], 'servers', 'report', 72, ['patching'], 'desktop-patches.html'],
  ['server-provision', 'New server (Windows / Linux / Solaris)', ['admin', 'governance'], 'servers', 'change', 120, [], 'servers.html'],
  ['server-health', 'Server availability and capacity report', ['governance', 'risk'], 'servers', 'report', 72, ['servers'], 'server-availability.html'],
  ['kpi-pack', 'Monthly IT operations KPI pack', ['governance', 'admin'], 'servers', 'report', 120, ['servers', 'tickets'], 'report-center.html'],
  ['db-user-review', 'Database accounts and privileges review', ['audit', 'ciso', 'dpo'], 'dba', 'evidence', 72, ['databases'], 'db-audit.html'],
  ['db-audit-trail', 'Database audit trail evidence', ['audit', 'grc', 'dpo'], 'dba', 'evidence', 72, ['db_hardening'], 'db-audit.html'],
  ['db-backup-restore', 'Database backup and restore test', ['risk', 'audit'], 'dba', 'evidence', 120, ['backups', 'databases'], 'databases.html'],
  ['db-new', 'New database or schema', ['admin'], 'dba', 'change', 72, [], 'databases.html'],
  ['db-licence', 'Oracle licence position', ['governance', 'audit'], 'dba', 'report', 120, ['licences'], 'oracle-licences.html'],
  ['vuln-remediation', 'Critical vulnerability remediation status', ['ciso', 'risk'], 'security', 'report', 48, ['vulns'], 'vuln-dashboard.html'],
  ['sec-exception', 'Security exception (risk acceptance)', ['ciso', 'risk', 'grc'], 'security', 'assessment', 72, [], 'risk-control.html'],
  ['incident-rca', 'Incident root-cause report', ['ciso', 'risk'], 'security', 'report', 72, [], 'incident-response.html'],
  ['cert-status', 'Certificate expiry status', ['ciso', 'governance'], 'security', 'report', 72, ['certs'], 'certificates.html'],
  ['priv-access-list', 'Privileged accounts list', ['ciso', 'audit', 'grc'], 'identity', 'evidence', 48, ['privileged'], 'privileged-access.html'],
  ['access-review', 'User access review evidence', ['audit', 'grc', 'dpo'], 'identity', 'evidence', 72, ['privileged'], 'access-reviews.html'],
  ['joiner-access', 'New joiner - accounts and access', ['hr'], 'identity', 'access', 24, ['joiners'], 'hr-onboarding.html'],
  ['leaver-disable', 'Leaver - disable all accounts', ['hr'], 'identity', 'access', 4, ['joiners'], 'hr-offboarding.html'],
  ['mover-change', 'Role change (mover) - adjust access', ['hr'], 'identity', 'access', 24, ['joiners'], 'hr-movers.html'],
  ['backup-evidence', 'Backup success evidence', ['audit', 'risk', 'grc'], 'backup', 'evidence', 48, ['backups'], 'backup.html'],
  ['dr-test', 'DR test evidence', ['risk', 'audit', 'governance'], 'backup', 'evidence', 168, ['dr'], 'dr-studio.html'],
  ['asset-register', 'IT asset register extract', ['audit', 'governance', 'risk'], 'endpoint', 'report', 72, ['assets'], 'inventory.html'],
  ['endpoint-compliance', 'Endpoint protection and encryption status', ['ciso', 'audit'], 'endpoint', 'evidence', 72, ['mdm'], 'mdm.html'],
  ['app-access', 'Application access or change', ['admin', 'hr'], 'apps', 'access', 48, [], 'applications.html'],
  ['dpia-input', 'Technical input for a DPIA or data flow', ['dpo', 'grc'], 'apps', 'assessment', 120, [], 'pdpl-dpia.html'],
  ['other', 'Other request to an IT team', ALL, '', 'info', 72, [], '']
].map(([id, title, from, team, kind, sla_h, sources, page]) => ({ id, title, from, team, kind, sla_h, sources, page, approval: APPROVAL.has(kind) }));
const TYPE = Object.fromEntries(CATALOGUE.map((c) => [c.id, c]));
// what the platform already holds, per evidence source: the collections and the page that shows them
const SOURCES = {
  network: { label: 'Network devices and their configuration backups', cols: ['disc_devices', 'netops_sync'] },
  hardening: { label: 'Server hardening checks', cols: ['hardening_history'] },
  patching: { label: 'Patch status', cols: ['desk_patch', 'me_ec_patches'] },
  servers: { label: 'Server health', cols: ['server_os_health'] },
  databases: { label: 'Database inventory and health targets', cols: ['db_inventory', 'db_health_targets'] },
  db_hardening: { label: 'Database hardening and audit settings', cols: ['db_hardening'] },
  backups: { label: 'Backup platforms and protected objects', cols: ['backup_platforms', 'backup_objects'] },
  licences: { label: 'Licences and Oracle licence reports', cols: ['licences', 'ora_lic_reports'] },
  vulns: { label: 'Vulnerability scan findings', cols: ['vulnscan_findings'] },
  certs: { label: 'Certificate endpoints', cols: ['cert_endpoints'] },
  privileged: { label: 'Privileged access requests and role assignments', cols: ['pam_requests', 'role_assignments'] },
  joiners: { label: 'Joiners, leavers and movers', cols: ['onboarding', 'offboarding', 'movers'] },
  dr: { label: 'DR tests and recovery points', cols: ['dr_history', 'dr_rpo'] },
  assets: { label: 'IT asset register', cols: ['assets'] },
  mdm: { label: 'Device management inventory', cols: ['mdm_inventory'] },
  tickets: { label: 'Service desk tickets', cols: ['me_tickets'] }
};
// only these fields of a record ever leave its collection in an evidence pack (no credentials, no free text bodies)
const SAFE = ['id', 'name', 'host', 'hostname', 'ip', 'os', 'version', 'status', 'state', 'severity', 'result', 'kind', 'type', 'platform', 'db', 'instance', 'title', 'vendor', 'model', 'site', 'user', 'updated_at', 'at', 'ts', 'last_seen', 'expires', 'not_after', 'due'];
const TIME_F = ['updated_at', 'at', 'ts', 'last_seen', 'created_at'];
const PRI = ['low', 'normal', 'high', 'urgent'], PRI_F = { low: 2, normal: 1, high: 0.5, urgent: 0.25 };
const ACTIVE = ['awaiting_approval', 'open', 'in_progress', 'returned'];
const EVERY = { weekly: 7, monthly: 30, quarterly: 91 };
const STOP = new Set('a an the of and or for to in on at by with from is are be this that our we need please any all as it its into per - / ( )'.split(' '));
const words = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9؀-ۿ]+/g, ' ').split(' ').filter((w) => w.length > 2 && !STOP.has(w));
const jaccard = (a, b) => { const A = new Set(a), B = new Set(b); if (!A.size || !B.size) return 0; let i = 0; for (const x of A) if (B.has(x)) i++; return i / (A.size + B.size - i); };
const q = (arr, p) => { if (!arr.length) return null; const s = arr.slice().sort((x, y) => x - y); return Math.round(s[Math.min(s.length - 1, Math.floor(p * s.length))] * 10) / 10; };
const low = (s) => String(s || '').toLowerCase();
const clip = (s, n) => String(s === undefined || s === null ? '' : s).slice(0, n);

function createWorkflow(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const R = () => store.collection('wf_requests'), S = () => store.collection('wf_schedules'), C = () => store.collection('wf_cfg');
  const iso = (t) => new Date(t === undefined ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'workflow.' + action, target, detail }); };
  const cfg = () => Object.assign({ functions: {}, teams: {}, leads: {}, escalate: true, version: 0 }, C().get('cfg') || {});
  const inList = (l, u) => (l || []).some((x) => low(x) === low(u));
  const isAdmin = (who) => who.role === 'admin';
  const memberOfTeam = (who, team) => inList(cfg().teams[team], who.user) || inList(cfg().leads[team], who.user);
  const leadOf = (who, team) => inList(cfg().leads[team], who.user);
  const teamWorker = (who, team) => isAdmin(who) || (who.role === 'operator' && memberOfTeam(who, team));
  const fnMember = (who, fn) => inList(cfg().functions[fn], who.user);
  const fnOpen = (fn) => !(cfg().functions[fn] || []).length;
  const requesterSide = (who, r) => low(r.requester) === low(who.user) || fnMember(who, r.from);
  const participant = (who, r) => isAdmin(who) || requesterSide(who, r) || memberOfTeam(who, r.team) || low(r.assignee) === low(who.user);
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const get = (id) => { const r = R().get(String(id || '')); if (!r) throw httpErr(404, 'request not found'); return r; };
  const hist = (r, who, action, note) => { r.history = (r.history || []).concat({ at: iso(), by: who.user, action, note: note ? clip(note, 1000) : undefined }).slice(-200); r.updated_at = iso(); };
  const nextId = () => { const y = new Date(now()).getUTCFullYear(), c = store.collection('counters'), k = 'wf-' + y, n = ((c.get(k) || {}).n || 0) + 1; c.put({ id: k, n }); return 'REQ-' + y + '-' + String(n).padStart(4, '0'); };
  const hours = (a, b) => (Date.parse(b) - Date.parse(a)) / H;

  /* ---- evidence from what the platform already holds */
  function collect(keys) {
    const parts = [];
    for (const k of keys) {
      const src = SOURCES[k]; if (!src) continue;
      for (const col of src.cols) {
        let rows = []; try { rows = store.collection(col).all(); } catch (e) { rows = []; /* collection not present on this install: reported as no records */ }
        let latest = null; const sample = [];
        for (const r of rows) {
          for (const f of TIME_F) { const t = Date.parse(r[f]); if (t && (!latest || t > latest)) latest = t; }
          if (sample.length < 20) { const o = {}; for (const f of SAFE) { const v = r[f]; if (v !== undefined && v !== null && typeof v !== 'object') o[f] = clip(v, 120); } if (Object.keys(o).length) sample.push(o); }
        }
        parts.push({ source: k, label: src.label, collection: col, records: rows.length, latest: latest ? iso(latest) : null, sample, note: rows.length ? null : 'the platform holds no records here yet - not evidence of compliance; the team attaches evidence instead' });
      }
    }
    const pack = { collected_at: iso(), parts };
    pack.sha256 = crypto.createHash('sha256').update(JSON.stringify(parts)).digest('hex');
    return pack;
  }

  /* ---- create */
  function create(b0, who, sys) {
    const b = body(b0 || {}).oneOf('type', Object.keys(TYPE), { required: true }).oneOf('from', ALL, { required: true })
      .str('title', { required: true, max: 200 }).str('details', { required: true, max: 5000 }).str('target', { max: 300 })
      .oneOf('priority', PRI).str('due', { max: 30 }).oneOf('team', Object.keys(TEAMS)).done();
    const t = TYPE[b.type], team = t.team || b.team;
    if (!team) throw httpErr(400, 'team: an "Other" request needs the IT team it is for (Suggest picks one from what you wrote)');
    if (!t.from.includes(b.from)) throw httpErr(400, 'from: "' + t.title + '" is requested by ' + t.from.map((f) => FUNCS[f]).join(', '));
    const verified = fnMember(who, b.from);
    if (!sys && !verified && !fnOpen(b.from) && !isAdmin(who)) throw httpErr(403, 'you are not a member of ' + FUNCS[b.from] + ' (Workflow Automation -> Settings)');
    const pri = b.priority || 'normal', created = now();
    let due = created + t.sla_h * PRI_F[pri] * H;
    if (b.due) { const d = Date.parse(b.due); if (!d) throw httpErr(400, 'due must be a date'); if (d < created) throw httpErr(400, 'due must be in the future'); due = Math.min(due, d); }
    const r = { id: nextId(), type: t.id, kind: t.kind, from: b.from, from_verified: !!(verified || sys), team, title: b.title.trim(), details: b.details.trim(), target: b.target || '',
      priority: pri, sla_h: Math.round(t.sla_h * PRI_F[pri] * 10) / 10, due: iso(due), status: t.approval ? 'awaiting_approval' : 'open', requester: who.user, requester_role: who.role,
      created_at: iso(created), updated_at: iso(created), assignee: null, evidence: [], comments: [], history: [], schedule: sys ? sys.schedule : null };
    hist(r, who, 'created', sys ? 'raised by schedule ' + sys.schedule : null);
    if (sys && t.sources.length && r.status === 'open') { r.evidence.push(Object.assign({ kind: 'auto', by: 'system:workflow', at: iso() }, { pack: collect(t.sources) })); hist(r, { user: 'system:workflow' }, 'evidence', 'collected automatically'); }
    R().put(r);
    audit(who, 'create', r.id, { type: r.type, from: r.from, team: r.team, priority: pri, approval: t.approval, schedule: r.schedule || null });
    return shape(r, who);
  }

  /* ---- transitions */
  function act(id, action, b0, who) {
    const r = get(id), t = TYPE[r.type];
    const need = (ok, msg) => { if (!ok) throw httpErr(403, msg); };
    const state = (...s) => { if (!s.includes(r.status)) throw httpErr(409, 'the request is ' + r.status.replace('_', ' ') + ' - ' + action + ' is not possible now'); };
    let detail = {};
    if (action === 'approve' || action === 'reject') {
      person(who, 'approves'); state('awaiting_approval');
      need(isAdmin(who) || (who.role === 'operator' && leadOf(who, r.team)), 'a lead of ' + TEAMS[r.team] + ' or an administrator approves');
      need(low(who.user) !== low(r.requester), 'the requester cannot approve their own request (four-eyes)');
      const b = action === 'approve' ? body(b0 || {}).str('note', { max: 1000 }).done() : body(b0 || {}).str('reason', { required: true, max: 1000 }).done();
      r.approval = { decision: action === 'approve' ? 'approved' : 'rejected', by: who.user, at: iso(), note: b.note || b.reason || '' };
      r.status = action === 'approve' ? 'open' : 'rejected'; hist(r, who, action === 'approve' ? 'approved' : 'rejected', b.note || b.reason);
    } else if (action === 'assign') {
      person(who, 'assigns'); state('open', 'in_progress', 'returned'); need(teamWorker(who, r.team), 'a member of ' + TEAMS[r.team] + ' or an administrator assigns');
      const b = body(b0 || {}).str('assignee', { required: true, max: 100, re: /^[A-Za-z0-9._@-]{2,100}$/, msg: 'assignee must be a user name' }).done();
      need(memberOfTeam({ user: b.assignee }, r.team) || ((cfg().teams[r.team] || []).length === 0 && isAdmin(who)), b.assignee + ' is not a member of ' + TEAMS[r.team]);
      need(low(b.assignee) !== low(r.requester), 'the requester cannot be assigned their own request');
      r.assignee = b.assignee; if (r.status === 'open') r.status = 'in_progress'; hist(r, who, 'assigned', b.assignee); detail = { assignee: b.assignee };
    } else if (action === 'start') {
      person(who, 'works the request'); state('open', 'returned', 'in_progress'); need(teamWorker(who, r.team), 'a member of ' + TEAMS[r.team] + ' works it');
      need(low(who.user) !== low(r.requester), 'the requester cannot work their own request');
      r.assignee = who.user; r.status = 'in_progress'; hist(r, who, 'started');
    } else if (action === 'evidence') {
      person(who, 'adds evidence'); state('open', 'in_progress', 'returned'); need(teamWorker(who, r.team), 'a member of ' + TEAMS[r.team] + ' adds evidence');
      const b = body(b0 || {}).oneOf('kind', ['auto', 'reference', 'note'], { required: true }).str('text', { max: 3000 }).done();
      if (b.kind === 'auto') { if (!t.sources.length) throw httpErr(409, 'the platform holds no records for "' + t.title + '" - attach a reference or a note'); r.evidence.push({ kind: 'auto', by: who.user, at: iso(), pack: collect(t.sources) }); }
      else { if (!b.text || !b.text.trim()) throw httpErr(400, 'text: the reference (document, ticket, file location) or the note'); r.evidence.push({ kind: b.kind, by: who.user, at: iso(), text: b.text.trim(), sha256: crypto.createHash('sha256').update(b.text.trim()).digest('hex') }); }
      r.evidence = r.evidence.slice(-50); hist(r, who, 'evidence', b.kind); detail = { kind: b.kind };
    } else if (action === 'fulfil') {
      person(who, 'fulfils'); state('in_progress', 'open', 'returned'); need(teamWorker(who, r.team), 'a member of ' + TEAMS[r.team] + ' fulfils it');
      need(low(who.user) !== low(r.requester), 'the requester cannot fulfil their own request');
      const b = body(b0 || {}).str('response', { required: true, max: 8000 }).done();
      if (t.kind === 'evidence' && !r.evidence.length) throw httpErr(409, 'an evidence request is fulfilled with evidence: collect it or attach a reference first');
      r.response = b.response.trim(); r.fulfilled_by = who.user; r.fulfilled_at = iso(); r.status = 'fulfilled'; if (!r.assignee) r.assignee = who.user;
      hist(r, who, 'fulfilled'); detail = { on_time: Date.parse(r.fulfilled_at) <= Date.parse(r.due) };
    } else if (action === 'accept' || action === 'return') {
      person(who, action === 'accept' ? 'accepts' : 'returns'); state('fulfilled');
      need(requesterSide(who, r) || isAdmin(who), 'the requester or a member of ' + FUNCS[r.from] + ' decides');
      need(low(who.user) !== low(r.fulfilled_by), 'the person who fulfilled it cannot accept or return it (four-eyes)');
      const b = action === 'accept' ? body(b0 || {}).str('note', { max: 1000 }).done() : body(b0 || {}).str('reason', { required: true, max: 1000 }).done();
      if (action === 'accept') { r.status = 'closed'; r.closed_at = iso(); r.accepted_by = who.user; }
      else { r.status = 'returned'; r.returned = (r.returned || 0) + 1; }
      hist(r, who, action === 'accept' ? 'accepted' : 'returned', b.note || b.reason);
    } else if (action === 'cancel') {
      state('awaiting_approval', 'open', 'in_progress', 'returned'); need(low(who.user) === low(r.requester) || isAdmin(who), 'only the requester or an administrator cancels');
      const b = body(b0 || {}).str('reason', { required: true, max: 1000 }).done();
      r.status = 'cancelled'; r.closed_at = iso(); hist(r, who, 'cancelled', b.reason);
    } else if (action === 'comment') {
      need(participant(who, r), 'only the people on this request comment on it');
      const b = body(b0 || {}).str('text', { required: true, max: 2000 }).done();
      r.comments = (r.comments || []).concat({ at: iso(), by: who.user, text: b.text.trim() }).slice(-200); r.updated_at = iso();
    } else throw httpErr(404, 'unknown action');
    R().put(r); audit(who, action, r.id, Object.assign({ status: r.status, team: r.team }, detail));
    return shape(r, who);
  }

  /* ---- ML over this platform's own history */
  function stats() {
    const all = R().all(), t0 = now();
    const done = all.filter((r) => r.fulfilled_at), late = (r) => Date.parse(r.fulfilled_at) > Date.parse(r.due);
    const turnaround = {}; for (const c of CATALOGUE) { const h = done.filter((r) => r.type === c.id).map((r) => hours(r.created_at, r.fulfilled_at)); turnaround[c.id] = h.length >= 5 ? { n: h.length, median_h: q(h, 0.5), p80_h: q(h, 0.8) } : { n: h.length, median_h: null, why: 'not enough history (' + h.length + ' of 5 fulfilled)' }; }
    const beta = (L) => { const n = L.length, m = L.filter((r) => !late(r)).length; return { n, on_time: m, rate: Math.round(((m + 1) / (n + 2)) * 100) / 100 }; };
    const teams = Object.keys(TEAMS).map((k) => { const a = all.filter((r) => r.team === k); return Object.assign({ team: k, name: TEAMS[k], open: a.filter((r) => ACTIVE.includes(r.status)).length, overdue: a.filter((r) => ACTIVE.includes(r.status) && Date.parse(r.due) < t0).length }, beta(done.filter((r) => r.team === k))); });
    const people = {}; for (const r of all) if (r.assignee) { const p = people[low(r.assignee)] || (people[low(r.assignee)] = { user: r.assignee, open: 0, done: [] }); if (ACTIVE.includes(r.status)) p.open++; if (r.fulfilled_at && low(r.fulfilled_by) === low(r.assignee)) p.done.push(r); }
    const person = (u) => { const p = people[low(u)] || { user: u, open: 0, done: [] }; return Object.assign({ user: p.user, open: p.open }, beta(p.done)); };
    const risk = (r) => {
      const age = (t0 - Date.parse(r.created_at)) / H; let pool = done.filter((x) => x.type === r.type && hours(x.created_at, x.fulfilled_at) >= age), basis = 'type';
      if (pool.length < 5) { pool = done.filter((x) => x.team === r.team && hours(x.created_at, x.fulfilled_at) >= age); basis = 'team'; }
      if (pool.length < 5) return { p: null, why: 'not enough history (' + pool.length + ' comparable fulfilled requests, 5 needed)' };
      const m = pool.filter(late).length; return { p: Math.round((m / pool.length) * 100) / 100, why: m + ' of ' + pool.length + ' ' + basis + ' requests still open at ' + Math.round(age) + ' h went past their SLA' };
    };
    const suggestAssignee = (team) => { const mem = (cfg().teams[team] || []); if (!mem.length) return null; const sc = mem.map((u) => { const p = person(u); return Object.assign(p, { score: Math.round(((p.open + 1) / p.rate) * 100) / 100 }); }).sort((a, b) => a.score - b.score); return { user: sc[0].user, why: sc[0].open + ' open, on-time ' + Math.round(sc[0].rate * 100) + '% (' + sc[0].on_time + ' of ' + sc[0].n + ')', ranked: sc }; };
    const open = all.filter((r) => ACTIVE.includes(r.status)), dups = [];
    for (let i = 0; i < open.length; i++) for (let j = i + 1; j < open.length; j++) { const a = open[i], b = open[j]; if (a.team !== b.team) continue; const s = jaccard(words(a.title + ' ' + a.details), words(b.title + ' ' + b.details)); if (s >= 0.6) dups.push({ a: a.id, b: b.id, similarity: Math.round(s * 100) / 100 }); }
    const recent = all.filter((r) => !r.schedule && t0 - Date.parse(r.created_at) <= 90 * DAY), rec = {};
    for (const r of recent) { const k = r.type + '|' + r.from; (rec[k] = rec[k] || []).push(r); }
    const sch = S().all();
    const recurring = Object.entries(rec).filter(([k, L]) => L.length >= 3 && !sch.some((s) => s.type + '|' + s.from === k)).map(([k, L]) => { const [type, from] = k.split('|'); const gaps = L.map((r) => Date.parse(r.created_at)).sort().map((x, i, a) => i ? (x - a[i - 1]) / DAY : null).filter((x) => x != null); const g = q(gaps, 0.5); return { type, from, title: TYPE[type].title, function: FUNCS[from], count: L.length, every: g == null ? 'monthly' : g <= 10 ? 'weekly' : g <= 45 ? 'monthly' : 'quarterly', why: L.length + ' in 90 days, median gap ' + (g == null ? '?' : Math.round(g)) + ' days - schedule it and the evidence arrives on its own' }; });
    return { turnaround, teams, person, risk, suggestAssignee, duplicates: dups.slice(0, 50), recurring, flow: flow(all, t0) };
  }
  function flow(all, t0) {
    const at = (r, a) => { const e = (r.history || []).filter((x) => x.action === a); return e.length ? Date.parse(e[0].at) : null; };
    const lastAt = (r, a) => { const e = (r.history || []).filter((x) => x.action === a); return e.length ? Date.parse(e[e.length - 1].at) : null; };
    const STG = [['approval', 'waiting for approval'], ['start', 'waiting to be started'], ['work', 'the work'], ['accept', 'waiting for the requester to accept']];
    const durs = (L) => { const o = { approval: [], start: [], work: [], accept: [] };
      for (const r of L) { const c = Date.parse(r.created_at), ap = at(r, 'approved'), st = Math.min(at(r, 'started') || Infinity, at(r, 'assigned') || Infinity), fu = r.fulfilled_at ? Date.parse(r.fulfilled_at) : null, ac = lastAt(r, 'accepted');
        if (ap) o.approval.push((ap - c) / H); const base = ap || c; if (isFinite(st) && st >= base) o.start.push((st - base) / H); if (fu && isFinite(st) && fu >= st) o.work.push((fu - st) / H); if (ac && fu && ac >= fu) o.accept.push((ac - fu) / H); }
      const out = {}; for (const [k] of STG) out[k] = o[k].length >= 5 ? Math.round(q(o[k], 0.5) * 10) / 10 : null; return out; };
    const week = (t) => Math.floor((t0 - t) / (7 * DAY));
    const holt = (y) => { let l = y[0], b = y.length > 1 ? y[1] - y[0] : 0; for (let i = 1; i < y.length; i++) { const pl = l; l = 0.5 * y[i] + 0.5 * (l + b); b = 0.3 * (l - pl) + 0.7 * b; } return Math.max(0, Math.round((l + b) * 10) / 10); };
    const teams = Object.keys(TEAMS).map((k) => {
      const L = all.filter((r) => r.team === k); if (!L.length) return null;
      const d = durs(L), known = STG.filter(([x]) => d[x] != null), bott = known.length ? known.reduce((a, z) => (d[z[0]] > d[a[0]] ? z : a)) : null;
      const fulfilled = L.filter((r) => r.fulfilled_at).length, returned = L.reduce((a, r) => a + (r.history || []).filter((x) => x.action === 'returned').length, 0);
      const wk = Array(12).fill(0), done = Array(12).fill(0); for (const r of L) { const w = week(Date.parse(r.created_at)); if (w >= 0 && w < 12) wk[11 - w]++; if (r.fulfilled_at) { const f = week(Date.parse(r.fulfilled_at)); if (f >= 0 && f < 12) done[11 - f]++; } }
      const active = wk.filter((x) => x > 0).length, fc = active >= 4 ? holt(wk) : null, thr = q(done.slice(-4), 0.5), open = L.filter((r) => ACTIVE.includes(r.status)).length;
      return { team: k, name: TEAMS[k], stages: d, bottleneck: bott ? { stage: bott[0], label: bott[1], hours: d[bott[0]] } : null,
        rework: fulfilled >= 5 ? { returned, fulfilled, rate: Math.round(returned / fulfilled * 100) } : null,
        weekly: wk, next_week: fc, throughput: thr, growth: fc != null ? Math.round((fc - thr) * 10) / 10 : null, open, wait_weeks: thr > 0 ? Math.round(open / thr * 10) / 10 : null,
        why: fc == null ? 'forecast needs 4 weeks with requests (' + active + ')' : 'Holt linear smoothing over 12 weeks; throughput = median fulfilled a week over the last 4' };
    }).filter(Boolean);
    const cand = CATALOGUE.filter((c) => c.id !== 'other').map((c) => { const L = all.filter((r) => r.type === c.id), f = L.filter((r) => r.fulfilled_at); if (f.length < 5) return null;
      const h = f.map((r) => hours(r.created_at, r.fulfilled_at)), med = q(h, 0.5), iqr = q(h, 0.75) - q(h, 0.25), steady = med > 0 ? Math.max(0, 1 - iqr / med) : 0, n90 = L.filter((r) => t0 - Date.parse(r.created_at) <= 90 * DAY).length, auto = (c.sources || []).length > 0;
      const score = Math.round(n90 * (0.5 + steady) * (auto ? 1.5 : 1) * 10) / 10;
      return { type: c.id, title: c.title, team: TEAMS[c.team], n90, median_h: Math.round(med * 10) / 10, steady: Math.round(steady * 100), auto_evidence: auto, score,
        how: auto ? 'schedule it and let the platform attach the evidence pack' : 'schedule it, or write a runbook so it is done the same way each time' }; }).filter(Boolean).sort((a, b) => b.score - a.score).slice(0, 6);
    return { teams, candidates: cand, stages: Object.fromEntries(STG) };
  }

  /* route suggestion: naive Bayes over the platform's requests (20+), the catalogue's own words before that */
  function classify(b0) {
    const b = body(b0 || {}).str('text', { required: true, max: 3000 }).done(), w = words(b.text);
    if (!w.length) throw httpErr(400, 'text: describe what you need in a few words');
    const hist0 = R().all().filter((r) => r.type && r.team);
    const vocab = new Set(), byType = {};
    if (hist0.length >= 20) {
      for (const r of hist0) { const k = r.type === 'other' ? 'other:' + r.team : r.type, ws = words(r.title + ' ' + r.details); const s = byType[k] || (byType[k] = { n: 0, w: {}, total: 0 }); s.n++; for (const x of ws) { s.w[x] = (s.w[x] || 0) + 1; s.total++; vocab.add(x); } }
      const V = vocab.size || 1, scores = Object.entries(byType).map(([k, s]) => { let lp = Math.log(s.n / hist0.length); for (const x of w) lp += Math.log(((s.w[x] || 0) + 1) / (s.total + V)); return { k, lp }; }).sort((a, z) => z.lp - a.lp);
      const mx = scores[0].lp, ex = scores.map((s) => Math.exp(s.lp - mx)), sum = ex.reduce((a, z) => a + z, 0);
      const best = scores[0].k, conf = Math.round((ex[0] / sum) * 100) / 100, type = best.startsWith('other:') ? 'other' : best, team = best.startsWith('other:') ? best.slice(6) : TYPE[best].team;
      return { type, team, title: TYPE[type].title, team_name: TEAMS[team], confidence: conf, method: 'naive Bayes over ' + hist0.length + ' requests on this platform', alternatives: scores.slice(1, 3).map((s, i) => ({ type: s.k.startsWith('other:') ? 'other' : s.k, p: Math.round((ex[i + 1] / sum) * 100) / 100 })) };
    }
    const sc = CATALOGUE.filter((c) => c.id !== 'other').map((c) => { const cw = words(c.title + ' ' + KINDS[c.kind] + ' ' + TEAMS[c.team]); const hit = w.filter((x) => cw.some((y) => y === x || (x.length > 4 && y.startsWith(x.slice(0, 5))))).length; return { c, hit }; }).sort((a, z) => z.hit - a.hit);
    if (!sc[0].hit) return { type: 'other', team: null, title: TYPE.other.title, confidence: 0, method: 'catalogue words (fewer than 20 requests to learn from)', why: 'nothing in the catalogue matches - choose the team' };
    return { type: sc[0].c.id, team: sc[0].c.team, title: sc[0].c.title, team_name: TEAMS[sc[0].c.team], confidence: Math.round((sc[0].hit / w.length) * 100) / 100, method: 'catalogue words (fewer than 20 requests to learn from)', alternatives: sc.slice(1, 3).filter((x) => x.hit).map((x) => ({ type: x.c.id, hits: x.hit })) };
  }

  /* ---- what a person sees */
  function can(r, who) {
    const c = [], human = isHuman(who.user), worker = teamWorker(who, r.team), mine = low(who.user) === low(r.requester);
    if (!human) return c;
    if (r.status === 'awaiting_approval' && !mine && (isAdmin(who) || (who.role === 'operator' && leadOf(who, r.team)))) c.push('approve', 'reject');
    if (['open', 'in_progress', 'returned'].includes(r.status) && worker && !mine) c.push('start', 'assign', 'evidence', 'fulfil', 'ai-draft');
    if (r.status === 'fulfilled' && (requesterSide(who, r) || isAdmin(who)) && low(who.user) !== low(r.fulfilled_by)) c.push('accept', 'return');
    if (ACTIVE.includes(r.status) && (mine || isAdmin(who))) c.push('cancel');
    if (participant(who, r)) c.push('comment');
    return c;
  }
  function shape(r, who, st) {
    const o = Object.assign({}, r, { type_title: (TYPE[r.type] || {}).title, team_name: TEAMS[r.team], from_name: FUNCS[r.from], page: (TYPE[r.type] || {}).page || '', can: can(r, who),
      overdue: ACTIVE.includes(r.status) && Date.parse(r.due) < now(), auto_evidence: !!((TYPE[r.type] || {}).sources || []).length });
    if (st && ACTIVE.includes(r.status)) o.breach_risk = st.risk(r);
    return o;
  }
  function view(who) {
    const st = stats(), all = R().all().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))), c = cfg(), t0 = now();
    const mine = all.filter((r) => requesterSide(who, r)), myTeams = Object.keys(TEAMS).filter((k) => memberOfTeam(who, k));
    const queue = all.filter((r) => (isAdmin(who) || myTeams.includes(r.team)) && (ACTIVE.includes(r.status) || r.status === 'fulfilled'));
    const approvals = all.filter((r) => r.status === 'awaiting_approval' && low(r.requester) !== low(who.user) && (isAdmin(who) || (who.role === 'operator' && leadOf(who, r.team))));
    const visible = isAdmin(who) ? all : all.filter((r) => participant(who, r));
    const active = all.filter((r) => ACTIVE.includes(r.status));
    return { at: iso(t0), me: { user: who.user, role: who.role, functions: ALL.filter((f) => fnMember(who, f)), teams: myTeams, leads: Object.keys(TEAMS).filter((k) => leadOf(who, k)) },
      functions: FUNCS, teams: TEAMS, kinds: KINDS, priorities: PRI, every: Object.keys(EVERY), open_functions: ALL.filter(fnOpen),
      catalogue: CATALOGUE.map((x) => Object.assign({}, x, { turnaround: st.turnaround[x.id], sources: x.sources.map((s) => SOURCES[s].label) })),
      kpis: { open: active.length, awaiting_approval: all.filter((r) => r.status === 'awaiting_approval').length, overdue: active.filter((r) => Date.parse(r.due) < t0).length,
        fulfilled_waiting_acceptance: all.filter((r) => r.status === 'fulfilled').length, closed_30d: all.filter((r) => r.status === 'closed' && t0 - Date.parse(r.closed_at) <= 30 * DAY).length,
        on_time_rate: (() => { const d = all.filter((r) => r.fulfilled_at); return d.length ? Math.round((d.filter((r) => Date.parse(r.fulfilled_at) <= Date.parse(r.due)).length / d.length) * 100) : null; })(),
        scheduled: S().all().length },
      mine: mine.slice(0, 300).map((r) => shape(r, who, st)), queue: queue.slice(0, 300).map((r) => shape(r, who, st)), approvals: approvals.map((r) => shape(r, who, st)),
      all: isAdmin(who) ? visible.slice(0, 500).map((r) => shape(r, who, st)) : [],
      ml: { flow: st.flow, teams: st.teams, duplicates: st.duplicates.filter((d) => visible.some((r) => r.id === d.a)), recurring: st.recurring,
        assign: Object.fromEntries(myTeams.concat(isAdmin(who) ? Object.keys(TEAMS) : []).map((k) => [k, st.suggestAssignee(k)])) },
      schedules: S().all().filter((s) => isAdmin(who) || low(s.owner) === low(who.user) || fnMember(who, s.from)),
      settings: isAdmin(who) ? { functions: c.functions, teams: c.teams, leads: c.leads, escalate: c.escalate, version: c.version } : null,
      ai: !!app.provider };
  }
  function detail(id, who) { const r = get(id); if (!participant(who, r)) throw httpErr(403, 'only the people on this request see it'); return shape(r, who, stats()); }

  /* ---- schedules: the platform raises the request on its date, with the evidence pack */
  function schedule(b0, who) {
    person(who, 'schedules requests'); if (who.role === 'viewer') throw httpErr(403, 'scheduling requests needs the operator role');
    const b = body(b0 || {}).oneOf('type', Object.keys(TYPE), { required: true }).oneOf('from', ALL, { required: true }).str('title', { required: true, max: 200 }).str('details', { required: true, max: 5000 })
      .oneOf('every', Object.keys(EVERY), { required: true }).str('next', { required: true, max: 30 }).oneOf('team', Object.keys(TEAMS)).done();
    const t = TYPE[b.type]; if (t.approval) throw httpErr(400, 'type: changes and access requests are not scheduled - each one is approved on its own');
    if (!t.from.includes(b.from)) throw httpErr(400, 'from: "' + t.title + '" is requested by ' + t.from.map((f) => FUNCS[f]).join(', '));
    if (!isAdmin(who) && !fnMember(who, b.from) && !fnOpen(b.from)) throw httpErr(403, 'you are not a member of ' + FUNCS[b.from]);
    if (!t.team && !b.team) throw httpErr(400, 'team: an "Other" schedule needs its team');
    const nx = Date.parse(b.next); if (!nx) throw httpErr(400, 'next must be a date');
    const s = { id: 'SCH-' + crypto.randomBytes(5).toString('hex'), type: b.type, from: b.from, team: t.team || b.team, title: b.title.trim(), details: b.details.trim(), every: b.every, next: iso(nx), owner: who.user, owner_role: who.role, created_at: iso(), runs: 0 };
    S().put(s); audit(who, 'schedule', s.id, { type: s.type, every: s.every, next: s.next }); return s;
  }
  function unschedule(id, who) {
    const s = S().get(String(id || '')); if (!s) throw httpErr(404, 'schedule not found');
    if (!isAdmin(who) && low(s.owner) !== low(who.user)) throw httpErr(403, 'only its owner or an administrator removes a schedule');
    S().remove(s.id); audit(who, 'unschedule', s.id, { type: s.type }); return { ok: true };
  }
  function settingsSave(b0, who) {
    if (!isAdmin(who)) throw httpErr(403, 'Workflow Automation settings are for administrators'); person(who, 'changes settings');
    const raw = b0 && typeof b0 === 'object' ? b0 : {}, isObj = (v) => v === undefined || (v && typeof v === 'object' && !Array.isArray(v));
    for (const k of ['functions', 'teams', 'leads']) if (!isObj(raw[k])) throw httpErr(400, k + ' must be an object of lists of user names');
    const b = Object.assign(body(raw).bool('escalate').int('version', { min: 0, required: true }).done(), { functions: raw.functions, teams: raw.teams, leads: raw.leads });   // the three maps are checked entry by entry below
    const c = cfg(); if (b.version !== c.version) throw httpErr(409, 'the settings were changed by someone else - reload');
    const users = (o, keys, name) => { const out = {}; for (const [k, v] of Object.entries(o || {})) { if (!keys.includes(k)) throw httpErr(400, name + ': unknown ' + k); if (!Array.isArray(v) || v.length > 100) throw httpErr(400, name + '.' + k + ' must be a list of up to 100 user names'); out[k] = [...new Set(v.map((u) => String(u).trim()))].filter(Boolean); const bad = out[k].find((u) => !/^[A-Za-z0-9._@-]{2,100}$/.test(u)); if (bad) throw httpErr(400, name + '.' + k + ': "' + clip(bad, 40) + '" is not a user name'); } return out; };
    const next = Object.assign({}, c, { id: 'cfg', version: c.version + 1, updated_by: who.user, updated_at: iso() });
    if (b.functions) next.functions = users(b.functions, ALL, 'functions'); if (b.teams) next.teams = users(b.teams, Object.keys(TEAMS), 'teams'); if (b.leads) next.leads = users(b.leads, Object.keys(TEAMS), 'leads');
    if (b.escalate !== undefined) next.escalate = b.escalate;
    C().put(next); audit(who, 'settings', 'workflow', { version: next.version, functions: Object.keys(next.functions).length, teams: Object.keys(next.teams).length }); return view(who).settings;
  }

  /* ---- AI: a draft response for the team; it changes nothing */
  async function aiDraft(id, who) {
    person(who, 'asks the AI'); const r = get(id);
    if (!teamWorker(who, r.team)) throw httpErr(403, 'a member of ' + TEAMS[r.team] + ' asks for a draft');
    const P = app.provider; if (!P) throw httpErr(409, 'AI is not configured on this server');
    const st = await P.status(); if (st.state !== 'ready') throw httpErr(409, 'AI is not ready: ' + (st.message || st.state));
    const ev = (r.evidence || []).map((e) => e.kind === 'auto' ? 'Platform evidence ' + e.at + ': ' + e.pack.parts.map((p) => p.label + ' / ' + p.collection + ': ' + p.records + ' records, latest ' + (p.latest || 'none')).join('; ') : e.kind + ' by ' + e.by + ': ' + clip(e.text, 600)).join('\n');
    const system = 'You are a senior IT infrastructure engineer answering a request from ' + FUNCS[r.from] + ' to the ' + TEAMS[r.team] + '. Draft a short, factual response: what was done or found, the evidence attached (only what is listed - never invent records, numbers or dates), what is missing, and next steps. If the evidence is not enough to answer, say exactly what the team still has to provide. Plain text, under 250 words.';
    const prompt = 'Request type: ' + (TYPE[r.type] || {}).title + ' (' + KINDS[r.kind] + '), priority ' + r.priority + ', due ' + r.due + '.\n' + untrusted('request', 'Title: ' + r.title + '\nDetails: ' + clip(r.details, 4000) + (r.target ? '\nTarget: ' + clip(r.target, 300) : ''))
      + '\n' + untrusted('evidence', ev || 'No evidence attached yet.');
    const out = await P.call({ system, prompt, who, feature: 'itam.workflow_draft' }); if (!out || out.ok === false) throw httpErr(409, (out && out.message) || 'the AI did not answer');
    const text = String(out.text || '').slice(0, 6000);
    audit(who, 'ai_draft', r.id, { model: out.model || null, chars: text.length });
    return { ok: true, label: 'AI draft - check it against the evidence before you fulfil', text, model: out.model || null };
  }

  /* ---- what needs this person, for the role briefs (My Workspace: CISO, IT Manager, Head of Risk): requests waiting for their
     approval (never their own), the queue of the teams they work or lead (overdue, likely to miss the SLA), and what they or their
     function raised (late with the IT teams, results waiting for their acceptance). Priorities carry their points as [reason, points]. */
  function attention(who) {
    const wv = view(who), ACT = ['awaiting_approval', 'open', 'in_progress', 'returned'], P = [];
    const urgent = (r) => r.priority === 'urgent' || r.priority === 'high', pg = (r) => 'workflow-automation.html#req=' + r.id, d16 = (x) => String(x).slice(0, 16).replace('T', ' ');
    const q = wv.queue.filter((r) => ['open', 'in_progress', 'returned'].includes(r.status)), over = q.filter((r) => r.overdue), risk = q.filter((r) => !r.overdue && r.breach_risk && r.breach_risk.p != null && r.breach_risk.p >= 0.6);
    const acc = wv.mine.filter((r) => r.can.includes('accept')), ap = wv.approvals, raised = wv.mine.filter((r) => ACT.includes(r.status)), late = raised.filter((r) => r.overdue && !q.includes(r));
    for (const r of ap.slice(0, 8)) P.push({ kind: 'Request approval', ref: r.id, text: clip(r.title, 140) + ' - ' + r.type_title + ', from ' + r.from_name + ' (' + r.requester + ')', page: pg(r), why: [['a business request waiting for your approval', 45]].concat(urgent(r) ? [[r.priority + ' priority', 10]] : []) });
    for (const r of over.slice(0, 8)) P.push({ kind: 'Request overdue', ref: r.id, text: clip(r.title, 140) + ' - ' + r.team_name + ', due ' + d16(r.due), page: pg(r), why: [['a request to the IT team past its due date', 40]].concat(r.escalated_at ? [['escalated', 10]] : []) });
    for (const r of risk.slice(0, 5)) P.push({ kind: 'Request at risk', ref: r.id, text: clip(r.title, 140) + ' - ' + r.team_name + ': ' + clip(r.breach_risk.why, 160), page: pg(r), why: [['likely to miss its SLA (' + Math.round(r.breach_risk.p * 100) + ' %)', 30]] });
    for (const r of late.slice(0, 8)) P.push({ kind: 'Request late', ref: r.id, text: clip(r.title, 140) + ' - with ' + r.team_name + ', due ' + d16(r.due), page: pg(r), why: [['raised by you or your function, late with the IT team', 35]].concat(urgent(r) ? [[r.priority + ' priority', 10]] : []) });
    for (const r of acc.slice(0, 5)) P.push({ kind: 'Request to accept', ref: r.id, text: clip(r.title, 140) + ' - fulfilled by ' + r.fulfilled_by, page: pg(r), why: [['a result waiting for your acceptance', 25]] });
    const T = wv.ml.teams;
    return { priorities: P, summary: { approvals: ap.length, queue_open: q.length, overdue: over.length, at_risk: risk.length, to_accept: acc.length, raised_open: raised.length, raised_late: late.length,
      functions: wv.me.functions, all_overdue: T.reduce((n, t) => n + t.overdue, 0), recurring: wv.ml.recurring.length,
      teams: T.filter((t) => t.open || t.n).map((t) => ({ team: t.team, name: t.name, open: t.open, overdue: t.overdue, n: t.n, on_time: t.on_time, rate: t.rate })),
      items: ap.concat(over, late, acc, q.filter((r) => !r.overdue), raised.filter((r) => !r.overdue)).filter((r, i, a) => a.indexOf(r) === i).slice(0, 6)
        .map((r) => ({ id: r.id, title: clip(r.title, 140), team: r.team_name, from: r.from_name, status: r.status, due: r.due, overdue: !!r.overdue })) } };
  }

  /* ---- background: scheduled requests, escalation of overdue ones */
  const SYS = { user: 'system:workflow', role: 'admin', ip: '' };
  function tick() {
    const t0 = now(), did = { raised: 0, escalated: 0 };
    for (const s of S().all()) {
      if (Date.parse(s.next) > t0) continue;
      try { create({ type: s.type, from: s.from, title: s.title, details: s.details, team: s.team }, { user: s.owner, role: s.owner_role || 'operator', ip: '' }, { schedule: s.id }); did.raised++; }
      catch (e) { if (app.log && app.log.every) app.log.every('workflow:schedule:' + s.id, 6 * H, 'warn', 'scheduled request not raised', { schedule: s.id, err: e.message }); }
      s.runs = (s.runs || 0) + 1; s.last = iso(t0); let nx = Date.parse(s.next); while (nx <= t0) nx += EVERY[s.every] * DAY; s.next = iso(nx); S().put(s);
    }
    if (cfg().escalate) for (const r of R().all((x) => ACTIVE.includes(x.status) && !x.escalated_at && Date.parse(x.due) < t0)) {
      r.escalated_at = iso(t0); hist(r, SYS, 'escalated', 'past its due date ' + r.due); R().put(r); audit(SYS, 'escalate', r.id, { team: r.team, due: r.due }); did.escalated++;
    }
    return did;
  }
  function signals() {
    return R().all((r) => ACTIVE.includes(r.status) && r.escalated_at).map((r) => ({ fp: 'requests:' + r.id, source: 'requests', ref: r.id, title: 'Request ' + r.id + ' to ' + TEAMS[r.team] + ' is overdue', text: clip(r.title, 200) + ' - from ' + FUNCS[r.from] + ', due ' + r.due, severity: r.priority === 'urgent' || r.priority === 'high' ? 3 : 2, condition: true }));
  }
  let timer = null;
  const run = guardOf(app, 'workflow.tick', () => tick());
  return { view, detail, attention, create, act, classify, schedule, unschedule, settingsSave, aiDraft, tick, signals, collect,
    start() { if (timer || opts.noTimer) return; setTimeout(run, 60000).unref(); timer = setInterval(run, 10 * 60000); timer.unref(); }, stop() { if (timer) clearInterval(timer); timer = null; } };
}

function registerWorkflow(srv, app, W) {
  srv.route('GET', '/workflow', (ctx) => { ctx.need('viewer'); return W.view(ctx.who); });
  srv.route('GET', '/workflow/requests/:id', (ctx) => { ctx.need('viewer'); return W.detail(ctx.params.id, ctx.who); });
  srv.route('GET', '/workflow/attention', (ctx) => { ctx.need('viewer'); return W.attention(ctx.who); });
  srv.route('POST', '/workflow/classify', (ctx) => { ctx.need('viewer'); return W.classify(ctx.body); }, { maxBody: 8192, anyRole: 'any requester classifies their own request text before raising it; nothing is stored' });
  srv.route('POST', '/workflow/requests', (ctx) => W.create(ctx.body, ctx.who), { maxBody: 16384, anyRole: 'any business requester (CISO office, auditors, HR) may have the viewer role - membership is checked in create' });
  for (const a of ['approve', 'reject', 'assign', 'start', 'evidence', 'fulfil']) srv.route('POST', '/workflow/requests/:id/' + a, (ctx) => { ctx.need('operator'); return W.act(ctx.params.id, a, ctx.body, ctx.who); }, { maxBody: 16384 });
  for (const a of ['accept', 'return', 'cancel', 'comment']) srv.route('POST', '/workflow/requests/:id/' + a, (ctx) => W.act(ctx.params.id, a, ctx.body, ctx.who), { maxBody: 8192, anyRole: 'the requesting side (often viewers) accepts, returns, cancels and comments - checked per request in act' });
  srv.route('POST', '/workflow/requests/:id/ai-draft', (ctx) => { ctx.need('operator'); return W.aiDraft(ctx.params.id, ctx.who); }, { maxBody: 1024 });
  srv.route('POST', '/workflow/schedules', (ctx) => { ctx.need('operator'); return W.schedule(ctx.body, ctx.who); }, { maxBody: 16384 });
  srv.route('POST', '/workflow/schedules/:id/delete', (ctx) => { ctx.need('operator'); return W.unschedule(ctx.params.id, ctx.who); });
  srv.route('GET', '/workflow/settings', (ctx) => { ctx.need('admin'); return W.view(ctx.who).settings; });
  srv.route('POST', '/workflow/settings', (ctx) => { ctx.need('admin'); return W.settingsSave(ctx.body, ctx.who); }, { maxBody: 65536 });
  W.start();
}

module.exports = { createWorkflow, registerWorkflow, CATALOGUE, FUNCS, TEAMS, SOURCES, SAFE };
