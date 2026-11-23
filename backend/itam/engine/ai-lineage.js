// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body } = require('./check');
/*
 * AI Data Lineage ({P} = /api/itam, page ai-lineage.html): which AI can reach which data store, and which data classes those stores
 * hold - AI actors (left) -> data stores (middle) -> data classes (right). REPORT ONLY, built from what Data Security Posture
 * (engine/data-posture.js collect()) already read; no model is called, nothing is changed. Every edge carries `basis`: why it is
 * drawn, from which source. Only real actors are drawn:
 *   1. AI apps from the SIEM's Shadow AI register (GET /shadow-ai/register): sanctioned / tolerated apps may receive their
 *      allowed_classes (edge kind "allowed", to the class); any app with DLP incidents let through in 30 days (GET /shadow-ai/signals)
 *      gets an edge per class actually sent (kind "sent", weight = incidents)
 *   2. Microsoft 365 Copilot - only when the SIEM's Microsoft Graph sync (GET /m365/graph, subscribedSkus) shows a Copilot SKU with
 *      seats assigned: Copilot answers from what the signed-in user can open, so it reaches the SharePoint / Teams / OneDrive stores
 *      (kind "reach"). No licence data = not drawn, and the notes say why
 *   3. the platform's own AI engineers, from their read-only tools (engine/approve-scopes.js ENGINEERS and the modules below):
 *      AI PDPL Consultant  engine/pdpl.js personal-data discovery - every database it scanned (dictionary + sampled match COUNTS)  "reads"
 *      AI Oracle DBA       engine/db-health.js - Oracle databases, fixed monitoring SELECTs, no table data                    "metadata"
 *      AI Database Administrator  engine/db-inventory.js + engine/sqldba.js - SQL Server / PostgreSQL / MySQL, no table data   "metadata"
 *      the other AI engineers read device configuration, performance and logs - no data store in this view (listed in not_drawn)
 * Stores: SharePoint sites, Teams-connected sites, OneDrive, file-share roots, databases, AWS / Azure / OCI stores, with their
 * classes (store -> class edges, weight = files / objects / columns). Classes: personal (identity / contact), financial, health,
 * credentials, employment, confidential, other.
 * Roles: viewer = stores grouped by type (no store, file or person name); operator / admin = store names (audited named read).
 * Readable: at most `max` store nodes (default 14); the rest are grouped per type as "+N more".
 *   GET /ai-lineage     viewer   ?max=4..40
 */
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const CLASS = { personal: 'Personal (identity / contact)', financial: 'Financial', health: 'Health', credentials: 'Credentials / secrets', employment: 'Employment', confidential: 'Confidential', other: 'Other' };
const CAT2CLASS = { identity: 'personal', contact: 'personal', financial: 'financial', health: 'health', credentials: 'credentials', employment: 'employment', other: 'other' };
const TYPE_LABEL = { sharepoint: 'SharePoint sites', teams: 'Teams-connected sites', onedrive: 'OneDrive', fileshare: 'File-share roots', 'db:oracle': 'Oracle databases', 'db:mssql': 'SQL Server databases', 'db:postgres': 'PostgreSQL databases', 'db:mysql': 'MySQL databases',
  'cloud:azure': 'Azure storage accounts', 'cloud:aws': 'AWS S3 buckets', 'cloud:oci': 'OCI buckets', 'cloud:other': 'Other cloud stores' };
const M365 = ['sharepoint', 'teams', 'onedrive'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n || 200);
const hid = (p, v) => p + crypto.createHash('sha256').update(String(v)).digest('hex').slice(0, 12);
const has = (f) => { try { require.resolve(f); return true; } catch (e) { return false; /* not installed: that engineer is not drawn */ } };

function createAiLineage(app, opts = {}) {
  const now = opts.now || Date.now;
  const DP = () => opts.posture || (app.addons && app.addons.dataPosture) || null;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };

  async function view(who, q = {}) {
    const P = DP(), named = (RANK[String(who.role || '').toLowerCase()] || 0) >= RANK.operator, max = q.max || 14;
    if (!P) throw httpErr(409, 'Data Security Posture (engine/data-posture.js) is not installed - run the update; the lineage is built from what it reads');
    const C = await P.collect(who), notes = [], not_drawn = [];
    /* ---- stores with their classes */
    const S = new Map(), classOf = (k) => CAT2CLASS[P.CATEGORY[k] || 'other'] || 'other';
    const store = (id, type, label, extra) => S.get(id) || S.set(id, Object.assign({ id, type, label: s(label, 200), cls: {}, findings: 0 }, extra || {})).get(id);
    for (const st of C.stores) { const x = store(st.id, st.type, st.label, { unit: 'file' }); for (const r of C.rows.filter((y) => y.store === st)) { x.findings++; for (const c of new Set(r.kinds.map(classOf))) x.cls[c] = (x.cls[c] || 0) + 1; } }
    for (const d of C.dbs) { const x = store(d.id, d.type, d.label, { unit: 'column', engine: d.engine, discovered: d.discovered }); for (const k of Object.keys(d.kinds)) { const c = classOf(k); x.cls[c] = (x.cls[c] || 0) + d.kinds[k]; x.findings += d.kinds[k]; } }
    for (const c of C.cloudStores) { const x = store(c.id, c.type, c.label, { unit: 'object', public: c.public, in_kingdom: c.in_kingdom }); for (const k of Object.keys(c.kinds)) { const n = Number(c.kinds[k]) || 0; if (!n) continue; const cl = classOf(k); x.cls[cl] = (x.cls[cl] || 0) + n; x.findings += n; } }
    /* ---- actors and their edges to stores (sid) or straight to classes (cls) */
    const A = [], E = [];
    const actor = (key, label, type, detail) => { const a = { id: hid('a.', key), key, label: s(label, 120), type, detail: detail || {} }; A.push(a); return a; };
    if (C.src.shadow_ai.measured) {
      const sent = new Map();
      for (const x of C.sig.incidents || []) { if (!x.left || !(x.classes || []).length) continue; const k = x.app || 'name:' + s(x.app_name, 80); const e = sent.get(k) || sent.set(k, { app: x.app, name: x.app_name, n: 0, cls: {}, src: new Set() }).get(k); e.n++; for (const c of x.classes) e.cls[c] = (e.cls[c] || 0) + 1; e.src.add(s(x.source, 20)); }
      const reg = new Map(C.reg.map((r) => [r.id, r]));
      const ids = new Set(C.reg.filter((r) => r.status === 'sanctioned' || r.status === 'tolerated').map((r) => r.id).concat([...sent.keys()]));
      for (const id of ids) {
        const r = reg.get(id) || {}, sx = sent.get(id), status = r.status || 'unreviewed';
        const a = actor('app:' + id, r.name || (sx && sx.name) || id, 'ai-app', { status, vendor: s(r.vendor, 80), category: s(r.category, 40), owner: named ? s(r.owner, 120) || null : undefined, source: 'Shadow AI register (SIEM)' });
        if (status === 'sanctioned' || status === 'tolerated') for (const c of r.allowed_classes || []) E.push({ from: a.id, cls: CLASS[c] ? c : 'other', kind: 'allowed', weight: 0, basis: status + ' in the Shadow AI register' + (named && r.owner ? ' (owner ' + s(r.owner, 120) + ')' : '') + ': it may receive ' + (CLASS[c] || c) + ' data' });
        if (sx) for (const c of Object.keys(sx.cls)) E.push({ from: a.id, cls: CLASS[c] ? c : 'other', kind: 'sent', weight: sx.cls[c], basis: sx.cls[c] + ' DLP incident(s) in 30 days let through with ' + (CLASS[c] || c) + ' data (' + [...sx.src].join(', ') + ', Shadow AI signals)' });
      }
    } else notes.push('AI apps are not drawn: ' + (C.src.shadow_ai.reason || 'the Shadow AI DLP data is not available'));
    // Microsoft 365 Copilot
    if (C.src.m365_directory.measured || (C.graph && Array.isArray(C.graph.licenses))) {
      const lic = (C.graph.licenses || []).filter((l) => /copilot/i.test(String(l.sku || '')) && !/github/i.test(String(l.sku || '')));
      const seats = lic.reduce((a, l) => a + (Number(l.total) || 0), 0), assigned = lic.reduce((a, l) => a + (Number(l.consumed) || 0), 0);
      if (!Array.isArray(C.graph.licenses)) notes.push('Microsoft 365 Copilot is not judged: the Graph sync did not return the licences (LicenseManagement.Read.All or Organization.Read.All)');
      else if (!lic.length || !assigned) notes.push('Microsoft 365 Copilot is not drawn: no Copilot licence with seats assigned in subscribedSkus');
      else {
        const users = Array.isArray(C.graph.users && C.graph.users.list) ? C.graph.users.list.filter((u) => (u.skus || []).some((k) => /copilot/i.test(String(k)) && !/github/i.test(String(k)))).length : null;
        const a = actor('m365-copilot', 'Microsoft 365 Copilot', 'copilot', { skus: lic.map((l) => s(l.sku, 80)), seats, assigned, licensed_users: users, source: 'Microsoft Graph subscribedSkus (SIEM GET /m365/graph)' });
        const reach = [...S.values()].filter((x) => M365.includes(x.type) && x.findings > 0);
        for (const x of reach) E.push({ from: a.id, sid: x.id, kind: 'reach', weight: x.findings, basis: 'Copilot answers from the content the signed-in user can open: ' + assigned + ' of ' + seats + ' Copilot seat(s) assigned (' + lic.map((l) => s(l.sku, 80)).join(', ') + '); this ' + (x.type === 'onedrive' ? 'OneDrive' : 'site') + ' holds ' + x.findings + ' file(s) with personal data or credentials (SharePoint / OneDrive discovery)' });
        const quiet = [...S.values()].filter((x) => M365.includes(x.type) && !x.findings).length;
        if (quiet) notes.push('Copilot also reaches ' + quiet + ' SharePoint / OneDrive store(s) where the discovery found nothing - not drawn');
        if (!reach.length) notes.push('Copilot is licensed, but the SharePoint / OneDrive discovery has found no store with personal data yet' + (C.src.m365_files.measured ? '' : ' (' + (C.src.m365_files.reason || 'not run') + ')'));
      }
    } else notes.push('Microsoft 365 Copilot is not judged: ' + (C.src.m365_directory.reason || 'Microsoft 365 is not connected to the SIEM'));
    // the platform's own AI engineers
    const dbs = [...S.values()].filter((x) => x.type.startsWith('db:'));
    if (app.addons && app.addons.pdpl) {
      const reach = dbs.filter((x) => x.discovered);
      if (reach.length) { const a = actor('eng:pdpl', 'AI PDPL Consultant', 'ai-engineer', { scope: 'platform', source: 'engine/pdpl.js personal-data discovery' });
        for (const x of reach) E.push({ from: a.id, sid: x.id, kind: 'reads', weight: x.findings, basis: 'Personal-data discovery (engine/pdpl.js) read this database read-only: the data dictionary and, where the login may read a table, 50 values tested inside the helper - only the number of matches is kept, never a value' }); }
      else not_drawn.push('AI PDPL Consultant: no database scanned yet');
    }
    if (app.addons && app.addons.dbHealth) {
      const reach = dbs.filter((x) => x.engine === 'oracle');
      if (reach.length) { const a = actor('eng:dba', 'AI Oracle DBA', 'ai-engineer', { scope: 'eng:dba', source: 'engine/db-health.js' });
        for (const x of reach) E.push({ from: a.id, sid: x.id, kind: 'metadata', weight: 0, basis: 'Database Health (engine/db-health.js): fixed read-only monitoring SELECTs (instance, tablespaces, sessions, backups); an account with more than monitoring rights is refused - no table data is read' }); }
      else not_drawn.push('AI Oracle DBA: no Oracle database known yet');
    }
    if (has('./sqldba')) {
      const reach = dbs.filter((x) => ['mssql', 'postgres', 'mysql'].includes(x.engine));
      if (reach.length) { const a = actor('eng:sqldba', 'AI Database Administrator', 'ai-engineer', { scope: 'infra', source: 'engine/db-inventory.js + engine/sqldba.js' });
        for (const x of reach) E.push({ from: a.id, sid: x.id, kind: 'metadata', weight: 0, basis: 'Database inventory (engine/db-inventory.js): server version, sessions, database sizes and backups through fixed SELECTs with a read-only login - no table data is read' }); }
      else not_drawn.push('AI Database Administrator: no SQL Server / PostgreSQL / MySQL database known yet');
    }
    const SC = require('./approve-scopes').ENGINEERS;
    not_drawn.push('Other AI engineers (' + Object.keys(SC).filter((k) => k !== 'eng:dba').map((k) => SC[k][1]).join(', ') + ') read device configuration, performance and logs - no data store in this view');
    /* ---- which stores are drawn, grouping the rest (viewer: every store grouped by type) */
    const linked = new Set(E.filter((e) => e.sid).map((e) => e.sid));
    const cand = [...S.values()].filter((x) => x.findings > 0 || linked.has(x.id)).sort((a, b) => b.findings - a.findings || a.label.localeCompare(b.label));
    const shown = named ? cand.slice(0, max) : [], node = new Map(), groups = new Map();
    for (const x of shown) node.set(x.id, { id: hid('s.', x.id), column: 'store', type: x.type, label: x.label, count: x.findings, unit: x.unit, detail: { type: TYPE_LABEL[x.type] || x.type, public: x.public, in_kingdom: x.in_kingdom }, cls: Object.assign({}, x.cls), members: 1 });
    for (const x of cand.slice(shown.length)) {
      const g = groups.get(x.type) || groups.set(x.type, { id: hid('g.', x.type), column: 'store', type: x.type, label: '', count: 0, unit: x.unit, detail: { type: TYPE_LABEL[x.type] || x.type }, cls: {}, members: 0, group: true }).get(x.type);
      g.members++; g.count += x.findings; for (const c of Object.keys(x.cls)) g.cls[c] = (g.cls[c] || 0) + x.cls[c]; node.set(x.id, g);
    }
    for (const g of groups.values()) g.label = (named ? '+' + g.members + ' more ' : g.members + ' ') + (TYPE_LABEL[g.type] || g.type);
    /* ---- edges: actor -> store node, actor -> class, store node -> class; merged when grouped */
    const out = new Map(), addE = (from, to, kind, weight, basis) => { const k = from + '>' + to + '>' + kind; const e = out.get(k); if (e) { e.weight += weight; e.merged++; } else out.set(k, { id: hid('e.', k), from, to, kind, weight, basis, merged: 1 }); };
    const usedCls = new Map(), cnode = (c) => { if (!usedCls.has(c)) usedCls.set(c, { id: 'c.' + c, column: 'class', type: 'class', label: CLASS[c] || c, count: 0 }); return usedCls.get(c); };
    for (const e of E) {
      if (e.cls) { const c = cnode(e.cls); if (e.kind === 'sent') c.count += e.weight; addE(e.from, c.id, e.kind, e.weight, e.basis); continue; }
      const n = node.get(e.sid); if (!n) continue;
      addE(e.from, n.id, e.kind, e.weight, n.group ? e.basis.replace(/this (database|site|OneDrive)/, 'these stores') : e.basis);
    }
    const nodes = new Map(); for (const n of node.values()) nodes.set(n.id, n);
    for (const n of nodes.values()) for (const c of Object.keys(n.cls)) { const cn = cnode(c); cn.count += n.cls[c]; addE(n.id, cn.id, 'holds', n.cls[c], n.cls[c] + ' ' + n.unit + '(s) holding ' + (CLASS[c] || c) + ' data (' + (n.type.startsWith('db:') ? 'personal-data discovery' : n.type.startsWith('cloud:') ? 'cloud data discovery' : n.type === 'fileshare' ? 'file-share scan' : 'SharePoint / OneDrive discovery') + ')'); }
    for (const e of out.values()) if (e.merged > 1) e.basis += ' (' + e.merged + ' stores merged into this group)';
    const actorsUsed = A.filter((a) => [...out.values()].some((e) => e.from === a.id));
    const storeNodes = [...nodes.values()].map((n) => ({ id: n.id, column: 'store', type: n.type, label: n.label, count: n.count, unit: n.unit, group: !!n.group, members: n.members, detail: n.detail }));
    const order = ['personal', 'health', 'financial', 'credentials', 'employment', 'confidential', 'other'];
    const classNodes = [...usedCls.values()].sort((a, b) => order.indexOf(a.id.slice(2)) - order.indexOf(b.id.slice(2)));
    if (named) audit(who, 'ai.lineage.read', 'all', { actors: actorsUsed.length, stores: storeNodes.length });
    return { generated_at: new Date(now()).toISOString(), named, max,
      nodes: actorsUsed.map((a) => ({ id: a.id, column: 'actor', type: a.type, label: a.label, detail: a.detail })).concat(storeNodes, classNodes),
      edges: [...out.values()].map((e) => ({ id: e.id, from: e.from, to: e.to, kind: e.kind, weight: e.weight, basis: e.basis })),
      legend: { sent: 'data actually sent (DLP incidents let through)', allowed: 'allowed by the Shadow AI register', reach: 'can reach (Copilot answers from what the user can open)', reads: 'reads read-only (match counts, never a value)', metadata: 'reads metadata only (no table data)', holds: 'the store holds this class' },
      notes, not_drawn,
      empty: actorsUsed.length ? null : 'No AI actor reaches a data store yet. Connect the Shadow AI DLP data (DLP / web-filter logs or the AI DLP browser extension) and Microsoft 365 to the SIEM, and run the SharePoint / OneDrive and database discovery - nothing is drawn until a source has reported.',
      note: 'An edge says an AI can reach or did receive a class of data - an indicator for a person to confirm, not proof that data was misused.' };
  }
  return { view };
}

function registerAiLineage(srv, app, X) {
  const L = X && X.view ? X : createAiLineage(app, X || {});
  app.addons = app.addons || {}; app.addons.aiLineage = L;
  srv.route('GET', '/ai-lineage', (ctx) => { ctx.need('viewer'); const q = body(ctx.query || {}).int('max', { min: 4, max: 40 }).done(); return L.view(ctx.who, q); });
  return L;
}

module.exports = { createAiLineage, registerAiLineage, CLASS };
