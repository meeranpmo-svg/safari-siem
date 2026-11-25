// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');
/*
 * Aramco CCC - evidence collected by the platform and the submission pack ({P} = /api/itam), on top of engine/aramco-ccc.js.
 *   sources      a fixed catalogue of what the platform already holds (asset register and discovery scans, vulnerability scans,
 *                patching, backup, certificates, policies and GRC evidence, risks, privileged access, the directory). Collecting
 *                takes a SNAPSHOT of each: counts and dates only (never names or personal data), with a SHA-256 of the snapshot so
 *                the audit firm can check it was not changed. Collected daily and on demand; a source the platform does not hold
 *                yet says what to connect - never a 0 that reads as a result.
 *   matching     ML, local: TF-IDF over each control's title + requirement against each source's description and keywords;
 *                cosine similarity ranks the sources per control. A suggestion is only a suggestion: a person links a source to
 *                a control (audited); the link then counts as evidence, refreshed with every snapshot. Stale (> 90 days) is said.
 *   gaps         per applicable control: no evidence, only stale evidence, implemented without evidence.
 *   submission   a pack: every applicable control with status, evidence references (with their dates and hashes), linked platform
 *                snapshots, open actions, findings - frozen with a manifest hash. Prepared by an operator, APPROVED by the CCC
 *                owner / an administrator who did not prepare it (four-eyes), then recorded as SUBMITTED to the audit firm (date,
 *                reference). The pack is downloaded as JSON + CSV; evidence files themselves stay in the organisation's systems.
 *   GET  /aramco-ccc/evidence                 viewer    sources, last snapshots, suggestions and links per control, gaps
 *   POST /aramco-ccc/evidence/collect         operator  take the snapshots now                                        audited
 *   POST /aramco-ccc/evidence/link            operator  {control, source, linked}                                     audited
 *   GET  /aramco-ccc/submissions              viewer
 *   POST /aramco-ccc/submissions              operator  prepare a pack                                                audited
 *   POST /aramco-ccc/submissions/:id/approve  operator  the CCC owner / admin, not the preparer                       audited
 *   POST /aramco-ccc/submissions/:id/submitted operator {submitted_on, reference}                                    audited
 *   GET  /aramco-ccc/submissions/:id/export   operator  ?format=json|csv                                              audited
 */
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const S = [
  ['assets', 'Asset inventory', 'hardware software asset register inventory discovery scan network devices servers endpoints cmdb configuration items asset management owner classification', ['assets', 'disc_runs', 'disc_scopes']],
  ['vuln', 'Vulnerability management', 'vulnerability scan findings patch critical high remediation penetration testing weakness cve exposure', ['vulnscan_findings', 'vulnscan', 'vapt_scanned']],
  ['patch', 'Patch management', 'patch update security updates operating system endpoints servers patching exceptions windows', ['desk_patch', 'patch_exceptions']],
  ['backup', 'Backup and recovery', 'backup restore recovery resilience continuity disaster data copies retention', ['backup_objects', 'backup_platforms']],
  ['certs', 'Certificates and cryptography', 'certificate tls ssl encryption cryptography key management expiry https', ['cert_endpoints', 'cert_keys']],
  ['policy', 'Policies and GRC evidence', 'policy procedure standard governance approved documented review roles responsibilities awareness compliance', ['grc_files', 'grc_evidence', 'grc_exceptions']],
  ['risk', 'Risk management', 'risk assessment register treatment third party risk management', ['grc_risks', 'riskassess_snaps']],
  ['pam', 'Privileged access', 'privileged access administrator accounts approval session elevated access management', ['pam_requests']],
  ['directory', 'Identity and accounts', 'identity user accounts access control authentication directory active directory disabled accounts joiners leavers mfa password', ['ad_directory']],
  ['drills', 'Incident and continuity drills', 'incident response drill exercise business continuity test tabletop', ['grc_drills']],
];
const TOK = (t) => String(t || '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').split(/\s+/).filter((w) => w.length > 2 && !STOP.has(w));
const STOP = new Set(['the', 'and', 'for', 'with', 'all', 'shall', 'must', 'are', 'that', 'this', 'from', 'third', 'party', 'parties', 'its', 'any', 'each', 'not', 'have', 'has', 'been', 'will', 'should', 'such', 'other', 'into']);
// TF-IDF cosine between documents (the controls and the sources together form the corpus)
function tfidf(docs) {
  const df = new Map(), toks = docs.map(TOK);
  for (const t of toks) for (const w of new Set(t)) df.set(w, (df.get(w) || 0) + 1);
  const N = docs.length;
  return toks.map((t) => { const tf = new Map(); for (const w of t) tf.set(w, (tf.get(w) || 0) + 1); const v = new Map(); let n = 0; for (const [w, c] of tf) { const x = (c / t.length) * Math.log(1 + N / (df.get(w) || 1)); v.set(w, x); n += x * x; } return { v, n: Math.sqrt(n) || 1 }; });
}
const cos = (a, b) => { let s = 0; for (const [w, x] of a.v) { const y = b.v.get(w); if (y) s += x * y; } return s / (a.n * b.n); };

function createAcccEvidence(app, opts = {}) {
  const now = opts.now || Date.now, C = (n) => app.store.collection(n), iso = () => new Date(now()).toISOString();
  const snaps = () => C('accc_ev_snaps'), links = () => C('accc_ev_links'), subs = () => C('accc_submissions');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'aramco-ccc.' + action, target, detail }); };
  const prof = () => C('accc_profile').get('profile') || {};
  const manager = (who) => who.role === 'admin' || (prof().ccc_owner && String(prof().ccc_owner).toLowerCase() === String(who.user).toLowerCase());
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const ts = (o) => Date.parse(o.finished_at || o.updated_at || o.at || o.created_at || o.ts || '') || 0;

  // one snapshot per source: counts and dates only
  function snapshotOf(src) {
    const [id, , , cols] = src, out = { source: id, at: iso(), collections: {} };
    let any = false;
    for (const n of cols) {
      let rows; try { rows = C(n).all(() => true); } catch (e) { rows = []; /* the module is not installed: the source says so */ }
      const by = (k) => { const m = {}; for (const r of rows) { const v = String(r[k] == null ? '' : r[k]).toLowerCase().slice(0, 40); if (v) m[v] = (m[v] || 0) + 1; } return Object.keys(m).length && Object.keys(m).length <= 30 ? m : undefined; };
      const last = rows.reduce((a, r) => Math.max(a, ts(r)), 0);
      if (rows.length) any = true;
      out.collections[n] = { count: rows.length, last: last ? new Date(last).toISOString() : null, by_status: by('status'), by_severity: by('severity'), by_type: by('type') };
    }
    out.available = any;
    out.why = any ? '' : 'nothing recorded yet - connect or run it in the platform (' + cols.join(', ') + ')';
    out.sha256 = crypto.createHash('sha256').update(JSON.stringify(out.collections)).digest('hex');
    return out;
  }
  function collect(who) {
    const at = iso(), res = S.map((s) => snapshotOf(s));
    for (const r of res) snaps().put(Object.assign({ id: r.source + '@' + at.slice(0, 10) }, r));
    // keep 400 days of daily snapshots per source
    for (const o of snaps().all((x) => now() - Date.parse(x.at) > 400 * DAY)) snaps().remove(o.id);
    if (who) audit(who, 'evidence.collect', 'sources', { available: res.filter((r) => r.available).length, sources: res.length });
    return res;
  }
  function latest(id) { return snaps().all((x) => x.source === id).sort((a, b) => String(b.at).localeCompare(String(a.at)))[0] || null; }
  function suggestions(controls) {
    const docs = controls.map((c) => [c.title, c.domain, c.requirement].join(' ')).concat(S.map((s) => s[1] + ' ' + s[2]));
    const V = tfidf(docs), off = controls.length, out = {};
    controls.forEach((c, i) => { out[c.id] = S.map((s, j) => ({ source: s[0], score: Math.round(cos(V[i], V[off + j]) * 1000) / 1000 })).filter((x) => x.score >= 0.05).sort((a, b) => b.score - a.score).slice(0, 3); });
    return out;
  }
  function view() {
    const X = app.addons && app.addons.aramcoCcc; const v = X ? X.view({ user: 'system', role: 'viewer' }) : { controls: [] };
    const sources = S.map((s) => { const l = latest(s[0]); return { id: s[0], name: s[1], snapshot: l, stale: !!(l && now() - Date.parse(l.at) > 2 * DAY) }; });
    const sug = suggestions(v.controls), L = links().all((x) => x.linked);
    const per = v.controls.map((c) => {
      const mine = L.filter((x) => x.control === c.id).map((x) => x.source), refs = c.evidence || [];
      const fresh = refs.filter((e) => now() - Date.parse(e.collected) <= 90 * DAY).length + mine.filter((m) => { const l = latest(m); return l && l.available; }).length;
      const gap = !refs.length && !mine.length ? 'no evidence' : !fresh ? 'only stale evidence (older than 90 days)' : c.status === 'implemented' && !fresh ? 'implemented without current evidence' : '';
      return { id: c.id, title: c.title, status: c.status || 'not-assessed', linked: mine, references: refs.length, suggested: sug[c.id].filter((x) => !mine.includes(x.source)), gap };
    });
    return { sources, controls: per, gaps: per.filter((p) => p.gap).length, covered: per.filter((p) => !p.gap).length, catalogue: S.map((s) => ({ id: s[0], name: s[1] })),
      submissions: subs().all().sort((a, b) => String(b.id).localeCompare(String(a.id))).map((x) => { const o = Object.assign({}, x); delete o.pack; return o; }) };
  }
  function link(b0, who) {
    person(who, 'link evidence');
    const b = body(b0).str('control', { required: true, id: true }).oneOf('source', S.map((s) => s[0]), { required: true }).bool('linked', { def: true }).done();
    if (!C('accc_controls').get(b.control)) throw httpErr(404, 'control not found');
    const id = b.control + '|' + b.source, l = links().put({ id, control: b.control, source: b.source, linked: b.linked, by: who.user, at: iso() });
    audit(who, b.linked ? 'evidence.link' : 'evidence.unlink', b.control, { source: b.source }); return l;
  }
  function nextId() { let m = 0; for (const x of subs().all()) { const n = Number(String(x.id).slice(4)); if (n > m) m = n; } return 'SUB-' + String(m + 1).padStart(4, '0'); }
  function prepare(who) {
    person(who, 'prepare a submission');
    const X = app.addons && app.addons.aramcoCcc; if (!X) throw httpErr(409, 'Aramco CCC is not installed');
    const v = X.view(who), ev = view();
    if (!v.controls.length) throw httpErr(409, 'no applicable control - import the control list first');
    const unassessed = v.controls.filter((c) => !c.status || c.status === 'not-assessed').length;
    const pack = { organisation: v.org, vendor_no: (v.profile || {}).vendor_no || '', prepared_at: iso(), prepared_by: who.user, readiness: v.score, contracts: v.contracts.map((c) => ({ contract_no: c.contract_no, services: c.services })),
      controls: v.controls.map((c) => { const e = ev.controls.find((x) => x.id === c.id) || {}; return { id: c.id, domain: c.domain, title: c.title, status: c.status || 'not-assessed', na: c.na && c.na.state === 'accepted' ? c.na.justification : '',
        evidence: (c.evidence || []).map((x) => ({ title: x.title, location: x.location, collected: x.collected })), platform: (e.linked || []).map((sid) => { const l = latest(sid); return l ? { source: sid, at: l.at, sha256: l.sha256, available: l.available } : { source: sid, missing: true }; }),
        actions: v.actions.filter((a) => a.control === c.id && a.status !== 'done').map((a) => ({ title: a.title, due: a.due })), gap: e.gap || '' }; }),
      findings: v.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title, status: f.status })), audit: v.audit || null };
    pack.manifest_sha256 = crypto.createHash('sha256').update(JSON.stringify(pack.controls) + JSON.stringify(pack.findings)).digest('hex');
    const s = subs().put({ id: nextId(), status: 'prepared', prepared_by: who.user, prepared_at: pack.prepared_at, readiness: v.score, controls: pack.controls.length, gaps: pack.controls.filter((c) => c.gap).length, unassessed, manifest_sha256: pack.manifest_sha256, pack });
    audit(who, 'submission.prepare', s.id, { controls: s.controls, gaps: s.gaps, manifest: s.manifest_sha256.slice(0, 16) });
    const o = Object.assign({}, s); delete o.pack; return o;
  }
  function must(id) { param(id); const s = subs().get(id); if (!s) throw httpErr(404, 'submission not found'); return s; }
  function approve(id, who) {
    person(who, 'approve a submission'); if (!manager(who)) throw httpErr(403, 'the CCC owner named in the profile, or an administrator, approves a submission');
    const s = must(id); if (s.status !== 'prepared') throw httpErr(409, 'only a prepared pack is approved (this one is ' + s.status + ')');
    if (String(s.prepared_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: the person who prepared the pack does not approve it');
    if (s.unassessed) throw httpErr(409, s.unassessed + ' applicable control(s) are not assessed - assess them and prepare a new pack');
    const n = subs().patch(id, (x) => { x.status = 'approved'; x.approved_by = who.user; x.approved_at = iso(); return x; });
    audit(who, 'submission.approve', id, { prepared_by: s.prepared_by, manifest: s.manifest_sha256.slice(0, 16) }); const o = Object.assign({}, n); delete o.pack; return o;
  }
  function submitted(id, b0, who) {
    person(who, 'record a submission'); if (!manager(who)) throw httpErr(403, 'the CCC owner or an administrator records the submission');
    const s = must(id), b = body(b0).date('submitted_on', { required: true }).str('reference', { required: true, max: 120 }).done();
    if (s.status !== 'approved') throw httpErr(409, 'only an approved pack is submitted');
    if (b.submitted_on > iso().slice(0, 10)) throw httpErr(400, 'submitted_on: not in the future');
    const n = subs().patch(id, (x) => { x.status = 'submitted'; x.submitted_on = b.submitted_on; x.reference = b.reference; x.submitted_by = who.user; return x; });
    audit(who, 'submission.submitted', id, { reference: b.reference }); const o = Object.assign({}, n); delete o.pack; return o;
  }
  function exportPack(id, q, who) {
    const s = must(id), fmt = (q && q.format) === 'csv' ? 'csv' : 'json';
    audit(who, 'submission.export', id, { format: fmt });
    if (fmt === 'json') return { filename: 'aramco-ccc-' + id + '.json', pack: s.pack, status: s.status, approved_by: s.approved_by || null, manifest_sha256: s.manifest_sha256 };
    const q2 = (x) => '"' + String(x == null ? '' : x).replace(/"/g, '""') + '"';
    const rows = [['control', 'domain', 'title', 'status', 'not applicable because', 'evidence (title @ location, collected)', 'platform snapshots (source @ date sha256)', 'open actions', 'gap']].concat(s.pack.controls.map((c) => [c.id, c.domain, c.title, c.status, c.na,
      c.evidence.map((e) => e.title + ' @ ' + e.location + ', ' + e.collected).join('; '), c.platform.map((p) => p.missing ? p.source + ' (no snapshot)' : p.source + ' @ ' + p.at.slice(0, 10) + ' ' + p.sha256.slice(0, 16)).join('; '), c.actions.map((a) => a.title + ' by ' + a.due).join('; '), c.gap]));
    return { filename: 'aramco-ccc-' + id + '.csv', csv: rows.map((r) => r.map(q2).join(',')).join('\n'), manifest_sha256: s.manifest_sha256 };
  }
  let timer = null; const tick = guardOf(app, 'aramco-ccc.evidence.daily', async () => { collect(null); });
  return { view, collect, link, prepare, approve, submitted, exportPack, suggestions, snapshotOf, SOURCES: S,
    start() { if (timer || opts.noTimer) return; setTimeout(tick, 200000).unref(); timer = setInterval(tick, 24 * 3600000); timer.unref(); }, stop() { if (timer) clearInterval(timer); timer = null; } };
}

function registerAcccEvidence(srv, app, E) {
  srv.route('GET', '/aramco-ccc/evidence', (ctx) => { ctx.need('viewer'); return E.view(); });
  srv.route('POST', '/aramco-ccc/evidence/collect', (ctx) => { ctx.need('operator'); if (!isHuman(ctx.who.user)) throw httpErr(403, 'a person collects evidence'); return E.collect(ctx.who); });
  srv.route('POST', '/aramco-ccc/evidence/link', (ctx) => { ctx.need('operator'); return E.link(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('GET', '/aramco-ccc/submissions', (ctx) => { ctx.need('viewer'); return { submissions: E.view().submissions }; });
  srv.route('POST', '/aramco-ccc/submissions', (ctx) => { ctx.need('operator'); return E.prepare(ctx.who); });
  srv.route('POST', '/aramco-ccc/submissions/:id/approve', (ctx) => { ctx.need('operator'); return E.approve(ctx.params.id, ctx.who); });
  srv.route('POST', '/aramco-ccc/submissions/:id/submitted', (ctx) => { ctx.need('operator'); return E.submitted(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('GET', '/aramco-ccc/submissions/:id/export', (ctx) => { ctx.need('operator'); return E.exportPack(ctx.params.id, ctx.query, ctx.who); });
}

module.exports = { createAcccEvidence, registerAcccEvidence, tfidf, SOURCES: S };
