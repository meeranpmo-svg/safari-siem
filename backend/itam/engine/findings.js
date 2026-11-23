// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Deterministic gaps/anomalies/licence/EOL/refresh findings. Works WITHOUT the model (the AI layer only enriches
// rationale / refresh narratives). Every finding is advisory and labelled; nothing here changes or retires an asset.
// Findings are keyed deterministically so a regenerate preserves a human's accept/dismiss decision and never
// resurfaces a dismissed item while the underlying condition is unchanged.
const crypto = require('node:crypto');
const { rollup, licenceCompliance } = require('./model/software');

const AI_LABEL = 'AI — verify';
const DAY = 86400000;
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });

// the built-in rules, pure, over what was read (the Python twin pyengine/asset_rules.py findings() answers the same, step 6b)
//   inp = {assets, licences, settings: {not_seen_days, expiry_window_days}, now}
function findingsCore(inp) {
    const st = inp.settings, now = inp.now;
    const daysUntil = (iso) => { const x = Date.parse(iso); return Number.isFinite(x) ? Math.round((x - now) / DAY) : null; };
    const daysSince = (iso) => { const x = Date.parse(iso); return Number.isFinite(x) ? Math.round((now - x) / DAY) : null; };
    const notSeen = st.not_seen_days; const win = st.expiry_window_days;
    const live = inp.assets.filter((a) => a.status !== 'disposed' && a.status !== 'retired');
    const out = [];
    const add = (f) => out.push(f);
    for (const a of live) {
      const ident = a.asset_tag || a.name || a.id;
      // not-seen-for-N-days (possible lost/decommissioned)
      if (a.status === 'in_use' && a.last_seen) {
        const ds = daysSince(a.last_seen);
        if (ds !== null && ds >= notSeen) add({ key: `not_seen:${a.id}`, kind: 'not_seen', severity: ds >= notSeen * 3 ? 'high' : 'medium', asset_id: a.id, title: `${ident} not seen for ${ds} days`, detail: `In use but no source has reported it for ${ds} days (threshold ${notSeen}). Confirm it is still deployed or move it to lost/retired.`, evidence: { last_seen: a.last_seen, days: ds } });
      }
      // shadow IT: networked, discovered by a sensor only, with no owner and no agent → unmanaged endpoint (ties to ASM)
      const srcs = new Set((a.sources || []).map((s) => s.source));
      if (a.networked && !a.owner && srcs.has('sensor') && !srcs.has('agent') && !srcs.has('manual') && (a.type === 'workstation' || a.type === 'laptop' || a.type === 'server' || a.type === 'other')) {
        add({ key: `shadow_it:${a.id}`, kind: 'shadow_it', severity: 'high', asset_id: a.id, title: `Possible shadow IT: ${ident}`, detail: 'On the network (sensor-discovered) but unmanaged: no owner and no endpoint agent. Cross-check against ASM/attack-surface and assign an owner or deploy the agent.', evidence: { sources: [...srcs], mgmt_ip: a.mgmt_ip } });
      }
      // missing core data
      if (a.status === 'in_use') {
        if (!a.owner && !a.custodian) add({ key: `missing_owner:${a.id}`, kind: 'missing_owner', severity: 'medium', asset_id: a.id, title: `No owner/custodian: ${ident}`, detail: 'An in-use asset has no owner or custodian recorded.', evidence: {} });
        if (!a.site && !a.location) add({ key: `missing_location:${a.id}`, kind: 'missing_location', severity: 'low', asset_id: a.id, title: `No location: ${ident}`, detail: 'An in-use asset has no site or location recorded.', evidence: {} });
        if (!a.warranty || !a.warranty.end) add({ key: `missing_warranty:${a.id}`, kind: 'missing_warranty', severity: 'low', asset_id: a.id, title: `No warranty data: ${ident}`, detail: 'No warranty end date recorded; renewal/refresh cannot be planned.', evidence: {} });
      }
      // warranty expiry
      if (a.warranty && a.warranty.end) {
        const du = daysUntil(a.warranty.end);
        if (du !== null && du < 0) add({ key: `warranty_expired:${a.id}`, kind: 'warranty_expired', severity: 'medium', asset_id: a.id, title: `Warranty expired: ${ident}`, detail: `Warranty ended ${-du} days ago (${a.warranty.end.slice(0, 10)}).`, evidence: { end: a.warranty.end, days: du } });
        else if (du !== null && du <= win) add({ key: `warranty_expiring:${a.id}`, kind: 'warranty_expiring', severity: du <= 30 ? 'medium' : 'low', asset_id: a.id, title: `Warranty expiring in ${du} days: ${ident}`, detail: `Warranty ends ${a.warranty.end.slice(0, 10)}. Plan renewal or refresh.`, evidence: { end: a.warranty.end, days: du } });
      }
      // EOL
      if (a.eol) {
        const du = daysUntil(a.eol);
        if (du !== null && du < 0) add({ key: `eol_passed:${a.id}`, kind: 'eol_passed', severity: 'high', asset_id: a.id, title: `Past end-of-life: ${ident}`, detail: `EOL was ${a.eol.slice(0, 10)} (${-du} days ago). Prioritise refresh/replacement.`, evidence: { eol: a.eol, days: du } });
        else if (du !== null && du <= win) add({ key: `eol_expiring:${a.id}`, kind: 'eol_expiring', severity: 'medium', asset_id: a.id, title: `Approaching end-of-life: ${ident}`, detail: `EOL ${a.eol.slice(0, 10)} (in ${du} days). Add to the refresh plan.`, evidence: { eol: a.eol, days: du } });
      }
    }
    // licence over/under deployment
    const rolled = rollup(live);
    for (const lic of inp.licences || []) {
      const comp = licenceCompliance(lic, rolled);
      if (comp.compliance === 'over') add({ key: `licence_over:${lic.id}`, kind: 'licence_over', severity: 'high', licence_id: lic.id, title: `Licence over-deployed: ${lic.product}`, detail: `${comp.used} installs against ${lic.seats} seats (over by ${comp.delta}). True-up or reclaim installs.`, evidence: { seats: lic.seats, used: comp.used, delta: comp.delta, products: comp.products } });
      else if (comp.compliance === 'under' && comp.delta <= -1) add({ key: `licence_under:${lic.id}`, kind: 'licence_under', severity: 'low', licence_id: lic.id, title: `Unused licence seats: ${lic.product}`, detail: `${comp.used} of ${lic.seats} seats used (${-comp.delta} spare). Consider reclaim at renewal.`, evidence: { seats: lic.seats, used: comp.used, delta: comp.delta } });
      if (lic.expiry) { const du = daysUntil(lic.expiry); if (du !== null && du <= win) add({ key: `licence_expiring:${lic.id}`, kind: 'licence_expiring', severity: du < 0 ? 'high' : 'low', licence_id: lic.id, title: `Licence ${du < 0 ? 'expired' : 'expiring'}: ${lic.product}`, detail: `Licence ${du < 0 ? 'expired' : 'expires'} ${lic.expiry.slice(0, 10)}.`, evidence: { expiry: lic.expiry, days: du } }); }
    }
    return out;
}

function createFindings({ store, audit, settings, assets, getLicences, python }) {
  const col = store.collection('findings');
  const mkId = () => `fnd_${crypto.randomBytes(6).toString('hex')}`;
  // other engine modules (Asset Discovery: rogue devices, silent SIEM sources) contribute deterministic findings through
  // providers: fn() → [{key, kind, severity, asset_id?, title, detail, evidence, label?}]. They take part in
  // regenerate() (so they are not "resolved" by it) and can be refreshed on their own with syncKinds().
  const providers = [];
  function addProvider(fn) { if (typeof fn === 'function') providers.push(fn); }
  function fromProviders(kinds) {
    const out = [];
    for (const p of providers) { let list = []; try { list = p() || []; } catch { list = []; } for (const f of list) if (!kinds || kinds.includes(f.kind)) out.push(f); }
    return out;
  }

  // compute the current set of findings as {key, kind, severity, asset_id?, licence_id?, title, detail, evidence}
  const inputs = () => ({ assets: assets.all(), licences: getLicences ? getLicences() : [], settings: settings.get(), now: Date.now() });
  function compute() { return findingsCore(inputs()).concat(fromProviders(null)); }
  // the same, with the built-in rules run in Python (pyengine/asset_rules.py; a missing or failing Python → Node.js)
  const py = (() => { try { return python === false ? null : require('./pyengine').createPyEngine({ python: python || undefined, timeoutMs: 5 * 60000 }); } catch (e) { return null; } })();
  const slim = (a) => { const r = {}; for (const k of ['id', 'name', 'asset_tag', 'status', 'type', 'last_seen', 'networked', 'owner', 'custodian', 'site', 'location', 'warranty', 'eol', 'mgmt_ip', 'software']) if (a[k] !== undefined) r[k] = a[k]; if (Array.isArray(a.sources)) r.sources = a.sources.map((x) => ({ source: x && x.source })); return r; };
  async function computeAsync() {
    const inp = inputs();
    if (py) {
      const r = await py.call('rules.findings', Object.assign({}, inp, { assets: inp.assets.map(slim) }));
      if (r && Array.isArray(r.findings)) return r.findings.concat(fromProviders(null));
    }
    return findingsCore(inp).concat(fromProviders(null));
  }

  // refresh only the findings of the given kinds from the providers (no audit noise unless something opened/closed)
  function syncKinds(kinds, who) {
    const computed = fromProviders(kinds);
    const byKey = new Map(computed.map((f) => [f.key, f]));
    const now = new Date().toISOString();
    const existing = col.all((f) => kinds.includes(f.kind));
    const existingByKey = new Map(existing.map((e) => [e.key, e]));
    const created = []; const resolved = [];
    for (const f of computed) {
      const prev = existingByKey.get(f.key);
      if (prev) {
        const next = Object.assign({}, prev, { severity: f.severity, title: f.title, detail: f.detail, evidence: f.evidence, last_computed: now, ai_label: f.label || AI_LABEL });
        if (prev.status === 'resolved') { next.status = 'open'; next.reopened_at = now; created.push(prev.id); }
        col.put(next);
      } else {
        const id = mkId();
        col.put({ id, key: f.key, kind: f.kind, severity: f.severity, asset_id: f.asset_id || null, licence_id: null, title: f.title, detail: f.detail, evidence: f.evidence, status: 'open', ai_label: f.label || AI_LABEL, created_at: now, last_computed: now });
        created.push(id);
      }
    }
    for (const e of existing) if (!byKey.has(e.key) && e.status !== 'dismissed' && e.status !== 'resolved') { col.put(Object.assign({}, e, { status: 'resolved', resolved_at: now })); resolved.push(e.id); }
    if (audit && (created.length || resolved.length)) audit({ by: who ? who.user : 'system', role: who ? who.role : 'system', action: 'findings.sync', target: kinds.join(','), detail: { created: created.length, resolved: resolved.length } });
    return { computed: computed.length, created, resolved };
  }

  // regenerate: upsert computed findings, preserving accepted/dismissed status by key; close findings whose
  // condition no longer holds (status 'resolved' — kept for the trail, not deleted).
  // asynchronous now (the rules may run in Python); the hourly timer in main.js calls it inside a plain try/catch, so a
  // failure is caught and logged here - it can never become an unhandled rejection that stops the engine
  function regenerate(who) {
    const p = regenerateNow(who);
    p.catch((e) => { try { console.error('findings: regenerate failed', e && e.message); } catch (x) { /* no console */ } });
    return p;
  }
  async function regenerateNow(who) {
    const computed = await computeAsync();
    const byKey = new Map(computed.map((f) => [f.key, f]));
    const now = new Date().toISOString();
    const existing = col.all();
    const existingByKey = new Map(existing.map((e) => [e.key, e]));
    let created = 0; let resolved = 0;
    for (const f of computed) {
      const prev = existingByKey.get(f.key);
      if (prev) {
        // refresh advisory text/severity/evidence but keep the human status + accepted/dismissed metadata
        const next = Object.assign({}, prev, { severity: f.severity, title: f.title, detail: f.detail, evidence: f.evidence, last_computed: now, ai_label: f.label || AI_LABEL });
        if (prev.status === 'resolved') { next.status = 'open'; next.reopened_at = now; }
        col.put(next);
      } else {
        col.put({ id: mkId(), key: f.key, kind: f.kind, severity: f.severity, asset_id: f.asset_id || null, licence_id: f.licence_id || null, title: f.title, detail: f.detail, evidence: f.evidence, status: 'open', ai_label: f.label || AI_LABEL, created_at: now, last_computed: now });
        created++;
      }
    }
    for (const e of existing) {
      if (!byKey.has(e.key) && e.status !== 'dismissed' && e.status !== 'resolved') { col.put(Object.assign({}, e, { status: 'resolved', resolved_at: now })); resolved++; }
    }
    if (audit) audit({ by: who ? who.user : 'system', role: who ? who.role : '', action: 'ai.findings.regenerate', target: 'findings', detail: { computed: computed.length, created, resolved } });
    return { computed: computed.length, created, resolved, total_open: col.all((f) => f.status === 'open').length };
  }

  // upsert an AI-produced finding (advisory, labelled). Preserves a prior human accept/dismiss on the same key.
  function upsertAi(f) {
    const now = new Date().toISOString();
    const prev = col.all().find((e) => e.key === f.key);
    if (prev && (prev.status === 'dismissed' || prev.status === 'accepted')) return prev; // respect the human decision
    const rec = Object.assign({ id: prev ? prev.id : mkId(), status: 'open', ai_label: AI_LABEL, created_at: prev ? prev.created_at : now }, prev || {}, {
      key: f.key, kind: f.kind, severity: f.severity || 'low', asset_id: f.asset_id || null, licence_id: f.licence_id || null,
      title: f.title, detail: f.detail, evidence: f.evidence || {}, suggestion: f.suggestion || null, ai_label: AI_LABEL, last_computed: now,
    });
    col.put(rec);
    return rec;
  }

  function list(filter) { return col.all(filter); }
  function get(id) { return col.get(id); }
  function setStatus(id, status, who, reason) {
    if (!['open', 'accepted', 'dismissed'].includes(status)) throw bad('status must be accepted or dismissed');
    const f = col.get(id);
    if (!f) throw bad('finding not found', 404);
    const next = Object.assign({}, f, { status, [`${status}_at`]: new Date().toISOString(), [`${status}_by`]: who && who.user, reason: reason || f.reason || null });
    col.put(next);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: `ai.findings.${status}`, target: id, detail: { kind: f.kind, asset_id: f.asset_id, licence_id: f.licence_id, reason: reason || null } });
    return next;
  }
  function summary() {
    const open = col.all((f) => f.status === 'open');
    const byKind = {}; const bySeverity = { high: 0, medium: 0, low: 0 };
    for (const f of open) { byKind[f.kind] = (byKind[f.kind] || 0) + 1; if (bySeverity[f.severity] !== undefined) bySeverity[f.severity]++; }
    return { open: open.length, by_kind: byKind, by_severity: bySeverity };
  }

  return { compute, regenerate, syncKinds, addProvider, upsertAi, list, get, setStatus, summary, AI_LABEL };
}

module.exports = { createFindings, findingsCore, AI_LABEL };
