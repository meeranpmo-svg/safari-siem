// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset service: the single normalised asset record. Handles manual/barcode add, human edits (locking), source
// upserts via the merge/de-dup engine, and lifecycle transitions. Retire/dispose set a status
// and append a lifecycle event; the record and its audit trail remain. Admin delete: engine/asset-delete.js.
const crypto = require('node:crypto');
const asset = require('./model/asset');
const merge = require('./model/merge');
const rel = require('./model/relationship');
const { normSoftwareEntry } = require('./model/software');

const newId = () => `as_${crypto.randomBytes(6).toString('hex')}`;
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const LIFECYCLE_ACTIONS = { retire: 'retired', dispose: 'disposed', repair: 'in_repair', restock: 'in_stock', activate: 'in_use', lost: 'lost', found: 'in_use' };

function createAssets({ store, audit }) {
  const col = store.collection('assets');
  const rels = store.collection('relationships');

  function event(a, ev, by, detail) {
    a.lifecycle = Array.isArray(a.lifecycle) ? a.lifecycle : [];
    a.lifecycle.push({ event: ev, at: new Date().toISOString(), by: by || 'system', detail: detail === undefined ? null : detail });
    if (a.lifecycle.length > 1000) a.lifecycle = a.lifecycle.slice(-1000);
  }

  // ---- manual / barcode add -------------------------------------------------------------------------------------
  function create(body, who, opts = {}) {
    const source = asset.SOURCES.includes(opts.source) ? opts.source : 'manual';
    const { fields, warnings } = asset.normaliseFields(body);
    const now = new Date().toISOString();
    const a = asset.blankAsset();
    a.id = newId();
    a.source = source;
    a.created_at = now; a.updated_at = now;
    a.prov = {}; a.locked = {};
    Object.assign(a, fields);
    if (!a.type) a.type = 'other';
    if (!a.status) a.status = source === 'manual' ? 'in_use' : 'in_use';
    // manual entry with no network identity → flag "no network source — manually tracked"
    if (source === 'manual' && !a.mgmt_ip && !a.mac && body.no_network_source !== false) a.no_network_source = true;
    a.networked = !!(a.mgmt_ip || a.mac) || a.networked;
    // seed a sighting for this source
    const keys = merge.identityKeys(fields).map((x) => x.k);
    a.sources = [{ source, source_id: asset.s(body.source_id, 120) || null, first_seen: now, last_seen: now, keys, detail: null }];
    a.first_seen = now; a.last_seen = now;
    // human-entered business fields are locked against discovery overwrite
    for (const k of merge.MERGE_FIELDS) if (k in fields && fields[k] !== null) { a.prov[k] = source; if (source === 'manual') a.locked[k] = true; }
    // optional initial software list (import)
    if (Array.isArray(body.software)) a.software = body.software.map(normSoftwareEntry).filter(Boolean).slice(0, 5000);
    event(a, 'created', who && who.user, { source });
    col.put(a);
    if (audit) audit({ by: (who && who.user) || 'system', role: who && who.role, action: 'asset.create', target: a.id, detail: { source, asset_tag: a.asset_tag, type: a.type, name: a.name, warnings } });
    return { asset: publicAsset(a), warnings };
  }

  // ---- human edit (locks edited business fields) ----------------------------------------------------------------
  function edit(id, body, who) {
    const a = col.get(id);
    if (!a) throw bad('asset not found', 404);
    const { fields, warnings } = asset.normaliseFields(body);
    a.prov = a.prov || {}; a.locked = a.locked || {};
    const changed = [];
    for (const k of merge.MERGE_FIELDS) {
      if (!(k in fields)) continue;
      if (JSON.stringify(a[k]) !== JSON.stringify(fields[k])) { a[k] = fields[k]; changed.push(k); }
      a.prov[k] = 'manual'; a.locked[k] = true; // sticky human decision
    }
    if ('tags' in fields) { if (JSON.stringify(a.tags) !== JSON.stringify(fields.tags)) changed.push('tags'); a.tags = fields.tags; }
    // status changes go through the dedicated retire/dispose/… transitions, not a free-text edit
    a.networked = !!(a.mgmt_ip || a.mac) || a.networked;
    a.updated_at = new Date().toISOString();
    event(a, 'edited', who && who.user, { fields: changed });
    col.put(a);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'asset.edit', target: a.id, detail: { changed } });
    return { asset: publicAsset(a), warnings, changed };
  }

  // ---- source upsert (ingest): merge/de-dup into one record -----------------------------------------------------
  // matchResult allows the caller (ingest) to supply an AI tie-break decision for ambiguous matches.
  function upsert(rawFields, source, sighting, opts = {}) {
    // every source value goes through the same normalisation/caps as a human edit (create + merge paths alike)
    const fields = asset.normaliseSourceFields(rawFields).fields;
    const keys = merge.identityKeys(fields);
    let target = opts.forceAssetId ? col.get(opts.forceAssetId) : null;
    let decision = null;
    if (!target) {
      // only match against non-disposed records (a disposed asset is not re-adopted silently)
      decision = merge.decideMatch(keys, col.all((x) => x.status !== 'disposed'));
      target = decision.match;
    }
    if (!target) {
      // create a new discovered record
      const res = create(Object.assign({}, fields, { source_id: sighting && sighting.source_id }), { user: `source:${source}`, role: 'system' }, { source });
      // discovered records do NOT lock fields
      const a = col.get(res.asset.id); a.locked = {}; col.put(a);
      return { assetId: res.asset.id, created: true, changed: Object.keys(fields), ambiguous: false, candidates: (decision && decision.candidates) || [] };
    }
    const { asset: merged, changed } = merge.mergeInto(target, fields, source, sighting);
    if (changed.length) event(merged, 'seen', `source:${source}`, { source, changed });
    col.put(merged);
    if (audit && changed.length) audit({ by: `source:${source}`, role: 'system', action: 'asset.merge', target: merged.id, detail: { source, changed, ambiguous: !!(decision && decision.ambiguous) } });
    return { assetId: merged.id, created: false, changed, ambiguous: !!(decision && decision.ambiguous), candidates: (decision && decision.candidates) || [] };
  }

  // replace an asset's installed-software list (agent authoritative)
  function setSoftware(id, list, source) {
    const a = col.get(id);
    if (!a) return null;
    a.software = (Array.isArray(list) ? list : []).map(normSoftwareEntry).filter(Boolean).slice(0, 5000);
    a.updated_at = new Date().toISOString();
    col.put(a);
    if (audit) audit({ by: `source:${source || 'agent'}`, role: 'system', action: 'asset.software', target: id, detail: { count: a.software.length } });
    return a.software.length;
  }

  // ---- lifecycle transitions (no hard delete) -------------------------------------------------------------------
  function transition(id, action, who, reason, extra) {
    const a = col.get(id);
    if (!a) throw bad('asset not found', 404);
    if (!LIFECYCLE_ACTIONS[action]) throw bad(`unknown lifecycle action ${action}`);
    const toStatus = LIFECYCLE_ACTIONS[action];
    const from = a.status;
    a.status = toStatus;
    a.updated_at = new Date().toISOString();
    event(a, action, who && who.user, Object.assign({ from, to: toStatus, reason: asset.s(reason, 2000) || null }, extra || {}));
    col.put(a);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: `asset.${action}`, target: id, detail: { from, to: toStatus, reason: asset.s(reason, 2000) || null } });
    return { asset: publicAsset(a) };
  }
  function move(id, body, who) {
    const a = col.get(id);
    if (!a) throw bad('asset not found', 404);
    const loc = asset.isObj(body.location) ? { building: asset.s(body.location.building, 200) || null, room: asset.s(body.location.room, 120) || null, rack: asset.s(body.location.rack, 120) || null } : null;
    const site = asset.s(body.site, 200);
    const from = { site: a.site, location: a.location };
    if (site) { a.site = site; a.locked = a.locked || {}; a.locked.site = true; }
    if (loc) { a.location = loc; a.locked = a.locked || {}; a.locked.location = true; }
    a.updated_at = new Date().toISOString();
    event(a, 'moved', who && who.user, { from, to: { site: a.site, location: a.location } });
    col.put(a);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'asset.move', target: id, detail: { from, to: { site: a.site, location: a.location } } });
    return { asset: publicAsset(a) };
  }
  function assign(id, body, who) {
    const a = col.get(id);
    if (!a) throw bad('asset not found', 404);
    const from = { owner: a.owner, custodian: a.custodian, department: a.department };
    a.locked = a.locked || {};
    for (const k of ['owner', 'custodian', 'department']) if (k in body) { a[k] = asset.s(body[k], 300) || null; a.locked[k] = true; }
    a.updated_at = new Date().toISOString();
    event(a, 'assigned', who && who.user, { from, to: { owner: a.owner, custodian: a.custodian, department: a.department } });
    col.put(a);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'asset.assign', target: id, detail: { to: { owner: a.owner, custodian: a.custodian, department: a.department } } });
    return { asset: publicAsset(a) };
  }

  // ---- reads ----------------------------------------------------------------------------------------------------
  function publicAsset(a) {
    if (!a) return null;
    const { prov, locked, ...rest } = a; // provenance/lock are internal bookkeeping
    return rest;
  }
  function get(id) { return publicAsset(col.get(id)); }
  function raw(id) { return col.get(id); }
  function list(filter) { return col.all(filter).map(publicAsset); }
  function all() { return col.all(); }
  function byTag(tag) {
    const t = String(tag || '').trim().toLowerCase();
    if (!t) return [];
    return col.all((a) => (a.asset_tag && a.asset_tag.toLowerCase() === t) || (a.serial && a.serial.toLowerCase() === t)).map(publicAsset);
  }
  function detail(id) {
    const a = col.get(id);
    if (!a) return null;
    const relationships = rels.all((r) => r.from === id || r.to === id);
    return {
      asset: publicAsset(a),
      relationships: relationships.map((r) => { const { key, ...rest } = r; return rest; }),
      software: a.software || [],
      lifecycle: a.lifecycle || [],
      seen_by: (a.sources || []).map((sg) => ({ source: sg.source, source_id: sg.source_id, first_seen: sg.first_seen, last_seen: sg.last_seen })),
    };
  }

  // ---- relationships (CMDB) -------------------------------------------------------------------------------------
  function addRelationship(body, who, { source = 'manual', autoConfirm } = {}) {
    const r = rel.normRelationship(Object.assign({ source }, body));
    if (!r) throw bad('invalid relationship (need from, to, type)');
    if (!col.get(r.from) || !col.get(r.to)) throw bad('relationship endpoints must be existing assets', 404);
    const existing = rels.all().find((x) => x.key === r.key);
    // a relationship a person confirmed is never rewritten by a machine proposal (AI / sensor): its source, confidence and
    // rationale stay what the person accepted
    if (existing && existing.status === 'confirmed' && source !== 'manual' && autoConfirm !== true) return { relationship: existing, unchanged: true };
    const now = new Date().toISOString();
    // human confirmation (via API by operator) confirms; AI/sensor proposals stay 'proposed' unless low-impact
    const confirm = autoConfirm !== undefined ? autoConfirm : (source === 'manual');
    const rec = Object.assign({}, existing || {}, r, {
      id: (existing && existing.id) || `rel_${crypto.randomBytes(5).toString('hex')}`,
      status: confirm ? 'confirmed' : (existing && existing.status === 'confirmed' ? 'confirmed' : r.status),
      by: who && who.user, at: now,
    });
    rels.put(rec);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: existing ? 'cmdb.update' : 'cmdb.add', target: rec.id, detail: { from: rec.from, to: rec.to, type: rec.type, status: rec.status, source } });
    const { key, ...pub } = rec;
    return pub;
  }
  function relationshipsFor(id, opts) { return rel.graphFor(id, rels.all(), opts); }
  function allRelationships() { return rels.all(); }

  return {
    create, edit, upsert, setSoftware, transition, move, assign,
    get, raw, list, all, byTag, detail, publicAsset,
    addRelationship, relationshipsFor, allRelationships,
    LIFECYCLE_ACTIONS,
  };
}

module.exports = { createAssets, LIFECYCLE_ACTIONS };
