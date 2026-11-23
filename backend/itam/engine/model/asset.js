// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset record model + normalisation/validation. Pure functions; no I/O. Used by the ingest pipeline, the manual/
// barcode add path, imports and the API edit path. Shapes follow ARCH "Model".
//
//   asset {id, asset_tag, type, name, status, source, sources[], site, location{building,room,rack}, owner, custodian,
//          department, vendor, model, serial, mgmt_ip?, mac?, os, cpu, mem_gb, disk_gb, warranty{start,end,provider}, support{provider,contract,level,start,end,verified},
//          purchase{date,cost,po,supplier}, eol?, first_seen, last_seen, networked, no_network_source, tags[],
//          software[], notes, created_at, updated_at}
//   plus internal: lifecycle[] (events), per-source sightings held separately on the record as sources[].

const TYPES = ['server', 'vm', 'workstation', 'laptop', 'network', 'printer', 'phone', 'storage', 'ups', 'mobile', 'peripheral', 'software', 'licence', 'other'];
const STATUSES = ['in_use', 'in_stock', 'in_repair', 'retired', 'lost', 'disposed'];
const SOURCES = ['sensor', 'agent', 'vcenter', 'manual', 'import', 'discovery'];
// statuses that mean the record is kept for the trail but is no longer a live/active asset
const CLOSED_STATUSES = ['retired', 'disposed'];

const TYPE_ALIASES = {
  pc: 'workstation', desktop: 'workstation', notebook: 'laptop', macbook: 'laptop',
  switch: 'network', router: 'network', ap: 'network', 'access point': 'network', firewall: 'network', gateway: 'network',
  'ip phone': 'phone', voip: 'phone', nas: 'storage', san: 'storage', 'virtual machine': 'vm',
  smartphone: 'mobile', tablet: 'mobile', mfp: 'printer', scanner: 'peripheral', monitor: 'peripheral',
};

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
function s(v, max = 2000) {
  if (v === null || v === undefined) return '';
  const t = typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : '';
  return t.trim().slice(0, max);
}
function num(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }
function enumOf(v, allowed, aliases = {}) {
  const k = s(v).toLowerCase();
  if (aliases[k]) return aliases[k];
  const hit = allowed.find((a) => a === k);
  return hit || null;
}
function dateISO(v) {
  const t = s(v, 40);
  if (!t) return null;
  if (/^\d{4}-\d{2}-\d{2}/.test(t)) { const d = Date.parse(t.length <= 10 ? t + 'T00:00:00Z' : t); return Number.isFinite(d) ? new Date(d).toISOString() : null; }
  const d = Date.parse(t); return Number.isFinite(d) ? new Date(d).toISOString() : null;
}
function normMac(v) {
  const t = s(v, 40).toLowerCase().replace(/[^0-9a-f]/g, '');
  if (t.length !== 12) return s(v, 40) ? s(v, 40).toLowerCase() : null;
  return t.match(/.{2}/g).join(':');
}
function normIp(v) {
  const t = s(v, 60);
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(t) && t.split('.').every((o) => Number(o) <= 255) ? t : (t || null);
}
function tagList(v) {
  const a = Array.isArray(v) ? v : v === undefined || v === null || v === '' ? [] : [v];
  const out = [];
  for (const t of a) { const x = s(t, 60); if (x && !out.includes(x)) out.push(x); if (out.length >= 50) break; }
  return out;
}

function normWarranty(w) {
  if (!isObj(w)) return null;
  const start = dateISO(w.start); const end = dateISO(w.end); const provider = s(w.provider, 200);
  if (!start && !end && !provider) return null;
  return { start, end, provider: provider || null };
}
// vendor support / maintenance coverage of the asset (Smart Net, ProSupport, FortiCare, a support contract ...)
function normSupport(v) {
  if (!isObj(v)) return null;
  const provider = s(v.provider, 200), contract = s(v.contract, 120), level = s(v.level, 120), end = dateISO(v.end), start = dateISO(v.start);
  if (!provider && !contract && !level && !end) return null;
  return { provider: provider || null, contract: contract || null, level: level || null, start, end, verified: v.verified === true };
}
function normPurchase(p) {
  if (!isObj(p)) return null;
  const date = dateISO(p.date); const cost = num(p.cost); const po = s(p.po, 100); const supplier = s(p.supplier, 200);
  if (!date && cost === null && !po && !supplier) return null;
  return { date, cost, po: po || null, supplier: supplier || null };
}

// normalise an arbitrary partial asset into a clean partial (only keys present in input are set).
// Returns {fields, warnings[]}. Used for merge inputs and for API edits.
function normaliseFields(raw) {
  const o = isObj(raw) ? raw : {};
  const W = [];
  const f = {};
  if ('asset_tag' in o) f.asset_tag = s(o.asset_tag, 120) || null;
  if ('name' in o) f.name = s(o.name, 300) || null;
  if ('type' in o) { const t = enumOf(o.type, TYPES, TYPE_ALIASES); if (t) f.type = t; else if (s(o.type)) { f.type = 'other'; W.push(`type "${s(o.type, 40)}" not recognised — set to other`); } }
  if ('status' in o) { const st = enumOf(o.status, STATUSES); if (st) f.status = st; else if (s(o.status)) W.push(`status "${s(o.status, 40)}" invalid — ignored`); }
  if ('site' in o) f.site = s(o.site, 200) || null;
  if ('location' in o && isObj(o.location)) f.location = { building: s(o.location.building, 200) || null, room: s(o.location.room, 120) || null, rack: s(o.location.rack, 120) || null };
  for (const k of ['owner', 'custodian', 'department', 'vendor', 'model', 'serial', 'os', 'cpu', 'notes']) if (k in o) f[k] = s(o[k], k === 'notes' ? 8000 : 300) || null;
  if ('mem_gb' in o) f.mem_gb = num(o.mem_gb);
  if ('disk_gb' in o) f.disk_gb = num(o.disk_gb);
  if ('mgmt_ip' in o) f.mgmt_ip = normIp(o.mgmt_ip);
  if ('mac' in o) f.mac = normMac(o.mac);
  if ('warranty' in o) f.warranty = normWarranty(o.warranty);
  if ('purchase' in o) f.purchase = normPurchase(o.purchase);
  if ('support' in o) f.support = normSupport(o.support);
  if ('eol' in o) f.eol = dateISO(o.eol);
  if ('networked' in o) f.networked = !!o.networked;
  if ('no_network_source' in o) f.no_network_source = !!o.no_network_source;
  if ('tags' in o) f.tags = tagList(o.tags);
  if ('classification' in o) { const c = normClassification(o.classification); if (c !== undefined) f.classification = c; else W.push(`classification "${s(o.classification, 40)}" invalid — use top_secret, secret, restricted or public`); }
  if ('cia' in o) f.cia = normCia(o.cia);
  return { fields: f, warnings: W };
}

// normalise a SOURCE-supplied partial (agent / discovery / connector / import) for upsert + merge: the same field
// normalisation as an API edit, plus the identity-only keys a source may carry (uuid, macs[]) with hard caps so an
// untrusted reporter cannot plant oversized strings or thousands of identity keys on a record.
const MAX_SOURCE_MACS = 16;
function normaliseSourceFields(raw) {
  const o = isObj(raw) ? raw : {};
  const { fields, warnings } = normaliseFields(o);
  if ('uuid' in o) { const u = s(o.uuid, 120); if (u) fields.uuid = u; }
  if ('macs' in o) {
    const list = Array.isArray(o.macs) ? o.macs : [];
    const out = [];
    for (const m of list.slice(0, 256)) { const x = normMac(m); if (x && /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/.test(x) && !out.includes(x)) out.push(x); if (out.length >= MAX_SOURCE_MACS) break; }
    fields.macs = out;
  }
  return { fields, warnings };
}

// information classification (NDMO data classification levels) and the CIA impact of the asset
const CLASSIFICATIONS = ['top_secret', 'secret', 'restricted', 'public'];
const CIA_LEVELS = ['high', 'medium', 'low'];
function normClassification(v) {
  if (v === null || v === undefined || v === '') return null;
  const t = String(v).trim().toLowerCase().replace(/[\s-]+/g, '_');
  return CLASSIFICATIONS.includes(t) ? t : undefined;
}
function normCia(v) {
  if (!isObj(v)) return null;
  const one = (x) => { const t = String(x == null ? '' : x).trim().toLowerCase(); return CIA_LEVELS.includes(t) ? t : null; };
  const o = { c: one(v.c), i: one(v.i), a: one(v.a) };
  return o.c || o.i || o.a ? o : null;
}

// a blank, valid asset skeleton
function blankAsset() {
  return {
    id: null, asset_tag: null, type: 'other', name: null, status: 'in_use', source: 'manual', sources: [],
    site: null, location: null, owner: null, custodian: null, department: null,
    vendor: null, model: null, serial: null, mgmt_ip: null, mac: null, os: null, cpu: null, mem_gb: null, disk_gb: null,
    warranty: null, support: null, purchase: null, eol: null, classification: null, cia: null,
    first_seen: null, last_seen: null, networked: false, no_network_source: false,
    tags: [], software: [], lifecycle: [], notes: null, created_at: null, updated_at: null,
  };
}

function isClosed(asset) { return !!asset && CLOSED_STATUSES.includes(asset.status); }

module.exports = {
  TYPES, STATUSES, SOURCES, CLOSED_STATUSES, TYPE_ALIASES,
  normaliseFields, normaliseSourceFields, MAX_SOURCE_MACS, blankAsset, isClosed, CLASSIFICATIONS, CIA_LEVELS,
  // helpers reused by other modules/tests
  s, num, enumOf, dateISO, normMac, normIp, tagList, normWarranty, normPurchase, isObj,
};
