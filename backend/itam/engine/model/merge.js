// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// De-duplication + merge across sources (sensor | agent | vcenter | manual | import). Pure, deterministic; the AI
// tie-break (engine/ai/classify.js) is only consulted when this module reports an *ambiguous* match — never to
// overwrite a confident deterministic decision. ARCH: "merge rules + AI tie-break, explainable".
//
//   identityKeys(fields|asset) → [{k, w}]   weighted identity keys (serial/uuid/tag strong; mac medium; ip+name/name weak)
//   matchCandidates(keys, assets) → [{asset, score, strong}]   scored, best first
//   decideMatch(keys, assets) → {match|null, ambiguous, candidates[]}   deterministic match decision
//   mergeInto(asset, fields, source, sighting) → {asset, changed[]}   field-precedence merge, provenance-tracked
const { isObj, normaliseSourceFields } = require('./asset');

const STRONG_W = 70;
// field precedence: for each field, which source "wins" when both have a value (earliest in the list = highest).
// Discovery sources win for technical/network facts; humans (manual) + import win for business/ownership facts.
// 'discovery' = the admin-approved active/passive Asset Discovery (engine/discovery): it ranks just below the
// netops sensor for technical facts and never overrides human/import business data.
const DEF = ['manual', 'import', 'agent', 'vcenter', 'sensor', 'discovery'];
const FIELD_PRECEDENCE = {
  os: ['agent', 'vcenter', 'sensor', 'discovery', 'import', 'manual'],
  cpu: ['agent', 'vcenter', 'sensor', 'discovery', 'import', 'manual'],
  mem_gb: ['agent', 'vcenter', 'sensor', 'discovery', 'import', 'manual'],
  disk_gb: ['agent', 'vcenter', 'sensor', 'discovery', 'import', 'manual'],
  serial: ['agent', 'sensor', 'vcenter', 'discovery', 'import', 'manual'],
  mac: ['sensor', 'agent', 'vcenter', 'discovery', 'import', 'manual'],
  mgmt_ip: ['sensor', 'vcenter', 'agent', 'discovery', 'import', 'manual'],
  vendor: ['sensor', 'agent', 'vcenter', 'discovery', 'import', 'manual'],
  model: ['sensor', 'agent', 'vcenter', 'discovery', 'import', 'manual'],
  name: ['manual', 'agent', 'vcenter', 'sensor', 'discovery', 'import'],
  type: ['manual', 'agent', 'vcenter', 'sensor', 'discovery', 'import'],
  // ownership / lifecycle business data: humans and the system of record win, discovery never overwrites
  owner: ['manual', 'import'], custodian: ['manual', 'import'], department: ['manual', 'import'],
  site: ['manual', 'import', 'sensor', 'discovery'], location: ['manual', 'import', 'sensor', 'discovery'],
  // 'autofill' = a vendor-verified value the Asset Data Autopilot wrote into an EMPTY field (asset-autofill.js): lowest rank,
  // so a person or an import always wins over it
  warranty: ['manual', 'import', 'autofill'], purchase: ['manual', 'import'], eol: ['manual', 'import', 'autofill'], support: ['manual', 'import', 'autofill'],
  // information classification is a human decision (or the system of record): discovery never sets it
  classification: ['manual', 'import'], cia: ['manual', 'import'],
};
// status is NEVER changed by a merge — only explicit lifecycle transitions move status. networked/no_network_source
// are derived. tags are unioned.
const MERGE_FIELDS = ['asset_tag', 'name', 'type', 'site', 'location', 'owner', 'custodian', 'department',
  'vendor', 'model', 'serial', 'mgmt_ip', 'mac', 'os', 'cpu', 'mem_gb', 'disk_gb', 'warranty', 'support', 'purchase', 'eol', 'notes', 'classification', 'cia'];

const lc = (v) => String(v == null ? '' : v).trim().toLowerCase();
const hex12 = (v) => lc(v).replace(/[^0-9a-f]/g, '');

function identityKeys(src) {
  const f = isObj(src) ? src : {};
  const out = [];
  const add = (k, w) => { if (k && !out.some((x) => x.k === k)) out.push({ k, w }); };
  if (f.uuid) add(`uuid:${lc(f.uuid)}`, 95);               // vcenter instance uuid / agent machine uuid
  if (f.serial && lc(f.serial).length >= 3) add(`serial:${lc(f.serial)}`, 100);
  if (f.asset_tag) add(`tag:${lc(f.asset_tag)}`, 90);
  if (f.mac && hex12(f.mac).length === 12) add(`mac:${hex12(f.mac)}`, 70);
  if (Array.isArray(f.macs)) for (const m of f.macs) if (hex12(m).length === 12) add(`mac:${hex12(m)}`, 70);
  if (f.mgmt_ip && f.name) add(`ipn:${lc(f.mgmt_ip)}|${lc(f.name)}`, 60);
  if (f.name) add(`name:${lc(f.name)}`, 30);
  return out;
}

// keys stored on an asset for matching: its own identity keys plus any carried in its sightings
function assetKeys(asset) {
  const base = identityKeys(asset);
  const extra = [];
  for (const sg of asset.sources || []) for (const kk of sg.keys || []) extra.push({ k: kk, w: 70 });
  const seen = new Set(base.map((x) => x.k));
  for (const e of extra) if (!seen.has(e.k)) { base.push(e); seen.add(e.k); }
  return base;
}

function matchCandidates(keys, assets) {
  const kw = new Map(keys.map((x) => [x.k, x.w]));
  const scored = [];
  for (const a of assets) {
    let score = 0; let strong = false;
    for (const ak of assetKeys(a)) { if (kw.has(ak.k)) { const w = Math.max(kw.get(ak.k), ak.w); score += w; if (w >= STRONG_W) strong = true; } }
    if (score > 0) scored.push({ asset: a, score, strong });
  }
  scored.sort((x, y) => y.score - x.score);
  return scored;
}

// deterministic decision: a single asset sharing a strong key wins. Several assets sharing strong keys, or only a
// weak (name) overlap, is ambiguous → the caller may ask the AI to tie-break / a human to confirm.
function decideMatch(keys, assets) {
  const cands = matchCandidates(keys, assets);
  if (!cands.length) return { match: null, ambiguous: false, candidates: [] };
  const strong = cands.filter((c) => c.strong);
  if (strong.length === 1) return { match: strong[0].asset, ambiguous: false, candidates: cands };
  if (strong.length > 1) return { match: null, ambiguous: true, candidates: cands };
  // only weak overlaps
  if (cands.length === 1 && cands[0].score >= 30) return { match: cands[0].asset, ambiguous: cands[0].score < STRONG_W, candidates: cands };
  return { match: null, ambiguous: true, candidates: cands };
}

function precedence(field) { return FIELD_PRECEDENCE[field] || DEF; }
const empty = (v) => v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length);

// merge normalised `fields` (from this source) into `asset`; returns a new asset + list of changed field names.
// Provenance (asset.prov[field] = source) decides whether a lower-priority source may overwrite.
// `fields` is (re-)normalised here so no merge path can write raw, un-capped source values onto a record.
function mergeInto(asset, rawFields, source, sighting) {
  const fields = normaliseSourceFields(rawFields).fields;
  const a = JSON.parse(JSON.stringify(asset));
  a.prov = a.prov || {};
  const changed = [];
  const now = (sighting && sighting.at) || new Date().toISOString();
  for (const k of MERGE_FIELDS) {
    if (!(k in fields)) continue;
    // a human edit locks a field; discovery sources never overwrite it (only another human edit, source 'manual')
    if (a.locked && a.locked[k] && source !== 'manual') continue;
    const incoming = fields[k];
    if (empty(incoming)) continue;
    const cur = a[k];
    const owner = a.prov[k];
    let win = false;
    if (empty(cur)) win = true;
    else if (!owner) win = true; // current value has no provenance (legacy/import seed) — a known source may set it
    else {
      const order = precedence(k);
      const io = order.indexOf(source); const oo = order.indexOf(owner);
      // lower index = higher priority. unknown source for this field (io<0) only fills blanks (handled above).
      if (io >= 0 && (oo < 0 || io <= oo)) win = true;
    }
    if (win && JSON.stringify(cur) !== JSON.stringify(incoming)) { a[k] = incoming; a.prov[k] = source; changed.push(k); }
    else if (win) { a.prov[k] = source; }
  }
  // networked: any networked sighting or an mgmt_ip/mac makes it networked; manual off-network flag is sticky
  if (fields.networked === true || a.mgmt_ip || a.mac) a.networked = true;
  if (fields.no_network_source === true) a.no_network_source = true;
  // tags union
  if (Array.isArray(fields.tags) && fields.tags.length) {
    const set = new Set(a.tags || []);
    for (const t of fields.tags) if (!set.has(t)) { set.add(t); }
    const merged = [...set].slice(0, 100);
    if (JSON.stringify(merged) !== JSON.stringify(a.tags || [])) { a.tags = merged; changed.push('tags'); }
  }
  // record / update the per-source sighting
  a.sources = Array.isArray(a.sources) ? a.sources : [];
  const keys = identityKeys(fields).map((x) => x.k);
  const sidx = a.sources.findIndex((x) => x.source === source && (!sighting || !sighting.source_id || x.source_id === sighting.source_id));
  const sg = {
    source, source_id: (sighting && sighting.source_id) || null,
    first_seen: sidx >= 0 ? a.sources[sidx].first_seen : now, last_seen: now,
    keys: [...new Set((sidx >= 0 ? a.sources[sidx].keys || [] : []).concat(keys))].slice(0, 20),
    detail: (sighting && sighting.detail) || null,
  };
  if (sidx >= 0) a.sources[sidx] = sg; else a.sources.push(sg);
  // last_seen / first_seen across all sources
  const seens = a.sources.map((x) => x.last_seen).filter(Boolean).sort();
  const firsts = a.sources.map((x) => x.first_seen).filter(Boolean).sort();
  a.last_seen = seens.length ? seens[seens.length - 1] : now;
  a.first_seen = firsts.length ? firsts[0] : (a.first_seen || now);
  a.updated_at = now;
  return { asset: a, changed };
}

// Discovery duplicate check (results review): which existing assets look like the same device?
//   MAC (any of mac/macs vs the asset's mac and the MAC keys its sources carry) and serial number are STRONG matches;
//   the host name (short name, case-insensitive, domain suffix ignored) is only a WEAK hint shown to the admin — it never
//   merges on its own. → [{asset_id, name, asset_tag, by:['mac'|'serial'|'hostname'], strength:'strong'|'weak'}]
const shortName = (v) => lc(v).split('.')[0];
function duplicateCandidates(fields, assets) {
  const f = isObj(fields) ? fields : {};
  const macs = new Set([f.mac].concat(Array.isArray(f.macs) ? f.macs : []).map(hex12).filter((m) => m.length === 12));
  const serial = f.serial && lc(f.serial).length >= 3 ? lc(f.serial) : '';
  const host = shortName(f.hostname || f.name || '');
  const out = [];
  for (const a of assets || []) {
    if (!a || a.status === 'disposed') continue;
    const by = [];
    const amacs = new Set([hex12(a.mac)]);
    for (const sg of a.sources || []) for (const k of sg.keys || []) if (k.startsWith('mac:')) amacs.add(k.slice(4));
    if ([...macs].some((m) => amacs.has(m))) by.push('mac');
    if (serial && a.serial && lc(a.serial) === serial) by.push('serial');
    if (host && host.length >= 3 && a.name && shortName(a.name) === host) by.push('hostname');
    if (by.length) out.push({ asset_id: a.id, name: a.name || null, asset_tag: a.asset_tag || null, by, strength: by.includes('mac') || by.includes('serial') ? 'strong' : 'weak' });
  }
  out.sort((x, y) => (x.strength === y.strength ? y.by.length - x.by.length : x.strength === 'strong' ? -1 : 1));
  return out;
}

module.exports = { identityKeys, assetKeys, matchCandidates, decideMatch, mergeInto, duplicateCandidates, FIELD_PRECEDENCE, MERGE_FIELDS, STRONG_W };
