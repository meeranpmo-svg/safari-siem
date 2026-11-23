// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// CSV / CMDB imports, idempotent (re-running merges by identity, never duplicates). Named column mappings including
// ManageEngine AssetExplorer and the existing portal /api/db asset store. Produces an unmapped-column report.
const asset = require('./model/asset');

// ---- CSV parser (RFC4180-ish: quotes, embedded commas/newlines, doubled quotes) ---------------------------------
function parseCsv(text) {
  const s = String(text || '').replace(/^﻿/, '');
  const rows = []; let row = []; let field = ''; let inQ = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQ) {
      if (c === '"') { if (s[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\r') { /* skip */ }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  // a leading '# ...' line is the note the Inventory export writes (when, how many assets): metadata, never the header row
  const nonEmpty = rows.filter((r) => r.some((x) => String(x).trim() !== ''));
  while (nonEmpty.length && String(nonEmpty[0][0]).trim().startsWith('#')) nonEmpty.shift();
  if (!nonEmpty.length) return { headers: [], rows: [] };
  const headers = nonEmpty[0].map((h) => String(h).trim());
  const out = nonEmpty.slice(1).map((r) => { const o = {}; headers.forEach((h, idx) => { o[h] = r[idx] !== undefined ? r[idx] : ''; }); return o; });
  return { headers, rows: out };
}

const norm = (h) => String(h || '').trim().toLowerCase().replace(/[\s_]+/g, ' ');

// ManageEngine AssetExplorer → ITAM field. Keys are normalised headers.
const MANAGEENGINE = {
  'asset name': 'name', 'name': 'name', 'asset tag': 'asset_tag', 'asset id': 'asset_tag',
  'product type': 'type', 'product': 'model', 'asset type': 'type',
  'manufacturer': 'vendor', 'vendor': 'vendor', 'model': 'model',
  'serial number': 'serial', 'serial no': 'serial', 'serial': 'serial',
  'ip address': 'mgmt_ip', 'ip': 'mgmt_ip', 'mac address': 'mac', 'mac': 'mac',
  'operating system': 'os', 'os': 'os', 'cpu': 'cpu',
  'location': 'site', 'site': 'site', 'department': 'department', 'dept': 'department',
  'user': 'owner', 'assigned to': 'owner', 'owner': 'owner', 'custodian': 'custodian',
  'state': 'status', 'status': 'status', 'asset state': 'status',
  'warranty expiry': 'warranty.end', 'warranty expiry date': 'warranty.end', 'warranty start': 'warranty.start',
  'acquisition date': 'purchase.date', 'purchase date': 'purchase.date', 'cost': 'purchase.cost',
  'po number': 'purchase.po', 'po': 'purchase.po', 'supplier': 'purchase.supplier',
};
// generic / portal /api/db asset store (snake_case JSON keys map mostly 1:1)
const GENERIC = Object.assign({}, MANAGEENGINE, {
  'hostname': 'name', 'serial_number': 'serial', 'mgmt_ip': 'mgmt_ip', 'management ip': 'mgmt_ip',
  'mem gb': 'mem_gb', 'memory gb': 'mem_gb', 'disk gb': 'disk_gb', 'eol': 'eol', 'end of life': 'eol',
  'warranty_end': 'warranty.end', 'purchase_date': 'purchase.date', 'asset_tag': 'asset_tag',
});
// the columns the Inventory page exports (Export CSV), so an export imports back unchanged; Quality, Seen and Issues are computed
// by the platform and are reported as unmapped, never written
const INVENTORY = Object.assign({}, GENERIC, {
  'tag': 'asset_tag', 'type': 'type', 'warranty end': 'warranty.end', 'support end': 'support.end', 'classification': 'classification',
  'platform id': '_id',   // the register's own id: that exact asset is updated (an export never duplicates when it comes back)
});
Object.assign(GENERIC, { 'tag': 'asset_tag', 'type': 'type', 'warranty end': 'warranty.end', 'support end': 'support.end', 'classification': 'classification' });
const MAPPINGS = { manageengine: MANAGEENGINE, generic: GENERIC, db: GENERIC, inventory: INVENTORY };

function setPath(obj, path, value) {
  const parts = path.split('.');
  let o = obj;
  for (let i = 0; i < parts.length - 1; i++) { o[parts[i]] = o[parts[i]] || {}; o = o[parts[i]]; }
  o[parts[parts.length - 1]] = value;
}

// map one source row → raw asset fields + the set of columns that had no mapping (and were non-empty)
function mapRow(rowObj, map) {
  const fields = {}; const unmapped = [];
  for (const [col, v] of Object.entries(rowObj)) {
    const key = map[norm(col)];
    // the export puts ' before a value starting with = + - @ so a spreadsheet does not run it; take it off again here
    const val = String(v == null ? '' : v).trim().replace(/^'(?=[=+\-@])/, '');
    if (!key) { if (val) unmapped.push(col); continue; }
    if (val === '') continue;
    setPath(fields, key, val);
  }
  return { fields, unmapped };
}

// runImport({format, mapping, text|rows}, assets, {dryRun, who})
function runImport(spec, assets, { dryRun = false, who } = {}) {
  const mapName = (spec.mapping || 'generic').toLowerCase();
  const map = MAPPINGS[mapName] || GENERIC;
  let rows = [];
  if (spec.format === 'csv') rows = parseCsv(spec.text).rows;
  else if (Array.isArray(spec.rows)) rows = spec.rows;
  else if (spec.format === 'json' && typeof spec.text === 'string') { try { const j = JSON.parse(spec.text); rows = Array.isArray(j) ? j : (Array.isArray(j.rows) ? j.rows : []); } catch { rows = []; } }
  const unmappedCols = new Set();
  let created = 0; let updated = 0; let skipped = 0; let matchedById = 0; let unknownIds = 0; const errors = [];
  const preview = [];
  rows.forEach((r, i) => {
    const { fields, unmapped } = mapRow(r, map);
    unmapped.forEach((c) => unmappedCols.add(c));
    // need at least one identity-bearing field to be safe (avoid merging unrelated blank rows)
    // a Platform ID the register holds (and not disposed) = update exactly that asset; an unknown id is ignored and the row is
    // matched by serial / tag / MAC / name like any other
    const pid = fields._id; delete fields._id;
    const known = pid && assets && typeof assets.raw === 'function' ? assets.raw(String(pid)) : null, byId = !!(known && known.status !== 'disposed');
    if (pid && !byId) unknownIds++;
    if (!byId && !fields.serial && !fields.asset_tag && !fields.mac && !fields.name) { skipped++; return; }
    if (dryRun) { preview.push({ row: i + 1, fields, action: byId ? 'update' : 'match' }); if (byId) matchedById++; return; }
    try {
      const res = assets.upsert(fields, 'import', { source_id: fields.asset_tag || fields.serial || fields.name || String(pid), at: new Date().toISOString() }, byId ? { forceAssetId: known.id } : {});
      if (byId) matchedById++;
      if (res.created) created++; else updated++;
    } catch (e) { errors.push({ row: i + 1, error: e.message }); }
  });
  return {
    mapping: mapName, rows: rows.length, created, updated, skipped, matched_by_id: matchedById, unknown_ids: unknownIds,
    unmapped_columns: [...unmappedCols], errors, preview: dryRun ? preview : undefined, dry_run: dryRun,
  };
}

module.exports = { parseCsv, mapRow, runImport, MAPPINGS, MANAGEENGINE, GENERIC };
