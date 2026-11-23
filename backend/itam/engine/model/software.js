// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Software inventory + licence model. Pure functions.
//   software {name, publisher, version, installs(count), licence_id?}  — rolled up across assets
//   licence  {id, product, type, seats, used, expiry, cost, compliance(ok|over|under)}
// Installed-software facts come from the endpoint agent (authoritative) and from imports. The engine rolls per-asset
// software lists up into a publisher/product install count and reconciles against licences.
const { s, num, dateISO, isObj } = require('./asset');

function normSoftwareEntry(raw) {
  const o = isObj(raw) ? raw : { name: raw };
  const name = s(o.name, 300);
  if (!name) return null;
  return {
    name, publisher: s(o.publisher, 200) || null, version: s(o.version, 80) || null,
    install_date: dateISO(o.install_date), licence_id: s(o.licence_id, 80) || null,
  };
}

// a stable key to group the "same product" across assets/versions (publisher + base name, case-insensitive)
function productKey(sw) {
  const pub = (sw.publisher || '').toLowerCase().trim();
  const name = (sw.name || '').toLowerCase().trim().replace(/\s+\d[\d.]*$/, ''); // drop a trailing version in the name
  return `${pub}|${name}`;
}

// roll per-asset software arrays up into a product inventory [{key, name, publisher, versions[], installs, asset_ids[]}]
function rollup(assets) {
  const map = new Map();
  for (const a of assets) {
    for (const sw0 of a.software || []) {
      const sw = normSoftwareEntry(sw0);
      if (!sw) continue;
      const key = productKey(sw);
      let e = map.get(key);
      if (!e) { e = { key, name: sw.name, publisher: sw.publisher, versions: new Set(), installs: 0, asset_ids: new Set(), licence_id: sw.licence_id || null }; map.set(key, e); }
      if (sw.version) e.versions.add(sw.version);
      if (sw.licence_id && !e.licence_id) e.licence_id = sw.licence_id;
      e.installs++; e.asset_ids.add(a.id);
    }
  }
  return [...map.values()].map((e) => ({
    key: e.key, name: e.name, publisher: e.publisher, versions: [...e.versions].sort(),
    installs: e.installs, asset_ids: [...e.asset_ids], licence_id: e.licence_id,
  })).sort((x, y) => y.installs - x.installs);
}

function normLicence(raw) {
  const o = isObj(raw) ? raw : {};
  const id = s(o.id, 80);
  const product = s(o.product, 300);
  if (!id || !product) return null;
  const seats = num(o.seats);
  return {
    id, product, type: s(o.type, 80) || 'subscription',
    seats: seats === null ? null : Math.max(0, Math.round(seats)),
    expiry: dateISO(o.expiry), cost: num(o.cost),
    publisher: s(o.publisher, 200) || null, notes: s(o.notes, 2000) || null,
    product_key_match: s(o.product_key_match, 300) || null, // substring used to attribute installs to this licence
  };
}

// compute used seats + compliance for a licence against the software rollup.
// used = installs of products whose key matches licence.product_key_match (substring) OR whose entries carry licence_id.
function licenceCompliance(licence, rollup) {
  const match = (licence.product_key_match || licence.product || '').toLowerCase().trim();
  let used = 0;
  const products = [];
  for (const p of rollup) {
    const byId = p.licence_id === licence.id;
    const byName = match && (`${p.publisher || ''} ${p.name}`.toLowerCase().includes(match) || p.name.toLowerCase().includes(match));
    if (byId || byName) { used += p.installs; products.push(p.key); }
  }
  let compliance = 'ok';
  if (licence.seats !== null) {
    if (used > licence.seats) compliance = 'over';
    else if (used < licence.seats) compliance = 'under';
  } else compliance = 'unknown';
  const delta = licence.seats === null ? null : used - licence.seats;
  return { used, compliance, delta, products };
}

module.exports = { normSoftwareEntry, productKey, rollup, normLicence, licenceCompliance };
