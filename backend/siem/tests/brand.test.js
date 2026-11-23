// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The brand setting as the SIEM engine reads it (engine/util/brand.js): the same file and rules as the asset engine.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const brand = require('../engine/util/brand');

test('brand: the SIEM copy is the brand setting and identical to the asset engine copy', () => {
  const src = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../brand/brand.json'), 'utf8'));
  for (const k of ['name', 'short', 'name_ar', 'short_ar', 'domain', 'portal_host', 'report_header']) assert.equal(brand[k], src[k], k);
  assert.equal(fs.readFileSync(path.join(__dirname, '../engine/util/brand.default.json'), 'utf8'), fs.readFileSync(path.join(__dirname, '../../itam/engine/brand.default.json'), 'utf8'), 'both engines carry the same copy');
  assert.equal(fs.readFileSync(path.join(__dirname, '../engine/util/brand.js'), 'utf8'), fs.readFileSync(path.join(__dirname, '../../itam/engine/brand.js'), 'utf8'), 'and the same loader');
  assert.ok(Object.isFrozen(brand));
});

test('brand: values that would break a page, a report or a pattern are refused', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'brand-')), f = path.join(d, 'brand.json');
  const good = { name: 'Synthetic Org Limited', short: 'Synthetic', name_ar: 'منظمة تجريبية', short_ar: 'تجريبية', domain: 'synthetic.example', website: 'https://www.synthetic.example', portal_host: 'soc.synthetic.example', report_header: 'Synthetic Org - IT' };
  fs.writeFileSync(f, JSON.stringify(good)); assert.equal(brand.load({ SENTRA_BRAND_FILE: f }).domain_re, 'synthetic\\.example');
  for (const [k, v] of [['name', '<img src=x>'], ['report_header', 'a "quoted" header'], ['domain', 'synthetic.example/path'], ['portal_host', '']]) {
    fs.writeFileSync(f, JSON.stringify(Object.assign({}, good, { [k]: v }))); assert.throws(() => brand.load({ SENTRA_BRAND_FILE: f }), /brand:/, k);
  }
});
