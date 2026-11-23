// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The brand setting as the asset engine reads it (engine/brand.js), the Python readers' copy (pyengine/org_brand.py) and
// the policy register loader (engine/grc-policy-file.js). Synthetic values only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { spawnSync } = require('node:child_process');
const brand = require('../engine/brand');

const GOOD = { name: 'Synthetic Org Limited', short: 'Synthetic', name_ar: 'منظمة تجريبية', short_ar: 'تجريبية', domain: 'synthetic.example', website: 'https://www.synthetic.example', portal_host: 'soc.synthetic.example', report_header: 'Synthetic Org - IT' };
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'brand-'));

test('brand: the engine copy is the brand setting (brand/brand.json), with the derived fields', () => {
  const src = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../brand/brand.json'), 'utf8'));
  for (const k of ['name', 'short', 'name_ar', 'short_ar', 'domain', 'portal_host', 'report_header']) assert.equal(brand[k], src[k], k);
  assert.equal(brand.upper, src.short.toUpperCase());
  assert.ok(new RegExp('^' + brand.domain_re + '$').test(src.domain) && !new RegExp('^' + brand.domain_re + '$').test(src.domain.replace(/\./g, 'x')), 'domain_re matches the domain literally');
  assert.equal(brand.platform_addr, src.platform_ip || 'the platform server');
  assert.deepEqual(brand.frameworks, src.frameworks); assert.deepEqual(brand.modules_off, src.modules_off);
  assert.ok(Object.isFrozen(brand), 'nothing can change the brand at run time');
});

test('brand: a server file replaces the installed copy; a broken one is refused, never half-used', () => {
  const d = tmp(), f = path.join(d, 'brand.json');
  fs.writeFileSync(f, JSON.stringify(GOOD));
  const b = brand.load({ SENTRA_BRAND_FILE: f });
  assert.equal(b.name, 'Synthetic Org Limited'); assert.equal(b.li_ar, 'ل' + GOOD.short_ar); assert.equal(b.portal_host_re, 'soc\\.synthetic\\.example'); assert.deepEqual(b.modules_off, []);
  for (const [k, v, re] of [['name', 'Evil <script>', /may not contain/], ['short', 'A & B', /may not contain/], ['name', 'Two\nlines', /may not contain/], ['short', "O'Org", /may not contain/],
    ['domain', 'http://x.example/', /plain DNS name/], ['portal_host', 'soc example', /plain DNS name/], ['platform_ip', 'ten.zero', /IPv4/], ['logo', 'https://x.example/logo.png', /image data URI/], ['name', '', /missing/]]) {
    fs.writeFileSync(f, JSON.stringify(Object.assign({}, GOOD, { [k]: v })));
    assert.throws(() => brand.load({ SENTRA_BRAND_FILE: f }), re, k + ' = ' + JSON.stringify(v));
  }
  const miss = Object.assign({}, GOOD); delete miss.short_ar; fs.writeFileSync(f, JSON.stringify(miss));
  assert.throws(() => brand.load({ SENTRA_BRAND_FILE: f }), /"short_ar" is missing/);
  fs.writeFileSync(f, '{ not json'); assert.throws(() => brand.load({ SENTRA_BRAND_FILE: f }));
  fs.writeFileSync(f, JSON.stringify(Object.assign({}, GOOD, { platform_ip: '10.0.0.5' }))); assert.equal(brand.load({ SENTRA_BRAND_FILE: f }).platform_addr, '10.0.0.5');
  assert.equal(brand.load({ SENTRA_BRAND_FILE: path.join(d, 'absent.json') }).name, brand.name, 'a file that is not there falls back to the installed copy');
});

test('brand: the Python readers read the same setting and fill {{org.*}} tokens', () => {
  const d = tmp(), f = path.join(d, 'brand.json'); fs.writeFileSync(f, JSON.stringify(GOOD));
  const code = 'import sys, json\nsys.path.insert(0, sys.argv[1])\nimport org_brand\nprint(json.dumps([org_brand.ORG["name"], org_brand.fill("{{org.short}} / {{org.name_ar}} / {{org.li_ar}} / {{org.unknown}} / {{org.platform_addr}}")]))';
  const run = (env) => spawnSync('python3', ['-I', '-c', code, path.join(__dirname, '../pyengine')], { encoding: 'utf8', env: Object.assign({}, process.env, env) });
  let r = run({ SENTRA_BRAND_FILE: f }); assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), ['Synthetic Org Limited', 'Synthetic / ' + GOOD.name_ar + ' / ل' + GOOD.short_ar + ' / {{org.unknown}} / the platform server']);
  r = run({ SENTRA_BRAND_FILE: '' }); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout)[0], brand.load({}).name, 'without a server file: the installed copy');
  fs.writeFileSync(f, JSON.stringify(Object.assign({}, GOOD, { name: 'Bad <b>' }))); r = run({ SENTRA_BRAND_FILE: f }); assert.notEqual(r.status, 0); assert.match(r.stderr, /may not contain/);
});

test('policy register: none is shipped; the organisation provides its own file; a wrong file is an error', () => {
  const policies = require('../engine/grc-policy-file');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(__dirname, '../engine/grc-policies.json'), 'utf8')), [], 'the engine ships an empty register');
  const d = tmp(), f = path.join(d, 'p.json');
  fs.writeFileSync(f, JSON.stringify([{ doc_id: 'SYN-001', title: 'Synthetic policy' }])); assert.equal(policies({ SENTRA_GRC_POLICIES: f })[0].doc_id, 'SYN-001');
  fs.writeFileSync(f, JSON.stringify({ policies: [{ doc_id: 'SYN-002' }] })); assert.equal(policies({ SENTRA_GRC_POLICIES: f + '' })[0].doc_id, 'SYN-001', 'read once per file list');
  const g = path.join(d, 'q.json'); fs.writeFileSync(g, JSON.stringify({ policies: [{ doc_id: 'SYN-002' }] })); assert.equal(policies({ SENTRA_GRC_POLICIES: g })[0].doc_id, 'SYN-002');
  const h = path.join(d, 'r.json'); fs.writeFileSync(h, JSON.stringify({ nope: 1 })); assert.throws(() => policies({ SENTRA_GRC_POLICIES: h }), /not a list of policies/);
});
