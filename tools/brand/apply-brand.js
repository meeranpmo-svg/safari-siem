#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * apply-brand - write the generated copies of the brand setting (brand/brand.json):
 *   ui/vendor/zyb-org.js                         window.ZYB_ORG for every page, and the {{org.*}} tokens in static page text
 *   backend/itam/engine/brand.default.json       the asset engine's copy
 *   backend/siem/engine/util/brand.default.json  the SIEM engine's copy
 *   node tools/brand/apply-brand.js [--check] [--all-modules] [--brand <brand.json>] [--ui-out <zyb-org.js>]
 * --check writes nothing and exits 1 when a copy is stale. --brand / --ui-out let the server installer build the page
 * copy from /etc/sentra/brand.json.
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..');
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const CHECK = process.argv.includes('--check');
const { derive } = require(path.join(ROOT, 'brand/index.js'));
const file = path.resolve(arg('brand', path.join(ROOT, 'brand/brand.json')));
const b = derive(JSON.parse(fs.readFileSync(file, 'utf8')), path.dirname(file));
// --all-modules: the page copy with nothing switched off and the platform's own design, for the product's page tests;
// tools/run-tests.sh writes it before the page tests and puts the real copy back afterwards
const ALL = process.argv.includes('--all-modules');
if (ALL) { b.modules_off = []; b.pages_off = []; b.connections_off = []; b.company_look = false; b.frameworks_all = true; }   // and the platform's own design, which the design tests describe
const PAGE = fs.readFileSync(path.join(__dirname, 'zyb-org.template.js'), 'utf8').replace('/*BRAND*/{}', JSON.stringify(b));
const engine = JSON.stringify({ name: b.name, short: b.short, name_ar: b.name_ar, short_ar: b.short_ar, domain: b.domain, website: b.website, portal_host: b.portal_host, platform_ip: b.platform_ip, report_header: b.report_header, logo: b.logo, colors: b.colors, sector: b.sector, frameworks: b.frameworks, framework_scope: b.framework_scope || {}, sites: Array.isArray(b.sites) ? b.sites : [], departments: Array.isArray(b.departments) ? b.departments : [], modules_off: b.modules_off, pages_off: b.pages_off }, null, 1) + '\n';
const outs = arg('ui-out') ? [[path.resolve(arg('ui-out')), PAGE]] : ALL ? [[path.join(ROOT, 'ui/vendor/zyb-org.js'), PAGE]] : [
  [path.join(ROOT, 'ui/vendor/zyb-org.js'), PAGE],
  [path.join(ROOT, 'backend/itam/engine/brand.default.json'), engine],
  [path.join(ROOT, 'backend/siem/engine/util/brand.default.json'), engine],
];
let stale = 0;
for (const [f, text] of outs) {
  const cur = fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null;
  if (cur === text) continue;
  if (CHECK) { console.error('stale: ' + path.relative(ROOT, f)); stale++; } else { fs.writeFileSync(f, text); console.log('wrote ' + path.relative(ROOT, f)); }
}
if (CHECK && stale) process.exit(1);
console.log(CHECK ? 'brand copies are current' : 'brand applied: ' + b.name + ' (' + b.domain + ')');
