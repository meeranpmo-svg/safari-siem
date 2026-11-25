// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/* brand/index.js - the brand setting (brand.json) with the derived fields, for tools and page tests. */
const fs = require('fs'), path = require('path');
const BAD = /[<>&"'`\r\n]/;
function derive(raw, dir) {
  const b = Object.assign({}, raw);
  for (const k of ['name', 'short', 'name_ar', 'short_ar', 'domain', 'website', 'report_header', 'portal_host']) {
    if (typeof b[k] !== 'string' || !b[k].trim()) throw new Error('brand.json: "' + k + '" is required');
    if (BAD.test(b[k])) throw new Error('brand.json: "' + k + '" may not contain < > & quotes or line breaks');
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(b.domain)) throw new Error('brand.json: "domain" must be a plain DNS name');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(b.portal_host)) throw new Error('brand.json: "portal_host" must be a plain DNS name');
  if (b.platform_ip && !/^(\d{1,3}\.){3}\d{1,3}$/.test(b.platform_ip)) throw new Error('brand.json: "platform_ip" must be an IPv4 address or empty');
  b.platform_ip = b.platform_ip || ''; b.platform_addr = b.platform_ip || 'the platform server';
  const rx = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  b.domain_re = rx(b.domain); b.portal_host_re = rx(b.portal_host); b.platform_addr_re = rx(b.platform_addr);
  b.upper = b.short.toUpperCase();
  b.li_ar = 'ل' + b.short_ar; b.bi_ar = 'ب' + b.short_ar;
  b.company_look = b.company_look !== false;   // the company colours are the default look of the home page, menu and sign-in page
  b.frameworks = Array.isArray(b.frameworks) ? b.frameworks.map(String) : [];
  for (const k of ['modules_off', 'pages_off', 'connections_off']) { b[k] = Array.isArray(b[k]) ? b[k].map(String) : []; if (b[k].some((x) => !/^[a-z0-9-]+$/.test(x))) throw new Error('brand.json: "' + k + '" holds module / page ids (lowercase letters, digits, hyphens)'); }
  b.colors = Object.assign({ primary: '#1f4e9c', accent: '#2f7fd0', ink: '#16233b', muted: '#6f7378' }, b.colors || {});
  for (const [k, v] of Object.entries(b.colors)) if (!/^#[0-9a-fA-F]{6}$/.test(v)) throw new Error('brand.json: colors.' + k + ' must be #rrggbb');
  if (dir && b.logo && !/^data:/.test(b.logo)) {
    const f = path.join(dir, b.logo), ext = path.extname(f).slice(1).toLowerCase();
    const mime = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', svg: 'image/svg+xml' }[ext];
    if (!mime) throw new Error('brand.json: logo must be png, jpg, webp or svg');
    b.logo = 'data:' + mime + ';base64,' + fs.readFileSync(f).toString('base64');
  }
  return b;
}
const brand = derive(JSON.parse(fs.readFileSync(path.join(__dirname, 'brand.json'), 'utf8')), __dirname);
Object.defineProperty(brand, 'derive', { value: derive });
module.exports = Object.freeze(brand);
