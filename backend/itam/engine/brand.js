// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * brand.js - the company identity this engine prints on reports, e-mails and prompts: name, Arabic name, short name,
 * domain, portal host, platform server address, logo, report header, sector and the frameworks that apply. One setting, never text in the code.
 * Read once at start: SENTRA_BRAND_FILE, then /etc/sentra/brand.json, then brand.default.json beside this file (written
 * by tools/brand/apply-brand.js from brand/brand.json). A broken server file is refused loudly, never half-used.
 */
const fs = require('fs'), path = require('path');
const BAD = /[<>&"'`\r\n]/, TEXT = ['name', 'short', 'name_ar', 'short_ar', 'domain', 'website', 'report_header', 'portal_host'];
function check(b, from) {
  if (!b || typeof b !== 'object') throw new Error('brand: ' + from + ' is not an object');
  for (const k of TEXT) {
    if (typeof b[k] !== 'string' || !b[k].trim()) throw new Error('brand: "' + k + '" is missing in ' + from);
    if (BAD.test(b[k])) throw new Error('brand: "' + k + '" in ' + from + ' may not contain < > & quotes or line breaks');
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(b.domain)) throw new Error('brand: "domain" in ' + from + ' must be a plain DNS name');
  if (b.logo && !/^data:image\/(png|jpe?g|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(b.logo)) throw new Error('brand: "logo" in ' + from + ' must be an image data URI');
  const out = Object.assign({}, b);
  out.upper = out.short.toUpperCase(); out.li_ar = 'ل' + out.short_ar; out.bi_ar = 'ب' + out.short_ar;
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(b.portal_host)) throw new Error('brand: "portal_host" in ' + from + ' must be a plain DNS name');
  if (b.platform_ip && !/^(\d{1,3}\.){3}\d{1,3}$/.test(b.platform_ip)) throw new Error('brand: "platform_ip" in ' + from + ' must be an IPv4 address or empty');
  // the platform server as people read it in instructions: its LAN address once set, otherwise the words
  out.platform_ip = out.platform_ip || ''; out.platform_addr = out.platform_ip || 'the platform server';
  out.logo = out.logo || ''; out.sector = String(out.sector || 'general');
  out.frameworks = Array.isArray(out.frameworks) ? out.frameworks.map(String) : [];
  out.modules_off = Array.isArray(out.modules_off) ? out.modules_off.map(String) : []; out.pages_off = Array.isArray(out.pages_off) ? out.pages_off.map(String) : [];
  // the domain as a regular-expression fragment, for mail and host checks
  const rx = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  out.domain_re = rx(out.domain); out.portal_host_re = rx(out.portal_host); out.platform_addr_re = rx(out.platform_addr);
  return out;
}
function load(env) {
  env = env || process.env;
  const tries = [env.SENTRA_BRAND_FILE, '/etc/sentra/brand.json', path.join(__dirname, 'brand.default.json')].filter(Boolean);
  for (const f of tries) {
    let raw;
    try { raw = fs.readFileSync(f, 'utf8'); } catch (e) { if (e.code === 'ENOENT' || e.code === 'EACCES') continue; throw e; }
    return check(JSON.parse(raw), f);
  }
  throw new Error('brand: no brand file found (run tools/brand/apply-brand.js)');
}
const brand = load();
Object.defineProperty(brand, 'load', { value: load }); Object.defineProperty(brand, 'check', { value: check });
module.exports = Object.freeze(brand);
