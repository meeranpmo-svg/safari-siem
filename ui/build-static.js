#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* build-static.js - install-time build of the dashboards, run by install-dashboards.sh on the staged copy:
 *     node build-static.js <stage dir> <build stamp>
 *   1. inline <script> blocks move into js/<page>.<n>.js, so nginx can send a strict Content-Security-Policy
 *      (script-src 'self'): an injected <script> or onclick= in a page then simply does not run
 *   2. every local script / stylesheet reference gets ?v=<build>, so nginx can let browsers keep them for a year
 *      (immutable) and the next install is still picked up at once - the stamp changes, so the URL changes
 *   3. zyb-display.js is built into zyb-dash.js: one request less per page and no document.write
 *   4. pages and scripts are pre-compressed (.gz next to the file) for nginx gzip_static - no compression per request
 *   5. anything that would break under the strict policy (onclick=, javascript: links, eval) is listed, and the
 *      manifest (.zyb-static.json) then says "relaxed", which harden-web.sh reads before it enforces the policy
 * Node standard library only. Exit code 1 = the stage is unusable and the install must stop. */
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const STAGE = path.resolve(process.argv[2] || '');
const BUILD = String(process.argv[3] || '').replace(/[^0-9A-Za-z._-]/g, '');
if (!process.argv[2] || !BUILD || !fs.existsSync(path.join(STAGE, 'index.html'))) {
  console.error('usage: node build-static.js <stage dir with index.html> <build stamp>'); process.exit(1);
}
const issues = [];
let extracted = 0, versioned = 0, gz = 0;

// a script that runs: no type, or a JavaScript type. JSON / template blocks are data and may stay inline.
const RUNS = (attrs) => { const m = /\btype\s*=\s*["']?([^"'\s>]+)/i.exec(attrs); return !m || /^(text|application)\/(javascript|ecmascript)$|^module$/i.test(m[1]); };
// a reference we serve ourselves (not another site, not the API)
const LOCAL = (u) => !/^(?:[a-z][a-z0-9+.-]*:|\/\/|\/api\/|#)/i.test(u) && /\.(?:js|css)(?:[?#]|$)/i.test(u);
const stamp = (u) => { versioned++; const [p, h] = u.split('#'); const [base, q] = p.split('?'); const qs = (q || '').split('&').filter((x) => x && !/^v=/.test(x)); qs.push('v=' + BUILD); return base + '?' + qs.join('&') + (h !== undefined ? '#' + h : ''); };

fs.mkdirSync(path.join(STAGE, 'js'), { recursive: true });
const pages = fs.readdirSync(STAGE).filter((f) => /\.html$/i.test(f)).sort();
for (const page of pages) {
  const file = path.join(STAGE, page);
  let html = fs.readFileSync(file, 'utf8');
  let n = 0;
  html = html.replace(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi, (all, attrs, body) => {
    if (/\bsrc\s*=/i.test(attrs)) return all.replace(/\bsrc\s*=\s*(["'])([^"']+)\1/i, (m, q, u) => LOCAL(u) ? 'src=' + q + stamp(u) + q : m);
    if (!RUNS(attrs) || !body.trim()) return all;
    n++; extracted++;
    const name = 'js/' + page.replace(/\.html$/i, '') + '.' + n + '.js';
    fs.writeFileSync(path.join(STAGE, name), '/* ' + page + ' - inline script ' + n + ' (build-static.js, build ' + BUILD + ') */\n' + body + '\n');
    return '<script' + attrs + ' src="' + name + '?v=' + BUILD + '"></script>';
  });
  html = html.replace(/<link\b[^>]*>/gi, (tag) => /\brel\s*=\s*["']?stylesheet/i.test(tag) ? tag.replace(/\bhref\s*=\s*(["'])([^"']+)\1/i, (m, q, u) => LOCAL(u) ? 'href=' + q + stamp(u) + q : m) : tag);
  // what would still break under script-src 'self': handlers and javascript: links in the markup itself
  const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, '').replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, '');
  const ev = markup.match(/<[a-z][^>]*\son[a-z]+\s*=/gi); if (ev) issues.push(page + ': ' + ev.length + ' inline event handler(s) in the markup');
  if (/\b(?:href|src|action)\s*=\s*["']?\s*javascript:/i.test(markup)) issues.push(page + ': javascript: link in the markup');
  fs.writeFileSync(file, html);
}

// the same checks over every script we ship: markup built in strings (innerHTML) and string-to-code calls
const scripts = [].concat(
  fs.readdirSync(path.join(STAGE, 'js')).map((f) => 'js/' + f),
  fs.existsSync(path.join(STAGE, 'vendor')) ? fs.readdirSync(path.join(STAGE, 'vendor')).filter((f) => /^zyb-.*\.js$|^discovery-module\.js$/.test(f)).map((f) => 'vendor/' + f) : []);
for (const s of scripts) {
  const src = fs.readFileSync(path.join(STAGE, s), 'utf8');
  if (/<[a-z][^<>'"]*\son[a-z]+=\\?["']/i.test(src)) issues.push(s + ': builds markup with an inline event handler (on...=)');
  if (/\bnew Function\s*\(|\beval\s*\(|set(?:Timeout|Interval)\s*\(\s*["'`]/.test(src)) issues.push(s + ': turns a string into code (eval / new Function / timer string)');
  if (/<script>[^<]*window\.print/i.test(src)) issues.push(s + ': a report window runs its own inline script');
}

// zyb-display.js into zyb-dash.js (zyb-dash only writes the extra <script> tag while window.__zybDisplay is unset)
const dash = path.join(STAGE, 'vendor', 'zyb-dash.js'), disp = path.join(STAGE, 'vendor', 'zyb-display.js');
if (fs.existsSync(dash) && fs.existsSync(disp)) {
  const d = fs.readFileSync(dash, 'utf8');
  if (!d.includes('window.__zybDisplay = true')) fs.writeFileSync(dash, fs.readFileSync(disp, 'utf8') + '\n;\n' + d);
  if (!fs.readFileSync(dash, 'utf8').includes('window.__zybDisplay = true')) { console.error('could not build zyb-display.js into zyb-dash.js'); process.exit(1); }
}

// pre-compressed copies, written last so they match the final files
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);
for (const f of walk(STAGE)) {
  if (!/\.(?:html|js|css|json|svg)$/i.test(f)) continue;
  const buf = fs.readFileSync(f); if (buf.length < 1024) continue;
  fs.writeFileSync(f + '.gz', zlib.gzipSync(buf, { level: 9 })); gz++;
}

const csp = issues.length ? 'relaxed' : 'strict';
fs.writeFileSync(path.join(STAGE, '.zyb-static.json'), JSON.stringify({ build: BUILD, generated: new Date().toISOString(), csp, pages: pages.length, extracted, versioned, gz, issues }, null, 1) + '\n');
console.log('==> static build ' + BUILD + ': ' + pages.length + ' pages, ' + extracted + ' inline scripts moved to files, ' + versioned + ' references versioned, ' + gz + ' files pre-compressed');
console.log('    Content-Security-Policy: ' + (csp === 'strict' ? "ready for script-src 'self'" : 'NOT ready - ' + issues.length + ' item(s):'));
issues.forEach((i) => console.log('      - ' + i));
