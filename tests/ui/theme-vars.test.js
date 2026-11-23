// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The theme layers (vendor/zyb-look.css, zyb-tabler.css, zyb-theme.css) define --ink as a BACKGROUND colour, as the older pages
// use it. A page that defines --ink as a light TEXT colour gets dark-on-dark text once the theme loads (button labels vanished
// on eleven pages, Nov 2026). Text colour on a page is --tx. This fails if any page defines --ink as a light colour.
// Run: node theme-vars.test.js
const fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
const lum = (hex) => { let h = hex.replace('#', ''); if (h.length === 3) h = h.split('').map((c) => c + c).join(''); const n = parseInt(h.slice(0, 6), 16); return ((n >> 16 & 255) * 0.299 + (n >> 8 & 255) * 0.587 + (n & 255) * 0.114) / 255; };
let n = 0, bad = [];
for (const f of fs.readdirSync(DASH).filter((x) => x.endsWith('.html'))) {
  const s = fs.readFileSync(path.join(DASH, f), 'utf8'); n++;
  for (const m of s.matchAll(/--ink\s*:\s*(#[0-9a-fA-F]{3,8})/g)) if (lum(m[1]) > 0.5) bad.push(f + ' defines --ink:' + m[1] + ' (use --tx for text)');
}
if (bad.length) { bad.forEach((b) => console.log('FAIL', b)); console.log('FAILED ' + bad.length + ' of ' + n + ' pages'); process.exit(1); }
console.log('OK ' + n + ' pages checked');
