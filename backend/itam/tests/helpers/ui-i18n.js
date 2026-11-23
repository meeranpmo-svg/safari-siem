// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// UI string extraction for the Arabic dictionary checks. The discovery module passes every user-visible English string
// through T('…'), TF('…', {…}) or marks it with N('…') (label maps translated at render time).
//   extract(src) → Set of English strings          check(src, dict, extra[]) → {used, missing[], notArabic[], badSlots[]}
const LIT = "'((?:[^'\\\\]|\\\\.)*)'";

function extract(src) {
  const out = new Set();
  for (const m of String(src).matchAll(new RegExp('\\b(?:TF?|N)\\(\\s*' + LIT, 'g'))) out.add(m[1].replace(/\\'/g, "'"));
  return out;
}
const slots = (s) => (String(s).match(/\{\w+\}/g) || []).sort().join(',');
function check(src, dict, extra = []) {
  const used = extract(src);
  for (const e of extra) used.add(e);
  const missing = []; const notArabic = []; const badSlots = [];
  for (const k of used) {
    if (!Object.prototype.hasOwnProperty.call(dict, k)) { missing.push(k); continue; }
    if (!/[؀-ۿ]/.test(dict[k])) notArabic.push(k);
    if (slots(k) !== slots(dict[k])) badSlots.push(k);
  }
  return { used, missing, notArabic, badSlots };
}

module.exports = { extract, check };
