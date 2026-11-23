// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * grc-policy-file.js - the organisation's signed IT policy register as the GRC modules read it.
 * The register is the organisation's own content: it is NOT shipped with the engine (engine/grc-policies.json is an empty
 * list). An administrator provides it as a JSON file (the same fields: doc_id, title, domain, sub_code, owner, status,
 * next_review, requirements ...) at SENTRA_GRC_POLICIES or /var/lib/sentra-itam/grc-policies.json; until then the GRC
 * pages show an empty register and say what to add. A file that cannot be read or is not a list is an error in the log
 * and an empty register - never another organisation's policies.
 */
const fs = require('fs'), path = require('path');
let cache = null, cacheKey = '';
function policies(env) {
  env = env || process.env;
  const tries = [env.SENTRA_GRC_POLICIES, '/var/lib/sentra-itam/grc-policies.json', path.join(__dirname, 'grc-policies.json')].filter(Boolean);
  const key = tries.join('|'); if (cache && key === cacheKey) return cache;
  let out = [];
  for (const f of tries) {
    let raw;
    try { raw = fs.readFileSync(f, 'utf8'); } catch (e) { if (e.code === 'ENOENT' || e.code === 'EACCES') continue; throw e; }
    const j = JSON.parse(raw); out = Array.isArray(j) ? j : (Array.isArray(j.policies) ? j.policies : null);
    if (!out) throw new Error('grc policy register ' + f + ' is not a list of policies');
    break;
  }
  cache = out; cacheKey = key; return out;
}
module.exports = policies;
