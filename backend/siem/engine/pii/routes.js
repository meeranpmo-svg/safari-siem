// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Personal-data discovery in files ({P} = /api/soc), read by IT Asset Management's PDPL Data Catalog as a named person.
 *   GET  {P}/pii/files               analyst  SharePoint / OneDrive result (collect/m365-files.js) + the latest file-share
 *                                             scan per Windows file server (agent 1.5, pii/classify.js rules)   every read audited
 *   POST {P}/pii/sharepoint/run      admin    start the SharePoint / OneDrive discovery now (one at a time)          audited
 * Analyst and above: file names, folders and sharing say where personal data lies - not for every viewer. No value is
 * ever in these answers: counts per kind per file only. The file-share scans arrive with the agent's events (its token).
 * The answer also carries credentials: { files, by_kind: { private_key, api_key, password, secret_file }, shared } - files
 * holding a secret (counted from what is already held, nothing new is read), so other modules can show risky credentials
 * without re-deriving them; shared = SharePoint / OneDrive shared beyond its permissions, or a file-share file open to everyone.
 */
const { wrap, audit, prefixOf } = require('../soc/routeutil');
const { CATEGORY } = require('./classify');

const CRED_KINDS = Object.keys(CATEGORY).filter((k) => CATEGORY[k] === 'credentials');
function credentialSummary(sp, shares) {
  const out = { files: 0, by_kind: Object.fromEntries(CRED_KINDS.map((k) => [k, 0])), shared: 0 };
  const take = (h, shared) => {
    if (!h || typeof h !== 'object') return;
    const kinds = Object.keys(h.kinds && typeof h.kinds === 'object' ? h.kinds : {}).concat(Array.isArray(h.name_kinds) ? h.name_kinds : []).filter((k, i, a) => CATEGORY[k] === 'credentials' && a.indexOf(k) === i);
    if (!kinds.length) return;
    out.files++; for (const k of kinds) out.by_kind[k]++;
    if (shared) out.shared++;
  };
  for (const s of (sp && Array.isArray(sp.sources) ? sp.sources : [])) for (const h of Array.isArray(s.hits) ? s.hits : []) take(h, h.shared === 'anonymous' || h.shared === 'external' || h.shared === 'organization');
  for (const host of shares || []) for (const r of ((host && host.settings && Array.isArray(host.settings.roots)) ? host.settings.roots : [])) for (const h of Array.isArray(r.hits) ? r.hits : []) take(h, h.open === true);
  return out;
}

function register(api, deps) {
  const P = prefixOf(deps);
  api.route('GET', `${P}/pii/files`, wrap(deps, 'analyst', (ctx) => {
    const sp = deps.m365Files ? deps.m365Files.data() : { sources: [], never: true, status: { last_error: 'the SharePoint collector is not running on the SIEM' } };
    const shares = deps.piiShares ? deps.piiShares.list() : [];
    const credentials = credentialSummary(sp, shares);
    audit(ctx, 'pii.files.read', 'all', { sharepoint_sources: (sp.sources || []).length, file_servers: shares.length, credential_files: credentials.files });
    return { sharepoint: sp, fileshares: { hosts: shares, stats: deps.piiShares ? deps.piiShares.stats() : null }, credentials };
  }));
  api.route('POST', `${P}/pii/sharepoint/run`, wrap(deps, 'admin', (ctx) => {
    if (!deps.m365Files) return { started: false, reason: 'the SharePoint collector is not running on the SIEM' };
    const r = deps.m365Files.runNow(ctx.user || 'admin');
    audit(ctx, 'pii.sharepoint.run', 'sharepoint', { started: r.started });
    return r;
  }));
}

module.exports = { register, credentialSummary };
