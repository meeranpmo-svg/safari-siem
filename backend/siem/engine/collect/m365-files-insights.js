// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SharePoint & OneDrive insights over the read-only file discovery (collect/m365-files.js): nothing new is read from Microsoft and
 * nothing is changed there. Only counts per personal-data kind are held - never a value.
 *   exposure     every file holding personal data or credentials scored 0-100, itemised: what it holds (health / identity /
 *                financial / credentials weigh most, more kinds weigh more) x how far it is shared (anonymous link > people outside the organisation > the whole
 *                organisation > not shared beyond its permissions; sharing not read = unknown, never "safe")
 *   sources      each site and OneDrive ranked by the exposure it holds: files seen, files with personal data, exposed files,
 *                coverage (truncated, unreadable, permission errors said by name)
 *   retention    files with personal data not modified for 3 years - candidates for the retention schedule (PDPL: keep only as
 *                long as needed); folders where personal data concentrates
 *   trend / ML   one sample per discovery run (state m365_files_hist): change in exposed files against the previous runs (robust
 *                z on median / MAD, 4+ runs), new anonymous links since the last run
 *   actions      what to do first, ordered by impact (a credential in a shared file near the top: rotate it, then remove it)
 *   credentials  secrets in files (pii/classify.js: private_key, api_key, password; secret_file by name) - counts only, never a value
 *   GET  {P}/m365/files/insights     any signed-in user: counts; file names, folders, sites and OneDrive owners to analysts and
 *                                    above (they say where personal data lies) - every named read audited
 */
const { wrap, audit, prefixOf } = require('../soc/routeutil');
const DAY = 86400000, RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const CAT_W = { health: 30, identity: 25, financial: 25, credentials: 25, employment: 15, contact: 10 };
const CRED = 'credentials', SHARED = (s) => s === 'anonymous' || s === 'external' || s === 'organization';
const SHARE = { anonymous: [40, 'anyone with the link (anonymous)'], external: [30, 'shared with people outside the organisation'], organization: [10, 'shared with the whole organisation'], none: [0, 'not shared beyond its permissions'] };
const median = (a) => { const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length ? (b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2) : 0; };

function scoreFile(h, CATEGORY) {
  const kinds = Object.keys(h.kinds || {}).concat(h.name_kinds || []).filter((k, i, a) => a.indexOf(k) === i);
  const cats = [...new Set(kinds.map((k) => CATEGORY[k] || 'other'))];
  const why = [];
  const personal = cats.filter((c) => c !== CRED), what = (personal.length ? personal.join(' + ') + ' data' : '') + (cats.includes(CRED) ? (personal.length ? ' and ' : '') + 'credentials' : '');
  const top = cats.reduce((m, c) => Math.max(m, CAT_W[c] || 5), 0); if (top) why.push({ points: top, text: 'holds ' + what + ' (' + kinds.join(', ') + ')' });
  if (kinds.length > 1) why.push({ points: Math.min(15, (kinds.length - 1) * 5), text: kinds.length + ' kinds of ' + (personal.length ? 'personal data' : 'credentials') + (personal.length && cats.includes(CRED) ? ' and credentials' : '') + ' in one file' });
  if (h.shared == null) why.push({ points: 10, text: 'sharing not read - treated as unknown, not safe' });
  else if (SHARE[h.shared] && SHARE[h.shared][0]) why.push({ points: SHARE[h.shared][0], text: SHARE[h.shared][1] });
  if (h.by === 'content') why.push({ points: 5, text: 'found in the content, not just the name' });
  return { score: Math.min(100, why.reduce((s, w) => s + w.points, 0)), why, kinds, categories: cats };
}

function analyse(snap, hist, now, CATEGORY) {
  const t = now || Date.now(), S = (snap && snap.sources) || [], files = [], sources = [];
  for (const s of S) {
    let exp = 0, risk = 0;
    for (const h of s.hits || []) {
      const sc = scoreFile(h, CATEGORY), exposed = h.shared === 'anonymous' || h.shared === 'external', mod = h.modified ? Date.parse(h.modified) : null;
      files.push({ source: s.key, source_label: s.label, kind: s.kind, name: h.name, path: h.path, size: h.size, modified: h.modified, shared: h.shared, score: sc.score, why: sc.why, kinds: sc.kinds, categories: sc.categories, exposed, old: !!(mod && t - mod > 3 * 365 * DAY) });
      if (exposed) exp++; risk += sc.score;
    }
    sources.push({ key: s.key, label: s.label, kind: s.kind, url: s.url, files_seen: s.files_seen, files_read: s.files_read, sensitive: (s.hits || []).length, exposed: exp, risk,
      coverage: { truncated: !!(s.truncated || s.hits_truncated), unreadable: s.files_unreadable || 0, skipped: s.files_skipped || 0, errors: s.errors || [] } });
  }
  files.sort((a, b) => b.score - a.score); sources.sort((a, b) => b.risk - a.risk);
  const by = (f) => files.filter(f).length, share = {}; for (const f of files) { const k = f.shared == null ? 'unknown' : f.shared; share[k] = (share[k] || 0) + 1; }
  const cats = {}; for (const f of files) for (const c of f.categories) cats[c] = (cats[c] || 0) + 1;
  const folders = {}; for (const f of files) { const k = f.source_label + ' › ' + (f.path || '/'); (folders[k] = folders[k] || { folder: k, files: 0, exposed: 0 }).files++; if (f.exposed) folders[k].exposed++; }
  const kpis = { sources: sources.length, sharepoint: sources.filter((s) => s.kind === 'sharepoint').length, onedrive: sources.filter((s) => s.kind === 'onedrive').length,
    files_seen: sources.reduce((a, s) => a + (s.files_seen || 0), 0), sensitive: files.length, anonymous: share.anonymous || 0, external: share.external || 0, organization: share.organization || 0, unknown_sharing: share.unknown || 0,
    high: by((f) => f.score >= 60), old: by((f) => f.old), credentials: by((f) => f.categories.includes(CRED)), credentials_shared: by((f) => f.categories.includes(CRED) && SHARED(f.shared)) };
  // trend: change in exposed files against previous runs
  const H = (hist || []).slice().sort((a, b) => String(a.at).localeCompare(String(b.at))), exposedNow = kpis.anonymous + kpis.external;
  let unusual = null; const prev = H.filter((h) => h.at !== (snap && snap.at)).map((h) => h.exposed);
  if (prev.length >= 4) { const m = median(prev), mad = median(prev.map((v) => Math.abs(v - m))), z = (exposedNow - m) / (1.4826 * (mad || 0.5)); if (Math.abs(z) >= 3) unusual = { exposed: exposedNow, usual: m, z: Math.round(z * 10) / 10 }; }
  const last = H.filter((h) => h.at !== (snap && snap.at)).pop() || null;
  const actions = [], A = (p, title, detail, n) => { if (n) actions.push({ priority: p, title, detail, count: n }); };
  A(98, kpis.credentials_shared + ' shared file(s) holding credentials (' + [...new Set(files.filter((f) => f.categories.includes(CRED) && SHARED(f.shared)).flatMap((f) => f.kinds.filter((k) => CATEGORY[k] === CRED)))].join(', ') + ')',
    'Treat each as leaked: rotate the key / password first, then remove it from the file and stop the sharing; keep secrets in a vault, not in documents.', kpis.credentials_shared);
  A(45, (kpis.credentials - kpis.credentials_shared) + ' other file(s) holding credentials (not shared, or sharing not read)', 'Anyone with access to the library can read them: move the secret to a vault, rotate it, then remove it from the file.', kpis.credentials - kpis.credentials_shared);
  A(100, kpis.anonymous + ' file(s) with personal data behind an anonymous link', 'Anyone with the link can open them: remove the link (or set an expiry and sign-in) in SharePoint / OneDrive sharing.', kpis.anonymous);
  A(90, by((f) => f.shared === 'external' && f.categories.some((c) => c === 'health' || c === 'identity')) + ' file(s) with health or identity data shared outside the organisation', 'Confirm each recipient needs it; PDPL transfers outside need a basis.', by((f) => f.shared === 'external' && f.categories.some((c) => c === 'health' || c === 'identity')));
  A(70, kpis.external + ' file(s) with personal data shared with outside people', 'Review the outside recipients site by site, starting with the highest score.', kpis.external);
  A(55, kpis.unknown_sharing + ' file(s) whose sharing could not be read', 'Grant Sites.Read.All, or the permission budget ran out - sharing is unknown, not safe.', kpis.unknown_sharing);
  A(50, kpis.old + ' file(s) with personal data unchanged for 3 years', 'Candidates for the retention schedule: delete or archive what is no longer needed (PDPL).', kpis.old);
  A(40, sources.filter((s) => s.coverage.truncated || s.coverage.errors.length).length + ' site(s) / OneDrive(s) not fully read', 'The limits or a permission stopped the read - the counts there are a floor.', sources.filter((s) => s.coverage.truncated || s.coverage.errors.length).length);
  if (unusual) A(65, 'Exposed files moved from about ' + unusual.usual + ' to ' + unusual.exposed, 'Far from the usual across the previous runs (robust z ' + unusual.z + ').', 1);
  actions.sort((a, b) => b.priority - a.priority);
  return { generated_at: new Date(t).toISOString(), read_at: (snap && snap.at) || null, never: !!(snap && snap.never), status: (snap && snap.status) || null, errors: (snap && snap.errors) || [],
    kpis, sharing: share, categories: cats, sources, files: files.slice(0, 500), folders: Object.values(folders).sort((a, b) => b.files - a.files).slice(0, 15),
    trend: { runs: H.length, previous: last ? { at: last.at, exposed: last.exposed, sensitive: last.sensitive } : null, unusual, history: H.slice(-20).map((h) => ({ at: h.at, exposed: h.exposed, sensitive: h.sensitive })) },
    actions, note: 'Only counts per kind are kept - never a value (for a credential neither the value nor a snippet). Sharing is read for files that hold personal data; a file whose sharing could not be read is unknown, not safe.' };
}

function register(api, deps) {
  const P = prefixOf(deps), CATEGORY = require('../pii/classify').CATEGORY;
  const col = deps.state ? deps.state.collection('m365_files_hist') : null;
  function view(role) {
    const snap = deps.m365Files ? deps.m365Files.data() : { sources: [], never: true, status: { last_error: 'the SharePoint collector is not running on the SIEM' } };
    if (col && snap.at && !col.get(snap.at)) {
      const a0 = analyse(snap, [], Date.now(), CATEGORY);
      col.put({ id: snap.at, at: snap.at, exposed: a0.kpis.anonymous + a0.kpis.external, sensitive: a0.kpis.sensitive, anonymous: a0.kpis.anonymous });
      const all = col.all().sort((a, b) => String(a.at).localeCompare(String(b.at))); for (const x of all.slice(0, Math.max(0, all.length - 60))) col.remove(x.id);
    }
    const a = analyse(snap, col ? col.all() : [], Date.now(), CATEGORY), named = (RANK[role] || 0) >= RANK.analyst;
    if (!named) { a.files = []; a.folders = []; a.sources = a.sources.map((s) => ({ kind: s.kind, sensitive: s.sensitive, exposed: s.exposed, risk: s.risk })); a.limited = true; }
    a.named = named;
    return a;
  }
  api.route('GET', `${P}/m365/files/insights`, wrap(deps, null, (ctx) => { const v = view(ctx.role); if (v.named) audit(ctx, 'm365.files.insights.read', 'all', { sources: v.kpis.sources, sensitive: v.kpis.sensitive }); return v; }));
}

module.exports = { register, analyse, scoreFile };
