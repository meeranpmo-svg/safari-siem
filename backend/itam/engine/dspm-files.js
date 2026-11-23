// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * DSPM - sensitive files, label policies and breach analysis ({P} = /api/itam, page data-posture.html). Built on what Data Security
 * Posture already reads (engine/data-posture.js build(): every file the SharePoint / OneDrive / file-share discovery found holding
 * personal data or a secret, with its data classes, sharing and age; cloud objects; stores). REPORT ONLY: nothing here changes a file,
 * a label, a permission or a store - labels are SUGGESTED for the people who apply them in Microsoft Purview. PDPL: every figure is an
 * indicator for a person to confirm; file and owner names are shown to operators and administrators only, and each named read is audited.
 *
 *   files      PRIORITISE SENSITIVE DATA RISKS. Every file / object: format (from its extension), system (SharePoint, OneDrive, Teams,
 *              file share, AWS / Azure / OCI), data elements (the classes found, most sensitive first), owner / location, exposure, age,
 *              the regulations its elements bring (PDPL, SAMA / IA financial, PCI DSS card data, health), and a risk score 0-100 with every
 *              point itemised: sensitivity (the most sensitive element, weight x 4, at most 40) + breadth (2 per further element, at most
 *              10) + exposure (anonymous link 30, public 30, outside people 20, everyone 12, the whole organisation 8, unknown 4) + age
 *              (untouched 3 years 8) + personal storage (strong identity / financial / health data on a OneDrive 5) + TOXIC COMBINATION
 *              (a Restricted / Confidential element reachable outside the organisation 12). Violations = files whose policy label is
 *              Confidential or higher and reachable outside, or a secret shared at all. KPIs: files scanned, sensitive files, violations.
 *   clusters   alert-fatigue reduction: violations grouped by location x toxic combination - one finding per group with its file count.
 *   policies   AUTOMATE TAGGING & LABELLING: label policies over file attributes - data elements, system, format, location (site / share
 *              / bucket name), owner, exposure, regulation, age, words in the file name - each giving a label (Public, Internal,
 *              Confidential, Highly Confidential, Restricted) and optionally EXCLUDE FROM COPILOT (the label to set in Purview so the file
 *              is kept out of Microsoft 365 Copilot answers). The lowest priority number wins; a file matched by two policies with
 *              different labels is a CONFLICT. Four built-in policies are seeded once (Restricted identity / health / secrets, Confidential
 *              financial, Internal contact data, Highly Confidential board / legal / HR documents). Written by an administrator - a person,
 *              with a reason, versioned, audited.
 *   logs       each evaluation compares every file's label with the previous one (dspm_label_state): new / changed labels are logged
 *              (dspm_label_log, 5,000 kept) with the policy that set them.
 *   stats      per policy: files matched, by system, by label, Copilot exclusions; unlabelled sensitive files.
 *   suggest    LEARNED policies: sensitive files no policy labels, clustered by location x most sensitive element (5+ files) - a draft
 *              policy for an administrator to review.
 *   breach     DATA BREACH ANALYSIS: the radius if a store, a system or a data element were breached (or after it was) - files, data
 *              elements, who could reach them, locations outside the Kingdom, the regulations triggered with what they require and by when
 *              (PDPL Implementing Regulation Art. 24: SDAIA within 72 hours of becoming aware when harm is likely, data subjects without
 *              undue delay; SAMA / IA incident reporting for financial data; PCI DSS for card data), an impact tier with its reasons and, when
 *              the DPO has set a cost per affected file in the settings, an indicative SAR estimate stating that basis. WHAT-IF: every store
 *              ranked by the radius it would have, before any incident.
 * Routes:  GET  /data-posture/files?filter=&limit= (operator, audited)     GET /data-posture/labels (operator)
 *          GET  /data-posture/label-policies (operator)                     POST /data-posture/label-policies (admin, a person)
 *          POST /data-posture/label-policies/:id/delete (admin, a person)  GET /data-posture/label-log (operator)
 *          POST /data-posture/breach (operator, audited)                    GET /data-posture/breach/what-if (operator)
 *          POST /data-posture/breach/settings (admin, a person) {cost_per_file_sar}
 */
const r1 = (x) => Math.round(x * 10) / 10;
const LABELS = ['Public', 'Internal', 'Confidential', 'Highly Confidential', 'Restricted'];
const WEIGHT = { health: 10, biometric: 10, private_key: 9, api_key: 9, password: 9, secret_file: 8, national_id: 8, iqama: 8, passport: 8, card: 8, iban: 7, salary: 7, credit: 7, cv: 5, birth_date: 5, mobile: 4, address: 4, email: 3, name: 2 };
const CRED = ['private_key', 'api_key', 'password', 'secret_file'], STRONG = ['national_id', 'iqama', 'passport', 'iban', 'card', 'health', 'salary', 'biometric'];
const SYSTEM = { sharepoint: 'SharePoint', onedrive: 'OneDrive', teams: 'Teams', fileshare: 'File share', 'cloud:aws': 'AWS S3', 'cloud:azure': 'Azure storage', 'cloud:oci': 'OCI storage', 'cloud:other': 'Cloud storage' };
const FORMAT = [[/\.(docx?|rtf|odt)$/i, 'Word'], [/\.(xlsx?|xlsm|ods)$/i, 'Excel'], [/\.csv$/i, 'CSV'], [/\.pdf$/i, 'PDF'], [/\.(pptx?|odp)$/i, 'PowerPoint'], [/\.(txt|log|md)$/i, 'Plain text'], [/\.(json|xml|ya?ml|ini|conf|cfg|env|properties)$/i, 'Config / data'],
  [/\.(pem|key|pfx|p12|cer|crt|jks|kdbx|ppk)$/i, 'Key / certificate'], [/\.(sql|bak|dmp|mdb|accdb|db|sqlite)$/i, 'Database / dump'], [/\.(zip|7z|rar|tar|gz)$/i, 'Archive'], [/\.(jpe?g|png|gif|bmp|tiff?|heic)$/i, 'Image'], [/\.(msg|eml|pst)$/i, 'E-mail']];
const formatOf = (n) => { for (const [re, f] of FORMAT) if (re.test(String(n || ''))) return f; return 'Other'; };
const EXPOSURE = { anonymous: [30, 'anyone with the link'], public: [30, 'public on the internet'], external: [20, 'people outside the organisation'], everyone: [12, 'everyone in the organisation (share open to all)'], organization: [8, 'the whole organisation'], unknown: [4, 'sharing not reported'] };
const OUTSIDE = ['anonymous', 'public', 'external'];
const regsOf = (els) => { const r = []; if (els.some((k) => !CRED.includes(k))) r.push('PDPL'); if (els.some((k) => ['iban', 'card', 'salary', 'credit'].includes(k))) r.push('SAMA / IA'); if (els.includes('card')) r.push('PCI DSS'); if (els.some((k) => ['health', 'biometric'].includes(k))) r.push('Health data'); if (els.some((k) => CRED.includes(k))) r.push('Secrets'); return r; };
const ageDays = (m, now) => { const t = Date.parse(m || ''); return Number.isFinite(t) ? Math.floor((now - t) / 86400000) : null; };
const idOf = (store, path, name) => crypto.createHash('sha1').update(String(store) + '|' + String(path) + '|' + String(name)).digest('hex').slice(0, 16);

/* pure: the DSPM context -> file items */
function fileItems(C, KIND_LABEL, now) {
  const out = [];
  for (const r of C.rows || []) {
    const st = r.store || {}, els = [...new Set(r.kinds || [])].sort((a, b) => (WEIGHT[b] || 0) - (WEIGHT[a] || 0));
    const exp = r.shared == null ? 'unknown' : ['anonymous', 'external', 'organization', 'everyone', 'none'].includes(String(r.shared)) ? String(r.shared) : 'unknown';
    out.push({ id: idOf(st.id, r.path, r.name), name: r.name, path: r.path, store_id: st.id, location: st.label, system: SYSTEM[st.type] || st.type || 'Other', system_key: st.type, owner: st.type === 'onedrive' ? st.label : null, format: formatOf(r.name),
      elements: els, element_labels: els.map((k) => KIND_LABEL[k] || k), exposure: exp, age_days: ageDays(r.modified, now), modified: r.modified || null, in_kingdom: null });
  }
  const cloudById = new Map((C.cloudStores || []).map((x) => [x.id, x]));
  for (const o of C.cloudObjects || []) {
    const st = cloudById.get(o.store_id) || cloudById.get('cloud:' + String(o.store_id)) || [...cloudById.values()].find((x) => x.raw_id === o.store_id) || {};
    const els = [...new Set(o.kinds || [])].sort((a, b) => (WEIGHT[b] || 0) - (WEIGHT[a] || 0)), name = String(o.key || '').split('/').pop();
    out.push({ id: idOf(o.store_id, o.key, ''), name, path: o.key, store_id: st.id || o.store_id, location: st.label || o.store_id, system: SYSTEM[st.type] || 'Cloud storage', system_key: st.type || 'cloud:other', owner: null, format: formatOf(name),
      elements: els, element_labels: els.map((k) => KIND_LABEL[k] || k), exposure: st.public === true ? 'public' : o.exposure === 'public' ? 'public' : st.public === false ? 'none' : 'unknown', age_days: ageDays(o.modified, now), modified: o.modified || null, in_kingdom: st.in_kingdom == null ? null : st.in_kingdom });
  }
  return out;
}

/* pure: a file's risk, itemised */
function riskOf(f, label) {
  const items = [], add = (p, l) => { if (p) items.push({ points: Math.round(p), label: l }); };
  const top = f.elements[0], w = WEIGHT[top] || 1;
  add(Math.min(40, w * 4), 'holds ' + (f.element_labels[0] || 'personal data'));
  add(Math.min(10, 2 * Math.max(0, f.elements.length - 1)), f.elements.length > 1 ? (f.elements.length - 1) + ' more data element(s)' : '');
  const e = EXPOSURE[f.exposure]; if (e) add(e[0], 'reachable by ' + e[1]);
  if (f.age_days != null && f.age_days >= 3 * 365) add(8, 'untouched for ' + Math.floor(f.age_days / 365) + ' years');
  if (f.system_key === 'onedrive' && f.elements.some((k) => STRONG.includes(k))) add(5, 'strong personal data in personal storage (OneDrive)');
  if (f.in_kingdom === false) add(6, 'stored outside the Kingdom');
  const lv = LABELS.indexOf(label), toxic = lv >= 2 && (OUTSIDE.includes(f.exposure) || (f.elements.some((k) => CRED.includes(k)) && f.exposure !== 'none' && f.exposure !== 'unknown'));
  if (toxic) add(12, 'TOXIC: ' + (f.element_labels[0] || 'sensitive data') + ' (' + label + ') reachable by ' + (EXPOSURE[f.exposure] || ['', f.exposure])[1]);
  return { score: Math.min(100, items.reduce((n, i) => n + i.points, 0)), items, toxic };
}

/* pure: label policies */
const BUILTIN = [
  { id: 'lp-restricted', name: 'Restricted - identity, health and secrets', label: 'Restricted', exclude_copilot: true, priority: 10, enabled: true, elements_any: ['national_id', 'iqama', 'passport', 'health', 'biometric', 'private_key', 'api_key', 'password', 'secret_file'], note: 'national ID / Iqama / passport numbers, health and biometric data, keys and passwords' },
  { id: 'lp-board', name: 'Highly Confidential - board, legal and HR documents', label: 'Highly Confidential', exclude_copilot: true, priority: 20, enabled: true, name_any: ['board', 'minutes', 'strategy', 'merger', 'acquisition', 'contract', 'legal', 'salary', 'payroll', 'appraisal', 'disciplinary'], note: 'documents whose name marks them as board, legal or HR material' },
  { id: 'lp-financial', name: 'Confidential - financial data', label: 'Confidential', exclude_copilot: true, priority: 30, enabled: true, elements_any: ['iban', 'card', 'salary', 'credit'], note: 'IBAN, card, salary and credit data (SAMA / IA, PCI DSS)' },
  { id: 'lp-internal', name: 'Internal - contact data', label: 'Internal', exclude_copilot: false, priority: 90, enabled: true, elements_any: ['mobile', 'email', 'name', 'address', 'birth_date', 'cv'], note: 'names, contact details, CVs' }];
function matches(p, f) {
  if (p.enabled === false) return false;
  const any = (list, vals) => !list || !list.length || list.some((x) => vals.includes(x));
  const low = (s) => String(s || '').toLowerCase();
  if (!any(p.elements_any, f.elements)) return false;
  if (p.systems_any && p.systems_any.length && !p.systems_any.includes(f.system_key)) return false;
  if (p.formats_any && p.formats_any.length && !p.formats_any.includes(f.format)) return false;
  if (p.exposure_any && p.exposure_any.length && !p.exposure_any.includes(f.exposure)) return false;
  if (p.regulation_any && p.regulation_any.length && !p.regulation_any.some((r) => regsOf(f.elements).includes(r))) return false;
  if (p.location_contains && !low(f.location).includes(low(p.location_contains))) return false;
  if (p.owner_contains && !low(f.owner).includes(low(p.owner_contains))) return false;
  if (p.name_any && p.name_any.length && !p.name_any.some((w) => new RegExp('(^|[^a-z])' + low(w).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i').test(f.name || ''))) return false;
  if (p.min_age_days != null && (f.age_days == null || f.age_days < p.min_age_days)) return false;
  if (p.max_age_days != null && (f.age_days == null || f.age_days > p.max_age_days)) return false;
  return true;
}
function labelOf(f, policies) {
  const hit = policies.filter((p) => matches(p, f)).sort((a, b) => a.priority - b.priority);
  if (!hit.length) return { label: null, policy: null, exclude_copilot: false, conflict: false };
  const conflict = new Set(hit.map((p) => p.label)).size > 1;
  return { label: hit[0].label, policy: { id: hit[0].id, name: hit[0].name }, exclude_copilot: !!hit[0].exclude_copilot, conflict, others: conflict ? hit.slice(1).filter((p) => p.label !== hit[0].label).map((p) => ({ id: p.id, name: p.name, label: p.label })) : [] };
}

function createDspmFiles(app, P, opts = {}) {
  const now = opts.now || Date.now, store = app.store, pol = () => store.collection('dspm_label_policies'), state = () => store.collection('dspm_label_state'), log = () => store.collection('dspm_label_log'), cfg = () => store.collection('dspm_files_cfg');
  const bad = (m, status = 400) => Object.assign(new Error(m), { status });
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action, target, detail }); };
  function policies() {
    const c = pol(); if (!c.get('seeded')) { for (const b of BUILTIN) c.put(Object.assign({}, b, { version: 1, created_by: 'built-in', created_at: new Date(now()).toISOString(), history: [] })); c.put({ id: 'seeded', seeded: true }); }
    return c.all((p) => p.id !== 'seeded' && !p.deleted).sort((a, b) => a.priority - b.priority);
  }
  async function model(who) {
    const { C } = await P.build(who), P2 = policies(), files = fileItems(C, P.KIND_LABEL || {}, now());
    for (const f of files) { f.policy = labelOf(f, P2); f.label = f.policy.label; const r = riskOf(f, f.label || 'Internal'); f.risk = r.score; f.risk_items = r.items; f.toxic = r.toxic; f.regulations = regsOf(f.elements);
      f.violation = (LABELS.indexOf(f.label) >= 2 && OUTSIDE.includes(f.exposure)) || (f.elements.some((k) => CRED.includes(k)) && !['none', 'unknown'].includes(f.exposure)) ? (OUTSIDE.includes(f.exposure) ? f.label + ' data reachable by ' + EXPOSURE[f.exposure][1] : 'a secret shared with ' + EXPOSURE[f.exposure][1]) : null; }
    files.sort((a, b) => b.risk - a.risk);
    const scanned = (C.stores || []).reduce((n, s) => n + (Number(s.files_seen) || 0), 0) + (C.cloudStores || []).reduce((n, s) => n + (Number(s.objects_scanned) || 0), 0);
    return { C, files, policies: P2, scanned, measured: !!(C.src && ((C.src.m365_files && C.src.m365_files.measured) || (C.src.cloud && C.src.cloud.measured))) };
  }
  /* label logs: new / changed labels since the previous evaluation */
  function recordLabels(files) {
    const S = state(), L = log(), t = new Date(now()).toISOString(); let n = 0;
    for (const f of files) {
      const prev = S.get(f.id), cur = f.label || null;
      if (!prev || prev.label !== cur) { S.put({ id: f.id, label: cur, at: t }); if (cur || prev) { n++; L.put({ id: t + '-' + f.id, at: t, file: f.name, location: f.location, system: f.system, element: f.element_labels[0] || '', from: prev ? prev.label : null, to: cur, policy: f.policy.policy ? f.policy.policy.name : null, exclude_copilot: f.policy.exclude_copilot }); } }
    }
    if (n) { const all = L.all().sort((a, b) => String(b.at).localeCompare(String(a.at))); for (const x of all.slice(5000)) L.remove(x.id); }
    return n;
  }
  async function filesView(q, who) {
    const b = body(q || {}).oneOf('filter', ['all', 'violations', 'toxic', 'unlabelled', 'copilot'], { def: 'all' }).int('limit', { min: 1, max: 500, def: 100 }).done();
    const M = await model(who); recordLabels(M.files);
    const sens = M.files.filter((f) => f.elements.length), F = sens.filter((f) => b.filter === 'all' || (b.filter === 'violations' && f.violation) || (b.filter === 'toxic' && f.toxic) || (b.filter === 'unlabelled' && !f.label) || (b.filter === 'copilot' && f.policy.exclude_copilot));
    const groups = new Map(); for (const f of sens.filter((x) => x.violation)) { const k = f.location + '|' + (f.element_labels[0] || '') + '|' + f.exposure; const g = groups.get(k) || { location: f.location, system: f.system, element: f.element_labels[0] || '', exposure: EXPOSURE[f.exposure] ? EXPOSURE[f.exposure][1] : f.exposure, files: 0, max_risk: 0 }; g.files++; g.max_risk = Math.max(g.max_risk, f.risk); groups.set(k, g); }
    const clusters = [...groups.values()].sort((a, b) => b.max_risk - a.max_risk || b.files - a.files).slice(0, 20).map((g) => Object.assign(g, { why: g.files + ' file(s) with ' + g.element + ' in ' + g.location + ' reachable by ' + g.exposure + ' - one fix (the sharing of that location) closes them' }));
    const byEl = {}; for (const f of sens) for (const l of f.element_labels) byEl[l] = (byEl[l] || 0) + 1;
    audit(who, 'dspm.files.read', b.filter, { files: F.length });
    return { generated_at: new Date(now()).toISOString(), measured: M.measured, kpis: { files: M.scanned, sensitive: sens.length, violations: sens.filter((f) => f.violation).length, toxic: sens.filter((f) => f.toxic).length, unlabelled: sens.filter((f) => !f.label).length, copilot_excluded: sens.filter((f) => f.policy.exclude_copilot).length },
      by_element: Object.entries(byEl).map(([k, n]) => ({ element: k, files: n })).sort((a, b) => b.files - a.files), clusters, filter: b.filter, total: F.length,
      files: F.slice(0, b.limit).map((f) => ({ id: f.id, name: f.name, path: f.path, location: f.location, system: f.system, owner: f.owner, format: f.format, elements: f.element_labels, exposure: f.exposure, age_days: f.age_days, label: f.label, policy: f.policy.policy, conflict: f.policy.conflict, exclude_copilot: f.policy.exclude_copilot, regulations: f.regulations, risk: f.risk, risk_items: f.risk_items, toxic: f.toxic, violation: f.violation })),
      note: 'Data elements are found by the discovery scans (patterns and checks per class); the score is an indicator for a person to confirm. Labels are suggestions for Microsoft Purview - this platform applies none.' };
  }
  async function labelsView(who) {
    const M = await model(who); recordLabels(M.files);
    const sens = M.files.filter((f) => f.elements.length), stats = M.policies.map((p) => { const mine = sens.filter((f) => f.policy.policy && f.policy.policy.id === p.id), bySys = {}; for (const f of mine) bySys[f.system] = (bySys[f.system] || 0) + 1;
      return { id: p.id, name: p.name, label: p.label, files: mine.length, by_system: bySys, copilot_excluded: p.exclude_copilot ? mine.length : 0, conflicts: mine.filter((f) => f.policy.conflict).length }; });
    const byLabel = {}; for (const f of sens) byLabel[f.label || 'Not labelled'] = (byLabel[f.label || 'Not labelled'] || 0) + 1;
    // learned: sensitive files no policy labels, clustered by location x most sensitive element (5+)
    const cl = new Map(); for (const f of sens.filter((x) => !x.label)) { const k = f.location + '|' + f.elements[0]; const g = cl.get(k) || { location: f.location, system_key: f.system_key, element: f.elements[0], element_label: f.element_labels[0], files: 0 }; g.files++; cl.set(k, g); }
    const suggestions = [...cl.values()].filter((g) => g.files >= 5).sort((a, b) => b.files - a.files).slice(0, 10).map((g) => { const w = WEIGHT[g.element] || 1, label = w >= 8 ? 'Restricted' : w >= 7 ? 'Confidential' : 'Internal';
      return { name: label + ' - ' + g.element_label + ' in ' + g.location, label, exclude_copilot: w >= 7, elements_any: [g.element], location_contains: g.location, files: g.files, why: g.files + ' file(s) with ' + g.element_label + ' in ' + g.location + ' that no policy labels' }; });
    return { policies: M.policies, stats, by_label: byLabel, conflicts: sens.filter((f) => f.policy.conflict).length, unlabelled: sens.filter((f) => !f.label).length, suggestions, labels: LABELS, can_edit: (who && String(who.role).toLowerCase() === 'admin' && isHuman(who.user)) || false };
  }
  function savePolicy(b0, who) {
    if (!isHuman(who && who.user)) throw bad('a person writes label policies', 403);
    const b = body(b0 || {}).str('id', { max: 40 }).str('name', { required: true, min: 3, max: 120 }).oneOf('label', LABELS, { required: true }).bool('exclude_copilot', { def: false }).int('priority', { min: 1, max: 999, def: 50 }).bool('enabled', { def: true })
      .list('elements_any', { max: 30, item: Object.keys(WEIGHT), unique: true }).list('systems_any', { max: 10, item: Object.keys(SYSTEM), unique: true }).list('formats_any', { max: 15, item: FORMAT.map((f) => f[1]).concat(['Other']), unique: true })
      .list('exposure_any', { max: 7, item: ['anonymous', 'public', 'external', 'everyone', 'organization', 'none', 'unknown'], unique: true }).list('regulation_any', { max: 5, item: ['PDPL', 'SAMA / IA', 'PCI DSS', 'Health data', 'Secrets'], unique: true })
      .list('name_any', { max: 20, item: 'str', itemMax: 40 }).str('location_contains', { max: 120 }).str('owner_contains', { max: 120 }).int('min_age_days', { min: 0, max: 36500 }).int('max_age_days', { min: 0, max: 36500 })
      .str('note', { max: 300 }).str('reason', { required: true, min: 3, max: 300 }).int('base_version', { min: 0, max: 1e9 })
      .rule((o) => (!['elements_any', 'systems_any', 'formats_any', 'exposure_any', 'regulation_any', 'name_any'].some((k) => o[k] && o[k].length) && !o.location_contains && !o.owner_contains && o.min_age_days == null && o.max_age_days == null ? 'give the policy at least one condition' : null)).done();
    policies(); const c = pol(), prev = b.id ? c.get(b.id) : null;
    if (b.id && (!prev || prev.deleted)) throw bad('label policy not found', 404);
    if (prev && b.base_version != null && b.base_version !== prev.version) throw bad('this policy was changed meanwhile (version ' + prev.version + ') - reload and try again', 409);
    const t = new Date(now()).toISOString(), id = prev ? prev.id : 'lp-' + crypto.randomBytes(4).toString('hex');
    const rec = Object.assign({}, b, { id, version: prev ? prev.version + 1 : 1, created_by: prev ? prev.created_by : who.user, created_at: prev ? prev.created_at : t, updated_by: who.user, updated_at: t, history: (prev ? prev.history || [] : []).concat({ at: t, by: who.user, reason: b.reason, action: prev ? 'changed' : 'created' }).slice(-50) });
    delete rec.reason; delete rec.base_version; c.put(rec);
    audit(who, prev ? 'dspm.label.policy.change' : 'dspm.label.policy.create', id, { name: rec.name, label: rec.label, exclude_copilot: rec.exclude_copilot, priority: rec.priority, reason: b.reason });
    return rec;
  }
  function deletePolicy(id, b0, who) {
    if (!isHuman(who && who.user)) throw bad('a person removes label policies', 403);
    const b = body(b0 || {}).str('reason', { required: true, min: 3, max: 300 }).done(), c = pol(), p = c.get(String(id || ''));
    if (!p || p.deleted || p.id === 'seeded') throw bad('label policy not found', 404);
    p.deleted = { by: who.user, at: new Date(now()).toISOString(), reason: b.reason }; c.put(p);
    audit(who, 'dspm.label.policy.delete', p.id, { name: p.name, reason: b.reason });
    return { removed: p.id };
  }
  function labelLog(q) { const b = body(q || {}).int('limit', { min: 1, max: 1000, def: 200 }).done(); return { items: log().all().sort((a, b2) => String(b2.at).localeCompare(String(a.at))).slice(0, b.limit), total: log().all().length }; }
  /* breach analysis */
  function radius(sel, M) {
    const F = M.files.filter((f) => f.elements.length && sel(f)); if (!F.length) return null;
    const els = {}; for (const f of F) for (const l of f.element_labels) els[l] = (els[l] || 0) + 1;
    const reach = {}; for (const f of F) { const e = EXPOSURE[f.exposure]; const k = e ? e[1] : f.exposure === 'none' ? 'only people given access' : f.exposure; reach[k] = (reach[k] || 0) + 1; }
    const regs = [...new Set(F.flatMap((f) => f.regulations))], strong = F.filter((f) => f.elements.some((k) => STRONG.includes(k))).length, outside = F.filter((f) => OUTSIDE.includes(f.exposure)).length, abroad = F.filter((f) => f.in_kingdom === false).length;
    const reasons = []; let tier = 'Low';
    if (strong) reasons.push(strong + ' file(s) with identity, financial or health data'); if (outside) reasons.push(outside + ' already reachable outside the organisation'); if (abroad) reasons.push(abroad + ' stored outside the Kingdom'); if (F.length >= 100) reasons.push(F.length + ' files');
    if (strong && (outside || F.length >= 100)) tier = 'High'; else if (strong || F.length >= 50 || outside) tier = 'Medium';
    return { files: F.length, locations: [...new Set(F.map((f) => f.location))].length, elements: Object.entries(els).map(([k, n]) => ({ element: k, files: n })).sort((a, b) => b.files - a.files), reachable_by: reach, regulations: regs, abroad, tier, reasons };
  }
  function obligations(regs, abroad) {
    const o = [];
    if (regs.includes('PDPL') || regs.includes('Health data')) { o.push({ who: 'SDAIA (National Data Management Office)', what: 'Notify the personal data breach when it may harm the data subjects: what happened, the data and approximate number of people, the risks, the measures, the DPO contact', when: 'within 72 hours of becoming aware', ref: 'PDPL Implementing Regulation Art. 24' });
      o.push({ who: 'The people affected', what: 'Tell them in clear language what happened, the risks, what was done and what they can do', when: 'without undue delay, when the breach may harm them', ref: 'PDPL Implementing Regulation Art. 24' }); }
    if (regs.includes('SAMA / IA')) o.push({ who: 'SAMA / Insurance Authority', what: 'Report the cyber security incident as the Cyber Security Framework requires', when: 'per the framework\'s incident-reporting timelines', ref: 'SAMA CSF 3.3.15 (Cyber Security Incident Management)' });
    if (regs.includes('PCI DSS')) o.push({ who: 'Acquiring bank / card brands', what: 'Start the card-data incident response plan', when: 'immediately', ref: 'PCI DSS 12.10' });
    if (regs.includes('Secrets')) o.push({ who: 'System owners', what: 'Rotate every key, token and password found in the affected files', when: 'immediately', ref: 'incident containment' });
    if (abroad) o.push({ who: 'DPO', what: 'Check the cross-border transfer basis for the data stored outside the Kingdom', when: 'with the SDAIA notification', ref: 'PDPL Art. 29 / Transfer Regulation' });
    return o;
  }
  async function breach(b0, who) {
    const b = body(b0 || {}).oneOf('scope_type', ['store', 'system', 'element'], { required: true }).str('scope', { required: true, max: 300 }).done();
    const M = await model(who), sel = b.scope_type === 'store' ? (f) => f.store_id === b.scope || f.location === b.scope : b.scope_type === 'system' ? (f) => f.system_key === b.scope || f.system === b.scope : (f) => f.elements.includes(b.scope);
    const R = radius(sel, M); if (!R) throw bad('nothing holding personal data or secrets matches this scope in the latest discovery', 404);
    const cost = Number((cfg().get('cfg') || {}).cost_per_file_sar) || null;
    audit(who, 'dspm.breach.analyse', b.scope_type + ':' + b.scope, { files: R.files, tier: R.tier });
    return Object.assign({ scope_type: b.scope_type, scope: b.scope, obligations: obligations(R.regulations, R.abroad), estimate: cost ? { sar: Math.round(cost * R.files), basis: 'SAR ' + cost + ' per affected file (set by the DPO) x ' + R.files + ' files - an indication, not a valuation' } : { sar: null, basis: 'set a cost per affected file in the breach settings (DPO) to see an indicative figure' },
      note: 'The radius is what the latest discovery found: files not scanned and records inside databases are not counted. Confirm with the owners before notifying.' }, R);
  }
  async function whatIf(who) {
    const M = await model(who), stores = [...new Set(M.files.filter((f) => f.elements.length).map((f) => f.store_id))];
    const T = { High: 3, Medium: 2, Low: 1 };
    return { stores: stores.map((id) => { const R = radius((f) => f.store_id === id, M), f0 = M.files.find((f) => f.store_id === id); return Object.assign({ store_id: id, location: f0.location, system: f0.system }, R); }).sort((a, b) => T[b.tier] - T[a.tier] || b.files - a.files).slice(0, 25), cost_per_file_sar: Number((cfg().get('cfg') || {}).cost_per_file_sar) || null };
  }
  function saveSettings(b0, who) {
    if (!isHuman(who && who.user)) throw bad('a person changes this', 403);
    const b = body(b0 || {}).num('cost_per_file_sar', { min: 0, max: 1e7 }).str('reason', { required: true, min: 3, max: 300 }).done();
    cfg().put({ id: 'cfg', cost_per_file_sar: b.cost_per_file_sar == null ? null : b.cost_per_file_sar, by: who.user, at: new Date(now()).toISOString() });
    audit(who, 'dspm.breach.settings', 'cost', { cost_per_file_sar: b.cost_per_file_sar, reason: b.reason });
    return cfg().get('cfg');
  }
  return { filesView, labelsView, savePolicy, deletePolicy, labelLog, breach, whatIf, saveSettings, policies };
}

function registerDspmFiles(srv, app, P, opts) {
  const X = createDspmFiles(app, P, opts || {});
  (app.addons = app.addons || {}).dspmFiles = X;
  srv.route('GET', '/data-posture/files', (ctx) => { ctx.need('operator'); return X.filesView(ctx.query, ctx.who); });
  srv.route('GET', '/data-posture/labels', (ctx) => { ctx.need('operator'); body(ctx.query || {}).done(); return X.labelsView(ctx.who); });
  srv.route('GET', '/data-posture/label-policies', (ctx) => { ctx.need('operator'); body(ctx.query || {}).done(); return { policies: X.policies() }; });
  srv.route('POST', '/data-posture/label-policies', (ctx) => { ctx.need('admin'); return X.savePolicy(ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('POST', '/data-posture/label-policies/:id/delete', (ctx) => { ctx.need('admin'); return X.deletePolicy(param(ctx.params.id, 'id'), ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('GET', '/data-posture/label-log', (ctx) => { ctx.need('operator'); return X.labelLog(ctx.query); });
  srv.route('POST', '/data-posture/breach', (ctx) => { ctx.need('operator'); return X.breach(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('GET', '/data-posture/breach/what-if', (ctx) => { ctx.need('operator'); body(ctx.query || {}).done(); return X.whatIf(ctx.who); });
  srv.route('POST', '/data-posture/breach/settings', (ctx) => { ctx.need('admin'); return X.saveSettings(ctx.body, ctx.who); }, { maxBody: 2048 });
  return X;
}

module.exports = { createDspmFiles, registerDspmFiles, fileItems, riskOf, labelOf, matches, formatOf, regsOf, BUILTIN, LABELS };
