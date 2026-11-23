// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { guardOf } = require('./errors');
/*
 * Data Security Posture ({P} = /api/itam, page data-posture.html). REPORT ONLY: it reads what the platform already collects and
 * changes nothing anywhere. Microsoft 365 and Azure are the first-class sources; everything else is read the same way.
 * PDPL framing: every number is an INDICATOR for a person to confirm, not proof.
 *
 * Sources (a source that is not there is listed under not_measured with what to connect - it never counts as safe):
 *   SIEM, through the platform's ONE link (app.discovery.siem.call) as the named person with the analyst role:
 *     m365_files      GET /pii/files              SharePoint / OneDrive discovery (collect/m365-files.js: every file holding personal
 *                                                 data or credentials, counts per kind, sharing anonymous / external / organization /
 *                                                 none / unknown) + the Windows agent's file-share scans (fileshares.hosts[].settings.roots)
 *                                                 and, when the SIEM has it, a `credentials` summary {files, by_kind, shared}
 *     m365_insights   GET /m365/files/insights    the SIEM's 0-100 exposure per file and its KPIs (anonymous, external, old, credentials) -
 *                                                 used for the exposure score of each named file, and for the counts when /pii/files is not readable
 *     cloud           GET /cloud-data/stores      AWS S3 / Azure storage / OCI buckets: in_kingdom, public, encrypted, objects with findings,
 *                                                 kinds and categories (HTTP 404 = the SIEM is not updated yet, said so)
 *     shadow_ai       GET /shadow-ai/register, GET /shadow-ai/signals?hours=720   AI apps with status / allowed classes; DLP incidents to them
 *     m365_security   GET /m365/security          administrators without MFA; open Defender / Purview alerts (product / category)
 *     m365_directory  GET /m365/graph             guest accounts and their last sign-in (only when Graph gave signInActivity)
 *   Local (IT Asset Management):
 *     databases       pdpl_discovery (engine/pdpl.js runDiscovery: Oracle / SQL Server / PostgreSQL read-only dictionary scans) +
 *                     db_inventory (engine/db-inventory.js) for the database stores that exist
 *     ropa            the PDPL records of processing (pdpl_records kind ropa): which systems / categories are declared
 *     transfers       the PDPL transfer register (kind transfer): basis, transfer impact assessment signed (tia.signed_by)
 *     breaches        the PDPL breach register (kind breach): SDAIA / data-subject notification
 *     access_reviews  the latest access review campaign (engine/access-reviews.js: access_reviews / access_review_items)
 *
 * RISKS (count, definition, sources, trend against the previous daily snapshot in data_posture_hist, top items for operators):
 *   shadow       personal data in a store that NO active processing activity names (systems[] matched as pyengine/pdpl_rules.py
 *                discovery() does: a system entry equal to, or containing, the store's label / host / service / key) - databases,
 *                SharePoint / Teams sites, file-share roots, cloud stores (OneDrive is personal storage: counted as misplaced instead);
 *                and categories found that the naming activities do not declare
 *   exposed      files / objects holding personal data reachable OUTSIDE the organisation: an anonymous link, sharing with outside
 *                people (SharePoint / OneDrive), a public bucket / container (cloud public = true). Public unknown = listed, not safe
 *   credentials  files / objects holding a secret (private_key, api_key, password, secret_file by name): by kind, how many shared
 *   localisation cloud stores outside the Kingdom (in_kingdom = false) that hold personal data; transfers abroad with no legal basis
 *                recorded, or a basis without a signed transfer impact assessment. in_kingdom unknown = listed, not safe
 *   excessive    exactly these measures: (a) members of privileged groups (or privileged accounts) in the latest access review that are
 *                dormant (no sign-in 90 days) or disabled and not removed; (b) lines still undecided in an overdue campaign; (c) removals
 *                decided but not carried out; (d) Entra ID administrators without MFA (m365/security); (e) guest accounts with no sign-in
 *                for 90 days (m365/graph signInActivity; not judged when Graph did not give it)
 *   misplaced    (a) OneDrive (personal storage) files holding strong personal data (national ID, Iqama, passport, IBAN, card, health,
 *                salary); (b) files holding personal data not modified for 3 years (the SIEM insights' retention rule); (c) health or
 *                financial data on a file share readable by everyone, or shared with the whole organisation
 *   privacy      (a) DLP incidents to AI apps that were let through with a data class, to an app not sanctioned / tolerated or with a class
 *                its register entry does not allow; (b) open PDPL breaches (SDAIA not notified; data subjects not notified when harm is
 *                likely); (c) open Microsoft Defender / Purview alerts whose product is DLP / insider risk / information protection or
 *                whose category is exfiltration
 * SCORE 0-10: start at 10, every measure deducts `each` x count up to the risk's cap (RULES below); every deduction is in why[] with its
 *   source. A risk whose sources are all missing deducts nothing and is listed under not_measured; the score says "based on N of M
 *   sources" and is provisional until every source is measured. Good >= 8, Fair >= 5, else Poor. No source at all = no score.
 * Roles: viewer counts only (no file, bucket, site, server or person name); operator and admin also the top items (audited named read).
 *   GET /data-posture                 viewer    score, why, risks, not_measured, stores, scan status, classes (operators: items)
 *   GET /data-posture/risks/:key      operator  ?limit=1..500  every item of one risk                                    audited
 * Background: one snapshot a day (guardOf 'data-posture.snapshot', rescheduled in finally) so the trend exists without a visitor.
 */
const DAY = 86400000, RIYADH = 3 * 3600000, CACHE_MS = 30000, TOP = 25, OLD_DAYS = 3 * 365, STALE_DAYS = 90;
const SIEM_SYS = { user: 'system:itam-data-posture', role: 'analyst' };
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const CATEGORY = { national_id: 'identity', iqama: 'identity', passport: 'identity', mobile: 'contact', email: 'contact', iban: 'financial', card: 'financial', salary: 'financial', credit: 'financial',
  health: 'health', cv: 'employment', private_key: 'credentials', api_key: 'credentials', password: 'credentials', secret_file: 'credentials', biometric: 'health', name: 'identity', birth_date: 'identity', address: 'contact' };
const CRED_KINDS = ['private_key', 'api_key', 'password', 'secret_file'];
const STRONG = ['national_id', 'iqama', 'passport', 'iban', 'card', 'health', 'salary'];
const KIND_LABEL = { national_id: 'National ID', iqama: 'Iqama number', passport: 'Passport number', mobile: 'Mobile / phone', email: 'E-mail address', iban: 'IBAN / bank account', card: 'Payment card',
  salary: 'Salary / income', health: 'Health / diagnosis', cv: 'CV / résumé', private_key: 'Private key', api_key: 'API key / token', password: 'Password in text', secret_file: 'Secret / key file', credit: 'Credit data',
  biometric: 'Biometric / photo', name: 'Person name', birth_date: 'Date of birth', address: 'Address' };
// sensitivity weight of a kind (ordering only, never a score): health / credentials / identity numbers first
const WEIGHT = { health: 10, biometric: 10, private_key: 9, api_key: 9, password: 9, secret_file: 8, national_id: 8, iqama: 8, passport: 8, card: 8, iban: 7, salary: 7, credit: 7, cv: 5, birth_date: 5, mobile: 4, address: 4, email: 3, name: 2 };
const CLOUD = { aws: 'AWS S3 buckets', azure: 'Azure storage accounts', oci: 'OCI Object Storage buckets' };
const ENGINE = { oracle: 'Oracle', mssql: 'SQL Server', postgres: 'PostgreSQL', mysql: 'MySQL / MariaDB' };
const SOURCES = {
  m365_files: ['SharePoint / OneDrive discovery (SIEM)', 'Microsoft 365: switch on the SharePoint / OneDrive discovery in the SIEM (config m365.files) or run Scan now in the Data Catalog, with Sites.Read.All / Files.Read.All granted to the Entra ID app'],
  m365_insights: ['SharePoint / OneDrive insights (SIEM)', 'the SIEM\'s SharePoint & OneDrive insights read the same discovery - run the discovery once'],
  file_shares: ['File-share scans (Windows agent)', 'install the Windows agent 1.5 on the file servers with the file-share scan switched on'],
  cloud: ['Cloud data stores (AWS / Azure / OCI)', 'connect the cloud agent in the SIEM read-only (Azure Resource Manager for storage accounts, AWS S3, OCI Object Storage)'],
  databases: ['Database personal-data discovery', 'register Oracle databases on the Databases page or let Asset Discovery prove a read-only SQL Server / PostgreSQL login, then run Personal-data discovery'],
  ropa: ['Records of processing (PDPL)', 'install the PDPL module (run the update) and record the processing activities with their systems'],
  transfers: ['Transfers outside the Kingdom (PDPL)', 'install the PDPL module (run the update) and record each transfer abroad'],
  breaches: ['Breach register (PDPL)', 'install the PDPL module (run the update)'],
  access_reviews: ['Access reviews', 'list the groups to review in Access Reviews and run a campaign'],
  m365_security: ['Microsoft 365 security (SIEM)', 'connect Microsoft 365 to the SIEM (Connections & Setup) with SecurityAlert.Read.All and UserAuthenticationMethod.Read.All'],
  m365_directory: ['Microsoft 365 directory (SIEM)', 'connect Microsoft 365 to the SIEM with User.Read.All (and AuditLog.Read.All for last sign-in)'],
  shadow_ai: ['Shadow AI DLP (SIEM)', 'send the DLP / web-filter logs to the SIEM or deploy the AI DLP browser extension (Shadow AI DLP page)'],
};
// [title, definition, sources (any one measures it), cap, measures {key: [each, text]}]
const RULES = {
  shadow: ['Shadow data', 'Personal data in a store that no active processing activity (records of processing) names, and categories found that the naming activities do not declare.', ['databases', 'm365_files', 'file_shares', 'cloud'], 2,
    { undeclared_store: [0.5, 'store(s) holding personal data that no processing activity names'], undeclared_category: [0.1, 'store(s) where a category found is not declared by the activities that name it'] }],
  exposed: ['Exposed data', 'Files and objects holding personal data reachable outside the organisation: anonymous links, sharing with outside people, public buckets / containers.', ['m365_files', 'm365_insights', 'cloud'], 2.5,
    { anonymous: [0.5, 'file(s) with personal data behind an anonymous link'], external: [0.25, 'file(s) with personal data shared with people outside the organisation'], public_store: [0.75, 'public cloud store(s) holding personal data'] }],
  credentials: ['Risky credentials', 'Files and objects holding a secret (private key, API key, password in text, key / secret file), by kind; a shared one is treated as leaked.', ['m365_files', 'm365_insights', 'file_shares', 'cloud'], 1.5,
    { shared: [0.5, 'shared file(s) / object(s) holding credentials'], unshared: [0.25, 'other file(s) / object(s) holding credentials'] }],
  localisation: ['Data localisation', 'Cloud stores outside the Kingdom holding personal data; transfers abroad without a recorded legal basis or without a signed transfer impact assessment.', ['cloud', 'transfers'], 1.5,
    { outside_store: [0.75, 'cloud store(s) outside the Kingdom holding personal data'], no_basis: [0.5, 'transfer(s) abroad with no legal basis recorded'], no_tia: [0.25, 'transfer(s) with a basis but no signed transfer impact assessment'] }],
  excessive: ['Excessive access', 'Privileged access nobody uses or should hold, and access nobody reviewed: dormant / disabled members of privileged groups not removed, undecided review lines past due, removals not carried out, administrators without MFA, guests with no sign-in for 90 days.', ['access_reviews', 'm365_security', 'm365_directory'], 1.5,
    { priv_dormant: [0.1, 'dormant or disabled member(s) of privileged groups not removed (latest access review)'], undecided: [0.02, 'review line(s) undecided in an overdue campaign'], removal_open: [0.05, 'removal(s) decided but not carried out'], admin_no_mfa: [0.25, 'Entra ID administrator(s) without MFA'], stale_guest: [0.02, 'guest account(s) with no sign-in for 90 days'] }],
  misplaced: ['Misplaced data', 'Personal data where it should not be: strong personal data in OneDrive (personal storage), personal data unchanged for 3 years (past retention), health or financial data readable by everyone / the whole organisation.', ['m365_files', 'file_shares', 'm365_insights'], 1,
    { onedrive_strong: [0.05, 'OneDrive file(s) holding national ID / Iqama / passport / IBAN / card / health / salary data'], old: [0.02, 'file(s) with personal data not modified for 3 years'], general_sensitive: [0.1, 'file(s) with health or financial data readable by everyone / the whole organisation'] }],
  privacy: ['Privacy infringement', 'Personal data that left to an AI app the register does not allow it to reach, open PDPL breaches, open Microsoft Defender / Purview data-loss alerts.', ['shadow_ai', 'breaches', 'm365_security'], 2,
    { ai_leak: [0.25, 'DLP incident(s) let through to an AI app not allowed that data'], breach_open: [1, 'open breach(es): SDAIA not notified'], breach_subjects: [0.5, 'breach(es): data subjects not notified though harm is likely'], dlp_alert: [0.25, 'open Defender / Purview data-loss alert(s)'] }],
};
const RISK_KEYS = Object.keys(RULES);
const SCORE_RULE = 'Start at 10; each measure deducts its points per item, each risk at most its cap; a risk with no measured source deducts nothing and is listed as not measured (never as safe). Good >= 8, Fair >= 5, else Poor.';
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n || 200);
const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
const r2 = (x) => Math.round(x * 100) / 100;
const ms = (v) => { const t = v ? Date.parse(v) : NaN; return Number.isFinite(t) ? t : null; };
const kindsOf = (k) => (Array.isArray(k) ? k.map(String) : k && typeof k === 'object' ? Object.keys(k).filter((x) => Number(k[x]) !== 0) : []);
const catOf = (k) => CATEGORY[k] || 'other';
const personalKinds = (ks) => ks.filter((k) => catOf(k) !== 'credentials');

function createDataPosture(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, warn() {}, every() {} };
  const hist = () => store.collection('data_posture_hist');
  const iso = () => new Date(now()).toISOString(), dayOf = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const link = () => opts.siem || ((app.discovery && app.discovery.siem && typeof app.discovery.siem.call === 'function' && !(app.discovery.siem.configured && !app.discovery.siem.configured())) ? app.discovery.siem.call : null);
  const PD = () => (app.addons && app.addons.pdpl) || null;

  /* ---- reading the SIEM: {ok, status, json, error} - never throws */
  async function siemGet(path, who) {
    const call = link();
    if (!call) return { ok: false, status: 0, error: 'IT Asset Management has no link to the SIEM (discovery.siem.secret_file is not set) - run the update so the link is configured' };
    try {
      const r = await call('GET', path, { user: who.user, role: 'analyst' });
      if (r && r.status === 200 && r.json && typeof r.json === 'object') return { ok: true, status: 200, json: r.json };
      const st = r ? r.status : 0;
      L.every('dposture:' + path, 600000, 'warn', 'data posture: the SIEM did not answer a source', { path, status: st });
      return { ok: false, status: st, error: st === 404 ? 'the SIEM does not have ' + path.split('?')[0] + ' yet - update the SIEM' : st === 403 ? 'the SIEM refused the analyst role for ' + path.split('?')[0] + ' - run the update (install/fix-siem-role.sh)' : 'the SIEM answered HTTP ' + st + ' for ' + path.split('?')[0] };
    } catch (e) {
      L.every('dposture:' + path, 600000, 'warn', 'data posture: the SIEM is not reachable', { path, err: s(e.message, 200) });
      return { ok: false, status: 0, error: 'the SIEM is not reachable: ' + s(e.message, 120) };
    }
  }

  /* ---- everything the posture and the AI lineage are built from, in one normalised shape */
  let cache = null;
  async function collect(who) {
    if (cache && now() - cache.t < CACHE_MS) return cache.v;
    const W = who && who.user ? who : SIEM_SYS;
    const [files, insights, cloud, reg, sig, sec, graph] = await Promise.all(['/pii/files', '/m365/files/insights', '/cloud-data/stores', '/shadow-ai/register', '/shadow-ai/signals?hours=720', '/m365/security', '/m365/graph'].map((p) => siemGet(p, W)));
    const src = {}, mark = (k, measured, reason, extra) => { src[k] = Object.assign({ key: k, label: SOURCES[k][0], measured: !!measured, reason: measured ? null : (reason || SOURCES[k][1]), connect: measured ? null : SOURCES[k][1] }, extra || {}); };
    const t = now();
    /* SharePoint / OneDrive / Teams + file shares */
    const sp = files.ok ? (files.json.sharepoint || {}) : null, hosts = files.ok ? (((files.json.fileshares || {}).hosts) || []) : [];
    const rows = [], storesM = new Map();
    const storeOf = (id, type, label, url, extra) => { let x = storesM.get(id); if (!x) storesM.set(id, x = Object.assign({ id, type, label: s(label, 200) || id, url: s(url, 300) || '', files_seen: 0, personal: 0, credentials: 0, kinds: {}, last_scan: null, errors: [] }, extra || {})); return x; };
    if (sp) for (const x of sp.sources || []) {
      const type = x.kind === 'onedrive' ? 'onedrive' : (x.kind === 'teams' || x.teams === true || x.group === true) ? 'teams' : 'sharepoint';
      const st = storeOf('m365:' + s(x.key, 120), type, x.label, x.url, { files_seen: Number(x.files_seen) || 0, last_scan: sp.at || null, errors: (x.errors || []).map((e) => s(e, 200)).slice(0, 5), truncated: !!(x.truncated || x.hits_truncated) });
      for (const h of x.hits || []) rows.push({ store: st, name: s(h.name, 200), path: s(h.path, 400), modified: h.modified || null, kinds: [...new Set(kindsOf(h.kinds).concat(kindsOf(h.name_kinds)))], shared: h.shared == null ? null : String(h.shared) });
    }
    for (const hst of hosts) {
      const set = hst.settings || {};
      for (const r of set.roots || []) {
        const label = r.share ? '\\\\' + s(hst.host, 120) + '\\' + s(r.share, 120) : s(hst.host, 120) + ':' + s(r.path, 200);
        const st = storeOf('fs:' + s(hst.host, 120) + ':' + s(r.path || r.share, 200), 'fileshare', label, '', { host: s(hst.host, 120), files_seen: Number(r.files_seen) || 0, last_scan: set.at || hst.at || null, errors: r.dirs_denied ? [r.dirs_denied + ' folder(s) could not be read'] : [] });
        for (const h of r.hits || []) {
          const p = String(h.p || ''), parts = p.split('\\');
          rows.push({ store: st, name: s(h.name || parts[parts.length - 1], 200), path: s(h.path != null ? h.path : parts.slice(0, -1).join('\\'), 400), modified: h.modified || null, kinds: [...new Set(kindsOf(h.kinds).concat(kindsOf(h.name_kinds)))], shared: h.open === true ? 'everyone' : h.open === false ? 'none' : null });
        }
      }
    }
    for (const r of rows) { const pk = personalKinds(r.kinds); r.personal = pk.length > 0; r.cred = r.kinds.some((k) => CRED_KINDS.includes(k)); r.cats = [...new Set(r.kinds.map(catOf))]; if (r.personal) r.store.personal++; if (r.cred) r.store.credentials++; for (const k of r.kinds) r.store.kinds[k] = (r.store.kinds[k] || 0) + 1; }
    const spNever = !sp || !!sp.never || !sp.at;
    mark('m365_files', files.ok && !spNever, !files.ok ? files.error : (sp && sp.status && sp.status.last_error) ? 'the SharePoint / OneDrive discovery has not completed: ' + s(sp.status.last_error, 200) : null, { last: sp ? sp.at || null : null, running: !!(sp && sp.status && sp.status.running) });
    mark('file_shares', files.ok && hosts.length > 0, !files.ok ? files.error : null, { last: hosts.map((h) => (h.settings || {}).at || h.at).filter(Boolean).sort().pop() || null });
    const ins = insights.ok && !insights.json.never ? insights.json : null;
    mark('m365_insights', !!ins, !insights.ok ? insights.error : null, { last: ins ? ins.read_at || null : null });
    /* cloud data stores */
    const cj = cloud.ok ? cloud.json : null, cloudStores = [];
    if (cj && cj.configured !== false) for (const x of cj.stores || []) {
      const cats = x.categories && typeof x.categories === 'object' ? Object.keys(x.categories).filter((k) => Number(x.categories[k])) : [], kinds = kindsOf(x.kinds);
      const allCats = [...new Set(cats.concat(kinds.map(catOf)))];
      cloudStores.push({ id: 'cloud:' + s(x.provider, 10) + ':' + s(x.id, 200), raw_id: s(x.id, 200), type: 'cloud:' + (CLOUD[x.provider] ? x.provider : 'other'), provider: s(x.provider, 10), account: s(x.account, 120), label: s(x.name || x.id, 200), region: s(x.region, 60),
        in_kingdom: x.in_kingdom === true ? true : x.in_kingdom === false ? false : null, public: x.public === true ? true : x.public === false ? false : null, public_why: s(x.public_why, 200), encrypted: x.encrypted == null ? null : !!x.encrypted, cmk: x.cmk == null ? null : !!x.cmk,
        objects_seen: Number(x.objects_seen) || 0, objects_scanned: Number(x.objects_scanned) || 0, with_findings: Number(x.objects_with_findings) || 0, kinds: x.kinds && typeof x.kinds === 'object' && !Array.isArray(x.kinds) ? x.kinds : {}, cats: allCats,
        personal: (Number(x.objects_with_findings) || 0) > 0 && allCats.some((c) => c !== 'credentials'), credentials: CRED_KINDS.reduce((a, k) => a + (Number((x.kinds || {})[k]) || 0), 0), truncated: !!x.truncated, last_scan: x.last_scan || null });
    }
    const cloudObjects = cj && Array.isArray(cj.top_objects) ? cj.top_objects.map((o) => ({ store_id: s(o.store_id, 200), key: s(o.key, 400), modified: o.modified || null, kinds: kindsOf(o.kinds), exposure: o.exposure })) : [];
    mark('cloud', !!(cj && cj.configured !== false && (cj.providers || []).some((p) => p.configured)), !cloud.ok ? (cloud.status === 404 ? 'the SIEM is not updated yet: it has no cloud data discovery (GET /cloud-data/stores answered 404) - run the update on the SIEM' : cloud.error) : (cj && cj.note) || null,
      { providers: cj ? (cj.providers || []).map((p) => ({ provider: s(p.provider, 10), configured: !!p.configured, last_scan: p.last_scan || null, last_ok: p.last_ok || null, error: p.error ? s(p.error, 200) : null })) : [], running: !!(cj && cj.scan && cj.scan.running) });
    /* databases: the read-only discovery scans + the inventory */
    const scans = store.collection('pdpl_discovery').all((x) => x.id !== '_last'), dbs = new Map();
    for (const x of scans) {
      const cols = (x.columns || []).filter((c) => c.confirmed !== false && c.category);
      const kinds = {}; for (const c of cols) if (c.kind) kinds[c.kind] = (kinds[c.kind] || 0) + 1;
      dbs.set(String(x.db), { id: 'db:' + s(x.db, 200), key: String(x.db), type: 'db:' + (ENGINE[x.engine] ? x.engine : 'oracle'), engine: ENGINE[x.engine] ? x.engine : 'oracle', label: s(x.label || x.host || x.db, 200), host: s(x.host, 120), service: s(x.service, 120),
        ok: !!x.ok, error: x.error ? s(x.error, 200) : null, last_scan: x.at || null, cats: [...new Set(cols.map((c) => c.category))], kinds, columns: cols.length, personal: !!x.ok && cols.some((c) => c.category !== 'credentials'), discovered: true });
    }
    for (const r of store.collection('db_inventory').all()) {
      if (dbs.has(String(r.id))) continue;
      dbs.set(String(r.id), { id: 'db:' + s(r.id, 200), key: String(r.id), type: 'db:' + (ENGINE[r.engine] ? r.engine : 'oracle'), engine: ENGINE[r.engine] ? r.engine : 'oracle', label: s(r.asset_name || r.host || r.ip, 200), host: s(r.ip || r.host, 120), service: '',
        ok: !r.error, error: r.error ? s(r.error, 200) : null, last_scan: r.at || r.error_at || null, cats: [], kinds: {}, columns: 0, personal: false, discovered: false });
    }
    const dbList = [...dbs.values()];
    mark('databases', scans.some((x) => x.ok), scans.length ? 'no database scan succeeded yet: ' + (scans.find((x) => x.error) || {}).error : null, { last: (store.collection('pdpl_discovery').get('_last') || {}).at || null });
    /* PDPL registers */
    const recs = PD() ? (typeof PD().records === 'function' ? PD().records() : []) : null, active = (k) => (recs || []).filter((r) => r.kind === k && r.status !== 'archived');
    mark('ropa', !!recs, null, { count: recs ? active('ropa').length : null }); mark('transfers', !!recs, null, { count: recs ? active('transfer').length : null }); mark('breaches', !!recs, null, { count: recs ? active('breach').length : null });
    /* access reviews */
    const camps = store.collection('access_reviews').all().sort((a, b) => String(b.id).localeCompare(String(a.id))), camp = camps[0] || null;
    const lines = camp ? store.collection('access_review_items').all((x) => x.campaign === camp.id) : [];
    mark('access_reviews', !!camp, null, { last: camp ? camp.started_at || null : null, campaign: camp ? camp.id : null });
    /* Microsoft 365 security and directory */
    const sj = sec.ok && sec.json.configured ? sec.json : null;
    mark('m365_security', !!sj, !sec.ok ? sec.error : sec.json.note || null, { last: sj ? sj.updated || null : null });
    const gj = graph.ok && graph.json.configured ? graph.json : null;
    mark('m365_directory', !!(gj && gj.users && Array.isArray(gj.users.list)), !graph.ok ? graph.error : !gj ? 'Microsoft 365 is not connected to the SIEM' + (graph.json && graph.json.reason ? ' (' + s(graph.json.reason, 160) + ')' : '') : null, { last: gj ? gj.updated || null : null });
    /* Shadow AI */
    const regItems = reg.ok && Array.isArray(reg.json.items) ? reg.json.items : null, sj2 = sig.ok ? sig.json : null;
    mark('shadow_ai', !!(regItems && sj2), !reg.ok ? reg.error : !sig.ok ? sig.error : null);
    const filesCred = files.ok ? (files.json.credentials || (files.json.sharepoint || {}).credentials || null) : null;
    const v = { t, src, rows, filesCred, stores: [...storesM.values()], cloudStores, cloudObjects, cloud: cj, dbs: dbList, recs, active, camp, lines, sec: sj, graph: gj, ins, reg: regItems, sig: sj2, sp };
    cache = { t: now(), v };
    return v;
  }

  /* ---- the ROPA match (the rule of pyengine/pdpl_rules.py discovery()) */
  function activitiesFor(C, names) {
    const N = names.map(low).filter(Boolean);
    return C.active('ropa').filter((a) => (a.systems || []).some((x) => { const v = low(x); return N.includes(v) || N.some((n) => n.length >= 3 && v.includes(n)); }));
  }

  /* ---- the seven risks: count, measures, items */
  function risks(C) {
    const out = {}, t = C.t;
    const make = (key) => { const R = RULES[key]; const srcs = R[2].map((k) => ({ key: k, label: SOURCES[k][0], measured: !!(C.src[k] && C.src[k].measured) }));
      return { key, title: R[0], what: R[1], cap: R[3], sources: srcs, measured: srcs.some((x) => x.measured), missing: srcs.filter((x) => !x.measured).map((x) => x.key), m: {}, items: [] }; };
    const add = (R, measure, n, source, item) => { const e = R.m[measure] || (R.m[measure] = { measure, count: 0, sources: new Set() }); e.count += n; if (source) e.sources.add(source); if (item) R.items.push(Object.assign({ measure }, item)); };
    const fileItem = (r, extra) => Object.assign({ store: r.store.label, store_type: r.store.type, name: r.name, path: r.path, classes: r.kinds.map((k) => KIND_LABEL[k] || k), shared: r.shared, modified: r.modified }, extra || {});
    const insScore = new Map(); if (C.ins) for (const f of C.ins.files || []) insScore.set(low(f.source_label) + '|' + low(f.path) + '|' + low(f.name), f.score);
    const scoreOf = (r) => insScore.get(low(r.store.label) + '|' + low(r.path) + '|' + low(r.name));
    const filesOk = C.src.m365_files.measured || C.src.file_shares.measured;
    // shadow data
    let R = make('shadow'); out.shadow = R;
    if (C.src.ropa.measured) {
      const check = (st, names, cats, type, source) => {
        if (!cats.length) return;
        const acts = activitiesFor(C, names);
        if (!acts.length) add(R, 'undeclared_store', 1, source, { store: st.label, store_type: type, classes: cats, detail: 'no processing activity names it' });
        else { const decl = new Set(acts.flatMap((a) => a.data_categories || [])), miss = cats.filter((c) => !decl.has(c)); if (miss.length) add(R, 'undeclared_category', 1, source, { store: st.label, store_type: type, classes: miss, detail: 'not declared by ' + acts.map((a) => a.id).join(', ') }); }
      };
      if (C.src.databases.measured) for (const d of C.dbs.filter((x) => x.personal)) check(d, [d.label, d.host, d.service, d.key], d.cats.filter((c) => c !== 'credentials'), d.type, 'databases');
      for (const st of C.stores.filter((x) => x.personal && x.type !== 'onedrive')) check(st, [st.label, st.url, st.host], [...new Set(C.rows.filter((r) => r.store === st && r.personal).flatMap((r) => r.cats).filter((c) => c !== 'credentials' && c !== 'other'))], st.type, st.type === 'fileshare' ? 'file_shares' : 'm365_files');
      if (C.src.cloud.measured) for (const c of C.cloudStores.filter((x) => x.personal)) check(c, [c.label, c.account, c.raw_id], c.cats.filter((x) => x !== 'credentials' && x !== 'other'), c.type, 'cloud');
    } else { R.missing = [...new Set(R.missing.concat(['ropa']))]; R.measured = false; R.why_unmeasured = 'shadow data needs the records of processing to compare with'; }
    // exposed data
    R = make('exposed'); out.exposed = R;
    if (C.src.m365_files.measured) for (const r of C.rows.filter((x) => x.personal && (x.shared === 'anonymous' || x.shared === 'external'))) add(R, r.shared, 1, 'm365_files', fileItem(r, { exposure: scoreOf(r) == null ? null : scoreOf(r) }));
    else if (C.src.m365_insights.measured) { const k = C.ins.kpis || {}; if (k.anonymous) add(R, 'anonymous', Number(k.anonymous) || 0, 'm365_insights'); if (k.external) add(R, 'external', Number(k.external) || 0, 'm365_insights'); R.note = 'counts from the SIEM insights (they include files holding only credentials); file names need the discovery (GET /pii/files)'; }
    if (C.src.cloud.measured) for (const c of C.cloudStores.filter((x) => x.personal)) {
      if (c.public === true) add(R, 'public_store', 1, 'cloud', { store: c.label, store_type: c.type, account: c.account, region: c.region, classes: c.cats, objects: c.with_findings, detail: c.public_why || 'public access is allowed' });
      else if (c.public === null) R.unknown = (R.unknown || 0) + 1;
    }
    if (R.unknown) R.note = (R.note ? R.note + '; ' : '') + R.unknown + ' cloud store(s) holding personal data whose public access could not be read - unknown, not safe';
    // risky credentials
    R = make('credentials'); out.credentials = R; R.by_kind = {}; R.shared_total = 0;
    const cj = C.filesCred;
    if (C.src.m365_files.measured || C.src.file_shares.measured) {
      for (const r of C.rows.filter((x) => x.cred)) {
        const shared = r.shared === 'anonymous' || r.shared === 'external' || r.shared === 'organization' || r.shared === 'everyone';
        add(R, shared ? 'shared' : 'unshared', 1, r.store.type === 'fileshare' ? 'file_shares' : 'm365_files', fileItem(r, { classes: r.kinds.filter((k) => CRED_KINDS.includes(k)).map((k) => KIND_LABEL[k]) }));
        for (const k of r.kinds.filter((x) => CRED_KINDS.includes(x))) R.by_kind[k] = (R.by_kind[k] || 0) + 1;
        if (shared) R.shared_total++;
      }
      // the SIEM's own summary (GET /pii/files credentials) is complete where the file lists stop at their cap: its counts win
      if (cj && typeof cj === 'object' && cj.by_kind && typeof cj.by_kind === 'object') {
        const files = Math.max(0, Number(cj.files) || 0), sh = Math.min(files, Math.max(0, Number(cj.shared) || 0));
        R.siem_summary = { files, by_kind: cj.by_kind, shared: sh };
        for (const m of ['shared', 'unshared']) if (R.m[m]) { R.m[m].count = 0; }
        if (sh) add(R, 'shared', sh, 'm365_files'); if (files - sh) add(R, 'unshared', files - sh, 'm365_files');
        R.by_kind = {}; for (const k of CRED_KINDS) if (Number(cj.by_kind[k])) R.by_kind[k] = Number(cj.by_kind[k]);
        R.shared_total = sh;
      }
    } else if (C.src.m365_insights.measured) { const k = C.ins.kpis || {}; const sh = Number(k.credentials_shared) || 0, all = Number(k.credentials) || 0; if (sh) add(R, 'shared', sh, 'm365_insights'); if (all - sh > 0) add(R, 'unshared', all - sh, 'm365_insights'); R.shared_total += sh; }
    if (C.src.cloud.measured) for (const c of C.cloudStores.filter((x) => x.credentials > 0)) {
      add(R, c.public === true ? 'shared' : 'unshared', c.credentials, 'cloud', { store: c.label, store_type: c.type, account: c.account, classes: CRED_KINDS.filter((k) => Number(c.kinds[k])).map((k) => KIND_LABEL[k]), objects: c.credentials, detail: c.public === true ? 'in a public store' : 'credential finding(s) in the store' });
      for (const k of CRED_KINDS) if (Number(c.kinds[k])) R.by_kind[k] = (R.by_kind[k] || 0) + Number(c.kinds[k]);
      if (c.public === true) R.shared_total += c.credentials;
    }
    // data localisation
    R = make('localisation'); out.localisation = R;
    if (C.src.cloud.measured) for (const c of C.cloudStores.filter((x) => x.personal)) {
      if (c.in_kingdom === false) add(R, 'outside_store', 1, 'cloud', { store: c.label, store_type: c.type, account: c.account, region: c.region, classes: c.cats, objects: c.with_findings, detail: 'region ' + (c.region || 'not given') + ' is outside the Kingdom' });
      else if (c.in_kingdom === null) R.unknown = (R.unknown || 0) + 1;
    }
    if (R.unknown) R.note = R.unknown + ' cloud store(s) holding personal data whose location could not be read - unknown, not safe';
    if (C.src.transfers.measured) for (const x of C.active('transfer')) {
      if (!x.basis) add(R, 'no_basis', 1, 'transfers', { store: s(x.name, 160), store_type: 'transfer', country: s(x.country, 80), detail: 'no legal basis recorded', ref: x.id });
      else if (!(x.tia && x.tia.signed_by)) add(R, 'no_tia', 1, 'transfers', { store: s(x.name, 160), store_type: 'transfer', country: s(x.country, 80), detail: 'basis ' + x.basis + ', transfer impact assessment not signed', ref: x.id });
    }
    // excessive access
    R = make('excessive'); out.excessive = R;
    if (C.src.access_reviews.measured) {
      const overdue = C.camp.status === 'open' && t > Date.parse(C.camp.due_at || 0);
      for (const x of C.lines) {
        if ((x.privileged_group || x.privileged_account) && (x.dormant || x.enabled === false) && x.decision !== 'remove' && x.state !== 'removed') add(R, 'priv_dormant', 1, 'access_reviews', { name: s(x.user, 80), store: s(x.group, 128), store_type: 'ad-group', detail: (x.enabled === false ? 'disabled' : 'no sign-in for 90 days') + ', ' + (x.decision ? 'kept' : 'not decided') });
        if (overdue && !x.decision) add(R, 'undecided', 1, 'access_reviews');
        if (['removal_pending', 'removal_approved', 'removal_failed'].includes(x.state)) add(R, 'removal_open', 1, 'access_reviews', { name: s(x.user, 80), store: s(x.group, 128), store_type: 'ad-group', detail: x.state.replace('_', ' ') });
      }
      R.campaign = { id: C.camp.id, status: C.camp.status, due_at: C.camp.due_at || null, overdue };
    }
    if (C.src.m365_security.measured && C.sec.mfa) {
      const adm = Array.isArray(C.sec.mfa.admins) ? C.sec.mfa.admins : [], n = Array.isArray(C.sec.mfa.admins) ? adm.length : Number((C.sec.kpis || {}).admins_no_mfa) || 0;
      if (Array.isArray(C.sec.mfa.admins)) for (const a of adm) add(R, 'admin_no_mfa', 1, 'm365_security', { name: s(a.upn || a.name, 160), store: 'Entra ID', store_type: 'm365-identity', detail: 'administrator without MFA registered' });
      else if (n) add(R, 'admin_no_mfa', n, 'm365_security');
    }
    if (C.src.m365_directory.measured) {
      const guests = C.graph.users.list.filter((u) => u.guest), judged = guests.filter((u) => u.last !== undefined);
      R.guests = { total: guests.length, judged: judged.length };
      for (const g of judged) if (g.enabled !== false && (!g.last || t - Date.parse(g.last) > STALE_DAYS * DAY)) add(R, 'stale_guest', 1, 'm365_directory', { name: s(g.upn, 160), store: 'Entra ID', store_type: 'm365-identity', detail: g.last ? 'last sign-in ' + String(g.last).slice(0, 10) : 'never signed in' });
      if (guests.length && !judged.length) R.note = guests.length + ' guest account(s); their last sign-in is not in the Graph data (AuditLog.Read.All + Entra ID P1), so stale guests are not judged';
    }
    // misplaced data
    R = make('misplaced'); out.misplaced = R;
    if (filesOk) for (const r of C.rows.filter((x) => x.personal)) {
      if (r.store.type === 'onedrive' && r.kinds.some((k) => STRONG.includes(k))) add(R, 'onedrive_strong', 1, 'm365_files', fileItem(r, { detail: 'strong personal data in personal storage' }));
      const m = ms(r.modified); if (m && t - m > OLD_DAYS * DAY) add(R, 'old', 1, r.store.type === 'fileshare' ? 'file_shares' : 'm365_files', fileItem(r, { detail: 'not modified since ' + String(r.modified).slice(0, 10) }));
      if ((r.shared === 'everyone' || r.shared === 'organization') && r.cats.some((c) => c === 'health' || c === 'financial')) add(R, 'general_sensitive', 1, r.store.type === 'fileshare' ? 'file_shares' : 'm365_files', fileItem(r, { detail: r.shared === 'everyone' ? 'readable by everyone on the share' : 'shared with the whole organisation' }));
    } else if (C.src.m365_insights.measured) { const k = C.ins.kpis || {}; if (k.old) add(R, 'old', Number(k.old) || 0, 'm365_insights'); }
    // privacy infringement
    R = make('privacy'); out.privacy = R;
    if (C.src.shadow_ai.measured) {
      const regM = new Map(C.reg.map((a) => [a.id, a]));
      for (const x of C.sig.incidents || []) {
        if (!x.left || !(x.classes || []).length) continue;
        const e = regM.get(x.app) || {}, st = e.status || x.status || 'unreviewed', allowed = st === 'sanctioned' || st === 'tolerated' ? (e.allowed_classes || []) : [];
        const bad = x.classes.filter((c) => !allowed.includes(c));
        if (bad.length) add(R, 'ai_leak', 1, 'shadow_ai', { store: s(x.app_name || x.app, 120), store_type: 'ai-app', classes: bad, detail: st + ' app · ' + s(x.source, 20) + ' · ' + s(x.action, 40) + (x.ts ? ' · ' + String(x.ts).slice(0, 10) : '') });
      }
    }
    if (C.src.breaches.measured) for (const b of C.active('breach')) {
      if (!b.sdaia_notified_at) add(R, 'breach_open', 1, 'breaches', { store: s(b.ref, 60), store_type: 'breach', ref: b.id, detail: 'SDAIA not notified (aware ' + String(b.aware_at || '').slice(0, 16) + ')' });
      else if (b.harm_likely && !b.subjects_notified_at) add(R, 'breach_subjects', 1, 'breaches', { store: s(b.ref, 60), store_type: 'breach', ref: b.id, detail: 'data subjects not notified' });
    }
    if (C.src.m365_security.measured && C.sec.alerts && Array.isArray(C.sec.alerts.list)) for (const a of C.sec.alerts.list) {
      if (a.open && (/dataloss|dlp|insiderrisk|purview|informationprotection/i.test(String(a.product || '')) || /exfiltration/i.test(String(a.category || '')))) add(R, 'dlp_alert', 1, 'm365_security', { store: s(a.title, 200), store_type: 'm365-alert', detail: s(a.product, 60) + ' · ' + s(a.severity, 20) + ' · ' + String(a.created || '').slice(0, 10) });
    }
    // points per risk, capped
    for (const k of RISK_KEYS) {
      const X = out[k], M = RULES[k][4];
      X.breakdown = Object.values(X.m).filter((e) => e.count > 0).map((e) => ({ measure: e.measure, text: M[e.measure][1], count: e.count, each: M[e.measure][0], points: r2(e.count * M[e.measure][0]), sources: [...e.sources].map((x) => SOURCES[x][0]) }));
      const raw = r2(X.breakdown.reduce((a, e) => a + e.points, 0));
      X.deduction = X.measured ? Math.min(X.cap, raw) : 0; X.raw = raw; X.capped = X.measured && raw > X.cap;
      X.count = X.measured ? X.breakdown.reduce((a, e) => a + e.count, 0) : null;
      X.items_total = X.items.length; delete X.m;
    }
    return out;
  }

  /* ---- data stores summary, scan status, data classes */
  function storesSummary(C) {
    const T = new Map(), put = (type, label, group, x) => { const e = T.get(type) || T.set(type, { type, label, group, count: 0, with_personal: 0, with_credentials: 0, last_scan: null }).get(type);
      e.count++; if (x.personal) e.with_personal++; if (x.credentials || x.cred) e.with_credentials++; if (x.last_scan && (!e.last_scan || x.last_scan > e.last_scan)) e.last_scan = x.last_scan; };
    for (const st of C.stores) put(st.type, { sharepoint: 'SharePoint sites', teams: 'Teams-connected sites', onedrive: 'OneDrive (personal storage)', fileshare: 'File-share roots' }[st.type], st.type === 'fileshare' ? 'File servers' : 'Microsoft 365', st);
    for (const d of C.dbs) put(d.type, ENGINE[d.engine] + ' databases', 'Databases', d);
    for (const c of C.cloudStores) put(c.type, CLOUD[c.provider] || 'Other cloud stores', 'Cloud', c);
    const order = ['sharepoint', 'teams', 'onedrive', 'fileshare', 'cloud:azure', 'cloud:aws', 'cloud:oci', 'db:oracle', 'db:mssql', 'db:postgres', 'db:mysql'];
    const list = [...T.values()].sort((a, b) => (order.indexOf(a.type) + 1 || 99) - (order.indexOf(b.type) + 1 || 99));
    const teams = C.stores.some((x) => x.type === 'teams');
    return { types: list, file_servers: new Set(C.stores.filter((x) => x.type === 'fileshare').map((x) => x.host)).size,
      teams_note: teams ? null : 'Teams files are counted in their SharePoint site: the SIEM discovery does not tell Teams-connected (group) sites apart from other SharePoint sites.' };
  }
  function scanStatus(C, named) {
    const out = [], row = (source, label, state, last, detail, items) => out.push(Object.assign({ source, label, state, last: last || null, detail: detail || null }, named && items ? { items } : {}));
    const sp = C.sp, ms3 = C.src.m365_files;
    if (!sp) row('m365_files', 'SharePoint / OneDrive', 'not_connected', null, ms3.reason);
    else row('m365_files', 'SharePoint / OneDrive', sp.status && sp.status.running ? 'in_progress' : !sp.at ? (sp.status && sp.status.last_error ? 'failed' : 'never') : 'scanned', sp.at, sp.status && sp.status.last_error ? s(sp.status.last_error, 200) : (sp.errors || []).length ? s(sp.errors.join('; '), 300) : null,
      C.stores.filter((x) => x.type !== 'fileshare').map((x) => ({ name: x.label, type: x.type, errors: x.errors, truncated: !!x.truncated })));
    const fsS = C.stores.filter((x) => x.type === 'fileshare');
    row('file_shares', 'File shares (Windows agent)', !C.src.file_shares.measured ? (C.sp ? 'never' : 'not_connected') : 'scanned', C.src.file_shares.last, C.src.file_shares.measured ? fsS.length + ' root(s) on ' + new Set(fsS.map((x) => x.host)).size + ' server(s)' : C.src.file_shares.reason, fsS.map((x) => ({ name: x.label, last: x.last_scan, errors: x.errors })));
    const sc = C.dbs.filter((d) => d.discovered);
    row('databases', 'Databases (personal-data discovery)', !sc.length ? 'never' : sc.some((d) => d.ok) ? 'scanned' : 'failed', C.src.databases.last, sc.length ? sc.filter((d) => d.ok).length + ' of ' + sc.length + ' scanned' + (sc.some((d) => !d.ok) ? ', ' + sc.filter((d) => !d.ok).length + ' failed' : '') : C.src.databases.connect,
      sc.map((d) => ({ name: d.label, engine: ENGINE[d.engine], ok: d.ok, last: d.last_scan, error: d.error })));
    const cl = C.src.cloud;
    if (!C.cloud || !(cl.providers || []).length) row('cloud', 'Cloud data stores', 'not_connected', null, cl.reason);
    else for (const p of cl.providers) row('cloud:' + p.provider, (CLOUD[p.provider] || p.provider) + ' (cloud agent)', !p.configured ? 'not_connected' : cl.running ? 'in_progress' : p.error ? 'failed' : p.last_scan ? 'scanned' : 'never', p.last_scan, p.error || null);
    return out;
  }
  function classes(C) {
    const K = {}, put = (k, field, n) => { const e = K[k] || (K[k] = { kind: k, label: KIND_LABEL[k] || k, category: catOf(k), weight: WEIGHT[k] || 1, count: 0, files: 0, objects: 0, columns: 0 }); e[field] += n; e.count += n; };
    for (const r of C.rows) for (const k of r.kinds) put(k, 'files', 1);
    for (const c of C.cloudStores) for (const k of Object.keys(c.kinds)) if (Number(c.kinds[k])) put(k, 'objects', Number(c.kinds[k]));
    for (const d of C.dbs) for (const k of Object.keys(d.kinds)) put(k, 'columns', d.kinds[k]);
    return Object.values(K).sort((a, b) => b.weight - a.weight || b.count - a.count).slice(0, 30);
  }

  /* ---- score and trend */
  function score(R, C) {
    const M = Object.keys(SOURCES).length, N = Object.values(C.src).filter((x) => x.measured).length, why = [];
    for (const k of RISK_KEYS) {
      const X = R[k]; if (!X.measured) continue;
      for (const b of X.breakdown) why.push({ risk: k, title: X.title, points: -b.points, text: b.count + ' ' + b.text + ' × ' + b.each + ' = ' + b.points, source: b.sources.join(', ') });
      if (X.capped) why.push({ risk: k, title: X.title, points: r2(X.raw - X.cap), text: X.title + ' capped at ' + X.cap + ' (measured ' + X.raw + ')', source: 'cap' });
    }
    if (!N) return { value: null, label: 'Not measured', based_on: { measured: 0, of: M }, provisional: true, why, rule: SCORE_RULE };
    const ded = r2(RISK_KEYS.reduce((a, k) => a + R[k].deduction, 0)), v = Math.max(0, Math.round((10 - ded) * 10) / 10);
    return { value: v, label: v >= 8 ? 'Good' : v >= 5 ? 'Fair' : 'Poor', deducted: ded, based_on: { measured: N, of: M, text: 'based on ' + N + ' of ' + M + ' sources' }, provisional: N < M || RISK_KEYS.some((k) => !R[k].measured), why, rule: SCORE_RULE };
  }
  function snapshot(R, S, t) {
    const day = dayOf(t), counts = {}; for (const k of RISK_KEYS) counts[k] = R[k].count;
    hist().put({ id: day, at: new Date(t).toISOString(), score: S.value, measured: S.based_on.measured, counts });
    const all = hist().all().sort((a, b) => String(a.id).localeCompare(String(b.id))); for (const x of all.slice(0, Math.max(0, all.length - 400))) hist().remove(x.id);
    return hist().all((x) => x.id < day).sort((a, b) => String(b.id).localeCompare(String(a.id)))[0] || null;
  }

  async function build(who) {
    const C = await collect(who), R = risks(C), S = score(R, C), prev = snapshot(R, S, C.t);
    for (const k of RISK_KEYS) { const p = prev && prev.counts ? prev.counts[k] : undefined; R[k].trend = prev && p != null && R[k].count != null ? { previous: p, delta: R[k].count - p, previous_at: prev.at } : { previous: null, delta: null, previous_at: prev ? prev.at : null }; }
    S.trend = prev && prev.score != null && S.value != null ? { previous: prev.score, delta: Math.round((S.value - prev.score) * 10) / 10, previous_at: prev.at } : null;
    return { C, R, S };
  }
  const isNamed = (who) => (RANK[low(who && who.role)] || 0) >= RANK.operator;
  const order = (items) => items.sort((a, b) => (b.exposure || 0) - (a.exposure || 0) || String(a.store).localeCompare(String(b.store)) || String(a.name || '').localeCompare(String(b.name || '')));

  async function view(who) {
    const named = isNamed(who), { C, R, S } = await build(who);
    const risksOut = RISK_KEYS.map((k) => { const X = R[k]; const o = { key: k, title: X.title, what: X.what, measured: X.measured, count: X.count, deduction: X.deduction, cap: X.cap, capped: X.capped, breakdown: X.breakdown, sources: X.sources, missing: X.missing.map((m) => ({ key: m, label: SOURCES[m][0], connect: SOURCES[m][1] })), trend: X.trend, note: X.note || X.why_unmeasured || null, items_total: X.items_total };
      if (k === 'credentials') { o.by_kind = Object.entries(X.by_kind).map(([kind, n]) => ({ kind, label: KIND_LABEL[kind] || kind, count: n })); o.shared = X.shared_total; if (X.siem_summary) o.siem_summary = X.siem_summary; }
      if (k === 'excessive') { if (X.campaign) o.campaign = X.campaign; if (X.guests) o.guests = X.guests; }
      if (named) o.items = order(X.items.slice()).slice(0, TOP);
      return o; });
    const nm = Object.values(C.src).filter((x) => !x.measured).map((x) => ({ key: x.key, label: x.label, reason: x.reason, connect: x.connect }));
    const anyStore = C.stores.length + C.dbs.length + C.cloudStores.length > 0;
    if (named) audit(who, 'data.posture.read', 'all', { items: risksOut.reduce((a, r) => a + (r.items ? r.items.length : 0), 0), measured: S.based_on.measured });
    return { generated_at: iso(), named, score: S, risks: risksOut, not_measured: nm, sources: Object.values(C.src).map((x) => ({ key: x.key, label: x.label, measured: x.measured, last: x.last || null, reason: x.reason })),
      stores: storesSummary(C), scan_status: scanStatus(C, named), classes: classes(C),
      empty: S.value == null ? 'Nothing is connected yet: ' + nm.map((x) => x.label).join(', ') + '. Connect Microsoft 365 (SharePoint / OneDrive discovery) and the cloud agent in the SIEM, run Personal-data discovery on the databases, and record the processing activities - nothing is shown until a source has reported.' : anyStore ? null : 'No data store has been discovered yet - run the SharePoint / OneDrive discovery, the file-share scan, the cloud agent or Personal-data discovery.',
      note: 'Indicators for a person to confirm, not proof. Only counts per kind are read - never a personal data value or a secret. A source that is not connected is listed as not measured; it never counts as safe.' };
  }
  async function riskItems(key, q, who) {
    const { R } = await build(who), X = R[key];
    const items = order(X.items.slice()).slice(0, q.limit || 500);
    audit(who, 'data.posture.risk.read', key, { items: items.length, total: X.items_total });
    return { key, title: X.title, what: X.what, measured: X.measured, count: X.count, deduction: X.deduction, breakdown: X.breakdown, total: X.items_total, items, truncated: X.items_total > items.length, note: X.note || null };
  }

  /* ---- the daily snapshot without a visitor */
  let timer = null, stopped = false;
  const job = guardOf(app, 'data-posture.snapshot', async () => { cache = null; await build(SIEM_SYS); });
  function schedule(delay) { if (stopped) return; timer = setTimeout(async () => { try { await job(); } finally { schedule(DAY); } }, delay); if (timer.unref) timer.unref(); }
  function start() { if (opts.noTimer || timer) return; schedule(10 * 60000); }
  function stop() { stopped = true; if (timer) clearTimeout(timer); }
  return { view, riskItems, collect, build, start, stop, flush: () => { cache = null; }, RULES, SOURCES, KIND_LABEL, CATEGORY, CLOUD, ENGINE, isNamed };
}

function registerDataPosture(srv, app, X) {
  const P = X && X.view ? X : createDataPosture(app, X || {});
  app.addons = app.addons || {}; app.addons.dataPosture = P;
  srv.route('GET', '/data-posture', (ctx) => { ctx.need('viewer'); body(ctx.query || {}).done(); return P.view(ctx.who); });
  srv.route('GET', '/data-posture/risks/:key', (ctx) => {
    ctx.need('operator');   // file, bucket, site and person names: operators and administrators (PDPL)
    const key = param(ctx.params.key, 'key'); if (!RISK_KEYS.includes(key)) throw httpErr(400, 'key must be one of: ' + RISK_KEYS.join(', '));
    const q = body(ctx.query || {}).int('limit', { min: 1, max: 500 }).done();
    return P.riskItems(key, q, ctx.who);
  });
  return P;
}

module.exports = { createDataPosture, registerDataPosture, RULES, SOURCES, RISK_KEYS, SCORE_RULE };
