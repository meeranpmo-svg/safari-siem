// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Licence details pulled automatically from what the estate already reports - nothing is typed twice:
//   1. Core-based licence audit facts (core_lic_facts) per server / VM, from Asset Discovery's read-only logins:
//        sockets + cores per socket   SSH login (unix_login)   physical servers only; ESXi / Nutanix hosts come from vCenter / Prism
//        Oracle edition               database login (db_login.oracle.edition): Enterprise -> ee, Standard -> se2, Express -> none
//        CPU vendor (SPARC)           SSH login (Solaris on SPARC: Oracle core factor 0.5)
//        Windows Server edition       the asset's OS ("... Datacenter" -> dc, "... Standard" -> std), physical Windows servers
//      A value typed by hand is NEVER overwritten: a field is filled only when it is empty, or still holds the value this
//      sync wrote last time (kept in f.auto[field]). A field typed over an auto value stays the person's from then on.
//   2. Microsoft 365 subscriptions -> licence register, from the SIEM's Graph sync (GET /m365/graph, subscribedSkus):
//      one record per paid SKU (id lic_m365_<sku>), seats = purchased, expiry = renewal date, used = assigned in Microsoft 365.
//      Seats and expiry follow Microsoft; product name, cost, publisher and notes stay as the register has them. Free /
//      trial SKUs (10 000+ seats) are skipped. A licence retired in the register is not revived.
//   3. Commercial products installed on assets with no licence record - listed for review, never created (seats unknown).
//   GET  /licence-sync        {last, sources{}, filled[], kept[], skipped[], m365{}, unlicensed[]}     operator
//   POST /licence-sync/run    run now                                                                  operator
// Runs 2 minutes after start and then every hour. Reads the inventory and the SIEM; writes only core_lic_facts and the
// licence register, each change audited as system:licence-sync.
// Self-contained, added to an existing install with one registration line (install/add-licence-sync.sh).

const SYS = { user: 'system:licence-sync', role: 'admin', ip: '' };
const CLOSED = { retired: 1, disposed: 1 };
const HOUR = 3600000;
const tags = (a) => (Array.isArray(a.tags) ? a.tags : []).map((t) => String(t).toLowerCase());
const isVm = (a) => a.type === 'vm' || tags(a).includes('vm');
const isHypervisor = (a) => tags(a).includes('esxi-host') || /esxi|vmware\s*esx|nutanix|\bahv\b/i.test(a.os || '');
const WIN_SERVER = /win[a-z_ ]*\d*[ _]*(server|srv)/i;
const int = (v) => { const n = parseInt(v, 10); return Number.isFinite(n) && n > 0 && n < 100000 ? n : null; };
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max || 120);

// Microsoft's SKU part numbers -> the names on the invoice (unknown SKUs keep their part number)
const SKU_NAMES = {
  SPE_E3: 'Microsoft 365 E3', SPE_E5: 'Microsoft 365 E5', SPE_F1: 'Microsoft 365 F3', M365_F1: 'Microsoft 365 F1',
  ENTERPRISEPACK: 'Office 365 E3', ENTERPRISEPREMIUM: 'Office 365 E5', STANDARDPACK: 'Office 365 E1', DESKLESSPACK: 'Office 365 F3',
  O365_BUSINESS_ESSENTIALS: 'Microsoft 365 Business Basic', O365_BUSINESS_PREMIUM: 'Microsoft 365 Business Standard', SPB: 'Microsoft 365 Business Premium',
  O365_BUSINESS: 'Microsoft 365 Apps for business', OFFICESUBSCRIPTION: 'Microsoft 365 Apps for enterprise',
  EXCHANGESTANDARD: 'Exchange Online (Plan 1)', EXCHANGEENTERPRISE: 'Exchange Online (Plan 2)', EXCHANGEDESKLESS: 'Exchange Online Kiosk', EXCHANGEARCHIVE_ADDON: 'Exchange Online Archiving',
  EMS: 'Enterprise Mobility + Security E3', EMSPREMIUM: 'Enterprise Mobility + Security E5', AAD_PREMIUM: 'Microsoft Entra ID P1', AAD_PREMIUM_P2: 'Microsoft Entra ID P2',
  INTUNE_A: 'Microsoft Intune Plan 1', ATP_ENTERPRISE: 'Microsoft Defender for Office 365 (Plan 1)', THREAT_INTELLIGENCE: 'Microsoft Defender for Office 365 (Plan 2)',
  WIN_DEF_ATP: 'Microsoft Defender for Endpoint P2', DEFENDER_ENDPOINT_P1: 'Microsoft Defender for Endpoint P1', IDENTITY_THREAT_PROTECTION: 'Microsoft 365 E5 Security',
  POWER_BI_PRO: 'Power BI Pro', PBI_PREMIUM_PER_USER: 'Power BI Premium Per User', PROJECTPROFESSIONAL: 'Project Plan 3', PROJECTPREMIUM: 'Project Plan 5',
  VISIOCLIENT: 'Visio Plan 2', VISIO_PLAN1_DEPT: 'Visio Plan 1', MCOEV: 'Teams Phone Standard', MCOMEETADV: 'Teams Audio Conferencing',
  Microsoft_Teams_Premium: 'Teams Premium', Microsoft_Teams_Rooms_Pro: 'Teams Rooms Pro', Microsoft_365_Copilot: 'Microsoft 365 Copilot',
  WIN10_VDA_E3: 'Windows Enterprise E3', WIN10_VDA_E5: 'Windows Enterprise E5', RIGHTSMANAGEMENT: 'Azure Information Protection P1',
};
const skuName = (sku) => SKU_NAMES[sku] || `Microsoft 365 subscription ${sku}`;
const skuId = (sku) => 'lic_m365_' + String(sku).toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 60);

// publishers whose products are sold per device / user / core - an install with no licence record is worth a look
const COMMERCIAL = /\b(microsoft|oracle|adobe|vmware|broadcom|autodesk|ibm|sap|red\s*hat|citrix|veeam|kaspersky|fortinet|tableau|minitab|matlab|mathworks|corel|nitro|foxit|bentley|esri|teamviewer|anydesk|quest|solarwinds|idera|embarcadero|jetbrains)\b/i;
// Windows / Office components, runtimes and drivers that ship with the OS or another licence - never listed
const BUNDLED = /\b(runtime|redistributable|update|hotfix|security intelligence|language pack|proofing|driver|sdk|\.net|visual c\+\+|edge|onedrive|teams machine-wide|webview|silverlight|xml|odbc|ole db|native client|clr types|management objects|report viewer|setup|bootstrapper|helper|tools for office|click-to-run|access database engine|policy|health|telemetry|compatibility|application compatibility)\b/i;

function createLicenceSync(app, opts = {}) {
  const { store } = app;
  const facts = store.collection('core_lic_facts'), devs = store.collection('disc_devices'), assets = store.collection('assets');
  const lic = store.collection('licences'), state = store.collection('licence_sync_state');
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  const siemCall = opts.siemCall || ((method, path) => {
    const d = app.discovery; if (!d || !d.siem || typeof d.siem.call !== 'function') throw Object.assign(new Error('SIEM link not configured in Asset Discovery'), { status: 503 });
    return d.siem.call(method, path, { user: SYS.user, role: 'viewer' });
  });
  let running = null;

  // the login records discovery holds for each asset: approved device -> asset_id, else the device's IP = asset mgmt_ip
  function loginsByAsset(live) {
    const byIp = new Map();
    for (const a of live) if (a.mgmt_ip) byIp.set(a.mgmt_ip, a.id);
    const out = new Map();
    for (const d of devs.all((x) => x.extra && (x.extra.unix_login || x.extra.db_login))) {
      const id = (d.asset_id && assets.get(d.asset_id) && d.asset_id) || (d.ip && byIp.get(d.ip));
      if (!id) continue;
      const o = out.get(id) || {};
      const u = d.extra.unix_login, db = d.extra.db_login;
      if (u && !u.error && (!o.unix || String(u.at || '') > String(o.unix.at || ''))) o.unix = u;
      if (db && db.oracle && (!o.oracle || String(d.last_seen || '') > String(o.oracle_seen || ''))) { o.oracle = db.oracle; o.oracle_seen = d.last_seen || ''; }
      out.set(id, o);
    }
    return out;
  }

  // what the assets say, per field: {value, from} or {skip: reason}
  function derive(a, L) {
    const r = {};
    const vm = isVm(a), hyp = isHypervisor(a), u = L && L.unix;
    if (!vm && !hyp && u) {
      const solaris = /solaris|sunos/i.test(u.os || a.os || '');
      // the old collector counted one "physical id" line per logical CPU: a Linux socket count is used only from the
      // fixed collector (sockets_v 2), or when it is plainly not a CPU count (fewer sockets than logical CPUs)
      const trusted = solaris || u.sockets_v >= 2 || (int(u.sockets) && int(u.cpus) && int(u.sockets) < int(u.cpus));
      if (int(u.sockets) && trusted) r.sockets = { value: int(u.sockets), from: 'SSH login' };
      else if (int(u.sockets)) r.sockets = { skip: 'socket count from an older collector (it counted logical CPUs) - run discovery again' };
      if (int(u.cores_per_socket)) r.cores_per_socket = { value: int(u.cores_per_socket), from: 'SSH login' };
      // SPARC (Oracle core factor 0.5 for SPARC T / M / SPARC64) - from what the login reported, never guessed for x86
      if (/sparc|sun4[uvm]/i.test(`${u.os || ''} ${u.model || ''} ${u.platform || ''}`)) r.cpu_vendor = { value: 'sparc', from: 'SSH login' };
    }
    if (L && L.oracle && L.oracle.edition) {
      const e = String(L.oracle.edition);
      const v = /enterprise/i.test(e) ? 'ee' : /standard/i.test(e) ? 'se2' : /express/i.test(e) ? 'none' : null;
      if (v) r.oracle = { value: v, from: `database login (${s(e, 40)})` };
      else r.oracle = { skip: `Oracle ${s(e, 40)} - set the edition by hand` };
    }
    if (!vm && !hyp && WIN_SERVER.test(a.os || '')) {
      const v = /datacenter/i.test(a.os) ? 'dc' : /standard/i.test(a.os) ? 'std' : null;
      if (v) r.windows = { value: v, from: 'operating system' };
    }
    return r;
  }

  function syncFacts(out) {
    const live = assets.all((a) => !CLOSED[a.status] && (a.type === 'server' || isVm(a) || isHypervisor(a)));
    const logins = loginsByAsset(live);
    const at = new Date(now()).toISOString();
    for (const a of live) {
      const want = derive(a, logins.get(a.id));
      const keys = Object.keys(want); if (!keys.length) continue;
      const cur = facts.get(a.id) || null, f = Object.assign({ id: a.id }, cur || {}), auto = Object.assign({}, f.auto || {});
      const name = a.name || a.asset_tag || a.id; let changed = false;
      for (const k of keys) {
        const w = want[k];
        if (w.skip) { out.skipped.push({ asset: name, field: k, reason: w.skip }); continue; }
        // Nutanix Prism fills its hosts' sockets / cores itself (engine/virt.js) - not touched here
        if ((k === 'sockets' || k === 'cores_per_socket') && f.source === 'nutanix') continue;
        const have = f[k], mine = auto[k];
        const empty = have == null || have === '';
        if (!empty && !(mine && mine.v === have)) { if (have !== w.value) out.kept.push({ asset: name, field: k, entered: have, found: w.value, from: w.from }); continue; }
        if (have !== w.value) { f[k] = w.value; changed = true; out.filled.push({ asset: name, field: k, value: w.value, from: w.from }); }
        if (!mine || mine.v !== w.value || mine.from !== w.from) { auto[k] = { v: w.value, from: w.from, at }; changed = true; }
      }
      if (!changed) continue;
      f.auto = auto; if (!cur) { f.updated_by = SYS.user; f.updated_at = at; }
      facts.put(f);
    }
    if (out.filled.length) audit({ by: SYS.user, role: SYS.role, ip: '', action: 'licence_sync.facts', target: 'core_lic_facts', detail: { filled: out.filled.length, kept_hand_entered: out.kept.length } });
  }

  // the same decisions in Python (pyengine/asset_rules.py licence_facts, step 6c); Node.js writes what it decided.
  // A missing or failing Python → syncFacts() above.
  const py = opts.request || opts.siemCall || ((app.config && app.config.licence_sync) || {}).engine === 'node' ? null
    : (() => { try { return require('./pyengine').createPyEngine({ python: (((app.config && app.config.discovery) || {}).python_bin) || undefined, timeoutMs: 5 * 60000 }); } catch (e) { return null; } })();
  const pick = (o, ks) => { const r = {}; for (const k of ks) if (o[k] !== undefined) r[k] = o[k]; return r; };
  async function syncFactsAuto(out) {
    if (py) {
      const factsById = {}; for (const f of facts.all()) factsById[f.id] = f;
      const r = await py.call('rules.licence_facts', {
        assets: assets.all().map((a) => pick(a, ['id', 'name', 'asset_tag', 'status', 'type', 'tags', 'os', 'mgmt_ip'])),
        devices: devs.all((x) => x.extra && (x.extra.unix_login || x.extra.db_login)).map((d) => Object.assign(pick(d, ['asset_id', 'ip', 'last_seen']), { extra: { unix_login: d.extra.unix_login, db_login: d.extra.db_login } })),
        facts: factsById, now: now(),
      });
      if (r && Array.isArray(r.puts)) {
        for (const f of r.puts) facts.put(f);
        out.filled.push(...r.filled); out.kept.push(...r.kept); out.skipped.push(...r.skipped); out.engine = 'python';
        if (out.filled.length) audit({ by: SYS.user, role: SYS.role, ip: '', action: 'licence_sync.facts', target: 'core_lic_facts', detail: { filled: out.filled.length, kept_hand_entered: out.kept.length } });
        return;
      }
    }
    syncFacts(out); out.engine = 'node';
  }
  async function unlicensedAuto() {
    if (py) {
      const r = await py.call('rules.unlicensed', { assets: assets.all((a) => !CLOSED[a.status]).map((a) => pick(a, ['id', 'status', 'software'])), licences: app.licences.active() });
      if (r && Array.isArray(r.unlicensed)) return r.unlicensed;
    }
    return unlicensed();
  }

  async function syncM365(out) {
    let r;
    try { r = await siemCall('GET', '/m365/graph'); } catch (e) { out.m365 = { ok: false, error: e.message }; return; }
    const j = r && r.json;
    if (!r || r.status !== 200 || !j) { out.m365 = { ok: false, error: `SIEM answered HTTP ${r ? r.status : 0}` }; return; }
    if (!j.configured) { out.m365 = { ok: false, error: 'Microsoft 365 is not connected in the SIEM' + (j.reason ? ` (${s(j.reason, 160)})` : '') }; return; }
    if (!Array.isArray(j.licenses)) { out.m365 = { ok: false, error: 'the Microsoft 365 sync did not return licences (needs LicenseManagement.Read.All or Organization.Read.All)' }; return; }
    const at = new Date(now()).toISOString(), res = { ok: true, updated: j.updated || null, created: 0, updated_records: 0, unchanged: 0, skipped_free: 0, retired_kept: 0 };
    for (const l of j.licenses) {
      const sku = s(l && l.sku, 80); if (!sku) continue;
      const total = Number(l.total) || 0, consumed = Number(l.consumed) || 0;
      if (l.free || total >= 10000) { res.skipped_free++; continue; }
      const id = skuId(sku), prev = lic.get(id);
      if (prev && prev.status === 'inactive') { res.retired_kept++; continue; }
      const expiry = /^\d{4}-\d{2}-\d{2}/.test(String(l.renews || '')) ? String(l.renews).slice(0, 10) : (prev && prev.expiry ? String(prev.expiry).slice(0, 10) : null);
      const m365 = { sku, consumed, total, at };
      if (prev && prev.seats === total && (prev.expiry ? String(prev.expiry).slice(0, 10) : null) === expiry && prev.m365 && prev.m365.consumed === consumed && prev.m365.total === total) { res.unchanged++; continue; }
      // product / cost / publisher / notes as the register already has them; seats + expiry follow Microsoft
      const body = Object.assign({}, prev || { product: skuName(sku), type: 'subscription', publisher: 'Microsoft', notes: 'Imported from Microsoft 365 (subscribedSkus) - add the cost to include it in the budget.' }, { id, seats: total, expiry });
      app.licences.upsert(body, SYS);
      const rec = lic.get(id); if (rec) lic.put(Object.assign({}, rec, { source: 'm365', m365 }));
      if (prev) res.updated_records++; else res.created++;
    }
    out.m365 = res;
  }

  // installed commercial products that no licence record covers (same matching as the register's compliance view)
  function unlicensed() {
    const { rollup, licenceCompliance } = require('./model/software');
    const rolled = rollup(assets.all((a) => !CLOSED[a.status]));
    const covered = new Set();
    for (const l of app.licences.active()) for (const k of licenceCompliance(l, rolled).products) covered.add(k);
    return rolled.filter((p) => !covered.has(p.key) && !p.licence_id && COMMERCIAL.test(`${p.publisher || ''} ${p.name}`) && !BUNDLED.test(p.name))
      .slice(0, 100).map((p) => ({ product: p.name, publisher: p.publisher || '', installs: p.installs, versions: p.versions.slice(0, 5) }));
  }

  async function run(who) {
    if (running) return running;
    running = (async () => {
      const t0 = now(), out = { at: new Date(t0).toISOString(), by: (who && who.user) || SYS.user, filled: [], kept: [], skipped: [], m365: null };
      try { await syncFactsAuto(out); } catch (e) { out.facts_error = e.message; }
      await syncM365(out);
      out.ms = now() - t0;
      state.put(Object.assign({ id: 'last' }, out, { filled: out.filled.slice(0, 500), kept: out.kept.slice(0, 500), skipped: out.skipped.slice(0, 500) }));
      return out;
    })();
    try { return await running; } finally { running = null; }
  }

  function status(un0) {
    const last = state.get('last') || null;
    let un = un0 || []; if (!un0) { try { un = unlicensed(); } catch (e) { /* inventory without software */ } }
    const autoFacts = facts.all((f) => f.auto && Object.keys(f.auto).length);
    return {
      last, running: !!running,
      sources: {
        ssh_logins: devs.all((d) => d.extra && d.extra.unix_login && !d.extra.unix_login.error).length,
        oracle_logins: devs.all((d) => d.extra && d.extra.db_login && d.extra.db_login.oracle).length,
        servers_with_auto_facts: autoFacts.length,
        m365_records: lic.all((l) => l.source === 'm365' && l.status !== 'inactive').length,
      },
      unlicensed: un,
      not_automatic: [
        'cores per socket on Windows servers and on Linux servers discovery has no SSH login for - enter them on Core-based licences, or add vCenter / Nutanix',
        'Oracle edition where there is no database login - the edition is then read from the installed-software list',
        'contract cost and purchase details - from the contract, not from the assets',
      ],
    };
  }

  // the register's "used" for a Microsoft 365 subscription is what Microsoft says is assigned, not installs on devices
  if (app.licences && typeof app.licences.complianceView === 'function' && !app.licences.complianceView.m365) {
    const orig = app.licences.complianceView.bind(app.licences);
    const wrapped = () => orig().map((l) => {
      const rec = lic.get(l.id); const m = rec && rec.source === 'm365' && rec.m365;
      if (!m) return l;
      const used = Number(m.consumed) || 0, seats = l.seats;
      return Object.assign({}, l, { used, delta: seats == null ? null : used - seats, compliance: seats == null ? 'unknown' : used > seats ? 'over' : used < seats ? 'under' : 'ok', products: ['assigned in Microsoft 365'], m365: m });
    });
    wrapped.m365 = true;
    app.licences.complianceView = wrapped;
  }

  // the page's view, with the unlicensed list from Python
  async function statusAuto() { let un = []; try { un = await unlicensedAuto(); } catch (e) { /* inventory without software */ } return status(un); }

  return { run, status, statusAuto, derive, syncFacts };
}

function registerLicenceSync(srv, app) {
  const L = createLicenceSync(app);
  (app.addons = app.addons || {}).licenceSync = L;
  srv.route('GET', '/licence-sync', (ctx) => { ctx.need('operator'); return L.statusAuto(); });
  srv.route('POST', '/licence-sync/run', async (ctx) => { ctx.need('operator'); await L.run(ctx.who); return L.statusAuto(); });
  const tick = () => { L.run().catch((e) => app.log && app.log.warn && app.log.warn('licence-sync', { error: e.message })); };
  const t1 = setTimeout(guardOf(app, 'licence-sync.tick', tick), 120000), t2 = setInterval(guardOf(app, 'licence-sync.tick', tick), HOUR);
  if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  return L;
}

module.exports = { createLicenceSync, registerLicenceSync, skuName, skuId, SKU_NAMES };
