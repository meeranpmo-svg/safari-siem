// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Support contracts register — every vendor support / maintenance agreement in one place, assigned to what it covers in
// IT Asset Management and validated against the inventory:
//   Microsoft (Windows Server, Exchange, SQL Server: Software Assurance / Unified Support), VMware by Broadcom, Nutanix,
//   Oracle (CSI), Red Hat, Cisco (Smart Net), Fortinet (FortiCare / FortiGuard), Palo Alto Networks, and hardware support from
//   Dell, HPE, Lenovo, NetApp … FortiGate and PAN-OS firewalls also report their own support and subscription dates to the
//   AI Network Engineer (SIEM /netops/licenses); the Support Contracts page shows that next to the register.
//
//   Assigned   a contract covers a FAMILY (all Windows servers, all ESXi hosts, all Nutanix nodes …) or a list of assets /
//              serial numbers. In-scope assets are recognised from facts in the asset record only (OS, installed software,
//              tags, vendor / model) — never from name similarity — and the reason is shown.
//   Validated  dates (expired / expiring), coverage gaps (in-scope assets no active contract covers), listed assets that
//              are retired or missing, and quantity: the number of devices / servers / hosts / nodes from the inventory, or
//              the cores / processors the core-licensing audit computes (Windows Server, VMware, Oracle). Cisco serials are
//              also checked with Cisco itself (cisco-support.js). For other vendors there is no vendor check from here: an
//              operator records "verified with the vendor" with a reference (portal screenshot, partner e-mail, CSI page),
//              dated, and the page says which contracts were never verified.
//
//   GET  /support-contracts                     {settings, families, contracts[], gaps{}, summary}   any role (cost: operator+)
//   GET  /support-contracts/coverage?asset_id|serial|ip|name  contracts covering one asset + where to open a case   any role
//   POST /support-contracts                     {id?, vendor, family, product, contract_number, level, kind, start, end,
//                                                quantity, unit, asset_ids[], serials[], owner, cost, currency, portal, notes}  operator
//   POST /support-contracts/:id/verify          {reference}  verified with the vendor                         operator
//   POST /support-contracts/:id/retire          {reason}     (no hard delete)                                 operator
//   POST /support-contracts/import              {text}       CSV: vendor, family, product, contract, level, start, end,
//                                                quantity, unit, serials, assets, owner, cost, currency, notes  operator
//   PUT  /support-contracts/settings            {expiring_days}                                                admin
// Every change is audited (support.*) with who and when. Added with one registration line (install/add-support-contracts.sh).
const crypto = require('node:crypto');
const { parseCsv } = require('./import');
const { exchangeWhy } = require('./sysadmin-sync');

const DAY = 86400000;
const CLOSED = { retired: 1, disposed: 1 };
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max || 200);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const low = (v) => String(v || '').toLowerCase();
const normSerial = (v) => String(v || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 40);
const swHas = (a, re) => (a.software || []).some((x) => re.test(String(x && (x.name || x))));
const tagHas = (a, t) => (a.tags || []).map(low).includes(t);
const isoDate = (v) => { const t = s(v, 30); if (!t) return null; const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(t); if (!m) throw bad('dates must be YYYY-MM-DD: ' + t); return t; };

// how each family is recognised in the inventory, and what its quantity can be checked against
const FAMILIES = {
  windows_server: { label: 'Windows Server', vendor: 'Microsoft', units: ['servers', 'cores'], cores: ['windows_std', 'windows_dc'],
    why: (a) => ['server', 'vm'].includes(a.type) && (/windows server/i.test(a.os || '') ? 'OS ' + a.os : swHas(a, /windows server/i) ? 'software: Windows Server' : '') },
  exchange: { label: 'Exchange Server', vendor: 'Microsoft', units: ['servers'], why: (a) => ['server', 'vm'].includes(a.type) && exchangeWhy(a) },
  sql_server: { label: 'SQL Server', vendor: 'Microsoft', units: ['servers', 'cores'], why: (a) => ['server', 'vm'].includes(a.type) && (swHas(a, /microsoft sql server/i) ? 'software: SQL Server' : tagHas(a, 'sql') ? 'tag: sql' : '') },
  vmware: { label: 'VMware vSphere / VCF', vendor: 'VMware by Broadcom', units: ['hosts', 'cores'], cores: ['vmware'],
    why: (a) => a.type === 'server' && (/esxi|vmware esx/i.test(a.os || '') ? 'OS ' + a.os : '') },
  nutanix: { label: 'Nutanix (AOS / AHV, nodes)', vendor: 'Nutanix', units: ['nodes'],
    why: (a) => ['server', 'storage'].includes(a.type) && (/\bnutanix\b/i.test(a.vendor || '') ? 'vendor ' + a.vendor : /^NX-/i.test(a.model || '') ? 'model ' + a.model : /\bAHV\b/.test(a.os || '') ? 'OS ' + a.os : '') },
  oracle_db: { label: 'Oracle Database', vendor: 'Oracle', units: ['servers', 'processors'], cores: ['oracle_ee', 'oracle_se2'],
    why: (a) => ['server', 'vm'].includes(a.type) && (swHas(a, /oracle database/i) ? 'software: Oracle Database' : tagHas(a, 'oracle') ? 'tag: oracle' : '') },
  rhel: { label: 'Red Hat Enterprise Linux', vendor: 'Red Hat', units: ['servers'], why: (a) => ['server', 'vm'].includes(a.type) && (/red hat enterprise linux|\brhel\b/i.test(a.os || '') ? 'OS ' + a.os : '') },
  cisco: { label: 'Cisco hardware (Smart Net)', vendor: 'Cisco', units: ['devices'], why: (a, x) => (x.isCisco && x.isCisco(a) ? 'Cisco ' + (a.model || a.vendor || '') : '') },
  fortinet: { label: 'Fortinet (FortiCare, FortiGuard)', vendor: 'Fortinet', units: ['devices'],
    why: (a) => !CLOSED[a.status] && ['network', 'server', 'other'].includes(a.type) && (/\bforti/i.test(a.vendor || '') ? 'vendor ' + a.vendor : /^(FG|FGT|FortiGate|FS-|FortiSwitch|FAP|FortiAP|FAZ|FMG)/i.test(a.model || '') ? 'model ' + a.model : '') },
  paloalto: { label: 'Palo Alto Networks (support, subscriptions)', vendor: 'Palo Alto Networks', units: ['devices'],
    why: (a) => !CLOSED[a.status] && ['network', 'server', 'other'].includes(a.type) && (/palo ?alto/i.test(a.vendor || '') ? 'vendor ' + a.vendor : /^PA-\d/i.test(a.model || '') ? 'model ' + a.model : '') },
  hardware: { label: 'Hardware support (by vendor)', vendor: '', units: ['devices'], why: (a, x, c) => (c && c.vendor && ['server', 'storage', 'network', 'ups'].includes(a.type) && new RegExp('\\b' + c.vendor.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i').test(a.vendor || '') ? 'vendor ' + a.vendor : '') },
  other: { label: 'Other (listed assets only)', vendor: '', units: ['devices', 'users', 'subscription'], why: () => '' },
};
const UNITS = ['devices', 'servers', 'hosts', 'nodes', 'cores', 'processors', 'users', 'subscription'];
const KINDS = ['support', 'subscription', 'hardware', 'software-assurance'];
// where a case is opened (shown with the contract number); an admin can set another address per contract
const PORTALS = { microsoft: 'https://serviceshub.microsoft.com', 'vmware by broadcom': 'https://support.broadcom.com', vmware: 'https://support.broadcom.com', broadcom: 'https://support.broadcom.com',
  nutanix: 'https://portal.nutanix.com', oracle: 'https://support.oracle.com', 'red hat': 'https://access.redhat.com/support/cases', cisco: 'https://mycase.cloudapps.cisco.com/case',
  dell: 'https://www.dell.com/support', hpe: 'https://support.hpe.com', lenovo: 'https://support.lenovo.com', fortinet: 'https://support.fortinet.com', 'palo alto networks': 'https://support.paloaltonetworks.com', netapp: 'https://mysupport.netapp.com' };
const portalFor = (c) => c.portal || PORTALS[low(c.vendor)] || '';

function createSupportContracts(app, opts = {}) {
  const { store } = app, now = opts.now || Date.now;
  const col = store.collection('support_contracts'), cfg = store.collection('support_contracts_cfg'), assets = store.collection('assets');
  const audit = (e) => { if (app.audit) app.audit(e); };
  const cisco = () => (app.addons && app.addons.ciscoSupport) || opts.ciscoSupport || null;
  function settings() { return Object.assign({ expiring_days: 90 }, (cfg.get('settings') || {}).s || {}); }
  function putSettings(b, who) {
    const v = Number(b.expiring_days); if (!Number.isInteger(v) || v < 7 || v > 365) throw bad('expiring window must be 7-365 days');
    cfg.put({ id: 'settings', s: { expiring_days: v } }); audit({ by: who.user, role: who.role, ip: who.ip, action: 'support.settings', target: 'support-contracts', detail: { expiring_days: v } });
    return settings();
  }
  function httpsUrl(v) { if (!v) return ''; let u; try { u = new URL(String(v)); } catch { throw bad('portal must be an https:// address'); } if (u.protocol !== 'https:' || u.username || u.password) throw bad('portal must be an https:// address without a login'); return u.href; }

  function put(b, who) {
    const prev = b.id ? col.get(s(b.id, 40)) : null;
    if (b.id && !prev) throw bad('contract not found', 404);
    const family = s(b.family || (prev && prev.family), 30); if (!FAMILIES[family]) throw bad('family must be one of ' + Object.keys(FAMILIES).join(', '));
    const vendor = s(b.vendor || (prev && prev.vendor) || FAMILIES[family].vendor, 80); if (!vendor) throw bad('vendor required');
    const end = isoDate(b.end !== undefined ? b.end : prev && prev.end); if (!end) throw bad('end date required (YYYY-MM-DD)');
    const unit = s(b.unit || (prev && prev.unit) || FAMILIES[family].units[0], 20); if (!UNITS.includes(unit)) throw bad('unit must be one of ' + UNITS.join(', '));
    const qty = b.quantity === undefined || b.quantity === '' || b.quantity === null ? (prev ? prev.quantity : null) : Number(b.quantity);
    if (qty !== null && (!Number.isFinite(qty) || qty < 0 || qty > 1e7)) throw bad('quantity must be a number');
    const ids = Array.isArray(b.asset_ids) ? [...new Set(b.asset_ids.map((x) => s(x, 60)).filter(Boolean))].slice(0, 5000) : prev ? prev.asset_ids : [];
    for (const id of ids) if (!assets.get(id)) throw bad('asset not found: ' + id);
    const serials = Array.isArray(b.serials) ? [...new Set(b.serials.map(normSerial).filter(Boolean))].slice(0, 5000) : prev ? prev.serials : [];
    const cost = b.cost === undefined ? (prev ? prev.cost : null) : b.cost === '' || b.cost === null ? null : Number(b.cost);
    if (cost !== null && (!Number.isFinite(cost) || cost < 0)) throw bad('cost must be a number');
    const kind = s(b.kind || (prev && prev.kind) || 'support', 30); if (!KINDS.includes(kind)) throw bad('kind must be one of ' + KINDS.join(', '));
    const rec = Object.assign({ id: 'sc_' + crypto.randomBytes(5).toString('hex'), status: 'active', created_by: who.user, created_at: new Date(now()).toISOString(), history: [] }, prev || {}, {
      vendor, family, product: s(b.product !== undefined ? b.product : prev && prev.product, 160) || FAMILIES[family].label, contract_number: s(b.contract_number !== undefined ? b.contract_number : prev && prev.contract_number, 80),
      level: s(b.level !== undefined ? b.level : prev && prev.level, 120), kind, start: isoDate(b.start !== undefined ? b.start : prev && prev.start), end, quantity: qty, unit, asset_ids: ids, serials,
      owner: s(b.owner !== undefined ? b.owner : prev && prev.owner, 120), cost, currency: s(b.currency || (prev && prev.currency) || 'SAR', 3).toUpperCase(),
      portal: httpsUrl(b.portal !== undefined ? b.portal : prev && prev.portal), notes: s(b.notes !== undefined ? b.notes : prev && prev.notes, 1000), updated_by: who.user, updated_at: new Date(now()).toISOString() });
    // a renewal (new end date) resets the vendor verification: the new term has not been verified yet
    if (prev && prev.end !== rec.end) { rec.verified = null; rec.history = (rec.history || []).concat([{ at: rec.updated_at, by: who.user, what: `end date ${prev.end} → ${rec.end}` }]); }
    rec.history = (rec.history || []).concat([{ at: rec.updated_at, by: who.user, what: prev ? 'updated' : 'created' }]).slice(-100);
    col.put(rec);
    audit({ by: who.user, role: who.role, ip: who.ip, action: prev ? 'support.update' : 'support.create', target: rec.id, detail: { vendor, family, contract: rec.contract_number, end, assets: ids.length, serials: serials.length } });
    return rec;
  }
  function verify(id, b, who) {
    const c = col.get(s(id, 40)); if (!c) throw bad('contract not found', 404);
    const ref = s(b.reference, 300); if (!ref) throw bad('a reference is required (what you checked: portal page, partner e-mail, case number)');
    const at = new Date(now()).toISOString();
    col.patch(c.id, (x) => { x.verified = { at, by: who.user, reference: ref, end_seen: x.end }; x.history = (x.history || []).concat([{ at, by: who.user, what: 'verified with the vendor: ' + ref }]).slice(-100); return x; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'support.verify', target: c.id, detail: { reference: ref } });
    return col.get(c.id);
  }
  function retire(id, b, who) {
    const c = col.get(s(id, 40)); if (!c) throw bad('contract not found', 404);
    const reason = s(b.reason, 300); if (!reason) throw bad('a reason is required');
    const at = new Date(now()).toISOString();
    col.patch(c.id, (x) => { x.status = 'retired'; x.retired = { at, by: who.user, reason }; x.history = (x.history || []).concat([{ at, by: who.user, what: 'retired: ' + reason }]); return x; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'support.retire', target: c.id, detail: { reason } });
    return { ok: true };
  }
  function importText(b, who) {
    const p = parseCsv(String(b.text || '')); if (!p.rows.length) throw bad('no rows (expected a header line: vendor, family, product, contract, end …)');
    const H = Object.fromEntries(p.headers.map((h) => [low(h).replace(/[\s_]+/g, ' '), h]));
    const col_ = (...names) => { for (const n of names) if (H[n]) return H[n]; return null; };
    const C = { vendor: col_('vendor'), family: col_('family', 'type'), product: col_('product'), contract: col_('contract', 'contract number', 'csi', 'agreement'), level: col_('level', 'service level'),
      start: col_('start', 'start date'), end: col_('end', 'end date', 'expiry', 'expiry date'), quantity: col_('quantity', 'qty'), unit: col_('unit'), serials: col_('serials', 'serial numbers'),
      assets: col_('assets', 'asset names', 'servers'), owner: col_('owner'), cost: col_('cost'), currency: col_('currency'), notes: col_('notes') };
    if (!C.end || !C.family) throw bad('the CSV needs at least "family" and "end" columns');
    const byName = new Map(); for (const a of assets.all((x) => !CLOSED[x.status])) byName.set(low(a.name), a.id);
    let created = 0; const errors = [];
    p.rows.forEach((r, i) => {
      try {
        const names = C.assets ? String(r[C.assets] || '').split(/[;|]/).map((x) => x.trim()).filter(Boolean) : [];
        const missing = names.filter((n) => !byName.has(low(n))); if (missing.length) throw bad('assets not in the inventory: ' + missing.slice(0, 5).join(', '));
        put({ vendor: r[C.vendor], family: low(r[C.family]).replace(/\s+/g, '_'), product: r[C.product], contract_number: r[C.contract], level: r[C.level], start: r[C.start] || null, end: r[C.end],
          quantity: C.quantity ? r[C.quantity] : null, unit: C.unit ? low(r[C.unit]) || undefined : undefined, serials: C.serials ? String(r[C.serials] || '').split(/[;|\s]/) : [],
          asset_ids: names.map((n) => byName.get(low(n))), owner: C.owner ? r[C.owner] : '', cost: C.cost ? r[C.cost] : null, currency: C.currency ? r[C.currency] : undefined, notes: C.notes ? r[C.notes] : '' }, who);
        created++;
      } catch (e) { errors.push({ line: i + 2, error: e.message }); }
    });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'support.import', target: 'support contracts', detail: { created, errors: errors.length } });
    return { created, errors: errors.slice(0, 200), errors_total: errors.length };
  }

  /* ---- assessment */
  function needs() {   // cores / processors from the core-licensing audit (it reads the stored host facts; nothing is guessed)
    try { const v = require('./core-licensing').createCoreLicensing(app).view(); const o = {}; for (const x of v.summary) o[x.product] = { required: x.required, unknown: x.cores_unknown }; return o; } catch (e) { return {}; }
  }
  function inScope(fam, a, c) { if (!a || CLOSED[a.status]) return ''; try { return FAMILIES[fam].why(a, { isCisco: cisco() ? cisco().isCisco : null }, c) || ''; } catch (e) { return ''; } }
  function covers(c, a) {
    if (c.asset_ids.length || c.serials.length) return c.asset_ids.includes(a.id) || (!!normSerial(a.serial) && c.serials.includes(normSerial(a.serial)));
    return !!inScope(c.family, a, c);
  }
  function assess(c, all, cores, st, today) {
    const issues = [], days = Math.round((Date.parse(c.end + 'T00:00:00Z') - Date.parse(today + 'T00:00:00Z')) / DAY);
    const state = c.status === 'retired' ? 'retired' : days < 0 ? 'expired' : days <= st.expiring_days ? 'expiring' : 'active';
    if (state === 'expired') issues.push({ level: 'bad', text: `expired ${-days} day(s) ago` }); else if (state === 'expiring') issues.push({ level: 'warn', text: `ends in ${days} day(s): start the renewal` });
    const listed = c.asset_ids.map((id) => assets.get(id)), covered = all.filter((a) => covers(c, a));
    for (const a of listed) if (!a) issues.push({ level: 'warn', text: 'a listed asset no longer exists' }); else if (CLOSED[a.status]) issues.push({ level: 'warn', text: `${a.name} is ${a.status}: drop it at renewal` });
    const known = new Set(assets.all().map((a) => normSerial(a.serial)).filter(Boolean));
    const lost = c.serials.filter((x) => !known.has(x)); if (lost.length) issues.push({ level: 'warn', text: `${lost.length} serial(s) not in the inventory: ${lost.slice(0, 5).join(', ')}${lost.length > 5 ? '…' : ''}` });
    let need = null, need_from = '';
    if (['devices', 'servers', 'hosts', 'nodes'].includes(c.unit)) { need = covered.length; need_from = 'inventory'; }
    else if (['cores', 'processors'].includes(c.unit) && FAMILIES[c.family].cores && !c.asset_ids.length && !c.serials.length) {
      const ks = FAMILIES[c.family].cores.filter((k) => cores[k]); if (ks.length) { need = ks.reduce((n, k) => n + (cores[k].required || 0), 0); need_from = 'core-licensing audit'; if (ks.some((k) => cores[k].unknown)) issues.push({ level: 'warn', text: 'some hosts have no core count: the requirement is incomplete (Core licensing page)' }); }
    }
    if (c.quantity != null && need != null && state !== 'retired') {
      if (c.quantity < need) issues.push({ level: 'bad', text: `covers ${c.quantity} ${c.unit}, the estate has ${need} (${need_from})` });
      else if (need < c.quantity * 0.8 && c.quantity - need >= 2) issues.push({ level: 'info', text: `covers ${c.quantity} ${c.unit}, the estate has ${need}: possible saving at renewal` });
    }
    let vendor_check = null;
    if (c.family === 'cisco' && cisco()) {
      try { const rows = cisco().report().rows.filter((r) => covered.some((a) => a.id === r.asset_id)); const nc = rows.filter((r) => r.status === 'not-covered').length, val = rows.filter((r) => r.validated).length;
        vendor_check = { by: 'Cisco Support API', validated: val, of: rows.length, not_covered: nc }; if (nc) issues.push({ level: 'bad', text: `${nc} device(s) reported NOT covered by Cisco` }); } catch (e) { /* cisco add-on not ready */ }
    }
    if (!vendor_check && state !== 'retired' && (!c.verified || c.verified.end_seen !== c.end)) issues.push({ level: 'info', text: 'not verified with the vendor for this term' });
    return { state, days_left: days, covered_count: covered.length, need, need_from, issues, vendor_check, portal: portalFor(c), covered_sample: covered.slice(0, 50).map((a) => ({ id: a.id, name: a.name, why: c.asset_ids.includes(a.id) ? 'listed' : (c.serials.includes(normSerial(a.serial)) ? 'serial ' + normSerial(a.serial) : inScope(c.family, a, c)) })) };
  }
  function view(role) {
    const st = settings(), today = new Date(now()).toISOString().slice(0, 10), all = assets.all((a) => !CLOSED[a.status]), cores = needs();
    const list = col.all().map((c) => Object.assign({}, c, assess(c, all, cores, st, today)));
    const priv = !role || role === 'viewer';
    if (priv) for (const c of list) { delete c.cost; delete c.currency; }
    // gaps: per family, in-scope assets no active contract covers
    const gaps = {};
    for (const fam of Object.keys(FAMILIES)) {
      if (fam === 'hardware' || fam === 'other') continue;
      const scope = all.map((a) => ({ a, why: inScope(fam, a) })).filter((x) => x.why);
      if (!scope.length) continue;
      const active = list.filter((c) => c.family === fam && (c.state === 'active' || c.state === 'expiring'));
      const un = scope.filter((x) => !active.some((c) => covers(c, x.a)));
      gaps[fam] = { label: FAMILIES[fam].label, in_scope: scope.length, uncovered: un.length, items: un.slice(0, 200).map((x) => ({ id: x.a.id, name: x.a.name, type: x.a.type, why: x.why, serial: x.a.serial || '' })) };
    }
    const live = list.filter((c) => c.state !== 'retired');
    const summary = { contracts: live.length, expired: live.filter((c) => c.state === 'expired').length, expiring: live.filter((c) => c.state === 'expiring').length,
      problems: live.filter((c) => c.issues.some((i) => i.level === 'bad')).length, unverified: live.filter((c) => c.issues.some((i) => /not verified/.test(i.text))).length,
      uncovered_assets: Object.values(gaps).reduce((n, g) => n + g.uncovered, 0), renewal_cost_90d: priv ? undefined : live.filter((c) => c.days_left <= 90 && c.cost).reduce((n, c) => n + c.cost, 0) };
    list.sort((x, y) => ({ expired: 0, expiring: 1, active: 2, retired: 3 }[x.state] - { expired: 0, expiring: 1, active: 2, retired: 3 }[y.state]) || x.days_left - y.days_left);
    return { at: new Date(now()).toISOString(), settings: st, families: Object.fromEntries(Object.entries(FAMILIES).map(([k, f]) => [k, { label: f.label, vendor: f.vendor, units: f.units }])), units: UNITS, kinds: KINDS, contracts: list, gaps, summary };
  }
  function coverage(q = {}) {
    const sn = normSerial(q.serial), ip = s(q.ip, 45), name = low(s(q.name, 120)), id = s(q.asset_id, 60);
    const a = assets.all((x) => !CLOSED[x.status] && ((id && x.id === id) || (sn && normSerial(x.serial) === sn) || (ip && x.mgmt_ip === ip) || (name && low(x.name) === name)))[0];
    if (!a) return { found: false };
    const st = settings(), today = new Date(now()).toISOString().slice(0, 10), cores = needs(), all = [a];
    const contracts = col.all((c) => c.status !== 'retired' && covers(c, a)).map((c) => { const r = assess(c, all, cores, st, today); return { id: c.id, vendor: c.vendor, product: c.product, contract_number: c.contract_number, level: c.level, end: c.end, state: r.state, days_left: r.days_left, portal: r.portal, verified: c.verified || null }; });
    const fams = Object.keys(FAMILIES).filter((f) => inScope(f, a)).map((f) => FAMILIES[f].label);
    let ciscoRow = null; try { if (cisco()) ciscoRow = cisco().coverage({ serial: a.serial, ip: a.mgmt_ip, name: a.name }); } catch (e) { /* none */ }
    return { found: true, asset: { id: a.id, name: a.name, type: a.type, vendor: a.vendor || '', model: a.model || '', serial: a.serial || '' }, families: fams, contracts,
      covered: contracts.some((c) => c.state === 'active' || c.state === 'expiring'), cisco: ciscoRow && ciscoRow.found ? ciscoRow : null };
  }
  return { view, put, verify, retire, importText, coverage, settings, putSettings, FAMILIES };
}

// the writes decided in Python (pyengine/support_write.py, migration step 9g), committed by engine/py-writer.js;
// supportContracts.engine = "node", or a missing Python bridge, keeps Node.js
function registerSupportContracts(srv, app) {
  const C = createSupportContracts(app);
  (app.addons = app.addons || {}).supportContracts = C;
  const W = (() => { try { return require('./py-writer').createPyWriter(app, { off: ((app.config && app.config.supportContracts) || {}).engine === 'node' }); } catch (e) { return null; } })();
  const w = (op, spec, who, node) => (W ? W.write(op, Object.assign({ own: ['support_contracts', 'support_contracts_cfg'], reads: ['assets'] }, spec), who, node) : node());
  const scId = () => 'sc_' + crypto.randomBytes(5).toString('hex');
  app.supportWriteStats = () => (W ? W.stats() : null);
  srv.route('GET', '/support-contracts', (ctx) => void ctx.need('viewer') || C.view(ctx.who && ctx.who.role));
  srv.route('GET', '/support-contracts/coverage', (ctx) => void ctx.need('viewer') || C.coverage(ctx.query || {}));
  srv.route('PUT', '/support-contracts/settings', (ctx) => { ctx.need('admin'); const b = ctx.body || {}; return w('support.settings', { extra: { body: b } }, ctx.who, () => C.putSettings(b, ctx.who)); });
  srv.route('POST', '/support-contracts/import', (ctx) => { ctx.need('operator'); const b = ctx.body || {}; return w('support.import', { extra: { body: b }, newIdRe: /^sc_[0-9a-f]{10}$/ }, ctx.who, () => C.importText(b, ctx.who)); }, { maxBody: 4 * 1024 * 1024 });
  srv.route('POST', '/support-contracts', (ctx) => { ctx.need('operator'); const b = ctx.body || {}; return w('support.put', { extra: { body: b }, newId: scId }, ctx.who, () => C.put(b, ctx.who)); });
  srv.route('POST', '/support-contracts/:id/verify', (ctx) => { ctx.need('operator'); const b = ctx.body || {}; return w('support.verify', { extra: { id: ctx.params.id, body: b } }, ctx.who, () => C.verify(ctx.params.id, b, ctx.who)); });
  srv.route('POST', '/support-contracts/:id/retire', (ctx) => { ctx.need('operator'); const b = ctx.body || {}; return w('support.retire', { extra: { id: ctx.params.id, body: b } }, ctx.who, () => C.retire(ctx.params.id, b, ctx.who)); });
  return C;
}

module.exports = { createSupportContracts, registerSupportContracts, FAMILIES, PORTALS };
