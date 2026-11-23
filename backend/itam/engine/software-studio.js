// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const { rollup, licenceCompliance } = require('./model/software');
/*
 * Software & Licences Studio (IT Assets -> Software & Licences, {P} = /api/itam). Over the installed software the agents and imports
 * report on every active asset, and the licence records:
 *   licences     seats vs installs (over / under / unknown), utilisation %, cost per seat and per USED seat, the cost of seats
 *                nobody uses (waste) and the true-up exposure of installs over the seats - money only from the licence's own cost
 *   reclaim      installs that free a seat: on retired / in-stock assets, or on assets not seen for 60+ days
 *   unlicensed   commercial publishers (word-bounded list) installed with no licence record that covers them
 *   risky        remote-access / tunnelling / torrent tools (word-bounded) - a finding until the software policy approves them
 *   rare         ML: a product on <= 2 assets of a type where >= 20 assets report software, and not approved - unusual for that
 *                type (typical shadow IT); said with the counts
 *   sprawl       versions per product and installs not on the newest version seen
 *   policy       approved / blocked per product (operator, a person, audited); a blocked product installed anywhere is a finding
 *   GET  /software-studio                viewer   (costs: operator and up)
 *   POST /software-studio/policy         operator {key, status: approved|blocked|none, reason}
 */
const DAY = 86400000;
const CLOSED = { retired: 1, disposed: 1 };
const COMMERCIAL = /\b(microsoft|oracle|adobe|autodesk|vmware|broadcom|citrix|sap|ibm|red hat|veeam|solarwinds|manageengine|zoho|tableau|atlassian|jetbrains|corel|nitro|foxit|bentley|esri|matlab|mathworks|quest|idera|sophos|kaspersky|trend micro|symantec|mcafee|fortinet|palo alto|splunk|teamviewer)\b/i;
const FREEWARE = /\b(redistributable|runtime|update for|security update|hotfix|language pack|visual c\+\+|\.net framework|edge webview|onedrive|teams machine-wide|defender|windows driver|direct ?x)\b/i;
const RISKY = /\b(anydesk|teamviewer|ultraviewer|rustdesk|logmein|ammyy|supremo|radmin|vnc|ngrok|tor browser|utorrent|bittorrent|qbittorrent|psiphon|hotspot shield|cheat engine|mimikatz|nmap|wireshark|putty)\b/i;
const CAT = [['security', /\b(antivirus|endpoint|kaspersky|defender|sophos|crowdstrike|forti|edr|firewall|vpn client|globalprotect)\b/i], ['database', /\b(sql server|oracle database|mysql|postgres|mariadb|db2|ssms|toad)\b/i],
  ['office', /\b(office|microsoft 365|word|excel|outlook|powerpoint|acrobat|pdf|visio|project)\b/i], ['remote', RISKY], ['developer', /\b(visual studio|git|python|node\.?js|java|jdk|eclipse|intellij|docker|postman)\b/i],
  ['browser', /\b(chrome|firefox|edge|opera|brave)\b/i], ['runtime', FREEWARE]];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const r2 = (n) => Math.round(n * 100) / 100;
const vcmp = (a, b) => { const pa = String(a).split(/[.\-_ ]/).map((x) => parseInt(x, 10) || 0), pb = String(b).split(/[.\-_ ]/).map((x) => parseInt(x, 10) || 0); for (let i = 0; i < Math.max(pa.length, pb.length); i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); } return 0; };

function createSoftwareStudio(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const polC = store.collection('software_policy');
  function analyse(role) {
    const priv = ['operator', 'admin'].includes(role);
    const all = store.collection('assets').all(), act = all.filter((a) => !CLOSED[a.status]);
    const byId = Object.fromEntries(all.map((a) => [a.id, a]));
    const prods = rollup(act), pol = Object.fromEntries(polC.all().map((p) => [p.id, p]));
    const lics = store.collection('licences').all((l) => l.status !== 'inactive');
    const covered = new Set(), T = now();
    // licences
    const licences = lics.map((l) => {
      const c = licenceCompliance(l, prods); c.products.forEach((k) => covered.add(k));
      const ids = new Set(); for (const p of prods) if (c.products.includes(p.key)) p.asset_ids.forEach((x) => ids.add(x));
      const reclaim = [...ids].map((id) => byId[id]).filter(Boolean).filter((a) => a.status === 'in_stock' || (a.last_seen && T - Date.parse(a.last_seen) > 60 * DAY))
        .map((a) => ({ asset_id: a.id, name: a.name || a.id, why: a.status === 'in_stock' ? 'asset is in stock' : 'not seen for ' + Math.round((T - Date.parse(a.last_seen)) / DAY) + ' days' }));
      const unit = l.cost != null && l.seats ? r2(l.cost / l.seats) : null;
      const days = l.expiry ? Math.round((Date.parse(l.expiry) - T) / DAY) : null;
      const out = { id: l.id, product: l.product, publisher: l.publisher, type: l.type, seats: l.seats, used: c.used, compliance: c.compliance, delta: c.delta, utilisation_pct: l.seats ? Math.round(100 * c.used / l.seats) : null,
        expiry: l.expiry ? String(l.expiry).slice(0, 10) : null, days_left: days, reclaim: reclaim.slice(0, 50), reclaim_count: reclaim.length, products: c.products.length };
      if (priv) Object.assign(out, { cost: l.cost, unit_cost: unit, cost_per_used_seat: l.cost != null && c.used ? r2(l.cost / c.used) : null,
        waste: unit != null && c.delta != null && c.delta < 0 ? r2(-c.delta * unit) : null, true_up: unit != null && c.delta != null && c.delta > 0 ? r2(c.delta * unit) : null, reclaim_value: unit != null ? r2(reclaim.length * unit) : null });
      return out;
    }).sort((a, b) => ({ over: 0, unknown: 2, under: 1, ok: 3 }[a.compliance] - { over: 0, unknown: 2, under: 1, ok: 3 }[b.compliance]) || (a.days_left == null ? 1e9 : a.days_left) - (b.days_left == null ? 1e9 : b.days_left));
    // software per asset type, for rarity
    const typeAssets = {}; for (const a of act) if ((a.software || []).length) typeAssets[a.type || 'other'] = (typeAssets[a.type || 'other'] || 0) + 1;
    const findings = [], F = (kind, sev, p, why, extra) => findings.push(Object.assign({ kind, severity: sev, key: p.key, product: p.name, publisher: p.publisher, installs: p.installs, why }, extra || {}));
    const products = prods.map((p) => {
      const label = (p.publisher || '') + ' ' + p.name, cat = (CAT.find(([, re]) => re.test(label)) || ['other'])[0], po = pol[p.key];
      const vs = p.versions.slice().sort(vcmp), newest = vs[vs.length - 1] || null;
      let behind = 0; if (vs.length > 1) for (const id of p.asset_ids) { const a = byId[id]; const v = ((a && a.software) || []).map((x) => (x && typeof x === 'object' ? x : { name: x })).find((x) => x.version && x.name && (p.name.toLowerCase().startsWith(String(x.name).toLowerCase().replace(/\s+\d[\d.]*$/, '')) || String(x.name).toLowerCase().startsWith(p.name.toLowerCase().replace(/\s+\d[\d.]*$/, '')))); if (v && v.version !== newest) behind++; }
      const licensed = covered.has(p.key) || !!p.licence_id;
      const flags = [];
      if (po && po.status === 'blocked') { flags.push('blocked'); F('blocked', 'high', p, 'blocked by the software policy (' + po.reason + ') and installed on ' + p.asset_ids.length + ' asset(s)', { assets: p.asset_ids.slice(0, 20) }); }
      if (RISKY.test(label) && !(po && po.status === 'approved')) { flags.push('risky'); F('risky', 'high', p, 'remote-access / tunnelling / dual-use tool on ' + p.asset_ids.length + ' asset(s) - approve it in the policy if it is sanctioned', { assets: p.asset_ids.slice(0, 20) }); }
      if (COMMERCIAL.test(label) && !FREEWARE.test(label) && !licensed && !(po && po.status === 'approved')) { flags.push('unlicensed'); F('unlicensed', 'medium', p, 'commercial software with no licence record covering it - add the licence or confirm it is free', { assets: p.asset_ids.slice(0, 20) }); }
      // rarity per asset type
      const types = {}; for (const id of p.asset_ids) { const t = (byId[id] && byId[id].type) || 'other'; types[t] = (types[t] || 0) + 1; }
      for (const [t, n] of Object.entries(types)) if (n <= 2 && (typeAssets[t] || 0) >= 20 && !(po && po.status === 'approved') && cat !== 'runtime') { flags.push('rare'); F('rare', 'low', p, 'on ' + n + ' of ' + typeAssets[t] + ' ' + t + ' assets that report software - unusual for that type', { assets: p.asset_ids.filter((id) => ((byId[id] || {}).type || 'other') === t) }); }
      if (vs.length >= 4) F('sprawl', 'low', p, vs.length + ' versions in use (' + vs[0] + ' ... ' + newest + '), ' + behind + ' install(s) behind the newest');
      return { key: p.key, name: p.name, publisher: p.publisher, category: cat, installs: p.installs, assets: p.asset_ids.length, versions: vs, newest, behind, licensed, policy: po ? po.status : null, flags };
    });
    const SEV = { high: 0, medium: 1, low: 2 }; findings.sort((a, b) => SEV[a.severity] - SEV[b.severity] || b.installs - a.installs);
    const cats = {}; for (const p of products) cats[p.category] = (cats[p.category] || 0) + 1;
    const sum = (f) => r2(licences.reduce((n, l) => n + (l[f] || 0), 0));
    return { at: new Date(T).toISOString(), costs_visible: priv,
      kpis: { products: products.length, installs: products.reduce((n, p) => n + p.installs, 0), assets_reporting: act.filter((a) => (a.software || []).length).length, assets: act.length, licences: licences.length,
        over: licences.filter((l) => l.compliance === 'over').length, under: licences.filter((l) => l.compliance === 'under').length, expiring_90: licences.filter((l) => l.days_left != null && l.days_left >= 0 && l.days_left <= 90).length,
        unlicensed: findings.filter((f) => f.kind === 'unlicensed').length, risky: findings.filter((f) => f.kind === 'risky' || f.kind === 'blocked').length, reclaim: licences.reduce((n, l) => n + l.reclaim_count, 0),
        waste: priv ? sum('waste') : undefined, true_up: priv ? sum('true_up') : undefined, reclaim_value: priv ? sum('reclaim_value') : undefined },
      categories: cats, licences, products, findings, policy: polC.all(),
      note: 'From the software the endpoint agents and imports report. An asset that reports no software is not counted as having none - coverage is shown. Money comes only from the licence records.' };
  }
  function setPolicy(input, who) {
    if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot set the software policy: a person does');
    const b = body(input).str('key', { required: true, max: 400 }).oneOf('status', ['approved', 'blocked', 'none'], { required: true }).str('reason', { max: 500 }).done();
    if (b.status !== 'none' && !b.reason) throw httpErr(400, 'reason: say why it is ' + b.status);
    const prev = polC.get(b.key);
    if (b.status === 'none') { if (prev) polC.remove(b.key); } else polC.put({ id: b.key, status: b.status, reason: b.reason, by: who.user, at: new Date(now()).toISOString() });
    app.audit && app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'software.policy', target: b.key, detail: { from: prev ? prev.status : null, to: b.status, reason: b.reason || null } });
    return { key: b.key, status: b.status };
  }
  return { analyse, setPolicy };
}

function registerSoftwareStudio(srv, app, S) {
  srv.route('GET', '/software-studio', (ctx) => { ctx.need('viewer'); return S.analyse(ctx.who && ctx.who.role); });
  srv.route('POST', '/software-studio/policy', (ctx) => { ctx.need('operator'); return S.setPolicy(ctx.body, Object.assign({ ip: ctx.ip }, ctx.who)); });
}

module.exports = { createSoftwareStudio, registerSoftwareStudio, RISKY, FREEWARE, CAT };
