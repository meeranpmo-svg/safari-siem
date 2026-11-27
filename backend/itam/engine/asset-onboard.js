// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Asset Onboarding - the system administrator's one place to add assets fast and keep the inventory accurate per branch.
 *   AI helper   paste anything - a CSV or Excel copy (with or without a header), a list of host names / IPs / MACs, an AD export -
 *               and it reads every row: the columns are recognised by their header or by their values; each row gets a TYPE
 *               (from the naming convention: DC / SRV / FS / SQL -> server, PC / LT -> workstation / laptop, SW / FW / AP / PRN ...,
 *               or the OS) and a SITE (an explicit column, a site name inside the host name, or LEARNED from the inventory: the site
 *               most assets of the same /24 already carry), each with its reason; a row already in the register (serial, MAC, name
 *               or IP) is matched and not created twice. Rule-based and learned from the inventory - no data leaves the platform.
 *   add         the rows a person keeps are created in the register (operator, a person - never an AI identity), audited.
 *   accuracy    per branch: assets, completeness (IP, serial, owner, OS), sources (agent / AD / discovery / manual), not seen for
 *               30+ days, suspected duplicates (the same serial or MAC on two records), site conflicts (an asset's /24 mostly
 *               belongs to another branch) and no site at all - a score per branch, the issues listed with the records.
 *   GET  /asset-onboard/overview   viewer     branch accuracy (names of assets for operator and above)
 *   POST /asset-onboard/parse      operator   {text}            -> rows with guesses, reasons and matches (nothing written)
 *   POST /asset-onboard/commit     operator   {rows:[...]}      -> created / skipped with the reason              audited
 */
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const MAC = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
const HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const JUNK_SERIAL = /^(to be filled|default string|0+|none|n\/a|system serial number|123456789)$/i;
const DAY = 86400000;
// column headers people use (English and Arabic)
const COLS = { name: /^(name|host ?name|computer( ?name)?|device( ?name)?|asset( ?name)?|cn|dnshostname|اسم|الجهاز)$/i, ip: /^(ip|ip ?address|ipv4|address|mgmt[_ ]?ip|عنوان)$/i,
  mac: /^(mac|mac ?address)$/i, serial: /^(serial|serial ?(no|number)|s\/n|sn|service ?tag|الرقم التسلسلي)$/i, os: /^(os|operating ?system|operatingsystem|نظام التشغيل)$/i,
  site: /^(site|branch|location|office|الفرع|الموقع)$/i, type: /^(type|category|class|النوع)$/i, owner: /^(owner|user|assigned ?to|custodian|المستخدم)$/i,
  model: /^(model|الطراز)$/i, department: /^(department|dept|الإدارة|القسم)$/i, vendor: /^(vendor|manufacturer|make)$/i };
// naming convention -> type (first match), with the reason shown
const NAME_RULES = [[/(^|[-_.])(dc|adc|addc)\d*([-_.]|$)|^dc\d/i, 'server', ['domain-controller'], 'name looks like a domain controller'],
  [/(^|[-_.])(srv|svr|server|fs|file|db|sql|ora|app|web|exch|mail|hv|hyperv|esx|vm|bkp|backup)\d*([-_.]|$)/i, 'server', [], 'name looks like a server'],
  [/(^|[-_.])(lt|lap|laptop|nb|nbk)\d*([-_.]|$)/i, 'laptop', [], 'name looks like a laptop'], [/(^|[-_.])(pc|ws|wks|dt|desk)\d*([-_.]|$)/i, 'workstation', [], 'name looks like a workstation'],
  [/(^|[-_.])(sw|switch|core|acc)\d*([-_.]|$)/i, 'network', ['switch'], 'name looks like a switch'], [/(^|[-_.])(fw|fgt|forti|firewall)\d*([-_.]|$)/i, 'network', ['firewall'], 'name looks like a firewall'],
  [/(^|[-_.])(ap|wap|wifi)\d*([-_.]|$)/i, 'network', ['wireless'], 'name looks like an access point'], [/(^|[-_.])(prn|prt|printer|mfp)\d*([-_.]|$)/i, 'printer', [], 'name looks like a printer'],
  [/(^|[-_.])(cam|nvr|cctv)\d*([-_.]|$)/i, 'other', ['cctv'], 'name looks like a camera / recorder'], [/(^|[-_.])(ups)\d*([-_.]|$)/i, 'ups', [], 'name looks like a UPS'],
  [/(^|[-_.])(ph|phone|ipp)\d*([-_.]|$)/i, 'phone', [], 'name looks like an IP phone']];
const TYPES = ['server', 'vm', 'workstation', 'laptop', 'network', 'printer', 'phone', 'storage', 'ups', 'mobile', 'peripheral', 'other'];
const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
const s = (v, m = 200) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, m);
const net24 = (ip) => (IPV4.test(ip || '') ? ip.split('.').slice(0, 3).join('.') : null);

// ---- pure: read pasted text into rows of fields
function splitLine(l, d) {
  if (d !== ',') return l.split(d).map((x) => x.trim());
  const out = []; let cur = '', q = false;
  for (let i = 0; i < l.length; i++) { const c = l[i]; if (c === '"') { if (q && l[i + 1] === '"') { cur += '"'; i++; } else q = !q; } else if (c === ',' && !q) { out.push(cur.trim()); cur = ''; } else cur += c; }
  out.push(cur.trim()); return out;
}
function readText(text) {
  const lines = String(text || '').replace(/\r/g, '').split('\n').map((l) => l.trim()).filter((l) => l && !/^#/.test(l)).slice(0, 2001);
  if (!lines.length) return { rows: [], columns: [], header: false };
  const d = lines[0].includes('\t') ? '\t' : (lines[0].split(';').length > lines[0].split(',').length ? ';' : ',');
  const first = splitLine(lines[0], d), cols = first.map((h) => Object.keys(COLS).find((k) => COLS[k].test(h.replace(/[*:]/g, '').trim())) || null);
  const header = cols.filter(Boolean).length >= 1 && first.every((h) => !IPV4.test(h) && !MAC.test(h));
  const rows = [];
  for (const l of header ? lines.slice(1) : lines) {
    const cells = d === ',' && !header && !l.includes(',') ? l.split(/\s+/) : splitLine(l, d), f = {};
    if (header) cells.forEach((v, i) => { if (cols[i] && v && f[cols[i]] == null) f[cols[i]] = v; });
    else for (const v of cells) {   // no header: recognise each value
      if (!v) continue; if (IPV4.test(v) && !f.ip) f.ip = v; else if (MAC.test(v) && !f.mac) f.mac = v; else if (/windows|linux|ubuntu|red hat|centos|solaris|aix|macos|ios-xe|fortios|esxi/i.test(v) && !f.os) f.os = v;
      else if (HOST.test(v) && !f.name && !/^\d+$/.test(v)) f.name = v; else if (!f.serial && /^[A-Z0-9]{6,20}$/.test(v)) f.serial = v; }
    if (f.name && f.name.includes('.') && !IPV4.test(f.name) && /^[A-Za-z0-9-]+\.[A-Za-z0-9.-]+$/.test(f.name)) f.name = f.name.split('.')[0];   // an FQDN: the host part
    if (Object.keys(f).length) rows.push(f);
  }
  return { rows: rows.slice(0, 2000), columns: header ? cols : [], header, truncated: lines.length > 2001 };
}

function createAssetOnboard(app, opts = {}) {
  const now = opts.now || Date.now;
  const C = (x) => app.store.collection(x), assets = () => C('assets').all((a) => a.status !== 'deleted' && a.status !== 'disposed');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'asset_onboard.' + action, target, detail }); };

  function index(list) {
    const by = { serial: new Map(), mac: new Map(), name: new Map(), ip: new Map() }, subnet = new Map(), sites = new Set();
    for (const a of list) {
      if (a.serial && !JUNK_SERIAL.test(a.serial)) by.serial.set(low(a.serial), a);
      for (const m of [a.mac].concat(a.macs || [])) if (m) by.mac.set(low(m).replace(/-/g, ':'), a);
      if (a.name) { by.name.set(low(a.name), a); by.name.set(low(a.name).split('.')[0], a); }
      if (a.mgmt_ip) by.ip.set(a.mgmt_ip, a);
      if (a.site) { sites.add(a.site); const n = net24(a.mgmt_ip); if (n) { const m = subnet.get(n) || new Map(); m.set(a.site, (m.get(a.site) || 0) + 1); subnet.set(n, m); } }
    }
    return { by, subnet, sites: [...sites] };
  }
  // the site most assets of the /24 carry (learned), when it is a clear majority
  function learnedSite(I, ip) { const m = I.subnet.get(net24(ip)); if (!m) return null; const tot = [...m.values()].reduce((x, y) => x + y, 0), top = [...m.entries()].sort((a, b) => b[1] - a[1])[0]; return top[1] >= 2 && top[1] / tot >= 0.6 ? { site: top[0], n: top[1], of: tot } : null; }

  function parse(b0, who) {
    if (!isHuman(who.user)) throw bad('a person adds assets', 403);
    const b = body(b0).str('text', { required: true, max: 200000 }).done();
    const R = readText(b.text); if (!R.rows.length) throw bad('text: no asset found - paste one asset per line (name, IP, MAC, serial ...) or a table with a header');
    const I = index(assets()), siteNames = I.sites.map((x) => [x, low(x).replace(/[^a-z0-9]+/g, '')]).filter((x) => x[1].length >= 3);
    const rows = R.rows.map((f, i) => {
      const why = [], issues = [], out = { line: i + 1, name: s(f.name, 63), ip: IPV4.test(f.ip || '') ? f.ip : '', mac: MAC.test(f.mac || '') ? low(f.mac).replace(/-/g, ':') : '', serial: s(f.serial, 80), os: s(f.os, 120), model: s(f.model, 120), vendor: s(f.vendor, 120), owner: s(f.owner, 120), department: s(f.department, 120), type: '', tags: [], site: s(f.site, 120) };
      if (f.ip && !out.ip) issues.push('"' + s(f.ip, 40) + '" is not an IPv4 address'); if (f.mac && !out.mac) issues.push('"' + s(f.mac, 40) + '" is not a MAC address');
      if (out.name && !HOST.test(out.name)) { issues.push('name "' + out.name + '" has characters a host name cannot have'); }
      if (!out.name && !out.ip && !out.serial) issues.push('no name, IP or serial - nothing to identify it by');
      // type: an explicit column, else the naming convention, else the OS
      const t = low(f.type); if (t && TYPES.includes(t)) { out.type = t; why.push('type from the pasted column'); }
      if (!out.type && out.name) { const r = NAME_RULES.find((x) => x[0].test(out.name)); if (r) { out.type = r[1]; out.tags = r[2].slice(); why.push(r[3]); } }
      if (!out.type && out.os) { out.type = /server/i.test(out.os) || /linux|solaris|aix|esxi/i.test(out.os) ? 'server' : /windows (10|11|7|8)|macos/i.test(out.os) ? 'workstation' : /fortios|ios-xe|comware/i.test(out.os) ? 'network' : ''; if (out.type) why.push('type from the OS'); }
      if (!out.type) { out.type = 'other'; why.push('type not recognised - set it'); }
      if (/windows/i.test(out.os) || /^(dc|srv|pc|lt|ws)/i.test(out.name)) out.tags.push('windows');
      // site: column, a known branch inside the name, else learned from the /24
      if (out.site) why.push('site from the pasted column');
      if (!out.site && out.name) { const k = low(out.name).replace(/[^a-z0-9]+/g, ''), hit = siteNames.find((x) => k.includes(x[1])); if (hit) { out.site = hit[0]; why.push('site "' + hit[0] + '" is in the name'); } }
      if (!out.site && out.ip) { const L = learnedSite(I, out.ip); if (L) { out.site = L.site; why.push('site learned: ' + L.n + ' of ' + L.of + ' assets in ' + net24(out.ip) + '.0/24 are at ' + L.site); } }
      if (!out.site) issues.push('no site - choose the branch');
      // already in the register?
      const m = (out.serial && !JUNK_SERIAL.test(out.serial) && I.by.serial.get(low(out.serial)) && ['serial', I.by.serial.get(low(out.serial))]) || (out.mac && I.by.mac.get(out.mac) && ['MAC', I.by.mac.get(out.mac)])
        || (out.name && I.by.name.get(low(out.name)) && ['name', I.by.name.get(low(out.name))]) || (out.ip && I.by.ip.get(out.ip) && ['IP', I.by.ip.get(out.ip)]);
      out.match = m ? { asset_id: m[1].id, name: m[1].name, by: m[0] } : null;
      out.action = m ? 'skip' : issues.some((x) => /nothing to identify|not an IPv4|cannot have/.test(x)) ? 'fix' : 'create';
      out.why = why; out.issues = issues; return out;
    });
    const c = (a) => rows.filter((r) => r.action === a).length;
    return { rows, summary: { read: rows.length, create: c('create'), already: c('skip'), fix: c('fix'), header: R.header, columns: R.columns.filter(Boolean), truncated: !!R.truncated } };
  }

  function commit(b0, who) {
    if (!isHuman(who.user)) throw bad('a person adds assets', 403);
    if (!b0 || !Array.isArray(b0.rows)) throw bad('rows: a list of assets');
    if (!b0.rows.length || b0.rows.length > 500) throw bad('rows: 1 - 500 assets per add');
    const I = index(assets()), out = { created: [], skipped: [] };
    b0.rows.forEach((r0, i) => {
      let r; try {
        r = body(r0).str('name', { max: 63 }).str('ip', { max: 15 }).str('mac', { max: 17 }).str('serial', { max: 80 }).str('os', { max: 120 }).str('model', { max: 120 }).str('vendor', { max: 120 })
          .str('owner', { max: 120 }).str('department', { max: 120 }).str('site', { max: 120 }).oneOf('type', TYPES, { def: 'other' }).list('tags', { max: 10, item: 'str', itemMax: 40 }).done();
      } catch (e) { out.skipped.push({ row: i + 1, name: s(r0 && r0.name, 63), reason: 'rows[' + i + ']: ' + e.message }); return; }
      if (r.name && !HOST.test(r.name)) return out.skipped.push({ row: i + 1, name: r.name, reason: 'rows[' + i + '].name: not a host name' });
      if (r.ip && !IPV4.test(r.ip)) return out.skipped.push({ row: i + 1, name: r.name, reason: 'rows[' + i + '].ip: not an IPv4 address' });
      if (r.mac && !MAC.test(r.mac)) return out.skipped.push({ row: i + 1, name: r.name, reason: 'rows[' + i + '].mac: not a MAC address' });
      if (!r.name && !r.ip && !r.serial) return out.skipped.push({ row: i + 1, reason: 'rows[' + i + ']: no name, IP or serial' });
      const dup = (r.serial && I.by.serial.get(low(r.serial))) || (r.mac && I.by.mac.get(low(r.mac))) || (r.name && I.by.name.get(low(r.name))) || (r.ip && I.by.ip.get(r.ip));
      if (dup) return out.skipped.push({ row: i + 1, name: r.name, reason: 'already in the register as ' + (dup.name || dup.id), asset_id: dup.id });
      try {
        const res = app.assets.create({ name: r.name || r.ip || r.serial, type: r.type, mgmt_ip: r.ip || undefined, mac: r.mac || undefined, serial: r.serial || undefined, os: r.os || undefined, model: r.model || undefined, vendor: r.vendor || undefined,
          owner: r.owner || undefined, department: r.department || undefined, site: r.site || undefined, status: 'in_use', source: 'manual', tags: [...new Set((r.tags || []).concat(['onboarding-helper']))] }, who);
        const a = res.asset || res; out.created.push({ row: i + 1, asset_id: a.id, name: a.name });
        if (a.name) I.by.name.set(low(a.name), a); if (r.ip) I.by.ip.set(r.ip, a); if (r.serial) I.by.serial.set(low(r.serial), a); if (r.mac) I.by.mac.set(low(r.mac), a);
      } catch (e) { out.skipped.push({ row: i + 1, name: r.name, reason: s(e.message, 200) }); }
    });
    audit(who, 'commit', 'assets', { created: out.created.length, skipped: out.skipped.length });
    return out;
  }

  function overview(role) {
    const names = ({ operator: 1, admin: 1 })[role] === 1, list = assets().filter((a) => !['software', 'licence'].includes(a.type)), I = index(list), t = now();
    const serials = new Map(), macs = new Map();
    for (const a of list) { if (a.serial && !JUNK_SERIAL.test(a.serial)) { const k = low(a.serial); serials.set(k, (serials.get(k) || []).concat([a])); } if (a.mac) { const k = low(a.mac); macs.set(k, (macs.get(k) || []).concat([a])); } }
    const dupIds = new Set(); for (const g of [...serials.values(), ...macs.values()]) if (g.length > 1) g.forEach((a) => dupIds.add(a.id));
    const srcOf = (a) => { const S = new Set([a.source].concat((a.sources || []).map((x) => x && (x.source || x.name || x)))); return [...S].join(' ').toLowerCase(); };
    const B = new Map();
    for (const a of list) {
      const site = a.site || '(no site)', b = B.get(site) || { site, assets: 0, types: {}, ip: 0, serial: 0, owner: 0, os: 0, agent: 0, ad: 0, discovery: 0, manual: 0, stale: 0, dup: 0, conflict: 0, issues: [] };
      b.assets++; b.types[a.type] = (b.types[a.type] || 0) + 1;
      if (a.mgmt_ip) b.ip++; if (a.serial && !JUNK_SERIAL.test(a.serial)) b.serial++; if (a.owner || a.custodian) b.owner++; if (a.os) b.os++;
      const src = srcOf(a); if (/agent/.test(src) || (a.tags || []).includes('agent-reported')) b.agent++; else if (/\bad\b|active directory/.test(src)) b.ad++; else if (/discovery|sweep|snmp|vcenter|hyperv|unix/.test(src)) b.discovery++; else b.manual++;
      const seen = Date.parse(a.last_seen || ''), stale = Number.isFinite(seen) && t - seen > 30 * DAY; if (stale) b.stale++;
      if (dupIds.has(a.id)) b.dup++;
      const L = a.mgmt_ip && learnedSite(I, a.mgmt_ip), conflict = L && a.site && L.site !== a.site; if (conflict) b.conflict++;
      const iss = []; if (!a.site) iss.push('no site'); if (stale) iss.push('not seen for 30+ days'); if (dupIds.has(a.id)) iss.push('same serial or MAC as another record'); if (conflict) iss.push('its network ' + net24(a.mgmt_ip) + '.0/24 is mostly ' + L.site);
      if (iss.length && b.issues.length < 200) b.issues.push(Object.assign({ issues: iss }, names ? { asset_id: a.id, name: a.name, ip: a.mgmt_ip || '' } : {}));
      B.set(site, b);
    }
    const pct = (x, n) => (n ? Math.round(100 * x / n) : null);
    const branches = [...B.values()].map((b) => { const comp = Math.round((pct(b.ip, b.assets) + pct(b.serial, b.assets) + pct(b.owner, b.assets) + pct(b.os, b.assets)) / 4);
      const penalty = pct(b.stale + b.dup + b.conflict, b.assets) || 0, score = b.site === '(no site)' ? 0 : Math.max(0, Math.round(comp - penalty / 2));
      return Object.assign(b, { completeness: comp, score, pct: { ip: pct(b.ip, b.assets), serial: pct(b.serial, b.assets), owner: pct(b.owner, b.assets), os: pct(b.os, b.assets) } }); }).sort((a, b) => b.assets - a.assets);
    const tot = (k) => branches.reduce((x, b) => x + b[k], 0);
    return { branches, totals: { assets: list.length, branches: branches.filter((b) => b.site !== '(no site)').length, no_site: (B.get('(no site)') || { assets: 0 }).assets, stale: tot('stale'), duplicates: dupIds.size, conflicts: tot('conflict'),
      agent: tot('agent'), ad: tot('ad'), discovery: tot('discovery'), manual: tot('manual'), score: branches.length ? Math.round(branches.reduce((x, b) => x + b.score * b.assets, 0) / Math.max(1, list.length)) : null }, names };
  }
  return { parse, commit, overview, readText };
}

function registerAssetOnboard(srv, app, X) {
  srv.route('GET', '/asset-onboard/overview', (ctx) => { ctx.need('viewer'); return X.overview(ctx.who.role); });
  srv.route('POST', '/asset-onboard/parse', (ctx) => { ctx.need('operator'); return X.parse(ctx.body, ctx.who); }, { maxBody: 262144 });
  srv.route('POST', '/asset-onboard/commit', (ctx) => { ctx.need('operator'); return X.commit(ctx.body, ctx.who); }, { maxBody: 524288 });
  (app.addons = app.addons || {}).assetOnboard = X;
  return X;
}

module.exports = { createAssetOnboard, registerAssetOnboard, readText, NAME_RULES };
