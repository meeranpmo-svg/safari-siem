// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * Dark Web Watch - the organisation's staff accounts found in data breaches, stealer-malware logs, pastes and underground mentions,
 * from LEGITIMATE providers only. This module never crawls Tor or criminal forums and never buys data: it reads
 *   hibp      Have I Been Pwned's domain search (api/v3/breacheddomain/<domain>, a paid key and a domain verified with HIBP),
 *             the public breach catalogue (api/v3/breaches) for what each breach exposed and when, and - where the
 *             subscription includes it - stealer logs by e-mail domain (api/v3/stealerlogsbyemaildomain/<domain>)
 *   import    findings exported from the threat-intelligence provider the organisation subscribes to (Cyble, SOCRadar, Recorded
 *             Future, Flare, KELA ...) as JSON or CSV: account, source, kind, date, data classes
 * Only accounts on the company's own e-mail domains are kept. PASSWORDS ARE NEVER STORED: any password / hash / cookie / token
 * field in an import is dropped before anything is saved, and only "the leak included a password" is kept (counted on the import).
 * Each exposure is matched to Active Directory (ad/identity.js): enabled or disabled, privileged, last logon, and whether the
 * password was changed AFTER the leak - which is what decides whether the leaked password still works. Risk 0-100, every point
 * named. A new exposure at risk >= 50 raises one alert (rule dw-exposure, grouped per account).
 * Lifecycle: new -> notified (the user / manager told) -> reset (the password changed) -> closed, or false positive. "reset" is
 * VERIFIED when the directory shows a password change after the exposure was first seen; otherwise a person attests it with a
 * note, and the page says it was attested, not verified. This module changes no account: resetting a password and revoking
 * sessions are done in Active Directory / Entra by the identity team.
 * Personal data (PDPL): account names are shown to analysts and above, viewers get counts; every named read is audited.
 *   GET  {P}/soc/darkweb                        any signed-in user   summary, sources, settings (counts only for viewers)
 *   GET  {P}/soc/darkweb/exposures              analyst              ?status=&kind=  the exposures with directory match and risk
 *   POST {P}/soc/darkweb/exposures/:id          operator             {status, note}
 *   POST {P}/soc/darkweb/sync                   operator             read Have I Been Pwned now
 *   POST {P}/soc/darkweb/import                 operator             {provider, format: json|csv, content}
 *   POST {P}/soc/darkweb/settings               admin                {domains[], poll_h, hibp_key?}  (the key is write-only)
 */
const SF = require('../secretfile');
const { wrap, audit, prefixOf, HttpError } = require('./routeutil');
const { body, param } = require('../util/check');
const { guard } = require('../util/errors');

const DAY = 86400000, H = 3600000;
const KINDS = ['breach', 'stealer', 'paste', 'mention', 'credential'];
const STATUSES = ['new', 'notified', 'reset', 'closed', 'false_positive'];
const NEXT = { new: ['notified', 'reset', 'false_positive'], notified: ['reset', 'false_positive'], reset: ['closed', 'notified'], closed: ['notified'], false_positive: ['new'] };
const DOMAIN = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SECRETISH = /^(pass(word)?|pwd|pass_?hash|hash|password_?hash|cookie|cookies|token|session|secret|plaintext|cleartext)$/i;
const HIBP = 'https://haveibeenpwned.com/api/v3';
const lc = (s) => String(s == null ? '' : s).trim().toLowerCase();
const clip = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const toMs = (v) => { if (v == null || v === '') return null; const t = typeof v === 'number' ? v : Date.parse(v); return Number.isFinite(t) ? t : null; };

function csvRows(text) {
  const out = [], s = String(text); let row = [], cell = '', q = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '"' && s[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') q = false; else cell += c; }
    else if (c === '"') q = true; else if (c === ',') { row.push(cell); cell = ''; } else if (c === '\n' || c === '\r') { if (c === '\r' && s[i + 1] === '\n') i++; row.push(cell); out.push(row); row = []; cell = ''; } else cell += c;
  }
  if (cell !== '' || row.length) { row.push(cell); out.push(row); }
  const hd = (out.shift() || []).map((h) => lc(h));
  return out.filter((r) => r.some((x) => x.trim())).map((r) => Object.fromEntries(hd.map((h, i) => [h, r[i] == null ? '' : r[i]])));
}

function createDarkweb(deps = {}) {
  const { state } = deps, now = deps.now || Date.now, L = deps.log || { info() {}, warn() {} };
  const E = state.collection('darkweb_exposures'), C = state.collection('darkweb_cfg');
  const doFetch = deps.fetch || ((...a) => fetch(...a));
  const secPath = deps.secretsPath || (deps.config && deps.config._paths && deps.config._paths.secrets);
  let timer = null;
  const cfg = () => Object.assign({ domains: [], poll_h: 24 }, (C.get('cfg') || {}).value || {});
  const key = () => { if (deps.hibpKey) return deps.hibpKey(); if (!secPath) return ''; try { return ((SF.read(secPath) || {}).darkweb || {}).hibp_key || ''; } catch (e) { return ''; /* no secrets file yet: not configured */ } };
  const inDomain = (acct, D) => { const d = lc(acct).split('@')[1]; return !!d && D.some((x) => d === x || d.endsWith('.' + x)); };
  const nextId = () => 'DW-' + String(E.all().reduce((m, x) => Math.max(m, Number(String(x.id).split('-')[1]) || 0), 0) + 1).padStart(5, '0');

  // ---------- directory match and risk (recomputed at read: the directory moves)
  function enrich(x) {
    const t = now(), id = deps.identity && deps.identity.lookup ? (deps.identity.lookup(x.account) || deps.identity.lookup(x.account.split('@')[0])) : null;
    const leakAt = x.breach_date || x.added_date || x.first_seen;
    const dir = id ? { matched: true, sam: id.sam || '', disabled: !!id.disabled, privileged: !!id.privileged, last_logon: id.last_logon || 0, pwd_last_set: id.pwd_last_set || 0,
      changed_since_leak: !!(id.pwd_last_set && leakAt && id.pwd_last_set > leakAt), changed_since_seen: !!(id.pwd_last_set && id.pwd_last_set > x.first_seen) } : { matched: false };
    const pts = [], add = (p, why) => pts.push({ points: p, why });
    if (x.kind === 'stealer') add(40, 'stealer-malware log: taken from an infected device, often with live sessions');
    else if (x.kind === 'credential') add(30, 'credential listing (account and password offered together)');
    else if (x.kind === 'breach') add(15, 'in a third-party data breach');
    else if (x.kind === 'paste') add(20, 'posted in a public paste');
    else add(10, 'named in an underground mention');
    if (x.includes_password) add(20, 'the leak included a password');
    if (dir.matched) {
      if (dir.privileged) add(25, 'privileged account in Active Directory');
      if (!dir.disabled) add(10, 'the account is enabled');
      if (!dir.disabled && x.includes_password && !dir.changed_since_leak) add(20, 'password not changed since the leak');
      if (dir.disabled) add(-30, 'the account is disabled');
    } else add(0, 'not found in the directory (a former employee, an alias or a shared mailbox) - check who owns it');
    if (leakAt && t - leakAt > 3 * 365 * DAY) add(-10, 'the leak is more than three years old');
    const risk = Math.max(0, Math.min(100, pts.reduce((s, p) => s + p.points, 0)));
    const verified = x.status === 'reset' || x.status === 'closed' ? (dir.changed_since_seen ? 'verified' : 'attested') : null;
    return Object.assign({}, x, { directory: dir, risk, risk_why: pts, level: risk >= 70 ? 'high' : risk >= 40 ? 'medium' : 'low', reset_evidence: verified });
  }

  // ---------- intake (both sources)
  function upsert(f, by) {
    const t = now(), k = lc(f.account) + '|' + lc(f.source) + '|' + f.kind;
    const cur = E.all((x) => x.key === k)[0];
    if (cur) { const u = Object.assign({}, cur, { last_seen: t, includes_password: cur.includes_password || !!f.includes_password, data_classes: [...new Set([].concat(cur.data_classes || [], f.data_classes || []))].slice(0, 30) }); E.put(u); return { rec: u, created: false }; }
    const rec = { id: nextId(), key: k, account: lc(f.account), domain: lc(f.account).split('@')[1], source: clip(f.source, 120), kind: f.kind, provider: f.provider, breach_date: toMs(f.breach_date), added_date: toMs(f.added_date),
      data_classes: (f.data_classes || []).map((d) => clip(d, 60)).slice(0, 30), includes_password: !!f.includes_password, first_seen: t, last_seen: t, status: 'new', history: [{ at: t, by, action: 'found', note: f.provider }] };
    E.put(rec);
    const e = enrich(rec);
    if (e.risk >= 50 && deps.alerts) {
      deps.alerts.raise({ rule_id: 'dw-exposure', rule_name: 'Staff account exposed: ' + (rec.kind === 'stealer' ? 'stealer log' : rec.kind), severity: rec.kind === 'stealer' || (e.directory.privileged) ? 4 : 3,
        group: { user: rec.account }, fields: { exposure: rec.id, source: rec.source }, summary: rec.account + ' found in ' + rec.source + ' (' + rec.kind + ', risk ' + e.risk + '): ' + e.risk_why.filter((p) => p.points > 0).map((p) => p.why).join('; '),
        ts_first: t, ts_last: t, count: 1, source: 'engine', suppress_s: 7 * 86400 });
    }
    return { rec, created: true };
  }

  async function syncHibp(by) {
    const k = key(), D = cfg().domains;
    if (!k) throw new HttpError(409, 'no Have I Been Pwned API key - an administrator enters it in Settings (a domain search key, with each domain verified at haveibeenpwned.com)');
    if (!D.length) throw new HttpError(409, 'no company e-mail domain set - an administrator adds them in Settings');
    const hdr = { 'hibp-api-key': k, 'user-agent': 'sentra-siem-darkweb/1', accept: 'application/json' };
    const get = async (u, withKey) => { const r = await doFetch(HIBP + u, { headers: withKey ? hdr : { 'user-agent': hdr['user-agent'], accept: 'application/json' }, signal: AbortSignal.timeout(60000) }); if (r.status === 404) return null; if (!r.ok) { const e = new Error('HTTP ' + r.status); e.status = r.status; throw e; } return r.json(); };
    const catalog = new Map(); try { for (const b of (await get('/breaches', false)) || []) catalog.set(b.Name, b); } catch (e) { L.warn('darkweb: breach catalogue read failed', { err: e.message }); }
    const res = { domains: 0, found: 0, created: 0, errors: [], stealer: 'not read' };
    for (const d of D) {
      try {
        const m = (await get('/breacheddomain/' + encodeURIComponent(d), true)) || {}; res.domains++;
        for (const [alias, names] of Object.entries(m)) for (const n of [].concat(names || [])) {
          const b = catalog.get(n) || {}; res.found++;
          const r = upsert({ account: alias + '@' + d, source: b.Title || n, kind: b.IsStealerLog ? 'stealer' : 'breach', provider: 'hibp', breach_date: b.BreachDate, added_date: b.AddedDate, data_classes: b.DataClasses || [], includes_password: (b.DataClasses || []).some((x) => /password/i.test(x)) }, by);
          if (r.created) res.created++;
        }
      } catch (e) { res.errors.push(d + ': ' + (e.status === 401 ? 'the API key was refused' : e.status === 403 ? 'the domain is not verified for this key' : e.status === 429 ? 'rate limited - try later' : e.message)); }
      try {
        const s = await get('/stealerlogsbyemaildomain/' + encodeURIComponent(d), true);
        if (s) { res.stealer = 'read'; for (const [alias, sites] of Object.entries(s)) { res.found++; const r = upsert({ account: alias + '@' + d, source: 'Stealer logs (' + [].concat(sites || []).slice(0, 3).join(', ') + ')', kind: 'stealer', provider: 'hibp', includes_password: true }, by); if (r.created) res.created++; } }
      } catch (e) { if (e.status === 401 || e.status === 403) res.stealer = 'not included in this subscription'; else res.errors.push(d + ' stealer logs: ' + e.message); }
    }
    C.put({ id: 'last_sync', value: { at: now(), by, result: res } });
    return res;
  }

  function importFindings(b0, by) {
    const b = body(b0 || {}).str('provider', { required: true, max: 60 }).oneOf('format', ['json', 'csv'], { required: true }).str('content', { required: true, max: 5 * 1024 * 1024 }).done();
    const D = cfg().domains; if (!D.length) throw new HttpError(409, 'no company e-mail domain set - an administrator adds them in Settings first');
    let rows;
    if (b.format === 'json') { try { const j = JSON.parse(b.content); rows = Array.isArray(j) ? j : Array.isArray(j.items) ? j.items : Array.isArray(j.findings) ? j.findings : null; } catch (e) { throw new HttpError(400, 'content is not valid JSON: ' + clip(e.message, 120)); } if (!rows) throw new HttpError(400, 'content: expected a JSON array (or {items: [...]})'); }
    else rows = csvRows(b.content);
    if (rows.length > 50000) throw new HttpError(400, 'content: at most 50 000 rows per import');
    const res = { rows: rows.length, kept: 0, created: 0, other_domain: 0, invalid: 0, passwords_dropped: 0 };
    for (const r0 of rows) {
      if (!r0 || typeof r0 !== 'object') { res.invalid++; continue; }
      const r = {}; for (const [k, v] of Object.entries(r0)) { if (SECRETISH.test(k)) { if (v) res.passwords_dropped++; continue; } r[lc(k)] = v; }   // never stored
      const acct = lc(r.email || r.account || r.username || r.login || r.user || '');
      if (!/^[^\s@]{1,64}@[a-z0-9.-]{3,253}$/.test(acct)) { res.invalid++; continue; }
      if (!inDomain(acct, D)) { res.other_domain++; continue; }
      const kind = KINDS.includes(lc(r.kind || r.type)) ? lc(r.kind || r.type) : /stealer|infostealer|botnet/i.test(String(r.kind || r.type || r.category || '')) ? 'stealer' : 'breach';
      const pw = Object.keys(r0).some((k) => SECRETISH.test(k) && r0[k]) || /^(1|true|yes)$/i.test(String(r.includes_password || r.has_password || ''));
      const dc = Array.isArray(r.data_classes) ? r.data_classes : String(r.data_classes || '').split(/[;|]/).map((x) => x.trim()).filter(Boolean);
      const out = upsert({ account: acct, source: r.source || r.breach || r.site || b.provider, kind, provider: 'import:' + clip(b.provider, 60), breach_date: r.breach_date || r.date || r.leak_date, added_date: r.added_date || r.discovered || r.found, data_classes: dc, includes_password: pw }, by);
      res.kept++; if (out.created) res.created++;
    }
    return res;
  }

  function transition(id, b0, by) {
    const x = E.get(param(String(id || ''))); if (!x) throw new HttpError(404, 'no exposure ' + String(id).slice(0, 40));
    const b = body(b0 || {}).oneOf('status', STATUSES, { required: true }).str('note', { max: 1000 }).done();
    if (!(NEXT[x.status] || []).includes(b.status)) throw new HttpError(409, 'from ' + x.status + ' the next step is ' + (NEXT[x.status] || []).join(' or '));
    const e = enrich(x);
    if ((b.status === 'false_positive' || b.status === 'closed') && !(b.note && b.note.length >= 5)) throw new HttpError(400, 'note is required (why)');
    if (b.status === 'reset' && !e.directory.changed_since_seen && !(b.note && b.note.length >= 5)) throw new HttpError(400, 'note is required: the directory shows no password change since this exposure was found, so say who reset it and when');
    x.status = b.status; x.history.push({ at: now(), by, action: b.status, note: b.note || '', evidence: b.status === 'reset' ? (e.directory.changed_since_seen ? 'directory' : 'attested') : undefined });
    E.put(x); return enrich(x);
  }

  function setSettings(b0, by) {
    const b = body(b0 || {}).list('domains', { max: 20 }).int('poll_h', { min: 6, max: 168 }).str('hibp_key', { max: 64 }).bool('clear_key', {}).done();
    const v = Object.assign({}, cfg());
    if (b.domains !== undefined) { v.domains = [...new Set(b.domains.map((d, i) => { const x = lc(d); if (!DOMAIN.test(x)) throw new HttpError(400, 'domains[' + i + ('] is not a domain name (e.g. ' + ZYB_ORG.domain + ')')); return x; }))]; }
    if (b.poll_h !== undefined) v.poll_h = b.poll_h;
    if (b.hibp_key !== undefined || b.clear_key) {
      if (b.hibp_key && !/^[A-Za-z0-9]{16,64}$/.test(b.hibp_key)) throw new HttpError(400, 'hibp_key is not a Have I Been Pwned API key (letters and digits)');
      if (!secPath) throw new HttpError(500, 'the secrets file location is unknown');
      let sec = {}; try { sec = SF.read(secPath) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; /* first secret: the file is created */ }
      sec.darkweb = Object.assign({}, sec.darkweb); if (b.clear_key) delete sec.darkweb.hibp_key; else sec.darkweb.hibp_key = b.hibp_key;
      SF.write(secPath, sec);
    }
    C.put({ id: 'cfg', value: { domains: v.domains, poll_h: v.poll_h }, by, at: now() });
    restart();
    return { domains: v.domains, poll_h: v.poll_h, key_set: !!key(), changed: Object.keys(b).filter((k) => k !== 'hibp_key').concat(b.hibp_key ? ['hibp_key'] : []) };
  }

  function list(q = {}) { return E.all((x) => (!q.status || x.status === q.status) && (!q.kind || x.kind === q.kind)).map(enrich).sort((a, b) => b.risk - a.risk || b.first_seen - a.first_seen); }
  function view(named) {
    const all = E.all().map(enrich), open = all.filter((x) => !['closed', 'false_positive'].includes(x.status)), c = cfg(), t = now();
    const cnt = (f) => open.filter(f).length;
    const bySource = {}; for (const x of all) bySource[x.source] = (bySource[x.source] || 0) + 1;
    return { at: new Date(t).toISOString(), named,
      settings: { domains: c.domains, poll_h: c.poll_h, key_set: !!key() }, last_sync: (C.get('last_sync') || {}).value || null,
      summary: { exposures: all.length, open: open.length, accounts: new Set(open.map((x) => x.account)).size, high: cnt((x) => x.level === 'high'), stealer: cnt((x) => x.kind === 'stealer'),
        privileged: cnt((x) => x.directory.privileged), not_changed: cnt((x) => x.includes_password && x.directory.matched && !x.directory.disabled && !x.directory.changed_since_leak), unmatched: cnt((x) => !x.directory.matched),
        new_30d: all.filter((x) => t - x.first_seen <= 30 * DAY).length },
      sources: Object.entries(bySource).map(([source, n]) => ({ source, exposures: n })).sort((a, b) => b.exposures - a.exposures).slice(0, 15),
      directory: !!(deps.identity && deps.identity.lookup),
      note: 'From legitimate providers only - Have I Been Pwned and the threat-intelligence provider\'s exports. Passwords are never stored. A finding says an account was exposed, not that it was misused: check sign-ins before acting.' };
  }

  // a self-rescheduling read of Have I Been Pwned every poll_h hours; it reschedules in finally, and a settings change re-arms it
  let armed = false;
  function arm() { if (!armed) return; if (timer) clearTimeout(timer); timer = setTimeout(tick, cfg().poll_h * H); if (timer.unref) timer.unref(); }
  const tick = guard('soc.darkweb.sync', async () => { try { if (key() && cfg().domains.length) await syncHibp('system:darkweb'); } finally { arm(); } });
  function start() { if (armed) return; armed = true; arm(); }
  function restart() { arm(); }
  return { view, list, enrich, syncHibp, importFindings, transition, setSettings, start, csvRows };
}

function register(api, deps) {
  if (!deps.state) return;
  const P = prefixOf(deps), D = createDarkweb(deps);
  if (!deps.noTimers) D.start();
  const named = (ctx) => ['analyst', 'operator', 'admin'].includes(String(ctx.role || '').toLowerCase());
  api.route('GET', `${P}/soc/darkweb`, wrap(deps, null, (ctx) => ctx.ok(D.view(named(ctx)))));
  api.route('GET', `${P}/soc/darkweb/exposures`, wrap(deps, 'analyst', (ctx) => {
    const q = body(ctx.query || {}).oneOf('status', STATUSES).oneOf('kind', KINDS).done(), L = D.list(q);
    audit(ctx, 'soc.darkweb.read', 'exposures', { shown: L.length, status: q.status, kind: q.kind });
    return ctx.ok({ items: L.slice(0, 2000), total: L.length });
  }));
  api.route('POST', `${P}/soc/darkweb/exposures/:id`, wrap(deps, 'operator', (ctx) => { const r = D.transition(ctx.params.id, ctx.body, ctx.user); audit(ctx, 'soc.darkweb.status', r.id, { status: r.status, evidence: r.reset_evidence || undefined }); return ctx.ok(r); }));
  api.route('POST', `${P}/soc/darkweb/sync`, wrap(deps, 'operator', async (ctx) => { const r = await D.syncHibp(ctx.user); audit(ctx, 'soc.darkweb.sync', 'hibp', { domains: r.domains, found: r.found, created: r.created, errors: r.errors.length }); return ctx.ok(r); }));
  api.route('POST', `${P}/soc/darkweb/import`, wrap(deps, 'operator', (ctx) => { const r = D.importFindings(ctx.body, ctx.user); audit(ctx, 'soc.darkweb.import', String((ctx.body || {}).provider || '').slice(0, 60), r); return ctx.ok(r); }), { maxBody: 6 * 1024 * 1024 });
  api.route('POST', `${P}/soc/darkweb/settings`, wrap(deps, 'admin', (ctx) => { const r = D.setSettings(ctx.body, ctx.user); audit(ctx, 'soc.darkweb.settings', 'darkweb', { domains: r.domains, poll_h: r.poll_h, changed: r.changed }); return ctx.ok(r); }));
}

module.exports = { register, createDarkweb, csvRows, KINDS, STATUSES };
