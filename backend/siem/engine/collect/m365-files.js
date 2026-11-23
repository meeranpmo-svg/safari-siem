// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Personal-data discovery in SharePoint Online (and, when switched on, OneDrive) - READ-ONLY, through the same Entra ID app
 * registration as the Microsoft 365 collectors (collect/m365-graph.js graphGet / graphContent).
 *   Microsoft Graph permissions (application): Sites.Read.All (sites, libraries, files, sharing links); Files.Read.All for
 *   OneDrive; User.Read.All to list OneDrive owners; Organization.Read.All for the verified domains (to tell an outside
 *   recipient from a colleague). A permission not granted is reported by name; nothing else is asked for.
 * Per library: every file's name, folder, size and date (delta query); file names are classified (passport, medical, payroll
 * ... and credential files: id_rsa, *.pem, .env ...); the text of .txt/.csv/.json/.xml/.html, configuration and script
 * files (.env/.ini/.conf/.yml/.config/.ps1/.sh/.py ...) and .docx/.xlsx/.pptx up to max_mb is read on this server and matched
 * by pii/classify.js - personal data and credentials (private_key / api_key / password, category 'credentials') alike: only
 * COUNTS per kind are kept, never a value or a snippet, and the downloaded bytes are dropped at once. For a
 * file that holds personal data, its sharing is read: anonymous link, people outside the organisation, the whole
 * organisation, or not shared beyond its permissions.
 * Runs when asked (POST {P}/pii/sharepoint/run, admin) and weekly when config.json "m365": { "files": { "enabled": true } }.
 *   config m365.files: { enabled, poll_h (168), onedrive (false), max_items (100000), max_content (2000), max_mb (5) }
 * The result: <state_dir>/m365-files.json (0600) - file names and folders are themselves sensitive: analysts and above.
 */
const fs = require('node:fs');
const path = require('node:path');
const { guard } = require('../util/errors');
const C = require('../pii/classify');

const HIT_CAP = 1000;

function createFiles({ graph, config = {}, log, stateDir, now = Date.now } = {}) {
  const lg = log || { info() {}, warn() {}, error() {}, every() {} };
  const file = stateDir ? path.join(stateDir, 'm365-files.json') : '';
  let snap = null; try { if (file) snap = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { snap = null; if (e.code !== 'ENOENT') lg.warn('m365 files: result file unreadable, starting empty', { err: e.message }); }
  const st = { running: false, started_at: null, by: null, progress: '', last_error: '' };
  let timer = null, stopped = false, running = null;
  const cfg = () => Object.assign({ enabled: false, poll_h: 168, onedrive: false, max_items: 100000, max_content: 2000, max_mb: 5 }, ((config.m365 || {}).files) || {});
  const permOf = (e, perm) => (e && e.status === 403 ? perm + ' not granted' : String((e && e.message) || e).slice(0, 200));

  function relPath(it) { const p = String((it.parentReference && it.parentReference.path) || ''); const i = p.indexOf('root:'); return (i >= 0 ? p.slice(i + 5) : '') || '/'; }
  async function sharing(driveId, itemId, domains) {
    const perms = await graph.graphGet(`/drives/${driveId}/items/${itemId}/permissions`);
    let out = 'none';
    for (const p of Array.isArray(perms) ? perms : []) {
      const scope = p.link && p.link.scope;
      if (scope === 'anonymous') return 'anonymous';
      const ids = [p.grantedToV2, ...(p.grantedToIdentitiesV2 || [])].filter(Boolean);
      for (const g of ids) { const mail = String((g.user && (g.user.email || g.user.userPrincipalName)) || (g.siteUser && g.siteUser.email) || ''); const dom = mail.split('@')[1]; if (dom && domains.size && !domains.has(dom.toLowerCase())) out = 'external'; }
      if (scope === 'organization' && out === 'none') out = 'organization';
    }
    return out;
  }
  async function scanDrive(src, driveId, budget, domains, lim) {
    let items;
    try { items = await graph.graphGet(`/drives/${driveId}/root/delta?$select=id,name,size,file,folder,parentReference,lastModifiedDateTime,deleted&$top=999`, Math.ceil(lim.items / 999)); }
    catch (e) { src.errors.push(permOf(e, 'Sites.Read.All')); return; }
    for (const it of Array.isArray(items) ? items : []) {
      if (!it.file || it.deleted) continue;
      if (budget.items <= 0) { src.truncated = true; break; }
      budget.items--; src.files_seen++;
      const nameKinds = C.classifyName(it.name);
      let kinds = {}, by = nameKinds.length ? 'name' : null;
      if (C.readable(it.name) && (it.size || 0) <= lim.max_mb * 1048576 && budget.content > 0) {
        budget.content--;
        try {
          let buf = await graph.graphContent(`/drives/${driveId}/items/${it.id}/content`, lim.max_mb * 1048576);
          const text = C.textOf(it.name, buf); buf = null;
          if (text != null) { src.files_read++; kinds = C.classifyText(text).kinds; if (Object.keys(kinds).length) by = 'content'; }
          else src.files_unreadable++;
        } catch (e) { src.files_unreadable++; if (e.status === 403) src.errors.push(permOf(e, 'Sites.Read.All / Files.Read.All')); }
      } else if (C.readable(it.name)) src.files_skipped++;
      if (!by) continue;
      const hit = { id: it.id, drive: driveId, name: String(it.name).slice(0, 200), path: relPath(it).slice(0, 400), size: it.size || 0, modified: it.lastModifiedDateTime || null, kinds, name_kinds: nameKinds, by, shared: null };
      if (budget.perms > 0) { budget.perms--; try { hit.shared = await sharing(driveId, it.id, domains); } catch (e) { hit.shared = null; if (e.status === 403) src.errors.push(permOf(e, 'Sites.Read.All')); } }
      if (src.hits.length < HIT_CAP) src.hits.push(hit); else src.hits_truncated = true;
    }
  }
  const newSrc = (key, kind, label, url) => ({ key, kind, label: String(label || key).slice(0, 200), url: url || '', drives: 0, files_seen: 0, files_read: 0, files_skipped: 0, files_unreadable: 0, truncated: false, hits: [], errors: [] });

  async function run(who) {
    const lim = cfg(), t0 = now(), budget = { items: lim.max_items, content: lim.max_content, perms: 3000 }, out = { at: new Date(t0).toISOString(), by: who || 'schedule', sources: [], errors: [], limits: lim };
    let domains = new Set();
    try { const org = await graph.graphGet('/organization?$select=verifiedDomains'); for (const o of Array.isArray(org) ? org : []) for (const d of o.verifiedDomains || []) domains.add(String(d.name).toLowerCase()); }
    catch (e) { out.errors.push('verified domains: ' + permOf(e, 'Organization.Read.All') + ' - outside recipients cannot be told apart'); }
    let sites = [];
    try { sites = await graph.graphGet('/sites?search=*&$select=id,displayName,webUrl&$top=200', 10); }
    catch (e) { out.errors.push('sites: ' + permOf(e, 'Sites.Read.All')); }
    for (const s of (Array.isArray(sites) ? sites : []).slice(0, 1000)) {
      const src = newSrc('sp:' + s.id, 'sharepoint', s.displayName || s.webUrl, s.webUrl);
      st.progress = 'SharePoint: ' + src.label;
      let drives = [];
      try { drives = await graph.graphGet(`/sites/${s.id}/drives?$select=id,name`, 5); } catch (e) { src.errors.push(permOf(e, 'Sites.Read.All')); }
      for (const d of Array.isArray(drives) ? drives : []) { src.drives++; await scanDrive(src, d.id, budget, domains, lim); }
      src.errors = [...new Set(src.errors)].slice(0, 10);
      out.sources.push(src);
    }
    if (lim.onedrive) {
      let users = [];
      try { users = await graph.graphGet('/users?$select=id,userPrincipalName&$top=999', 10); } catch (e) { out.errors.push('OneDrive owners: ' + permOf(e, 'User.Read.All')); }
      for (const u of (Array.isArray(users) ? users : []).slice(0, 5000)) {
        if (budget.items <= 0) break;
        let d = null; try { d = await graph.graphGet(`/users/${u.id}/drive?$select=id`); } catch (e) { if (e.status === 403) { out.errors.push('OneDrive: ' + permOf(e, 'Files.Read.All')); break; } continue; }   // 404: the user has no OneDrive
        if (!d || !d.id) continue;
        const src = newSrc('od:' + u.id, 'onedrive', 'OneDrive: ' + u.userPrincipalName, '');
        st.progress = src.label; src.drives = 1;
        await scanDrive(src, d.id, budget, domains, lim);
        src.errors = [...new Set(src.errors)].slice(0, 10);
        if (src.files_seen) out.sources.push(src);
      }
    }
    out.errors = [...new Set(out.errors)];
    out.ok = out.sources.length > 0 || !out.errors.length;
    out.totals = { sources: out.sources.length, files_seen: out.sources.reduce((a, x) => a + x.files_seen, 0), files_read: out.sources.reduce((a, x) => a + x.files_read, 0), hits: out.sources.reduce((a, x) => a + x.hits.length, 0), seconds: Math.round((now() - t0) / 1000) };
    return out;
  }
  function runNow(who) {
    if (running) return { started: false, running: true, started_at: st.started_at, progress: st.progress };
    st.running = true; st.started_at = new Date(now()).toISOString(); st.by = who || 'schedule'; st.last_error = '';
    running = (async () => {
      try {
        const r = await run(who);
        if (!r.ok) throw new Error(r.errors.join('; ') || 'nothing could be read');
        snap = r;
        if (file) { fs.writeFileSync(file + '.tmp', JSON.stringify(r), { mode: 0o600 }); fs.renameSync(file + '.tmp', file); }
      } catch (e) { st.last_error = String(e.message).slice(0, 300); lg.warn('m365 files: discovery failed', { err: st.last_error }); }
      finally { st.running = false; st.progress = ''; running = null; }
    })();
    return { started: true, started_at: st.started_at };
  }
  const job = guard('collect.m365-files.discover', async () => { if (cfg().enabled) { runNow('schedule'); await running; if (st.last_error) throw new Error(st.last_error); } });
  function schedule() {
    if (stopped) return;
    const ms = Math.max(24, Number(cfg().poll_h) || 168) * 3600000;
    const age = snap && snap.at ? now() - Date.parse(snap.at) : Infinity;
    timer = setTimeout(async () => { try { await job(); } finally { schedule(); } }, Math.max(60000, Math.min(ms, ms - age))); if (timer.unref) timer.unref();
  }
  return {
    start() { schedule(); return this; },
    stop() { stopped = true; if (timer) clearTimeout(timer); },
    runNow, wait: () => running,
    data: () => Object.assign({ status: { running: st.running, started_at: st.started_at, by: st.by, progress: st.progress, last_error: st.last_error, enabled: cfg().enabled, onedrive: cfg().onedrive } }, snap || { sources: [], never: true }),
  };
}

module.exports = { createFiles };
