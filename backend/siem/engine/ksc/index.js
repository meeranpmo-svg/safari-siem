// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * AI engineer data source for Kaspersky Security Center (KSC OpenAPI), read-only. Same shape as the Zscaler module:
 * a connection inventory (state collection "ksc_servers"; password in secrets.json "ksc.servers.<id>", write-only), a
 * poll loop that reads endpoint posture, findings aggregated PER CATEGORY per server (so one noisy estate is a handful
 * of work items, not one per device), read-only investigation, verification by a fresh poll, and a four-eyes change
 * plan (createChanges, "ksc_changes"). Nothing changes KSC: a plan is applied by a person in the KSC console.
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const { writeJsonAtomic } = require('../onboard/store');
const { createChanges } = require('../netops/changes');
const ksc = require('./ksc');

const ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const clean = (s, max) => String(s == null ? '' : s).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, max);

const FIX = {
  'ksc-unreachable': 'Check the KSC OpenAPI endpoint (host:13299), the read-only account (user/password, internal vs domain) and that the SIEM can reach it over HTTPS. Pin the KSC certificate (fingerprint) rather than disabling verification.',
  'ksc-unprotected': 'Open each listed host in the KSC console (Managed devices) and restart / repair Kaspersky real-time protection; investigate why protection is stopped or suspended before clearing it.',
  'ksc-outdated': 'Update the anti-virus databases on the listed hosts (KSC → the database-update task) and check their Network Agent connectivity; out-of-date databases miss new threats.',
  'ksc-infected': 'Treat as an endpoint incident: isolate and investigate the listed hosts in KSC (detections / active threats), confirm remediation, and inform the SOC.',
  'ksc-critical-status': 'Open the hosts KSC marks Critical (Managed devices → status Critical) and clear the underlying reason (protection, databases, restart required, licence).',
};
const RISK = { 'ksc-unreachable': 'medium', 'ksc-unprotected': 'high', 'ksc-outdated': 'medium', 'ksc-infected': 'high', 'ksc-critical-status': 'medium' };

function createKsc({ state, config, log } = {}) {
  if (!state) throw new Error('ksc needs state');
  const col = state.collection('ksc_servers');
  const changes = createChanges({ state, log, collection: 'ksc_changes', prefix: 'KCHG', execution: 'manual — applied by a person in the Kaspersky Security Center console; the SIEM only reads' });
  const L = log || { info() {}, warn() {} };
  const secPath = (config && config._paths && config._paths.secrets) || null;
  const snaps = new Map();
  const pollMin = (config && config.ksc && config.ksc.poll_min) || 30;

  const secretsAll = () => (config && config.secrets && config.secrets.ksc && config.secrets.ksc.servers) || {};
  const secretOf = (id) => secretsAll()[id] || {};
  function err(code, msg) { return Object.assign(new Error(msg), { code, status: code, errors: [msg] }); }

  function view(s) { const sec = secretOf(s.id); return Object.assign({}, s, { credentials: { password: sec.password ? 'password set' + (sec.tls && sec.tls.insecure ? ' (TLS NOT verified)' : sec.tls && sec.tls.fingerprint256 ? ' (certificate pinned)' : '') : null } }); }
  function validate(input, ex) {
    const s = Object.assign({}, ex || {});
    if (!ex) { s.id = clean(input.id, 40).toLowerCase(); if (!ID_RE.test(s.id)) throw err(400, 'server id: 2-40 lowercase letters, digits and dashes'); }
    if (input.label !== undefined || !ex) s.label = clean(input.label || s.id, 80);
    if (input.site !== undefined || !ex) s.site = clean(input.site || 'Unassigned', 60);
    if (input.enabled !== undefined || !ex) s.enabled = input.enabled !== false;
    if (input.host !== undefined || !ex) { s.host = clean(input.host, 253); if (!s.host) throw err(400, 'KSC host required'); }
    if (input.port !== undefined || !ex) { const p = Number(input.port || 13299); s.port = Number.isInteger(p) && p > 0 && p < 65536 ? p : 13299; }
    if (input.user !== undefined || !ex) { s.user = clean(input.user, 120); if (!s.user) throw err(400, 'KSC read-only user required'); }
    if (input.internal !== undefined || !ex) s.internal = input.internal !== false;   // internal KSC user vs domain account
    if (input.dbStaleDays !== undefined || !ex) { const d = Number(input.dbStaleDays || 3); s.dbStaleDays = d >= 1 && d <= 30 ? Math.round(d) : 3; }
    return s;
  }
  function cfgOf(s) { const sec = secretOf(s.id); return { host: s.host, port: s.port, user: s.user, pass: sec.password, internal: s.internal, tls: sec.tls || {}, dbStaleDays: s.dbStaleDays, maxHosts: (config && config.ksc && config.ksc.max_hosts) || 5000 }; }

  async function pollOne(id) {
    const s = col.get(id); if (!s) return null;
    const out = { at: Date.now(), data: null, errors: [] }; const sec = secretOf(id);
    if (s.enabled) { if (sec.password) { try { out.data = await ksc.snapshot(cfgOf(s)); } catch (e) { out.errors.push(e.message); } } else out.errors.push('password not set'); }
    snaps.set(id, out); return out;
  }
  async function pollAll() { for (const s of col.all()) if (s.enabled) { try { await pollOne(s.id); } catch (e) { L.warn('ksc poll failed', { id: s.id, err: e.message }); } } }

  function findings() {
    const servers = col.all(); if (!servers.length) return null;
    const now = Date.now(), out = [];
    for (const s of servers) {
      if (!s.enabled) continue;
      const snap = snaps.get(s.id), site = s.site || '', tgt = { type: 'kaspersky-ksc', id: s.id, name: s.label };
      const stale = !snap || (now - snap.at) > Math.max(pollMin, 2 * pollMin) * 60000 * 2;
      if (!snap || !snap.data || (snap.errors || []).length || stale) {
        const e0 = (snap && (snap.errors || [])[0]) || (stale ? 'no successful poll yet' : 'not read');
        out.push({ key: `${s.id}:ksc-unreachable`, severity: 'high', kind: 'ksc-unreachable', title: `${s.label}: Kaspersky Security Center not available`, site, evidence: [e0, 'last read ' + (snap ? new Date(snap.at).toISOString() : 'never')], recommendation: FIX['ksc-unreachable'], target: tgt });
        continue;
      }
      const d = snap.data, su = d.summary, names = (pred) => d.hosts.filter(pred).map((h) => h.host).slice(0, 8);
      if (su.unprotected > 0) out.push({ key: `${s.id}:ksc-unprotected`, severity: 'high', kind: 'ksc-unprotected', title: `${s.label}: ${su.unprotected} endpoint(s) without running protection`, site, evidence: [`${su.unprotected} of ${su.hosts} not protected`, 'e.g. ' + names((h) => !h.protection).join(', ')], recommendation: FIX['ksc-unprotected'], target: tgt });
      if (su.infected > 0) out.push({ key: `${s.id}:ksc-infected`, severity: 'critical', kind: 'ksc-infected', title: `${s.label}: ${su.infected} endpoint(s) with active threats`, site, evidence: [`${su.infected} host(s) report threats`, 'e.g. ' + names((h) => h.threats && h.threats > 0).join(', ')], recommendation: FIX['ksc-infected'], target: tgt });
      if (su.outdated > 0) out.push({ key: `${s.id}:ksc-outdated`, severity: 'medium', kind: 'ksc-outdated', title: `${s.label}: ${su.outdated} endpoint(s) with out-of-date databases`, site, evidence: [`databases older than ${su.dbStaleDays} day(s) on ${su.outdated} host(s)`, 'e.g. ' + names((h) => h.dbOutdated).join(', ')], recommendation: FIX['ksc-outdated'], target: tgt });
      if (su.critical > 0) out.push({ key: `${s.id}:ksc-critical-status`, severity: 'high', kind: 'ksc-critical-status', title: `${s.label}: ${su.critical} endpoint(s) in Critical status`, site, evidence: [`${su.critical} host(s) marked Critical by KSC`, 'e.g. ' + names((h) => h.status === 'critical').join(', ')], recommendation: FIX['ksc-critical-status'], target: tgt });
    }
    return out;
  }

  function investigate(it) {
    const snap = snaps.get(String(it.target.id)); const checks = [];
    if (snap && snap.data) { const su = snap.data.summary;
      checks.push({ name: 'Last poll', status: (snap.errors || []).length ? 'warn' : 'ok', detail: new Date(snap.at).toISOString() });
      checks.push({ name: 'Coverage', status: su.unprotected ? 'warn' : 'ok', detail: `${su.protected}/${su.hosts} protected` });
      checks.push({ name: 'Databases', status: su.outdated ? 'warn' : 'ok', detail: `${su.outdated} out of date (> ${su.dbStaleDays}d)` });
      checks.push({ name: 'Threats', status: su.infected ? 'fail' : 'ok', detail: `${su.infected} host(s) with active threats` });
    } else checks.push({ name: 'Poll', status: 'warn', detail: (snap && (snap.errors || [])[0]) || 'no successful poll yet' });
    return { summary: `${it.title}. ${it.recommendation || ''}`.trim(), checks, causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation || '' }] };
  }
  async function verify(it) {
    try { await pollOne(String(it.target.id)); } catch (e) { return { present: null, note: 'could not re-read KSC: ' + e.message }; }
    const f = findings(); if (!f) return { present: null, note: 'no KSC server configured' };
    const present = f.some((x) => x.key === it.key);
    return { present, note: present ? 'a fresh read of KSC still reports it' : 'a fresh read of KSC no longer reports it' };
  }
  function propose(it, { onChange } = {}) {
    const plan = changes.propose({ device: String(it.target.id), title: clean(it.title, 160), reason: clean((it.evidence || []).join(' | '), 2000),
      commands: [FIX[it.kind] || it.recommendation || 'Apply the recommended action in the Kaspersky Security Center console.'],
      prechecks: ['Confirm with the endpoint administrator', 'This is a change in the Kaspersky console — the SIEM applies nothing'],
      rollback: ['Not applicable — this restores protection/updates; no configuration is removed'], risk: RISK[it.kind] || 'low', source: 'ai', requested_by: 'duty:ksc' }, 'duty:ksc');
    if (onChange) onChange({ id: plan.id });
    return { note: 'recorded a change plan for a person to action in the Kaspersky console' };
  }
  const changeStatus = (cid) => { const c = changes.get(cid); return c ? { status: c.status, comment: c.comment } : null; };

  function overview() {
    const servers = col.all().map((s) => { const snap = snaps.get(s.id); return Object.assign(view(s), { last: snap ? { at: snap.at, errors: snap.errors, summary: snap.data ? snap.data.summary : null } : null }); });
    const f = findings();
    return { servers, findings: f || [], connected: f !== null, poll_min: pollMin, changes_pending: changes.list({ status: 'proposed' }).length };
  }

  function put(input, by) { const ex = input && input.id ? col.get(String(input.id).toLowerCase()) : null; const s = validate(input || {}, ex); s.updated = Date.now(); s.updated_by = by || ''; if (!ex) s.created = s.updated; col.put(s); return view(s); }
  function remove(id, by) { if (!col.get(id)) throw err(404, 'server not found'); col.remove(id); snaps.delete(id); if (secretsAll()[id]) setCredentials(id, null, by); return { removed: id }; }
  function tlsOf(c) { const tls = {}; if (c.fingerprint256) { const f = String(c.fingerprint256).replace(/[^0-9a-f]/gi, ''); if (f.length !== 64) throw err(400, 'certificate fingerprint must be a SHA-256 fingerprint'); tls.fingerprint256 = f; } if (c.insecure) tls.insecure = true; return tls; }
  function setCredentials(id, creds, by) {
    if (!secPath) throw err(500, 'secrets path unknown');
    if (creds && !col.get(id)) throw err(404, 'server not found');
    let sec = {}; try { sec = SF.read(secPath) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    sec.ksc = sec.ksc || {}; sec.ksc.servers = sec.ksc.servers || {};
    if (creds) { const cur = sec.ksc.servers[id] || {}, next = Object.assign({}, cur); if (creds.password) next.password = String(creds.password).slice(0, 256); next.tls = tlsOf(creds); sec.ksc.servers[id] = next; }
    else delete sec.ksc.servers[id];
    writeJsonAtomic(secPath, sec);
    if (config && config.secrets) { config.secrets.ksc = config.secrets.ksc || {}; config.secrets.ksc.servers = sec.ksc.servers; }
    L.info('ksc credentials changed', { id, by, set: creds ? 'password' : 'removed' });
    return view(col.get(id) || { id });
  }
  async function test(id, by) {
    const s = col.get(id); if (!s) throw err(404, 'server not found'); const sec = secretOf(id);
    if (!sec.password) return { ok: false, error: 'password not set' };
    try { const p = await ksc.probe(cfgOf(s)); L.info('ksc test', { id, by, hosts: p.hostsInKsc }); return { ok: true, hostsInKsc: p.hostsInKsc, fieldsReturned: p.fieldsReturned, fieldsMissing: p.fieldsMissing }; }
    catch (e) { return { ok: false, error: e.message }; }
  }

  let timer = null;
  function start() { if (timer) return; const run = guardJob('ksc.poll', () => pollAll()); const a = setTimeout(run, 25000); timer = setInterval(run, Math.max(5, pollMin) * 60000); if (a.unref) a.unref(); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }

  return { list: () => col.all().map(view), get: (id) => { const s = col.get(id); return s ? view(s) : null; }, put, remove, setCredentials, test,
    sync: pollOne, pollAll, findings, investigate, verify, propose, changeStatus, changes, overview, snapshot: (id) => snaps.get(id) || null, start, stop };
}

module.exports = { createKsc };
