// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * AI engineer data source for Zscaler (ZIA + ZPA), read-only. Mirrors the netops module: a connection inventory
 * (state collection "zscaler_tenants"; secrets in secrets.json "zscaler.tenants.<id>", write-only), a poll loop that
 * reads posture over the vendor API, rule-based findings, read-only investigation, verification by a fresh poll, and a
 * four-eyes change-plan workflow (createChanges, collection "zscaler_changes"). Nothing here changes Zscaler: an
 * approved change plan is applied by a person in the Zscaler admin console and then verified by re-reading the API.
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const { writeJsonAtomic } = require('../onboard/store');
const { createChanges } = require('../netops/changes');
const zia = require('./zia');
const zpa = require('./zpa');

const ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const clean = (s, max) => String(s == null ? '' : s).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, max);

const FIX = {
  'zia-unreachable': 'Check the ZIA API credentials (API key, admin login, API access enabled) and that the SIEM can reach the ZIA cloud over HTTPS. Zscaler → Administration → API Key Management.',
  'zia-fw-nolog': 'In the ZIA admin console (Policy → Firewall Control) enable logging on the rule so the Cloud Firewall decision is recorded and reaches the SIEM. An ALLOW rule with logging off is a blind spot.',
  'zia-location-unprotected': 'In ZIA (Administration → Locations) enable the Firewall and IPS Control for the location so its traffic is inspected and logged.',
  'zia-url-disabled': 'Review the disabled URL-filtering rule in ZIA (Policy → URL & Cloud App Control): re-enable it if it should be active, or record why it is off.',
  'zpa-unreachable': 'Check the ZPA API client (client id and secret, and the customer id) and that the SIEM can reach the ZPA config cloud over HTTPS. ZPA → Configuration → API Clients.',
  'zpa-connector-down': 'Check the App Connector: power/network at its site, its service, and the control channel to Zscaler (ZPA → Infrastructure → App Connectors). Apps behind it are unreachable while it is down.',
  'zpa-segment-disabled': 'Review the disabled application segment in ZPA (Configuration → Application Segments): re-enable it if users should reach it, or record why it is off.',
  'zpa-rule-disabled': 'Review the disabled access policy rule in ZPA (Configuration → Access Policy): a disabled rule is not enforced.',
};
const RISK = { 'zia-unreachable': 'medium', 'zia-fw-nolog': 'low', 'zia-location-unprotected': 'medium', 'zia-url-disabled': 'low', 'zpa-unreachable': 'medium', 'zpa-connector-down': 'high', 'zpa-segment-disabled': 'low', 'zpa-rule-disabled': 'low' };

function createZscaler({ state, config, log } = {}) {
  if (!state) throw new Error('zscaler needs state');
  const col = state.collection('zscaler_tenants');
  const changes = createChanges({ state, log, collection: 'zscaler_changes', prefix: 'ZCHG', execution: 'manual — applied by a person in the Zscaler admin console; the SIEM only reads' });
  const L = log || { info() {}, warn() {} };
  const secPath = (config && config._paths && config._paths.secrets) || null;
  const snaps = new Map();               // id → { at, zia, zpa, errors:[] }
  const pollMin = (config && config.zscaler && config.zscaler.poll_min) || 30;

  function secretsAll() { return (config && config.secrets && config.secrets.zscaler && config.secrets.zscaler.tenants) || {}; }
  function secretOf(id) { return secretsAll()[id] || {}; }

  function view(t) {
    const s = secretOf(t.id);
    return Object.assign({}, t, { credentials: {
      zia: s.zia && s.zia.apiKey ? 'API key + admin login set' + (s.zia.tls && s.zia.tls.insecure ? ' (TLS NOT verified)' : '') : null,
      zpa: s.zpa && s.zpa.clientSecret ? 'client secret set' : null,
    } });
  }
  function validate(input, ex) {
    const t = Object.assign({}, ex || {});
    if (!ex) { t.id = clean(input.id, 40).toLowerCase(); if (!ID_RE.test(t.id)) throw err(400, 'tenant id: 2-40 lowercase letters, digits and dashes'); }
    if (input.label !== undefined || !ex) t.label = clean(input.label || t.id, 80);
    if (input.site !== undefined || !ex) t.site = clean(input.site || 'Unassigned', 60);
    if (input.enabled !== undefined || !ex) t.enabled = input.enabled !== false;
    const zi = input.zia || (ex && ex.zia) || {};
    t.zia = { enabled: zi.enabled !== false, cloud: clean(zi.cloud, 120).replace(/^https?:\/\//, ''), username: clean(zi.username, 120) };
    const zp = input.zpa || (ex && ex.zpa) || {};
    t.zpa = { enabled: !!zp.enabled, base_url: clean(zp.base_url || 'https://config.private.zscaler.com', 200), customerId: clean(zp.customerId, 40), clientId: clean(zp.clientId, 120) };
    if (t.zia.enabled && !t.zia.cloud) throw err(400, 'ZIA cloud host required (e.g. zsapi.zscalertwo.net) — or disable ZIA for this tenant');
    return t;
  }
  function err(code, msg) { return Object.assign(new Error(msg), { code, status: code, errors: [msg] }); }

  function ziaCfg(t) { const s = secretOf(t.id).zia || {}; return { cloud: t.zia.cloud, username: t.zia.username, apiKey: s.apiKey, password: s.password, tls: s.tls || {} }; }
  function zpaCfg(t) { const s = secretOf(t.id).zpa || {}; return { base_url: t.zpa.base_url, customerId: t.zpa.customerId, clientId: t.zpa.clientId, clientSecret: s.clientSecret, tls: s.tls || {} }; }

  async function pollOne(id) {
    const t = col.get(id); if (!t) return null;
    const out = { at: Date.now(), zia: null, zpa: null, errors: [] };
    const sec = secretOf(id);
    if (t.enabled && t.zia && t.zia.enabled) {
      if (sec.zia && sec.zia.apiKey) { try { out.zia = await zia.snapshot(ziaCfg(t)); } catch (e) { out.errors.push('ZIA: ' + e.message); } }
      else out.errors.push('ZIA: credentials not set');
    }
    if (t.enabled && t.zpa && t.zpa.enabled) {
      if (sec.zpa && sec.zpa.clientSecret) { try { out.zpa = await zpa.snapshot(zpaCfg(t)); } catch (e) { out.errors.push('ZPA: ' + e.message); } }
      else out.errors.push('ZPA: credentials not set');
    }
    snaps.set(id, out); return out;
  }
  async function pollAll() { for (const t of col.all()) { if (t.enabled) { try { await pollOne(t.id); } catch (e) { L.warn('zscaler poll failed', { id: t.id, err: e.message }); } } } }

  // rule-based findings in the duty shape; null = nothing configured (not connected)
  function findings() {
    const tenants = col.all(); if (!tenants.length) return null;
    const now = Date.now(), out = [];
    for (const t of tenants) {
      if (!t.enabled) continue;
      const snap = snaps.get(t.id), site = t.site || '';
      const tgt = (type, id, name) => ({ type, id: t.id + ':' + id, name });
      const stale = !snap || (now - snap.at) > Math.max(pollMin, 2 * pollMin) * 60000 * 2;
      // ZIA
      if (t.zia && t.zia.enabled) {
        const z = snap && snap.zia;
        if (!z || (snap && snap.errors || []).some((e) => /^ZIA/.test(e)) || stale) {
          const e0 = (snap && (snap.errors || []).find((e) => /^ZIA/.test(e))) || (stale ? 'no successful poll yet' : 'not read');
          out.push({ key: `${t.id}:zia-unreachable`, severity: 'high', kind: 'zia-unreachable', title: `${t.label} ZIA: posture not available`, site,
            evidence: [e0, 'last read ' + (snap ? new Date(snap.at).toISOString() : 'never')], recommendation: FIX['zia-unreachable'], target: tgt('zscaler-zia', 'zia', t.label + ' (ZIA)') });
        } else {
          for (const r of (z.fwNoLog || []).slice(0, 50)) out.push({ key: `${t.id}:zia-fw-nolog:${r.id}`, severity: 'medium', kind: 'zia-fw-nolog', title: `${t.label} ZIA: Cloud Firewall rule "${r.name}" allows traffic without logging`, site, evidence: ['rule ' + r.name + ' (id ' + r.id + ')', 'action ALLOW, logging off'], recommendation: FIX['zia-fw-nolog'], target: tgt('zscaler-zia', 'fw:' + r.id, r.name) });
          for (const l of (z.locUnprotected || []).slice(0, 50)) out.push({ key: `${t.id}:zia-location-unprotected:${l.id}`, severity: 'medium', kind: 'zia-location-unprotected', title: `${t.label} ZIA: location "${l.name}" without full enforcement`, site, evidence: ['firewall ' + (l.ofw ? 'on' : 'OFF') + ', IPS ' + (l.ips ? 'on' : 'OFF')], recommendation: FIX['zia-location-unprotected'], target: tgt('zscaler-zia', 'loc:' + l.id, l.name) });
          for (const r of (z.urlDisabled || []).slice(0, 50)) out.push({ key: `${t.id}:zia-url-disabled:${r.id}`, severity: 'low', kind: 'zia-url-disabled', title: `${t.label} ZIA: URL-filtering rule "${r.name}" is disabled`, site, evidence: ['rule ' + r.name + ' disabled'], recommendation: FIX['zia-url-disabled'], target: tgt('zscaler-zia', 'url:' + r.id, r.name) });
        }
      }
      // ZPA
      if (t.zpa && t.zpa.enabled) {
        const z = snap && snap.zpa;
        if (!z || (snap && (snap.errors || []).some((e) => /^ZPA/.test(e))) || stale) {
          const e0 = (snap && (snap.errors || []).find((e) => /^ZPA/.test(e))) || (stale ? 'no successful poll yet' : 'not read');
          out.push({ key: `${t.id}:zpa-unreachable`, severity: 'high', kind: 'zpa-unreachable', title: `${t.label} ZPA: posture not available`, site, evidence: [e0], recommendation: FIX['zpa-unreachable'], target: tgt('zscaler-zpa', 'zpa', t.label + ' (ZPA)') });
        } else {
          for (const c of (z.connectorsDown || []).slice(0, 50)) out.push({ key: `${t.id}:zpa-connector-down:${c.id}`, severity: 'high', kind: 'zpa-connector-down', title: `${t.label} ZPA: App Connector "${c.name}" not connected`, site, evidence: ['control channel ' + (c.status || 'not connected')], recommendation: FIX['zpa-connector-down'], target: tgt('zscaler-zpa', 'conn:' + c.id, c.name) });
          for (const s of (z.disabledSegments || []).slice(0, 50)) out.push({ key: `${t.id}:zpa-segment-disabled:${s.id}`, severity: 'low', kind: 'zpa-segment-disabled', title: `${t.label} ZPA: application segment "${s.name}" is disabled`, site, evidence: ['segment disabled'], recommendation: FIX['zpa-segment-disabled'], target: tgt('zscaler-zpa', 'seg:' + s.id, s.name) });
          for (const r of (z.disabledRules || []).slice(0, 50)) out.push({ key: `${t.id}:zpa-rule-disabled:${r.id}`, severity: 'low', kind: 'zpa-rule-disabled', title: `${t.label} ZPA: access policy rule "${r.name}" is disabled`, site, evidence: ['rule disabled'], recommendation: FIX['zpa-rule-disabled'], target: tgt('zscaler-zpa', 'rule:' + r.id, r.name) });
        }
      }
    }
    return out;
  }

  function investigate(it) {
    const [id] = String(it.target.id).split(':'); const t = col.get(id), snap = snaps.get(id);
    const checks = [];
    if (snap) { checks.push({ name: 'Last poll', status: (snap.errors || []).length ? 'warn' : 'ok', detail: new Date(snap.at).toISOString() + ((snap.errors || []).length ? ' · ' + snap.errors.join('; ') : '') });
      if (snap.zia) checks.push({ name: 'ZIA', status: 'ok', detail: `${snap.zia.counts.locations} locations, ${snap.zia.counts.fwRules} firewall rules, ${snap.zia.counts.urlRules} URL rules` });
      if (snap.zpa) checks.push({ name: 'ZPA', status: 'ok', detail: `${snap.zpa.counts.segments} segments, ${snap.zpa.counts.connectors} connectors, ${snap.zpa.counts.access} access rules` });
    } else checks.push({ name: 'Poll', status: 'warn', detail: 'no successful poll yet' });
    return { summary: `${it.title}. ${it.recommendation || ''}`.trim(), checks, causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation || '' }] };
  }

  async function verify(it) {
    const [id] = String(it.target.id).split(':');
    try { await pollOne(id); } catch (e) { return { present: null, note: 'could not re-read Zscaler: ' + e.message }; }
    const f = findings(); if (!f) return { present: null, note: 'no tenant configured' };
    const present = f.some((x) => x.key === it.key);
    return { present, note: present ? 'a fresh read of Zscaler still reports it' : 'a fresh read of Zscaler no longer reports it' };
  }

  function propose(it, { onChange } = {}) {
    const steps = [FIX[it.kind] || it.recommendation || 'Apply the recommended change in the Zscaler admin console.'];
    const plan = changes.propose({ device: String(it.target.id).split(':')[0], title: clean(it.title, 160), reason: clean((it.evidence || []).join(' | '), 2000),
      commands: steps, prechecks: ['Confirm the change with the Zscaler administrator and the service owner', 'This is a configuration change in the Zscaler console — the SIEM applies nothing'],
      rollback: ['Revert the setting to its previous value in the Zscaler console'], risk: RISK[it.kind] || 'low', source: 'ai', requested_by: 'duty:zscaler' }, 'duty:zscaler');
    if (onChange) onChange({ id: plan.id });
    return { note: 'recorded a change plan for a person to apply in the Zscaler console' };
  }
  const changeStatus = (cid) => { const c = changes.get(cid); return c ? { status: c.status, comment: c.comment } : null; };

  function overview() {
    const tenants = col.all().map((t) => { const s = snaps.get(t.id); return Object.assign(view(t), { last: s ? { at: s.at, errors: s.errors, zia: s.zia ? s.zia.counts : null, zpa: s.zpa ? s.zpa.counts : null } : null }); });
    const f = findings();
    return { tenants, findings: f || [], connected: f !== null, poll_min: pollMin, changes_pending: changes.list({ status: 'proposed' }).length };
  }

  // ---- CRUD
  function put(input, by) { const ex = input && input.id ? col.get(String(input.id).toLowerCase()) : null; const t = validate(input || {}, ex); t.updated = Date.now(); t.updated_by = by || ''; if (!ex) t.created = t.updated; col.put(t); return view(t); }
  function remove(id, by) { if (!col.get(id)) throw err(404, 'tenant not found'); col.remove(id); snaps.delete(id); if (secretsAll()[id]) setCredentials(id, null, by); return { removed: id }; }
  function setCredentials(id, creds, by) {
    if (!secPath) throw err(500, 'secrets path unknown');
    if (creds && !col.get(id)) throw err(404, 'tenant not found');
    let sec = {}; try { sec = SF.read(secPath) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    sec.zscaler = sec.zscaler || {}; sec.zscaler.tenants = sec.zscaler.tenants || {};
    if (creds) {
      const cur = sec.zscaler.tenants[id] || {}, next = { zia: Object.assign({}, cur.zia), zpa: Object.assign({}, cur.zpa) };
      if (creds.zia) { const z = creds.zia; if (z.apiKey) next.zia.apiKey = String(z.apiKey).slice(0, 256); if (z.password) next.zia.password = String(z.password).slice(0, 256); next.zia.tls = tlsOf(z); }
      if (creds.zpa) { const z = creds.zpa; if (z.clientSecret) next.zpa.clientSecret = String(z.clientSecret).slice(0, 512); next.zpa.tls = tlsOf(z); }
      sec.zscaler.tenants[id] = next;
    } else delete sec.zscaler.tenants[id];
    writeJsonAtomic(secPath, sec);
    if (config && config.secrets) { config.secrets.zscaler = config.secrets.zscaler || {}; config.secrets.zscaler.tenants = sec.zscaler.tenants; }
    L.info('zscaler credentials changed', { id, by, set: creds ? Object.keys(creds) : 'removed' });
    return view(col.get(id) || { id });
  }
  function tlsOf(c) { const tls = {}; if (c.fingerprint256) { const f = String(c.fingerprint256).replace(/[^0-9a-f]/gi, ''); if (f.length !== 64) throw err(400, 'certificate fingerprint must be a SHA-256 fingerprint'); tls.fingerprint256 = f; } if (c.insecure) tls.insecure = true; return tls; }
  async function test(id, by) {
    const t = col.get(id); if (!t) throw err(404, 'tenant not found');
    const r = { zia: null, zpa: null }; const sec = secretOf(id);
    if (t.zia && t.zia.enabled) { if (sec.zia && sec.zia.apiKey) { try { const s = await zia.snapshot(ziaCfg(t)); r.zia = { ok: true, counts: s.counts }; } catch (e) { r.zia = { ok: false, error: e.message }; } } else r.zia = { ok: false, error: 'credentials not set' }; }
    if (t.zpa && t.zpa.enabled) { if (sec.zpa && sec.zpa.clientSecret) { try { const s = await zpa.snapshot(zpaCfg(t)); r.zpa = { ok: true, counts: s.counts }; } catch (e) { r.zpa = { ok: false, error: e.message }; } } else r.zpa = { ok: false, error: 'credentials not set' }; }
    L.info('zscaler test', { id, by, zia: r.zia && r.zia.ok, zpa: r.zpa && r.zpa.ok });
    return r;
  }

  let timer = null;
  function start() { if (timer) return; const run = guardJob('zscaler.poll', () => pollAll()); const a = setTimeout(run, 20000); timer = setInterval(run, Math.max(5, pollMin) * 60000); if (a.unref) a.unref(); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }

  return { list: () => col.all().map(view), get: (id) => { const t = col.get(id); return t ? view(t) : null; }, put, remove, setCredentials, test,
    sync: pollOne, pollAll, findings, investigate, verify, propose, changeStatus, changes, overview, snapshot: (id) => snaps.get(id) || null, start, stop };
}

module.exports = { createZscaler };
