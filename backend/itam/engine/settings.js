// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Admin settings (collection "settings", single document) + write-only connector credentials (collection
// "credentials", never serialised to any client). Every change is audited per key.
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });

const DEFAULTS = {
  sources: { sensor: true, agent: true, vcenter: false, netops: false },  // which ingest sources are active
  redact_terms: [],                        // extra redaction terms for the AI sanitiser
  external_ai_allowed: false,              // allow the staging Claude provider (sanitised content leaves the platform)
  not_seen_days: 30,                       // "not seen" anomaly threshold
  expiry_window_days: 90,                  // warranty / EOL "expiring soon" window
  auto_adopt: false,                       // auto-create asset records for newly discovered devices (else: unmatched)
};

const CRED_NAMES = ['vcenter_user', 'vcenter_pass', 'netops_token', 'private_token'];

// sealer: engine/discovery/vault.js createSealer() — AES-256-GCM under the discovery vault master key. Credentials are
// stored as {enc} only; legacy plaintext {value} records are re-sealed on load and the journal compacted.
function createSettings({ store, audit, config, sealer, log }) {
  const col = store.collection('settings');
  const creds = store.collection('credentials');
  if (!sealer) {
    const { createSealer } = require('./discovery/vault');
    const dc = (config && config.discovery) || {};
    sealer = createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-settings-credentials' });
  }
  (function migrate() {
    const legacy = creds.all((r) => typeof r.value === 'string');
    if (!legacy.length) return;
    if (!sealer.available()) { if (log) log.warn('settings: plaintext connector credentials found but the vault key is unavailable — not migrated', { reason: sealer.unavailableReason() }); return; }
    for (const r of legacy) { const { value, ...rest } = r; creds.put(Object.assign(rest, { enc: sealer.seal(r.id, value), len: value.length })); }
    store.snapshot(); // compaction drops the old plaintext journal lines
    if (audit) audit({ by: 'system', role: 'system', action: 'settings.credential.migrate', target: 'credentials', detail: { sealed: legacy.map((r) => r.id) } });
  })();
  const cfgD = {
    not_seen_days: (config && config.not_seen_days) || DEFAULTS.not_seen_days,
    expiry_window_days: (config && config.expiry_window_days) || DEFAULTS.expiry_window_days,
  };

  function get() {
    const s = col.get('settings') || {};
    return {
      sources: Object.assign({}, DEFAULTS.sources, s.sources || {}),
      redact_terms: Array.isArray(s.redact_terms) ? s.redact_terms : [],
      external_ai_allowed: s.external_ai_allowed === true,
      not_seen_days: Number.isInteger(s.not_seen_days) ? s.not_seen_days : cfgD.not_seen_days,
      expiry_window_days: Number.isInteger(s.expiry_window_days) ? s.expiry_window_days : cfgD.expiry_window_days,
      auto_adopt: s.auto_adopt === true,
      updated_by: s.updated_by || null, updated_at: s.updated_at || null,
    };
  }

  function update(body, who) {
    const cur = get();
    const next = JSON.parse(JSON.stringify(cur));
    const b = body || {};
    if (b.sources !== undefined) {
      if (!b.sources || typeof b.sources !== 'object' || Array.isArray(b.sources)) throw bad('sources must be an object');
      for (const [k, v] of Object.entries(b.sources)) {
        if (!(k in DEFAULTS.sources)) throw bad(`unknown source ${k}`);
        if (typeof v !== 'boolean') throw bad(`sources.${k} must be true or false`);
        next.sources[k] = v;
      }
    }
    if (b.redact_terms !== undefined) {
      if (!Array.isArray(b.redact_terms) || b.redact_terms.length > 200) throw bad('redact_terms must be an array (max 200)');
      const terms = [];
      for (const t of b.redact_terms) {
        const s = String(t == null ? '' : t).trim();
        if (!s) continue;
        if (s.length < 2 || s.length > 100) throw bad('each redaction term must be 2-100 characters');
        if (!terms.some((x) => x.toLowerCase() === s.toLowerCase())) terms.push(s);
      }
      next.redact_terms = terms;
    }
    if (b.external_ai_allowed !== undefined) { if (typeof b.external_ai_allowed !== 'boolean') throw bad('external_ai_allowed must be true or false'); next.external_ai_allowed = b.external_ai_allowed; }
    if (b.auto_adopt !== undefined) { if (typeof b.auto_adopt !== 'boolean') throw bad('auto_adopt must be true or false'); next.auto_adopt = b.auto_adopt; }
    for (const k of ['not_seen_days', 'expiry_window_days']) {
      if (b[k] !== undefined) { const n = Number(b[k]); if (!Number.isInteger(n) || n < 1 || n > 3650) throw bad(`${k} must be an integer 1-3650`); next[k] = n; }
    }
    const changed = {};
    for (const k of Object.keys(DEFAULTS)) if (JSON.stringify(cur[k]) !== JSON.stringify(next[k])) changed[k] = { from: k === 'redact_terms' ? `${cur[k].length} terms` : cur[k], to: k === 'redact_terms' ? `${next[k].length} terms` : next[k] };
    if (!Object.keys(changed).length) return get();
    next.updated_by = who.user; next.updated_at = new Date().toISOString();
    col.put(Object.assign({ id: 'settings' }, next));
    for (const [k, v] of Object.entries(changed)) audit({ by: who.user, role: who.role, action: `settings.${k}`, target: 'settings', detail: v });
    return get();
  }

  // write-only credentials: stored, never returned. status() exposes only whether each is configured.
  function setCredential(name, value, who) {
    if (!CRED_NAMES.includes(name)) throw bad(`unknown credential ${name}`);
    const v = String(value == null ? '' : value);
    if (v) creds.put({ id: name, set_at: new Date().toISOString(), by: who && who.user, len: v.length, enc: sealer.seal(name, v) }); // sealed, never plaintext
    else creds.remove(name);
    audit({ by: who && who.user, role: who && who.role, action: 'settings.credential', target: name, detail: { set: !!v } }); // value never audited
  }
  function getCredential(name) {
    const r = creds.get(name);
    if (!r) return '';
    if (r.enc) return sealer.unseal(name, r.enc);
    return typeof r.value === 'string' ? r.value : ''; // legacy plaintext only when the vault key is unavailable (not migrated)
  }
  function credentialStatus() {
    const out = {};
    for (const name of CRED_NAMES) { const r = creds.get(name); out[name] = { configured: !!r, set_at: r ? r.set_at : null }; }
    return out;
  }

  return { get, update, setCredential, getCredential, credentialStatus, DEFAULTS };
}

module.exports = { createSettings, DEFAULTS };
