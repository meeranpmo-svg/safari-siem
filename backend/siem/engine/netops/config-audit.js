// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Configuration capture for the AI auditors (CIS Cisco IOS / ASA benchmark tests run in IT Asset Management, pyengine
 * infra_audit_rules.py). Once a day, for every Cisco IOS / ASA device that has an SSH login and a trusted host key, the
 * read-only CLI (cli.js: allow-listed show commands, secrets removed by redact()) reads "show running-config"; the latest
 * copy per device is kept in the state collection "netops_config_audit" with its SHA-256 and when it was read.
 * Nothing is changed on a device. A device that cannot be read keeps its previous copy and records the error, so the
 * auditor can say "configuration not read" instead of passing it.
 * The hash is taken over the configuration WITHOUT the lines that change by themselves (comments such as "! Last
 * configuration change at …", "ntp clock-period", the "Current configuration : N bytes" header), so a new hash means a
 * real change; the last 30 hashes are kept (history) for the auditors' unauthorised-change test.
 *
 *   createConfigAudit({ inventory, cli, state, log, now }) → { run(), list(), get(id) }
 */
const crypto = require('node:crypto');

const VENDORS = new Set(['cisco-ios', 'cisco-asa', 'h3c-comware']);
// the read-only command that shows the whole configuration, per vendor (Comware's read-only verb is "display")
const SHOW = { 'cisco-ios': 'show running-config', 'cisco-asa': 'show running-config', 'h3c-comware': 'display current-configuration' };
const DAY = 86400000, MAX_PER_RUN = 30, MAX_TEXT = 200000, MAX_HIST = 30;
const VOLATILE = /^\s*(?:!|#\s*$|ntp clock-period\b|Building configuration|Current configuration\s*:|: Saved|: Written by|Cryptochecksum:)/;
const normalise = (text) => String(text || '').split('\n').map((l) => l.replace(/\s+$/, '')).filter((l) => l && !VOLATILE.test(l)).join('\n');

function createConfigAudit({ inventory, cli, state, log, now = Date.now }) {
  const col = state.collection('netops_config_audit');
  const L = log || { info() {}, warn() {} };

  async function run(opt = {}) {
    const t = now(), out = { read: 0, failed: 0, skipped: 0 };
    for (const d of inventory.list()) {
      if (!VENDORS.has(d.vendor)) continue;
      if (out.read + out.failed >= MAX_PER_RUN) break;
      const prev = col.get(d.id);
      if (!opt.force && prev && prev.at && t - prev.at < DAY - 3600000) { out.skipped++; continue; }
      if (!cli.supported(d.vendor) || !inventory.credentialSummary(d.id).ssh || !cli.hostKey(d.id)) {
        col.put(Object.assign({}, prev || {}, { id: d.id, name: d.name, vendor: d.vendor, site: d.site || '', role: d.role || '', checked: t, error: 'no SSH login or trusted host key - configuration not read' }));
        out.skipped++; continue;
      }
      try {
        const r = await cli.run(d.id, [SHOW[d.vendor]], { by: 'system:it-auditor', via: 'audit' });
        const res = r.results[0] || {};
        if (res.error || !res.output) throw new Error(res.error || 'empty output');
        const text = String(res.output).slice(0, MAX_TEXT);
        const sha256 = crypto.createHash('sha256').update(normalise(text)).digest('hex');
        const history = ((prev && prev.history) || []).slice();
        const changed = !prev || !prev.sha256 || prev.sha256 !== sha256;
        if (changed) { history.push({ sha256, first_seen: t, previous_read: prev && prev.at ? prev.at : null }); while (history.length > MAX_HIST) history.shift(); }
        col.put({ id: d.id, name: d.name, vendor: d.vendor, site: d.site || '', role: d.role || '', at: t, checked: t, error: '',
          sha256, history, truncated: String(res.output).length > MAX_TEXT, text });
        out.read++;
      } catch (e) {
        col.put(Object.assign({}, prev || {}, { id: d.id, name: d.name, vendor: d.vendor, site: d.site || '', role: d.role || '', checked: t, error: String(e.message || e).slice(0, 300) }));
        out.failed++;
        L.warn('config audit: running-config not read', { device: d.id, err: String(e.message || e).slice(0, 200) });
      }
    }
    return out;
  }

  return { run, list: () => col.all(), get: (id) => col.get(id) || null };
}

module.exports = { createConfigAudit, normalise, VENDORS, SHOW };
