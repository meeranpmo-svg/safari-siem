// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * the organisation SIEM — ATT&CK detection-coverage map (DEFENSIVE).
 *
 * Pure, side-effect-free computation: given the effective detection rules + which log-source classes are connected,
 * it reports a per-technique coverage status and rolls it up by ATT&CK tactic. It performs NO attacks and touches NO
 * endpoints — it only reads rule definitions and a set of connected source-class ids.
 *
 *   computeCoverage({ rules, connectedClasses, catalog?, now? }) → { tactics, techniques, summary, unmapped_rules, source_classes, generated_at }
 *   classesForRule(rule)            → [classId]      the log-source classes that feed a rule (explicit src_type, else pack)
 *   connectedClassesFrom(sources)   → Set(classId)   from onboarding source rows [{ type, state }]
 *   SOURCE_CLASSES                  → [{ id, title, types[] }]
 *
 * Status per technique (the catalog universe = techniques the rules reference + this module's bundled ATT&CK names):
 *   covered  — an ENABLED rule maps to it AND at least one feeding source class is connected
 *   partial  — an ENABLED rule maps to it but none of its feeding source classes are connected
 *   gap      — no enabled rule maps to it (only disabled rules, or no rule at all)
 * Rules with no MITRE mapping are counted as "unmapped" (listed with a suggestion; NEVER auto-edited).
 */
const fs = require('node:fs');
const path = require('node:path');

let CATALOG = null;
function loadCatalog() {
  if (!CATALOG) CATALOG = JSON.parse(fs.readFileSync(path.join(__dirname, 'attack-catalog.json'), 'utf8'));
  return CATALOG;
}

// ---- log-source class model ---------------------------------------------------------------------------------------
// A "class" is a family of log sources that feeds a group of rules. `types` are the engine src_type values (and a few
// aliases) that belong to the class. Zscaler and several gateways ride the shared `cef`/`leef` parsers, so a connected
// CEF/LEEF feed optimistically marks proxy/dlp/email-gateway/generic as connected (documented heuristic).
const SOURCE_CLASSES = [
  { id: 'windows', title: 'Windows / Active Directory hosts', types: ['windows'] },
  { id: 'identity', title: 'Active Directory identity sync', types: ['ad'] },
  { id: 'linux', title: 'Linux servers', types: ['linux'] },
  { id: 'email', title: 'Exchange / mailbox audit', types: ['exchange'] },
  { id: 'email-gateway', title: 'Email security gateway', types: ['libraesva', 'cef', 'leef'] },
  { id: 'm365', title: 'Microsoft 365 audit', types: ['m365'] },
  { id: 'firewall', title: 'Firewall / network', types: ['fortigate', 'paloalto', 'cisco-asa', 'cisco', 'netscaler', 'f5'] },
  { id: 'proxy', title: 'Secure web gateway / proxy', types: ['cef'] },
  { id: 'dlp', title: 'Data-loss prevention (DLP)', types: ['somansa', 'cef'] },
  { id: 'web', title: 'Web servers / portal', types: ['nginx', 'apache', 'web', 'webaccess', 'iis'] },
  { id: 'wan', title: 'SD-WAN / WAN optimisation', types: ['silverpeak'] },
  { id: 'virtualization', title: 'Virtualisation (ESXi / vCenter)', types: ['esxi'] },
  { id: 'infra', title: 'Infrastructure (compute / ADC)', types: ['cisco-ucs', 'f5', 'netscaler'] },
  { id: 'database', title: 'Database audit (Oracle / SQL)', types: ['oracle', 'mssql'] },
  { id: 'generic-cef', title: 'Generic CEF / LEEF feed', types: ['cef', 'leef', 'dlp-cef', 'edr-cef'] },
];
const TYPE_TO_CLASSES = (() => {
  const m = new Map();
  for (const c of SOURCE_CLASSES) for (const t of c.types) { if (!m.has(t)) m.set(t, []); m.get(t).push(c.id); }
  return m;
})();
const CLASS_IDS = new Set(SOURCE_CLASSES.map((c) => c.id));

// Fallback class(es) for a rule pack when a rule carries no explicit src_type condition.
const PACK_TO_CLASSES = {
  'auth.json': ['windows', 'linux', 'firewall', 'm365'],
  'windows.json': ['windows'],
  'scheduled.json': ['windows'],
  'identity.json': ['identity'],
  'linux.json': ['linux'],
  'exchange.json': ['email'],
  'email-security.json': ['email-gateway'],
  'intel-cloud.json': ['m365'],
  'network.json': ['firewall'],
  'web.json': ['web'],
  'somansa.json': ['dlp'],
  'zscaler.json': ['proxy'],
  'silverpeak.json': ['wan'],
  'oracle.json': ['database'],
  'oracle-perf.json': ['database'],
  'devices.json': [],
};

function pushUnique(arr, v) { if (v && arr.indexOf(v) < 0) arr.push(v); }

/** Deep-scan a rule match tree for explicit src_type eq/in values. */
function srcTypesOf(match, out) {
  if (!match || typeof match !== 'object') return out;
  if (Array.isArray(match)) { for (const m of match) srcTypesOf(m, out); return out; }
  if (match.field === 'src_type' && (match.op === 'eq' || match.op === 'in') && match.not !== true) {
    for (const v of [].concat(match.value)) pushUnique(out, String(v).toLowerCase());
  }
  for (const k of ['all', 'any', 'none']) if (Array.isArray(match[k])) srcTypesOf(match[k], out);
  return out;
}

/** The log-source classes that feed a rule. */
function classesForRule(rule) {
  const out = [];
  const types = [];
  srcTypesOf(rule.match, types);
  if (Array.isArray(rule.steps)) for (const s of rule.steps) srcTypesOf(s.match, types);
  for (const t of types) for (const cid of (TYPE_TO_CLASSES.get(t) || [])) pushUnique(out, cid);
  if (!out.length) {
    const pack = rule.pack_file || rule._pack || '';
    for (const cid of (PACK_TO_CLASSES[pack] || [])) pushUnique(out, cid);
  }
  return out;
}

/** Connected source classes from onboarding rows. A source "feeds" its class when it has reported (state receiving/silent). */
function connectedClassesFrom(sources, opts = {}) {
  const activeStates = opts.states || ['receiving', 'silent'];
  const set = new Set();
  for (const s of sources || []) {
    if (!s) continue;
    const type = String(s.type || '').toLowerCase();
    const state = s.state || (s.connected ? 'receiving' : 'waiting');
    if (activeStates.indexOf(state) < 0 && s.connected !== true) continue;
    for (const cid of (TYPE_TO_CLASSES.get(type) || [])) set.add(cid);
  }
  return set;
}

function mitreOf(rule) { return Array.isArray(rule.mitre) ? rule.mitre.filter((x) => typeof x === 'string' && x) : []; }

/**
 * computeCoverage — the whole map.
 *   rules             effective rule defs (built-ins + overrides + custom)
 *   connectedClasses  Set|Array of connected source-class ids
 *   catalog           optional ATT&CK catalog override (tests); defaults to attack-catalog.json
 */
function computeCoverage({ rules = [], connectedClasses = [], catalog = null, now = Date.now } = {}) {
  const cat = catalog || loadCatalog();
  const connected = connectedClasses instanceof Set ? connectedClasses : new Set(connectedClasses || []);
  const techMeta = cat.techniques || {};
  const tacticByKey = new Map((cat.tactics || []).map((t) => [t.key, t]));
  // ids MITRE revoked (v20: T1562 → T1685 …) and tactic keys it renamed (TA0005 defense-evasion → stealth) resolve to the
  // current ones, so a rule or an imported Sigma rule that still carries the old id counts under the current technique
  const revoked = cat.revoked || {}, aliases = cat.tactic_aliases || {};
  const curId = (id) => revoked[id] || id, curTactic = (k) => (k ? aliases[k] || k : k);

  // technique id → { rules:[], classes:Set, enabledRules:[], tacticHint }
  const tmap = new Map();
  const ensure = (id) => {
    if (!tmap.has(id)) tmap.set(id, { id, rules: [], classes: new Set(), enabled: 0, tacticHint: '' });
    return tmap.get(id);
  };

  const unmapped = [];
  let rulesTotal = 0;
  let rulesMapped = 0;

  for (const r of rules) {
    if (!r || !r.id) continue;
    if (r.type === 'scheduled') { /* scheduled rules still count for mapping below */ }
    rulesTotal++;
    const mitre = [...new Set(mitreOf(r).map(curId))];
    const enabled = r.enabled !== false;
    if (!mitre.length) {
      unmapped.push({ id: r.id, name: r.name || r.id, pack: r.pack_file || '', enabled, suggested_classes: classesForRule(r) });
      continue;
    }
    rulesMapped++;
    const classes = classesForRule(r);
    for (const id of mitre) {
      const t = ensure(id);
      t.rules.push({ id: r.id, name: r.name || r.id, enabled, severity: Number(r.severity) || 0, type: r.type || 'single', classes });
      for (const c of classes) t.classes.add(c);
      if (enabled) {
        t.enabled++;
        if (!t.tacticHint && r.tactic) t.tacticHint = curTactic(r.tactic);
      }
      if (!t.tacticHint && r.tactic) t.tacticHint = curTactic(r.tactic);
    }
  }

  // status per technique
  const techniques = [];
  for (const t of tmap.values()) {
    const meta = techMeta[t.id] || {};
    const tacticKey = t.tacticHint || meta.tactic || 'other';
    const enabledRules = t.rules.filter((r) => r.enabled);
    let status;
    if (!enabledRules.length) status = 'gap';
    else {
      const enabledClasses = new Set();
      for (const r of enabledRules) for (const c of r.classes) enabledClasses.add(c);
      let anyConnected = false;
      for (const c of enabledClasses) if (connected.has(c)) { anyConnected = true; break; }
      // a rule with no derivable source class is treated as source-agnostic → covered if it has an enabled rule
      if (!enabledClasses.size) anyConnected = true;
      status = anyConnected ? 'covered' : 'partial';
    }
    techniques.push({
      id: t.id,
      name: meta.name || t.id,
      parent: meta.parent || null,
      tactic: tacticKey,
      status,
      rules: t.rules,
      enabled_rules: enabledRules.length,
      sources: [...t.classes].sort(),
      connected_sources: [...t.classes].filter((c) => connected.has(c)).sort(),
    });
  }
  techniques.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // roll up by tactic (only tactics that carry techniques, in ATT&CK order)
  const byTactic = new Map();
  for (const tech of techniques) {
    if (!byTactic.has(tech.tactic)) byTactic.set(tech.tactic, []);
    byTactic.get(tech.tactic).push(tech);
  }
  const tactics = [];
  for (const [key, techs] of byTactic) {
    const meta = tacticByKey.get(key) || { key, name: key, order: 99, id: '' };
    const counts = { covered: 0, partial: 0, gap: 0 };
    for (const t of techs) counts[t.status]++;
    tactics.push({
      id: meta.id || '', key, name: meta.name || key, order: meta.order || 99,
      counts, total: techs.length, techniques: techs.map((t) => t.id),
    });
  }
  tactics.sort((a, b) => a.order - b.order || (a.key < b.key ? -1 : 1));

  const summary = { covered: 0, partial: 0, gap: 0 };
  for (const t of techniques) summary[t.status]++;
  const total = techniques.length;
  summary.total_techniques = total;
  summary.unmapped = unmapped.length;
  summary.rules_total = rulesTotal;
  summary.rules_mapped = rulesMapped;
  summary.rules_unmapped = unmapped.length;
  summary.pct = total ? Math.round((summary.covered * 100) / total) : 0;
  summary.detectable_pct = total ? Math.round(((summary.covered + summary.partial) * 100) / total) : 0;
  summary.connected_classes = [...connected].sort();

  return {
    tactics,
    techniques,
    summary,
    unmapped_rules: unmapped.sort((a, b) => (a.id < b.id ? -1 : 1)),
    source_classes: SOURCE_CLASSES.map((c) => ({ id: c.id, title: c.title, connected: connected.has(c.id) })),
    generated_at: new Date(now()).toISOString(),
  };
}

module.exports = {
  computeCoverage, classesForRule, connectedClassesFrom, srcTypesOf,
  SOURCE_CLASSES, TYPE_TO_CLASSES, PACK_TO_CLASSES, CLASS_IDS, loadCatalog,
};
