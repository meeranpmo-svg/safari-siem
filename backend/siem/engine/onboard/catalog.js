// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
// Connector catalogue for the self-service "Connect & Onboard" hub (engine/onboard/catalog.json).
//   loadCatalog()                       → the parsed catalogue (cached); throws when a connector entry is malformed
//   byKind(kind)                        → connector or null
//   placeholdersOf(text)                → ['token', 'siem_host', …] found in a template
//   render(text, vars)                  → template with every {{name}} replaced; unknown names throw (never leaks a raw
//                                          "{{token}}" into instructions handed to an admin)
//   instructionsFor(conn, vars)         → [{title:{en,ar}, lang, body}] rendered for one source
//   siteVars(config, extra)             → {siem_host, siem_ip, kit_url, syslog_port, tls_port} from config.onboard/syslog
// Token kinds (mode "token") get an ingest token; syslog kinds (mode "syslog") need a device IP; "cloud" is M365;
// "link" entries only point at another module's settings page (link.view) or at another connector (link.kind);
// "future" entries are listed but cannot be connected yet. Every connector has a category (catalog.categories[]),
// the SIEM source type/parser it registers (`type`), and parser_status "dedicated" | "generic" (closest parser used,
// `dedicated_parser` names the planned one).
const fs = require('node:fs');
const path = require('node:path');

const FILE = path.join(__dirname, 'catalog.json');
const PH_RE = /\{\{\s*([a-z_]+)\s*\}\}/g;
const MODES = new Set(['token', 'syslog', 'cloud', 'link', 'future']);
const PARSER_STATUS = new Set(['dedicated', 'generic']);
let cache = null;

function bi(v, where) {
  if (!v || typeof v !== 'object' || typeof v.en !== 'string' || typeof v.ar !== 'string' || !v.en.trim() || !v.ar.trim()) throw new Error(`catalog: ${where} needs {en, ar}`);
}

function validate(cat) {
  if (!cat || !Array.isArray(cat.connectors) || !cat.connectors.length) throw new Error('catalog: connectors[] missing');
  if (!Array.isArray(cat.placeholders)) throw new Error('catalog: placeholders[] missing');
  if (!Array.isArray(cat.categories) || !cat.categories.length) throw new Error('catalog: categories[] missing');
  cat.categories.forEach((c, i) => { if (!c || !/^[a-z]+$/.test(String(c.id || ''))) throw new Error(`catalog: categories[${i}].id invalid`); bi(c, `categories[${i}]`); });
  const cats = new Set(cat.categories.map((c) => c.id));
  const allowed = new Set(cat.placeholders);
  const kinds = new Set();
  for (const c of cat.connectors) {
    const w = `connector "${c && c.kind}"`;
    if (!c || !/^[a-z0-9-]{2,32}$/.test(String(c.kind || ''))) throw new Error('catalog: connector kind invalid');
    if (kinds.has(c.kind)) throw new Error(`catalog: duplicate kind ${c.kind}`);
    kinds.add(c.kind);
    if (!MODES.has(c.mode)) throw new Error(`catalog: ${w} mode must be one of ${[...MODES].join('|')}`);
    if (!cats.has(c.category)) throw new Error(`catalog: ${w} category unknown`);
    if (!PARSER_STATUS.has(c.parser_status)) throw new Error(`catalog: ${w} parser_status must be dedicated|generic`);
    if (c.mode !== 'link' && !/^[a-z0-9_-]{1,32}$/.test(String(c.type || ''))) throw new Error(`catalog: ${w} type missing`);
    if (c.dedicated_parser !== undefined && c.parser_status !== 'generic') throw new Error(`catalog: ${w} dedicated_parser only with parser_status generic`);
    bi(c.title, `${w}.title`); bi(c.gives, `${w}.gives`);
    for (const k of ['detects', 'prerequisites', 'steps']) {
      if (!Array.isArray(c[k])) throw new Error(`catalog: ${w}.${k} must be an array`);
      c[k].forEach((x, i) => bi(x, `${w}.${k}[${i}]`));
    }
    if (!Array.isArray(c.sama) || !c.sama.every((s) => /^3\.\d\.\d{1,2}$/.test(s))) throw new Error(`catalog: ${w}.sama must list SAMA control ids`);
    if (!c.network || typeof c.network.en !== 'string' || typeof c.network.ar !== 'string') throw new Error(`catalog: ${w}.network needs en/ar`);
    if (!Array.isArray(c.instructions)) throw new Error(`catalog: ${w}.instructions must be an array`);
    c.instructions.forEach((ins, i) => {
      bi(ins.title, `${w}.instructions[${i}].title`);
      if (typeof ins.body !== 'string' || !ins.body.trim()) throw new Error(`catalog: ${w}.instructions[${i}].body missing`);
      if (!/^[a-z]+$/.test(String(ins.lang || ''))) throw new Error(`catalog: ${w}.instructions[${i}].lang missing`);
    });
    for (const ph of placeholdersOfConnector(c)) if (!allowed.has(ph)) throw new Error(`catalog: ${w} uses unknown placeholder {{${ph}}}`);
    if (c.mode === 'token' && !c.instructions.some((i) => placeholdersOf(i.body).includes('token'))) throw new Error(`catalog: ${w} is a token connector but no instruction uses {{token}}`);
    if (c.mode === 'link' && !(c.link && (typeof c.link.view === 'string' || typeof c.link.kind === 'string'))) throw new Error(`catalog: ${w} is a link connector without link.view or link.kind`);
    if (c.mode === 'link' && c.link.kind && !cat.connectors.some((o) => o.kind === c.link.kind && o.mode !== 'link')) throw new Error(`catalog: ${w} links to unknown connector ${c.link.kind}`);
    if (c.mode !== 'link' && !/^[a-z0-9-]{2,12}$/.test(String(c.id_prefix || ''))) throw new Error(`catalog: ${w}.id_prefix missing`);
  }
  return cat;
}

function loadCatalog(force) {
  if (cache && !force) return cache;
  cache = validate(JSON.parse(fs.readFileSync(FILE, 'utf8')));
  return cache;
}

function byKind(kind) { return loadCatalog().connectors.find((c) => c.kind === kind) || null; }

function placeholdersOf(text) {
  const out = [];
  let m;
  PH_RE.lastIndex = 0;
  while ((m = PH_RE.exec(String(text || '')))) if (!out.includes(m[1])) out.push(m[1]);
  return out;
}

function walkStrings(v, fn) {
  if (typeof v === 'string') return fn(v);
  if (Array.isArray(v)) return v.forEach((x) => walkStrings(x, fn));
  if (v && typeof v === 'object') return Object.values(v).forEach((x) => walkStrings(x, fn));
  return undefined;
}

function placeholdersOfConnector(c) {
  const set = new Set();
  walkStrings(c, (s) => placeholdersOf(s).forEach((p) => set.add(p)));
  return [...set];
}

function render(text, vars) {
  return String(text || '').replace(PH_RE, (m, name) => {
    if (vars && Object.prototype.hasOwnProperty.call(vars, name) && vars[name] !== undefined && vars[name] !== null) return String(vars[name]);
    throw new Error(`template placeholder {{${name}}} has no value`);
  });
}

function instructionsFor(conn, vars) {
  return (conn.instructions || []).map((i) => ({ title: i.title, lang: i.lang, body: render(i.body, vars) }));
}

// Renders every bilingual text of a connector (network note, steps…) for display; token/device placeholders are left to
// the caller (they are per source) and replaced by a readable marker when absent.
function describe(conn, vars) {
  const v = Object.assign({ token: '<token>', device_ip: '<device-ip>', source_id: conn.id_prefix ? conn.id_prefix + '<name>' : '<source-id>' }, vars || {});
  const r = (x) => (typeof x === 'string' ? render(x, v) : x && typeof x === 'object' ? { en: render(x.en, v), ar: render(x.ar, v) } : x);
  return Object.assign({}, conn, {
    network: Object.assign({}, conn.network, { en: r(conn.network.en), ar: r(conn.network.ar), from: r(conn.network.from), to: r(conn.network.to) }),
    prerequisites: conn.prerequisites.map(r), steps: conn.steps.map(r), gives: r(conn.gives),
    instructions: conn.instructions.map((i) => ({ title: i.title, lang: i.lang, body: render(i.body, v) })),
  });
}

function siteVars(config, extra) {
  const ob = (config && config.onboard) || {};
  const sl = (config && config.syslog) || {};
  const host = ob.siem_host || ZYB_ORG.portal_host;
  return Object.assign({
    siem_host: host,
    siem_ip: ob.siem_ip || (sl.host && sl.host !== '0.0.0.0' && sl.host !== '127.0.0.1' && sl.host !== '::' ? sl.host : ZYB_ORG.platform_addr),
    kit_url: 'https://' + host + (ob.kit_base || '/agent'),
    syslog_port: (sl.tcp && sl.tcp.port) || 5514,
    tls_port: (sl.tls && sl.tls.port) || 6514,
  }, extra || {});
}

module.exports = { loadCatalog, byKind, placeholdersOf, placeholdersOfConnector, render, instructionsFor, describe, siteVars, FILE };
