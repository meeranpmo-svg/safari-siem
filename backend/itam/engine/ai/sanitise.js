// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Sanitisation applied to the system prompt and the prompt before EVERY model call. Asset data can carry PII (last
// user, owner) and network detail; this strips the obvious identifiers before anything leaves for the model.
// Mirrors sentra-grcai/engine/ai/sanitise.js. Order matters: long numeric patterns first.
//   e-mail                                → [email]
//   IBAN SA + 22 digits                    → [iban]
//   13-19 digit card-like numbers          → [card]
//   KSA mobile                             → [phone]
//   10-digit IDs (national/iqama)          → [id]
//   IPv4 host octet                        → 10.1.2.•   (keeps subnet shape, hides the host)
//   admin redaction terms (whole words)    → [redacted]
const crypto = require('node:crypto');

const RULES = [
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g, '[email]'],
  [/\bSA\d{2}(?: ?\d{4}){5}\b/gi, '[iban]'],
  [/\b\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?\b/g, '[card]'],
  [/\b\d{13,19}\b/g, '[card]'],
  [/(?:\+966|\b00966|\b966|\b0)[ -]?5\d(?:[ -]?\d){7}\b/g, '[phone]'],
  [/\b\d{10}\b/g, '[id]'],
  [/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, '$1.$2.$3.•'],
];

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function termsRegex(terms) {
  const list = (Array.isArray(terms) ? terms : [])
    .map((t) => String(t || '').trim()).filter((t) => t.length >= 2 && t.length <= 100)
    .sort((a, b) => b.length - a.length);
  if (!list.length) return null;
  return new RegExp(`(?<![\\p{L}\\p{N}_])(?:${list.map(escapeRe).join('|')})(?![\\p{L}\\p{N}_])`, 'giu');
}

function sanitise(text, opts = {}) {
  let s = String(text == null ? '' : text);
  for (const [re, rep] of RULES) s = s.replace(re, rep);
  const tre = opts.termsRe || termsRegex(opts.redact_terms);
  if (tre) s = s.replace(tre, '[redacted]');
  return s;
}

function sanitisePair(system, prompt, redactTerms) {
  const termsRe = termsRegex(redactTerms);
  const ss = sanitise(system, { termsRe });
  const sp = sanitise(prompt, { termsRe });
  const h = (x) => crypto.createHash('sha256').update(x).digest('hex');
  return { system: ss, prompt: sp, system_sha256: h(ss), prompt_sha256: h(sp) };
}

module.exports = { sanitise, sanitisePair, termsRegex };
