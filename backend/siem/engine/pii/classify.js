// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Personal-data classification of FILES (SharePoint / OneDrive in collect/m365-files.js; the Windows agent applies the
 * same rules to file shares - agents/windows/sentra-agent.ps1 Get-FileScanSnapshot, kept identical by tests/pii-classify.test.js).
 * Text is pulled from .txt/.csv/.log/.json/.xml/.html, from configuration and script files (.pem/.key/.env/.ini/.conf/
 * .cfg/.yml/.yaml/.config/.properties/.ps1/.sh/.py) and from the XML inside .docx/.xlsx/.pptx (a minimal zip reader:
 * stored or deflated entries only). Matches are COUNTED here and only the counts leave - no value, no snippet is kept,
 * logged or sent (for a credential either: only that the file holds one, and how many).
 * A kind counts for a file only at its threshold (one stray number is not a register of national IDs):
 *   national_id / iqama >= 3   mobile >= 3   email >= 10   iban >= 1   card >= 1 (Luhn)   health keywords >= 2
 *   credentials (secrets in files): private_key >= 1   api_key >= 1   password (password = ... / كلمة المرور: ...) >= 1
 *   (the three credential patterns are the browser extension's - agents/browser-ai-dlp/classify.js, tests/shadow-ai.test.js)
 * File NAMES are classified too (passport, iqama, medical report, payroll ... and credential files: id_rsa, *.pem, *.key,
 * *.pfx, .env, credentials, secrets) and reported as by: 'name'.
 *   classifyText(text) → { kinds: {kind: n}, matched: n }      classifyName(name) → [kind]      textOf(name, buf) → text | null
 */
const zlib = require('node:zlib');

const RULES = [
  { kind: 'national_id', category: 'identity', re: /(?<![\d])1\d{9}(?![\d])/g, min: 3 },
  { kind: 'iqama', category: 'identity', re: /(?<![\d])2\d{9}(?![\d])/g, min: 3 },
  { kind: 'mobile', category: 'contact', re: /(?<![\d+])(?:\+?966|00966|0)5\d{8}(?![\d])/g, min: 3 },
  { kind: 'email', category: 'contact', re: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, min: 10 },
  { kind: 'iban', category: 'financial', re: /\bSA\d{2}[ ]?(?:\d{4}[ ]?){5}\b/g, min: 1 },
  { kind: 'card', category: 'financial', re: /(?<![\d])(?:\d[ -]?){13,19}(?![\d])/g, min: 1, luhn: true },
  { kind: 'health', category: 'health', re: /\b(?:diagnosis|ICD-?10|medical report|prescription|chronic disease|lab result)\b|تشخيص|تقرير طبي|وصفة طبية|مرض مزمن/gi, min: 2 },
  { kind: 'private_key', category: 'credentials', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g, min: 1 },
  { kind: 'api_key', category: 'credentials', re: /\b(?:AKIA[0-9A-Z]{16}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b/g, min: 1 },
  { kind: 'password', category: 'credentials', re: /\b(?:password|passwd|pwd)\s*[:=]\s*\S{4,}|كلمة (?:المرور|السر)\s*[:=]\s*\S{4,}/gi, min: 1 },
];
const NAME_RULES = [
  ['passport', 'identity', /passport|جواز/i], ['iqama', 'identity', /iqama|إقامة|اقامة/i], ['national_id', 'identity', /national[ _-]?id|هوية/i],
  ['health', 'health', /medical|diagnos|prescription|lab[ _-]?result|تقرير[ _]طبي|طبي/i], ['salary', 'financial', /payroll|salary|payslip|رواتب|راتب/i],
  ['iban', 'financial', /\biban\b|bank[ _-]?(details|account)|حساب[ _]بنكي/i], ['cv', 'employment', /\b(cv|resume|curriculum)\b|سيرة[ _]ذاتية/i],
  ['secret_file', 'credentials', /^id_(?:rsa|dsa|ecdsa|ed25519)$|\.(?:pem|key|pfx|p12|ppk|jks|keystore|kdbx)$|^\.env(?:\.[a-z]+)?$|(?:^|[^a-z])(?:credentials?|secrets?|passwords?)(?:[^a-z]|$)|كلمات[ _]المرور/i],
];
const CATEGORY = Object.fromEntries(RULES.map((r) => [r.kind, r.category]).concat(NAME_RULES.map((r) => [r[0], r[1]])));
const TEXT_EXT = /\.(txt|csv|log|json|xml|html?|tsv|pem|key|env|ini|conf|cfg|ya?ml|config|properties|ps1|sh|py)$/i, ZIP_EXT = /\.(docx|xlsx|pptx)$/i;
const MAX_TEXT = 2 * 1024 * 1024;

function luhn(d) { let t = 0; for (let i = 0; i < d.length; i++) { let n = d.charCodeAt(d.length - 1 - i) - 48; if (i % 2) { n *= 2; if (n > 9) n -= 9; } t += n; } return t % 10 === 0; }

function classifyText(text) {
  const t = String(text || '').slice(0, MAX_TEXT), kinds = {};
  let matched = 0;
  const noIban = t.replace(RULES.find((r) => r.kind === 'iban').re, ' ');   // an IBAN's digits are not a card number
  for (const r of RULES) {
    let n = 0;
    for (const m of (r.luhn ? noIban : t).matchAll(r.re)) { if (r.luhn) { const d = m[0].replace(/\D/g, ''); if (d.length < 13 || !luhn(d)) continue; } n++; if (n >= 100000) break; }
    if (n >= r.min) { kinds[r.kind] = n; matched += n; }
  }
  return { kinds, matched };
}
const classifyName = (name) => NAME_RULES.filter((r) => r[2].test(String(name || ''))).map((r) => r[0]);
const readable = (name) => TEXT_EXT.test(name) || ZIP_EXT.test(name);

// minimal zip reader (central directory): the XML parts that hold the text of an Office file
function zipText(buf, name) {
  const want = /\.docx$/i.test(name) ? /^word\/(document|header\d*|footer\d*)\.xml$/ : /\.xlsx$/i.test(name) ? /^xl\/(sharedStrings|worksheets\/sheet\d+)\.xml$/ : /^ppt\/slides\/slide\d+\.xml$/;
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 66000); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) return null;
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16), out = '';
  for (let k = 0; k < count && p + 46 <= buf.length; k++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) return out || null;
    const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24), nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32), loc = buf.readUInt32LE(p + 42);
    const ent = buf.toString('utf8', p + 46, p + 46 + nlen);
    p += 46 + nlen + xlen + clen;
    if (!want.test(ent) || usize > MAX_TEXT * 4 || loc + 30 > buf.length) continue;
    const start = loc + 30 + buf.readUInt16LE(loc + 26) + buf.readUInt16LE(loc + 28), data = buf.subarray(start, start + csize);
    let xml;
    try { xml = method === 0 ? data : method === 8 ? zlib.inflateRawSync(data, { maxOutputLength: MAX_TEXT * 4 }) : null; } catch (e) { xml = null; /* a damaged part: the file is reported as not read */ }
    if (!xml) continue;
    out += ' ' + xml.toString('utf8').replace(/<[^>]+>/g, ' ');
    if (out.length > MAX_TEXT) break;
  }
  return out || null;
}
function textOf(name, buf) {
  if (!buf || !buf.length) return null;
  if (TEXT_EXT.test(name)) return buf.subarray(0, MAX_TEXT).toString('utf8');
  if (ZIP_EXT.test(name)) return zipText(buf, name);
  return null;
}

module.exports = { classifyText, classifyName, textOf, readable, luhn, RULES, NAME_RULES, CATEGORY, TEXT_EXT, ZIP_EXT };
