// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Minimal YAML parser — enough for Sigma rules (not a general YAML implementation).
 *   parse(text)    → first document
 *   parseAll(text) → [documents] (split on `---`)
 * Supported: block mappings, block sequences (incl. "- key: value" maps inside sequences), nesting by indentation,
 * plain / 'single' / "double" quoted scalars, flow sequences [a, b] and simple flow maps {a: b},
 * block scalars `|` and `>` (with -/+ chomping and explicit indent digit), multi-line plain scalars,
 * comments (# at line start or after whitespace), null/~/true/false/ints/floats.
 * Not supported (throws YamlError with the line number): anchors/aliases (&, *), tags (!!), complex keys (?),
 * multi-line flow collections, tabs used for indentation.
 */

class YamlError extends Error {
  constructor(msg, line) { super(line ? `YAML line ${line}: ${msg}` : `YAML: ${msg}`); this.line = line; }
}

function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === q) {
        if (q === "'" && s[i + 1] === "'") { i++; continue; }
        q = null;
      } else if (c === '\\' && q === '"') i++;
    } else if (c === '"' || c === "'") {
      // quotes only open a quoted scalar at token start
      const prev = i === 0 ? ' ' : s[i - 1];
      if (/[\s:\-[{,]/.test(prev)) q = c;
    } else if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).replace(/\s+$/, '');
  }
  return s.replace(/\s+$/, '');
}

function unescapeDouble(s, line) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== '\\') { out += c; continue; }
    const n = s[++i];
    switch (n) {
      case 'n': out += '\n'; break;
      case 't': out += '\t'; break;
      case 'r': out += '\r'; break;
      case '0': out += '\0'; break;
      case '"': out += '"'; break;
      case '/': out += '/'; break;
      case '\\': out += '\\'; break;
      case ' ': out += ' '; break;
      case 'x': out += String.fromCharCode(parseInt(s.substr(i + 1, 2), 16)); i += 2; break;
      case 'u': out += String.fromCharCode(parseInt(s.substr(i + 1, 4), 16)); i += 4; break;
      default: throw new YamlError(`unknown escape \\${n}`, line);
    }
  }
  return out;
}

function plainScalar(s) {
  const t = s.trim();
  if (t === '' || t === '~' || t === 'null' || t === 'Null' || t === 'NULL') return null;
  if (t === 'true' || t === 'True' || t === 'TRUE') return true;
  if (t === 'false' || t === 'False' || t === 'FALSE') return false;
  if (/^[-+]?(0|[1-9][0-9]*)$/.test(t)) { const n = Number(t); if (Number.isSafeInteger(n)) return n; return t; }
  if (/^0x[0-9a-fA-F]+$/.test(t)) return parseInt(t, 16);
  if (/^[-+]?([0-9]*\.[0-9]+|[0-9]+\.[0-9]*)([eE][-+]?[0-9]+)?$/.test(t)) return Number(t);
  return t;
}

/** Parse a scalar or flow collection written on one line. */
function inlineValue(s, line) {
  const t = s.trim();
  if (!t) return null;
  const c = t[0];
  if (c === '&' || c === '*') throw new YamlError('anchors/aliases are not supported', line);
  if (c === '!') throw new YamlError('tags are not supported', line);
  if (c === '"') {
    const end = findClosingDouble(t, 0);
    if (end < 0) throw new YamlError('unterminated double-quoted string', line);
    if (t.slice(end + 1).trim()) throw new YamlError(`unexpected text after string: ${t.slice(end + 1)}`, line);
    return unescapeDouble(t.slice(1, end), line);
  }
  if (c === "'") {
    const end = findClosingSingle(t, 0);
    if (end < 0) throw new YamlError('unterminated single-quoted string', line);
    if (t.slice(end + 1).trim()) throw new YamlError(`unexpected text after string: ${t.slice(end + 1)}`, line);
    return t.slice(1, end).replace(/''/g, "'");
  }
  if (c === '[' || c === '{') {
    const p = { s: t, i: 0, line };
    const v = flow(p);
    if (t.slice(p.i).trim()) throw new YamlError(`unexpected text after flow collection: ${t.slice(p.i)}`, line);
    return v;
  }
  return plainScalar(t);
}

function findClosingDouble(t, start) {
  for (let i = start + 1; i < t.length; i++) { if (t[i] === '\\') { i++; continue; } if (t[i] === '"') return i; }
  return -1;
}
function findClosingSingle(t, start) {
  for (let i = start + 1; i < t.length; i++) { if (t[i] === "'") { if (t[i + 1] === "'") { i++; continue; } return i; } }
  return -1;
}

function flow(p) {
  const skip = () => { while (p.i < p.s.length && /\s/.test(p.s[p.i])) p.i++; };
  skip();
  const c = p.s[p.i];
  if (c === '[') {
    p.i++; const arr = [];
    skip();
    if (p.s[p.i] === ']') { p.i++; return arr; }
    for (;;) {
      arr.push(flowItem(p, ',]'));
      skip();
      if (p.s[p.i] === ',') { p.i++; skip(); if (p.s[p.i] === ']') { p.i++; return arr; } continue; }
      if (p.s[p.i] === ']') { p.i++; return arr; }
      throw new YamlError('bad flow sequence (multi-line flow collections are not supported)', p.line);
    }
  }
  if (c === '{') {
    p.i++; const obj = {};
    skip();
    if (p.s[p.i] === '}') { p.i++; return obj; }
    for (;;) {
      const k = flowItem(p, ':,}');
      skip();
      if (p.s[p.i] !== ':') throw new YamlError('bad flow mapping', p.line);
      p.i++;
      obj[String(k)] = flowItem(p, ',}');
      skip();
      if (p.s[p.i] === ',') { p.i++; skip(); continue; }
      if (p.s[p.i] === '}') { p.i++; return obj; }
      throw new YamlError('bad flow mapping (multi-line flow collections are not supported)', p.line);
    }
  }
  return flowItem(p, ',]}');
}

function flowItem(p, stops) {
  while (p.i < p.s.length && /\s/.test(p.s[p.i])) p.i++;
  const c = p.s[p.i];
  if (c === '[' || c === '{') return flow(p);
  if (c === '"') {
    const e = findClosingDouble(p.s, p.i);
    if (e < 0) throw new YamlError('unterminated string', p.line);
    const v = unescapeDouble(p.s.slice(p.i + 1, e), p.line); p.i = e + 1; return v;
  }
  if (c === "'") {
    const e = findClosingSingle(p.s, p.i);
    if (e < 0) throw new YamlError('unterminated string', p.line);
    const v = p.s.slice(p.i + 1, e).replace(/''/g, "'"); p.i = e + 1; return v;
  }
  let j = p.i;
  while (j < p.s.length && stops.indexOf(p.s[j]) < 0) {
    if (p.s[j] === ':' && stops.indexOf(':') >= 0 && !/\s/.test(p.s[j + 1] || ' ')) { j++; continue; }
    j++;
  }
  const v = plainScalar(p.s.slice(p.i, j)); p.i = j; return v;
}

/** Split `key: rest` → [key, rest] or null (colon must be followed by space/EOL, outside quotes). */
function splitKey(text, line) {
  let i = 0; let key;
  if (text[0] === '"' || text[0] === "'") {
    const e = text[0] === '"' ? findClosingDouble(text, 0) : findClosingSingle(text, 0);
    if (e < 0) return null;
    key = text[0] === '"' ? unescapeDouble(text.slice(1, e), line) : text.slice(1, e).replace(/''/g, "'");
    i = e + 1;
    while (text[i] === ' ') i++;
    if (text[i] !== ':' || (i + 1 < text.length && text[i + 1] !== ' ')) return null;
    return [key, text.slice(i + 1)];
  }
  if (text[0] === '?') throw new YamlError('complex keys are not supported', line);
  for (i = 0; i < text.length; i++) {
    if (text[i] === ':' && (i + 1 === text.length || text[i + 1] === ' ')) return [text.slice(0, i).trim(), text.slice(i + 1)];
    if (text[i] === ' ' && text[i + 1] === '#') return null;
  }
  return null;
}

function isSeqItem(text) { return text === '-' || text.startsWith('- '); }

function parseDocument(rawLines, baseLine) {
  // pre-process: [{indent, text, n (1-based line), raw}]
  const lines = [];
  for (let k = 0; k < rawLines.length; k++) {
    const raw = rawLines[k];
    const m = raw.match(/^( *)(.*)$/);
    if (/^ *\t/.test(raw) && raw.trim()) throw new YamlError('tabs are not allowed for indentation', baseLine + k);
    const text = stripComment(m[2]);
    lines.push({ indent: m[1].length, text, n: baseLine + k, raw, blank: text === '' });
  }
  let i = 0;
  const skipBlank = () => { while (i < lines.length && lines[i].blank) i++; };

  function blockScalar(header, parentIndent, lineNo) {
    const style = header[0];
    const mods = header.slice(1).trim();
    let chomp = 'clip'; let explicit = 0;
    for (const ch of mods) {
      if (ch === '-') chomp = 'strip';
      else if (ch === '+') chomp = 'keep';
      else if (/[1-9]/.test(ch)) explicit = Number(ch);
      else throw new YamlError(`bad block scalar header "${header}"`, lineNo);
    }
    const body = [];
    let ind = explicit ? parentIndent + explicit : -1;
    while (i < lines.length) {
      const L = lines[i];
      const rawText = L.raw;
      if (rawText.trim() === '') { body.push(''); i++; continue; }
      const lead = rawText.match(/^ */)[0].length;
      if (ind < 0) { if (lead <= parentIndent) break; ind = lead; }
      if (lead < ind) break;
      body.push(rawText.slice(ind));
      i++;
    }
    // trailing blank lines belong to chomping
    let trailing = 0;
    while (body.length && body[body.length - 1] === '') { body.pop(); trailing++; }
    let out;
    if (style === '|') out = body.join('\n');
    else {
      out = '';
      for (let k = 0; k < body.length; k++) {
        const b = body[k];
        if (k === 0) { out = b; continue; }
        const prevMore = /^\s/.test(body[k - 1]) || body[k - 1] === '';
        if (b === '') out += '\n';
        else if (/^\s/.test(b) || prevMore) out += (body[k - 1] === '' ? '' : '\n') + b;
        else out += ' ' + b;
      }
    }
    if (chomp === 'strip') return out;
    if (chomp === 'keep') return out + '\n' + '\n'.repeat(trailing);
    return body.length ? out + '\n' : '';
  }

  function parseNode(indent) {
    skipBlank();
    if (i >= lines.length) return null;
    const L = lines[i];
    if (L.indent < indent) return null;
    if (isSeqItem(L.text)) return parseSeq(L.indent);
    if (splitKey(L.text, L.n)) return parseMap(L.indent);
    // a scalar node (possibly multi-line plain)
    i++;
    const first = L.text;
    if (first[0] === '|' || first[0] === '>') return blockScalar(first, L.indent - 1, L.n);
    let s = first;
    while (i < lines.length && !lines[i].blank && lines[i].indent >= L.indent && !isSeqItem(lines[i].text) && first[0] !== '"' && first[0] !== "'") {
      s += ' ' + lines[i].text.trim(); i++;
    }
    return inlineValue(s, L.n);
  }

  function valueAfterKey(rest, keyIndent, lineNo) {
    const r = rest.trim();
    if (r === '') {
      skipBlank();
      if (i >= lines.length) return null;
      const N = lines[i];
      if (N.indent > keyIndent) return parseNode(N.indent);
      if (N.indent === keyIndent && isSeqItem(N.text)) return parseSeq(keyIndent); // "key:\n- a" (same indent)
      return null;
    }
    if (r[0] === '|' || r[0] === '>') return blockScalar(r, keyIndent, lineNo);
    // multi-line plain scalar continuation
    if (r[0] !== '"' && r[0] !== "'" && r[0] !== '[' && r[0] !== '{') {
      let s = r;
      while (i < lines.length && !lines[i].blank && lines[i].indent > keyIndent && !isSeqItem(lines[i].text) && !splitKey(lines[i].text, lines[i].n)) {
        s += ' ' + lines[i].text.trim(); i++;
      }
      return inlineValue(s, lineNo);
    }
    // quoted scalar that may continue on following lines
    if ((r[0] === '"' && findClosingDouble(r, 0) < 0) || (r[0] === "'" && findClosingSingle(r, 0) < 0)) {
      let s = r;
      while (i < lines.length) {
        const cont = lines[i].raw.trim(); i++;
        s += ' ' + cont;
        if ((r[0] === '"' && findClosingDouble(s, 0) >= 0) || (r[0] === "'" && findClosingSingle(s, 0) >= 0)) break;
      }
      return inlineValue(s, lineNo);
    }
    return inlineValue(r, lineNo);
  }

  function parseMap(indent) {
    const obj = {};
    while (true) {
      skipBlank();
      if (i >= lines.length) break;
      const L = lines[i];
      if (L.indent < indent) break;
      if (L.indent > indent) throw new YamlError(`unexpected indentation`, L.n);
      if (isSeqItem(L.text)) break;
      const kv = splitKey(L.text, L.n);
      if (!kv) throw new YamlError(`expected "key: value", got "${L.text}"`, L.n);
      const [k, rest] = kv;
      if (k.startsWith('&') || k.startsWith('*')) throw new YamlError('anchors/aliases are not supported', L.n);
      if (Object.prototype.hasOwnProperty.call(obj, k)) throw new YamlError(`duplicate key "${k}"`, L.n);
      i++;
      obj[k] = valueAfterKey(rest, indent, L.n);
    }
    return obj;
  }

  function parseSeq(indent) {
    const arr = [];
    while (true) {
      skipBlank();
      if (i >= lines.length) break;
      const L = lines[i];
      if (L.indent !== indent || !isSeqItem(L.text)) {
        if (L.indent > indent) throw new YamlError('unexpected indentation in sequence', L.n);
        break;
      }
      const content = L.text === '-' ? '' : L.text.slice(2);
      const lead = L.text === '-' ? 0 : (L.text.slice(1).match(/^ */)[0].length);
      if (content.trim() === '') { i++; arr.push(valueAfterKeySeq(indent)); continue; }
      const itemIndent = indent + 1 + lead;
      const trimmed = content.trim();
      if (isSeqItem(trimmed) || (splitKey(trimmed, L.n) && trimmed[0] !== '[' && trimmed[0] !== '{')) {
        // rewrite this line as a virtual line at the item's indentation and parse a nested node there
        lines[i] = { indent: itemIndent, text: trimmed, n: L.n, raw: ' '.repeat(itemIndent) + trimmed, blank: false };
        arr.push(parseNode(itemIndent));
        continue;
      }
      i++;
      if (trimmed[0] === '|' || trimmed[0] === '>') { arr.push(blockScalar(trimmed, indent, L.n)); continue; }
      let s = trimmed;
      if (trimmed[0] !== '"' && trimmed[0] !== "'" && trimmed[0] !== '[' && trimmed[0] !== '{') {
        while (i < lines.length && !lines[i].blank && lines[i].indent > indent && !isSeqItem(lines[i].text)) { s += ' ' + lines[i].text.trim(); i++; }
      }
      arr.push(inlineValue(s, L.n));
    }
    return arr;
  }

  function valueAfterKeySeq(indent) {
    skipBlank();
    if (i >= lines.length) return null;
    if (lines[i].indent > indent) return parseNode(lines[i].indent);
    return null;
  }

  skipBlank();
  if (i >= lines.length) return null;
  const root = parseNode(lines[i].indent);
  skipBlank();
  if (i < lines.length) throw new YamlError(`unexpected content "${lines[i].text}"`, lines[i].n);
  return root;
}

function parseAll(text) {
  const src = String(text).replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  const all = src.split('\n');
  const docs = [];
  let cur = []; let start = 1;
  for (let k = 0; k < all.length; k++) {
    const line = all[k];
    if (/^---(\s|$)/.test(line)) {
      if (cur.some((l) => stripComment(l).trim())) docs.push(parseDocument(cur, start));
      cur = []; start = k + 2;
      const rest = line.slice(3).trim();
      if (rest && !rest.startsWith('#')) { cur.push(rest); start = k + 1; }
      continue;
    }
    if (/^\.\.\.(\s|$)/.test(line)) continue;
    if (/^%/.test(line) && !cur.length) continue; // directives
    cur.push(line);
  }
  if (cur.some((l) => stripComment(l).trim())) docs.push(parseDocument(cur, start));
  return docs;
}

function parse(text) {
  const docs = parseAll(text);
  return docs.length ? docs[0] : null;
}

module.exports = { parse, parseAll, YamlError };
