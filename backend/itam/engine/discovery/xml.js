// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Minimal, tolerant XML reader for SOAP (CUCM AXL / RisPort70) and AWS EC2 Query API responses. No DTDs, no external
// entities (they are not expanded — XXE-safe by construction), namespaces reduced to local names.
//   parse(text) → root node {name, attrs, children[], text}
//   find(node, name) → first descendant (depth-first)        findAll(node, name) → all descendants with that name
//   child(node, name) → direct child                          textOf(node, name) → trimmed text of first descendant
//   esc(s) → XML-escaped text for building requests
const ENT = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
function decode(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (m, e) => {
    if (e[0] === '#') { const n = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return Number.isFinite(n) && n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ''; }
    return Object.prototype.hasOwnProperty.call(ENT, e) ? ENT[e] : m;
  });
}
const local = (n) => { const i = n.indexOf(':'); return i >= 0 ? n.slice(i + 1) : n; };

function parse(text) {
  const s = String(text || '');
  if (s.length > 32 * 1024 * 1024) throw new Error('XML too large');
  const root = { name: '#root', attrs: {}, children: [], text: '' };
  const stack = [root];
  let i = 0;
  while (i < s.length) {
    const lt = s.indexOf('<', i);
    if (lt < 0) { stack[stack.length - 1].text += decode(s.slice(i)); break; }
    if (lt > i) stack[stack.length - 1].text += decode(s.slice(i, lt));
    if (s.startsWith('<!--', lt)) { const e = s.indexOf('-->', lt + 4); i = e < 0 ? s.length : e + 3; continue; }
    if (s.startsWith('<![CDATA[', lt)) { const e = s.indexOf(']]>', lt + 9); stack[stack.length - 1].text += s.slice(lt + 9, e < 0 ? s.length : e); i = e < 0 ? s.length : e + 3; continue; }
    if (s.startsWith('<?', lt) || s.startsWith('<!', lt)) { const e = s.indexOf('>', lt); i = e < 0 ? s.length : e + 1; continue; }
    const gt = s.indexOf('>', lt);
    if (gt < 0) throw new Error('unterminated tag');
    let tag = s.slice(lt + 1, gt);
    i = gt + 1;
    if (tag[0] === '/') {
      const name = local(tag.slice(1).trim());
      for (let k = stack.length - 1; k > 0; k--) if (stack[k].name === name) { stack.length = k; break; }
      continue;
    }
    const selfClose = tag.endsWith('/');
    if (selfClose) tag = tag.slice(0, -1);
    const m = /^([^\s/>]+)/.exec(tag);
    if (!m) continue;
    const node = { name: local(m[1]), attrs: {}, children: [], text: '' };
    const re = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')/g; const rest = tag.slice(m[1].length); let a;
    while ((a = re.exec(rest))) node.attrs[local(a[1])] = decode(a[3] !== undefined ? a[3] : a[4]);
    stack[stack.length - 1].children.push(node);
    if (!selfClose) stack.push(node);
    if (stack.length > 200) throw new Error('XML nested too deeply');
  }
  return root;
}

function find(node, name) {
  if (!node) return null;
  for (const c of node.children) { if (c.name === name) return c; const r = find(c, name); if (r) return r; }
  return null;
}
function findAll(node, name, out = []) {
  if (!node) return out;
  for (const c of node.children) { if (c.name === name) out.push(c); findAll(c, name, out); }
  return out;
}
function child(node, name) { return node ? node.children.find((c) => c.name === name) || null : null; }
function textOf(node, name) { const n = name ? find(node, name) : node; return n ? n.text.trim() : ''; }
function childText(node, name) { const n = child(node, name); return n ? n.text.trim() : ''; }
const esc = (v) => String(v == null ? '' : v).replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));

module.exports = { parse, find, findAll, child, textOf, childText, esc, decode };
