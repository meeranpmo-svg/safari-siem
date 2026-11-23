// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Tiny XML reader for PAN-OS API answers (well-formed, small documents). No DTDs, no external entities — so no XXE.
 *   parse(text) → node {name, attrs, children[], text}
 *   find(node, 'result/system/hostname') → first node on the path;  all(node, 'result/entries/entry') → nodes
 *   txt(node, 'path') → trimmed text ('' when missing);  toObj(node) → plain object (repeated tags → arrays)
 */
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
function decode(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') { const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return Number.isFinite(n) && n < 0x110000 ? String.fromCodePoint(n) : m; }
    return ENT[e.toLowerCase()] !== undefined ? ENT[e.toLowerCase()] : m;
  });
}
function parse(text) {
  const s = String(text || ''); const root = { name: '#root', attrs: {}, children: [], text: '' }; const stack = [root]; let i = 0;
  if (s.length > 16 * 1048576) throw new Error('XML too large');
  while (i < s.length) {
    const lt = s.indexOf('<', i);
    if (lt < 0) { stack[stack.length - 1].text += decode(s.slice(i)); break; }
    if (lt > i) stack[stack.length - 1].text += decode(s.slice(i, lt));
    if (s.startsWith('<!--', lt)) { const e = s.indexOf('-->', lt); i = e < 0 ? s.length : e + 3; continue; }
    if (s.startsWith('<![CDATA[', lt)) { const e = s.indexOf(']]>', lt); stack[stack.length - 1].text += s.slice(lt + 9, e < 0 ? s.length : e); i = e < 0 ? s.length : e + 3; continue; }
    if (s[lt + 1] === '?' || s[lt + 1] === '!') { const e = s.indexOf('>', lt); i = e < 0 ? s.length : e + 1; continue; }
    const gt = s.indexOf('>', lt); if (gt < 0) throw new Error('unterminated tag');
    const raw = s.slice(lt + 1, gt);
    if (raw[0] === '/') { if (stack.length > 1) stack.pop(); i = gt + 1; continue; }
    const self = raw.endsWith('/'); const body = self ? raw.slice(0, -1) : raw;
    const m = /^([^\s/>]+)/.exec(body); if (!m) throw new Error('bad tag');
    const node = { name: m[1], attrs: {}, children: [], text: '' };
    const re = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')/g; let a;
    while ((a = re.exec(body.slice(m[1].length)))) node.attrs[a[1]] = decode(a[3] !== undefined ? a[3] : a[4]);
    stack[stack.length - 1].children.push(node);
    if (!self) { if (stack.length > 200) throw new Error('XML too deep'); stack.push(node); }
    i = gt + 1;
  }
  return root.children[0] || root;
}
function all(node, p) {
  let cur = [node];
  for (const part of String(p).split('/').filter(Boolean)) cur = cur.flatMap((n) => n.children.filter((c) => c.name === part));
  return cur;
}
function find(node, p) { return all(node, p)[0] || null; }
function txt(node, p) { const n = p ? find(node, p) : node; return n ? n.text.trim() : ''; }
function toObj(n) {
  if (!n.children.length) return n.text.trim();
  const o = {}; for (const [k, v] of Object.entries(n.attrs)) o['@' + k] = v;
  for (const c of n.children) { const v = toObj(c); if (o[c.name] === undefined) o[c.name] = v; else { if (!Array.isArray(o[c.name])) o[c.name] = [o[c.name]]; o[c.name].push(v); } }
  return o;
}
module.exports = { parse, all, find, txt, toObj };
