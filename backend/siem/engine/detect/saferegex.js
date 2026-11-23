// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Static safety check for user-supplied detection regexes (rules, Sigma |re, rule tests). JavaScript's RegExp engine
// backtracks, so a pattern such as (a+)+$ run against an attacker-controlled log field can stall the engine thread.
// Refused: patterns longer than MAX_LEN, back-references (\1 … \9, \k<name>), a quantified group that itself
// contains a quantifier ("nested quantifiers" — the classic catastrophic shape, including (.*a){12}), a repeated group
// whose alternatives can overlap (^(a|a)*$ backtracks exponentially), and more than MAX_WILD open-ended wildcards in
// one alternative (.* \S+ [^ ]* …: each one multiplies the work, .*.*.*.*x$ is O(n^5)). Matching also caps the input.
//   checkRegex(pattern) → throws Error with a readable reason; returns the pattern when it is acceptable
const MAX_LEN = 512;
const MAX_INPUT = 16 * 1024;
const MAX_WILD = 2;

// A repeated group with alternatives backtracks exponentially when two alternatives can match the same text, as in
// ^(a|a)*$ or (\w|\d)*$. Allowed only when the alternatives cannot overlap at their first character:
// (\s|\+|%20)* is fine, (a|ab)*, (\w|\d)* and (a|)* are not.
function splitTop(body) {
  const out = []; let depth = 0, inC = false, cur = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '\\') { cur += c + (body[i + 1] || ''); i++; continue; }
    if (inC) { if (c === ']') inC = false; cur += c; continue; }
    if (c === '[') inC = true; else if (c === '(') depth++; else if (c === ')') depth--;
    else if (c === '|' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur); return out;
}
function firstTok(b) {
  if (!b) return { empty: true };
  if (b[0] === '\\') { const e = b[1] || ''; return /[dDwWsSbB]/.test(e) ? { cls: b.slice(0, 2) } : { lit: e }; }
  if (b[0] === '[') { const j = b.indexOf(']', b[1] === ']' ? 2 : 1); return { cls: j > 0 ? b.slice(0, j + 1) : b }; }
  if (b[0] === '.' || b[0] === '(' || b[0] === '^' || b[0] === '$') return { cls: b[0] === '.' ? '.' : null };
  return { lit: b[0] };
}
function overlapCheck(body) {
  const alts = splitTop(body.replace(/^\?(?::|<[A-Za-z_][\w]*>)/, ''));
  if (alts.length < 2) return;
  const bad = () => { throw new Error('a repeated group whose alternatives can match the same text, such as (a|a)* or (\\w|\\d)*, is not allowed in detection regexes'); };
  const toks = alts.map(firstTok), lits = new Set(); let cls = null;
  for (const t of toks) {
    if (t.empty) bad();
    if ('cls' in t) { if (cls !== null || t.cls === null) bad(); cls = t.cls; continue; }
    const l = t.lit.toLowerCase(); if (lits.has(l)) bad(); lits.add(l);
  }
  if (cls) { let re; try { re = new RegExp('^' + cls + '$', 'i'); } catch (e) { bad(); } for (const l of lits) if (re.test(l)) bad(); }
}

function checkRegex(pattern) {
  const p = String(pattern);
  if (p.length > MAX_LEN) throw new Error(`regex too long (max ${MAX_LEN} characters)`);
  if (/\\[1-9]|\\k</.test(p)) throw new Error('back-references are not allowed in detection regexes');
  const stack = []; // one entry per open group: { q: contains a quantifier, start }
  let inClass = false, wild = 0, maxWild = 0;
  const quantAt = (j) => { const n = p[j]; return n === '*' || n === '+' || (n === '{' && /^\{\d+(,\d*)?\}/.test(p.slice(j))); };
  const openAt = (j) => { const n = p[j]; return n === '*' || n === '+' || (n === '{' && /^\{\d+,\d*\}/.test(p.slice(j))); };
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '\\') { if (/[SWD]/.test(p[i + 1] || '') && openAt(i + 2)) wild++; i++; continue; }
    if (inClass) { if (c === ']') { inClass = false; if (p[i - 1] !== '[' && /^\[\^/.test(p.slice(classAt, classAt + 2)) && openAt(i + 1)) wild++; } continue; }
    if (c === '[') { inClass = true; var classAt = i; if (p[i + 1] === '^') i++; if (p[i + 1] === ']') i++; continue; }
    if (c === '(') { stack.push({ q: false, start: i }); continue; }
    if (c === '|' && !stack.length) { maxWild = Math.max(maxWild, wild); wild = 0; continue; }   // wildcards count per alternative
    if (c === '.' && openAt(i + 1)) wild++;
    const quant = c === '*' || c === '+' || (c === '{' && /^\{\d+(,\d*)?\}/.test(p.slice(i)));
    if (c === ')') {
      const g = stack.pop() || { q: false, start: i };
      const repeated = quantAt(i + 1);
      if (g.q && repeated) throw new Error('nested quantifiers such as (a+)+ or (.*a){3} are not allowed in detection regexes');
      if (openAt(i + 1)) overlapCheck(p.slice(g.start + 1, i));
      if (stack.length && (g.q || repeated)) stack[stack.length - 1].q = true;
      continue;
    }
    if (quant && stack.length) stack[stack.length - 1].q = true;
  }
  maxWild = Math.max(maxWild, wild);
  if (maxWild > MAX_WILD) throw new Error(`at most ${MAX_WILD} open-ended wildcards (.* \\S+ [^x]* …) are allowed in one alternative of a detection regex`);
  return p;
}

module.exports = { checkRegex, MAX_REGEX_LEN: MAX_LEN, MAX_REGEX_INPUT: MAX_INPUT, MAX_REGEX_WILD: MAX_WILD };
