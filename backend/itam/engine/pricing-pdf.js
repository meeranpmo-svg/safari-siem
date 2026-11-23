// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Pricing figures out of an actuarial report PDF (engine/pdf-text.js gives the lines and cells of each page). The result is a list
 * of PROPOSALS - never a saved review: each one names the line / sub-line, the period, the field, the value as printed and the page
 * and table it came from, and the actuary confirms or corrects every value before a draft review is recorded (and a different person
 * approves it). Fields: earned premium (nep, SAR '000), ultimate loss ratio, expense ratio, commission ratio, target loss ratio, rate
 * change, exposure growth (all %); the combined ratio is read only as a cross-check.
 * Four table layouts are recognised:
 *   columns   lines down the side, measures across the top              (Motor TPL | 21,300 | 82.1% | 14.0% | ...)
 *   rows      measures down the side, lines across the top              (Ultimate loss ratio | 82.1% | 74.5% | ...)
 *   periods   lines down the side, periods across the top, the measure named in the table title or the header's first cell
 *   text      a line of prose naming a line, a measure and one number   ("the Motor TPL ultimate loss ratio is 82.1%")
 * Lines are recognised by name (Motor TPL / compulsory / comprehensive, Medical / Health individual / SME / corporate) and by LOB code
 * when the report itself maps a code to a name ("LOB9  Health Insurance") - never by guessing what a code means.
 * Units: a ratio printed as a fraction (0.821) is read as 82.1% and says so; premium in SAR million is converted to SAR '000 and says
 * so; premium with no unit stated is proposed as printed with a note to check the unit.
 */
const LINES = { motor: ['Compulsory (TPL)', 'Comprehensive', 'Compulsory + Others'], medical: ['Individual', 'SME / Group', 'Corporate'] };
const FIELDS = {
  nep: { re: /\b(net\s+)?earned\s+premiums?\b|\bNEP\b|\bnet\s+premiums?\s+earned\b|\binsurance\s+revenue\b/i, pct: false, label: "Earned premium (SAR '000)" },
  ulr: { re: /\bultimate\s+(loss|claims?)\s+ratio\b|\bULR\b|\b(expected|projected|best[- ]estimate)\s+loss\s+ratio\b|\bultimate\s+LR\b/i, pct: true, label: 'Ultimate loss ratio %' },
  expense_ratio: { re: /\b(admin(istrative|istration)?\s+|management\s+|operating\s+)?expenses?\s+ratio\b|\bexpense\s+loading\b/i, pct: true, label: 'Expense ratio %' },
  commission_ratio: { re: /\bcommissions?(\s+ratio)?\b|\bacquisition\s+(cost\s+)?ratio\b|\bacquisition\s+costs?\b/i, pct: true, label: 'Commission ratio %' },
  target_loss_ratio: { re: /\btarget\s+(loss\s+)?ratio\b|\bpermissible\s+loss\s+ratio\b|\bpricing\s+loss\s+ratio\b|\btarget\s+LR\b/i, pct: true, label: 'Target loss ratio %' },
  rate_change: { re: /\b(premium\s+)?rate\s+(change|increase|adjustment)\b|\btariff\s+(change|increase)\b|\bprice\s+change\b/i, pct: true, label: 'Rate change implemented %' },
  exposure_growth: { re: /\bexposure\s+growth\b|\bgrowth\s+in\s+exposure\b|\b(policy|member|vehicle)\s+count\s+growth\b/i, pct: true, label: 'Exposure growth %' },
  combined: { re: /\bcombined\s+ratio\b|\bCOR\b/i, pct: true, label: 'Combined ratio % (cross-check)' },
};
const ORDER = ['ulr', 'target_loss_ratio', 'expense_ratio', 'commission_ratio', 'rate_change', 'exposure_growth', 'combined', 'nep'];   // most specific first
// a heading about capital or reserves is not a pricing measure even when it names one ("Allocation based on NEP", "RBC / NEP")
const NOT_PRICING = /\b(allocation|based\s+on|RBC|capital|reinsur|ceded|cession|sliding|treaty|quota|retention|excess\s+of\s+loss|XoL|reserves?|technical\s+provisions?|TP\b|IBNR|OSLR|OCR|UPR|stress|shock|diversif)/i;
function fieldOf(t) { const s = String(t || ''); if (s.length > 90 || NOT_PRICING.test(s)) return null; for (const k of ORDER) if (FIELDS[k].re.test(s)) return k; return null; }

function lineOf(t, lob) {
  let s = String(t || '').trim(); if (!s || s.length > 70) return null;
  const code = /^(LOB\s*\d{1,2})\b/i.exec(s); if (code && lob[code[1].replace(/\s+/g, '').toUpperCase()]) s = lob[code[1].replace(/\s+/g, '').toUpperCase()] + ' ' + s.slice(code[0].length);
  if (/\bmotor\b|\bvehicle\b|\bauto\b/i.test(s)) {
    if (/compulsory\s*\+|\+\s*others|compulsory\s+and\s+others/i.test(s)) return { line: 'motor', sub: 'Compulsory + Others' };
    if (/\bcompulsory\b|\bTPL\b|third[- ]party|\bliability\b/i.test(s)) return { line: 'motor', sub: 'Compulsory (TPL)' };
    if (/comprehensive|\bown\s+damage\b|\bOD\b/i.test(s)) return { line: 'motor', sub: 'Comprehensive' };
    if (/^motor(\s+(total|insurance|all))?$/i.test(s.replace(/[^A-Za-z +]/g, '').trim())) return { line: 'motor', sub: null };
    return null; }
  if (/\b(medical|health)\b/i.test(s) && !/pandemic|cat(astrophe)?\b/i.test(s)) {
    if (/\bindividual\b|\bretail\b/i.test(s)) return { line: 'medical', sub: 'Individual' };
    if (/\bSME\b|\bsmall\b|\bgroup\b/i.test(s)) return { line: 'medical', sub: 'SME / Group' };
    if (/\bcorporate\b|\blarge\b|\bkey\s+accounts?\b/i.test(s)) return { line: 'medical', sub: 'Corporate' };
    if (/^(medical|health)(\s+(insurance|total|all))?$/i.test(s.replace(/[^A-Za-z ]/g, '').trim())) return { line: 'medical', sub: null };
    return null; }
  return null;
}
const PER = /\b(20\d\d)\s*[-_ ]?\s*Q([1-4])\b|\bQ([1-4])\s*[-_ ]?\s*(20\d\d)\b|\b(?:FY|YE)\s*[-_ ]?(20\d\d)\b|\b(20\d\d)\s*(?:YE|FY)\b|\b(20\d\d)\s*[-_ ]?\s*H([12])\b/i;
function periodOf(t) { const m = PER.exec(String(t || '')); if (!m) { const y = /^\s*(20\d\d)\s*$/.exec(String(t || '')); return y ? y[1] : null; }
  if (m[1]) return m[1] + '-Q' + m[2]; if (m[3]) return m[4] + '-Q' + m[3]; if (m[5]) return m[5]; if (m[6]) return m[6]; return m[7] + '-H' + m[8]; }
function numOf(t) {
  let s = String(t || '').trim(); if (!s || /^[-–—]$|^n\/?a$/i.test(s)) return null;
  const pct = /%\s*$/.test(s), neg = /^\(.*\)$/.test(s) || /^[-–−]\s*\d/.test(s);
  s = s.replace(/[()%\s,]/g, '').replace(/^[-–−]/, ''); if (!/^\d+(\.\d+)?$/.test(s)) return null;
  return { v: (neg ? -1 : 1) * Number(s), pct };
}
// header cell -> value cell by position: numbers are usually right-aligned under their heading, text left-aligned
// - and only when it sits under that heading: a value under a column whose heading is on another line is not given to a neighbour
function colIndex(hdr, c) { let best = -1, bd = Infinity; hdr.forEach((h, i) => { const d = Math.min(Math.abs(c.x - h.x), Math.abs(c.x2 - h.x2), Math.abs((c.x + c.x2) / 2 - (h.x + h.x2) / 2)); if (d < bd) { bd = d; best = i; } });
  const h = hdr[best]; if (!h) return -1; const over = Math.min(c.x2, h.x2) - Math.max(c.x, h.x); return over > 0 || bd <= Math.max(12, 0.5 * (h.x2 - h.x)) ? best : -1; }

function pricingFromPdf(doc, o = {}) {
  const out = [], notes = [], lob = {};
  // the report's own LOB code -> name map ("LOB9  Health Insurance")
  for (const p of doc.pages) for (const l of p.lines) { const a = l.cells[0] && /^LOB\s*(\d{1,2})$/i.exec(l.cells[0].text), b = l.cells[1] && l.cells[1].text;
    if (a && b && /[A-Za-z]{3}/.test(b) && !/^LOB\s*\d/i.test(b) && !numOf(b) && b.length < 60) { const k = 'LOB' + a[1]; if (!lob[k]) lob[k] = b; } }
  const docPeriod = (() => { const cnt = {}; for (const p of doc.pages.slice(0, 3)) for (const l of p.lines) { const x = periodOf(l.text); if (x) cnt[x] = (cnt[x] || 0) + 1; } return Object.keys(cnt).sort((a, b) => cnt[b] - cnt[a])[0] || null; })();
  const unitNear = (p, i) => { const t = p.lines.slice(Math.max(0, i - 4), i + 1).map((l) => l.text).join(' ');
    return /SAR\s*(m\b|mn\b|million)|\(\s*SAR\s*m\s*\)|SR\s*million/i.test(t) ? 'million' : /'?\s*000\s*'?s?\b|thousand/i.test(t) ? 'thousand' : null; };
  const titleNear = (p, i) => { for (let k = i - 1; k >= Math.max(0, i - 4); k--) { const t = p.lines[k].text; if (/^table\b|\bratio|premium|pricing|adequacy|loss/i.test(t) && t.length < 160) return t; } return ''; };
  let curTitle = '';
  const add = (p, i, line, period, field, raw, how, row) => {
    const n = numOf(raw); if (!n || !line) return; let v = n.v, note = '';
    if (FIELDS[field].pct) { if (!n.pct && Math.abs(v) <= 3 && field !== 'rate_change' && field !== 'exposure_growth') { v = v * 100; note = 'printed as a fraction (' + raw + '), read as ' + (Math.round(v * 10) / 10) + '%'; } else if (!n.pct && (field === 'rate_change' || field === 'exposure_growth') && Math.abs(v) < 1 && /\./.test(raw)) { v = v * 100; note = 'printed as a fraction (' + raw + '), read as ' + (Math.round(v * 10) / 10) + '%'; } }
    else { const u = unitNear(p, i); if (u === 'million') { v = v * 1000; note = 'SAR million in the report, converted to SAR \'000'; } else if (!u) note = 'no unit stated near the table - check it is SAR \'000'; }
    out.push({ line: line.line, sub_line: line.sub, period: period || null, field, value: Math.round(v * 1000) / 1000, raw: String(raw).trim(), page: p.n, table: curTitle || titleNear(p, i) || null, row: String(row || '').slice(0, 200), how, note });
  };
  for (const p of doc.pages) {
    const L = p.lines, textOnly = (l) => !l.cells.some((c) => numOf(c.text) && !periodOf(c.text));   // a row of years is a heading
    for (let i = 0; i < L.length; i++) {
      // a heading block: the run of text-only lines this line belongs to; read once, at its widest line, each column's heading being
      // every block cell above or below it ("Allocation / Based on / NEP" is one heading, not "NEP")
      if (!textOnly(L[i]) || (i > 0 && textOnly(L[i - 1]) && L[i - 1].cells.length >= 2 && i - 1 >= 0 && L[i]._seen)) continue;
      let b0 = i, b1 = i; while (b1 + 1 < L.length && textOnly(L[b1 + 1]) && b1 - b0 < 30) b1++;
      for (let k = b0; k <= b1; k++) L[k]._seen = true;
      let w = b0; for (let k = b0; k <= b1; k++) if (L[k].cells.length > L[w].cells.length) w = k;
      const H = L[w].cells; if (H.length < 2) { i = b1; continue; }
      const nearestH = (c) => { let best = -1, bd = Infinity; H.forEach((h, j2) => { const d = Math.abs((c.x + c.x2) / 2 - (h.x + h.x2) / 2); if (d < bd) { bd = d; best = j2; } }); return best; };
      const head = H.map((h, j) => { const parts = []; for (let k = b0; k <= b1; k++) for (const c of L[k].cells) { if (k === w ? c === h : (c.x2 - c.x < 2.5 * Math.max(20, h.x2 - h.x) && nearestH(c) === j && (Math.min(c.x2, h.x2) - Math.max(c.x, h.x) > 0 || Math.abs((c.x + c.x2) / 2 - (h.x + h.x2) / 2) < 14))) parts.push(c.text); } return parts.join(' '); });
      const hf = head.map((t) => fieldOf(t)), hl = head.map((t) => lineOf(t, lob)), hp = head.map((t) => periodOf(t));
      // a year (or quarter) heading that spans several columns ("Actual 2025 | Projections 2026"): each column takes the nearest one above it
      const pureP = (t) => /^\s*(?:(?:FY|YE)\s*)?(?:20\d\d(?:\s*[-_ ]?\s*(?:Q[1-4]|H[12]))?|Q[1-4]\s*[-_ ]?\s*20\d\d)(?:\s*(?:YE|FY|A|P|actual|projected|projection))?\s*$/i.test(t) && periodOf(t);
      for (let k = w - 1; k >= b0; k--) { const P2 = L[k].cells.filter((c) => pureP(c.text)); if (!P2.length || P2.length !== L[k].cells.length) continue;
        H.forEach((h, j) => { if (hp[j]) return; const mid = (h.x + h.x2) / 2; let best = null, bd = Infinity; for (const c of P2) { const d = Math.abs((c.x + c.x2) / 2 - mid); if (d < bd) { bd = d; best = c; } } if (best) hp[j] = periodOf(best.text); }); }
      const blockTitle = (() => { for (let k = w - 1; k >= Math.max(0, b0 - 4); k--) { const t = L[k].text; if (/^(table\s|\d+(\.\d+)+\s)/i.test(t) && t.length < 160) return t; } return ''; })();
      const i0 = i; i = b1; curTitle = blockTitle;
      const nf = hf.filter(Boolean).length, nl = hl.filter(Boolean).length, np = hp.filter(Boolean).length;
      const pageP = (() => { for (let k = b1; k >= Math.max(0, i0 - 6); k--) { const t = L[k].text, x = periodOf(t) || (/^table\b|\b(allocation|premium|ratio|pricing|projected|actual)\b/i.test(t) && (t.match(/\b(20\d\d)\b/g) || []).length === 1 ? t.match(/\b(20\d\d)\b/)[1] : null); if (x) return x; } return null; })() || docPeriod;
      // the rows under a heading: a text-only line (the rest of a heading split over lines) is passed over, up to 8 of them
      // a new table (a "Table n" / section title, or another heading row once data has started) ends this one
      const rowsBelow = (fn) => { let miss = 0, soft = 0, started = false; for (let k = i + 1; k < Math.min(L.length, i + 60) && miss < 3; k++) { const r = L[k];
        if (textOnly(r) && (/^(table\s|\d+(\.\d+)+\s)/i.test(r.text) || (started && r.cells.length >= 2))) break;
        const res = fn(r, k); if (res === false) { if (textOnly(r) && soft < 8) soft++; else miss++; } else { miss = 0; if (res !== undefined || !textOnly(r)) started = true; } } };
      if ((nf >= 2 || (nf === 1 && !hf[0])) && !nl) {   // columns: lines down the side, measures across the top (one measure column is enough)
        rowsBelow((r, k) => { const ln = lineOf(r.cells[0].text, lob) || (r.cells[1] && /^LOB/i.test(r.cells[0].text) ? lineOf(r.cells[1].text, lob) : null); if (!ln) return r.cells.length >= 2 && r.cells.slice(1).some((c) => numOf(c.text)) && !/^\s*(total|sub-?total|grand total)\b/i.test(r.cells[0].text) ? undefined : false;   // another line of the same table
          for (const c of r.cells.slice(1)) { const j = colIndex(H, c); if (j >= 0 && hf[j]) add(p, k, ln, hp[j] || pageP, hf[j], c.text, 'columns', r.text); } });
      } else if (nl >= 2 && !nf) {   // rows: measures down the side, lines across the top
        rowsBelow((r, k) => { const f = fieldOf(r.cells[0].text); if (!f) return false;
          for (const c of r.cells.slice(1)) { const j = colIndex(H, c); if (j >= 0 && hl[j]) add(p, k, hl[j], pageP, f, c.text, 'rows', r.text); } });
      } else if (np >= 2 && !nl) {   // periods across the top, one measure named by the title or the first header cell
        const f = hf[0] || fieldOf(blockTitle.replace(/^(table\s+[\d.]+:?|\d+(\.\d+)+)\s*/i, '')) || (() => { for (let k = w - 1; k >= b0; k--) { const x = fieldOf(L[k].text.replace(/^table\s+[\d.]+:?\s*/i, '')); if (x) return x; } return null; })() || fieldOf(titleNear(p, i0)) || (() => { for (let k = i0 - 1; k >= Math.max(0, i0 - 3); k--) { const x = fieldOf(L[k].text.replace(/^table\s+[\d.]+:?\s*/i, '').slice(0, 90)); if (x) return x; } return null; })();
        if (f && f !== 'combined' || f === 'combined') rowsBelow((r, k) => { const ln = lineOf(r.cells[0].text, lob) || (r.cells[1] && /^LOB/i.test(r.cells[0].text) ? lineOf(r.cells[1].text, lob) : null); if (!ln) return r.cells.length >= 2 && r.cells.slice(1).some((c) => numOf(c.text)) && !/^\s*(total|sub-?total|grand total)\b/i.test(r.cells[0].text) ? undefined : false;   // another line of the same table
          if (!f) return; for (const c of r.cells.slice(1)) { const j = colIndex(H, c); if (j >= 0 && hp[j]) add(p, k, ln, hp[j], f, c.text, 'periods', r.text); } });
      }
    }
    curTitle = '';
    // prose: one line naming a line, a measure and a number
    for (let i = 0; i < L.length; i++) { const t = L[i].text; if (t.length > 400) continue;
      const f = (() => { for (const k of ORDER) if (FIELDS[k].re.test(t)) return k; return null; })(); if (!f) continue;
      const ln = (() => { const m = t.match(/(motor[^,.;:]{0,40}|(medical|health)[^,.;:]{0,30})/i); return m ? lineOf(m[0].replace(/\b(ultimate|loss|ratio|is|was|of|the|for|at|expense|commission|target|combined)\b.*$/i, '').trim(), lob) : null; })();
      const nums = (t.match(/\(?-?\d[\d,]*(\.\d+)?\)?\s*%/g) || []); if (!ln || nums.length !== 1 || L[i].cells.length > 3) continue;
      add(p, i, ln, periodOf(t) || docPeriod, f, nums[0], 'text', t); }
  }
  // one proposal per (period, line, sub-line, field, value): the same figure printed on several pages is one proposal with its pages
  const key = (x) => [x.period, x.line, x.sub_line, x.field, x.value].join('|'), seen = new Map();
  for (const x of out) { const k = key(x); if (seen.has(k)) { const y = seen.get(k); if (!y.pages.includes(x.page)) y.pages.push(x.page); } else seen.set(k, Object.assign({}, x, { pages: [x.page] })); }
  const props = [...seen.values()];
  // grouped for the page: per period + line + sub-line, each field with its candidates (more than one = the actuary chooses)
  const G = new Map(); for (const x of props) { const k = [x.period || '', x.line, x.sub_line || ''].join('|'); if (!G.has(k)) G.set(k, { period: x.period, line: x.line, sub_line: x.sub_line, fields: {} });
    const g = G.get(k); (g.fields[x.field] = g.fields[x.field] || []).push({ value: x.value, raw: x.raw, pages: x.pages, table: x.table, row: x.row, how: x.how, note: x.note }); }
  const groups = [...G.values()].map((g) => Object.assign(g, { found: Object.keys(g.fields).filter((k) => k !== 'combined').length, conflicts: Object.keys(g.fields).filter((k) => g.fields[k].length > 1),
    missing: ['nep', 'ulr', 'expense_ratio', 'target_loss_ratio'].filter((k) => !g.fields[k]) })).sort((a, b) => b.found - a.found || String(b.period).localeCompare(String(a.period)));
  if (!props.length) notes.push('no pricing figures were recognised. The reader looks for tables that name a line (Motor TPL / comprehensive, Medical individual / SME / corporate, or an LOB code the report maps to a name) together with measures (earned premium, ultimate loss ratio, expense, commission, target loss ratio, rate change). Enter the figures by hand, or send the report so the reader can learn its layout.');
  if (Object.keys(lob).length) notes.push('LOB codes named in the report: ' + Object.keys(lob).map((k) => k + ' = ' + lob[k]).join(', '));
  return { groups, proposals: props.length, lob_map: lob, period_guess: docPeriod, notes, fields: Object.fromEntries(Object.keys(FIELDS).map((k) => [k, FIELDS[k].label])), lines: LINES };
}
module.exports = { pricingFromPdf, _t: { lineOf, fieldOf, periodOf, numOf } };
