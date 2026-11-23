/* Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
 * Shared helpers for the PDPL pages (pdpl-*.html): the ITAM request, escaping, tiles, tables, forms built from a field list
 * (the server validates the same fields and drops anything else), and the strip that links the PDPL pages together.
 * No inline handlers: pages wire with addEventListener / delegated clicks. Every value reaching innerHTML is escaped. */
(function () {
  'use strict';
  // Arabic for the PDPL pages (vendor/zyb-pdpl-ar.js): only when Customize -> Language = العربية; written now so it is in place
  // before the page draws (zyb-lang.js swaps the words as they appear)
  try { if (window.zybLang && window.zybLang.lang === 'ar' && !window.zybPdplAr) { if (document.readyState === 'loading') document.write('<script src="vendor/zyb-pdpl-ar.js"><\/script>'); else { var ar = document.createElement('script'); ar.src = 'vendor/zyb-pdpl-ar.js'; document.head.appendChild(ar); } } } catch (e) { /* English only */ }
  // helper text under every field of the compliance forms (vendor/zyb-form-hints.js): what to enter, with an example
  try { if (!window.zybFormHints) { if (document.readyState === 'loading') document.write('<script src="vendor/zyb-form-hints.js"><\/script>'); else { var fh = document.createElement('script'); fh.src = 'vendor/zyb-form-hints.js'; document.head.appendChild(fh); } } } catch (e) { /* the forms work without the helper text */ }
  var esc = function (s) { return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var $ = function (id) { return document.getElementById(id); };
  function req(m, p, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, '/api/itam' + p); x.withCredentials = true; x.timeout = 60000; x.zybQuiet = true;
      if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not JSON: reported below as HTTP status */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status, path: m + ' ' + p })); };
      x.onerror = x.ontimeout = function () { bad(new Error('IT Asset Management is not reachable')); };
      x.send(b ? JSON.stringify(b) : null);
    });
  }
  function why(e) {
    // a role refusal gets the explanation; a four-eyes or DPO-only refusal keeps the server's own words
    if (e && e.status === 403 && (!e.message || /requires|role|HTTP 403/i.test(e.message))) return 'These PDPL records need the operator role (a named person) - they are personal-data records themselves.';
    if (e && e.status === 404) return 'The server part of this page is not installed or not running yet (' + (e.path || 'HTTP 404') + '). Run the update from the PC: git pull origin main, then scripts\\update-platform.ps1 - add-duty.sh installs the IT Asset Management modules and restarts it. If it still shows, run sudo zyb-ai-ready on the server: it names the missing file.';
    if (e && e.status === 409 && /Python/.test(e.message)) return e.message;
    return (e && e.message) || 'request failed';
  }
  function fail(el, e) { if (el) el.innerHTML = '<div class="card-body"><div class="alert alert-warning mb-0">' + esc(why(e)) + '</div></div>'; }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast-zyb'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 4500); }
  function tile(v, l, cls) { return '<div class="col-6 col-md-3"><div class="card card-sm"><div class="card-body"><div class="au-num' + (cls ? ' ' + cls : '') + '">' + esc(v === null || v === undefined ? '—' : v) + '</div><div class="au-lbl">' + esc(l) + '</div></div></div></div>'; }
  function badge(t, c) { return '<span class="badge bg-' + (c || 'secondary') + '-lt">' + esc(t) + '</span>'; }
  var dt = function (v) { return v ? String(v).replace('T', ' ').replace(/:\d\d(\.\d+)?Z$|Z$/, '').slice(0, 16) : '—'; };
  // cols: [[label, fn(row) -> html (already escaped)]]; attr(row) -> extra <tr> attributes (escaped by the caller)
  function table(cols, rows, attr, empty) {
    if (!rows || !rows.length) return '<div class="card-body text-secondary">' + esc(empty || 'Nothing recorded yet.') + '</div>';
    return '<table class="table table-vcenter card-table table-sm"><thead><tr>' + cols.map(function (c) { return '<th>' + esc(c[0]) + '</th>'; }).join('') + '</tr></thead><tbody>'
      + rows.map(function (r) { return '<tr' + (attr ? ' ' + attr(r) : '') + '>' + cols.map(function (c) { return '<td>' + c[1](r) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table>';
  }
  // f: [name, type, label, required?, options?]; types: text, area, date, dtl, num, sel, multi, bool, list
  function form(id, f, rec, submit, extra) {
    rec = rec || {};
    var h = f.map(function (x) {
      var n = x[0], t = x[1], v = rec[n], lab = esc(x[2]) + (x[3] ? ' *' : ''), fid = id + '-' + n;
      if (t === 'bool') return '<label class="form-check mb-2"><input type="checkbox" class="form-check-input" name="' + esc(n) + '"' + (v ? ' checked' : '') + '><span class="form-check-label">' + lab + '</span></label>';
      if (t === 'sel') return '<div class="mb-2"><label class="form-label" for="' + fid + '">' + lab + '</label><select class="form-select" id="' + fid + '" name="' + esc(n) + '"><option value=""></option>' + x[4].map(function (o) { var ov = Array.isArray(o) ? o[0] : o, ol = Array.isArray(o) ? o[1] : o; return '<option value="' + esc(ov) + '"' + (v === ov ? ' selected' : '') + '>' + esc(ol) + '</option>'; }).join('') + '</select></div>';
      if (t === 'multi') return '<div class="mb-2"><div class="form-label">' + lab + '</div><div class="d-flex flex-wrap gap-2">' + x[4].map(function (o) { return '<label class="form-check form-check-inline m-0"><input type="checkbox" class="form-check-input" name="' + esc(n) + '" value="' + esc(o) + '"' + ((v || []).indexOf(o) >= 0 ? ' checked' : '') + '><span class="form-check-label">' + esc(o) + '</span></label>'; }).join('') + '</div></div>';
      if (t === 'area') return '<div class="mb-2"><label class="form-label" for="' + fid + '">' + lab + '</label><textarea class="form-control" rows="3" id="' + fid + '" name="' + esc(n) + '" maxlength="1000">' + esc(v || '') + '</textarea></div>';
      var it = { date: 'date', dtl: 'datetime-local', num: 'number', pass: 'password' }[t] || 'text';
      var val = t === 'pass' ? '' : t === 'list' ? (v || []).join(', ') : t === 'dtl' && v ? String(v).slice(0, 16).replace('Z', '') : (v === undefined || v === null ? '' : v);   // a secret is never put back into a page
      return '<div class="mb-2"><label class="form-label" for="' + fid + '">' + lab + '</label><input class="form-control" type="' + it + '" id="' + fid + '" name="' + esc(n) + '" value="' + esc(val) + '" maxlength="500"' + (t === 'pass' ? ' autocomplete="new-password"' : '') + (x[3] ? ' required' : '') + '></div>';
    }).join('');
    return '<form id="' + esc(id) + '" data-fields="' + esc(JSON.stringify(f.map(function (x) { return [x[0], x[1]]; }))) + '">' + h + (extra || '') + '<div class="d-flex gap-2 align-items-center mt-2"><button type="submit" class="btn btn-primary">' + esc(submit || 'Save') + '</button><span class="small text-secondary" data-msg></span></div><div class="small text-secondary mt-1">Written to the audit trail.</div></form>';
  }
  function body(fm) {
    var f = JSON.parse(fm.getAttribute('data-fields') || '[]'), o = {};
    f.forEach(function (x) {
      var n = x[0], t = x[1];
      if (t === 'multi') { o[n] = [].slice.call(fm.querySelectorAll('input[name="' + n + '"]:checked')).map(function (i) { return i.value; }); return; }
      var el = fm.elements[n]; if (!el) return;
      if (t === 'bool') { o[n] = el.checked; return; }
      var v = String(el.value || '').trim(); if (!v) return;
      if (t === 'num') o[n] = Number(v);
      else if (t === 'list') o[n] = v.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      else if (t === 'dtl') o[n] = v.slice(0, 16) + 'Z';
      else o[n] = v;
    });
    return o;
  }
  function msg(fm, t) { var m = fm.querySelector('[data-msg]'); if (m) m.textContent = t; }
  var PAGES = [['pdpl-dashboard.html', 'Dashboard', 'ti-chart-donut'], ['pdpl-office.html', 'Privacy Office', 'ti-route'], ['pdpl-programme.html', 'Programme', 'ti-sitemap'], ['pdpl-governance.html', 'Governance', 'ti-building-bank'], ['pdpl-assessment.html', 'Self-assessment', 'ti-checklist'], ['ai-pdpl.html', 'AI PDPL Consultant', 'ti-robot'], ['pdpl-policies.html', 'Policies', 'ti-file-certificate'], ['pdpl-ropa.html', 'Records of processing', 'ti-list-details'], ['pdpl-ropa-collect.html', 'RoPA by department', 'ti-building-community'], ['pdpl-catalog.html', 'Data catalog', 'ti-books'], ['pdpl-sensitive.html', 'Sensitive data', 'ti-lock'],
    ['pdpl-dsar.html', 'Data subject requests', 'ti-user-question'], ['pdpl-dpia.html', 'DPIA', 'ti-scale'], ['pdpl-transfers.html', 'Cross-border transfers', 'ti-world-share'],
    ['pdpl-breach.html', 'Breach response', 'ti-alarm'], ['pdpl-access.html', 'Access intelligence', 'ti-eye-check'], ['pdpl-processors.html', 'Processors', 'ti-building']];
  function strip() {
    var el = $('pdplnav'); if (!el) return;
    var me = (location.pathname.split('/').pop() || '').toLowerCase();
    el.innerHTML = PAGES.map(function (p) { return '<a class="btn btn-sm ' + (p[0] === me ? 'btn-primary' : 'btn-ghost-secondary') + '" href="' + esc(p[0]) + '"><i class="ti ' + esc(p[2]) + ' me-1"></i>' + esc(p[1]) + '</a>'; }).join('')
      + '<div class="w-100 small text-secondary mt-1" data-pdpl-source>Source of truth: ' + SOURCES.map(function (x) { return '<a href="' + esc(x[1]) + '" target="_blank" rel="noopener noreferrer">' + esc(x[0]) + '</a>'; }).join(' · ')
      + '. Article references on these pages follow these texts; where a page and the official text differ, the official text applies.</div>';
  }
  // the official texts published by SDAIA - the PDPL rules (pyengine/pdpl_rules.py, pdpl_workflows.py) cite their articles
  var SOURCES = [['Personal Data Protection Law (Royal Decree M/19, amended by M/148) - SDAIA', 'https://sdaia.gov.sa/en/SDAIA/about/Documents/PersonalDataProtectionLaw.pdf'],
    ['Implementing Regulation of the PDPL - SDAIA', 'https://sdaia.gov.sa/en/SDAIA/about/Documents/ImplementingRegulation.pdf']];
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', strip); else strip();
  // a finding's title / recommendation in the page language: the engine sends title_ar / recommendation_ar (pyengine/pdpl_ar.py)
  function ar(o, k) { return o && o[k + '_ar'] && window.zybLang && window.zybLang.lang === 'ar' ? o[k + '_ar'] : o && o[k]; }
  window.zybPdpl = { ar: ar, esc: esc, $: $, req: req, fail: fail, why: why, toast: toast, tile: tile, badge: badge, dt: dt, table: table, form: form, body: body, msg: msg };
})();
