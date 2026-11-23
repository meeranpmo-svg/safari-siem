/* Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
 * zyb-assist.js - the Compliance Assistant (ITAM engine/compliance-assist.js, ML in pyengine/assist_rules.py).
 * Ask in plain words about SAMA + IA, NCA ECC, ISO 27001, NDMO or PDPL; the answer is built from the registers themselves by
 * machine learning on the server (no external AI). Used two ways:
 *   - compliance-assistant.html renders answers with zybAssist.render(el, answer)
 *   - on every compliance page a "? Ask" button opens a side panel scoped to that page's framework
 * Every value is escaped; no inline handlers (CSP); requests the page handles itself are marked zybQuiet. */
(function () {
  'use strict';
  var esc = function (s) { return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var PAGE = (location.pathname.split('/').pop() || '').replace(/\.html$/, '');
  var FW_OF = { 'sama-ia': 'sama', 'sama-compliance': 'sama', 'nca-ecc': 'ecc', 'iso27001': 'iso', 'ndmo': 'ndmo', 'pdpl-dashboard': 'pdpl', 'pdpl-assessment': 'pdpl', 'pdpl-programme': 'pdpl', 'audit-dashboard': '' };
  var INTENT = { explain: 'what it means', status: 'how we stand', why: 'why it is not met', todo: 'what to do', evidence: 'what evidence is needed', who: 'who approves' };
  var ST_CLS = { met: 'bg-green-lt', partial: 'bg-yellow-lt', gap: 'bg-red-lt', unknown: 'bg-secondary-lt', na: 'bg-secondary-lt' };

  function req(m, p, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, '/api/itam' + p); x.withCredentials = true; x.timeout = 60000; x.zybQuiet = true;
      if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not JSON: reported as the HTTP status */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('IT Asset Management is not reachable')); };
      x.send(b ? JSON.stringify(b) : null);
    });
  }
  function why(e) {
    if (e && e.status === 404 && !/older than|not in the/.test(e.message)) return 'The Compliance Assistant is not installed yet - run the update from the PC (git pull origin main, then scripts\\update-platform.ps1).';
    return (e && e.message) || 'request failed';
  }
  function section(label, text) { return text ? '<div class="mb-2"><div class="text-secondary small text-uppercase fw-bold">' + esc(label) + '</div><div>' + esc(text) + '</div></div>' : ''; }
  function match(m, open) {
    var also = (m.also || []).map(function (a) { return '<span class="badge bg-blue-lt me-1">' + esc(a.name + ' ' + a.id) + '</span>'; }).join('');
    return '<details class="as-m border rounded p-2 mb-2"' + (open ? ' open' : '') + '><summary class="d-flex gap-2 align-items-center flex-wrap">'
      + '<span class="badge ' + (ST_CLS[m.state] || '') + '">' + esc(m.status) + '</span> <b>' + esc(m.framework + ' ' + m.id) + '</b> <span class="text-secondary">· ' + esc(m.area) + '</span></summary>'
      + '<div class="mt-2">' + section('What it asks', m.what) + section('Where we stand', m.where) + section('What to do next', m.todo)
      + section('Evidence an auditor accepts', m.evidence) + section('Who approves', m.who) + section('How it is checked', m.checked + ' ' + m.importance)
      + (also ? '<div class="mb-2"><div class="text-secondary small text-uppercase fw-bold">Also counts for</div>' + also + '</div>' : '')
      + '<a class="small" href="' + esc(m.page) + '">Open the ' + esc(m.framework) + ' register</a></div></details>';
  }
  function first(list) {
    return '<ol class="as-first ps-3 mb-0">' + list.map(function (x) {
      return '<li class="mb-2"><div><span class="badge ' + (ST_CLS[x.state] || '') + ' me-1">' + esc(x.status) + '</span> ' + (x.page ? '<a href="' + esc(x.page) + '"><b>' + esc(x.framework + ' ' + x.id) + '</b> ' + esc(x.title) + '</a>' : '<b>' + esc(x.framework + ' ' + x.id) + '</b> ' + esc(x.title)) + '</div>'
        + '<div class="small">' + esc(x.todo) + '</div><div class="small text-secondary">Why first: ' + esc(x.why.join('; ')) + '</div></li>';
    }).join('') + '</ol>';
  }
  function render(el, a) {
    var h = '<div class="as-sum fs-3 mb-2">' + esc(a.summary) + '</div>';
    if (a.note) h += '<div class="alert alert-warning py-2">' + esc(a.note) + '</div>';
    h += '<div class="small text-secondary mb-2">Understood as: <b class="as-int">' + esc(INTENT[a.intent] || a.intent) + '</b>'
      + (a.framework ? ' · about <b>' + esc(a.framework) + '</b>' : '') + ' · ' + esc(a.engine) + '</div>';
    if (a.overview && a.intent === 'status') h += a.overview.frameworks.map(function (f) { return bars(f); }).join('');
    if (a.overview && a.overview.first.length) h += '<h4 class="mt-3">Do these first</h4>' + first(a.overview.first);
    (a.matches || []).forEach(function (m, i) { h += match(m, i === 0); });
    if ((a.glossary || []).length) h += '<div class="mt-2">' + a.glossary.map(function (g) { return '<div class="small"><b>' + esc(g.term) + '</b> - ' + esc(g.plain) + '</div>'; }).join('') + '</div>';
    if ((a.suggest || []).length) h += '<div class="mt-2 d-flex gap-1 flex-wrap">' + a.suggest.map(function (q) { return '<button type="button" class="btn btn-sm btn-ghost-primary" data-as-q="' + esc(q) + '">' + esc(q) + '</button>'; }).join('') + '</div>';
    if ((a.not_installed || []).length) h += '<div class="small text-secondary mt-2">Not installed, so not in this answer: ' + esc(a.not_installed.join(', ')) + '</div>';
    if (a.ask_id) h += '<div class="as-fb mt-3 d-flex gap-2 align-items-center flex-wrap" data-ask="' + esc(a.ask_id) + '"><span class="small text-secondary">Did this help?</span>'
      + '<button type="button" class="btn btn-sm" data-as-fb="yes">Yes</button><button type="button" class="btn btn-sm" data-as-fb="no">No</button>'
      + '<select class="form-select form-select-sm w-auto" data-as-meant aria-label="I meant"><option value="">I meant…</option>'
      + Object.keys(INTENT).map(function (k) { return '<option value="' + k + '">' + esc(INTENT[k]) + '</option>'; }).join('') + '</select></div>';
    el.innerHTML = h;
  }
  function bars(f) {
    var c = f.counts, t = c.total || 1, pc = function (n) { return (100 * n / t).toFixed(1) + '%'; };
    var tag = f.installed && f.page ? 'a' : 'div';   // a framework bar opens its register (the engine names the page)
    return '<' + tag + ' class="as-fw mb-2 d-block" data-fw="' + esc(f.fw) + '"' + (tag === 'a' ? ' href="' + esc(f.page) + '" title="Open the ' + esc(f.framework) + ' register"' : '') + '><div class="d-flex justify-content-between"><b>' + esc(f.framework) + '</b><span>' + (f.installed ? esc(c.pct_met + '% done') : 'not installed') + '</span></div>'
      + '<div class="progress progress-separated my-1" role="img" aria-label="' + esc(f.framework) + '">'
      + '<div class="progress-bar bg-green" style="width:' + pc(c.met) + '"></div><div class="progress-bar bg-yellow" style="width:' + pc(c.partial) + '"></div>'
      + '<div class="progress-bar bg-red" style="width:' + pc(c.gap) + '"></div><div class="progress-bar bg-secondary" style="width:' + pc(c.unknown) + '"></div></div>'
      + '<div class="small">' + esc(f.sentence) + '</div></' + tag + '>';
  }
  // ask + feedback wiring on a container that holds #as-q (input), #as-go and #as-out
  function wire(root, fwOf) {
    var q = root.querySelector('[data-as-input]'), out = root.querySelector('[data-as-out]'), busy = false;
    function ask(text) {
      if (busy) return; text = String(text || q.value || '').trim(); if (text.length < 2) { out.innerHTML = '<div class="text-secondary">Type a question first - for example: What should we fix first?</div>'; return; }
      q.value = text; busy = true; out.innerHTML = '<div class="text-secondary">Thinking…</div>';
      var b = { question: text }, fw = fwOf(); if (fw) b.fw = fw;
      req('POST', '/assist/ask', b).then(function (a) { render(out, a); }, function (e) { out.innerHTML = '<div class="alert alert-warning">' + esc(why(e)) + '</div>'; })
        .then(function () { busy = false; });
    }
    function rate(box, body) {
      req('POST', '/assist/feedback', Object.assign({ ask_id: box.getAttribute('data-ask') }, body)).then(function () {
        box.innerHTML = '<span class="small text-success">Thank you - the assistant learns from this.</span>';
      }, function (e) { box.innerHTML = '<span class="small text-warning">' + esc(why(e)) + '</span>'; });
    }
    root.addEventListener('click', function (ev) {
      var t = ev.target.closest('[data-as-q],[data-as-go],[data-as-fb]'); if (!t) return;
      if (t.hasAttribute('data-as-go')) return ask();
      if (t.hasAttribute('data-as-q')) return ask(t.getAttribute('data-as-q'));
      var box = t.closest('[data-ask]'); if (box) rate(box, { helpful: t.getAttribute('data-as-fb') === 'yes' });
    });
    root.addEventListener('change', function (ev) {
      var s = ev.target.closest('[data-as-meant]'); if (!s || !s.value) return;
      rate(s.closest('[data-ask]'), { helpful: false, intent: s.value });
    });
    q.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); ask(); } });
    return ask;
  }
  window.zybAssist = { render: render, bars: bars, first: first, wire: wire, req: req, why: why, esc: esc };

  // ---- the side panel on the compliance pages
  if (!(PAGE in FW_OF)) return;
  var CSS = '#as-b{position:fixed;right:20px;bottom:20px;z-index:1200;border:0;border-radius:24px;padding:11px 18px;font:600 13px Inter,system-ui,sans-serif;color:#fff;cursor:pointer;background:linear-gradient(135deg,#0ea5a4,#3987e5);box-shadow:0 6px 22px rgba(57,135,229,.35)}'
    + '#as-p{position:fixed;top:0;right:0;bottom:0;width:min(460px,100%);z-index:1250;background:var(--tblr-bg-surface,#181b1f);color:inherit;border-left:1px solid var(--tblr-border-color,#24272e);display:flex;flex-direction:column;box-shadow:-18px 0 40px rgba(0,0,0,.35)}'
    + '#as-p[hidden]{display:none}#as-p header{display:flex;gap:8px;align-items:center;padding:12px 14px;border-bottom:1px solid var(--tblr-border-color,#24272e)}#as-p .as-body{flex:1;overflow-y:auto;padding:12px 14px}';
  function mount() {
    var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);
    var b = document.createElement('button'); b.type = 'button'; b.id = 'as-b'; b.textContent = '? Ask about compliance'; document.body.appendChild(b);
    var p = document.createElement('aside'); p.id = 'as-p'; p.hidden = true; p.setAttribute('aria-label', 'Compliance Assistant');
    var sug = ['Are we compliant?', 'What should we fix first?', 'What does a gap mean?', 'Who approves the evidence?'];
    p.innerHTML = '<header><b>Compliance Assistant</b><span class="small text-secondary">plain answers from the registers</span><span class="ms-auto"></span><button type="button" class="btn btn-sm" id="as-x" aria-label="Close">✕</button></header>'
      + '<div class="as-body"><div class="input-group mb-2"><input class="form-control" data-as-input id="as-q" maxlength="500" placeholder="Ask in your own words…" aria-label="Your question"><button type="button" class="btn btn-primary" data-as-go>Ask</button></div>'
      + '<div class="d-flex gap-1 flex-wrap mb-2">' + sug.map(function (q) { return '<button type="button" class="btn btn-sm btn-ghost-primary" data-as-q="' + esc(q) + '">' + esc(q) + '</button>'; }).join('') + '</div>'
      + '<div data-as-out></div><div class="small mt-3"><a href="compliance-assistant.html">Open the full Compliance Assistant</a></div></div>';
    document.body.appendChild(p);
    wire(p, function () { return FW_OF[PAGE]; });
    b.addEventListener('click', function () { p.hidden = !p.hidden; if (!p.hidden) p.querySelector('#as-q').focus(); });
    p.querySelector('#as-x').addEventListener('click', function () { p.hidden = true; });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !p.hidden && !document.getElementById('zd')) p.hidden = true; });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount); else mount();
})();
