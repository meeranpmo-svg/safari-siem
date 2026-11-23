// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-copilot.js - the SOC Copilot panel beside every Security Operations page (SIEM engine/soc/copilot.js).
 * A "✦ Copilot" button opens a side panel: the Copilot knows the page and the record you are looking at (pages call
 * zybCopilot.context({kind, id}) when they open an alert, case, entity or query), answers from the platform's read tools,
 * and records PROPOSALS (open a case, add a note, close / assign an alert, add alerts to a case, save a hunt) as cards you
 * accept or reject - an accepted card runs as you. Every value is escaped; text from the model is never turned into a link.
 * Shown to analysts and above (its tools read alerts and events - PDPL). Needs zyb-soc.js. */
(function () {
  'use strict';
  var S = window.zybSoc; if (!S) return;
  var esc = S.esc, PAGE = (location.pathname.split('/').pop() || '').replace(/\.html$/, ''), CTX = { kind: 'none', id: '' }, CONV = '', BUSY = false, ST = null, root = null;
  var PAGES = ['soc-overview', 'soc-alerts', 'soc-cases', 'soc-hunt', 'soc-ueba', 'soc-ti'];
  var SUGGEST = {
    'soc-overview': ['What needs my attention first this shift?', 'Which rules are the noisiest and why?', 'Summarise the last 24 hours for the CISO'],
    'soc-alerts': ['Triage this alert: what happened and is it real?', 'What else did this user or host do?', 'Which open alerts look related?'],
    'soc-cases': ['Summarise this case and what is missing', 'Which open alerts belong to this case?', 'Draft the next investigation steps'],
    'soc-hunt': ['Explain these results', 'How do I narrow this query?', 'What should I hunt for next?'],
    'soc-ueba': ['Why is this entity risky?', 'Which findings are most likely benign?', 'What should I ask the manager?'],
    'soc-ti': ['Which threat-intel sightings are still open?', 'Is any listed indicator in recent traffic?', 'Which hosts talked to listed addresses?'] };
  var KIND = { open_case: 'Open a case', add_case_note: 'Add a note to a case', add_alerts_to_case: 'Add alerts to a case', close_alert: 'Close an alert', assign_alert: 'Assign an alert', save_hunt: 'Save a hunt' };
  var CSS = '#cop-b{position:fixed;right:20px;bottom:20px;z-index:1200;border:0;border-radius:24px;padding:11px 18px;font:600 13px Inter,system-ui,sans-serif;color:#fff;cursor:pointer;background:linear-gradient(135deg,#8f6bff,#5794f2);box-shadow:0 6px 22px rgba(87,148,242,.35)}'
    + '#cop-b:hover{filter:brightness(1.1)}#cop{position:fixed;top:0;right:0;bottom:0;width:min(440px,100%);z-index:1250;background:var(--v-panel,#181b1f);color:var(--v-ink,#d8d9da);border-left:1px solid var(--v-line,#24272e);display:flex;flex-direction:column;box-shadow:-18px 0 40px rgba(0,0,0,.35);font:13px/1.5 Inter,system-ui,sans-serif}'
    + '#cop[hidden]{display:none}#cop header{display:flex;align-items:center;gap:8px;padding:12px 14px;border-bottom:1px solid var(--v-line,#24272e)}#cop header b{font-size:14px}#cop header .sp{flex:1}'
    + '#cop .cb{background:var(--v-panel2,#1f2228);color:inherit;border:1px solid var(--v-line,#24272e);border-radius:7px;padding:4px 9px;font-size:12px;cursor:pointer}#cop .cb:hover{border-color:var(--v-acc,#5794f2)}#cop .cb.pri{background:var(--v-acc,#5794f2);border-color:var(--v-acc,#5794f2);color:#fff}#cop .cb.ok{border-color:var(--v-ok,#73bf69)}#cop .cb.bad{border-color:var(--v-crit,#f2495c)}'
    + '#cop .ctx{margin:8px 14px 0;font-size:11.5px;color:var(--v-mute,#8e8e8e)}#cop .ctx b{color:var(--v-ink,#d8d9da)}#cop .msgs{flex:1;overflow-y:auto;padding:10px 14px}'
    + '#cop .m{margin:0 0 12px}#cop .m.q{background:rgba(87,148,242,.12);border-radius:10px;padding:8px 10px;margin-left:30px}#cop .m.a{background:rgba(184,119,217,.07);border:1px solid rgba(184,119,217,.3);border-radius:10px;padding:9px 11px}'
    + '#cop .m.a p{margin:0 0 6px}#cop .m.a ul{margin:4px 0 6px 18px;padding:0}#cop .steps{font-size:11px;color:var(--v-mute,#8e8e8e);margin-top:4px}#cop .pc{border:1px solid var(--v-warn,#ff9830);border-radius:9px;padding:8px 10px;margin:6px 0;background:rgba(255,152,48,.06)}'
    + '#cop .pc .k{font-weight:700}#cop .pc .p{font-size:11.5px;color:var(--v-mute,#8e8e8e);margin:3px 0 6px;word-break:break-word}#cop .sug{display:flex;flex-direction:column;gap:6px;margin-top:6px}#cop .sug button{text-align:left}'
    + '#cop form{display:flex;gap:6px;padding:10px 14px;border-top:1px solid var(--v-line,#24272e)}#cop textarea{flex:1;resize:none;height:54px;background:var(--v-panel2,#1f2228);color:inherit;border:1px solid var(--v-line,#24272e);border-radius:8px;padding:7px 9px;font:13px Inter,system-ui,sans-serif}'
    + '#cop .note{font-size:11px;color:var(--v-mute,#8e8e8e);padding:0 14px 10px}#cop .err{color:var(--v-warn,#ff9830)}#cop select{background:var(--v-panel2,#1f2228);color:inherit;border:1px solid var(--v-line,#24272e);border-radius:7px;font-size:12px;max-width:150px}';
  // escaped text -> a few safe tags only: **bold**, `code`, bullet lines, paragraphs. Never a link.
  function md(t) {
    var lines = esc(t).split('\n'), out = [], ul = false;
    lines.forEach(function (l) {
      var m = /^\s*(?:[-*•]|\d+\.)\s+(.*)$/.exec(l);
      if (m) { if (!ul) { out.push('<ul>'); ul = true; } out.push('<li>' + inl(m[1]) + '</li>'); return; }
      if (ul) { out.push('</ul>'); ul = false; }
      if (l.trim()) out.push('<p>' + inl(l) + '</p>');
    });
    if (ul) out.push('</ul>');
    return out.join('');
  }
  function inl(s) { return s.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>'); }
  function params(p) { return Object.keys(p.params || {}).map(function (k) { var v = p.params[k]; return k + ': ' + (Array.isArray(v) ? v.join(', ') : v); }).join(' · '); }
  function card(p) {
    var can = S.can(p.needs_role || 'operator');
    return '<div class="pc" data-pid="' + esc(p.id) + '"><div class="k">✦ ' + esc(KIND[p.kind] || p.kind) + ' <span class="steps">' + esc(p.id) + ' · ' + esc(p.status) + '</span></div><div class="p">' + esc(params(p)) + (p.reason ? '<br>Why: ' + esc(p.reason) : '') + '</div>'
      + (p.status === 'pending' ? (can ? '<button type="button" class="cb ok" data-acc="' + esc(p.id) + '">Accept - run it as me</button> <button type="button" class="cb bad" data-rej="' + esc(p.id) + '">Reject</button>' : '<span class="steps">Accepting needs the ' + esc(p.needs_role) + ' role.</span>')
        : '<span class="steps">' + esc(p.status) + ' by ' + esc(p.decided_by || '') + (p.result ? ' · ' + esc(JSON.stringify(p.result)) : '') + '</span>') + '</div>';
  }
  function add(html) { var m = root.querySelector('.msgs'), d = document.createElement('div'); d.innerHTML = html; while (d.firstChild) m.appendChild(d.firstChild); m.scrollTop = m.scrollHeight; }
  function ctxLine() { var c = root.querySelector('.ctx'); c.innerHTML = 'Context: <b>' + esc(PAGE.replace('soc-', '') || 'SOC') + '</b>' + (CTX.kind !== 'none' && CTX.id ? ' · ' + esc(CTX.kind) + ' <b>' + esc(CTX.id) + '</b>' : ''); }
  function welcome() {
    var m = root.querySelector('.msgs'); m.innerHTML = '';
    add('<div class="m a"><p><b>SOC Copilot</b> - ask about what you are looking at. I read alerts, cases, events, behaviour and threat intel; when something is worth doing I <b>propose</b> it here and you decide.</p><div class="sug">'
      + (SUGGEST[PAGE] || SUGGEST['soc-overview']).map(function (s) { return '<button type="button" class="cb" data-sug="' + esc(s) + '">' + esc(s) + '</button>'; }).join('') + '</div></div>');
  }
  function build() {
    var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);
    var b = document.createElement('button'); b.id = 'cop-b'; b.type = 'button'; b.textContent = '✦ Copilot'; b.setAttribute('aria-controls', 'cop'); document.body.appendChild(b);
    root = document.createElement('aside'); root.id = 'cop'; root.hidden = true; root.setAttribute('aria-label', 'SOC Copilot');
    root.innerHTML = '<header><b>✦ SOC Copilot</b><span class="steps" id="cop-m"></span><span class="sp"></span><select id="cop-h" aria-label="Earlier conversations"><option value="">Earlier chats…</option></select><button type="button" class="cb" id="cop-new">New</button><button type="button" class="cb" id="cop-x" aria-label="Close">✕</button></header>'
      + '<div class="ctx"></div><div class="msgs" role="log" aria-live="polite"></div><form id="cop-f"><textarea id="cop-q" maxlength="4000" placeholder="Ask about this page… (Enter to send, Shift+Enter for a new line)" aria-label="Ask the Copilot"></textarea><button type="submit" class="cb pri" id="cop-s">Ask</button></form>'
      + '<div class="note">The Copilot proposes; you decide. It cannot contain, block or disable - those stay approval requests for a named approver.</div>';
    document.body.appendChild(root);
    b.addEventListener('click', function () { root.hidden = !root.hidden; if (!root.hidden) { ctxLine(); history(); root.querySelector('#cop-q').focus(); } });
    root.querySelector('#cop-x').addEventListener('click', function () { root.hidden = true; });
    root.querySelector('#cop-new').addEventListener('click', function () { CONV = ''; welcome(); });
    root.querySelector('#cop-h').addEventListener('change', function () { if (this.value) load(this.value); });
    root.querySelector('#cop-f').addEventListener('submit', function (e) { e.preventDefault(); ask(); });
    root.querySelector('#cop-q').addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(); } });
    root.addEventListener('click', function (e) {
      var x;
      if ((x = e.target.closest('[data-sug]'))) { root.querySelector('#cop-q').value = x.getAttribute('data-sug'); ask(); return; }
      if ((x = e.target.closest('[data-acc]')) || (x = e.target.closest('[data-rej]'))) {
        var acc = x.hasAttribute('data-acc'), id = x.getAttribute(acc ? 'data-acc' : 'data-rej');
        x.disabled = true;
        S.req('POST', '/soc/copilot/proposals/' + encodeURIComponent(id) + '/decide', { decision: acc ? 'accept' : 'reject' }).then(function (p) {
          var c = root.querySelector('[data-pid="' + id + '"]'); if (c) c.outerHTML = card(p);
          S.toast(acc ? 'Done - recorded with your name' : 'Rejected');
          if (acc && typeof window.zybCopilotRefresh === 'function') window.zybCopilotRefresh();
        }).catch(function (er) { x.disabled = false; S.toast(er.message); });
      }
    });
    welcome();
  }
  function history() { S.req('GET', '/soc/copilot/conversations').then(function (r) { var h = root.querySelector('#cop-h'); h.innerHTML = '<option value="">Earlier chats…</option>' + r.items.map(function (c) { return '<option value="' + esc(c.id) + '">' + esc(c.title) + '</option>'; }).join(''); }).catch(function () { /* the list is optional; asking still works */ }); }
  function load(id) {
    S.req('GET', '/soc/copilot/conversations/' + encodeURIComponent(id)).then(function (c) {
      CONV = c.id; root.querySelector('.msgs').innerHTML = '';
      c.turns.forEach(function (t) { add(t.role === 'analyst' ? '<div class="m q">' + esc(t.text) + '</div>' : '<div class="m a">' + md(t.text) + '</div>'); });
      c.proposals.forEach(function (p) { add(card(p)); });
    }).catch(function (e) { S.toast(e.message); });
  }
  function ask() {
    var q = root.querySelector('#cop-q').value.trim(); if (!q || BUSY) return;
    BUSY = true; root.querySelector('#cop-q').value = ''; var sb = root.querySelector('#cop-s'); sb.disabled = true; sb.textContent = '…';
    add('<div class="m q">' + esc(q) + '</div><div class="m a" id="cop-wait"><p class="steps">Investigating…</p></div>');
    var body = { question: q, context: { page: PAGES.indexOf(PAGE) >= 0 ? PAGE : 'other', kind: CTX.kind, id: String(CTX.id || '').slice(0, 300) } }; if (CONV) body.conversation = CONV;
    S.req('POST', '/soc/copilot/ask', body).then(function (r) {
      CONV = r.conversation; var w = document.getElementById('cop-wait'); if (w) w.remove();
      var used = r.steps.filter(function (s) { return s.ok; }).map(function (s) { return s.tool; });
      add('<div class="m a">' + md(r.answer) + (used.length ? '<div class="steps">Used: ' + esc(used.join(', ')) + '</div>' : '') + ((r.injection_signals || []).length ? '<div class="steps err">The data contained text that looks like instructions to the AI - check the answer.</div>' : '') + '</div>');
      r.proposals.forEach(function (p) { add(card(p)); });
    }).catch(function (e) { var w = document.getElementById('cop-wait'); if (w) w.innerHTML = '<p class="err">' + esc(e.message) + '</p>'; })
      .then(function () { BUSY = false; sb.disabled = false; sb.textContent = 'Ask'; });
  }
  // ask(q): a page button puts a question to the Copilot (opens the panel, same route, same rules); false when it is not available
  window.zybCopilot = { context: function (c) { CTX = { kind: (c && c.kind) || 'none', id: (c && c.id) || '' }; if (root && !root.hidden) ctxLine(); },
    ready: function () { return !!(root && ST && ST.enabled); },
    ask: function (q) { if (!root || !ST || !ST.enabled || BUSY) return false; root.hidden = false; ctxLine(); root.querySelector('#cop-q').value = String(q || '').slice(0, 2000); ask(); return true; } };
  S.ready(function () {
    if (!S.can('analyst')) return;   // a viewer gets no Copilot: its tools read alerts and events
    S.req('GET', '/soc/copilot/status').then(function (s) { ST = s; build(); root.querySelector('#cop-m').textContent = s.enabled ? s.model : ''; if (!s.enabled) add('<div class="m a err">' + esc(s.reason || 'The Copilot is not available.') + '</div>'); })
      .catch(function () { /* the SIEM does not have the Copilot yet (not updated): no button rather than a broken one */ });
  });
})();
