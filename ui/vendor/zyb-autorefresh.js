// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-autorefresh.js - keeps an administration page current without getting in the way.
 *   window.zybAutoRefresh({ load, every: 30, into: element|id, label? }) -> { now(), pause(), resume(), state() }
 * Every `every` seconds it calls the page's own load() - the same read the page does on opening; nothing new is sent - but NOT
 * while the person is working: the tab is hidden; a field has focus; something was typed or changed in the last 60 s; a dialog,
 * drawer or confirmation is open; text is selected; a form field holds an unsaved change; or the person paused it. A skipped round is retried on the next tick, and
 * the page is read again as soon as the tab is shown. The scroll position is kept. A chip shows when the page was last read and
 * lets the person pause / resume (the choice is kept per page in this browser) or refresh now. No inline handlers (CSP). */
(function () {
  'use strict';
  var IDLE_MS = 60000;
  var edited = [];
  var IGNORE = function (x) { return !x || !x.matches || !x.matches('input, textarea, select') || x.closest('.zyb-ar') || x.type === 'search' || x.type === 'checkbox' && x.closest('table') || x.hasAttribute('data-ar-ignore') || /search|find|filter/i.test(x.placeholder || '') || /^(q|lq|dq|fq|uq|pq|search)$/i.test(x.id || ''); };
  function busy(lastInput) {
    var a = document.activeElement;
    if (a && (/^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) || a.isContentEditable) && a.type !== 'checkbox' && a.type !== 'radio' && a.type !== 'button') return 'a field is in use';
    if (Date.now() - lastInput < IDLE_MS) return 'you were typing';
    if (document.querySelector('.dlg-bg.open, dialog[open], .drawer[aria-hidden="false"], .drawer.open, [role="dialog"].open, .modal.show, .modal.open')) return 'a dialog is open';
    var sel = window.getSelection && window.getSelection(); if (sel && String(sel).length > 2) return 'text is selected';
    // a form field the person edited and has not acted on yet (save / cancel = any button click; a re-rendered field is gone)
    for (var k = edited.length - 1; k >= 0; k--) { if (!edited[k].isConnected) edited.splice(k, 1); }
    if (edited.length) return 'a change is not saved yet';
    return '';
  }
  function fmt(d) { try { return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); } catch (e) { return d.toISOString().slice(11, 19); } }
  window.zybAutoRefresh = function (o) {
    var every = Math.max(10, Math.min(600, Number(o.every) || 30)) * 1000, key = 'zyb-autorefresh:' + location.pathname, lastInput = 0, last = Date.now(), running = false, why = '';
    var paused = false; try { paused = localStorage.getItem(key) === 'off'; } catch (e) { paused = false; /* no storage (private window): not paused */ }
    var host = typeof o.into === 'string' ? document.getElementById(o.into) : o.into;
    var chip = document.createElement('span'); chip.className = 'zyb-ar'; chip.setAttribute('role', 'status');
    chip.style.cssText = 'display:inline-flex;gap:6px;align-items:center;font:12px Inter,"Segoe UI",system-ui,sans-serif;color:#8b93a4;border:1px solid #232837;border-radius:999px;padding:3px 4px 3px 10px;white-space:nowrap';
    chip.innerHTML = '<span data-ar-t></span><button type="button" data-ar-now title="Refresh now" style="all:unset;cursor:pointer;padding:0 6px">⟳</button><button type="button" data-ar-p style="all:unset;cursor:pointer;padding:0 8px;border-left:1px solid #232837"></button>';
    if (host) host.appendChild(chip);
    function paint() {
      var t = chip.querySelector('[data-ar-t]'), p = chip.querySelector('[data-ar-p]');
      t.innerHTML = '<span>Updated</span> <span class="mono" data-no-tr>' + fmt(new Date(last)) + '</span>' + (paused ? ' · <span>auto-refresh paused</span>' : why ? ' · <span>waiting</span> - <span>' + why + '</span>' : ' · <span>auto every</span> <span class="mono" data-no-tr>' + every / 1000 + ' s</span>');
      p.textContent = paused ? 'Resume' : 'Pause';
    }
    function run(force) {
      if (running) return; if (!force) { if (paused || document.hidden) return; why = busy(lastInput); if (why) { paint(); return; } }
      running = true; why = ''; var y = window.scrollY, r;
      try { r = o.load(); } catch (e) { running = false; paint(); return; }
      Promise.resolve(r).then(function () { last = Date.now(); }, function () { /* the page shows its own error; the chip keeps the last good time */ })
        .then(function () { running = false; if (Math.abs(window.scrollY - y) > 2) window.scrollTo(0, y); paint(); });
    }
    ['input', 'keydown', 'change', 'paste'].forEach(function (ev) { document.addEventListener(ev, function (e) { if (e.target && e.target.closest && e.target.closest('.zyb-ar')) return; lastInput = Date.now();
      if ((ev === 'input' || ev === 'change') && !IGNORE(e.target) && edited.indexOf(e.target) < 0) edited.push(e.target); }, true); });
    // a button click is the person acting on what they typed (save, cancel, apply): their edits are no longer pending
    document.addEventListener('click', function (e) { if (e.target.closest && e.target.closest('button, [type=submit], a.btn') && !e.target.closest('.zyb-ar')) edited.length = 0; }, true);
    chip.addEventListener('click', function (e) {
      if (e.target.closest('[data-ar-now]')) { run(true); return; }
      if (e.target.closest('[data-ar-p]')) { paused = !paused; try { localStorage.setItem(key, paused ? 'off' : 'on'); } catch (x) { /* not kept across visits without storage */ } if (!paused) run(false); paint(); }
    });
    document.addEventListener('visibilitychange', function () { if (!document.hidden && Date.now() - last > every / 2) run(false); });
    var timer = setInterval(function () { run(false); }, every);
    paint();
    return { now: function () { run(true); }, pause: function () { paused = true; paint(); }, resume: function () { paused = false; paint(); }, state: function () { return { paused: paused, last: last, waiting: why, every: every / 1000 }; }, stop: function () { clearInterval(timer); } };
  };
})();
