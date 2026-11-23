// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-errors.js - error handling for every page (loaded by zyb-dash.js on the dashboards and by zyb-menu.js in the portal).
 *
 * What it catches: an uncaught error, a promise nobody handled, a file of the page that did not load, and every request
 * (XMLHttpRequest and fetch) that fails - no answer, timed out, 5xx, or 401 (the session has ended).
 * What the person sees: one short message in English or Arabic - what failed, that the rest of the page still works, a
 * reference number and Details / Copy / Reload - never a blank or frozen page, never a stack trace. The same failure is
 * shown once every two minutes, at most three messages at a time. A 401 says the session has ended, with Sign in again.
 * What the administrator sees: each error is reported to Platform Health (POST /api/itam/platform/client-errors) with the
 * page, the message and the reference - no request body, no query string (PDPL), at most 20 reports per page view.
 * The portal loads it quiet (window.ZYB_ERR_QUIET): it reports, but leaves the portal's own messages alone.
 * A page that handles a failure itself can mark the request so it is not shown twice: x.zybQuiet = true (XHR) or
 * fetch(url, {zybQuiet: true}); window.zybErrors.show(message) shows a message in the same style.
 */
(function () {
  'use strict';
  if (window.zybErrors) return;
  var QUIET = !!window.ZYB_ERR_QUIET, REPORT = '/api/itam/platform/client-errors';
  var AR = window.ZYB_ARABIC === true && (function () { try { return (JSON.parse(localStorage.getItem('zyb-dash-prefs') || '{}') || {}).lang === 'ar'; } catch (e) { return false; } })();
  var TXT = {
    title: ['Something went wrong', 'حدث خطأ'],
    still: ['The rest of the page still works.', 'باقي الصفحة يعمل.'],
    net: ['The server did not answer - check the connection or try again in a minute.', 'لم يستجب الخادم - تحقّق من الاتصال أو أعد المحاولة بعد دقيقة.'],
    timeout: ['The server took too long to answer - try again.', 'استغرق الخادم وقتاً طويلاً للرد - أعد المحاولة.'],
    server: ['The server could not complete this request', 'تعذّر على الخادم إكمال هذا الطلب'],
    session: ['Your session has ended - sign in again to continue.', 'انتهت جلستك - سجّل الدخول مجدداً للمتابعة.'],
    file: ['A part of this page did not load', 'لم يتم تحميل جزء من هذه الصفحة'],
    page: ['This page hit an unexpected error', 'واجهت هذه الصفحة خطأً غير متوقع'],
    details: ['Details', 'التفاصيل'], copy: ['Copy', 'نسخ'], reload: ['Reload', 'إعادة التحميل'], close: ['Dismiss', 'إغلاق'], signin: ['Sign in again', 'تسجيل الدخول مجدداً'],
    copied: ['Copied', 'تم النسخ'], ref: ['Reference', 'المرجع']
  };
  function T(k) { return TXT[k] ? TXT[k][AR ? 1 : 0] : k; }
  // errors that are not the page's fault and tell nobody anything
  var IGNORE = /ResizeObserver loop|^Script error\.?$|AbortError|The user aborted|cancell?ed|chrome-extension:|moz-extension:|safari-extension:/i;
  var origFetch = window.fetch ? window.fetch.bind(window) : null;
  var seen = {}, reports = 0, stack = [];
  function ref() { return 'E-' + Date.now().toString(36).slice(-5).toUpperCase() + Math.random().toString(36).slice(2, 5).toUpperCase(); }
  function pathOf(u) { try { return new URL(String(u), location.href).pathname; } catch (e) { return String(u || '').split('?')[0]; } }

  function report(kind, message, extra) {
    if (reports >= 20 || !origFetch) return;
    reports++;
    var body = { kind: kind, page: location.pathname, message: String(message || '').slice(0, 300), ref: extra && extra.ref };
    if (extra) { if (extra.status) body.status = extra.status; if (extra.url) body.url = pathOf(extra.url); if (extra.source) body.source = pathOf(extra.source); if (extra.line) body.line = extra.line; }
    try { origFetch(REPORT, { method: 'POST', credentials: 'same-origin', keepalive: true, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).catch(function () { /* reporting is best effort */ }); } catch (e) { /* best effort */ }
  }

  /* ---- the message ---- */
  function css() {
    if (document.getElementById('zyb-err-css')) return;
    var s = document.createElement('style'); s.id = 'zyb-err-css';
    s.textContent = '#zyb-err{position:fixed;right:16px;bottom:16px;z-index:2147483000;display:flex;flex-direction:column;gap:8px;max-width:min(420px,calc(100vw - 32px));font:13px/1.45 system-ui,"Segoe UI",sans-serif}'
      + 'html[dir=rtl] #zyb-err{right:auto;left:16px}'
      + '#zyb-err .ze{background:#1b1e24;color:#e8eef7;border:1px solid #3a2a2e;border-left:4px solid #f2495c;border-radius:10px;padding:10px 12px;box-shadow:0 10px 28px rgba(0,0,0,.45)}'
      + 'html[dir=rtl] #zyb-err .ze{border-left:1px solid #3a2a2e;border-right:4px solid #f2495c}'
      + '#zyb-err .ze.warn{border-left-color:#ff9830}#zyb-err .ze b{display:block;margin-bottom:2px}#zyb-err .ze .zm{opacity:.9}#zyb-err .ze .zr{opacity:.6;font-size:11.5px;margin-top:4px}'
      + '#zyb-err .ze pre{white-space:pre-wrap;word-break:break-word;background:#111317;border-radius:6px;padding:6px 8px;margin:6px 0 0;font:11.5px/1.4 ui-monospace,Consolas,monospace;max-height:140px;overflow:auto;display:none}#zyb-err .ze.open pre{display:block}'
      + '#zyb-err .ze .zb{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}#zyb-err .ze button,#zyb-err .ze a{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.16);color:#e8eef7;border-radius:6px;padding:3px 9px;font:600 12px system-ui,sans-serif;cursor:pointer;text-decoration:none}'
      + '#zyb-err .ze button:hover,#zyb-err .ze a:hover{background:rgba(255,255,255,.14)}#zyb-err .ze .zp{background:#d7262d;border-color:#d7262d}'
      + '@media print{#zyb-err{display:none}}';
    (document.head || document.documentElement).appendChild(s);
  }
  function box() { var b = document.getElementById('zyb-err'); if (!b && document.body) { b = document.createElement('div'); b.id = 'zyb-err'; b.setAttribute('role', 'alert'); b.setAttribute('aria-live', 'assertive'); document.body.appendChild(b); } return b; }
  function btn(label, cls, fn) { var b = document.createElement('button'); b.type = 'button'; b.textContent = label; if (cls) b.className = cls; b.addEventListener('click', fn); return b; }

  /* show(title, message, detail, opts) - opts: {key, ref, sticky, warn, signin} */
  function show(title, message, detail, opts) {
    opts = opts || {};
    var key = opts.key || (title + '|' + message), t = Date.now();
    if (seen[key] && t - seen[key] < 120000) return null;   // the same failure once every two minutes
    seen[key] = t;
    if (!document.body) { document.addEventListener('DOMContentLoaded', function () { delete seen[key]; show(title, message, detail, opts); }); return null; }
    css(); var b = box(); if (!b) return null;
    var el = document.createElement('div'); el.className = 'ze' + (opts.warn ? ' warn' : '');
    var h = document.createElement('b'); h.textContent = title; el.appendChild(h);
    var m = document.createElement('div'); m.className = 'zm'; m.textContent = message; el.appendChild(m);
    if (opts.ref) { var r = document.createElement('div'); r.className = 'zr'; r.textContent = T('ref') + ': ' + opts.ref; el.appendChild(r); }
    var pre = null; if (detail) { pre = document.createElement('pre'); pre.textContent = detail; el.appendChild(pre); }
    var bar = document.createElement('div'); bar.className = 'zb';
    if (opts.signin) { var a = document.createElement('a'); a.href = '/'; a.className = 'zp'; a.textContent = T('signin'); bar.appendChild(a); }
    if (pre) bar.appendChild(btn(T('details'), '', function () { el.classList.toggle('open'); }));
    bar.appendChild(btn(T('copy'), '', function (e) {
      var txt = [title, message, opts.ref ? T('ref') + ': ' + opts.ref : '', location.pathname, new Date().toISOString(), detail || ''].filter(Boolean).join('\n');
      try { navigator.clipboard.writeText(txt).then(function () { e.target.textContent = T('copied'); }, function () {}); } catch (x) { /* no clipboard */ }
    }));
    if (!opts.signin) bar.appendChild(btn(T('reload'), '', function () { location.reload(); }));
    bar.appendChild(btn(T('close'), '', function () { el.remove(); }));
    el.appendChild(bar);
    b.appendChild(el); stack.push(el);
    while (stack.length > 3) { var old = stack.shift(); if (old.parentNode) old.remove(); }
    if (!opts.sticky) setTimeout(function () { if (el.parentNode && !el.classList.contains('open')) el.remove(); }, 15000);
    return el;
  }

  /* ---- what failed ---- */
  function failed(kind, title, message, detail, extra, opts) {
    var r = ref(); extra = extra || {}; extra.ref = r;
    report(kind, (message + (detail ? ' - ' + detail : '')).slice(0, 300), extra);
    if (QUIET) return;   // the portal shows its own messages
    show(title, message, detail, Object.assign({ ref: r }, opts || {}));
  }
  function onHttp(status, url, method, timedOut) {
    var p = pathOf(url);
    if (p === REPORT || /\/whoami(\.json)?$|\/auth\//.test(p)) return;   // our own report, the sign-in checks: they handle themselves
    if (status === 401) return failed('session', T('title'), T('session'), '', { status: 401, url: url }, { key: 'session', sticky: true, warn: true, signin: true });
    if (timedOut) return failed('timeout', T('title'), T('timeout') + ' ' + T('still'), method + ' ' + p, { url: url }, { key: 'to|' + p });
    if (status === 0) return failed('network', T('title'), T('net') + ' ' + T('still'), method + ' ' + p, { url: url }, { key: 'net|' + p });
    if (status >= 500) return failed('http', T('title'), T('server') + ' (HTTP ' + status + '). ' + T('still'), method + ' ' + p, { status: status, url: url }, { key: status + '|' + p });
  }

  window.addEventListener('error', function (e) {
    var t = e.target;
    if (t && t !== window && (t.tagName === 'SCRIPT' || t.tagName === 'LINK')) {   // a file of the page did not load
      var src = t.src || t.href || ''; if (IGNORE.test(src)) return;
      return failed('error', T('title'), T('file') + '. ' + T('still'), pathOf(src), { source: src }, { key: 'file|' + pathOf(src) });
    }
    var msg = (e.error && e.error.message) || e.message || '';
    if (!msg || IGNORE.test(msg) || IGNORE.test(e.filename || '')) return;
    failed('error', T('title'), T('page') + '. ' + T('still'), msg, { source: e.filename, line: e.lineno }, { key: 'err|' + msg });
  }, true);
  window.addEventListener('unhandledrejection', function (e) {
    var r = e.reason, msg = r && (r.message || r.error || r.statusText) || (typeof r === 'string' ? r : '');
    if (r && r.zybShown) return;   // already shown by the request hooks below
    msg = String(msg || 'unknown error');
    if (IGNORE.test(msg) || (r && r.name === 'AbortError')) return;
    failed('rejection', T('title'), T('page') + '. ' + T('still'), msg, {}, { key: 'rej|' + msg });
  });

  /* ---- every request ---- */
  try {
    var XO = XMLHttpRequest.prototype.open, XS = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (m, u) { this.__zyb = { m: String(m || 'GET').toUpperCase(), u: u }; return XO.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function () {
      var x = this, info = x.__zyb || { m: 'GET', u: '' }, to = false, ab = false;
      x.addEventListener('timeout', function () { to = true; });
      x.addEventListener('abort', function () { ab = true; });
      x.addEventListener('loadend', function () { if (ab || x.zybQuiet) return; if (to || x.status === 0 || x.status === 401 || x.status >= 500) onHttp(x.status, info.u, info.m, to); });
      return XS.apply(this, arguments);
    };
  } catch (e) { /* requests are still made, only not watched */ }
  if (origFetch) {
    window.fetch = function (input, init) {
      var quiet = init && init.zybQuiet, url = typeof input === 'string' ? input : (input && input.url) || '', m = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
      return origFetch(input, init).then(function (res) {
        if (!quiet && (res.status === 401 || res.status >= 500)) onHttp(res.status, url, m, false);
        return res;
      }, function (err) {
        if (!quiet && !(err && err.name === 'AbortError')) { onHttp(0, url, m, false); try { err.zybShown = true; } catch (x) { /* frozen error */ } }
        throw err;
      });
    };
  }

  /* ---- "not installed on the server": point at the cause ----
   * A page that gets a 404 from its API says "... is not installed on the server". That is the symptom; the cause (a module
   * the update could not start, a file it did not copy, the engine rolled back) is on Platform Admin -> Update Health, read
   * from the service log. Add that link next to every such message, once, on every page - text only, never innerHTML. */
  try {
    if (!/update-health\.html$/.test(location.pathname)) {
      var uhT = 0, uhScan = function () {
        uhT = 0; if (!document.body) return;
        var w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null), t, hits = [];
        while ((t = w.nextNode())) if (/not installed (on|or|yet)/i.test(t.nodeValue) && t.parentNode && !t.parentNode.closest('script,style,a,textarea')) hits.push(t.parentNode);
        hits.forEach(function (el) {
          if (el.querySelector(':scope > a.zyb-uh-link')) return;   // a page that rewrites the message gets the link again
          var a = document.createElement('a'); a.href = 'update-health.html'; a.className = 'zyb-uh-link';
          a.textContent = ' Why? See Platform Admin \u2192 Update Health for the cause and the fix.';
          a.style.cssText = 'color:#7aa7ff;margin-left:4px;font-weight:600'; el.appendChild(a);
        });
      };
      var uhObs = new MutationObserver(function () { if (!uhT) uhT = setTimeout(uhScan, 250); });
      var uhStart = function () { if (document.body) { uhObs.observe(document.body, { childList: true, subtree: true, characterData: true }); uhScan(); } };
      if (document.body) uhStart(); else document.addEventListener('DOMContentLoaded', uhStart);
    }
  } catch (e) { /* older browser without MutationObserver: the message still shows, only without the link */ }

  window.zybErrors = { show: function (message, detail) { return show(T('title'), String(message || ''), detail ? String(detail) : '', { ref: ref(), key: 'app|' + message }); }, report: report, quiet: QUIET };
})();
