// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Zyberon AI DLP - content script on AI app pages. Checks what the person is about to give the AI - a paste, a message on
 * Enter or Send, a file chosen or dropped - LOCALLY with classify.js, and under the organisation's policy (from the SIEM via
 * the service worker): allow, warn (Cancel / Send anyway) or block. An app the register blocks is covered by a notice.
 * Only metadata goes to the service worker (the app, the kinds and counts, what happened) - never the text or a file name.
 * Residual: a person who can turn the extension off or use another browser is not covered (force-install it by policy and
 * block other browsers); text typed character by character into a page that has no send button we recognise is checked on
 * Enter only. Indicators, not proof. */
(function () {
  'use strict';
  if (window.__zybAiDlp) return; window.__zybAiDlp = true;
  var C = self.ZybAiDlp, POLICY = null, APP = null, allowOnce = null, PASS = '__zybAiDlpChecked';
  var send = function (ev) { try { chrome.runtime.sendMessage({ type: 'event', ev: ev }); } catch (e) { /* the extension was reloaded: nothing to report to */ } };

  // ---------------- the notice and the dialog (shadow DOM: the page's styles cannot change them, nothing from the page is shown)
  var host = null;
  function shell() {
    if (host && host.isConnected) return host.shadowRoot;
    host = document.createElement('zyb-ai-dlp'); host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;inset:auto 0 0 0';
    var r = host.attachShadow({ mode: 'closed' }); host.__r = r;
    var st = document.createElement('style');
    st.textContent = '.box{font:14px/1.5 system-ui,"Segoe UI",Tahoma,sans-serif;color:#0F172A;background:#fff;border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.35);padding:18px 20px;max-width:440px;margin:0 auto 24px;border-top:4px solid #2F7BF6}'
      + '.box.bad{border-top-color:#DC2626}.t{font-weight:700;font-size:15px;margin:0 0 6px}.p{margin:0 0 12px;color:#334155}.row{display:flex;gap:8px;justify-content:flex-end}'
      + 'button{font:600 13px system-ui,sans-serif;border-radius:9px;padding:8px 14px;border:1px solid #CBD5E1;background:#fff;color:#0F172A;cursor:pointer}button.go{background:#DC2626;border-color:#DC2626;color:#fff}button.ok{background:#2F7BF6;border-color:#2F7BF6;color:#fff}'
      + '.page{position:fixed;inset:0;background:rgba(3,8,23,.92);display:flex;align-items:center;justify-content:center}.page .box{margin:0}';
    r.appendChild(st); (document.body || document.documentElement).appendChild(host);
    return r;
  }
  function root() { var r = shell(); return host.__r || r; }
  function box(kind, title, text, buttons) {
    var r = root(); [].slice.call(r.querySelectorAll('.wrap')).forEach(function (x) { x.remove(); });
    var w = document.createElement('div'); w.className = 'wrap' + (kind === 'page' ? ' page' : '');
    var b = document.createElement('div'); b.className = 'box' + (kind !== 'info' ? ' bad' : ''); b.setAttribute('role', kind === 'info' ? 'status' : 'alertdialog');
    var t = document.createElement('p'); t.className = 't'; t.textContent = title; var p = document.createElement('p'); p.className = 'p'; p.textContent = text;
    var row = document.createElement('div'); row.className = 'row';
    (buttons || []).forEach(function (x) { var bt = document.createElement('button'); bt.textContent = x.label; if (x.cls) bt.className = x.cls; bt.addEventListener('click', function () { w.remove(); x.fn && x.fn(); }); row.appendChild(bt); });
    b.appendChild(t); b.appendChild(p); if (buttons && buttons.length) b.appendChild(row); w.appendChild(b); r.appendChild(w);
    if ((!buttons || !buttons.length) && kind !== 'page') setTimeout(function () { w.remove(); }, 6000);
    var first = row.querySelector('button'); if (first) first.focus();
    return w;
  }
  function report(action, channel, found, extra) {
    send(Object.assign({ ts: Date.now(), app: APP.id, host: location.hostname.toLowerCase(), action: action, channel: channel, kinds: found ? found.kinds : {}, classes: found ? found.classes : [] }, extra || {}));
  }
  // one check: returns true when the action may go ahead now; otherwise the person is told and asked (warn) or stopped (block)
  function check(text, channel, onSendAnyway, extra, onStop) {
    if (!APP || !POLICY) return true;
    if (allowOnce && allowOnce === text) { allowOnce = null; return true; }
    var found = C.classify(text, POLICY.keywords), d = C.decide(APP, found, POLICY.mode);
    if (d.action === 'allow') return true;
    var what = C.describe(found.kinds), name = APP.name;
    if (d.action === 'block') {
      report('blocked', channel, found, extra); if (onStop) onStop();
      box('bad', 'Not sent to ' + name, 'This contains ' + what + '. Company policy does not allow this data in ' + name + '. Remove it and try again, or use an approved tool.', [{ label: 'OK', cls: 'ok' }]);
      return false;
    }
    box('bad', 'Check before sending to ' + name, 'This contains ' + what + '. ' + name + ' is not approved for this data. Sending it is recorded.', [
      { label: 'Cancel', cls: 'ok', fn: function () { report('warned', channel, found, extra); if (onStop) onStop(); } },
      { label: 'Send anyway', cls: 'go', fn: function () { report('sent_after_warning', channel, found, extra); onSendAnyway && onSendAnyway(); } },
    ]);
    return false;
  }

  // ---------------- what the person gives the AI
  function composerText(t) {
    var el = t && t.closest ? t.closest('textarea,input[type=text],[contenteditable=""],[contenteditable=true],[role=textbox]') : null;
    if (!el) el = document.activeElement;
    if (!el) return '';
    return el.value !== undefined && el.tagName !== 'DIV' ? String(el.value || '') : String(el.innerText || el.textContent || '');
  }
  function onPaste(e) {
    var txt = e.clipboardData ? e.clipboardData.getData('text/plain') : '';
    if (!txt) return;
    if (!check(txt, 'paste', function () { allowOnce = txt; try { document.execCommand('insertText', false, txt); } catch (x) { /* the page refuses: the person pastes again */ } })) { e.preventDefault(); e.stopImmediatePropagation(); }
  }
  function onKey(e) {
    if (e.key !== 'Enter' || e.shiftKey || e.isComposing || e[PASS]) return;
    var t = e.target; if (!t || !(t.tagName === 'TEXTAREA' || t.isContentEditable || (t.getAttribute && t.getAttribute('role') === 'textbox'))) return;
    var txt = composerText(t);
    if (txt && !check(txt, 'submit', function () { allowOnce = txt; box('info', 'Press Enter again to send', 'The message is ready.', []); })) { e.preventDefault(); e.stopImmediatePropagation(); }
  }
  function onClick(e) {
    var b = e.target && e.target.closest ? e.target.closest('button[type=submit],button[aria-label*="Send" i],button[data-testid*="send" i],[role=button][aria-label*="Send" i]') : null;
    if (!b || e[PASS]) return;
    var form = b.closest('form'), area = (form || document).querySelector('textarea,[contenteditable=true],[contenteditable=""],[role=textbox]');
    var txt = area ? composerText(area) : '';
    if (txt && !check(txt, 'submit', function () { allowOnce = txt; box('info', 'Press Send again', 'The message is ready.', []); })) { e.preventDefault(); e.stopImmediatePropagation(); }
  }
  // files: read locally (text and Office files), only the extension leaves
  function readZip(buf) {   // Office files: the XML text parts (stored or deflated entries)
    var v = new DataView(buf), eocd = -1;
    for (var i = buf.byteLength - 22; i >= Math.max(0, buf.byteLength - 66000); i--) if (v.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) return Promise.resolve('');
    var count = v.getUint16(eocd + 10, true), p = v.getUint32(eocd + 16, true), parts = [];
    for (var k = 0; k < count && p + 46 <= buf.byteLength; k++) {
      if (v.getUint32(p, true) !== 0x02014b50) break;
      var method = v.getUint16(p + 10, true), csize = v.getUint32(p + 20, true), nlen = v.getUint16(p + 28, true), xlen = v.getUint16(p + 30, true), clen = v.getUint16(p + 32, true), loc = v.getUint32(p + 42, true);
      var name = new TextDecoder().decode(new Uint8Array(buf, p + 46, nlen)); p += 46 + nlen + xlen + clen;
      if (!/^(word\/(document|header\d*|footer\d*)|xl\/(sharedStrings|worksheets\/sheet\d+)|ppt\/slides\/slide\d+)\.xml$/.test(name) || loc + 30 > buf.byteLength) continue;
      var start = loc + 30 + v.getUint16(loc + 26, true) + v.getUint16(loc + 28, true), data = new Uint8Array(buf, start, Math.min(csize, buf.byteLength - start));
      if (method === 0) parts.push(Promise.resolve(new TextDecoder().decode(data)));
      else if (method === 8 && typeof DecompressionStream === 'function') parts.push(new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).text().catch(function () { return ''; /* a damaged part: not read */ }));
    }
    return Promise.all(parts).then(function (x) { return x.join(' ').replace(/<[^>]+>/g, ' '); });
  }
  function fileText(f) {
    var ext = (String(f.name).split('.').pop() || '').toLowerCase();
    if (f.size > 20 * 1024 * 1024) return Promise.resolve({ ext: ext, text: '' });
    if (/^(txt|csv|tsv|log|json|xml|html?|md|sql|py|js|ts|java|cs|ps1|sh|yml|yaml|ini|conf|env|pem|key)$/.test(ext)) return f.slice(0, 2 * 1024 * 1024).text().then(function (t) { return { ext: ext, text: t }; });
    if (/^(docx|xlsx|pptx)$/.test(ext)) return f.arrayBuffer().then(readZip).then(function (t) { return { ext: ext, text: t }; });
    return Promise.resolve({ ext: ext, text: '' });
  }
  function checkFiles(files, again, stop) {
    return Promise.all([].slice.call(files || []).map(fileText)).then(function (rs) {
      var text = rs.map(function (r) { return r.text; }).join('\n'), ext = rs.length ? rs[0].ext.slice(0, 10).replace(/[^a-z0-9]/g, '') : '';
      return check(text, 'file', again, ext ? { file_type: ext } : {}, stop);
    });
  }
  function onChange(e) {
    var inp = e.target; if (!inp || inp.type !== 'file' || e[PASS] || !inp.files || !inp.files.length || !APP || !POLICY) return;
    e.stopImmediatePropagation();
    var resend = function () { var ev = new Event('change', { bubbles: true }); ev[PASS] = true; inp.dispatchEvent(ev); };
    // blocked or cancelled: the choice is cleared; Send anyway hands the same files to the page
    checkFiles(inp.files, resend, function () { try { inp.value = ''; } catch (x) { /* a read-only input: the page never received the files */ } })
      .then(function (ok) { if (ok) resend(); }, function () { resend(); /* unreadable: the page decides, the policy cannot see inside */ });
  }
  function onDrop(e) {
    var dt = e.dataTransfer; if (e[PASS] || !dt || !dt.files || !dt.files.length || !APP || !POLICY) return;
    e.preventDefault(); e.stopImmediatePropagation();
    var target = e.target, files = [].slice.call(dt.files), x = e.clientX, y = e.clientY;
    var resend = function () { var d = new DataTransfer(); files.forEach(function (f) { d.items.add(f); }); var ev = new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: d, clientX: x, clientY: y }); ev[PASS] = true; target.dispatchEvent(ev); };
    checkFiles(files, resend).then(function (ok) { if (ok) resend(); }, function () { resend(); /* unreadable: the page decides */ });
  }

  function blockPage() {
    var go = function () {
      report('page_blocked', 'navigate', null);
      box('page', APP.name + ' is not approved', 'The company has not approved ' + APP.name + ' for work data. Use an approved AI tool - ask the IT Service Desk which ones.', []);
    };
    if (document.body) go(); else document.addEventListener('DOMContentLoaded', go);
  }

  function start(policy) {
    POLICY = policy; APP = C.appFor(location.hostname, policy && policy.apps);
    if (!APP) return;
    if (APP.status === 'blocked') { blockPage(); return; }
    document.addEventListener('paste', onPaste, true);
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('click', onClick, true);
    document.addEventListener('change', onChange, true);
    document.addEventListener('drop', onDrop, true);
  }
  try { chrome.runtime.sendMessage({ type: 'policy' }, function (p) { if (chrome.runtime.lastError) { start(null); return; } start(p || null); }); }
  catch (e) { start(null); /* no service worker: nothing is checked, and the page says nothing */ }
})();
