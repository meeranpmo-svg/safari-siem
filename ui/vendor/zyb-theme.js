// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-theme.js - Light mode for colours a dashboard page wrote literally (in its <style>, its stylesheets or a style=""):
 * zyb-theme.css switches every shared token, but a page that wrote "color:#3fb950" or "background:#13161d" for a dark
 * screen would keep them on a light one. In ☀️ Light this reads the page's own CSS rules and inline colours and adds the
 * readable counterpart, keeping the hue:
 *   text      a light / bright colour is darkened until it reads on white (contrast ≥ 4.5; greys map to the text greys)
 *   surface   a dark opaque background becomes the matching light one (lightness inverted)
 *   border    a dark border becomes a light hairline
 * Tabler's own stylesheet is skipped (data-bs-theme switches it) and so are rules already written for a theme. Switching
 * back to Dark NOC / Midnight removes everything it added. Loaded by zyb-look.js on dashboard pages and the portal (rules the portal wrote for its own themes are left alone). */
(function () {
  'use strict';
  if (window.zybThemeFix) return;
  var STYLE_ID = 'zyb-theme-fix', MARK = 'data-zyb-tf';
  function parse(v) {
    var m = /rgba?\(\s*([\d.]+)[ ,]+([\d.]+)[ ,]+([\d.]+)(?:[ ,/]+([\d.]+%?))?\s*\)/.exec(v || ''); if (m) return { r: +m[1], g: +m[2], b: +m[3], a: m[4] == null ? 1 : (/%$/.test(m[4]) ? parseFloat(m[4]) / 100 : +m[4]) };
    m = /^#([0-9a-f]{3,8})$/i.exec(String(v || '').trim()); if (!m) return null;
    var h = m[1]; if (h.length === 3 || h.length === 4) h = h.split('').map(function (c) { return c + c; }).join('');
    return { r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16), a: h.length === 8 ? parseInt(h.slice(6, 8), 16) / 255 : 1 };
  }
  function lum(c) { var f = function (v) { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); }
  function toHsl(c) { var r = c.r / 255, g = c.g / 255, b = c.b / 255, mx = Math.max(r, g, b), mn = Math.min(r, g, b), l = (mx + mn) / 2, h = 0, s = 0;
    if (mx !== mn) { var d = mx - mn; s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn); h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; h /= 6; }
    return { h: h, s: s, l: l }; }
  function fromHsl(o, a) { var h = o.h, s = o.s, l = o.l, r, g, b;
    if (!s) { r = g = b = l; } else { var q = l < 0.5 ? l * (1 + s) : l + s - l * s, p = 2 * l - q, t = function (x) { if (x < 0) x += 1; if (x > 1) x -= 1; return x < 1 / 6 ? p + (q - p) * 6 * x : x < 1 / 2 ? q : x < 2 / 3 ? p + (q - p) * (2 / 3 - x) * 6 : p; }; r = t(h + 1 / 3); g = t(h); b = t(h - 1 / 3); }
    var c = { r: Math.round(r * 255), g: Math.round(g * 255), b: Math.round(b * 255) };
    return a < 1 ? 'rgba(' + c.r + ',' + c.g + ',' + c.b + ',' + a + ')' : 'rgb(' + c.r + ',' + c.g + ',' + c.b + ')'; }
  var contrastWhite = function (c) { return 1.05 / (lum(c) + 0.05); };
  // text: readable on a light surface
  function text(v) {
    var c = parse(v); if (!c || c.a < 0.3) return null;
    if (contrastWhite(c) >= 5.5) return null;                 // already dark enough (5.5: it often sits on a tinted pill)
    var o = toHsl(c);
    if (o.s < 0.18) return o.l > 0.86 ? '#1f2633' : o.l > 0.66 ? '#3d4554' : '#5e6675';   // greys: the text greys
    for (var i = 0; i < 40 && o.l > 0.05; i++) { o.l -= 0.02; var t = parse(fromHsl(o, 1)); if (contrastWhite(t) >= 5.5) break; }
    o.s = Math.min(1, o.s * 1.05);
    return fromHsl(o, c.a);
  }
  // surface: a dark opaque fill becomes light (a translucent tint keeps working on both)
  function surface(v) {
    var c = parse(v); if (!c || lum(c) > 0.12) return null;
    if (c.a < 0.6) {   // translucent: a tinted dark "glass" card becomes light glass; a black scrim (modal backdrop) stays
      if (c.a < 0.3 || Math.max(c.r, c.g, c.b) <= 8) return null;
      return 'rgba(255,255,255,' + Math.min(0.92, c.a + 0.4).toFixed(2) + ')';
    }
    var o = toHsl(c); o.l = Math.min(0.995, 0.99 - o.l * 0.3); if (o.s < 0.45) o.s *= 0.2;   // near-white, nearly neutral: the dark navy greys do not turn into blue-grey
    return fromHsl(o, c.a);
  }
  function border(v) {
    var c = parse(v); if (!c || c.a < 0.3 || lum(c) > 0.2) return null;
    var o = toHsl(c); o.l = 0.86 - o.l * 0.3; o.s *= 0.4; return fromHsl(o, c.a);
  }
  function scope(sel) {   // the selector, only while Light is on
    return sel.split(/,(?![^(]*\))/).map(function (x) {
      x = x.trim(); if (!x) return '';
      if (/^:root\b/.test(x)) return x.replace(/^:root/, 'html[data-zyb-theme="light"]');
      if (/^html\b/.test(x)) return x.replace(/^html((?:[.#\[:][^ >+~]*)?)/, 'html$1[data-zyb-theme="light"]');
      return 'html[data-zyb-theme="light"] ' + x;
    }).filter(Boolean).join(',');
  }
  var PROPS = [['color', text], ['background-color', surface], ['border-top-color', border], ['border-right-color', border], ['border-bottom-color', border], ['border-left-color', border]];
  function rulesOf(sheet, out) {
    var list; try { list = sheet.cssRules; } catch (e) { return; }   // another origin: not ours to read
    if (!list) return;
    for (var i = 0; i < list.length; i++) {
      var r = list[i];
      if (r.cssRules && !r.selectorText) { if (!r.media || !/print/.test(r.media.mediaText || '')) rulesOf(r, out); continue; }
      if (!r.selectorText || !r.style || /data-zyb-theme|data-theme|data-bs-theme|prefers-color-scheme/.test(r.selectorText)) continue;
      var decl = [];
      // the page's own colour variables (:root{--green:#3fb950;--panel:#13161d}): by name - surfaces lighten, lines lighten,
      // text and status colours darken until they read on white
      for (var v = 0; v < r.style.length; v++) {
        var name = r.style[v]; if (name.indexOf('--') !== 0 || /^--(tblr|v-|m-|zyb)/.test(name)) continue;
        var val = r.style.getPropertyValue(name).trim(); if (!val || /var\(|gradient|\s/.test(val.replace(/,\s*/g, ','))) continue;
        var fn = /bg|back|surf|panel|card|canvas|well|raise|input|top|side|bar|head|ink$|base|layer|tile|chip-bg/i.test(name) ? surface
          : /line|border|edge|grid|rule|sep|divid|stroke/i.test(name) ? border : text;
        var nv0 = fn(val); if (nv0) decl.push(name + ':' + nv0 + '!important');
      }
      for (var k = 0; k < PROPS.length; k++) {
        var raw = r.style.getPropertyValue(PROPS[k][0]); if (!raw || /var\(|gradient|currentcolor|inherit|transparent/i.test(raw)) continue;
        // text on the rule's OWN fill (a coloured header / button with white text): the fill decides, leave the text
        if (PROPS[k][0] === 'color') { var ownBg = r.style.getPropertyValue('background-color') || r.style.getPropertyValue('background'); if (ownBg && !/transparent|none|rgba\([^)]*,\s*0(\.0?[0-5])?\)/.test(ownBg) && !surface(ownBg)) continue; }
        var nv = PROPS[k][1](raw); if (nv) decl.push(PROPS[k][0] + ':' + nv + '!important');
      }
      if (decl.length) out.push(scope(r.selectorText) + '{' + decl.join(';') + '}');
    }
  }
  function sheets() {
    var out = [];
    for (var i = 0; i < document.styleSheets.length; i++) {
      var s = document.styleSheets[i], href = s.href || '', own = s.ownerNode;
      if (own && own.id === STYLE_ID) continue;
      // zyb-color.css (the company colour layer) carries its own light-look rules: darkening its white banner text would undo them
      if (/tabler\.min\.css|zyb-theme\.css|zyb-color\.css|fonts\.googleapis/.test(href)) continue;
      rulesOf(s, out);
    }
    return out.join('\n');
  }
  // inline style="" colours (pages that build rows with style="color:#…")
  function inline(root) {
    var els = (root || document).querySelectorAll('[style*="color"],[style*="background"]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i]; if (el.hasAttribute(MARK) || el.closest('svg')) continue;
      var st = el.style, keep = {};
      [['color', text], ['background-color', surface]].forEach(function (p) { var v = st.getPropertyValue(p[0]); if (!v || /var\(|gradient/.test(v)) return; var nv = p[1](v); if (nv) { keep[p[0]] = v + (st.getPropertyPriority(p[0]) ? '!' : ''); st.setProperty(p[0], nv, 'important'); } });
      // a coloured fill set inline (a status tile): the text inside it reads against that fill, not the page
      var fill = parse(st.getPropertyValue('background-color') || st.getPropertyValue('background'));
      if (fill && fill.a > 0.6 && lum(fill) > 0.12 && !keep['background-color']) {
        var ink = lum(fill) < 0.36 ? '#ffffff' : '#111827';
        [el].concat([].slice.call(el.querySelectorAll('*'))).forEach(function (x) { if (x.closest('svg') || (x !== el && x.hasAttribute(MARK))) return;
          var k2 = x === el ? keep : {}; k2.color = x.style.getPropertyValue('color') + (x.style.getPropertyPriority('color') ? '!' : ''); x.style.setProperty('color', ink, 'important');
          if (x !== el) x.setAttribute(MARK, JSON.stringify(k2)); });
      }
      el.setAttribute(MARK, Object.keys(keep).length ? JSON.stringify(keep) : '');
    }
  }
  function uninline() {
    var els = document.querySelectorAll('[' + MARK + ']');
    for (var i = 0; i < els.length; i++) { var el = els[i], k = el.getAttribute(MARK); el.removeAttribute(MARK); if (!k) continue; try { var o = JSON.parse(k); Object.keys(o).forEach(function (p) { var v = o[p], imp = /!$/.test(v), raw = v.replace(/!$/, ''); if (raw) el.style.setProperty(p, raw, imp ? 'important' : ''); else el.style.removeProperty(p); }); } catch (e) { /* leave it as it is */ } }
  }
  // the last safety net: any visible text still under 3:1 against what is really behind it gets plain dark or white ink
  // (a colour variable used both as text and as a fill cannot be right both ways from the CSS alone)
  function guard() {
    if (!on() || !document.body) return;
    var cache = new Map(), n = 0;
    function bgOf(el) {
      if (!el || el.nodeType !== 1) return { r: 255, g: 255, b: 255, a: 1 };
      if (cache.has(el)) return cache.get(el);
      var st = getComputedStyle(el), img = st.backgroundImage, under = bgOf(el.parentElement), c = under;
      if (img && img !== 'none' && /gradient|url/.test(img)) c = null;
      else if (under) { var b = parse(st.backgroundColor); if (b && b.a > 0) c = { r: b.r * b.a + under.r * (1 - b.a), g: b.g * b.a + under.g * (1 - b.a), b: b.b * b.a + under.b * (1 - b.a), a: 1 }; }
      cache.set(el, c); return c;
    }
    var els = document.body.querySelectorAll('body *');
    for (var i = 0; i < els.length && n < 6000; i++) {
      // an element inline() already marked is checked too: inline() marks every style="" naming a colour (border-color, a
      // var() it cannot read, white text on its own var() fill), so skipping marked ones left that text unreadable
      var el = els[i]; if (el.closest('svg,canvas,.toast,.toast-zyb,#zyb-err')) continue;
      var has = false; for (var j = 0; j < el.childNodes.length; j++) { var t = el.childNodes[j]; if (t.nodeType === 3 && t.nodeValue.trim().length > 1) { has = true; break; } }
      if (!has) continue; n++;
      var st = getComputedStyle(el); if (st.visibility !== 'visible') continue;
      var fg = parse(st.color), bg = bgOf(el); if (!fg || !bg) continue;
      var f = fg.a < 1 ? { r: fg.r * fg.a + bg.r * (1 - fg.a), g: fg.g * fg.a + bg.g * (1 - fg.a), b: fg.b * fg.a + bg.b * (1 - fg.a) } : fg;
      var L1 = lum(f), L2 = lum(bg), ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
      if (ratio >= 3) continue;
      var ink = (1.05 / (L2 + 0.05)) >= ((L2 + 0.05) / 0.0625) ? '#ffffff' : '#111827';
      // keep the values inline() saved (uninline() restores them on a theme change); add the colour only if it is not there yet
      var prev = el.getAttribute(MARK), k = {}; if (prev) { try { k = JSON.parse(prev) || {}; } catch (x) { k = {}; /* not ours: start a new record */ } }
      if (!Object.prototype.hasOwnProperty.call(k, 'color')) k.color = el.style.getPropertyValue('color') + (el.style.getPropertyPriority('color') ? '!' : '');
      el.setAttribute(MARK, JSON.stringify(k));
      el.style.setProperty('color', ink, 'important');
    }
  }
  var gTimer = null; function guardSoon() { if (gTimer) clearTimeout(gTimer); gTimer = setTimeout(function () { gTimer = null; guard(); }, 250); }
  var obs = null, pending = null, last = '';
  function on() { return document.documentElement.getAttribute('data-zyb-theme') === 'light'; }
  function build() {
    pending = null;
    var st = document.getElementById(STYLE_ID);
    if (!on()) { if (st) st.remove(); uninline(); last = ''; return; }
    var css = sheets();
    if (css !== last) { if (!st) { st = document.createElement('style'); st.id = STYLE_ID; } st.textContent = css; last = css; }
    if (st && !st.parentNode) (document.head || document.documentElement).appendChild(st);   // last in <head>: after every page style
    inline(); guardSoon();
  }
  function soon() { if (!pending) pending = setTimeout(build, 60); }
  function watch() {
    if (obs || !window.MutationObserver) return;
    obs = new MutationObserver(function (ms) {
      if (!on()) return;
      for (var i = 0; i < ms.length; i++) { var m = ms[i];
        if (m.type === 'childList') for (var j = 0; j < m.addedNodes.length; j++) { var n = m.addedNodes[j]; if (n.nodeType !== 1) continue; if (n.tagName === 'STYLE' || n.tagName === 'LINK') { if (n.id !== STYLE_ID) soon(); } else { inline(n.parentNode || n); guardSoon(); } }
      }
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
  }
  window.addEventListener('zyb-theme', function () { build(); });
  function start() { build(); watch(); window.addEventListener('load', soon); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
  window.zybThemeFix = { rebuild: build, guard: guard, text: text, surface: surface };
})();
