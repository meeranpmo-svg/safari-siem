// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-eml.js - Email / Phishing Analysis (email-analysis.html). Parses a pasted message source IN THE BROWSER: headers,
 * SPF / DKIM / DMARC verdicts the receiving server recorded, delivery path, links, attachments. Nothing is stored and
 * nothing is fetched (opening a link can confirm a live mailbox to the sender). The only thing that leaves the page is the
 * list of indicators (sender / reply domains, link hosts, origin IP) checked against the SIEM's own threat-intel lists.
 * The score is the sum of the points of each indicator that fired, capped at 100, every one named - indicators, not proof.
 *
 *   zybEml.indicators(raw) → [value]                       what the page asks the SIEM's intel lists about
 *   zybEml.analyze(raw, ti) → result | {err}               ti: Map(value → [list names]) or null when not checked
 *   zybEml.defang(url)                                     hxxp://host[.]tld - safe to copy into a ticket
 * Works in the browser (window.zybEml) and in Node (module.exports) so the test runs it without a page. */
(function (root) {
  'use strict';
  var ZYB_ORG = root.ZYB_ORG || (typeof globalThis !== 'undefined' && globalThis.ZYB_ORG);   // the brand setting (vendor/zyb-org.js; a Node test sets global.ZYB_ORG)
  var MAX = 1024 * 1024;
  // the organisation's own domains: a look-alike of these is the strongest tell
  var RX = function (t) { return String(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); };
  var LBL = ZYB_ORG.domain.split('.')[0];   // the company's own domain label: what a look-alike imitates
  var CORP = new RegExp('(^|\\.)' + RX(ZYB_ORG.domain) + '$', 'i');
  var BRAND_DISPLAY = new RegExp('\\b' + RX(ZYB_ORG.short).replace(/ /g, '[\\s-]?') + '\\b|\\b' + RX(LBL) + '\\b|' + RX(ZYB_ORG.short_ar), 'i');
  var RISKY_EXT = /\.(exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|iso|img|vhd|vhdx|msi|jar|cpl|reg|docm|xlsm|pptm|dotm|xlam|one|html?|svg)$/i;
  var SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rb\.gy|rebrand\.ly|shorturl\.at|t\.ly|lnkd\.in)$/i;
  var PRESSURE = /\b(urgent|immediately|verify|suspend|password|invoice|payment|wire|gift ?card|action required|account (?:locked|disabled)|unusual (?:sign|activity)|claim|policy renewal|refund)\b|عاجل|تحقق|كلمة المرور|تعليق الحساب|فاتورة|دفع|تجديد الوثيقة|مطالبة/i;

  function atobU(s) { if (typeof atob === 'function') return atob(s); return Buffer.from(s, 'base64').toString('binary'); }
  function dec(bytes, cs) { try { return new TextDecoder(/^(utf-?8|us-ascii)$/i.test(cs || '') ? 'utf-8' : cs, { fatal: false }).decode(bytes); } catch (e) { return new TextDecoder('utf-8').decode(bytes); } }
  function unfold(h) { return String(h).replace(/\r\n/g, '\n').replace(/\n[ \t]+/g, ' '); }
  function split(raw) { raw = String(raw || '').replace(/\r\n/g, '\n'); var i = raw.search(/\n\n/); return i < 0 ? { head: raw, body: '' } : { head: raw.slice(0, i), body: raw.slice(i + 2) }; }
  function headers(head) { var out = []; unfold(head).split('\n').forEach(function (l) { var m = /^([!-9;-~]+):\s?(.*)$/.exec(l); if (m) out.push([m[1].toLowerCase(), m[2].trim()]); }); return out; }
  function get(H, n) { for (var i = 0; i < H.length; i++) if (H[i][0] === n) return H[i][1]; return ''; }
  function all(H, n) { return H.filter(function (h) { return h[0] === n; }).map(function (h) { return h[1]; }); }
  // RFC 2047 encoded words, so an Arabic subject reads as sent
  function words(s) {
    return String(s || '').replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, function (whole, cs, enc, txt) {
      try {
        var a = [];
        if (enc.toLowerCase() === 'b') { var bin = atobU(txt); for (var i = 0; i < bin.length; i++) a.push(bin.charCodeAt(i)); }
        else { var q = txt.replace(/_/g, ' '); for (var j = 0; j < q.length; j++) { if (q[j] === '=' && /^[0-9a-f]{2}$/i.test(q.substr(j + 1, 2))) { a.push(parseInt(q.substr(j + 1, 2), 16)); j += 2; } else a.push(q.charCodeAt(j)); } }
        return dec(new Uint8Array(a), cs);
      } catch (e) { return whole; }
    });
  }
  function addr(s) { var m = /<([^>]+)>/.exec(s || ''); var a = (m ? m[1] : String(s || '')).trim().replace(/^mailto:/i, ''); var d = (a.split('@')[1] || '').toLowerCase().replace(/[>\s].*$/, ''); return { addr: a, domain: d, display: m ? String(s).slice(0, m.index).replace(/"/g, '').trim() : '' }; }
  // organisational domain: last two labels, three for the usual 2nd-level ccTLDs (com.sa, co.uk …)
  function org(d) { d = String(d || '').toLowerCase().replace(/\.$/, ''); var p = d.split('.'); if (p.length <= 2) return d; return /^(com|net|org|gov|edu|co|ac|med|sch)$/.test(p[p.length - 2]) && p[p.length - 1].length === 2 ? p.slice(-3).join('.') : p.slice(-2).join('.'); }
  function lev(a, b) { if (Math.abs(a.length - b.length) > 2) return 9; var d = [], i, j; for (i = 0; i <= a.length; i++) d[i] = [i]; for (j = 0; j <= b.length; j++) d[0][j] = j;
    for (i = 1; i <= a.length; i++) for (j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); return d[a.length][b.length]; }
  function lookalike(dom) {
    var o = org(dom); if (!o || CORP.test(dom)) return false;
    if (/^xn--|\.xn--/.test(dom)) return 'punycode (internationalised) domain';
    var label = o.split('.')[0].replace(/[01]/g, function (c) { return c === '0' ? 'o' : 'l'; }).replace(/rn/g, 'm').replace(/vv/g, 'w');
    var flat = label.replace(/-/g, '');
    if (flat === LBL) return ('uses the ' + ZYB_ORG.short + ' name on another domain (') + o + ')';
    if (lev(flat, LBL) <= (LBL.length >= 10 ? 2 : 1)) return 'a character or two away from ' + LBL + ' (' + o + ')';
    if (dom.toLowerCase().replace(/-/g, '').indexOf(LBL) >= 0) return ('contains the ' + ZYB_ORG.short + (' name but is not ' + ZYB_ORG.domain + ' (')) + dom + ')';
    return false;
  }
  function auth(H) {
    var ar = all(H, 'authentication-results').join(' ; ');
    var pick = function (k) { var m = new RegExp('\\b' + k + '\\s*=\\s*([a-z]+)', 'i').exec(ar); return m ? m[1].toLowerCase() : ''; };
    var r = { spf: pick('spf'), dkim: pick('dkim'), dmarc: pick('dmarc') };
    if (!r.spf) { var m = /^\s*([a-z]+)/i.exec(get(H, 'received-spf')); if (m) r.spf = m[1].toLowerCase(); }
    var mf = /smtp\.mailfrom\s*=\s*([^\s;]+)/i.exec(ar); r.mailfrom = mf ? mf[1].replace(/^.*@/, '').toLowerCase() : '';
    r.dkimD = all(H, 'dkim-signature').map(function (s) { var x = /\bd\s*=\s*([^;\s]+)/i.exec(s); return x ? x[1].toLowerCase() : ''; }).filter(Boolean);
    r.present = !!ar;
    return r;
  }
  function hops(H) {
    return all(H, 'received').map(function (v) {
      var from = (/\bfrom\s+([^\s(;]+)/i.exec(v) || [])[1] || '', by = (/\bby\s+([^\s(;]+)/i.exec(v) || [])[1] || '';
      var ip = (/\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,})\]/i.exec(v) || /\(((?:\d{1,3}\.){3}\d{1,3})\)/.exec(v) || [])[1] || '';
      var dt = v.lastIndexOf(';') >= 0 ? Date.parse(v.slice(v.lastIndexOf(';') + 1).trim()) : NaN;
      return { from: from, by: by, ip: ip, ts: isNaN(dt) ? null : dt };
    }).reverse();   // oldest hop first
  }
  function privateIp(ip) { return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|f[cd][0-9a-f]{2}:|fe80:)/i.test(ip); }
  function qp(s) { return String(s).replace(/=\n/g, '').replace(/=([0-9A-F]{2})/g, function (m, h) { return String.fromCharCode(parseInt(h, 16)); }); }
  function bodyText(body) {
    var b = String(body || ''), txt = qp(b);
    (b.match(/Content-Transfer-Encoding:\s*base64\s*\n(?:[^\n]*\n)*?\n([A-Za-z0-9+/=\n]{40,})/gi) || []).forEach(function (p) {
      var m = /\n\n([A-Za-z0-9+/=\n]{40,})/.exec(p); if (!m) return;
      try { var d = atobU(m[1].replace(/\n/g, '')); if (/[\x00-\x08]/.test(d.slice(0, 200))) return; var a = new Uint8Array(d.length); for (var i = 0; i < d.length; i++) a[i] = d.charCodeAt(i); txt += '\n' + dec(a, 'utf-8'); } catch (e) { /* not text */ }
    });
    return txt;
  }
  function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return ''; } }
  function urls(text) {
    var T = String(text || ''), out = [], seen = {};
    var push = function (href, shown) { href = href.replace(/[)>\].,'"]+$/, ''); if (seen[href]) return; seen[href] = 1; var host = hostOf(href); if (!host) return; out.push({ href: href, host: host, shown: shown || '', flags: [] }); };
    (T.match(/<a\b[^>]*href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/a>/gi) || []).forEach(function (a) { var m = /href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/a>/i.exec(a); if (m && /^https?:/i.test(m[1])) push(m[1], m[2].replace(/<[^>]+>/g, '').trim().slice(0, 200)); });
    (T.match(/https?:\/\/[^\s"'<>]+/gi) || []).forEach(function (u) { push(u, ''); });
    return out.slice(0, 200);
  }
  function attachments(raw) {
    var out = [], seen = {};
    (String(raw).match(/(?:filename\*?|name)\s*=\s*(?:"([^"]+)"|([^;\s]+))/gi) || []).forEach(function (x) {
      var m = /=\s*(?:"([^"]+)"|([^;\s]+))/.exec(x); var n = words((m[1] || m[2] || '').replace(/^utf-8''/i, '')); try { n = decodeURIComponent(n); } catch (e) { /* keep */ }
      if (!n || seen[n]) return; seen[n] = 1; out.push({ name: n, risky: RISKY_EXT.test(n), double: /\.(pdf|docx?|xlsx?|jpg|png|txt)\.[a-z0-9]{2,4}$/i.test(n) });
    });
    return out;
  }
  function parse(raw) {
    raw = String(raw || '');
    if (raw.length > MAX) return { err: 'That is more than 1 MB. Paste the headers and the text part only.' };
    var s = split(raw), H = headers(s.head);
    if (!H.length || !(get(H, 'from') || get(H, 'received'))) return { err: 'No e-mail headers found. In Outlook: File → Properties → Internet headers (or save the message as .eml); in OWA: ⋯ → View → View message details. Paste from the first line.' };
    var text = bodyText(s.body), hp = hops(H), pub = hp.filter(function (h) { return h.ip && !privateIp(h.ip); });
    return { raw: raw, H: H, body: s.body, text: text, hops: hp, firstIp: pub.length ? pub[0].ip : '', urls: urls(text), att: attachments(raw),
      from: addr(words(get(H, 'from'))), reply: addr(get(H, 'reply-to')), rpath: addr(get(H, 'return-path')) };
  }
  function indicators(raw) {
    var P = parse(raw); if (P.err) return [];
    var v = [P.from.domain, P.reply.domain, P.rpath.domain, P.firstIp].concat(P.urls.map(function (u) { return u.host; }));
    return v.filter(function (x, i) { return x && v.indexOf(x) === i && !CORP.test(x); }).slice(0, 200);
  }
  function analyze(raw, ti) {
    var P = parse(raw); if (P.err) return P;
    var A = auth(P.H), from = P.from, reply = P.reply, fOrg = org(from.domain), F = [];
    var add = function (p, k, d) { F.push({ p: p, k: k, d: d }); };
    var hit = function (v) { if (!ti || !v) return null; var l = ti.get(String(v).toLowerCase()); return l && l.length ? l : null; };
    if (!A.present && !A.spf) add(10, 'No authentication results', 'the receiving server recorded no SPF / DKIM / DMARC verdict - check it was copied from the mailbox, not from the sender');
    if (/^(fail|softfail|permerror)$/.test(A.spf)) add(A.spf === 'fail' ? 20 : 10, 'SPF ' + A.spf, 'the sending server is not authorised for ' + (A.mailfrom || 'the envelope domain'));
    if (/^(fail|permerror|temperror)$/.test(A.dkim)) add(15, 'DKIM ' + A.dkim, 'the signature did not verify - the message may have been altered or forged');
    if (A.dmarc === 'fail') add(25, 'DMARC fail', 'the From domain ' + (from.domain || '') + ' does not authenticate this message');
    if (A.dkim === 'pass' && A.dkimD.length && fOrg && !A.dkimD.some(function (d) { return org(d) === fOrg; })) add(10, 'DKIM not aligned', 'signed by ' + A.dkimD.join(', ') + ', not by ' + fOrg);
    if (A.mailfrom && fOrg && org(A.mailfrom) !== fOrg) add(5, 'Envelope sender differs', 'MAIL FROM ' + A.mailfrom + ' vs From ' + from.domain + ' - normal for mailing services, suspicious with a DMARC failure');
    var la = lookalike(from.domain); if (la) add(35, 'Look-alike sender domain', la);
    if (CORP.test(from.domain) && (A.dmarc === 'fail' || A.spf === 'fail')) add(25, (ZYB_ORG.short + ' domain failing authentication'), 'From says ' + from.domain + ' but the message did not authenticate - spoofed internal sender');
    if (reply.domain && fOrg && org(reply.domain) !== fOrg) add(15, 'Reply-To goes elsewhere', 'replies go to ' + reply.addr + ', not to ' + from.domain);
    if (from.display && /@/.test(from.display)) { var dd = addr(from.display).domain; if (dd && dd !== from.domain) add(20, 'Display name shows another address', 'shown as "' + from.display + '" but sent from ' + from.addr); }
    if (from.display && BRAND_DISPLAY.test(from.display) && !CORP.test(from.domain)) add(15, ('Display name claims ' + ZYB_ORG.short), '"' + from.display + '" from an outside domain (' + from.domain + ')');
    var subj = words(get(P.H, 'subject'));
    if (PRESSURE.test(subj + ' ' + P.text.slice(0, 4000))) add(10, 'Pressure / credential language', 'urgency, payment, claim or password wording in the subject or body');
    P.urls.forEach(function (u) {
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(u.host)) u.flags.push('IP address instead of a name');
      if (/^xn--|\.xn--/.test(u.host)) u.flags.push('punycode host');
      if (SHORTENERS.test(u.host)) u.flags.push('URL shortener hides the destination');
      var l = lookalike(u.host); if (l) u.flags.push(l);
      if (u.shown && /^(https?:\/\/)?[\w.-]+\.[a-z]{2,}/i.test(u.shown)) { var sh = hostOf(/^https?:/i.test(u.shown) ? u.shown : 'http://' + u.shown); if (sh && org(sh) !== org(u.host)) u.flags.push('link text shows ' + sh + ' but goes to ' + u.host); }
      var h = hit(u.host); if (h) { u.ti = h; u.flags.push('threat intel: ' + h.join(', ')); }
    });
    var badU = P.urls.filter(function (u) { return u.flags.length; });
    if (badU.length) { var fl = []; badU.forEach(function (u) { u.flags.forEach(function (f) { if (fl.indexOf(f) < 0) fl.push(f); }); }); add(Math.min(30, badU.length * 10), 'Suspicious links', badU.length + ' of ' + P.urls.length + ' link(s): ' + fl.slice(0, 4).join('; ')); }
    if (P.urls.some(function (u) { return u.ti; })) add(30, 'Link matches threat intel', 'a link host is on one of the SIEM\'s indicator lists');
    var hs = hit(from.domain) || hit(reply.domain); if (hs) add(30, 'Sender domain matches threat intel', (hit(from.domain) ? from.domain : reply.domain) + ' - ' + hs.join(', '));
    var risky = P.att.filter(function (a) { return a.risky || a.double; });
    if (risky.length) add(Math.min(35, risky.length * 20), 'Risky attachment', risky.map(function (a) { return a.name + (a.double ? ' (double extension)' : ''); }).join(', '));
    var hi = hit(P.firstIp); if (hi) add(30, 'Origin IP matches threat intel', P.firstIp + ' - ' + hi.join(', '));
    var score = Math.min(100, F.reduce(function (s, f) { return s + f.p; }, 0));
    return { from: from, reply: reply, rpath: P.rpath, to: get(P.H, 'to'), subject: subj, date: get(P.H, 'date'), msgId: get(P.H, 'message-id'), auth: A, hops: P.hops, firstIp: P.firstIp,
      urls: P.urls, att: P.att, F: F.sort(function (a, b) { return b.p - a.p; }), score: score, verdict: score >= 60 ? 'High' : score >= 30 ? 'Medium' : score >= 10 ? 'Low' : 'No indicators',
      tiChecked: !!ti, bodyGiven: !!String(P.body).trim(), privateIp: privateIp };
  }
  function defang(u) { return String(u).replace(/^http/i, 'hxxp').replace(/\./g, '[.]'); }
  var api = { analyze: analyze, indicators: indicators, defang: defang, lookalike: lookalike, org: org, privateIp: privateIp, MAX: MAX };
  if (typeof module === 'object' && module.exports) module.exports = api; else root.zybEml = api;
})(typeof window !== 'undefined' ? window : this);
