// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-login.js - the approved sign-in design, drawn over the sign-in service's own page.
 *
 * nginx adds one <script> line to the sign-in pages (install-login-skin.sh). This file restyles what the sign-in service
 * sends and changes nothing about how signing in works: the service's own <form> is kept - its action, method, field
 * names, hidden fields and button - and is only moved into the new layout. Decoration around it (logo boxes, animated
 * background, the policy chips) is hidden, never removed from the form's data. Error and notice messages the service
 * shows are kept and moved above the form.
 * Pages: the password step (a password field), the code step (a one-time-code field), anything else (enrolment with a
 * QR code, notices): the form is kept whole, QR codes and instructions included, under a neutral heading.
 * If this script fails or the page has no form, the page shows exactly as the service drew it (nothing is hidden
 * until the new layout is in place, and a 2 s fallback shows the original whatever happens). */
(function () {
  'use strict';
  if (window.__zybLogin) return; window.__zybLogin = true;
  var DESK = '';   // IT Service Desk contact (email or phone), written by install-login-skin.sh --desk; empty = no link
  var NAME = 'IT Operations & Cyber Security Automation and Monitoring Platform', PRODUCT = 'ZYBERON SENTRA';
  // the language chosen here is the platform's language: saved where every dashboard (vendor/zyb-lang.js, key zyb-dash-prefs) and the
  // portal (noc_lang) read it, so the person signs in and lands in the language they picked. Only words change - never the form.
  var PREF = 'zyb-dash-prefs';
  function getLang() { try { return (JSON.parse(localStorage.getItem(PREF) || '{}') || {}).lang === 'ar' ? 'ar' : 'en'; } catch (e) { return 'en'; } }
  function setLang(l) { try { var p = JSON.parse(localStorage.getItem(PREF) || '{}') || {}; p.lang = l; localStorage.setItem(PREF, JSON.stringify(p)); localStorage.setItem('noc_lang', l); } catch (e) { /* private window: the choice applies to this page only */ } }
  var LANG = getLang();
  // the brand colours chosen on the main page (Zyberon Sentra blue by default, the organisation colours when switched on)
  // the sign-in page always wears the the organisation colours (greens over a deep canvas), whatever the dashboards use
  var ASB = true;
  var C1 = ASB ? '#01579B' : '#3B82F6', C2 = ASB ? '#568ADD' : '#22D3EE', RGB = ASB ? '38,87,166' : '59,130,246';
  var AR = {
    'IT Operations & Cyber Security Automation and Monitoring Platform': '\u0645\u0646\u0635\u0629 \u0623\u062a\u0645\u062a\u0629 \u0648\u0645\u0631\u0627\u0642\u0628\u0629 \u0639\u0645\u0644\u064a\u0627\u062a \u062a\u0642\u0646\u064a\u0629 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062a \u0648\u0627\u0644\u0623\u0645\u0646 \u0627\u0644\u0633\u064a\u0628\u0631\u0627\u0646\u064a',
    'Enterprise Risk & Compliance': '\u0627\u0644\u0645\u062e\u0627\u0637\u0631 \u0627\u0644\u0645\u0624\u0633\u0633\u064a\u0629 \u0648\u0627\u0644\u0627\u0644\u062a\u0632\u0627\u0645',
    ['Monitoring, security operations, automation and audit evidence for ' + ZYB_ORG.name + ' - with AI and machine learning watching every signal.']: '\u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629 \u0648\u0639\u0645\u0644\u064a\u0627\u062a \u0627\u0644\u0623\u0645\u0646 \u0648\u0627\u0644\u0623\u062a\u0645\u062a\u0629 \u0648\u0623\u062f\u0644\u0629 \u0627\u0644\u062a\u062f\u0642\u064a\u0642 \u0644\u0644\u062f\u0631\u0639 \u0627\u0644\u0639\u0631\u0628\u064a \u0644\u0644\u062a\u0623\u0645\u064a\u0646 - \u0645\u0639 \u0630\u0643\u0627\u0621 \u0627\u0635\u0637\u0646\u0627\u0639\u064a \u0648\u062a\u0639\u0644\u0651\u0645 \u0622\u0644\u064a \u064a\u0631\u0627\u0642\u0628\u0627\u0646 \u0643\u0644 \u0625\u0634\u0627\u0631\u0629.',
    'IT operations and network monitoring': '\u0645\u0631\u0627\u0642\u0628\u0629 \u0639\u0645\u0644\u064a\u0627\u062a \u062a\u0642\u0646\u064a\u0629 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062a \u0648\u0627\u0644\u0634\u0628\u0643\u0627\u062a',
    'Security operations and automated response': '\u0639\u0645\u0644\u064a\u0627\u062a \u0627\u0644\u0623\u0645\u0646 \u0648\u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0627\u0644\u0645\u0624\u062a\u0645\u062a\u0629',
    'Enterprise risk, compliance and audit': '\u0627\u0644\u0645\u062e\u0627\u0637\u0631 \u0627\u0644\u0645\u0624\u0633\u0633\u064a\u0629 \u0648\u0627\u0644\u0627\u0644\u062a\u0632\u0627\u0645 \u0648\u0627\u0644\u062a\u062f\u0642\u064a\u0642',
    'AI and machine learning: anomalies, forecasts, insights': '\u0627\u0644\u0630\u0643\u0627\u0621 \u0627\u0644\u0627\u0635\u0637\u0646\u0627\u0639\u064a \u0648\u0627\u0644\u062a\u0639\u0644\u0651\u0645 \u0627\u0644\u0622\u0644\u064a: \u0627\u0644\u0634\u0630\u0648\u0630 \u0648\u0627\u0644\u062a\u0648\u0642\u0639\u0627\u062a \u0648\u0627\u0644\u0631\u0624\u0649',
    'Frameworks': '\u0627\u0644\u0623\u0637\u0631',
    'Audit': '\u0627\u0644\u062a\u062f\u0642\u064a\u0642',
    'IT Ops': '\u0627\u0644\u0639\u0645\u0644\u064a\u0627\u062a',
    'SOC': '\u0645\u0631\u0643\u0632 \u0627\u0644\u0623\u0645\u0646',
    'Network': '\u0627\u0644\u0634\u0628\u0643\u0629',
    'Cloud': '\u0627\u0644\u0633\u062d\u0627\u0628\u0629',
    'Risk': '\u0627\u0644\u0645\u062e\u0627\u0637\u0631',
    'AI and machine learning at the core of IT operations, security, risk and audit': '\u0627\u0644\u0630\u0643\u0627\u0621 \u0627\u0644\u0627\u0635\u0637\u0646\u0627\u0639\u064a \u0648\u0627\u0644\u062a\u0639\u0644\u0651\u0645 \u0627\u0644\u0622\u0644\u064a \u0641\u064a \u0642\u0644\u0628 \u0627\u0644\u0639\u0645\u0644\u064a\u0627\u062a \u0648\u0627\u0644\u0623\u0645\u0646 \u0648\u0627\u0644\u0645\u062e\u0627\u0637\u0631 \u0648\u0627\u0644\u062a\u062f\u0642\u064a\u0642',
    'IT Operations and Cyber Security Automation Platform': '\u0645\u0646\u0635\u0629 \u0623\u062a\u0645\u062a\u0629 \u0639\u0645\u0644\u064a\u0627\u062a \u062a\u0642\u0646\u064a\u0629 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062a \u0648\u0627\u0644\u0623\u0645\u0646 \u0627\u0644\u0633\u064a\u0628\u0631\u0627\u0646\u064a',
    'Internal system \u00b7 authorised users only': '\u0646\u0638\u0627\u0645 \u062f\u0627\u062e\u0644\u064a \u00b7 \u0644\u0644\u0645\u0633\u062a\u062e\u062f\u0645\u064a\u0646 \u0627\u0644\u0645\u0635\u0631\u0651\u062d \u0644\u0647\u0645 \u0641\u0642\u0637',
    ['Monitoring, security operations and compliance evidence for ' + ZYB_ORG.name + ', in one place.']: '\u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629 \u0648\u0639\u0645\u0644\u064a\u0627\u062a \u0627\u0644\u0623\u0645\u0646 \u0648\u0623\u062f\u0644\u0629 \u0627\u0644\u0627\u0644\u062a\u0632\u0627\u0645 \u0644\u0644\u062f\u0631\u0639 \u0627\u0644\u0639\u0631\u0628\u064a \u0644\u0644\u062a\u0623\u0645\u064a\u0646\u060c \u0641\u064a \u0645\u0643\u0627\u0646 \u0648\u0627\u062d\u062f.',
    'Infrastructure and network monitoring': '\u0645\u0631\u0627\u0642\u0628\u0629 \u0627\u0644\u0628\u0646\u064a\u0629 \u0627\u0644\u062a\u062d\u062a\u064a\u0629 \u0648\u0627\u0644\u0634\u0628\u0643\u0629', 'Security operations and incident response': '\u0639\u0645\u0644\u064a\u0627\u062a \u0627\u0644\u0623\u0645\u0646 \u0648\u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0644\u0644\u062d\u0648\u0627\u062f\u062b',
    'SAMA CSF, NCA ECC and PDPL compliance evidence': '\u0623\u062f\u0644\u0629 \u0627\u0644\u0627\u0644\u062a\u0632\u0627\u0645 \u0628\u0625\u0637\u0627\u0631 \u0633\u0627\u0645\u0627 \u0648\u0627\u0644\u0636\u0648\u0627\u0628\u0637 \u0627\u0644\u0623\u0633\u0627\u0633\u064a\u0629 \u0644\u0644\u0623\u0645\u0646 \u0627\u0644\u0633\u064a\u0628\u0631\u0627\u0646\u064a \u0648\u0646\u0638\u0627\u0645 \u062d\u0645\u0627\u064a\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0634\u062e\u0635\u064a\u0629', 'Evidence for': '\u0623\u062f\u0644\u0629 \u0644\u0640',
    'Sign in': '\u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644', 'Two-step verification': '\u0627\u0644\u062a\u062d\u0642\u0642 \u0628\u062e\u0637\u0648\u062a\u064a\u0646', 'Account security': '\u0623\u0645\u0627\u0646 \u0627\u0644\u062d\u0633\u0627\u0628',
    'Use your platform account to continue.': '\u0627\u0633\u062a\u062e\u062f\u0645 \u062d\u0633\u0627\u0628 \u0627\u0644\u0645\u0646\u0635\u0629 \u0644\u0644\u0645\u062a\u0627\u0628\u0639\u0629.', 'Enter the 6-digit code shown in your authenticator app.': '\u0623\u062f\u062e\u0644 \u0627\u0644\u0631\u0645\u0632 \u0627\u0644\u0645\u0643\u0648\u0651\u0646 \u0645\u0646 6 \u0623\u0631\u0642\u0627\u0645 \u0627\u0644\u0638\u0627\u0647\u0631 \u0641\u064a \u062a\u0637\u0628\u064a\u0642 \u0627\u0644\u0645\u0635\u0627\u062f\u0642\u0629.',
    'Follow the steps below to continue.': '\u0627\u062a\u0628\u0639 \u0627\u0644\u062e\u0637\u0648\u0627\u062a \u0623\u062f\u0646\u0627\u0647 \u0644\u0644\u0645\u062a\u0627\u0628\u0639\u0629.', 'Continue': '\u0645\u062a\u0627\u0628\u0639\u0629', 'Verify and sign in': '\u062a\u062d\u0642\u0642 \u0648\u0633\u062c\u0651\u0644 \u0627\u0644\u062f\u062e\u0648\u0644',
    'Two-step verification is required. After your password you will be asked for the code from your authenticator app.': '\u0627\u0644\u062a\u062d\u0642\u0642 \u0628\u062e\u0637\u0648\u062a\u064a\u0646 \u0645\u0637\u0644\u0648\u0628. \u0628\u0639\u062f \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0633\u064a\u064f\u0637\u0644\u0628 \u0645\u0646\u0643 \u0627\u0644\u0631\u0645\u0632 \u0645\u0646 \u062a\u0637\u0628\u064a\u0642 \u0627\u0644\u0645\u0635\u0627\u062f\u0642\u0629.',
    'The code changes every 30 seconds. Only an administrator can reset two-step verification, after confirming who you are.': '\u064a\u062a\u063a\u064a\u0631 \u0627\u0644\u0631\u0645\u0632 \u0643\u0644 30 \u062b\u0627\u0646\u064a\u0629. \u0644\u0627 \u064a\u0645\u0643\u0646 \u0625\u0639\u0627\u062f\u0629 \u0636\u0628\u0637 \u0627\u0644\u062a\u062d\u0642\u0642 \u0628\u062e\u0637\u0648\u062a\u064a\u0646 \u0625\u0644\u0627 \u0645\u0646 \u0642\u0628\u0644 \u0645\u0633\u0624\u0648\u0644 \u0628\u0639\u062f \u0627\u0644\u062a\u0623\u0643\u062f \u0645\u0646 \u0647\u0648\u064a\u062a\u0643.',
    'Lost access to your authenticator app? ': '\u0641\u0642\u062f\u062a \u0627\u0644\u0648\u0635\u0648\u0644 \u0625\u0644\u0649 \u062a\u0637\u0628\u064a\u0642 \u0627\u0644\u0645\u0635\u0627\u062f\u0642\u0629\u061f ', 'Trouble signing in? ': '\u0645\u0634\u0643\u0644\u0629 \u0641\u064a \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644\u061f ', 'Contact the IT Service Desk.': '\u062a\u0648\u0627\u0635\u0644 \u0645\u0639 \u0645\u0643\u062a\u0628 \u062e\u062f\u0645\u0629 \u062a\u0642\u0646\u064a\u0629 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062a.', 'Contact the IT Service Desk': '\u062a\u0648\u0627\u0635\u0644 \u0645\u0639 \u0645\u0643\u062a\u0628 \u062e\u062f\u0645\u0629 \u062a\u0642\u0646\u064a\u0629 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062a',
    ['This system is for authorised use only. Sign-ins and activity are recorded and monitored in line with ' + ZYB_ORG.name + ' policy and the Saudi Personal Data Protection Law.']: '\u0647\u0630\u0627 \u0627\u0644\u0646\u0638\u0627\u0645 \u0644\u0644\u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0627\u0644\u0645\u0635\u0631\u0651\u062d \u0628\u0647 \u0641\u0642\u0637. \u062a\u064f\u0633\u062c\u064e\u0651\u0644 \u0639\u0645\u0644\u064a\u0627\u062a \u0627\u0644\u062f\u062e\u0648\u0644 \u0648\u0627\u0644\u0623\u0646\u0634\u0637\u0629 \u0648\u062a\u064f\u0631\u0627\u0642\u064e\u0628 \u0648\u0641\u0642 \u0633\u064a\u0627\u0633\u0629 \u0627\u0644\u062f\u0631\u0639 \u0627\u0644\u0639\u0631\u0628\u064a \u0644\u0644\u062a\u0623\u0645\u064a\u0646 \u0648\u0646\u0638\u0627\u0645 \u062d\u0645\u0627\u064a\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u0634\u062e\u0635\u064a\u0629 \u0627\u0644\u0633\u0639\u0648\u062f\u064a.',
    'Username': '\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645', 'Password': '\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631', 'Verification code': '\u0631\u0645\u0632 \u0627\u0644\u062a\u062d\u0642\u0642', 'Code': '\u0627\u0644\u0631\u0645\u0632', 'or use a local account': '\u0623\u0648 \u0627\u0633\u062a\u062e\u062f\u0645 \u062d\u0633\u0627\u0628\u0627\u064b \u0645\u062d\u0644\u064a\u0627\u064b', 'break-glass account': '\u062d\u0633\u0627\u0628 \u0627\u0644\u0637\u0648\u0627\u0631\u0626',
    'Show password': '\u0625\u0638\u0647\u0627\u0631 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631', 'Hide password': '\u0625\u062e\u0641\u0627\u0621 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631', 'Language': '\u0627\u0644\u0644\u063a\u0629', 'Motor': '\u0627\u0644\u0645\u0631\u0643\u0628\u0627\u062a', 'Medical': '\u0627\u0644\u0637\u0628\u064a', 'Property': '\u0627\u0644\u0645\u0645\u062a\u0644\u0643\u0627\u062a', 'Marine': '\u0627\u0644\u0628\u062d\u0631\u064a',
    'Secure access': '\u062f\u062e\u0648\u0644 \u0622\u0645\u0646',
    'Encrypted connection': '\u0627\u062a\u0635\u0627\u0644 \u0645\u0634\u0641\u0651\u0631',
    'Sign-ins are recorded': '\u062a\u064f\u0633\u062c\u064e\u0651\u0644 \u0639\u0645\u0644\u064a\u0627\u062a \u0627\u0644\u062f\u062e\u0648\u0644',
    'Caps Lock is on': '\u0645\u0641\u062a\u0627\u062d Caps Lock \u0645\u0641\u0639\u0651\u0644',
    'Riyadh time': '\u062a\u0648\u0642\u064a\u062a \u0627\u0644\u0631\u064a\u0627\u0636',
    'Signing in\u2026': '\u062c\u0627\u0631\u064d \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644\u2026',
    'One platform for IT operations, security and compliance.': '\u0645\u0646\u0635\u0629 \u0648\u0627\u062d\u062f\u0629 \u0644\u0639\u0645\u0644\u064a\u0627\u062a \u062a\u0642\u0646\u064a\u0629 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062a \u0648\u0627\u0644\u0623\u0645\u0646 \u0648\u0627\u0644\u0627\u0644\u062a\u0632\u0627\u0645.',
    'Step': '\u0627\u0644\u062e\u0637\u0648\u0629',
  };
  function T(t) { return LANG === 'ar' && Object.prototype.hasOwnProperty.call(AR, t) ? AR[t] : t; }
  // the sign-in service's own sentences that carry a name (the AD domain, the identity provider): the name is kept as it is
  function TS(t) {
    var s = String(t || '').trim(), m;
    if (LANG !== 'ar') return s;
    if (Object.prototype.hasOwnProperty.call(AR, s)) return AR[s];
    if ((m = /^Sign in with your (.+) account$/.exec(s))) return '\u0633\u062c\u0651\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0628\u062d\u0633\u0627\u0628 ' + m[1];
    if ((m = /^Sign in with (.+)$/.exec(s))) return '\u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0639\u0628\u0631 ' + m[1];
    return s;
  }
  var de = document.documentElement;
  de.classList.add('zl-pre');
  var css = document.createElement('style'); css.id = 'zl-css';
  css.textContent = [
    'html.zl-pre body{visibility:hidden;animation:zl-show 0s 2s forwards}@keyframes zl-show{to{visibility:visible}}',
    'html.zl-on,html.zl-on body{margin:0!important;padding:0!important;background:#fff!important;display:block!important;width:auto!important;min-height:0!important;height:auto!important;overflow:auto!important;grid-template-columns:none!important;visibility:visible;animation:none}',
    'html.zl-on body>*:not(.zl){display:none!important}',
    '.zl{position:relative!important;z-index:1;width:100%!important;min-height:100vh;display:flex!important;flex-wrap:wrap;text-align:left;font:15px/1.5 "IBM Plex Sans","Segoe UI",system-ui,-apple-system,sans-serif;color:#0F172A;background:#fff}',
    '.zl *{box-sizing:border-box}.zl h1,.zl h2,.zl p,.zl ul,.zl li{text-shadow:none!important;background:none;border:0}',
    '.zl-side{flex:1.15 1 560px;min-width:0;color:#fff;display:flex;flex-direction:column;justify-content:space-between;gap:36px;padding:44px 56px;position:relative;overflow:hidden;background:radial-gradient(820px 520px at 108% -10%,rgba(124,92,255,.30),transparent 60%),radial-gradient(760px 620px at -20% 115%,rgba(0,194,255,.26),transparent 60%),radial-gradient(520px 380px at 60% 45%,rgba(0,229,190,.10),transparent 70%),linear-gradient(160deg,#050B1F 0%,#0A1838 40%,#0B2550 72%,#06324A 100%)}',
    '.zl-side:before{content:"";position:absolute;inset:0;pointer-events:none;background-image:radial-gradient(rgba(255,255,255,.10) 1px,transparent 1.2px);background-size:22px 22px;-webkit-mask-image:linear-gradient(180deg,rgba(0,0,0,.9),rgba(0,0,0,.15) 70%,transparent);mask-image:linear-gradient(180deg,rgba(0,0,0,.9),rgba(0,0,0,.15) 70%,transparent)}',
    '.zl-side:after{content:"";position:absolute;left:0;right:0;top:0;height:3px;background:linear-gradient(90deg,#00C2FF,#7C5CFF 45%,#D4AF37 80%,transparent)}',
    '.zl-brandrow{position:relative;display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}',
    '.zl-wm{display:flex;flex-direction:column;gap:4px}.zl-wm b{font:800 30px/1 "IBM Plex Sans","Segoe UI",system-ui,sans-serif;letter-spacing:.20em;background:linear-gradient(92deg,#FFFFFF 0%,#BFE9FF 45%,#8FA2FF 100%);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;filter:drop-shadow(0 4px 18px rgba(0,194,255,.25))}',
    '.zl-wm b i{font-style:normal;background:linear-gradient(92deg,#00E5BE,#00C2FF);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}',
    '.zl-wm span{font-size:11.5px;letter-spacing:.32em;text-transform:uppercase;color:#8FB4D8}',
    '.zl-art .zl-node{animation:zl-blink 3.6s ease-in-out infinite}.zl-art .zl-node.n2{animation-delay:.9s}.zl-art .zl-node.n3{animation-delay:1.8s}.zl-art .zl-node.n4{animation-delay:2.7s}',
    '@keyframes zl-blink{0%,100%{opacity:.25}50%{opacity:1}}',
    '.zl-art .zl-orbit{transform-origin:280px 104px;animation:zl-spin 60s linear infinite}@keyframes zl-spin{to{transform:rotate(360deg)}}',
    '.zl-art .zl-pulse{animation:zl-pl 2.6s ease-in-out infinite}@keyframes zl-pl{0%,100%{opacity:.55}50%{opacity:1}}',
    '.zl-art .zl-spark{offset-rotate:0deg;animation:zl-move 3.2s linear infinite}.zl-art .zl-spark.s2{animation-delay:.8s}.zl-art .zl-spark.s3{animation-delay:1.6s}.zl-art .zl-spark.s4{animation-delay:2.4s}',
    '@keyframes zl-move{0%{offset-distance:0%;opacity:0}15%{opacity:1}85%{opacity:1}100%{offset-distance:100%;opacity:0}}',
    '.zl-art{position:relative;width:100%;max-width:560px;height:auto;display:block;margin:-6px 0 -4px}',
    '.zl-art .zl-ring{transform-origin:280px 92px;animation:zl-ring 4.8s ease-out infinite}.zl-art .zl-ring.r2{animation-delay:1.6s}.zl-art .zl-ring.r3{animation-delay:3.2s}',
    '@keyframes zl-ring{0%{opacity:.55;transform:scale(.6)}100%{opacity:0;transform:scale(1.9)}}',
    '.zl-art .zl-link{stroke-dasharray:4 7;animation:zl-flow 2.4s linear infinite}@keyframes zl-flow{to{stroke-dashoffset:-22}}',
    '.zl-art .zl-badge{animation:zl-float 6s ease-in-out infinite}.zl-art .zl-badge.b2{animation-delay:1.5s}.zl-art .zl-badge.b3{animation-delay:3s}.zl-art .zl-badge.b4{animation-delay:4.5s}',
    '@keyframes zl-float{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}',
    '.zl-chips{position:relative;display:flex;flex-wrap:wrap;align-items:center;gap:8px;font-size:12px;color:#9DB6D3}',
    '.zl-chips b{display:inline-flex;align-items:center;gap:7px;height:28px;padding:0 12px;border-radius:999px;background:rgba(212,175,55,.12);border:1px solid rgba(212,175,55,.38);color:#F6E7B0;font-weight:600;letter-spacing:.3px}',
    '.zl-chips b:before{content:"";width:6px;height:6px;border-radius:50%;background:#E8C766;box-shadow:0 0 0 3px rgba(232,199,102,.18)}',
    '.zl-pill{position:relative;align-self:flex-start;height:28px;padding:0 12px;display:inline-flex;align-items:center;gap:8px;border-radius:999px;border:1px solid rgba(255,255,255,.22);background:rgba(255,255,255,.06);-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);font-size:12.5px;font-weight:500;color:#D3D9E4}',
    '.zl-mid{position:relative;display:flex;flex-direction:column;gap:22px;max-width:560px}',
    '.zl-mid h1{margin:0!important;font:650 36px/1.16 "IBM Plex Sans","Segoe UI",system-ui,sans-serif!important;letter-spacing:-.4px!important;color:#fff!important;text-transform:none!important;background:linear-gradient(92deg,#FFFFFF 0%,#FFFFFF 55%,#F3DE9A 100%)!important;-webkit-background-clip:text!important;background-clip:text!important;-webkit-text-fill-color:transparent}',
    '.zl-mid p{margin:0!important;font-size:16px!important;line-height:1.6!important;color:#B8CAE6!important}',
    '.zl-mid .zl-sub2{display:inline-flex;align-self:flex-start;align-items:center;gap:8px;font:600 13px "IBM Plex Sans","Segoe UI",system-ui,sans-serif;letter-spacing:.14em;text-transform:uppercase;color:#F3DE9A;padding:6px 12px;border-radius:999px;background:rgba(212,175,55,.10);border:1px solid rgba(212,175,55,.35)}',
    '.zl-caps{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:10px}',
    '.zl-caps li{display:flex;align-items:center;gap:14px;padding:11px 14px;border-radius:12px;background:linear-gradient(90deg,rgba(255,255,255,.09),rgba(255,255,255,.03));border:1px solid rgba(255,255,255,.12);font-size:15px!important;font-weight:500;color:#EDF1F6!important;-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px)}',
    '.zl-caps i{width:36px;height:36px;flex:0 0 auto;border-radius:10px;display:grid;place-items:center;color:#fff;background:linear-gradient(140deg,#00C2FF,#1D4ED8);box-shadow:0 6px 16px rgba(0,0,0,.22),inset 0 1px 0 rgba(255,255,255,.25)}',
    '.zl-caps li:nth-child(2) i{background:linear-gradient(140deg,#00E5BE,#0F766E)}.zl-caps li:nth-child(3) i{background:linear-gradient(140deg,#E2BE52,#9C7A16)}.zl-caps li:nth-child(4) i{background:linear-gradient(140deg,#A78BFA,#6D28D9)}',
    '.zl-foot{position:relative;display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:16px;font-size:12.5px;color:#A7B0BE}',
    '.zl-foot span{display:inline-flex;align-items:center;gap:10px}.zl-foot img{height:26px;width:auto;display:block}',
    '.zl-main{flex:1 1 480px;min-width:0;display:flex;flex-direction:column;justify-content:center;gap:32px;padding:56px}',
    '.zl-card{width:100%;max-width:400px;margin:0 auto;display:flex;flex-direction:column;gap:24px}',
    '.zl-logo{height:52px;width:auto;align-self:flex-start;display:block}',
    '.zl-head h2{margin:0 0 6px!important;font:600 28px/1.25 "IBM Plex Sans","Segoe UI",system-ui,sans-serif!important;letter-spacing:-.3px!important;color:#0F172A!important;text-transform:none!important}.zl-head p{margin:0!important;font-size:15px!important;color:#475569!important}',
    '.zl form{display:flex!important;flex-direction:column!important;gap:6px!important;margin:0!important;padding:0!important;background:none!important;border:0!important;box-shadow:none!important;width:auto!important;max-width:none!important;color:#1E293B!important;position:static!important;transform:none!important}',
    '.zl form label{display:block!important;margin:12px 0 0!important;font:500 14px/1.4 "IBM Plex Sans","Segoe UI",system-ui,sans-serif!important;color:#1E293B!important;text-transform:none!important;letter-spacing:0!important}',
    '.zl form label:first-of-type{margin-top:0!important}',
    '.zl form input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){display:block!important;width:100%!important;height:48px!important;margin:0!important;padding:0 14px!important;border:1px solid #CBD5E1!important;border-radius:8px!important;background:#fff!important;color:#0F172A!important;font:400 15px "IBM Plex Sans","Segoe UI",system-ui,sans-serif!important;box-shadow:none!important}',
    '.zl form input:focus{outline:none!important;border-color:#0F2C5B!important;box-shadow:0 0 0 3px rgba(15,44,91,.18)!important}',
    '.zl form input.zl-code{height:56px!important;text-align:center!important;font:600 24px "IBM Plex Mono",ui-monospace,Consolas,monospace!important;letter-spacing:.5em!important;padding-left:.5em!important}',
    '.zl form button,.zl form input[type=submit]{display:flex!important;align-items:center!important;justify-content:center!important;width:100%!important;height:48px!important;margin:18px 0 0!important;padding:0 16px!important;border:0!important;border-radius:8px!important;background:#0F2C5B!important;color:#fff!important;font:600 15px "IBM Plex Sans","Segoe UI",system-ui,sans-serif!important;cursor:pointer!important;box-shadow:none!important;text-transform:none!important;letter-spacing:0!important}',
    '.zl form button:hover,.zl form input[type=submit]:hover{background:#0A2043!important}',
    '.zl form button.zl-eye{position:absolute!important;right:2px!important;top:2px!important;width:44px!important;height:44px!important;margin:0!important;padding:0!important;background:transparent!important;color:#64748B!important;border-radius:6px!important}',
    '.zl form button.zl-eye:hover{background:#F1F5F9!important}',
    '.zl-pw{position:relative;display:block}.zl-pw input{padding-right:52px!important}',
    '.zl form img,.zl form canvas,.zl form svg:not(.zl-i){max-width:100%;height:auto}',
    '.zl form p,.zl form div:not(.zl-pw),.zl form small,.zl form code{color:#334155}',
    '.zl-msgs{display:flex;flex-direction:column;gap:8px}',
    '.zl-msgs>*{margin:0!important;padding:12px 14px!important;border-radius:8px!important;font-size:14px!important;line-height:1.5!important}',
    '.zl-msgs>.zl-bad{background:#FEF2F2!important;border:1px solid #FECACA!important;color:#991B1B!important}',
    '.zl-msgs>.zl-info{background:#F1F2F5!important;border:1px solid #DBE0E8!important;color:#1E293B!important}',
    '.zl-note{display:flex;gap:12px;padding:14px 16px;border-radius:10px;background:#F1F2F5;border:1px solid #DBE0E8;font-size:13.5px;line-height:1.5;color:#334155}',
    '.zl-note svg{flex:0 0 auto;margin-top:1px}',
    '.zl-help{margin:0!important;font-size:14px!important;color:#475569!important}.zl-help a{color:#0F2C5B;font-weight:600;text-decoration:none}.zl-help a:hover{text-decoration:underline}',
    '.zl-legal{width:100%;max-width:400px;margin:0 auto!important;font-size:12px!important;line-height:1.6!important;color:#64748B!important}',
    '@media(max-width:720px){.zl-side{padding:28px 24px;gap:22px}.zl-mid h1{font-size:26px;-webkit-text-fill-color:#fff}.zl-caps,.zl-chips{display:none}.zl-art{max-width:340px}.zl-main{padding:32px 24px}}',
    '.zl-lang{display:flex;justify-content:flex-end;gap:6px;margin:0 0 14px}.zl-lang button{font:600 13px "IBM Plex Sans","Segoe UI",Tahoma,system-ui,sans-serif!important;border:1px solid #CBD5E1!important;background:#fff!important;color:#334155!important;border-radius:999px!important;padding:6px 14px!important;cursor:pointer;width:auto!important;margin:0!important}',
    '.zl-lang button[aria-pressed=true]{background:#0F2C5B!important;border-color:#0F2C5B!important;color:#fff!important}',
    'html.zl-rtl .zl{direction:rtl;text-align:right;font-family:"IBM Plex Sans Arabic","Segoe UI",Tahoma,system-ui,sans-serif}html.zl-rtl .zl-lang{justify-content:flex-start}html.zl-rtl .zl form input{text-align:right}html.zl-rtl .zl form input[type=password],html.zl-rtl .zl form input.zl-code,html.zl-rtl .zl form input[type=text]{direction:ltr;text-align:left}html.zl-rtl .zl-pw input{padding-right:12px!important;padding-left:52px!important}html.zl-rtl .zl form button.zl-eye{right:auto!important;left:2px!important}',
    /* ONE PAGE, ONE COLOUR: the whole screen is one navy canvas, the content and the sign-in card share one centre line in a
       two-column grid, and one accent (Sentra blue) is used for every action, link, focus ring, icon and chip */
    'html.zl-on,html.zl-on body{background:#071330!important}',
    '.zl{box-sizing:border-box!important;--zb:#2F7BF6;--zb2:#1E5FD6;--zt:#E8EEF9;--zm:#9DB0CF;display:grid!important;grid-template-columns:minmax(0,1fr) minmax(380px,440px);align-items:center;column-gap:clamp(40px,6vw,96px);row-gap:28px;min-height:100vh;padding:32px max(48px,calc((100vw - 1320px) / 2));background:radial-gradient(900px 600px at 0% 0%,rgba(47,123,246,.22),transparent 60%),radial-gradient(800px 600px at 100% 100%,rgba(47,123,246,.14),transparent 60%),linear-gradient(160deg,#061029 0%,#0A1C42 55%,#071330 100%)!important;color:var(--zt)}',
    '.zl:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:radial-gradient(rgba(255,255,255,.07) 1px,transparent 1.2px);background-size:24px 24px;-webkit-mask-image:linear-gradient(180deg,#000,transparent 85%);mask-image:linear-gradient(180deg,#000,transparent 85%)}',
    '.zl:after{content:"";position:fixed;left:0;right:0;top:0;height:3px;background:linear-gradient(90deg,transparent,var(--zb) 30%,#5AA2FF 70%,transparent)}',
    '.zl-side{width:100%;max-width:660px;justify-self:end;padding:0!important;background:none!important;gap:22px!important;justify-content:center!important;overflow:visible!important}.zl-side:before,.zl-side:after{display:none!important}',
    '.zl-wm b{background:linear-gradient(92deg,#FFFFFF,#CFE0FF)!important;-webkit-background-clip:text!important;background-clip:text!important;filter:none!important}.zl-wm b i{background:linear-gradient(92deg,#6FA8FF,var(--zb))!important;-webkit-background-clip:text!important;background-clip:text!important}.zl-wm span{color:var(--zm)!important}',
    '.zl-pill{border-color:rgba(157,176,207,.30)!important;background:rgba(255,255,255,.04)!important;color:var(--zt)!important}',
    '.zl-art{max-width:520px!important;max-height:190px;margin:0!important}',
    '.zl-mid{gap:16px!important;max-width:640px!important}',
    '.zl-mid h1{font-size:clamp(26px,2.4vw,34px)!important;background:none!important;-webkit-text-fill-color:#fff!important;color:#fff!important}',
    '.zl-mid .zl-sub2{color:#CFE0FF!important;background:rgba(47,123,246,.14)!important;border-color:rgba(47,123,246,.45)!important}',
    '.zl-mid p{font-size:15px!important;color:var(--zm)!important}',
    '.zl-caps{display:grid!important;grid-template-columns:1fr 1fr;gap:10px!important}.zl-caps li{padding:10px 12px!important;font-size:13.5px!important;line-height:1.35;background:rgba(255,255,255,.04)!important;border-color:rgba(157,176,207,.18)!important}',
    '.zl-caps i,.zl-caps li:nth-child(n) i{width:32px!important;height:32px!important;background:rgba(47,123,246,.16)!important;color:#8DB8FF!important;box-shadow:inset 0 0 0 1px rgba(47,123,246,.45)!important}',
    '.zl-chips{color:var(--zm)!important}.zl-chips b{background:rgba(47,123,246,.10)!important;border-color:rgba(47,123,246,.40)!important;color:#CFE0FF!important}.zl-chips b:before{background:var(--zb)!important;box-shadow:0 0 0 3px rgba(47,123,246,.20)!important}',
    '.zl-foot{color:var(--zm)!important;margin-top:4px}',
    '.zl-main{width:100%;max-width:440px;justify-self:start;padding:0!important;gap:16px!important;justify-content:center!important}',
    '.zl-card{max-width:none!important;padding:30px 32px;border-radius:18px;background:#fff;box-shadow:0 30px 80px rgba(2,8,23,.55),0 0 0 1px rgba(255,255,255,.06);gap:20px!important;color:#0F172A}',
    '.zl-logo{height:44px!important}',
    '.zl-legal{max-width:none!important;color:var(--zm)!important;text-align:center}',
    '.zl form input:focus{border-color:var(--zb)!important;box-shadow:0 0 0 3px rgba(47,123,246,.20)!important}',
    '.zl form button:not(.zl-eye),.zl form input[type=submit]{background:var(--zb)!important;border-color:var(--zb)!important}.zl form button:not(.zl-eye):hover,.zl form input[type=submit]:hover{background:var(--zb2)!important}',
    '.zl-help a{color:var(--zb2)!important}.zl-note{background:#F1F5FB!important;border-color:#DCE5F4!important}',
    '.zl-lang{margin:0!important}.zl-lang button[aria-pressed=true]{background:var(--zb)!important;border-color:var(--zb)!important}',
    '@media(max-height:820px){.zl-art{max-height:150px}.zl-mid p{display:none}}',
    '@media(max-width:980px){.zl{grid-template-columns:1fr;padding:28px 20px}.zl-main{order:-1}.zl-art,.zl-caps{display:none!important}.zl-mid h1{font-size:24px!important}}',
    '@media(prefers-reduced-motion:reduce){.zl *{transition:none!important;animation:none!important}}'
  ].concat(ASB ? [
    /* the organisation colours (switch on the main page, saved in zyb-dash-prefs.brand): the same layout in the brand colours */
    'html.zl-on,html.zl-on body{background:#060B12!important}',
    '.zl{box-sizing:border-box!important;--zb:#01579B;--zb2:#0F2C5B;--zt:#E5E9F0;--zm:#919CAD;display:grid!important;grid-template-columns:minmax(0,1fr) minmax(380px,440px);align-items:center;column-gap:clamp(40px,6vw,96px);row-gap:28px;min-height:100vh;padding:32px max(48px,calc((100vw - 1320px) / 2));background:radial-gradient(900px 600px at 0% 0%,rgba(23,64,129,.24),transparent 60%),radial-gradient(800px 600px at 100% 100%,rgba(15,44,91,.18),transparent 60%),linear-gradient(160deg,#050A11 0%,#0A1220 55%,#060B12 100%)!important;color:var(--zt)}',
    '.zl:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:radial-gradient(rgba(255,255,255,.07) 1px,transparent 1.2px);background-size:24px 24px;-webkit-mask-image:linear-gradient(180deg,#000,transparent 85%);mask-image:linear-gradient(180deg,#000,transparent 85%)}',
    '.zl:after{content:"";position:fixed;left:0;right:0;top:0;height:3px;background:linear-gradient(90deg,transparent,var(--zb) 30%,#4472BB 70%,transparent)}',
    '.zl-side{width:100%;max-width:660px;justify-self:end;padding:0!important;background:none!important;gap:22px!important;justify-content:center!important;overflow:visible!important}.zl-side:before,.zl-side:after{display:none!important}',
    '.zl-wm b{background:linear-gradient(92deg,#FFFFFF,#C6D7F3)!important;-webkit-background-clip:text!important;background-clip:text!important;filter:none!important}.zl-wm b i{background:linear-gradient(92deg,#89ADE6,var(--zb))!important;-webkit-background-clip:text!important;background-clip:text!important}.zl-wm span{color:var(--zm)!important}',
    '.zl-pill{border-color:rgba(145,156,173,.30)!important;background:rgba(255,255,255,.04)!important;color:var(--zt)!important}',
    '.zl-art{max-width:520px!important;max-height:190px;margin:0!important}',
    '.zl-mid{gap:16px!important;max-width:640px!important}',
    '.zl-mid h1{font-size:clamp(26px,2.4vw,34px)!important;background:none!important;-webkit-text-fill-color:#fff!important;color:#fff!important}',
    '.zl-mid .zl-sub2{color:#C6D7F3!important;background:rgba(15,44,91,.18)!important;border-color:rgba(68,114,187,.45)!important}',
    '.zl-mid p{font-size:15px!important;color:var(--zm)!important}',
    '.zl-caps{display:grid!important;grid-template-columns:1fr 1fr;gap:10px!important}.zl-caps li{padding:10px 12px!important;font-size:13.5px!important;line-height:1.35;background:rgba(255,255,255,.04)!important;border-color:rgba(145,156,173,.18)!important}',
    '.zl-caps i,.zl-caps li:nth-child(n) i{width:32px!important;height:32px!important;background:rgba(68,114,187,.16)!important;color:#89ADE6!important;box-shadow:inset 0 0 0 1px rgba(68,114,187,.45)!important}',
    '.zl-chips{color:var(--zm)!important}.zl-chips b{background:rgba(68,114,187,.10)!important;border-color:rgba(68,114,187,.40)!important;color:#C6D7F3!important}.zl-chips b:before{background:var(--zb)!important;box-shadow:0 0 0 3px rgba(68,114,187,.20)!important}',
    '.zl-foot{color:var(--zm)!important;margin-top:4px}',
    '.zl-main{width:100%;max-width:440px;justify-self:start;padding:0!important;gap:16px!important;justify-content:center!important}',
    '.zl-card{max-width:none!important;padding:30px 32px;border-radius:18px;background:#fff;box-shadow:0 30px 80px rgba(2,8,23,.55),0 0 0 1px rgba(255,255,255,.06);gap:20px!important;color:#0F172A}',
    '.zl-logo{height:44px!important}',
    '.zl-legal{max-width:none!important;color:var(--zm)!important;text-align:center}',
    '.zl form input:focus{border-color:var(--zb)!important;box-shadow:0 0 0 3px rgba(68,114,187,.20)!important}',
    '.zl form button:not(.zl-eye),.zl form input[type=submit]{background:var(--zb)!important;border-color:var(--zb)!important}.zl form button:not(.zl-eye):hover,.zl form input[type=submit]:hover{background:var(--zb2)!important}',
    '.zl-help a{color:var(--zb2)!important}.zl-note{background:#F1F3F7!important;border-color:#D6DDE8!important}',
    '.zl-lang{margin:0!important}.zl-lang button[aria-pressed=true]{background:var(--zb)!important;border-color:var(--zb)!important}',
    '@media(max-height:820px){.zl-art{max-height:150px}.zl-mid p{display:none}}',
    '@media(max-width:980px){.zl{grid-template-columns:1fr;padding:28px 20px}.zl-main{order:-1}.zl-art,.zl-caps{display:none!important}.zl-mid h1{font-size:24px!important}}',
  ] : []).join('') + [
    /* CENTRED: one column on the centre line - brand, sign-in card, frameworks, footer - over a deep animated canvas */
    'html.zl-on,html.zl-on body{background:' + (ASB ? '#04142D' : '#030817') + '!important}',
    '.zl{display:flex!important;flex-direction:column!important;flex-wrap:nowrap!important;align-items:center!important;justify-content:center!important;gap:18px!important;min-height:100vh;padding:34px 20px 22px!important;isolation:isolate;overflow-x:hidden}',
    '.zl:before{display:none!important}.zl:after{z-index:2}',
    '.zl-bg{position:fixed;inset:0;z-index:-1;pointer-events:none;overflow:hidden;background:radial-gradient(1100px 620px at 50% -12%,rgba(' + RGB + ',.30),transparent 62%),radial-gradient(900px 500px at 50% 112%,rgba(' + RGB + ',.18),transparent 60%),linear-gradient(180deg,' + (ASB ? '#09244E,#071B3B 45%,#041228' : '#071331,#040B20 55%,#030817') + ')}',
    '.zl-bg i{position:absolute;border-radius:50%;filter:blur(90px);opacity:.42;animation:zl-drift 26s ease-in-out infinite alternate}',
    '.zl-bg .b1{width:560px;height:560px;left:-180px;top:6%;background:' + C1 + '}.zl-bg .b2{width:460px;height:460px;right:-140px;top:28%;background:' + C2 + ';opacity:.28;animation-delay:-9s}.zl-bg .b3{width:420px;height:420px;left:38%;bottom:-220px;background:' + (ASB ? '#C9A227' : '#6D5DFC') + ';opacity:.26;animation-delay:-17s}',
    '@keyframes zl-drift{0%{transform:translate(0,0) scale(1)}50%{transform:translate(60px,-40px) scale(1.12)}100%{transform:translate(-40px,30px) scale(.94)}}',
    '.zl-dots{position:absolute;inset:0;background-image:radial-gradient(rgba(255,255,255,.09) 1px,transparent 1.3px);background-size:26px 26px;-webkit-mask-image:radial-gradient(ellipse 70% 60% at 50% 40%,#000 20%,transparent 75%);mask-image:radial-gradient(ellipse 70% 60% at 50% 40%,#000 20%,transparent 75%)}',
    '.zl-rings{position:absolute;left:50%;top:50%;width:min(1100px,150vw);height:auto;transform:translate(-50%,-50%);opacity:.9}',
    '.zl-orb{animation:zl-spin 38s linear infinite}.zl-orb.o2{animation-duration:64s;animation-direction:reverse}.zl-orb.o3{animation-duration:30s}',
    '.zl-floor{position:absolute;left:-50%;right:-50%;bottom:-6%;height:46%;background-image:linear-gradient(rgba(' + RGB + ',.20) 1px,transparent 1px),linear-gradient(90deg,rgba(' + RGB + ',.20) 1px,transparent 1px);background-size:64px 64px;transform:perspective(520px) rotateX(64deg);transform-origin:50% 100%;-webkit-mask-image:linear-gradient(to top,#000 0%,transparent 80%);mask-image:linear-gradient(to top,#000 0%,transparent 80%);animation:zl-floor 9s linear infinite}',
    '@keyframes zl-floor{to{background-position:0 64px,0 0}}',
    '.zl-brand{display:flex;flex-direction:column;align-items:center;gap:12px;text-align:center;max-width:620px;animation:zl-up .7s ease-out both}',
    '.zl-lockup{display:flex;align-items:center;gap:14px}',
    '.zl-mark{width:58px;height:58px;flex:0 0 auto;filter:drop-shadow(0 10px 28px rgba(' + RGB + ',.55));animation:zl-glow 5s ease-in-out infinite}',
    '@keyframes zl-glow{0%,100%{filter:drop-shadow(0 10px 26px rgba(' + RGB + ',.45))}50%{filter:drop-shadow(0 10px 34px rgba(' + RGB + ',.85))}}',
    '.zl-wm{align-items:flex-start;text-align:left}.zl-wm b{font-size:27px!important;letter-spacing:.22em!important}.zl-wm span{font-size:10.5px!important;letter-spacing:.38em!important;color:var(--zm)!important}',
    '.zl-title{margin:4px 0 0!important;font:500 15px/1.5 "IBM Plex Sans","Segoe UI",system-ui,sans-serif!important;letter-spacing:.01em!important;color:var(--zm)!important;text-transform:none!important;background:none!important;-webkit-text-fill-color:currentColor!important}',
    '.zl-pill{align-self:center!important;height:26px!important;font-size:12px!important;color:var(--zt)!important}',
    '.zl-main{width:100%!important;max-width:440px!important;justify-self:auto!important;padding:0!important;animation:zl-up .7s .12s ease-out both}',
    '.zl-card{position:relative;padding:30px 34px 28px!important;border-radius:20px!important;background:rgba(255,255,255,.985)!important;box-shadow:0 40px 90px rgba(0,0,0,.55),0 0 0 1px rgba(255,255,255,.08),0 0 80px rgba(' + RGB + ',.18)!important;gap:18px!important;overflow:hidden}',
    '.zl-card:before{content:"";position:absolute;left:0;right:0;top:0;height:4px;background:linear-gradient(90deg,' + C1 + ',' + C2 + ')}',
    '.zl-cardtop{display:flex;align-items:center;justify-content:space-between;gap:12px}',
    '.zl-logo{height:40px!important;align-self:center!important}',
    '.zl-lang{gap:0!important;padding:3px;border-radius:999px;background:#F1F5F9;border:1px solid #E2E8F0}.zl-lang button{border:0!important;background:transparent!important;color:#475569!important;border-radius:999px!important;padding:5px 12px!important;min-width:0!important;height:auto!important;font-size:12.5px!important;box-shadow:none!important;text-shadow:none!important;filter:none!important}.zl-lang:before,.zl-lang:after,.zl-lang button:before,.zl-lang button:after{display:none!important}',
    '.zl-lang button[aria-pressed=true]{background:var(--zb)!important;color:#fff!important;box-shadow:0 2px 8px rgba(' + RGB + ',.35)!important}',
    '.zl-head{text-align:center}.zl-head h2{font-size:26px!important}.zl-head p{color:#64748B!important}',
    '.zl form button:not(.zl-eye),.zl form input[type=submit]{border-radius:12px!important;box-shadow:0 10px 24px rgba(' + RGB + ',.32)!important;transition:transform .15s,box-shadow .15s}.zl form button:not(.zl-eye):hover{transform:translateY(-1px)}',
    '.zl form input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){border-radius:12px!important;background:#F8FAFC!important}',
    '.zl-help{text-align:center}',
    '.zl-chips{justify-content:center;animation:zl-up .7s .24s ease-out both}',
    '.zl-end{display:flex;flex-direction:column;align-items:center;gap:8px;max-width:620px;text-align:center}',
    '.zl-foot{justify-content:center!important;gap:14px!important;margin:0!important}.zl-sep{width:4px;height:4px;border-radius:50%;background:var(--zm);opacity:.6}',
    '.zl-legal{font-size:11.5px!important;opacity:.85}',
    '@keyframes zl-up{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}',
    'html.zl-rtl .zl-head,html.zl-rtl .zl-help{text-align:center}',
    '@media(max-width:980px){.zl-main{order:0!important}}',
    '@media(max-width:560px){.zl-pill,.zl-sep{display:none!important}.zl{padding:22px 14px 18px!important;gap:14px!important}.zl-card{padding:24px 20px!important}.zl-wm b{font-size:20px!important;letter-spacing:.16em!important}.zl-mark{width:44px;height:44px}.zl-title{font-size:13px!important}.zl-chips{display:none!important}}',
    '@media(max-height:760px){.zl-title,.zl-chips{display:none!important}.zl{gap:14px!important}}',
    '.zl{padding:26px 28px 16px!important;gap:16px!important}',
    '.zl-shell{position:relative;width:100%;max-width:1140px;display:grid;grid-template-columns:minmax(0,1.08fr) minmax(380px,440px);align-items:center;column-gap:72px;row-gap:18px}',
    '.zl-hero{display:flex;flex-direction:column;gap:20px;min-width:0;color:var(--zt);animation:zl-up .7s ease-out both}',
    '.zl-shell .zl-brand{align-items:flex-start!important;text-align:start!important;max-width:none!important;gap:10px!important;animation:none!important}.zl-shell .zl-pill{align-self:flex-start!important}',
    '.zl-pitch{margin:6px 0 0;font:650 clamp(28px,2.9vw,42px)/1.14 "IBM Plex Sans","Segoe UI",system-ui,sans-serif;letter-spacing:-.6px;color:#fff;max-width:560px}.zl-pitch em{font-style:normal;background:linear-gradient(92deg,#B4CDF6,' + C2 + ');-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}',
    '.zl-shell .zl-title{margin:0!important;font-size:15.5px!important;max-width:520px}',
    '.zl-shell .zl-caps{max-width:560px}.zl-shell .zl-caps li{-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);transition:transform .2s,border-color .2s}.zl-shell .zl-caps li:hover{transform:translateY(-2px);border-color:rgba(' + RGB + ',.55)!important}',
    '.zl-shell .zl-chips{justify-content:flex-start!important;animation:none!important}',
    '.zl-clock{display:inline-flex;align-items:center;gap:9px;font-size:12.5px;color:var(--zm);font-variant-numeric:tabular-nums}.zl-clock:before{content:"";width:7px;height:7px;border-radius:50%;background:' + C2 + ';box-shadow:0 0 0 4px rgba(' + RGB + ',.22);animation:zl-pl 2.6s ease-in-out infinite}',
    '.zl-card{border-radius:22px!important;padding:28px 34px 26px!important;gap:16px!important}',
    '.zl-steps{display:flex;align-items:center;gap:10px;margin:0;padding:0;list-style:none;font-size:12.5px;font-weight:600;color:#94A3B8}.zl-steps li{display:flex;align-items:center;gap:8px;white-space:nowrap}.zl-steps li i{font-style:normal;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;font-size:12px;background:#E2E8F0;color:#64748B}',
    '.zl-steps li.on{color:#0F172A}.zl-steps li.on i{background:var(--zb);color:#fff;box-shadow:0 0 0 4px rgba(' + RGB + ',.16)}.zl-steps li.done{color:var(--zb2)}.zl-steps li.done i{background:rgba(' + RGB + ',.16);color:var(--zb2)}.zl-steps span.ln{flex:1 1 auto;height:2px;border-radius:2px;background:#E2E8F0}.zl-steps span.ln.done{background:var(--zb)}',
    '.zl form input.zl-fi:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){background-repeat:no-repeat!important;background-position:14px 50%!important;background-size:18px 18px!important;padding-left:44px!important}',
    '.zl form input.zl-fu:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){background-image:url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2718%27 height=%2718%27 viewBox=%270 0 24 24%27 fill=%27none%27 stroke=%27%2394A3B8%27 stroke-width=%271.9%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27%3E%3Ccircle cx=%2712%27 cy=%278%27 r=%274%27/%3E%3Cpath d=%27M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5%27/%3E%3C/svg%3E")!important}.zl form input.zl-fp:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){background-image:url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2718%27 height=%2718%27 viewBox=%270 0 24 24%27 fill=%27none%27 stroke=%27%2394A3B8%27 stroke-width=%271.9%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27%3E%3Crect x=%275%27 y=%2711%27 width=%2714%27 height=%2710%27 rx=%272%27/%3E%3Cpath d=%27M8 11V8a4 4 0 0 1 8 0v3%27/%3E%3C/svg%3E")!important}',
    '.zl form input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){transition:border-color .15s,box-shadow .15s,background-color .15s}.zl form input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]):hover{border-color:#94A3B8!important}.zl form input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]):focus{background-color:#fff!important}',
    '.zl-capsw{display:none;align-items:center;gap:7px;margin:6px 0 0;font-size:12.5px;font-weight:600;color:#B45309}.zl-capsw.on{display:flex}',
    '.zl form button:not(.zl-eye):after{content:"\\2192";margin-inline-start:10px;font-size:17px;line-height:1;transition:transform .15s}html.zl-rtl .zl form button:not(.zl-eye):after{content:"\\2190"}.zl form button:not(.zl-eye):hover:after{transform:translateX(3px)}html.zl-rtl .zl form button:not(.zl-eye):hover:after{transform:translateX(-3px)}',
    '.zl-busy form button:not(.zl-eye){pointer-events:none!important;opacity:.9}.zl-busy form button:not(.zl-eye):after{content:""!important;width:16px;height:16px;border-radius:50%;border:2px solid rgba(255,255,255,.45);border-top-color:#fff;animation:zl-spin .7s linear infinite;transform:none!important}',
    '.zl-note{padding:11px 14px!important;font-size:13px!important}',
    '.zl-trust{display:flex;flex-wrap:wrap;justify-content:center;gap:8px 18px;margin:14px 0 0;padding:0;list-style:none;font-size:12px;color:var(--zm)}.zl-trust li{display:inline-flex;align-items:center;gap:6px}.zl-trust svg{color:' + C2 + '}',
    '@media(max-width:1080px){.zl-shell{grid-template-columns:1fr;max-width:440px}.zl-hero{align-items:center;text-align:center;gap:12px}.zl-shell .zl-brand{align-items:center!important;text-align:center!important}.zl-shell .zl-pill{align-self:center!important}.zl-pitch,.zl-eyebrow,.zl-shell .zl-caps,.zl-clock{display:none!important}.zl-shell .zl-chips{justify-content:center!important}}',
    '@media(min-width:1081px) and (max-height:760px){.zl-shell .zl-title{display:block!important}.zl-shell .zl-chips{display:flex!important}.zl-shell .zl-caps{display:none!important}}',
    '@media(max-height:700px){.zl-note,.zl-legal,.zl-trust{display:none!important}}',
    '@media(max-width:560px){.zl-steps{font-size:12px}.zl-card{padding:22px 18px!important}}',
    'html.zl-rtl .zl form input.zl-fi:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){background-position:right 14px top 50%!important;padding-right:44px!important;padding-left:14px!important}html.zl-rtl .zl form .zl-pw input.zl-fi:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){padding-left:52px!important}',
    '.zl-bg:after{content:"";position:absolute;inset:0;background:radial-gradient(ellipse 60% 55% at 72% 46%,rgba(255,255,255,.07),transparent 60%),radial-gradient(ellipse 120% 90% at 50% 50%,transparent 55%,rgba(0,0,0,.42))}',
    '.zl:after{height:2px!important;background:linear-gradient(90deg,transparent,#D9B95B 22%,' + C2 + ' 55%,#D9B95B 82%,transparent)!important;opacity:.9}',
    '.zl-eyebrow{display:inline-flex;align-items:center;gap:10px;font:600 11.5px/1 "IBM Plex Sans","Segoe UI",system-ui,sans-serif;letter-spacing:.28em;text-transform:uppercase;color:#D9B95B}.zl-eyebrow:before{content:"";width:28px;height:1px;background:linear-gradient(90deg,#D9B95B,transparent)}html.zl-rtl .zl-eyebrow{letter-spacing:0;font-size:13px}html.zl-rtl .zl-eyebrow:before{background:linear-gradient(270deg,#D9B95B,transparent)}',
    '.zl-pitch{font-weight:600!important;letter-spacing:-.9px!important;text-shadow:0 2px 30px rgba(0,0,0,.25)}.zl-pitch em{background:linear-gradient(92deg,#F1E3B0 0%,#B4CDF6 38%,' + C2 + ' 100%)!important;-webkit-background-clip:text!important;background-clip:text!important}',
    '.zl-wm b{letter-spacing:.26em!important}',
    '.zl-shell .zl-caps li{position:relative;border:0!important;border-radius:14px!important;padding:13px 14px!important;background:linear-gradient(160deg,rgba(255,255,255,.085),rgba(255,255,255,.025))!important;box-shadow:inset 0 0 0 1px rgba(255,255,255,.10),inset 0 1px 0 rgba(255,255,255,.14),0 12px 30px rgba(0,0,0,.18)}.zl-shell .zl-caps li:hover{box-shadow:inset 0 0 0 1px rgba(217,185,91,.55),inset 0 1px 0 rgba(255,255,255,.18),0 16px 36px rgba(0,0,0,.26)!important}',
    '.zl-shell .zl-caps i,.zl-shell .zl-caps li:nth-child(n) i{border-radius:10px!important;background:linear-gradient(150deg,rgba(' + RGB + ',.55),rgba(' + RGB + ',.18))!important;color:#E8F0FC!important;box-shadow:inset 0 0 0 1px rgba(255,255,255,.18),0 6px 14px rgba(0,0,0,.22)!important}',
    '.zl-chips b{background:rgba(217,185,91,.08)!important;border-color:rgba(217,185,91,.38)!important;color:#F1E3B0!important;letter-spacing:.06em}.zl-chips b:before{background:#D9B95B!important;box-shadow:0 0 0 3px rgba(217,185,91,.18)!important}',
    '.zl-pill{border-color:rgba(217,185,91,.35)!important;background:rgba(217,185,91,.07)!important;color:#F1E3B0!important}',
    '.zl-main{position:relative}.zl-main:before{content:"";position:absolute;inset:-70px -60px;z-index:-1;border-radius:50%;background:radial-gradient(closest-side,rgba(' + RGB + ',.38),transparent 72%);filter:blur(12px);pointer-events:none}',
    '.zl-card{border-radius:24px!important;padding:30px 36px 28px!important;background:linear-gradient(180deg,#FFFFFF 0%,#FBFCFD 100%)!important;box-shadow:0 1px 0 rgba(255,255,255,.9) inset,0 60px 120px -20px rgba(0,0,0,.62),0 30px 60px -30px rgba(0,0,0,.5),0 0 0 1px rgba(255,255,255,.10)!important;overflow:visible!important}',
    '.zl-card:before{content:""!important;position:absolute!important;inset:-1.5px!important;height:auto!important;border-radius:25.5px;padding:1.5px;background:linear-gradient(140deg,#D9B95B 0%,rgba(217,185,91,.25) 22%,' + C2 + ' 50%,rgba(' + RGB + ',.35) 78%,#D9B95B 100%)!important;-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box exclude,linear-gradient(#000 0 0);pointer-events:none}',
    '.zl-cardtop{padding-bottom:16px;border-bottom:1px solid #EEEFF2}',
    '.zl-head h2{font-size:27px!important;font-weight:650!important;letter-spacing:-.5px!important}.zl-head p{font-size:14.5px!important}',
    '.zl-steps li.on i{background:linear-gradient(150deg,' + C1 + ',#0F2C5B)!important;box-shadow:0 0 0 3px #fff,0 0 0 4.5px rgba(217,185,91,.75)!important}',
    '.zl form label{font-size:12px!important;font-weight:600!important;letter-spacing:.08em!important;text-transform:uppercase!important;color:#475569!important}html.zl-rtl .zl form label{letter-spacing:0!important;font-size:13.5px!important}',
    '.zl form input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){height:50px!important;border-radius:13px!important;background-color:#F6F7F9!important;border-color:#DBDFE6!important;box-shadow:inset 0 1px 2px rgba(15,23,42,.04)!important}.zl form input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]):focus{border-color:' + C1 + '!important;box-shadow:0 0 0 4px rgba(' + RGB + ',.16),inset 0 1px 2px rgba(15,23,42,.04)!important}',
    '.zl form button.zl-eye{top:3px!important}',
    '.zl form button:not(.zl-eye),.zl form input[type=submit]{position:relative!important;overflow:hidden!important;height:52px!important;border:0!important;border-radius:14px!important;font-weight:650!important;letter-spacing:.02em!important;background-color:' + C1 + '!important;background-image:linear-gradient(180deg,#1B4FA3 0%,' + C1 + ' 48%,#0F2C5B 100%)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.28),inset 0 -1px 0 rgba(0,0,0,.18),0 14px 30px -8px rgba(' + RGB + ',.65)!important}',
    '.zl form button:not(.zl-eye):hover,.zl form input[type=submit]:hover{background-color:' + C1 + '!important;background-image:linear-gradient(180deg,#1E55AE 0%,#01579B 48%,#0D254D 100%)!important}',
    '.zl form button:not(.zl-eye):before{content:"";position:absolute;top:0;bottom:0;left:-60%;width:45%;background:linear-gradient(100deg,transparent,rgba(255,255,255,.28),transparent);transform:skewX(-18deg);animation:zl-sheen 5.5s ease-in-out infinite;pointer-events:none}@keyframes zl-sheen{0%,62%{left:-60%}100%{left:130%}}',
    '.zl-note{border-radius:12px!important;background:linear-gradient(180deg,#F4F6F9,#EDF1F6)!important;border-color:#D8DEE9!important}',
    '.zl-help{font-size:13.5px!important}',
    '.zl-trust{margin-top:18px!important;gap:8px 10px!important}.zl-trust li{padding:5px 11px;border-radius:999px;background:rgba(255,255,255,.05);box-shadow:inset 0 0 0 1px rgba(255,255,255,.10);color:var(--zt)}.zl-trust svg{color:#D9B95B!important}',
    '.zl-clock:before{background:#D9B95B!important;box-shadow:0 0 0 4px rgba(217,185,91,.20)!important}',
    '@media(max-width:560px){.zl-card{padding:24px 20px!important;border-radius:20px!important}.zl-card:before{border-radius:21.5px}.zl-main:before{display:none}}',
    '.zl{display:grid!important;grid-template-columns:minmax(0,1fr)!important;column-gap:0!important;row-gap:0!important;grid-template-rows:auto minmax(0,1fr) auto!important;justify-items:center!important;align-items:stretch!important;flex-direction:unset!important;gap:0!important;padding:0!important;min-height:100vh!important;height:auto}',
    '.zl-top,.zl-shell,.zl-end{width:100%;max-width:1200px;padding-left:40px!important;padding-right:40px!important;box-sizing:border-box}',
    '.zl-top{display:flex;align-items:center;justify-content:space-between;gap:20px;padding-top:22px!important;padding-bottom:22px!important;border-bottom:1px solid rgba(255,255,255,.07);animation:zl-up .6s ease-out both}',
    '.zl-top .zl-brand{display:flex!important;flex-direction:row!important;align-items:center!important;gap:18px!important;text-align:start!important;max-width:none!important;animation:none!important;min-width:0}',
    '.zl-top .zl-mark{width:40px!important;height:40px!important}.zl-top .zl-lockup{gap:11px!important}.zl-top .zl-wm b{font-size:19px!important;letter-spacing:.24em!important}.zl-top .zl-wm span{font-size:9px!important;letter-spacing:.34em!important}',
    '.zl-vr{width:1px;height:30px;background:rgba(255,255,255,.16);flex:0 0 auto}',
    '.zl-top .zl-title{margin:0!important;font-size:13.5px!important;line-height:1.35!important;color:var(--zm)!important;max-width:300px;display:block!important}',
    '.zl-top .zl-pill{align-self:center!important;flex:0 0 auto}',
    '.zl-shell{align-self:center!important;display:grid!important;grid-template-columns:minmax(0,1fr) 420px!important;column-gap:clamp(40px,6vw,96px)!important;align-items:center!important;padding-top:28px!important;padding-bottom:28px!important}',
    '.zl-hero{gap:22px!important;justify-content:center}',
    '.zl-eyebrow{align-self:flex-start}',
    '.zl-pitch{margin:0!important;font-size:clamp(28px,2.7vw,40px)!important;line-height:1.14!important;max-width:540px!important}',
    '.zl-shell .zl-caps{display:grid!important;grid-template-columns:1fr 1fr!important;max-width:580px!important;margin:4px 0 0!important}',
    '.zl-shell .zl-chips{display:flex!important;justify-content:flex-start!important;margin:0!important}',
    '.zl-main{max-width:420px!important;width:100%!important;justify-self:end}',
    '.zl-card{padding:26px 30px 24px!important;gap:15px!important}',
    '.zl-cardtop{padding-bottom:14px!important}',
    '.zl-head h2{font-size:25px!important;margin-bottom:4px!important}',
    '.zl form label{margin-top:10px!important}',
    '.zl form input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=submit]){height:48px!important}',
    '.zl form button:not(.zl-eye),.zl form input[type=submit]{height:50px!important;margin-top:16px!important}',
    '.zl-note{padding:10px 13px!important;font-size:12.5px!important}',
    '.zl-help{font-size:13px!important}',
    '.zl-end{display:flex!important;flex-direction:column!important;align-items:stretch!important;gap:8px!important;max-width:1200px!important;padding-top:14px!important;padding-bottom:16px!important;border-top:1px solid rgba(255,255,255,.07);text-align:start!important}',
    '.zl-barrow{display:flex;align-items:center;justify-content:space-between;gap:12px 20px;flex-wrap:wrap}',
    '.zl-end .zl-trust{margin:0!important;justify-content:center!important;flex:1 1 auto}',
    '.zl-end .zl-foot{margin:0!important;justify-content:flex-end!important;flex-wrap:nowrap}',
    '.zl-end .zl-legal{margin:0!important;text-align:center!important;font-size:11px!important;opacity:.7;max-width:none!important}',
    '.zl-end .zl-clock{flex:0 0 auto;display:inline-flex!important}',
    '@media(max-height:820px){.zl-top{padding-top:14px!important;padding-bottom:14px!important}.zl-shell{padding-top:16px!important;padding-bottom:16px!important}.zl-hero{gap:16px!important}.zl-note{display:none!important}.zl-end .zl-legal{display:none!important}}',
    '@media(max-height:700px){.zl-shell .zl-caps{display:none!important}}',
    '@media(max-width:1080px){.zl-shell{grid-template-columns:1fr!important;max-width:520px!important;row-gap:18px!important}.zl-main{justify-self:center;order:-1}.zl-hero{align-items:center;text-align:center}.zl-eyebrow,.zl-pitch,.zl-shell .zl-caps{display:none!important}.zl-shell .zl-chips{justify-content:center!important}.zl-top .zl-title,.zl-vr{display:none!important}.zl-barrow{justify-content:center}.zl-end .zl-clock{display:none!important}}',
    '@media(max-width:560px){.zl-top,.zl-shell,.zl-end{padding-left:16px!important;padding-right:16px!important}.zl-top .zl-pill{display:none!important}.zl-top{justify-content:center}.zl-shell .zl-chips{display:none!important}.zl-end .zl-foot{justify-content:center!important;flex-wrap:wrap}}',
    'html.zl-rtl .zl-top .zl-brand,html.zl-rtl .zl-end{text-align:right!important}'
  ].join('');
  (document.head || de).appendChild(css);

  function reveal() { de.classList.remove('zl-pre'); }
  function el(tag, attrs, html) { var e = document.createElement(tag); if (attrs) Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); }); if (html != null) e.innerHTML = html; return e; }
  var I = {
    ai: '<svg class="zl-i" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v3M12 18v3M3 12h3M18 12h3M6 6l2 2M16 16l2 2M6 18l2-2M16 8l2-2"/><circle cx="12" cy="12" r="3.5"/></svg>',
    lock: '<svg class="zl-i" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
    srv: '<svg class="zl-i" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01"/></svg>',
    shield: '<svg class="zl-i" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6zM9 12l2 2 4-4"/></svg>',
    list: '<svg class="zl-i" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6h10M10 12h10M10 18h10M4 6l1 1 2-2M4 12l1 1 2-2M4 18l1 1 2-2"/></svg>',
    tls: '<svg class="zl-i" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
    ok: '<svg class="zl-i" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6zM9 12l2 2 4-4"/></svg>',
    rec: '<svg class="zl-i" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 4h8l4 4v12H4V4zM8 13h8M8 17h5"/></svg>',
    eye: '<svg class="zl-i" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
    note: '<svg class="zl-i" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="' + (ASB ? '#01579B' : '#2F7BF6') + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/></svg>'
  };
  // the brand mark: a hexagon carrying an "S" drawn as a circuit trace with a node at each end (Zyberon Sentra's own mark)
  var HEX = 'M32 5 L55 18.5 V45.5 L32 59 L9 45.5 V18.5 Z';
  var MARK = '<svg class="zl-mark" viewBox="0 0 64 64" role="img" aria-label="Zyberon Sentra"><defs>'
    + '<linearGradient id="zlmk" x1="8" y1="4" x2="56" y2="60" gradientUnits="userSpaceOnUse"><stop stop-color="' + C1 + '"/><stop offset="1" stop-color="' + C2 + '"/></linearGradient>'
    + '<linearGradient id="zlmg" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#fff" stop-opacity=".32"/><stop offset=".55" stop-color="#fff" stop-opacity="0"/></linearGradient></defs>'
    + '<path d="' + HEX + '" fill="url(#zlmk)" stroke="url(#zlmk)" stroke-width="6" stroke-linejoin="round"/><path d="' + HEX + '" fill="url(#zlmg)"/>'
    + '<path d="M41 22.5C38.8 20 35.6 18.8 32 18.8c-5.4 0-9.2 2.8-9.2 6.8 0 8 18.4 4 18.4 12.4 0 4.2-4 7.2-9.2 7.2-4 0-7.4-1.4-9.4-4" fill="none" stroke="#fff" stroke-width="4.2" stroke-linecap="round"/>'
    + '<circle cx="41" cy="22.5" r="3.3" fill="#fff"/><circle cx="22.6" cy="41.2" r="3.3" fill="#fff"/></svg>';
  // background: slow orbits around the centre line, two travelling signals
  var RINGS = '<svg class="zl-rings" viewBox="-320 -320 640 640"><g fill="none" stroke="rgba(' + RGB + ',.22)" stroke-width="1"><circle r="170" stroke-dasharray="2 9"/><circle r="236"/><circle r="306" stroke-dasharray="1 12"/></g>'
    + '<g class="zl-orb"><circle cx="236" cy="0" r="3.4" fill="' + C2 + '"/></g><g class="zl-orb o2"><circle cx="0" cy="-306" r="2.6" fill="' + C1 + '"/></g><g class="zl-orb o3"><circle cx="-170" cy="0" r="2.4" fill="' + C2 + '"/></g></svg>';

  // the headline: the last word pair carries the accent; one sentence, translated whole
  function pitch() { var t = T('One platform for IT operations, security and compliance.'); return LANG === 'ar' ? t : 'One platform for IT operations, <em>security and compliance.</em>'; }
  // where the person is in signing in: 1 password, 2 code from the authenticator app (not drawn on other pages, e.g. enrolment)
  function steps(step) {
    if (step === 'other') return '';
    var two = step === 'code';
    return '<ol class="zl-steps" aria-label="' + T('Step') + ' ' + (two ? 2 : 1) + ' / 2"><li class="' + (two ? 'done' : 'on') + '"><i>' + (two ? '\u2713' : '1') + '</i>' + T('Password') + '</li><span class="ln' + (two ? ' done' : '') + '"></span><li class="' + (two ? 'on' : '') + '"><i>2</i>' + T('Verification code') + '</li></ol>';
  }
  var CLOCK = null;
  function clock(node) {
    if (CLOCK) clearInterval(CLOCK);
    var draw = function () { try { var loc = LANG === 'ar' ? 'ar-u-ca-gregory-nu-latn' : 'en-GB', d = new Date();
      node.textContent = T('Riyadh time') + ' ' + d.toLocaleTimeString(loc, { timeZone: 'Asia/Riyadh', hour: '2-digit', minute: '2-digit', hour12: false }) + ' \u00b7 ' + d.toLocaleDateString(loc, { timeZone: 'Asia/Riyadh', weekday: 'long', day: 'numeric', month: 'long' }); } catch (e) { node.style.display = 'none'; /* a browser without time zones: no clock */ } };
    draw(); CLOCK = setInterval(draw, 20000);
  }

  function build() {
    var form = document.querySelector('form');
    if (!form || document.querySelector('.zl')) { reveal(); return; }
    var pass = form.querySelector('input[type=password]');
    var code = !pass && form.querySelector('input[autocomplete="one-time-code"],input[inputmode=numeric],input[name*="otp" i],input[name*="code" i],input[name*="token" i]:not([type=hidden])');
    // a QR code (an image that is not a logo, or a canvas) means enrolment: keep that page's own heading and steps
    var qr = [].some.call(form.querySelectorAll('img,canvas,svg:not(.zl-i)'), function (x) { return x.tagName !== 'IMG' || !/logo|zyberon/i.test((x.getAttribute('src') || '') + ' ' + (x.getAttribute('alt') || '') + ' ' + x.className); });
    var step = pass ? 'password' : code && !qr ? 'code' : 'other';

    // the service's messages (wrong password, locked, expired code...) - kept, moved above the form
    var msgs = el('div', { class: 'zl-msgs', 'aria-live': 'polite' });
    [].slice.call(document.querySelectorAll('.err,.error,.alert,.msg,.notice,.ok,.success,.warn,[role=alert]')).forEach(function (m) {
      if (m.closest('.zl') || !String(m.textContent || '').trim()) return;
      m.classList.add(/err|error|alert|warn/i.test(m.className) || m.getAttribute('role') === 'alert' ? 'zl-bad' : 'zl-info');
      msgs.appendChild(m);
    });

    // decoration inside the form: logo boxes, taglines, policy chips, its own heading and footer. Never an input, a
    // button, a label, a hidden field or an image that is not a logo (a QR code on the enrolment page stays).
    var isLogo = function (img) { return /logo|zyberon/i.test((img.getAttribute('src') || '') + ' ' + (img.getAttribute('alt') || '') + ' ' + img.className); };
    [].slice.call(form.querySelectorAll('.zyb-coab,.zyb-tag,.badges,.foot,.aslogo,h1,h2,.sub,img')).forEach(function (x) {
      if (x.tagName === 'IMG' && !isLogo(x)) return;
      if (x.querySelector && x.querySelector('input,button,select,textarea,canvas,img:not(.aslogo):not(.zyb-mark):not(.zyb-tenant)') && x.tagName !== 'IMG') return;
      if (step === 'other' && /^H[12]$/.test(x.tagName)) return;   // an unknown page keeps its own wording
      x.style.setProperty('display', 'none', 'important'); x.setAttribute('data-zl-hidden', '');
    });

    if (pass) {   // show / hide password: the field stays the same input, only wrapped
      var w = el('span', { class: 'zl-pw' }); pass.parentNode.insertBefore(w, pass); w.appendChild(pass);
      var eye = el('button', { type: 'button', class: 'zl-eye', 'aria-label': T('Show password'), 'aria-pressed': 'false' }, I.eye);
      eye.addEventListener('click', function () { var s = pass.type === 'password'; pass.type = s ? 'text' : 'password'; eye.setAttribute('aria-pressed', String(s)); eye.setAttribute('aria-label', T(s ? 'Hide password' : 'Show password')); pass.focus(); });
      w.appendChild(eye);
    }
    if (code) code.classList.add('zl-code');
    // the service's own words in the form (AD sign-in: Username / Password, "Sign in with your <domain> account", the single
    // sign-on link and its "or" line) follow the chosen language. The English original is kept on the node, so switching back
    // restores it; no field, name, value or action changes. Account names are Latin: the two fields stay left-to-right.
    var said = function (node) { if (node.__zlEn == null) node.__zlEn = node.nodeValue; return node.__zlEn; };
    [].forEach.call(form.querySelectorAll('label, .or, a.sso, a.btn'), function (x) {
      [].forEach.call(x.childNodes, function (t) { if (t.nodeType === 3 && String(t.nodeValue).trim()) { var en = said(t), lead = /^\s*/.exec(en)[0]; t.nodeValue = lead + TS(en); } });
    });
    var adHint = null;
    [].forEach.call(form.querySelectorAll('.sub'), function (x) { if (x.__zlEn == null) x.__zlEn = x.textContent; if (/^Sign in with your .+ account$/.test(String(x.__zlEn).trim())) adHint = String(x.__zlEn).trim(); });
    [].forEach.call(form.querySelectorAll('input[name=user], input[autocomplete=username], input[type=password]'), function (i) { i.setAttribute('dir', 'ltr'); });
    var sub = form.querySelector('button[type=submit],button:not([type]),input[type=submit]');
    if (sub && step === 'password') { if (sub.tagName === 'INPUT') sub.value = T('Continue'); else sub.textContent = T('Continue'); }
    if (sub && step === 'code') { if (sub.tagName === 'INPUT') sub.value = T('Verify and sign in'); else sub.textContent = T('Verify and sign in'); }

    var B = window.__zybLoginBrand || {};
    var root = el('div', { class: 'zl' });
    // one centred column over an animated background: the brand (mark + word mark + platform name), the sign-in card, the
    // frameworks, the footer. Decoration only - the service's form is moved into the card unchanged.
    // three rows: a top bar (brand left, "authorised users only" right), the middle (message beside the sign-in card, both centred),
    // a bottom bar (clock, what protects this sign-in, powered by / copyright, the legal line)
    root.innerHTML = '<div class="zl-bg" aria-hidden="true"><i class="b1"></i><i class="b2"></i><i class="b3"></i><span class="zl-dots"></span>' + RINGS + '<span class="zl-floor"></span></div>'
      + '<header class="zl-top"><div class="zl-brand"><div class="zl-lockup" lang="en" dir="ltr">' + MARK + '<div class="zl-wm"><b>ZYBERON <i>SENTRA</i></b><span>AI \u00b7 Automation \u00b7 Monitoring</span></div></div>'
      + '<span class="zl-vr" aria-hidden="true"></span><h1 class="zl-title">' + T(NAME) + '</h1></div><span class="zl-pill">' + I.lock + T('Internal system \u00b7 authorised users only') + '</span></header>'
      + '<div class="zl-shell"><section class="zl-hero">'
      + ('<span class="zl-eyebrow">' + ZYB_ORG.short + ' \u00b7 ') + T('Secure access') + '</span><p class="zl-pitch">' + pitch() + '</p>'
      + '<ul class="zl-caps"><li><i>' + I.srv + '</i>' + T('IT operations and network monitoring') + '</li><li><i>' + I.shield + '</i>' + T('Security operations and automated response') + '</li><li><i>' + I.list + '</i>' + T('Enterprise risk, compliance and audit') + '</li><li><i>' + I.ai + '</i>' + T('AI and machine learning: anomalies, forecasts, insights') + '</li></ul>'
      + '<div class="zl-chips"><span>' + T('Evidence for') + '</span><b>SAMA CSF</b><b>NCA ECC</b><b>PDPL</b><b>NDMO</b><b>' + T('Audit') + '</b></div></section>'
      + '<div class="zl-main"><div class="zl-card"><div class="zl-cardtop">' + (ZYB_ORG.logo ? ('<img class="zl-logo" alt="' + ZYB_ORG.name + '" src="') + ZYB_ORG.logo + '">' : '<span></span>')
      + '<div class="zl-lang" role="group" aria-label="' + T('Language') + '"><button type="button" data-zl-lang="en" lang="en" aria-pressed="' + (LANG === 'en') + '">EN</button><button type="button" data-zl-lang="ar" lang="ar" aria-pressed="' + (LANG === 'ar') + '">\u0639\u0631\u0628\u064a</button></div></div>'
      + '<div class="zl-head"><h2></h2><p></p></div>' + steps(step) + '</div></div></div>'
      + '<footer class="zl-end"><div class="zl-barrow"><span class="zl-clock" aria-live="off"></span>'
      + '<ul class="zl-trust">' + (location.protocol === 'https:' ? '<li>' + I.tls + T('Encrypted connection') + '</li>' : '') + '<li>' + I.ok + T('Two-step verification') + '</li><li>' + I.rec + T('Sign-ins are recorded') + '</li></ul>'
      + '<div class="zl-foot"><span>Powered by ' + (B.zyberon ? '<img alt="Zyberon" src="' + B.zyberon + '">' : '<b>Zyberon</b>') + '</span><span class="zl-sep"></span><span>\u00a9 ' + new Date().getFullYear() + (' ' + ZYB_ORG.name + '</span></div></div>')
      + '<p class="zl-legal">' + T(('This system is for authorised use only. Sign-ins and activity are recorded and monitored in line with ' + ZYB_ORG.name + ' policy and the Saudi Personal Data Protection Law.')) + '</p></footer>';
    var card = root.querySelector('.zl-card'), head = root.querySelector('.zl-head');
    head.querySelector('h2').textContent = T(step === 'password' ? 'Sign in' : step === 'code' ? 'Two-step verification' : 'Account security');
    head.querySelector('p').textContent = step === 'password' && adHint ? TS(adHint) : T(step === 'password' ? 'Use your platform account to continue.' : step === 'code' ? 'Enter the 6-digit code shown in your authenticator app.' : 'Follow the steps below to continue.');
    if (msgs.childNodes.length) card.appendChild(msgs);
    card.appendChild(form);
    // field icons (a class on the service's own inputs - nothing about them changes), Caps Lock warning, busy button
    var userIn = form.querySelector('input[name=user], input[autocomplete=username], input[type=text], input[type=email]');
    if (userIn && step === 'password') userIn.classList.add('zl-fi', 'zl-fu');
    if (pass) {
      pass.classList.add('zl-fi', 'zl-fp');
      var cw = form.querySelector('.zl-capsw') || el('div', { class: 'zl-capsw', role: 'status' }); cw.textContent = '\u21ea ' + T('Caps Lock is on');
      var wrapPw = pass.parentNode; if (!cw.parentNode) wrapPw.parentNode.insertBefore(cw, wrapPw.nextSibling);
      if (!pass.__zlCaps) { pass.__zlCaps = true; ['keydown', 'keyup'].forEach(function (ev) { pass.addEventListener(ev, function (e) { var c = form.querySelector('.zl-capsw'); if (c && e.getModifierState) c.classList.toggle('on', !!e.getModifierState('CapsLock')); }); }); pass.addEventListener('blur', function () { var c = form.querySelector('.zl-capsw'); if (c) c.classList.remove('on'); }); }
    }
    // the button shows it is working once the form is really submitted (it is not disabled: its name and value still post)
    if (!form.__zlBusy) { form.__zlBusy = true; form.addEventListener('submit', function () { var r = document.querySelector('.zl'); if (r) r.classList.add('zl-busy'); setTimeout(function () { var r2 = document.querySelector('.zl'); if (r2) r2.classList.remove('zl-busy'); }, 15000); }); }
    var ck = root.querySelector('.zl-clock'); if (ck) clock(ck);
    if (step === 'password') card.appendChild(el('div', { class: 'zl-note' }, I.note + '<span>' + T('Two-step verification is required. After your password you will be asked for the code from your authenticator app.') + '</span>'));
    if (step === 'code') card.appendChild(el('p', { class: 'zl-help', style: 'color:#64748B;font-size:13px' }, T('The code changes every 30 seconds. Only an administrator can reset two-step verification, after confirming who you are.')));
    var help = el('p', { class: 'zl-help' }); help.appendChild(document.createTextNode(T(step === 'code' ? 'Lost access to your authenticator app? ' : 'Trouble signing in? ')));
    if (DESK) { var a = el('a', { href: /@/.test(DESK) ? 'mailto:' + DESK : 'tel:' + DESK.replace(/[^\d+]/g, '') }); a.textContent = T('Contact the IT Service Desk') + ' (' + DESK + ')'; help.appendChild(a); }
    else help.appendChild(document.createTextNode(T('Contact the IT Service Desk.')));
    card.appendChild(help);
    document.body.insertBefore(root, document.body.firstChild);
    try { document.title = T(step === 'code' ? 'Two-step verification' : 'Sign in') + ' \u2014 ' + 'Zyberon Sentra \u00b7 ' + T(NAME); } catch (e) { /* ignore */ }
    de.classList.toggle('zl-rtl', LANG === 'ar'); de.setAttribute('lang', LANG); de.setAttribute('dir', LANG === 'ar' ? 'rtl' : 'ltr');
    [].forEach.call(root.querySelectorAll('[data-zl-lang]'), function (b) { b.addEventListener('click', function () {
      var l = b.getAttribute('data-zl-lang'); if (l === LANG) return; setLang(l); LANG = l;
      // the same form element (and the service's messages) go back to the page and the layout is drawn again in the new language
      var f = root.querySelector('form'), ms = root.querySelector('.zl-msgs'), keep = document.createElement('div'); keep.style.display = 'none';
      document.body.appendChild(keep); if (ms) [].slice.call(ms.childNodes).forEach(function (m) { keep.appendChild(m); }); keep.appendChild(f);
      if (pass && pass.parentNode && pass.parentNode.classList.contains('zl-pw')) { var wrap = pass.parentNode; wrap.parentNode.insertBefore(pass, wrap); wrap.remove(); }
      root.remove(); build(); if (keep.parentNode) keep.remove();
      var nb = document.querySelector('[data-zl-lang="' + l + '"]'); if (nb) try { nb.focus(); } catch (e) { /* focus is a convenience */ }
    }); });
    de.classList.add('zl-on'); reveal();
    var first = form.querySelector('input[autofocus]') || code || form.querySelector('input:not([type=hidden])'); if (first) try { first.focus(); } catch (e) { /* ignore */ }
  }
  function safe() { try { build(); } catch (e) { de.classList.remove('zl-on'); var r = document.querySelector('.zl'); if (r && !r.querySelector('form')) r.remove(); reveal(); } }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', safe); else safe();
})();
/* the real logos, inline: the sign-in page is shown before anyone is signed in, so nothing here may need a login */
window.__zybLoginBrand = {
  zyberon: 'data:image/webp;base64,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'
};
