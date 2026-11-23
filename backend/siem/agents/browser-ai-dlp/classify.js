// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Zyberon AI DLP - the classifier and the built-in AI app list, shared by the content script and the service worker.
 * Runs LOCALLY in the browser: the text is read, matches are counted, and only {kind: count} leaves this file - no value,
 * no prompt, no file name. The personal-data rules are the SIEM's file rules (engine/pii/classify.js) with prompt
 * thresholds (one national ID in a prompt matters); tests/shadow-ai.test.js keeps the patterns and the app list identical
 * to the engine's (engine/soc/shadow-ai.js CATALOG). Keywords are plain text the administrator lists (no regular expressions,
 * so a keyword cannot hang the browser). */
(function (root) {
  'use strict';
  var RULES = [
    { kind: 'national_id', re: /(?<![\d])1\d{9}(?![\d])/g, min: 1 },
    { kind: 'iqama', re: /(?<![\d])2\d{9}(?![\d])/g, min: 1 },
    { kind: 'mobile', re: /(?<![\d+])(?:\+?966|00966|0)5\d{8}(?![\d])/g, min: 2 },
    { kind: 'email', re: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, min: 3 },
    { kind: 'iban', re: /\bSA\d{2}[ ]?(?:\d{4}[ ]?){5}\b/g, min: 1 },
    { kind: 'card', re: /(?<![\d])(?:\d[ -]?){13,19}(?![\d])/g, min: 1, luhn: true },
    { kind: 'health', re: /\b(?:diagnosis|ICD-?10|medical report|prescription|chronic disease|lab result)\b|تشخيص|تقرير طبي|وصفة طبية|مرض مزمن/gi, min: 1 },
    { kind: 'private_key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g, min: 1 },
    { kind: 'api_key', re: /\b(?:AKIA[0-9A-Z]{16}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b/g, min: 1 },
    { kind: 'password', re: /\b(?:password|passwd|pwd)\s*[:=]\s*\S{4,}|كلمة (?:المرور|السر)\s*[:=]\s*\S{4,}/gi, min: 1 },
    { kind: 'label', re: /\b(?:strictly confidential|confidential|internal use only)\b|سري للغاية|(?:^|\s)سري(?=\s|$|[.,،])/gi, min: 1 },
  ];
  var KIND_CLASS = { national_id: 'personal', iqama: 'personal', mobile: 'personal', email: 'personal', iban: 'financial', card: 'financial', health: 'health',
    private_key: 'credentials', api_key: 'credentials', password: 'credentials', label: 'confidential', keyword: 'confidential' };
  var KIND_LABEL = { national_id: 'national ID numbers', iqama: 'Iqama numbers', mobile: 'mobile numbers', email: 'e-mail addresses', iban: 'IBANs', card: 'payment card numbers',
    health: 'health / medical terms', private_key: 'a private key', api_key: 'API keys', password: 'passwords', label: 'a confidential label', keyword: 'protected keywords' };
  var MAX_TEXT = 2 * 1024 * 1024;
  // [id, name, domains] - the same apps and domains as the engine's catalog
  var APPS = [
    ['openai-api', 'OpenAI API', ['api.openai.com', 'platform.openai.com']], ['chatgpt', 'ChatGPT', ['chatgpt.com', 'chat.openai.com', 'oaistatic.com', 'oaiusercontent.com']],
    ['anthropic-api', 'Anthropic API', ['api.anthropic.com', 'console.anthropic.com']], ['claude', 'Claude', ['claude.ai', 'claudeusercontent.com']],
    ['gemini-api', 'Gemini API', ['generativelanguage.googleapis.com']], ['gemini', 'Gemini', ['gemini.google.com', 'bard.google.com', 'aistudio.google.com', 'notebooklm.google.com']],
    ['github-copilot', 'GitHub Copilot', ['githubcopilot.com', 'copilot-proxy.githubusercontent.com']], ['copilot', 'Microsoft Copilot', ['copilot.microsoft.com', 'copilot.cloud.microsoft', 'sydney.bing.com']],
    ['perplexity', 'Perplexity', ['perplexity.ai']], ['deepseek', 'DeepSeek', ['deepseek.com']], ['mistral', 'Le Chat', ['mistral.ai']], ['meta-ai', 'Meta AI', ['meta.ai']],
    ['grok', 'Grok', ['grok.com', 'x.ai']], ['poe', 'Poe', ['poe.com']], ['character-ai', 'Character.AI', ['character.ai']],
    ['qwen', 'Qwen', ['chat.qwen.ai', 'qianwen.aliyun.com', 'tongyi.aliyun.com']], ['kimi', 'Kimi', ['kimi.com', 'kimi.moonshot.cn']], ['huggingface', 'Hugging Face', ['huggingface.co', 'hf.co']],
    ['midjourney', 'Midjourney', ['midjourney.com']], ['otter', 'Otter.ai', ['otter.ai']], ['fireflies', 'Fireflies.ai', ['fireflies.ai']], ['grammarly', 'Grammarly', ['grammarly.com', 'grammarly.io']],
    ['deepl', 'DeepL', ['deepl.com']], ['quillbot', 'QuillBot', ['quillbot.com']], ['cursor', 'Cursor', ['cursor.com', 'cursor.sh']], ['windsurf', 'Windsurf', ['windsurf.com', 'codeium.com']],
    ['jasper', 'Jasper', ['jasper.ai']], ['gamma', 'Gamma', ['gamma.app']],
  ];

  function luhn(d) { var t = 0; for (var i = 0; i < d.length; i++) { var n = d.charCodeAt(d.length - 1 - i) - 48; if (i % 2) { n *= 2; if (n > 9) n -= 9; } t += n; } return t % 10 === 0; }

  // text → { kinds: {kind: n}, classes: [class], matches: n }
  function classify(text, keywords) {
    var t = String(text || '').slice(0, MAX_TEXT), kinds = {}, matches = 0;
    var ibanRe = RULES[4].re, noIban = t.replace(ibanRe, ' ');
    RULES.forEach(function (r) {
      var n = 0, src = r.luhn ? noIban : t, m; r.re.lastIndex = 0;
      while ((m = r.re.exec(src)) !== null) {
        if (m[0] === '') { r.re.lastIndex++; continue; }
        if (r.luhn) { var d = m[0].replace(/\D/g, ''); if (d.length < 13 || !luhn(d)) continue; }
        n++; if (n >= 100000) break;
      }
      r.re.lastIndex = 0;
      if (n >= r.min) { kinds[r.kind] = n; matches += n; }
    });
    var low = t.toLowerCase(), kw = 0;
    (keywords || []).forEach(function (k) { var w = String(k || '').toLowerCase(); if (w.length < 3) return; var i = low.indexOf(w); while (i >= 0 && kw < 100000) { kw++; i = low.indexOf(w, i + w.length); } });
    if (kw) { kinds.keyword = kw; matches += kw; }
    var classes = []; Object.keys(kinds).forEach(function (k) { var c = KIND_CLASS[k]; if (c && classes.indexOf(c) < 0) classes.push(c); });
    return { kinds: kinds, classes: classes, matches: matches };
  }
  // what the person is told: "3 national ID numbers, an API key"
  function describe(kinds) { return Object.keys(kinds).map(function (k) { return /^an? /.test(KIND_LABEL[k]) ? KIND_LABEL[k] : kinds[k] + ' ' + KIND_LABEL[k]; }).join(', '); }

  // host → app from a policy's apps (or the built-in list); the longest matching domain wins
  function appFor(host, apps) {
    var h = String(host || '').toLowerCase().replace(/\.$/, ''), best = null, len = 0;
    (apps || APPS.map(function (a) { return { id: a[0], name: a[1], domains: a[2], status: 'unreviewed', allowed_classes: [] }; })).forEach(function (a) {
      (a.domains || []).forEach(function (d) { if ((h === d || h.slice(-d.length - 1) === '.' + d) && d.length > len) { best = a; len = d.length; } });
    });
    return best;
  }
  // the decision for what was found, under the policy: allow | warn | block
  function decide(app, found, mode) {
    if (!app) return { action: 'allow', disallowed: [] };
    if (app.status === 'blocked') return { action: 'block', disallowed: found.classes.slice(), page: true };
    var allowed = app.status === 'sanctioned' ? (app.allowed_classes || []) : [];
    var dis = found.classes.filter(function (c) { return allowed.indexOf(c) < 0; });
    if (!dis.length) return { action: 'allow', disallowed: [] };
    return { action: mode === 'block' ? 'block' : 'warn', disallowed: dis };
  }

  var api = { classify: classify, describe: describe, appFor: appFor, decide: decide, RULES: RULES, KIND_CLASS: KIND_CLASS, APPS: APPS, luhn: luhn };
  if (typeof module === 'object' && module.exports) module.exports = api; else root.ZybAiDlp = api;
})(typeof self !== 'undefined' ? self : this);
