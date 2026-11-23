// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Shadow AI DLP - which AI apps people use, what the organisation allows each one to receive, and the data-loss signals
 * towards them. Routes in soc/shadow-ai-routes.js; the browser extension in agents/browser-ai-dlp/.
 *
 *   Discovery     over the logs the SIEM already stores, read-only: web-filter / proxy URLs (category web), firewall traffic
 *                 with the TLS host name (fields.hostname) or the application (fields.app: FortiGate / Palo Alto App-ID),
 *                 DNS queries (dns_query), Cloudflare Gateway (parsed into the same fields). A host is an AI app when it is
 *                 one of the app's domains or below one; an application name when it matches the app's App-ID pattern.
 *                 Bytes sent come from fields.sentbyte / bytes_out when the log carries them, otherwise "not in the logs".
 *   Register      each app is sanctioned, tolerated, blocked or not reviewed (the default), with an owner, the data classes it
 *                 may receive, a review date and a note. A change is a REQUEST (operator) that a different named person
 *                 approves (approve:security - administrator or a security approver; four-eyes; never a service identity).
 *                 Custom apps (custom:<slug>, with their domains) go through the same request.
 *   Block list    the domains of blocked apps as text / CSV for the firewall's external list - a person loads it there.
 *   Signals       DLP incidents whose destination is an AI app (Somansa / Forcepoint / Symantec / Trend via reports/dlp.js
 *                 fields, Zscaler DLP on an AI URL, and the browser extension's own incidents), large uploads to AI apps
 *                 (bytes sent per person and app above the threshold) and policy gaps (an app the register blocks that the
 *                 firewall still allowed). Indicators to look at, not proof of wrongdoing.
 *   Cases         an operator opens a SOC case from a signal; the guarded job opens one per person / app / day for data the
 *                 DLP product let go to an AI app with a sensitive class, and per app / day for a policy gap (setting).
 *   Extension     the browser extension classifies prompts and files LOCALLY and sends only metadata: the app, the data
 *                 classes and counts, what it did (blocked / warned / sent after the warning / page blocked). Never the text.
 *                 Its events become DLP incidents (action dlp-incident, dlp_vendor zyberon), so the DLP analysis page sees
 *                 them too. It authenticates with an ingest token (secrets.json shadow_ai.ext_token, SHA-256 only).
 * PDPL: user names and device IPs are personal data - operators and administrators see them, a viewer sees counts; every named view
 * is audited. No prompt, file content or file name is stored anywhere.
 */
const crypto = require('node:crypto');
const { HttpError } = require('./routeutil');

const DAY = 86400000, MB = 1024 * 1024;
const STATUSES = ['unreviewed', 'sanctioned', 'tolerated', 'blocked'];
const CATEGORIES = ['chat', 'api', 'code', 'search', 'image', 'meeting', 'writing', 'translation', 'models', 'other'];
// data classes the register allows per app and the extension finds in a prompt
const CLASSES = ['personal', 'financial', 'health', 'credentials', 'confidential'];
const CLASS_LABEL = { personal: 'Personal data (national ID / Iqama, mobile, e-mail)', financial: 'Financial (IBAN, payment card)', health: 'Health / medical',
  credentials: 'Credentials (keys, passwords, private keys)', confidential: 'Confidential (classification label or a protected keyword)' };
// the extension's kinds and their class (agents/browser-ai-dlp/classify.js - kept identical by tests/shadow-ai.test.js)
const KIND_CLASS = { national_id: 'personal', iqama: 'personal', mobile: 'personal', email: 'personal', iban: 'financial', card: 'financial', health: 'health',
  private_key: 'credentials', api_key: 'credentials', password: 'credentials', label: 'confidential', keyword: 'confidential' };
// how a class reads in dlp_classification so reports/dlp.js recognises it as sensitive
const CLASS_DLP = { personal: 'national id / personal data', financial: 'iban / credit card', health: 'health / medical', credentials: 'credentials', confidential: 'confidential' };

// [id, name, vendor, category, domains, App-ID pattern or null] - more specific entries first (the first App-ID match wins)
const CATALOG = [
  ['openai-api', 'OpenAI API', 'OpenAI', 'api', ['api.openai.com', 'platform.openai.com'], /openai[-_ ]?api/],
  ['chatgpt', 'ChatGPT', 'OpenAI', 'chat', ['chatgpt.com', 'chat.openai.com', 'oaistatic.com', 'oaiusercontent.com'], /chatgpt|openai/],
  ['anthropic-api', 'Anthropic API', 'Anthropic', 'api', ['api.anthropic.com', 'console.anthropic.com'], /anthropic[-_ ]?api/],
  ['claude', 'Claude', 'Anthropic', 'chat', ['claude.ai', 'claudeusercontent.com'], /claude|anthropic/],
  ['gemini-api', 'Gemini API', 'Google', 'api', ['generativelanguage.googleapis.com'], /gemini[-_ ]?api/],
  ['gemini', 'Gemini', 'Google', 'chat', ['gemini.google.com', 'bard.google.com', 'aistudio.google.com', 'notebooklm.google.com'], /gemini|bard|notebooklm/],
  ['github-copilot', 'GitHub Copilot', 'GitHub', 'code', ['githubcopilot.com', 'copilot-proxy.githubusercontent.com'], /github[-_ ]?copilot/],
  ['copilot', 'Microsoft Copilot', 'Microsoft', 'chat', ['copilot.microsoft.com', 'copilot.cloud.microsoft', 'sydney.bing.com'], /copilot|bing[-_ ]?chat/],
  ['perplexity', 'Perplexity', 'Perplexity', 'search', ['perplexity.ai'], /perplexity/],
  ['deepseek', 'DeepSeek', 'DeepSeek', 'chat', ['deepseek.com'], /deepseek/],
  ['mistral', 'Le Chat', 'Mistral AI', 'chat', ['mistral.ai'], /mistral/],
  ['meta-ai', 'Meta AI', 'Meta', 'chat', ['meta.ai'], /meta[-_ ]?ai\b/],
  ['grok', 'Grok', 'xAI', 'chat', ['grok.com', 'x.ai'], /\bgrok\b/],
  ['poe', 'Poe', 'Quora', 'chat', ['poe.com'], /^poe\b/],
  ['character-ai', 'Character.AI', 'Character.AI', 'chat', ['character.ai'], /character[-_. ]?ai/],
  ['qwen', 'Qwen', 'Alibaba', 'chat', ['chat.qwen.ai', 'qianwen.aliyun.com', 'tongyi.aliyun.com'], /qwen|tongyi/],
  ['kimi', 'Kimi', 'Moonshot AI', 'chat', ['kimi.com', 'kimi.moonshot.cn'], /\bkimi\b|moonshot/],
  ['huggingface', 'Hugging Face', 'Hugging Face', 'models', ['huggingface.co', 'hf.co'], /hugging[-_ ]?face/],
  ['midjourney', 'Midjourney', 'Midjourney', 'image', ['midjourney.com'], /midjourney/],
  ['otter', 'Otter.ai', 'Otter.ai', 'meeting', ['otter.ai'], /otter[-_. ]?ai/],
  ['fireflies', 'Fireflies.ai', 'Fireflies', 'meeting', ['fireflies.ai'], /fireflies/],
  ['grammarly', 'Grammarly', 'Grammarly', 'writing', ['grammarly.com', 'grammarly.io'], /grammarly/],
  ['deepl', 'DeepL', 'DeepL', 'translation', ['deepl.com'], /deepl/],
  ['quillbot', 'QuillBot', 'QuillBot', 'writing', ['quillbot.com'], /quillbot/],
  ['cursor', 'Cursor', 'Anysphere', 'code', ['cursor.com', 'cursor.sh'], null],
  ['windsurf', 'Windsurf', 'Windsurf', 'code', ['windsurf.com', 'codeium.com'], /codeium|windsurf/],
  ['jasper', 'Jasper', 'Jasper', 'writing', ['jasper.ai'], /jasper/],
  ['gamma', 'Gamma', 'Gamma', 'writing', ['gamma.app'], null],
].map(([id, name, vendor, category, domains, app]) => ({ id, name, vendor, category, domains, app, custom: false }));

const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const APP_ID_RE = /^(custom:[a-z0-9][a-z0-9-]{1,40}|[a-z0-9][a-z0-9-]{1,40})$/;
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const cleanHost = (h) => String(h || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').split('/')[0].replace(/:\d+$/, '').replace(/\.$/, '');

// host → the app whose domain is the host or a parent of it (the longest domain wins); null when it is no AI app
function appForHost(host, catalog) {
  const h = cleanHost(host); if (!h) return null;
  let best = null, len = 0;
  for (const a of catalog) for (const d of a.domains) if ((h === d || h.endsWith('.' + d)) && d.length > len) { best = a; len = d.length; }
  return best;
}
function appForName(name, catalog) {
  const n = String(name || '').trim().toLowerCase(); if (!n) return null;
  return catalog.find((a) => a.app && a.app.test(n)) || null;
}
const hostRegex = (catalog) => '(^|\\.)(' + [...new Set(catalog.flatMap((a) => a.domains))].map(reEsc).join('|') + ')$';
const appRegex = (catalog) => catalog.filter((a) => a.app).map((a) => a.app.source).join('|');

// SQL pieces (every value is a parameter)
const URLHOST = "replaceRegexpOne(lower(splitByChar('/', replaceRegexpOne(url, '^[A-Za-z]+://', ''))[1]), ':[0-9]+$', '')";
const HOSTX = `multiIf(url != '', ${URLHOST}, fields['hostname'] != '', lower(fields['hostname']), dns_query != '', lower(trimRight(dns_query, '.')), '')`;
const APPX = "lower(fields['app'])";
const MATCH = `(match(${HOSTX}, {hrx:String}) OR (fields['app'] != '' AND match(${APPX}, {arx:String})))`;
const WHO = "if(user != '', user, src_ip)";
const BLOCKED = "(action IN ('blocked', 'deny', 'denied', 'drop', 'dropped', 'reset') OR outcome = 'failure')";
const OUTB = "(toUInt64OrZero(fields['sentbyte']) + toUInt64OrZero(fields['bytes_out']))";
const DESTHOST = "replaceRegexpOne(lower(splitByChar('/', replaceRegexpOne(fields['dlp_destination'], '^[A-Za-z]+://', ''))[1]), ':[0-9]+$', '')";
const LEFT = ['permitted', 'released', 'allowed', 'sent_after_warning'];
const WINDOWS = [24, 168, 720];

function defaults() {
  return { upload_mb: 10, auto_cases: { enabled: true, dlp_left: true, gaps: true }, extension: { mode: 'warn', keywords: [], heartbeat_min: 60 } };
}

function createShadowAi({ ch, state, config, log, now, cases, emit, secrets } = {}) {
  if (!state) throw new Error('shadow AI needs state');
  const clock = now || Date.now, L = log || { info() {}, warn() {}, error() {}, every() {} };
  const db = (config && config.clickhouse && config.clickhouse.database) || 'siem', T = `${db}.events`;
  const reg = state.collection('shadow_ai_register'), reqs = state.collection('shadow_ai_requests'), opened = state.collection('shadow_ai_cases'), meta = state.collection('shadow_ai_meta');
  const q = (tag, sql, p) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true, timeout_ms: 30000 });

  /* ---------------- settings */
  function settings() { const s = meta.get('settings'); const d = defaults(); return s ? { upload_mb: s.upload_mb, auto_cases: Object.assign(d.auto_cases, s.auto_cases), extension: Object.assign(d.extension, s.extension) } : d; }
  function putSettings(b, by) {
    const cur = settings(), next = JSON.parse(JSON.stringify(cur));
    if (b.upload_mb !== undefined) next.upload_mb = b.upload_mb;
    for (const k of ['enabled', 'dlp_left', 'gaps']) if (b['auto_' + k] !== undefined) next.auto_cases[k] = b['auto_' + k];
    if (b.mode !== undefined) next.extension.mode = b.mode;
    if (b.keywords !== undefined) next.extension.keywords = b.keywords;
    if (b.heartbeat_min !== undefined) next.extension.heartbeat_min = b.heartbeat_min;
    meta.put(Object.assign({ id: 'settings', updated: clock(), updated_by: by || '' }, next));
    const changed = []; for (const k of ['upload_mb']) if (cur[k] !== next[k]) changed.push(k);
    for (const k of Object.keys(next.auto_cases)) if (cur.auto_cases[k] !== next.auto_cases[k]) changed.push('auto_cases.' + k);
    for (const k of Object.keys(next.extension)) if (JSON.stringify(cur.extension[k]) !== JSON.stringify(next.extension[k])) changed.push('extension.' + k);
    return { settings: settings(), changed };
  }

  /* ---------------- catalog and register */
  function catalog() {
    const custom = reg.all((r) => r.custom && r.domains && r.domains.length).map((r) => ({ id: r.id, name: r.name, vendor: r.vendor || '', category: r.category || 'other', domains: r.domains, app: null, custom: true }));
    return CATALOG.concat(custom);
  }
  const entryOf = (id) => reg.get(id) || { id, status: 'unreviewed', owner: '', allowed_classes: [], review_by: '', note: '' };
  function register() {
    const pend = reqs.all((r) => r.status === 'pending');
    return catalog().map((a) => {
      const e = entryOf(a.id);
      return { id: a.id, name: a.name, vendor: a.vendor, category: a.category, domains: a.domains, custom: a.custom, status: e.status, owner: e.owner || '', allowed_classes: e.allowed_classes || [],
        review_by: e.review_by || '', review_due: !!(e.review_by && Date.parse(e.review_by + 'T00:00:00Z') < clock()), note: e.note || '', approved_by: e.approved_by || '', updated: e.updated || 0,
        pending: pend.filter((r) => r.app === a.id).map((r) => r.id) };
    });
  }
  function request(b, by) {
    const known = catalog().find((a) => a.id === b.app);
    if (!known && !b.app.startsWith('custom:')) throw new HttpError(400, 'app must be an app from the catalog or custom:<name>');
    if (!known && (!b.name || !b.domains || !b.domains.length)) throw new HttpError(400, 'a new custom app needs name and domains');
    if (known && !known.custom && (b.domains || b.name)) throw new HttpError(400, 'name and domains can be changed only for a custom app');
    if (reqs.all((r) => r.status === 'pending' && r.app === b.app).length) throw new HttpError(409, 'a change for this app is already waiting for approval - decide that one first');
    const before = entryOf(b.app), change = {};
    for (const k of ['status', 'owner', 'allowed_classes', 'review_by', 'note', 'name', 'vendor', 'category', 'domains']) if (b[k] !== undefined) change[k] = b[k];
    if (change.status === 'blocked' && change.allowed_classes && change.allowed_classes.length) throw new HttpError(400, 'allowed_classes must be empty for a blocked app');
    if (!Object.keys(change).length) throw new HttpError(400, 'nothing to change: give status, owner, allowed_classes, review_by or note');
    const r = { id: 'sar-' + crypto.randomBytes(5).toString('hex'), app: b.app, change, before: { status: before.status, owner: before.owner || '', allowed_classes: before.allowed_classes || [] },
      reason: b.reason, requested_by: by, requested_at: clock(), status: 'pending' };
    reqs.put(r); return r;
  }
  function requests(f = {}) {
    return reqs.all((r) => !f.status || r.status === f.status).sort((a, b) => b.requested_at - a.requested_at).slice(0, 200)
      .map((r) => Object.assign({}, r, { app_name: (catalog().find((a) => a.id === r.app) || { name: r.change.name || r.app }).name }));
  }
  function decide(id, decision, by, comment) {
    const r = reqs.get(id); if (!r) throw new HttpError(404, 'request not found');
    if (r.status !== 'pending') throw new HttpError(409, 'this request was already ' + r.status);
    if (String(r.requested_by).toLowerCase() === String(by).toLowerCase()) throw new HttpError(403, 'you asked for this change; a different person approves it (four-eyes)');
    const t = clock();
    const done = reqs.patch(id, (x) => { x.status = decision === 'approve' ? 'approved' : 'rejected'; x.decided_by = by; x.decided_at = t; x.comment = comment || ''; });
    if (decision === 'approve') {
      const e = Object.assign(entryOf(r.app), r.change, { id: r.app, custom: r.app.startsWith('custom:'), updated: t, approved_by: by, requested_by: r.requested_by });
      if (e.status === 'blocked') e.allowed_classes = [];
      reg.put(e);
    }
    return done;
  }
  function blocklist() {
    const blocked = register().filter((a) => a.status === 'blocked');
    return { apps: blocked.map((a) => ({ id: a.id, name: a.name, domains: a.domains })), domains: [...new Set(blocked.flatMap((a) => a.domains))].sort() };
  }

  /* ---------------- discovery */
  function params(o) {
    const cat = catalog();
    return { f: { type: 'Int64', value: o.from }, t: { type: 'Int64', value: o.to }, w30: { type: 'Int64', value: o.from - 30 * DAY }, s7: { type: 'Int64', value: o.to - 7 * DAY },
      hrx: { type: 'String', value: hostRegex(cat) }, arx: { type: 'String', value: appRegex(cat) || '^$' } };
  }
  const windowOf = (hours) => { const h = WINDOWS.includes(Number(hours)) ? Number(hours) : 168, to = clock(); return { hours: h, from: to - h * 3600000, to }; };

  async function discovery(hours, canName) {
    const o = windowOf(hours), p = params(o), cat = catalog(), regMap = new Map(register().map((a) => [a.id, a]));
    const W = `ts >= fromUnixTimestamp64Milli({f:Int64}) AND ts < fromUnixTimestamp64Milli({t:Int64}) AND ${MATCH}`;
    const any = await q('sa_any', `SELECT category AS c, count() AS n FROM ${T} WHERE ts >= fromUnixTimestamp64Milli({s7:Int64}) AND (category IN ('web', 'dns', 'network') OR url != '' OR dns_query != '' OR fields['hostname'] != '' OR fields['app'] != '') GROUP BY c ORDER BY n DESC LIMIT 10`, p);
    if (!any.length) return { configured: false, hours: o.hours, note: 'No web-filter, proxy, firewall traffic or DNS log has reached the SIEM in 7 days. Send the firewall\'s web-filter and traffic logs (with the TLS host name or App-ID), the proxy logs or the DNS logs - AI use shows up here as soon as they arrive.' };
    const [src, hosts, days, users, first] = await Promise.all([
      q('sa_src', `SELECT src_type AS s, category AS c, count() AS n, max(ts) AS last FROM ${T} WHERE ${W} GROUP BY s, c ORDER BY n DESC LIMIT 20`, p),
      q('sa_hosts', `SELECT ${HOSTX} AS host, ${APPX} AS app, count() AS n, countIf(${BLOCKED}) AS blk, uniqExact(${WHO}) AS u, sum(${OUTB}) AS out, min(ts) AS first, max(ts) AS last FROM ${T} WHERE ${W} GROUP BY host, app ORDER BY n DESC LIMIT 2000`, p),
      q('sa_days', `SELECT toString(toDate(ts)) AS d, ${HOSTX} AS host, ${APPX} AS app, count() AS n FROM ${T} WHERE ${W} GROUP BY d, host, app LIMIT 20000`, p),
      q('sa_users', `SELECT ${WHO} AS who, ${HOSTX} AS host, ${APPX} AS app, count() AS n, countIf(${BLOCKED}) AS blk, sum(${OUTB}) AS out, max(ts) AS last FROM ${T} WHERE ${W} GROUP BY who, host, app ORDER BY out DESC, n DESC LIMIT 20000`, p),
      q('sa_first', `SELECT ${HOSTX} AS host, ${APPX} AS app, min(ts) AS first FROM ${T} WHERE ts >= fromUnixTimestamp64Milli({w30:Int64}) AND ts < fromUnixTimestamp64Milli({t:Int64}) AND ${MATCH} GROUP BY host, app HAVING first >= fromUnixTimestamp64Milli({f:Int64}) LIMIT 2000`, p),
    ]);
    const idOf = (r) => { const a = appForHost(r.host, cat) || appForName(r.app, cat); return a ? a.id : null; };
    const apps = new Map(), byUser = new Map(), trend = new Map();
    const appRow = (id) => apps.get(id) || apps.set(id, { requests: 0, blocked: 0, out: 0, first: null, last: null, hosts: new Set(), people: new Set(), sources: new Set(), new_in_window: false }).get(id);
    for (const r of hosts) {
      const id = idOf(r); if (!id) continue; const a = appRow(id);
      a.requests += num(r.n); a.blocked += num(r.blk); a.out += num(r.out); if (r.host) a.hosts.add(r.host); else if (r.app) a.hosts.add('app: ' + r.app);
      if (!a.first || r.first < a.first) a.first = r.first; if (!a.last || r.last > a.last) a.last = r.last;
    }
    for (const r of users) {
      const id = idOf(r); if (!id || !r.who) continue; appRow(id).people.add(r.who);
      const k = r.who + '\u0000' + id, u = byUser.get(k) || byUser.set(k, { who: r.who, app: id, requests: 0, blocked: 0, out: 0, last: null }).get(k);
      u.requests += num(r.n); u.blocked += num(r.blk); u.out += num(r.out); if (!u.last || r.last > u.last) u.last = r.last;
    }
    for (const r of days) { const id = idOf(r); if (!id) continue; const k = r.d + '\u0000' + id; trend.set(k, (trend.get(k) || 0) + num(r.n)); }
    for (const r of first) { const id = idOf(r); if (id && apps.has(id)) apps.get(id).new_in_window = true; }
    for (const s of src) for (const a of apps.values()) a.sources.add(s.s);
    const hasBytes = [...apps.values()].some((a) => a.out > 0), S = settings();
    const list = [...apps.entries()].map(([id, a]) => {
      const c = cat.find((x) => x.id === id), e = regMap.get(id) || {};
      const allowed = a.requests - a.blocked;
      return { id, name: c.name, vendor: c.vendor, category: c.category, status: e.status || 'unreviewed', owner: e.owner || '', requests: a.requests, blocked: a.blocked, allowed,
        users: a.people.size, mb_sent: hasBytes ? Math.round(a.out / MB * 10) / 10 : null, first: a.first, last: a.last, new_in_window: a.new_in_window, hosts: [...a.hosts].slice(0, 10),
        unsanctioned: (e.status || 'unreviewed') !== 'sanctioned' && allowed > 0, gap: e.status === 'blocked' && allowed > 0 };
    }).sort((x, y) => y.users - x.users || y.requests - x.requests);
    const people = [...byUser.values()];
    const totalUsers = new Set(people.map((u) => u.who)).size, unsanctionedUsers = new Set(people.filter((u) => { const s = (regMap.get(u.app) || {}).status || 'unreviewed'; return s !== 'sanctioned' && u.requests > u.blocked; }).map((u) => u.who)).size;
    const uploads = hasBytes ? people.filter((u) => u.out >= S.upload_mb * MB).sort((x, y) => y.out - x.out).slice(0, 100).map((u) => {
      const st = (regMap.get(u.app) || {}).status || 'unreviewed', name = (cat.find((x) => x.id === u.app) || {}).name || u.app;
      return { who: canName ? u.who : null, app: u.app, app_name: name, status: st, mb_sent: Math.round(u.out / MB * 10) / 10, requests: u.requests, last: u.last,
        why: (Math.round(u.out / MB * 10) / 10) + ' MB sent to ' + name + ' (' + st + ') in ' + o.hours + ' h, above the ' + S.upload_mb + ' MB threshold' };
    }) : [];
    const dates = [...new Set([...trend.keys()].map((k) => k.split('\u0000')[0]))].sort();
    return {
      configured: true, hours: o.hours, from: o.from, to: o.to, named: canName,
      sources: src.map((s) => ({ source: s.s, category: s.c, events: num(s.n), last: s.last })),
      totals: { apps: list.length, users: totalUsers, unsanctioned_apps: list.filter((a) => a.unsanctioned).length, unsanctioned_users: unsanctionedUsers, gaps: list.filter((a) => a.gap).length,
        new_apps: list.filter((a) => a.new_in_window).length, requests: list.reduce((s, a) => s + a.requests, 0), mb_sent: hasBytes ? Math.round(list.reduce((s, a) => s + (a.mb_sent || 0), 0) * 10) / 10 : null },
      apps: list,
      trend: dates.map((d) => ({ date: d, apps: Object.fromEntries(list.map((a) => [a.id, trend.get(d + '\u0000' + a.id) || 0])) })),
      people: canName ? people.sort((x, y) => y.out - x.out || y.requests - x.requests).slice(0, 200).map((u) => ({ who: u.who, app: u.app, status: (regMap.get(u.app) || {}).status || 'unreviewed',
        requests: u.requests, blocked: u.blocked, mb_sent: hasBytes ? Math.round(u.out / MB * 10) / 10 : null, last: u.last })) : { hidden: true },
      uploads, upload_mb: S.upload_mb, bytes_in_logs: hasBytes,
      note: 'Behavioural indicators, not proof of wrongdoing: an AI app or a volume is a reason to look, with the person\'s manager and the HR process, never a finding by itself.'
        + (hasBytes ? '' : ' The logs carry no byte counts, so uploads cannot be measured - send firewall traffic logs with sent bytes.'),
    };
  }

  /* ---------------- signals */
  async function signals(hours, canName) {
    const o = windowOf(hours), p = params(o), cat = catalog();
    const W = `ts >= fromUnixTimestamp64Milli({f:Int64}) AND ts < fromUnixTimestamp64Milli({t:Int64})`;
    const rows = await q('sa_dlp', `SELECT ts, fields['dlp_incident_id'] AS id, ${WHO} AS who, host, fields['ai_app'] AS ai, ${DESTHOST} AS dest, ${HOSTX} AS urlhost, fields['dlp_channel'] AS chan, `
      + `lower(fields['dlp_action']) AS act, fields['dlp_classification'] AS cls, fields['dlp_policy'] AS pol, toUInt32OrZero(fields['dlp_match_count']) AS m, fields['dlp_product'] AS prod, fields['dlp_vendor'] AS vendor, `
      + `fields['zscaler_dlp'] AS zdlp FROM ${T} WHERE ${W} AND ((action = 'dlp-incident' AND (fields['ai_app'] != '' OR match(${DESTHOST}, {hrx:String}))) OR (fields['zscaler_dlp'] != '' AND match(${HOSTX}, {hrx:String}))) ORDER BY ts DESC LIMIT 2000`, p);
    const regMap = new Map(register().map((a) => [a.id, a]));
    const incidents = rows.map((r) => {
      const a = cat.find((x) => x.id === r.ai) || appForHost(r.dest, cat) || appForHost(r.urlhost, cat);
      const act = r.act || (r.zdlp ? 'zscaler: ' + String(r.zdlp).toLowerCase() : '');
      const source = r.vendor === 'zyberon' ? 'extension' : r.zdlp ? 'zscaler' : 'dlp';
      const classes = CLASSES.filter((c) => new RegExp(c === 'personal' ? 'national id|iqama|personal|pii|mobile|e-?mail' : c === 'financial' ? 'iban|card|bank|financial' : c === 'health' ? 'health|medical' : c, 'i').test(r.cls || ''));
      return { ts: r.ts, id: r.id || null, who: canName ? r.who : null, device: canName ? (r.host || null) : null, app: a ? a.id : null, app_name: a ? a.name : (r.dest || r.urlhost || ''), status: a ? ((regMap.get(a.id) || {}).status || 'unreviewed') : 'unreviewed',
        source, channel: r.chan || '', action: act || 'not reported', left: LEFT.includes(r.act), classification: r.cls || '', classes, policy: r.pol || '', matches: num(r.m), product: r.prod || '' };
    });
    const d = await discovery(o.hours, canName);
    const count = (fn) => incidents.reduce((m, x) => { for (const k of [].concat(fn(x))) if (k) m[k] = (m[k] || 0) + 1; return m; }, {});
    return {
      hours: o.hours, named: canName,
      totals: { incidents: incidents.length, left: incidents.filter((x) => x.left).length, blocked: incidents.filter((x) => /block|quarant/.test(x.action)).length,
        sensitive_left: incidents.filter((x) => x.left && x.classes.length).length, uploads: d.configured ? d.uploads.length : 0, gaps: d.configured ? d.totals.gaps : 0 },
      by_app: count((x) => x.app_name), by_class: count((x) => x.classes), by_source: count((x) => x.source),
      incidents: incidents.slice(0, 500), uploads: d.configured ? d.uploads : [], gaps: d.configured ? d.apps.filter((a) => a.gap).map((a) => ({ app: a.id, app_name: a.name, allowed: a.allowed, users: a.users, why: a.name + ' is blocked in the register but the firewall allowed ' + a.allowed + ' requests' })) : [],
      bytes_in_logs: d.configured ? d.bytes_in_logs : false,
      note: 'Indicators, not proof: a DLP match or an upload is a reason to look with the person\'s manager and HR, never a finding by itself. The extension sends what it found (data classes and counts), never the text.',
    };
  }

  /* ---------------- cases */
  const CASE_KINDS = { dlp: 'sensitive data sent to an AI app', upload: 'large upload to an AI app', gap: 'blocked AI app still reachable' };
  function openCase(b, by, auto) {
    if (!cases || typeof cases.create !== 'function') throw new HttpError(503, 'SOC cases are not available on this engine');
    const app = catalog().find((a) => a.id === b.app); if (!app) throw new HttpError(400, 'app must be an app from the catalog');
    const day = new Date(clock()).toISOString().slice(0, 10), key = [b.kind, b.app, b.who || '', b.incident_id || '', day].join('|').toLowerCase();
    const prev = opened.get(crypto.createHash('sha256').update(key).digest('hex').slice(0, 24));
    if (prev) {
      let c = null; try { c = cases.get ? cases.get(prev.case_id) : null; } catch (e) { c = null; /* the case was removed: open a new one */ }
      if (c && c.status !== 'closed') return { case_id: prev.case_id, existed: true };
    }
    const sev = b.kind === 'dlp' ? 3 : 2;
    const desc = ['Shadow AI DLP: ' + CASE_KINDS[b.kind] + '.', 'App: ' + app.name + ' (' + app.vendor + ', ' + ((reg.get(app.id) || {}).status || 'unreviewed') + ').',
      b.who ? 'Person / device: ' + b.who + '.' : '', b.incident_id ? 'DLP incident: ' + b.incident_id + '.' : '', b.detail ? 'Detail: ' + b.detail : '', b.note ? 'Note: ' + b.note : '',
      'Indicators, not proof: confirm with the person\'s manager and HR before any conclusion. No prompt or file content is held by the SIEM.'].filter(Boolean).join('\n');
    const c = cases.create({ title: 'Shadow AI: ' + app.name + ' - ' + CASE_KINDS[b.kind] + (b.who ? ' (' + b.who + ')' : ''), description: desc, severity: sev, auto_playbook: false }, by);
    opened.put({ id: crypto.createHash('sha256').update(key).digest('hex').slice(0, 24), case_id: c.id, kind: b.kind, app: b.app, at: clock(), by, auto: !!auto });
    return { case_id: c.id, existed: false };
  }
  async function autoCases(auditFn) {
    const S = settings(); if (!S.auto_cases.enabled || !cases) return { opened: 0 };
    const s = await signals(24, true); let n = 0;
    const tryOpen = (b, why) => { try { const r = openCase(b, 'system:shadow-ai', true); if (!r.existed) { n++; if (auditFn) auditFn('shadow_ai.case.auto', r.case_id, { kind: b.kind, app: b.app, why }); } } catch (e) { L.every('shadow-ai-autocase', 600000, 'warn', 'shadow AI: automatic case not opened', { kind: b.kind, app: b.app, err: e.message }); } };
    if (S.auto_cases.dlp_left) for (const x of s.incidents.filter((i) => i.left && i.classes.length && i.app)) tryOpen({ kind: 'dlp', app: x.app, who: x.who || '', detail: x.classes.join(', ') + ' (' + x.source + ', ' + x.action + ')' }, 'sensitive data left to an AI app');
    if (S.auto_cases.gaps) for (const g of s.gaps) tryOpen({ kind: 'gap', app: g.app, detail: g.why }, 'policy gap');
    return { opened: n };
  }

  /* ---------------- browser extension */
  function policy() {
    const S = settings();
    const apps = register().map((a) => ({ id: a.id, name: a.name, domains: a.domains, status: a.status, allowed_classes: a.allowed_classes }));
    const body = { mode: S.extension.mode, keywords: S.extension.keywords, heartbeat_min: S.extension.heartbeat_min, apps, classes: CLASSES };
    return Object.assign({ version: crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex').slice(0, 16), generated: clock() }, body);
  }
  const ACTION_DLP = { blocked: 'blocked', page_blocked: 'blocked', warned: 'withheld', sent_after_warning: 'permitted' };
  function ingest(items, meta = {}) {
    const cat = catalog(); let accepted = 0, heartbeats = 0;
    for (const it of items) {
      const a = cat.find((x) => x.id === it.app) || appForHost(it.host, cat);
      const ev = { ts: it.ts, rts: clock(), category: 'dlp', src_type: 'ai-dlp', collector: 'ai-dlp-extension', src_id: 'ai-dlp', user: it.user || '', host: it.device || '', src_ip: meta.ip || '', fields: { ext_version: it.ext_version || '' } };
      if (it.action === 'heartbeat') {
        Object.assign(ev, { action: 'ai-dlp-heartbeat', outcome: 'success', severity: 0, message: 'AI DLP browser extension active' });
        heartbeats++;
      } else {
        const classes = [...new Set(Object.keys(it.kinds || {}).map((k) => KIND_CLASS[k]).filter(Boolean).concat(it.classes || []))];
        const matches = Object.values(it.kinds || {}).reduce((s, n) => s + n, 0);
        Object.assign(ev, { action: 'dlp-incident', outcome: it.action === 'sent_after_warning' ? 'success' : 'failure', severity: it.action === 'sent_after_warning' ? 3 : it.action === 'warned' ? 1 : 2,
          url: it.host ? 'https://' + it.host + '/' : '', message: 'AI DLP (browser): ' + it.action.replace(/_/g, ' ') + ' - ' + (classes.join(', ') || 'blocked app') + ' to ' + (a ? a.name : it.host) });
        Object.assign(ev.fields, { ai_app: a ? a.id : '', dlp_vendor: 'zyberon', dlp_product: 'Zyberon AI DLP (browser)', dlp_channel: 'ai-' + (it.channel || 'submit'), dlp_destination: it.host || '',
          dlp_action: ACTION_DLP[it.action], dlp_classification: classes.map((c) => CLASS_DLP[c]).join(', '), dlp_match_count: String(matches), dlp_severity: it.action === 'sent_after_warning' ? 'high' : 'medium',
          dlp_incident_id: 'aidlp-' + crypto.randomUUID(), ai_dlp_action: it.action, ai_dlp_kinds: Object.keys(it.kinds || {}).join(','), file_type: it.file_type || '' });
      }
      emit(ev); accepted++;
    }
    return { accepted, heartbeats };
  }
  async function extensionStatus() {
    const p = { s: { type: 'Int64', value: clock() - DAY }, s7: { type: 'Int64', value: clock() - 7 * DAY } };
    const [rows, acts] = await Promise.all([
      q('sa_ext', `SELECT fields['ext_version'] AS v, uniqExact(user) AS u, uniqExact(src_ip) AS d, max(ts) AS last FROM ${T} WHERE ts >= fromUnixTimestamp64Milli({s:Int64}) AND src_type = 'ai-dlp' GROUP BY v ORDER BY u DESC LIMIT 20`, p),
      q('sa_ext_act', `SELECT fields['ai_dlp_action'] AS a, count() AS n FROM ${T} WHERE ts >= fromUnixTimestamp64Milli({s7:Int64}) AND src_type = 'ai-dlp' AND action = 'dlp-incident' GROUP BY a`, p),
    ]);
    const sec = (secrets() || {});
    return { token_set: !!sec.ext_token, token_created: sec.ext_token_created || null, versions: rows.map((r) => ({ version: r.v || '(unknown)', users: num(r.u), devices: num(r.d), last: r.last })),
      users_24h: rows.reduce((s, r) => s + num(r.u), 0), actions_7d: Object.fromEntries(acts.map((r) => [r.a || 'other', num(r.n)])), policy: policy() };
  }

  return { settings, putSettings, catalog, register, request, requests, decide, blocklist, discovery, signals, openCase, autoCases, policy, ingest, extensionStatus };
}

module.exports = { createShadowAi, appForHost, appForName, hostRegex, appRegex, cleanHost, CATALOG, STATUSES, CATEGORIES, CLASSES, CLASS_LABEL, KIND_CLASS, DOMAIN_RE, APP_ID_RE, WINDOWS };
