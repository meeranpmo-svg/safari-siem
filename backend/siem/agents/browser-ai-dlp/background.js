// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Zyberon AI DLP - service worker. Configuration comes ONLY from the browser policy (managed storage, set by IT through
 * Group Policy / Intune: siem_url, token, device) - a person cannot change it. Every 30 minutes it fetches the policy
 * (GET <siem_url>/ingest/ai-dlp/policy) and keeps the last good copy; without one it protects with the built-in app list in
 * warn mode. Events from the content script (metadata only) are queued and sent once a minute (POST .../events, at most 200
 * per request); a failed send keeps them (up to 2000) for the next round. A heartbeat says the extension is active.
 * Apps added in the SIEM's register (custom:...) get the content script registered for their domains. */
'use strict';
importScripts('classify.js');
var C = self.ZybAiDlp, QUEUE_MAX = 2000, BATCH = 200, VERSION = chrome.runtime.getManifest().version;
var DEFAULT = { version: 'built-in', mode: 'warn', keywords: [], heartbeat_min: 60, apps: C.APPS.map(function (a) { return { id: a[0], name: a[1], domains: a[2], status: 'unreviewed', allowed_classes: [] }; }) };

function managed() { return new Promise(function (ok) { try { chrome.storage.managed.get(['siem_url', 'token', 'device'], function (v) { ok(chrome.runtime.lastError ? {} : (v || {})); }); } catch (e) { ok({}); /* no policy store (unmanaged browser) */ } }); }
function local(keys) { return new Promise(function (ok) { chrome.storage.local.get(keys, function (v) { ok(v || {}); }); }); }
function setLocal(o) { return new Promise(function (ok) { chrome.storage.local.set(o, ok); }); }
function base(url) { var u = String(url || '').trim().replace(/\/+$/, ''); return /^https:\/\/[A-Za-z0-9.-]+(:\d+)?$/.test(u) ? u : ''; }
function who() { return new Promise(function (ok) { try { chrome.identity.getProfileUserInfo({ accountStatus: 'ANY' }, function (i) { ok((i && i.email) || ''); }); } catch (e) { ok(''); /* not signed in to the browser: the SIEM has the address */ } }); }

async function policy() { var v = await local(['policy']); return v.policy && v.policy.apps ? v.policy : DEFAULT; }
async function refresh() {
  var m = await managed(), b = base(m.siem_url); if (!b || !m.token) return;
  try {
    var r = await fetch(b + '/ingest/ai-dlp/policy', { headers: { 'X-Sentra-Token': m.token }, cache: 'no-store', credentials: 'omit' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    var p = await r.json(); if (!p || !Array.isArray(p.apps)) throw new Error('not a policy');
    await setLocal({ policy: p, policy_at: Date.now(), policy_error: '' }); await registerCustom(p);
  } catch (e) { await setLocal({ policy_error: String(e.message || e).slice(0, 120) }); /* the last good policy stays in force */ }
}
// custom apps from the register: the same content script on their domains (built-in domains are in the manifest)
async function registerCustom(p) {
  var builtIn = {}; C.APPS.forEach(function (a) { a[2].forEach(function (d) { builtIn[d] = 1; }); });
  var doms = []; p.apps.forEach(function (a) { (a.domains || []).forEach(function (d) { if (!builtIn[d] && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) doms.push(d); }); });
  try {
    var ex = await chrome.scripting.getRegisteredContentScripts({ ids: ['zyb-custom'] }); if (ex.length) await chrome.scripting.unregisterContentScripts({ ids: ['zyb-custom'] });
    if (doms.length) await chrome.scripting.registerContentScripts([{ id: 'zyb-custom', matches: doms.flatMap(function (d) { return ['https://' + d + '/*', 'https://*.' + d + '/*']; }), js: ['classify.js', 'content.js'], runAt: 'document_start' }]);
  } catch (e) { await setLocal({ policy_error: 'custom apps: ' + String(e.message || e).slice(0, 100) }); }
}
async function enqueue(ev) {
  var v = await local(['queue']), q = Array.isArray(v.queue) ? v.queue : [];
  q.push(ev); if (q.length > QUEUE_MAX) q = q.slice(q.length - QUEUE_MAX);
  await setLocal({ queue: q });
}
async function flush() {
  var m = await managed(), b = base(m.siem_url); if (!b || !m.token) return;
  var v = await local(['queue']), q = Array.isArray(v.queue) ? v.queue : []; if (!q.length) return;
  var user = await who(), batch = q.slice(0, BATCH).map(function (e) { var o = Object.assign({}, e, { ext_version: VERSION }); if (user) o.user = user; if (m.device && /^[A-Za-z0-9._-]{1,64}$/.test(m.device)) o.device = m.device; return o; });
  try {
    var r = await fetch(b + '/ingest/ai-dlp/events', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Sentra-Token': m.token }, body: JSON.stringify({ events: batch }), credentials: 'omit' });
    if (r.ok || r.status === 400) {   // 400: the SIEM refused this batch as invalid - dropping it stops a poisoned queue
      var now = await local(['queue']); await setLocal({ queue: (now.queue || []).slice(batch.length), send_error: r.ok ? '' : 'refused (400)' });
      var j = r.ok ? await r.json().catch(function () { return {}; }) : {}; var p = await policy(); if (j.policy_version && j.policy_version !== p.version) await refresh();
    } else await setLocal({ send_error: 'HTTP ' + r.status });
  } catch (e) { await setLocal({ send_error: String(e.message || e).slice(0, 120) }); /* kept for the next round */ }
}
async function heartbeat() { var p = await policy(), v = await local(['beat_at']); if (Date.now() - (v.beat_at || 0) >= (p.heartbeat_min || 60) * 60000) { await enqueue({ ts: Date.now(), action: 'heartbeat' }); await setLocal({ beat_at: Date.now() }); } }

chrome.runtime.onMessage.addListener(function (msg, sender, reply) {
  if (!msg || sender.id !== chrome.runtime.id) return false;
  if (msg.type === 'policy') { policy().then(reply); return true; }
  if (msg.type === 'event' && msg.ev && typeof msg.ev === 'object') {
    var e = msg.ev, ok = { ts: Number(e.ts) || Date.now(), app: String(e.app || '').slice(0, 48), host: String(e.host || '').slice(0, 253), action: String(e.action || ''), channel: String(e.channel || ''), kinds: {}, classes: Array.isArray(e.classes) ? e.classes.slice(0, 5) : [] };
    Object.keys(e.kinds || {}).forEach(function (k) { if (C.KIND_CLASS[k] && Number.isInteger(e.kinds[k])) ok.kinds[k] = e.kinds[k]; });
    if (e.file_type && /^[a-z0-9]{1,10}$/.test(e.file_type)) ok.file_type = e.file_type;
    enqueue(ok).then(function () { if (ok.action !== 'heartbeat') flush(); });   // what the content script may send: these fields only
  }
  return false;
});
chrome.alarms.create('zyb-policy', { periodInMinutes: 30 }); chrome.alarms.create('zyb-flush', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(function (a) { if (a.name === 'zyb-policy') refresh(); if (a.name === 'zyb-flush') heartbeat().then(flush); });
chrome.runtime.onInstalled.addListener(function () { refresh(); });
chrome.runtime.onStartup.addListener(function () { refresh(); });
chrome.storage.onChanged.addListener(function (ch, area) { if (area === 'managed') refresh(); });
