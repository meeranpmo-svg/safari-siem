// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Exchange hybrid migration workspace (on-premises Exchange → Exchange Online, hybrid mode) on top of the AI Exchange
 * Server Administrator's read-only checks ({P} = /api/soc):
 *   GET  {P}/sysadmin/hybrid                        viewer    readiness checklist, mailbox inventory, waves (addresses: operator+)
 *   PUT  {P}/sysadmin/hybrid/settings               admin     {tenant, endpoint, notify}
 *   POST {P}/sysadmin/hybrid/refresh                operator  re-read the Exchange organisation now (read-only checks)
 *   POST {P}/sysadmin/hybrid/manual/:id             operator  {done, note} a step the platform cannot see (Entra Connect, firewall …)
 *   POST {P}/sysadmin/hybrid/waves                  operator  {id?, name, planned, mailboxes, notes} a migration wave
 *   POST {P}/sysadmin/hybrid/waves/:id/status       operator  {status, note}
 *   GET  {P}/sysadmin/hybrid/waves/:id/commands     operator  the CSV + Exchange Online PowerShell for the wave
 * The readiness checks read what the servers report (Get-HybridConfiguration, EWS / MRS Proxy, accepted / remote domains,
 * send connectors, certificates, versions) - a check with no data says "not read yet", never "ready". The platform never
 * runs a migration: it writes the commands, a person runs them in Exchange Online PowerShell and records the outcome here.
 */
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

const WAVE_FLOW = ['planned', 'syncing', 'synced', 'completing', 'completed', 'failed'];
const ADDR = /^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;
const MANUAL = [
  ['entra', 'Microsoft Entra Connect is synchronising users, with Exchange hybrid deployment write-back enabled'],
  ['licences', 'Exchange Online licences are ready for the users in the first wave'],
  ['firewall', 'Exchange Online can reach the hybrid servers: TCP 443 (EWS, Autodiscover) and TCP 25 (mail) from the Microsoft 365 IP ranges'],
  ['hcw', 'Hybrid Configuration Wizard run by an Exchange admin and a test mailbox moved both ways'],
  ['backup', 'A full backup of every mailbox database taken before the first wave'],
  ['comms', 'Users told about the move (Outlook restart, mobile profile, support contact)'],
  ['change', 'Change request approved for the migration window'],
];
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n || 200);
const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);
const psq = (v) => "'" + String(v).replace(/'/g, "''") + "'";

// Exchange build → supported for hybrid? (Exchange 2013 and older are out of support; a server several CUs behind is not)
function versionOf(v) { const m = /(\d+)\.(\d+)\s*\(Build\s*(\d+)/i.exec(String(v || '')) || /(\d+)\.(\d+)\.(\d+)/.exec(String(v || '')); return m ? { major: +m[1], minor: +m[2], build: +m[3] } : null; }
function versionVerdict(v) {
  const x = versionOf(v); if (!x) return ['unknown', 'version not reported'];
  if (x.major < 15 || (x.major === 15 && x.minor === 0)) return ['bad', 'Exchange 2013 or older - out of support; Exchange Online hybrid needs Exchange 2016 / 2019 / SE on a current update'];
  if (x.minor === 1) return x.build >= 2507 ? ['ok', 'Exchange 2016 CU23'] : ['warn', 'Exchange 2016 before CU23 - install CU23 and the latest security update first'];
  if (x.minor === 2) return x.build >= 1544 ? ['ok', x.build >= 2562 ? 'Exchange Server SE' : 'Exchange 2019 CU14 or later'] : ['warn', 'Exchange 2019 before CU14 - install the current CU and security update first'];
  return ['unknown', 'unrecognised version'];
}

// readiness from what the servers reported; D = { checkId: { at, data, error } } (newest per check across Exchange servers)
function readiness(D, settings) {
  const items = [], add = (id, title, status, detail, fix) => items.push({ id, title, status, detail: detail || '', fix: fix || '' });
  const val = (id) => (D[id] && !D[id].error ? D[id].data : undefined);
  const missing = (id) => (D[id] && D[id].error ? 'could not be read: ' + D[id].error : 'not read yet - an Exchange server needs a login (AI Exchange Server Administrator)');

  const sv = arr(val('ex_servers'));
  if (!val('ex_servers')) add('versions', 'Exchange servers on a supported update', 'unknown', missing('ex_servers'));
  else { const v = sv.map((x) => [x.name, versionVerdict(x.version), x.version]); const w = v.some((x) => x[1][0] === 'bad') ? 'bad' : v.some((x) => x[1][0] === 'warn') ? 'warn' : v.some((x) => x[1][0] === 'unknown') ? 'unknown' : 'ok';
    add('versions', 'Exchange servers on a supported update', w, v.map((x) => `${x[0]}: ${x[1][1]} (${x[2]})`).join(' · '), w === 'ok' ? '' : 'Update every Exchange server to the current CU and security update before running the Hybrid Configuration Wizard.'); }

  const certs = arr(val('ex_certificates'));
  if (!val('ex_certificates')) add('certificate', 'Public certificate on IIS and SMTP', 'unknown', missing('ex_certificates'));
  else { const pub = certs.filter((c) => !c.self_signed && /IIS/.test(c.services || '') && /SMTP/.test(c.services || '')).sort((a, b) => (b.days_left || 0) - (a.days_left || 0))[0];
    if (!pub) add('certificate', 'Public certificate on IIS and SMTP', 'bad', 'no certificate from a public CA is bound to both IIS and SMTP', 'Install a public certificate that names the hybrid / mail hostname and autodiscover, then Enable-ExchangeCertificate -Services IIS,SMTP on every hybrid server.');
    else add('certificate', 'Public certificate on IIS and SMTP', pub.days_left < 30 ? 'warn' : 'ok', `${pub.subject} · ${pub.days_left} days left · names ${arr(pub.names).slice(0, 6).join(', ')}`, pub.days_left < 30 ? 'Renew it before the migration: the hybrid mail flow (TLS) and EWS moves use it.' : ''); }

  const ews = arr(val('ex_hybrid_ews'));
  if (!val('ex_hybrid_ews')) add('ews', 'EWS published with an external URL and MRS Proxy on', 'unknown', missing('ex_hybrid_ews'));
  else { const noUrl = ews.filter((e) => !e.external_url), noMrs = ews.filter((e) => e.mrs_proxy !== true);
    add('ews', 'EWS published with an external URL and MRS Proxy on', noUrl.length === ews.length || !ews.length ? 'bad' : (noUrl.length || noMrs.length) ? 'warn' : 'ok',
      ews.map((e) => `${e.server}: ${e.external_url || 'no external URL'}, MRS Proxy ${e.mrs_proxy ? 'on' : 'off'}`).join(' · '),
      (noUrl.length || noMrs.length) ? 'Mailbox moves come in over EWS: set the ExternalUrl and run Set-WebServicesVirtualDirectory -MRSProxyEnabled $true on each hybrid server (the HCW does this on the servers it is given).' : ''); }

  const dom = val('ex_hybrid_domains') || {}, acc = arr(dom.accepted), rem = arr(dom.remote), sc = arr(dom.send_connectors);
  const tenantRe = settings.tenant ? new RegExp('^' + settings.tenant.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\.mail\\.onmicrosoft\\.com$', 'i') : /\.mail\.onmicrosoft\.com$/i;
  if (!val('ex_hybrid_domains')) { add('routing', 'Tenant routing domain accepted (…mail.onmicrosoft.com)', 'unknown', missing('ex_hybrid_domains')); add('remote', 'Remote domain delivers to Exchange Online', 'unknown', missing('ex_hybrid_domains')); add('connector', 'Send connector to Exchange Online', 'unknown', missing('ex_hybrid_domains')); }
  else {
    const r = acc.find((a) => tenantRe.test(a.name || ''));
    add('routing', 'Tenant routing domain accepted (…mail.onmicrosoft.com)', r ? 'ok' : 'bad', r ? r.name : 'not an accepted domain on-premises', r ? '' : 'The Hybrid Configuration Wizard adds it; until then mail for moved mailboxes has nowhere to go.');
    const rd = rem.find((x) => tenantRe.test(x.domain || ''));
    add('remote', 'Remote domain delivers to Exchange Online', rd && rd.target_delivery ? 'ok' : rd ? 'warn' : 'bad', rd ? `${rd.domain} · target delivery ${rd.target_delivery ? 'on' : 'off'}` : 'no remote domain for the tenant', rd && rd.target_delivery ? '' : 'Run the HCW (it creates the remote domain with TargetDeliveryDomain $true).');
    const c = sc.find((x) => x.enabled !== false && (x.cloud || arr(x.smart_hosts).some((h) => /mail\.protection\.outlook\.com$/i.test(h)) || arr(x.spaces).some((h) => tenantRe.test(String(h).replace(/^smtp:/i, '').split(';')[0]))));
    add('connector', 'Send connector to Exchange Online', c ? 'ok' : 'bad', c ? `${c.name} → ${arr(c.smart_hosts).join(', ') || 'DNS'}${c.tls_domain ? ' · TLS ' + c.tls_domain : ''}` : 'no enabled connector to *.mail.protection.outlook.com', c ? '' : 'The HCW creates "Outbound to Office 365"; check it is enabled after the wizard.');
  }

  const h = val('ex_hybrid');
  if (!h) { add('hcw', 'Hybrid configuration (Hybrid Configuration Wizard)', 'unknown', missing('ex_hybrid')); add('freebusy', 'Free/busy and calendar sharing with the cloud', 'unknown', missing('ex_hybrid')); add('oauth', 'OAuth (modern hybrid authentication)', 'unknown', missing('ex_hybrid')); }
  else {
    add('hcw', 'Hybrid configuration (Hybrid Configuration Wizard)', h.hybrid ? 'ok' : 'bad', h.hybrid ? `domains ${arr(h.domains).join(', ') || '-'} · features ${arr(h.features).join(', ') || '-'} · transport servers ${arr(h.servers).join(', ') || '-'}` : 'no hybrid configuration on-premises', h.hybrid ? '' : 'Run the Hybrid Configuration Wizard (Classic or Modern hybrid) from an Exchange server.');
    const or = arr(h.org_relationships).filter((x) => x.enabled && x.free_busy), ioc = arr(h.intra_org_connectors).filter((x) => x.enabled);
    add('freebusy', 'Free/busy and calendar sharing with the cloud', or.length || ioc.length ? 'ok' : 'warn', [].concat(or.map((x) => 'organization relationship ' + x.name), ioc.map((x) => 'intra-organization connector ' + x.name)).join(' · ') || 'none enabled', or.length || ioc.length ? '' : 'Without it, on-premises and cloud users cannot see each other\'s free/busy during the coexistence.');
    const au = arr(h.auth_servers).filter((x) => x.enabled !== false && /evosts|azuread|microsoft/i.test(String(x.name) + ' ' + String(x.type)));
    add('oauth', 'OAuth (modern hybrid authentication)', au.length ? 'ok' : 'warn', au.length ? au.map((x) => x.name).join(', ') : 'no Entra ID auth server configured', au.length ? '' : 'Recommended: the HCW configures OAuth; Classic hybrid falls back to the organization relationship.');
  }

  const order = { bad: 0, warn: 1, unknown: 2, ok: 3 };
  const counts = items.reduce((m, x) => (m[x.status] = (m[x.status] || 0) + 1, m), {});
  const verdict = counts.bad ? 'not_ready' : counts.unknown ? 'incomplete' : counts.warn ? 'ready_with_warnings' : 'ready';
  return { items: items.sort((a, b) => order[a.status] - order[b.status]), counts, verdict };
}

function createHybrid({ state, targets, health, now = Date.now }) {
  const col = state.collection('exo_hybrid');
  const settings = () => Object.assign({ tenant: '', endpoint: 'Hybrid Migration Endpoint - EWS (Default Web Site)', notify: '' }, (col.get('settings') || {}).values || {});
  function putSettings(b, who) {
    const cur = settings(), v = Object.assign({}, cur);
    if (b.tenant !== undefined) { const t = s(b.tenant, 63).toLowerCase().replace(/\.(mail\.)?onmicrosoft\.com$/, ''); if (t && !/^[a-z0-9][a-z0-9-]{0,62}$/.test(t)) throw new HttpError(400, 'tenant: the name before .onmicrosoft.com, e.g. sentra'); v.tenant = t; }
    if (b.endpoint !== undefined) { const e = s(b.endpoint, 120); if (!e) throw new HttpError(400, 'endpoint: the migration endpoint name in Exchange Online'); v.endpoint = e; }
    if (b.notify !== undefined) { const n = s(b.notify, 200); if (n && !ADDR.test(n)) throw new HttpError(400, 'notify: one e-mail address'); v.notify = n; }
    col.put({ id: 'settings', values: v, by: who, at: now() }); return v;
  }
  // the newest result of each check across the Exchange servers (org checks run on one server)
  function data() {
    const D = {};
    for (const t of targets.list('exchange')) { const snap = health.snapshot(t.id); for (const [id, r] of Object.entries((snap && snap.results) || {})) if (!D[id] || (r.at || 0) > (D[id].at || 0)) D[id] = Object.assign({ server: t.name }, r); }
    return D;
  }
  function manual() { const m = (col.get('manual') || {}).items || {}; return MANUAL.map(([id, title]) => Object.assign({ id, title, done: false }, m[id] || {})); }
  function setManual(id, b, who) {
    if (!MANUAL.some((x) => x[0] === id)) throw new HttpError(404, 'unknown step');
    const rec = col.get('manual') || { id: 'manual', items: {} };
    rec.items = Object.assign({}, rec.items, { [id]: { done: b.done === true, note: s(b.note, 300), by: who, at: now() } }); col.put(rec); return manual();
  }
  const waves = () => col.all().filter((x) => /^wave-/.test(x.id)).sort((a, b) => String(a.planned || '').localeCompare(String(b.planned || '')) || a.created_at - b.created_at);
  function parseAddrs(text) {
    const L = [...new Set(String(text || '').split(/[\s,;]+/).map((x) => x.trim().toLowerCase()).filter(Boolean))];
    const badOnes = L.filter((x) => !ADDR.test(x)); if (badOnes.length) throw new HttpError(400, 'not an e-mail address: ' + badOnes.slice(0, 5).join(', '));
    if (L.length > 2000) throw new HttpError(400, 'at most 2000 mailboxes per wave'); return L;
  }
  function putWave(b, who) {
    const prev = b.id && /^wave-/.test(String(b.id)) ? col.get(s(b.id, 40)) : null; if (b.id && !prev) throw new HttpError(404, 'wave not found');
    const name = s(b.name, 60); if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{1,59}$/.test(name)) throw new HttpError(400, 'name: 2-60 letters, digits, space . _ - (it becomes the migration batch name)');
    if (waves().some((w) => w.name.toLowerCase() === name.toLowerCase() && (!prev || w.id !== prev.id))) throw new HttpError(400, 'a wave with this name exists');
    const planned = s(b.planned, 10); if (planned && !/^\d{4}-\d{2}-\d{2}$/.test(planned)) throw new HttpError(400, 'planned: YYYY-MM-DD');
    const mailboxes = b.mailboxes !== undefined ? parseAddrs(b.mailboxes) : (prev ? prev.mailboxes : []);
    if (!mailboxes.length) throw new HttpError(400, 'list the mailboxes (e-mail addresses) in this wave');
    const at = now(), id = prev ? prev.id : 'wave-' + at.toString(36);
    const rec = Object.assign({}, prev || { id, created_at: at, created_by: who, status: 'planned', history: [{ at, by: who, what: 'planned' }] }, { name, planned, mailboxes, notes: s(b.notes, 1000), updated_at: at, updated_by: who });
    if (prev) rec.history = (prev.history || []).concat({ at, by: who, what: 'edited' });
    col.put(rec); return rec;
  }
  function setStatus(id, b, who) {
    const w = /^wave-/.test(String(id)) ? col.get(s(id, 40)) : null; if (!w) throw new HttpError(404, 'wave not found');
    const st = s(b.status, 20); if (!WAVE_FLOW.includes(st)) throw new HttpError(400, 'status: ' + WAVE_FLOW.join(', '));
    const note = s(b.note, 500); if (st === 'failed' && note.length < 5) throw new HttpError(400, 'say what failed (at least 5 characters)');
    w.status = st; w.history = (w.history || []).concat({ at: now(), by: who, what: st + (note ? ': ' + note : '') }); w.updated_at = now(); col.put(w); return w;
  }
  function commands(id) {
    const w = /^wave-/.test(String(id)) ? col.get(s(id, 40)) : null; if (!w) throw new HttpError(404, 'wave not found');
    const S = settings(); if (!S.tenant) throw new HttpError(409, 'set the Microsoft 365 tenant name first (Settings)');
    const file = 'C:\\Migration\\' + w.name.replace(/[^A-Za-z0-9._-]+/g, '-') + '.csv', b = psq(w.name), target = S.tenant + '.mail.onmicrosoft.com';
    const csv = 'EmailAddress\r\n' + w.mailboxes.join('\r\n') + '\r\n';
    const ps = [
      '# Wave ' + w.name + ' - ' + w.mailboxes.length + ' mailbox(es)' + (w.planned ? ', planned ' + w.planned : '') + '. Run in Exchange Online PowerShell; review before running.',
      '# 1. Save the CSV from the portal as ' + file,
      'Connect-ExchangeOnline',
      '# 2. Create the batch: it copies the mailboxes in the background and does NOT switch users over yet',
      'New-MigrationBatch -Name ' + b + ' -SourceEndpoint ' + psq(S.endpoint) + ' -TargetDeliveryDomain ' + psq(target) + " -CSVData ([System.IO.File]::ReadAllBytes(" + psq(file) + ')) -AutoStart' + (S.notify ? ' -NotificationEmails ' + psq(S.notify) : ''),
      '# 3. Follow the copy (record "synced" in the portal when every mailbox is Synced)',
      'Get-MigrationBatch -Identity ' + b + ' | Format-List Status,TotalCount,SyncedCount,FinalizedCount,FailedCount',
      'Get-MigrationUser -BatchId ' + b + ' | Get-MigrationUserStatistics | Format-Table Identity,Status,PercentageComplete,ErrorSummary -AutoSize',
      '# 4. In the migration window: switch the users over (Outlook asks them to restart)',
      'Complete-MigrationBatch -Identity ' + b,
      '# 5. When every mailbox is Completed, record "completed" in the portal; then remove the finished batch',
      '# Remove-MigrationBatch -Identity ' + b,
    ].join('\r\n') + '\r\n';
    return { wave: w.name, mailboxes: w.mailboxes.length, csv, csv_name: file.split('\\').pop(), powershell: ps };
  }
  function view(role) {
    const D = data(), S = settings(), R = readiness(D, S), C = (D.ex_mailbox_counts && !D.ex_mailbox_counts.error && D.ex_mailbox_counts.data) || null;
    const priv = !role || role === 'viewer' || role === 'analyst';
    const W = waves().map((w) => Object.assign({}, w, { count: w.mailboxes.length, mailboxes: priv ? undefined : w.mailboxes }));
    const planned = W.reduce((n, w) => n + (w.status === 'completed' || w.status === 'failed' ? 0 : w.count), 0), done = W.reduce((n, w) => n + (w.status === 'completed' ? w.count : 0), 0);
    const ats = Object.values(D).map((r) => r.at || 0).filter(Boolean);
    return { settings: S, readiness: R, manual: manual(), data_at: ats.length ? Math.max(...ats) : null, servers: targets.list('exchange').length, servers_with_login: targets.list('exchange').filter((t) => targets.login(t, 'exchange')).length,
      inventory: C ? { on_premises: C.on_premises, in_cloud: C.in_cloud, by_type: arr(C.by_type), by_database: arr(C.by_database), in_cloud_by_type: arr(C.in_cloud_by_type), with_archive: C.with_archive, at: D.ex_mailbox_counts.at } : null,
      waves: W, waves_summary: { waves: W.length, planned_mailboxes: planned, completed_mailboxes: done }, flow: WAVE_FLOW };
  }
  return { view, putSettings, setManual, putWave, setStatus, commands, readiness, data };
}

function register(api, deps, S) {
  const P = prefixOf(deps), { targets, health } = S;
  const H = createHybrid({ state: deps.state, targets, health, now: deps.now });
  api.route('GET', `${P}/sysadmin/hybrid`, wrap(deps, null, (ctx) => H.view(ctx.role)));
  api.route('PUT', `${P}/sysadmin/hybrid/settings`, wrap(deps, 'admin', (ctx) => { const r = H.putSettings(body(ctx), ctx.user); audit(ctx, 'sysadmin.hybrid.settings', 'hybrid', r); return r; }));
  api.route('POST', `${P}/sysadmin/hybrid/refresh`, wrap(deps, 'operator', async (ctx) => {
    const t = targets.list('exchange').find((x) => targets.login(x, 'exchange')); if (!t) throw new HttpError(409, 'no Exchange server with a login - add one on the AI Exchange Server Administrator');
    await health.pollServer(t.id, { org: true, by: 'hybrid-readiness' }); audit(ctx, 'sysadmin.hybrid.refresh', t.id); return H.view(ctx.role);
  }));
  api.route('POST', `${P}/sysadmin/hybrid/manual/:id`, wrap(deps, 'operator', (ctx) => { const r = H.setManual(ctx.params.id, body(ctx), ctx.user); audit(ctx, 'sysadmin.hybrid.step', ctx.params.id, { done: body(ctx).done === true }); return { manual: r }; }));
  api.route('POST', `${P}/sysadmin/hybrid/waves`, wrap(deps, 'operator', (ctx) => { const w = H.putWave(body(ctx), ctx.user); audit(ctx, 'sysadmin.hybrid.wave', w.id, { name: w.name, mailboxes: w.mailboxes.length }); return w; }));
  api.route('POST', `${P}/sysadmin/hybrid/waves/:id/status`, wrap(deps, 'operator', (ctx) => { const w = H.setStatus(ctx.params.id, body(ctx), ctx.user); audit(ctx, 'sysadmin.hybrid.wave.status', w.id, { status: w.status }); return w; }));
  api.route('GET', `${P}/sysadmin/hybrid/waves/:id/commands`, wrap(deps, 'operator', (ctx) => { const r = H.commands(ctx.params.id); audit(ctx, 'sysadmin.hybrid.commands', ctx.params.id, { mailboxes: r.mailboxes }); return r; }));
  return H;
}

module.exports = { register, createHybrid, readiness, versionVerdict, WAVE_FLOW };
