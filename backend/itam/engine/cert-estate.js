// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body } = require('./check');
const { guardOf } = require('./errors');
/*
 * Certificate lifecycle across the estate - the four pillars of the Certificates page, beside the endpoint inventory
 * (certs.js), issuance (cert-issue.js) and installation (cert-install.js). Python decides (pyengine/cert_estate.py).
 *   1. Discovery & inventory   network endpoints + the Windows machine certificate stores ("keystores") + the machine
 *                              certificates an AD CS CA issued (agent 1.6, through the SIEM's GET /hardening/snapshots) -
 *                              one row per certificate with every place it was seen (matched on the serial number)
 *   2. Expiration risk         the expiry timeline and the alerts: each installed certificate that crosses a threshold
 *                              (default 60 / 30 / 14 / 7 / 1 days, and expired) is e-mailed ONCE to the alert list and to
 *                              the endpoint's owner, through the platform's mail relay (Privacy Office -> Notifications)
 *   3. Renewal & publishing    certs.js renewals, cert-issue.js (ACME public / AD CS private) and cert-install.js (four-eyes
 *                              installs on Palo Alto / FortiGate) - unchanged, summarised in the report
 *   4. Compliance & audit      the report: by source, issuer, key, risk; within policy; owners; renewed before expiry;
 *                              automation coverage; the SAMA CSF / NCA ECC controls it evidences; CSV export (audited)
 * Nothing here contacts a server or changes a certificate.
 *
 *   GET  /certs/estate           viewer    inventory across sources, timeline, sources
 *   GET  /certs/report           viewer    the compliance & audit report
 *   GET  /certs/report/export    operator  CSV of every certificate and place                       audited
 *   GET  /certs/alerts           operator  alert settings, the alerts due now and the last 100 sent
 *   POST /certs/alerts           admin     {enabled, thresholds[], recipients[], notify_owners}         audited
 *   POST /certs/alerts/run       admin     send the alerts due now                                      audited
 */
const SIEM_AS = { user: 'system:itam-pki', role: 'analyst' };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const EMAIL = /^[^\s@<>()",;]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$/;

function createCertEstate(app, C, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const AL = () => store.collection('cert_alert_settings'), SENT = () => store.collection('cert_alerts');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, err) => { if (app.log && app.log.every) app.log.every('cert-estate:' + key, 3600000, 'warn', msg, { err: String((err && err.message) || err || '').slice(0, 200) }); };
  const settings = () => Object.assign({ enabled: false, thresholds: [60, 30, 14, 7, 1], recipients: [], notify_owners: true }, AL().get('settings') || {});

  async function siem(path) {
    if (opts.siem) return opts.siem(path);
    const L = app.discovery && app.discovery.siem; if (!L || typeof L.call !== 'function') return { _down: 'the SIEM link is not configured' };
    let r;
    try { r = await L.call('GET', path, SIEM_AS); }
    catch (e) { warn('siem', 'certificates: the SIEM link failed - keystores and CA shown as not reachable', String(e.message)); return { _down: 'the SIEM did not answer (' + String(e.message).slice(0, 120) + ')' }; }   // the network certificates still show
    if (!r) return { _down: 'the SIEM did not answer' };
    if (r.status !== 200) return { _down: 'SIEM ' + path + ': HTTP ' + r.status };
    return r.json || {};
  }
  async function stores() {
    const s = await siem('/hardening/snapshots');
    if (s._down) return { keystores: [], ca: [], keystore_reason: s._down, ca_reason: s._down };
    const ks = [], ca = [];
    let agents = 0, old = 0;
    for (const h of s.hosts || []) {
      const st = h.settings || {};
      agents++;
      if (Array.isArray(st.certs)) ks.push({ host: h.host, at: h.at, certs: st.certs.slice(0, 300) }); else if (st.certs === undefined) old++;
      if (Array.isArray(st.ca_issued)) ca.push({ host: h.host, at: h.at, rows: st.ca_issued.slice(0, 500) });
    }
    return { keystores: ks, ca, keystore_reason: !agents ? 'no Windows agent snapshot yet' : !ks.length ? old + ' server(s) run an agent older than 1.6 - update the Windows agent' : '',
      ca_reason: !agents ? 'no Windows agent snapshot yet' : 'no AD CS certification authority with agent 1.6 found' };
  }
  const all = (name) => { try { return store.collection(name).all(); } catch (e) { warn('read:' + name, 'certificates: ' + name + ' not read', e); return []; } };

  async function estate() {
    const a = await C.assess(), st = await stores();
    const r = await C.py.call('certs.estate', { endpoints: a.endpoints, keystores: st.keystores, ca: st.ca, keystore_reason: st.keystore_reason, ca_reason: st.ca_reason,
      renewals: all('cert_renewals'), requests: all('cert_requests').map((q) => ({ id: q.id, status: q.status })), installs: all('cert_install_jobs').map((j) => ({ id: j.id, status: j.status })),
      policy: store.collection('cert_policy').get('policy') || {}, alerts: settings(), sent: SENT().all().map((x) => x.id), now: now() });
    if (!r || r.ok === false) { warn('py', 'certificates: the estate rules (Python) did not answer', r && r.error); throw httpErr(409, 'The certificate rules run in Python and Python did not answer - run the update so pyengine is installed'); }
    return Object.assign(r, { generated_at: iso() });
  }
  async function report() { const e = await estate(); return { report: e.report, timeline: e.timeline, sources: e.sources, generated_at: e.generated_at }; }

  async function exportCsv(who) {
    const e = await estate();
    const q = (s) => { const t = String(s == null ? '' : s); return /^[=+\-@\t\r]/.test(t) ? "'" + t : t; };   // no formula injection in Excel
    const cell = (s) => '"' + q(s).replace(/"/g, '""') + '"';
    const lines = [['Subject', 'Names', 'Issuer', 'Serial', 'Expires', 'Days left', 'Key', 'Signature', 'Sources', 'Places', 'Owner', 'Risk', 'Risks'].map(cell).join(',')];
    for (const x of e.items) lines.push([x.subject, x.names.join(' '), x.issuer, x.serial, x.not_after, x.days_left, x.key, x.sig_alg, x.sources.join(' '), x.places.map((p) => p.where).join(' | '), x.owner, x.risk, x.risks.map((r) => r.severity + ': ' + r.text).join(' | ')].map(cell).join(','));
    audit(who, 'certs.report.export', 'estate', { certificates: e.items.length });
    return { filename: 'certificate-inventory-' + iso().slice(0, 10) + '.csv', csv: lines.join('\r\n') };
  }

  async function alertsView() {
    const e = await estate();
    return { settings: settings(), due: e.alerts_due, sent: SENT().all().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 100),
      relay: app.addons && app.addons.privacyOffice && app.addons.privacyOffice.notifier ? 'the platform mail relay (Privacy Office -> Notifications)' : null };
  }
  function putAlerts(input, who) {
    if (require('./approve-scopes').isHuman && !require('./approve-scopes').isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot change the alert settings');
    const b = body(input || {}).bool('enabled').list('thresholds', { max: 8, unique: true }).list('recipients', { max: 30, item: 'str', itemMax: 254, unique: true }).bool('notify_owners').done();
    if (b.thresholds && b.thresholds.some((t) => !Number.isInteger(t) || t < 1 || t > 365)) throw httpErr(400, 'thresholds: each must be a whole number of days between 1 and 365');
    if (b.recipients && b.recipients.some((x) => !EMAIL.test(x))) throw httpErr(400, 'recipients: each must be an e-mail address');
    const prev = settings();
    const rec = Object.assign({}, prev, b, { id: 'settings', updated_by: who.user, updated_at: iso() });
    if (rec.enabled && !(rec.recipients.length || rec.notify_owners)) throw httpErr(400, 'recipients: give at least one address, or notify the owners');
    AL().put(rec);
    audit(who, 'certs.alerts.settings', 'alerts', { enabled: rec.enabled, thresholds: rec.thresholds, recipients: rec.recipients.length, notify_owners: rec.notify_owners });
    return settings();
  }
  // send what is due: each (certificate, threshold) once; recorded only when the relay accepted it
  async function runAlerts(who) {
    const s = settings();
    if (!s.enabled) return { sent: 0, note: 'alerts are off' };
    const N = app.addons && app.addons.privacyOffice && app.addons.privacyOffice.notifier;
    if (!N || typeof N.sendPlatform !== 'function') { warn('relay', 'certificates: no mail relay to send expiry alerts'); return { sent: 0, note: 'no mail relay - set it in Privacy Office -> Notifications' }; }
    const e = await estate(); let sent = 0, failed = 0, skipped = null;
    for (const d of e.alerts_due.slice(0, 200)) {
      const owner = d.owner && EMAIL.test(d.owner) ? [d.owner] : [];
      const users = s.notify_owners && d.owner && !EMAIL.test(d.owner) ? [d.owner] : [];
      const emails = s.recipients.concat(s.notify_owners ? owner : []);
      if (!emails.length && !users.length) continue;
      const when = d.threshold === 'expired' ? 'EXPIRED on ' + d.not_after : 'expires in ' + d.days_left + ' day(s), on ' + d.not_after;
      const r = await N.sendPlatform({ key: 'cert|' + d.key, event: 'cert-expiry', emails, users, from_name: (ZYB_ORG.short + ' PKI'),
        subject: (d.critical ? '[critical] ' : '') + 'Certificate ' + d.subject + ' ' + (d.threshold === 'expired' ? 'has expired' : 'expires in ' + d.days_left + ' day(s)'),
        text: 'Certificate: ' + d.subject + '\nStatus: ' + when + '\nInstalled on: ' + d.where.join('; ') + '\nOwner: ' + (d.owner || 'not recorded') +
          '\n\nRenew it and publish it to every place listed: Certificates -> Renewal & Publishing.\nThis alert is sent once for this threshold.' });
      if (r.status === 'sent' || r.status === 'duplicate') { SENT().put({ id: d.key, at: iso(), threshold: d.threshold, subject: d.subject, days_left: d.days_left, to: emails.length + users.length, status: r.status }); sent++; }
      else if (r.status === 'skipped') skipped = r.error || 'not sent';
      else failed++;
    }
    if (sent || failed) audit(who || { user: 'system:pki', role: '' }, 'certs.alerts.sent', 'alerts', { sent, failed });
    return Object.assign({ sent, failed }, skipped && !sent ? { note: skipped + ' - nothing was sent; the alerts stay due' } : {});
  }
  function start() {
    if (app.noTimers || opts.noTimer) return;
    const job = guardOf(app, 'certs.alerts', () => runAlerts(null));
    const t1 = setTimeout(job, 15 * 60000), t2 = setInterval(job, 6 * 3600000); if (t1.unref) { t1.unref(); t2.unref(); }
  }
  return { estate, report, exportCsv, alertsView, putAlerts, runAlerts, start };
}

function registerCertEstateRoutes(srv, app, X) {
  srv.route('GET', '/certs/estate', (ctx) => { ctx.need('viewer'); return X.estate(); });
  srv.route('GET', '/certs/report', (ctx) => { ctx.need('viewer'); return X.report(); });
  srv.route('GET', '/certs/report/export', (ctx) => { ctx.need('operator'); return X.exportCsv(ctx.who); });
  srv.route('GET', '/certs/alerts', (ctx) => { ctx.need('operator'); return X.alertsView(); });
  srv.route('POST', '/certs/alerts', (ctx) => { ctx.need('admin'); return X.putAlerts(ctx.body, ctx.who); });
  srv.route('POST', '/certs/alerts/run', async (ctx) => { ctx.need('admin'); body(ctx.body).done(); const r = await X.runAlerts(ctx.who); return r; });
}

module.exports = { createCertEstate, registerCertEstateRoutes };
