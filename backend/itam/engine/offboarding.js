// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { tempPassword } = require('./ad-writer');
/*
 * HR offboarding - leavers ({P} = /api/itam, User Desktops -> HR Offboarding): an employee's Active Directory account is
 * disabled on their last day, after two decisions by two people, and their equipment comes back.
 *   1. request     HR (operator) records the leaver: name, employee number, AD user name, department, last day, manager,
 *                  reason, "immediate" (termination: disable as soon as it is approved). The platform reads the account
 *                  from the directory (read-only) and shows who it is - display name, employee number, groups, last sign-in
 *   2. confirm     the named manager (or an administrator) confirms the person is leaving - never the requester
 *   3. approve     an administrator who is neither the requester nor the person who confirmed approves DISABLING the account
 *                  (four eyes on a change to a system). Refused when the directory account looks like someone else (its
 *                  employee number differs), is privileged (admin groups / adminCount), is on the never-disable list or is
 *                  the platform's own service account - those are disabled by hand by a domain administrator
 *   4. disable     AUTOMATIC at the approved time (the last day at the configured hour, Riyadh; or at once for "immediate"):
 *                  re-read and re-checked, then disabled, its password replaced by a random one nobody sees (so a re-enable
 *                  by mistake does not open it), the description says which request did it, moved to the leavers OU if one
 *                  is set; read back and verified. Never deleted, groups kept (recorded) for the audit. Without directory
 *                  settings, the person who disabled it by hand records it (not the leaver)
 *   5. equipment   every asset the leaver holds in the register is returned to stock (or marked not applicable with a reason)
 *   5b. forwarding when Exchange Online is set up: the administrator who approves the disable also decides what happens to the
 *                  leaver's mail forwarding - remove all of it (default), remove only forwarding OUTSIDE the company (to an
 *                  address not in the tenant's accepted domains), or decide after the disable. When the account is disabled
 *                  the platform reads the mailbox forwarding (ForwardingSmtpAddress / ForwardingAddress) and every inbox rule
 *                  that forwards or redirects, and removes what was approved at once: the mailbox forwarding is cleared, the
 *                  rules are DISABLED (never deleted - they stay as evidence); each is read back. What was removed (and what was
 *                  kept, internal) is recorded with its targets, so it can be put back by hand on a rehire. For 30 days the
 *                  platform reads it again once a day: forwarding that comes back (a delegate re-enabling a rule) is removed
 *                  under the same decision, recorded and logged. "Decide after" is decided by an administrator who did not
 *                  raise the request. An on-premises mailbox is handled by an Exchange administrator and recorded.
 *                  Before the disable, an operator can check the forwarding (read-only) so the approver sees it
 *   6. mailbox     when Exchange Online is set up (engine/exo.js): once the account is disabled the platform reads the leaver's
 *                  mailbox and PROPOSES converting it to a shared mailbox, with Full Access for the manager (or named people)
 *                  and an automatic reply. An administrator who did not raise the request approves; the platform converts it,
 *                  checks it is now a SharedMailbox, grants the access and sets the reply. A shared mailbox needs no licence
 *                  (under 50 GB, no archive or hold - the page warns otherwise), which is what makes the licence reclaim safe.
 *                  An on-premises mailbox (hybrid, not migrated) is converted by an Exchange administrator and recorded
 *   6b. onedrive   when SharePoint is set up (Exchange Online settings -> SharePoint admin address): the administrator who approves the
 *                  disable also decides the leaver's OneDrive - give the manager access (default), decide after the disable, or
 *                  do not hand it over - and for how long (default 60 days, 7-365). At the disable the platform reads the
 *                  OneDrive and adds the named people as its site collection administrators, read back. The owner is never
 *                  removed and nothing is moved or deleted. When the period ends the platform removes exactly the people it
 *                  added (anyone who was an administrator before keeps what they had). An administrator who is not one of
 *                  the people given access can extend it (to at most 365 days from the start, with a reason); an operator can
 *                  end it early. A re-enable ends it at once. The OneDrive holds the leaver's own files too (PDPL): access is
 *                  for named people, for a period, and every grant, extension and end is audited
 *   6c. teams      when "leavers' groups and Teams" is on (Microsoft 365 licensing settings): the administrator who approves the
 *                  disable also decides the Microsoft 365 groups and Teams the leaver owns - transfer them to the manager
 *                  (default: the manager becomes an owner, and member of a team; the leaver stops being an owner), add the
 *                  manager and keep the leaver listed, decide after the disable, or leave them. At the disable the platform
 *                  lists what the leaver owns and who else owns each (a group whose only active owner is the leaver is
 *                  flagged - it would be orphaned), then makes the changes through Microsoft Graph, each read back. The leaver
 *                  is never removed as owner when that would leave a group without an active owner. Nothing is deleted;
 *                  what changed is recorded per group so it can be put back by hand
 *   6d. calendar   when "leavers' meetings" is on (Microsoft 365 licensing settings): the administrator who approves the disable
 *                  also decides the meetings the leaver organises in the coming months (default 180 days) - move them to the
 *                  manager (default), cancel them, decide after the disable, or leave them. Exchange cannot change a meeting's
 *                  organiser, so "move" creates each meeting again from the manager's calendar (same subject, agenda,
 *                  attendees, place and repeat pattern from the next occurrence; a new Teams link when it was online; a line
 *                  saying who organised it) and THEN ends the leaver's one - a series stops yesterday so past occurrences stay
 *                  in everyone's calendar, a single meeting is cancelled with a note naming the new organiser. A meeting is
 *                  never ended before its replacement exists. Private meetings are listed and left alone. Attendees receive
 *                  the new invitations and the cancellations - the approval form says so. An operator can check the meetings
 *                  before the disable (read-only)
 *   apps           business applications in the application register (HR Offboarding -> Applications, administrators keep it):
 *                  each application says how access is removed - "entra" (an Entra ID enterprise application: the leaver's
 *                  own assignments are removed through Graph and read back, and the leaver's sign-in sessions are ended once),
 *                  "ad_group" (access comes from AD groups: the leaver is taken out of them and read back - the groups were
 *                  recorded at the disable), or "manual" (an application with its own accounts: its named owner gets a task
 *                  with a due date and confirms "removed" or "had no account" with a reference; late tasks show as overdue).
 *                  A manual application applies to everyone, to named departments, or "check" (the owner checks). The disable
 *                  approval decides: remove at the disable (default) or decide after (an administrator who did not raise the
 *                  request, keeping any application with a reason). Automatic removal falls back to the owner when its
 *                  connection is not set up. Failures are retried hourly (taking access away is safe to repeat)
 *   devices        when "leavers' devices" is on (Microsoft 365 licensing settings): once the account is disabled the platform lists
 *                  the leaver's devices in the MDM - ManageEngine MDM Plus now, Intune later (engine/mdm.js) - matched to the asset
 *                  register by serial, and PROPOSES an action for each - a
 *                  company device: full wipe (factory reset); a personal device: retire (company data removed, the person's
 *                  own data untouched). An administrator who did not raise the request decides device by device (wipe /
 *                  retire / keep with a reason); a full wipe also needs the device's serial typed. Never a full wipe of a
 *                  personal or unknown-owner device, never of a Mac (it needs an unlock code - done in Intune and recorded
 *                  here), never of a device now assigned to someone else (checked again just before sending), and nothing at
 *                  all while a legal hold is being placed or in place (the device may hold evidence). The action is sent once,
 *                  then followed until Intune reports it done; a failed send is retried only by an administrator
 *   legal hold     for a leaver under a claim, investigation or audit (Microsoft 365 licensing settings -> leavers under legal
 *                  hold): an operator asks for it - the matter, why, optionally the PDPL legal hold it belongs to, an existing
 *                  eDiscovery case, a date range and whether to export - at any time, before or after the disable. An
 *                  administrator who did not ask approves; then the platform works through Microsoft Purview eDiscovery: opens
 *                  the case (or uses the one named), adds the leaver as custodian with their mailbox (Teams chats are stored
 *                  there) and OneDrive, places the hold and waits until Purview says it is applied, then - if asked - searches
 *                  the custodian's content (the date range), estimates it and starts an export IN Purview, where the legal team
 *                  downloads it. The content never comes to the platform: it records ids, item counts, sizes and file names.
 *                  The licence reclaim waits while a hold is being put in place. Releasing a hold is asked by one person and
 *                  approved by another; the case is never closed or deleted here
 *   7. licences    when licence reclaim is on (Microsoft 365 licensing settings): once the account is disabled the platform reads
 *                  the leaver's Microsoft 365 licences and PROPOSES taking them back after the hold period (default 30 days).
 *                  An administrator who did not raise the request approves - choosing which licences go, giving a reason for
 *                  any kept, and confirming the mailbox was handled (removing the Exchange licence starts Microsoft's 30-day
 *                  mailbox deletion, so convert it to a shared mailbox or put it on hold first). At the due time the licences
 *                  are removed and the user read back; the seats are free for joiners. Rejected = licences kept, recorded.
 *                  A re-enable before then cancels it; after it, the licences have to be assigned again
 * The request is complete when 2-5 are done. Re-enabling (a mistake, a rehire) is asked by an administrator and approved by
 * another one. Hybrid Microsoft 365: the disabled account stops signing in to Microsoft 365 at the next Entra Connect sync;
 * revoking open sessions and the mailbox stay with the Microsoft 365 administrators (the page says so).
 * Names and employee numbers are personal data (PDPL): operators and administrators only; viewers are refused.
 *   GET  /offboarding                        operator  list + counts
 *   GET  /offboarding/:id                    operator  (with the assets the leaver holds)
 *   POST /offboarding                        operator  {name, employee_id, username, department, last_day, manager, reason, immediate?, note?}
 *   POST /offboarding/:id/lookup             operator  read the account from the directory again
 *   POST /offboarding/:id/confirm            operator  {decision: confirm|reject, note?}   the named manager or an admin, not the requester
 *   POST /offboarding/:id/approve            admin     {decision: approve|reject, forwarding?: remove|remove_external|ask,
 *                                                       onedrive?: manager|ask|none, onedrive_days?, teams?: transfer|add|ask|none, apps?: remove|ask,
 *                                                       calendar?: transfer|cancel|ask|none, note?}
 *                                                       not the requester, not the confirmer
 *   POST /offboarding/:id/disabled           operator  {directory_ref, note?}   manual record when automatic disabling is off / failed
 *   POST /offboarding/:id/retry              admin     disable now after a failure (still only after approval and the due time)
 *   POST /offboarding/:id/equipment          operator  {returned: [asset ids], na_reason?}
 *   POST /offboarding/:id/cancel             operator  {reason}   before the account was disabled
 *   POST /offboarding/:id/reenable           admin     {reason}   ask to re-enable a disabled account
 *   POST /offboarding/:id/reenable/decide    admin     {decision, note?}   not the person who asked
 *   POST /offboarding/:id/reclaim/refresh    operator  read the leaver's licences again
 *   POST /offboarding/:id/reclaim/decide     admin     {decision: approve|reject, remove?[sku ids], keep_reason?, mailbox: converted_to_shared|on_hold|not_needed,
 *                                                       now?: bool, note?}   not the person who raised the leaver request
 *   POST /offboarding/:id/reclaim/manual     operator  {reference}   removed by hand
 *   POST /offboarding/:id/mailbox/decide     admin     {decision: approve|reject, delegates?[addresses], auto_reply?, note?}   not the requester
 *   POST /offboarding/:id/mailbox/retry      admin     run the conversion again after a failure / partial result
 *   POST /offboarding/:id/mailbox/manual     operator  {reference}   converted by hand
 *   GET  /offboarding/apps                   operator  the application register
 *   POST /offboarding/apps                   admin     {id?, name, owner, method: entra|ad_group|manual, sp_id?, groups?[], applies?, departments?[], sla_days?, notes?}
 *   POST /offboarding/apps/retire            admin     {id, reason}   take an application out of the register
 *   POST /offboarding/:id/apps/decide        admin     {decision: approve|reject, keep?: [{app_id, reason}], note?}   not the requester
 *   POST /offboarding/:id/apps/confirm       operator  {app_id, outcome: removed|no_account, reference}   the application's owner or an admin
 *   POST /offboarding/:id/apps/retry         admin     run again what failed
 *   POST /offboarding/:id/devices/decide     admin     {decisions: [{device_id, action: wipe|retire|keep, confirm?, reason?}], note?}
 *   POST /offboarding/:id/devices/retry      admin     send again what failed (re-checked first) / read again after a failed read
 *   POST /offboarding/:id/devices/manual     operator  {device_id, reference}   handled by hand (e.g. a Mac wiped in Intune)
 *   POST /offboarding/:id/legal              operator  {matter, reason, pdpl_hold?, case_id?, export?, from?, to?}   ask for a legal hold
 *   POST /offboarding/:id/legal/decide       admin     {decision: approve|reject, note?}   not the person who asked, not the leaver
 *   POST /offboarding/:id/legal/retry        admin     after a failed step
 *   POST /offboarding/:id/legal/release      operator  {reason}   ask to release the hold
 *   POST /offboarding/:id/legal/release/decide admin   {decision, note?}   not the person who asked for the release
 *   POST /offboarding/:id/calendar/check     operator  read the meetings the leaver organises (read-only; shown to the approver)
 *   POST /offboarding/:id/calendar/decide    admin     {decision: approve|reject, mode?: transfer|cancel, owner?, exclude?[meeting ids], note?}
 *   POST /offboarding/:id/calendar/retry     admin     after a failed read / change
 *   POST /offboarding/:id/calendar/manual    operator  {reference}   handled by hand
 *   POST /offboarding/:id/teams/decide       admin     {decision: approve|reject, owner?, mode?: transfer|add, note?}   not the requester
 *   POST /offboarding/:id/teams/retry        admin     after a failed read / change
 *   POST /offboarding/:id/teams/manual       operator  {reference}   changed by hand
 *   POST /offboarding/:id/onedrive/decide    admin     {decision: approve|reject, delegates?[addresses], days?, note?}   not the requester
 *   POST /offboarding/:id/onedrive/extend    admin     {days, reason}   not the requester, not a person who has the access
 *   POST /offboarding/:id/onedrive/end       operator  {reason}   end the access now
 *   POST /offboarding/:id/onedrive/retry     admin     after a failed read / grant / end
 *   POST /offboarding/:id/onedrive/manual    operator  {reference}   given by hand
 *   POST /offboarding/:id/forwarding/check   operator  read the leaver's forwarding now (read-only; shown to the approver)
 *   POST /offboarding/:id/forwarding/decide  admin     {decision: approve|reject, scope?: all|external, note?}   not the requester
 *   POST /offboarding/:id/forwarding/retry   admin     remove again after a failure / read again after a failed read
 *   POST /offboarding/:id/forwarding/manual  operator  {reference}   removed by hand (on-premises mailbox, or after a failure)
 *   (Exchange Online settings: GET/POST /offboarding/exo, POST /offboarding/exo/test - engine/exo.js)
 *   POST /offboarding/run                    admin     run the disables (and licence reclaims) that are due now (the 5-minute job does it too)
 */
const REASONS = ['resignation', 'end_of_contract', 'termination', 'retirement', 'transfer', 'other'];
const USER = { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'manager must be a platform user name (letters, digits, . _ - @ \\)' };
const SAM = /^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/;
const PRIVILEGED = /\b(domain admins|enterprise admins|schema admins|administrators|account operators|backup operators|server operators|print operators|dnsadmins|key admins|organization management|admins?)\b/i;
const SECRETISH = /\b(pass(word|wd|phrase|code)?|pwd|secret|pin)\b\s*(is|was|=|:|-)?\s*\S{4,}/i;
const TZ = 3;   // Riyadh, UTC+3, no daylight saving
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const cnOf = (dn) => { const m = /^CN=((?:[^,\\]|\\.)+)/i.exec(dn || ''); return m ? m[1] : dn; };

function createOffboarding(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const col = () => store.collection('offboarding');
  const iso = () => new Date(now()).toISOString();
  const today = () => new Date(now() + TZ * 3600000).toISOString().slice(0, 10);
  const AD = () => opts.ad || (app.addons && app.addons.onboarding && app.addons.onboarding.ad) || null;
  const auto = () => { const a = AD(); return !!(a && a.leaversEnabled()); };
  const SYSTEM = { user: 'system:offboarding-ad', role: 'system', ip: '' };
  const LSYS = { user: 'system:m365-licensing', role: 'system', ip: '' };
  const RDONE = ['reclaimed', 'not_needed', 'kept', 'reclaimed_manually', 'cancelled'];
  const MDONE = ['converted', 'converted_manually', 'not_needed', 'kept', 'cancelled'];
  const EXM = loadExo(app);
  const EXO = opts.exo || (EXM ? EXM.createExo(app, { now, run: opts.exoRun }) : exoMissing());
  const MSYS = { user: 'system:exchange-online', role: 'system', ip: '' };
  const FDONE = ['removed', 'removed_manually', 'not_needed', 'kept', 'cancelled'];
  const FWATCH_DAYS = 30;
  const ODONE = ['granted', 'granted_manually', 'not_needed', 'declined', 'ended', 'cancelled'];
  const ONEDRIVE = /^https:\/\/[a-z0-9-]{1,63}-my\.sharepoint\.com\/personal\/[A-Za-z0-9_]{1,200}\/?$/;
  const spoOn = () => !!(EXO.spoEnabled && EXO.spoEnabled());
  const odDays = () => (EXO.onedriveDays ? EXO.onedriveDays() : 60);
  const OSYS = { user: 'system:sharepoint-online', role: 'system', ip: '' };
  const AFINAL = ['removed', 'no_access', 'confirmed', 'no_account', 'kept', 'not_applicable'];
  const appsReg = () => store.collection('offboarding_apps');
  const activeApps = () => appsReg().all((a) => a.active !== false);
  const appsGraph = () => { const L = LIC(); return !!(L && L.appsEnabled && L.appsEnabled()); };
  const ASYS = { user: 'system:app-access', role: 'system', ip: '' };
  const DFINAL = ['wiped', 'retired', 'kept', 'gone', 'manual'];
  // the MDM (ManageEngine now, Intune later - engine/mdm.js); loaded like exo.js so a file the update missed never stops sentra-itam
  const MDM = opts.mdm || (() => { try { return require('./mdm').createMdm(app, { now, request: opts.mdmRequest }); } catch (e) { if (e.code === 'MODULE_NOT_FOUND' && String(e.message).split('\n')[0].indexOf("'./mdm'") >= 0) { warn('mdm-missing', 'offboarding: engine/mdm.js is not installed - the device step is off until the update is re-run', {}); return null; } throw e; } })();
  const DEV = () => (MDM ? MDM.adapter() : null);
  const devOn = () => !!DEV();
  const DEVID = /^(\d{1,20}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
  const legalActive = (r) => !!(r.legal && !['released', 'rejected'].includes(r.legal.status));
  const DSYS = { user: 'system:intune', role: 'system', ip: '' };
  const LWORK = ['approved', 'holding', 'estimating', 'exporting', 'releasing'];
  const legalOn = () => { const L = LIC(); return !!(L && L.legalEnabled && L.legalEnabled()); };
  const legalPending = (r) => !!(r.legal && ['requested', 'approved', 'holding'].includes(r.legal.status));
  // done = the hold is in place (and the export finished, when one was asked for), or it was rejected / released
  const legalDone = (l) => ['released', 'rejected', 'releasing', 'exported'].includes(l.status) || (l.status === 'held' && !l.export) || (l.status === 'release_requested' && !!l.release && legalDone({ status: l.release.from, export: l.export }));
  const PSYS = { user: 'system:purview-ediscovery', role: 'system', ip: '' };
  const CDONE = ['transferred', 'transferred_manually', 'not_needed', 'kept', 'cancelled'];
  const CSYS = { user: 'system:microsoft-graph', role: 'system', ip: '' };
  const calOn = () => { const L = LIC(); return !!(L && L.calendarEnabled && L.calendarEnabled()); };
  const escH = (x) => String(x == null ? '' : x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const TDONE = ['transferred', 'transferred_manually', 'not_needed', 'kept', 'cancelled'];
  const GSYS = { user: 'system:microsoft-graph', role: 'system', ip: '' };
  const teamsOn = () => { const L = LIC(); return !!(L && L.teamsEnabled && L.teamsEnabled()); };
  const ADDR = /^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;
  const LIC = () => opts.lic || (app.addons && app.addons.onboarding && app.addons.onboarding.lic) || null;
  const reclaimOn = () => { const L = LIC(); return !!(L && L.reclaimEnabled()); };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('offboarding:' + key, 3600000, 'warn', msg, detail); };
  const person = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const notLeaver = (r, who, what) => { if (same(r.username, who.user)) throw httpErr(403, 'the leaver cannot ' + what + ' on their own request'); };
  const hist = (r, who, step, detail) => { r.history = (r.history || []).concat([{ at: iso(), by: who.user, role: who.role, step, detail: detail || null }]).slice(-200); };
  const get = (id) => { const k = param(id); if (!/^OFF-\d{3,6}$/.test(k)) throw httpErr(400, 'id must be an offboarding request (OFF-nnn)'); const r = col().get(k); if (!r) throw httpErr(404, 'no offboarding request ' + k); return r; };
  const open = (r) => !['completed', 'cancelled'].includes(r.status);
  const assetsAll = () => (app.assets && typeof app.assets.all === 'function' ? app.assets.all() : store.collection('assets').all());
  const held = (r) => assetsAll().filter((a) => a.status !== 'disposed' && a.status !== 'retired' && (same(a.custodian, r.username) || same(a.custodian, r.name) || same(a.assigned_to, r.username)))
    .map((a) => ({ id: a.id, asset_tag: a.asset_tag || null, name: a.name || null, type: a.type || null, model: [a.vendor, a.model].filter(Boolean).join(' ') || null, serial: a.serial || null, status: a.status }));
  const hour = () => { const a = AD(); const v = a ? a.view().disable_hour : 18; return Number.isInteger(v) ? v : 18; };
  // the last day at the configured hour, Riyadh time, as an instant
  const dueAt = (r) => (r.immediate ? r.disable.approved_at : new Date(Date.parse(r.last_day + 'T00:00:00Z') + (hour() - TZ) * 3600000).toISOString());

  function steps(r) {
    return [
      { key: 'confirm', name: 'Manager confirmed the leaving', done: !!(r.confirm && r.confirm.decision === 'confirm'), by: r.confirm && r.confirm.by },
      { key: 'approve', name: 'Disable approved (four eyes)', done: !!(r.disable && r.disable.approved_by), by: r.disable && r.disable.approved_by },
      { key: 'disabled', name: 'Account disabled in the directory', done: !!(r.disabled && r.disabled.at), by: r.disabled && r.disabled.by },
    ].concat(r.forwarding ? [{ key: 'forwarding', name: 'Mail forwarding removed', done: FDONE.includes(r.forwarding.status), by: r.forwarding.decided_by || r.forwarding.by || null }] : []).concat([
      { key: 'equipment', name: 'Equipment returned', done: !!r.equipment, by: r.equipment && r.equipment.by },
    ]).concat(r.mailbox ? [{ key: 'mailbox', name: 'Mailbox converted to shared', done: MDONE.includes(r.mailbox.status), by: r.mailbox.decided_by || r.mailbox.by || null }] : [])
     .concat(r.apps ? [{ key: 'apps', name: 'Business application access removed', done: ['done', 'kept', 'not_needed', 'cancelled'].includes(r.apps.status), by: r.apps.decided_by || null }] : [])
     .concat(r.devices ? [{ key: 'devices', name: 'Devices wiped or retired', done: ['done', 'not_needed', 'cancelled'].includes(r.devices.status), by: r.devices.decided_by || null }] : [])
     .concat(r.legal ? [{ key: 'legal', name: 'Legal hold in place', done: legalDone(r.legal), by: r.legal.decided_by || null }] : [])
     .concat(r.calendar ? [{ key: 'calendar', name: 'Meetings handed over', done: CDONE.includes(r.calendar.status), by: r.calendar.decided_by || r.calendar.by || null }] : [])
     .concat(r.teams ? [{ key: 'teams', name: 'Groups and Teams handed over', done: TDONE.includes(r.teams.status), by: r.teams.decided_by || r.teams.by || null }] : [])
     .concat(r.onedrive ? [{ key: 'onedrive', name: 'OneDrive handed over', done: ODONE.includes(r.onedrive.status), by: r.onedrive.decided_by || r.onedrive.by || null }] : [])
     .concat(r.reclaim ? [{ key: 'licences', name: 'Microsoft 365 licences reclaimed', done: RDONE.includes(r.reclaim.status), by: r.reclaim.decided_by || r.reclaim.by || null }] : []);
  }
  function view(r, full) {
    const st = steps(r), left = st.filter((s) => !s.done);
    const out = Object.assign({}, r, { steps: st, next: open(r) && left.length ? left[0].key : null,
      due_at: r.disable && r.disable.approved_by && !(r.disabled && r.disabled.at) ? dueAt(r) : null,
      overdue: open(r) && !(r.disabled && r.disabled.at) && r.last_day < today() });
    if (full) {
      out.assets = held(r);
      const h = store.collection('handovers').all((x) => same(x.leaver, r.username) && x.status !== 'cancelled')[0];
      out.it_handover = h ? { id: h.id, status: h.status } : null;
    }
    return out;
  }
  function maybeComplete(r, who) {
    if (r.status === 'cancelled' || r.status === 'completed') return;   // a step added later (a legal hold) never completes it twice
    if (steps(r).every((s) => s.done)) { r.status = 'completed'; r.completed_at = iso(); hist(r, who, 'completed'); audit(who, 'offboarding.complete', r.id, { username: r.username }); }
  }

  function list() {
    const items = col().all(() => true).map((x) => view(x)).sort((a, b) => (open(a) === open(b) ? String(a.last_day).localeCompare(String(b.last_day)) : open(a) ? -1 : 1));
    const o = items.filter(open);
    const od = (x) => x.onedrive || {};
    const tm = (x) => x.teams || {};
    const cl = (x) => x.calendar || {};
    const lg = (x) => x.legal || {};
    const dv = (x) => (x.devices && x.devices.devices) || [];
    const ap = (x) => (x.apps && x.apps.items) || [];
    return { items, counts: { apps_waiting: o.filter((x) => x.apps && x.apps.status === 'proposed').length, apps_owner_tasks: items.reduce((n, x) => n + ap(x).filter((i) => i.state === 'owner_task').length, 0),
      apps_overdue: items.reduce((n, x) => n + ap(x).filter((i) => i.state === 'owner_task' && i.due_at && Date.parse(i.due_at) < now()).length, 0), apps_failed: items.reduce((n, x) => n + ap(x).filter((i) => i.state === 'error').length, 0), devices_waiting: o.filter((x) => dv(x).some((d) => d.state === 'proposed')).length, devices_pending: items.reduce((n, x) => n + dv(x).filter((d) => d.state === 'sent').length, 0),
      devices_failed: items.reduce((n, x) => n + dv(x).filter((d) => d.state === 'error' || d.state === 'failed').length, 0), legal_waiting: items.filter((x) => ['requested', 'release_requested'].includes(lg(x).status)).length, legal_active: items.filter((x) => ['held', 'estimating', 'exporting', 'exported', 'release_requested'].includes(lg(x).status)).length,
      legal_failed: items.filter((x) => lg(x).error).length, calendar_waiting: o.filter((x) => cl(x).status === 'proposed').length, calendar_failed: o.filter((x) => cl(x).error && !CDONE.includes(cl(x).status)).length,
      calendar_meetings: o.filter((x) => ['proposed', 'approved'].includes(cl(x).status)).reduce((n, x) => n + (cl(x).meetings || []).length, 0), teams_waiting: o.filter((x) => tm(x).status === 'proposed').length, teams_failed: o.filter((x) => tm(x).error && !TDONE.includes(tm(x).status)).length,
      teams_sole: o.filter((x) => !TDONE.includes(tm(x).status)).reduce((n, x) => n + (tm(x).groups || []).filter((g) => g.sole).length, 0), onedrive_waiting: o.filter((x) => od(x).status === 'proposed').length, onedrive_failed: items.filter((x) => od(x).error && !ODONE.includes(od(x).status) || od(x).end_error).length,
      onedrive_active: items.filter((x) => od(x).status === 'granted').length, onedrive_ending: items.filter((x) => od(x).status === 'granted' && od(x).access_until && Date.parse(od(x).access_until) - now() <= 7 * DAY).length, forwarding_waiting: o.filter((x) => x.forwarding && x.forwarding.status === 'proposed').length, forwarding_failed: o.filter((x) => x.forwarding && x.forwarding.error && !FDONE.includes(x.forwarding.status)).length,
      forwarding_external: items.filter((x) => x.forwarding && (x.forwarding.items || []).some((i) => i.external && i.active)).length, mailbox_waiting: o.filter((x) => x.mailbox && x.mailbox.status === 'proposed').length, mailbox_failed: o.filter((x) => x.mailbox && x.mailbox.error && !MDONE.includes(x.mailbox.status)).length, reclaim_waiting: o.filter((x) => x.reclaim && x.reclaim.status === 'proposed').length, reclaim_failed: o.filter((x) => x.reclaim && x.reclaim.error && !RDONE.includes(x.reclaim.status)).length, open: o.length, waiting_manager: o.filter((x) => x.next === 'confirm').length, waiting_approval: o.filter((x) => x.next === 'approve').length,
      scheduled: o.filter((x) => x.next === 'disabled' && !(x.disabled && x.disabled.error)).length, failed: o.filter((x) => x.disabled && x.disabled.error && !x.disabled.at).length,
      overdue: o.filter((x) => x.overdue).length, completed: items.filter((x) => x.status === 'completed').length },
    reasons: REASONS, directory: { automatic: auto(), disable_hour: hour() }, reclaim: { automatic: reclaimOn(), hold_days: reclaimOn() ? LIC().holdDays() : null }, mailbox: { automatic: EXO.enabled() }, forwarding: { automatic: EXO.enabled(), watch_days: FWATCH_DAYS }, onedrive: { automatic: spoOn(), days: odDays() }, teams: { automatic: teamsOn() }, legal: { available: legalOn() }, apps: { register: activeApps().length, graph: appsGraph() }, devices: { automatic: devOn(), provider: devOn() ? DEV().name : null }, calendar: { automatic: calOn(), days: calOn() ? LIC().calendarDays() : null } };
  }

  // what the directory says about the account, and why the platform would refuse to disable it
  async function lookup(r) {
    if (!auto()) return { read: false, reason: 'automatic disabling is off - Directory settings' };
    const A = AD(), c = A.cfg();
    let u;
    try { u = await A.writer().findUser(r.username); }
    catch (e) { warn('lookup', 'offboarding: the directory could not be read', { id: r.id, err: String(e.message).slice(0, 160) }); return { read: false, reason: 'the directory did not answer: ' + String(e.message).slice(0, 160), at: iso() }; }
    if (!u) return { read: true, found: false, at: iso(), blockers: ['no account ' + r.username + ' in the directory'] };
    const blockers = [];
    if (u.employee_id && !same(u.employee_id, r.employee_id)) blockers.push('the directory account ' + r.username + ' belongs to employee ' + u.employee_id + ', not ' + r.employee_id + ' - check the user name');
    const priv = u.member_of.map(cnOf).filter((g) => PRIVILEGED.test(g));
    if (priv.length || u.admin_count) blockers.push('privileged account (' + (priv.join(', ') || 'adminCount') + ') - a domain administrator disables it by hand');
    if ((c.never_disable || []).some((x) => same(x, u.sam))) blockers.push(u.sam + ' is on the never-disable list');
    if (same(u.dn, c.bind_dn)) blockers.push('this is the platform\'s own directory service account');
    return { read: true, found: true, at: iso(), dn: u.dn, upn: u.upn, display_name: u.display_name, employee_id: u.employee_id || null, enabled: u.enabled,
      groups: u.member_of.map(cnOf).slice(0, 100), last_logon: u.last_logon, blockers };
  }

  // several leavers at once (a pasted list, e.g. the end of a project): each row is a normal leaver request - same validation,
  // the same four-eyes approval before anything is disabled; an error per row
  async function bulk(input, who) {
    person(who, 'raise leaver requests');
    if (!input || !Array.isArray(input.rows) || !input.rows.length || input.rows.length > 100) throw httpErr(400, 'rows: 1 - 100 leavers');
    const out = { created: [], failed: [] };
    for (let i = 0; i < input.rows.length; i++) { const r = input.rows[i];
      try { const v = await create(r, who); out.created.push({ row: i + 1, id: v.id || (v.request && v.request.id), name: r && r.name }); }
      catch (e) { out.failed.push({ row: i + 1, name: r && typeof r.name === 'string' ? r.name.slice(0, 120) : '', error: 'rows[' + i + ']: ' + String(e.message).slice(0, 200) }); } }
    audit(who, 'offboarding.bulk', 'offboarding', { created: out.created.length, failed: out.failed.length });
    return out;
  }
  async function create(input, who) {
    person(who, 'raise a leaver request');
    { const DEP = app.addons && app.addons.departments, dn = input && input.department;   // the department register, once saved
      if (DEP && typeof dn === 'string' && dn.trim()) { const d = DEP.find(dn); if (d && d.active !== false) input = Object.assign({}, input, { department: d.name }); else if (DEP.enforced()) throw httpErr(400, 'department: "' + dn.slice(0, 80) + '" is not in the department register (Departments) - pick one of it'); } }
    const b = body(input || {}).str('name', { required: true, max: 120, min: 3 }).str('employee_id', { required: true, max: 20, re: /^[A-Za-z0-9-]{1,20}$/, msg: 'employee_id must be the HR employee number (letters, digits, -)' })
      .str('username', { required: true, max: 20, re: SAM, msg: 'username must be the Active Directory user name (sAMAccountName), e.g. sara.ghamdi' })
      .str('department', { required: true, max: 120 }).date('last_day', { required: true }).str('manager', Object.assign({ required: true }, USER))
      .oneOf('reason', REASONS, { required: true }).bool('immediate', { def: false }).str('note', { max: 1000 })
      .rule((o) => (o.last_day < new Date(now() - 30 * DAY).toISOString().slice(0, 10) ? 'last_day is more than 30 days ago - disable it by hand and record why' : null)).done();
    if (SECRETISH.test(b.note || '')) throw httpErr(400, 'note looks like it contains a password - the platform never holds one');
    if (same(b.username, who.user)) throw httpErr(403, 'you cannot raise a leaver request for your own account');
    if (same(b.manager, b.username)) throw httpErr(400, 'manager cannot be the leaver');
    if (col().all((r) => open(r) && (same(r.username, b.username) || same(r.employee_id, b.employee_id))).length) throw httpErr(409, 'an open leaver request already exists for ' + b.username + ' / ' + b.employee_id);
    const n = col().all(() => true).length + 1, id = 'OFF-' + String(n).padStart(3, '0');
    const r = Object.assign({ id }, b, { username: b.username.toLowerCase(), status: 'requested', requested_by: who.user, requested_at: iso(), history: [] });
    r.directory = await lookup(r);
    hist(r, who, 'requested', { found: r.directory.found === undefined ? null : r.directory.found });
    col().put(r);
    audit(who, 'offboarding.request', id, { username: r.username, department: b.department, last_day: b.last_day, reason: b.reason, immediate: b.immediate, manager: b.manager });
    return view(r, true);
  }
  async function relook(id, who) {
    const r = get(id); person(who, 'read the directory'); notLeaver(r, who, 'act');
    if (!open(r)) throw httpErr(409, r.id + ' is ' + r.status);
    r.directory = await lookup(r); col().put(r);
    return view(r, true);
  }

  function confirm(id, input, who) {
    const r = get(id); person(who, 'confirm a leaver'); notLeaver(r, who, 'confirm');
    const b = body(input || {}).oneOf('decision', ['confirm', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why' : null)).done();
    if (r.status !== 'requested') throw httpErr(409, r.id + ' is ' + r.status + ' - only a new request is confirmed');
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also confirm it');
    if (!(same(r.manager, who.user) || who.role === 'admin')) throw httpErr(403, 'confirming needs the named manager (' + r.manager + ') or an administrator');
    r.confirm = { decision: b.decision, by: who.user, at: iso(), note: b.note || '' };
    if (b.decision === 'reject') { r.status = 'cancelled'; r.cancel = { by: who.user, at: iso(), reason: 'not confirmed: ' + b.note }; }
    else r.status = 'in_progress';
    hist(r, who, 'confirm', { decision: b.decision }); col().put(r);
    audit(who, 'offboarding.confirm', r.id, { decision: b.decision, username: r.username });
    return view(r, true);
  }

  async function approve(id, input, who) {
    const r = get(id); person(who, 'approve disabling an account'); notLeaver(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .oneOf('forwarding', ['remove', 'remove_external', 'ask'], { def: 'remove' })
      .oneOf('onedrive', ['manager', 'ask', 'none'], { def: 'manager' }).num('onedrive_days', { min: 7, max: 365 }).oneOf('teams', ['transfer', 'add', 'ask', 'none'], { def: 'transfer' }).oneOf('calendar', ['transfer', 'cancel', 'ask', 'none'], { def: 'transfer' }).oneOf('apps', ['remove', 'ask'], { def: 'remove' })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why' : null))
      .rule((o) => (o.onedrive_days !== undefined && !Number.isInteger(o.onedrive_days) ? 'onedrive_days must be a whole number of days' : null)).done();
    if (r.status !== 'in_progress') throw httpErr(409, r.id + ' is ' + r.status + ' - the leaving must be confirmed first');
    if (r.disable && r.disable.approved_by) throw httpErr(409, 'already approved by ' + r.disable.approved_by);
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also approve the disable');
    if (r.confirm && same(r.confirm.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' confirmed the leaving; a different administrator approves the disable');
    if (b.decision === 'reject') {
      r.disable = { rejected_by: who.user, rejected_at: iso(), note: b.note };
      hist(r, who, 'disable_reject', { note: b.note }); col().put(r);
      audit(who, 'offboarding.disable.reject', r.id, { username: r.username, note: b.note });
      return view(r, true);
    }
    if (auto()) {
      r.directory = await lookup(r);
      if (!r.directory.read) throw httpErr(409, 'cannot approve without reading the account: ' + r.directory.reason);
      if (r.directory.blockers.length) throw httpErr(409, 'the platform will not disable this account automatically: ' + r.directory.blockers.join('; ') + ' - disable it by hand and record it');
    }
    // the forwarding decision is part of this approval only when the platform can carry it out (Exchange Online set up)
    r.disable = { approved_by: who.user, approved_at: iso(), note: b.note || '', mode: auto() ? 'automatic' : 'manual', forwarding: EXO.enabled() ? b.forwarding : null,
      apps: activeApps().length ? b.apps : null, teams: teamsOn() ? b.teams : null, calendar: calOn() ? b.calendar : null, onedrive: spoOn() ? b.onedrive : null, onedrive_days: spoOn() && b.onedrive === 'manager' ? (b.onedrive_days || odDays()) : null };
    hist(r, who, 'disable_approve', { due_at: dueAt(r), mode: r.disable.mode, forwarding: r.disable.forwarding, onedrive: r.disable.onedrive, teams: r.disable.teams, calendar: r.disable.calendar, apps: r.disable.apps }); col().put(r);
    audit(who, 'offboarding.disable.approve', r.id, { username: r.username, dn: r.directory && r.directory.dn || null, due_at: dueAt(r), mode: r.disable.mode, forwarding: r.disable.forwarding, onedrive: r.disable.onedrive, onedrive_days: r.disable.onedrive_days, teams: r.disable.teams, calendar: r.disable.calendar, apps: r.disable.apps, requested_by: r.requested_by, confirmed_by: r.confirm.by });
    if (auto() && Date.parse(dueAt(r)) <= now()) await disableNow(r);
    return view(get(r.id), true);
  }

  // the disable itself, under the platform's own name; the approvals above are the people's
  async function disableNow(r) {
    const A = AD(), c = A.cfg();
    try {
      const d = await lookup(r);
      if (!d.read) throw new Error(d.reason);
      if (d.blockers.length) throw new Error(d.blockers.join('; '));
      const W = A.writer();
      if (d.enabled) await W.setEnabled(d.dn, false);
      if (c.scramble_password !== false) await W.resetPassword(d.dn, tempPassword());   // a password nobody knows; the value is dropped here
      await W.describe(d.dn, ('Disabled by ' + ZYB_ORG.short + ' offboarding ') + r.id + ' on ' + iso().slice(0, 10) + ' (approved by ' + r.disable.approved_by + ')');
      let dn = d.dn;
      if (c.leavers_ou && !norm(dn).endsWith(',' + norm(c.leavers_ou))) dn = await W.move(dn, c.leavers_ou);
      const v = await W.read(dn);
      if (!v || v.enabled) throw new Error('read back: the account is still enabled');
      r.disabled = { at: iso(), by: SYSTEM.user, dn, was_enabled: d.enabled, moved: dn !== d.dn, password_replaced: c.scramble_password !== false, groups_kept: d.groups, verified: true, error: null };
      hist(r, SYSTEM, 'disabled', { dn, moved: dn !== d.dn });
      audit(SYSTEM, 'offboarding.disabled', r.id, { username: r.username, dn, from: d.dn, was_enabled: d.enabled, password_replaced: r.disabled.password_replaced, approved_by: r.disable.approved_by });
      await startForwarding(r);
      await startMailbox(r);
      await startOneDrive(r);
      await startTeams(r);
      await startCalendar(r);
      await startDevices(r);
      await startApps(r);
      await startReclaim(r);
      maybeComplete(r, SYSTEM);
    } catch (e) {
      const msg = String(e.message).slice(0, 300);
      r.disabled = Object.assign({}, r.disabled || {}, { error: msg, failed_at: iso(), attempts: ((r.disabled && r.disabled.attempts) || 0) + 1 });
      hist(r, SYSTEM, 'disable_failed', { error: msg });
      audit(SYSTEM, 'offboarding.disable.failed', r.id, { username: r.username, error: msg });
      warn('disable', 'offboarding: the account could not be disabled', { id: r.id, err: msg });
    }
    col().put(r);
    return r;
  }
  // due approved requests; a failure is retried by the job at most every hour, three times, then waits for a person
  // ---- licence reclaim: proposed by the platform after the disable, approved by a person, carried out after the hold
  const upnOf = (r) => (r.directory && r.directory.upn) || (AD() && AD().cfg().upn_suffix ? r.username + '@' + AD().cfg().upn_suffix : null);
  async function readLicences(r) {
    const upn = upnOf(r);
    if (!upn) return { status: 'read_failed', error: 'the sign-in name (UPN) is not known - set the UPN suffix in Directory settings' };
    try {
      const u = await LIC().readUser(upn);
      if (!u.found) return { status: 'not_needed', upn, note: upn + ' is not in Entra ID - no licence to reclaim' };
      if (!u.licences.length) return { status: 'not_needed', upn, entra_id: u.entra_id, note: 'no licence assigned' };
      return { status: 'proposed', upn, entra_id: u.entra_id, licences: u.licences, read_at: iso() };
    } catch (e) {
      warn('reclaim-read', 'offboarding: licences could not be read', { id: r.id, err: String(e.message).slice(0, 160) });
      return { status: 'read_failed', upn, error: String(e.message).slice(0, 240) };
    }
  }
  async function startReclaim(r) {
    if (r.reclaim || !reclaimOn()) return;
    const x = await readLicences(r);
    const base = r.disabled && r.disabled.at ? Date.parse(r.disabled.at) : now();
    r.reclaim = Object.assign(x, { proposed_at: iso(), due_at: new Date(base + LIC().holdDays() * DAY).toISOString(), hold_days: LIC().holdDays() });
    hist(r, LSYS, 'reclaim_' + r.reclaim.status, { licences: (x.licences || []).map((l) => l.name) });
    audit(LSYS, 'offboarding.reclaim.' + r.reclaim.status, r.id, { upn: x.upn || null, licences: (x.licences || []).map((l) => l.name), due_at: r.reclaim.due_at, error: x.error || null });
  }
  async function refreshReclaim(id, who) {
    const r = get(id); person(who, 'read licences'); notLeaver(r, who, 'act');
    if (!reclaimOn()) throw httpErr(409, 'licence reclaim is off - Microsoft 365 licensing settings');
    if (!(r.disabled && r.disabled.at)) throw httpErr(409, 'the account is not disabled yet');
    if (r.reclaim && !['proposed', 'read_failed', 'not_needed'].includes(r.reclaim.status)) throw httpErr(409, 'the reclaim is already ' + r.reclaim.status);
    const prev = r.reclaim; r.reclaim = null; await startReclaim(r);
    if (prev && prev.due_at) Object.assign(r.reclaim, { due_at: prev.due_at, proposed_at: prev.proposed_at });
    maybeComplete(r, who); col().put(r);
    return view(r, true);
  }
  async function decideReclaim(id, input, who) {
    const r = get(id); person(who, 'approve a licence reclaim'); notLeaver(r, who, 'approve');
    if (legalPending(r)) throw httpErr(409, 'a legal hold is being put in place for ' + r.id + ' - the licences stay until it is applied');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).list('remove', { max: 30, item: 'str', itemMax: 36, unique: true })
      .str('keep_reason', { max: 300 }).oneOf('mailbox', ['converted_to_shared', 'on_hold', 'not_needed']).bool('now', { def: false }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the licences stay' : null)).done();
    const q = r.reclaim; if (!q || q.status !== 'proposed') throw httpErr(409, 'no licence reclaim is waiting for ' + r.id + (q ? ' (it is ' + q.status + ')' : ''));
    if (b.decision === 'approve') {
      const mb = r.mailbox, verified = mb && ['converted', 'converted_manually'].includes(mb.status);
      if (!b.mailbox && verified) b.mailbox = 'converted_to_shared';
      if (!b.mailbox) throw httpErr(400, 'mailbox is required: confirm the mailbox was converted to a shared mailbox, put on hold, or is not needed');
      if (b.mailbox === 'converted_to_shared' && mb && !verified && mb.status !== 'not_needed') throw httpErr(409, 'the mailbox has not been converted yet - approve the Mailbox step first (or choose "on hold" / "not needed")');
    }
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also approve taking the licences back');
    if (r.status === 'cancelled') throw httpErr(409, r.id + ' is cancelled');
    if (b.decision === 'reject') {
      Object.assign(q, { status: 'kept', decided_by: who.user, decided_at: iso(), note: b.note });
      hist(r, who, 'reclaim_kept', { note: b.note }); maybeComplete(r, who); col().put(r);
      audit(who, 'offboarding.reclaim.kept', r.id, { licences: q.licences.map((l) => l.name), note: b.note });
      return view(r, true);
    }
    const all = q.licences.map((l) => l.sku_id), remove = b.remove ? b.remove : all;
    const unknown = remove.filter((x) => !all.includes(x)); if (unknown.length) throw httpErr(400, 'remove: ' + unknown.join(', ') + ' is not a licence of this user');
    if (!remove.length) throw httpErr(400, 'remove: choose at least one licence (or reject to keep them all)');
    const kept = q.licences.filter((l) => !remove.includes(l.sku_id));
    if (kept.length && !(b.keep_reason && b.keep_reason.length >= 5)) throw httpErr(400, 'keep_reason is required: say why ' + kept.map((l) => l.name).join(', ') + ' stays');
    Object.assign(q, { status: 'approved', decided_by: who.user, decided_at: iso(), remove, kept: kept.map((l) => l.name), keep_reason: b.keep_reason || '', mailbox: b.mailbox, note: b.note || '' });
    if (b.now) q.due_at = iso();
    hist(r, who, 'reclaim_approved', { remove: remove.length, kept: kept.length, mailbox: b.mailbox, due_at: q.due_at }); col().put(r);
    audit(who, 'offboarding.reclaim.approved', r.id, { remove: q.licences.filter((l) => remove.includes(l.sku_id)).map((l) => l.name), kept: q.kept, mailbox: b.mailbox, due_at: q.due_at });
    if (Date.parse(q.due_at) <= now()) await doReclaim(r);
    return view(get(r.id), true);
  }
  async function doReclaim(r) {
    const q = r.reclaim;
    if (legalPending(r)) { q.waiting = 'a legal hold is being put in place'; col().put(r); return r; }   // licences stay until Purview says the hold is applied
    q.waiting = null;
    try {
      await LIC().removeLicences(q.entra_id, q.remove);
      Object.assign(q, { status: 'reclaimed', reclaimed_at: iso(), error: null, freed: q.licences.filter((l) => q.remove.includes(l.sku_id)).map((l) => l.name) });
      hist(r, LSYS, 'reclaimed', { freed: q.freed });
      audit(LSYS, 'offboarding.reclaim.done', r.id, { upn: q.upn, freed: q.freed, approved_by: q.decided_by });
      maybeComplete(r, LSYS);
    } catch (e) {
      Object.assign(q, { error: String(e.message).slice(0, 240), failed_at: iso(), attempts: (q.attempts || 0) + 1 });
      hist(r, LSYS, 'reclaim_failed', { error: q.error });
      if (q.attempts === 1) audit(LSYS, 'offboarding.reclaim.failed', r.id, { error: q.error });
      warn('reclaim', 'offboarding: licences could not be removed', { id: r.id, err: q.error });
    }
    col().put(r);
    return r;
  }
  function manualReclaim(id, input, who) {
    const r = get(id); person(who, 'record a licence reclaim'); notLeaver(r, who, 'record');
    const b = body(input || {}).str('reference', { required: true, min: 3, max: 200 }).done();
    if (SECRETISH.test(b.reference)) throw httpErr(400, 'reference looks like it contains a password');
    if (!r.reclaim || RDONE.includes(r.reclaim.status)) throw httpErr(409, 'no licence reclaim is open for ' + r.id);
    if (r.reclaim.status === 'proposed') throw httpErr(409, 'the reclaim must be approved first');
    Object.assign(r.reclaim, { status: 'reclaimed_manually', by: who.user, at: iso(), reference: b.reference, error: null });
    hist(r, who, 'reclaim_manual', { reference: b.reference }); maybeComplete(r, who); col().put(r);
    audit(who, 'offboarding.reclaim.manual', r.id, { reference: b.reference });
    return view(r, true);
  }
  // ---- mailbox to shared: proposed after the disable, approved by a person, done through Exchange Online and read back
  const upnOfM = (r) => (r.directory && r.directory.upn) || (AD() && AD().cfg().upn_suffix ? r.username + '@' + AD().cfg().upn_suffix : null);
  const managerAddr = (r) => (AD() && AD().cfg().upn_suffix && /^[A-Za-z0-9._-]{1,64}$/.test(r.manager) ? r.manager.toLowerCase() + '@' + AD().cfg().upn_suffix : null);
  async function readMailbox(r) {
    const upn = upnOfM(r);
    if (!upn) return { status: 'read_failed', error: 'the mailbox address (UPN) is not known - set the UPN suffix in Directory settings' };
    const x = await EXO.run('get-mailbox', { identity: upn });
    if (!x.ok) { warn('mbx-read', 'offboarding: the mailbox could not be read', { id: r.id, err: String(x.error).slice(0, 160) }); return { status: 'read_failed', upn, error: String(x.error).slice(0, 240) }; }
    const d = x.data || {};
    if (!d.found) return d.recipient_type && /remote|mailuser/i.test(d.recipient_type) ? { status: 'on_premises', upn, note: 'the mailbox is on the on-premises Exchange (' + d.recipient_type + ') - an Exchange administrator converts it there (Set-RemoteMailbox / Set-Mailbox -Type Shared) and records it' } : { status: 'not_needed', upn, note: 'no mailbox in Exchange Online' };
    if (/shared/i.test(d.type)) return { status: 'not_needed', upn, type: d.type, note: 'already a shared mailbox' };
    const warnings = [];
    if (d.litigation_hold) warnings.push('the mailbox is on litigation hold: a shared mailbox on hold still needs an Exchange Online Plan 2 licence - keep one');
    if (d.archive && !/none/i.test(d.archive)) warnings.push('the mailbox has an archive: a shared mailbox with an archive still needs a licence - keep one');
    const mgr = managerAddr(r);
    return { status: 'proposed', upn, type: d.type, litigation_hold: !!d.litigation_hold, archive: d.archive || '', forwarding: d.forwarding || '', warnings, delegates: mgr ? [mgr] : [],
      auto_reply: EXO.template().replace('{name}', r.name).replace('{delegate}', mgr || 'your contact'), read_at: iso() };
  }
  async function startMailbox(r) {
    if (r.mailbox || !EXO.enabled()) return;
    r.mailbox = Object.assign(await readMailbox(r), { proposed_at: iso() });
    hist(r, MSYS, 'mailbox_' + r.mailbox.status, { type: r.mailbox.type || null });
    audit(MSYS, 'offboarding.mailbox.' + r.mailbox.status, r.id, { upn: r.mailbox.upn || null, type: r.mailbox.type || null, warnings: r.mailbox.warnings || [], error: r.mailbox.error || null });
  }
  async function convertNow(r) {
    const m = r.mailbox, steps = m.steps || [];
    const did = (k) => steps.some((x) => x.step === k && x.ok);
    const add = (step, x, extra) => { steps.push(Object.assign({ step, ok: !!x.ok, at: iso() }, x.ok ? {} : { error: String(x.error || '').slice(0, 200) }, extra || {})); return x.ok; };
    try {
      if (!did('convert')) { const x = await EXO.run('convert-shared', { identity: m.upn }); if (!add('convert', x.ok && /shared/i.test((x.data || {}).type) ? x : { ok: false, error: x.ok ? 'read back: still ' + (x.data || {}).type : x.error })) throw new Error(steps[steps.length - 1].error); }
      for (const d of m.delegates || []) if (!did('access:' + d)) { const x = await EXO.run('add-fullaccess', { identity: m.upn, user: d }); add('access:' + d, x.ok && (x.data || {}).granted ? x : { ok: false, error: x.ok ? 'read back: no Full Access for ' + d : x.error }); }
      if (m.auto_reply && !did('autoreply')) add('autoreply', await EXO.run('set-autoreply', { identity: m.upn, message: m.auto_reply }));
      const failed = steps.filter((x) => !x.ok && !steps.some((y) => y.ok && y.step === x.step));
      m.steps = steps;
      if (failed.length) throw new Error('partly done - ' + failed.map((x) => x.step + ': ' + x.error).join('; '));
      Object.assign(m, { status: 'converted', converted_at: iso(), error: null });
      hist(r, MSYS, 'mailbox_converted', { delegates: m.delegates });
      audit(MSYS, 'offboarding.mailbox.converted', r.id, { upn: m.upn, delegates: m.delegates, auto_reply: !!m.auto_reply, approved_by: m.decided_by });
      maybeComplete(r, MSYS);
    } catch (e) {
      m.steps = steps;
      Object.assign(m, { error: String(e.message).slice(0, 300), failed_at: iso(), attempts: (m.attempts || 0) + 1 });
      hist(r, MSYS, 'mailbox_failed', { error: m.error });
      if (m.attempts === 1) audit(MSYS, 'offboarding.mailbox.failed', r.id, { upn: m.upn, error: m.error });
      warn('mbx', 'offboarding: the mailbox conversion did not complete', { id: r.id, err: m.error });
    }
    col().put(r);
    return r;
  }
  async function decideMailbox(id, input, who) {
    const r = get(id); person(who, 'approve a mailbox conversion'); notLeaver(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).list('delegates', { max: 5, item: 'str', itemMax: 254, unique: true })
      .str('auto_reply', { max: 2000 }).bool('no_auto_reply', { def: false }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the mailbox stays a user mailbox' : null)).done();
    const m = r.mailbox; if (!m || m.status !== 'proposed') throw httpErr(409, 'no mailbox conversion is waiting for ' + r.id + (m ? ' (it is ' + m.status + ')' : ''));
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also approve the mailbox change');
    if (!(r.disabled && r.disabled.at)) throw httpErr(409, 'the account must be disabled first');
    if (b.decision === 'reject') {
      Object.assign(m, { status: 'kept', decided_by: who.user, decided_at: iso(), note: b.note });
      hist(r, who, 'mailbox_kept', { note: b.note }); maybeComplete(r, who); col().put(r);
      audit(who, 'offboarding.mailbox.kept', r.id, { upn: m.upn, note: b.note });
      return view(r, true);
    }
    const delegates = (b.delegates || m.delegates || []).map((x) => x.toLowerCase());
    const bad = delegates.find((x) => !ADDR.test(x)); if (bad) throw httpErr(400, 'delegates: ' + bad + ' is not a mailbox address');
    if (delegates.some((x) => x === String(m.upn).toLowerCase())) throw httpErr(400, 'delegates: the leaver cannot be their own delegate');
    if (!delegates.length) throw httpErr(400, 'delegates: name at least one person who will read the mailbox (the manager by default)');
    const reply = b.no_auto_reply ? '' : (b.auto_reply !== undefined ? b.auto_reply : m.auto_reply);
    if (reply && reply.length < 5) throw httpErr(400, 'auto_reply must be at least 5 characters (or tick no automatic reply)');
    if (reply && SECRETISH.test(reply)) throw httpErr(400, 'auto_reply looks like it contains a password');
    Object.assign(m, { status: 'approved', decided_by: who.user, decided_at: iso(), delegates, auto_reply: reply, note: b.note || '' });
    hist(r, who, 'mailbox_approved', { delegates }); col().put(r);
    audit(who, 'offboarding.mailbox.approved', r.id, { upn: m.upn, delegates, auto_reply: !!reply });
    await convertNow(r);
    return view(get(r.id), true);
  }
  async function retryMailbox(id, who) {
    const r = get(id); person(who, 'convert a mailbox'); notLeaver(r, who, 'act');
    const m = r.mailbox;
    if (m && m.status === 'read_failed') { r.mailbox = null; await startMailbox(r); col().put(r); return view(r, true); }
    if (!m || m.status !== 'approved') throw httpErr(409, 'no approved mailbox conversion to retry');
    audit(who, 'offboarding.mailbox.retry', r.id, {});
    await convertNow(r);
    return view(get(r.id), true);
  }
  function manualMailbox(id, input, who) {
    const r = get(id); person(who, 'record a mailbox conversion'); notLeaver(r, who, 'record');
    const b = body(input || {}).str('reference', { required: true, min: 3, max: 200 }).done();
    if (SECRETISH.test(b.reference)) throw httpErr(400, 'reference looks like it contains a password');
    if (!r.mailbox || MDONE.includes(r.mailbox.status)) throw httpErr(409, 'no mailbox conversion is open for ' + r.id);
    if (r.mailbox.status === 'proposed') throw httpErr(409, 'the conversion must be approved first');
    Object.assign(r.mailbox, { status: 'converted_manually', by: who.user, at: iso(), reference: b.reference, error: null });
    hist(r, who, 'mailbox_manual', { reference: b.reference }); maybeComplete(r, who); col().put(r);
    audit(who, 'offboarding.mailbox.manual', r.id, { reference: b.reference });
    return view(r, true);
  }
  // ---- mail forwarding: read after the disable, removed under the approver's decision, read back, watched for 30 days
  const domOf = (a) => String(a).split('@')[1] || '';
  // an inbox-rule target is '"Name" [SMTP:a@b.c]', '[EX:/o=...]' (an internal recipient) or a bare address
  const addrOf = (t) => { const m = /SMTP:([^\]\s]+)/i.exec(t) || /([A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24})/.exec(t); return m ? m[1].toLowerCase() : null; };
  function fwdItems(d) {
    const acc = (d.accepted_domains || []).map((x) => String(x).toLowerCase());
    const ext = (a) => !!a && !!acc.length && !acc.some((x) => domOf(a) === x || domOf(a).endsWith('.' + x));
    const out = [];
    for (const [k, v] of [['mailbox-smtp', d.smtp], ['mailbox-address', d.address]]) if (v) { const a = addrOf(v) || String(v).slice(0, 254); out.push({ kind: 'mailbox', ref: k, targets: [a], external: ext(addrOf(v)), active: true, keep_copy: !!d.keep_copy }); }
    for (const r of d.rules || []) {
      if (!/^\d{1,20}$/.test(String(r.id))) continue;
      const t = (r.targets || []).map((x) => addrOf(x) || String(x).slice(0, 120));
      out.push({ kind: 'rule', ref: String(r.id), name: String(r.name || '').slice(0, 120), targets: t.slice(0, 20), external: t.some((a) => ext(a)), active: !!r.enabled });
    }
    return { items: out, accepted_domains: acc.slice(0, 50), domains_known: !!acc.length };
  }
  async function readForwarding(r) {
    const upn = upnOfM(r);
    if (!upn) return { status: 'read_failed', error: 'the mailbox address (UPN) is not known - set the UPN suffix in Directory settings' };
    const x = await EXO.run('get-forwarding', { identity: upn });
    if (!x.ok) { warn('fwd-read', 'offboarding: the forwarding could not be read', { id: r.id, err: String(x.error).slice(0, 160) }); return { status: 'read_failed', upn, error: String(x.error).slice(0, 240) }; }
    const d = x.data || {};
    if (!d.found) return d.recipient_type && /remote|mailuser/i.test(d.recipient_type) ? { status: 'on_premises', upn, items: [], note: 'the mailbox is on the on-premises Exchange (' + d.recipient_type + ') - an Exchange administrator removes its forwarding there and records it' } : { status: 'not_needed', upn, items: [], note: 'no mailbox in Exchange Online' };
    return Object.assign({ upn, read_at: iso() }, fwdItems(d));
  }
  // what a scope removes: everything active, or only what leaves the company (an unknown domain list never counts as internal)
  const inScope = (i, scope) => i.active && (scope === 'all' || i.external || i.kind === 'mailbox' && !i.targets.some((a) => /@/.test(a)));
  function checkForwarding(id, who) {
    const r = get(id); person(who, 'check forwarding');
    if (!EXO.enabled()) throw httpErr(409, 'Exchange Online is not set up - HR Offboarding -> Exchange Online');
    return readForwarding(r).then((f) => {
      r.forwarding_check = Object.assign({ by: who.user, at: iso() }, f); col().put(r);
      audit(who, 'offboarding.forwarding.check', r.id, { upn: f.upn || null, found: (f.items || []).filter((i) => i.active).length, external: (f.items || []).filter((i) => i.active && i.external).length, error: f.error || null });
      return view(r, true);
    });
  }
  async function startForwarding(r) {
    if (r.forwarding || !EXO.enabled()) return;
    const f = await readForwarding(r);
    const active = (f.items || []).filter((i) => i.active);
    const mode = (r.disable && r.disable.forwarding) || 'ask';
    if (!f.status) f.status = !active.length ? 'not_needed' : mode === 'ask' ? 'proposed' : 'approved';
    if (f.status === 'not_needed' && !f.note) f.note = 'no forwarding on the mailbox or in its inbox rules';
    // "only outside the company" needs the accepted domains to tell inside from outside: without them a person decides
    if (f.status === 'approved' && mode === 'remove_external' && !f.domains_known) Object.assign(f, { status: 'proposed', note: 'the tenant\'s accepted domains could not be read, so internal and external forwarding cannot be told apart - an administrator decides' });
    if (f.status === 'approved') Object.assign(f, { scope: mode === 'remove_external' ? 'external' : 'all', decided_by: r.disable.approved_by, decided_at: r.disable.approved_at, decided_with: 'disable approval' });
    if (f.status === 'approved' && !active.some((i) => inScope(i, f.scope))) Object.assign(f, { status: 'not_needed', kept: active.map((i) => ({ kind: i.kind, name: i.name || null, targets: i.targets })), note: 'only forwarding inside the company - kept, as approved' });
    r.forwarding = Object.assign(f, { proposed_at: iso() });
    hist(r, MSYS, 'forwarding_' + f.status, { found: active.length });
    audit(MSYS, 'offboarding.forwarding.read', r.id, { status: f.status, upn: f.upn || null, found: active.map((i) => ({ kind: i.kind, name: i.name || null, targets: i.targets, external: i.external })), error: f.error || null });
    if (active.some((i) => i.external)) warn('fwd-ext', 'offboarding: a leaver\'s mail is forwarded outside the company', { id: r.id, items: active.filter((i) => i.external).length });
    if (f.status === 'approved') await removeForwarding(r);
    else if (f.status === 'not_needed') r.forwarding.watch_until = new Date(now() + FWATCH_DAYS * DAY).toISOString();
  }
  // remove what the scope covers, read each back, then read the whole forwarding again to prove nothing in scope is left
  async function removeForwarding(r, reason) {
    const f = r.forwarding, steps = f.steps || [];
    const add = (step, ok, err) => { steps.push(Object.assign({ step, ok, at: iso() }, ok ? {} : { error: String(err || '').slice(0, 200) })); return ok; };
    const did = (k) => steps.some((x) => x.step === k && x.ok);   // a retry does not repeat what already worked
    const todo = (f.items || []).filter((i) => inScope(i, f.scope));
    try {
      if (todo.some((i) => i.kind === 'mailbox') && !did('mailbox')) {
        const x = await EXO.run('clear-forwarding', { identity: f.upn });
        add('mailbox', x.ok && !(x.data || {}).smtp && !(x.data || {}).address, x.ok ? 'read back: the mailbox still forwards' : x.error);
      }
      for (const i of todo.filter((y) => y.kind === 'rule' && !did('rule:' + y.ref))) {
        const x = await EXO.run('disable-inbox-rule', { identity: f.upn, rule: i.ref });
        add('rule:' + i.ref, x.ok && (x.data || {}).enabled === false, x.ok ? 'read back: rule "' + i.name + '" is still enabled' : x.error);
      }
      const failed = steps.filter((x) => !x.ok && !steps.some((y) => y.ok && y.step === x.step && y.at >= x.at));
      f.steps = steps.slice(-60);
      if (failed.length) throw new Error('partly done - ' + failed.map((x) => x.step + ': ' + x.error).join('; '));
      const again = await readForwarding(r);
      if (again.status === 'read_failed') throw new Error('removed, but the check read failed: ' + again.error);
      const left = (again.items || []).filter((i) => inScope(i, f.scope));
      if (left.length) throw new Error('read back: still forwarding - ' + left.map((i) => (i.name || i.kind) + ' -> ' + i.targets.join(', ')).join('; '));
      const removed = todo.map((i) => ({ kind: i.kind, name: i.name || null, targets: i.targets, external: i.external, keep_copy: i.keep_copy }));
      const kept = (f.items || []).filter((i) => i.active && !inScope(i, f.scope)).map((i) => ({ kind: i.kind, name: i.name || null, targets: i.targets }));
      Object.assign(f, { status: 'removed', removed_at: f.removed_at || iso(), removed: (f.removed || []).concat(removed), kept, error: null, verified_at: iso(), last_watch: iso(),
        watch_until: f.watch_until || new Date(now() + FWATCH_DAYS * DAY).toISOString() });
      hist(r, MSYS, reason ? 'forwarding_reappeared_removed' : 'forwarding_removed', { removed: removed.length, kept: kept.length });
      audit(MSYS, reason ? 'offboarding.forwarding.reappeared' : 'offboarding.forwarding.removed', r.id, { upn: f.upn, removed, kept, scope: f.scope, approved_by: f.decided_by });
      if (reason) warn('fwd-back', 'offboarding: forwarding came back on a leaver\'s mailbox and was removed again', { id: r.id, items: removed.length });
      maybeComplete(r, MSYS);
    } catch (e) {
      f.steps = steps.slice(-60);
      Object.assign(f, { error: String(e.message).slice(0, 300), failed_at: iso(), attempts: (f.attempts || 0) + 1 });
      if (f.status !== 'removed') f.status = 'approved';
      hist(r, MSYS, 'forwarding_failed', { error: f.error });
      if (f.attempts === 1) audit(MSYS, 'offboarding.forwarding.failed', r.id, { upn: f.upn, error: f.error });
      warn('fwd', 'offboarding: the forwarding could not be removed', { id: r.id, err: f.error });
    }
    col().put(r);
    return r;
  }
  async function decideForwarding(id, input, who) {
    const r = get(id); person(who, 'approve removing forwarding'); notLeaver(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).oneOf('scope', ['all', 'external'], { def: 'all' }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the forwarding stays' : null)).done();
    const f = r.forwarding; if (!f || f.status !== 'proposed') throw httpErr(409, 'no forwarding decision is waiting for ' + r.id + (f ? ' (it is ' + f.status + ')' : ''));
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also decide the forwarding');
    if (b.decision === 'reject') {
      Object.assign(f, { status: 'kept', decided_by: who.user, decided_at: iso(), note: b.note });
      hist(r, who, 'forwarding_kept', { note: b.note }); maybeComplete(r, who); col().put(r);
      audit(who, 'offboarding.forwarding.kept', r.id, { upn: f.upn, kept: (f.items || []).filter((i) => i.active).map((i) => ({ kind: i.kind, targets: i.targets, external: i.external })), note: b.note });
      return view(r, true);
    }
    if (b.scope === 'external' && !f.domains_known) throw httpErr(409, 'scope external needs the tenant\'s accepted domains, which could not be read - remove all, or retry the read');
    if (!(f.items || []).some((i) => inScope(i, b.scope))) throw httpErr(409, 'nothing to remove with scope ' + b.scope + ' - choose all, or keep it (reject with a note)');
    Object.assign(f, { status: 'approved', scope: b.scope, decided_by: who.user, decided_at: iso(), note: b.note || '' });
    hist(r, who, 'forwarding_approved', { scope: b.scope }); col().put(r);
    audit(who, 'offboarding.forwarding.approved', r.id, { upn: f.upn, scope: b.scope });
    await removeForwarding(r);
    return view(get(r.id), true);
  }
  async function retryForwarding(id, who) {
    const r = get(id); person(who, 'remove forwarding'); notLeaver(r, who, 'act');
    const f = r.forwarding;
    if (f && f.status === 'read_failed') { r.forwarding = null; await startForwarding(r); col().put(r); return view(r, true); }
    if (!f || f.status !== 'approved') throw httpErr(409, 'no approved forwarding removal to retry');
    audit(who, 'offboarding.forwarding.retry', r.id, {});
    await removeForwarding(r);
    return view(get(r.id), true);
  }
  function manualForwarding(id, input, who) {
    const r = get(id); person(who, 'record a forwarding removal'); notLeaver(r, who, 'record');
    const b = body(input || {}).str('reference', { required: true, min: 3, max: 200 }).done();
    if (SECRETISH.test(b.reference)) throw httpErr(400, 'reference looks like it contains a password');
    const f = r.forwarding;
    if (!f || FDONE.includes(f.status)) throw httpErr(409, 'no forwarding removal is open for ' + r.id);
    if (f.status === 'proposed') throw httpErr(409, 'the removal must be decided first');
    Object.assign(f, { status: 'removed_manually', by: who.user, at: iso(), reference: b.reference, error: null });
    hist(r, who, 'forwarding_manual', { reference: b.reference }); maybeComplete(r, who); col().put(r);
    audit(who, 'offboarding.forwarding.manual', r.id, { reference: b.reference });
    return view(r, true);
  }
  // after the disable: start, retry a failed read / removal hourly (5 times), and once a day for 30 days read it again - forwarding
  // that came back is removed under the same decision (an empty mailbox is watched too: a rule added later is the same risk)
  async function forwardingTick() {
    if (!EXO.enabled()) return 0;
    let n = 0;
    for (const r of col().all((x) => x.status !== 'cancelled' && x.disabled && x.disabled.at && !x.disabled.reenabled_at)) {
      const f = r.forwarding;
      if (!f) { if (r.status === 'in_progress') { await startForwarding(r); maybeComplete(r, MSYS); col().put(r); n++; } continue; }
      const hourAgo = (t) => !t || now() - Date.parse(t) >= 3600000;
      if (f.status === 'read_failed' && hourAgo(f.proposed_at) && (f.reads || 0) < 5) { const k = (f.reads || 0) + 1; r.forwarding = null; await startForwarding(r); if (r.forwarding.status === 'read_failed') r.forwarding.reads = k; maybeComplete(r, MSYS); col().put(r); n++; continue; }
      if (f.status === 'approved' && f.failed_at && hourAgo(f.failed_at) && (f.attempts || 0) < 5) { await removeForwarding(r); n++; continue; }
      if (['removed', 'not_needed'].includes(f.status) && f.watch_until && Date.parse(f.watch_until) > now() && (!f.last_watch || now() - Date.parse(f.last_watch) >= DAY)) {
        const again = await readForwarding(r);
        f.last_watch = iso();
        if (again.status === 'read_failed') { warn('fwd-watch', 'offboarding: the daily forwarding check could not read the mailbox', { id: r.id, err: again.error }); col().put(r); continue; }
        const scope = f.scope || ((r.disable && r.disable.forwarding) === 'remove_external' ? 'external' : 'all');
        const back = (again.items || []).filter((i) => inScope(i, scope));
        if (back.length) {
          Object.assign(f, { items: again.items, accepted_domains: again.accepted_domains, domains_known: again.domains_known, scope, status: 'approved', steps: [], attempts: 0, reappeared: (f.reappeared || []).concat([{ at: iso(), items: back.map((i) => ({ kind: i.kind, name: i.name || null, targets: i.targets, external: i.external })) }]).slice(-20) });
          if (!f.decided_by) Object.assign(f, { decided_by: r.disable.approved_by, decided_with: 'disable approval' });
          await removeForwarding(r, 'reappeared'); n++; continue;
        }
        col().put(r);
      }
    }
    return n;
  }
  // ---- business applications: the register, and per leaver the removal (automatic where a connection exists, else the owner)
  const APPNAME = /^[A-Za-z0-9 ._&()'\/+-]{2,80}$/, GROUPN = /^[A-Za-z0-9 ._&()'-]{1,64}$/;
  function listApps() { return { apps: appsReg().all(() => true).sort((a, b) => a.id.localeCompare(b.id)), graph: appsGraph(), directory: auto() }; }
  async function putApp(input, who) {
    person(who, 'change the application register');
    const b = body(input || {}).str('id', { max: 12, re: /^APP-\d{3,6}$/, msg: 'id must be an application id (APP-nnn)' }).str('name', { required: true, max: 80, re: APPNAME, msg: 'name must be the application name (letters, digits, spaces, . _ & ( ) \' / + -)' })
      .str('owner', Object.assign({ required: true }, USER, { msg: 'owner must be the platform user who owns the application' })).oneOf('method', ['entra', 'ad_group', 'manual'], { required: true })
      .str('sp_id', { max: 36, re: GUIDR, msg: 'sp_id must be the enterprise application\'s object id (a GUID from Entra ID -> Enterprise applications)' })
      .list('groups', { max: 10, item: 'str', itemMax: 64, unique: true }).oneOf('applies', ['all', 'departments', 'check'], { def: 'check' }).list('departments', { max: 20, item: 'str', itemMax: 80, unique: true })
      .num('sla_days', { min: 1, max: 30 }).str('notes', { max: 300 }).done();
    if (b.sla_days !== undefined && !Number.isInteger(b.sla_days)) throw httpErr(400, 'sla_days must be a whole number of days (1-30)');
    if (b.method === 'entra' && !b.sp_id) throw httpErr(400, 'sp_id is required for an Entra ID application');
    if (b.method === 'ad_group' && !(b.groups || []).length) throw httpErr(400, 'groups: name the AD groups that give access');
    const bad = (b.groups || []).find((g) => !GROUPN.test(g) || PRIVILEGED.test(g)); if (bad) throw httpErr(400, 'groups: ' + bad + ' is not a group name the platform may change');
    if (b.applies === 'departments' && !(b.departments || []).length) throw httpErr(400, 'departments: name at least one department');
    const cur = b.id ? appsReg().get(b.id) : null; if (b.id && !cur) throw httpErr(404, 'no application ' + b.id);
    if (appsReg().all((a) => a.active !== false && a.id !== b.id && same(a.name, b.name)).length) throw httpErr(409, b.name + ' is already in the register');
    let sp = null;
    if (b.method === 'entra' && appsGraph()) { try { sp = await LIC().servicePrincipal(b.sp_id); } catch (e) { throw httpErr(409, 'Entra ID could not be read to check the application: ' + String(e.message).slice(0, 160)); } if (!sp) throw httpErr(400, 'sp_id: no enterprise application ' + b.sp_id + ' in Entra ID'); }
    let id = b.id; if (!id) { let n = appsReg().all(() => true).length + 1; do { id = 'APP-' + String(n++).padStart(3, '0'); } while (appsReg().get(id)); }
    const rec = Object.assign({}, cur || { created_by: who.user, created_at: iso() }, { id, name: b.name, owner: b.owner.toLowerCase(), method: b.method, sp_id: b.method === 'entra' ? b.sp_id : null, sp_name: sp ? sp.name : (cur && cur.sp_name) || null,
      groups: b.method === 'ad_group' ? b.groups : [], applies: b.method === 'manual' ? b.applies : null, departments: b.method === 'manual' && b.applies === 'departments' ? b.departments : [], sla_days: b.sla_days || (cur && cur.sla_days) || 3, notes: b.notes || '', active: true, updated_by: who.user, updated_at: iso() });
    appsReg().put(rec);
    audit(who, cur ? 'offboarding.apps.updated' : 'offboarding.apps.added', id, { name: rec.name, owner: rec.owner, method: rec.method, sp_id: rec.sp_id, groups: rec.groups, applies: rec.applies });
    return rec;
  }
  function retireApp(input, who) {
    person(who, 'change the application register');
    const b = body(input || {}).str('id', { required: true, max: 12, re: /^APP-\d{3,6}$/, msg: 'id must be an application id (APP-nnn)' }).str('reason', { required: true, min: 5, max: 300 }).done();
    const a = appsReg().get(b.id); if (!a || a.active === false) throw httpErr(404, 'no active application ' + b.id);
    Object.assign(a, { active: false, retired_by: who.user, retired_at: iso(), retire_reason: b.reason }); appsReg().put(a);
    audit(who, 'offboarding.apps.retired', a.id, { name: a.name, reason: b.reason });
    return a;
  }
  function appItem(r, a) {
    const base = { app_id: a.id, name: a.name, method: a.method, owner: a.owner };
    if (a.method === 'manual' && a.applies === 'departments' && !(a.departments || []).some((d) => same(d, r.department))) return Object.assign(base, { state: 'not_applicable', note: 'not used by ' + r.department });
    return Object.assign(base, { state: 'pending' });
  }
  async function startApps(r) {
    if (r.apps || !activeApps().length) return;
    const mode = (r.disable && r.disable.apps) || 'ask';
    const items = activeApps().map((a) => appItem(r, a));
    if (mode === 'ask') items.forEach((i) => { if (i.state === 'pending') i.state = 'proposed'; });
    r.apps = { status: mode === 'ask' ? 'proposed' : 'working', items, upn: upnOfM(r), proposed_at: iso() };
    if (mode !== 'ask') Object.assign(r.apps, { decided_by: r.disable.approved_by, decided_with: 'disable approval' });
    hist(r, ASYS, 'apps_' + r.apps.status, { apps: items.length });
    audit(ASYS, 'offboarding.apps.read', r.id, { status: r.apps.status, apps: items.map((i) => ({ name: i.name, method: i.method, state: i.state })) });
    if (mode !== 'ask') await runApps(r);
  }
  // one application at a time; anything the platform cannot do itself goes to the application's owner with a due date
  async function runApps(r) {
    const A = r.apps, ownerTask = (i, why) => Object.assign(i, { state: 'owner_task', due_at: i.due_at || new Date(now() + ((appsReg().get(i.app_id) || {}).sla_days || 3) * DAY).toISOString(), note: why || i.note || null, error: null });
    for (const i of A.items.filter((x) => x.state === 'pending' || x.state === 'error')) {
      const a = appsReg().get(i.app_id) || {};
      try {
        if (i.method === 'manual') { ownerTask(i, a.applies === 'check' ? 'the owner checks whether ' + r.username + ' had an account' : null); continue; }
        if (i.method === 'entra') {
          if (!appsGraph()) { ownerTask(i, 'automatic removal is off (Microsoft 365 licensing settings) - the owner removes it'); continue; }
          if (!A.upn) throw new Error('the user address (UPN) is not known - set the UPN suffix in Directory settings');
          const x = await LIC().appAssignments(A.upn, a.sp_id);
          if (!x.found || !x.assignments.length) { Object.assign(i, { state: 'no_access', done_at: iso(), error: null, note: x.found ? 'no direct assignment (access through a group is removed with the group)' : 'the user is not in Entra ID' }); continue; }
          for (const as of x.assignments) await LIC().removeAppAssignment(x.user_id, as.id);
          Object.assign(i, { state: 'removed', done_at: iso(), error: null, detail: x.assignments.length + ' assignment(s) removed' });
        }
        if (i.method === 'ad_group') {
          if (!auto()) { ownerTask(i, 'automatic directory changes are off - the owner (or a directory administrator) removes it'); continue; }
          const W = AD().writer(), u = await W.findUser(r.username);
          if (!u) { Object.assign(i, { state: 'no_access', done_at: iso(), error: null, note: 'no account in the directory' }); continue; }
          const hit = (u.member_of || []).filter((dn) => (a.groups || []).some((g) => same(cnOf(dn), g)));
          if (!hit.length) { Object.assign(i, { state: 'no_access', done_at: iso(), error: null, note: 'not in ' + (a.groups || []).join(', ') }); continue; }
          for (const dn of hit) await W.removeFromGroup(dn, u.dn);
          const back = await W.findUser(r.username), left = ((back && back.member_of) || []).filter((dn) => hit.includes(dn));
          if (left.length) throw new Error('read back: still in ' + left.map(cnOf).join(', '));
          Object.assign(i, { state: 'removed', done_at: iso(), error: null, detail: 'removed from ' + hit.map(cnOf).join(', ') });
        }
        audit(ASYS, 'offboarding.apps.removed', r.id, { app: i.name, method: i.method, detail: i.detail || null, approved_by: A.decided_by });
      } catch (e) {
        Object.assign(i, { state: 'error', error: String(e.message).slice(0, 240) + (e.http === 403 ? ' - the app registration lacks AppRoleAssignment.ReadWrite.All' : ''), failed_at: iso(), attempts: (i.attempts || 0) + 1 });
        if (i.attempts === 1) audit(ASYS, 'offboarding.apps.failed', r.id, { app: i.name, error: i.error });
        warn('apps', 'offboarding: access to a business application could not be removed', { id: r.id, err: i.error });
      }
    }
    // end the leaver's Microsoft sign-in sessions once, so single sign-on stops at every application now, not at token expiry
    if (!A.sessions_revoked && appsGraph() && A.upn && A.items.some((i) => i.method === 'entra')) {
      try { await LIC().revokeSessions(A.upn); A.sessions_revoked = iso(); audit(ASYS, 'offboarding.apps.sessions_revoked', r.id, { upn: A.upn }); }
      catch (e) { warn('apps-rev', 'offboarding: the sign-in sessions could not be ended', { id: r.id, err: String(e.message).slice(0, 160) }); }   // retried on the next run
    }
    appsSettle(r, ASYS); col().put(r);
    return r;
  }
  function appsSettle(r, who) {
    const A = r.apps; if (!A || ['done', 'kept', 'cancelled'].includes(A.status)) return;
    if (A.items.every((i) => AFINAL.includes(i.state))) {
      A.status = 'done'; A.done_at = iso();
      hist(r, who, 'apps_done', { apps: A.items.map((i) => i.name + ': ' + i.state) });
      audit(who, 'offboarding.apps.done', r.id, { apps: A.items.map((i) => ({ name: i.name, state: i.state })) });
      maybeComplete(r, who);
    } else if (A.status === 'proposed' && !A.items.some((i) => i.state === 'proposed')) A.status = 'working';
  }
  async function decideApps(id, input, who) {
    const r = get(id); person(who, 'approve removing application access'); notLeaver(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).list('keep', { max: 100 }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why access stays' : null)).done();
    const A = r.apps; if (!A || A.status !== 'proposed') throw httpErr(409, 'no application decision is waiting for ' + r.id);
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also decide the application access');
    if (b.decision === 'reject') {
      A.items.forEach((i) => { if (i.state === 'proposed') Object.assign(i, { state: 'kept', note: b.note }); });
      Object.assign(A, { status: 'kept', decided_by: who.user, decided_at: iso(), note: b.note });
      hist(r, who, 'apps_kept', { note: b.note }); maybeComplete(r, who); col().put(r);
      audit(who, 'offboarding.apps.kept', r.id, { apps: A.items.map((i) => i.name), note: b.note });
      return view(r, true);
    }
    const keep = (b.keep || []).map((x, n) => {
      if (!x || typeof x !== 'object') throw httpErr(400, 'keep[' + n + '] must be {app_id, reason}');
      const v = body(x).str('app_id', { required: true, max: 12, re: /^APP-\d{3,6}$/, msg: 'keep[' + n + '].app_id must be an application id' }).str('reason', { required: true, min: 5, max: 300 }).done();
      if (!A.items.some((i) => i.app_id === v.app_id && i.state === 'proposed')) throw httpErr(400, 'keep[' + n + ']: ' + v.app_id + ' is not waiting for a decision on ' + r.id);
      return v;
    });
    A.items.forEach((i) => { if (i.state !== 'proposed') return; const k = keep.find((x) => x.app_id === i.app_id); Object.assign(i, k ? { state: 'kept', note: k.reason } : { state: 'pending' }); });
    Object.assign(A, { status: 'working', decided_by: who.user, decided_at: iso(), note: b.note || '' });
    hist(r, who, 'apps_approved', { kept: keep.length }); col().put(r);
    audit(who, 'offboarding.apps.approved', r.id, { kept: keep.map((k) => ({ app: k.app_id, reason: k.reason })) });
    await runApps(r);
    return view(get(r.id), true);
  }
  function confirmApp(id, input, who) {
    const r = get(id); person(who, 'confirm application access removed'); notLeaver(r, who, 'confirm');
    const b = body(input || {}).str('app_id', { required: true, max: 12, re: /^APP-\d{3,6}$/, msg: 'app_id must be an application id (APP-nnn)' }).oneOf('outcome', ['removed', 'no_account'], { required: true }).str('reference', { required: true, min: 3, max: 200 }).done();
    if (SECRETISH.test(b.reference)) throw httpErr(400, 'reference looks like it contains a password');
    const i = r.apps && r.apps.items.find((x) => x.app_id === b.app_id);
    if (!i || !['owner_task', 'error'].includes(i.state)) throw httpErr(409, 'no task for ' + b.app_id + ' on ' + r.id);
    if (!same(i.owner, who.user) && who.role !== 'admin') throw httpErr(403, 'the owner of ' + i.name + ' (' + i.owner + ') or an administrator confirms it');
    Object.assign(i, { state: b.outcome === 'removed' ? 'confirmed' : 'no_account', by: who.user, done_at: iso(), reference: b.reference, error: null, late: !!(i.due_at && Date.parse(i.due_at) < now()) });
    hist(r, who, 'app_' + i.state, { app: i.name });
    audit(who, 'offboarding.apps.' + i.state, r.id, { app: i.name, reference: b.reference, late: i.late });
    appsSettle(r, who); col().put(r);
    return view(r, true);
  }
  async function retryApps(id, who) {
    const r = get(id); person(who, 'retry application access removal'); notLeaver(r, who, 'act');
    if (!r.apps || !r.apps.items.some((i) => i.state === 'error')) throw httpErr(409, 'no failed application removal on ' + r.id);
    audit(who, 'offboarding.apps.retry', r.id, {});
    await runApps(r);
    return view(get(r.id), true);
  }
  async function appsTick() {
    if (!activeApps().length) return 0;
    let n = 0;
    for (const r of col().all((x) => x.status === 'in_progress' && x.disabled && x.disabled.at && !x.disabled.reenabled_at)) {
      if (!r.apps) { await startApps(r); maybeComplete(r, ASYS); col().put(r); n++; continue; }
      const due = r.apps.status === 'working' && (r.apps.items.some((i) => i.state === 'error' && (i.attempts || 0) < 5 && (!i.failed_at || now() - Date.parse(i.failed_at) >= 3600000)) || (!r.apps.sessions_revoked && appsGraph() && r.apps.items.some((i) => i.method === 'entra')));
      if (due) { await runApps(r); n++; }
    }
    return n;
  }
  // ---- leaver devices (Intune): proposed per device, decided per device by a second person, sent once, followed to the end
  const isMac = (d) => /mac ?os|macos|os x/i.test(d.os || '');
  const allowedFor = (d) => (d.owner_type === 'company' && !isMac(d) ? ['wipe', 'retire', 'keep'] : ['retire', 'keep']);
  async function readDevices(r) {
    const upn = upnOfM(r);
    if (!upn) return { status: 'read_failed', error: 'the user address (UPN) is not known - set the UPN suffix in Directory settings' };
    let d;
    const A = DEV();
    try { d = await A.userDevices(upn); }
    catch (e) { warn('dev-read', 'offboarding: the leaver\'s devices could not be read', { id: r.id, err: String(e.message).slice(0, 160) }); return { status: 'read_failed', upn, provider: A.name, error: String(e.message).slice(0, 240) + (e.http === 403 || e.http === 401 ? (A.name === 'intune' ? ' - the app registration lacks DeviceManagementManagedDevices.Read.All' : ' - the ManageEngine API token is refused or lacks the permission') : '') }; }
    if (!d.found) return { status: 'not_needed', upn, devices: [], note: 'the user is not in Entra ID' };
    const assets = assetsAll();
    const devices = d.devices.map((x) => {
      const a = x.serial ? assets.find((y) => y.serial && String(y.serial).trim().toLowerCase() === x.serial.trim().toLowerCase()) : null;
      const allowed = allowedFor(x);
      return Object.assign({}, x, { asset: a ? { id: a.id, tag: a.asset_tag || null, name: a.name || null } : null, allowed, proposed: allowed.includes('wipe') ? 'wipe' : 'retire', state: 'proposed',
        note: isMac(x) && x.owner_type === 'company' ? 'a Mac: full wipe is done in Intune (it needs an unlock code) and recorded here' : x.owner_type !== 'company' ? 'not a company device: only company data can be removed (retire)' : null });
    });
    return Object.assign({ upn, provider: A.name, devices, read_at: iso() }, devices.length ? { status: 'proposed' } : { status: 'not_needed', note: 'no device in ' + (A.name === 'intune' ? 'Intune' : 'ManageEngine MDM') + ' for this user' });
  }
  async function startDevices(r) {
    if (r.devices || !devOn()) return;
    r.devices = Object.assign(await readDevices(r), { proposed_at: iso() });
    const dv = r.devices.devices || [];
    hist(r, DSYS, 'devices_' + r.devices.status, { devices: dv.length });
    audit(DSYS, 'offboarding.devices.read', r.id, { status: r.devices.status, devices: dv.map((x) => ({ name: x.name, serial: x.serial, owner: x.owner_type, proposed: x.proposed })), error: r.devices.error || null });
  }
  function devicesSettle(r, who) {
    const D = r.devices, dv = D.devices || [];
    if (D.status !== 'cancelled' && dv.length && dv.every((x) => DFINAL.includes(x.state))) {
      D.status = 'done'; D.done_at = iso();
      hist(r, who, 'devices_done', { devices: dv.map((x) => x.name + ': ' + x.state) });
      audit(who, 'offboarding.devices.done', r.id, { devices: dv.map((x) => ({ name: x.name, serial: x.serial, state: x.state })) });
      maybeComplete(r, who);
    } else if (D.status === 'proposed' && dv.some((x) => x.state !== 'proposed')) D.status = 'working';
  }
  async function sendDevice(r, d, approver) {
    const act = d.decision.action;
    try {
      const A = DEV(); if (!A) throw new Error('no MDM is set up any more - HR Offboarding -> MDM');
      if (r.devices.provider && A.name !== r.devices.provider) throw Object.assign(new Error('the MDM changed from ' + r.devices.provider + ' to ' + A.name + ' since the devices were read - read them again'), { final: true });
      const now0 = await A.deviceGet(d.id);
      if (!now0) { Object.assign(d, { state: 'gone', done_at: iso(), error: null, note: 'no longer in the MDM - nothing sent' }); return; }
      if (now0.upn && now0.upn !== String(r.devices.upn).toLowerCase()) throw Object.assign(new Error('the device is now assigned to ' + now0.upn + ' - nothing sent'), { final: true });
      if (act === 'wipe' && !(now0.owner_type === 'company' && !isMac(now0))) throw Object.assign(new Error('the device is no longer a company device the platform may wipe - nothing sent'), { final: true });
      const pending = (now0.actions || []).find((a) => a.name === act && /pending|active/.test(a.state));
      if (!pending) await A.deviceAction(d.id, act);
      Object.assign(d, { state: 'sent', sent_at: d.sent_at || iso(), error: null });
      hist(r, DSYS, 'device_' + act + '_sent', { device: d.name });
      audit(DSYS, 'offboarding.device.' + act + '_sent', r.id, { device: d.name, serial: d.serial, owner: d.owner_type, asset: d.asset && d.asset.tag, approved_by: approver });
    } catch (e) {
      Object.assign(d, { state: 'error', error: String(e.message).slice(0, 240) + (e.http === 403 ? (r.devices.provider === 'intune' ? ' - the app registration lacks DeviceManagementManagedDevices.PrivilegedOperations.All' : ' - the ManageEngine technician lacks the device actions permission') : ''), failed_at: iso(), attempts: (d.attempts || 0) + 1 });
      hist(r, DSYS, 'device_failed', { device: d.name, error: d.error });
      audit(DSYS, 'offboarding.device.failed', r.id, { device: d.name, serial: d.serial, action: act, error: d.error });
      warn('dev', 'offboarding: a device action was not sent', { id: r.id, err: d.error });
    }
  }
  async function decideDevices(id, input, who) {
    const r = get(id); person(who, 'approve wiping devices'); notLeaver(r, who, 'approve');
    const b = body(input || {}).list('decisions', { required: true, max: 100 }).str('note', { max: 300 }).done();
    const D = r.devices; if (!D || !['proposed', 'working'].includes(D.status)) throw httpErr(409, 'no device decision is waiting for ' + r.id);
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also approve wiping the devices');
    const ds = b.decisions.map((x, i) => {
      if (!x || typeof x !== 'object' || Array.isArray(x)) throw httpErr(400, 'decisions[' + i + '] must be {device_id, action, confirm?, reason?}');
      const v = body(x).str('device_id', { required: true, max: 36, re: DEVID, msg: 'decisions[' + i + '].device_id must be a device id from the MDM' }).oneOf('action', ['wipe', 'retire', 'keep'], { required: true }).str('confirm', { max: 80 }).str('reason', { max: 300 }).done();
      const d = (D.devices || []).find((y) => y.id === v.device_id); if (!d) throw httpErr(400, 'decisions[' + i + ']: not one of this leaver\'s devices');
      if (d.state !== 'proposed') throw httpErr(409, d.name + ' was already decided (' + d.state + ')');
      if (!d.allowed.includes(v.action)) throw httpErr(400, 'decisions[' + i + ']: ' + d.name + ' cannot be wiped here - ' + (d.note || 'only retire or keep'));
      if (v.action === 'wipe' && String(v.confirm || '').trim().toLowerCase() !== String(d.serial || d.name).trim().toLowerCase()) throw httpErr(400, 'decisions[' + i + '].confirm: type the serial of ' + d.name + ' (' + (d.serial ? 'serial' : 'device name') + ') to confirm the full wipe');
      if (v.action === 'keep' && (!v.reason || v.reason.length < 5)) throw httpErr(400, 'decisions[' + i + '].reason: say why ' + d.name + ' is kept as it is');
      return { d, v };
    });
    if (ds.some((x) => x.v.action !== 'keep') && legalActive(r)) throw httpErr(409, 'a legal hold is ' + r.legal.status.replace('_', ' ') + ' for ' + r.id + ' - devices are not wiped or retired while it is (they may hold evidence)');
    D.decided_by = who.user; D.decided_at = iso(); if (b.note) D.note = b.note;
    for (const { d, v } of ds) {
      d.decision = { action: v.action, by: who.user, at: iso(), reason: v.reason || '' };
      if (v.action === 'keep') { d.state = 'kept'; d.done_at = iso(); }
      audit(who, 'offboarding.device.' + v.action + '_approved', r.id, { device: d.name, serial: d.serial, owner: d.owner_type, reason: v.reason || null });
    }
    hist(r, who, 'devices_decided', { devices: ds.map((x) => x.d.name + ': ' + x.v.action) });
    for (const { d, v } of ds) if (v.action !== 'keep') await sendDevice(r, d, who.user);
    devicesSettle(r, who); col().put(r);
    return view(get(r.id), true);
  }
  async function retryDevices(id, who) {
    const r = get(id); person(who, 'retry device actions'); notLeaver(r, who, 'act');
    const D = r.devices; if (!D) throw httpErr(409, 'no device step for ' + r.id);
    if (D.status === 'read_failed') { r.devices = null; await startDevices(r); col().put(r); return view(r, true); }
    const todo = (D.devices || []).filter((d) => ['error', 'failed'].includes(d.state) && d.decision && d.decision.action !== 'keep');
    if (!todo.length) throw httpErr(409, 'no failed device action to send again');
    if (legalActive(r)) throw httpErr(409, 'a legal hold is in place for ' + r.id + ' - devices are not wiped or retired');
    audit(who, 'offboarding.devices.retry', r.id, { devices: todo.map((d) => d.name) });
    for (const d of todo) await sendDevice(r, d, D.decided_by);
    devicesSettle(r, who); col().put(r);
    return view(get(r.id), true);
  }
  function manualDevice(id, input, who) {
    const r = get(id); person(who, 'record a device handled by hand'); notLeaver(r, who, 'record');
    const b = body(input || {}).str('device_id', { required: true, max: 36, re: DEVID, msg: 'device_id must be a device id from the MDM' }).str('reference', { required: true, min: 3, max: 200 }).done();
    if (SECRETISH.test(b.reference)) throw httpErr(400, 'reference looks like it contains a password or unlock code');
    const D = r.devices, d = D && (D.devices || []).find((x) => x.id === b.device_id);
    if (!d) throw httpErr(404, 'no such device on ' + r.id);
    if (DFINAL.includes(d.state)) throw httpErr(409, d.name + ' is already ' + d.state);
    Object.assign(d, { state: 'manual', by: who.user, done_at: iso(), reference: b.reference, error: null });
    hist(r, who, 'device_manual', { device: d.name, reference: b.reference });
    audit(who, 'offboarding.device.manual', r.id, { device: d.name, serial: d.serial, reference: b.reference });
    devicesSettle(r, who); col().put(r);
    return view(r, true);
  }
  // follow sent actions until Intune reports them; a read failure is retried; a failed send waits for a person (destructive)
  async function devicesTick() {
    if (!devOn()) return 0;
    let n = 0;
    for (const r of col().all((x) => x.status !== 'cancelled' && x.disabled && x.disabled.at)) {
      const D = r.devices;
      if (!D) { if (r.status === 'in_progress' && !r.disabled.reenabled_at) { await startDevices(r); col().put(r); n++; } continue; }
      if (D.status === 'read_failed' && (!D.proposed_at || now() - Date.parse(D.proposed_at) >= 3600000) && (D.reads || 0) < 5) { const k = (D.reads || 0) + 1; r.devices = null; await startDevices(r); if (r.devices.status === 'read_failed') r.devices.reads = k; col().put(r); n++; continue; }
      const sent = (D.devices || []).filter((d) => d.state === 'sent');
      if (!sent.length) continue;
      for (const d of sent) {
        try {
          const A = DEV(); if (!A) break;
          const x = await A.deviceGet(d.id), act = d.decision.action;
          if (!x) { Object.assign(d, { state: act === 'wipe' ? 'wiped' : 'retired', done_at: iso(), note: 'removed from the MDM after the ' + act }); }
          else {
            const a = (x.actions || []).find((y) => y.name === act);
            if (a && /done|succeeded/.test(a.state)) Object.assign(d, { state: act === 'wipe' ? 'wiped' : 'retired', done_at: iso() });
            else if (a && /failed|canceled|cancelled/.test(a.state)) Object.assign(d, { state: 'failed', error: 'Intune reports the ' + act + ' as ' + a.state, failed_at: iso() });
            else if (now() - Date.parse(d.sent_at) > 14 * DAY && !d.late) { d.late = true; warn('dev-late', 'offboarding: a device has not checked in to receive its action', { id: r.id }); }
          }
          if (DFINAL.includes(d.state)) audit(DSYS, 'offboarding.device.' + d.state, r.id, { device: d.name, serial: d.serial });
          if (d.state === 'failed') audit(DSYS, 'offboarding.device.failed', r.id, { device: d.name, serial: d.serial, error: d.error });
        } catch (e) { warn('dev-poll', 'offboarding: a device could not be read back', { id: r.id, err: String(e.message).slice(0, 160) }); }   // read again next run
      }
      devicesSettle(r, DSYS); col().put(r); n++;
    }
    return n;
  }
  // ---- legal hold through Microsoft Purview eDiscovery: asked by one person, approved by another, then worked step by step
  const GUIDR = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  function requestLegal(id, input, who) {
    const r = get(id); person(who, 'ask for a legal hold'); notLeaver(r, who, 'ask for a legal hold');
    if (!legalOn()) throw httpErr(409, 'legal holds through Microsoft Purview are off - Microsoft 365 licensing settings (HR Onboarding)');
    const b = body(input || {}).str('matter', { required: true, min: 3, max: 120 }).str('reason', { required: true, min: 10, max: 500 })
      .str('pdpl_hold', { max: 30, re: /^PD-LEGAL_HOLD-\d{3,}$/, msg: 'pdpl_hold must be a PDPL legal hold id (PD-LEGAL_HOLD-nnn)' })
      .str('case_id', { max: 36, re: GUIDR, msg: 'case_id must be the eDiscovery case id (a GUID from Purview)' }).bool('export', { def: true })
      .date('from', {}).date('to', {}).rule((o) => (o.from && o.to && o.from > o.to ? 'to must be on or after from' : null)).done();
    if (r.status === 'cancelled') throw httpErr(409, r.id + ' was cancelled');
    if (r.legal && !['released', 'rejected'].includes(r.legal.status)) throw httpErr(409, 'a legal hold is already ' + r.legal.status.replace('_', ' ') + ' for ' + r.id);
    if (SECRETISH.test(b.reason) || SECRETISH.test(b.matter)) throw httpErr(400, 'matter / reason look like they contain a password');
    if (b.pdpl_hold) { const h = store.collection('pdpl_records').get(b.pdpl_hold); if (!h || h.kind !== 'legal_hold' || h.status !== 'active') throw httpErr(400, 'pdpl_hold: ' + b.pdpl_hold + ' is not an active PDPL legal hold'); }
    const upn = upnOfM(r); if (!upn) throw httpErr(409, 'the user address (UPN) is not known - set the UPN suffix in Directory settings');
    r.legal = { status: 'requested', upn, matter: b.matter, reason: b.reason, pdpl_hold: b.pdpl_hold || null, case_id: b.case_id || null, export: b.export, from: b.from || null, to: b.to || null, requested_by: who.user, requested_at: iso(), history: (r.legal && r.legal.history) || [] };
    hist(r, who, 'legal_requested', { matter: b.matter }); col().put(r);
    audit(who, 'offboarding.legal.requested', r.id, { matter: b.matter, pdpl_hold: b.pdpl_hold || null, case_id: b.case_id || null, export: b.export, from: b.from || null, to: b.to || null });
    return view(r, true);
  }
  // KQL over the custodian's mail (received) and files (lastmodifiedtime); empty = everything
  const legalQuery = (l) => (!l.from && !l.to ? '' : ['received', 'lastmodifiedtime'].map((f) => '(' + [l.from ? f + '>=' + l.from : null, l.to ? f + '<=' + l.to : null].filter(Boolean).join(' AND ') + ')').join(' OR '));
  async function legalRun(r) {
    const l = r.legal, X = (op, a) => LIC().ediscovery(op, a), steps = l.steps || [];
    const did = (k) => steps.some((x) => x.step === k && x.ok);
    const ok = (step, extra) => steps.push(Object.assign({ step, ok: true, at: iso() }, extra || {}));
    const desc = 'HR Offboarding ' + r.id + ' (' + r.username + '): ' + l.matter;
    try {
      if (l.status === 'approved') {
        if (!did('case')) {
          if (l.case_id) { const c = await X('case-get', { caseId: l.case_id }); if (!c) throw new Error('eDiscovery case ' + l.case_id + ' was not found'); if (/closed/i.test(c.status || '')) throw new Error('eDiscovery case ' + c.name + ' is closed - reopen it in Purview or name another'); l.case_name = c.name; }
          else { const c = await X('case-create', { name: ('Leaver ' + r.id + ' - ' + l.matter).slice(0, 120), description: desc, externalId: l.pdpl_hold || r.id }); l.case_id = c.id; l.case_name = c.name; l.case_created = true; }
          ok('case', { case_id: l.case_id });
        }
        if (!did('custodian')) { const c = await X('custodian', { caseId: l.case_id, upn: l.upn }); l.custodian_id = c.id; ok('custodian', { existing: !!c.existing }); }
        if (!did('sources')) { const u = await X('user-source', { caseId: l.case_id, custodianId: l.custodian_id, upn: l.upn }); l.source_id = u.id; l.included = u.included || 'mailbox,site'; ok('sources'); }
        if (!did('hold')) { await X('apply-hold', { caseId: l.case_id, custodianId: l.custodian_id }); ok('hold'); }
        Object.assign(l, { status: 'holding', error: null });
        hist(r, PSYS, 'legal_holding', { case_id: l.case_id });
        audit(PSYS, 'offboarding.legal.hold_requested', r.id, { case_id: l.case_id, case_created: !!l.case_created, custodian: l.upn, sources: l.included, approved_by: l.decided_by });
      }
      if (l.status === 'holding') {
        const h = await X('hold-status', { caseId: l.case_id, custodianId: l.custodian_id }); l.hold_status = h; l.checked_at = iso();
        if (/failed/i.test(h || '')) throw new Error('Purview reports the hold as ' + h + ' - check the case in Purview, then try again');
        if (/^applied$/i.test(h || '')) {
          Object.assign(l, { status: 'held', held_at: iso(), error: null });
          hist(r, PSYS, 'legal_held', { case_id: l.case_id });
          audit(PSYS, 'offboarding.legal.held', r.id, { case_id: l.case_id, custodian: l.upn, matter: l.matter });
          maybeComplete(r, PSYS);
        }
      }
      if (l.status === 'held' && l.export && !l.export_done && !l.error) {
        if (!did('search')) { const sr = await X('search-create', { caseId: l.case_id, custodianId: l.custodian_id, sourceId: l.source_id, name: ('Leaver ' + r.id + ' export').slice(0, 100), description: desc, query: legalQuery(l) }); l.search_id = sr.id; l.query = legalQuery(l); ok('search'); }
        if (!did('estimate')) { await X('estimate', { caseId: l.case_id, searchId: l.search_id }); ok('estimate'); }
        l.status = 'estimating';
      }
      if (l.status === 'estimating') {
        const e = await X('estimate-result', { caseId: l.case_id, searchId: l.search_id });
        if (e && /failed/i.test(e.status)) throw Object.assign(new Error('the Purview estimate failed - try again'), { phase: 'export' });
        if (e && /succeeded/i.test(e.status)) {
          l.estimate = { items: e.items, bytes: e.bytes, unindexed: e.unindexed, unindexed_bytes: e.unindexed_bytes, mailboxes: e.mailboxes, sites: e.sites, at: iso() };
          if (!did('export')) { l.export_started_at = iso(); await X('export', { caseId: l.case_id, searchId: l.search_id, name: ('Leaver ' + r.id + ' - ' + l.matter).slice(0, 100), description: desc }); ok('export'); }
          l.status = 'exporting';
          audit(PSYS, 'offboarding.legal.export_started', r.id, { case_id: l.case_id, items: e.items, bytes: e.bytes, unindexed: e.unindexed });
        }
      }
      if (l.status === 'exporting') {
        const o = await X('export-status', { caseId: l.case_id, since: l.export_started_at });
        if (o) l.export_op = { id: o.id, status: o.status, progress: o.progress, files: o.files };
        if (o && /failed/i.test(o.status)) throw Object.assign(new Error('the Purview export failed - try again'), { phase: 'export' });
        if (o && /succeeded/i.test(o.status)) {
          Object.assign(l, { status: 'exported', exported_at: iso(), export_done: true, error: null });
          hist(r, PSYS, 'legal_exported', { files: o.files.length });
          audit(PSYS, 'offboarding.legal.exported', r.id, { case_id: l.case_id, files: o.files.map((f) => ({ name: f.name, size: f.size })) });
          maybeComplete(r, PSYS);
        }
      }
      if (l.status === 'releasing') {
        const h = await X('hold-status', { caseId: l.case_id, custodianId: l.custodian_id }); l.hold_status = h;
        if (/^notApplied$/i.test(h || '')) {
          Object.assign(l, { status: 'released', released_at: iso(), error: null });
          hist(r, PSYS, 'legal_released', { case_id: l.case_id });
          audit(PSYS, 'offboarding.legal.released', r.id, { case_id: l.case_id, approved_by: l.release.decided_by, reason: l.release.reason });
        }
      }
      l.steps = steps.slice(-40);
    } catch (e) {
      l.steps = steps.slice(-40);
      if (e.phase === 'export') { l.status = 'held'; l.steps = l.steps.filter((x) => !['search', 'estimate', 'export'].includes(x.step)); }
      Object.assign(l, { error: String(e.message).slice(0, 300) + (e.http === 403 ? ' - the app registration lacks eDiscovery.ReadWrite.All (or the tenant has no eDiscovery licence)' : ''), failed_at: iso(), attempts: (l.attempts || 0) + 1 });
      hist(r, PSYS, 'legal_failed', { error: l.error });
      if (l.attempts === 1) audit(PSYS, 'offboarding.legal.failed', r.id, { case_id: l.case_id || null, error: l.error });
      warn('legal', 'offboarding: a legal hold step did not complete', { id: r.id, err: l.error });
    }
    col().put(r);
    return r;
  }
  async function decideLegal(id, input, who) {
    const r = get(id); person(who, 'approve a legal hold'); notLeaver(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why there is no hold' : null)).done();
    const l = r.legal; if (!l || l.status !== 'requested') throw httpErr(409, 'no legal hold is waiting for ' + r.id);
    if (same(l.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked for this legal hold and cannot also approve it');
    Object.assign(l, { status: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), note: b.note || '' });
    hist(r, who, 'legal_' + (b.decision === 'approve' ? 'approved' : 'rejected')); col().put(r);
    audit(who, 'offboarding.legal.' + (b.decision === 'approve' ? 'approved' : 'rejected'), r.id, { matter: l.matter, requested_by: l.requested_by, note: b.note || null });
    if (b.decision === 'approve') await legalRun(r);
    return view(get(r.id), true);
  }
  async function retryLegal(id, who) {
    const r = get(id); person(who, 'retry a legal hold step'); notLeaver(r, who, 'act');
    const l = r.legal; if (!l || !l.error) throw httpErr(409, 'no failed legal hold step to retry for ' + r.id);
    audit(who, 'offboarding.legal.retry', r.id, { status: l.status });
    l.error = null; await legalRun(r);
    return view(get(r.id), true);
  }
  function requestRelease(id, input, who) {
    const r = get(id); person(who, 'ask to release a legal hold');
    const b = body(input || {}).str('reason', { required: true, min: 10, max: 500 }).done();
    const l = r.legal; if (!l || !['held', 'estimating', 'exporting', 'exported'].includes(l.status)) throw httpErr(409, 'no legal hold in place for ' + r.id);
    if (l.pdpl_hold) { const h = store.collection('pdpl_records').get(l.pdpl_hold); if (h && h.status === 'active') throw httpErr(409, 'the PDPL legal hold ' + l.pdpl_hold + ' is still active - release it there first'); }
    l.release = { from: l.status, requested_by: who.user, requested_at: iso(), reason: b.reason };
    l.status = 'release_requested';
    hist(r, who, 'legal_release_requested'); col().put(r);
    audit(who, 'offboarding.legal.release_requested', r.id, { case_id: l.case_id, reason: b.reason });
    return view(r, true);
  }
  async function decideRelease(id, input, who) {
    const r = get(id); person(who, 'release a legal hold'); notLeaver(r, who, 'release');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the hold stays' : null)).done();
    const l = r.legal; if (!l || l.status !== 'release_requested') throw httpErr(409, 'no release is waiting for ' + r.id);
    if (same(l.release.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked for the release and cannot also approve it');
    Object.assign(l.release, { decided_by: who.user, decided_at: iso(), decision: b.decision, note: b.note || '' });
    if (b.decision === 'reject') {
      l.status = l.release.from; l.history = (l.history || []).concat([l.release]).slice(-20); l.release = null;
      hist(r, who, 'legal_release_rejected', { note: b.note }); col().put(r);
      audit(who, 'offboarding.legal.release_rejected', r.id, { case_id: l.case_id, note: b.note });
      return view(r, true);
    }
    try { await LIC().ediscovery('remove-hold', { caseId: l.case_id, custodianId: l.custodian_id }); }
    catch (e) { warn('legal-rel', 'offboarding: the legal hold could not be released', { id: r.id, err: String(e.message).slice(0, 160) }); throw httpErr(409, 'Purview refused the release: ' + String(e.message).slice(0, 200)); }
    l.status = 'releasing';
    hist(r, who, 'legal_release_approved'); col().put(r);
    audit(who, 'offboarding.legal.release_approved', r.id, { case_id: l.case_id, requested_by: l.release.requested_by, reason: l.release.reason });
    await legalRun(r);
    return view(get(r.id), true);
  }
  // poll Purview every run while something is under way; a failed step is retried hourly, five times, then waits for a person
  async function legalTick() {
    if (!legalOn()) return 0;
    let n = 0;
    for (const r of col().all((x) => x.legal && LWORK.concat(['held']).includes(x.legal.status))) {
      const l = r.legal;
      if (l.status === 'held' && !(l.export && !l.export_done)) continue;
      if (l.error && (!(l.failed_at && now() - Date.parse(l.failed_at) >= 3600000) || (l.attempts || 0) >= 5)) continue;
      l.error = null; await legalRun(r); n++;
    }
    return n;
  }
  // ---- meetings the leaver organises: created again by the new owner, then the leaver's one ended - never the other way round
  async function readCalendar(r) {
    const upn = upnOfM(r);
    if (!upn) return { status: 'read_failed', error: 'the user address (UPN) is not known - set the UPN suffix in Directory settings' };
    let d;
    try { d = await LIC().organizedMeetings(upn); }
    catch (e) { warn('cal-read', 'offboarding: the leaver\'s meetings could not be read', { id: r.id, err: String(e.message).slice(0, 160) }); return { status: 'read_failed', upn, error: String(e.message).slice(0, 240) + (e.http === 403 ? ' - the app registration lacks Calendars.ReadWrite' : '') }; }
    if (!d.found) return { status: 'not_needed', upn, meetings: [], note: 'the user is not in Entra ID' };
    return Object.assign({ upn, meetings: d.meetings, window_days: d.window_days, read_at: iso() }, d.meetings.length ? {} : { status: 'not_needed', note: 'no meeting with attendees organised by the leaver in the next ' + d.window_days + ' days' });
  }
  function checkCalendar(id, who) {
    const r = get(id); person(who, 'check meetings');
    if (!calOn()) throw httpErr(409, 'leavers\' meetings are off - Microsoft 365 licensing settings (HR Onboarding)');
    return readCalendar(r).then((c) => {
      r.calendar_check = Object.assign({ by: who.user, at: iso() }, c); col().put(r);
      audit(who, 'offboarding.calendar.check', r.id, { meetings: (c.meetings || []).length, error: c.error || null });
      return view(r, true);
    });
  }
  async function startCalendar(r) {
    if (r.calendar || !calOn()) return;
    const c = await readCalendar(r);
    const mode = (r.disable && r.disable.calendar) || 'ask', mgr = managerAddr(r);
    if (!c.status) {
      if (mode === 'none') Object.assign(c, { status: 'kept', decided_by: r.disable.approved_by, decided_at: r.disable.approved_at, decided_with: 'disable approval', note: 'left as they are - decided with the disable approval' });
      else if (mode === 'cancel' || (mode === 'transfer' && mgr)) Object.assign(c, { status: 'approved', owner: mode === 'transfer' ? mgr : null, mode, exclude: [], decided_by: r.disable.approved_by, decided_at: r.disable.approved_at, decided_with: 'disable approval' });
      else Object.assign(c, { status: 'proposed', owner: mgr || '', mode: 'transfer', exclude: [] }, mode === 'transfer' ? { note: 'the manager\'s address is not known - an administrator names the new organiser' } : {});
    }
    r.calendar = Object.assign(c, { proposed_at: iso() });
    hist(r, CSYS, 'calendar_' + c.status, { meetings: (c.meetings || []).length });
    audit(CSYS, 'offboarding.calendar.read', r.id, { status: c.status, meetings: (c.meetings || []).length, recurring: (c.meetings || []).filter((m) => m.recurring).length, external_attendees: (c.meetings || []).reduce((n, m) => n + (m.external || 0), 0), error: c.error || null });
    if (c.status === 'approved') await moveMeetings(r);
  }
  async function moveMeetings(r) {
    const c = r.calendar, steps = c.steps || [], L = LIC();
    const did = (k) => steps.some((x) => x.step === k && x.ok);
    const add = (step, ok, err, extra) => { steps.push(Object.assign({ step, ok, at: iso() }, ok ? {} : { error: String(err || '').slice(0, 200) }, extra || {})); return ok; };
    const todo = (c.meetings || []).filter((m) => !m.private && !(c.exclude || []).includes(m.id));
    const crypto = require('crypto');
    const note = '<p><i>This meeting was organised by ' + escH(r.name) + (', who has left ' + ZYB_ORG.short + '. It is now organised by ') + escH(c.owner || '') + ' (HR Offboarding ' + escH(r.id) + ').</i></p><hr>';
    const comment = c.mode === 'transfer' ? r.name + (' has left ' + ZYB_ORG.short + '. This meeting is now organised by ') + c.owner + ' - you will receive a new invitation.' : r.name + (' has left ' + ZYB_ORG.short + ' and this meeting is cancelled. Contact ') + (managerAddr(r) || r.manager) + ' if it is still needed.';
    try {
      for (const m of todo) {
        if (c.mode === 'transfer' && !did('create:' + m.id)) {
          try { const x = await L.recreateMeeting(c.upn, m.id, c.owner, { note, transactionId: 'sentra-' + r.id + '-' + crypto.createHash('sha256').update(m.id).digest('hex').slice(0, 24) }); add('create:' + m.id, true, null, { new_id: x.id }); }
          catch (e) { add('create:' + m.id, false, e.message); continue; }   // the leaver's meeting stays until its replacement exists
        }
        if (!did('retire:' + m.id)) { try { const x = await L.retireMeeting(c.upn, m.id, comment); add('retire:' + m.id, true, null, { done: x.done }); } catch (e) { add('retire:' + m.id, false, e.message); } }
      }
      c.steps = steps.slice(-800);
      const need = todo.flatMap((m) => (c.mode === 'transfer' ? ['create:' + m.id] : []).concat(['retire:' + m.id])), left = need.filter((k) => !did(k));
      if (left.length) throw new Error('partly done - ' + left.length + ' change(s) left: ' + left.slice(0, 3).map((k) => { const m = todo.find((x) => x.id === k.slice(k.indexOf(':') + 1)); return (k.startsWith('create') ? 'create "' : 'end "') + (m ? m.subject : '?') + '": ' + ((steps.filter((x) => x.step === k).pop() || {}).error || ''); }).join('; '));
      c.results = todo.map((m) => ({ id: m.id, subject: m.subject, recurring: m.recurring, recreated: c.mode === 'transfer', retired: ((steps.filter((x) => x.step === 'retire:' + m.id && x.ok).pop()) || {}).done || null }));
      Object.assign(c, { status: 'transferred', transferred_at: iso(), error: null });
      hist(r, CSYS, 'calendar_transferred', { meetings: c.results.length, owner: c.owner, mode: c.mode });
      audit(CSYS, 'offboarding.calendar.transferred', r.id, { owner: c.owner, mode: c.mode, meetings: c.results.length, skipped_private: (c.meetings || []).filter((m) => m.private).length, excluded: (c.exclude || []).length, approved_by: c.decided_by });
      maybeComplete(r, CSYS);
    } catch (e) {
      c.steps = steps.slice(-800);
      Object.assign(c, { error: String(e.message).slice(0, 400), failed_at: iso(), attempts: (c.attempts || 0) + 1 });
      hist(r, CSYS, 'calendar_failed', { error: c.error });
      if (c.attempts === 1) audit(CSYS, 'offboarding.calendar.failed', r.id, { owner: c.owner, error: c.error });
      warn('cal', 'offboarding: the meetings could not all be handed over', { id: r.id, err: c.error });
    }
    col().put(r);
    return r;
  }
  async function decideCalendar(id, input, who) {
    const r = get(id); person(who, 'hand over meetings'); notLeaver(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).oneOf('mode', ['transfer', 'cancel'], { def: 'transfer' }).str('owner', { max: 254 })
      .list('exclude', { max: 300, item: 'str', itemMax: 400, unique: true }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the meetings stay as they are' : null)).done();
    const c = r.calendar; if (!c || c.status !== 'proposed') throw httpErr(409, 'no meetings decision is waiting for ' + r.id + (c ? ' (it is ' + c.status + ')' : ''));
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also decide the meetings');
    if (b.decision === 'reject') {
      Object.assign(c, { status: 'kept', decided_by: who.user, decided_at: iso(), note: b.note });
      hist(r, who, 'calendar_kept', { note: b.note }); maybeComplete(r, who); col().put(r);
      audit(who, 'offboarding.calendar.kept', r.id, { meetings: (c.meetings || []).length, note: b.note });
      return view(r, true);
    }
    const ids = (c.meetings || []).map((m) => m.id), ex = b.exclude || [];
    const unknown = ex.find((x) => !ids.includes(x)); if (unknown) throw httpErr(400, 'exclude: not one of this leaver\'s meetings');
    let owner = null;
    if (b.mode === 'transfer') {
      owner = String(b.owner || c.owner || '').toLowerCase();
      if (!ADDR.test(owner)) throw httpErr(400, 'owner: name the new organiser\'s address (the manager by default)');
      if (owner === String(c.upn || '').toLowerCase() || same(owner.split('@')[0], r.username)) throw httpErr(400, 'owner: the leaver cannot be the new organiser');
    }
    if (!(c.meetings || []).some((m) => !m.private && !ex.includes(m.id))) throw httpErr(409, 'nothing left to hand over - every meeting is private or excluded; keep them (reject with a note)');
    Object.assign(c, { status: 'approved', owner, mode: b.mode, exclude: ex, decided_by: who.user, decided_at: iso(), note: b.note || '' });
    hist(r, who, 'calendar_approved', { owner, mode: b.mode, excluded: ex.length }); col().put(r);
    audit(who, 'offboarding.calendar.approved', r.id, { owner, mode: b.mode, excluded: ex.length, meetings: (c.meetings || []).length });
    await moveMeetings(r);
    return view(get(r.id), true);
  }
  async function retryCalendar(id, who) {
    const r = get(id); person(who, 'retry the meetings step'); notLeaver(r, who, 'act');
    const c = r.calendar;
    if (c && c.status === 'read_failed') { r.calendar = null; await startCalendar(r); col().put(r); return view(r, true); }
    if (!c || c.status !== 'approved') throw httpErr(409, 'no approved meetings hand-over to retry');
    audit(who, 'offboarding.calendar.retry', r.id, {});
    await moveMeetings(r);
    return view(get(r.id), true);
  }
  function manualCalendar(id, input, who) {
    const r = get(id); person(who, 'record a meetings hand-over'); notLeaver(r, who, 'record');
    const b = body(input || {}).str('reference', { required: true, min: 3, max: 200 }).done();
    if (SECRETISH.test(b.reference)) throw httpErr(400, 'reference looks like it contains a password');
    const c = r.calendar;
    if (!c || CDONE.includes(c.status)) throw httpErr(409, 'no meetings hand-over is open for ' + r.id);
    if (c.status === 'proposed') throw httpErr(409, 'the hand-over must be decided first');
    Object.assign(c, { status: 'transferred_manually', by: who.user, at: iso(), reference: b.reference, error: null });
    hist(r, who, 'calendar_manual', { reference: b.reference }); maybeComplete(r, who); col().put(r);
    audit(who, 'offboarding.calendar.manual', r.id, { reference: b.reference });
    return view(r, true);
  }
  async function calendarTick() {
    if (!calOn()) return 0;
    let n = 0;
    const hourAgo = (x) => !x || now() - Date.parse(x) >= 3600000;
    for (const r of col().all((x) => x.status === 'in_progress' && x.disabled && x.disabled.at && !x.disabled.reenabled_at)) {
      const c = r.calendar;
      if (!c) { await startCalendar(r); maybeComplete(r, CSYS); col().put(r); n++; continue; }
      if (c.status === 'read_failed' && hourAgo(c.proposed_at) && (c.reads || 0) < 5) { const k = (c.reads || 0) + 1; r.calendar = null; await startCalendar(r); if (r.calendar.status === 'read_failed') r.calendar.reads = k; maybeComplete(r, CSYS); col().put(r); n++; continue; }
      if (c.status === 'approved' && c.failed_at && hourAgo(c.failed_at) && (c.attempts || 0) < 5) { await moveMeetings(r); n++; }
    }
    return n;
  }
  // ---- Microsoft 365 groups and Teams the leaver owns: handed to the manager (or a named person), read back, never orphaned
  async function readTeams(r) {
    const upn = upnOfM(r);
    if (!upn) return { status: 'read_failed', error: 'the user address (UPN) is not known - set the UPN suffix in Directory settings' };
    let d;
    try { d = await LIC().ownedGroups(upn); }
    catch (e) { warn('tm-read', 'offboarding: the groups the leaver owns could not be read', { id: r.id, err: String(e.message).slice(0, 160) }); return { status: 'read_failed', upn, error: String(e.message).slice(0, 240) + (e.http === 403 ? ' - the app registration lacks Group.ReadWrite.All / Directory.Read.All' : '') }; }
    if (!d.found) return { status: 'not_needed', upn, groups: [], note: 'the user is not in Entra ID' };
    const groups = d.groups.map((g) => Object.assign({}, g, { sole: g.other_active_owners === 0 }));
    return Object.assign({ upn, leaver_id: d.user_id, groups, read_at: iso() }, groups.length ? {} : { status: 'not_needed', note: 'the leaver owns no Microsoft 365 group or team' });
  }
  async function startTeams(r) {
    if (r.teams || !teamsOn()) return;
    const t = await readTeams(r);
    const mode = (r.disable && r.disable.teams) || 'ask', mgr = managerAddr(r);
    if (!t.status) {
      if (mode === 'none') Object.assign(t, { status: 'kept', decided_by: r.disable.approved_by, decided_at: r.disable.approved_at, decided_with: 'disable approval', note: 'left as they are - decided with the disable approval' });
      else if ((mode === 'transfer' || mode === 'add') && mgr) Object.assign(t, { status: 'approved', owner: mgr, mode, decided_by: r.disable.approved_by, decided_at: r.disable.approved_at, decided_with: 'disable approval' });
      else Object.assign(t, { status: 'proposed', owner: mgr || '', mode: mode === 'add' ? 'add' : 'transfer' }, mode !== 'ask' ? { note: 'the manager\'s address is not known - an administrator names the new owner' } : {});
    }
    r.teams = Object.assign(t, { proposed_at: iso() });
    hist(r, GSYS, 'teams_' + t.status, { groups: (t.groups || []).length });
    audit(GSYS, 'offboarding.teams.read', r.id, { status: t.status, groups: (t.groups || []).map((g) => ({ name: g.name, team: g.team, sole: g.sole })), error: t.error || null });
    if ((t.groups || []).some((g) => g.sole)) warn('tm-sole', 'offboarding: a leaver is the only owner of a group or team', { id: r.id, groups: t.groups.filter((g) => g.sole).length });
    if (t.status === 'approved') await transferTeams(r);
  }
  async function transferTeams(r) {
    const t = r.teams, steps = t.steps || [], L = LIC();
    const did = (k) => steps.some((x) => x.step === k && x.ok);
    const add = (step, ok, err, extra) => { steps.push(Object.assign({ step, ok, at: iso() }, ok ? {} : { error: String(err || '').slice(0, 200) }, extra || {})); return ok; };
    try {
      if (!t.owner_id) {
        const o = await L.userRef(t.owner);
        if (!o) throw new Error('the new owner ' + t.owner + ' is not in Entra ID');
        if (!o.enabled) throw new Error('the new owner ' + t.owner + ' is disabled in Entra ID');
        t.owner_id = o.id;
      }
      for (const g of t.groups || []) {
        if (!did('add:' + g.id)) {
          if ((g.owners || []).includes(String(t.owner).toLowerCase())) add('add:' + g.id, true, null, { already: true });
          else { try { await L.addOwner(g.id, t.owner_id, g.team); add('add:' + g.id, true); } catch (e) { add('add:' + g.id, false, e.message); continue; } }
        }
        if (t.mode === 'transfer' && !did('remove:' + g.id)) { try { await L.removeOwner(g.id, t.leaver_id); add('remove:' + g.id, true); } catch (e) { add('remove:' + g.id, false, e.message); } }
      }
      t.steps = steps.slice(-400);
      const need = (t.groups || []).flatMap((g) => ['add:' + g.id].concat(t.mode === 'transfer' ? ['remove:' + g.id] : []));
      const left = need.filter((k) => !did(k));
      if (left.length) throw new Error('partly done - ' + left.length + ' change(s) left: ' + left.slice(0, 3).map((k) => { const g = t.groups.find((x) => x.id === k.split(':')[1]); return (k.startsWith('add') ? 'add owner to ' : 'remove the leaver from ') + (g ? g.name : k) + ': ' + ((steps.filter((x) => x.step === k).pop() || {}).error || ''); }).join('; '));
      t.results = (t.groups || []).map((g) => ({ id: g.id, name: g.name, team: g.team, added: !steps.some((x) => x.step === 'add:' + g.id && x.already), already_owner: steps.some((x) => x.step === 'add:' + g.id && x.already), leaver_removed: t.mode === 'transfer' }));
      Object.assign(t, { status: 'transferred', transferred_at: iso(), error: null });
      hist(r, GSYS, 'teams_transferred', { groups: t.results.length, owner: t.owner });
      audit(GSYS, 'offboarding.teams.transferred', r.id, { owner: t.owner, mode: t.mode, groups: t.results.map((x) => ({ name: x.name, team: x.team, added: x.added, leaver_removed: x.leaver_removed })), approved_by: t.decided_by });
      maybeComplete(r, GSYS);
    } catch (e) {
      t.steps = steps.slice(-400);
      Object.assign(t, { error: String(e.message).slice(0, 400), failed_at: iso(), attempts: (t.attempts || 0) + 1 });
      hist(r, GSYS, 'teams_failed', { error: t.error });
      if (t.attempts === 1) audit(GSYS, 'offboarding.teams.failed', r.id, { owner: t.owner, error: t.error });
      warn('tm', 'offboarding: the groups and Teams could not all be handed over', { id: r.id, err: t.error });
    }
    col().put(r);
    return r;
  }
  async function decideTeams(id, input, who) {
    const r = get(id); person(who, 'hand over groups and Teams'); notLeaver(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('owner', { max: 254 }).oneOf('mode', ['transfer', 'add'], { def: 'transfer' }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the groups stay as they are' : null)).done();
    const t = r.teams; if (!t || t.status !== 'proposed') throw httpErr(409, 'no groups and Teams decision is waiting for ' + r.id + (t ? ' (it is ' + t.status + ')' : ''));
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also decide the groups and Teams');
    if (b.decision === 'reject') {
      Object.assign(t, { status: 'kept', decided_by: who.user, decided_at: iso(), note: b.note });
      hist(r, who, 'teams_kept', { note: b.note }); maybeComplete(r, who); col().put(r);
      audit(who, 'offboarding.teams.kept', r.id, { groups: (t.groups || []).map((g) => g.name), sole: (t.groups || []).filter((g) => g.sole).map((g) => g.name), note: b.note });
      return view(r, true);
    }
    const owner = String(b.owner || t.owner || '').toLowerCase();
    if (!ADDR.test(owner)) throw httpErr(400, 'owner: name the new owner\'s address (the manager by default)');
    if (owner === String(t.upn || '').toLowerCase() || same(owner.split('@')[0], r.username)) throw httpErr(400, 'owner: the leaver cannot be the new owner');
    Object.assign(t, { status: 'approved', owner, owner_id: null, mode: b.mode, decided_by: who.user, decided_at: iso(), note: b.note || '' });
    hist(r, who, 'teams_approved', { owner, mode: b.mode }); col().put(r);
    audit(who, 'offboarding.teams.approved', r.id, { owner, mode: b.mode, groups: (t.groups || []).length });
    await transferTeams(r);
    return view(get(r.id), true);
  }
  async function retryTeams(id, who) {
    const r = get(id); person(who, 'retry the groups and Teams step'); notLeaver(r, who, 'act');
    const t = r.teams;
    if (t && t.status === 'read_failed') { r.teams = null; await startTeams(r); col().put(r); return view(r, true); }
    if (!t || t.status !== 'approved') throw httpErr(409, 'no approved groups and Teams hand-over to retry');
    audit(who, 'offboarding.teams.retry', r.id, {});
    await transferTeams(r);
    return view(get(r.id), true);
  }
  function manualTeams(id, input, who) {
    const r = get(id); person(who, 'record a groups and Teams hand-over'); notLeaver(r, who, 'record');
    const b = body(input || {}).str('reference', { required: true, min: 3, max: 200 }).done();
    if (SECRETISH.test(b.reference)) throw httpErr(400, 'reference looks like it contains a password');
    const t = r.teams;
    if (!t || TDONE.includes(t.status)) throw httpErr(409, 'no groups and Teams hand-over is open for ' + r.id);
    if (t.status === 'proposed') throw httpErr(409, 'the hand-over must be decided first');
    Object.assign(t, { status: 'transferred_manually', by: who.user, at: iso(), reference: b.reference, error: null });
    hist(r, who, 'teams_manual', { reference: b.reference }); maybeComplete(r, who); col().put(r);
    audit(who, 'offboarding.teams.manual', r.id, { reference: b.reference });
    return view(r, true);
  }
  async function teamsTick() {
    if (!teamsOn()) return 0;
    let n = 0;
    const hourAgo = (x) => !x || now() - Date.parse(x) >= 3600000;
    for (const r of col().all((x) => x.status === 'in_progress' && x.disabled && x.disabled.at && !x.disabled.reenabled_at)) {
      const t = r.teams;
      if (!t) { await startTeams(r); maybeComplete(r, GSYS); col().put(r); n++; continue; }
      if (t.status === 'read_failed' && hourAgo(t.proposed_at) && (t.reads || 0) < 5) { const k = (t.reads || 0) + 1; r.teams = null; await startTeams(r); if (r.teams.status === 'read_failed') r.teams.reads = k; maybeComplete(r, GSYS); col().put(r); n++; continue; }
      if (t.status === 'approved' && t.failed_at && hourAgo(t.failed_at) && (t.attempts || 0) < 5) { await transferTeams(r); n++; }
    }
    return n;
  }
  // ---- OneDrive: handed to the manager (or named people) for an approved period, then taken back - exactly what was added
  async function readOneDrive(r) {
    const upn = upnOfM(r);
    if (!upn) return { status: 'read_failed', error: 'the user address (UPN) is not known - set the UPN suffix in Directory settings' };
    const x = await EXO.run('get-onedrive', { identity: upn });
    if (!x.ok) { warn('od-read', 'offboarding: the OneDrive could not be read', { id: r.id, err: String(x.error).slice(0, 160) }); return { status: 'read_failed', upn, error: String(x.error).slice(0, 240) }; }
    const d = x.data || {};
    if (!d.found) return { status: 'not_needed', upn, note: 'no OneDrive for this user (it was never opened)' };
    if (!ONEDRIVE.test(String(d.url || ''))) return { status: 'read_failed', upn, error: 'the address SharePoint gave is not a OneDrive address' };
    const warnings = [];
    if (d.lock && !/^unlock/i.test(d.lock)) warnings.push('the OneDrive is locked (' + d.lock + ') - a SharePoint administrator unlocks it first');
    if (reclaimOn()) warnings.push('removing the leaver\'s licence makes this OneDrive unlicensed: Microsoft makes unlicensed OneDrive accounts read-only and archives or deletes them after 93 days - copy what the business needs before then');
    return { upn, url: String(d.url).replace(/\/$/, ''), storage_mb: Number(d.storage_mb) || 0, last_modified: d.last_modified || null, owner: d.owner || null,
      admins_before: (d.admins || []).map((a) => String(a).toLowerCase()).filter((a) => ADDR.test(a)).slice(0, 20), warnings, read_at: iso() };
  }
  async function startOneDrive(r) {
    if (r.onedrive || !spoOn()) return;
    const o = await readOneDrive(r);
    const mode = (r.disable && r.disable.onedrive) || 'ask', mgr = managerAddr(r);
    if (!o.status) {
      if (mode === 'none') Object.assign(o, { status: 'declined', decided_by: r.disable.approved_by, decided_at: r.disable.approved_at, decided_with: 'disable approval', note: 'not handed over - decided with the disable approval' });
      else if (mode === 'manager' && mgr) Object.assign(o, { status: 'approved', delegates: [mgr], days: r.disable.onedrive_days || odDays(), decided_by: r.disable.approved_by, decided_at: r.disable.approved_at, decided_with: 'disable approval' });
      else Object.assign(o, { status: 'proposed', delegates: mgr ? [mgr] : [], days: odDays() }, mode === 'manager' ? { note: 'the manager\'s address is not known - an administrator names who gets access' } : {});
    }
    r.onedrive = Object.assign(o, { proposed_at: iso() });
    hist(r, OSYS, 'onedrive_' + o.status, { url: o.url || null });
    audit(OSYS, 'offboarding.onedrive.read', r.id, { status: o.status, url: o.url || null, storage_mb: o.storage_mb || null, error: o.error || null });
    if (o.status === 'approved') await grantOneDrive(r);
  }
  async function grantOneDrive(r) {
    const o = r.onedrive, steps = o.steps || [];
    const did = (k) => steps.some((x) => x.step === k && x.ok);
    try {
      for (const d of o.delegates || []) {
        if (did('grant:' + d)) continue;
        if ((o.admins_before || []).includes(d)) { steps.push({ step: 'grant:' + d, ok: true, at: iso(), note: 'already an administrator of this OneDrive' }); continue; }
        const x = await EXO.run('add-site-admin', { site: o.url, user: d });
        const ok = x.ok && (x.data || {}).granted === true;
        steps.push(Object.assign({ step: 'grant:' + d, ok, at: iso(), added: ok }, ok ? {} : { error: String(x.ok ? 'read back: ' + d + ' is not an administrator' : x.error).slice(0, 200) }));
      }
      o.steps = steps.slice(-40);
      const failed = (o.delegates || []).filter((d) => !did('grant:' + d));
      if (failed.length) throw new Error('partly done - ' + failed.map((d) => d + ': ' + ((steps.filter((x) => x.step === 'grant:' + d).pop() || {}).error || 'not done')).join('; '));
      const added = (o.delegates || []).filter((d) => steps.some((x) => x.step === 'grant:' + d && x.added));
      Object.assign(o, { status: 'granted', granted_at: iso(), access_until: new Date(now() + o.days * DAY).toISOString(), added, already: (o.delegates || []).filter((d) => !added.includes(d)), error: null });
      hist(r, OSYS, 'onedrive_granted', { delegates: o.delegates, until: o.access_until });
      audit(OSYS, 'offboarding.onedrive.granted', r.id, { url: o.url, delegates: o.delegates, added, until: o.access_until, approved_by: o.decided_by });
      maybeComplete(r, OSYS);
    } catch (e) {
      o.steps = steps.slice(-40);
      Object.assign(o, { error: String(e.message).slice(0, 300), failed_at: iso(), attempts: (o.attempts || 0) + 1 });
      hist(r, OSYS, 'onedrive_failed', { error: o.error });
      if (o.attempts === 1) audit(OSYS, 'offboarding.onedrive.failed', r.id, { url: o.url, error: o.error });
      warn('od', 'offboarding: the OneDrive access could not be given', { id: r.id, err: o.error });
    }
    col().put(r);
    return r;
  }
  // takes back only the people the platform added; someone who was an administrator before keeps it
  async function endOneDrive(r, reason, who) {
    const o = r.onedrive, w = who || OSYS, removed = o.removed || [];
    try {
      for (const d of (o.added || []).filter((x) => !removed.includes(x))) {
        const x = await EXO.run('remove-site-admin', { site: o.url, user: d });
        if (!(x.ok && (x.data || {}).removed === true)) throw new Error(d + ': ' + (x.ok ? 'read back: still an administrator' : x.error));
        removed.push(d);
      }
      Object.assign(o, { status: 'ended', ended_at: iso(), end_reason: reason, ended_by: w.user, removed, end_error: null });
      hist(r, w, 'onedrive_ended', { reason, removed });
      audit(w, 'offboarding.onedrive.ended', r.id, { url: o.url, removed, kept: o.already || [], reason });
    } catch (e) {
      Object.assign(o, { removed, end_error: String(e.message).slice(0, 300), end_failed_at: iso(), end_attempts: (o.end_attempts || 0) + 1, end_reason: reason });
      hist(r, w, 'onedrive_end_failed', { error: o.end_error });
      if (o.end_attempts === 1) audit(w, 'offboarding.onedrive.end_failed', r.id, { url: o.url, error: o.end_error });
      warn('od-end', 'offboarding: the OneDrive access could not be taken back', { id: r.id, err: o.end_error });
    }
    col().put(r);
    return r;
  }
  const isDelegate = (o, who) => (o.delegates || []).some((d) => same(d, who.user) || same(d.split('@')[0], who.user));
  function delegatesOf(list, r) {
    const ds = (list || []).map((x) => String(x).trim().toLowerCase()).filter(Boolean);
    const bad = ds.find((x) => !ADDR.test(x)); if (bad) throw httpErr(400, 'delegates: ' + bad + ' is not a user address');
    if (ds.some((x) => x === String((r.onedrive && r.onedrive.upn) || '').toLowerCase() || same(x.split('@')[0], r.username))) throw httpErr(400, 'delegates: the leaver cannot be given their own OneDrive');
    if (!ds.length) throw httpErr(400, 'delegates: name at least one person (the manager by default)');
    return ds;
  }
  async function decideOneDrive(id, input, who) {
    const r = get(id); person(who, 'hand over a OneDrive'); notLeaver(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).list('delegates', { max: 5, item: 'str', itemMax: 254, unique: true })
      .num('days', { min: 7, max: 365 }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the OneDrive is not handed over' : null))
      .rule((o) => (o.days !== undefined && !Number.isInteger(o.days) ? 'days must be a whole number' : null)).done();
    const o = r.onedrive; if (!o || o.status !== 'proposed') throw httpErr(409, 'no OneDrive decision is waiting for ' + r.id + (o ? ' (it is ' + o.status + ')' : ''));
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also decide the OneDrive');
    if (b.decision === 'reject') {
      Object.assign(o, { status: 'declined', decided_by: who.user, decided_at: iso(), note: b.note });
      hist(r, who, 'onedrive_declined', { note: b.note }); maybeComplete(r, who); col().put(r);
      audit(who, 'offboarding.onedrive.declined', r.id, { url: o.url, note: b.note });
      return view(r, true);
    }
    const ds = delegatesOf(b.delegates || o.delegates, r);
    Object.assign(o, { status: 'approved', delegates: ds, days: b.days || o.days || odDays(), decided_by: who.user, decided_at: iso(), note: b.note || '' });
    hist(r, who, 'onedrive_approved', { delegates: ds, days: o.days }); col().put(r);
    audit(who, 'offboarding.onedrive.approved', r.id, { url: o.url, delegates: ds, days: o.days });
    await grantOneDrive(r);
    return view(get(r.id), true);
  }
  function extendOneDrive(id, input, who) {
    const r = get(id); person(who, 'extend OneDrive access'); notLeaver(r, who, 'extend');
    const b = body(input || {}).num('days', { required: true, min: 1, max: 365 }).str('reason', { required: true, min: 5, max: 300 })
      .rule((o) => (!Number.isInteger(o.days) ? 'days must be a whole number' : null)).done();
    const o = r.onedrive; if (!o || o.status !== 'granted') throw httpErr(409, 'no OneDrive access is running for ' + r.id);
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot extend the access');
    if (isDelegate(o, who)) throw httpErr(403, 'four eyes: ' + who.user + ' has this access and cannot extend it - another administrator does');
    const until = Date.parse(o.access_until) + b.days * DAY, cap = Date.parse(o.granted_at) + 365 * DAY;
    if (until > cap) throw httpErr(400, 'days: at most 365 days from when the access started (' + new Date(cap).toISOString().slice(0, 10) + ')');
    o.extensions = (o.extensions || []).concat([{ by: who.user, at: iso(), days: b.days, reason: b.reason, from: o.access_until }]).slice(-20);
    o.access_until = new Date(until).toISOString();
    hist(r, who, 'onedrive_extended', { days: b.days, until: o.access_until }); col().put(r);
    audit(who, 'offboarding.onedrive.extended', r.id, { url: o.url, days: b.days, until: o.access_until, reason: b.reason });
    return view(r, true);
  }
  async function endOneDriveNow(id, input, who) {
    const r = get(id); person(who, 'end OneDrive access');
    const b = body(input || {}).str('reason', { required: true, min: 5, max: 300 }).done();
    const o = r.onedrive; if (!o || o.status !== 'granted') throw httpErr(409, 'no OneDrive access is running for ' + r.id);
    audit(who, 'offboarding.onedrive.end_requested', r.id, { reason: b.reason });
    await endOneDrive(r, b.reason, who);
    return view(get(r.id), true);
  }
  async function retryOneDrive(id, who) {
    const r = get(id); person(who, 'retry the OneDrive step'); notLeaver(r, who, 'act');
    const o = r.onedrive;
    if (o && o.status === 'read_failed') { r.onedrive = null; await startOneDrive(r); col().put(r); return view(r, true); }
    if (o && o.status === 'approved') { audit(who, 'offboarding.onedrive.retry', r.id, {}); await grantOneDrive(r); return view(get(r.id), true); }
    if (o && o.status === 'granted' && o.end_error) { audit(who, 'offboarding.onedrive.retry', r.id, { end: true }); await endOneDrive(r, o.end_reason || 'the approved period ended', who); return view(get(r.id), true); }
    throw httpErr(409, 'nothing to retry on the OneDrive step');
  }
  function manualOneDrive(id, input, who) {
    const r = get(id); person(who, 'record a OneDrive hand-over'); notLeaver(r, who, 'record');
    const b = body(input || {}).str('reference', { required: true, min: 3, max: 200 }).done();
    if (SECRETISH.test(b.reference)) throw httpErr(400, 'reference looks like it contains a password');
    const o = r.onedrive;
    if (!o || ODONE.includes(o.status)) throw httpErr(409, 'no OneDrive hand-over is open for ' + r.id);
    if (o.status === 'proposed') throw httpErr(409, 'the hand-over must be decided first');
    Object.assign(o, { status: 'granted_manually', by: who.user, at: iso(), reference: b.reference, error: null });
    hist(r, who, 'onedrive_manual', { reference: b.reference }); maybeComplete(r, who); col().put(r);
    audit(who, 'offboarding.onedrive.manual', r.id, { reference: b.reference });
    return view(r, true);
  }
  // start after the disable; retry a failed read / grant hourly (5 times); take the access back when the period ends
  async function onedriveTick() {
    if (!spoOn()) return 0;
    let n = 0;
    const hourAgo = (t) => !t || now() - Date.parse(t) >= 3600000;
    for (const r of col().all((x) => x.status !== 'cancelled' && x.disabled && x.disabled.at)) {
      const o = r.onedrive;
      if (!o) { if (r.status === 'in_progress' && !r.disabled.reenabled_at) { await startOneDrive(r); maybeComplete(r, OSYS); col().put(r); n++; } continue; }
      if (o.status === 'read_failed' && hourAgo(o.proposed_at) && (o.reads || 0) < 5) { const k = (o.reads || 0) + 1; r.onedrive = null; await startOneDrive(r); if (r.onedrive.status === 'read_failed') r.onedrive.reads = k; maybeComplete(r, OSYS); col().put(r); n++; continue; }
      if (o.status === 'approved' && o.failed_at && hourAgo(o.failed_at) && (o.attempts || 0) < 5) { await grantOneDrive(r); n++; continue; }
      if (o.status === 'granted' && Date.parse(o.access_until) <= now() && hourAgo(o.end_failed_at) && (o.end_attempts || 0) < 5) { await endOneDrive(r, o.end_reason || 'the approved period ended'); n++; }
    }
    return n;
  }
  async function mailboxTick() {
    if (!EXO.enabled()) return 0;
    let n = 0;
    for (const r of col().all((x) => x.status === 'in_progress' && x.disabled && x.disabled.at)) {
      if (!r.mailbox) { await startMailbox(r); col().put(r); n++; continue; }
      if (r.mailbox.status === 'read_failed') { r.mailbox = null; await startMailbox(r); col().put(r); n++; }
      else if (r.mailbox.status === 'approved' && r.mailbox.failed_at && now() - Date.parse(r.mailbox.failed_at) >= 3600000 && (r.mailbox.attempts || 0) < 5) { await convertNow(r); n++; }
    }
    return n;
  }

  async function reclaimTick() {
    if (!reclaimOn()) return 0;
    let n = 0;
    for (const r of col().all((x) => x.status === 'in_progress' && x.disabled && x.disabled.at)) {
      if (!r.reclaim) { await startReclaim(r); maybeComplete(r, LSYS); col().put(r); n++; continue; }
      const q = r.reclaim;
      if (q.status === 'read_failed') { const prev = q; r.reclaim = null; await startReclaim(r); r.reclaim.due_at = prev.due_at; col().put(r); n++; }
      else if (q.status === 'approved' && Date.parse(q.due_at) <= now() && !(q.failed_at && now() - Date.parse(q.failed_at) < 3600000)) { await doReclaim(r); n++; }
    }
    return n;
  }

  async function runDue(who) {
    await forwardingTick();
    await mailboxTick();
    await onedriveTick();
    await teamsTick();
    await calendarTick();
    await legalTick();
    await devicesTick();
    await appsTick();
    await reclaimTick();
    if (!auto()) return { ran: 0, note: 'automatic disabling is off' };
    let ran = 0, ok = 0;
    for (const r of col().all((x) => x.status === 'in_progress' && x.disable && x.disable.approved_by && !(x.disabled && x.disabled.at))) {
      if (Date.parse(dueAt(r)) > now()) continue;
      const f = r.disabled || {};
      if (!who && f.failed_at && (f.attempts >= 3 || now() - Date.parse(f.failed_at) < 3600000)) continue;
      ran++; await disableNow(r); if (r.disabled.at) ok++;
    }
    if (who && ran) audit(who, 'offboarding.run', 'due', { ran, disabled: ok });
    return { ran, disabled: ok, failed: ran - ok };
  }
  async function retry(id, who) {
    const r = get(id); person(who, 'disable an account'); notLeaver(r, who, 'act');
    if (!(r.disable && r.disable.approved_by)) throw httpErr(409, 'the disable has not been approved');
    if (r.disabled && r.disabled.at) throw httpErr(409, 'already disabled');
    if (!auto()) throw httpErr(409, 'automatic disabling is off - disable it by hand and record it');
    if (Date.parse(dueAt(r)) > now()) throw httpErr(409, 'not due before ' + dueAt(r) + ' - the approval was for the last day');
    audit(who, 'offboarding.retry', r.id, { username: r.username });
    await disableNow(r);
    return view(get(r.id), true);
  }

  async function manualDisabled(id, input, who) {
    const r = get(id); person(who, 'record the account'); notLeaver(r, who, 'record');
    const b = body(input || {}).str('directory_ref', { required: true, min: 3, max: 300 }).str('note', { max: 500 }).done();
    if (SECRETISH.test(b.directory_ref + ' ' + (b.note || ''))) throw httpErr(400, 'directory_ref looks like it contains a password - the platform never holds one');
    if (!(r.disable && r.disable.approved_by)) throw httpErr(409, 'the disable must be approved (four eyes) before it is recorded');
    if (r.disabled && r.disabled.at) throw httpErr(409, 'already recorded by ' + r.disabled.by);
    r.disabled = Object.assign({}, r.disabled || {}, { at: iso(), by: who.user, manual: true, directory_ref: b.directory_ref, note: b.note || '', error: null });
    hist(r, who, 'disabled', { manual: true });
    await startForwarding(r);
    await startMailbox(r);
    await startOneDrive(r);
    await startTeams(r);
    await startCalendar(r);
    await startDevices(r);
    await startApps(r);
    await startReclaim(r);
    maybeComplete(r, who); col().put(r);
    audit(who, 'offboarding.disabled.manual', r.id, { username: r.username, directory_ref: b.directory_ref });
    return view(r, true);
  }

  function equipment(id, input, who) {
    const r = get(id); person(who, 'record the equipment'); notLeaver(r, who, 'record');
    const b = body(input || {}).list('returned', { max: 50, item: 'id', unique: true, def: [] }).str('na_reason', { max: 300 }).done();
    if (r.status !== 'in_progress') throw httpErr(409, r.id + ' is ' + r.status);
    if (r.equipment) throw httpErr(409, 'already recorded by ' + r.equipment.by);
    const h = held(r), ids = new Set(h.map((a) => a.id));
    const stray = b.returned.filter((x) => !ids.has(x)); if (stray.length) throw httpErr(400, 'returned: ' + stray.join(', ') + ' is not held by ' + r.username);
    const missing = h.filter((a) => !b.returned.includes(a.id));
    if (missing.length && !b.na_reason) throw httpErr(400, 'na_reason is required: ' + missing.map((a) => a.asset_tag || a.id).join(', ') + ' not returned - say why (lost, kept under an agreement, ...)');
    if (!h.length && !b.na_reason) throw httpErr(400, 'na_reason is required: the register shows no equipment held by ' + r.username + ' - say so');
    for (const aid of b.returned) {
      try {
        if (app.assets && typeof app.assets.assign === 'function') app.assets.assign(aid, { custodian: '', department: '' }, who);
        if (app.assets && typeof app.assets.transition === 'function') app.assets.transition(aid, 'restock', who, 'returned by leaver ' + r.username + ' (' + r.id + ')');
      } catch (e) { throw httpErr(409, 'the asset register refused ' + aid + ': ' + String(e.message).slice(0, 160)); }
    }
    r.equipment = { by: who.user, at: iso(), returned: b.returned, not_returned: missing.map((a) => a.id), na_reason: b.na_reason || '' };
    hist(r, who, 'equipment', { returned: b.returned.length, not_returned: missing.length }); maybeComplete(r, who); col().put(r);
    audit(who, 'offboarding.equipment', r.id, { returned: b.returned, not_returned: r.equipment.not_returned, na_reason: b.na_reason || null });
    return view(r, true);
  }

  function cancel(id, input, who) {
    const r = get(id); person(who, 'cancel a leaver request'); notLeaver(r, who, 'cancel');
    const b = body(input || {}).str('reason', { required: true, min: 5, max: 500 }).done();
    if (!open(r)) throw httpErr(409, r.id + ' is already ' + r.status);
    if (r.disabled && r.disabled.at) throw httpErr(409, 'the account was already disabled - ask for a re-enable instead');
    if (!(same(r.requested_by, who.user) || same(r.manager, who.user) || who.role === 'admin')) throw httpErr(403, 'cancelling needs the requester, the manager or an administrator');
    r.status = 'cancelled'; r.cancel = { by: who.user, at: iso(), reason: b.reason };
    hist(r, who, 'cancel', { reason: b.reason }); col().put(r);
    audit(who, 'offboarding.cancel', r.id, { reason: b.reason, username: r.username });
    return view(r, true);
  }

  function reenableRequest(id, input, who) {
    const r = get(id); person(who, 'ask for a re-enable'); notLeaver(r, who, 'act');
    const b = body(input || {}).str('reason', { required: true, min: 5, max: 500 }).done();
    if (!(r.disabled && r.disabled.at && r.disabled.dn && !r.disabled.manual)) throw httpErr(409, 'only an account the platform disabled can be re-enabled here - otherwise in Active Directory');
    if (r.reenable && r.reenable.status === 'pending') throw httpErr(409, 'a re-enable is already waiting');
    r.reenable = { status: 'pending', requested_by: who.user, at: iso(), reason: b.reason };
    hist(r, who, 'reenable_request', { reason: b.reason }); col().put(r);
    audit(who, 'offboarding.reenable.request', r.id, { username: r.username, reason: b.reason });
    return view(r, true);
  }
  async function reenableDecide(id, input, who) {
    const r = get(id); person(who, 'approve a re-enable'); notLeaver(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 500 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why' : null)).done();
    const q = r.reenable; if (!q || q.status !== 'pending') throw httpErr(409, 'no re-enable is waiting for ' + r.id);
    if (same(q.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked for the re-enable and cannot also approve it');
    if (b.decision === 'approve') {
      if (!auto()) throw httpErr(409, 'automatic directory changes are off - re-enable it in Active Directory');
      try { await AD().writer().setEnabled(r.disabled.dn, true); }
      catch (e) { warn('reenable', 'offboarding: re-enable failed', { id: r.id, err: String(e.message).slice(0, 160) }); throw httpErr(409, 'the directory refused: ' + String(e.message).slice(0, 160)); }
      r.disabled.reenabled_at = iso();
      if (r.reclaim && !RDONE.includes(r.reclaim.status)) { r.reclaim.status = 'cancelled'; r.reclaim.note = 'the account was enabled again'; }
      if (r.mailbox && !MDONE.includes(r.mailbox.status)) { r.mailbox.status = 'cancelled'; r.mailbox.note = 'the account was enabled again'; }
      if (r.apps && !['done', 'kept', 'not_needed'].includes(r.apps.status)) { r.apps.status = 'cancelled'; r.apps.note = 'the account was enabled again - access already removed (' + (r.apps.items || []).filter((i) => i.state === 'removed' || i.state === 'confirmed').map((i) => i.name).join(', ') + ') is given back by hand'; }
      if (r.devices && !['done', 'not_needed'].includes(r.devices.status)) { (r.devices.devices || []).forEach((d) => { if (d.state === 'proposed') d.state = 'kept', d.decision = { action: 'keep', by: who.user, at: iso(), reason: 'the account was enabled again' }; }); r.devices.status = 'cancelled'; r.devices.note = 'the account was enabled again - an action already sent to a device cannot be called back'; }
      if (r.calendar && !CDONE.includes(r.calendar.status)) { r.calendar.status = 'cancelled'; r.calendar.note = 'the account was enabled again'; }
      if (r.teams) { if (!TDONE.includes(r.teams.status)) { r.teams.status = 'cancelled'; r.teams.note = 'the account was enabled again'; } else if (r.teams.status === 'transferred' && (r.teams.results || []).some((x) => x.leaver_removed)) r.teams.note = 'the account was enabled again - the leaver was removed as owner of ' + r.teams.results.filter((x) => x.leaver_removed).map((x) => x.name).join(', ') + ': add them back by hand if needed'; }
      if (r.onedrive) { if (r.onedrive.status === 'granted') await endOneDrive(r, 'the account was enabled again', who); else if (!ODONE.includes(r.onedrive.status)) { r.onedrive.status = 'cancelled'; r.onedrive.note = 'the account was enabled again'; } }
      if (r.forwarding) { if (!FDONE.includes(r.forwarding.status)) { r.forwarding.status = 'cancelled'; r.forwarding.note = 'the account was enabled again'; } r.forwarding.watch_until = null; }
    }
    Object.assign(q, { status: b.decision === 'approve' ? 'done' : 'rejected', decided_by: who.user, decided_at: iso(), note: b.note || '' });
    hist(r, who, 'reenable_' + b.decision); col().put(r);
    audit(who, 'offboarding.reenable.' + b.decision, r.id, { username: r.username, requested_by: q.requested_by, note: b.note || null });
    return Object.assign(view(r, true), b.decision === 'approve' ? { warning: r.disabled.password_replaced ? 'enabled - its password was replaced at disable: reset it in Active Directory before handing it back' : 'enabled' } : {});
  }

  function start() {
    if (app.noTimers || opts.noTimer) return;
    const t = setInterval(guardOf(app, 'offboarding.disable', () => runDue(null)), 5 * 60000);
    if (t.unref) t.unref();
  }
  start();
  return { list, one: (id) => view(get(id), true), create, bulk, relook, confirm, approve, retry, manualDisabled, equipment, cancel, reenableRequest, reenableDecide, runDue,
    refreshReclaim, decideReclaim, manualReclaim, reclaimTick, decideMailbox, retryMailbox, manualMailbox, mailboxTick, checkForwarding, decideForwarding, retryForwarding, manualForwarding, forwardingTick,
    decideOneDrive, extendOneDrive, endOneDriveNow, retryOneDrive, manualOneDrive, onedriveTick, decideTeams, retryTeams, manualTeams, teamsTick,
    checkCalendar, decideCalendar, retryCalendar, manualCalendar, calendarTick, requestLegal, decideLegal, retryLegal, requestRelease, decideRelease, legalTick,
    decideDevices, retryDevices, manualDevice, devicesTick, listApps, putApp, retireApp, decideApps, confirmApp, retryApps, appsTick, mdm: MDM, exo: EXO, REASONS };
}

// exo.js is loaded like duty.js's optional(): a file the update did not copy turns the mailbox step off (and says so) instead
// of stopping sentra-itam at start-up - a missing require() takes every page down (HTTP 502)
function loadExo(app) {
  try { return require('./exo'); } catch (e) {
    if (e.code === 'MODULE_NOT_FOUND' && String(e.message).split('\n')[0].indexOf("'./exo'") >= 0) {   // exo.js itself, not something it needs
      if (app.log && app.log.every) app.log.every('offboarding:exo-missing', 3600000, 'warn', 'offboarding: engine/exo.js is not installed - mailbox conversion is off until the update is re-run', {});
      return null;
    }
    throw e;
  }
}
const EXO_MISSING = 'the Exchange Online module (engine/exo.js) is not installed on this server - re-run the update';
function exoMissing() {
  return { installed: false, enabled: () => false, spoEnabled: () => false, onedriveDays: () => 60, template: () => '', run: async () => ({ ok: false, error: EXO_MISSING }), test: async () => { throw httpErr(409, EXO_MISSING); },
    configure: () => { throw httpErr(409, EXO_MISSING); }, view: () => ({ installed: false, enabled: false, ready: false, note: EXO_MISSING }) };
}

function registerOffboarding(srv, app, O) {
  // first: /offboarding/exo is not an :id
  const EXM = loadExo(app);
  if (EXM) EXM.registerExoRoutes(srv, app, O.exo);
  else {
    srv.route('GET', '/offboarding/exo', (ctx) => { ctx.need('operator'); return O.exo.view(); });
    srv.route('POST', '/offboarding/exo', (ctx) => { ctx.need('admin'); throw httpErr(409, EXO_MISSING); });
    srv.route('POST', '/offboarding/exo/test', (ctx) => { ctx.need('admin'); throw httpErr(409, EXO_MISSING); });
  }
  if (O.mdm) require('./mdm').registerMdmRoutes(srv, app, O.mdm);   // literal paths before /offboarding/:id
  srv.route('GET', '/offboarding/apps', (ctx) => { ctx.need('operator'); return O.listApps(); });
  srv.route('POST', '/offboarding/apps', (ctx) => { ctx.need('admin'); return O.putApp(ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/apps/retire', (ctx) => { ctx.need('admin'); return O.retireApp(ctx.body, ctx.who); });
  srv.route('GET', '/offboarding', (ctx) => { ctx.need('operator'); return O.list(); });
  srv.route('POST', '/offboarding/run', async (ctx) => { ctx.need('admin'); body(ctx.body).done(); if (isService(ctx.who.user)) throw httpErr(403, 'a person runs it'); return O.runDue(ctx.who); });
  srv.route('GET', '/offboarding/:id', (ctx) => { ctx.need('operator'); return O.one(ctx.params.id); });
  srv.route('POST', '/offboarding', (ctx) => { ctx.need('operator'); return O.create(ctx.body, ctx.who); });
  srv.route('POST', '/offboarding-bulk', (ctx) => { ctx.need('operator'); if (!O.bulk) throw httpErr(404, 'offboarding is not installed'); return O.bulk(ctx.body, ctx.who); }, { maxBody: 262144 });
  srv.route('POST', '/offboarding/:id/lookup', (ctx) => { ctx.need('operator'); body(ctx.body).done(); return O.relook(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/confirm', (ctx) => { ctx.need('operator'); return O.confirm(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/approve', (ctx) => { ctx.need('admin'); return O.approve(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.retry(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/disabled', (ctx) => { ctx.need('operator'); return O.manualDisabled(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/equipment', (ctx) => { ctx.need('operator'); return O.equipment(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/cancel', (ctx) => { ctx.need('operator'); return O.cancel(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/reenable', (ctx) => { ctx.need('admin'); return O.reenableRequest(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/reenable/decide', (ctx) => { ctx.need('admin'); return O.reenableDecide(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/reclaim/refresh', (ctx) => { ctx.need('operator'); body(ctx.body).done(); return O.refreshReclaim(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/reclaim/decide', (ctx) => { ctx.need('admin'); return O.decideReclaim(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/mailbox/decide', (ctx) => { ctx.need('admin'); return O.decideMailbox(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/mailbox/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.retryMailbox(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/mailbox/manual', (ctx) => { ctx.need('operator'); return O.manualMailbox(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/apps/decide', (ctx) => { ctx.need('admin'); return O.decideApps(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/apps/confirm', (ctx) => { ctx.need('operator'); return O.confirmApp(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/apps/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.retryApps(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/devices/decide', (ctx) => { ctx.need('admin'); return O.decideDevices(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/devices/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.retryDevices(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/devices/manual', (ctx) => { ctx.need('operator'); return O.manualDevice(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/legal', (ctx) => { ctx.need('operator'); return O.requestLegal(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/legal/decide', (ctx) => { ctx.need('admin'); return O.decideLegal(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/legal/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.retryLegal(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/legal/release', (ctx) => { ctx.need('operator'); return O.requestRelease(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/legal/release/decide', (ctx) => { ctx.need('admin'); return O.decideRelease(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/calendar/check', (ctx) => { ctx.need('operator'); body(ctx.body).done(); return O.checkCalendar(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/calendar/decide', (ctx) => { ctx.need('admin'); return O.decideCalendar(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/calendar/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.retryCalendar(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/calendar/manual', (ctx) => { ctx.need('operator'); return O.manualCalendar(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/teams/decide', (ctx) => { ctx.need('admin'); return O.decideTeams(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/teams/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.retryTeams(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/teams/manual', (ctx) => { ctx.need('operator'); return O.manualTeams(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/onedrive/decide', (ctx) => { ctx.need('admin'); return O.decideOneDrive(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/onedrive/extend', (ctx) => { ctx.need('admin'); return O.extendOneDrive(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/onedrive/end', (ctx) => { ctx.need('operator'); return O.endOneDriveNow(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/onedrive/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.retryOneDrive(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/onedrive/manual', (ctx) => { ctx.need('operator'); return O.manualOneDrive(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/forwarding/check', (ctx) => { ctx.need('operator'); body(ctx.body).done(); return O.checkForwarding(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/forwarding/decide', (ctx) => { ctx.need('admin'); return O.decideForwarding(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/forwarding/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.retryForwarding(ctx.params.id, ctx.who); });
  srv.route('POST', '/offboarding/:id/forwarding/manual', (ctx) => { ctx.need('operator'); return O.manualForwarding(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/:id/reclaim/manual', (ctx) => { ctx.need('operator'); return O.manualReclaim(ctx.params.id, ctx.body, ctx.who); });
}

module.exports = { createOffboarding, registerOffboarding, REASONS };
