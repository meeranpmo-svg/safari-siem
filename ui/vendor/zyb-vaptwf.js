// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-vaptwf.js - VAPT Workflow page (vapt-workflow.html). Reads /api/itam/vapt-workflow; every action is a POST the server checks
 * (roles, four eyes, the test window, validation). The scoping form takes its targets from the Network Assistant
 * (/api/itam/scan-targets, built from IP Address Management) - a person ticks subnets, nothing is typed by hand unless wanted.
 * No inline handlers; every value is escaped; requests the page handles itself are marked zybQuiet. */
(function () {
  'use strict';
  var esc = function (v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var $ = function (id) { return document.getElementById(id); };
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', V = null, D = null, CUR = null, OK = null;
  var STAGE = { scoping: 'Scoping', authorisation: 'Authorisation', approval: 'Approval (four eyes)', testing: 'Testing', validation: 'Validation', remediation: 'Remediation', retest: 'Retest', report: 'Report', signoff: 'Sign-off', closed: 'Closed' };
  function req(m, u, b) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open(m, '/api/itam' + u); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not JSON: shown as the HTTP status */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
    x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('IT Asset Management is not reachable'), { status: 0 })); }; x.send(b ? JSON.stringify(b) : null); }); }
  function toast(t) { var d = document.createElement('div'); d.setAttribute('role', 'status'); d.style.cssText = 'position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#1d2430;border:1px solid #2e3747;border-radius:10px;padding:10px 16px;z-index:9999;max-width:90vw'; d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 6000); }
  function tile(l, v, s, c) { return '<div class="t ' + (c || '') + '"><div class="l">' + esc(l) + '</div><div class="v">' + esc(v) + '</div><div class="s">' + esc(s || '') + '</div></div>'; }
  function pill(t, c) { return '<span class="pill ' + (c || '') + '">' + esc(t) + '</span>'; }
  var SEVC = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: '' };
  var op = function () { return RANK[ROLE] >= RANK.operator; }, adm = function () { return ROLE === 'admin'; };
  function lines(v) { return String(v || '').split(/[\n,]+/).map(function (x) { return x.trim(); }).filter(Boolean); }
  function today(d) { return new Date(Date.now() + (d || 0) * 86400000).toISOString().slice(0, 10); }

  // ---- a small form in the dialog: fields [name, label, type, options/hint]
  function field(f) { var n = f[0], l = f[1], t = f[2] || 'text', o = f[3], v = f[4] == null ? '' : f[4], id = 'f-' + n;
    var inp = t === 'area' ? '<textarea id="' + id + '" rows="4">' + esc(v) + '</textarea>' : t === 'sel' ? '<select id="' + id + '">' + o.map(function (x) { return '<option value="' + esc(x[0]) + '"' + (x[0] === v ? ' selected' : '') + '>' + esc(x[1]) + '</option>'; }).join('') + '</select>'
      : t === 'chk' ? '<input type="checkbox" id="' + id + '"' + (v ? ' checked' : '') + ' style="width:auto">' : '<input id="' + id + '" type="' + (t === 'date' ? 'date' : t === 'num' ? 'number' : 'text') + '" value="' + esc(v) + '"' + (t === 'num' ? ' step="0.1" min="0" max="10"' : '') + '>';
    return '<label for="' + id + '">' + esc(l) + '</label><div>' + inp + (t !== 'sel' && t !== 'chk' && o ? '<div class="hint">' + esc(o) + '</div>' : '') + '</div>'; }
  function open(title, fields, extra, onOk, okText) { $('dlgt').textContent = title; $('dlgb').innerHTML = (extra || '') + (fields.length ? '<div class="form">' + fields.map(field).join('') + '</div>' : ''); OK = onOk; $('dlgok').textContent = okText || 'Save'; $('dlgok').hidden = !onOk; $('dlg').showModal(); }
  function val(n) { var el = $('f-' + n); if (!el) return undefined; return el.type === 'checkbox' ? el.checked : el.value.trim(); }
  function act(p, b, msg) { $('dlgok').disabled = true; return req('POST', p, b || {}).then(function (d) { if (d && d.engagement) { D = d; drawDet(); } $('dlg').open && $('dlg').close(); toast(msg || 'Saved (audited)'); loadList(); return d; }, function (e) { toast(e.message); }).then(function (x) { $('dlgok').disabled = false; return x; }); }

  // ---- list
  function loadList() { return req('GET', '/vapt-workflow').then(function (v) { V = v; $('main').hidden = false; $('err').innerHTML = ''; drawList(); }, function (e) { $('main').hidden = true; $('err').innerHTML = '<div class="card"><p>' + esc(e.status === 404 ? 'The VAPT Workflow is not installed yet - run the platform update.' : e.message) + '</p></div>'; }); }
  function drawList() { var k = V.kpi;
    $('kk').innerHTML = tile('Engagements', k.engagements, k.active + ' active, ' + k.closed + ' closed') + tile('Open findings', k.open_findings, 'confirmed, not fixed', k.open_findings ? 'warn' : 'ok') + tile('Past SLA', k.sla_breached, 'confirmed findings past due', k.sla_breached ? 'bad' : 'ok')
      + tile('Network Assistant', V.installed && V.installed.greenbone ? 'Greenbone ready' : 'no Greenbone', V.installed && V.installed.vapt_center ? 'scanner findings importable' : 'VAPT Center not installed');
    $('newb').hidden = !op(); $('up').textContent = 'Updated ' + String(V.generated_at).slice(11, 16) + ' UTC';
    if (!V.engagements) { $('list').innerHTML = '<div class="empty">' + esc(V.note) + '</div>'; $('lc').textContent = ''; return; }
    $('lc').textContent = V.engagements.length + ' engagement(s)';
    $('list').innerHTML = V.engagements.length ? '<table><thead><tr><th>Engagement</th><th>Kind</th><th>Stage</th><th>Window</th><th>Risk</th><th>Open</th><th>Lead</th></tr></thead><tbody>' + V.engagements.map(function (e) {
      return '<tr data-eng="' + esc(e.id) + '" tabindex="0"><td><b>' + esc(e.id) + '</b> ' + esc(e.name) + '</td><td>' + esc(e.kind) + '</td><td>' + pill(e.stage_no + '/10 ' + (STAGE[e.stage] || e.stage), e.stage === 'closed' ? 'ok' : 'info') + '</td><td class="small">' + esc(e.window.join(' to ')) + '</td><td>' + pill(e.risk + ' ' + e.band, SEVC[e.band] || '') + '</td><td>' + esc(e.open) + (e.sla_breached ? ' ' + pill(e.sla_breached + ' past SLA', 'bad') : '') + '</td><td>' + esc(e.lead) + '</td></tr>'; }).join('') + '</tbody></table>'
      : '<div class="empty">No engagement yet. ' + (op() ? 'Click + New engagement - the Network Assistant fills the targets from IP Address Management.' : 'An operator starts one.') + '</div>'; }

  // ---- detail
  function openDet(id) { CUR = id; req('GET', '/vapt-workflow/' + encodeURIComponent(id)).then(function (d) { D = d; $('listv').hidden = true; $('detv').hidden = false; drawDet(); }, function (e) { toast(e.message); }); }
  function drawDet() { var d = D, e = d.engagement, a = d.analysis, si = d.stages.indexOf(d.stage);
    $('dk').textContent = e.id + ' · ' + e.kind_name + ' · ' + e.approach_name; $('dt').textContent = e.name;
    $('steps').innerHTML = d.stages.slice(0, 9).map(function (s, i) { return '<div class="' + (i < si || d.stage === 'closed' ? 'done' : i === si ? 'on' : '') + '"><span class="muted">' + (i + 1) + '</span><b>' + esc(STAGE[s]) + '</b>' + (i < si || d.stage === 'closed' ? '<span class="pill ok">done</span>' : '') + '</div>'; }).join('');
    $('nextv').innerHTML = '<b>' + esc(STAGE[d.stage]) + ':</b> ' + esc(d.next);
    $('acts').innerHTML = actions(d);
    $('dkk').innerHTML = tile('Risk rating', a.risk + '/100', a.band + (a.risk_why.length ? ' - ' + a.risk_why[0] : ''), a.band === 'critical' || a.band === 'high' ? 'bad' : a.band === 'medium' ? 'warn' : 'ok') + tile('Confirmed', a.confirmed, a.counts.critical + ' critical, ' + a.counts.high + ' high')
      + tile('To validate', a.pending, a.false_positive + ' false positive(s)', a.pending ? 'warn' : '') + tile('Fixed & verified', a.verified, a.accepted + ' risk-accepted', '') + tile('Past SLA', a.sla.breached, a.sla.due_14d + ' due in 14 days', a.sla.breached ? 'bad' : 'ok')
      + tile('Recurring', a.recurring.length, 'seen in an earlier engagement', a.recurring.length ? 'warn' : '') + tile('Forecast close', a.cycle.withheld ? '—' : (a.cycle.forecast_close || 'closed'), a.cycle.withheld ? a.cycle.why : 'median ' + a.cycle.median_days + ' days over ' + a.cycle.from);
    $('fc').textContent = d.findings.length + ' finding(s)';
    $('finds').innerHTML = d.findings.length ? '<table><thead><tr><th>Finding</th><th>Status</th><th></th></tr></thead><tbody>' + d.findings.map(function (f) {
      var st = f.validation === 'pending' ? pill('to validate', 'warn') : f.validation === 'fp_pending' ? pill('false positive - awaiting decision', 'warn') : f.validation === 'false_positive' ? pill('false positive') : f.validation === 'informational' ? pill('informational') : f.state === 'verified' ? pill('fixed - ' + (f.verified_how === 'rescan' ? 'rescan' : 'retest'), 'ok') : f.state === 'accepted' ? pill('risk accepted to ' + f.accepted_until, 'info') : f.state === 'fix_claimed' ? pill('fix claimed', 'info') : pill('open', 'bad');
      return '<tr><td>' + pill(f.severity, SEVC[f.severity]) + '<b>' + esc(f.title) + '</b>' + (a.recurring.indexOf(f.id) >= 0 ? ' ' + pill('recurring', 'warn') : '') + '<div class="hint">' + esc(f.host + (f.cves && f.cves.length ? ' · ' + f.cves.join(', ') : '') + ' · ' + f.src + (f.owner ? ' · owner ' + f.owner + ', due ' + f.due : '') + (f.request ? ' · ' + f.request.kind.replace('_', ' ') + ' requested by ' + f.request.by : '')) + '</div></td><td>' + st + '</td><td><div class="acts">' + fActs(f) + '</div></td></tr>'; }).join('') + '</tbody></table>' : '<div class="empty">No finding yet.</div>';
    $('scope').innerHTML = '<table><tbody>' + [['Targets', e.targets.join(', ')], ['Out of scope', e.out_of_scope.join(', ') || 'none'], ['Window', e.window_start + ' to ' + e.window_end], ['Lead', e.lead], ['Tester', e.tester_type === 'third_party' ? e.tester_org + (e.tester_cert ? ' (' + e.tester_cert + ')' : '') : 'Internal' + (e.tester_cert ? ' (' + e.tester_cert + ')' : '')], ['Emergency contact', e.emergency_contact || '—'], ['Authorised', e.authorised_by ? e.authorised_by + ' · change ' + (e.checklist.change_ref || '') : '—'], ['Approved', e.approved_by || '—'], ['Scans', (e.scans || []).map(function (s) { return s.ref; }).join(', ') || '—'], ['Tool runs', (e.tool_runs || []).map(function (t) { return t.tool + ' ' + t.ran_on; }).join(', ') || '—']].map(function (r) { return '<tr><th style="width:130px">' + esc(r[0]) + '</th><td>' + esc(r[1]) + '</td></tr>'; }).join('') + '</tbody></table>';
    $('reps').innerHTML = d.reports.length ? d.reports.map(function (r) { return '<div class="nx"><div style="flex:1"><b>v' + esc(r.version) + ' ' + esc(r.kind) + '</b> ' + pill(r.status, r.status === 'issued' ? 'ok' : '') + '<div class="hint">' + esc(r.by + ' · ' + String(r.at).slice(0, 16).replace('T', ' ') + ' · SHA-256 ' + r.sha256.slice(0, 16) + '…') + '</div></div><div class="acts"><button type="button" data-rep="' + esc(r.version) + '" data-fmt="html">Open</button><button type="button" data-rep="' + esc(r.version) + '" data-fmt="csv">CSV</button>' + (adm() && r.status !== 'issued' ? '<button type="button" data-issue="' + esc(r.version) + '">Issue</button>' : '') + '</div></div>'; }).join('') : '<div class="empty">No report yet.</div>';
    $('hist').innerHTML = (e.history || []).slice().reverse().slice(0, 30).map(function (h) { return '<div>' + esc(String(h.at).slice(0, 16).replace('T', ' ') + ' · ' + h.by + ' · ' + h.what) + '</div>'; }).join(''); }
  function b(a, t) { return '<button type="button" data-a="' + a + '">' + esc(t) + '</button>'; }
  function actions(d) { var e = d.engagement, s = d.stage, o = '';
    if (!op()) return '<span class="hint">Operators and administrators work the engagement.</span>';
    if (!e.approved_by) o += b('scope', 'Edit scope');
    if (s === 'authorisation' && adm()) o += b('authorise', 'Authorise (safety checklist)');
    if (s === 'approval') o += b('approve', 'Approve (four eyes)');
    if (e.approved_by && !e.testing_done_at) o += b('scan', 'File Greenbone scan') + b('tool', 'Record tool run') + b('finding', 'Add finding') + b('import', 'Import scanner findings') + b('done', 'Testing complete');
    if (e.approved_by && !e.closed_at) o += b('interim', 'Interim report');
    if (s === 'report') o += b('final', 'Generate final report');
    if (s === 'signoff') o += b('signoff', 'Sign off');
    return o; }
  function fActs(f) { if (!op() || D.engagement.closed_at) return ''; var o = '', fb = function (a, t) { return '<button type="button" data-fa="' + a + '" data-fid="' + esc(f.id) + '">' + esc(t) + '</button>'; };
    if (f.validation === 'pending' && D.engagement.testing_done_at) o += fb('validate', 'Validate');
    if (f.request) o += fb('decide', 'Decide');
    if (f.validation === 'confirmed' && !f.owner && f.state === 'open') o += fb('remediate', 'Assign');
    if (f.validation === 'confirmed' && f.state === 'open' && f.owner) o += fb('fixed', 'Claim fixed') + (f.request ? '' : fb('accept', 'Risk acceptance'));
    if (f.state === 'fix_claimed' && f.src === 'manual') o += fb('retest', 'Retest');
    return o; }

  // ---- scoping with the Network Assistant
  function ipamPicker() { return '<div class="card" style="margin:0 0 8px"><h2 style="font-size:13px">Targets from IP Address Management <span class="c">Network Assistant - live addresses only; fragile devices go to out of scope</span></h2><div id="stg" class="small muted">Reading IP Address Management…</div></div>'; }
  function loadPicker() { req('GET', '/scan-targets').then(function (r) { var bx = $('stg'); if (!bx) return;
    if (!r.installed || !r.subnets.length) { bx.innerHTML = esc(r.note || 'No subnet in IP Address Management yet - register the address plan there, or type the targets below.'); return; }
    bx.innerHTML = r.subnets.filter(function (s) { return s.live; }).map(function (s, i) { return '<label class="chk"><input type="checkbox" data-sub="' + i + '"' + (r.recommendations.some(function (x) { return x.subnet === s.id; }) && i < 3 ? ' checked' : '') + '><span><b>' + esc(s.name + ' (' + s.cidr + ')') + '</b>' + (s.site ? ' · ' + esc(s.site) : '') + ' · ' + esc(s.live) + ' live · priority ' + esc(s.priority) + '<span class="hint" style="display:block">' + esc((s.why.join('; ') || 'recently scanned') + (s.fragile.length ? ' · ' + s.fragile.length + ' fragile left out' : '') + (s.blocked ? ' · ' + s.blocked : '')) + '</span></span></label>'; }).join('') + '<button type="button" id="stgapply">Use the ticked subnets</button>';
    var live = r.subnets.filter(function (s) { return s.live; }), apply = function () { var t = [], x = []; Array.prototype.forEach.call(document.querySelectorAll('[data-sub]'), function (c) { if (!c.checked) return; var s = live[Number(c.getAttribute('data-sub'))]; s.live && (t = t.concat(s.targets.length ? s.targets : [s.cidr])); x = x.concat(s.exclude); });
      $('f-targets').value = t.join('\n'); $('f-out_of_scope').value = x.join('\n'); };
    $('stgapply').addEventListener('click', apply); apply(); }, function (e) { var bx = $('stg'); if (bx) bx.textContent = 'Network Assistant: ' + e.message + ' - type the targets below.'; /* optional helper: the form still works by hand */ }); }
  function scopeForm(e) { e = e || {}; var K = (V && V.kinds) || {}, AP = (V && V.approaches) || {};
    open(e.id ? 'Edit scope - ' + e.id : 'New engagement', [['name', 'Name', 'text', '', e.name], ['kind', 'Kind', 'sel', Object.keys(K).map(function (k) { return [k, K[k]]; }), e.kind || 'internal_vapt'], ['approach', 'Approach', 'sel', Object.keys(AP).map(function (k) { return [k, AP[k]]; }), e.approach || 'grey'],
      ['tester_type', 'Tester', 'sel', [['internal', 'Internal'], ['third_party', 'Third party']], e.tester_type || 'internal'], ['tester_org', 'Tester company', 'text', 'required for a third party', e.tester_org], ['tester_cert', 'Certification', 'text', 'e.g. CREST, OSCP', e.tester_cert],
      ['targets', 'Targets', 'area', 'one per line: address, range, CIDR, host name or URL', (e.targets || []).join('\n')], ['out_of_scope', 'Out of scope', 'area', 'always wins over a range', (e.out_of_scope || []).join('\n')], ['objectives', 'Objectives', 'area', '', e.objectives],
      ['window_start', 'Window start', 'date', '', e.window_start || today(1)], ['window_end', 'Window end', 'date', 'at most 90 days', e.window_end || today(14)], ['emergency_contact', 'Emergency contact', 'text', 'who to call during the window', e.emergency_contact]],
      ipamPicker(), function () { var body = { name: val('name'), kind: val('kind'), approach: val('approach'), tester_type: val('tester_type'), tester_org: val('tester_org'), tester_cert: val('tester_cert'), targets: lines(val('targets')), out_of_scope: lines(val('out_of_scope')), objectives: val('objectives'), window_start: val('window_start'), window_end: val('window_end'), emergency_contact: val('emergency_contact') };
        Object.keys(body).forEach(function (k) { if (body[k] === '') delete body[k]; });
        if (!body.targets.length) { toast('Targets: tick subnets above or type at least one target.'); return; }
        act(e.id ? '/vapt-workflow/' + e.id + '/scope' : '/vapt-workflow', body, e.id ? 'Scope saved (audited)' : 'Engagement requested (audited)').then(function (d) { if (d && d.engagement) { CUR = d.engagement.id; $('listv').hidden = true; $('detv').hidden = false; } }); }, e.id ? 'Save scope' : 'Request engagement');
    loadPicker(); }

  function doAct(a) { var e = D.engagement, P = '/vapt-workflow/' + e.id;
    if (a === 'scope') return scopeForm(e);
    if (a === 'authorise') { var C = D.checklist_items; return open('Authorise - safety checklist', Object.keys(C).filter(function (k) { return k !== 'change_ref'; }).map(function (k) { return [k, C[k], 'chk']; }).concat([['change_ref', C.change_ref, 'text', 'e.g. CHG-1001']]), '', function () { var c = {}; Object.keys(C).forEach(function (k) { c[k] = val(k); }); act(P + '/authorise', { checklist: c }, 'Authorised (audited)'); }, 'Authorise'); }
    if (a === 'approve') return open('Approve ' + e.id, [], '<p>You approve testing <b>' + esc(e.targets.length) + '</b> target(s) from ' + esc(e.window_start) + ' to ' + esc(e.window_end) + '. The requester and the authoriser cannot approve.</p>', function () { act(P + '/approve', {}, 'Approved (audited)'); }, 'Approve');
    if (a === 'scan') return open('File Greenbone scan', [['profile', 'Profile', 'sel', [['full', 'Full'], ['discovery', 'Discovery only']], 'full'], ['hours', 'Hours', 'text', '1-12', '4']], '<p class="small">Filed in Vulnerability Scans for the IPv4 targets; it runs inside the scan scope after a different person approves it there.</p>', function () { act(P + '/scan', { profile: val('profile'), hours: Number(val('hours')) || 4 }, 'Scan filed - a different person approves it in Vulnerability Scans'); }, 'File scan');
    if (a === 'tool') return open('Record tool run', [['tool', 'Tool', 'text', 'e.g. Burp Suite, Nessus'], ['ran_on', 'Ran on', 'date', '', today()], ['note', 'Note', 'text']], '', function () { act(P + '/tool-run', { tool: val('tool'), ran_on: val('ran_on'), note: val('note') || undefined }); });
    if (a === 'finding') return open('Add finding', [['title', 'Title'], ['severity', 'Severity', 'sel', [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']], 'high'], ['cvss', 'CVSS', 'num'], ['host', 'Host', 'text', 'must be in scope'], ['cves', 'CVEs', 'text', 'comma-separated'], ['description', 'Description', 'area'], ['evidence', 'Evidence', 'area', 'where it can be seen - never a password or key'], ['fix', 'Fix', 'area'], ['technique', 'ATT&CK', 'text', 'e.g. T1190'], ['exposure', 'Exposure', 'sel', [['', '—'], ['internet', 'Internet-facing'], ['internal', 'Internal']], '']], '',
      function () { var bd = { title: val('title'), severity: val('severity'), host: val('host'), evidence: val('evidence'), description: val('description') || undefined, fix: val('fix') || undefined, technique: val('technique') || undefined, exposure: val('exposure'), cves: lines(val('cves')) }; if (val('cvss')) bd.cvss = Number(val('cvss')); act(P + '/findings', bd, 'Finding recorded (audited)'); });
    if (a === 'import') return act(P + '/import', {}).then(function (r) { if (r) toast((r.imported || 0) + ' finding(s) imported, ' + (r.already || 0) + ' already here'); });
    if (a === 'done') return open('Testing complete', [], '<p>Close testing for ' + esc(e.id) + '? Findings are validated next.</p>', function () { act(P + '/testing-done', {}, 'Testing complete'); }, 'Confirm');
    if (a === 'interim' || a === 'final') return act(P + '/report', { kind: a }, a === 'final' ? 'Final report generated - an administrator issues it' : 'Interim report generated');
    if (a === 'signoff') return open('Sign off ' + e.id, [['statement', 'Statement', 'area', 'at least 10 characters']], '<p class="small">The report\'s author cannot sign it off. Signing closes the engagement.</p>', function () { act(P + '/signoff', { statement: val('statement') }, 'Signed off - engagement closed'); }, 'Sign off'); }
  function doF(a, fid) { var f = D.findings.filter(function (x) { return x.id === fid; })[0], P = '/vapt-workflow/' + D.engagement.id + '/findings/' + encodeURIComponent(fid); if (!f) return;
    if (a === 'validate') return open('Validate - ' + f.title, [['result', 'Result', 'sel', [['confirmed', 'Confirmed'], ['informational', 'Informational'], ['false_positive', 'False positive (a second person decides)']], 'confirmed'], ['note', 'Note', 'area', 'required for a false positive']], '', function () { act(P + '/validate', { result: val('result'), note: val('note') || undefined }); });
    if (a === 'decide') return open('Decide - ' + f.request.kind.replace('_', ' '), [['decision', 'Decision', 'sel', [['approve', 'Approve'], ['reject', 'Reject']], 'approve'], ['note', 'Note', 'text']], '<p class="small">Requested by ' + esc(f.request.by) + ': ' + esc(f.request.reason) + (f.request.until ? ' (until ' + esc(f.request.until) + ')' : '') + '</p>', function () { act(P + '/decide', { decision: val('decision'), note: val('note') || undefined }); });
    if (a === 'remediate') return open('Assign remediation', [['owner', 'Owner', 'text', 'user name'], ['due', 'Due', 'date', 'empty = the SLA for ' + f.severity + ' (' + (D.sla_days[f.severity] || '') + ' days)']], '', function () { act(P + '/remediate', { owner: val('owner'), due: val('due') || undefined }); });
    if (a === 'fixed') return open('Claim fixed', [['note', 'What was done']], '<p class="small">A claim is not a fix: a later scan or an independent retest verifies it.</p>', function () { act(P + '/fixed', { note: val('note') }); });
    if (a === 'retest') return open('Retest', [['result', 'Result', 'sel', [['pass', 'Pass - fixed'], ['fail', 'Fail - still present']], 'pass'], ['evidence', 'Evidence', 'area']], '<p class="small">The owner and the person who claimed the fix cannot retest it.</p>', function () { act(P + '/retest', { result: val('result'), evidence: val('evidence') }); });
    if (a === 'accept') return open('Request risk acceptance', [['reason', 'Reason', 'area'], ['until', 'Until', 'date', 'at most a year']], '', function () { act(P + '/accept', { reason: val('reason'), until: val('until') }); }); }
  function getRep(v, fmt) { req('GET', '/vapt-workflow/' + D.engagement.id + '/report/' + v + '?format=' + fmt).then(function (r) { var blob = new Blob([fmt === 'csv' ? '﻿' + r.csv : r.html], { type: fmt === 'csv' ? 'text/csv' : 'text/html' }), u = URL.createObjectURL(blob);
    if (fmt === 'html') { var w = window.open(u, '_blank', 'noopener'); if (!w) toast('Allow pop-ups to open the report'); } else { var a = document.createElement('a'); a.href = u; a.download = r.filename; document.body.appendChild(a); a.click(); a.remove(); } setTimeout(function () { URL.revokeObjectURL(u); }, 60000); }, function (e) { toast(e.message); }); }

  document.addEventListener('click', function (ev) { var t = ev.target, x;
    if ((x = t.closest('tr[data-eng]'))) return openDet(x.getAttribute('data-eng'));
    if ((x = t.closest('[data-a]'))) return doAct(x.getAttribute('data-a'));
    if ((x = t.closest('[data-fa]'))) return doF(x.getAttribute('data-fa'), x.getAttribute('data-fid'));
    if ((x = t.closest('[data-rep]'))) return getRep(x.getAttribute('data-rep'), x.getAttribute('data-fmt'));
    if ((x = t.closest('[data-issue]'))) return act('/vapt-workflow/' + D.engagement.id + '/report/' + x.getAttribute('data-issue') + '/issue', {}, 'Report issued (audited)');
    if (t.id === 'dlgx') return $('dlg').close(); if (t.id === 'dlgok' && OK) return OK();
    if (t.id === 'newb') return scopeForm(null);
    if (t.id === 'back') { $('detv').hidden = true; $('listv').hidden = false; CUR = null; return loadList(); }
    if (t.id === 'refresh') return CUR ? openDet(CUR) : loadList(); });
  document.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' && ev.target.matches && ev.target.matches('tr[data-eng]')) openDet(ev.target.getAttribute('data-eng')); });
  (function () { var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.zybQuiet = true; w.onload = function () { try { var j = JSON.parse(w.responseText), r = String(j.role || '').toLowerCase(); if (RANK[r] != null) ROLE = r; } catch (e) { /* not signed in: viewer */ } loadList(); }; w.onerror = loadList; w.send(); })();
})();
