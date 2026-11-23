// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Renewal Autopilot card on Domains & DNS (domains.html, #ren) over /api/itam/renewals: tiles that filter, what to do first, every domain
 * and hosting subscription ranked by renewal risk (every point on hover and in the drawer), what the registry (RDAP) says, the renewal
 * task and its next step (request -> approve by another admin -> renewed -> verified by the registry), the 12-month cost forecast, the
 * learned lead time, hosting subscriptions (admin), the read-only AI advisor. Delegated listeners; every value escaped. */
(function () {
  'use strict';
  var el = document.getElementById('ren'); if (!el) return;
  var Z = window.zybDetail, esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', V = null, F = '';
  var can = function (r) { return RANK[ROLE] >= RANK[r]; };
  var NEXT = { open: ['requested', 'Request the renewal'], requested: ['approved', 'Approve (another admin)'], approved: ['renewed', 'Record the renewal'], renewed: ['verified', 'Verify by hand (hosting)'] };
  var ST = { open: ['opened', 'p-warn'], requested: ['requested', 'p-info'], approved: ['approved', 'p-info'], renewed: ['renewed - awaiting proof', 'p-warn'], verified: ['verified', 'p-ok'], cancelled: ['cancelled', 'p-mut'] };
  function req(m, p, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, '/api/itam' + p); x.withCredentials = true; x.timeout = 300000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: reported below */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('IT Asset Management is not reachable')); }; x.send(b ? JSON.stringify(b) : null);
    });
  }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 6000); }
  var pill = function (t, c) { return '<span class="pill ' + c + '">' + esc(t) + '</span>'; };
  var lv = function (l) { return l === 'high' ? 'p-bad' : l === 'medium' ? 'p-warn' : 'p-ok'; };
  var days = function (d) { return d == null ? 'no date' : d < 0 ? 'expired ' + -d + ' d ago' : d + ' days'; };
  function tile(l, v, s, cls, f) { return '<button type="button" class="t ' + (cls || '') + '" data-rf="' + esc(f || '') + '"' + (F && F === f ? ' style="outline:1px solid var(--info)"' : '') + '><div class="l">' + esc(l) + '</div><div class="v">' + esc(v == null ? '—' : v) + '</div><div class="s">' + esc(s || '') + '</div></button>'; }
  function match(x) {
    switch (F) { case 'expired': return x.days_left != null && x.days_left < 0; case 'due': return x.days_left != null && x.days_left >= 0 && x.days_left <= 30; case 'high': return x.level === 'high';
      case 'tasks': return !!x.task; case 'approval': return x.task && x.task.state === 'requested'; case 'unlocked': return x.registry && x.registry.ok && x.registry.locked === false;
      case 'hijack': return x.registry && (x.registry.changes || []).some(function (c) { return c.level === 'bad'; }); case 'unverified': return x.task && x.task.state === 'renewed'; case 'nodate': return !x.expires;
      case 'price': return x.price_change_pct != null && x.price_change_pct > 15; case 'rdap': return x.registry && !x.registry.ok && !x.registry.no_rdap; default: return true; }
  }
  function load() { return req('GET', '/renewals').then(function (v) { V = v; draw(); }).catch(function (e) { V = null; el.innerHTML = '<div class="card"><h2>Renewal Autopilot</h2><div class="err">' + esc(e.status === 404 ? 'The Renewal Autopilot is not installed on the server yet - run the update (update-platform.ps1).' : e.message) + '</div></div>'; }); }
  function draw() {
    var k = V.kpis, L = V.items.filter(match);
    var acts = V.actions.length ? V.actions.map(function (a) { return '<div class="fd ' + (a.priority >= 80 ? 'bad' : a.priority >= 50 ? 'warn' : 'info') + '" data-rf="' + esc(a.filter) + '" style="cursor:pointer"><b>' + esc(a.title) + '</b><small>' + esc(a.detail) + '</small></div>'; }).join('') : '<div class="empty">Nothing needs action: every renewal is outside its lead time or already in hand.</div>';
    var mx = Math.max.apply(null, V.forecast.map(function (m) { return m.cost || m.items; }).concat([1]));
    var fc = '<div style="display:flex;align-items:flex-end;gap:4px;height:90px" aria-label="renewals per month">' + V.forecast.map(function (m) { var val = V.named ? m.cost : m.items; return '<div style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:100%" title="' + esc(m.month + ': ' + m.items + ' renewal(s)' + (V.named ? ', ' + m.cost + ' recorded' + (m.unknown_cost ? ' + ' + m.unknown_cost + ' without a cost' : '') : '')) + '"><span class="muted" style="font-size:10px">' + esc(m.items || '') + '</span><i style="display:block;width:70%;background:var(--info);border-radius:3px 3px 0 0;height:' + Math.max(m.items ? 4 : 0, (val || 0) / mx * 100) + '%"></i><span class="muted" style="font-size:10px">' + esc(m.month.slice(5)) + '</span></div>'; }).join('') + '</div>';
    el.innerHTML = '<div class="card"><h2>🔁 Renewal Autopilot <span class="c">domains read from the registry (RDAP) · hosting subscriptions · request → approve → renew → verified</span>'
      + '<span style="flex:1"></span>' + (can('operator') ? '<button type="button" class="btn" id="rn-rdap">⟳ Read the registry now</button>' : '') + (can('admin') ? '<button type="button" class="btn" id="rn-host">➕ Hosting subscription</button>' : '') + (can('operator') ? '<button type="button" class="btn" id="rn-ask">🤖 Ask the advisor</button>' : '') + '</h2>'
      + '<div class="k">' + tile('Expired', k.expired, 'renew now', k.expired ? 'bad' : 'ok', 'expired') + tile('Expire in 30 days', k.due_30, 'each has a task', k.due_30 ? 'warn' : 'ok', 'due') + tile('High risk', k.high, 'score 60+', k.high ? 'bad' : 'ok', 'high')
        + tile('Open renewals', k.open_tasks, k.awaiting_approval + ' awaiting approval', k.awaiting_approval ? 'warn' : '', 'tasks') + tile('No transfer lock', k.unlocked, 'at the registry', k.unlocked ? 'warn' : 'ok', 'unlocked')
        + tile('Verified in 12 months', k.verified_12m, k.late_rate == null ? 'late rate: no history yet' : k.late_rate + ' % renewed late', '', '') + '</div>'
      + '<div style="display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:14px"><div><h3>What to do first</h3>' + acts + '</div><div><h3>Next 12 months' + (V.named ? ' (cost recorded)' : '') + '</h3>' + fc
      + '<div class="muted" style="margin-top:6px;font-size:12px">Lead time: renewals open <b>' + esc(V.lead.used) + '</b> days ahead - ' + esc(V.lead.basis) + '.' + (can('admin') ? ' <button type="button" class="btn" id="rn-set" style="padding:2px 8px;font-size:11px">Change</button>' : '') + '</div></div></div>'
      + '<h3>Domains and hosting ' + (F ? '<span class="muted">· filter: ' + esc(F) + ' <button type="button" class="btn" data-rf="" style="padding:1px 7px;font-size:11px">clear</button></span>' : '') + '</h3>'
      + (L.length ? '<div class="tw"><table><thead><tr><th>Item</th><th>Expires</th><th>Registry (RDAP)</th><th>Risk</th><th>Renewal</th></tr></thead><tbody>' + L.map(function (x) {
        var r = x.registry, reg = x.kind === 'hosting' ? '<span class="muted">no registry - hosting</span>' : !r ? '<span class="muted">not read yet</span>' : r.ok ? esc(r.registrar || '—') + ' · ' + (r.locked ? pill('locked', 'p-ok') : pill('no lock', 'p-bad')) + (r.expires && r.expires !== x.expires ? '<div class="err">registry: ' + esc(r.expires) + '</div>' : '') + ((r.changes || []).filter(function (c) { return c.level === 'bad'; }).length ? '<div class="err">⚠ ' + esc(r.changes.filter(function (c) { return c.level === 'bad'; }).map(function (c) { return c.text; }).join('; ')) + '</div>' : '') : '<span class="muted" title="' + esc(r.error) + '">' + esc(r.no_rdap ? 'registry has no RDAP' : 'not read: ' + r.error) + '</span>';
        var tk = x.task ? pill(x.task.id + ' ' + ST[x.task.state][0], ST[x.task.state][1]) : x.days_left != null && x.days_left > V.lead.used ? '<span class="muted">opens ' + esc(x.days_left - V.lead.used) + ' d before the lead time</span>' : '<span class="muted">—</span>';
        return '<tr class="rw" data-ri="' + esc(x.kind + ':' + x.id) + '"><td><b>' + esc(x.name) + '</b><div class="muted">' + esc(x.kind === 'domain' ? 'domain' : 'hosting · ' + (x.plan || '')) + (x.auto_renew ? ' · auto-renew' : '') + '</div></td><td class="mono">' + esc(x.expires || '—') + '<div class="' + (x.days_left != null && x.days_left <= 30 ? 'err' : 'muted') + '">' + esc(days(x.days_left)) + '</div></td><td>' + reg + '</td>'
          + '<td title="' + esc(x.why.map(function (w) { return '+' + w.points + ' ' + w.text; }).join('\n')) + '">' + pill(x.score + ' ' + x.level, lv(x.level)) + '</td><td>' + tk + '</td></tr>'; }).join('') + '</tbody></table></div>'
        : '<div class="empty">' + (V.items.length ? 'Nothing matches the filter.' : 'No domain or hosting subscription yet - add domains above (Add domain) and hosting subscriptions here; the registry is then read every day.') + '</div>')
      + '<p class="muted" style="font-size:12px;margin:8px 0 0">' + esc(V.note) + '</p></div>';
  }
  function itemOf(key) { return V.items.filter(function (x) { return x.kind + ':' + x.id === key; })[0]; }
  function openItem(key) {
    var x = itemOf(key); if (!x) return; var t = x.task, r = x.registry, nx = t && NEXT[t.state];
    var form = '';
    if (t && nx && can('operator') && !(t.state === 'renewed' && x.kind === 'domain' && r && r.ok)) {
      var to = nx[0], need = to === 'approved' || to === 'verified' ? 'admin' : 'operator';
      if (can(need)) form = '<h3>' + esc(nx[1]) + '</h3><form id="rn-adv" class="fm" data-id="' + esc(t.id) + '" data-to="' + esc(to) + '">'
        + (to === 'renewed' ? '<label>New expiry date<input type="date" name="new_expiry" required></label><label>Cost (' + esc(x.currency || 'SAR') + ')<input type="number" min="0" step="0.01" name="cost"></label><label>Order / invoice reference<input name="evidence" maxlength="500" required></label>' : '')
        + (to === 'verified' ? '<label>What you checked (portal, invoice)<input name="evidence" maxlength="500" required></label>' : '')
        + '<label style="grid-column:1/-1">Note<textarea name="note" rows="2" maxlength="1000" required></textarea></label><div><button type="submit" class="btn pri">' + esc(nx[1]) + '</button> ' + (can('admin') ? '<button type="button" class="btn" id="rn-cancel">Cancel the renewal</button>' : '') + '</div><div class="err" id="rn-msg" style="grid-column:1/-1"></div></form>'
        + (to === 'approved' ? '<p class="muted">Approved by an administrator other than ' + esc(t.requested_by || 'the requester') + '.</p>' : '') + (to === 'renewed' && x.kind === 'domain' ? '<p class="muted">The registry confirms it: once RDAP shows the new expiry the renewal is verified by itself.</p>' : '');
    } else if (t && t.state === 'renewed' && x.kind === 'domain') form = '<p class="muted">Waiting for the registry: the renewal is verified when RDAP shows an expiry after ' + esc(t.due) + '. Read the registry now to check.</p>';
    Z.open('Renewal', x.name, Z.kv([['Kind', esc(x.kind)], ['Expires', esc((x.expires || '—') + ' (' + days(x.days_left) + ')')], ['Auto-renew', x.auto_renew ? 'on' : 'off'], ['Provider', esc(x.provider || '—')]].concat(V.named ? [['Owner', esc(x.owner || '—')], ['Cost', esc(x.cost == null ? '—' : x.cost + ' ' + (x.currency || ''))], ['Price change', esc(x.price_change_pct == null ? '—' : x.price_change_pct + ' % against the last renewal')]] : []).concat(x.hosts ? [['Serves', esc(x.hosts.join(', ') || '—')]] : []))
      + '<h3>Risk ' + esc(x.score) + ' / 100</h3>' + x.why.map(function (w) { return '<div class="fd ' + (w.points >= 25 ? 'bad' : w.points >= 10 ? 'warn' : 'info') + '">+' + esc(w.points) + ' ' + esc(w.text) + '</div>'; }).join('')
      + (r ? '<h3>Registry (RDAP) ' + esc(r.at ? new Date(r.at).toISOString().slice(0, 16).replace('T', ' ') : '') + '</h3>' + (r.ok ? Z.kv([['Expires', esc(r.expires || '—')], ['Registrar', esc(r.registrar || '—')], ['Transfer lock', r.locked ? 'yes' : 'NO'], ['Status', esc((r.status || []).join(', '))]]) : '<div class="fd warn">' + esc(r.error) + '</div>') + (r.changes || []).map(function (c) { return '<div class="fd ' + (c.level === 'bad' ? 'bad' : 'info') + '">' + esc(c.text) + '</div>'; }).join('') : '')
      + (t ? '<h3>' + esc(t.id) + ' · ' + esc(ST[t.state][0]) + '</h3>' + (t.history || []).slice().reverse().map(function (h) { return '<div class="muted" style="font-size:12px">' + esc(String(h.at).slice(0, 16).replace('T', ' ')) + (h.by ? ' · ' + esc(h.by) : '') + ' · ' + esc(h.what) + '</div>'; }).join('') : '<p class="muted">No renewal open: it opens by itself ' + esc(V.lead.used) + ' days before the expiry.</p>')
      + form + (x.kind === 'hosting' && can('admin') ? '<p><button type="button" class="btn" data-he="' + esc(x.id) + '">Edit the subscription</button></p>' : ''));
  }
  function hostForm(id) {
    var h = id ? itemOf('hosting:' + id) : null;
    Z.open('Hosting subscription', h ? h.name : 'New', '<form id="rn-hf" class="fm" data-id="' + esc(id || '') + '"><label>Provider<input name="provider" required maxlength="120" value="' + esc(h ? h.provider : '') + '"></label><label>Service<input name="service" required maxlength="120" value="' + esc(h ? h.name.split(' · ')[1] || '' : '') + '"></label>'
      + '<label>Plan<input name="plan" maxlength="120" value="' + esc(h ? h.plan : '') + '"></label><label>Renews on<input type="date" name="renews" required value="' + esc(h ? h.expires : '') + '"></label><label>Term (months)<input type="number" name="term_months" min="1" max="120" value="' + esc(h ? h.term_months : 12) + '"></label>'
      + '<label>Cost<input type="number" name="cost" min="0" step="0.01" value="' + esc(h && h.cost != null ? h.cost : '') + '"></label><label>Owner<input name="owner" required maxlength="120" value="' + esc(h ? h.owner : '') + '"></label>'
      + '<label>Hostnames it serves<select name="hosts" multiple size="4">' + (V.hosts || []).map(function (o) { return '<option value="' + esc(o.id) + '"' + (h && h.hosts && h.hosts.indexOf(o.fqdn) >= 0 ? ' selected' : '') + '>' + esc(o.fqdn) + '</option>'; }).join('') + '</select></label>'
      + '<label><span><input type="checkbox" name="auto_renew"' + (h && h.auto_renew ? ' checked' : '') + '> auto-renew at the provider</span></label><div><button type="submit" class="btn pri">Save</button></div><div class="err" id="rn-msg" style="grid-column:1/-1"></div></form>');
  }
  function askForm() { Z.open('Renewal advisor (AI)', 'read-only - it explains and drafts, it never moves a renewal', '<form id="rn-af"><textarea name="q" rows="3" maxlength="2000" style="width:100%" placeholder="What should we renew first, and what should I ask the registrar?"></textarea><p><button type="submit" class="btn pri">Ask</button></p></form><div id="rn-aa"></div>'); }
  document.addEventListener('click', function (ev) {
    var b;
    if ((b = ev.target.closest('#ren [data-rf]'))) { F = F === b.getAttribute('data-rf') ? '' : b.getAttribute('data-rf'); return draw(); }
    if ((b = ev.target.closest('#ren [data-ri]'))) return openItem(b.getAttribute('data-ri'));
    if (ev.target.closest('#rn-rdap')) { ev.target.disabled = true; toast('Reading every domain from the registry (RDAP)…'); return req('POST', '/renewals/rdap', {}).then(function (r) { toast(r.ok + ' of ' + r.read + ' domain(s) read from the registry' + (r.failed.length ? ' - ' + r.failed.length + ' not readable' : '')); load(); }).catch(function (e) { toast(e.message); load(); }); }
    if (ev.target.closest('#rn-host')) return hostForm(null);
    if ((b = ev.target.closest('[data-he]'))) return hostForm(b.getAttribute('data-he'));
    if (ev.target.closest('#rn-ask')) return askForm();
    if (ev.target.closest('#rn-set')) { return Z.open('Lead time', 'days before the expiry a renewal opens', '<form id="rn-sf" class="fm"><label>Lead days (14-365)<input type="number" name="lead_days" min="14" max="365" value="' + esc(V.settings.lead_days) + '" required></label><div><button type="submit" class="btn pri">Save</button></div><div class="err" id="rn-msg"></div><p class="muted" style="grid-column:1/-1">The autopilot uses the larger of this and what it learned: ' + esc(V.lead.basis) + '.</p></form>'); }
    if (ev.target.closest('#rn-cancel')) { var f0 = document.getElementById('rn-adv'), note = f0.elements.namedItem('note').value; return req('POST', '/renewals/tasks/' + encodeURIComponent(f0.getAttribute('data-id')) + '/advance', { to: 'cancelled', note: note }).then(function () { Z.close(); toast('Renewal cancelled'); load(); }).catch(function (e) { document.getElementById('rn-msg').textContent = e.message; }); }
  });
  document.addEventListener('submit', function (ev) {
    var f = ev.target, g = function (n) { var x = f.elements.namedItem(n); return x ? x.value.trim() : ''; }, msg = function (t) { var m = document.getElementById('rn-msg'); if (m) m.textContent = t; };
    if (f.id === 'rn-adv') { ev.preventDefault(); var b = { to: f.getAttribute('data-to'), note: g('note') }; if (g('new_expiry')) b.new_expiry = g('new_expiry'); if (g('cost')) b.cost = Number(g('cost')); if (g('evidence')) b.evidence = g('evidence');
      return req('POST', '/renewals/tasks/' + encodeURIComponent(f.getAttribute('data-id')) + '/advance', b).then(function (t) { Z.close(); toast(t.id + ' is now ' + t.state); load(); }).catch(function (e) { msg(e.message); }); }
    if (f.id === 'rn-hf') { ev.preventDefault(); var h = { provider: g('provider'), service: g('service'), plan: g('plan'), renews: g('renews'), term_months: Number(g('term_months') || 12), owner: g('owner'), auto_renew: f.elements.namedItem('auto_renew').checked, hosts: [].slice.call(f.elements.namedItem('hosts').selectedOptions).map(function (o) { return o.value; }) };
      if (g('cost')) h.cost = Number(g('cost')); if (f.getAttribute('data-id')) h.id = f.getAttribute('data-id');
      return req('POST', '/renewals/hosting', h).then(function () { Z.close(); toast('Hosting subscription saved'); load(); }).catch(function (e) { msg(e.message); }); }
    if (f.id === 'rn-sf') { ev.preventDefault(); return req('POST', '/renewals/settings', { lead_days: Number(g('lead_days')), version: V.settings.version || 0 }).then(function () { Z.close(); toast('Lead time saved'); load(); }).catch(function (e) { msg(e.message); }); }
    if (f.id === 'rn-af') { ev.preventDefault(); var out = document.getElementById('rn-aa'); out.innerHTML = '<span class="muted">Thinking…</span>'; return req('POST', '/renewals/ask', { question: g('q') }).then(function (r) { out.innerHTML = '<div style="white-space:pre-wrap">' + esc(r.answer) + '</div>'; }).catch(function (e) { out.innerHTML = '<div class="err">' + esc(e.message) + '</div>'; }); }
  });
  var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.onload = function () { try { var j = JSON.parse(w.responseText), rl = String(j.role || '').toLowerCase(); if (RANK[rl] != null) ROLE = rl; } catch (e) { /* no identity: viewer */ } load(); }; w.onerror = function () { load(); }; w.send();
})();
