/* Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE. */
/* Directory accounts drawer - shared by AD & Exchange and AD Audit. The accounts behind a number (a filter of the SIEM's directory
 * snapshot, GET /api/soc/identity/users) or the members of a privileged group, in the side drawer with a search; an account opens
 * with its groups, sign-in, password age and flags, a way back to the list and a link to AD Management.
 *   zybAdAccounts.open(key, group?, opts?)   key: a filter below ('' with a group); opts.events(u, el) fills the account's events,
 *                                            opts.full(key, group) adds "Full list with CSV export"
 * Every value is escaped; requests are marked quiet (the drawer reports its own failures). */
(function () {
  'use strict';
  var F = {
    all: ['All accounts', {}], privileged: ['Privileged accounts (enabled)', { privileged: 1, disabled: 0 }], disabled: ['Disabled accounts', { disabled: 1 }],
    dormant: ['Dormant accounts', { dormant: 1 }], service: ['Service accounts', { service: 1 }], priv_dormant: ['Dormant privileged accounts', { privileged: 1, dormant: 1 }],
    priv_never: ['Privileged, password never expires', { privileged: 1, flag: 'pwd_never_expires' }], pwd_never_expires: ['Password never expires', { flag: 'pwd_never_expires' }],
    pwd_not_required: ['Password not required', { flag: 'pwd_not_required' }], no_preauth: ['Kerberos pre-authentication off (AS-REP roastable)', { flag: 'no_preauth' }],
    delegation: ['Trusted for unconstrained delegation', { flag: 'delegation' }], old_pwd: ['Password older than 365 days', { flag: 'old_pwd' }],
    never_logon: ['Enabled, never signed in', { flag: 'never_logon' }], admin_orphan: ['adminCount leftovers - adminCount=1 but no longer privileged', { flag: 'admin_orphan' }],
    expired: ['Expired accounts', { flag: 'expired' }]
  };
  var S = { L: null, title: '', key: '', group: '', opts: {}, err: '' };
  var Z = function () { return window.zybDetail; }, esc = function (v) { return Z().esc(v); }, $ = function (id) { return document.getElementById(id); };
  var dd = function (x) { return x ? String(x).replace('T', ' ').slice(0, 16) : 'never'; };
  function get(url) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open('GET', url); x.withCredentials = true; x.timeout = 60000; x.zybQuiet = true;
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: reported below with the status */ } if (x.status >= 200 && x.status < 300 && j) ok(j); else bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('The SIEM is not reachable')); }; x.send(null);
    });
  }
  function flags(u) {
    var o = [], p = function (c, t) { o.push('<span class="pill ' + c + '">' + t + '</span>'); };
    if (u.privileged) p('bad', 'privileged'); if (u.disabled) p('', 'disabled'); if (u.dormant) p('warn', 'dormant'); if (u.pwd_never_expires) p('warn', 'pwd never expires');
    if (u.pwd_not_required) p('bad', 'pwd not required'); if (u.no_preauth) p('bad', 'no pre-auth'); if (u.delegation) p('bad', 'unconstrained delegation');
    if (u.admin_orphan) p('info', 'adminCount leftover'); if (u.service_account) p('info', 'service'); if (u.expired) p('', 'expired');
    return o.join(' ');
  }
  function shell(body) {
    var full = S.opts.full ? '<button type="button" class="btn" data-zafull="1">Full list with CSV export</button>' : '<a href="ad-audit.html" style="color:var(--info)">AD Audit</a> has every list, CSV export and each account\'s events.';
    Z().open('Directory accounts', S.title, '<input type="search" id="zaq" placeholder="Search name, account, department" style="width:100%;margin:0 0 10px" value="' + esc(S.q || '') + '">'
      + '<div id="zal">' + body + '</div><p class="muted" style="margin-top:10px">Read from the last directory sync. ' + full + '</p>');
  }
  function draw() {
    var el = $('zal'); if (!el) return;
    if (S.err) { el.innerHTML = '<p class="err">' + esc(S.err) + '</p>'; return; }
    if (!S.L) { el.innerHTML = '<div class="empty">Loading…</div>'; return; }
    var q = (S.q || '').toLowerCase(), L = S.L.filter(function (u) { return !q || [u.sam, u.name, u.upn, u.department, u.title].join(' ').toLowerCase().indexOf(q) >= 0; });
    el.innerHTML = '<div class="muted" style="margin:0 0 6px">' + L.length + ' account(s)' + (L.length > 500 ? ' - showing 500, search to narrow' : '') + '</div>' + (L.length
      ? '<div class="tw"><table><thead><tr><th>Account</th><th>Name</th><th>Department</th><th>Last sign-in</th><th>Flags</th></tr></thead><tbody>' + L.slice(0, 500).map(function (u) {
        return '<tr data-zau="' + esc(u.sam) + '" tabindex="0" style="cursor:pointer"><td><b>' + esc(u.sam) + '</b></td><td>' + esc(u.name || '') + '</td><td>' + esc(u.department || '–') + '</td><td class="mono">' + esc(dd(u.last_logon)) + '</td><td>' + flags(u) + '</td></tr>';
      }).join('') + '</tbody></table></div>'
      : '<div class="empty">No accounts in this list.</div>');
  }
  function open(key, group, opts) {
    var f = group ? ['Members of ' + group, { privileged: 1 }] : (F[key] || F.all);
    S = { L: null, title: f[0], key: group ? '' : (F[key] ? key : 'all'), group: group || '', opts: opts || {}, err: '', q: '' };
    shell('<div class="empty">Loading…</div>');
    var all = [], qs = Object.keys(f[1]).map(function (k) { return k + '=' + encodeURIComponent(f[1][k]); }).join('&'), mine = S;
    var page = function (off) { return get('/api/soc/identity/users?limit=1000&offset=' + off + (qs ? '&' + qs : '')).then(function (r) { all = all.concat(r.items || []); return all.length < (r.total || 0) && off < 20000 ? page(off + 1000) : all; }); };
    page(0).then(function (L) { if (S !== mine) return; S.L = group ? L.filter(function (u) { return (u.privileged_groups || []).indexOf(group) >= 0; }) : L; draw(); })
      .catch(function (e) { if (S !== mine) return; S.err = e.status === 403 ? 'Directory accounts are visible to administrators only.' : e.message; draw(); });
  }
  function account(sam) {
    var u = (S.L || []).filter(function (x) { return x.sam === sam; })[0]; if (!u) return;
    var z = Z();
    z.open('Directory account', u.sam, '<p><a href="#" data-zaback="1" style="color:var(--info)">← ' + esc(S.title) + '</a></p>'
      + z.kv([['Name', esc(u.name || '')], ['UPN', esc(u.upn || '')], ['Department', esc(u.department || '')], ['Title', esc(u.title || '')], ['Manager', esc(u.manager || '')], ['Created', esc(dd(u.created))],
        ['Last sign-in', esc(dd(u.last_logon))], ['Password last set', esc(dd(u.pwd_last_set)) + (u.pwd_age_days != null ? ' (' + u.pwd_age_days + ' days)' : '')], ['Expires', esc(u.expires ? dd(u.expires) : 'never')],
        ['Privileged groups', esc((u.privileged_groups || []).join(', ') || 'none')]])
      + z.sec('Flags', flags(u) || 'none') + z.sec('Distinguished name', '<span class="mono">' + esc(u.dn || '') + '</span>')
      + '<p style="margin-top:12px"><a class="btn" href="ad-manage.html" style="color:var(--info)">Change it in AD Management</a> <span class="muted">(disable, groups, reset - approved by a second administrator)</span></p>'
      + (S.opts.events ? '<div id="zaev">Loading recent events…</div>' : ''));
    if (S.opts.events) { try { S.opts.events(u, $('zaev')); } catch (e) { var el = $('zaev'); if (el) el.textContent = ''; /* the events are an extra: the account is shown without them */ } }
  }
  document.addEventListener('click', function (e) {
    var t = e.target, r;
    if ((r = t.closest('[data-zau]'))) { account(r.getAttribute('data-zau')); return; }
    if ((r = t.closest('[data-zaback]'))) { e.preventDefault(); shell(''); draw(); return; }
    if ((r = t.closest('[data-zafull]'))) { Z().close(); S.opts.full(S.key, S.group); return; }
  });
  document.addEventListener('input', function (e) { if (e.target.id === 'zaq') { S.q = e.target.value; draw(); } });
  document.addEventListener('keydown', function (e) { if (e.key === 'Enter' && e.target.closest && e.target.closest('[data-zau]')) { e.preventDefault(); e.target.closest('[data-zau]').click(); } });
  window.zybAdAccounts = { open: open, filters: F, flags: flags };
})();
