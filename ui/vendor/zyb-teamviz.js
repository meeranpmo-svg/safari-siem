/* Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
 * zyb-teamviz.js - the live Team overview on ai-team.html: every AI engineer drawn on an operations floor around the duty
 * engine, and each one's agent loop (detect -> diagnose -> propose -> approve -> act -> verify).
 *
 * Every movement is the engineer's real state from /duty/engineers - nothing animated is invented:
 *   radar sweep        on duty and patrolling on time (its last patrol was not late)
 *   gentle bob         it has open work items
 *   dots to the core   open work items travelling through the loop (red = critical), at most 6 per engineer
 *   purple dots down   changes waiting for a human approver (four-eyes: the AI never approves its own change)
 *   amber blink        the last patrol was late or failed
 *   grey and still     off duty, or its source is not connected yet
 * Respects prefers-reduced-motion (the state stays readable, the movement stops). Every value is escaped; no inline
 * handlers. window.zybTeamViz = { floor(el, engineers), loop(engineer) → html, stages(byStatus) }. */
(function () {
  'use strict';
  var esc = function (s) { return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var REDUCED = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  var HEX = { teal: '#0ca678', pink: '#d6336c', orange: '#f76707', indigo: '#4263eb', green: '#2fb344', cyan: '#17a2b8', blue: '#206bc4', azure: '#4299e1',
    red: '#d63939', purple: '#ae3ec9', yellow: '#f59f00', lime: '#74b816', secondary: '#6c7a91' };
  // the agent loop and which work-item statuses sit in each step (engine/duty-core.js)
  var LOOP = [['detect', 'Detect', ['open']], ['diagnose', 'Diagnose', ['investigating']], ['propose', 'Propose', ['diagnosed', 'needs-human']],
    ['approve', 'Approve', ['awaiting-approval']], ['act', 'Act', ['approved']], ['verify', 'Verify', ['fix-applied']]];
  var CSS = ''
    + '.tv-floor{position:relative;width:100%;aspect-ratio:16/8;min-height:460px;border:1px solid var(--tblr-border-color);border-radius:14px;overflow:hidden;'
    + 'background:radial-gradient(ellipse at center,rgba(57,135,229,.14),transparent 62%),repeating-linear-gradient(0deg,rgba(255,255,255,.025) 0 1px,transparent 1px 28px),repeating-linear-gradient(90deg,rgba(255,255,255,.025) 0 1px,transparent 1px 28px)}'
    + '.tv-floor svg.tv-links{position:absolute;inset:0;width:100%;height:100%}'
    + '.tv-core{position:absolute;left:50%;top:44%;transform:translate(-50%,-50%);width:132px;height:132px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;'
    + 'background:radial-gradient(circle,#1d3a5f,#0f1c2e);border:1px solid #2c5282;box-shadow:0 0 40px rgba(57,135,229,.35);z-index:2}'
    + '.tv-core b{font-size:13px}.tv-core small{font-size:10.5px;color:var(--tblr-secondary)}.tv-core .tv-ring{position:absolute;inset:-10px;border-radius:50%;border:2px dashed rgba(66,153,225,.45);animation:tv-spin 22s linear infinite}'
    + '.tv-core .tv-ring2{position:absolute;inset:-22px;border-radius:50%;border:1px solid rgba(66,153,225,.18);animation:tv-spin 40s linear infinite reverse}'
    + '.tv-hum{position:absolute;left:50%;bottom:10px;transform:translateX(-50%);z-index:2;padding:6px 14px;border-radius:20px;background:rgba(174,62,201,.14);border:1px solid rgba(174,62,201,.55);font-size:12px;white-space:nowrap}'
    + '.tv-hum.tv-wait{box-shadow:0 0 0 0 rgba(174,62,201,.6);animation:tv-pulse 2s infinite}'
    + '.tv-n{position:absolute;transform:translate(-50%,-50%);width:112px;text-align:center;text-decoration:none!important;color:inherit;z-index:3}'
    + '.tv-av{position:relative;width:54px;height:54px;margin:0 auto 4px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:24px;color:#fff;border:2px solid rgba(255,255,255,.18)}'
    + '.tv-n .tv-nm{font-size:11.5px;font-weight:600;line-height:1.15;display:block}.tv-n .tv-st{font-size:10.5px;color:var(--tblr-secondary);display:block}'
    + '.tv-n .tv-cnt{position:absolute;top:-6px;right:-8px;min-width:20px;height:20px;padding:0 5px;border-radius:10px;background:#d63939;color:#fff;font-size:11px;font-weight:700;line-height:20px}'
    + '.tv-n .tv-cnt.tv-c-open{background:#206bc4}.tv-n .tv-apr{position:absolute;bottom:-4px;right:-10px;font-size:13px;background:#ae3ec9;border-radius:50%;width:22px;height:22px;line-height:22px;color:#fff}'
    + '.tv-n:hover .tv-av{transform:scale(1.08)}.tv-n:focus-visible{outline:2px solid #4299e1;border-radius:8px}'
    + '.tv-radar{position:absolute;inset:-9px;border-radius:50%;background:conic-gradient(from 0deg,rgba(47,179,68,.0),rgba(47,179,68,.55) 18%,rgba(47,179,68,0) 30%);animation:tv-spin 3.2s linear infinite;-webkit-mask:radial-gradient(circle,transparent 58%,#000 60%);mask:radial-gradient(circle,transparent 58%,#000 60%)}'
    + '.tv-busy .tv-av{animation:tv-bob 2.6s ease-in-out infinite}.tv-warn .tv-av{animation:tv-blink 1.4s steps(2) infinite}.tv-off{opacity:.45;filter:grayscale(1)}'
    + '@keyframes tv-spin{to{transform:rotate(360deg)}}@keyframes tv-bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}'
    + '@keyframes tv-blink{0%{box-shadow:0 0 0 0 rgba(245,159,0,.9)}100%{box-shadow:0 0 0 8px rgba(245,159,0,0)}}@keyframes tv-pulse{70%{box-shadow:0 0 0 12px rgba(174,62,201,0)}100%{box-shadow:0 0 0 0 rgba(174,62,201,0)}}'
    + '.tv-legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12px;color:var(--tblr-secondary);margin-top:10px}.tv-legend i.tv-k{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:-1px}'
    + '.tv-loop{display:flex;align-items:center;gap:0;margin-top:12px}.tv-step{flex:1;text-align:center;min-width:0}'
    + '.tv-step .tv-d{width:26px;height:26px;margin:0 auto 3px;border-radius:50%;border:2px solid var(--tblr-border-color);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--tblr-secondary)}'
    + '.tv-step.tv-on .tv-d{border-color:#4299e1;color:#fff;background:#206bc4;box-shadow:0 0 0 0 rgba(66,153,225,.7);animation:tv-pulse 2.2s infinite}'
    + '.tv-step.tv-on.tv-apv .tv-d{background:#ae3ec9;border-color:#ae3ec9}.tv-step .tv-l{font-size:10px;color:var(--tblr-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}'
    + '.tv-bar{flex:0 0 10px;height:2px;margin-bottom:16px;background:var(--tblr-border-color);position:relative;overflow:hidden}'
    + '.tv-bar.tv-flow{background:linear-gradient(90deg,transparent,#4299e1,transparent);background-size:200% 100%;animation:tv-flow 1.6s linear infinite}@keyframes tv-flow{from{background-position:100% 0}to{background-position:-100% 0}}'
    + '@media (max-width:767px){.tv-floor{aspect-ratio:auto;min-height:0;display:flex;flex-wrap:wrap;gap:14px;justify-content:center;padding:16px 8px 56px}.tv-floor svg.tv-links,.tv-core{display:none}.tv-n{position:static;transform:none}}'
    + '@media (prefers-reduced-motion:reduce){.tv-floor *,.tv-loop *{animation:none!important}}';

  function stages(by) {
    by = by || {}; var out = {};
    LOOP.forEach(function (s) { out[s[0]] = s[2].reduce(function (n, k) { return n + (by[k] || 0); }, 0); });
    return out;
  }
  function stateOf(e) {
    if (!e.on_duty || e.not_connected) return 'off';
    if (e.late || e.last_error) return 'warn';
    return e.open ? 'busy' : 'idle';
  }
  function statusLine(e) {
    var st = stateOf(e), sg = stages(e.by_status);
    if (!e.on_duty) return 'off duty';
    if (e.not_connected) return 'source not connected';
    if (e.last_error) return 'last patrol had a problem';
    if (e.late) return 'patrol is late';
    if (sg.approve) return sg.approve + ' waiting for approval';
    if (st === 'busy') return e.open + ' open · working';
    return 'patrolling · all clear';
  }
  function loop(e) {
    var sg = stages(e.by_status), h = '<div class="tv-loop" role="img" aria-label="Agent loop for ' + esc(e.name) + '">';
    LOOP.forEach(function (s, i) {
      var n = sg[s[0]], on = n > 0;
      if (i) h += '<div class="tv-bar' + (on || sg[LOOP[i - 1][0]] ? ' tv-flow' : '') + '"></div>';
      h += '<div class="tv-step' + (on ? ' tv-on' : '') + (s[0] === 'approve' ? ' tv-apv' : '') + '" title="' + esc(s[1] + ': ' + n + ' item(s)') + '"><div class="tv-d">' + (on ? esc(n) : i + 1) + '</div><div class="tv-l">' + esc(s[1]) + '</div></div>';
    });
    return h + '</div>';
  }
  function floor(el, list) {
    if (!document.getElementById('tv-css')) { var st = document.createElement('style'); st.id = 'tv-css'; st.textContent = CSS; document.head.appendChild(st); }
    if (!list.length) { el.innerHTML = '<div class="text-secondary p-3">No AI engineer reported yet - run the engine update, then Patrol all now.</div>'; return; }
    var n = list.length, cx = 50, cy = 44, rx = 40, ry = 33;
    var pos = list.map(function (e, i) { var a = -Math.PI / 2 + 2 * Math.PI * i / n; return { x: cx + rx * Math.cos(a), y: cy + ry * Math.sin(a) }; });
    var waiting = list.reduce(function (t, e) { return t + stages(e.by_status).approve; }, 0);
    var open = list.reduce(function (t, e) { return t + (e.on_duty ? e.open || 0 : 0); }, 0);
    var onDuty = list.filter(function (e) { return e.on_duty && !e.not_connected; }).length;
    // links and the packets travelling on them (viewBox in percent units, so the floor scales)
    var svg = '<svg class="tv-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">';
    list.forEach(function (e, i) {
      var p = pos[i], col = HEX[e.color] || HEX.purple, s = stateOf(e), sg = stages(e.by_status);
      var d = 'M' + p.x.toFixed(2) + ' ' + p.y.toFixed(2) + ' L' + cx + ' ' + cy, id = 'tv-p' + i;
      svg += '<path id="' + id + '" d="' + d + '" stroke="' + (s === 'off' ? '#3a4458' : col) + '" stroke-opacity="' + (s === 'off' ? .35 : .45) + '" stroke-width=".25" fill="none" vector-effect="non-scaling-stroke" stroke-dasharray="' + (s === 'off' ? '1 1' : '0') + '"/>';
      if (REDUCED || s === 'off') return;
      var k = Math.min(6, e.open || 0), crit = e.critical || 0;
      for (var j = 0; j < k; j++) {
        var dur = (crit ? 2.2 : 3.4) + (j % 3) * .4, c = j < crit ? '#ff5c5c' : '#7cc4ff';
        svg += '<circle r=".55" fill="' + c + '"><animateMotion dur="' + dur + 's" begin="' + (j * dur / Math.max(k, 1)).toFixed(2) + 's" repeatCount="indefinite"><mpath href="#' + id + '"/></animateMotion></circle>';
      }
      if (sg.approve) {
        var ap = 'tv-a' + i;
        svg += '<path id="' + ap + '" d="M' + p.x.toFixed(2) + ' ' + p.y.toFixed(2) + ' Q' + cx + ' ' + (cy + 30) + ' 50 96" stroke="#ae3ec9" stroke-opacity=".35" stroke-width=".2" fill="none" vector-effect="non-scaling-stroke" stroke-dasharray="1.2 1"/>';
        for (var q = 0; q < Math.min(3, sg.approve); q++) svg += '<circle r=".7" fill="#d68cf0"><animateMotion dur="3s" begin="' + q + 's" repeatCount="indefinite"><mpath href="#' + ap + '"/></animateMotion></circle>';
      }
    });
    svg += '</svg>';
    var nodes = list.map(function (e, i) {
      var p = pos[i], s = stateOf(e), sg = stages(e.by_status), col = HEX[e.color] || HEX.purple;
      return '<a class="tv-n tv-' + s + '" href="' + esc(e.page || '#') + '" style="left:' + p.x.toFixed(2) + '%;top:' + p.y.toFixed(2) + '%" title="' + esc(e.name + ' - ' + statusLine(e) + (e.ai && e.ai.enabled ? ' · agentic AI on' : ' · rules + ML')) + '" data-eng="' + esc(e.id) + '">'
        + '<span class="tv-av" style="background:radial-gradient(circle at 30% 30%,' + col + ',' + col + 'aa 70%)">'
        + ((s === 'idle' || s === 'busy') && !REDUCED ? '<span class="tv-radar"></span>' : '')
        + '<i class="ti ti-' + esc(e.icon || 'robot') + '"></i>'
        + (e.open && s !== 'off' ? '<span class="tv-cnt' + (e.critical ? '' : ' tv-c-open') + '">' + esc(e.open) + '</span>' : '')
        + (sg.approve ? '<span class="tv-apr" aria-label="waiting for approval">✋</span>' : '') + '</span>'
        + '<span class="tv-nm">' + esc(e.short || e.name) + '</span><span class="tv-st">' + esc(statusLine(e)) + '</span></a>';
    }).join('');
    el.innerHTML = '<div class="tv-floor">' + svg
      + '<div class="tv-core"><span class="tv-ring"></span><span class="tv-ring2"></span><i class="ti ti-cpu" style="font-size:26px"></i><b>Duty engine</b><small>' + esc(onDuty + ' of ' + n + ' on duty') + '<br>' + esc(open + ' open item' + (open === 1 ? '' : 's')) + '</small></div>'
      + nodes
      + '<div class="tv-hum' + (waiting ? ' tv-wait' : '') + '"><i class="ti ti-user-check me-1"></i>Human approvers · ' + esc(waiting ? waiting + ' change' + (waiting === 1 ? '' : 's') + ' waiting for a decision' : 'nothing waiting') + '</div></div>'
      + '<div class="tv-legend"><span><i class="tv-k" style="background:#2fb344"></i>radar = patrolling on time</span><span><i class="tv-k" style="background:#7cc4ff"></i>dots to the core = open work (red = critical)</span>'
      + '<span><i class="tv-k" style="background:#d68cf0"></i>purple = waiting for a person to approve</span><span><i class="tv-k" style="background:#f59f00"></i>amber = late or failed patrol</span><span><i class="tv-k" style="background:#6c7a91"></i>grey = off duty / not connected</span>'
      + '<span>Every movement is live state from the duty engine - nothing is simulated.</span></div>';
  }
  /* an engineer and what it looks after: estate(el, centre, nodes) - the AI engineer in the middle (its own duty state), each
   * system around it. node = {id, name, sub, state: ok|warn|bad|off, issues, icon, href, title}. Movement is real state only:
   * radar = reporting and healthy, amber blink = needs attention, red pulse + red dots to the centre = problems the engineer is
   * working on (one dot per issue, at most 6), grey and still = not reporting / not read. */
  function estate(el, centre, nodes) {
    if (!document.getElementById('tv-css')) { var st = document.createElement('style'); st.id = 'tv-css'; st.textContent = CSS; document.head.appendChild(st); }
    if (!document.getElementById('tv-css2')) { var s2 = document.createElement('style'); s2.id = 'tv-css2'; s2.textContent = '.tv-bad .tv-av{animation:tv-red 1.6s infinite}@keyframes tv-red{0%{box-shadow:0 0 0 0 rgba(214,57,57,.8)}100%{box-shadow:0 0 0 12px rgba(214,57,57,0)}}@media (prefers-reduced-motion:reduce){.tv-bad .tv-av{animation:none}}'; document.head.appendChild(s2); }
    var n = nodes.length, cx = 50, cy = 44, rx = n > 10 ? 42 : 36, ry = n > 10 ? 35 : 30;
    if (!n) { el.innerHTML = '<div class="text-secondary p-3">' + esc(centre.empty || 'Nothing to look after yet.') + '</div>'; return; }
    var COL = { ok: '#2fb344', warn: '#f59f00', bad: '#d63939', off: '#6c7a91' };
    var pos = nodes.map(function (x, i) { var a = -Math.PI / 2 + 2 * Math.PI * i / n; return { x: cx + rx * Math.cos(a), y: cy + ry * Math.sin(a) }; });
    var svg = '<svg class="tv-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">';
    nodes.forEach(function (x, i) {
      var p = pos[i], id = 'tv-e' + i;
      svg += '<path id="' + id + '" d="M' + p.x.toFixed(2) + ' ' + p.y.toFixed(2) + ' L' + cx + ' ' + cy + '" stroke="' + COL[x.state] + '" stroke-opacity="' + (x.state === 'off' ? .3 : .45) + '" stroke-width=".25" fill="none" vector-effect="non-scaling-stroke"' + (x.state === 'off' ? ' stroke-dasharray="1 1"' : '') + '/>';
      if (REDUCED || x.state === 'off') return;
      var k = Math.min(6, x.issues || 0);
      for (var j = 0; j < k; j++) svg += '<circle r=".55" fill="' + (x.state === 'bad' ? '#ff5c5c' : '#ffc04d') + '"><animateMotion dur="' + (2.4 + (j % 3) * .4) + 's" begin="' + (j * .5).toFixed(2) + 's" repeatCount="indefinite"><mpath href="#' + id + '"/></animateMotion></circle>';
    });
    svg += '</svg>';
    var html = nodes.map(function (x, i) {
      var p = pos[i], c = COL[x.state] || COL.off;
      return '<a class="tv-n tv-' + (x.state === 'ok' ? 'idle' : x.state) + '" href="' + esc(x.href || '#') + '" style="left:' + p.x.toFixed(2) + '%;top:' + p.y.toFixed(2) + '%" title="' + esc(x.title || x.name) + '" data-node="' + esc(x.id) + '">'
        + '<span class="tv-av" style="width:46px;height:46px;font-size:20px;background:radial-gradient(circle at 30% 30%,' + c + ',' + c + '99 70%)">'
        + (x.state === 'ok' && !REDUCED ? '<span class="tv-radar"></span>' : '') + '<i class="ti ti-' + esc(x.icon || 'database') + '"></i>'
        + (x.issues ? '<span class="tv-cnt' + (x.state === 'bad' ? '' : ' tv-c-open') + '">' + esc(x.issues) + '</span>' : '') + '</span>'
        + '<span class="tv-nm">' + esc(x.name) + '</span><span class="tv-st">' + esc(x.sub || '') + '</span></a>';
    }).join('');
    var cnt = { ok: 0, warn: 0, bad: 0, off: 0 }; nodes.forEach(function (x) { cnt[x.state] = (cnt[x.state] || 0) + 1; });
    el.innerHTML = '<div class="tv-floor">' + svg
      + '<div class="tv-core"><span class="tv-ring"></span><span class="tv-ring2"></span><i class="ti ti-' + esc(centre.icon || 'robot') + '" style="font-size:26px"></i><b>' + esc(centre.name) + '</b><small>' + esc(centre.sub || '') + '</small></div>'
      + html + (centre.waiting ? '<div class="tv-hum tv-wait"><i class="ti ti-user-check me-1"></i>' + esc(centre.waiting) + '</div>' : '') + '</div>'
      + '<div class="tv-legend"><span><i class="tv-k" style="background:#2fb344"></i>radar = reporting, healthy (' + cnt.ok + ')</span><span><i class="tv-k" style="background:#f59f00"></i>amber = needs attention (' + cnt.warn + ')</span>'
      + '<span><i class="tv-k" style="background:#d63939"></i>red + dots to the centre = ' + esc(centre.badLabel || 'problems being worked') + ' (' + cnt.bad + ')</span><span><i class="tv-k" style="background:#6c7a91"></i>grey = not reporting / not read (' + cnt.off + ')</span>'
      + '<span>Every movement is the database\'s real state - nothing is simulated.</span>' + (centre.note ? '<span>' + esc(centre.note) + '</span>' : '') + '</div>';
  }
  /* the AI Oracle DBA and every Oracle database it looks after: health from the SIEM's Oracle summary (every 4 min) joined with the
   * database inventory (PDBs, size; ITAM engine/db-inventory.js) and the DBA's own duty state. Each read fails on its own.
   * Used by ai-dba.html and ai-team.html. */
  function get(u){return new Promise(function(ok){var x=new XMLHttpRequest();x.open('GET',u);x.withCredentials=true;x.timeout=60000;x.zybQuiet=true;
    x.onload=function(){var j=null;try{j=JSON.parse(x.responseText);}catch(e){j=null;/* not JSON: treated as not available */}ok(x.status===200?j:{__status:x.status});};x.onerror=x.ontimeout=function(){ok({__status:0});};x.send();});}
  function mb(v){return v==null?'':v>=1048576?(v/1048576).toFixed(1)+' TB':v>=1024?(v/1024).toFixed(1)+' GB':v+' MB';}
  var low=function(v){return String(v||'').toLowerCase().split('.')[0];};
  function oracleEstate(el, countEl){return Promise.all([get('/api/soc/db/oracle'),get('/api/itam/db-inventory'),get('/api/soc/duty/engineers')]).then(function(R){
    var I=(R[0]&&R[0].instances)||[], inv=((R[1]&&R[1].servers)||[]).filter(function(x){return x.engine==='oracle';}), used={}, nodes=[];
    I.forEach(function(i){
      var m=inv.filter(function(r){var sv=r.server||{};return !used[r.id]&&((sv.instance&&low(sv.instance)===low(i.instance))||(sv.host_name&&low(sv.host_name)===low(i.host))||low(r.host)===low(i.host)||r.ip===i.host);})[0];
      if(m)used[m.id]=1;
      var n=(i.issues||[]).length, st=i.stale?'off':!i.up&&i.state!=='unknown'?'bad':n&&(i.worst_severity||0)>=3?'bad':n?'warn':'ok';
      var pdb=m&&m.totals?m.totals.databases+' DB'+(m.totals.databases===1?'':'s')+' · '+mb(m.totals.size_mb):'';
      nodes.push({id:'i:'+i.instance+'@'+i.host,name:i.instance,icon:'database',state:st,issues:n,href:document.getElementById('inst')?'#inst':'ai-dba.html',
        sub:i.stale?'not reporting':(!i.up&&i.state!=='unknown'?(i.status||'down'):n?n+' issue'+(n>1?'s':''):(i.role||'open'))+(pdb?' · '+pdb:''),
        title:i.instance+' on '+i.host+(i.version?' · '+i.version:'')+(n?' - '+i.issues[0].text:'')+(m?' · inventory: '+pdb:'')});});
    inv.filter(function(r){return !used[r.id];}).forEach(function(r){var sv=r.server||{},hi=(r.notes||[]).filter(function(x){return x.severity==='high';}).length,nn=(r.notes||[]).length;
      nodes.push({id:'v:'+r.id,name:sv.instance||sv.db_name||r.asset_name||r.host,icon:'database',state:r.error?'off':hi?'bad':nn?'warn':'ok',issues:r.error?0:nn,href:'databases.html',
        sub:r.error?(r.error_class==='auth'?'login refused':'not read'):'inventory only'+(r.totals?' · '+mb(r.totals.size_mb):''),
        title:(r.asset_name||r.host)+' · '+r.ip+' - '+(r.error?r.error:'read by the database inventory; health is not collected for it yet (Database Health / collector)')+(nn&&!r.error?' - '+r.notes[0].text:'')});});
    var dba=((R[2]&&R[2].engineers)||[]).filter(function(e){return e.id==='dba';})[0], ap=dba&&dba.by_status?(dba.by_status['awaiting-approval']||0):0;
    estate(el,{name:'AI Oracle DBA',icon:'robot',sub:dba?(dba.on_duty?'on duty':'off duty')+' · '+(dba.open||0)+' open':'duty engine not reachable',
      waiting:ap?ap+' change'+(ap>1?'s':'')+' waiting for a DBA to approve':'',empty:'No Oracle database reports yet: install the read-only collector (agents/oracle), register a database on the Databases page, or add an Oracle login in Asset Discovery.'},nodes);
    if(countEl)countEl.textContent=nodes.length+' Oracle database'+(nodes.length===1?'':'s')+(R[1]&&R[1].__status===403?' · inventory details are for operators':'')+(R[0]&&R[0].__status?' · SIEM Oracle summary not available':'');
  });}
  /* SQL Server, PostgreSQL and MySQL around the AI Database Administrator (ITAM engine/sqldba.js over engine/db-inventory.js):
   * every server read from its proven login, and every server where the database runs without a login yet (grey). The centre is
   * the engineer's own duty state; without the engineer installed it is the database inventory. */
  var ENG_ICON = { mssql: 'brand-windows', postgres: 'database', mysql: 'database' };
  function dbEstate(el, countEl) {
    return Promise.all([get('/api/itam/db-inventory'), get('/api/itam/duty/engineers')]).then(function (R) {
      var v = R[0], me = ((R[1] && R[1].engineers) || []).filter(function (e) { return e.id === 'sqldba'; })[0];
      if (!v || v.__status) {
        el.innerHTML = '<div class="text-secondary p-3">' + esc(v && v.__status === 403 ? 'The database inventory is for operators and administrators.' : v && v.__status === 404 ? 'The database inventory is not installed yet - run the platform update.' : 'The database inventory is not reachable.') + '</div>';
        if (countEl) countEl.textContent = ''; return;
      }
      var eng = { mssql: 1, postgres: 1, mysql: 1 }, nodes = [];
      (v.servers || []).filter(function (r) { return eng[r.engine]; }).forEach(function (r) {
        var hi = (r.notes || []).filter(function (x) { return x.severity === 'high'; }).length, nn = (r.notes || []).length, sv = r.server || {};
        nodes.push({ id: 'r:' + r.id, name: r.asset_name || r.host, icon: ENG_ICON[r.engine], state: r.error ? 'off' : hi ? 'bad' : nn ? 'warn' : 'ok', issues: r.error ? 0 : nn, href: document.getElementById('fnd') ? '#fnd' : 'ai-sql-dba.html',
          sub: r.label + ' · ' + (r.error ? (r.error_class === 'auth' ? 'login refused' : 'not read') : (r.totals ? r.totals.databases + ' DB' + (r.totals.databases === 1 ? '' : 's') + ' · ' + mb(r.totals.size_mb) : 'read')),
          title: (r.asset_name || r.host) + ' · ' + r.ip + ':' + r.port + ' - ' + r.label + (sv.version ? ' ' + sv.version : '') + (sv.edition ? ' ' + sv.edition : '') + (r.error ? ' - ' + r.error : nn ? ' - ' + r.notes[0].text : '') });
      });
      (v.found || []).filter(function (f) { return eng[f.engine]; }).forEach(function (f) {
        nodes.push({ id: 'f:' + f.engine + '@' + f.ip, name: f.asset_name || f.host, icon: ENG_ICON[f.engine], state: 'off', issues: 0, href: 'databases.html#inv', sub: f.label + ' · no login yet', title: f.label + ' found on ' + f.ip + ' - ' + f.next });
      });
      var read = (v.servers || []).filter(function (r) { return eng[r.engine] && !r.error; }).length;
      estate(el, { name: me ? 'AI Database Administrator' : 'Database inventory', icon: me ? 'robot' : 'database-search', badLabel: 'problems the AI DBA is working',
        sub: (me ? (me.on_duty ? 'on duty' : 'off duty') + ' · ' + (me.open || 0) + ' open · ' : '') + read + ' read · every ' + ((v.settings || {}).interval_h || 6) + ' h',
        note: me ? 'Recommends only: every fix is a statement for a DBA to review and run.' : 'The AI Database Administrator is not installed yet - run the platform update; findings are on the Databases page.',
        empty: 'No SQL Server, PostgreSQL or MySQL server found yet: add a read-only login on the Databases page or in Asset Discovery.' }, nodes);
      if (countEl) countEl.textContent = nodes.length + ' server' + (nodes.length === 1 ? '' : 's');
    });
  }
  /* Asset Discovery through Scope Studio (ITAM engine/discovery-advisor.js): every scope around the centre, coloured by its learned
   * health (good = radar, fair = amber, poor or an anomaly in the devices seen = red with dots), and every subnet with assets but no
   * scope as a grey "gap" node. The centre counts coverage and the proposals waiting for a System Admin. */
  function scopeEstate(el, countEl) {
    return get('/api/itam/discovery/advisor').then(function (v) {
      if (!v || v.__status) {
        el.innerHTML = '<div class="text-secondary p-3">' + esc(v && v.__status === 403 ? 'Scope Studio is for operators and System Admins (it shows the network layout).' : v && v.__status === 404 ? 'Scope Studio is not installed yet - run the platform update.' : 'Scope Studio is not reachable.') + '</div>';
        if (countEl) countEl.textContent = ''; return;
      }
      var nodes = [];
      (v.scopes || []).forEach(function (x) {
        var st = x.anomaly && x.anomaly.z < 0 ? 'bad' : x.grade === 'good' ? 'ok' : x.grade === 'fair' ? 'warn' : 'bad';
        nodes.push({ id: 's:' + x.id, name: x.name, icon: 'radar', state: st, issues: (x.recommendations || []).length, href: 'scope-studio.html',
          sub: 'health ' + x.health + (x.anomaly ? ' · anomaly' : '') + ' · ' + x.found + ' found',
          title: x.name + ' - health ' + x.health + '/100' + (x.anomaly ? ' - ' + x.anomaly.text : '') + ((x.recommendations || [])[0] ? ' - ' + x.recommendations[0].text : '') });
      });
      (v.coverage || []).filter(function (c) { return !c.covered && c.assets; }).slice(0, 12).forEach(function (c) {
        nodes.push({ id: 'g:' + c.subnet, name: c.subnet, icon: 'route-off', state: 'off', issues: 0, href: 'scope-studio.html', sub: c.assets + ' asset' + (c.assets === 1 ? '' : 's') + ' · no scope', title: c.subnet + ' - ' + c.assets + ' asset(s) in the register, no scope covers it: a proposal is waiting in Scope Studio' });
      });
      var sm = v.summary || {}, pr = (v.proposals || []).length;
      estate(el, { name: 'Asset Discovery', icon: 'radar-2', badLabel: 'scopes that need attention',
        sub: (sm.coverage_pct == null ? 'coverage not known yet' : sm.coverage_pct + '% of assets covered') + ' · ' + (sm.scopes || 0) + ' scope(s)',
        waiting: pr ? pr + ' scope proposal' + (pr === 1 ? '' : 's') + ' waiting for a System Admin' : '',
        note: 'Grey = a subnet with assets and no scope. Health and anomalies are learned from your own scans; the AI advisor only drafts proposals.',
        empty: 'No scope and no known address yet: add assets with a management IP, or run a passive method (AD, vCenter) first.' }, nodes);
      if (countEl) countEl.textContent = (sm.scopes || 0) + ' scope(s) · ' + (sm.uncovered || 0) + ' subnet(s) not covered';
    });
  }
  /* the Compliance Assistant (ITAM engine/compliance-assist.js) and the five registers it explains: each framework coloured by the
   * share of applicable requirements done (>= 80 % radar, >= 40 % amber, below red with one dot per open gap, max 6; grey = not
   * installed), the ranked "do these first" count in the pill. Local machine learning only - no external AI. */
  var FW_ICON = { sama: 'building-bank', ecc: 'shield-check', iso: 'certificate', ndmo: 'database', pdpl: 'lock' };
  function compEstate(el, countEl) {
    return get('/api/itam/assist/overview').then(function (v) {
      if (!v || v.__status) {
        el.innerHTML = '<div class="text-secondary p-3">' + esc(v && v.__status === 404 ? 'The Compliance Assistant is not installed yet - run the platform update.' : v && v.__status === 409 ? 'The Compliance Assistant runs in Python and Python did not answer - run the update.' : 'The Compliance Assistant is not reachable.') + '</div>';
        if (countEl) countEl.textContent = ''; return;
      }
      var nodes = (v.frameworks || []).map(function (f) {
        var c = f.counts || {}, pct = c.pct_met || 0, st = !f.installed ? 'off' : pct >= 80 ? 'ok' : pct >= 40 ? 'warn' : 'bad';
        return { id: 'f:' + f.fw, name: f.framework, icon: FW_ICON[f.fw] || 'checklist', state: st, issues: f.installed ? (c.gap || 0) + (c.partial || 0) : 0,
          href: 'compliance-assistant.html?q=' + encodeURIComponent('Are we compliant with ' + f.framework + '?'),
          sub: f.installed ? pct + '% done · ' + (c.gap || 0) + ' not done' + (c.unknown ? ' · ' + c.unknown + ' not checked' : '') : 'not installed', title: f.sentence };
      });
      var first = (v.first || []).length, done = (v.frameworks || []).filter(function (f) { return f.installed; }).length;
      estate(el, { name: 'Compliance Assistant', icon: 'message-chatbot', badLabel: 'frameworks with most to do',
        sub: done + ' of ' + (v.frameworks || []).length + ' registers · local ML, no external AI',
        waiting: first ? first + ' fix' + (first === 1 ? '' : 'es') + ' ranked to do first' : '',
        note: 'Colour = share of applicable requirements done; dots = open gaps. Click a framework to ask the assistant about it in plain words.',
        empty: 'No compliance register answered yet - run the update so the registers are installed.' }, nodes);
      if (countEl) countEl.textContent = (v.frameworks || []).filter(function (f) { return f.installed && (f.counts || {}).pct_met >= 80; }).length + ' of ' + done + ' frameworks at 80 %+';
    });
  }
  /* CMDB Studio (ITAM engine/cmdb-studio.js; ML in pyengine/cmdb_rules.py): every CI type around the centre, coloured by its data
   * quality (>= 80 % radar, >= 55 % amber, below red), the dots = CIs of that type that 3+ others fail with plus CIs with no
   * relationship at all. The centre counts the links and the proposals waiting for a person (the ML and the AI only propose). */
  var CI_ICON = { server: 'server', vm: 'box', network: 'router', storage: 'database', workstation: 'device-desktop', laptop: 'device-laptop', printer: 'printer', ups: 'battery-charging', phone: 'phone', mobile: 'device-mobile', software: 'apps', licence: 'license' };
  function cmdbEstate(el, countEl) {
    return get('/api/itam/cmdb/studio').then(function (v) {
      if (!v || v.__status) {
        el.innerHTML = '<div class="text-secondary p-3">' + esc(v && v.__status === 404 ? 'CMDB Studio is not installed yet - run the platform update.' : v && v.__status === 409 ? 'CMDB Studio runs in Python and Python did not answer - run the update.' : v && v.__status === 403 ? 'You are not allowed to view the CMDB.' : 'CMDB Studio is not reachable.') + '</div>';
        if (countEl) countEl.textContent = ''; return;
      }
      var sm = v.summary || {};
      var nodes = (sm.types || []).map(function (t) {
        var q = t.quality_pct, st = q == null ? 'off' : q >= 80 ? 'ok' : q >= 55 ? 'warn' : 'bad', n = (t.spof || 0) + (t.orphans || 0);
        return { id: 't:' + t.type, name: t.type, icon: CI_ICON[t.type] || 'tag', state: st, issues: n, href: 'cmdb-studio.html',
          sub: t.cis + ' CI' + (t.cis === 1 ? '' : 's') + ' · ' + (q == null ? 'quality not known' : q + '% complete'),
          title: t.cis + ' ' + t.type + ' CI(s) - data ' + (q == null ? 'not scored' : q + '% complete') + (t.spof ? ' - ' + t.spof + ' that 3 or more others fail with' : '') + (t.orphans ? ' - ' + t.orphans + ' with no relationship' : '') };
      });
      var wait = (sm.proposals || 0) + ((v.pending || []).length);
      estate(el, { name: 'CMDB Studio', icon: 'affiliate', badLabel: 'CI types with weak data',
        sub: (sm.cis || 0) + ' CIs · ' + (sm.confirmed || 0) + ' confirmed links' + (sm.quality_pct == null ? '' : ' · ' + sm.quality_pct + '% quality'),
        waiting: wait ? wait + ' relationship proposal' + (wait === 1 ? '' : 's') + ' waiting for a person' : '',
        note: 'Colour = data quality of that CI type; dots = single points of failure and CIs with no relationship. The ML and the AI analyst only propose links - a person confirms.',
        empty: 'No configuration item in the register yet: add assets or run Asset Discovery.' }, nodes);
      if (countEl) countEl.textContent = (sm.cis || 0) + ' CI(s) · ' + (sm.spof || 0) + ' single point(s) of failure · ' + (sm.duplicates || 0) + ' possible duplicate(s)';
    });
  }
  window.zybTeamViz = { floor: floor, loop: loop, stages: stages, stateOf: stateOf, estate: estate, oracleEstate: oracleEstate, dbEstate: dbEstate, scopeEstate: scopeEstate, compEstate: compEstate, cmdbEstate: cmdbEstate };
})();
