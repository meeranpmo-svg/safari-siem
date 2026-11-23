// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
// The auditor's dashboard (audit-dashboard.html): every framework, the attention list, the AI audit programmes and the audit
// teams, read from GET /api/itam/audit-dashboard (engine/audit-dashboard.js). Every value is escaped; links are our own pages.
(function(){
  'use strict';
  var P=window.zybPdpl, Z=window.zybDetail, esc=P.esc, $=P.$, V=null;
  var ST={compliant:['compliant','green'],partial:['partial','yellow'],gaps:['gaps','red'],not_assessed:['not assessed','secondary'],not_available:['not available','secondary']};
  var RES={non_compliant:['non-compliant','red'],gap:['gap','red'],partial:['partial','yellow']};
  var LBL={requirements:'requirements',controls:'controls',checks:'checks',compliant:'compliant',verified:'verified',met:'met',partial:'partial',gaps:'gaps',not_assessed:'not assessed',not_measured:'not measured',no_evidence:'no evidence',auto_pass:'automated pass, to confirm'};
  // our own pages only: a link from the data is never followed
  var PAGES={'pdpl-dashboard.html':1,'nca-ecc.html':1,'ndmo.html':1,'ai-auditors.html':1,'internal-audit-team.html':1,'audit-team.html':1,'cyber-audit-team.html':1,'dept-checklist.html':1,'iso27001.html':1,'audit-ccm.html':1,'pdpl-intel.html':1,'audit-analytics.html':1};
  var C=window.zybCharts, COL={ok:'#0ca30c',partial:'#fab219',gap:'#d03b3b',open:'#6b7280'};
  function gauge(v){var r=78,c=2*Math.PI*r,arc=c*0.75,val=v==null?0:Math.max(0,Math.min(100,v)),col=v==null?'#6b7280':colour(v);
    return '<svg viewBox="0 0 190 190" role="img" aria-label="Assurance index '+(v==null?'withheld':v)+'"><defs><linearGradient id="gg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3987e5"/><stop offset="1" stop-color="'+col+'"/></linearGradient></defs>'
      +'<circle cx="95" cy="95" r="'+r+'" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="14" stroke-dasharray="'+arc+' '+c+'" transform="rotate(135 95 95)" stroke-linecap="round"/>'
      +'<circle cx="95" cy="95" r="'+r+'" fill="none" stroke="url(#gg)" stroke-width="14" stroke-dasharray="'+(arc*val/100)+' '+c+'" transform="rotate(135 95 95)" stroke-linecap="round"/></svg>'
      +'<div class="gv"><b>'+(v==null?'—':esc(v))+'</b><span class="au-lbl">assurance index</span></div>';}
  function spark(series){var pts=(series||[]).filter(function(p){return p.value!=null;});if(pts.length<2)return '<div class="mut" style="height:36px;line-height:36px">trend after the second daily snapshot</div>';
    var w=220,h=36,mn=Math.min.apply(null,pts.map(function(p){return p.value;})),mx=Math.max.apply(null,pts.map(function(p){return p.value;})),rg=(mx-mn)||1;
    var d=pts.map(function(p,i){return (i?'L':'M')+(i*(w-4)/(pts.length-1)+2).toFixed(1)+' '+(h-3-(p.value-mn)/rg*(h-6)).toFixed(1);}).join(' ');
    return '<svg class="spark" viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none" aria-hidden="true"><path d="'+d+'" fill="none" stroke="#3987e5" stroke-width="2"/></svg>';}
  function stack(dd){var t=dd.ok+dd.partial+dd.gap+dd.open;if(!t)return '<div class="stack"></div>';return '<div class="stack" title="'+esc('compliant '+dd.ok+' · partial '+dd.partial+' · gap '+dd.gap+' · not assessed / to confirm '+dd.open)+'">'+['ok','partial','gap','open'].map(function(k){return dd[k]?'<span style="width:'+(dd[k]/t*100)+'%;background:'+COL[k]+'"></span>':'';}).join('')+'</div>';}
  function hero(v){var I=v.insight;if(!I){$('hero').hidden=true;return;}var ix=I.index;
    $('gauge').innerHTML=gauge(ix.value);$('gwhy').textContent=ix.value==null?ix.why:(I.index_move_30d==null?'no snapshot from 30 days ago yet':(I.index_move_30d>=0?'+':'')+I.index_move_30d+' points against 30 days ago');
    var mx=Math.max.apply(null,[1].concat(ix.items.map(function(x){return Math.abs(x.points);})));
    $('ix').innerHTML=ix.items.length?ix.items.map(function(x){return '<div>'+esc(x.label)+'<div class="bx"><span style="width:'+(Math.abs(x.points)/mx*100)+'%;background:'+(x.side==='base'?'#3987e5':'#d03b3b')+'"></span></div></div><b class="text-end '+(x.points<0?'text-red':'')+'">'+(x.points>0?'':'')+esc(x.points)+'</b>';}).join(''):'<div class="mut" style="grid-column:1/-1">'+esc(ix.why)+'</div>';
    $('proj').textContent=(ix.value!=null?ix.why+'. ':'')+'Target '+I.target+': '+(I.projection.reached?'reached':I.projection.why)+'. '+I.snapshots+' daily snapshot(s) held.';
    var S=I.series.filter(function(p){return p.value!=null;});
    if(C&&S.length>1)C.area($('c-ix'),S.map(function(p){return p.date.slice(5);}),[{label:'Assurance index',data:S.map(function(p){return p.value;}),color:'acc'}],{title:'Assurance index per day'});
    else if(C)C.empty($('c-ix'),'The trend appears after the second daily snapshot.');}
  function matrix(v){var rows=v.insight?v.insight.frameworks:[];
    $('mx').innerHTML='<table class="table table-sm card-table mx mb-0"><thead><tr><th>Framework</th><th>Compliant</th><th>Partial</th><th>Gap</th><th>Open</th></tr></thead><tbody>'+rows.map(function(f){var d=f.dist,t=(d.ok+d.partial+d.gap+d.open)||1;
      return '<tr><td>'+esc(f.name)+'</td>'+['ok','partial','gap','open'].map(function(k){var a=d[k]/t;return '<td><div class="c" style="background:'+COL[k]+(d[k]?Math.round(25+a*60).toString(16).padStart(2,'0'):'10')+'">'+esc(d[k])+'</div></td>';}).join('')+'</tr>';}).join('')+'</tbody></table>';}
  function delivery(v){var D=v.insight?v.insight.delivery:[];$('dlv').innerHTML=D.length?'<div class="dl">'+D.map(function(d){return '<div><b>'+esc(d.name)+'</b><div class="mut">'+esc(d.why)+'</div></div><div class="bx"><span style="width:'+esc(d.on_track)+'%;background:'+colour(d.on_track)+'"></span></div><b>'+esc(d.on_track)+'%</b>';}).join('')+'</div>'
      :'<span class="text-secondary">The audit teams are not installed - run the update.</span>';}
  function analytics(v){var a=v.analytics||{available:false,reason:'not installed'};if(!a.available){$('an').innerHTML='<span class="text-secondary">'+esc(a.reason||'not installed')+'</span>';return;}var k=a.kpis;
    $('an').innerHTML='<div class="row g-2 mb-2"><div class="col-4"><div class="au-num">'+esc(k.runs)+'</div><div class="au-lbl">runs</div></div><div class="col-4"><div class="au-num '+(k.exceptions_open?'text-orange':'')+'">'+esc(k.exceptions_open)+'</div><div class="au-lbl">exceptions open</div></div><div class="col-4"><div class="au-num '+(k.awaiting_review?'text-orange':'')+'">'+esc(k.awaiting_review)+'</div><div class="au-lbl">awaiting review</div></div></div>'
      +(a.recent.length?a.recent.map(function(r){return '<div class="small mb-1"><b>'+esc(r.id)+'</b> '+esc(r.test)+' · '+esc(r.dataset)+(r.reviewed?' '+P.badge('reviewed','green'):'')+'<div class="mut">'+esc(r.summary)+'</div></div>';}).join(''):'<span class="mut">No analytic run yet - duplicates, Benford, gaps and samples run in the workbench.</span>');}
  function href(p){return PAGES[p]?p:'#';}
  function why(e){if(e&&e.status===403)return 'The audit dashboard needs the operator role (a named person): it names people and weaknesses.';if(e&&e.status===404)return 'The audit dashboard service is not installed yet: run the update (git pull origin main, then scripts\\update-platform.ps1).';return (e&&e.message)||'request failed';}
  function sb(s){var x=ST[s]||[s,'secondary'];return P.badge(x[0],x[1]);}
  function rb(r){var x=RES[r]||[r,'secondary'];return P.badge(x[0],x[1]);}
  function colour(n){return n>=80?'#0ca30c':n>=50?'#fab219':'#d03b3b';}

  function load(){return P.req('GET','/audit-dashboard').then(function(v){V=v;draw();}).catch(function(e){var m='<div class="alert alert-warning mb-0">'+esc(why(e))+'</div>';$('fws').innerHTML='<div class="col-12">'+m+'</div>';$('att').innerHTML='';$('prog').innerHTML='';$('teams').innerHTML='';$('kpis').innerHTML='';$('depts').innerHTML='';$('hero').hidden=true;});}
  function draw(){var v=V,s=v.summary;
    $('kpis').innerHTML=P.tile(s.assessed+' / '+s.of,'Frameworks assessed')+P.tile(s.gaps,'Verified gaps',s.gaps?'text-red':'')
      +P.tile(s.overdue_findings===null?'—':s.overdue_findings,'Overdue audit findings',s.overdue_findings?'text-red':'')+P.tile(s.overdue_requests,'Overdue evidence requests',s.overdue_requests?'text-orange':'')
      +P.tile(s.control_exceptions_open==null?'—':s.control_exceptions_open,'Open control-monitoring exceptions',s.control_exceptions_open?'text-red':'')+P.tile(s.pdpl_deadlines_at_risk==null?'—':s.pdpl_deadlines_at_risk,'PDPL deadlines at risk',s.pdpl_deadlines_at_risk?'text-red':'');
    $('fws').innerHTML=v.frameworks.map(function(f){
      if(!f.available)return '<div class="col-md-6 col-xl-4"><div class="card fw s-not_available"><div class="card-body"><div class="d-flex justify-content-between"><b>'+esc(f.name)+'</b>'+sb('not_available')+'</div><p class="mut mt-2 mb-0">'+esc(f.reason)+'</p></div></div></div>';
      var sc=f.score===null||f.score===undefined?'<div class="score text-secondary">—</div><div class="mut">not assessed yet</div>':'<div class="score">'+esc(f.score)+'%</div><div class="bar"><span style="width:'+Math.max(0,Math.min(100,Number(f.score)))+'%;background:'+colour(f.score)+'"></span></div>';
      var cn=Object.keys(f.counts||{}).map(function(k){return '<span class="me-2">'+esc(LBL[k]||k)+' <b>'+esc(f.counts[k])+'</b></span>';}).join('');
      var I=(v.insight?v.insight.frameworks:[]).filter(function(x){return x.id===f.id;})[0]||{dist:{ok:0,partial:0,gap:0,open:0},series:[],projection:{}};
      var mv=I.move_30d==null?'':' '+P.badge((I.move_30d>=0?'+':'')+I.move_30d+' pts · 30 d',I.regressed?'red':I.move_30d>0?'green':'secondary');
      return '<div class="col-md-6 col-xl-4"><div class="card fw s-'+esc(f.status)+'"><div class="card-body"><div class="d-flex justify-content-between align-items-start mb-1"><b>'+esc(f.name)+'</b><span>'+sb(f.status)+mv+'</span></div>'+sc
        +stack(I.dist)+spark(I.series)+(f.score!=null&&I.projection&&I.projection.why?'<div class="mut">'+esc(I.projection.reached?'at the 80 % target':'80 %: '+I.projection.why)+'</div>':'')
        +'<div class="small mt-1">'+cn+'</div><div class="mut mt-1">'+esc(f.owner||'')+(f.extra?' · '+esc(f.extra):'')+'</div>'
        +'<div class="d-flex gap-2 mt-2"><button type="button" class="btn btn-sm" data-fw="'+esc(f.id)+'"'+(f.top&&f.top.length?'':' disabled')+'>Gaps ('+esc((f.top||[]).length)+')</button><a class="btn btn-sm btn-ghost-secondary" href="'+esc(href(f.page))+'">Open the evidence</a></div></div></div></div>';}).join('');
    $('att').innerHTML=v.attention.length?v.attention.map(function(a){return '<div class="bi s-'+esc(a.severity)+'"><div class="d-flex justify-content-between gap-2"><span class="small"><b>'+esc(a.ref)+'</b> '+esc(a.text)+'<div class="mut">'+esc(a.source)+'</div>'+(a.priority!=null?'<span class="pr" title="'+esc((a.priority_why||[]).join(', '))+'">priority '+esc(a.priority)+'<i><b style="width:'+esc(a.priority)+'%"></b></i><span class="mut">'+esc((a.priority_why||[]).join(' · '))+'</span></span>':'')+'</span><a class="btn btn-sm btn-ghost-secondary" href="'+esc(href(a.page))+'">Open</a></div></div>';}).join('')
      :'<p class="text-secondary mb-0">Nothing overdue and no verified gap. As registers are assessed and audits run, what needs an auditor first appears here.</p>';
    var pg=v.programmes;
    $('prog').innerHTML=!pg.available?'<div class="card-body text-secondary">'+esc(pg.reason)+'</div>':P.table([['Programme',function(p){return '<b>'+esc(p.name)+'</b><div class="mut">'+(p.last_run?'last run '+esc(P.dt(p.last_run)):'not run yet')+'</div>';}],
      ['Tests',function(p){var c=p.counts||{};return '<span class="small">pass '+esc(c.pass||0)+' · fail '+esc(c.fail||0)+' · not tested '+esc((c.not_tested||0)+(c.not_run||0))+'</span>';}],['Pass %',function(p){return p.pass_pct===null||p.pass_pct===undefined?'—':esc(p.pass_pct)+'%';}]],pg.list,function(p){return 'class="rowc" data-prog="'+esc(p.id)+'"';});
    var dp=v.departments||{available:false,reason:'not installed - run the update'},L=window.zybLevels;
    $('depts').innerHTML=!dp.available?'<span class="text-secondary">'+esc(dp.reason)+'</span>':(L?L.groups(dp.list.map(function(d){return {name:d.name+(d.overdue?' · '+d.overdue+' overdue':''),status:d.status,pct:d.pct,counts:d.counts||{},applicable:d.applicable};}))+L.legend('Fully compliant = done and verified by an auditor. A department with no head named reads not assessed.'):'');
    var tm=v.teams;
    $('teams').innerHTML=!tm.available?'<div class="card-body text-secondary">'+esc(tm.reason)+'</div>':P.table([['Team',function(t){return '<a href="'+esc(href(t.page))+'"><b>'+esc(t.name)+'</b></a><div class="mut">Head of Audit: '+esc(t.head_of_audit||'not named')+'</div>';}],
      ['Plan this year',function(t){return t.plan?esc(t.plan.id)+' '+P.badge(t.plan.state,t.plan.state==='approved'?'green':'orange')+'<div class="mut">'+esc(t.plan.engagements)+' engagement(s)</div>':'<span class="mut">no plan</span>';}],
      ['Engagements',function(t){var e=t.engagements;return '<span class="small">planning '+esc(e.planning)+' · fieldwork '+esc(e.fieldwork)+' · draft report '+esc(e.draft_report)+' · final '+esc(e.final)+'</span>';}],
      ['Findings',function(t){var f=t.findings;return '<span class="small">open '+esc(f.open)+' (high '+esc(f.high)+')'+(f.overdue?' '+P.badge(f.overdue+' overdue','red'):'')+' · risk accepted '+esc(f.risk_accepted)+' · closed '+esc(f.closed)+'</span>';}]],tm.list);
    $('note').textContent=v.note+' Generated '+P.dt(v.generated_at)+' UTC.';
    $('up').textContent='as of '+P.dt(v.generated_at)+' UTC';hero(v);matrix(v);delivery(v);analytics(v);
    var ai=v.insight&&v.insight.ai;$('ais').textContent=ai?(ai.enabled?'available ('+ai.model+')':'Not available: '+ai.reason):'';
  }
  function gaps(id){var f=(V.frameworks||[]).filter(function(x){return x.id===id;})[0];if(!f)return;
    var h=P.table([['Item',function(g){return '<b>'+esc(g.id)+'</b> '+esc(g.title)+'<div class="mut">'+esc(g.ref||'')+'</div>';}],['Result',function(g){return rb(g.result)+(g.severity?' <span class="mut">'+esc(g.severity)+'</span>':'');}],['Why',function(g){return '<span class="small">'+esc(g.why||'')+'</span>';}]],f.top,null,'No gap.');
    if(f.pbc&&f.pbc.overdue.length)h+=Z.sec('Overdue evidence requests',P.table([['Request',function(r){return '<b>'+esc(r.ref)+'</b> '+esc(r.title);}],['Owner',function(r){return esc(r.owner);}],['Overdue',function(r){return esc(r.days_overdue)+' day(s)';}]],f.pbc.overdue));
    Z.open('Audit Dashboard',f.name+' - gaps',h+'<div class="mt-2"><a class="btn btn-sm" href="'+esc(href(f.page))+'">Open the evidence</a></div>');}
  function prog(id){var p=(V.programmes.list||[]).filter(function(x){return x.id===id;})[0];if(!p)return;
    Z.open('Audit Dashboard',p.name+' - failing tests',P.table([['Test',function(t){return '<b>'+esc(t.id)+'</b> '+esc(t.title);}],['Owner',function(t){return esc(t.owner);}],['Detail',function(t){return '<span class="small">'+esc(t.detail)+'</span>';}]],p.failing,null,'No failing test.')+'<div class="mt-2"><a class="btn btn-sm" href="ai-auditors.html">Open the programmes</a></div>');}
  document.addEventListener('click',function(ev){var b=ev.target.closest('[data-fw]');if(b){gaps(b.getAttribute('data-fw'));return;}b=ev.target.closest('[data-prog]');if(b){prog(b.getAttribute('data-prog'));}});
  $('refresh').addEventListener('click',load);
  $('af').addEventListener('submit',function(ev){ev.preventDefault();$('aa').innerHTML='<span class="mut">Thinking…</span>';P.req('POST','/audit-dashboard/ask',{question:$('af-q').value}).then(function(r){$('aa').innerHTML='<div style="white-space:pre-wrap">'+esc(r.answer)+'</div><div class="mut mt-1">'+esc((r.steps||[]).length)+' read(s) · '+esc(r.model||'')+'</div>';}).catch(function(e){$('aa').innerHTML='<div class="alert alert-warning mb-0">'+esc(why(e))+'</div>';});});
  $('csv').addEventListener('click',function(){P.req('GET','/audit-dashboard/export').then(function(r){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['﻿'+r.csv],{type:'text/csv'}));a.download=r.filename;document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove();},1000);P.toast('Exported - recorded in the audit trail');}).catch(function(e){P.toast(why(e));});});
  load();
})();
