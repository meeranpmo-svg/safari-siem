// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
// Vulnerability Scans (vuln-scans.html): Greenbone connection and internal scan scope (admin), scan requests with four-eyes
// approval, findings with their lifecycle, from /api/itam/vulnscan (engine/vulnscan.js). Every value is escaped - host names,
// banners and NVT text are attacker-influenced; CVE ids are shown as text, never as links.
(function(){
  'use strict';
  var P=window.zybPdpl, Z=window.zybDetail, esc=P.esc, $=P.$, V=null, F={status:'open',sev:'',q:''}, qt=null;
  var SEV={critical:['critical','red'],high:['high','orange'],medium:['medium','yellow'],low:['low','azure']};
  var STATE={requested:['waiting for approval','orange'],approved:['approved - waits for its window','blue'],running:['running','blue'],stopping:['stopping','orange'],done:['done','green'],stopped:['stopped (partial)','yellow'],
    rejected:['rejected','secondary'],cancelled:['cancelled','secondary'],expired:['expired','secondary'],failed:['could not start','red']};
  var FST={open:['open','red'],fixed:['fixed','green'],risk_accepted:['risk accepted','secondary']};
  var ICON={ok:'✓',fail:'✗',warn:'!',info:'i'};
  function why(e){if(e&&e.status===403&&(!e.message||/requires|HTTP 403/i.test(e.message)))return 'This needs the operator role (a named person); the connection and the scope need an administrator.';if(e&&e.status===404&&/HTTP 404/.test(e.message||''))return 'The vulnerability scan service is not installed yet: run the update (git pull origin main, then scripts\\update-platform.ps1).';return (e&&e.message)||'request failed';}
  var bd=function(m,t){var x=m[t]||[t,'secondary'];return P.badge(x[0],x[1]);};
  function dt(v){return v?esc(P.dt(v)):'—';}

  function load(){return P.req('GET','/vulnscan').then(function(v){V=v;draw();return list();}).catch(function(e){var m='<div class="alert alert-warning mb-0">'+esc(why(e))+'</div>';$('kpis').innerHTML='<div class="col-12">'+m+'</div>';['setup','hosts','scans','finds'].forEach(function(k){$(k).innerHTML='';});});}
  function draw(){var v=V,o=v.open,c=v.connection;
    $('kpis').innerHTML=P.tile(o.critical,'Critical open',o.critical?'text-red':'')+P.tile(o.high,'High open',o.high?'text-orange':'')+P.tile(o.medium,'Medium open')+P.tile(o.low,'Low open')
      +P.tile(v.hosts_affected,'Hosts with open findings')+P.tile(v.fixed_30d,'Fixed in 30 days (verified by a scan)',v.fixed_30d?'text-green':'')+P.tile(v.waiting_approval,'Scans waiting for approval',v.waiting_approval?'text-orange':'')+P.tile(v.pending_risk,'Risk acceptances to decide',v.pending_risk?'text-orange':'');
    var lt=c.last_test;
    $('setup').innerHTML=Z.kv([['Greenbone',c.configured?esc(c.via)+'<div class="mut">user '+esc(c.username)+' · password '+esc(c.password)+'</div>':'<span class="text-orange">not connected - an admin sets the Greenbone connection</span>'],
      ['Last test',lt?(lt.ok?P.badge('passed','green'):P.badge('stopped at '+(lt.failed||'?'),'red'))+' <span class="mut">'+dt(lt.at)+'</span>':'<span class="mut">not tested</span>'],
      ['Internal scan scope',v.scope.allowed.length?esc(v.scope.allowed.join(', ')):'<span class="text-orange">no range may be scanned yet</span>'],['Never scanned',v.scope.exclude.length?esc(v.scope.exclude.join(', ')):'—'],
      ['Limits','at most '+esc(v.limits.max_hosts)+' addresses and '+esc(v.limits.max_window_hours)+' hours per scan'],['Minimum quality of detection',esc(c.min_qod)+'%']])
      +(c.configured?'<button type="button" class="btn btn-sm mt-2" id="testb"><i class="ti ti-stethoscope me-1"></i>Test the connection</button>':'');
    $('hosts').innerHTML=P.table([['Host',function(h){return '<b>'+esc(h.host)+'</b><div class="mut">'+esc(h.hostname||'')+'</div>';}],['Critical',function(h){return h.critical?P.badge(h.critical,'red'):'0';}],['High',function(h){return h.high?P.badge(h.high,'orange'):'0';}],['Medium',function(h){return esc(h.medium);}],['Low',function(h){return esc(h.low);}],['Top CVSS',function(h){return esc(h.top);}]],
      v.hosts,function(h){return 'class="rowc" data-host="'+esc(h.host)+'"';},v.last_scan?'No open finding.':'No scan has finished yet: request one, a second person approves it, and it runs in its window.');
    $('scans').innerHTML=P.table([['Scan',function(x){return '<b>'+esc(x.id)+'</b> '+esc(x.name)+'<div class="mut">'+esc(x.targets.join(', '))+' · '+esc(x.hosts)+' address(es)'+(x.exclude.length?' · not '+esc(x.exclude.join(', ')):'')+'</div>';}],
      ['Window (UTC)',function(x){return esc(String(x.window_start).slice(0,16).replace('T',' '))+'<div class="mut">to '+esc(String(x.window_end).slice(0,16).replace('T',' '))+'</div>';}],
      ['State',function(x){return bd(STATE,x.state)+(x.state==='running'||x.state==='stopping'?'<div class="prog"><span style="width:'+Math.max(0,Math.min(100,Number(x.progress)||0))+'%"></span></div>':'')+(x.counts?'<div class="mut">'+['critical','high','medium','low'].map(function(k){return esc(x.counts[k])+' '+k;}).join(' · ')+'</div>':'')+(x.error||x.last_error?'<div class="small text-red">'+esc(x.error||x.last_error)+'</div>':'');}],
      ['People',function(x){return '<span class="small">requested by '+esc(x.requested_by)+(x.approved_by?'<br>approved by '+esc(x.approved_by):'')+'</span><div class="mut">'+esc(x.reason)+'</div>';}],
      ['',function(x){var b='';if(x.state==='requested')b+='<button type="button" class="btn btn-sm btn-success me-1" data-sact="approve" data-sid="'+esc(x.id)+'">Approve</button><button type="button" class="btn btn-sm me-1" data-sact="reject" data-sid="'+esc(x.id)+'">Reject</button>';
        if(['requested','approved','running'].indexOf(x.state)>=0)b+='<button type="button" class="btn btn-sm btn-ghost-danger" data-sact="cancel" data-sid="'+esc(x.id)+'">'+(x.state==='running'?'Stop':'Cancel')+'</button>';
        if(['done','stopped'].indexOf(x.state)>=0)b+='<button type="button" class="btn btn-sm" data-sact="open" data-sid="'+esc(x.id)+'">Results</button>';return b;}]],v.scans,null,'No scan requested yet.');
    $('note').textContent=v.note;
  }
  function list(){var q='?status='+encodeURIComponent(F.status)+(F.sev?'&sev='+F.sev:'')+(F.q?'&q='+encodeURIComponent(F.q):'');
    return P.req('GET','/vulnscan/findings'+q).then(function(r){
      $('finds').innerHTML=P.table([['Finding',function(f){return '<b>'+esc(f.name)+'</b><div class="mut">'+esc(f.cves.join(' '))+'</div>';}],['Host',function(f){return esc(f.host)+' <span class="mut">'+esc(f.port)+'</span><div class="mut">'+esc(f.hostname||'')+'</div>';}],
        ['Severity',function(f){return bd(SEV,f.severity)+' <span class="mut">'+esc(f.score)+'</span>';}],['Status',function(f){return bd(FST,f.status)+(f.risk&&f.risk.state==='pending'?' '+P.badge('risk acceptance pending','orange'):'')+(f.owner?'<div class="mut">owner '+esc(f.owner)+'</div>':'');}],
        ['Seen',function(f){return '<span class="small">'+dt(f.first_seen)+'</span><div class="mut">last '+dt(f.last_seen)+'</div>';}]],r.items,function(f){return 'class="rowc" data-fid="'+esc(f.id)+'"';},'No finding matches.')
        +(r.total>r.shown?'<div class="card-body mut">Showing '+esc(r.shown)+' of '+esc(r.total)+' - narrow the filter or export the CSV.</div>':'');
    }).catch(function(e){$('finds').innerHTML='<div class="card-body text-warning">'+esc(why(e))+'</div>';});}

  function openFinding(id){P.req('GET','/vulnscan/findings/'+encodeURIComponent(id)).then(function(f){
    var h=Z.kv([['Host',esc(f.host)+' '+esc(f.port)+(f.hostname?' · '+esc(f.hostname):'')],['Severity',bd(SEV,f.severity)+' CVSS '+esc(f.score)+' · quality of detection '+esc(f.qod)+'%'],['Status',bd(FST,f.status)+(f.fixed_by_scan?' <span class="mut">by '+esc(f.fixed_by_scan)+'</span>':'')],
      ['CVEs',esc(f.cves.join(', ')||'—')],['Owner',esc(f.owner||'not assigned')],['First / last seen',dt(f.first_seen)+' / '+dt(f.last_seen)]]);
    h+=Z.sec('Fix',(f.solution_type?P.badge(f.solution_type,'blue')+' ':'')+'<div class="pre">'+esc(f.solution||'No solution given by the scanner.')+'</div>');
    if(f.summary||f.insight||f.impact)h+=Z.sec('What it is','<div class="pre">'+esc([f.summary,f.insight&&'Insight: '+f.insight,f.impact&&'Impact: '+f.impact,f.affected&&'Affected: '+f.affected].filter(Boolean).join('\n\n'))+'</div>');
    if(f.evidence)h+=Z.sec('Evidence from the scan','<div class="pre">'+esc(f.evidence)+'</div>');
    h+=Z.sec('History','<ul class="small mb-0">'+(f.history||[]).map(function(x){return '<li>'+dt(x.at)+' - '+esc(x.what)+'</li>';}).join('')+'</ul>');
    h+=Z.sec('Owner',P.form('ownf',[['owner','text','Owner (user name)',1]],{owner:f.owner},'Assign','<input type="hidden" name="fid" value="'+esc(f.id)+'">'));
    if(f.risk&&f.risk.state==='pending')h+=Z.sec('Risk acceptance waiting for a decision','<p class="small">'+esc(f.risk.reason)+'<br><span class="mut">asked by '+esc(f.risk.by)+' until '+esc(String(f.risk.until).slice(0,10))+'</span></p><button type="button" class="btn btn-sm btn-success me-1" data-ract="approve" data-fid="'+esc(f.id)+'">Approve</button><button type="button" class="btn btn-sm" data-ract="reject" data-fid="'+esc(f.id)+'">Reject</button>');
    else if(f.status==='open')h+=Z.sec('Ask to accept the risk (a different person approves)',P.form('riskf',[['reason','area','Reason and compensating controls',1],['until','date','Accepted until (within 12 months)',1]],{},'Ask for approval','<input type="hidden" name="fid" value="'+esc(f.id)+'">'));
    if(f.risk&&f.risk.state!=='pending')h+='<div class="mut mt-2">Risk acceptance '+esc(f.risk.state)+(f.risk.decided_by?' by '+esc(f.risk.decided_by):'')+' until '+esc(String(f.risk.until).slice(0,10))+'</div>';
    Z.open('Vulnerability Scans',f.name,h);}).catch(function(e){P.toast(why(e));});}
  function openScan(id){P.req('GET','/vulnscan/scans/'+encodeURIComponent(id)).then(function(x){
    var h=Z.kv([['State',bd(STATE,x.state)],['Hosts scanned',esc(x.hosts_scanned)],['Left out',x.dropped?esc(x.dropped.log)+' log-level, '+esc(x.dropped.low_qod)+' below the quality threshold, '+esc(x.dropped.false_positive)+' overridden false positive(s)':'—'],['New / fixed',esc(x.new_findings||0)+' new · '+esc(x.fixed_findings||0)+' fixed'],['Approved by',esc(x.approved_by||'—')]]);
    h+=Z.sec('Highest findings',P.table([['Finding',function(f){return esc(f.name)+'<div class="mut">'+esc(f.cves.join(' '))+'</div>';}],['Host',function(f){return esc(f.host)+' '+esc(f.port);}],['Severity',function(f){return bd(SEV,f.severity)+' '+esc(f.score);}]],x.top,null,'Nothing found.'));
    h+=Z.sec('History','<ul class="small mb-0">'+(x.history||[]).map(function(y){return '<li>'+dt(y.at)+' - '+esc(y.by)+': '+esc(y.what)+'</li>';}).join('')+'</ul>');
    Z.open('Vulnerability Scans',x.id+' '+x.name,h);}).catch(function(e){P.toast(why(e));});}
  // The Network Assistant (GET /scan-targets, engine/scan-targets.js) builds the targets from IP Address Management: the live,
  // non-fragile addresses inside the scope, highest priority first. The best proposal fills the form; a person can pick another or edit.
  var STG=null;
  function stg(){return P.req('GET','/scan-targets').then(function(r){STG=r;return r;},function(e){STG={installed:false,note:why(e)};return STG; /* the planner is optional: the form still works by hand */});}
  function utc(t){return new Date(t).toISOString().slice(0,16);}
  function fillScan(i){var r=STG&&STG.recommendations&&STG.recommendations[i],fm=$('scanf');if(!r||!fm)return;var set=function(n,v){var el=fm.querySelector('[name='+n+']');if(el)el.value=v;};
    set('name',r.suggested_name);set('targets',r.targets.join(', '));set('exclude',r.exclude.join(', '));set('reason',r.suggested_reason);
    var st=Date.now()+15*60000;if(!fm.querySelector('[name=window_start]').value){set('window_start',utc(st));set('window_end',utc(st+4*3600000));}
    Array.prototype.forEach.call(document.querySelectorAll('[data-stg]'),function(b){b.classList.toggle('btn-primary',b.getAttribute('data-stg')===String(i));});}
  function assistantHtml(r){if(!r||!r.installed)return '<div class="alert alert-secondary small py-2">Network Assistant: '+esc((r&&r.note)||'not available')+'</div>';
    var L=r.recommendations||[];
    if(!L.length)return '<div class="alert alert-secondary small py-2"><b>Network Assistant</b> - nothing to propose: '+esc(!r.scope.set?'no internal scan scope yet. Open Scope - it is filled from IP Address Management.':(r.subnets.length?'every subnet with live devices is outside the scope, fragile or recently scanned.':'no subnet in IP Address Management yet - register the address plan there.'))+'</div>';
    return '<div class="card mb-2"><div class="card-body py-2"><div class="small mb-1"><b>Network Assistant</b> <span class="mut">- targets built from IP Address Management (live addresses only, fragile devices left out). Pick one; the form fills.</span></div>'
      +L.map(function(x,i){return '<button type="button" class="btn btn-sm w-100 text-start mb-1'+(i===0?' btn-primary':'')+'" data-stg="'+i+'"><b>'+esc(x.name)+'</b>'+(x.site?' · '+esc(x.site):'')+' · '+esc(x.hosts)+' address(es) · priority '+esc(x.priority)+'<div class="mut small">'+esc(x.why.join('; '))+(x.exclude.length?' · leaves out '+esc(x.exclude.length)+' fragile device(s)':'')+'</div></button>';}).join('')+'</div></div>';}
  function newScan(){var v=V||{profiles:[],scope:{allowed:[]}};
    var h='<p class="small">Inside the scope: <b>'+esc(v.scope.allowed.join(', ')||'none set yet')+'</b>. Times are UTC (Riyadh is UTC+3).</p><div id="stgbox"><div class="mut small mb-2">Network Assistant: reading IP Address Management...</div></div>'+P.form('scanf',[['name','text','Name',1],['targets','list','Targets (CIDR, ranges or addresses, comma-separated)',1],['exclude','list','Leave out (optional)'],['profile','sel','Profile',1,(v.profiles||[]).map(function(p){return [p.key,p.name];})],
      ['window_start','dtl','Window start (UTC)',1],['window_end','dtl','Window end (UTC, at most '+esc((v.limits||{}).max_window_hours||12)+' h later)',1],['reason','area','Reason',1]],{profile:'full'},'Request the scan');
    Z.open('Vulnerability Scans','Request a scan',h);
    stg().then(function(r){var bx=$('stgbox');if(!bx)return;bx.innerHTML=assistantHtml(r);if(r.recommendations&&r.recommendations.length)fillScan(0);});}
  function connForm(){var c=(V&&V.connection)||{};
    Z.open('Vulnerability Scans','Greenbone connection','<p class="small">Use a dedicated Greenbone user with the <b>User</b> role (not Admin). A gvmd on this server is reached through its socket; a remote gvmd needs its host, port and certificate fingerprint. The password is stored sealed and never shown again.</p>'
      +P.form('connf',[['socket','text','gvmd socket path (e.g. /run/zyb-gvmd/gvmd.sock)'],['host','text','or gvmd host'],['port','num','port (9390)'],['pin','text','certificate SHA-256 fingerprint (with host)'],['username','text','Greenbone user',1],['password','pass','Password (leave empty to keep the stored one)'],['min_qod','num','Minimum quality of detection % (70)']],{socket:c.via&&c.via.indexOf('socket ')===0?c.via.slice(7):'',username:c.username,min_qod:c.min_qod},'Save'));}
  // The scope is proposed by the Network Assistant from IP Address Management: private subnets with live devices the scope does not
  // cover, and the fragile devices to keep out. The form arrives filled; an administrator reviews it and saves (audited).
  function uniq(L){var o=[];L.forEach(function(x){if(x&&o.indexOf(x)<0)o.push(x);});return o;}
  function scopeForm(){var sc=(V&&V.scope)||{allowed:[],exclude:[]};
    Z.open('Vulnerability Scans','Internal scan scope','<p class="small">Only private (RFC 1918) ranges can be scanned. Put fragile devices, OT and third-party equipment under "never scanned".</p><div id="scpbox"><div class="mut small mb-2">Network Assistant: reading IP Address Management...</div></div>'+P.form('scopef',[['allowed','list','Ranges that may be scanned (comma-separated)',1],['exclude','list','Never scanned (comma-separated)']],sc,'Save the scope'));
    stg().then(function(r){var bx=$('scpbox'),fm=$('scopef');if(!bx||!fm)return;
      if(!r||!r.installed){bx.innerHTML='<div class="alert alert-secondary small py-2">Network Assistant: '+esc((r&&r.note)||'not available')+'</div>';return;}
      var sp=r.scope_proposal||{},al=fm.querySelector('[name=allowed]'),ex=fm.querySelector('[name=exclude]'),cur=function(el){return el.value.split(',').map(function(x){return x.trim();}).filter(Boolean);};
      al.value=uniq(cur(al).concat(sp.add_allowed||[])).join(', ');ex.value=uniq(cur(ex).concat(sp.add_exclude||[])).join(', ');
      var frag=[];(r.subnets||[]).forEach(function(s){(s.fragile||[]).forEach(function(f){frag.push(f.ip+' - '+f.why);});});
      bx.innerHTML='<div class="card mb-2"><div class="card-body py-2 small"><b>Network Assistant</b> <span class="mut">- filled from IP Address Management. Review, then save.</span>'
        +'<div class="mt-1">'+((sp.add_allowed||[]).length?'Added '+esc(sp.add_allowed.length)+' planned subnet(s) with live devices: '+esc(sp.add_allowed.join(', ')):'Every planned subnet with live devices is already in the scope.')+'</div>'
        +(frag.length?'<div class="mt-1">Never scanned (fragile, '+esc(frag.length)+'):<ul class="mb-0">'+frag.slice(0,30).map(function(x){return '<li>'+esc(x)+'</li>';}).join('')+'</ul></div>':'')
        +((sp.add_allowed_unplanned||[]).length?'<div class="mt-1">In use but not in the address plan: '+esc(sp.add_allowed_unplanned.join(', '))+' <button type="button" class="btn btn-sm ms-1" id="scpun">Add these too</button><div class="mut">Better: register them in IP Address Management so they have a site and an owner.</div></div>':'')
        +'</div></div>';
      var u=$('scpun');if(u)u.addEventListener('click',function(){al.value=uniq(cur(al).concat(sp.add_allowed_unplanned)).join(', ');u.disabled=true;});});}
  function runTest(){var b=$('testb');if(b)b.disabled=true;P.req('POST','/vulnscan/test',{}).then(function(r){
    Z.open('Vulnerability Scans','Connection test','<ol class="steps small">'+r.steps.map(function(t){return '<li><b>'+esc(ICON[t.status]||t.status)+' '+esc(t.step)+'</b> '+esc(t.detail)+(t.fix?'<div class="fix">Fix: '+esc(t.fix)+'</div>':'')+'</li>';}).join('')+'</ol>');load();
  }).catch(function(e){P.toast(why(e));}).then(function(){var b2=$('testb');if(b2)b2.disabled=false;});}

  document.addEventListener('click',function(ev){var b;
    if((b=ev.target.closest('#testb'))){runTest();return;}
    if((b=ev.target.closest('[data-sact]'))){var act=b.getAttribute('data-sact'),id=b.getAttribute('data-sid');
      if(act==='open'){openScan(id);return;}
      var note='';if(act==='reject'){note=window.prompt('Reason for rejecting '+id);if(!note)return;}
      if(act==='cancel'&&!window.confirm((b.textContent==='Stop'?'Stop ':'Cancel ')+id+'?'))return;
      P.req('POST','/vulnscan/scans/'+encodeURIComponent(id)+'/'+act,act==='approve'?{}:{note:note||undefined}).then(function(x){P.toast(x.id+': '+(STATE[x.state]||[x.state])[0]);load();}).catch(function(e){P.toast(why(e));});return;}
    if((b=ev.target.closest('[data-ract]'))){var d=b.getAttribute('data-ract'),n2='';if(d==='reject'){n2=window.prompt('Why is the risk not accepted?');if(!n2)return;}
      P.req('POST','/vulnscan/findings/'+encodeURIComponent(b.getAttribute('data-fid'))+'/risk-decision',{decision:d,note:n2||undefined}).then(function(f){P.toast('Risk acceptance '+(f.risk||{}).state);openFinding(f.id);load();}).catch(function(e){P.toast(why(e));});return;}
    if((b=ev.target.closest('tr[data-fid]'))){openFinding(b.getAttribute('data-fid'));return;}
    if((b=ev.target.closest('tr[data-host]'))){F.q=b.getAttribute('data-host');$('fq').value=F.q;list();}});
  document.addEventListener('click',function(ev){var b=ev.target.closest('[data-stg]');if(b)fillScan(Number(b.getAttribute('data-stg')));});
  document.addEventListener('submit',function(ev){var fm=ev.target,err=function(e){P.msg(fm,why(e));},b;
    if(fm.id==='scanf'){ev.preventDefault();P.req('POST','/vulnscan/scans',P.body(fm)).then(function(x){P.toast(x.id+' requested - a different person approves it');Z.close&&Z.close();load();}).catch(err);}
    else if(fm.id==='connf'){ev.preventDefault();b=P.body(fm);P.req('PUT','/vulnscan/config',b).then(function(){P.toast('Connection saved - test it');load();runTest();}).catch(err);}
    else if(fm.id==='scopef'){ev.preventDefault();b=P.body(fm);b.allowed=b.allowed||[];b.exclude=b.exclude||[];P.req('PUT','/vulnscan/scope',b).then(function(){P.toast('Scope saved');Z.close&&Z.close();load();}).catch(err);}
    else if(fm.id==='ownf'||fm.id==='riskf'){ev.preventDefault();var fid=fm.querySelector('[name=fid]').value;b=P.body(fm);
      P.req('POST','/vulnscan/findings/'+encodeURIComponent(fid)+(fm.id==='ownf'?'/owner':'/accept-risk'),b).then(function(f){P.toast(fm.id==='ownf'?'Owner '+f.owner:'Risk acceptance asked - a different person decides');openFinding(f.id);load();}).catch(err);}});
  $('fst').addEventListener('change',function(){F.status=this.value;list();});
  $('fsev').addEventListener('change',function(){F.sev=this.value;list();});
  $('fq').addEventListener('input',function(){F.q=this.value.trim();clearTimeout(qt);qt=setTimeout(list,300);});
  $('newscan').addEventListener('click',newScan);$('conn').addEventListener('click',connForm);$('scopeb').addEventListener('click',scopeForm);$('refresh').addEventListener('click',load);
  $('csv').addEventListener('click',function(){P.req('GET','/vulnscan/export').then(function(r){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['﻿'+r.csv],{type:'text/csv'}));a.download=r.filename;document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove();},1000);P.toast('Exported - recorded in the audit trail');}).catch(function(e){P.toast(why(e));});});
  load();setInterval(function(){if(V&&V.scans.some(function(x){return x.state==='running'||x.state==='stopping'||x.state==='approved';}))load();},30000);
})();
