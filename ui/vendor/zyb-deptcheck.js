// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
// Department Checklist (dept-checklist.html): each department's periodic framework obligations, attested by its head and verified
// by an auditor, read from /api/itam/dept-checklist (engine/dept-checklist.js). The server decides who may attest or review; every
// value is escaped.
(function(){
  'use strict';
  var P=window.zybPdpl, Z=window.zybDetail, L=window.zybLevels, esc=P.esc, $=P.$, V=null, F={dept:'',fw:'',res:'',q:''};
  var RES={verified:['Done · verified','green'],awaiting_review:['Attested · to verify','orange'],partly:['Partly done','yellow'],not_done:['Not done','red'],exception:['Auditor exception','red'],
    overdue:['Overdue','red'],open:['Open','secondary'],no_owner:['No head named','secondary'],not_applicable:['Not applicable','secondary']};
  var ST={done:'Done',partly:'Partly done',not_done:'Not done',not_applicable:'Not applicable'};
  var FWN={sama:'SAMA',nca:'NCA',pdpl:'PDPL',ndmo:'NDMO',ia:'IA'};
  function why(e){if(e&&e.status===403&&(!e.message||/requires|HTTP 403/i.test(e.message)))return 'This needs the operator role (a named person); naming department heads needs the admin role.';if(e&&e.status===404&&/HTTP 404/.test(e.message||''))return 'The department checklist service is not installed yet: run the update (git pull origin main, then scripts\\update-platform.ps1).';return (e&&e.message)||'request failed';}
  function rb(r){var x=RES[r]||[r,'secondary'];return P.badge(x[0],x[1]);}
  function refs(r){return '<div class="refs">'+['sama','nca','pdpl','ndmo'].map(function(k){return (r[k]||[]).map(function(c){return '<span>'+esc(FWN[k]+' '+c)+'</span>';}).join('');}).join('')+'</div>';}

  function load(){return P.req('GET','/dept-checklist').then(function(v){V=v;draw();}).catch(function(e){var m='<div class="alert alert-warning mb-0">'+esc(why(e))+'</div>';$('kpis').innerHTML='<div class="col-12">'+m+'</div>';$('depts').innerHTML='';$('fws').innerHTML='';$('list').innerHTML='';});}
  function draw(){var v=V,c=v.counts;
    $('kpis').innerHTML=L.tiles(v.overall,P.tile,'obligations')+P.tile(c.overdue,'Overdue',c.overdue?'text-red':'')+P.tile(c.awaiting_review,'Attested, to verify',c.awaiting_review?'text-orange':'')
      +P.tile(c.exceptions,'Auditor exceptions',c.exceptions?'text-red':'')+P.tile(c.no_owner,'Departments with no head named',c.no_owner?'text-orange':'');
    $('depts').innerHTML=L.groups(v.departments,function(g){return 'data-dept="'+esc(g.key)+'"'+(F.dept===g.key?' aria-pressed="true"':'');})+L.legend('A department with no head named reads not assessed: an admin names one (Department heads).');
    $('fws').innerHTML=L.groups(v.frameworks,function(g){return 'data-fwk="'+esc(g.key)+'"';})+'<div class="mut mt-1">The framework mapping is domain-level: a draft for the compliance team to verify against the framework texts.</div>';
    [].forEach.call(document.querySelectorAll('#depts [data-dept]'),function(b){b.classList.toggle('on',b.getAttribute('data-dept')===F.dept);});
    [].forEach.call(document.querySelectorAll('#fws [data-fwk]'),function(b){b.classList.toggle('on',b.getAttribute('data-fwk')===F.fw);});
    if($('fdept').options.length<2){v.departments.forEach(function(d){var o=document.createElement('option');o.value=d.key;o.textContent=d.name;$('fdept').appendChild(o);});
      v.frameworks.forEach(function(f){var o=document.createElement('option');o.value=f.key;o.textContent=f.name;$('ffw').appendChild(o);});}
    $('fdept').value=F.dept;$('ffw').value=F.fw;list();
    $('note').textContent=v.note;
  }
  function shown(){var q=F.q.toLowerCase();return V.items.filter(function(r){
    if(F.dept&&r.dept!==F.dept)return false;if(F.fw&&!(r[F.fw]||[]).length)return false;
    if(F.res==='attention'&&['overdue','exception','not_done'].indexOf(r.result)<0)return false;
    if(F.res==='open'&&['open','no_owner'].indexOf(r.result)<0)return false;
    if(F.res&&['attention','open'].indexOf(F.res)<0&&r.result!==F.res)return false;
    return !q||(r.id+' '+r.title+' '+r.dept_name).toLowerCase().indexOf(q)>=0;});}
  function list(){var rows=shown();
    $('list').innerHTML=P.table([['Obligation',function(r){return '<b>'+esc(r.id)+'</b> '+esc(r.title)+refs(r);}],['Department',function(r){return esc(r.dept_name)+'<div class="mut">'+esc(r.frequency)+'</div>';}],
      ['Period',function(r){return esc(r.current_period)+'<div class="mut">attest by '+esc(r.attest_by)+'</div>';}],
      ['Status',function(r){return rb(r.result)+'<div class="mut">'+esc(r.why)+'</div>';}]],rows,function(r){return 'class="rowc" data-ob="'+esc(r.id)+'"';},'No obligation matches the filter.');}

  function open(id){var r=V.items.filter(function(x){return x.id===id;})[0];if(!r)return;
    var h=Z.kv([['Department',esc(r.dept_name)],['Frequency',esc(r.frequency)],['Status',rb(r.result)+' <span class="mut">'+esc(r.why)+'</span>'],['Evidence expected',esc(r.evidence_expected)],['Frameworks',refs(r)||'—']]);
    h+=Z.sec('Periods',P.table([['Period',function(p){return esc(p.period)+'<div class="mut">due '+esc(p.due)+'</div>';}],
      ['Attestation',function(p){var a=p.rec;return a?esc(ST[a.status]||a.status)+(a.late?' '+P.badge('late','orange'):'')+'<div class="mut">'+esc(a.by||'')+' · '+esc(P.dt(a.at))+'</div>'+(a.evidence?'<div class="small">Evidence: '+esc(a.evidence)+'</div>':'')+(a.note?'<div class="small">'+esc(a.note)+'</div>':''):'<span class="mut">not attested</span>';}],
      ['Auditor',function(p){var a=p.rec&&p.rec.review;return a?P.badge(a.decision==='verified'?'verified':'exception',a.decision==='verified'?'green':'red')+'<div class="mut">'+esc(a.by||'')+' · '+esc(P.dt(a.at))+'</div>'+(a.note?'<div class="small">'+esc(a.note)+'</div>':''):'<span class="mut">—</span>';}]],r.history));
    var per=[[r.current_period,r.current_period+' (current)'],[r.previous_period,r.previous_period+' (previous)']];
    h+=Z.sec('Attest (department head or deputy)',P.form('atf',[['period','sel','Period',1,per],['status','sel','Status',1,[['done','Done'],['partly','Partly done'],['not_done','Not done'],['not_applicable','Not applicable']]],['evidence','text','Evidence reference (document store location) - required for done / partly'],['note','area','Note - required for partly, not done, not applicable']],{period:r.current_period},'Attest','<input type="hidden" name="oid" value="'+esc(r.id)+'">'));
    var rv=r.history.filter(function(p){return p.rec&&!p.rec.review;}).slice(0,2);
    if(rv.length)h+=Z.sec('Review (auditor - not the person who attested, not this department\'s head)',P.form('rvf',[['period','sel','Period',1,rv.map(function(p){return [p.period,p.period+' - '+(ST[p.rec.status]||p.rec.status)];})],['decision','sel','Decision',1,[['verified','Verified - the evidence shows it was done'],['exception','Exception - the evidence does not show it']]],['note','area','Note - required for an exception']],{period:rv[0].period},'Record review','<input type="hidden" name="oid" value="'+esc(r.id)+'">'));
    Z.open('Department Checklist',r.id+' '+r.title,h);
  }
  function heads(){P.req('GET','/dept-checklist/owners').then(function(o){
    var h=P.table([['Department',function(d){return esc(d.name)+'<div class="mut">'+esc(d.obligations)+' obligation(s)</div>';}],['Head',function(d){return d.named?esc(d.head||'named')+(d.deputy?'<div class="mut">deputy '+esc(d.deputy)+'</div>':''):'<span class="text-orange">not named</span>';}],['Tracked since',function(d){return d.since?esc(P.dt(d.since)):'—';}]],o);
    h+=Z.sec('Name a department head (admin)',P.form('hdf',[['dept','sel','Department',1,o.map(function(d){return [d.dept,d.name];})],['head','text','Head (user name)',1],['deputy','text','Deputy (user name, optional)']],{},'Save'));
    Z.open('Department Checklist','Department heads',h);}).catch(function(e){P.toast(why(e));});}

  document.addEventListener('click',function(ev){var b=ev.target.closest('[data-dept]');if(b){F.dept=F.dept===b.getAttribute('data-dept')?'':b.getAttribute('data-dept');draw();return;}
    b=ev.target.closest('[data-fwk]');if(b){F.fw=F.fw===b.getAttribute('data-fwk')?'':b.getAttribute('data-fwk');draw();return;}
    b=ev.target.closest('tr[data-ob]');if(b)open(b.getAttribute('data-ob'));});
  document.addEventListener('submit',function(ev){var fm=ev.target,err=function(e){P.msg(fm,why(e));};
    if(fm.id==='atf'||fm.id==='rvf'){ev.preventDefault();var b=P.body(fm);b.id=fm.querySelector('[name=oid]').value;
      P.req('POST',fm.id==='atf'?'/dept-checklist/attest':'/dept-checklist/review',b).then(function(r){P.toast(r.id+': '+(RES[r.result]||[r.result])[0]);load().then(function(){open(r.id);});}).catch(err);}
    else if(fm.id==='hdf'){ev.preventDefault();P.req('POST','/dept-checklist/owners',P.body(fm)).then(function(r){P.toast(r.name+': head '+r.head);load();heads();}).catch(err);}});
  $('fdept').addEventListener('change',function(){F.dept=this.value;draw();});
  $('ffw').addEventListener('change',function(){F.fw=this.value;draw();});
  $('fres').addEventListener('change',function(){F.res=this.value;list();});
  $('fq').addEventListener('input',function(){F.q=this.value;list();});
  $('heads').addEventListener('click',heads);
  $('refresh').addEventListener('click',load);
  $('csv').addEventListener('click',function(){P.req('GET','/dept-checklist/export').then(function(r){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['﻿'+r.csv],{type:'text/csv'}));a.download=r.filename;document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove();},1000);P.toast('Exported - recorded in the audit trail');}).catch(function(e){P.toast(why(e));});});
  load();
})();
