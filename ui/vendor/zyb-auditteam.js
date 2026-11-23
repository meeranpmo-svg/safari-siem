// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
// The audit team pages (internal-audit-team.html, audit-team.html, cyber-audit-team.html): morning brief, annual plan, engagements with sampling,
// workpapers, findings and the report, ask the auditor, profile. Engine: repos/sentra-itam/engine/audit-engage.js.
(function(){
  'use strict';
  var P=window.zybPdpl, Z=window.zybDetail, esc=P.esc, $=P.$;
  // one script, three teams: <body data-audit="ia"> (IT Audit Team), "csa" (Cyber Security Audit Team) or "iad" (Internal Audit Team) - separate records and routes
  var TEAMS={ia:{eng:/^ENG-/,find:/^IAF-/,plan:/^PLAN-/,work:/^SMP-|^WP-/,planPrefix:'PLAN'},csa:{eng:/^CSE-/,find:/^CSF-/,plan:/^CSPLAN-/,work:/^CSS-|^CWP-/,planPrefix:'CSPLAN'},
    iad:{eng:/^INE-/,find:/^INF-/,plan:/^INPLAN-/,work:/^INS-|^INW-/,planPrefix:'INPLAN'}};
  var KIND=TEAMS[document.body.getAttribute('data-audit')]?document.body.getAttribute('data-audit'):'ia', B='/'+KIND, IDS=TEAMS[KIND];
  var PROF=null, AREAS=[], POPS=[], ENGS=[], CUR=null, ME='';
  var ST={planning:['planning','secondary'],fieldwork:['fieldwork','blue'],draft_report:['draft report','orange'],final:['final','green'],cancelled:['cancelled','secondary'],
    draft:['draft','secondary'],issued:['issued','orange'],responded:['responded','blue'],implemented:['implemented - re-test','purple'],closed:['closed','green'],risk_accepted:['risk accepted','yellow'],withdrawn:['withdrawn','secondary'],
    submitted:['submitted','orange'],approved:['approved','green'],open:['open','secondary'],concluded:['concluded - to review','orange'],reviewed:['reviewed','green']};
  var RT={high:'red',medium:'orange',low:'blue'};
  function sb(s){var x=ST[s]||[s,'secondary'];return P.badge(x[0],x[1]);}
  function why(e){if(e&&e.status===403&&(!e.message||/requires|role|HTTP 403/i.test(e.message)))return 'Audit records need the operator role (a named person).';if(e&&e.status===404&&/HTTP 404/.test(e.message||''))return 'The IT audit service is not installed yet: run the update (git pull origin main, then scripts\\update-platform.ps1).';return (e&&e.message)||'request failed';}
  function fail(el,e){if(el)el.innerHTML='<div class="card-body"><div class="alert alert-warning mb-0">'+esc(why(e))+'</div></div>';}
  function toastErr(e){P.toast(why(e));}
  function areaName(id){var a=AREAS.filter(function(x){return x.id===id;})[0];return a?a.name:id;}

  function tabs(t){[].forEach.call(document.querySelectorAll('[data-tab]'),function(b){b.classList.toggle('btn-primary',b.getAttribute('data-tab')===t);});
    [].forEach.call(document.querySelectorAll('[data-pane]'),function(p){p.hidden=p.getAttribute('data-pane')!==t;});
    if(t==='plan')loadPlan();if(t==='eng')loadEngs();if(t==='find')loadFinds();if(t==='ask')loadAi();if(t==='profile')drawProfile();}

  function loadBrief(){return P.req('GET',B+'/brief').then(function(b){
    $('brief').innerHTML=b.items.length?b.items.map(function(x){return '<div class="bi s-'+esc(x.severity)+'"><div class="d-flex justify-content-between gap-2"><span class="small">'+esc(x.text)+'</span><button type="button" class="btn btn-sm btn-ghost-secondary" data-ref="'+esc(x.ref)+'">Open</button></div></div>';}).join('')
      :'<p class="text-secondary mb-0">Nothing due or overdue. When engagements, findings or an approved plan exist, what needs attention today appears here.</p>';
    return b;}).catch(function(e){fail($('brief'),e);});}
  function kpis(){Promise.all([P.req('GET',B+'/engagements').catch(function(){return [];}),P.req('GET',B+'/findings').catch(function(){return [];})]).then(function(r){var e=r[0],f=r[1];
    $('kpis').innerHTML=P.tile(e.filter(function(x){return x.state==='fieldwork';}).length,'In fieldwork')+P.tile(e.filter(function(x){return x.state==='draft_report';}).length,'Reports in draft')
      +P.tile(f.filter(function(x){return ['issued','responded','implemented'].indexOf(x.state)>=0;}).length,'Open findings')+P.tile(f.filter(function(x){return x.overdue;}).length,'Overdue findings',f.some(function(x){return x.overdue;})?'text-red':'');});}

  // ---- plan
  function loadPlan(){return P.req('GET',B+'/plans').then(function(ps){
    var y=Number($('pyear').value)||new Date().getFullYear();var p=ps.filter(function(x){return x.year===y;})[0];
    if(!p){$('plan').innerHTML='<div class="card-body text-secondary">No plan for '+esc(y)+' yet. "Propose the plan" scores every area of the audit universe from the risk register, the audit programme, NCA ECC gaps, overdue findings and the audit history.</div>';$('pnote').textContent='';return;}
    var draft=p.state==='draft';
    $('plan').innerHTML='<div class="card-body pb-0 d-flex flex-wrap gap-2 align-items-center">'+sb(p.state)+'<span class="mut">prepared by '+esc(p.prepared_by)+(p.decided_by?' · decided by '+esc(p.decided_by):'')+'</span>'
      +(draft?'<button type="button" class="btn btn-sm ms-auto" id="psubmit" data-plan="'+esc(p.id)+'">Submit to the Head of Audit</button>':'')+(p.state==='submitted'?'<button type="button" class="btn btn-sm btn-success ms-auto" data-pdec="approve" data-plan="'+esc(p.id)+'">Approve</button><button type="button" class="btn btn-sm" data-pdec="reject" data-plan="'+esc(p.id)+'">Reject</button>':'')+'</div>'
      +'<div class="table-responsive">'+P.table([['Include',function(x){return '<input type="checkbox" class="form-check-input" data-inc="'+esc(x.area)+'"'+(x.include?' checked':'')+(draft?'':' disabled')+' aria-label="include '+esc(x.name)+'">';}],
        ['Area',function(x){return '<b>'+esc(x.name)+'</b>';}],['Score',function(x){return '<b>'+esc(x.score)+'</b> '+P.badge(x.band,x.band==='high'?'red':x.band==='medium'?'orange':'secondary');}],
        ['Why',function(x){return '<ul class="why mb-0 ps-3">'+x.why.map(function(w){return '<li>+'+esc(w.points)+' '+esc(w.source)+': '+esc(w.text)+(w.refs?' <span class="mut">'+esc(w.refs.join(', '))+'</span>':'')+'</li>';}).join('')+'</ul>';}],
        ['Quarter',function(x){return draft?'<select class="form-select form-select-sm" data-q="'+esc(x.area)+'" aria-label="quarter">'+['Q1','Q2','Q3','Q4'].map(function(q){return '<option'+(q===x.quarter?' selected':'')+'>'+q+'</option>';}).join('')+'</select>':esc(x.quarter);}],
        ['Days',function(x){return draft?'<input type="number" class="form-control form-control-sm" style="width:70px" min="1" max="120" data-d="'+esc(x.area)+'" value="'+esc(x.days)+'" aria-label="days">':esc(x.days);}]],p.items)+'</div>'
      +(draft?'<div class="card-body pt-2"><button type="button" class="btn btn-sm" id="psave" data-plan="'+esc(p.id)+'">Save changes</button></div>':'');
    $('pnote').textContent='Score = inherent risk ×4 + highest linked risk + failed programme tests + NCA ECC gaps + overdue findings + time since last audit. A source that is not connected adds nothing.';
  }).catch(function(e){fail($('plan'),e);});}

  // ---- engagements
  function loadEngs(){return P.req('GET',B+'/engagements').then(function(es){ENGS=es;
    $('engs').innerHTML=P.table([['Engagement',function(x){return '<b>'+esc(x.id)+'</b> '+esc(x.title)+'<div class="mut">'+esc(x.area_name||x.area)+' · '+esc(x.auditee_dept)+'</div>';}],['State',function(x){return sb(x.state);}],
      ['Lead',function(x){return esc(x.lead);}],['Fieldwork',function(x){return esc(x.start)+' → '+esc(x.fieldwork_end)+'<div class="mut">report due '+esc(x.report_due)+'</div>';}],['Findings',function(x){return esc(x.findings);}]],es,function(x){return 'class="rowc" data-eng="'+esc(x.id)+'"';},'No engagement yet. Open one from an approved plan item or with "New engagement".');
  }).catch(function(e){fail($('engs'),e);});}
  function newEng(){var opts=AREAS.map(function(a){return [a.id,a.name];});
    Z.open('IT Audit','New engagement',P.form('engf',[['title','text','Title',1],['area','sel','Audit area',1,opts],['auditee_dept','text','Auditee department',1],['auditee_owner','text','Auditee owner (user name)',1],['lead','text','Lead auditor (user name)',1],['team','list','Other auditors (user names, comma-separated)'],
      ['objectives','area','Objectives (one per line)'],['scope','area','Scope'],['criteria','text','Criteria (e.g. ISO 27001 A.5.18, NCA ECC 2-2)'],['start','date','Start',1],['fieldwork_end','date','Fieldwork ends',1],['report_due','date','Report due',1],['plan_item','text','Plan item ('+IDS.planPrefix+'-<year>:<area>, optional)']],{lead:ME},'Create'));}

  function openEng(id){return P.req('GET',B+'/engagements/'+encodeURIComponent(id)).then(function(e){CUR=e;drawEng(e);}).catch(toastErr);}
  function drawEng(e){
    var next={planning:'fieldwork',fieldwork:'draft_report'}[e.state];
    var h=Z.kv([['State',sb(e.state)+(e.overdue?' '+P.badge('overdue','red'):'')],['Area',esc(e.area_name||e.area)],['Auditee',esc(e.auditee_dept)+' · '+esc(e.auditee_owner)],['Team',esc([e.lead+' (lead)'].concat(e.team||[]).join(', '))],
      ['Dates',esc(e.start+' → '+e.fieldwork_end+' · report due '+e.report_due)],['Objectives',esc((e.objectives||[]).join(' · ')||'—')],['Scope',esc(e.scope||'—')],['Criteria',esc(e.criteria||'—')]]);
    // previous audit reports of the area: fieldwork needs one on file (or "no previous audit"), the report needs their open findings followed up
    var pr=e.prior||[],fu=e.follow_up||[],fl=fu.filter(function(x){return !x.result;}).length,tm=KIND;
    h+='<div class="my-2 mut">Previous audit: '+(pr.length?esc(pr[0].title+' ('+pr[0].report_date+')')+(fu.length?' · follow-up '+esc(fu.length-fl)+' of '+esc(fu.length)+' done':''):e.prior_none?'none - '+esc(e.prior_none.note):'<b>no previous report on file</b> - needed before fieldwork')
      +' · <a href="audit-start.html#team='+esc(tm)+'&eng='+encodeURIComponent(e.id)+'">'+(pr.length||e.prior_none?'open in Start an Audit':'upload it in Start an Audit')+'</a></div>';
    if(next)h+='<div class="my-2"><button type="button" class="btn btn-sm btn-primary" data-adv="'+esc(next)+'">Move to '+esc(next.replace('_',' '))+'</button></div>';
    // samples
    var sh=e.samples.map(function(s){return '<div class="border rounded p-2 mb-2"><div class="d-flex justify-content-between"><b>'+esc(s.id)+' · '+esc(s.population_name)+'</b><span class="mut">'+esc(s.method)+(s.seed?' · seed '+esc(s.seed):'')+' · '+esc(s.size)+' of '+esc(s.population_size)+'</span></div>'
      +P.table([['Record',function(i){return esc(i.label);}],['Suggested tests',function(i){return i.suggested.map(function(t){return (t.ok===true?P.badge('pass','green'):t.ok===false?P.badge('fail','red'):P.badge('n/a','secondary'))+' <span class="mut">'+esc(t.test)+'</span>';}).join('<br>');}],
        ['Auditor\'s result',function(i){return i.result?(P.badge(i.result,i.result==='pass'?'green':i.result==='exception'?'red':'secondary')+'<div class="mut">'+esc(i.by)+(i.note?': '+esc(i.note):'')+'</div>'):(e.state==='fieldwork'?'<button type="button" class="btn btn-sm" data-si="'+esc(s.id)+'" data-ref="'+esc(i.ref)+'" data-r="pass">Pass</button> <button type="button" class="btn btn-sm" data-si="'+esc(s.id)+'" data-ref="'+esc(i.ref)+'" data-r="exception">Exception</button> <button type="button" class="btn btn-sm" data-si="'+esc(s.id)+'" data-ref="'+esc(i.ref)+'" data-r="na">N/A</button>':'—');}]],s.items)+'</div>';}).join('');
    if(e.state==='fieldwork')sh+=P.form('smpf',[['population','sel','Population',1,POPS.map(function(p){return [p.id,p.name+' ('+p.size+')'];})],['size','num','Sample size (1-60)',1],['method','sel','Method',1,[['random','Random (seed recorded)'],['judgemental','Judgemental (records chosen)']]],['from','date','From (optional)'],['to','date','To (optional)'],['refs','list','Records for a judgemental sample (ids, comma-separated)']],{},'Draw the sample');
    h+=Z.sec('Samples',sh||'<p class="mut mb-0">Samples are drawn during fieldwork.</p>');
    // workpapers
    var wh=P.table([['Workpaper',function(w){return '<b>'+esc(w.id)+'</b> '+esc(w.title)+'<div class="mut">'+esc(w.procedure)+'</div>';}],['State',function(w){return sb(w.state)+(w.conclusion?' '+P.badge(w.conclusion.replace('_',' '),w.conclusion==='effective'?'green':w.conclusion==='ineffective'?'red':'orange'):'');}],
      ['',function(w){return (e.state==='fieldwork'&&w.state==='open'?'<button type="button" class="btn btn-sm" data-wc="'+esc(w.id)+'">Conclude</button>':'')+(w.state==='concluded'?'<button type="button" class="btn btn-sm" data-wr="'+esc(w.id)+'" data-d="accept">Accept</button> <button type="button" class="btn btn-sm" data-wr="'+esc(w.id)+'" data-d="return">Return</button>':'')+(w.reviewed_by?'<div class="mut">reviewed by '+esc(w.reviewed_by)+'</div>':'');}]],e.workpapers,null,'No workpaper yet.');
    if(['planning','fieldwork'].indexOf(e.state)>=0)wh+=P.form('wpf',[['title','text','Title',1],['objective','area','Objective',1],['procedure','area','Procedure',1],['sample','sel','Sample tested',0,e.samples.map(function(s){return [s.id,s.id+' '+s.population_name];})]],{},'Add workpaper');
    h+=Z.sec('Workpapers',wh);
    // findings
    var fh=P.table([['Finding',function(f){return '<b>'+esc(f.id)+'</b> '+esc(f.title)+'<div class="mut">owner '+esc(f.owner)+(f.due?' · due '+esc(f.due):'')+'</div>';}],['Rating',function(f){return P.badge(f.rating,RT[f.rating]);}],['State',function(f){return sb(f.state)+(f.overdue?' '+P.badge('overdue','red'):'');}],
      ['',function(f){return '<button type="button" class="btn btn-sm" data-fo="'+esc(f.id)+'">Open</button>';}]],e.findings,null,'No finding raised.');
    if(['fieldwork','draft_report'].indexOf(e.state)>=0){var exc=[];e.samples.forEach(function(s){s.items.forEach(function(i){if(i.result==='exception')exc.push(s.id+'/'+i.ref);});});
      fh+=P.form('ffm',[['title','text','Title',1],['condition','area','Condition (what was found)',1],['criteria','area','Criteria (what should be)',1],['cause','area','Cause',1],['effect','area','Effect (risk)',1],['recommendation','area','Recommendation',1],['rating','sel','Rating',1,[['high','High'],['medium','Medium'],['low','Low']]],['owner','text','Owner in the auditee department (user name)',1],['samples','multi','Sample exceptions',0,exc]],{},'Raise finding');}
    h+=Z.sec('Findings',fh);
    if(['draft_report','final'].indexOf(e.state)>=0)h+=Z.sec('Report','<button type="button" class="btn btn-sm btn-primary" data-rep="'+esc(e.id)+'">Open the report</button>');
    Z.open('IT Audit',e.id+' · '+e.title,h);}

  function openReport(id){return P.req('GET',B+'/engagements/'+encodeURIComponent(id)+'/report').then(function(r){
    var e=r.engagement, h=Z.kv([['Engagement',esc(e.id+' · '+e.title)],['Area',esc(e.area)],['Auditee',esc(e.auditee_dept+' · '+e.auditee_owner)],['Opinion','<b>'+esc(r.opinion)+'</b>'],['Findings',esc('high '+r.counts.high+' · medium '+r.counts.medium+' · low '+r.counts.low)],
      ['State',r.final?P.badge('final','green')+' <span class="mut">approved by '+esc(r.approved_by)+' · hash '+esc(String(r.hash).slice(0,16))+'…</span>':(r.signed_by?P.badge('signed by '+r.signed_by,'blue'):P.badge('draft','secondary'))]]);
    h+=Z.sec('Executive summary',r.executive_summary?'<p class="small" style="white-space:pre-wrap">'+esc(r.executive_summary)+'</p><div class="mut">written by '+esc(r.summary_by)+'</div>':'<p class="mut">Not written yet.</p>');
    if(!r.final){
      if(r.ai_draft)h+=Z.sec('AI draft (not adopted)','<p class="small" style="white-space:pre-wrap">'+esc(r.ai_draft.text)+'</p><div class="mut">drafted by the AI ('+esc(r.ai_draft.model)+') at the request of '+esc(r.ai_draft.requested_by)+' - check it against the workpapers before adopting</div><button type="button" class="btn btn-sm mt-1" id="adopt">Copy into the summary below</button>');
      h+=P.form('sumf',[['summary','area','Executive summary (written by a person)',1]],{summary:r.executive_summary},'Save summary')
        +'<div class="d-flex gap-2 mt-2"><button type="button" class="btn btn-sm" data-aid="'+esc(e.id)+'"><i class="ti ti-sparkles me-1"></i>Ask the AI for a draft</button><button type="button" class="btn btn-sm btn-primary" data-sign="'+esc(e.id)+'">Sign (lead auditor)</button><button type="button" class="btn btn-sm btn-success" data-appr="'+esc(e.id)+'">Approve (Head of Audit)</button></div>';
    }
    h+=Z.sec('Work performed',P.table([['Workpaper',function(w){return esc(w.id+' '+w.title);}],['Conclusion',function(w){return esc((w.conclusion||'').replace('_',' '));}],['Summary',function(w){return '<span class="small">'+esc(w.summary)+'</span>';}]],r.work_performed));
    h+=Z.sec('Sampling',P.table([['Sample',function(s){return esc(s.id+' '+s.population);}],['Method',function(s){return esc(s.method+(s.seed?' · seed '+s.seed:''));}],['Size',function(s){return esc(s.size+' of '+s.population_size);}],['Exceptions',function(s){return esc(s.exceptions);}]],r.sampling));
    h+=Z.sec('Findings',r.findings.map(function(f){return '<div class="border rounded p-2 mb-2"><b>'+esc(f.id+' '+f.title)+'</b> '+P.badge(f.rating,RT[f.rating])+Z.kv([['Condition',esc(f.condition)],['Criteria',esc(f.criteria)],['Cause',esc(f.cause)],['Effect',esc(f.effect)],['Recommendation',esc(f.recommendation)],['Management response',esc(f.response||'—')],['Action plan',esc((f.action_plan||'—')+(f.due?' · due '+f.due:''))]])+'</div>';}).join('')||'<p class="mut">No findings.</p>');
    Z.open('IT Audit report',e.id,h+'<input type="hidden" id="repid" value="'+esc(e.id)+'">');
    var ad=$('adopt');if(ad)ad.addEventListener('click',function(){var t=document.querySelector('#sumf [name=summary]');if(t)t.value=r.ai_draft.text;});
  }).catch(toastErr);}

  function openFinding(id){return P.req('GET',B+'/findings').then(function(fs){var f=fs.filter(function(x){return x.id===id;})[0];if(!f){P.toast('Finding not found');return;}
    var h=Z.kv([['State',sb(f.state)+(f.overdue?' '+P.badge('overdue','red'):'')],['Rating',P.badge(f.rating,RT[f.rating])],['Engagement',esc(f.engagement)],['Owner',esc(f.owner)],['Condition',esc(f.condition)],['Criteria',esc(f.criteria)],['Cause',esc(f.cause)],['Effect',esc(f.effect)],['Recommendation',esc(f.recommendation)],
      ['Management response',esc(f.response||'—')],['Action plan',esc((f.action_plan||'—')+(f.due?' · due '+f.due:''))],['Evidence of implementation',esc(f.evidence||'—')],['Samples',esc((f.samples||[]).join(', ')||'—')]]);
    var A=[];
    if(f.state==='draft')A.push(['issue','Issue to the owner',[]],['withdraw','Withdraw',[['note','area','Reason',1]]]);
    if(['issued','responded'].indexOf(f.state)>=0)A.push(['respond','Record management\'s response (owner)',[['response','area','Response',1],['action_plan','area','Action plan',1],['due','date','Due',1]]]);
    if(f.state==='responded')A.push(['implemented','Mark implemented (owner)',[['evidence','area','Evidence',1]]]);
    if(f.state==='implemented')A.push(['retest','Re-test (auditor)',[['result','sel','Result',1,[['closed','Closed - the fix works'],['reopen','Re-open - not fixed']]],['note','area','What was re-tested',1]]]);
    if(['issued','responded','implemented'].indexOf(f.state)>=0)A.push(['accept-risk','Accept the risk (Head of Audit)',[['reason','area','Reason',1]]]);
    h+=A.map(function(a){return Z.sec(a[1],P.form('fa-'+a[0],a[2],{},a[1],'<input type="hidden" name="fid" value="'+esc(f.id)+'">'));}).join('');
    Z.open('Audit finding',f.id+' · '+f.title,h);}).catch(toastErr);}

  function loadFinds(){var q=[];if($('fstate').value)q.push('state='+encodeURIComponent($('fstate').value));if($('fover').checked)q.push('overdue=1');
    return P.req('GET',B+'/findings'+(q.length?'?'+q.join('&'):'')).then(function(fs){
      $('finds').innerHTML=P.table([['Finding',function(f){return '<b>'+esc(f.id)+'</b> '+esc(f.title)+'<div class="mut">'+esc(f.engagement)+' · '+esc(areaName(f.area))+'</div>';}],['Rating',function(f){return P.badge(f.rating,RT[f.rating]);}],['Owner',function(f){return esc(f.owner);}],
        ['Due',function(f){return esc(f.due||'—')+(f.overdue?' '+P.badge('overdue','red'):'');}],['State',function(f){return sb(f.state);}]],fs,function(f){return 'class="rowc" data-fo="'+esc(f.id)+'"';},'No finding matches.');}).catch(function(e){fail($('finds'),e);});}

  function loadAi(){P.req('GET',B+'/ai/status').then(function(s){$('aistat').textContent=s.enabled?'On - '+s.model+'. It reads only the audit records, through read-only tools; it cannot sign, approve or close anything.':'Off: '+s.reason;}).catch(function(e){$('aistat').textContent=why(e);});}
  function drawProfile(){var p=PROF||{};$('prof').innerHTML=P.form('proff',[['head_of_audit','text','Head of Audit (user name)',1],['auditors','list','Auditors (user names, comma-separated)'],['engagements_per_year','num','Engagements per year (plan capacity)']],p,'Save profile');}

  function load(){return P.req('GET',B+'/profile').then(function(p){PROF=p;}).catch(function(){PROF=null;}).then(function(){loadBrief();kpis();});}

  // ---- events
  $('tabs').addEventListener('click',function(ev){var b=ev.target.closest('[data-tab]');if(b)tabs(b.getAttribute('data-tab'));});
  $('refresh').addEventListener('click',load);
  $('pyear').value=new Date().getFullYear();$('pyear').addEventListener('change',loadPlan);
  $('propose').addEventListener('click',function(){P.req('POST',B+'/plans/propose',{year:Number($('pyear').value)}).then(function(){P.toast('Plan proposed - review it, then submit it to the Head of Audit');loadPlan();}).catch(toastErr);});
  $('newEng').addEventListener('click',function(){areasP.then(newEng);});
  $('fstate').addEventListener('change',loadFinds);$('fover').addEventListener('change',loadFinds);
  $('askf').addEventListener('submit',function(ev){ev.preventDefault();var q=$('askq').value.trim();if(!q)return;$('askmsg').textContent='Thinking…';
    P.req('POST',B+'/ask',{question:q}).then(function(r){$('askmsg').textContent='';$('answer').textContent=r.answer;}).catch(function(e){$('askmsg').textContent=why(e);});});
  document.addEventListener('click',function(ev){var t=ev.target, b;
    if((b=t.closest('#plan #psubmit'))){P.req('POST',B+'/plans/'+encodeURIComponent(b.getAttribute('data-plan'))+'/submit',{}).then(function(){P.toast('Submitted');loadPlan();}).catch(toastErr);return;}
    if((b=t.closest('[data-pdec]'))){var dec=b.getAttribute('data-pdec'),note=dec==='reject'?window.prompt('Reason for rejecting the plan'):'';if(dec==='reject'&&!note)return;
      P.req('POST',B+'/plans/'+encodeURIComponent(b.getAttribute('data-plan'))+'/decide',{decision:dec,note:note||undefined}).then(function(){P.toast(dec==='approve'?'Plan approved':'Plan sent back');loadPlan();}).catch(toastErr);return;}
    if((b=t.closest('#psave'))){var items=[].map.call(document.querySelectorAll('[data-inc]'),function(c){var a=c.getAttribute('data-inc');return {area:a,include:c.checked,quarter:document.querySelector('[data-q="'+a+'"]').value,days:Number(document.querySelector('[data-d="'+a+'"]').value)};});
      P.req('POST',B+'/plans/'+encodeURIComponent(b.getAttribute('data-plan'))+'/items',{items:items}).then(function(){P.toast('Plan saved');loadPlan();}).catch(toastErr);return;}
    if((b=t.closest('[data-eng]'))){openEng(b.getAttribute('data-eng'));return;}
    if((b=t.closest('#brief [data-ref]'))){var ref=b.getAttribute('data-ref');if(IDS.eng.test(ref)){tabs('eng');openEng(ref);}else if(IDS.find.test(ref)){openFinding(ref);}else if(IDS.plan.test(ref)){tabs('plan');}else if(IDS.work.test(ref)){tabs('eng');}return;}
    if((b=t.closest('[data-adv]'))&&CUR){var to=b.getAttribute('data-adv');P.req('POST',B+'/engagements/'+encodeURIComponent(CUR.id)+'/advance',{to:to}).then(function(){P.toast('Moved to '+to.replace('_',' '));openEng(CUR.id);loadEngs();}).catch(toastErr);return;}
    if((b=t.closest('[data-si]'))){var r=b.getAttribute('data-r'),n=r==='pass'?'':window.prompt(r==='exception'?'Describe the exception':'Why is it not applicable?');if(r!=='pass'&&!n)return;
      P.req('POST',B+'/samples/'+encodeURIComponent(b.getAttribute('data-si'))+'/items/'+encodeURIComponent(b.getAttribute('data-ref')),{result:r,note:n||undefined}).then(function(){openEng(CUR.id);}).catch(toastErr);return;}
    if((b=t.closest('[data-wc]'))){var wid=b.getAttribute('data-wc');Z.open('Conclude workpaper',wid,P.form('wcf',[['conclusion','sel','Conclusion',1,[['effective','Effective'],['partially_effective','Partially effective'],['ineffective','Ineffective']]],['summary','area','Summary of the work and the evidence',1]],{},'Conclude','<input type="hidden" name="wid" value="'+esc(wid)+'">'));return;}
    if((b=t.closest('[data-wr]'))){var d=b.getAttribute('data-d'),wn=d==='return'?window.prompt('What must the preparer fix?'):'';if(d==='return'&&!wn)return;
      P.req('POST',B+'/workpapers/'+encodeURIComponent(b.getAttribute('data-wr'))+'/review',{decision:d,note:wn||undefined}).then(function(){P.toast(d==='accept'?'Reviewed':'Returned');openEng(CUR.id);}).catch(toastErr);return;}
    if((b=t.closest('[data-fo]'))){openFinding(b.getAttribute('data-fo'));return;}
    if((b=t.closest('[data-rep]'))){openReport(b.getAttribute('data-rep'));return;}
    if((b=t.closest('[data-aid]'))){b.disabled=true;P.req('POST',B+'/engagements/'+encodeURIComponent(b.getAttribute('data-aid'))+'/report/ai-draft',{}).then(function(){openReport(b.getAttribute('data-aid'));}).catch(function(e){b.disabled=false;toastErr(e);});return;}
    if((b=t.closest('[data-sign]'))){P.req('POST',B+'/engagements/'+encodeURIComponent(b.getAttribute('data-sign'))+'/report/sign',{}).then(function(){P.toast('Signed - waiting for the Head of Audit');openReport(b.getAttribute('data-sign'));}).catch(toastErr);return;}
    if((b=t.closest('[data-appr]'))){P.req('POST',B+'/engagements/'+encodeURIComponent(b.getAttribute('data-appr'))+'/report/approve',{}).then(function(){P.toast('Report approved - final');openReport(b.getAttribute('data-appr'));loadEngs();}).catch(toastErr);return;}
  });
  document.addEventListener('submit',function(ev){var fm=ev.target;if(!fm.id)return;var b;
    var done=function(msg,fn){return function(){P.toast(msg);if(fn)fn();};}, err=function(e){P.msg(fm,why(e));};
    if(fm.id==='engf'){ev.preventDefault();b=P.body(fm);b.objectives=String(b.objectives||'').split(/\n+/).map(function(s){return s.trim();}).filter(Boolean);
      P.req('POST',B+'/engagements',b).then(function(e){P.toast('Engagement '+e.id+' created');loadEngs();openEng(e.id);}).catch(err);}
    else if(fm.id==='smpf'&&CUR){ev.preventDefault();P.req('POST',B+'/engagements/'+encodeURIComponent(CUR.id)+'/samples',P.body(fm)).then(function(s){P.toast(s.id+' drawn: '+s.size+' of '+s.population_size);openEng(CUR.id);}).catch(err);}
    else if(fm.id==='wpf'&&CUR){ev.preventDefault();P.req('POST',B+'/engagements/'+encodeURIComponent(CUR.id)+'/workpapers',P.body(fm)).then(function(){P.toast('Workpaper added');openEng(CUR.id);}).catch(err);}
    else if(fm.id==='wcf'){ev.preventDefault();var wid=fm.querySelector('[name=wid]').value;P.req('POST',B+'/workpapers/'+encodeURIComponent(wid)+'/conclude',P.body(fm)).then(function(){P.toast('Concluded - waiting for review');if(CUR)openEng(CUR.id);}).catch(err);}
    else if(fm.id==='ffm'&&CUR){ev.preventDefault();P.req('POST',B+'/engagements/'+encodeURIComponent(CUR.id)+'/findings',P.body(fm)).then(function(f){P.toast(f.id+' raised (draft)');openEng(CUR.id);}).catch(err);}
    else if(fm.id.indexOf('fa-')===0){ev.preventDefault();var act=fm.id.slice(3),fid=fm.querySelector('[name=fid]').value;P.req('POST',B+'/findings/'+encodeURIComponent(fid)+'/'+act,P.body(fm)).then(function(){P.toast('Done');openFinding(fid);loadFinds();kpis();}).catch(err);}
    else if(fm.id==='sumf'){ev.preventDefault();var id=$('repid').value;P.req('POST',B+'/engagements/'+encodeURIComponent(id)+'/report/summary',P.body(fm)).then(function(){P.toast('Summary saved');openReport(id);}).catch(err);}
    else if(fm.id==='proff'){ev.preventDefault();P.req('POST',B+'/profile',P.body(fm)).then(function(p){PROF=p;P.toast('Profile saved');}).catch(err);}
  });
  // reference lists for the forms: the audit areas (from the universe) and the sample populations
  var areasP=P.req('GET',B+'/areas').then(function(a){AREAS=a;}).catch(function(e){/* the forms still open; the area list stays empty and the error shows on the brief */ void e;});
  P.req('GET',B+'/populations').then(function(p){POPS=p;}).catch(function(e){/* drawing a sample then says why */ void e;});
  try{var w=window.zybWho&&window.zybWho();if(w&&w.user)ME=w.user;}catch(e){/* no signed-in name: the lead field starts empty */}
  load();
})();
