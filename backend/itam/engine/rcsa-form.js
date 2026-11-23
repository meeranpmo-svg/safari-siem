// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The public RCSA response page served by engine/rcsa-collect.js under the agent gateway (/agent/rcsa/form) - no login.
 * The owner's link is /agent/rcsa/form#t=<token>: the token is in the URL FRAGMENT, so it is never sent with the page request,
 * never written to an access log and never leaves in a Referer. The script moves it to sessionStorage, strips it from the address
 * bar, and sends it to /agent/rcsa/view and /agent/rcsa/submit in the X-RCSA-Token header (same origin).
 * Strict CSP (served with the page): scripts only from this origin, no inline script, images only as data: (the company logo),
 * connections only to this origin, no framing. Every value from the server is set with textContent - nothing reaches innerHTML.
 */
const CSP = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow"><title>Risk & Control Self-Assessment</title>
<style>
:root{--ink:#14213d;--mute:#5b6576;--line:#dfe3ea;--brand:#1f3a5f;--ok:#1e7d3a;--bad:#b42318;--warn:#a15c07}
*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:var(--ink);font:15px/1.5 "Segoe UI",Arial,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:20px 16px 60px}
header{display:flex;align-items:center;gap:14px;background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:14px}
header img{max-height:48px;max-width:180px}header .org{font-weight:700;font-size:16px}header .sub{color:var(--mute);font-size:13px}
h1{font-size:21px;margin:6px 0 4px}.lead{color:var(--mute);margin:0 0 14px}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:12px}
.card h2{font-size:16px;margin:0 0 4px}.meta{color:var(--mute);font-size:13px;margin-bottom:10px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}@media(max-width:640px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
label{display:block;font-size:12px;color:var(--mute);margin-bottom:3px}
select,textarea{width:100%;font:14px "Segoe UI",Arial,sans-serif;border:1px solid #c6ccd6;border-radius:8px;padding:7px 9px;background:#fff;color:var(--ink)}
textarea{min-height:60px;resize:vertical}.full{grid-column:1/-1}
.cur{font-size:12.5px;color:var(--mute);margin-bottom:10px}.pill{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:1px 9px;border:1px solid var(--line)}
.pill.ok{color:var(--ok);border-color:#a7d7b5}
button{font:600 15px "Segoe UI",Arial,sans-serif;background:var(--brand);color:#fff;border:0;border-radius:9px;padding:11px 20px;cursor:pointer}button:disabled{opacity:.55;cursor:default}
.msg{border-radius:10px;padding:12px 14px;margin-bottom:12px;font-size:14px}.msg.err{background:#fdecea;color:var(--bad);border:1px solid #f5c2bd}.msg.ok{background:#e8f5ec;color:var(--ok);border:1px solid #a7d7b5}.msg.info{background:#eef3fb;color:var(--brand);border:1px solid #c9d8ef}
footer{color:var(--mute);font-size:12px;margin-top:18px;text-align:center}
</style></head><body><div class="wrap">
<header><img id="logo" alt="" hidden><div><div class="org" id="org">Risk & Control Self-Assessment</div><div class="sub" id="camp"></div></div></header>
<div id="msg"></div>
<div id="main" hidden><h1 id="who"></h1><p class="lead" id="lead"></p><div id="risks"></div>
<div class="card"><label for="note">Anything else the Risk team should know (optional)</label><textarea id="note" maxlength="1000"></textarea></div>
<button type="button" id="send">Submit my assessment</button></div>
<footer>This page is private to you. Your answers are reviewed by the Risk team before anything is changed.</footer>
</div><script src="/agent/rcsa/form.js"></script></body></html>`;

const js = `(function(){'use strict';
var KEY='rcsa_t',tok='',$=function(i){return document.getElementById(i);};
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=String(text);return e;}
function msg(kind,text){var m=$('msg');m.textContent='';var d=el('div','msg '+kind,text);m.appendChild(d);}
try{var h=location.hash.match(/[#&]t=([^&]+)/);if(h){tok=decodeURIComponent(h[1]);try{sessionStorage.setItem(KEY,tok);}catch(e){/* private mode: keep it in memory only */}history.replaceState(null,'',location.pathname);}else{try{tok=sessionStorage.getItem(KEY)||'';}catch(e){tok='';/* storage blocked: the link has to be opened again */}}}catch(e){tok='';/* malformed address */}
function api(method,path,body){return fetch(path,{method:method,credentials:'omit',cache:'no-store',headers:Object.assign({'X-RCSA-Token':tok},body?{'Content-Type':'application/json'}:{}),body:body?JSON.stringify(body):undefined}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){if(!r.ok)throw new Error(j.error||('Request failed ('+r.status+')'));return j;});});}
function opts(sel,cur){for(var i=1;i<=5;i++){var o=el('option',null,i+(i===1?' - very low':i===5?' - very high':''));o.value=String(i);if(cur===i)o.selected=true;sel.appendChild(o);}}
function sel(id,cur,blank){var s=document.createElement('select');s.id=id;if(blank){var b=el('option',null,'(no change)');b.value='';s.appendChild(b);}opts(s,cur);return s;}
function field(lbl,input,full){var d=el('div',full?'full':null);var l=el('label',null,lbl);l.htmlFor=input.id;d.appendChild(l);d.appendChild(input);return d;}
var RISKS=[];
function draw(v){
  if(v.brand&&v.brand.logo_url&&/^data:image\\//.test(v.brand.logo_url)){$('logo').src=v.brand.logo_url;$('logo').hidden=false;}
  if(v.brand&&v.brand.name)$('org').textContent=v.brand.name;
  $('camp').textContent=v.campaign.title+' · '+v.campaign.period+' · due '+v.campaign.due;
  $('who').textContent='Hello '+v.owner;$('lead').textContent=v.note;
  var box=$('risks');box.textContent='';RISKS=v.risks;
  if(!v.risks.length){msg('info','No risk is assigned to you in this assessment. Nothing to do - thank you.');return;}
  v.risks.forEach(function(r,i){var c=el('div','card');c.appendChild(el('h2',null,r.title));
    c.appendChild(el('div','meta',(r.category?r.category+' · ':'')+'Risk '+r.id));
    var cur=el('div','cur','Current rating: likelihood '+r.current_likelihood+', impact '+r.current_impact+(r.residual_likelihood?' · residual '+r.residual_likelihood+' x '+r.residual_impact:''));
    if(r.submitted){cur.appendChild(document.createTextNode(' '));cur.appendChild(el('span','pill ok','already submitted - you can update it'));}
    c.appendChild(cur);
    var g=el('div','grid');
    g.appendChild(field('Likelihood (1-5)',sel('l'+i,r.current_likelihood)));g.appendChild(field('Impact (1-5)',sel('m'+i,r.current_impact)));
    g.appendChild(field('Residual likelihood',sel('rl'+i,r.residual_likelihood,true)));g.appendChild(field('Residual impact',sel('rm'+i,r.residual_impact,true)));
    var ct=document.createElement('textarea');ct.id='c'+i;ct.maxLength=2000;ct.placeholder='One control per line';g.appendChild(field('Controls in place or added',ct,true));
    var cm=document.createElement('textarea');cm.id='k'+i;cm.maxLength=1000;g.appendChild(field('Comment (what changed and why)',cm,true));
    c.appendChild(g);box.appendChild(c);});
  $('main').hidden=false;}
function collect(){return RISKS.map(function(r,i){var o={risk:r.id,likelihood:Number($('l'+i).value),impact:Number($('m'+i).value)};
  var rl=$('rl'+i).value,rm=$('rm'+i).value;if(rl)o.residual_likelihood=Number(rl);if(rm)o.residual_impact=Number(rm);
  var ctl=$('c'+i).value.split('\\n').map(function(x){return x.trim();}).filter(Boolean).slice(0,20);if(ctl.length)o.controls=ctl;
  var k=$('k'+i).value.trim();if(k)o.comment=k;return o;});}
$('send').addEventListener('click',function(){var b=$('send');b.disabled=true;
  api('POST','/agent/rcsa/submit',{responses:collect(),note:$('note').value.trim()||undefined}).then(function(r){$('main').hidden=true;msg('ok',r.note+' ('+r.received+' risk(s) received)');window.scrollTo(0,0);},function(e){msg('err',e.message);b.disabled=false;window.scrollTo(0,0);});});
if(!tok){msg('err','This link is incomplete. Please open the full link from your e-mail again.');}
else api('GET','/agent/rcsa/view').then(draw,function(e){msg('err',e.message);});
})();`;

module.exports = { html, js, CSP };
