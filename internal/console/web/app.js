'use strict';
document.documentElement.dataset.appInitialized = 'true';
const $ = id => document.getElementById(id);
let endpoints = [], collectors = [], customerGeneration = 0;
function notify(text) { $('message').textContent = text; }
async function api(path, options = {}) {
  const response = await fetch(path, {credentials:'same-origin', ...options, headers:{'Content-Type':'application/json',...options.headers}});
  if (!response.ok) { const body = await response.json().catch(()=>({})); if(response.status===401) showLogin(); throw new Error(body.error || `HTTP ${response.status}`); }
  return response.status === 204 ? null : response.json();
}
function showLogin(){ $('welcome').hidden=false; $('workspace').hidden=true; $('logout').hidden=true; endpoints=[]; $('plan-result').hidden=true; }
function option(value,label){const el=document.createElement('option');el.value=value;el.textContent=label;return el;}
function drawEndpoints(){
 const query=$('search').value.toLocaleLowerCase(); const visible=endpoints.filter(e=>(e.hostname+' '+e.os).toLocaleLowerCase().includes(query));
 $('endpoints').replaceChildren(); $('empty').hidden=visible.length>0;
 for(const e of visible){const row=document.createElement('tr');const cell=document.createElement('td');const name=document.createElement('strong');name.textContent=e.hostname;const id=document.createElement('small');id.textContent=e.id;cell.append(name,id);row.append(cell);
 for(const value of [e.os,e.ip]){const td=document.createElement('td');td.textContent=value;row.append(td);}
 const state=document.createElement('td');const badge=document.createElement('span');badge.className='badge';badge.textContent='DEMO · NEOVERENÉ';state.append(badge);row.append(state);
 const action=document.createElement('td');const button=document.createElement('button');button.className='select-device';button.textContent='Vybrať →';button.setAttribute('aria-label','Vybrať '+e.hostname);button.onclick=()=>{$('plan-endpoint').value=e.id;$('plan').scrollIntoView({behavior:'smooth',block:'center'});};action.append(button);row.append(action);$('endpoints').append(row);}
}
async function loadCustomer(){const generation=++customerGeneration;endpoints=[];drawEndpoints();$('plan-endpoint').replaceChildren();$('count').textContent='0';$('create-plan').disabled=true;$('plan-result').hidden=true;const id=$('customer').value;
 const data=await api('/v1/customers/'+encodeURIComponent(id)+'/endpoints');if(generation!==customerGeneration)return;endpoints=data.items;$('count').textContent=String(endpoints.length);$('plan-endpoint').replaceChildren(...endpoints.map(e=>option(e.id,e.hostname)));drawEndpoints();$('create-plan').disabled=!endpoints.length;
}
function drawCollectors(){const query=$('catalog-search').value.toLocaleLowerCase();$('collectors').replaceChildren();for(const c of collectors.filter(c=>(c.id+' '+c.description).toLocaleLowerCase().includes(query))){const item=document.createElement('div');item.className='collector-item';const id=document.createElement('strong');id.textContent=c.id;const body=document.createElement('div');const title=document.createElement('p');title.textContent=c.description;const note=document.createElement('small');note.textContent='PLÁNOVANÉ · '+c.privileges+' · '+c.os_notes;body.append(title,note);item.append(id,body);$('collectors').append(item);}}
async function openWorkspace(){const data=await api('/v1/customers');$('customer').replaceChildren(...data.items.map(c=>option(c.id,c.name)));collectors=await api('/v1/collectors');drawCollectors();await loadCustomer();$('welcome').hidden=true;$('workspace').hidden=false;$('logout').hidden=false;notify('');}
$('enter').onclick=async()=>{try{$('enter').disabled=true;await api('/demo/session',{method:'POST',body:JSON.stringify({mode:'synthetic_demo'})});await openWorkspace();}catch(e){notify(e.message);}finally{$('enter').disabled=false;}};
$('logout').onclick=async()=>{try{await api('/demo/session',{method:'DELETE'});customerGeneration++;showLogin();notify('');}catch(e){notify(e.message);}};
$('customer').onchange=()=>loadCustomer().catch(e=>notify(e.message));$('search').oninput=drawEndpoints;$('catalog-search').oninput=drawCollectors;
$('plan-form').onsubmit=async event=>{event.preventDefault();const customer=$('customer').value;$('create-plan').disabled=true;try{const p=await api('/v1/job-plans',{method:'POST',body:JSON.stringify({customer_id:customer,endpoint_ids:[$('plan-endpoint').value],collector_id:$('collector').value})});if(customer!==$('customer').value)return;$('plan-result').textContent=`Návrh ${p.collector_id} pripravený. Stav: ${p.status}. Vykonanie je vypnuté. Platnosť do ${new Date(p.expires_at).toLocaleTimeString('sk-SK')}. ID: ${p.id}`;$('plan-result').hidden=false;notify('');}catch(e){notify(e.message);}finally{$('create-plan').disabled=!endpoints.length;}};
api('/v1/me').then(openWorkspace).catch(e=>{if(e.message!=='session_required')notify('Demo sa nepodarilo načítať: '+e.message);});
