'use strict';
const $=id=>document.getElementById(id);
const registering=location.pathname==='/register';
$('login-view').hidden=registering;$('register-view').hidden=!registering;
$(registering?'register-tab':'login-tab').classList.add('active');
let invitation='';
if(registering&&location.hash.startsWith('#invite=')){const value=location.hash.slice(8);if(/^[a-f0-9]{64}$/.test(value))$('invitation').value=value;history.replaceState(null,'','/register');}
const errors={login_failed:'Meno, heslo alebo kód nie sú správne. Skúste nový kód z autentifikátora.',try_later:'Príliš veľa pokusov. Skúste to neskôr.',verification_failed:'Kód nesedí. Skontrolujte čas v telefóne a skúste nový kód.',invitation_invalid_or_expired:'Pozvánka vypršala alebo nie je platná. Požiadajte o novú.',registration_already_started:'Nastavenie tejto pozvánky už začalo. Dokončite ho v pôvodnej karte, alebo počkajte 10 minút.',account_unavailable:'Toto meno nie je dostupné alebo je kapacita pilotu naplnená.',invalid_registration:'Skontrolujte pozvánku, meno a heslo s aspoň 14 znakmi.'};
async function post(path,body){const r=await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const d=await r.json();if(!r.ok)throw new Error(errors[d.error]||'Operáciu sa nepodarilo dokončiť. Skúste to znova.');return d;}
function wire(id,fn){$(id).onsubmit=async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;$('portal-message').textContent='';try{await fn();}catch(err){$('portal-message').textContent=err.message;}finally{b.disabled=false;}};}
wire('login-form',async()=>{await post('/auth/login',{username:$('username').value,password:$('password').value,code:$('code').value});$('password').value='';location.assign('/control');});
wire('register-form',async()=>{invitation=$('invitation').value.trim();const d=await post('/auth/register/start',{invitation,username:$('register-user').value.trim(),password:$('register-password').value,workspace:$('workspace-name').value});$('register-password').value='';$('register-view').hidden=true;$('enrollment-view').hidden=false;$('setup-secret').textContent=d.secret;$('enroll-account').textContent='Forensics — '+d.account;});
wire('verify-form',async()=>{await post('/auth/register/confirm',{invitation,code:$('verify-code').value});$('setup-secret').textContent='';invitation='';location.assign('/control');});
$('copy-secret').onclick=async()=>{try{await navigator.clipboard.writeText($('setup-secret').textContent);$('copy-secret').textContent='Skopírované';}catch{$('portal-message').textContent='Označte a skopírujte celý kľúč ručne.';}};

wire('oidc-factor-form',async()=>{await post('/auth/oidc/confirm',{code:$('oidc-code').value});$('oidc-code').value='';location.assign('/control');});
$('oidc-start').onclick=async()=>{const b=$('oidc-start');b.disabled=true;try{const d=await post('/auth/oidc/start',{});location.assign(d.authorization_url);}catch(err){$('portal-message').textContent=err.message;b.disabled=false;}};
if(!registering){
 fetch('/auth/methods',{credentials:'same-origin'}).then(r=>r.ok?r.json():{}).then(d=>{$('oidc-start').hidden=!d.oidc;}).catch(()=>{});
 if(location.hash==='#oidc-factor'){$('login-view').hidden=true;$('oidc-factor-view').hidden=false;history.replaceState(null,'','/portal');}
 if(location.hash==='#oidc-error'){$('portal-message').textContent='Prihlásenie cez organizáciu sa nepodarilo. Začnite znova; ak problém trvá, správca musí overiť priradenie účtu.';history.replaceState(null,'','/portal');}
}
