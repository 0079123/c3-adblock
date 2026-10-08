#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span></h1>
<button id=langbtn onclick=toggleLang() style="position:absolute;top:14px;right:18px;background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:5px 10px;cursor:pointer;font-size:13px">English</button></header><div class=wrap>
<div id=credwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px">
⚠️ <b id=credwarnT></b> <span id=credwarnB></span>
</div>
<div id=blockbar style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1></b>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30></option><option value=300 selected></option><option value=1800></option><option value=0></option></select>
<button id=pausebtn onclick=togglePause()></button></div>
<div class=cards id=sys></div>
<h2 id=hClients></h2><table id=ct><thead><tr><th id=thClient></th><th>MAC</th><th id=thBlocked></th><th id=thAllowed></th><th></th></tr></thead><tbody></tbody></table>
<h2 id=hCustom></h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button id=btnAddDom onclick=addDom()></button></div>
<table id=cl><tbody></tbody></table>
<h2 id=hUpload></h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button id=btnUpload></button> <span id=upmsg style=color:#8b949e></span></form>
<div id=uploadHint style="color:#8b949e;font-size:12px;margin-bottom:18px"></div>
<h2 id=hRemote></h2>
<div style=margin-bottom:6px><input id=uurl placeholder="https://host/blocklist.bin" size=40> <span id=lblEvery></span> <input id=uiv size=2 value=24>h
<button id=btnSave onclick=saveUpd()></button> <button id=btnFetch onclick=fetchNow()></button> <button id=btnResetUpd onclick=resetUpd()></button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px"><span id=remoteHint></span> <span id=lblLast></span> <span id=ustat>&mdash;</span></div>
<div id=upBadge style="font-size:12px;margin:-12px 0 18px"></div>
<h2 id=hFw></h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button id=btnFw></button> <span id=fwmsg style=color:#8b949e></span></form>
<div id=fwHint style="color:#8b949e;font-size:12px;margin-bottom:18px"></div>
<h2 id=hWifi></h2>
<div style=margin-bottom:18px><button id=btnForget onclick="forgetWifi()"></button></div>
</div><script>
// ---- i18n: 中文为主，保留 WiFi/SSID/OTA/MAC/RAM 等英文技术术语 ----
var L={
zh:{pause:'暂停',resume:'恢复',pause30:'30 秒',pause300:'5 分钟',pause1800:'30 分钟',pauseInf:'直到我手动恢复',
 blocking:'拦截已启用',paused:'已暂停',resumesIn:'已暂停 — {n} 秒后恢复',
 totalBlocked:'累计拦截',totalAllowed:'累计放行',blocklist:'规则库',clients:'客户端',
temp:'芯片温度',freeRam:'剩余 RAM',uptime:'运行时长',
 hClients:'客户端 (CLIENTS)',thClient:'客户端',thBlocked:'拦截',thAllowed:'放行',ban:'封禁',unban:'解封',banned:'已封禁',remove:'移除',
 noneYet:'暂无',hCustom:'自定义拦截域名 (CUSTOM BLOCKED DOMAINS)',
 btnAddDom:'加入拦截',hUpload:'规则库 — 上传 (BLOCKLIST UPLOAD)',btnUpload:'上传规则库',
 uploadHint:'用 tools/build_blocklist.py 生成 blocklist.bin 后在此上传 — 无需 USB',
 hRemote:'规则库 — 远程自动更新 (REMOTE AUTO-UPDATE)',lblEvery:'每',btnSave:'保存',btnFetch:'立即拉取',
 remoteHint:'设备会按周期拉取预编译好的 blocklist.bin（例如 GitHub release 资源）。',lblLast:'上次：',
 btnResetUpd:'恢复默认订阅',updDefault:'✓ 使用默认订阅（已启用，每 {h} 小时自动更新）',
 updCustom:'⚙ 使用自定义订阅',updOff:'⚠ 自动更新已关闭 —— 规则不会刷新',
 hFw:'固件 — OTA 升级 (FIRMWARE)',btnFw:'刷入固件',
 fwHint:'上传 .pio/build/c3/firmware.bin — 设备会校验后重启进入新固件',
 hWifi:'WiFi 设置',btnForget:'忘记 WiFi 并重启到配网页面',
 forgetConfirm:'确定要清除已保存的 WiFi 并重启进入配网页面吗？',
 updFetching:'拉取中…',updUploading:'上传中',updUpdated:'已更新',updFailed:'上传失败',
 fwFlashing:'刷写中',fwDone:'重启中，约 15 秒后重连',langBtn:'English',
 credWarnTitle:'正在使用默认密码。',credWarnBody:'secrets.h 里的 WEB_PASS/OTA_PASS 仍是占位值——任何人都能从公开仓库读到。请设置真实密码并重新烧录。'},
en:{pause:'Pause',resume:'Resume',pause30:'30s',pause300:'5 min',pause1800:'30 min',pauseInf:'until I re-enable',
 blocking:'Blocking active',paused:'Paused',resumesIn:'Paused — resumes in {n}s',
 totalBlocked:'Total blocked',totalAllowed:'Total allowed',blocklist:'Blocklist',clients:'Clients',
temp:'Temp',freeRam:'Free RAM',uptime:'Uptime',
 hClients:'CLIENTS',thClient:'Client',thBlocked:'Blocked',thAllowed:'Allowed',ban:'Ban',unban:'Unban',banned:'BANNED',remove:'remove',
 noneYet:'none yet',hCustom:'CUSTOM BLOCKED DOMAINS',
 btnAddDom:'Block domain',hUpload:'BLOCKLIST — UPLOAD',btnUpload:'Upload blocklist',
 uploadHint:'build blocklist.bin with tools/build_blocklist.py, then upload here — no USB',
 hRemote:'BLOCKLIST — REMOTE AUTO-UPDATE',lblEvery:'every',btnSave:'Save',btnFetch:'Fetch now',
 remoteHint:'device pulls a prebuilt blocklist.bin on a schedule (e.g. a GitHub release asset).',lblLast:'last:',
 btnResetUpd:'Restore default',updDefault:'✓ Using the default subscription (enabled, every {h}h)',
 updCustom:'⚙ Using a custom subscription',updOff:'⚠ Auto-update is OFF -- rules will not refresh',
 hFw:'FIRMWARE — OTA UPDATE',btnFw:'Flash firmware',
 fwHint:'upload .pio/build/c3/firmware.bin — device verifies it and reboots into it',
 hWifi:'WIFI',btnForget:'Forget WiFi and reboot into the setup portal',
 forgetConfirm:'Forget saved WiFi and reboot into the setup portal?',
 updFetching:'fetching...',updUploading:'uploading',updUpdated:'updated',updFailed:'upload failed',
 fwFlashing:'flashing',fwDone:'rebooting, reconnect in ~15s',langBtn:'中文',
 credWarnTitle:'Default credentials in use.',credWarnBody:'WEB_PASS/OTA_PASS in secrets.h are still the placeholder values — anyone can read them in the public repo. Set real values and reflash.'}};
var lang='en', blockingNow=true;
function t(k){return (L[lang]&&L[lang][k])||k}
function cur(){try{return localStorage.getItem('c3lang')}catch(e){return null}}
function applyLang(l){lang=l;try{localStorage.setItem('c3lang',l)}catch(e){}
 document.documentElement.lang=(l==='zh'?'zh-CN':'en');
 langbtn.textContent=t('langBtn');
 pausebtn.textContent=blockingNow?t('pause'):t('resume');
 pausedur.options[0].text=t('pause30');pausedur.options[1].text=t('pause300');
 pausedur.options[2].text=t('pause1800');pausedur.options[3].text=t('pauseInf');
 hClients.textContent=t('hClients');thClient.textContent=t('thClient');thBlocked.textContent=t('thBlocked');thAllowed.textContent=t('thAllowed');
 hCustom.textContent=t('hCustom');btnAddDom.textContent=t('btnAddDom');
 hUpload.textContent=t('hUpload');btnUpload.textContent=t('btnUpload');uploadHint.textContent=t('uploadHint');
 hRemote.textContent=t('hRemote');lblEvery.textContent=t('lblEvery');btnSave.textContent=t('btnSave');btnFetch.textContent=t('btnFetch');
 btnResetUpd.textContent=t('btnResetUpd');
 remoteHint.textContent=t('remoteHint');lblLast.textContent=t('lblLast');
 hFw.textContent=t('hFw');btnFw.textContent=t('btnFw');fwHint.textContent=t('fwHint');
 hWifi.textContent=t('hWifi');btnForget.textContent=t('btnForget');
 credwarnT.textContent=t('credWarnTitle');credwarnB.textContent=t('credWarnBody');
 load();}
function toggleLang(){applyLang(lang==='zh'?'en':'zh')}
function fmt(n){return n.toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// plain HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load);}
async function load(){let s=await(await fetch('/stats.json')).json();
host.textContent='@ '+s.ip;
credwarn.style.display=s.defcreds?'block':'none';
let on=s.blocking!==false;blockingNow=on;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?t('blocking'):(s.resumeIn>0?t('resumesIn').replace('{n}',s.resumeIn):t('paused'));
pausebtn.textContent=on?t('pause'):t('resume');pausedur.style.display=on?'':'none';
sys.innerHTML=[[t('totalBlocked'),fmt(s.blocked),'b'],[t('totalAllowed'),fmt(s.allowed),'a'],[t('blocklist'),fmt(s.domains),''],
[t('clients'),s.clients.length,''],['WiFi',s.rssi+' dBm',''],[t('temp'),s.temp+' °C',''],[t('freeRam'),Math.round(s.heap/1024)+' KB',''],[t('uptime'),s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>'+t('banned')+'</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban data-ip="${c.ip}">${c.banned?t('unban'):t('ban')}</button></td></tr>`).join('');
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">${t('remove')}</button></td></tr>`).join('')||`<tr><td style=color:#8b949e>${t('noneYet')}</td></tr>`;
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
ustat.textContent=s.upstat||'—';
var hasUrl=!!(s.upurl&&s.upurl.length);
upBadge.style.color=hasUrl?(s.upcustom?'#8b949e':'#3fb950'):'#f0883e';
upBadge.textContent=!hasUrl?t('updOff')
  :(s.upcustom?t('updCustom'):t('updDefault').replace('{h}',s.upiv||24));}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:CSRF_HDRS}).then(load)}
function resetUpd(){if(!confirm(t('btnResetUpd')+'?'))return;fetch('/resetupdate',{headers:CSRF_HDRS}).then(r=>r.text()).then(x=>{ustat.textContent=x;load()})}
function fetchNow(){ustat.textContent=t('updFetching');fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(x=>{ustat.textContent=x;load()})}
function forgetWifi(){if(!confirm(t('forgetConfirm')))return;fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(x=>alert(x))}
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent=t('fwFlashing')+' '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?'✓ '+t('fwDone'):'✗ '+await r.text();}
catch(_){fwmsg.textContent='✓ '+t('fwDone');}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent=t('updUploading')+' '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=r.ok?'✓ '+t('updUpdated'):'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ '+t('updFailed');}
blf.value='';setTimeout(load,600);};
applyLang(cur()||((navigator.language||'en').toLowerCase().indexOf('zh')===0?'zh':'en'));
setInterval(load,3000);
</script></body></html>)HTML";
