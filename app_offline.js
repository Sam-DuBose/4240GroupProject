'use strict';
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
let report = null;
let lastReport = null;
const pageInfo = {
 home:['Home','Home',''],
 overview:['Overview','Capture overview','Click a summary card for an explanation.'],
 alerts:['Security alerts','Security findings','Review the unusual activity identified by your analyzer.'],
 traffic:['Traffic analysis','Network activity','Explore destinations, ports, and protocols in this capture.'],
 console:['Analysis report','PCAP analysis report','Text version of the local analysis.'],
 guide:['Explanations','Learn the metrics','Clear explanations of every number and alert on your capture overview.']
};
const explain = {
 'Abnormal Connection':'An outgoing SYN targeted a port outside your script’s normal IoT ports (53, 80, 123, and 443). This is a lead to investigate, not proof of an attack.',
 'Unsafe Protocol':'An outgoing connection attempted a port associated with FTP, Telnet, or HTTP. Port numbers alone cannot verify whether a payload is encrypted.',
 'Request Burst':'The script observed more than five HTTP GET or POST requests in a 30-second window. Bursts can be legitimate or suspicious depending on the device.'
};
const palette=['#0e85c6','#47b7dd','#174f82','#8bd5ec','#7daed4'];
const num=v=>typeof v==='number'?v.toLocaleString('en-US'):String(v??'—');
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function feedback(text='',style=''){let el=$('#feedback');el.className=style?`feedback ${style}`:'feedback';el.textContent=text;$('#home-feedback').textContent=text;}
function view(which){
 const info=pageInfo[which];if(!info)return;
 const home=which==='home';
 $('#view-home').classList.toggle('hidden',!home);
 $('#dashboard-shell').classList.toggle('hidden',home);
 $$('.view').forEach(el=>el.classList.toggle('hidden',el.id!==`view-${which}`));
 $$('.menu-link').forEach(el=>{let on=el.dataset.view===which;el.classList.toggle('active',on);if(on)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');});
 $('#nav-home').classList.toggle('active',home);
 if(home)$('#nav-home').setAttribute('aria-current','page');else $('#nav-home').removeAttribute('aria-current');
 if(!home){$('#breadcrumb-view').textContent=info[0];$('#section-title').textContent=info[1];$('#section-subtitle').textContent=info[2];}
} 
function navigate(which){if(location.hash.slice(1)===which)syncRoute();else location.hash=which;}
function syncRoute(){
 const route=decodeURIComponent(location.hash.slice(1));
 if(route.startsWith('explain-')&&document.getElementById(route)){
  view('guide');$$('.guide-card').forEach(card=>card.classList.toggle('targeted',card.id===route));
  requestAnimationFrame(()=>{const node=document.getElementById(route);node.scrollIntoView({behavior:'smooth',block:'start'});node.focus({preventScroll:true});});
 }else{
  $$('.guide-card').forEach(card=>card.classList.remove('targeted'));
  view(pageInfo[route]?route:'home');
  window.scrollTo({top:0,behavior:'instant'});
 }
}
window.addEventListener('hashchange',syncRoute);
function bars(rows,key,limit=5){if(!rows.length)return '<div class="muted-placeholder">No port records available.</div>';let max=Math.max(1,...rows.map(x=>x.count));return rows.slice(0,limit).map(x=>`<div class="bar-row"><span class="bar-name">${esc(x[key])}</span><div class="bar-track"><div class="bar-fill" style="width:${100*x.count/max}%"></div></div><span class="bar-value">${num(x.count)}</span></div>`).join('');}
function preview(alerts){if(!alerts.length)return '<div class="empty-panel"><span class="empty-glyph">✓</span><strong>No alerts in this capture</strong><p>None of the current analyzer rules fired.</p></div>';return alerts.slice(0,3).map(f=>`<div class="finding-preview"><span class="finding-glyph ${f.severity}">${f.severity==='high'?'⚑':'!'}</span><div class="finding-body"><strong>${esc(f.category)}</strong><p>${esc(f.message)}</p></div><span class="severity-tag ${f.severity}">${esc(f.severity.toUpperCase())}</span></div>`).join('')+(alerts.length>3?`<button class="text-button" type="button" data-link="alerts">+ ${alerts.length-3} more findings →</button>`:'');}
function renderAlerts(){if(!report)return;let selected=$('#severity-filter').value;let rows=report.alerts.filter(a=>selected==='all'||a.severity===selected);$('#alert-counter').textContent=`${rows.length} finding${rows.length===1?'':'s'}`;$('#alerts-list').innerHTML=rows.length?rows.map(f=>`<article class="alert-card"><div class="alert-marker ${f.severity}"></div><div style="flex:1;min-width:0"><div class="alert-top"><span class="severity-tag ${f.severity}">${esc(f.severity.toUpperCase())}</span><strong>${esc(f.category)}</strong></div><p class="alert-desc">${esc(f.message)}</p><div class="alert-explain"><b>What this means: </b>${esc(explain[f.category]||'Review the supporting packets to determine whether this activity is malicious.')}</div></div></article>`).join(''):`<div class="empty-large"><div class="empty-large-icon">✓</div><h3>No matching alerts</h3><p>The selected severity filter does not contain any findings.</p></div>`;}
function table(rows,key,selector){let el=$(selector);if(!rows.length){el.innerHTML='<tr><td colspan="3" class="table-empty">No records available</td></tr>';return;}let total=rows.reduce((n,x)=>n+x.count,0)||1;el.innerHTML=rows.map(x=>`<tr><td>${esc(x[key])}</td><td>${num(x.count)}</td><td><span class="pct">${(100*x.count/total).toFixed(1)}%</span></td></tr>`).join('');}
function render(r){report=r;setLastReport(r);$('#metric-packets').textContent=num(r.packet_count);$('#metric-alerts').textContent=num(r.alerts.length);$('#metric-http').textContent=num(r.http_requests);$('#metric-duration').textContent=`${num(r.duration_seconds)}s`;$('#detail-alerts').textContent=r.alerts.length?`${r.alerts.filter(a=>a.severity==='high').length} high priority`:'No rule-based alerts';$('#overview-alerts').innerHTML=preview(r.alerts);let max=Math.max(1,...r.protocols.map(x=>x.count));$('#overview-protocols').innerHTML=r.protocols.length?r.protocols.map((x,i)=>`<div class="proto-row"><span class="proto-label">${esc(x.name)}</span><div class="proto-track"><div class="proto-fill" style="width:${100*x.count/max}%;background:${palette[i%palette.length]}"></div></div><span class="proto-count">${num(x.count)}</span></div>`).join(''):'<div class="muted-placeholder">No protocols available</div>';$('#protocol-legend').innerHTML=r.protocols.map((x,i)=>`<span class="legend-item"><span class="legend-swatch" style="background:${palette[i%palette.length]}"></span>${esc(x.name)}</span>`).join('');$('#overview-ports').innerHTML=bars(r.ports,'port',4);$('#traffic-ports').innerHTML=bars(r.ports,'port',25);$('#detail-ip').textContent=r.device_ip;$('#detail-connections').textContent=num(r.connection_attempts);$('#detail-dests').textContent=num(r.destinations.length);table(r.destinations,'address','#destinations-table');table(r.protocols,'name','#protocols-table');$('#console-output').textContent=r.raw_console;$('#console-filename').textContent='/ '+r.filename;$('#report-time').textContent='Capture analyzed';$('#capture-title').textContent='Analysis complete — drop another file any time';$('#capture-subtitle').textContent=`Analyzed ${num(r.packet_count)} packets locally in your browser`;$('#capture-file').textContent=r.filename;$('#report-pill').innerHTML=`<span class="soft-dot"></span>${esc(r.filename)}`;$('#report-pill').className='report-pill '+(r.alerts.length?'warn':'good');$('#nav-alerts').textContent=r.alerts.length;$('#nav-alerts').classList.toggle('hidden',!r.alerts.length);['#export-json','#copy-console','#save-console'].forEach(s=>$(s).disabled=false);renderAlerts();feedback();navigate('overview');}
function setLastReport(r){
 lastReport=r;
 $('#home-last').disabled=!r||document.body.classList.contains('uploading');
 $('#last-file-label').textContent=r?r.filename:'No previous analysis';
 $('#last-status').textContent=r?`Last analyzed: ${r.filename}`:'No previous analysis saved yet';
}
function openHistoryDb() {
 return new Promise((resolve,reject)=>{
   if(!('indexedDB' in window)){reject(new Error('Browser storage unavailable'));return;}
   let request=indexedDB.open('iot-traffic-monitor-offline',1);
   request.onupgradeneeded=()=>{if(!request.result.objectStoreNames.contains('reports'))request.result.createObjectStore('reports');};
   request.onsuccess=()=>resolve(request.result);
   request.onerror=()=>reject(request.error||new Error('Storage failed'));
 });
}
async function saveHistory(r) {
 try {
   const db=await openHistoryDb();
   try {await new Promise((resolve,reject)=>{let tx=db.transaction('reports','readwrite');tx.objectStore('reports').put(r,'last');tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);});}
   finally {db.close();}
 } catch (_) {
   try {localStorage.setItem('iot-last-report',JSON.stringify(r));} catch (_) { /* Private mode may block storage. */ }
 }
}
async function loadLastReport(){
 try {
  let saved=null;
  try {
    const db=await openHistoryDb();
    try {saved=await new Promise((resolve,reject)=>{const tx=db.transaction('reports','readonly');const req=tx.objectStore('reports').get('last');req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);});}
    finally {db.close();}
  } catch(_) { saved=JSON.parse(localStorage.getItem('iot-last-report')||'null'); }
  if(saved?.device_ip&&saved?.raw_console)setLastReport(saved);else setLastReport(null);
 } catch(_){setLastReport(null);$('#last-status').textContent='Previous report unavailable';}
}
function busy(on){document.body.classList.toggle('uploading',on);$$('#header-upload, #capture-browse, #home-upload').forEach(x=>x.disabled=on);$('#home-last').disabled=on||!lastReport;if(on)feedback('Analyzing capture locally in your browser…','info');}
async function fileUpload(file){
 if(!file)return;
 if(!/\.(pcap|pcapng)$/i.test(file.name)){feedback('Choose a .pcap or .pcapng file.','error');return;}
 if(file.size>50*1024*1024){feedback('Maximum file size is 50 MB.','error');return;}
 busy(true);
 try {
  // Allow the spinner to render before parsing the capture.
  await new Promise(resolve=>setTimeout(resolve,25));
  const data=await window.analyzeOfflinePCAP(file);
  render(data);
  await saveHistory(data);
 } catch(e){feedback(e.message||'Could not read this capture.','error');}
 finally {busy(false);}
}
function download(blob,name){let url=URL.createObjectURL(blob);let a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),2000);}
function stem(){return (report?.filename||'capture').replace(/\.(pcap|pcapng)$/i,'').replace(/[^\w.-]/g,'_').slice(0,80);}
$$('.menu-link').forEach(link=>link.addEventListener('click',()=>{$('#results-dropdown').open=false;}));
document.addEventListener('click',e=>{if(!$('#results-dropdown').contains(e.target))$('#results-dropdown').open=false;});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&$('#results-dropdown').open){$('#results-dropdown').open=false;$('#results-summary').focus();}});
document.addEventListener('click',event=>{let el=event.target.closest('[data-link]');if(el)navigate(el.dataset.link);});
$('#home-upload').addEventListener('click',()=>$('#file-input').click());
$('#home-last').addEventListener('click',()=>{if(lastReport)render(lastReport);});
$('#header-upload').addEventListener('click',()=>$('#file-input').click());$('#capture-browse').addEventListener('click',e=>{e.stopPropagation();$('#file-input').click();});$('#drop-zone').addEventListener('click',e=>{if(!e.target.closest('button'))$('#file-input').click();});$('#drop-zone').addEventListener('keydown',e=>{if(e.target===$('#drop-zone')&&['Enter',' '].includes(e.key)){e.preventDefault();$('#file-input').click();}});$('#file-input').addEventListener('change',e=>{fileUpload(e.target.files[0]);e.target.value='';});const drop=$('#drop-zone');['dragenter','dragover'].forEach(k=>drop.addEventListener(k,e=>{e.preventDefault();drop.classList.add('drag-over');}));['dragleave','drop'].forEach(k=>drop.addEventListener(k,e=>{e.preventDefault();drop.classList.remove('drag-over');}));drop.addEventListener('drop',e=>fileUpload(e.dataTransfer?.files?.[0]));$('#severity-filter').addEventListener('change',renderAlerts);$('#export-json').addEventListener('click',()=>{if(report)download(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}),stem()+'_report.json');});$('#save-console').addEventListener('click',()=>{if(report)download(new Blob([report.raw_console],{type:'text/plain'}),stem()+'_console.txt');});$('#copy-console').addEventListener('click',async()=>{if(!report)return;try{await navigator.clipboard.writeText(report.raw_console);$('#copy-console').textContent='Copied!';setTimeout(()=>$('#copy-console').textContent='Copy output',1200);}catch{feedback('Clipboard access blocked; use Save .txt.','error');}});

// Start on the home page and check for the most recent locally saved analysis.
syncRoute();
loadLastReport();
