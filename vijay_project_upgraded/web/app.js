const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const state = { health:null, alerts:[], events:[], incidents:[], responses:[] };
let loading = false;

function apiErrorMessage(err, path='') {
  if (err?.name === 'AbortError') return `Request timed out: ${path}`;
  if (err instanceof TypeError) return `Cannot reach the Trojan Defense backend. Keep the Python server running on http://127.0.0.1:8080 and try again.`;
  return err?.message || 'Request failed';
}

async function api(path, options={}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout || 8000);
  try {
    const headers = {'Accept':'application/json','Content-Type':'application/json',...(options.headers||{})};
    const res = await fetch(path, {cache:'no-store', ...options, headers, signal:controller.signal});
    let data = {};
    try { data = await res.json(); } catch (_) {}
    if (!res.ok) throw new Error(data.message || data.error || `HTTP ${res.status}`);
    return data;
  } catch (e) {
    e.userMessage = apiErrorMessage(e, path);
    throw e;
  } finally { clearTimeout(timer); }
}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmt(v){if(!v)return '—'; const d=new Date(v); return isNaN(d)?esc(v):d.toLocaleString([], {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'});}
function sev(v){let x=String(v||'LOW').toLowerCase();return `<span class="severity ${x}">${esc(v||'LOW')}</span>`}
function status(v){let x=String(v||'OPEN').toLowerCase();return `<span class="status ${x}">${esc(v||'OPEN')}</span>`}
function idOf(x){return x?.alert_id || x?.id || x?.event_id || x?.incident_id || x?.action_id || '—';}
function toast(msg, kind='info'){const t=$('#toast'); if(!t)return; t.textContent=msg;t.dataset.kind=kind;t.classList.add('show');clearTimeout(window.__toast);window.__toast=setTimeout(()=>t.classList.remove('show'),3500);}
function emptyRow(n,msg){return `<tr><td colspan="${n}" style="padding:28px;text-align:center;color:#8995a5">${esc(msg)}</td></tr>`}
function setBusy(id,busy,label){const b=$(id);if(!b)return;b.disabled=busy;b.dataset.oldText=b.dataset.oldText||b.textContent;if(busy)b.textContent='⏳ Working…';else b.textContent=label||b.dataset.oldText;}

async function loadHealth(showError=true){
  try {
    state.health=await api('/api/health');
    $('#statEvents').textContent=state.health.total_events;
    $('#statAlerts').textContent=state.health.total_alerts;
    $('#statIncidents').textContent=state.health.total_incidents;
    $('#statResponses').textContent=state.health.total_responses;
    $('#endpointText').textContent=`Backend healthy · v${state.health.version}`;
    $('#settingHealth').textContent='Healthy'; $('#settingVersion').textContent=state.health.version;
    $('#lastSync').textContent='Last sync '+new Date().toLocaleTimeString();
    $('#healthDot')?.classList.add('live');
    return true;
  } catch(e) {
    $('#endpointText').textContent='Backend unavailable'; $('#settingHealth').textContent='Unavailable';
    if(showError) toast(e.userMessage || apiErrorMessage(e),'error');
    return false;
  }
}
async function loadAlerts(showError=false){try{state.alerts=(await api('/api/alerts?limit=100')).alerts||[];renderAlerts();renderOverview();return true;}catch(e){if(showError)toast(e.userMessage,'error');return false;}}
async function loadEvents(showError=false){try{state.events=(await api('/api/events?limit=200')).events||[];renderEvents();renderOverview();return true;}catch(e){if(showError)toast(e.userMessage,'error');return false;}}
async function loadIncidents(showError=false){try{state.incidents=(await api('/api/incidents?limit=100')).incidents||[];renderIncidents();renderOverview();return true;}catch(e){if(showError)toast(e.userMessage,'error');return false;}}
async function loadResponses(showError=false){try{state.responses=(await api('/api/responses?limit=100')).actions||[];renderResponses();renderOverview();return true;}catch(e){if(showError)toast(e.userMessage,'error');return false;}}
async function loadAll({silent=false}={}){
  if(loading)return;
  loading=true;
  const results=await Promise.all([loadHealth(!silent),loadAlerts(!silent),loadEvents(!silent),loadIncidents(!silent),loadResponses(!silent)]);
  render();
  loading=false;
  if(!silent && results.some(x=>!x)) toast('Some dashboard data could not be loaded. Check the backend status.','error');
}
function render(){renderOverview();renderAlerts();renderEvents();renderIncidents();renderResponses();}
function renderOverview(){
  $('#eventTotalBadge').textContent=`${state.events.length || state.health?.total_events || 0} events`;
  const counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  state.events.forEach(e=>{const s=String(e.severity||'LOW').toUpperCase();if(counts[s]!==undefined)counts[s]++;});
  const max=Math.max(1,...Object.values(counts));
  $('#severityChart').innerHTML=Object.entries(counts).map(([k,v])=>`<div class="bar"><i style="height:${Math.max(8,v/max*125)}px"></i><em>${v}</em><label>${k}</label></div>`).join('');
  $('#overviewAlerts').innerHTML=(state.alerts.slice(0,6).map(a=>`<tr class="click-row" data-action="details" data-kind="alert" data-id="${esc(idOf(a))}"><td><b>${esc(a.title||a.rule_name||idOf(a))}</b><br><small>${esc(idOf(a))}</small></td><td>${sev(a.severity)}</td><td><b>${esc(a.risk_score??'—')}</b>/100</td><td>${status(a.status)}</td><td>${fmt(a.created_at||a.timestamp)}</td></tr>`).join('')||emptyRow(5,'No alerts recorded yet.'));
}
function renderAlerts(){
  const sevFilter=$('#alertSeverity')?.value||'', statFilter=$('#alertStatus')?.value||'';
  const list=state.alerts.filter(a=>(!sevFilter||String(a.severity).toUpperCase()===sevFilter)&&(!statFilter||String(a.status).toUpperCase()===statFilter));
  $('#alertsTable').innerHTML=list.map(a=>{const id=esc(idOf(a));const s=String(a.status||'OPEN').toUpperCase();const controls=s==='OPEN'?`<button class="action-btn" data-action="ack" data-id="${id}">Acknowledge</button>`:s==='ACKNOWLEDGED'?`<button class="action-btn primary" data-action="resolve" data-id="${id}">Resolve</button>`:s==='RESOLVED'?`<button class="action-btn" data-action="reopen-alert" data-id="${id}">Reopen</button>`:'';return `<tr><td><button class="link-btn" data-action="details" data-kind="alert" data-id="${id}">${esc(a.title||a.rule_name||idOf(a))}</button><br><small>${esc(a.finding_id||a.rule_id||'Behavior detection')}</small></td><td>${sev(a.severity)}</td><td><b>${esc(a.risk_score??'—')}</b>/100</td><td>${esc(a.rule_name||a.rule_id||'—')}</td><td>${status(a.status)}</td><td>${fmt(a.created_at||a.timestamp)}</td><td class="actions-cell">${controls}</td></tr>`}).join('')||emptyRow(7,'No matching alerts.');
}
function renderEvents(){$('#eventsTable').innerHTML=state.events.slice(0,200).map(e=>`<tr><td>${fmt(e.timestamp)}</td><td>${esc(e.event_type||'—')}</td><td>${sev(e.severity)}</td><td>${esc(e.endpoint?.endpoint_id||e.endpoint_id||'—')}</td><td><button class="link-btn" data-action="details" data-kind="event" data-id="${esc(e.event_id||'')}">${esc(e.event_id||'—')}</button></td></tr>`).join('')||emptyRow(5,'No security events recorded.');}
function renderIncidents(){$('#incidentsTable').innerHTML=state.incidents.map(i=>{const st=String(i.status||'OPEN').toUpperCase();const next=st==='OPEN'?'INVESTIGATING':st==='INVESTIGATING'?'CONTAINED':st==='CONTAINED'?'RESOLVED':st==='RESOLVED'?'CLOSED':'INVESTIGATING';return `<tr><td><button class="link-btn" data-action="details" data-kind="incident" data-id="${esc(i.incident_id||'')}">${esc(i.title||idOf(i))}</button><br><small>${esc(i.incident_id||'')}</small></td><td>${sev(i.severity)}</td><td>${status(i.status)}</td><td>${esc(i.assigned_to||'Unassigned')}</td><td>${fmt(i.created_at)}</td><td><button class="action-btn" data-action="incident-status" data-id="${esc(i.incident_id||'')}" data-status="${next}">${st==='CLOSED'?'Reopen':next}</button></td></tr>`}).join('')||emptyRow(6,'No incidents created.');}
function renderResponses(){$('#responsesTable').innerHTML=state.responses.map(a=>{const s=String(a.status||'').toUpperCase(),id=esc(a.action_id||idOf(a));let controls='';if(s==='REQUESTED')controls=`<button class="action-btn primary" data-action="authorize" data-id="${id}">Authorize</button><button class="action-btn danger-btn" data-action="reject" data-id="${id}">Reject</button>`;else if(s==='AUTHORIZED')controls=`<button class="action-btn primary" data-action="execute" data-id="${id}">Execute</button>`;else if(s==='SUCCEEDED')controls=`<button class="action-btn" data-action="rollback" data-id="${id}">Rollback</button>`;return `<tr><td><button class="link-btn" data-action="details" data-kind="response" data-id="${id}">${id}</button></td><td>${esc(a.action_type||'—')}</td><td>${status(a.status)}</td><td><small>${esc(a.alert_id||'—')}</small></td><td>${fmt(a.requested_at||a.created_at)}</td><td class="actions-cell">${controls||'—'}</td></tr>`}).join('')||emptyRow(6,'No response actions recorded.');}

function showPage(page){$$('.page').forEach(p=>p.classList.add('hidden'));const target=$(`#page-${page}`);if(!target)return;target.classList.remove('hidden');$$('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===page));const titles={overview:'Security Overview',alerts:'Security Alerts',events:'Security Events',incidents:'Incident Management',response:'Response Center',deception:'Cyber Deception',settings:'System Configuration'};$('#pageTitle').textContent=titles[page]||'Security Overview';}

async function ackAlert(id){try{await api(`/api/alerts/${encodeURIComponent(id)}/acknowledge`,{method:'POST',body:JSON.stringify({comment:'Acknowledged from SOC dashboard'})});toast('Alert acknowledged','success');await loadAlerts();await loadHealth(false);}catch(e){toast(e.userMessage,'error');}}
async function resolveAlert(id){try{await api(`/api/alerts/${encodeURIComponent(id)}/resolve`,{method:'POST',body:JSON.stringify({comment:'Resolved from SOC dashboard'})});toast('Alert resolved','success');await loadAlerts();await loadHealth(false);}catch(e){toast(e.userMessage,'error');}}
async function reopenAlert(id){try{await api(`/api/alerts/${encodeURIComponent(id)}/status`,{method:'POST',body:JSON.stringify({status:'OPEN',comment:'Reopened from SOC dashboard'})});toast('Alert reopened','success');await loadAlerts();await loadHealth(false);}catch(e){toast(e.userMessage,'error');}}
async function changeIncidentStatus(id,next){try{await api(`/api/incidents/${encodeURIComponent(id)}/status`,{method:'POST',body:JSON.stringify({status:next})});toast(`Incident moved to ${next}`,'success');await loadIncidents();await loadHealth(false);}catch(e){toast(e.userMessage,'error');}}
async function authorizeAction(id){try{await api(`/api/responses/${encodeURIComponent(id)}/authorize`,{method:'POST',body:'{}'});toast('Response action authorized','success');await loadResponses();await loadHealth(false);}catch(e){toast(e.userMessage,'error');}}
async function rejectAction(id){const reason=prompt('Reason for rejection:','Rejected from SOC dashboard')||'Rejected by analyst';try{await api(`/api/responses/${encodeURIComponent(id)}/reject`,{method:'POST',body:JSON.stringify({reason})});toast('Response action rejected','success');await loadResponses();await loadHealth(false);}catch(e){toast(e.userMessage,'error');}}
async function executeAction(id){if(!confirm('Execute this authorized response action?'))return;try{await api(`/api/responses/${encodeURIComponent(id)}/execute`,{method:'POST',body:'{}'});toast('Response action executed','success');await loadResponses();await loadHealth(false);}catch(e){toast(e.userMessage,'error');}}
async function rollbackAction(id){if(!confirm('Rollback this response action?'))return;try{await api(`/api/responses/${encodeURIComponent(id)}/rollback`,{method:'POST',body:'{}'});toast('Response action rolled back','success');await loadResponses();await loadHealth(false);}catch(e){toast(e.userMessage,'error');}}

function openForm(title, bodyHtml, onSubmit){
  $('#formTitle').textContent=title; $('#formBody').innerHTML=bodyHtml; $('#formModal').classList.add('show');
  $('#formCancel').onclick=()=>$('#formModal').classList.remove('show');
  $('#formSubmit').onclick=async()=>{const btn=$('#formSubmit');btn.disabled=true;try{await onSubmit();$('#formModal').classList.remove('show');}catch(e){toast(e.userMessage||e.message,'error');}finally{btn.disabled=false;}};
}
async function createIncident(){
  const alertOptions=state.alerts.map(a=>`<option value="${esc(a.alert_id)}">${esc(a.title||a.alert_id)}</option>`).join('');
  openForm('Create security incident',`<label>Title<input id="incidentTitle" value="Suspicious Trojan activity"></label><label>Description<textarea id="incidentDescription">Created from the Trojan Defense SOC dashboard</textarea></label><label>Severity<select id="incidentSeverity"><option>CRITICAL</option><option selected>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label><label>Link alert (optional)<select id="incidentAlert"><option value="">None</option>${alertOptions}</select></label>`,async()=>{
    const title=$('#incidentTitle').value.trim();if(!title){toast('Incident title is required','error');return;}const alertId=$('#incidentAlert').value;const body={title,description:$('#incidentDescription').value.trim(),severity:$('#incidentSeverity').value};if(alertId)body.alert_ids=[alertId];
    const result=await api('/api/incidents',{method:'POST',body:JSON.stringify(body)});toast(`Incident created: ${result.incident.incident_id}`,'success');showPage('incidents');await loadIncidents();await loadHealth(false);
  });
}
async function requestResponse(){
  const alertOptions=state.alerts.map(a=>`<option value="${esc(a.alert_id)}">${esc(a.title||a.alert_id)}</option>`).join('');
  openForm('Request defensive response',`<label>Response type<select id="responseType"><option value="HOST_ISOLATION">Host isolation</option><option value="NETWORK_BLOCK">Network block</option><option value="FILE_QUARANTINE">File quarantine</option><option value="PROCESS_TERMINATION">Process termination</option></select></label><label>Related alert (optional)<select id="responseAlert"><option value="">None</option>${alertOptions}</select></label><div class="form-note">Dashboard demo mode uses safe simulated targets. Real file/process actions still require a verified target.</div>`,async()=>{
    const type=$('#responseType').value, alertId=$('#responseAlert').value;let target={source:'dashboard',demo:true};if(type==='NETWORK_BLOCK')target={source:'dashboard',demo:true,remote_ip:'203.0.113.10',direction:'out'};else if(type==='FILE_QUARANTINE')target={source:'dashboard',demo:true,path:'runtime/quarantine/demo-sample.txt'};else if(type==='PROCESS_TERMINATION')target={source:'dashboard',demo:true,pid:4242,process_name:'suspicious_demo_process'};
    const body={action_type:type,target_params:target};if(alertId)body.alert_id=alertId;const result=await api('/api/responses',{method:'POST',body:JSON.stringify(body)});toast(`Response requested: ${result.action.action_id}`,'success');showPage('response');await loadResponses();await loadHealth(false);
  });
}
async function simulateTelemetry(){
  setBusy('#simulateTelemetryBtn',true);
  try{const result=await api('/api/demo/test-detection',{method:'POST',body:'{}'});toast(result.alert?`Detection created · ${result.alert.severity} alert created`:'Detection event created','success');await Promise.all([loadEvents(),loadAlerts(),loadHealth(false)]);showPage('alerts');}
  catch(e){toast(e.userMessage||e.message,'error');}
  finally{setBusy('#simulateTelemetryBtn',false,'▶ Test detection');}
}
async function showDetails(kind,id){try{const endpoint={alert:`/api/alerts/${encodeURIComponent(id)}`,event:`/api/events/${encodeURIComponent(id)}`,incident:`/api/incidents/${encodeURIComponent(id)}`,response:`/api/responses/${encodeURIComponent(id)}`}[kind];const data=await api(endpoint);const payload=data.alert||data.event||data.incident||data.action||data;$('#modalTitle').textContent=`${kind[0].toUpperCase()+kind.slice(1)} details`;$('#modalBody').innerHTML=`<pre>${esc(JSON.stringify(payload,null,2))}</pre>`;$('#detailsModal').classList.add('show');}catch(e){toast(e.userMessage,'error');}}

document.addEventListener('click',e=>{const nav=e.target.closest('.nav-item');if(nav?.dataset.page){showPage(nav.dataset.page);return;}const link=e.target.closest('[data-page-link]');if(link){showPage(link.dataset.pageLink);return;}const btn=e.target.closest('[data-action]');if(!btn)return;const action=btn.dataset.action,id=btn.dataset.id;if(action==='ack')ackAlert(id);else if(action==='resolve')resolveAlert(id);else if(action==='reopen-alert')reopenAlert(id);else if(action==='authorize')authorizeAction(id);else if(action==='reject')rejectAction(id);else if(action==='execute')executeAction(id);else if(action==='rollback')rollbackAction(id);else if(action==='details')showDetails(btn.dataset.kind,id);else if(action==='incident-status')changeIncidentStatus(id,btn.dataset.status);});
$('#refreshBtn').addEventListener('click',async()=>{setBusy('#refreshBtn',true);await loadAll();setBusy('#refreshBtn',false,'↻ Refresh');});
$('#eventsRefresh').addEventListener('click',async()=>{setBusy('#eventsRefresh',true);const ok=await loadEvents(true);await loadHealth(false);setBusy('#eventsRefresh',false,'↻ Refresh events');if(ok)toast('Events refreshed','success');});
$('#alertSeverity').addEventListener('change',renderAlerts);$('#alertStatus').addEventListener('change',renderAlerts);
$('#createIncidentBtn')?.addEventListener('click',createIncident);$('#requestResponseBtn')?.addEventListener('click',requestResponse);$('#simulateTelemetryBtn')?.addEventListener('click',simulateTelemetry);
$('#checkBackendBtn')?.addEventListener('click',()=>loadHealth(true));$('#closeModal')?.addEventListener('click',()=>$('#detailsModal').classList.remove('show'));$('#detailsModal')?.addEventListener('click',e=>{if(e.target.id==='detailsModal')$('#detailsModal').classList.remove('show');});$('#formModal')?.addEventListener('click',e=>{if(e.target.id==='formModal')$('#formModal').classList.remove('show');});
loadAll();setInterval(()=>loadAll({silent:true}),15000);
