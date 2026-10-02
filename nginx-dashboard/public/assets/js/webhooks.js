'use strict';
/**
 * Page "Webhooks" — gestion des webhooks sortants (création, test,
 * suppression). Extrait de public/index.html (voir CHANGELOG.md).
 */
async function loadWebhooks(){
  const d=await api('/webhooks').catch(()=>null);
  document.getElementById('wh-count').textContent=(d?.webhooks||[]).length;
  const el=document.getElementById('wh-list');
  if(!d?.webhooks?.length){el.innerHTML='<div style="color:var(--text3);font-family:\'JetBrains Mono\',monospace;font-size:12px">Aucun webhook</div>';return;}
  el.innerHTML=d.webhooks.map(w=>`<div class="wc">
    <div class="wi"><div class="wu" title="${h(w.url)}">${h(w.url)}</div>
    <div class="wm"><span>${h(w.description||'—')}</span><span>Events: ${h((w.events||['*']).join(', '))}</span><span>Fires: ${w.fireCount||0}</span>${w.lastFired?`<span>${timeAgo(w.lastFired)}</span>`:''}</div>
    </div><div class="wa"><button class="sm" onclick="testWH('${w.id}')">Test</button><button class="sm danger" onclick="deleteWH('${w.id}')">×</button></div></div>`).join('');
}
async function addWebhook(){
  const url=document.getElementById('wh-url').value.trim();
  if(!url)return;
  const evts=document.getElementById('wh-events').value.split(',').map(e=>e.trim()).filter(Boolean);
  const desc=document.getElementById('wh-desc').value.trim();
  await api('/webhooks',{method:'POST',body:JSON.stringify({url,description:desc,events:evts})});
  document.getElementById('wh-url').value='';document.getElementById('wh-desc').value='';
  loadWebhooks();
}
async function testWH(id){await api('/webhooks/'+id+'/test',{method:'POST'});alert('Test envoyé!');}
async function deleteWH(id){if(confirm('Supprimer ce webhook?')){await api('/webhooks/'+id,{method:'DELETE'});loadWebhooks();}}
