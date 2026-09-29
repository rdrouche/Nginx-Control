'use strict';
/**
 * Journal des événements du dashboard (page "Événements" — nav.logs) :
 * historique interne (redémarrages, erreurs, etc.), distinct du LOG VIEWER
 * (public/assets/js/log-viewer.js) qui, lui, lit les fichiers de logs Nginx
 * eux-mêmes. Extrait de public/index.html (voir CHANGELOG.md).
 */
async function refreshLog(){
  const d=await api('/logs?limit=100').catch(()=>null);
  if(!d)return;
  logs=d.logs||[];
  document.getElementById('log-count').textContent=logs.length;
  document.getElementById('log-list').innerHTML=logs.length?logs.map(l=>{
    const isErr=l.type.includes('error');
    return`<div class="le ${isErr?'lerr':l.type.includes('reload')?'lrld':''}">
      <span class="lt">${timeAgo(l.timestamp)}</span>
      <span class="lty" style="color:${isErr?'var(--red)':l.type.includes('reload')?'var(--green)':'var(--blue)'}">${h(l.type)}</span>
      <span class="ld">${h(JSON.stringify(l.data))}</span>
      <span style="color:var(--text3);font-family:monospace;font-size:10px">${l.source}</span>
    </div>`;}).join(''):'<div style="color:var(--text3);font-family:\'JetBrains Mono\',monospace;font-size:12px">Aucun événement</div>';
}
async function clearLog(){
  if(!confirm('Vider le journal des événements (base de données incluse) ?')) return;
  await api('/logs/clear', { method: 'POST' }).catch(() => {});
  logs = [];
  document.getElementById('log-list').innerHTML = '';
  const totalEl = document.getElementById('log-total');
  if (totalEl) totalEl.textContent = '0 événement(s)';
}
