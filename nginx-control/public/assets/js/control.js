'use strict';
/**
 * Page "Contrôle" (Nginx Control) — actions test/reload/status, redémarrage
 * complet du conteneur, statistiques CPU/RAM/réseau, et test verbose
 * (nginx -t / -T détaillé). Extrait de public/index.html dans le cadre du
 * découpage JS (voir CHANGELOG.md) — script global classique (pas un module
 * ES), chargé après le script inline principal : partage son scope global
 * (api(), fmtB(), ctrlLogs, ...).
 *
 * nginxTestVerbose() vivait par erreur sous le commentaire d'extraction de
 * la section CONFIGURATION (éditeur générique des fichiers d'intégration,
 * voir config-editor.js) — elle n'a pourtant rien à voir avec cette
 * fonctionnalité et est rapatriée ici avec le reste de Control (audit
 * refactoring, voir CHANGELOG.md).
 */
async function doAction(action){
  const el=document.getElementById('cr-'+action);
  el.className='cr show';el.textContent='En cours…';el.style.color='var(--text3)';
  let r;
  if(action==='test')r=await api('/nginx/test',{method:'POST'}).catch(e=>({error:e.message}));
  else if(action==='reload')r=await api('/nginx/reload',{method:'POST'}).catch(e=>({error:e.message}));
  else r=await api('/status').catch(e=>({error:e.message}));
  el.textContent=JSON.stringify(r,null,2);
  el.style.color=(r?.error||r?.ok===false)?'var(--red)':'var(--green)';
  ctrlLogs.unshift({ts:new Date().toLocaleTimeString('fr'),action,ok:!r?.error&&r?.ok!==false});
  document.getElementById('ctrl-log').innerHTML=ctrlLogs.slice(0,10).map(l=>`
    <div class="le ${l.ok?'lrld':'lerr'}">
      <span class="lt">${l.ts}</span>
      <span class="lty" style="color:${l.ok?'var(--green)':'var(--red)'}">${l.action}</span>
      <span class="ld">${l.ok?'✓ Succès':'✗ Erreur'}</span>
    </div>`).join('');
}

/**
 * Full container restart — distinct from reload. Causes a brief gap in
 * service, so it asks for confirmation rather than firing on a single click
 * like the other cards.
 */
async function nginxRestartContainer(){
  if (!confirm("Redemarrer completement le conteneur nginx ?\n\nCela coupe le service quelques secondes, contrairement au rechargement. Necessaire apres un changement de module comme ModSecurity.")) return;
  const el=document.getElementById('cr-restart-container');
  el.className='cr show';el.textContent='Redemarrage en cours…';el.style.color='var(--text3)';
  const r=await api('/nginx/restart-container',{method:'POST'}).catch(e=>({error:e.message}));
  el.textContent=JSON.stringify(r,null,2);
  el.style.color=(r?.error)?'var(--red)':'var(--green)';
  ctrlLogs.unshift({ts:new Date().toLocaleTimeString('fr'),action:'restart-container',ok:!r?.error});
  document.getElementById('ctrl-log').innerHTML=ctrlLogs.slice(0,10).map(l=>`
    <div class="le ${l.ok?'lrld':'lerr'}">
      <span class="lt">${l.ts}</span>
      <span class="lty" style="color:${l.ok?'var(--green)':'var(--red)'}">${l.action}</span>
      <span class="ld">${l.ok?'✓ Succès':'✗ Erreur'}</span>
    </div>`).join('');
  setTimeout(nginxLoadStats, 3000);
}

/** CPU/RAM/reseau du conteneur nginx, en un seul instantane. */
async function nginxLoadStats(){
  const errBox = document.getElementById('nginx-stats-error');
  const d = await api('/nginx/stats').catch(e=>({ok:false,error:e.message}));
  if (!d || d.ok === false) {
    errBox.style.display = '';
    errBox.textContent = 'Statistiques indisponibles : ' + (d?.error || 'agent injoignable');
    for (const id of ['ns-cpu','ns-mem','ns-net','ns-pids']) document.getElementById(id).textContent = '—';
    return;
  }
  errBox.style.display = 'none';

  document.getElementById('ns-cpu').textContent = d.cpuPercent != null
    ? `${d.cpuPercent}% (${d.onlineCpus} coeur${d.onlineCpus>1?'s':''})` : '—';

  document.getElementById('ns-mem').textContent = d.memUsedBytes != null
    ? fmtB(d.memUsedBytes) + (d.memPercent != null ? ` / ${fmtB(d.memLimitBytes)} (${d.memPercent}%)` : ' (sans limite)')
    : '—';

  document.getElementById('ns-net').textContent = `${fmtB(d.netRxBytes||0)} / ${fmtB(d.netTxBytes||0)}`;
  document.getElementById('ns-pids').textContent = d.pids != null ? String(d.pids) : '—';
}

async function nginxTestVerbose() {
  const crEl = document.getElementById('cr-test-verbose');
  const card = document.getElementById('nginx-verbose-card');
  const dump = document.getElementById('nginx-verbose-dump');
  if (crEl) crEl.innerHTML = '<span style="color:var(--text3)">...</span>';
  const d = await api('/nginx/test-verbose', { method: 'POST' }).catch(e => ({ ok: false, valid: false, error: e.message }));
  if (crEl) {
    crEl.innerHTML = d.valid
      ? '<span style="color:var(--green)">OK</span>'
      : '<span style="color:var(--red)">FAILED</span>';
  }
  if (card && dump) {
    card.style.display = '';
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    if (d.valid) {
      dump.textContent = '=== nginx -t ===\n' + (d.stdout || d.stderr || 'Configuration OK').trim();
      dump.className = 'verbose-dump';
    } else {
      var testOut = (d.stderr || d.stdout || d.error || '').trim();
      var dumpOut = d.dump ? ((d.dump.stdout || '') + (d.dump.stderr || '')).trim() : '';
      var text = '=== nginx -t ===\n' + (testOut || '(no output)') + '\n';
      if (dumpOut) text += '\n=== nginx -T (config dump) ===\n' + dumpOut;
      dump.textContent = text;
      dump.className = 'verbose-dump error';
    }
  }
}
