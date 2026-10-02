'use strict';
/**
 * Page "Monitoring" (sondes actives sur les vhosts) — extrait de
 * public/index.html dans le cadre du decoupage JS (voir CHANGELOG.md), meme
 * demarche que crowdsec.js/vhost-generator.js/system-info.js. Charge apres le
 * script inline principal : partage le meme scope global (api(), h(), ...),
 * pas un module ES.
 *
 * Liste + etat courant vient de GET /api/monitor (mis a jour par les sondes
 * automatiques en arriere-plan, ou par "Verifier maintenant" ->
 * POST /api/monitor/check-now). L historique detaille (checks + pannes) d
 * une cible n est charge qu a l ouverture de son panneau, pas pour toutes
 * les cibles a chaque rafraichissement.
 *
 * monitorTargetsByKey et monitorTargetRowHtml() sont aussi utilises par
 * l onglet "Monitoring" du panneau Diagnostic (voir
 * public/assets/js/diagnostic.js#renderDiagMonitoring()) — une seule carte
 * par cible, jamais dupliquee entre les deux pages.
 */
let monitorTargetsByKey = {};

function monitorUpBadge(up){
  if(up === true)  return '<span class="badge gn">UP</span>';
  if(up === false) return '<span class="badge rd">DOWN</span>';
  return '<span class="badge gy">—</span>';
}

function keyToDomId(key){
  // Un target_key contient des ":" et le chemin du fichier — pas utilisable
  // tel quel comme id DOM ; un hash simple suffit, on n a pas besoin qu il
  // soit reversible.
  let h2 = 0;
  for(let i=0;i<key.length;i++){ h2 = ((h2<<5)-h2+key.charCodeAt(i))|0; }
  return 'mk' + Math.abs(h2);
}

/** Mini-graphe up/down (barres colorees) a partir du tableau sparkline (booleens, plus ancien -> plus recent). */
function sparklineSvg(arr){
  const points = Array.isArray(arr) ? arr : [];
  if(!points.length) return '<span style="color:var(--text3);font-size:10px">—</span>';
  const w = 5, gap = 2, hgt = 16;
  const totalW = points.length * w + Math.max(0, points.length - 1) * gap;
  const bars = points.map((ok, i) => {
    const x = i * (w + gap);
    const barH = ok ? hgt * 0.55 : hgt;
    const y = hgt - barH;
    const color = ok ? '#00e87a' : '#ff4d6a';
    return `<rect x="${x}" y="${y}" width="${w}" height="${barH}" rx="1" fill="${color}"/>`;
  }).join('');
  return `<svg viewBox="0 0 ${totalW} ${hgt}" width="${totalW}" height="${hgt}" style="display:block" title="20 derniers checks">${bars}</svg>`;
}

/** Une cible surveillee (bouton Historique inclus) — reutilise telle quelle par la page Monitoring (groupee par vhost) et par l onglet Monitoring du panneau Diagnostic. */
function monitorTargetRowHtml(t){
  const domId = keyToDomId(t.key);
  const s = t.summary || {};
  // Fix (audit report, Basse/Divers dashboard) : s.last.error est le message
  // d erreur d une sonde reseau (timeout, refus de connexion, corps de
  // reponse tronque...) — potentiellement influence par ce que renvoie la
  // cible surveillee — et se retrouvait insere tel quel dans du HTML
  // (innerHTML, voir loadMonitoring()) sans jamais passer par h().
  const lastLine = s.last
    ? `${new Date(s.last.ts).toLocaleString('fr')} — ${s.last.ok ? h(s.last.status ?? 'ok') : h(s.last.error||'echec')}${s.last.ms!=null?` (${s.last.ms} ms)`:''}`
    : 'aucun check pour le moment';
  const downLine = s.downSince ? ` · <span style="color:var(--red)">en panne depuis ${new Date(s.downSince).toLocaleString('fr')}</span>` : '';
  // Rappel visuel de la regle appliquee quand elle a ete surchargee
  // (# nginx-control-monitoring-valid-http-code) — sans ca, un code "up"
  // inattendu (ex: 404 accepte volontairement) serait facilement pris pour
  // un oubli plutot qu un choix explicite.
  const ruleLine = (Array.isArray(t.validHttpCodes) && t.validHttpCodes.length)
    ? ` · <span title="Codes HTTP consideres comme UP pour cette cible (# nginx-control-monitoring-valid-http-code)">règle : ${t.validHttpCodes.map(h).join(', ')}</span>`
    : '';
  return `<div style="padding-top:8px;margin-top:8px;border-top:1px dashed var(--border)">
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      ${monitorUpBadge(s.up)}
      <span style="color:var(--text2);font-family:monospace;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%">${h(t.path)} → ${h(t.scheme)}://${h(t.host)}:${h(String(t.port))}</span>
      <span style="margin-left:auto;flex-shrink:0">${sparklineSvg(t.sparkline)}</span>
    </div>
    <div style="font-size:10px;color:var(--text3);margin-top:4px">
      ${s.uptimePct!=null ? `<b style="color:var(--text2)">${s.uptimePct}%</b> (24h, intervalle ${t.intervalSec}s) · ` : `intervalle ${t.intervalSec}s · `}${lastLine}${downLine}${ruleLine}
    </div>
    <button class="btn sm" style="margin-top:6px" onclick="toggleMonitorHistory('${t.key.replace(/'/g,"\\'")}','${domId}')">Historique</button>
    <div id="${domId}" style="display:none;margin-top:6px"></div>
  </div>`;
}

async function loadMonitoring(){
  const grid = document.getElementById('monitoring-list');
  const d = await api('/monitor').catch(()=>null);
  if(!d){ grid.innerHTML = '<div class="card" style="color:var(--red)">Erreur — impossible de lire les cibles surveillees</div>'; return; }
  const targets = d.targets || [];
  document.getElementById('monitoring-count').textContent = targets.length;
  monitorTargetsByKey = {};
  targets.forEach(t => monitorTargetsByKey[t.key] = t);

  if(!targets.length){
    grid.innerHTML = '<div class="card" style="color:var(--text3)">Aucun vhost avec le monitoring actif — ajoutez <code style="font-family:monospace"># nginx-control-monitoring: on</code> dans un bloc server{} pour l activer.</div>';
    return;
  }

  // Regroupe par fichier vhost : plusieurs cibles (locations, ou membres d un
  // pool LB/HA) du meme vhost partagent une seule card plutot qu une card par
  // cible brute — demande explicite : "regrouper dans les cards, peut etre le
  // virtualhost car tout les backends sont testes".
  const byFile = new Map();
  targets.forEach(t => { if(!byFile.has(t.file)) byFile.set(t.file, []); byFile.get(t.file).push(t); });

  grid.innerHTML = [...byFile.entries()].map(([file, ts]) => {
    const names = [...new Set(ts.flatMap(t=>t.serverNames||[]).filter(n=>n!=='_'))].map(h).join(', ') || '<span style="color:var(--text3)">(aucun server_name)</span>';
    const anyDown = ts.some(t => t.summary?.up === false);
    const anyUnknown = ts.every(t => t.summary?.up == null);
    return `<div class="card">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="font-family:monospace;font-size:13px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${names}</span>
        ${anyUnknown ? '<span class="badge gy">—</span>' : (anyDown ? '<span class="badge rd">DOWN</span>' : '<span class="badge gn">UP</span>')}
      </div>
      <div style="max-height:340px;overflow-y:auto;padding-right:2px">
        ${ts.map(monitorTargetRowHtml).join('')}
      </div>
    </div>`;
  }).join('');
}

async function checkMonitoringNow(){
  const btn = document.getElementById('monitoring-check-now-btn');
  if(btn){ btn.disabled = true; btn.textContent = '...'; }
  await api('/monitor/check-now', { method: 'POST' }).catch(()=>null);
  if(btn){ btn.disabled = false; btn.textContent = '▶ Vérifier maintenant'; }
  loadMonitoring();
}

async function toggleMonitorHistory(key, domId){
  const el = document.getElementById(domId);
  if(!el) return;
  if(el.style.display !== 'none'){ el.style.display = 'none'; return; }
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--text3);font-size:11px">Chargement…</div>';
  const d = await api('/monitor/history?key=' + encodeURIComponent(key)).catch(()=>null);
  if(!d){ el.innerHTML = '<div style="color:var(--red);font-size:11px">Erreur de chargement</div>'; return; }

  const incidentsHtml = (d.incidents||[]).length
    ? d.incidents.map(i => {
        const dur = i.endedAt ? `${Math.round((i.endedAt-i.startedAt)/60000)} min` : 'en cours';
        return `<div style="font-size:11px;color:var(--text2)">
          <span class="badge ${i.endedAt?'gy':'rd'}">${i.endedAt?'terminee':'EN COURS'}</span>
          ${new Date(i.startedAt).toLocaleString('fr')} → ${i.endedAt?new Date(i.endedAt).toLocaleString('fr'):'—'} (${dur})
          ${i.lastError ? `<span style="color:var(--text3)"> — ${h(i.lastError)}</span>` : ''}
        </div>`;
      }).join('')
    : '<div style="color:var(--text3);font-size:11px">Aucune panne enregistree</div>';

  const historyHtml = (d.history||[]).slice(0, 20).map(c =>
    `<div style="font-family:monospace;font-size:10px;color:var(--text3)">
      ${new Date(c.ts).toLocaleString('fr')} — ${c.ok ? `<span style="color:var(--green)">${c.status??'ok'}</span>` : `<span style="color:var(--red)">${h(c.error||'echec')}</span>`}${c.ms!=null?` (${c.ms} ms)`:''}
    </div>`
  ).join('') || '<div style="color:var(--text3);font-size:11px">Aucun historique</div>';

  el.innerHTML = `<div style="padding-left:12px;border-left:2px solid var(--border)">
    <div style="font-size:11px;color:var(--text3);margin-bottom:4px">Historique des pannes :</div>
    ${incidentsHtml}
    <div style="font-size:11px;color:var(--text3);margin:8px 0 4px">20 derniers checks :</div>
    ${historyHtml}
  </div>`;
}

// Carte "MONITORING" de l'Overview — rapatriée ici lors de l'audit de
// refactoring (voir CHANGELOG.md) : elle vivait par erreur dans la section
// "Page Notifications" de public/index.html, sans rapport avec les
// notifications. Appelée depuis poll() (index.html) quand l'Overview est
// la page active.

/**
 * Carte "MONITORING" de l Overview (cinquieme card du sgrid) — resume en un
 * coup d oeil l etat du monitoring continu (features/monitor.js) sans avoir
 * a ouvrir la page dediee. Directement lie a un bug remonte : une cible en
 * panne ne se voyait jamais depuis l ecran principal (rien n y refletait
 * l etat), seule la page Monitoring elle-meme le montrait. Volontairement
 * appelee seulement quand l Overview est la page active (comme
 * loadRpsChart() juste au-dessus) plutot qu a chaque poll() global : inutile
 * de sonder /api/monitor toutes les 5s pour une carte que personne ne
 * regarde.
 */
async function refreshOverviewMonitoringCard(){
  const card = document.getElementById('s-mon-card');
  const val  = document.getElementById('s-mon');
  const sub  = document.getElementById('s-mon-sub');
  if(!card || !val || !sub) return;
  const d = await api('/monitor').catch(()=>null);
  const targets = d?.targets || [];
  const downCount = targets.filter(t => t.summary?.up === false).length;
  const upCount   = targets.filter(t => t.summary?.up === true).length;
  const unknown   = targets.length - downCount - upCount;
  card.classList.toggle('re', downCount > 0);
  if(!targets.length){
    val.style.color = 'var(--text3)'; val.textContent = '—';
    sub.textContent = 'aucune cible surveillée';
  } else if(downCount > 0){
    val.style.color = 'var(--red)'; val.textContent = downCount + ' down';
    sub.textContent = upCount + ' up' + (unknown ? ` · ${unknown} —` : '');
  } else {
    val.style.color = 'var(--green)'; val.textContent = 'OK';
    sub.textContent = upCount + (upCount > 1 ? ' cibles surveillées' : ' cible surveillée');
  }
}
