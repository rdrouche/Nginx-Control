'use strict';
/**
 * Page "Diagnostic" (fusion Backends + Audit) — extrait de public/index.html
 * dans le cadre du decoupage JS (voir CHANGELOG.md), meme demarche que
 * crowdsec.js/vhost-generator.js/system-info.js. Charge apres le script
 * inline principal ET apres graph.js/monitoring.js (dont il reutilise
 * respectivement renderVhostGraphSvg() et monitorTargetsByKey/
 * monitorTargetRowHtml()) : partage le meme scope global (api(), h(),
 * nginxHighlight(), fmtB(), ...), pas un module ES.
 *
 * Une grille de cards (une par vhost, resumant sa posture) qui ouvre un
 * panneau glissant a 6 onglets. Chaque onglet reutilise la logique deja
 * existante plutot que de la dupliquer : resolution des cibles (meme forme
 * {file, blockIndex, locationIndex, targetIndex}), findings statiques de
 * lib/vhost-audit.js, sonde des en-tetes (POST /api/audit/headers), schema
 * SVG (renderVhostGraphSvg, voir graph.js), et le lecteur de fichier de la
 * page Configs.
 * Best-effort: aucune donnee serveur n est jamais injectee en innerHTML sans
 * passer par h() — un server_name ou un chemin de location peut contenir des
 * caracteres qui casseraient un template litteral naif.
 */
const BACKEND_KIND_BADGE = {
  direct:     { cls: 'gy', label: 'DIRECT' },
  upstream:   { cls: 'te', label: 'UPSTREAM (LB/HA)' },
  docker:     { cls: 'bl', label: 'DOCKER' },
  variable:   { cls: 'am', label: 'VARIABLE' },
  unresolved: { cls: 'rd', label: 'NON RÉSOLU' },
};
const FINDING_BADGE = { ok: 'gn', info: 'bl', warning: 'am' };

let diagVhosts = [];
let diagMonitorTargets = [];
let diagCurrentIndex = -1;

// Cible -> {file, blockIndex, locationIndex, targetIndex, serverNameIndex?},
// remplie a l ouverture de l onglet Backends. Un chemin de fichier peut
// contenir a peu pres n importe quel caractere : passer par un index plutot
// que d injecter le chemin dans un attribut onclick evite tout probleme
// d echappement (meme principe que cfgFileMap pour la page Configuration).
let backendTargetMap = {};
let backendTargetIndex = 0;
// Meme principe pour les blocs a sonder cote en-tetes (onglet Sécurité).
let diagHeaderBlockMap = {};
let diagHeaderBlockIndex = 0;

/** Rendu d une ligne de test (bouton + zone de resultat) pour un idx donne. */
function renderCheckRow(idx, label){
  return `<div style="display:flex;align-items:center;gap:8px;margin-top:4px;font-family:monospace;font-size:11px">
    ${label}
    <button class="btn sm" id="bck-btn-${idx}" onclick="checkBackendTarget(${idx})">Tester</button>
    <span id="bck-res-${idx}"></span>
  </div><div id="bck-verbose-${idx}"></div>`;
}

/** Formatte le detail verbose (-v) : en-tetes + certificat backend si HTTPS. */
function renderVerboseDetails(v){
  if(!v) return '';
  const hdrRows = (obj) => Object.entries(obj||{}).map(([k,val])=>`<div>${h(k)}: ${h(Array.isArray(val)?val.join(', '):String(val))}</div>`).join('');
  const tls = v.tls ? `<div style="margin-top:6px;padding-top:6px;border-top:1px dashed var(--border)">
      <div style="color:var(--text3)">Certificat backend (non verifie — -k) :</div>
      <div>subject: ${h(v.tls.subject||'—')}</div>
      <div>issuer: ${h(v.tls.issuer||'—')}</div>
      <div>validite: ${h(v.tls.validFrom||'?')} → ${h(v.tls.validTo||'?')}</div>
      ${v.tls.selfSigned ? '<div style="color:var(--amber)">auto-signe</div>' : ''}
    </div>` : '';
  return `<details style="margin-top:4px;font-family:monospace;font-size:10px;color:var(--text3)">
    <summary style="cursor:pointer">Détails (-v)</summary>
    <div style="margin-top:4px"><div style="color:var(--text3)">Requete :</div>${hdrRows(v.requestHeaders)}</div>
    <div style="margin-top:6px"><div style="color:var(--text3)">Reponse :</div>${hdrRows(v.responseHeaders)}</div>
    ${tls}
  </details>`;
}

async function checkBackendTarget(idx){
  const ref = backendTargetMap[idx];
  if(!ref) return;
  const btn = document.getElementById(`bck-btn-${idx}`);
  const resEl = document.getElementById(`bck-res-${idx}`);
  const verboseEl = document.getElementById(`bck-verbose-${idx}`);
  if(btn){ btn.disabled = true; btn.textContent = '...'; }
  if(resEl) resEl.textContent = '';
  if(verboseEl) verboseEl.innerHTML = '';

  const verbose = !!document.getElementById('diag-backends-verbose')?.checked;
  const d = await api('/backends/check', {
    method: 'POST',
    body: JSON.stringify({ ...ref, verbose })
  }).catch(e => ({ ok:false, error: e.message }));

  if(btn){ btn.disabled = false; btn.textContent = 'Tester'; }
  if(!resEl) return;
  if(d?.ok && d.redirectsToHttps){
    // Le backend force lui-meme le HTTPS (redirection sur une requete HTTP) —
    // comportement attendu, pas un echec : on l affiche distinctement plutot
    // que comme un simple code de statut brut.
    resEl.innerHTML = `<span class="badge bl">↪ HTTPS</span> <span style="color:var(--text3)">redirige vers ${h(d.redirectLocation||'')} (${d.ms} ms)</span>`;
  } else if(d?.ok){
    resEl.innerHTML = `<span class="badge gn">${d.status}</span> <span style="color:var(--text3)">${d.ms} ms</span>` + (d.target?.hostHeader ? ` <span style="color:var(--text3)">Host: ${h(d.target.hostHeader)}</span>` : '');
  } else {
    resEl.innerHTML = `<span class="badge rd">ÉCHEC</span> <span style="color:var(--text3)">${h(d?.error || 'erreur inconnue')}</span>`;
  }
  if(verboseEl && d?.verbose) verboseEl.innerHTML = renderVerboseDetails(d.verbose);
}

/** Pire niveau de finding statique (warning > info > ok) toutes locations confondues. */
function diagWorstLevel(v){
  const rank = { ok: 0, info: 1, warning: 2 };
  let worst = null;
  (v.serverBlocks||[]).forEach(b => (b.findings||[]).forEach(f => {
    if (worst === null || (rank[f.level]||0) > (rank[worst]||0)) worst = f.level;
  }));
  return worst;
}

/** Etat de monitoring agrege pour un vhost (tous les targets de son fichier). */
function diagMonitorStatusFor(v){
  const targets = diagMonitorTargets.filter(t => t.file === v.file);
  if (!targets.length) return { label: '—', cls: 'gy', monitored: false };
  if (targets.some(t => t.summary?.up === false)) return { label: 'DOWN', cls: 'rd', monitored: true };
  if (targets.every(t => t.summary?.up === true)) return { label: 'UP', cls: 'gn', monitored: true };
  return { label: '—', cls: 'gy', monitored: true };
}

// État du filtre de la grille Diagnostic : recherche texte (fichier +
// server_name) et filtre Tous/Actif/Désactivé, sur le même champ `enabled`
// que le reste de l'app (suffixe .conf.DISABLE — voir listVhostTargets()).
// Purement cote client : diagVhosts est deja charge en entier, pas besoin de
// retourner au serveur pour changer un filtre.
let diagStateFilter = 'all'; // 'all' | 'enabled' | 'disabled'

function setDiagStateFilter(state){
  diagStateFilter = state;
  ['all','enabled','disabled'].forEach(s => {
    const b = document.getElementById('diag-filter-'+s);
    if(b) b.classList.toggle('active', s === state);
  });
  renderDiagGrid();
}

/** vhosts (avec leur index d origine dans diagVhosts, pour que openDiagPanel(idx) reste valide) qui passent le filtre courant. */
function diagFilteredEntries(){
  const q = (document.getElementById('diag-search')?.value || '').trim().toLowerCase();
  return diagVhosts
    .map((v, idx) => ({ v, idx }))
    .filter(({v}) => diagStateFilter === 'all' || (diagStateFilter === 'enabled') === !!v.enabled)
    .filter(({v}) => {
      if(!q) return true;
      if(v.name.toLowerCase().includes(q)) return true;
      const names = (v.serverBlocks||[]).flatMap(b=>b.serverNames||[]);
      return names.some(n => n.toLowerCase().includes(q));
    });
}

function renderDiagGrid(){
  const grid = document.getElementById('diag-grid');
  const countEl = document.getElementById('diag-grid-count');
  if(!diagVhosts.length){
    grid.innerHTML = '<div class="card" style="color:var(--text3)">Aucun vhost trouvé</div>';
    if(countEl) countEl.textContent = '';
    return;
  }
  const entries = diagFilteredEntries();
  if(countEl) countEl.textContent = entries.length === diagVhosts.length ? `${diagVhosts.length}` : `${entries.length} / ${diagVhosts.length}`;
  if(!entries.length){ grid.innerHTML = '<div class="card" style="color:var(--text3)">Aucun vhost ne correspond a ce filtre</div>'; return; }

  grid.innerHTML = entries.map(({v, idx}) => {
    const worst = diagWorstLevel(v);
    const worstBadge = worst ? `<span class="badge ${FINDING_BADGE[worst]||'gy'}">${h(worst.toUpperCase())}</span>` : '<span class="badge gy">—</span>';
    const anySsl = (v.serverBlocks||[]).some(b => b.ssl);
    const anyHttp = (v.serverBlocks||[]).some(b => !b.ssl);
    const sslBadges = (anySsl?'<span class="badge gn">HTTPS</span>':'') + (anyHttp?'<span class="badge gy">HTTP</span>':'');
    const mon = diagMonitorStatusFor(v);
    const names = (v.serverBlocks||[]).flatMap(b=>b.serverNames||[]).filter(n=>n!=='_');
    const nameLabel = names.length ? h(names[0]) + (names.length>1?` <span style="color:var(--text3)">+${names.length-1}</span>`:'') : '<span style="color:var(--text3)">(aucun server_name)</span>';
    return `<div class="card diag-card" onclick="openDiagPanel(${idx})">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">
        <div class="cfg-file-icon ${v.enabled?'enabled':'disabled'}"></div>
        <span style="font-family:monospace;font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${h(v.name)}</span>
      </div>
      <div style="font-family:monospace;font-size:11px;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:8px">${nameLabel}</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px">
        ${sslBadges || '<span class="badge gy">?</span>'}
        ${worstBadge}
        ${mon.monitored ? `<span class="badge ${mon.cls}">${mon.label}</span>` : ''}
        ${!v.enabled ? '<span class="badge gy">DÉSACTIVÉ</span>' : ''}
      </div>
    </div>`;
  }).join('');
}

async function loadDiagnostic(){
  const grid = document.getElementById('diag-grid');
  const [auditData, monitorData] = await Promise.all([
    api('/audit').catch(()=>null),
    api('/monitor').catch(()=>null),
  ]);
  if(!auditData){ grid.innerHTML = '<div class="card" style="color:var(--red)">Erreur — impossible de lire les vhosts</div>'; return; }
  diagVhosts = auditData.vhosts || [];
  diagMonitorTargets = monitorData?.targets || [];
  document.getElementById('diagnostic-count').textContent = diagVhosts.length;
  renderDiagGrid();
}

function openDiagPanel(idx){
  const v = diagVhosts[idx];
  if(!v) return;
  diagCurrentIndex = idx;
  document.getElementById('diag-panel-title').textContent = v.name;
  const names = (v.serverBlocks||[]).flatMap(b=>b.serverNames||[]).filter(n=>n!=='_');
  document.getElementById('diag-panel-sub').textContent = names.join(', ') || v.file;
  document.getElementById('diag-backdrop').style.display = 'block';
  const panel = document.getElementById('diag-panel');
  panel.style.display = 'flex';
  requestAnimationFrame(()=>{ panel.style.transform = 'translateX(0)'; });
  switchDiagTab('overview');
}

function closeDiagPanel(){
  const panel = document.getElementById('diag-panel');
  panel.style.transform = 'translateX(100%)';
  document.getElementById('diag-backdrop').style.display = 'none';
  setTimeout(()=>{ if(diagCurrentIndex===-1 || panel.style.transform==='translateX(100%)') panel.style.display='none'; }, 220);
  diagCurrentIndex = -1;
}

function switchDiagTab(tab){
  document.querySelectorAll('.diag-tab').forEach(b=>b.classList.toggle('active', b.dataset.tab===tab));
  const v = diagVhosts[diagCurrentIndex];
  const body = document.getElementById('diag-panel-body');
  if(!v){ body.innerHTML=''; return; }
  if(tab==='overview')   return renderDiagOverview(v, body);
  if(tab==='backends')   return renderDiagBackends(v, body);
  if(tab==='security')   return renderDiagSecurity(v, body);
  if(tab==='monitoring') return renderDiagMonitoring(v, body);
  if(tab==='graph')      return renderDiagGraph(v, body);
  if(tab==='conf')       return renderDiagConf(v, body);
}

function renderDiagOverview(v, body){
  const mon = diagMonitorStatusFor(v);
  const rank = { ok: 0, info: 1, warning: 2 };
  const blocksHtml = (v.serverBlocks||[]).map((b, bi) => {
    const names = b.serverNames.length ? b.serverNames.map(h).join(', ') : '<span style="color:var(--text3)">(aucun server_name)</span>';
    const sslBadge = b.ssl ? '<span class="badge gn">HTTPS</span>' : '<span class="badge gy">HTTP</span>';
    const worstInBlock = (b.findings||[]).reduce((w,f)=> (w===null || (rank[f.level]||0) > (rank[w]||0)) ? f.level : w, null);
    return `<div style="margin-top:${bi>0?'12px':'0'};padding-top:${bi>0?'10px':'0'};${bi>0?'border-top:1px dashed var(--border)':''}">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="font-family:monospace;font-size:12px;font-weight:600">${names}</span>
        ${sslBadge}
        ${worstInBlock ? `<span class="badge ${FINDING_BADGE[worstInBlock]||'gy'}">${h(worstInBlock.toUpperCase())}</span>` : ''}
      </div>
      <div style="font-family:monospace;font-size:10px;color:var(--text3);margin-top:4px">${(b.listen||[]).map(h).join(' · ')||'—'}</div>
    </div>`;
  }).join('') || '<div style="color:var(--text3);font-family:monospace;font-size:11px">Aucun bloc server</div>';

  body.innerHTML = `
    <div style="font-family:monospace;font-size:11px;color:var(--text3);margin-bottom:10px">${h(v.file)}</div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px">
      ${mon.monitored ? `<span class="badge ${mon.cls}">Monitoring : ${h(mon.label)}</span>` : '<span class="badge gy">Monitoring non actif</span>'}
      ${!v.enabled ? '<span class="badge gy">DÉSACTIVÉ</span>' : '<span class="badge gn">ACTIVÉ</span>'}
    </div>
    ${blocksHtml}
  `;
}

function renderDiagBackends(v, body){
  backendTargetMap = {}; backendTargetIndex = 0;
  // Un bloc server{} en listen 80 qui ne fait que rediriger vers son pendant
  // HTTPS (return/rewrite ... https://, sans aucune location proxy_pass) n a
  // aucun backend a tester ici — generalement le meme server_name que le
  // bloc 443 du meme fichier.
  const isRedirectOnly = (b) => b.redirectsToHttps && (!b.locations || !b.locations.length);

  const blocksHtml = (v.serverBlocks||[]).map((b, bi) => {
    if (isRedirectOnly(b)) return '';
    const names = b.serverNames.length ? b.serverNames.map(h).join(', ') : '<span style="color:var(--text3)">(aucun server_name)</span>';
    const sslBadge = b.ssl ? '<span class="badge gn">HTTPS</span>' : '<span class="badge gy">HTTP</span>';
    // server_name reels (hors le fourre-tout "_"), avec leur index d origine
    // dans b.serverNames — c est cet index, jamais le nom lui-meme, qui est
    // envoye au serveur pour choisir quel domaine tester.
    const realNames = b.serverNames.map((n,ni)=>({n,ni})).filter(o=>o.n!=='_');
    const locsHtml = (b.locations||[]).length
      ? b.locations.map((loc, li) => {
          const kb = BACKEND_KIND_BADGE[loc.kind] || BACKEND_KIND_BADGE.unresolved;
          const targetsHtml = (loc.targets||[]).map((t, ti) => {
            const targetLabel = `<span style="color:var(--text2)">${h(t.scheme)}://${h(t.host)}:${h(String(t.port))}</span>`;
            if(realNames.length > 1){
              // Plusieurs domaines sur la meme cible : le routage par nom
              // cote backend peut repondre differemment pour chacun, donc
              // un test par domaine plutot qu un seul test "au hasard".
              const rows = realNames.map(({n,ni}) => {
                const idx = backendTargetIndex++;
                backendTargetMap[idx] = { file: v.file, blockIndex: bi, locationIndex: li, targetIndex: ti, serverNameIndex: ni };
                return renderCheckRow(idx, `${targetLabel} <span style="color:var(--text3)">Host: ${h(n)}</span>`);
              }).join('');
              return `<div style="margin-top:4px">${rows}</div>`;
            }
            const idx = backendTargetIndex++;
            backendTargetMap[idx] = { file: v.file, blockIndex: bi, locationIndex: li, targetIndex: ti };
            return renderCheckRow(idx, targetLabel);
          }).join('');
          return `<div style="margin-top:8px;padding-left:12px;border-left:2px solid var(--border)">
            <div style="display:flex;align-items:center;gap:8px;font-family:monospace;font-size:12px">
              <span style="color:var(--text2)">${h(loc.path)}</span>
              <span class="badge ${kb.cls}">${kb.label}</span>
            </div>
            ${loc.raw ? `<div style="font-family:monospace;font-size:10px;color:var(--text3);margin-top:2px">proxy_pass ${h(loc.raw)};</div>` : ''}
            ${targetsHtml}
          </div>`;
        }).join('')
      : '<div style="color:var(--text3);font-family:monospace;font-size:11px;margin-top:8px">Aucune location avec proxy_pass</div>';
    return `<div style="margin-top:${bi>0?'16px':'8px'};padding-top:${bi>0?'12px':'0'};${bi>0?'border-top:1px dashed var(--border)':''}">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-family:monospace;font-size:12px;font-weight:600">${names}</span>
        ${sslBadge}
      </div>
      ${locsHtml}
    </div>`;
  }).join('') || '<div style="color:var(--text3);font-family:monospace;font-size:11px">Aucun bloc server</div>';

  body.innerHTML = `
    <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text2);margin-bottom:10px;cursor:pointer" title="Capture les en-tetes de la requete/reponse et, en HTTPS, le certificat presente par le backend (jamais verifie — -k reste actif)">
      <input type="checkbox" id="diag-backends-verbose"><span>Verbeux (-v)</span>
    </label>
    ${blocksHtml}
  `;
}

function diagHeaderFindingsHtml(findings){
  return (findings||[]).map(f => `<div style="display:flex;gap:8px;align-items:flex-start;margin-top:4px;font-size:11px">
    <span class="badge ${FINDING_BADGE[f.level]||'gy'}" style="flex-shrink:0">${h((f.level||'').toUpperCase())}</span>
    <span style="color:var(--text2)">${h(f.message)}</span>
  </div>`).join('');
}

function renderDiagSecurity(v, body){
  diagHeaderBlockMap = {}; diagHeaderBlockIndex = 0;
  const blocksHtml = (v.serverBlocks||[]).map((b, bi) => {
    const names = b.serverNames.length ? b.serverNames.map(h).join(', ') : '<span style="color:var(--text3)">(aucun server_name)</span>';
    const sslBadge = b.ssl ? '<span class="badge gn">HTTPS</span>' : '<span class="badge gy">HTTP</span>';
    const findingsHtml = (b.findings||[]).map(f => {
      const cls = FINDING_BADGE[f.level] || 'gy';
      return `<div style="display:flex;gap:8px;align-items:flex-start;margin-top:4px;font-size:11px">
        <span class="badge ${cls}" style="flex-shrink:0">${h((f.level||'').toUpperCase())}</span>
        <span style="color:var(--text2)">${h(f.message)}</span>
      </div>`;
    }).join('') || '<div style="color:var(--text3);font-size:11px;margin-top:4px">Aucune remarque</div>';

    // Analyse live des en-tetes : seulement possible si ce bloc a un vrai
    // server_name a sonder (POST /api/audit/headers le refuse sinon).
    const hasName = b.serverNames.some(n => n !== '_');
    let headerProbeHtml = '';
    if (hasName) {
      const hidx = diagHeaderBlockIndex++;
      diagHeaderBlockMap[hidx] = { file: v.file, blockIndex: bi };
      headerProbeHtml = `<div style="margin-top:8px">
        <button class="btn sm" id="diag-hdr-btn-${hidx}" onclick="analyzeDiagHeaders(${hidx})">Analyser les en-têtes</button>
        <div id="diag-hdr-res-${hidx}" style="margin-top:6px"></div>
      </div>`;
    }

    return `<div style="margin-top:${bi>0?'16px':'8px'};padding-top:${bi>0?'12px':'0'};${bi>0?'border-top:1px dashed var(--border)':''}">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-family:monospace;font-size:12px;font-weight:600">${names}</span>
        ${sslBadge}
      </div>
      ${findingsHtml}
      ${headerProbeHtml}
    </div>`;
  }).join('') || '<div style="color:var(--text3);font-family:monospace;font-size:11px">Aucun bloc server</div>';

  body.innerHTML = blocksHtml;
}

async function analyzeDiagHeaders(hidx){
  const ref = diagHeaderBlockMap[hidx];
  if(!ref) return;
  const btn = document.getElementById(`diag-hdr-btn-${hidx}`);
  const resEl = document.getElementById(`diag-hdr-res-${hidx}`);
  if(btn){ btn.disabled = true; btn.textContent = '...'; }
  if(resEl) resEl.innerHTML = '<div style="color:var(--text3);font-size:11px">Analyse en cours…</div>';

  const d = await api('/audit/headers', { method: 'POST', body: JSON.stringify(ref) }).catch(e => ({ error: e.message }));

  if(btn){ btn.disabled = false; btn.textContent = 'Analyser les en-têtes'; }
  if(!resEl) return;
  if(!d || (d.error && !d.findings)){ resEl.innerHTML = `<div style="color:var(--red);font-size:11px">${h(d?.error || 'Erreur inconnue')}</div>`; return; }

  // r.skipped : il n y avait rien a tester (bloc redirect-only, ou toutes
  // les locations sont statiques) — un etat normal, a ne pas confondre avec
  // un ECHEC de connexion vers une cible qui, elle, existe reellement.
  const sideStatus = (label, r) => `<div style="font-family:monospace;font-size:11px;margin-top:4px">
    <span style="color:var(--text3)">${label} :</span> ${
      r?.ok ? `<span class="badge gn">${r.status}</span> <span style="color:var(--text3)">${r.ms} ms</span>`
      : r?.skipped ? `<span class="badge gy">N/A</span> <span style="color:var(--text3)">${h(r?.error||'aucune cible a comparer')}</span>`
      : `<span class="badge rd">ÉCHEC</span> <span style="color:var(--text3)">${h(r?.error||'?')}</span>`
    }
    ${r?.verbose ? renderVerboseDetails(r.verbose) : ''}
  </div>`;

  resEl.innerHTML = `
    ${sideStatus('Reverse proxy', d.proxy)}
    ${sideStatus('Backend', d.backend)}
    <div style="margin-top:6px">${diagHeaderFindingsHtml(d.findings) || '<div style="color:var(--text3);font-size:11px">Aucune remarque</div>'}</div>
  `;
}

function renderDiagMonitoring(v, body){
  const targets = diagMonitorTargets.filter(t => t.file === v.file);
  if(!targets.length){
    body.innerHTML = '<div style="color:var(--text3);font-size:11px">Aucun bloc de ce vhost n a le monitoring actif — ajoutez <code style="font-family:monospace"># nginx-control-monitoring: on</code> dans le bloc server{} pour l activer.</div>';
    return;
  }
  targets.forEach(t => monitorTargetsByKey[t.key] = t);
  body.innerHTML = `<div class="card">${targets.map(monitorTargetRowHtml).join('')}</div>`;
}

function renderDiagGraph(v, body){
  body.innerHTML = `<div style="overflow-x:auto">${renderVhostGraphSvg(v, { big: true })}</div>`;
}

async function renderDiagConf(v, body){
  body.innerHTML = '<div style="color:var(--text3);font-size:11px">Chargement…</div>';
  const d = await api('/configs/file?path='+encodeURIComponent(v.file)).catch(()=>null);
  if(!d || d.error){ body.innerHTML = `<div style="color:var(--red);font-size:11px">${h(d?.error || 'Erreur lecture fichier')}</div>`; return; }
  const highlighted = nginxHighlight(d.content||'');
  body.innerHTML = `<div style="font-family:monospace;font-size:10px;color:var(--text3);margin-bottom:8px">${h(v.file)} · ${(d.content||'').split('\n').length} lignes · ${fmtB(d.size)}</div>
    <pre class="code" style="max-height:60vh;overflow:auto">${highlighted}</pre>`;
}
