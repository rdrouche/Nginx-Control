'use strict';
/**
 * Page "GoAccess" — rapports HTML par source de log (démarrage/arrêt/
 * recréation du conteneur par vhost, logs du conteneur, pull de l'image).
 * Extrait de public/index.html (voir CHANGELOG.md).
 *
 * Ce fichier rassemble du code qui, avant cet audit de refactoring, se
 * trouvait dispersé sous PLUSIEURS commentaires d'extraction sans rapport
 * (la section "CROWDSEC" annonçait crowdsec.js mais portait en réalité tout
 * le corps de GoAccess ; pullGoAccessImage() était sous "LOG HELPERS" ;
 * gaRestart()/copyNginxFile() étaient sous "GOACCESS RESTART / OPTIONS" ;
 * gaRecreate() n'avait aucun commentaire du tout). Tout est désormais réuni
 * ici, sous son vrai nom (voir CHANGELOG.md).
 */
let gaCurrentSource = null;
let gaRefreshTimer  = null;

async function loadGoAccess() {
  const d = await api('/goaccess/sources').catch(() => null);
  const list = document.getElementById('ga-list');

  if (!d || !d.configured) {
    document.getElementById('ga-not-configured').style.display = 'block';
    document.getElementById('ga-layout').style.display = 'none';
    return;
  }
  document.getElementById('ga-not-configured').style.display = 'none';
  document.getElementById('ga-layout').style.display = 'grid';
  document.getElementById('ga-count').textContent = d.sources?.length || 0;

  // Show image warning if not ready
  let imgWarn = document.getElementById('ga-image-warn');
  if (!imgWarn) {
    imgWarn = document.createElement('div');
    imgWarn.id = 'ga-image-warn';
    imgWarn.style.cssText = 'display:none;color:var(--amber);font-family:monospace;font-size:12px;padding:8px 12px;background:var(--bg3);border-radius:var(--r);margin-bottom:12px';
    imgWarn.innerHTML = 'Image GoAccess non disponible (<code>' + (d.image||'?') + '</code>) — <button class="btn sm" onclick="pullGoAccessImage()">Pull image</button> <span id="ga-pull-status" style="margin-left:8px"></span>';
    document.getElementById('ga-layout').before(imgWarn);
  }
  imgWarn.style.display = (d.imageStatus && d.imageStatus !== 'ready') ? '' : 'none';

  if (!d.sources?.length) {
    list.innerHTML = '<div style="padding:16px;color:var(--text3);font-family:monospace;font-size:12px">Aucun fichier de log trouve dans le repertoire logs/</div>';
    return;
  }

  list.innerHTML = d.sources.map(s => {
    const running = s.container?.running;
    const typeLabel = s.type === 'consolidated' ? 'ALL' : s.type === 'vhost' ? 'VH' : 'LOG';
    const typeBadge = s.type === 'consolidated' ? 'bl' : s.type === 'vhost' ? 'gn' : 'gy';
    return `<div class="ga-source${gaCurrentSource===s.id?' active':''}" id="gas-${s.id}" onclick="selectGoAccessSource('${s.id}','${h(s.vhost)}',${running})">
      <div class="ga-dot ${running?'running':'stopped'}"></div>
      <div class="ga-source-name" title="${h(s.file)}">${h(s.vhost)}</div>
      <span class="badge ${typeBadge}" style="font-size:8px;padding:1px 5px">${typeLabel}</span>
      <div class="ga-source-size">${fmtB(s.size)}</div>
    </div>`;
  }).join('');

  // Re-select current if still valid
  if (gaCurrentSource) {
    const still = d.sources.find(s => s.id === gaCurrentSource);
    if (still) selectGoAccessSource(gaCurrentSource, still.vhost, still.container?.running);
  }
}

async function selectGoAccessSource(sourceId, vhost, running) {
  gaCurrentSource = sourceId;
  // Highlight
  document.querySelectorAll('.ga-source').forEach(el => el.classList.remove('active'));
  document.getElementById('gas-' + sourceId)?.classList.add('active');

  // Build viewer header
  const viewer = document.getElementById('ga-viewer');
  viewer.innerHTML = `
    <div class="ga-viewer-hd">
      <div class="ga-dot ${running?'running':'stopped'}"></div>
      <span class="ga-viewer-title">${h(vhost)}</span>
      <span class="badge ${running?'gn':'gy'}">${running?'En cours':'Arrete'}</span>
      ${running
        ? `<button class="btn sm danger" onclick="gaStop('${sourceId}')"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="11" height="11"><rect x="3" y="3" width="10" height="10" rx="1"/></svg>Arreter</button>
           <button class="btn sm" onclick="gaRestart('${sourceId}')" title="Restart sans perte de donnees">&#8635; Restart</button>
             <button class="btn sm" onclick="gaRecreate('${sourceId}')" title="Stop + Recreer avec options">&#9881; Recreer</button>`
        : `<button class="btn sm primary" onclick="gaStartWithOpts('${sourceId}')"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="11" height="11"><path d="M5 3l9 5-9 5V3z" fill="currentColor"/></svg>Demarrer</button>`
      }
      <button class="btn sm" onclick="gaRefresh('${sourceId}')">&#8635; Rapport</button>
      <button class="btn sm" onclick="gaShowLogs('${sourceId}')" title="Container logs">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="11" height="11"><path d="M2 4h12M2 8h8M2 12h10"/></svg>
        Logs
      </button>
    </div>
    <div id="ga-logs-panel-${sourceId}" style="display:none;font-family:monospace;font-size:11px;background:var(--bg);border-bottom:1px solid var(--border);padding:10px 14px;max-height:180px;overflow-y:auto;color:var(--text2);white-space:pre-wrap;line-height:1.6"></div>
    <div class="ga-iframe-wrap" id="ga-frame-wrap">
      ${running
        ? `<iframe id="ga-iframe" src="/api/goaccess/report?sourceId=${encodeURIComponent(sourceId)}" title="Rapport GoAccess ${h(vhost)}"></iframe>`
        : `<div class="ga-placeholder" style="height:100%">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" width="36" height="36"><path d="M3 3v18h18M7 16l4-4 4 4 4-4"/></svg>
            <span style="font-size:12px">Demarrez GoAccess pour voir le rapport</span>
          </div>`
      }
    </div>`;

  // Auto-refresh iframe every 30s
  clearInterval(gaRefreshTimer);
  // WebSocket handles real-time updates — no polling needed
}

async function gaStart(sourceId, opts) {
  if (!opts) opts = {};
  const btn = event.currentTarget;
  btn.disabled = true; btn.textContent = 'Demarrage...';
  const d = await api('/goaccess/start', { method: 'POST', body: JSON.stringify({ sourceId, persist: opts.persist !== false, geoip: !!opts.geoip }) }).catch(e => ({ error: e.message }));
  if (d?.error) { alert('Erreur: ' + d.error); btn.disabled = false; return; }
  await loadGoAccess();
}

async function gaStop(sourceId) {
  if (!confirm('Arreter GoAccess pour ce vhost ?')) return;
  clearInterval(gaRefreshTimer);
  const d = await api('/goaccess/stop', { method: 'POST', body: JSON.stringify({ sourceId }) }).catch(e => ({ error: e.message }));
  if (d?.error) { alert('Erreur: ' + d.error); return; }
  gaCurrentSource = null;
  await loadGoAccess();
}

async function gaShowLogs(sourceId) {
  const panel = document.getElementById('ga-logs-panel-' + sourceId);
  if (!panel) return;
  if (panel.style.display !== 'none') { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  panel.textContent = 'Loading container logs...';
  const d = await api('/goaccess/logs?sourceId=' + encodeURIComponent(sourceId) + '&tail=80').catch(e => ({ error: e.message }));
  if (d?.error) {
    panel.style.color = 'var(--red)';
    panel.textContent = 'Error: ' + d.error;
    return;
  }
  panel.style.color = 'var(--text2)';
  if (!d.logs?.length) {
    panel.textContent = 'No logs yet.';
    return;
  }
  // Colorize error lines
  panel.innerHTML = d.logs.map(l => {
    const isErr = /error|fatal|warn|EXIT|exit/i.test(l);
    const color = isErr ? 'color:var(--red)' : '';
    return `<span style="${color}">${h(l)}</span>`;
  }).join('\n');
  panel.scrollTop = panel.scrollHeight;
}

function gaRefresh(sourceId) {
  const iframe = document.getElementById('ga-iframe');
  if (iframe) {
    iframe.src = '/api/goaccess/report?sourceId=' + encodeURIComponent(sourceId) + '&_t=' + Date.now();
  }
}

async function pullGoAccessImage() {
  const warn   = document.getElementById('ga-image-warn');
  const status = document.getElementById('ga-pull-status');
  if (status) status.textContent = 'En cours...';
  const d = await api('/goaccess/pull-image', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (d?.error) {
    if (status) status.textContent = 'Erreur: ' + d.error;
    return;
  }
  if (status) status.textContent = 'Pull lancé — patienter 30s puis réessayer';
  // Poll status
  let tries = 0;
  const poll = setInterval(async () => {
    tries++;
    const s = await api('/goaccess/image-status').catch(() => null);
    if (s?.status === 'ready') {
      clearInterval(poll);
      if (warn) warn.style.display = 'none';
      if (status) status.textContent = '';
    } else if (s?.status === 'error' || tries > 20) {
      clearInterval(poll);
      if (status) status.textContent = s?.error || 'Échec';
    }
  }, 3000);
}

async function gaRestart(sourceId) {
  const d = await api('/goaccess/restart', { method: 'POST', body: JSON.stringify({ sourceId }) }).catch(e => ({ error: e.message }));
  if (d && d.error) { alert('Erreur restart: ' + d.error); return; }
  setTimeout(() => loadGoAccess(), 2000);
}

let gaStartTargetId = null;

function gaStartWithOpts(sourceId) {
  gaStartTargetId = sourceId;
  const modal = document.getElementById('ga-start-modal');
  if (modal) {
    modal.style.display = 'flex';
  } else {
    // Fallback if modal not found
    gaStart(sourceId, { persist: true, geoip: false });
  }
}

let gaStartMode = 'start';

async function gaConfirmStart() {
  const persist = document.getElementById('ga-opt-persist')?.checked !== false;
  const geoip   = document.getElementById('ga-opt-geoip')?.checked === true;
  document.getElementById('ga-start-modal').style.display = 'none';
  // Reset modal title
  const title = document.querySelector('#ga-start-modal .ctitle');
  if (title) title.textContent = 'Demarrer GoAccess';
  if (!gaStartTargetId) return;
  if (gaStartMode === 'recreate') {
    const d = await api('/goaccess/recreate', {
      method: 'POST',
      body: JSON.stringify({ sourceId: gaStartTargetId, persist, geoip })
    }).catch(e => ({ error: e.message }));
    if (d?.error) alert('Erreur recréation: ' + d.error);
    else setTimeout(() => loadGoAccess(), 2000);
  } else {
    await gaStart(gaStartTargetId, { persist, geoip });
  }
  gaStartMode = 'start';
}

async function gaRecreate(sourceId) {
  // Reuse the modal but call recreate endpoint
  gaStartTargetId = sourceId;
  gaStartMode = 'recreate';
  const modal = document.getElementById('ga-start-modal');
  const title = modal && modal.querySelector('.ctitle');
  if (title) title.textContent = 'Recréer GoAccess (stop + recréer)';
  if (modal) modal.style.display = 'flex';
}
