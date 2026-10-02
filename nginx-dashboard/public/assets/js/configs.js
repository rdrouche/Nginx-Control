'use strict';
/**
 * Page "Configs" (Zones, Upstreams, arborescence des fichiers Nginx) et
 * tout ce qui s'y rattache : coloration syntaxique, création de nouveau
 * fichier (ALLOW_CREATE, sans Git configuré), édition inline (ALLOW_EDIT,
 * sans Git configuré), copie du contenu. Extrait de public/index.html (voir
 * CHANGELOG.md).
 *
 * Comme goaccess.js, ce fichier réunit du code qui se trouvait dispersé
 * sous des commentaires d'extraction sans rapport avec sa vraie
 * fonctionnalité (copyConfigFile() sous "COPY FILE CONTENT",
 * copyNginxFile() sous "GOACCESS RESTART / OPTIONS", loadConfigFile() sans
 * commentaire du tout) — tout est désormais réuni ici (audit refactoring,
 * voir CHANGELOG.md). À ne pas confondre avec public/assets/js/
 * config-editor.js, qui est un éditeur générique distinct pour les fichiers
 * d'intégration (git.yml, agents.yml, ...), pas pour les fichiers Nginx.
 */
async function loadZones(){
  const d = await api('/zones').catch(()=>null);
  const tb = document.getElementById('zones-tbody');
  if(!d?.zones?.length){tb.innerHTML='<tr><td colspan="8" style="color:var(--text3);text-align:center;padding:24px">Aucune zone VTS — activer vts-settings.conf</td></tr>';return;}
  const mx = Math.max(...d.zones.map(z=>z.requests?.total||0),1);
  tb.innerHTML=d.zones.map(z=>{
    const req=z.requests?.total||0,pct=Math.round((req/mx)*100);
    const r2=z.responses?.['2xx']||0,r4=z.responses?.['4xx']||0,r5=z.responses?.['5xx']||0;
    return`<tr><td class="zn">${h(z.name)}</td>
      <td><div class="bc"><div class="mb"><div class="mbf" style="width:${pct}%"></div></div>${fmt(req)}</div></td>
      <td><span class="badge gn">${fmt(r2)}</span></td>
      <td><span class="badge ${r4>0?'am':'gy'}">${fmt(r4)}</span></td>
      <td><span class="badge ${r5>0?'rd':'gy'}">${fmt(r5)}</span></td>
      <td>${fmtB(z.inBytes??z.traffic?.in)}</td><td>${fmtB(z.outBytes??z.traffic?.out)}</td>
      <td><span class="badge bl">${z.requests?.processing||0}</span></td></tr>`;
  }).join('');
}

async function loadUpstreams(){
  const d = await api('/upstreams').catch(()=>null);
  const el = document.getElementById('upstreams-list');
  if(!d?.upstreams?.length){el.innerHTML='<div class="card" style="color:var(--text3)">Aucun upstream configuré avec VTS</div>';return;}
  el.innerHTML=d.upstreams.map(u=>`<div class="card"><div class="ctitle">${h(u.name)}</div>
    <table><thead><tr><th>Serveur</th><th>Requêtes</th><th>Actif</th><th>Réponse</th><th>Trafic ↓</th><th>Trafic ↑</th></tr></thead>
    <tbody>${(u.servers||[]).map(s=>`<tr>
      <td class="zn">${h(s.server||'?')}</td><td>${fmt(s.requestCounter)}</td>
      <td><span class="badge ${s.active>0?'gn':'gy'}">${s.active||0}</span></td>
      <td><span class="badge ${s.responseMsec>500?'rd':s.responseMsec>200?'am':'gy'}">${s.responseMsec||0}ms</span></td>
      <td>${fmtB(s.inBytes)}</td><td>${fmtB(s.outBytes)}</td></tr>`).join('')}
    </tbody></table></div>`).join('');
}

let configData = null;
let cfgFileMap = {};
let cfgFileIndex = 0;

function nginxHighlight(code){
  return code.split('\n').map(line=>{
    const esc = h(line);
    if(esc.trimStart().startsWith('#')) return `<span class="tok-comment">${esc}</span>`;
    // block openers/closers
    if(/^\s*[{}]\s*$/.test(line)) return `<span class="tok-block">${esc}</span>`;
    // directive line: first word = directive, rest = value
    return esc.replace(/^(\s*)(\S+)(\s+)(.+?)(;?\s*)$/, (m,indent,dir,sp,val,semi)=>{
      const vhigh = val.replace(/"([^"]*)"/g, (_,s)=>`<span class="tok-string">"${h(s)}"</span>`);
      return `${indent}<span class="tok-directive">${dir}</span>${sp}<span class="tok-value">${vhigh}</span>${semi}`;
    });
  }).join('\n');
}

async function loadConfigs(){
  cfgFileMap = {}; cfgFileIndex = 0;
  initNewConfigButton();
  configData = await api('/configs').catch(()=>null);
  const tree = document.getElementById('cfg-tree');
  if(!configData){tree.innerHTML='<div style="padding:20px;color:var(--red);font-family:\'JetBrains Mono\',monospace;font-size:12px">Erreur — volumes montés ?</div>';return;}
  const sections = [
    { key:'sites',    label:'Sites',    icon:'⬡', dir: configData.sites?.dir },
    { key:'conf',     label:'conf.d',   icon:'⬡', dir: configData.conf?.dir },
    { key:'snippets', label:'Snippets', icon:'⬡', dir: configData.snippets?.dir },
    { key:'streams',  label:'Streams',  icon:'⬡', dir: configData.streams?.dir },
  ];
  let totalFiles = 0;
  tree.innerHTML = sections.map(s=>{
    const files = configData[s.key]?.files || [];
    totalFiles += files.length;
    return `<div class="cfg-section">
      <div class="cfg-section-hd" onclick="toggleSection('${s.key}')">
        <svg viewBox="0 0 13 13" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 3h11M3 3V2a1 1 0 0 1 1-1h5a1 1 0 0 1 1 1v1M5 6h3M2 3v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V3"/></svg>
        ${s.label}
        <span class="cfg-section-tag" id="tag-${s.key}">${files.length} fichiers</span>
        <svg class="chv" id="chv-${s.key}" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="2,4 6,8 10,4"/></svg>
      </div>
      <div class="cfg-files" id="sec-${s.key}">
        ${files.length===0
          ? `<div class="cfg-file" style="cursor:default;color:var(--text3)">Aucun fichier</div>`
          : files.map((f,fi)=>{const idx=cfgFileIndex++;cfgFileMap[idx]=f;f._section=s.key;return`<div class="cfg-file" id="cfi-${idx}" onclick="openFile(${idx})">
              <div class="cfg-file-icon ${f.enabled?'enabled':'disabled'}"></div>
              ${h(f.name)}
              <span style="margin-left:auto;font-size:9px;color:var(--text3)">${fmtB(f.size)}</span>
            </div>`;}).join('')}
      </div>
    </div>`;
  }).join('');
  document.getElementById('conf-count').textContent=totalFiles;
  cfgFilterFiles();
}

// Filtre par nom : masque les fichiers non correspondants, déplie les sections
// qui ont des résultats, met à jour le compteur de chaque section.
function cfgFilterFiles(){
  const q=((document.getElementById('cfg-search')||{}).value||'').trim().toLowerCase();
  ['sites','conf','snippets','streams'].forEach(key=>{
    const sec=document.getElementById('sec-'+key);
    if(!sec) return;
    const rows=[...sec.querySelectorAll('.cfg-file[id^="cfi-"]')];
    let n=0;
    rows.forEach(r=>{
      const ok=!q||r.textContent.toLowerCase().includes(q);
      r.style.display=ok?'':'none';
      if(ok) n++;
    });
    const tag=document.getElementById('tag-'+key);
    if(tag) tag.textContent=q?(n+' / '+rows.length):(rows.length+' fichiers');
    const box=sec.closest('.cfg-section');
    if(box) box.style.display=(q&&!n)?'none':'';
    if(q&&n){ sec.style.display=''; }
  });
}

function toggleSection(key){
  const sec=document.getElementById('sec-'+key);
  const chv=document.getElementById('chv-'+key);
  const hidden=sec.style.display==='none';
  sec.style.display=hidden?'':'none';
  chv.classList.toggle('open',!hidden);
}

async function openFile(idx){
  const f = cfgFileMap[idx];
  if (!f) return;
  const filePath = f.path, name = f.name;
  // Highlight selected
  document.querySelectorAll('.cfg-file').forEach(el=>el.classList.remove('active'));
  const el = document.getElementById('cfi-'+idx);
  if(el) el.classList.add('active');

  const viewer = document.getElementById('cfg-viewer');
  viewer.innerHTML=`<div class="cfg-viewer-header"><span class="cfg-viewer-path">${h(filePath)}</span><span class="badge gy sm">chargement…</span></div><div class="cfg-viewer-body" style="display:flex;align-items:center;justify-content:center;height:200px;color:var(--text3)">Lecture…</div>`;

  const d = await api('/configs/file?path='+encodeURIComponent(filePath)).catch(()=>null);
  if(!d||d.error){
    viewer.innerHTML=`<div class="cfg-viewer-header"><span class="cfg-viewer-path">${h(filePath)}</span></div><div class="cfg-viewer-body" style="padding:20px;color:var(--red);font-family:monospace;font-size:12px">${d?.error||'Erreur lecture fichier'}</div>`;
    return;
  }

  const isDisabled = name.endsWith('.DISABLE');
  const lines    = (d.content||'').split('\n').length;
  const rawContent = d.content||'';
  const highlighted = nginxHighlight(rawContent);
  viewer.innerHTML=`
    <div class="cfg-viewer-header">
      <span class="cfg-viewer-path">${h(filePath)}</span>
      <span class="badge ${isDisabled?'gy':'gn'}">${isDisabled?'DÉSACTIVÉ':'ACTIF'}</span>
      <span class="badge gy">${lines} lignes</span>
      <span class="badge gy">${fmtB(d.size)}</span>
      <span style="font-family:monospace;font-size:10px;color:var(--text3)">modifié ${timeAgo(d.mtime)}</span>
      <button class="btn sm" id="cfg-copy-btn" style="margin-left:auto" onclick="copyNginxFile()">&#128203; Copier</button>
      <button class="btn sm" id="cfg-edit-btn" style="display:none" onclick="toggleCfgEdit()">&#9998; Editer</button>
    </div>
    <div class="cfg-viewer-body"><pre class="code ${isDisabled?'tok-disabled':''}" id="cfg-pre">${highlighted}</pre></div>`;
  // Store raw content for copy
  viewer._rawContent = rawContent;
  viewer._filePath    = filePath;
  // Init inline edit button visibility
  initInlineEdit();
}

function copyConfigFile() {
  const ta = document.getElementById('cfg-file-content') || document.getElementById('file-content');
  if (!ta) return;
  copyToClipboard(ta.value).then(ok => copyFeedback('cfg-copy-btn', ok));
}

function copyNginxFile() {
  const viewer = document.getElementById('cfg-viewer');
  const raw = viewer && viewer._rawContent;
  if (!raw) return;
  copyToClipboard(raw).then(ok => copyFeedback('cfg-copy-btn', ok));
}

// Re-open a file by path (used after an edit/creation is saved). cfgFileMap
// is keyed by the display index built in loadConfigs(), not by path, so this
// looks the matching entry up rather than duplicating openFile()'s fetch.
function loadConfigFile(filePath) {
  const idx = Object.keys(cfgFileMap).find(k => cfgFileMap[k].path === filePath);
  if (idx !== undefined) return openFile(Number(idx));
}

async function initNewConfigButton() {
  const d = await api('/configs/create-status').catch(() => null);
  const btn = document.getElementById('cfg-new-file-btn');
  if (btn) btn.style.display = (d && d.enabled) ? '' : 'none';
}

function openNewConfigModal() {
  document.getElementById('cfg-new-section').value = 'sites';
  document.getElementById('cfg-new-name').value = '';
  document.getElementById('cfg-new-content').value = '';
  const err = document.getElementById('cfg-new-error');
  err.style.display = 'none'; err.textContent = '';
  document.getElementById('cfg-new-modal').style.display = 'flex';
}

async function submitNewConfigFile() {
  const section = document.getElementById('cfg-new-section').value;
  const name    = document.getElementById('cfg-new-name').value.trim();
  const content = document.getElementById('cfg-new-content').value;
  const err     = document.getElementById('cfg-new-error');
  const btn     = document.getElementById('cfg-new-submit-btn');
  err.style.display = 'none';
  if (!name) { err.textContent = 'Le nom du fichier est requis.'; err.style.display = ''; return; }

  btn.disabled = true; btn.textContent = 'Test en cours...';
  const d = await api('/configs/create', {
    method: 'POST',
    body: JSON.stringify({ section, name, content })
  }).catch(e => ({ error: e.message }));
  btn.disabled = false; btn.textContent = 'Tester + Créer';

  if (d?.ok) {
    document.getElementById('cfg-new-modal').style.display = 'none';
    await loadConfigs();
    loadConfigFile(d.path);
    setTimeout(() => {
      const flash = document.createElement('div');
      const reloadMsg = d.reloaded ? ' + nginx reloaded' : (d.reloadError ? ' (reload error: ' + d.reloadError + ')' : '');
      flash.style.cssText = 'position:fixed;bottom:20px;right:20px;background:var(--green-dim);border:1px solid var(--green);color:var(--green);font-family:monospace;font-size:12px;padding:10px 16px;border-radius:var(--r2);z-index:9999';
      flash.textContent = 'Fichier créé' + reloadMsg;
      document.body.appendChild(flash);
      setTimeout(() => flash.remove(), 4000);
    }, 100);
  } else {
    // Fix (retour utilisateur v12.49.0) : d?.error valait toujours la chaine
    // generique "Config test failed" des que le test echouait, donc
    // `d?.error || d?.testResult?.output` n affichait jamais que ce libelle
    // fixe — le vrai texte de nginx -t (et le mappage du bac a sable, voir
    // features/deploy.js#testConfigEphemeral()) restait invisible pour
    // l operateur. Inversion de l ordre pour privilegier le detail.
    const errMsg = d?.testResult?.output || d?.error || 'Erreur inconnue';
    err.textContent = errMsg;
    err.style.display = '';
  }
}

let cfgEditMode = false;

async function initInlineEdit() {
  const d = await api('/configs/edit-status').catch(() => null);
  const btn = document.getElementById('cfg-edit-btn');
  if (btn && d?.enabled) btn.style.display = '';
}

function toggleCfgEdit() {
  const viewer = document.getElementById('cfg-viewer');
  if (!viewer) return;
  const pre = viewer.querySelector('.cfg-viewer-body pre');
  const editBar = viewer.querySelector('.cfg-edit-bar');
  const btn = document.getElementById('cfg-edit-btn');

  cfgEditMode = !cfgEditMode;
  if (cfgEditMode) {
    // Switch to edit mode
    const raw = viewer._rawContent || (pre ? pre.textContent : '');
    const filePath = viewer._filePath || '';
    const ta = document.createElement('textarea');
    ta.className = 'cfg-edit-area';
    ta.value = raw;
    ta.id = 'cfg-edit-textarea';
    ta.style.height = '400px';
    const body = viewer.querySelector('.cfg-viewer-body');
    if (body) { body.innerHTML = ''; body.appendChild(ta); }
    // Add save bar
    if (!editBar) {
      const bar = document.createElement('div');
      bar.className = 'cfg-edit-bar';
      bar.innerHTML = '<span style="font-family:monospace;font-size:11px;color:var(--amber)">&#9888; Test + Backup + Prod automatique avant sauvegarde</span>'
        + '<div style="margin-left:auto;display:flex;gap:8px">'
        + '<button class="btn sm" onclick="toggleCfgEdit()">Annuler</button>'
        + '<button class="btn sm primary" onclick="saveCfgEdit()">Tester + Sauvegarder</button>'
        + '</div>';
      viewer.appendChild(bar);
    }
    if (btn) btn.innerHTML = '&#10005; Annuler';
  } else {
    // Restore view mode
    const bar = viewer.querySelector('.cfg-edit-bar');
    if (bar) bar.remove();
    if (btn) btn.innerHTML = '&#9998; Editer';
    // Reload file
    if (viewer._filePath) loadConfigFile(viewer._filePath);
  }
}

async function saveCfgEdit() {
  const viewer  = document.getElementById('cfg-viewer');
  const ta      = document.getElementById('cfg-edit-textarea');
  const filePath = viewer?._filePath;
  if (!ta || !filePath) return;

  const saveBtn = viewer.querySelector('.cfg-edit-bar .btn.primary');
  if (saveBtn) saveBtn.textContent = 'Test en cours...';

  const d = await api('/configs/save', {
    method: 'POST',
    body: JSON.stringify({ path: filePath, content: ta.value })
  }).catch(e => ({ error: e.message }));

  if (d?.ok) {
    cfgEditMode = false;
    const bar = viewer.querySelector('.cfg-edit-bar');
    if (bar) bar.remove();
    const btn = document.getElementById('cfg-edit-btn');
    if (btn) btn.innerHTML = '&#9998; Editer';
    loadConfigFile(filePath);
    setTimeout(() => {
      const flash = document.createElement('div');
      const reloadMsg = d.reloaded ? ' + nginx reloaded' : (d.reloadError ? ' (reload error: ' + d.reloadError + ')' : '');
      flash.style.cssText = 'position:fixed;bottom:20px;right:20px;background:var(--green-dim);border:1px solid var(--green);color:var(--green);font-family:monospace;font-size:12px;padding:10px 16px;border-radius:var(--r2);z-index:9999';
      flash.textContent = 'Sauvegarde OK' + reloadMsg;
      document.body.appendChild(flash);
      setTimeout(() => flash.remove(), 4000);
    }, 100);
  } else {
    if (saveBtn) saveBtn.textContent = 'Tester + Sauvegarder';
    // Meme fix qu au-dessus dans submitNewConfigFile() (v12.49.0) : privilegier
    // le detail du test (nginx -t + mappage du bac a sable) au libelle
    // generique "Config test failed".
    const errMsg = d?.testResult?.output || d?.error || 'Erreur inconnue';
    alert('Erreur : ' + errMsg);
  }
}
