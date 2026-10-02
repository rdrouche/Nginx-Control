// ── CONFIGURATION (éditeur générique des fichiers d'intégration) ─────────────
// Extrait de index.html (voir CHANGELOG.md) — script global classique (pas
// un module ES), chargé après le script principal : il partage sa portée
// globale et peut donc appeler api(), t() et les autres helpers déjà
// définis à ce moment-là, exactement comme s'il était encore inline.
let cfgEditorFiles = [];
let cfgEditorCurrent = null;
let cfgEditorRevealed = false;

// Regroupement des fichiers par thème (clé inconnue -> « Autres »).
const CFGED_GROUPS = [
  ['security', ['blocklists', 'challenge', 'crowdsec', 'certbot', 'certbot-dns', 'deploy-tokens']],
  ['analysis', ['analyzer', 'goaccess', 'geoipupdate']],
  ['infra', ['error-pages', 'godns', 'docker-autoconfig', 'agents', 'git']],
];

async function initConfigEditor() {
  const d = await api('/config-editor/files').catch(() => null);
  if (!d) return;
  cfgEditorFiles = d.files || [];
  const revealBtn = document.getElementById('cfged-reveal-btn');
  if (revealBtn) revealBtn.style.display = d.canReveal ? '' : 'none';
  if (!cfgEditorCurrent && cfgEditorFiles.length) cfgEditorCurrent = cfgEditorFiles[0].key;
  cfgEditorRenderList();
  if (cfgEditorCurrent) await cfgEditorSelect(cfgEditorCurrent);
}

function cfgEditorRenderList() {
  const box = document.getElementById('cfged-tabs');
  if (!box) return;
  const q = ((document.getElementById('cfged-search') || {}).value || '').trim().toLowerCase();
  box.textContent = '';
  const known = new Set(CFGED_GROUPS.flatMap(g => g[1]));
  const groups = CFGED_GROUPS.map(([id, keys]) => [id, cfgEditorFiles.filter(f => keys.includes(f.key))]);
  groups.push(['other', cfgEditorFiles.filter(f => !known.has(f.key))]);
  let shown = 0;
  groups.forEach(([id, files]) => {
    const list = files.filter(f => !q || (f.label + ' ' + f.key).toLowerCase().includes(q));
    if (!list.length) return;
    const h = document.createElement('div');
    h.className = 'cfged-group';
    h.textContent = t('configEditor.group.' + id);
    box.appendChild(h);
    list.forEach(f => {
      const btn = document.createElement('button');
      btn.className = 'cfged-item' + (f.key === cfgEditorCurrent ? ' active' : '') + (f.exists ? '' : ' missing');
      btn.id = 'cfged-tab-' + f.key;
      btn.title = f.key + '.yml' + (f.exists ? '' : ' — ' + t('configEditor.notConfigured').replace(/^[\s(]+|[\s)]+$/g, ''));
      const dot = document.createElement('span'); dot.className = 'dot';
      const name = document.createElement('span'); name.className = 'fname'; name.textContent = f.label;
      btn.appendChild(dot); btn.appendChild(name);
      btn.addEventListener('click', () => cfgEditorSelect(f.key));
      box.appendChild(btn);
      shown++;
    });
  });
  if (!shown) {
    const e = document.createElement('div');
    e.className = 'cfged-empty';
    e.textContent = t('configEditor.noMatch');
    box.appendChild(e);
  }
}

async function cfgEditorSelect(key) {
  cfgEditorCurrent = key;
  document.querySelectorAll('#cfged-tabs .cfged-item').forEach(b => b.classList.toggle('active', b.id === 'cfged-tab-' + key));
  const meta = cfgEditorFiles.find(f => f.key === key);
  document.getElementById('cfged-current-label').textContent = meta ? meta.label : key;
  const metaEl = document.getElementById('cfged-current-meta');
  if (metaEl) {
    const parts = [key + '.yml'];
    if (meta && meta.size != null) parts.push(meta.size + ' B');
    if (meta && meta.mtime) parts.push(new Date(meta.mtime).toLocaleString());
    metaEl.textContent = parts.join(' · ');
  }

  const q = cfgEditorRevealed ? '&reveal=1' : '';
  const d = await api('/config-editor/file?key=' + encodeURIComponent(key) + q).catch(() => null);
  const editor = document.getElementById('cfged-editor');
  const status = document.getElementById('cfged-status');
  if (!editor) return;
  editor.value = d ? (d.content || '') : '';
  if (status) {
    status.style.color = 'var(--text3)';
    status.textContent = !d ? t('configEditor.statusReadError')
      : d.masked ? t('configEditor.statusMasked')
      : (!d.exists ? t('configEditor.statusMissing') : '');
  }
}

async function cfgEditorToggleReveal() {
  cfgEditorRevealed = !cfgEditorRevealed;
  if (cfgEditorCurrent) await cfgEditorSelect(cfgEditorCurrent);
}

async function cfgEditorSave() {
  if (!cfgEditorCurrent) return;
  const content = document.getElementById('cfged-editor').value;
  const status  = document.getElementById('cfged-status');
  const d = await api('/config-editor/file', {
    method: 'POST',
    body: JSON.stringify({ key: cfgEditorCurrent, content }),
  }).catch(e => ({ error: e.message }));
  if (d && d.ok) {
    if (status) { status.textContent = t('configEditor.saved'); status.style.color = 'var(--green)'; }
    await initConfigEditor();
    if (d.regenerateChallenge) {
      const s2 = document.getElementById('cfged-status');
      if (s2) {
        s2.textContent = t('configEditor.regenerateChallenge') + ' ';
        s2.style.color = 'var(--amber, #d98e04)';
        const a = document.createElement('a');
        a.href = '#'; a.textContent = t('configEditor.openChallenge');
        a.addEventListener('click', ev => { ev.preventDefault(); openPage('challenge'); });
        s2.appendChild(a);
      }
    }
  } else {
    alert(t('common.error') + ' : ' + (d && d.error ? d.error : 'unknown'));
  }
}
