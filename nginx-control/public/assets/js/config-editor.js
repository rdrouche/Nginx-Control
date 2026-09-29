// ── CONFIGURATION (éditeur générique des fichiers d'intégration) ─────────────
// Extrait de index.html (voir CHANGELOG.md) — script global classique (pas
// un module ES), chargé après le script principal : il partage sa portée
// globale et peut donc appeler api(), t() et les autres helpers déjà
// définis à ce moment-là, exactement comme s'il était encore inline.
let cfgEditorFiles = [];
let cfgEditorCurrent = null;
let cfgEditorRevealed = false;

async function initConfigEditor() {
  const d = await api('/config-editor/files').catch(() => null);
  if (!d) return;
  cfgEditorFiles = d.files || [];
  const revealBtn = document.getElementById('cfged-reveal-btn');
  if (revealBtn) revealBtn.style.display = d.canReveal ? '' : 'none';

  const tabs = document.getElementById('cfged-tabs');
  tabs.innerHTML = '';
  cfgEditorFiles.forEach((f, i) => {
    const btn = document.createElement('button');
    btn.className = 'format-tab' + ((f.key === cfgEditorCurrent || (!cfgEditorCurrent && i === 0)) ? ' active' : '');
    btn.style.border = 'none';
    btn.id = 'cfged-tab-' + f.key;
    btn.textContent = f.label + (f.exists ? '' : t('configEditor.notConfigured'));
    btn.onclick = () => cfgEditorSelect(f.key);
    tabs.appendChild(btn);
  });

  if (!cfgEditorCurrent && cfgEditorFiles.length) cfgEditorCurrent = cfgEditorFiles[0].key;
  if (cfgEditorCurrent) await cfgEditorSelect(cfgEditorCurrent);
}

async function cfgEditorSelect(key) {
  cfgEditorCurrent = key;
  document.querySelectorAll('#cfged-tabs .format-tab').forEach(b => b.classList.toggle('active', b.id === 'cfged-tab-' + key));
  const meta = cfgEditorFiles.find(f => f.key === key);
  document.getElementById('cfged-current-label').textContent = meta ? meta.label : key;

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
  } else {
    alert(t('common.error') + ' : ' + (d && d.error ? d.error : 'unknown'));
  }
}
