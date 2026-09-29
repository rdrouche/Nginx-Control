// Extrait de public/index.html (voir CHANGELOG.md).

// ── VHOST GENERATOR ───────────────────────────────────────────────────────────
let vhgSnippetsMeta  = [];
let vhgDrafts        = {};
let vhgActiveDraftId = null;

const VHG_DRAFTS_KEY = 'ngx_vhg_drafts';

function vhgLoadDrafts() {
  try { vhgDrafts = JSON.parse(localStorage.getItem(VHG_DRAFTS_KEY) || '{}'); } catch { vhgDrafts = {}; }
  vhgRenderDraftList();
}

function vhgSaveDraftsToStorage() {
  try { localStorage.setItem(VHG_DRAFTS_KEY, JSON.stringify(vhgDrafts)); } catch {}
}

function vhgRenderDraftList() {
  const el = document.getElementById('vhg-draft-list');
  const ids = Object.keys(vhgDrafts).sort((a,b) => (vhgDrafts[b].updated||0) - (vhgDrafts[a].updated||0));
  if (!ids.length) {
    el.innerHTML = '<div style="color:var(--text3);font-family:monospace;font-size:12px">' + t('vhg.empty.drafts') + '</div>';
    return;
  }
  el.innerHTML = ids.map(id => {
    const d = vhgDrafts[id];
    const isActive = id === vhgActiveDraftId;
    return `<div class="draft-item${isActive?' active':''}" onclick="vhgLoadDraft('${id}')">
      <span class="draft-name">${h(d.name||id)}</span>
      <span class="draft-date">${d.updated ? timeAgo(new Date(d.updated).toISOString()) : ''}</span>
      <button class="btn sm" style="padding:2px 7px;font-size:10px" onclick="event.stopPropagation();vhgDeleteDraft('${id}')">x</button>
    </div>`;
  }).join('');
}

function vhgNewDraft() {
  const name = prompt(t('vhg.draft.name'), 'nouveau-vhost');
  if (!name) return;
  const id = 'draft_' + Date.now();
  vhgDrafts[id] = { name, config: '', form: {}, updated: Date.now() };
  vhgActiveDraftId = id;
  vhgSaveDraftsToStorage();
  vhgRenderDraftList();
  document.getElementById('vhg-draft-name-badge').textContent = name;
  document.getElementById('vhg-editor').value = '';
  vhgResetForm();
}

function vhgLoadDraft(id) {
  const d = vhgDrafts[id];
  if (!d) return;
  vhgActiveDraftId = id;
  document.getElementById('vhg-draft-name-badge').textContent = d.name || id;
  document.getElementById('vhg-editor').value = d.config || '';
  if (d.form) vhgRestoreForm(d.form);
  vhgRenderDraftList();
}

function vhgSaveDraft() {
  if (!vhgActiveDraftId) {
    const name = prompt(t('vhg.draft.name'), 'nouveau-vhost');
    if (!name) return;
    vhgActiveDraftId = 'draft_' + Date.now();
    vhgDrafts[vhgActiveDraftId] = { name };
    document.getElementById('vhg-draft-name-badge').textContent = name;
  }
  const config = document.getElementById('vhg-editor').value;
  vhgDrafts[vhgActiveDraftId] = {
    ...vhgDrafts[vhgActiveDraftId],
    config,
    form: vhgCollectForm(),
    updated: Date.now(),
  };
  vhgSaveDraftsToStorage();
  vhgRenderDraftList();
}

function vhgDeleteDraft(id) {
  if (!confirm(t('vhg.draft.delete.confirm'))) return;
  delete vhgDrafts[id];
  if (vhgActiveDraftId === id) { vhgActiveDraftId = null; document.getElementById('vhg-editor').value = ''; }
  vhgSaveDraftsToStorage();
  vhgRenderDraftList();
}

function vhgDownload() {
  const config = document.getElementById('vhg-editor').value;
  if (!config.trim()) return;
  const serverName = document.getElementById('vhg-serverName').value.trim().split(/\s+/)[0] || 'vhost';
  const fname = serverName.replace(/[^a-zA-Z0-9.-]/g, '_') + '.conf';
  const blob = new Blob([config], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = fname;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function vhgCollectForm() {
  const g = id => { const el = document.getElementById(id); return el ? (el.type==='checkbox'?el.checked:el.value) : ''; };
  return {
    serverName: g('vhg-serverName'), https: g('vhg-https'), redirect: g('vhg-redirect'),
    http2: g('vhg-http2'), port: g('vhg-port'),
    sslSource: (() => {
      const sel = document.getElementById('vhg-sslSource');
      const opt = sel?.options[sel?.selectedIndex];
      return { val: sel?.value||'', type: opt?.dataset?.type||'manual', file: sel?.value||'' };
    })(),
    sslCert: g('vhg-sslCert'), sslKey: g('vhg-sslKey'),
    accesslogEnabled: g('vhg-accesslog-enabled'),
    docker: g('vhg-docker'), backend: g('vhg-backend'),
    containerName: g('vhg-containerName'), containerPort: g('vhg-containerPort'),
    containerScheme: g('vhg-containerScheme'),
    timeout: g('vhg-timeout'), maxbody: g('vhg-maxbody'), accesslog: g('vhg-accesslog'),
    extraServer: g('vhg-extraServer'), extraLocation: g('vhg-extraLocation'),
    snippetsServer:   [...document.querySelectorAll('#vhg-snippets-server input:checked')].map(i=>i.value),
    snippetsLocation: [...document.querySelectorAll('#vhg-snippets-location input:checked')].map(i=>i.value),
  };
}

function vhgRestoreForm(form) {
  const s = (id, val) => { const el = document.getElementById(id); if (!el) return; el.type==='checkbox' ? (el.checked=!!val) : (el.value=val||''); };
  s('vhg-serverName', form.serverName); s('vhg-https', form.https); s('vhg-redirect', form.redirect);
  s('vhg-http2', form.http2); s('vhg-port', form.port);
  s('vhg-sslSnippet', form.sslSnippet); s('vhg-sslCert', form.sslCert); s('vhg-sslKey', form.sslKey);
  s('vhg-docker', form.docker); s('vhg-backend', form.backend);
  s('vhg-containerName', form.containerName); s('vhg-containerPort', form.containerPort);
  s('vhg-containerScheme', form.containerScheme);
  s('vhg-timeout', form.timeout); s('vhg-maxbody', form.maxbody); s('vhg-accesslog', form.accesslog);
  s('vhg-extraServer', form.extraServer); s('vhg-extraLocation', form.extraLocation);
  vhgToggleHttps(); vhgToggleDocker(); vhgToggleSSLMode();
  // Restore snippet checkboxes
  if (form.snippetsServer) {
    form.snippetsServer.forEach(v => { const cb = document.querySelector(`#vhg-snippets-server input[value="${v}"]`); if (cb) cb.checked = true; });
  }
  if (form.snippetsLocation) {
    form.snippetsLocation.forEach(v => { const cb = document.querySelector(`#vhg-snippets-location input[value="${v}"]`); if (cb) cb.checked = true; });
  }
}

function vhgResetForm() {
  ['vhg-serverName','vhg-port','vhg-sslCert','vhg-sslKey','vhg-backend',
   'vhg-containerName','vhg-containerPort','vhg-timeout','vhg-maxbody',
   'vhg-accesslog','vhg-extraServer','vhg-extraLocation'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  ['vhg-https','vhg-redirect','vhg-http2','vhg-docker'].forEach(id => {
    const el = document.getElementById(id); if (el) el.checked = id==='vhg-redirect'||id==='vhg-http2';
  });
  document.querySelectorAll('#vhg-snippets-server input, #vhg-snippets-location input').forEach(cb => cb.checked = false);
  vhgToggleHttps(); vhgToggleDocker(); vhgToggleSSLMode();
}

function vhgToggleHttps() {
  const on = document.getElementById('vhg-https').checked;
  document.getElementById('vhg-https-opts').style.display  = on ? '' : 'none';
  document.getElementById('vhg-ssl-section').style.display = on ? '' : 'none';
}

function vhgToggleDocker() {
  const on = document.getElementById('vhg-docker').checked;
  document.getElementById('vhg-backend-direct').style.display = on ? 'none' : '';
  document.getElementById('vhg-backend-docker').style.display = on ? '' : 'none';
}

function vhgToggleAccessLog() {
  const on = document.getElementById('vhg-accesslog-enabled').checked;
  document.getElementById('vhg-accesslog-opts').style.display = on ? '' : 'none';
}

function vhgApplySSLSource() {
  const sel = document.getElementById('vhg-sslSource');
  const opt = sel.options[sel.selectedIndex];
  const type = opt?.dataset?.type || '';

  // Reset hidden fields
  document.getElementById('vhg-sslCert').value = '';
  document.getElementById('vhg-sslKey').value  = '';
  document.getElementById('vhg-ssl-free').style.display      = 'none';
  document.getElementById('vhg-snippet-selected').style.display = 'none';

  if (!sel.value) {
    // Nothing selected — show free form
    document.getElementById('vhg-ssl-free').style.display = '';
    return;
  }
  if (type === 'snippet') {
    // Snippet handles cert — just show confirmation
    document.getElementById('vhg-snippet-selected').style.display = '';
  } else {
    // Pre-fill cert/key paths and show fields read-only style
    document.getElementById('vhg-sslCert').value = opt?.dataset?.cert || '';
    document.getElementById('vhg-sslKey').value  = opt?.dataset?.key  || '';
    document.getElementById('vhg-ssl-free').style.display = '';
  }
}

function vhgToggleSSLMode() { vhgApplySSLSource(); }

async function vhgPreview() {
  const form = vhgCollectForm();
  if (!form.serverName) return;
  const d = await api('/vhost/generate', { method:'POST', body: JSON.stringify({
    serverName:        form.serverName.split(/\s+/),
    https:             form.https,
    redirectHttp:      form.redirect,
    http2:             form.http2,
    listenPort:        form.port || undefined,
    sslSnippet:  form.sslSource?.type === 'snippet' ? form.sslSource.file : undefined,
    sslCertPath:       form.sslCert   || undefined,
    sslKeyPath:        form.sslKey    || undefined,
    isDockerContainer: form.docker,
    containerName:     form.containerName || undefined,
    containerPort:     form.containerPort || undefined,
    containerScheme:   form.containerScheme || 'http',
    backend:           form.backend || undefined,
    proxyReadTimeout:  parseInt(form.timeout)||undefined,
    clientMaxBody:     form.maxbody || undefined,
    accessLog: form.accesslogEnabled ? (form.accesslog || true) : 'none',
    snippetsServer:    form.snippetsServer,
    snippetsLocation:  form.snippetsLocation,
    extraServerConf:   form.extraServer   || undefined,
    extraLocationConf: form.extraLocation || undefined,
  }) }).catch(() => null);
  if (d?.config) {
    const editor = document.getElementById('vhg-editor');
    editor.value = d.config;
    delete editor.dataset.manualEdit;
    const copyBtn = document.getElementById('vhg-copy-btn');
    if (copyBtn) copyBtn.style.display = d.config ? '' : 'none';
  }
}

async function initVhostGen() {
  vhgLoadDrafts();
  const editor = document.getElementById('vhg-editor');

  // Load snippets with metadata
  const d = await api('/snippets/meta').catch(() => null);
  if (d?.snippets) {
    vhgSnippetsMeta = d.snippets;
    vhgRenderSnippetLists();
  }

  // Load all SSL sources (snippets + manual certs + Let's Encrypt)
  const sslSrc = await api('/vhost/ssl-sources').catch(() => null);
  if (sslSrc?.sources) {
    const sel = document.getElementById('vhg-sslSource');
    const snippets = sslSrc.sources.filter(s => s.type === 'snippet');
    const manuals  = sslSrc.sources.filter(s => s.type === 'manual');
    const leSnips  = sslSrc.sources.filter(s => s.type === 'letsencrypt');
    let html = '<option value="">-- Manuel (saisie libre) --</option>';
    if (snippets.length) {
      html += '<optgroup label="Snippets SSL (ssl-*.conf)">' +
        snippets.map(s => `<option value="${h(s.file)}" data-type="snippet">${h(s.label)}</option>`).join('') +
        '</optgroup>';
    }
    if (manuals.length) {
      html += '<optgroup label="Certificats /ssl/">' +
        manuals.map(s => `<option value="${h(s.certPath)}" data-type="manual" data-cert="${h(s.certPath)}" data-key="${h(s.keyPath)}">${h(s.label)}${s.hasPair?'':' (cle manquante)'}</option>`).join('') +
        '</optgroup>';
    }
    if (leSnips.length) {
      html += '<optgroup label="Let\'s Encrypt">' +
        leSnips.map(s => `<option value="${h(s.certPath)}" data-type="letsencrypt" data-cert="${h(s.certPath)}" data-key="${h(s.keyPath)}">${h(s.label)}</option>`).join('') +
        '</optgroup>';
    }
    sel.innerHTML = html;
  }
}

function vhgRenderSnippetLists() {
  const serverEl   = document.getElementById('vhg-snippets-server');
  const locationEl = document.getElementById('vhg-snippets-location');

  const serverSnippets   = vhgSnippetsMeta.filter(s => s.emplacement.includes('server') && !s.isSSL);
  const locationSnippets = vhgSnippetsMeta.filter(s => s.emplacement.includes('location'));

  const renderList = (snippets, containerId) => {
    const el = document.getElementById(containerId);
    if (!snippets.length) {
      el.innerHTML = '<div style="color:var(--text3);font-size:11px;font-family:monospace">Aucun snippet disponible</div>';
      return;
    }
    el.innerHTML = snippets.map(s => `
      <div class="vhg-snippet-item">
        <input type="checkbox" value="${h(s.file)}" onchange="vhgPreview()">
        <span style="flex:1">${h(s.name)}</span>
        ${s.description ? `<span style="color:var(--text3);font-size:10px">${h(s.description)}</span>` : ''}
        <span class="vhg-snippet-badge">${h(s.emplacement.join('+'))}</span>
      </div>`).join('');
  };

  renderList(serverSnippets, 'vhg-snippets-server');
  renderList(locationSnippets, 'vhg-snippets-location');
}


// ── VHOST GENERATOR COPY ─────────────────────────────────────────────────────
function copyVhgOutput() {
  const ta = document.getElementById('vhg-editor');
  if (!ta || !ta.value) return;
  // Fix (retour utilisateur v12.44.0) : navigator.clipboard.writeText() sans
  // garde levait une TypeError synchrone (jamais interceptee par le .catch()
  // qui suit) des que le dashboard est servi en HTTP simple, hors contexte
  // securise — voir copyToClipboard() dans index.html.
  copyToClipboard(ta.value).then(ok => copyFeedback('vhg-copy-btn', ok, t('vhg.copy.done'), t('vhg.copy.unsupported')));
}
