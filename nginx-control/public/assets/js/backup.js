'use strict';
/**
 * Page "Sauvegardes" — liste, création (local/Git/les deux), téléchargement,
 * restauration et suppression des backups. Extrait de public/index.html
 * (voir CHANGELOG.md). Le bouton Restaurer est masqué côté serveur quand
 * Git est configuré (voir README.md, "Git configuré = source de vérité").
 */
async function loadBackupsPage() {
  const el = document.getElementById('bkp-list');
  el.innerHTML = '<div style="color:var(--text3);font-family:monospace;font-size:12px">Chargement…</div>';
  const d = await api('/backups').catch(() => null);
  if (!d) { el.innerHTML = '<div style="color:var(--red)">Erreur API</div>'; return; }

  document.getElementById('bkp-count').textContent = d.backups?.length || 0;
  document.getElementById('bkp-keep-label').textContent = d.keep || '—';

  // Restaurer une sauvegarde locale desynchroniserait le depot Git (source
  // de verite une fois configure) sans que rien ne le signale ensuite — le
  // serveur refuse deja la requete (403, voir POST /api/backups/restore),
  // ce bandeau/bouton masque evite juste de laisser cliquer pour rien.
  const gitNote = document.getElementById('bkp-git-note');
  if (gitNote) gitNote.style.display = d.gitConfigured ? '' : 'none';

  if (!d.backups?.length) {
    el.innerHTML = '<div style="color:var(--text3);font-family:monospace;font-size:12px">Aucune sauvegarde</div>';
    return;
  }

  el.innerHTML = d.backups.map(b => {
    const safeName = b.name.replace(/'/g, "\'");
    const restoreBtn = d.gitConfigured ? '' : `
        <button class="btn sm" onclick="restoreBackup('${safeName}')" title="Restaurer">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="11" height="11"><path d="M3 8a5 5 0 1 0 1-2.9"/><polyline points="1,4 3,8 7,6"/></svg>
          Restaurer
        </button>`;
    return `<div class="bkp-row">
      <svg viewBox="0 0 16 16" fill="none" stroke="var(--text3)" stroke-width="1.5" width="14" height="14" style="flex-shrink:0"><path d="M4 2h6l4 4v8a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z"/><path d="M10 2v4h4"/></svg>
      <span class="bkp-name" title="${b.name}">${b.name}</span>
      <span class="bkp-size">${fmtB(b.size)}</span>
      <span style="color:var(--text3);font-family:monospace;font-size:10px;min-width:70px;text-align:right">${timeAgo(b.mtime)}</span>
      <div class="bkp-actions">
        <button class="btn sm" onclick="dlBackup('${safeName}')" title="Telecharger">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="11" height="11"><path d="M8 2v8M5 11l3 3 3-3M2 14h12"/></svg>
          DL
        </button>${restoreBtn}
        <button class="btn sm danger" onclick="deleteBackup('${safeName}')" title="Supprimer">x</button>
      </div>
    </div>`;
  }).join('');
}

function backupChoiceDialog() {
  return new Promise(resolve => {
    // Remove existing dialog if any
    const existing = document.getElementById('bkp-dialog');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'bkp-dialog';
    overlay.style.cssText = 'position:fixed;inset:0;background:#00000088;z-index:9999;display:flex;align-items:center;justify-content:center';

    overlay.innerHTML = `
      <div style="background:var(--bg2);border:1px solid var(--border2);border-radius:14px;padding:28px 32px;width:380px;max-width:90vw">
        <div style="font-size:16px;font-weight:700;margin-bottom:6px;color:var(--text)">Sauvegarder maintenant</div>
        <div style="font-size:12px;color:var(--text3);margin-bottom:20px">Choisissez la destination et le label</div>
        <div style="margin-bottom:16px">
          <label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px;font-family:monospace">Label (optionnel)</label>
          <input id="bkp-dlg-label" type="text" value="manual" placeholder="manual, pre-deploy, etc."
            style="width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:6px;color:var(--text);font-family:monospace;font-size:12px;padding:8px 12px;outline:none">
        </div>
        <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:20px">
          <button id="bkp-opt-local" onclick="bkpPick('local')" class="btn" style="justify-content:flex-start;gap:10px;padding:10px 14px">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="15" height="15"><path d="M2 12V5a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v7"/><path d="M1 12h14v1a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1v-1z"/><path d="M6 8h4"/></svg>
            <div style="text-align:left"><div style="font-weight:600">Local uniquement</div><div style="font-size:11px;color:var(--text3);font-family:monospace">ZIP dans ./backups/</div></div>
          </button>
          <button id="bkp-opt-git" onclick="bkpPick('git')" class="btn" style="justify-content:flex-start;gap:10px;padding:10px 14px">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="15" height="15"><circle cx="5" cy="4" r="2"/><circle cx="5" cy="12" r="2"/><circle cx="11" cy="12" r="2"/><path d="M5 6v4M7 12h2"/><path d="M5 6a4 4 0 0 0 4 4"/></svg>
            <div style="text-align:left"><div style="font-weight:600">Git uniquement</div><div style="font-size:11px;color:var(--text3);font-family:monospace">Push branche backup + tag</div></div>
          </button>
          <button id="bkp-opt-both" onclick="bkpPick('both')" class="btn primary" style="justify-content:flex-start;gap:10px;padding:10px 14px">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="15" height="15"><path d="M2 12V5a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v7"/><path d="M1 12h14v1a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1v-1z"/><circle cx="11" cy="4" r="2"/><path d="M7 4h2"/></svg>
            <div style="text-align:left"><div style="font-weight:600">Local + Git</div><div style="font-size:11px;color:var(--text3);font-family:monospace">ZIP + push branche backup + tag</div></div>
          </button>
        </div>
        <button onclick="bkpCancel()" style="width:100%;background:none;border:1px solid var(--border);border-radius:6px;color:var(--text3);padding:7px;cursor:pointer;font-family:monospace;font-size:12px">Annuler</button>
      </div>`;

    document.body.appendChild(overlay);

    window.bkpPick = (mode) => {
      const label = document.getElementById('bkp-dlg-label').value.trim() || 'manual';
      overlay.remove();
      delete window.bkpPick; delete window.bkpCancel;
      resolve({ label, mode });
    };
    window.bkpCancel = () => { overlay.remove(); delete window.bkpPick; delete window.bkpCancel; resolve(null); };
    overlay.addEventListener('click', e => { if (e.target === overlay) window.bkpCancel(); });
  });
}

function dlBackup(name) {
  fetch('/api/backups/download?name=' + encodeURIComponent(name), { credentials: 'same-origin' })
    .then(r => {
      if (!r.ok) { alert('Erreur telechargement : ' + r.status); return null; }
      return r.blob();
    })
    .then(blob => {
      if (!blob) return;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    })
    .catch(err => alert('Erreur : ' + err.message));
}

async function doManualBackup() {
  // 3-choice modal via custom overlay
  const choice = await backupChoiceDialog();
  if (!choice) return;
  const { label, mode } = choice;
  const el = document.getElementById('bkp-list');
  el.innerHTML = '<div style="color:var(--blue);font-family:monospace;font-size:12px">Sauvegarde en cours…</div>';
  const d = await api('/backups', { method: 'POST', body: JSON.stringify({ label, mode }) }).catch(e => ({ error: e.message }));
  if (d?.ok) {
    await loadBackupsPage();
    const parts = [];
    if (d.zip && !d.zip.skipped) parts.push('ZIP: ' + d.zip.zipName);
    if (d.git?.ok) parts.push('Git tag: ' + d.git.tag);
    else if (d.git?.error) parts.push('Git erreur: ' + d.git.error);
    else if (d.git?.skipped) parts.push('Git: ignore (' + d.git.reason + ')');
    alert('Sauvegarde OK\n' + parts.join('\n'));
  } else {
    alert('Erreur : ' + (d?.error || 'Inconnue'));
    await loadBackupsPage();
  }
}

async function restoreBackup(name) {
  if (!confirm(`Restaurer la sauvegarde "${name}" ?\n\nUn backup de l etat actuel sera cree avant la restauration.`)) return;
  const el = document.getElementById('bkp-list');
  el.innerHTML = '<div style="color:var(--amber);font-family:monospace;font-size:12px">Restauration en cours…</div>';
  const d = await api('/backups/restore', { method:'POST', body: JSON.stringify({ name }) }).catch(e=>({error:e.message}));
  if (d?.ok) {
    await loadBackupsPage();
    alert(`✓ Restauré depuis "${name}"\nBackup pré-restauration : ${d.preBkp?.zipName || '—'}`);
  } else {
    alert('Erreur restauration : ' + (d?.error || 'Inconnue'));
    await loadBackupsPage();
  }
}

async function deleteBackup(name) {
  if (!confirm(`Supprimer définitivement "${name}" ?`)) return;
  await api('/backups/' + encodeURIComponent(name), { method: 'DELETE' });
  await loadBackupsPage();
}
