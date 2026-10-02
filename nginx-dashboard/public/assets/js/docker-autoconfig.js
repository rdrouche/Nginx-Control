'use strict';
/**
 * Page "Auto-config Docker" — vue en lecture (+ actions d'approbation) sur
 * les conteneurs portant les labels `nginx-control.*` (voir
 * features/docker-autoconfig.js#getStatus()). Aucune configuration n'est
 * modifiable ici (docker-autoconfig.yml reste un fichier a editer via la
 * page Configs/Editeur, comme les autres YAML de ce projet) — cette page ne
 * fait qu'exposer /api/docker-autoconfig/status et les deux actions
 * approve/reject/rescan deja exposees par le backend, pour ne plus avoir a
 * lire du JSON brut pour savoir ce que le watcher est en train de faire.
 *
 * Meme convention que les autres pages extraites (analyzer.js, blocklists.js) :
 * scope global partage (api(), t(), h(), hasPerm()), pas un module ES.
 */
let dacBusy = false;

// Libelle + couleur du badge de statut renvoye par getStatus() — voir
// features/docker-autoconfig.js pour la liste exhaustive des valeurs
// possibles (invalid/pending_approval/rejected/ssl_error/applied/pending_apply).
const DAC_STATUS_META = {
  invalid:          { cls: 'rd', label: () => t('dockerAutoconfig.status.invalid')        || 'Invalide' },
  pending_approval: { cls: 'am', label: () => t('dockerAutoconfig.status.pendingApproval') || 'En attente d approbation' },
  rejected:         { cls: 'gy', label: () => t('dockerAutoconfig.status.rejected')        || 'Rejete' },
  ssl_error:        { cls: 'am', label: () => t('dockerAutoconfig.status.sslError')        || 'Erreur SSL' },
  applied:          { cls: 'gn', label: () => t('dockerAutoconfig.status.applied')         || 'Applique' },
  pending_apply:    { cls: 'bl', label: () => t('dockerAutoconfig.status.pendingApply')    || 'En attente d application' },
  // v12.35.0 (demande utilisateur) : une publication approuvee peut etre mise
  // en pause sans revoquer son approbation — voir dacRenderDecision() plus
  // bas pour la table dediee (visible meme conteneur arrete) et le bouton
  // Pause/Reprendre sur la carte d un conteneur toujours vivant.
  paused:           { cls: 'gy', label: () => t('dockerAutoconfig.status.paused')          || 'En pause' },
};

async function initDockerAutoconfig() { await dacLoad(); }

async function dacLoad() {
  const d = await api('/docker-autoconfig/status').catch(e => ({ error: e.message }));
  const errEl = document.getElementById('dac-config-errors');
  if (!d || d.error) {
    errEl.style.display = '';
    errEl.textContent = (t('dockerAutoconfig.error.api') || 'Erreur') + (d?.error ? ' : ' + d.error : '');
    document.getElementById('dac-list').innerHTML = '';
    document.getElementById('dac-empty').style.display = 'none';
    return;
  }

  if (d.configErrors && d.configErrors.length) {
    errEl.style.display = '';
    errEl.textContent = d.configErrors.join('\n');
  } else {
    errEl.style.display = 'none';
  }

  const s = d.settings || {};
  document.getElementById('dac-cfg-enable').textContent =
    s.enable ? (t('common.yes') || 'Oui') : (t('common.no') || 'Non');
  document.getElementById('dac-cfg-approval').textContent =
    s.requireApproval ? (t('common.yes') || 'Oui') : (t('common.no') || 'Non');
  document.getElementById('dac-cfg-poll').textContent = `${s.pollIntervalSec ?? '—'}s`;
  document.getElementById('dac-cfg-events').textContent = s.eventsEnable
    ? `${t('dockerAutoconfig.eventsOn') || 'Actifs'} (debounce ${s.eventsDebounceMs ?? '—'}ms)`
    : (t('dockerAutoconfig.eventsOff') || 'Desactives (sondage seul)');
  const patternsEl = document.getElementById('dac-cfg-patterns');
  patternsEl.textContent = (s.allowedServerNamePatterns && s.allowedServerNamePatterns.length)
    ? (t('dockerAutoconfig.patternsLabel') || 'Motifs auto-approuves : ') + s.allowedServerNamePatterns.join(', ')
    : (t('dockerAutoconfig.noPatterns') || 'Aucun motif auto-approuve : tout server_name inconnu reste en attente d approbation.');

  const generatedByKey = {};
  for (const g of (d.generatedFiles || [])) generatedByKey[g.key] = g.file;

  const list = document.getElementById('dac-list');
  const empty = document.getElementById('dac-empty');
  const containers = d.containers || [];
  if (!containers.length) {
    empty.style.display = '';
    list.innerHTML = '';
  } else {
    empty.style.display = 'none';
    list.innerHTML = '';
    for (const c of containers) list.appendChild(dacRenderContainer(c, generatedByKey));
  }

  // v12.35.0 (demande utilisateur) : rendue INCONDITIONNELLEMENT, contrairement
  // a la liste des conteneurs ci-dessus — c'est precisement le probleme
  // signale : un conteneur arrete disparaissait de la page ET de toute
  // possibilite de gerer sa decision. Cette table reste visible et actionnable
  // qu'un conteneur corresponde ou non en ce moment.
  dacRenderDecisions(d.decisions || []);
}

function dacRenderDecisions(decisions) {
  const card = document.getElementById('dac-decisions-card');
  const empty = document.getElementById('dac-decisions-empty');
  const body = document.getElementById('dac-decisions-body');
  if (!card) return;
  if (!decisions.length) {
    empty.style.display = '';
    body.innerHTML = '';
    return;
  }
  empty.style.display = 'none';
  body.innerHTML = '';
  for (const dcs of decisions) body.appendChild(dacRenderDecisionRow(dcs));
}

function dacRenderDecisionRow(dcs) {
  const tr = document.createElement('tr');

  const tdNames = document.createElement('td');
  tdNames.style.cssText = 'font-family:monospace;font-size:11px';
  tdNames.textContent = (dcs.names || []).join(', ') || '—';
  tr.appendChild(tdNames);

  const tdDecision = document.createElement('td');
  const decisionBadge = document.createElement('span');
  if (dcs.paused) {
    decisionBadge.className = 'badge gy';
    decisionBadge.textContent = t('dockerAutoconfig.status.paused') || 'En pause';
  } else {
    decisionBadge.className = 'badge ' + (dcs.decision === 'approved' ? 'gn' : 'rd');
    decisionBadge.textContent = dcs.decision === 'approved'
      ? (t('dockerAutoconfig.approved') || 'Approuve')
      : (t('dockerAutoconfig.status.rejected') || 'Rejete');
  }
  tdDecision.appendChild(decisionBadge);
  tr.appendChild(tdDecision);

  const tdLive = document.createElement('td');
  tdLive.style.cssText = 'font-size:11px;color:var(--text3)';
  tdLive.textContent = dcs.hasLiveContainer
    ? (dcs.containerName || (t('dockerAutoconfig.liveYes') || 'Oui'))
    : (t('dockerAutoconfig.liveNo') || 'Non (conteneur arrete ou absent)');
  tr.appendChild(tdLive);

  const tdWhen = document.createElement('td');
  tdWhen.style.cssText = 'font-size:11px;color:var(--text3)';
  const at = dcs.at ? new Date(dcs.at).toLocaleString() : '—';
  tdWhen.textContent = dcs.by ? `${at} (${dcs.by})` : at;
  tr.appendChild(tdWhen);

  const tdActions = document.createElement('td');
  tdActions.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap';
  const canDeploy = hasPerm('deploy');
  if (dcs.decision === 'approved') {
    const btn = document.createElement('button');
    btn.className = 'btn sm';
    if (dcs.paused) {
      btn.classList.add('primary');
      btn.textContent = t('dockerAutoconfig.resume') || 'Reprendre';
      btn.onclick = () => dacPauseResume(dcs.names, 'resume');
    } else {
      btn.textContent = t('dockerAutoconfig.pause') || 'Mettre en pause';
      btn.onclick = () => dacPauseResume(dcs.names, 'pause');
    }
    if (!canDeploy) btn.disabled = true;
    tdActions.appendChild(btn);
  }
  const revokeBtn = document.createElement('button');
  revokeBtn.className = 'btn sm danger';
  revokeBtn.textContent = t('dockerAutoconfig.revoke') || 'Revoquer';
  revokeBtn.onclick = () => dacRevokeDecision(dcs.names);
  if (!canDeploy) revokeBtn.disabled = true;
  tdActions.appendChild(revokeBtn);
  tr.appendChild(tdActions);

  return tr;
}

function dacRenderContainer(c, generatedByKey) {
  const wrap = document.createElement('div');
  wrap.style.cssText = 'border:1px solid var(--border2);border-radius:var(--r);padding:10px 12px';

  const head = document.createElement('div');
  head.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap';

  const left = document.createElement('div');
  left.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
  const nameEl = document.createElement('span');
  nameEl.style.fontWeight = '600';
  nameEl.textContent = c.containerName || c.containerId?.slice(0, 12) || '?';
  left.appendChild(nameEl);
  const namesEl = document.createElement('span');
  namesEl.style.cssText = 'font-family:monospace;font-size:11px;color:var(--text3)';
  namesEl.textContent = (c.serverNames || []).join(', ') || '—';
  left.appendChild(namesEl);
  if (c.listen) {
    const listenEl = document.createElement('span');
    listenEl.style.cssText = 'font-family:monospace;font-size:10px;color:var(--text3);background:var(--bg);border-radius:4px;padding:1px 5px';
    listenEl.textContent = `:${c.listen}`;
    left.appendChild(listenEl);
  }

  const meta = DAC_STATUS_META[c.status] || { cls: 'gy', label: () => c.status };
  const badge = document.createElement('span');
  badge.className = 'badge ' + meta.cls;
  badge.textContent = meta.label();

  head.appendChild(left);
  head.appendChild(badge);
  wrap.appendChild(head);

  if (c.errors && c.errors.length) {
    const errBox = document.createElement('div');
    errBox.style.cssText = 'margin-top:6px;font-size:11px;color:var(--red);font-family:monospace;white-space:pre-wrap';
    errBox.textContent = c.errors.join('\n');
    wrap.appendChild(errBox);
  }

  // v12.35.0 (demande utilisateur) : message explicite quand la publication
  // est en pause, avec qui et depuis quand — jamais un simple badge sans
  // explication.
  if (c.status === 'paused') {
    const pauseBox = document.createElement('div');
    pauseBox.style.cssText = 'margin-top:6px;font-size:11px;color:var(--text2)';
    const when = c.pausedAt ? new Date(c.pausedAt).toLocaleString() : '—';
    pauseBox.textContent = t('dockerAutoconfig.pausedSince', { when, by: c.pausedBy || '—' });
    wrap.appendChild(pauseBox);
  }

  if (c.ssl && c.ssl.mode && c.ssl.mode !== 'none') {
    const sslBox = document.createElement('div');
    sslBox.style.cssText = 'margin-top:6px;font-size:11px;color:var(--text2)';
    let line = `${t('dockerAutoconfig.sslMode') || 'SSL'} : ${c.ssl.mode} → ${c.ssl.resolved || '—'}`;
    sslBox.textContent = line;
    wrap.appendChild(sslBox);
    if (c.ssl.error) {
      const sslErr = document.createElement('div');
      sslErr.style.cssText = 'margin-top:2px;font-size:11px;color:var(--amber)';
      sslErr.textContent = c.ssl.error.message || c.ssl.error.code;
      wrap.appendChild(sslErr);
    }
  }

  const actions = document.createElement('div');
  actions.style.cssText = 'display:flex;gap:6px;margin-top:8px';
  const key = (c.serverNames && c.serverNames[0] || '').toLowerCase();
  // Fix v12.21.2 (audit finding DAC-03): the decision now applies to the
  // FULL set of server_names, not just the first — the whole array is sent
  // so the backend can tie the approval to the exact set (see
  // features/docker-autoconfig.js#namesDecisionKey()). Approving one name on
  // a multi-name vhost no longer silently approves the others.
  const serverNames = c.serverNames || [];

  if (c.status === 'pending_approval') {
    const approveBtn = document.createElement('button');
    approveBtn.className = 'btn sm primary';
    approveBtn.textContent = t('dockerAutoconfig.approve') || 'Approuver';
    approveBtn.onclick = () => dacDecide(serverNames, 'approve');
    const rejectBtn = document.createElement('button');
    rejectBtn.className = 'btn sm danger';
    rejectBtn.textContent = t('dockerAutoconfig.reject') || 'Rejeter';
    rejectBtn.onclick = () => dacDecide(serverNames, 'reject');
    if (!hasPerm('deploy')) { approveBtn.disabled = true; rejectBtn.disabled = true; }
    actions.appendChild(approveBtn);
    actions.appendChild(rejectBtn);
  } else if (c.status === 'rejected') {
    const approveBtn = document.createElement('button');
    approveBtn.className = 'btn sm';
    approveBtn.textContent = t('dockerAutoconfig.approve') || 'Approuver';
    approveBtn.onclick = () => dacDecide(serverNames, 'approve');
    if (!hasPerm('deploy')) approveBtn.disabled = true;
    actions.appendChild(approveBtn);
  }

  // v12.35.0 (demande utilisateur) : pause/reprise + revocation, disponibles
  // directement sur la carte tant que le conteneur est vivant (la meme
  // action reste possible sans conteneur vivant depuis la table "Decisions
  // enregistrees" plus bas, voir dacRenderDecision()).
  if (['applied', 'pending_apply', 'ssl_error', 'paused'].includes(c.status)) {
    if (c.status === 'paused') {
      const resumeBtn = document.createElement('button');
      resumeBtn.className = 'btn sm primary';
      resumeBtn.textContent = t('dockerAutoconfig.resume') || 'Reprendre';
      resumeBtn.onclick = () => dacPauseResume(serverNames, 'resume');
      if (!hasPerm('deploy')) resumeBtn.disabled = true;
      actions.appendChild(resumeBtn);
    } else {
      const pauseBtn = document.createElement('button');
      pauseBtn.className = 'btn sm';
      pauseBtn.textContent = t('dockerAutoconfig.pause') || 'Mettre en pause';
      pauseBtn.onclick = () => dacPauseResume(serverNames, 'pause');
      if (!hasPerm('deploy')) pauseBtn.disabled = true;
      actions.appendChild(pauseBtn);
    }
    const revokeBtn = document.createElement('button');
    revokeBtn.className = 'btn sm danger';
    revokeBtn.textContent = t('dockerAutoconfig.revoke') || 'Revoquer l approbation';
    revokeBtn.onclick = () => dacRevokeDecision(serverNames);
    if (!hasPerm('deploy')) revokeBtn.disabled = true;
    actions.appendChild(revokeBtn);
  }

  const file = generatedByKey[key];
  if (file) {
    const previewBtn = document.createElement('button');
    previewBtn.className = 'btn sm';
    previewBtn.textContent = t('dockerAutoconfig.preview') || 'Apercu';
    previewBtn.onclick = () => dacPreviewOpen(file, c.containerName);
    actions.appendChild(previewBtn);
  }

  if (actions.childNodes.length) wrap.appendChild(actions);
  return wrap;
}

async function dacDecide(serverNames, action) {
  if (dacBusy || !serverNames || !serverNames.length) return;
  dacBusy = true;
  await api(`/docker-autoconfig/${action}`, {
    method: 'POST', body: JSON.stringify({ serverNames }),
  }).catch(e => ({ error: e.message }));
  dacBusy = false;
  await dacLoad();
}

// v12.35.0 (demande utilisateur) : pause/reprise et revocation d une decision
// — memes garde-fous (dacBusy, tableau non vide) que dacDecide() ci-dessus,
// utilisables aussi bien depuis une carte de conteneur vivant que depuis la
// table "Decisions enregistrees" (dacRenderDecision() plus bas), qui reste
// visible meme quand le conteneur est arrete.
async function dacPauseResume(serverNames, action) {
  if (dacBusy || !serverNames || !serverNames.length) return;
  dacBusy = true;
  await api(`/docker-autoconfig/${action}`, {
    method: 'POST', body: JSON.stringify({ serverNames }),
  }).catch(e => ({ error: e.message }));
  dacBusy = false;
  await dacLoad();
}

async function dacRevokeDecision(serverNames) {
  if (dacBusy || !serverNames || !serverNames.length) return;
  if (!confirm(t('dockerAutoconfig.confirmRevoke') || 'Revoquer cette decision ? Le vhost genere sera retire immediatement si actif, et une nouvelle approbation sera necessaire.')) return;
  dacBusy = true;
  await api('/docker-autoconfig/decisions/remove', {
    method: 'POST', body: JSON.stringify({ serverNames }),
  }).catch(e => ({ error: e.message }));
  dacBusy = false;
  await dacLoad();
}

async function dacRescan() {
  if (dacBusy) return;
  dacBusy = true;
  const btn = document.getElementById('dac-btn-rescan');
  const label = btn?.querySelector('span');
  const prevLabel = label ? label.textContent : '';
  if (btn) btn.disabled = true;
  if (label) label.textContent = t('dockerAutoconfig.rescanning') || 'Rescan en cours…';

  await api('/docker-autoconfig/rescan', { method: 'POST' }).catch(e => ({ error: e.message }));

  if (btn) btn.disabled = false;
  if (label) label.textContent = prevLabel;
  dacBusy = false;
  await dacLoad();
}

async function dacPreviewOpen(file, containerName) {
  const overlay = document.getElementById('dac-preview-overlay');
  const titleEl = document.getElementById('dac-preview-title');
  const contentEl = document.getElementById('dac-preview-content');
  titleEl.textContent = (t('dockerAutoconfig.previewTitle') || 'Vhost genere') + (containerName ? ` — ${containerName}` : '');
  contentEl.textContent = t('common.loading') || 'Chargement…';
  overlay.style.display = 'flex';
  const d = await api(`/configs/file?path=${encodeURIComponent(file)}`).catch(e => ({ error: e.message }));
  contentEl.textContent = (!d || d.error) ? ((t('dockerAutoconfig.previewError') || 'Impossible de lire le fichier') + (d?.error ? ' : ' + d.error : '')) : (d.content || '');
}
function dacPreviewClose() {
  document.getElementById('dac-preview-overlay').style.display = 'none';
}
