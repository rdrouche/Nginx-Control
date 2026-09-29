'use strict';
/**
 * Page "Hotes Docker distants" (agents, Partie 2 du document de conception)
 * — vue en lecture (+ actions d'approbation/revocation) sur le registre
 * d'agents distants (voir features/agents.js#getStatus-equivalent :
 * GET /api/agents). Meme convention que docker-autoconfig.js : scope global
 * partage (api(), t(), hasPerm()), pas un module ES.
 *
 * Un agent lui-meme ne s'enrole JAMAIS depuis cette page (pas de bouton
 * "creer un agent") — l'enrolement est initie par l'agent (POST
 * /api/agent/enroll, public, voir le rappel affiche sur la page), cette
 * page ne fait qu'approuver/rejeter/revoquer ce qui arrive.
 */
let agentsLastToken = '';

const AGENTS_STATUS_META = {
  pending:  { cls: 'am', label: () => t('agents.status.pending')  || 'En attente' },
  approved: { cls: 'gn', label: () => t('agents.status.approved') || 'Approuve' },
  rejected: { cls: 'gy', label: () => t('agents.status.rejected') || 'Rejete' },
  revoked:  { cls: 'rd', label: () => t('agents.status.revoked')  || 'Revoque' },
};

async function initAgents() { await agentsLoad(); }

async function agentsLoad() {
  const d = await api('/agents').catch(e => ({ error: e.message }));
  const errEl = document.getElementById('agents-config-errors');
  if (!d || d.error) {
    errEl.style.display = '';
    errEl.textContent = (t('agents.error.api') || 'Erreur') + (d?.error ? ' : ' + d.error : '');
    document.getElementById('agents-list').innerHTML = '';
    document.getElementById('agents-empty').style.display = 'none';
    return;
  }
  if (d.configErrors && d.configErrors.length) {
    errEl.style.display = '';
    errEl.textContent = d.configErrors.join('\n');
  } else {
    errEl.style.display = 'none';
  }

  const s = d.settings || {};
  document.getElementById('agents-cfg-enable').textContent = s.enable ? (t('common.yes') || 'Oui') : (t('common.no') || 'Non');
  document.getElementById('agents-cfg-offline').textContent = `${s.offlineAfterSec ?? '—'}s`;
  document.getElementById('agents-cfg-max').textContent = `${s.maxVhostsPerAgent ?? '—'}`;

  const list = document.getElementById('agents-list');
  const empty = document.getElementById('agents-empty');
  const agents = d.agents || [];
  const pendingCount = agents.filter(a => a.status === 'pending').length;
  const badge = document.getElementById('agents-pending-count');
  if (badge) { badge.textContent = pendingCount ? String(pendingCount) : ''; badge.style.display = pendingCount ? '' : 'none'; }

  if (!agents.length) {
    empty.style.display = '';
    list.innerHTML = '';
    return;
  }
  empty.style.display = 'none';
  list.innerHTML = '';
  for (const a of agents) list.appendChild(agentsRenderRow(a));
}

function agentsRenderRow(a) {
  const wrap = document.createElement('div');
  wrap.style.cssText = 'border:1px solid var(--border2);border-radius:var(--r);padding:10px 12px';

  const head = document.createElement('div');
  head.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap';

  const left = document.createElement('div');
  left.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
  const nameEl = document.createElement('span');
  nameEl.style.fontWeight = '600';
  nameEl.textContent = a.hostnameProposed || a.id;
  left.appendChild(nameEl);
  const idEl = document.createElement('span');
  idEl.style.cssText = 'font-family:monospace;font-size:10px;color:var(--text3);background:var(--bg);border-radius:4px;padding:1px 5px';
  idEl.textContent = a.id;
  left.appendChild(idEl);
  if (a.status === 'approved') {
    const onlineEl = document.createElement('span');
    onlineEl.className = 'badge ' + (a.online ? 'gn' : 'gy');
    onlineEl.textContent = a.online
      ? (t('agents.online') || 'En ligne')
      : (a.lastManifestAt
          ? (t('agents.offlineSince') || 'Hors ligne depuis') + ' ' + agentsFormatUptime((Date.now() - a.lastManifestAt) / 1000)
          : (t('agents.offline') || 'Hors ligne'));
    left.appendChild(onlineEl);
    if (a.tunnelConnected) {
      const tunnelEl = document.createElement('span');
      tunnelEl.className = 'badge bl';
      tunnelEl.textContent = t('agents.tunnelConnected') || 'Tunnel actif';
      left.appendChild(tunnelEl);
    }
  }

  const meta = AGENTS_STATUS_META[a.status] || { cls: 'gy', label: () => a.status };
  const badgeEl = document.createElement('span');
  badgeEl.className = 'badge ' + meta.cls;
  badgeEl.textContent = meta.label();

  head.appendChild(left);
  head.appendChild(badgeEl);
  wrap.appendChild(head);

  const info = document.createElement('div');
  info.style.cssText = 'margin-top:6px;font-size:11px;color:var(--text3);display:flex;flex-direction:column;gap:2px';
  if (a.fingerprint) {
    const fp = document.createElement('div');
    fp.textContent = (t('agents.fingerprint') || 'Empreinte') + ' : ' + a.fingerprint;
    info.appendChild(fp);
  }
  const created = document.createElement('div');
  created.textContent = (t('agents.createdAt') || 'Enrole le') + ' : ' + new Date(a.createdAt).toLocaleString();
  info.appendChild(created);
  if (a.status === 'approved') {
    const vhosts = document.createElement('div');
    vhosts.textContent = (t('agents.vhostCount') || 'Vhosts publies') + ' : ' + (a.vhostCount || 0);
    info.appendChild(vhosts);
    if (a.lastManifestAt) {
      const lastPush = document.createElement('div');
      lastPush.textContent = (t('agents.lastManifest') || 'Dernier manifeste') + ' : ' + new Date(a.lastManifestAt).toLocaleString();
      info.appendChild(lastPush);
    }
    if (a.lastManifestOk === false && a.lastManifestError) {
      const err = document.createElement('div');
      err.style.color = 'var(--red)';
      err.textContent = (t('agents.lastError') || 'Derniere erreur') + ' : ' + a.lastManifestError;
      info.appendChild(err);
    }
    if (a.protocolVersion) {
      const proto = document.createElement('div');
      proto.textContent = (t('agents.protocolVersion') || 'Protocole') + ' : v' + a.protocolVersion;
      info.appendChild(proto);
    }
    if (a.metrics) {
      const m = document.createElement('div');
      const parts = [];
      if (a.metrics.cpuPercent !== undefined) parts.push('CPU ' + a.metrics.cpuPercent + '%');
      if (a.metrics.memPercent !== undefined) parts.push('RAM ' + a.metrics.memPercent + '%');
      if (a.metrics.uptimeSec !== undefined) parts.push((t('agents.uptime') || 'uptime') + ' ' + agentsFormatUptime(a.metrics.uptimeSec));
      if (a.metrics.netRxBytesPerSec !== undefined || a.metrics.netTxBytesPerSec !== undefined) {
        parts.push('↓' + agentsFormatBytes(a.metrics.netRxBytesPerSec || 0) + '/s ↑' + agentsFormatBytes(a.metrics.netTxBytesPerSec || 0) + '/s');
      }
      if (parts.length) {
        m.textContent = (t('agents.metrics') || 'Metriques') + ' : ' + parts.join(' — ');
        info.appendChild(m);
      }
    }
  }
  wrap.appendChild(info);

  const actions = document.createElement('div');
  actions.style.cssText = 'display:flex;gap:6px;margin-top:10px;flex-wrap:wrap';

  if (a.status === 'pending') {
    actions.appendChild(agentsButton(t('agents.approve') || 'Approuver', () => agentsApprove(a.id)));
    actions.appendChild(agentsButton(t('agents.reject') || 'Rejeter', () => agentsReject(a.id), 'danger'));
  }
  if (a.status === 'approved') {
    if (a.vhosts && a.vhosts.length) {
      actions.appendChild(agentsButton(t('agents.preview') || 'Vhosts publies', () => agentsPreviewOpen(a)));
    }
    actions.appendChild(agentsButton(t('agents.regenerateToken') || 'Regenerer le jeton', () => agentsRegenerateToken(a.id)));
    actions.appendChild(agentsButton(t('agents.revoke') || 'Revoquer', () => agentsRevoke(a.id), 'danger'));
  }
  if (a.status === 'rejected' || a.status === 'revoked') {
    actions.appendChild(agentsButton(t('common.delete') || 'Supprimer', () => agentsDelete(a.id), 'danger'));
  }
  if (actions.childNodes.length) wrap.appendChild(actions);

  return wrap;
}

function agentsFormatUptime(sec) {
  sec = Math.max(0, Math.floor(sec));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}j ${h}h`;
  if (h > 0) return `${h}h ${m}min`;
  return `${m}min`;
}
function agentsFormatBytes(n) {
  if (n < 1024) return n.toFixed(0) + ' o';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' Ko';
  return (n / (1024 * 1024)).toFixed(1) + ' Mo';
}

function agentsButton(label, onClick, variant) {
  const btn = document.createElement('button');
  btn.className = 'btn sm' + (variant ? ' ' + variant : '');
  btn.textContent = label;
  btn.addEventListener('click', onClick);
  return btn;
}

async function agentsApprove(id) {
  const r = await api(`/agents/${id}/approve`, { method: 'POST' });
  if (r && r.token) agentsTokenOpen(r.token);
  await agentsLoad();
}
async function agentsReject(id) {
  await api(`/agents/${id}/reject`, { method: 'POST' });
  await agentsLoad();
}
async function agentsRevoke(id) {
  await api(`/agents/${id}/revoke`, { method: 'POST' });
  await agentsLoad();
}
async function agentsRegenerateToken(id) {
  const r = await api(`/agents/${id}/regenerate-token`, { method: 'POST' });
  if (r && r.token) agentsTokenOpen(r.token);
  await agentsLoad();
}
async function agentsDelete(id) {
  await api(`/agents/${id}`, { method: 'DELETE' });
  await agentsLoad();
}

function agentsTokenOpen(token) {
  agentsLastToken = token;
  document.getElementById('agents-token-value').textContent = token;
  document.getElementById('agents-token-overlay').style.display = 'flex';
}
function agentsTokenClose() {
  document.getElementById('agents-token-overlay').style.display = 'none';
  agentsLastToken = '';
}
function agentsTokenCopy() {
  // Fix (retour utilisateur v12.44.0) : ne faisait rien en HTTP simple
  // (navigator.clipboard absent hors contexte securise) — voir
  // copyToClipboard() dans index.html pour le detail et le repli
  // document.execCommand('copy').
  if (!agentsLastToken) return;
  copyToClipboard(agentsLastToken).then(ok => copyFeedback('agents-token-copy-btn', ok));
}

let agentsPreviewAgentId = '';

function agentsPreviewOpen(a) {
  agentsPreviewAgentId = a.id;
  document.getElementById('agents-preview-title').textContent =
    (t('agents.previewTitle') || 'Vhosts publies') + ' — ' + (a.hostnameProposed || a.id);
  agentsPreviewRender(a.vhosts || []);
  document.getElementById('agents-preview-overlay').style.display = 'flex';
}
function agentsPreviewClose() {
  document.getElementById('agents-preview-overlay').style.display = 'none';
  agentsPreviewAgentId = '';
}

function agentsPreviewRender(vhosts) {
  const box = document.getElementById('agents-preview-content');
  box.innerHTML = '';
  for (const v of vhosts) box.appendChild(agentsPreviewRow(v));
}

function agentsPreviewRow(v) {
  const names = (v.serverNames || []).join(', ');
  const row = document.createElement('div');
  row.style.cssText = 'padding:8px 10px;background:var(--bg);border-radius:6px;display:flex;flex-direction:column;gap:4px';

  const head = document.createElement('div');
  head.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap';
  const label = document.createElement('span');
  label.style.cssText = 'font-family:monospace;font-size:12px';
  const modeTag = v.mode === 'tunnel' ? ' [tunnel]' : v.mode === 'relay' ? ` [relay${v.relayTarget ? ' -> ' + v.relayTarget : ''}]` : '';
  const listenPart = v.inLastManifest ? ` :${v.listen}${v.sslMode && v.sslMode !== 'none' ? ' (ssl: ' + v.sslMode + ')' : ''}${modeTag}` : '';
  label.textContent = names + listenPart;
  head.appendChild(label);

  if (v.paused) {
    const badge = document.createElement('span');
    badge.className = 'badge gy';
    badge.textContent = t('agents.vhostPaused') || 'En pause';
    head.appendChild(badge);
  } else if (!v.inLastManifest) {
    const badge = document.createElement('span');
    badge.className = 'badge gy';
    badge.textContent = t('agents.vhostNotLive') || 'Pas dans le dernier manifeste';
    head.appendChild(badge);
  }
  row.appendChild(head);

  if (v.paused) {
    const when = v.pausedAt ? new Date(v.pausedAt).toLocaleString() : '—';
    const info = document.createElement('div');
    info.style.cssText = 'font-size:11px;color:var(--text3)';
    info.textContent = t('agents.vhostPausedSince', { when, by: v.pausedBy || '—' });
    row.appendChild(info);
  }

  const actions = document.createElement('div');
  actions.style.cssText = 'display:flex;gap:6px';
  if (hasPerm('deploy')) {
    if (v.paused) {
      actions.appendChild(agentsButton(t('agents.vhostResume') || 'Reprendre', () => agentsVhostPauseResume(v.serverNames, 'resume')));
    } else {
      actions.appendChild(agentsButton(t('agents.vhostPause') || 'Mettre en pause', () => agentsVhostPauseResume(v.serverNames, 'pause')));
    }
  }
  if (actions.childNodes.length) row.appendChild(actions);

  return row;
}

let agentsVhostBusy = false;
async function agentsVhostPauseResume(serverNames, action) {
  if (agentsVhostBusy || !agentsPreviewAgentId || !serverNames || !serverNames.length) return;
  agentsVhostBusy = true;
  const id = agentsPreviewAgentId;
  await api(`/agents/${id}/vhosts/${action}`, {
    method: 'POST', body: JSON.stringify({ serverNames }),
  }).catch(e => ({ error: e.message }));
  agentsVhostBusy = false;
  // Recharge la liste complete, puis rafraichit la fenetre encore ouverte
  // avec les donnees a jour de CE meme agent (meme convention que
  // dacPauseResume() cote docker-autoconfig.js).
  const d = await api('/agents').catch(() => null);
  const fresh = d?.agents?.find(a => a.id === id);
  if (fresh) agentsPreviewRender(fresh.vhosts || []);
  await agentsLoad();
}
