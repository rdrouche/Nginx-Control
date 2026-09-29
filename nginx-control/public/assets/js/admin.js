'use strict';
/**
 * Page "Administration" — utilisateurs, matrice de permissions, sessions
 * actives, et l'outil de hash de mot de passe. Extrait de public/index.html
 * (voir CHANGELOG.md).
 */
const ROLE_COLORS = { admin: 'var(--green)', operator: 'var(--blue)', viewer: 'var(--text3)' };
const ALL_PERMS = ['view_metrics','view_configs','view_logs','view_ssl','nginx_control','manage_webhooks','view_api_doc','manage_users'];

async function loadAdminUsers() {
  const d = await api('/auth/users').catch(() => null);
  document.getElementById('users-count').textContent = d?.users?.length || '—';
  const grid = document.getElementById('users-grid');
  if (!d?.users) { grid.innerHTML = '<div style="color:var(--red)">Accès refusé ou erreur</div>'; return; }

  grid.innerHTML = d.users.map(u => {
    const roleColor = ROLE_COLORS[u.role] || 'var(--text3)';
    const initials = (u.name || u.username).split(' ').map(w => w[0]).join('').slice(0,2).toUpperCase();
    const rolePerms = d.permissions?.[u.role] || [];
    return `<div class="user-card">
      <div class="uc-avatar" style="background:${roleColor}">${h(initials)}</div>
      <div class="uc-info">
        <div class="uc-name">${h(u.name || u.username)}</div>
        <div class="uc-username">@${h(u.username)}</div>
        <div class="uc-meta">
          <span class="badge ${u.role === 'admin' ? 'gn' : u.role === 'operator' ? 'bl' : 'gy'}">${h(u.role)}</span>
          <span class="badge ${u.enabled ? 'gn' : 'rd'}">${u.enabled ? 'actif' : 'désactivé'}</span>
        </div>
        <div class="perm-list">
          ${ALL_PERMS.map(p => `<span class="perm-tag ${rolePerms.includes(p) ? 'active' : ''}">${p.replace(/_/g,' ')}</span>`).join('')}
        </div>
      </div>
    </div>`;
  }).join('');

  // Render permission matrix
  const matrix = document.getElementById('perm-matrix');
  matrix.innerHTML = Object.entries(d.permissions || {}).map(([role, perms]) => {
    const roleColor = ROLE_COLORS[role] || 'var(--text3)';
    return `<div class="perm-card">
      <div class="perm-card-role" style="color:${roleColor}">${h(role)}</div>
      <div class="perm-card-perms">
        ${ALL_PERMS.map(p => `<div class="perm-item ${perms.includes(p)?'ok':'no'}">${p.replace(/_/g,' ')}</div>`).join('')}
      </div>
    </div>`;
  }).join('');
}

async function loadSessions() {
  const d = await api('/auth/sessions').catch(() => null);
  const el = document.getElementById('sessions-list');
  if (!d?.sessions) { el.innerHTML = `<div style="color:var(--text3);font-family:monospace;font-size:12px">Accès refusé</div>`; return; }
  if (!d.sessions.length) { el.innerHTML = `<div style="color:var(--text3);font-family:monospace;font-size:12px">Aucune session active</div>`; return; }
  el.innerHTML = d.sessions.map(s => `
    <div style="display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--bg3);border-radius:var(--r);font-family:monospace;font-size:11px">
      <div class="user-avatar role-${s.role}" style="width:26px;height:26px;font-size:10px">${h((s.name||s.username)[0].toUpperCase())}</div>
      <div style="flex:1">
        <div style="color:var(--text);font-weight:600">${h(s.name||s.username)} <span style="color:var(--text3)">@${h(s.username)}</span></div>
        <div style="color:var(--text3);margin-top:2px">IP: ${h(s.ip||'?')} — expire ${timeAgo(s.expiresAt)}</div>
      </div>
      <span class="badge ${s.role==='admin'?'gn':s.role==='operator'?'bl':'gy'}">${h(s.role)}</span>
    </div>`).join('');
}

async function hashPw() {
  const pw = document.getElementById('pw-input').value;
  if (!pw) return;
  const d = await api('/auth/hash', { method: 'POST', body: JSON.stringify({ password: pw }) });
  const box = document.getElementById('hash-result');
  box.className = 'hash-box show';
  box.textContent = d.digest || d.error || 'Erreur';
  document.getElementById('pw-input').value = '';
}

// copyToken replaced by clipboard on user info
