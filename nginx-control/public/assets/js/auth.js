'use strict';
/**
 * Authentification / session côté client : chargement de l'utilisateur
 * courant, permissions de navigation, et visibilité conditionnelle des
 * items de menu optionnels (CrowdSec, GoAccess, WAF, GoDNS, ...) selon la
 * configuration serveur. Extrait de public/index.html (voir CHANGELOG.md).
 * Appelé depuis Boot (index.html) via initAuth().
 */
let currentUser = null;

async function initAuth() {
  try {
    const me = await fetch('/api/auth/me', { headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin' });
    if (me.status === 401) { window.location.href = '/auth/login'; return false; }
    currentUser = await me.json();
    // Update header user pill
    const initials = (currentUser.name || currentUser.username || '?').split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
    document.getElementById('user-avatar').textContent = initials;
    document.getElementById('user-avatar').className = 'user-avatar role-' + currentUser.role;
    document.getElementById('user-name').textContent = currentUser.name || currentUser.username;
    document.getElementById('user-role').textContent = currentUser.role;
    // Show admin section if admin
    if (currentUser.role === 'admin') {
      document.getElementById('nav-admin-section').style.display = '';
      document.getElementById('nav-admin').style.display = '';
      document.getElementById('nav-notify').style.display = '';
      document.getElementById('nav-scheduler').style.display = '';
      document.getElementById('nav-config-editor').style.display = '';
      document.getElementById('nav-system-info').style.display = '';
    }
    // Disable nav items based on permissions
    applyPermissionsToNav();
    checkOptionalFeatures().catch(() => {});
    applyTranslations();
    return true;
  } catch(e) { return false; }
}

function hasPerm(perm) {
  return currentUser?.permissions?.includes(perm);
}

function applyPermissionsToNav() {
  if (!currentUser) return;
  // Gray out items the user can't access
  const permMap = {
    configs:   'view_configs',
    ssl:       'view_ssl',
    logviewer: 'view_logs',
    control:   'nginx_control',
    webhooks:  'manage_webhooks',
    'docker-autoconfig': 'view_configs',
    agents:    'view_configs',
  };
  Object.entries(permMap).forEach(([page, perm]) => {
    const el = document.querySelector(`.ni[data-page="${page}"]`);
    if (el && !hasPerm(perm)) {
      el.style.opacity = '.4';
      el.style.pointerEvents = 'none';
      el.title = 'Accès refusé — permissions insuffisantes';
    }
  });
}

async function checkOptionalFeatures() {
  // CrowdSec
  const cs = await api('/crowdsec/status').catch(() => null);
  if (cs?.configured) {
    document.getElementById('nav-crowdsec').style.display = '';
  } else {
    document.getElementById('nav-crowdsec').style.display = 'none';
  }
  // GoAccess
  const ga = await api('/goaccess/sources').catch(() => null);
  if (ga?.configured) {
    document.getElementById('nav-goaccess').style.display = '';
    document.getElementById('ga-count').textContent = ga.sources?.length || 0;
  } else {
    document.getElementById('nav-goaccess').style.display = 'none';
  }
  // WAF / GoDNS — visibilite reglable (config/menu.yml ou MENU_WAF/MENU_GODNS),
  // WAF avec un mode "auto" en plus (detecte via le suffixe -waf/-coraza de
  // l image nginx en cours) — voir lib/menu-visibility.js. Repli sur "affiche"
  // si la route echoue, pour ne jamais masquer une page par erreur reseau.
  const mv = await api('/menu-visibility').catch(() => null);
  document.getElementById('nav-waf').style.display = (mv && mv.waf.visible === false) ? 'none' : '';
  document.getElementById('nav-godns').style.display = (mv && mv.godns.visible === false) ? 'none' : '';
  // REST API / Webhooks (v12.41.0) : sous Administration, donc admin
  // uniquement de toute facon (nav-admin-section reste masque pour les
  // autres roles) — sans quoi un item affiche ici pour un non-admin
  // apparaitrait "orphelin", sans l en-tete de section qui le precede.
  if (currentUser?.role === 'admin') {
    document.getElementById('nav-api').style.display = (mv && mv.api.visible === false) ? 'none' : '';
    document.getElementById('nav-webhooks').style.display = (mv && mv.webhooks.visible === false) ? 'none' : '';
  }
  // Auto-config Docker / Hotes distants (v12.41.0) : reflete desormais leur
  // propre `enable: true/false` (docker-autoconfig.yml/agents.yml) — un
  // operateur qui desactive la fonctionnalite ne la voit plus dans le menu,
  // au lieu de continuer a afficher une page qui ne fait plus rien.
  document.getElementById('nav-docker-autoconfig').style.display = (mv && mv.dockerAutoconfig.visible === false) ? 'none' : '';
  document.getElementById('nav-agents').style.display = (mv && mv.agents.visible === false) ? 'none' : '';
}
