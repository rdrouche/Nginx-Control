'use strict';
/**
 * Centre de notification (cloche d'en-tête) et page "Notifications"
 * (historique complet, paginé et filtrable). Extrait de public/index.html
 * (voir CHANGELOG.md). Feature "modulable" : aucune autre fonctionnalité
 * n'a besoin de connaître ce fichier, qui se contente d'afficher ce que
 * GET /api/notifications renvoie (lib/notifications.js côté serveur).
 */
// Feature "modulable" au sens ou aucune autre fonctionnalite n a besoin de
// connaitre ce fichier : elle appelle pushNotification() cote serveur
// (lib/notifications.js), et cette section se contente d afficher ce que
// GET /api/notifications renvoie. Fix v12.21.2 : son propre cycle de poll,
// independant de poll() (statut/metriques), au rythme configurable via
// NOTIF_POLL_INTERVAL_SEC (voir lib/config.js et window.NOTIF_POLL_INTERVAL_MS) —
// pas de flux SSE dedie ici, pour rester coherent avec le reste du dashboard
// qui fonctionne deja tout en polling.
let notifItems = [];
let notifUnreadCount = 0;
let notifDropdownOpen = false;
let notifCloseHandler = null;

async function notifCenterPoll(){
  const d = await api('/notifications?limit=30');
  notifItems = d.notifications || [];
  notifUnreadCount = d.unreadCount || 0;
  renderNotifBadge();
  if (notifDropdownOpen) renderNotifList();
}

function renderNotifBadge(){
  const badge = document.getElementById('notif-badge');
  const bell = document.getElementById('notif-bell');
  const navBadge = document.getElementById('notif-nav-badge');
  if (navBadge) navBadge.textContent = notifUnreadCount > 99 ? '99+' : String(notifUnreadCount);
  if (!badge || !bell) return;
  if (notifUnreadCount > 0) {
    badge.style.display = 'flex';
    badge.textContent = notifUnreadCount > 99 ? '99+' : String(notifUnreadCount);
    bell.classList.add('has-unread');
  } else {
    badge.style.display = 'none';
    bell.classList.remove('has-unread');
  }
}

const NOTIF_LEVEL_CLASS = { info: 'lvl-info', success: 'lvl-success', warning: 'lvl-warning', error: 'lvl-error' };

function renderNotifList(){
  const list = document.getElementById('notif-list');
  if (!list) return;
  if (!notifItems.length) {
    list.innerHTML = `<div class="notif-empty" data-i18n="notifCenter.empty">${t('notifCenter.empty')}</div>`;
    return;
  }
  list.innerHTML = notifItems.map(n => `
    <div class="notif-item ${NOTIF_LEVEL_CLASS[n.level]||'lvl-info'} ${n.read?'':'unread'}" data-id="${n.id}" onclick="notifMarkRead(${n.id})">
      <span class="notif-item-dot"></span>
      <div class="notif-item-body">
        <div class="notif-item-msg">${h(n.message)}</div>
        <div class="notif-item-meta"><span>${timeAgo(n.ts)}</span><span>·</span><span>${h(n.type)}</span></div>
      </div>
      <button class="notif-item-del" title="${t('notifCenter.dismiss')}" data-i18n-title="notifCenter.dismiss" onclick="event.stopPropagation();notifDelete(${n.id})">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M4 4l8 8M12 4l-8 8"/></svg>
      </button>
    </div>`).join('');
}

function toggleNotifCenter(ev){
  ev?.stopPropagation();
  notifDropdownOpen = !notifDropdownOpen;
  const dd = document.getElementById('notif-dropdown');
  if (!dd) return;
  dd.style.display = notifDropdownOpen ? 'flex' : 'none';
  if (notifDropdownOpen) {
    // Affiche d abord ce qu on a deja (cache notifItems, evite un flash vide),
    // puis rafraichit immediatement depuis le serveur : sans ce fetch immediat,
    // le dropdown ne montrait que les donnees du dernier cycle poll() (5s) —
    // une notification poussee dans l intervalle restait invisible tant que le
    // prochain tick n avait pas eu lieu (bug reel constate en test manuel).
    renderNotifList();
    notifCenterPoll().catch(e => console.warn('[notifCenter] refresh a l ouverture :', e?.message||e));
    if (notifCloseHandler) document.removeEventListener('click', notifCloseHandler);
    notifCloseHandler = (e) => {
      if (!document.getElementById('notif-center')?.contains(e.target)) {
        notifDropdownOpen = false;
        dd.style.display = 'none';
        document.removeEventListener('click', notifCloseHandler);
        notifCloseHandler = null;
      }
    };
    // Deferre : le clic qui vient d ouvrir le dropdown ne doit pas aussi le fermer.
    setTimeout(() => document.addEventListener('click', notifCloseHandler), 0);
  }
}

async function notifMarkRead(id){
  const item = notifItems.find(n => n.id === id);
  if (item && !item.read) { item.read = true; renderNotifList(); }
  try { await api(`/notifications/${id}/read`, { method: 'POST' }); } catch(e) { console.warn('[notifCenter] markRead:', e?.message||e); }
  notifCenterPoll();
}

async function notifDelete(id){
  notifItems = notifItems.filter(n => n.id !== id);
  renderNotifList();
  try { await api(`/notifications/${id}`, { method: 'DELETE' }); } catch(e) { console.warn('[notifCenter] delete:', e?.message||e); }
  notifCenterPoll();
}

async function notifMarkAllRead(){
  notifItems.forEach(n => n.read = true);
  renderNotifList();
  try { await api('/notifications/read-all', { method: 'POST' }); } catch(e) { console.warn('[notifCenter] markAllRead:', e?.message||e); }
  notifCenterPoll();
}

async function notifClearRead(){
  notifItems = notifItems.filter(n => !n.read);
  renderNotifList();
  try { await api('/notifications/clear-read', { method: 'POST' }); } catch(e) { console.warn('[notifCenter] clearRead:', e?.message||e); }
  notifCenterPoll();
}

async function notifClearAll(){
  notifItems = [];
  renderNotifList();
  try { await api('/notifications/clear', { method: 'POST' }); } catch(e) { console.warn('[notifCenter] clearAll:', e?.message||e); }
  notifCenterPoll();
}

// ── Page Notifications (historique complet) ─────────────────────────────────
// La cloche d en-tete (ci-dessus) n affiche que les ~30 dernieres entrees —
// cette page dediee (nav "Notifications", entre Cache et le reste de la
// section Contrôle) permet de retrouver et filtrer tout l historique,
// charge par pages successives plutot que d un coup.
let notifPageItems = [];
let notifPageOffset = 0;
let notifPageHasMore = true;
const NOTIF_PAGE_LIMIT = 50;

async function loadNotificationsPage(){
  notifPageItems = [];
  notifPageOffset = 0;
  notifPageHasMore = true;
  await notifPageFetchMore();
}

async function notifPageFetchMore(){
  const d = await api(`/notifications?limit=${NOTIF_PAGE_LIMIT}&offset=${notifPageOffset}`);
  if (!d) return;
  const batch = d.notifications || [];
  notifPageItems = notifPageItems.concat(batch);
  notifPageOffset += batch.length;
  notifPageHasMore = batch.length === NOTIF_PAGE_LIMIT;
  const moreBtn = document.getElementById('notif-page-more');
  if (moreBtn) moreBtn.style.display = notifPageHasMore ? '' : 'none';
  renderNotifPageList();
}

function notifPageLoadMore(){ notifPageFetchMore(); }

function notifPageFilteredEntries(){
  const q     = (document.getElementById('notif-page-search')?.value || '').trim().toLowerCase();
  const level = document.getElementById('notif-page-level')?.value || 'all';
  const state = document.getElementById('notif-page-state')?.value || 'all';
  return notifPageItems.filter(n => {
    if (level !== 'all' && n.level !== level) return false;
    if (state === 'unread' && n.read) return false;
    if (state === 'read' && !n.read) return false;
    if (q && !`${n.message} ${n.type}`.toLowerCase().includes(q)) return false;
    return true;
  });
}

function renderNotifPageList(){
  const list = document.getElementById('notif-page-list');
  if (!list) return;
  const entries = notifPageFilteredEntries();
  if (!entries.length) {
    list.innerHTML = `<div class="notif-empty">${t('notifCenter.empty')}</div>`;
    return;
  }
  list.innerHTML = entries.map(n => `
    <div class="notif-item ${NOTIF_LEVEL_CLASS[n.level]||'lvl-info'} ${n.read?'':'unread'}" data-id="${n.id}" onclick="notifPageMarkRead(${n.id})">
      <span class="notif-item-dot"></span>
      <div class="notif-item-body">
        <div class="notif-item-msg">${h(n.message)}</div>
        <div class="notif-item-meta"><span>${new Date(n.ts).toLocaleString()}</span><span>·</span><span>${h(n.type)}</span></div>
      </div>
      <button class="notif-item-del" title="${t('notifCenter.dismiss')}" onclick="event.stopPropagation();notifPageDelete(${n.id})">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M4 4l8 8M12 4l-8 8"/></svg>
      </button>
    </div>`).join('');
}

async function notifPageMarkRead(id){
  const item = notifPageItems.find(n => n.id === id);
  if (item && !item.read) { item.read = true; renderNotifPageList(); }
  try { await api(`/notifications/${id}/read`, { method: 'POST' }); } catch(e) { console.warn('[notifCenter] markRead:', e?.message||e); }
  notifCenterPoll();
}

async function notifPageDelete(id){
  notifPageItems = notifPageItems.filter(n => n.id !== id);
  renderNotifPageList();
  try { await api(`/notifications/${id}`, { method: 'DELETE' }); } catch(e) { console.warn('[notifCenter] delete:', e?.message||e); }
  notifCenterPoll();
}

async function notifPageMarkAllRead(){
  notifPageItems.forEach(n => n.read = true);
  renderNotifPageList();
  try { await api('/notifications/read-all', { method: 'POST' }); } catch(e) { console.warn('[notifCenter] markAllRead:', e?.message||e); }
  notifCenterPoll();
}

async function notifPageClearRead(){
  notifPageItems = notifPageItems.filter(n => !n.read);
  renderNotifPageList();
  try { await api('/notifications/clear-read', { method: 'POST' }); } catch(e) { console.warn('[notifCenter] clearRead:', e?.message||e); }
  notifCenterPoll();
}

async function notifPageClearAll(){
  notifPageItems = [];
  renderNotifPageList();
  try { await api('/notifications/clear', { method: 'POST' }); } catch(e) { console.warn('[notifCenter] clearAll:', e?.message||e); }
  notifCenterPoll();
}

// Depuis le dropdown de la cloche : ferme le dropdown et bascule sur la
// page complete, plutot que de dupliquer la liste dans les deux endroits.
function notifGoToHistoryPage(){
  document.getElementById('notif-dropdown').style.display = 'none';
  notifDropdownOpen = false;
  openPage('notif-history');
}
