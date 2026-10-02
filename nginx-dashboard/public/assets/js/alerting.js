'use strict';
/**
 * Message important (alertes distantes, ALERTING_URL) — v12.45.0. Extrait
 * dans son propre fichier des le depart (pas d ajout inline dans index.html,
 * retour utilisateur explicite), meme discipline que crowdsec.js/agents.js/
 * system-info.js : charge apres le script inline principal, partage le meme
 * scope global (api(), t(), h(), svgEsc(), timeAgo(), notifCenterPoll(),
 * renderSimpleMarkdown()/inlineMd() de system-info.js), pas un module ES.
 *
 * Le client ne parle JAMAIS directement a ALERTING_URL : il n appelle que
 * GET /api/alerting/unread (ce qui est deja en base) et GET /api/alerting/
 * history — c est le planificateur cote serveur (features/alerting.js), seul,
 * qui sort vers l exterieur. Idem pour "marquer lu" : on reutilise tel quel
 * POST /api/notifications/<id>/read (deja existant pour la cloche d en-tete),
 * aucune route de plus a maintenir.
 *
 * Etat de session (perdu au rechargement de la page, c est voulu) :
 * alertingShownIds retient les notifications deja poussees en modale ce
 * cycle de navigation, pour ne pas rouvrir la modale a chaque sondage
 * horaire tant qu aucune alerte VRAIMENT nouvelle n est apparue. Une alerte
 * deja affichee puis fermee sans etre marquee lue reste "non lue" cote
 * serveur (et donc toujours visible via le bouton "Alertes" de la page
 * Systeme), mais ne rouvre pas la modale toute seule — seule une alerte
 * jamais vue le fait.
 */

let alertingShownIds = new Set();
let alertingCurrentAlerts = [];
let alertingNotifiedDenied = false; // evite de re-tenter Notification.requestPermission() une fois refusee

// ── Sondage (verification au chargement + toutes les heures) ────────────────
async function alertingCheck() {
  const d = await api('/alerting/unread').catch(() => null);
  if (!d || !d.configured || !d.enabled) return;
  const alerts = d.alerts || [];
  const newOnes = alerts.filter(a => !alertingShownIds.has(a.id));
  if (!newOnes.length) return;
  newOnes.forEach(a => alertingShownIds.add(a.id));
  // La modale montre l ensemble des alertes non lues actuelles (pas
  // seulement les nouvelles) : un operateur qui revient doit voir toutes
  // celles en attente, pas seulement le dernier lot.
  alertingCurrentAlerts = alerts;
  alertingRenderModal();
  alertingNotifyBrowser(newOnes);
}

// ── Modale forcee (connexion / nouvelle alerte) ──────────────────────────────
const ALERT_LEVEL_LABEL = { info: 'notifCenter.levelInfo', success: 'notifCenter.levelSuccess', warning: 'notifCenter.levelWarning', error: 'notifCenter.levelError' };

function alertingRenderModal() {
  const overlay = document.getElementById('alerting-overlay');
  const body = document.getElementById('alerting-content');
  if (!overlay || !body) return;
  if (!alertingCurrentAlerts.length) { alertingClose(); return; }
  body.innerHTML = alertingCurrentAlerts.map(a => `
    <div class="card ${NOTIF_LEVEL_CLASS[a.level] || 'lvl-info'}" style="margin-bottom:12px;padding:12px 14px">
      <div class="row" style="margin-bottom:6px">
        <div style="font-weight:600">${h(a.title)}</div>
        <span style="font-size:11px;color:var(--text3)">${timeAgo(a.ts)} · ${svgEsc(t(ALERT_LEVEL_LABEL[a.level] || 'notifCenter.levelInfo'))}</span>
      </div>
      <div class="changelog-md">${renderSimpleMarkdown(a.body || '')}</div>
      <div style="margin-top:8px;text-align:right">
        <button class="btn sm primary" onclick="alertingMarkRead(${a.id})">&#10003; <span data-i18n="alerting.markRead">Lu</span></button>
      </div>
    </div>`).join('');
  overlay.style.display = 'flex';
}

function alertingClose() {
  const overlay = document.getElementById('alerting-overlay');
  if (overlay) overlay.style.display = 'none';
}

async function alertingMarkRead(id) {
  await api('/notifications/' + id + '/read', { method: 'POST' }).catch(() => {});
  alertingCurrentAlerts = alertingCurrentAlerts.filter(a => a.id !== id);
  if (alertingCurrentAlerts.length) alertingRenderModal();
  else alertingClose();
  notifCenterPoll().catch(() => {});
  // Si l historique (page Systeme) est ouvert en parallele, le refleter aussi.
  if (document.getElementById('alerting-history-overlay')?.style.display === 'flex') alertingHistoryOpen();
}

// ── Notification navigateur ───────────────────────────────────────────────────
/**
 * Demande la permission de facon paresseuse : seulement quand une alerte
 * vraiment nouvelle arrive, jamais au chargement de la page. Ne redemande
 * jamais si l utilisateur a deja refuse (Notification.permission === 'denied')
 * — un rappel systematique serait plus genant qu utile. Aucune erreur si
 * l API Notification n existe pas (navigateur ancien, contexte non-HTTPS
 * sur certains navigateurs, etc.) : no-op silencieux.
 */
function alertingNotifyBrowser(newOnes) {
  if (typeof Notification === 'undefined' || !newOnes.length) return;
  const fire = () => {
    newOnes.slice(0, 3).forEach(a => {
      try { new Notification(a.title, { body: (a.body || '').slice(0, 200), tag: 'alerting-' + a.id }); }
      catch (e) { console.warn('[alerting] Notification navigateur impossible :', e?.message || e); }
    });
  };
  if (Notification.permission === 'granted') return fire();
  if (Notification.permission === 'denied' || alertingNotifiedDenied) return;
  Notification.requestPermission().then(p => {
    if (p === 'granted') fire();
    else alertingNotifiedDenied = true;
  }).catch(() => { alertingNotifiedDenied = true; });
}

// ── Historique (page Systeme, bouton "Alertes") ──────────────────────────────
async function alertingHistoryOpen() {
  const overlay = document.getElementById('alerting-history-overlay');
  const body = document.getElementById('alerting-history-content');
  if (!overlay || !body) return;
  overlay.style.display = 'flex';
  body.innerHTML = `<div style="color:var(--text3);font-size:12px;padding:12px 0">${svgEsc(t('common.loading'))}</div>`;
  const d = await api('/alerting/history').catch(() => null);
  if (!d || !d.alerts || !d.alerts.length) {
    body.innerHTML = `<div style="color:var(--text3);font-size:12px" data-i18n="alerting.history.empty">${svgEsc(t('alerting.history.empty'))}</div>`;
    return;
  }
  body.innerHTML = d.alerts.map(a => `
    <div class="card ${NOTIF_LEVEL_CLASS[a.level] || 'lvl-info'} ${a.read ? '' : 'unread'}" style="margin-bottom:12px;padding:12px 14px">
      <div class="row" style="margin-bottom:6px">
        <div style="font-weight:600">${h(a.title)}</div>
        <span style="font-size:11px;color:var(--text3)">${timeAgo(a.ts)} · ${svgEsc(t(ALERT_LEVEL_LABEL[a.level] || 'notifCenter.levelInfo'))}</span>
      </div>
      <div class="changelog-md">${renderSimpleMarkdown(a.body || '')}</div>
      ${a.read ? '' : `<div style="margin-top:8px;text-align:right">
        <button class="btn sm primary" onclick="alertingHistoryMarkRead(${a.id})">&#10003; <span data-i18n="alerting.markRead">Lu</span></button>
      </div>`}
    </div>`).join('');
}

function alertingHistoryClose() {
  const overlay = document.getElementById('alerting-history-overlay');
  if (overlay) overlay.style.display = 'none';
}

async function alertingHistoryMarkRead(id) {
  await api('/notifications/' + id + '/read', { method: 'POST' }).catch(() => {});
  alertingCurrentAlerts = alertingCurrentAlerts.filter(a => a.id !== id);
  notifCenterPoll().catch(() => {});
  alertingHistoryOpen();
}

async function alertingRefreshNow() {
  await api('/alerting/refresh', { method: 'POST' }).catch(() => {});
  await alertingHistoryOpen();
  await alertingCheck();
}
