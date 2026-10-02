'use strict';
/**
 * Message important (v12.45.0, retour utilisateur) — un mecanisme d alerte
 * simple, sur le meme principe que le Changelog distant
 * (features/changelog.js) : un fichier Markdown hors de l image, dont
 * chaque section `## titre` est une alerte independante, identifiee par un
 * `ID:` stable (timestamp Unix au moment de sa redaction, choix de
 * l operateur — voir parseAlertsMarkdown() plus bas). L etat lu/non-lu est
 * delegue entierement a lib/notifications.js (le centre de notification
 * existant) : chaque alerte devient une notification de type 'alerting',
 * avec son ID externe range dans `data.externalId` pour la deduplication au
 * cycle suivant. Rien de nouveau a construire pour "marquer comme lu" —
 * POST /api/notifications/<id>/read (features/notification-center.js) fait
 * deja exactement ca, partage, persistant, identique a la cloche d en-tete.
 *
 * Le fichier distant "vit" (ton du createur du projet) : une alerte qui en
 * disparait n est PAS retiree de l historique local — elle est simplement
 * ignoree au prochain diff (ni repoussee, ni supprimee). L historique local
 * suit sa propre politique de retention (NOTIF_CENTER_RETENTION_DAYS),
 * partagee avec le reste du centre de notification.
 *
 * Desactivable independamment de l URL (voir ALERTING_URL dans
 * lib/config.js) via ALERTING_ENABLE/config/features.yml (lib/feature-flags.js)
 * — utile si l URL est injectee au build (commune a toute une flotte
 * d images) mais qu une instance doit s en desactiver sans y toucher.
 */
const https = require('https');
const http  = require('http');

const cfg          = require('../lib/config');
const httpLib      = require('../lib/http');
const auth         = require('../lib/auth');
const notifications = require('../lib/notifications');
const { isFeatureEnabled } = require('../lib/feature-flags');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { ALERTING_URL, ALERTING_POLL_INTERVAL_MIN } = cfg;

const NOTIF_TYPE = 'alerting';
const MAX_BYTES  = 2 * 1024 * 1024; // 2 Mo — tres large pour un fichier d alertes, evite un telechargement sans limite

/**
 * Meme discipline que fetchChangelog()/fetchVersionFile() : `depth` borne
 * les redirections, toute erreur (URL invalide, DNS mort, timeout, HTTP
 * non-200, fichier trop volumineux) resout `{ error }` plutot que de lever
 * — un fichier inaccessible ou absent ne doit jamais faire planter le
 * dashboard ni le cycle de sondage.
 */
function fetchAlertingFile(fileUrl, depth = 5) {
  return new Promise((resolve) => {
    if (!fileUrl || depth <= 0) return resolve({ error: 'URL invalide ou trop de redirections' });
    let u;
    try { u = new URL(fileUrl); } catch { return resolve({ error: 'URL invalide' }); }
    const proto = u.protocol === 'http:' ? http : https;
    const req = proto.request(u, { method: 'GET', headers: { 'User-Agent': cfg.HTTP_USER_AGENT }, timeout: 8000 }, (res) => {
      if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location) {
        res.resume();
        let next;
        try { next = new URL(res.headers.location, u).toString(); } catch { return resolve({ error: 'Redirection invalide' }); }
        return resolve(fetchAlertingFile(next, depth - 1));
      }
      if (res.statusCode !== 200) { res.resume(); return resolve({ error: `HTTP ${res.statusCode}` }); }
      let data = '';
      let bytes = 0;
      res.on('data', (d) => {
        bytes += d.length;
        if (bytes > MAX_BYTES) { req.destroy(); return resolve({ error: 'Fichier trop volumineux' }); }
        data += d;
      });
      res.on('end', () => resolve({ content: data }));
      res.on('error', (e) => resolve({ error: e.message }));
    });
    req.on('error', (e) => resolve({ error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ error: 'Delai depasse' }); });
    req.end();
  });
}

/**
 * Decoupe le Markdown en alertes independantes sur les titres `## `. Chaque
 * bloc DOIT porter une ligne `ID: <identifiant>` (texte brut, jamais rendu
 * — un simple marqueur de metadonnees, pas du Markdown) juste apres le
 * titre, sinon il est ignore avec un avertissement : sans identifiant
 * stable, impossible de savoir plus tard si cette alerte a deja ete vue,
 * et re-notifier la meme alerte a chaque cycle serait pire que ne pas la
 * traiter du tout. `LEVEL: info|warning|error` est optionnel juste apres
 * (defaut 'info') — mêmes trois niveaux que le reste du centre de
 * notification (lib/notifications.js), pas de vocabulaire supplementaire a
 * maintenir en parallele.
 */
function parseAlertsMarkdown(raw) {
  const alerts = [];
  const blocks = String(raw || '').replace(/\r/g, '').split(/\n(?=##\s+)/);
  for (const block of blocks) {
    const lines = block.split('\n');
    const titleMatch = lines[0].match(/^##\s+(.*)$/);
    if (!titleMatch) continue; // texte avant la premiere alerte, ou fichier vide
    const title = titleMatch[1].trim();
    let i = 1;
    let externalId = null;
    let level = 'info';
    // Les lignes de metadonnees suivent immediatement le titre, dans un ordre
    // libre (ID puis LEVEL, ou l inverse) — on avance tant qu on en reconnait.
    while (i < lines.length) {
      const idMatch = lines[i].match(/^ID:\s*(\S+)\s*$/i);
      const levelMatch = lines[i].match(/^LEVEL:\s*(info|warning|error)\s*$/i);
      if (idMatch) { externalId = idMatch[1]; i++; continue; }
      if (levelMatch) { level = levelMatch[1].toLowerCase(); i++; continue; }
      break;
    }
    if (!externalId) {
      console.warn(`[alerting] Alerte sans "ID:" ignoree (titre : "${title}")`);
      continue;
    }
    // Une ligne vide separe generalement les metadonnees du corps — sautee
    // si presente, sans etre obligatoire (un fichier redige a la main peut
    // l omettre).
    if (lines[i] !== undefined && lines[i].trim() === '') i++;
    const body = lines.slice(i).join('\n').trim();
    alerts.push({ externalId, level, title, body });
  }
  return alerts;
}

const CACHE_TTL_MS = 5 * 60 * 1000; // meme discipline que features/changelog.js : evite de re-telecharger a chaque clic sur "Rafraichir"
let cache = null; // { content, fetchedAt } | { error, fetchedAt }

async function getAlertingFile(forceRefresh) {
  if (!forceRefresh && cache && (Date.now() - cache.fetchedAt) < CACHE_TTL_MS) return cache;
  const result = await fetchAlertingFile(ALERTING_URL);
  cache = { ...result, fetchedAt: Date.now() };
  return cache;
}

/**
 * Le coeur du cycle : recupere le fichier, le decoupe, et pousse une
 * notification pour chaque alerte dont l ID externe n a encore jamais ete
 * vu. Ne renvoie ni ne leve jamais d erreur bloquante — un fichier
 * injoignable/mal forme ne doit jamais interrompre le planificateur ni
 * faire echouer un appel manuel de rafraichissement.
 *
 * Limite connue (acceptee, memes termes que le reste du centre de
 * notification — voir lib/notifications.js) : si node:sqlite est
 * indisponible, l historique retombe en memoire et repart vide a chaque
 * redemarrage — les alertes deja lues avant un redemarrage seraient alors
 * re-notifiees une fois au cycle suivant.
 */
async function runCycle({ forceRefresh = false } = {}) {
  if (!ALERTING_URL) return { configured: false };
  const result = await getAlertingFile(forceRefresh);
  if (result.error) return { configured: true, error: result.error };
  const parsed = parseAlertsMarkdown(result.content);
  const known = new Set(
    notifications.listNotifications({ type: NOTIF_TYPE, limit: 500 })
      .map(n => n.data && n.data.externalId)
      .filter(Boolean)
  );
  let pushed = 0;
  for (const alert of parsed) {
    if (known.has(alert.externalId)) continue;
    notifications.pushNotification({
      type: NOTIF_TYPE,
      level: alert.level,
      message: alert.title,
      data: { externalId: alert.externalId, title: alert.title, body: alert.body },
    });
    pushed++;
  }
  return { configured: true, found: parsed.length, pushed };
}

function notifToAlert(n) {
  return {
    id: n.id, // id interne — reutilise directement par POST /api/notifications/<id>/read
    ts: n.ts,
    level: n.level,
    read: n.read,
    externalId: n.data ? n.data.externalId : null,
    title: n.data ? n.data.title : n.message,
    body: n.data ? n.data.body : '',
  };
}

// ─── Scheduling ─────────────────────────────────────────────────────────────
// Meme schema auto-suffisant que features/docker-autoconfig.js#startScheduler()
// et features/blocklists.js#startBlocklistScheduler() : cet intervalle
// n est pas branche sur lib/scheduler.js, il s administre lui-meme.
let pollTimer = null;

function startScheduler() {
  if (pollTimer) return;
  const tick = () => {
    if (!isFeatureEnabled('alerting')) return;
    runCycle().catch(e => console.error('[alerting] cycle error:', e.message));
  };
  pollTimer = setInterval(tick, ALERTING_POLL_INTERVAL_MIN * 60 * 1000);
  pollTimer.unref();
  // Pas de premier cycle immediat au demarrage (contrairement a une
  // relecture de config) — meme choix que
  // features/docker-autoconfig.js#startScheduler() : un operateur qui vient
  // d activer la fonctionnalite et de renseigner ALERTING_URL dispose deja
  // du bouton "Rafraichir maintenant" (POST /api/alerting/refresh, page
  // Systeme) pour la toute premiere verification, sans avoir a attendre
  // jusqu a ALERTING_POLL_INTERVAL_MIN (une heure par defaut).
}

function register(router) {
  // GET non lues — appele au chargement de la page et toutes les heures par
  // public/assets/js/alerting.js. Ne declenche JAMAIS de requete vers
  // ALERTING_URL lui-meme : c est le planificateur serveur, seul, qui parle
  // a l exterieur (voir startScheduler() ci-dessus) — un onglet ouvert par
  // operateur ne doit pas multiplier les appels sortants.
  router.get('/api/alerting/unread', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    if (!ALERTING_URL) return send(res, 200, { configured: false, enabled: false, alerts: [] });
    const enabled = isFeatureEnabled('alerting');
    if (!enabled) return send(res, 200, { configured: true, enabled: false, alerts: [] });
    const alerts = notifications.listNotifications({ type: NOTIF_TYPE, unreadOnly: true, limit: 50 }).map(notifToAlert);
    return send(res, 200, { configured: true, enabled: true, alerts });
  });

  // Historique complet (lues et non lues) — page Systeme, bouton "Alertes".
  router.get('/api/alerting/history', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const alerts = notifications.listNotifications({ type: NOTIF_TYPE, limit: 50 }).map(notifToAlert);
    return send(res, 200, { configured: !!ALERTING_URL, enabled: isFeatureEnabled('alerting'), alerts });
  });

  // Rafraichissement manuel (bouton de la page Systeme) — meme role que
  // GET /api/changelog?refresh=1, mais doit aussi POUSSER les nouvelles
  // alertes (pas seulement relire le cache) puisqu il n y a pas de rendu
  // direct du fichier ici, seulement le centre de notification comme source
  // de verite pour le frontend.
  router.post('/api/alerting/refresh', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    if (!ALERTING_URL) return send(res, 200, { configured: false });
    if (!isFeatureEnabled('alerting')) return send(res, 200, { configured: true, enabled: false });
    const result = await runCycle({ forceRefresh: true });
    return send(res, 200, result);
  });
}

module.exports = { register, startScheduler, runCycle, fetchAlertingFile, parseAlertsMarkdown };
