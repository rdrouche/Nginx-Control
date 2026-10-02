'use strict';
/**
 * Planificateur de tâches récurrentes.
 *
 * Les tâches (rechargement/redémarrage nginx, redémarrage analyzer, sauvegarde,
 * résumé, redémarrage GoAccess…) sont stockées en base (lib/scheduler-store.js),
 * créées depuis la page « Scheduler » (formulaire visuel) et exécutées par le
 * registre lib/scheduler-tasks.js. Le fichier `scheduler.yml` n'est plus lu que
 * pour l'import initial.
 *
 * La boucle tourne toutes les 30 s mais n'agit qu'une fois par minute ; les
 * tâches sont relues à chaque minute, donc une modification faite dans
 * l'interface prend effet sans redémarrage. Une tâche n'est jamais lancée deux
 * fois en parallèle (si la précédente exécution dure encore, la suivante est
 * ignorée).
 *
 * Les tâches de nginx (reload, restart) exécutent d'abord `nginx -t` et
 * s'abstiennent si la configuration est invalide : une configuration cassée ne
 * doit pas être poussée en production par un job à 3 h du matin.
 *
 * Les dépendances qui appartiennent à une feature (sauvegarde, GoAccess,
 * analyzer…) sont injectées par server.js plutôt qu'importées, ce qui garde ce
 * module libre de toute dépendance vers les features.
 *
 * Restent codées en dur, hors liste de tâches : la vérification quotidienne de
 * l'expiration des certificats (règles de notifications.yml) et le recheck SSL
 * des agents distants (toutes les 5 minutes).
 */

const cfg    = require('./config');
const docker = require('./docker');
const notify = require('./notify');
const certs  = require('./certs');
const events = require('./events');
const { pushNotification } = require('./notifications');
const store    = require('./scheduler-store');
const registry = require('./scheduler-tasks');
const { cronMatches } = require('./schedule-cron');

const { execNginx } = docker;
const { sendNotification, sendMail, reloadAll, getSchedConfig, getNotifConfig,
        loadSmtpConfig, loadNotifConfig, loadSchedConfig } = notify;
const { getAllCertificates, adaptiveThreshold } = certs;
const { logEvent } = events;

// Dedup pour checkCertExpiry() : evite de repousser la meme notification
// (meme certificat, meme type) plus d une fois par jour calendaire, meme si
// le tick qui l appelle passe plus souvent (voir startScheduler() plus bas).
// Cle : `${type}:${identifiant du certificat}` -> 'YYYY-MM-DD' du dernier
// push. Volontairement en memoire (pas persiste) : au pire un redemarrage
// du conteneur peut redeclencher une notification deja vue le jour meme,
// bien moins genant qu un spam a chaque tick.
const lastCertNotifDay = new Map();
function pushCertNotificationOnce(type, level, certKey, message, data) {
  const day = new Date().toISOString().slice(0, 10);
  const dedupKey = `${type}:${certKey}`;
  if (lastCertNotifDay.get(dedupKey) === day) return;
  lastCertNotifDay.set(dedupKey, day);
  pushNotification({ type, level, message, data });
}

// Injected at boot — see the module header.
const tasks = {
  createBackupZip:   async () => { throw new Error('backup not wired'); },
  gitBackupPush:     async () => { throw new Error('git backup not wired'); },
  restartAnalyzer: async () => { throw new Error('analyzer restart not wired'); },
  listGoAccessSources: () => [],
  getGoAccessContainerStatus: async () => ({ running: false }),
  restartGoAccessContainer:   async () => {},
  // Fix (audit report, Basse/"Agents (dashboard)"): Docker auto-config
  // (Partie 1) already re-resolves every vhost's SSL status on its own
  // periodic poll cycle (features/docker-autoconfig.js's runCycle(), on a
  // timer independent of any external event) — a certbot_http/certbot_dns
  // issuance that completes asynchronously always gets picked up on the very
  // next cycle. Remote agents (Partie 2) had NO equivalent: a vhost only
  // ever got regenerated when the agent itself pushed a fresh manifest, so
  // an issuance completing after that push already returned stayed on plain
  // HTTP forever if the agent never happened to push again. Defaults to
  // "nothing to check" so a boot order (or a test) that never called
  // setDeps() is a safe no-op, same discipline as every other stub here.
  listAgentsNeedingSslRecheck: () => [],
  reapplyAgentManifest: async () => ({ ok: false, error: 'reapplyAgentManifest not wired' }),
  // Defaults to the real implementations so production behavior is
  // unchanged; tests override these via setTasks() to exercise the
  // scheduling/safety-gate logic without a real Docker socket.
  runCertsync: async () => ({ ok: false, message: 'runCertsync not wired' }),
  listCertsyncRemotes: () => [],
  execNginx,
  restartContainer: (...args) => docker.restartContainer(...args),
};

function setTasks(overrides) { Object.assign(tasks, overrides); }

let notifCfg  = null;

/** Rétro-compatibilité : l'ancien appel `matchCron(cron, date)`. */
function matchCron(cron, now) {
  try { return cronMatches(cron, now); } catch { return false; }
}

// Exécutions en cours, par identifiant de tâche : une tâche lente (sauvegarde,
// redémarrage avec attente) ne doit jamais se chevaucher elle-même.
const running = new Map();

/**
 * Exécute UNE tâche (planifiée ou lancée à la main), enregistre le résultat dans
 * l'historique et le journal d'événements. Ne lève jamais d'exception.
 * @returns {{status:'ok'|'error'|'skipped'|'busy', message:string, durationMs?:number}}
 */
async function runTask(task, { trigger = 'schedule', by = null } = {}) {
  const type = registry.getType(task.type);
  if (!type) return { status: 'error', message: `type de tâche inconnu : ${task.type}` };
  if (running.has(task.id)) return { status: 'busy', message: 'Cette tâche est déjà en cours d\'exécution' };
  running.set(task.id, Date.now());
  const startedAt = Date.now();
  console.log(`[scheduler] Tâche « ${task.name} » (${task.type}) — ${trigger}`);
  let res;
  try {
    res = await type.run(task.params || {}, { tasks, task });
    if (!res || !['ok', 'error', 'skipped'].includes(res.status)) res = { status: 'ok', message: (res && res.message) || '' };
  } catch (e) {
    const msg = (e && (e.message || e.error)) || String(e);
    console.error(`[scheduler] Tâche « ${task.name} » en erreur :`, msg);
    pushNotification({ type: 'scheduled_task_failed', level: 'error', message: `Tâche planifiée « ${task.name} » en échec : ${msg}` });
    res = { status: 'error', message: msg };
  } finally {
    running.delete(task.id);
  }
  const durationMs = Date.now() - startedAt;
  try { store.recordRun(task.id, { startedAt, durationMs, status: res.status, message: res.message, trigger, by }); }
  catch (e) { console.warn('[scheduler] historique non enregistré :', e.message); }
  logEvent('scheduler.task', { id: task.id, name: task.name, type: task.type, status: res.status, trigger, by, durationMs }, 'scheduler');
  return { ...res, durationMs };
}

/** Lance une tâche à la demande (bouton « Exécuter maintenant »). */
async function runTaskNow(id, by) {
  const task = store.getTask(id);
  if (!task) return { status: 'error', message: 'tâche introuvable', notFound: true };
  return runTask(task, { trigger: 'manual', by });
}

function isRunning(id) { return running.has(Number(id)); }

/** Listes dynamiques du formulaire (ex. conteneurs GoAccess) : { value, label }[]. */
function resolveOptions(name) {
  if (name === 'goaccess_sources') {
    return (tasks.listGoAccessSources() || []).map(src => ({ value: src.id, label: src.name || src.id }));
  }
  if (name === 'certsync_remotes') return tasks.listCertsyncRemotes() || [];
  return [];
}

/**
 * Fix (audit report, Basse/"Agents (dashboard)"): give agent vhosts the same
 * periodic re-check Docker auto-config's own poll cycle already gives Partie
 * 1's vhosts (see the `tasks.listAgentsNeedingSslRecheck` comment above for
 * the full scenario). Unconditional — unlike the other scheduled tasks in
 * this file, this one isn't gated by a scheduler.yml toggle: it's a
 * consistency fix for an existing feature (agents' own certbot_http/
 * certbot_dns SSL modes), not a new opt-in behavior, and it costs nothing
 * when there are no agents (or none currently mid-issuance) to check.
 * Errors are isolated per agent so one agent's failure (a stale/unreachable
 * one, say) never blocks the others in the same run.
 */
async function runScheduledAgentSslRecheck() {
  const candidates = tasks.listAgentsNeedingSslRecheck();
  if (!candidates.length) return;
  console.log(`[scheduler] Agent SSL recheck: ${candidates.length} agent(s)`);
  for (const agentId of candidates) {
    try {
      const result = await tasks.reapplyAgentManifest(agentId);
      if (result?.ok) logEvent('scheduler.agent_ssl_recheck', `Agent ${agentId} re-applique (recheck SSL)`);
    } catch(e) {
      console.error(`[scheduler] Agent SSL recheck error (${agentId}):`, e.message);
    }
  }
}

async function checkCertExpiry() {
  const cfg = notifCfg?.cert_expiry;
  if (!cfg?.enable) return;
  const daysWarn   = parseInt(cfg.days_before) || 30;
  const daysUrgent = parseInt(cfg.urgent_days) || 5;
  // getAllCertificates() couvre a la fois les certificats geres par Certbot
  // (DIR_CERTS/live) ET ceux deposes manuellement sur la page SSL
  // (DIR_SSL) — auparavant cette verification n utilisait que
  // listExistingCerts() (Certbot uniquement), si bien qu un certificat
  // importe manuellement n avait jamais aucune chance de generer une
  // alerte d expiration, silencieusement.
  const { certificates } = getAllCertificates();
  for (const cert of certificates) {
    if (cert.error || !cert.validTo || cert.daysLeft == null) continue;
    const days  = cert.daysLeft;
    const label = (cert.sans && cert.sans.length) ? cert.sans.join(', ') : (cert.domain || cert.name);
    const certKey = cert.fingerprint256 || cert.path || label;
    // Seuils adaptes a la duree de vie reelle du certificat (voir
    // adaptiveThreshold() dans lib/certs.js) : un certificat delivre pour
    // seulement 30 jours (certains fournisseurs ACME) ne doit pas basculer
    // en "bientot expire" des sa delivrance juste parce que le seuil
    // configure (30 jours par defaut) vaut alors 100% de sa duree de vie.
    const warnDays   = adaptiveThreshold(cert.totalDays, daysWarn);
    const urgentDays = Math.min(daysUrgent, warnDays > 1 ? warnDays - 1 : warnDays);
    const data = { name: cert.name, domain: cert.domain, sans: cert.sans, notAfter: cert.validTo, daysLeft: days, totalDays: cert.totalDays };
    if (days < 0) {
      // Deja expire — auparavant ce cas ne generait strictement aucune alerte
      // (ni email, ni journal), silencieusement : ni la branche "urgent"
      // (days >= 0), ni la branche "warning" ci-dessous ne le couvraient.
      pushCertNotificationOnce('cert_expired', 'error', certKey,
        `Certificat ${label} expire depuis ${Math.abs(days)} jour(s) (${cert.validTo})`, data);
      const urgentRecipients = Array.isArray(cfg.urgent_recipients) && cfg.urgent_recipients.length
        ? cfg.urgent_recipients : (Array.isArray(cfg.recipients) ? cfg.recipients : []);
      if (urgentRecipients.length) {
        await sendMail(urgentRecipients,
          `[EXPIRED] Certificate expired ${Math.abs(days)} day(s) ago: ${label}`,
          `Certificate ${label} expired ${Math.abs(days)} day(s) ago (${cert.validTo}).\n\nRenew as soon as possible.`
        ).catch(() => {});
      }
    } else if (days <= urgentDays) {
      pushCertNotificationOnce('cert_expiring', 'warning', certKey,
        `Certificat ${label} expire dans ${days} jour(s) (${cert.validTo})`, data);
      const urgentRecipients = Array.isArray(cfg.urgent_recipients) && cfg.urgent_recipients.length
        ? cfg.urgent_recipients : (Array.isArray(cfg.recipients) ? cfg.recipients : []);
      if (urgentRecipients.length) {
        await sendMail(urgentRecipients,
          `[URGENT] Certificate expiring in ${days} day(s): ${label}`,
          `Certificate ${label} expires in ${days} day(s) on ${cert.validTo}.\n\nPlease renew immediately.`
        ).catch(() => {});
      }
    } else if (days <= warnDays) {
      pushCertNotificationOnce('cert_expiring', 'warning', certKey,
        `Certificat ${label} expire dans ${days} jour(s) (${cert.validTo})`, data);
      await sendNotification('cert_expiry',
        `[Warning] Certificate expiring in ${days} day(s): ${label}`,
        `Certificate ${label} expires in ${days} day(s) on ${cert.validTo}.`
      );
    }
  }
}

function startScheduler() {
  loadSmtpConfig();
  // BUG REEL (signale par un utilisateur : "certificat qui expire dans 22
  // jours, aucune notification, y a-t-il un scheduler interne ?") : la
  // valeur de retour de loadNotifConfig() etait ignoree, si bien que
  // `notifCfg` restait a `null` pour toujours et checkCertExpiry() ne
  // verifiait strictement aucun certificat. La valeur de retour est donc
  // toujours recuperee, au demarrage comme a chaque minute.
  notifCfg = loadNotifConfig();

  // Import unique de l'ancien scheduler.yml dans la base (sans effet si deja fait
  // ou si la base n'est pas disponible).
  try { store.migrateLegacyYaml(loadSchedConfig()); }
  catch (e) { console.warn('[scheduler] import de scheduler.yml impossible :', e.message); }
  console.log('[scheduler] Started');

  // Persiste d'un tick a l'autre par fermeture (pas portee module) : l'intervalle
  // n'est jamais recree pendant la vie du processus. Cle = minute ecoulee depuis
  // l'epoch, pas seulement getMinutes() : deux ticks de la meme minute civile
  // n'executent jamais deux fois les memes taches.
  let lastSchedulerMinute = null;

  setInterval(async () => {
    const now = new Date();
    const minuteKey = Math.floor(now.getTime() / 60000);
    if (minuteKey === lastSchedulerMinute) return;
    lastSchedulerMinute = minuteKey;

    loadSmtpConfig();
    notifCfg = loadNotifConfig();

    // Verification d'expiration des certificats : une fois par jour, a 03:00
    // (dedup quotidien supplementaire dans pushCertNotificationOnce()).
    if (now.getHours() === 3 && now.getMinutes() === 0) {
      checkCertExpiry().catch(e => console.error('[scheduler] certExpiry error:', e.message));
    }

    // Taches planifiees (base) : relues a chaque minute, tire-et-oublie pour
    // qu'une tache lente ne retarde pas les autres.
    let tasksList = [];
    try { tasksList = store.listTasks(); }
    catch (e) { /* base indisponible : on ne declenche rien plutot que de planter */ }
    for (const task of tasksList) {
      if (!task.enabled || !cronMatches(task.cron, now)) continue;
      runTask(task, { trigger: 'schedule' }).catch(e => console.error('[scheduler] task error:', e.message));
    }

    // Recheck SSL des agents distants — toutes les 5 minutes, sans condition
    // (voir runScheduledAgentSslRecheck() : correctif de coherence, pas une
    // option a activer).
    if (now.getMinutes() % 5 === 0) {
      runScheduledAgentSslRecheck().catch(e => console.error('[scheduler] agent SSL recheck error:', e.message));
    }
  }, 30000); // verification toutes les 30 s
}
module.exports = {
  matchCron, startScheduler, setTasks, checkCertExpiry, runScheduledAgentSslRecheck,
  runTask, runTaskNow, isRunning, resolveOptions,
};
