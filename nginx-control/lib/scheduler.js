'use strict';
/**
 * Recurring tasks: nginx reload, backups, GoAccess restarts, certificate
 * expiry checks.
 *
 * A minimal cron matcher rather than a dependency — the patterns in use are
 * simple, and the loop ticks once a minute. Configuration is re-read on every
 * tick so an edit takes effect without a restart.
 *
 * The scheduled reload always runs `nginx -t` first and gives up when it fails:
 * a broken configuration must not be pushed live by a background job at 3 a.m.
 *
 * Tasks that belong to a feature (deploying, restarting GoAccess) are injected
 * by server.js rather than imported, keeping this module free of feature
 * dependencies.
 */

const cfg    = require('./config');
const docker = require('./docker');
const notify = require('./notify');
const certs  = require('./certs');
const events = require('./events');
const digest = require('./digest');
const { pushNotification } = require('./notifications');

const { execNginx } = docker;
const { GIT_REPO_URL } = cfg;
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
  execNginx,
  restartContainer: (...args) => docker.restartContainer(...args),
};

function setTasks(overrides) { Object.assign(tasks, overrides); }

let schedCfg  = null;
let notifCfg  = null;

function matchCron(cron, now) {
  try {
    const [min, hour, dom, mon, dow] = cron.split(' ');
    const match = (pat, val) => {
      if (pat === '*') return true;
      if (pat.includes('/')) {
        const [, step] = pat.split('/');
        return val % parseInt(step) === 0;
      }
      if (pat.includes(',')) return pat.split(',').map(Number).includes(val);
      if (pat.includes('-')) {
        const [a, b] = pat.split('-').map(Number);
        return val >= a && val <= b;
      }
      return parseInt(pat) === val;
    };
    return match(min, now.getMinutes())
        && match(hour, now.getHours())
        && match(dom, now.getDate())
        && match(mon, now.getMonth() + 1)
        && match(dow, now.getDay());
  } catch { return false; }
}

async function runScheduledReload() {
  const cfg = schedCfg?.nginx_reload;
  if (!cfg?.enable) return;
  console.log('[scheduler] Running scheduled nginx reload');
  try {
    const testResult = await execNginx('nginx -t');
    if (!testResult.valid && testResult.stderr?.includes('failed')) {
      console.warn('[scheduler] nginx -t failed — reload aborted');
      pushNotification({ type: 'scheduled_reload_failed', level: 'error',
        message: 'Reload nginx planifie annule : nginx -t a echoue',
        data: { stderr: testResult.stderr || testResult.stdout || '' } });
      await sendNotification('nginx_reload',
        '[Nginx Dashboard] Scheduled reload FAILED — config error',
        `Scheduled nginx reload was aborted because nginx -t failed.\n\nOutput:\n${testResult.stderr || testResult.stdout || ''}`
      );
      return;
    }
    await execNginx('nginx -s reload');
    logEvent('scheduler.reload', 'Scheduled nginx reload OK');
    pushNotification({ type: 'scheduled_reload', level: 'success',
      message: 'Reload nginx planifie effectue avec succes' });
    if (cfg.notify) {
      await sendNotification('nginx_reload',
        '[Nginx Dashboard] Scheduled nginx reload OK',
        `Nginx was successfully reloaded at ${new Date().toISOString()}.`
      );
    }
  } catch(e) {
    console.error('[scheduler] Reload error:', e.message || e);
    pushNotification({ type: 'scheduled_reload_failed', level: 'error',
      message: `Erreur lors du reload nginx planifie : ${e.message || e}` });
    await sendNotification('nginx_reload',
      '[Nginx Dashboard] Scheduled reload ERROR',
      `Error during scheduled reload: ${e.message || JSON.stringify(e)}`
    );
  }
}

/**
 * A full container restart, not just `nginx -s reload` — for the cases a
 * reload cannot fix: a stuck worker, a leaked file descriptor, memory that
 * only a fresh process reclaims. Same nginx -t safety gate as the reload
 * task: restarting on top of a broken config is strictly worse than
 * reloading on top of one, since the container briefly has no nginx running
 * at all rather than just an old config still serving traffic.
 */
async function runScheduledNginxRestart() {
  const cfg = schedCfg?.nginx_restart;
  if (!cfg?.enable) return;
  console.log('[scheduler] Running scheduled nginx container restart');
  try {
    const testResult = await tasks.execNginx('nginx -t');
    if (!testResult.valid && testResult.stderr?.includes('failed')) {
      console.warn('[scheduler] nginx -t failed — restart aborted');
      pushNotification({ type: 'scheduled_restart_failed', level: 'error',
        message: 'Redemarrage nginx planifie annule : nginx -t a echoue',
        data: { stderr: testResult.stderr || testResult.stdout || '' } });
      await sendNotification('nginx_restart',
        '[Nginx Dashboard] Scheduled restart FAILED — config error',
        `Scheduled nginx container restart was aborted because nginx -t failed.\n\nOutput:\n${testResult.stderr || testResult.stdout || ''}`
      );
      return;
    }
    await tasks.restartContainer(cfg.grace_seconds || 10);
    logEvent('scheduler.nginx_restart', 'Scheduled nginx container restart OK');
    pushNotification({ type: 'scheduled_restart', level: 'success',
      message: 'Redemarrage nginx planifie effectue avec succes' });
    if (cfg.notify) {
      await sendNotification('nginx_restart',
        '[Nginx Dashboard] Scheduled nginx container restart OK',
        `The nginx container was successfully restarted at ${new Date().toISOString()}.`
      );
    }
  } catch(e) {
    console.error('[scheduler] Nginx restart error:', e.message || e);
    pushNotification({ type: 'scheduled_restart_failed', level: 'error',
      message: `Erreur lors du redemarrage nginx planifie : ${e.message || e}` });
    await sendNotification('nginx_restart',
      '[Nginx Dashboard] Scheduled nginx restart ERROR',
      `Error during scheduled nginx container restart: ${e.message || JSON.stringify(e)}`
    );
  }
}

async function runScheduledGoAccessRestart() {
  const cfg = schedCfg?.goaccess_restart;
  if (!cfg?.enable) return;
  // Fix (audit report, Basse/"Partie 1 et certificats", confirmed "✔"):
  // these three calls used the bare identifiers `listGoAccessSources`,
  // `getGoAccessContainerStatus`, `restartGoAccessContainer` — which don't
  // exist anywhere in this module's own scope. The real implementations are
  // only ever available through the injected `tasks` object just above
  // (this module's header explains why: features are injected here, never
  // imported directly). Every real run of this function threw a
  // ReferenceError on the very first line below, meaning the scheduled
  // GoAccess restart has never actually restarted anything since it shipped
  // — the feature looked wired up (config, UI, a scheduler tick that fires
  // on time) but silently failed on every single run.
  const sources = tasks.listGoAccessSources();
  const targets = cfg.sources && cfg.sources.length
    ? sources.filter(s => cfg.sources.includes(s.id))
    : sources;
  console.log(`[scheduler] GoAccess restart: ${targets.length} container(s)`);
  for (const src of targets) {
    try {
      const status = await tasks.getGoAccessContainerStatus(src.id);
      if (!status.running) continue;
      await tasks.restartGoAccessContainer(src.id);
      console.log(`[scheduler] GoAccess restarted: ${src.id}`);
      logEvent('scheduler.goaccess_restart', `GoAccess restarted: ${src.id}`);
    } catch(e) {
      console.error(`[scheduler] GoAccess restart error (${src.id}):`, e.message);
    }
  }
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

async function runScheduledBackup() {
  const cfg = schedCfg?.backup;
  if (!cfg?.enable) return;
  console.log('[scheduler] Running scheduled backup');
  try {
    const mode    = cfg.mode || 'local';
    const doLocal = mode === 'local' || mode === 'both';
    const doGit   = (mode === 'git'   || mode === 'both') && !!GIT_REPO_URL;
    let zipResult = null;
    let gitResult = null;
    if (doLocal) zipResult = await tasks.createBackupZip('scheduled').catch(e => ({ error: e.message }));
    if (doGit)   gitResult = await tasks.gitBackupPush('scheduled').catch(e => ({ error: e.message }));
    const failed = (zipResult?.error) || (doGit && gitResult?.error);
    logEvent('scheduler.backup', { mode, zip: zipResult?.zipName, git: gitResult?.tag, failed });
    if (failed && cfg.notify_on_failure) {
      await sendNotification('backup_failure',
        '[Nginx Dashboard] Scheduled backup FAILED',
        `Backup failed.\nMode: ${mode}\nZIP: ${zipResult?.error || zipResult?.zipName || 'skipped'}\nGit: ${gitResult?.error || gitResult?.tag || 'skipped'}`
      );
    }
  } catch(e) {
    console.error('[scheduler] Backup error:', e.message);
    if (schedCfg?.backup?.notify_on_failure) {
      await sendNotification('backup_failure',
        '[Nginx Dashboard] Scheduled backup ERROR',
        `Error during scheduled backup: ${e.message}`
      );
    }
  }
}

/**
 * A periodic operational summary, composed by lib/digest.js from data this
 * project already computes elsewhere (traffic, bot/human split, CrowdSec,
 * WAF, certificate expiry). Saved to the events database so the dashboard
 * can show it and its history, and mailed when configured to — the same
 * two-destination pattern requested for this feature: visible in the UI,
 * and delivered without anyone needing to remember to go look.
 *
 * A daily vs. weekly cadence is just a matter of which cron the operator
 * writes in scheduler.yml (e.g. "0 7 * * *" for daily at 7am, "0 7 * * 1"
 * for weekly on Monday at 7am) — the same single `cron` field every other
 * scheduled task in this file already uses, rather than a separate
 * "frequency" concept invented just for this one.
 */
async function runScheduledDigest() {
  const cfgDigest = schedCfg?.digest;
  if (!cfgDigest?.enable) return;
  console.log('[scheduler] Generating scheduled digest');
  try {
    const periodHours = cfgDigest.period_hours || 24;
    const d = await digest.generateDigest(periodHours);
    const id = events.saveDigest(d);
    logEvent('scheduler.digest', `Scheduled digest generated${id ? ` (#${id})` : ''}`);
    if (cfgDigest.notify) {
      const recipients = Array.isArray(cfgDigest.recipients) ? cfgDigest.recipients : [];
      if (recipients.length) {
        await sendMail(recipients,
          `[Nginx Dashboard] Résumé périodique — ${new Date(d.generatedAt).toLocaleDateString('fr-FR')}`,
          digest.formatDigestText(d)
        ).catch(e => console.warn('[scheduler] Digest mail error:', e.message));
      }
    }
  } catch (e) {
    console.error('[scheduler] Digest generation error:', e.message || e);
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
  // valeur de retour de loadNotifConfig() etait ignoree ici, exactement le
  // meme bug que celui deja identifie et corrige pour schedCfg (voir le
  // commentaire plus bas, "Reload configs each minute") — sauf que le
  // correctif n avait alors ete applique qu a schedCfg, pas a notifCfg.
  // Consequence : `notifCfg` restait a `null` pour toujours, si bien que
  // checkCertExpiry() faisait systematiquement `if (!cfg?.enable) return;`
  // des sa premiere ligne et ne verifiait STRICTEMENT AUCUN certificat,
  // meme avec `cert_expiry: enable: true` dans notifications.yml. Silencieux
  // : aucune exception, aucun log — le planificateur tournait, juste sans
  // jamais rien vérifier.
  notifCfg = loadNotifConfig();
  schedCfg = loadSchedConfig();
  console.log('[scheduler] Started');

  // Persists across ticks via closure, not module scope: the interval never
  // gets recreated for the life of the process, so a local variable here
  // survives exactly as long as it needs to. It was previously read without
  // ever being declared — under strict mode that throws a ReferenceError on
  // every single tick, meaning no scheduled task (cert expiry, backups) had
  // ever actually run. The crash used to be fatal and obvious; since the
  // global unhandledRejection safety net was added, it degraded into a
  // silent, repeating failure instead — same bug, much quieter symptom.
  let lastSchedulerMinute = null;

  setInterval(async () => {
    const now = new Date();
    if (now.getMinutes() === lastSchedulerMinute) return;
    lastSchedulerMinute = now.getMinutes();

    // Reload configs each minute (picks up changes without restart).
    // loadSchedConfig() (from lib/notify.js) updates ITS OWN internal
    // module-level variable and returns the parsed config — this file has a
    // SEPARATE `schedCfg` declared above, which every scheduled-task check
    // below reads. The return value was previously discarded here, leaving
    // this file's `schedCfg` at its initial `null` forever: every
    // `schedCfg?.xxx` below silently evaluated to `undefined` regardless of
    // what scheduler.yml actually contained. No exception, no log line —
    // reload, backup, GoAccess restart and this file's own scheduled tasks
    // had never actually been able to fire. Confirmed directly: with
    // `enable: true` and a cron that always matches, the task still never
    // ran until this line captured the return value.
    loadSmtpConfig();
    notifCfg = loadNotifConfig(); // meme correctif qu au demarrage ci-dessus — voir le commentaire la-bas
    schedCfg = loadSchedConfig();

    // Cert expiry check — once per day, at 03:00. Le commentaire disait deja
    // "once per day" mais la condition ne testait QUE les minutes, donc la
    // verification tournait en realite toutes les heures (24x/jour) —
    // inoffensif pour l email (deja idempotent par nature, un email de plus
    // ne casse rien) mais aurait fait spammer le centre de notification a
    // chaque tick sans le garde-fou pushCertNotificationOnce() (dedup
    // quotidien, voir plus haut dans ce fichier).
    if (now.getHours() === 3 && now.getMinutes() === 0) {
      checkCertExpiry().catch(e => console.error('[scheduler] certExpiry error:', e.message));
    }

    // Scheduled reload
    const reloadCron = schedCfg?.nginx_reload?.cron;
    if (reloadCron && schedCfg?.nginx_reload?.enable && matchCron(reloadCron, now)) {
      runScheduledReload().catch(e => console.error('[scheduler] reload error:', e.message));
    }

    // Scheduled full container restart — distinct from reload above
    const restartCron = schedCfg?.nginx_restart?.cron;
    if (restartCron && schedCfg?.nginx_restart?.enable && matchCron(restartCron, now)) {
      runScheduledNginxRestart().catch(e => console.error('[scheduler] nginx restart error:', e.message));
    }

    // Scheduled digest
    const digestCron = schedCfg?.digest?.cron;
    if (digestCron && schedCfg?.digest?.enable && matchCron(digestCron, now)) {
      runScheduledDigest().catch(e => console.error('[scheduler] digest error:', e.message));
    }

    // Scheduled backup
    const backupCron = schedCfg?.backup?.cron;
    if (backupCron && schedCfg?.backup?.enable && matchCron(backupCron, now)) {
      runScheduledBackup().catch(e => console.error('[scheduler] backup error:', e.message));
    }

    // Scheduled GoAccess restart
    const gaCron = schedCfg?.goaccess_restart?.cron;
    if (gaCron && schedCfg?.goaccess_restart?.enable && matchCron(gaCron, now)) {
      runScheduledGoAccessRestart().catch(e => console.error('[scheduler] goaccess restart error:', e.message));
    }

    // Agent SSL recheck — every 5 minutes, unconditional (see
    // runScheduledAgentSslRecheck()'s own header comment for why this one
    // isn't gated by a scheduler.yml toggle like the tasks above).
    if (now.getMinutes() % 5 === 0) {
      runScheduledAgentSslRecheck().catch(e => console.error('[scheduler] agent SSL recheck error:', e.message));
    }
  }, 30000); // check every 30s
}
module.exports = { matchCron, startScheduler, setTasks, checkCertExpiry, runScheduledNginxRestart, runScheduledDigest, runScheduledGoAccessRestart, runScheduledAgentSslRecheck };
