'use strict';
/**
 * Registre des TYPES de tâches planifiables.
 *
 * Ajouter une tâche = ajouter un objet ici : le formulaire de la page
 * « Scheduler » est généré depuis `params` (aucun code d'interface à écrire), la
 * validation vient du même schéma, et `run()` est appelée par lib/scheduler.js.
 * Aucune commande arbitraire n'est possible : l'opérateur choisit un type dans
 * cette liste fermée et règle ses paramètres.
 *
 * Un `run(params, ctx)` renvoie `{ status: 'ok' | 'error' | 'skipped', message }`
 * (ou lève une exception, traitée comme une erreur). `ctx` :
 *   ctx.tasks   dépendances injectées par server.js (voir lib/scheduler.js)
 *   ctx.task    la tâche { id, name, notify, ... }
 * Les notifications (centre de notifications + e-mail) restent celles de l'ancien
 * planificateur, avec les mêmes clés de règle (nginx_reload, nginx_restart,
 * backup_failure…) pour que les règles de notifications.yml continuent de
 * s'appliquer telles quelles.
 */

const cfg    = require('./config');
const notify = require('./notify');
const events = require('./events');
const digest = require('./digest');
const { pushNotification } = require('./notifications');

const { sendNotification, sendMail } = notify;
const { logEvent } = events;

const L = (fr, en) => ({ fr, en });

// ─── Utilitaires ─────────────────────────────────────────────────────────────
/** Même garde que l'ancien planificateur : `nginx -t` invalide => on n'agit pas. */
function nginxTestFailed(r) {
  return !!r && !r.valid && !!r.stderr && r.stderr.includes('failed');
}
const errText = e => (e && (e.message || e.error)) || (typeof e === 'string' ? e : JSON.stringify(e));

// ─── Définition des types ────────────────────────────────────────────────────
const TYPES = {
  nginx_reload: {
    label: L('Recharger Nginx', 'Reload Nginx'),
    description: L(
      'Exécute nginx -t puis nginx -s reload, sans interruption de service. Annulé si la configuration est invalide.',
      'Runs nginx -t then nginx -s reload, with no downtime. Aborted when the configuration is invalid.'),
    notifyLabel: L('Envoyer un e-mail après un rechargement réussi', 'Send an e-mail after a successful reload'),
    params: [],
    async run(params, ctx) {
      let t;
      try { t = await ctx.tasks.execNginx('nginx -t'); }
      catch (e) {
        // execNginx rejette quand `nginx -t` echoue : meme traitement que l'ancien planificateur.
        pushNotification({ type: 'scheduled_reload_failed', level: 'error',
          message: `Erreur lors du reload nginx planifie : ${errText(e)}` });
        await sendNotification('nginx_reload', '[Nginx Dashboard] Scheduled reload ERROR',
          `Error during scheduled reload: ${errText(e)}`);
        return { status: 'error', message: errText(e) };
      }
      if (nginxTestFailed(t)) {
        const out = t.stderr || t.stdout || '';
        pushNotification({ type: 'scheduled_reload_failed', level: 'error',
          message: 'Reload nginx planifie annule : nginx -t a echoue', data: { stderr: out } });
        await sendNotification('nginx_reload', '[Nginx Dashboard] Scheduled reload FAILED — config error',
          `Scheduled nginx reload was aborted because nginx -t failed.\n\nOutput:\n${out}`);
        return { status: 'error', message: 'nginx -t a echoue : rechargement annule' };
      }
      try {
        await ctx.tasks.execNginx('nginx -s reload');
      } catch (e) {
        pushNotification({ type: 'scheduled_reload_failed', level: 'error',
          message: `Erreur lors du reload nginx planifie : ${errText(e)}` });
        await sendNotification('nginx_reload', '[Nginx Dashboard] Scheduled reload ERROR',
          `Error during scheduled reload: ${errText(e)}`);
        return { status: 'error', message: errText(e) };
      }
      logEvent('scheduler.reload', 'Scheduled nginx reload OK');
      pushNotification({ type: 'scheduled_reload', level: 'success', message: 'Reload nginx planifie effectue avec succes' });
      if (ctx.task.notify) {
        await sendNotification('nginx_reload', '[Nginx Dashboard] Scheduled nginx reload OK',
          `Nginx was successfully reloaded at ${new Date().toISOString()}.`);
      }
      return { status: 'ok', message: 'Rechargement effectue' };
    },
  },

  nginx_restart: {
    label: L('Redémarrer le conteneur Nginx', 'Restart the Nginx container'),
    description: L(
      'Redémarre tout le conteneur (pas seulement un reload) : pour ce qu\'un reload ne règle pas — worker bloqué, descripteurs de fichiers qui fuient, mémoire. Coupure brève. Annulé si nginx -t échoue.',
      'Restarts the whole container (not just a reload): for what a reload cannot fix — stuck worker, leaked file descriptors, memory. Brief outage. Aborted when nginx -t fails.'),
    notifyLabel: L('Envoyer un e-mail après un redémarrage réussi', 'Send an e-mail after a successful restart'),
    params: [
      { key: 'grace_seconds', type: 'number', min: 1, max: 120, default: 10, unit: L('secondes', 'seconds'),
        label: L('Délai avant arrêt forcé', 'Delay before forced stop'),
        help: L('Temps laissé aux connexions en cours avant le SIGKILL.', 'Time given to in-flight connections before SIGKILL.') },
    ],
    async run(params, ctx) {
      let t;
      try { t = await ctx.tasks.execNginx('nginx -t'); }
      catch (e) {
        pushNotification({ type: 'scheduled_restart_failed', level: 'error',
          message: `Erreur lors du redemarrage nginx planifie : ${errText(e)}` });
        await sendNotification('nginx_restart', '[Nginx Dashboard] Scheduled nginx restart ERROR',
          `Error during scheduled nginx container restart: ${errText(e)}`);
        return { status: 'error', message: errText(e) };
      }
      if (nginxTestFailed(t)) {
        const out = t.stderr || t.stdout || '';
        pushNotification({ type: 'scheduled_restart_failed', level: 'error',
          message: 'Redemarrage nginx planifie annule : nginx -t a echoue', data: { stderr: out } });
        await sendNotification('nginx_restart', '[Nginx Dashboard] Scheduled restart FAILED — config error',
          `Scheduled nginx container restart was aborted because nginx -t failed.\n\nOutput:\n${out}`);
        return { status: 'error', message: 'nginx -t a echoue : redemarrage annule' };
      }
      try {
        await ctx.tasks.restartContainer(params.grace_seconds || 10);
      } catch (e) {
        pushNotification({ type: 'scheduled_restart_failed', level: 'error',
          message: `Erreur lors du redemarrage nginx planifie : ${errText(e)}` });
        await sendNotification('nginx_restart', '[Nginx Dashboard] Scheduled nginx restart ERROR',
          `Error during scheduled nginx container restart: ${errText(e)}`);
        return { status: 'error', message: errText(e) };
      }
      logEvent('scheduler.nginx_restart', 'Scheduled nginx container restart OK');
      pushNotification({ type: 'scheduled_restart', level: 'success', message: 'Redemarrage nginx planifie effectue avec succes' });
      if (ctx.task.notify) {
        await sendNotification('nginx_restart', '[Nginx Dashboard] Scheduled nginx container restart OK',
          `The nginx container was successfully restarted at ${new Date().toISOString()}.`);
      }
      return { status: 'ok', message: 'Conteneur redemarre' };
    },
  },

  analyzer_restart: {
    label: L('Redémarrer l\'analyzer', 'Restart the analyzer'),
    description: L(
      'Redémarre le conteneur analyzer (analyse des journaux) puis attend que son API réponde de nouveau. L\'historique et la baseline sont conservés. Utile pour libérer la mémoire d\'un conteneur qui tourne depuis longtemps.',
      'Restarts the analyzer container (log analysis), then waits until its API answers again. History and baseline are kept. Handy to release memory from a long-running container.'),
    notifyLabel: L('Envoyer un e-mail à l\'issue (succès ou échec)', 'Send an e-mail when done (success or failure)'),
    params: [
      { key: 'grace_seconds', type: 'number', min: 1, max: 120, default: 10, unit: L('secondes', 'seconds'),
        label: L('Délai avant arrêt forcé', 'Delay before forced stop') },
      { key: 'wait_healthy', type: 'boolean', default: true,
        label: L('Attendre que l\'API réponde', 'Wait for the API to answer'),
        help: L('Jusqu\'à 90 s ; la tâche est en erreur si l\'API ne revient pas.', 'Up to 90 s; the task fails if the API does not come back.') },
    ],
    async run(params, ctx) {
      let r;
      try {
        r = await ctx.tasks.restartAnalyzer({ graceSeconds: params.grace_seconds || 10, waitHealthy: params.wait_healthy !== false });
      } catch (e) {
        pushNotification({ type: 'scheduled_analyzer_restart_failed', level: 'error',
          message: `Redemarrage analyzer planifie en echec : ${errText(e)}` });
        await sendNotification('analyzer_restart', '[Nginx Dashboard] Scheduled analyzer restart FAILED', errText(e)).catch(() => {});
        return { status: 'error', message: errText(e) };
      }
      if (r.skipped) return { status: 'skipped', message: r.message };
      if (!r.ok) {
        pushNotification({ type: 'scheduled_analyzer_restart_failed', level: 'error', message: r.message });
        await sendNotification('analyzer_restart', '[Nginx Dashboard] Scheduled analyzer restart FAILED', r.message).catch(() => {});
        return { status: 'error', message: r.message };
      }
      logEvent('scheduler.analyzer_restart', r.message);
      pushNotification({ type: 'scheduled_analyzer_restart', level: 'success', message: 'Redemarrage analyzer planifie effectue : ' + r.message });
      if (ctx.task.notify) {
        await sendNotification('analyzer_restart', '[Nginx Dashboard] Scheduled analyzer restart OK', r.message).catch(() => {});
      }
      return { status: 'ok', message: r.message };
    },
  },

  digest: {
    label: L('Résumé périodique', 'Periodic digest'),
    description: L(
      'Génère le résumé (trafic, robots, CrowdSec, WAF, certificats), visible dans la page Résumé et envoyable par e-mail.',
      'Generates the digest (traffic, bots, CrowdSec, WAF, certificates), shown on the Digest page and optionally e-mailed.'),
    notifyLabel: L('Envoyer le résumé par e-mail aux destinataires', 'E-mail the digest to the recipients'),
    params: [
      { key: 'period_hours', type: 'number', min: 1, max: 720, default: 24, unit: L('heures', 'hours'),
        label: L('Période couverte', 'Period covered'),
        help: L('À accorder avec la fréquence : 24 pour un résumé quotidien, 168 pour un hebdomadaire.', 'Match it to the schedule: 24 for a daily digest, 168 for a weekly one.') },
      { key: 'recipients', type: 'emails', max: 20, default: [],
        label: L('Destinataires', 'Recipients') },
    ],
    async run(params, ctx) {
      const d = await digest.generateDigest(params.period_hours || 24);
      const id = events.saveDigest(d);
      logEvent('scheduler.digest', `Scheduled digest generated${id ? ` (#${id})` : ''}`);
      let mailed = 0;
      if (ctx.task.notify) {
        const recipients = Array.isArray(params.recipients) ? params.recipients : [];
        if (recipients.length) {
          try {
            await sendMail(recipients,
              `[Nginx Dashboard] Résumé périodique — ${new Date(d.generatedAt).toLocaleDateString('fr-FR')}`,
              digest.formatDigestText(d));
            mailed = recipients.length;
          } catch (e) { console.warn('[scheduler] Digest mail error:', e.message); }
        }
      }
      return { status: 'ok', message: `Résumé généré${id ? ` (#${id})` : ''}${mailed ? `, envoyé à ${mailed} destinataire(s)` : ''}` };
    },
  },

  backup: {
    label: L('Sauvegarde', 'Backup'),
    description: L(
      'Crée une sauvegarde de la configuration : archive ZIP locale, push Git, ou les deux.',
      'Creates a configuration backup: local ZIP, Git push, or both.'),
    notifyLabel: L('Envoyer un e-mail en cas d\'échec', 'E-mail on failure'),
    params: [
      { key: 'mode', type: 'select', default: 'local',
        label: L('Destination', 'Destination'),
        options: [
          { value: 'local', label: L('Archive ZIP locale', 'Local ZIP archive') },
          { value: 'git',   label: L('Push Git', 'Git push') },
          { value: 'both',  label: L('Les deux', 'Both') },
        ] },
    ],
    async run(params, ctx) {
      const mode = params.mode || 'local';
      const doLocal = mode === 'local' || mode === 'both';
      const doGit = (mode === 'git' || mode === 'both') && !!cfg.GIT_REPO_URL;
      let zip = null, git = null;
      if (doLocal) zip = await ctx.tasks.createBackupZip('scheduled').catch(e => ({ error: e.message }));
      if (doGit) git = await ctx.tasks.gitBackupPush('scheduled').catch(e => ({ error: e.message }));
      const failed = (zip && zip.error) || (doGit && git && git.error);
      logEvent('scheduler.backup', { mode, zip: zip && zip.zipName, git: git && git.tag, failed });
      if (failed && ctx.task.notify) {
        await sendNotification('backup_failure', '[Nginx Dashboard] Scheduled backup FAILED',
          `Backup failed.\nMode: ${mode}\nZIP: ${(zip && (zip.error || zip.zipName)) || 'skipped'}\nGit: ${(git && (git.error || git.tag)) || 'skipped'}`);
      }
      const parts = [];
      if (zip) parts.push(zip.error ? `ZIP : ${zip.error}` : `ZIP : ${zip.zipName}`);
      if (git) parts.push(git.error ? `Git : ${git.error}` : `Git : ${git.tag}`);
      if (!parts.length) return { status: 'skipped', message: 'Rien à sauvegarder (mode Git sans dépôt configuré)' };
      return { status: failed ? 'error' : 'ok', message: parts.join(' — ') };
    },
  },

  goaccess_restart: {
    label: L('Redémarrer GoAccess', 'Restart GoAccess'),
    description: L(
      'Redémarre les conteneurs GoAccess actifs (rapports de trafic) pour qu\'ils relisent les journaux.',
      'Restarts the running GoAccess containers (traffic reports) so they re-read the logs.'),
    notifyLabel: null,
    params: [
      { key: 'sources', type: 'multiselect', optionsFrom: 'goaccess_sources', max: 50, default: [],
        label: L('Sources concernées', 'Sources'),
        help: L('Aucune sélection = tous les conteneurs GoAccess actifs.', 'No selection = every running GoAccess container.') },
    ],
    async run(params, ctx) {
      const all = ctx.tasks.listGoAccessSources();
      const wanted = Array.isArray(params.sources) ? params.sources : [];
      const targets = wanted.length ? all.filter(s => wanted.includes(s.id)) : all;
      let restarted = 0; const errors = [];
      for (const src of targets) {
        try {
          const st = await ctx.tasks.getGoAccessContainerStatus(src.id);
          if (!st.running) continue;
          await ctx.tasks.restartGoAccessContainer(src.id);
          restarted++;
          logEvent('scheduler.goaccess_restart', `GoAccess restarted: ${src.id}`);
        } catch (e) { errors.push(`${src.id} : ${e.message}`); }
      }
      if (errors.length) return { status: 'error', message: `${restarted} redémarré(s), erreurs : ${errors.join(' ; ')}` };
      return { status: 'ok', message: `${restarted} conteneur(s) GoAccess redémarré(s) sur ${targets.length}` };
    },
  },

  certsync: {
    label: L('Synchroniser les certificats', 'Synchronize certificates'),
    description: L(
      'Synchronise les certificats avec les autres Nginx Control (récupération et/ou envoi selon chaque source) : un seul nœud obtient le certificat Let\'s Encrypt, les autres l\'installent. Un nginx -t précède chaque rechargement, avec retour arrière si il échoue.',
      'Synchronizes certificates with the other Nginx Control instances (pull and/or push depending on each source): a single node gets the Let\'s Encrypt certificate, the others install it. nginx -t runs before every reload, with rollback if it fails.'),
    notifyLabel: null,
    params: [
      { key: 'remotes', type: 'multiselect', optionsFrom: 'certsync_remotes', max: 50, default: [],
        label: L('Sources concernées', 'Sources'),
        help: L('Aucune sélection = toutes les sources activées. Les sources se configurent dans la page SSL.', 'No selection = every enabled source. Sources are configured on the SSL page.') },
    ],
    async run(params, ctx) {
      const ids = Array.isArray(params.remotes) ? params.remotes : [];
      const r = await ctx.tasks.runCertsync({ ids, by: 'scheduler' });
      return { status: r.ok ? 'ok' : 'error', message: r.message };
    },
  },
};

// ─── API du registre ─────────────────────────────────────────────────────────
function getType(id) {
  return typeof id === 'string' && Object.prototype.hasOwnProperty.call(TYPES, id) ? { id, ...TYPES[id] } : null;
}

/** Description sérialisable des types (formulaire de l'interface). `resolveOptions(name)` fournit les listes dynamiques. */
function describeTypes(resolveOptions = () => []) {
  return Object.entries(TYPES).map(([id, t]) => ({
    id, label: t.label, description: t.description, notifyLabel: t.notifyLabel || null,
    params: t.params.map(p => ({
      key: p.key, type: p.type, label: p.label, help: p.help || null, default: p.default,
      min: p.min, max: p.max, unit: p.unit || null,
      options: p.optionsFrom ? safeOptions(resolveOptions, p.optionsFrom) : (p.options || undefined),
    })),
  }));
}
function safeOptions(resolve, name) {
  try { return (resolve(name) || []).map(o => ({ value: String(o.value), label: L(String(o.label), String(o.label)) })); }
  catch { return []; }
}

const EMAIL_RE = /^[^\s@<>()"',;:]+@[^\s@<>()"',;:]+\.[^\s@<>()"',;:]+$/;

/**
 * Valide et normalise les paramètres d'une tâche selon le schéma du type.
 * Les clés inconnues sont ignorées ; une valeur invalide est refusée (jamais
 * « corrigée » en silence).
 */
function validateParams(type, raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const out = {};
  for (const p of type.params) {
    let v = src[p.key];
    if (v === undefined || v === null || v === '') v = p.default;
    const name = p.label && p.label.fr || p.key;
    switch (p.type) {
      case 'number': {
        const n = Number(v);
        if (!Number.isFinite(n) || n < p.min || n > p.max) return { ok: false, error: `${name} : valeur entre ${p.min} et ${p.max} attendue` };
        out[p.key] = Math.floor(n);
        break;
      }
      case 'boolean':
        out[p.key] = v === true || v === 'true' || v === 1;
        break;
      case 'select':
        if (!p.options.some(o => o.value === v)) return { ok: false, error: `${name} : choix inconnu` };
        out[p.key] = v;
        break;
      case 'emails': {
        const list = Array.isArray(v) ? v : String(v).split(/[\s,;]+/).filter(Boolean);
        if (list.length > p.max) return { ok: false, error: `${name} : ${p.max} adresses maximum` };
        const bad = list.find(e => typeof e !== 'string' || e.length > 254 || !EMAIL_RE.test(e));
        if (bad !== undefined) return { ok: false, error: `${name} : adresse invalide « ${String(bad).slice(0, 60)} »` };
        out[p.key] = [...new Set(list)];
        break;
      }
      case 'multiselect': {
        const list = Array.isArray(v) ? v : [];
        if (list.length > p.max) return { ok: false, error: `${name} : ${p.max} éléments maximum` };
        if (list.some(x => typeof x !== 'string' || x.length > 100)) return { ok: false, error: `${name} : valeur invalide` };
        out[p.key] = [...new Set(list)];
        break;
      }
      default:
        return { ok: false, error: `type de paramètre inconnu : ${p.type}` };
    }
  }
  return { ok: true, value: out };
}

module.exports = { TYPES, getType, describeTypes, validateParams, nginxTestFailed };
