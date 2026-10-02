'use strict';
/**
 * Tâches planifiées — interface HTTP (page « Scheduler »).
 *
 * Stockage : lib/scheduler-store.js (base SQLite). Types de tâches et schéma de
 * leurs paramètres : lib/scheduler-tasks.js (le formulaire de l'interface est
 * généré depuis ce schéma). Exécution : lib/scheduler.js.
 *
 *   GET  /api/scheduler/tasks            liste (prochaine exécution, dernier résultat)
 *   GET  /api/scheduler/types            types disponibles + schéma des paramètres
 *   POST /api/scheduler/preview          { schedule } -> cron, texte, 5 prochaines exécutions
 *   POST /api/scheduler/tasks/save       { id?, name, type, enabled, schedule, params, notify }
 *   POST /api/scheduler/tasks/toggle     { id, enabled }
 *   POST /api/scheduler/tasks/delete     { id }
 *   POST /api/scheduler/tasks/run        { id }   exécution immédiate
 *   GET  /api/scheduler/runs?id=&limit=  historique d'une tâche
 *   GET  /api/scheduler/export           fichier tâche (JSON)
 *   POST /api/scheduler/import           { content, mode: merge|replace }
 *
 * Lecture : view_configs. Écriture et exécution : nginx_control (un opérateur
 * peut déjà recharger/redémarrer nginx à la main, planifier cela n'élargit rien).
 */

const httpLib   = require('../lib/http');
const auth      = require('../lib/auth');
const events    = require('../lib/events');
const store     = require('../lib/scheduler-store');
const registry  = require('../lib/scheduler-tasks');
const cronLib   = require('../lib/schedule-cron');
const scheduler = require('../lib/scheduler');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { logEvent } = events;

const langOf = url => (url.searchParams.get('lang') === 'en' ? 'en' : 'fr');
const timezone = () => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch { return 'UTC'; } };

function decorate(task, lang) {
  const next = task.enabled ? cronLib.nextRuns(task.cron, new Date(), 1)[0] : null;
  return {
    ...task,
    scheduleText: cronLib.describeCron(task.cron, lang),
    nextRun: next ? next.getTime() : null,
    running: scheduler.isRunning(task.id),
  };
}

function register(router) {
  router.get('/api/scheduler/tasks', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    try {
      const lang = langOf(url);
      return send(res, 200, { tasks: store.listTasks().map(t => decorate(t, lang)), timezone: timezone(), now: Date.now() });
    } catch (e) { return send(res, 500, { error: e.message }); }
  });

  router.get('/api/scheduler/types', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    return send(res, 200, {
      types: registry.describeTypes(scheduler.resolveOptions),
      minuteSteps: cronLib.MINUTE_STEPS, hourSteps: cronLib.HOUR_STEPS, timezone: timezone(),
    });
  });

  router.post('/api/scheduler/preview', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const r = cronLib.buildSchedule(body.schedule);
    if (!r.ok) return send(res, 200, { ok: false, error: r.error });
    return send(res, 200, {
      ok: true, cron: r.cron, schedule: r.schedule, text: cronLib.describeCron(r.cron, langOf(url)),
      next: cronLib.nextRuns(r.cron, new Date(), 5).map(d => d.getTime()), timezone: timezone(),
    });
  });

  router.post('/api/scheduler/tasks/save', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    try {
      const creating = body.id === undefined || body.id === null || body.id === '';
      const r = creating ? store.createTask(body) : store.updateTask(body.id, body);
      if (!r.ok) return send(res, r.status || 400, { ok: false, error: r.error });
      logEvent(creating ? 'scheduler.task.create' : 'scheduler.task.update',
        { id: r.task.id, name: r.task.name, type: r.task.type, cron: r.task.cron, enabled: r.task.enabled, by: session.username }, 'api');
      return send(res, 200, { ok: true, task: decorate(r.task, 'fr') });
    } catch (e) { return send(res, 500, { ok: false, error: e.message }); }
  });

  router.post('/api/scheduler/tasks/toggle', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    try {
      const r = store.setEnabled(body.id, body.enabled === true);
      if (!r.ok) return send(res, r.status || 400, { ok: false, error: r.error });
      logEvent('scheduler.task.toggle', { id: r.task.id, name: r.task.name, enabled: r.task.enabled, by: session.username }, 'api');
      return send(res, 200, { ok: true, task: decorate(r.task, 'fr') });
    } catch (e) { return send(res, 500, { ok: false, error: e.message }); }
  });

  router.post('/api/scheduler/tasks/delete', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    try {
      const cur = store.getTask(body.id);
      const r = store.deleteTask(body.id);
      if (!r.ok) return send(res, r.status || 400, { ok: false, error: r.error });
      logEvent('scheduler.task.delete', { id: cur.id, name: cur.name, type: cur.type, by: session.username }, 'api');
      return send(res, 200, { ok: true });
    } catch (e) { return send(res, 500, { ok: false, error: e.message }); }
  });

  router.post('/api/scheduler/tasks/run', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    try {
      const r = await scheduler.runTaskNow(body.id, session.username);
      if (r.notFound) return send(res, 404, { ok: false, error: r.message });
      if (r.status === 'busy') return send(res, 409, { ok: false, error: r.message });
      return send(res, 200, { ok: r.status !== 'error', status: r.status, message: r.message, durationMs: r.durationMs });
    } catch (e) { return send(res, 500, { ok: false, error: e.message }); }
  });

  router.get('/api/scheduler/runs', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    try {
      return send(res, 200, { runs: store.listRuns(url.searchParams.get('id'), url.searchParams.get('limit')) });
    } catch (e) { return send(res, 500, { error: e.message }); }
  });

  router.get('/api/scheduler/export', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    try {
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': 'attachment; filename="scheduled-tasks.json"',
        'X-Content-Type-Options': 'nosniff',
      });
      return res.end(JSON.stringify(store.exportTasks(), null, 2) + '\n');
    } catch (e) { return send(res, 500, { error: e.message }); }
  });

  router.post('/api/scheduler/import', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    try {
      const r = store.importTasks(body.content, body.mode || 'merge');
      if (!r.ok) return send(res, 400, r);
      logEvent('scheduler.task.import', { added: r.added, skipped: r.skipped, mode: r.mode, by: session.username }, 'api');
      return send(res, 200, r);
    } catch (e) { return send(res, 500, { ok: false, error: e.message }); }
  });
}

module.exports = { register };
