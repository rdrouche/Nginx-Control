'use strict';
/**
 * Stockage des tâches planifiées (base SQLite des événements, `events.db`) :
 * définitions, dernier résultat et historique des exécutions.
 *
 * Remplace l'édition du fichier `scheduler.yml` (YAML + syntaxe cron à connaître) :
 * la page « Scheduler » lit et écrit ici via /api/scheduler/*. L'ancien fichier
 * n'est lu qu'une fois, par migrateLegacyYaml(), pour ne rien perdre d'une
 * installation existante.
 *
 * Les paramètres propres à chaque type de tâche sont validés par le registre
 * (lib/scheduler-tasks.js) — ce module ne connaît que la forme générale.
 */

const events = require('./events');
const cron = require('./schedule-cron');
const registry = require('./scheduler-tasks');

const MAX_TASKS = 200;
const MAX_NAME = 80;
const MAX_RUNS_PER_TASK = 50;
const MIGRATED_KEY = 'scheduler_tasks_migrated_v1';

function db() { return events.getDb(); }

function ensureTables() {
  const d = db();
  if (!d) return false;
  d.exec(`
    CREATE TABLE IF NOT EXISTS scheduled_tasks (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      name             TEXT NOT NULL,
      type             TEXT NOT NULL,
      enabled          INTEGER NOT NULL DEFAULT 1,
      schedule         TEXT NOT NULL,
      cron             TEXT NOT NULL,
      params           TEXT NOT NULL DEFAULT '{}',
      notify           INTEGER NOT NULL DEFAULT 0,
      created_at       INTEGER NOT NULL,
      updated_at       INTEGER NOT NULL,
      last_run_at      INTEGER,
      last_status      TEXT,
      last_message     TEXT,
      last_duration_ms INTEGER,
      run_count        INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS scheduled_task_runs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id     INTEGER NOT NULL,
      started_at  INTEGER NOT NULL,
      duration_ms INTEGER,
      status      TEXT NOT NULL,
      message     TEXT,
      trigger     TEXT,
      by          TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_sched_runs_task ON scheduled_task_runs (task_id, started_at DESC);
  `);
  return true;
}

function requireDb() {
  if (!ensureTables()) throw new Error('base de données des événements indisponible');
  return db();
}

const clip = (s, n) => String(s == null ? '' : s).slice(0, n);

function rowToTask(r) {
  if (!r) return null;
  let schedule = null, params = {};
  try { schedule = JSON.parse(r.schedule); } catch { schedule = { mode: 'cron', cron: r.cron }; }
  try { params = JSON.parse(r.params) || {}; } catch { params = {}; }
  return {
    id: r.id, name: r.name, type: r.type, enabled: !!r.enabled,
    schedule, cron: r.cron, params, notify: !!r.notify,
    createdAt: r.created_at, updatedAt: r.updated_at,
    lastRunAt: r.last_run_at, lastStatus: r.last_status, lastMessage: r.last_message,
    lastDurationMs: r.last_duration_ms, runCount: r.run_count,
  };
}

/**
 * Valide une définition de tâche (création, mise à jour, import).
 * @returns {{ok:true, value:object}|{ok:false, error:string}}
 */
function validateTask(input) {
  if (!input || typeof input !== 'object') return { ok: false, error: 'tâche invalide' };
  const name = clip(input.name, MAX_NAME + 1).trim();
  if (!name) return { ok: false, error: 'nom obligatoire' };
  if (name.length > MAX_NAME) return { ok: false, error: `nom trop long (${MAX_NAME} caractères max)` };
  const type = registry.getType(input.type);
  if (!type) return { ok: false, error: `type de tâche inconnu : ${clip(input.type, 40)}` };
  const sched = cron.buildSchedule(input.schedule);
  if (!sched.ok) return { ok: false, error: `planification : ${sched.error}` };
  const params = registry.validateParams(type, input.params);
  if (!params.ok) return { ok: false, error: params.error };
  return {
    ok: true,
    value: {
      name, type: type.id, enabled: input.enabled !== false,
      schedule: sched.schedule, cron: sched.cron, params: params.value,
      notify: !!input.notify,
    },
  };
}

function listTasks() {
  const d = requireDb();
  return d.prepare('SELECT * FROM scheduled_tasks ORDER BY id').all().map(rowToTask);
}

function getTask(id) {
  const d = requireDb();
  return rowToTask(d.prepare('SELECT * FROM scheduled_tasks WHERE id = ?').get(Number(id)));
}

function createTask(input) {
  const v = validateTask(input);
  if (!v.ok) return v;
  const d = requireDb();
  if (d.prepare('SELECT COUNT(*) AS n FROM scheduled_tasks').get().n >= MAX_TASKS) {
    return { ok: false, error: `limite de ${MAX_TASKS} tâches atteinte` };
  }
  const t = Date.now(), x = v.value;
  const r = d.prepare(`INSERT INTO scheduled_tasks (name, type, enabled, schedule, cron, params, notify, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(x.name, x.type, x.enabled ? 1 : 0, JSON.stringify(x.schedule), x.cron, JSON.stringify(x.params), x.notify ? 1 : 0, t, t);
  return { ok: true, task: getTask(Number(r.lastInsertRowid)) };
}

function updateTask(id, input) {
  const cur = getTask(id);
  if (!cur) return { ok: false, error: 'tâche introuvable', status: 404 };
  const v = validateTask({ ...input });
  if (!v.ok) return v;
  const x = v.value;
  requireDb().prepare(`UPDATE scheduled_tasks SET name=?, type=?, enabled=?, schedule=?, cron=?, params=?, notify=?, updated_at=? WHERE id=?`)
    .run(x.name, x.type, x.enabled ? 1 : 0, JSON.stringify(x.schedule), x.cron, JSON.stringify(x.params), x.notify ? 1 : 0, Date.now(), cur.id);
  return { ok: true, task: getTask(cur.id) };
}

function setEnabled(id, enabled) {
  const cur = getTask(id);
  if (!cur) return { ok: false, error: 'tâche introuvable', status: 404 };
  requireDb().prepare('UPDATE scheduled_tasks SET enabled=?, updated_at=? WHERE id=?').run(enabled ? 1 : 0, Date.now(), cur.id);
  return { ok: true, task: getTask(cur.id) };
}

function deleteTask(id) {
  const cur = getTask(id);
  if (!cur) return { ok: false, error: 'tâche introuvable', status: 404 };
  const d = requireDb();
  d.prepare('DELETE FROM scheduled_tasks WHERE id = ?').run(cur.id);
  d.prepare('DELETE FROM scheduled_task_runs WHERE task_id = ?').run(cur.id);
  return { ok: true };
}

/** Enregistre une exécution et met à jour le « dernier résultat » de la tâche. */
function recordRun(taskId, { startedAt, durationMs, status, message, trigger, by }) {
  const d = requireDb();
  const msg = clip(message, 2000);
  d.prepare(`INSERT INTO scheduled_task_runs (task_id, started_at, duration_ms, status, message, trigger, by) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(taskId, startedAt, durationMs, status, msg, trigger || 'schedule', by || null);
  d.prepare(`UPDATE scheduled_tasks SET last_run_at=?, last_status=?, last_message=?, last_duration_ms=?, run_count=run_count+1 WHERE id=?`)
    .run(startedAt, status, msg, durationMs, taskId);
  d.prepare(`DELETE FROM scheduled_task_runs WHERE task_id = ? AND id NOT IN
             (SELECT id FROM scheduled_task_runs WHERE task_id = ? ORDER BY started_at DESC, id DESC LIMIT ?)`)
    .run(taskId, taskId, MAX_RUNS_PER_TASK);
}

function listRuns(taskId, limit = 20) {
  const lim = Math.max(1, Math.min(MAX_RUNS_PER_TASK, Math.floor(Number(limit)) || 20));
  return requireDb().prepare(`SELECT id, task_id AS taskId, started_at AS startedAt, duration_ms AS durationMs,
      status, message, trigger, by FROM scheduled_task_runs WHERE task_id = ? ORDER BY started_at DESC, id DESC LIMIT ?`)
    .all(Number(taskId), lim);
}

// ─── Fichier tâche (export / import) ─────────────────────────────────────────
const FILE_VERSION = 1;

function exportTasks() {
  return {
    format: 'nginx-dashboard-scheduled-tasks',
    version: FILE_VERSION,
    exportedAt: new Date().toISOString(),
    tasks: listTasks().map(t => ({
      name: t.name, type: t.type, enabled: t.enabled, schedule: t.schedule, params: t.params, notify: t.notify,
    })),
  };
}

/**
 * Importe un fichier tâche. Tout est validé AVANT la moindre écriture : un seul
 * élément invalide refuse l'ensemble (jamais d'import partiel).
 * mode 'merge' : ajoute (une tâche identique — mêmes nom, type, planification et
 * paramètres — n'est pas dupliquée) ; mode 'replace' : remplace tout.
 */
function importTasks(content, mode = 'merge') {
  let doc;
  try { doc = typeof content === 'string' ? JSON.parse(content) : content; }
  catch (e) { return { ok: false, error: 'fichier illisible (JSON attendu)' }; }
  if (!doc || doc.format !== 'nginx-dashboard-scheduled-tasks' || !Array.isArray(doc.tasks)) {
    return { ok: false, error: 'ce n\'est pas un fichier de tâches nginx-dashboard' };
  }
  if (doc.version !== FILE_VERSION) return { ok: false, error: `version de fichier non prise en charge : ${clip(doc.version, 10)}` };
  if (doc.tasks.length > MAX_TASKS) return { ok: false, error: `trop de tâches (${MAX_TASKS} max)` };
  if (mode !== 'merge' && mode !== 'replace') return { ok: false, error: 'mode : merge ou replace' };

  const parsed = [];
  for (let i = 0; i < doc.tasks.length; i++) {
    const v = validateTask(doc.tasks[i]);
    if (!v.ok) return { ok: false, error: `tâche n°${i + 1} : ${v.error}` };
    parsed.push(v.value);
  }
  const d = requireDb();
  const sig = x => JSON.stringify([x.name, x.type, x.cron, x.params]);
  let added = 0, skipped = 0;
  d.exec('BEGIN');
  try {
    if (mode === 'replace') { d.exec('DELETE FROM scheduled_tasks; DELETE FROM scheduled_task_runs;'); }
    const existing = new Set(listTasks().map(sig));
    const count = d.prepare('SELECT COUNT(*) AS n FROM scheduled_tasks').get().n;
    if (count + parsed.length > MAX_TASKS) throw new Error(`limite de ${MAX_TASKS} tâches dépassée`);
    for (const x of parsed) {
      if (existing.has(sig(x))) { skipped++; continue; }
      const t = Date.now();
      d.prepare(`INSERT INTO scheduled_tasks (name, type, enabled, schedule, cron, params, notify, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(x.name, x.type, x.enabled ? 1 : 0, JSON.stringify(x.schedule), x.cron, JSON.stringify(x.params), x.notify ? 1 : 0, t, t);
      existing.add(sig(x));
      added++;
    }
    d.exec('COMMIT');
  } catch (e) {
    try { d.exec('ROLLBACK'); } catch { /* déjà annulé */ }
    return { ok: false, error: e.message };
  }
  return { ok: true, added, skipped, mode };
}

// ─── Migration de l'ancien scheduler.yml ─────────────────────────────────────
/**
 * Convertit les cinq tâches de l'ancien `scheduler.yml` (déjà analysé par
 * lib/notify.js#loadSchedConfig) en tâches de la base, UNE seule fois. Les
 * entrées présentes dans le fichier sont créées avec leur état activé/désactivé
 * d'origine, pour qu'une installation existante se retrouve à l'identique.
 * @param {object|null} legacy  résultat de loadSchedConfig()
 * @returns {{migrated:boolean, created:number}}
 */
function migrateLegacyYaml(legacy) {
  if (!ensureTables()) return { migrated: false, created: 0 };
  if (events.getState(MIGRATED_KEY)) return { migrated: false, created: 0 };
  let created = 0;
  const LEGACY = [
    { key: 'nginx_reload', type: 'nginx_reload', name: 'Recharger Nginx', notifyKey: 'notify' },
    { key: 'nginx_restart', type: 'nginx_restart', name: 'Redémarrer le conteneur Nginx', notifyKey: 'notify' },
    { key: 'digest', type: 'digest', name: 'Résumé périodique', notifyKey: 'notify' },
    { key: 'backup', type: 'backup', name: 'Sauvegarde', notifyKey: 'notify_on_failure' },
    { key: 'goaccess_restart', type: 'goaccess_restart', name: 'Redémarrer GoAccess', notifyKey: 'notify' },
  ];
  for (const L of LEGACY) {
    const c = legacy && typeof legacy[L.key] === 'object' ? legacy[L.key] : null;
    if (!c) continue;
    const params = {};
    if (L.type === 'nginx_restart' && c.grace_seconds != null) params.grace_seconds = c.grace_seconds;
    if (L.type === 'digest') {
      if (c.period_hours != null) params.period_hours = c.period_hours;
      if (Array.isArray(c.recipients)) params.recipients = c.recipients;
    }
    if (L.type === 'backup' && c.mode) params.mode = c.mode;
    if (L.type === 'goaccess_restart' && Array.isArray(c.sources)) params.sources = c.sources;
    const schedule = cron.scheduleFromCron(String(c.cron || '')) || { mode: 'daily', time: '03:00' };
    const r = createTask({
      name: L.name, type: L.type, enabled: c.enable === true, schedule, params,
      notify: c[L.notifyKey] === true,
    });
    if (r.ok) created++;
    else console.warn(`[scheduler] migration de « ${L.key} » ignorée : ${r.error}`);
  }
  events.setState(MIGRATED_KEY, new Date().toISOString());
  if (created) console.log(`[scheduler] ${created} tâche(s) importée(s) depuis scheduler.yml`);
  return { migrated: true, created };
}

module.exports = {
  ensureTables, validateTask, listTasks, getTask, createTask, updateTask, setEnabled, deleteTask,
  recordRun, listRuns, exportTasks, importTasks, migrateLegacyYaml,
  MAX_TASKS, MAX_NAME, MAX_RUNS_PER_TASK, FILE_VERSION,
};
