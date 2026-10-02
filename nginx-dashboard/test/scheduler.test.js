'use strict';
/**
 * `lastSchedulerMinute` etait lue sans jamais avoir ete declaree — une
 * ReferenceError en mode strict, a chaque tick, sans exception. Avant le
 * filet de securite global ajoute ailleurs dans ce projet, ceci aurait fait
 * planter le processus des le premier tick ; depuis, l echec se repetait
 * silencieusement en boucle, et aucune tache planifiee (verification de
 * certificats, sauvegardes) n a jamais pu s executer.
 *
 * Deuxieme regression trouvee en ecrivant ce test lui-meme : `check()` n
 * attendait pas les verifications asynchrones. `f()` renvoie une promesse
 * immediatement ; le try/catch synchrone ne voit jamais un rejet qui survient
 * apres coup, et "PASS" s affiche avant meme que l assertion interne se soit
 * executee. Verifie concretement : avec le bug de variable reintroduit
 * exprès, ce test "passait" quand meme jusqu a cette correction.
 */
const assert = require('assert');
let pass = 0, fail = 0;
const check = async (n, f) => {
  try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; }
};

// CONFIG_DIR n a pas de variable d environnement a lui : il est toujours
// derive du repertoire de USERS_FILE (voir lib/config.js). Ce fichier fixait
// auparavant CONFIG_DIR directement, une variable que rien dans le code reel
// ne lit — les tests tournaient donc sans le savoir contre le vrai
// scheduler.yml du systeme plutot qu un dossier isole. C est precisement ce
// qui a permis a la regression ci-dessous (schedCfg jamais assigne) de
// passer inapercue : aucun test ici ne verifiait jamais le comportement
// pilote par un fichier de configuration reel.
const tmpConfigDir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'sched-'));
process.env.USERS_FILE = require('path').join(tmpConfigDir, 'users.yml');
require('fs').writeFileSync(process.env.USERS_FILE, 'users: []\n');
const scheduler = require('../lib/scheduler');

(async () => {
  console.log('\ndemarrage du planificateur (regression : variable non declaree)');
  await check('le module se charge sans exception', () => { assert.ok(scheduler.startScheduler); });
  await check('le planificateur tourne au moins un tick sans lever de ReferenceError', async () => {
    // L intervalle reel est de 30s — bien trop long pour une suite de tests.
    // setInterval est intercepte pour recuperer le callback et le declencher
    // immediatement, plutot que d attendre en conditions reelles.
    const realSetInterval = global.setInterval;
    let captured = null;
    global.setInterval = (fn, ms) => { captured = fn; return { unref(){} }; };
    try {
      scheduler.startScheduler();
      assert.ok(captured, 'setInterval doit avoir ete appele au demarrage');
      // Le callback rejette directement si la variable manque : pas besoin
      // d un ecouteur unhandledRejection, juste attendre la promesse.
      await captured();
    } finally { global.setInterval = realSetInterval; }
  });
  await check('aucune variable non declaree dans le fichier (mode strict)', () => {
    const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'scheduler.js'), 'utf8');
    assert.ok(/let lastSchedulerMinute/.test(src), 'la variable doit etre explicitement declaree');
  });

  console.log('\ncorrespondance cron');
  await check('champ * accepte toute valeur', () => {
    assert.strictEqual(scheduler.matchCron('* * * * *', new Date('2026-01-01T00:00:00')), true);
  });
  await check('champ precis doit correspondre exactement', () => {
    assert.strictEqual(scheduler.matchCron('30 2 * * *', new Date('2026-01-01T02:30:00')), true);
    assert.strictEqual(scheduler.matchCron('30 2 * * *', new Date('2026-01-01T02:31:00')), false);
  });
  await check('format invalide -> false, pas d exception', () => {
    assert.doesNotThrow(() => scheduler.matchCron('n importe quoi', new Date()));
  });

  console.log('\ntaches stockees en base (v12.56.0) — remplace la lecture de scheduler.yml');
  const events = require('../lib/events');
  events.initEventsDb();
  const store = require('../lib/scheduler-store');
  const fs = require('fs'), path = require('path');
  const clearTasks = () => { for (const t of store.listTasks()) store.deleteTask(t.id); };
  const everyMinute = { mode: 'interval', every: 1, unit: 'minutes' };
  const seed = (type, extra = {}) => {
    const r = store.createTask({ name: 'test ' + type, type, enabled: true, schedule: everyMinute, params: {}, notify: false, ...extra });
    assert.ok(r.ok, r.error);
    return r.task;
  };
  const tick = async () => {
    const realSetInterval = global.setInterval;
    let captured = null;
    global.setInterval = (fn) => { captured = fn; return { unref(){} }; };
    try { scheduler.startScheduler(); assert.ok(captured, 'setInterval doit avoir ete appele au demarrage'); await captured(); }
    finally { global.setInterval = realSetInterval; }
    await new Promise(r => setTimeout(r, 150)); // taches tire-et-oublie
  };

  await check('une tache activee dont le cron correspond se declenche reellement (via le tick)', async () => {
    clearTasks();
    seed('nginx_restart');
    let restartCalled = false;
    scheduler.setTasks({
      execNginx: async () => ({ valid: true, stdout: 'ok' }),
      restartContainer: async () => { restartCalled = true; },
    });
    await tick();
    assert.strictEqual(restartCalled, true, 'une tache activee, avec un cron qui correspond toujours, doit reellement se declencher');
  });
  await check('une tache desactivee ne se declenche jamais, meme avec un cron qui correspond', async () => {
    clearTasks();
    seed('nginx_restart', { enabled: false });
    let restartCalled = false;
    scheduler.setTasks({
      execNginx: async () => ({ valid: true, stdout: 'ok' }),
      restartContainer: async () => { restartCalled = true; },
    });
    await tick();
    assert.strictEqual(restartCalled, false);
  });
  await check('nginx -t en echec bloque le redemarrage planifie, meme si le cron correspond', async () => {
    clearTasks();
    const t = seed('nginx_restart');
    let restartCalled = false;
    scheduler.setTasks({
      execNginx: async () => ({ valid: false, stderr: 'nginx: configuration file test failed' }),
      restartContainer: async () => { restartCalled = true; },
    });
    await tick();
    assert.strictEqual(restartCalled, false,
      'un redemarrage sur une configuration cassee est pire qu un reload sur une configuration cassee : le conteneur se retrouve sans nginx du tout');
    assert.strictEqual(store.getTask(t.id).lastStatus, 'error');
  });
  await check('nginx -t en echec bloque aussi le reload planifie', async () => {
    clearTasks();
    seed('nginx_reload');
    const cmds = [];
    scheduler.setTasks({
      execNginx: async (c) => { cmds.push(c); return { valid: false, stderr: 'test failed' }; },
    });
    await tick();
    assert.deepStrictEqual(cmds, ['nginx -t']);
  });
  await check('chaque execution est enregistree (statut, duree, historique, dernier message)', async () => {
    clearTasks();
    const t = seed('nginx_reload');
    scheduler.setTasks({ execNginx: async () => ({ valid: true, stdout: 'ok' }) });
    const r = await scheduler.runTaskNow(t.id, 'romain');
    assert.strictEqual(r.status, 'ok');
    const cur = store.getTask(t.id);
    assert.deepStrictEqual([cur.lastStatus, cur.runCount], ['ok', 1]);
    assert.ok(cur.lastDurationMs >= 0);
    const runs = store.listRuns(t.id);
    assert.deepStrictEqual([runs.length, runs[0].trigger, runs[0].by], [1, 'manual', 'romain']);
  });
  await check('une tache ne se chevauche jamais elle-meme (deuxieme lancement -> busy)', async () => {
    clearTasks();
    const t = seed('nginx_restart');
    let release;
    scheduler.setTasks({
      execNginx: async () => ({ valid: true }),
      restartContainer: () => new Promise(r => { release = r; }),
    });
    const first = scheduler.runTaskNow(t.id, 'a');
    await new Promise(r => setTimeout(r, 30));
    assert.strictEqual(scheduler.isRunning(t.id), true);
    const second = await scheduler.runTaskNow(t.id, 'b');
    assert.strictEqual(second.status, 'busy');
    release();
    assert.strictEqual((await first).status, 'ok');
    assert.strictEqual(scheduler.isRunning(t.id), false);
  });
  await check('une exception dans une tache est capturee : statut error, jamais de plantage', async () => {
    clearTasks();
    const t = seed('backup', { params: { mode: 'local' } });
    scheduler.setTasks({ createBackupZip: async () => { throw new Error('disque plein'); } });
    const r = await scheduler.runTaskNow(t.id, 'x');
    assert.strictEqual(r.status, 'error');
    assert.ok(/disque plein/.test(r.message));
  });

  console.log('\nimport unique de l ancien scheduler.yml');
  await check('les entrees de scheduler.yml deviennent des taches (etat, cron, parametres conserves), une seule fois', async () => {
    clearTasks();
    events.setState('scheduler_tasks_migrated_v1', null);
    fs.writeFileSync(path.join(tmpConfigDir, 'scheduler.yml'), [
      'nginx_reload:', '  enable: true', '  cron: "0 3 * * *"', '  notify: true',
      'nginx_restart:', '  enable: false', '  cron: "0 4 * * 0"', '  grace_seconds: 20', '  notify: false',
      'digest:', '  enable: true', '  cron: "0 7 * * 1"', '  period_hours: 168', '  notify: true', '  recipients:', '    - admin@example.com',
      'backup:', '  enable: true', '  cron: "0 2 * * *"', '  mode: both', '  notify_on_failure: true',
    ].join('\n'));
    scheduler.startScheduler.call(null); // restaure setInterval reel ci-dessous
  }).catch(() => {});
  clearTasks();
  events.setState('scheduler_tasks_migrated_v1', null);
  {
    const realSetInterval = global.setInterval; global.setInterval = () => ({ unref(){} });
    try { scheduler.startScheduler(); } finally { global.setInterval = realSetInterval; }
  }
  await check('migration : 4 taches creees avec leurs reglages', () => {
    const list = store.listTasks();
    assert.strictEqual(list.length, 4);
    const by = Object.fromEntries(list.map(t => [t.type, t]));
    assert.deepStrictEqual([by.nginx_reload.enabled, by.nginx_reload.cron, by.nginx_reload.notify], [true, '0 3 * * *', true]);
    assert.deepStrictEqual([by.nginx_restart.enabled, by.nginx_restart.params.grace_seconds, by.nginx_restart.schedule.mode], [false, 20, 'weekly']);
    assert.deepStrictEqual([by.digest.params.period_hours, by.digest.params.recipients], [168, ['admin@example.com']]);
    assert.deepStrictEqual([by.backup.params.mode, by.backup.notify], ['both', true]);
  });
  await check('migration non rejouee : une tache supprimee ne revient pas au demarrage suivant', () => {
    const t = store.listTasks().find(x => x.type === 'digest');
    store.deleteTask(t.id);
    const realSetInterval = global.setInterval; global.setInterval = () => ({ unref(){} });
    try { scheduler.startScheduler(); } finally { global.setInterval = realSetInterval; }
    assert.strictEqual(store.listTasks().length, 3);
  });

  console.log('\ndigest planifie');
  await check('la tache digest genere et sauvegarde reellement un digest', async () => {
    clearTasks();
    const t = seed('digest', { params: { period_hours: 24 } });
    const digest = require('../lib/digest');
    digest.configure({
      analyzerApi: async (p) => p.includes('vhosts')
        ? { data: { vhosts: [{ vhost: 'test.fr', requests: 321, bytes: 10, errors: 0 }] } }
        : { data: null },
      crowdsecGet: null, crowdsecConfigured: () => false,
      listExistingCerts: () => [],
    });
    const r = await scheduler.runTaskNow(t.id, 'test');
    assert.strictEqual(r.status, 'ok', r.message);
    const latest = events.getLatestDigest();
    assert.ok(latest, 'un digest doit avoir ete sauvegarde');
    assert.strictEqual(latest.traffic.totalRequests, 321);
  });
  await check('digest desactive : le tick ne genere rien', async () => {
    clearTasks();
    seed('digest', { enabled: false });
    const before = events.listDigests(1)[0]?.id || 0;
    await tick();
    assert.strictEqual(events.listDigests(1)[0]?.id || 0, before, 'aucun nouveau digest ne doit apparaitre');
  });
  await check('le declencheur de tick se met en route pour le digest (cron qui correspond)', async () => {
    clearTasks();
    seed('digest');
    const digest = require('../lib/digest');
    let generateCalled = false;
    const realGenerate = digest.generateDigest;
    digest.generateDigest = async (...args) => { generateCalled = true; return realGenerate(...args); };
    digest.configure({ analyzerApi: null, crowdsecGet: null, crowdsecConfigured: () => false, listExistingCerts: () => [] });
    try { await tick(); } finally { digest.generateDigest = realGenerate; }
    assert.strictEqual(generateCalled, true);
  });

  console.log('\nredemarrage de l analyzer planifie (v12.56.0)');
  await check('analyzer_restart appelle restartAnalyzer avec delai et attente, statut ok', async () => {
    clearTasks();
    const t = seed('analyzer_restart', { params: { grace_seconds: 15, wait_healthy: true } });
    let got = null;
    scheduler.setTasks({ restartAnalyzer: async (o) => { got = o; return { ok: true, healthy: true, message: 'redemarre, API de retour apres 4.0 s' }; } });
    const r = await scheduler.runTaskNow(t.id, 'x');
    assert.deepStrictEqual(got, { graceSeconds: 15, waitHealthy: true });
    assert.strictEqual(r.status, 'ok');
  });
  await check('analyzer_restart : API qui ne revient pas -> erreur (pas un faux succes)', async () => {
    clearTasks();
    const t = seed('analyzer_restart');
    scheduler.setTasks({ restartAnalyzer: async () => ({ ok: false, healthy: false, message: "l'API ne repond toujours pas apres 90 s" }) });
    const r = await scheduler.runTaskNow(t.id, 'x');
    assert.strictEqual(r.status, 'error');
    assert.ok(/ne repond/.test(r.message));
  });
  await check('analyzer_restart : analyzer desactive -> skipped ; conteneur absent -> error', async () => {
    clearTasks();
    const t = seed('analyzer_restart');
    scheduler.setTasks({ restartAnalyzer: async () => ({ ok: false, skipped: true, message: 'desactive' }) });
    assert.strictEqual((await scheduler.runTaskNow(t.id, 'x')).status, 'skipped');
    scheduler.setTasks({ restartAnalyzer: async () => { throw new Error('Conteneur absent'); } });
    const r = await scheduler.runTaskNow(t.id, 'x');
    assert.strictEqual(r.status, 'error');
    assert.ok(/absent/.test(r.message));
  });

  console.log('\nredemarrage GoAccess planifie (regression : bug audit Basse/"Partie 1 et certificats")');
  await check('le cycle complet GoAccess s execute reellement (liste, statut, redemarrage du seul conteneur actif)', async () => {
    clearTasks();
    const t = seed('goaccess_restart');
    let listCalled = false, statusCalled = false, restartCalled = false;
    scheduler.setTasks({
      listGoAccessSources: () => { listCalled = true; return [{ id: 'src1' }, { id: 'src2' }]; },
      getGoAccessContainerStatus: async (id) => { statusCalled = true; return { running: id === 'src1' }; },
      restartGoAccessContainer: async (id) => { restartCalled = true; assert.strictEqual(id, 'src1'); },
    });
    const r = await scheduler.runTaskNow(t.id, 'x');
    assert.strictEqual(r.status, 'ok', r.message);
    assert.deepStrictEqual([listCalled, statusCalled, restartCalled], [true, true, true]);
  });
  await check('goaccess_restart avec sources choisies : seules celles-la sont visees', async () => {
    clearTasks();
    const t = seed('goaccess_restart', { params: { sources: ['src2'] } });
    const seen = [];
    scheduler.setTasks({
      listGoAccessSources: () => [{ id: 'src1' }, { id: 'src2' }],
      getGoAccessContainerStatus: async () => ({ running: true }),
      restartGoAccessContainer: async (id) => { seen.push(id); },
    });
    await scheduler.runTaskNow(t.id, 'x');
    assert.deepStrictEqual(seen, ['src2']);
  });
  await check('goaccess_restart desactive : aucun appel', async () => {
    clearTasks();
    seed('goaccess_restart', { enabled: false });
    let called = false;
    scheduler.setTasks({ listGoAccessSources: () => { called = true; return []; } });
    await tick();
    assert.strictEqual(called, false);
  });

  console.log('\nrecheck SSL des agents distants (fix, audit report Basse/"Agents (dashboard)")');
  await check('runScheduledAgentSslRecheck() : rien a verifier -> reapplyAgentManifest jamais appele', async () => {
    let listCalled = false, applyCalled = false;
    scheduler.setTasks({
      listAgentsNeedingSslRecheck: () => { listCalled = true; return []; },
      reapplyAgentManifest: async () => { applyCalled = true; return { ok: true }; },
    });
    await scheduler.runScheduledAgentSslRecheck();
    assert.strictEqual(listCalled, true);
    assert.strictEqual(applyCalled, false);
  });
  await check('runScheduledAgentSslRecheck() : rejoue bien chaque agent candidat', async () => {
    const seen = [];
    scheduler.setTasks({
      listAgentsNeedingSslRecheck: () => ['agentA', 'agentB'],
      reapplyAgentManifest: async (id) => { seen.push(id); return { ok: true }; },
    });
    await scheduler.runScheduledAgentSslRecheck();
    assert.deepStrictEqual(seen, ['agentA', 'agentB']);
  });
  await check('un agent qui echoue n empeche pas les suivants (isolation des erreurs)', async () => {
    const seen = [];
    scheduler.setTasks({
      listAgentsNeedingSslRecheck: () => ['agentA', 'agentB'],
      reapplyAgentManifest: async (id) => {
        seen.push(id);
        if (id === 'agentA') throw new Error('boom');
        return { ok: true };
      },
    });
    await assert.doesNotReject(() => scheduler.runScheduledAgentSslRecheck());
    assert.deepStrictEqual(seen, ['agentA', 'agentB']);
  });
  await check('declenche bien depuis la boucle de sondage toutes les 5 minutes (pas a chaque tick)', async () => {
    let called = 0;
    scheduler.setTasks({
      listAgentsNeedingSslRecheck: () => { called++; return []; },
      reapplyAgentManifest: async () => ({ ok: true }),
    });
    const realSetInterval = global.setInterval;
    let captured = null;
    global.setInterval = (fn) => { captured = fn; return { unref(){} }; };
    // matchCron() etc n interviennent pas ici : le module Date reel est
    // utilise, donc on verifie seulement que l appel a bien lieu (peu importe
    // la minute reelle au moment du test) — le filtrage "toutes les 5 min"
    // est verifie separement par lecture du source ci-dessous.
    try {
      scheduler.startScheduler();
      await captured();
    } finally { global.setInterval = realSetInterval; }
    const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'scheduler.js'), 'utf8');
    assert.ok(/getMinutes\(\)\s*%\s*5\s*===\s*0/.test(src), 'doit etre filtre a toutes les 5 minutes, jamais a chaque tick de 30s');
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
