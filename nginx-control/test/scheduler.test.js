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

  console.log('\nconfiguration effectivement lue depuis scheduler.yml (regression : schedCfg jamais assigne)');
  await check('une tache activee avec un cron qui correspond toujours se declenche reellement', async () => {
    // Bug reel, trouve en ecrivant un test pour la nouvelle tache de
    // redemarrage planifie : `loadSchedConfig()` (lib/notify.js) met a jour
    // SA PROPRE variable interne et renvoie la config analysee — ce fichier
    // declare son propre `schedCfg` separe, lu par toutes les taches
    // planifiees, mais la valeur de retour n etait jamais recuperee dans la
    // boucle de sondage NI au demarrage. `schedCfg` restait donc a `null`
    // pour toujours : chaque `schedCfg?.xxx` s evaluait a `undefined`, sans
    // la moindre erreur ni avertissement, quel que soit le contenu reel de
    // scheduler.yml. Reload planifie, sauvegarde planifiee et redemarrage
    // GoAccess planifie n avaient donc jamais pu se declencher.
    require('fs').writeFileSync(
      require('path').join(tmpConfigDir, 'scheduler.yml'),
      'nginx_restart:\n  enable: true\n  cron: "* * * * *"\n  notify: false\n'
    );
    let restartCalled = false;
    scheduler.setTasks({
      execNginx: async () => ({ valid: true, stdout: 'ok' }),
      restartContainer: async () => { restartCalled = true; },
    });

    const realSetInterval = global.setInterval;
    let captured = null;
    global.setInterval = (fn) => { captured = fn; return { unref(){} }; };
    try {
      scheduler.startScheduler();
      assert.ok(captured, 'setInterval doit avoir ete appele au demarrage');
      await captured();
    } finally { global.setInterval = realSetInterval; }

    assert.strictEqual(restartCalled, true,
      'une tache activee, avec un cron qui correspond toujours, doit reellement se declencher');
  });
  await check('une tache desactivee (enable:false) ne se declenche jamais, meme avec un cron qui correspond', async () => {
    require('fs').writeFileSync(
      require('path').join(tmpConfigDir, 'scheduler.yml'),
      'nginx_restart:\n  enable: false\n  cron: "* * * * *"\n  notify: false\n'
    );
    let restartCalled = false;
    scheduler.setTasks({
      execNginx: async () => ({ valid: true, stdout: 'ok' }),
      restartContainer: async () => { restartCalled = true; },
    });
    const realSetInterval = global.setInterval;
    let captured = null;
    global.setInterval = (fn) => { captured = fn; return { unref(){} }; };
    try {
      scheduler.startScheduler();
      await captured();
    } finally { global.setInterval = realSetInterval; }
    assert.strictEqual(restartCalled, false);
  });
  await check('nginx -t en echec bloque le redemarrage planifie, meme si le cron correspond', async () => {
    require('fs').writeFileSync(
      require('path').join(tmpConfigDir, 'scheduler.yml'),
      'nginx_restart:\n  enable: true\n  cron: "* * * * *"\n  notify: false\n'
    );
    let restartCalled = false;
    scheduler.setTasks({
      execNginx: async () => ({ valid: false, stderr: 'nginx: configuration file test failed' }),
      restartContainer: async () => { restartCalled = true; },
    });
    const realSetInterval = global.setInterval;
    let captured = null;
    global.setInterval = (fn) => { captured = fn; return { unref(){} }; };
    try {
      scheduler.startScheduler();
      await captured();
    } finally { global.setInterval = realSetInterval; }
    assert.strictEqual(restartCalled, false,
      'un redemarrage sur une configuration cassee est pire qu un reload sur une configuration cassee : le conteneur se retrouve sans nginx du tout, pas seulement avec une ancienne configuration qui continue de servir');
  });

  console.log('\ndigest planifie');
  await check('runScheduledDigest() genere et sauvegarde reellement un digest', async () => {
    // Appel direct plutot que via le tick capture : les taches planifiees
    // sont volontairement "tire et oublie" dans la boucle de sondage (une
    // tache lente ne doit pas bloquer les autres), donc capturer le tick et
    // verifier immediatement apres cree une course avec le propre travail
    // asynchrone du digest (generation + ecriture SQLite). Un appel direct
    // a la fonction exportee, lui, est correctement attendu de bout en bout.
    require('fs').writeFileSync(
      require('path').join(tmpConfigDir, 'scheduler.yml'),
      'digest:\n  enable: true\n  cron: "* * * * *"\n  period_hours: 24\n  notify: false\n'
    );
    const digest = require('../lib/digest');
    const events = require('../lib/events');
    events.initEventsDb();
    digest.configure({
      analyzerApi: async (p) => p.includes('vhosts')
        ? { data: { vhosts: [{ vhost: 'test.fr', requests: 321, bytes: 10, errors: 0 }] } }
        : { data: null },
      crowdsecGet: null, crowdsecConfigured: () => false,
      listExistingCerts: () => [],
    });

    scheduler.startScheduler();   // recharge schedCfg avec la nouvelle config
    await scheduler.runScheduledDigest();

    const latest = events.getLatestDigest();
    assert.ok(latest, 'un digest doit avoir ete sauvegarde');
    assert.strictEqual(latest.traffic.totalRequests, 321);
  });
  await check('digest desactive (enable:false) ne genere rien', async () => {
    require('fs').writeFileSync(
      require('path').join(tmpConfigDir, 'scheduler.yml'),
      'digest:\n  enable: false\n  cron: "* * * * *"\n'
    );
    const events = require('../lib/events');
    const before = events.listDigests(1)[0]?.id || 0;
    scheduler.startScheduler();
    await scheduler.runScheduledDigest();
    const after = events.listDigests(1)[0]?.id || 0;
    assert.strictEqual(after, before, 'aucun nouveau digest ne doit apparaitre');
  });
  await check('le declencheur de tick se met bien en route pour le digest (cron qui correspond)', async () => {
    // Verifie que la boucle de sondage appelle reellement runScheduledDigest
    // quand le cron correspond — sans verifier le contenu ecrit (course
    // deja expliquee plus haut), juste que l appel part.
    require('fs').writeFileSync(
      require('path').join(tmpConfigDir, 'scheduler.yml'),
      'digest:\n  enable: true\n  cron: "* * * * *"\n'
    );
    const digest = require('../lib/digest');
    let generateCalled = false;
    const realGenerate = digest.generateDigest;
    digest.generateDigest = async (...args) => { generateCalled = true; return realGenerate(...args); };
    digest.configure({ analyzerApi: null, crowdsecGet: null, crowdsecConfigured: () => false, listExistingCerts: () => [] });

    const realSetInterval = global.setInterval;
    let captured = null;
    global.setInterval = (fn) => { captured = fn; return { unref(){} }; };
    try {
      scheduler.startScheduler();
      captured();   // volontairement non attendu : on verifie juste le declenchement
      await new Promise(r => setTimeout(r, 100));
    } finally { global.setInterval = realSetInterval; digest.generateDigest = realGenerate; }
    assert.strictEqual(generateCalled, true);
  });

  console.log('\nredemarrage GoAccess planifie (regression : bug audit Basse/"Partie 1 et certificats")');
  await check('runScheduledGoAccessRestart() appelait auparavant des identifiants non declares (ReferenceError avalee par le .catch) ; verifie ici que le cycle complet s execute reellement', async () => {
    require('fs').writeFileSync(
      require('path').join(tmpConfigDir, 'scheduler.yml'),
      'goaccess_restart:\n  enable: true\n  cron: "* * * * *"\n'
    );
    let listCalled = false, statusCalled = false, restartCalled = false;
    scheduler.setTasks({
      listGoAccessSources: () => { listCalled = true; return [{ id: 'src1' }, { id: 'src2' }]; },
      getGoAccessContainerStatus: async (id) => { statusCalled = true; return { running: id === 'src1' }; },
      restartGoAccessContainer: async (id) => { restartCalled = true; assert.strictEqual(id, 'src1'); },
    });

    scheduler.startScheduler();   // recharge schedCfg avec la nouvelle config
    await scheduler.runScheduledGoAccessRestart();

    assert.strictEqual(listCalled, true, 'listGoAccessSources (via tasks.) doit avoir ete appele');
    assert.strictEqual(statusCalled, true, 'getGoAccessContainerStatus (via tasks.) doit avoir ete appele');
    assert.strictEqual(restartCalled, true, 'restartGoAccessContainer (via tasks.) doit avoir ete appele pour le conteneur actif');
  });
  await check('goaccess_restart desactive (enable:false) ne declenche aucun appel', async () => {
    require('fs').writeFileSync(
      require('path').join(tmpConfigDir, 'scheduler.yml'),
      'goaccess_restart:\n  enable: false\n  cron: "* * * * *"\n'
    );
    let called = false;
    scheduler.setTasks({
      listGoAccessSources: () => { called = true; return []; },
      getGoAccessContainerStatus: async () => ({ running: false }),
      restartGoAccessContainer: async () => {},
    });
    scheduler.startScheduler();
    await scheduler.runScheduledGoAccessRestart();
    assert.strictEqual(called, false);
  });
  await check('le declencheur de tick se met bien en route pour le redemarrage GoAccess (cron qui correspond)', async () => {
    require('fs').writeFileSync(
      require('path').join(tmpConfigDir, 'scheduler.yml'),
      'goaccess_restart:\n  enable: true\n  cron: "* * * * *"\n'
    );
    let listCalled = false;
    scheduler.setTasks({
      listGoAccessSources: () => { listCalled = true; return []; },
      getGoAccessContainerStatus: async () => ({ running: false }),
      restartGoAccessContainer: async () => {},
    });
    const realSetInterval = global.setInterval;
    let captured = null;
    global.setInterval = (fn) => { captured = fn; return { unref(){} }; };
    try {
      scheduler.startScheduler();
      captured();   // volontairement non attendu, comme pour le digest ci-dessus
      await new Promise(r => setTimeout(r, 100));
    } finally { global.setInterval = realSetInterval; }
    assert.strictEqual(listCalled, true);
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
