'use strict';
/**
 * features/blocklists.js — end-to-end behavior with a fake upstream blocklist
 * server and a mocked `nginx -t` / `nginx -s reload` (docker.execNginx),
 * since neither a real Docker socket nor a real nginx are available here.
 *
 * Covers the three safety properties from that file's header: first-run
 * safety (ensureSnippetsAtBoot), cache-on-failure (a source that stops
 * responding doesn't lose its previously-known IPs), and test-before-reload
 * with rollback (a failing `nginx -t` must restore the previous snippet).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blocklists-'));
  process.env.USERS_FILE   = path.join(dir, 'config', 'users.yml');
  fs.mkdirSync(path.dirname(process.env.USERS_FILE), { recursive: true });
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  process.env.DIR_SNIPPETS = path.join(dir, 'snippets');
  process.env.DIR_CONF     = path.join(dir, 'conf');
  process.env.DIR_LOGS     = path.join(dir, 'logs');

  const docker = require('../lib/docker');
  const events = require('../lib/events');
  const cfg    = require('../lib/config');
  const B      = require('../features/blocklists');

  events.initEventsDb(path.join(dir, 'events.db'));

  const writeBlocklistsYaml = (text) => fs.writeFileSync(cfg.BLOCKLIST_CONFIG_FILE, text);

  // ── Fake upstream: one endpoint returns a valid list, another always 500s ──
  let sourceAText = [
    '# Data-Shield style list',
    '1.2.3.4',
    '5.6.7.0/24',
    'garbage line, ignored',
    '',
  ].join('\n');
  let sourceAStatus = 200;
  const server = http.createServer((req, res) => {
    if (req.url === '/a.txt') { res.writeHead(sourceAStatus); res.end(sourceAStatus === 200 ? sourceAText : 'error'); return; }
    if (req.url === '/b.txt') { res.writeHead(500); res.end('boom'); return; }
    res.writeHead(404); res.end();
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  console.log('\nensureSnippetsAtBoot() — securite au tout premier demarrage');
  check('cree des snippets valides (vides) quand aucun n existe encore', () => {
    assert.ok(!fs.existsSync(B.GEO_FILE));
    B.ensureSnippetsAtBoot();
    assert.ok(fs.existsSync(B.GEO_FILE));
    assert.ok(fs.existsSync(B.ENFORCE_FILE));
    const geo = fs.readFileSync(B.GEO_FILE, 'utf8');
    assert.ok(geo.includes('geo $blocklist_ip {'));
    assert.ok(geo.includes('default 0;'));
  });
  check('idempotent : ne touche pas un fichier deja present', () => {
    fs.writeFileSync(B.GEO_FILE, 'contenu personnalise');
    B.ensureSnippetsAtBoot();
    assert.strictEqual(fs.readFileSync(B.GEO_FILE, 'utf8'), 'contenu personnalise');
    // restaure un etat propre pour la suite
    fs.rmSync(B.GEO_FILE);
    B.ensureSnippetsAtBoot();
  });

  writeBlocklistsYaml([
    'enable: true',
    'interval_cron: "0 3 * * *"',
    'block_action: deny_403',
    'sources:',
    `  - name: source-a`,
    `    url: "http://127.0.0.1:${port}/a.txt"`,
    '    enable: true',
    `  - name: source-b`,
    `    url: "http://127.0.0.1:${port}/b.txt"`,
    '    enable: true',
  ].join('\n'));

  console.log('\nrefreshBlocklists() — fusion, deduplication, validation stricte des IP');
  docker.execNginx = async (cmd) => ({ stdout: `${cmd} ok`, stderr: '' }); // nginx -t et -s reload OK

  let status = await B.refreshBlocklists({ manual: true, actor: 'test' });
  check('les deux sources sont tentees', () => {
    assert.strictEqual(status.sources.length, 2);
  });
  check('la source valide contribue ses IP, la ligne garbage est ignoree', () => {
    const a = status.sources.find(s => s.name === 'source-a');
    assert.strictEqual(a.ok, true);
    assert.strictEqual(a.count, 2); // 1.2.3.4 et 5.6.7.0/24, "garbage line" rejetee
  });
  check('la source en echec (HTTP 500) est rapportee sans IP en cache au premier essai', () => {
    const b = status.sources.find(s => s.name === 'source-b');
    assert.strictEqual(b.ok, false);
    assert.strictEqual(b.cachedCount, 0);
  });
  check('le snippet genere contient les IP valides et rien d autre', () => {
    const geo = fs.readFileSync(B.GEO_FILE, 'utf8');
    assert.ok(geo.includes('1.2.3.4 1;'));
    assert.ok(geo.includes('5.6.7.0/24 1;'));
    assert.ok(!geo.includes('garbage'));
  });
  check('reload effectue puisque le contenu a change', () => {
    assert.strictEqual(status.reloaded, true);
  });

  console.log('\nrefreshBlocklists() — une source qui tombe garde ses IP en cache');
  sourceAStatus = 500; // source-a devient indisponible a son tour
  status = await B.refreshBlocklists({ manual: true, actor: 'test' });
  check('toutes les sources ont echoue ce cycle', () => {
    assert.strictEqual(status.allFailedThisCycle, true);
  });
  check('les IP precedemment connues restent dans le snippet (rien efface)', () => {
    const geo = fs.readFileSync(B.GEO_FILE, 'utf8');
    assert.ok(geo.includes('1.2.3.4 1;'));
    assert.ok(geo.includes('5.6.7.0/24 1;'));
  });
  check('aucun reload inutile (rien n a change)', () => {
    assert.strictEqual(status.reloaded, false);
  });
  sourceAStatus = 200; // restaure pour la suite

  console.log('\nrefreshBlocklists() — nginx -t en echec -> restauration, pas de reload');
  const beforeFail = fs.readFileSync(B.GEO_FILE, 'utf8');
  docker.execNginx = async (cmd) => {
    if (cmd === 'nginx -t') throw { error: 'nginx exited with code 1', stderr: 'nginx: [emerg] test failed' };
    return { stdout: 'ok', stderr: '' };
  };
  // Change la liste source pour forcer un contenu different (sinon le
  // refresh est un no-op detecte avant meme d appeler nginx -t).
  sourceAText = sourceAText + '\n9.9.9.9';
  status = await B.refreshBlocklists({ manual: true, actor: 'test' });
  check('le refresh rapporte l echec du test nginx', () => {
    assert.strictEqual(status.testFailed, true);
    assert.strictEqual(status.reloaded, false);
  });
  check('le fichier est restaure a son contenu precedent (rollback)', () => {
    assert.strictEqual(fs.readFileSync(B.GEO_FILE, 'utf8'), beforeFail);
  });
  docker.execNginx = async (cmd) => ({ stdout: `${cmd} ok`, stderr: '' }); // restaure un mock sain

  console.log('\nrefreshBlocklists() — configuration desactivee ou sans source');
  writeBlocklistsYaml('enable: false\nsources: []\n');
  status = await B.refreshBlocklists({ manual: true, actor: 'test' });
  check('feature desactivee -> aucun fetch, refresh ignore', () => {
    assert.strictEqual(status.skipped, true);
    assert.strictEqual(status.reason, 'disabled');
  });

  writeBlocklistsYaml('enable: true\nsources: []\n');
  status = await B.refreshBlocklists({ manual: true, actor: 'test' });
  check('aucune source configuree -> refresh ignore proprement (pas d exception)', () => {
    assert.strictEqual(status.skipped, true);
    assert.strictEqual(status.reason, 'no-sources');
  });

  console.log('\ngetBlocklistStatus()');
  writeBlocklistsYaml([
    'enable: true',
    'sources:',
    `  - name: source-a`,
    `    url: "http://127.0.0.1:${port}/a.txt"`,
    '    enable: true',
  ].join('\n'));
  await B.refreshBlocklists({ manual: true, actor: 'test' });
  const st = B.getBlocklistStatus();
  check('expose les compteurs et l etat des fichiers generes', () => {
    assert.ok(st.totalUniqueIps > 0);
    assert.strictEqual(st.sources.length, 1);
    assert.ok(st.geoFile.exists);
    assert.ok(st.enforceFile.exists);
  });

  console.log('\nhit_logging — snippet genere selon la methode choisie par l operateur');
  check('log_format toujours present, meme desactive (aucune action requise pour activer plus tard)', () => {
    assert.ok(fs.existsSync(B.HITLOG_FORMAT_FILE));
    assert.ok(fs.readFileSync(B.HITLOG_FORMAT_FILE, 'utf8').includes('log_format blocklist_hits'));
  });
  check('hit_logging desactive -> aucune ligne access_log dans le snippet d application', () => {
    assert.ok(!fs.readFileSync(B.ENFORCE_FILE, 'utf8').includes('access_log'));
  });
  check('hit_logging active + methode dedicated -> access_log conditionnel ajoute, sans toucher au bloc if existant', () => {
    const content = B.buildEnforceSnippet('deny_403', { enable: true, method: 'dedicated' });
    assert.ok(content.includes('if ($blocklist_ip) {'));
    assert.ok(content.includes('return 403;'));
    assert.ok(content.includes(`access_log ${B.HIT_LOG_FILE} blocklist_hits if=$blocklist_ip;`));
  });
  check('hit_logging active + methode approx -> aucune ligne access_log (pas de log dedie)', () => {
    const content = B.buildEnforceSnippet('deny_403', { enable: true, method: 'approx' });
    assert.ok(!content.includes('access_log'));
  });
  check('HIT_LOG_FILE est le chemin du conteneur NGINX (/var/log/nginx), jamais DIR_LOGS (interne au dashboard)', () => {
    // Bug reel corrige : le docker-compose de reference ne monte /nginx/logs
    // (DIR_LOGS) que dans le conteneur DASHBOARD, en lecture seule — le
    // conteneur nginx, lui, ne monte que /var/log/nginx (voir logging.conf
    // et features/vhost-generator.js, qui utilisent deja cette meme
    // convention pour leurs propres access_log). Ecrire DIR_LOGS ici faisait
    // echouer `nginx -t` (exit code 1) des que hit_logging_enable passait a
    // true, sur CHAQUE rafraichissement (automatique ou manuel), puisque
    // nginx ne peut pas ouvrir un fichier de log dans un repertoire qui
    // n existe pas dans son propre conteneur.
    assert.strictEqual(B.HIT_LOG_FILE, '/var/log/nginx/blocklist-hits.log');
    assert.ok(!B.HIT_LOG_FILE.includes('/nginx/logs'), 'ne doit jamais referencer DIR_LOGS');
  });
  writeBlocklistsYaml([
    'enable: true',
    'hit_logging_enable: true',
    'hit_logging_method: dedicated',
    'sources:',
    `  - name: source-a`,
    `    url: "http://127.0.0.1:${port}/a.txt"`,
    '    enable: true',
  ].join('\n'));
  await B.refreshBlocklists({ manual: true, actor: 'test' });
  check('refreshBlocklists() applique la methode configuree au snippet reellement ecrit', () => {
    assert.ok(fs.readFileSync(B.ENFORCE_FILE, 'utf8').includes('access_log'));
  });
  // desactive de nouveau pour ne pas polluer les tests suivants
  writeBlocklistsYaml([
    'enable: true', 'sources:',
    `  - name: source-a`, `    url: "http://127.0.0.1:${port}/a.txt"`, '    enable: true',
  ].join('\n'));
  await B.refreshBlocklists({ manual: true, actor: 'test' });

  console.log('\ncheckIp() — recherche d une IP dans les blocklists (une IP peut etre dans plusieurs listes)');
  check('IP presente dans une liste -> trouvee, avec le nom de la source', () => {
    const r = B.checkIp('1.2.3.4');
    assert.strictEqual(r.blocked, true);
    assert.deepStrictEqual(r.sources, ['source-a']);
  });
  check('IP incluse via un bloc CIDR -> trouvee', () => {
    const r = B.checkIp('5.6.7.42');
    assert.strictEqual(r.blocked, true);
    assert.deepStrictEqual(r.sources, ['source-a']);
  });
  check('IP absente de toute liste -> non trouvee, tableau vide', () => {
    const r = B.checkIp('203.0.113.99');
    assert.strictEqual(r.blocked, false);
    assert.deepStrictEqual(r.sources, []);
  });

  console.log('\ngetHitStats() / getDigestStats() — degradent proprement sans analyseur, relaient sinon');
  let hitStats = await B.getHitStats({ hours: 24 });
  check('sans analyzerApi injecte -> available: false, jamais d exception', () => {
    assert.strictEqual(hitStats.available, false);
  });

  // Depuis la v12.29.0, bySource est calcule cote analyseur (il a recu les
  // memes sources via pushBlocklistSources()) — getHitStats() ne fait plus
  // que relayer sa reponse telle quelle, voir les tests dedies plus bas pour
  // la construction du payload envoye a l analyseur.
  B.setDeps({
    analyzerApi: async () => ({ status: 200, data: {
      totalHits: 5, uniqueIps: 2,
      topIps: [{ ip: '1.2.3.4', count: 3 }, { ip: '5.6.7.42', count: 2 }],
      bySource: [{ name: 'source-a', hits: 5 }],
    } }),
  });
  hitStats = await B.getHitStats({ hours: 24 });
  check('avec un analyzerApi mocke -> le bySource de l analyseur est relaye tel quel', () => {
    assert.strictEqual(hitStats.available, true);
    assert.strictEqual(hitStats.totalHits, 5);
    assert.strictEqual(hitStats.uniqueHitIps, 2);
    assert.deepStrictEqual(hitStats.bySource, [{ name: 'source-a', hits: 5 }]);
  });
  B.setDeps({ analyzerApi: async () => ({ status: 200, data: { totalHits: 0, uniqueIps: 0, topIps: [] } }) });
  const hitStatsNoBySource = await B.getHitStats({ hours: 1 }); // fenetre differente -> pas de cache
  check('un bySource absent de la reponse analyseur degrade vers un tableau vide, jamais une exception', () => {
    assert.deepStrictEqual(hitStatsNoBySource.bySource, []);
  });
  B.setDeps({ analyzerApi: null }); // ne pas polluer les tests suivants

  console.log('\npushBlocklistSources() — synchronisation vers l analyseur (v12.29.0)');
  let pushedCalls = [];
  B.setDeps({
    analyzerApiJson: async (p, method, body) => { pushedCalls.push({ p, method, body }); return { status: 200, data: { ok: true } }; },
  });
  writeBlocklistsYaml([
    'enable: true',
    'hit_logging_enable: true',
    'hit_logging_method: approx',
    'sources:',
    `  - name: source-a`, `    url: "http://127.0.0.1:${port}/a.txt"`, '    enable: true',
    `  - name: source-disabled`, `    url: "http://127.0.0.1:${port}/a.txt"`, '    enable: false',
  ].join('\n'));
  await B.refreshBlocklists({ manual: true, actor: 'test' }); // peuple le cache pour source-a
  pushedCalls = []; // ignore le push automatique de refreshBlocklists() lui-meme
  await B.pushBlocklistSources();
  check('envoie une requete POST /api/blocklist-sources', () => {
    assert.strictEqual(pushedCalls.length, 1);
    assert.strictEqual(pushedCalls[0].p, '/api/blocklist-sources');
    assert.strictEqual(pushedCalls[0].method, 'POST');
  });
  check('le mode reflete hit_logging_method (approx)', () => {
    assert.strictEqual(pushedCalls[0].body.mode, 'approx');
  });
  check('seules les sources activees, avec leur cache d IP, sont envoyees', () => {
    const sources = pushedCalls[0].body.sources;
    assert.ok(Array.isArray(sources['source-a'].ips) && sources['source-a'].ips.length > 0);
    assert.strictEqual(sources['source-disabled'], undefined);
  });
  pushedCalls = [];
  await B.refreshBlocklists({ manual: true, actor: 'test' });
  check('refreshBlocklists() pousse lui-meme apres chaque cycle (freshness)', () => {
    assert.strictEqual(pushedCalls.length, 1);
  });

  writeBlocklistsYaml('enable: false\nsources: []\n');
  pushedCalls = [];
  await B.pushBlocklistSources();
  check('feature desactivee -> pousse un mode/sources vides (ne laisse pas l analyseur sur une attribution perimee)', () => {
    assert.strictEqual(pushedCalls.length, 1);
    assert.deepStrictEqual(pushedCalls[0].body.sources, {});
  });

  B.setDeps({ analyzerApiJson: async () => { throw new Error('ECONNREFUSED'); } });
  let pushThrew = false;
  try { await B.pushBlocklistSources(); } catch { pushThrew = true; }
  check('analyseur injoignable -> ne leve jamais (refreshBlocklists ne doit pas en dependre)', () => {
    assert.strictEqual(pushThrew, false);
  });
  B.setDeps({ analyzerApiJson: null }); // ne pas polluer les tests suivants
  writeBlocklistsYaml([
    'enable: true', 'sources:',
    `  - name: source-a`, `    url: "http://127.0.0.1:${port}/a.txt"`, '    enable: true',
  ].join('\n'));

  writeBlocklistsYaml('enable: false\nsources: []\n');
  const digestDisabled = await B.getDigestStats({ hours: 24 });
  check('getDigestStats() renvoie enable:false quand la fonctionnalite est desactivee', () => {
    assert.strictEqual(digestDisabled.enable, false);
  });
  writeBlocklistsYaml([
    'enable: true', 'sources:',
    `  - name: source-a`, `    url: "http://127.0.0.1:${port}/a.txt"`, '    enable: true',
  ].join('\n'));

  server.close();
  fs.rmSync(dir, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
