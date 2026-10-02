'use strict';
/**
 * pushVhostRules() (features/analyzer.js) — le pendant "Analyse" de ce que
 * features/monitor.js fait deja pour la surveillance : lire les commentaires
 * d opt-out des fichiers vhost et les pousser vers l agent separe. Verifie
 * ici en pointant l agent (container_name/port) vers un faux serveur HTTP
 * local plutot qu un vrai conteneur Docker — aucun autre test de ce fichier
 * n a besoin d un agent joignable, celui-ci si, puisque c est justement le
 * contenu envoye qui est sous test.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzer-vhostrules-'));
  const sitesDir = path.join(dir, 'sites');
  const confDir = path.join(dir, 'conf');
  fs.mkdirSync(sitesDir, { recursive: true });
  fs.mkdirSync(confDir, { recursive: true });

  fs.writeFileSync(path.join(sitesDir, 'a.conf'), [
    'server {',
    '    listen 443 ssl;',
    '    server_name a.example.com;',
    '    location / { proxy_pass http://10.0.0.1:8080; }',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(sitesDir, 'b.conf'), [
    'server {',
    '    # nginx-control-analyze: off',
    '    listen 443 ssl;',
    '    server_name b.internal;',
    '    location / { proxy_pass http://10.0.0.2:8080; }',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(sitesDir, 'c.conf'), [
    'server {',
    '    # nginx-control-analyze-ignore-rules: 1, 2, 4',
    '    listen 443 ssl;',
    '    server_name c.example.com;',
    '    location / { proxy_pass http://10.0.0.3:8080; }',
    '}',
  ].join('\n'));
  // Bug reel signale par un operateur (Flood non ignore malgre le
  // commentaire) : le vhost "normal" a DEUX blocs server{} partageant le
  // meme server_name — le bloc :443 (avec les commentaires) et le bloc :80
  // de redirection HTTP->HTTPS (sans aucun commentaire), exactement comme
  // features/vhost-generator.js les ecrit tous les deux. Le bloc :80 arrive
  // APRES le bloc :443 dans le fichier — s il ecrasait bêtement les reglages
  // au lieu de les fusionner, ses valeurs par defaut (enabled:true,
  // ignore:[]) effaceraient silencieusement le "ignore-rules" du bloc :443.
  fs.writeFileSync(path.join(sitesDir, 'd.conf'), [
    'server {',
    '    # nginx-control-analyze-ignore-rules: 3',
    '    listen 443 ssl;',
    '    server_name d.example.com;',
    '    location / { proxy_pass http://10.0.0.4:8080; }',
    '}',
    'server {',
    '    listen 80;',
    '    server_name d.example.com;',
    '    return 301 https://$host$request_uri;',
    '}',
  ].join('\n'));
  // v12.54.0 : # nginx-control-analyze-rule-{ID}-paths-ignore, deux blocs
  // partageant le meme server_name (union par regle, ordre indifferent).
  fs.writeFileSync(path.join(sitesDir, 'f.conf'), [
    'server {',
    '    listen 443 ssl;',
    '    server_name wp.example.com;',
    '    # nginx-control-analyze-rule-1-paths-ignore: /wp-json/wpa/v1/verify-session, /a*',
    '    location / { proxy_pass http://10.0.0.6:8080; }',
    '}',
    'server {',
    '    listen 80;',
    '    server_name wp.example.com;',
    '    # nginx-control-analyze-rule-1-paths-ignore: /b',
    '    # nginx-control-analyze-rule-4-paths-ignore: /c',
    '    return 301 https://$host$request_uri;',
    '}',
  ].join('\n'));
  // Retour utilisateur (v12.50.0) : "commentaire dans la configuration vhost
  // pour ignore la remediation ... comme cela on garde les alertes mais [pas]
  // de blocage" — distinct de "# nginx-control-analyze: off" (b.conf), qui
  // coupe l alerte elle-meme.
  fs.writeFileSync(path.join(sitesDir, 'e.conf'), [
    'server {',
    '    # nginx-control-analyze-no-remediation: on',
    '    listen 443 ssl;',
    '    server_name e.example.com;',
    '    location / { proxy_pass http://10.0.0.5:8080; }',
    '}',
  ].join('\n'));

  // Faux "agent" : capture le corps du POST /api/vhost-rules.
  let captured = null;
  const mock = http.createServer((req, res) => {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      if (req.url === '/api/vhost-rules' && req.method === 'POST') {
        try { captured = JSON.parse(body); } catch { captured = null; }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise(r => mock.listen(0, '127.0.0.1', r));
  const mockPort = mock.address().port;

  process.env.CONFIG_DIR = path.join(dir, 'config');
  fs.mkdirSync(process.env.CONFIG_DIR, { recursive: true });
  process.env.USERS_FILE = path.join(process.env.CONFIG_DIR, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  process.env.DIR_SITES = sitesDir;
  process.env.DIR_CONF = confDir;
  fs.writeFileSync(path.join(process.env.CONFIG_DIR, 'analyzer.yml'), [
    'enable: true',
    `container_name: 127.0.0.1`,
    `port: ${mockPort}`,
    'host_data_path: /tmp/whatever',
  ].join('\n'));

  for (const mod of ['../lib/config', '../lib/vhost-targets', '../features/analyzer'])
    delete require.cache[require.resolve(mod)];
  const A = require('../features/analyzer');

  console.log('\npushVhostRules() — traduit les commentaires de vhost en carte envoyee a l analyzer');
  await A.pushVhostRules();
  await new Promise(r => setTimeout(r, 50));

  check('un appel a bien ete recu', () => assert.ok(captured, 'aucun POST /api/vhost-rules capture'));
  check('vhost sans flag -> enabled:true, aucune regle ignoree, remediation non exclue', () => {
    assert.deepStrictEqual(captured.vhosts['a.example.com'], { enabled: true, ignore: [], noRemediation: false });
  });
  check('vhost avec # nginx-control-analyze: off -> enabled:false', () => {
    assert.strictEqual(captured.vhosts['b.internal'].enabled, false);
  });
  check('vhost avec # nginx-control-analyze-ignore-rules: 1, 2, 4 -> ignore:[1,2,4], enabled reste true', () => {
    assert.deepStrictEqual(captured.vhosts['c.example.com'], { enabled: true, ignore: [1, 2, 4], noRemediation: false });
  });
  check('vhost avec bloc :443 (ignore-rules) + bloc :80 de redirection (sans commentaire) -> le bloc :80 ne doit jamais ecraser le reglage du bloc :443', () => {
    assert.deepStrictEqual(captured.vhosts['d.example.com'], { enabled: true, ignore: [3], noRemediation: false });
  });
  check('v12.54.0 : # nginx-control-analyze-rule-N-paths-ignore -> pathsIgnore par regle, union des blocs, motif invalide ecarte', () => {
    assert.deepStrictEqual(captured.vhosts['wp.example.com'], {
      enabled: true, ignore: [], noRemediation: false,
      pathsIgnore: { 1: ['/wp-json/wpa/v1/verify-session', '/a*', '/b'], 4: ['/c'] },
    });
  });
  check('v12.54.0 : sans directive, aucune cle pathsIgnore dans la charge utile', () => {
    assert.ok(!('pathsIgnore' in captured.vhosts['a.example.com']));
  });
  check('parseAnalyzePathsIgnore : bornes et validation', () => {
    const { parseAnalyzePathsIgnore } = require('../lib/vhost-targets');
    const many = Array.from({ length: 80 }, (_, i) => '/p' + i).join(',');
    const r = parseAnalyzePathsIgnore('# nginx-control-analyze-rule-1-paths-ignore: ' + many + ',nope,' + '/' + 'x'.repeat(300));
    assert.strictEqual(r[1].length, 50);
    assert.deepStrictEqual(parseAnalyzePathsIgnore('# nginx-control-analyze-rule-2-paths-ignore: rien,*'), {});
    assert.deepStrictEqual(parseAnalyzePathsIgnore('location /x { # nginx-control-analyze-rule-1-paths-ignore: /a\n}'), {});
  });
  check('vhost avec # nginx-control-analyze-no-remediation: on -> noRemediation:true, alertes/regles inchangees', () => {
    assert.deepStrictEqual(captured.vhosts['e.example.com'], { enabled: true, ignore: [], noRemediation: true });
  });

  console.log('\npushVhostRules() — analyzer non active');
  captured = null;
  fs.writeFileSync(path.join(process.env.CONFIG_DIR, 'analyzer.yml'), 'enable: false\n');
  delete require.cache[require.resolve('../features/analyzer')];
  const A2 = require('../features/analyzer');
  await A2.pushVhostRules();
  await new Promise(r => setTimeout(r, 50));
  check('rien n est envoye quand l analyzer est desactive', () => assert.strictEqual(captured, null));

  mock.close();
  fs.rmSync(dir, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
