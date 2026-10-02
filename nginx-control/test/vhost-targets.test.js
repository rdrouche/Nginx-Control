'use strict';
/**
 * lib/vhost-targets.js — resolveur best-effort de la cible reelle d une
 * location proxy_pass. Ce n est pas un parseur nginx complet (voir le
 * commentaire d en-tete du module) : ces tests couvrent les quatre formes
 * que le projet emet ou rencontre reellement (direct, upstream/LB, docker
 * via variable+resolver, variable non resolue) plutot que l ensemble de la
 * grammaire nginx.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const {
  extractBlocks, splitHostPort, parseUpstreams, resolveProxyPass, parseVhostFile, listVhostTargets,
  fileDiagnosticEnabled,
} = require('../lib/vhost-targets');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nextractBlocks() — respecte les accolades imbriquees');
(() => {
  const content = 'server {\n  location / {\n    if (1) { return 200; }\n  }\n  location /a { return 404; }\n}\nserver { listen 81; }';
  const blocks = extractBlocks(content, /server\s*\{/g);
  check('deux blocs server trouves malgre les accolades imbriquees dans le premier', () => {
    assert.strictEqual(blocks.length, 2);
  });
  check('le premier bloc contient bien les deux locations completes', () => {
    assert.ok(blocks[0].body.includes('location /a { return 404; }'));
  });
})();

console.log('\nsplitHostPort()');
(() => {
  check('host:port simple', () => assert.deepStrictEqual(splitHostPort('127.0.0.1:8080'), { host: '127.0.0.1', port: 8080 }));
  check('host seul, pas de port', () => assert.deepStrictEqual(splitHostPort('backend-name'), { host: 'backend-name', port: null }));
  check('IPv6 entre crochets avec port', () => assert.deepStrictEqual(splitHostPort('[::1]:9000'), { host: '::1', port: 9000 }));
})();

console.log('\nresolveProxyPass() — direct');
(() => {
  const r = resolveProxyPass('http://127.0.0.1:8080', '', {});
  check('kind direct, port explicite conserve', () => {
    assert.strictEqual(r.kind, 'direct');
    assert.deepStrictEqual(r.targets, [{ scheme: 'http', host: '127.0.0.1', port: 8080 }]);
  });
  const r2 = resolveProxyPass('https://api.interne.local', '', {});
  check('port par defaut 443 en https quand absent', () => {
    assert.strictEqual(r2.targets[0].port, 443);
  });
})();

console.log('\nresolveProxyPass() — upstream (load-balancing / HA)');
(() => {
  const upstreams = { backend_pool: [{ host: '10.0.0.1', port: 8080 }, { host: '10.0.0.2', port: 8080 }] };
  const r = resolveProxyPass('http://backend_pool', '', upstreams);
  check('kind upstream, toutes les cibles du pool renvoyees', () => {
    assert.strictEqual(r.kind, 'upstream');
    assert.strictEqual(r.targets.length, 2);
    assert.deepStrictEqual(r.targets.map(t => t.host), ['10.0.0.1', '10.0.0.2']);
  });
})();

console.log('\nresolveProxyPass() — docker (set $var + resolver), les deux formes');
(() => {
  // Forme A (features/vhost-generator.js) : set $var scheme://host:port; proxy_pass $var;
  const fileA = 'set $backend http://mon-app:3000;\nresolver 127.0.0.11 valid=30s;\n';
  const rA = resolveProxyPass('$backend', fileA, {});
  check('forme A : variable seule -> hote/port extraits de la valeur du set', () => {
    assert.strictEqual(rA.kind, 'docker');
    assert.deepStrictEqual(rA.targets, [{ scheme: 'http', host: 'mon-app', port: 3000 }]);
  });

  // Forme B (global-error.conf / 00-default.conf reels du projet) :
  // set $var host; proxy_pass http://$var:port;
  const fileB = 'set $upstream_errors error-pages;\nresolver 127.0.0.11 valid=30s;\n';
  const rB = resolveProxyPass('http://$upstream_errors:8080', fileB, {});
  check('forme B : scheme/port du proxy_pass, hote de la variable', () => {
    assert.strictEqual(rB.kind, 'docker');
    assert.deepStrictEqual(rB.targets, [{ scheme: 'http', host: 'error-pages', port: 8080 }]);
  });

  check('sans directive resolver -> kind variable, pas docker (moins de certitude)', () => {
    const fileNoResolver = 'set $backend mon-app;\n';
    const r = resolveProxyPass('http://$backend:3000', fileNoResolver, {});
    assert.strictEqual(r.kind, 'variable');
    assert.strictEqual(r.targets[0].host, 'mon-app');
  });
})();

console.log('\nresolveProxyPass() — non resolu');
(() => {
  check('variable referencee sans set correspondant -> unresolved, raw conserve', () => {
    const r = resolveProxyPass('$inconnu', 'resolver 127.0.0.11;\n', {});
    assert.strictEqual(r.kind, 'unresolved');
    assert.strictEqual(r.targets.length, 0);
    assert.strictEqual(r.raw, '$inconnu');
  });
  check('valeur qui ne ressemble pas a une URL -> unresolved', () => {
    const r = resolveProxyPass('n-importe-quoi sans scheme', '', {});
    assert.strictEqual(r.kind, 'unresolved');
  });
})();

console.log('\nparseVhostFile() — blocs server complets');
(() => {
  const content = [
    'server {',
    '    listen 443 ssl;',
    '    server_name exemple.com www.exemple.com;',
    '    location /static/ {',
    '        root /var/www;',
    '    }',
    '    location / {',
    '        proxy_pass http://127.0.0.1:8080;',
    '    }',
    '}',
    'server {',
    '    listen 80;',
    '    server_name exemple.com;',
    '    location / { return 301 https://$host$request_uri; }',
    '}',
  ].join('\n');
  const blocks = parseVhostFile(content, {});
  check('deux blocs server extraits', () => assert.strictEqual(blocks.length, 2));
  check('ssl detecte via listen ... ssl', () => assert.strictEqual(blocks[0].ssl, true));
  check('server_name multi-valeurs, separes', () => {
    assert.deepStrictEqual(blocks[0].serverNames, ['exemple.com', 'www.exemple.com']);
  });
  check('seule la location avec proxy_pass est retenue (static et redirect ignores)', () => {
    assert.strictEqual(blocks[0].locations.length, 1);
    assert.strictEqual(blocks[0].locations[0].path, '/');
    assert.strictEqual(blocks[1].locations.length, 0);
  });
  check('le second bloc (redirect HTTP) n est pas ssl', () => assert.strictEqual(blocks[1].ssl, false));
  check('redirectsToHttps : detecte sur le bloc qui redirige, pas sur le premier', () => {
    assert.strictEqual(blocks[0].redirectsToHttps, false);
    assert.strictEqual(blocks[1].redirectsToHttps, true);
  });
})();

console.log('\nparseVhostFile() — bug reel : un nom d upstream qui se termine par "server"');
(() => {
  // Signale par un utilisateur : upstream jitsiserver { ... } definit un bloc
  // fantome supplementaire ("server" est un sous-mot de "jitsiserver", donc
  // "...jitsiserver {" matchait a tort le motif d ouverture "server\s*\{").
  // Meme risque avec `location` a l interieur d un identifiant comme
  // "$geolocation {". Ce test rejoue exactement le fichier signale.
  const content = [
    'upstream jitsiserver {',
    '  server 172.16.127.7:8443;',
    '}',
    '',
    'server {',
    '  listen 443 ssl;',
    '  server_name jitsi.exemple.com;',
    '  location / { proxy_pass https://jitsiserver; }',
    '}',
    '',
    'server {',
    '  listen 80;',
    '  server_name jitsi.exemple.com;',
    '  return 301 https://$host$request_uri;',
    '}',
  ].join('\n');
  const upstreams = { jitsiserver: [{ host: '172.16.127.7', port: 8443 }] };
  const blocks = parseVhostFile(content, upstreams);
  check('exactement deux blocs server (pas de bloc fantome depuis "jitsiserver")', () => {
    assert.strictEqual(blocks.length, 2);
  });
  check('les deux vrais blocs ont bien leur server_name', () => {
    assert.deepStrictEqual(blocks[0].serverNames, ['jitsi.exemple.com']);
    assert.deepStrictEqual(blocks[1].serverNames, ['jitsi.exemple.com']);
  });
  check('le proxy_pass vers le pool upstream reste resolu normalement', () => {
    assert.strictEqual(blocks[0].locations[0].kind, 'upstream');
    assert.deepStrictEqual(blocks[0].locations[0].targets, [{ scheme: 'https', host: '172.16.127.7', port: 8443 }]);
  });
})();

console.log('\nparseVhostFile() — sslVerifyOff par location');
(() => {
  const content = [
    'server {',
    '    listen 443 ssl;',
    '    server_name a.example.com;',
    '    location / { proxy_ssl_verify off; proxy_pass https://10.0.0.1:8443; }',
    '    location /b { proxy_pass https://10.0.0.2:8443; }',
    '}',
  ].join('\n');
  const blocks = parseVhostFile(content, {});
  check('proxy_ssl_verify off detecte uniquement sur la location qui le porte', () => {
    assert.strictEqual(blocks[0].locations[0].sslVerifyOff, true);
    assert.strictEqual(blocks[0].locations[1].sslVerifyOff, false);
  });
})();

console.log('\nparseVhostFile() — flag de monitoring en commentaire');
(() => {
  const on = parseVhostFile([
    'server {',
    '    # nginx-control-monitoring: on',
    '    # nginx-control-monitoring-interval: 30s',
    '    listen 443 ssl;',
    '    server_name a.example.com;',
    '    location / { proxy_pass http://10.0.0.1:8080; }',
    '}',
  ].join('\n'), {});
  check('monitoring: on + interval explicite', () => {
    assert.strictEqual(on[0].monitoring.enabled, true);
    assert.strictEqual(on[0].monitoring.intervalSec, 30);
  });

  const off = parseVhostFile([
    'server {',
    '    # nginx-control-monitoring: off',
    '    listen 443 ssl;',
    '    server_name b.example.com;',
    '}',
  ].join('\n'), {});
  check('monitoring: off -> disabled', () => assert.strictEqual(off[0].monitoring.enabled, false));

  const absent = parseVhostFile([
    'server {',
    '    listen 443 ssl;',
    '    server_name c.example.com;',
    '}',
  ].join('\n'), {});
  check('flag absent -> disabled par defaut, intervalle par defaut 60s', () => {
    assert.strictEqual(absent[0].monitoring.enabled, false);
    assert.strictEqual(absent[0].monitoring.intervalSec, 60);
  });

  const tinyInterval = parseVhostFile([
    'server {',
    '    # nginx-control-monitoring: on',
    '    # nginx-control-monitoring-interval: 1s',
    '    listen 443 ssl;',
    '    server_name d.example.com;',
    '}',
  ].join('\n'), {});
  check('intervalle trop petit -> plancher a 10s (pas de flood de sondes)', () => {
    assert.strictEqual(tinyInterval[0].monitoring.intervalSec, 10);
  });

  const inText = parseVhostFile([
    'server {',
    '    listen 443 ssl;',
    '    server_name e.example.com;',
    '    location / { proxy_pass http://10.0.0.1:8080; } # not nginx-control-monitoring: on, just a stray mention',
    '}',
  ].join('\n'), {});
  check('la mention doit etre sur sa propre ligne de commentaire, pas juste presente quelque part', () => {
    assert.strictEqual(inText[0].monitoring.enabled, false);
  });

  const noOverride = parseVhostFile([
    'server {',
    '    # nginx-control-monitoring: on',
    '    listen 443 ssl;',
    '    server_name f.example.com;',
    '}',
  ].join('\n'), {});
  check('flag valid-http-code absent -> validHttpCodes null (regle par defaut appliquee par lib/monitor-status.js)', () => {
    assert.strictEqual(noOverride[0].monitoring.validHttpCodes, null);
  });

  const withOverride = parseVhostFile([
    'server {',
    '    # nginx-control-monitoring: on',
    '    # nginx-control-monitoring-valid-http-code: 2xx, 3xx',
    '    listen 443 ssl;',
    '    server_name g.example.com;',
    '}',
  ].join('\n'), {});
  check('flag valid-http-code present -> liste de patterns parsee', () => {
    assert.deepStrictEqual(withOverride[0].monitoring.validHttpCodes, ['2xx', '3xx']);
  });

  const invalidOverride = parseVhostFile([
    'server {',
    '    # nginx-control-monitoring: on',
    '    # nginx-control-monitoring-valid-http-code: n-importe-quoi',
    '    listen 443 ssl;',
    '    server_name h.example.com;',
    '}',
  ].join('\n'), {});
  check('flag valid-http-code avec un contenu invalide -> null, retombe sur la regle par defaut', () => {
    assert.strictEqual(invalidOverride[0].monitoring.validHttpCodes, null);
  });
})();

console.log('\nparseVhostFile() — opt-out de monitoring par location (# nginx-control-monitoring-ignore-location)');
(() => {
  // Deux locations d un meme bloc qui proxifient la meme cible : sans le
  // flag, monitor.js les sonderait toutes les deux independamment pour rien.
  const blocks = parseVhostFile([
    'server {',
    '    # nginx-control-monitoring: on',
    '    listen 443 ssl;',
    '    server_name f.example.com;',
    '    location / { proxy_pass http://10.0.0.1:8080; }',
    '    location /api {',
    '        # nginx-control-monitoring-ignore-location: on',
    '        proxy_pass http://10.0.0.1:8080;',
    '    }',
    '    location /off {',
    '        # nginx-control-monitoring-ignore-location: off',
    '        proxy_pass http://10.0.0.1:8080;',
    '    }',
    '}',
  ].join('\n'), {});
  check('location sans le flag -> monitoringIgnored: false', () => {
    assert.strictEqual(blocks[0].locations[0].monitoringIgnored, false);
  });
  check('location avec le flag "on" -> monitoringIgnored: true', () => {
    assert.strictEqual(blocks[0].locations[1].monitoringIgnored, true);
  });
  check('location avec le flag explicitement "off" -> monitoringIgnored: false', () => {
    assert.strictEqual(blocks[0].locations[2].monitoringIgnored, false);
  });

  const inText = parseVhostFile([
    'server {',
    '    listen 443 ssl;',
    '    server_name g.example.com;',
    '    location / { proxy_pass http://10.0.0.1:8080; } # not nginx-control-monitoring-ignore-location: on, just a stray mention',
    '}',
  ].join('\n'), {});
  check('la mention doit etre sur sa propre ligne de commentaire, pas juste presente quelque part', () => {
    assert.strictEqual(inText[0].locations[0].monitoringIgnored, false);
  });
})();

console.log('\nparseVhostFile() — opt-out de diagnostic par bloc (# nginx-control-diagnostic-vhost)');
(() => {
  const blocks = parseVhostFile([
    'server {',
    '    listen 443 ssl;',
    '    server_name a.example.com;',
    '    location / { proxy_pass http://10.0.0.1:8080; }',
    '}',
    'server {',
    '    # nginx-control-diagnostic-vhost: off',
    '    listen 8443 ssl;',
    '    server_name b.internal;',
    '    location / { proxy_pass http://10.0.0.2:8080; }',
    '}',
  ].join('\n'), {});
  check('bloc sans le flag -> diagnosticEnabled: true (comportement par defaut, inchange)', () => {
    assert.strictEqual(blocks[0].diagnosticEnabled, true);
  });
  check('bloc avec le flag "off" -> diagnosticEnabled: false', () => {
    assert.strictEqual(blocks[1].diagnosticEnabled, false);
  });

  const inText = parseVhostFile([
    'server {',
    '    listen 443 ssl;',
    '    server_name c.example.com; # not nginx-control-diagnostic-vhost: off, just a stray mention',
    '    location / { proxy_pass http://10.0.0.1:8080; }',
    '}',
  ].join('\n'), {});
  check('la mention doit etre sur sa propre ligne de commentaire, pas juste presente quelque part', () => {
    assert.strictEqual(inText[0].diagnosticEnabled, true);
  });
})();

console.log('\nparseVhostFile() — opt-out d analyse par bloc (# nginx-control-analyze / -ignore-rules)');
(() => {
  const blocks = parseVhostFile([
    'server {',
    '    listen 443 ssl;',
    '    server_name a.example.com;',
    '    location / { proxy_pass http://10.0.0.1:8080; }',
    '}',
    'server {',
    '    # nginx-control-analyze: off',
    '    listen 8443 ssl;',
    '    server_name b.internal;',
    '    location / { proxy_pass http://10.0.0.2:8080; }',
    '}',
    'server {',
    '    # nginx-control-analyze-ignore-rules: 1, 2, 4',
    '    listen 8444 ssl;',
    '    server_name c.internal;',
    '    location / { proxy_pass http://10.0.0.3:8080; }',
    '}',
  ].join('\n'), {});
  check('bloc sans flag -> analyzeEnabled: true, aucune regle ignoree (comportement par defaut)', () => {
    assert.strictEqual(blocks[0].analyzeEnabled, true);
    assert.deepStrictEqual(blocks[0].analyzeIgnoreRuleIds, []);
    assert.strictEqual(blocks[0].analyzeNoRemediation, false);
  });
  check('bloc avec # nginx-control-analyze: off -> analyzeEnabled: false', () => {
    assert.strictEqual(blocks[1].analyzeEnabled, false);
  });
  check('# nginx-control-analyze-ignore-rules: 1, 2, 4 -> liste d ids numeriques, vhost reste actif', () => {
    assert.strictEqual(blocks[2].analyzeEnabled, true);
    assert.deepStrictEqual(blocks[2].analyzeIgnoreRuleIds, [1, 2, 4]);
  });

  const noRemediationBlocks = parseVhostFile([
    'server {',
    '    # nginx-control-analyze-no-remediation: on',
    '    listen 8445 ssl;',
    '    server_name e.internal;',
    '    location / { proxy_pass http://10.0.0.4:8080; }',
    '}',
  ].join('\n'), {});
  check('# nginx-control-analyze-no-remediation: on -> analyzeNoRemediation: true, alertes/analyse inchangees', () => {
    assert.strictEqual(noRemediationBlocks[0].analyzeNoRemediation, true);
    assert.strictEqual(noRemediationBlocks[0].analyzeEnabled, true);
    assert.deepStrictEqual(noRemediationBlocks[0].analyzeIgnoreRuleIds, []);
  });

  const inText = parseVhostFile([
    'server {',
    '    listen 443 ssl;',
    '    server_name d.example.com; # not nginx-control-analyze: off, just a stray mention',
    '    location / { proxy_pass http://10.0.0.1:8080; }',
    '}',
  ].join('\n'), {});
  check('la mention doit etre sur sa propre ligne de commentaire, pas juste presente quelque part', () => {
    assert.strictEqual(inText[0].analyzeEnabled, true);
  });
})();

console.log('\nfileDiagnosticEnabled() — opt-out de diagnostic pour tout le fichier (# nginx-control-diagnostic)');
(() => {
  check('flag absent -> true (comportement par defaut, inchange)', () => {
    assert.strictEqual(fileDiagnosticEnabled('server { listen 80; }'), true);
  });
  check('flag "off" avant tout bloc server -> false', () => {
    const content = [
      '# nginx-control-diagnostic: off',
      'server { listen 80; }',
    ].join('\n');
    assert.strictEqual(fileDiagnosticEnabled(content), false);
  });
  check('flag "off" mais APRES le premier bloc server (donc a l interieur) -> ignore, le fichier reste inclus', () => {
    // Le flag fichier est explicitement documente comme devant precede tout
    // bloc server{} — un flag place a l interieur n a pas cette portee
    // globale (c est nginx-control-diagnostic-vhost qu il faudrait alors).
    const content = [
      'server {',
      '    # nginx-control-diagnostic: off',
      '    listen 80;',
      '}',
    ].join('\n');
    assert.strictEqual(fileDiagnosticEnabled(content), true);
  });
  check('flag "on" explicite avant tout bloc server -> true', () => {
    const content = [
      '# nginx-control-diagnostic: on',
      'server { listen 80; }',
    ].join('\n');
    assert.strictEqual(fileDiagnosticEnabled(content), true);
  });
})();

console.log('\nlistVhostTargets() — expose diagnosticEnabled au niveau fichier');
(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vhost-diag-file-'));
  fs.writeFileSync(path.join(dir, 'included.conf'), 'server { listen 80; server_name x.example.com; }');
  fs.writeFileSync(path.join(dir, 'excluded.conf'), [
    '# nginx-control-diagnostic: off',
    'server { listen 80; server_name y.example.com; }',
  ].join('\n'));
  const vhosts = listVhostTargets({ sitesDir: dir, upstreamDirs: [] });
  check('vhost sans le flag -> diagnosticEnabled: true', () => {
    assert.strictEqual(vhosts.find(v => v.name === 'included.conf').diagnosticEnabled, true);
  });
  check('vhost avec # nginx-control-diagnostic: off -> diagnosticEnabled: false', () => {
    assert.strictEqual(vhosts.find(v => v.name === 'excluded.conf').diagnosticEnabled, false);
  });
})();

console.log('\nparseUpstreams() — a travers plusieurs fichiers/repertoires');
(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vhost-upstreams-'));
  fs.writeFileSync(path.join(dir, 'pool.conf'), 'upstream mon_pool {\n    server 10.0.0.1:8080;\n    server 10.0.0.2:8080 backup;\n}\n');
  fs.writeFileSync(path.join(dir, 'ignored.txt'), 'upstream faux { server 1.2.3.4:1; }\n');
  const upstreams = parseUpstreams([dir]);
  check('le pool est trouve avec ses deux serveurs (parametres extra ignores)', () => {
    assert.strictEqual(upstreams.mon_pool.length, 2);
    assert.deepStrictEqual(upstreams.mon_pool[1], { host: '10.0.0.2', port: 8080 });
  });
  check('seuls les fichiers .conf/.conf.DISABLE sont scannes', () => {
    assert.strictEqual(upstreams.faux, undefined);
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\nlistVhostTargets() — bout en bout sur un repertoire sites/');
(() => {
  const sitesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vhost-sites-'));
  const confDir  = fs.mkdtempSync(path.join(os.tmpdir(), 'vhost-conf-'));
  fs.writeFileSync(path.join(confDir, 'upstreams.conf'), 'upstream api_pool {\n    server 10.0.0.1:9000;\n    server 10.0.0.2:9000;\n}\n');
  fs.writeFileSync(path.join(sitesDir, 'active.conf'), 'server {\n    listen 80;\n    server_name a.example.com;\n    location / { proxy_pass http://api_pool; }\n}\n');
  fs.writeFileSync(path.join(sitesDir, 'disabled.conf.DISABLE'), 'server {\n    listen 80;\n    server_name b.example.com;\n    location / { proxy_pass http://127.0.0.1:9001; }\n}\n');

  const result = listVhostTargets({ sitesDir, upstreamDirs: [confDir, sitesDir] });
  check('deux fichiers vhost trouves, tries par nom', () => {
    assert.strictEqual(result.length, 2);
    assert.deepStrictEqual(result.map(r => r.name), ['active.conf', 'disabled.conf.DISABLE']);
  });
  check('le fichier .DISABLE est marque non-actif mais reste analyse', () => {
    const disabled = result.find(r => r.name === 'disabled.conf.DISABLE');
    assert.strictEqual(disabled.enabled, false);
    assert.strictEqual(disabled.serverBlocks[0].locations[0].kind, 'direct');
  });
  check('le vhost actif resout bien son upstream inter-fichiers (conf/ vs sites/)', () => {
    const active = result.find(r => r.name === 'active.conf');
    const loc = active.serverBlocks[0].locations[0];
    assert.strictEqual(loc.kind, 'upstream');
    assert.strictEqual(loc.targets.length, 2);
  });

  fs.rmSync(sitesDir, { recursive: true, force: true });
  fs.rmSync(confDir, { recursive: true, force: true });
})();

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
