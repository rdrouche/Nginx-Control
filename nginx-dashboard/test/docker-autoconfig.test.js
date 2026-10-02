'use strict';
/**
 * lib/docker-autoconfig.js — parsing des labels Docker, validation, rendu du
 * vhost. Purement synchrone, aucun appel Docker/fs ici (voir
 * test/docker-autoconfig-routes.test.js pour l orchestration complete).
 */
const assert = require('assert');
const {
  parseContainerLabels, validateDesiredVhost, sanitizeForFilename,
  dockerVhostFileName, generateVhostContent, parseBackendUrl,
} = require('../lib/docker-autoconfig');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nparseContainerLabels()');
check('conteneur sans label nginx-control.enable -> null (jamais un objet enabled:false)', () => {
  assert.strictEqual(parseContainerLabels({}), null);
  assert.strictEqual(parseContainerLabels({ 'nginx-control.enable': 'false' }), null);
  assert.strictEqual(parseContainerLabels({ 'some.other.label': 'true' }), null);
});
check('un jeu de labels complet est extrait, une seule location', () => {
  const d = parseContainerLabels({
    'nginx-control.enable': 'true',
    'nginx-control.network': 'nginx-net',
    'nginx-control.vhost.server_name': 'app.example.com',
    'nginx-control.vhost.listen': '80',
    'nginx-control.vhost.location01': '/',
    'nginx-control.vhost.location01.proxy_pass': 'http://backend:8080',
  });
  assert.strictEqual(d.network, 'nginx-net');
  assert.strictEqual(d.serverNameRaw, 'app.example.com');
  assert.strictEqual(d.listenRaw, '80');
  assert.strictEqual(d.locations.length, 1);
  assert.strictEqual(d.locations[0].path, '/');
  assert.strictEqual(d.locations[0].proxyPass, 'http://backend:8080');
});
check('v12.34.0 : .target est accepte comme alias de .proxy_pass (parite avec nginx-agent/labels.go)', () => {
  const d = parseContainerLabels({
    'nginx-control.enable': 'true',
    'nginx-control.network': 'nginx-net',
    'nginx-control.vhost.server_name': 'app.example.com',
    'nginx-control.vhost.location01': '/',
    'nginx-control.vhost.location01.target': 'http://backend:8080',
  });
  assert.strictEqual(d.locations[0].proxyPass, 'http://backend:8080');
});
check('.target est prioritaire sur .proxy_pass si les deux sont poses (meme ordre que nginx-agent/labels.go)', () => {
  const d = parseContainerLabels({
    'nginx-control.enable': 'true',
    'nginx-control.vhost.location01': '/',
    'nginx-control.vhost.location01.target': 'http://from-target:8080',
    'nginx-control.vhost.location01.proxy_pass': 'http://from-proxy-pass:8080',
  });
  assert.strictEqual(d.locations[0].proxyPass, 'http://from-target:8080');
});
check('plusieurs locations sont triees numeriquement (10 apres 2, pas apres 1 en tri lexical)', () => {
  const d = parseContainerLabels({
    'nginx-control.enable': 'true',
    'nginx-control.vhost.location10': '/ten',
    'nginx-control.vhost.location10.proxy_pass': 'http://b10:80',
    'nginx-control.vhost.location02': '/two',
    'nginx-control.vhost.location02.proxy_pass': 'http://b2:80',
  });
  assert.deepStrictEqual(d.locations.map(l => l.path), ['/two', '/ten']);
});
check('listen absent -> laisse vide (le defaut 80/443 est tranche par validateDesiredVhost selon ssl_certificate)', () => {
  const d = parseContainerLabels({ 'nginx-control.enable': 'true' });
  assert.strictEqual(d.listenRaw, '');
});

console.log('\nvalidateDesiredVhost()');
function baseDesired(overrides = {}) {
  return {
    network: 'nginx-net', serverNameRaw: 'app.example.com', listenRaw: '80',
    locations: [{ index: '01', path: '/', proxyPass: 'http://backend:8080' }],
    ...overrides,
  };
}
check('jeu de labels valide -> valid true, aucune erreur', () => {
  const r = validateDesiredVhost(baseDesired());
  assert.deepStrictEqual(r.errors, []);
  assert.strictEqual(r.valid, true);
  assert.deepStrictEqual(r.serverNames, ['app.example.com']);
  assert.strictEqual(r.listen, 80);
});
check('server_name manquant -> erreur explicite', () => {
  const r = validateDesiredVhost(baseDesired({ serverNameRaw: '' }));
  assert.ok(!r.valid);
  assert.ok(r.errors.some(e => e.includes('server_name est requis')));
});
check('server_name avec un caractere d injection -> rejete', () => {
  for (const bad of ['app.example.com; }', 'app example.com', 'app$(whoami).com', '../../etc']) {
    const r = validateDesiredVhost(baseDesired({ serverNameRaw: bad }));
    assert.ok(!r.valid, `"${bad}" aurait du etre rejete`);
  }
});
check('server_name avec wildcard "*.example.com" -> accepte (syntaxe nginx standard)', () => {
  const r = validateDesiredVhost(baseDesired({ serverNameRaw: '*.example.com' }));
  assert.ok(r.valid, r.errors.join('; '));
});
check('plusieurs server_name espaces/virgules -> tous extraits', () => {
  const r = validateDesiredVhost(baseDesired({ serverNameRaw: 'app.example.com, www.example.com' }));
  assert.deepStrictEqual(r.serverNames, ['app.example.com', 'www.example.com']);
});
check('listen hors bornes ou non numerique -> erreur', () => {
  for (const bad of ['0', '70000', 'abc', '80; rm -rf /']) {
    const r = validateDesiredVhost(baseDesired({ listenRaw: bad }));
    assert.ok(!r.valid, `listen="${bad}" aurait du etre rejete`);
  }
});
check('network manquant -> erreur', () => {
  const r = validateDesiredVhost(baseDesired({ network: '' }));
  assert.ok(r.errors.some(e => e.includes('network est requis')));
});
check('network non attache au conteneur nginx -> erreur explicite (jamais un vhost silencieusement casse)', () => {
  const r = validateDesiredVhost(baseDesired({ network: 'reseau-inconnu' }), { nginxNetworks: ['nginx-net', 'autre-net'] });
  assert.ok(!r.valid);
  assert.ok(r.errors.some(e => e.includes('non attache')));
});
check('network attache -> accepte', () => {
  const r = validateDesiredVhost(baseDesired({ network: 'nginx-net' }), { nginxNetworks: ['nginx-net'] });
  assert.ok(r.valid, r.errors.join('; '));
});
check('aucune location -> erreur', () => {
  const r = validateDesiredVhost(baseDesired({ locations: [] }));
  assert.ok(r.errors.some(e => e.includes('au moins une location')));
});
check('location path invalide (injection) -> rejete', () => {
  for (const bad of ['/api; return 500', '/a{b}c', '/a b', 'no-leading-slash']) {
    const r = validateDesiredVhost(baseDesired({ locations: [{ index: '01', path: bad, proxyPass: 'http://backend:80' }] }));
    assert.ok(!r.valid, `location "${bad}" aurait du etre rejetee`);
  }
});
check('proxy_pass invalide (injection, scheme interdit, chemin en trop) -> rejete', () => {
  for (const bad of ['http://backend:8080; drop table', 'ftp://backend:21', 'http://backend:8080/path', 'javascript:alert(1)', '']) {
    const r = validateDesiredVhost(baseDesired({ locations: [{ index: '01', path: '/', proxyPass: bad }] }));
    assert.ok(!r.valid, `proxy_pass "${bad}" aurait du etre rejete`);
  }
});
check('proxy_pass valide avec ou sans port -> accepte', () => {
  for (const good of ['http://backend:8080', 'https://backend', 'http://my-service.internal:3000']) {
    const r = validateDesiredVhost(baseDesired({ locations: [{ index: '01', path: '/', proxyPass: good }] }));
    assert.ok(r.valid, `proxy_pass "${good}" : ${r.errors.join('; ')}`);
  }
});

console.log('\nsanitizeForFilename() / dockerVhostFileName()');
check('un server_name devient un nom de fichier stable et sans danger', () => {
  assert.strictEqual(sanitizeForFilename('app.example.com'), 'app_example_com');
  assert.strictEqual(sanitizeForFilename('*.example.com'), 'example_com');
  // Fix v12.21.2 (audit finding DAC-02): a short hash of the lower-cased
  // server_name is now appended — see dockerVhostFileName()'s own comment.
  assert.match(dockerVhostFileName(['app.example.com']), /^docker_app_example_com_[0-9a-f]{8}\.conf$/);
});
check('deux server_names differents qui se sanitizent pareil ne collisionnent jamais (fix DAC-02)', () => {
  const a = dockerVhostFileName(['*.example.com']);
  const b = dockerVhostFileName(['example.com']);
  const c = dockerVhostFileName(['a-b.example.com']);
  const d = dockerVhostFileName(['a.b.example.com']);
  assert.notStrictEqual(a, b);
  assert.notStrictEqual(c, d);
});
check('nom de fichier stable (meme entree -> meme sortie)', () => {
  assert.strictEqual(dockerVhostFileName(['App.Example.com']), dockerVhostFileName(['app.example.com']));
});
check('un caractere de traversee de repertoire ne produit jamais de fichier hors sites/', () => {
  const name = sanitizeForFilename('../../etc/passwd');
  assert.ok(!name.includes('/'), 'le nom sanitize ne doit jamais contenir de separateur de chemin');
  assert.ok(!name.includes('..'));
});

console.log('\ngenerateVhostContent()');
// generateVhostContent() takes the OBJECT RETURNED BY validateDesiredVhost()
// (not the raw parseContainerLabels() shape) — it renders already-trusted,
// already-normalized values (ssl, monitor, analyze, locations with their own
// resolved booleans, etc.), never the raw label strings.
check('rendu HTTP simple : resolver Docker, set + proxy_pass par variable, chemin nginx pour les futurs snippets', () => {
  const validated = validateDesiredVhost(baseDesired());
  const content = generateVhostContent(validated, ['app.example.com'], 80, { containerName: 'app', containerId: 'abc123456789' });
  assert.ok(content.includes('listen 80;'));
  assert.ok(content.includes('server_name app.example.com;'));
  assert.ok(content.includes('resolver 127.0.0.11 valid=30s;'));
  assert.ok(content.includes('set $backend01 "http://backend:8080";'));
  assert.ok(content.includes('proxy_pass $backend01;'));
  assert.ok(content.includes('NE PAS EDITER A LA MAIN'));
  // Jamais le chemin interne DIR_SNIPPETS du dashboard dans un vhost genere.
  assert.ok(!content.includes('/nginx/snippets'), 'un vhost genere ne doit jamais reference le chemin interne du dashboard');
});
check('deux locations -> deux variables $backendNN distinctes (pas de collision)', () => {
  const validated = validateDesiredVhost(baseDesired({
    locations: [
      { index: '01', path: '/', proxyPass: 'http://front:80' },
      { index: '02', path: '/api', proxyPass: 'http://api:8080' },
    ],
  }));
  const content = generateVhostContent(validated, ['app.example.com'], 80, {});
  assert.ok(content.includes('set $backend01 "http://front:80";'));
  assert.ok(content.includes('set $backend02 "http://api:8080";'));
  assert.ok(content.includes('location / {'));
  assert.ok(content.includes('location /api {'));
});

console.log('\nEtape 2 — ssl_certificate / http_to_https_auto');
check('ssl_certificate absent -> mode none, listen par defaut 80, aucune ligne ssl', () => {
  const r = validateDesiredVhost(baseDesired({ listenRaw: '' }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.strictEqual(r.ssl.mode, 'none');
  assert.strictEqual(r.ssl.active, false);
  assert.strictEqual(r.listen, 80);
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(!content.includes(' ssl;'));
});
check('ssl_certificate=auto sans listen -> defaut 443', () => {
  const r = validateDesiredVhost(baseDesired({ listenRaw: '', sslModeRaw: 'auto' }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.strictEqual(r.listen, 443);
  assert.strictEqual(r.ssl.active, true);
});
check('ssl_certificate=snippet sans ssl_certificate.snippet -> erreur', () => {
  const r = validateDesiredVhost(baseDesired({ sslModeRaw: 'snippet' }));
  assert.ok(!r.valid);
  assert.ok(r.errors.some(e => e.includes('ssl_certificate.snippet est requis')));
});
check('ssl_certificate.snippet avec traversee de repertoire -> rejete', () => {
  for (const bad of ['../ssl-evil.conf', '/etc/passwd', 'ssl-ok.conf; rm -rf /', '']) {
    const r = validateDesiredVhost(baseDesired({ sslModeRaw: 'snippet', sslSnippetRaw: bad }));
    assert.ok(!r.valid, `snippet "${bad}" aurait du etre rejete`);
  }
});
check('ssl_certificate invalide -> erreur explicite', () => {
  const r = validateDesiredVhost(baseDesired({ sslModeRaw: 'bogus' }));
  assert.ok(!r.valid);
  assert.ok(r.errors.some(e => e.includes('ssl_certificate invalide')));
});
check('ssl_certificate=certbot_http / certbot_dns -> acceptes, actifs, sans snippet requis', () => {
  for (const mode of ['certbot_http', 'certbot_dns', 'CERTBOT_HTTP']) {
    const r = validateDesiredVhost(baseDesired({ sslModeRaw: mode }));
    assert.ok(r.valid, `mode "${mode}" aurait du etre valide : ${JSON.stringify(r.errors)}`);
    assert.strictEqual(r.ssl.active, true);
    assert.strictEqual(r.ssl.mode, mode.toLowerCase());
  }
});
check('rendu avec ssl resolu (type error, certbot non active) : HTTP simple, note d erreur explicite, jamais un bloc ssl casse', () => {
  const r = validateDesiredVhost(baseDesired({ listenRaw: '', sslModeRaw: 'certbot_http' }));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {
    sslResolved: { type: 'error', code: 'certbot_http_disabled', message: 'Certbot n est pas active (config/certbot.yml : enable: false)' },
  });
  assert.ok(!content.includes(' ssl;'), 'un mode certbot non configure ne doit jamais produire un `listen ... ssl;` sans certificat');
  assert.ok(!content.includes('ssl_certificate '), 'aucune directive ssl_certificate sans certificat reel');
  assert.ok(content.includes('ERREUR ssl_certificate=certbot_http'));
  assert.ok(content.includes('Certbot n est pas active'));
});
check('rendu avec ssl resolu (type cert) : listen ssl, ssl_certificate/key, jamais sans meta.sslResolved', () => {
  const r = validateDesiredVhost(baseDesired({ listenRaw: '', sslModeRaw: 'auto' }));
  const noSsl = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(!noSsl.includes(' ssl;'), 'sans sslResolved fourni, ne jamais pretendre etre en HTTPS');
  assert.ok(noSsl.includes('aucun certificat correspondant'));
  const withSsl = generateVhostContent(r, ['app.example.com'], r.listen, {
    sslResolved: { type: 'cert', certPath: '/etc/letsencrypt/live/app.example.com/fullchain.pem', keyPath: '/etc/letsencrypt/live/app.example.com/privkey.pem' },
  });
  assert.ok(withSsl.includes('listen 443 ssl;'));
  assert.ok(withSsl.includes('ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;'));
  assert.ok(withSsl.includes('ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;'));
});
check('rendu avec ssl resolu (type snippet) : include snippets/<file>, jamais /nginx/snippets', () => {
  const r = validateDesiredVhost(baseDesired({ sslModeRaw: 'snippet', sslSnippetRaw: 'ssl-wildcard.conf' }));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, { sslResolved: { type: 'snippet', file: 'ssl-wildcard.conf' } });
  assert.ok(content.includes('include snippets/ssl-wildcard.conf;'));
  assert.ok(!content.includes('/nginx/snippets'));
});
check('http_to_https_auto=true + ssl resolu -> bloc de redirection 80 present avant le bloc principal', () => {
  const r = validateDesiredVhost(baseDesired({ listenRaw: '', sslModeRaw: 'auto', httpToHttpsAutoRaw: 'true' }));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {
    sslResolved: { type: 'cert', certPath: '/c', keyPath: '/k' },
  });
  assert.ok(content.includes('return 301 https://$host$request_uri;'));
  assert.ok(content.indexOf('listen 80;') < content.indexOf('listen 443 ssl;'));
});
check('http_to_https_auto=true mais ssl encore "pending" -> aucune redirection (rien a rediriger vers)', () => {
  const r = validateDesiredVhost(baseDesired({ sslModeRaw: 'auto', httpToHttpsAutoRaw: 'true' }));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, { sslResolved: { type: 'pending' } });
  assert.ok(!content.includes('return 301'));
});
check('http_to_https_auto invalide (ni true ni false) -> erreur', () => {
  const r = validateDesiredVhost(baseDesired({ httpToHttpsAutoRaw: 'oui' }));
  assert.ok(!r.valid);
  assert.ok(r.errors.some(e => e.includes('http_to_https_auto invalide')));
});

console.log('\nEtape 2 — snippets server/location');
check('server.snippetNN valide -> include trie, jamais /nginx/snippets', () => {
  const r = validateDesiredVhost(baseDesired({ serverSnippets: [{ index: '2', file: 'b.conf' }, { index: '1', file: 'a.conf' }] }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(content.indexOf('include snippets/a.conf;') < content.indexOf('include snippets/b.conf;'));
  assert.ok(!content.includes('/nginx/snippets'));
});
check('server.snippetNN avec un nom de fichier dangereux -> rejete', () => {
  for (const bad of ['../evil.conf', '/etc/passwd', 'a.conf; rm -rf /']) {
    const r = validateDesiredVhost(baseDesired({ serverSnippets: [{ index: '1', file: bad }] }));
    assert.ok(!r.valid, `server snippet "${bad}" aurait du etre rejete`);
  }
});
check('location.snippetMM valide -> include a l interieur du bon bloc location', () => {
  const r = validateDesiredVhost(baseDesired({
    locations: [{ index: '01', path: '/', proxyPass: 'http://backend:8080', snippets: [{ index: '1', file: 'loc.conf' }] }],
  }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(content.includes('include snippets/loc.conf;'));
});
check('location.snippetMM avec un nom de fichier dangereux -> rejete', () => {
  const r = validateDesiredVhost(baseDesired({
    locations: [{ index: '01', path: '/', proxyPass: 'http://backend:8080', snippets: [{ index: '1', file: '../evil.conf' }] }],
  }));
  assert.ok(!r.valid);
});

console.log('\nEtape 2 — monitor / diagnostic / analyze (memes commentaires magiques que lib/vhost-targets.js)');
check('monitor.enable=true -> commentaire nginx-control-monitoring: on', () => {
  const r = validateDesiredVhost(baseDesired({ monitor: { enableRaw: 'true', intervalRaw: '60s', validHttpCodeRaw: '2xx, 3xx' } }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(content.includes('# nginx-control-monitoring: on'));
  assert.ok(content.includes('# nginx-control-monitoring-interval: 60s'));
  assert.ok(content.includes('# nginx-control-monitoring-valid-http-code: 2xx, 3xx'));
});
check('monitor absent -> pas de commentaire (opt-in, comme le mecanisme existant)', () => {
  const r = validateDesiredVhost(baseDesired());
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(!content.includes('nginx-control-monitoring'));
});
check('monitor.interval invalide -> erreur', () => {
  const r = validateDesiredVhost(baseDesired({ monitor: { enableRaw: 'true', intervalRaw: 'abc' } }));
  assert.ok(!r.valid);
});
check('monitor.valid_http_code invalide -> erreur', () => {
  const r = validateDesiredVhost(baseDesired({ monitor: { enableRaw: 'true', validHttpCodeRaw: '999' } }));
  assert.ok(!r.valid);
});
check('location.monitor.ignore=true -> commentaire ignore dans le bon bloc location', () => {
  const r = validateDesiredVhost(baseDesired({
    locations: [{ index: '01', path: '/', proxyPass: 'http://backend:8080', monitorIgnoreRaw: 'true' }],
  }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(content.includes('# nginx-control-monitoring-ignore-location: on'));
});
check('diagnostic.enable=false -> commentaire fichier-niveau avant le premier server{}', () => {
  const r = validateDesiredVhost(baseDesired({ diagnostic: { enableRaw: 'false' } }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  const commentIdx = content.indexOf('# nginx-control-diagnostic: off');
  const serverIdx = content.indexOf('server {');
  assert.ok(commentIdx !== -1 && commentIdx < serverIdx, 'le commentaire diagnostic doit preceder le premier bloc server{}');
});
check('diagnostic absent -> par defaut actif (aucun commentaire off)', () => {
  const r = validateDesiredVhost(baseDesired());
  assert.strictEqual(r.diagnostic.enable, true);
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(!content.includes('nginx-control-diagnostic'));
});
check('analyze.enable=false -> commentaire nginx-control-analyze: off', () => {
  const r = validateDesiredVhost(baseDesired({ analyze: { enableRaw: 'false' } }));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(content.includes('# nginx-control-analyze: off'));
});
check('analyze.ignore_rules valide -> commentaire nginx-control-analyze-ignore-rules', () => {
  const r = validateDesiredVhost(baseDesired({ analyze: { ignoreRulesRaw: '1, 2, 4' } }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(content.includes('# nginx-control-analyze-ignore-rules: 1, 2, 4'));
});
check('analyze.ignore_rules invalide (non numerique) -> erreur', () => {
  const r = validateDesiredVhost(baseDesired({ analyze: { ignoreRulesRaw: '1, deux, 4' } }));
  assert.ok(!r.valid);
});

console.log('\nEtape 2 — upstream_group (le nom seul ; l agregation multi-conteneurs est testee dans features/docker-autoconfig.js)');
check('upstream_group absent -> chaine vide, rendu inchange (resolver/set/proxy_pass classique)', () => {
  const r = validateDesiredVhost(baseDesired());
  assert.strictEqual(r.locations[0].upstreamGroup, '');
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(!content.includes('upstream '));
  assert.ok(content.includes('resolver 127.0.0.11 valid=30s;'));
});
check('upstream_group valide -> conserve tel quel dans le resultat valide', () => {
  const r = validateDesiredVhost(baseDesired({
    locations: [{ index: '01', path: '/', proxyPass: 'http://backend:8080', upstreamGroupRaw: 'api-pool' }],
  }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.strictEqual(r.locations[0].upstreamGroup, 'api-pool');
});
check('upstream_group avec un caractere d injection -> rejete', () => {
  for (const bad of ['api; rm -rf /', 'api pool', '../api']) {
    const r = validateDesiredVhost(baseDesired({
      locations: [{ index: '01', path: '/', proxyPass: 'http://backend:8080', upstreamGroupRaw: bad }],
    }));
    assert.ok(!r.valid, `upstream_group "${bad}" aurait du etre rejete`);
  }
});
check('rendu avec upstreamBackends fournis (simule la fusion faite par features/docker-autoconfig.js) : bloc upstream + proxy_pass par nom de groupe, jamais de resolver/set', () => {
  const r = validateDesiredVhost(baseDesired({
    locations: [{ index: '01', path: '/', proxyPass: 'http://ignored:0', upstreamGroupRaw: 'api-pool' }],
  }));
  r.locations[0].upstreamBackends = [{ host: 'app1', port: 8080 }, { host: 'app2', port: 8080 }];
  r.locations[0].upstreamScheme = 'http';
  const content = generateVhostContent(r, ['app.example.com'], r.listen, {});
  assert.ok(content.includes('upstream api-pool {'));
  assert.ok(content.includes('server app1:8080;'));
  assert.ok(content.includes('server app2:8080;'));
  assert.ok(content.includes('proxy_pass http://api-pool;'));
  assert.ok(!content.includes('resolver 127.0.0.11'));
  assert.ok(!content.includes('set $backend'));
});

console.log('\nparseBackendUrl()');
check('extrait scheme/host/port, port par defaut selon le scheme si absent', () => {
  assert.deepStrictEqual(parseBackendUrl('http://backend:8080'), { scheme: 'http', host: 'backend', port: 8080 });
  assert.deepStrictEqual(parseBackendUrl('https://backend'), { scheme: 'https', host: 'backend', port: 443 });
  assert.deepStrictEqual(parseBackendUrl('http://backend'), { scheme: 'http', host: 'backend', port: 80 });
});
check('entree invalide -> null, jamais d exception', () => {
  assert.strictEqual(parseBackendUrl('not-a-url'), null);
  assert.strictEqual(parseBackendUrl(''), null);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
