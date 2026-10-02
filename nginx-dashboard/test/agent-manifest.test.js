'use strict';
/**
 * lib/agent-manifest.js — validation d'un manifeste d'agent distant (Partie
 * 2) et rendu du vhost nginx correspondant. Logique pure, meme discipline de
 * test que lib/docker-autoconfig.js's own test file : chaque regex ancree
 * doit rejeter ce qu elle doit rejeter, jamais moins.
 */
const assert = require('assert');
const {
  validateManifestVhost, validateManifest, agentVhostFileName,
  generateAgentVhostContent, sanitizeForFilename, validateMetrics,
  SUPPORTED_PROTOCOL_VERSIONS,
} = require('../lib/agent-manifest');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function baseVhost(overrides = {}) {
  return {
    serverName: 'app.example.com',
    locations: [{ path: '/', target: 'http://203.0.113.10:8080' }],
    ...overrides,
  };
}

console.log('\nvalidateManifestVhost() — cas valides');
check('vhost minimal valide (HTTP simple, une location)', () => {
  const r = validateManifestVhost(baseVhost());
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.deepStrictEqual(r.serverNames, ['app.example.com']);
  assert.strictEqual(r.listen, 80);
  assert.strictEqual(r.ssl.active, false);
});
check('plusieurs server_name (espace/virgule)', () => {
  const r = validateManifestVhost(baseVhost({ serverName: 'app.example.com, www.app.example.com' }));
  assert.strictEqual(r.valid, true);
  assert.deepStrictEqual(r.serverNames, ['app.example.com', 'www.app.example.com']);
});
check('sslCertificate=auto -> listen par defaut 443', () => {
  const r = validateManifestVhost(baseVhost({ sslCertificate: 'auto' }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.strictEqual(r.listen, 443);
  assert.strictEqual(r.ssl.active, true);
});
check('sslCertificate=snippet avec un nom de fichier valide', () => {
  const r = validateManifestVhost(baseVhost({ sslCertificate: 'snippet', sslCertificateSnippet: 'ssl-wildcard.conf' }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.strictEqual(r.ssl.snippetFile, 'ssl-wildcard.conf');
});
check('listen explicite respecte', () => {
  const r = validateManifestVhost(baseVhost({ listen: 8443 }));
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.listen, 8443);
});
check('monitor/diagnostic/analyze passent et se retrouvent normalises', () => {
  const r = validateManifestVhost(baseVhost({
    monitor: { enable: true, interval: '30s', validHttpCode: '2xx, 3xx' },
    diagnostic: { enable: false },
    analyze: { enable: false, ignoreRules: [1, 4] },
  }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.deepStrictEqual(r.monitor, { enable: true, interval: '30s', validHttpCodes: ['2xx', '3xx'] });
  assert.strictEqual(r.diagnostic.enable, false);
  assert.strictEqual(r.analyze.enable, false);
  assert.deepStrictEqual(r.analyze.ignoreRules, [1, 4]);
});
check('cible IPv4 littérale acceptée (mode direct)', () => {
  const r = validateManifestVhost(baseVhost({ locations: [{ path: '/', target: 'https://203.0.113.99:8443' }] }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.strictEqual(r.locations[0].target, 'https://203.0.113.99:8443');
});
check('sslCertificate=certbot_http accepte (v12.21.0) -> listen par defaut 443', () => {
  const r = validateManifestVhost(baseVhost({ sslCertificate: 'certbot_http' }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.strictEqual(r.listen, 443);
  assert.strictEqual(r.ssl.active, true);
  assert.strictEqual(r.ssl.mode, 'certbot_http');
});
check('sslCertificate=certbot_dns accepte (v12.21.0)', () => {
  const r = validateManifestVhost(baseVhost({ sslCertificate: 'certbot_dns' }));
  assert.strictEqual(r.valid, true, r.errors.join('; '));
  assert.strictEqual(r.ssl.mode, 'certbot_dns');
});

console.log('\nvalidateManifestVhost() — cas invalides (tout doit etre rejete explicitement)');
check('sans serverName -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ serverName: '' }));
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some(e => /serverName/.test(e)));
});
check('serverName invalide (espace interdit dans un seul token) -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ serverName: 'not a hostname!' }));
  assert.strictEqual(r.valid, false);
});
check('sslCertificate invalide (mode inconnu) -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ sslCertificate: 'lets-encrypt-magique' }));
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some(e => /sslCertificate invalide/.test(e)));
});
check('sslCertificate=snippet sans sslCertificateSnippet -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ sslCertificate: 'snippet' }));
  assert.strictEqual(r.valid, false);
});
check('listen hors bornes -> invalide', () => {
  assert.strictEqual(validateManifestVhost(baseVhost({ listen: 0 })).valid, false);
  assert.strictEqual(validateManifestVhost(baseVhost({ listen: 70000 })).valid, false);
  assert.strictEqual(validateManifestVhost(baseVhost({ listen: '80' })).valid, false, 'listen doit etre un entier JSON, jamais une chaine');
});
check('aucune location -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ locations: [] }));
  assert.strictEqual(r.valid, false);
});
check('location sans target -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ locations: [{ path: '/' }] }));
  assert.strictEqual(r.valid, false);
});
check('target avec un chemin/une query -> invalide (uniquement scheme://host:port)', () => {
  const r = validateManifestVhost(baseVhost({ locations: [{ path: '/', target: 'http://203.0.113.10:8080/api' }] }));
  assert.strictEqual(r.valid, false);
});
check('target avec un schema non http(s) -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ locations: [{ path: '/', target: 'ftp://203.0.113.10:21' }] }));
  assert.strictEqual(r.valid, false);
});
check('path de location invalide (espace, accolade) -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ locations: [{ path: '/a b', target: 'http://203.0.113.10:8080' }] }));
  assert.strictEqual(r.valid, false);
});
check('trop de locations (> MAX_LOCATIONS_PER_VHOST) -> invalide', () => {
  const locations = Array.from({ length: 31 }, (_, i) => ({ path: `/p${i}`, target: 'http://203.0.113.10:8080' }));
  const r = validateManifestVhost(baseVhost({ locations }));
  assert.strictEqual(r.valid, false);
});
check('httpToHttpsAuto non-booleen -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ httpToHttpsAuto: 'true' }));
  assert.strictEqual(r.valid, false);
});
check('analyze.ignoreRules avec une valeur non numerique -> invalide', () => {
  const r = validateManifestVhost(baseVhost({ analyze: { ignoreRules: [1, 'x'] } }));
  assert.strictEqual(r.valid, false);
});
check('entree non-objet -> invalide sans exception', () => {
  assert.strictEqual(validateManifestVhost(null).valid, false);
  assert.strictEqual(validateManifestVhost('oops').valid, false);
  assert.strictEqual(validateManifestVhost([1, 2]).valid, false);
});

console.log('\nvalidateManifest() — enveloppe complete');
check('manifeste valide avec plusieurs vhosts, un bon un mauvais', () => {
  const r = validateManifest({ vhosts: [baseVhost(), baseVhost({ serverName: '' })] });
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.vhosts.length, 2);
  assert.strictEqual(r.vhosts[0].valid, true);
  assert.strictEqual(r.vhosts[1].valid, false);
});
check('body non-objet -> invalide au niveau enveloppe', () => {
  assert.strictEqual(validateManifest(null).valid, false);
  assert.strictEqual(validateManifest('oops').valid, false);
});
check('"vhosts" absent ou pas un tableau -> invalide au niveau enveloppe', () => {
  assert.strictEqual(validateManifest({}).valid, false);
  assert.strictEqual(validateManifest({ vhosts: {} }).valid, false);
});
check('trop de vhosts (> maxVhosts) -> rejet en bloc, jamais une troncature silencieuse', () => {
  const vhosts = Array.from({ length: 5 }, () => baseVhost());
  const r = validateManifest({ vhosts }, { maxVhosts: 3 });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.vhosts.length, 0);
  assert.ok(r.errors.some(e => /trop de vhosts/.test(e)));
});

console.log('\nagentVhostFileName() / sanitizeForFilename()');
check('nom de fichier stable et prefixe par agent_<id>_', () => {
  // Fix v12.21.2 (audit finding DAC-02): a short hash of the lower-cased
  // server_name is now appended to keep file names collision-free — see
  // lib/agent-manifest.js#agentVhostFileName()'s own comment.
  const name = agentVhostFileName('abc123', ['App.Example.com']);
  assert.match(name, /^agent_abc123_app_example_com_[0-9a-f]{8}\.conf$/);
});
check('nom de fichier stable (meme entree -> meme sortie)', () => {
  const a = agentVhostFileName('abc123', ['App.Example.com']);
  const b = agentVhostFileName('abc123', ['app.example.com']);
  assert.strictEqual(a, b);
});
check('deux server_names differents ne collisionnent jamais (fix DAC-02)', () => {
  const a = agentVhostFileName('abc123', ['a-b.example.com']);
  const b = agentVhostFileName('abc123', ['a.b.example.com']);
  assert.notStrictEqual(a, b);
});
check('sanitizeForFilename() ne produit jamais de chaine vide', () => {
  assert.strictEqual(sanitizeForFilename('!!!'), 'vhost');
});

console.log('\ngenerateAgentVhostContent() — rendu nginx');
check('vhost HTTP simple : pas de resolver Docker (mode direct, cible ip:port fixe)', () => {
  const v = validateManifestVhost(baseVhost());
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, { agentId: 'abc123', agentName: 'vps-1' });
  assert.ok(content.includes('proxy_pass http://203.0.113.10:8080;'));
  assert.ok(!content.includes('resolver 127.0.0.11'), 'le mode direct ne doit jamais utiliser le trick resolver/set de Partie 1');
  assert.ok(content.includes('server_name app.example.com;'));
  assert.ok(content.includes('listen 80;'));
  assert.ok(!content.includes(' ssl'), 'pas de SSL demande -> jamais un `listen ... ssl`');
});
check('SSL "cert" resolu -> bloc ssl_certificate/ssl_certificate_key, listen ssl', () => {
  const v = validateManifestVhost(baseVhost({ sslCertificate: 'auto' }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, {
    agentId: 'abc123', agentName: 'vps-1',
    sslResolved: { type: 'cert', certPath: '/etc/letsencrypt/live/app.example.com/fullchain.pem', keyPath: '/etc/letsencrypt/live/app.example.com/privkey.pem' },
  });
  assert.ok(content.includes('listen 443 ssl;'));
  assert.ok(content.includes('ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;'));
  assert.ok(content.includes('ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;'));
});
check('SSL "pending" (auto, rien trouve) -> reste en HTTP simple, jamais un bloc ssl casse', () => {
  const v = validateManifestVhost(baseVhost({ sslCertificate: 'auto' }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, {
    agentId: 'abc123', agentName: 'vps-1', sslResolved: { type: 'pending' },
  });
  assert.ok(content.includes('listen 443;'), 'listen sans "ssl" tant que rien n est resolu');
  assert.ok(!content.includes('ssl_certificate '));
  assert.ok(/aucun certificat correspondant/.test(content));
});
check('httpToHttpsAuto avec SSL live -> bloc de redirection 301 present', () => {
  const v = validateManifestVhost(baseVhost({ sslCertificate: 'auto', httpToHttpsAuto: true }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, {
    agentId: 'abc123', agentName: 'vps-1',
    sslResolved: { type: 'cert', certPath: '/x/fullchain.pem', keyPath: '/x/privkey.pem' },
  });
  assert.ok(content.includes('return 301 https://$host$request_uri;'));
});
check('httpToHttpsAuto sans SSL live (pending) -> pas de redirection (rien a rediriger vers)', () => {
  const v = validateManifestVhost(baseVhost({ sslCertificate: 'auto', httpToHttpsAuto: true }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, {
    agentId: 'abc123', agentName: 'vps-1', sslResolved: { type: 'pending' },
  });
  assert.ok(!content.includes('return 301 https'));
});
check('diagnostic desactive -> commentaire magique en tete de fichier', () => {
  const v = validateManifestVhost(baseVhost({ diagnostic: { enable: false } }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, { agentId: 'abc123', agentName: 'vps-1' });
  assert.ok(/# nginx-control-diagnostic: off/.test(content));
});
check('analyze.ignoreRules -> commentaire magique dans le bloc server', () => {
  const v = validateManifestVhost(baseVhost({ analyze: { ignoreRules: [1, 3] } }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, { agentId: 'abc123', agentName: 'vps-1' });
  assert.ok(/# nginx-control-analyze-ignore-rules: 1, 3/.test(content));
});
check('monitor active -> commentaires magiques monitoring', () => {
  const v = validateManifestVhost(baseVhost({ monitor: { enable: true, interval: '45s', validHttpCode: '2xx' } }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, { agentId: 'abc123', agentName: 'vps-1' });
  assert.ok(/# nginx-control-monitoring: on/.test(content));
  assert.ok(/# nginx-control-monitoring-interval: 45s/.test(content));
  assert.ok(/# nginx-control-monitoring-valid-http-code: 2xx/.test(content));
});
check('plusieurs locations -> chacune son propre bloc, dans l ordre', () => {
  const v = validateManifestVhost(baseVhost({ locations: [
    { path: '/', target: 'http://203.0.113.10:8080' },
    { path: '/api', target: 'http://203.0.113.11:9090' },
  ] }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, { agentId: 'abc123', agentName: 'vps-1' });
  assert.ok(content.indexOf('location / {') < content.indexOf('location /api {'));
  assert.ok(content.includes('proxy_pass http://203.0.113.11:9090;'));
});

console.log('\nvalidateManifest() — protocolVersion');
check('protocolVersion absent -> traite comme 1, manifeste valide', () => {
  const r = validateManifest({ vhosts: [baseVhost()] });
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.protocolVersion, 1);
});
check('protocolVersion supportee explicite -> valide', () => {
  const r = validateManifest({ vhosts: [baseVhost()], protocolVersion: 1 });
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.protocolVersion, 1);
});
check('protocolVersion non supportee -> rejet enveloppe avec la liste des versions connues', () => {
  const r = validateManifest({ vhosts: [baseVhost()], protocolVersion: 99 });
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors[0].includes('protocolVersion'));
  assert.ok(r.errors[0].includes(String(SUPPORTED_PROTOCOL_VERSIONS[0])));
});
check('protocolVersion non entiere -> rejet enveloppe', () => {
  const r = validateManifest({ vhosts: [baseVhost()], protocolVersion: '1' });
  assert.strictEqual(r.valid, false);
});

console.log('\nvalidateManifestVhost() — mode direct/tunnel');
check('mode absent -> defaut "direct"', () => {
  const v = validateManifestVhost(baseVhost());
  assert.strictEqual(v.mode, 'direct');
  assert.strictEqual(v.valid, true);
});
check('mode="tunnel" explicite -> accepte', () => {
  const v = validateManifestVhost(baseVhost({ mode: 'tunnel' }));
  assert.strictEqual(v.mode, 'tunnel');
  assert.strictEqual(v.valid, true);
});
check('mode invalide -> rejete', () => {
  const v = validateManifestVhost(baseVhost({ mode: 'bogus' }));
  assert.strictEqual(v.valid, false);
});
check('mode="relay" explicite -> accepte, relayScheme par defaut "http"', () => {
  const v = validateManifestVhost(baseVhost({ mode: 'relay' }));
  assert.strictEqual(v.mode, 'relay');
  assert.strictEqual(v.relayScheme, 'http');
  assert.strictEqual(v.valid, true);
});
check('relayScheme="https" explicite -> accepte', () => {
  const v = validateManifestVhost(baseVhost({ mode: 'relay', relayScheme: 'https' }));
  assert.strictEqual(v.relayScheme, 'https');
  assert.strictEqual(v.valid, true);
});
check('relayScheme invalide -> rejete', () => {
  const v = validateManifestVhost(baseVhost({ mode: 'relay', relayScheme: 'ftp' }));
  assert.strictEqual(v.valid, false);
});

console.log('\nvalidateManifest() — enveloppe "relay"');
check('mode relay + relay.http fourni -> vhost accepte', () => {
  const r = validateManifest({ vhosts: [baseVhost({ mode: 'relay' })], relay: { http: 'http://10.0.5.9:8443' } });
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.vhosts[0].valid, true, r.vhosts[0].errors.join('; '));
  assert.deepStrictEqual(r.relay, { http: 'http://10.0.5.9:8443' });
});
check('mode relay (https) mais relay.https absent -> ce vhost seul est invalide', () => {
  const r = validateManifest({ vhosts: [baseVhost({ mode: 'relay', relayScheme: 'https' }), baseVhost({ serverName: 'other.example.com' })], relay: { http: 'http://10.0.5.9:8080' } });
  assert.strictEqual(r.valid, true, 'l enveloppe reste valide (une seule entree en cause)');
  assert.strictEqual(r.vhosts[0].valid, false);
  assert.ok(r.vhosts[0].errors.some(e => /relay\.https/.test(e)));
  assert.strictEqual(r.vhosts[1].valid, true, 'les autres vhosts du meme manifeste ne sont pas impactes');
});
check('relay.http/https invalides -> ignores silencieusement au niveau enveloppe, vhost relay invalide', () => {
  const r = validateManifest({ vhosts: [baseVhost({ mode: 'relay' })], relay: { http: 'not-a-url' } });
  assert.strictEqual(r.valid, true);
  assert.deepStrictEqual(r.relay, {});
  assert.strictEqual(r.vhosts[0].valid, false);
});
check('pas d objet relay du tout -> vhosts direct/tunnel non affectes', () => {
  const r = validateManifest({ vhosts: [baseVhost()] });
  assert.strictEqual(r.valid, true);
  assert.deepStrictEqual(r.relay, {});
  assert.strictEqual(r.vhosts[0].valid, true);
});

console.log('\ngenerateAgentVhostContent() — mode tunnel');
check('mode tunnel -> un seul location "/" vers le relais du dashboard, pas de target agent', () => {
  const v = validateManifestVhost(baseVhost({ mode: 'tunnel', locations: [
    { path: '/', target: 'http://127.0.0.1:8080' },
    { path: '/api', target: 'http://127.0.0.1:9090' },
  ] }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, {
    agentId: 'abc123', agentName: 'vps-1', tunnelTarget: 'http://nginx-dashboard:3000',
  });
  assert.ok(content.includes('location / {'));
  assert.ok(!content.includes('location /api {'));
  assert.ok(content.includes('proxy_pass http://nginx-dashboard:3000;'));
  assert.ok(!content.includes('proxy_pass http://127.0.0.1:8080;'));
  assert.ok(/# Mode: tunnel/.test(content));
});

console.log('\ngenerateAgentVhostContent() — mode relay');
check('mode relay (http) -> un seul location "/" vers le port fixe de l agent, pas de proxy_ssl_verify', () => {
  const v = validateManifestVhost(baseVhost({ mode: 'relay', locations: [
    { path: '/', target: 'http://127.0.0.1:8080' },
    { path: '/api', target: 'http://127.0.0.1:9090' },
  ] }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, {
    agentId: 'abc123', agentName: 'vps-1', relayTarget: 'http://198.51.100.5:34443',
  });
  assert.ok(content.includes('location / {'));
  assert.ok(!content.includes('location /api {'));
  assert.ok(content.includes('proxy_pass http://198.51.100.5:34443;'));
  assert.ok(!content.includes('proxy_pass http://127.0.0.1:8080;'));
  assert.ok(/# Mode: relay/.test(content));
  assert.ok(!content.includes('proxy_ssl_verify off;'));
});
check('mode relay (https) -> proxy_ssl_verify off ajoute (saut agent probablement auto-signe)', () => {
  const v = validateManifestVhost(baseVhost({ mode: 'relay', relayScheme: 'https' }));
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, {
    agentId: 'abc123', agentName: 'vps-1', relayTarget: 'https://198.51.100.5:34943',
  });
  assert.ok(content.includes('proxy_pass https://198.51.100.5:34943;'));
  assert.ok(content.includes('proxy_ssl_verify off;'));
});

console.log('\nvalidateMetrics()');
check('metrics absentes -> null', () => {
  assert.strictEqual(validateMetrics(undefined), null);
  assert.strictEqual(validateMetrics(null), null);
});
check('metrics valides -> normalisees en nombres', () => {
  const m = validateMetrics({ cpuPercent: '42.5', memPercent: 60, uptimeSec: 3600 });
  assert.deepStrictEqual(m, { cpuPercent: 42.5, memPercent: 60, uptimeSec: 3600 });
});
check('metrics hors bornes -> cle ignoree, pas d exception', () => {
  const m = validateMetrics({ cpuPercent: 150, memPercent: -5, uptimeSec: 100 });
  assert.deepStrictEqual(m, { uptimeSec: 100 });
});
check('metrics toutes invalides -> null (pas un objet vide)', () => {
  assert.strictEqual(validateMetrics({ cpuPercent: 'abc' }), null);
});
check('metrics non-objet -> null', () => {
  assert.strictEqual(validateMetrics('nope'), null);
});
check('validateManifest() propage les metrics valides', () => {
  const r = validateManifest({ vhosts: [baseVhost()], metrics: { cpuPercent: 12 } });
  assert.deepStrictEqual(r.metrics, { cpuPercent: 12 });
});

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);
