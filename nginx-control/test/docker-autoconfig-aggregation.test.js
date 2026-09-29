'use strict';
/**
 * tryAggregateGroup() (features/docker-autoconfig.js) — l'agregation
 * `upstream_group` de l'etape 2 : plusieurs conteneurs (replicas d'un meme
 * service) partageant un `server_name` doivent se fusionner en UN vhost
 * avec un bloc `upstream {}`, au lieu de se faire mutuellement traiter comme
 * un conflit de server_name (cf. test/docker-autoconfig-routes.test.js pour
 * le cas conflit classique, inchange).
 *
 * Purement synchrone, aucun appel Docker/fs — tryAggregateGroup() ne fait
 * que comparer des objets deja valides par validateDesiredVhost().
 */
const assert = require('assert');
const { validateDesiredVhost, generateVhostContent } = require('../lib/docker-autoconfig');
const { tryAggregateGroup } = require('../features/docker-autoconfig');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

/** Build a runCycle()-shaped candidate from a raw label set. */
function candidate(containerName, containerId, overrides = {}) {
  const { nginxNetworks, ...desiredOverrides } = overrides;
  const desired = {
    network: 'nginx-net', serverNameRaw: 'api.example.com', listenRaw: '80',
    locations: [{ index: '01', path: '/', proxyPass: 'http://replica:8080', upstreamGroupRaw: 'api-pool' }],
    ...desiredOverrides,
  };
  const validated = validateDesiredVhost(desired, { nginxNetworks: nginxNetworks || ['nginx-net', 'autre-net'] });
  assert.strictEqual(validated.valid, true, `candidat de test invalide : ${validated.errors.join('; ')}`);
  return { containerId, containerName, desired, validated, valid: validated.valid, errors: validated.errors, serverNames: validated.serverNames, listen: validated.listen };
}

console.log('\ntryAggregateGroup() — cas nominal : deux replicas, meme groupe, memes reglages');
check('fusionne en un seul vhost avec un bloc upstream a deux serveurs', () => {
  const group = [
    candidate('app1', 'id1', { locations: [{ index: '01', path: '/', proxyPass: 'http://app1:8080', upstreamGroupRaw: 'api-pool' }] }),
    candidate('app2', 'id2', { locations: [{ index: '01', path: '/', proxyPass: 'http://app2:8080', upstreamGroupRaw: 'api-pool' }] }),
  ];
  const merged = tryAggregateGroup(group);
  assert.ok(merged, 'la fusion aurait du reussir');
  assert.strictEqual(merged.locations.length, 1);
  assert.strictEqual(merged.locations[0].upstreamGroup, 'api-pool');
  assert.deepStrictEqual(merged.locations[0].upstreamBackends, [{ host: 'app1', port: 8080 }, { host: 'app2', port: 8080 }]);

  const content = generateVhostContent(merged, ['api.example.com'], merged.listen, {});
  assert.ok(content.includes('upstream api-pool {'));
  assert.ok(content.includes('server app1:8080;'));
  assert.ok(content.includes('server app2:8080;'));
  assert.ok(content.includes('proxy_pass http://api-pool;'));
});

console.log('\ntryAggregateGroup() — trois replicas, plusieurs locations partagees');
check('chaque location garde son propre groupe et ses propres backends', () => {
  const locsFor = host => [
    { index: '01', path: '/', proxyPass: `http://${host}:8080`, upstreamGroupRaw: 'web-pool' },
    { index: '02', path: '/api', proxyPass: `http://${host}:9000`, upstreamGroupRaw: 'api-pool' },
  ];
  const group = [
    candidate('app1', 'id1', { locations: locsFor('app1') }),
    candidate('app2', 'id2', { locations: locsFor('app2') }),
    candidate('app3', 'id3', { locations: locsFor('app3') }),
  ];
  const merged = tryAggregateGroup(group);
  assert.ok(merged, 'la fusion aurait du reussir');
  const web = merged.locations.find(l => l.path === '/');
  const api = merged.locations.find(l => l.path === '/api');
  assert.strictEqual(web.upstreamGroup, 'web-pool');
  assert.strictEqual(web.upstreamBackends.length, 3);
  assert.strictEqual(api.upstreamGroup, 'api-pool');
  assert.strictEqual(api.upstreamBackends.length, 3);
});

console.log('\ntryAggregateGroup() — jamais une fusion silencieuse en cas d ambiguite');
check('un seul candidat sans upstream_group -> pas de fusion (reste un conflit ordinaire)', () => {
  const group = [
    candidate('app1', 'id1', { locations: [{ index: '01', path: '/', proxyPass: 'http://app1:8080', upstreamGroupRaw: 'api-pool' }] }),
    candidate('app2', 'id2', { locations: [{ index: '01', path: '/', proxyPass: 'http://app2:8080' }] }), // pas de groupe
  ];
  assert.strictEqual(tryAggregateGroup(group), null);
});
check('deux candidats avec des noms de groupe differents -> pas de fusion', () => {
  const group = [
    candidate('app1', 'id1', { locations: [{ index: '01', path: '/', proxyPass: 'http://app1:8080', upstreamGroupRaw: 'pool-a' }] }),
    candidate('app2', 'id2', { locations: [{ index: '01', path: '/', proxyPass: 'http://app2:8080', upstreamGroupRaw: 'pool-b' }] }),
  ];
  assert.strictEqual(tryAggregateGroup(group), null);
});
check('schemes http/https melanges sur le meme groupe -> pas de fusion (proxy_pass ambigu)', () => {
  const group = [
    candidate('app1', 'id1', { locations: [{ index: '01', path: '/', proxyPass: 'http://app1:8080', upstreamGroupRaw: 'api-pool' }] }),
    candidate('app2', 'id2', { locations: [{ index: '01', path: '/', proxyPass: 'https://app2:8443', upstreamGroupRaw: 'api-pool' }] }),
  ];
  assert.strictEqual(tryAggregateGroup(group), null);
});
check('ensembles de locations differents (chemins qui ne correspondent pas) -> pas de fusion', () => {
  const group = [
    candidate('app1', 'id1', { locations: [{ index: '01', path: '/', proxyPass: 'http://app1:8080', upstreamGroupRaw: 'api-pool' }] }),
    candidate('app2', 'id2', { locations: [{ index: '01', path: '/other', proxyPass: 'http://app2:8080', upstreamGroupRaw: 'api-pool' }] }),
  ];
  assert.strictEqual(tryAggregateGroup(group), null);
});
check('reseaux Docker differents -> pas de fusion (des replicas doivent partager le meme reseau)', () => {
  const group = [
    candidate('app1', 'id1', { network: 'nginx-net', locations: [{ index: '01', path: '/', proxyPass: 'http://app1:8080', upstreamGroupRaw: 'api-pool' }] }),
    candidate('app2', 'id2', { network: 'autre-net', locations: [{ index: '01', path: '/', proxyPass: 'http://app2:8080', upstreamGroupRaw: 'api-pool' }] }),
  ];
  assert.strictEqual(tryAggregateGroup(group), null);
});
check('reglages globaux differents (ex : listen) -> pas de fusion', () => {
  const group = [
    candidate('app1', 'id1', { listenRaw: '80', locations: [{ index: '01', path: '/', proxyPass: 'http://app1:8080', upstreamGroupRaw: 'api-pool' }] }),
    candidate('app2', 'id2', { listenRaw: '8080', locations: [{ index: '01', path: '/', proxyPass: 'http://app2:8080', upstreamGroupRaw: 'api-pool' }] }),
  ];
  assert.strictEqual(tryAggregateGroup(group), null);
});
check('http_to_https_auto different entre replicas -> pas de fusion', () => {
  const group = [
    candidate('app1', 'id1', { httpToHttpsAutoRaw: 'true', locations: [{ index: '01', path: '/', proxyPass: 'http://app1:8080', upstreamGroupRaw: 'api-pool' }] }),
    candidate('app2', 'id2', { httpToHttpsAutoRaw: 'false', locations: [{ index: '01', path: '/', proxyPass: 'http://app2:8080', upstreamGroupRaw: 'api-pool' }] }),
  ];
  assert.strictEqual(tryAggregateGroup(group), null);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
