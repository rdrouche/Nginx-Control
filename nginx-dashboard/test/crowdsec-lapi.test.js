'use strict';
/**
 * Rien de ce module ne peut etre verifie contre un vrai serveur CrowdSec dans
 * cet environnement : ces tests simulent le transport HTTP et se concentrent
 * sur ce qui est verifiable sans lui — construction des requetes, mise en
 * cache du jeton, propagation fidele des erreurs du LAPI. Le format exact des
 * requetes d ecriture (bannissement, listes blanches) reste une hypothese
 * documentee dans le module ; ces tests figent le comportement attendu, pas
 * une garantie de compatibilite avec un serveur reel non teste ici.
 */
process.env.CROWDSEC_URL = 'http://crowdsec.example:8080';
process.env.CROWDSEC_MACHINE_ID = 'nginx-dashboard';
process.env.CROWDSEC_MACHINE_PASSWORD = 'secret';

const assert = require('assert');
const L = require('../lib/crowdsec-lapi');
let pass = 0, fail = 0;
const check = async (n, f) => {
  try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; }
};

/** Faux transport : enregistre les appels et rejoue des reponses programmees. */
function fakeTransport(responses) {
  const calls = [];
  const fn = async (method, endpoint, opts = {}) => {
    calls.push({ method, endpoint, body: opts.body, token: opts.token });
    const key = `${method} ${endpoint.split('?')[0]}`;
    const r = responses[key] || responses['*'];
    if (!r) throw new Error(`Reponse non programmee pour ${key}`);
    return typeof r === 'function' ? r(calls.length) : r;
  };
  fn.calls = calls;
  return fn;
}

(async () => {
console.log('\nconfiguration');
await check('machineConfigured vrai quand tout est present', () => assert.ok(L.machineConfigured()));
await check('machineConfigured faux si un identifiant manque', () => {
  const saved = process.env.CROWDSEC_MACHINE_PASSWORD;
  delete process.env.CROWDSEC_MACHINE_PASSWORD;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/crowdsec-cfg')];
  delete require.cache[require.resolve('../lib/crowdsec-lapi')];
  const L2 = require('../lib/crowdsec-lapi');
  assert.strictEqual(L2.machineConfigured(), false);
  process.env.CROWDSEC_MACHINE_PASSWORD = saved;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/crowdsec-cfg')];
  delete require.cache[require.resolve('../lib/crowdsec-lapi')];
});

console.log('\nauthentification machine');
await check('connexion reussie renvoie et met en cache le jeton', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok-1', expire: new Date(Date.now() + 3600_000).toISOString() } },
  });
  const token = await L.getMachineToken(t);
  assert.strictEqual(token, 'tok-1');
  assert.strictEqual(t.calls.length, 1);
  const token2 = await L.getMachineToken(t);
  assert.strictEqual(token2, 'tok-1');
  assert.strictEqual(t.calls.length, 1, 'le second appel ne doit pas relancer une connexion');
});
await check('un jeton expire est renouvele', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok-2', expire: new Date(Date.now() - 1000).toISOString() } },
  });
  await L.getMachineToken(t);
  await L.getMachineToken(t);
  assert.strictEqual(t.calls.length, 2, 'un jeton deja expire doit relancer une connexion a chaque fois');
});
await check('sans expiration fournie, une duree de secours est appliquee', async () => {
  L.clearTokenCache();
  const t = fakeTransport({ 'POST /v1/watchers/login': { status: 200, body: { token: 'tok-3' } } });
  const token = await L.getMachineToken(t);
  assert.strictEqual(token, 'tok-3');
});
await check('identifiants refuses -> erreur explicite, pas d exception opaque', async () => {
  L.clearTokenCache();
  const t = fakeTransport({ 'POST /v1/watchers/login': { status: 403, body: { message: 'bad credentials' } } });
  await assert.rejects(() => L.getMachineToken(t), (e) => {
    assert.ok(/login failed/i.test(e.error));
    assert.strictEqual(e.body.message, 'bad credentials');
    return true;
  });
});
await check('un 401 en cours de route force une reconnexion', async () => {
  L.clearTokenCache();
  let logins = 0;
  const t = async (method, endpoint) => {
    if (endpoint === '/v1/watchers/login') { logins++; return { status: 200, body: { token: `tok-${logins}`, expire: new Date(Date.now() + 3600_000).toISOString() } }; }
    if (endpoint.startsWith('/v1/decisions')) return logins === 1 ? { status: 401, body: {} } : { status: 200, body: { deleted: '1' } };
    throw new Error('endpoint inattendu: ' + endpoint);
  };
  const r = await L.machineRequest('DELETE', '/v1/decisions?ip=1.2.3.4', null, t);
  assert.strictEqual(logins, 2, 'le 401 doit avoir declenche une seconde connexion');
  assert.strictEqual(r.status, 200);
});

console.log('\nconversion de duree (vers le format Go attendu par CrowdSec)');
for (const [input, expected] of [['30m', '30m0s'], ['4h', '4h0m0s'], ['7d', '168h0m0s'], ['1h', '1h0m0s']])
  await check(`${input} -> ${expected}`, () => assert.strictEqual(L.toGoDuration(input), expected));
await check('format non reconnu -> null, pas d exception', () => {
  assert.strictEqual(L.toGoDuration('n importe quoi'), null);
  assert.strictEqual(L.toGoDuration(''), null);
  assert.strictEqual(L.toGoDuration('4 heures'), null);
});

console.log('\nbannissement');
await check('construit une alerte avec une decision de type ban', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'POST /v1/alerts': { status: 201, body: [1] },
  });
  const r = await L.banIp({ ip: '203.0.113.5', duration: '4h', reason: 'test' }, t);
  assert.strictEqual(r.ok, true);
  const alertCall = t.calls.find(c => c.endpoint === '/v1/alerts');
  assert.ok(alertCall, 'la requete /v1/alerts doit avoir ete emise');
  const alert = alertCall.body[0];
  assert.strictEqual(alert.source.value, '203.0.113.5');
  assert.strictEqual(alert.decisions[0].type, 'ban');
  assert.strictEqual(alert.decisions[0].duration, '4h0m0s');
  assert.strictEqual(alert.decisions[0].scope, 'Ip');
  assert.strictEqual(alertCall.token, 'tok', 'doit etre authentifie comme machine');
  assert.strictEqual(alert.leakspeed, '0s',
    'une chaine vide echoue au parsing Go d une duree et a cause un 500 en production');
  assert.ok(Array.isArray(alert.events) && alert.events.length >= 1,
    'la LAPI rejette une alerte sans "events" : "validation Failure: events in body is required"');
  assert.ok(alert.events[0].timestamp, 'chaque evenement doit porter un horodatage');
  assert.ok(Array.isArray(alert.events[0].meta), 'le modele Meta de CrowdSec est une liste de paires cle/valeur');
  assert.strictEqual(alert.remediation, true,
    'un bannissement manuel doit produire une decision appliquee, pas la valeur zero');
  assert.ok(Array.isArray(alert.labels), 'present dans le schema publie par la LAPI');
  assert.ok(Array.isArray(alert.meta), 'meta au niveau de l alerte, distinct du meta par evenement');
});
await check('duree invalide rejetee avant tout appel reseau', async () => {
  const t = fakeTransport({});
  await assert.rejects(() => L.banIp({ ip: '1.2.3.4', duration: 'demain' }, t));
  assert.strictEqual(t.calls.length, 0, 'aucun appel ne doit partir avec une duree invalide');
});
await check('ip manquante rejetee', async () => {
  const t = fakeTransport({});
  await assert.rejects(() => L.banIp({ duration: '1h' }, t));
});
await check('erreur LAPI propagee telle quelle, pas avalee', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'POST /v1/alerts': { status: 422, body: { message: 'invalid scope' } },
  });
  await assert.rejects(() => L.banIp({ ip: '1.2.3.4', duration: '1h' }, t), (e) => {
    assert.strictEqual(e.body.message, 'invalid scope');
    return true;
  });
});

console.log('\ndebannissement');
await check('suppression par identifiant de decision', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'DELETE /v1/decisions/42': { status: 200, body: { nbDeleted: '1' } },
  });
  const r = await L.unbanDecisionId(42, t);
  assert.strictEqual(r.ok, true);
});
await check('suppression par adresse (peut retirer plusieurs decisions)', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'DELETE /v1/decisions': { status: 200, body: { nbDeleted: '2' } },
  });
  const r = await L.unbanIp('203.0.113.5', t);
  assert.strictEqual(r.ok, true);
  const call = t.calls.find(c => c.method === 'DELETE');
  assert.ok(call.endpoint.includes('203.0.113.5'));
});
await check('adresse manquante rejetee sans appel reseau', async () => {
  const t = fakeTransport({});
  await assert.rejects(() => L.unbanIp(null, t));
  assert.strictEqual(t.calls.length, 0);
});

console.log('\nlistes blanches centralisees');
await check('liste des allowlists', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'GET /v1/allowlists': { status: 200, body: [{ name: 'proxies', description: 'Proxies internes' }] },
  });
  const r = await L.listAllowlists(t);
  assert.strictEqual(r[0].name, 'proxies');
});
await check('une collection sans items recupere le detail par liste (le bug signale : rien ne s affichait apres ajout)', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'GET /v1/allowlists': { status: 200, body: [{ name: 'proxies', description: 'x' }] },
    'GET /v1/allowlists/proxies': { status: 200, body: { name: 'proxies', items: [{ value: '203.0.113.0/24', description: 'siege' }] } },
  });
  const r = await L.listAllowlists(t);
  assert.deepStrictEqual(r[0].items, [{ value: '203.0.113.0/24', description: 'siege' }]);
  assert.ok(t.calls.some(c => c.endpoint === '/v1/allowlists/proxies'),
    'le detail par liste doit avoir ete recupere puisque la collection ne portait pas les items');
});
await check('une collection qui porte deja les items evite un appel redondant', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'GET /v1/allowlists': { status: 200, body: [{ name: 'proxies', items: [{ value: '9.9.9.9' }] }] },
  });
  const r = await L.listAllowlists(t);
  assert.deepStrictEqual(r[0].items, [{ value: '9.9.9.9' }]);
  assert.ok(!t.calls.some(c => c.endpoint === '/v1/allowlists/proxies'),
    'aucun appel de detail ne doit partir quand les items sont deja presents');
});
await check('un echec du detail par liste degrade sans faire echouer la liste entiere', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'GET /v1/allowlists': { status: 200, body: [{ name: 'proxies' }] },
    'GET /v1/allowlists/proxies': { status: 500, body: { message: 'oops' } },
  });
  await assert.doesNotReject(() => L.listAllowlists(t));
});
await check('creation d une liste rejetee immediatement, sans appel reseau (confirme absent du schema LAPI)', async () => {
  // Le vrai schema Swagger de la LAPI, obtenu directement d un operateur, ne
  // definit AUCUNE methode d ecriture sous /allowlists — seul GET existe. Ce
  // n etait pas une question de mauvais chemin ou de mauvais verbe a deviner :
  // la capacite n existe pas du tout. Plus d appel reseau qui se solde par un
  // 405 apres coup ; l echec est immediat et dit pourquoi.
  const t = fakeTransport({});
  await assert.rejects(() => L.createAllowlist({ name: 'proxies' }, t), (e) => {
    assert.strictEqual(e.status, 501);
    assert.ok(/cscli allowlists/.test(e.error), 'doit orienter vers cscli, la seule voie reelle');
    return true;
  });
  assert.strictEqual(t.calls.length, 0, 'aucun appel reseau ne doit partir pour une capacite qui n existe pas');
});
await check('ajout d une entree rejete immediatement, sans appel reseau', async () => {
  const t = fakeTransport({});
  await assert.rejects(() => L.addAllowlistItem({ name: 'proxies', value: '1.2.3.4' }, t), (e) => {
    assert.strictEqual(e.status, 501);
    return true;
  });
  assert.strictEqual(t.calls.length, 0);
});
await check('retrait d une entree rejete immediatement, sans appel reseau', async () => {
  const t = fakeTransport({});
  await assert.rejects(() => L.removeAllowlistItem({ name: 'proxies', value: '1.2.3.4' }, t), (e) => {
    assert.strictEqual(e.status, 501);
    return true;
  });
  assert.strictEqual(t.calls.length, 0);
});

console.log('\nverification d appartenance a une liste blanche (confirmee reelle et en lecture seule)');
await check('une adresse couverte par une liste', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'GET /v1/allowlists/check/203.0.113.5': { status: 200, body: { allowlisted: true, reason: 'proxies-internes' } },
  });
  const r = await L.checkAllowlist('203.0.113.5', t);
  assert.strictEqual(r.allowlisted, true);
  assert.strictEqual(r.reason, 'proxies-internes');
});
await check('une adresse non couverte', async () => {
  L.clearTokenCache();
  const t = fakeTransport({
    'POST /v1/watchers/login': { status: 200, body: { token: 'tok', expire: new Date(Date.now() + 3600_000).toISOString() } },
    'GET /v1/allowlists/check/9.9.9.9': { status: 200, body: { allowlisted: false } },
  });
  const r = await L.checkAllowlist('9.9.9.9', t);
  assert.strictEqual(r.allowlisted, false);
});
await check('valeur manquante rejetee sans appel reseau', async () => {
  const t = fakeTransport({});
  await assert.rejects(() => L.checkAllowlist('', t));
  assert.strictEqual(t.calls.length, 0);
});

console.log('\nregression : la consigne --auto ne doit jamais revenir');
await check('aucun texte d aide ne recommande --auto (mot de passe jamais montre a l operateur)', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'crowdsec-lapi.js'), 'utf8');
  assert.ok(!/add\s+\S+\s+--auto/.test(src), '--auto ne doit plus etre presente comme la commande a executer');
  assert.ok(/--password/.test(src), 'la consigne doit recommander un mot de passe explicite');
  assert.ok(/never .?--auto|not --auto/.test(src), 'la mise en garde explicite doit etre conservee');
});
await check('la meme regle s applique au message d erreur cote route', () => {
  // --auto peut legitimement apparaitre dans une mise en garde explicite
  // ("jamais --auto") ; ce qui compte est qu il ne soit plus jamais
  // *recommande* comme methode de creation.
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'features', 'crowdsec.js'), 'utf8');
  assert.ok(!/add\s+\S+\s+--auto/.test(src), '--auto ne doit plus etre presente comme la commande a executer');
  assert.ok(/never --auto|jamais.*--auto/.test(src), 'la mise en garde explicite doit rester presente');
});
await check('et cote interface', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'public', 'index.html'), 'utf8');
  assert.ok(!/add\s+\S+\s+--auto/.test(src));
  assert.ok(/jamais.*--auto/.test(src));
});

console.log('\nen-tete User-Agent (CrowdSec rejette une valeur vide sur /v1/watchers/login)');
await check('lapiRequest envoie toujours un User-Agent non vide', () => {
  // Node n envoie aucun User-Agent par defaut. CrowdSec journalise et, sur
  // /v1/watchers/login specifiquement, rejette une requete qui n en porte
  // pas — les lectures /v1/decisions en clef bouncer, elles, passaient malgre
  // tout, ce qui a longtemps masque le probleme.
  const http = require('http');
  const orig = http.request;
  let captured = null;
  http.request = function (opts, cb) {
    captured = opts.headers;
    return { on(){}, write(){}, end(){
      cb({ statusCode: 200, on(evt, fn){ if (evt === 'data') fn('{}'); if (evt === 'end') fn(); } });
    }};
  };
  try {
    L.lapiRequest('GET', '/v1/decisions', {});
    assert.ok(captured['User-Agent'], 'aucun User-Agent envoye');
    assert.notStrictEqual(captured['User-Agent'], '');
  } finally { http.request = orig; }
});
await check('le module identifie clairement le produit dans le User-Agent', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'crowdsec-lapi.js'), 'utf8');
  assert.ok(/User-Agent/.test(src));
  assert.ok(/nginx-dashboard/.test(src));
});
await check('la lecture en cle bouncer envoie elle aussi un User-Agent', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'features', 'crowdsec.js'), 'utf8');
  assert.ok(/'User-Agent'/.test(src));
});

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
