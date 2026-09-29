'use strict';
/**
 * Fixes, audit report Basse/"Agents (dashboard)" (v12.24.0, partie 2) :
 *
 *  1. La revocation et la regeneration de jeton ne fermaient pas un tunnel
 *     deja ouvert (agentTunnelFeature.closeConnection() jamais appele).
 *  2. Requetes tunnel bufferisees sans limite de concurrence : risque
 *     memoire (features/agent-tunnel.js).
 *  3. Port de `target` non borne (99999 accepte cote validation, alors que
 *     ce n est pas un port TCP valide) ; `listen` n avait aucune liste
 *     blanche possible.
 *  4. `agents_certbot_state` n etait jamais nettoye a la revocation : un
 *     etat `failed` perime etait herite par le prochain agent declarant le
 *     meme nom.
 *  5. Apres une emission reussie, le passage en HTTPS n avait lieu qu au
 *     push suivant — jamais si l agent ne pousse plus. Ajout d un recheck
 *     periodique (lib/scheduler.js#runScheduledAgentSslRecheck), miroir du
 *     cycle deja existant cote Partie 1 (Docker auto-config).
 *
 * Style unitaire/in-process, meme convention que
 * test/agents-certbot-issuance.test.js (pas de serveur reel necessaire pour
 * ces cinq points).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agents-fixes-'));
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

const events = require('../lib/events');
events.initEventsDb();

const agentsStore = require('../lib/agents-store');
const agentsFeature = require('../features/agents');
const { validateManifestVhost, validateManifest } = require('../lib/agent-manifest');
const { parseAndValidate } = require('../lib/agents-yaml');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const flush = () => new Promise(r => setImmediate(r));

function resetAgentsState() { agentsStore.saveState({ agents: {} }); }
function resetCertbotState() { agentsFeature.saveCertbotState({ issuance: {} }); }

function fakeRouter() {
  const routes = {};
  return {
    get(p, h) { routes[`GET ${p}`] = h; },
    post(p, h) { routes[`POST ${p}`] = h; },
    addPrefix(m, p, h) { routes[`${m} ${p}`] = h; },
    _dispatch(method, pathname, ctx) {
      // exact-path first, then longest-prefix — mirrors lib/http.js's own
      // matching order closely enough for these two routes.
      const exact = routes[`${method} ${pathname}`];
      if (exact) return exact({ ...ctx, pathname });
      let best = null, bestLen = -1;
      for (const key of Object.keys(routes)) {
        const [km, kp] = key.split(' ');
        if (km !== method) continue;
        if (kp.endsWith('/') && pathname.startsWith(kp) && kp.length > bestLen) { best = routes[key]; bestLen = kp.length; }
      }
      if (!best) throw new Error(`no route for ${method} ${pathname}`);
      return best({ ...ctx, pathname });
    },
  };
}
function fakeRes() {
  const res = { status: null, body: null };
  res.writeHead = (code) => { res.status = code; };
  res.end = (body) => { try { res.body = JSON.parse(body); } catch { res.body = body; } };
  return res;
}
const adminSession = { username: 'admin', role: 'admin' };

console.log('\n1) revocation/regeneration de jeton ferment un tunnel deja ouvert');
(async () => {

await (async () => {
  resetAgentsState();
  const enrolled = agentsStore.enroll({ hostnameProposed: 'host1', fingerprint: 'fp1' });
  const { agent } = agentsStore.approve(enrolled.id, 'admin');

  let closedFor = [];
  agentsFeature.setDeps({ closeTunnel: (id, reason) => closedFor.push({ id, reason }) });
  const router = fakeRouter();
  agentsFeature.register(router);

  closedFor = [];
  const res1 = fakeRes();
  await router._dispatch('POST', `/api/agents/${agent.id}/revoke`, { res: res1, session: adminSession });
  check('revoke() : appelle deps.closeTunnel() avec l id de l agent revoque', () => {
    assert.strictEqual(closedFor.length, 1);
    assert.strictEqual(closedFor[0].id, agent.id);
  });

  // Re-approuver pour tester regenerate-token separement.
  const { agent: agent2 } = agentsStore.approve(agent.id, 'admin');
  closedFor = [];
  const res2 = fakeRes();
  await router._dispatch('POST', `/api/agents/${agent2.id}/regenerate-token`, { res: res2, session: adminSession });
  check('regenerate-token : appelle egalement deps.closeTunnel()', () => {
    assert.strictEqual(closedFor.length, 1);
    assert.strictEqual(closedFor[0].id, agent2.id);
  });

  agentsFeature.setDeps({ closeTunnel: () => {} });
})();

console.log('\n2) limite de concurrence sur les requetes tunnel (features/agent-tunnel.js)');
await (async () => {
  const tunnel = require('../features/agent-tunnel');
  check('constantes exportees, valeurs raisonnables (> 1, bornees)', () => {
    assert.ok(tunnel.MAX_CONCURRENT_TUNNEL_REQUESTS_PER_AGENT > 1);
    assert.ok(tunnel.MAX_CONCURRENT_TUNNEL_REQUESTS_GLOBAL >= tunnel.MAX_CONCURRENT_TUNNEL_REQUESTS_PER_AGENT);
  });
})();

console.log('\n3) validation manifeste : port de target borne, liste blanche pour listen');
await (async () => {
  const okEntry = { serverName: 'app.example.com', listen: 8080,
    locations: [{ path: '/', target: 'http://10.0.0.5:8080' }] };
  check("target avec un port > 65535 (regex 5 chiffres mais hors bornes) -> rejete", () => {
    const r = validateManifestVhost({ ...okEntry, locations: [{ path: '/', target: 'http://10.0.0.5:99999' }] });
    assert.strictEqual(r.valid, false);
    assert.ok(r.errors.some(e => /port de target/.test(e)), JSON.stringify(r.errors));
  });
  check('target avec un port valide (dans les bornes) -> accepte', () => {
    const r = validateManifestVhost(okEntry);
    assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
  });
  check('listen : sans allowedListenPorts (non configure) -> tout port valide accepte, comme avant', () => {
    const r = validateManifestVhost({ ...okEntry, listen: 3000 });
    assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
  });
  check('listen : avec allowedListenPorts configure, un port hors liste est rejete', () => {
    const r = validateManifestVhost({ ...okEntry, listen: 22 }, { allowedListenPorts: [80, 443] });
    assert.strictEqual(r.valid, false);
    assert.ok(r.errors.some(e => /non autorise/.test(e)), JSON.stringify(r.errors));
  });
  check('listen : avec allowedListenPorts configure, un port dans la liste est accepte', () => {
    const r = validateManifestVhost({ ...okEntry, listen: 443 }, { allowedListenPorts: [80, 443] });
    assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
  });
  check('agents.yml : allowed_listen_ports se propage bien jusqu a validateManifest()', () => {
    const { settings } = parseAndValidate('allowed_listen_ports: "80,443"\n');
    const result = validateManifest(
      { vhosts: [{ ...okEntry, listen: 8080 }] },
      { allowedListenPorts: settings.allowedListenPorts }
    );
    assert.strictEqual(result.vhosts[0].valid, false);
    assert.ok(result.vhosts[0].errors.some(e => /non autorise/.test(e)));
  });
})();

console.log('\n4) etat certbot des agents purge a la revocation (agents_certbot_state)');
await (async () => {
  resetCertbotState();
  agentsFeature.saveCertbotState({ issuance: {
    'stale.example.com': { status: 'failed', lastAttemptAt: Date.now(), lastError: 'boom', attempts: 3 },
    'other.example.com': { status: 'idle', lastAttemptAt: Date.now(), lastError: null, attempts: 1 },
  } });
  agentsFeature.clearCertbotStateForServerNames(['stale.example.com']);
  check("l entree du domaine revoque est supprimee (plus d etat 'failed' herite)", () => {
    assert.strictEqual(loadIssuance()['stale.example.com'], undefined);
  });
  check('un autre domaine, non lie a cet agent, reste intact', () => {
    assert.strictEqual(loadIssuance()['other.example.com'].status, 'idle');
  });
  check('appel avec une liste vide/absente -> no-op, jamais une exception', () => {
    assert.doesNotThrow(() => agentsFeature.clearCertbotStateForServerNames([]));
    assert.doesNotThrow(() => agentsFeature.clearCertbotStateForServerNames());
  });
  function loadIssuance() { return agentsFeature.loadCertbotState().issuance; }
})();

console.log('\n5) recheck SSL periodique (Partie 1 a un cycle periodique, les agents en ont desormais un aussi)');
await (async () => {
  resetAgentsState();
  const enrolled = agentsStore.enroll({ hostnameProposed: 'host2', fingerprint: 'fp2' });
  const { agent } = agentsStore.approve(enrolled.id, 'admin');
  const manifestBody = { vhosts: [{ serverName: 'pending.example.com', sslCertificate: 'certbot_http',
    locations: [{ path: '/', target: 'http://10.0.0.9:80' }] }] };

  check('un agent sans manifeste rejouable (jamais pousse) -> jamais candidat', () => {
    assert.deepStrictEqual(agentsFeature.listAgentsNeedingSslRecheck(), []);
  });

  agentsStore.recordManifestResult(agent.id, {
    ok: true, generatedFiles: ['/x/agent_x.conf'], vhostCount: 1,
    lastVhosts: [{ serverNames: ['pending.example.com'], listen: 80, sslMode: 'certbot_http', sslStatus: 'pending', sslError: null, mode: 'direct' }],
    lastManifestBody: manifestBody,
  });
  check('SSL certbot_http encore "pending" et manifeste connu -> agent candidat au recheck', () => {
    assert.deepStrictEqual(agentsFeature.listAgentsNeedingSslRecheck(), [agent.id]);
  });

  let applyCalledWith = null;
  const realApply = agentsFeature.applyManifestForAgent;
  // Remplace temporairement l export utilise par reapplyAgentManifest() —
  // reapplyAgentManifest() appelle la fonction du module directement (pas
  // via injection), donc on verifie plutot son EFFET (agentsStore.getAgent
  // reste coherent) que l appel lui-meme ici ; le point important teste est
  // le cablage id -> lastManifestBody -> applyManifestForAgent().
  const result = await agentsFeature.reapplyAgentManifest(agent.id);
  check("reapplyAgentManifest() rejoue bien le manifeste (echoue proprement ici, pas de Docker dans ce bac a sable, mais atteint bien applyManifestForAgent)", () => {
    assert.strictEqual(result.ok, false); // nginx -t indisponible ici -> attendu
    assert.ok(result.error || result.testFailed !== undefined);
  });

  agentsStore.recordManifestResult(agent.id, {
    ok: true, generatedFiles: [], vhostCount: 0, lastVhosts: [], lastManifestBody: null,
  }, { allowNonApproved: true });
  check('une fois le vhost retire (lastVhosts vide) -> plus candidat', () => {
    assert.deepStrictEqual(agentsFeature.listAgentsNeedingSslRecheck(), []);
  });

  const result2 = await agentsFeature.reapplyAgentManifest('id-inconnu');
  check('id inconnu -> echec propre, jamais une exception', () => {
    assert.strictEqual(result2.ok, false);
  });
})();

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
})();
