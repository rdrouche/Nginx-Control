'use strict';
/**
 * Hôtes Docker distants (agents, Partie 2) — routes, contre un vrai serveur.
 * Même convention que test/docker-autoconfig-routes.test.js : le socket
 * Docker n'est pas disponible dans ce bac à sable (DOCKER_SOCKET pointe vers
 * un chemin inexistant), donc un manifeste avec un vrai vhost déclenche
 * toujours un `nginx -t` qui échoue et un rollback (testFailed) — ce qui est
 * lui-même le scénario testé ici (le fichier ne doit jamais rester sur le
 * disque après ce rollback). Ce qui NE dépend PAS d'un vrai conteneur —
 * permissions, enrôlement public, émission/révocation de jeton, confinement
 * du jeton d'agent à sa seule route, validation de manifeste — est couvert
 * en entier.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentsroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agentsroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'), [
  'users:',
  '  - username: admin',
  '    password: admin123',
  '    role: admin',
  '    name: A',
  '    enabled: true',
  '  - username: viewer',
  '    password: viewer123',
  '    role: viewer',
  '    name: V',
  '    enabled: true',
].join('\n'));
// enable: false est desormais le defaut (v12.41.0, opt-in) — ce fichier
// teste le comportement de la fonctionnalite elle-meme, donc active
// explicitement, sauf pour le test dedie a la desactivation plus bas.
fs.writeFileSync(path.join(tmp, 'config', 'agents.yml'), 'enable: true\n');

const PORT = 3918, BASE = `http://127.0.0.1:${PORT}`;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip'),
  // Socket volontairement absent/invalide : le sous-systeme Docker doit
  // degrader proprement (nginx -t "echoue", rollback), jamais planter.
  DOCKER_SOCKET: path.join(tmp, 'no-such-docker.sock') };

function req(method, p, cookieOrAuth, body) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    // Content-Type: application/json toujours envoye pour une methode non-GET,
    // meme sans corps — c est ce que fait le vrai frontend (index.html#api()),
    // et depuis le correctif SEC-12, le serveur l exige desormais aussi.
    const headers = { ...(method !== 'GET' ? { 'Content-Type': 'application/json' } : {}),
                       ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) };
    if (cookieOrAuth?.bearer) headers.Authorization = `Bearer ${cookieOrAuth.bearer}`;
    else if (cookieOrAuth) headers.Cookie = cookieOrAuth;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers, timeout: 8000 }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b) }); } catch { resolve({ status: res.statusCode, body: b }); } });
    });
    r.on('error', e => resolve({ status: 0, body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
    if (data) r.write(data);
    r.end();
  });
}

function login(username, password) {
  return new Promise(resolve => {
    const params = new URLSearchParams({ username, password }).toString();
    const r = http.request({ host: '127.0.0.1', port: PORT, path: '/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(params) } },
      res => { res.resume(); resolve((res.headers['set-cookie'] || [])[0]?.split(';')[0] || ''); });
    r.write(params); r.end();
  });
}

(async () => {
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  try {
    const adminCk = await login('admin', 'admin123');
    const viewerCk = await login('viewer', 'viewer123');

    console.log('\nPOST /api/agent/enroll — public, aucune session/jeton requis');
    const enroll1 = await req('POST', '/api/agent/enroll', null, { hostname: 'vps-paris-1', fingerprint: 'sha256:deadbeef' });
    check('enrolement sans credentials -> 200, statut pending', () => {
      assert.strictEqual(enroll1.status, 200, JSON.stringify(enroll1.body));
      assert.strictEqual(enroll1.body.status, 'pending');
      assert.ok(enroll1.body.agentId);
    });
    const badHostname = await req('POST', '/api/agent/enroll', null, { hostname: 'not valid!' });
    check('hostname invalide -> 400', () => assert.strictEqual(badHostname.status, 400));
    const noHostname = await req('POST', '/api/agent/enroll', null, {});
    check('hostname absent -> 400', () => assert.strictEqual(noHostname.status, 400));

    console.log('\nGET /api/agents — permissions');
    const noSession = await req('GET', '/api/agents');
    check('sans session -> 401', () => assert.strictEqual(noSession.status, 401));
    const listAsViewer = await req('GET', '/api/agents', viewerCk);
    check('viewer (VIEW_CONFIGS) -> 200, voit l agent en attente', () => {
      assert.strictEqual(listAsViewer.status, 200);
      const a = listAsViewer.body.agents.find(x => x.id === enroll1.body.agentId);
      assert.ok(a, 'l agent enrole doit apparaitre dans la liste');
      assert.strictEqual(a.status, 'pending');
      assert.strictEqual(a.hostnameProposed, 'vps-paris-1');
      assert.strictEqual('tokenHash' in a, false, 'un hash de jeton ne doit jamais fuiter dans une reponse GET');
    });

    const agentId = enroll1.body.agentId;

    console.log('\nPOST /api/agents/<id>/approve|reject|revoke|regenerate-token — permissions + machine a etats');
    const approveAsViewer = await req('POST', `/api/agents/${agentId}/approve`, viewerCk);
    check('viewer (pas DEPLOY) -> 403 sur approve', () => assert.strictEqual(approveAsViewer.status, 403));

    const approveResp = await req('POST', `/api/agents/${agentId}/approve`, adminCk);
    check('admin (DEPLOY) -> 200, jeton emis exactement une fois', () => {
      assert.strictEqual(approveResp.status, 200, JSON.stringify(approveResp.body));
      assert.ok(approveResp.body.token && approveResp.body.token.startsWith('agt_'));
    });
    const issuedToken = approveResp.body.token;

    const reapprove = await req('POST', `/api/agents/${agentId}/approve`, adminCk);
    check('re-approuver un agent deja approuve -> 400', () => assert.strictEqual(reapprove.status, 400));

    const rejectApproved = await req('POST', `/api/agents/${agentId}/reject`, adminCk);
    check('rejeter un agent deja approuve -> 400 (revoquer plutot que rejeter)', () => assert.strictEqual(rejectApproved.status, 400));

    const unknownId = await req('POST', '/api/agents/0000000000000000/approve', adminCk);
    check('id inconnu -> 404', () => assert.strictEqual(unknownId.status, 404));

    const unknownAction = await req('POST', `/api/agents/${agentId}/frobnicate`, adminCk);
    check('action inconnue -> 404', () => assert.strictEqual(unknownAction.status, 404));

    console.log('\nPOST /api/agent/manifest — confinement du jeton d agent a sa seule route');
    const agentTokenOnAgentsRoute = await req('GET', '/api/agents', { bearer: issuedToken });
    check('le jeton d agent ne peut PAS authentifier une route reservee a la session/au token admin (ex: /api/agents)', () =>
      assert.strictEqual(agentTokenOnAgentsRoute.status, 401, 'AGENT_TOKEN_ROUTES ne couvre que /api/agent/manifest — ce jeton ne doit authentifier RIEN d autre'));

    const noAuthManifest = await req('POST', '/api/agent/manifest', null, { vhosts: [] });
    check('sans Authorization -> 401', () => assert.strictEqual(noAuthManifest.status, 401));

    const badTokenManifest = await req('POST', '/api/agent/manifest', { bearer: 'agt_ce-jeton-nexiste-pas' }, { vhosts: [] });
    check('jeton invalide -> 401', () => assert.strictEqual(badTokenManifest.status, 401));

    const emptyManifest = await req('POST', '/api/agent/manifest', { bearer: issuedToken }, { vhosts: [] });
    check('jeton valide, manifeste vide -> 200, aucun vhost', () => {
      assert.strictEqual(emptyManifest.status, 200, JSON.stringify(emptyManifest.body));
      assert.strictEqual(emptyManifest.body.ok, true);
      assert.deepStrictEqual(emptyManifest.body.vhosts, []);
    });

    const malformedManifest = await req('POST', '/api/agent/manifest', { bearer: issuedToken }, { vhosts: 'oops' });
    check('manifeste malforme (vhosts pas un tableau) -> 400, erreur explicite', () => {
      assert.strictEqual(malformedManifest.status, 400);
      assert.ok(malformedManifest.body.error);
    });

    const invalidVhostManifest = await req('POST', '/api/agent/manifest', { bearer: issuedToken },
      { vhosts: [{ serverName: '', locations: [] }] });
    check('un vhost invalide dans le manifeste est rapporte, jamais un plantage', () => {
      assert.strictEqual(invalidVhostManifest.status, 200);
      assert.strictEqual(invalidVhostManifest.body.vhosts.length, 1);
      assert.strictEqual(invalidVhostManifest.body.vhosts[0].ok, false);
      assert.ok(invalidVhostManifest.body.vhosts[0].errors.length > 0);
    });

    const validVhostManifest = await req('POST', '/api/agent/manifest', { bearer: issuedToken }, {
      vhosts: [{ serverName: 'app.example.com', locations: [{ path: '/', target: 'http://203.0.113.10:8080' }] }],
    });
    check('un vhost valide, sans docker reel -> nginx -t echoue -> rollback (testFailed), rien ne reste sur le disque', () => {
      assert.strictEqual(validVhostManifest.body.testFailed, true, JSON.stringify(validVhostManifest.body));
      const files = fs.readdirSync(path.join(tmp, 'sites'));
      assert.deepStrictEqual(files.filter(f => f.startsWith('agent_')), [], 'un rollback doit laisser sites/ exactement comme avant');
    });

    console.log('\nPOST /api/agent/manifest — protocolVersion, metrics, mode "tunnel"');
    const badProtocolVersion = await req('POST', '/api/agent/manifest', { bearer: issuedToken }, { vhosts: [], protocolVersion: 99 });
    check('protocolVersion non supportee -> 400, erreur explicite listant les versions connues', () => {
      assert.strictEqual(badProtocolVersion.status, 400, JSON.stringify(badProtocolVersion.body));
      assert.ok(/protocolVersion/.test(badProtocolVersion.body.error));
    });

    const withMetrics = await req('POST', '/api/agent/manifest', { bearer: issuedToken },
      { vhosts: [], metrics: { cpuPercent: 12.5, memPercent: 40, uptimeSec: 7200 } });
    check('manifeste avec metriques hote -> accepte', () => {
      assert.strictEqual(withMetrics.status, 200, JSON.stringify(withMetrics.body));
    });
    const listAfterMetrics = await req('GET', '/api/agents', adminCk);
    check('les metriques poussees apparaissent sur GET /api/agents', () => {
      const a = listAfterMetrics.body.agents.find(x => x.id === agentId);
      assert.deepStrictEqual(a.metrics, { cpuPercent: 12.5, memPercent: 40, uptimeSec: 7200 });
      assert.ok(a.metricsAt > 0);
    });

    const tunnelManifest = await req('POST', '/api/agent/manifest', { bearer: issuedToken }, {
      vhosts: [{ serverName: 'tunnel-app.example.com', mode: 'tunnel',
        locations: [{ path: '/', target: 'http://127.0.0.1:8080' }] }],
    });
    check('vhost mode="tunnel" -> valide cote manifeste (l echec nginx -t vient de l absence de docker reel, pas de la validation)', () => {
      assert.strictEqual(tunnelManifest.body.vhosts.length, 1, JSON.stringify(tunnelManifest.body));
      assert.strictEqual(tunnelManifest.body.vhosts[0].ok, true, JSON.stringify(tunnelManifest.body.vhosts[0]));
      assert.strictEqual(tunnelManifest.body.testFailed, true);
      const files = fs.readdirSync(path.join(tmp, 'sites'));
      assert.deepStrictEqual(files.filter(f => f.startsWith('agent_')), [], 'rollback : rien ne doit rester sur le disque');
    });

    console.log('\nPOST /api/agent/manifest — mode "relay"');
    const relayManifestOk = await req('POST', '/api/agent/manifest', { bearer: issuedToken }, {
      vhosts: [{ serverName: 'relay-app.example.com', mode: 'relay',
        locations: [{ path: '/', target: 'http://127.0.0.1:8080' }] }],
      relay: { http: 'http://10.0.5.9:8443' },
    });
    check('vhost mode="relay" + relay.http fourni -> valide cote manifeste', () => {
      assert.strictEqual(relayManifestOk.body.vhosts.length, 1, JSON.stringify(relayManifestOk.body));
      assert.strictEqual(relayManifestOk.body.vhosts[0].ok, true, JSON.stringify(relayManifestOk.body.vhosts[0]));
    });

    const relayManifestMissingTarget = await req('POST', '/api/agent/manifest', { bearer: issuedToken }, {
      vhosts: [{ serverName: 'relay-app2.example.com', mode: 'relay', relayScheme: 'https',
        locations: [{ path: '/', target: 'http://127.0.0.1:8080' }] }],
      relay: { http: 'http://10.0.5.9:8443' },
    });
    check('vhost mode="relay" (https) mais relay.https absent -> ce vhost seul est rejete (200 global, vhost ok:false)', () => {
      assert.strictEqual(relayManifestMissingTarget.status, 200, JSON.stringify(relayManifestMissingTarget.body));
      assert.strictEqual(relayManifestMissingTarget.body.vhosts.length, 1);
      assert.strictEqual(relayManifestMissingTarget.body.vhosts[0].ok, false);
      assert.ok(/relay\.https/.test(relayManifestMissingTarget.body.vhosts[0].errors.join(' ')));
    });

    console.log('\nPOST /api/agents/<id>/vhosts/pause|resume — pause par vhost (v12.36.0)');
    const enrollPause = await req('POST', '/api/agent/enroll', null, { hostname: 'vps-lyon-2' });
    const pauseAgentId = enrollPause.body.agentId;
    const approvePause = await req('POST', `/api/agents/${pauseAgentId}/approve`, adminCk);
    const pauseToken = approvePause.body.token;

    const pauseAsViewer = await req('POST', `/api/agents/${pauseAgentId}/vhosts/pause`, viewerCk, { serverNames: ['app.example.com'] });
    check('viewer (pas DEPLOY) -> 403 sur pause', () => assert.strictEqual(pauseAsViewer.status, 403));

    const pauseNoNames = await req('POST', `/api/agents/${pauseAgentId}/vhosts/pause`, adminCk, {});
    check('serverNames absent -> 400', () => assert.strictEqual(pauseNoNames.status, 400));

    const pauseUnknownAgent = await req('POST', '/api/agents/0000000000000000/vhosts/pause', adminCk, { serverNames: ['app.example.com'] });
    check('agent inconnu -> 404', () => assert.strictEqual(pauseUnknownAgent.status, 404));

    const resumeNotPaused = await req('POST', `/api/agents/${pauseAgentId}/vhosts/resume`, adminCk, { serverNames: ['app.example.com'] });
    check("resume() sans pause existante -> 400", () => assert.strictEqual(resumeNotPaused.status, 400));

    const pauseAhead = await req('POST', `/api/agents/${pauseAgentId}/vhosts/pause`, adminCk, { serverNames: ['app.example.com'] });
    check('pause posee "a l avance" (vhost jamais encore publie) -> 200, acceptee', () => {
      assert.strictEqual(pauseAhead.status, 200, JSON.stringify(pauseAhead.body));
      assert.strictEqual(pauseAhead.body.ok, true);
      const v = pauseAhead.body.vhosts.find(x => x.decisionKey === 'app.example.com');
      assert.ok(v, JSON.stringify(pauseAhead.body.vhosts));
      assert.strictEqual(v.paused, true);
      assert.strictEqual(v.inLastManifest, false, 'jamais vu dans un manifeste -> pas dans lastVhosts');
      assert.strictEqual(pauseAhead.body.apply.skipped, true, "aucun lastManifestBody encore -> rien a reappliquer");
    });

    const listShowsPaused = await req('GET', '/api/agents', adminCk);
    check('GET /api/agents expose la decision de pause pour cet agent', () => {
      const a = listShowsPaused.body.agents.find(x => x.id === pauseAgentId);
      assert.ok(a.vhosts.find(v => v.decisionKey === 'app.example.com' && v.paused === true));
    });

    const manifestWithPausedVhost = await req('POST', '/api/agent/manifest', { bearer: pauseToken }, {
      vhosts: [{ serverName: 'app.example.com', locations: [{ path: '/', target: 'http://203.0.113.20:8080' }] }],
    });
    check('un vhost en pause est exclu de la publication : ok:true, paused:true, sans passer par nginx -t', () => {
      assert.strictEqual(manifestWithPausedVhost.status, 200, JSON.stringify(manifestWithPausedVhost.body));
      assert.strictEqual(manifestWithPausedVhost.body.ok, true);
      assert.strictEqual(manifestWithPausedVhost.body.testFailed, undefined, 'exclu avant meme d ecrire un fichier -> jamais de nginx -t');
      assert.strictEqual(manifestWithPausedVhost.body.vhosts.length, 1);
      assert.strictEqual(manifestWithPausedVhost.body.vhosts[0].ok, true);
      assert.strictEqual(manifestWithPausedVhost.body.vhosts[0].paused, true);
      const files = fs.readdirSync(path.join(tmp, 'sites'));
      assert.deepStrictEqual(files.filter(f => f.startsWith('agent_')), [], 'rien ne doit etre ecrit pour un vhost en pause');
    });

    const listStillNotInLastVhosts = await req('GET', '/api/agents', adminCk);
    check('un vhost en pause n apparait pas dans lastVhosts (jamais applique)', () => {
      const a = listStillNotInLastVhosts.body.agents.find(x => x.id === pauseAgentId);
      assert.deepStrictEqual(a.lastVhosts, []);
      const v = a.vhosts.find(x => x.decisionKey === 'app.example.com');
      assert.strictEqual(v.paused, true);
      assert.strictEqual(v.inLastManifest, false);
    });

    const resumeAsViewer = await req('POST', `/api/agents/${pauseAgentId}/vhosts/resume`, viewerCk, { serverNames: ['app.example.com'] });
    check('viewer (pas DEPLOY) -> 403 sur resume', () => assert.strictEqual(resumeAsViewer.status, 403));

    const resumeOk = await req('POST', `/api/agents/${pauseAgentId}/vhosts/resume`, adminCk, { serverNames: ['app.example.com'] });
    check('resume() republie immediatement (memem manifeste que la derniere fois) -> tente un vrai apply -> testFailed en sandbox (pas de vrai nginx)', () => {
      assert.strictEqual(resumeOk.status, 200, JSON.stringify(resumeOk.body));
      assert.strictEqual(resumeOk.body.ok, true, 'l action resume elle-meme a reussi (la decision est bien levee)');
      assert.strictEqual(resumeOk.body.apply.testFailed, true, 'le vhost redevient eligible -> vraie tentative d ecriture -> echoue faute de docker reel, comme partout ailleurs dans ce fichier');
      // La pause a bien ete levee (plus aucune decision enregistree) ; comme
      // le vrai apply a echoue (pas de nginx reel dans ce bac a sable), le
      // vhost n a pas non plus rejoint lastVhosts — il n apparait donc plus
      // du tout dans la vue fusionnee, ce qui est le comportement correct
      // (ni en pause, ni publie).
      const v = resumeOk.body.vhosts.find(x => x.decisionKey === 'app.example.com');
      assert.ok(!v || v.paused === false, JSON.stringify(v));
    });

    const resumeAgainNotPaused = await req('POST', `/api/agents/${pauseAgentId}/vhosts/resume`, adminCk, { serverNames: ['app.example.com'] });
    check('resume() une seconde fois (deja repris) -> 400', () => assert.strictEqual(resumeAgainNotPaused.status, 400));

    console.log('\nDELETE /api/agents/<id> — uniquement pour un agent non-approuve');
    const deleteApproved = await req('DELETE', `/api/agents/${agentId}`, adminCk);
    check("un agent 'approved' ne peut pas etre supprime sans revocation prealable -> 400", () => assert.strictEqual(deleteApproved.status, 400));

    const revokeResp = await req('POST', `/api/agents/${agentId}/revoke`, adminCk);
    const pushAfterRevoke = await req('POST', '/api/agent/manifest', { bearer: issuedToken }, { vhosts: [] });
    check("revoke() -> le jeton cesse d authentifier immediatement", () => {
      assert.strictEqual(revokeResp.status, 200, JSON.stringify(revokeResp.body));
      assert.strictEqual(pushAfterRevoke.status, 401);
    });

    const deleteAfterRevoke = await req('DELETE', `/api/agents/${agentId}`, adminCk);
    const listAfterDelete = await req('GET', '/api/agents', viewerCk);
    check("un agent revoque peut ensuite etre supprime du registre", () => {
      assert.strictEqual(deleteAfterRevoke.status, 200);
      assert.ok(!listAfterDelete.body.agents.find(a => a.id === agentId));
    });

    console.log('\nEnrolement desactive (config/agents.yml: enable: false)');
    fs.writeFileSync(path.join(tmp, 'config', 'agents.yml'), 'enable: false\n');
    const enrollDisabled = await req('POST', '/api/agent/enroll', null, { hostname: 'vps-x' });
    check('enroll refuse quand agents.yml a enable:false', () => assert.strictEqual(enrollDisabled.status, 403));
    fs.rmSync(path.join(tmp, 'config', 'agents.yml'));

  } finally {
    srv.kill();
    await new Promise(r => setTimeout(r, 300));
  }

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
