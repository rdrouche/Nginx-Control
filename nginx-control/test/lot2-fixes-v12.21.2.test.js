'use strict';
/**
 * Regression tests for Lot 2 of the v12.21.0 audit (rapport-bugs-v12.21.0.md):
 * DAC-01 through DAC-10, AGT-01, AGT-05, MISC-08. Each block is named after
 * the finding it covers. Mirrors the structure/conventions of
 * test/security-fixes-v12.21.1.test.js (Lot 1) and
 * test/docker-autoconfig-certbot-issuance.test.js (fresh CONFIG_DIR +
 * events.initEventsDb()). Everything runs sequentially inside one top-level
 * async IIFE so the final pass/fail tally can never print before an
 * asynchronous block (certbot issuance, the write-lock) has settled.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lot2-'));
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

const events = require('../lib/events');
events.initEventsDb();

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const flush = () => new Promise(r => setImmediate(r));

(async () => {

// ─── DAC-04 — lib/certs.js checkDomainConflict() ───────────────────────────
console.log('\nDAC-04 — checkDomainConflict() : wildcard un seul niveau, casse, certificats expires');
{
  const certsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lot2-certs-'));
  const liveDir = path.join(certsDir, 'live');
  const { execFileSync } = require('child_process');

  function makeCert(name, { days = 90, cn, san }) {
    const dir = path.join(liveDir, name);
    fs.mkdirSync(dir, { recursive: true });
    const keyFile = path.join(dir, 'privkey.pem');
    const certFile = path.join(dir, 'cert.pem');
    const csrFile = path.join(dir, 'req.csr');
    const cnfFile = path.join(dir, 'req.cnf');
    fs.writeFileSync(cnfFile, [
      '[req]', 'distinguished_name=dn', 'req_extensions=ext', 'prompt=no',
      '[dn]', `CN=${cn}`,
      '[ext]', `subjectAltName=${san}`,
    ].join('\n'));
    execFileSync('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyFile, '-out', csrFile, '-config', cnfFile], { stdio: 'pipe' });
    // `-days` a une valeur negative (certificat deja expire, pour DAC-04)
    // n'est accepte que par `x509 -req` (une re-signature du CSR), jamais
    // par `req -x509` directement — d'ou les deux etapes.
    execFileSync('openssl', ['x509', '-req', '-in', csrFile, '-signkey', keyFile,
      '-out', certFile, '-days', String(days), '-extfile', cnfFile, '-extensions', 'ext'], { stdio: 'pipe' });
  }

  let opensslAvailable = true;
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); } catch { opensslAvailable = false; }

  if (!opensslAvailable) {
    console.log('  (openssl indisponible dans ce bac a sable — bloc DAC-04 ignore)');
  } else {
    // CN deliberately unrelated to the wildcard's own base domain — a CN
    // equal to "wild.example.com" would ALSO be picked up as its own exact
    // SAN-equivalent entry (some tooling echoes it there), which would make
    // the "wildcard does not cover its own base domain" assertion below
    // pass for the wrong reason.
    makeCert('wild.example.com', { cn: 'unrelated-cn.example.net', san: 'DNS:*.wild.example.com' });
    makeCert('exact.example.com', { cn: 'exact.example.com', san: 'DNS:Exact.Example.com' }); // mixed case on purpose
    makeCert('expired.example.com', { days: -1, cn: 'expired.example.com', san: 'DNS:expired.example.com' });

    const prevDirCerts = process.env.DIR_CERTS;
    process.env.DIR_CERTS = certsDir;
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../lib/certs')];
    const certs = require('../lib/certs');

    check('*.wild.example.com couvre a.wild.example.com (un niveau)', () => {
      assert.strictEqual(certs.checkDomainConflict('a.wild.example.com').conflict, true);
    });
    check('*.wild.example.com NE couvre PAS wild.example.com lui-meme', () => {
      assert.strictEqual(certs.checkDomainConflict('wild.example.com').conflict, false);
    });
    check('*.wild.example.com NE couvre PAS a.b.wild.example.com (deux niveaux)', () => {
      assert.strictEqual(certs.checkDomainConflict('a.b.wild.example.com').conflict, false);
    });
    check('comparaison insensible a la casse (SAN "Exact.Example.com" vs recherche minuscule)', () => {
      assert.strictEqual(certs.checkDomainConflict('exact.example.com').conflict, true);
    });
    check('un certificat EXPIRE est ignore', () => {
      assert.strictEqual(certs.checkDomainConflict('expired.example.com').conflict, false);
    });
    check('allNames : toutes les server_names doivent etre couvertes par le MEME certificat', () => {
      assert.strictEqual(certs.checkDomainConflict('a.wild.example.com', { allNames: ['a.wild.example.com', 'b.wild.example.com'] }).conflict, true);
      assert.strictEqual(certs.checkDomainConflict('a.wild.example.com', { allNames: ['a.wild.example.com', 'unrelated.example.org'] }).conflict, false);
    });

    process.env.DIR_CERTS = prevDirCerts;
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../lib/certs')];
    fs.rmSync(certsDir, { recursive: true, force: true });
  }
}

// ─── DAC-02 — noms de fichiers sans collision ──────────────────────────────
console.log('\nDAC-02 — dockerVhostFileName()/agentVhostFileName() : plus de collisions');
{
  const { dockerVhostFileName } = require('../lib/docker-autoconfig');
  const { agentVhostFileName } = require('../lib/agent-manifest');
  check('docker: *.example.com et example.com donnent des fichiers differents', () => {
    assert.notStrictEqual(dockerVhostFileName(['*.example.com']), dockerVhostFileName(['example.com']));
  });
  check('docker: a-b.example.com et a.b.example.com donnent des fichiers differents', () => {
    assert.notStrictEqual(dockerVhostFileName(['a-b.example.com']), dockerVhostFileName(['a.b.example.com']));
  });
  check('docker: stable (insensible a la casse)', () => {
    assert.strictEqual(dockerVhostFileName(['App.Example.com']), dockerVhostFileName(['app.example.com']));
  });
  check('agent: memes garanties, prefixe par agent_<id>_', () => {
    const a = agentVhostFileName('abc', ['a-b.example.com']);
    const b = agentVhostFileName('abc', ['a.b.example.com']);
    assert.notStrictEqual(a, b);
    assert.match(a, /^agent_abc_/);
  });
}

// ─── DAC-09 (partiel) — locations dupliquees rejetees a la validation ──────
console.log('\nDAC-09 — deux locations au meme chemin sont rejetees (jamais un nginx -t casse pour tout le lot)');
{
  const { validateDesiredVhost } = require('../lib/docker-autoconfig');
  const desired = {
    serverNameRaw: 'app.example.com', networkRaw: '', listenRaw: '',
    sslModeRaw: 'none', sslSnippetRaw: '', httpToHttpsAutoRaw: '',
    serverSnippets: [], monitor: {}, diagnostic: {}, analyze: {},
    locations: [
      { index: '1', path: '/', proxyPassRaw: 'http://backend:80', monitorIgnoreRaw: '', snippets: [], upstreamGroupRaw: '' },
      { index: '2', path: '/', proxyPassRaw: 'http://backend2:80', monitorIgnoreRaw: '', snippets: [], upstreamGroupRaw: '' },
    ],
  };
  const r = validateDesiredVhost(desired, { nginxNetworks: [] });
  check('deux locations "/" -> invalide, avec un message explicite', () => {
    assert.strictEqual(r.valid, false);
    assert.ok(r.errors.some(e => /meme chemin/.test(e)), r.errors.join('; '));
  });

  const { validateManifestVhost } = require('../lib/agent-manifest');
  const v = validateManifestVhost({
    serverName: 'app.example.com', mode: 'direct',
    locations: [
      { path: '/', target: 'http://10.0.0.1:80' },
      { path: '/', target: 'http://10.0.0.2:80' },
    ],
  });
  check('agents: meme garde-fou', () => {
    assert.strictEqual(v.valid, false);
    assert.ok(v.errors.some(e => /meme chemin/.test(e)), v.errors.join('; '));
  });
}

// ─── AGT-05 — casse normalisee a la validation ─────────────────────────────
console.log('\nAGT-05 — server_names normalises en minuscules a la validation');
{
  const { validateManifestVhost } = require('../lib/agent-manifest');
  const v = validateManifestVhost({
    serverName: 'App.Example.com', mode: 'direct',
    locations: [{ path: '/', target: 'http://10.0.0.1:80' }],
  });
  check('serverNames[0] est deja en minuscules apres validation', () => {
    assert.strictEqual(v.serverNames[0], 'app.example.com');
  });
}

// ─── AGT-01 — sslIsLive exclut 'error' (pas seulement 'pending') ───────────
console.log("\nAGT-01 — generateAgentVhostContent() : sslResolved.type='error' ne produit jamais `listen ... ssl` sans certificat");
{
  const { validateManifestVhost, generateAgentVhostContent } = require('../lib/agent-manifest');
  const v = validateManifestVhost({
    serverName: 'app.example.com', mode: 'direct', sslCertificate: 'certbot_http',
    locations: [{ path: '/', target: 'http://10.0.0.1:80' }],
  });
  const content = generateAgentVhostContent(v, v.serverNames, v.listen, {
    agentId: 'abc', agentName: 'vps-1',
    sslResolved: { type: 'error', code: 'certbot_http_disabled', message: 'Certbot non active' },
  });
  check("aucune ligne `listen ... ssl` quand sslResolved.type === 'error'", () => {
    assert.ok(!/listen\s+\d+\s+ssl/.test(content), content);
  });
  check('le message d erreur est visible en tete du fichier genere', () => {
    assert.ok(content.includes('Certbot non active'), content);
  });
}

// ─── DAC-03 — approbation liee a l ensemble exact des server_names ─────────
console.log('\nDAC-03 — namesDecisionKey() : une decision ne s applique qu au SET EXACT de noms');
{
  const { namesDecisionKey } = require('../features/docker-autoconfig');
  check('ordre indifferent, casse indifferente', () => {
    assert.strictEqual(namesDecisionKey(['B.example.com', 'a.example.com']), namesDecisionKey(['a.example.com', 'b.example.com']));
  });
  check('un sous-ensemble donne une cle DIFFERENTE (approuver un nom ne doit jamais approuver un autre nom)', () => {
    assert.notStrictEqual(namesDecisionKey(['a.example.com']), namesDecisionKey(['a.example.com', 'b.example.com']));
  });
}

// ─── DAC-07 — retry sur 'failed', et 'issuing' bloque traite comme echec ──
console.log("\nDAC-07 — un 'issuing' bloque (redemarrage) redevient 'failed' et peut etre retente");
{
  const { triggerCertbotIssuanceIfDue, setDeps } = require('../features/docker-autoconfig');
  const STATE_KEY = 'docker_autoconfig_state';
  const loadState = () => ({ decisions: {}, generatedFiles: {}, ...(events.getState(STATE_KEY) || {}) });

  events.setState(STATE_KEY, { decisions: {}, generatedFiles: {},
    issuance: { 'stuck.example.com': { status: 'issuing', lastAttemptAt: Date.now() - 20 * 60_000, attempts: 1 } } });
  let calls = 0;
  setDeps({ issueHttp: async () => { calls++; return { ok: true }; }, issueDns: async () => ({ ok: true }) });
  triggerCertbotIssuanceIfDue('stuck.example.com', 'certbot_http', ['stuck.example.com'], loadState(), 15);
  await flush();
  check("un 'issuing' bloque depuis plus de 10 minutes redevient 'failed' et autorise une nouvelle tentative", () => {
    assert.strictEqual(calls, 1);
  });
  setDeps({ issueHttp: async () => ({ ok: true }), issueDns: async () => ({ ok: true }) });
}

// ─── DAC-05 — mutex global (lib/nginx-write-lock.js) ───────────────────────
console.log('\nDAC-05 — withLock() : exclusion mutuelle + une seule execution "coalescee"');
{
  const { withLock } = require('../lib/nginx-write-lock');
  let running = 0, maxConcurrent = 0, runs = 0;
  const job = async () => {
    running++; runs++;
    maxConcurrent = Math.max(maxConcurrent, running);
    await new Promise(r => setTimeout(r, 20));
    running--;
    return runs;
  };
  const p1 = withLock(job);
  const p2 = withLock(job); // demande pendant que p1 tourne -> coalescee
  const p3 = withLock(job); // demande pendant que p1 tourne aussi -> MEME slot que p2
  const results = await Promise.all([p1, p2, p3]);
  check('jamais deux jobs en meme temps', () => assert.strictEqual(maxConcurrent, 1));
  check('au plus DEUX executions au total pour trois demandes concurrentes (1 en cours + 1 coalescee)', () => {
    assert.strictEqual(runs, 2);
  });
  check('p2 et p3 recoivent bien le resultat de la MEME execution coalescee', () => {
    assert.strictEqual(results[1], results[2]);
  });
  const p4 = await withLock(job);
  check('une demande apres resolution complete s execute normalement', () => assert.strictEqual(p4, 3));
}

// ─── MISC-08 — NGINX_NETWORK au lieu de 'nginx-net' code en dur ────────────
console.log("\nMISC-08 — NetworkMode utilise cfg.NGINX_NETWORK (jamais la chaine 'nginx-net' figee)");
{
  const files = ['features/certbot.js', 'features/certbot-dns.js', 'features/error-pages.js', 'features/geoipupdate.js'];
  for (const f of files) {
    const fileSrc = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    check(`${f} : plus de "NetworkMode: 'nginx-net'" code en dur`, () => {
      assert.ok(!/NetworkMode:\s*'nginx-net'/.test(fileSrc), 'trouve encore une occurrence codee en dur');
      assert.ok(/NetworkMode:\s*cfg\.NGINX_NETWORK/.test(fileSrc), 'aucun fallback sur cfg.NGINX_NETWORK trouve');
    });
  }
}

// ─── DAC-10 — le deploiement Git ne copie jamais par-dessus un fichier genere ─
console.log('\nDAC-10 — features/deploy.js : la boucle de copie ignore aussi isGeneratedFile()');
{
  const deploySrc = fs.readFileSync(path.join(__dirname, '..', 'features', 'deploy.js'), 'utf8');
  const copyLoopMatch = deploySrc.match(/for \(const rel of srcFiles\) \{[\s\S]{0,900}/);
  check('la boucle "for (const rel of srcFiles)" appelle isGeneratedFile() avant de copier', () => {
    assert.ok(copyLoopMatch, 'boucle de copie introuvable');
    assert.ok(/isGeneratedFile\(dp\)/.test(copyLoopMatch[0]), copyLoopMatch[0]);
  });
}

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);

})();
