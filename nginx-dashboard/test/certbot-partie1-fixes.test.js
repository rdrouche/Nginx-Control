'use strict';
/**
 * Fixes, audit report Basse/"Partie 1 et certificats" (v12.24.0, partie 2) :
 *
 *  1. issueCertificate() renvoyait {ok:false, logs} sans champ `error` sur un
 *     echec reel : "echec inconnu" affiche systematiquement. Un extrait des
 *     logs est desormais remonte dans `error`.
 *  2. Un domaine `*.example.com` avec le defi HTTP-01 (certbot_http) ne peut
 *     jamais reussir (HTTP-01 ne delivre pas de wildcard) mais etait
 *     reessaye a l infini : rejete des la validation, avant tout appel
 *     Docker.
 *  3. En mode "pending" avec ssl_certificate=certbot_http, le vhost genere
 *     ecoutait sur 443 en clair, sans bloc port 80 ni
 *     /.well-known/acme-challenge/ : le defi HTTP-01 ne pouvait jamais
 *     aboutir (repli sur 00-default.conf's default_server). Le vhost genere
 *     doit desormais ecouter sur 80 avec ce location tant que ce n est pas
 *     en ligne.
 *  4. Revocation Certbot : `body.domain` n etait pas valide par HOSTNAME_RE
 *     avant d etre utilise dans un chemin (certbot.js, certbot-dns.js) —
 *     une traversee de chemin etait possible.
 *
 * Items 1 et 2 sont testes au niveau unitaire (features/certbot.js exporte
 * issueCertificate/extractCertbotError) ; items 3 au niveau unitaire (les
 * lib/*.js purs) ; item 4 contre un vrai serveur, meme convention que
 * test/certbot-dns-routes.test.js.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

// ─── 1 & 2 : issueCertificate() / extractCertbotError() (unitaire) ─────────
const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cb-fixes-'));
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
fs.writeFileSync(path.join(tmpConfigDir, 'certbot.yml'), [
  'enable: true',
  'email: admin@example.com',
  '',
].join('\n'));
const certbot = require('../features/certbot');

console.log('\nextractCertbotError() — extrait exploitable des logs certbot');
check('logs vides/absents -> null', () => {
  assert.strictEqual(certbot.extractCertbotError(''), null);
  assert.strictEqual(certbot.extractCertbotError(null), null);
  assert.strictEqual(certbot.extractCertbotError(undefined), null);
});
check('logs multi-lignes -> les dernieres lignes non vides, jointes', () => {
  const logs = 'Saving debug log...\nRequesting a certificate...\n\nDetail: DNS problem: NXDOMAIN\nAsk for help.';
  const err = certbot.extractCertbotError(logs);
  assert.ok(err.includes('DNS problem'), 'doit contenir la raison reelle');
  assert.ok(err.includes('Ask for help'), 'doit contenir la derniere ligne utile');
});
check('logs tres longs -> tronques a une taille raisonnable', () => {
  const err = certbot.extractCertbotError('x'.repeat(2000));
  assert.ok(err.length <= 501, `${err.length} caracteres — devrait etre borne`);
});

console.log('\nissueCertificate() — rejet wildcard (HTTP-01, avant tout appel Docker)');
(async () => {
  const rWildcard = await certbot.issueCertificate(['*.example.com'], { dryRun: true, source: 'test' });
  check('*.example.com rejete avant certbot, message explicite, jamais un ok:false generique', () => {
    assert.ok(rWildcard.error, 'un message d erreur doit etre present');
    assert.ok(/wildcard/i.test(rWildcard.error), 'le message doit expliquer que HTTP-01 ne peut pas emettre de wildcard');
    assert.strictEqual(rWildcard.ok, undefined, 'doit etre un echec de pre-validation (pas ok:false), donc jamais tente contre Docker');
  });
  const rMixed = await certbot.issueCertificate(['ok.example.com', '*.example.com'], { dryRun: true, source: 'test' });
  check('un seul domaine wildcard parmi plusieurs suffit a rejeter toute la demande', () => {
    assert.ok(rMixed.error);
    assert.ok(/\*\.example\.com/.test(rMixed.error), 'le domaine fautif doit etre nomme');
  });
  const rNoDomains = await certbot.issueCertificate([], { dryRun: true });
  check('non-regression : aucun domaine -> message existant inchange', () => {
    assert.strictEqual(rNoDomains.error, 'domains required');
  });

  // ─── 3 : generateVhostContent()/generateAgentVhostContent() (unitaire) ──
  console.log('\ngenerateVhostContent() (Docker auto-config) — /.well-known/acme-challenge/ en attente d emission');
  const { generateVhostContent } = require('../lib/docker-autoconfig');
  const validated = {
    ssl: { active: true, mode: 'certbot_http' },
    diagnostic: { enable: true }, monitor: { enable: false, validHttpCodes: [] },
    analyze: { enable: true, ignoreRules: [] }, serverSnippets: [],
    locations: [{ path: '/', index: 0, proxyPass: 'http://127.0.0.1:8080', snippets: [] }],
    httpToHttpsAuto: false,
  };
  const pendingContent = generateVhostContent(validated, ['app.example.com'], 443, {
    sslResolved: { type: 'pending' }, certbotWebrootPath: '/var/www/certbot',
  });
  check('en attente (pending) : ecoute sur 80, pas 443', () => {
    assert.ok(/listen 80;/.test(pendingContent), 'doit ecouter sur le port 80');
    assert.ok(!/listen 443/.test(pendingContent), 'ne doit plus ecouter sur 443 tant que ce n est pas en ligne');
  });
  check('en attente (pending) : bloc /.well-known/acme-challenge/ present, pointant vers le webroot', () => {
    assert.ok(pendingContent.includes('location /.well-known/acme-challenge/'), 'le defi HTTP-01 doit avoir sa propre location');
    assert.ok(pendingContent.includes('root /var/www/certbot;'), 'doit pointer vers le webroot certbot configure');
  });
  check("sans certbotWebrootPath (Certbot pas configure) : comportement inchange, pas de location acme, port 443 comme avant", () => {
    const noWebroot = generateVhostContent(validated, ['app.example.com'], 443, { sslResolved: { type: 'pending' } });
    assert.ok(!noWebroot.includes('acme-challenge'));
    assert.ok(/listen 443;/.test(noWebroot));
  });
  const liveContent = generateVhostContent(validated, ['app.example.com'], 443, {
    sslResolved: { type: 'cert', certPath: '/x/fullchain.pem', keyPath: '/x/privkey.pem' },
    certbotWebrootPath: '/var/www/certbot',
  });
  check('une fois en ligne (cert trouve) : ecoute normalement sur 443 ssl, pas de bloc acme-challenge parasite', () => {
    assert.ok(/listen 443 ssl;/.test(liveContent));
    assert.ok(!liveContent.includes('acme-challenge'), 'le vhost live n a plus besoin de ce bloc dans le server{} principal');
  });

  const { generateAgentVhostContent } = require('../lib/agent-manifest');
  const validatedAgent = {
    ssl: { active: true, mode: 'certbot_http' }, mode: 'direct',
    diagnostic: { enable: true }, monitor: { enable: false, validHttpCodes: [] },
    analyze: { enable: true, ignoreRules: [] }, serverSnippets: [],
    locations: [{ path: '/', index: 0, proxyPass: 'http://10.0.0.5:8080', snippets: [] }],
    httpToHttpsAuto: false,
  };
  const pendingAgentContent = generateAgentVhostContent(validatedAgent, ['agent.example.com'], 443, {
    sslResolved: { type: 'pending' }, certbotWebrootPath: '/var/www/certbot',
  });
  check('meme correctif cote Agents (agent-manifest.js) : port 80 + acme-challenge en attente', () => {
    assert.ok(/listen 80;/.test(pendingAgentContent));
    assert.ok(pendingAgentContent.includes('location /.well-known/acme-challenge/'));
  });

  // ─── 4 : validation HOSTNAME_RE a la revocation (bout en bout) ──────────
  console.log('\nrevocation Certbot — domaine valide contre HOSTNAME_RE avant utilisation dans un chemin');
  const root = path.join(__dirname, '..');
  const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbrevoke-app-'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbrevoke-data-'));
  fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
  fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
  fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
  fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));
  for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
    fs.mkdirSync(path.join(tmp, d), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
  fs.writeFileSync(path.join(tmp, 'config', 'certbot.yml'), 'enable: true\nemail: admin@example.com\n');
  fs.writeFileSync(path.join(tmp, 'config', 'certbot-dns.yml'),
    'enable: true\nprovider: cloudflare\nemail: admin@example.com\ncredentials_host_path: /x\ncerts_host_path: /containers/certs\n');

  const PORT = 3941;
  const env = { ...process.env, PORT: String(PORT),
    USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
    DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
    DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
    DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
    DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
    DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
    DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

  function req(method, p, cookie, body) {
    return new Promise(resolve => {
      const data = body ? JSON.stringify(body) : null;
      const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method,
        headers: { ...(cookie ? { Cookie: cookie } : {}), ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) },
        timeout: 5000 }, res => {
        let b = ''; res.on('data', d => b += d);
        res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b) }); } catch { resolve({ status: res.statusCode, body: b }); } });
      });
      r.on('error', e => resolve({ status: 0, body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
      if (data) r.write(data);
      r.end();
    });
  }

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));
  const login = await new Promise(resolve => {
    const b = 'username=admin&password=admin123';
    const r = http.request({ host: '127.0.0.1', port: PORT, path: '/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } },
      res => resolve({ status: res.statusCode, cookie: (res.headers['set-cookie'] || [''])[0].split(';')[0] }));
    r.on('error', () => resolve({ status: 0, cookie: '' }));
    r.write(b); r.end();
  });
  const ck = login.cookie;

  const revokeTraversal = await req('POST', '/api/certbot/revoke', ck, { domain: '../../../../etc/passwd' });
  check('certbot/revoke : domaine invalide (traversee de chemin) -> 400, jamais un acces disque hors DIR_CERTS', () => {
    assert.strictEqual(revokeTraversal.status, 400);
  });
  const revokeNotFound = await req('POST', '/api/certbot/revoke', ck, { domain: 'valid.example.com' });
  check('certbot/revoke : domaine valide mais sans certificat -> 404 (comportement existant, pas 400)', () => {
    assert.strictEqual(revokeNotFound.status, 404);
  });

  const revokeDnsTraversal = await req('POST', '/api/certbot-dns/revoke', ck, { domain: '../../../../etc/passwd' });
  check('certbot-dns/revoke : domaine invalide -> 400', () => {
    assert.strictEqual(revokeDnsTraversal.status, 400);
  });
  const revokeDnsWildcardNotFound = await req('POST', '/api/certbot-dns/revoke', ck, { domain: '*.valid.example.com' });
  check('certbot-dns/revoke : un domaine wildcard reste accepte par la validation (DNS-01 le permet), 404 attendu (pas de cert)', () => {
    assert.strictEqual(revokeDnsWildcardNotFound.status, 404);
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(tmpConfigDir, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
