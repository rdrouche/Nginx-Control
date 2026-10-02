'use strict';
/**
 * Regression tests for the v12.21.1 security audit fixes (lot 1). Each
 * block is named after the audit finding it closes — see the delivered
 * rapport-bugs-v12.21.0.md and this version's CHANGELOG.md entry.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function freshEnv(env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secfix-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  for (const k of ['API_TOKEN', 'WEBHOOK_SECRET', 'TRUSTED_PROXIES']) delete process.env[k];
  Object.assign(process.env, env || {});
  for (const mod of ['../lib/config', '../lib/git', '../lib/http', '../lib/auth', '../lib/cidr']) {
    delete require.cache[require.resolve(mod)];
  }
  return dir;
}

// ─── SEC-01 / SEC-04 — no more shell interpolation in git commands ─────────
console.log('\nSEC-01 — lib/git.js validateBranch()/validateRepoUrl() reject injection attempts');
(() => {
  freshEnv({});
  const git = require('../lib/git');
  check('branche avec point-virgule shell rejetee', () => {
    assert.throws(() => git.validateBranch('main;touch /tmp/pwned', 'branch'));
  });
  check('branche ressemblant a un flag git rejetee (argument injection)', () => {
    assert.throws(() => git.validateBranch('--upload-pack=/bin/sh', 'branch'));
  });
  check('branche normale acceptee', () => {
    assert.doesNotThrow(() => git.validateBranch('release/12.21', 'branch'));
  });
  check('URL de depot avec backticks rejetee', () => {
    assert.throws(() => git.validateRepoUrl('https://host/`touch /tmp/x`.git'));
  });
  check('URL de depot commencant par un flag rejetee', () => {
    assert.throws(() => git.validateRepoUrl('--upload-pack=/bin/sh'));
  });
  check('URL https normale acceptee', () => {
    assert.doesNotThrow(() => git.validateRepoUrl('https://forge.example.com/owner/repo.git'));
  });
  check('URL ssh (scp-like) normale acceptee', () => {
    assert.doesNotThrow(() => git.validateRepoUrl('git@forge.example.com:owner/repo.git'));
  });
  check('runCmd() ne passe plus par un shell — execFile avec argv (pas de chaine)', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'git.js'), 'utf8');
    assert.ok(!/require\('child_process'\)\.exec\b|\{ exec \}/.test(src) || /execFile/.test(src));
    assert.ok(src.includes('execFile'), 'attendu: execFile utilise pour toutes les commandes git');
    assert.ok(!src.includes("exec(cmd"), 'attendu: plus de exec(cmd) construit par interpolation de chaine');
  });
})();

console.log('\nSEC-04 — features/sync-ref.js commitAndPushSync() no longer shells out via exec()');
(() => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'features', 'sync-ref.js'), 'utf8');
  check('commitAndPushSync() utilise execFile, pas exec(cmd) interpole', () => {
    assert.ok(src.includes('execFile'));
    assert.ok(!/exec\(cmd/.test(src));
  });
})();

console.log('\nMISC-03 — sync-ref.js : un nouveau fichier de reference arrive desactive');
(() => {
  freshEnv({});
  const syncRef = require('../features/sync-ref');
  // applySyncToGitWork n'est pas exportee (logique interne a la route) — on
  // verifie le contrat au niveau du code source : les deux branches du
  // ternaire ne doivent plus etre identiques.
  const src = fs.readFileSync(path.join(__dirname, '..', 'features', 'sync-ref.js'), 'utf8');
  check('shouldDisable distingue bien "nouveau fichier" de "fichier existant"', () => {
    assert.ok(/shouldDisable\s*=\s*item\.localExists\s*\?\s*item\.localDisabled\s*:\s*true/.test(src),
      'attendu: shouldDisable = item.localExists ? item.localDisabled : true');
  });
})();

// ─── SEC-03 — placeholder API_TOKEN never enables Bearer auth ──────────────
console.log('\nSEC-03 — un API_TOKEN "changeme*" reste desactive quelle que soit sa longueur');
(() => {
  freshEnv({ API_TOKEN: 'changeme-generate-with-openssl-rand-hex-32' });
  let cfg = require('../lib/config');
  check('valeur d exemple du sample.env : Bearer auth reste desactivee', () => {
    assert.strictEqual(cfg.API_TOKEN_ENABLED, false);
  });

  freshEnv({ API_TOKEN: 'CHANGEME-SET-IN-ENV-1234567890123456' });
  cfg = require('../lib/config');
  check('valeur d exemple du docker-compose.yml (casse differente) : toujours desactivee', () => {
    assert.strictEqual(cfg.API_TOKEN_ENABLED, false);
  });

  freshEnv({ API_TOKEN: 'a'.repeat(20) });
  cfg = require('../lib/config');
  check('jeton reel mais < 32 caracteres : desactivee', () => {
    assert.strictEqual(cfg.API_TOKEN_ENABLED, false);
  });

  freshEnv({ API_TOKEN: require('crypto').randomBytes(32).toString('hex') });
  cfg = require('../lib/config');
  check('vrai jeton aleatoire >= 32 caracteres : activee', () => {
    assert.strictEqual(cfg.API_TOKEN_ENABLED, true);
  });
})();

// ─── SEC-02 — config-editor write requires MANAGE_USERS, not just DEPLOY ───
console.log('\nSEC-02 — features/config-editor.js : ecriture reservee a MANAGE_USERS');
(() => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'features', 'config-editor.js'), 'utf8');
  const postBlock = src.slice(src.indexOf("router.post('/api/config-editor/file'"));
  check('la route POST verifie MANAGE_USERS avant tout hasPerm(DEPLOY)', () => {
    const firstCheck = postBlock.match(/hasPerm\(session,\s*PERMS\.(\w+)\)/);
    assert.ok(firstCheck, 'aucun hasPerm() trouve dans le handler POST');
    assert.strictEqual(firstCheck[1], 'MANAGE_USERS');
  });
})();

// ─── MISC-01 — GoAccess start/stop require DEPLOY, not just VIEW_GOACCESS ──
console.log('\nMISC-01 — features/goaccess.js : start/stop reserves a DEPLOY');
(() => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'features', 'goaccess.js'), 'utf8');
  for (const route of ["'/api/goaccess/start'", "'/api/goaccess/stop'"]) {
    const idx = src.indexOf(`router.post(${route}`);
    assert.ok(idx !== -1, `route ${route} introuvable`);
    const block = src.slice(idx, idx + 700);
    check(`${route} verifie PERMS.DEPLOY`, () => {
      const m = block.match(/hasPerm\(session,\s*PERMS\.(\w+)\)/);
      assert.ok(m);
      assert.strictEqual(m[1], 'DEPLOY');
    });
  }
})();

// ─── SEC-05 — X-Forwarded-For trust and per-username rate limiting ─────────
console.log('\nSEC-05 — lib/http.js clientIp() ne fait confiance a XFF que depuis un proxy de confiance');
(() => {
  freshEnv({ TRUSTED_PROXIES: '10.0.0.0/8' });
  const http = require('../lib/http');
  const reqFrom = (remoteAddress, xff) => ({
    headers: xff ? { 'x-forwarded-for': xff } : {},
    socket: { remoteAddress },
  });
  check('client direct (hors liste de confiance) : XFF ignore, adresse socket utilisee', () => {
    assert.strictEqual(http.clientIp(reqFrom('203.0.113.9', '1.2.3.4')), '203.0.113.9');
  });
  check('proxy de confiance : le dernier hop non-proxy de XFF est retenu', () => {
    assert.strictEqual(http.clientIp(reqFrom('10.1.2.3', '198.51.100.7, 10.1.2.3')), '198.51.100.7');
  });
  check('sans XFF du tout : adresse socket utilisee', () => {
    assert.strictEqual(http.clientIp(reqFrom('203.0.113.9', null)), '203.0.113.9');
  });
  check('un client direct ne peut pas usurper son IP en changeant XFF a chaque appel', () => {
    const a = http.clientIp(reqFrom('203.0.113.9', '1.1.1.1'));
    const b = http.clientIp(reqFrom('203.0.113.9', '2.2.2.2'));
    assert.strictEqual(a, b, 'les deux appels doivent retomber sur la meme adresse socket');
  });
})();

console.log('\nSEC-05 — lib/auth.js : un compte ne peut plus etre force en tournant les IP');
(() => {
  freshEnv({});
  process.env.LOGIN_MAX_ATTEMPTS = '3';
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/auth')];
  const auth = require('../lib/auth');
  const username = 'admin';
  // cfg.LOGIN_MAX_ATTEMPTS(3) * 5 = 15 echecs suffisent a bloquer meme depuis
  // 15 IP toutes differentes.
  for (let i = 0; i < 15; i++) auth.recordLoginFailure(`10.0.0.${i}`, username);
  check('le compte est bloque malgre des IP toutes differentes (bucket user|<name>)', () => {
    const rate = auth.checkLoginRate('10.0.0.999', username);
    assert.strictEqual(rate.blocked, true);
  });
  delete process.env.LOGIN_MAX_ATTEMPTS;
})();

// ─── SEC-06 — no session token in the SSE URL / logs stream ────────────────
console.log('\nSEC-06 — /api/auth/stream-token retire, features/logs.js authentifie via cookie');
(() => {
  const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  check("la route /api/auth/stream-token n'existe plus", () => {
    assert.ok(!serverSrc.includes("'/api/auth/stream-token'"));
  });
  const logsSrc = fs.readFileSync(path.join(__dirname, '..', 'features', 'logs.js'), 'utf8');
  check('handleStream() authentifie via getSessionFromReq (cookie) en premier', () => {
    const idx = logsSrc.indexOf('function handleStream');
    const block = logsSrc.slice(idx, idx + 600);
    assert.ok(block.includes('getSessionFromReq(req)'));
  });
  check("le SSE de logs n'envoie plus Access-Control-Allow-Origin: *", () => {
    const idx = logsSrc.indexOf('function startTailSSE');
    const block = logsSrc.slice(idx, logsSrc.indexOf('function', idx + 10));
    assert.ok(!block.includes("'Access-Control-Allow-Origin'"));
  });
  const indexSrc = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  check("le frontend ne recupere plus de token pour l'EventSource de logs", () => {
    assert.ok(!indexSrc.includes('/api/auth/stream-token'));
  });
})();

// ─── SEC-07 — git error/status responses never leak an embedded credential ─
console.log('\nSEC-07 — lib/git.js redactUrl() masque un identifiant embarque');
(() => {
  const git = require('../lib/git');
  check('redactUrl masque user:token@ dans une URL https', () => {
    const out = git.redactUrl('https://x-access-token:ghp_SECRETVALUE@forge.example.com/owner/repo.git');
    assert.ok(!out.includes('ghp_SECRETVALUE'), 'le token ne doit jamais apparaitre en clair');
    assert.ok(out.includes('***@'));
  });
  check('redactUrl ne modifie pas une URL sans identifiant', () => {
    assert.strictEqual(git.redactUrl('https://forge.example.com/owner/repo.git'),
      'https://forge.example.com/owner/repo.git');
  });
})();

// ─── SEC-13 — bounded login body ───────────────────────────────────────────
console.log('\nSEC-13 — lib/http.js expose readRawBody() borne, utilise par /auth/login');
(() => {
  const http = require('../lib/http');
  check('readRawBody existe et est exportee', () => {
    assert.strictEqual(typeof http.readRawBody, 'function');
  });
  const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  check("le handler /auth/login utilise readRawBody (plus d'accumulation sans limite)", () => {
    const idx = serverSrc.indexOf("pathname === '/auth/login'");
    const block = serverSrc.slice(idx, idx + 1200);
    assert.ok(block.includes('readRawBody(req'));
    assert.ok(!/let d = '';\s*req\.on\('data',\s*c\s*=>\s*d\s*\+=\s*c\)/.test(block));
  });
})();

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
