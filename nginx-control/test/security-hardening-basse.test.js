'use strict';
/**
 * Fixes, audit report section 5 "Basse" / "Sécurité et durcissement" :
 *  - cookie de session sans `Secure` (jamais, meme en HTTPS) ;
 *  - aucun en-tete HSTS ni CSP sur aucune reponse ;
 *  - /auth/logout acceptait GET (deconnexion forcee cross-site) ;
 *  - login CSRF (soumission cross-site d un formulaire de connexion avec les
 *    identifiants de l attaquant).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nlib/auth.js — unites (isRequestHttps, loginOriginAllowed)');
const auth = require('../lib/auth');
check('isRequestHttps() : socket TLS -> true', () => {
  assert.strictEqual(auth.isRequestHttps({ socket: { encrypted: true }, headers: {} }), true);
});
check('isRequestHttps() : X-Forwarded-Proto: https (derriere le reverse proxy du projet) -> true', () => {
  assert.strictEqual(auth.isRequestHttps({ socket: {}, headers: { 'x-forwarded-proto': 'https' } }), true);
});
check('isRequestHttps() : ni TLS ni en-tete -> false (jamais Secure en HTTP simple, pas de regression)', () => {
  assert.strictEqual(auth.isRequestHttps({ socket: {}, headers: {} }), false);
});
check('setCookieHeader() : Secure ajoute seulement en HTTPS', () => {
  assert.ok(auth.setCookieHeader('tok', { socket: { encrypted: true }, headers: {} }).includes('; Secure'));
  assert.ok(!auth.setCookieHeader('tok', { socket: {}, headers: {} }).includes('; Secure'));
});
check('loginOriginAllowed() : aucun Origin/Referer -> autorise (client direct, pas de regression)', () => {
  assert.strictEqual(auth.loginOriginAllowed({ headers: { host: 'dash.example.com' } }), true);
});
check('loginOriginAllowed() : Origin different du Host -> refuse', () => {
  assert.strictEqual(auth.loginOriginAllowed({ headers: { host: 'dash.example.com', origin: 'http://attacker.example' } }), false);
});
check('loginOriginAllowed() : Origin identique au Host -> autorise', () => {
  assert.strictEqual(auth.loginOriginAllowed({ headers: { host: 'dash.example.com', origin: 'http://dash.example.com' } }), true);
});

console.log('\nlib/http.js — HSTS + CSP presents sur toute reponse');
const httpLib = require('../lib/http');
(() => {
  const res = { writeHead(c, h) { this.code = c; this.headers = h; }, end() {} };
  httpLib.send(res, 200, {});
  check('Strict-Transport-Security present', () => assert.ok(res.headers['Strict-Transport-Security']));
  check('Content-Security-Policy present et restreint aux origines connues', () => {
    const csp = res.headers['Content-Security-Policy'];
    assert.ok(csp);
    assert.ok(csp.includes("default-src 'self'"));
    assert.ok(csp.includes("frame-ancestors 'self'"));
  });
  check('font-src/style-src ne font plus confiance a un CDN tiers (fix v12.30.0)', () => {
    // Avant la v12.30.0 : font-src/style-src autorisaient
    // fonts.gstatic.com/fonts.googleapis.com pour la police Google Fonts de
    // public/index.html, et Chart.js etait charge depuis cdn.jsdelivr.net —
    // que script-src n a jamais autorise, cassant silencieusement le
    // graphique pour quiconque fait reellement respecter cette CSP. Les deux
    // sont desormais auto-heberges (public/assets/fonts/, public/assets/vendor/),
    // donc plus aucun hote tiers n a besoin d etre dans la policy.
    const csp = res.headers['Content-Security-Policy'];
    assert.ok(!/googleapis|gstatic|jsdelivr/.test(csp), `CSP fait encore reference a un CDN tiers : ${csp}`);
  });
})();

console.log('\npublic/index.html ne charge plus rien depuis un CDN tiers (fix v12.30.0)');
(() => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  check('aucune reference a fonts.googleapis.com/fonts.gstatic.com/cdn.jsdelivr.net', () => {
    assert.ok(!/fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.jsdelivr\.net/.test(html), 'reference CDN encore presente dans index.html');
  });
  check('la police est chargee depuis les fichiers auto-heberges', () => {
    assert.ok(html.includes('/assets/fonts/fonts.css'));
  });
  check('Chart.js est charge depuis les fichiers auto-heberges', () => {
    assert.ok(html.includes('/assets/vendor/chart.umd.min.js'));
  });
})();

console.log('\ncontre un vrai serveur : logout GET refuse, login cross-origine refuse, cookie Secure en HTTPS');
(async () => {
  const root = path.join(__dirname, '..');
  const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hardening-app-'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hardening-data-'));
  fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
  fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
  fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
  fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));
  for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
    fs.mkdirSync(path.join(tmp, d), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

  const PORT = 3930;
  const env = { ...process.env, PORT: String(PORT),
    USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
    DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
    DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
    DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
    DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
    DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
    DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

  function rawReq(method, p, { headers = {}, body } = {}) {
    return new Promise(resolve => {
      const data = body !== undefined ? body : null;
      const h = { ...headers };
      if (data) h['Content-Length'] = Buffer.byteLength(data);
      const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers: h, timeout: 5000 }, res => {
        let b = ''; res.on('data', d => b += d);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
      });
      r.on('error', e => resolve({ status: 0, body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
      if (data) r.write(data);
      r.end();
    });
  }

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 1500));

  const loginOk = await rawReq('POST', '/auth/login', {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=admin&password=admin123' });
  check('login normal (sans Origin, comme un vrai navigateur sur une soumission de formulaire same-site) fonctionne toujours', () => {
    assert.strictEqual(loginOk.status, 302);
  });
  const cookie = (loginOk.headers['set-cookie'] || [''])[0].split(';')[0];
  check('cookie de session obtenu, sans Secure (serveur de test en HTTP simple)', () => {
    assert.ok(cookie);
    assert.ok(!(loginOk.headers['set-cookie'][0].includes('Secure')));
  });

  const loginCsrf = await rawReq('POST', '/auth/login', {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'http://attacker.example' },
    body: 'username=admin&password=admin123' });
  check('login CSRF (Origin cross-site) refuse (403), avant toute verification du mot de passe', () => {
    assert.strictEqual(loginCsrf.status, 403);
  });

  const loginSecure = await rawReq('POST', '/auth/login', {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwarded-Proto': 'https' },
    body: 'username=admin&password=admin123' });
  check('cookie de session avec Secure quand la requete est vue comme HTTPS (X-Forwarded-Proto)', () => {
    assert.ok((loginSecure.headers['set-cookie'] || [''])[0].includes('Secure'));
  });

  const logoutGet = await rawReq('GET', '/auth/logout', { headers: { Cookie: cookie } });
  check('GET /auth/logout ne detruit plus la session (redirection simple, pas de Set-Cookie)', () => {
    assert.strictEqual(logoutGet.status, 302);
    assert.strictEqual(logoutGet.headers['set-cookie'], undefined);
  });
  const stillAuthed = await rawReq('GET', '/api/auth/me', { headers: { Cookie: cookie } });
  check('la session est toujours valide apres un GET sur /auth/logout', () => {
    assert.strictEqual(stillAuthed.status, 200);
  });

  const logoutPost = await rawReq('POST', '/auth/logout', { headers: { Cookie: cookie, 'Content-Type': 'application/json' } });
  check('POST /auth/logout detruit bien la session', () => assert.strictEqual(logoutPost.status, 302));
  const noLongerAuthed = await rawReq('GET', '/api/auth/me', { headers: { Cookie: cookie } });
  check('la session est bien invalide apres un POST sur /auth/logout', () => assert.strictEqual(noLongerAuthed.status, 401));

  console.log('\nassets auto-heberges (fonts + Chart.js) servis sans authentification (fix v12.30.0)');
  const chartJs = await rawReq('GET', '/assets/vendor/chart.umd.min.js');
  check('GET /assets/vendor/chart.umd.min.js -> 200, type javascript', () => {
    assert.strictEqual(chartJs.status, 200);
    assert.ok(chartJs.headers['content-type'].includes('javascript'));
    assert.ok(chartJs.body.includes('Chart.js'), 'contenu inattendu');
  });
  const fontsCss = await rawReq('GET', '/assets/fonts/fonts.css');
  check('GET /assets/fonts/fonts.css -> 200, type css', () => {
    assert.strictEqual(fontsCss.status, 200);
    assert.ok(fontsCss.headers['content-type'].includes('text/css'));
    assert.ok(fontsCss.body.includes("font-family: 'JetBrains Mono'"));
    assert.ok(fontsCss.body.includes("font-family: 'Syne'"));
  });
  const woff2 = await rawReq('GET', '/assets/fonts/jetbrains-mono/jetbrains-mono-latin-400-normal.woff2');
  check('GET d un fichier .woff2 -> 200, type font/woff2 (ext ajoutee a STATIC_ASSET_TYPES)', () => {
    assert.strictEqual(woff2.status, 200);
    assert.strictEqual(woff2.headers['content-type'], 'font/woff2');
  });
  const traversal = await rawReq('GET', '/assets/vendor/../../server.js');
  check('un chemin qui tente de sortir de public/assets/ reste bloque (garde deja existante)', () => {
    assert.strictEqual(traversal.status, 404);
  });

  srv.kill('SIGTERM');
  await new Promise(r => setTimeout(r, 300));
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(appDir, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
