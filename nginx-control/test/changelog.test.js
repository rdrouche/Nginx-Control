'use strict';
/**
 * features/changelog.js — bouton "Changelog" de la page Systeme (v12.41.0,
 * retour utilisateur). Le fichier CHANGELOG.md n'est pas embarque dans
 * l'image : il est recupere depuis CHANGELOG_URL (ARG/ENV, voir Dockerfile),
 * avec un cache court en memoire.
 */
const assert = require('assert');
const http   = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const checkAsync = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nfeatures/changelog.js');

(async () => {
  // Petit serveur HTTP local qui joue le role du depot distant.
  let serveCount = 0;
  const srv = http.createServer((req, res) => {
    serveCount++;
    if (req.url === '/redirect') {
      res.writeHead(302, { Location: '/CHANGELOG.md' });
      return res.end();
    }
    if (req.url === '/404') { res.writeHead(404); return res.end(); }
    if (req.url === '/big') {
      res.writeHead(200);
      // 3 Mo, au-dela de MAX_BYTES (2 Mo)
      return res.end(Buffer.alloc(3 * 1024 * 1024, 'a'));
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('# v1.0.0\n\n- une entree\n');
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const port = srv.address().port;
  const base = `http://127.0.0.1:${port}`;

  process.env.CONFIG_DIR = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'changelog-'));
  const { fetchChangelog } = require('../features/changelog');

  await checkAsync('recupere le contenu tel quel sur 200', async () => {
    const r = await fetchChangelog(base + '/CHANGELOG.md');
    assert.strictEqual(r.content, '# v1.0.0\n\n- une entree\n');
    assert.strictEqual(r.error, undefined);
  });

  await checkAsync('suit une redirection 302', async () => {
    const r = await fetchChangelog(base + '/redirect');
    assert.strictEqual(r.content, '# v1.0.0\n\n- une entree\n');
  });

  await checkAsync('404 -> erreur explicite, pas de contenu', async () => {
    const r = await fetchChangelog(base + '/404');
    assert.ok(r.error);
    assert.strictEqual(r.content, undefined);
  });

  await checkAsync('fichier trop volumineux -> erreur, jamais charge entierement en memoire sans limite', async () => {
    const r = await fetchChangelog(base + '/big');
    assert.ok(r.error);
  });

  check('URL invalide -> erreur, pas d exception', () => {
    // Le test suivant est async, mais on verifie juste l absence d exception synchrone ici
    assert.doesNotThrow(() => { fetchChangelog('pas-une-url').catch(() => {}); });
  });

  await checkAsync('URL vide -> erreur explicite', async () => {
    const r = await fetchChangelog('');
    assert.ok(r.error);
  });

  srv.close();
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
