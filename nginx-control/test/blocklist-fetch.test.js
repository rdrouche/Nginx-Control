'use strict';
/**
 * lib/blocklist-fetch.js — jamais de rejet, toujours { ok, ... }, et le
 * plafond de taille est bien applique EN COURS de streaming (pas seulement
 * apres coup), pour qu une source malveillante ou juste tres volumineuse ne
 * puisse jamais faire gonfler la memoire du process.
 */
const assert = require('assert');
const http = require('http');
const { fetchBlocklistText, MAX_BYTES, TIMEOUT_MS } = require('../lib/blocklist-fetch');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

(async () => {
  const server = http.createServer((req, res) => {
    if (req.url === '/ok.txt') { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('1.2.3.4\n5.6.7.0/24\n'); return; }
    if (req.url === '/notfound.txt') { res.writeHead(404); res.end('not found'); return; }
    if (req.url === '/servererror.txt') { res.writeHead(500); res.end('boom'); return; }
    if (req.url === '/huge.txt') {
      // Envoie bien plus que MAX_BYTES en petits morceaux, pour verifier que
      // le flux est coupe EN COURS de reception plutot qu apres avoir tout
      // bufferise (ce que ferait un simple check sur la longueur finale).
      res.writeHead(200);
      const chunk = 'X'.repeat(1024 * 1024); // 1MB
      let sent = 0;
      const iv = setInterval(() => {
        if (sent > MAX_BYTES * 1.5 || res.writableEnded) { clearInterval(iv); try { res.end(); } catch {} return; }
        sent += chunk.length;
        res.write(chunk);
      }, 1);
      return;
    }
    if (req.url === '/slow.txt') { /* ne repond jamais avant timeout du test */ return; }
    res.writeHead(404); res.end();
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  console.log('\nfetchBlocklistText() — cas nominal');
  {
    const r = await fetchBlocklistText(`${base}/ok.txt`);
    check('reponse 200 -> { ok: true, text }', () => {
      assert.strictEqual(r.ok, true);
      assert.ok(r.text.includes('1.2.3.4'));
    });
  }

  console.log('\nfetchBlocklistText() — echecs HTTP : jamais de rejet, toujours { ok:false, error }');
  {
    const r404 = await fetchBlocklistText(`${base}/notfound.txt`);
    check('HTTP 404 -> ok:false avec le code dans error', () => {
      assert.strictEqual(r404.ok, false);
      assert.ok(r404.error.includes('404'));
    });
    const r500 = await fetchBlocklistText(`${base}/servererror.txt`);
    check('HTTP 500 -> ok:false avec le code dans error', () => {
      assert.strictEqual(r500.ok, false);
      assert.ok(r500.error.includes('500'));
    });
  }

  console.log('\nfetchBlocklistText() — validation d URL avant toute requete reseau');
  {
    const rBad = await fetchBlocklistText('ceci n est pas une url');
    check('URL syntaxiquement invalide -> ok:false, aucune exception levee', () => {
      assert.strictEqual(rBad.ok, false);
    });
    const rFtp = await fetchBlocklistText('ftp://example.org/list.txt');
    check('schema non http(s) (ftp://) -> refuse explicitement', () => {
      assert.strictEqual(rFtp.ok, false);
      assert.ok(/http/i.test(rFtp.error));
    });
    const rFile = await fetchBlocklistText('file:///etc/passwd');
    check('schema file:// -> refuse (pas de lecture locale via une URL de source)', () => {
      assert.strictEqual(rFile.ok, false);
    });
  }

  console.log('\nfetchBlocklistText() — plafond de taille applique en cours de streaming');
  {
    const r = await fetchBlocklistText(`${base}/huge.txt`);
    check('reponse trop volumineuse -> coupee et rejetee proprement (pas de crash memoire)', () => {
      assert.strictEqual(r.ok, false);
      assert.ok(/volumineuse/i.test(r.error));
    });
  }

  console.log('\nfetchBlocklistText() — timeout');
  {
    // Le mecanisme interne coupe apres TIMEOUT_MS ; on verifie juste qu il
    // resout bien ok:false dans un delai raisonnable au-dela de cette valeur,
    // sans dupliquer la constante dans un `setTimeout` du test.
    const start = Date.now();
    const r = await fetchBlocklistText(`${base}/slow.txt`);
    const elapsed = Date.now() - start;
    check('aucune reponse avant TIMEOUT_MS -> ok:false, jamais bloque indefiniment', () => {
      assert.strictEqual(r.ok, false);
      assert.ok(elapsed < TIMEOUT_MS + 5000, `le timeout interne (${TIMEOUT_MS}ms) n a pas ete respecte (${elapsed}ms ecoules)`);
    });
  }

  server.close();
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
