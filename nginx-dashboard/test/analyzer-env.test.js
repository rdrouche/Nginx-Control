'use strict';
/**
 * Signalement reel : la page WAF affiche le panneau "non configure" (avec
 * l exemple de directives ModSecurity) alors que la page Analyse fonctionne,
 * juste apres etre passe de la gestion manuelle du conteneur analyzer (dans
 * docker-compose.yml) a sa gestion via Nginx Control (start/stop depuis la
 * page Analyse).
 *
 * Cause reelle, trouvee dans features/analyzer.js -> startAnalyzer() -> env :
 *   LOG_PATTERN=${c.log_pattern || '\\.access\\.log$'}       // 2 backslashes -> OK
 *   WAF_LOG_PATTERN=${c.waf_log_pattern || '\\\\.waf\\\\.log$'}  // 4 backslashes -> BUG
 *
 * Cote source JS, '\\.access\\.log$' est la chaine `\.access\.log$` — le bon
 * texte source d une regex qui matche un point litteral. Mais
 * '\\\\.waf\\\\.log$' est la chaine `\\.waf\\.log$` (deux vrais
 * antislashs) : une fois passee en variable d environnement puis rechargee
 * cote analyzer via `new RegExp(str('WAF_LOG_PATTERN', ...))`, `\\` y est
 * interprete comme un antislash litteral suivi d un point non echappe — un
 * motif qui ne peut matcher aucun nom de fichier reel. Resultat :
 * `wafTailer.status().files` reste a 0 pour toujours, quoi qu il arrive sur
 * le disque, et la page WAF affiche indefiniment son panneau de mise en
 * route.
 *
 * L ancienne gestion manuelle du conteneur (docker-compose.yml, avant le
 * passage a Nginx Control) ne passait meme pas WAF_LOG_PATTERN : l analyzer
 * retombait sur son PROPRE defaut interne (server.js), correctement
 * echappe — ce qui explique pourquoi le bug n etait apparu qu apres le
 * passage a la gestion via le dashboard.
 *
 * On ne peut pas appeler startAnalyzer() directement sans un vrai demon
 * Docker (dockerCall est destructure au chargement du module, donc pas
 * injectable via setDeps comme les autres dependances croisees) : ce test
 * relit donc la ligne source telle qu elle sera executee et verifie que le
 * motif de repli produit reellement matche un nom de fichier `<vhost>.waf.log`
 * — le seul fait qui compte ici.
 */
const assert = require('assert'), fs = require('fs'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const SRC = fs.readFileSync(path.join(__dirname, '..', 'features', 'analyzer.js'), 'utf8');

console.log('\nfeatures/analyzer.js — motif de repli WAF_LOG_PATTERN passe au conteneur analyzer');

// Note (fix ANA-02, v12.22.x) : LOG_PATTERN et WAF_LOG_PATTERN n ont plus la
// meme FORME depuis le correctif ANA-02 — LOG_PATTERN est passe a une
// alternance `(^|[._])access\.log$` pour matcher a la fois la convention
// mono-fichier (vhosts_access.log) et une convention par-vhost
// (<vhost>.access.log), alors que WAF_LOG_PATTERN reste un simple suffixe
// echappe `\.waf\.log$` (un seul fichier partage `vhosts_waf.log` par
// design). Cette difference de FORME est intentionnelle. Ce qui reste un
// bug reel si ca se reproduit, c est un niveau d ECHAPPEMENT incorrect
// (antislashs doubles transmis via l env -> `\\.` au lieu de `\.` une fois
// releu cote analyzer) — c est ce que ce test verifie desormais,
// independamment pour chaque motif.
check('LOG_PATTERN et WAF_LOG_PATTERN ont chacun un niveau d echappement correct dans le source (pas d antislash literal parasite)', () => {
  const logM = SRC.match(/LOG_PATTERN=\$\{c\.log_pattern \|\| '([^']+)'\}/);
  const wafM = SRC.match(/WAF_LOG_PATTERN=\$\{c\.waf_log_pattern \|\| '([^']+)'\}/);
  assert.ok(logM, 'motif de repli de LOG_PATTERN introuvable (le code a peut-etre change de forme)');
  assert.ok(wafM, 'motif de repli de WAF_LOG_PATTERN introuvable (le code a peut-etre change de forme)');
  // Le texte source ('\\.access\\.log$' etc.) doit se de-echapper, une fois
  // evalue comme litteral JS, en un vrai antislash simple ('\.') devant
  // chaque point litteral — pas un antislash litteral suivi d un point non
  // echappe ('\\.'), qui est exactement le bug historique (WAF_LOG_PATTERN
  // avait un niveau d echappement en trop).
  const evaluated = s => new Function('return ' + s)();
  const logVal = evaluated(`'${logM[1]}'`);
  const wafVal = evaluated(`'${wafM[1]}'`);
  assert.ok(!/\\\\/.test(logVal), `LOG_PATTERN a un antislash litteral en trop dans sa valeur transmise : ${JSON.stringify(logVal)}`);
  assert.ok(!/\\\\/.test(wafVal), `WAF_LOG_PATTERN a un antislash litteral en trop dans sa valeur transmise : ${JSON.stringify(wafVal)}`);
});

// Le texte capture par la regex ci-dessus est le LITTERAL SOURCE (les
// antislashs tels qu ecrits dans le fichier), pas la valeur JS apres
// desechappement — exactement la distinction qui a cause le bug. On la fait
// evaluer par le moteur JS lui-meme (`new Function`) plutot que de la
// reinterpreter a la main, pour obtenir la vraie valeur transmise en
// variable d environnement au conteneur.
function evalStringLiteral(quoted) {
  return new Function('return ' + quoted)();
}

check('le motif de repli WAF_LOG_PATTERN, une fois transmis tel quel en variable d environnement, matche bien un fichier <vhost>.waf.log', () => {
  const wafM = SRC.match(/WAF_LOG_PATTERN=\$\{c\.waf_log_pattern \|\| ('[^']+')\}/);
  assert.ok(wafM);
  const pattern = evalStringLiteral(wafM[1]);
  const re = new RegExp(pattern);
  assert.ok(re.test('exemple.com.waf.log'),
    `le motif "${pattern}" ne matche aucun fichier <vhost>.waf.log reel — c est exactement le bug signale (page WAF bloquee sur "non configure")`);
  assert.ok(!re.test('exemple.com.access.log'), 'le motif WAF ne doit pas matcher les logs d acces');
});

check('le motif de repli LOG_PATTERN (access) matche bien un fichier <vhost>.access.log (garde-fou : ne pas casser Analyse en corrigeant WAF)', () => {
  const logM = SRC.match(/LOG_PATTERN=\$\{c\.log_pattern \|\| ('[^']+')\}/);
  assert.ok(logM);
  const pattern = evalStringLiteral(logM[1]);
  const re = new RegExp(pattern);
  assert.ok(re.test('exemple.com.access.log'));
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
