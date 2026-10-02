'use strict';
/**
 * Fix (audit report, Basse/Divers dashboard, "sourceId (GoAccess) est
 * injecte dans du JS inline") : buildWsOverrideScript() concatenait
 * `sourceId` (parametre de requete brut) directement dans un litteral de
 * chaine JavaScript inline, permettant a une valeur comme
 * `x'+alert(document.cookie)+'` de sortir du litteral et d executer du JS
 * arbitraire dans l origine du dashboard. JSON.stringify() echappe
 * correctement n importe quelle entree.
 */
const assert = require('assert');
const { buildWsOverrideScript } = require('../features/goaccess');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nbuildWsOverrideScript() — echappement du sourceId (fix XSS)');
check('un sourceId normal produit un script valide contenant son id', () => {
  const script = buildWsOverrideScript('site-fr');
  assert.ok(script.includes('"site-fr"'));
  assert.ok(script.startsWith('<script>'));
});
// Execute le script genere dans un bac a sable minimal, PUIS declenche
// reellement le chemin vulnerable : `new window.WebSocket(url)` avec une URL
// contenant ":7890", exactement ce que le report GoAccess fait lui-meme des
// son chargement. Sans cet appel, le payload injecte ne serait jamais
// evalue (il vit dans le corps du `try{}` de l override, qui n execute rien
// tant que le constructeur intercepte n est pas reellement invoque) — un
// test qui ne fait qu executer le <script> sans creer de WebSocket passerait
// a tort meme avec l ancien code vulnerable.
function runOverrideAndTriggerIt(script, urlWithPort) {
  const inner = script.replace(/^<script>\n/, '').replace(/<\/script>$/, '');
  let calledAlert = false;
  const fakeWindow = { WebSocket: function FakeWS(url){ this.url = url; } };
  new Function('window', 'location', 'URL', 'alert', inner)(
    fakeWindow, { protocol: 'http:', host: 'dashboard.local' }, URL,
    () => { calledAlert = true; }
  );
  new fakeWindow.WebSocket(urlWithPort); // declenche reellement le override
  return calledAlert;
}

// Le litteral JS source (avant ce correctif) qui encadrait sourceId etait
// delimite par des guillemets DOUBLES ("/api/goaccess/ws/" + sourceId +
// "..."), donc c est un GUILLEMET DOUBLE dans sourceId qui rompait le
// litteral et transformait la suite en code JS execute — c est exactement
// ce que verifient les deux payloads ci-dessous (verifie contre l ancien
// code, sans le correctif, avant d ecrire ce test : les deux declenchaient
// bien alert()).
check('un sourceId qui casse le litteral JS par des guillemets doubles reste contenu et inoffensif', () => {
  const payload = 'x"+alert(document.cookie)+"';
  const script = buildWsOverrideScript(payload);
  assert.ok(script.includes(JSON.stringify(payload)), 'le payload doit apparaitre sous forme d un litteral JSON.stringify correctement encadre');
  const calledAlert = runOverrideAndTriggerIt(script, 'ws://old-goaccess-host:7890/ws');
  assert.strictEqual(calledAlert, false, 'le payload a ete execute comme du code — echappement rompu');
});
check('variante avec commentaire JS pour neutraliser la suite de la ligne', () => {
  const payload = '"+alert(1)+"//';
  const script = buildWsOverrideScript(payload);
  assert.ok(script.includes(JSON.stringify(payload)), 'le payload doit apparaitre sous forme d un litteral JSON.stringify correctement encadre');
  let calledAlert;
  assert.doesNotThrow(() => { calledAlert = runOverrideAndTriggerIt(script, 'ws://old-goaccess-host:7890/ws'); },
    'le script genere doit rester syntaxiquement et semantiquement valide');
  assert.strictEqual(calledAlert, false, 'le payload a ete execute comme du code — echappement rompu');
});
check('le script genere reste syntaxiquement valide (parseable)', () => {
  const payload = "'; document.write('pwned');";
  const script = buildWsOverrideScript(payload);
  const inner = script.replace(/^<script>\n/, '').replace(/<\/script>$/, '');
  assert.doesNotThrow(() => new Function(inner), 'le script genere n est plus du JS valide');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
