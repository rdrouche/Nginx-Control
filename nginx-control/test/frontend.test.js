'use strict';
/**
 * L interface est un seul fichier de 5 000 lignes ou HTML et JavaScript se
 * melangent. Deux classes d erreur y sont invisibles jusqu au clic :
 *
 *  - un `onclick` qui appelle une fonction inexistante ;
 *  - une fonction definie deux fois, la seconde ecrasant silencieusement la
 *    premiere.
 *
 * Les deux se sont produites sur ce projet.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','public','index.html'),'utf8');
// Dictionnaires de traduction : extraits dans des fichiers separes (voir
// CHANGELOG.md, meme demarche que le CSS) — plus dans index.html lui-meme,
// charges en direct au demarrage via loadTranslations() (fetch).
const I18N_EN_RAW = fs.readFileSync(path.join(__dirname,'..','public','assets','lang','en.json'),'utf8');
const I18N_FR_RAW = fs.readFileSync(path.join(__dirname,'..','public','assets','lang','fr.json'),'utf8');
const I18N_EN = JSON.parse(I18N_EN_RAW);
const I18N_FR = JSON.parse(I18N_FR_RAW);
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

// Tous les blocs script, pas seulement le premier — y compris les scripts
// par page extraits dans des fichiers separes (public/assets/js/*.js, voir
// CHANGELOG.md) : un <script src="..."> n a pas de contenu inline, donc ces
// fonctions ne seraient sinon plus vues par aucun des controles ci-dessous.
const EXTERNAL_JS_SRCS=[...SRC.matchAll(/<script src="\/assets\/(js\/[^"]+\.js)"><\/script>/g)].map(m=>m[1]);
const externalScripts=EXTERNAL_JS_SRCS.map(rel=>fs.readFileSync(path.join(__dirname,'..','public','assets',rel),'utf8')).join('\n');
const scripts=[...SRC.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m=>m[1]).join('\n') + '\n' + externalScripts;
const html=SRC.replace(/<script[\s\S]*?<\/script>/g,'');
const defined=new Set([
  ...[...scripts.matchAll(/^\s*(?:async\s+)?function\s+(\w+)/gm)].map(m=>m[1]),
  ...[...scripts.matchAll(/^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(/gm)].map(m=>m[1]),
  ...[...scripts.matchAll(/^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function/gm)].map(m=>m[1]),
]);

console.log(`\nintegrite du frontend (${scripts.split('\n').length} lignes de script)`);

check('chaque handler inline existe', ()=>{
  const called=new Set([...html.matchAll(/on(?:click|change|input|submit|keydown)="(\w+)\(/g)].map(m=>m[1]));
  // Un handler peut commencer par un mot-cle : onclick="if(...)"
  const keywords=new Set(['if','for','while','return','typeof','void','delete','new','switch','do']);
  const missing=[...called].filter(f=>!defined.has(f)&&!keywords.has(f)).sort();
  assert.deepStrictEqual(missing,[],`introuvables : ${missing.join(', ')}`);
});

check('aucune fonction definie deux fois', ()=>{
  const names=[...scripts.matchAll(/^\s*(?:async\s+)?function\s+(\w+)/gm)].map(m=>m[1]);
  const dup={};
  for(const n of names) dup[n]=(dup[n]||0)+1;
  const twice=Object.entries(dup).filter(([,v])=>v>1).map(([k,v])=>`${k} (${v}x)`);
  assert.deepStrictEqual(twice,[],`redefinies : ${twice.join(', ')}`);
});

check('quotes equilibrees dans le JavaScript', ()=>{
  // Un onclick construit par concatenation avec des quotes mal echappees casse
  // le parsing du fichier entier.
  const bad=[];
  scripts.split('\n').forEach((l,i)=>{
    const x=l.rstrip? l.rstrip():l.replace(/\s+$/,'');
    const q=(x.match(/'/g)||[]).length-(x.match(/\\'/g)||[]).length;
    if(q%2===1 && !/\/\/|\/\*|\*|['"][^'"]*'[^'"]*['"]/.test(x)) bad.push(`L${i+1}: ${x.slice(0,70)}`);
  });
  assert.ok(bad.length<5,`lignes suspectes :\n        ${bad.slice(0,5).join('\n        ')}`);
});

console.log('\npages et navigation');
check('chaque entree de menu a sa page', ()=>{
  const navs=[...html.matchAll(/data-page="([\w-]+)"/g)].map(m=>m[1]);
  const pages=new Set([...html.matchAll(/id="page-([\w-]+)"/g)].map(m=>m[1]));
  const orphans=[...new Set(navs)].filter(p=>!pages.has(p)).sort();
  assert.deepStrictEqual(orphans,[],`sans page : ${orphans.join(', ')}`);
});

check('la page Analyse est presente et cablee', ()=>{
  assert.ok(html.includes('id="page-analyzer"'),'page absente');
  assert.ok(html.includes('data-page="analyzer"'),'entree de menu absente');
  assert.ok(scripts.includes('function initAnalyzer'),'initialisation absente');
  assert.ok(scripts.includes("page==='analyzer'"),'non declenchee a la navigation');
});

check('les donnees serveur passent par l API DOM', ()=>{
  // Une IP ou un agent utilisateur contient des quotes : les injecter dans un
  // onclick par concatenation casse silencieusement.
  // Fix (audit refactoring v12.48.0) : ce controle visait uniquement
  // analyzer.js, mais un slice(indexOf('ANALYSEUR DE JOURNAUX')) jusqu a la
  // fin de `scripts` capturait aussi, en pratique, TOUS les fichiers
  // externes charges apres lui (leur <script src> vient plus loin dans
  // index.html) — un faux negatif tant qu aucun d eux n utilisait ce motif,
  // devenu un faux positif des qu un fichier sans rapport (ex. sync-files.js,
  // ou idx est un simple entier de boucle, pas une donnee serveur) a fini
  // charge apres analyzer.js suite a une extraction. Lire directement le
  // fichier d analyzer.js cible le controle sur la fonctionnalite visee,
  // quel que soit l ordre des <script src> autour de lui.
  const an=fs.readFileSync(path.join(__dirname,'..','public','assets','js','analyzer.js'),'utf8');
  assert.ok(!/onclick="[^"]*'\s*\+/.test(an),'onclick construit par concatenation');
  assert.ok(an.includes('createElement'),'devrait utiliser l API DOM');
});
console.log('\ncarte en direct : tracé reel du monde (pas de corruption du gros bloc integre)');
check('GM_WORLD_PATH est present et d une taille plausible', () => {
  // Extrait dans public/assets/js/geomap.js (voir CHANGELOG.md) : on cherche
  // donc dans `scripts` (SRC + tous les <script src> par page), pas dans SRC
  // seul, sinon ce controle ne voit plus jamais la constante.
  const m = scripts.match(/const GM_WORLD_PATH = '([^']*)'/);
  assert.ok(m, 'la constante doit exister sous forme de chaine simple (aucun guillemet dans les donnees)');
  const len = m[1].length;
  assert.ok(len > 30000 && len < 80000, `taille inattendue : ${len} octets`);
});
check('le trace est syntaxiquement equilibre (autant de M que de Z)', () => {
  const m = scripts.match(/const GM_WORLD_PATH = '([^']*)'/);
  const d = m[1];
  const mCount = (d.match(/M/g) || []).length;
  const zCount = (d.match(/Z/g) || []).length;
  assert.strictEqual(mCount, zCount, 'chaque sous-trace M doit se refermer par un Z');
  assert.ok(mCount > 200, `attendu au moins 200 sous-traces (pays + iles), obtenu ${mCount}`);
});

console.log('\npoll() : une panne de /api/status ne doit jamais faire taire la carte ou le graphe req/s');
check("gmPoll() et loadRpsChart() sont hors du try/catch partage avec /status et /metrics", () => {
  // Bug reel, trouve avec un vrai navigateur automatise : gmPoll() et
  // loadRpsChart() vivaient a l interieur du meme try/catch que la recuperation
  // de /api/status et /api/metrics. Une panne de nginx (redemarrage, VTS pas
  // encore pret, reseau instable) faisait donc taire silencieusement la carte
  // en direct ET le graphe requetes/sec — sans la moindre trace en console, le
  // seul signe visible etant un petit point rouge "Offline" dans l en-tete,
  // facilement invisible en regardant la carte plutot que l en-tete. Confirme
  // avec un vrai navigateur automatise avant correctif, puis apres.
  const m = SRC.match(/async function poll\(\)\{([\s\S]*?)\n\}\n\n\/\//);
  assert.ok(m, 'la fonction poll() doit etre localisable');
  const body = m[1];

  const tryStart = body.indexOf('try{');
  const catchMarker = '}catch(e){';
  const catchStart = body.indexOf(catchMarker, tryStart);
  assert.ok(tryStart >= 0 && catchStart > tryStart, 'poll() doit garder un bloc try/catch pour /status et /metrics');
  const catchBodyEnd = body.indexOf('\n  }\n', catchStart);
  const tryAndCatchBlock = body.slice(tryStart, catchBodyEnd);
  const afterCatchBlock = body.slice(catchBodyEnd);

  assert.ok(!/gmPoll\(\)/.test(tryAndCatchBlock),
    'gmPoll() ne doit jamais etre appelee a l interieur du try/catch de /status et /metrics');
  assert.ok(!/loadRpsChart\(\)/.test(tryAndCatchBlock),
    'loadRpsChart() ne doit jamais etre appelee a l interieur du try/catch de /status et /metrics');
  assert.ok(/gmPoll\(\)/.test(afterCatchBlock), 'gmPoll() doit toujours etre appelee, mais apres le try/catch');
  assert.ok(/loadRpsChart\(\)/.test(afterCatchBlock), 'loadRpsChart() doit toujours etre appelee, mais apres le try/catch');
});
check("l echec de gmPoll() ou loadRpsChart() est logge, pas avale en silence", () => {
  const m = SRC.match(/async function poll\(\)\{([\s\S]*?)\n\}\n\n\/\//);
  const body = m[1];
  const catchStart = body.indexOf('}catch(e){');
  const afterCatchBlock = body.slice(body.indexOf('\n  }\n', catchStart));
  assert.ok(/catch\(e\)\s*\{\s*console\.warn\([^)]*echec loadRpsChart/.test(afterCatchBlock),
    'un echec de loadRpsChart doit etre visible en console, pas silencieux');
  assert.ok(/catch\(e\)\s*\{\s*console\.warn\([^)]*echec gmPoll/.test(afterCatchBlock),
    'un echec de gmPoll doit etre visible en console, pas silencieux');
});
check("la page Analyse se rafraichit toutes les 5s comme le reste du dashboard", () => {
  // anLoadTraffic()/anLoadBotStats() n etaient appelees qu a l ouverture de
  // la page ou au changement d onglet — jamais en continu, contrairement a
  // Overview et a la Carte. Un operateur qui restait sur cette page voyait
  // des chiffres figes, a tort pris pour une panne.
  const m = SRC.match(/async function poll\(\)\{([\s\S]*?)\n\}\n\n\/\//);
  const body = m[1];
  const catchStart = body.indexOf('}catch(e){');
  const afterCatchBlock = body.slice(body.indexOf('\n  }\n', catchStart));
  assert.ok(/page-analyzer.*classList\.contains\('active'\)/.test(afterCatchBlock.replace(/\n/g,' ')),
    'poll() doit verifier si la page Analyse est active');
  assert.ok(/anLoadTraffic\(\)/.test(afterCatchBlock), 'anLoadTraffic() doit etre appelee dans le cycle de sondage');
  assert.ok(/anLoadBotStats\(\)/.test(afterCatchBlock), 'anLoadBotStats() doit etre appelee dans le cycle de sondage');
});


check('an-bot-card annule explicitement overflow:hidden de la classe .sc', () => {
  // Bug reel, trouve apres signalement : la classe .sc (carte de statistique,
  // reutilisee partout dans le dashboard) porte overflow:hidden. L infobulle
  // du survol des robots, positionnee en absolu et debordant sous la carte,
  // etait donc invisible — techniquement affichee (display:block), mais
  // decoupee par son parent. Ni un test de syntaxe ni jsdom (qui ne calcule
  // pas le rendu visuel) ne l auraient detecte ; seule une verification
  // explicite de cette regle precise le peut.
  const m = SRC.match(/<div class="sc" id="an-bot-card" style="([^"]*)"/);
  assert.ok(m, 'la carte an-bot-card doit exister avec sa classe .sc');
  assert.ok(/overflow:visible/.test(m[1]),
    'doit annuler explicitement le overflow:hidden herite de .sc, sinon l infobulle est invisible');
});

console.log('\nanimation des points de la carte : timeline relative a l insertion, pas au document');
check('gmPulse n utilise pas SMIL <animate> avec begin/freeze (timeline du document)', () => {
  // Bug reel, cause racine du symptome « les points s affichent a la premiere
  // vue, disparaissent, puis plus rien ». En SMIL, `begin` est relatif a la
  // timeline du DOCUMENT, pas a l insertion de l element : un begin="4.5s"
  // avec fill="freeze" sur un point insere alors que la page est ouverte
  // depuis plus de 4,5 s voyait son animation deja terminee, et le point
  // etait fige a opacity:0 — present dans le DOM, mais invisible. Les tests
  // precedents comptaient les <circle> du DOM et passaient donc a cote.
  // Verifie en isolation dans un vrai navigateur : meme element, opacite 1 a
  // t=0.3s, opacite 0 a t=6.6s.
  const m = scripts.match(/function gmPulse\(country, category\) \{([\s\S]*?)\n\}/);
  assert.ok(m, 'gmPulse doit etre localisable');
  const body = m[1];
  assert.ok(!/createElementNS\([^,]+,\s*'animate'\)/.test(body),
    'gmPulse ne doit pas creer d element SMIL <animate> : sa timeline est celle du document');
  assert.ok(!/setAttribute\('begin'/.test(body),
    "l attribut SMIL begin est relatif au document et rend les points invisibles apres quelques secondes");
});
check('gmPulse anime via l API Web Animations (timeline relative a l appel)', () => {
  const m = scripts.match(/function gmPulse\(country, category\) \{([\s\S]*?)\n\}/);
  const body = m[1];
  const animateCalls = body.match(/\.animate\(/g) || [];
  assert.strictEqual(animateCalls.length, 2,
    'le point et l anneau doivent chacun etre animes via element.animate()');
  assert.ok(/fill:\s*'forwards'/.test(body), 'les animations doivent conserver leur etat final');
});

console.log('\naucun doublon de cle de traduction (garde-fou general, pas seulement la carte)');
check('aucune cle du dictionnaire en/fr n a plus d une valeur (semantique JS : la derniere l emporte, en silence)', () => {
  // Bug reel signale : 58 cles reparties sur CrowdSec, la synchronisation de
  // fichiers de reference et le generateur de VHost portaient du texte dans
  // la mauvaise langue. Cause : un bloc entier de traductions duplique au
  // mauvais endroit — la deuxieme occurrence d une meme cle dans un objet
  // litteral JavaScript ecrase silencieusement la premiere, sans la moindre
  // erreur ni avertissement. Ce test verifie qu aucune cle n a plus d une
  // valeur DISTINCTE dans chacun des deux dictionnaires — il aurait attrape
  // les 58 cles d un coup, plutot que de les decouvrir une par une au fil
  // de signalements successifs.
  // JSON.parse() a exactement la meme semantique "la derniere cle ecrase la
  // precedente, en silence" qu un objet litteral JS — le bug reel decrit
  // ci-dessus reste tout aussi possible dans les fichiers separes. On
  // detecte donc les doublons sur le TEXTE BRUT (avant parsing), pas sur
  // l objet deja aplati par JSON.parse.
  function findDuplicates(raw) {
    const byKey = new Map();
    for (const line of raw.split('\n')) {
      const kv = line.match(/^\s*"([a-zA-Z0-9_.]+)":\s*(.+?),?\s*$/);
      if (!kv) continue;
      const [, key, value] = kv;
      if (!byKey.has(key)) byKey.set(key, new Set());
      byKey.get(key).add(value.replace(/,$/, ''));
    }
    return [...byKey.entries()].filter(([, vals]) => vals.size > 1);
  }

  const enDupes = findDuplicates(I18N_EN_RAW);
  const frDupes = findDuplicates(I18N_FR_RAW);
  assert.strictEqual(enDupes.length, 0,
    `cles avec des valeurs divergentes dans en: ${JSON.stringify(enDupes.map(([k])=>k))}`);
  assert.strictEqual(frDupes.length, 0,
    `cles avec des valeurs divergentes dans fr: ${JSON.stringify(frDupes.map(([k])=>k))}`);
});

console.log('\ncouverture i18n generale : tout appel t(\'cle\') litteral doit exister dans les deux dictionnaires');
check('aucune cle appelee via t() ne manque, dans aucune des deux langues (garde-fou general, toute page)', () => {
  // Seuls les appels a une CLE LITTERALE sont verifiables ici (celles
  // construites par concatenation, ex. t('sync.status.' + item.status),
  // sont exclues par construction : le regex n accepte qu une virgule ou
  // une parenthese fermante juste apres la chaine).
  const used = new Set([...scripts.matchAll(/\bt\(\s*'([a-zA-Z0-9_.]+)'\s*[,)]/g)].map(m => m[1]));
  const missingEn = [...used].filter(k => !(k in I18N_EN)).sort();
  const missingFr = [...used].filter(k => !(k in I18N_FR)).sort();
  assert.deepStrictEqual(missingEn, [], `cles manquantes en anglais : ${missingEn.join(', ')}`);
  assert.deepStrictEqual(missingFr, [], `cles manquantes en francais : ${missingFr.join(', ')}`);
});

check('tout data-i18n / data-i18n-title / data-i18n-placeholder du HTML a sa cle dans les deux langues', () => {
  const used = new Set([
    ...html.matchAll(/data-i18n="([a-zA-Z0-9_.]+)"/g),
    ...html.matchAll(/data-i18n-title="([a-zA-Z0-9_.]+)"/g),
    ...html.matchAll(/data-i18n-placeholder="([a-zA-Z0-9_.]+)"/g),
  ].map(m => m[1]));
  const missingEn = [...used].filter(k => !(k in I18N_EN)).sort();
  const missingFr = [...used].filter(k => !(k in I18N_FR)).sort();
  assert.deepStrictEqual(missingEn, [], `cles manquantes en anglais : ${missingEn.join(', ')}`);
  assert.deepStrictEqual(missingFr, [], `cles manquantes en francais : ${missingFr.join(', ')}`);
});

console.log('\ntraduction de la carte en direct (EN/FR)');
check('toutes les cles data-i18n de la page carte existent dans en et fr', () => {
  const pageMatch = SRC.match(/<!-- CARTE EN DIRECT -->([\s\S]*?)<!-- GODNS -->/);
  assert.ok(pageMatch, 'la page carte doit etre localisable');
  const keys = [...pageMatch[1].matchAll(/data-i18n="([^"]+)"/g)].map(m => m[1]);
  assert.ok(keys.length >= 10, `attendu au moins 10 cles data-i18n sur la page carte, trouve ${keys.length}`);

  for (const key of keys) {
    assert.ok(Object.prototype.hasOwnProperty.call(I18N_EN, key), `cle manquante en anglais : ${key}`);
    assert.ok(Object.prototype.hasOwnProperty.call(I18N_FR, key), `cle manquante en francais : ${key}`);
  }
  // Le lien de menu utilise aussi data-i18n, en dehors du bloc de la page.
  assert.ok(SRC.includes(`data-i18n="nav.geomap"`), 'le lien de menu de la carte doit etre traduit');
  assert.ok('nav.geomap' in I18N_EN && 'nav.geomap' in I18N_FR,
    'nav.geomap doit exister dans les deux langues');
});

console.log('\ntraduction de la page Deploiement Git (EN/FR)');
check('toutes les cles data-i18n de la page Deploiement existent dans en et fr', () => {
  // La page existait avec des cles "deploy.*" deja presentes dans les deux
  // dictionnaires, mais jamais posees sur le HTML ni jamais lues par le JS
  // (extrait depuis dans public/assets/js/git.js) : le texte affiche restait
  // donc toujours en francais, quelle que soit la langue choisie. Ce test
  // verifie que le HTML de la page pose bien des data-i18n, et que chacune
  // resout dans les deux dictionnaires.
  const pageMatch = SRC.match(/<!-- DEPLOY -->([\s\S]*?)<!-- BACKUPS -->/);
  assert.ok(pageMatch, 'la page Deploiement Git doit etre localisable');
  const keys = [...pageMatch[1].matchAll(/data-i18n="([^"]+)"/g)].map(m => m[1]);
  assert.ok(keys.length >= 10, `attendu au moins 10 cles data-i18n sur la page Deploiement, trouve ${keys.length}`);
  for (const key of keys) {
    assert.ok(Object.prototype.hasOwnProperty.call(I18N_EN, key), `cle manquante en anglais : ${key}`);
    assert.ok(Object.prototype.hasOwnProperty.call(I18N_FR, key), `cle manquante en francais : ${key}`);
  }
});

check('git.js ne contient plus de texte francais code en dur (tout passe par t())', () => {
  // Bug reel corrige a l extraction : le texte de toute la page (statuts,
  // boutons, messages de test de connexion, etapes du pipeline) etait ecrit
  // en dur en francais dans index.html, affiche identique quelle que soit
  // la langue choisie. On verifie ici qu aucune des chaines les plus
  // visibles n est revenue en dur dans le fichier extrait.
  const gitJs = fs.readFileSync(path.join(__dirname,'..','public','assets','js','git.js'),'utf8');
  const hardcodedFrench = [
    'Pull (sans déployer)', 'Tester la config (conteneur éphémère)',
    'Déployer (test', 'Tester la connexion Git', 'Initialiser la branche backup',
    'Chargement…', 'Erreur API', 'Dépôt', 'Branche backup', 'Commit local',
    'Commit distant', 'À jour', 'Mise à jour disponible', 'Aucune différence',
    'Connexion OK', 'Branches distantes', 'INTROUVABLE', 'Erreur connexion',
  ];
  const found = hardcodedFrench.filter(s => gitJs.includes(s));
  assert.deepStrictEqual(found, [], `texte francais code en dur retrouve : ${found.join(', ')}`);
});
check('gmCategoryLabel() est la seule source de libelles de categorie bot (carte + page Analyse)', () => {
  // GM_CATEGORY_LABEL (brut, francais) ne doit plus servir que de repli
  // interne a gmCategoryLabel() — ni la carte ni la page Analyse
  // (public/assets/js/analyzer.js, traduite depuis sa propre passe i18n) ne
  // doivent le lire directement, sous peine de retomber en francais force.
  assert.ok(/function gmCategoryLabel\(category\)/.test(scripts),
    'la fonction de traduction des categories doit exister');
  assert.ok(/textContent = gmCategoryLabel\(e\.category\)/.test(scripts),
    'la liste des derniers pays actifs (carte) doit utiliser la version traduite');
  assert.ok(externalScripts.includes('label.textContent = gmCategoryLabel(row.category)'),
    'la page Analyse doit utiliser la version traduite, pas GM_CATEGORY_LABEL brut');
  assert.ok(!/GM_CATEGORY_LABEL\[row\.category\]/.test(externalScripts),
    'la page Analyse ne doit plus lire GM_CATEGORY_LABEL directement');
});

console.log('\nidentification visuelle de l origine des decisions CrowdSec');
check('cscli (bannissement manuel) a un badge distinct, pas la couleur generique', () => {
  // csOriginBadge() vit desormais dans public/assets/js/crowdsec.js (voir
  // CHANGELOG.md) — on la cherche donc dans `scripts` (inline + fichiers
  // externes), pas dans `SRC` (index.html seul).
  assert.ok(/origin === 'cscli'\)\s*return \{ cls: 'bl'/.test(scripts),
    'un ban manuel (origine cscli) doit se distinguer visuellement du reste, sinon indiscernable d une valeur inattendue');
});

console.log('\nverification des mises a jour (nginx) : variantes -waf/-coraza');
check('stripVer() ignore le suffixe de variante, sinon une image a jour est signalee obsolete a vie', () => {
  // Signalement reel : "Nginx: 1.30.5-waf -> 1.30.5" affiche comme mise a
  // jour disponible alors que 1.30.5-waf EST la 1.30.5. La comparaison
  // vit entierement cote client (stripVer, dans checkUpdates()) ; on
  // extrait la vraie ligne source et on l execute, plutot que de retester
  // une copie qui pourrait diverger silencieusement du code livre.
  // checkUpdates() (et stripVer avec elle) vit desormais dans
  // public/assets/js/version-check.js (voir CHANGELOG.md) — on la cherche
  // donc dans `scripts` (inline + fichiers externes), pas dans `SRC`
  // (index.html seul), sans quoi l extraction rend ce controle aveugle.
  const m = scripts.match(/const stripVer = (v => \([^;]+\));/);
  assert.ok(m, 'stripVer() introuvable ou sa forme a change');
  const stripVer = new Function('return ' + m[1])();
  assert.strictEqual(stripVer('1.30.5-waf'), stripVer('1.30.5'),
    'une image -waf ne doit jamais paraitre "differente" de la version bare equivalente');
  assert.strictEqual(stripVer('1.30.5-coraza'), '1.30.5');
  assert.strictEqual(stripVer('1.30.5-WAF'), '1.30.5', 'insensible a la casse');
  assert.strictEqual(stripVer('nginx/1.30.5-waf'), '1.30.5', 'cumulable avec le prefixe nginx/');
  assert.strictEqual(stripVer('v1.30.5'), '1.30.5', 'le "v" en tete reste strippe');
  // Un vrai changement de version ne doit pas etre masque par erreur.
  assert.notStrictEqual(stripVer('1.30.5-waf'), stripVer('1.30.6'));
});

console.log('\ntheme de couleur (vert par defaut / bleu en option)');
check('style.css definit --accent (par defaut = --green) et sa surcharge [data-theme="blue"]', () => {
  const css = fs.readFileSync(path.join(__dirname,'..','public','assets','style.css'),'utf8');
  assert.ok(/--accent:var\(--green\)/.test(css), '--accent doit valoir --green par defaut (theme historique inchange)');
  assert.ok(/:root\[data-theme="blue"\]\{[^}]*--accent:/.test(css), 'la surcharge bleue de --accent est introuvable');
});
check('setColorTheme() persiste le choix et applique/retire data-theme sur <html>', () => {
  assert.ok(/function setColorTheme\(theme\)/.test(scripts));
  assert.ok(/localStorage\.setItem\('ngx_theme', theme\)/.test(scripts));
  assert.ok(/document\.documentElement\.setAttribute\('data-theme', theme\)/.test(scripts));
});
check('le theme choisi est applique avant le premier rendu (script synchrone dans <head>), pas seulement au boot JS', () => {
  const headScript = SRC.slice(0, SRC.indexOf('<link href="/assets/style.css"'));
  assert.ok(/localStorage\.getItem\('ngx_theme'\)/.test(headScript),
    'sans ca, la page flashe le theme par defaut (vert) avant que le script principal ne s execute');
});

console.log('\nmenu de navigation : sections repliables + traduction des en-tetes');
check('les 5 en-tetes de section (.ns) portent toutes data-i18n sur un <span> enfant, plus aucune sur la div elle-meme', () => {
  // Bug reel : "Configuration", "Controle" et "Integrations" avaient un
  // texte fige dans la div .ns alors que les cles nav.section.config/
  // control/integrations existaient deja, pretes a l emploi, dans les deux
  // dictionnaires — meme classe de bug que les items de nav corriges plus tot.
  const nsBlocks = [...html.matchAll(/<div class="ns"[^>]*>([\s\S]*?)<\/div>/g)];
  assert.strictEqual(nsBlocks.length, 5, 'les 5 sections du menu doivent toutes matcher ce gabarit');
  for (const key of ['monitoring','config','control','integrations','admin']) {
    assert.ok(new RegExp(`data-section="${key}"[\\s\\S]{0,40}<span data-i18n="nav\\.section\\.${key}"`).test(html),
      `section "${key}" : data-i18n doit etre sur le <span> enfant, pas sur la div .ns`);
  }
  assert.ok(!/<div class="ns"[^>]*data-i18n=/.test(html),
    'data-i18n ne doit plus etre pose directement sur .ns (il ecraserait le chevron ajoute a cote du libelle)');
});
check('chaque item de menu (.ni) a son libelle dans un <span data-i18n>, jamais en texte fige', () => {
  // Bug reel (v12.46.0) : "Deploiement Git" (.ni data-page="deploy") etait
  // ecrit en dur dans le HTML alors que la cle nav.deploy existait deja,
  // prete a l emploi, dans les deux dictionnaires (meme classe de bug que
  // les en-tetes de section .ns corriges plus haut) — invisible tant qu on
  // ne passait pas le dashboard en anglais. Ce test scanne CHAQUE item de
  // menu : une fois l icone SVG et les <span> (libelle traduit, badge de
  // compteur) retires, il ne doit plus rester le moindre texte a l air libre.
  const niBlocks = [...html.matchAll(/<div class="ni"[^>]*data-page="([^"]+)"[^>]*>([\s\S]*?)<\/div>/g)];
  assert.ok(niBlocks.length >= 15, `attendu au moins 15 items de menu (.ni), trouve ${niBlocks.length}`);
  const offenders = [];
  for (const [, page, inner] of niBlocks) {
    const stripped = inner
      .replace(/<svg[\s\S]*?<\/svg>/g, '')
      .replace(/<span[^>]*>[\s\S]*?<\/span>/g, '')
      .trim();
    if (stripped) offenders.push(`${page}: "${stripped}"`);
  }
  assert.deepStrictEqual(offenders, [], `item(s) de menu avec du texte fige hors <span data-i18n> : ${offenders.join(', ')}`);
});
check('chaque section a son chevron de repli/depli (.ns-chevron)', () => {
  const nsCount = [...html.matchAll(/<div class="ns"/g)].length;
  const chevronCount = [...html.matchAll(/class="ns-chevron"/g)].length;
  assert.strictEqual(chevronCount, nsCount, 'chaque .ns doit avoir exactement un chevron');
});
check('initNavSections() regroupe les .ni par section, bascule .collapsed/.nav-hidden et persiste par section', () => {
  assert.ok(/function initNavSections\(\)/.test(scripts), 'initNavSections() introuvable');
  assert.ok(/function navSectionItems\(nsEl\)/.test(scripts), 'le regroupement des .ni suivant chaque .ns doit etre factorise, pas duplique inline');
  assert.ok(/localStorage\.setItem\(NAV_COLLAPSE_KEY/.test(scripts), 'l etat replie/deplie doit etre persiste (sinon tout se re-deplie a chaque rafraichissement)');
  assert.ok(/localStorage\.getItem\(NAV_COLLAPSE_KEY/.test(scripts));
  assert.ok(/classList\.toggle\('collapsed'/.test(scripts));
  assert.ok(/classList\.toggle\('nav-hidden'/.test(scripts));
});
check('initNavSections() est bien appele au demarrage', () => {
  assert.ok(/initNavSections\(\);/.test(scripts));
});

console.log('\nDiagnostic / Securite : le backend "sans cible" ne doit plus s afficher comme un ECHEC');
check('sideStatus() distingue r.skipped (badge neutre) de r.ok===false (badge ECHEC rouge)', () => {
  // Signalement reel : un vhost redirect-only (aucune location proxy_pass)
  // affichait "Backend : ECHEC" en rouge, alors qu il n y avait simplement
  // rien a tester de ce cote — voir features/audit.js (backendResult.skipped).
  const m = scripts.match(/const sideStatus = \(label, r\) => `[\s\S]*?`;/);
  assert.ok(m, 'sideStatus() introuvable ou sa forme a change');
  assert.ok(/r\?\.skipped/.test(m[0]), 'le cas "rien a tester" (skipped) doit etre teste separement de r.ok');
  assert.ok(!/badge rd">ÉCHEC<\/span>[^`]*r\?\.skipped/.test(m[0]),
    'le badge ECHEC ne doit pas etre le rendu par defaut pour un resultat skipped');
});

console.log('\nDiagnostic : recherche + filtre Tous/Actif/Désactivé sur la grille de vhosts');
check('diagFilteredEntries() filtre par etat (enabled) et par recherche (nom de fichier ou server_name), et conserve l index d origine', () => {
  const m = scripts.match(/function diagFilteredEntries\(\)\{([\s\S]*?)\n\}\n\nfunction renderDiagGrid/);
  assert.ok(m, 'diagFilteredEntries() introuvable ou sa forme a change');
  const fn = new Function('document', 'diagVhosts', 'diagStateFilter', m[1]);

  const vhosts = [
    { name: 'a-plain.conf', enabled: true,  serverBlocks: [{ serverNames: ['plain.example.com'] }] },
    { name: 'b-api.conf',   enabled: true,  serverBlocks: [{ serverNames: ['api.example.com'] }] },
    { name: 'c-old.conf.DISABLE', enabled: false, serverBlocks: [{ serverNames: ['old.example.com'] }] },
  ];
  const fakeDoc = (value) => ({ getElementById: (id) => id === 'diag-search' ? { value } : null });

  const all = fn(fakeDoc(''), vhosts, 'all');
  assert.strictEqual(all.length, 3, 'sans filtre ni recherche, les trois vhosts doivent ressortir');
  assert.deepStrictEqual(all.map(e => e.idx), [0, 1, 2],
    'l index d origine dans diagVhosts doit etre conserve (utilise par onclick="openDiagPanel(idx)")');

  const onlyEnabled = fn(fakeDoc(''), vhosts, 'enabled');
  assert.deepStrictEqual(onlyEnabled.map(e => e.v.name), ['a-plain.conf', 'b-api.conf']);

  const onlyDisabled = fn(fakeDoc(''), vhosts, 'disabled');
  assert.deepStrictEqual(onlyDisabled.map(e => e.v.name), ['c-old.conf.DISABLE']);

  const byFilename = fn(fakeDoc('api'), vhosts, 'all');
  assert.deepStrictEqual(byFilename.map(e => e.v.name), ['b-api.conf'], 'recherche par nom de fichier');

  const byServerName = fn(fakeDoc('old.example'), vhosts, 'all');
  assert.deepStrictEqual(byServerName.map(e => e.v.name), ['c-old.conf.DISABLE'], 'recherche par server_name');

  const combined = fn(fakeDoc('example'), vhosts, 'enabled');
  assert.deepStrictEqual(combined.map(e => e.v.name), ['a-plain.conf', 'b-api.conf'],
    'recherche et filtre d etat doivent se combiner (ET logique), pas s ecraser l un l autre');

  const caseInsensitive = fn(fakeDoc('API'), vhosts, 'all');
  assert.strictEqual(caseInsensitive.length, 1, 'la recherche doit etre insensible a la casse');
});
check('renderDiagGrid() existe, remplace l ancien rendu inline de loadDiagnostic(), et setDiagStateFilter() bascule les boutons actifs', () => {
  assert.ok(/function renderDiagGrid\(\)/.test(scripts));
  assert.ok(/function setDiagStateFilter\(state\)/.test(scripts));
  assert.ok(/diagStateFilter = state/.test(scripts));
  assert.ok(/renderDiagGrid\(\);/.test(scripts), 'renderDiagGrid() doit etre appele (au chargement et sur changement de filtre/recherche)');
});

console.log('\nCentre de notification : place dans le header entre lang-switcher et user-pill, i18n, rendu');
check('le bloc #notif-center est bien entre .lang-switcher et .user-pill (emplacement demande explicitement)', () => {
  const langIdx  = html.indexOf('class="lang-switcher"');
  const notifIdx = html.indexOf('id="notif-center"');
  const userIdx  = html.indexOf('id="user-pill"');
  assert.ok(langIdx !== -1 && notifIdx !== -1 && userIdx !== -1, 'un des trois marqueurs est introuvable');
  assert.ok(langIdx < notifIdx && notifIdx < userIdx, 'le centre de notification doit se trouver entre les deux');
});
check('la cloche, le badge et le dropdown existent avec leurs handlers', () => {
  assert.ok(/id="notif-bell"[\s\S]{0,200}onclick="toggleNotifCenter\(event\)"/.test(html));
  assert.ok(/id="notif-badge"/.test(html));
  assert.ok(/id="notif-dropdown"/.test(html));
  assert.ok(/id="notif-list"/.test(html));
});
check('renderNotifList()/renderNotifBadge()/toggleNotifCenter()/notifCenterPoll() existent et sont bien appeles depuis leur propre cycle (v12.21.2 : decouple de poll(), delai configurable)', () => {
  assert.ok(/function renderNotifList\(\)/.test(scripts));
  assert.ok(/function renderNotifBadge\(\)/.test(scripts));
  assert.ok(/function toggleNotifCenter\(ev\)/.test(scripts));
  assert.ok(/async function notifCenterPoll\(\)/.test(scripts));
  // v12.21.2 : notifCenterPoll() n est plus attele au cycle fixe de poll() (5s) —
  // il a son propre setInterval, cadence par window.NOTIF_POLL_INTERVAL_MS
  // (lui-meme derive de la var d env NOTIF_POLL_INTERVAL_SEC, configurable
  // depuis la page Systeme). On verifie que ce cycle dedie existe bien.
  assert.ok(/setInterval\(\s*\(\)\s*=>\s*\{\s*\n\s*notifCenterPoll\(\)/.test(scripts) ||
            /setInterval\(\(\) => \{\s*\n\s*notifCenterPoll\(\)/.test(scripts),
    'notifCenterPoll() doit tourner sur son propre setInterval');
  assert.ok(/window\.NOTIF_POLL_INTERVAL_MS/.test(scripts),
    'le delai de notifCenterPoll() doit etre configurable via window.NOTIF_POLL_INTERVAL_MS');
  // et il ne doit plus etre appele en dur depuis le corps de poll()
  const pollFn = scripts.match(/async function poll\(\)\{[\s\S]*?\n\}/);
  assert.ok(pollFn, 'poll() introuvable');
  assert.ok(!/notifCenterPoll\(\)/.test(pollFn[0]),
    'notifCenterPoll() ne doit plus etre appele depuis poll() (decouple en v12.21.2)');
});
check('markRead/delete/markAllRead/clearRead/clearAll appellent bien les routes /api/notifications correspondantes', () => {
  assert.ok(/api\(`\/notifications\/\$\{id\}\/read`, \{ method: 'POST' \}\)/.test(scripts));
  assert.ok(/api\(`\/notifications\/\$\{id\}`, \{ method: 'DELETE' \}\)/.test(scripts));
  assert.ok(/api\('\/notifications\/read-all', \{ method: 'POST' \}\)/.test(scripts));
  assert.ok(/api\('\/notifications\/clear-read', \{ method: 'POST' \}\)/.test(scripts));
  assert.ok(/api\('\/notifications\/clear', \{ method: 'POST' \}\)/.test(scripts));
});
check('les messages/type sont echappes via h() avant insertion dans le DOM (pas d injection depuis data/message)', () => {
  const m = scripts.match(/function renderNotifList\(\)\{[\s\S]*?\n\}/);
  assert.ok(m, 'renderNotifList() introuvable');
  assert.ok(/h\(n\.message\)/.test(m[0]));
  assert.ok(/h\(n\.type\)/.test(m[0]));
});
check('regression : .notif-bell remet le padding a 0 (bug reel — la regle generique ' +
      '"button,.btn{padding:7px 14px}" ne laissait plus que 2px de large pour l icone ' +
      'dans une boite fixe 32x32 en border-box, rendant la cloche invisible)', () => {
  const css = fs.readFileSync(path.join(__dirname, '..', 'public', 'assets', 'style.css'), 'utf8');
  const m = css.match(/\.notif-bell\{[^}]*\}/);
  assert.ok(m, '.notif-bell introuvable dans style.css');
  assert.ok(/padding:\s*0\b/.test(m[0]), '.notif-bell doit fixer padding:0 : ' + m[0]);
});
check('regression : ouvrir la cloche relance immediatement notifCenterPoll() (bug reel — le ' +
      'dropdown ne montrait que les donnees du dernier cycle poll() de 5s ; une notification ' +
      'poussee juste avant l ouverture restait invisible jusqu au prochain tick)', () => {
  const m = scripts.match(/function toggleNotifCenter\(ev\)\{[\s\S]*?\n\}/);
  assert.ok(m, 'toggleNotifCenter() introuvable');
  assert.ok(/notifCenterPoll\(\)/.test(m[0]),
    'toggleNotifCenter() doit appeler notifCenterPoll() a l ouverture, pas seulement renderNotifList() sur le cache : ' + m[0]);
});

console.log('\nPage Notifications (historique complet) : nav, filtres, pagination');
check('le nav item et la page #page-notif-history existent avec leur badge', () => {
  assert.ok(/data-page="notif-history"/.test(html));
  assert.ok(/id="page-notif-history"/.test(html));
  assert.ok(/id="notif-nav-badge"/.test(html));
});
check('le dispatcher de nav charge bien loadNotificationsPage() sur ce nav item', () => {
  assert.ok(/page==='notif-history'\)\s*loadNotificationsPage\(\)/.test(scripts));
});
check('la page expose recherche + filtres niveau/etat + pagination "charger plus"', () => {
  assert.ok(/id="notif-page-search"/.test(html));
  assert.ok(/id="notif-page-list"/.test(html));
  assert.ok(/id="notif-page-more"/.test(html));
  assert.ok(/function loadNotificationsPage\(\)/.test(scripts));
  assert.ok(/function notifPageFilteredEntries\(\)/.test(scripts));
  assert.ok(/function notifPageLoadMore\(\)/.test(scripts));
});
check('le lien "Voir tout l\'historique" du dropdown ouvre bien la page dediee', () => {
  assert.ok(/onclick="notifGoToHistoryPage\(\)"/.test(html));
  assert.ok(/function notifGoToHistoryPage\(\)/.test(scripts));
});
check('renderNotifBadge() synchronise aussi le badge du nav item (#notif-nav-badge)', () => {
  const m = scripts.match(/function renderNotifBadge\(\)\{[\s\S]*?\n\}/);
  assert.ok(m, 'renderNotifBadge() introuvable');
  assert.ok(/notif-nav-badge/.test(m[0]), 'renderNotifBadge() doit aussi mettre a jour #notif-nav-badge : ' + m[0]);
});

console.log('\nmodale "Regles" (page Analyse) : catalogue integre + regles personnalisees YAML');
check('le bouton "Regles" ouvre la modale, elle-meme presente avec ses zones', () => {
  assert.ok(/onclick="rulesOpen\(\)"/.test(html));
  assert.ok(/id="rules-modal-overlay"/.test(html));
  assert.ok(/id="rules-builtin-list"/.test(html));
  assert.ok(/id="rb-list"/.test(html));          // onglet « Mes regles » (formulaire, v12.61.0)
  assert.ok(/id="rb-tpl-list"/.test(html));      // onglet « Modeles »
  assert.ok(/id="rules-custom-yaml"/.test(html)); // onglet « Mode avance (YAML) »
  for (const tab of ['builtin', 'mine', 'templates', 'yaml']) assert.ok(new RegExp('id="rb-tab-' + tab + '"').test(html), tab);
});
check('formulaire de regles : toute valeur issue des regles passe par h() (pas d\'injection HTML)', () => {
  const rb = fs.readFileSync(path.join(__dirname, '..', 'public', 'assets', 'js', 'rules-builder.js'), 'utf8');
  // Les seules concatenations brutes dans du HTML sont des identifiants numeriques (_uid) ou des fonctions deja echappees.
  assert.ok(/h\(r\.name \|\| rbT\('rb\.unnamed'\)\)/.test(rb));
  assert.ok(/h\(rbSummary\(r\)\)/.test(rb));
  assert.ok(/value="' \+ h\(value == null/.test(rb));
  assert.ok(!/\+\s*r\.(name|description|pathHint|uaHint)\s*[+;]/.test(rb), 'concatenation brute de r.name/description/hints');
});
check('rulesOpen()/rulesClose()/rulesLoad()/rulesToggle()/rulesSaveCustom() sont bien definies', () => {
  assert.ok(/function rulesOpen\(\)/.test(scripts));
  assert.ok(/function rulesClose\(\)/.test(scripts));
  assert.ok(/async function rulesLoad\(\)/.test(scripts));
  assert.ok(/async function rulesToggle\(/.test(scripts));
  assert.ok(/async function rulesSaveCustom\(\)/.test(scripts));
});
check('rulesLoad() degrade proprement si l agent est injoignable (reachable:false)', () => {
  const start = scripts.indexOf('async function rulesLoad()');
  assert.ok(start !== -1, 'rulesLoad() introuvable');
  assert.ok(/reachable === false/.test(scripts.slice(start, start + 800)));
});
check('les descriptions de regles (what/why/legit/action) passent par des noeuds texte, jamais innerHTML avec interpolation', () => {
  const m = scripts.match(/function rulesRenderBuiltins\([\s\S]*?\n\}/);
  assert.ok(m, 'rulesRenderBuiltins() introuvable');
  assert.ok(/createTextNode/.test(m[0]));
  assert.ok(!/innerHTML\s*\+=.*explanation/.test(m[0]));
});
check('le rappel des flags par vhost (# nginx-control-analyze / -ignore-rules) est present dans la modale', () => {
  assert.ok(html.includes('nginx-control-analyze:'));
  assert.ok(html.includes('nginx-control-analyze-ignore-rules:'));
});

// Fix (retour utilisateur v12.44.0) : les boutons "Copier" a cote des jetons
// affiches (API_TOKEN/WEBHOOK_SECRET, jeton d agent, sortie du Generateur de
// VHost, contenu de fichier...) ne faisaient rien sur un dashboard servi en
// HTTP simple (navigator.clipboard absent hors contexte securise). Voir
// copyToClipboard()/copyToClipboardFallback() dans index.html.
check('copyToClipboard() existe et a un repli execCommand pour les contextes non securises', () => {
  assert.ok(/function copyToClipboard\(text\)/.test(scripts), 'copyToClipboard() introuvable');
  assert.ok(/function copyToClipboardFallback\(text\)/.test(scripts), 'copyToClipboardFallback() introuvable');
  assert.ok(/document\.execCommand\('copy'\)/.test(scripts), 'pas de repli document.execCommand(\'copy\')');
  assert.ok(/function copyFeedback\(/.test(scripts), 'copyFeedback() introuvable');
});
check('aucun appel direct a navigator.clipboard.writeText ne subsiste hors de copyToClipboard() lui-meme', () => {
  // Fix reel : `if (x && navigator.clipboard) navigator.clipboard.writeText(x)`
  // (sysinfoSecretCopy/agentsTokenCopy, silencieux), `navigator.clipboard
  // .writeText(x).catch(...)` sans garde (copyVhgOutput/copyConfigFile/
  // copyNginxFile/bouton CrowdSec en dur, TypeError synchrone jamais
  // interceptee par le .catch()), et `navigator.clipboard?.writeText(x)
  // .then(...)` (le `?.` ne protege que l acces a writeText, pas le .then()
  // qui suit — popover user-agent) etaient tous casses en HTTP simple. Tout
  // doit desormais passer par copyToClipboard(). Les commentaires (lignes
  // qui expliquent ce meme fix) sont ignores : seul du code executable compte.
  const codeOnly = scripts.split('\n').filter(l => !/^\s*\/\//.test(l)).join('\n');
  const withoutHelperDef = codeOnly.replace(/function copyToClipboard\(text\)[\s\S]*?\n\}/, '');
  assert.ok(!/navigator\.clipboard(\?\.|\.)writeText/.test(withoutHelperDef),
    'un appel direct a navigator.clipboard.writeText subsiste en dehors de copyToClipboard()');
});
check('sysinfoSecretCopy()/agentsTokenCopy()/copyVhgOutput() passent par copyToClipboard()', () => {
  for (const fn of ['sysinfoSecretCopy', 'agentsTokenCopy', 'copyVhgOutput']) {
    const m = scripts.match(new RegExp('function ' + fn + '\\([^)]*\\)[\\s\\S]*?\\n\\}'));
    assert.ok(m, fn + '() introuvable');
    assert.ok(/copyToClipboard\(/.test(m[0]), fn + '() n appelle pas copyToClipboard()');
  }
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
