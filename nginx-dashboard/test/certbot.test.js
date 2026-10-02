'use strict';
const assert = require('assert');
const path = require('path');
const { buildCertbotArgs, applyStagingOverride, certbotTrustExtras, resolveCertsHostPath, resolveWebrootNginxPath } = require('../features/certbot');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nbuildCertbotArgs — serveur ACME personnalise (internal CA, step-ca...)');

check('sans configuration : comportement standard, aucun --server ni --staging', () => {
  const args = buildCertbotArgs({ email: 'a@b.c' }, ['example.com'], false);
  assert.ok(!args.includes('--server'));
  assert.ok(!args.includes('--staging'));
});
check('server vide (chaine vide) -> comme non configure, pas de --server', () => {
  const args = buildCertbotArgs({ email: 'a@b.c', server: '' }, ['example.com'], false);
  assert.ok(!args.includes('--server'));
});
check('server renseigne -> --server suivi de l URL exacte', () => {
  const args = buildCertbotArgs({ email: 'a@b.c', server: 'https://step-ca.interne.local/acme/acme/directory' }, ['example.com'], false);
  const idx = args.indexOf('--server');
  assert.ok(idx !== -1, '--server doit etre present');
  assert.strictEqual(args[idx + 1], 'https://step-ca.interne.local/acme/acme/directory');
});
check('espaces autour de la valeur nettoyes (une config YAML mal indentee ne doit pas produire une URL invalide)', () => {
  const args = buildCertbotArgs({ email: 'a@b.c', server: '   https://step-ca.local/acme  ' }, ['example.com'], false);
  const idx = args.indexOf('--server');
  assert.strictEqual(args[idx + 1], 'https://step-ca.local/acme');
});
check('staging seul (sans server) : comportement existant inchange, --staging present', () => {
  const args = buildCertbotArgs({ email: 'a@b.c', staging: true }, ['example.com'], false);
  assert.ok(args.includes('--staging'));
  assert.ok(!args.includes('--server'));
});
check('server ET staging tous les deux configures : server prime, --staging absent', () => {
  // --staging n a de sens que pour Let s Encrypt lui-meme ; une fois un
  // serveur ACME different configure, le concept ne s applique plus.
  const args = buildCertbotArgs(
    { email: 'a@b.c', server: 'https://step-ca.local/acme', staging: true },
    ['example.com'], false
  );
  assert.ok(args.includes('--server'));
  assert.ok(!args.includes('--staging'), '--staging ne doit jamais accompagner --server');
});
check('dry-run et domaines multiples fonctionnent toujours avec un serveur personnalise', () => {
  const args = buildCertbotArgs(
    { email: 'a@b.c', server: 'https://step-ca.local/acme' },
    ['a.example.com', 'b.example.com'], true
  );
  assert.ok(args.includes('--dry-run'));
  assert.ok(args.includes('--server'));
  const dIdx = args.map((v,i)=>v==='-d'?i:-1).filter(i=>i!==-1);
  assert.strictEqual(dIdx.length, 2, 'chaque domaine doit garder son propre -d');
});
check('email absent -> repli sur admin@localhost, comme avant, quel que soit le serveur', () => {
  const args = buildCertbotArgs({ server: 'https://step-ca.local/acme' }, ['example.com'], false);
  const idx = args.indexOf('--email');
  assert.strictEqual(args[idx + 1], 'admin@localhost');
});
check('un objet vide (le piege du parseur YAML sur une cle sans valeur) n est jamais traite comme un serveur valide', () => {
  // Bug reel, trouve avant livraison en testant le fichier d exemple tel
  // quel : une ligne "server:" sans rien apres le deux-points s analyse,
  // dans ce parseur YAML maison, comme une SECTION VIDE ({}), pas une
  // chaine vide — exactement le motif deja utilise pour "nginx_reload:"
  // suivi de sous-cles indentees. `{}` est truthy en JS, et
  // String({}) === '[object Object]' : sans cette garde de type, le fichier
  // d exemple lui-meme aurait envoye "--server [object Object]" a certbot,
  // cassant la generation de certificats pour quiconque le laissait tel
  // quel. La ligne d exemple livree est desormais commentee par defaut
  // plutot que vide, et cette verification protege contre toute autre
  // valeur non-chaine du meme genre.
  const args = buildCertbotArgs({ email: 'a@b.c', server: {} }, ['example.com'], false);
  assert.ok(!args.includes('--server'), 'un objet vide ne doit jamais devenir "--server [object Object]"');
});

console.log('\napplyStagingOverride — la case a cocher "staging" du formulaire d emission');
check('un booleen explicite dans la requete remplace la valeur du fichier de config', () => {
  // Bug reel trouve en tracant le flux complet d une emission : le
  // formulaire envoyait bien un "staging" par requete, mais rien cote
  // serveur ne le lisait jamais — la case a cocher etait donc sans effet,
  // silencieusement.
  const cfg = { staging: false, server: null };
  assert.strictEqual(applyStagingOverride(cfg, true).staging, true);
  assert.strictEqual(applyStagingOverride({ staging: true, server: null }, false).staging, false);
});
check('une valeur absente ou non booleenne laisse la config du fichier inchangee', () => {
  const cfg = { staging: true, server: null };
  assert.strictEqual(applyStagingOverride(cfg, undefined).staging, true);
  assert.strictEqual(applyStagingOverride(cfg, null).staging, true);
});
check('le server configure prime toujours, meme avec staging force par la requete (verifie via buildCertbotArgs)', () => {
  const cfg = { email: 'a@b.c', staging: false, server: 'https://step-ca.local/acme' };
  const merged = applyStagingOverride(cfg, true);
  const args = buildCertbotArgs(merged, ['example.com'], false);
  assert.ok(args.includes('--server'));
  assert.ok(!args.includes('--staging'), 'un server configure reste prioritaire sur un staging force par la requete');
});

console.log('\ncertbotTrustExtras — faire confiance au certificat TLS d une autorite ACME interne');
check('sans ca_bundle_host_path : aucun montage, aucune variable d environnement ajoutee', () => {
  const t = certbotTrustExtras({});
  assert.deepStrictEqual(t.binds, []);
  assert.deepStrictEqual(t.env, []);
});
check('avec ca_bundle_host_path : montage en lecture seule + REQUESTS_CA_BUNDLE (honore par le client ACME de certbot, base sur requests)', () => {
  const t = certbotTrustExtras({ ca_bundle_host_path: '/containers/nginx-rproxy/step-ca-root.pem' });
  assert.strictEqual(t.binds.length, 1);
  assert.ok(t.binds[0].startsWith('/containers/nginx-rproxy/step-ca-root.pem:'));
  assert.ok(t.binds[0].endsWith(':ro'), 'le certificat racine ne doit etre monte qu en lecture seule');
  assert.deepStrictEqual(t.env, ['REQUESTS_CA_BUNDLE=/etc/ssl/certs/internal-ca.pem']);
});
check('un objet vide (meme piege de parseur qu ailleurs) n active jamais le montage', () => {
  const t = certbotTrustExtras({ ca_bundle_host_path: {} });
  assert.deepStrictEqual(t.binds, []);
  assert.deepStrictEqual(t.env, []);
});

console.log('\nresolveCertsHostPath — repertoire hote des certificats (regression : certs generes mais invisibles)');
check('certs_host_path explicite -> utilise tel quel', () => {
  const p = resolveCertsHostPath({ certs_host_path: '/containers/nginx-rproxy/certs', webroot_host_path: '/containers/nginx-rproxy/webroot' });
  assert.strictEqual(p, '/containers/nginx-rproxy/certs');
});
check('certs_host_path absent, webroot_host_path present -> derive comme repertoire "certs" voisin (meme convention que le docker-compose.yml fourni)', () => {
  const p = resolveCertsHostPath({ webroot_host_path: '/containers/nginx-rproxy/webroot' });
  assert.strictEqual(p, path.join('/containers/nginx-rproxy', 'certs'));
});
check('ni l un ni l autre -> repli sur le chemin relatif historique "certs" (signale par un avertissement, jamais silencieux)', () => {
  const p = resolveCertsHostPath({});
  assert.strictEqual(p, 'certs');
});
check('certs_host_path vide (chaine vide) -> traite comme non configure, derive depuis webroot_host_path', () => {
  const p = resolveCertsHostPath({ certs_host_path: '', webroot_host_path: '/data/webroot' });
  assert.strictEqual(p, path.join('/data', 'certs'));
});
check('objet vide issu du meme piege de parseur YAML qu ailleurs -> jamais utilise tel quel', () => {
  const p = resolveCertsHostPath({ certs_host_path: {}, webroot_host_path: '/data/webroot' });
  assert.strictEqual(p, path.join('/data', 'certs'));
});
check('espaces autour de la valeur explicite nettoyes', () => {
  const p = resolveCertsHostPath({ certs_host_path: '  /containers/nginx-rproxy/certs  ' });
  assert.strictEqual(p, '/containers/nginx-rproxy/certs');
});
check('n utilise plus jamais cfg._hostConfigDir (regression du bug reporte : certificats generes mais absents des conteneurs nginx/dashboard)', () => {
  // Avant le correctif, seul _hostConfigDir (jamais renseigne nulle part dans
  // le code) influencait ce calcul ; le fixer a une valeur ne doit plus rien
  // changer au resultat, qui depend desormais uniquement de certs_host_path
  // et webroot_host_path.
  const withHostConfigDir = resolveCertsHostPath({ _hostConfigDir: '/some/other/path/certbot.yml', webroot_host_path: '/containers/nginx-rproxy/webroot' });
  const withoutHostConfigDir = resolveCertsHostPath({ webroot_host_path: '/containers/nginx-rproxy/webroot' });
  assert.strictEqual(withHostConfigDir, withoutHostConfigDir);
});

console.log('\nresolveWebrootNginxPath — repertoire de service nginx pour le challenge HTTP-01 (regression : extrait post-emission incorrect)');
check('non configure -> repli sur /var/www, la convention du docker-compose.yml fourni (pas /var/www/letsencrypt)', () => {
  assert.strictEqual(resolveWebrootNginxPath({}), '/var/www');
});
check('webroot_nginx_path explicite -> utilise tel quel', () => {
  assert.strictEqual(resolveWebrootNginxPath({ webroot_nginx_path: '/var/www/letsencrypt' }), '/var/www/letsencrypt');
});
check('chaine vide -> traite comme non configure, repli sur /var/www', () => {
  assert.strictEqual(resolveWebrootNginxPath({ webroot_nginx_path: '' }), '/var/www');
});
check('objet vide issu du piege de parseur YAML -> jamais utilise tel quel', () => {
  assert.strictEqual(resolveWebrootNginxPath({ webroot_nginx_path: {} }), '/var/www');
});
check('espaces autour de la valeur explicite nettoyes', () => {
  assert.strictEqual(resolveWebrootNginxPath({ webroot_nginx_path: '  /srv/www  ' }), '/srv/www');
});

console.log('\nensureRenewalContainerAtBoot — reconstitution apres redemarrage de l hote');
(async () => {
  const { ensureRenewalContainerAtBoot } = require('../features/certbot');
  const check2 = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
    catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

  await check2('certbot.yml absent -> skipped, jamais d appel Docker', async () => {
    // Aucun fichier de config dans ce repertoire de test -> getCertbotCfg() renvoie null.
    const r = await ensureRenewalContainerAtBoot();
    assert.strictEqual(r.skipped, 'not enabled');
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();