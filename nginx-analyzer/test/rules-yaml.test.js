'use strict';
const assert = require('assert');
const { parseRulesYaml, validateRule, parseAndValidate, stringifyRules } = require('../lib/rules-yaml');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nparseRulesYaml() — syntaxe');
check('parse une regle simple avec tous les champs', () => {
  const yaml = `rules:
  - id: 101
    name: admin_probe
    enable: true
    severity: high
    description: "Beaucoup de requetes vers des chemins d administration"
    window_minutes: 5
    min_matches: 10
    path_hint: "(wp-admin|phpmyadmin)"
    ua_hint: null
    status_in: [401, 403]
    method_in: []
`;
  const { rules, errors } = parseRulesYaml(yaml);
  assert.strictEqual(errors.length, 0);
  assert.strictEqual(rules.length, 1);
  assert.strictEqual(rules[0].id, 101);
  assert.strictEqual(rules[0].name, 'admin_probe');
  assert.strictEqual(rules[0].enable, true);
  assert.strictEqual(rules[0].min_matches, 10);
  assert.strictEqual(rules[0].path_hint, '(wp-admin|phpmyadmin)');
  assert.strictEqual(rules[0].ua_hint, null);
  assert.deepStrictEqual(rules[0].status_in, [401, 403]);
  assert.deepStrictEqual(rules[0].method_in, []);
});
check('plusieurs regles a la suite', () => {
  const yaml = `rules:
  - id: 101
    name: a
    min_matches: 5
  - id: 102
    name: b
    min_matches: 8
`;
  const { rules } = parseRulesYaml(yaml);
  assert.strictEqual(rules.length, 2);
  assert.strictEqual(rules[1].id, 102);
});
check('commentaires et lignes vides ignores', () => {
  const yaml = `# commentaire
rules:
  # une autre regle
  - id: 101
    name: a

    min_matches: 5
`;
  const { rules, errors } = parseRulesYaml(yaml);
  assert.strictEqual(errors.length, 0);
  assert.strictEqual(rules.length, 1);
});
check('une ligne mal formee est signalee avec son numero', () => {
  const yaml = `rules:
  - id: 101
    name: a
this ne va pas
`;
  const { errors } = parseRulesYaml(yaml);
  assert.ok(errors.some(e => e.includes('Ligne 4')), errors.join('; '));
});
check('fichier vide -> aucune regle, aucune erreur', () => {
  assert.deepStrictEqual(parseRulesYaml(''), { rules: [], errors: [] });
});
check('contenu non reconnu sur un fichier non vide -> erreur (pas d echec silencieux)', () => {
  const { errors } = parseRulesYaml('foo: bar\n');
  assert.ok(errors.length > 0);
});

console.log('\nvalidateRule() — chaque champ');
check('regle valide -> aucune erreur', () => {
  const errs = validateRule({ id: 101, name: 'ok', min_matches: 5 }, new Set());
  assert.deepStrictEqual(errs, []);
});
check('id absent ou < 100 rejete (reserve aux regles integrees)', () => {
  assert.ok(validateRule({ id: 5, name: 'a', min_matches: 1 }, new Set()).length > 0);
  assert.ok(validateRule({ name: 'a', min_matches: 1 }, new Set()).length > 0);
});
check('id deja utilise rejete', () => {
  const seen = new Set([101]);
  assert.ok(validateRule({ id: 101, name: 'a', min_matches: 1 }, seen).length > 0);
});
check('name manquant ou invalide rejete', () => {
  assert.ok(validateRule({ id: 101, min_matches: 1 }, new Set()).length > 0);
  assert.ok(validateRule({ id: 101, name: 'a b', min_matches: 1 }, new Set()).length > 0);
});
check('severity hors enum rejetee', () => {
  assert.ok(validateRule({ id: 101, name: 'a', min_matches: 1, severity: 'critical' }, new Set()).length > 0);
});
check('min_matches manquant ou <= 0 rejete', () => {
  assert.ok(validateRule({ id: 101, name: 'a' }, new Set()).length > 0);
  assert.ok(validateRule({ id: 101, name: 'a', min_matches: 0 }, new Set()).length > 0);
});
check('path_hint/ua_hint : regex invalide rejetee', () => {
  assert.ok(validateRule({ id: 101, name: 'a', min_matches: 1, path_hint: '(' }, new Set()).length > 0);
});
check('status_in/method_in non-tableau rejete', () => {
  assert.ok(validateRule({ id: 101, name: 'a', min_matches: 1, status_in: 401 }, new Set()).length > 0);
});

console.log('\nparseAndValidate() — un id invalide n empeche pas les autres regles de passer');
check('regle valide gardee, regle invalide reportee dans errors', () => {
  const yaml = `rules:
  - id: 101
    name: ok_rule
    min_matches: 5
  - id: 50
    name: bad_id
    min_matches: 5
`;
  const { valid, errors } = parseAndValidate(yaml);
  assert.strictEqual(valid.length, 1);
  assert.strictEqual(valid[0].name, 'ok_rule');
  assert.ok(errors.some(e => e.includes('bad_id')));
});
check('valeurs par defaut appliquees (enable, severity, window_minutes)', () => {
  const { valid } = parseAndValidate(`rules:\n  - id: 101\n    name: a\n    min_matches: 5\n`);
  assert.strictEqual(valid[0].enable, true);
  assert.strictEqual(valid[0].severity, 'medium');
  assert.strictEqual(valid[0].windowMinutes, 5);
});
check('path_hint/ua_hint compiles en RegExp exploitables', () => {
  const { valid } = parseAndValidate(`rules:\n  - id: 101\n    name: a\n    min_matches: 5\n    path_hint: "admin"\n`);
  assert.ok(valid[0].pathHint instanceof RegExp);
  assert.ok(valid[0].pathHint.test('/wp-admin/x'));
});

console.log('\nstringifyRules() — aller-retour');
check('une regle serialisee puis reparsee redonne les memes valeurs utiles', () => {
  const original = [{ id: 101, name: 'x', enable: true, severity: 'high', description: 'd', window_minutes: 7, min_matches: 3, path_hint: 'a', ua_hint: null, status_in: [403], method_in: ['GET'] }];
  const text = stringifyRules(original);
  const { valid, errors } = parseAndValidate(text);
  assert.strictEqual(errors.length, 0);
  assert.strictEqual(valid.length, 1);
  assert.strictEqual(valid[0].id, 101);
  assert.strictEqual(valid[0].minMatches, 3);
  assert.strictEqual(valid[0].windowMinutes, 7);
  assert.deepStrictEqual(valid[0].statusIn, [403]);
});
check('liste vide -> "rules: []"', () => {
  assert.strictEqual(stringifyRules([]), 'rules: []\n');
});

console.log('\n"Blocklist a la CrowdSec" par regle personnalisee (v12.50.0)');
check('champs absents -> blocklistThreshold: null (desactive), fenetre 1440 min, remediation false', () => {
  const { valid } = parseAndValidate('rules:\n  - id: 100\n    name: x\n    min_matches: 5');
  assert.deepStrictEqual(
    { threshold: valid[0].blocklistThreshold, window: valid[0].blocklistWindowMinutes, remediation: valid[0].blocklistRemediation, remediationMinutes: valid[0].blocklistRemediationMinutes },
    { threshold: null, window: 1440, remediation: false, remediationMinutes: null }
  );
});
check('champs fournis sont repris tels quels', () => {
  const { valid } = parseAndValidate([
    'rules:', '  - id: 100', '    name: x', '    min_matches: 5',
    '    blocklist_threshold: 3', '    blocklist_window_minutes: 120',
    '    blocklist_remediation: true', '    blocklist_remediation_minutes: 60',
  ].join('\n'));
  assert.strictEqual(valid[0].blocklistThreshold, 3);
  assert.strictEqual(valid[0].blocklistWindowMinutes, 120);
  assert.strictEqual(valid[0].blocklistRemediation, true);
  assert.strictEqual(valid[0].blocklistRemediationMinutes, 60);
});
check('blocklist_threshold < 1 ou non numerique -> erreur explicite', () => {
  const { errors } = parseAndValidate('rules:\n  - id: 100\n    name: x\n    min_matches: 5\n    blocklist_threshold: 0');
  assert.ok(errors.some(e => e.includes('blocklist_threshold')));
});
check('blocklist_window_minutes est borne (MAX_BLOCKLIST_WINDOW_MINUTES)', () => {
  const { MAX_BLOCKLIST_WINDOW_MINUTES } = require('../lib/rules-yaml');
  const { valid } = parseAndValidate(`rules:\n  - id: 100\n    name: x\n    min_matches: 5\n    blocklist_window_minutes: ${MAX_BLOCKLIST_WINDOW_MINUTES * 10}`);
  assert.strictEqual(valid[0].blocklistWindowMinutes, MAX_BLOCKLIST_WINDOW_MINUTES);
});
check('blocklist_remediation_minutes est borne (MAX_BLOCKLIST_REMEDIATION_MINUTES)', () => {
  const { MAX_BLOCKLIST_REMEDIATION_MINUTES } = require('../lib/rules-yaml');
  const { valid } = parseAndValidate(`rules:\n  - id: 100\n    name: x\n    min_matches: 5\n    blocklist_remediation_minutes: ${MAX_BLOCKLIST_REMEDIATION_MINUTES * 10}`);
  assert.strictEqual(valid[0].blocklistRemediationMinutes, MAX_BLOCKLIST_REMEDIATION_MINUTES);
});
check('blocklist_remediation: absent ou false -> false ; seul "true" litteral l active', () => {
  const a = parseAndValidate('rules:\n  - id: 100\n    name: a\n    min_matches: 5').valid[0];
  const b = parseAndValidate('rules:\n  - id: 101\n    name: b\n    min_matches: 5\n    blocklist_remediation: false').valid[0];
  const c = parseAndValidate('rules:\n  - id: 102\n    name: c\n    min_matches: 5\n    blocklist_remediation: true').valid[0];
  assert.strictEqual(a.blocklistRemediation, false);
  assert.strictEqual(b.blocklistRemediation, false);
  assert.strictEqual(c.blocklistRemediation, true);
});
check('stringifyRules() aller-retour conserve les champs blocklist_*', () => {
  const original = [{
    id: 105, name: 'y', min_matches: 4,
    blocklist_threshold: 7, blocklist_window_minutes: 30, blocklist_remediation: true, blocklist_remediation_minutes: 15,
  }];
  const text = stringifyRules(original);
  const { valid, errors } = parseAndValidate(text);
  assert.strictEqual(errors.length, 0);
  assert.strictEqual(valid[0].blocklistThreshold, 7);
  assert.strictEqual(valid[0].blocklistWindowMinutes, 30);
  assert.strictEqual(valid[0].blocklistRemediation, true);
  assert.strictEqual(valid[0].blocklistRemediationMinutes, 15);
});

console.log('\nscope: global / min_ips (v12.60.0)');
check('scope global : defauts (min_ips 5), scope ip par defaut, aller-retour stringify', () => {
  const y = `rules:
  - id: 120
    name: botnet
    min_matches: 20
    scope: global
    path_hint: "x"
  - id: 121
    name: normal
    min_matches: 3
`;
  const { valid, errors } = parseAndValidate(y);
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(valid[0].scope, 'global'); assert.strictEqual(valid[0].minIps, 5);
  assert.strictEqual(valid[1].scope, 'ip'); assert.strictEqual(valid[1].minIps, null);
  const out = stringifyRules(valid);
  assert.ok(/scope: global\n    min_ips: 5/.test(out));
  assert.strictEqual((out.match(/scope:/g) || []).length, 1);
  const again = parseAndValidate(out);
  assert.deepStrictEqual(again.errors, []);
  assert.strictEqual(again.valid[0].scope, 'global');
});
check('scope invalide et min_ips invalide refuses', () => {
  const { errors } = parseAndValidate(`rules:
  - id: 120
    name: a
    min_matches: 1
    scope: monde
  - id: 121
    name: b
    min_matches: 1
    scope: global
    min_ips: 0
`);
  assert.ok(errors.some(e => /"scope"/.test(e)));
  assert.ok(errors.some(e => /"min_ips"/.test(e)));
});

check('un booleen n est pas une duree : blocklist_remediation_minutes: true refuse', () => {
  const { errors, valid } = parseAndValidate(`rules:
  - id: 120
    name: a
    min_matches: 1
    blocklist_threshold: 1
    blocklist_remediation: true
    blocklist_remediation_minutes: true
`);
  assert.ok(errors.some(e => /blocklist_remediation_minutes/.test(e)));
  assert.strictEqual(valid.length, 0);
});

check('blocklist_remediation_type : block par defaut, challenge accepte, valeur inconnue refusee, aller-retour YAML', () => {
  const base = `rules:
  - id: 120
    name: a
    min_matches: 1
    blocklist_threshold: 1
    blocklist_remediation: true
`;
  assert.strictEqual(parseAndValidate(base).valid[0].blocklistRemediationType, 'block');
  const ch = parseAndValidate(base + '    blocklist_remediation_type: challenge\n');
  assert.strictEqual(ch.errors.length, 0);
  assert.strictEqual(ch.valid[0].blocklistRemediationType, 'challenge');
  const out = stringifyRules(ch.valid);
  assert.ok(/blocklist_remediation_type: challenge/.test(out));
  assert.ok(!/blocklist_remediation_type/.test(stringifyRules(parseAndValidate(base).valid)));
  const bad = parseAndValidate(base + '    blocklist_remediation_type: captcha\n');
  assert.ok(bad.errors.some(e => /blocklist_remediation_type/.test(e)));
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
