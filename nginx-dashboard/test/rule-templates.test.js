'use strict';
/**
 * Formulaire de règles d'analyse : modèles (lib/rule-templates.js) et
 * génération du YAML (lib/rule-yaml-out.js). Le YAML produit est relu par le
 * vrai chargeur de l'analyzer quand le dépôt le contient.
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');
const templates = require('../lib/rule-templates');
const out = require('../lib/rule-yaml-out');

let pass = 0, fail = 0;
const checks = [];
const check = (n, f) => checks.push([n, f]);

let analyzerYaml = null;
try { analyzerYaml = require('../../nginx-analyzer/lib/rules-yaml'); } catch { /* dashboard seul */ }

const asRules = packs => {
  let id = 100;
  return packs.flatMap(p => p.rules).map(r => ({ ...r, id: id++ }));
};

check('modèles : chaque règle est valide, slugs et ids uniques, au moins forgejo/gitlab/wordpress/nextcloud/ua', () => {
  const packs = templates.listTemplates('fr');
  const ids = packs.map(p => p.id);
  for (const want of ['forgejo', 'gitlab', 'wordpress', 'nextcloud', 'bad-ua']) assert.ok(ids.includes(want), want);
  const { rules, errors } = out.normalizeRules(asRules(packs));
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(new Set(rules.map(r => r.name)).size, rules.length);
  for (const p of packs) { assert.ok(p.title && p.description, p.id); for (const r of p.rules) assert.ok(r.description, r.slug); }
});

check('modèles : langue en/fr résolue, aucun objet {fr,en} résiduel', () => {
  for (const lang of ['fr', 'en']) {
    const j = JSON.stringify(templates.listTemplates(lang));
    assert.ok(!/"fr":/.test(j) && !/"en":/.test(j), lang);
  }
});

check('modèles : regex compatibles RE2 (pas d anticipation ni de reference arriere)', () => {
  for (const p of templates.PACKS) for (const r of p.rules) {
    for (const re of [r.pathHint, r.uaHint].filter(Boolean)) {
      assert.ok(!/\(\?<?[=!]|\\[1-9]/.test(re), r.slug);
      new RegExp(re, 'i');
    }
  }
});

check('modèles : le YAML généré est relu à l identique par le chargeur de l analyzer', () => {
  if (!analyzerYaml) return;
  const { rules } = out.normalizeRules(asRules(templates.listTemplates('fr')));
  const y = out.rulesToYaml(rules);
  const p = analyzerYaml.parseAndValidate(y);
  assert.deepStrictEqual(p.errors, []);
  assert.strictEqual(p.valid.length, rules.length);
  rules.forEach((r, i) => {
    const v = p.valid[i];
    assert.strictEqual(v.pathHintRaw, r.pathHint || null, r.name);
    assert.strictEqual(v.uaHintRaw, r.uaHint || null, r.name);
    assert.strictEqual(v.minMatches, r.minMatches);
    assert.strictEqual(v.scope, r.scope);
    assert.strictEqual(v.enable, r.enable);
    assert.deepStrictEqual(v.statusIn, r.statusIn);
    assert.deepStrictEqual(v.methodIn, r.methodIn);
    assert.strictEqual(v.description, r.description);
    assert.strictEqual(v.blocklistThreshold, r.blocklist.threshold);
    assert.strictEqual(v.blocklistRemediationMinutes, r.blocklist.remediationMinutes);
  });
});

check('modèle Forgejo : correspond aux requêtes du botnet, pas au runner ni à une page normale', () => {
  const f = templates.PACKS.find(p => p.id === 'forgejo').rules;
  const re = slug => new RegExp(f.find(r => r.slug === slug).pathHint, 'i');
  assert.ok(re('forgejo_scraper_commit_walk').test('/Dockerfiles/x/commits/commit/5dbe59d4418fff31ff00a201551b7cf7a012f439/sample.env'));
  assert.ok(re('forgejo_scraper_commit_walk').test('/Scripts/PowerShell/src/commit/f50e3ae74d3c6dfe6b5dd7181603cebeeacca00c/Net/'));
  assert.ok(re('forgejo_scraper_filtered_lists').test('/Dockerfiles/agh-central/issues?assignee=0&labels=68&milestone=-1&poster=0&project=-1&sort=relevance&state=open&type=all'));
  assert.ok(re('forgejo_scraper_login_redirect').test('/user/login?redirect_to=%2FDockerfiles%2Fnginx-reverse-proxy%2Fsrc%2Fcommit%2F12deb'));
  for (const ok of ['/api/actions/runner.v1.RunnerService/FetchTask', '/Dockerfiles/x', '/Dockerfiles/x/issues?state=open', '/user/login']) {
    for (const r of f.filter(x => /scraper/.test(x.slug))) assert.ok(!new RegExp(r.pathHint, 'i').test(ok), r.slug + ' ' + ok);
  }
});

check('modèles : fichiers sensibles / outils d admin / injections sans faux positif évident', () => {
  const g = slug => new RegExp(templates.PACKS.find(p => p.id === 'web-generic').rules.find(r => r.slug === slug).pathHint, 'i');
  assert.ok(g('probe_sensitive_files').test('/.env') && g('probe_sensitive_files').test('/app/.git/config'));
  assert.ok(!g('probe_sensitive_files').test('/assets/environment.js'));
  assert.ok(g('probe_admin_tools').test('/phpmyadmin/index.php') && g('probe_admin_tools').test('/pma/'));
  assert.ok(!g('probe_admin_tools').test('/pmap/list') && !g('probe_admin_tools').test('/adminer-theme.css'));
  assert.ok(g('attack_injection_patterns').test('/x?f=../../etc/passwd') && g('attack_injection_patterns').test('/?q=${jndi:ldap://a}'));
});

check('génération : échappements, listes, global, aller-retour', () => {
  const { rules, errors } = out.normalizeRules([{ id: 120, name: 'a_b', pathHint: "\\.env|it's", methodIn: ['get'], statusIn: ['403'], minMatches: '5', scope: 'global', minIps: '10', description: 'ça # ok', blocklist: { threshold: 1, remediation: true, remediationMinutes: 60 } }]);
  assert.deepStrictEqual(errors, []);
  const y = out.rulesToYaml(rules);
  assert.ok(y.includes("path_hint: '\\.env|it''s'") && y.includes('scope: global\n    min_ips: 10') && y.includes("method_in: ['GET']"));
  if (analyzerYaml) {
    const p = analyzerYaml.parseAndValidate(y);
    assert.deepStrictEqual(p.errors, []);
    assert.strictEqual(p.valid[0].pathHintRaw, "\\.env|it's");
  }
});

check('validation : refus (id, nom, regex, RE2, saut de ligne, critère absent, doublons)', () => {
  const base = { id: 100, name: 'ok', minMatches: 1, pathHint: 'x' };
  const bad = (patch, re) => {
    const { errors } = out.normalizeRules([{ ...base, ...patch }]);
    assert.ok(errors.some(e => re.test(e)), JSON.stringify(patch) + ' -> ' + errors.join('|'));
  };
  bad({ id: 5 }, /id/); bad({ name: 'a b' }, /nom/); bad({ name: 'true' }, /nom/); bad({ pathHint: '(' }, /expression/);
  bad({ pathHint: '(?=a)b' }, /RE2/); bad({ description: 'a\nb' }, /saut de ligne/); bad({ pathHint: '' }, /critère/);
  bad({ minMatches: 0 }, /correspondances/); bad({ scope: 'monde' }, /portée/); bad({ severity: 'critical' }, /gravité/);
  bad({ statusIn: [99] }, /code HTTP/); bad({ methodIn: ['GET /'] }, /méthode/);
  bad({ blocklist: { remediationMinutes: true } }, /durée/); bad({ blocklist: { threshold: 0 } }, /seuil/);
  const dup = out.normalizeRules([base, { ...base }]);
  assert.ok(dup.errors.some(e => /id 100 déjà/.test(e)) && dup.errors.some(e => /nom/.test(e)));
});

check('routes : modèles et to-yaml (droits, erreurs, YAML)', async () => {
  const feature = require('../features/analyzer-rules');
  const handlers = { get: {}, post: {} };
  feature.register({ get: (p, h) => { handlers.get[p] = h; }, post: (p, h) => { handlers.post[p] = h; }, addPrefix() {} });
  const mkRes = () => { const r = { code: 0, body: null, writeHead(c) { r.code = c; }, end(b) { r.body = b ? JSON.parse(b) : null; } }; return r; };
  const admin = { username: 'a', role: 'admin' };
  const none = { username: 'x', role: 'certsync' };
  let res = mkRes();
  await handlers.get['/api/analyzer/rules/templates']({ res, session: admin, url: new URL('http://x/api/analyzer/rules/templates?lang=en') });
  assert.strictEqual(res.code, 200); assert.ok(res.body.packs.length >= 5);
  res = mkRes();
  await handlers.get['/api/analyzer/rules/templates']({ res, session: none, url: new URL('http://x/api/analyzer/rules/templates') });
  assert.strictEqual(res.code, 403);
  res = mkRes();
  await handlers.post['/api/analyzer/rules/to-yaml']({ req: Readable.from([JSON.stringify({ rules: [{ id: 100, name: 'r', minMatches: 2, pathHint: 'x' }] })]), res, session: admin });
  assert.strictEqual(res.body.ok, true); assert.ok(res.body.yaml.startsWith('rules:'));
  res = mkRes();
  await handlers.post['/api/analyzer/rules/to-yaml']({ req: Readable.from([JSON.stringify({ rules: [{ id: 1, name: 'r' }] })]), res, session: admin });
  assert.strictEqual(res.body.ok, false); assert.ok(res.body.errors.length);
});

(async () => {
  for (const [n, f] of checks) {
    try { await f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; }
  }
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
