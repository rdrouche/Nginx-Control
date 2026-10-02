'use strict';
/** lib/challenge-gate.js : generation nginx du challenge navigateur (v12.63.0). */
const assert = require('assert');
const G = require('../lib/challenge-gate');
const { parseAndValidate } = require('../lib/blocklist-yaml');
const { normalizeRule, rulesToYaml } = require('../lib/rule-yaml-out');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const code = s => s.split('\n').filter(l => !l.startsWith('#')).join('\n');

console.log('\nnormalizeChallengeSettings()');
check('defauts : desactive, moteur builtin, upstream du moteur', () => {
  const { settings, errors } = G.normalizeChallengeSettings({});
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(settings.enable, false);
  assert.strictEqual(settings.engine, 'builtin');
  assert.strictEqual(settings.upstreamEffective, 'nginx-challenge:8080');
});
check('anubis : upstream par defaut anubis:8923 ; upstream personnalise accepte', () => {
  assert.strictEqual(G.normalizeChallengeSettings({ challenge_engine: 'anubis' }).settings.upstreamEffective, 'anubis:8923');
  assert.strictEqual(G.normalizeChallengeSettings({ challenge_upstream: 'chal.internal:9000' }).settings.upstreamEffective, 'chal.internal:9000');
});
check('valeurs dangereuses refusees et remplacees par le defaut (jamais ecrites dans nginx)', () => {
  const bad = {
    challenge_engine: 'evil', challenge_upstream: 'a;b', challenge_resolver: '1.1.1.1; x', challenge_enable: 'oui',
    challenge_exempt_path_regex: '^/x" 1; } server {', challenge_exempt_ua_regex: 'a$b',
  };
  const { settings, errors } = G.normalizeChallengeSettings(bad);
  assert.ok(errors.length >= 6, errors.join(' | '));
  assert.strictEqual(settings.engine, 'builtin');
  assert.strictEqual(settings.enable, false);
  assert.strictEqual(settings.upstreamEffective, 'nginx-challenge:8080');
  assert.strictEqual(settings.exemptUaRegex, '');
  assert.strictEqual(settings.exemptPathRegex, '^/[.]well-known/');
});
check('upstream : port hors bornes et injection refuses', () => {
  assert.ok(G.validateUpstream('host:99999'));
  assert.ok(G.validateUpstream('host:80;'));
  assert.ok(G.validateUpstream('http://host:80'));
  assert.strictEqual(G.validateUpstream('nginx-challenge:8080'), null);
});
check('regex : liste blanche de caracteres, longueur, validite', () => {
  assert.strictEqual(G.validateRegex('x', ''), null);
  assert.strictEqual(G.validateRegex('x', '^/(api|git)/'), null);
  for (const bad of ['a b', 'a"b', "a'b", 'a\\b', 'a;b', 'a{2}', 'a$', '(', 'x'.repeat(201)]) assert.ok(G.validateRegex('x', bad), bad);
});

console.log('\nbuildChallengeHttp()');
check('geo + maps ; le defaut ne challenge personne ; "100" = soumettre', () => {
  const { settings } = G.normalizeChallengeSettings({ challenge_enable: true, challenge_exempt_ua_regex: '^git/' });
  const c = code(G.buildChallengeHttp(settings, ['192.0.2.1', '198.51.100.0/24']));
  assert.ok(c.includes('geo $blocklist_challenge {') && c.includes('default 0;') && c.includes('192.0.2.1 1;') && c.includes('198.51.100.0/24 1;'));
  assert.ok(c.includes('"~*^/[.]well-known/" 1;') && c.includes('"~*^git/" 1;'));
  assert.ok(/default 1;\s*"100" 0;/.test(c));
});
check('liste vide : fichier valide sans entree', () => {
  const c = code(G.emptyChallengeHttp());
  assert.ok(/geo \$blocklist_challenge \{\s*default 0;\s*\}/.test(c));
});

console.log('\nbuildGateSnippet()');
check('desactive : aucune directive (une inclusion existante ne casse jamais nginx -t)', () => {
  const s = G.buildGateSnippet(G.normalizeChallengeSettings({}).settings);
  assert.strictEqual(code(s).trim(), '');
});
check('builtin : auth_request, error_page, passerelle /check, page /.nc-challenge/, redirection 302 sans echappement', () => {
  const c = code(G.buildGateSnippet(G.normalizeChallengeSettings({ challenge_enable: true }).settings));
  assert.ok(c.includes('auth_request /_nc_gate;') && c.includes('error_page 401 = @nc_challenge;'));
  assert.ok(c.includes('rewrite ^ /check break;') && c.includes('if ($nc_gate_skip) { return 204; }'));
  assert.ok(c.includes('location ^~ /.nc-challenge/ {') && c.includes('return 302 /.nc-challenge/go$request_uri;'));
  assert.ok(c.includes('resolver 127.0.0.11') && c.includes('set $nc_up "nginx-challenge:8080";'));
});
check('anubis : chemin de controle Anubis, redirection 307 vers /.within.website/', () => {
  const c = code(G.buildGateSnippet(G.normalizeChallengeSettings({ challenge_enable: true, challenge_engine: 'anubis' }).settings));
  assert.ok(c.includes('rewrite ^ /.within.website/x/cmd/anubis/api/check break;'));
  assert.ok(c.includes('location ^~ /.within.website/ {') && c.includes('return 307 /.within.website/?redir=$request_uri;'));
  assert.ok(c.includes('set $nc_up "anubis:8923";'));
});
check('l IP et l hote ne sont jamais pris dans un en-tete controlable par le client', () => {
  const c = code(G.buildGateSnippet(G.normalizeChallengeSettings({ challenge_enable: true }).settings));
  assert.ok(c.includes('proxy_set_header X-Real-IP $remote_addr;'));
  assert.ok(!/\$http_x_/i.test(c));
});
check('stripComments ignore les en-tetes (horodatage) mais pas le fond', () => {
  const s = G.normalizeChallengeSettings({ challenge_enable: true }).settings;
  assert.strictEqual(G.stripComments(G.buildGateSnippet(s)), G.stripComments(G.buildGateSnippet(s)));
  assert.notStrictEqual(G.stripComments(G.buildChallengeHttp(s, ['1.1.1.1'])), G.stripComments(G.buildChallengeHttp(s, [])));
});

console.log('\nvariantes : challenge-all / challenge-all-allowbots');
check('trois fichiers, noms attendus ; all* utilisent $nc_gate_skip_all, listed $nc_gate_skip', () => {
  const st = G.normalizeChallengeSettings({ challenge_enable: true }).settings;
  const all = G.buildAllGateSnippets(st);
  assert.deepStrictEqual(all.map(g => g.name), ['challenge-gate.conf', 'challenge-all.conf', 'challenge-all-allowbots.conf', 'challenge-location-support.conf', 'challenge-location-support-allowbots.conf', 'challenge-location.conf']);
  assert.ok(code(all[0].content).includes('if ($nc_gate_skip) { return 204; }'));
  assert.ok(code(all[1].content).includes('if ($nc_gate_skip_all) { return 204; }'));
  assert.ok(code(all[2].content).includes('if ($nc_gate_skip_all) { return 204; }'));
});
check('X-NC-Allow-Bots toujours ecrase : "1" seulement pour allbots, vide ailleurs (jamais celui du client)', () => {
  const st = G.normalizeChallengeSettings({ challenge_enable: true }).settings;
  const [listed, all, bots] = G.buildAllGateSnippets(st).map(g => code(g.content));
  assert.ok(listed.includes('proxy_set_header X-NC-Allow-Bots "";'));
  assert.ok(all.includes('proxy_set_header X-NC-Allow-Bots "";'));
  assert.ok(bots.includes('proxy_set_header X-NC-Allow-Bots "1";'));
});
check('desactive : les trois snippets sont vides de directives', () => {
  for (const g of G.buildAllGateSnippets(G.normalizeChallengeSettings({}).settings)) assert.strictEqual(code(g.content).trim(), '', g.name);
});
check('la map $nc_gate_skip_all ne laisse passer que les exemptions', () => {
  const c = code(G.buildChallengeHttp(G.normalizeChallengeSettings({ challenge_enable: true }).settings, []));
  assert.ok(/map "\$nc_exempt_path\$nc_exempt_ua" \$nc_gate_skip_all \{\s*default 1;\s*"00" 0;/.test(c));
});

console.log('\nblocklists.yml : cles challenge_*');
check('parseAndValidate expose settings.challenge et remonte les erreurs', () => {
  const ok = parseAndValidate('enable: true\nchallenge_enable: true\nchallenge_engine: anubis\n');
  assert.strictEqual(ok.settings.challenge.enable, true);
  assert.strictEqual(ok.settings.challenge.engine, 'anubis');
  const bad = parseAndValidate('challenge_engine: nope\n');
  assert.ok(bad.errors.some(e => /challenge_engine/.test(e)));
  assert.strictEqual(parseAndValidate('').settings.challenge.enable, false);
});

console.log('\nregles : remediationType dans le formulaire -> YAML');
check('block par defaut (aucune cle ecrite) ; challenge ecrit ; valeur inconnue refusee', () => {
  const base = { id: 120, name: 'r', minMatches: 1, pathHint: '/x', blocklist: { threshold: 1, remediation: true } };
  const a = normalizeRule(base);
  assert.deepStrictEqual(a.errors, []);
  assert.ok(!/blocklist_remediation_type/.test(rulesToYaml([a.rule])));
  const b = normalizeRule({ ...base, blocklist: { threshold: 1, remediation: true, remediationType: 'challenge' } });
  assert.ok(/blocklist_remediation_type: challenge/.test(rulesToYaml([b.rule])));
  const c = normalizeRule({ ...base, blocklist: { threshold: 1, remediation: true, remediationType: 'captcha' } });
  assert.ok(c.errors.some(e => /block ou challenge/.test(e)));
});


console.log('\nfichiers generes vus par le test nginx ephemere (deploy / git)');
check('les 4 fichiers du challenge sont dans GENERATED_FILES (copies dans le bac a sable, jamais supprimes)', () => {
  const B = require('../features/blocklists');
  for (const f of [B.CHALLENGE_FILE, ...Object.values(B.GATE_FILES)]) {
    assert.ok(B.GENERATED_FILES.includes(f), f);
  }
});
check('proxy_pass par variable : nginx -t n\'a pas besoin que le conteneur de challenge existe', () => {
  const { settings } = G.normalizeChallengeSettings({ challenge_enable: true });
  for (const v of ['listed', 'all', 'allbots']) {
    const c = code(G.buildGateSnippet(settings, v));
    assert.ok(/proxy_pass http:\/\/\$nc_up/.test(c), v);
    assert.ok(!/proxy_pass http:\/\/nginx-challenge/.test(c), v);
  }
});


console.log('\nchallenge par location');
check('location : support sans auth_request global, snippet inline = auth_request + error_page seulement', () => {
  const st = G.normalizeChallengeSettings({ challenge_enable: true }).settings;
  const by = Object.fromEntries(G.buildAllGateSnippets(st).map(g => [g.name, code(g.content)]));
  const sup = by['challenge-location-support.conf'], bots = by['challenge-location-support-allowbots.conf'], inc = by['challenge-location.conf'];
  assert.ok(!/^auth_request \/_nc_gate;/m.test(sup));
  assert.ok(sup.includes('location = /_nc_gate') && sup.includes('location @nc_challenge'));
  assert.ok(sup.includes('X-NC-Allow-Bots ""') && bots.includes('X-NC-Allow-Bots "1"'));
  assert.ok(sup.includes('$nc_gate_skip_all'));
  assert.strictEqual(inc.trim(), 'auth_request /_nc_gate;\nerror_page 401 = @nc_challenge;');
});
console.log('\nprofils par vhost');
const S = require('../lib/challenge-settings');
const profText = 'challenge_enable: true\nprofiles:\n  - name: forgejo\n    mode: allbots\n    exempt_ua_regex: "^forgejo-runner/"\n  - name: git\n    mode: listed\n';
check('profils lus : exemptions propres, heritage du global sinon', () => {
  const { settings, errors } = G.normalizeChallengeSettings(S.challengeOverridesFromText(profText));
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(settings.profiles.length, 2);
  assert.strictEqual(settings.profiles[0].exemptUaRegex, '^forgejo-runner/');
  assert.strictEqual(settings.profiles[1].exemptUaRegex, '');
  assert.strictEqual(settings.profiles[1].exemptPathRegex, settings.exemptPathRegex);
});
check('un snippet et des variables nginx dedies par profil, aucune collision avec le global', () => {
  const { settings } = G.normalizeChallengeSettings(S.challengeOverridesFromText(profText));
  const snips = G.buildAllGateSnippets(settings);
  assert.deepStrictEqual(snips.map(x => x.name), ['challenge-gate.conf', 'challenge-all.conf', 'challenge-all-allowbots.conf', 'challenge-location-support.conf', 'challenge-location-support-allowbots.conf', 'challenge-location.conf', 'challenge-forgejo.conf', 'challenge-git.conf']);
  const forge = code(snips[6].content);
  assert.ok(forge.includes('if ($nc_gate_skip_forgejo)'));
  assert.ok(forge.includes('X-NC-Allow-Bots "1"'));
  assert.ok(code(snips[7].content).includes('X-NC-Allow-Bots ""'));
  const http = code(G.buildChallengeHttp(settings, ['203.0.113.1'], 's'));
  assert.ok(http.includes('"~*^forgejo-runner/" 1;'));
  assert.ok(http.includes('map "$blocklist_challenge$nc_exempt_path_git$nc_exempt_ua_git" $nc_gate_skip_git'));
  assert.ok(http.includes('map "$nc_exempt_path_forgejo$nc_exempt_ua_forgejo" $nc_gate_skip_forgejo'));
});
check('noms invalides, reserves, doubles et regex dangereuse refuses', () => {
  const bad = [{ name: 'Bad' }, { name: 'all' }, { name: 'x;y' }, { name: 'ok' }, { name: 'ok' }, { name: 'z', mode: 'nope' }, { name: 'w', exempt_ua_regex: 'a b' }];
  const r = G.normalizeProfiles(bad, G.DEFAULTS);
  assert.deepStrictEqual(r.profiles.map(p => p.name), ['ok']);
  assert.strictEqual(r.errors.length, 6);
});
check('challenge desactive : snippets de profil sans directive', () => {
  const { settings } = G.normalizeChallengeSettings({ challenge_profiles: [{ name: 'forgejo' }] });
  assert.ok(!/auth_request/.test(code(G.buildAllGateSnippets(settings)[3].content)));
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
