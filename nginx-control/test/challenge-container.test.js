'use strict';
/** lib/challenge-container.js : config + spec du conteneur de challenge (v12.64.0). */
const assert = require('assert');
const C = require('../lib/challenge-container');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const DEF = { challengeImage: 'img/nc:latest', anubisImage: 'img/anubis:latest' };
const SECRET = 'a'.repeat(40);

console.log('\nparseChallengeConfig()');
check('vide : defauts, aucune erreur', () => {
  const { config, errors } = C.parseChallengeConfig('');
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(config.enable, false);
  assert.strictEqual(config.difficultyBits, 16);
  assert.strictEqual(config.goodbots, true);
});
check('valeurs valides lues, commentaires inline ignores', () => {
  const { config, errors } = C.parseChallengeConfig(
    'enable: true  # on\ncontainer_image: "reg.example/nc:1"\ndifficulty_bits: 20\ncookie_hours: 48\ngoodbots: false\nanubis_difficulty: 5\n');
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(config.enable, true);
  assert.strictEqual(config.containerImage, 'reg.example/nc:1');
  assert.strictEqual(config.difficultyBits, 20);
  assert.strictEqual(config.cookieHours, 48);
  assert.strictEqual(config.goodbots, false);
  assert.strictEqual(config.anubisDifficulty, 5);
});
check('valeurs invalides refusees, defauts conserves', () => {
  const { config, errors } = C.parseChallengeConfig(
    'enable: oui\ncontainer_image: a b;c\nsecret: court\ndifficulty_bits: 99\ncookie_hours: 0\nanubis_difficulty: 9\ngoodbots_extra: "x|y"\nredirect_domains: "a b"\ncookie_domain: "a;b"\n');
  assert.ok(errors.length >= 9, errors.join(' | '));
  assert.strictEqual(config.enable, false);
  assert.strictEqual(config.containerImage, '');
  assert.strictEqual(config.secret, '');
  assert.strictEqual(config.difficultyBits, 16);
  assert.strictEqual(config.goodbotsExtra, '');
});
check('goodbots_extra valide accepte', () => {
  const { config, errors } = C.parseChallengeConfig('goodbots_extra: "Foo|foobot|.foo.com,.foo.net;Bar|bar|.bar.org"\n');
  assert.deepStrictEqual(errors, []);
  assert.ok(config.goodbotsExtra.startsWith('Foo|'));
});

console.log('\nnom / port / image');
check('nom = hote de l upstream, defaut par moteur si invalide', () => {
  assert.strictEqual(C.containerNameFor('chal.internal:9000', 'builtin'), 'chal.internal');
  assert.strictEqual(C.containerNameFor('', 'builtin'), 'nginx-challenge');
  assert.strictEqual(C.containerNameFor('', 'anubis'), 'anubis');
});
check('port : extrait ou defaut par moteur', () => {
  assert.strictEqual(C.portFor('x:9000', 'builtin'), 9000);
  assert.strictEqual(C.portFor('x', 'builtin'), 8080);
  assert.strictEqual(C.portFor('x', 'anubis'), 8923);
});
check('image : config > defaut du moteur', () => {
  assert.strictEqual(C.imageFor({ containerImage: 'mine' }, 'builtin', DEF), 'mine');
  assert.strictEqual(C.imageFor({ containerImage: '' }, 'builtin', DEF), 'img/nc:latest');
  assert.strictEqual(C.imageFor({ containerImage: '' }, 'anubis', DEF), 'img/anubis:latest');
});

console.log('\nbuildContainerSpec()');
const cfg = () => C.parseChallengeConfig('goodbots_extra: "Foo|foo|.foo.com"\nredirect_domains: "a.com,b.com"\ncookie_domain: "a.com"\n').config;
check('builtin : env NC_*, rootfs en lecture seule, durci, aucun port publie', () => {
  const s = C.buildContainerSpec({ engine: 'builtin', image: 'i', network: 'net', upstream: 'nginx-challenge:8080', config: cfg(), secret: SECRET });
  assert.ok(s.Env.includes('NC_BIND=:8080'));
  assert.ok(s.Env.includes('NC_SECRET=' + SECRET));
  assert.ok(s.Env.includes('NC_GOODBOTS=true'));
  assert.ok(s.Env.some(e => e.startsWith('NC_GOODBOTS_EXTRA=')));
  assert.strictEqual(s.HostConfig.ReadonlyRootfs, true);
  assert.deepStrictEqual(s.HostConfig.CapDrop, ['ALL']);
  assert.deepStrictEqual(s.HostConfig.SecurityOpt, ['no-new-privileges:true']);
  assert.strictEqual(s.HostConfig.NetworkMode, 'net');
  assert.strictEqual(s.HostConfig.PortBindings, undefined);
  assert.strictEqual(s.Labels['nginx-dashboard.engine'], 'builtin');
});
check('anubis : cle 64 hex, domaines, pas de NC_*', () => {
  const key = 'b'.repeat(64);
  const s = C.buildContainerSpec({ engine: 'anubis', image: 'i', upstream: 'anubis:8923', config: cfg(), secret: key });
  assert.ok(s.Env.includes('ED25519_PRIVATE_KEY_HEX=' + key));
  assert.ok(s.Env.includes('BIND=:8923'));
  assert.ok(s.Env.includes('REDIRECT_DOMAINS=a.com,b.com'));
  assert.ok(s.Env.includes('COOKIE_DOMAIN=a.com'));
  assert.ok(!s.Env.some(e => e.startsWith('NC_')));
  assert.strictEqual(s.HostConfig.NetworkMode, 'nginx-net');
});

console.log('\napplyEnv() : ENV > yml > defaut');
check('ENV l emporte sur le yml, valeur d ENV invalide ignoree', () => {
  const base = C.parseChallengeConfig('difficulty_bits: 12\ncookie_hours: 10\n').config;
  const r = C.applyEnv(base, { difficultyBits: '20', cookieHours: '9999', goodbots: 'false', secret: SECRET });
  assert.strictEqual(r.config.difficultyBits, 20);
  assert.strictEqual(r.config.cookieHours, 10);
  assert.strictEqual(r.config.goodbots, false);
  assert.strictEqual(r.config.secret, SECRET);
  assert.strictEqual(r.errors.length, 1);
});
check('sans ENV : config inchangee', () => {
  const base = C.parseChallengeConfig('difficulty_bits: 12\n').config;
  const r = C.applyEnv(base, {});
  assert.strictEqual(r.config.difficultyBits, 12);
  assert.deepStrictEqual(r.errors, []);
});

console.log(`\n${pass} PASS, ${fail} FAIL`);
process.exit(fail ? 1 : 0);
