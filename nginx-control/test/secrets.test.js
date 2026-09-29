'use strict';
const assert = require('assert');
const S = require('../lib/secrets');
let pass=0, fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const YAML = 'host: smtp.example.com\npassword: SuperSecret123\nport: 587\nfrom: a@b.c';
const JSON_CFG = '{\n  "provider": "Cloudflare",\n  "password": "tok123",\n  "interval": 600\n}';

console.log('\nmasquage');
check('le secret YAML disparait', () => {
  const m = S.maskSecretsInConfig(YAML);
  assert.ok(!m.includes('SuperSecret123'));
  assert.ok(m.includes('"********"'));
});
check('les autres champs sont intacts', () => {
  const m = S.maskSecretsInConfig(YAML);
  assert.ok(m.includes('host: smtp.example.com') && m.includes('port: 587'));
});
check('le JSON masque reste parsable', () => {
  JSON.parse(S.maskSecretsInConfig(JSON_CFG));   // la virgule doit survivre
});
check('une valeur vide n est pas masquee', () => {
  assert.strictEqual(S.maskSecretsInConfig('password: ""'), 'password: ""');
});

console.log('\naller-retour (le piege : ecraser le vrai mot de passe)');
check('YAML restaure a l identique', () => {
  assert.strictEqual(S.unmaskSecrets(S.maskSecretsInConfig(YAML), YAML), YAML);
});
check('JSON restaure a l identique', () => {
  assert.strictEqual(S.unmaskSecrets(S.maskSecretsInConfig(JSON_CFG), JSON_CFG), JSON_CFG);
});
check('une nouvelle valeur est conservee', () => {
  const edited = YAML.replace('SuperSecret123', 'NouveauMotDePasse');
  assert.ok(S.unmaskSecrets(edited, YAML).includes('NouveauMotDePasse'));
});
check('le placeholder n atteint jamais le disque', () => {
  const out = S.unmaskSecrets(S.maskSecretsInConfig(YAML), YAML);
  assert.ok(!out.includes(S.MASK_PLACEHOLDER));
});

console.log('\nvariantes de cles');
for (const key of ['token', 'api_key', 'license_key', 'secret', 'private_key'])
  check(`${key} est masque`, () => assert.ok(S.maskSecretsInConfig(`${key}: valeur`).includes('********')));
check('une cle anodine est ignoree', () => {
  assert.strictEqual(S.maskSecretsInConfig('username: admin'), 'username: admin');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
