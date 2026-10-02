'use strict';
/**
 * lib/menu-visibility.js — visibilite des elements de menu optionnels
 * (WAF, GoDNS), reglable par config/menu.yml et/ou ENV (priorite ENV),
 * avec un mode "auto" pour WAF base sur le suffixe -waf/-coraza du tag
 * d image nginx (meme convention que lib/docker.js#stripVariantSuffix,
 * deja utilisee pour la comparaison de versions au moment des mises a jour).
 *
 * Isolation CONFIG_DIR/USERS_FILE comme les autres tests lib/* : chaque
 * test tourne dans un repertoire temporaire dedie pour ne jamais lire/ecrire
 * le vrai config/menu.yml du projet.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'menu-visibility-'));
process.env.CONFIG_DIR = tmpConfigDir;
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const checkAsync = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nlib/menu-visibility.js — visibilite des elements de menu optionnels');

function freshMenuVisibility() {
  for (const id of [require.resolve('../lib/config'), require.resolve('../lib/menu-visibility')]) {
    delete require.cache[id];
  }
  return require('../lib/menu-visibility');
}

function writeMenuYml(content) {
  fs.writeFileSync(path.join(tmpConfigDir, 'menu.yml'), content);
}
function removeMenuYml() {
  const f = path.join(tmpConfigDir, 'menu.yml');
  if (fs.existsSync(f)) fs.unlinkSync(f);
}

console.log('\nlooksWafCapable() — suffixe -waf/-coraza du tag d image');
check('image se terminant par -waf -> capable', () => {
  const { looksWafCapable } = freshMenuVisibility();
  assert.strictEqual(looksWafCapable('nginx:1.27-waf'), true);
});
check('image se terminant par -coraza -> capable', () => {
  const { looksWafCapable } = freshMenuVisibility();
  assert.strictEqual(looksWafCapable('my-registry/nginx:1.27-coraza'), true);
});
check('image standard sans suffixe -> pas capable', () => {
  const { looksWafCapable } = freshMenuVisibility();
  assert.strictEqual(looksWafCapable('nginx:1.27'), false);
});
check('image absente/vide -> pas capable, pas d exception', () => {
  const { looksWafCapable } = freshMenuVisibility();
  assert.strictEqual(looksWafCapable(null), false);
  assert.strictEqual(looksWafCapable(''), false);
  assert.strictEqual(looksWafCapable(undefined), false);
});

console.log('\nresolveToggle() — priorite ENV > YAML > defaut');
check('ni ENV ni YAML -> defaut (waf: auto, godns: show)', () => {
  delete process.env.MENU_WAF;
  delete process.env.MENU_GODNS;
  removeMenuYml();
  const { resolveToggle } = freshMenuVisibility();
  assert.deepStrictEqual(resolveToggle('waf'), { mode: 'auto', source: 'default' });
  assert.deepStrictEqual(resolveToggle('godns'), { mode: 'show', source: 'default' });
});
check('YAML seul -> valeur YAML utilisee', () => {
  delete process.env.MENU_WAF;
  delete process.env.MENU_GODNS;
  writeMenuYml('waf_menu: show\ngodns_menu: hide\n');
  const { resolveToggle } = freshMenuVisibility();
  assert.deepStrictEqual(resolveToggle('waf'), { mode: 'show', source: 'yaml' });
  assert.deepStrictEqual(resolveToggle('godns'), { mode: 'hide', source: 'yaml' });
});
check('ENV et YAML tous deux presents -> ENV gagne', () => {
  writeMenuYml('waf_menu: show\ngodns_menu: hide\n');
  process.env.MENU_WAF = 'hide';
  process.env.MENU_GODNS = 'show';
  const { resolveToggle } = freshMenuVisibility();
  assert.deepStrictEqual(resolveToggle('waf'), { mode: 'hide', source: 'env' });
  assert.deepStrictEqual(resolveToggle('godns'), { mode: 'show', source: 'env' });
  delete process.env.MENU_WAF;
  delete process.env.MENU_GODNS;
  removeMenuYml();
});
check('ENV avec une valeur non reconnue -> ignoree, repli sur YAML puis defaut', () => {
  writeMenuYml('waf_menu: show\n');
  process.env.MENU_WAF = 'peut-etre';
  const { resolveToggle } = freshMenuVisibility();
  assert.deepStrictEqual(resolveToggle('waf'), { mode: 'show', source: 'yaml' });
  delete process.env.MENU_WAF;
  removeMenuYml();
});
check('GODNS_MENU n accepte pas "auto" (pas d heuristique image pour GoDNS)', () => {
  process.env.MENU_GODNS = 'auto';
  const { resolveToggle } = freshMenuVisibility();
  assert.deepStrictEqual(resolveToggle('godns'), { mode: 'show', source: 'default' },
    '"auto" n est pas dans allowed pour godns -> ignore, repli sur le defaut');
  delete process.env.MENU_GODNS;
});
check('ENV vide ("") traite comme absente, pas comme une valeur -> repli sur YAML/defaut', () => {
  writeMenuYml('waf_menu: hide\n');
  process.env.MENU_WAF = '';
  const { resolveToggle } = freshMenuVisibility();
  assert.deepStrictEqual(resolveToggle('waf'), { mode: 'hide', source: 'yaml' });
  delete process.env.MENU_WAF;
  removeMenuYml();
});

console.log('\nresolveMenuVisibility() — resolution complete');
(async () => {
  await checkAsync('mode "show"/"hide" explicites -> pas de detection Docker necessaire', async () => {
    process.env.MENU_WAF = 'show';
    process.env.MENU_GODNS = 'hide';
    const { resolveMenuVisibility } = freshMenuVisibility();
    const v = await resolveMenuVisibility('nginx:1.27'); // image sans suffixe, sans importance ici
    assert.strictEqual(v.waf.visible, true);
    assert.strictEqual(v.waf.mode, 'show');
    assert.strictEqual(v.godns.visible, false);
    delete process.env.MENU_WAF;
    delete process.env.MENU_GODNS;
  });

  await checkAsync('mode "auto" avec une image WAF-capable fournie directement -> visible', async () => {
    const { resolveMenuVisibility } = freshMenuVisibility();
    const v = await resolveMenuVisibility('nginx:1.27-waf');
    assert.strictEqual(v.waf.mode, 'auto');
    assert.strictEqual(v.waf.visible, true);
    assert.strictEqual(v.waf.detectedImage, 'nginx:1.27-waf');
  });

  await checkAsync('mode "auto" avec une image standard fournie directement -> masque', async () => {
    const { resolveMenuVisibility } = freshMenuVisibility();
    const v = await resolveMenuVisibility('nginx:1.27');
    assert.strictEqual(v.waf.mode, 'auto');
    assert.strictEqual(v.waf.visible, false);
  });

  await checkAsync('godns par defaut -> visible (show)', async () => {
    const { resolveMenuVisibility } = freshMenuVisibility();
    const v = await resolveMenuVisibility('nginx:1.27');
    assert.strictEqual(v.godns.visible, true);
    assert.strictEqual(v.godns.mode, 'show');
  });

  await checkAsync('api/webhooks en mode "auto" -> masques tant qu API_TOKEN/WEBHOOK_SECRET ne sont pas configures (bug v12.41.0)', async () => {
    delete process.env.API_TOKEN;
    delete process.env.WEBHOOK_SECRET;
    const { resolveMenuVisibility } = freshMenuVisibility();
    const v = await resolveMenuVisibility('nginx:1.27');
    assert.strictEqual(v.api.mode, 'auto');
    assert.strictEqual(v.api.visible, false);
    assert.strictEqual(v.webhooks.mode, 'auto');
    assert.strictEqual(v.webhooks.visible, false);
  });

  await checkAsync('api/webhooks en mode "auto" -> visibles des que API_TOKEN/WEBHOOK_SECRET sont configures', async () => {
    process.env.API_TOKEN = 'a'.repeat(32);
    process.env.WEBHOOK_SECRET = 'b'.repeat(32);
    const { resolveMenuVisibility } = freshMenuVisibility();
    const v = await resolveMenuVisibility('nginx:1.27');
    assert.strictEqual(v.api.visible, true);
    assert.strictEqual(v.webhooks.visible, true);
    delete process.env.API_TOKEN;
    delete process.env.WEBHOOK_SECRET;
  });

  await checkAsync('docker_autoconfig/agents en mode "auto" -> reflete enable:true/false de leur propre fichier, sans fichier -> masques (v12.41.0 : opt-in, desactive par defaut)', async () => {
    const { resolveMenuVisibility } = freshMenuVisibility();
    const v = await resolveMenuVisibility('nginx:1.27');
    assert.strictEqual(v.dockerAutoconfig.visible, false);
    assert.strictEqual(v.agents.visible, false);
  });

  await checkAsync('docker_autoconfig/agents en mode "auto" -> masques quand enable: false dans leur fichier', async () => {
    fs.writeFileSync(path.join(tmpConfigDir, 'docker-autoconfig.yml'), 'enable: false\n');
    fs.writeFileSync(path.join(tmpConfigDir, 'agents.yml'), 'enable: false\n');
    const { resolveMenuVisibility } = freshMenuVisibility();
    const v = await resolveMenuVisibility('nginx:1.27');
    assert.strictEqual(v.dockerAutoconfig.visible, false);
    assert.strictEqual(v.agents.visible, false);
    fs.unlinkSync(path.join(tmpConfigDir, 'docker-autoconfig.yml'));
    fs.unlinkSync(path.join(tmpConfigDir, 'agents.yml'));
  });

  await checkAsync('docker_autoconfig/agents en mode "auto" -> visibles quand enable: true explicite dans leur fichier', async () => {
    fs.writeFileSync(path.join(tmpConfigDir, 'docker-autoconfig.yml'), 'enable: true\n');
    fs.writeFileSync(path.join(tmpConfigDir, 'agents.yml'), 'enable: true\n');
    const { resolveMenuVisibility } = freshMenuVisibility();
    const v = await resolveMenuVisibility('nginx:1.27');
    assert.strictEqual(v.dockerAutoconfig.visible, true);
    assert.strictEqual(v.agents.visible, true);
    fs.unlinkSync(path.join(tmpConfigDir, 'docker-autoconfig.yml'));
    fs.unlinkSync(path.join(tmpConfigDir, 'agents.yml'));
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
