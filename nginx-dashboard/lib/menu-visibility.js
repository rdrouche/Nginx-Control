'use strict';
/**
 * Visibilite des elements de menu optionnels (WAF, GoDNS, ...) — retour
 * utilisateur : le menu WAF s'affichait tout le temps, meme avec une image
 * nginx qui n'a rien a voir avec un WAF (Coraza/ModSecurity), et il
 * n'existait aucun moyen de masquer un menu jamais utilise (GoDNS, par
 * exemple) sans modifier le code.
 *
 * Meme discipline de priorite que partout ailleurs dans ce projet : une
 * variable d'environnement, des qu'elle est DEFINIE (une chaine vide ne
 * compte pas — voir resolveToggle() plus bas), l'emporte toujours sur
 * config/menu.yml, qui l'emporte lui-meme sur le defaut cable en dur. Relu a
 * chaque appel (pas de cache) — changer menu.yml prend effet au prochain
 * chargement de page, sans redemarrer le conteneur.
 *
 * WAF a un troisieme mode, "auto" (le defaut) : le nav n'est affiche que si
 * l'image nginx en cours d'execution ressemble a un build compatible WAF
 * (suffixe de tag "-waf"/"-coraza" — meme convention que
 * lib/docker.js#stripVariantSuffix(), deja utilisee pour la comparaison de
 * version a la mise a jour). GoDNS n'a pas d'equivalent (rien dans une image
 * de conteneur ne dit "cet operateur utilise du DNS dynamique") : "show"/
 * "hide" seulement. D'autres elements optionnels pourront rejoindre TOGGLES
 * ci-dessous sans toucher au reste de ce fichier ni a la route qui l'expose
 * (features/menu-config.js).
 */
const fs = require('fs');
const cfg = require('./config');
const { parseFlatYaml } = require('./simple-yaml');
const { parseImageTag, stripVariantSuffix } = require('./docker');
const { parseAndValidate: parseDockerAutoconfig } = require('./docker-autoconfig-yaml');
const { parseAndValidate: parseAgents } = require('./agents-yaml');

const TOGGLES = {
  waf:   { envVar: 'MENU_WAF',   yamlKey: 'waf_menu',   default: 'auto', allowed: ['auto', 'show', 'hide'] },
  godns: { envVar: 'MENU_GODNS', yamlKey: 'godns_menu',  default: 'show', allowed: ['show', 'hide'] },
  // v12.41.0 (retour utilisateur) : REST API et Webhooks n ont de sens que si
  // un jeton/secret est reellement configure (sinon la page ne fait
  // qu afficher "non configure") ; Auto-config Docker et Hotes distants ont
  // deja leur propre interrupteur (`enable: true/false` dans
  // docker-autoconfig.yml/agents.yml), mais le nav ne le refletait pas — un
  // operateur qui desactive la fonctionnalite continuait a la voir dans le
  // menu. Les quatre ont un mode "auto" qui reflete cet etat existant plutot
  // que d en inventer un second reglage a maintenir en parallele.
  api:               { envVar: 'MENU_API',              yamlKey: 'api_menu',               default: 'auto', allowed: ['auto', 'show', 'hide'] },
  webhooks:          { envVar: 'MENU_WEBHOOKS',          yamlKey: 'webhooks_menu',           default: 'auto', allowed: ['auto', 'show', 'hide'] },
  docker_autoconfig: { envVar: 'MENU_DOCKER_AUTOCONFIG', yamlKey: 'docker_autoconfig_menu',  default: 'auto', allowed: ['auto', 'show', 'hide'] },
  agents:            { envVar: 'MENU_AGENTS',            yamlKey: 'agents_menu',             default: 'auto', allowed: ['auto', 'show', 'hide'] },
};

function loadMenuConfig() {
  if (!fs.existsSync(cfg.MENU_CONFIG_FILE)) return {};
  try {
    return parseFlatYaml(fs.readFileSync(cfg.MENU_CONFIG_FILE, 'utf8'));
  } catch (e) {
    console.warn('[menu] Config load error:', e.message);
    return {};
  }
}

/** Resout un seul reglage : { mode, source }, source valant 'env'|'yaml'|'default'. Une valeur presente mais non reconnue (typo) est ignoree avec un avertissement plutot que de silencieusement retomber sur le defaut sans explication. */
function resolveToggle(key) {
  const t = TOGGLES[key];
  const envRaw = process.env[t.envVar];
  if (envRaw !== undefined && envRaw !== '') {
    const mode = envRaw.trim().toLowerCase();
    if (t.allowed.includes(mode)) return { mode, source: 'env' };
    console.warn(`[menu] ${t.envVar}=${JSON.stringify(envRaw)} non reconnu (attendu : ${t.allowed.join('/')}), valeur ignoree`);
  }
  const yamlCfg = loadMenuConfig();
  const yamlRaw = yamlCfg[t.yamlKey];
  if (yamlRaw !== undefined && yamlRaw !== '') {
    const mode = String(yamlRaw).trim().toLowerCase();
    if (t.allowed.includes(mode)) return { mode, source: 'yaml' };
    console.warn(`[menu] ${cfg.MENU_CONFIG_FILE} : ${t.yamlKey}=${JSON.stringify(yamlRaw)} non reconnu (attendu : ${t.allowed.join('/')}), valeur ignoree`);
  }
  return { mode: t.default, source: 'default' };
}

/**
 * Un tag d'image ressemble-t-il a un build compatible WAF ? Reutilise
 * EXACTEMENT la meme regle que lib/docker.js#stripVariantSuffix() (deja
 * utilisee pour la comparaison de version a la mise a jour) — un seul
 * endroit qui connait ce suffixe, jamais une seconde regex a maintenir en
 * parallele.
 */
function looksWafCapable(imageRef) {
  if (!imageRef) return false;
  const tag = parseImageTag(imageRef);
  return stripVariantSuffix(tag) !== tag;
}

/**
 * Lit `enable` depuis un fichier de config *-.yml deja gere par le projet
 * (docker-autoconfig.yml, agents.yml), en reutilisant leur propre
 * parseAndValidate() — jamais une seconde lecture/interpretation du meme
 * fichier. Illisible ou absent -> `true` (le defaut de ces deux fichiers,
 * voir leurs commentaires "secure-by-default" respectifs) : une erreur de
 * lecture ici ne doit jamais, a elle seule, faire disparaitre un menu.
 */
function readFeatureEnabled(file, parseAndValidate) {
  try {
    const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    return parseAndValidate(text).settings.enable !== false;
  } catch (e) {
    console.warn(`[menu] Lecture de ${file} :`, e.message);
    return true;
  }
}

/**
 * Resolution complete, prete a envoyer au frontend. `nginxImage` (la
 * reference complete de l'image, ex. "user/nginx-dashboard:1.2.3-waf") est
 * optionnel — le fournir evite un second appel Docker quand l'appelant l'a
 * deja sous la main ; sinon elle est detectee ici via
 * lib/system-info.js#detectNginxImage(), la MEME detection que celle
 * affichee sur la page Systeme, pour ne jamais donner deux reponses
 * differentes a la meme question. Import fait a l'appel (pas en tete de
 * fichier) uniquement pour eviter de payer ce require quand l'appelant a
 * deja l'information — lib/system-info.js n'importe pas ce module en
 * retour, il n'y a donc aucun cycle.
 */
async function resolveMenuVisibility(nginxImage) {
  const waf     = resolveToggle('waf');
  const godns   = resolveToggle('godns');
  const api     = resolveToggle('api');
  const webhooks = resolveToggle('webhooks');
  const dockerAutoconfig = resolveToggle('docker_autoconfig');
  const agents  = resolveToggle('agents');

  let wafVisible;
  let wafDetectedImage = null;
  if (waf.mode === 'auto') {
    if (nginxImage === undefined) {
      const { detectNginxImage } = require('./system-info');
      const detected = await detectNginxImage();
      nginxImage = detected.value;
    }
    wafDetectedImage = nginxImage || null;
    wafVisible = looksWafCapable(nginxImage);
  } else {
    wafVisible = waf.mode === 'show';
  }

  const apiVisible = api.mode === 'auto' ? cfg.apiTokenActive() : api.mode === 'show';
  const webhooksVisible = webhooks.mode === 'auto' ? cfg.isWebhookSecretConfigured() : webhooks.mode === 'show';
  const dockerAutoconfigVisible = dockerAutoconfig.mode === 'auto'
    ? readFeatureEnabled(cfg.DOCKER_AUTOCONFIG_CONFIG_FILE, parseDockerAutoconfig)
    : dockerAutoconfig.mode === 'show';
  const agentsVisible = agents.mode === 'auto'
    ? readFeatureEnabled(cfg.AGENTS_CONFIG_FILE, parseAgents)
    : agents.mode === 'show';

  return {
    waf:      { visible: wafVisible, mode: waf.mode, source: waf.source, detectedImage: wafDetectedImage },
    godns:    { visible: godns.mode === 'show', mode: godns.mode, source: godns.source },
    api:      { visible: apiVisible, mode: api.mode, source: api.source },
    webhooks: { visible: webhooksVisible, mode: webhooks.mode, source: webhooks.source },
    dockerAutoconfig: { visible: dockerAutoconfigVisible, mode: dockerAutoconfig.mode, source: dockerAutoconfig.source },
    agents:   { visible: agentsVisible, mode: agents.mode, source: agents.source },
  };
}

module.exports = { TOGGLES, loadMenuConfig, resolveToggle, looksWafCapable, readFeatureEnabled, resolveMenuVisibility };
