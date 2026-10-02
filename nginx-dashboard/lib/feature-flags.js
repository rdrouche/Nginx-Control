'use strict';
/**
 * Simple marche/arret pour des fonctionnalites qui n ont pas besoin de leur
 * propre fichier de configuration dedie (contrairement a
 * docker-autoconfig.yml/agents.yml, qui configurent aussi le COMPORTEMENT
 * detaille d une fonctionnalite complexe, pas seulement si elle tourne) —
 * voir FEATURES_CONFIG_FILE dans lib/config.js pour pourquoi ce fichier est
 * distinct de menu.yml (visibilite de nav uniquement) et sans rapport avec
 * features/nginx-control.js (reload/redemarrage/stats nginx).
 *
 * Meme discipline de priorite que resolveToggle() dans
 * lib/menu-visibility.js : une variable d environnement, des qu elle est
 * DEFINIE (une chaine vide ne compte pas), l emporte toujours sur
 * config/features.yml, qui l emporte lui-meme sur le defaut cable en dur.
 * Relu a chaque appel (pas de cache) — changer features.yml prend effet
 * immediatement, sans redemarrer le conteneur.
 *
 * Ajouter un nouvel interrupteur = une ligne dans FLAGS ci-dessous, rien
 * d autre a toucher dans ce fichier.
 */
const fs = require('fs');
const cfg = require('./config');
const { parseFlatYaml } = require('./simple-yaml');

const FLAGS = {
  // v12.45.0 (retour utilisateur) : le "message important"/alerte distante
  // (features/alerting.js) est opt-in par defaut — meme raisonnement que
  // docker-autoconfig/agents (lib/docker-autoconfig-yaml.js) : une
  // fonctionnalite qui fait un appel reseau sortant periodique ne doit pas
  // se mettre en marche toute seule au premier demarrage.
  alerting: { envVar: 'ALERTING_ENABLE', yamlKey: 'alerting_enable', default: false },
};

function loadFeaturesConfig() {
  if (!fs.existsSync(cfg.FEATURES_CONFIG_FILE)) return {};
  try {
    return parseFlatYaml(fs.readFileSync(cfg.FEATURES_CONFIG_FILE, 'utf8'));
  } catch (e) {
    console.warn('[features] Config load error:', e.message);
    return {};
  }
}

/** Parses a flat-yaml string value ("true"/"false", case-insensitive) into a boolean, or null if unrecognized. */
function parseBoolString(v) {
  const s = String(v).trim().toLowerCase();
  if (s === 'true' || s === '1') return true;
  if (s === 'false' || s === '0') return false;
  return null;
}

/** Resout un seul interrupteur : { enabled, source }, source valant 'env'|'yaml'|'default'. */
function resolveFlag(key) {
  const f = FLAGS[key];
  if (!f) throw new Error(`[features] interrupteur inconnu : ${key}`);
  const envRaw = process.env[f.envVar];
  if (envRaw !== undefined && envRaw.trim() !== '') {
    const parsed = parseBoolString(envRaw);
    if (parsed !== null) return { enabled: parsed, source: 'env' };
    console.warn(`[features] ${f.envVar}=${JSON.stringify(envRaw)} non reconnu (attendu : true/false), valeur ignoree`);
  }
  const yamlCfg = loadFeaturesConfig();
  if (yamlCfg[f.yamlKey] !== undefined) {
    const parsed = parseBoolString(yamlCfg[f.yamlKey]);
    if (parsed !== null) return { enabled: parsed, source: 'yaml' };
    console.warn(`[features] ${cfg.FEATURES_CONFIG_FILE}: ${f.yamlKey}=${JSON.stringify(yamlCfg[f.yamlKey])} non reconnu (attendu : true/false), valeur ignoree`);
  }
  return { enabled: f.default, source: 'default' };
}

function isFeatureEnabled(key) {
  return resolveFlag(key).enabled;
}

module.exports = { FLAGS, resolveFlag, isFeatureEnabled };
