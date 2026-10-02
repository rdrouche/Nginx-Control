'use strict';
/**
 * Réglages `challenge_*` et profils par vhost portés par config/challenge.yml.
 *
 * Le challenge HTTP est une fonctionnalité à part entière : on peut l'utiliser
 * sans liste de blocage. Ses réglages (challenge_enable, challenge_engine,
 * challenge_upstream, challenge_resolver, challenge_exempt_*) se posent donc
 * dans challenge.yml ; ceux de blocklists.yml (v12.63/12.64) restent lus pour la
 * compatibilité, challenge.yml l'emportant.
 *
 * v12.65.1 : liste `profiles:` — un snippet dédié par vhost.
 *   profiles:
 *     - name: forgejo
 *       mode: allbots                 # listed | all | allbots (défaut all)
 *       exempt_ua_regex: '^forgejo-runner/'   # absent = hérite du global
 */
const fs = require('fs');
const { parseBlocklistYaml } = require('./blocklist-yaml');
const { stripInlineComment } = require('./simple-yaml');

function scalar(raw) {
  const v = stripInlineComment(raw);
  if (/^".*"$/.test(v) || /^'.*'$/.test(v)) return v.slice(1, -1);
  if (v === '~' || v.toLowerCase() === 'null') return null;
  return v;
}

/** Lit la liste `profiles:` (items `  - name: x`, champs `    key: value`). */
function parseProfiles(text) {
  const out = [];
  let inList = false;
  let cur = null;
  for (const line of String(text || '').split('\n')) {
    const l = line.replace(/\r$/, '');
    if (!l.trim() || l.trim().startsWith('#')) continue;
    if (/^profiles\s*:\s*$/.test(l)) { inList = true; continue; }
    if (/^[A-Za-z_]+\s*:/.test(l)) { inList = false; cur = null; continue; }
    if (!inList) continue;
    let m = l.match(/^  - ([A-Za-z_]+)\s*:\s*(.*)$/);
    if (m) { cur = {}; out.push(cur); cur[m[1]] = scalar(m[2]); continue; }
    m = l.match(/^    ([A-Za-z_]+)\s*:\s*(.*)$/);
    if (m && cur) cur[m[1]] = scalar(m[2]);
  }
  return out;
}

/** @returns {object} clés challenge_* (valeurs typées) + challenge_profiles (liste brute) */
function challengeOverridesFromText(text) {
  const { config } = parseBlocklistYaml(text);
  const out = {};
  for (const [k, v] of Object.entries(config)) if (/^challenge_/.test(k)) out[k] = v;
  const profiles = parseProfiles(text);
  if (profiles.length) out.challenge_profiles = profiles;
  return out;
}

function readChallengeOverrides(file) {
  try { return challengeOverridesFromText(fs.readFileSync(file, 'utf8')); } catch { return {}; }
}

module.exports = { challengeOverridesFromText, readChallengeOverrides, parseProfiles };
