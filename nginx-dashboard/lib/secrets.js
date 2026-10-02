'use strict';
/**
 * Masking of credentials in configuration files served to the UI.
 *
 * smtp.yml and godns.config.* hold an SMTP password and a DNS provider API
 * token in cleartext. Those files are editable from the dashboard, so they have
 * to travel to the browser — masked for everyone but an admin who explicitly
 * asks to reveal them.
 *
 * The subtle part is the return trip: saving a masked view must not write
 * "********" over the real password. unmaskSecrets() restores any value the
 * user left untouched, while still accepting a genuinely new one.
 *
 * Both YAML and JSON are supported, hence group 6: a JSON line ends with a
 * comma that must survive masking, or the file stops parsing.
 */

// 1=indent 2=opening quote 3=key 4=":" separator 5=value 6=trailing comma
//
// machine_password added for crowdsec.yml's CrowdSec "machine" (watcher)
// credential (see lib/crowdsec-cfg.js) — a literal addition to the
// enumeration rather than a generic "ends with _password" suffix match, to
// keep this regex's behavior exactly as predictable as it was before: only
// the exact key names listed here are ever masked, never guessed.
const SECRET_KEY_RE =
  /^(\s*)("?)(password|passwd|secret|token|api_key|apikey|license_key|private_key|credentials|machine_password)("?\s*:\s*)(.*?)(,?)\s*$/i;

const MASK_PLACEHOLDER = '********';

/** Replace secret-looking values with a placeholder, preserving JSON syntax. */
function maskSecretsInConfig(text) {
  if (!text) return text;
  return text.split('\n').map(line => {
    const m = line.match(SECRET_KEY_RE);
    if (!m) return line;
    const val = m[5].trim();
    if (!val || val === '""' || val === "''") return line;   // nothing to hide
    return `${m[1]}${m[2]}${m[3]}${m[4]}"${MASK_PLACEHOLDER}"${m[6]}`;
  }).join('\n');
}

/**
 * Re-inject real values where the client sent the placeholder back unchanged.
 * A value that differs from the placeholder is taken as a deliberate update.
 */
function unmaskSecrets(newText, oldText) {
  if (!newText || !oldText) return newText;
  const previous = {};
  for (const line of oldText.split('\n')) {
    const m = line.match(SECRET_KEY_RE);
    if (m) previous[m[3].toLowerCase()] = m[5];
  }
  return newText.split('\n').map(line => {
    const m = line.match(SECRET_KEY_RE);
    if (!m) return line;
    const val = m[5].trim().replace(/^["']|["']$/g, '');
    if (val !== MASK_PLACEHOLDER) return line;               // user typed a new value
    const prev = previous[m[3].toLowerCase()];
    return prev === undefined ? line : `${m[1]}${m[2]}${m[3]}${m[4]}${prev}${m[6]}`;
  }).join('\n');
}

/**
 * Apres unmaskSecrets() : un secret qui est toujours le masque n'avait aucune
 * valeur precedente a restaurer (champ vide a l'origine). Ecrire « ******** »
 * en faisait un vrai mot de passe ; on le remet a vide.
 */
function clearUnresolvedMasks(text) {
  if (!text) return text;
  return text.split('\n').map(line => {
    const m = line.match(SECRET_KEY_RE);
    if (!m) return line;
    return m[5].trim().replace(/^["']|["']$/g, '') === MASK_PLACEHOLDER ? `${m[1]}${m[2]}${m[3]}${m[4]}""${m[6]}` : line;
  }).join('\n');
}

module.exports = { SECRET_KEY_RE, MASK_PLACEHOLDER, maskSecretsInConfig, unmaskSecrets, clearUnresolvedMasks };
