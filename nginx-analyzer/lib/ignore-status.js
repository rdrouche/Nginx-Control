'use strict';
/**
 * Codes HTTP ignorés par la détection (v12.65.1) : DETECT_IGNORE_STATUS="444,403".
 * Les requêtes déjà refusées par un autre mécanisme (ex. blocklist en « 444 »)
 * ne comptent plus pour les règles ni pour la baseline : elles ne déclenchent
 * plus d'alerte. Elles restent comptées dans les statistiques et les hits de blocklist.
 */
function parseIgnoreStatus(raw) {
  const out = new Set();
  for (const part of String(raw || '').split(/[\s,;]+/)) {
    if (!/^\d{3}$/.test(part)) continue;
    const n = Number(part);
    if (n >= 100 && n <= 599) out.add(n);
  }
  return out;
}
module.exports = { parseIgnoreStatus };
