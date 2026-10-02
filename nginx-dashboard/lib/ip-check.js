'use strict';
/**
 * Verification independante de l IP publique — voir GODNS_IP_CHECK dans
 * lib/config.js pour le "pourquoi" (retour utilisateur v12.39.0 : GoDNS a
 * mis a jour tous ses enregistrements DNS vers une IP Cloudflare au lieu de
 * l IP reelle du serveur).
 *
 * Interroge plusieurs services "what is my IP" independants en parallele et
 * ne conclut qu au consensus (majorite absolue) : un seul service compromis,
 * mal configure ou lui-meme derriere un CDN ne suffit pas a fausser le
 * resultat tant que les autres sont d accord entre eux. Sans majorite claire
 * (ex: chaque service renvoie une IP differente), consensus est null plutot
 * que de choisir arbitrairement — c est a l appelant de traiter ce cas comme
 * "indetermine", pas comme "conforme".
 */

const https = require('https');
const http  = require('http');
const cfg   = require('./config');

const IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;

/** Recupere le corps texte d une URL, avec un delai d attente court. Ne rejette jamais : renvoie null en cas d echec. */
function fetchText(url, timeoutMs = 5000) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve(null); }
    const lib = u.protocol === 'http:' ? http : https;
    const req = lib.get(u, { timeout: timeoutMs, headers: { 'user-agent': cfg.HTTP_USER_AGENT } }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return resolve(null); }
      let body = '';
      res.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
      res.on('end', () => resolve(body));
      res.on('error', () => resolve(null));
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
  });
}

/** Interroge une liste de services et renvoie l IPv4 extraite de chacun (ou null si injoignable/reponse illisible). */
async function collectPublicIps(urls, timeoutMs) {
  const results = await Promise.all(urls.map(async (url) => {
    const body = await fetchText(url, timeoutMs);
    const m = body && body.match(IPV4_RE);
    return { url, ip: m ? m[1] : null };
  }));
  return results;
}

/** Majorite absolue parmi les IP obtenues (ignore les echecs). null si aucune majorite ne se degage. */
function majorityIp(results) {
  const counts = new Map();
  for (const r of results) {
    if (!r.ip) continue;
    counts.set(r.ip, (counts.get(r.ip) || 0) + 1);
  }
  let best = null, bestCount = 0, total = 0;
  for (const [ip, count] of counts) {
    total += count;
    if (count > bestCount) { best = ip; bestCount = count; }
  }
  if (!best || bestCount * 2 <= total) return null; // pas de majorite absolue
  return best;
}

/**
 * Verifie l IP rapportee par GoDNS (extraite de ses journaux) contre le
 * consensus de plusieurs services independants.
 * @param {string|null} reportedIp IP que GoDNS pense avoir detectee, ou null.
 * @param {string[]} urls Services a interroger.
 * @returns {{checked:boolean, consensusIp:string|null, sources:Array, mismatch:boolean}}
 */
async function checkPublicIp(reportedIp, urls, timeoutMs) {
  if (!urls || urls.length === 0) return { checked: false, consensusIp: null, sources: [], mismatch: false };
  const sources = await collectPublicIps(urls, timeoutMs);
  const consensusIp = majorityIp(sources);
  const mismatch = !!(reportedIp && consensusIp && reportedIp !== consensusIp);
  return { checked: true, consensusIp, sources, mismatch };
}

module.exports = { fetchText, collectPublicIps, majorityIp, checkPublicIp };
