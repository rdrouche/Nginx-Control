'use strict';
/**
 * Minimal YAML subset for config/agents.yml — same restricted shape and
 * rationale as lib/docker-autoconfig-yaml.js (zero-npm-dependency project):
 * flat top-level scalar settings only, no lists.
 *
 *   enable: true
 *   offline_after_sec: 90
 *   max_vhosts_per_agent: 50
 *   tunnel_enable: true
 *   tunnel_target: http://nginx-dashboard:3000
 *   certbot_retry_minutes: 15
 */

// Meme forme que lib/agent-manifest.js#AGENT_TARGET_RE (scheme://host:port,
// sans chemin) — duplique volontairement plutot que require() entre deux
// modules lib/ pour cette seule regex triviale, chacun reste lisible seul.
const TUNNEL_TARGET_RE = /^(https?):\/\/([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*)(:([0-9]{1,5}))?$/i;

function parseScalar(raw) {
  const v = raw.trim();
  if (v === '' || v === '~' || v.toLowerCase() === 'null') return null;
  if (v.toLowerCase() === 'true') return true;
  if (v.toLowerCase() === 'false') return false;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  if (/^".*"$/.test(v) || /^'.*'$/.test(v)) return v.slice(1, -1);
  return v;
}

function parseAgentsYaml(text) {
  const errors = [];
  const config = {};
  const lines = String(text || '').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const raw = lines[i].replace(/\r$/, '');
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const topMatch = raw.match(/^([A-Za-z_]+)\s*:\s*(.*)$/);
    if (topMatch) { config[topMatch[1]] = parseScalar(topMatch[2]); continue; }
    errors.push(`Ligne ${lineNo} : syntaxe non reconnue — "${raw.trim()}"`);
  }
  return { config, errors };
}

/**
 * Parse + validate in one pass, normalizing defaults.
 *
 * `enable` defaults to `false` (retour utilisateur v12.41.0, reverses the
 * previous secure-by-default-true stance) — remote hosts is an opt-in
 * feature: an operator who never wrote this file, or wrote it without an
 * explicit `enable: true`, should not have the agent enrollment endpoint
 * live by default. Existing deployments that rely on it must add
 * `enable: true` explicitly.
 */
function parseAndValidate(text) {
  const { config, errors } = parseAgentsYaml(text);
  let tunnelTarget = 'http://nginx-dashboard:3000';
  if (config.tunnel_target !== undefined) {
    if (typeof config.tunnel_target === 'string' && TUNNEL_TARGET_RE.test(config.tunnel_target)) {
      tunnelTarget = config.tunnel_target;
    } else {
      errors.push(`tunnel_target invalide : "${config.tunnel_target}" (attendu scheme://host:port, ex: http://nginx-dashboard:3000) — valeur par defaut conservee`);
    }
  }
  // Fix (audit report, Basse/"Agents (dashboard)"): a remote agent's manifest
  // could previously request `listen` on ANY port 1-65535 — including 22,
  // 3000, or any other port already used by something else on the host —
  // with nothing to stop it. Opt-in and unrestricted by default (no existing
  // deployment breaks from upgrading): only enforced once an operator
  // actually lists the ports they want to allow, same flat-scalar-only YAML
  // shape as the rest of this file (a comma-separated string, since this
  // format has no list syntax — see the file's own header comment).
  let allowedListenPorts = null;
  if (typeof config.allowed_listen_ports === 'string' && config.allowed_listen_ports.trim()) {
    const parts = config.allowed_listen_ports.split(',').map(s => s.trim()).filter(Boolean);
    const ports = parts.map(p => Number(p));
    if (parts.length && ports.every(p => Number.isInteger(p) && p >= 1 && p <= 65535)) {
      allowedListenPorts = ports;
    } else {
      errors.push(`allowed_listen_ports invalide : "${config.allowed_listen_ports}" (attendu une liste de ports separes par des virgules, ex: 80,443) — restriction ignoree`);
    }
  }
  const settings = {
    enable: config.enable === true,
    offlineAfterSec: Number.isFinite(config.offline_after_sec) && config.offline_after_sec >= 10
      ? config.offline_after_sec : 90,
    maxVhostsPerAgent: Number.isFinite(config.max_vhosts_per_agent) && config.max_vhosts_per_agent >= 1
      ? config.max_vhosts_per_agent : 50,
    // Mode 3 (tunnel NAT sortant) — voir features/agent-tunnel.js.
    tunnelEnable: config.tunnel_enable !== false,
    tunnelTarget,
    // certbot_http/certbot_dns pour les agents (v12.21.0) — meme delai
    // d'attente entre deux tentatives d'emission qu'en Partie 1
    // (docker-autoconfig.yml#certbot_retry_minutes), pour ne jamais epuiser
    // les limites de debit reelles de Let's Encrypt sur un domaine mal
    // configure pousse par un agent distant.
    certbotRetryMinutes: Number.isFinite(config.certbot_retry_minutes) && config.certbot_retry_minutes >= 1
      ? config.certbot_retry_minutes : 15,
    allowedListenPorts,
  };
  return { settings, errors };
}

module.exports = { parseAgentsYaml, parseAndValidate };
