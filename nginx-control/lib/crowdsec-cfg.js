'use strict';
/**
 * CrowdSec settings resolution, shared by features/crowdsec.js (dashboard
 * metrics/Prometheus/bouncer reads) and lib/crowdsec-lapi.js (machine
 * auth/ban/unban) — both used to read CROWDSEC_URL/CROWDSEC_API_KEY/etc.
 * directly off lib/config.js as frozen, env-only constants.
 *
 * getCrowdsecCfg() reads crowdsec.yml fresh on every call and overlays it on
 * those same env vars, which now act only as a fallback default — the same
 * "YAML wins when set, env is the fallback" rule used for git.yml and
 * ANALYZER_DEFAULT_IMAGE. An existing .env-only deployment keeps working
 * unchanged (crowdsec.yml is optional); an operator who wants to change the
 * LAPI URL, API key or CROWDSEC_LOCAL_ONLY from the Configuration page can,
 * without restarting the container.
 */

const fs  = require('fs');
const cfg = require('./config');
const { parseFlatYaml } = require('./simple-yaml');

function getCrowdsecCfg() {
  const fromEnv = {
    url:             cfg.CROWDSEC_URL,
    apiKey:          cfg.CROWDSEC_API_KEY,
    promUrl:         cfg.CROWDSEC_PROM_URL,
    localOnly:       cfg.CROWDSEC_LOCAL_ONLY,
    machineId:       cfg.CROWDSEC_MACHINE_ID,
    machinePassword: cfg.CROWDSEC_MACHINE_PASSWORD,
  };
  if (!fs.existsSync(cfg.CROWDSEC_CONFIG_FILE)) return fromEnv;
  try {
    const raw = fs.readFileSync(cfg.CROWDSEC_CONFIG_FILE, 'utf8');
    // Fix (audit finding MISC-10): shared parser strips a trailing inline
    // comment — see lib/simple-yaml.js.
    const y = parseFlatYaml(raw);
    return {
      url:             y.url              || fromEnv.url,
      apiKey:          y.api_key          || fromEnv.apiKey,
      promUrl:         y.prometheus_url   || fromEnv.promUrl,
      localOnly:       y.local_only !== undefined && y.local_only !== ''
        ? (y.local_only === 'true' || y.local_only === '1')
        : fromEnv.localOnly,
      machineId:       y.machine_id       || fromEnv.machineId,
      machinePassword: y.machine_password || fromEnv.machinePassword,
    };
  } catch (e) {
    console.warn('[crowdsec] crowdsec.yml load error, falling back to env:', e.message);
    return fromEnv;
  }
}

module.exports = { getCrowdsecCfg };
