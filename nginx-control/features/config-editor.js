'use strict';
/**
 * Generic raw editor for the feature configuration files that had no editor
 * at all until now: certbot.yml, certbot-dns.yml, geoipupdate.yml,
 * error-pages.yml, analyzer.yml, godns.yml, git.yml, crowdsec.yml,
 * goaccess.yml. Until this feature, changing any of them meant editing the
 * file directly on the host — the dashboard could only read them (structured
 * summaries for the status pages), never write.
 *
 * smtp.yml / notifications.yml / scheduler.yml (features/notifications.js)
 * and godns.config.yaml/json (features/godns.js) already have their own
 * raw editor using the exact same masking mechanism (lib/secrets.js) — this
 * feature does not duplicate or replace those, it only covers the files
 * that were missing one. FILES below is intentionally a flat allowlist, not
 * a directory listing: a `key` from the client always resolves through this
 * map, never straight to a filesystem path, so nothing outside this fixed
 * set of six files can be read or written from here.
 *
 * No per-file schema validation on save: every one of these files is read by
 * its own feature with a lenient line-based parser that already ignores
 * anything it doesn't recognize (same convention as certbot.js/geoipupdate.js
 * etc.), and none of them cache their parsed config in memory — each feature
 * reloads it fresh on every request, so writing the file here is immediately
 * effective without an explicit "reload" step.
 */

const fs   = require('fs');
const path = require('path');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const secrets = require('../lib/secrets');
const events  = require('../lib/events');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { maskSecretsInConfig, unmaskSecrets } = secrets;
const { logEvent } = events;

const FILES = [
  { key: 'certbot',      label: 'Certbot — défi HTTP',   file: cfg.CERTBOT_CONFIG_FILE },
  { key: 'certbot-dns',  label: 'Certbot — défi DNS',     file: cfg.CERTBOT_DNS_CONFIG_FILE },
  { key: 'geoipupdate',  label: 'GeoIP (geoipupdate)',    file: cfg.GEOIPUPDATE_CONFIG_FILE },
  { key: 'error-pages',  label: "Pages d'erreur",         file: cfg.ERROR_PAGES_CONFIG_FILE },
  { key: 'analyzer',     label: 'Analyseur de journaux',  file: path.join(cfg.CONFIG_DIR, 'analyzer.yml') },
  { key: 'godns',        label: 'GoDNS (paramètres)',     file: cfg.GODNS_CONFIG_FILE },
  { key: 'git',          label: 'Git (dépôt config)',     file: cfg.GIT_CONFIG_FILE },
  { key: 'crowdsec',     label: 'CrowdSec',               file: cfg.CROWDSEC_CONFIG_FILE },
  { key: 'goaccess',     label: 'GoAccess',               file: cfg.GOACCESS_CONFIG_FILE },
  { key: 'blocklists',   label: 'Blocklists IP',          file: cfg.BLOCKLIST_CONFIG_FILE },
  { key: 'deploy-tokens', label: 'Jetons de déploiement (CI/CD)', file: cfg.DEPLOY_TOKENS_FILE },
  { key: 'docker-autoconfig', label: 'Auto-config Docker (labels)', file: cfg.DOCKER_AUTOCONFIG_CONFIG_FILE },
  { key: 'agents', label: 'Hôtes Docker distants (agents)', file: cfg.AGENTS_CONFIG_FILE },
];

const byKey = key => FILES.find(f => f.key === key);

function register(router) {
  router.get('/api/config-editor/files', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const list = FILES.map(f => {
      const exists = fs.existsSync(f.file);
      let size = null, mtime = null;
      if (exists) {
        try { const st = fs.statSync(f.file); size = st.size; mtime = st.mtime.toISOString(); } catch {}
      }
      return { key: f.key, label: f.label, exists, size, mtime };
    });
    return send(res, 200, { files: list, canReveal: hasPerm(session, PERMS.MANAGE_USERS) });
  });

  router.get('/api/config-editor/file', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const entry = byKey(url.searchParams.get('key'));
    if (!entry) return httpLib.badRequest(res, 'unknown key');
    if (!fs.existsSync(entry.file)) return send(res, 200, { exists: false, content: '' });
    const raw    = fs.readFileSync(entry.file, 'utf8');
    const reveal = hasPerm(session, PERMS.MANAGE_USERS) && url.searchParams.get('reveal') === '1';
    return send(res, 200, {
      exists: true,
      content: reveal ? raw : maskSecretsInConfig(raw),
      masked: !reveal,
      canReveal: hasPerm(session, PERMS.MANAGE_USERS),
    });
  });

  router.post('/api/config-editor/file', async ({ req, res, session }) => {
    // SECURITY (fix v12.21.1, audit finding SEC-02): writing here used to
    // require only PERMS.DEPLOY, which the `operator` role holds. Several of
    // these files control what a subsequent feature does with the Docker
    // socket — analyzer.yml's `container_image`/`host_data_path` go straight
    // into `POST /containers/create` (features/analyzer.js), so an operator
    // could point them at an attacker-controlled image and `/` on the host,
    // then start it from the Analyzer page with the very same DEPLOY
    // permission. git.yml and deploy-tokens.yml are just as sensitive (a
    // rogue repo_url/branch, or a self-issued CI token). Writing any of
    // these files is now admin-only; reading (masked, as before) stays
    // DEPLOY so an operator can still see non-secret settings.
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return httpLib.forbidden(res);
    const body  = await parseBody(req);
    const entry = byKey(body.key);
    if (!entry) return httpLib.badRequest(res, 'unknown key');
    if (typeof body.content !== 'string' || !body.content) return httpLib.badRequest(res, 'content required');
    const previous = fs.existsSync(entry.file) ? fs.readFileSync(entry.file, 'utf8') : '';
    // Re-inject real secret values where the client sent the masked
    // placeholder back unchanged — same rule as the smtp/notifications and
    // godns raw editors, so a save from a non-revealing session can never
    // clobber a license_key/token/credentials value with "********".
    fs.writeFileSync(entry.file, unmaskSecrets(body.content, previous), 'utf8');
    logEvent('config_editor_save', `${entry.label} (${entry.key}) config saved`, session.username);
    return send(res, 200, { ok: true });
  });
}

module.exports = { register, FILES };
