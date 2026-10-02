'use strict';
/**
 * Direct nginx control: reload and configuration test.
 *
 * `POST /api/nginx/test-ephemeral` (v12.54.0) runs the same sandboxed
 * `nginx -t` as the Git test and the config add/edit pipeline — a throwaway
 * nginx container fed with a copy of the ACTIVE configuration — and returns
 * its complete output, mapping summary included.
 *
 * The verbose test runs `nginx -t` and, when it fails, follows with `nginx -T`
 * so the operator sees the full effective configuration next to the error —
 * the usual next question after a syntax failure.
 */

const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const notify  = require('../lib/notify');
const events  = require('../lib/events');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { execNginx, restartContainer, getContainerStats } = docker;
const { sendNotification } = notify;
const { logEvent } = events;

// testConfigEphemeral lives in features/deploy.js ; features never import each
// other, so server.js (the composition root) injects it — same pattern as
// features/configs.js.
let testConfigEphemeral = async () => { throw new Error('deploy not wired — call setDeps({ testConfigEphemeral })'); };
function setDeps({ testConfigEphemeral: t } = {}) {
  if (typeof t === 'function') testConfigEphemeral = t;
}

// One sandbox run at a time: each one creates a container and copies the whole
// configuration, so a double click (or a script in a loop) must not stack them.
let ephemeralRunning = false;

function register(router) {
  router.post('/api/nginx/reload', async ({ req, res, session, url, pathname }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    try { const r = await execNginx('nginx -s reload'); logEvent('nginx.reload', { result: r, by: session.username }, 'api'); return send(res, 200, { ok: true, ...r }); }
    catch(e) { logEvent('nginx.reload.error', { ...e, by: session.username }, 'api'); return send(res, 500, { error: 'Reload failed', ...e }); }
  });

  /**
   * A full container restart, distinct from `reload`: some changes only take
   * effect this way — loading or unloading a dynamic module such as
   * ModSecurity, an engine that got stuck, a leak that only a fresh process
   * clears. Unlike a reload, this causes a brief gap in service while the
   * container stops and starts, so it stays a deliberate, separate action
   * rather than a variant of reload.
   */
  router.post('/api/nginx/restart-container', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    try {
      const r = await restartContainer(10);
      logEvent('nginx.restart_container', { by: session.username }, 'api');
      return send(res, 200, r);
    } catch (e) {
      logEvent('nginx.restart_container.error', { ...e, by: session.username }, 'api');
      return send(res, 500, { error: 'Restart failed', ...e });
    }
  });

  /** One-shot CPU/memory/network snapshot for the nginx container. */
  router.get('/api/nginx/stats', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    try { return send(res, 200, { ok: true, ...(await getContainerStats()) }); }
    catch (e) { return send(res, 200, { ok: false, error: e.error || e.message || String(e) }); }
  });

  router.post('/api/nginx/test', async ({ req, res, session, url, pathname }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    try { const r = await execNginx('nginx -t'); logEvent('nginx.test', { result: r, by: session.username }, 'api'); return send(res, 200, { ok: true, valid: true, ...r }); }
    catch(e) {
      logEvent('nginx.test.error', { ...e, by: session.username }, 'api');
      // Notification
      sendNotification('nginx_test_error',
        '[Nginx Dashboard] nginx -t FAILED',
        'nginx configuration test failed.\n\n' + (e.stderr || e.stdout || JSON.stringify(e))
      ).catch(() => {});
      return send(res, 200, { ok: false, valid: false, ...e });
    }
  });

  /**
   * Test of the active configuration in a throwaway nginx container.
   * Unlike `/api/nginx/test` (exec inside the production container), this never
   * touches the running server and uses the image/mounts the deploy pipeline
   * uses, so its verdict is the one a deploy or an edit would get. Always 200
   * with `valid` + the full `output` (an invalid config is a normal result for
   * the UI); a 500 means the sandbox itself could not run (Docker unreachable,
   * unmappable workspace).
   */
  router.post('/api/nginx/test-ephemeral', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    if (ephemeralRunning) return send(res, 409, { error: 'Un test éphémère est déjà en cours' });
    ephemeralRunning = true;
    const t0 = Date.now();
    try {
      const r = await testConfigEphemeral({});
      const durationMs = Date.now() - t0;
      logEvent('nginx.test.ephemeral', { valid: r.valid, exitCode: r.exitCode, image: r.image, durationMs, by: session.username }, 'api');
      if (!r.valid) {
        sendNotification('nginx_test_error',
          '[Nginx Dashboard] ephemeral nginx -t FAILED',
          'The ephemeral nginx configuration test failed.\n\n' + (r.output || '')
        ).catch(() => {});
      }
      return send(res, 200, { ok: true, valid: !!r.valid, exitCode: r.exitCode, image: r.image, output: r.output || '', durationMs });
    } catch (e) {
      logEvent('nginx.test.ephemeral.error', { error: e.message || String(e), by: session.username }, 'api');
      return send(res, 500, { ok: false, error: e.message || String(e) });
    } finally {
      ephemeralRunning = false;
    }
  });

  router.post('/api/nginx/test-verbose', async ({ req, res, session, url, pathname }) => {
    // Fix (audit finding, Basse/"Sécurité et durcissement"): this used to
    // gate on VIEW_CONFIGS — a read-only permission a plain viewer holds —
    // even though the action it performs is neither read-only nor free of
    // side effects: on a failing test it runs `nginx -T` (a full effective
    // configuration dump — every vhost, every upstream, everything an
    // operator ever put in a `# ` comment) and fires an operator-configured
    // error notification (email/webhook), both triggerable on demand and as
    // often as the caller likes. The plain `/api/nginx/test` route right
    // above already requires NGINX_CONTROL for the exact same category of
    // action (running a real nginx subprocess); this now matches it.
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    // Run nginx -t first, then if fails run nginx -T for full config dump
    let testResult, dumpResult = null;
    try {
      testResult = await execNginx('nginx -t');
      return send(res, 200, { ok: true, valid: true, stdout: testResult.stdout || '', stderr: testResult.stderr || '', dump: null });
    } catch(e) {
      testResult = e;
      // Try full config dump for debugging
      try { dumpResult = await execNginx('nginx -T'); } catch(e2) { dumpResult = { stdout: '', stderr: e2.stderr || e2.error || String(e2) }; }
      sendNotification('nginx_test_error',
        '[Nginx Dashboard] nginx -t FAILED',
        'nginx configuration test failed.\n\n' + (e.stderr || e.stdout || '')
      ).catch(() => {});
      return send(res, 200, {
        ok: false, valid: false,
        stdout: testResult.stdout || '', stderr: testResult.stderr || testResult.error || '',
        dump: { stdout: dumpResult?.stdout || '', stderr: dumpResult?.stderr || '' }
      });
    }
  });
}

module.exports = { register, setDeps };
