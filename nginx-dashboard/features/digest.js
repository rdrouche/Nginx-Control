'use strict';
/**
 * Periodic operational digest — read access (latest, history) and a manual
 * "generate now" trigger. Generation itself (lib/digest.js) is configured
 * once at boot in server.js, the composition root; scheduling lives in
 * lib/scheduler.js. This file is purely the HTTP surface over both.
 */

const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const events  = require('../lib/events');
const digest  = require('../lib/digest');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;

function register(router) {
  router.get('/api/digest/latest', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const latest = events.getLatestDigest();
    return send(res, 200, { digest: latest });
  });

  router.get('/api/digest/history', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const limit = Math.min(+url.searchParams.get('limit') || 20, 100);
    return send(res, 200, { digests: events.listDigests(limit) });
  });

  router.addPrefix('GET', '/api/digest/', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    // /api/digest/latest and /api/digest/history are registered as exact
    // routes above and always win over this prefix route (Router.match()
    // checks its exact map first) — only a numeric id ever reaches here.
    const id = +url.pathname.slice('/api/digest/'.length);
    if (!id) return httpLib.badRequest(res, 'invalid id');
    const d = events.getDigest(id);
    if (!d) return httpLib.notFound(res, 'digest not found');
    return send(res, 200, { digest: d });
  });

  /**
   * On-demand generation — the same "manual trigger alongside the scheduled
   * one" pattern already used for reload and container restart elsewhere in
   * this project. Requires DEPLOY, matching those other manual actions: it
   * queries the analyzer and CrowdSec, not free to trigger from a read-only
   * role.
   */
  router.post('/api/digest/generate', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const periodHours = +url.searchParams.get('period_hours') || 24;
    try {
      const d = await digest.generateDigest(periodHours);
      const id = events.saveDigest(d);
      events.logEvent('digest.manual', `Digest generated manually (#${id})`, session.username);
      return send(res, 200, { digest: { id, ...d } });
    } catch (e) {
      return httpLib.serverError(res, e);
    }
  });

  /**
   * Manual delete — same "/remove, POST, DEPLOY permission" pattern as the
   * other destructive actions in this project (analyzer exceptions, alert
   * clearing, WAF clearing). Automatic retention (purgeOldDigests(), see
   * lib/events.js) already bounds the table on its own; this is purely for
   * an operator who wants a specific report gone right now (e.g. a test run
   * or a digest generated with the wrong period).
   */
  router.post('/api/digest/remove', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const id = +body.id;
    if (!id) return httpLib.badRequest(res, 'id required');
    const deleted = events.deleteDigest(id);
    if (deleted) events.logEvent('digest.remove', `Digest #${id} deleted manually`, session.username);
    return send(res, 200, { ok: deleted });
  });
}

module.exports = { register };
