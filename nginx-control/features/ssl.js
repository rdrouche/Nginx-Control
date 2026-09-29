'use strict';
/**
 * SSL certificate browser.
 *
 * Read-only: lists what is present in DIR_SSL (operator-supplied certificates)
 * and DIR_CERTS (Let's Encrypt output), and shows the details of one file.
 * Issuing and renewing belong to features/certbot.js.
 */

const cfg   = require('../lib/config');
const http  = require('../lib/http');
const auth  = require('../lib/auth');
const certs = require('../lib/certs');
const tree  = require('../lib/fs-tree');

const { PERMS, hasPerm } = auth;
const { send } = http;

function register(router) {
  router.get('/api/ssl', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_SSL)) return http.forbidden(res);
    return send(res, 200, certs.getAllCertificates());
  });

  /**
   * Details of a single certificate. The path comes from the client, so it is
   * resolved and confined: a plain startsWith() check once let
   * "…/ssl/../../etc/shadow" through.
   */
  router.get('/api/ssl/file', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_SSL)) return http.forbidden(res);
    const rawPath = url.searchParams.get('path');
    if (!rawPath) return http.badRequest(res, 'path param required');
    const filePath = tree.safeResolveWithin(rawPath, [cfg.DIR_SSL, cfg.DIR_CERTS]);
    if (!filePath) return http.forbidden(res, 'Access denied');
    const pem = tree.safeReadFile(filePath);
    if (!pem) return http.notFound(res, 'File not found');
    return send(res, 200, certs.parseCert(pem));
  });
}

module.exports = { register };
