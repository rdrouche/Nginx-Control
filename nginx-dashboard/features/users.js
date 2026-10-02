'use strict';
/**
 * User administration.
 *
 * Read-only over HTTP by design: accounts live in users.yml, which is the
 * source of truth and is version-controlled alongside the rest of the
 * configuration. The dashboard lists them and hashes a password on request,
 * but does not rewrite the file behind the operator's back — the one exception
 * being the automatic upgrade of a legacy digest at login, handled in lib/auth.
 */

const auth = require('../lib/auth');
const http = require('../lib/http');

const { PERMS, ROLE_PERMS, hasPerm, hashPassword, loadUsers, getUsers } = auth;
const { send, parseBody } = http;

function register(router) {
  /** Hash a password for pasting into users.yml. */
  router.post('/api/auth/hash', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return http.forbidden(res);
    const body = await parseBody(req);
    if (!body.password) return http.badRequest(res, 'password required');
    const { digest } = hashPassword(body.password);
    return send(res, 200, {
      digest,
      note: 'Copy this value into users.yml as the password field',
    });
  });

  /** List accounts and the permission matrix. Never returns password digests. */
  router.get('/api/auth/users', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return http.forbidden(res);
    loadUsers();
    return send(res, 200, {
      users: getUsers().map(u => ({
        username: u.username, role: u.role, name: u.name, enabled: u.enabled,
      })),
      roles: Object.keys(ROLE_PERMS),
      permissions: ROLE_PERMS,
    });
  });
}

module.exports = { register };
