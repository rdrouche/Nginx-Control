'use strict';
/**
 * Routes for the in-app notification center (lib/notifications.js) — the
 * bell/dropdown in the header. This feature only exposes the read/list/
 * mark-read/delete surface; pushing a notification is `lib/notifications.js`'s
 * pushNotification(), called directly by whichever feature has something to
 * report (monitor.js, certbot.js, analyzer.js, lib/scheduler.js, ...) —
 * exactly like they already call lib/events.js's logEvent() today. Nothing
 * here needs setDeps(): a lib is freely require()-able by any feature, only
 * feature-to-feature dependencies go through the composition root.
 *
 * Gated on PERMS.VIEW_METRICS (granted to every role, including viewer) —
 * this is the operator's own read/unread state on a shared feed, not a
 * change to any actual infrastructure, so there is no reason to restrict it
 * further than the rest of the read-only dashboard.
 */

const httpLib = require('../lib/http');
const auth = require('../lib/auth');
const notifications = require('../lib/notifications');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;

function register(router) {
  router.get('/api/notifications', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 200);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10) || 0;
    const unreadOnly = url.searchParams.get('unreadOnly') === 'true';
    const list = notifications.listNotifications({ limit, offset, unreadOnly });
    return send(res, 200, { notifications: list, unreadCount: notifications.getUnreadCount() });
  });

  router.get('/api/notifications/unread-count', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    return send(res, 200, { unreadCount: notifications.getUnreadCount() });
  });

  router.post('/api/notifications/read-all', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    notifications.markAllRead();
    return send(res, 200, { ok: true, unreadCount: notifications.getUnreadCount() });
  });

  router.post('/api/notifications/clear-read', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    notifications.clearRead();
    return send(res, 200, { ok: true });
  });

  router.post('/api/notifications/clear', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    notifications.clearAll();
    return send(res, 200, { ok: true });
  });

  // POST /api/notifications/<id>/read — mark one notification read. Exact
  // routes above (read-all, clear-read, clear) always win over this prefix
  // (Router.match() checks its exact map before any prefix), so there is no
  // ambiguity between an action name and a numeric id in that slot.
  router.addPrefix('POST', '/api/notifications/', async ({ res, session, pathname }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const parts = pathname.split('/').filter(Boolean); // ['api','notifications','<id>','read']
    if (parts.length !== 4 || parts[3] !== 'read' || !/^\d+$/.test(parts[2])) return httpLib.notFound(res, 'Not found');
    notifications.markRead(parts[2]);
    return send(res, 200, { ok: true, unreadCount: notifications.getUnreadCount() });
  });

  // DELETE /api/notifications/<id> — dismiss one notification.
  router.addPrefix('DELETE', '/api/notifications/', async ({ res, session, pathname }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const id = pathname.split('/').pop();
    if (!/^\d+$/.test(id)) return httpLib.notFound(res, 'Not found');
    notifications.deleteNotification(id);
    return send(res, 200, { ok: true });
  });
}

module.exports = { register };
