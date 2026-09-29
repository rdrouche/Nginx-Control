'use strict';
/**
 * Notification settings: SMTP, alert rules and scheduled tasks.
 *
 * The three YAML files are editable from the dashboard, so they travel to the
 * browser — with credentials masked. Only an admin may reveal them, and saving
 * a masked view re-injects the real values rather than writing "********" over
 * the password.
 *
 * Delivery itself lives in lib/notify.js, shared with the scheduler.
 */

const fs = require('fs');

const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const notify  = require('../lib/notify');
const secrets = require('../lib/secrets');
const events  = require('../lib/events');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { maskSecretsInConfig, unmaskSecrets } = secrets;
const { SMTP_CONFIG_FILE, NOTIF_CONFIG_FILE, SCHED_CONFIG_FILE } = notify;

function register(router) {
  router.get('/api/notify/smtp-config', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = notify.loadSmtpConfig();
    if (!cfg) return send(res, 200, { configured: false });
    // Never echo the password, even to an admin: this endpoint feeds a status
    // panel, not the editor.
    return send(res, 200, {
      configured: true, enabled: !!cfg.enable,
      host: cfg.host, port: cfg.port, security: cfg.security,
      from: cfg.from, from_name: cfg.from_name,
      hasAuth: !!cfg.username,
    });
  });

  router.post('/api/notify/test', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const cfg  = notify.loadSmtpConfig();
    const to   = body.to || cfg?.from || 'admin@localhost';
    const result = await notify.sendMail([to],
      '[Nginx Dashboard] Test notification',
      'This is a test notification from Nginx Dashboard.\n\nSMTP configuration is working correctly.'
    ).catch(e => ({ ok: false, reason: e.message }));
    return send(res, 200, result);
  });

  router.get('/api/notify/config-files', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    // Only admins may see cleartext credentials; everyone else gets them masked.
    const reveal = hasPerm(session, PERMS.MANAGE_USERS) && url.searchParams.get('reveal') === '1';
    const read = f => {
      if (!fs.existsSync(f)) return { exists: false, content: '' };
      const raw = fs.readFileSync(f, 'utf8');
      return { exists: true, content: reveal ? raw : maskSecretsInConfig(raw), masked: !reveal };
    };
    return send(res, 200, {
      smtp:          read(SMTP_CONFIG_FILE),
      notifications: read(NOTIF_CONFIG_FILE),
      scheduler:     read(SCHED_CONFIG_FILE),
      canReveal:     hasPerm(session, PERMS.MANAGE_USERS),
    });
  });

  router.post('/api/notify/config-files', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    // Saving a masked view must not overwrite the real secrets.
    const write = (file, incoming, reload) => {
      const previous = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
      fs.writeFileSync(file, unmaskSecrets(incoming, previous), 'utf8');
      reload();
    };
    if (body.smtp)          write(SMTP_CONFIG_FILE,  body.smtp,          notify.loadSmtpConfig);
    if (body.notifications) write(NOTIF_CONFIG_FILE, body.notifications, notify.loadNotifConfig);
    if (body.scheduler)     write(SCHED_CONFIG_FILE, body.scheduler,     notify.loadSchedConfig);
    events.logEvent('notify_config_save', 'Notification/scheduler config saved');
    return send(res, 200, { ok: true });
  });
}

module.exports = { register };
