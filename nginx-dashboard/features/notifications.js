'use strict';
/**
 * Notification settings: SMTP and alert rules (forms), plus the raw YAML files.
 *
 * Forms (v12.57.0, lib/notify-form.js):
 *   GET  /api/notify/form         SMTP view (no password), presets, rule schema + values
 *   POST /api/notify/smtp-form    save the SMTP form (empty password = keep)
 *   POST /api/notify/rules-form   save the alert rules form
 *   POST /api/notify/test         { to, smtp? } — test mail; `smtp` = unsaved form values
 *   GET/POST /api/notify/config-files   advanced raw YAML editors (unchanged)
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
const form    = require('../lib/notify-form');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { maskSecretsInConfig, unmaskSecrets, clearUnresolvedMasks } = secrets;
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
    let override;
    if (body.smtp) {
      // Test with the form values, saved or not (empty password = the saved one).
      const v = form.validateSmtp({ ...body.smtp, enabled: true }, cfg);
      if (!v.ok) return send(res, 200, { ok: false, reason: v.error });
      override = form.smtpAsConfig(v.value);
    }
    const to = String(body.to || (override ? override.from : cfg?.from) || '').trim();
    if (!to || to.length > 254 || /[\r\n,;\s<>]/.test(to)) return send(res, 200, { ok: false, reason: 'Adresse de test invalide' });
    const t0 = Date.now();
    const result = await notify.sendMail([to],
      '[Nginx Dashboard] Test notification',
      'This is a test notification from Nginx Dashboard.\n\nSMTP configuration is working correctly.',
      override
    ).catch(e => ({ ok: false, reason: e.message }));
    return send(res, 200, { ...result, durationMs: Date.now() - t0 });
  });

  router.get('/api/notify/form', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const rv = form.rulesView(notify.loadNotifConfig());
    return send(res, 200, {
      smtp: form.smtpView(notify.loadSmtpConfig()), presets: form.SMTP_PRESETS,
      schema: form.describeRules(), rules: rv.rules, unknownSections: rv.unknown,
      maxRecipients: form.MAX_RECIPIENTS,
    });
  });

  router.post('/api/notify/smtp-form', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    try {
      const v = form.validateSmtp(body, notify.loadSmtpConfig());
      if (!v.ok) return send(res, 400, { ok: false, error: v.error });
      fs.writeFileSync(SMTP_CONFIG_FILE, form.smtpToYaml(v.value), { encoding: 'utf8', mode: 0o600 });
      notify.loadSmtpConfig();
      events.logEvent('notify_config_save', { what: 'smtp', enabled: v.value.enable, host: v.value.host, by: session.username }, 'api');
      return send(res, 200, { ok: true, smtp: form.smtpView(notify.loadSmtpConfig()) });
    } catch (e) { return send(res, 500, { ok: false, error: e.message }); }
  });

  router.post('/api/notify/rules-form', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    try {
      const prev = notify.loadNotifConfig();
      const v = form.validateRules(body, prev);
      if (!v.ok) return send(res, 400, { ok: false, error: v.error });
      fs.writeFileSync(NOTIF_CONFIG_FILE, form.rulesToYaml(v.value, prev), 'utf8');
      notify.loadNotifConfig();
      events.logEvent('notify_config_save', { what: 'rules', by: session.username }, 'api');
      return send(res, 200, { ok: true, ...(() => { const r = form.rulesView(notify.loadNotifConfig()); return { rules: r.rules, unknownSections: r.unknown }; })() });
    } catch (e) { return send(res, 500, { ok: false, error: e.message }); }
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
      fs.writeFileSync(file, clearUnresolvedMasks(unmaskSecrets(incoming, previous)), 'utf8');
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
