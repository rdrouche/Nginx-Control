'use strict';
/**
 * Notifications : formulaires SMTP et règles d'alerte (page Notifications).
 *
 * Le stockage reste celui de lib/notify.js (smtp.yml / notifications.yml, relus
 * à chaud) : ce module ne fait que (1) décrire les champs, (2) valider ce que
 * le formulaire envoie, (3) régénérer le YAML. Aucune valeur n'est jamais
 * « corrigée » en silence, et rien de ce qui est écrit ne peut ajouter une
 * clé ou une ligne au fichier (valeurs sans saut de ligne, guillemets choisis
 * pour que le chargeur maison relise exactement la valeur saisie).
 *
 * Ajouter un type d'alerte = une entrée dans RULES (+ l'appel
 * sendNotification('<id>', …) à l'endroit voulu) : le formulaire suit.
 */

const L = (fr, en) => ({ fr, en });

const SECURITY = ['tls', 'ssl', 'plain'];

/** Préréglages proposés dans le formulaire (hôte/port/sécurité usuels). */
const SMTP_PRESETS = [
  { id: 'gmail',    label: 'Gmail',                 host: 'smtp.gmail.com',        port: 587, security: 'tls' },
  { id: 'outlook',  label: 'Outlook / Microsoft 365', host: 'smtp.office365.com',  port: 587, security: 'tls' },
  { id: 'ovh',      label: 'OVH',                   host: 'ssl0.ovh.net',          port: 465, security: 'ssl' },
  { id: 'infomaniak', label: 'Infomaniak',          host: 'mail.infomaniak.com',   port: 587, security: 'tls' },
  { id: 'brevo',    label: 'Brevo (Sendinblue)',    host: 'smtp-relay.brevo.com',  port: 587, security: 'tls' },
  { id: 'mailgun',  label: 'Mailgun',               host: 'smtp.mailgun.org',      port: 587, security: 'tls' },
  { id: 'local',    label: 'Relais local (sans chiffrement)', host: 'localhost',   port: 25,  security: 'plain' },
];

/** Types d'alertes. `fields` : paramètres numériques propres à la règle. */
const RULES = [
  { id: 'cert_expiry', label: L('Expiration des certificats', 'Certificate expiry'),
    description: L('Avertit avant l\'expiration d\'un certificat (vérification quotidienne).', 'Warns before a certificate expires (checked daily).'),
    fields: [
      { key: 'days_before', min: 1, max: 365, default: 30, label: L('Avertir X jours avant', 'Warn X days before') },
      { key: 'urgent_days', min: 1, max: 90, default: 5, label: L('Alerte urgente à X jours', 'Urgent alert at X days') },
    ] },
  { id: 'nginx_test_error', label: L('Erreur de test nginx (nginx -t)', 'nginx test error (nginx -t)'),
    description: L('Une configuration refusée par nginx -t (manuel, planifié ou conteneur éphémère).', 'A configuration rejected by nginx -t (manual, scheduled or ephemeral container).') },
  { id: 'nginx_reload', label: L('Reload nginx', 'nginx reload'),
    description: L('Reload nginx effectué ou en échec (page Control ou tâche planifiée).', 'nginx reload done or failed (Control page or scheduled task).') },
  { id: 'nginx_restart', label: L('Redémarrage nginx', 'nginx restart'),
    description: L('Redémarrage du conteneur nginx (tâche planifiée).', 'nginx container restart (scheduled task).') },
  { id: 'analyzer_alert', label: L('Alertes de l\'analyzer', 'Analyzer alerts'),
    description: L('Brute force, scan, flood, volumétrie détectés dans les journaux.', 'Brute force, scan, flood, volume spikes found in the logs.') },
  { id: 'analyzer_restart', label: L('Redémarrage de l\'analyzer', 'Analyzer restart'),
    description: L('Résultat de la tâche planifiée « Redémarrer l\'analyzer ».', 'Result of the “Restart the analyzer” scheduled task.') },
  { id: 'backup_failure', label: L('Échec de sauvegarde', 'Backup failure'),
    description: L('Une sauvegarde planifiée a échoué.', 'A scheduled backup failed.') },
  { id: 'blocklist_reload_failed', label: L('Échec du rechargement des listes de blocage', 'Blocklist reload failure'),
    description: L('Le rechargement nginx après mise à jour des listes a échoué.', 'The nginx reload after a blocklist update failed.') },
  { id: 'docker_autoconfig_failed', label: L('Échec de l\'autoconfiguration Docker', 'Docker autoconfig failure'),
    description: L('La génération automatique depuis les conteneurs Docker a échoué.', 'Automatic generation from Docker containers failed.') },
  { id: 'certsync_failed', label: L('Échec de synchronisation des certificats', 'Certificate sync failure'),
    description: L('Une synchronisation de certificats avec un autre Nginx Control a échoué.', 'A certificate synchronization with another Nginx Control failed.') },
  { id: 'agent_manifest_failed', label: L('Échec du manifeste des agents', 'Agent manifest failure'),
    description: L('La publication du manifeste vers les agents a échoué.', 'Publishing the manifest to the agents failed.') },
];

const MAX_RECIPIENTS = 20;
const EMAIL_RE = /^[^\s@<>()"',;:\\]+@[^\s@<>()"',;:\\]+\.[^\s@<>()"',;:\\]+$/;
const HOST_RE = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$|^\[[0-9A-Fa-f:.]+\]$/;
const CTRL_RE = /[\u0000-\u001f\u007f]/;

/**
 * Écrit une chaîne de façon que le chargeur de lib/notify.js la relise à
 * l'identique : il retire les guillemets de bord mais ne gère aucun
 * échappement, et coupe à la première occurrence du guillemet ouvrant. On
 * choisit donc le guillemet absent de la valeur ; les deux présents = refus.
 */
function quote(value) {
  const s = String(value);
  if (!s.includes('"')) return `"${s}"`;
  if (!s.includes("'")) return `'${s}'`;
  return null;
}

function cleanLine(v, max, name, { required = false } = {}) {
  const s = String(v === undefined || v === null ? '' : v).trim();
  if (CTRL_RE.test(s)) return { error: `${name} : caractères de contrôle interdits` };
  if (s.length > max) return { error: `${name} : ${max} caractères maximum` };
  if (required && !s) return { error: `${name} : obligatoire` };
  return { value: s };
}

// ─── SMTP ────────────────────────────────────────────────────────────────────

/** Vue du formulaire (jamais le mot de passe : seulement s'il existe). */
function smtpView(cfg) {
  const c = cfg || {};
  return {
    configured: !!cfg,
    enabled: c.enable === true || c.enable === 'true',
    host: String(c.host ?? ''),
    port: Number(c.port) || 587,
    security: SECURITY.includes(String(c.security || '').toLowerCase()) ? String(c.security).toLowerCase() : 'tls',
    ignoreSsl: c.ignore_ssl === true || c.ignore_ssl === 'true',
    from: String(c.from ?? ''),
    fromName: String(c.from_name ?? ''),
    username: String(c.username ?? ''),
    passwordSet: !!c.password,
  };
}

/**
 * Valide le formulaire SMTP. `prev` : configuration actuelle (pour conserver
 * le mot de passe quand le champ est laissé vide).
 * @returns {{ok:true, value:object}|{ok:false, error:string}}
 */
function validateSmtp(input, prev) {
  const i = input && typeof input === 'object' ? input : {};
  const enabled = i.enabled === true;
  const host = cleanLine(i.host, 253, 'Serveur', { required: enabled });
  if (host.error) return { ok: false, error: host.error };
  if (host.value && !HOST_RE.test(host.value)) return { ok: false, error: 'Serveur : nom d\'hôte ou adresse IP invalide' };
  const port = Number(i.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, error: 'Port : entier entre 1 et 65535' };
  const security = String(i.security || '').toLowerCase();
  if (!SECURITY.includes(security)) return { ok: false, error: 'Sécurité : tls, ssl ou plain' };
  const from = cleanLine(i.from, 254, 'Expéditeur', { required: enabled });
  if (from.error) return { ok: false, error: from.error };
  if (from.value && !EMAIL_RE.test(from.value)) return { ok: false, error: 'Expéditeur : adresse e-mail invalide' };
  const fromName = cleanLine(i.fromName, 80, 'Nom affiché');
  if (fromName.error) return { ok: false, error: fromName.error };
  const username = cleanLine(i.username, 254, 'Identifiant');
  if (username.error) return { ok: false, error: username.error };

  let password;
  if (i.clearPassword === true) password = '';
  else if (typeof i.password === 'string' && i.password !== '') password = i.password;
  else password = String(prev && prev.password !== undefined ? prev.password : '');
  if (CTRL_RE.test(password)) return { ok: false, error: 'Mot de passe : caractères de contrôle interdits' };
  if (password.length > 256) return { ok: false, error: 'Mot de passe : 256 caractères maximum' };
  if (password && quote(password) === null) return { ok: false, error: 'Mot de passe : ne peut pas contenir à la fois des guillemets simples et doubles' };
  if (username.value && quote(username.value) === null) return { ok: false, error: 'Identifiant : guillemets simples et doubles ensemble non pris en charge' };
  if (fromName.value && quote(fromName.value) === null) return { ok: false, error: 'Nom affiché : guillemets simples et doubles ensemble non pris en charge' };

  return { ok: true, value: {
    enable: enabled, host: host.value, port, security, ignore_ssl: i.ignoreSsl === true,
    from: from.value, from_name: fromName.value, username: username.value, password,
  } };
}

/** smtp.yml à partir d'une valeur validée. */
function smtpToYaml(v) {
  const q = s => (s === '' ? '""' : quote(s));
  return [
    '# SMTP Configuration — Nginx Dashboard notifications',
    '# Fichier généré par le formulaire de la page Notifications (Administration).',
    `enable: ${v.enable ? 'true' : 'false'}`,
    '',
    `host: ${v.host || 'smtp.example.com'}`,
    `port: ${v.port}`,
    '',
    '# Security: tls (STARTTLS) | ssl (SMTPS) | plain',
    `security: ${v.security}`,
    '',
    '# Ignore SSL certificate errors (self-signed)',
    `ignore_ssl: ${v.ignore_ssl ? 'true' : 'false'}`,
    '',
    `from: ${v.from || 'dashboard@example.com'}`,
    `from_name: ${q(v.from_name)}`,
    '',
    '# Leave empty if no authentication required',
    `username: ${q(v.username)}`,
    `password: ${q(v.password)}`,
    '',
  ].join('\n');
}

/** Configuration SMTP « à la manière du chargeur » pour un envoi de test non enregistré. */
function smtpAsConfig(v) { return { ...v }; }

// ─── Règles ──────────────────────────────────────────────────────────────────

function describeRules() {
  return RULES.map(r => ({
    id: r.id, label: r.label, description: r.description,
    fields: (r.fields || []).map(f => ({ key: f.key, min: f.min, max: f.max, default: f.default, label: f.label })),
  }));
}

/** Valeurs actuelles des règles (les sections inconnues sont renvoyées à part). */
function rulesView(cfg) {
  const c = cfg || {};
  const rules = RULES.map(r => {
    const cur = c[r.id] && typeof c[r.id] === 'object' ? c[r.id] : {};
    const vals = {};
    for (const f of r.fields || []) vals[f.key] = Number(cur[f.key]) || f.default;
    return {
      id: r.id, enabled: cur.enable === true || cur.enable === 'true',
      recipients: Array.isArray(cur.recipients) ? cur.recipients.map(String) : [], ...{ values: vals },
    };
  });
  const known = new Set(RULES.map(r => r.id));
  const unknown = Object.keys(c).filter(k => !known.has(k) && c[k] && typeof c[k] === 'object');
  return { rules, unknown };
}

/**
 * Valide les règles envoyées par le formulaire.
 * Entrée : { rules: [{ id, enabled, recipients:[...], values:{...} }] }
 * Les règles absentes de l'entrée gardent leur valeur actuelle ; les sections
 * inconnues du fichier (ajoutées à la main) sont conservées telles quelles.
 */
function validateRules(input, prevCfg) {
  const list = input && Array.isArray(input.rules) ? input.rules : null;
  if (!list) return { ok: false, error: 'règles absentes' };
  const prev = rulesView(prevCfg).rules;
  const out = {};
  for (const r of RULES) out[r.id] = prev.find(p => p.id === r.id);
  const seen = new Set();
  for (const it of list) {
    const rule = RULES.find(r => r.id === (it && it.id));
    if (!rule) return { ok: false, error: `type d'alerte inconnu : ${String(it && it.id).slice(0, 40)}` };
    if (seen.has(rule.id)) return { ok: false, error: `type d'alerte en double : ${rule.id}` };
    seen.add(rule.id);
    const name = rule.label.fr;
    const raw = Array.isArray(it.recipients) ? it.recipients : String(it.recipients || '').split(/[\s,;]+/).filter(Boolean);
    const recipients = [...new Set(raw.map(x => String(x).trim()).filter(Boolean))];
    if (recipients.length > MAX_RECIPIENTS) return { ok: false, error: `${name} : ${MAX_RECIPIENTS} destinataires maximum` };
    const bad = recipients.find(e => e.length > 254 || !EMAIL_RE.test(e));
    if (bad !== undefined) return { ok: false, error: `${name} : adresse invalide « ${bad.slice(0, 60)} »` };
    const enabled = it.enabled === true;
    if (enabled && !recipients.length) return { ok: false, error: `${name} : ajoutez au moins un destinataire pour activer l'alerte` };
    const values = {};
    for (const f of rule.fields || []) {
      const v = Number(it.values && it.values[f.key] !== undefined && it.values[f.key] !== '' ? it.values[f.key] : f.default);
      if (!Number.isInteger(v) || v < f.min || v > f.max) return { ok: false, error: `${name} — ${f.label.fr} : entier entre ${f.min} et ${f.max}` };
      values[f.key] = v;
    }
    if (rule.id === 'cert_expiry' && values.urgent_days > values.days_before) {
      return { ok: false, error: `${name} : l'alerte urgente doit être inférieure ou égale au délai d'avertissement` };
    }
    out[rule.id] = { id: rule.id, enabled, recipients, values };
  }
  return { ok: true, value: out };
}

/** notifications.yml à partir des règles validées + sections inconnues conservées. */
function rulesToYaml(rules, prevCfg) {
  const lines = [
    '# Notification rules — Nginx Dashboard',
    '# Fichier généré par le formulaire de la page Notifications (Administration).',
    '# Each section can have enable: true/false and a recipients list',
    '',
  ];
  const emit = (id, r, extras) => {
    lines.push(`${id}:`, `  enable: ${r.enabled ? 'true' : 'false'}`);
    for (const [k, v] of extras) lines.push(`  ${k}: ${v}`);
    lines.push('  recipients:');
    if (r.recipients.length) r.recipients.forEach(e => lines.push(`    - ${e}`));
    lines.push('');
  };
  for (const rule of RULES) {
    const r = rules[rule.id];
    emit(rule.id, r, (rule.fields || []).map(f => [f.key, r.values[f.key]]));
  }
  // Sections ajoutées à la main : conservées (enable, recipients, scalaires simples).
  const known = new Set(RULES.map(r => r.id));
  for (const [id, sec] of Object.entries(prevCfg || {})) {
    if (known.has(id) || !sec || typeof sec !== 'object' || !/^[a-z0-9_]+$/i.test(id)) continue;
    lines.push(`${id}:`);
    for (const [k, v] of Object.entries(sec)) {
      if (!/^[a-z0-9_]+$/i.test(k) || Array.isArray(v) || (v && typeof v === 'object')) continue;
      const sv = typeof v === 'string' ? quote(v) : String(v);
      if (sv !== null) lines.push(`  ${k}: ${sv}`);
    }
    if (Array.isArray(sec.recipients)) {
      lines.push('  recipients:');
      sec.recipients.filter(e => EMAIL_RE.test(String(e))).forEach(e => lines.push(`    - ${e}`));
    }
    lines.push('');
  }
  return lines.join('\n');
}

module.exports = {
  SMTP_PRESETS, RULES, SECURITY, MAX_RECIPIENTS,
  smtpView, validateSmtp, smtpToYaml, smtpAsConfig,
  describeRules, rulesView, validateRules, rulesToYaml,
  quote,
};
