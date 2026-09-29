'use strict';
/**
 * Page "Système" (registre de configuration du dashboard lui-même) — extrait
 * de public/index.html dans le cadre du decoupage JS + traduction (voir
 * CHANGELOG.md). Charge apres le script inline principal : partage le meme
 * scope global (api(), t(), svgEsc(), ...), pas un module ES.
 *
 * `cat.name` (nom de categorie) et `entry.description` viennent du backend
 * (lib/system-info.js), toujours en francais cote serveur — ce fichier les
 * fait passer par une table de correspondance vers des cles data-i18n
 * (`sysinfo.category.*`, `sysinfo.entryDesc.*`) plutot que de les afficher
 * bruts. Une entree nouvellement ajoutee au backend sans sa traduction n est
 * pas cassee pour autant : sysinfoCategoryName()/sysinfoEntryDesc() retombent
 * sur le texte francais brut tant que sa cle n existe pas encore dans les
 * dictionnaires — mieux vaut un intitule en francais qu une cle brute
 * affichee a l ecran.
 */

/** Categorie (francais, telle qu ecrite dans lib/system-info.js) -> slug de cle data-i18n. */
const SYSINFO_CATEGORY_SLUG = {
  'Général': 'general',
  'Comportement de déploiement': 'deployBehavior',
  'Sécurité & sessions': 'security',
  'Déploiement Git': 'gitDeploy',
  'Répertoires nginx': 'nginxDirs',
  'Sync & mises à jour': 'syncUpdates',
  'Rétention': 'retention',
  'Alertes': 'alerting',
  // Docker, GeoIP, CrowdSec, GoAccess, Branding, Menu, GoDNS : identiques en
  // francais et en anglais, pas besoin d une cle de traduction.
};

/** Nom de fichier YAML -> slug de cle data-i18n pour sa description (colonne "Contenu"). */
const SYSINFO_YAML_PURPOSE_SLUG = {
  'users.yml': 'users_yml', 'smtp.yml': 'smtp_yml', 'notifications.yml': 'notifications_yml',
  'scheduler.yml': 'scheduler_yml', 'certbot.yml': 'certbot_yml', 'certbot-dns.yml': 'certbot_dns_yml',
  'godns.yml': 'godns_yml', 'geoipupdate.yml': 'geoipupdate_yml', 'error-pages.yml': 'error_pages_yml',
  'crowdsec.yml': 'crowdsec_yml', 'git.yml': 'git_yml', 'analyzer.yml': 'analyzer_yml',
  'blocklists.yml': 'blocklists_yml',
  'deploy-tokens.yml': 'deploy_tokens_yml',
  'docker-autoconfig.yml': 'docker_autoconfig_yml',
  'menu.yml': 'menu_yml',
  'features.yml': 'features_yml',
};

/**
 * Lit une cle dans le dictionnaire courant sans jamais retomber sur la cle
 * brute (contrairement a t()) : utile ici, ou une cle peut legitimement ne
 * pas exister encore (nouvelle entree backend). Retombe sur `fallback` (le
 * texte francais du backend) plutot que d afficher `sysinfo.entryDesc.XYZ`
 * a l ecran.
 */
function sysinfoLookup(key, fallback) {
  const dict = TRANSLATIONS[LANG] || TRANSLATIONS.en;
  return (dict && dict[key]) || (TRANSLATIONS.en && TRANSLATIONS.en[key]) || fallback;
}

function sysinfoCategoryName(name) {
  const slug = SYSINFO_CATEGORY_SLUG[name];
  return slug ? sysinfoLookup('sysinfo.category.' + slug, name) : name;
}

function sysinfoEntryDesc(entry) {
  if (!entry.description) return null;
  return sysinfoLookup('sysinfo.entryDesc.' + entry.key, entry.description);
}

function sysinfoYamlPurpose(y) {
  const slug = SYSINFO_YAML_PURPOSE_SLUG[y.file];
  return slug ? sysinfoLookup('sysinfo.yamlPurpose.' + slug, y.purpose) : y.purpose;
}

/** Le backend renvoie ce message fixe (non localise) quand l auto-detection echoue. */
function sysinfoDetectErrorText(entry) {
  return entry.detectError === 'Conteneur nginx introuvable'
    ? t('sysinfo.containerNotFound')
    : entry.detectError;
}

const SYSINFO_OVERRIDE_LABEL = () => ({
  env: t('sysinfo.override.env'),
  yaml: t('sysinfo.override.yaml'),
  fixed: t('sysinfo.override.fixed'),
});

function sysinfoOverrideText(o) {
  if (!o) return '—';
  const labels = SYSINFO_OVERRIDE_LABEL();
  if (o.kind === 'env')      return `${labels.env}: <code>${svgEsc(o.var)}</code>`;
  if (o.kind === 'yaml')     return `${labels.yaml}: <code>${svgEsc(o.file)}</code>`;
  if (o.kind === 'fixed')    return labels.fixed;
  if (o.kind === 'env_yaml') return `${labels.env}: <code>${svgEsc(o.var)}</code> / ${labels.yaml}: <code>${svgEsc(o.file)}</code>`;
  return '—';
}

// v12.32.0 : API_TOKEN/WEBHOOK_SECRET peuvent aussi etre generes depuis
// cette page (bouton), plutot que seulement via .env — voir
// features/system-info.js pour les deux routes POST correspondantes. Meme
// principe qu un jeton d agent : affiche UNE SEULE FOIS a la generation,
// jamais revelable ensuite (sysinfoSecretOpen() reutilise l overlay dedie).
const SYSINFO_GENERATABLE = {
  API_TOKEN:      { generate: '/system-info/generate-api-token',      revoke: '/system-info/revoke-api-token',      field: 'token',
                     titleKey: 'sysinfo.generateApiTokenTitle',      warningKey: 'sysinfo.secretWarningApiToken',      confirmKey: 'sysinfo.confirmRevokeApiToken' },
  WEBHOOK_SECRET: { generate: '/system-info/generate-webhook-secret', revoke: '/system-info/revoke-webhook-secret', field: 'secret',
                     titleKey: 'sysinfo.generateWebhookSecretTitle', warningKey: 'sysinfo.secretWarningWebhook',       confirmKey: 'sysinfo.confirmRevokeWebhookSecret' },
};

async function sysinfoGenerateSecret(key) {
  const cfg = SYSINFO_GENERATABLE[key];
  if (!cfg) return;
  const r = await api(cfg.generate, { method: 'POST' });
  if (!r || !r[cfg.field]) { alert(t('sysinfo.generateError')); return; }
  sysinfoSecretOpen(t(cfg.titleKey), t(cfg.warningKey), r[cfg.field]);
  await loadSystemInfo();
}
async function sysinfoRevokeSecret(key) {
  const cfg = SYSINFO_GENERATABLE[key];
  if (!cfg) return;
  if (!confirm(t(cfg.confirmKey))) return;
  await api(cfg.revoke, { method: 'POST' });
  await loadSystemInfo();
}
let sysinfoLastSecret = '';
function sysinfoSecretOpen(title, warning, value) {
  sysinfoLastSecret = value;
  document.getElementById('sysinfo-secret-title').textContent = title;
  document.getElementById('sysinfo-secret-warning').textContent = warning;
  document.getElementById('sysinfo-secret-value').textContent = value;
  document.getElementById('sysinfo-secret-overlay').style.display = 'flex';
}
function sysinfoSecretClose() {
  document.getElementById('sysinfo-secret-overlay').style.display = 'none';
  sysinfoLastSecret = '';
}
function sysinfoSecretCopy() {
  // Fix (retour utilisateur v12.44.0) : ne faisait rien en HTTP simple
  // (navigator.clipboard absent hors contexte securise) — voir
  // copyToClipboard() dans index.html pour le detail et le repli
  // document.execCommand('copy').
  if (!sysinfoLastSecret) return;
  copyToClipboard(sysinfoLastSecret).then(ok => copyFeedback('sysinfo-secret-copy-btn', ok));
}

function sysinfoGenerateButtons(entry) {
  const cfg = SYSINFO_GENERATABLE[entry.key];
  if (!cfg) return '';
  const revokeBtn = entry.value
    ? `<button class="btn sm" onclick="sysinfoRevokeSecret('${entry.key}')">${svgEsc(t('sysinfo.revoke'))}</button>`
    : '';
  return ` <button class="btn sm" onclick="sysinfoGenerateSecret('${entry.key}')">${svgEsc(t('sysinfo.generate'))}</button>${revokeBtn}`;
}

function sysinfoValueText(entry) {
  if (entry.key === 'NGINX_IMAGE') {
    if (entry.detectError) return `<span style="color:var(--red)">${svgEsc(t('sysinfo.detectFailed', { msg: sysinfoDetectErrorText(entry) }))}</span>`;
    if (entry.autoDetected) return `<span title="${svgEsc(t('sysinfo.autoDetectedTooltip'))}">${svgEsc(entry.value || '—')} <span style="color:var(--text3);font-size:10px">${svgEsc(t('sysinfo.autoDetectedLabel'))}</span></span>`;
    return svgEsc(entry.value);
  }
  if (entry.sensitive) {
    const badge = entry.value
      ? `<span style="color:var(--green)">&#10003; ${svgEsc(t('sysinfo.configured'))}</span>`
      : `<span style="color:var(--text3)">${svgEsc(t('sysinfo.notConfigured'))}</span>`;
    return badge + sysinfoGenerateButtons(entry);
  }
  if (entry.value === '' || entry.value === null || entry.value === undefined) return `<span style="color:var(--text3)">${svgEsc(t('sysinfo.empty'))}</span>`;
  if (typeof entry.value === 'boolean') return entry.value
    ? `<span style="color:var(--green)">${svgEsc(t('sysinfo.on'))}</span>`
    : `<span style="color:var(--text3)">${svgEsc(t('sysinfo.off'))}</span>`;
  return svgEsc(String(entry.value));
}

function sysinfoDefaultText(entry) {
  if (entry.sensitive) return entry.default ? t('sysinfo.configured') : t('sysinfo.notConfigured');
  if (entry.default === '' || entry.default === null || entry.default === undefined) return `<span style="color:var(--text3)">${svgEsc(t('sysinfo.empty'))}</span>`;
  if (typeof entry.default === 'boolean') return entry.default ? t('sysinfo.on') : t('sysinfo.off');
  return svgEsc(String(entry.default));
}

function sysinfoIsDefault(entry) {
  if (entry.key === 'NGINX_IMAGE') return false; // toujours affiche comme information, pas comme ecart
  if (entry.sensitive) return entry.value === entry.default;
  return entry.value === entry.default;
}

async function loadSystemInfo() {
  const body = document.getElementById('sysinfo-body');
  const yamlBody = document.getElementById('sysinfo-yaml-body');
  if (!body) return;
  const d = await api('/system-info').catch(() => null);
  if (!d) { body.innerHTML = `<div class="card" style="color:var(--red)">${svgEsc(t('sysinfo.loadError'))}</div>`; return; }

  body.innerHTML = (d.categories || []).map(cat => `
    <div class="card" style="margin-bottom:14px">
      <div class="ctitle" style="margin-bottom:8px">${svgEsc(sysinfoCategoryName(cat.name))}</div>
      <div class="tw">
        <table class="sync-table">
          <thead><tr><th>${svgEsc(t('sysinfo.col.name'))}</th><th>${svgEsc(t('sysinfo.col.currentValue'))}</th><th>${svgEsc(t('sysinfo.col.defaultValue'))}</th><th>${svgEsc(t('sysinfo.col.override'))}</th><th>${svgEsc(t('sysinfo.col.explanation'))}</th></tr></thead>
          <tbody>
            ${cat.entries.map(e => `
              <tr>
                <td><code>${svgEsc(e.key)}</code>${sysinfoIsDefault(e) ? '' : ` <span title="${svgEsc(t('sysinfo.differsFromDefault'))}" style="color:var(--amber)">&#9679;</span>`}</td>
                <td>${sysinfoValueText(e)}</td>
                <td style="color:var(--text3)">${sysinfoDefaultText(e)}</td>
                <td style="font-size:11px">${sysinfoOverrideText(e.override)}</td>
                <td style="color:var(--text2);font-size:11.5px">${svgEsc(sysinfoEntryDesc(e) || '—')}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>`).join('');

  if (yamlBody) {
    yamlBody.innerHTML = (d.yamlBackedSettings || []).map(y => `
      <tr><td><code>${svgEsc(y.file)}</code></td><td>${svgEsc(sysinfoYamlPurpose(y))}</td></tr>`).join('');
  }

  // v12.41.0 (retour utilisateur) : bouton "Changelog", visible seulement si
  // CHANGELOG_URL est configuree (voir CHANGELOG_URL dans la categorie "Sync
  // & mises a jour" ci-dessus, deja presente dans cette meme reponse —
  // aucun appel reseau supplementaire juste pour savoir si le bouton doit
  // s afficher).
  const changelogEntry = (d.categories || []).flatMap(c => c.entries).find(e => e.key === 'CHANGELOG_URL');
  const clBtn = document.getElementById('sysinfo-changelog-btn');
  if (clBtn) clBtn.style.display = (changelogEntry && changelogEntry.value) ? '' : 'none';

  // Meme principe pour le bouton "Alertes" (ALERTING_URL, v12.45.0) : visible
  // seulement si une URL est configuree, sans appel reseau supplementaire —
  // la fonctionnalite peut par ailleurs etre desactivee (ALERTING_ENABLE)
  // sans que l URL soit retiree, auquel cas le bouton reste visible (l
  // historique local reste consultable) mais alertingCheck() ne remontera
  // jamais de nouvelle alerte tant qu elle est desactivee.
  const alertingEntry = (d.categories || []).flatMap(c => c.entries).find(e => e.key === 'ALERTING_URL');
  const alBtn = document.getElementById('sysinfo-alerting-btn');
  if (alBtn) alBtn.style.display = (alertingEntry && alertingEntry.value) ? '' : 'none';
}

// ── Changelog (modale, CHANGELOG_URL) ───────────────────────────────────────
/**
 * Rendu Markdown volontairement minimal (pas de dependance externe, le
 * projet en a zero — voir README) : titres, listes a puces, gras, code
 * inline/blocs, liens. Le texte est d abord echappe HTML (svgEsc) puis les
 * quelques motifs Markdown reconnus sont reinjectes comme balises — jamais
 * l inverse (jamais de HTML brut venu du fichier distant insere tel quel),
 * pour rester sans risque meme si CHANGELOG_URL pointe vers un contenu
 * inattendu.
 */
function renderSimpleMarkdown(md) {
  const lines = svgEsc(md).split('\n');
  const html = [];
  let inList = false;
  let inCode = false;
  const closeList = () => { if (inList) { html.push('</ul>'); inList = false; } };
  for (const raw of lines) {
    if (/^```/.test(raw.trim())) { inCode = !inCode; html.push(inCode ? '<pre><code>' : '</code></pre>'); continue; }
    if (inCode) { html.push(raw + '\n'); continue; }
    const line = raw;
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { closeList(); html.push(`<h${h[1].length + 2}>${inlineMd(h[2])}</h${h[1].length + 2}>`); continue; }
    const li = line.match(/^\s*[-*]\s+(.*)$/);
    if (li) { if (!inList) { html.push('<ul>'); inList = true; } html.push(`<li>${inlineMd(li[1])}</li>`); continue; }
    if (!line.trim()) { closeList(); continue; }
    closeList();
    html.push(`<p>${inlineMd(line)}</p>`);
  }
  closeList();
  return html.join('\n');
}
function inlineMd(s) {
  return s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
}

async function changelogOpen(forceRefresh) {
  document.getElementById('changelog-overlay').style.display = 'flex';
  const el = document.getElementById('changelog-content');
  el.innerHTML = `<div style="color:var(--text3);font-size:12px;padding:12px 0">${svgEsc(t('common.loading'))}</div>`;
  const d = await api('/changelog' + (forceRefresh ? '?refresh=1' : '')).catch(() => null);
  if (!d || !d.configured) {
    el.innerHTML = `<div style="color:var(--text3);font-family:monospace;font-size:12px">${svgEsc(t('sysinfo.changelogNotConfigured'))}</div>`;
    return;
  }
  if (d.error) {
    el.innerHTML = `<div style="color:var(--red);font-family:monospace;font-size:12px">${svgEsc(t('sysinfo.changelogError', { msg: d.error }))}</div>`;
    return;
  }
  el.innerHTML = renderSimpleMarkdown(d.content || '');
}
function changelogClose() {
  document.getElementById('changelog-overlay').style.display = 'none';
}
