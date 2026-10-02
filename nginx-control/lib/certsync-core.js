'use strict';
/**
 * Synchronisation de certificats entre instances Nginx Control — cœur
 * (validation + fichiers), sans réseau (v12.59.0).
 *
 * Un nœud « émetteur » (celui qui a certbot) expose ses certificats ; un nœud
 * « consommateur » les installe dans `<DIR_CERTS>/synced/<nom>/` — jamais dans
 * `live/`, géré par certbot (liens symboliques vers `archive/`) : un
 * renouvellement local et une synchro ne se marchent jamais dessus. nginx voit
 * ce dossier au même endroit que `live/` (volume Let's Encrypt partagé) :
 *   ssl_certificate     /etc/letsencrypt/synced/<nom>/fullchain.pem;
 *   ssl_certificate_key /etc/letsencrypt/synced/<nom>/privkey.pem;
 *
 * Tout ce qui arrive du réseau (certificat reçu en push ou en pull) passe par
 * inspectBundle() avant d'être écrit : la clé doit correspondre au certificat,
 * le certificat ne doit pas être expiré, et il ne doit pas être plus ancien
 * que celui déjà en place (anti-retour en arrière).
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_PEM = 256 * 1024;
const FP_RE = /^[0-9a-f]{64}$/;

const validName = n => typeof n === 'string' && NAME_RE.test(n);

/** Empreinte SHA-256 normalisée (64 hex minuscules) depuis « AA:BB:… », « aabb… » ou un Buffer. */
function normFingerprint(v) {
  if (Buffer.isBuffer(v)) return crypto.createHash('sha256').update(v).digest('hex');
  const s = String(v ?? '').replace(/[:\s]/g, '').toLowerCase();
  return FP_RE.test(s) ? s : null;
}

function firstCertPem(pem) {
  const m = String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
  return m ? m[0] : null;
}

/**
 * Analyse un couple fullchain/clé.
 * @returns {{ok:true, info:object}|{ok:false, error:string}}
 */
function inspectBundle(fullchain, privkey, now = Date.now()) {
  if (typeof fullchain !== 'string' || typeof privkey !== 'string') return { ok: false, error: 'fullchain et privkey (PEM) requis' };
  if (fullchain.length > MAX_PEM || privkey.length > MAX_PEM) return { ok: false, error: 'PEM trop volumineux' };
  const leafPem = firstCertPem(fullchain);
  if (!leafPem) return { ok: false, error: 'fullchain.pem ne contient aucun certificat PEM' };
  if (!/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/.test(privkey)) return { ok: false, error: 'privkey.pem ne contient aucune clé privée PEM' };
  let cert, key;
  try { cert = new crypto.X509Certificate(leafPem); } catch (e) { return { ok: false, error: `certificat illisible : ${e.message}` }; }
  try { key = crypto.createPrivateKey(privkey); } catch (e) { return { ok: false, error: 'clé privée illisible (chiffrée par mot de passe ?)' }; }
  if (!cert.checkPrivateKey(key)) return { ok: false, error: 'la clé privée ne correspond pas au certificat' };
  const notAfter = new Date(cert.validTo).getTime();
  const notBefore = new Date(cert.validFrom).getTime();
  if (!Number.isFinite(notAfter) || notAfter <= now) return { ok: false, error: 'certificat expiré' };
  let domains = [];
  try { domains = (cert.subjectAltName || '').split(',').map(s => s.trim()).filter(s => /^DNS:/i.test(s)).map(s => s.replace(/^DNS:/i, '')); } catch { /* sans SAN */ }
  return { ok: true, info: {
    fingerprint256: normFingerprint(cert.fingerprint256), serial: cert.serialNumber, subject: cert.subject, issuer: cert.issuer,
    notBefore, notAfter, domains, daysLeft: Math.floor((notAfter - now) / 86400000), chainLength: (fullchain.match(/-----BEGIN CERTIFICATE-----/g) || []).length,
  } };
}

const syncedDir = (certsDir, name) => path.join(certsDir, 'synced', name);

/** Certificat local à exposer/pousser : `live/<nom>` (certbot) puis `synced/<nom>`. */
function readLocalBundle(certsDir, name) {
  if (!validName(name)) return null;
  for (const [source, dir] of [['live', path.join(certsDir, 'live', name)], ['synced', syncedDir(certsDir, name)]]) {
    try {
      const fullchain = fs.readFileSync(path.join(dir, 'fullchain.pem'), 'utf8');
      const privkey = fs.readFileSync(path.join(dir, 'privkey.pem'), 'utf8');
      const r = inspectBundle(fullchain, privkey);
      return { name, source, fullchain, privkey, ok: r.ok, error: r.ok ? null : r.error, info: r.ok ? r.info : null };
    } catch { /* absent : source suivante */ }
  }
  return null;
}

/** Métadonnées du certificat actuellement installé en `synced/` (sans la clé), ou null. */
function readSyncedMeta(certsDir, name) {
  if (!validName(name)) return null;
  try {
    const dir = syncedDir(certsDir, name);
    const meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));
    const fullchain = fs.readFileSync(path.join(dir, 'fullchain.pem'), 'utf8');
    const leaf = firstCertPem(fullchain);
    const cert = new crypto.X509Certificate(leaf);
    const notAfter = new Date(cert.validTo).getTime();
    return { ...meta, name, fingerprint256: normFingerprint(cert.fingerprint256), notAfter, daysLeft: Math.floor((notAfter - Date.now()) / 86400000) };
  } catch { return null; }
}

function listSynced(certsDir) {
  let names = [];
  try { names = fs.readdirSync(path.join(certsDir, 'synced')); } catch { return []; }
  return names.filter(validName).map(n => readSyncedMeta(certsDir, n)).filter(Boolean);
}

function writeAtomic(file, data, mode) {
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, data, { mode });
  fs.renameSync(tmp, file);
}

/**
 * Installe un certificat reçu dans `synced/<nom>/`.
 * @param {string} certsDir  racine (DIR_CERTS)
 * @param {{fullchain:string, privkey:string, source?:string}} bundle
 * @param {{force?:boolean}} opts  force : autorise un certificat plus ancien que celui en place
 * @returns {{ok:true, changed:boolean, info:object, previous:object|null}|{ok:false, error:string}}
 */
function installSynced(certsDir, name, bundle, { force = false } = {}) {
  if (!validName(name)) return { ok: false, error: 'nom de certificat invalide' };
  const r = inspectBundle(bundle && bundle.fullchain, bundle && bundle.privkey);
  if (!r.ok) return r;
  const current = readSyncedMeta(certsDir, name);
  if (current && current.fingerprint256 === r.info.fingerprint256) {
    return { ok: true, changed: false, info: r.info, previous: current };
  }
  if (current && current.notAfter > r.info.notAfter && !force) {
    return { ok: false, error: 'le certificat reçu expire avant celui déjà installé (refus du retour en arrière)' };
  }
  const dir = syncedDir(certsDir, name);
  try { fs.mkdirSync(dir, { recursive: true, mode: 0o750 }); } catch (e) {
    return { ok: false, error: `dossier ${path.dirname(dir)} non inscriptible (${e.code || e.message}) : montez-le en lecture-écriture dans le conteneur du dashboard (voir README « Synchronisation de certificats »)` };
  }
  // Sauvegarde de la version précédente (retour arrière si nginx -t échoue).
  const prevDir = path.join(dir, '.previous');
  if (current) {
    fs.mkdirSync(prevDir, { recursive: true, mode: 0o700 });
    for (const f of ['fullchain.pem', 'privkey.pem', 'meta.json']) {
      try { writeAtomic(path.join(prevDir, f), fs.readFileSync(path.join(dir, f)), f === 'privkey.pem' ? 0o600 : 0o644); } catch { /* absent */ }
    }
  }
  writeAtomic(path.join(dir, 'privkey.pem'), bundle.privkey, 0o600);
  writeAtomic(path.join(dir, 'fullchain.pem'), bundle.fullchain, 0o644);
  writeAtomic(path.join(dir, 'meta.json'), JSON.stringify({
    source: String(bundle.source || '').slice(0, 200), receivedAt: Date.now(), domains: r.info.domains,
    issuer: r.info.issuer, serial: r.info.serial,
  }, null, 2) + '\n', 0o644);
  return { ok: true, changed: true, info: r.info, previous: current };
}

/** Restaure la version sauvegardée par installSynced() (ou supprime l'installation si c'était la première). */
function rollbackSynced(certsDir, name, hadPrevious) {
  if (!validName(name)) return false;
  const dir = syncedDir(certsDir, name);
  try {
    if (!hadPrevious) { fs.rmSync(dir, { recursive: true, force: true }); return true; }
    const prevDir = path.join(dir, '.previous');
    for (const f of ['privkey.pem', 'fullchain.pem', 'meta.json']) {
      writeAtomic(path.join(dir, f), fs.readFileSync(path.join(prevDir, f)), f === 'privkey.pem' ? 0o600 : 0o644);
    }
    return true;
  } catch { return false; }
}

/** Supprime un certificat synchronisé (le lien de l'interface « retirer »). */
function removeSynced(certsDir, name) {
  if (!validName(name)) return false;
  try { fs.rmSync(syncedDir(certsDir, name), { recursive: true, force: true }); return true; } catch { return false; }
}

// ─── Validation des entrées de configuration ─────────────────────────────────

const CTRL_RE = /[\u0000-\u001f\u007f]/;
const TLS_MODES = ['verify', 'ca', 'pin', 'insecure'];

function cleanName(v, max, label) {
  const s = String(v ?? '').trim();
  if (!s) return { error: `${label} obligatoire` };
  if (s.length > max || CTRL_RE.test(s)) return { error: `${label} invalide (${max} caractères maximum, pas de caractère de contrôle)` };
  return { value: s };
}

/** URL d'un autre Nginx Control : HTTPS uniquement, sans identifiants ni paramètres. */
function validateRemoteUrl(input) {
  let u;
  try { u = new URL(String(input ?? '').trim()); } catch { return { ok: false, error: 'URL invalide' }; }
  if (u.protocol !== 'https:') return { ok: false, error: 'HTTPS obligatoire (https://hôte[:port]) — le certificat peut être auto-signé, voir le mode TLS' };
  if (u.username || u.password || u.search || u.hash) return { ok: false, error: 'URL sans identifiants ni paramètres' };
  if (!u.hostname) return { ok: false, error: 'URL sans hôte' };
  return { ok: true, value: u.origin + (u.pathname !== '/' ? u.pathname.replace(/\/+$/, '') : '') };
}

const MAX_MAPPINGS = 100;

/**
 * Valide une source distante saisie dans le formulaire.
 * `prev` : enregistrement actuel (le jeton et le CA laissés vides sont conservés).
 */
function validateRemote(input, prev) {
  const i = input && typeof input === 'object' ? input : {};
  const name = cleanName(i.name, 80, 'Nom');
  if (name.error) return { ok: false, error: name.error };
  const url = validateRemoteUrl(i.url);
  if (!url.ok) return url;
  const direction = i.direction === 'push' ? 'push' : i.direction === 'pull' ? 'pull' : null;
  if (!direction) return { ok: false, error: 'Sens : pull (récupérer) ou push (envoyer)' };

  let token = typeof i.token === 'string' && i.token.trim() ? i.token.trim() : (prev && prev.token) || '';
  if (!token) return { ok: false, error: 'Jeton obligatoire (créé sur l\'autre Nginx Control)' };
  if (token.length > 200 || !/^[A-Za-z0-9_-]+$/.test(token)) return { ok: false, error: 'Jeton invalide' };

  const mode = String(i.tlsMode ?? 'verify');
  if (!TLS_MODES.includes(mode)) return { ok: false, error: `Mode TLS : ${TLS_MODES.join(', ')}` };
  let ca = '', pin = '';
  if (mode === 'ca') {
    ca = typeof i.ca === 'string' && i.ca.trim() ? i.ca.trim() : (prev && prev.tls && prev.tls.ca) || '';
    if (!ca || ca.length > 64 * 1024 || !/-----BEGIN CERTIFICATE-----/.test(ca)) return { ok: false, error: 'Mode CA : collez le(s) certificat(s) PEM de votre autorité' };
    const blocks = ca.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
    for (const b of blocks) { try { new crypto.X509Certificate(b); } catch { return { ok: false, error: 'CA : certificat PEM illisible' }; } }
    if (!blocks.length) return { ok: false, error: 'CA : aucun certificat PEM' };
  }
  if (mode === 'pin') {
    pin = normFingerprint(i.pin) || (!i.pin && prev && prev.tls && prev.tls.pin) || '';
    if (!pin) return { ok: false, error: 'Empreinte SHA-256 du certificat du serveur obligatoire (utilisez « Récupérer l\'empreinte »)' };
  }

  const certsIn = Array.isArray(i.certs) ? i.certs : [];
  if (!certsIn.length) return { ok: false, error: 'Ajoutez au moins un certificat' };
  if (certsIn.length > MAX_MAPPINGS) return { ok: false, error: `${MAX_MAPPINGS} certificats maximum` };
  const certs = [], seen = new Set();
  for (const c of certsIn) {
    const remote = String(c && c.remote ? c.remote : '').trim();
    const local = String(c && c.local ? c.local : remote).trim();
    if (!validName(remote) || !validName(local)) return { ok: false, error: `Nom de certificat invalide : « ${String(remote || local).slice(0, 60)} »` };
    // Côté qui reçoit, le nom local est un dossier `synced/<local>` : unique.
    const key = direction === 'pull' ? local : remote;
    if (seen.has(key)) return { ok: false, error: `Certificat en double : ${key}` };
    seen.add(key);
    certs.push({ remote, local });
  }

  return { ok: true, value: {
    name: name.value, url: url.value, direction, token, enabled: i.enabled !== false,
    tls: { mode, ca, pin }, certs,
  } };
}

/**
 * Valide la création d'un jeton d'accès (côté qui expose/reçoit).
 *  scope 'pull' : l'autre nœud peut LIRE ces certificats (clé privée comprise).
 *  scope 'push' : l'autre nœud peut ÉCRIRE ces certificats ici (dans synced/).
 */
function validateTokenInput(input) {
  const i = input && typeof input === 'object' ? input : {};
  const name = cleanName(i.name, 80, 'Nom');
  if (name.error) return { ok: false, error: name.error };
  if (i.scope !== 'pull' && i.scope !== 'push') return { ok: false, error: 'Type : pull (l\'autre nœud lit) ou push (l\'autre nœud envoie)' };
  const certs = [...new Set((Array.isArray(i.certs) ? i.certs : []).map(c => String(c).trim()).filter(Boolean))];
  if (!certs.length) return { ok: false, error: 'Choisissez au moins un certificat' };
  if (certs.length > MAX_MAPPINGS) return { ok: false, error: `${MAX_MAPPINGS} certificats maximum` };
  const bad = certs.find(c => !validName(c));
  if (bad !== undefined) return { ok: false, error: `Nom de certificat invalide : « ${bad.slice(0, 60)} »` };
  return { ok: true, value: { name: name.value, scope: i.scope, certs } };
}

module.exports = {
  NAME_RE, TLS_MODES, MAX_MAPPINGS, validName, normFingerprint, firstCertPem, inspectBundle,
  syncedDir, readLocalBundle, readSyncedMeta, listSynced, installSynced, rollbackSynced, removeSynced,
  validateRemoteUrl, validateRemote, validateTokenInput,
};
