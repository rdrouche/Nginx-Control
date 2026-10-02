'use strict';
/**
 * Remédiation « challenge » (v12.63.0) — génération des fichiers nginx.
 *
 * Données pures, sans E/S : features/blocklists.js appelle ces fonctions puis
 * écrit les fichiers (test + reload + retour arrière, comme pour la liste de
 * blocage). Deux fichiers sont produits :
 *
 *  - conf/blocklist-challenge.conf (contexte http, chargé une seule fois) :
 *      geo $blocklist_challenge  — les IP à soumettre au challenge
 *      map ... $nc_gate_skip     — 1 = laisser passer sans challenge (IP non
 *                                  listée, chemin ou user-agent exempté)
 *  - snippets/challenge-gate.conf (à inclure dans chaque server{} protégé) :
 *      auth_request /_nc_gate    — sous-requête interne ; elle répond 204
 *                                  immédiatement pour les IP non listées
 *      error_page 401 = @nc_challenge → redirection vers la page de vérification
 *
 * Deux moteurs, même squelette :
 *  - builtin : conteneur nginx-challenge (preuve de travail, cookie signé HMAC)
 *  - anubis  : conteneur Anubis (https://anubis.techaro.lol) en mode auth_request
 *
 * Aucune valeur issue d'une saisie n'est écrite dans nginx sans validation
 * stricte (liste blanche de caractères) : voir validateRegex / validateUpstream.
 */

const ENGINES = Object.freeze({
  builtin: { upstream: 'nginx-challenge:8080', prefix: '/.nc-challenge/', checkPath: '/check' },
  anubis: { upstream: 'anubis:8923', prefix: '/.within.website/', checkPath: '/.within.website/x/cmd/anubis/api/check' },
});

// Trois snippets, a inclure UN SEUL par server{} :
//  listed   : seules les IP de $blocklist_challenge (remediation des regles d Analyse)
//  all      : TOUT LE MONDE (hors chemins/user-agents exemptes) — vhost entierement protege
//  allbots  : tout le monde SAUF les robots d indexation verifies par DNS inverse
const GATE_VARIANTS = Object.freeze({
  listed: { file: 'challenge-gate.conf', skip: '$nc_gate_skip', bots: false,
    desc: 'Challenge navigateur pour les IP de $blocklist_challenge (remediation "challenge" des regles d analyse). A inclure dans chaque server{} a proteger, APRES blocklist-enforce.conf.' },
  all: { file: 'challenge-all.conf', skip: '$nc_gate_skip_all', bots: false,
    desc: 'Challenge navigateur pour TOUS les visiteurs de ce server{} (hors chemins et user-agents exemptes). A inclure a la place de challenge-gate.conf, jamais les deux.' },
  allbots: { file: 'challenge-all-allowbots.conf', skip: '$nc_gate_skip_all', bots: true,
    desc: 'Challenge navigateur pour tous les visiteurs SAUF les robots d indexation verifies par DNS inverse (Googlebot, Bingbot...). A inclure a la place de challenge-gate.conf, jamais les deux.' },
  // v12.67.1 — challenge limite a une ou plusieurs location{} (ex. /wp-login.php) :
  // 2 snippets "support" (server{}, memes sous-requetes sans auth_request global)
  // + 1 snippet a inclure DANS chaque location{} concernee.
  locsupport: { file: 'challenge-location-support.conf', skip: '$nc_gate_skip_all', bots: false, support: true,
    desc: 'Locations techniques du challenge SANS le declencher : a inclure dans le server{}, puis inclure challenge-location.conf dans chaque location{} a proteger. Tous les visiteurs de ces locations (hors exemptions).' },
  locsupportbots: { file: 'challenge-location-support-allowbots.conf', skip: '$nc_gate_skip_all', bots: true, support: true,
    desc: 'Comme challenge-location-support.conf, mais les robots d indexation verifies par DNS inverse passent. A inclure a la place de lui, jamais les deux.' },
  locinc: { file: 'challenge-location.conf', inline: true,
    desc: 'A inclure DANS une location{} (ex. location = /wp-login.php { include snippets/challenge-location.conf; ... }). Necessite challenge-location-support.conf (ou -allowbots) dans le server{}.' },
});

const DEFAULTS = Object.freeze({
  enable: false,
  engine: 'builtin',
  upstream: '',               // vide = défaut du moteur
  resolver: '127.0.0.11',     // DNS interne de Docker
  exemptPathRegex: '^/[.]well-known/',
  exemptUaRegex: '',
});

// Caractères admis dans une expression régulière injectée dans un `map` nginx :
// ni guillemet, ni antislash, ni `$`, `;`, `{`, `}`, espace ou retour ligne.
const REGEX_ALLOWED = /^[A-Za-z0-9_./\-|()^*+?[\]:@%=,~]+$/;
const MAX_REGEX_LEN = 200;
const UPSTREAM_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,120}[A-Za-z0-9])?(:\d{1,5})?$/;
const RESOLVER_RE = /^[A-Za-z0-9.:-]{1,80}$/;

/** @returns {string|null} message d'erreur, ou null si l'expression est acceptable. */
function validateRegex(label, v) {
  if (v === '') return null;
  if (typeof v !== 'string') return `${label} : texte attendu`;
  if (v.length > MAX_REGEX_LEN) return `${label} : ${MAX_REGEX_LEN} caractères maximum`;
  if (!REGEX_ALLOWED.test(v)) return `${label} : caractères non autorisés (espaces, guillemets, antislash, $ ; { } interdits — utilisez [.] pour un point littéral)`;
  try { new RegExp(v); } catch { return `${label} : expression régulière invalide`; }
  return null;
}

function validateUpstream(v) {
  if (!UPSTREAM_RE.test(v)) return 'challenge_upstream : attendu hote:port (ex. nginx-challenge:8080)';
  const m = v.match(/:(\d+)$/);
  if (m && (+m[1] < 1 || +m[1] > 65535)) return 'challenge_upstream : port hors bornes';
  return null;
}

/**
 * Lit les clés `challenge_*` de la configuration plate de blocklists.yml.
 * Toute valeur invalide est signalée (errors) et remplacée par son défaut :
 * une faute de frappe ne peut jamais produire de configuration nginx dangereuse.
 */
function normalizeChallengeSettings(config = {}) {
  const errors = [];
  const s = { ...DEFAULTS };
  s.enable = config.challenge_enable === true;
  if (config.challenge_enable != null && typeof config.challenge_enable !== 'boolean') {
    errors.push('challenge_enable : true ou false attendu');
  }
  if (config.challenge_engine != null) {
    if (Object.prototype.hasOwnProperty.call(ENGINES, config.challenge_engine)) s.engine = config.challenge_engine;
    else errors.push('challenge_engine : valeurs acceptées builtin ou anubis');
  }
  if (config.challenge_upstream != null && config.challenge_upstream !== '') {
    const e = validateUpstream(String(config.challenge_upstream));
    if (e) errors.push(e); else s.upstream = String(config.challenge_upstream);
  }
  if (config.challenge_resolver != null && config.challenge_resolver !== '') {
    if (RESOLVER_RE.test(String(config.challenge_resolver))) s.resolver = String(config.challenge_resolver);
    else errors.push('challenge_resolver : adresse invalide');
  }
  if (config.challenge_exempt_path_regex != null) {
    const e = validateRegex('challenge_exempt_path_regex', config.challenge_exempt_path_regex);
    if (e) errors.push(e); else s.exemptPathRegex = config.challenge_exempt_path_regex;
  }
  if (config.challenge_exempt_ua_regex != null) {
    const e = validateRegex('challenge_exempt_ua_regex', config.challenge_exempt_ua_regex);
    if (e) errors.push(e); else s.exemptUaRegex = config.challenge_exempt_ua_regex;
  }
  s.upstreamEffective = s.upstream || ENGINES[s.engine].upstream;
  s.profiles = [];
  if (config.challenge_profiles != null) {
    const r = normalizeProfiles(config.challenge_profiles, s);
    s.profiles = r.profiles;
    errors.push(...r.errors);
  }
  return { settings: s, errors };
}

// ── Profils par vhost (v12.65.1) ─────────────────────────────────────────────
// Un profil = un snippet dedie `challenge-<nom>.conf` avec son mode et ses
// exemptions propres (chemins / user-agents) ; une exemption absente herite du
// reglage global. Le nom sert aussi de suffixe aux variables nginx : liste blanche stricte.
const PROFILE_NAME_RE = /^[a-z0-9][a-z0-9_]{0,29}$/;
const PROFILE_RESERVED = new Set(['all', 'allbots', 'gate', 'location', 'location-support', 'location-support-allowbots']);
const PROFILE_MODES = ['listed', 'all', 'allbots'];
const MAX_PROFILES = 50;

function normalizeProfiles(raw, globalSettings) {
  const errors = [];
  const profiles = [];
  if (!Array.isArray(raw)) return { profiles, errors: ['profiles : liste attendue'] };
  const seen = new Set();
  for (const p of raw.slice(0, MAX_PROFILES)) {
    const name = p && typeof p.name === 'string' ? p.name : '';
    const label = name ? `profil "${name}"` : 'profil sans nom';
    if (!PROFILE_NAME_RE.test(name)) { errors.push(`${label} : "name" attendu (minuscules, chiffres, _ ; 30 caracteres max)`); continue; }
    if (PROFILE_RESERVED.has(name)) { errors.push(`${label} : nom reserve`); continue; }
    if (seen.has(name)) { errors.push(`${label} : nom deja utilise`); continue; }
    const mode = p.mode == null ? 'all' : p.mode;
    if (!PROFILE_MODES.includes(mode)) { errors.push(`${label} : "mode" attendu : ${PROFILE_MODES.join(', ')}`); continue; }
    let exemptPathRegex = globalSettings.exemptPathRegex;
    let exemptUaRegex = globalSettings.exemptUaRegex;
    let bad = false;
    for (const [key, field] of [['exempt_path_regex', 'path'], ['exempt_ua_regex', 'ua']]) {
      if (p[key] == null) continue;
      const v = typeof p[key] === 'string' ? p[key] : String(p[key]);
      const e = validateRegex(`${label} : ${key}`, v);
      if (e) { errors.push(e); bad = true; break; }
      if (field === 'path') exemptPathRegex = v; else exemptUaRegex = v;
    }
    if (bad) continue;
    seen.add(name);
    profiles.push({ name, mode, exemptPathRegex, exemptUaRegex, file: `challenge-${name}.conf`, suffix: name });
  }
  if (raw.length > MAX_PROFILES) errors.push(`profiles : ${MAX_PROFILES} profils maximum`);
  return { profiles, errors };
}

const header = (name, desc, where) => [
  `# name: ${name}`,
  `# description: ${desc}`,
  `# emplacement: ${where}`,
  `# genere le: ${new Date().toISOString()}`,
  '#',
];

/** Fichier http : table geo des IP à challenger + variables de décision. */
function buildChallengeHttp(settings, ips, summary = '') {
  const lines = [
    ...header('blocklist-challenge', 'IP soumises au challenge navigateur (remediation "challenge" des regles d analyse). Ne pas editer a la main : ecrasee a chaque rafraichissement.', 'http'),
    summary ? `# ${summary}` : `# total: ${ips.length} IP`,
    '',
    'geo $blocklist_challenge {',
    '    default 0;',
  ];
  for (const ip of ips) lines.push(`    ${ip} 1;`);
  lines.push('}', '');
  lines.push('map $request_uri $nc_exempt_path {', '    default 0;');
  if (settings.exemptPathRegex) lines.push(`    "~*${settings.exemptPathRegex}" 1;`);
  lines.push('}', '');
  lines.push('map $http_user_agent $nc_exempt_ua {', '    default 0;');
  if (settings.exemptUaRegex) lines.push(`    "~*${settings.exemptUaRegex}" 1;`);
  lines.push('}', '');
  lines.push(
    '# Snippets challenge-all*.conf : 0 = soumettre (ni chemin ni user-agent exemptes) ; 1 = laisser passer.',
    'map "$nc_exempt_path$nc_exempt_ua" $nc_gate_skip_all {',
    '    default 1;',
    '    "00" 0;',
    '}',
    '',
    '# Snippet challenge-gate.conf : 0 = soumettre au challenge (IP listee, ni chemin ni user-agent exemptes) ; 1 = laisser passer.',
    'map "$blocklist_challenge$nc_exempt_path$nc_exempt_ua" $nc_gate_skip {',
    '    default 1;',
    '    "100" 0;',
    '}',
    '');
  for (const pr of settings.profiles || []) {
    const sx = pr.suffix;
    lines.push(`# Profil "${pr.name}" (mode ${pr.mode}) : challenge-${pr.name}.conf`);
    lines.push(`map $request_uri $nc_exempt_path_${sx} {`, '    default 0;');
    if (pr.exemptPathRegex) lines.push(`    "~*${pr.exemptPathRegex}" 1;`);
    lines.push('}');
    lines.push(`map $http_user_agent $nc_exempt_ua_${sx} {`, '    default 0;');
    if (pr.exemptUaRegex) lines.push(`    "~*${pr.exemptUaRegex}" 1;`);
    lines.push('}');
    if (pr.mode === 'listed') {
      lines.push(`map "$blocklist_challenge$nc_exempt_path_${sx}$nc_exempt_ua_${sx}" $nc_gate_skip_${sx} {`, '    default 1;', '    "100" 0;', '}', '');
    } else {
      lines.push(`map "$nc_exempt_path_${sx}$nc_exempt_ua_${sx}" $nc_gate_skip_${sx} {`, '    default 1;', '    "00" 0;', '}', '');
    }
  }
  return lines.join('\n');
}

/** Valeur neutre, toujours valide : une liste vide ne challenge personne. */
function emptyChallengeHttp(settings = DEFAULTS) {
  return buildChallengeHttp({ ...DEFAULTS, ...settings }, [], 'aucune IP');
}

/**
 * Snippet à inclure dans chaque server{} protégé. Désactivé, il ne contient
 * que des commentaires : une inclusion existante ne peut donc jamais casser
 * `nginx -t`, que le challenge soit actif ou non.
 */
function buildGateSnippet(settings, variant = 'listed', profile = null) {
  let v = GATE_VARIANTS[variant] || GATE_VARIANTS.listed;
  if (profile) {
    v = { ...GATE_VARIANTS[profile.mode], file: profile.file, skip: `$nc_gate_skip_${profile.suffix}`,
      desc: `Profil "${profile.name}" (mode ${profile.mode}) : challenge dedie a ce vhost, avec ses propres exemptions. A inclure dans le server{} concerne, a la place de tout autre snippet challenge.` };
    variant = profile.mode;
  }
  const eng = ENGINES[settings.engine];
  const head = header(v.file.replace(/\.conf$/, ''), v.desc, v.inline ? 'location' : 'server');
  if (v.inline) {
    if (!settings.enable) return [...head, '# Challenge desactive (challenge_enable: false dans config/challenge.yml) : aucune directive.', ''].join('\n');
    return [...head, 'auth_request /_nc_gate;', 'error_page 401 = @nc_challenge;', ''].join('\n');
  }
  if (!settings.enable) {
    return [...head, '# Challenge desactive (challenge_enable: false dans config/challenge.yml) : aucune directive.', ''].join('\n');
  }
  const up = settings.upstreamEffective || settings.upstream || eng.upstream;
  const res = [
    `    resolver ${settings.resolver} valid=10s ipv6=off;`,
    `    set $nc_up "${up}";`,
  ];
  const hdrs = [
    '    proxy_http_version 1.1;',
    '    proxy_set_header Connection "";',
    '    proxy_set_header Host $host;',
    '    proxy_set_header X-Real-IP $remote_addr;',
    '    proxy_set_header X-Forwarded-For $remote_addr;',
    '    proxy_set_header X-Forwarded-Proto $scheme;',
  ];
  const redirect = settings.engine === 'anubis'
    ? 'return 307 /.within.website/?redir=$request_uri;'
    : 'return 302 /.nc-challenge/go$request_uri;';
  const notes = [];
  if (variant === 'allbots' && settings.engine === 'anubis') {
    notes.push('# Moteur Anubis : les robots d indexation sont autorises par la politique d Anubis (botPolicy.yaml), pas par ce snippet.');
  }
  return [
    ...head,
    ...notes,
    '# Resolution DNS a la requete (resolver) : si le conteneur du challenge est absent,',
    '# nginx demarre quand meme ; seuls les visiteurs concernes recoivent alors une erreur 502.',
    '',
    ...(v.support ? ['# Aucun auth_request ici : il est pose dans chaque location{} par challenge-location.conf.'] : ['auth_request /_nc_gate;', 'error_page 401 = @nc_challenge;']),
    '',
    '# Sous-requete interne : repond 204 tout de suite quand aucun challenge n est du.',
    'location = /_nc_gate {',
    '    internal;',
    `    if (${v.skip}) { return 204; }`,
    ...res,
    `    rewrite ^ ${eng.checkPath} break;`,
    '    proxy_pass http://$nc_up;',
    '    proxy_pass_request_body off;',
    '    proxy_set_header Content-Length "";',
    '    proxy_connect_timeout 3s;',
    '    proxy_read_timeout 5s;',
    ...hdrs,
    '    # Toujours ecrase : un client ne doit jamais pouvoir se declarer "bon robot".',
    `    proxy_set_header X-NC-Allow-Bots "${v.bots ? '1' : ''}";`,
    '}',
    '',
    '# Page de verification et ses ressources (jamais soumises au challenge).',
    `location ^~ ${eng.prefix} {`,
    '    auth_request off;',
    ...res,
    '    proxy_pass http://$nc_up;',
    '    proxy_connect_timeout 3s;',
    '    proxy_read_timeout 15s;',
    ...hdrs,
    '}',
    '',
    'location @nc_challenge {',
    '    auth_request off;',
    `    ${redirect}`,
    '}',
    '',
  ].join('\n');
}

/** Les snippets a ecrire (3 globaux + 1 par profil) : [{ variant, name (fichier), content, profile? }]. */
function buildAllGateSnippets(settings) {
  return Object.keys(GATE_VARIANTS).map(variant => ({
    variant, name: GATE_VARIANTS[variant].file, content: buildGateSnippet(settings, variant),
  })).concat((settings.profiles || []).map(pr => ({
    variant: `profile:${pr.name}`, name: pr.file, profile: pr.name, content: buildGateSnippet(settings, pr.mode, pr),
  })));
}

/** Vérifie qu'un fichier généré n'a pas changé sur le fond (hors en-tête de commentaires). */
function stripComments(s) {
  return String(s || '').split('\n').filter(l => !l.startsWith('#')).join('\n').trim();
}

module.exports = {
  ENGINES, DEFAULTS, GATE_VARIANTS, buildAllGateSnippets, validateRegex, validateUpstream, normalizeChallengeSettings,
  buildChallengeHttp, emptyChallengeHttp, buildGateSnippet, stripComments, normalizeProfiles, PROFILE_NAME_RE,
};
