'use strict';
/**
 * Authentication and authorisation.
 *
 * Covers roles, the users.yml store, password hashing, sessions and
 * brute-force protection — everything needed to answer "who is this request,
 * and may it do that".
 *
 * Deliberately has no HTTP knowledge: it takes a request only to read cookies
 * and the Authorization header, and returns a session object or null. Routes
 * live in features/auth-routes.js.
 */

const fs     = require('fs');
const crypto = require('crypto');
const cfg    = require('./config');

// ─── Roles & permissions ─────────────────────────────────────────────────────
const PERMS = {
  VIEW_METRICS:    'view_metrics',
  VIEW_CONFIGS:    'view_configs',
  VIEW_LOGS:       'view_logs',
  VIEW_SSL:        'view_ssl',
  NGINX_CONTROL:   'nginx_control',
  MANAGE_WEBHOOKS: 'manage_webhooks',
  VIEW_API_DOC:    'view_api_doc',
  MANAGE_USERS:    'manage_users',
  DEPLOY:          'deploy',
  VIEW_CROWDSEC:   'view_crowdsec',
  VIEW_GOACCESS:   'view_goaccess',
  // Alias for admin-only operations. Kept because `PERMS.ADMIN` returning
  // undefined once made hasPerm() reject everyone, admins included.
  ADMIN:           'manage_users',
};

const ROLE_PERMS = {
  admin: Object.values(PERMS),
  operator: [
    PERMS.VIEW_METRICS, PERMS.VIEW_CONFIGS, PERMS.VIEW_LOGS,
    PERMS.VIEW_SSL, PERMS.NGINX_CONTROL, PERMS.DEPLOY,
    PERMS.VIEW_CROWDSEC, PERMS.VIEW_GOACCESS,
  ],
  viewer: [
    PERMS.VIEW_METRICS, PERMS.VIEW_CONFIGS, PERMS.VIEW_LOGS, PERMS.VIEW_SSL,
    PERMS.VIEW_CROWDSEC, PERMS.VIEW_GOACCESS,
  ],
  // A CI/CD deploy token (see lib/deploy-tokens.js) authenticates as this
  // role — PERMS.DEPLOY and nothing else. The real containment is one layer
  // up though: server.js's dispatch only ever calls
  // authenticateDeployToken() for a fixed, small allowlist of git/backup
  // routes, so a session with this role can never even be constructed for
  // any other path, regardless of what PERMS.DEPLOY happens to gate
  // elsewhere today or in the future.
  deploy_ci: [PERMS.DEPLOY],
  // A remote agent's own bearer token (lib/agents-store.js, Partie 2 —
  // hôtes Docker distants) authenticates as this role — deliberately zero
  // permissions. The real containment is the same one layer up as
  // deploy_ci: server.js's dispatch only ever calls
  // authenticateAgentToken() for the one fixed route an agent needs
  // (POST /api/agent/manifest, see AGENT_TOKEN_ROUTES), and that route
  // checks session.agentScope/session.agentId directly rather than any
  // PERMS bit — this empty list is belt-and-suspenders, not the mechanism.
  agent: [],
};

function roleHasPerm(role, perm) {
  return (ROLE_PERMS[role] || []).includes(perm);
}

function hasPerm(session, perm) {
  return !!session && roleHasPerm(session.role, perm);
}

// ─── Password hashing ────────────────────────────────────────────────────────
// scrypt is memory-hard: someone who steals users.yml cannot brute-force it at
// GPU speed the way the previous single-round HMAC allowed.
const SCRYPT_KEYLEN = 32;
const SCRYPT_OPTS   = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function hashPassword(password, salt) {
  if (!salt) salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEYLEN, SCRYPT_OPTS).toString('hex');
  return { hash, salt, digest: `scrypt:${salt}:${hash}` };
}

/** Legacy single-round HMAC — read-only, so existing users.yml keeps working. */
function hashPasswordLegacy(password, salt) {
  return crypto.createHmac('sha256', salt).update(password).digest('hex');
}

function verifyPassword(password, digest) {
  try {
    const [algo, salt, storedHash] = String(digest).split(':');
    let computed;
    if (algo === 'scrypt')      computed = crypto.scryptSync(password, salt, SCRYPT_KEYLEN, SCRYPT_OPTS).toString('hex');
    else if (algo === 'sha256') computed = hashPasswordLegacy(password, salt);
    else return false;
    const a = Buffer.from(computed), b = Buffer.from(storedHash);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

/** True when a stored digest uses the old algorithm and should be upgraded. */
function needsRehash(digest) {
  return String(digest).startsWith('sha256:');
}

// Fixed dummy digest for verifyCredentials() below — never a real account's
// password, just something scrypt-shaped to spend the same CPU time on.
// Computed once at module load (a fixed salt is fine here: this digest is
// never checked against anything meaningful, only used to burn time).
const DUMMY_DIGEST = hashPassword('this-is-not-a-real-password', 'dummy-salt-for-timing-parity').digest;

/**
 * Fix (audit finding, Basse/"Sécurité et durcissement"): user enumeration by
 * response time. The login route used to call `findUser()` then, ONLY when
 * a user was found, `verifyPassword()` — which runs a real scrypt hash
 * (deliberately slow, tens of milliseconds). A request for a username that
 * doesn't exist returned almost instantly; one for a real username with the
 * wrong password took measurably longer. Timed side-by-side (or even just a
 * handful of samples), that difference tells an attacker which usernames
 * are real without ever seeing a login succeed. This always runs a scrypt
 * computation — against the real stored digest when the user exists,
 * against a fixed dummy one when it doesn't — so both paths cost the same
 * CPU time regardless of which branch is actually taken.
 */
function verifyCredentials(username, password) {
  const user = findUser(username);
  const ok = verifyPassword(password, user ? user.password : DUMMY_DIGEST);
  return ok && user ? user : null;
}

/** Constant-time comparison; false on any length or format mismatch. */
function safeCompare(a, b) {
  try {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

// ─── Users store ─────────────────────────────────────────────────────────────
// users.yml format:
//   users:
//     - username: admin
//       password: scrypt:<salt>:<hash>
//       role: admin
//       name: Administrateur
//       enabled: true
//
// A plaintext password is hashed on first load and the file rewritten, which
// keeps first-run setup simple.

let usersCache = [];
let usersFileMtime = 0;

/** Minimal YAML parser for the users.yml shape (no dependency). */
function parseYmlUsers(yaml) {
  const users = [];
  let current = null;
  for (const rawLine of yaml.split('\n')) {
    const line = rawLine.replace(/\r/g, '').trimEnd();
    if (/^\s*-\s+username:/.test(line)) {
      if (current) users.push(current);
      current = {
        username: line.split(':').slice(1).join(':').trim(),
        role: 'viewer', enabled: true, name: '',
      };
    } else if (current && /^\s+(password|role|name|enabled):/.test(line)) {
      const [k, ...rest] = line.trim().split(':');
      const val = rest.join(':').trim();
      if (k === 'enabled') current.enabled = val !== 'false';
      else current[k] = val;
    }
  }
  if (current) users.push(current);
  return users;
}

function rewriteUsersFile(users) {
  try {
    const lines = ['users:'];
    for (const u of users) {
      lines.push(`  - username: ${u.username}`);
      lines.push(`    password: ${u.password}`);
      lines.push(`    role: ${u.role || 'viewer'}`);
      lines.push(`    name: ${u.name || u.username}`);
      lines.push(`    enabled: ${u.enabled !== false}`);
    }
    fs.writeFileSync(cfg.USERS_FILE, lines.join('\n') + '\n', 'utf8');
    usersFileMtime = fs.statSync(cfg.USERS_FILE).mtimeMs;
  } catch (e) {
    console.warn('[auth] Cannot rewrite users file:', e.message);
  }
}

// SECURITY (fix v12.21.1, audit finding SEC-08): shipped credentials that
// stay easy to guess forever. Two distinct issues, two distinct fixes below:
//
//  1. `config/users.yml` ships with three well-known plaintext passwords
//     (admin/admin, operator/operator123, viewer/viewer123), documented as
//     "change immediately" but with nothing that enforces or even reminds an
//     operator who never does. Blocking startup on this would break the
//     documented first-boot flow (the README walks a new install through
//     logging in as admin/admin), so instead loadUsers() now checks, on
//     every successful parse, whether any account's password still matches
//     one of these three known defaults and — if so — logs a loud, repeated
//     warning AND raises a persistent dashboard notification, so the risk
//     survives past the first boot log a busy operator might not read.
//  2. The `usersCache.length === 0` fallback below used to synthesize a
//     FIXED admin:admin account when USERS_FILE could not be read at all
//     (e.g. the volume isn't mounted yet). That combination — a guessable
//     password AND full admin — needed no `users.yml` to exist at all. It
//     now generates a random 24-character password instead, logs it once,
//     and persists it to USERS_FILE so the very next restart reads that
//     same (now real) account rather than regenerating — an operator who
//     misses the one-time log line is not locked out, they just re-run
//     `docker logs` for that first boot, or reset the file to trigger a
//     fresh one.
//  3. (v12.32.0) The far more common case: `users.yml` DOES exist, exactly as
//     shipped, with `admin`/`admin` still in it. loadUsers() now detects that
//     one exact combination on first read and replaces it with the same kind
//     of generated-and-logged-once random password as case 2, instead of
//     silently hashing "admin" and leaving it valid indefinitely. Any other
//     account, or any password the operator actually changed (even to
//     something weak), is left alone — only the untouched shipped default is
//     ever auto-replaced.
const KNOWN_DEFAULT_CREDS = [
  { username: 'admin',    password: 'admin' },
  { username: 'operator', password: 'operator123' },
  { username: 'viewer',   password: 'viewer123' },
];

function warnIfDefaultCredsInUse(users) {
  const stillDefault = KNOWN_DEFAULT_CREDS.filter(d => {
    const u = users.find(x => x.username === d.username && x.enabled !== false);
    return u && verifyPassword(d.password, u.password);
  });
  if (!stillDefault.length) return;
  const names = stillDefault.map(d => d.username).join(', ');
  console.warn(`[auth] SECURITE: le(s) compte(s) suivant(s) utilisent encore leur mot de passe d'exemple livre avec le projet : ${names}. Changez-le(s) immediatement (page Utilisateurs) — ce sont des identifiants publics, documentes dans le depot.`);
  // onEvent is the same boot-injected logger used by createSession()/
  // destroySession() below (see setEventLogger()) — keeps this module
  // independent of lib/events.js rather than require()-ing it directly.
  onEvent('auth.default_credentials', { accounts: stillDefault.map(d => d.username) }, 'auth');
}

function loadUsers() {
  try {
    const stat = fs.statSync(cfg.USERS_FILE);
    if (stat.mtimeMs === usersFileMtime) return usersCache;   // unchanged
    usersFileMtime = stat.mtimeMs;
    const parsed = parseYmlUsers(fs.readFileSync(cfg.USERS_FILE, 'utf8'));
    let dirty = false;
    for (const u of parsed) {
      // v12.32.0: the admin account still using the literal shipped default
      // password ("admin") is replaced with a freshly generated random one on
      // the very first read, instead of being hashed and left usable as-is —
      // closes the same "admin/admin reachable forever" gap already fixed for
      // the "no users.yml at all" case below, for the far more common case of
      // a users.yml that exists but was never edited. Self-limiting: once
      // rewritten, the stored value is a scrypt digest, never the literal
      // "admin" again, so this branch cannot fire twice for the same install.
      // Any OTHER password (including a weak one the operator chose on
      // purpose) is left untouched — this only ever overrides the exact
      // shipped placeholder, never a manual choice.
      if (u.username === 'admin' && u.password === 'admin') {
        const generated = crypto.randomBytes(18).toString('base64').replace(/[+/=]/g, '');
        console.warn('[auth] SECURITE: le compte admin utilise encore le mot de passe d\'exemple "admin" livre avec le projet.');
        console.warn(`[auth] Generation automatique d'un mot de passe aleatoire (affiche UNE SEULE FOIS ci-dessous) :`);
        console.warn(`[auth]   username: admin   password: ${generated}`);
        u.password = hashPassword(generated).digest;
        dirty = true;
        continue;
      }
      if (u.password && !u.password.startsWith('sha256:') && !u.password.startsWith('scrypt:')) {
        u.password = hashPassword(u.password).digest;
        dirty = true;
      }
    }
    if (dirty) rewriteUsersFile(parsed);
    usersCache = parsed;
    console.log(`[auth] Loaded ${usersCache.length} user(s) from ${cfg.USERS_FILE}`);
    warnIfDefaultCredsInUse(usersCache);
  } catch (e) {
    if (usersCache.length === 0) {
      console.warn(`[auth] Cannot read ${cfg.USERS_FILE}: ${e.message}`);
      const generated = crypto.randomBytes(18).toString('base64').replace(/[+/=]/g, '');
      console.warn(`[auth] Aucun users.yml lisible : creation d'un compte admin avec un mot de passe genere aleatoirement (affiche UNE SEULE FOIS ci-dessous) plutot qu'un admin:admin par defaut :`);
      console.warn(`[auth]   username: admin   password: ${generated}`);
      usersCache = [{
        username: 'admin', password: hashPassword(generated).digest,
        role: 'admin', name: 'Admin', enabled: true,
      }];
      try { rewriteUsersFile(usersCache); usersFileMtime = fs.statSync(cfg.USERS_FILE).mtimeMs; } catch {}
    }
  }
  return usersCache;
}

function findUser(username) {
  loadUsers();
  return usersCache.find(u => u.username === username && u.enabled !== false);
}

function getUsers() { loadUsers(); return usersCache; }
function saveUsers() { rewriteUsersFile(usersCache); }

/** Re-hash a legacy digest after a successful login. */
function upgradePasswordHash(user, plaintext) {
  try {
    user.password = hashPassword(plaintext).digest;
    saveUsers();
    console.log(`[auth] Upgraded password hash to scrypt for "${user.username}"`);
  } catch (e) {
    console.warn('[auth] Hash upgrade failed:', e.message);
  }
}

// ─── Login CSRF ──────────────────────────────────────────────────────────────
/**
 * Fix (audit finding, Basse/"Sécurité et durcissement"): "login CSRF" — an
 * attacker's page auto-submits a hidden cross-site form to POST /auth/login
 * with the ATTACKER's own credentials, so the victim's browser ends up
 * logged into the attacker's account without the victim doing anything. They
 * may then unknowingly save real data (a config change, an API token they
 * paste for "testing") into what they think is their own session but is
 * actually the attacker's, who reads it back later.
 *
 * Same Origin/Referer check as SEC-12's CSRF guard (server.js), applied here
 * to the one route that guard structurally cannot cover — it only runs for
 * already-authenticated requests, and there is no session yet at login time.
 * A same-site-but-cross-origin page (SEC-12's own threat model) or a
 * genuinely cross-site one both get a Host mismatch here the same way. A
 * request with neither header (a non-browser client, or a browser that
 * strips them) is allowed through unchanged — this narrows the attack to
 * "a browser, cross-origin, with Origin/Referer suppressed", not "any
 * request that isn't literally the dashboard's own login form", so it never
 * regresses a direct API/script login.
 */
function loginOriginAllowed(req) {
  const originHeader = req?.headers?.['origin'] || req?.headers?.['referer'];
  if (!originHeader) return true;
  let originHost = null;
  try { originHost = new URL(originHeader).host; } catch { return true; } // malformed -> treated as absent
  return originHost === req.headers.host;
}

// ─── Sessions ────────────────────────────────────────────────────────────────
// Fix (audit finding, Basse/"Sécurité et durcissement"): this Map — and
// therefore whatever setSessionStore() persists to disk (events.db, via
// persistSessions()/restoreSessions() below) — used to be keyed by the raw
// session token: the exact bearer credential the `ngx_session` cookie
// carries. Anyone who could read that table (a backup file, a misconfigured
// mount, a bug elsewhere that leaks the events DB) got back live, directly
// usable session tokens, no further work needed. It's now keyed by
// SHA-256(token) instead — a one-way digest, so a leaked table hands out
// nothing an attacker could present as a cookie. This costs nothing at
// lookup time (hashing once per request is negligible) and needs no reverse
// mapping anywhere: every lookup re-hashes the token the caller already
// has, it never needs to go the other way.
function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }

const sessions = new Map();   // sha256(token) → { username, role, name, createdAt, expiresAt, ip }

/**
 * onEvent is injected by the boot sequence so this module stays independent of
 * the event log — importing it here would create a cycle.
 */
let onEvent = () => {};
function setEventLogger(fn) { onEvent = fn || (() => {}); }

/**
 * Sessions live in memory, so any restart used to sign everyone out — including
 * a routine image update. A store can be injected to persist them; without one
 * the behaviour is unchanged.
 *
 * Persistence only makes sense when SESSION_SECRET stays the same across a
 * restart, since it signs every token: restoring a session issued under a
 * secret that no longer applies would just hand back a token that fails its
 * signature check on the very next request.
 *
 * Bug fixe (retour utilisateur, v12.49.3) : cette fonction verifiait
 * `process.env.SESSION_SECRET` directement — vrai uniquement si l operateur a
 * defini la variable d environnement lui-meme. Depuis la v12.32.0, le mode
 * "automatique" (rien defini) genere une valeur UNE SEULE FOIS et la persiste
 * dans `.generated-secrets.json` (voir `lib/config.js#resolveGeneratedSecret()`)
 * precisement pour qu elle reste stable d un redemarrage a l autre — mais
 * cette fonction n avait jamais ete mise a jour pour en tenir compte, et
 * continuait a refuser toute restauration des qu aucune variable d env n etait
 * definie. Resultat : en mode automatique (le cas par defaut, sans .env
 * personnalise), un redemarrage deconnectait systematiquement tout le monde,
 * exactement le bug que la v12.32.0 pensait avoir eradique. `cfg.SESSION_SECRET`
 * est la valeur REELLEMENT utilisee pour signer les tokens (env si definie,
 * sinon la valeur generee-et-persistee) : c est elle qu il faut verifier.
 */
let store = null;
function setSessionStore(s) {
  store = s;
  restoreSessions();
}

function persistSessions() {
  if (!store) return;
  try {
    const now = Date.now();
    const live = [...sessions.entries()].filter(([, s]) => s.expiresAt > now);
    store.setState('sessions', live);
  } catch (e) { console.warn('[auth] Session persist error:', e.message); }
}

function restoreSessions() {
  if (!store) return;
  if (!cfg.SESSION_SECRET) {
    // Defensive only: cfg.SESSION_SECRET is always resolved (env value, or a
    // generated one persisted to .generated-secrets.json) unless persisting
    // that generated file itself failed (read-only config dir, say) — see
    // resolveGeneratedSecret()'s own warning in that case.
    console.warn('[auth] SESSION_SECRET indisponible — les sessions ne survivront pas '
      + 'a un redemarrage.');
    return;
  }
  try {
    const saved = store.getState('sessions');
    if (!Array.isArray(saved)) return;
    const now = Date.now();
    let restored = 0;
    for (const [token, s] of saved) {
      if (s && s.expiresAt > now) { sessions.set(token, s); restored++; }
    }
    if (restored) console.log(`[auth] ${restored} session(s) restauree(s)`);
  } catch (e) { console.warn('[auth] Session restore error:', e.message); }
}

function createSession(user, ip) {
  const token = crypto.randomBytes(32).toString('hex');
  const sig   = crypto.createHmac('sha256', cfg.SESSION_SECRET).update(token).digest('hex');
  const sessionToken = `${token}.${sig}`;
  sessions.set(hashToken(sessionToken), {
    username:  user.username,
    role:      user.role || 'viewer',
    name:      user.name || user.username,
    createdAt: Date.now(),
    expiresAt: Date.now() + cfg.SESSION_TTL_MS,
    ip,
  });
  onEvent('auth.login', { username: user.username, role: user.role, ip }, 'auth');
  persistSessions();
  return sessionToken;
}

// Fix (audit finding SEC-09): a session cached the role and username it was
// issued with, and nothing afterwards ever checked that account against
// users.yml again — an admin disabling a user, or demoting them from admin
// to viewer, had no effect on that user's already-open session for up to
// SESSION_ABSOLUTE_MAX_MS (24h by default). A disabled account kept full
// access through any session it opened before being disabled. validateSession()
// now re-reads the live account on every call (loadUsers() is mtime-cached,
// so this costs a cheap fs.statSync(), not a re-parse) and destroys the
// session the moment the account is gone or disabled, or refreshes the
// session's role/name to match the live record otherwise — a role change
// takes effect on the user's very next request, not at their next login.
function validateSession(token) {
  if (!token) return null;
  const key = hashToken(token);
  const session = sessions.get(key);
  if (!session) return null;
  const now = Date.now();
  // Sliding TTL, bounded by an absolute cap.
  if (now > session.expiresAt || now - session.createdAt > cfg.SESSION_ABSOLUTE_MAX_MS) {
    sessions.delete(key);
    return null;
  }
  const user = findUser(session.username);
  if (!user) {
    // Deleted, or disabled (findUser() itself filters enabled !== false).
    sessions.delete(key);
    persistSessions();
    return null;
  }
  session.role = user.role || 'viewer';
  session.name = user.name || user.username;
  session.expiresAt = now + cfg.SESSION_TTL_MS;
  return session;
}

function destroySession(token) {
  const key = hashToken(token);
  const s = sessions.get(key);
  if (s) onEvent('auth.logout', { username: s.username }, 'auth');
  sessions.delete(key);
  persistSessions();
}

// ─── Login rate limiting (brute-force protection, in-memory) ────────────────
const loginAttempts = new Map();   // key → { count, first, lockedUntil }

const rateKey = (ip, username) => `${ip}|${(username || '').toLowerCase()}`;

// Fix v12.21.1 (audit finding SEC-05): a `user|<username>` bucket, keyed on
// nothing but the account name, on top of the existing `ip|<ip>` and
// `<ip>|<username>` ones. Even with clientIp() now correctly resistant to a
// spoofed X-Forwarded-For (lib/http.js), an attacker with real access to
// many source IPs (a botnet, a rotating proxy pool) could previously still
// brute-force one specific account without limit, since every per-IP bucket
// only ever saw a handful of attempts each. This bucket has no such
// escape: it counts failures against a username regardless of where they
// came from.
function userKey(username) { return `user|${(username || '').toLowerCase()}`; }

/** Returns { blocked, retryAfterSec }. Checked before any password comparison. */
function checkLoginRate(ip, username) {
  const now = Date.now();
  for (const k of [rateKey(ip, username), `ip|${ip}`, userKey(username)]) {
    const e = loginAttempts.get(k);
    if (e?.lockedUntil && now < e.lockedUntil) {
      return { blocked: true, retryAfterSec: Math.ceil((e.lockedUntil - now) / 1000) };
    }
  }
  return { blocked: false };
}

function recordLoginFailure(ip, username) {
  const now = Date.now();
  for (const k of [rateKey(ip, username), `ip|${ip}`, userKey(username)]) {
    let e = loginAttempts.get(k);
    if (!e || now - e.first > cfg.LOGIN_WINDOW_MS) e = { count: 0, first: now, lockedUntil: 0 };
    e.count++;
    // The per-IP bucket is looser, since a whole office can share one
    // address; the per-username bucket is looser still (it must tolerate
    // many legitimate users failing against the same account concurrently
    // less often than a single IP would), but it is never unlimited.
    const limit = k.startsWith('ip|') ? cfg.LOGIN_MAX_ATTEMPTS * 3
      : k.startsWith('user|') ? cfg.LOGIN_MAX_ATTEMPTS * 5
      : cfg.LOGIN_MAX_ATTEMPTS;
    if (e.count >= limit) e.lockedUntil = now + cfg.LOGIN_LOCKOUT_MS;
    loginAttempts.set(k, e);
  }
}

function clearLoginFailures(ip, username) {
  loginAttempts.delete(rateKey(ip, username));
  loginAttempts.delete(`ip|${ip}`);
  loginAttempts.delete(userKey(username));
}

// ─── Cookies & request helpers ───────────────────────────────────────────────
function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k.trim()] = decodeURIComponent(v.join('='));
  });
  return cookies;
}

// Fix (audit finding, Basse/"Sécurité et durcissement"): the session cookie
// never carried `Secure`, so it would legally be sent back over a plain-HTTP
// connection — an on-path attacker (a shared network, a compromised
// intermediate proxy) could read it in cleartext. Unconditionally adding
// `Secure` would instead break every deployment still served over plain HTTP
// (this project runs its OWN reverse proxy and terminates TLS itself, but an
// operator may not have set that up yet, and every existing test in this
// suite spawns the dashboard over plain HTTP). `isRequestHttps()` detects
// TLS directly on the socket, or via `X-Forwarded-Proto: https` when this
// request arrived through this project's own nginx reverse proxy — the only
// intended way to reach the dashboard with a browser in production — so the
// flag is added exactly when it is safe to, and never regresses a
// plain-HTTP setup (dev, tests, or an operator who hasn't put TLS in front
// of it yet).
function isRequestHttps(req) {
  if (req?.socket?.encrypted) return true;
  const proto = (req?.headers?.['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  return proto === 'https';
}

function setCookieHeader(token, req) {
  return `ngx_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; ` +
         `Max-Age=${Math.floor(cfg.SESSION_TTL_MS / 1000)}` + (isRequestHttps(req) ? '; Secure' : '');
}

function clearCookieHeader(req) {
  return 'ngx_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' + (isRequestHttps(req) ? '; Secure' : '');
}

function getTokenFromReq(req) {
  return parseCookies(req).ngx_session || '';
}

/** Web UI: cookie only. */
function getSessionFromReq(req) {
  return validateSession(getTokenFromReq(req));
}
const requireSession = getSessionFromReq;

/** API: Bearer token or session cookie. */
function requireApiAuth(req) {
  const auth = req.headers['authorization'] || '';
  // v12.32.0: cfg.apiTokenActive()/verifyApiToken() also accept a token
  // generated from the UI (page Systeme) and stored as a hash — see
  // lib/config.js's own comment block for why that verification lives there.
  if (cfg.apiTokenActive() && auth.startsWith('Bearer ') && cfg.verifyApiToken(auth.slice(7))) {
    return { username: 'api', role: 'admin', name: 'API Token' };
  }
  return getSessionFromReq(req);
}

/**
 * Scoped CI/CD auth: a Bearer token matching one of config/deploy-tokens.yml's
 * entries authenticates as role 'deploy_ci' (PERMS.DEPLOY only), carrying
 * that entry's own action allowlist. Callers MUST only invoke this for the
 * fixed set of git/backup routes a deploy token is allowed to reach — see
 * server.js's DEPLOY_TOKEN_ROUTES — never as a general-purpose auth check,
 * or the route-level containment this mechanism relies on stops holding.
 * Required lazily (not at module load) so a deployment with no
 * deploy-tokens.yml at all pays nothing extra and this file has no import
 * cycle with lib/deploy-tokens.js.
 */
function authenticateDeployToken(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  const entry = require('./deploy-tokens').findByToken(auth.slice(7));
  if (!entry) return null;
  return { username: `deploy-token:${entry.name}`, role: 'deploy_ci', name: entry.name,
    deployTokenScope: true, deployActions: entry.actions };
}

/**
 * Scoped remote-agent auth (Partie 2 — hôtes Docker distants): a Bearer
 * token matching an APPROVED entry in lib/agents-store.js authenticates as
 * role 'agent' (zero PERMS — see ROLE_PERMS above), carrying that agent's
 * own id. Same containment discipline as authenticateDeployToken() just
 * above: callers MUST only invoke this for the one fixed route an agent may
 * ever reach — see server.js's AGENT_TOKEN_ROUTES — never as a
 * general-purpose auth check. Required lazily, not at module load, for the
 * same reason: a deployment that never uses this feature pays nothing extra,
 * and there is no import cycle with lib/agents-store.js.
 */
function authenticateAgentToken(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  const agent = require('./agents-store').findByToken(auth.slice(7));
  if (!agent) return null;
  return { username: `agent:${agent.id}`, role: 'agent', name: agent.hostnameProposed,
    agentScope: true, agentId: agent.id };
}

/**
 * Whether `session` is allowed to perform `action` (one of
 * lib/deploy-tokens.js's ACTIONS: pull/test/deploy/backup). Always true for
 * an ordinary session (cookie login or the global API_TOKEN) — the
 * per-action allowlist only ever narrows a scoped deploy-token session.
 */
function deployTokenAllows(session, action) {
  return !session?.deployTokenScope || (session.deployActions || []).includes(action);
}

/** Authenticate an EventSource request, which cannot send custom headers. */
function authenticateQueryToken(token) {
  if (cfg.apiTokenActive() && cfg.verifyApiToken(token)) {
    return { username: 'api', role: 'admin', name: 'API Token' };
  }
  return null;
}

// ─── Housekeeping ────────────────────────────────────────────────────────────
function startCleanupTimers() {
  // Expired sessions, every 10 minutes. The sliding TTL moves on every request,
  // so the refreshed expiry is written here rather than per request.
  setInterval(() => {
    const now = Date.now();
    for (const [tok, s] of sessions) if (now > s.expiresAt) sessions.delete(tok);
    persistSessions();
  }, 600_000).unref();

  // Stale rate-limit buckets, hourly
  setInterval(() => {
    const now = Date.now();
    for (const [k, e] of loginAttempts) {
      if (now - e.first > cfg.LOGIN_WINDOW_MS && (!e.lockedUntil || now > e.lockedUntil)) {
        loginAttempts.delete(k);
      }
    }
  }, 3_600_000).unref();
}

module.exports = {
  PERMS, ROLE_PERMS, roleHasPerm, hasPerm,
  hashPassword, verifyPassword, needsRehash, safeCompare, verifyCredentials,
  loadUsers, findUser, getUsers, saveUsers, upgradePasswordHash,
  parseYmlUsers, rewriteUsersFile,
  createSession, validateSession, destroySession, sessions, hashToken,
  checkLoginRate, recordLoginFailure, clearLoginFailures,
  parseCookies, setCookieHeader, clearCookieHeader, isRequestHttps,
  loginOriginAllowed,
  getTokenFromReq, getSessionFromReq, requireSession, requireApiAuth,
  authenticateQueryToken, authenticateDeployToken, deployTokenAllows, authenticateAgentToken,
  setEventLogger, setSessionStore, persistSessions, startCleanupTimers,
};
