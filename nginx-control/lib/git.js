'use strict';
/**
 * Git primitives for the configuration repository.
 *
 * The dashboard keeps a work tree under DIR_GIT_WORK and pushes backups to a
 * dedicated branch. Authentication goes through either a token embedded in the
 * remote URL or an SSH key; `effectiveRepoUrl()` builds the former and takes
 * care never to leak the token into logs.
 *
 * Every command runs through `runCmd()` with an explicit environment, so a
 * misconfigured global git config on the host cannot change the behaviour.
 *
 * Repo URL/branch/token/identity used to be env-only (GIT_REPO_URL, GIT_TOKEN,
 * ...), read once at process start. getGitCfg() below reads git.yml fresh on
 * every call and merges it over those same env vars, which now act only as a
 * fallback default — same "YAML wins when set, env is the fallback" rule used
 * everywhere else in this project (see ANALYZER_DEFAULT_IMAGE). This lets an
 * operator change the repo/branch/token from the Configuration page without
 * restarting the container, while an existing .env-only deployment keeps
 * working unchanged (git.yml is optional). DIR_GIT_WORK stays env-only: it is
 * a path inside THIS container, the same category as DIR_SITES/DIR_CONF, not
 * a behaviour setting.
 *
 * SECURITY (fix v12.21.1, audit finding SEC-01): every git.yml field
 * (repo_url, branch, backup_branch, user_name, user_email) is data an
 * `operator`-role account can write via the config editor (PERMS.DEPLOY).
 * Until v12.21.0, runCmd() built a single shell string and ran it through
 * `child_process.exec()` — so a repo_url of `x;touch /tmp/pwned;#` or a
 * branch of `--upload-pack=...` ran arbitrary commands or arbitrary git
 * sub-flags inside a container that holds the Docker socket (root on the
 * host). Every git invocation now goes through `execFile('git', argv, ...)`
 * with argv built as a plain array — no shell is ever spawned, so `;`, `$()`,
 * backticks and the like are inert data, never syntax. That closes command
 * injection, but `execFile` still hands git a `-C <dir>` or a bare value as
 * one of its own argv entries, so a value starting with `-` could still be
 * parsed as a git FLAG rather than as data (argument injection — e.g. a
 * branch of `--upload-pack=/bin/sh` reaching `git fetch`). `validateBranch()`
 * and `validateRepoUrl()` below reject anything that isn't a plausible
 * branch name / http(s) or ssh URL *before* it ever reaches argv, closing
 * that second path too.
 */

const fs   = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const cfg = require('./config');
const { safeReadFile, safeReadDir, copyTree } = require('./fs-tree');
const { timestamp } = require('./backup');

/**
 * DIR_GIT_WORK doubles as the ephemeral test workspace for
 * features/deploy.js#testConfigEphemeral() — its own comment explains why:
 * it has to be a real Docker volume/bind mount so a subdirectory of it can
 * be bind-mounted into the throwaway test container, and this one already
 * is, whether or not Git is configured (an inline edit via ALLOW_EDIT tests
 * itself the same way). These are the only directories that feature ever
 * creates directly under DIR_GIT_WORK (`.sandbox`, `.test-merge`,
 * `.test-merge-generated`) — everything else there is either `.git` or one
 * of the tracked sections (sites/conf/snippets/streams/ssl). Normally they
 * are removed right after each test; kept here as a fixed, dashboard-owned
 * allowlist so ensureGitRepo() can safely clear a crash leftover before the
 * very first clone (see the comment there) without ever touching anything
 * else that might be sitting in that directory.
 */
const DEPLOY_TRANSIENT_DIRS = ['.sandbox', '.test-merge', '.test-merge-generated'];

const {
  DIR_GIT_WORK,
  DIR_SITES, DIR_CONF, DIR_SNIPPETS, DIR_STREAMS, DIR_SSL, DEPLOY_SYNC_SSL,
} = cfg;

const { GIT_CONFIG_FILE } = cfg;

// A git ref name: no leading '-' (would be read as a flag), no whitespace, no
// shell metacharacters, no '..' (ref-format forbids it too). Deliberately
// stricter than `git check-ref-format` — this only ever needs to express a
// normal branch name like "main" or "release/12.21".
const SAFE_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,199}$/;
function validateBranch(name, label) {
  if (typeof name !== 'string' || !SAFE_REF_RE.test(name) || name.includes('..') || name.endsWith('.lock')) {
    throw new Error(`${label || 'branch'} invalide : "${name}" (lettres/chiffres/./-/_ uniquement, sans espace, sans ".." ni "-" en tete)`);
  }
  return name;
}

// Only http(s) URLs (optionally with an embedded token, added by
// effectiveRepoUrl() below) or the two standard SSH forms are accepted.
// Anything else — in particular anything starting with '-' — is rejected
// before it can reach argv as a flag.
const SAFE_HTTPS_URL_RE = /^https:\/\/[^\s]+$/;
const SAFE_SSH_URL_RE   = /^(ssh:\/\/[^\s]+|[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[^\s]+)$/;
function validateRepoUrl(url) {
  if (typeof url !== 'string' || url.startsWith('-') ||
      !(SAFE_HTTPS_URL_RE.test(url) || SAFE_SSH_URL_RE.test(url))) {
    throw new Error('URL de depot git invalide : doit commencer par https://, ssh:// ou user@host:path');
  }
  return url;
}

// A git identity (user.name/user.email) reaches argv as one `-c key=value`
// entry with execFile — never parsed by a shell — but a newline could still
// confuse git's own config parser, and a leading '-' would look like a flag
// to `-c` itself (it isn't, `-c` always takes the next argv as its value,
// but staying defensive costs nothing here).
function sanitizeIdentity(s, fallback) {
  const v = String(s ?? '').replace(/[\r\n]/g, ' ').trim();
  return v || fallback;
}

/**
 * Effective git settings: git.yml overlaid on the env-derived defaults.
 * A field missing (or the file itself missing) falls back to its env value,
 * so an operator who only ever used .env sees no change in behaviour.
 */
function getGitCfg() {
  const fromEnv = {
    repoUrl:      cfg.GIT_REPO_URL,
    branch:       cfg.GIT_BRANCH,
    backupBranch: cfg.GIT_BACKUP_BRANCH,
    token:        cfg.GIT_TOKEN,
    sshKey:       cfg.GIT_SSH_KEY,
    userName:     cfg.GIT_USER_NAME,
    userEmail:    cfg.GIT_USER_EMAIL,
  };
  if (!fs.existsSync(GIT_CONFIG_FILE)) return fromEnv;
  try {
    const raw = fs.readFileSync(GIT_CONFIG_FILE, 'utf8');
    const y = {};
    raw.split('\n').forEach(line => {
      const m = line.replace(/\r/g, '').match(/^([a-z_]+)\s*:\s*(.*)$/);
      if (m) y[m[1].trim()] = m[2].trim().replace(/\r/g, '').replace(/^["']|["']$/g, '');
    });
    return {
      repoUrl:      y.repo_url      || fromEnv.repoUrl,
      branch:       y.branch        || fromEnv.branch,
      backupBranch: y.backup_branch || fromEnv.backupBranch,
      token:        y.token         || fromEnv.token,
      // sshKey stays env-only (GIT_SSH_KEY) on purpose: it is a path inside
      // THIS container (a bind-mount target set by docker-compose.yml), the
      // same category as DIR_GIT_WORK — not a behaviour setting an operator
      // would change from the Configuration page.
      sshKey:       fromEnv.sshKey,
      userName:     y.user_name     || fromEnv.userName,
      userEmail:    y.user_email    || fromEnv.userEmail,
    };
  } catch (e) {
    console.warn('[git] git.yml load error, falling back to env:', e.message);
    return fromEnv;
  }
}

// Fix (audit finding, Basse/"Sécurité et durcissement"): `StrictHostKeyChecking=no`
// disabled host key verification ENTIRELY — every connection, forever — so
// an on-path attacker (a poisoned DNS answer, ARP spoofing on the Docker
// network, a compromised hop between here and the real git remote) could
// silently MITM every clone/fetch/push and inject arbitrary content into
// what this dashboard treats as trusted nginx configuration. `accept-new`
// keeps the same zero-config, non-interactive behavior an operator gets
// today (no prompt, no pre-populated known_hosts required — this container
// has neither a TTY nor an interactive operator to answer one) for the
// FIRST connection to a given host, but pins that host's key afterwards: a
// later MITM presenting a different key is then rejected instead of
// silently trusted, and a genuine host key rotation surfaces as a visible
// git failure rather than passing through unnoticed. The known_hosts file
// lives under CONFIG_DIR (already a persistent bind-mounted volume) so the
// pinned key survives a container restart instead of re-trusting on every
// boot.
const GIT_KNOWN_HOSTS_FILE = path.join(cfg.CONFIG_DIR, '.git_known_hosts');

function gitEnv(g) {
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
  if (g.sshKey) {
    // Still a single string, but it is handed to git as GIT_SSH_COMMAND, not
    // built into an exec()'d shell line — git itself splits and runs it.
    // g.sshKey stays env-only (see getGitCfg()), never operator-supplied.
    env.GIT_SSH_COMMAND = `ssh -i ${g.sshKey} -o StrictHostKeyChecking=accept-new `
      + `-o UserKnownHostsFile=${GIT_KNOWN_HOSTS_FILE} -o BatchMode=yes`;
  }
  return env;
}

/** Redact any embedded `user:token@`/`user@` credential before logging or
 *  returning a URL to a client that shouldn't see it (SEC-07). */
function redactUrl(url) {
  return String(url || '').replace(/:\/\/[^/@\s]+@/, '://***@');
}

function effectiveRepoUrl(g) {
  g = g || getGitCfg();
  validateRepoUrl(g.repoUrl);
  if (g.token && g.repoUrl.startsWith('https://')) {
    try {
      const u = new URL(g.repoUrl);
      u.username = g.token;
      return u.toString();
    } catch { return g.repoUrl; }
  }
  return g.repoUrl;
}

/**
 * Run a git command via execFile — argv is a plain array, so no shell is
 * ever involved (see the SECURITY note at the top of this file). `args`
 * excludes the leading "git"; pass `cwd` in opts instead of "-C <dir>" where
 * possible (kept as an explicit arg in a few call sites below for clarity).
 * Any error message is redacted (SEC-07): a credential embedded in a URL
 * argv entry must never reach a caller, a log line, or a CI token's response.
 */
function runCmd(args, opts = {}) {
  const g = getGitCfg();
  return new Promise((resolve, reject) => {
    execFile('git', args, { timeout: 120000, maxBuffer: 10 * 1024 * 1024, env: gitEnv(g), ...opts },
      (err, stdout, stderr) => {
        if (err) {
          reject({
            error: redactUrl(err.message),
            stdout: redactUrl(stdout || ''),
            stderr: redactUrl(stderr || ''),
            code: err.code,
          });
        } else {
          resolve({ stdout: redactUrl((stdout || '').trim()), stderr: redactUrl((stderr || '').trim()) });
        }
      });
  });
}

async function ensureGitRepo() {
  const g = getGitCfg();
  if (!g.repoUrl) throw new Error('GIT_REPO_URL not configured');
  validateBranch(g.branch, 'branch');
  const gitDir = path.join(DIR_GIT_WORK, '.git');
  const exists = fs.existsSync(gitDir);
  if (!exists) {
    fs.mkdirSync(DIR_GIT_WORK, { recursive: true });
    // `git clone` refuses a non-empty target directory. Under normal use
    // DIR_GIT_WORK is empty at this point, but a crashed config test
    // (container hang, a dashboard restart mid-run) can leave a `.sandbox`/
    // `.test-merge*` directory behind — features/deploy.js's own age-based
    // sweep only runs at the START of the NEXT test, never on this path, so
    // a leftover could sit there for hours until the very first clone hit
    // it (real-world report: surfaced as a confusing failure, "worked
    // around" at the time with `docker compose down -v`, which wipes the
    // whole volume and hides the actual cause). Clear exactly the known,
    // dashboard-owned transient directories first — never anything else —
    // then fail with a clear, actionable message if something unexpected
    // remains, rather than letting git's own generic error through.
    for (const d of DEPLOY_TRANSIENT_DIRS) {
      try { fs.rmSync(path.join(DIR_GIT_WORK, d), { recursive: true, force: true }); } catch {}
    }
    const leftover = safeReadDir(DIR_GIT_WORK);
    if (leftover.length) {
      throw new Error(
        `${DIR_GIT_WORK} n'est pas vide et ne contient pas encore de depot Git ` +
        `(reste : ${leftover.join(', ')}) — impossible de cloner tant que ce ` +
        `repertoire n'est pas vide. Videz-le (ou le volume qui le porte) puis reessayez.`
      );
    }
    await runCmd(['clone', '--branch', g.branch, '--single-branch', effectiveRepoUrl(g), DIR_GIT_WORK]);
    console.log('[git] Cloned repo into', DIR_GIT_WORK);
  }
}

async function gitPull() {
  await ensureGitRepo();
  const g = getGitCfg();
  validateBranch(g.branch, 'branch');
  await runCmd(['-C', DIR_GIT_WORK, 'fetch', 'origin', g.branch]);
  const r = await runCmd(['-C', DIR_GIT_WORK, 'reset', '--hard', `origin/${g.branch}`]);
  const log = await runCmd(['-C', DIR_GIT_WORK, 'log', '-5', '--oneline']).catch(() => ({ stdout: '' }));
  return { ...r, log: log.stdout };
}

async function gitDiff() {
  // Compare git work tree with active nginx dirs, file by file
  await ensureGitRepo();
  const sections = {
    sites:    { src: path.join(DIR_GIT_WORK, 'sites'),    dst: DIR_SITES },
    conf:     { src: path.join(DIR_GIT_WORK, 'conf'),     dst: DIR_CONF },
    snippets: { src: path.join(DIR_GIT_WORK, 'snippets'), dst: DIR_SNIPPETS },
    streams:  { src: path.join(DIR_GIT_WORK, 'streams'),  dst: DIR_STREAMS },
    ssl:      { src: path.join(DIR_GIT_WORK, 'ssl'),      dst: DIR_SSL },
  };
  const changes = [];
  for (const [section, { src, dst }] of Object.entries(sections)) {
    const srcFiles = fs.existsSync(src) ? fs.readdirSync(src) : [];
    const dstFiles = fs.existsSync(dst) ? fs.readdirSync(dst) : [];
    const allFiles = new Set([...srcFiles, ...dstFiles]);
    for (const f of allFiles) {
      const srcPath = path.join(src, f), dstPath = path.join(dst, f);
      const inSrc = fs.existsSync(srcPath), inDst = fs.existsSync(dstPath);
      if (inSrc && !inDst) {
        changes.push({ section, file: f, status: 'added' });
      } else if (!inSrc && inDst) {
        changes.push({ section, file: f, status: 'deleted' });
      } else if (inSrc && inDst) {
        const srcContent = safeReadFile(srcPath), dstContent = safeReadFile(dstPath);
        if (srcContent !== dstContent) changes.push({ section, file: f, status: 'modified' });
      }
    }
  }
  return changes;
}

async function gitTestConnection() {
  const g = getGitCfg();
  if (!g.repoUrl) throw new Error('GIT_REPO_URL not configured');
  validateBranch(g.branch, 'branch');
  if (g.backupBranch) validateBranch(g.backupBranch, 'backup_branch');
  const start      = Date.now();
  const remoteUrl  = effectiveRepoUrl(g);
  // git ls-remote --heads lists all branches — no extra arg after URL
  const result = await runCmd(['ls-remote', '--heads', remoteUrl]);
  const ms = Date.now() - start;
  const branches = result.stdout.split('\n')
    .filter(Boolean)
    .map(l => { const parts = l.split('\t'); return parts[1] ? parts[1].replace('refs/heads/', '') : null; })
    .filter(Boolean);
  const mainFound   = branches.includes(g.branch);
  const backupFound = branches.includes(g.backupBranch);
  return {
    ok: true,
    url: redactUrl(g.repoUrl),
    branch: g.branch,
    backupBranch: g.backupBranch,
    latencyMs: ms,
    branches,
    mainBranchFound: mainFound,
    backupBranchFound: backupFound,
    authMethod: g.token ? 'https-token' : g.sshKey ? 'ssh-key' : 'none',
  };
}

async function gitCreateBackupBranch() {
  const g = getGitCfg();
  if (!g.repoUrl) throw new Error('GIT_REPO_URL not configured');
  validateBranch(g.branch, 'branch');
  validateBranch(g.backupBranch, 'backup_branch');
  const workDir = DIR_GIT_WORK;
  const remoteUrl = effectiveRepoUrl(g);
  const userName  = sanitizeIdentity(g.userName, 'Nginx Dashboard');
  const userEmail = sanitizeIdentity(g.userEmail, 'dashboard@localhost');
  await ensureGitRepo();
  await runCmd(['-C', workDir, 'config', 'user.email', userEmail]).catch(() => {});
  await runCmd(['-C', workDir, 'config', 'user.name', userName]).catch(() => {});

  // Check it doesn't already exist
  const check = await runCmd(['-C', workDir, 'ls-remote', '--heads', remoteUrl, g.backupBranch]).catch(() => ({ stdout: '' }));
  if (check.stdout.trim().length > 0) return { ok: true, alreadyExists: true, branch: g.backupBranch };

  try {
    await runCmd(['-C', workDir, 'checkout', '--orphan', g.backupBranch]);
    await runCmd(['-C', workDir, 'reset', 'HEAD']).catch(() => {});
    await runCmd(['-C', workDir, 'clean', '-fd']).catch(() => {});
    // Create an empty initial commit
    await runCmd(['-C', workDir, 'commit', '--allow-empty', '-m', 'init: backup branch created by nginx-dashboard']);
    await runCmd(['-C', workDir, 'push', remoteUrl, g.backupBranch]).catch(e => {
      if (e.stderr && (e.stderr.includes('403') || e.stderr.includes('Forbidden'))) {
        throw { error: 'HTTP 403 Forbidden: token sans droits write:repository. Forgejo: Settings > Applications > Token', stderr: e.stderr };
      }
      throw e;
    });
    return { ok: true, alreadyExists: false, branch: g.backupBranch };
  } finally {
    await runCmd(['-C', workDir, 'checkout', g.branch]).catch(() => {});
  }
}

async function gitBackupPush(label) {
  const g = getGitCfg();
  if (!g.repoUrl) return { skipped: true, reason: 'GIT_REPO_URL not set' };
  validateBranch(g.branch, 'branch');
  validateBranch(g.backupBranch, 'backup_branch');
  const ts      = timestamp();
  const workDir = DIR_GIT_WORK;
  const tagName = `backup/${ts}${label ? '_' + label.replace(/[^a-zA-Z0-9-]/g, '') : ''}`;
  const remoteUrl = effectiveRepoUrl(g);
  const userName  = sanitizeIdentity(g.userName, 'Nginx Dashboard');
  const userEmail = sanitizeIdentity(g.userEmail, 'dashboard@localhost');

  await ensureGitRepo();
  await runCmd(['-C', workDir, 'config', 'user.email', userEmail]).catch(() => {});
  await runCmd(['-C', workDir, 'config', 'user.name', userName]).catch(() => {});

  try {
    // Check if backup branch already exists on remote
    await runCmd(['-C', workDir, 'fetch', 'origin']).catch(() => {});
    const remoteBranches = await runCmd(['-C', workDir, 'ls-remote', '--heads', remoteUrl, g.backupBranch]).catch(() => ({ stdout: '' }));
    const backupExists = remoteBranches.stdout.trim().length > 0;

    if (backupExists) {
      // Fetch the backup branch explicitly (force-update local ref)
      await runCmd(['-C', workDir, 'fetch', 'origin', `${g.backupBranch}:refs/remotes/origin/${g.backupBranch}`]).catch(() => {});
      // Check if local branch exists
      const localBranches = await runCmd(['-C', workDir, 'branch']).catch(() => ({ stdout: '' }));
      const localExists = localBranches.stdout.split('\n')
        .map(l => l.replace(/^[* ]+/, '').trim())
        .includes(g.backupBranch);
      if (localExists) {
        // Local branch exists — just switch to it and reset to remote
        await runCmd(['-C', workDir, 'checkout', g.backupBranch]);
        await runCmd(['-C', workDir, 'reset', '--hard', `origin/${g.backupBranch}`]);
      } else {
        // Local branch does not exist yet — create it tracking remote
        await runCmd(['-C', workDir, 'checkout', '-b', g.backupBranch, `origin/${g.backupBranch}`]);
      }
    } else {
      // Remote branch does not exist — create orphan
      await runCmd(['-C', workDir, 'checkout', '--orphan', g.backupBranch]);
      await runCmd(['-C', workDir, 'reset', 'HEAD']).catch(() => {});
      await runCmd(['-C', workDir, 'clean', '-fd']).catch(() => {});
    }

    // Copy active nginx configs into work dir (section by section)
    const dirs = { sites: DIR_SITES, conf: DIR_CONF, snippets: DIR_SNIPPETS, streams: DIR_STREAMS, ssl: DIR_SSL };
    // Remove old section dirs so deleted files are cleaned up
    for (const section of Object.keys(dirs)) {
      const dst = path.join(workDir, section);
      if (fs.existsSync(dst)) fs.rmSync(dst, { recursive: true, force: true });
      fs.mkdirSync(dst, { recursive: true });
    }
    for (const [section, src] of Object.entries(dirs)) {
      if (!fs.existsSync(src)) continue;
      copyTree(src, path.join(workDir, section));   // recursive: keeps ssl/<ca>/ etc.
    }

    // Commit
    await runCmd(['-C', workDir, 'add', '-A']);
    const commitMsg = `backup: ${ts.replace(/_/g, ' ')}${label ? ' — ' + label : ''}`;
    const commitResult = await runCmd(['-C', workDir, 'commit', '--allow-empty', '-m', commitMsg]);

    // Tag (delete existing tag with same name to avoid conflict)
    await runCmd(['-C', workDir, 'tag', '-d', tagName]).catch(() => {});
    await runCmd(['-C', workDir, 'tag', tagName]);

    // Push branch + tag to remote
    await runCmd(['-C', workDir, 'push', remoteUrl, g.backupBranch, '--force']);
    await runCmd(['-C', workDir, 'push', remoteUrl, `refs/tags/${tagName}`, '--force']);

    return { ok: true, tag: tagName, branch: g.backupBranch, ts, commit: commitResult.stdout };
  } finally {
    // Always restore main branch so git-work is ready for next pull
    await runCmd(['-C', workDir, 'checkout', g.branch]).catch(() => {});
  }
}
module.exports = {
  getGitCfg, GIT_CONFIG_FILE,
  gitEnv, effectiveRepoUrl, redactUrl, validateBranch, validateRepoUrl,
  runCmd, ensureGitRepo, gitPull, gitDiff,
  gitTestConnection, gitCreateBackupBranch, gitBackupPush,
};
