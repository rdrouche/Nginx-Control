'use strict';
/**
 * Configuration file browser, inline editor and (conditionally) file
 * creation.
 *
 * Covers the four managed directories (sites, conf, snippets, streams), the
 * snippet metadata headers, and two opt-in write paths that share the same
 * safety pipeline (write to a temp file, test in an ephemeral nginx sandbox,
 * back up, apply, reload — a broken file can never reach production):
 *
 *  - Editing an existing file, when ALLOW_EDIT is on (unchanged behaviour,
 *    moved here from server.js — see "Migration note" below).
 *  - Creating a brand new file, when ALLOW_CREATE is on AND Git is NOT
 *    configured (git.yml/GIT_REPO_URL). Without Git, the dashboard's own
 *    managed directories ARE the source of truth, so creating a file
 *    in-place is safe; with Git configured, new files are expected to come
 *    from the repository (Sync ref / Git deploy) so the directories stay
 *    reproducible from it and a locally-created file can't silently drift
 *    out of sync with what Git thinks is deployed.
 *
 * Client-supplied paths are resolved with safeResolveWithin() before being
 * compared to a base directory. Comparing the raw string is not enough:
 * "/nginx/sites/../../etc/shadow" passes a startsWith("/nginx/sites") check,
 * which turned this endpoint into an arbitrary file read for any account,
 * viewer included.
 *
 * Migration note — /api/configs/save used to live directly in server.js and
 * called testConfigEphemeral()/fetchRefFileList() without importing them: a
 * pre-existing bug (ReferenceError on every call) left over from when those
 * functions were extracted into features/deploy.js and features/sync-ref.js.
 * It went unnoticed because the route had no test coverage and ALLOW_EDIT
 * defaults to off. Moving it here fixes that by wiring both through the same
 * injection pattern sync-ref.js already uses for the deploy feature —
 * features never import each other directly, server.js (the composition
 * root) wires them with setDeps().
 */

const fs   = require('fs');
const path = require('path');

const cfg      = require('../lib/config');
const httpLib  = require('../lib/http');
const auth     = require('../lib/auth');
const tree     = require('../lib/fs-tree');
const events   = require('../lib/events');
const snippets = require('../lib/snippets');
const { createBackupZip } = require('../lib/backup');
const { execNginx } = require('../lib/docker');
const { getGitCfg } = require('../lib/git');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { safeStat, safeReadDir, safeReadFile, safeResolveWithin, isDirWritable, copyTree } = tree;
const { logEvent } = events;
const {
  DIR_SITES, DIR_CONF, DIR_SNIPPETS, DIR_STREAMS, DIR_SSL, CONF_EXTS,
  ALLOW_EDIT, ALLOW_CREATE, SYNC_REF_URL, SYNC_REF_SECTIONS,
} = cfg;

/** The directories a client may browse (GET routes below). */
const MANAGED_DIRS = [DIR_SITES, DIR_CONF, DIR_SNIPPETS, DIR_STREAMS];

/** Section name -> directory, shared by the create route and the sandbox merge. */
const SECTION_DIRS = { sites: DIR_SITES, conf: DIR_CONF, snippets: DIR_SNIPPETS, streams: DIR_STREAMS };
// The sandbox test also needs ssl/ present (vhosts reference ssl_certificate
// snippets there) even though ssl/ is not a section files can be *created*
// in from this feature — DIR_SSL is a bind mount, editable via /save, never
// a /create target.
const SANDBOX_SECTION_DIRS = { ...SECTION_DIRS, ssl: DIR_SSL };

/**
 * testConfigEphemeral (features/deploy.js) and fetchRefFileList
 * (features/sync-ref.js) each live in a different feature, and features
 * never import each other — server.js, the composition root, injects both
 * here, the same pattern features/sync-ref.js uses for its own deploy
 * dependency (setDeployHandlers).
 */
let testConfigEphemeral = async () => { throw new Error('deploy not wired — call setDeps({ testConfigEphemeral })'); };
let fetchRefFileList    = async () => [];

function setDeps({ testConfigEphemeral: t, fetchRefFileList: f } = {}) {
  if (t) testConfigEphemeral = t;
  if (f) fetchRefFileList = f;
}

function listConfDir(dir, includeContent = false) {
  return safeReadDir(dir)
    .filter(name => CONF_EXTS.has(path.extname(name)))
    .map(name => {
      const fullPath = path.join(dir, name);
      const stat = safeStat(fullPath);
      if (!stat || stat.isDirectory()) return null;
      const item = { name, path: fullPath, ext: path.extname(name), size: stat.size, mtime: stat.mtime.toISOString(), enabled: !name.endsWith('.DISABLE') };
      if (includeContent) item.content = safeReadFile(fullPath) || '';
      return item;
    }).filter(Boolean).sort((a, b) => a.name.localeCompare(b.name));
}

function getAllConfigs(withContent = false) {
  return {
    sites:    { dir: DIR_SITES,    files: listConfDir(DIR_SITES,    withContent) },
    conf:     { dir: DIR_CONF,     files: listConfDir(DIR_CONF,     withContent) },
    snippets: { dir: DIR_SNIPPETS, files: listConfDir(DIR_SNIPPETS, withContent) },
    streams:  { dir: DIR_STREAMS,  files: listConfDir(DIR_STREAMS,  withContent) },
  };
}

/** True when `fileName` (enabled or .DISABLE) is tracked by the reference repo. */
async function isReferenceFile(fileName) {
  if (!SYNC_REF_URL) return false;
  const baseName = fileName.replace(/\.DISABLE$/, '');
  for (const section of SYNC_REF_SECTIONS) {
    const files = await fetchRefFileList(section).catch(() => []);
    if (files.some(f => f.name.replace(/\.DISABLE$/, '') === baseName)) return true;
  }
  return false;
}

/**
 * Shared pipeline behind both the save (edit) and create routes: write to a
 * temp file, substitute it into a full copy of every managed section, run
 * an ephemeral nginx test against that copy, back up the live directories,
 * only then apply and reload. `filePath` may or may not exist yet on disk —
 * the pipeline itself doesn't care, that distinction (edit vs create) is
 * enforced by the callers before this runs.
 */
async function applyManagedFileWrite(filePath, newContent, { session, eventName, successMessage }) {
  const normalized = path.resolve(filePath);
  const fileName = path.basename(filePath);

  // A read-only bind mount (ssl/, certs/) can't be written — say so plainly
  // instead of failing later with a raw EROFS.
  if (!isDirWritable(path.dirname(normalized))) {
    return { status: 400, body: { error: `Directory is mounted read-only: ${path.dirname(normalized)}` } };
  }

  const tmpFile = filePath + '.edit-tmp';
  const MERGE_TMP = path.join(path.dirname(filePath), '.edit-merge-tmp');
  try {
    fs.writeFileSync(tmpFile, newContent, 'utf8');

    // Build test dirs with the new/edited file substituted in.
    const srcDirs = {};
    for (const [section, activeDir] of Object.entries(SANDBOX_SECTION_DIRS)) {
      const mergeDir = path.join(MERGE_TMP, section);
      fs.mkdirSync(mergeDir, { recursive: true });
      copyTree(activeDir, mergeDir);
      if (activeDir && normalized.startsWith(path.resolve(activeDir))) {
        fs.copyFileSync(tmpFile, path.join(mergeDir, fileName));
      }
      srcDirs[section] = mergeDir;
    }

    const testResult = await testConfigEphemeral(srcDirs);
    try { fs.rmSync(MERGE_TMP, { recursive: true, force: true }); } catch {}

    if (!testResult.valid) {
      fs.unlinkSync(tmpFile);
      return { status: 200, body: { ok: false, error: 'Config test failed', testResult } };
    }

    // Backup before touching the live file.
    await createBackupZip(eventName === 'config.create' ? 'pre-create' : 'pre-edit').catch(() => {});

    // Apply.
    fs.copyFileSync(tmpFile, filePath);
    fs.unlinkSync(tmpFile);

    // Reload nginx.
    let reloadResult = null;
    try {
      reloadResult = await execNginx('nginx -s reload');
    } catch (re) {
      reloadResult = { error: re.message || String(re) };
    }

    logEvent(eventName, { file: fileName, by: session.username, reloaded: !reloadResult?.error });
    return {
      status: 200,
      body: { ok: true, message: successMessage, reloaded: !reloadResult?.error, reloadError: reloadResult?.error },
    };
  } catch (e) {
    try { fs.unlinkSync(tmpFile); } catch {}
    try { fs.rmSync(MERGE_TMP, { recursive: true, force: true }); } catch {}
    return { status: 500, body: { error: e.message } };
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/configs', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    return send(res, 200, getAllConfigs(url.searchParams.get('content') === '1'));
  });

  router.get('/api/configs/file', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const rawPath = url.searchParams.get('path');
    if (!rawPath) return httpLib.badRequest(res, 'path param required');
    // Resolve before comparing — see the module header.
    const filePath = safeResolveWithin(rawPath, MANAGED_DIRS);
    if (!filePath) return httpLib.forbidden(res, 'Access denied');
    const content = safeReadFile(filePath);
    if (content === null) return httpLib.notFound(res, 'File not found');
    const stat = safeStat(filePath);
    return send(res, 200, {
      path: filePath,
      name: path.basename(filePath),
      content,
      size: stat ? stat.size : 0,
      mtime: stat ? stat.mtime.toISOString() : null,
      enabled: !filePath.endsWith('.DISABLE'),
    });
  });

  router.get('/api/snippets/meta', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    return send(res, 200, { snippets: snippets.listSnippetsWithMeta() });
  });

  router.get('/api/snippets/ssl', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    return send(res, 200, { snippets: snippets.listSSLSnippets() });
  });

  // GET /api/configs/edit-status — whether the inline editor should show up
  // at all, and why not when it doesn't. Bug fixed in v12.46.0 (retour
  // utilisateur) : this used to return `enabled: ALLOW_EDIT` alone, so with
  // Git configured, ALLOW_EDIT=true still let an operator edit a live file
  // in place — a change Git knows nothing about, and that the very next
  // `git pull`/deploy silently overwrites (or, worse, that a manual local
  // edit could make look like drift the next time someone diffs against the
  // repo). Same rationale as ALLOW_CREATE/create-status just below: once Git
  // is configured, the repository is the source of truth, so in-place edits
  // are only safe when there's no repo to fall out of sync with.
  router.get('/api/configs/edit-status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const gitConfigured = !!getGitCfg().repoUrl;
    return send(res, 200, { enabled: ALLOW_EDIT && !gitConfigured, allowEdit: ALLOW_EDIT, gitConfigured });
  });

  // GET /api/configs/create-status — whether the "new file" action should
  // show up at all, and why not when it doesn't (ALLOW_CREATE off, or Git
  // configured — see the module header for the rationale).
  router.get('/api/configs/create-status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const gitConfigured = !!getGitCfg().repoUrl;
    return send(res, 200, {
      enabled: ALLOW_CREATE && !gitConfigured,
      allowCreate: ALLOW_CREATE,
      gitConfigured,
      sections: Object.keys(SECTION_DIRS),
    });
  });

  // POST /api/configs/save — edit an existing file (requires ALLOW_EDIT=true
  // AND no Git repo configured — see the comment on GET /api/configs/edit-
  // status above; this is the enforcement side of the same fix, since a
  // hidden button alone never stopped a direct API call).
  router.post('/api/configs/save', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return send(res, 403, { error: 'Forbidden' });
    if (!ALLOW_EDIT) return send(res, 403, { error: 'Inline edit disabled (set ALLOW_EDIT=true)' });
    if (getGitCfg().repoUrl) {
      return send(res, 403, {
        error: 'Inline edit is disabled while Git is configured — '
             + 'commit the change to your reference repository and deploy it via Git instead',
      });
    }

    const body = await parseBody(req);
    const filePath = body.path;
    const newContent = body.content;
    if (!filePath || newContent === undefined) return send(res, 400, { error: 'path and content required' });

    // Security: only allow editing files in managed dirs (+ ssl, read via a
    // bind mount but still editable when the mount itself is writable).
    const allowedDirs = [DIR_SITES, DIR_CONF, DIR_SNIPPETS, DIR_STREAMS, DIR_SSL];
    const normalized = path.resolve(filePath);
    const allowed = allowedDirs.some(d => d && normalized.startsWith(path.resolve(d)));
    if (!allowed) return send(res, 403, { error: 'File outside managed directories' });

    // Detect reference files (from SYNC_REF_URL repo) — block editing.
    const fileName = path.basename(filePath);
    if (await isReferenceFile(fileName)) {
      return send(res, 403, { error: 'Reference files cannot be edited inline — use Sync ref to update' });
    }

    const result = await applyManagedFileWrite(filePath, newContent, {
      session, eventName: 'config.edit', successMessage: 'File saved, tested and nginx reloaded',
    });
    return send(res, result.status, result.body);
  });

  // POST /api/configs/create — create a brand new file (requires
  // ALLOW_CREATE=true AND no Git repo configured — see the module header).
  router.post('/api/configs/create', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return send(res, 403, { error: 'Forbidden' });
    if (!ALLOW_CREATE) return send(res, 403, { error: 'File creation disabled (set ALLOW_CREATE=true)' });
    if (getGitCfg().repoUrl) {
      return send(res, 403, {
        error: 'File creation from the dashboard is only available when Git is not configured — '
             + 'add new files to your reference repository and deploy them via Git/Sync ref instead',
      });
    }

    const body = await parseBody(req);
    const { section, name, content } = body;
    if (typeof content !== 'string') return send(res, 400, { error: 'content required' });

    const dir = SECTION_DIRS[section];
    if (!dir) return send(res, 400, { error: `unknown section — expected one of: ${Object.keys(SECTION_DIRS).join(', ')}` });

    // basename(name) !== name catches both a bare ".." and any path
    // separator (a slash reaching here would otherwise let a section jump
    // into an arbitrary subdirectory of `dir`, or escape it entirely).
    if (!name || typeof name !== 'string' || path.basename(name) !== name) {
      return send(res, 400, { error: 'invalid file name' });
    }
    if (!CONF_EXTS.has(path.extname(name))) {
      return send(res, 400, { error: `unsupported extension — allowed: ${[...CONF_EXTS].join(', ')}` });
    }

    const filePath = safeResolveWithin(path.join(dir, name), [dir]);
    if (!filePath) return httpLib.forbidden(res, 'Access denied');
    if (fs.existsSync(filePath)) return send(res, 409, { error: 'File already exists — use the editor to modify it' });

    const result = await applyManagedFileWrite(filePath, content, {
      session, eventName: 'config.create', successMessage: 'File created, tested and nginx reloaded',
    });
    const body2 = result.body.ok ? { ...result.body, path: filePath, name } : result.body;
    return send(res, result.status, body2);
  });
}

module.exports = {
  register, setDeps, MANAGED_DIRS, SECTION_DIRS,
  listConfDir, getAllConfigs, applyManagedFileWrite,
};
