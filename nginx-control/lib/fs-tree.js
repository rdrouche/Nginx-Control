'use strict';
/**
 * Filesystem helpers shared by deploy, test, backup and sync.
 *
 * Two hard-won rules live here:
 *
 *  - Configuration trees are NOT flat. `ssl/` routinely holds a per-CA
 *    subfolder, and a plain readdir silently drops everything nested. Every
 *    traversal in this file recurses.
 *  - A path coming from a request must be resolved before it is compared to a
 *    base directory. `"/nginx/logs/../../etc/shadow".startsWith("/nginx/logs")`
 *    is true, which is how an arbitrary-file-read once slipped through.
 */

const fs   = require('fs');
const path = require('path');

/** stat() that returns null instead of throwing on a missing/unreadable path. */
function safeStat(p) {
  try { return fs.statSync(p); } catch { return null; }
}

/** readdir() that returns [] instead of throwing on a missing/unreadable dir. */
function safeReadDir(dir) {
  try { return fs.readdirSync(dir); } catch { return []; }
}

/** readFile() that returns null instead of throwing. */
function safeReadFile(filePath) {
  try { return fs.readFileSync(filePath, 'utf8'); } catch { return null; }
}

/** Files never touched by a deploy sync: VCS placeholders and hidden files. */
function isProtectedFile(name) {
  return name.startsWith('.');
}

/** True when any path segment is a protected (dot) file or directory. */
function hasProtectedSegment(relPath) {
  return relPath.split(path.sep).some(isProtectedFile);
}

/**
 * List every file under `dir`, as paths relative to it, recursing into
 * subdirectories. Returns [] when the directory does not exist.
 */
function listTreeFiles(dir, base = dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return out; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) listTreeFiles(full, base, out);
    else if (e.isFile()) out.push(path.relative(base, full));
  }
  return out;
}

/** Recursively copy a directory tree, creating intermediate directories. */
function copyTree(src, dst) {
  let count = 0;
  for (const rel of listTreeFiles(src)) {
    const sp = path.join(src, rel);
    const dp = path.join(dst, rel);
    fs.mkdirSync(path.dirname(dp), { recursive: true });
    fs.copyFileSync(sp, dp);
    count++;
  }
  return count;
}

/** Remove directories left empty after a sync, deepest first. Keeps `root`. */
function pruneEmptyDirs(root) {
  if (!fs.existsSync(root)) return;
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); }
  catch { return; }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const child = path.join(root, e.name);
    pruneEmptyDirs(child);
    try {
      if (fs.readdirSync(child).length === 0) fs.rmdirSync(child);
    } catch { /* raced or read-only — not worth failing a deploy over */ }
  }
}

/**
 * Resolve a user-supplied path and guarantee it stays inside one of `bases`.
 * Returns the normalized absolute path, or null when it escapes.
 */
function safeResolveWithin(userPath, bases) {
  if (!userPath || typeof userPath !== 'string') return null;
  if (userPath.includes('\0')) return null;
  const resolved = path.resolve(userPath);
  for (const base of bases) {
    if (!base) continue;
    const b = path.resolve(base);
    if (resolved === b || resolved.startsWith(b + path.sep)) return resolved;
  }
  return null;
}

/**
 * True when a directory exists and is writable. On a `:ro` bind mount the
 * kernel reports EROFS even for root, so this correctly detects the
 * intentionally read-only mounts (certs/).
 *
 * Treated as a hint, not a guarantee: callers still wrap individual writes, so
 * a false positive degrades to a logged per-file failure rather than an
 * aborted deploy.
 */
function isDirWritable(dir) {
  try {
    if (!fs.existsSync(dir)) return true;   // will be created by mkdirSync
    fs.accessSync(dir, fs.constants.W_OK);
    return true;
  } catch { return false; }
}

module.exports = {
  safeStat, safeReadDir, safeReadFile,
  isProtectedFile,
  hasProtectedSegment,
  listTreeFiles,
  copyTree,
  pruneEmptyDirs,
  safeResolveWithin,
  isDirWritable,
};
