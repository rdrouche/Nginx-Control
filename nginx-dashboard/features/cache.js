'use strict';
/**
 * Nginx proxy cache.
 *
 * Cache zones are subdirectories of DIR_CACHE. Clearing empties a zone's
 * contents but keeps the directory itself — nginx holds an open handle on it,
 * and removing it would force a restart rather than a reload.
 *
 * The `*_temp` directories are nginx scratch space, never listed or cleared.
 */

const fs   = require('fs');
const path = require('path');

const cfg    = require('../lib/config');
const http   = require('../lib/http');
const auth   = require('../lib/auth');
const docker = require('../lib/docker');
const events = require('../lib/events');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = http;

/** Recursively count files and total bytes under a directory. */
function dirStats(dirPath) {
  let files = 0, bytes = 0;
  try {
    for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
      const full = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        const sub = dirStats(full);
        files += sub.files; bytes += sub.bytes;
      } else {
        files++;
        try { bytes += fs.statSync(full).size; } catch { /* raced */ }
      }
    }
  } catch { /* unreadable — report what we have */ }
  return { files, bytes };
}

/** Cache zones: direct subdirectories of DIR_CACHE, excluding nginx scratch. */
function listCacheZones() {
  if (!cfg.DIR_CACHE || !fs.existsSync(cfg.DIR_CACHE)) return [];
  return fs.readdirSync(cfg.DIR_CACHE, { withFileTypes: true })
    .filter(e => e.isDirectory() && !e.name.endsWith('_temp'))
    .map(e => {
      const zonePath = path.join(cfg.DIR_CACHE, e.name);
      const { files, bytes } = dirStats(zonePath);
      return { name: e.name, path: zonePath, files, bytes };
    });
}

/** Empty a directory's contents, keeping the directory itself. */
function clearDir(dirPath) {
  let deleted = 0, freed = 0;
  try {
    for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
      const full = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        const sub = dirStats(full);
        freed += sub.bytes; deleted += sub.files;
        fs.rmSync(full, { recursive: true, force: true });
      } else {
        try { freed += fs.statSync(full).size; } catch { /* raced */ }
        fs.unlinkSync(full);
        deleted++;
      }
    }
  } catch (e) {
    console.warn('[cache] clearDir error:', e.message);
  }
  return { deleted, freed };
}

/**
 * Clear the given zones (all of them when `zones` is empty) and reload nginx.
 * SIGHUP is enough: nginx re-opens its cache after a reload.
 */
async function clearCacheZones(zones) {
  if (!cfg.DIR_CACHE) throw new Error('DIR_CACHE not configured');
  const allZones = listCacheZones();
  const toClear  = zones?.length ? allZones.filter(z => zones.includes(z.name)) : allZones;

  const results = [];
  let totalDeleted = 0, totalFreed = 0;
  for (const zone of toClear) {
    const { deleted, freed } = clearDir(zone.path);
    totalDeleted += deleted; totalFreed += freed;
    results.push({ zone: zone.name, deleted, freed });
  }

  const reloadLog = [];
  try {
    const r = await docker.dockerCall(
      'POST', `/containers/${encodeURIComponent(cfg.NGINX_CONTAINER)}/kill?signal=HUP`);
    reloadLog.push(r.status === 204
      ? '[OK] nginx reloaded (HUP)'
      : `[WARN] nginx reload status: ${r.status}`);
  } catch (e) {
    reloadLog.push(`[ERROR] nginx reload failed: ${e.message}`);
  }

  events.logEvent('cache_clear',
    `Cleared ${totalDeleted} files (${totalFreed} bytes) from ${toClear.length} zone(s)`);
  return { results, totalDeleted, totalFreed, reloadLog };
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/cache/zones', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return http.forbidden(res);
    if (!cfg.DIR_CACHE) return send(res, 200, { configured: false });
    return send(res, 200, { configured: true, dir: cfg.DIR_CACHE, zones: listCacheZones() });
  });

  router.post('/api/cache/clear', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return http.forbidden(res);
    if (!cfg.DIR_CACHE) return http.badRequest(res, 'DIR_CACHE not configured');
    const body  = await parseBody(req);
    const zones = body.zones || null;   // null = every zone
    try {
      const result = await clearCacheZones(zones);
      return send(res, 200, { ok: true, ...result });
    } catch (e) {
      return http.serverError(res, e);
    }
  });
}

module.exports = { register, listCacheZones, clearCacheZones, dirStats, clearDir };
