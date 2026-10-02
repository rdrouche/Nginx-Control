'use strict';
/**
 * Docker daemon access over the Unix socket.
 *
 * Two things here are easy to get wrong and have both bitten this project:
 *
 *  - Docker's attach/logs endpoints return a *multiplexed* stream: each frame
 *    carries an 8-byte header before its payload. Reading the body as text
 *    leaves those header bytes inline, which is where the stray characters in
 *    container logs came from. demuxStream() strips them.
 *  - The daemon resolves bind-mount sources on the HOST. Passing a path that
 *    only exists inside this container makes it silently create an empty
 *    directory and mount that — which is how the "config test" managed to pass
 *    while validating nothing. toHostPath() translates, and returns null rather
 *    than guessing.
 */

const http = require('http');
const path = require('path');
const os   = require('os');
const { exec } = require('child_process');
const cfg = require('./config');

// ─── Stream demultiplexing ───────────────────────────────────────────────────
/**
 * Split a multiplexed Docker stream into stdout/stderr.
 * Frame layout: [type(1), 0, 0, 0, size(4, big-endian)] followed by `size` bytes.
 * type 1 = stdout, 2 = stderr.
 */
function demuxStream(raw) {
  let stdout = '', stderr = '';
  if (!raw || !raw.length) return { stdout, stderr };
  // A TTY-enabled container sends a plain stream with no framing.
  if (raw.length >= 1 && raw[0] !== 0 && raw[0] !== 1 && raw[0] !== 2) {
    return { stdout: raw.toString('utf8'), stderr: '' };
  }
  let pos = 0;
  while (pos + 8 <= raw.length) {
    const type = raw[pos];
    const size = raw.readUInt32BE(pos + 4);
    const payload = raw.slice(pos + 8, pos + 8 + size).toString('utf8');
    if (type === 2) stderr += payload; else stdout += payload;
    pos += 8 + size;
  }
  return { stdout, stderr };
}

/** Convenience: both streams of a demuxed response, in order. */
function demuxToText(raw) {
  const { stdout, stderr } = demuxStream(raw);
  return stdout + stderr;
}

// ─── Low-level API call ──────────────────────────────────────────────────────
/**
 * Call the Docker API. Returns { status, body, rawBuffer }.
 *
 * `rawBuffer` is always present so callers of log/attach endpoints can demux;
 * it was previously missing, leaving frame headers in the parsed output.
 */
async function dockerCall(method, urlPath, body) {
  return new Promise((resolve) => {
    const bodyBuf = body ? Buffer.from(JSON.stringify(body)) : null;
    const opts = {
      socketPath: cfg.DOCKER_SOCKET, path: urlPath, method,
      headers: bodyBuf
        ? { 'Content-Type': 'application/json', 'Content-Length': bodyBuf.length }
        : {},
    };
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on('data', d => chunks.push(d));
      res.on('end', () => {
        const rawBuffer = Buffer.concat(chunks);
        const text = rawBuffer.toString('utf8');
        let parsed = null;
        if (text) { try { parsed = JSON.parse(text); } catch { parsed = text; } }
        resolve({ status: res.statusCode, body: parsed, rawBuffer });
      });
    });
    // An unreachable daemon is a state to report, not an exception to propagate:
    // callers already branch on `status`, and rejecting here turned a missing
    // socket into a 500 on every page that shows a container's state.
    req.on('error', (e) => resolve({
      status: 0, body: null, rawBuffer: Buffer.alloc(0),
      error: e.code || e.message,
    }));
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

/** Fetch container logs, already demultiplexed. */
async function getContainerLogs(nameOrId, { tail = 100, timestamps = true } = {}) {
  const q = `stdout=1&stderr=1&tail=${tail}&timestamps=${timestamps ? 1 : 0}`;
  const r = await dockerCall('GET', `/containers/${encodeURIComponent(nameOrId)}/logs?${q}`);
  if (r.status === 404) return '';
  return demuxToText(r.rawBuffer);
}

// ─── Container resolution ────────────────────────────────────────────────────
let resolvedContainerId = null;

/**
 * Locate the nginx container. Matches the configured name exactly first, then
 * falls back to a substring match so docker-compose prefixes
 * ("mystack_nginx_1") still resolve.
 */
async function resolveContainer() {
  return new Promise((resolve) => {
    http.get({ socketPath: cfg.DOCKER_SOCKET, path: '/containers/json?all=0' }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const containers = JSON.parse(data);
          const want = cfg.NGINX_CONTAINER;
          let found = containers.find(c =>
            c.Names.some(n => n === '/' + want || n === want));
          if (!found) found = containers.find(c =>
            c.Names.some(n => n.toLowerCase().includes(want.toLowerCase())));
          if (found) {
            resolvedContainerId = found.Id;
            console.log(`[docker] Resolved container "${want}" → ${found.Names[0]} (${found.Id.slice(0, 12)})`);
            resolve(found.Id);
          } else {
            console.warn(`[docker] Container matching "${want}" not found`);
            resolve(want);   // fall back to the raw name
          }
        } catch { resolve(cfg.NGINX_CONTAINER); }
      });
    }).on('error', () => resolve(cfg.NGINX_CONTAINER));
  });
}

async function getContainerId() {
  return resolvedContainerId || resolveContainer();
}

function invalidateContainerId() { resolvedContainerId = null; }

// ─── Host path translation ───────────────────────────────────────────────────
let selfMountsCache = null;

/** Bind mounts of this container, longest destination first. */
async function getSelfMounts() {
  if (selfMountsCache) return selfMountsCache;
  for (const id of [process.env.HOSTNAME, os.hostname()].filter(Boolean)) {
    try {
      const r = await dockerCall('GET', `/containers/${encodeURIComponent(id)}/json`);
      if (r.status === 200 && Array.isArray(r.body?.Mounts)) {
        selfMountsCache = r.body.Mounts
          .filter(m => m.Source && m.Destination)
          .sort((a, b) => b.Destination.length - a.Destination.length);
        return selfMountsCache;
      }
    } catch { /* try the next candidate */ }
  }
  selfMountsCache = [];
  return selfMountsCache;
}

/**
 * Translate a path inside this container to its host equivalent.
 * Returns null when no mount covers it — callers must treat that as an error
 * rather than falling back to the raw path, or Docker will mount an empty
 * directory and the caller will never notice.
 */
async function toHostPath(containerPath) {
  const p = path.resolve(containerPath);
  for (const m of await getSelfMounts()) {
    const dest = path.resolve(m.Destination);
    if (p === dest) return m.Source;
    if (p.startsWith(dest + path.sep)) return path.join(m.Source, p.slice(dest.length));
  }
  return null;
}

/**
 * Network for containers we spawn. Mirrors the nginx container so DNS
 * resolution matches production — nginx resolves upstream hostnames while
 * parsing its config, so an isolated container fails on every `upstream`
 * pointing at a real host. Never "none".
 */
async function getNginxNetworkMode() {
  try {
    const id = await getContainerId();
    if (id) {
      const r = await dockerCall('GET', `/containers/${encodeURIComponent(id)}/json`);
      const nets = r.status === 200 ? Object.keys(r.body?.NetworkSettings?.Networks || {}) : [];
      if (nets.length) return nets[0];
    }
  } catch { /* fall through */ }
  return cfg.NGINX_NETWORK || 'bridge';
}

// ─── Command execution inside the nginx container ────────────────────────────
/**
 * Run a command in the nginx container via the exec endpoint.
 * Resolves { stdout, stderr } on exit code 0, rejects with the same shape plus
 * `error` otherwise. Falls back to the docker CLI if the socket is unavailable.
 */
/**
 * Restart the nginx container itself — stop and start the process, not a
 * graceful `nginx -s reload`. Some changes only take effect on a full
 * restart: loading or unloading a dynamic module (ModSecurity among them),
 * a module that leaks memory across reloads, or an engine that got stuck.
 * A short grace period lets in-flight connections drain before the kill.
 */
async function restartContainer(graceSeconds = 10) {
  const containerId = await getContainerId();
  const r = await dockerCall('POST',
    `/containers/${encodeURIComponent(containerId)}/restart?t=${graceSeconds}`);
  if (r.status !== 204 && r.status !== 304) {
    throw { error: `Restart failed: HTTP ${r.status}`, status: r.status };
  }
  return { ok: true };
}

/**
 * Turn Docker's raw stats snapshot into the figures the dashboard displays.
 * Pure and side-effect free — separated from getContainerStats() so the
 * arithmetic can be tested directly against known inputs, without a Docker
 * socket to talk to.
 */
function computeContainerStats(s) {
  const cpuDelta    = (s.cpu_stats?.cpu_usage?.total_usage    || 0) - (s.precpu_stats?.cpu_usage?.total_usage    || 0);
  const systemDelta = (s.cpu_stats?.system_cpu_usage          || 0) - (s.precpu_stats?.system_cpu_usage          || 0);
  const onlineCpus  = s.cpu_stats?.online_cpus
    || s.cpu_stats?.cpu_usage?.percpu_usage?.length || 1;
  // Both deltas are zero right after a restart — the previous sample doesn't
  // exist yet. That is a real "no data yet", not a divide-by-zero to hide.
  const cpuPercent = systemDelta > 0 && cpuDelta >= 0
    ? (cpuDelta / systemDelta) * onlineCpus * 100
    : null;

  const memUsage = s.memory_stats?.usage ?? null;
  // Docker's raw "usage" includes the page cache, which balloons with disk
  // activity and does not reflect what the application actually holds; the
  // cache figure moves around by cgroup version (v1 exposes it as
  // `stats.cache`, v2 as `stats.inactive_file`), so both are tried.
  const cache = s.memory_stats?.stats?.cache ?? s.memory_stats?.stats?.inactive_file ?? 0;
  const memUsed  = memUsage !== null ? Math.max(0, memUsage - cache) : null;
  const memLimit = s.memory_stats?.limit ?? null;

  let netRx = 0, netTx = 0;
  for (const iface of Object.values(s.networks || {})) {
    netRx += iface.rx_bytes || 0;
    netTx += iface.tx_bytes || 0;
  }

  return {
    cpuPercent: cpuPercent !== null ? +cpuPercent.toFixed(1) : null,
    onlineCpus,
    memUsedBytes: memUsed, memLimitBytes: memLimit,
    // No limit set on the container (0, or absurdly large as Docker reports
    // for "unlimited") means a percentage of it would be meaningless.
    memPercent: memUsed !== null && memLimit ? +((memUsed / memLimit) * 100).toFixed(1) : null,
    netRxBytes: netRx, netTxBytes: netTx,
    pids: s.pids_stats?.current ?? null,
    readAt: s.read || null,
  };
}

/**
 * A one-shot resource snapshot for the nginx container — the same data
 * `docker stats --no-stream` reports. A single call already carries both the
 * current and the previous CPU accounting sample (`cpu_stats` and
 * `precpu_stats`), which is what makes a CPU percentage computable without a
 * second round-trip a few seconds later.
 */
async function getContainerStats() {
  const containerId = await getContainerId();
  const r = await dockerCall('GET', `/containers/${encodeURIComponent(containerId)}/stats?stream=false`);
  if (r.status !== 200 || !r.body) throw { error: `Stats unavailable: HTTP ${r.status}` };
  return computeContainerStats(r.body);
}

async function execNginx(cmd) {
  const containerId = await getContainerId();
  const args = cmd.split(' ');

  return new Promise((resolve, reject) => {
    const createBody = JSON.stringify({ AttachStdout: true, AttachStderr: true, Cmd: args });
    const createReq = http.request({
      socketPath: cfg.DOCKER_SOCKET,
      path: `/containers/${encodeURIComponent(containerId)}/exec`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(createBody) },
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode === 404) {
          invalidateContainerId();
          return reject({ error: `Container not found: ${containerId}. Check NGINX_CONTAINER.`, stderr: data });
        }
        if (res.statusCode !== 201) {
          return reject({ error: `Docker API error ${res.statusCode}`, stderr: data });
        }
        let execId;
        try { execId = JSON.parse(data).Id; }
        catch { return reject({ error: 'Cannot parse exec ID', stderr: data }); }

        const startBody = JSON.stringify({ Detach: false, Tty: false });
        const startReq = http.request({
          socketPath: cfg.DOCKER_SOCKET,
          path: `/exec/${execId}/start`,
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(startBody) },
        }, (sres) => {
          const chunks = [];
          sres.on('data', d => chunks.push(d));
          sres.on('end', () => {
            const { stdout, stderr } = demuxStream(Buffer.concat(chunks));
            http.get({ socketPath: cfg.DOCKER_SOCKET, path: `/exec/${execId}/json` }, (ires) => {
              let idata = '';
              ires.on('data', d => idata += d);
              ires.on('end', () => {
                let exitCode = 0;
                try { exitCode = JSON.parse(idata).ExitCode; } catch { /* assume success */ }
                const out = { stdout: stdout.trim(), stderr: stderr.trim() };
                if (exitCode !== 0) reject({ error: `nginx exited with code ${exitCode}`, ...out });
                else resolve(out);
              });
            }).on('error', () => resolve({ stdout: stdout.trim(), stderr: stderr.trim() }));
          });
        });
        startReq.on('error', e => reject({ error: e.message, stderr: '' }));
        startReq.write(startBody);
        startReq.end();
      });
    });

    createReq.on('error', () => {
      // Socket unavailable — fall back to the CLI.
      invalidateContainerId();
      exec(`docker exec ${cfg.NGINX_CONTAINER} ${cmd}`, { timeout: 10_000 }, (err, so, se) => {
        if (err) reject({ error: err.message, stderr: se });
        else resolve({ stdout: so.trim(), stderr: se.trim() });
      });
    });
    createReq.write(createBody);
    createReq.end();
  });
}

/**
 * Extract just the tag from a full Docker image reference, the way `docker
 * images` or `docker inspect .Config.Image` returns it — e.g.
 * "ghcr.io/user/nginx-dashboard:1.2.3-waf" or, with a registry that runs on
 * a non-default port, "registry.example.com:5000/user/image:1.2.3". Version
 * checking previously compared against this whole string unparsed, which
 * meant it never actually recognized the running version as matching
 * anything an update-check feed would return (a bare "1.2.4", never a full
 * registry path) — every check looked like an update was needed, or none
 * ever was, depending on how the comparison happened to fail.
 *
 * A colon before the final `/` is a registry port, not a tag separator —
 * this only treats a colon found *after* the last `/` as the tag boundary,
 * and returns 'latest' (Docker's own default) when the reference has no
 * explicit tag at all. A digest reference (`@sha256:...`) has no tag in the
 * traditional sense; its digest is returned as-is since there is nothing
 * more specific to extract.
 */
function parseImageTag(image) {
  if (!image) return null;
  const atIdx = image.indexOf('@');
  const withoutDigest = atIdx === -1 ? image : image.slice(0, atIdx);
  const lastSlash = withoutDigest.lastIndexOf('/');
  const afterSlash = lastSlash === -1 ? withoutDigest : withoutDigest.slice(lastSlash + 1);
  const colonIdx = afterSlash.lastIndexOf(':');
  if (colonIdx === -1) return atIdx !== -1 ? image.slice(atIdx + 1) : 'latest';
  return afterSlash.slice(colonIdx + 1);
}

/**
 * Strip a known build-variant suffix (this project ships `a.b.c`, `a.b.c-waf`
 * and `a.b.c-coraza` tags for the same underlying nginx version) so version
 * *comparison* treats "1.2.3-waf" as equivalent to "1.2.3" — an update-check
 * feed publishes one bare version, not one per variant, so comparing the
 * suffixed tag literally against it would flag an update as available
 * forever, even immediately after upgrading to the latest -waf build.
 * Comparison-only: the real tag, suffix included, is still what gets shown
 * to the operator everywhere else.
 */
function stripVariantSuffix(tag) {
  if (!tag) return tag;
  return tag.replace(/-(waf|coraza)$/i, '');
}

/** Local image ID (sha256:...) as `docker inspect` reports it, or null if the
 * image has never been pulled. Used purely for before/after comparison —
 * pullAndCheckUpdate() below is the only caller that needs this to mean
 * anything on its own. */
async function getImageId(image) {
  const r = await dockerCall('GET', `/images/${encodeURIComponent(image)}/json`);
  return r.status === 200 ? (r.body?.Id || null) : null;
}

/**
 * Pull an image's tag from its registry and report whether the locally
 * cached image actually changed — a `:latest`-style tag can be re-pulled
 * any number of times without a new image existing upstream, and a
 * container already running the old content keeps doing so until it is
 * recreated from the freshly pulled image, `docker pull` alone changes
 * nothing for a container that already exists.
 *
 * Deliberately does not recreate anything itself — every managed container
 * (certbot, geoipupdate, error-pages) already has its own `startContainer()`
 * that destroys and recreates from current config, and reusing that instead
 * of duplicating container-creation logic here keeps this function a pure,
 * reusable "did the registry give us something new" check.
 */
async function pullAndCheckUpdate(image) {
  if (!image) return { ok: false, error: 'no image configured' };
  const before = await getImageId(image);
  const pull = await dockerCall('POST', `/images/create?fromImage=${encodeURIComponent(image)}`);
  if (pull.status !== 200 && pull.status !== 204) {
    // An unreachable daemon or a registry timeout comes back as a genuine
    // non-2xx/0 status here.
    return { ok: false, error: pull.error || `HTTP ${pull.status}`, pulled: false };
  }
  // The Engine API always answers a pull with HTTP 200 and a stream of
  // newline-delimited JSON progress objects — a real failure (bad tag,
  // auth wall, unknown repository) shows up as an "error" field INSIDE that
  // stream, never as the HTTP status. dockerCall() tries to JSON.parse the
  // whole concatenated stream as one value, which fails for more than one
  // line and falls back to the raw text — so this checks that raw text
  // directly rather than trusting a 200 status to mean the pull succeeded.
  const streamText = pull.rawBuffer ? pull.rawBuffer.toString('utf8') : (typeof pull.body === 'string' ? pull.body : '');
  const errorLine = streamText.split('\n').map(l => { try { return JSON.parse(l); } catch { return null; } })
    .find(o => o && o.error);
  if (errorLine) return { ok: false, error: errorLine.error, pulled: false };
  const after = await getImageId(image);
  if (!after) return { ok: false, error: 'image not found after pull', pulled: false };
  return { ok: true, pulled: true, updated: before !== after, before, after };
}

/**
 * Stream Docker's `/events` endpoint (container start/stop/die/update/...)
 * as they happen, instead of polling. A thin, single-connection primitive:
 * it does NOT retry on its own when the stream ends or errors — that policy
 * (backoff, giving up while the socket is unreachable, etc.) belongs to the
 * caller, which knows what it's watching for and how urgently it needs to
 * reconnect. See features/docker-autoconfig.js's own watcher for the
 * intended usage (reactive detection + poll as a safety net).
 *
 * The engine sends one JSON object per line (newline-delimited, not a JSON
 * array) over a connection that otherwise never closes on its own — this
 * buffers partial lines across `data` chunks rather than assuming each
 * chunk is exactly one event.
 *
 * Returns `{ close() }` to end the stream deliberately (e.g. on shutdown).
 */
function streamEvents({ filters, onEvent, onEnd } = {}) {
  const q = filters ? `?filters=${encodeURIComponent(JSON.stringify(filters))}` : '';
  let ended = false;
  const finish = (err) => { if (ended) return; ended = true; onEnd?.(err || null); };

  const req = http.request({ socketPath: cfg.DOCKER_SOCKET, path: `/events${q}`, method: 'GET' }, (res) => {
    if (res.statusCode !== 200) {
      res.resume();
      return finish(new Error(`HTTP ${res.statusCode} from /events`));
    }
    let buf = '';
    res.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      let idx;
      while ((idx = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        if (!line.trim()) continue;
        try { onEvent?.(JSON.parse(line)); } catch { /* malformed/partial line — skip it, not fatal */ }
      }
    });
    res.on('end', () => finish());
    res.on('error', (e) => finish(e));
  });
  req.on('error', (e) => finish(e));
  req.end();
  return { close: () => { ended = true; req.destroy(); } };
}

module.exports = {
  demuxStream, demuxToText,
  dockerCall, getContainerLogs,
  resolveContainer, getContainerId, invalidateContainerId,
  getSelfMounts, toHostPath, getNginxNetworkMode,
  parseImageTag, stripVariantSuffix,
  execNginx, restartContainer, getContainerStats, computeContainerStats,
  getImageId, pullAndCheckUpdate, streamEvents,
};
