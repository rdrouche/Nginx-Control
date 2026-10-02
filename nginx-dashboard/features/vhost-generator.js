'use strict';
/**
 * VHost configuration generator.
 *
 * Turns a form payload into an nginx server block, and lists the certificate
 * sources the operator can pick from: SSL snippets, manually installed
 * certificates in DIR_SSL, and Let's Encrypt live directories.
 *
 * Generation only — nothing is written to disk. The operator copies the result,
 * reviews it and commits it like any other configuration.
 */

const fs   = require('fs');
const path = require('path');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const tree    = require('../lib/fs-tree');
const snippets = require('../lib/snippets');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { safeStat } = tree;
const { DIR_SSL, DIR_CERTS } = cfg;

function generateVhostConfig(opts) {
  const {
    serverName, https, redirectHttp, http2, listenPort,
    sslSnippet, sslCertPath, sslKeyPath,
    backend, isDockerContainer, containerName, containerPort, containerScheme,
    proxyReadTimeout, snippetsServer, snippetsLocation,
    extraServerConf, extraLocationConf, clientMaxBody, accessLog,
  } = opts;

  // Accept serverName as string or array
  const nameArr  = Array.isArray(serverName) ? serverName : (serverName||'').split(/\s+/).filter(Boolean);
  if (!nameArr.length) throw new Error('serverName is required');
  const names    = nameArr.join(' ');
  const port     = listenPort || (https ? '443' : '80');
  const timeout  = parseInt(proxyReadTimeout) || 60;

  const fmtSnippets = (arr, indent) =>
    (arr||[]).filter(Boolean).map(s => `${indent}include snippets/${s};`).join('\n');

  const lines = [];

  // HTTP → HTTPS redirect
  if (https && redirectHttp) {
    lines.push('server {');
    lines.push('    listen 80;');
    lines.push('    listen [::]:80;');
    lines.push(`    server_name ${names};`);
    lines.push('');
    lines.push('    location / {');
    lines.push('        return 301 https://$host$request_uri;');
    lines.push('    }');
    lines.push('}');
    lines.push('');
  }

  // Main server block
  lines.push('server {');
  if (https) {
    lines.push(`    listen ${port} ssl;`);
    lines.push(`    listen [::]:${port} ssl;`);
    if (http2) lines.push('    http2 on;');
  } else {
    lines.push(`    listen ${port};`);
    lines.push(`    listen [::]:${port};`);
  }
  lines.push(`    server_name ${names};`);
  lines.push('');

  // SSL
  if (https) {
    if (sslSnippet) {
      lines.push(`    include snippets/${sslSnippet};`);
    } else if (sslCertPath && sslKeyPath) {
      lines.push(`    ssl_certificate ${sslCertPath};`);
      lines.push(`    ssl_certificate_key ${sslKeyPath};`);
    }
    lines.push('');
  }

  // Access log — omit entirely if not requested (snippet may handle it)
  if (accessLog === true || accessLog === 'auto' || accessLog === '') {
    // auto: generate based on server name
    const logName = nameArr[0].replace(/[^a-zA-Z0-9.-]/g, '_');
    lines.push(`    access_log /var/log/nginx/${logName}.access.log combined_vhost if=$is_not_static;`);
    lines.push('');
  } else if (typeof accessLog === 'string' && accessLog && accessLog !== 'none' && accessLog !== 'false') {
    // custom path
    lines.push(`    access_log ${accessLog};`);
    lines.push('');
  }
  // else: omit access_log directive entirely

  // Server-level snippets
  const serverSnips = fmtSnippets(snippetsServer, '    ');
  if (serverSnips) { lines.push(serverSnips); lines.push(''); }

  // Extra server conf
  if (extraServerConf && extraServerConf.trim()) {
    extraServerConf.trim().split('\n').forEach(l => lines.push('    ' + l));
    lines.push('');
  }

  // Docker resolver + backend var
  if (isDockerContainer && containerName) {
    const scheme = containerScheme || 'http';
    const cport  = containerPort  || '80';
    lines.push(`    set $backend ${scheme}://${containerName}:${cport};`);
    lines.push('    resolver 127.0.0.11 valid=30s;');
    lines.push('');
  }

  // client_max_body_size
  if (clientMaxBody && clientMaxBody.trim()) {
    lines.push(`    client_max_body_size ${clientMaxBody.trim()};`);
    lines.push('');
  }

  // Location block
  // For Docker containers: $backend already includes scheme (set above), so proxy_pass uses it directly
  const backendUrl = isDockerContainer ? '$backend' : (backend || 'http://127.0.0.1:8080');
  lines.push('    location / {');
  lines.push(`        proxy_pass ${backendUrl};`);
  lines.push(`        proxy_read_timeout ${timeout}s;`);
  lines.push('');

  const locSnips = fmtSnippets(snippetsLocation, '        ');
  if (locSnips) { lines.push(locSnips); lines.push(''); }

  if (extraLocationConf && extraLocationConf.trim()) {
    extraLocationConf.trim().split('\n').forEach(l => lines.push('        ' + l));
    lines.push('');
  }

  lines.push('    }');
  lines.push('}');

  return lines.join('\n');
}
// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  /** Certificate sources the operator can attach to a vhost. */
  router.get('/api/vhost/ssl-sources', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const sources = [];

    // 1. SSL snippets (ssl-*.conf)
    const sslSnippets = snippets.listSSLSnippets();
    for (const s of sslSnippets) {
      sources.push({ type: 'snippet', label: s.name, file: s.file, cert: s.sslCert || '' });
    }

    // 2. Manual certs in DIR_SSL — pair .cer/.crt with .key
    if (fs.existsSync(DIR_SSL)) {
      const sslFiles = fs.readdirSync(DIR_SSL);
      const certs = sslFiles.filter(f => /\.(cer|crt|pem)$/i.test(f));
      for (const cert of certs) {
        const base = cert.replace(/\.(cer|crt|pem)$/i, '');
        const keyFile = sslFiles.find(f => f === base + '.key' || f === base + '.pem.key');
        sources.push({
          type:     'manual',
          label:    base,
          certPath: `/ssl/${cert}`,
          keyPath:  keyFile ? `/ssl/${keyFile}` : '',
          hasPair:  !!keyFile,
        });
      }
    }

    // 3. Let's Encrypt live certs in DIR_CERTS/live/
    const lePath = path.join(DIR_CERTS, 'live');
    if (fs.existsSync(lePath)) {
      const domains = fs.readdirSync(lePath).filter(d => {
        if (d === 'README') return false;
        return safeStat(path.join(lePath, d))?.isDirectory();
      });
      for (const domain of domains) {
        sources.push({
          type:     'letsencrypt',
          label:    domain,
          certPath: `/etc/letsencrypt/live/${domain}/fullchain.pem`,
          keyPath:  `/etc/letsencrypt/live/${domain}/privkey.pem`,
          hasPair:  true,
        });
      }
    }

    return send(res, 200, { sources });
  });

  router.post('/api/vhost/generate', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    try {
      return send(res, 200, { config: generateVhostConfig(body) });
    } catch (e) {
      return httpLib.badRequest(res, e.message);
    }
  });
}

module.exports = { register, generateVhostConfig };
