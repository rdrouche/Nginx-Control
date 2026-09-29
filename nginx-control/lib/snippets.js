'use strict';
/**
 * Snippet metadata.
 *
 * Snippets carry a small header describing what they do and where they belong:
 *
 *   # name: letsencrypt-webroot
 *   # description: ACME HTTP challenge location
 *   # emplacement: server
 *   # version: 1.0.0
 *
 * Foundation rather than a feature: the configuration browser lists them and
 * the vhost generator offers the SSL ones as certificate sources, and features
 * never import each other.
 */

const fs   = require('fs');
const path = require('path');

const cfg  = require('./config');
const { safeReadDir, safeReadFile, safeStat } = require('./fs-tree');

const { DIR_SNIPPETS } = cfg;

/**
 * Parse metadata from snippet header comments.
 * Supports:
 *   # name: xxx
 *   # description: xxx
 *   # emplacement: server,location
 * Retrocompatible: missing metadata = universal snippet (server+location)
 */
function parseSnippetMeta(content, filename) {
  const meta = {
    name:        filename.replace(/\.conf$/i, ''),
    description: '',
    emplacement: ['server', 'location'], // default: usable everywhere
    raw:         content,
  };

  const lines = content.split('\n').slice(0, 15); // only check header
  for (const line of lines) {
    const m = line.match(/^#\s*(name|description|emplacement)\s*:\s*(.+)$/i);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (key === 'name')        meta.name        = val;
    if (key === 'description') meta.description = val;
    if (key === 'emplacement') {
      meta.emplacement = val.split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
    }
  }

  // SSL snippets (ssl-*.conf) are always server-level only
  if (filename.startsWith('ssl-')) {
    meta.emplacement = ['server'];
    meta.isSSL = true;
    // Try to extract cert path from ssl_certificate directive
    const certMatch = content.match(/ssl_certificate\s+([^;]+);/);
    if (certMatch) meta.sslCert = certMatch[1].trim();
  }

  return meta;
}

/** List all snippets with their parsed metadata */
function listSnippetsWithMeta() {
  if (!fs.existsSync(DIR_SNIPPETS)) return [];
  return fs.readdirSync(DIR_SNIPPETS)
    .filter(f => f.endsWith('.conf'))
    .map(f => {
      const fp      = path.join(DIR_SNIPPETS, f);
      const content = safeReadFile(fp) || '';
      const meta    = parseSnippetMeta(content, f);
      return { file: f, path: fp, ...meta };
    })
    .sort((a, b) => a.file.localeCompare(b.file));
}

/** List SSL snippets specifically */
function listSSLSnippets() {
  return listSnippetsWithMeta().filter(s => s.isSSL || s.file.startsWith('ssl-'));
}

module.exports = { parseSnippetMeta, listSnippetsWithMeta, listSSLSnippets };
