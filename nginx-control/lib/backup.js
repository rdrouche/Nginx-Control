'use strict';
/**
 * ZIP archives of the configuration.
 *
 * The ZIP format is written by hand — store method, no compression — rather
 * than shelling out to `zip` or adding a dependency: the container image is
 * minimal and archives are small enough that compression buys little.
 *
 * `crc32` and the central directory are implemented to the spec so the result
 * opens in any standard tool, which matters when an operator has to recover a
 * configuration by hand.
 */

const fs   = require('fs');
const path = require('path');
const zlib = require('zlib');

const cfg  = require('./config');
const tree = require('./fs-tree');

const { safeStat, listTreeFiles, copyTree } = tree;
const {
  DIR_BACKUPS, BACKUP_KEEP,
  DIR_SITES, DIR_CONF, DIR_SNIPPETS, DIR_STREAMS, DIR_SSL, DIR_CERTS,
} = cfg;

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
}

function crc32(buf) {
  // Standard CRC-32 for ZIP
  const table = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[i] = c;
    }
    return t;
  })();
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function writeZip(outPath, entries) {
  // Minimal ZIP writer (stored, no compression — avoids zlib for simplicity)
  const localHeaders = [];
  let offset = 0;
  const parts = [];
  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.arcPath, 'utf8');
    // entry.content = pre-read buffer (e.g. symlink-resolved LE certs)
    // entry.path    = file path to read (normal case)
    const data = entry.content instanceof Buffer ? entry.content : fs.readFileSync(entry.path);
    const crc = crc32(data);
    const localHeader = Buffer.alloc(30 + nameBytes.length);
    localHeader.writeUInt32LE(0x04034b50, 0);  // local file header sig
    localHeader.writeUInt16LE(20, 4);           // version needed
    localHeader.writeUInt16LE(0, 6);            // flags
    localHeader.writeUInt16LE(0, 8);            // compression (stored)
    localHeader.writeUInt16LE(0, 10);           // mod time
    localHeader.writeUInt16LE(0, 12);           // mod date
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(data.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(nameBytes.length, 26);
    localHeader.writeUInt16LE(0, 28);
    nameBytes.copy(localHeader, 30);
    localHeaders.push({ nameBytes, data, crc, offset });
    offset += localHeader.length + data.length;
    parts.push(localHeader, data);
  }
  // Central directory
  const cdParts = [];
  let cdOffset = offset;
  for (const { nameBytes, data, crc, offset: loff } of localHeaders) {
    const cd = Buffer.alloc(46 + nameBytes.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 8); cd.writeUInt16LE(0, 10);
    cd.writeUInt16LE(0, 12); cd.writeUInt16LE(0, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20); cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBytes.length, 28);
    cd.writeUInt16LE(0, 30); cd.writeUInt16LE(0, 32); cd.writeUInt16LE(0, 34); cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38); cd.writeUInt32LE(loff, 42);
    nameBytes.copy(cd, 46);
    cdParts.push(cd);
  }
  const cdBuffer = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4); eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(localHeaders.length, 8);
  eocd.writeUInt16LE(localHeaders.length, 10);
  eocd.writeUInt32LE(cdBuffer.length, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  eocd.writeUInt16LE(0, 20);
  fs.writeFileSync(outPath, Buffer.concat([...parts, cdBuffer, eocd]));
}

function parseZip(data) {
  // Find EOCD
  let eocdPos = -1;
  for (let i = data.length - 22; i >= 0; i--) {
    if (data.readUInt32LE(i) === 0x06054b50) { eocdPos = i; break; }
  }
  if (eocdPos < 0) throw new Error('Invalid ZIP: EOCD not found');
  const cdCount  = data.readUInt16LE(eocdPos + 10);
  const cdSize   = data.readUInt32LE(eocdPos + 12);
  const cdOffset = data.readUInt32LE(eocdPos + 16);
  const entries = [];
  let pos = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (data.readUInt32LE(pos) !== 0x02014b50) break;
    const nameLen  = data.readUInt16LE(pos + 28);
    const extraLen = data.readUInt16LE(pos + 30);
    const commentLen = data.readUInt16LE(pos + 32);
    const arcPath  = data.slice(pos + 46, pos + 46 + nameLen).toString('utf8');
    const lhOffset = data.readUInt32LE(pos + 42);
    const lhNameLen  = data.readUInt16LE(lhOffset + 26);
    const lhExtraLen = data.readUInt16LE(lhOffset + 28);
    const dataStart  = lhOffset + 30 + lhNameLen + lhExtraLen;
    const dataSize   = data.readUInt32LE(pos + 24);
    const content = data.slice(dataStart, dataStart + dataSize);
    if (!arcPath.endsWith('/')) entries.push({ arcPath, content });
    pos += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

async function createBackupZip(label) {
  fs.mkdirSync(DIR_BACKUPS, { recursive: true });
  const ts = timestamp();
  const zipName = `${ts}${label ? '_' + label.replace(/[^a-zA-Z0-9-]/g, '') : ''}.zip`;
  const zipPath = path.join(DIR_BACKUPS, zipName);

  // Flat dirs (one level of files)
  const dirs = [
    { src: DIR_SITES,    arc: 'sites' },
    { src: DIR_CONF,     arc: 'conf' },
    { src: DIR_SNIPPETS, arc: 'snippets' },
    { src: DIR_STREAMS,  arc: 'streams' },
    { src: DIR_SSL,      arc: 'ssl' },
  ].filter(d => fs.existsSync(d.src));

  const archiveEntries = [];

  // Add flat config dirs
  for (const { src, arc } of dirs) {
    for (const f of fs.readdirSync(src)) {
      const fp = path.join(src, f);
      const stat = safeStat(fp);
      if (stat && stat.isFile()) archiveEntries.push({ path: fp, arcPath: `${arc}/${f}` });
    }
  }

  // Add Let's Encrypt live certs (walk live/<domain>/ subdirs)
  const letsEncryptLive = path.join(DIR_CERTS, 'live');
  if (fs.existsSync(letsEncryptLive)) {
    const domains = fs.readdirSync(letsEncryptLive).filter(d => d !== 'README');
    for (const domain of domains) {
      const domainDir = path.join(letsEncryptLive, domain);
      const stat = safeStat(domainDir);
      if (!stat || !stat.isDirectory()) continue;
      for (const f of fs.readdirSync(domainDir)) {
        const fp = path.join(domainDir, f);
        const fstat = safeStat(fp);
        // Include .pem files, follow symlinks via readFileSync (which resolves them)
        if (fstat && (fstat.isFile() || fstat.isSymbolicLink())) {
          try {
            const content = fs.readFileSync(fp); // follows symlinks
            archiveEntries.push({ path: null, content, arcPath: `certs/live/${domain}/${f}` });
          } catch { /* skip unreadable */ }
        }
      }
    }
  }

  writeZip(zipPath, archiveEntries);
  await rotateBackups();
  return { zipPath, zipName, ts, files: archiveEntries.length };
}

async function rotateBackups() {
  try {
    const files = fs.readdirSync(DIR_BACKUPS)
      .filter(f => f.endsWith('.zip'))
      .map(f => ({ name: f, mtime: safeStat(path.join(DIR_BACKUPS, f))?.mtimeMs || 0 }))
      .sort((a, b) => b.mtime - a.mtime);
    const toDelete = files.slice(BACKUP_KEEP);
    for (const f of toDelete) fs.unlinkSync(path.join(DIR_BACKUPS, f.name));
    if (toDelete.length) console.log(`[backup] Rotated ${toDelete.length} old backup(s)`);
  } catch(e) { console.warn('[backup] Rotate error:', e.message); }
}

function listBackups() {
  if (!fs.existsSync(DIR_BACKUPS)) return [];
  return fs.readdirSync(DIR_BACKUPS)
    .filter(f => f.endsWith('.zip'))
    .map(f => {
      const fp = path.join(DIR_BACKUPS, f);
      const stat = safeStat(fp);
      return { name: f, path: fp, size: stat?.size || 0, mtime: stat?.mtime.toISOString() };
    })
    .sort((a, b) => b.mtime.localeCompare(a.mtime));
}

async function restoreBackupZip(zipPath) {
  // Extract ZIP and overwrite active dirs
  const data = fs.readFileSync(zipPath);
  const files = parseZip(data);
  for (const { arcPath, content } of files) {
    const parts = arcPath.split('/');
    const section = parts[0], fname = parts.slice(1).join('/');
    const dirMap = { sites: DIR_SITES, conf: DIR_CONF, snippets: DIR_SNIPPETS, streams: DIR_STREAMS, ssl: DIR_SSL };
    const dst = dirMap[section];
    if (!dst || !fname) continue;
    fs.mkdirSync(dst, { recursive: true });
    fs.writeFileSync(path.join(dst, fname), content);
  }
  return { files: files.length };
}

function bufIndexOf(buf, needle) {
  for (let i = 0; i <= buf.length - needle.length; i++) {
    let found = true;
    for (let j = 0; j < needle.length; j++) { if (buf[i+j] !== needle[j]) { found = false; break; } }
    if (found) return i;
  }
  return -1;
}
module.exports = {
  timestamp, crc32, writeZip, parseZip, bufIndexOf,
  createBackupZip, rotateBackups, listBackups, restoreBackupZip,
};
