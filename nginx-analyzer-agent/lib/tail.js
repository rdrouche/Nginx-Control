'use strict';
/**
 * Log file tailing.
 *
 * Rotation is the whole difficulty. logrotate renames the file and nginx opens
 * a new one at the same path, so following a path naively either keeps reading
 * a renamed file forever or re-reads everything from the start. The inode is
 * what actually identifies a file: when it changes, the file was rotated and
 * reading restarts from offset zero.
 *
 * Truncation in place (`> file`) is the other case: same inode, smaller size.
 * Detected by comparing size to the last offset.
 *
 * Offsets are persisted so a restart resumes where it stopped instead of
 * re-ingesting a day of traffic — which would both waste time and corrupt the
 * volumetric baseline with duplicated counts.
 *
 * Polling rather than fs.watch: watch is unreliable across bind mounts and
 * container filesystems, and a one-second poll on a handful of files costs
 * nothing.
 */

const fs   = require('fs');
const path = require('path');

const parse = require('./parse');

// Fix (audit report, Basse/Analyzer, "tail.js"): an unterminated line (no
// trailing "\n" yet, or a genuinely corrupt file that never produces one)
// used to grow `partial` without any bound, one poll at a time, for as long
// as the file kept being appended to without a newline — an unbounded
// in-memory leak driven entirely by file content the analyzer does not
// control. Past this size, the held-back bytes are treated as unparseable
// (counted as dropped, not silently kept forever) and discarded. A real
// nginx log line (URI + UA + referer) is a few KB at most; this leaves a
// generous margin above any legitimate line.
const MAX_PARTIAL_BYTES = 64 * 1024;

// Fix (audit report, Basse/Analyzer, "tail.js"): used to detect a
// `copytruncate`-style rotation (same inode, file emptied and rewritten in
// place) that regrows PAST the previous offset before the next poll runs —
// `st.size < f.offset` never fires in that case, so the tailer keeps reading
// from the old byte offset into what is actually unrelated new content,
// silently misaligning every field for the rest of that file. A short
// signature of the file's first bytes is kept and re-checked every poll;
// a mismatch means the file's beginning changed under us even though its
// size alone did not prove it.
const HEAD_SIG_BYTES = 64;

class Tailer {
  /**
   * @param {object} opts
   * @param {string}   opts.dir        directory holding the log files
   * @param {RegExp}   opts.pattern    which files to follow
   * @param {object}   opts.store      persistence for offsets
   * @param {Function} opts.onEntry    called with each parsed entry
   * @param {number}   opts.pollMs
   * @param {number}   opts.maxChunk   bytes read per file per poll
   */
  constructor({ dir, pattern = /\.access\.log$/, store, onEntry,
                pollMs = 1000, maxChunk = 4 * 1024 * 1024,
                // The parsing strategy is injectable so this class can follow
                // any line-oriented log, not only nginx access logs. Rotation,
                // truncation, offsets and partial-line buffering — the parts
                // that took real effort to get right — stay in one place and
                // are reused as-is by every log type.
                detectFormat = parse.detectFormat,
                parseLine = parse.parseLine,
                vhostFromFilename = parse.vhostFromFilename }) {
    this.dir = dir;
    this.pattern = pattern;
    this.detectFormat = detectFormat;
    this.parseLine = parseLine;
    this.vhostFromFilename = vhostFromFilename;
    this.store = store;
    this.onEntry = onEntry || (() => {});
    this.pollMs = pollMs;
    this.maxChunk = maxChunk;
    this.files = new Map();     // path → { inode, offset, format, vhost, partial }
    this.timer = null;
    this.stats = { lines: 0, parsed: 0, dropped: 0, rotations: 0, files: 0 };
  }

  /** Log files currently present in the directory. */
  listFiles() {
    try {
      return fs.readdirSync(this.dir)
        .filter(n => this.pattern.test(n))
        .map(n => path.join(this.dir, n));
    } catch { return []; }
  }

  /**
   * Determine a file's format from its first lines. Done once per file: doing
   * it per line breaks as soon as a hostname looks like an IP address.
   */
  _detectFormat(file) {
    // Fix (audit report, Basse/Analyzer, "tail.js"): the file descriptor was
    // only closed on the success path — a throwing readSync (e.g. the file
    // vanishing between openSync and readSync, a rotation mid-call) left it
    // open forever. Every code path out of this function now goes through
    // the same close.
    let fd = -1;
    try {
      fd = fs.openSync(file, 'r');
      const buf = Buffer.alloc(8192);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      const lines = buf.slice(0, n).toString('utf8').split('\n').slice(0, 20);
      return this.detectFormat(lines);
    } catch {
      return 'combined';
    } finally {
      if (fd !== -1) { try { fs.closeSync(fd); } catch { /* deja ferme ou disparu */ } }
    }
  }

  /** First few bytes of a file, used to detect a copytruncate that regrows past the old offset (see HEAD_SIG_BYTES). */
  _headSignature(file) {
    let fd = -1;
    try {
      fd = fs.openSync(file, 'r');
      const buf = Buffer.alloc(HEAD_SIG_BYTES);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      return buf.slice(0, n).toString('latin1');
    } catch {
      return null;
    } finally {
      if (fd !== -1) { try { fs.closeSync(fd); } catch { /* deja ferme ou disparu */ } }
    }
  }

  /** Start following a file, resuming from a persisted offset when possible. */
  _open(file) {
    const st = fs.statSync(file);
    const saved = this.store?.getOffset(file);
    let offset = 0, format = null;

    if (saved && saved.inode === st.ino && saved.offset <= st.size) {
      offset = saved.offset;
      format = saved.format;
    } else if (!saved) {
      // A file seen for the first time starts at its end: ingesting an entire
      // historical log on first start would flood the detectors with events
      // that are hours old and skew every counter.
      offset = st.size;
    }

    const entry = {
      inode: st.ino,
      offset,
      format: format || this._detectFormat(file),
      vhost: this.vhostFromFilename(path.basename(file)),
      // Fix (audit report, Basse/Analyzer, "tail.js"): kept as a Buffer, not
      // a decoded string — see _read()'s comment on the UTF-8 splitting fix.
      partialBuf: Buffer.alloc(0),
      // Fix (audit report, Basse/Analyzer, "tail.js"): see HEAD_SIG_BYTES.
      headSig: this._headSignature(file),
      // Per-file counters, separate from the tailer-wide totals. A global
      // drop count cannot tell you *which* file is misconfigured when several
      // are followed at once; a per-file ratio can.
      lines: 0, parsed: 0, dropped: 0,
    };
    this.files.set(file, entry);
    this.store?.setOffset(file, entry.inode, entry.offset, entry.format);
    return entry;
  }

  /**
   * Parse and hand off whatever is left in `f.partialBuf` as a final,
   * best-effort line, then clear it. Used right before that leftover would
   * otherwise be discarded (rotation, truncation) — once we know no more
   * bytes are coming to complete it, holding it back any longer only loses
   * it for good.
   *
   * Fix (audit report, Basse/Analyzer, "tail.js"): a file's last line, when
   * it had not yet been terminated by a trailing "\n" at the moment logrotate
   * renamed it away, used to simply vanish — `partial` was reset to '' on
   * both the rotation and truncation branches with no attempt to use it
   * first.
   */
  _flushPartial(f) {
    if (!f.partialBuf.length) return;
    const line = f.partialBuf.toString('utf8').replace(/\r$/, '');
    f.partialBuf = Buffer.alloc(0);
    if (!line) return;
    this.stats.lines++;
    f.lines++;
    const entry = this.parseLine(line, f.format, f.vhost);
    if (!entry) { this.stats.dropped++; f.dropped++; return; }
    this.stats.parsed++;
    f.parsed++;
    try { this.onEntry(entry); } catch (e) { console.warn('[tail] onEntry:', e.message); }
  }

  /** Read whatever is new in one file. */
  _read(file) {
    let st;
    try { st = fs.statSync(file); } catch { this.files.delete(file); return; }

    let f = this.files.get(file);
    if (!f) f = this._open(file);

    // Rotation: a different inode means a different file at the same path.
    //
    // Fix (audit finding ANA-01): format used to be redetected RIGHT HERE,
    // synchronously, on a file that logrotate has just created — empty, by
    // construction. Sampling an empty file always falls through to
    // detectFormat()'s default ('combined'), so a `combined_vhost` log
    // rotated at 3am would be silently misread as plain `combined` from then
    // on: every subsequent line fails to parse, and both detection and the
    // volumetric baseline go blind until the process restarts. Format is now
    // left `null` ("pending") across a rotation and only actually detected
    // once a batch with real content arrives (see below) — an empty file
    // produces no lines to sample from, so there is nothing lost by waiting.
    // Fix (audit report, Basse/Analyzer, "tail.js"): a `copytruncate`-style
    // rotation that truncates AND regrows past the old offset between two
    // polls never satisfies `st.size < f.offset` below, so it used to go
    // completely undetected — the tailer kept reading from the stale byte
    // offset into unrelated new content. A cheap signature of the file's
    // first bytes catches this even when size alone can't: if what is
    // actually at the start of the file changed, this is not a continuation
    // of the same stream, regardless of what its current size says.
    let headChanged = false;
    if (st.ino === f.inode && f.headSig !== null && st.size > 0) {
      const nowSig = this._headSignature(file);
      if (nowSig !== null && nowSig !== f.headSig) headChanged = true;
    }

    if (st.ino !== f.inode) {
      // Fix (audit report, Basse/Analyzer, "tail.js"): flush before
      // discarding — see _flushPartial()'s comment.
      this._flushPartial(f);
      this.stats.rotations++;
      f.inode = st.ino;
      f.offset = 0;
      f.format = null;
      f.headSig = this._headSignature(file);
    } else if (st.size < f.offset || headChanged) {
      // Truncated in place (e.g. `copytruncate`), whether caught by a
      // smaller size or by the head-signature check above — same file, so
      // unlike a real rotation the format almost certainly hasn't changed;
      // no need to force redetection here (but if it was already pending
      // from an earlier rotation, it stays pending).
      this._flushPartial(f);
      this.stats.rotations++;
      f.offset = 0;
      f.headSig = this._headSignature(file);
    }

    if (st.size === f.offset) return;

    const length = Math.min(st.size - f.offset, this.maxChunk);
    const buf = Buffer.alloc(length);
    let read = 0;
    let fd = -1;
    try {
      fd = fs.openSync(file, 'r');
      read = fs.readSync(fd, buf, 0, length, f.offset);
    } catch {
      return;
    } finally {
      // Fix (audit report, Basse/Analyzer, "tail.js"): same fd-leak class as
      // _detectFormat() — close on every path out, not only the success one.
      if (fd !== -1) { try { fs.closeSync(fd); } catch { /* deja ferme ou disparu */ } }
    }
    if (read <= 0) return;

    // Fix (audit report, Basse/Analyzer, "tail.js"): the previous version
    // decoded each raw chunk to UTF-8 text BEFORE knowing where the last
    // complete line ended, so a chunk boundary that landed in the middle of
    // a multi-byte UTF-8 character (an accented name in a referer/UA, for
    // instance) decoded that character's leftover bytes as U+FFFD on this
    // chunk and produced a different, equally wrong result when the
    // remaining bytes were re-decoded on their own next poll — the
    // replacement was permanent, not just a display glitch. Splitting on the
    // raw bytes first and only decoding complete, newline-terminated spans
    // is safe because "\n" (0x0A) can never appear as part of a multi-byte
    // UTF-8 sequence (continuation and lead bytes are all >= 0x80).
    const combined = f.partialBuf.length ? Buffer.concat([f.partialBuf, buf.slice(0, read)]) : buf.slice(0, read);
    f.offset += read;
    const lastNL = combined.lastIndexOf(0x0a);
    if (lastNL === -1) {
      // No complete line yet at all in the combined buffer.
      f.partialBuf = combined;
    } else {
      f.partialBuf = combined.slice(lastNL + 1);
    }
    if (f.partialBuf.length > MAX_PARTIAL_BYTES) {
      // Fix (audit report, Basse/Analyzer, "tail.js"): see MAX_PARTIAL_BYTES.
      console.warn(`[tail] ${path.basename(file)} : ligne incomplete de plus de ${MAX_PARTIAL_BYTES} octets, abandonnee`);
      this.stats.dropped++;
      f.dropped++;
      f.partialBuf = Buffer.alloc(0);
    }
    if (lastNL === -1) {
      this.store?.setOffset(file, f.inode, f.offset, f.format);
      return;
    }
    const text = combined.slice(0, lastNL).toString('utf8');
    const lines = text.split('\n');

    // Fix (audit finding ANA-01, continued): redetect on the first batch
    // that actually contains a non-blank line, using THAT batch as the
    // sample — never on an empty read. Until then, format stays `null` and
    // every line in an all-blank batch is skipped below anyway
    // (`if (!line) continue`), so nothing is lost by waiting one more poll.
    if (f.format === null) {
      const sample = lines.filter(l => l.trim() !== '');
      if (sample.length > 0) f.format = this.detectFormat(sample);
    }

    for (const rawLine of lines) {
      if (f.format === null) break; // toujours aucun contenu a echantillonner ce tour-ci

      const line = rawLine.replace(/\r$/, '');
      if (!line) continue;
      this.stats.lines++;
      f.lines++;
      const entry = this.parseLine(line, f.format, f.vhost);
      if (!entry) { this.stats.dropped++; f.dropped++; continue; }
      this.stats.parsed++;
      f.parsed++;
      try { this.onEntry(entry); } catch (e) { console.warn('[tail] onEntry:', e.message); }
    }

    this.store?.setOffset(file, f.inode, f.offset, f.format);
  }

  /** One pass over every matching file. */
  poll() {
    const files = this.listFiles();
    this.stats.files = files.length;
    for (const file of files) {
      try { this._read(file); }
      catch (e) { console.warn(`[tail] ${path.basename(file)}: ${e.message}`); }
    }
    // Forget files that disappeared, so the map does not grow with rotations.
    for (const known of [...this.files.keys()])
      if (!files.includes(known)) this.files.delete(known);
  }

  start() {
    if (this.timer) return;
    this.poll();
    this.timer = setInterval(() => this.poll(), this.pollMs);
    this.timer.unref();
    console.log(`[tail] Following ${this.stats.files} file(s) in ${this.dir}`);
  }

  stop() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  status() {
    return {
      ...this.stats,
      following: [...this.files.entries()].map(([file, f]) => {
        // A file that has produced lines but almost nothing parsed is the
        // signature of a format mismatch — e.g. a WAF log left in
        // ModSecurity's native "serial" format when JSON is what this project
        // reads. Flagged here rather than only in raw counters, since a
        // silent drop of every single line is otherwise indistinguishable
        // from "this vhost simply has no events".
        const ratio = f.lines > 0 ? f.dropped / f.lines : 0;
        return {
          file: path.basename(file), vhost: f.vhost, format: f.format, offset: f.offset,
          lines: f.lines, parsed: f.parsed, dropped: f.dropped,
          suspectFormat: f.lines >= 5 && ratio > 0.8,
        };
      }),
    };
  }
}

module.exports = { Tailer };
