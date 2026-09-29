'use strict';
/**
 * Aggregation and storage.
 *
 * Raw log lines are never kept: a busy server produces millions a day and the
 * analyzer would become the disk problem it is supposed to warn about. Traffic
 * is folded into per-minute buckets keyed by (vhost, country, status class,
 * method), which is enough to answer every question the dashboard asks.
 *
 * Retention is tiered — minutes for a day, hours for a month, days for a year.
 * Rolling up rather than deleting keeps long-term trends available at a fixed
 * cost, and the volumetric baseline needs weeks of history to mean anything.
 *
 * Uses node:sqlite, built into Node 22, so the agent stays dependency-free like
 * the dashboard. If it is unavailable the agent degrades to memory-only rather
 * than refusing to start: signature detection still works, only history is lost.
 */

const fs   = require('fs');
const path = require('path');
const cidr = require('./cidr');

const RETENTION = {
  minuteHours: 24,        // per-minute detail for a day
  hourDays:    30,        // hourly for a month
  dayDays:     365,       // daily for a year
};

class Store {
  constructor(dbPath, { retention = {} } = {}) {
    this.dbPath = dbPath;
    this.retention = { ...RETENTION, ...retention };
    this.db = null;
    this.memory = { buckets: new Map(), botBuckets: new Map(), alerts: [] };
    this._open();
  }

  _open() {
    try {
      fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
      const { DatabaseSync } = require('node:sqlite');
      this.db = new DatabaseSync(this.dbPath);
      this.db.exec(`
        PRAGMA journal_mode = WAL;

        CREATE TABLE IF NOT EXISTS traffic (
          bucket    INTEGER NOT NULL,   -- epoch seconds, truncated
          grain     TEXT    NOT NULL,   -- 'minute' | 'hour' | 'day'
          vhost     TEXT    NOT NULL,
          country   TEXT,
          status    INTEGER NOT NULL,   -- status class: 2, 3, 4, 5
          method    TEXT    NOT NULL,
          requests  INTEGER NOT NULL DEFAULT 0,
          bytes     INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (bucket, grain, vhost, country, status, method)
        );
        CREATE INDEX IF NOT EXISTS idx_traffic_bucket ON traffic(grain, bucket);

        -- Same tiering as traffic, kept as its own table rather than a wider
        -- primary key on traffic: country x status x method x bot-category
        -- would multiply row counts on a busy vhost for a breakdown that
        -- only ever needs vhost + category, not the other dimensions.
        CREATE TABLE IF NOT EXISTS bot_traffic (
          bucket    INTEGER NOT NULL,
          grain     TEXT    NOT NULL,
          vhost     TEXT    NOT NULL,
          category  TEXT    NOT NULL,   -- 'human' | 'good' | 'ai' | 'bad' | 'unknown'
          country   TEXT,               -- '??' when unresolved, same convention as traffic.country
          requests  INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (bucket, grain, vhost, category, country)
        );
        CREATE INDEX IF NOT EXISTS idx_bot_traffic_bucket ON bot_traffic(grain, bucket);

        CREATE TABLE IF NOT EXISTS alerts (
          id        INTEGER PRIMARY KEY AUTOINCREMENT,
          ts        INTEGER NOT NULL,
          type      TEXT    NOT NULL,
          severity  TEXT    NOT NULL,
          ip        TEXT,
          vhost     TEXT,
          summary   TEXT    NOT NULL,
          evidence  TEXT,
          acked     INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

        CREATE TABLE IF NOT EXISTS state (
          key   TEXT PRIMARY KEY,
          value TEXT
        );

        -- Addresses excluded from detection, per vhost.
        -- Scoped rather than global on purpose: a monitoring probe is expected
        -- on a status endpoint and suspicious anywhere else, and a blanket
        -- exemption would hide a real attack on another site.
        CREATE TABLE IF NOT EXISTS exceptions (
          id      INTEGER PRIMARY KEY AUTOINCREMENT,
          vhost   TEXT    NOT NULL,
          ip      TEXT    NOT NULL,
          reason  TEXT,
          created INTEGER NOT NULL,
          author  TEXT,
          UNIQUE (vhost, ip)
        );
        CREATE INDEX IF NOT EXISTS idx_exceptions_vhost ON exceptions(vhost);

        -- ModSecurity WAF events. Volume is far lower than access logs (one
        -- row per triggered rule, not per request), so raw storage with a
        -- retention purge is simple enough — no need for the tiered rollup
        -- traffic gets.
        CREATE TABLE IF NOT EXISTS waf_events (
          id       INTEGER PRIMARY KEY AUTOINCREMENT,
          ts       INTEGER NOT NULL,
          vhost    TEXT    NOT NULL,
          ip       TEXT,
          method   TEXT,
          uri      TEXT,
          status   INTEGER,
          blocked  INTEGER NOT NULL DEFAULT 0,
          severity TEXT,
          ruleIds  TEXT,
          messages TEXT,
          uniqueId TEXT,
          engine   TEXT,
          raw      TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_waf_ts    ON waf_events(ts);
        CREATE INDEX IF NOT EXISTS idx_waf_vhost ON waf_events(vhost, ts);

        -- Blocklist hits ("Method 1" dedicated global log — see
        -- nginx-dashboard's hit_logging config). One row per request that
        -- matched $blocklist_ip, across every vhost — vhost comes from the
        -- log line itself (there is one shared file, not one per vhost).
        CREATE TABLE IF NOT EXISTS blocklist_hits (
          id     INTEGER PRIMARY KEY AUTOINCREMENT,
          ts     INTEGER NOT NULL,
          ip     TEXT,
          vhost  TEXT,
          method TEXT,
          uri    TEXT,
          status INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_blocklist_hits_ts ON blocklist_hits(ts);
        CREATE INDEX IF NOT EXISTS idx_blocklist_hits_ip ON blocklist_hits(ip);

        -- Where each log file was last read, so a restart does not re-ingest.
        CREATE TABLE IF NOT EXISTS offsets (
          file   TEXT PRIMARY KEY,
          inode  INTEGER,
          offset INTEGER,
          format TEXT
        );
      `);
      // A database created before `engine`/`raw` existed on waf_events has
      // neither column. `CREATE TABLE IF NOT EXISTS` only runs for a table
      // that does not exist at all, so an upgrade path needs its own
      // migration; each ALTER is guarded since re-running it on an
      // already-migrated database must not be an error.
      for (const col of ['engine TEXT', 'raw TEXT']) {
        try { this.db.exec(`ALTER TABLE waf_events ADD COLUMN ${col}`); } catch { /* already present */ }
      }

      // bot_traffic gained a `country` column shortly after it was introduced,
      // and that column is part of its primary key. A plain
      // `ALTER TABLE ... ADD COLUMN` adds the column but CANNOT widen the
      // primary key — which broke flush() completely on any pre-existing
      // database: its `INSERT ... ON CONFLICT(bucket, grain, vhost, category,
      // country)` needs a unique index over exactly those five columns, the
      // migrated table only had one over four, and SQLite rejects the
      // statement outright ("ON CONFLICT clause does not match any PRIMARY KEY
      // or UNIQUE constraint"). Every bot write then failed, was swallowed by
      // flush()'s own try/catch, and the human/bot figures stayed frozen at
      // whatever they held before the upgrade — silently, and only on
      // databases that already existed, never on the fresh ones used in tests.
      //
      // Changing a primary key in SQLite requires rebuilding the table, so
      // that is what happens here: create the correct shape, copy the rows
      // across (their country is unknown, hence the same '??' placeholder
      // used elsewhere), then swap. Guarded so it runs once and never on an
      // already-correct database.
      try {
        const cols = this.db.prepare(`PRAGMA table_info(bot_traffic)`).all();
        if (cols.length > 0) {
          const country = cols.find(c => c.name === 'country');
          const countryInKey = country && country.pk > 0;
          if (!countryInKey) {
            console.log('[store] Migration de bot_traffic : reconstruction pour inclure country dans la cle');
            this.db.exec('BEGIN');
            this.db.exec(`
              CREATE TABLE bot_traffic_migrated (
                bucket    INTEGER NOT NULL,
                grain     TEXT    NOT NULL,
                vhost     TEXT    NOT NULL,
                category  TEXT    NOT NULL,
                country   TEXT,
                requests  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (bucket, grain, vhost, category, country)
              );
            `);
            // Les lignes d avant la migration n ont pas de pays connu : on les
            // conserve (les totaux historiques restent justes) sous le meme
            // marqueur '??' que le reste du projet, et SUM() les regroupe
            // correctement si une meme cle existait deja des deux cotes.
            const src = country ? `COALESCE(country, '??')` : `'??'`;
            this.db.exec(`
              INSERT INTO bot_traffic_migrated (bucket, grain, vhost, category, country, requests)
              SELECT bucket, grain, vhost, category, ${src}, SUM(requests)
              FROM bot_traffic
              GROUP BY bucket, grain, vhost, category, ${src};
            `);
            this.db.exec('DROP TABLE bot_traffic');
            this.db.exec('ALTER TABLE bot_traffic_migrated RENAME TO bot_traffic');
            this.db.exec(`CREATE INDEX IF NOT EXISTS idx_bot_traffic_bucket ON bot_traffic(grain, bucket)`);
            this.db.exec('COMMIT');
            console.log('[store] Migration de bot_traffic terminee');
          }
        }
      } catch (e) {
        try { this.db.exec('ROLLBACK'); } catch { /* pas de transaction ouverte */ }
        console.warn('[store] Migration de bot_traffic echouee:', e.message);
      }

      console.log(`[store] SQLite ready: ${this.dbPath}`);
    } catch (e) {
      console.warn('[store] SQLite unavailable, running in memory only:', e.message);
      this.db = null;
    }
  }

  get persistent() { return this.db !== null; }

  // ─── Traffic ───────────────────────────────────────────────────────────────
  /** Fold one request into its minute bucket. */
  record(entry, country) {
    const bucket = Math.floor(entry.ts / 60_000) * 60;
    const key = [bucket, 'minute', entry.vhost, country || '??',
                 Math.floor(entry.status / 100), entry.method].join('\u0000');
    const cur = this.memory.buckets.get(key) || { requests: 0, bytes: 0 };
    cur.requests++;
    cur.bytes += entry.bytes || 0;
    this.memory.buckets.set(key, cur);
  }

  /**
   * Same bucketing as record(), for the bot/human breakdown. A separate call
   * rather than folding into record() itself: not every caller that records
   * traffic necessarily has a classified category on hand (or wants the
   * extra work done when it doesn't), and geoip-less deployments still
   * classify bots without needing a country resolved — `country` is
   * optional and falls back to '??', the same placeholder record() already
   * uses, so an unresolved address doesn't need special-casing downstream.
   */
  recordBot(entry, category, country) {
    if (!category) return;
    const bucket = Math.floor(entry.ts / 60_000) * 60;
    const key = [bucket, 'minute', entry.vhost, category, country || '??'].join('\u0000');
    const cur = this.memory.botBuckets.get(key) || 0;
    this.memory.botBuckets.set(key, cur + 1);
  }

  /**
   * Drop memory-mode traffic/bot buckets older than the minute-detail
   * retention window.
   *
   * Fix (audit finding ANA-04): without a database (node:sqlite missing, or
   * DB_PATH unwritable), record()/recordBot() fold every request into
   * this.memory.buckets / botBuckets forever — flush() below only writes to
   * disk and clears these maps when this.db is set, so in memory-only mode
   * it was a complete no-op and the maps grew without bound for the life of
   * the process. hourlyMetrics() and friends already return [] without a
   * db, so nothing ever reads a bucket once it falls out of the retention
   * window anyway; this just reclaims the memory instead of leaking it.
   */
  _pruneMemoryBuckets() {
    const cutoff = Math.floor((Date.now() - this.retention.minuteHours * 3600_000) / 1000);
    let n = 0;
    for (const key of this.memory.buckets.keys()) {
      const bucket = +key.slice(0, key.indexOf('\u0000'));
      if (bucket < cutoff) { this.memory.buckets.delete(key); n++; }
    }
    for (const key of this.memory.botBuckets.keys()) {
      const bucket = +key.slice(0, key.indexOf('\u0000'));
      if (bucket < cutoff) { this.memory.botBuckets.delete(key); n++; }
    }
    return n;
  }

  /** Write buffered buckets to disk. Called on a timer, not per request. */
  flush() {
    let n = 0;
    if (!this.db) { this._pruneMemoryBuckets(); return 0; }
    if (this.db && this.memory.buckets.size > 0) {
      const stmt = this.db.prepare(`
        INSERT INTO traffic (bucket, grain, vhost, country, status, method, requests, bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(bucket, grain, vhost, country, status, method)
        DO UPDATE SET requests = requests + excluded.requests,
                      bytes    = bytes    + excluded.bytes
      `);
      for (const [key, v] of this.memory.buckets) {
        const [bucket, grain, vhost, country, status, method] = key.split('\u0000');
        try {
          stmt.run(+bucket, grain, vhost, country, +status, method, v.requests, v.bytes);
          n++;
        } catch (e) { console.warn('[store] flush error:', e.message); }
      }
      this.memory.buckets.clear();
    }
    if (this.db && this.memory.botBuckets.size > 0) {
      const stmt = this.db.prepare(`
        INSERT INTO bot_traffic (bucket, grain, vhost, category, country, requests)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(bucket, grain, vhost, category, country)
        DO UPDATE SET requests = requests + excluded.requests
      `);
      for (const [key, requests] of this.memory.botBuckets) {
        const [bucket, grain, vhost, category, country] = key.split('\u0000');
        try { stmt.run(+bucket, grain, vhost, category, country, requests); n++; }
        catch (e) { console.warn('[store] flush (bot) error:', e.message); }
      }
      this.memory.botBuckets.clear();
    }
    return n;
  }

  /**
   * Hourly totals for a vhost, with the structural signals the baseline needs
   * to tell an audience apart from a flood.
   */
  hourlyMetrics(vhost, fromMs, toMs) {
    if (!this.db) return [];
    const rows = this.db.prepare(`
      SELECT (bucket / 3600) * 3600 AS hour,
             SUM(requests) AS requests,
             SUM(bytes)    AS bytes,
             SUM(CASE WHEN status >= 4 THEN requests ELSE 0 END) AS errors
      FROM traffic
      WHERE grain = 'minute' AND vhost = ? AND bucket >= ? AND bucket < ?
      GROUP BY hour ORDER BY hour
    `).all(vhost, Math.floor(fromMs / 1000), Math.floor(toMs / 1000));
    return rows.map(r => ({ ...r, ts: r.hour * 1000 }));
  }

  /** Traffic grouped by country over a window. */
  byCountry(fromMs, toMs, vhost = null) {
    if (!this.db) return [];
    const where = vhost ? 'AND vhost = ?' : '';
    const params = [Math.floor(fromMs / 1000), Math.floor(toMs / 1000)];
    if (vhost) params.push(vhost);
    return this.db.prepare(`
      SELECT country,
             SUM(requests) AS requests,
             SUM(bytes)    AS bytes,
             SUM(CASE WHEN status >= 4 THEN requests ELSE 0 END) AS errors
      FROM traffic
      WHERE bucket >= ? AND bucket < ? ${where}
      GROUP BY country ORDER BY requests DESC
    `).all(...params);
  }

  /** Traffic grouped by vhost over a window. */
  byVhost(fromMs, toMs) {
    if (!this.db) return [];
    return this.db.prepare(`
      SELECT vhost,
             SUM(requests) AS requests,
             SUM(bytes)    AS bytes,
             SUM(CASE WHEN status >= 4 THEN requests ELSE 0 END) AS errors
      FROM traffic
      WHERE bucket >= ? AND bucket < ?
      GROUP BY vhost ORDER BY requests DESC
    `).all(Math.floor(fromMs / 1000), Math.floor(toMs / 1000));
  }

  /**
   * Human vs bot breakdown over a window, and the bot sub-categories within
   * it — the detail behind a hover on the Analyse page, not a second query.
   */
  byBotCategory(fromMs, toMs, vhost = null) {
    if (!this.db) return [];
    const where = vhost ? 'AND vhost = ?' : '';
    const params = [Math.floor(fromMs / 1000), Math.floor(toMs / 1000)];
    if (vhost) params.push(vhost);
    return this.db.prepare(`
      SELECT category, SUM(requests) AS requests
      FROM bot_traffic
      WHERE bucket >= ? AND bucket < ? ${where}
      GROUP BY category ORDER BY requests DESC
    `).all(...params);
  }

  /**
   * Human vs bot split per vhost — the extra columns the Analyse page's own
   * vhost table adds alongside its existing request/traffic/error figures.
   */
  botByVhost(fromMs, toMs) {
    if (!this.db) return [];
    const rows = this.db.prepare(`
      SELECT vhost, category, SUM(requests) AS requests
      FROM bot_traffic WHERE bucket >= ? AND bucket < ?
      GROUP BY vhost, category
    `).all(Math.floor(fromMs / 1000), Math.floor(toMs / 1000));
    return this._pivotByCategory(rows, 'vhost');
  }

  /** Human vs bot split per country, same shape as botByVhost(). */
  botByCountry(fromMs, toMs, vhost = null) {
    if (!this.db) return [];
    const where = vhost ? 'AND vhost = ?' : '';
    const params = [Math.floor(fromMs / 1000), Math.floor(toMs / 1000)];
    if (vhost) params.push(vhost);
    const rows = this.db.prepare(`
      SELECT country, category, SUM(requests) AS requests
      FROM bot_traffic WHERE bucket >= ? AND bucket < ? ${where}
      GROUP BY country, category
    `).all(...params);
    return this._pivotByCategory(rows, 'country');
  }

  /**
   * Turns [{key, category, requests}, ...] rows into one row per key with
   * human/bots totals — shared by botByVhost() and botByCountry() so the two
   * don't duplicate the same pivot logic for a table column that only needs
   * "how many were bots" rather than the full category breakdown a hover
   * tooltip shows.
   */
  _pivotByCategory(rows, keyField) {
    const byKey = new Map();
    for (const r of rows) {
      let entry = byKey.get(r[keyField]);
      if (!entry) { entry = { [keyField]: r[keyField], human: 0, bots: 0, total: 0 }; byKey.set(r[keyField], entry); }
      entry.total += r.requests;
      if (r.category === 'human') entry.human += r.requests;
      else entry.bots += r.requests;
    }
    return [...byKey.values()].sort((a, b) => b.total - a.total);
  }

  /** Time series at a given grain, for charting. */
  series(grain, fromMs, toMs, vhost = null) {
    if (!this.db) return [];
    const where = vhost ? 'AND vhost = ?' : '';
    const params = [grain, Math.floor(fromMs / 1000), Math.floor(toMs / 1000)];
    if (vhost) params.push(vhost);
    return this.db.prepare(`
      SELECT bucket,
             SUM(requests) AS requests,
             SUM(bytes)    AS bytes,
             SUM(CASE WHEN status >= 4 THEN requests ELSE 0 END) AS errors
      FROM traffic
      WHERE grain = ? AND bucket >= ? AND bucket < ? ${where}
      GROUP BY bucket ORDER BY bucket
    `).all(...params).map(r => ({ ...r, ts: r.bucket * 1000 }));
  }

  // ─── Retention ─────────────────────────────────────────────────────────────
  /**
   * Roll minutes into hours and hours into days, then drop what has aged out.
   * Aggregating rather than deleting keeps long-term trends at a fixed cost.
   */
  rollup(now = Date.now()) {
    if (!this.db) return { rolled: 0, deleted: 0 };
    const sec = Math.floor(now / 1000);
    const minuteCutoff = sec - this.retention.minuteHours * 3600;
    const hourCutoff   = sec - this.retention.hourDays * 86400;
    const dayCutoff    = sec - this.retention.dayDays * 86400;
    let rolled = 0, deleted = 0;

    const roll = (fromGrain, toGrain, span, cutoff) => {
      const r = this.db.prepare(`
        INSERT INTO traffic (bucket, grain, vhost, country, status, method, requests, bytes)
        SELECT (bucket / ${span}) * ${span}, '${toGrain}', vhost, country, status, method,
               SUM(requests), SUM(bytes)
        FROM traffic WHERE grain = '${fromGrain}' AND bucket < ?
        GROUP BY (bucket / ${span}), vhost, country, status, method
        ON CONFLICT(bucket, grain, vhost, country, status, method)
        DO UPDATE SET requests = requests + excluded.requests,
                      bytes    = bytes    + excluded.bytes
      `).run(cutoff);
      rolled += r.changes || 0;
      const d = this.db.prepare(`DELETE FROM traffic WHERE grain = ? AND bucket < ?`)
        .run(fromGrain, cutoff);
      deleted += d.changes || 0;
    };

    // Same shape as roll() above, for bot_traffic's narrower key (no
    // country/status/method to group by).
    const rollBot = (fromGrain, toGrain, span, cutoff) => {
      const r = this.db.prepare(`
        INSERT INTO bot_traffic (bucket, grain, vhost, category, country, requests)
        SELECT (bucket / ${span}) * ${span}, '${toGrain}', vhost, category, country, SUM(requests)
        FROM bot_traffic WHERE grain = '${fromGrain}' AND bucket < ?
        GROUP BY (bucket / ${span}), vhost, category, country
        ON CONFLICT(bucket, grain, vhost, category, country)
        DO UPDATE SET requests = requests + excluded.requests
      `).run(cutoff);
      rolled += r.changes || 0;
      const d = this.db.prepare(`DELETE FROM bot_traffic WHERE grain = ? AND bucket < ?`)
        .run(fromGrain, cutoff);
      deleted += d.changes || 0;
    };

    try {
      roll('minute', 'hour', 3600, minuteCutoff);
      roll('hour', 'day', 86400, hourCutoff);
      deleted += (this.db.prepare(`DELETE FROM traffic WHERE grain = 'day' AND bucket < ?`)
        .run(dayCutoff).changes || 0);
      rollBot('minute', 'hour', 3600, minuteCutoff);
      rollBot('hour', 'day', 86400, hourCutoff);
      deleted += (this.db.prepare(`DELETE FROM bot_traffic WHERE grain = 'day' AND bucket < ?`)
        .run(dayCutoff).changes || 0);
    } catch (e) {
      console.warn('[store] rollup error:', e.message);
    }
    return { rolled, deleted };
  }

  // ─── Alerts ────────────────────────────────────────────────────────────────
  addAlert(alert) {
    const row = {
      ts: Date.now(),
      type: alert.type,
      severity: alert.severity || 'medium',
      ip: alert.evidence?.ip || alert.ip || null,
      vhost: alert.vhost || alert.evidence?.vhost || null,
      summary: alert.summary,
      evidence: JSON.stringify(alert.evidence || {}),
    };
    if (!this.db) {
      // Fix (companion to ANA-08): Date.now() is not a safe id — two alerts
      // firing in the same millisecond (plausible under a real flood, which
      // is exactly when several rules tend to fire together) would collide,
      // breaking a cursor based on "id > sinceId". A per-store monotonic
      // counter guarantees a strictly increasing id regardless of timing.
      this._memAlertSeq = (this._memAlertSeq || 0) + 1;
      this.memory.alerts.unshift({ id: this._memAlertSeq, ...row, evidence: alert.evidence });
      if (this.memory.alerts.length > 200) this.memory.alerts.pop();
      return row;
    }
    try {
      this.db.prepare(`INSERT INTO alerts (ts, type, severity, ip, vhost, summary, evidence)
                       VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(row.ts, row.type, row.severity, row.ip, row.vhost, row.summary, row.evidence);
    } catch (e) { console.warn('[store] addAlert error:', e.message); }
    return row;
  }

  /**
   * `sinceId` and `order` (fix, audit finding ANA-08): the dashboard's
   * catch-up poll used to ask for `ORDER BY ts DESC LIMIT 50` and jump its
   * cursor straight to the newest alert returned — fine while the backlog
   * fit in 50, but past that, every alert older than the newest 50 was
   * silently skipped and the cursor's jump to the newest ts made sure they
   * would never be asked for again. `ts` is also not a safe pagination key
   * on its own (two alerts can share a millisecond). `sinceId` (an
   * alert's own strictly increasing id, memory-mode or SQLite) plus
   * `order: 'asc'` lets a caller page through the ENTIRE backlog from
   * oldest to newest, one page at a time, never skipping a page's worth
   * regardless of how large the backlog has grown.
   */
  listAlerts({ limit = 100, offset = 0, type = null, severity = null, since = null,
               sinceId = null, order = 'desc', acked = null } = {}) {
    if (!this.db) {
      let rows = this.memory.alerts;
      if (type)      rows = rows.filter(a => a.type === type);
      if (severity)  rows = rows.filter(a => a.severity === severity);
      if (since)     rows = rows.filter(a => a.ts >= since);
      if (sinceId)   rows = rows.filter(a => a.id > sinceId);
      if (acked === false) rows = rows.filter(a => !a.acked);
      if (acked === true)  rows = rows.filter(a => !!a.acked);
      // this.memory.alerts is stored newest-first (unshift in addAlert()).
      if (order === 'asc') rows = [...rows].reverse();
      return { alerts: rows.slice(offset, offset + limit), total: rows.length, fromDb: false };
    }
    let where = '1=1'; const params = [];
    if (type)     { where += ' AND type = ?';     params.push(type); }
    if (severity) { where += ' AND severity = ?'; params.push(severity); }
    if (since)    { where += ' AND ts >= ?';      params.push(since); }
    if (sinceId)  { where += ' AND id > ?';       params.push(sinceId); }
    if (acked === false) where += ' AND acked = 0';
    if (acked === true)  where += ' AND acked = 1';
    const total = this.db.prepare(`SELECT COUNT(*) n FROM alerts WHERE ${where}`).get(...params).n;
    const dir = order === 'asc' ? 'ASC' : 'DESC';
    const rows = this.db.prepare(
      `SELECT * FROM alerts WHERE ${where} ORDER BY id ${dir} LIMIT ? OFFSET ?`
    ).all(...params, limit, offset);
    return {
      alerts: rows.map(r => ({ ...r, evidence: safeParse(r.evidence), acked: !!r.acked })),
      total, fromDb: true,
    };
  }

  ackAlert(id) {
    if (!this.db) return false;
    try { return (this.db.prepare('UPDATE alerts SET acked = 1 WHERE id = ?').run(id).changes || 0) > 0; }
    catch { return false; }
  }

  /**
   * Acknowledge every alert matching the filters at once. Defaults to only
   * the currently unacked ones, so calling it twice in a row is harmless.
   */
  ackAllAlerts({ type = null, severity = null, vhost = null, onlyUnacked = true } = {}) {
    if (!this.db) {
      let n = 0;
      for (const a of this.memory.alerts) {
        if (onlyUnacked && a.acked) continue;
        if (type && a.type !== type) continue;
        if (severity && a.severity !== severity) continue;
        if (vhost && a.vhost !== vhost) continue;
        a.acked = true; n++;
      }
      return { updated: n };
    }
    let where = '1=1'; const params = [];
    if (onlyUnacked) where += ' AND acked = 0';
    if (type)     { where += ' AND type = ?';     params.push(type); }
    if (severity) { where += ' AND severity = ?'; params.push(severity); }
    if (vhost)    { where += ' AND vhost = ?';    params.push(vhost); }
    try {
      const r = this.db.prepare(`UPDATE alerts SET acked = 1 WHERE ${where}`).run(...params);
      return { updated: r.changes || 0 };
    } catch (e) { return { updated: 0, error: e.message }; }
  }

  /**
   * Delete every alert matching the filters. With no filter at all, this
   * wipes the table — a deliberate "clear everything" the caller must ask
   * for explicitly, not a default.
   */
  clearAlerts({ type = null, severity = null, vhost = null } = {}) {
    if (!this.db) {
      const before = this.memory.alerts.length;
      this.memory.alerts = this.memory.alerts.filter(a =>
        (type && a.type !== type) || (severity && a.severity !== severity) || (vhost && a.vhost !== vhost));
      return { deleted: before - this.memory.alerts.length };
    }
    let where = '1=1'; const params = [];
    if (type)     { where += ' AND type = ?';     params.push(type); }
    if (severity) { where += ' AND severity = ?'; params.push(severity); }
    if (vhost)    { where += ' AND vhost = ?';    params.push(vhost); }
    try {
      const r = this.db.prepare(`DELETE FROM alerts WHERE ${where}`).run(...params);
      return { deleted: r.changes || 0 };
    } catch (e) { return { deleted: 0, error: e.message }; }
  }

  purgeAlerts(olderThanMs) {
    // Fix (audit finding ANA-11): this used to unconditionally wipe every
    // in-memory alert regardless of olderThanMs, so the hourly retention
    // sweep (server.js) silently deleted alerts from the last minute along
    // with anything actually old, in any deployment without node:sqlite.
    if (!this.db) {
      const before = this.memory.alerts.length;
      this.memory.alerts = this.memory.alerts.filter(a => a.ts >= olderThanMs);
      return before - this.memory.alerts.length;
    }
    try { return this.db.prepare('DELETE FROM alerts WHERE ts < ?').run(olderThanMs).changes || 0; }
    catch { return 0; }
  }

  // ─── Exceptions ────────────────────────────────────────────────────────────
  listExceptions(vhost = null) {
    if (!this.db) return this.memory.exceptions || [];
    try {
      return vhost
        ? this.db.prepare('SELECT * FROM exceptions WHERE vhost = ? ORDER BY created DESC').all(vhost)
        : this.db.prepare('SELECT * FROM exceptions ORDER BY vhost, created DESC').all();
    } catch { return []; }
  }

  addException({ vhost, ip, reason = '', author = '' }) {
    if (!vhost || !ip) return { ok: false, error: 'vhost and ip required' };
    // A pattern that cannot be parsed as an address or a CIDR block would
    // silently match nothing forever — reject it now, with a clear reason,
    // rather than accepting an exception that never actually excludes.
    if (!cidr.isValidPattern(ip)) {
      return { ok: false, error: `"${ip}" n est ni une adresse IP valide ni un bloc CIDR (ex: 203.0.113.0/24)` };
    }
    if (!this.db) {
      this.memory.exceptions = this.memory.exceptions || [];
      this.memory.exceptions.push({ id: Date.now(), vhost, ip, reason, author, created: Date.now() });
      return { ok: true };
    }
    try {
      this.db.prepare(`INSERT INTO exceptions (vhost, ip, reason, created, author)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(vhost, ip) DO UPDATE SET reason = excluded.reason,
                                                            author = excluded.author`)
        .run(vhost, ip, reason, Date.now(), author);
      return { ok: true };
    } catch (e) { return { ok: false, error: e.message }; }
  }

  removeException(id) {
    if (!this.db) {
      this.memory.exceptions = (this.memory.exceptions || []).filter(e => e.id !== id);
      return true;
    }
    try { return (this.db.prepare('DELETE FROM exceptions WHERE id = ?').run(id).changes || 0) > 0; }
    catch { return false; }
  }

  // ─── WAF events ────────────────────────────────────────────────────────────
  /**
   * Record one WAF event. Inserted directly rather than buffered like
   * access-log traffic: a WAF only logs on a rule match, so volume is orders
   * of magnitude lower and batching would add complexity for no real gain.
   */
  recordWaf(e) {
    // SQLite bindings reject `undefined` outright (it must be `null`), and
    // the parser only guarantees these fields when every branch of a real
    // ModSecurity payload matches what it expects. A field it could not
    // determine — or a caller building an event by hand, as tests do — must
    // degrade to a null column, not fail the whole insert.
    const row = {
      ts: e.ts, vhost: e.vhost ?? null, ip: e.ip ?? null,
      method: e.method ?? null, uri: e.uri ?? null,
      status: e.status ?? null, blocked: e.blocked ? 1 : 0, severity: e.severity ?? null,
      ruleIds: JSON.stringify(e.ruleIds || []),
      messages: JSON.stringify(e.messages || []),
      uniqueId: e.uniqueId ?? null,
      engine: e.engine ?? null,
      raw: e.raw ?? null,
    };
    if (!this.db) {
      this.memory.waf = this.memory.waf || [];
      this.memory.waf.unshift({ id: Date.now() + Math.random(), ...row,
        ruleIds: e.ruleIds || [], messages: e.messages || [] });
      if (this.memory.waf.length > 500) this.memory.waf.pop();
      return;
    }
    try {
      this.db.prepare(`INSERT INTO waf_events
        (ts, vhost, ip, method, uri, status, blocked, severity, ruleIds, messages, uniqueId, engine, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(row.ts, row.vhost, row.ip, row.method, row.uri, row.status, row.blocked,
             row.severity, row.ruleIds, row.messages, row.uniqueId, row.engine, row.raw);
    } catch (e2) { console.warn('[store] recordWaf error:', e2.message); }
  }

  /** One full WAF event, including its raw original line, for a detail view. */
  getWafEvent(id) {
    if (!this.db) return (this.memory.waf || []).find(e => e.id === id) || null;
    try {
      const r = this.db.prepare('SELECT * FROM waf_events WHERE id = ?').get(id);
      if (!r) return null;
      return { ...r, blocked: !!r.blocked, ruleIds: safeParse(r.ruleIds) || [], messages: safeParse(r.messages) || [] };
    } catch { return null; }
  }

  listWaf({ limit = 100, offset = 0, vhost = null, severity = null, blocked = null, since = null } = {}) {
    if (!this.db) {
      let rows = this.memory.waf || [];
      if (vhost)              rows = rows.filter(r => r.vhost === vhost);
      if (severity)           rows = rows.filter(r => r.severity === severity);
      if (blocked !== null)   rows = rows.filter(r => !!r.blocked === blocked);
      if (since)               rows = rows.filter(r => r.ts >= since);
      return { events: rows.slice(offset, offset + limit), total: rows.length, fromDb: false };
    }
    let where = '1=1'; const params = [];
    if (vhost)            { where += ' AND vhost = ?';    params.push(vhost); }
    if (severity)         { where += ' AND severity = ?'; params.push(severity); }
    if (blocked !== null) { where += ' AND blocked = ?';  params.push(blocked ? 1 : 0); }
    if (since)            { where += ' AND ts >= ?';      params.push(since); }
    const total = this.db.prepare(`SELECT COUNT(*) n FROM waf_events WHERE ${where}`).get(...params).n;
    // `raw` is deliberately excluded here: a page of results should stay
    // light. The full line is fetched on demand, per event, via getWafEvent().
    const rows = this.db.prepare(
      `SELECT id, ts, vhost, ip, method, uri, status, blocked, severity, ruleIds, messages, uniqueId, engine
       FROM waf_events WHERE ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`
    ).all(...params, limit, offset);
    return {
      events: rows.map(r => ({ ...r, blocked: !!r.blocked,
        ruleIds: safeParse(r.ruleIds) || [], messages: safeParse(r.messages) || [] })),
      total, fromDb: true,
    };
  }

  /**
   * Rule IDs ranked by how often they fired. Tallied in JS from a bounded
   * fetch rather than a SQL aggregate, since a rule id list is stored as a
   * JSON array per row (one event can trigger several rules) — exploding
   * that in SQL would need a JSON extension this project does not depend on.
   */
  wafTopRules(fromMs, toMs, vhost = null, limit = 4000) {
    const rows = this._wafWindow(fromMs, toMs, vhost, limit);
    const counts = new Map();   // ruleId → { count, example }
    for (const r of rows) {
      const ids = this.db ? safeParse(r.ruleIds) || [] : r.ruleIds || [];
      const msgs = this.db ? safeParse(r.messages) || [] : r.messages || [];
      for (const id of ids) {
        const c = counts.get(id) || { ruleId: id, count: 0, example: null };
        c.count++;
        if (!c.example) c.example = msgs.find(m => m.ruleId === id)?.message || null;
        counts.set(id, c);
      }
    }
    return [...counts.values()].sort((a, b) => b.count - a.count).slice(0, 20);
  }

  /** Addresses ranked by how many WAF events they triggered. */
  wafTopIps(fromMs, toMs, vhost = null) {
    if (!this.db) {
      const rows = this._wafWindow(fromMs, toMs, vhost, 100000);
      const counts = new Map();
      for (const r of rows) {
        if (!r.ip) continue;
        const c = counts.get(r.ip) || { ip: r.ip, count: 0, blocked: 0 };
        c.count++; if (r.blocked) c.blocked++;
        counts.set(r.ip, c);
      }
      return [...counts.values()].sort((a, b) => b.count - a.count).slice(0, 20);
    }
    let where = 'ts >= ? AND ts < ? AND ip IS NOT NULL'; const params = [Math.floor(fromMs), Math.floor(toMs)];
    if (vhost) { where += ' AND vhost = ?'; params.push(vhost); }
    return this.db.prepare(`
      SELECT ip, COUNT(*) as count, SUM(blocked) as blocked
      FROM waf_events WHERE ${where} GROUP BY ip ORDER BY count DESC LIMIT 20
    `).all(...params);
  }

  /** Hourly counts, blocked vs detected, for a simple timeline. */
  wafSeries(fromMs, toMs, vhost = null) {
    if (!this.db) return [];
    let where = 'ts >= ? AND ts < ?'; const params = [Math.floor(fromMs), Math.floor(toMs)];
    if (vhost) { where += ' AND vhost = ?'; params.push(vhost); }
    return this.db.prepare(`
      SELECT (ts / 3600000) * 3600000 as hour, COUNT(*) as count, SUM(blocked) as blocked
      FROM waf_events WHERE ${where} GROUP BY hour ORDER BY hour
    `).all(...params).map(r => ({ ts: r.hour, count: r.count, blocked: r.blocked }));
  }

  /** Internal: bounded raw fetch used by the two "top" aggregations above. */
  _wafWindow(fromMs, toMs, vhost, limit) {
    if (!this.db) {
      let rows = this.memory.waf || [];
      rows = rows.filter(r => r.ts >= fromMs && r.ts < toMs);
      if (vhost) rows = rows.filter(r => r.vhost === vhost);
      return rows.slice(0, limit);
    }
    let where = 'ts >= ? AND ts < ?'; const params = [Math.floor(fromMs), Math.floor(toMs)];
    if (vhost) { where += ' AND vhost = ?'; params.push(vhost); }
    try {
      return this.db.prepare(
        `SELECT ruleIds, messages FROM waf_events WHERE ${where} ORDER BY ts DESC LIMIT ?`
      ).all(...params, limit);
    } catch { return []; }
  }

  purgeWaf(olderThanMs) {
    // Fix (audit finding ANA-11): same age-blind wipe as purgeAlerts() above.
    if (!this.db) {
      const before = (this.memory.waf || []).length;
      this.memory.waf = (this.memory.waf || []).filter(r => r.ts >= olderThanMs);
      return before - this.memory.waf.length;
    }
    try { return this.db.prepare('DELETE FROM waf_events WHERE ts < ?').run(olderThanMs).changes || 0; }
    catch { return 0; }
  }

  /**
   * Manual, filtered purge — distinct from purgeWaf()'s age-based retention.
   * With no filter at all, this clears every WAF event: a deliberate
   * "empty the table" the caller must ask for explicitly, mirroring
   * clearAlerts() for the alert log.
   */
  clearWaf({ vhost = null, severity = null, blocked = null } = {}) {
    if (!this.db) {
      const before = (this.memory.waf || []).length;
      this.memory.waf = (this.memory.waf || []).filter(r =>
        (vhost && r.vhost !== vhost) ||
        (severity && r.severity !== severity) ||
        (blocked !== null && !!r.blocked !== blocked));
      return { deleted: before - (this.memory.waf || []).length };
    }
    let where = '1=1'; const params = [];
    if (vhost)             { where += ' AND vhost = ?';    params.push(vhost); }
    if (severity)          { where += ' AND severity = ?'; params.push(severity); }
    if (blocked !== null)  { where += ' AND blocked = ?';  params.push(blocked ? 1 : 0); }
    try {
      const r = this.db.prepare(`DELETE FROM waf_events WHERE ${where}`).run(...params);
      return { deleted: r.changes || 0 };
    } catch (e) { return { deleted: 0, error: e.message }; }
  }

  wafStats() {
    if (!this.db) return { rows: (this.memory.waf || []).length, persistent: false };
    try { return { rows: this.db.prepare('SELECT COUNT(*) n FROM waf_events').get().n, persistent: true }; }
    catch { return { rows: 0, persistent: true, error: true }; }
  }

  // ─── Blocklist hits ────────────────────────────────────────────────────────
  /** Record one blocklist hit. Same low-volume reasoning as recordWaf(): inserted directly, no buffering. */
  recordBlocklistHit(e) {
    const row = {
      ts: e.ts, ip: e.ip ?? null, vhost: e.vhost ?? null,
      method: e.method ?? null, uri: e.uri ?? null, status: e.status ?? null,
    };
    if (!this.db) {
      this.memory.blocklistHits = this.memory.blocklistHits || [];
      this.memory.blocklistHits.unshift({ id: Date.now() + Math.random(), ...row });
      if (this.memory.blocklistHits.length > 5000) this.memory.blocklistHits.pop();
      return;
    }
    try {
      this.db.prepare(`INSERT INTO blocklist_hits (ts, ip, vhost, method, uri, status)
        VALUES (?, ?, ?, ?, ?, ?)`)
        .run(row.ts, row.ip, row.vhost, row.method, row.uri, row.status);
    } catch (e2) { console.warn('[store] recordBlocklistHit error:', e2.message); }
  }

  /**
   * Window summary for the Digest and effectiveness measurement: total hits,
   * distinct IPs, and the IPs that hit most — `limit` bounds the top-IP list
   * so a caller cross-referencing every hit IP against its own source cache
   * (as nginx-dashboard does for "hits per blocklist") can bound that work too.
   */
  blocklistHitsSummary(fromMs, toMs, limit = 500) {
    if (!this.db) {
      const rows = (this.memory.blocklistHits || []).filter(r => r.ts >= fromMs && r.ts < toMs);
      const counts = new Map();
      for (const r of rows) {
        if (!r.ip) continue;
        const c = counts.get(r.ip) || { ip: r.ip, count: 0 };
        c.count++; counts.set(r.ip, c);
      }
      const topIps = [...counts.values()].sort((a, b) => b.count - a.count).slice(0, limit);
      return { totalHits: rows.length, uniqueIps: counts.size, topIps };
    }
    const where = 'ts >= ? AND ts < ?'; const params = [Math.floor(fromMs), Math.floor(toMs)];
    try {
      const totals = this.db.prepare(
        `SELECT COUNT(*) totalHits, COUNT(DISTINCT ip) uniqueIps FROM blocklist_hits WHERE ${where}`
      ).get(...params);
      const topIps = this.db.prepare(
        `SELECT ip, COUNT(*) as count FROM blocklist_hits WHERE ${where} AND ip IS NOT NULL
         GROUP BY ip ORDER BY count DESC LIMIT ?`
      ).all(...params, limit);
      return { totalHits: totals.totalHits || 0, uniqueIps: totals.uniqueIps || 0, topIps };
    } catch { return { totalHits: 0, uniqueIps: 0, topIps: [] }; }
  }

  /** Hit history for one specific IP — how many times it was blocked and when, for the IP-search feature. */
  blocklistHitsForIp(ip, fromMs, toMs) {
    if (!this.db) {
      const rows = (this.memory.blocklistHits || []).filter(r => r.ip === ip && r.ts >= fromMs && r.ts < toMs);
      return { ip, count: rows.length,
        firstSeen: rows.length ? Math.min(...rows.map(r => r.ts)) : null,
        lastSeen:  rows.length ? Math.max(...rows.map(r => r.ts)) : null };
    }
    try {
      const r = this.db.prepare(
        `SELECT COUNT(*) count, MIN(ts) firstSeen, MAX(ts) lastSeen
         FROM blocklist_hits WHERE ip = ? AND ts >= ? AND ts < ?`
      ).get(ip, Math.floor(fromMs), Math.floor(toMs));
      return { ip, count: r.count || 0, firstSeen: r.firstSeen || null, lastSeen: r.lastSeen || null };
    } catch { return { ip, count: 0, firstSeen: null, lastSeen: null }; }
  }

  purgeBlocklistHits(olderThanMs) {
    // Fix (audit finding ANA-11): same age-blind wipe as purgeAlerts() above.
    if (!this.db) {
      const before = (this.memory.blocklistHits || []).length;
      this.memory.blocklistHits = (this.memory.blocklistHits || []).filter(r => r.ts >= olderThanMs);
      return before - this.memory.blocklistHits.length;
    }
    try { return this.db.prepare('DELETE FROM blocklist_hits WHERE ts < ?').run(olderThanMs).changes || 0; }
    catch { return 0; }
  }

  clearBlocklistHits() {
    if (!this.db) {
      const before = (this.memory.blocklistHits || []).length;
      this.memory.blocklistHits = [];
      return { deleted: before };
    }
    try { return { deleted: this.db.prepare('DELETE FROM blocklist_hits').run().changes || 0 }; }
    catch (e) { return { deleted: 0, error: e.message }; }
  }

  // ─── Key/value state ───────────────────────────────────────────────────────
  getState(key) {
    if (!this.db) return null;
    try { return safeParse(this.db.prepare('SELECT value FROM state WHERE key = ?').get(key)?.value); }
    catch { return null; }
  }

  setState(key, value) {
    if (!this.db) return;
    try {
      this.db.prepare(`INSERT INTO state (key, value) VALUES (?, ?)
                       ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
        .run(key, JSON.stringify(value));
    } catch (e) { console.warn('[store] setState error:', e.message); }
  }

  // ─── File offsets ──────────────────────────────────────────────────────────
  getOffset(file) {
    if (!this.db) return null;
    try { return this.db.prepare('SELECT * FROM offsets WHERE file = ?').get(file) || null; }
    catch { return null; }
  }

  setOffset(file, inode, offset, format) {
    if (!this.db) return;
    try {
      this.db.prepare(`INSERT INTO offsets (file, inode, offset, format) VALUES (?, ?, ?, ?)
                       ON CONFLICT(file) DO UPDATE SET inode = excluded.inode,
                                                       offset = excluded.offset,
                                                       format = excluded.format`)
        .run(file, inode, offset, format);
    } catch (e) { console.warn('[store] setOffset error:', e.message); }
  }

  stats() {
    if (!this.db) return { persistent: false, pending: this.memory.buckets.size + this.memory.botBuckets.size };
    try {
      const t = this.db.prepare('SELECT grain, COUNT(*) n FROM traffic GROUP BY grain').all();
      const a = this.db.prepare('SELECT COUNT(*) n FROM alerts').get().n;
      let size = 0;
      try { size = fs.statSync(this.dbPath).size; } catch {}
      return {
        persistent: true,
        pending: this.memory.buckets.size + this.memory.botBuckets.size,
        rows: Object.fromEntries(t.map(r => [r.grain, r.n])),
        alerts: a,
        dbBytes: size,
      };
    } catch { return { persistent: true, error: true }; }
  }

  close() { try { this.flush(); this.db?.close(); } catch {} }
}

const safeParse = s => { try { return JSON.parse(s); } catch { return s; } };

module.exports = { Store, RETENTION };
