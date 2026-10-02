package store

import "fmt"

func statusClass(status int) int { return status / 100 }

func normCountry(country string) string {
	if country == "" {
		return "??"
	}
	return country
}

// Record replique record() : replie une requete dans son bucket minute.
func (s *Store) Record(e Entry, country string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := (e.Ts / 60_000) * 60
	key := bucketKey{
		bucket:  bucket,
		grain:   "minute",
		vhost:   e.Vhost,
		country: normCountry(country),
		status:  statusClass(e.Status),
		method:  e.Method,
	}
	cur, ok := s.memBuckets[key]
	if !ok {
		cur = &bucketVal{}
		s.memBuckets[key] = cur
	}
	cur.requests++
	cur.bytes += e.Bytes
}

// RecordBot replique recordBot() : meme bucketing, pour la repartition bot/humain.
func (s *Store) RecordBot(e Entry, category, country string) {
	if category == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := (e.Ts / 60_000) * 60
	key := botBucketKey{
		bucket:   bucket,
		grain:    "minute",
		vhost:    e.Vhost,
		category: category,
		country:  normCountry(country),
	}
	s.memBotBuckets[key]++
}

// pruneMemoryBuckets replique _pruneMemoryBuckets() : purge les buckets
// memoire plus vieux que la retention minute, pour ne pas fuir en l'absence
// de SQLite (correctif ANA-04).
func (s *Store) pruneMemoryBuckets(nowMs int64) int {
	cutoff := (nowMs - int64(s.retention.MinuteHours)*3600_000) / 1000
	n := 0
	for k := range s.memBuckets {
		if k.bucket < cutoff {
			delete(s.memBuckets, k)
			n++
		}
	}
	for k := range s.memBotBuckets {
		if k.bucket < cutoff {
			delete(s.memBotBuckets, k)
			n++
		}
	}
	return n
}

// Flush replique flush() : ecrit les buckets tamponnes sur disque.
func (s *Store) Flush() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

func (s *Store) flushLocked() int {
	if s.db == nil {
		s.pruneMemoryBuckets(nowMs())
		return 0
	}
	n := 0
	if len(s.memBuckets) > 0 {
		stmt, err := s.db.Prepare(`
			INSERT INTO traffic (bucket, grain, vhost, country, status, method, requests, bytes)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(bucket, grain, vhost, country, status, method)
			DO UPDATE SET requests = requests + excluded.requests,
			              bytes    = bytes    + excluded.bytes
		`)
		if err == nil {
			for k, v := range s.memBuckets {
				if _, err := stmt.Exec(k.bucket, k.grain, k.vhost, k.country, k.status, k.method, v.requests, v.bytes); err != nil {
					fmt.Printf("[store] erreur flush: %v\n", err)
					continue
				}
				n++
			}
			stmt.Close()
		} else {
			fmt.Printf("[store] erreur flush: %v\n", err)
		}
		s.memBuckets = make(map[bucketKey]*bucketVal)
	}
	if len(s.memBotBuckets) > 0 {
		stmt, err := s.db.Prepare(`
			INSERT INTO bot_traffic (bucket, grain, vhost, category, country, requests)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(bucket, grain, vhost, category, country)
			DO UPDATE SET requests = requests + excluded.requests
		`)
		if err == nil {
			for k, requests := range s.memBotBuckets {
				if _, err := stmt.Exec(k.bucket, k.grain, k.vhost, k.category, k.country, requests); err != nil {
					fmt.Printf("[store] erreur flush (bot): %v\n", err)
					continue
				}
				n++
			}
			stmt.Close()
		} else {
			fmt.Printf("[store] erreur flush (bot): %v\n", err)
		}
		s.memBotBuckets = make(map[botBucketKey]int64)
	}
	return n
}

// Rollup replique rollup() : promeut minute->heure->jour puis supprime ce qui
// a depasse sa retention. Promouvoir plutot que supprimer garde l'historique
// long terme a cout constant.
func (s *Store) Rollup(nowMsOpt ...int64) (rolled int, deleted int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, 0
	}
	now := nowMs()
	if len(nowMsOpt) > 0 {
		now = nowMsOpt[0]
	}
	sec := now / 1000
	minuteCutoff := sec - int64(s.retention.MinuteHours)*3600
	hourCutoff := sec - int64(s.retention.HourDays)*86400
	dayCutoff := sec - int64(s.retention.DayDays)*86400

	roll := func(fromGrain, toGrain string, span int64, cutoff int64) {
		res, err := s.db.Exec(fmt.Sprintf(`
			INSERT INTO traffic (bucket, grain, vhost, country, status, method, requests, bytes)
			SELECT (bucket / %d) * %d, '%s', vhost, country, status, method,
			       SUM(requests), SUM(bytes)
			FROM traffic WHERE grain = '%s' AND bucket < ?
			GROUP BY (bucket / %d), vhost, country, status, method
			ON CONFLICT(bucket, grain, vhost, country, status, method)
			DO UPDATE SET requests = requests + excluded.requests,
			              bytes    = bytes    + excluded.bytes
		`, span, span, toGrain, fromGrain, span), cutoff)
		if err == nil {
			if c, _ := res.RowsAffected(); c > 0 {
				rolled += int(c)
			}
		} else {
			fmt.Printf("[store] erreur rollup: %v\n", err)
		}
		d, err := s.db.Exec(`DELETE FROM traffic WHERE grain = ? AND bucket < ?`, fromGrain, cutoff)
		if err == nil {
			if c, _ := d.RowsAffected(); c > 0 {
				deleted += int(c)
			}
		} else {
			fmt.Printf("[store] erreur rollup: %v\n", err)
		}
	}
	rollBot := func(fromGrain, toGrain string, span int64, cutoff int64) {
		res, err := s.db.Exec(fmt.Sprintf(`
			INSERT INTO bot_traffic (bucket, grain, vhost, category, country, requests)
			SELECT (bucket / %d) * %d, '%s', vhost, category, country, SUM(requests)
			FROM bot_traffic WHERE grain = '%s' AND bucket < ?
			GROUP BY (bucket / %d), vhost, category, country
			ON CONFLICT(bucket, grain, vhost, category, country)
			DO UPDATE SET requests = requests + excluded.requests
		`, span, span, toGrain, fromGrain, span), cutoff)
		if err == nil {
			if c, _ := res.RowsAffected(); c > 0 {
				rolled += int(c)
			}
		} else {
			fmt.Printf("[store] erreur rollup (bot): %v\n", err)
		}
		d, err := s.db.Exec(`DELETE FROM bot_traffic WHERE grain = ? AND bucket < ?`, fromGrain, cutoff)
		if err == nil {
			if c, _ := d.RowsAffected(); c > 0 {
				deleted += int(c)
			}
		} else {
			fmt.Printf("[store] erreur rollup (bot): %v\n", err)
		}
	}

	roll("minute", "hour", 3600, minuteCutoff)
	roll("hour", "day", 86400, hourCutoff)
	if d, err := s.db.Exec(`DELETE FROM traffic WHERE grain = 'day' AND bucket < ?`, dayCutoff); err == nil {
		if c, _ := d.RowsAffected(); c > 0 {
			deleted += int(c)
		}
	}
	rollBot("minute", "hour", 3600, minuteCutoff)
	rollBot("hour", "day", 86400, hourCutoff)
	if d, err := s.db.Exec(`DELETE FROM bot_traffic WHERE grain = 'day' AND bucket < ?`, dayCutoff); err == nil {
		if c, _ := d.RowsAffected(); c > 0 {
			deleted += int(c)
		}
	}
	return rolled, deleted
}
