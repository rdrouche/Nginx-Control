package store

import "fmt"

// BlocklistHitInput reproduit l'argument de recordBlocklistHit().
type BlocklistHitInput struct {
	Ts     int64
	IP     string
	Vhost  string
	Method string
	URI    string
	Status int
}

// RecordBlocklistHit replique recordBlocklistHit() : meme raisonnement bas
// volume que RecordWaf(), insertion directe sans tampon.
func (s *Store) RecordBlocklistHit(e BlocklistHitInput) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		s.memBlockSeq++
		hit := BlocklistHit{ID: s.memBlockSeq, Ts: e.Ts, IP: e.IP, Vhost: e.Vhost, Method: e.Method, URI: e.URI, Status: e.Status}
		s.memBlocklist = append([]BlocklistHit{hit}, s.memBlocklist...)
		if len(s.memBlocklist) > 5000 {
			s.memBlocklist = s.memBlocklist[:5000]
		}
		return
	}
	_, err := s.db.Exec(`INSERT INTO blocklist_hits (ts, ip, vhost, method, uri, status) VALUES (?, ?, ?, ?, ?, ?)`,
		e.Ts, nullIfEmpty(e.IP), nullIfEmpty(e.Vhost), nullIfEmpty(e.Method), nullIfEmpty(e.URI), nullIfZero(e.Status))
	if err != nil {
		fmt.Printf("[store] erreur recordBlocklistHit: %v\n", err)
	}
}

// BlocklistTopIP reproduit une entree topIps de blocklistHitsSummary().
type BlocklistTopIP struct {
	IP    string
	Count int
}

// BlocklistHitsSummary reproduit blocklistHitsSummary() : total, IP
// distinctes, et les IP les plus actives sur une fenetre. `limit` borne la
// liste des IP en tete pour qu'un appelant qui croise chaque IP touchee avec
// son propre cache de sources (comme le fait nginx-dashboard pour "hits par
// blocklist") puisse aussi borner ce travail.
type BlocklistHitsSummary struct {
	TotalHits int
	UniqueIPs int
	TopIPs    []BlocklistTopIP
}

func (s *Store) BlocklistHitsSummary(fromMs, toMs int64, limit int) BlocklistHitsSummary {
	if limit == 0 {
		limit = 500
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		counts := make(map[string]*BlocklistTopIP)
		var order []string
		total := 0
		for _, r := range s.memBlocklist {
			if r.Ts < fromMs || r.Ts >= toMs {
				continue
			}
			total++
			if r.IP == "" {
				continue
			}
			c, ok := counts[r.IP]
			if !ok {
				c = &BlocklistTopIP{IP: r.IP}
				counts[r.IP] = c
				order = append(order, r.IP)
			}
			c.Count++
		}
		top := make([]BlocklistTopIP, 0, len(order))
		for _, ip := range order {
			top = append(top, *counts[ip])
		}
		for i := 1; i < len(top); i++ {
			j := i
			for j > 0 && top[j-1].Count < top[j].Count {
				top[j-1], top[j] = top[j], top[j-1]
				j--
			}
		}
		if len(top) > limit {
			top = top[:limit]
		}
		return BlocklistHitsSummary{TotalHits: total, UniqueIPs: len(counts), TopIPs: top}
	}
	where := "ts >= ? AND ts < ?"
	args := []any{fromMs, toMs}
	var totalHits, uniqueIPs int
	if err := s.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT ip) FROM blocklist_hits WHERE `+where, args...).
		Scan(&totalHits, &uniqueIPs); err != nil {
		return BlocklistHitsSummary{}
	}
	rows, err := s.db.Query(`SELECT ip, COUNT(*) as count FROM blocklist_hits WHERE `+where+
		` AND ip IS NOT NULL GROUP BY ip ORDER BY count DESC LIMIT ?`, append(append([]any{}, args...), limit)...)
	if err != nil {
		return BlocklistHitsSummary{TotalHits: totalHits, UniqueIPs: uniqueIPs}
	}
	defer rows.Close()
	var top []BlocklistTopIP
	for rows.Next() {
		var t BlocklistTopIP
		if err := rows.Scan(&t.IP, &t.Count); err != nil {
			continue
		}
		top = append(top, t)
	}
	return BlocklistHitsSummary{TotalHits: totalHits, UniqueIPs: uniqueIPs, TopIPs: top}
}

// BlocklistIPHistory reproduit la valeur de retour de blocklistHitsForIp().
type BlocklistIPHistory struct {
	IP        string
	Count     int
	FirstSeen *int64
	LastSeen  *int64
}

// BlocklistHitsForIp replique blocklistHitsForIp() : historique de blocage
// pour une IP donnee, pour la recherche d'IP.
func (s *Store) BlocklistHitsForIp(ip string, fromMs, toMs int64) BlocklistIPHistory {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		var first, last *int64
		count := 0
		for _, r := range s.memBlocklist {
			if r.IP != ip || r.Ts < fromMs || r.Ts >= toMs {
				continue
			}
			count++
			ts := r.Ts
			if first == nil || ts < *first {
				v := ts
				first = &v
			}
			if last == nil || ts > *last {
				v := ts
				last = &v
			}
		}
		return BlocklistIPHistory{IP: ip, Count: count, FirstSeen: first, LastSeen: last}
	}
	var count int
	var first, last *int64
	err := s.db.QueryRow(`SELECT COUNT(*), MIN(ts), MAX(ts) FROM blocklist_hits WHERE ip = ? AND ts >= ? AND ts < ?`,
		ip, fromMs, toMs).Scan(&count, &first, &last)
	if err != nil {
		return BlocklistIPHistory{IP: ip}
	}
	return BlocklistIPHistory{IP: ip, Count: count, FirstSeen: first, LastSeen: last}
}

// PurgeBlocklistHits replique purgeBlocklistHits() (correctif ANA-11).
func (s *Store) PurgeBlocklistHits(olderThanMs int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		before := len(s.memBlocklist)
		kept := s.memBlocklist[:0]
		for _, r := range s.memBlocklist {
			if r.Ts >= olderThanMs {
				kept = append(kept, r)
			}
		}
		s.memBlocklist = kept
		return before - len(s.memBlocklist)
	}
	res, err := s.db.Exec(`DELETE FROM blocklist_hits WHERE ts < ?`, olderThanMs)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// ClearBlocklistHits replique clearBlocklistHits().
func (s *Store) ClearBlocklistHits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		before := len(s.memBlocklist)
		s.memBlocklist = nil
		return before
	}
	res, err := s.db.Exec(`DELETE FROM blocklist_hits`)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}
