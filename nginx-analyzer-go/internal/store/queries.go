package store

// HourlyMetric reproduit une ligne de hourlyMetrics().
type HourlyMetric struct {
	Hour     int64
	Ts       int64
	Requests int64
	Bytes    int64
	Errors   int64
}

// HourlyMetrics replique hourlyMetrics() : totaux horaires pour un vhost,
// avec les signaux structurels dont la baseline a besoin pour distinguer une
// audience d'un flood.
func (s *Store) HourlyMetrics(vhost string, fromMs, toMs int64) []HourlyMetric {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`
		SELECT (bucket / 3600) * 3600 AS hour,
		       SUM(requests) AS requests,
		       SUM(bytes)    AS bytes,
		       SUM(CASE WHEN status >= 4 THEN requests ELSE 0 END) AS errors
		FROM traffic
		WHERE grain = 'minute' AND vhost = ? AND bucket >= ? AND bucket < ?
		GROUP BY hour ORDER BY hour
	`, vhost, floorDiv1000(fromMs), floorDiv1000(toMs))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []HourlyMetric
	for rows.Next() {
		var h HourlyMetric
		if err := rows.Scan(&h.Hour, &h.Requests, &h.Bytes, &h.Errors); err != nil {
			continue
		}
		h.Ts = h.Hour * 1000
		out = append(out, h)
	}
	return out
}

// CountryStat reproduit une ligne de byCountry().
type CountryStat struct {
	Country  string
	Requests int64
	Bytes    int64
	Errors   int64
}

// ByCountry replique byCountry().
func (s *Store) ByCountry(fromMs, toMs int64, vhost string) []CountryStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	where := ""
	args := []any{floorDiv1000(fromMs), floorDiv1000(toMs)}
	if vhost != "" {
		where = "AND vhost = ?"
		args = append(args, vhost)
	}
	rows, err := s.db.Query(`
		SELECT country,
		       SUM(requests) AS requests,
		       SUM(bytes)    AS bytes,
		       SUM(CASE WHEN status >= 4 THEN requests ELSE 0 END) AS errors
		FROM traffic
		WHERE bucket >= ? AND bucket < ? `+where+`
		GROUP BY country ORDER BY requests DESC
	`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []CountryStat
	for rows.Next() {
		var c CountryStat
		var country *string
		if err := rows.Scan(&country, &c.Requests, &c.Bytes, &c.Errors); err != nil {
			continue
		}
		if country != nil {
			c.Country = *country
		}
		out = append(out, c)
	}
	return out
}

// VhostStat reproduit une ligne de byVhost().
type VhostStat struct {
	Vhost    string
	Requests int64
	Bytes    int64
	Errors   int64
}

// ByVhost replique byVhost().
func (s *Store) ByVhost(fromMs, toMs int64) []VhostStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`
		SELECT vhost,
		       SUM(requests) AS requests,
		       SUM(bytes)    AS bytes,
		       SUM(CASE WHEN status >= 4 THEN requests ELSE 0 END) AS errors
		FROM traffic
		WHERE bucket >= ? AND bucket < ?
		GROUP BY vhost ORDER BY requests DESC
	`, floorDiv1000(fromMs), floorDiv1000(toMs))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []VhostStat
	for rows.Next() {
		var v VhostStat
		if err := rows.Scan(&v.Vhost, &v.Requests, &v.Bytes, &v.Errors); err != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}

// BotCategoryStat reproduit une ligne de byBotCategory().
type BotCategoryStat struct {
	Category string
	Requests int64
}

// ByBotCategory replique byBotCategory() : repartition humain/bot sur une
// fenetre, avec les sous-categories de bots.
func (s *Store) ByBotCategory(fromMs, toMs int64, vhost string) []BotCategoryStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	where := ""
	args := []any{floorDiv1000(fromMs), floorDiv1000(toMs)}
	if vhost != "" {
		where = "AND vhost = ?"
		args = append(args, vhost)
	}
	rows, err := s.db.Query(`
		SELECT category, SUM(requests) AS requests
		FROM bot_traffic
		WHERE bucket >= ? AND bucket < ? `+where+`
		GROUP BY category ORDER BY requests DESC
	`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []BotCategoryStat
	for rows.Next() {
		var c BotCategoryStat
		if err := rows.Scan(&c.Category, &c.Requests); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}

// BotPivotRow reproduit une ligne pivotee par _pivotByCategory() : Key vaut le
// vhost ou le pays selon l'appelant (BotByVhost / BotByCountry).
type BotPivotRow struct {
	Key   string
	Human int64
	Bots  int64
	Total int64
}

type categoryRow struct {
	key      string
	category string
	requests int64
}

// pivotByCategory replique _pivotByCategory().
func pivotByCategory(rows []categoryRow) []BotPivotRow {
	byKey := make(map[string]*BotPivotRow)
	var order []string
	for _, r := range rows {
		e, ok := byKey[r.key]
		if !ok {
			e = &BotPivotRow{Key: r.key}
			byKey[r.key] = e
			order = append(order, r.key)
		}
		e.Total += r.requests
		if r.category == "human" {
			e.Human += r.requests
		} else {
			e.Bots += r.requests
		}
	}
	out := make([]BotPivotRow, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	// Tri decroissant par Total, comme le sort() JS ; tri stable pour
	// preserver un ordre deterministe en cas d'egalite.
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j-1].Total < out[j].Total {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

// BotByVhost replique botByVhost() : repartition humain/bot par vhost, les
// colonnes que la page Analyse ajoute a son tableau de vhosts existant.
func (s *Store) BotByVhost(fromMs, toMs int64) []BotPivotRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`
		SELECT vhost, category, SUM(requests) AS requests
		FROM bot_traffic WHERE bucket >= ? AND bucket < ?
		GROUP BY vhost, category
	`, floorDiv1000(fromMs), floorDiv1000(toMs))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var crows []categoryRow
	for rows.Next() {
		var c categoryRow
		if err := rows.Scan(&c.key, &c.category, &c.requests); err != nil {
			continue
		}
		crows = append(crows, c)
	}
	return pivotByCategory(crows)
}

// BotByCountry replique botByCountry() : meme forme que BotByVhost, par pays.
func (s *Store) BotByCountry(fromMs, toMs int64, vhost string) []BotPivotRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	where := ""
	args := []any{floorDiv1000(fromMs), floorDiv1000(toMs)}
	if vhost != "" {
		where = "AND vhost = ?"
		args = append(args, vhost)
	}
	rows, err := s.db.Query(`
		SELECT country, category, SUM(requests) AS requests
		FROM bot_traffic WHERE bucket >= ? AND bucket < ? `+where+`
		GROUP BY country, category
	`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var crows []categoryRow
	for rows.Next() {
		var c categoryRow
		var country *string
		if err := rows.Scan(&country, &c.category, &c.requests); err != nil {
			continue
		}
		if country != nil {
			c.key = *country
		}
		crows = append(crows, c)
	}
	return pivotByCategory(crows)
}

// SeriesPoint reproduit une ligne de series().
type SeriesPoint struct {
	Bucket   int64
	Ts       int64
	Requests int64
	Bytes    int64
	Errors   int64
}

// Series replique series() : serie temporelle a un grain donne, pour un graphe.
func (s *Store) Series(grain string, fromMs, toMs int64, vhost string) []SeriesPoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	where := ""
	args := []any{grain, floorDiv1000(fromMs), floorDiv1000(toMs)}
	if vhost != "" {
		where = "AND vhost = ?"
		args = append(args, vhost)
	}
	rows, err := s.db.Query(`
		SELECT bucket,
		       SUM(requests) AS requests,
		       SUM(bytes)    AS bytes,
		       SUM(CASE WHEN status >= 4 THEN requests ELSE 0 END) AS errors
		FROM traffic
		WHERE grain = ? AND bucket >= ? AND bucket < ? `+where+`
		GROUP BY bucket ORDER BY bucket
	`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []SeriesPoint
	for rows.Next() {
		var p SeriesPoint
		if err := rows.Scan(&p.Bucket, &p.Requests, &p.Bytes, &p.Errors); err != nil {
			continue
		}
		p.Ts = p.Bucket * 1000
		out = append(out, p)
	}
	return out
}
