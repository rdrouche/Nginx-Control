package store

import "encoding/json"

// AddAlert replique addAlert().
func (s *Store) AddAlert(a AlertInput) Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := nowMs()
	severity := a.Severity
	if severity == "" {
		severity = "medium"
	}
	ip := a.IP
	if ip == "" && a.Evidence != nil {
		if v, ok := a.Evidence["ip"].(string); ok {
			ip = v
		}
	}
	vhost := a.Vhost
	if vhost == "" && a.Evidence != nil {
		if v, ok := a.Evidence["vhost"].(string); ok {
			vhost = v
		}
	}
	row := Alert{
		Ts:       ts,
		Type:     a.Type,
		Severity: severity,
		IP:       ip,
		Vhost:    vhost,
		Summary:  a.Summary,
		Evidence: a.Evidence,
	}
	if s.db == nil {
		// Correctif (compagnon ANA-08) : Date.now() n'est pas un id sur ; deux
		// alertes dans la meme milliseconde (plausible lors d'un vrai flood,
		// justement quand plusieurs regles se declenchent ensemble) entreraient
		// en collision et casseraient un curseur base sur "id > sinceId". Un
		// compteur monotone par Store garantit un id strictement croissant.
		s.memAlertSeq++
		row.ID = s.memAlertSeq
		s.memAlerts = append([]Alert{row}, s.memAlerts...)
		if len(s.memAlerts) > 200 {
			s.memAlerts = s.memAlerts[:200]
		}
		return row
	}
	evidenceJSON, _ := json.Marshal(a.Evidence)
	res, err := s.db.Exec(`INSERT INTO alerts (ts, type, severity, ip, vhost, summary, evidence)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, row.Ts, row.Type, row.Severity, nullIfEmpty(row.IP), nullIfEmpty(row.Vhost), row.Summary, string(evidenceJSON))
	if err == nil {
		if id, e := res.LastInsertId(); e == nil {
			row.ID = id
		}
	}
	return row
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ListAlertsOptions reproduit l'objet d'options de listAlerts().
type ListAlertsOptions struct {
	Limit    int
	Offset   int
	Type     string
	Severity string
	Since    int64  // 0 = non filtre
	SinceID  int64  // 0 = non filtre
	Order    string // "asc" | "desc" (defaut)
	Acked    *bool  // nil = non filtre
}

// ListAlertsResult reproduit la valeur de retour de listAlerts().
type ListAlertsResult struct {
	Alerts []Alert
	Total  int
	FromDB bool
}

// ListAlerts replique listAlerts(), y compris la pagination par sinceId/order
// (correctif ANA-08) qui permet de parcourir tout l'historique sans jamais
// sauter une page, contrairement a un curseur base sur ORDER BY ts DESC.
func (s *Store) ListAlerts(o ListAlertsOptions) ListAlertsResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := o.Limit
	if limit == 0 {
		limit = 100
	}
	if s.db == nil {
		rows := make([]Alert, len(s.memAlerts))
		copy(rows, s.memAlerts)
		filtered := rows[:0]
		for _, a := range rows {
			if o.Type != "" && a.Type != o.Type {
				continue
			}
			if o.Severity != "" && a.Severity != o.Severity {
				continue
			}
			if o.Since != 0 && a.Ts < o.Since {
				continue
			}
			if o.SinceID != 0 && a.ID <= o.SinceID {
				continue
			}
			if o.Acked != nil {
				if *o.Acked && !a.Acked {
					continue
				}
				if !*o.Acked && a.Acked {
					continue
				}
			}
			filtered = append(filtered, a)
		}
		// s.memAlerts est stocke le plus recent en premier (unshift dans AddAlert).
		if o.Order == "asc" {
			for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
				filtered[i], filtered[j] = filtered[j], filtered[i]
			}
		}
		total := len(filtered)
		end := o.Offset + limit
		if o.Offset > total {
			o.Offset = total
		}
		if end > total {
			end = total
		}
		return ListAlertsResult{Alerts: filtered[o.Offset:end], Total: total, FromDB: false}
	}

	where := "1=1"
	var args []any
	if o.Type != "" {
		where += " AND type = ?"
		args = append(args, o.Type)
	}
	if o.Severity != "" {
		where += " AND severity = ?"
		args = append(args, o.Severity)
	}
	if o.Since != 0 {
		where += " AND ts >= ?"
		args = append(args, o.Since)
	}
	if o.SinceID != 0 {
		where += " AND id > ?"
		args = append(args, o.SinceID)
	}
	if o.Acked != nil {
		if *o.Acked {
			where += " AND acked = 1"
		} else {
			where += " AND acked = 0"
		}
	}
	var total int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE `+where, args...).Scan(&total)
	dir := "DESC"
	if o.Order == "asc" {
		dir = "ASC"
	}
	q := `SELECT id, ts, type, severity, ip, vhost, summary, evidence, acked FROM alerts WHERE ` + where +
		` ORDER BY id ` + dir + ` LIMIT ? OFFSET ?`
	rows, err := s.db.Query(q, append(append([]any{}, args...), limit, o.Offset)...)
	if err != nil {
		return ListAlertsResult{FromDB: true}
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var ip, vhost, evidence *string
		var acked int
		if err := rows.Scan(&a.ID, &a.Ts, &a.Type, &a.Severity, &ip, &vhost, &a.Summary, &evidence, &acked); err != nil {
			continue
		}
		if ip != nil {
			a.IP = *ip
		}
		if vhost != nil {
			a.Vhost = *vhost
		}
		a.Acked = acked != 0
		if evidence != nil {
			a.Evidence = safeParse(*evidence)
		}
		out = append(out, a)
	}
	return ListAlertsResult{Alerts: out, Total: total, FromDB: true}
}

// AckAlert replique ackAlert().
func (s *Store) AckAlert(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return false
	}
	res, err := s.db.Exec(`UPDATE alerts SET acked = 1 WHERE id = ?`, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// AckAllAlertsOptions reproduit l'objet d'options de ackAllAlerts().
type AckAllAlertsOptions struct {
	Type        string
	Severity    string
	Vhost       string
	OnlyUnacked bool // JS: defaut true ; l'appelant doit le mettre explicitement a true
}

// AckAllAlerts replique ackAllAlerts() : acquitte toutes les alertes filtrees
// d'un coup. Par defaut, seulement celles non encore acquittees, pour que
// l'appeler deux fois de suite soit sans effet.
func (s *Store) AckAllAlerts(o AckAllAlertsOptions) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		n := 0
		for i := range s.memAlerts {
			a := &s.memAlerts[i]
			if o.OnlyUnacked && a.Acked {
				continue
			}
			if o.Type != "" && a.Type != o.Type {
				continue
			}
			if o.Severity != "" && a.Severity != o.Severity {
				continue
			}
			if o.Vhost != "" && a.Vhost != o.Vhost {
				continue
			}
			a.Acked = true
			n++
		}
		return n
	}
	where := "1=1"
	var args []any
	if o.OnlyUnacked {
		where += " AND acked = 0"
	}
	if o.Type != "" {
		where += " AND type = ?"
		args = append(args, o.Type)
	}
	if o.Severity != "" {
		where += " AND severity = ?"
		args = append(args, o.Severity)
	}
	if o.Vhost != "" {
		where += " AND vhost = ?"
		args = append(args, o.Vhost)
	}
	res, err := s.db.Exec(`UPDATE alerts SET acked = 1 WHERE `+where, args...)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// ClearAlertsOptions reproduit l'objet d'options de clearAlerts().
type ClearAlertsOptions struct {
	Type     string
	Severity string
	Vhost    string
}

// ClearAlerts replique clearAlerts() : supprime toutes les alertes filtrees.
// Sans aucun filtre, vide la table entiere - un "tout effacer" delibere que
// l'appelant doit demander explicitement, pas un defaut.
//
// Note de parite : le filtre memoire JS utilise des OU entre criteres
// (`(type && a.type !== type) || ...`), ce qui ne fait un ET logique que
// lorsqu'un seul critere est fourni a la fois - c'est le seul usage reel
// (server.js ne passe jamais plus d'un filtre en meme temps). Reproduit tel
// quel plutot que "corrige" pour rester fidele au comportement observable.
func (s *Store) ClearAlerts(o ClearAlertsOptions) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		before := len(s.memAlerts)
		kept := s.memAlerts[:0]
		for _, a := range s.memAlerts {
			if (o.Type != "" && a.Type != o.Type) || (o.Severity != "" && a.Severity != o.Severity) || (o.Vhost != "" && a.Vhost != o.Vhost) {
				kept = append(kept, a)
			}
		}
		s.memAlerts = kept
		return before - len(s.memAlerts)
	}
	where := "1=1"
	var args []any
	if o.Type != "" {
		where += " AND type = ?"
		args = append(args, o.Type)
	}
	if o.Severity != "" {
		where += " AND severity = ?"
		args = append(args, o.Severity)
	}
	if o.Vhost != "" {
		where += " AND vhost = ?"
		args = append(args, o.Vhost)
	}
	res, err := s.db.Exec(`DELETE FROM alerts WHERE `+where, args...)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// PurgeAlerts replique purgeAlerts() (correctif ANA-11) : ne supprime que les
// alertes plus vieilles que olderThanMs, meme en mode memoire.
func (s *Store) PurgeAlerts(olderThanMs int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		before := len(s.memAlerts)
		kept := s.memAlerts[:0]
		for _, a := range s.memAlerts {
			if a.Ts >= olderThanMs {
				kept = append(kept, a)
			}
		}
		s.memAlerts = kept
		return before - len(s.memAlerts)
	}
	res, err := s.db.Exec(`DELETE FROM alerts WHERE ts < ?`, olderThanMs)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

func safeParse(str string) any {
	var v any
	if err := json.Unmarshal([]byte(str), &v); err != nil {
		return str
	}
	return v
}
