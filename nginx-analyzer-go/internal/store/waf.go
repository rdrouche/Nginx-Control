package store

import (
	"encoding/json"
	"fmt"
)

// WafRecordInput reproduit l'argument attendu par recordWaf().
type WafRecordInput struct {
	Ts       int64
	Vhost    string
	IP       string
	Method   string
	URI      string
	Status   int
	Blocked  bool
	Severity string
	RuleIDs  []string
	Messages []WafMessage
	UniqueID string
	Engine   string
	Raw      string
}

// RecordWaf replique recordWaf() : insertion directe, pas de tampon - un WAF
// n'ecrit que sur declenchement d'une regle, volume bien plus faible que les
// acces, un tampon ajouterait de la complexite sans gain reel.
func (s *Store) RecordWaf(e WafRecordInput) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ruleIDs := e.RuleIDs
	if ruleIDs == nil {
		ruleIDs = []string{}
	}
	messages := e.Messages
	if messages == nil {
		messages = []WafMessage{}
	}
	if s.db == nil {
		s.memWafSeq++
		ev := WafEvent{
			ID: s.memWafSeq, Ts: e.Ts, Vhost: e.Vhost, IP: e.IP, Method: e.Method, URI: e.URI,
			Status: e.Status, Blocked: e.Blocked, Severity: e.Severity, RuleIDs: ruleIDs,
			Messages: messages, UniqueID: e.UniqueID, Engine: e.Engine, Raw: e.Raw,
		}
		s.memWaf = append([]WafEvent{ev}, s.memWaf...)
		if len(s.memWaf) > 500 {
			s.memWaf = s.memWaf[:500]
		}
		return
	}
	ruleIDsJSON, _ := json.Marshal(ruleIDs)
	messagesJSON, _ := json.Marshal(messages)
	_, err := s.db.Exec(`INSERT INTO waf_events
		(ts, vhost, ip, method, uri, status, blocked, severity, ruleIds, messages, uniqueId, engine, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Ts, nullIfEmpty(e.Vhost), nullIfEmpty(e.IP), nullIfEmpty(e.Method), nullIfEmpty(e.URI),
		nullIfZero(e.Status), boolToInt(e.Blocked), nullIfEmpty(e.Severity),
		string(ruleIDsJSON), string(messagesJSON), nullIfEmpty(e.UniqueID), nullIfEmpty(e.Engine), nullIfEmpty(e.Raw))
	if err != nil {
		fmt.Printf("[store] erreur recordWaf: %v\n", err)
	}
}

func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetWafEvent replique getWafEvent() : un evenement complet, avec sa ligne
// brute d'origine, pour une vue de detail.
func (s *Store) GetWafEvent(id int64) *WafEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		for _, e := range s.memWaf {
			if e.ID == id {
				cp := e
				return &cp
			}
		}
		return nil
	}
	row := s.db.QueryRow(`SELECT id, ts, vhost, ip, method, uri, status, blocked, severity, ruleIds, messages, uniqueId, engine, raw
		FROM waf_events WHERE id = ?`, id)
	e, err := scanWafRow(row)
	if err != nil {
		return nil
	}
	return e
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanWafRow(row rowScanner) (*WafEvent, error) {
	var e WafEvent
	var vhost, ip, method, uri, severity, ruleIDs, messages, uniqueID, engine, raw *string
	var status *int
	var blocked int
	if err := row.Scan(&e.ID, &e.Ts, &vhost, &ip, &method, &uri, &status, &blocked, &severity, &ruleIDs, &messages, &uniqueID, &engine, &raw); err != nil {
		return nil, err
	}
	if vhost != nil {
		e.Vhost = *vhost
	}
	if ip != nil {
		e.IP = *ip
	}
	if method != nil {
		e.Method = *method
	}
	if uri != nil {
		e.URI = *uri
	}
	if status != nil {
		e.Status = *status
	}
	e.Blocked = blocked != 0
	if severity != nil {
		e.Severity = *severity
	}
	if uniqueID != nil {
		e.UniqueID = *uniqueID
	}
	if engine != nil {
		e.Engine = *engine
	}
	if raw != nil {
		e.Raw = *raw
	}
	if ruleIDs != nil {
		_ = json.Unmarshal([]byte(*ruleIDs), &e.RuleIDs)
	}
	if e.RuleIDs == nil {
		e.RuleIDs = []string{}
	}
	if messages != nil {
		_ = json.Unmarshal([]byte(*messages), &e.Messages)
	}
	if e.Messages == nil {
		e.Messages = []WafMessage{}
	}
	return &e, nil
}

// ListWafOptions reproduit l'objet d'options de listWaf().
type ListWafOptions struct {
	Limit    int
	Offset   int
	Vhost    string
	Severity string
	Blocked  *bool
	Since    int64
}

// ListWafResult reproduit la valeur de retour de listWaf().
type ListWafResult struct {
	Events []WafEvent
	Total  int
	FromDB bool
}

// ListWaf replique listWaf(). `raw` est deliberement exclu ici : une page de
// resultats doit rester legere. La ligne complete est recuperee a la demande,
// par evenement, via GetWafEvent().
func (s *Store) ListWaf(o ListWafOptions) ListWafResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := o.Limit
	if limit == 0 {
		limit = 100
	}
	if s.db == nil {
		var rows []WafEvent
		for _, r := range s.memWaf {
			if o.Vhost != "" && r.Vhost != o.Vhost {
				continue
			}
			if o.Severity != "" && r.Severity != o.Severity {
				continue
			}
			if o.Blocked != nil && r.Blocked != *o.Blocked {
				continue
			}
			if o.Since != 0 && r.Ts < o.Since {
				continue
			}
			rows = append(rows, r)
		}
		total := len(rows)
		end := o.Offset + limit
		if o.Offset > total {
			o.Offset = total
		}
		if end > total {
			end = total
		}
		out := make([]WafEvent, end-o.Offset)
		copy(out, rows[o.Offset:end])
		return ListWafResult{Events: out, Total: total, FromDB: false}
	}
	where := "1=1"
	var args []any
	if o.Vhost != "" {
		where += " AND vhost = ?"
		args = append(args, o.Vhost)
	}
	if o.Severity != "" {
		where += " AND severity = ?"
		args = append(args, o.Severity)
	}
	if o.Blocked != nil {
		where += " AND blocked = ?"
		args = append(args, boolToInt(*o.Blocked))
	}
	if o.Since != 0 {
		where += " AND ts >= ?"
		args = append(args, o.Since)
	}
	var total int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM waf_events WHERE `+where, args...).Scan(&total)
	q := `SELECT id, ts, vhost, ip, method, uri, status, blocked, severity, ruleIds, messages, uniqueId, engine
		FROM waf_events WHERE ` + where + ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	rows, err := s.db.Query(q, append(append([]any{}, args...), limit, o.Offset)...)
	if err != nil {
		return ListWafResult{FromDB: true}
	}
	defer rows.Close()
	var out []WafEvent
	for rows.Next() {
		var e WafEvent
		var vhost, ip, method, uri, severity, ruleIDs, messages, uniqueID, engine *string
		var status *int
		var blocked int
		if err := rows.Scan(&e.ID, &e.Ts, &vhost, &ip, &method, &uri, &status, &blocked, &severity, &ruleIDs, &messages, &uniqueID, &engine); err != nil {
			continue
		}
		if vhost != nil {
			e.Vhost = *vhost
		}
		if ip != nil {
			e.IP = *ip
		}
		if method != nil {
			e.Method = *method
		}
		if uri != nil {
			e.URI = *uri
		}
		if status != nil {
			e.Status = *status
		}
		e.Blocked = blocked != 0
		if severity != nil {
			e.Severity = *severity
		}
		if uniqueID != nil {
			e.UniqueID = *uniqueID
		}
		if engine != nil {
			e.Engine = *engine
		}
		if ruleIDs != nil {
			_ = json.Unmarshal([]byte(*ruleIDs), &e.RuleIDs)
		}
		if e.RuleIDs == nil {
			e.RuleIDs = []string{}
		}
		if messages != nil {
			_ = json.Unmarshal([]byte(*messages), &e.Messages)
		}
		if e.Messages == nil {
			e.Messages = []WafMessage{}
		}
		out = append(out, e)
	}
	return ListWafResult{Events: out, Total: total, FromDB: true}
}

// WafTopRule reproduit une ligne de wafTopRules().
type WafTopRule struct {
	RuleID  string
	Count   int
	Example string
}

// WafTopRules replique wafTopRules() : identifiants de regles classes par
// frequence de declenchement. Compte en Go a partir d'une recuperation
// bornee plutot que par un agregat SQL, puisque la liste des regles est
// stockee en JSON par ligne (un evenement peut declencher plusieurs regles) -
// l'exploser en SQL demanderait une extension JSON dont ce projet ne depend pas.
func (s *Store) WafTopRules(fromMs, toMs int64, vhost string, limit int) []WafTopRule {
	if limit == 0 {
		limit = 4000
	}
	rows := s.wafWindow(fromMs, toMs, vhost, limit)
	type acc struct {
		count   int
		example string
	}
	counts := make(map[string]*acc)
	var order []string
	for _, r := range rows {
		for _, id := range r.RuleIDs {
			c, ok := counts[id]
			if !ok {
				c = &acc{}
				counts[id] = c
				order = append(order, id)
			}
			c.count++
			if c.example == "" {
				for _, m := range r.Messages {
					if m.RuleID == id {
						c.example = m.Message
						break
					}
				}
			}
		}
	}
	out := make([]WafTopRule, 0, len(order))
	for _, id := range order {
		out = append(out, WafTopRule{RuleID: id, Count: counts[id].count, Example: counts[id].example})
	}
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j-1].Count < out[j].Count {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// WafTopIP reproduit une ligne de wafTopIps().
type WafTopIP struct {
	IP      string
	Count   int
	Blocked int
}

// WafTopIps replique wafTopIps().
func (s *Store) WafTopIps(fromMs, toMs int64, vhost string) []WafTopIP {
	s.mu.Lock()
	if s.db == nil {
		s.mu.Unlock()
		rows := s.wafWindow(fromMs, toMs, vhost, 100000)
		counts := make(map[string]*WafTopIP)
		var order []string
		for _, r := range rows {
			if r.IP == "" {
				continue
			}
			c, ok := counts[r.IP]
			if !ok {
				c = &WafTopIP{IP: r.IP}
				counts[r.IP] = c
				order = append(order, r.IP)
			}
			c.Count++
			if r.Blocked {
				c.Blocked++
			}
		}
		out := make([]WafTopIP, 0, len(order))
		for _, ip := range order {
			out = append(out, *counts[ip])
		}
		for i := 1; i < len(out); i++ {
			j := i
			for j > 0 && out[j-1].Count < out[j].Count {
				out[j-1], out[j] = out[j], out[j-1]
				j--
			}
		}
		if len(out) > 20 {
			out = out[:20]
		}
		return out
	}
	where := "ts >= ? AND ts < ? AND ip IS NOT NULL"
	args := []any{fromMs, toMs}
	if vhost != "" {
		where += " AND vhost = ?"
		args = append(args, vhost)
	}
	rows, err := s.db.Query(`SELECT ip, COUNT(*) as count, SUM(blocked) as blocked
		FROM waf_events WHERE `+where+` GROUP BY ip ORDER BY count DESC LIMIT 20`, args...)
	s.mu.Unlock()
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []WafTopIP
	for rows.Next() {
		var t WafTopIP
		if err := rows.Scan(&t.IP, &t.Count, &t.Blocked); err != nil {
			continue
		}
		out = append(out, t)
	}
	return out
}

// WafSeriesPoint reproduit une ligne de wafSeries().
type WafSeriesPoint struct {
	Ts      int64
	Count   int
	Blocked int
}

// WafSeries replique wafSeries() : comptages horaires, bloques vs detectes,
// pour une frise chronologique simple.
func (s *Store) WafSeries(fromMs, toMs int64, vhost string) []WafSeriesPoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	where := "ts >= ? AND ts < ?"
	args := []any{fromMs, toMs}
	if vhost != "" {
		where += " AND vhost = ?"
		args = append(args, vhost)
	}
	rows, err := s.db.Query(`SELECT (ts / 3600000) * 3600000 as hour, COUNT(*) as count, SUM(blocked) as blocked
		FROM waf_events WHERE `+where+` GROUP BY hour ORDER BY hour`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []WafSeriesPoint
	for rows.Next() {
		var p WafSeriesPoint
		if err := rows.Scan(&p.Ts, &p.Count, &p.Blocked); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

// wafWindow replique _wafWindow() : recuperation brute bornee, partagee par
// les deux agregations "top" ci-dessus. Appele avec s.mu deja verrouille par
// l'appelant public le cas echeant ; verrouille lui-meme sinon (WafTopRules).
func (s *Store) wafWindow(fromMs, toMs int64, vhost string, limit int) []WafEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		var rows []WafEvent
		for _, r := range s.memWaf {
			if r.Ts >= fromMs && r.Ts < toMs {
				if vhost == "" || r.Vhost == vhost {
					rows = append(rows, r)
				}
			}
		}
		if len(rows) > limit {
			rows = rows[:limit]
		}
		return rows
	}
	where := "ts >= ? AND ts < ?"
	args := []any{fromMs, toMs}
	if vhost != "" {
		where += " AND vhost = ?"
		args = append(args, vhost)
	}
	rows, err := s.db.Query(`SELECT ruleIds, messages FROM waf_events WHERE `+where+` ORDER BY ts DESC LIMIT ?`,
		append(append([]any{}, args...), limit)...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []WafEvent
	for rows.Next() {
		var ruleIDs, messages string
		if err := rows.Scan(&ruleIDs, &messages); err != nil {
			continue
		}
		var e WafEvent
		_ = json.Unmarshal([]byte(ruleIDs), &e.RuleIDs)
		_ = json.Unmarshal([]byte(messages), &e.Messages)
		out = append(out, e)
	}
	return out
}

// PurgeWaf replique purgeWaf() (correctif ANA-11).
func (s *Store) PurgeWaf(olderThanMs int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		before := len(s.memWaf)
		kept := s.memWaf[:0]
		for _, r := range s.memWaf {
			if r.Ts >= olderThanMs {
				kept = append(kept, r)
			}
		}
		s.memWaf = kept
		return before - len(s.memWaf)
	}
	res, err := s.db.Exec(`DELETE FROM waf_events WHERE ts < ?`, olderThanMs)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// ClearWafOptions reproduit l'objet d'options de clearWaf().
type ClearWafOptions struct {
	Vhost    string
	Severity string
	Blocked  *bool
}

// ClearWaf replique clearWaf() : purge manuelle filtree, distincte de la
// retention par anciennete de PurgeWaf(). Sans aucun filtre, vide toute la
// table WAF - un "tout effacer" delibere que l'appelant doit demander
// explicitement, a l'image de ClearAlerts() pour le journal d'alertes.
func (s *Store) ClearWaf(o ClearWafOptions) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		before := len(s.memWaf)
		kept := s.memWaf[:0]
		for _, r := range s.memWaf {
			if (o.Vhost != "" && r.Vhost != o.Vhost) || (o.Severity != "" && r.Severity != o.Severity) ||
				(o.Blocked != nil && r.Blocked != *o.Blocked) {
				kept = append(kept, r)
			}
		}
		s.memWaf = kept
		return before - len(s.memWaf)
	}
	where := "1=1"
	var args []any
	if o.Vhost != "" {
		where += " AND vhost = ?"
		args = append(args, o.Vhost)
	}
	if o.Severity != "" {
		where += " AND severity = ?"
		args = append(args, o.Severity)
	}
	if o.Blocked != nil {
		where += " AND blocked = ?"
		args = append(args, boolToInt(*o.Blocked))
	}
	res, err := s.db.Exec(`DELETE FROM waf_events WHERE `+where, args...)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// WafStats replique wafStats().
type WafStats struct {
	Rows       int
	Persistent bool
}

func (s *Store) WafStats() WafStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return WafStats{Rows: len(s.memWaf), Persistent: false}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM waf_events`).Scan(&n); err != nil {
		return WafStats{Rows: 0, Persistent: true}
	}
	return WafStats{Rows: n, Persistent: true}
}
