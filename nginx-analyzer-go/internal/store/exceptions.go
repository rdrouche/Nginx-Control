package store

import (
	"database/sql"

	"nginx-analyzer-go/internal/cidr"
)

// ListExceptions replique listExceptions().
func (s *Store) ListExceptions(vhost string) []Exception {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		if vhost == "" {
			out := make([]Exception, len(s.memExceptions))
			copy(out, s.memExceptions)
			return out
		}
		var out []Exception
		for _, e := range s.memExceptions {
			if e.Vhost == vhost {
				out = append(out, e)
			}
		}
		return out
	}
	var rows *sql.Rows
	var err error
	if vhost != "" {
		rows, err = s.db.Query(`SELECT id, vhost, ip, reason, created, author FROM exceptions WHERE vhost = ? ORDER BY created DESC`, vhost)
	} else {
		rows, err = s.db.Query(`SELECT id, vhost, ip, reason, created, author FROM exceptions ORDER BY vhost, created DESC`)
	}
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Exception
	for rows.Next() {
		var e Exception
		var reason, author *string
		if err := rows.Scan(&e.ID, &e.Vhost, &e.IP, &reason, &e.Created, &author); err != nil {
			continue
		}
		if reason != nil {
			e.Reason = *reason
		}
		if author != nil {
			e.Author = *author
		}
		out = append(out, e)
	}
	return out
}

// AddExceptionResult reproduit { ok, error? } de addException().
type AddExceptionResult struct {
	OK    bool
	Error string
}

// AddExceptionInput reproduit l'argument de addException().
type AddExceptionInput struct {
	Vhost  string
	IP     string
	Reason string
	Author string
}

// AddException replique addException().
func (s *Store) AddException(in AddExceptionInput) AddExceptionResult {
	if in.Vhost == "" || in.IP == "" {
		return AddExceptionResult{OK: false, Error: "vhost and ip required"}
	}
	// Un motif qui ne peut etre analyse comme une adresse ou un bloc CIDR
	// matcherait silencieusement rien pour toujours - le rejeter maintenant,
	// avec une raison claire, plutot que d'accepter une exception qui n'exclut
	// jamais rien en pratique.
	if !cidr.IsValidPattern(in.IP) {
		return AddExceptionResult{OK: false, Error: "\"" + in.IP + "\" n est ni une adresse IP valide ni un bloc CIDR (ex: 203.0.113.0/24)"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		s.memExceptions = append(s.memExceptions, Exception{
			ID: nowMs(), Vhost: in.Vhost, IP: in.IP, Reason: in.Reason, Author: in.Author, Created: nowMs(),
		})
		return AddExceptionResult{OK: true}
	}
	_, err := s.db.Exec(`INSERT INTO exceptions (vhost, ip, reason, created, author)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(vhost, ip) DO UPDATE SET reason = excluded.reason, author = excluded.author`,
		in.Vhost, in.IP, in.Reason, nowMs(), in.Author)
	if err != nil {
		return AddExceptionResult{OK: false, Error: err.Error()}
	}
	return AddExceptionResult{OK: true}
}

// RemoveException replique removeException().
func (s *Store) RemoveException(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		kept := s.memExceptions[:0]
		found := false
		for _, e := range s.memExceptions {
			if e.ID == id {
				found = true
				continue
			}
			kept = append(kept, e)
		}
		s.memExceptions = kept
		return found
	}
	res, err := s.db.Exec(`DELETE FROM exceptions WHERE id = ?`, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}
