package store

import (
	"encoding/json"
	"fmt"
	"os"
)

// GetState replique getState() : lit une valeur JSON generique.
func (s *Store) GetState(key string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	var value *string
	if err := s.db.QueryRow(`SELECT value FROM state WHERE key = ?`, key).Scan(&value); err != nil {
		return nil
	}
	if value == nil {
		return nil
	}
	return safeParse(*value)
}

// SetState replique setState().
func (s *Store) SetState(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return
	}
	_, err = s.db.Exec(`INSERT INTO state (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, string(encoded))
	if err != nil {
		fmt.Printf("[store] erreur setState: %v\n", err)
	}
}

// GetOffset replique getOffset(), avec la signature attendue par
// internal/tail.OffsetStore pour que *Store puisse servir directement de
// stockage d'offsets au tailer.
func (s *Store) GetOffset(file string) (inode uint64, offset int64, format string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, 0, "", false
	}
	var inodeVal, offsetVal *int64
	var formatVal *string
	err := s.db.QueryRow(`SELECT inode, offset, format FROM offsets WHERE file = ?`, file).
		Scan(&inodeVal, &offsetVal, &formatVal)
	if err != nil {
		return 0, 0, "", false
	}
	if inodeVal != nil {
		inode = uint64(*inodeVal)
	}
	if offsetVal != nil {
		offset = *offsetVal
	}
	if formatVal != nil {
		format = *formatVal
	}
	return inode, offset, format, true
}

// SetOffset replique setOffset().
func (s *Store) SetOffset(file string, inode uint64, offset int64, format string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	_, err := s.db.Exec(`INSERT INTO offsets (file, inode, offset, format) VALUES (?, ?, ?, ?)
		ON CONFLICT(file) DO UPDATE SET inode = excluded.inode, offset = excluded.offset, format = excluded.format`,
		file, int64(inode), offset, format)
	if err != nil {
		fmt.Printf("[store] erreur setOffset: %v\n", err)
	}
}

// Stats replique stats().
type Stats struct {
	Persistent bool
	Pending    int
	Rows       map[string]int
	Alerts     int
	DBBytes    int64
}

func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := len(s.memBuckets) + len(s.memBotBuckets)
	if s.db == nil {
		return Stats{Persistent: false, Pending: pending}
	}
	rows, err := s.db.Query(`SELECT grain, COUNT(*) n FROM traffic GROUP BY grain`)
	if err != nil {
		return Stats{Persistent: true}
	}
	rowCounts := make(map[string]int)
	for rows.Next() {
		var grain string
		var n int
		if err := rows.Scan(&grain, &n); err != nil {
			continue
		}
		rowCounts[grain] = n
	}
	rows.Close()
	var alertCount int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&alertCount)
	var size int64
	if fi, err := os.Stat(s.dbPath); err == nil {
		size = fi.Size()
	}
	return Stats{Persistent: true, Pending: pending, Rows: rowCounts, Alerts: alertCount, DBBytes: size}
}
