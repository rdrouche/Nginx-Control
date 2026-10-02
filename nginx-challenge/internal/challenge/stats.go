package challenge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Statistiques d'efficacité du challenge : compteurs agrégés par heure
// (aucune IP ni donnée personnelle n'est conservée), conservés 30 jours.
// Persistées à côté du secret (NC_SECRET_FILE) quand il existe, sinon en mémoire.

const statsRetention = 30 * 24 * time.Hour

// Counts : les compteurs d'une heure.
type Counts struct {
	Redirected  int `json:"redirected"`  // visiteurs renvoyés vers la page de vérification (401 du contrôle)
	Pages       int `json:"pages"`       // page de vérification servie
	Started     int `json:"started"`     // défi émis (le JavaScript s'est exécuté)
	Solved      int `json:"solved"`      // preuve de travail correcte, cookie délivré
	Failed      int `json:"failed"`      // solution fausse, défi expiré/invalide/déjà utilisé
	RateLimited int `json:"rateLimited"` // trop de tentatives
	PassCookie  int `json:"passCookie"`  // requêtes laissées passer grâce au cookie
	PassBot     int `json:"passBot"`     // requêtes laissées passer : robot d'indexation vérifié
}

func (c *Counts) add(o Counts) {
	c.Redirected += o.Redirected
	c.Pages += o.Pages
	c.Started += o.Started
	c.Solved += o.Solved
	c.Failed += o.Failed
	c.RateLimited += o.RateLimited
	c.PassCookie += o.PassCookie
	c.PassBot += o.PassBot
}

// Stats : accumulateur thread-safe.
type Stats struct {
	mu      sync.Mutex
	hours   map[int64]*Counts // clé : début d'heure (epoch, secondes)
	since   int64
	path    string
	dirty   bool
	nowFunc func() time.Time
}

type statsFile struct {
	Since int64             `json:"since"`
	Hours map[int64]*Counts `json:"hours"`
}

// NewStats charge l'état persisté s'il existe (path vide = mémoire seule).
func NewStats(path string) *Stats {
	s := &Stats{hours: map[int64]*Counts{}, path: path, nowFunc: time.Now}
	s.since = s.nowFunc().Unix()
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var f statsFile
			if json.Unmarshal(b, &f) == nil && f.Hours != nil {
				s.hours = f.Hours
				if f.Since > 0 {
					s.since = f.Since
				}
			}
		}
	}
	return s
}

// statsPathFor : stats.json à côté du fichier secret (vide si pas de volume).
func statsPathFor(secretFile string) string {
	if secretFile == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(secretFile), "stats.json")
}

func (s *Stats) bucket() *Counts {
	h := s.nowFunc().Truncate(time.Hour).Unix()
	c := s.hours[h]
	if c == nil {
		c = &Counts{}
		s.hours[h] = c
		cut := s.nowFunc().Add(-statsRetention).Unix()
		for k := range s.hours {
			if k < cut {
				delete(s.hours, k)
			}
		}
	}
	return c
}

// Inc incrémente un compteur (nil-safe : un Server de test peut ne pas en avoir).
func (s *Stats) Inc(f func(*Counts)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	f(s.bucket())
	s.dirty = true
	s.mu.Unlock()
}

// HourPoint : un point de la série horaire.
type HourPoint struct {
	Hour int64 `json:"hour"`
	Counts
}

// Snapshot : totaux sur la fenêtre (heures) et série horaire.
type Snapshot struct {
	Since       int64       `json:"since"`
	WindowHours int         `json:"windowHours"`
	Total       Counts      `json:"total"`
	Series      []HourPoint `json:"series"`
}

// Snapshot renvoie les totaux des `hours` dernières heures (1..720).
func (s *Stats) Snapshot(hours int) Snapshot {
	if hours < 1 {
		hours = 24
	}
	if hours > 720 {
		hours = 720
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.nowFunc().Truncate(time.Hour).Add(-time.Duration(hours-1) * time.Hour).Unix()
	out := Snapshot{Since: s.since, WindowHours: hours, Series: []HourPoint{}}
	for h, c := range s.hours {
		if h >= cut {
			out.Total.add(*c)
			out.Series = append(out.Series, HourPoint{Hour: h, Counts: *c})
		}
	}
	sort.Slice(out.Series, func(i, j int) bool { return out.Series[i].Hour < out.Series[j].Hour })
	return out
}

// Flush écrit l'état si modifié (écriture atomique, 0600).
func (s *Stats) Flush() error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(statsFile{Since: s.since, Hours: s.hours})
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// RunFlusher écrit périodiquement jusqu'à la fermeture de stop.
func (s *Stats) RunFlusher(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_ = s.Flush()
		case <-stop:
			_ = s.Flush()
			return
		}
	}
}
